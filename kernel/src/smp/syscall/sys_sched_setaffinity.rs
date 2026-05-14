use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitmap::traits::BitMapOps;
use system_error::SystemError;

use crate::{
    arch::{interrupt::TrapFrame, syscall::nr::SYS_SCHED_SETAFFINITY, CurrentIrqArch},
    exception::InterruptArch,
    libs::cpumask::CpuMask,
    process::{ProcessManager, RawPid},
    sched::{
        cpu_rq, schedule, task_cpu, ttwu_queue, DequeueFlag, EnqueueFlag, OnRq, SchedMode,
        WakeupFlags, __set_task_cpu, load_balance::LoadBalancer, send_resched_ipi,
        syscall::util::has_sched_setaffinity_permission,
    },
    smp::{
        core::smp_get_processor_id,
        cpu::{smp_cpu_manager, ProcessorId},
    },
    syscall::{
        table::{FormattedSyscallParam, Syscall},
        user_access::UserBufferReader,
    },
};

pub struct SysSchedSetaffinity;

impl Syscall for SysSchedSetaffinity {
    fn num_args(&self) -> usize {
        3
    }

    fn handle(&self, args: &[usize], frame: &mut TrapFrame) -> Result<usize, SystemError> {
        let pid = args[0] as i32;
        let size = args[1];
        let set_vaddr = args[2];

        if size == 0 {
            return Err(SystemError::EINVAL);
        }

        let target_pcb = if pid == 0 {
            ProcessManager::current_pcb()
        } else {
            ProcessManager::find_task_by_vpid(RawPid::from(pid as usize))
                .ok_or(SystemError::ESRCH)?
        };

        let current_pcb = ProcessManager::current_pcb();
        if !has_sched_setaffinity_permission(&current_pcb, &target_pcb) {
            return Err(SystemError::EPERM);
        }

        let reader = UserBufferReader::new(set_vaddr as *const u8, size, frame.is_from_user())?;
        let user_set = reader.buffer(0)?;
        let mask = Self::parse_user_mask(user_set)?;

        if mask.is_empty() {
            return Err(SystemError::EINVAL);
        }

        let possible_cpus = smp_cpu_manager().possible_cpus();
        for cpu in mask.iter_cpu() {
            if possible_cpus.get(cpu) != Some(true) {
                return Err(SystemError::EINVAL);
            }
        }

        let is_current = Arc::ptr_eq(&target_pcb, &ProcessManager::current_pcb());

        if is_current {
            // 锁序：pi_lock → rq_lock（与 ttwu_do_activate 的 pi_lock→rq_lock 一致，避免 ABBA 死锁）
            let irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };
            let cur_cpu = smp_get_processor_id();

            let mut pi_guard = target_pcb.sched_info().pi_lock_irqsave();
            pi_guard.set_cpus_allowed(mask.clone());

            let needs_migration = mask.get(cur_cpu) != Some(true);
            if !needs_migration {
                drop(pi_guard);
                drop(irq_guard);
                return Ok(0);
            }

            let dest_cpu = LoadBalancer::select_task_rq(
                &target_pcb,
                &pi_guard,
                cur_cpu,
                WakeupFlags::WF_TTWU.bits(),
            );
            let dest_cpu = if dest_cpu == ProcessorId::INVALID || mask.get(dest_cpu) != Some(true) {
                mask.first().unwrap_or(cur_cpu)
            } else {
                dest_cpu
            };

            let rq = cpu_rq(cur_cpu.data() as usize);
            let (rq_ref, guard) = rq.self_lock();
            rq_ref.update_rq_clock();

            target_pcb.sched_info().on_rq.set(OnRq::Migrating);
            rq_ref.dequeue_task(
                target_pcb.clone(),
                DequeueFlag::DEQUEUE_SAVE | DequeueFlag::DEQUEUE_NOCLOCK,
            );
            if dest_cpu != cur_cpu {
                __set_task_cpu(&target_pcb, dest_cpu);
                ttwu_queue(&target_pcb, dest_cpu, WakeupFlags::WF_MIGRATED);
            }

            drop(guard);
            drop(pi_guard);
            schedule(SchedMode::SM_NONE);
            drop(irq_guard);
        } else {
            let irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };

            // 只负责获取 pi_lock + rq_lock 并验证任务未迁移，retry 时不重复设 mask。
            'task_rq_lock: loop {
                let mut pi_guard = target_pcb.sched_info().pi_lock_irqsave();

                let task_cpu_id = task_cpu(&target_pcb);
                let src_rq = cpu_rq(task_cpu_id.data() as usize);
                let (src_ref, src_guard) = src_rq.self_lock();
                src_ref.update_rq_clock();

                let current_cpu = task_cpu(&target_pcb);
                if current_cpu != task_cpu_id
                    || target_pcb.sched_info().on_rq.get() == OnRq::Migrating
                {
                    // 对标 Linux: unlock both → spin-wait on MIGRATING → retry
                    drop(src_guard);
                    drop(pi_guard);
                    while target_pcb.sched_info().on_rq.get() == OnRq::Migrating {
                        core::hint::spin_loop();
                    }
                    continue 'task_rq_lock;
                }
                // task_rq_lock 成功：pi_lock + src_rq 锁稳定持有

                // 在双锁保护下设置 cpus_mask、选 dest_cpu、执行迁移
                pi_guard.set_cpus_allowed(mask.clone());

                let on_rq = target_pcb.sched_info().on_rq.get();
                let on_cpu = target_pcb.sched_info().on_cpu();

                let needs_migration = mask.get(task_cpu_id) != Some(true);
                if !needs_migration {
                    drop(src_guard);
                    drop(pi_guard);
                    break 'task_rq_lock;
                }

                // 选 dest_cpu
                let dest_cpu = LoadBalancer::select_task_rq(
                    &target_pcb,
                    &pi_guard,
                    task_cpu_id,
                    WakeupFlags::WF_TTWU.bits(),
                );
                let dest_cpu =
                    if dest_cpu == ProcessorId::INVALID || mask.get(dest_cpu) != Some(true) {
                        mask.first().unwrap_or(task_cpu_id)
                    } else {
                        dest_cpu
                    };

                if on_rq == OnRq::Queued && on_cpu.is_none() {
                    // move_queued_task
                    target_pcb.sched_info().on_rq.set(OnRq::Migrating);
                    src_ref.dequeue_task(target_pcb.clone(), DequeueFlag::DEQUEUE_NOCLOCK);
                    __set_task_cpu(&target_pcb, dest_cpu);
                    drop(src_guard);
                    // rq_unlock(src) 后 rq_lock(dst) 期间 pi_lock 不释放

                    let dst_rq = cpu_rq(dest_cpu.data() as usize);
                    let (dst_ref, dst_guard) = dst_rq.self_lock();
                    dst_ref.update_rq_clock();
                    dst_ref.activate_task(
                        &target_pcb,
                        EnqueueFlag::ENQUEUE_NOCLOCK | EnqueueFlag::ENQUEUE_MIGRATED,
                    );
                    dst_ref.check_preempt_current(&target_pcb, WakeupFlags::WF_MIGRATED);
                    drop(dst_guard);
                    drop(pi_guard);
                    break 'task_rq_lock;
                } else if on_cpu.is_some() {
                    // 任务正在运行，缺少 stop_one_cpu 基础设施，
                    // 发送 resched IPI 后依赖下次唤醒时使用新 cpus_allowed。
                    // TODO: 实现 stop_one_cpu_nowait
                    drop(src_guard);
                    drop(pi_guard);
                    send_resched_ipi(on_cpu.unwrap());
                    break 'task_rq_lock;
                } else {
                    drop(src_guard);
                    drop(pi_guard);
                    break 'task_rq_lock;
                }
            }

            drop(irq_guard);
        }

        Ok(0)
    }

    fn entry_format(&self, args: &[usize]) -> Vec<FormattedSyscallParam> {
        vec![
            FormattedSyscallParam::new("pid", (args[0] as i32).to_string()),
            FormattedSyscallParam::new("size", args[1].to_string()),
            FormattedSyscallParam::new("set", format!("0x{:x}", args[2])),
        ]
    }
}

impl SysSchedSetaffinity {
    fn parse_user_mask(user_set: &[u8]) -> Result<CpuMask, SystemError> {
        let mut mask = CpuMask::new();
        let kernel_mask_bytes = unsafe { mask.inner().as_bytes().len() };
        let parse_len = core::cmp::min(user_set.len(), kernel_mask_bytes);

        for (byte_index, byte) in user_set[..parse_len].iter().enumerate() {
            if *byte == 0 {
                continue;
            }

            for bit in 0..8 {
                if (byte & (1 << bit)) == 0 {
                    continue;
                }

                let cpu_index = byte_index * 8 + bit;
                let cpu_id = ProcessorId::new(cpu_index as u32);
                if mask.set(cpu_id, true).is_none() {
                    return Err(SystemError::EINVAL);
                }
            }
        }

        if user_set[parse_len..].iter().any(|byte| *byte != 0) {
            return Err(SystemError::EINVAL);
        }

        Ok(mask)
    }
}

syscall_table_macros::declare_syscall!(SYS_SCHED_SETAFFINITY, SysSchedSetaffinity);
