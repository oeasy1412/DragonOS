use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitmap::traits::BitMapOps;
use system_error::SystemError;

use crate::arch::interrupt::TrapFrame;
use crate::arch::syscall::nr::SYS_SCHED_SETAFFINITY;
use crate::arch::CurrentIrqArch;
use crate::exception::InterruptArch;
use crate::libs::cpumask::CpuMask;
use crate::process::{ProcessManager, RawPid};
use crate::sched::load_balance::LoadBalancer;
use crate::sched::send_resched_ipi;
use crate::sched::syscall::util::has_sched_setaffinity_permission;
use crate::sched::{
    cpu_rq, schedule, task_cpu, ttwu_queue, DequeueFlag, EnqueueFlag, OnRq, SchedMode, WakeupFlags,
    __set_task_cpu,
};
use crate::smp::core::smp_get_processor_id;
use crate::smp::cpu::smp_cpu_manager;
use crate::syscall::table::{FormattedSyscallParam, Syscall};
use crate::syscall::user_access::UserBufferReader;

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

        // 设置新 mask 后，判断是否需要物理迁移。
        target_pcb.sched_info().set_cpus_allowed(mask.clone());

        let task_cpu_id = task_cpu(&target_pcb);
        let needs_migration = mask.get(task_cpu_id) != Some(true);
        if !needs_migration {
            return Ok(0);
        }

        // 选择目标 CPU
        let dest_cpu =
            LoadBalancer::select_task_rq(&target_pcb, task_cpu_id, WakeupFlags::WF_TTWU.bits());
        let dest_cpu = if dest_cpu == crate::smp::cpu::ProcessorId::INVALID {
            mask.first().unwrap_or(task_cpu_id)
        } else {
            dest_cpu
        };

        let is_current = Arc::ptr_eq(&target_pcb, &ProcessManager::current_pcb());

        if is_current {
            // 对标 Linux affine_move_task + move_queued_task：
            // 当前任务从自身 rq 出队，迁移到目标 CPU，schedule 让出 CPU。
            let _irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };
            let cur_cpu = smp_get_processor_id();
            let rq = cpu_rq(cur_cpu.data() as usize);
            let (rq_ref, guard) = rq.self_lock();
            rq_ref.update_rq_clock();

            *target_pcb.sched_info().on_rq.lock_irqsave() = OnRq::Migrating;
            rq_ref.dequeue_task(
                target_pcb.clone(),
                DequeueFlag::DEQUEUE_SAVE | DequeueFlag::DEQUEUE_NOCLOCK,
            );
            // 不调用 __set_task_cpu：由 drain_wake_queue 根据 prev_cpu != local_cpu 判断迁移并调用 __set_task_cpu。
            if dest_cpu != cur_cpu {
                ttwu_queue(&target_pcb, dest_cpu, WakeupFlags::WF_MIGRATED);
            }

            drop(guard);
            schedule(SchedMode::SM_NONE);
            drop(_irq_guard);
        } else {
            // 对标 __set_cpus_allowed_ptr_locked → affine_move_task：
            // DragonOS 无 pi_lock，在获取 rq 锁后重新校验状态防止 TOCTOU。
            let _irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };

            let src_rq = cpu_rq(task_cpu_id.data() as usize);
            let (src_ref, src_guard) = src_rq.self_lock();
            src_ref.update_rq_clock();

            // 获取 rq 锁后重新校验：task_cpu / on_rq / on_cpu 可能已变化。
            let current_cpu = task_cpu(&target_pcb);
            let on_rq = *target_pcb.sched_info().on_rq.lock_irqsave();
            let on_cpu = target_pcb.sched_info().on_cpu();

            if current_cpu != task_cpu_id {
                // 任务已被迁移到其他 CPU，放弃本次操作。
                // 下次 wakeup 时 select_task_rq 会使用新的 cpus_allowed。
                drop(src_guard);
                drop(_irq_guard);
                return Ok(0);
            }

            if on_rq == OnRq::Queued && on_cpu.is_none() {
                // 任务在 rq 上排队且未运行，对标 Linux move_queued_task
                *target_pcb.sched_info().on_rq.lock_irqsave() = OnRq::Migrating;
                src_ref.dequeue_task(
                    target_pcb.clone(),
                    DequeueFlag::DEQUEUE_SAVE | DequeueFlag::DEQUEUE_NOCLOCK,
                );
                __set_task_cpu(&target_pcb, dest_cpu);
                drop(src_guard);

                // 锁目标 rq 并 activate
                let dst_rq = cpu_rq(dest_cpu.data() as usize);
                let (dst_ref, dst_guard) = dst_rq.self_lock();
                dst_ref.update_rq_clock();
                dst_ref.activate_task(
                    &target_pcb,
                    EnqueueFlag::ENQUEUE_WAKEUP
                        | EnqueueFlag::ENQUEUE_NOCLOCK
                        | EnqueueFlag::ENQUEUE_MIGRATED,
                );
                dst_ref.check_preempt_current(&target_pcb, WakeupFlags::WF_MIGRATED);
                drop(dst_guard);
            } else if on_cpu.is_some() {
                // 任务正在运行（在另一个 CPU 上）。
                // affine_move_task 的 task_on_cpu 路径：
                // Linux 使用 stop_one_cpu_nowait + migration_cpu_stop 在目标 CPU 上完成出队→迁移→入队。
                // DragonOS 缺少 stop_one_cpu 基础设施，仅发送 resched IPI，任务暂时继续在原 CPU 运行。
                // 下次阻塞→唤醒时 ttwu_do_activate → select_task_rq 会使用新的 cpus_allowed 选择正确 CPU。
                drop(src_guard);
                send_resched_ipi(on_cpu.unwrap());
            } else {
                drop(src_guard);
            }

            drop(_irq_guard);
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
                let cpu_id = crate::smp::cpu::ProcessorId::new(cpu_index as u32);
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
