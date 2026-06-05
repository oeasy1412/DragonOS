//! 获取指定进程（或当前进程）的实时调度优先级。

use system_error::SystemError;

use crate::arch::interrupt::TrapFrame;
use crate::arch::syscall::nr::SYS_SCHED_GETPARAM;
use crate::process::ProcessManager;
use crate::process::RawPid;
use crate::sched::prio::MAX_RT_PRIO;
use crate::sched::SchedPolicy;
use crate::syscall::table::FormattedSyscallParam;
use crate::syscall::table::Syscall;
use crate::syscall::user_access::UserBufferWriter;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Linux sched_param 结构体
/// 与 musl-libc 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct PosixSchedParam {
    sched_priority: i32,
    __reserved1: i32,
    __reserved2: [i64; 4],
    __reserved3: i32,
}

/// `sched_getparam` 系统调用处理。
struct SysSchedGetparam;

impl Syscall for SysSchedGetparam {
    fn num_args(&self) -> usize {
        2
    }

    /// 获取指定进程的调度参数。pid=0 表示当前进程。
    /// 写入用户的 `sched_param.sched_priority` 为实时优先级（1-99），
    /// 非实时策略（CFS/IDLE）始终为 0。
    fn handle(&self, args: &[usize], frame: &mut TrapFrame) -> Result<usize, SystemError> {
        let pid = Self::pid(args);
        let param = Self::param(args);

        // 验证用户空间指针
        if param.is_null() {
            return Err(SystemError::EFAULT);
        }

        // 获取目标进程
        let target_pcb = if pid == 0 {
            // pid 为 0 表示当前进程
            ProcessManager::current_pcb()
        } else {
            // 查找指定进程
            let raw_pid = RawPid::from(pid);
            ProcessManager::find_task_by_vpid(raw_pid).ok_or(SystemError::ESRCH)?
        };

        // 权限检查：只有进程自己或具有 CAP_SYS_NICE 权限的进程可以查询
        let current_pcb = ProcessManager::current_pcb();
        if !super::util::has_sched_permission(&current_pcb, &target_pcb) {
            return Err(SystemError::EPERM);
        }

        let policy = target_pcb.sched_info().policy();

        let sched_priority = match policy {
            SchedPolicy::CFS | SchedPolicy::IDLE => {
                // 普通进程的 sched_priority 始终为 0
                0
            }
            SchedPolicy::RT | SchedPolicy::FIFO => {
                let rt_prio = target_pcb.sched_info().rt_priority();
                rt_prio.clamp(1, MAX_RT_PRIO - 1)
            }
        };

        // 构造 sched_param 结构
        let sched_param = PosixSchedParam {
            sched_priority,
            __reserved1: 0,
            __reserved2: [0; 4],
            __reserved3: 0,
        };

        // 将结果写入用户空间
        let mut writer = UserBufferWriter::new(
            param,
            core::mem::size_of::<PosixSchedParam>(),
            frame.is_from_user(),
        )?;

        writer.buffer_protected(0)?.write_one(0, &sched_param)?;

        Ok(0)
    }

    /// 格式化系统调用参数用于日志输出。
    fn entry_format(&self, args: &[usize]) -> Vec<FormattedSyscallParam> {
        vec![
            FormattedSyscallParam::new("pid", Self::pid(args).to_string()),
            FormattedSyscallParam::new("param", format!("{:#x}", Self::param(args) as usize)),
        ]
    }
}

impl SysSchedGetparam {
    fn pid(args: &[usize]) -> usize {
        args[0]
    }

    fn param(args: &[usize]) -> *mut PosixSchedParam {
        args[1] as *mut PosixSchedParam
    }
}

syscall_table_macros::declare_syscall!(SYS_SCHED_GETPARAM, SysSchedGetparam);
