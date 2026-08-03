use super::{
    abi::WaitOption, ExitState, ProcessControlBlock, ProcessFlags, ProcessManager, RawPid,
    PTRACE_RELATION_LOCK,
};
use crate::{
    arch::{
        interrupt::TrapFrame,
        ipc::signal::{SigChildCode, SigFlags, SigSet, Signal},
        CurrentIrqArch, MMArch,
    },
    exception::InterruptArch,
    ipc::signal_types::{SigCode, SigInfo, SigType, SignalFlags},
    mm::{fault, ucontext, MemoryManagementArch, PhysAddr, VirtAddr, VmFaultReason, VmFlags},
    process::{namespace::user_namespace::map_id_up, pid::PidType, KernelStack, ProcessState},
    sched::{schedule, SchedMode},
};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    mem::size_of,
    sync::atomic::{fence, Ordering},
};
use system_error::SystemError;

/// 信号递送路径的 ptrace hook：在 `do_signal` 出队信号后、动作查找前调用。
pub fn ptrace_signal(
    pcb: &Arc<ProcessControlBlock>,
    original: Signal,
    info: &mut Option<SigInfo>,
) -> Option<Signal> {
    // SIGKILL 不经过 ptrace_signal（防御性，do_signal 已在 kernel_only 路径处理）。
    if original == Signal::SIGKILL {
        return Some(Signal::SIGKILL);
    }

    // 进入 signal-delivery-stop。ptrace_stop 内部会 fatal 早退、阻塞、唤醒后清理。
    let signr = pcb.ptrace_stop(original as usize, SigChildCode::Trapped, info.as_mut());

    if signr == 0 {
        // tracer 丢弃了信号。
        return None;
    }

    let injected = Signal::from(signr as i32);
    if injected == Signal::INVALID {
        return None;
    }

    // 如果 tracer 改变了信号号，重建 siginfo（来源 SI_USER）。
    if let Some(i) = info {
        if injected as i32 != i.signo_i32() {
            let sender = crate::process::ptrace::ptracer_of(pcb).or_else(|| pcb.real_parent_pcb());
            let sender_vpid = sender
                .as_ref()
                .and_then(|parent| parent.task_pid_nr_ns(PidType::PID, Some(pcb.active_pid_ns())))
                .map(|p| p.data())
                .unwrap_or(0);
            let sender_uid = sender
                .as_ref()
                .map(|p| {
                    let kuid = p.cred().uid.data() as u32;
                    // 把 tracer 的全局 uid 映射进 tracee 的 user namespace
                    map_id_up(&pcb.cred().user_ns.inner.lock().uid_map, kuid).unwrap_or(u32::MAX)
                })
                .unwrap_or(u32::MAX);
            *i = SigInfo::new(
                injected,
                0,
                SigCode::User,
                SigType::Kill {
                    pid: RawPid(sender_vpid),
                    uid: sender_uid,
                },
            );
        }
    }

    // 若注入的信号被当前掩码阻塞，或有 fatal 信号 pending，则重新入队并返回 None，让 do_signal 继续出队下一个
    let blocked = {
        let g = pcb.sig_info_irqsave();
        g.sig_blocked().contains(injected.into())
    };
    let fatal_pending = Signal::fatal_signal_pending(pcb);
    if blocked || fatal_pending {
        if let Some(i) = info.as_mut() {
            let _ = injected.send_signal_info_to_pcb(Some(i), pcb.clone(), PidType::PID);
        } else {
            let _ = injected.send_signal_info_to_pcb(None, pcb.clone(), PidType::PID);
        }
        return None;
    }

    Some(injected)
}

/// ptrace 系统调用的请求类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PtraceRequest {
    Traceme = 0,
    Peektext = 1,
    Peekdata = 2,
    Peekuser = 3,
    Poketext = 4,
    Pokedata = 5,
    Pokeuser = 6,
    Cont = 7,
    Kill = 8,
    Singlestep = 9,
    Getregs = 12,
    Setregs = 13,
    Attach = 16,
    Detach = 17,
    Syscall = 24,
    Sysemu = 31,
    SysemuSinglestep = 32,
    Setoptions = 0x4200,
    Geteventmsg = 0x4201,
    Getsiginfo = 0x4202,
    Setsiginfo = 0x4203,
    Getregset = 0x4204,
    Setregset = 0x4205,
    Seize = 0x4206,
    Interrupt = 0x4207,
    Listen = 0x4208,
    Getsigmask = 0x420a,
    Setsigmask = 0x420b,
    Getsyscallinfo = 0x420e,
}

impl TryFrom<usize> for PtraceRequest {
    type Error = SystemError;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Traceme),
            1 => Ok(Self::Peektext),
            2 => Ok(Self::Peekdata),
            3 => Ok(Self::Peekuser),
            4 => Ok(Self::Poketext),
            5 => Ok(Self::Pokedata),
            6 => Ok(Self::Pokeuser),
            7 => Ok(Self::Cont),
            8 => Ok(Self::Kill),
            9 => Ok(Self::Singlestep),
            12 => Ok(Self::Getregs),
            13 => Ok(Self::Setregs),
            16 => Ok(Self::Attach),
            17 => Ok(Self::Detach),
            24 => Ok(Self::Syscall),
            31 => Ok(Self::Sysemu),
            32 => Ok(Self::SysemuSinglestep),
            0x4200 => Ok(Self::Setoptions),
            0x4201 => Ok(Self::Geteventmsg),
            0x4202 => Ok(Self::Getsiginfo),
            0x4203 => Ok(Self::Setsiginfo),
            0x4204 => Ok(Self::Getregset),
            0x4205 => Ok(Self::Setregset),
            0x4206 => Ok(Self::Seize),
            0x4207 => Ok(Self::Interrupt),
            0x4208 => Ok(Self::Listen),
            0x420a => Ok(Self::Getsigmask),
            0x420b => Ok(Self::Setsigmask),
            0x420e => Ok(Self::Getsyscallinfo),
            _ => Err(SystemError::EINVAL),
        }
    }
}

/// ptrace 事件类型（PTRACE_EVENT_*）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PtraceEvent {
    Fork = 1,
    VFork = 2,
    Clone = 3,
    Exec = 4,
    VForkDone = 5,
    Exit = 6,
    Seccomp = 7,
    /// PTRACE_EVENT_STOP（128）：seize/INTERRUPT/group-stop 在 seized 模式下产生。
    Stop = 128,
}

/// `PTRACE_GET_SYSCALL_INFO` 的 syscall 消息标识。
pub const PTRACE_EVENTMSG_SYSCALL_ENTRY: usize = 1;
pub const PTRACE_EVENTMSG_SYSCALL_EXIT: usize = 2;

// SIGTRAP 的 si_code 取值
// ptrace tracer（gdb）据 si_code 区分单步 / 硬件断点 / 软件断点。
pub const TRAP_BRKPT: i32 = 1; // 软件断点（int3）
pub const TRAP_TRACE: i32 = 2; // 单步（RFLAGS.TF）
/// DragonOS-v 暂未实现 BTS（分支追踪），保留供未来使用。
#[allow(dead_code)]
pub const TRAP_BRANCH: i32 = 3; // 分支陷阱（BTS）
pub const TRAP_HWBKPT: i32 = 4; // 硬件断点（DR0-3 命中）
/// x86 DR6 中单步位（BS）。do_debug 的 error_code（=DR6）置此位表示单步陷阱。
pub const X86_DR_BS: u64 = 1 << 14;
/// x86 DR6 中硬件断点命中位（B0-B3）。
pub const X86_DR_B_MASK: u64 = 0x0f;

bitflags::bitflags! {
    /// ptrace 选项（PTRACE_O_*）。
    #[derive(Default)]
    pub struct PtraceOptions: usize {
        const TRACESYSGOOD   = 1 << 0;
        const TRACEFORK      = 1 << 1;
        const TRACEVFORK     = 1 << 2;
        const TRACECLONE     = 1 << 3;
        const TRACEEXEC      = 1 << 4;
        const TRACEVFORKDONE = 1 << 5;
        const TRACEEXIT      = 1 << 6;
        const TRACESECCOMP   = 1 << 7;
        const EXITKILL       = 1 << 20;
        const SUSPEND_SECCOMP = 1 << 21;
    }
}

// PTRACE_GET_SYSCALL_INFO 结构
/// `ptrace_syscall_info.op` 取值。
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum PtraceSyscallInfoOp {
    #[default]
    None = 0,
    Entry = 1,
    Exit = 2,
    Seccomp = 3,
}

/// `ptrace_syscall_info.entry`。
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PtraceSyscallInfoEntry {
    pub nr: u64,
    pub args: [u64; 6],
}

/// `ptrace_syscall_info.exit`。
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PtraceSyscallInfoExit {
    pub rval: i64,
    pub is_error: u8,
}

/// `ptrace_syscall_info.seccomp`。
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PtraceSyscallInfoSeccomp {
    pub nr: u64,
    pub args: [u64; 6],
    pub ret_data: u32,
}

/// `ptrace_syscall_info` 的 data 联合体。
#[repr(C)]
#[derive(Clone, Copy)]
pub union PtraceSyscallInfoData {
    pub entry: PtraceSyscallInfoEntry,
    pub exit: PtraceSyscallInfoExit,
    pub seccomp: PtraceSyscallInfoSeccomp,
}

impl Default for PtraceSyscallInfoData {
    fn default() -> Self {
        // SAFETY: 联合体所有字段均为 POD 整数类型，零初始化有效。
        unsafe { core::mem::zeroed() }
    }
}

/// `struct ptrace_syscall_info`。
#[repr(C)]
#[derive(Clone)]
pub struct PtraceSyscallInfo {
    pub op: PtraceSyscallInfoOp,
    pub pad: [u8; 3],
    pub arch: u32,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub data: PtraceSyscallInfoData,
}

impl Default for PtraceSyscallInfo {
    fn default() -> Self {
        // SAFETY: 同 PtraceSyscallInfoData。
        unsafe { core::mem::zeroed() }
    }
}

impl PtraceSyscallInfo {
    /// 最底层构造：填入架构无关的 op/arch/ip/sp，data 留空。
    pub fn new(arch: u32, ip: u64, sp: u64) -> Self {
        Self {
            op: PtraceSyscallInfoOp::None,
            pad: [0; 3],
            arch,
            instruction_pointer: ip,
            stack_pointer: sp,
            data: PtraceSyscallInfoData::default(),
        }
    }

    /// 标记为 Entry 并填充系统调用号与参数。
    pub fn with_entry(mut self, nr: u64, args: [u64; 6]) -> Self {
        self.op = PtraceSyscallInfoOp::Entry;
        self.data.entry = PtraceSyscallInfoEntry { nr, args };
        self
    }

    /// 标记为 Exit 并填充返回值与是否错误。
    pub fn with_exit(mut self, rval: i64, is_error: bool) -> Self {
        self.op = PtraceSyscallInfoOp::Exit;
        self.data.exit = PtraceSyscallInfoExit {
            rval,
            is_error: is_error as u8,
        };
        self
    }

    /// 标记为 Seccomp。
    pub fn with_seccomp(mut self, nr: u64, args: [u64; 6], ret_data: u32) -> Self {
        self.op = PtraceSyscallInfoOp::Seccomp;
        self.data.seccomp = PtraceSyscallInfoSeccomp { nr, args, ret_data };
        self
    }
}

/// 判断系统调用返回值是否为错误
#[inline(always)]
pub fn syscall_retval_is_error(retval: i64) -> bool {
    (-4095..=-1).contains(&retval)
}

// x86_64 用户寄存器
/// x86_64 `struct user_regs_struct`，供 PTRACE_GETREGS/SETREGS/PEEKUSER/POKEUSER 使用。
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct UserRegsStruct {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub bp: u64,
    pub bx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub ax: u64,
    pub cx: u64,
    pub dx: u64,
    pub si: u64,
    pub di: u64,
    /// 系统调用号（DragonOS TrapFrame 的 errcode 字段在 syscall 时存 nr）。
    pub orig_ax: u64,
    pub ip: u64,
    pub cs: u64,
    pub flags: u64,
    pub sp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

#[cfg(target_arch = "x86_64")]
impl UserRegsStruct {
    /// 从 TrapFrame 构造（GETREGS 路径）。
    /// 注意 orig_ax 取 TrapFrame.errcode（syscall 时为系统调用号）。
    pub fn from_trap_frame(frame: &TrapFrame) -> Self {
        Self {
            r15: frame.r15,
            r14: frame.r14,
            r13: frame.r13,
            r12: frame.r12,
            bp: frame.rbp,
            bx: frame.rbx,
            r11: frame.r11,
            r10: frame.r10,
            r9: frame.r9,
            r8: frame.r8,
            ax: frame.rax,
            cx: frame.rcx,
            dx: frame.rdx,
            si: frame.rsi,
            di: frame.rdi,
            orig_ax: frame.errcode,
            ip: frame.rip,
            cs: frame.cs,
            flags: frame.rflags,
            sp: frame.rsp,
            ss: frame.ss,
            fs_base: 0,
            gs_base: 0,
            ds: frame.ds,
            es: frame.es,
            fs: 0,
            gs: 0,
        }
    }

    /// 写回 TrapFrame（SETREGS 路径）。
    /// 安全校验：
    /// - cs/ss 必须 RPL=3 且非零（防 ring-0 注入）
    /// - rflags 仅放行 FLAG_MASK 位，保留 frame 非掩码位（防清 IF 致用户态挂死）
    pub fn write_to_trap_frame(&self, frame: &mut TrapFrame) -> Result<(), SystemError> {
        // 段选择子校验
        // cs/ss: RPL=3，非零（SEGMENT_RPL_MASK=0x3, USER_RPL=3）。
        if (self.cs & 0x3) != 3 || self.cs == 0 {
            return Err(SystemError::EIO);
        }
        if (self.ss & 0x3) != 3 || self.ss == 0 {
            return Err(SystemError::EIO);
        }
        // rflags: 保留 frame 非掩码位，仅放行 FLAG_MASK 位。
        // FLAG_MASK = FLAG_MASK_32 | NT = CF|PF|AF|ZF|SF|TF|DF|RF|AC|NT = 0x00054DD5。
        const FLAG_MASK: u64 = 0x0005_4DD5;
        let new_rflags = (frame.rflags & !FLAG_MASK) | (self.flags & FLAG_MASK);

        frame.r15 = self.r15;
        frame.r14 = self.r14;
        frame.r13 = self.r13;
        frame.r12 = self.r12;
        frame.rbp = self.bp;
        frame.rbx = self.bx;
        frame.r11 = self.r11;
        frame.r10 = self.r10;
        frame.r9 = self.r9;
        frame.r8 = self.r8;
        frame.rax = self.ax;
        frame.rcx = self.cx;
        frame.rdx = self.dx;
        frame.rsi = self.si;
        frame.rdi = self.di;
        frame.errcode = self.orig_ax;
        frame.rip = self.ip;
        frame.cs = self.cs;
        frame.rflags = new_rflags;
        frame.rsp = self.sp;
        frame.ss = self.ss;
        frame.ds = self.ds;
        frame.es = self.es;
        Ok(())
    }
}

/// ELF NT_PRSTATUS note type（PTRACE_GETREGSET/SETREGSET 用）。
pub const NT_PRSTATUS: u32 = 1;

// PtraceState —— 跟踪状态机（对应 Linux task_struct 的 ptrace/jobctl 相关字段）
/// 进程被 ptrace 跟踪时的状态信息。
#[derive(Debug)]
pub struct PtraceState {
    /// 当前 ptrace-stop 的 exit_code（信号号或 `(event<<8)|SIGTRAP` 或 `SIGTRAP|0x80`）。
    pub exit_code: usize,
    /// tracer 在 resume 时注入的信号（0/INVALID 表示不注入）。
    pub injected_signal: Signal,
    /// 最近一次 ptrace-stop 的 siginfo 副本，供 GETSIGINFO/SETSIGINFO 读写。
    /// 必须在持本 `PtraceState` 锁时访问。
    pub last_siginfo: Option<SigInfo>,
    /// 事件消息，供 GETEVENTMSG 读取（fork/clone 的 child pid、syscall entry/exit 标识等）。
    pub event_message: usize,
    /// ptrace 选项（PTRACE_O_*）。
    pub options: PtraceOptions,
    /// PTRACE_LISTEN：tracee 处于 STOP trap 但不被 wait 视为 TRACED。
    pub listening: bool,
    /// 本 stop 仍可被 wait(2) 报告一次；消费后清零（除非 WNOWAT）。一次性标志。
    pub stop_report_pending: bool,
    /// 持久标志：tracee 当前是否处于 ptrace-stop
    pub in_ptrace_stop: bool,
    /// attach 到已 STOPPED 任务时挂起的 PTRACE_EVENT_STOP 信号。
    pub pending_event_stop: Option<Signal>,
    /// TIF_FORCED_TF：true 表示当前 TF 是调试器为 single-step 强制置位。
    pub forced_trap_flag: bool,
    /// 当前 ptrace-stop 的用户 TrapFrame 是否位于 syscall 栈。
    /// 调度上下文保存的 rsp 不能用来猜 TrapFrame 位置。
    pub stop_frame_on_syscall_stack: bool,
    /// 调试寄存器（DR0-DR7）的 ptrace 侧存储。
    pub debug_regs: [u64; 8],
}

impl Default for PtraceState {
    fn default() -> Self {
        Self {
            exit_code: 0,
            injected_signal: Signal::INVALID,
            last_siginfo: None,
            event_message: 0,
            options: PtraceOptions::empty(),
            listening: false,
            stop_report_pending: false,
            in_ptrace_stop: false,
            pending_event_stop: None,
            forced_trap_flag: false,
            stop_frame_on_syscall_stack: false,
            debug_regs: [0; 8],
        }
    }
}

impl PtraceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn consume_stop_report(&mut self, consume: bool) -> Option<i32> {
        if self.listening || !self.stop_report_pending {
            return None;
        }
        let code = self.exit_code as i32;
        if consume {
            self.stop_report_pending = false;
        }
        Some(code)
    }
}

fn traceme_allowed(
    parent: &Arc<ProcessControlBlock>,
    child: &Arc<ProcessControlBlock>,
) -> Result<(), SystemError> {
    if is_ptraced_locked(child) {
        return Err(SystemError::EPERM);
    }
    if parent.flags().contains(ProcessFlags::EXITING) {
        return Err(SystemError::EPERM);
    }

    // Linux also calls security_ptrace_traceme() here. DragonOS does not yet
    // have the equivalent LSM/dumpable/credential/capability hooks wired into
    // ptrace, so keep this as the single future extension point instead of
    // spreading partial checks across syscall and wait code.
    Ok(())
}

fn traceme_parent_for(
    child: &Arc<ProcessControlBlock>,
) -> Result<Arc<ProcessControlBlock>, SystemError> {
    let real_parent = child.real_parent_pcb().ok_or(SystemError::EPERM)?;
    let Some(fork_parent) = child.fork_parent_pcb() else {
        return Ok(real_parent);
    };

    if fork_parent.tgid == real_parent.tgid {
        Ok(fork_parent)
    } else {
        Ok(real_parent)
    }
}

pub fn traceme_current() -> Result<(), SystemError> {
    let _relation_guard = PTRACE_RELATION_LOCK.lock_irqsave();
    let current = ProcessManager::current_pcb();
    let tracer = traceme_parent_for(&current)?;
    traceme_allowed(&tracer, &current)?;

    let raw_pid = current.raw_pid();
    {
        let mut ptracer = current.ptracer_pcb.write_irqsave();
        if ptracer.upgrade().is_some() {
            return Err(SystemError::EPERM);
        }
        *ptracer = Arc::downgrade(&tracer);
        current.flags().insert(ProcessFlags::PTRACED);
    }

    let mut ptraced = tracer.ptraced.write_irqsave();
    if !ptraced.contains(&raw_pid) {
        ptraced.push(raw_pid);
    }

    Ok(())
}

pub fn unlink_tracee(tracee: &Arc<ProcessControlBlock>) {
    let tracer = {
        let _relation_guard = PTRACE_RELATION_LOCK.lock_irqsave();
        let tracer = {
            let mut ptracer = tracee.ptracer_pcb.write_irqsave();
            let tracer = ptracer.upgrade();
            *ptracer = Weak::new();
            tracee.flags().remove(ProcessFlags::PTRACED);
            tracer
        };

        if let Some(tracer) = tracer.as_ref() {
            let raw_pid = tracee.raw_pid();
            tracer.ptraced.write_irqsave().retain(|pid| *pid != raw_pid);
        }
        tracer
    };

    // Linux wakes the ptrace parent before destroying the old leader in
    // de_thread().  DragonOS keeps separate per-task wait queues, so both the
    // tracer and natural parent must recheck their wait ownership after the
    // relation and index update become visible.
    if let Some(tracer) = tracer.as_ref() {
        ProcessManager::wake_wait_parent(tracer);
    }

    if let Some(real_parent) = tracee.real_parent_pcb() {
        if !tracer
            .as_ref()
            .map(|tracer| Arc::ptr_eq(tracer, &real_parent))
            .unwrap_or(false)
        {
            ProcessManager::wake_wait_parent(&real_parent);
        }
    }
}

pub(crate) struct TraceePidExchangePlan {
    left: Option<TraceePidUpdate>,
    right: Option<TraceePidUpdate>,
}

struct TraceePidUpdate {
    tracer: Arc<ProcessControlBlock>,
    index: usize,
    old_pid: RawPid,
    new_pid: RawPid,
}

/// Resolve tracer-side vector positions before entering the global process-map
/// IRQ-off critical section. `PTRACE_RELATION_LOCK` keeps these indices stable
/// until `commit_tracee_pid_exchange_locked()` applies the two O(1) writes.
pub(crate) fn prepare_tracee_pid_exchange_locked(
    left: &Arc<ProcessControlBlock>,
    right: &Arc<ProcessControlBlock>,
    left_old_pid: RawPid,
    right_old_pid: RawPid,
) -> TraceePidExchangePlan {
    let left_tracer = left.ptracer_pcb.read_irqsave().upgrade();
    let right_tracer = right.ptracer_pcb.read_irqsave().upgrade();
    let left = left_tracer.as_ref().map(|tracer| {
        let ptraced = tracer.ptraced.read_irqsave();
        let index = ptraced
            .iter()
            .position(|pid| *pid == left_old_pid)
            .expect("left tracee missing from tracer raw-PID index");
        TraceePidUpdate {
            tracer: tracer.clone(),
            index,
            old_pid: left_old_pid,
            new_pid: right_old_pid,
        }
    });
    let right = right_tracer.as_ref().map(|tracer| {
        let ptraced = tracer.ptraced.read_irqsave();
        let index = ptraced
            .iter()
            .position(|pid| *pid == right_old_pid)
            .expect("right tracee missing from tracer raw-PID index");
        TraceePidUpdate {
            tracer: tracer.clone(),
            index,
            old_pid: right_old_pid,
            new_pid: left_old_pid,
        }
    });

    TraceePidExchangePlan { left, right }
}

/// Update tracer-side raw-PID indices after the corresponding task identities
/// have been exchanged.  The caller must hold `PTRACE_RELATION_LOCK` and must
/// call `prepare_tracee_pid_exchange_locked()` before beginning the identity
/// transaction.
pub(crate) fn commit_tracee_pid_exchange_locked(plan: TraceePidExchangePlan) {
    for update in [plan.left, plan.right].into_iter().flatten() {
        let mut ptraced = update.tracer.ptraced.write_irqsave();
        let entry = ptraced
            .get_mut(update.index)
            .expect("tracee index changed during PID identity exchange");
        assert_eq!(
            *entry, update.old_pid,
            "tracee PID changed during identity exchange"
        );
        *entry = update.new_pid;
    }
}

/// 退出/销毁 tracer 时解除其所有 tracee 的跟踪关系。
pub fn exit_ptrace(tracer: &Arc<ProcessControlBlock>) {
    let _relation_guard = PTRACE_RELATION_LOCK.lock_irqsave();
    let traced_pids: Vec<RawPid> = {
        let mut ptraced = tracer.ptraced.write_irqsave();
        core::mem::take(&mut *ptraced)
    };

    for pid in traced_pids {
        let Some(tracee) = ProcessManager::find(pid) else {
            continue;
        };
        // 仅当 tracee 确实由本 tracer 跟踪时才处理（防止竞态下被换 tracer）。
        let was_traced = {
            let mut ptracer = tracee.ptracer_pcb.write_irqsave();
            let mine = ptracer
                .upgrade()
                .as_ref()
                .map(|t| Arc::ptr_eq(t, tracer))
                .unwrap_or(false);
            if mine {
                *ptracer = Weak::new();
                tracee.flags().remove(ProcessFlags::PTRACED);
            }
            mine
        };
        if !was_traced {
            continue;
        }

        // 若 tracee 开启 PTRACE_O_EXITKILL，tracer 退出时向其发 SIGKILL
        let exitkill = tracee
            .ptrace_state
            .lock_irqsave()
            .options
            .contains(PtraceOptions::EXITKILL);
        // 清 syscall-trace/单步工作位，避免残留。
        tracee.flags().remove(
            ProcessFlags::TRACE_SYSCALL
                | ProcessFlags::TRACE_SINGLESTEP
                | ProcessFlags::TRACE_SYSEMU
                | ProcessFlags::PT_SEIZED,
        );

        // 决策：tracee 是否真的在 ptrace-stop。
        let in_ptrace_stop = {
            let ps = tracee.ptrace_state.lock_irqsave();
            (ps.in_ptrace_stop || ps.listening) && tracee.sched_info().state().is_stopped()
        };
        // 与 ptrace_unlink 对称：tracee 处于 ptrace-stop 时清单步 TF，
        // 避免 detach/退出后 tracee 恢复执行触发 SIGTRAP 风暴。
        if in_ptrace_stop {
            tracee.disable_single_step();
        }
        let group_stop_active = tracee.sighand().flags_contains(SignalFlags::STOP_STOPPED);

        // 清本 stop 的 ptrace 侧状态。
        {
            let mut ps = tracee.ptrace_state.lock_irqsave();
            ps.stop_report_pending = false;
            ps.in_ptrace_stop = false;
            ps.listening = false;
            ps.pending_event_stop = None;
            ps.exit_code = 0;
        }
        tracee.flags().remove(
            ProcessFlags::PTRACE_EVENT_STOP
                | ProcessFlags::PENDING_PTRACE_STOP
                | ProcessFlags::TRAPPING,
        );

        if exitkill {
            // SIGKILL 不可阻塞/忽略，tracee 将被终止
            let _ = Signal::SIGKILL.send_signal_info_to_pcb(None, tracee.clone(), PidType::PID);
        }

        if in_ptrace_stop {
            if group_stop_active {
                // group-stop 仍有效：保持 Stopped，设 CLD_STOPPED 让 real_parent
                // 的 wait 能报告（CLD_STOPPED 是一次性消费位，ptrace 会话期间可能已消费）。
                tracee.sighand().flags_insert(SignalFlags::CLD_STOPPED);
            } else {
                // group-stop 不再有效：无条件唤醒 tracee 脱离 ptrace_stop。
                let _ = ProcessManager::wakeup_stop(&tracee);
            }
            // real_parent 的 wait 唤醒独立于 tracee 唤醒（存在则通知）。
            if let Some(real_parent) = tracee.real_parent_pcb() {
                ProcessManager::wake_wait_parent(&real_parent);
            }
        } else if let Some(real_parent) = tracee.real_parent_pcb() {
            // 非 ptrace-stop（如运行中）：唤醒等待者（parent + leader）。
            ProcessManager::wake_wait_parent(&real_parent);
        }
    }
}

pub fn tracees_of(tracer: &Arc<ProcessControlBlock>) -> Vec<RawPid> {
    let _relation_guard = PTRACE_RELATION_LOCK.lock_irqsave();
    tracees_of_locked(tracer)
}

fn tracees_of_locked(tracer: &Arc<ProcessControlBlock>) -> Vec<RawPid> {
    tracer.ptraced.read_irqsave().clone()
}

pub fn ptracer_of(tracee: &Arc<ProcessControlBlock>) -> Option<Arc<ProcessControlBlock>> {
    let _relation_guard = PTRACE_RELATION_LOCK.lock_irqsave();
    ptracer_of_locked(tracee)
}

/// Return the tracee's ptracer while the caller holds `PTRACE_RELATION_LOCK`.
pub(crate) fn ptracer_of_locked(
    tracee: &Arc<ProcessControlBlock>,
) -> Option<Arc<ProcessControlBlock>> {
    tracee.ptracer_pcb.read_irqsave().upgrade()
}

pub fn is_ptraced(tracee: &ProcessControlBlock) -> bool {
    let _relation_guard = PTRACE_RELATION_LOCK.lock_irqsave();
    is_ptraced_locked(tracee)
}

fn is_ptraced_locked(tracee: &ProcessControlBlock) -> bool {
    tracee.flags().contains(ProcessFlags::PTRACED)
        && tracee.ptracer_pcb.read_irqsave().upgrade().is_some()
}

pub fn is_wait_tracee_of(
    tracee: &Arc<ProcessControlBlock>,
    waiter: &Arc<ProcessControlBlock>,
    options: WaitOption,
) -> bool {
    let _relation_guard = PTRACE_RELATION_LOCK.lock_irqsave();
    let Some(tracer) = ptracer_of_locked(tracee) else {
        return false;
    };

    let same_waiter = Arc::ptr_eq(&tracer, waiter);
    let same_thread_group = !options.contains(WaitOption::WNOTHREAD) && tracer.tgid == waiter.tgid;
    if !same_waiter && !same_thread_group {
        return false;
    }

    tracees_of_locked(&tracer).contains(&tracee.raw_pid())
}

// PCB ptrace 方法 —— 关系建立/解除、attach/seize/detach、TRAPPING 同步
impl ProcessControlBlock {
    /// 是否有权限跟踪目标。简化版：
    /// 同线程组允许（自省）；否则要求 uid/gid 全匹配且 dumpable；或 CAP_SYS_PTRACE。
    pub fn has_permission_to_trace(&self, tracee: &Self) -> bool {
        // 1. 同一线程组允许访问（自省）
        if self.tgid == tracee.tgid {
            return true;
        }

        // 2. 凭证匹配 + dumpable
        let caller_cred = self.cred();
        let tracee_cred = tracee.cred();
        let uid_match = caller_cred.uid == tracee_cred.euid
            && caller_cred.uid == tracee_cred.suid
            && caller_cred.uid == tracee_cred.uid;
        let gid_match = caller_cred.gid == tracee_cred.egid
            && caller_cred.gid == tracee_cred.sgid
            && caller_cred.gid == tracee_cred.gid;
        if uid_match && gid_match && tracee.dumpable() != 0 {
            return true;
        }

        // 3. CAP_SYS_PTRACE
        caller_cred.has_capability(crate::process::cred::CAPFlags::CAP_SYS_PTRACE)
    }

    /// 建立跟踪关系（tracee 侧调用）。
    /// 调用者不必持 `PTRACE_RELATION_LOCK`函数会自行获取。
    pub fn ptrace_link(&self, tracer: &Arc<ProcessControlBlock>) -> Result<(), SystemError> {
        if !tracer.has_permission_to_trace(self) {
            return Err(SystemError::EPERM);
        }

        let raw_pid = self.raw_pid();
        let _relation_guard = PTRACE_RELATION_LOCK.lock_irqsave();

        {
            let mut ptracer = self.ptracer_pcb.write_irqsave();
            if ptracer.upgrade().is_some() {
                // 已经被跟踪
                return Err(SystemError::EPERM);
            }
            // 拒绝正在退出/已退出的目标
            if self.exit_state() != ExitState::Running {
                return Err(SystemError::EPERM);
            }
            *ptracer = Arc::downgrade(tracer);
            self.flags().insert(ProcessFlags::PTRACED);
        }

        let mut ptraced = tracer.ptraced.write_irqsave();
        if !ptraced.contains(&raw_pid) {
            ptraced.push(raw_pid);
        }
        Ok(())
    }

    /// 解除跟踪关系，并按 group-stop 状态恢复 tracee 执行状态。
    /// 从 ptraced 列表移除、清 syscall-trace 工作、按 group-stop 决定 TracedStopped→Stopped 或唤醒。
    pub fn ptrace_unlink(&self) -> Result<(), SystemError> {
        let _relation_guard = PTRACE_RELATION_LOCK.lock_irqsave();

        // 取出 tracer 并清关系（复用 unlink_tracee 的核心，但需要后续状态决策）。
        let tracer = {
            let mut ptracer = self.ptracer_pcb.write_irqsave();
            let t = ptracer.upgrade();
            *ptracer = Weak::new();
            self.flags().remove(ProcessFlags::PTRACED);
            t
        };
        if let Some(tracer) = tracer.as_ref() {
            let raw_pid = self.raw_pid();
            tracer.ptraced.write_irqsave().retain(|p| *p != raw_pid);
        }

        // 清除 syscall-trace / 单步工作位，避免 detach 后残留。
        #[cfg(target_arch = "x86_64")]
        self.disable_single_step();

        self.flags().remove(
            ProcessFlags::TRACE_SYSCALL
                | ProcessFlags::TRACE_SINGLESTEP
                | ProcessFlags::TRACE_SYSEMU
                | ProcessFlags::PT_SEIZED,
        );
        // 决策：tracee 当前是否真的在 ptrace-stop（schedule 已完成 state=Stopped）。
        let in_ptrace_stop = {
            let ps = self.ptrace_state.lock_irqsave();
            (ps.in_ptrace_stop || ps.listening) && self.sched_info().state().is_stopped()
        };
        let group_stop_active = self.sighand().flags_contains(SignalFlags::STOP_STOPPED);

        // 清本 stop 的 ptrace 侧状态。
        {
            let mut ps = self.ptrace_state.lock_irqsave();
            ps.stop_report_pending = false;
            ps.in_ptrace_stop = false;
            ps.listening = false;
            ps.pending_event_stop = None;
            ps.exit_code = 0;
        }
        self.flags().remove(
            ProcessFlags::PTRACE_EVENT_STOP
                | ProcessFlags::PENDING_PTRACE_STOP
                | ProcessFlags::TRAPPING,
        );

        if in_ptrace_stop {
            if let Some(strong) = self.self_ref.upgrade() {
                if group_stop_active {
                    // group stop 仍有效：保持 Stopped（child 本就已 Stopped）
                } else {
                    // group stop 不再有效：唤醒 tracee。
                    let _ = ProcessManager::wakeup_stop(&strong);
                }
            }
        }

        Ok(())
    }

    /// 当前是否被跟踪。
    pub fn is_traced(&self) -> bool {
        let _g = PTRACE_RELATION_LOCK.lock_irqsave();
        is_ptraced_locked(self)
    }

    /// 当前是否被指定 tracer 跟踪。
    pub fn is_traced_by(&self, tracer: &Arc<ProcessControlBlock>) -> bool {
        // 不能用 self（&ProcessControlBlock）调 ptracer_of_locked（要 &Arc），
        // 改用 pub API ptracer_of，它自行取关系锁。
        match ptracer_of(&self.self_ref.upgrade().unwrap_or_else(|| tracer.clone())) {
            Some(t) => Arc::ptr_eq(&t, tracer),
            None => false,
        }
    }

    fn ptrace_set_trapping(&self) {
        self.flags().insert(ProcessFlags::TRAPPING);
    }

    fn ptrace_clear_trapping(&self) {
        let was_trapping = self.flags().test_and_clear(ProcessFlags::TRAPPING);
        if was_trapping {
            // 唤醒 attach 等待者
            self.wait_queue
                .wakeup_all(Some(ProcessState::Blocked(true)));
        }
    }

    /// attach 端等待 tracee 完成 STOPPED→TRACED 过渡（TRAPPING 清零）。
    fn ptrace_wait_trapping_cleared(&self) {
        let _ = self.wait_queue.wait_event_killable(
            || !self.flags().contains(ProcessFlags::TRAPPING),
            None::<fn()>,
        );
    }

    /// 若 tracee 当前处于 group-stop（Stopped），将其直接转换为 ptrace-stop。
    fn ptrace_arm_attach_trap_if_stopped(&self) -> bool {
        // 临界区内仅做 state 重判 + ptrace_state 提交；notify 移出 pi_lock
        let stop_sig;
        #[cfg(target_arch = "x86_64")]
        let on_syscall_stack;
        #[cfg(not(target_arch = "x86_64"))]
        let on_syscall_stack = false;

        {
            let _pi = self.sched_info().pi_lock_irqsave();
            if !self.sched_info().state().is_stopped() {
                return false;
            }
            self.ptrace_set_trapping();
            // 用 group-stop 的信号作为 exit_code（低 7 位）。
            stop_sig = self.sighand().stop_signal();

            #[cfg(target_arch = "x86_64")]
            {
                let saved_rsp = self.arch_info_irqsave().kernel_rsp();
                let s = self.syscall_stack();
                let start = s.start_address().data();
                let end = s.stack_max_address().data();
                on_syscall_stack = (start..end).contains(&saved_rsp);
            }

            // 提交合成 ptrace-stop 标志；并补 PENDING_PTRACE_STOP 兜底：即使 pi_lock
            // 释放后 wakeup_stop 抢先唤醒 tracee，返回用户态路径（do_signal_or_restart）
            // 也必消费 PENDING 重新陷入 ptrace_event_stop，不丢 stop 报告。
            {
                let mut ps = self.ptrace_state.lock_irqsave();
                ps.in_ptrace_stop = true;
                ps.stop_report_pending = true;
                ps.exit_code = stop_sig as usize;
                ps.listening = false;
                ps.last_siginfo = None;
                ps.stop_frame_on_syscall_stack = on_syscall_stack;
            }
            self.flags().insert(ProcessFlags::PENDING_PTRACE_STOP);
        }
        // tracee 已 Stopped，TRAPPING 可立即清除（无需等待 tracee 重新调度）。
        self.ptrace_clear_trapping();
        // 合成 stop 不经 tracee 运行路径，必须显式通知 tracer 的 wait_queue，
        // 否则 tracer 的 waitpid 在 wait_event_interruptible 上不会被唤醒。
        if let Some(tracer) = self.ptracer_pcb() {
            tracer.wake_all_waiters();
        }
        true
    }

    pub fn ptrace_attach(&self, tracer: &Arc<ProcessControlBlock>) -> Result<isize, SystemError> {
        let is_same_thread_group = tracer.tgid == self.tgid;

        if !tracer.has_permission_to_trace(self)
            || self.flags().contains(ProcessFlags::KTHREAD)
            || is_same_thread_group
        {
            return Err(SystemError::EPERM);
        }

        self.ptrace_link(tracer)?;
        let strong_ref = self.self_ref.upgrade().ok_or_else(|| {
            // self_ref 升级失败：进程正在销毁，回滚关系。
            let _ = self.ptrace_unlink();
            SystemError::ESRCH
        })?;

        // 非 SEIZE 的 ATTACH：
        // 若目标已处于 group-stop（Stopped），直接将其 group-stop 转为 ptrace-stop
        // 仅当目标未 Stopped 时才发 SIGSTOP 让其停止。
        if self.ptrace_arm_attach_trap_if_stopped() {
            // 目标已 group-stop：合成 ptrace-stop（last_siginfo=None），清 TRAPPING。
            self.ptrace_wait_trapping_cleared();
        } else {
            let mut info = SigInfo::new(
                Signal::SIGSTOP,
                0,
                SigCode::Kernel,
                SigType::Kill {
                    pid: RawPid(0),
                    uid: 0,
                },
            );
            if let Err(e) = Signal::SIGSTOP.send_signal_info_to_pcb(
                Some(&mut info),
                strong_ref.clone(),
                PidType::PID,
            ) {
                let _ = self.ptrace_unlink();
                return Err(e);
            }
        }

        Ok(0)
    }

    /// 处理 PTRACE_SEIZE。
    /// 不发送 SIGSTOP，设置 PT_SEIZED + 选项。
    pub fn ptrace_seize(
        &self,
        tracer: &Arc<ProcessControlBlock>,
        options: PtraceOptions,
    ) -> Result<isize, SystemError> {
        let is_same_thread_group = tracer.tgid == self.tgid;

        if !tracer.has_permission_to_trace(self)
            || self.flags().contains(ProcessFlags::KTHREAD)
            || is_same_thread_group
        {
            return Err(SystemError::EPERM);
        }

        self.ptrace_link(tracer)?;
        self.flags().insert(ProcessFlags::PT_SEIZED);
        {
            let mut ps = self.ptrace_state.lock_irqsave();
            ps.options = options;
        }
        Ok(0)
    }

    /// 处理 PTRACE_DETACH。
    pub fn ptrace_detach(&self, signal: Option<Signal>) -> Result<isize, SystemError> {
        let current_pcb = ProcessManager::current_pcb();
        if !self.is_traced_by(&current_pcb) {
            return Err(SystemError::EPERM);
        }

        // data=0 表示不注入信号
        let data_signal = match signal {
            None => Signal::INVALID,
            Some(s) => {
                if s == Signal::INVALID {
                    return Err(SystemError::EIO);
                }
                s
            }
        };
        {
            let mut ps = self.ptrace_state.lock_irqsave();
            ps.injected_signal = data_signal;
            ps.pending_event_stop = None;
            ps.stop_report_pending = false;
            // 不在此处清 in_ptrace_stop 让 ptrace_unlink 读到它，才能正确唤醒 tracee。
        }
        self.flags().remove(ProcessFlags::PTRACE_EVENT_STOP);

        self.ptrace_unlink()?;
        Ok(0)
    }

    /// ptrace 操作前置检查：tracee 是否由 current 跟踪且处于可操作状态。
    pub fn ptrace_check_attach(&self, request: PtraceRequest) -> Result<(), SystemError> {
        let current = ProcessManager::current_pcb();
        if !self.is_traced_by(&current) {
            return Err(SystemError::ESRCH);
        }
        // KILL/INTERRUPT 允许在任意状态
        if matches!(request, PtraceRequest::Kill | PtraceRequest::Interrupt) {
            return Ok(());
        }
        // LISTEN 状态下不可操作
        if self.ptrace_state.lock_irqsave().listening {
            return Err(SystemError::ESRCH);
        }
        // 其余请求要求 tracee 处于 ptrace-stop。
        let in_stop = {
            let ps = self.ptrace_state.lock_irqsave();
            ps.in_ptrace_stop && self.sched_info().state().is_stopped()
        };
        if !in_stop {
            return Err(SystemError::ESRCH);
        }
        Ok(())
    }

    /// 设置 ptrace 选项（PTRACE_SETOPTIONS）。
    pub fn set_ptrace_options(&self, options: PtraceOptions) -> Result<(), SystemError> {
        if options.contains(PtraceOptions::SUSPEND_SECCOMP) {
            return Err(SystemError::EPERM);
        }
        let mut ps = self.ptrace_state.lock_irqsave();
        ps.options = options;
        Ok(())
    }

    /// 读最近一次 event message（PTRACE_GETEVENTMSG）。
    pub fn ptrace_get_event_message(&self) -> usize {
        self.ptrace_state.lock_irqsave().event_message
    }

    /// 系统调用栈访问器（ptrace 需要读 syscall 栈上的 trap frame）。
    fn syscall_stack(&self) -> crate::libs::rwlock::RwLockReadGuard<'_, KernelStack> {
        self.syscall_stack.read()
    }

    /// 检查当前 rsp 是否在 syscall 栈范围内
    /// 用于在 ptrace_stop 中动态判断 TrapFrame 在哪个栈上。
    #[cfg(target_arch = "x86_64")]
    fn current_stop_frame_on_syscall_stack(&self) -> bool {
        let current_rsp = x86::current::registers::rsp() as usize;
        let syscall_stack = self.syscall_stack();
        let start = syscall_stack.start_address().data();
        let end = syscall_stack.stack_max_address().data();
        (start..end).contains(&current_rsp)
    }

    /// 计算 kernel 栈上的 TrapFrame 指针。
    fn trap_frame_ptr_on_kernel_stack(stack: &KernelStack) -> *mut TrapFrame {
        let ptr = stack.stack_max_address().data() - size_of::<TrapFrame>();
        ptr as *mut TrapFrame
    }

    /// 计算 syscall 栈上的 TrapFrame 指针。
    /// 注意：init_syscall_stack 设 GS:0x0 = stack_max - 8（预留 8 字节），
    /// 所以 TrapFrame 实际在 stack_max - 8 - sizeof(TrapFrame)。
    #[cfg(target_arch = "x86_64")]
    fn trap_frame_ptr_on_syscall_stack(stack: &KernelStack) -> *mut TrapFrame {
        let ptr = stack.stack_max_address().data() - 8 - size_of::<TrapFrame>();
        ptr as *mut TrapFrame
    }

    /// 返回 tracee 当前 stop 对应的用户态 TrapFrame 指针。
    /// 根据 stop_frame_on_syscall_stack 选择正确的栈和偏移。
    fn tracee_trap_frame_ptr(&self) -> *mut TrapFrame {
        let on_syscall_stack = self.ptrace_state.lock_irqsave().stop_frame_on_syscall_stack;
        if on_syscall_stack {
            #[cfg(target_arch = "x86_64")]
            {
                let s = self.syscall_stack();
                Self::trap_frame_ptr_on_syscall_stack(&s)
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                let s = self.kernel_stack();
                Self::trap_frame_ptr_on_kernel_stack(&s)
            }
        } else {
            let s = self.kernel_stack();
            Self::trap_frame_ptr_on_kernel_stack(&s)
        }
    }

    /// 读 tracee 的用户寄存器（PTRACE_GETREGS）。
    #[cfg(target_arch = "x86_64")]
    pub fn tracee_user_regs(&self) -> UserRegsStruct {
        // SAFETY: tracee 处于 ptrace-stop，TrapFrame 稳定。
        let frame = unsafe { &*self.tracee_trap_frame_ptr() };
        UserRegsStruct::from_trap_frame(frame)
    }

    /// 写 tracee 的用户寄存器（PTRACE_SETREGS）。
    /// 返回 EIO 当段选择子/rflags 校验失败。
    #[cfg(target_arch = "x86_64")]
    pub fn write_tracee_user_regs(&self, regs: &UserRegsStruct) -> Result<(), SystemError> {
        // SAFETY: tracee 处于 ptrace-stop。
        let frame = unsafe { &mut *self.tracee_trap_frame_ptr() };
        regs.write_to_trap_frame(frame)?;
        let mut ps = self.ptrace_state.lock_irqsave();
        const X86_EFLAGS_TF: u64 = 0x100;
        if frame.rflags & X86_EFLAGS_TF != 0 {
            ps.forced_trap_flag = false;
        } else if ps.forced_trap_flag {
            frame.rflags |= X86_EFLAGS_TF;
        }
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    pub fn ptrace_peek_user(&self, offset: usize) -> Result<usize, SystemError> {
        // 对齐校验：要求 8 字节对齐。
        if offset & (size_of::<u64>() - 1) != 0 {
            return Err(SystemError::EIO);
        }
        const SIZEOF_USER: usize = 928; // sizeof(struct user) x86_64
        const DR_OFFSET: usize = 848; // offsetof(struct user, u_debugreg[0])
        const GP_REGS_SIZE: usize = size_of::<UserRegsStruct>(); // 216
        if offset
            .checked_add(size_of::<u64>())
            .is_none_or(|end| end > SIZEOF_USER)
        {
            return Err(SystemError::EIO);
        }
        // 通用寄存器区：offset 0..GP_REGS_SIZE
        if offset < GP_REGS_SIZE {
            let regs = self.tracee_user_regs();
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &regs as *const UserRegsStruct as *const u8,
                    GP_REGS_SIZE,
                )
            };
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[offset..offset + 8]);
            return Ok(u64::from_ne_bytes(buf) as usize);
        }
        // 调试寄存器区：offset DR_OFFSET..=DR_OFFSET+56 (DR0-DR7, 8个slot)
        if (DR_OFFSET..DR_OFFSET + 8 * 8).contains(&offset) {
            let idx = (offset - DR_OFFSET) / 8;
            let mut val = self.ptrace_state.lock_irqsave().debug_regs[idx];
            // DR6(slot6) 存储的是 virtual_dr6（正极性），返回时翻转回硬件极性。
            if idx == 6 {
                val ^= 0xffff_0ff0; // DR6_RESERVED
            }
            return Ok(val as usize);
        }
        // 间隙区（GP_REGS_SIZE..DR_OFFSET 之间的填充字段）静默返回 0。
        Ok(0)
    }

    /// PTRACE_POKEUSER：按字节偏移写一个字。
    /// 要求 8 字节对齐，经 putreg 校验。
    #[cfg(target_arch = "x86_64")]
    pub fn ptrace_poke_user(&self, offset: usize, value: usize) -> Result<(), SystemError> {
        const SIZEOF_USER: usize = 928;
        const DR_OFFSET: usize = 848;
        const GP_REGS_SIZE: usize = size_of::<UserRegsStruct>();
        if offset & (size_of::<u64>() - 1) != 0 {
            return Err(SystemError::EIO);
        }
        if offset
            .checked_add(size_of::<u64>())
            .is_none_or(|end| end > SIZEOF_USER)
        {
            return Err(SystemError::EIO);
        }
        let val = value as u64;
        // 通用寄存器区：经 putreg 校验后写回 trap frame。
        if offset < GP_REGS_SIZE {
            let mut regs = self.tracee_user_regs();
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    &mut regs as *mut UserRegsStruct as *mut u8,
                    GP_REGS_SIZE,
                )
            };
            bytes[offset..offset + 8].copy_from_slice(&val.to_ne_bytes());
            self.write_tracee_user_regs(&regs)?;
            return Ok(());
        }
        // 调试寄存器区。
        if (DR_OFFSET..DR_OFFSET + 8 * 8).contains(&offset) {
            let idx = (offset - DR_OFFSET) / 8;
            // DR4/DR5 不存在，拒绝写入。
            if idx == 4 || idx == 5 {
                return Err(SystemError::EIO);
            }
            let mut ps = self.ptrace_state.lock_irqsave();
            // DR6(slot6) 存储正极性 virtual_dr6，写入时翻转。
            let stored = if idx == 6 { val ^ 0xffff_0ff0 } else { val };
            ps.debug_regs[idx] = stored;
            return Ok(());
        }
        // 间隙区拒绝写入。
        Err(SystemError::EIO)
    }

    /// PTRACE_GETSIGINFO：读 last_siginfo。
    pub fn ptrace_get_siginfo(&self) -> Result<SigInfo, SystemError> {
        let ps = self.ptrace_state.lock_irqsave();
        ps.last_siginfo.ok_or(SystemError::EINVAL)
    }

    /// PTRACE_SETSIGINFO：写 last_siginfo。
    pub fn ptrace_set_siginfo(&self, info: SigInfo) -> Result<(), SystemError> {
        let mut ps = self.ptrace_state.lock_irqsave();
        if ps.last_siginfo.is_none() {
            return Err(SystemError::EINVAL);
        }
        ps.last_siginfo = Some(info);
        Ok(())
    }

    /// PTRACE_GETSIGMASK：读当前阻塞掩码。
    /// 返回 SigSet（DragonOS-v GenericSigSet，u64）。
    pub fn ptrace_get_sigmask(&self) -> SigSet {
        let g = self.sig_info_irqsave();
        *g.sig_blocked()
    }

    /// PTRACE_SETSIGMASK：设置阻塞掩码（SIGKILL/SIGSTOP 不可阻塞）。
    pub fn ptrace_set_sigmask(&self, mut new_set: SigSet) {
        new_set.remove(SigSet::SIGKILL);
        new_set.remove(SigSet::SIGSTOP);
        let mut g = self.sig_info_mut();
        *g.sig_block_mut() = new_set;
    }

    // PEEKDATA / POKEDATA —— 通过页表翻译访问 tracee 用户内存

    /// PTRACE_PEEKDATA/PEEKTEXT：读 tracee 用户空间一个 word。
    /// 通过 tracee 的 AddressSpace 页表翻译虚拟地址→物理地址→内核可访问虚拟地址。
    /// 正确处理跨页 word（addr 位于页尾时 8 字节跨两页）。
    pub fn ptrace_peek_data(&self, addr: usize) -> Result<usize, SystemError> {
        // 防回绕校验
        let last = addr
            .checked_add(size_of::<usize>() - 1)
            .ok_or(SystemError::EIO)?;
        if last >= MMArch::USER_END_VADDR.data() {
            return Err(SystemError::EIO);
        }
        let mut bytes = [0u8; size_of::<usize>()];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = self.peek_user_byte(addr + i)?;
        }
        Ok(usize::from_ne_bytes(bytes))
    }

    /// PTRACE_POKEDATA/POKETEXT：写 tracee 用户空间一个 word。
    /// 正确处理跨页 word。
    pub fn ptrace_poke_data(&self, addr: usize, value: usize) -> Result<(), SystemError> {
        let last = addr
            .checked_add(size_of::<usize>() - 1)
            .ok_or(SystemError::EIO)?;
        if last >= MMArch::USER_END_VADDR.data() {
            return Err(SystemError::EIO);
        }
        let bytes = value.to_ne_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            self.poke_user_byte(addr + i, b)?;
        }
        Ok(())
    }

    /// 读 tracee 用户空间单个字节（PEEKDATA 跨页安全的基础）。
    /// 经 tracee AddressSpace 缺页 fault-in（只读，FOLL_FORCE|FOLL_REMOTE），再翻译页表读。
    /// 字节拷贝在 AddressSpace 读锁内完成，避免物理页在 resolve 返回后失效。
    pub(crate) fn peek_user_byte(&self, addr: usize) -> Result<u8, SystemError> {
        self.access_user_byte(addr, false, 0)
            .map(|v| v.unwrap_or(0))
    }
    /// 写 tracee 用户空间单个字节（POKEDATA 跨页安全的基础）。
    /// 字节拷贝在 AddressSpace 读锁内完成，避免物理页在 resolve 返回后失效。
    pub(crate) fn poke_user_byte(&self, addr: usize, value: u8) -> Result<(), SystemError> {
        self.access_user_byte(addr, true, value).map(|_| ())
    }

    /// 在 AddressSpace 读锁保护内解析物理地址并完成单字节拷贝。
    fn access_user_byte(
        &self,
        addr: usize,
        write: bool,
        value: u8,
    ) -> Result<Option<u8>, SystemError> {
        let basic = self.basic();
        let target_vm = basic.user_vm().clone().ok_or(SystemError::ESRCH)?;
        drop(basic);

        let address = VirtAddr::new(addr);
        let page_offset = addr & (MMArch::PAGE_SIZE - 1);
        let mut faulted = false;

        loop {
            // 先尝试 translate + 锁内拷贝（已映射页直接操作）
            let target_guard = target_vm.read();
            if let Some(_vma) = target_guard.mappings.contains(address) {
                if let Some((phys_frame, entry_flags)) =
                    target_guard.user_mapper.utable.translate(address)
                {
                    if !write || entry_flags.has_write() {
                        let kernel_vaddr = unsafe {
                            MMArch::phys_2_virt(PhysAddr::new(phys_frame.data() + page_offset))
                        }
                        .ok_or(SystemError::EIO)?;
                        // 读锁内完成拷贝：此期间兄弟线程无法 munmap/COW 替换该页。
                        return Ok(if write {
                            unsafe { *(kernel_vaddr.data() as *mut u8) = value };
                            None
                        } else {
                            Some(unsafe { *(kernel_vaddr.data() as *const u8) })
                        });
                    }
                    // 写命中已映射的只读页且尚未 fault-in：落到下方触发写时复制
                }
            }
            drop(target_guard);

            if faulted {
                return Err(SystemError::EIO);
            }

            // fault-in：触发缺页处理使页表建立映射（在 read 锁外，避免与 write 锁自死锁）。
            Self::fault_in_tracee_page(&target_vm, address, write)?;
            faulted = true;
        }
    }

    /// 在 tracee 地址空间中 fault-in 一个页。
    /// 对 file-backed VMA 先 prefault page_cache，再 handle_mm_fault（设 FAULT_FLAG_REMOTE）。
    fn fault_in_tracee_page(
        target_vm: &Arc<ucontext::AddressSpace>,
        address: VirtAddr,
        write: bool,
    ) -> Result<(), SystemError> {
        let mut flags = fault::FaultFlags::FAULT_FLAG_REMOTE;
        if write {
            flags |= fault::FaultFlags::FAULT_FLAG_WRITE;
        }

        // 对 file-backed VMA 预建 page_cache，确保后续 handle_mm_fault 能命中。
        let file_backed_vma = {
            let space_guard = target_vm.read();
            let vma = match space_guard.mappings.find_nearest(address) {
                Some(vma) => vma,
                None => return Err(SystemError::EIO),
            };
            let vma_guard = vma.lock();
            if vma_guard.region().contains(address) && vma_guard.vm_file().is_some() {
                Some(vma.clone())
            } else {
                None
            }
        };

        if let Some(vma) = file_backed_vma {
            Self::prefault_file_backing(&vma, address)?;
        }

        // handle_mm_fault
        let mut space_guard = target_vm.write();
        let vma = match space_guard.mappings.find_nearest(address) {
            Some(vma) => vma,
            None => return Err(SystemError::EIO),
        };

        let vma_guard = vma.lock();
        let region = *vma_guard.region();
        let vm_flags = *vma_guard.vm_flags();
        drop(vma_guard);

        if !region.contains(address) {
            if !vm_flags.contains(VmFlags::VM_GROWSDOWN) {
                return Err(SystemError::EIO);
            }
            let extension_size = region.start().data() - address.data();
            let max_stack_limit = space_guard
                .user_stack
                .as_ref()
                .map(|s| s.max_limit())
                .unwrap_or(0);
            if extension_size > max_stack_limit || !space_guard.can_extend_stack(extension_size) {
                return Err(SystemError::EIO);
            }
            space_guard
                .extend_stack(extension_size)
                .map_err(|_| SystemError::EIO)?;
        }

        let fault = unsafe {
            let mm = space_guard.outer_addr_space().ok_or(SystemError::EFAULT)?;
            let mapper = &mut space_guard.user_mapper.utable;
            fault::PageFaultHandler::handle_mm_fault(fault::PageFaultMessage::new(
                vma, address, flags, mapper, mm,
            ))
        };

        if fault.reason.contains(VmFaultReason::VM_FAULT_COMPLETED) {
            Ok(())
        } else {
            Err(SystemError::EIO)
        }
    }

    /// 预建 file-backed VMA 的 page_cache 页。
    fn prefault_file_backing(
        vma: &Arc<ucontext::LockedVMA>,
        address: VirtAddr,
    ) -> Result<(), SystemError> {
        let (file, base_pgoff, region_start) = {
            let vma_guard = vma.lock();
            let file = vma_guard.vm_file().ok_or(SystemError::EIO)?;
            let base_pgoff = vma_guard.backing_page_offset().ok_or(SystemError::EIO)?;
            (file, base_pgoff, vma_guard.region().start().data())
        };

        let page_index = base_pgoff + ((address.data() - region_start) >> MMArch::PAGE_SHIFT);
        let inode = file.inode();
        let file_size = inode.metadata()?.size.max(0) as usize;
        if file_size == 0 || page_index.saturating_mul(MMArch::PAGE_SIZE) >= file_size {
            return Err(SystemError::EIO);
        }

        let page_cache = inode.page_cache().ok_or(SystemError::EIO)?;
        let _ = page_cache.manager().commit_page(page_index)?;
        Ok(())
    }

    /// PTRACE_GET_SYSCALL_INFO。
    /// 根据 last_siginfo 的 si_code（SIGTRAP|0x80 syscall，或 SIGTRAP|(SECCOMP<<8)）
    /// 和 event_message（ENTRY/EXIT）决定 op，读 trap frame 填 nr/args/ip/sp。
    #[cfg(target_arch = "x86_64")]
    pub fn ptrace_get_syscall_info(
        &self,
        _user_size: usize,
    ) -> Result<PtraceSyscallInfo, SystemError> {
        let (op, ret_data) = {
            let ps = self.ptrace_state.lock_irqsave();
            let code = ps
                .last_siginfo
                .as_ref()
                .map(|i| i.sig_code().as_i32())
                .unwrap_or(0);
            let msg = ps.event_message;
            let op = match (code, msg) {
                (c, PTRACE_EVENTMSG_SYSCALL_ENTRY)
                    if (c & 0xff) == (Signal::SIGTRAP as i32 | 0x80) =>
                {
                    PtraceSyscallInfoOp::Entry
                }
                (c, PTRACE_EVENTMSG_SYSCALL_EXIT)
                    if (c & 0xff) == (Signal::SIGTRAP as i32 | 0x80) =>
                {
                    PtraceSyscallInfoOp::Exit
                }
                _ if (code >> 8) == PtraceEvent::Seccomp as i32 => PtraceSyscallInfoOp::Seccomp,
                _ => PtraceSyscallInfoOp::None,
            };
            // Seccomp 停止时 ret_data = SECCOMP_RET_DATA
            let ret_data = if op == PtraceSyscallInfoOp::Seccomp {
                msg as u32
            } else {
                0
            };
            (op, ret_data)
        };
        // 读 trap frame 填 ip/sp/nr/args。
        let frame = unsafe { &*self.tracee_trap_frame_ptr() };
        // AUDIT_ARCH_X86_64（x86_64 唯一支持架构；多架构时改为 arch 提供）。
        let arch: u32 = 0xC000003E;
        let mut info = PtraceSyscallInfo::new(arch, frame.rip, frame.rsp);
        match op {
            PtraceSyscallInfoOp::Entry | PtraceSyscallInfoOp::Seccomp => {
                let nr = frame.errcode;
                let args = [
                    frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
                ];
                info = info.with_entry(nr, args);
                if op == PtraceSyscallInfoOp::Seccomp {
                    info = info.with_seccomp(nr, args, ret_data);
                }
            }
            PtraceSyscallInfoOp::Exit => {
                let rval = frame.rax as i64;
                let is_error = syscall_retval_is_error(rval);
                info = info.with_exit(rval, is_error);
            }
            PtraceSyscallInfoOp::None => {}
        }
        Ok(info)
    }

    // 核心停止状态机

    /// 进入 ptrace-stop
    pub fn ptrace_stop(
        &self,
        exit_code: usize,
        why: SigChildCode,
        info: Option<&mut SigInfo>,
    ) -> usize {
        // 1. 关中断（schedule 前才释放，保证检查与 commit 原子）。
        let irq = unsafe { CurrentIrqArch::save_and_disable_irq() };

        // 2. 关系检查 + arm TRAPPING + commit Stopped 必须在同一 PTRACE_RELATION_LOCK 临界区内，关闭 detach race
        let relation_guard = super::PTRACE_RELATION_LOCK.lock_irqsave();
        if !super::ptrace::is_ptraced_locked(self) {
            drop(relation_guard);
            drop(irq);
            self.ptrace_clear_trapping();
            return exit_code;
        }

        // 3. arm TRAPPING（若 attach 已 set）。
        self.ptrace_set_trapping();

        // 4. fatal 检查 + commit TRACED 状态（同一 sig_info 读锁段内，等价 Linux siglock）。
        //    SIGKILL 入队（complete_signal 取 sig_info 写锁）被读锁阻塞，故 SIGKILL
        //    要么在检查前入队（abort），要么在 set_state(Stopped) 后到达（wakeup_stop 生效）。
        let abort = {
            let siginfo_g = self.sig_info_irqsave();
            let fatal = siginfo_g
                .sig_pending()
                .signal()
                .contains(Signal::SIGKILL.into());
            if fatal {
                true
            } else {
                let mut ps = self.ptrace_state.lock_irqsave();
                ps.exit_code = exit_code;
                ps.listening = false;
                ps.stop_report_pending = true;
                ps.in_ptrace_stop = true;
                #[cfg(target_arch = "x86_64")]
                {
                    ps.stop_frame_on_syscall_stack = self.current_stop_frame_on_syscall_stack();
                }
                match info.as_ref() {
                    Some(i) => ps.last_siginfo = Some(**i),
                    None => ps.last_siginfo = None,
                }
                drop(ps);
                self.sched_info().set_state(ProcessState::Stopped);
                false
            }
            // siginfo_g 在 set_state 之后才 drop（关闭 fatal 检查与 commit 之间的窗口）
        };

        drop(relation_guard);

        // 5. fence(Release)：保证 Stopped + exit_code 在 TRAPPING 清除前对 tracer 可见。
        fence(Ordering::Release);

        if abort {
            self.ptrace_clear_trapping();
            return 0;
        }

        // 6. 清 TRAPPING，唤醒 attach 等待者。
        self.ptrace_clear_trapping();

        // group-stop 参与记账 + real_parent CLD_STOPPED 通知。
        let gstop_done = if why == SigChildCode::Stopped {
            let stop_sig = Signal::from((exit_code & 0x7f) as i32);
            if crate::ipc::signal_types::SIG_KERNEL_STOP_MASK.contains(stop_sig.into()) {
                self.sighand().ptrace_participate_group_stop(stop_sig)
            } else {
                false
            }
        } else {
            false
        };
        // 7. 通知 tracer 并阻塞。
        if let Some(tracer) = self.ptracer_pcb() {
            self.notify_tracer(&tracer, why, exit_code);
        }
        // real_parent 的 CLD_STOPPED 通知：仅 group-stop 完成 && ptracer≠real_parent。
        if gstop_done {
            let real_parent_to_notify = match (self.ptracer_pcb(), self.real_parent_pcb()) {
                (Some(ptracer), Some(rp)) if ptracer.tgid != rp.tgid => Some(rp),
                (None, Some(rp)) => Some(rp),
                _ => None,
            };
            if let Some(rp) = real_parent_to_notify {
                let status = (exit_code & 0x7f) as i32;
                let mut chld = SigInfo::new(
                    Signal::SIGCHLD,
                    0,
                    SigCode::Raw(SigChildCode::Stopped as i32),
                    SigType::SigChild {
                        pid: self.raw_pid(),
                        uid: 0,
                        status,
                        utime: 0,
                        stime: 0,
                    },
                );
                let _ = Signal::SIGCHLD.send_signal_info_to_pcb(
                    Some(&mut chld),
                    rp.clone(),
                    PidType::TGID,
                );
                rp.wake_all_waiters();
            }
        }
        schedule(SchedMode::SM_NONE);
        // 8. 唤醒后清理。
        let mut ps = self.ptrace_state.lock_irqsave();
        if let Some(i) = info {
            if let Some(saved) = ps.last_siginfo {
                // 回填：PTRACE_SETSIGINFO 的修改参与后续信号递送。
                *i = saved;
            }
        }
        let injected = ps.injected_signal;
        ps.listening = false;
        ps.stop_report_pending = false;
        ps.in_ptrace_stop = false;
        ps.last_siginfo = None;
        ps.event_message = 0;
        ps.exit_code = 0;
        let result = if injected == Signal::INVALID {
            0
        } else {
            ps.injected_signal = Signal::INVALID;
            injected as usize
        };
        drop(ps);

        // 唤醒后重算信号 pending（可能被 tracer 注入了信号）。
        if let Some(strong) = self.self_ref.upgrade() {
            strong.recalc_sigpending();
        }

        result
    }

    /// 发送 SIGCHLD + 唤醒 tracer wait_queue。
    fn notify_tracer(
        &self,
        tracer: &Arc<ProcessControlBlock>,
        why: SigChildCode,
        stop_code: usize,
    ) {
        // 1. 发送 SIGCHLD 给 tracer（如果 tracer 不忽略）。
        let should_send = {
            let sa = tracer.sighand().handler(Signal::SIGCHLD);
            let force = why == SigChildCode::Trapped;
            match sa {
                Some(a) => {
                    !a.action().is_ignore()
                        && (force || !a.flags().contains(SigFlags::SA_NOCLDSTOP))
                }
                None => false,
            }
        };
        if should_send {
            let status = match why {
                SigChildCode::Stopped | SigChildCode::Trapped => (stop_code & 0x7f) as i32,
                _ => Signal::SIGCONT as i32,
            };
            let mut chld = SigInfo::new(
                Signal::SIGCHLD,
                0,
                SigCode::Raw(why as i32),
                SigType::SigChild {
                    pid: self.raw_pid(),
                    uid: 0,
                    status,
                    utime: 0,
                    stime: 0,
                },
            );
            let _ = Signal::SIGCHLD.send_signal_info_to_pcb(
                Some(&mut chld),
                tracer.clone(),
                PidType::TGID,
            );
        }
        // 无条件唤醒 ptracer 的 wait_queue。
        // gdb/strace 默认不装 SIGCHLD handler，靠 waitpid(2) 阻塞
        // 此唤醒是它们能观察到 ptrace-stop 的唯一可靠路径（上面的 SIGCHLD 仅服务信号驱动型 tracer）。
        tracer.wake_all_waiters();
        // group leader 与 ptracer 不同时也唤醒
        let leader = tracer
            .thread
            .read_irqsave()
            .group_leader()
            .unwrap_or_else(|| tracer.clone());
        if !Arc::ptr_eq(&leader, tracer) {
            leader.wake_all_waiters();
        }
    }

    /// ptrace 事件通知（FORK/CLONE/VFORK/EXEC/EXIT/SECCOMP）。
    pub fn ptrace_event(&self, event: PtraceEvent, message: usize) {
        if self.ptrace_event_enabled(event) {
            self.ptrace_state.lock_irqsave().event_message = message;
            let exit_code = (event as usize) << 8 | Signal::SIGTRAP as usize;
            if let Ok(signr) = Self::ptrace_notify(exit_code, exit_code as i32) {
                Self::reinject_ptrace_signal(signr);
            }
        }
    }

    /// 检查事件选项是否开启。
    pub fn ptrace_event_enabled(&self, event: PtraceEvent) -> bool {
        let flag = match event {
            PtraceEvent::Fork => PtraceOptions::TRACEFORK,
            PtraceEvent::VFork => PtraceOptions::TRACEVFORK,
            PtraceEvent::Clone => PtraceOptions::TRACECLONE,
            PtraceEvent::Exec => PtraceOptions::TRACEEXEC,
            PtraceEvent::VForkDone => PtraceOptions::TRACEVFORKDONE,
            PtraceEvent::Exit => PtraceOptions::TRACEEXIT,
            PtraceEvent::Seccomp => PtraceOptions::TRACESECCOMP,
            _ => return false,
        };
        self.ptrace_state.lock_irqsave().options.contains(flag)
    }

    /// 构造 PTRACE_EVENT_STOP（seize 模式 group-stop / INTERRUPT / LISTEN 重陷）。
    pub(crate) fn ptrace_event_stop(&self, signal: Signal) -> usize {
        let exit_code = (PtraceEvent::Stop as usize) << 8 | signal as usize;
        // si_code 用 exit_code，GETSIGINFO 读到 (Stop<<8)|signal。
        let mut info = SigInfo::new(
            signal,
            0,
            SigCode::Raw(exit_code as i32),
            SigType::Kill {
                pid: RawPid(0),
                uid: 0,
            },
        );
        self.ptrace_stop(exit_code, SigChildCode::Stopped, Some(&mut info))
    }

    /// SIGCONT 投递路径调用，让 seized tracee 离开 group-stop/LISTEN 重新陷入 PTRACE_EVENT_STOP。
    pub fn ptrace_trap_notify(&self) {
        if !self.flags().contains(ProcessFlags::PT_SEIZED) {
            return;
        }
        // 单次持锁原子地写 pending_event_stop 并读唤醒门控：
        // 仅 LISTEN 或 group-stop（非 ptrace-stop）态需 wakeup_stop 重陷；
        // 正常 ptrace-stop 不打扰，PENDING 留待 CONT 后在 do_signal_or_restart 重检。
        let do_wake = {
            let mut ps = self.ptrace_state.lock_irqsave();
            ps.pending_event_stop = Some(Signal::SIGTRAP);
            ps.listening || !ps.in_ptrace_stop
        };
        self.flags().insert(ProcessFlags::PENDING_PTRACE_STOP);
        if do_wake {
            if let Some(strong) = self.self_ref.upgrade() {
                let _ = ProcessManager::wakeup_stop(&strong);
            }
        }
    }

    /// PTRACE_INTERRUPT：让运行中的 SEIZED tracee 进入 ptrace-stop。
    pub fn ptrace_interrupt(&self) -> Result<(), SystemError> {
        // 要求 PT_SEIZED
        if !self.flags().contains(ProcessFlags::PT_SEIZED) {
            return Err(SystemError::EIO);
        }
        // 单次持锁原子地写 pending_event_stop 并读唤醒门控，避免多次取锁间的 TOCTOU。
        // 仅 LISTEN 或 group-stop（非 ptrace-stop）态的 Stopped tracee 需 wakeup_stop 重陷；
        // 正常 ptrace-stop 不打扰，PENDING 留待 CONT 后在 do_signal_or_restart 重检。
        let wake_for_retrap = {
            let mut ps = self.ptrace_state.lock_irqsave();
            ps.pending_event_stop = Some(Signal::SIGTRAP);
            ps.listening || !ps.in_ptrace_stop
        };
        self.flags().insert(ProcessFlags::PENDING_PTRACE_STOP);
        if let Some(strong) = self.self_ref.upgrade() {
            // wakeup_stop 对非 Stopped 进程是 no-op（幂等）；wakeup 对 Stopped 是 no-op。
            // 故 stale 的 state 读至多一次冗余 kick，粘性 PENDING_PTRACE_STOP 保证最终必停。
            if strong.sched_info().state().is_stopped() && wake_for_retrap {
                let _ = ProcessManager::wakeup_stop(&strong);
            } else {
                // 运行态 tracee：wakeup + kick(IPI) 让它进内核消费 PENDING_PTRACE_STOP。
                let _ = ProcessManager::wakeup(&strong);
                ProcessManager::kick(&strong);
            }
        }
        Ok(())
    }

    /// PTRACE_LISTEN：让处于 PTRACE_EVENT_STOP 的 tracee 脱离 ptrace-stop 但保持 stopped。
    /// 语义：tracee 既不运行（保持 Stopped）也不在 ptrace-stop（wait 不可见、ptrace 命令失败 ESRCH）；
    /// group-stop 来源的 LISTEN 下信号排队但不投递，SIGCONT 使其离开 group-stop 重陷。
    pub fn ptrace_listen(&self) -> Result<(), SystemError> {
        // PT_SEIZED
        if !self.flags().contains(ProcessFlags::PT_SEIZED) {
            return Err(SystemError::EIO);
        }
        let mut ps = self.ptrace_state.lock_irqsave();
        // 仅在 PTRACE_EVENT_STOP trap 允许 LISTEN
        let is_event_stop = ps
            .last_siginfo
            .as_ref()
            .map(|i| (i.sig_code().as_i32() >> 8) == PtraceEvent::Stop as i32)
            .unwrap_or(false);
        if !ps.in_ptrace_stop || !is_event_stop {
            return Err(SystemError::EIO);
        }
        // 取出触发本次 event-stop 的信号（低字节）。
        let stop_signal = Signal::from(ps.exit_code as i32 & 0x7f);
        ps.listening = true;
        // 清 in_ptrace_stop：LISTEN 状态下 tracee 不在 ptrace-stop，
        // ptrace_check_attach 应返回 ESRCH
        ps.in_ptrace_stop = false;
        // 关键：清 stop_report_pending，使 wait 不再返回此 stop
        ps.stop_report_pending = false;
        // group-stop 来源（SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU）：置 STOP_STOPPED，
        // 使 tracee 保持 group-stop 语义（信号排队不投递；SIGCONT 经 ptrace_trap_notify 重陷）。
        if stop_signal != Signal::INVALID
            && crate::ipc::signal_types::SIG_KERNEL_STOP_MASK.contains(stop_signal.into())
        {
            self.sighand().set_stop_signal(stop_signal);
            self.sighand().flags_insert(SignalFlags::STOP_STOPPED);
        }
        Ok(())
    }

    /// 发送一个 ptrace 通知 stop（exit_code 必须是 SIGTRAP 编码）。
    /// `si_code` 写入 siginfo（如 TRAP_BRKPT/TRAP_TRACE/TRAP_HWBKPT，或 EVENT_STOP 编码）。
    pub fn ptrace_notify(exit_code: usize, si_code: i32) -> Result<usize, SystemError> {
        let current = ProcessManager::current_pcb();
        if (exit_code & (0x7f | !0xffff)) != Signal::SIGTRAP as usize {
            return Err(SystemError::EINVAL);
        }
        let mut info = SigInfo::new(
            Signal::SIGTRAP,
            0,
            SigCode::Raw(si_code),
            SigType::Kill {
                pid: current.raw_pid(),
                uid: 0,
            },
        );
        let signr = current.ptrace_stop(exit_code, SigChildCode::Trapped, Some(&mut info));
        Ok(signr)
    }

    /// 重新注入 ptrace_stop 返回的信号（若非 0）。
    pub fn reinject_ptrace_signal(signr: usize) {
        if signr == 0 {
            return;
        }
        let sig = Signal::from(signr as i32);
        if sig == Signal::INVALID {
            return;
        }
        let current = ProcessManager::current_pcb();
        let _ = sig.send_signal_info_to_pcb(None, current, PidType::PID);
    }

    /// 清除调试器为单步置位的 RFLAGS.TF
    #[cfg(target_arch = "x86_64")]
    fn disable_single_step(&self) {
        let mut ps = self.ptrace_state.lock_irqsave();
        if ps.forced_trap_flag {
            ps.forced_trap_flag = false;
            drop(ps);
            let frame = unsafe { &mut *self.tracee_trap_frame_ptr() };
            frame.rflags &= !0x100; // 清 X86_EFLAGS_TF
        }
    }

    /// 非x86_64架构无硬件单步机制，清除单步为空操作。
    #[cfg(not(target_arch = "x86_64"))]
    #[inline]
    fn disable_single_step(&self) {}

    /// 恢复 tracee 执行（CONT/SYSCALL/SINGLESTEP/SYSEMU）。
    /// 设置/清除 TRACE_* 工作位，存 injected_signal，唤醒 tracee 脱离 ptrace_stop。
    pub fn ptrace_resume(
        &self,
        request: PtraceRequest,
        signal: Option<Signal>,
    ) -> Result<isize, SystemError> {
        // 先校验注入信号
        let resume_signal = match signal {
            None => Signal::INVALID,
            Some(Signal::INVALID) => return Err(SystemError::EIO),
            Some(s) => s,
        };

        // 设置/清除 syscall-trace / 单步工作位。
        match request {
            PtraceRequest::Singlestep => {
                self.flags().insert(ProcessFlags::TRACE_SINGLESTEP);
                self.flags()
                    .remove(ProcessFlags::TRACE_SYSCALL | ProcessFlags::TRACE_SYSEMU);
                // 置 RFLAGS.TF（单步）+ 记录 forced_trap_flag
                #[cfg(target_arch = "x86_64")]
                {
                    let frame = unsafe { &mut *self.tracee_trap_frame_ptr() };
                    frame.rflags |= 0x100; // X86_EFLAGS_TF
                    self.ptrace_state.lock_irqsave().forced_trap_flag = true;
                }
            }
            PtraceRequest::Syscall => {
                self.flags().insert(ProcessFlags::TRACE_SYSCALL);
                self.flags()
                    .remove(ProcessFlags::TRACE_SINGLESTEP | ProcessFlags::TRACE_SYSEMU);
                self.disable_single_step();
            }
            PtraceRequest::Sysemu | PtraceRequest::SysemuSinglestep => {
                self.flags().insert(ProcessFlags::TRACE_SYSEMU);
                if request == PtraceRequest::SysemuSinglestep {
                    self.flags().insert(ProcessFlags::TRACE_SINGLESTEP);
                } else {
                    self.flags().remove(ProcessFlags::TRACE_SINGLESTEP);
                    self.disable_single_step();
                }
                self.flags().remove(ProcessFlags::TRACE_SYSCALL);
            }
            PtraceRequest::Cont => {
                self.flags().remove(
                    ProcessFlags::TRACE_SYSCALL
                        | ProcessFlags::TRACE_SINGLESTEP
                        | ProcessFlags::TRACE_SYSEMU,
                );
                self.disable_single_step();
            }
            _ => return Err(SystemError::EINVAL),
        }

        // 存注入信号，清 stop 标志，唤醒 tracee。
        let was_in_stop = {
            let mut ps = self.ptrace_state.lock_irqsave();
            ps.injected_signal = resume_signal;
            ps.listening = false;
            ps.stop_report_pending = false;
            ps.in_ptrace_stop = false; // 退出 ptrace-stop（修复 audit P0）
            self.sched_info().state().is_stopped()
        };

        if was_in_stop {
            if let Some(strong) = self.self_ref.upgrade() {
                // 从 Stopped 唤醒回 Runnable
                let _ = ProcessManager::wakeup_stop(&strong);
            }
        }
        Ok(0)
    }
    /// 系统调用入口/出口的 ptrace-stop。
    /// 返回 true 表示应跳过 syscall 执行（仅 SYSEMU 入口停止意义）；其余情况 false。
    pub fn ptrace_report_syscall(&self, is_entry: bool, _nr: u64, _args: &[usize; 6]) -> bool {
        let is_single_step = self.flags().contains(ProcessFlags::TRACE_SINGLESTEP);
        // 出口：单步或 syscall-trace 都触发，但停止类型不同。
        // 单步在 syscall 出口必须立即 trap（在执行任何用户指令之前）
        let traced = if is_entry {
            self.flags().contains(ProcessFlags::TRACE_SYSCALL)
                || self.flags().contains(ProcessFlags::TRACE_SYSEMU)
        } else {
            self.flags().contains(ProcessFlags::TRACE_SYSCALL) || is_single_step
        };
        if !traced {
            return false;
        }
        let msg = if is_entry {
            PTRACE_EVENTMSG_SYSCALL_ENTRY
        } else {
            PTRACE_EVENTMSG_SYSCALL_EXIT
        };
        let sysgood = self
            .ptrace_state
            .lock_irqsave()
            .options
            .contains(PtraceOptions::TRACESYSGOOD);
        let sysemu_skip = is_entry && self.flags().contains(ProcessFlags::TRACE_SYSEMU);
        {
            let mut ps = self.ptrace_state.lock_irqsave();
            ps.event_message = msg;
        }
        // 单步跨 syscall 出口：报告单步 trap
        if !is_entry && is_single_step {
            if let Ok(signr) = Self::ptrace_notify(Signal::SIGTRAP as usize, TRAP_BRKPT) {
                Self::reinject_ptrace_signal(signr);
            }
        } else {
            // 纯 syscall-stop（entry 或非单步的 exit）：sysgood 位仅加于纯 syscall-stop。
            let exit_code = if sysgood {
                Signal::SIGTRAP as usize | 0x80
            } else {
                Signal::SIGTRAP as usize
            };
            if let Ok(signr) = Self::ptrace_notify(exit_code, exit_code as i32) {
                Self::reinject_ptrace_signal(signr);
            }
        }
        sysemu_skip
    }
}
