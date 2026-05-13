use crate::{
    arch::{interrupt::TrapFrame, CurrentSignalArch},
    ipc::signal_types::SignalArch,
    process::{rseq::Rseq, ProcessFlags, ProcessManager},
    sched::{schedule, SchedMode},
};

#[no_mangle]
unsafe extern "C" fn irqentry_exit(frame: &mut TrapFrame) {
    if frame.is_from_user() {
        irqentry_exit_to_user_mode(frame);
    }
}

/// 退出到用户态之前，在这个函数内做最后的处理
///
/// # Safety
///
/// 由于这个函数内可能会直接退出进程，因此，在进入函数之前，
/// 必须保证所有的栈上的Arc/Box指针等，都已经被释放。否则，可能会导致内存泄漏。
unsafe fn irqentry_exit_to_user_mode(frame: &mut TrapFrame) {
    exit_to_user_mode_prepare(frame);
}

/// # Safety
///
/// 由于这个函数内可能会直接退出进程，因此，在进入函数之前，
/// 必须保证所有的栈上的Arc/Box指针等，都已经被释放。否则，可能会导致内存泄漏。
unsafe fn exit_to_user_mode_prepare(frame: &mut TrapFrame) {
    let process_flags_work = *ProcessManager::current_pcb().flags();
    if !process_flags_work.exit_to_user_mode_work().is_empty() {
        exit_to_user_mode_loop(frame, process_flags_work);
    }
}

/// # Safety
///
/// 由于这个函数内可能会直接退出进程，因此，在进入函数之前，
/// 必须保证所有的栈上的Arc/Box指针等，都已经被释放。否则，可能会导致内存泄漏。
unsafe fn exit_to_user_mode_loop(frame: &mut TrapFrame, mut process_flags_work: ProcessFlags) {
    while !process_flags_work.exit_to_user_mode_work().is_empty() {
        // NEED_SCHEDULE：调度优先级最高
        if process_flags_work.contains(ProcessFlags::NEED_SCHEDULE) {
            schedule(SchedMode::SM_NONE);
        }

        // HAS_PENDING_SIGNAL：信号递送会修改 trapframe
        if process_flags_work.contains(ProcessFlags::HAS_PENDING_SIGNAL) {
            unsafe { CurrentSignalArch::do_signal_or_restart(frame) };
        }

        // NEED_RSEQ：可重入序列可以在最后处理
        if process_flags_work.contains(ProcessFlags::NEED_RSEQ) {
            let _ = Rseq::handle_notify_resume(Some(frame));
        }

        process_flags_work = *ProcessManager::current_pcb().flags();
    }
}
