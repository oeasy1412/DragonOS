use core::intrinsics::likely;

use crate::{
    arch::driver::apic::{CurrentApic, LocalAPIC},
    arch::CurrentIrqArch,
    exception::{irqdesc::irq_desc_manager, softirq::do_softirq, InterruptArch, IrqNumber},
    process::{
        utils::{current_pcb_flags, current_pcb_preempt_count},
        ProcessFlags, ProcessManager,
    },
    sched::{need_resched, SchedMode, __schedule},
};

use super::TrapFrame;

#[no_mangle]
unsafe extern "C" fn x86_64_do_irq(trap_frame: &mut TrapFrame, vector: u32) {
    // swapgs

    if trap_frame.is_from_user() {
        x86_64::registers::segmentation::GS::swap();
    }

    // 由于x86上面，虚拟中断号与物理中断号是一一对应的，所以这里直接使用vector作为中断号来查询irqdesc

    let desc = irq_desc_manager().lookup(IrqNumber::new(vector));

    if likely(desc.is_some()) {
        let desc = desc.unwrap();
        let handler = desc.handler();
        if likely(handler.is_some()) {
            handler.unwrap().handle(&desc, trap_frame);
        } else {
            CurrentApic.send_eoi();
        }
    } else {
        CurrentApic.send_eoi();
    }

    do_softirq();

    if current_pcb_preempt_count() > 0 {
        return;
    }

    // 仅当 NEED_SCHEDULE 被设置时才调用 __schedule，
    if current_pcb_flags().contains(ProcessFlags::NEED_SCHEDULE) {
        // loop {
        //     ProcessManager::preempt_disable();
        //     unsafe { CurrentIrqArch::interrupt_enable() };
        //     let switched = __schedule(SchedMode::SM_PREEMPT);
        //     unsafe { CurrentIrqArch::interrupt_disable() };
        //     if !switched {
        //         ProcessManager::preempt_enable();
        //     }
        //     if !need_resched() {
        //         break;
        //     }
        // }
        __schedule(SchedMode::SM_PREEMPT);
    }
}
