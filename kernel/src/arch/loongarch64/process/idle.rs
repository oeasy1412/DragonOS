use core::hint::spin_loop;

use log::error;

use crate::{
    arch::CurrentIrqArch,
    exception::InterruptArch,
    process::{ProcessFlags, ProcessManager},
    sched::{SchedMode, __schedule},
};

impl ProcessManager {
    /// 每个核的idle进程
    pub fn arch_idle_func() -> ! {
        loop {
            let pcb = ProcessManager::current_pcb();
            if pcb.flags().contains(ProcessFlags::NEED_SCHEDULE) {
                ProcessManager::preempt_disable();
                let switched = __schedule(SchedMode::SM_NONE);
                if !switched {
                    ProcessManager::preempt_enable();
                }
            }
            if CurrentIrqArch::is_irq_enabled() {
                todo!("la64: arch_idle_func");
                // unsafe {
                //     x86::halt();
                // }
            } else {
                error!("Idle process should not be scheduled with IRQs disabled.");
                spin_loop();
            }
        }
    }
}
