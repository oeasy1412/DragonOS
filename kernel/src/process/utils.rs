use crate::process::{preempt::preempt_count_val, ProcessManager};

use super::{ProcessFlags, __PROCESS_MANAGEMENT_INIT_DONE};

pub fn current_pcb_flags() -> ProcessFlags {
    if unsafe { !__PROCESS_MANAGEMENT_INIT_DONE } {
        return ProcessFlags::empty();
    }
    return *ProcessManager::current_pcb().flags();
}

pub fn current_pcb_preempt_count() -> usize {
    if unsafe { !__PROCESS_MANAGEMENT_INIT_DONE } {
        return 0;
    }
    preempt_count_val()
}
