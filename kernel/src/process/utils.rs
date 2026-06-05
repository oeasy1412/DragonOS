use super::{ProcessFlags, __PROCESS_MANAGEMENT_INIT_DONE};
use crate::process::ProcessManager;

pub fn current_pcb_flags() -> ProcessFlags {
    if unsafe { !__PROCESS_MANAGEMENT_INIT_DONE } {
        return ProcessFlags::empty();
    }
    return *ProcessManager::current_pcb().flags();
}
