use log::info;

use crate::{
    arch::{syscall::arch_syscall_init, CurrentIrqArch, CurrentSchedArch},
    exception::InterruptArch,
    process::{preempt, ProcessManager},
    sched::SchedArch,
    smp::{core::smp_get_processor_id, cpu::smp_cpu_manager},
};

#[inline(never)]
pub fn smp_ap_start_stage2() -> ! {
    assert!(!CurrentIrqArch::is_irq_enabled());

    let cpu_id = smp_get_processor_id();
    smp_cpu_manager().cpuhp_step_state(cpu_id);
    smp_cpu_manager().complete_ap_thread(true);

    do_ap_start_stage2();

    CurrentSchedArch::initial_setup_sched_local();

    CurrentSchedArch::enable_sched_local();

    // per-CPU preempt_count 会累积 boot 过程中其他代码路径的不平衡，
    // 对标 BSP do_cpuhp_kick_ap 中的重置逻辑，在进入 idle 循环前归零。
    preempt::set_preempt_count_val(0);

    ProcessManager::arch_idle_func();
}

#[inline(never)]
fn do_ap_start_stage2() {
    info!("Successfully started AP {}", smp_get_processor_id().data());
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::mm::X86_64MMArch::init_current_cpu_nxe();
        crate::driver::clocksource::kvm_clock::kvmclock_init_secondary();
    }
    arch_syscall_init().expect("AP core failed to initialize syscall");
}
