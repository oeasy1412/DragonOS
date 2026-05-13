use core::intrinsics::likely;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    mm::percpu::PerCpu,
    process::{ProcessManager, __PROCESS_MANAGEMENT_INIT_DONE},
    smp::core::smp_get_processor_id,
};

/// 此处使用静态数组镜像该语义，避免 `lazy_static!` / `Vec` 引入的堆分配死锁：
/// SlabAllocator.lock_irqsave() → preempt_disable() → lazy_static init → heap alloc → SlabAllocator → 循环。
static PREEMPT_COUNT: [AtomicUsize; PerCpu::MAX_CPU_NUM as usize] =
    [const { AtomicUsize::new(0) }; PerCpu::MAX_CPU_NUM as usize];

/// 获取当前 CPU 的 preempt_count 引用。
#[inline(always)]
fn current_preempt_count() -> &'static AtomicUsize {
    let cpu = smp_get_processor_id().data() as usize;
    debug_assert!(
        cpu < PREEMPT_COUNT.len(),
        "current_preempt_count: CPU ID {} out of bounds",
        cpu
    );
    unsafe { PREEMPT_COUNT.get_unchecked(cpu) }
}

#[inline(always)]
pub fn preempt_count_val() -> usize {
    current_preempt_count().load(Ordering::SeqCst)
}

#[inline(always)]
pub fn set_preempt_count_val(val: usize) {
    current_preempt_count().store(val, Ordering::SeqCst);
}

pub struct PreemptGuard;

impl PreemptGuard {
    pub fn new() -> Self {
        ProcessManager::preempt_disable();
        Self
    }
}

impl Drop for PreemptGuard {
    fn drop(&mut self) {
        ProcessManager::preempt_enable();
    }
}

impl ProcessManager {
    /// 增加当前CPU的抢占禁用计数
    #[inline(always)]
    pub fn preempt_disable() {
        if likely(unsafe { __PROCESS_MANAGEMENT_INIT_DONE }) {
            current_preempt_count().fetch_add(1, Ordering::SeqCst);
        }
    }

    #[inline(always)]
    pub fn preempt_enable() {
        if likely(unsafe { __PROCESS_MANAGEMENT_INIT_DONE }) {
            let result =
                current_preempt_count().fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    if v == 0 {
                        None
                    } else {
                        Some(v - 1)
                    }
                });
            if result.is_err() {
                log::error!(
                    "preempt_enable underflow on cpu {} (count was 0)",
                    smp_get_processor_id().data()
                );
            }
        }
    }
}
