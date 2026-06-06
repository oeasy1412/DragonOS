//! per-CPU preempt_count 实现
//!
//! 对齐 Linux 6.6 的 `pcpu_hot.preempt_count` 语义：
//! - preempt_count 是 per-CPU 的调度锁嵌套深度，不属于任何 task 状态
//! - context_switch 时不需要保存/恢复（由 switch_finish_hook 重置）
//! - Relaxed ordering 足够：per-CPU 数据只有当前 CPU 在禁用抢占/中断上下文中访问

use crate::{
    mm::percpu::PerCpu,
    process::{ProcessManager, __PROCESS_MANAGEMENT_INIT_DONE},
    smp::core::smp_get_processor_id,
};
use core::{
    intrinsics::{likely, unlikely},
    sync::atomic::{AtomicUsize, Ordering},
};

/// per-CPU 静态数组，避免 `lazy_static!` / `Vec` 引入的堆分配死锁：
/// SlabAllocator.lock_irqsave() → preempt_disable() → lazy_static init → heap alloc → SlabAllocator → 循环。
static PREEMPT_COUNT: [AtomicUsize; PerCpu::MAX_CPU_NUM as usize] =
    [const { AtomicUsize::new(0) }; PerCpu::MAX_CPU_NUM as usize];

/// 读取当前 CPU 的 preempt_count。
#[inline(always)]
pub fn preempt_count_val() -> usize {
    current_preempt_count().load(Ordering::Relaxed)
}

/// 获取当前 CPU preempt_count 的静态引用。
#[inline(always)]
pub fn current_preempt_count() -> &'static AtomicUsize {
    let cpu = smp_get_processor_id().data() as usize;
    // 安全：smp_get_processor_id() 保证返回有效 CPU ID (< MAX_CPU_NUM)

    &PREEMPT_COUNT[cpu]
}

/// 设置当前 CPU 的 preempt_count。
/// 仅用于 switch_finish_hook 和 AP 启动初始化。
#[inline(always)]
pub fn set_preempt_count_val(val: usize) {
    current_preempt_count().store(val, Ordering::Relaxed);
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
    /// 增加当前进程的锁持有计数
    #[inline(always)]
    pub fn preempt_disable() {
        if likely(unsafe { __PROCESS_MANAGEMENT_INIT_DONE }) {
            current_preempt_count().fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 减少当前 CPU 的抢占计数，不检查 need_resched。
    #[inline(always)]
    pub fn preempt_enable_no_resched() {
        if likely(unsafe { __PROCESS_MANAGEMENT_INIT_DONE }) {
            let prev = current_preempt_count().fetch_sub(1, Ordering::Relaxed);
            if unlikely(prev == 0) {
                log::error!(
                    "preempt_enable_no_resched underflow on cpu {} (count was 0)",
                    smp_get_processor_id().data()
                );
                current_preempt_count().store(0, Ordering::Relaxed);
            }
        }
    }

    /// 减少当前 CPU 的抢占计数。
    ///
    /// TODO: 当 count 归零时应检查 need_resched() 并可能调用 preempt_schedule()。
    /// 当前实现等价于 preempt_enable_no_resched()
    #[inline(always)]
    pub fn preempt_enable() {
        Self::preempt_enable_no_resched();
    }
}
