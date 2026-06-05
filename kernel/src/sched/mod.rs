pub mod clock;
pub mod completion;
pub mod cputime;
pub mod fair;
pub mod fair_tree;
pub mod fifo;
#[cfg(feature = "fifo_demo")]
pub mod fifo_demo;
pub mod idle;
pub mod load_balance;
pub mod loadavg;
pub mod pelt;
pub mod prio;
pub mod rebalance;
pub mod sched_domain;
pub mod syscall;
pub mod topology;

use core::{
    intrinsics::{likely, unlikely},
    panic::Location,
    sync::atomic::{
        compiler_fence, fence, AtomicBool, AtomicIsize, AtomicPtr, AtomicU64, AtomicUsize, Ordering,
    },
};

use alloc::{
    boxed::Box,
    collections::LinkedList,
    sync::{Arc, Weak},
    vec::Vec,
};
use log::warn;
use system_error::SystemError;

use crate::{
    arch::{
        asm::irqflags::{local_irq_disable, local_irq_enable},
        cpu::current_cpu_id,
        interrupt::ipi::send_ipi,
        ipc::signal::Signal,
        CurrentIrqArch,
    },
    exception::{
        ipi::{IpiKind, IpiTarget},
        InterruptArch,
    },
    init::initial_kthread::{get_system_state, SystemState},
    libs::{
        cpumask::{AtomicCpuMask, CpuMask},
        lazy_init::Lazy,
        spinlock::{SpinLock, SpinLockGuard},
    },
    mm::percpu::{PerCpu, PerCpuVar},
    process::{
        preempt::PreemptGuard, ProcessControlBlock, ProcessFlags, ProcessManager, ProcessState,
        SchedInfo,
    },
    sched::idle::IdleScheduler,
    smp::{
        core::smp_get_processor_id,
        cpu::{smp_cpu_manager, smp_cpu_manager_initialized, ProcessorId},
    },
    time::{clocksource::HZ, timer::clock},
};

use self::{
    clock::{ClockUpdataFlag, SchedClock},
    cputime::{irq_time_read, CpuTimeFunc, IrqTime},
    fair::{CfsRunQueue, CompletelyFairScheduler, FairSchedEntity},
    fifo::FifoScheduler,
    prio::PrioUtil,
    sched_domain::SchedDomain,
};

static mut CPU_IRQ_TIME: Option<Vec<&'static mut IrqTime>> = None;
pub static IDLE_CPUS: AtomicCpuMask = AtomicCpuMask::new();

// 这里虽然rq是percpu的，但是在负载均衡的时候需要修改对端cpu的rq，所以仍需加锁
static CPU_RUNQUEUE: Lazy<PerCpuVar<Arc<CpuRunQueue>>> = PerCpuVar::define_lazy();
static CPU_WAKEQUEUE: Lazy<PerCpuVar<Arc<WakeQueue>>> = PerCpuVar::define_lazy();

pub const SCHED_FIXEDPOINT_SHIFT: u64 = 10;
#[allow(dead_code)]
pub const SCHED_FIXEDPOINT_SCALE: u64 = 1 << SCHED_FIXEDPOINT_SHIFT;
#[allow(dead_code)]
pub const SCHED_CAPACITY_SHIFT: u64 = SCHED_FIXEDPOINT_SHIFT;
#[allow(dead_code)]
pub const SCHED_CAPACITY_SCALE: u64 = 1 << SCHED_CAPACITY_SHIFT;

#[inline]
pub fn cpu_irq_time(cpu: ProcessorId) -> &'static mut IrqTime {
    unsafe { CPU_IRQ_TIME.as_mut().unwrap()[cpu.data() as usize] }
}

#[inline]
pub fn cpu_rq(cpu: usize) -> Arc<CpuRunQueue> {
    assert!(
        cpu < PerCpu::MAX_CPU_NUM as usize,
        "cpu_rq: cpu {} out of bounds (MAX_CPU_NUM = {})",
        cpu,
        PerCpu::MAX_CPU_NUM
    );
    CPU_RUNQUEUE.ensure();
    unsafe {
        CPU_RUNQUEUE
            .get()
            .force_get(ProcessorId::new(cpu as u32))
            .clone()
    }
}

#[inline]
pub fn cpu_wakequeue(cpu: usize) -> Arc<WakeQueue> {
    CPU_WAKEQUEUE.ensure();
    unsafe {
        CPU_WAKEQUEUE
            .get()
            .force_get(ProcessorId::new(cpu as u32))
            .clone()
    }
}

#[inline]
fn task_is_idle(pcb: &ProcessControlBlock) -> bool {
    pcb.sched_info().policy() == SchedPolicy::IDLE
}

#[inline]
pub fn cpu_is_online(cpu: ProcessorId) -> bool {
    smp_cpu_manager().is_online_cpu(cpu)
}

#[inline]
fn boot_in_progress() -> bool {
    matches!(
        get_system_state(),
        SystemState::Booting | SystemState::Scheduling | SystemState::FreeingInitMem
    )
}

/// 当前实现是功能正确的最小版本，直接扫描 `allowed` 位图找第一个空闲 CPU，
/// 不区分调度域、不感知 SMT/LLC 缓存拓扑、不做扫描成本控制。
/// 待调度域（SchedDomain）和 SIS_UTIL 实现后可替换为对齐 Linux 的版本。
#[allow(dead_code)]
pub fn pick_idle_cpu(allowed: &CpuMask) -> Option<ProcessorId> {
    if !smp_cpu_manager_initialized() {
        return IDLE_CPUS.first_and(allowed);
    }

    allowed
        .iter_cpu()
        .find(|&cpu| IDLE_CPUS.get(cpu) && cpu_is_online(cpu))
}

lazy_static! {
    pub static ref SCHED_FEATURES: SchedFeature = SchedFeature::GENTLE_FAIR_SLEEPERS
        | SchedFeature::START_DEBIT
        | SchedFeature::LAST_BUDDY
        | SchedFeature::CACHE_HOT_BUDDY
        | SchedFeature::WAKEUP_PREEMPTION
        | SchedFeature::NONTASK_CAPACITY
        | SchedFeature::TTWU_QUEUE
        | SchedFeature::SIS_UTIL
        | SchedFeature::RT_PUSH_IPI
        | SchedFeature::ALT_PERIOD
        | SchedFeature::BASE_SLICE
        | SchedFeature::UTIL_EST
        | SchedFeature::UTIL_EST_FASTUP;
}

pub trait Scheduler {
    /// ## 加入当任务进入可运行状态时调用。它将调度实体（任务）放到红黑树中，增加nr_running变量的值。
    fn enqueue(rq: &mut CpuRunQueue, pcb: Arc<ProcessControlBlock>, flags: EnqueueFlag);

    /// ## 当任务不再可运行时被调用，对应的调度实体被移出红黑树。它减少nr_running变量的值。
    fn dequeue(rq: &mut CpuRunQueue, pcb: Arc<ProcessControlBlock>, flags: DequeueFlag);

    /// ## 主动让出cpu，这个函数的行为基本上是出队，紧接着入队
    fn yield_task(rq: &mut CpuRunQueue);

    /// ## 检查进入可运行状态的任务能否抢占当前正在运行的任务
    fn check_preempt_current(
        rq: &mut CpuRunQueue,
        pcb: &Arc<ProcessControlBlock>,
        flags: WakeupFlags,
    );

    /// ## 选择接下来最适合运行的任务
    #[allow(dead_code)]
    fn pick_task(rq: &mut CpuRunQueue) -> Option<Arc<ProcessControlBlock>>;

    /// ## 选择接下来最适合运行的任务
    fn pick_next_task(
        rq: &mut CpuRunQueue,
        pcb: Option<Arc<ProcessControlBlock>>,
    ) -> Option<Arc<ProcessControlBlock>>;

    /// ## 被时间滴答函数调用，它可能导致进程切换。驱动了运行时抢占。
    fn tick(rq: &mut CpuRunQueue, pcb: Arc<ProcessControlBlock>, queued: bool);

    /// ## 在进程fork时，如需加入cfs，则调用
    fn task_fork(pcb: Arc<ProcessControlBlock>);

    fn put_prev_task(rq: &mut CpuRunQueue, prev: Arc<ProcessControlBlock>);
}

/// 调度策略
///
/// 裸字段，由调用者持 rq_lock 或 pi_lock 保护。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SchedPolicy {
    /// 实时进程
    RT = 0,
    /// 先进先出调度
    FIFO = 1,
    /// 完全公平调度
    CFS = 2,
    /// IDLE
    IDLE = 3,
}

impl SchedPolicy {
    #[inline]
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => SchedPolicy::RT,
            1 => SchedPolicy::FIFO,
            2 => SchedPolicy::CFS,
            3 => SchedPolicy::IDLE,
            _ => panic!("Invalid SchedPolicy value: {val}"),
        }
    }
}

#[allow(dead_code)]
pub struct TaskGroup {
    /// CFS管理的调度实体，percpu的
    entitys: Vec<Arc<FairSchedEntity>>,
    /// 每个CPU的CFS运行队列
    cfs: Vec<Arc<CfsRunQueue>>,
    /// 父节点
    parent: Option<Arc<TaskGroup>>,

    shares: u64,
}

#[derive(Debug, Default)]
pub struct LoadWeight {
    /// 负载权重
    pub weight: u64,
    /// weight的倒数，方便计算
    pub inv_weight: u32,
}

impl LoadWeight {
    /// 用于限制权重在一个合适的区域内
    pub const SCHED_FIXEDPOINT_SHIFT: u32 = 10;

    pub const WMULT_SHIFT: u32 = 32;
    pub const WMULT_CONST: u32 = !0;

    pub const NICE_0_LOAD_SHIFT: u32 = Self::SCHED_FIXEDPOINT_SHIFT + Self::SCHED_FIXEDPOINT_SHIFT;
    pub const NICE_0_LOAD: u64 = 1u64 << Self::NICE_0_LOAD_SHIFT;

    pub fn update_load_add(&mut self, inc: u64) {
        self.weight += inc;
        self.inv_weight = 0;
    }

    pub fn update_load_sub(&mut self, dec: u64) {
        self.weight -= dec;
        self.inv_weight = 0;
    }

    pub fn update_load_set(&mut self, weight: u64) {
        self.weight = weight;
        self.inv_weight = 0;
    }

    /// ## 更新负载权重的倒数
    pub fn update_inv_weight(&mut self) {
        // 已经更新
        if likely(self.inv_weight != 0) {
            return;
        }

        let w = Self::scale_load_down(self.weight);

        if unlikely(w >= Self::WMULT_CONST as u64) {
            // 高位有数据
            self.inv_weight = 1;
        } else if unlikely(w == 0) {
            // 倒数去最大
            self.inv_weight = Self::WMULT_CONST;
        } else {
            // 计算倒数
            self.inv_weight = Self::WMULT_CONST / w as u32;
        }
    }

    /// ## 计算任务的执行时间差
    ///
    /// 计算公式：(delta_exec * (weight * self.inv_weight)) >> WMULT_SHIFT
    pub fn calculate_delta(&mut self, delta_exec: u64, weight: u64) -> u64 {
        // 降低精度
        let mut fact = Self::scale_load_down(weight);

        // 记录fact高32位
        let mut fact_hi = (fact >> 32) as u32;
        // 用于恢复
        let mut shift = Self::WMULT_SHIFT;

        self.update_inv_weight();

        if unlikely(fact_hi != 0) {
            // 这里表示高32位还有数据
            // 需要计算最高位，然后继续调整fact
            let fs = 32 - fact_hi.leading_zeros();
            shift -= fs;

            // 确保高32位全为0
            fact >>= fs;
        }

        // 这里确定了fact已经在32位内
        fact *= self.inv_weight as u64;

        fact_hi = (fact >> 32) as u32;

        if fact_hi != 0 {
            // 这里表示高32位还有数据
            // 需要计算最高位，然后继续调整fact
            let fs = 32 - fact_hi.leading_zeros();
            shift -= fs;

            // 确保高32位全为0
            fact >>= fs;
        }

        return ((delta_exec as u128 * fact as u128) >> shift) as u64;
    }

    /// ## 将负载权重缩小到到一个小的范围中计算，相当于减小精度计算
    pub const fn scale_load_down(mut weight: u64) -> u64 {
        if weight != 0 {
            weight >>= Self::SCHED_FIXEDPOINT_SHIFT;

            if weight < 2 {
                weight = 2;
            }
        }
        weight
    }

    #[allow(dead_code)]
    pub const fn scale_load(weight: u64) -> u64 {
        weight << Self::SCHED_FIXEDPOINT_SHIFT
    }
}

pub trait SchedArch {
    /// 开启当前核心的调度
    fn enable_sched_local();
    /// 关闭当前核心的调度
    #[allow(dead_code)]
    fn disable_sched_local();

    /// 在第一次开启调度之前，进行初始化工作。
    ///
    /// 注意区别于sched_init，这个函数只是做初始化时钟的工作等等。
    fn initial_setup_sched_local() {}
}

/// ## PerCpu的运行队列，其中维护了各个调度器对应的rq
#[allow(dead_code)]
#[derive(Debug)]
pub struct CpuRunQueue {
    lock: SpinLock<()>,

    cpu: ProcessorId,
    clock_task: u64,
    clock: u64,
    prev_irq_time: u64,
    clock_updata_flags: ClockUpdataFlag,

    /// 过载
    overload: bool,

    /// 下一次负载均衡时间（jiffies）。
    /// 使用 AtomicU64 以便在 trigger_load_balance（rq 锁内）和 rebalance_domains（无 rq 锁）中无锁写入。
    pub(crate) next_balance: AtomicU64,

    /// 运行任务数
    nr_running: AtomicUsize,

    /// 被阻塞的任务数量
    /// 单个 CPU 的计数器可以下溢为负数，但全局总和始终正确。
    /// 允许跨 CPU 迁移时正确累减，避免 `saturating_sub` 导致的 loadavg 膨胀。
    nr_uninterruptible: AtomicIsize,

    /// 因 IO 阻塞而睡眠的任务数量（用于区分 iowait）
    nr_iowait: AtomicUsize,

    /// 记录上次更新负载时间
    calc_load_update: u64,
    calc_load_active: isize,

    /// CFS调度器
    cfs: Arc<CfsRunQueue>,

    fifo: fifo::FifoRunQueue,

    clock_pelt: u64,
    lost_idle_time: u64,
    clock_idle: u64,

    cfs_tasks: LinkedList<Arc<FairSchedEntity>>,

    /// 最近一次的调度信息
    sched_info: SchedInfo,

    /// 当前在运行队列上执行的进程。
    ///
    /// Linux 6.6 使用裸指针 `struct task_struct __rcu *curr`
    /// `rq->curr` 作为 "current" 持有一个引用计数；
    /// `finish_task_switch` 通过 `put_task_struct_rcu_user` 在 RCU 宽限期后释放。
    /// 安全由以下机制保证：
    /// - rq lock 保护 curr 的修改
    /// - on_cpu flag 防止 prev 在上下文切换完成前被并发唤醒
    /// - 引用计数保证 task_struct 在 curr 指向期间不被释放
    /// - RCU 宽限期保证并发读取者不会观察到已释放的内存
    ///
    /// DragonOS 使用 Arc 替代裸指针：
    /// - 原因：DragonOS 无 RCU 机制；若使用 Weak，prev 在 __schedule 中 dequeue 后
    ///   若所有外部强引用消失（如父进程 wait() 完成），Weak::upgrade() 会失败。
    ///   Arc 保证 rq 在上下文切换完成前始终持有有效引用。
    /// - 安全：rq lock + on_cpu flag + switch_finish_hook 释放 prev 的 Arc。
    /// - 代价：rq.current() 每次执行 Arc::clone()（原子递增），Linux 仅一次指针读取。
    current: Option<Arc<ProcessControlBlock>>,

    /// 专供无锁路径（如 `is_idle_cpu`）读取当前任务指针。
    ///
    /// 与 `current` 字段保持同步：`set_current` 时以 `Release` 写入，
    /// 无锁读取时以 `Acquire` 加载。存储的是 `Arc::as_ptr` 的裸指针，
    /// 不转移所有权，PCB 生命周期由 `current` 中的 Arc 保证。
    current_ptr: AtomicPtr<ProcessControlBlock>,

    idle: Weak<ProcessControlBlock>,

    /// 是否有待处理的远程唤醒。
    ttwu_pending: AtomicBool,

    /// 该 CPU 的 sched_domain 层级（单层模型下只有一个）
    sched_domain: Option<Arc<SchedDomain>>,
}

impl CpuRunQueue {
    #[inline]
    pub fn cpu(&self) -> ProcessorId {
        self.cpu
    }

    /// # Safety
    /// 调用者必须保证当前 CPU 持有此 rq 的锁，且上下文切换已完成。
    #[inline]
    pub unsafe fn force_unlock(&self) {
        self.lock.force_unlock();
    }

    pub fn new(cpu: ProcessorId) -> Self {
        Self {
            lock: SpinLock::new(()),
            cpu,
            clock_task: 0,
            clock: 0,
            prev_irq_time: 0,
            clock_updata_flags: ClockUpdataFlag::empty(),
            overload: false,
            next_balance: AtomicU64::new(clock().saturating_add(1)),
            nr_running: AtomicUsize::new(0),
            nr_uninterruptible: AtomicIsize::new(0),
            nr_iowait: AtomicUsize::new(0),
            calc_load_update: clock() + (5 * HZ + 1),
            calc_load_active: 0,
            cfs: Arc::new(CfsRunQueue::new()),
            fifo: fifo::FifoRunQueue::new(),
            clock_pelt: 0,
            lost_idle_time: 0,
            clock_idle: 0,
            cfs_tasks: LinkedList::new(),
            sched_info: SchedInfo::default(),
            current: None,
            current_ptr: AtomicPtr::new(core::ptr::null_mut()),
            idle: Weak::new(),
            ttwu_pending: AtomicBool::new(false),
            sched_domain: None,
        }
    }

    /// 此函数只能在关中断的情况下使用！！！
    /// 获取到 rq 的可变引用，并显式持有 rq 锁。
    #[allow(clippy::mut_from_ref)]
    #[track_caller]
    pub fn self_lock(&self) -> (&mut Self, SpinLockGuard<'_, ()>) {
        let mut spins = 0usize;
        let guard = loop {
            if let Ok(guard) = self.lock.try_lock_irqsave() {
                break guard;
            }

            spins += 1;
            if spins >= 1_000_000 {
                let caller = Location::caller();
                panic!(
                    "CpuRunQueue::self_lock spinout on cpu {:?}, caller {}:{}",
                    self.cpu,
                    caller.file(),
                    caller.line()
                );
            }

            core::hint::spin_loop();
        };
        (self.force_mut_locked(), guard)
    }

    /// `raw_spin_rq_lock(rq)`：只获取自旋锁 + preempt_disable，不做 irqsave。
    /// 调用者须保证 IRQ 已禁用（如 `__schedule` 入口的 `local_irq_disable`）。
    /// Guard drop 时只做 unlock + preempt_enable，不恢复 IRQ。
    #[allow(clippy::mut_from_ref)]
    #[track_caller]
    pub fn self_lock_no_irq(&self) -> (&mut Self, SpinLockGuard<'_, ()>) {
        let mut spins = 0usize;
        let guard = loop {
            if let Ok(guard) = self.lock.try_lock() {
                break guard;
            }

            spins += 1;
            if spins >= 1_000_000 {
                let caller = Location::caller();
                panic!(
                    "CpuRunQueue::self_lock_no_irq spinout on cpu {:?}, caller {}:{}",
                    self.cpu,
                    caller.file(),
                    caller.line()
                );
            }

            core::hint::spin_loop();
        };
        (self.force_mut_locked(), guard)
    }

    /// 尝试获取锁，失败时立即返回 `None` 而不是自旋。
    /// 用于需要避免死锁的并发路径（如负载均衡获取第二把锁）。
    #[track_caller]
    pub fn try_self_lock(&self) -> Option<(&mut Self, SpinLockGuard<'_, ()>)> {
        match self.lock.try_lock_irqsave() {
            Ok(guard) => Some((self.force_mut_locked(), guard)),
            Err(_) => None,
        }
    }

    /// # Safety
    /// 调用者必须保证不存在对该 `CpuRunQueue` 的其他并发引用。
    /// 实践中这意味着调用者必须持有该 runqueue 的锁。
    #[allow(clippy::mut_from_ref)]
    unsafe fn force_mut(&self) -> &mut Self {
        unsafe { (self as *const Self as *mut Self).as_mut().unwrap() }
    }

    /// 仅允许在已经持有 rq 锁的路径中使用。
    #[allow(clippy::mut_from_ref)]
    pub fn force_mut_locked(&self) -> &mut Self {
        assert!(
            self.lock.is_locked(),
            "rq must be locked before mutable access"
        );
        unsafe { self.force_mut() }
    }

    /// 获取运行队列的任务数（不加锁），用于负载均衡决策
    #[inline]
    pub fn nr_running_lockless(&self) -> usize {
        self.nr_running.load(Ordering::Acquire)
    }

    pub fn enqueue_task(&mut self, pcb: Arc<ProcessControlBlock>, flags: EnqueueFlag) {
        if !flags.contains(EnqueueFlag::ENQUEUE_NOCLOCK) {
            self.update_rq_clock();
        }

        if !flags.contains(EnqueueFlag::ENQUEUE_RESTORE) {
            let sched_info = pcb.sched_info().sched_stat.upgradeable_read_irqsave();
            if sched_info.last_queued == 0 {
                sched_info.upgrade().last_queued = self.clock;
            }
        }

        match pcb.sched_info().policy() {
            SchedPolicy::CFS => CompletelyFairScheduler::enqueue(self, pcb, flags),
            SchedPolicy::FIFO => FifoScheduler::enqueue(self, pcb, flags),
            SchedPolicy::RT => todo!(),
            SchedPolicy::IDLE => IdleScheduler::enqueue(self, pcb, flags),
        }

        // TODO:https://code.dragonos.org.cn/xref/linux-6.6.21/kernel/sched/core.c#239
    }

    pub fn dequeue_task(&mut self, pcb: Arc<ProcessControlBlock>, flags: DequeueFlag) {
        // TODO:sched_core

        if !flags.contains(DequeueFlag::DEQUEUE_NOCLOCK) {
            self.update_rq_clock()
        }

        if !flags.contains(DequeueFlag::DEQUEUE_SAVE) {
            let sched_info = pcb.sched_info().sched_stat.upgradeable_read_irqsave();

            if sched_info.last_queued > 0 {
                let delta = self.clock - sched_info.last_queued;

                let mut sched_info = sched_info.upgrade();
                sched_info.last_queued = 0;
                sched_info.run_delay += delta as usize;

                self.sched_info.run_delay += delta as usize;
            }
        }

        match pcb.sched_info().policy() {
            SchedPolicy::CFS => CompletelyFairScheduler::dequeue(self, pcb, flags),
            SchedPolicy::FIFO => FifoScheduler::dequeue(self, pcb, flags),
            SchedPolicy::RT => todo!(),
            SchedPolicy::IDLE => IdleScheduler::dequeue(self, pcb, flags),
        }
    }

    /// 将任务加入运行队列，设置 on_rq = Queued。
    pub fn activate_task(&mut self, pcb: &Arc<ProcessControlBlock>, mut flags: EnqueueFlag) {
        // 1. 迁移标志处理
        if pcb.sched_info().on_rq.get() == OnRq::Migrating {
            flags |= EnqueueFlag::ENQUEUE_MIGRATED;
        }
        // if flags.contains(EnqueueFlag::ENQUEUE_MIGRATED) {
        //     todo!()
        // }

        // 2. enqueue_task
        self.enqueue_task(pcb.clone(), flags);

        // 3. 设置 on_rq = Queued
        pcb.sched_info().on_rq.set(OnRq::Queued);
    }

    /// 检查对应的task是否可以抢占当前运行的task
    #[allow(clippy::comparison_chain)]
    pub fn check_preempt_current(&mut self, pcb: &Arc<ProcessControlBlock>, flags: WakeupFlags) {
        if pcb.sched_info().policy() == self.current_ref().sched_info().policy() {
            match self.current_ref().sched_info().policy() {
                SchedPolicy::CFS => {
                    CompletelyFairScheduler::check_preempt_current(self, pcb, flags)
                }
                SchedPolicy::FIFO => FifoScheduler::check_preempt_current(self, pcb, flags),
                SchedPolicy::RT => todo!(),
                SchedPolicy::IDLE => IdleScheduler::check_preempt_current(self, pcb, flags),
            }
        } else if pcb.sched_info().policy() < self.current_ref().sched_info().policy() {
            // 调度优先级更高
            self.resched_current();
        }

        if self.current_ref().sched_info().on_rq.get() == OnRq::Queued
            && self
                .current_ref()
                .flags()
                .contains(ProcessFlags::NEED_SCHEDULE)
        {
            self.clock_updata_flags
                .insert(ClockUpdataFlag::RQCF_REQ_SKIP);
        }
    }

    /// 远端 wakeup/策略调整场景下的保守抢占检查。
    ///
    /// Linux 会在持有目标 rq 锁且目标 rq 时钟已更新后执行完整的 wakeup-preempt 检查。
    /// 当前明确禁止跨核 `update_rq_clock()`，因此远端路径只能保留那些不依赖
    /// `rq.clock_task` 最新值的抢占决策：
    /// - 更高调度类抢占；
    /// - FIFO 优先级抢占；
    /// - idle 被非 idle 任务抢占。
    ///
    /// CFS 的 wakeup-preempt 需要像 Linux `check_preempt_wakeup()` 一样先更新当前实体，
    /// 这在远端场景会重新引入“错误 CPU 更新目标 rq 时钟”的问题，因此这里故意跳过。
    #[allow(clippy::comparison_chain)]
    pub fn check_preempt_remote(&mut self, pcb: &Arc<ProcessControlBlock>, flags: WakeupFlags) {
        let current_policy = self.current_ref().sched_info().policy();
        let next_policy = pcb.sched_info().policy();

        if self
            .current_ref()
            .flags()
            .contains(ProcessFlags::NEED_SCHEDULE)
        {
            if current_policy == SchedPolicy::IDLE {
                self.resched_current();
            }
            return;
        }

        if next_policy < current_policy {
            self.resched_current();
        } else if next_policy == current_policy {
            match current_policy {
                SchedPolicy::CFS => {}
                SchedPolicy::FIFO => FifoScheduler::check_preempt_current(self, pcb, flags),
                SchedPolicy::RT => todo!(),
                SchedPolicy::IDLE => IdleScheduler::check_preempt_current(self, pcb, flags),
            }
        }

        if self.current_ref().sched_info().on_rq.get() == OnRq::Queued
            && self
                .current_ref()
                .flags()
                .contains(ProcessFlags::NEED_SCHEDULE)
        {
            self.clock_updata_flags
                .insert(ClockUpdataFlag::RQCF_REQ_SKIP);
        }
    }

    /// 设置 on_rq，将任务移出运行队列
    pub fn deactivate_task(&mut self, pcb: Arc<ProcessControlBlock>, flags: DequeueFlag) {
        // 1. 根据标志设置 on_rq 状态
        pcb.sched_info().on_rq.set(
            if flags.intersects(DequeueFlag::DEQUEUE_SLEEP | DequeueFlag::DEQUEUE_STOPPED) {
                OnRq::None
            } else {
                OnRq::Migrating
            },
        );

        // 2. dequeue_task
        self.dequeue_task(pcb, flags);
    }

    #[inline]
    pub fn cfs_rq(&self) -> Arc<CfsRunQueue> {
        self.cfs.clone()
    }

    #[inline]
    pub fn sched_domain(&self) -> Option<Arc<SchedDomain>> {
        self.sched_domain.clone()
    }

    #[inline]
    pub fn set_sched_domain(&mut self, sd: Option<Arc<SchedDomain>>) {
        self.sched_domain = sd;
    }

    #[inline]
    pub fn cfs_load_avg_lockless(&self) -> usize {
        self.cfs.load_avg_lockless()
    }

    /// 获取 CFS 运行队列的 util_avg（CPU 利用率）。
    #[inline]
    pub fn cfs_util_avg_lockless(&self) -> usize {
        self.cfs.util_avg_lockless()
    }

    /// 获取 CFS 运行队列的 runnable_avg（可运行时间）。
    #[inline]
    pub fn cfs_runnable_avg_lockless(&self) -> usize {
        self.cfs.runnable_avg_lockless()
    }

    /// 获取 CFS 运行队列的 h_nr_running（CFS 层任务计数）。
    #[inline]
    pub fn cfs_h_nr_running_lockless(&self) -> u64 {
        self.cfs.h_nr_running
    }

    /// 获取因 IO 阻塞而睡眠的任务数量
    #[inline]
    pub fn nr_iowait(&self) -> usize {
        self.nr_iowait.load(Ordering::Relaxed)
    }

    /// 在持有 rq 锁的上下文中排空本 CPU 的 WakeQueue，将所有待唤醒任务 activate
    ///
    /// 调用前提：
    /// - 调用者持有本 rq 的锁（通过 self_lock / try_self_lock）
    /// - 调用者在 `update_rq_clock()` 之后调用
    ///
    /// 此函数将激活逻辑从 IPI handler 中移出，避免 IPI handler
    /// 因等待 rq 锁而死锁（如 load_balance 通过 double_rq_lock 持有远端 rq 锁）。
    pub fn drain_wake_queue(&mut self) {
        let cpu = self.cpu;
        let wq = cpu_wakequeue(cpu.data() as usize);
        let mut requeued = false;
        for pcb in wq.drain() {
            let state = pcb.sched_info().state();
            // 已退出进程不可被唤醒，跳过过期条目以防重新入队。
            if state.is_exited() {
                continue;
            }

            // sched_ttwu_pending：如果任务已在某个 rq 上排队，
            // 说明它已经被 activate 过了（可能被另一个 wakeup 路径抢先处理），
            // 此时不能调用 __set_task_cpu，否则会破坏 cfs_rq 指针导致 dequeue mismatch。
            // activate_task 内部也有同样的 on_rq==Queued 早退，但我们必须在
            // __set_task_cpu 之前拦截，因为后者是无条件执行的。
            if pcb.sched_info().on_rq.get() == OnRq::Queued {
                log::trace!(
                    "drain_wake_queue: pid={:?} already queued, skip",
                    pcb.raw_pid()
                );
                continue;
            }

            let on_cpu = pcb.sched_info().on_cpu();
            if on_cpu == Some(cpu) {
                // 这个任务的 on_cpu 指向当前 CPU。
                // 检查它是否就是 rq 的 current task（即正在运行的任务）。
                // 如果是，说明 wakelist 入队发生在 __schedule pick 之前，
                // 该任务已经被 activate + schedule in，这是一个 stale entry。
                if Arc::ptr_eq(&pcb, self.current.as_ref().unwrap()) {
                    log::debug!(
                        "drain_wake_queue: pid={:?} is current task on this rq, skip stale entry",
                        pcb.raw_pid()
                    );
                    continue;
                }
                // 不是 current 但 on_cpu == Some(this_cpu)：不应该发生，
                // 因为同一 CPU 上同一时刻只有一个任务的 on_cpu==Some。
                log::warn!(
                    "drain_wake_queue: pid={:?} on_cpu==Some(this_cpu) but not current, waiting",
                    pcb.raw_pid()
                );
            }

            // on_cpu 指向其他 CPU：不能在持有 rq lock 时 busy-spin（会阻塞 scheduler tick），
            // 重新入队留给下一个 tick 处理。
            if on_cpu.is_some() {
                log::trace!(
                    "drain_wake_queue: pid={:?} on_cpu={:?} still running, re-queue",
                    pcb.raw_pid(),
                    on_cpu
                );
                wq.push(pcb.clone());
                requeued = true;
                continue;
            }

            let prev_cpu = task_cpu(&pcb);
            let migrated = prev_cpu != cpu;

            // 先迁移（set_task_cpu），后在目标 rq（已持锁）上递减。
            if migrated {
                log::trace!(
                    "drain_wake_queue: migrating pid={:?} prev_cpu={:?} -> local_cpu={:?}",
                    pcb.raw_pid(),
                    prev_cpu,
                    cpu
                );
                if pcb
                    .flags()
                    .contains(crate::process::ProcessFlags::IN_IOWAIT)
                {
                    cpu_rq(prev_cpu.data() as usize).dec_nr_iowait();
                }
                __set_task_cpu(&pcb, cpu);
            }

            // nr_uninterruptible 在目标 rq（self，已持锁）上递减
            if pcb
                .flags()
                .contains(crate::process::ProcessFlags::SCHED_CONTRIBUTES_TO_LOAD)
            {
                self.dec_nr_uninterruptible();
                pcb.flags()
                    .remove(crate::process::ProcessFlags::SCHED_CONTRIBUTES_TO_LOAD);
            }
            if !migrated
                && pcb
                    .flags()
                    .contains(crate::process::ProcessFlags::IN_IOWAIT)
            {
                self.dec_nr_iowait();
            }
            // 新 fork 的 CFS 任务 util_avg 初始为 0（init_entity_runnable_average），
            // 首次 activate 前需初始化 PELT，此条件仅在 fork 路径触发一次。
            if pcb.sched_info().policy() == SchedPolicy::CFS
                && pcb
                    .sched_info()
                    .sched_entity()
                    .avg
                    .util_avg
                    .load(Ordering::Relaxed)
                    == 0
            {
                crate::sched::pelt::SchedulerAvg::post_init_entity_util_avg(&pcb);
            }

            let mut flags = EnqueueFlag::ENQUEUE_WAKEUP | EnqueueFlag::ENQUEUE_NOCLOCK;
            if migrated {
                flags |= EnqueueFlag::ENQUEUE_MIGRATED;
            }

            self.activate_task(&pcb, flags);
            // DragonOS 没有 sched_remote_wakeup 字段，但 migrated 局部变量等价于此判断。
            let wake_flags = if migrated {
                WakeupFlags::WF_MIGRATED
            } else {
                WakeupFlags::empty()
            };
            self.check_preempt_current(&pcb, wake_flags);
        }

        // 如果有 re-queue 的条目，保持 ttwu_pending=true，下一个 tick 会再处理。
        // 如果没有 re-queue，清除标志：
        //   - 有 activate 的路径：nr_running > 0，is_idle_cpu 返回 false，正确。
        //   - 全 skip 的路径：nr_running 不变，WakeQueue 为空，is_idle_cpu 返回 true，正确。
        if !requeued {
            self.ttwu_pending.store(false, Ordering::Release);
        }
    }

    /// 更新rq时钟
    pub fn update_rq_clock(&mut self) {
        debug_assert_eq!(
            self.cpu,
            smp_get_processor_id(),
            "update_rq_clock must run on its own cpu"
        );

        let clock = SchedClock::sched_clock_cpu(self.cpu);
        self.update_rq_clock_from_clock(clock);
    }

    pub fn update_rq_clock_from_clock(&mut self, clock: u64) {
        // 需要跳过这次时钟更新
        if self
            .clock_updata_flags
            .contains(ClockUpdataFlag::RQCF_ACT_SKIP)
        {
            return;
        }

        if clock < self.clock {
            return;
        }

        let delta = clock - self.clock;
        self.clock += delta;
        // error!("clock {}", self.clock);
        self.update_rq_clock_task(delta);
    }

    /// 更新任务时钟
    pub fn update_rq_clock_task(&mut self, mut delta: u64) {
        let mut irq_delta = irq_time_read(self.cpu) - self.prev_irq_time;
        // if self.cpu == 0 {
        //     error!(
        //         "cpu 0 delta {delta} irq_delta {} irq_time_read(self.cpu) {} self.prev_irq_time {}",
        //         irq_delta,
        //         irq_time_read(self.cpu),
        //         self.prev_irq_time
        //     );
        // }
        compiler_fence(Ordering::SeqCst);

        if irq_delta > delta {
            irq_delta = delta;
        }

        self.prev_irq_time += irq_delta;

        delta -= irq_delta;

        // todo: psi?

        // send_to_default_serial8250_port(format!("\n{delta}\n",).as_bytes());
        compiler_fence(Ordering::SeqCst);
        self.clock_task += delta;

        self.update_rq_clock_pelt(delta);
    }

    pub fn calculate_global_load_tick(&mut self) {
        loadavg::calc_global_load_tick(self);
    }

    pub fn add_nr_running(&mut self, nr_running: usize) {
        let prev = self.nr_running.fetch_add(nr_running, Ordering::Relaxed);
        loadavg::inc_nr_running(nr_running);
        if prev < 2 && prev + nr_running >= 2 && !self.overload {
            self.overload = true;
        }
    }

    pub fn sub_nr_running(&mut self, count: usize) {
        let prev = self.nr_running.load(Ordering::Relaxed);
        let actual_dec = if prev < count {
            log::warn!("sub_nr_running underflow: prev={prev} count={count}");
            self.nr_running.store(0, Ordering::Relaxed);
            prev
        } else {
            self.nr_running.store(prev - count, Ordering::Relaxed);
            count
        };
        let new_val = self.nr_running.load(Ordering::Relaxed);
        loadavg::dec_nr_running(actual_dec);
        if new_val < 2 && self.overload {
            self.overload = false;
        }
    }

    /// per-CPU 计数器，跨 CPU 迁移时允许负数。
    /// Linux 使用 `unsigned int` 并依赖无符号回绕；DragonOS 使用 `AtomicIsize` 直接表达。
    pub fn dec_nr_uninterruptible(&self) {
        self.nr_uninterruptible.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn dec_nr_iowait(&self) {
        loop {
            let prev = self.nr_iowait.load(Ordering::Relaxed);
            if prev == 0 {
                warn!("nr_iowait underflow");
                return;
            }
            if self
                .nr_iowait
                .compare_exchange_weak(prev, prev - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    /// 在运行idle？
    pub fn sched_idle_rq(&self) -> bool {
        let nr_running = self.nr_running.load(Ordering::Relaxed);
        return unlikely(nr_running == self.cfs.idle_h_nr_running as usize && nr_running > 0);
    }

    /// 获取当前进程的 Arc 引用（原子递增引用计数）。
    ///
    /// 仅在需要 Arc 所有权时使用（如 context switch 传参）。
    /// 热路径读取请使用 `current_ref()`。
    #[inline]
    pub fn current(&self) -> Arc<ProcessControlBlock> {
        self.current.clone().expect("rq current is None")
    }

    /// 零开销读取当前进程引用，不增加引用计数。
    ///
    /// # Preconditions
    ///
    /// 调用者必须满足以下任一条件：
    /// 1. 持有 rq lock（通过 `self_lock()` / `try_self_lock()`）
    /// 2. 在本 CPU 的中断上下文中（如 scheduler_tick），此时 prev 不会并发释放
    ///
    /// PCB 不会被释放的保证：
    /// - rq lock 保护 `current` 字段的修改
    /// - `on_cpu` flag 防止 PCB 在为 current 期间被释放
    /// - `prev` Arc 在 __schedule 栈帧中持有，直到任务被重新调度时栈帧展开才释放
    #[inline]
    pub fn current_ref(&self) -> &ProcessControlBlock {
        self.current.as_ref().expect("rq current is None")
    }

    #[inline]
    pub fn set_current(&mut self, pcb: Arc<ProcessControlBlock>) {
        self.current_ptr
            .store(Arc::as_ptr(&pcb) as *mut _, Ordering::Release);
        self.current = Some(pcb);
    }

    /// 无锁读取当前任务指针，仅用于 `is_idle_cpu` 等不持有 rq lock 的路径。
    /// Linux `idle_cpu()` (core.c:7325) 同样无锁直接读 `rq->curr`
    /// （x86 指针自然对齐，天然原子）。DragonOS 用 AtomicPtr + Acquire
    /// 在 Rust 安全框架下提供等价的原子性保证。
    #[inline]
    pub fn current_ptr_lockless(&self) -> *const ProcessControlBlock {
        self.current_ptr.load(Ordering::Acquire)
    }

    #[inline]
    pub fn idle(&self) -> Weak<ProcessControlBlock> {
        self.idle.clone()
    }

    #[inline]
    pub fn set_idle(&mut self, pcb: Weak<ProcessControlBlock>) {
        self.idle = pcb;
    }

    #[inline]
    pub fn clock_task(&self) -> u64 {
        self.clock_task
    }

    /// 重新调度当前进程
    pub fn resched_current(&self) {
        let already_set = self
            .current_ref()
            .flags()
            .contains(ProcessFlags::NEED_SCHEDULE);
        self.current_ref()
            .flags()
            .insert(ProcessFlags::NEED_SCHEDULE);

        let cpu = self.cpu;

        if cpu == smp_get_processor_id() {
            return;
        }

        // 对标 Linux: idle CPU 即使 NEED_RESCHED 已设置也需要 kick（退出 C-state）。
        // 非 IDLE 任务在 NEED_SCHEDULE 已设置时无需重复发送 IPI。
        if already_set && self.current_ref().sched_info().policy() != SchedPolicy::IDLE {
            return;
        }

        // 向目标cpu发送重调度ipi
        send_resched_ipi(cpu);
    }

    /// 选择下一个task
    pub fn pick_next_task(&mut self, prev: Arc<ProcessControlBlock>) -> Arc<ProcessControlBlock> {
        // prev 可能已被迁移到其他 CPU（on_cpu == None），
        // 此时跳过 debug_assert——迁移块已清理 prev 在本 rq 的调度器状态。
        if prev.sched_info().on_cpu().is_some() {
            debug_assert_eq!(prev.sched_info().on_cpu(), Some(self.cpu));
        }

        let mut next: Option<Arc<ProcessControlBlock>> = None;

        if self.fifo.nr_running() > 0 {
            next = FifoScheduler::pick_next_task(self, Some(prev.clone()));
        }

        if next.is_none() {
            next = CompletelyFairScheduler::pick_next_task(self, Some(prev.clone()));
        }

        let next = next.unwrap_or_else(|| self.idle.upgrade().unwrap());

        if !Arc::ptr_eq(&prev, &next) {
            // 仅在 prev 仍在本 CPU 时执行 put_prev_task。
            // 迁移路径已在迁移块中完成等效清理（CFS: set_current(Weak::default())），
            // 若再次 put_prev_task，put_prev_entity 会操作 dest_cpu 的 cfs_rq
            // 并静默清除其 current 指针。
            if prev.sched_info().on_cpu() == Some(self.cpu) {
                match prev.sched_info().policy() {
                    SchedPolicy::FIFO => FifoScheduler::put_prev_task(self, prev),
                    SchedPolicy::RT => todo!(),
                    SchedPolicy::CFS => CompletelyFairScheduler::put_prev_task(self, prev),
                    SchedPolicy::IDLE => IdleScheduler::put_prev_task(self, prev),
                }
            }

            if next.sched_info().policy() == SchedPolicy::CFS {
                CompletelyFairScheduler::set_next_task(self, next.clone());
            }
        }

        next
    }
}

/// 远程唤醒队列（per-CPU）。
/// 当任务在 CPU A 被唤醒但目标 CPU 是 B 时，任务被放入 B 的 WakeQueue，
/// 由 B 在 IPI 处理中自行出队并 activate，避免跨 CPU 直接操作远端 rq。
#[derive(Debug)]
pub struct WakeQueue {
    list: SpinLock<LinkedList<Arc<ProcessControlBlock>>>,
}

impl WakeQueue {
    pub fn new() -> Self {
        Self {
            list: SpinLock::new(LinkedList::new()),
        }
    }

    pub fn push(&self, pcb: Arc<ProcessControlBlock>) {
        self.list.lock_irqsave().push_back(pcb);
    }

    pub fn drain(&self) -> LinkedList<Arc<ProcessControlBlock>> {
        core::mem::take(&mut *self.list.lock_irqsave())
    }
}

/// 将目标 CPU 标记 ttwu_pending 然后把任务 push 到 WakeQueue，再发送 IPI。
pub fn wakequeue_push_and_kick(cpu: ProcessorId, pcb: Arc<ProcessControlBlock>) {
    let rq = cpu_rq(cpu.data() as usize);
    rq.ttwu_pending.store(true, Ordering::Release);
    let wq = cpu_wakequeue(cpu.data() as usize);
    wq.push(pcb);
    send_resched_ipi(cpu);
}

/// 远程唤醒入队。
/// 将任务放入目标 CPU 的 WakeQueue 并发送 IPI，由目标 CPU 本地处理 activate。
pub fn ttwu_queue(pcb: &Arc<ProcessControlBlock>, cpu: ProcessorId, _wake_flags: WakeupFlags) {
    wakequeue_push_and_kick(cpu, pcb.clone());
}

bitflags! {
    pub struct SchedFeature:u32 {
        /// 给予睡眠任务仅有 50% 的服务赤字。这意味着睡眠任务在被唤醒后会获得一定的服务，但不能过多地占用资源。
        const GENTLE_FAIR_SLEEPERS = 1 << 0;
        /// 将新任务排在前面，以避免已经运行的任务被饿死
        const START_DEBIT = 1 << 1;
        /// 在调度时优先选择上次唤醒的任务，因为它可能会访问之前唤醒的任务所使用的数据，从而提高缓存局部性。
        const NEXT_BUDDY = 1 << 2;
        /// 在调度时优先选择上次运行的任务，因为它可能会访问与之前运行的任务相同的数据，从而提高缓存局部性。
        const LAST_BUDDY = 1 << 3;
        /// 认为任务的伙伴（buddy）在缓存中是热点，减少缓存伙伴被迁移的可能性，从而提高缓存局部性。
        const CACHE_HOT_BUDDY = 1 << 4;
        /// 允许唤醒时抢占当前任务。
        const WAKEUP_PREEMPTION = 1 << 5;
        /// 基于任务未运行时间来减少 CPU 的容量。
        const NONTASK_CAPACITY = 1 << 6;
        /// 将远程唤醒排队到目标 CPU，并使用调度器 IPI 处理它们，以减少运行队列锁的争用。
        const TTWU_QUEUE = 1 << 7;
        /// 在唤醒时尝试限制对最后级联缓存（LLC）域的无谓扫描。
        const SIS_UTIL = 1 << 8;
        /// 在 RT（Real-Time）任务迁移时，通过发送 IPI 来减少 CPU 之间的锁竞争。
        const RT_PUSH_IPI = 1 << 9;
        /// 启用估计的 CPU 利用率功能，用于调度决策。
        const UTIL_EST = 1 << 10;
        const UTIL_EST_FASTUP = 1 << 11;
        /// 启用备选调度周期
        const ALT_PERIOD = 1 << 12;
        /// 启用基本时间片
        const BASE_SLICE = 1 << 13;
    }

    pub struct EnqueueFlag: u8 {
        const ENQUEUE_WAKEUP	= 0x01;
        const ENQUEUE_RESTORE	= 0x02;
        const ENQUEUE_MOVE	= 0x04;
        const ENQUEUE_NOCLOCK	= 0x08;

        const ENQUEUE_MIGRATED	= 0x40;

        const ENQUEUE_INITIAL	= 0x80;
    }

    pub struct DequeueFlag: u8 {
        const DEQUEUE_SLEEP		= 0x01;
        const DEQUEUE_SAVE		= 0x02; /* Matches ENQUEUE_RESTORE */
        const DEQUEUE_MOVE		= 0x04; /* Matches ENQUEUE_MOVE */
        const DEQUEUE_NOCLOCK		= 0x08; /* Matches ENQUEUE_NOCLOCK */

        /// 任务因 job-control stop（如 SIGSTOP/SIGTSTP）不可运行而出队。
        ///
        /// 这不是 sleep，也不是 migrate：应当将 OnRq 置为 None。
        const DEQUEUE_STOPPED		= 0x10;
    }

    pub struct WakeupFlags: u8 {
        /* Wake flags. The first three directly map to some SD flag value */
        const WF_EXEC         = 0x02; /* Wakeup after exec; maps to SD_BALANCE_EXEC */
        const WF_FORK         = 0x04; /* Wakeup after fork; maps to SD_BALANCE_FORK */
        const WF_TTWU         = 0x08; /* Wakeup;            maps to SD_BALANCE_WAKE */

        const WF_SYNC         = 0x10; /* Waker goes to sleep after wakeup */
        const WF_MIGRATED     = 0x20; /* Internal use, task got migrated */
        const WF_CURRENT_CPU  = 0x40; /* Prefer to move the wakee to the current CPU. */
    }

    pub struct SchedMode: u8 {
        /*
        * Constants for the sched_mode argument of __schedule().
        *
        * The mode argument allows RT enabled kernels to differentiate a
        * preemption from blocking on an 'sleeping' spin/rwlock. Note that
        * SM_MASK_PREEMPT for !RT has all bits set, which allows the compiler to
        * optimize the AND operation out and just check for zero.
        */
        /// 在调度过程中不会再次进入队列，即需要手动唤醒
        const SM_NONE			= 0x0;
        /// 重新加入队列，即当前进程被抢占，需要时钟调度
        const SM_PREEMPT		= 0x1;
        /// rt相关
        const SM_RTLOCK_WAIT		= 0x2;
        /// 默认与SM_PREEMPT相同
        const SM_MASK_PREEMPT	= Self::SM_PREEMPT.bits;
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum OnRq {
    None = 0,
    Queued = 1,
    Migrating = 2,
}

impl ProcessManager {
    pub fn update_process_times(user_tick: bool) {
        let pcb = Self::current_pcb();
        CpuTimeFunc::irqtime_account_process_tick(&pcb, user_tick, 1);

        scheduler_tick();
    }
}

/// ## 时钟tick时调用此函数
pub fn scheduler_tick() {
    fence(Ordering::SeqCst);
    // 获取当前CPU索引
    let cpu_idx = smp_get_processor_id().data() as usize;

    // 获取当前CPU的请求队列
    let rq = cpu_rq(cpu_idx);

    let (rq, guard) = rq.self_lock();

    // 获取当前请求队列的当前请求
    let current = rq.current();

    // 更新请求队列时钟
    rq.update_rq_clock();

    match current.sched_info().policy() {
        SchedPolicy::CFS => CompletelyFairScheduler::tick(rq, current, false),
        SchedPolicy::FIFO => FifoScheduler::tick(rq, current, false),
        SchedPolicy::RT => todo!(),
        SchedPolicy::IDLE => IdleScheduler::tick(rq, current, false),
    }

    rq.calculate_global_load_tick();

    rq.drain_wake_queue();

    if let Some((cpu, idle_type)) = trigger_load_balance(rq) {
        drop(guard);
        crate::exception::workqueue::schedule_work(crate::exception::workqueue::Work::new(
            move || {
                rebalance::rebalance_domains(cpu, idle_type);
            },
        ));
    } else {
        drop(guard);
    }
}

/// 检查时间窗口和 domain 状态，满足条件时通过 workqueue 延迟执行 `rebalance_domains`。
/// Linux 使用 `raise_softirq(SCHED_SOFTIRQ)`，DragonOS 暂时使用 `schedule_work` 等效。
fn trigger_load_balance(rq: &CpuRunQueue) -> Option<(ProcessorId, rebalance::CpuIdleType)> {
    let _sd = rq.sched_domain()?;

    let jiffies = clock();
    if jiffies < rq.next_balance.load(Ordering::Relaxed) {
        return None;
    }

    if !load_balance::LoadBalancer::should_balance(rq) {
        return None;
    }

    let cpu = rq.cpu();
    let idle_type = if rq.nr_running_lockless() == 0 {
        rebalance::CpuIdleType::Idle
    } else {
        rebalance::CpuIdleType::NotIdle
    };
    Some((cpu, idle_type))
}

/// 检查当前进程是否被标记需要重新调度。
#[inline(always)]
pub fn need_resched() -> bool {
    ProcessManager::current_pcb()
        .flags()
        .contains(ProcessFlags::NEED_SCHEDULE)
}

/// ## 执行调度
/// 如果 context switch 期间 `NEED_RESCHED` 被并发唤醒重新设置，
/// 立即重新调度而不是返回调用者，避免调度延迟。
#[inline]
pub fn schedule(sched_mod: SchedMode) {
    loop {
        ProcessManager::preempt_disable();
        let switched = __schedule(sched_mod);
        if !switched {
            ProcessManager::preempt_enable();
        }
        if !need_resched() {
            break;
        }
    }
}

/// IO 调度函数：标记当前进程正在等待 IO 并触发调度
///
/// 此函数用于在进程因 IO 操作而需要睡眠时调用，它会：
/// 1. 设置 IN_IOWAIT 标志，表示进程正在等待 IO
/// 2. 调用 schedule() 触发调度
/// 3. 进程被唤醒后自动清除 IN_IOWAIT 标志
///
/// 这样可以正确统计 iowait 时间，区分 CPU 空闲是因为等待 IO 还是纯粹空闲
pub fn io_schedule() {
    let current = ProcessManager::current_pcb();
    // 设置 IO 等待标志
    current.flags().insert(ProcessFlags::IN_IOWAIT);
    // 调用普通调度
    schedule(SchedMode::SM_NONE);
    // 被唤醒后清除 IO 等待标志
    current.flags().remove(ProcessFlags::IN_IOWAIT);
}

/// ## 执行调度
/// 调用者必须在调用前 preempt_disable。
/// 返回 true 表示发生了 context switch（preempt_count 已由 switch_finish_hook 释放），
/// 返回 false 表示 same-task 路径（preempt_count 仍需调用方 preempt_enable）。
pub fn __schedule(sched_mod: SchedMode) -> bool {
    let cpu = smp_get_processor_id().data() as usize;
    let rq = cpu_rq(cpu);

    let irq_was_enabled = CurrentIrqArch::is_irq_enabled();
    local_irq_disable();
    let prev = rq.current();

    // TODO: hrtick_clear(rq);

    // IRQ 已禁用，只获取 spinlock + preempt_disable，不做 irqsave。
    let (rq, guard) = rq.self_lock_no_irq();

    // 防止 signal_pending_state() 与调用方 __set_current_state() 重排序。
    fence(Ordering::SeqCst);

    let mut voluntary_switch = false;

    rq.clock_updata_flags = ClockUpdataFlag::from_bits_truncate(rq.clock_updata_flags.bits() << 1);

    rq.update_rq_clock();
    rq.clock_updata_flags = ClockUpdataFlag::RQCF_UPDATE;

    let mut prev_migrated = false;

    if let Some(dest_cpu) = take_current_migration_target(&prev) {
        debug_assert!(
            !task_is_idle(&prev),
            "idle task must not be migrated through current task migration"
        );
        debug_assert!(
            cpu_is_online(dest_cpu),
            "current task migration target {:?} must be online",
            dest_cpu
        );
        debug_assert!(
            prev.sched_info()
                .cpus_allowed()
                .get(dest_cpu)
                .unwrap_or(false),
            "current task migration target {:?} must be allowed by affinity",
            dest_cpu
        );

        rq.deactivate_task(
            prev.clone(),
            DequeueFlag::DEQUEUE_MOVE | DequeueFlag::DEQUEUE_NOCLOCK,
        );

        if prev.sched_info().policy() == SchedPolicy::CFS {
            let mut se = prev.sched_info().sched_entity();
            crate::sched::fair::FairSchedEntity::for_each_in_group(&mut se, |se| {
                unsafe { se.cfs_rq().force_mut().set_current(Weak::default()) };
                (true, true)
            });
        }

        prev.sched_info().on_rq.set(OnRq::None);
        __set_task_cpu(&prev, dest_cpu);
        prev.sched_info().set_on_cpu(None);

        // 将迁移目标存入 PROCESS_SWITCH_RESULT，由 switch_finish_hook 在
        // set_on_cpu(None) 之后 push WakeQueue + send_resched_ipi。
        unsafe {
            crate::process::PROCESS_SWITCH_RESULT
                .as_mut()
                .unwrap()
                .get_mut()
                .migrate_dest = Some(dest_cpu);
        }

        prev_migrated = true;
    }

    // kBUG!(
    //     "before cfs rq pcbs {:?}\nvruntimes {:?}\n",
    //     rq.cfs
    //         .entities
    //         .iter()
    //         .map(|x| { x.1.pcb().pid() })
    //         .collect::<Vec<_>>(),
    //     rq.cfs
    //         .entities
    //         .iter()
    //         .map(|x| { x.1.vruntime })
    //         .collect::<Vec<_>>(),
    // );

    if !prev_migrated
        && !sched_mod.contains(SchedMode::SM_MASK_PREEMPT)
        && prev.sched_info().policy() != SchedPolicy::IDLE
    {
        // 关键设计：prev 的 state / wake_kill / mark_sleep 均通过 AtomicU32 / AtomicBool 无锁读取
        // 因此 __schedule 持有 rq_lock 期间不需要再获取 pi_lock。
        // （对比 ttwu 路径的 pi_lock → rq_lock 顺序）这避免了 rq_lock → pi_lock 的嵌套死锁风险。
        let prev_state = prev.sched_info().state();
        let is_mark_sleep = prev.sched_info().is_mark_sleep();

        let is_exited = matches!(prev_state, ProcessState::Exited(_));

        let is_stopped = matches!(prev_state, ProcessState::Stopped);
        if is_mark_sleep || is_exited || is_stopped {
            // switch_count = &prev->nvcsw
            voluntary_switch = true;
            // 对标 Linux signal_pending_state(prev_state, prev)：
            //   TASK_INTERRUPTIBLE                       → 有任意信号 → 恢复 RUNNING
            //   TASK_STOPPED (含 TASK_WAKEKILL)           → 仅 SIGKILL → 恢复 RUNNING
            //   TASK_UNINTERRUPTIBLE                     → 不检查信号，直接 deactivate
            // SM_PREEMPT 路径不检查信号，因为异步 stop 不应被信号恢复。
            let interruptible = prev_state.is_blocked_interruptable();
            let wake_kill = is_stopped || prev.sched_info().wake_kill();

            let has_signal = !is_exited
                && !sched_mod.contains(SchedMode::SM_MASK_PREEMPT)
                && Signal::signal_pending_state(interruptible, wake_kill, &prev);
            if has_signal {
                prev.flags().remove(ProcessFlags::SCHED_CONTRIBUTES_TO_LOAD);
                prev.sched_info().set_state(ProcessState::Runnable);
                prev.sched_info().set_wakeup();
            } else if is_exited {
                // TASK_DEAD 任务直接 deactivate，不计入负载。
                prev.flags().remove(ProcessFlags::SCHED_CONTRIBUTES_TO_LOAD);
                if prev.sched_info().on_rq.get() == OnRq::Queued {
                    rq.deactivate_task(
                        prev.clone(),
                        DequeueFlag::DEQUEUE_SLEEP | DequeueFlag::DEQUEUE_NOCLOCK,
                    );
                }
            } else {
                // sched_contributes_to_load 和 nr_uninterruptible++ 必须在任务正式离开运行队列之前完成。
                let contributes_to_load = matches!(prev_state, ProcessState::Blocked(false));
                if contributes_to_load {
                    prev.flags().insert(ProcessFlags::SCHED_CONTRIBUTES_TO_LOAD);
                    rq.nr_uninterruptible.fetch_add(1, Ordering::Relaxed);
                } else {
                    prev.flags().remove(ProcessFlags::SCHED_CONTRIBUTES_TO_LOAD);
                }

                if prev.sched_info().on_rq.get() == OnRq::Queued {
                    rq.deactivate_task(
                        prev.clone(),
                        DequeueFlag::DEQUEUE_SLEEP | DequeueFlag::DEQUEUE_NOCLOCK,
                    );
                }

                // nr_iowait++ 在 deactivate_task 之后
                if prev.flags().contains(ProcessFlags::IN_IOWAIT) {
                    rq.nr_iowait.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    let next = rq.pick_next_task(prev.clone());

    if task_is_idle(&next) {
        IDLE_CPUS.set(rq.cpu);
    } else if task_is_idle(&prev) {
        IDLE_CPUS.clear(rq.cpu);
    }

    prev.flags().remove(ProcessFlags::NEED_SCHEDULE);
    fence(Ordering::SeqCst);
    if likely(!Arc::ptr_eq(&prev, &next)) {
        // core.c:6687: ++*switch_count
        if voluntary_switch {
            prev.inc_nvcsw();
        } else {
            prev.inc_nivcsw();
        }

        crate::process::rseq::Rseq::on_preempt(&prev);
        if next.rseq_state().is_registered() {
            next.flags().insert(ProcessFlags::NEED_RSEQ);
        }

        // Linux __schedule 不检查 cpus_allowed 迁移。
        // 迁移由 set_cpus_allowed_ptr → migration thread 处理，
        // 或 try_to_wake_up → select_task_rq → set_task_cpu 处理。

        rq.set_current(next.clone());

        crate::process::account_context_switch();

        // 在 context_switch 前设置 next->on_cpu
        // ttwu 观察到 on_cpu==None 时可能迁移 prev；必须在 finish_task_switch 读取 prev->state 之后才能清除
        next.sched_info().set_on_cpu(Some(rq.cpu()));
        // warn!(
        //     "switch_process prev {:?} next {:?} sched_mode {sched_mod:?}",
        //     prev.pid(),
        //     next.pid()
        // );

        // send_to_default_serial8250_port(
        //     format!(
        //         "switch_process prev {:?} next {:?} sched_mode {sched_mod:?}\n",
        //         prev.pid(),
        //         next.pid()
        //     )
        //     .as_bytes(),
        // );

        // CurrentApic.send_eoi();
        compiler_fence(Ordering::SeqCst);

        // prepare_lock_switch: 对标 Linux，rq lock 在 context_switch 期间持续持有。
        // 由 switch_finish_hook（finish_lock_switch）释放。
        // 这确保 on_cpu 清除、wakelist 排空等操作在 rq lock 保护下完成，防止远程 CPU 在上下文切换窗口中操作本 rq
        core::mem::forget(guard);

        unsafe { ProcessManager::switch_process(prev, next) };
        true
    } else {
        drop(guard);
        if irq_was_enabled {
            local_irq_enable();
        }
        false
    }
}

/// 初始化子进程的调度信息：继承父进程 normal_prio、设置调度策略、
/// 初始化 PELT runnable average。
///
/// 注意：此函数在 fork 上下文中调用，子进程尚未加入 pid-hash，
/// 子进程是 TASK_NEW，不可见。可以直接写裸字段。
pub fn sched_fork(pcb: &Arc<ProcessControlBlock>) -> Result<(), SystemError> {
    let current = ProcessManager::current_pcb();
    let fork_prio = current.sched_info().normal_prio();

    // 子进程继承父进程的 prio、static_prio、normal_prio
    pcb.sched_info().set_prio(fork_prio);
    pcb.sched_info()
        .set_static_prio(current.sched_info().static_prio());
    pcb.sched_info().set_normal_prio(fork_prio);
    pcb.sched_info()
        .set_rt_priority(current.sched_info().rt_priority());

    if PrioUtil::dl_prio(fork_prio) {
        return Err(SystemError::EAGAIN_OR_EWOULDBLOCK);
    } else if PrioUtil::rt_prio(fork_prio) {
        // 子进程继承父进程的调度策略（FIFO/RR），而非统一设为 RT
        pcb.sched_info().set_policy(current.sched_info().policy());
    } else {
        pcb.sched_info().set_policy(SchedPolicy::CFS);
    }

    unsafe { pcb.sched_info().sched_entity().force_mut() }.init_entity_runnable_average();

    let lw = FairSchedEntity::set_load_weight(pcb.sched_info().static_prio());
    unsafe { pcb.sched_info().sched_entity().force_mut() }.load = lw;

    Ok(())
}

pub fn sched_cgroup_fork(pcb: &Arc<ProcessControlBlock>) {
    // 在 irq 关闭下绑定父 CPU + task_fork
    let _guard = unsafe { CurrentIrqArch::save_and_disable_irq() };
    let fork_cpu = smp_get_processor_id();
    __set_task_cpu(pcb, fork_cpu);
    match pcb.sched_info().policy() {
        SchedPolicy::CFS => CompletelyFairScheduler::task_fork(pcb.clone()),
        SchedPolicy::FIFO => FifoScheduler::task_fork(pcb.clone()),
        // TODO: RT / IDLE task_fork 待实现
        _ => {}
    }

    debug_assert_eq!(
        pcb.sched_info().sched_entity().cfs_rq().rq().cpu(),
        fork_cpu,
        "fork-time task_fork must only charge the local rq clock"
    );
}

/// Fork 后的唯一唤醒入口：做一次 select_task_rq(WF_FORK) 负载均衡，然后 activate_task。
/// 锁序：Linux 先 pi_lock 再 rq->lock；此处 task 尚未加入 pid-hash，pi_lock 无争用，
/// 远端路径通过 ttwu_queue 将 pi_lock 持有到 IPI 发送完成（SpinLock 不会与 rq_lock 产生 ABBA）。
pub fn wake_up_new_task(pcb: &Arc<ProcessControlBlock>) {
    let _guard = unsafe { CurrentIrqArch::save_and_disable_irq() };

    let prev_cpu = task_cpu(pcb);
    // TODO: p->recent_used_cpu = task_cpu(p); 需要在 PCB 中新增该字段，
    //       以对齐 CFS select_task_rq_fair 的快速路径优化。

    // 先拿 pi_lock 再设 state，保证锁序一致。
    let pi_guard = pcb.sched_info().pi_lock_irqsave();
    pcb.sched_info().set_state(ProcessState::Runnable);
    pcb.sched_info().set_wakeup();

    let target_cpu = crate::sched::load_balance::LoadBalancer::select_task_rq(
        pcb,
        &pi_guard,
        prev_cpu,
        WakeupFlags::WF_FORK.bits(),
    );

    let target_cpu = if target_cpu == ProcessorId::INVALID {
        log::error!(
            "wake_up_new_task: select_task_rq returned INVALID for pid={:?}, fallback to current CPU",
            pcb.raw_pid()
        );
        smp_get_processor_id()
    } else {
        target_cpu
    };
    __set_task_cpu(pcb, target_cpu);

    let current_cpu = smp_get_processor_id();
    if target_cpu == current_cpu {
        let rq = cpu_rq(target_cpu.data() as usize);
        let (rq, _rq_guard) = rq.self_lock();
        rq.update_rq_clock();
        crate::sched::pelt::SchedulerAvg::post_init_entity_util_avg(pcb);
        rq.activate_task(pcb, EnqueueFlag::ENQUEUE_NOCLOCK);
        rq.check_preempt_current(pcb, WakeupFlags::WF_FORK);
        drop(_rq_guard);
    } else {
        crate::sched::ttwu_queue(pcb, target_cpu, WakeupFlags::WF_FORK);
        return;
    }
    // TODO: 当 RT 调度实现后，需在此添加 sched_class::task_woken 回调
}

/// 返回任务当前绑定的 CPU。
/// 不通过 cfs_rq 计算，避免 cfs_rq 指针陈旧时返回错误 CPU。
#[inline]
pub fn task_cpu(pcb: &Arc<ProcessControlBlock>) -> ProcessorId {
    pcb.sched_info().cpu()
}

/// 判断指定 CPU 是否空闲：当前任务为 idle、`nr_running == 0` 且无 pending ttwu。
#[inline]
pub(crate) fn is_idle_cpu(cpu: ProcessorId) -> bool {
    if cpu == ProcessorId::INVALID {
        return false;
    }
    let rq = cpu_rq(cpu.data() as usize);
    let curr_ptr = rq.current_ptr_lockless();
    let idle = rq.idle();
    let is_idle_task = idle.upgrade().is_some_and(|i| Arc::as_ptr(&i) == curr_ptr);
    if !is_idle_task {
        return false;
    }
    if rq.nr_running_lockless() != 0 {
        return false;
    }
    if rq.ttwu_pending.load(Ordering::Acquire) {
        return false;
    }
    true
}

/// 更新任务的 CPU 绑定及对应的 cfs_rq 指针。
///
/// - 调用者必须保证任务不在运行队列上（on_rq != Queued），
///   否则 cfs_rq 指针变更会导致 rbtree 操作在错误的队列上执行。
/// - 目标 CPU 必须 online（boot 阶段除外）。
pub(crate) fn __set_task_cpu(pcb: &Arc<ProcessControlBlock>, cpu: ProcessorId) {
    if smp_cpu_manager_initialized() && !boot_in_progress() {
        assert!(
            cpu_is_online(cpu),
            "__set_task_cpu target cpu {:?} must be online outside boot",
            cpu
        );
    }

    let on_rq = pcb.sched_info().on_rq.get();
    assert!(
        on_rq != OnRq::Queued,
        "__set_task_cpu called on pid={:?} with on_rq=Queued! \
         old_cpu={:?} -> new_cpu={:?}. \
         Caller is corrupting cfs_rq while task is in rbtree.",
        pcb.raw_pid(),
        pcb.sched_info().cpu(),
        cpu,
    );

    let old_cpu = pcb.sched_info().cpu();
    if old_cpu != cpu {
        log::trace!(
            "__set_task_cpu: pid={:?} old_cpu={:?} -> new_cpu={:?} on_rq={:?}",
            pcb.raw_pid(),
            old_cpu,
            cpu,
            on_rq,
        );
    }

    // 先更新 cpu 字段，再更新 cfs_rq。on_cpu 由 prepare_task() 在 context_switch 前设置
    pcb.sched_info().set_cpu(cpu);
    if pcb.sched_info().policy() == SchedPolicy::CFS {
        let se = pcb.sched_info().sched_entity();
        let rq = cpu_rq(cpu.data() as usize);
        // 设置 cfs_rq 指向新 CPU 的队列，同时清零 last_update_time
        // 强制 PELT 在新 CPU 上重新同步，防止 stale 负载数据漂移。
        let se_mut = unsafe { se.force_mut() };
        se_mut.set_cfs(Arc::downgrade(&rq.cfs));
        se_mut.avg.last_update_time = 0;
    }
}

pub fn take_current_migration_target(current: &Arc<ProcessControlBlock>) -> Option<ProcessorId> {
    if !current.flags().contains(ProcessFlags::NEED_MIGRATE) {
        return None;
    }

    let dest_cpu = current.sched_info().migrate_to()?;
    current.sched_info().set_migrate_to(None);
    current.flags().remove(ProcessFlags::NEED_MIGRATE);
    Some(dest_cpu)
}

#[inline(never)]
pub fn sched_init() {
    // 初始化percpu变量
    unsafe {
        CPU_IRQ_TIME = Some(Vec::with_capacity(PerCpu::MAX_CPU_NUM as usize));
        CPU_IRQ_TIME
            .as_mut()
            .unwrap()
            .resize_with(PerCpu::MAX_CPU_NUM as usize, || Box::leak(Box::default()));

        let mut cpu_runqueue = Vec::with_capacity(PerCpu::MAX_CPU_NUM as usize);
        for cpu in 0..PerCpu::MAX_CPU_NUM as usize {
            let rq = Arc::new(CpuRunQueue::new(ProcessorId::new(cpu as u32)));
            rq.cfs.force_mut().set_rq(Arc::downgrade(&rq));
            cpu_runqueue.push(rq);
        }

        CPU_RUNQUEUE.init(PerCpuVar::new(cpu_runqueue).unwrap());

        let mut cpu_wakequeue = Vec::with_capacity(PerCpu::MAX_CPU_NUM as usize);
        for _cpu in 0..PerCpu::MAX_CPU_NUM as usize {
            cpu_wakequeue.push(Arc::new(WakeQueue::new()));
        }
        CPU_WAKEQUEUE.init(PerCpuVar::new(cpu_wakequeue).unwrap());
    };

    // 初始化 per-CPU CPU 时间统计
    cputime::init_kernel_cpu_stat();
}

#[inline]
pub fn send_resched_ipi(cpu: ProcessorId) {
    send_ipi(IpiKind::KickCpu, IpiTarget::Specified(cpu));
}

pub fn sched_yield() {
    // 禁用中断
    let irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };

    let pcb = ProcessManager::current_pcb();
    let rq = cpu_rq(current_cpu_id().data() as usize);
    let (rq, guard) = rq.self_lock();

    // TODO: schedstat_inc(rq->yld_count);

    match pcb.sched_info().policy() {
        SchedPolicy::CFS => CompletelyFairScheduler::yield_task(rq),
        SchedPolicy::FIFO => FifoScheduler::yield_task(rq),
        SchedPolicy::RT => rq.resched_current(),
        SchedPolicy::IDLE => {}
    }

    let preempt_guard = PreemptGuard::new();

    drop(guard);
    drop(irq_guard);

    drop(preempt_guard);

    schedule(SchedMode::SM_NONE);
}

pub fn request_task_migration(
    pcb: &Arc<ProcessControlBlock>,
    dest_cpu: ProcessorId,
) -> Result<(), SystemError> {
    pcb.sched_info().set_migrate_to(Some(dest_cpu));
    pcb.flags()
        .insert(ProcessFlags::NEED_MIGRATE | ProcessFlags::NEED_SCHEDULE);
    if let Some(cpu) = pcb.sched_info().on_cpu() {
        if cpu != smp_get_processor_id() {
            send_resched_ipi(cpu);
        }
    }
    Ok(())
}

pub fn nr_iowait() -> u64 {
    let mut total: u64 = 0;
    for cpu in smp_cpu_manager().present_cpus().iter_cpu() {
        let rq = cpu_rq(cpu.data() as usize);
        total += rq.nr_iowait() as u64;
    }
    total
}

#[cfg(test)]
mod tests {
    use super::loadavg;
    use crate::sched::CpuRunQueue;
    use crate::smp::cpu::ProcessorId;

    #[test]
    fn rq_overload_clears_after_nr_running_drops_below_two() {
        let mut rq = CpuRunQueue::new(ProcessorId::new(0));
        let global_before = loadavg::nr_running();

        rq.add_nr_running(2);
        assert!(rq.overload);
        assert_eq!(rq.nr_running.load(Ordering::Relaxed), 2);

        rq.sub_nr_running(1);
        assert!(!rq.overload);
        assert_eq!(rq.nr_running.load(Ordering::Relaxed), 1);

        assert_eq!(loadavg::nr_running(), global_before + 1);

        rq.sub_nr_running(1);
        assert_eq!(rq.nr_running.load(Ordering::Relaxed), 0);
        assert_eq!(loadavg::nr_running(), global_before);
    }
}
