#![allow(dead_code)]
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::CurrentIrqArch;
use crate::exception::bottom_half::{local_bh_disable, LocalBhDisableGuard};
use crate::exception::{InterruptArch, IrqFlagsGuard};
use crate::process::ProcessManager;
use system_error::SystemError;

/// 实现了守卫的SpinLock, 能够支持内部可变性
///
#[derive(Debug)]
pub struct SpinLock<T> {
    lock: AtomicBool,
    /// 自旋锁保护的数据
    data: UnsafeCell<T>,
}

/// SpinLock的守卫
/// 该守卫没有构造器，并且其信息均为私有的。我们只能通过SpinLock的lock()方法获得一个守卫。
/// 因此我们可以认为，只要能够获得一个守卫，那么数据就在自旋锁的保护之下。
#[derive(Debug)]
pub struct SpinLockGuard<'a, T: 'a> {
    lock: &'a SpinLock<T>,
    data: *mut T,
    irq_flag: Option<IrqFlagsGuard>,
}

/// `spin_lock_bh` 风格的守卫：持锁期间屏蔽本 CPU 的 softirq/tasklet 执行（不关硬中断）。
///
/// Drop 顺序：先解锁(guard)，再恢复 BH。等价于 Linux 的 `spin_unlock_bh`。
/// Rust 按字段声明顺序 drop，因此 guard 必须在 bh 前面。
pub struct SpinLockBhGuard<'a, T: 'a> {
    guard: SpinLockGuard<'a, T>,
    bh: LocalBhDisableGuard,
}

impl<'a, T: 'a> SpinLockGuard<'a, T> {
    /// 泄露自旋锁的守卫，返回一个可变的引用
    ///
    ///  ## Safety
    ///
    /// 由于这样做可能导致守卫在另一个线程中被释放，从而导致pcb的preempt count不正确，
    /// 因此必须小心的手动维护好preempt count。
    ///
    /// 并且，leak还可能导致锁的状态不正确。因此请仔细考虑是否真的需要使用这个函数。
    #[inline]
    pub unsafe fn leak(this: Self) -> &'a mut T {
        // Use ManuallyDrop to avoid stacked-borrow invalidation
        let this = ManuallyDrop::new(this);
        // We know statically that only we are referencing data
        unsafe { &mut *this.lock.data.get() }
    }
}

/// 向编译器保证，SpinLock在线程之间是安全的.
/// 其中要求类型T实现了Send这个Trait
unsafe impl<T> Sync for SpinLock<T> where T: Send {}

impl<T> SpinLock<T> {
    /// 在外部同步保证下，不获取锁直接读取内部数据的共享引用。
    ///
    /// # Safety
    ///
    /// 调用者必须保证通过其他同步机制（如另一个锁）与所有写者互斥。
    /// 调用期间绝对不能有其他代码通过 `lock()`/`try_lock()` 等方式获取写访问。
    ///
    /// 对标 Linux: 这个模式等价于 Linux 中在 `rq_lock` 保护下读取
    /// `pi_lock` 保护的字段（如 `p->cpus_ptr`）。Linux 依赖 `rq_lock` 与写者
    /// 互斥（core.c:486-493），此处依赖同样的原理。
    #[inline]
    pub(crate) unsafe fn get_assume_locked(&self) -> &T {
        &*self.data.get()
    }

    pub const fn new(value: T) -> Self {
        return Self {
            lock: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        };
    }

    #[inline(always)]
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        loop {
            let res = self.try_lock();
            if let Ok(res) = res {
                return res;
            }
            spin_loop();
        }
    }

    pub fn lock_irqsave(&self) -> SpinLockGuard<'_, T> {
        let irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };
        ProcessManager::preempt_disable();
        loop {
            if self.inner_try_lock() {
                return SpinLockGuard {
                    lock: self,
                    data: unsafe { &mut *self.data.get() },
                    irq_flag: Some(irq_guard),
                };
            }
            spin_loop();
        }
    }

    /// `spin_lock_bh()`：禁用本 CPU BH 后获取锁。
    ///
    /// 注意：该接口不关硬中断；若同一把锁也会在 hardirq 获取，则必须用 `lock_irqsave()`。
    pub fn lock_bh(&self) -> SpinLockBhGuard<'_, T> {
        let bh = local_bh_disable();
        // `local_bh_disable()` 不禁用抢占，由 `lock()` 来禁用
        let guard = self.lock();
        SpinLockBhGuard { bh, guard }
    }

    pub fn try_lock(&self) -> Result<SpinLockGuard<'_, T>, SystemError> {
        // 先增加自旋锁持有计数
        ProcessManager::preempt_disable();

        if self.inner_try_lock() {
            return Ok(SpinLockGuard {
                lock: self,
                data: unsafe { &mut *self.data.get() },
                irq_flag: None,
            });
        }

        // 如果加锁失败恢复自旋锁持有计数
        ProcessManager::preempt_enable();

        return Err(SystemError::EAGAIN_OR_EWOULDBLOCK);
    }

    fn inner_try_lock(&self) -> bool {
        let res = self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok();
        return res;
    }

    pub fn try_lock_irqsave(&self) -> Result<SpinLockGuard<'_, T>, SystemError> {
        let irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };
        ProcessManager::preempt_disable();
        if self.inner_try_lock() {
            return Ok(SpinLockGuard {
                lock: self,
                data: unsafe { &mut *self.data.get() },
                irq_flag: Some(irq_guard),
            });
        }
        ProcessManager::preempt_enable();
        drop(irq_guard);
        return Err(SystemError::EAGAIN_OR_EWOULDBLOCK);
    }

    /// 强制解锁，并且不更改preempt count
    ///
    /// ## Safety
    ///
    /// 由于这样做可能导致preempt count不正确，因此必须小心的手动维护好preempt count。
    /// 如非必要，请不要使用这个函数。
    /// 获取锁并禁用中断，但**不增加** preempt_count。
    ///
    /// 专用于 context_switch 中 `SpinLockGuard::leak()` 场景：guard 被 leak 后
    /// Drop 不会执行，如果用 `try_lock_irqsave` 则 `preempt_disable` 永远不会被平衡。
    /// 由于 context_switch 在 IRQ 已禁用 + rq lock 已持有的上下文中执行，
    /// 抢占不可能发生，因此跳过 preempt_disable 是安全的。
    ///
    /// ## Safety
    ///
    /// 调用者必须保证：
    /// - 本 CPU 硬中断已禁用（或等价的无抢占环境）
    /// - 守卫将通过 `SpinLockGuard::leak()` 泄漏，由 `force_unlock()` 手动释放
    /// - 不需要对 preempt_count 的维护
    pub unsafe fn lock_irqsave_no_preempt(&self) -> SpinLockGuard<'_, T> {
        let irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };
        loop {
            if self.inner_try_lock() {
                return SpinLockGuard {
                    lock: self,
                    data: unsafe { &mut *self.data.get() },
                    irq_flag: Some(irq_guard),
                };
            }
            spin_loop();
        }
    }

    pub unsafe fn force_unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }

    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }

    pub fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed)
    }
}

/// 实现Deref trait，支持通过获取SpinLockGuard来获取临界区数据的不可变引用
impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        return unsafe { &*self.data };
    }
}

/// 实现DerefMut trait，支持通过获取SpinLockGuard来获取临界区数据的可变引用
impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        return unsafe { &mut *self.data };
    }
}

/// @brief 为SpinLockGuard实现Drop方法，那么，一旦守卫的生命周期结束，就会自动释放自旋锁，避免了忘记放锁的情况
impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock();
        // 先恢复中断，再启用抢占
        self.irq_flag.take();
        ProcessManager::preempt_enable();
    }
}

impl<T> Deref for SpinLockBhGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.guard.deref()
    }
}

impl<T> DerefMut for SpinLockBhGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.deref_mut()
    }
}
