/// Nice 值范围：-20 (最高优先级) .. +19 (最低优先级)，共 40 个级别。
pub const MAX_NICE: i32 = 19;
pub const MIN_NICE: i32 = -20;
pub const NICE_WIDTH: i32 = MAX_NICE - MIN_NICE + 1;

pub const MAX_RT_PRIO: i32 = 100;
#[allow(dead_code)]
pub const MAX_PRIO: i32 = MAX_RT_PRIO + NICE_WIDTH;
pub const DEFAULT_PRIO: i32 = MAX_RT_PRIO + NICE_WIDTH / 2;

pub const MAX_DL_PRIO: i32 = 0;

/// nice 值到 CFS 权重的映射表（对齐 Linux kernel/sched/core.c）。
/// 索引 = static_prio - MAX_RT_PRIO，范围 [0, 39]。
pub const SCHED_PRIO_TO_WEIGHT: [u64; NICE_WIDTH as usize] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

pub struct PrioUtil;
#[allow(dead_code)]
impl PrioUtil {
    #[inline]
    pub fn nice_to_prio(nice: i32) -> i32 {
        nice + DEFAULT_PRIO
    }

    #[inline]
    pub fn prio_to_nice(prio: i32) -> i32 {
        prio - DEFAULT_PRIO
    }

    #[inline]
    pub fn dl_prio(prio: i32) -> bool {
        prio < MAX_DL_PRIO
    }

    #[inline]
    pub fn rt_prio(prio: i32) -> bool {
        prio < MAX_RT_PRIO
    }

    /// 根据调度策略计算"自然"优先级（不考虑 PI 继承）。
    #[inline]
    pub fn normal_prio_for(policy: super::SchedPolicy, rt_prio_val: i32, nice: i32) -> i32 {
        match policy {
            super::SchedPolicy::CFS | super::SchedPolicy::IDLE => nice + DEFAULT_PRIO,
            super::SchedPolicy::FIFO | super::SchedPolicy::RT => MAX_RT_PRIO - 1 - rt_prio_val,
        }
    }
}
