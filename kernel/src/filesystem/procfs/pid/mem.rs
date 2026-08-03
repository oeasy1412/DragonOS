//! /proc/[pid]/mem - 目标进程虚拟地址空间访问。
//!
//! 文件偏移量即目标进程的用户虚拟地址，read/write 直接读写该地址空间。
//! 复用 ptrace 的 peek/poke_user_byte（页表翻译 + 缺页 fault-in）。

use crate::{
    filesystem::{
        procfs::{
            pid::ProcPidTarget,
            template::{Builder, FileOps, ProcFileBuilder},
        },
        vfs::{FilePrivateData, IndexNode, InodeMode},
    },
    libs::mutex::MutexGuard,
    process::ProcessControlBlock,
};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use system_error::SystemError;

/// /proc/[pid]/mem 的 FileOps 实现。
#[derive(Debug)]
pub struct MemFileOps {
    target: ProcPidTarget,
}

impl MemFileOps {
    pub fn new_inode(target: ProcPidTarget, parent: Weak<dyn IndexNode>) -> Arc<dyn IndexNode> {
        ProcFileBuilder::new(Self { target }, InodeMode::S_IRUSR | InodeMode::S_IWUSR)
            .parent(parent)
            .build()
            .unwrap()
    }

    /// 权限检查
    fn check_access(target: &Arc<ProcessControlBlock>) -> Result<(), SystemError> {
        let current = crate::process::ProcessManager::current_pcb();
        if current.has_permission_to_trace(target) {
            Ok(())
        } else {
            Err(SystemError::EACCES)
        }
    }
    /// 批量读写目标进程内存，逐字节经 access_user_byte 翻译+fault-in+锁内拷贝。
    /// 返回实际拷贝字节数；首字节失败由调用者转 EIO。
    fn access_vm(
        target: &Arc<ProcessControlBlock>,
        addr: usize,
        buf: &mut [u8],
        write: bool,
    ) -> Result<usize, SystemError> {
        let _end = addr.checked_add(buf.len()).ok_or(SystemError::EIO)?;
        let mut copied = 0usize;
        while copied < buf.len() {
            let cur = addr + copied;
            if write {
                match target.poke_user_byte(cur, buf[copied]) {
                    Ok(()) => copied += 1,
                    Err(_) => break,
                }
            } else {
                match target.peek_user_byte(cur) {
                    Ok(byte) => {
                        buf[copied] = byte;
                        copied += 1;
                    }
                    Err(_) => break,
                }
            }
        }
        Ok(copied)
    }
}

impl FileOps for MemFileOps {
    fn open(&self, _data: &mut MutexGuard<FilePrivateData>) -> Result<(), SystemError> {
        // 解析目标并做权限判定。
        let target = self.target.task().ok_or(SystemError::ESRCH)?;
        Self::check_access(&target)?;
        // open 时校验目标确有用户地址空间。
        let _ = target.basic().user_vm().ok_or(SystemError::ESRCH)?;
        Ok(())
    }

    fn read_at(
        &self,
        offset: usize,
        len: usize,
        buf: &mut [u8],
        _data: MutexGuard<FilePrivateData>,
    ) -> Result<usize, SystemError> {
        if len == 0 {
            return Ok(0);
        }
        let Some(target) = self.target.task() else {
            // 目标 PID 已不存在。
            return Ok(0);
        };
        // 目标已 exit_mm 但 PCB 仍存活（zombie/被持引用）：地址空间为空
        if target.basic().user_vm().is_none() {
            return Ok(0);
        }
        // 权限已在 open 时判定，此处不再重查。
        let actual_len = len.min(buf.len());
        let copied = Self::access_vm(&target, offset, &mut buf[..actual_len], false)?;
        // 首字节不可读且尚未拷贝任何数据时返回 EIO，避免被上层当作 EOF。
        if copied == 0 && len != 0 {
            return Err(SystemError::EIO);
        }
        Ok(copied)
    }

    fn write_at(
        &self,
        offset: usize,
        len: usize,
        buf: &[u8],
        _data: MutexGuard<FilePrivateData>,
    ) -> Result<usize, SystemError> {
        if len == 0 {
            return Ok(0);
        }
        let Some(target) = self.target.task() else {
            // 目标 PID 已不存在：与 read 一致按 0 处理。
            return Ok(0);
        };
        if target.basic().user_vm().is_none() {
            return Ok(0);
        }
        let actual_len = len.min(buf.len());
        let mut scratch = Vec::from(&buf[..actual_len]);
        let copied = Self::access_vm(&target, offset, &mut scratch, true)?;
        if copied == 0 && actual_len != 0 {
            return Err(SystemError::EIO);
        }
        Ok(copied)
    }

    fn owner(&self) -> Option<(usize, usize)> {
        self.target.owner_uid_gid()
    }
}
