//! Immutable, deny-by-default system call allowlists.
//!
//! A policy is useful only when the kernel enforces it on every syscall,
//! including fast paths. Allowing a syscall does not restrict its arguments
//! or the handles it can use.

use alloc::vec::Vec;

pub const MAX_PATH_RULES: u64 = 64;
pub const MAX_SYSCALL_RULES: u64 = 256;
pub const MAX_SPAWN_CHANNELS: u64 = 32;
pub const PATH_READ: u64 = 1;
pub const PATH_WRITE: u64 = 2;
pub const PATH_EXEC: u64 = 4;
pub const SPAWN_SUSPENDED: u64 = 1;

/// A canonical absolute UTF-8 subtree and its access bits.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PathRule {
    pub path: u64,
    pub path_len: u64,
    pub access: u64,
}

/// Pointer/count pairs. The kernel copies each array and path before spawn.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SpawnPolicy {
    pub paths: u64,
    pub path_count: u64,
    pub syscalls: u64,
    pub syscall_count: u64,
    /// Optional channel capability installed as handle 3 in the child.
    pub broker_handle: u64,
    pub flags: u64,
    /// Existing channel handles installed consecutively after the broker.
    pub channels: u64,
    pub channel_count: u64,
}

impl Default for SpawnPolicy {
    fn default() -> Self {
        Self { paths: 0, path_count: 0, syscalls: 0, syscall_count: 0, broker_handle: crate::HANDLE_NONE, flags: 0, channels: 0, channel_count: 0 }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SyscallPolicy {
    allowed: Vec<u64>,
}

impl SyscallPolicy {
    pub fn new(allowed: &[u64]) -> Self {
        let mut allowed = allowed.to_vec();
        allowed.sort_unstable();
        allowed.dedup();
        Self { allowed }
    }

    pub fn allows(&self, number: u64) -> bool {
        self.allowed.binary_search(&number).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{PathRule, SpawnPolicy, SyscallPolicy};

    #[test]
    fn spawn_policy_layout_and_default_broker() {
        assert_eq!(core::mem::size_of::<PathRule>(), 24);
        assert_eq!(core::mem::size_of::<SpawnPolicy>(), 64);
        assert_eq!(SpawnPolicy::default().broker_handle, crate::HANDLE_NONE);
        assert_eq!(SpawnPolicy::default().channel_count, 0);
    }

    #[test]
    fn deny_by_default_and_support_full_syscall_number_range() {
        let empty = SyscallPolicy::default();
        assert!(!empty.allows(0));
        let policy = SyscallPolicy::new(&[u64::MAX, 5, 0, 5]);
        assert!(policy.allows(0));
        assert!(policy.allows(5));
        assert!(policy.allows(u64::MAX));
        assert!(!policy.allows(4));
        assert!(!policy.allows(u64::MAX - 1));
    }
}
