//! Building blocks of the OSyx virtual file system that do not depend on
//! the kernel: path handling, permission checks, the mount table and the
//! types file system drivers exchange with the VFS.
//!
//! The kernel VFS (`kernel/src/vfs`) combines them with drivers and locks;
//! everything here is unit-tested on the host.

#![no_std]

extern crate alloc;

pub mod mounts;
pub mod path;
pub mod perm;
pub mod sandbox;

pub use mounts::MountTable;
pub use osyx_abi::{Errno, FileStat};
pub use perm::{Access, Cred};

use alloc::string::String;

/// One directory entry as a driver reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub ino: u64,
    /// `osyx_abi::KIND_*`.
    pub kind: u32,
}

/// What a create call makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewNode<'a> {
    File,
    Dir,
    Symlink(&'a str),
}

impl NewNode<'_> {
    pub fn kind(&self) -> u32 {
        match self {
            NewNode::File => osyx_abi::KIND_FILE,
            NewNode::Dir => osyx_abi::KIND_DIR,
            NewNode::Symlink(_) => osyx_abi::KIND_SYMLINK,
        }
    }
}

/// Capacity of a volume (`statfs`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsUsage {
    pub block_size: u64,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
}

pub type Result<T> = core::result::Result<T, Errno>;
