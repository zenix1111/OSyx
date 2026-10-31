//! VFS adapter for `osyx-tmpfs`: one sleeping mutex per instance.

use super::{Filesystem, Result};
use crate::sync::KMutex;
use alloc::string::String;
use alloc::vec::Vec;
use osyx_abi::FileStat;
use osyx_tmpfs::TmpFs;
use osyx_vfs::{Cred, DirEntry, FsUsage, NewNode};

/// Memory limit of a tmpfs mounted without an explicit size.
pub const DEFAULT_LIMIT: u64 = 32 << 20;

pub struct TmpfsVolume {
    fs: KMutex<TmpFs>,
}

impl TmpfsVolume {
    pub fn new(limit: u64, root_mode: u32) -> TmpfsVolume {
        TmpfsVolume { fs: KMutex::new(TmpFs::new(limit, root_mode, crate::time::now_ns)) }
    }
}

impl Filesystem for TmpfsVolume {
    fn fs_type(&self) -> &'static str {
        "tmpfs"
    }

    fn root(&self) -> u64 {
        osyx_tmpfs::ROOT
    }

    fn lookup(&self, dir: u64, name: &str) -> Result<u64> {
        self.fs.lock().lookup(dir, name)
    }

    fn stat(&self, ino: u64) -> Result<FileStat> {
        self.fs.lock().stat(ino)
    }

    fn read_dir(&self, dir: u64) -> Result<Vec<DirEntry>> {
        self.fs.lock().read_dir(dir)
    }

    fn readlink(&self, ino: u64) -> Result<String> {
        self.fs.lock().readlink(ino)
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.fs.lock().read(ino, offset, buf)
    }

    fn write(&self, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        self.fs.lock().write(ino, offset, data)
    }

    fn truncate(&self, ino: u64, size: u64) -> Result<()> {
        self.fs.lock().truncate(ino, size)
    }

    fn create(&self, dir: u64, name: &str, what: NewNode<'_>, mode: u32, cred: &Cred) -> Result<u64> {
        self.fs.lock().create(dir, name, what, mode, cred)
    }

    fn unlink(&self, dir: u64, name: &str) -> Result<()> {
        self.fs.lock().unlink(dir, name)
    }

    fn link(&self, dir: u64, name: &str, target: u64) -> Result<()> {
        self.fs.lock().link(dir, name, target)
    }

    fn rmdir(&self, dir: u64, name: &str) -> Result<()> {
        self.fs.lock().rmdir(dir, name)
    }

    fn rename(&self, sdir: u64, sname: &str, ddir: u64, dname: &str) -> Result<()> {
        self.fs.lock().rename(sdir, sname, ddir, dname)
    }

    fn set_mode(&self, ino: u64, mode: u32) -> Result<()> {
        self.fs.lock().set_mode(ino, mode)
    }

    fn open(&self, ino: u64) -> Result<()> {
        self.fs.lock().open(ino)
    }

    fn release(&self, ino: u64) {
        self.fs.lock().release(ino)
    }

    fn usage(&self) -> FsUsage {
        self.fs.lock().usage()
    }
}
