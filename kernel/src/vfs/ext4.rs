//! VFS adapter for the ext4 driver (`osyx-ext4`): one sleeping mutex per
//! volume. Ownership and permission bits come from the inodes.

use super::{Filesystem, Result};
use crate::block::{BlockDev, Disk};
use crate::sync::KMutex;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use osyx_abi::*;
use osyx_ext4::inode::{S_IFBLK, S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use osyx_ext4::{dir as ft, Error, Ext4, MountOptions, NewKind};
use osyx_vfs::{Cred, DirEntry, FsUsage, NewNode};

pub fn errno(e: Error) -> Errno {
    match e {
        Error::Io => Errno::Io,
        Error::NotExt | Error::Corrupt(_) => Errno::Io,
        Error::Unsupported(_) => Errno::Unsupported,
        Error::NotFound => Errno::NotFound,
        Error::NotADirectory => Errno::NotADirectory,
        Error::IsADirectory => Errno::IsADirectory,
        Error::AlreadyExists => Errno::AlreadyExists,
        Error::DirectoryNotEmpty => Errno::DirectoryNotEmpty,
        Error::InvalidName | Error::InvalidInput(_) => Errno::InvalidArgument,
        Error::NoSpace => Errno::NoSpace,
        Error::FileTooLarge => Errno::FileTooLarge,
        Error::ReadOnly => Errno::ReadOnly,
    }
}

fn kind_of_mode(mode: u16) -> u32 {
    match mode & S_IFMT {
        S_IFDIR => KIND_DIR,
        S_IFLNK => KIND_SYMLINK,
        S_IFCHR => KIND_CHAR_DEVICE,
        S_IFBLK => KIND_BLOCK_DEVICE,
        // Regular files, and FIFOs/sockets (not supported yet) as plain files.
        _ => KIND_FILE,
    }
}

fn kind_of_ft(t: u8) -> Option<u32> {
    Some(match t {
        ft::FT_REG => KIND_FILE,
        ft::FT_DIR => KIND_DIR,
        ft::FT_SYMLINK => KIND_SYMLINK,
        ft::FT_CHR => KIND_CHAR_DEVICE,
        ft::FT_BLK => KIND_BLOCK_DEVICE,
        ft::FT_FIFO | ft::FT_SOCK => KIND_FILE,
        _ => return None,
    })
}

fn clock() -> (i64, u32) {
    let ns = crate::time::now_ns();
    (ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000) as u32)
}

pub struct Ext4Volume {
    fs: KMutex<Ext4<Disk>>,
    device: String,
    label: String,
    read_only: bool,
    /// Uptime (ms) when write-back first saw unwritten changes; 0 = clean.
    dirty_since: core::sync::atomic::AtomicU64,
}

/// How long file data and metadata may stay only in memory.
pub const DIRTY_EXPIRE_MS: u64 = 5000;

impl Ext4Volume {
    /// Mounts the volume; a writable mount is refused (`Unsupported`) when
    /// the driver cannot write it safely.
    pub fn mount(disk: Arc<dyn BlockDev>, read_only: bool) -> Result<Ext4Volume> {
        let device = disk.name().to_string();
        let read_only = read_only || disk.read_only();
        let fs = Ext4::mount(Disk(disk), MountOptions { read_only, clock: Some(clock) }).map_err(|e| {
            crate::kprintln!("ext4 {device}: {e}");
            errno(e)
        })?;
        if let Some(why) = fs.write_refusal() {
            crate::kprintln!("ext4 {device}: read-only: {why}");
        }
        if fs.recovered_blocks > 0 || fs.orphans_freed > 0 {
            crate::kprintln!(
                "ext4 {device}: recovery replayed {} journal blocks, freed {} orphaned inodes",
                fs.recovered_blocks,
                fs.orphans_freed
            );
        }
        let label = fs.label();
        Ok(Ext4Volume { fs: KMutex::new(fs), device, label, read_only, dirty_since: core::sync::atomic::AtomicU64::new(0) })
    }

    fn ino(n: u64) -> Result<u32> {
        u32::try_from(n).map_err(|_| Errno::NotFound)
    }
}

impl Filesystem for Ext4Volume {
    fn fs_type(&self) -> &'static str {
        "ext4"
    }

    fn root(&self) -> u64 {
        osyx_ext4::ROOT_INO as u64
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn lookup(&self, dir: u64, name: &str) -> Result<u64> {
        self.fs.lock().lookup(Self::ino(dir)?, name).map(|i| i as u64).map_err(errno)
    }

    fn stat(&self, ino: u64) -> Result<FileStat> {
        let s = self.fs.lock().stat(Self::ino(ino)?).map_err(errno)?;
        Ok(FileStat {
            size: if s.mode & S_IFMT == S_IFDIR || s.mode & S_IFMT == S_IFREG || s.mode & S_IFMT == S_IFLNK { s.size } else { 0 },
            ino,
            blocks: s.blocks_512,
            atime_ns: s.atime_ns,
            mtime_ns: s.mtime_ns,
            ctime_ns: s.ctime_ns,
            kind: kind_of_mode(s.mode),
            mode: (s.mode & 0o7777) as u32,
            uid: s.uid,
            gid: s.gid,
            nlink: s.links as u32,
            ..Default::default()
        })
    }

    fn read_dir(&self, dir: u64) -> Result<Vec<DirEntry>> {
        let mut fs = self.fs.lock();
        let list = fs.read_dir(Self::ino(dir)?).map_err(errno)?;
        let mut out = Vec::with_capacity(list.len());
        for e in list {
            let kind = match kind_of_ft(e.file_type) {
                Some(k) => k,
                None => kind_of_mode(fs.stat(e.ino).map_err(errno)?.mode),
            };
            out.push(DirEntry { name: e.name, ino: e.ino as u64, kind });
        }
        Ok(out)
    }

    fn readlink(&self, ino: u64) -> Result<String> {
        self.fs.lock().readlink(Self::ino(ino)?).map_err(errno)
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.fs.lock().read(Self::ino(ino)?, offset, buf).map_err(errno)
    }

    fn write(&self, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        if self.read_only {
            return Err(Errno::ReadOnly);
        }
        self.fs.lock().write(Self::ino(ino)?, offset, data).map_err(errno)
    }

    fn truncate(&self, ino: u64, size: u64) -> Result<()> {
        if self.read_only {
            return Err(Errno::ReadOnly);
        }
        self.fs.lock().truncate(Self::ino(ino)?, size).map_err(errno)
    }

    fn create(&self, dir: u64, name: &str, what: NewNode<'_>, mode: u32, cred: &Cred) -> Result<u64> {
        if self.read_only {
            return Err(Errno::ReadOnly);
        }
        let kind = match what {
            NewNode::File => NewKind::File,
            NewNode::Dir => NewKind::Dir,
            NewNode::Symlink(t) => NewKind::Symlink(t),
        };
        self.fs.lock().create(Self::ino(dir)?, name, kind, mode as u16, cred.uid, cred.gid).map(|i| i as u64).map_err(errno)
    }

    fn unlink(&self, dir: u64, name: &str) -> Result<()> {
        if self.read_only {
            return Err(Errno::ReadOnly);
        }
        self.fs.lock().unlink(Self::ino(dir)?, name).map_err(errno)
    }

    fn rmdir(&self, dir: u64, name: &str) -> Result<()> {
        if self.read_only {
            return Err(Errno::ReadOnly);
        }
        self.fs.lock().rmdir(Self::ino(dir)?, name).map_err(errno)
    }

    fn rename(&self, sdir: u64, sname: &str, ddir: u64, dname: &str) -> Result<()> {
        if self.read_only {
            return Err(Errno::ReadOnly);
        }
        self.fs.lock().rename(Self::ino(sdir)?, sname, Self::ino(ddir)?, dname).map_err(errno)
    }

    fn link(&self, dir: u64, name: &str, target: u64) -> Result<()> {
        if self.read_only {
            return Err(Errno::ReadOnly);
        }
        self.fs.lock().link(Self::ino(dir)?, name, Self::ino(target)?).map_err(errno)
    }

    fn set_mode(&self, ino: u64, mode: u32) -> Result<()> {
        if self.read_only {
            return Err(Errno::ReadOnly);
        }
        self.fs.lock().set_mode(Self::ino(ino)?, mode as u16).map_err(errno)
    }

    fn open(&self, ino: u64) -> Result<()> {
        self.fs.lock().open(Self::ino(ino)?);
        Ok(())
    }

    fn release(&self, ino: u64) {
        if let Ok(i) = Self::ino(ino) {
            if let Err(e) = self.fs.lock().release(i) {
                crate::kprintln!("ext4 {}: releasing inode {i}: {e}", self.device);
            }
        }
    }

    fn sync(&self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        self.fs.lock().sync().map_err(errno)
    }

    fn writeback(&self, now_ms: u64) -> Result<bool> {
        use core::sync::atomic::Ordering;
        if self.read_only {
            return Ok(false);
        }
        let Some(mut fs) = self.fs.try_lock() else { return Ok(false) };
        if !fs.has_pending() {
            self.dirty_since.store(0, Ordering::Relaxed);
            return Ok(false);
        }
        let since = self.dirty_since.load(Ordering::Relaxed);
        if since == 0 {
            self.dirty_since.store(now_ms.max(1), Ordering::Relaxed);
            return Ok(false);
        }
        if now_ms.saturating_sub(since) < DIRTY_EXPIRE_MS {
            return Ok(false);
        }
        let r = fs.sync().map_err(errno);
        self.dirty_since.store(0, Ordering::Relaxed);
        r.map(|_| true)
    }

    fn unmount(&self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        self.fs.lock().clean_shutdown().map_err(errno)
    }

    fn usage(&self) -> FsUsage {
        let fs = self.fs.lock();
        let (free_blocks, free_inodes) = fs.free_counts();
        let sb = fs.superblock();
        FsUsage {
            block_size: sb.block_size as u64,
            total_blocks: sb.blocks_count,
            free_blocks,
            total_inodes: sb.inodes_count as u64,
            free_inodes: free_inodes as u64,
        }
    }

    fn fsck(&self) -> Option<core::result::Result<String, String>> {
        Some(self.fs.lock().check().map_err(|e| alloc::format!("{e}")))
    }

    fn backing_device(&self) -> Option<String> {
        Some(self.device.clone())
    }
}
