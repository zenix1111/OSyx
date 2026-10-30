//! VFS adapter for the FAT32 driver (`osyx-fat`).
//!
//! FAT has no inode numbers, so the adapter assigns them: each node is
//! known by its path on the volume (with the case stored on disk), and the
//! number stays valid across renames because the path table is updated.
//! FAT cannot keep the data of a removed file, so removing or replacing a
//! file that is open fails with `Busy` (Windows behaves the same way).
//! Ownership and permissions do not exist on FAT: everything belongs to
//! root, directories are 0755 and files 0644 (0444 with the read-only
//! attribute). Metadata is written through after every change.

use super::{Filesystem, Result};
use crate::block::{BlockDev, Disk};
use crate::sync::KMutex;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use osyx_abi::{Errno, FileStat, KIND_DIR, KIND_FILE};
use osyx_fat::{FileRef, FileSystem, FsError, OpenOptions};
use osyx_vfs::path::validate_name;
use osyx_vfs::{Cred, DirEntry, FsUsage, NewNode};

/// The FAT driver's fixed timestamp (1980-01-01 00:00:00 UTC).
const FAT_EPOCH_NS: i64 = 315_532_800 * 1_000_000_000;
const ROOT: u64 = 1;

pub fn fs_errno(e: FsError) -> Errno {
    match e {
        FsError::Io => Errno::Io,
        FsError::Corrupt(_) => Errno::Io,
        FsError::NotFound => Errno::NotFound,
        FsError::AlreadyExists => Errno::AlreadyExists,
        FsError::NotADirectory => Errno::NotADirectory,
        FsError::IsADirectory => Errno::IsADirectory,
        FsError::DirectoryNotEmpty => Errno::DirectoryNotEmpty,
        FsError::InvalidName | FsError::InvalidInput(_) => Errno::InvalidArgument,
        FsError::NoSpace => Errno::NoSpace,
        FsError::FileTooLarge => Errno::FileTooLarge,
        FsError::Unsupported(_) => Errno::Unsupported,
    }
}

struct State {
    fs: FileSystem<Disk>,
    /// Node number -> path on the volume ("/" for the root).
    paths: BTreeMap<u64, String>,
    /// Lower-case path -> node number.
    by_path: BTreeMap<String, u64>,
    next: u64,
    open: BTreeMap<u64, u32>,
    /// Cached file references of regular files.
    files: BTreeMap<u64, FileRef>,
}

pub struct FatVolume {
    state: KMutex<State>,
    label: String,
    device: String,
    read_only: bool,
    /// Owner of every node (FAT has none on disk); root when `None`.
    owner: (u32, u32),
}

fn join(dir: &str, name: &str) -> String {
    osyx_vfs::path::join(dir, name)
}

impl State {
    fn path(&self, ino: u64) -> Result<String> {
        self.paths.get(&ino).cloned().ok_or(Errno::NotFound)
    }

    fn ino_for(&mut self, path: &str) -> u64 {
        let key = path.to_lowercase();
        if let Some(&i) = self.by_path.get(&key) {
            return i;
        }
        let i = self.next;
        self.next += 1;
        self.by_path.insert(key, i);
        self.paths.insert(i, path.to_string());
        i
    }

    fn forget(&mut self, path: &str) {
        if let Some(i) = self.by_path.remove(&path.to_lowercase()) {
            self.paths.remove(&i);
            self.files.remove(&i);
        }
    }

    /// Name of `name` in `dir` as stored on disk.
    fn actual_name(&mut self, dir: &str, name: &str) -> Result<String> {
        let list = self.fs.read_dir(dir).map_err(fs_errno)?;
        if list.iter().any(|e| e.name == name) {
            return Ok(name.to_string());
        }
        let lower = name.to_lowercase();
        list.into_iter().map(|e| e.name).find(|n| n.to_lowercase() == lower).ok_or(Errno::NotFound)
    }

    fn file(&mut self, ino: u64) -> Result<&mut FileRef> {
        if !self.files.contains_key(&ino) {
            let p = self.path(ino)?;
            let f = self.fs.open(&p, OpenOptions::default()).map_err(fs_errno)?;
            self.files.insert(ino, f);
        }
        Ok(self.files.get_mut(&ino).expect("just inserted"))
    }

    fn is_open(&self, ino: u64) -> bool {
        self.open.get(&ino).is_some_and(|&n| n > 0)
    }

    fn flush(&mut self) -> Result<()> {
        self.fs.flush().map_err(fs_errno)
    }
}

impl FatVolume {
    pub fn mount(disk: Arc<dyn BlockDev>, read_only: bool, owner: Option<(u32, u32)>) -> Result<FatVolume> {
        let device = disk.name().to_string();
        let read_only = read_only || disk.read_only();
        let fs = FileSystem::mount(Disk(disk)).map_err(fs_errno)?;
        let label = fs.label().to_string();
        let mut paths = BTreeMap::new();
        paths.insert(ROOT, String::from("/"));
        let mut by_path = BTreeMap::new();
        by_path.insert(String::from("/"), ROOT);
        let state = State { fs, paths, by_path, next: ROOT + 1, open: BTreeMap::new(), files: BTreeMap::new() };
        Ok(FatVolume { state: KMutex::new(state), label, device, read_only, owner: owner.unwrap_or((0, 0)) })
    }

    /// Full consistency check of the volume (FAT chains, sizes, free count).
    pub fn check(&self) -> core::result::Result<osyx_fat::CheckReport, FsError> {
        let mut s = self.state.lock();
        s.flush().map_err(|_| FsError::Io)?;
        s.fs.check()
    }

    fn modify<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        if self.read_only {
            return Err(Errno::ReadOnly);
        }
        let mut s = self.state.lock();
        let r = f(&mut s);
        let flushed = s.flush();
        let v = r?;
        flushed?;
        Ok(v)
    }
}

fn stat_of(ino: u64, md: &osyx_fat::Metadata, cluster: u64, owner: (u32, u32)) -> FileStat {
    let (kind, mode) = if md.is_dir {
        (KIND_DIR, 0o755)
    } else if md.attributes & osyx_fat::ATTR_READ_ONLY != 0 {
        (KIND_FILE, 0o444)
    } else {
        (KIND_FILE, 0o644)
    };
    let size = if md.is_dir { 0 } else { md.size as u64 };
    FileStat {
        size,
        ino,
        blocks: size.div_ceil(cluster) * (cluster / 512),
        atime_ns: FAT_EPOCH_NS,
        mtime_ns: FAT_EPOCH_NS,
        ctime_ns: FAT_EPOCH_NS,
        kind,
        mode,
        nlink: if md.is_dir { 2 } else { 1 },
        attributes: md.attributes as u32,
        uid: owner.0,
        gid: owner.1,
        ..Default::default()
    }
}

impl Filesystem for FatVolume {
    fn fs_type(&self) -> &'static str {
        "fat32"
    }

    fn root(&self) -> u64 {
        ROOT
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn lookup(&self, dir: u64, name: &str) -> Result<u64> {
        let mut s = self.state.lock();
        let dpath = s.path(dir)?;
        if !s.fs.metadata(&dpath).map_err(fs_errno)?.is_dir {
            return Err(Errno::NotADirectory);
        }
        let actual = s.actual_name(&dpath, name)?;
        Ok(s.ino_for(&join(&dpath, &actual)))
    }

    // FAT names are case-insensitive anyway.
    fn lookup_case_insensitive(&self, dir: u64, name: &str) -> Result<(u64, String)> {
        let ino = self.lookup(dir, name)?;
        let s = self.state.lock();
        let p = s.path(ino)?;
        Ok((ino, String::from(p.rsplit('/').next().unwrap_or(name))))
    }

    fn stat(&self, ino: u64) -> Result<FileStat> {
        let mut s = self.state.lock();
        let p = s.path(ino)?;
        let md = s.fs.metadata(&p).map_err(fs_errno)?;
        Ok(stat_of(ino, &md, s.fs.geometry().cluster_bytes() as u64, self.owner))
    }

    fn read_dir(&self, dir: u64) -> Result<Vec<DirEntry>> {
        let mut s = self.state.lock();
        let dpath = s.path(dir)?;
        let list = s.fs.read_dir(&dpath).map_err(fs_errno)?;
        Ok(list
            .into_iter()
            .map(|e| {
                let ino = s.ino_for(&join(&dpath, &e.name));
                DirEntry { ino, kind: if e.is_dir { KIND_DIR } else { KIND_FILE }, name: e.name }
            })
            .collect())
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut s = self.state.lock();
        let p = s.path(ino)?;
        if s.fs.metadata(&p).map_err(fs_errno)?.is_dir {
            return Err(Errno::IsADirectory);
        }
        let mut f = *s.file(ino)?;
        let r = s.fs.read(&mut f, offset, buf).map_err(fs_errno);
        s.files.insert(ino, f);
        r
    }

    fn write(&self, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        self.modify(|s| {
            let mut f = *s.file(ino)?;
            let r = s.fs.write(&mut f, offset, data).map_err(fs_errno);
            s.files.insert(ino, f);
            r
        })
    }

    fn truncate(&self, ino: u64, size: u64) -> Result<()> {
        self.modify(|s| {
            let mut f = *s.file(ino)?;
            let r = s.fs.truncate(&mut f, size).map_err(fs_errno);
            s.files.insert(ino, f);
            r
        })
    }

    fn create(&self, dir: u64, name: &str, what: NewNode<'_>, _mode: u32, _cred: &Cred) -> Result<u64> {
        validate_name(name)?;
        self.modify(|s| {
            let p = join(&s.path(dir)?, name);
            match what {
                NewNode::File => {
                    let f = s.fs.open(&p, OpenOptions { create_new: true, create: true, truncate: false }).map_err(fs_errno)?;
                    let ino = s.ino_for(&p);
                    s.files.insert(ino, f);
                    Ok(ino)
                }
                NewNode::Dir => {
                    s.fs.create_dir(&p).map_err(fs_errno)?;
                    Ok(s.ino_for(&p))
                }
                NewNode::Symlink(_) => Err(Errno::NotSupported),
            }
        })
    }

    fn unlink(&self, dir: u64, name: &str) -> Result<()> {
        self.modify(|s| {
            let dpath = s.path(dir)?;
            let actual = s.actual_name(&dpath, name)?;
            let p = join(&dpath, &actual);
            let ino = s.ino_for(&p);
            if s.is_open(ino) {
                return Err(Errno::Busy);
            }
            s.fs.remove_file(&p).map_err(fs_errno)?;
            s.forget(&p);
            Ok(())
        })
    }

    fn rmdir(&self, dir: u64, name: &str) -> Result<()> {
        self.modify(|s| {
            let dpath = s.path(dir)?;
            let actual = s.actual_name(&dpath, name)?;
            let p = join(&dpath, &actual);
            s.fs.remove_dir(&p).map_err(fs_errno)?;
            s.forget(&p);
            Ok(())
        })
    }

    fn rename(&self, sdir: u64, sname: &str, ddir: u64, dname: &str) -> Result<()> {
        validate_name(dname)?;
        self.modify(|s| {
            let sp = s.path(sdir)?;
            let from = join(&sp, &s.actual_name(&sp, sname)?);
            let to = join(&s.path(ddir)?, dname);
            if from.to_lowercase() != to.to_lowercase() {
                if let Some(&victim) = s.by_path.get(&to.to_lowercase()) {
                    if s.is_open(victim) {
                        return Err(Errno::Busy);
                    }
                }
            }
            s.fs.rename(&from, &to).map_err(fs_errno)?;
            if from.to_lowercase() != to.to_lowercase() {
                s.forget(&to);
            }
            // Move every known node at or below `from` to its new path; their
            // directory entries moved, so cached file references are stale.
            let moved: Vec<(u64, String)> = s
                .paths
                .iter()
                .filter(|(_, p)| osyx_vfs::path::is_within(p, &from))
                .map(|(&i, p)| (i, p.clone()))
                .collect();
            for (i, old) in moved {
                let new = alloc::format!("{}{}", to, &old[from.len()..]);
                s.by_path.remove(&old.to_lowercase());
                s.by_path.insert(new.to_lowercase(), i);
                s.paths.insert(i, new);
                s.files.remove(&i);
            }
            Ok(())
        })
    }

    fn set_mode(&self, _ino: u64, _mode: u32) -> Result<()> {
        Err(Errno::NotSupported)
    }

    fn open(&self, ino: u64) -> Result<()> {
        *self.state.lock().open.entry(ino).or_default() += 1;
        Ok(())
    }

    fn release(&self, ino: u64) {
        let mut s = self.state.lock();
        if let Some(n) = s.open.get_mut(&ino) {
            *n -= 1;
            if *n == 0 {
                s.open.remove(&ino);
            }
        }
    }

    fn sync(&self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        self.state.lock().flush()
    }

    fn usage(&self) -> FsUsage {
        let s = self.state.lock();
        let g = s.fs.geometry();
        FsUsage {
            block_size: g.cluster_bytes() as u64,
            total_blocks: g.cluster_count as u64,
            free_blocks: s.fs.free_clusters() as u64,
            total_inodes: 0,
            free_inodes: 0,
        }
    }

    fn fsck(&self) -> Option<core::result::Result<String, String>> {
        Some(match self.check() {
            Ok(r) if r.fsinfo_accurate => Ok(alloc::format!(
                "{} files, {} directories, {} clusters used",
                r.files,
                r.directories,
                r.used_clusters
            )),
            Ok(_) => Err(String::from("FSInfo free count is stale")),
            Err(e) => Err(alloc::format!("{e}")),
        })
    }

    fn backing_device(&self) -> Option<String> {
        Some(self.device.clone())
    }
}
