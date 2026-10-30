//! Virtual file system: mounted file systems, path resolution, permission
//! checks and open files.
//!
//! * Drivers implement [`Filesystem`], an inode-style interface (lookup a
//!   name in a directory, read/write a node by number). Each driver
//!   serialises its own state (a sleeping `KMutex` per volume).
//! * Paths are resolved one component at a time from `/` or the caller's
//!   current directory. A component whose canonical path is a mount point
//!   continues in the mounted file system's root (longest-prefix match on
//!   the mount table); symbolic links are expanded in place (at most
//!   `MAX_SYMLINKS`); `..` returns to the previous directory on the walk,
//!   so it crosses mount points correctly and never climbs above `/`.
//! * Every directory searched needs execute permission, and the usual
//!   read/write checks apply to the final node (see `osyx_vfs::perm`).
//! * An [`OpenFile`] keeps its [`Mount`] alive; a volume with open files
//!   cannot be unmounted (`Busy`). Drivers are told about open nodes, so a
//!   file that is removed while open keeps its data until the last close
//!   (tmpfs, ext4) or refuses the removal (FAT, which cannot represent it).
//!
//! Lock order: open file `KMutex` -> volume `KMutex` -> block device. The
//! mount table is a spinlock that is never held while a driver runs.
//!
//! Windows compatibility hooks: [`Lookup::case_insensitive`] resolves every
//! component case-insensitively (exact match first), and every node has a
//! stable identity `(FileStat::dev, FileStat::ino)` on which share modes
//! and byte-range locks can be built. Drive letters, `\` separators and the
//! NT object namespace are meant to be translated to VFS paths by the
//! compatibility layer, above this module (see docs/windows-compatibility.md).

pub mod devfs;
pub mod exfat;
pub mod ext4;
pub mod fat;
pub mod tmpfs;

use crate::devices::DeviceFile;
use crate::kprintln;
use crate::sync::IrqSpinLock;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use osyx_abi::*;
use osyx_vfs::path::{self, split_last, validate, validate_name};
use osyx_vfs::perm::{self, may};
use osyx_vfs::{Access, Cred, DirEntry, FsUsage, MountTable, NewNode};

pub type Result<T> = core::result::Result<T, Errno>;

/// A mounted file system driver. Node numbers are the driver's own; the
/// VFS never interprets them beyond passing them back.
pub trait Filesystem: Send + Sync {
    fn fs_type(&self) -> &'static str;
    fn root(&self) -> u64;
    /// Volume label (empty if the file system has none).
    fn label(&self) -> String {
        String::new()
    }
    fn lookup(&self, dir: u64, name: &str) -> Result<u64>;
    /// Case-insensitive (ASCII) lookup, exact match first; returns the node
    /// and the name as stored. The default scans the directory.
    fn lookup_case_insensitive(&self, dir: u64, name: &str) -> Result<(u64, String)> {
        match self.lookup(dir, name) {
            Err(Errno::NotFound) => self
                .read_dir(dir)?
                .into_iter()
                .find(|e| e.name.eq_ignore_ascii_case(name))
                .map(|e| (e.ino, e.name))
                .ok_or(Errno::NotFound),
            r => r.map(|ino| (ino, String::from(name))),
        }
    }
    fn stat(&self, ino: u64) -> Result<FileStat>;
    /// Entries without `.` and `..`.
    fn read_dir(&self, dir: u64) -> Result<Vec<DirEntry>>;
    fn readlink(&self, _ino: u64) -> Result<String> {
        Err(Errno::InvalidArgument)
    }
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn write(&self, _ino: u64, _offset: u64, _data: &[u8]) -> Result<usize> {
        Err(Errno::ReadOnly)
    }
    fn truncate(&self, _ino: u64, _size: u64) -> Result<()> {
        Err(Errno::ReadOnly)
    }
    fn create(&self, _dir: u64, _name: &str, _what: NewNode<'_>, _mode: u32, _cred: &Cred) -> Result<u64> {
        Err(Errno::ReadOnly)
    }
    /// Removes a non-directory entry.
    fn unlink(&self, _dir: u64, _name: &str) -> Result<()> {
        Err(Errno::ReadOnly)
    }
    fn rmdir(&self, _dir: u64, _name: &str) -> Result<()> {
        Err(Errno::ReadOnly)
    }
    fn rename(&self, _sdir: u64, _sname: &str, _ddir: u64, _dname: &str) -> Result<()> {
        Err(Errno::ReadOnly)
    }
    fn set_mode(&self, _ino: u64, _mode: u32) -> Result<()> {
        Err(Errno::ReadOnly)
    }
    /// A handle to `ino` was opened.
    fn open(&self, _ino: u64) -> Result<()> {
        Ok(())
    }
    /// A handle to `ino` was closed.
    fn release(&self, _ino: u64) {}
    /// The device behind a device node.
    fn device(&self, _ino: u64) -> Option<DeviceFile> {
        None
    }
    /// Writes everything cached to the device.
    fn sync(&self) -> Result<()> {
        Ok(())
    }
    /// Periodic write-back (`now_ms`: uptime): writes what has been held in
    /// memory for longer than the volume allows; never waits for a busy
    /// volume. True if something was written.
    fn writeback(&self, _now_ms: u64) -> Result<bool> {
        Ok(false)
    }
    fn usage(&self) -> FsUsage;
    /// Last call before the driver is dropped: flush and leave the volume
    /// clean.
    fn unmount(&self) -> Result<()> {
        self.sync()
    }
    /// Full consistency check of the volume, if the driver has one:
    /// `Ok(summary)` or `Err(problem)`.
    fn fsck(&self) -> Option<core::result::Result<String, String>> {
        None
    }
    /// The block devices this volume lives on (raw writes to them are
    /// refused while it is mounted).
    fn backing_device(&self) -> Option<String> {
        None
    }
}

pub struct Mount {
    pub id: u64,
    pub path: String,
    pub source: String,
    pub flags: u64,
    pub fs: Arc<dyn Filesystem>,
}

impl Mount {
    pub fn read_only(&self) -> bool {
        self.flags & MOUNT_READ_ONLY != 0
    }

    fn writable(&self) -> Result<()> {
        if self.read_only() {
            Err(Errno::ReadOnly)
        } else {
            Ok(())
        }
    }

    fn stat(&self, ino: u64) -> Result<FileStat> {
        let mut st = self.fs.stat(ino)?;
        st.dev = self.id;
        Ok(st)
    }
}

static MOUNTS: IrqSpinLock<MountTable<Arc<Mount>>> = IrqSpinLock::new(MountTable::new());
static NEXT_MOUNT_ID: AtomicU64 = AtomicU64::new(1);

/// Who is asking and from where.
#[derive(Clone, Debug)]
pub struct Lookup {
    pub cred: Cred,
    /// Canonical absolute current directory.
    pub cwd: String,
    pub case_insensitive: bool,
}

impl Lookup {
    pub fn kernel() -> Lookup {
        Lookup { cred: Cred::ROOT, cwd: String::from("/"), case_insensitive: false }
    }

    /// The calling process's credentials and current directory.
    pub fn current() -> Lookup {
        let (cred, cwd) = crate::process::current_identity();
        Lookup { cred, cwd, case_insensitive: false }
    }
}

/// A resolved node: its volume, number and canonical absolute path.
#[derive(Clone)]
pub struct Node {
    pub mount: Arc<Mount>,
    pub ino: u64,
    pub path: String,
}

impl Node {
    pub fn stat(&self) -> Result<FileStat> {
        self.mount.stat(self.ino)
    }
}

fn mount_at(canon: &str) -> Option<Arc<Mount>> {
    MOUNTS.lock().exact(canon).cloned()
}

// ---- lookup cache ----------------------------------------------------------

/// One resolved component: its node and the driver's stat that proved it.
/// The stat is kept so descending does not stat the same directory again.
struct WalkEntry {
    node: Node,
    st: FileStat,
}

struct Cached {
    ino: u64,
    st: FileStat,
    /// Name as the driver stores it (differs from the query only for
    /// case-insensitive lookups).
    stored: String,
    epoch: u64,
    /// The driver reported this name as absent. Databases probe the same
    /// journal names thousands of times per second, so the miss is cached
    /// too; every operation that adds a name forgets it.
    missing: bool,
}

enum Hit {
    Node { ino: u64, st: FileStat, stored: String },
    Missing,
}

const DCACHE_MAX: usize = 8192;

/// Bumped by changes that can invalidate entries wholesale: mounts, or an
/// inode's kind/permissions changing. Entry creation and removal forget the
/// single affected name instead, because otherwise one file churn (SQLite
/// journals) would invalidate every path in the tree on each operation.
static DCACHE_EPOCH: AtomicU64 = AtomicU64::new(1);
/// Keyed by (mount, directory, case-insensitive, requested name). The flag is
/// part of the key because the two modes disagree in both directions: a
/// case-sensitive miss is a case-insensitive hit, and a case-insensitive hit
/// under a spelling that is not stored is a case-sensitive miss.
static DCACHE: IrqSpinLock<BTreeMap<(u64, u64, bool, String), Cached>> = IrqSpinLock::new(BTreeMap::new());

fn cache_get(key: &(u64, u64, bool, String)) -> Option<Hit> {
    let t = DCACHE.lock();
    let c = t.get(key)?;
    if c.epoch != DCACHE_EPOCH.load(Ordering::Relaxed) {
        return None;
    }
    Some(if c.missing {
        Hit::Missing
    } else {
        Hit::Node { ino: c.ino, st: c.st, stored: c.stored.clone() }
    })
}

fn cache_put(key: (u64, u64, bool, String), ino: u64, st: FileStat, stored: String, epoch: u64) {
    if epoch != DCACHE_EPOCH.load(Ordering::Relaxed) {
        return;
    }
    let mut t = DCACHE.lock();
    if t.len() >= DCACHE_MAX {
        t.clear();
    }
    t.insert(key, Cached { ino, st, stored, epoch, missing: false });
}

fn cache_put_missing(key: (u64, u64, bool, String), name: String, epoch: u64) {
    if epoch != DCACHE_EPOCH.load(Ordering::Relaxed) {
        return;
    }
    let mut t = DCACHE.lock();
    if t.len() >= DCACHE_MAX {
        t.clear();
    }
    t.insert(key, Cached { ino: 0, st: FileStat::default(), stored: name, epoch, missing: true });
}

/// Forgets `name` in `dir`: the only cache entries a create, unlink or
/// rename can invalidate. An entry may be keyed by any spelling of the same
/// stored name, in either mode, so all of them go.
fn cache_forget(mount: u64, dir: u64, name: &str) {
    let mut t = DCACHE.lock();
    let lo = (mount, dir, false, String::new());
    let hi = (mount, dir, true, String::from("\u{10ffff}"));
    let stale: Vec<(u64, u64, bool, String)> =
        t.range(lo..=hi)
            .filter(|(_, c)| c.stored.to_lowercase() == name.to_lowercase())
            .map(|(k, _)| k.clone())
            .collect();
    for k in stale {
        t.remove(&k);
    }
}

fn cache_invalidate() {
    DCACHE_EPOCH.fetch_add(1, Ordering::Relaxed);
}

/// The root of the mount holding `/`, with its stat cached: every walk
/// descends through it and the driver stat would take the volume lock on
/// each path resolution.
fn root_entry() -> Result<WalkEntry> {
    let m = mount_at("/").ok_or(Errno::NotFound)?;
    let ino = m.fs.root();
    let key = (m.id, ino, false, String::new());
    let epoch = DCACHE_EPOCH.load(Ordering::Relaxed);
    let st = match cache_get(&key) {
        Some(Hit::Node { st, .. }) => st,
        _ => {
            let st = m.stat(ino)?;
            cache_put(key, ino, st, String::new(), epoch);
            st
        }
    };
    Ok(WalkEntry { node: Node { ino, mount: m, path: String::from("/") }, st })
}

/// Resolves `path` to a node; `follow_last` decides whether a final
/// symbolic link is followed.
pub fn walk(cx: &Lookup, p: &str, follow_last: bool) -> Result<Node> {
    validate(p)?;
    let mut queue: VecDeque<String> = VecDeque::new();
    if !p.starts_with('/') {
        queue.extend(path::components(&cx.cwd).map(String::from));
    }
    queue.extend(path::components(p).map(String::from));
    let mut stack = alloc::vec![root_entry()?];
    let mut links = 0;
    while let Some(c) = queue.pop_front() {
        match c.as_str() {
            "." => continue,
            ".." => {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            _ => {}
        }
        let (mount, dir_ino) = {
            let cur = stack.last().expect("walk stack never empty");
            if cur.st.kind != KIND_DIR {
                return Err(Errno::NotADirectory);
            }
            if !may(&cur.st, &cx.cred, Access::EXEC) {
                return Err(Errno::PermissionDenied);
            }
            (cur.node.mount.clone(), cur.node.ino)
        };
        let key = (mount.id, dir_ino, cx.case_insensitive, c);
        let epoch = DCACHE_EPOCH.load(Ordering::Relaxed);
        let (ino, stored, hit_st) = match cache_get(&key) {
            Some(Hit::Node { ino, st, stored }) => (ino, stored, Some(st)),
            Some(Hit::Missing) => return Err(Errno::NotFound),
            None => {
                // Case-insensitive lookups continue with the stored name, so
                // mount points and later comparisons see the canonical
                // spelling.
                let found = if cx.case_insensitive {
                    mount.fs.lookup_case_insensitive(dir_ino, &key.3)
                } else {
                    mount.fs.lookup(dir_ino, &key.3).map(|ino| (ino, key.3.clone()))
                };
                match found {
                    Ok((ino, stored)) => (ino, stored, None),
                    Err(Errno::NotFound) => {
                        let name = key.3.clone();
                        cache_put_missing(key, name, epoch);
                        return Err(Errno::NotFound);
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        let canon = path::join(&stack.last().expect("walk stack never empty").node.path, &stored);
        let last = queue.is_empty();
        let (child, cacheable) = match mount_at(&canon) {
            Some(m) => (Node { ino: m.fs.root(), mount: m, path: canon }, false),
            None => (Node { mount: mount.clone(), ino, path: canon }, true),
        };
        if !last || follow_last {
            let cst = match hit_st {
                Some(st) => st,
                None => {
                    let st = child.stat()?;
                    if cacheable {
                        cache_put(key, ino, st, stored, epoch);
                    }
                    st
                }
            };
            if cst.kind == KIND_SYMLINK {
                links += 1;
                if links > MAX_SYMLINKS {
                    return Err(Errno::Loop);
                }
                let target = child.mount.fs.readlink(child.ino)?;
                if target.starts_with('/') {
                    stack.truncate(1);
                }
                for comp in path::components(&target).collect::<Vec<_>>().into_iter().rev() {
                    queue.push_front(String::from(comp));
                }
                continue;
            }
            stack.push(WalkEntry { node: child, st: cst });
        } else {
            stack.push(WalkEntry { node: child, st: FileStat::default() });
        }
    }
    Ok(stack.pop().expect("walk stack never empty").node)
}

/// Resolves the directory that would contain `p`, and the final name.
fn walk_parent(cx: &Lookup, p: &str) -> Result<(Node, String)> {
    validate(p)?;
    let (dir, name) = split_last(p).ok_or(Errno::InvalidArgument)?;
    validate_name(name)?;
    let dir = walk(cx, dir, true)?;
    if dir.stat()?.kind != KIND_DIR {
        return Err(Errno::NotADirectory);
    }
    Ok((dir, String::from(name)))
}

/// Checks that `cred` may add or remove entries of `dir`.
fn check_dir_write(dir: &Node, cred: &Cred) -> Result<FileStat> {
    dir.mount.writable()?;
    let st = dir.stat()?;
    if !may(&st, cred, Access::WRITE_EXEC) {
        return Err(Errno::PermissionDenied);
    }
    Ok(st)
}

/// `name` in `dir` as an existing node (not following links), unless it
/// is a mount point (`Busy`).
fn existing_entry(cx: &Lookup, dir: &Node, name: &str) -> Result<Node> {
    let (ino, stored) = if cx.case_insensitive {
        dir.mount.fs.lookup_case_insensitive(dir.ino, name)?
    } else {
        (dir.mount.fs.lookup(dir.ino, name)?, String::from(name))
    };
    let canon = path::join(&dir.path, &stored);
    if mount_at(&canon).is_some() {
        return Err(Errno::Busy);
    }
    Ok(Node { mount: dir.mount.clone(), ino, path: canon })
}

// ---- mounting ------------------------------------------------------------

/// Mounts `fs` at the canonical path `at` (which must be an existing
/// directory unless it is `/`).
pub fn mount_fs(at: &str, source: &str, flags: u64, fs: Arc<dyn Filesystem>) -> Result<Arc<Mount>> {
    if at != "/" {
        let n = walk(&Lookup::kernel(), at, true)?;
        if n.stat()?.kind != KIND_DIR {
            return Err(Errno::NotADirectory);
        }
        if n.path != at {
            return Err(Errno::InvalidArgument);
        }
    }
    let m = Arc::new(Mount {
        id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed),
        path: String::from(at),
        source: String::from(source),
        flags,
        fs,
    });
    MOUNTS.lock().insert(at, m.clone())?;
    cache_invalidate();
    kprintln!(
        "vfs: {} {} mounted at {} ({}{})",
        m.fs.fs_type(),
        source,
        at,
        if m.read_only() { "read-only" } else { "read-write" },
        match m.fs.label() {
            l if l.is_empty() => String::new(),
            l => alloc::format!(", label \"{l}\""),
        }
    );
    Ok(m)
}

/// Unmounts the volume mounted exactly at `p` (after resolving it).
pub fn unmount(cx: &Lookup, p: &str) -> Result<()> {
    let at = walk(cx, p, true)?.path;
    if at == "/" {
        return Err(Errno::Busy);
    }
    let m = {
        let mut t = MOUNTS.lock();
        let m = t.exact(&at).cloned().ok_or(Errno::InvalidArgument)?;
        // The table and `m` hold references; anything more is an open file
        // or an operation in progress.
        if Arc::strong_count(&m) > 2 {
            return Err(Errno::Busy);
        }
        t.remove(&at)?;
        m
    };
    cache_invalidate();
    if let Err(e) = m.fs.unmount() {
        kprintln!("vfs: unmounting {} reported {:?}", m.path, e);
    }
    kprintln!("vfs: {} unmounted from {}", m.fs.fs_type(), m.path);
    Ok(())
}

/// Takes the volumes mounted at `paths` out of the mount table in one
/// step, so a group of volumes (the partitions of one USB stick) is either
/// all detached or none is. Without `force`, a volume with open files or
/// other mounts below it makes the whole call fail with `Busy` and changes
/// nothing; `force` (the device is gone) detaches regardless, and open
/// files then fail with I/O errors. The caller finishes each volume with
/// `fs.unmount()`.
pub fn detach_volumes(paths: &[String], force: bool) -> Result<Vec<Arc<Mount>>> {
    let mut order: Vec<&String> = paths.iter().collect();
    // Innermost first.
    order.sort_by_key(|p| core::cmp::Reverse(p.len()));
    let mut t = MOUNTS.lock();
    let found: Vec<Arc<Mount>> = order.iter().filter_map(|p| t.exact(p).cloned()).collect();
    if !force {
        for m in &found {
            // The table and `found` hold references; anything more is an
            // open file or an operation in progress.
            if Arc::strong_count(m) > 2 {
                return Err(Errno::Busy);
            }
            let nested = t.iter().any(|(p, _)| p != m.path && path::is_within(p, &m.path) && !paths.iter().any(|q| q == p));
            if nested {
                return Err(Errno::Busy);
            }
        }
    }
    for m in &found {
        if t.remove(&m.path).is_err() && force {
            kprintln!("vfs: {} still has mounts below it", m.path);
        }
    }
    drop(t);
    cache_invalidate();
    Ok(found)
}

/// Starts the write-back thread: once a second it lets every volume write
/// what it has held in memory for too long (ext4: 5 s), so data written
/// without `fsync` reaches the disk within seconds instead of only at the
/// next sync, a full buffer or unmount.
pub fn start_writeback() {
    crate::sched::spawn_kernel("writeback", writeback_thread, 0, 0);
}

fn writeback_thread(_: u64, _: u64) {
    loop {
        crate::sched::sleep_ticks(crate::arch::timer::ms_to_ticks(1000));
        let now = crate::interrupts::uptime_ms();
        for m in mounts() {
            match m.fs.writeback(now) {
                Ok(true) => crate::kprintln!("writeback: {} ({}) written", m.path, m.source),
                Ok(false) => {}
                Err(e) => crate::kprintln!("writeback: {} ({}): {:?}", m.path, m.source, e),
            }
        }
    }
}

/// Every mount, outermost first.
pub fn mounts() -> Vec<Arc<Mount>> {
    let mut v: Vec<Arc<Mount>> = MOUNTS.lock().iter().map(|(_, m)| m.clone()).collect();
    v.reverse();
    v
}

/// True if a mounted volume lives on block device `name` (a disk or one
/// of its partitions).
pub fn device_in_use(name: &str) -> bool {
    let devs = crate::block::devices();
    let parent_of = |n: &str| devs.iter().find(|d| d.name() == n).and_then(|d| d.parent_name().map(String::from));
    let wanted_parent = parent_of(name);
    mounts().iter().any(|m| {
        m.fs.backing_device().is_some_and(|d| {
            d == name || wanted_parent.as_deref() == Some(d.as_str()) || parent_of(&d).as_deref() == Some(name)
        })
    })
}


/// Unmounts everything except `/` (innermost first) and syncs `/`.
pub fn shutdown() {
    let mut list = mounts();
    list.reverse();
    for m in list {
        // `/` stays in the table (nothing can be mounted afterwards anyway).
        if m.path == "/" || MOUNTS.lock().remove(&m.path).is_ok() {
            let _ = m.fs.unmount();
        }
    }
}

// ---- operations on paths ---------------------------------------------------

pub fn stat(cx: &Lookup, p: &str) -> Result<FileStat> {
    walk(cx, p, true)?.stat()
}

pub fn lstat(cx: &Lookup, p: &str) -> Result<FileStat> {
    walk(cx, p, false)?.stat()
}

pub fn mkdir(cx: &Lookup, p: &str, mode: u32) -> Result<()> {
    let (dir, name) = walk_parent(cx, p)?;
    if walk(cx, p, false).is_ok() {
        return Err(Errno::AlreadyExists);
    }
    check_dir_write(&dir, &cx.cred)?;
    let r = dir.mount.fs.create(dir.ino, &name, NewNode::Dir, mode & MODE_PERMS, &cx.cred);
    if r.is_ok() {
        cache_forget(dir.mount.id, dir.ino, &name);
    }
    r.map(|_| ())
}

pub fn symlink(cx: &Lookup, target: &str, p: &str) -> Result<()> {
    validate(target)?;
    let (dir, name) = walk_parent(cx, p)?;
    if walk(cx, p, false).is_ok() {
        return Err(Errno::AlreadyExists);
    }
    check_dir_write(&dir, &cx.cred)?;
    let r = dir.mount.fs.create(dir.ino, &name, NewNode::Symlink(target), 0o777, &cx.cred);
    if r.is_ok() {
        cache_forget(dir.mount.id, dir.ino, &name);
    }
    r.map(|_| ())
}

pub fn readlink(cx: &Lookup, p: &str) -> Result<String> {
    let n = walk(cx, p, false)?;
    if n.stat()?.kind != KIND_SYMLINK {
        return Err(Errno::InvalidArgument);
    }
    n.mount.fs.readlink(n.ino)
}

/// Removes a file, symbolic link or device node (`dir == false`) or an
/// empty directory (`dir == true`).
fn remove(cx: &Lookup, p: &str, dir_wanted: bool) -> Result<()> {
    let (dir, name) = walk_parent(cx, p)?;
    let dst = check_dir_write(&dir, &cx.cred)?;
    let victim = existing_entry(cx, &dir, &name)?;
    let vst = victim.stat()?;
    if !perm::may_delete(&dst, &vst, &cx.cred) {
        return Err(Errno::PermissionDenied);
    }
    let r = match (dir_wanted, vst.kind == KIND_DIR) {
        (true, true) => dir.mount.fs.rmdir(dir.ino, &name),
        (true, false) => Err(Errno::NotADirectory),
        (false, true) => Err(Errno::IsADirectory),
        (false, false) => dir.mount.fs.unlink(dir.ino, &name),
    };
    if r.is_ok() {
        cache_forget(dir.mount.id, dir.ino, &name);
    }
    r
}

pub fn unlink(cx: &Lookup, p: &str) -> Result<()> {
    remove(cx, p, false)
}

pub fn rmdir(cx: &Lookup, p: &str) -> Result<()> {
    remove(cx, p, true)
}

pub fn rename(cx: &Lookup, from: &str, to: &str) -> Result<()> {
    let (sdir, sname) = walk_parent(cx, from)?;
    let (ddir, dname) = walk_parent(cx, to)?;
    if !Arc::ptr_eq(&sdir.mount, &ddir.mount) {
        return Err(Errno::CrossDevice);
    }
    let sst = check_dir_write(&sdir, &cx.cred)?;
    let dst = check_dir_write(&ddir, &cx.cred)?;
    let src = existing_entry(cx, &sdir, &sname)?;
    if !perm::may_delete(&sst, &src.stat()?, &cx.cred) {
        return Err(Errno::PermissionDenied);
    }
    match existing_entry(cx, &ddir, &dname) {
        Ok(target) => {
            if !perm::may_delete(&dst, &target.stat()?, &cx.cred) {
                return Err(Errno::PermissionDenied);
            }
        }
        Err(Errno::NotFound) => {}
        Err(e) => return Err(e),
    }
    // A directory may not move below itself (also across mount-free paths
    // the driver checks again with its own node numbers).
    if src.stat()?.kind == KIND_DIR && path::is_within(&path::join(&ddir.path, &dname), &src.path) {
        return Err(Errno::InvalidArgument);
    }
    let r = sdir.mount.fs.rename(sdir.ino, &sname, ddir.ino, &dname);
    if r.is_ok() {
        cache_forget(sdir.mount.id, sdir.ino, &sname);
        cache_forget(ddir.mount.id, ddir.ino, &dname);
    }
    r
}

pub fn chmod(cx: &Lookup, p: &str, mode: u32) -> Result<()> {
    let n = walk(cx, p, true)?;
    n.mount.writable()?;
    if !perm::may_chmod(&n.stat()?, &cx.cred) {
        return Err(Errno::PermissionDenied);
    }
    n.mount.fs.set_mode(n.ino, mode & MODE_PERMS)?;
    cache_invalidate();
    Ok(())
}

/// Resolves a new current directory; returns its canonical path.
pub fn chdir(cx: &Lookup, p: &str) -> Result<String> {
    let n = walk(cx, p, true)?;
    let st = n.stat()?;
    if st.kind != KIND_DIR {
        return Err(Errno::NotADirectory);
    }
    if !may(&st, &cx.cred, Access::EXEC) {
        return Err(Errno::PermissionDenied);
    }
    Ok(n.path)
}

pub fn statfs(cx: &Lookup, p: &str) -> Result<FsStat> {
    let n = walk(cx, p, true)?;
    let u = n.mount.fs.usage();
    let mut out = FsStat {
        block_size: u.block_size,
        total_blocks: u.total_blocks,
        free_blocks: u.free_blocks,
        total_inodes: u.total_inodes,
        free_inodes: u.free_inodes,
        dev: n.mount.id,
        flags: n.mount.flags,
        fstype: [0; 16],
    };
    let t = n.mount.fs.fs_type().as_bytes();
    out.fstype[..t.len().min(16)].copy_from_slice(&t[..t.len().min(16)]);
    Ok(out)
}

// ---- open files -------------------------------------------------------------

pub struct OpenFile {
    node: Node,
    kind: u32,
    pos: u64,
    read: bool,
    write: bool,
    append: bool,
    listing: Option<(Vec<DirEntry>, usize)>,
    device: Option<DeviceFile>,
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        if let Some(d) = &self.device {
            d.close();
        }
        self.node.mount.fs.release(self.node.ino);
    }
}

pub fn open(cx: &Lookup, p: &str, flags: u64, mode: u32) -> Result<OpenFile> {
    if flags & !OPEN_ALL != 0 || flags & (OPEN_READ | OPEN_WRITE) == 0 {
        return Err(Errno::InvalidArgument);
    }
    let write = flags & OPEN_WRITE != 0;
    let create = flags & OPEN_CREATE != 0;
    if !write && flags & (OPEN_CREATE | OPEN_TRUNCATE | OPEN_APPEND | OPEN_EXCLUSIVE) != 0 {
        return Err(Errno::InvalidArgument);
    }
    if flags & OPEN_EXCLUSIVE != 0 && !create {
        return Err(Errno::InvalidArgument);
    }
    let cx = &Lookup { case_insensitive: cx.case_insensitive || flags & OPEN_CASE_INSENSITIVE != 0, ..cx.clone() };
    let follow = flags & OPEN_NOFOLLOW == 0;
    let mut created = false;
    let node = if create {
        match walk(cx, p, follow && flags & OPEN_EXCLUSIVE == 0) {
            Ok(_) if flags & OPEN_EXCLUSIVE != 0 => return Err(Errno::AlreadyExists),
            Ok(n) => n,
            Err(Errno::NotFound) => {
                let (dir, name) = walk_parent(cx, p)?;
                check_dir_write(&dir, &cx.cred)?;
                let ino = dir.mount.fs.create(dir.ino, &name, NewNode::File, mode & MODE_PERMS, &cx.cred)?;
                cache_forget(dir.mount.id, dir.ino, &name);
                created = true;
                Node { mount: dir.mount.clone(), ino, path: path::join(&dir.path, &name) }
            }
            Err(e) => return Err(e),
        }
    } else {
        walk(cx, p, follow)?
    };
    let st = node.stat()?;
    if st.kind == KIND_SYMLINK {
        return Err(Errno::Loop);
    }
    if st.kind == KIND_DIR && write {
        return Err(Errno::IsADirectory);
    }
    if flags & OPEN_DIRECTORY != 0 && st.kind != KIND_DIR {
        return Err(Errno::NotADirectory);
    }
    // The creator may use the file it just made whatever the mode says.
    if !created {
        if flags & OPEN_READ != 0 && !may(&st, &cx.cred, Access::READ) {
            return Err(Errno::PermissionDenied);
        }
        if write && !may(&st, &cx.cred, Access::WRITE) {
            return Err(Errno::PermissionDenied);
        }
    }
    let device = node.mount.fs.device(node.ino);
    if write && device.is_none() {
        node.mount.writable()?;
    }
    if let Some(d) = &device {
        d.check_open(write)?;
    }
    node.mount.fs.open(node.ino)?;
    if let Some(d) = &device {
        if let Err(e) = d.open() {
            node.mount.fs.release(node.ino);
            return Err(e);
        }
    }
    let f = OpenFile {
        kind: st.kind,
        node,
        pos: 0,
        read: flags & OPEN_READ != 0,
        write,
        append: flags & OPEN_APPEND != 0,
        listing: None,
        device,
    };
    if flags & OPEN_TRUNCATE != 0 && st.kind == KIND_FILE {
        crate::filemap::truncate((st.dev, st.ino), 0, || f.node.mount.fs.truncate(f.node.ino, 0))?;
    }
    Ok(f)
}

/// Opens a regular file for the program loader. As on Unix this needs
/// execute permission, not read permission (root: any execute bit).
pub fn open_exec(cx: &Lookup, p: &str) -> Result<OpenFile> {
    let node = walk(cx, p, true)?;
    let st = node.stat()?;
    if st.kind != KIND_FILE || !may(&st, &cx.cred, Access::EXEC) {
        return Err(Errno::PermissionDenied);
    }
    node.mount.fs.open(node.ino)?;
    Ok(OpenFile { kind: st.kind, node, pos: 0, read: true, write: false, append: false, listing: None, device: None })
}

// TEMP: write volume by file kind, to find what keeps the disk busy.
static WRITE_CAT: [core::sync::atomic::AtomicU64; 8] = [const { core::sync::atomic::AtomicU64::new(0) }; 8];
static LAST_IDB_WRITE: [core::sync::atomic::AtomicU64; 3] = [const { core::sync::atomic::AtomicU64::new(0) }; 3];

fn note_idb_write(offset: u64, len: usize) {
    LAST_IDB_WRITE[0].store(crate::sched::current_tid(), core::sync::atomic::Ordering::Relaxed);
    LAST_IDB_WRITE[1].store(offset, core::sync::atomic::Ordering::Relaxed);
    LAST_IDB_WRITE[2].store(len as u64, core::sync::atomic::Ordering::Relaxed);
}

pub fn last_idb_write() -> (u64, u64, u64) {
    (
        LAST_IDB_WRITE[0].load(core::sync::atomic::Ordering::Relaxed),
        LAST_IDB_WRITE[1].load(core::sync::atomic::Ordering::Relaxed),
        LAST_IDB_WRITE[2].load(core::sync::atomic::Ordering::Relaxed),
    )
}

fn write_cat(path: &str) -> usize {
    let p = path.as_bytes();
    let has = |needle: &[u8]| p.windows(needle.len()).any(|w| w == needle);
    if has(b"/idb/") {
        0
    } else if has(b"places.sqlite") {
        1
    } else if has(b"sessionstore") {
        2
    } else if has(b"cache2") {
        3
    } else if has(b"-journal") || has(b"-wal") {
        4
    } else {
        5
    }
}

pub fn write_cat_bytes() -> [u64; 8] {
    let mut out = [0u64; 8];
    for (o, c) in out.iter_mut().zip(WRITE_CAT.iter()) {
        *o = c.load(core::sync::atomic::Ordering::Relaxed);
    }
    out
}

impl OpenFile {
    /// Mapped I/O does not move the file position or apply OPEN_APPEND.
    pub fn mapping_access(&self, writable: bool) -> Result<()> {
        if self.kind != KIND_FILE || self.device.is_some() { return Err(Errno::NotSupported); }
        if !self.read || (writable && !self.write) { return Err(Errno::PermissionDenied); }
        Ok(())
    }

    pub(crate) fn read_direct(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.mapping_access(false)?;
        self.node.mount.fs.read(self.node.ino, offset, buf)
    }

    pub fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        self.mapping_access(true)?;
        let n = self.node.mount.fs.write(self.node.ino, offset, data)?;
        crate::exec::invalidate(self.cache_key());
        crate::filecache::update_write(self.cache_key(), offset, &data[..n]);
        crate::filecache::note_write(self.cache_key(), offset, &data[..n]);
        let cat = write_cat(self.path());
        if cat == 0 {
            note_idb_write(offset, n);
        }
        WRITE_CAT[cat].fetch_add(n as u64, core::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }

    pub(crate) fn cache_key(&self) -> (u64, u64) {
        (self.node.mount.id, self.node.ino)
    }

    /// True when [`read`](Self::read) can be served from the page cache: an
    /// open regular file, not a device.
    pub fn cache_readable(&self) -> bool {
        self.read && self.device.is_none() && self.kind == osyx_abi::KIND_FILE
    }

    /// Current offset, without moving it.
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Canonical absolute path the file was opened under.
    pub fn path(&self) -> &str {
        &self.node.path
    }

    /// The device behind a device node.
    pub fn device(&self) -> Option<DeviceFile> {
        self.device.clone()
    }

    /// Reads at the current position into `buf` without moving it: the
    /// caller calls [`advance`](Self::advance) once the data has reached
    /// its destination, so a failed copy to user memory consumes nothing.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.read {
            return Err(Errno::BadHandle);
        }
        if let Some(d) = &self.device {
            return d.read(self.pos, buf);
        }
        match self.kind {
            KIND_DIR => Err(Errno::IsADirectory),
            KIND_FILE if self.device.is_none() => {
                let t0 = crate::interrupts::uptime_ms();
                let source = crate::filecache::Source { fs: self.node.mount.fs.clone(), ino: self.node.ino };
                let r = crate::filecache::read(
                    self.cache_key(),
                    self.pos,
                    buf,
                    |off, b| self.node.mount.fs.read(self.node.ino, off, b),
                    Some(&source),
                );
                let ms = crate::interrupts::uptime_ms().saturating_sub(t0);
                if ms >= 40 {
                    // TEMP I/O diagnostics: which read blocks its thread this long.
                    crate::kprintln!("sloread: {} at {} len {} in {} ms (pid {} tid {})", self.path(), self.pos, buf.len(), ms, crate::sched::current_pid(), crate::sched::current_tid());
                }
                r
            }
            _ => self.node.mount.fs.read(self.node.ino, self.pos, buf),
        }
    }

    pub fn advance(&mut self, n: usize) {
        self.pos += n as u64;
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.write {
            return Err(Errno::BadHandle);
        }
        if let Some(d) = &self.device {
            let n = d.write(self.pos, data)?;
            self.pos += n as u64;
            return Ok(n);
        }
        if self.append {
            self.pos = self.node.mount.fs.stat(self.node.ino)?.size;
        }
        // The cached page is updated in place below; dropping it here would
        // send the next read of this page back to a disk the writer keeps
        // busy.
        let n = self.node.mount.fs.write(self.node.ino, self.pos, data)?;
        crate::exec::invalidate(self.cache_key());
        crate::filecache::update_write(self.cache_key(), self.pos, &data[..n]);
        crate::filecache::note_write(self.cache_key(), self.pos, &data[..n]);
        let cat = write_cat(self.path());
        if cat == 0 {
            note_idb_write(self.pos, n);
        }
        WRITE_CAT[cat].fetch_add(n as u64, core::sync::atomic::Ordering::Relaxed);
        self.pos += n as u64;
        Ok(n)
    }

    pub fn seek(&mut self, offset: i64, whence: u64) -> Result<u64> {
        if self.kind == KIND_DIR {
            return Err(Errno::IsADirectory);
        }
        let base = match whence {
            SEEK_SET => 0,
            SEEK_CUR => self.pos,
            SEEK_END => match &self.device {
                Some(d) => d.size().ok_or(Errno::InvalidArgument)?,
                None => self.node.mount.fs.stat(self.node.ino)?.size,
            },
            _ => return Err(Errno::InvalidArgument),
        };
        let new = base as i128 + offset as i128;
        if !(0..=i64::MAX as i128).contains(&new) {
            return Err(Errno::InvalidArgument);
        }
        self.pos = new as u64;
        Ok(self.pos)
    }

    pub fn stat(&mut self) -> Result<FileStat> {
        let mut st = self.node.stat()?;
        if let Some(size) = self.device.as_ref().and_then(|d| d.size()) {
            st.size = size;
        }
        Ok(st)
    }

    pub fn truncate(&mut self, len: u64) -> Result<()> {
        if !self.write || self.device.is_some() {
            return Err(Errno::BadHandle);
        }
        match self.kind {
            KIND_DIR => Err(Errno::IsADirectory),
            _ => {
                let r = self.node.mount.fs.truncate(self.node.ino, len);
                if r.is_ok() {
                    crate::filecache::forget(self.cache_key());
                    crate::exec::invalidate(self.cache_key());
                }
                r
            }
        }
    }

    pub fn sync(&mut self) -> Result<()> {
        if let Some(d) = &self.device {
            return d.flush();
        }
        if self.node.mount.read_only() {
            return Ok(());
        }
        WRITE_CAT[6].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.node.mount.fs.sync()
    }

    /// Encodes the next directory records into `out`; returns bytes used
    /// (0 when the listing is complete).
    pub fn readdir(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.kind != KIND_DIR {
            return Err(Errno::NotADirectory);
        }
        if self.listing.is_none() {
            self.listing = Some((self.node.mount.fs.read_dir(self.node.ino)?, 0));
        }
        let (list, next) = self.listing.as_mut().expect("listing loaded");
        let mut used = 0;
        while let Some(e) = list.get(*next) {
            let rec = DirRecord { ino: e.ino, kind: e.kind, reserved: 0, name_len: e.name.len() as u16 };
            match rec.encode(e.name.as_bytes(), &mut out[used..]) {
                Some(n) => used += n,
                None if used == 0 => return Err(Errno::InvalidArgument),
                None => break,
            }
            *next += 1;
        }
        Ok(used)
    }
}

// ---- mount from user space ----------------------------------------------------

/// `mount(2)`: `fstype` is "tmpfs", "fat32", "exfat" or "ext4"; disk file systems
/// take a block device node path as `source`.
pub fn mount(cx: &Lookup, source: &str, target: &str, fstype: &str, flags: u64, size_limit: u64) -> Result<()> {
    if !cx.cred.is_root() {
        return Err(Errno::PermissionDenied);
    }
    if flags & !MOUNT_READ_ONLY != 0 {
        return Err(Errno::InvalidArgument);
    }
    let at = walk(cx, target, true)?;
    if at.stat()?.kind != KIND_DIR {
        return Err(Errno::NotADirectory);
    }
    let fs: Arc<dyn Filesystem> = match fstype {
        "tmpfs" => {
            let limit = if size_limit == 0 { tmpfs::DEFAULT_LIMIT } else { size_limit };
            Arc::new(tmpfs::TmpfsVolume::new(limit, 0o1777))
        }
        "fat32" | "ext4" | "exfat" => {
            let dev = walk(cx, source, true)?;
            let disk = dev.mount.fs.device(dev.ino).and_then(|d| d.block()).ok_or(Errno::InvalidArgument)?;
            if device_in_use(disk.name()) {
                return Err(Errno::Busy);
            }
            mount_disk(fstype, disk, flags & MOUNT_READ_ONLY != 0)?
        }
        _ => return Err(Errno::InvalidArgument),
    };
    let src = if fstype == "tmpfs" { "tmpfs".to_string() } else { source.to_string() };
    mount_fs(&at.path, &src, flags, fs).map(|_| ())
}

/// Opens a disk file system driver on `disk`.
pub fn mount_disk(fstype: &str, disk: Arc<dyn crate::block::BlockDev>, read_only: bool) -> Result<Arc<dyn Filesystem>> {
    mount_disk_owned(fstype, disk, read_only, None)
}

/// Like [`mount_disk`]; `owner` (uid, gid) becomes the owner of every file
/// and directory of a FAT32 or exFAT volume, which have no owners of their
/// own (ext4 keeps the ones on disk). Root owns them otherwise.
pub fn mount_disk_owned(
    fstype: &str,
    disk: Arc<dyn crate::block::BlockDev>,
    read_only: bool,
    owner: Option<(u32, u32)>,
) -> Result<Arc<dyn Filesystem>> {
    match fstype {
        "fat32" => Ok(Arc::new(fat::FatVolume::mount(disk, read_only, owner)?)),
        "exfat" => Ok(Arc::new(exfat::ExfatVolume::mount(disk, read_only, owner)?)),
        "ext4" => Ok(Arc::new(ext4::Ext4Volume::mount(disk, read_only)?)),
        _ => Err(Errno::InvalidArgument),
    }
}

