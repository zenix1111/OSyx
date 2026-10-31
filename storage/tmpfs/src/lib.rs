//! tmpfs: a file system whose nodes live in kernel memory.
//!
//! * File data is kept in 4 KiB pages allocated on first write, so holes in
//!   sparse files cost nothing.
//! * Every instance has a memory limit. Pages, nodes ([`NODE_COST`] each)
//!   and names / link targets are charged against it; a write or create
//!   that would exceed it fails with `NoSpace` (a write stores what fits).
//! * Unlinking a node that is still open (see [`TmpFs::open`]) only removes
//!   its name; the memory is released when the last user calls
//!   [`TmpFs::release`].
//!
//! The engine is single-threaded (`&mut self`); the kernel wraps each
//! instance in a sleeping mutex. Nothing is ever written to a disk, so the
//! contents disappear with the instance.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use osyx_abi::{Errno, FileStat, KIND_DIR, KIND_FILE, KIND_SYMLINK, MODE_PERMS};
use osyx_vfs::{path::validate_name, Cred, DirEntry, FsUsage, NewNode};

pub const PAGE: usize = 4096;
/// Memory charged for every node (bookkeeping estimate).
pub const NODE_COST: u64 = 256;
/// Largest file size (keeps page indices and offsets far from overflow).
pub const MAX_FILE_SIZE: u64 = 1 << 40;
pub const ROOT: u64 = 1;

type Result<T> = core::result::Result<T, Errno>;

enum Data {
    File { size: u64, pages: BTreeMap<u64, Box<[u8; PAGE]>> },
    Dir { entries: BTreeMap<String, u64>, parent: u64 },
    Symlink(String),
}

struct Node {
    data: Data,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    open: u32,
    atime: i64,
    mtime: i64,
    ctime: i64,
}

pub struct TmpFs {
    nodes: BTreeMap<u64, Node>,
    next_ino: u64,
    limit: u64,
    used: u64,
    clock: fn() -> i64,
}

impl TmpFs {
    /// A new instance whose root directory has `root_mode` and is owned by
    /// root; `limit` bytes of memory at most; `clock` gives nanoseconds
    /// since the Unix epoch for timestamps.
    pub fn new(limit: u64, root_mode: u32, clock: fn() -> i64) -> TmpFs {
        let now = clock();
        let root = Node {
            data: Data::Dir { entries: BTreeMap::new(), parent: ROOT },
            mode: root_mode & MODE_PERMS,
            uid: 0,
            gid: 0,
            nlink: 2,
            open: 0,
            atime: now,
            mtime: now,
            ctime: now,
        };
        let mut nodes = BTreeMap::new();
        nodes.insert(ROOT, root);
        TmpFs { nodes, next_ino: ROOT + 1, limit, used: NODE_COST, clock }
    }

    pub fn root(&self) -> u64 {
        ROOT
    }

    /// Bytes currently charged against the limit.
    pub fn used_bytes(&self) -> u64 {
        self.used
    }

    pub fn limit_bytes(&self) -> u64 {
        self.limit
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn usage(&self) -> FsUsage {
        FsUsage {
            block_size: PAGE as u64,
            total_blocks: self.limit / PAGE as u64,
            free_blocks: self.limit.saturating_sub(self.used) / PAGE as u64,
            total_inodes: self.limit / NODE_COST,
            free_inodes: self.limit.saturating_sub(self.used) / NODE_COST,
        }
    }

    fn charge(&mut self, bytes: u64) -> Result<()> {
        match self.used.checked_add(bytes) {
            Some(n) if n <= self.limit => {
                self.used = n;
                Ok(())
            }
            _ => Err(Errno::NoSpace),
        }
    }

    fn uncharge(&mut self, bytes: u64) {
        debug_assert!(self.used >= bytes, "tmpfs accounting underflow");
        self.used = self.used.saturating_sub(bytes);
    }

    fn node(&self, ino: u64) -> Result<&Node> {
        self.nodes.get(&ino).ok_or(Errno::NotFound)
    }

    fn node_mut(&mut self, ino: u64) -> Result<&mut Node> {
        self.nodes.get_mut(&ino).ok_or(Errno::NotFound)
    }

    fn entries(&self, dir: u64) -> Result<&BTreeMap<String, u64>> {
        match &self.node(dir)?.data {
            Data::Dir { entries, .. } => Ok(entries),
            _ => Err(Errno::NotADirectory),
        }
    }

    fn entries_mut(&mut self, dir: u64) -> Result<&mut BTreeMap<String, u64>> {
        match &mut self.node_mut(dir)?.data {
            Data::Dir { entries, .. } => Ok(entries),
            _ => Err(Errno::NotADirectory),
        }
    }

    pub fn lookup(&self, dir: u64, name: &str) -> Result<u64> {
        let entries = self.entries(dir)?;
        match name {
            "." => Ok(dir),
            ".." => match &self.node(dir)?.data {
                Data::Dir { parent, .. } => Ok(*parent),
                _ => Err(Errno::NotADirectory),
            },
            _ => entries.get(name).copied().ok_or(Errno::NotFound),
        }
    }

    pub fn stat(&self, ino: u64) -> Result<FileStat> {
        let n = self.node(ino)?;
        let (kind, size, pages) = match &n.data {
            Data::File { size, pages } => (KIND_FILE, *size, pages.len() as u64),
            Data::Dir { entries, .. } => (KIND_DIR, entries.len() as u64, 0),
            Data::Symlink(t) => (KIND_SYMLINK, t.len() as u64, 0),
        };
        Ok(FileStat {
            size,
            ino,
            blocks: pages * (PAGE as u64 / 512),
            atime_ns: n.atime,
            mtime_ns: n.mtime,
            ctime_ns: n.ctime,
            kind,
            mode: n.mode,
            uid: n.uid,
            gid: n.gid,
            nlink: n.nlink,
            ..Default::default()
        })
    }

    pub fn read_dir(&self, dir: u64) -> Result<Vec<DirEntry>> {
        let entries = self.entries(dir)?;
        let mut out = Vec::with_capacity(entries.len());
        for (name, &ino) in entries {
            let kind = match self.node(ino)?.data {
                Data::File { .. } => KIND_FILE,
                Data::Dir { .. } => KIND_DIR,
                Data::Symlink(_) => KIND_SYMLINK,
            };
            out.push(DirEntry { name: name.clone(), ino, kind });
        }
        Ok(out)
    }

    pub fn readlink(&self, ino: u64) -> Result<String> {
        match &self.node(ino)?.data {
            Data::Symlink(t) => Ok(t.clone()),
            _ => Err(Errno::InvalidArgument),
        }
    }

    pub fn read(&mut self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let n = self.node(ino)?;
        let Data::File { size, pages } = &n.data else {
            return Err(if matches!(n.data, Data::Dir { .. }) { Errno::IsADirectory } else { Errno::InvalidArgument });
        };
        if offset >= *size {
            return Ok(0);
        }
        let len = (buf.len() as u64).min(size - offset) as usize;
        let mut done = 0;
        while done < len {
            let pos = offset + done as u64;
            let (idx, off) = (pos / PAGE as u64, (pos % PAGE as u64) as usize);
            let n = (PAGE - off).min(len - done);
            match pages.get(&idx) {
                Some(p) => buf[done..done + n].copy_from_slice(&p[off..off + n]),
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        self.node_mut(ino)?.atime = (self.clock)();
        Ok(len)
    }

    /// Writes `data` at `offset`, growing the file; stores as much as the
    /// memory limit allows and fails with `NoSpace` only if nothing fits.
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        match &self.node(ino)?.data {
            Data::File { .. } => {}
            Data::Dir { .. } => return Err(Errno::IsADirectory),
            Data::Symlink(_) => return Err(Errno::InvalidArgument),
        }
        let end = offset.checked_add(data.len() as u64).ok_or(Errno::FileTooLarge)?;
        if end > MAX_FILE_SIZE {
            return Err(Errno::FileTooLarge);
        }
        let mut done = 0;
        while done < data.len() {
            let pos = offset + done as u64;
            let (idx, off) = (pos / PAGE as u64, (pos % PAGE as u64) as usize);
            let n = (PAGE - off).min(data.len() - done);
            let present = matches!(&self.node(ino)?.data, Data::File { pages, .. } if pages.contains_key(&idx));
            if !present {
                if self.charge(PAGE as u64).is_err() {
                    break;
                }
                if let Data::File { pages, .. } = &mut self.node_mut(ino)?.data {
                    pages.insert(idx, Box::new([0u8; PAGE]));
                }
            }
            if let Data::File { pages, size } = &mut self.node_mut(ino)?.data {
                let page = pages.get_mut(&idx).expect("page just ensured");
                page[off..off + n].copy_from_slice(&data[done..done + n]);
                *size = (*size).max(pos + n as u64);
            }
            done += n;
        }
        if done == 0 && !data.is_empty() {
            return Err(Errno::NoSpace);
        }
        let now = (self.clock)();
        let node = self.node_mut(ino)?;
        node.mtime = now;
        node.ctime = now;
        Ok(done)
    }

    /// Sets the file size; pages beyond it are freed and the tail of the
    /// last page is zeroed, so growing again reads zeros.
    pub fn truncate(&mut self, ino: u64, new_size: u64) -> Result<()> {
        if new_size > MAX_FILE_SIZE {
            return Err(Errno::FileTooLarge);
        }
        let now = (self.clock)();
        let node = self.node_mut(ino)?;
        let freed = match &mut node.data {
            Data::File { size, pages } => {
                let keep = new_size.div_ceil(PAGE as u64);
                let gone: Vec<u64> = pages.range(keep..).map(|(&k, _)| k).collect();
                for k in &gone {
                    pages.remove(k);
                }
                if !new_size.is_multiple_of(PAGE as u64) {
                    if let Some(p) = pages.get_mut(&(new_size / PAGE as u64)) {
                        p[(new_size % PAGE as u64) as usize..].fill(0);
                    }
                }
                *size = new_size;
                gone.len() as u64
            }
            Data::Dir { .. } => return Err(Errno::IsADirectory),
            Data::Symlink(_) => return Err(Errno::InvalidArgument),
        };
        node.mtime = now;
        node.ctime = now;
        self.uncharge(freed * PAGE as u64);
        Ok(())
    }

    pub fn create(&mut self, dir: u64, name: &str, what: NewNode<'_>, mode: u32, cred: &Cred) -> Result<u64> {
        validate_name(name)?;
        if self.entries(dir)?.contains_key(name) {
            return Err(Errno::AlreadyExists);
        }
        let extra = match what {
            NewNode::Symlink(t) => {
                if t.is_empty() || t.len() > osyx_abi::MAX_PATH {
                    return Err(Errno::InvalidArgument);
                }
                t.len() as u64
            }
            _ => 0,
        };
        self.charge(NODE_COST + name.len() as u64 + extra)?;
        let now = (self.clock)();
        let ino = self.next_ino;
        self.next_ino += 1;
        let (data, nlink) = match what {
            NewNode::File => (Data::File { size: 0, pages: BTreeMap::new() }, 1),
            NewNode::Dir => (Data::Dir { entries: BTreeMap::new(), parent: dir }, 2),
            NewNode::Symlink(t) => (Data::Symlink(t.to_string()), 1),
        };
        let mode = if matches!(what, NewNode::Symlink(_)) { 0o777 } else { mode & MODE_PERMS };
        self.nodes.insert(
            ino,
            Node { data, mode, uid: cred.uid, gid: cred.gid, nlink, open: 0, atime: now, mtime: now, ctime: now },
        );
        self.entries_mut(dir)?.insert(name.to_string(), ino);
        let parent = self.node_mut(dir)?;
        if matches!(what, NewNode::Dir) {
            parent.nlink += 1;
        }
        parent.mtime = now;
        parent.ctime = now;
        Ok(ino)
    }

    /// Gives the existing non-directory node `target` a second name.
    pub fn link(&mut self, dir: u64, name: &str, target: u64) -> Result<()> {
        validate_name(name)?;
        if self.entries(dir)?.contains_key(name) {
            return Err(Errno::AlreadyExists);
        }
        if matches!(self.node(target)?.data, Data::Dir { .. }) {
            return Err(Errno::IsADirectory);
        }
        if self.node(target)?.nlink == 0 {
            return Err(Errno::NotFound);
        }
        self.charge(NODE_COST + name.len() as u64)?;
        let now = (self.clock)();
        let n = self.node_mut(target)?;
        n.nlink += 1;
        n.ctime = now;
        self.entries_mut(dir)?.insert(name.to_string(), target);
        let parent = self.node_mut(dir)?;
        parent.mtime = now;
        parent.ctime = now;
        Ok(())
    }

    /// Records one more user of `ino` (an open file handle).
    pub fn open(&mut self, ino: u64) -> Result<()> {
        self.node_mut(ino)?.open += 1;
        Ok(())
    }

    /// Drops a user added by [`open`](Self::open); frees the node if it
    /// has no names left.
    pub fn release(&mut self, ino: u64) {
        if let Some(n) = self.nodes.get_mut(&ino) {
            n.open = n.open.saturating_sub(1);
            if n.open == 0 && n.nlink == 0 {
                self.free_node(ino);
            }
        }
    }

    fn free_node(&mut self, ino: u64) {
        if let Some(n) = self.nodes.remove(&ino) {
            let bytes = match n.data {
                Data::File { pages, .. } => pages.len() as u64 * PAGE as u64,
                Data::Symlink(t) => t.len() as u64,
                Data::Dir { .. } => 0,
            };
            self.uncharge(NODE_COST + bytes);
        }
    }

    /// Removes the name `name` from `dir` (charge for the name is returned)
    /// and drops the node's link; frees it unless it is still open.
    fn drop_name(&mut self, dir: u64, name: &str) -> Result<u64> {
        let ino = self.entries_mut(dir)?.remove(name).ok_or(Errno::NotFound)?;
        self.uncharge(name.len() as u64);
        let now = (self.clock)();
        let is_dir = matches!(self.node(ino)?.data, Data::Dir { .. });
        let parent = self.node_mut(dir)?;
        parent.mtime = now;
        parent.ctime = now;
        if is_dir {
            parent.nlink -= 1;
        }
        let n = self.node_mut(ino)?;
        n.nlink = if is_dir { 0 } else { n.nlink - 1 };
        n.ctime = now;
        if n.nlink == 0 && n.open == 0 {
            self.free_node(ino);
        }
        Ok(ino)
    }

    pub fn unlink(&mut self, dir: u64, name: &str) -> Result<()> {
        let ino = self.lookup(dir, name)?;
        if matches!(self.node(ino)?.data, Data::Dir { .. }) {
            return Err(Errno::IsADirectory);
        }
        self.drop_name(dir, name).map(|_| ())
    }

    pub fn rmdir(&mut self, dir: u64, name: &str) -> Result<()> {
        if name == "." || name == ".." {
            return Err(Errno::InvalidArgument);
        }
        let ino = self.lookup(dir, name)?;
        if !self.entries(ino)?.is_empty() {
            return Err(Errno::DirectoryNotEmpty);
        }
        self.drop_name(dir, name).map(|_| ())
    }

    /// True if `ancestor` is `ino` or one of its parent directories.
    fn is_ancestor(&self, ancestor: u64, mut ino: u64) -> Result<bool> {
        loop {
            if ino == ancestor {
                return Ok(true);
            }
            match &self.node(ino)?.data {
                Data::Dir { parent, .. } if *parent != ino => ino = *parent,
                _ => return Ok(false),
            }
        }
    }

    pub fn rename(&mut self, sdir: u64, sname: &str, ddir: u64, dname: &str) -> Result<()> {
        validate_name(dname)?;
        validate_name(sname)?;
        let src = self.lookup(sdir, sname)?;
        self.entries(ddir)?;
        let src_is_dir = matches!(self.node(src)?.data, Data::Dir { .. });
        if src_is_dir && self.is_ancestor(src, ddir)? {
            return Err(Errno::InvalidArgument);
        }
        let existing = self.lookup(ddir, dname).ok();
        if let Some(dst) = existing {
            if dst == src {
                return Ok(());
            }
            let dst_is_dir = matches!(self.node(dst)?.data, Data::Dir { .. });
            match (src_is_dir, dst_is_dir) {
                (true, false) => return Err(Errno::NotADirectory),
                (false, true) => return Err(Errno::IsADirectory),
                (true, true) if !self.entries(dst)?.is_empty() => return Err(Errno::DirectoryNotEmpty),
                _ => {}
            }
        }
        // Charge the new name before anything changes, so failure leaves
        // both names intact.
        self.charge(dname.len() as u64)?;
        if existing.is_some() {
            self.drop_name(ddir, dname)?;
        }
        self.entries_mut(sdir)?.remove(sname);
        self.uncharge(sname.len() as u64);
        self.entries_mut(ddir)?.insert(dname.to_string(), src);
        let now = (self.clock)();
        if src_is_dir {
            if let Data::Dir { parent, .. } = &mut self.node_mut(src)?.data {
                *parent = ddir;
            }
            self.node_mut(sdir)?.nlink -= 1;
            self.node_mut(ddir)?.nlink += 1;
        }
        for d in [sdir, ddir] {
            let n = self.node_mut(d)?;
            n.mtime = now;
            n.ctime = now;
        }
        self.node_mut(src)?.ctime = now;
        Ok(())
    }

    pub fn set_mode(&mut self, ino: u64, mode: u32) -> Result<()> {
        let now = (self.clock)();
        let n = self.node_mut(ino)?;
        if matches!(n.data, Data::Symlink(_)) {
            return Err(Errno::InvalidArgument);
        }
        n.mode = mode & MODE_PERMS;
        n.ctime = now;
        Ok(())
    }

    /// Checks the internal invariants (for tests): link counts, parent
    /// pointers, reachability and the memory charge.
    pub fn check(&self) -> core::result::Result<(), String> {
        let mut charged = 0u64;
        let mut names = BTreeMap::<u64, u32>::new();
        let mut subdirs = BTreeMap::<u64, u32>::new();
        for (&ino, n) in &self.nodes {
            charged += NODE_COST;
            match &n.data {
                Data::File { size, pages } => {
                    charged += pages.len() as u64 * PAGE as u64;
                    if pages.keys().any(|&k| k * PAGE as u64 >= *size) {
                        return Err(alloc::format!("inode {ino}: page beyond the end of the file"));
                    }
                }
                Data::Symlink(t) => charged += t.len() as u64,
                Data::Dir { entries, .. } => {
                    for (name, child) in entries {
                        charged += name.len() as u64;
                        let c = self.nodes.get(child).ok_or_else(|| alloc::format!("{name}: dangling entry"))?;
                        *names.entry(*child).or_default() += 1;
                        if let Data::Dir { parent, .. } = c.data {
                            if parent != ino {
                                return Err(alloc::format!("{name}: wrong parent"));
                            }
                            *subdirs.entry(ino).or_default() += 1;
                        }
                    }
                }
            }
        }
        if charged != self.used {
            return Err(alloc::format!("charged {charged} bytes but accounted {}", self.used));
        }
        for (&ino, n) in &self.nodes {
            let expect = match n.data {
                Data::Dir { .. } if ino == ROOT => 2 + subdirs.get(&ino).copied().unwrap_or(0),
                Data::Dir { .. } => 2 + subdirs.get(&ino).copied().unwrap_or(0),
                _ => names.get(&ino).copied().unwrap_or(0),
            };
            let reachable = ino == ROOT || names.contains_key(&ino);
            if reachable && n.nlink != expect {
                return Err(alloc::format!("inode {ino}: nlink {} != {expect}", n.nlink));
            }
            if !reachable && (n.nlink != 0 || n.open == 0) {
                return Err(alloc::format!("inode {ino}: unreachable but kept"));
            }
        }
        Ok(())
    }
}
