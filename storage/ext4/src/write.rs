//! Writing: allocation, files, directories, links, truncation, deletion.
//!
//! Safety model:
//! * Every public mutating call is one journal transaction: metadata
//!   changes collect in `tx` (block -> new contents) and are committed
//!   and checkpointed when the call succeeds ([`Ext4::commit`]); on error
//!   they are dropped and the in-memory superblock and group descriptors
//!   are restored, so a failed call changes nothing on disk except data
//!   blocks that remain unallocated.
//! * File data is staged in memory and written out *before* the metadata
//!   that makes it reachable is committed ("ordered" mode); reads see staged
//!   blocks. Overwrites of existing data blocks are in place, as in Linux's
//!   ordered mode.
//! * Blocks freed by a transaction are not reused by the same transaction,
//!   so a crash before the commit never finds new data in a block the old
//!   metadata still uses.
//! * A file removed while open goes on the superblock's orphan list and is
//!   freed on its last close; the list is processed at the next writable
//!   mount if the machine stops before that.
//! * Only extent-mapped files are written. Adding entries to hashed
//!   (`dir_index`) directories is refused (`Unsupported`); extent trees are
//!   kept at depth 0, 1 or 2 (up to 4 index blocks, each with a full page of
//!   leaves).

use crate::dir::{entries, has_tail, TAIL};
use crate::inode::{Inode, FL_EXTENTS, FL_INDEX, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use crate::map::{index_entry, leaf_entry, parse_header, EXTENT_MAGIC};
use crate::{crc, feature, le16, le32, put16, put32, BlockDevice, Error, Ext4, GroupDesc, Result, Superblock};
use crate::{BG_BLOCK_UNINIT, BG_INODE_UNINIT, ROOT_INO};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

// Temporary I/O diagnostics.
pub static WRITE_CALLS: AtomicU64 = AtomicU64::new(0);
pub static WRITE_BYTES: AtomicU64 = AtomicU64::new(0);

/// (calls, bytes) of file writes since mount.
pub fn write_stats() -> (u64, u64) {
    (WRITE_CALLS.load(Ordering::Relaxed), WRITE_BYTES.load(Ordering::Relaxed))
}

/// What [`Ext4::create`] makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewKind<'a> {
    File,
    Dir,
    Symlink(&'a str),
}

/// Per-transaction state.
#[derive(Default)]
pub(crate) struct Tx {
    pub blocks: BTreeMap<u64, Vec<u8>>,
    pub dirty_groups: BTreeSet<u32>,
    pub freed: BTreeSet<u64>,
    /// Original contents of blocks this operation has changed, for rollback.
    undo: BTreeMap<u64, Option<Vec<u8>>>,
    recording: bool,
}

/// Deferred metadata limit: file writes keep their data on disk immediately
/// but collect metadata here, so a burst of small writes costs one journal
/// transaction per few MiB instead of one per write. `sync` commits.
const PENDING_LIMIT: usize = 1024;

/// Staged file data limit, in blocks. Small or unaligned writes (SQLite WAL
/// frames are 4120 bytes) would otherwise each cost a read-modify-write
/// device round trip; staging them lets one flush write whole runs.
const PENDING_DATA_LIMIT: usize = 2048;

/// Largest staged run written in one device request.
const PENDING_DATA_RUN: usize = 256;

/// One extent in a flattened tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ext {
    lblk: u64,
    len: u64,
    phys: u64,
    uninit: bool,
}

const MAX_INIT_LEN: u64 = 32768;
const MAX_UNINIT_LEN: u64 = 32767;
const MAX_LINKS: u16 = 65000;

fn ft_of(mode: u16) -> u8 {
    match mode & S_IFMT {
        S_IFREG => crate::dir::FT_REG,
        S_IFDIR => crate::dir::FT_DIR,
        S_IFLNK => crate::dir::FT_SYMLINK,
        crate::inode::S_IFCHR => crate::dir::FT_CHR,
        crate::inode::S_IFBLK => crate::dir::FT_BLK,
        crate::inode::S_IFIFO => crate::dir::FT_FIFO,
        crate::inode::S_IFSOCK => crate::dir::FT_SOCK,
        _ => crate::dir::FT_UNKNOWN,
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn rec_size(name_len: usize) -> usize {
    (8 + name_len + 3) & !3
}

struct Snapshot {
    sb: Superblock,
    groups: Vec<GroupDesc>,
    orphans: BTreeMap<u32, u32>,
}

impl<D: BlockDevice> Ext4<D> {
    // ---- transactions --------------------------------------------------------

    pub(crate) fn start_writing(&mut self) -> Result<()> {
        self.open_journal_for_writing()?;
        let mut incompat = self.sb.incompat;
        if self.journal.is_some() {
            incompat |= feature::INCOMPAT_RECOVER;
        }
        // Not cleanly unmounted until `clean_shutdown`.
        self.sb.state &= !1;
        put16(&mut self.sb.raw, 58, self.sb.state);
        let (secs, _) = (self.clock)();
        put32(&mut self.sb.raw, 44, secs as u32); // s_mtime
        let mounts = le16(&self.sb.raw, 52).wrapping_add(1);
        put16(&mut self.sb.raw, 52, mounts);
        self.set_incompat(incompat)?;
        self.process_orphans()
    }

    pub(crate) fn finish_writing(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        self.clean_shutdown()
    }

    /// Marks the volume clean (nothing pending, journal empty). Further
    /// writes are refused until it is mounted again.
    pub fn clean_shutdown(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        self.flush_pending()?;
        let open: Vec<u32> = self.orphans.keys().copied().collect();
        if !open.is_empty() {
            // Files still open at shutdown: their space is reclaimed now.
            for ino in open {
                self.orphans.insert(ino, 0);
                self.release_orphan(ino)?;
            }
        }
        self.sb.state |= 1;
        put16(&mut self.sb.raw, 58, self.sb.state);
        let (secs, _) = (self.clock)();
        put32(&mut self.sb.raw, 48, secs as u32);
        let incompat = self.sb.incompat & !feature::INCOMPAT_RECOVER;
        self.set_incompat(incompat)?;
        self.read_only = true;
        Ok(())
    }

    /// Writes the primary superblock with new incompatible-feature flags.
    pub(crate) fn set_incompat(&mut self, incompat: u32) -> Result<()> {
        self.sb.incompat = incompat;
        put32(&mut self.sb.raw, 96, incompat);
        self.write_superblock()
    }

    /// Writes `self.sb.raw` (checksum updated) to the primary location.
    pub(crate) fn write_superblock(&mut self) -> Result<()> {
        self.sb.update_checksum();
        let blk = self.sb.first_data_block as u64;
        let mut b = self.read_block(blk)?;
        let off = if self.sb.block_size == 1024 { 0 } else { 1024 };
        b[off..off + 1024].copy_from_slice(&self.sb.raw);
        self.write_block_raw(blk, &b)?;
        self.dev.flush()
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot { sb: self.sb.clone(), groups: self.groups.clone(), orphans: self.orphans.clone() }
    }

    /// Runs one mutating operation as a transaction.
    fn op<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.flush_pending()?;
        let snap = self.snapshot();
        self.tx = Tx::default();
        match f(self).and_then(|v| self.commit_tx().map(|_| v)) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.tx = Tx::default();
                self.sb = snap.sb;
                self.groups = snap.groups;
                self.orphans = snap.orphans;
                Err(e)
            }
        }
    }

    /// Runs a file write against the pending transaction: no journal commit
    /// unless it grows past [`PENDING_LIMIT`]. On error only this write's
    /// metadata changes are rolled back.
    fn write_op<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        let snap = self.snapshot();
        let dirty_groups = self.tx.dirty_groups.clone();
        let freed = self.tx.freed.clone();
        self.tx.recording = true;
        match f(self) {
            Ok(v) => {
                self.tx.recording = false;
                self.tx.undo.clear();
                if self.tx.blocks.len() >= PENDING_LIMIT {
                    self.flush_pending()?;
                }
                Ok(v)
            }
            Err(e) => {
                self.tx.recording = false;
                let undo = core::mem::take(&mut self.tx.undo);
                for (b, prev) in undo {
                    match prev {
                        Some(d) => {
                            self.tx.blocks.insert(b, d);
                        }
                        None => {
                            self.tx.blocks.remove(&b);
                        }
                    }
                }
                self.tx.dirty_groups = dirty_groups;
                self.tx.freed = freed;
                self.sb = snap.sb;
                self.groups = snap.groups;
                self.orphans = snap.orphans;
                Err(e)
            }
        }
    }

    /// Stages file data in memory. Writes whole blocks; a partial block is
    /// merged by the caller. Flushed by [`Ext4::flush_pending`] before the
    /// metadata that references it is committed.
    fn stage_data(&mut self, b: u64, data: &[u8]) -> Result<()> {
        let bs = self.sb.block_size as usize;
        if data.is_empty() || !data.len().is_multiple_of(bs) {
            return Err(Error::InvalidInput("write length is not a block multiple"));
        }
        let n = (data.len() / bs) as u64;
        if b.checked_add(n).is_none_or(|e| e > self.sb.blocks_count) {
            return Err(Error::Corrupt("write beyond the end of the file system"));
        }
        for (i, d) in data.chunks(bs).enumerate() {
            self.pending.insert(b + i as u64, d.to_vec());
        }
        if self.pending.len() >= PENDING_DATA_LIMIT {
            self.write_back()?;
        }
        Ok(())
    }

    /// Writes staged file data as consecutive runs. Staged blocks stay on
    /// error, so a failed device request is retried by the next flush.
    fn write_back(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let keys: Vec<u64> = self.pending.keys().copied().collect();
        let mut i = 0;
        while i < keys.len() {
            let start = keys[i];
            let mut run = self.pending[&start].clone();
            let mut j = i + 1;
            while j < keys.len() && keys[j] == start + (j - i) as u64 && j - i < PENDING_DATA_RUN {
                run.extend_from_slice(&self.pending[&keys[j]]);
                j += 1;
            }
            self.write_blocks_raw(start, &run)?;
            i = j;
        }
        for &b in &keys {
            self.pending.remove(&b);
        }
        Ok(())
    }

    /// Commits metadata accumulated by file writes, if any.
    pub(crate) fn flush_pending(&mut self) -> Result<()> {
        self.write_back()?;
        if self.tx.blocks.is_empty() && self.tx.dirty_groups.is_empty() && self.tx.freed.is_empty() {
            return Ok(());
        }
        self.commit_tx()
    }

    fn commit_tx(&mut self) -> Result<()> {
        self.store_groups()?;
        self.store_superblock()?;
        let tx = core::mem::take(&mut self.tx);
        if let Err(e) = self.commit(&tx.blocks) {
            // The device state is uncertain: stop writing.
            self.read_only = true;
            return Err(e);
        }
        Ok(())
    }

    pub(crate) fn tx_read(&mut self, b: u64) -> Result<Vec<u8>> {
        match self.tx.blocks.get(&b) {
            Some(d) => Ok(d.clone()),
            None => self.read_block(b),
        }
    }

    fn tx_put(&mut self, b: u64, data: Vec<u8>) {
        if self.tx.recording {
            let prev = self.tx.blocks.get(&b).cloned();
            self.tx.undo.entry(b).or_insert(prev);
        }
        self.tx.blocks.insert(b, data);
    }

    fn store_groups(&mut self) -> Result<()> {
        let dirty: Vec<u32> = self.tx.dirty_groups.iter().copied().collect();
        let ds = self.sb.desc_size as usize;
        let per = self.sb.descs_per_block();
        let csum = self.sb.metadata_csum();
        for g in dirty {
            if csum {
                let ipb = self.sb.inodes_per_group as usize / 8;
                let bpb = self.sb.blocks_per_group as usize / 8;
                let gd = self.groups[g as usize];
                if gd.flags & BG_BLOCK_UNINIT == 0 {
                    let bm = self.tx_read(gd.block_bitmap)?;
                    self.groups[g as usize].block_bitmap_csum = crc::crc32c(self.csum_seed, &bm[..bpb]);
                }
                if gd.flags & BG_INODE_UNINIT == 0 {
                    let im = self.tx_read(gd.inode_bitmap)?;
                    self.groups[g as usize].inode_bitmap_csum = crc::crc32c(self.csum_seed, &im[..ipb]);
                }
            }
            let blk = self.desc_block(g / per);
            let mut b = self.tx_read(blk)?;
            let off = (g % per) as usize * ds;
            self.groups[g as usize].store(&mut b[off..off + ds], ds >= 64);
            if let Some(c) = self.desc_checksum(g, &b[off..off + ds]) {
                put16(&mut b, off + 30, c);
            }
            self.tx_put(blk, b);
        }
        Ok(())
    }

    fn store_superblock(&mut self) -> Result<()> {
        let free_b: u64 = self.groups.iter().map(|g| g.free_blocks as u64).sum();
        let free_i: u64 = self.groups.iter().map(|g| g.free_inodes as u64).sum();
        put32(&mut self.sb.raw, 12, free_b as u32);
        if self.sb.has_incompat(feature::INCOMPAT_64BIT) {
            put32(&mut self.sb.raw, 0x158, (free_b >> 32) as u32);
        }
        put32(&mut self.sb.raw, 16, free_i as u32);
        let (secs, _) = (self.clock)();
        put32(&mut self.sb.raw, 48, secs as u32);
        self.sb.update_checksum();
        let blk = self.sb.first_data_block as u64;
        let mut b = self.tx_read(blk)?;
        let off = if self.sb.block_size == 1024 { 0 } else { 1024 };
        b[off..off + 1024].copy_from_slice(&self.sb.raw);
        self.tx_put(blk, b);
        Ok(())
    }

    // ---- inodes ----------------------------------------------------------------

    pub(crate) fn tx_inode(&mut self, ino: u32) -> Result<Inode> {
        let (blk, off) = self.inode_location(ino)?;
        let b = self.tx_read(blk)?;
        let isz = self.sb.inode_size as usize;
        let i = Inode::parse(ino, &b[off..off + isz], &self.sb)?;
        if self.sb.metadata_csum() && !i.checksum_ok(&b[off..off + isz], self.csum_seed, &self.sb) {
            return Err(Error::Corrupt("inode checksum"));
        }
        Ok(i)
    }

    fn put_inode(&mut self, i: &mut Inode) -> Result<()> {
        i.store(&self.sb);
        i.update_checksum(self.csum_seed, &self.sb);
        let (blk, off) = self.inode_location(i.ino)?;
        let mut b = self.tx_read(blk)?;
        b[off..off + i.raw.len()].copy_from_slice(&i.raw);
        self.tx_put(blk, b);
        Ok(())
    }

    /// Current time; without a clock, the superblock's last write time
    /// (never 0, which e2fsck reads as "not deleted" in `dtime`).
    fn now(&self) -> (i64, u32) {
        match (self.clock)() {
            (0, 0) => ((le32(&self.sb.raw, 48) as i64).max(1), 0),
            t => t,
        }
    }

    // ---- bitmaps and allocation ------------------------------------------------

    fn group_of_block(&self, b: u64) -> u32 {
        ((b - self.sb.first_data_block as u64) / self.sb.blocks_per_group as u64) as u32
    }

    /// Blocks of group `g` (the last group may be short).
    fn group_len(&self, g: u32) -> u64 {
        let start = self.sb.group_first_block(g);
        (self.sb.blocks_count - start).min(self.sb.blocks_per_group as u64)
    }

    /// The block bitmap of `g`, initialising it if the group is BLOCK_UNINIT.
    fn block_bitmap(&mut self, g: u32) -> Result<Vec<u8>> {
        let gd = self.groups[g as usize];
        if gd.flags & BG_BLOCK_UNINIT == 0 {
            return self.tx_read(gd.block_bitmap);
        }
        let bs = self.sb.block_size as usize;
        let mut bm = vec![0u8; bs];
        let start = self.sb.group_first_block(g);
        let len = self.group_len(g);
        let mut mark = |b: u64| {
            if b >= start && b < start + len {
                let i = (b - start) as usize;
                bm[i / 8] |= 1 << (i % 8);
            }
        };
        if self.sb.has_super(g) && !self.sb.has_incompat(feature::INCOMPAT_META_BG) {
            let gdt = (self.sb.group_count() as u64).div_ceil(self.sb.descs_per_block() as u64);
            for b in start..start + 1 + gdt + self.sb.reserved_gdt_blocks as u64 {
                mark(b);
            }
        }
        let itable = (self.sb.inodes_per_group as u64 * self.sb.inode_size as u64).div_ceil(bs as u64);
        for d in self.groups.clone() {
            mark(d.block_bitmap);
            mark(d.inode_bitmap);
            for b in d.inode_table..d.inode_table + itable {
                mark(b);
            }
        }
        // Bits past the end of a short last group are set.
        for i in len as usize..self.sb.blocks_per_group as usize {
            bm[i / 8] |= 1 << (i % 8);
        }
        for i in self.sb.blocks_per_group as usize..bs * 8 {
            bm[i / 8] |= 1 << (i % 8);
        }
        let used = (0..len as usize).filter(|&i| bm[i / 8] & (1 << (i % 8)) != 0).count() as u32;
        if len as u32 - used != gd.free_blocks {
            return Err(Error::Corrupt("free block count of an uninitialised group"));
        }
        self.groups[g as usize].flags &= !BG_BLOCK_UNINIT;
        self.tx.dirty_groups.insert(g);
        Ok(bm)
    }

    /// Allocates up to `want` contiguous blocks, preferring `goal`.
    fn alloc_blocks(&mut self, goal: u64, want: u64) -> Result<(u64, u64)> {
        let groups = self.sb.group_count();
        let goal = goal.clamp(self.sb.first_data_block as u64, self.sb.blocks_count - 1);
        let first_g = self.group_of_block(goal);
        for k in 0..groups {
            let g = (first_g + k) % groups;
            if self.groups[g as usize].free_blocks == 0 {
                continue;
            }
            let mut bm = self.block_bitmap(g)?;
            let start = self.sb.group_first_block(g);
            let len = self.group_len(g);
            let from = if k == 0 { goal - start } else { 0 };
            let mut found = None;
            for pass in 0..2 {
                let (lo, hi) = if pass == 0 { (from, len) } else { (0, from) };
                let mut i = lo;
                while i < hi {
                    let free = bm[(i / 8) as usize] & (1 << (i % 8)) == 0 && !self.tx.freed.contains(&(start + i));
                    if free {
                        let mut n = 1;
                        while n < want
                            && i + n < len
                            && bm[((i + n) / 8) as usize] & (1 << ((i + n) % 8)) == 0
                            && !self.tx.freed.contains(&(start + i + n))
                        {
                            n += 1;
                        }
                        found = Some((i, n));
                        break;
                    }
                    i += 1;
                }
                if found.is_some() {
                    break;
                }
            }
            let Some((i, n)) = found else { continue };
            for j in i..i + n {
                bm[(j / 8) as usize] |= 1 << (j % 8);
            }
            let bmb = self.groups[g as usize].block_bitmap;
            self.tx_put(bmb, bm);
            self.groups[g as usize].free_blocks -= n as u32;
            self.tx.dirty_groups.insert(g);
            return Ok((start + i, n));
        }
        Err(Error::NoSpace)
    }

    fn free_blocks(&mut self, start: u64, len: u64) -> Result<()> {
        let mut b = start;
        while b < start + len {
            let g = self.group_of_block(b);
            let gs = self.sb.group_first_block(g);
            let end = (start + len).min(gs + self.group_len(g));
            let mut bm = self.block_bitmap(g)?;
            for x in b..end {
                let i = (x - gs) as usize;
                if bm[i / 8] & (1 << (i % 8)) == 0 {
                    return Err(Error::Corrupt("freeing a block that is not in use"));
                }
                bm[i / 8] &= !(1 << (i % 8));
                self.tx.freed.insert(x);
                self.tx.blocks.remove(&x);
                self.pending.remove(&x);
                self.forget_cached(x);
            }
            let bmb = self.groups[g as usize].block_bitmap;
            self.tx_put(bmb, bm);
            self.groups[g as usize].free_blocks += (end - b) as u32;
            self.tx.dirty_groups.insert(g);
            b = end;
        }
        Ok(())
    }

    fn alloc_inode(&mut self, near: u32, dir: bool) -> Result<u32> {
        let ipg = self.sb.inodes_per_group;
        let groups = self.sb.group_count();
        let first_g = (near.max(1) - 1) / ipg;
        for k in 0..groups {
            let g = (first_g + k) % groups;
            let gd = self.groups[g as usize];
            if gd.free_inodes == 0 {
                continue;
            }
            let mut bm = if gd.flags & BG_INODE_UNINIT != 0 {
                vec![0u8; self.sb.block_size as usize]
            } else {
                self.tx_read(gd.inode_bitmap)?
            };
            let mut found = None;
            for i in 0..ipg {
                let ino = g * ipg + i + 1;
                if ino < self.sb.first_ino {
                    continue;
                }
                if bm[(i / 8) as usize] & (1 << (i % 8)) == 0 {
                    found = Some(i);
                    break;
                }
            }
            let Some(i) = found else { continue };
            if gd.flags & BG_INODE_UNINIT != 0 {
                // Bits past the inodes of the group are set.
                for j in ipg as usize..self.sb.block_size as usize * 8 {
                    bm[j / 8] |= 1 << (j % 8);
                }
                self.groups[g as usize].flags &= !BG_INODE_UNINIT;
            }
            bm[(i / 8) as usize] |= 1 << (i % 8);
            let track_unused = self.has_group_csums_w();
            let gd = &mut self.groups[g as usize];
            self.tx.blocks.insert(gd.inode_bitmap, bm);
            gd.free_inodes -= 1;
            if dir {
                gd.used_dirs += 1;
            }
            if track_unused && ipg - gd.itable_unused <= i {
                gd.itable_unused = ipg - i - 1;
            }
            self.tx.dirty_groups.insert(g);
            return Ok(g * ipg + i + 1);
        }
        Err(Error::NoSpace)
    }

    fn has_group_csums_w(&self) -> bool {
        self.sb.metadata_csum() || self.sb.has_ro_compat(feature::RO_COMPAT_GDT_CSUM)
    }

    fn free_inode_bit(&mut self, ino: u32, dir: bool) -> Result<()> {
        let ipg = self.sb.inodes_per_group;
        let g = (ino - 1) / ipg;
        let i = (ino - 1) % ipg;
        let gd = self.groups[g as usize];
        let mut bm = self.tx_read(gd.inode_bitmap)?;
        if bm[(i / 8) as usize] & (1 << (i % 8)) == 0 {
            return Err(Error::Corrupt("freeing an inode that is not in use"));
        }
        bm[(i / 8) as usize] &= !(1 << (i % 8));
        self.tx_put(gd.inode_bitmap, bm);
        let gd = &mut self.groups[g as usize];
        gd.free_inodes += 1;
        if dir {
            gd.used_dirs = gd.used_dirs.saturating_sub(1);
        }
        self.tx.dirty_groups.insert(g);
        Ok(())
    }

    // ---- extents ---------------------------------------------------------------

    fn collect_extents(&mut self, inode: &Inode, node: &[u8], room: usize, out: &mut Vec<Ext>, tree: &mut Vec<u64>, depth_left: u16) -> Result<()> {
        let h = parse_header(node, room)?;
        if h.depth > depth_left {
            return Err(Error::Corrupt("extent tree too deep"));
        }
        for i in 0..h.entries as usize {
            if h.depth == 0 {
                let (l, len, phys, uninit) = leaf_entry(node, i);
                if len == 0 || phys.checked_add(len as u64).is_none_or(|e| e > self.sb.blocks_count) {
                    return Err(Error::Corrupt("extent outside the file system"));
                }
                out.push(Ext { lblk: l as u64, len: len as u64, phys, uninit });
            } else {
                let (_, child) = index_entry(node, i);
                tree.push(child);
                let b = self.extent_block_tx(inode, child, h.depth - 1)?;
                self.collect_extents(inode, &b, b.len(), out, tree, h.depth - 1)?;
            }
        }
        Ok(())
    }

    fn extent_block_tx(&mut self, inode: &Inode, blk: u64, depth: u16) -> Result<Vec<u8>> {
        if let Some(b) = self.tx.blocks.get(&blk) {
            let b = b.clone();
            let h = parse_header(&b, b.len())?;
            if h.depth != depth {
                return Err(Error::Corrupt("extent tree depth mismatch"));
            }
            return Ok(b);
        }
        self.extent_block(inode, blk, depth)
    }

    /// The whole extent list and the tree blocks holding it.
    fn extents(&mut self, inode: &Inode) -> Result<(Vec<Ext>, Vec<u64>)> {
        if !inode.uses_extents() {
            return Err(Error::Unsupported("writing block-mapped files"));
        }
        let mut out = Vec::new();
        let mut tree = Vec::new();
        let root = inode.block.to_vec();
        self.collect_extents(inode, &root, 60, &mut out, &mut tree, 5)?;
        out.sort_by_key(|e| e.lblk);
        if out.windows(2).any(|w| w[0].lblk + w[0].len > w[1].lblk) {
            return Err(Error::Corrupt("overlapping extents"));
        }
        Ok((out, tree))
    }

    /// Allocates one block for an extent tree node.
    fn tree_block(&mut self, goal: u64, inode: &mut Inode) -> Result<u64> {
        let (b, _) = self.alloc_blocks(goal, 1)?;
        inode.blocks_512 += self.sb.block_size as u64 / 512;
        Ok(b)
    }

    /// Writes `list` back as an extent tree of depth 0, 1 or 2.
    fn store_extents(&mut self, inode: &mut Inode, list: Vec<Ext>, old_tree: Vec<u64>) -> Result<()> {
        // Merge neighbours and split oversized extents.
        let mut merged: Vec<Ext> = Vec::with_capacity(list.len());
        for e in list {
            match merged.last_mut() {
                Some(p) if p.uninit == e.uninit && p.lblk + p.len == e.lblk && p.phys + p.len == e.phys => p.len += e.len,
                _ => merged.push(e),
            }
        }
        let mut flat = Vec::with_capacity(merged.len());
        for mut e in merged {
            let max = if e.uninit { MAX_UNINIT_LEN } else { MAX_INIT_LEN };
            while e.len > max {
                flat.push(Ext { len: max, ..e });
                e.lblk += max;
                e.phys += max;
                e.len -= max;
            }
            flat.push(e);
        }
        let bs = self.sb.block_size as usize;
        let per_node = (bs - 12) / 12;
        let put_extent = |b: &mut [u8], i: usize, e: &Ext| {
            let o = 12 + 12 * i;
            put32(b, o, e.lblk as u32);
            put16(b, o + 4, if e.uninit { e.len as u16 + 32768 } else { e.len as u16 });
            put16(b, o + 6, (e.phys >> 32) as u16);
            put32(b, o + 8, e.phys as u32);
        };
        let put_index = |b: &mut [u8], i: usize, first: u32, blk: u64| {
            let o = 12 + 12 * i;
            put32(b, o, first);
            put32(b, o + 4, blk as u32);
            put16(b, o + 8, (blk >> 32) as u16);
        };
        let header = |b: &mut [u8], entries: usize, max: usize, depth: u16| {
            put16(b, 0, EXTENT_MAGIC);
            put16(b, 2, entries as u16);
            put16(b, 4, max as u16);
            put16(b, 6, depth);
            put32(b, 8, 0);
        };
        let mut root = [0u8; 60];
        let mut reuse = old_tree.clone();
        if flat.len() <= 4 {
            header(&mut root, flat.len(), 4, 0);
            for (i, e) in flat.iter().enumerate() {
                put_extent(&mut root, i, e);
            }
            for b in reuse {
                self.free_blocks(b, 1)?;
                inode.blocks_512 -= bs as u64 / 512;
            }
            inode.block = root;
            return Ok(());
        }
        let leaves = flat.len().div_ceil(per_node);
        if leaves > 4 * per_node {
            return Err(Error::Unsupported("file too fragmented for a depth-2 extent tree"));
        }
        let seed = inode.csum_seed(self.csum_seed);
        let mut leaf_blocks: Vec<(u32, u64)> = Vec::with_capacity(leaves);
        for chunk in flat.chunks(per_node) {
            let blk = match reuse.pop() {
                Some(b) => b,
                None => self.tree_block(chunk[0].phys, inode)?,
            };
            let mut b = vec![0u8; bs];
            header(&mut b, chunk.len(), per_node, 0);
            for (i, e) in chunk.iter().enumerate() {
                put_extent(&mut b, i, e);
            }
            if self.sb.metadata_csum() {
                let tail = 12 + 12 * per_node;
                let c = crc::crc32c(seed, &b[..tail]);
                put32(&mut b, tail, c);
            }
            self.tx_put(blk, b);
            leaf_blocks.push((chunk[0].lblk as u32, blk));
        }
        if leaf_blocks.len() <= 4 {
            header(&mut root, leaf_blocks.len(), 4, 1);
            for (i, &(first, blk)) in leaf_blocks.iter().enumerate() {
                put_index(&mut root, i, first, blk);
            }
        } else {
            let mut index_blocks: Vec<(u32, u64)> = Vec::new();
            for group in leaf_blocks.chunks(per_node) {
                let blk = match reuse.pop() {
                    Some(b) => b,
                    None => self.tree_block(group[0].1, inode)?,
                };
                let mut b = vec![0u8; bs];
                header(&mut b, group.len(), per_node, 1);
                for (i, &(first, child)) in group.iter().enumerate() {
                    put_index(&mut b, i, first, child);
                }
                if self.sb.metadata_csum() {
                    let tail = 12 + 12 * per_node;
                    let c = crc::crc32c(seed, &b[..tail]);
                    put32(&mut b, tail, c);
                }
                self.tx_put(blk, b);
                index_blocks.push((group[0].0, blk));
            }
            if index_blocks.len() > 4 {
                return Err(Error::Unsupported("file too fragmented for a depth-2 extent tree"));
            }
            header(&mut root, index_blocks.len(), 4, 2);
            for (i, &(first, blk)) in index_blocks.iter().enumerate() {
                put_index(&mut root, i, first, blk);
            }
        }
        for b in reuse {
            self.free_blocks(b, 1)?;
            inode.blocks_512 -= bs as u64 / 512;
        }
        inode.block = root;
        Ok(())
    }

    // ---- file data -------------------------------------------------------------

    fn max_size(&self) -> u64 {
        let by_blocks = (u32::MAX as u64) * self.sb.block_size as u64;
        if self.sb.has_ro_compat(feature::RO_COMPAT_LARGE_FILE) {
            by_blocks
        } else {
            (1u64 << 31) - 1
        }
    }

    /// Writes `data` at `offset` of a regular file; returns bytes written.
    pub fn write(&mut self, ino: u32, offset: u64, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        WRITE_CALLS.fetch_add(1, Ordering::Relaxed);
        WRITE_BYTES.fetch_add(data.len() as u64, Ordering::Relaxed);
        let end = offset.checked_add(data.len() as u64).ok_or(Error::FileTooLarge)?;
        if end > self.max_size() {
            return Err(Error::FileTooLarge);
        }
        self.write_op(|fs| {
            let mut inode = fs.tx_inode(ino)?;
            if inode.file_type() != S_IFREG {
                return Err(if inode.is_dir() { Error::IsADirectory } else { Error::InvalidInput("not a regular file") });
            }
            fs.write_data(&mut inode, offset, data)?;
            inode.size = inode.size.max(end);
            let now = fs.now();
            inode.mtime = now;
            inode.ctime = now;
            fs.put_inode(&mut inode)?;
            Ok(data.len())
        })
    }

    fn write_data(&mut self, inode: &mut Inode, offset: u64, data: &[u8]) -> Result<()> {
        let bs = self.sb.block_size as u64;
        let (mut list, tree) = self.extents(inode)?;
        let first = offset / bs;
        let last = (offset + data.len() as u64 - 1) / bs;
        let goal_default = {
            let g = (inode.ino - 1) / self.sb.inodes_per_group;
            self.sb.group_first_block(g)
        };
        let mut l = first;
        let mut changed = false;
        // Newly allocated blocks: parts the write does not cover are zeroed.
        let mut fresh: BTreeSet<u64> = BTreeSet::new();
        while l <= last {
            let pos = list.iter().position(|e| e.lblk <= l && l < e.lblk + e.len);
            let (phys, run) = match pos {
                Some(i) if !list[i].uninit => {
                    let e = list[i];
                    (e.phys + (l - e.lblk), e.lblk + e.len - l)
                }
                Some(i) => {
                    // Unwritten extent: zero it on disk, then mark it written.
                    let e = list[i];
                    let zeros = vec![0u8; bs as usize];
                    for k in 0..e.len {
                        self.stage_data(e.phys + k, &zeros)?;
                    }
                    list[i].uninit = false;
                    changed = true;
                    continue;
                }
                None => {
                    let next = list.iter().filter(|e| e.lblk > l).map(|e| e.lblk).min().unwrap_or(u64::MAX);
                    let want = (last + 1).min(next) - l;
                    let goal = list.iter().filter(|e| e.lblk < l).max_by_key(|e| e.lblk).map_or(goal_default, |e| e.phys + e.len);
                    let (p, n) = self.alloc_blocks(goal, want)?;
                    inode.blocks_512 += n * (bs / 512);
                    fresh.extend(p..p + n);
                    list.push(Ext { lblk: l, len: n, phys: p, uninit: false });
                    list.sort_by_key(|e| e.lblk);
                    changed = true;
                    (p, n)
                }
            };
            let n = run.min(last + 1 - l);
            let mut k = 0;
            while k < n {
                let lb = l + k;
                let bstart = lb * bs;
                let from = offset.max(bstart);
                let to = (offset + data.len() as u64).min(bstart + bs);
                if from == bstart && to == bstart + bs {
                    // Extend over all following blocks this write covers
                    // completely; one device request instead of one per block.
                    let mut m = k + 1;
                    while m < n {
                        let nstart = (l + m) * bs;
                        if offset <= nstart && nstart + bs <= offset + data.len() as u64 {
                            m += 1;
                        } else {
                            break;
                        }
                    }
                    let start = (bstart - offset) as usize;
                    self.stage_data(phys + k, &data[start..start + (m - k) as usize * bs as usize])?;
                    k = m;
                } else {
                    let src = &data[(from - offset) as usize..(to - offset) as usize];
                    let mut blk = vec![0u8; bs as usize];
                    if !fresh.contains(&(phys + k)) {
                        self.read_blocks_raw(phys + k, &mut blk)?;
                    }
                    blk[(from - bstart) as usize..(to - bstart) as usize].copy_from_slice(src);
                    self.stage_data(phys + k, &blk)?;
                    k += 1;
                }
            }
            l += n;
        }
        if changed {
            self.store_extents(inode, list, tree)?;
        }
        Ok(())
    }

    /// Frees every block at or beyond logical block `keep`.
    fn free_from(&mut self, inode: &mut Inode, keep: u64) -> Result<()> {
        let bs = self.sb.block_size as u64;
        let (list, tree) = self.extents(inode)?;
        let mut kept = Vec::with_capacity(list.len());
        for e in list {
            if e.lblk + e.len <= keep {
                kept.push(e);
            } else if e.lblk >= keep {
                self.free_blocks(e.phys, e.len)?;
                inode.blocks_512 -= e.len * (bs / 512);
            } else {
                let stay = keep - e.lblk;
                self.free_blocks(e.phys + stay, e.len - stay)?;
                inode.blocks_512 -= (e.len - stay) * (bs / 512);
                kept.push(Ext { len: stay, ..e });
            }
        }
        self.store_extents(inode, kept, tree)
    }

    /// Sets the size of a regular file (growing leaves a hole).
    pub fn truncate(&mut self, ino: u32, size: u64) -> Result<()> {
        if size > self.max_size() {
            return Err(Error::FileTooLarge);
        }
        self.op(|fs| {
            let mut inode = fs.tx_inode(ino)?;
            if inode.file_type() != S_IFREG {
                return Err(if inode.is_dir() { Error::IsADirectory } else { Error::InvalidInput("not a regular file") });
            }
            let bs = fs.sb.block_size as u64;
            if size < inode.size {
                fs.free_from(&mut inode, size.div_ceil(bs))?;
                // Zero the tail of the last block so growing reads zeros.
                if !size.is_multiple_of(bs) {
                    let (list, _) = fs.extents(&inode)?;
                    let l = size / bs;
                    if let Some(e) = list.iter().find(|e| e.lblk <= l && l < e.lblk + e.len && !e.uninit) {
                        let phys = e.phys + (l - e.lblk);
                        let mut blk = vec![0u8; bs as usize];
                        fs.read_blocks_raw(phys, &mut blk)?;
                        blk[(size % bs) as usize..].fill(0);
                        fs.stage_data(phys, &blk)?;
                    }
                }
            }
            inode.size = size;
            let now = fs.now();
            inode.mtime = now;
            inode.ctime = now;
            fs.put_inode(&mut inode)
        })
    }

    // ---- directories -------------------------------------------------------------

    fn new_dir_block(&self, entries_: &[(u32, &[u8], u8)]) -> Vec<u8> {
        let bs = self.sb.block_size as usize;
        let csum = self.sb.metadata_csum();
        let usable = if csum { bs - TAIL } else { bs };
        let mut b = vec![0u8; bs];
        let mut off = 0;
        for (i, (ino, name, ft)) in entries_.iter().enumerate() {
            let len = if i + 1 == entries_.len() { usable - off } else { rec_size(name.len()) };
            put32(&mut b, off, *ino);
            put16(&mut b, off + 4, len as u16);
            b[off + 6] = name.len() as u8;
            b[off + 7] = *ft;
            b[off + 8..off + 8 + name.len()].copy_from_slice(name);
            off += len;
        }
        if entries_.is_empty() {
            put16(&mut b, 4, usable as u16);
        }
        if csum {
            let o = bs - TAIL;
            put16(&mut b, o + 4, TAIL as u16);
            b[o + 7] = 0xDE;
        }
        b
    }

    fn seal_dir_block(&self, dir: &Inode, b: &mut [u8]) {
        if self.sb.metadata_csum() && has_tail(b) {
            let o = b.len() - TAIL;
            let c = crc::crc32c(dir.csum_seed(self.csum_seed), &b[..o]);
            put32(b, o + 8, c);
        }
    }

    fn filetype(&self) -> bool {
        self.sb.has_incompat(feature::INCOMPAT_FILETYPE)
    }

    /// Finds `name` in `dir`: (logical block, offset, inode, file type).
    fn find_entry(&mut self, dir: &Inode, name: &str) -> Result<(u64, usize, u32, u8)> {
        let ft = self.filetype();
        for lblk in 0..self.dir_blocks(dir)? {
            let (_, b) = self.dir_block(dir, lblk)?;
            for e in entries(&b, ft, self.sb.inodes_count)? {
                if e.ino != 0 && e.name == name.as_bytes() {
                    return Ok((lblk, e.off, e.ino, e.file_type));
                }
            }
        }
        Err(Error::NotFound)
    }

    fn add_entry(&mut self, dir: &mut Inode, name: &str, ino: u32, ft: u8) -> Result<()> {
        if dir.flags & FL_INDEX != 0 {
            return Err(Error::Unsupported("adding entries to a hashed (dir_index) directory"));
        }
        let need = rec_size(name.len());
        let filetype = self.filetype();
        let bs = self.sb.block_size as usize;
        let usable_end = if self.sb.metadata_csum() { bs - TAIL } else { bs };
        for lblk in 0..self.dir_blocks(dir)? {
            let (phys, _) = self.dir_block(dir, lblk)?;
            let mut b = self.tx_read(phys)?;
            let list: Vec<(usize, u32, usize, usize)> =
                entries(&b, filetype, self.sb.inodes_count)?.iter().map(|e| (e.off, e.ino, e.rec_len, e.name.len())).collect();
            for (off, eino, rec_len, nlen) in list {
                if off >= usable_end {
                    continue; // the checksum tail
                }
                let rec_end = (off + rec_len).min(usable_end);
                let (slot, slot_len) = if eino == 0 {
                    (off, rec_end - off)
                } else {
                    let used = rec_size(nlen);
                    (off + used, rec_end.saturating_sub(off + used))
                };
                if slot_len < need {
                    continue;
                }
                if eino != 0 {
                    put16(&mut b, off + 4, (slot - off) as u16);
                }
                put32(&mut b, slot, ino);
                put16(&mut b, slot + 4, (off + rec_len - slot) as u16);
                b[slot + 6] = name.len() as u8;
                b[slot + 7] = if filetype { ft } else { 0 };
                b[slot + 8..slot + 8 + name.len()].copy_from_slice(name.as_bytes());
                self.seal_dir_block(dir, &mut b);
                self.tx_put(phys, b);
                return Ok(());
            }
        }
        // No room: append a block.
        let lblk = dir.size / bs as u64;
        let mut b = self.new_dir_block(&[(ino, name.as_bytes(), if filetype { ft } else { 0 })]);
        self.seal_dir_block(dir, &mut b);
        let (mut list, tree) = self.extents(dir)?;
        let goal = list.last().map_or(0, |e| e.phys + e.len);
        let (p, _) = self.alloc_blocks(goal, 1)?;
        dir.blocks_512 += bs as u64 / 512;
        list.push(Ext { lblk, len: 1, phys: p, uninit: false });
        self.store_extents(dir, list, tree)?;
        self.tx_put(p, b);
        dir.size += bs as u64;
        Ok(())
    }

    fn remove_entry(&mut self, dir: &Inode, lblk: u64, off: usize) -> Result<()> {
        let (phys, _) = self.dir_block(dir, lblk)?;
        let mut b = self.tx_read(phys)?;
        let filetype = self.filetype();
        let list: Vec<(usize, usize)> = entries(&b, filetype, self.sb.inodes_count)?.iter().map(|e| (e.off, e.rec_len)).collect();
        let i = list.iter().position(|&(o, _)| o == off).ok_or(Error::NotFound)?;
        if i == 0 {
            put32(&mut b, off, 0);
        } else {
            let (poff, plen) = list[i - 1];
            put16(&mut b, poff + 4, (plen + list[i].1) as u16);
        }
        self.seal_dir_block(dir, &mut b);
        self.tx_put(phys, b);
        Ok(())
    }

    /// Rewrites the `..` entry of directory `dir` to point at `parent`.
    fn set_dotdot(&mut self, dir: &Inode, parent: u32) -> Result<()> {
        let (phys, _) = self.dir_block(dir, 0)?;
        let mut b = self.tx_read(phys)?;
        let filetype = self.filetype();
        let off = entries(&b, filetype, self.sb.inodes_count)?
            .iter()
            .find(|e| e.name == b"..")
            .map(|e| e.off)
            .ok_or(Error::Corrupt("directory without .."))?;
        put32(&mut b, off, parent);
        self.seal_dir_block(dir, &mut b);
        self.tx_put(phys, b);
        Ok(())
    }

    fn dir_is_empty(&mut self, dir: &Inode) -> Result<bool> {
        let filetype = self.filetype();
        for lblk in 0..self.dir_blocks(dir)? {
            let (phys, _) = self.dir_block(dir, lblk)?;
            let b = self.tx_read(phys)?;
            if entries(&b, filetype, self.sb.inodes_count)?.iter().any(|e| e.ino != 0 && e.name != b"." && e.name != b"..") {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn parent_of(&mut self, dir: &Inode) -> Result<u32> {
        let (phys, _) = self.dir_block(dir, 0)?;
        let b = self.tx_read(phys)?;
        let filetype = self.filetype();
        let list = entries(&b, filetype, self.sb.inodes_count)?;
        list.iter().find(|e| e.name == b"..").map(|e| e.ino).ok_or(Error::Corrupt("directory without .."))
    }

    fn dir_tx(&mut self, ino: u32) -> Result<Inode> {
        let d = self.tx_inode(ino)?;
        if !d.is_dir() {
            return Err(Error::NotADirectory);
        }
        Ok(d)
    }

    fn new_inode(&mut self, ino: u32, mode: u16, uid: u32, gid: u32) -> Inode {
        let isz = self.sb.inode_size as usize;
        let now = self.now();
        let want = le16(&self.sb.raw, 350).max(self.sb.min_extra_isize);
        let extra = if isz > 128 { (if want >= 4 { want } else { 32 }).min((isz - 128) as u16) & !3 } else { 0 };
        let mut raw = vec![0u8; isz];
        if isz > 128 {
            put16(&mut raw, 128, extra);
            // crtime
            if 128 + extra as usize >= 152 {
                put32(&mut raw, 144, now.0 as u32);
                put32(&mut raw, 148, now.1 << 2);
            }
        }
        let generation = crc::crc32c(now.1 ^ ino, &now.0.to_le_bytes());
        Inode {
            ino,
            mode,
            uid,
            gid,
            size: 0,
            links: 0,
            blocks_512: 0,
            flags: 0,
            generation,
            block: [0; 60],
            atime: now,
            mtime: now,
            ctime: now,
            dtime: 0,
            extra_isize: extra,
            raw,
        }
    }

    fn empty_extent_root() -> [u8; 60] {
        let mut b = [0u8; 60];
        put16(&mut b, 0, EXTENT_MAGIC);
        put16(&mut b, 4, 4);
        b
    }

    /// Creates `name` in directory `dir`; returns the new inode number.
    pub fn create(&mut self, dir: u32, name: &str, kind: NewKind<'_>, perm: u16, uid: u32, gid: u32) -> Result<u32> {
        validate_name(name)?;
        if let NewKind::Symlink(t) = kind {
            if t.is_empty() || t.len() >= self.sb.block_size as usize {
                return Err(Error::InvalidInput("symbolic link target length"));
            }
        }
        self.op(|fs| {
            let mut parent = fs.dir_tx(dir)?;
            if parent.links == 0 {
                return Err(Error::NotFound);
            }
            if fs.find_entry(&parent, name).is_ok() {
                return Err(Error::AlreadyExists);
            }
            let is_dir = matches!(kind, NewKind::Dir);
            if is_dir && parent.links >= MAX_LINKS {
                return Err(Error::NoSpace);
            }
            let ino = fs.alloc_inode(dir, is_dir)?;
            let bs = fs.sb.block_size as usize;
            let type_bits = match kind {
                NewKind::File => S_IFREG,
                NewKind::Dir => S_IFDIR,
                NewKind::Symlink(_) => S_IFLNK,
            };
            let perm = if matches!(kind, NewKind::Symlink(_)) { 0o777 } else { perm & 0o7777 };
            let mut inode = fs.new_inode(ino, type_bits | perm, uid, gid);
            match kind {
                NewKind::File => {
                    inode.links = 1;
                    inode.flags = FL_EXTENTS;
                    inode.block = Self::empty_extent_root();
                }
                NewKind::Symlink(t) if t.len() < 60 => {
                    inode.links = 1;
                    inode.block[..t.len()].copy_from_slice(t.as_bytes());
                    inode.size = t.len() as u64;
                }
                NewKind::Symlink(t) => {
                    inode.links = 1;
                    inode.flags = FL_EXTENTS;
                    inode.block = Self::empty_extent_root();
                    let mut data = vec![0u8; bs];
                    data[..t.len()].copy_from_slice(t.as_bytes());
                    let goal = fs.sb.group_first_block((ino - 1) / fs.sb.inodes_per_group);
                    let (p, _) = fs.alloc_blocks(goal, 1)?;
                    fs.write_block_raw(p, &data)?;
                    inode.blocks_512 = bs as u64 / 512;
                    fs.store_extents(&mut inode, vec![Ext { lblk: 0, len: 1, phys: p, uninit: false }], Vec::new())?;
                    inode.size = t.len() as u64;
                }
                NewKind::Dir => {
                    inode.links = 2;
                    inode.flags = FL_EXTENTS;
                    inode.block = Self::empty_extent_root();
                    let goal = fs.sb.group_first_block((ino - 1) / fs.sb.inodes_per_group);
                    let (p, _) = fs.alloc_blocks(goal, 1)?;
                    inode.blocks_512 = bs as u64 / 512;
                    fs.store_extents(&mut inode, vec![Ext { lblk: 0, len: 1, phys: p, uninit: false }], Vec::new())?;
                    inode.size = bs as u64;
                    let ft = if fs.filetype() { crate::dir::FT_DIR } else { 0 };
                    let mut b = fs.new_dir_block(&[(ino, b".", ft), (dir, b"..", ft)]);
                    fs.seal_dir_block(&inode, &mut b);
                    fs.tx_put(p, b);
                    parent.links += 1;
                }
            }
            fs.put_inode(&mut inode)?;
            fs.add_entry(&mut parent, name, ino, ft_of(type_bits))?;
            let now = fs.now();
            parent.mtime = now;
            parent.ctime = now;
            fs.put_inode(&mut parent)?;
            Ok(ino)
        })
    }

    /// Gives the existing non-directory inode `target` a second name `name`
    /// in `dir` (a hard link).
    pub fn link(&mut self, dir: u32, name: &str, target: u32) -> Result<()> {
        validate_name(name)?;
        self.op(|fs| {
            let mut parent = fs.dir_tx(dir)?;
            if parent.links == 0 {
                return Err(Error::NotFound);
            }
            if fs.find_entry(&parent, name).is_ok() {
                return Err(Error::AlreadyExists);
            }
            let mut inode = fs.tx_inode(target)?;
            if inode.is_dir() {
                return Err(Error::IsADirectory);
            }
            if inode.links == 0 {
                return Err(Error::NotFound);
            }
            if inode.links >= MAX_LINKS {
                return Err(Error::NoSpace);
            }
            inode.links += 1;
            inode.ctime = fs.now();
            fs.put_inode(&mut inode)?;
            fs.add_entry(&mut parent, name, target, ft_of(inode.mode))?;
            let now = fs.now();
            parent.mtime = now;
            parent.ctime = now;
            fs.put_inode(&mut parent)
        })
    }

    /// Frees an inode with no names left: its blocks, then the inode.
    fn destroy_inode(&mut self, ino: u32) -> Result<()> {
        let mut inode = self.tx_inode(ino)?;
        let is_dir = inode.is_dir();
        if inode.uses_extents() {
            self.free_from(&mut inode, 0)?;
        } else if !inode.is_fast_symlink(self.sb.block_size) {
            return Err(Error::Unsupported("freeing block-mapped files"));
        }
        if inode.file_acl() != 0 {
            return Err(Error::Unsupported("freeing inodes with extended attribute blocks"));
        }
        inode.links = 0;
        inode.size = 0;
        inode.dtime = self.now().0 as u32;
        self.put_inode(&mut inode)?;
        self.free_inode_bit(ino, is_dir)
    }

    /// Drops one name of `victim` (already removed from its directory).
    fn drop_link(&mut self, victim: u32) -> Result<()> {
        let mut v = self.tx_inode(victim)?;
        let now = self.now();
        v.ctime = now;
        let gone = if v.is_dir() {
            v.links = 0;
            true
        } else {
            v.links = v.links.saturating_sub(1);
            v.links == 0
        };
        if !gone {
            return self.put_inode(&mut v);
        }
        if self.open_counts.get(&victim).copied().unwrap_or(0) > 0 {
            // Still open: keep the data, remember it on the orphan list.
            v.dtime = le32(&self.sb.raw, 232);
            self.put_inode(&mut v)?;
            put32(&mut self.sb.raw, 232, victim);
            self.orphans.insert(victim, 1);
            return Ok(());
        }
        self.put_inode(&mut v)?;
        self.destroy_inode(victim)
    }

    /// Removes a non-directory entry.
    pub fn unlink(&mut self, dir: u32, name: &str) -> Result<()> {
        validate_name(name)?;
        self.op(|fs| {
            let mut d = fs.dir_tx(dir)?;
            let (lblk, off, victim, _) = fs.find_entry(&d, name)?;
            if fs.tx_inode(victim)?.is_dir() {
                return Err(Error::IsADirectory);
            }
            fs.remove_entry(&d, lblk, off)?;
            fs.drop_link(victim)?;
            let now = fs.now();
            d.mtime = now;
            d.ctime = now;
            fs.put_inode(&mut d)
        })
    }

    /// Removes an empty directory.
    pub fn rmdir(&mut self, dir: u32, name: &str) -> Result<()> {
        validate_name(name)?;
        self.op(|fs| {
            let mut d = fs.dir_tx(dir)?;
            let (lblk, off, victim, _) = fs.find_entry(&d, name)?;
            let v = fs.tx_inode(victim)?;
            if !v.is_dir() {
                return Err(Error::NotADirectory);
            }
            if !fs.dir_is_empty(&v)? {
                return Err(Error::DirectoryNotEmpty);
            }
            fs.remove_entry(&d, lblk, off)?;
            fs.drop_link(victim)?;
            d.links = d.links.saturating_sub(1).max(2);
            let now = fs.now();
            d.mtime = now;
            d.ctime = now;
            fs.put_inode(&mut d)
        })
    }

    /// Moves `sname` in `sdir` to `dname` in `ddir`, replacing a file or
    /// an empty directory there.
    pub fn rename(&mut self, sdir: u32, sname: &str, ddir: u32, dname: &str) -> Result<()> {
        validate_name(sname)?;
        validate_name(dname)?;
        self.op(|fs| {
            let s = fs.dir_tx(sdir)?;
            let (_, _, src, sft) = fs.find_entry(&s, sname)?;
            let src_is_dir = fs.tx_inode(src)?.is_dir();
            let d = fs.dir_tx(ddir)?;
            // A directory may not move below itself.
            if src_is_dir && sdir != ddir {
                let mut cur = ddir;
                for _ in 0..4096 {
                    if cur == src {
                        return Err(Error::InvalidInput("moving a directory into itself"));
                    }
                    if cur == ROOT_INO {
                        break;
                    }
                    let ci = fs.dir_tx(cur)?;
                    cur = fs.parent_of(&ci)?;
                }
            }
            if let Ok((dl, doff, victim, _)) = fs.find_entry(&d, dname) {
                if victim == src {
                    return Ok(());
                }
                let v = fs.tx_inode(victim)?;
                match (src_is_dir, v.is_dir()) {
                    (true, false) => return Err(Error::NotADirectory),
                    (false, true) => return Err(Error::IsADirectory),
                    (true, true) if !fs.dir_is_empty(&v)? => return Err(Error::DirectoryNotEmpty),
                    _ => {}
                }
                fs.remove_entry(&d, dl, doff)?;
                fs.drop_link(victim)?;
                if v.is_dir() {
                    let mut dd = fs.dir_tx(ddir)?;
                    dd.links = dd.links.saturating_sub(1).max(2);
                    fs.put_inode(&mut dd)?;
                }
            }
            let s = fs.dir_tx(sdir)?;
            let (sl, so, _, _) = fs.find_entry(&s, sname)?;
            fs.remove_entry(&s, sl, so)?;
            let mut d = fs.dir_tx(ddir)?;
            if src_is_dir && sdir != ddir && d.links >= MAX_LINKS {
                return Err(Error::NoSpace);
            }
            fs.add_entry(&mut d, dname, src, sft)?;
            let now = fs.now();
            d.mtime = now;
            d.ctime = now;
            if src_is_dir && sdir != ddir {
                let si = fs.tx_inode(src)?;
                fs.set_dotdot(&si, ddir)?;
                d.links += 1;
            }
            fs.put_inode(&mut d)?;
            if sdir != ddir {
                let mut s = fs.dir_tx(sdir)?;
                if src_is_dir {
                    s.links = s.links.saturating_sub(1).max(2);
                }
                s.mtime = now;
                s.ctime = now;
                fs.put_inode(&mut s)?;
            }
            let mut moved = fs.tx_inode(src)?;
            moved.ctime = now;
            fs.put_inode(&mut moved)
        })
    }
    pub fn set_mode(&mut self, ino: u32, perm: u16) -> Result<()> {
        self.op(|fs| {
            let mut i = fs.tx_inode(ino)?;
            if i.is_symlink() {
                return Err(Error::InvalidInput("symbolic links have no mode"));
            }
            i.mode = (i.mode & S_IFMT) | (perm & 0o7777);
            i.ctime = fs.now();
            fs.put_inode(&mut i)
        })
    }

    // ---- open files and orphans ----------------------------------------------------

    /// Records an open handle of `ino`.
    pub fn open(&mut self, ino: u32) {
        *self.open_counts.entry(ino).or_default() += 1;
    }

    /// Drops an open handle; frees the inode if it was removed while open.
    pub fn release(&mut self, ino: u32) -> Result<()> {
        if let Some(n) = self.open_counts.get_mut(&ino) {
            *n -= 1;
            if *n == 0 {
                self.open_counts.remove(&ino);
            }
        }
        if self.orphans.contains_key(&ino) && !self.open_counts.contains_key(&ino) && !self.read_only {
            self.release_orphan(ino)?;
        }
        Ok(())
    }

    fn release_orphan(&mut self, ino: u32) -> Result<()> {
        self.op(|fs| {
            // Unlink `ino` from the on-disk orphan chain.
            let mut prev: Option<u32> = None;
            let mut cur = le32(&fs.sb.raw, 232);
            let mut steps = 0;
            while cur != 0 && cur != ino {
                steps += 1;
                if steps > fs.sb.inodes_count {
                    return Err(Error::Corrupt("orphan list loops"));
                }
                prev = Some(cur);
                cur = fs.tx_inode(cur)?.dtime;
            }
            let me = fs.tx_inode(ino)?;
            if cur == ino {
                match prev {
                    None => put32(&mut fs.sb.raw, 232, me.dtime),
                    Some(p) => {
                        let mut pi = fs.tx_inode(p)?;
                        pi.dtime = me.dtime;
                        fs.put_inode(&mut pi)?;
                    }
                }
            }
            fs.orphans.remove(&ino);
            fs.destroy_inode(ino)
        })
    }

    /// Frees inodes left on the orphan list by a previous session.
    fn process_orphans(&mut self) -> Result<()> {
        let mut cur = le32(&self.sb.raw, 232);
        let mut n = 0;
        while cur != 0 {
            n += 1;
            if n > self.sb.inodes_count {
                return Err(Error::Corrupt("orphan list loops"));
            }
            let next = self.inode(cur)?.dtime;
            let ino = cur;
            self.op(|fs| {
                put32(&mut fs.sb.raw, 232, next);
                let i = fs.tx_inode(ino)?;
                if i.links == 0 {
                    fs.destroy_inode(ino)?;
                    fs.orphans_freed += 1;
                }
                Ok(())
            })?;
            cur = next;
        }
        Ok(())
    }

    fn block_in_use(&mut self, b: u64) -> Result<bool> {
        let g = self.group_of_block(b);
        let gd = self.groups[g as usize];
        if gd.flags & BG_BLOCK_UNINIT != 0 {
            return Ok(false);
        }
        let bm = self.read_block(gd.block_bitmap)?;
        let i = (b - self.sb.group_first_block(g)) as usize;
        Ok(bm[i / 8] & (1 << (i % 8)) != 0)
    }

    /// Whether file data or metadata changes are held in memory, not yet
    /// written to the device (see [`Ext4::sync`]).
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty() || !self.tx.blocks.is_empty() || !self.tx.dirty_groups.is_empty() || !self.tx.freed.is_empty()
    }

    /// Writes the staged file data and commits the pending metadata, then
    /// flushes the device.
    pub fn sync(&mut self) -> Result<()> {
        self.flush_pending()?;
        self.dev.flush()
    }

    /// Consistency check: group and superblock counters against the
    /// bitmaps, bitmap checksums, and a walk of the directory tree that
    /// checks link counts, allocation bits and that no block is used twice.
    pub fn check(&mut self) -> Result<String> {
        // Pending file writes keep metadata in memory; journal it first so
        // the checks see either a committed volume or nothing new.
        self.flush_pending()?;
        let ipg = self.sb.inodes_per_group;
        let mut free_b = 0u64;
        let mut free_i = 0u64;

        for g in 0..self.sb.group_count() {
            let gd = self.groups[g as usize];
            let len = self.group_len(g);
            if gd.flags & BG_BLOCK_UNINIT == 0 {
                let bm = self.read_block(gd.block_bitmap)?;
                if self.sb.metadata_csum() {
                    let c = crc::crc32c(self.csum_seed, &bm[..self.sb.blocks_per_group as usize / 8]);
                    let stored = if self.sb.desc_size >= 64 { gd.block_bitmap_csum } else { gd.block_bitmap_csum & 0xFFFF };
                    let cmp = if self.sb.desc_size >= 64 { c } else { c & 0xFFFF };
                    if cmp != stored {
                        return Err(Error::Corrupt("block bitmap checksum"));
                    }
                }
                let free = (0..len as usize).filter(|&i| bm[i / 8] & (1 << (i % 8)) == 0).count() as u32;
                if free != gd.free_blocks {
                    return Err(Error::Corrupt("group free block count"));
                }
            }
            free_b += gd.free_blocks as u64;
            if gd.flags & BG_INODE_UNINIT == 0 {
                let bm = self.read_block(gd.inode_bitmap)?;
                let free = (0..ipg as usize).filter(|&i| bm[i / 8] & (1 << (i % 8)) == 0).count() as u32;
                if free != gd.free_inodes {
                    return Err(Error::Corrupt("group free inode count"));
                }
            } else if gd.free_inodes != ipg {
                return Err(Error::Corrupt("uninitialised inode group with used inodes"));
            }
            free_i += gd.free_inodes as u64;
        }
        if (free_b, free_i as u32) != self.free_counts() {
            return Err(Error::Corrupt("superblock free counts"));
        }
        // Directory tree walk.
        let mut links: BTreeMap<u32, u32> = BTreeMap::new();
        let mut seen_blocks: BTreeSet<u64> = BTreeSet::new();
        let mut stack = vec![(ROOT_INO, ROOT_INO)];
        let mut visited_dirs = BTreeSet::new();
        let mut files = 0u32;
        while let Some((dir, parent)) = stack.pop() {
            if !visited_dirs.insert(dir) {
                return Err(Error::Corrupt("directory reachable twice"));
            }
            let d = self.inode(dir)?;
            let filetype = self.filetype();
            for lblk in 0..self.dir_blocks(&d)? {
                let (_, b) = self.dir_block(&d, lblk)?;
                for e in entries(&b, filetype, self.sb.inodes_count)? {
                    if e.ino == 0 {
                        continue;
                    }
                    *links.entry(e.ino).or_default() += 1;
                    if e.name == b"." && e.ino != dir || e.name == b".." && e.ino != parent {
                        return Err(Error::Corrupt("wrong . or .. entry"));
                    }
                    if e.name == b"." || e.name == b".." {
                        continue;
                    }
                    let child = self.inode(e.ino)?;
                    if child.is_dir() {
                        stack.push((e.ino, dir));
                    } else if links[&e.ino] == 1 {
                        files += 1;
                    }
                }
            }
        }
        for (&ino, &count) in &links {
            let i = self.inode(ino)?;
            let g = (ino - 1) / ipg;
            let gd = self.groups[g as usize];
            let bm = if gd.flags & BG_INODE_UNINIT != 0 { vec![0u8; 1] } else { self.read_block(gd.inode_bitmap)? };
            let idx = ((ino - 1) % ipg) as usize;
            if gd.flags & BG_INODE_UNINIT != 0 || bm[idx / 8] & (1 << (idx % 8)) == 0 {
                return Err(Error::Corrupt("reachable inode is marked free"));
            }
            let ok = i.links as u32 == count || i.is_dir() && i.links == 1 && count > MAX_LINKS as u32;
            if !ok {
                return Err(Error::Corrupt("link count"));
            }
            if i.uses_extents() {
                let (list, tree) = self.extents(&i)?;
                for b in tree.iter().copied().chain(list.iter().flat_map(|e| e.phys..e.phys + e.len)) {
                    if !seen_blocks.insert(b) {
                        return Err(Error::Corrupt("block used twice"));
                    }
                    if !self.block_in_use(b)? {
                        return Err(Error::Corrupt("block in use is marked free"));
                    }
                }
            }
        }
        Ok(alloc::format!(
            "{} directories, {} files, {} blocks in files, {} free blocks, {} free inodes",
            visited_dirs.len(),
            files,
            seen_blocks.len(),
            free_b,
            free_i
        ))
    }
}

