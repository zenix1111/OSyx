//! exFAT driver: mounts volumes made by Windows, macOS and Linux (USB
//! sticks and SD cards above 32 GiB are exFAT), reads and writes them, and
//! can format and check one.
//!
//! Layout used (Microsoft exFAT specification): a boot region of 12 sectors
//! with a checksum (and a backup), the FAT, and the cluster heap whose root
//! directory holds the allocation bitmap, the up-case table and the volume
//! label. A file or directory is a *directory entry set*: a file entry
//! (`0x85`), a stream extension (`0xC0`) and name entries (`0xC1`), guarded
//! by a 16-bit checksum.
//!
//! Choices of this driver:
//! * Files it writes always use a FAT chain; files with the `NoFatChain`
//!   flag (contiguous, written by other systems) are read directly and are
//!   converted to a chain before they grow or shrink.
//! * The allocation bitmap and the up-case table live in memory; the bitmap
//!   and the FAT cache are written back by [`FileSystem::flush`], directory
//!   entries immediately.
//! * `VolumeDirty` is set before the first change and cleared by `flush`,
//!   unless the volume was already dirty when mounted.
//! * `ValidDataLength` is honoured: bytes beyond it read as zero.

#![no_std]

extern crate alloc;

mod check;
mod dir;
mod format;
mod ops;
mod time;

pub use check::CheckReport;
pub use dir::{entry_set_checksum, DirEntryInfo, DirRef, EntryPos, FileRef};
pub use format::format;
pub use ops::{Metadata, OpenOptions};
pub use time::{dos_from_unix, unix_from_dos};

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

pub const SECTOR_SIZE: usize = 512;

pub const ATTR_READ_ONLY: u16 = 0x01;
pub const ATTR_HIDDEN: u16 = 0x02;
pub const ATTR_SYSTEM: u16 = 0x04;
pub const ATTR_DIRECTORY: u16 = 0x10;
pub const ATTR_ARCHIVE: u16 = 0x20;

/// Longest file name, in UTF-16 units.
pub const MAX_NAME_UNITS: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    /// The block device reported an error.
    Io,
    NotFound,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    /// Empty, too long, reserved (`.`/`..`) or containing forbidden characters.
    InvalidName,
    NoSpace,
    /// On-disk structures are inconsistent.
    Corrupt(&'static str),
    /// Valid but not supported by this driver.
    Unsupported(&'static str),
    InvalidInput(&'static str),
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::Io => f.write_str("I/O error"),
            FsError::NotFound => f.write_str("not found"),
            FsError::AlreadyExists => f.write_str("already exists"),
            FsError::NotADirectory => f.write_str("not a directory"),
            FsError::IsADirectory => f.write_str("is a directory"),
            FsError::DirectoryNotEmpty => f.write_str("directory not empty"),
            FsError::InvalidName => f.write_str("invalid file name"),
            FsError::NoSpace => f.write_str("no space left on volume"),
            FsError::Corrupt(w) => write!(f, "corrupted volume: {w}"),
            FsError::Unsupported(w) => write!(f, "unsupported: {w}"),
            FsError::InvalidInput(w) => write!(f, "invalid input: {w}"),
        }
    }
}

pub type Result<T> = core::result::Result<T, FsError>;

/// A disk of 512-byte sectors.
pub trait BlockDevice {
    fn sector_count(&self) -> u64;
    /// Reads `buf.len() / 512` sectors starting at `lba`.
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<()>;
    /// Writes `buf.len() / 512` sectors starting at `lba`.
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<()>;
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// An in-memory disk image (used by tests and host tools).
impl BlockDevice for Vec<u8> {
    fn sector_count(&self) -> u64 {
        (self.len() / SECTOR_SIZE) as u64
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(lba).ok().and_then(|l| l.checked_mul(SECTOR_SIZE)).ok_or(FsError::Io)?;
        let end = start.checked_add(buf.len()).ok_or(FsError::Io)?;
        let src = self.get(start..end).ok_or(FsError::Io)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        let start = usize::try_from(lba).ok().and_then(|l| l.checked_mul(SECTOR_SIZE)).ok_or(FsError::Io)?;
        let end = start.checked_add(buf.len()).ok_or(FsError::Io)?;
        let dst = self.get_mut(start..end).ok_or(FsError::Io)?;
        dst.copy_from_slice(buf);
        Ok(())
    }
}

pub(crate) fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

pub(crate) fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub(crate) fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7]])
}

pub(crate) const FAT_EOC: u32 = 0xFFFF_FFFF;
const FAT_CACHE_SECTORS: usize = 8;
const MAX_CLUSTER_SHIFT: u32 = 22;
const MAX_BITMAP_BYTES: u64 = 32 << 20;
const MAX_UPCASE_BYTES: u64 = 256 << 10;
const VOLUME_DIRTY: u16 = 0x0002;
/// 1980-01-01 00:00:00, the clock before [`FileSystem::set_time`].
const DEFAULT_TIME: u32 = 0x0021_0000;

/// Layout of a mounted volume (from the boot sector).
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub bytes_per_sector_shift: u32,
    pub sectors_per_cluster_shift: u32,
    /// First FAT, in volume sectors.
    pub fat_offset: u32,
    pub fat_length: u32,
    pub num_fats: u32,
    /// Cluster heap, in volume sectors.
    pub heap_offset: u32,
    pub cluster_count: u32,
    pub root_cluster: u32,
    pub volume_length: u64,
    pub serial: u32,
    pub active_fat: u32,
}

impl Geometry {
    pub fn cluster_shift(&self) -> u32 {
        self.bytes_per_sector_shift + self.sectors_per_cluster_shift
    }

    pub fn cluster_bytes(&self) -> u64 {
        1 << self.cluster_shift()
    }

    pub(crate) fn is_valid_cluster(&self, c: u32) -> bool {
        c >= 2 && (c as u64) < self.cluster_count as u64 + 2
    }
}

struct FatSlot {
    lba: u64,
    data: [u8; SECTOR_SIZE],
    dirty: bool,
}

pub struct FileSystem<D: BlockDevice> {
    pub(crate) dev: D,
    pub(crate) geo: Geometry,
    label: Vec<u16>,
    fat_cache: Vec<FatSlot>,
    /// The allocation bitmap, bit `c - 2` for cluster `c`.
    bitmap: Vec<u8>,
    bitmap_first: u32,
    bitmap_dirty: Option<(usize, usize)>,
    pub(crate) upcase_first: u32,
    pub(crate) upcase_len: u64,
    free_clusters: u32,
    next_free: u32,
    pub(crate) upcase: Vec<u16>,
    flags: u16,
    flags_dirty: bool,
    /// The volume was dirty when it was mounted: it is left that way.
    was_dirty: bool,
    suspect: bool,
    now: u32,
}

impl<D: BlockDevice> FileSystem<D> {
    /// Mounts the exFAT volume on `dev` (no partition table: the volume
    /// starts at sector 0).
    pub fn mount(mut dev: D) -> Result<Self> {
        let mut vbr = [0u8; SECTOR_SIZE];
        dev.read_sectors(0, &mut vbr)?;
        if &vbr[3..11] != b"EXFAT   " {
            return Err(FsError::Unsupported("not an exFAT volume"));
        }
        if vbr[11..64].iter().any(|&b| b != 0) || vbr[510] != 0x55 || vbr[511] != 0xAA {
            return Err(FsError::Corrupt("boot sector"));
        }
        if vbr[105] != 1 {
            return Err(FsError::Unsupported("exFAT revision"));
        }
        let bps = vbr[108] as u32;
        let spc = vbr[109] as u32;
        if !(9..=12).contains(&bps) || bps + spc > MAX_CLUSTER_SHIFT {
            return Err(FsError::Unsupported("sector or cluster size"));
        }
        let num_fats = vbr[110] as u32;
        if !(1..=2).contains(&num_fats) {
            return Err(FsError::Corrupt("number of FATs"));
        }
        let flags = le16(&vbr, 106);
        let geo = Geometry {
            bytes_per_sector_shift: bps,
            sectors_per_cluster_shift: spc,
            fat_offset: le32(&vbr, 80),
            fat_length: le32(&vbr, 84),
            num_fats,
            heap_offset: le32(&vbr, 88),
            cluster_count: le32(&vbr, 92),
            root_cluster: le32(&vbr, 96),
            volume_length: le64(&vbr, 72),
            serial: le32(&vbr, 100),
            active_fat: if num_fats == 2 { (flags & 1) as u32 } else { 0 },
        };
        let dev_bytes = dev.sector_count() * SECTOR_SIZE as u64;
        if geo.volume_length << bps > dev_bytes || geo.volume_length < 24 {
            return Err(FsError::Corrupt("volume is larger than the device"));
        }
        if geo.cluster_count == 0 || geo.cluster_count > 0xFFFF_FFF5 || !geo.is_valid_cluster(geo.root_cluster) {
            return Err(FsError::Corrupt("cluster count or root directory"));
        }
        let fat_end = geo.fat_offset as u64 + geo.fat_length as u64 * num_fats as u64;
        let heap_end = geo.heap_offset as u64 + ((geo.cluster_count as u64) << spc);
        if geo.fat_offset < 24
            || fat_end > geo.heap_offset as u64
            || heap_end > geo.volume_length
            || (geo.fat_length as u64) << bps < (geo.cluster_count as u64 + 2) * 4
        {
            return Err(FsError::Corrupt("FAT or heap placement"));
        }
        let mut fs = FileSystem {
            dev,
            geo,
            label: Vec::new(),
            fat_cache: Vec::new(),
            bitmap: Vec::new(),
            bitmap_first: 0,
            bitmap_dirty: None,
            upcase_first: 0,
            upcase_len: 0,
            free_clusters: 0,
            next_free: 2,
            upcase: Vec::new(),
            flags,
            flags_dirty: false,
            was_dirty: flags & VOLUME_DIRTY != 0,
            suspect: false,
            now: DEFAULT_TIME,
        };
        fs.suspect = !fs.boot_checksum_ok()?;
        fs.load_system_entries()?;
        Ok(fs)
    }

    fn boot_checksum_ok(&mut self) -> Result<bool> {
        let bps = 1usize << self.geo.bytes_per_sector_shift;
        let mut region = vec![0u8; 12 * bps];
        self.read_at(0, &mut region)?;
        let sum = boot_checksum(&region[..11 * bps]);
        Ok((0..bps / 4).all(|i| le32(&region[11 * bps..], i * 4) == sum))
    }

    /// The bitmap, up-case table and label entries of the root directory.
    fn load_system_entries(&mut self) -> Result<()> {
        let root = DirRef { first: self.geo.root_cluster, nofat: false, len: 0, entry: None };
        let bytes = self.load_dir(&root)?;
        let mut bitmap = None;
        let mut upcase = None;
        for e in bytes.chunks_exact(32) {
            match e[0] {
                0x00 => break,
                0x81 if bitmap.is_none() && e[1] & 1 == 0 => bitmap = Some((le32(e, 20), le64(e, 24))),
                0x82 if upcase.is_none() => upcase = Some((le32(e, 20), le64(e, 24), le32(e, 4))),
                0x83 => {
                    let n = (e[1] as usize).min(11);
                    self.label = (0..n).map(|i| le16(e, 2 + i * 2)).collect();
                }
                _ => {}
            }
        }
        let (bfirst, blen) = bitmap.ok_or(FsError::Corrupt("no allocation bitmap"))?;
        let need = (self.geo.cluster_count as u64).div_ceil(8);
        if blen < need || blen > MAX_BITMAP_BYTES || !self.geo.is_valid_cluster(bfirst) {
            return Err(FsError::Corrupt("allocation bitmap size"));
        }
        let mut raw = vec![0u8; need as usize];
        self.read_extent(bfirst, false, blen, 0, &mut raw)?;
        self.bitmap = raw;
        self.bitmap_first = bfirst;
        let used: u32 = (0..self.geo.cluster_count).filter(|&i| self.bitmap[(i / 8) as usize] >> (i % 8) & 1 != 0).count() as u32;
        self.free_clusters = self.geo.cluster_count - used;

        self.upcase = default_upcase();
        if let Some((first, len, checksum)) = upcase {
            if len <= MAX_UPCASE_BYTES && len >= 2 && self.geo.is_valid_cluster(first) {
                self.upcase_first = first;
                self.upcase_len = len;
                let mut raw = vec![0u8; len as usize];
                self.read_extent(first, false, len, 0, &mut raw)?;
                if table_checksum(&raw) == checksum {
                    self.upcase = parse_upcase(&raw);
                } else {
                    self.suspect = true;
                }
            }
        }
        Ok(())
    }

    /// The underlying device.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geo
    }

    /// Volume label, from the label entry of the root directory.
    pub fn label(&self) -> alloc::string::String {
        alloc::string::String::from_utf16_lossy(&self.label)
    }

    pub fn free_clusters(&self) -> u32 {
        self.free_clusters
    }

    pub fn free_bytes(&self) -> u64 {
        self.free_clusters as u64 * self.geo.cluster_bytes()
    }

    /// True if the volume looked damaged at mount time (a wrong boot
    /// checksum or up-case table checksum): the caller should not write.
    pub fn is_suspect(&self) -> bool {
        self.suspect
    }

    /// True if the volume was not cleanly unmounted by its last user.
    pub fn was_dirty(&self) -> bool {
        self.was_dirty
    }

    /// Sets the clock used for new and changed entries (seconds since the
    /// Unix epoch, UTC).
    pub fn set_time(&mut self, unix_secs: i64) {
        self.now = dos_from_unix(unix_secs);
    }

    pub(crate) fn now(&self) -> u32 {
        self.now
    }

    // ---- device access --------------------------------------------------------------------

    pub(crate) fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let first = off / SECTOR_SIZE as u64;
        let skip = (off % SECTOR_SIZE as u64) as usize;
        if skip == 0 && buf.len().is_multiple_of(SECTOR_SIZE) {
            return self.dev.read_sectors(first, buf);
        }
        let mut tmp = vec![0u8; (skip + buf.len()).div_ceil(SECTOR_SIZE) * SECTOR_SIZE];
        self.dev.read_sectors(first, &mut tmp)?;
        buf.copy_from_slice(&tmp[skip..skip + buf.len()]);
        Ok(())
    }

    pub(crate) fn write_at(&mut self, off: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.mark_dirty()?;
        let first = off / SECTOR_SIZE as u64;
        let skip = (off % SECTOR_SIZE as u64) as usize;
        if skip == 0 && data.len().is_multiple_of(SECTOR_SIZE) {
            return self.dev.write_sectors(first, data);
        }
        let mut tmp = vec![0u8; (skip + data.len()).div_ceil(SECTOR_SIZE) * SECTOR_SIZE];
        self.dev.read_sectors(first, &mut tmp)?;
        tmp[skip..skip + data.len()].copy_from_slice(data);
        self.dev.write_sectors(first, &tmp)
    }

    /// Sets `VolumeDirty` on the medium before the first change.
    fn mark_dirty(&mut self) -> Result<()> {
        if self.flags_dirty || self.was_dirty {
            return Ok(());
        }
        self.flags_dirty = true;
        self.flags |= VOLUME_DIRTY;
        self.write_flags()
    }

    fn write_flags(&mut self) -> Result<()> {
        let mut vbr = [0u8; SECTOR_SIZE];
        self.dev.read_sectors(0, &mut vbr)?;
        vbr[106..108].copy_from_slice(&self.flags.to_le_bytes());
        self.dev.write_sectors(0, &vbr)
    }

    pub(crate) fn cluster_off(&self, c: u32) -> u64 {
        ((self.geo.heap_offset as u64) << self.geo.bytes_per_sector_shift) + ((c as u64 - 2) << self.geo.cluster_shift())
    }

    // ---- FAT ------------------------------------------------------------------------------

    fn fat_base(&self) -> u64 {
        ((self.geo.fat_offset + self.geo.active_fat * self.geo.fat_length) as u64) << self.geo.bytes_per_sector_shift
    }

    fn fat_slot(&mut self, lba: u64) -> Result<usize> {
        if let Some(i) = self.fat_cache.iter().position(|s| s.lba == lba) {
            return Ok(i);
        }
        let mut data = [0u8; SECTOR_SIZE];
        self.dev.read_sectors(lba, &mut data)?;
        if self.fat_cache.len() >= FAT_CACHE_SECTORS {
            let old = self.fat_cache.remove(0);
            if old.dirty {
                self.write_fat_slot(&old)?;
            }
        }
        self.fat_cache.push(FatSlot { lba, data, dirty: false });
        Ok(self.fat_cache.len() - 1)
    }

    fn write_fat_slot(&mut self, slot: &FatSlot) -> Result<()> {
        self.mark_dirty()?;
        self.dev.write_sectors(slot.lba, &slot.data)?;
        if self.geo.num_fats == 2 {
            // Without TexFAT both copies are kept equal.
            let delta = (self.geo.fat_length as u64) << self.geo.bytes_per_sector_shift;
            let sectors = delta / SECTOR_SIZE as u64;
            let other = if self.geo.active_fat == 0 { slot.lba + sectors } else { slot.lba - sectors };
            self.dev.write_sectors(other, &slot.data)?;
        }
        Ok(())
    }

    pub(crate) fn fat_get(&mut self, c: u32) -> Result<u32> {
        let off = self.fat_base() + c as u64 * 4;
        let i = self.fat_slot(off / SECTOR_SIZE as u64)?;
        Ok(le32(&self.fat_cache[i].data, (off % SECTOR_SIZE as u64) as usize))
    }

    pub(crate) fn fat_set(&mut self, c: u32, v: u32) -> Result<()> {
        let off = self.fat_base() + c as u64 * 4;
        let i = self.fat_slot(off / SECTOR_SIZE as u64)?;
        let o = (off % SECTOR_SIZE as u64) as usize;
        self.fat_cache[i].data[o..o + 4].copy_from_slice(&v.to_le_bytes());
        self.fat_cache[i].dirty = true;
        Ok(())
    }

    /// The cluster after `c` in a FAT chain; an error at the end or for a
    /// value outside the heap.
    pub(crate) fn fat_next(&mut self, c: u32) -> Result<u32> {
        let n = self.fat_get(c)?;
        if self.geo.is_valid_cluster(n) {
            Ok(n)
        } else {
            Err(FsError::Corrupt("FAT chain ends early or leaves the heap"))
        }
    }

    // ---- allocation bitmap ----------------------------------------------------------------

    pub(crate) fn is_allocated(&self, c: u32) -> bool {
        let i = (c - 2) as usize;
        self.bitmap[i / 8] >> (i % 8) & 1 != 0
    }

    fn set_allocated(&mut self, c: u32, on: bool) {
        let i = (c - 2) as usize;
        if on {
            self.bitmap[i / 8] |= 1 << (i % 8);
        } else {
            self.bitmap[i / 8] &= !(1 << (i % 8));
        }
        self.bitmap_dirty = Some(match self.bitmap_dirty {
            Some((a, b)) => (a.min(i / 8), b.max(i / 8)),
            None => (i / 8, i / 8),
        });
    }

    /// Takes one free cluster (searching from the last allocation).
    pub(crate) fn alloc_cluster(&mut self) -> Result<u32> {
        if self.free_clusters == 0 {
            return Err(FsError::NoSpace);
        }
        let count = self.geo.cluster_count;
        let start = if self.next_free >= 2 && self.next_free < count + 2 { self.next_free } else { 2 };
        let mut c = start;
        for _ in 0..count {
            if !self.is_allocated(c) {
                self.set_allocated(c, true);
                self.free_clusters -= 1;
                self.next_free = if c + 1 < count + 2 { c + 1 } else { 2 };
                return Ok(c);
            }
            c = if c + 1 < count + 2 { c + 1 } else { 2 };
        }
        Err(FsError::NoSpace)
    }

    pub(crate) fn free_cluster(&mut self, c: u32) {
        if self.geo.is_valid_cluster(c) && self.is_allocated(c) {
            self.set_allocated(c, false);
            self.free_clusters += 1;
            if c < self.next_free {
                self.next_free = c;
            }
        }
    }

    /// Frees `count` clusters of a chain (or contiguous run) starting at
    /// `first`, clearing their FAT entries for a chain.
    pub(crate) fn free_run(&mut self, first: u32, nofat: bool, count: u64) -> Result<()> {
        let mut c = first;
        for i in 0..count {
            if !self.geo.is_valid_cluster(c) {
                return Err(FsError::Corrupt("chain references an invalid cluster"));
            }
            let next = if nofat {
                c + 1
            } else {
                let n = self.fat_get(c)?;
                self.fat_set(c, 0)?;
                n
            };
            self.free_cluster(c);
            if i + 1 < count {
                c = next;
            }
        }
        Ok(())
    }

    // ---- flushing -------------------------------------------------------------------------

    /// Writes the FAT cache and the allocation bitmap; the volume stays
    /// marked dirty and the device is not flushed. For use after each change;
    /// [`flush`](Self::flush) finishes the job when things are quiet.
    pub fn commit(&mut self) -> Result<()> {
        for i in 0..self.fat_cache.len() {
            if self.fat_cache[i].dirty {
                let slot = FatSlot { lba: self.fat_cache[i].lba, data: self.fat_cache[i].data, dirty: true };
                self.write_fat_slot(&slot)?;
                self.fat_cache[i].dirty = false;
            }
        }
        if let Some((a, b)) = self.bitmap_dirty.take() {
            let data = self.bitmap[a..=b].to_vec();
            self.write_extent(self.bitmap_first, false, (self.bitmap.len() as u64).max(b as u64 + 1), a as u64, &data)?;
        }
        Ok(())
    }

    /// [`commit`](Self::commit), then marks the volume clean and flushes the
    /// device.
    pub fn flush(&mut self) -> Result<()> {
        self.commit()?;
        if self.flags_dirty {
            self.flags &= !VOLUME_DIRTY;
            self.flags_dirty = false;
            self.write_flags()?;
        }
        self.dev.flush()
    }

    /// Flushes and returns the device.
    pub fn unmount(mut self) -> Result<D> {
        self.flush()?;
        Ok(self.dev)
    }

    // ---- cluster chains -------------------------------------------------------------------

    /// The `idx`-th cluster of an extent. `cursor` remembers the last
    /// position so that sequential access does not walk the chain again.
    pub(crate) fn cluster_for(&mut self, first: u32, nofat: bool, idx: u32, cursor: &mut Cursor) -> Result<u32> {
        if !self.geo.is_valid_cluster(first) {
            return Err(FsError::Corrupt("extent starts outside the heap"));
        }
        if nofat {
            let c = first as u64 + idx as u64;
            return if self.geo.is_valid_cluster(c as u32) && c < self.geo.cluster_count as u64 + 2 {
                Ok(c as u32)
            } else {
                Err(FsError::Corrupt("contiguous extent leaves the heap"))
            };
        }
        let (mut i, mut c) = if cursor.valid && cursor.first == first && cursor.idx <= idx { (cursor.idx, cursor.cluster) } else { (0, first) };
        while i < idx {
            c = self.fat_next(c)?;
            i += 1;
        }
        *cursor = Cursor { valid: true, first, idx, cluster: c };
        Ok(c)
    }

    /// Device byte ranges covering `len` bytes at `off` of an extent.
    pub(crate) fn segments(&mut self, first: u32, nofat: bool, off: u64, len: usize, cursor: &mut Cursor) -> Result<Vec<(u64, usize)>> {
        let shift = self.geo.cluster_shift();
        let cb = 1u64 << shift;
        let mut out: Vec<(u64, usize)> = Vec::new();
        let mut pos = off;
        let end = off + len as u64;
        while pos < end {
            let idx = (pos >> shift) as u32;
            let c = self.cluster_for(first, nofat, idx, cursor)?;
            let in_off = pos & (cb - 1);
            let n = (cb - in_off).min(end - pos);
            let dev = self.cluster_off(c) + in_off;
            match out.last_mut() {
                Some(last) if last.0 + last.1 as u64 == dev => last.1 += n as usize,
                _ => out.push((dev, n as usize)),
            }
            pos += n;
        }
        Ok(out)
    }

    /// Reads from an extent of `size` bytes. Bytes at or past `size` are
    /// an error; the caller clamps.
    pub(crate) fn read_extent(&mut self, first: u32, nofat: bool, size: u64, off: u64, buf: &mut [u8]) -> Result<()> {
        if off + buf.len() as u64 > size {
            return Err(FsError::InvalidInput("read beyond the extent"));
        }
        let mut cursor = Cursor::default();
        let mut done = 0;
        for (dev, n) in self.segments(first, nofat, off, buf.len(), &mut cursor)? {
            self.read_at(dev, &mut buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }

    /// Writes into the allocated part of an extent.
    pub(crate) fn write_extent(&mut self, first: u32, nofat: bool, size: u64, off: u64, data: &[u8]) -> Result<()> {
        if off + data.len() as u64 > size {
            return Err(FsError::InvalidInput("write beyond the extent"));
        }
        let mut cursor = Cursor::default();
        let mut done = 0;
        for (dev, n) in self.segments(first, nofat, off, data.len(), &mut cursor)? {
            self.write_at(dev, &data[done..done + n])?;
            done += n;
        }
        Ok(())
    }
}

/// Position in a cluster chain, kept between calls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub(crate) valid: bool,
    pub(crate) first: u32,
    pub(crate) idx: u32,
    pub(crate) cluster: u32,
}

/// The boot region checksum (specification 3.1.1): sectors 0..=10, without
/// `VolumeFlags` and `PercentInUse`.
pub fn boot_checksum(region: &[u8]) -> u32 {
    let mut sum = 0u32;
    for (i, &b) in region.iter().enumerate() {
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        sum = sum.rotate_right(1).wrapping_add(b as u32);
    }
    sum
}

/// The up-case table checksum (specification 7.2.2).
pub fn table_checksum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    for &b in data {
        sum = sum.rotate_right(1).wrapping_add(b as u32);
    }
    sum
}

/// The up-case mapping this driver writes: ASCII, Latin-1, Latin Extended-A,
/// Greek and Cyrillic letters; everything else maps to itself.
pub(crate) fn default_upcase() -> Vec<u16> {
    let mut t: Vec<u16> = (0..0x460u16).collect();
    for c in b'a'..=b'z' {
        t[c as usize] = c as u16 - 32;
    }
    for c in 0xE0..=0xFEu16 {
        if c != 0xF7 {
            t[c as usize] = c - 32;
        }
    }
    t[0xFF] = 0x178;
    // Latin Extended-A: pairs, even = upper (odd = upper in 0x139..=0x148 and 0x179..=0x17E).
    for c in 0x100..=0x17Fu16 {
        let odd_upper = (0x139..=0x148).contains(&c) || (0x179..=0x17E).contains(&c);
        let lower = if odd_upper { c % 2 == 0 } else { c % 2 == 1 };
        let skip = matches!(c, 0x138 | 0x149 | 0x178 | 0x17F);
        if lower && !skip {
            t[c as usize] = c - 1;
        }
    }
    t[0x131] = 0x49;
    t[0x17F] = 0x53;
    for c in 0x3B1..=0x3C9u16 {
        t[c as usize] = c - 32;
    }
    t[0x3C2] = 0x3A3;
    for c in 0x430..=0x44Fu16 {
        t[c as usize] = c - 32;
    }
    for c in 0x450..=0x45Fu16 {
        t[c as usize] = c - 80;
    }
    t
}

/// Expands a stored up-case table (`0xFFFF n` skips `n` identity entries).
pub(crate) fn parse_upcase(raw: &[u8]) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    let mut i = 0;
    while i + 1 < raw.len() && out.len() < 0x10000 {
        let v = le16(raw, i);
        i += 2;
        if v == 0xFFFF && i + 2 <= raw.len() {
            let n = le16(raw, i) as usize;
            i += 2;
            for _ in 0..n {
                if out.len() >= 0x10000 {
                    break;
                }
                out.push(out.len() as u16);
            }
        } else {
            out.push(v);
        }
    }
    out
}
