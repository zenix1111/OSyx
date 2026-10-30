//! FAT32 file system driver, written from Microsoft's published FAT
//! specification ("FAT: General Overview of On-Disk Format").
//!
//! * `no_std` + `alloc`; works on any [`BlockDevice`] with 512-byte sectors
//!   (the kernel's virtio-blk disks, or a `Vec<u8>` image on the host).
//! * Reads and writes: files, directories, long file names (VFAT LFN with
//!   checksums, Windows NT lower-case flags for short names), rename,
//!   truncate, sparse extension with zero fill.
//! * [`format`] creates a FAT32 volume; [`FileSystem::check`] verifies the
//!   cluster accounting of a volume (cross-links, lost clusters, chain lengths
//!   against file sizes, FSInfo free count).
//! * All on-disk values are validated before use; a corrupted volume yields
//!   [`FsError::Corrupt`], never a panic or an endless loop.
//!
//! Single-threaded: callers serialise access (the kernel wraps a volume in a
//! sleeping mutex). There is no clock yet, so timestamps are left at the FAT
//! epoch (1980-01-01).

#![no_std]

extern crate alloc;

mod check;
mod dir;
mod file;
mod format;
mod ops;

pub use check::CheckReport;
pub use dir::{
    DirEntryInfo, ATTR_ARCHIVE, ATTR_DIRECTORY, ATTR_HIDDEN, ATTR_LFN, ATTR_READ_ONLY, ATTR_SYSTEM, ATTR_VOLUME_ID,
    MAX_NAME_UNITS,
};
pub use file::FileRef;
pub use format::format;
pub use ops::{Metadata, OpenOptions};

use alloc::vec::Vec;
use core::fmt;

pub const SECTOR_SIZE: usize = 512;

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
    /// FAT32 files are limited to 4 GiB - 1 bytes.
    FileTooLarge,
    /// On-disk structures are inconsistent.
    Corrupt(&'static str),
    /// Valid but not supported by this driver (e.g. FAT12/16).
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
            FsError::FileTooLarge => f.write_str("file too large for FAT32"),
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

pub(crate) const FAT_FREE: u32 = 0;
pub(crate) const FAT_BAD: u32 = 0x0FFF_FFF7;
pub(crate) const FAT_EOC: u32 = 0x0FFF_FFFF;
pub(crate) const FAT_MASK: u32 = 0x0FFF_FFFF;
const FSINFO_LEAD: u32 = 0x4161_5252;
const FSINFO_STRUCT: u32 = 0x6141_7272;
const FSINFO_TRAIL: u32 = 0xAA55_0000;
const FAT_CACHE_SECTORS: usize = 8;

pub(crate) fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

pub(crate) fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Layout of a mounted volume (from the BPB).
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub sectors_per_cluster: u32,
    pub reserved_sectors: u32,
    pub num_fats: u32,
    pub fat_size: u32,
    pub total_sectors: u32,
    pub root_cluster: u32,
    pub fsinfo_sector: u32,
    pub data_start: u32,
    pub cluster_count: u32,
    /// `Some(n)`: FAT mirroring disabled, only FAT `n` is active.
    pub active_fat: Option<u32>,
    pub volume_id: u32,
    pub label: [u8; 11],
}

impl Geometry {
    pub fn cluster_bytes(&self) -> u32 {
        self.sectors_per_cluster * SECTOR_SIZE as u32
    }

    /// One past the highest valid cluster number.
    pub(crate) fn max_cluster(&self) -> u32 {
        self.cluster_count + 2
    }

    pub(crate) fn cluster_lba(&self, c: u32) -> u64 {
        self.data_start as u64 + (c as u64 - 2) * self.sectors_per_cluster as u64
    }

    pub(crate) fn is_valid_cluster(&self, c: u32) -> bool {
        c >= 2 && c < self.max_cluster()
    }
}

struct CachedSector {
    index: u32,
    data: [u8; SECTOR_SIZE],
    dirty: bool,
}

/// A mounted FAT32 volume.
pub struct FileSystem<D: BlockDevice> {
    pub(crate) dev: D,
    pub(crate) geo: Geometry,
    fat_cache: Vec<CachedSector>,
    pub(crate) free_count: u32,
    next_free: u32,
    fsinfo_dirty: bool,
    fat_generation: u64,
}

impl<D: BlockDevice> FileSystem<D> {
    /// Mounts the FAT32 volume on `dev` (no partition table: the volume
    /// starts at sector 0).
    pub fn mount(mut dev: D) -> Result<Self> {
        let mut bs = [0u8; SECTOR_SIZE];
        dev.read_sectors(0, &mut bs)?;
        let geo = parse_bpb(&bs, dev.sector_count())?;
        let mut fs = FileSystem { dev, geo, fat_cache: Vec::new(), free_count: 0, next_free: 2, fsinfo_dirty: false, fat_generation: 0 };
        let mut have_info = false;
        if geo.fsinfo_sector != 0 && geo.fsinfo_sector != 0xFFFF && geo.fsinfo_sector < geo.reserved_sectors {
            let mut info = [0u8; SECTOR_SIZE];
            fs.dev.read_sectors(geo.fsinfo_sector as u64, &mut info)?;
            if le32(&info, 0) == FSINFO_LEAD && le32(&info, 484) == FSINFO_STRUCT && le32(&info, 508) == FSINFO_TRAIL {
                let free = le32(&info, 488);
                let next = le32(&info, 492);
                if free <= geo.cluster_count {
                    fs.free_count = free;
                    have_info = true;
                }
                if geo.is_valid_cluster(next) {
                    fs.next_free = next;
                }
            }
        }
        if !geo.is_valid_cluster(geo.root_cluster) {
            return Err(FsError::Corrupt("root cluster out of range"));
        }
        if !have_info {
            fs.free_count = fs.count_free()?;
            fs.fsinfo_dirty = true;
        }
        // A label set by an operating system lives in the root directory;
        // an unreadable root directory only costs the label.
        if let Ok(Some(label)) = fs.root_dir_label() {
            fs.geo.label = label;
        }
        Ok(fs)
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geo
    }

    /// Volume label: the root directory's label entry if there is one, else
    /// the boot sector's (trailing spaces removed).
    pub fn label(&self) -> &str {
        let l = &self.geo.label;
        let end = l.iter().rposition(|&b| b != b' ' && b != 0).map_or(0, |i| i + 1);
        core::str::from_utf8(&l[..end]).unwrap_or("")
    }

    pub fn free_clusters(&self) -> u32 {
        self.free_count
    }

    pub fn free_bytes(&self) -> u64 {
        self.free_count as u64 * self.geo.cluster_bytes() as u64
    }

    /// Writes cached FAT sectors and the FSInfo sector, then flushes the device.
    pub fn flush(&mut self) -> Result<()> {
        for i in 0..self.fat_cache.len() {
            if self.fat_cache[i].dirty {
                self.write_fat_sector(i)?;
            }
        }
        if self.fsinfo_dirty && self.geo.fsinfo_sector != 0 && self.geo.fsinfo_sector < self.geo.reserved_sectors {
            let mut info = [0u8; SECTOR_SIZE];
            self.dev.read_sectors(self.geo.fsinfo_sector as u64, &mut info)?;
            info[0..4].copy_from_slice(&FSINFO_LEAD.to_le_bytes());
            info[484..488].copy_from_slice(&FSINFO_STRUCT.to_le_bytes());
            info[488..492].copy_from_slice(&self.free_count.to_le_bytes());
            info[492..496].copy_from_slice(&self.next_free.to_le_bytes());
            info[508..512].copy_from_slice(&FSINFO_TRAIL.to_le_bytes());
            self.dev.write_sectors(self.geo.fsinfo_sector as u64, &info)?;
            self.fsinfo_dirty = false;
        }
        self.dev.flush()
    }

    /// Flushes and returns the device.
    pub fn unmount(mut self) -> Result<D> {
        self.flush()?;
        Ok(self.dev)
    }

    // ---- FAT access ----------------------------------------------------------

    fn fats_to_update(&self) -> core::ops::Range<u32> {
        match self.geo.active_fat {
            Some(n) => n..n + 1,
            None => 0..self.geo.num_fats,
        }
    }

    fn write_fat_sector(&mut self, slot: usize) -> Result<()> {
        let index = self.fat_cache[slot].index;
        let data = self.fat_cache[slot].data;
        for f in self.fats_to_update() {
            let lba = self.geo.reserved_sectors as u64 + f as u64 * self.geo.fat_size as u64 + index as u64;
            self.dev.write_sectors(lba, &data)?;
        }
        self.fat_cache[slot].dirty = false;
        Ok(())
    }

    /// Cache slot holding FAT sector `index` (loaded from the active FAT).
    fn fat_slot(&mut self, index: u32) -> Result<usize> {
        if let Some(pos) = self.fat_cache.iter().position(|c| c.index == index) {
            // Move to the back (most recently used).
            let entry = self.fat_cache.remove(pos);
            self.fat_cache.push(entry);
            return Ok(self.fat_cache.len() - 1);
        }
        if self.fat_cache.len() == FAT_CACHE_SECTORS {
            if self.fat_cache[0].dirty {
                self.write_fat_sector(0)?;
            }
            self.fat_cache.remove(0);
        }
        let fat = self.geo.active_fat.unwrap_or(0);
        let lba = self.geo.reserved_sectors as u64 + fat as u64 * self.geo.fat_size as u64 + index as u64;
        let mut data = [0u8; SECTOR_SIZE];
        self.dev.read_sectors(lba, &mut data)?;
        self.fat_cache.push(CachedSector { index, data, dirty: false });
        Ok(self.fat_cache.len() - 1)
    }

    /// Raw FAT entry of cluster `c` (28 bits).
    pub(crate) fn fat_get(&mut self, c: u32) -> Result<u32> {
        if c >= self.geo.max_cluster() {
            return Err(FsError::Corrupt("FAT index out of range"));
        }
        let byte = c as u64 * 4;
        let slot = self.fat_slot((byte / SECTOR_SIZE as u64) as u32)?;
        Ok(le32(&self.fat_cache[slot].data, (byte % SECTOR_SIZE as u64) as usize) & FAT_MASK)
    }

    pub(crate) fn fat_set(&mut self, c: u32, value: u32) -> Result<()> {
        if c < 2 || c >= self.geo.max_cluster() {
            return Err(FsError::Corrupt("FAT index out of range"));
        }
        let byte = c as u64 * 4;
        let slot = self.fat_slot((byte / SECTOR_SIZE as u64) as u32)?;
        let off = (byte % SECTOR_SIZE as u64) as usize;
        let s = &mut self.fat_cache[slot];
        // The top four bits are reserved and must be preserved.
        let old = le32(&s.data, off);
        let new = (old & !FAT_MASK) | (value & FAT_MASK);
        s.data[off..off + 4].copy_from_slice(&new.to_le_bytes());
        s.dirty = true;
        self.fat_generation = self.fat_generation.saturating_add(1);
        Ok(())
    }

    /// Next cluster of a chain, `None` at the end of the chain.
    pub(crate) fn next_cluster(&mut self, c: u32) -> Result<Option<u32>> {
        let v = self.fat_get(c)?;
        if v >= 0x0FFF_FFF8 {
            return Ok(None);
        }
        if v == FAT_BAD || !self.geo.is_valid_cluster(v) {
            return Err(FsError::Corrupt("invalid cluster in chain"));
        }
        Ok(Some(v))
    }

    /// The `index`-th cluster of the chain starting at `first`.
    pub(crate) fn nth_cluster(&mut self, first: u32, index: u32) -> Result<u32> {
        let mut c = first;
        for _ in 0..index {
            c = self.next_cluster(c)?.ok_or(FsError::Corrupt("cluster chain shorter than the file"))?;
        }
        Ok(c)
    }

    fn count_free(&mut self) -> Result<u32> {
        let mut n = 0;
        for c in 2..self.geo.max_cluster() {
            if self.fat_get(c)? == FAT_FREE {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Allocates one cluster, links it after `prev` (if any) and marks it as
    /// the end of its chain. Directory clusters are zeroed (`zero`).
    pub(crate) fn alloc_cluster(&mut self, prev: Option<u32>, zero: bool) -> Result<u32> {
        if self.free_count == 0 {
            return Err(FsError::NoSpace);
        }
        let max = self.geo.max_cluster();
        let start = if self.geo.is_valid_cluster(self.next_free) { self.next_free } else { 2 };
        let mut c = start;
        loop {
            if self.fat_get(c)? == FAT_FREE {
                break;
            }
            c += 1;
            if c == max {
                c = 2;
            }
            if c == start {
                // FSInfo said there was space but the FAT disagrees.
                self.free_count = 0;
                self.fsinfo_dirty = true;
                return Err(FsError::NoSpace);
            }
        }
        self.fat_set(c, FAT_EOC)?;
        if let Some(p) = prev {
            self.fat_set(p, c)?;
        }
        self.free_count -= 1;
        self.next_free = if c + 1 < max { c + 1 } else { 2 };
        self.fsinfo_dirty = true;
        if zero {
            let zeros = [0u8; SECTOR_SIZE];
            let lba = self.geo.cluster_lba(c);
            for s in 0..self.geo.sectors_per_cluster as u64 {
                self.dev.write_sectors(lba + s, &zeros)?;
            }
        }
        Ok(c)
    }

    /// Frees the chain starting at `first` (0 = empty chain).
    pub(crate) fn free_chain(&mut self, first: u32) -> Result<()> {
        if first == 0 {
            return Ok(());
        }
        let mut c = first;
        for _ in 0..self.geo.cluster_count {
            let next = self.next_cluster(c)?;
            self.fat_set(c, FAT_FREE)?;
            self.free_count += 1;
            self.fsinfo_dirty = true;
            match next {
                Some(n) => c = n,
                None => return Ok(()),
            }
        }
        Err(FsError::Corrupt("cluster chain loops"))
    }

    // ---- sector helpers ------------------------------------------------------

    pub(crate) fn read_sector(&mut self, lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> Result<()> {
        self.dev.read_sectors(lba, buf)
    }

    pub(crate) fn write_sector(&mut self, lba: u64, buf: &[u8; SECTOR_SIZE]) -> Result<()> {
        self.dev.write_sectors(lba, buf)
    }
}

fn parse_bpb(bs: &[u8; SECTOR_SIZE], device_sectors: u64) -> Result<Geometry> {
    if bs[510] != 0x55 || bs[511] != 0xAA {
        return Err(FsError::Unsupported("no boot sector signature"));
    }
    if bs[0] != 0xEB && bs[0] != 0xE9 {
        return Err(FsError::Unsupported("no x86 jump in the boot sector"));
    }
    let bytes_per_sector = le16(bs, 11);
    if bytes_per_sector as usize != SECTOR_SIZE {
        return Err(FsError::Unsupported("sector size other than 512"));
    }
    let spc = bs[13] as u32;
    if spc == 0 || !spc.is_power_of_two() || spc > 128 {
        return Err(FsError::Corrupt("invalid sectors per cluster"));
    }
    let reserved = le16(bs, 14) as u32;
    let num_fats = bs[16] as u32;
    let root_entries = le16(bs, 17);
    let total16 = le16(bs, 19) as u32;
    let fat16 = le16(bs, 22) as u32;
    if root_entries != 0 || fat16 != 0 {
        return Err(FsError::Unsupported("FAT12/FAT16 volume"));
    }
    if reserved == 0 || num_fats == 0 {
        return Err(FsError::Corrupt("no reserved sectors or no FATs"));
    }
    let total = if total16 != 0 { total16 } else { le32(bs, 32) };
    let fat_size = le32(bs, 36);
    let ext_flags = le16(bs, 40);
    if le16(bs, 42) != 0 {
        return Err(FsError::Unsupported("FAT32 version other than 0.0"));
    }
    let root_cluster = le32(bs, 44);
    let fsinfo_sector = le16(bs, 48) as u32;
    if total as u64 > device_sectors {
        return Err(FsError::Corrupt("volume larger than the device"));
    }
    let data_start = (num_fats as u64 * fat_size as u64)
        .checked_add(reserved as u64)
        .filter(|&d| d < total as u64)
        .ok_or(FsError::Corrupt("FATs larger than the volume"))? as u32;
    let cluster_count = (total - data_start) / spc;
    if cluster_count == 0 {
        return Err(FsError::Corrupt("no data clusters"));
    }
    // The FAT must have an entry for every cluster (plus the two reserved).
    if (fat_size as u64) * (SECTOR_SIZE as u64 / 4) < cluster_count as u64 + 2 {
        return Err(FsError::Corrupt("FAT too small for the cluster count"));
    }
    let active_fat = if ext_flags & 0x80 != 0 { Some((ext_flags & 0xF) as u32) } else { None };
    if active_fat.is_some_and(|f| f >= num_fats) {
        return Err(FsError::Corrupt("active FAT does not exist"));
    }
    let mut label = [b' '; 11];
    if bs[66] == 0x29 {
        label.copy_from_slice(&bs[71..82]);
    }
    Ok(Geometry {
        sectors_per_cluster: spc,
        reserved_sectors: reserved,
        num_fats,
        fat_size,
        total_sectors: total,
        root_cluster,
        fsinfo_sector,
        data_start,
        cluster_count,
        active_fat,
        volume_id: if bs[66] == 0x29 { le32(bs, 67) } else { 0 },
        label,
    })
}
