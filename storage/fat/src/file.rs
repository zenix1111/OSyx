//! File data: reading, writing (with cluster allocation and zero-filled
//! gaps) and truncation. A [`FileRef`] names a file by the position of its
//! directory entry; size and first cluster are re-read from that entry on
//! every operation, so several handles to one file stay consistent.

use crate::dir::{Pos, ATTR_DIRECTORY};
use crate::{BlockDevice, FileSystem, FsError, Result, SECTOR_SIZE};

/// An open file (or directory) of a mounted volume.
#[derive(Clone, Copy, Debug)]
pub struct FileRef {
    pub(crate) entry: Pos,
    pub(crate) first_cluster: u32,
    pub(crate) size: u32,
    pub(crate) is_dir: bool,
    /// Cached (cluster index, cluster) of the last access, for sequential I/O.
    cursor: Option<(u32, u32)>,
    cursor_generation: u64,
}

impl FileRef {
    pub(crate) fn new(entry: Pos, first_cluster: u32, size: u32, is_dir: bool) -> FileRef {
        FileRef { entry, first_cluster, size, is_dir, cursor: None, cursor_generation: 0 }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
}

impl<D: BlockDevice> FileSystem<D> {
    /// Re-reads size and first cluster; fails if the file was deleted.
    fn refresh(&mut self, f: &mut FileRef) -> Result<()> {
        let e = self.read_entry(f.entry)?;
        if e[0] == 0xE5 || e[0] == 0 {
            return Err(FsError::NotFound);
        }
        let first = (crate::le16(&e, 20) as u32) << 16 | crate::le16(&e, 26) as u32;
        // A different handle can change the chain without changing its size
        // or first cluster. Any FAT mutation invalidates cached links.
        if first != f.first_cluster || f.cursor_generation != self.fat_generation || self.fat_generation == u64::MAX {
            f.cursor = None;
        }
        f.first_cluster = first;
        f.size = crate::le32(&e, 28);
        f.is_dir = e[11] & ATTR_DIRECTORY != 0;
        if !f.is_dir && f.size != 0 && f.first_cluster == 0 {
            return Err(FsError::Corrupt("nonempty file has no first cluster"));
        }
        if f.first_cluster != 0 && !self.geo.is_valid_cluster(f.first_cluster) {
            return Err(FsError::Corrupt("file starts at an invalid cluster"));
        }
        Ok(())
    }

    /// Current size and attributes of an open file (fails if it was deleted).
    pub fn stat(&mut self, f: &mut FileRef) -> Result<crate::Metadata> {
        self.refresh(f)?;
        let e = self.read_entry(f.entry)?;
        Ok(crate::Metadata {
            is_dir: f.is_dir,
            size: f.size,
            attributes: e[11],
            first_cluster: f.first_cluster,
            mtime: crate::dos_to_unix(crate::le16(&e, 24), crate::le16(&e, 22)),
        })
    }

    /// Cluster number `index` of the file, using the cursor cache.
    fn cluster_of(&mut self, f: &mut FileRef, index: u32) -> Result<u32> {
        if f.cursor_generation != self.fat_generation || self.fat_generation == u64::MAX {
            f.cursor = None;
        }
        let (mut i, mut c) = match f.cursor {
            Some((ci, cc)) if ci <= index => (ci, cc),
            _ => (0, f.first_cluster),
        };
        while i < index {
            c = self.next_cluster(c)?.ok_or(FsError::Corrupt("cluster chain shorter than the file"))?;
            i += 1;
        }
        f.cursor = Some((index, c));
        f.cursor_generation = self.fat_generation;
        Ok(c)
    }

    /// Reads up to `buf.len()` bytes at `offset`; returns the count (0 at EOF).
    pub fn read(&mut self, f: &mut FileRef, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.refresh(f)?;
        if f.is_dir {
            return Err(FsError::IsADirectory);
        }
        if offset >= f.size as u64 || buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min((f.size as u64 - offset) as usize);
        let cbytes = self.geo.cluster_bytes() as u64;
        let mut done = 0;
        let mut sector = [0u8; SECTOR_SIZE];
        while done < n {
            let pos = offset + done as u64;
            let cluster = self.cluster_of(f, (pos / cbytes) as u32)?;
            let in_cluster = pos % cbytes;
            let lba = self.geo.cluster_lba(cluster) + in_cluster / SECTOR_SIZE as u64;
            let in_sector = (in_cluster % SECTOR_SIZE as u64) as usize;
            let chunk = (SECTOR_SIZE - in_sector).min(n - done);
            if in_sector == 0 && chunk == SECTOR_SIZE {
                self.dev.read_sectors(lba, &mut buf[done..done + SECTOR_SIZE])?;
            } else {
                self.read_sector(lba, &mut sector)?;
                buf[done..done + chunk].copy_from_slice(&sector[in_sector..in_sector + chunk]);
            }
            done += chunk;
        }
        Ok(n)
    }

    /// Makes the chain long enough for `bytes` bytes.
    fn ensure_clusters(&mut self, f: &mut FileRef, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let cbytes = self.geo.cluster_bytes() as u64;
        let needed = bytes.div_ceil(cbytes) as u32;
        let (mut have, mut last) = if f.first_cluster == 0 {
            let c = self.alloc_cluster(None, false)?;
            f.first_cluster = c;
            f.cursor = None;
            // Record the first cluster at once so a failure later cannot leak it.
            self.update_entry(f.entry, c, f.size)?;
            (1u32, c)
        } else {
            let mut count = 1;
            let mut c = f.first_cluster;
            while let Some(n) = self.next_cluster(c)? {
                c = n;
                count += 1;
                if count > self.geo.cluster_count {
                    return Err(FsError::Corrupt("cluster chain loops"));
                }
            }
            (count, c)
        };
        while have < needed {
            last = self.alloc_cluster(Some(last), false)?;
            have += 1;
        }
        Ok(())
    }

    /// Writes `data` at `offset` (extending the file; a gap after the old end
    /// is zero filled). Returns `data.len()`.
    pub fn write(&mut self, f: &mut FileRef, offset: u64, data: &[u8]) -> Result<usize> {
        self.refresh(f)?;
        if f.is_dir {
            return Err(FsError::IsADirectory);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(FsError::FileTooLarge)?;
        if end > u32::MAX as u64 {
            return Err(FsError::FileTooLarge);
        }
        if let Err(e) = self.ensure_clusters(f, end) {
            // Give back whatever was allocated before the failure.
            let size = f.size as u64;
            self.trim_chain(f, size)?;
            return Err(e);
        }
        if offset > f.size as u64 {
            self.zero_range(f, f.size as u64, offset)?;
        }
        let cbytes = self.geo.cluster_bytes() as u64;
        let mut done = 0;
        let mut sector = [0u8; SECTOR_SIZE];
        while done < data.len() {
            let pos = offset + done as u64;
            let cluster = self.cluster_of(f, (pos / cbytes) as u32)?;
            let in_cluster = pos % cbytes;
            let lba = self.geo.cluster_lba(cluster) + in_cluster / SECTOR_SIZE as u64;
            let in_sector = (in_cluster % SECTOR_SIZE as u64) as usize;
            let chunk = (SECTOR_SIZE - in_sector).min(data.len() - done);
            if in_sector == 0 && chunk == SECTOR_SIZE {
                self.dev.write_sectors(lba, &data[done..done + SECTOR_SIZE])?;
            } else {
                // Partial sector: read-modify-write, but bytes past the old end
                // of file must not keep stale data from a previous owner.
                self.read_sector(lba, &mut sector)?;
                let sector_start = pos - in_sector as u64;
                if sector_start + SECTOR_SIZE as u64 > f.size as u64 {
                    let keep = (f.size as u64).saturating_sub(sector_start) as usize;
                    sector[keep.min(SECTOR_SIZE)..].fill(0);
                }
                sector[in_sector..in_sector + chunk].copy_from_slice(&data[done..done + chunk]);
                self.write_sector(lba, &sector)?;
            }
            done += chunk;
        }
        if end > f.size as u64 {
            f.size = end as u32;
        }
        self.update_entry(f.entry, f.first_cluster, f.size)?;
        Ok(data.len())
    }

    /// Writes zeros to `[from, to)` of the file (clusters must exist).
    fn zero_range(&mut self, f: &mut FileRef, from: u64, to: u64) -> Result<()> {
        let zeros = [0u8; SECTOR_SIZE];
        let cbytes = self.geo.cluster_bytes() as u64;
        let mut pos = from;
        let mut sector = [0u8; SECTOR_SIZE];
        while pos < to {
            let cluster = self.cluster_of(f, (pos / cbytes) as u32)?;
            let in_cluster = pos % cbytes;
            let lba = self.geo.cluster_lba(cluster) + in_cluster / SECTOR_SIZE as u64;
            let in_sector = (in_cluster % SECTOR_SIZE as u64) as usize;
            let chunk = ((SECTOR_SIZE - in_sector) as u64).min(to - pos) as usize;
            if in_sector == 0 && chunk == SECTOR_SIZE {
                self.write_sector(lba, &zeros)?;
            } else {
                self.read_sector(lba, &mut sector)?;
                sector[in_sector..].fill(0);
                self.write_sector(lba, &sector)?;
            }
            pos += chunk as u64;
        }
        Ok(())
    }

    /// Sets the file length; shrinking frees clusters, growing zero fills.
    pub fn truncate(&mut self, f: &mut FileRef, new_size: u64) -> Result<()> {
        self.refresh(f)?;
        if f.is_dir {
            return Err(FsError::IsADirectory);
        }
        if new_size > u32::MAX as u64 {
            return Err(FsError::FileTooLarge);
        }
        let old = f.size as u64;
        if new_size > old {
            if let Err(e) = self.ensure_clusters(f, new_size) {
                self.trim_chain(f, old)?;
                return Err(e);
            }
            self.zero_range(f, old, new_size)?;
        }
        f.size = new_size as u32;
        // Always trim: this also repairs chains longer than the size.
        self.trim_chain(f, new_size)
    }

    /// Frees every cluster beyond what `size` bytes need and records `size`.
    fn trim_chain(&mut self, f: &mut FileRef, size: u64) -> Result<()> {
        let cbytes = self.geo.cluster_bytes() as u64;
        let keep = size.div_ceil(cbytes) as u32;
        if f.first_cluster != 0 {
            if keep == 0 {
                let first = f.first_cluster;
                f.first_cluster = 0;
                self.update_entry(f.entry, 0, 0)?;
                self.free_chain(first)?;
            } else {
                let last = self.nth_cluster(f.first_cluster, keep - 1)?;
                if let Some(rest) = self.next_cluster(last)? {
                    self.fat_set(last, crate::FAT_EOC)?;
                    self.free_chain(rest)?;
                }
            }
        }
        f.cursor = None;
        f.size = size as u32;
        self.update_entry(f.entry, f.first_cluster, f.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{format, OpenOptions};
    use alloc::vec;

    #[test]
    fn created_and_written_files_carry_the_clock() {
        let mut image = vec![0; 64 * 1024 * 1024];
        format(&mut image, "TEST", 1).unwrap();
        let mut fs = FileSystem::mount(image).unwrap();
        // 2025-06-15 12:34:56 UTC.
        fs.set_time(1_749_990_896);
        let mut file = fs.open("/stamped", OpenOptions { create: true, ..Default::default() }).unwrap();
        assert_eq!(fs.stat(&mut file).unwrap().mtime, 1_749_990_896);
        fs.write(&mut file, 0, b"data").unwrap();
        assert_eq!(fs.stat(&mut file).unwrap().mtime, 1_749_990_896);
        let md = fs.metadata("/stamped").unwrap();
        assert_eq!(md.mtime, 1_749_990_896);
        // Before 1980 the driver clamps to the DOS epoch.
        fs.set_time(0);
        let mut old = fs.open("/old", OpenOptions { create: true, ..Default::default() }).unwrap();
        assert_eq!(fs.stat(&mut old).unwrap().mtime, 315_532_800);
    }

    #[test]
    fn sequential_reads_keep_cursor_until_fat_changes() {
        let mut image = vec![0; 64 * 1024 * 1024];
        format(&mut image, "TEST", 1).unwrap();
        let mut fs = FileSystem::mount(image).unwrap();
        let mut file = fs.open("/file", OpenOptions { create: true, ..Default::default() }).unwrap();
        fs.write(&mut file, 0, &vec![1; 1536]).unwrap();
        fs.read(&mut file, 512, &mut [0]).unwrap();
        let cursor = file.cursor;
        fs.stat(&mut file).unwrap();
        assert_eq!(file.cursor, cursor);
        let mut other = fs.open("/other", OpenOptions { create: true, ..Default::default() }).unwrap();
        fs.write(&mut other, 0, b"x").unwrap();
        fs.stat(&mut file).unwrap();
        assert_eq!(file.cursor, None);
    }
}
