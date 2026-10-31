//! Consistency check: walks every directory and file, marks the clusters
//! they use and compares the result with the allocation bitmap.

use crate::dir::DirRef;
use crate::{BlockDevice, FileSystem, FsError, Result};
use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckReport {
    pub files: u32,
    pub directories: u32,
    pub used_clusters: u32,
    pub free_clusters: u32,
}

impl<D: BlockDevice> FileSystem<D> {
    /// Marks the `count` clusters of an extent; errors on a cluster used
    /// twice or outside the heap.
    fn mark_extent(&mut self, first: u32, nofat: bool, count: u64, seen: &mut [u8]) -> Result<()> {
        let mut c = first;
        for i in 0..count {
            if !self.geo.is_valid_cluster(c) {
                return Err(FsError::Corrupt("extent references an invalid cluster"));
            }
            let bit = (c - 2) as usize;
            if seen[bit / 8] >> (bit % 8) & 1 != 0 {
                return Err(FsError::Corrupt("cluster used twice"));
            }
            seen[bit / 8] |= 1 << (bit % 8);
            if i + 1 < count {
                c = if nofat { c + 1 } else { self.fat_next(c)? };
            }
        }
        if !nofat && count > 0 {
            // The chain must end exactly here.
            let end = self.fat_get(c)?;
            if self.geo.is_valid_cluster(end) {
                return Err(FsError::Corrupt("chain longer than the file"));
            }
        }
        Ok(())
    }

    /// Full consistency check (the volume is flushed first).
    pub fn check(&mut self) -> Result<CheckReport> {
        self.flush()?;
        let cb = self.geo.cluster_bytes();
        let mut seen = vec![0u8; self.bitmap.len()];
        let mut report = CheckReport::default();
        let bitmap_clusters = (self.bitmap.len() as u64).div_ceil(cb);
        self.mark_extent(self.bitmap_first, false, bitmap_clusters, &mut seen)?;
        if self.upcase_first != 0 {
            self.mark_extent(self.upcase_first, false, self.upcase_len.div_ceil(cb), &mut seen)?;
        }
        let root = self.root_dir();
        let root_clusters = self.chain_len(root.first)?;
        self.mark_extent(root.first, false, root_clusters, &mut seen)?;
        let mut stack: Vec<DirRef> = vec![root];
        while let Some(dir) = stack.pop() {
            report.directories += 1;
            let bytes = self.load_dir(&dir)?;
            for it in self.parse_dir(&bytes, &dir) {
                let f = it.file;
                if f.valid > f.size {
                    return Err(FsError::Corrupt("valid length beyond the size"));
                }
                let clusters = if f.first == 0 { 0 } else { f.size.div_ceil(cb) };
                if f.first == 0 && f.size != 0 {
                    return Err(FsError::Corrupt("file with data but no clusters"));
                }
                self.mark_extent(f.first, f.nofat, clusters, &mut seen)?;
                if f.is_dir() {
                    if f.size == 0 || f.size % cb != 0 {
                        return Err(FsError::Corrupt("directory size"));
                    }
                    stack.push(f.dir());
                } else {
                    report.files += 1;
                }
            }
        }
        let count = self.geo.cluster_count as usize;
        let mut used = 0u32;
        for bit in 0..count {
            let a = self.bitmap[bit / 8] >> (bit % 8) & 1 != 0;
            let b = seen[bit / 8] >> (bit % 8) & 1 != 0;
            if a != b {
                return Err(FsError::Corrupt(if a { "allocated cluster nobody uses" } else { "used cluster not allocated" }));
            }
            used += a as u32;
        }
        report.used_clusters = used;
        report.free_clusters = self.geo.cluster_count - used;
        if report.free_clusters != self.free_clusters {
            return Err(FsError::Corrupt("free cluster count"));
        }
        Ok(report)
    }
}
