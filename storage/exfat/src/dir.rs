//! Directories: entry sets, name matching, allocation of entries.

use crate::time::unix_with_offset;
use crate::{le16, le32, le64, BlockDevice, Cursor, FileSystem, FsError, Result, ATTR_ARCHIVE, ATTR_DIRECTORY, FAT_EOC, MAX_NAME_UNITS};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) const ENTRY: usize = 32;
pub(crate) const T_FILE: u8 = 0x85;
pub(crate) const T_STREAM: u8 = 0xC0;
pub(crate) const T_NAME: u8 = 0xC1;
const NAME_PER_ENTRY: usize = 15;
/// Entries per directory: a limit, like the specification's 256 MiB.
const MAX_DIR_BYTES: u64 = 256 << 20;

/// Where the directory entry set of a file or directory is, so that it can
/// be rewritten when the file changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryPos {
    /// The containing directory.
    pub pfirst: u32,
    pub pnofat: bool,
    /// Its length in bytes, 0 for the root directory (its chain is walked).
    pub plen: u64,
    /// Byte offset of the file entry in the directory.
    pub set_off: u64,
    /// Entries in the set, the file entry included.
    pub count: u8,
}

/// A directory: its extent and, except for the root, its own entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirRef {
    pub first: u32,
    pub nofat: bool,
    /// Length in bytes, 0 for the root directory.
    pub len: u64,
    pub entry: Option<EntryPos>,
}

/// An open file or directory: a snapshot of its entry, to be passed back
/// to `read`/`write`/`truncate`, which keep it current.
#[derive(Clone, Copy, Debug)]
pub struct FileRef {
    pub(crate) first: u32,
    pub(crate) nofat: bool,
    pub(crate) size: u64,
    pub(crate) valid: u64,
    pub(crate) attr: u16,
    pub(crate) pos: Option<EntryPos>,
    pub(crate) cursor: Cursor,
    pub(crate) times: Times,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Times {
    pub create: u32,
    pub modify: u32,
    pub access: u32,
    pub create_off: u8,
    pub modify_off: u8,
    pub access_off: u8,
}

impl FileRef {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }

    pub fn attributes(&self) -> u16 {
        self.attr
    }

    pub fn first_cluster(&self) -> u32 {
        self.first
    }

    pub(crate) fn dir(&self) -> DirRef {
        DirRef { first: self.first, nofat: self.nofat, len: self.size, entry: self.pos }
    }

    pub fn modified_unix(&self) -> i64 {
        unix_with_offset(self.times.modify, self.times.modify_off)
    }

    pub fn accessed_unix(&self) -> i64 {
        unix_with_offset(self.times.access, self.times.access_off)
    }

    pub fn created_unix(&self) -> i64 {
        unix_with_offset(self.times.create, self.times.create_off)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub attributes: u16,
}

pub(crate) struct Item {
    pub name16: Vec<u16>,
    pub file: FileRef,
}

impl Item {
    pub fn name(&self) -> String {
        String::from_utf16_lossy(&self.name16)
    }
}

/// The checksum of a directory entry set (specification 6.3.3); the two
/// checksum bytes of the first entry are skipped.
pub fn entry_set_checksum(set: &[u8]) -> u16 {
    let mut sum = 0u16;
    for (i, &b) in set.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        sum = sum.rotate_right(1).wrapping_add(b as u16);
    }
    sum
}

/// Characters a name cannot contain (and control characters).
fn forbidden(u: u16) -> bool {
    u < 0x20 || matches!(u, 0x22 | 0x2A | 0x2F | 0x3A | 0x3C | 0x3E | 0x3F | 0x5C | 0x7C)
}

pub(crate) fn validate_name(name: &str) -> Result<Vec<u16>> {
    let u: Vec<u16> = name.encode_utf16().collect();
    if u.is_empty() || u.len() > MAX_NAME_UNITS || name == "." || name == ".." || u.iter().any(|&c| forbidden(c)) {
        return Err(FsError::InvalidName);
    }
    Ok(u)
}

impl<D: BlockDevice> FileSystem<D> {
    pub(crate) fn up(&self, c: u16) -> u16 {
        self.upcase.get(c as usize).copied().unwrap_or(c)
    }

    pub(crate) fn names_equal(&self, a: &[u16], b: &[u16]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| x == y || self.up(x) == self.up(y))
    }

    fn name_hash(&self, name: &[u16]) -> u16 {
        let mut h = 0u16;
        for &c in name {
            let u = self.up(c);
            for b in [u as u8, (u >> 8) as u8] {
                h = h.rotate_right(1).wrapping_add(b as u16);
            }
        }
        h
    }

    pub(crate) fn root_dir(&self) -> DirRef {
        DirRef { first: self.geo.root_cluster, nofat: false, len: 0, entry: None }
    }

    /// Clusters in the chain starting at `first`.
    pub(crate) fn chain_len(&mut self, first: u32) -> Result<u64> {
        let mut n = 0u64;
        let mut c = first;
        loop {
            n += 1;
            if n > self.geo.cluster_count as u64 {
                return Err(FsError::Corrupt("FAT chain loops"));
            }
            let next = self.fat_get(c)?;
            if !self.geo.is_valid_cluster(next) {
                return Ok(n);
            }
            c = next;
        }
    }

    pub(crate) fn dir_len(&mut self, d: &DirRef) -> Result<u64> {
        if d.entry.is_none() {
            Ok(self.chain_len(d.first)? << self.geo.cluster_shift())
        } else {
            Ok(d.len)
        }
    }

    pub(crate) fn load_dir(&mut self, d: &DirRef) -> Result<Vec<u8>> {
        let len = self.dir_len(d)?;
        if len > MAX_DIR_BYTES {
            return Err(FsError::Corrupt("directory too large"));
        }
        let mut bytes = vec![0u8; len as usize];
        self.read_extent(d.first, d.nofat, len, 0, &mut bytes)?;
        Ok(bytes)
    }

    /// The files and directories listed in `bytes`, the contents of `d`.
    pub(crate) fn parse_dir(&self, bytes: &[u8], d: &DirRef) -> Vec<Item> {
        let mut items = Vec::new();
        let total = bytes.len() / ENTRY;
        let plen = if d.entry.is_none() { 0 } else { d.len };
        let mut i = 0;
        while i < total {
            let e = &bytes[i * ENTRY..(i + 1) * ENTRY];
            if e[0] == 0 {
                break;
            }
            if e[0] != T_FILE {
                i += 1;
                continue;
            }
            let secondary = e[1] as usize;
            if secondary < 2 || i + secondary >= total {
                i += 1;
                continue;
            }
            let set = &bytes[i * ENTRY..(i + secondary + 1) * ENTRY];
            let stream = &set[ENTRY..2 * ENTRY];
            let name_len = stream[3] as usize;
            let name_entries = name_len.div_ceil(NAME_PER_ENTRY);
            let ok = stream[0] == T_STREAM
                && name_len > 0
                && name_entries < secondary
                && (0..name_entries).all(|k| set[(2 + k) * ENTRY] == T_NAME)
                && entry_set_checksum(set) == le16(set, 2);
            if !ok {
                i += 1;
                continue;
            }
            let mut name16 = Vec::with_capacity(name_len);
            for k in 0..name_entries {
                let ne = &set[(2 + k) * ENTRY..(3 + k) * ENTRY];
                for j in 0..NAME_PER_ENTRY {
                    if name16.len() < name_len {
                        name16.push(le16(ne, 2 + j * 2));
                    }
                }
            }
            let file = FileRef {
                first: le32(stream, 20),
                nofat: stream[1] & 2 != 0,
                size: le64(stream, 24),
                valid: le64(stream, 8).min(le64(stream, 24)),
                attr: le16(set, 4),
                pos: Some(crate::EntryPos { pfirst: d.first, pnofat: d.nofat, plen, set_off: (i * ENTRY) as u64, count: (secondary + 1) as u8 }),
                cursor: Cursor::default(),
                times: Times {
                    create: le32(set, 8),
                    modify: le32(set, 12),
                    access: le32(set, 16),
                    create_off: set[22],
                    modify_off: set[23],
                    access_off: set[24],
                },
            };
            items.push(Item { name16, file });
            i += secondary + 1;
        }
        items
    }

    pub(crate) fn find_in_dir(&mut self, d: &DirRef, name: &[u16]) -> Result<Option<Item>> {
        let bytes = self.load_dir(d)?;
        Ok(self.parse_dir(&bytes, d).into_iter().find(|it| self.names_equal(&it.name16, name)))
    }

    /// A new entry set (file entry, stream extension, names).
    pub(crate) fn build_set(&self, name: &[u16], f: &FileRef) -> Vec<u8> {
        let name_entries = name.len().div_ceil(NAME_PER_ENTRY);
        let count = 2 + name_entries;
        let mut set = vec![0u8; count * ENTRY];
        set[0] = T_FILE;
        set[1] = (count - 1) as u8;
        set[4..6].copy_from_slice(&f.attr.to_le_bytes());
        set[8..12].copy_from_slice(&f.times.create.to_le_bytes());
        set[12..16].copy_from_slice(&f.times.modify.to_le_bytes());
        set[16..20].copy_from_slice(&f.times.access.to_le_bytes());
        set[22] = f.times.create_off;
        set[23] = f.times.modify_off;
        set[24] = f.times.access_off;
        let s = &mut set[ENTRY..2 * ENTRY];
        s[0] = T_STREAM;
        s[1] = 0x01 | if f.nofat { 0x02 } else { 0 };
        s[3] = name.len() as u8;
        s[4..6].copy_from_slice(&self.name_hash(name).to_le_bytes());
        s[8..16].copy_from_slice(&f.valid.to_le_bytes());
        s[20..24].copy_from_slice(&f.first.to_le_bytes());
        s[24..32].copy_from_slice(&f.size.to_le_bytes());
        for k in 0..name_entries {
            let e = &mut set[(2 + k) * ENTRY..(3 + k) * ENTRY];
            e[0] = T_NAME;
            for (j, &u) in name.iter().skip(k * NAME_PER_ENTRY).take(NAME_PER_ENTRY).enumerate() {
                e[2 + j * 2..4 + j * 2].copy_from_slice(&u.to_le_bytes());
            }
        }
        let sum = entry_set_checksum(&set);
        set[2..4].copy_from_slice(&sum.to_le_bytes());
        set
    }

    /// `FileRef` for a new, empty file or directory entry.
    pub(crate) fn new_ref(&self, attr: u16) -> FileRef {
        let t = self.now();
        FileRef {
            first: 0,
            nofat: false,
            size: 0,
            valid: 0,
            attr,
            pos: None,
            cursor: Cursor::default(),
            times: Times { create: t, modify: t, access: t, create_off: 0x80, modify_off: 0x80, access_off: 0x80 },
        }
    }

    fn parent_len(&mut self, pos: &EntryPos) -> Result<u64> {
        if pos.plen == 0 {
            Ok(self.chain_len(pos.pfirst)? << self.geo.cluster_shift())
        } else {
            Ok(pos.plen)
        }
    }

    /// Reads the entry set at `pos`, lets `f` change it, fixes the
    /// checksum and writes it back.
    pub(crate) fn edit_set(&mut self, pos: &EntryPos, f: impl FnOnce(&mut [u8])) -> Result<()> {
        let plen = self.parent_len(pos)?;
        let len = pos.count as usize * ENTRY;
        let mut set = vec![0u8; len];
        self.read_extent(pos.pfirst, pos.pnofat, plen, pos.set_off, &mut set)?;
        if set[0] != T_FILE || set[ENTRY] != T_STREAM {
            return Err(FsError::Corrupt("directory entry changed under us"));
        }
        f(&mut set);
        let sum = entry_set_checksum(&set);
        set[2..4].copy_from_slice(&sum.to_le_bytes());
        self.write_extent(pos.pfirst, pos.pnofat, plen, pos.set_off, &set)
    }

    /// Writes a file's current state into its directory entry.
    pub(crate) fn persist(&mut self, f: &mut FileRef, touch: bool) -> Result<()> {
        let Some(pos) = f.pos else { return Ok(()) };
        if touch {
            f.times.modify = self.now();
            f.times.modify_off = 0x80;
            f.times.access = f.times.modify;
            f.times.access_off = 0x80;
            if f.attr & ATTR_DIRECTORY == 0 {
                f.attr |= ATTR_ARCHIVE;
            }
        }
        let g = *f;
        self.edit_set(&pos, |set| {
            set[4..6].copy_from_slice(&g.attr.to_le_bytes());
            set[12..16].copy_from_slice(&g.times.modify.to_le_bytes());
            set[16..20].copy_from_slice(&g.times.access.to_le_bytes());
            set[23] = g.times.modify_off;
            set[24] = g.times.access_off;
            let s = &mut set[ENTRY..2 * ENTRY];
            s[1] = 0x01 | if g.nofat { 0x02 } else { 0 };
            s[8..16].copy_from_slice(&g.valid.to_le_bytes());
            s[20..24].copy_from_slice(&g.first.to_le_bytes());
            s[24..32].copy_from_slice(&g.size.to_le_bytes());
        })
    }

    /// Marks an entry set as deleted.
    pub(crate) fn delete_set(&mut self, pos: &EntryPos) -> Result<()> {
        let plen = self.parent_len(pos)?;
        let mut set = vec![0u8; pos.count as usize * ENTRY];
        self.read_extent(pos.pfirst, pos.pnofat, plen, pos.set_off, &mut set)?;
        for i in 0..pos.count as usize {
            set[i * ENTRY] &= 0x7F;
        }
        self.write_extent(pos.pfirst, pos.pnofat, plen, pos.set_off, &set)
    }

    /// Makes a contiguous run of `count` clusters a FAT chain.
    pub(crate) fn make_chain(&mut self, first: u32, count: u64) -> Result<()> {
        for k in 0..count {
            let c = first + k as u32;
            let next = if k + 1 < count { c + 1 } else { FAT_EOC };
            self.fat_set(c, next)?;
        }
        Ok(())
    }

    /// Appends `add` zeroed clusters to a directory.
    fn grow_dir(&mut self, d: &mut DirRef, add: u64) -> Result<()> {
        let cb = self.geo.cluster_bytes();
        let have = self.dir_len(d)? / cb;
        if have == 0 || have + add > MAX_DIR_BYTES / cb {
            return Err(FsError::NoSpace);
        }
        if d.nofat {
            self.make_chain(d.first, have)?;
            d.nofat = false;
        }
        let mut cursor = Cursor::default();
        let old_last = self.cluster_for(d.first, false, (have - 1) as u32, &mut cursor)?;
        let mut added: Vec<u32> = Vec::new();
        let zeros = vec![0u8; cb as usize];
        let mut last = old_last;
        let mut failure = None;
        for _ in 0..add {
            let c = match self.alloc_cluster() {
                Ok(c) => c,
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            };
            added.push(c);
            let r = self.write_at(self.cluster_off(c), &zeros).and_then(|_| self.fat_set(last, c)).and_then(|_| self.fat_set(c, FAT_EOC));
            if let Err(e) = r {
                failure = Some(e);
                break;
            }
            last = c;
        }
        if let Some(e) = failure {
            for &c in &added {
                let _ = self.fat_set(c, 0);
                self.free_cluster(c);
            }
            let _ = self.fat_set(old_last, FAT_EOC);
            return Err(e);
        }
        d.len = (have + add) * cb;
        if let Some(pos) = d.entry {
            let (len, nofat) = (d.len, d.nofat);
            self.edit_set(&pos, |set| {
                let s = &mut set[ENTRY..2 * ENTRY];
                s[1] = 0x01 | if nofat { 0x02 } else { 0 };
                s[8..16].copy_from_slice(&len.to_le_bytes());
                s[24..32].copy_from_slice(&len.to_le_bytes());
            })?;
        }
        Ok(())
    }

    /// Writes `set` into the first free run of entries of `d`, growing the
    /// directory if needed; returns where it went.
    pub(crate) fn insert_set(&mut self, d: &DirRef, set: &[u8]) -> Result<EntryPos> {
        let mut d = *d;
        let bytes = self.load_dir(&d)?;
        let need = set.len() / ENTRY;
        let total = bytes.len() / ENTRY;
        let mut run_start: Option<usize> = None;
        let mut found: Option<usize> = None;
        for i in 0..total {
            if bytes[i * ENTRY] & 0x80 == 0 {
                let s = *run_start.get_or_insert(i);
                if i + 1 - s >= need {
                    found = Some(s);
                    break;
                }
            } else {
                run_start = None;
            }
        }
        let start = match found {
            Some(s) => s,
            None => {
                let s = run_start.unwrap_or(total);
                let missing = (s + need).saturating_sub(total) as u64;
                let cb = self.geo.cluster_bytes();
                self.grow_dir(&mut d, (missing * ENTRY as u64).div_ceil(cb))?;
                s
            }
        };
        let len = self.dir_len(&d)?;
        let off = (start * ENTRY) as u64;
        self.write_extent(d.first, d.nofat, len, off, set)?;
        Ok(EntryPos { pfirst: d.first, pnofat: d.nofat, plen: if d.entry.is_none() { 0 } else { len }, set_off: off, count: need as u8 })
    }
}
