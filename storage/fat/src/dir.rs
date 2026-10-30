//! Directory entries: 8.3 short entries, VFAT long-name entries, lookup,
//! listing, insertion and removal.

use crate::{le16, le32, BlockDevice, FileSystem, FsError, Result, SECTOR_SIZE};
use alloc::string::String;
use alloc::vec::Vec;

pub(crate) const ENTRY_SIZE: usize = 32;
pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_LFN: u8 = 0x0F;
/// NT reserved byte: base / extension of the short name stored in lower case.
const NT_LOWER_BASE: u8 = 0x08;
const NT_LOWER_EXT: u8 = 0x10;
/// Longest long name in UTF-16 units.
pub const MAX_NAME_UNITS: usize = 255;
/// A directory may hold at most 65536 entries.
const MAX_DIR_ENTRIES: u32 = 65536;

/// Location of a 32-byte directory entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pos {
    pub lba: u64,
    pub offset: usize,
}

/// A parsed directory item (one file or directory).
#[derive(Clone, Debug)]
pub(crate) struct Item {
    pub name: String,
    pub short: [u8; 11],
    pub attr: u8,
    pub first_cluster: u32,
    pub size: u32,
    /// Modification time, seconds since 1970-01-01 UTC (0 if unset).
    pub mtime: u32,
    /// The short entry.
    pub sfn: Pos,
    /// All entries of the item (long-name entries first, then the short one).
    pub slots: Vec<Pos>,
}

impl Item {
    pub fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }

    pub fn is_dot(&self) -> bool {
        self.short == *b".          " || self.short == *b"..         "
    }
}

/// Public listing entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: u32,
    pub attributes: u8,
}

pub(crate) fn sfn_checksum(short: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in short {
        sum = (sum >> 1).wrapping_add((sum & 1) << 7).wrapping_add(b);
    }
    sum
}

/// Display form of a short name ("NAME.EXT"), honouring the NT case flags.
fn short_display(short: &[u8; 11], nt: u8) -> String {
    let mut base: Vec<u8> = short[..8].to_vec();
    if base[0] == 0x05 {
        base[0] = 0xE5;
    }
    let trim = |v: &[u8]| v.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    let b = &base[..trim(&base)];
    let e = &short[8..8 + trim(&short[8..])];
    let mut s = String::new();
    let push = |s: &mut String, bytes: &[u8], lower: bool| {
        for &c in bytes {
            // Bytes >= 0x80 are OEM code page characters; map them as Latin-1.
            let ch = c as char;
            s.push(if lower { ch.to_ascii_lowercase() } else { ch });
        }
    };
    push(&mut s, b, nt & NT_LOWER_BASE != 0);
    if !e.is_empty() {
        s.push('.');
        push(&mut s, e, nt & NT_LOWER_EXT != 0);
    }
    s
}

/// Validates a name for creation and returns it as UTF-16 units.
pub(crate) fn validate_name(name: &str) -> Result<Vec<u16>> {
    if name.is_empty() || name == "." || name == ".." || name.ends_with(' ') || name.ends_with('.') {
        return Err(FsError::InvalidName);
    }
    if name.chars().any(|c| (c as u32) < 0x20 || "\"*/:<>?\\|".contains(c)) {
        return Err(FsError::InvalidName);
    }
    let units: Vec<u16> = name.encode_utf16().collect();
    if units.len() > MAX_NAME_UNITS {
        return Err(FsError::InvalidName);
    }
    Ok(units)
}

const SFN_SPECIAL: &[u8] = b"!#$%&'()-@^_`{}~";

fn sfn_char_ok(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || SFN_SPECIAL.contains(&c)
}

/// The exact 8.3 form of `name` if it needs no long-name entries: upper-case
/// (or entirely lower-case base/extension, recorded with the NT flags).
pub(crate) fn exact_short(name: &str) -> Option<([u8; 11], u8)> {
    let (base, ext) = match name.rsplit_once('.') {
        Some((b, e)) => (b, e),
        None => (name, ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || base.contains('.') || !name.is_ascii() {
        return None;
    }
    let mut nt = 0;
    let mut short = [b' '; 11];
    for (part, range, flag) in [(base, 0..8, NT_LOWER_BASE), (ext, 8..11, NT_LOWER_EXT)] {
        let lower = part.bytes().any(|c| c.is_ascii_lowercase());
        let upper = part.bytes().any(|c| c.is_ascii_uppercase());
        if lower && upper {
            return None; // mixed case needs a long name
        }
        if lower {
            nt |= flag;
        }
        for (i, c) in part.bytes().enumerate() {
            let u = c.to_ascii_uppercase();
            if !sfn_char_ok(u) {
                return None;
            }
            short[range.start + i] = u;
        }
    }
    if short[0] == 0xE5 {
        short[0] = 0x05;
    }
    Some((short, nt))
}

/// Short alias for a long name: `BASIS~N.EXT` (the numeric tail is filled in
/// by the caller until it is unique in the directory).
fn short_basis(name: &str) -> ([u8; 8], [u8; 3]) {
    let clean = |s: &str, max: usize| {
        let mut out = Vec::new();
        for c in s.chars() {
            if out.len() == max {
                break;
            }
            if c == ' ' || c == '.' {
                continue;
            }
            let u = if c.is_ascii() { c.to_ascii_uppercase() as u8 } else { b'_' };
            out.push(if sfn_char_ok(u) { u } else { b'_' });
        }
        out
    };
    let trimmed = name.trim_start_matches('.');
    let (b, e) = match trimmed.rsplit_once('.') {
        Some((b, e)) if !b.is_empty() => (b, e),
        _ => (trimmed, ""),
    };
    let mut base = [b' '; 8];
    let mut ext = [b' '; 3];
    let cb = clean(b, 8);
    let cb = if cb.is_empty() { Vec::from(&b"_"[..]) } else { cb };
    base[..cb.len()].copy_from_slice(&cb);
    let ce = clean(e, 3);
    ext[..ce.len()].copy_from_slice(&ce);
    (base, ext)
}

fn with_tail(base: &[u8; 8], ext: &[u8; 3], n: u32) -> [u8; 11] {
    let mut digits = [0u8; 10];
    let mut len = 0;
    let mut v = n;
    while v > 0 {
        digits[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let tail_len = len + 1;
    let keep = base.iter().position(|&c| c == b' ').unwrap_or(8).min(8 - tail_len);
    let mut short = [b' '; 11];
    short[..keep].copy_from_slice(&base[..keep]);
    short[keep] = b'~';
    for i in 0..len {
        short[keep + 1 + i] = digits[len - 1 - i];
    }
    short[8..].copy_from_slice(ext);
    short
}

fn utf16_eq_ignore_case(a: &str, b: &str) -> bool {
    let mut x = a.chars().flat_map(char::to_lowercase);
    let mut y = b.chars().flat_map(char::to_lowercase);
    loop {
        match (x.next(), y.next()) {
            (None, None) => return true,
            (Some(p), Some(q)) if p == q => {}
            _ => return false,
        }
    }
}

impl<D: BlockDevice> FileSystem<D> {
    /// Calls `f` for every raw 32-byte slot of the directory starting at
    /// cluster `dir`, stopping when `f` returns `Ok(false)`. Bounded by the
    /// 65536-entry limit, so a looping chain cannot hang.
    fn for_each_slot(&mut self, dir: u32, mut f: impl FnMut(Pos, &[u8]) -> Result<bool>) -> Result<()> {
        let per_cluster = self.geo.cluster_bytes() as usize / ENTRY_SIZE;
        let mut cluster = dir;
        let mut seen = 0u32;
        let mut sector = [0u8; SECTOR_SIZE];
        loop {
            let lba = self.geo.cluster_lba(cluster);
            for s in 0..self.geo.sectors_per_cluster as u64 {
                self.read_sector(lba + s, &mut sector)?;
                for i in 0..SECTOR_SIZE / ENTRY_SIZE {
                    let off = i * ENTRY_SIZE;
                    if !f(Pos { lba: lba + s, offset: off }, &sector[off..off + ENTRY_SIZE])? {
                        return Ok(());
                    }
                }
            }
            seen += per_cluster as u32;
            if seen >= MAX_DIR_ENTRIES {
                return Err(FsError::Corrupt("directory too large or looping"));
            }
            match self.next_cluster(cluster)? {
                Some(n) => cluster = n,
                None => return Ok(()),
            }
        }
    }

    /// The volume label entry of the root directory (what Windows and
    /// `label` set; the boot sector copy is often left at "NO NAME").
    pub(crate) fn root_dir_label(&mut self) -> Result<Option<[u8; 11]>> {
        let root = self.geo.root_cluster;
        let mut found = None;
        self.for_each_slot(root, |_, e| {
            if e[0] == 0 {
                return Ok(false);
            }
            let attr = e[11];
            if e[0] != 0xE5 && attr & 0x3F != ATTR_LFN && attr & ATTR_VOLUME_ID != 0 && attr & ATTR_DIRECTORY == 0 {
                let mut l = [0u8; 11];
                l.copy_from_slice(&e[..11]);
                found = Some(l);
                return Ok(false);
            }
            Ok(true)
        })?;
        Ok(found)
    }

    /// Parses the directory at cluster `dir` into items (including `.`/`..`,
    /// excluding the volume label and deleted entries).
    pub(crate) fn read_items(&mut self, dir: u32) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        let mut lfn: Vec<u16> = Vec::new();
        let mut lfn_slots: Vec<Pos> = Vec::new();
        let mut lfn_checksum = 0u8;
        let mut expected_seq = 0u8;
        self.for_each_slot(dir, |pos, e| {
            let first = e[0];
            if first == 0x00 {
                return Ok(false); // end of directory
            }
            if first == 0xE5 {
                lfn.clear();
                lfn_slots.clear();
                return Ok(true);
            }
            let attr = e[11];
            if attr & 0x3F == ATTR_LFN {
                let seq = first & 0x1F;
                if first & 0x40 != 0 {
                    // Last (physically first) long-name entry.
                    lfn.clear();
                    lfn_slots.clear();
                    lfn.resize(seq as usize * 13, 0xFFFF);
                    lfn_checksum = e[13];
                    expected_seq = seq;
                } else if seq != expected_seq || e[13] != lfn_checksum {
                    lfn.clear();
                    lfn_slots.clear();
                    return Ok(true);
                }
                if seq == 0 || lfn.len() < seq as usize * 13 {
                    lfn.clear();
                    lfn_slots.clear();
                    return Ok(true);
                }
                let base = (seq as usize - 1) * 13;
                let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
                for (i, o) in offsets.iter().enumerate() {
                    lfn[base + i] = le16(e, *o);
                }
                lfn_slots.push(pos);
                expected_seq = seq - 1;
                return Ok(true);
            }
            let mut short = [0u8; 11];
            short.copy_from_slice(&e[..11]);
            if attr & ATTR_VOLUME_ID != 0 {
                lfn.clear();
                lfn_slots.clear();
                return Ok(true);
            }
            let long_ok = !lfn.is_empty() && expected_seq == 0 && sfn_checksum(&short) == lfn_checksum;
            let name = if long_ok {
                let end = lfn.iter().position(|&u| u == 0).unwrap_or(lfn.len());
                String::from_utf16(&lfn[..end]).ok()
            } else {
                None
            };
            let name = name.unwrap_or_else(|| short_display(&short, e[12]));
            let mut slots = if long_ok { core::mem::take(&mut lfn_slots) } else { Vec::new() };
            slots.push(pos);
            items.push(Item {
                name,
                short,
                attr,
                first_cluster: (le16(e, 20) as u32) << 16 | le16(e, 26) as u32,
                size: le32(e, 28),
                mtime: crate::dos_to_unix(le16(e, 24), le16(e, 22)),
                sfn: pos,
                slots,
            });
            lfn.clear();
            lfn_slots.clear();
            Ok(true)
        })?;
        Ok(items)
    }

    /// Finds `name` (case-insensitive, long or short form) in directory `dir`.
    pub(crate) fn find(&mut self, dir: u32, name: &str) -> Result<Option<Item>> {
        Ok(self.read_items(dir)?.into_iter().find(|it| {
            utf16_eq_ignore_case(&it.name, name)
                || (!it.is_dot() && utf16_eq_ignore_case(&short_display(&it.short, 0), name))
        }))
    }

    /// Positions of `count` consecutive free slots in directory `dir`,
    /// extending the directory with zeroed clusters if necessary.
    fn free_slots(&mut self, dir: u32, count: usize) -> Result<Vec<Pos>> {
        let mut run: Vec<Pos> = Vec::new();
        let mut done = false;
        self.for_each_slot(dir, |pos, e| {
            if e[0] == 0x00 || e[0] == 0xE5 {
                run.push(pos);
                if run.len() == count {
                    done = true;
                    return Ok(false);
                }
            } else {
                run.clear();
            }
            Ok(true)
        })?;
        while !done {
            // Append a cluster; a run may continue across the boundary.
            let mut last = dir;
            while let Some(n) = self.next_cluster(last)? {
                last = n;
            }
            let entries_now = self.dir_entry_capacity(dir)?;
            if entries_now + (self.geo.cluster_bytes() as usize / ENTRY_SIZE) as u32 > MAX_DIR_ENTRIES {
                return Err(FsError::NoSpace);
            }
            let c = self.alloc_cluster(Some(last), true)?;
            let lba = self.geo.cluster_lba(c);
            'fill: for s in 0..self.geo.sectors_per_cluster as u64 {
                for i in 0..SECTOR_SIZE / ENTRY_SIZE {
                    run.push(Pos { lba: lba + s, offset: i * ENTRY_SIZE });
                    if run.len() == count {
                        done = true;
                        break 'fill;
                    }
                }
            }
        }
        Ok(run)
    }

    fn dir_entry_capacity(&mut self, dir: u32) -> Result<u32> {
        let mut clusters = 1u32;
        let mut c = dir;
        while let Some(n) = self.next_cluster(c)? {
            clusters += 1;
            if clusters > self.geo.cluster_count {
                return Err(FsError::Corrupt("directory chain loops"));
            }
            c = n;
        }
        Ok(clusters * (self.geo.cluster_bytes() / ENTRY_SIZE as u32))
    }

    pub(crate) fn write_entry(&mut self, pos: Pos, entry: &[u8; ENTRY_SIZE]) -> Result<()> {
        let mut sector = [0u8; SECTOR_SIZE];
        self.read_sector(pos.lba, &mut sector)?;
        sector[pos.offset..pos.offset + ENTRY_SIZE].copy_from_slice(entry);
        self.write_sector(pos.lba, &sector)
    }

    pub(crate) fn read_entry(&mut self, pos: Pos) -> Result<[u8; ENTRY_SIZE]> {
        let mut sector = [0u8; SECTOR_SIZE];
        self.read_sector(pos.lba, &mut sector)?;
        let mut e = [0u8; ENTRY_SIZE];
        e.copy_from_slice(&sector[pos.offset..pos.offset + ENTRY_SIZE]);
        Ok(e)
    }

    /// Creates the entries for `name` in directory `dir`. The caller has
    /// checked that the name does not exist yet. Returns the short entry position.
    pub(crate) fn insert(&mut self, dir: u32, name: &str, attr: u8, first_cluster: u32, size: u32) -> Result<Pos> {
        let units = validate_name(name)?;
        let (short, nt, long) = match exact_short(name) {
            Some((s, nt)) => (s, nt, false),
            None => {
                let (base, ext) = short_basis(name);
                let existing: Vec<[u8; 11]> = self.read_items(dir)?.into_iter().map(|i| i.short).collect();
                let mut chosen = None;
                for n in 1..1_000_000 {
                    let candidate = with_tail(&base, &ext, n);
                    if !existing.contains(&candidate) {
                        chosen = Some(candidate);
                        break;
                    }
                }
                (chosen.ok_or(FsError::NoSpace)?, 0, true)
            }
        };
        let lfn_entries = if long { units.len().div_ceil(13) } else { 0 };
        let slots = self.free_slots(dir, lfn_entries + 1)?;
        let checksum = sfn_checksum(&short);
        for (k, pos) in slots[..lfn_entries].iter().enumerate() {
            // Physical order: highest sequence number first.
            let seq = (lfn_entries - k) as u8;
            let mut e = [0u8; ENTRY_SIZE];
            e[0] = seq | if k == 0 { 0x40 } else { 0 };
            e[11] = ATTR_LFN;
            e[13] = checksum;
            let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
            for (i, o) in offsets.iter().enumerate() {
                let idx = (seq as usize - 1) * 13 + i;
                let unit = match idx.cmp(&units.len()) {
                    core::cmp::Ordering::Less => units[idx],
                    core::cmp::Ordering::Equal => 0x0000,
                    core::cmp::Ordering::Greater => 0xFFFF,
                };
                e[*o..*o + 2].copy_from_slice(&unit.to_le_bytes());
            }
            self.write_entry(*pos, &e)?;
        }
        let sfn = slots[lfn_entries];
        let mut e = [0u8; ENTRY_SIZE];
        e[..11].copy_from_slice(&short);
        e[11] = attr;
        e[12] = nt;
        e[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        e[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
        // Creation, access and modification times.
        let (date, time) = self.timestamp();
        e[14..16].copy_from_slice(&time.to_le_bytes());
        e[16..18].copy_from_slice(&date.to_le_bytes());
        e[18..20].copy_from_slice(&date.to_le_bytes());
        e[22..24].copy_from_slice(&time.to_le_bytes());
        e[24..26].copy_from_slice(&date.to_le_bytes());
        self.write_entry(sfn, &e)?;
        Ok(sfn)
    }

    /// Marks every entry of `item` as deleted.
    pub(crate) fn remove_entries(&mut self, item: &Item) -> Result<()> {
        for pos in &item.slots {
            let mut e = self.read_entry(*pos)?;
            e[0] = 0xE5;
            self.write_entry(*pos, &e)?;
        }
        Ok(())
    }

    /// Updates first cluster and size in the short entry at `pos`.
    pub(crate) fn update_entry(&mut self, pos: Pos, first_cluster: u32, size: u32) -> Result<()> {
        let mut e = self.read_entry(pos)?;
        if e[0] == 0xE5 || e[0] == 0 {
            return Err(FsError::NotFound);
        }
        e[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        e[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
        if e[11] & ATTR_DIRECTORY == 0 {
            e[11] |= ATTR_ARCHIVE;
        }
        let (date, time) = self.timestamp();
        e[18..20].copy_from_slice(&date.to_le_bytes());
        e[22..24].copy_from_slice(&time.to_le_bytes());
        e[24..26].copy_from_slice(&date.to_le_bytes());
        self.write_entry(pos, &e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_specification_example() {
        // Checksum of "README  TXT" computed with the algorithm from the spec.
        let mut sum: u8 = 0;
        for &b in b"README  TXT" {
            sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
        }
        assert_eq!(sfn_checksum(b"README  TXT"), sum);
    }

    #[test]
    fn exact_short_names() {
        assert_eq!(exact_short("README.TXT"), Some((*b"README  TXT", 0)));
        assert_eq!(exact_short("readme.txt"), Some((*b"README  TXT", NT_LOWER_BASE | NT_LOWER_EXT)));
        assert_eq!(exact_short("README.txt"), Some((*b"README  TXT", NT_LOWER_EXT)));
        assert_eq!(exact_short("ReadMe.txt"), None, "mixed case needs a long name");
        assert_eq!(exact_short("longername.txt"), None);
        assert_eq!(exact_short("a.b.c"), None);
        assert_eq!(exact_short("with space"), None);
        assert_eq!(exact_short("NOEXT"), Some((*b"NOEXT      ", 0)));
    }

    #[test]
    fn short_aliases() {
        let (b, e) = short_basis("My Document.final.docx");
        assert_eq!(with_tail(&b, &e, 1), *b"MYDOCU~1DOC");
        assert_eq!(with_tail(&b, &e, 12), *b"MYDOC~12DOC");
        let (b, e) = short_basis(".hidden");
        assert_eq!(with_tail(&b, &e, 1), *b"HIDDEN~1   ");
        let (b, e) = short_basis("zażółć.txt");
        assert_eq!(with_tail(&b, &e, 1), *b"ZA____~1TXT");
    }

    #[test]
    fn name_validation() {
        assert!(validate_name("ok name.txt").is_ok());
        for bad in ["", ".", "..", "a/b", "a\\b", "x:y", "q?", "end.", "end ", "tab\t"] {
            assert_eq!(validate_name(bad).err(), Some(FsError::InvalidName), "{bad:?}");
        }
        let long: String = core::iter::repeat_n('x', 256).collect();
        assert_eq!(validate_name(&long).err(), Some(FsError::InvalidName));
    }

    #[test]
    fn short_display_honours_case_flags() {
        assert_eq!(short_display(b"HELLO   TXT", NT_LOWER_BASE | NT_LOWER_EXT), "hello.txt");
        assert_eq!(short_display(b"HELLO   TXT", 0), "HELLO.TXT");
        assert_eq!(short_display(b"NOEXT      ", 0), "NOEXT");
        assert_eq!(short_display(b"\x05BC     TXT", 0), "\u{e5}BC.TXT");
    }
}
