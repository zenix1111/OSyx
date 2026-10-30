//! POSIX ustar archives: headers to write them piece by piece (a file of
//! any size needs no buffer) and a reader for extraction.

use alloc::string::String;
use alloc::vec::Vec;

const BLOCK: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
}

fn octal(field: &mut [u8], value: u64) {
    // Zero-padded octal, NUL-terminated, in the width of the field.
    let digits = field.len() - 1;
    let mut v = value;
    for i in (0..digits).rev() {
        field[i] = b'0' + (v & 7) as u8;
        v >>= 3;
    }
    field[digits] = 0;
}

/// The 512-byte header of an entry. `path` uses `/`; a directory path gets a
/// trailing slash. Fails if the path does not fit ustar's name and prefix.
pub fn header(path: &str, kind: EntryKind, size: u64, mode: u32, mtime: u64) -> Result<[u8; BLOCK], String> {
    let mut path = String::from(path.trim_start_matches('/'));
    if kind == EntryKind::Dir && !path.ends_with('/') {
        path.push('/');
    }
    let bytes = path.as_bytes();
    let (prefix, name) = if bytes.len() <= 100 {
        (&bytes[..0], bytes)
    } else {
        // Split at a slash so that the name fits in 100 and the prefix in 155 bytes.
        let cut = (0..bytes.len().saturating_sub(1))
            .rfind(|&i| bytes[i] == b'/' && i <= 155 && bytes.len() - i - 1 <= 100)
            .ok_or_else(|| alloc::format!("path too long for tar: {path}"))?;
        (&bytes[..cut], &bytes[cut + 1..])
    };
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name);
    octal(&mut h[100..108], (mode & 0o7777) as u64);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], if kind == EntryKind::File { size } else { 0 });
    octal(&mut h[136..148], mtime);
    h[148..156].fill(b' ');
    h[156] = if kind == EntryKind::Dir { b'5' } else { b'0' };
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix);
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    octal(&mut h[148..155], sum as u64);
    h[154] = 0;
    h[155] = b' ';
    Ok(h)
}

/// Zero bytes that bring `size` up to a whole number of blocks.
pub fn padding(size: u64) -> usize {
    ((BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64) as usize
}

/// The end of an archive: two empty blocks.
pub const END: [u8; 2 * BLOCK] = [0; 2 * BLOCK];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    pub mode: u32,
    pub mtime: u64,
    /// Where the data lies in the archive bytes.
    pub data: core::ops::Range<usize>,
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let text: Vec<u8> = field.iter().copied().take_while(|&b| b != 0).filter(|&b| b != b' ').collect();
    if text.is_empty() {
        return Some(0);
    }
    text.iter().try_fold(0u64, |acc, &b| (b'0'..=b'7').contains(&b).then(|| acc.checked_mul(8)?.checked_add((b - b'0') as u64)).flatten())
}

/// All entries of a plain tar archive. Links, devices and other types are
/// skipped; a damaged header (bad checksum) ends the listing with an error.
pub fn parse(data: &[u8]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + BLOCK <= data.len() {
        let h = &data[pos..pos + BLOCK];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let stored = parse_octal(&h[148..156]).ok_or("bad tar checksum field")?;
        let sum: u32 = h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { b' ' as u32 } else { b as u32 }).sum();
        if stored != sum as u64 {
            return Err(String::from("tar header checksum mismatch: not a tar archive or damaged"));
        }
        let field = |r: core::ops::Range<usize>| -> String {
            let b = &h[r];
            String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
        };
        let name = field(0..100);
        let prefix = if &h[257..262] == b"ustar" { field(345..500) } else { String::new() };
        let path = if prefix.is_empty() { name } else { alloc::format!("{prefix}/{name}") };
        let size = parse_octal(&h[124..136]).ok_or("bad tar size")? as usize;
        let start = pos + BLOCK;
        let end = start.checked_add(size).filter(|&e| e <= data.len()).ok_or("tar entry runs past the end of the archive")?;
        let kind = match h[156] {
            b'0' | 0 => Some(EntryKind::File),
            b'5' => Some(EntryKind::Dir),
            _ => None,
        };
        if let Some(kind) = kind {
            out.push(Entry {
                path: String::from(path.trim_end_matches('/')),
                kind,
                mode: parse_octal(&h[100..108]).unwrap_or(0o644) as u32,
                mtime: parse_octal(&h[136..148]).unwrap_or(0),
                data: start..end,
            });
        }
        pos = start + size + padding(size as u64);
    }
    Ok(out)
}

/// Whether an archive path may be extracted below a folder: relative, no
/// `..`, no empty names.
pub fn safe_path(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('/') && path.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn pack(items: &[(&str, EntryKind, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (p, k, d) in items {
            out.extend_from_slice(&header(p, *k, d.len() as u64, 0o644, 1_700_000_000).unwrap());
            out.extend_from_slice(d);
            out.extend(vec![0u8; padding(d.len() as u64)]);
        }
        out.extend_from_slice(&END);
        out
    }

    #[test]
    fn round_trip() {
        let long = alloc::format!("{}/{}", "d".repeat(120), "f".repeat(60));
        let tar = pack(&[("dir", EntryKind::Dir, b""), ("dir/a.txt", EntryKind::File, b"hello"), (&long, EntryKind::File, &[7u8; 1000])]);
        assert_eq!(tar.len() % 512, 0);
        let e = parse(&tar).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!((e[0].path.as_str(), e[0].kind), ("dir", EntryKind::Dir));
        assert_eq!(&tar[e[1].data.clone()], b"hello");
        assert_eq!(e[1].mode, 0o644);
        assert_eq!(e[1].mtime, 1_700_000_000);
        assert_eq!(e[2].path, long);
        assert_eq!(e[2].data.len(), 1000);
    }

    #[test]
    fn paths_that_cannot_be_written() {
        assert!(header(&"x".repeat(300), EntryKind::File, 0, 0o644, 0).is_err());
        // A long name with no slash to split at.
        assert!(header(&"x".repeat(150), EntryKind::File, 0, 0o644, 0).is_err());
    }

    #[test]
    fn damaged_archives() {
        let mut tar = pack(&[("a", EntryKind::File, b"x")]);
        tar[10] ^= 1;
        assert!(parse(&tar).is_err());
        let mut tar = pack(&[("a", EntryKind::File, &[1u8; 600])]);
        tar.truncate(700);
        assert!(parse(&tar).is_err());
        assert!(parse(b"too short").unwrap().is_empty());
    }

    #[test]
    fn extraction_paths() {
        assert!(safe_path("a/b.txt"));
        assert!(!safe_path("../x"));
        assert!(!safe_path("/etc/passwd"));
        assert!(!safe_path("a/../../x"));
        assert!(!safe_path("a//b"));
        assert!(!safe_path(""));
    }

    #[test]
    fn checksum_matches_the_specification() {
        // A header's checksum field is the sum of all bytes with the field read as spaces.
        let h = header("a.txt", EntryKind::File, 3, 0o600, 0).unwrap();
        let sum: u32 = h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { b as u32 }).sum();
        assert_eq!(parse_octal(&h[148..156]), Some(sum as u64));
        assert_eq!(h[154], 0);
        assert_eq!(h[155], b' ');
    }
}
