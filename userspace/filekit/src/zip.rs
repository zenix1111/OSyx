//! ZIP archives, read only: the central directory, stored and deflated
//! entries, CRC-32 checked. No encryption, no ZIP64, no multi-disk archives.

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub is_dir: bool,
    pub method: u16,
    pub compressed: u32,
    pub size: u32,
    pub crc: u32,
    /// Offset of the local header.
    pub offset: u32,
}

fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

/// The entries of the archive in `data`.
pub fn list(data: &[u8]) -> Result<Vec<Entry>, String> {
    // The end of central directory record is within the last 64 KiB + 22 bytes.
    let from = data.len().saturating_sub(22 + 65_535);
    let eocd = (from..=data.len().saturating_sub(22))
        .rev()
        .find(|&i| data.get(i..i + 4) == Some(b"PK\x05\x06"))
        .ok_or("not a ZIP archive (no end of central directory)")?;
    let count = le16(data, eocd + 10).ok_or("truncated")? as usize;
    let dir_off = le32(data, eocd + 16).ok_or("truncated")? as usize;
    if le16(data, eocd + 4) != Some(0) || count == 0xFFFF || dir_off == 0xFFFF_FFFF {
        return Err(String::from("multi-disk and ZIP64 archives are not supported"));
    }
    let mut out = Vec::new();
    let mut p = dir_off;
    for _ in 0..count {
        if data.get(p..p + 4) != Some(b"PK\x01\x02") {
            return Err(String::from("damaged ZIP central directory"));
        }
        let flags = le16(data, p + 8).ok_or("truncated")?;
        let method = le16(data, p + 10).ok_or("truncated")?;
        let name_len = le16(data, p + 28).ok_or("truncated")? as usize;
        let extra = le16(data, p + 30).ok_or("truncated")? as usize;
        let comment = le16(data, p + 32).ok_or("truncated")? as usize;
        let name = data.get(p + 46..p + 46 + name_len).ok_or("truncated")?;
        if flags & 1 != 0 {
            return Err(String::from("encrypted ZIP archives are not supported"));
        }
        let path = String::from_utf8_lossy(name).into_owned();
        out.push(Entry {
            is_dir: path.ends_with('/'),
            path: String::from(path.trim_end_matches('/')),
            method,
            compressed: le32(data, p + 20).ok_or("truncated")?,
            size: le32(data, p + 24).ok_or("truncated")?,
            crc: le32(data, p + 16).ok_or("truncated")?,
            offset: le32(data, p + 42).ok_or("truncated")?,
        });
        p += 46 + name_len + extra + comment;
    }
    Ok(out)
}

/// The contents of an entry, checked against its CRC-32.
pub fn extract(data: &[u8], e: &Entry) -> Result<Vec<u8>, String> {
    let l = e.offset as usize;
    if data.get(l..l + 4) != Some(b"PK\x03\x04") {
        return Err(alloc::format!("{}: damaged local header", e.path));
    }
    let name_len = le16(data, l + 26).ok_or("truncated")? as usize;
    let extra = le16(data, l + 28).ok_or("truncated")? as usize;
    let start = l + 30 + name_len + extra;
    let raw = data.get(start..start + e.compressed as usize).ok_or_else(|| alloc::format!("{}: truncated", e.path))?;
    let out = match e.method {
        0 => raw.to_vec(),
        8 => miniz_oxide::inflate::decompress_to_vec_with_limit(raw, e.size as usize).map_err(|err| alloc::format!("{}: {:?}", e.path, err.status))?,
        m => return Err(alloc::format!("{}: compression method {m} is not supported", e.path)),
    };
    if out.len() != e.size as usize || crc32(&out) != e.crc {
        return Err(alloc::format!("{}: CRC mismatch, the archive is damaged", e.path));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    fn local(name: &str, data: &[u8], method: u16, stored: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"PK\x03\x04");
        v.extend_from_slice(&[20, 0, 0, 0]);
        v.extend_from_slice(&method.to_le_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&crc32(data).to_le_bytes());
        v.extend_from_slice(&(stored.len() as u32).to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(stored);
        v
    }

    fn build(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data, deflate) in files {
            let offset = out.len() as u32;
            let stored = if *deflate { miniz_oxide::deflate::compress_to_vec(data, 6) } else { data.to_vec() };
            let method = if *deflate { 8 } else { 0 };
            out.extend(local(name, data, method, &stored));
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            central.extend_from_slice(&(method as u16).to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0]);
            central.extend_from_slice(&crc32(data).to_le_bytes());
            central.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let dir_off = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&dir_off.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn stored_and_deflated_entries() {
        let text = b"hello hello hello hello hello hello zip".repeat(20);
        let zip = build(&[("a.txt", b"plain", false), ("dir/", b"", false), ("dir/b.txt", &text, true)]);
        let e = list(&zip).unwrap();
        assert_eq!(e.len(), 3);
        assert!(e[1].is_dir);
        assert_eq!(e[1].path, "dir");
        assert_eq!(extract(&zip, &e[0]).unwrap(), b"plain");
        assert_eq!(e[2].method, 8);
        assert!(e[2].compressed < e[2].size);
        assert_eq!(extract(&zip, &e[2]).unwrap(), text);
    }

    #[test]
    fn damage_is_noticed() {
        let mut zip = build(&[("a.txt", b"payload", false)]);
        let e = list(&zip).unwrap();
        let at = e[0].offset as usize + 30 + 5;
        zip[at] ^= 0xFF;
        assert!(extract(&zip, &e[0]).unwrap_err().contains("CRC"));
        assert!(list(b"not a zip at all").is_err());
        assert!(list(&vec![0u8; 10]).is_err());
    }

    #[test]
    fn crc_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
