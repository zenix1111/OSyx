//! gzip (RFC 1952) decompression: header, deflate stream, CRC-32 and size
//! check. Multi-member files are not supported.

use crate::zip::crc32;
use alloc::string::String;
use alloc::vec::Vec;

/// The decompressed data and the original file name stored in the header,
/// if any. `limit` bounds the output size.
pub fn decompress(data: &[u8], limit: usize) -> Result<(Vec<u8>, Option<String>), String> {
    if data.len() < 18 || data[0] != 0x1F || data[1] != 0x8B {
        return Err(String::from("not a gzip file"));
    }
    if data[2] != 8 {
        return Err(String::from("unsupported gzip compression method"));
    }
    let flags = data[3];
    let mut p = 10;
    if flags & 4 != 0 {
        let n = u16::from_le_bytes([*data.get(p).ok_or("truncated gzip header")?, *data.get(p + 1).ok_or("truncated gzip header")?]) as usize;
        p += 2 + n;
    }
    let mut name = None;
    for bit in [8u8, 16] {
        if flags & bit != 0 {
            let end = data.get(p..).and_then(|r| r.iter().position(|&b| b == 0)).ok_or("truncated gzip header")?;
            if bit == 8 {
                name = Some(String::from_utf8_lossy(&data[p..p + end]).into_owned());
            }
            p += end + 1;
        }
    }
    if flags & 2 != 0 {
        p += 2;
    }
    let trailer = data.len().checked_sub(8).filter(|&t| t >= p).ok_or("truncated gzip file")?;
    let out = miniz_oxide::inflate::decompress_to_vec_with_limit(&data[p..trailer], limit)
        .map_err(|e| alloc::format!("gzip data damaged or too large: {:?}", e.status))?;
    let crc = u32::from_le_bytes(data[trailer..trailer + 4].try_into().unwrap());
    let size = u32::from_le_bytes(data[trailer + 4..].try_into().unwrap());
    if crc != crc32(&out) || size != out.len() as u32 {
        return Err(String::from("gzip checksum mismatch: the file is damaged"));
    }
    Ok((out, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gz(data: &[u8], name: Option<&str>) -> Vec<u8> {
        let mut v = alloc::vec![0x1F, 0x8B, 8, if name.is_some() { 8 } else { 0 }, 0, 0, 0, 0, 0, 3];
        if let Some(n) = name {
            v.extend_from_slice(n.as_bytes());
            v.push(0);
        }
        v.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
        v.extend_from_slice(&crc32(data).to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v
    }

    #[test]
    fn round_trip_and_damage() {
        let text = b"gzip gzip gzip gzip".repeat(50);
        let (out, name) = decompress(&gz(&text, Some("a.txt")), 1 << 20).unwrap();
        assert_eq!(out, text);
        assert_eq!(name.as_deref(), Some("a.txt"));
        let mut bad = gz(&text, None);
        let n = bad.len();
        bad[n - 6] ^= 1;
        assert!(decompress(&bad, 1 << 20).unwrap_err().contains("checksum"));
        assert!(decompress(&gz(&text, None), 100).is_err(), "output limit");
        assert!(decompress(b"plain text, not gzip at all", 100).is_err());
    }
}
