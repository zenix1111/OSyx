//! GUID partition tables (UEFI specification 2.10, chapter 5).
//!
//! [`parse`] reads the primary header at LBA 1 and falls back to the
//! backup header at the last LBA when the primary one is damaged. Both the
//! header CRC32 and the partition array CRC32 are verified, every field is
//! range-checked against the disk size, and overlapping or out-of-range
//! partitions are rejected. [`build`] produces the primary and backup
//! structures for a new disk (protective MBR included).

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub const SECTOR: usize = 512;
const SIGNATURE: &[u8; 8] = b"EFI PART";
const REVISION: u32 = 0x0001_0000;
const HEADER_SIZE: usize = 92;
const ENTRY_SIZE: usize = 128;
/// Entries written by [`build`] (the minimum the specification requires space for).
pub const ENTRY_COUNT: usize = 128;
const MAX_ENTRIES: u32 = 4096;

/// A GUID in its on-disk (mixed-endian) byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// Parses the textual form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    pub const fn parse(s: &str) -> Guid {
        let b = s.as_bytes();
        const fn hex(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("bad hex digit"),
            }
        }
        const fn byte(b: &[u8], i: usize) -> u8 {
            hex(b[i]) << 4 | hex(b[i + 1])
        }
        assert!(b.len() == 36);
        // Text byte offsets of the 16 bytes in on-disk order.
        let pos = [6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34];
        let mut out = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            out[i] = byte(b, pos[i]);
            i += 1;
        }
        Guid(out)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }
}

impl core::fmt::Display for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

/// EFI system partition.
pub const TYPE_ESP: Guid = Guid::parse("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
/// Root file system for x86-64 (Discoverable Partitions Specification).
pub const TYPE_ROOT_X86_64: Guid = Guid::parse("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709");
/// Generic Linux file system data.
pub const TYPE_LINUX_DATA: Guid = Guid::parse("0FC63DAF-8483-4772-8E79-3D69D8477DE4");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    /// 1-based slot number in the partition array.
    pub number: u32,
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: String,
}

impl Partition {
    pub fn sectors(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub disk_guid: Guid,
    pub first_usable: u64,
    pub last_usable: u64,
    pub partitions: Vec<Partition>,
    /// True if the primary header was damaged and the backup was used.
    pub used_backup: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GptError {
    /// No GPT signature at either header location.
    NotGpt,
    /// A header or array failed validation (both copies).
    Corrupt(&'static str),
    Io,
}

/// Reads sectors; implemented by callers for their device type.
pub trait SectorReader {
    fn sectors(&self) -> u64;
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), GptError>;
}

static CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// CRC-32 (IEEE 802.3), as used by GPT.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().expect("4 bytes"))
}

fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"))
}

fn read_header<R: SectorReader>(r: &mut R, lba: u64) -> Result<Table, GptError> {
    let disk = r.sectors();
    let mut h = [0u8; SECTOR];
    r.read(lba, &mut h)?;
    if &h[0..8] != SIGNATURE {
        return Err(GptError::NotGpt);
    }
    let size = le32(&h, 12) as usize;
    if le32(&h, 8) != REVISION || !(HEADER_SIZE..=SECTOR).contains(&size) {
        return Err(GptError::Corrupt("unsupported header revision or size"));
    }
    let mut copy = h;
    copy[16..20].fill(0);
    if crc32(&copy[..size]) != le32(&h, 16) {
        return Err(GptError::Corrupt("header CRC mismatch"));
    }
    if le64(&h, 24) != lba {
        return Err(GptError::Corrupt("header is not where it says it is"));
    }
    let (first, last) = (le64(&h, 40), le64(&h, 48));
    let entries_lba = le64(&h, 72);
    let count = le32(&h, 80);
    let esize = le32(&h, 84) as usize;
    if esize < ENTRY_SIZE || !esize.is_multiple_of(8) || esize > SECTOR * 8 || count == 0 || count > MAX_ENTRIES {
        return Err(GptError::Corrupt("bad partition entry geometry"));
    }
    if first < 2 || last >= disk - 1 || first > last {
        return Err(GptError::Corrupt("usable range outside the disk"));
    }
    let bytes = count as usize * esize;
    let array_sectors = bytes.div_ceil(SECTOR) as u64;
    if entries_lba < 2 || entries_lba.checked_add(array_sectors).is_none_or(|e| e > disk - 1) {
        return Err(GptError::Corrupt("partition array outside the disk"));
    }
    // The array must not overlap the usable area.
    if entries_lba < first && entries_lba + array_sectors > first || entries_lba >= first && entries_lba <= last {
        return Err(GptError::Corrupt("partition array overlaps the usable area"));
    }
    let mut array = vec![0u8; array_sectors as usize * SECTOR];
    r.read(entries_lba, &mut array)?;
    if crc32(&array[..bytes]) != le32(&h, 88) {
        return Err(GptError::Corrupt("partition array CRC mismatch"));
    }
    let mut partitions = Vec::new();
    for i in 0..count as usize {
        let e = &array[i * esize..i * esize + ENTRY_SIZE];
        let type_guid = Guid(e[0..16].try_into().expect("16 bytes"));
        if type_guid.is_zero() {
            continue;
        }
        let (fl, ll) = (le64(e, 32), le64(e, 40));
        if fl < first || ll > last || fl > ll {
            return Err(GptError::Corrupt("partition outside the usable range"));
        }
        let units: Vec<u16> = (0..36).map(|k| u16::from_le_bytes([e[56 + 2 * k], e[57 + 2 * k]])).take_while(|&u| u != 0).collect();
        partitions.push(Partition {
            number: i as u32 + 1,
            type_guid,
            unique_guid: Guid(e[16..32].try_into().expect("16 bytes")),
            first_lba: fl,
            last_lba: ll,
            attributes: le64(e, 48),
            name: char::decode_utf16(units).map(|c| c.unwrap_or('\u{FFFD}')).collect(),
        });
    }
    let mut sorted: Vec<&Partition> = partitions.iter().collect();
    sorted.sort_by_key(|p| p.first_lba);
    if sorted.windows(2).any(|w| w[1].first_lba <= w[0].last_lba) {
        return Err(GptError::Corrupt("partitions overlap"));
    }
    Ok(Table {
        disk_guid: Guid(h[56..72].try_into().expect("16 bytes")),
        first_usable: first,
        last_usable: last,
        partitions,
        used_backup: false,
    })
}

/// Reads the partition table of a disk.
pub fn parse<R: SectorReader>(r: &mut R) -> Result<Table, GptError> {
    if r.sectors() < 3 {
        return Err(GptError::NotGpt);
    }
    match read_header(r, 1) {
        Ok(t) => Ok(t),
        Err(primary) => {
            let backup = r.sectors() - 1;
            match read_header(r, backup) {
                Ok(mut t) => {
                    t.used_backup = true;
                    Ok(t)
                }
                Err(GptError::NotGpt) => Err(primary),
                Err(e) => Err(if primary == GptError::NotGpt { e } else { primary }),
            }
        }
    }
}

/// A partition to create with [`build`].
pub struct NewPartition<'a> {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub sectors: u64,
    pub name: &'a str,
}

/// The sectors of a new GPT: `(lba, data)` pairs to write (protective MBR,
/// primary header and array, backup array and header).
pub fn build(disk_sectors: u64, disk_guid: Guid, parts: &[NewPartition<'_>]) -> Result<Vec<(u64, Vec<u8>)>, GptError> {
    let array_sectors = (ENTRY_COUNT * ENTRY_SIZE / SECTOR) as u64;
    let first = 2 + array_sectors;
    let last = disk_sectors.checked_sub(2 + array_sectors).ok_or(GptError::Corrupt("disk too small"))?;
    if parts.len() > ENTRY_COUNT || first > last {
        return Err(GptError::Corrupt("disk too small"));
    }
    let mut array = vec![0u8; ENTRY_COUNT * ENTRY_SIZE];
    let mut ranges = Vec::with_capacity(parts.len());
    for (i, p) in parts.iter().enumerate() {
        if p.type_guid.is_zero() {
            return Err(GptError::Corrupt("partition type is zero"));
        }
        let end = p.sectors.checked_sub(1).and_then(|n| p.first_lba.checked_add(n)).ok_or(GptError::Corrupt("partition outside the usable range"))?;
        if p.first_lba < first || end > last {
            return Err(GptError::Corrupt("partition outside the usable range"));
        }
        if ranges.iter().any(|&(start, stop)| p.first_lba <= stop && start <= end) {
            return Err(GptError::Corrupt("partitions overlap"));
        }
        ranges.push((p.first_lba, end));
        let e = &mut array[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE];
        e[0..16].copy_from_slice(&p.type_guid.0);
        e[16..32].copy_from_slice(&p.unique_guid.0);
        e[32..40].copy_from_slice(&p.first_lba.to_le_bytes());
        e[40..48].copy_from_slice(&end.to_le_bytes());
        for (k, u) in p.name.encode_utf16().take(36).enumerate() {
            e[56 + 2 * k..58 + 2 * k].copy_from_slice(&u.to_le_bytes());
        }
    }
    let array_crc = crc32(&array);
    let header = |my: u64, alt: u64, entries: u64| {
        let mut h = vec![0u8; SECTOR];
        h[0..8].copy_from_slice(SIGNATURE);
        h[8..12].copy_from_slice(&REVISION.to_le_bytes());
        h[12..16].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        h[24..32].copy_from_slice(&my.to_le_bytes());
        h[32..40].copy_from_slice(&alt.to_le_bytes());
        h[40..48].copy_from_slice(&first.to_le_bytes());
        h[48..56].copy_from_slice(&last.to_le_bytes());
        h[56..72].copy_from_slice(&disk_guid.0);
        h[72..80].copy_from_slice(&entries.to_le_bytes());
        h[80..84].copy_from_slice(&(ENTRY_COUNT as u32).to_le_bytes());
        h[84..88].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
        h[88..92].copy_from_slice(&array_crc.to_le_bytes());
        let crc = crc32(&h[..HEADER_SIZE]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };
    let backup_lba = disk_sectors - 1;
    let mut mbr = vec![0u8; SECTOR];
    // One protective partition of type 0xEE covering the disk (capped).
    let pe = &mut mbr[446..462];
    pe[1..4].copy_from_slice(&[0x00, 0x02, 0x00]);
    pe[4] = 0xEE;
    pe[5..8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    pe[8..12].copy_from_slice(&1u32.to_le_bytes());
    pe[12..16].copy_from_slice(&((disk_sectors - 1).min(u32::MAX as u64) as u32).to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    Ok(vec![
        (0, mbr),
        (1, header(1, backup_lba, 2)),
        (2, array.clone()),
        (backup_lba - array_sectors, array),
        (backup_lba, header(backup_lba, 1, backup_lba - array_sectors)),
    ])
}
