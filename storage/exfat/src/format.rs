//! Creating an exFAT volume.

use crate::{boot_checksum, default_upcase, table_checksum, BlockDevice, FsError, Result, FAT_EOC, SECTOR_SIZE};
use alloc::vec;
use alloc::vec::Vec;

const FAT_OFFSET: u32 = 128;
const MIN_SECTORS: u64 = 4096;

fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

/// Formats `dev` as exFAT with the volume `label` (up to 11 characters).
/// The cluster size follows the volume size like Windows picks it: 4 KiB up
/// to 256 MiB, 32 KiB up to 32 GiB, 128 KiB beyond.
pub fn format<D: BlockDevice>(dev: &mut D, label: &str, serial: u32) -> Result<()> {
    let total = dev.sector_count();
    if total < MIN_SECTORS {
        return Err(FsError::Unsupported("volume smaller than 2 MiB"));
    }
    let label16: Vec<u16> = label.encode_utf16().collect();
    if label16.len() > 11 || label16.iter().any(|&u| u < 0x20) {
        return Err(FsError::InvalidInput("label must be up to 11 printable characters"));
    }
    let bytes = total * SECTOR_SIZE as u64;
    let spc_shift: u32 = if bytes <= 256 << 20 {
        3
    } else if bytes <= 32 << 30 {
        6
    } else {
        8
    };
    let spc = 1u64 << spc_shift;
    let cb = spc * SECTOR_SIZE as u64;

    // The FAT and the heap size each other: iterate until they agree.
    let mut heap_offset = align_up(FAT_OFFSET as u64 + 8, spc);
    let mut fat_length = 0u64;
    for _ in 0..4 {
        let cluster_count = (total - heap_offset) / spc;
        fat_length = ((cluster_count + 2) * 4).div_ceil(SECTOR_SIZE as u64);
        heap_offset = align_up(FAT_OFFSET as u64 + fat_length, spc);
    }
    let cluster_count = (total - heap_offset) / spc;
    if !(16..=0xFFFF_FFF5).contains(&cluster_count) {
        return Err(FsError::Unsupported("volume size"));
    }

    let upcase = default_upcase();
    let upcase_bytes: Vec<u8> = upcase.iter().flat_map(|u| u.to_le_bytes()).collect();
    let bitmap_len = cluster_count.div_ceil(8);
    let bitmap_clusters = bitmap_len.div_ceil(cb);
    let upcase_clusters = (upcase_bytes.len() as u64).div_ceil(cb);
    let bitmap_first = 2u32;
    let upcase_first = bitmap_first + bitmap_clusters as u32;
    let root_first = upcase_first + upcase_clusters as u32;
    let used = root_first as u64 - 2 + 1;
    if used > cluster_count {
        return Err(FsError::Unsupported("volume too small"));
    }

    let zeros = vec![0u8; 64 * SECTOR_SIZE];
    let zero_range = |dev: &mut D, mut lba: u64, mut sectors: u64| -> Result<()> {
        while sectors > 0 {
            let n = sectors.min(64);
            dev.write_sectors(lba, &zeros[..n as usize * SECTOR_SIZE])?;
            lba += n;
            sectors -= n;
        }
        Ok(())
    };

    // FAT: media descriptor, reserved entry, and the system files' chains.
    zero_range(dev, FAT_OFFSET as u64, fat_length)?;
    let mut fat = vec![0u8; (fat_length as usize) * SECTOR_SIZE];
    let mut put = |c: u32, v: u32| fat[c as usize * 4..c as usize * 4 + 4].copy_from_slice(&v.to_le_bytes());
    put(0, 0xFFFF_FFF8);
    put(1, 0xFFFF_FFFF);
    let mut chain = |first: u32, n: u64| {
        for k in 0..n {
            let c = first + k as u32;
            put(c, if k + 1 < n { c + 1 } else { FAT_EOC });
        }
    };
    chain(bitmap_first, bitmap_clusters);
    chain(upcase_first, upcase_clusters);
    chain(root_first, 1);
    // Only the part of the FAT that holds entries.
    let fat_used = (root_first as usize + 1) * 4;
    let fat_sectors = fat_used.div_ceil(SECTOR_SIZE);
    dev.write_sectors(FAT_OFFSET as u64, &fat[..fat_sectors * SECTOR_SIZE])?;

    // Cluster heap: bitmap, up-case table, root directory.
    let heap_lba = heap_offset;
    zero_range(dev, heap_lba, (root_first as u64 - 1) * spc)?;
    let mut bitmap = vec![0u8; (bitmap_clusters * cb) as usize];
    for i in 0..used as usize {
        bitmap[i / 8] |= 1 << (i % 8);
    }
    dev.write_sectors(heap_lba, &bitmap)?;
    let mut table = upcase_bytes.clone();
    table.resize((upcase_clusters * cb) as usize, 0);
    dev.write_sectors(heap_lba + bitmap_clusters * spc, &table)?;
    let mut root = vec![0u8; cb as usize];
    root[0] = 0x83;
    root[1] = label16.len() as u8;
    for (i, u) in label16.iter().enumerate() {
        root[2 + i * 2..4 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    root[32] = 0x81;
    root[32 + 20..32 + 24].copy_from_slice(&bitmap_first.to_le_bytes());
    root[32 + 24..32 + 32].copy_from_slice(&bitmap_len.to_le_bytes());
    root[64] = 0x82;
    root[64 + 4..64 + 8].copy_from_slice(&table_checksum(&upcase_bytes).to_le_bytes());
    root[64 + 20..64 + 24].copy_from_slice(&upcase_first.to_le_bytes());
    root[64 + 24..64 + 32].copy_from_slice(&(upcase_bytes.len() as u64).to_le_bytes());
    dev.write_sectors(heap_lba + (root_first as u64 - 2) * spc, &root)?;

    // Boot region: main at 0..=11, the same again at 12..=23.
    let mut region = vec![0u8; 12 * SECTOR_SIZE];
    {
        let v = &mut region[..SECTOR_SIZE];
        v[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        v[3..11].copy_from_slice(b"EXFAT   ");
        v[64..72].copy_from_slice(&0u64.to_le_bytes());
        v[72..80].copy_from_slice(&total.to_le_bytes());
        v[80..84].copy_from_slice(&FAT_OFFSET.to_le_bytes());
        v[84..88].copy_from_slice(&(fat_length as u32).to_le_bytes());
        v[88..92].copy_from_slice(&(heap_offset as u32).to_le_bytes());
        v[92..96].copy_from_slice(&(cluster_count as u32).to_le_bytes());
        v[96..100].copy_from_slice(&root_first.to_le_bytes());
        v[100..104].copy_from_slice(&serial.to_le_bytes());
        v[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
        v[106..108].copy_from_slice(&0u16.to_le_bytes());
        v[108] = 9;
        v[109] = spc_shift as u8;
        v[110] = 1;
        v[111] = 0x80;
        v[112] = (used * 100 / cluster_count) as u8;
        v[120..510].fill(0xF4);
        v[510] = 0x55;
        v[511] = 0xAA;
    }
    for s in 1..9 {
        region[s * SECTOR_SIZE + 510] = 0x55;
        region[s * SECTOR_SIZE + 511] = 0xAA;
    }
    let sum = boot_checksum(&region[..11 * SECTOR_SIZE]);
    for i in 0..SECTOR_SIZE / 4 {
        region[11 * SECTOR_SIZE + i * 4..11 * SECTOR_SIZE + i * 4 + 4].copy_from_slice(&sum.to_le_bytes());
    }
    dev.write_sectors(0, &region)?;
    dev.write_sectors(12, &region)?;
    dev.flush()
}
