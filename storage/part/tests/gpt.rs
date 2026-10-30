use osyx_part::*;
use std::process::Command;

struct Mem(Vec<u8>);

impl SectorReader for Mem {
    fn sectors(&self) -> u64 {
        (self.0.len() / SECTOR) as u64
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), GptError> {
        let o = lba as usize * SECTOR;
        let src = self.0.get(o..o + buf.len()).ok_or(GptError::Io)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

fn disk(mib: u64) -> (Mem, Vec<NewPartition<'static>>) {
    let parts = vec![
        NewPartition { type_guid: TYPE_ESP, unique_guid: Guid([1; 16]), first_lba: 2048, sectors: 8192, name: "EFI system" },
        NewPartition { type_guid: TYPE_ROOT_X86_64, unique_guid: Guid([2; 16]), first_lba: 10240, sectors: 4096, name: "ROOT ŻÓŁW" },
    ];
    let mut img = vec![0u8; (mib << 20) as usize];
    for (lba, data) in build(mib << 11, Guid([9; 16]), &parts).unwrap() {
        img[lba as usize * SECTOR..lba as usize * SECTOR + data.len()].copy_from_slice(&data);
    }
    (Mem(img), parts)
}

#[test]
fn guid_text_round_trip() {
    assert_eq!(TYPE_ESP.to_string(), "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    assert_eq!(TYPE_ESP.0[0], 0x28, "first field is little-endian on disk");
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn build_then_parse() {
    let (mut d, parts) = disk(8);
    let t = parse(&mut d).unwrap();
    assert!(!t.used_backup);
    assert_eq!(t.disk_guid, Guid([9; 16]));
    assert_eq!(t.partitions.len(), 2);
    for (p, n) in t.partitions.iter().zip(&parts) {
        assert_eq!((p.type_guid, p.first_lba, p.sectors(), p.name.as_str()), (n.type_guid, n.first_lba, n.sectors, n.name));
    }
    assert_eq!(t.partitions[1].number, 2);
}

#[test]
fn damaged_primary_falls_back_to_backup() {
    let (mut d, _) = disk(8);
    d.0[SECTOR + 30] ^= 0xFF; // primary header field
    let t = parse(&mut d).unwrap();
    assert!(t.used_backup);
    assert_eq!(t.partitions.len(), 2);
    // Damaged primary array: CRC mismatch, backup used.
    let (mut d, _) = disk(8);
    d.0[2 * SECTOR + 40] ^= 1;
    assert!(parse(&mut d).unwrap().used_backup);
}

#[test]
fn primary_io_error_falls_back_to_backup() {
    struct FailingPrimary(Mem, u64);
    impl SectorReader for FailingPrimary {
        fn sectors(&self) -> u64 { self.0.sectors() }
        fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), GptError> {
            if lba == self.1 { Err(GptError::Io) } else { self.0.read(lba, buf) }
        }
    }
    for failing_lba in [1, 2] {
        let (disk, _) = disk(8);
        let table = parse(&mut FailingPrimary(disk, failing_lba)).unwrap();
        assert!(table.used_backup);
        assert_eq!(table.partitions.len(), 2);
    }
    let (mut disk, _) = disk(8);
    let backup = disk.0.len() - SECTOR;
    disk.0[backup] = 0;
    assert_eq!(parse(&mut FailingPrimary(disk, 1)), Err(GptError::Io));
}

#[test]
fn corrupt_tables_are_rejected() {
    let (mut d, _) = disk(8);
    let last = d.0.len() - SECTOR;
    d.0[SECTOR + 30] ^= 0xFF;
    d.0[last + 30] ^= 0xFF;
    assert!(matches!(parse(&mut d), Err(GptError::Corrupt(_))));
    assert_eq!(parse(&mut Mem(vec![0; 1 << 20])), Err(GptError::NotGpt));
    assert_eq!(parse(&mut Mem(vec![0; 512])), Err(GptError::NotGpt));
    // Overlapping and out-of-range partitions are refused by the writer too.
    let bad = [
        NewPartition { type_guid: TYPE_ESP, unique_guid: Guid([1; 16]), first_lba: 2048, sectors: 100, name: "" },
        NewPartition { type_guid: TYPE_ESP, unique_guid: Guid([1; 16]), first_lba: 1 << 30, sectors: 100, name: "" },
    ];
    assert!(build(1 << 14, Guid([0; 16]), &bad).is_err());
}

#[test]
fn build_rejects_overlaps_and_invalid_lengths() {
    let part = |first_lba, sectors| NewPartition { type_guid: TYPE_ESP, unique_guid: Guid([1; 16]), first_lba, sectors, name: "" };
    assert!(build(1 << 14, Guid([9; 16]), &[part(2048, 100), part(2147, 20)]).is_err());
    assert!(build(1 << 14, Guid([9; 16]), &[part(2048, 0)]).is_err());
    assert!(build(1 << 14, Guid([9; 16]), &[part(u64::MAX, 2)]).is_err());
    assert!(build(1 << 14, Guid([9; 16]), &[part(2148, 20), part(2048, 100)]).is_ok());
}

#[test]
fn build_rejects_unused_partition_type() {
    let p = NewPartition { type_guid: Guid([0; 16]), unique_guid: Guid([1; 16]), first_lba: 2048, sectors: 100, name: "missing" };
    assert_eq!(build(1 << 14, Guid([9; 16]), &[p]), Err(GptError::Corrupt("partition type is zero")));
}

#[test]
fn rejects_usable_range_covering_backup_header() {
    let (mut d, _) = disk(8);
    let backup = d.sectors() - 1;
    let h = &mut d.0[SECTOR..2 * SECTOR];
    h[48..56].copy_from_slice(&backup.to_le_bytes());
    h[16..20].fill(0);
    let crc = crc32(&h[..92]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    assert!(parse(&mut d).unwrap().used_backup);
}

#[test]
fn rejects_partition_array_covering_backup_header() {
    let (mut d, _) = disk(8);
    let backup = d.sectors() - 1;
    let offset = backup as usize * SECTOR;
    d.0[offset + 32..offset + 40].copy_from_slice(&2048u64.to_le_bytes());
    d.0[offset + 40..offset + 48].copy_from_slice(&2048u64.to_le_bytes());
    let array_crc = crc32(&d.0[offset..offset + 128]);
    let h = &mut d.0[SECTOR..2 * SECTOR];
    h[72..80].copy_from_slice(&backup.to_le_bytes());
    h[80..84].copy_from_slice(&1u32.to_le_bytes());
    h[88..92].copy_from_slice(&array_crc.to_le_bytes());
    h[16..20].fill(0);
    let crc = crc32(&h[..92]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    assert!(matches!(parse(&mut d), Err(GptError::Corrupt(_))));
}

/// Flips every byte of the primary header and array one at a time: parsing
/// must never panic, and must either succeed via the backup or fail cleanly.
#[test]
fn single_byte_corruptions_never_panic() {
    let (mut d, _) = disk(8);
    for off in SECTOR..SECTOR * 34 {
        d.0[off] ^= 0x5A;
        match parse(&mut d) {
            Ok(t) => assert_eq!(t.partitions.len(), 2, "offset {off}"),
            Err(e) => panic!("offset {off}: backup should have saved us: {e:?}"),
        }
        d.0[off] ^= 0x5A;
    }
}

fn wsl(cmd: &str) -> Option<std::process::Output> {
    Command::new("wsl.exe").args(["-d", "Ubuntu-24.04", "--", "bash", "-lc", cmd]).output().ok().filter(|o| o.status.code().is_some())
}

fn wsl_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    let (drive, rest) = s.split_once(':').expect("absolute Windows path");
    format!("/mnt/{}{}", drive.to_lowercase(), rest)
}

/// Cross-check with sgdisk (an independent GPT implementation) when WSL is
/// available: it must accept our table, and we must read its tables.
#[test]
fn interoperates_with_sgdisk() {
    if wsl("command -v sgdisk").is_none_or(|o| !o.status.success()) {
        eprintln!("SKIPPED: sgdisk not available through WSL");
        return;
    }
    let dir = std::env::temp_dir().join(format!("osyx-gpt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ours = dir.join("ours.img");
    let (d, _) = disk(8);
    std::fs::write(&ours, &d.0).unwrap();
    let o = wsl(&format!("sgdisk -v '{}'", wsl_path(&ours))).unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success() && text.contains("No problems found"), "sgdisk -v: {text}");
    let theirs = dir.join("theirs.img");
    std::fs::write(&theirs, vec![0u8; 16 << 20]).unwrap();
    let o = wsl(&format!(
        "sgdisk -n 1:2048:+4M -t 1:EF00 -c 1:boot -n 2:0:0 -t 2:8304 -c 2:root '{}'",
        wsl_path(&theirs)
    ))
    .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let t = parse(&mut Mem(std::fs::read(&theirs).unwrap())).unwrap();
    assert_eq!(t.partitions.len(), 2);
    assert_eq!((t.partitions[0].type_guid, t.partitions[0].first_lba, t.partitions[0].name.as_str()), (TYPE_ESP, 2048, "boot"));
    assert_eq!(t.partitions[1].type_guid, TYPE_ROOT_X86_64);
    let _ = std::fs::remove_dir_all(&dir);
}

fn mbr_disk(entries: &[(u8, u8, u32, u32)], sectors: usize) -> Mem {
    let mut img = vec![0u8; sectors * SECTOR];
    for (i, &(flag, kind, first, count)) in entries.iter().enumerate() {
        let e = &mut img[446 + i * 16..446 + (i + 1) * 16];
        e[0] = flag;
        e[4] = kind;
        e[8..12].copy_from_slice(&first.to_le_bytes());
        e[12..16].copy_from_slice(&count.to_le_bytes());
    }
    img[510] = 0x55;
    img[511] = 0xAA;
    Mem(img)
}

#[test]
fn mbr_primary_entries() {
    let mut d = mbr_disk(&[(0x80, 0x07, 2048, 4096), (0, 0x83, 8192, 1024), (0, 0, 0, 0), (0, 0x0F, 9300, 100)], 16384);
    let e = parse_mbr(&mut d).unwrap();
    assert_eq!(e.len(), 2, "empty slot and extended container are left out");
    assert_eq!((e[0].number, e[0].kind, e[0].bootable, e[0].first_lba, e[0].sectors), (1, 0x07, true, 2048, 4096));
    assert_eq!((e[1].number, e[1].kind, e[1].bootable), (2, 0x83, false));
}

#[test]
fn mbr_rejects_garbage() {
    // Overlapping, bad boot flag, beyond the disk.
    let mut d = mbr_disk(&[(0, 0x07, 2048, 4096), (0, 0x0C, 3000, 100), (0x40, 0x07, 6500, 100), (0, 0x07, 7990, 100)], 8000);
    let e = parse_mbr(&mut d).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].number, 1);
    let mut none = Mem(vec![0u8; 8 * SECTOR]);
    assert_eq!(parse_mbr(&mut none), Err(GptError::NotGpt));
}

#[test]
fn volume_boot_record_is_not_an_mbr() {
    // A FAT32 boot sector has the 0x55AA signature too.
    let mut d = Mem(vec![0u8; 64 * SECTOR]);
    d.0[0] = 0xEB;
    d.0[11..13].copy_from_slice(&512u16.to_le_bytes());
    d.0[13] = 8;
    d.0[510] = 0x55;
    d.0[511] = 0xAA;
    d.0[446 + 4] = 0x0C;
    d.0[446 + 8] = 1;
    d.0[446 + 12] = 4;
    assert_eq!(parse_mbr(&mut d), Err(GptError::NotGpt));
    // exFAT: zeros where the BIOS parameter block would be.
    let mut x = Mem(vec![0u8; 64 * SECTOR]);
    x.0[0] = 0xEB;
    x.0[3..11].copy_from_slice(b"EXFAT   ");
    x.0[510] = 0x55;
    x.0[511] = 0xAA;
    assert_eq!(parse_mbr(&mut x), Err(GptError::NotGpt));
}
