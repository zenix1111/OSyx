//! End-to-end scenarios on in-memory volumes; every test ends with the
//! consistency check (bitmap against the files' clusters, free count).

use osyx_exfat::{entry_set_checksum, format, BlockDevice, FileSystem, FsError, OpenOptions};

const MIB: usize = 1024 * 1024;

fn fresh(size: usize) -> FileSystem<Vec<u8>> {
    let mut img = vec![0u8; size];
    format(&mut img, "TESTVOL", 0x1234_5678).unwrap();
    FileSystem::mount(img).unwrap()
}

fn write_file(fs: &mut FileSystem<Vec<u8>>, path: &str, data: &[u8]) {
    let mut f = fs.open(path, OpenOptions { create: true, truncate: true, ..Default::default() }).unwrap();
    assert_eq!(fs.write(&mut f, 0, data).unwrap(), data.len());
}

fn read_file(fs: &mut FileSystem<Vec<u8>>, path: &str) -> Vec<u8> {
    let mut f = fs.open(path, OpenOptions::default()).unwrap();
    let mut buf = vec![0u8; f.size() as usize];
    assert_eq!(fs.read(&mut f, 0, &mut buf).unwrap(), buf.len());
    buf
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn check(fs: &mut FileSystem<Vec<u8>>) -> osyx_exfat::CheckReport {
    fs.check().expect("consistency check")
}

fn remount(fs: FileSystem<Vec<u8>>) -> FileSystem<Vec<u8>> {
    FileSystem::mount(fs.unmount().unwrap()).unwrap()
}

#[test]
fn format_and_mount() {
    let mut fs = fresh(64 * MIB);
    let g = *fs.geometry();
    assert_eq!(g.cluster_bytes(), 4096);
    assert_eq!(g.bytes_per_sector_shift, 9);
    assert_eq!(fs.label(), "TESTVOL");
    assert_eq!(g.serial, 0x1234_5678);
    assert!(!fs.is_suspect() && !fs.was_dirty());
    assert_eq!(fs.read_dir("/").unwrap(), vec![], "system entries are not listed");
    let r = check(&mut fs);
    assert_eq!((r.files, r.directories), (0, 1));
    assert!(fs.free_bytes() > 60 * MIB as u64);
    assert!(matches!(format(&mut vec![0u8; MIB], "X", 1), Err(FsError::Unsupported(_))), "too small");
    assert!(matches!(format(&mut vec![0u8; 8 * MIB], "TWELVE-CHARS", 1), Err(FsError::InvalidInput(_))), "label too long");
}

#[test]
fn not_an_exfat_volume() {
    let img = vec![0u8; 8 * MIB];
    assert!(matches!(FileSystem::mount(img), Err(FsError::Unsupported(_))));
    let mut img = vec![0u8; 8 * MIB];
    format(&mut img, "X", 1).unwrap();
    img[20] = 1; // MustBeZero
    assert!(matches!(FileSystem::mount(img), Err(FsError::Corrupt(_))));
}

#[test]
fn files_and_directories() {
    let mut fs = fresh(32 * MIB);
    fs.create_dir("/docs").unwrap();
    fs.create_dir("/docs/deep").unwrap();
    write_file(&mut fs, "/hello.txt", b"hello exFAT\n");
    write_file(&mut fs, "/docs/deep/data.bin", &pattern(100_000, 1));
    assert_eq!(read_file(&mut fs, "/hello.txt"), b"hello exFAT\n");
    assert_eq!(read_file(&mut fs, "/docs/deep/data.bin"), pattern(100_000, 1));
    let names: Vec<String> = fs.read_dir("/").unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"docs".to_string()) && names.contains(&"hello.txt".to_string()));
    let md = fs.metadata("/docs").unwrap();
    assert!(md.is_dir);
    assert_eq!(fs.metadata("/hello.txt").unwrap().size, 12);
    assert_eq!(fs.read_dir("/hello.txt"), Err(FsError::NotADirectory));
    assert_eq!(fs.open("/nope", OpenOptions::default()).err(), Some(FsError::NotFound));
    assert_eq!(fs.create_dir("/docs").err(), Some(FsError::AlreadyExists));
    assert_eq!(fs.remove_dir("/docs").err(), Some(FsError::DirectoryNotEmpty));
    assert_eq!(fs.remove_file("/docs").err(), Some(FsError::IsADirectory));
    assert_eq!(fs.remove_dir("/hello.txt").err(), Some(FsError::NotADirectory));
    let r = check(&mut fs);
    assert_eq!((r.files, r.directories), (2, 3));
    let mut fs = remount(fs);
    assert_eq!(read_file(&mut fs, "/docs/deep/data.bin"), pattern(100_000, 1));
    fs.remove_file("/docs/deep/data.bin").unwrap();
    fs.remove_dir("/docs/deep").unwrap();
    fs.remove_dir("/docs").unwrap();
    fs.remove_file("/hello.txt").unwrap();
    let r = check(&mut fs);
    assert_eq!((r.files, r.directories), (0, 1));
}

#[test]
fn names_case_and_unicode() {
    let mut fs = fresh(16 * MIB);
    write_file(&mut fs, "/Zażółć gęślą jaźń.txt", b"pl");
    write_file(&mut fs, "/MiXeD.Case", b"mixed");
    assert_eq!(read_file(&mut fs, "/mixed.case"), b"mixed");
    assert_eq!(read_file(&mut fs, "/MIXED.CASE"), b"mixed");
    assert_eq!(read_file(&mut fs, "/ZAŻÓŁĆ GĘŚLĄ JAŹŃ.TXT"), b"pl");
    assert_eq!(fs.create_dir("/MIXED.case").err(), Some(FsError::AlreadyExists));
    let long = "n".repeat(255);
    write_file(&mut fs, &format!("/{long}"), b"long");
    assert_eq!(read_file(&mut fs, &format!("/{long}")), b"long");
    for bad in ["/a?b", "/a:b", "/a\\b", "/a|b", "/a\"b", "/a<b", "/a*b", &format!("/{}", "n".repeat(256))] {
        assert_eq!(fs.open(bad, OpenOptions { create: true, ..Default::default() }).err(), Some(FsError::InvalidName), "{bad}");
    }
    assert!(fs.open("/a/../b", OpenOptions::default()).is_err());
    check(&mut fs);
}

#[test]
fn large_file_and_partial_writes() {
    let mut fs = fresh(32 * MIB);
    let data = pattern(5 * MIB + 123, 7);
    write_file(&mut fs, "/big.bin", &data);
    assert_eq!(read_file(&mut fs, "/big.bin"), data);
    // Overwrite in the middle, across cluster borders.
    let mut f = fs.open("/big.bin", OpenOptions::default()).unwrap();
    let patch = pattern(10_000, 9);
    fs.write(&mut f, 4090, &patch).unwrap();
    let mut expect = data.clone();
    expect[4090..4090 + 10_000].copy_from_slice(&patch);
    let mut back = vec![0u8; 20_000];
    assert_eq!(fs.read(&mut f, 4000, &mut back).unwrap(), 20_000);
    assert_eq!(back, expect[4000..24_000]);
    // Append.
    let tail = pattern(70_000, 11);
    fs.write(&mut f, data.len() as u64, &tail).unwrap();
    expect.extend_from_slice(&tail);
    check(&mut fs);
    let mut fs = remount(fs);
    assert_eq!(read_file(&mut fs, "/big.bin"), expect);
    check(&mut fs);
}

#[test]
fn truncate_and_sparse_writes() {
    let mut fs = fresh(16 * MIB);
    write_file(&mut fs, "/t.bin", &pattern(20_000, 3));
    let mut f = fs.open("/t.bin", OpenOptions::default()).unwrap();
    fs.truncate(&mut f, 5000).unwrap();
    assert_eq!(fs.metadata("/t.bin").unwrap().size, 5000);
    check(&mut fs);
    // Growing: the new part reads as zero even over stale cluster contents.
    fs.truncate(&mut f, 30_000).unwrap();
    let mut buf = vec![0xAAu8; 30_000];
    assert_eq!(fs.read(&mut f, 0, &mut buf).unwrap(), 30_000);
    assert_eq!(&buf[..5000], &pattern(20_000, 3)[..5000]);
    assert!(buf[5000..].iter().all(|&b| b == 0));
    // A write past the end leaves a zero gap, also over a reused cluster.
    write_file(&mut fs, "/junk.bin", &vec![0xEEu8; 64 * 1024]);
    fs.remove_file("/junk.bin").unwrap();
    let mut g = fs.open("/gap.bin", OpenOptions { create: true, ..Default::default() }).unwrap();
    fs.write(&mut g, 50_000, b"end").unwrap();
    let all = read_file(&mut fs, "/gap.bin");
    assert_eq!(all.len(), 50_003);
    assert!(all[..50_000].iter().all(|&b| b == 0), "gap is zero");
    assert_eq!(&all[50_000..], b"end");
    fs.truncate(&mut g, 0).unwrap();
    assert_eq!(fs.metadata("/gap.bin").unwrap().size, 0);
    check(&mut fs);
    let mut fs = remount(fs);
    assert_eq!(fs.metadata("/t.bin").unwrap().size, 30_000);
    check(&mut fs);
}

#[test]
fn directory_grows_and_shrinks_in_use() {
    let mut fs = fresh(32 * MIB);
    fs.create_dir("/many").unwrap();
    for i in 0..600 {
        write_file(&mut fs, &format!("/many/file-{i:04}-with-a-long-name-to-need-several-entries.txt"), format!("{i}").as_bytes());
    }
    assert_eq!(fs.read_dir("/many").unwrap().len(), 600);
    assert_eq!(read_file(&mut fs, "/many/file-0599-with-a-long-name-to-need-several-entries.txt"), b"599");
    check(&mut fs);
    for i in (0..600).step_by(2) {
        fs.remove_file(&format!("/many/file-{i:04}-with-a-long-name-to-need-several-entries.txt")).unwrap();
    }
    assert_eq!(fs.read_dir("/many").unwrap().len(), 300);
    // Freed entry slots are reused.
    for i in 0..300 {
        write_file(&mut fs, &format!("/many/again-{i:03}.txt"), b"x");
    }
    assert_eq!(fs.read_dir("/many").unwrap().len(), 600);
    let r = check(&mut fs);
    assert_eq!(r.files, 600);
    let mut fs = remount(fs);
    assert_eq!(fs.read_dir("/many").unwrap().len(), 600);
    check(&mut fs);
}

#[test]
fn rename_and_move() {
    let mut fs = fresh(16 * MIB);
    fs.create_dir("/a").unwrap();
    fs.create_dir("/b").unwrap();
    write_file(&mut fs, "/a/one.txt", b"one");
    write_file(&mut fs, "/a/two.txt", b"two");
    fs.rename("/a/one.txt", "/b/uno.txt").unwrap();
    assert_eq!(read_file(&mut fs, "/b/uno.txt"), b"one");
    assert_eq!(fs.open("/a/one.txt", OpenOptions::default()).err(), Some(FsError::NotFound));
    // Case-only change of the same entry.
    fs.rename("/b/uno.txt", "/b/UNO.TXT").unwrap();
    assert_eq!(fs.read_dir("/b").unwrap()[0].name, "UNO.TXT");
    // An existing file is replaced; an existing directory is not.
    fs.rename("/a/two.txt", "/b/UNO.TXT").unwrap();
    assert_eq!(read_file(&mut fs, "/b/uno.txt"), b"two");
    assert_eq!(fs.rename("/a", "/b").err(), Some(FsError::AlreadyExists));
    // Moving a directory with content; into itself is refused.
    write_file(&mut fs, "/a/inner.txt", b"inner");
    fs.rename("/a", "/b/moved").unwrap();
    assert_eq!(read_file(&mut fs, "/b/moved/inner.txt"), b"inner");
    assert!(matches!(fs.rename("/b", "/b/moved/x"), Err(FsError::InvalidInput(_))));
    assert!(matches!(fs.rename("/", "/x"), Err(FsError::InvalidInput(_))));
    check(&mut fs);
    let mut fs = remount(fs);
    assert_eq!(read_file(&mut fs, "/b/moved/inner.txt"), b"inner");
    check(&mut fs);
}

#[test]
fn no_space_is_clean() {
    let mut fs = fresh(4 * MIB);
    let free = fs.free_bytes();
    let mut f = fs.open("/fill.bin", OpenOptions { create: true, ..Default::default() }).unwrap();
    let chunk = pattern(64 * 1024, 5);
    let mut written = 0u64;
    loop {
        match fs.write(&mut f, written, &chunk) {
            Ok(n) => written += n as u64,
            Err(FsError::NoSpace) => break,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(written > free / 2, "most of the free space was usable");
    // The failed write left everything consistent and the file readable.
    check(&mut fs);
    assert_eq!(fs.metadata("/fill.bin").unwrap().size, written);
    fs.remove_file("/fill.bin").unwrap();
    assert_eq!(fs.free_bytes(), free);
    check(&mut fs);
    // A large truncate that cannot fit leaves the file unchanged.
    write_file(&mut fs, "/small", b"s");
    let mut s = fs.open("/small", OpenOptions::default()).unwrap();
    assert_eq!(fs.truncate(&mut s, 1 << 30).err(), Some(FsError::NoSpace));
    assert_eq!(fs.metadata("/small").unwrap().size, 1);
    check(&mut fs);
}

#[test]
fn contiguous_files_from_other_systems() {
    // Windows writes most files with NoFatChain: no FAT entries at all.
    let mut fs = fresh(16 * MIB);
    let data = pattern(40_000, 21);
    write_file(&mut fs, "/contig.bin", &data);
    let g = *fs.geometry();
    let mut img = fs.unmount().unwrap();
    let root = (g.heap_offset as usize * 512) + (g.root_cluster as usize - 2) * g.cluster_bytes() as usize;
    let mut patched = None;
    for i in 0..(g.cluster_bytes() as usize / 32) {
        let e = root + i * 32;
        if img[e] == 0x85 {
            let count = img[e + 1] as usize + 1;
            img[e + 32 + 1] |= 0x02;
            let sum = entry_set_checksum(&img[e..e + count * 32]);
            img[e + 2..e + 4].copy_from_slice(&sum.to_le_bytes());
            let first = u32::from_le_bytes(img[e + 32 + 20..e + 32 + 24].try_into().unwrap());
            patched = Some(first);
            break;
        }
    }
    let first = patched.expect("file entry") as usize;
    let fat = g.fat_offset as usize * 512;
    for c in first..first + 40_000usize.div_ceil(4096) {
        img[fat + c * 4..fat + c * 4 + 4].fill(0);
    }
    let mut fs = FileSystem::mount(img).unwrap();
    assert_eq!(read_file(&mut fs, "/contig.bin"), data, "read without FAT entries");
    // Growing converts it to a chain.
    let mut f = fs.open("/contig.bin", OpenOptions::default()).unwrap();
    let more = pattern(30_000, 22);
    fs.write(&mut f, 40_000, &more).unwrap();
    let mut all = data.clone();
    all.extend_from_slice(&more);
    assert_eq!(read_file(&mut fs, "/contig.bin"), all);
    check(&mut fs);
    fs.truncate(&mut f, 1000).unwrap();
    fs.remove_file("/contig.bin").unwrap();
    check(&mut fs);
}

#[test]
fn dirty_flag_and_suspect_volumes() {
    let mut fs = fresh(8 * MIB);
    let flags = |img: &Vec<u8>| u16::from_le_bytes([img[106], img[107]]);
    write_file(&mut fs, "/a", b"a");
    // Dirty on the medium until flushed.
    let mut img = fs.unmount().unwrap();
    assert_eq!(flags(&img) & 2, 0, "unmount flushes and clears VolumeDirty");
    let mut fs = FileSystem::mount(img.clone()).unwrap();
    write_file(&mut fs, "/b", b"b");
    let mut dev = fs.unmount().unwrap();
    assert_eq!(flags(&dev) & 2, 0);
    // A volume left dirty (pulled out) stays dirty after our use.
    dev[106] |= 2;
    let mut fs = FileSystem::mount(dev).unwrap();
    assert!(fs.was_dirty());
    write_file(&mut fs, "/c", b"c");
    let dev = fs.unmount().unwrap();
    assert_eq!(flags(&dev) & 2, 2);
    // A damaged boot region is reported.
    img[300] ^= 0xFF;
    assert!(FileSystem::mount(img).unwrap().is_suspect());
}

#[test]
fn unplugged_device_reports_io_errors() {
    struct Dying {
        inner: Vec<u8>,
        alive: bool,
    }
    impl BlockDevice for Dying {
        fn sector_count(&self) -> u64 {
            self.inner.sector_count()
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> osyx_exfat::Result<()> {
            if self.alive { self.inner.read_sectors(lba, buf) } else { Err(FsError::Io) }
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> osyx_exfat::Result<()> {
            if self.alive { self.inner.write_sectors(lba, buf) } else { Err(FsError::Io) }
        }
    }
    let mut img = vec![0u8; 16 * MIB];
    format(&mut img, "DYING", 1).unwrap();
    let mut fs = FileSystem::mount(Dying { inner: img, alive: true }).unwrap();
    let mut f = fs.open("/x", OpenOptions { create: true, ..Default::default() }).unwrap();
    fs.write(&mut f, 0, &pattern(20_000, 1)).unwrap();
    fs.flush().unwrap();
    fs.device_mut().alive = false;
    let mut buf = [0u8; 100];
    assert_eq!(fs.write(&mut f, 0, b"zzz").err(), Some(FsError::Io));
    assert_eq!(fs.create_dir("/d").err(), Some(FsError::Io));
    assert_eq!(fs.read_dir("/").err(), Some(FsError::Io));
    assert!(fs.read(&mut f, 100_000, &mut buf).is_ok(), "past the end needs no I/O");
    assert_eq!(fs.flush().err(), Some(FsError::Io));
}
