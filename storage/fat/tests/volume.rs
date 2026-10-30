//! End-to-end scenarios on in-memory volumes; every test finishes with the
//! consistency check (cluster accounting, chain lengths, FSInfo).

use osyx_fat::{format, BlockDevice, FileSystem, FsError, OpenOptions};

const MIB: usize = 1024 * 1024;

fn fresh(size: usize) -> FileSystem<Vec<u8>> {
    let mut img = vec![0u8; size];
    format(&mut img, "TESTVOL", 0x1234_5678).unwrap();
    FileSystem::mount(img).unwrap()
}

fn create() -> OpenOptions {
    OpenOptions { create: true, ..Default::default() }
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

fn check(fs: &mut FileSystem<Vec<u8>>) -> osyx_fat::CheckReport {
    fs.flush().unwrap();
    let r = fs.check().unwrap();
    assert!(r.fsinfo_accurate, "this driver must keep FSInfo exact");
    r
}

#[test]
fn format_and_mount() {
    let mut fs = fresh(64 * MIB);
    let g = *fs.geometry();
    assert_eq!(g.sectors_per_cluster, 1);
    assert_eq!(g.root_cluster, 2);
    assert!(g.cluster_count >= 65_525);
    assert_eq!(fs.label(), "TESTVOL");
    assert_eq!(fs.read_dir("/").unwrap(), vec![], "label entry is not listed");
    let r = check(&mut fs);
    assert_eq!((r.files, r.directories, r.used_clusters), (0, 1, 1));
    assert!(matches!(format(&mut vec![0u8; 16 * MIB], "X", 1), Err(FsError::Unsupported(_))), "too small for FAT32");
}

#[test]
fn files_round_trip_and_survive_remount() {
    let mut fs = fresh(64 * MIB);
    write_file(&mut fs, "/hello.txt", b"Hello, FAT32!\n");
    write_file(&mut fs, "/README", b"short upper-case name");
    let big = pattern(3 * MIB + 123, 7);
    write_file(&mut fs, "/big.bin", &big);
    assert_eq!(read_file(&mut fs, "/hello.txt"), b"Hello, FAT32!\n");
    let img = fs.unmount().unwrap();
    let mut fs = FileSystem::mount(img).unwrap();
    assert_eq!(read_file(&mut fs, "/HELLO.TXT"), b"Hello, FAT32!\n", "case-insensitive");
    assert_eq!(read_file(&mut fs, "/big.bin"), big);
    let mut names: Vec<String> = fs.read_dir("/").unwrap().into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, ["README", "big.bin", "hello.txt"]);
    let r = check(&mut fs);
    assert_eq!(r.files, 3);
    assert_eq!(fs.metadata("/big.bin").unwrap().size as usize, big.len());
}

#[test]
fn random_access_reads_and_overwrites() {
    let mut fs = fresh(64 * MIB);
    let data = pattern(200_000, 3);
    write_file(&mut fs, "/data", &data);
    let mut f = fs.open("/data", OpenOptions::default()).unwrap();
    for &(off, len) in &[(0usize, 1usize), (511, 2), (512, 512), (100_000, 4321), (199_990, 100)] {
        let mut buf = vec![0u8; len];
        let n = fs.read(&mut f, off as u64, &mut buf).unwrap();
        let end = (off + len).min(data.len());
        assert_eq!(&buf[..n], &data[off..end], "read at {off}");
    }
    assert_eq!(fs.read(&mut f, 200_000, &mut [0u8; 8]).unwrap(), 0, "EOF");
    fs.write(&mut f, 1000, b"OVERWRITE").unwrap();
    let mut buf = [0u8; 9];
    fs.read(&mut f, 1000, &mut buf).unwrap();
    assert_eq!(&buf, b"OVERWRITE");
    assert_eq!(f.size(), 200_000, "overwrite does not grow the file");
    check(&mut fs);
}

#[test]
fn sparse_extension_reads_zeros() {
    let mut fs = fresh(64 * MIB);
    let mut f = fs.open("/sparse", create()).unwrap();
    fs.write(&mut f, 0, b"head").unwrap();
    fs.write(&mut f, 10_000, b"tail").unwrap();
    let all = read_file(&mut fs, "/sparse");
    assert_eq!(all.len(), 10_004);
    assert_eq!(&all[..4], b"head");
    assert!(all[4..10_000].iter().all(|&b| b == 0), "gap must read as zeros");
    assert_eq!(&all[10_000..], b"tail");
    check(&mut fs);
}

#[test]
fn stale_data_never_becomes_visible() {
    let mut fs = fresh(64 * MIB);
    // Fill clusters with garbage, free them, then grow a new file over them.
    write_file(&mut fs, "/garbage", &vec![0xAA; 64 * 1024]);
    fs.remove_file("/garbage").unwrap();
    let mut f = fs.open("/new", create()).unwrap();
    fs.write(&mut f, 0, b"x").unwrap();
    fs.truncate(&mut f, 40_000).unwrap();
    fs.write(&mut f, 50_000, b"y").unwrap();
    let all = read_file(&mut fs, "/new");
    assert_eq!(all[0], b'x');
    assert_eq!(all[50_000], b'y');
    assert!(all[1..50_000].iter().all(|&b| b == 0));
    check(&mut fs);
}

#[test]
fn long_names_and_unicode() {
    let mut fs = fresh(64 * MIB);
    let names = [
        "A long file name with spaces.txt",
        "zażółć gęślą jaźń.md",
        "MixedCase.Txt",
        "many.dots.in.name.tar.gz",
        ".hidden",
        "Ünïcödé — ✓.bin",
        &"x".repeat(255),
    ];
    for (i, n) in names.iter().enumerate() {
        write_file(&mut fs, &format!("/{n}"), format!("file {i}").as_bytes());
    }
    let img = fs.unmount().unwrap();
    let mut fs = FileSystem::mount(img).unwrap();
    let listed: Vec<String> = fs.read_dir("/").unwrap().into_iter().map(|e| e.name).collect();
    for (i, n) in names.iter().enumerate() {
        assert!(listed.contains(&n.to_string()), "{n} not listed: {listed:?}");
        assert_eq!(read_file(&mut fs, &format!("/{n}")), format!("file {i}").as_bytes());
    }
    assert_eq!(read_file(&mut fs, "/ZAŻÓŁĆ GĘŚLĄ JAŹŃ.MD"), b"file 1", "Unicode case folding");
    assert_eq!(fs.open(&format!("/{}", "x".repeat(256)), create()).err(), Some(FsError::InvalidName));
    check(&mut fs);
}

#[test]
fn directories_nested_and_growing() {
    let mut fs = fresh(64 * MIB);
    fs.create_dir("/a").unwrap();
    fs.create_dir("/a/b").unwrap();
    fs.create_dir("/a/b/c").unwrap();
    write_file(&mut fs, "/a/b/c/deep.txt", b"deep");
    assert_eq!(read_file(&mut fs, "/a/./b/../b/c/deep.txt"), b"deep");
    assert_eq!(read_file(&mut fs, "/a/b/c/../../../a/b/c/deep.txt"), b"deep");
    assert_eq!(fs.create_dir("/a").err(), Some(FsError::AlreadyExists));
    assert_eq!(fs.create_dir("/missing/x").err(), Some(FsError::NotFound));
    assert_eq!(fs.open("/a/b/c/deep.txt/x", create()).err(), Some(FsError::NotADirectory));
    assert_eq!(fs.open("/a", OpenOptions::default()).err(), Some(FsError::IsADirectory));
    // 300 long-named files: the directory grows over many 512-byte clusters.
    for i in 0..300 {
        write_file(&mut fs, &format!("/a/b/entry number {i:04}.dat"), &[i as u8; 3]);
    }
    let list = fs.read_dir("/a/b").unwrap();
    assert_eq!(list.len(), 301, "300 files + directory c");
    for i in (0..300).step_by(37) {
        assert_eq!(read_file(&mut fs, &format!("/a/b/ENTRY NUMBER {i:04}.DAT")), [i as u8; 3]);
    }
    let r = check(&mut fs);
    assert_eq!((r.files, r.directories), (301, 4));
}

#[test]
fn removal_reuses_space() {
    let mut fs = fresh(64 * MIB);
    let free0 = fs.free_clusters();
    fs.create_dir("/d").unwrap();
    write_file(&mut fs, "/d/f1", &pattern(10_000, 1));
    assert_eq!(fs.remove_dir("/d").err(), Some(FsError::DirectoryNotEmpty));
    assert_eq!(fs.remove_file("/d").err(), Some(FsError::IsADirectory));
    assert_eq!(fs.remove_dir("/d/f1").err(), Some(FsError::NotADirectory));
    fs.remove_file("/d/f1").unwrap();
    assert_eq!(fs.remove_file("/d/f1").err(), Some(FsError::NotFound));
    fs.remove_dir("/d").unwrap();
    assert_eq!(fs.free_clusters(), free0, "all clusters returned");
    assert_eq!(fs.metadata("/d").err(), Some(FsError::NotFound));
    // Deleted slots are reused by later entries.
    for i in 0..50 {
        write_file(&mut fs, &format!("/tmp{i}"), b"t");
        fs.remove_file(&format!("/tmp{i}")).unwrap();
    }
    check(&mut fs);
}

#[test]
fn open_options_and_truncate() {
    let mut fs = fresh(64 * MIB);
    assert_eq!(fs.open("/nope", OpenOptions::default()).err(), Some(FsError::NotFound));
    write_file(&mut fs, "/f", &pattern(5000, 9));
    let new = OpenOptions { create: true, create_new: true, ..Default::default() };
    assert_eq!(fs.open("/f", new).err(), Some(FsError::AlreadyExists));
    let f = fs.open("/f", OpenOptions { truncate: true, ..Default::default() }).unwrap();
    assert_eq!(f.size(), 0);
    let mut f = fs.open("/f", OpenOptions::default()).unwrap();
    fs.write(&mut f, 0, &pattern(5000, 9)).unwrap();
    fs.truncate(&mut f, 700).unwrap();
    assert_eq!(read_file(&mut fs, "/f"), pattern(5000, 9)[..700]);
    fs.truncate(&mut f, 0).unwrap();
    assert_eq!(fs.metadata("/f").unwrap().first_cluster, 0);
    check(&mut fs);
}

#[test]
fn two_handles_see_each_others_writes() {
    let mut fs = fresh(64 * MIB);
    let mut a = fs.open("/shared", create()).unwrap();
    let mut b = fs.open("/shared", OpenOptions::default()).unwrap();
    fs.write(&mut a, 0, b"from a").unwrap();
    let mut buf = [0u8; 6];
    assert_eq!(fs.read(&mut b, 0, &mut buf).unwrap(), 6);
    assert_eq!(&buf, b"from a");
    fs.remove_file("/shared").unwrap();
    assert_eq!(fs.read(&mut a, 0, &mut buf).err(), Some(FsError::NotFound), "deleted under the handle");
    check(&mut fs);
}

#[test]
fn rename_and_move() {
    let mut fs = fresh(64 * MIB);
    fs.create_dir("/src").unwrap();
    fs.create_dir("/dst").unwrap();
    write_file(&mut fs, "/src/file.txt", b"payload");
    fs.rename("/src/file.txt", "/dst/renamed with long name.txt").unwrap();
    assert_eq!(fs.metadata("/src/file.txt").err(), Some(FsError::NotFound));
    assert_eq!(read_file(&mut fs, "/dst/renamed with long name.txt"), b"payload");
    // Replace an existing file.
    write_file(&mut fs, "/dst/old", b"old");
    fs.rename("/dst/renamed with long name.txt", "/dst/old").unwrap();
    assert_eq!(read_file(&mut fs, "/dst/old"), b"payload");
    // Case-only rename.
    fs.rename("/dst/old", "/dst/OLD").unwrap();
    assert_eq!(fs.read_dir("/dst").unwrap().len(), 1);
    // Move a directory and check its ".." follows.
    fs.create_dir("/src/sub").unwrap();
    write_file(&mut fs, "/src/sub/inner", b"in");
    fs.rename("/src/sub", "/dst/sub").unwrap();
    assert_eq!(read_file(&mut fs, "/dst/sub/../OLD"), b"payload");
    assert_eq!(read_file(&mut fs, "/dst/sub/inner"), b"in");
    assert!(matches!(fs.rename("/dst", "/dst/sub/loop"), Err(FsError::InvalidInput(_))));
    fs.create_dir("/other").unwrap();
    assert_eq!(fs.rename("/dst/OLD", "/other").err(), Some(FsError::AlreadyExists));
    check(&mut fs);
}

#[test]
fn directory_cannot_replace_file() {
    let mut fs = fresh(64 * MIB);
    fs.create_dir("/directory").unwrap();
    write_file(&mut fs, "/file", b"keep this data");
    assert_eq!(fs.rename("/directory", "/file"), Err(FsError::NotADirectory));
    assert!(fs.metadata("/directory").unwrap().is_dir);
    assert_eq!(read_file(&mut fs, "/file"), b"keep this data");
    check(&mut fs);
}

#[test]
fn cached_cluster_is_invalidated_after_another_handle_rewrites_chain() {
    let mut fs = fresh(64 * MIB);
    write_file(&mut fs, "/data", &vec![1; 1536]);
    let mut reader = fs.open("/data", OpenOptions::default()).unwrap();
    let mut writer = fs.open("/data", OpenOptions::default()).unwrap();
    let mut byte = [0];
    fs.read(&mut reader, 1024, &mut byte).unwrap();
    fs.truncate(&mut writer, 512).unwrap();
    write_file(&mut fs, "/other", &vec![9; 1024]);
    fs.truncate(&mut writer, 1536).unwrap();
    fs.read(&mut reader, 1024, &mut byte).unwrap();
    assert_eq!(byte, [0]);
    assert_eq!(read_file(&mut fs, "/other"), vec![9; 1024]);
    check(&mut fs);
}

#[test]
fn full_volume_reports_no_space_and_stays_consistent() {
    let mut fs = fresh(34 * MIB);
    let chunk = pattern(MIB, 1);
    let mut f = fs.open("/filler", create()).unwrap();
    let mut written = 0u64;
    loop {
        match fs.write(&mut f, written, &chunk) {
            Ok(n) => written += n as u64,
            Err(FsError::NoSpace) => break,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(written >= 30 * MIB as u64);
    // The failed write must not leave clusters beyond the file size.
    assert_eq!(fs.metadata("/filler").unwrap().size as u64, written);
    let r = check(&mut fs);
    assert_eq!(r.files, 1);
    assert_eq!(fs.open("/more", create()).map(|_| ()), Ok(()), "directory entries still fit");
    let mut g = fs.open("/more", OpenOptions::default()).unwrap();
    assert!(matches!(fs.write(&mut g, 0, &chunk), Err(FsError::NoSpace)));
    assert_eq!(fs.metadata("/more").unwrap().size, 0);
    check(&mut fs);
    fs.remove_file("/more").unwrap();
    fs.remove_file("/filler").unwrap();
    assert_eq!(check(&mut fs).used_clusters, 1);
}

#[test]
fn rejects_corrupted_volumes() {
    let mut img = vec![0u8; 64 * MIB];
    format(&mut img, "X", 1).unwrap();
    let mut bad = img.clone();
    bad[510] = 0;
    assert!(FileSystem::mount(bad).is_err());
    let mut bad = img.clone();
    bad[12] = 0x04; // bytes per sector = 1024
    assert!(FileSystem::mount(bad).is_err());
    let mut bad = img.clone();
    bad[13] = 3; // sectors per cluster not a power of two
    assert!(FileSystem::mount(bad).is_err());
    let mut bad = img.clone();
    bad[17] = 0xE0; // root entries: FAT16 style
    assert!(matches!(FileSystem::mount(bad).err(), Some(FsError::Unsupported(_))));
    let mut bad = img.clone();
    bad[44..48].copy_from_slice(&u32::MAX.to_le_bytes()); // root cluster
    assert!(FileSystem::mount(bad).is_err());
    // A FAT entry pointing to itself: reading must stop, not hang.
    let mut fs = FileSystem::mount(img).unwrap();
    write_file(&mut fs, "/loop", &pattern(2048, 2));
    let first = fs.metadata("/loop").unwrap().first_cluster;
    let mut img = fs.unmount().unwrap();
    let g_fat = 32 * 512 + first as usize * 4;
    img[g_fat..g_fat + 4].copy_from_slice(&first.to_le_bytes());
    let mut fs = FileSystem::mount(img).unwrap();
    assert!(matches!(fs.check(), Err(FsError::Corrupt(_))));
    assert!(fs.remove_file("/loop").is_err());
}

#[test]
fn rejects_nonempty_file_without_first_cluster() {
    let mut fs = fresh(64 * MIB);
    write_file(&mut fs, "/broken.bin", b"data");
    let g = *fs.geometry();
    let mut image = fs.unmount().unwrap();
    let root = (g.data_start + (g.root_cluster - 2) * g.sectors_per_cluster) as usize * 512;
    let entry = image[root..root + g.cluster_bytes() as usize]
        .as_chunks::<32>().0.iter()
        .position(|entry| &entry[..11] == b"BROKEN  BIN")
        .unwrap();
    let entry = root + entry * 32;
    image[entry + 20..entry + 22].fill(0);
    image[entry + 26..entry + 28].fill(0);
    let mut fs = FileSystem::mount(image).unwrap();
    let mut file = fs.open("/broken.bin", OpenOptions::default()).unwrap();
    assert!(matches!(fs.read(&mut file, 0, &mut [0; 1]), Err(FsError::Corrupt(_))));
    assert!(matches!(fs.write(&mut file, 0, b"x"), Err(FsError::Corrupt(_))));
}

#[test]
fn rejects_directory_without_first_cluster() {
    let mut fs = fresh(64 * MIB);
    fs.create_dir("/broken").unwrap();
    write_file(&mut fs, "/protected", b"keep");
    let g = *fs.geometry();
    let mut image = fs.unmount().unwrap();
    let root = (g.data_start + (g.root_cluster - 2) * g.sectors_per_cluster) as usize * 512;
    let entry = image[root..root + g.cluster_bytes() as usize]
        .as_chunks::<32>().0.iter()
        .position(|entry| &entry[..11] == b"BROKEN     ")
        .unwrap();
    let entry = root + entry * 32;
    image[entry + 20..entry + 22].fill(0);
    image[entry + 26..entry + 28].fill(0);
    let mut fs = FileSystem::mount(image).unwrap();
    assert!(matches!(fs.read_dir("/broken"), Err(FsError::Corrupt(_))));
    assert!(matches!(fs.remove_file("/broken/protected"), Err(FsError::Corrupt(_))));
    assert_eq!(read_file(&mut fs, "/protected"), b"keep");
}

#[test]
fn rejects_invalid_parent_directory_cluster() {
    let mut fs = fresh(64 * MIB);
    fs.create_dir("/child").unwrap();
    write_file(&mut fs, "/protected", b"keep");
    let cluster = fs.metadata("/child").unwrap().first_cluster;
    let g = *fs.geometry();
    let mut image = fs.unmount().unwrap();
    let child = (g.data_start + (cluster - 2) * g.sectors_per_cluster) as usize * 512;
    assert_eq!(&image[child + 32..child + 43], b"..         ");
    image[child + 32 + 26..child + 32 + 28].copy_from_slice(&1u16.to_le_bytes());
    let mut fs = FileSystem::mount(image).unwrap();
    assert!(matches!(fs.metadata("/child/../protected"), Err(FsError::Corrupt(_))));
    assert!(matches!(fs.create_dir("/child/../new"), Err(FsError::Corrupt(_))));
    assert_eq!(read_file(&mut fs, "/protected"), b"keep");
}

#[test]
fn block_device_bounds() {
    let mut img = vec![0u8; 4096];
    let mut buf = [0u8; 512];
    assert!(img.read_sectors(7, &mut buf).is_ok());
    assert!(img.read_sectors(8, &mut buf).is_err());
    assert!(img.write_sectors(u64::MAX, &buf).is_err());
}

#[test]
fn root_directory_label_wins_over_the_boot_sector() {
    // Windows stores a label it sets only in the root directory entry.
    let mut img = vec![0u8; 64 * MIB];
    format(&mut img, "NO NAME", 1).unwrap();
    let fs = FileSystem::mount(img.clone()).unwrap();
    let root = fs.geometry().data_start as usize * 512;
    assert_eq!(fs.label(), "NO NAME");
    img[root..root + 11].copy_from_slice(b"PENDRIVE   ");
    assert_eq!(FileSystem::mount(img).unwrap().label(), "PENDRIVE");
}
