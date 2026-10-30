//! Write tests. Every scenario ends with the image checked by e2fsck (an
//! independent implementation) when WSL with e2fsprogs is available, and
//! with the driver's own consistency check.

use osyx_ext4::{format, BlockDevice, Error, Ext4, FormatOptions, MountOptions, NewKind, ROOT_INO};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(format!("{name}.img"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn clock() -> (i64, u32) {
    (1_761_200_000, 123_456_789)
}

fn rw<D: BlockDevice>(dev: D) -> Ext4<D> {
    Ext4::mount(dev, MountOptions { read_only: false, clock: Some(clock) }).unwrap_or_else(|e| panic!("rw mount: {e}"))
}

fn ro(img: Vec<u8>) -> Ext4<Vec<u8>> {
    Ext4::mount(img, MountOptions { read_only: true, clock: None }).unwrap()
}

fn pattern(n: usize, seed: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 13 + seed) % 241) as u8).collect()
}

fn read_all<D: BlockDevice>(fs: &mut Ext4<D>, ino: u32) -> Vec<u8> {
    let size = fs.stat(ino).unwrap().size as usize;
    let mut buf = vec![0u8; size];
    let mut done = 0;
    while done < size {
        let n = fs.read(ino, done as u64, &mut buf[done..]).unwrap();
        assert!(n > 0);
        done += n;
    }
    buf
}

fn write_all<D: BlockDevice>(fs: &mut Ext4<D>, ino: u32, off: u64, data: &[u8]) {
    for (i, c) in data.chunks(64 * 1024).enumerate() {
        assert_eq!(fs.write(ino, off + (i * 64 * 1024) as u64, c).unwrap(), c.len());
    }
}

// ---- e2fsprogs through WSL ------------------------------------------------------

fn wsl_ok() -> bool {
    static OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OK.get_or_init(|| {
        Command::new("wsl.exe")
            .args(["-d", "Ubuntu-24.04", "--", "bash", "-lc", "command -v e2fsck debugfs"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

fn wsl_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    let (drive, rest) = s.split_once(':').expect("absolute path");
    format!("/mnt/{}{}", drive.to_lowercase(), rest)
}

fn scratch(name: &str, img: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("osyx-ext4-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("{name}.img"));
    std::fs::write(&p, img).unwrap();
    p
}

/// e2fsck -fn must report a clean volume.
fn e2fsck(name: &str, img: &[u8]) {
    if !wsl_ok() {
        eprintln!("SKIPPED e2fsck for {name}: WSL with e2fsprogs not available");
        return;
    }
    let p = scratch(name, img);
    let o = Command::new("wsl.exe")
        .args(["-d", "Ubuntu-24.04", "--", "e2fsck", "-fn", &wsl_path(&p)])
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{name}: e2fsck found problems:\n{text}");
    let _ = std::fs::remove_file(p);
}

/// File contents as debugfs reads them.
fn debugfs_cat(name: &str, img: &[u8], path: &str) -> Option<Vec<u8>> {
    if !wsl_ok() {
        return None;
    }
    let p = scratch(name, img);
    let o = Command::new("wsl.exe")
        .args(["-d", "Ubuntu-24.04", "--", "debugfs", "-R", &format!("cat \"{path}\""), &wsl_path(&p)])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(p);
    Some(o.stdout)
}

fn debugfs_stat(name: &str, img: &[u8], path: &str) -> Option<String> {
    if !wsl_ok() {
        return None;
    }
    let p = scratch(name, img);
    let o = Command::new("wsl.exe")
        .args(["-d", "Ubuntu-24.04", "--", "debugfs", "-R", &format!("stat \"{path}\""), &wsl_path(&p)])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(p);
    Some(String::from_utf8_lossy(&o.stdout).into_owned())
}

// ---- scenarios -----------------------------------------------------------------

fn exercise(name: &str) {
    let mut fs = rw(fixture(name));
    let docs = fs.create(ROOT_INO, "docs", NewKind::Dir, 0o750, 1000, 1000).unwrap();
    let nested = fs.create(docs, "nested", NewKind::Dir, 0o755, 0, 0).unwrap();
    let f = fs.create(nested, "data.bin", NewKind::File, 0o640, 1000, 100).unwrap();
    let big = pattern(1_500_000, 5);
    write_all(&mut fs, f, 0, &big);
    // Overwrite in the middle, unaligned.
    fs.write(f, 4095, b"OSyx was here").unwrap();
    let mut want = big.clone();
    want[4095..4095 + 13].copy_from_slice(b"OSyx was here");
    let empty = fs.create(ROOT_INO, "empty", NewKind::File, 0o644, 0, 0).unwrap();
    let sparse = fs.create(ROOT_INO, "sparse", NewKind::File, 0o644, 0, 0).unwrap();
    fs.write(sparse, 5 << 30, b"tail at 5 GiB").unwrap();
    fs.write(sparse, 100, b"head").unwrap();
    fs.create(ROOT_INO, "short-link", NewKind::Symlink("docs/nested/data.bin"), 0, 0, 0).unwrap();
    let long_target = format!("docs/{}", "y".repeat(150));
    fs.create(ROOT_INO, "long-link", NewKind::Symlink(&long_target), 0, 0, 0).unwrap();
    // Truncation both ways.
    let t = fs.create(ROOT_INO, "trunc", NewKind::File, 0o644, 0, 0).unwrap();
    write_all(&mut fs, t, 0, &pattern(300_000, 9));
    fs.truncate(t, 70_001).unwrap();
    fs.truncate(t, 200_000).unwrap();
    // Rename within and across directories, replacing a file.
    let r = fs.create(ROOT_INO, "to-move.txt", NewKind::File, 0o644, 0, 0).unwrap();
    fs.write(r, 0, b"moved").unwrap();
    let victim = fs.create(docs, "victim.txt", NewKind::File, 0o644, 0, 0).unwrap();
    fs.write(victim, 0, &pattern(50_000, 1)).unwrap();
    fs.rename(ROOT_INO, "to-move.txt", docs, "victim.txt").unwrap();
    fs.rename(docs, "nested", ROOT_INO, "nested-moved").unwrap();
    fs.set_mode(f, 0o600).unwrap();
    // Many entries: directory grows beyond one block.
    let many = fs.create(ROOT_INO, "many-new", NewKind::Dir, 0o755, 0, 0).unwrap();
    for i in 0..150 {
        let x = fs.create(many, &format!("entry-with-a-longish-name-{i:03}"), NewKind::File, 0o644, 0, 0).unwrap();
        fs.write(x, 0, format!("{i}\n").as_bytes()).unwrap();
    }
    for i in (0..150).step_by(3) {
        fs.unlink(many, &format!("entry-with-a-longish-name-{i:03}")).unwrap();
    }
    let gone = fs.create(ROOT_INO, "gone", NewKind::Dir, 0o755, 0, 0).unwrap();
    fs.create(gone, "x", NewKind::File, 0o644, 0, 0).unwrap();
    assert_eq!(fs.rmdir(ROOT_INO, "gone"), Err(Error::DirectoryNotEmpty));
    fs.unlink(gone, "x").unwrap();
    fs.rmdir(ROOT_INO, "gone").unwrap();
    // Existing files from mke2fs are writable too.
    let hello = fs.resolve("/hello.txt").unwrap();
    fs.write(hello, 0, b"HELLO").unwrap();
    // Errors leave nothing behind.
    assert_eq!(fs.create(ROOT_INO, "docs", NewKind::File, 0o644, 0, 0), Err(Error::AlreadyExists));
    assert_eq!(fs.unlink(ROOT_INO, "docs"), Err(Error::IsADirectory));
    assert_eq!(fs.rmdir(ROOT_INO, "empty"), Err(Error::NotADirectory));
    assert!(fs.rename(ROOT_INO, "docs", docs, "inside").is_err());
    assert_eq!(fs.create(ROOT_INO, "bad/name", NewKind::File, 0o644, 0, 0), Err(Error::InvalidName));
    let report = fs.check().unwrap_or_else(|e| panic!("{name}: driver check: {e}"));
    eprintln!("{name}: {report}");
    let img = fs.unmount().unwrap();

    // Read back with a fresh read-only mount.
    let mut fs = ro(img.clone());
    let f2 = fs.resolve("/nested-moved/data.bin").unwrap();
    assert_eq!(f2, f);
    assert_eq!(read_all(&mut fs, f2), want, "{name}: data.bin");
    let st = fs.stat(f2).unwrap();
    assert_eq!((st.perm(), st.uid, st.gid, st.mtime_ns), (0o600, 1000, 100, 1_761_200_000_123_456_789));
    assert_eq!(fs.stat(empty).unwrap().size, 0);
    let s = fs.stat(sparse).unwrap();
    assert_eq!(s.size, (5 << 30) + 13);
    assert!(s.blocks_512 <= 16, "{name}: sparse file allocates {} sectors", s.blocks_512);
    let mut tail = [0u8; 13];
    fs.read(sparse, 5 << 30, &mut tail).unwrap();
    assert_eq!(&tail, b"tail at 5 GiB");
    let sl = fs.resolve("/short-link").unwrap();
    assert_eq!(fs.readlink(sl).unwrap(), "docs/nested/data.bin");
    let ll = fs.resolve("/long-link").unwrap();
    assert_eq!(fs.readlink(ll).unwrap(), long_target);
    let tr = read_all(&mut fs, t);
    assert_eq!(tr.len(), 200_000);
    assert_eq!(&tr[..70_001], &pattern(300_000, 9)[..70_001]);
    assert!(tr[70_001..].iter().all(|&b| b == 0), "{name}: truncated tail reads zeros");
    let v = fs.resolve("/docs/victim.txt").unwrap();
    assert_eq!(read_all(&mut fs, v), b"moved");
    assert_eq!(fs.resolve("/to-move.txt"), Err(Error::NotFound));
    let m = fs.resolve("/many-new").unwrap();
    assert_eq!(fs.read_dir(m).unwrap().len(), 100);
    assert_eq!(fs.resolve("/gone"), Err(Error::NotFound));
    let h = fs.resolve("/hello.txt").unwrap();
    assert_eq!(read_all(&mut fs, h), b"HELLO from mke2fs!\n");
    fs.check().unwrap();

    // The independent checker and reader agree.
    e2fsck(name, &img);
    if let Some(cat) = debugfs_cat(name, &img, "/nested-moved/data.bin") {
        assert!(cat == want, "{name}: debugfs reads different data");
        assert_eq!(debugfs_cat(name, &img, "/docs/victim.txt").unwrap(), b"moved");
        let st = debugfs_stat(name, &img, "/nested-moved/data.bin").unwrap();
        assert!(st.contains("Mode:  0600") && st.contains("User:  1000"), "{st}");
    }
}

#[test]
fn write_4k_metadata_csum() {
    exercise("ext4-4k");
}

#[test]
fn write_1k_blocks() {
    exercise("ext4-1k");
}

#[test]
fn write_gdt_csum_without_metadata_csum() {
    exercise("ext4-nocsum");
}

#[test]
fn fragmented_file_gets_an_extent_tree() {
    let mut fs = rw(fixture("ext4-1k"));
    let a = fs.create(ROOT_INO, "a", NewKind::File, 0o644, 0, 0).unwrap();
    let b = fs.create(ROOT_INO, "b", NewKind::File, 0o644, 0, 0).unwrap();
    // Interleaved single-block writes fragment both files.
    for i in 0..40u64 {
        fs.write(a, i * 2048, &pattern(1024, i as usize)).unwrap();
        fs.write(b, i * 1024, &pattern(1024, 100 + i as usize)).unwrap();
    }
    fs.check().unwrap();
    let img = fs.unmount().unwrap();
    let mut fs = ro(img.clone());
    for i in 0..40u64 {
        let mut buf = vec![0u8; 1024];
        fs.read(a, i * 2048, &mut buf).unwrap();
        assert_eq!(buf, pattern(1024, i as usize));
    }
    // 40 one-block extents do not fit the inode: a depth-1 tree was built.
    let mut raw = [0u8; 2];
    let ia = fs.inode(a).unwrap();
    raw.copy_from_slice(&ia.block[6..8]);
    assert_eq!(u16::from_le_bytes(raw), 1, "extent tree depth");
    e2fsck("fragmented", &img);
    // Shrinking it again collapses the tree.
    let mut fs = rw(img);
    fs.truncate(a, 3000).unwrap();
    let img = fs.unmount().unwrap();
    let mut fs = ro(img.clone());
    assert_eq!(&fs.inode(a).unwrap().block[6..8], &[0, 0]);
    e2fsck("collapsed", &img);
}

#[test]
fn very_fragmented_file_gets_a_depth_two_tree() {
    let mut img = vec![0u8; 64 * 1024 * 1024];
    format(&mut img, &FormatOptions { label: "FRAG", uuid: [0x2a; 16], time: 1_761_200_000 }).unwrap();
    let mut fs = rw(img);
    let ino = fs.create(ROOT_INO, "frag", NewKind::File, 0o644, 0, 0).unwrap();
    let mut expect = Vec::new();
    // A one-block file between every block of `frag`: 2000 single-block
    // extents need six 4 KiB leaves, one level past the inode root.
    for i in 0..2_000u64 {
        let data = pattern(4096, i as usize);
        fs.write(ino, i * 4096, &data).unwrap();
        expect.extend_from_slice(&data);
        let pad = fs.create(ROOT_INO, &format!("pad-{i}"), NewKind::File, 0o644, 0, 0).unwrap();
        fs.write(pad, 0, &[i as u8]).unwrap();
    }
    fs.check().unwrap();
    let img = fs.unmount().unwrap();
    let mut fs = ro(img.clone());
    assert_eq!(&fs.inode(ino).unwrap().block[6..8], &[2, 0], "extent tree depth");
    assert_eq!(read_all(&mut fs, ino), expect);
    e2fsck("depth-two", &img);
}

#[test]
fn depth_two_tree_carries_checksums() {
    // The fixture is made by mke2fs with metadata_csum, so every leaf and
    // index block gets a checksum and e2fsck verifies them.
    let mut fs = rw(fixture("ext4-4k"));
    let ino = fs.create(ROOT_INO, "frag", NewKind::File, 0o644, 0, 0).unwrap();
    let mut expect = Vec::new();
    for i in 0..1_400u64 {
        let data = pattern(4096, i as usize);
        fs.write(ino, i * 4096, &data).unwrap();
        expect.extend_from_slice(&data);
        let pad = fs.create(ROOT_INO, &format!("pad-{i}"), NewKind::File, 0o644, 0, 0).unwrap();
        fs.write(pad, 0, &[i as u8]).unwrap();
    }
    fs.check().unwrap();
    let img = fs.unmount().unwrap();
    let mut fs = ro(img.clone());
    assert_eq!(&fs.inode(ino).unwrap().block[6..8], &[2, 0], "extent tree depth");
    assert_eq!(read_all(&mut fs, ino), expect);
    e2fsck("depth-two-csum", &img);
}

#[test]
fn out_of_space_and_recovery_of_space() {
    let mut fs = rw(fixture("ext4-1k"));
    let (free_before, _) = fs.free_counts();
    let f = fs.create(ROOT_INO, "filler", NewKind::File, 0o644, 0, 0).unwrap();
    let chunk = vec![0x5Au8; 256 * 1024];
    let mut off = 0u64;
    let err = loop {
        match fs.write(f, off, &chunk) {
            Ok(n) => off += n as u64,
            Err(e) => break e,
        }
        assert!(off < 64 << 20, "volume never filled up");
    };
    assert_eq!(err, Error::NoSpace);
    fs.check().unwrap();
    fs.unlink(ROOT_INO, "filler").unwrap();
    assert_eq!(fs.free_counts().0, free_before, "all blocks returned");
    let img = fs.unmount().unwrap();
    e2fsck("enospc", &img);
}

#[test]
fn removed_open_files_and_the_orphan_list() {
    let mut fs = rw(fixture("ext4-4k"));
    let f = fs.create(ROOT_INO, "open.bin", NewKind::File, 0o644, 0, 0).unwrap();
    write_all(&mut fs, f, 0, &pattern(100_000, 2));
    let free_with_file = fs.free_counts();
    fs.open(f);
    fs.unlink(ROOT_INO, "open.bin").unwrap();
    assert_eq!(fs.resolve("/open.bin"), Err(Error::NotFound));
    assert_eq!(read_all(&mut fs, f), pattern(100_000, 2), "data stays while open");
    assert_eq!(fs.free_counts(), free_with_file, "nothing freed yet");
    fs.release(f).unwrap();
    assert!(fs.free_counts().0 > free_with_file.0, "freed on last close");
    let img = fs.unmount().unwrap();
    e2fsck("orphan-closed", &img);
    // Power cut while the removed file is still open: the next writable
    // mount finds it on the orphan list and frees it.
    let mut fs = rw(img);
    let g = fs.create(ROOT_INO, "open2.bin", NewKind::File, 0o644, 0, 0).unwrap();
    write_all(&mut fs, g, 0, &pattern(100_000, 3));
    let (free_before, _) = fs.free_counts();
    fs.open(g);
    fs.unlink(ROOT_INO, "open2.bin").unwrap();
    let img = fs.into_device_unclean();
    let fs = rw(img);
    assert!(fs.free_counts().0 >= free_before + 24, "orphan freed at mount");
    let img = fs.unmount().unwrap();
    e2fsck("orphan-crash", &img);
}

#[test]
fn writable_mount_replays_the_journal_to_disk() {
    let fs = rw(fixture("ext4-journal"));
    let img = fs.unmount().unwrap();
    let mut fs = ro(img.clone());
    let h = fs.resolve("/hello.txt").unwrap();
    // The file keeps its size (19 bytes); its block now holds the journal's copy.
    let mut buf = [0u8; 19];
    fs.read(h, 0, &mut buf).unwrap();
    assert_eq!(&buf, b"Replayed by the jou");
    e2fsck("replayed", &img);
    if let Some(cat) = debugfs_cat("replayed", &img, "/hello.txt") {
        assert_eq!(cat, b"Replayed by the jou", "debugfs sees the replayed block");
    }
}

#[test]
fn unsupported_writes_are_refused() {
    // Hashed directory (indexed by e2fsck -D when the fixture was made).
    let mut fs = rw(fixture("ext4-4k"));
    let many = fs.resolve("/many").unwrap();
    assert!(fs.inode(many).unwrap().flags & osyx_ext4::inode::FL_INDEX != 0, "fixture has an htree directory");
    assert_eq!(fs.create(many, "new", NewKind::File, 0o644, 0, 0), Err(Error::Unsupported("adding entries to a hashed (dir_index) directory")));
    // Removing from it is fine.
    fs.unlink(many, "file-7.txt").unwrap();
    let img = fs.unmount().unwrap();
    e2fsck("htree-unlink", &img);
    // Block-mapped and checksum-less legacy volumes stay read-only.
    for name in ["ext3-1k", "ext2-4k", "ext4-metabg"] {
        assert!(matches!(Ext4::mount(fixture(name), MountOptions { read_only: false, clock: Some(clock) }), Err(Error::Unsupported(_))), "{name}");
    }
    // A read-only mount refuses changes.
    let mut fs = ro(fixture("ext4-4k"));
    assert_eq!(fs.create(ROOT_INO, "x", NewKind::File, 0o644, 0, 0), Err(Error::ReadOnly));
}

/// A device that loses every write after a given number of them, like a
/// machine losing power mid-operation.
struct PowerCut {
    img: Vec<u8>,
    writes_left: usize,
}

impl BlockDevice for PowerCut {
    fn sector_count(&self) -> u64 {
        self.img.sector_count()
    }
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> osyx_ext4::Result<()> {
        self.img.read_sectors(lba, buf)
    }
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> osyx_ext4::Result<()> {
        if self.writes_left == 0 {
            return Ok(());
        }
        self.writes_left -= 1;
        self.img.write_sectors(lba, buf)
    }
}

fn workload<D: BlockDevice>(fs: &mut Ext4<D>) -> Result<(), Error> {
    let d = fs.create(ROOT_INO, "crash-dir", NewKind::Dir, 0o755, 0, 0)?;
    let f = fs.create(d, "file", NewKind::File, 0o644, 0, 0)?;
    fs.write(f, 0, &pattern(20_000, 4))?;
    fs.rename(d, "file", ROOT_INO, "renamed")?;
    let hello = fs.resolve("/hello.txt")?;
    fs.truncate(hello, 3)?;
    fs.unlink(ROOT_INO, "small.bin")?;
    Ok(())
}

/// Power is cut after every possible number of device writes during a
/// workload; after recovery the volume is always consistent and each
/// operation is either fully there or not at all.
#[test]
fn power_cut_at_every_write_recovers_consistently() {
    let base = fixture("ext4-1k");
    // Count the writes of a complete run.
    let mut full = rw(PowerCut { img: base.clone(), writes_left: usize::MAX });
    workload(&mut full).unwrap();
    let total = usize::MAX - full.into_device_unclean().writes_left;
    eprintln!("workload performs {total} device writes");
    let mut fsck_samples = 0;
    for cut in 0..total {
        let mut fs = match Ext4::mount(PowerCut { img: base.clone(), writes_left: cut }, MountOptions { read_only: false, clock: Some(clock) }) {
            Ok(fs) => fs,
            Err(e) => panic!("mount with cut {cut}: {e}"),
        };
        let _ = workload(&mut fs);
        let img = fs.into_device_unclean().img;
        // Recovery happens at the next mount.
        let mut fs = rw(img);
        fs.check().unwrap_or_else(|e| panic!("cut after {cut} writes: {e}"));
        // Atomicity of the rename: the file is in exactly one place.
        let a = fs.resolve("/crash-dir/file").is_ok();
        let b = fs.resolve("/renamed").is_ok();
        assert!(!(a && b), "cut {cut}: file visible twice");
        if b {
            let r = fs.resolve("/renamed").unwrap();
            let st = fs.stat(r).unwrap();
            assert!(st.size == 0 || st.size == 20_000, "cut {cut}: size {}", st.size);
        }
        let img = fs.unmount().unwrap();
        if cut % 9 == 0 || cut + 1 == total {
            e2fsck(&format!("cut-{cut}"), &img);
            fsck_samples += 1;
        }
    }
    eprintln!("{total} power-cut points recovered; {fsck_samples} checked with e2fsck");
}

/// Random operations against a model; e2fsck at the end.
#[test]
fn randomised_operations_match_a_model() {
    let mut fs = rw(fixture("ext4-4k"));
    let dir = fs.create(ROOT_INO, "model", NewKind::Dir, 0o755, 0, 0).unwrap();
    let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut seed = 0x0123_4567_89AB_CDEFu64;
    let mut rnd = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for step in 0..600 {
        let name = format!("f{}", rnd(25));
        match rnd(6) {
            0 => {
                let r = fs.create(dir, &name, NewKind::File, 0o644, 0, 0);
                assert_eq!(r.is_ok(), !model.contains_key(&name), "step {step}");
                model.entry(name).or_default();
            }
            1 | 2 => {
                if let Ok(ino) = fs.lookup(dir, &name) {
                    let off = rnd(40_000) as usize;
                    let data = pattern(rnd(30_000) as usize + 1, step);
                    fs.write(ino, off as u64, &data).unwrap();
                    let m = model.get_mut(&name).unwrap();
                    if m.len() < off + data.len() {
                        m.resize(off + data.len(), 0);
                    }
                    m[off..off + data.len()].copy_from_slice(&data);
                }
            }
            3 => {
                if let Ok(ino) = fs.lookup(dir, &name) {
                    let len = rnd(60_000) as usize;
                    fs.truncate(ino, len as u64).unwrap();
                    model.get_mut(&name).unwrap().resize(len, 0);
                }
            }
            4 => {
                let r = fs.unlink(dir, &name);
                assert_eq!(r.is_ok(), model.remove(&name).is_some(), "step {step}");
            }
            _ => {
                let to = format!("f{}", rnd(25));
                let r = fs.rename(dir, &name, dir, &to);
                match model.remove(&name) {
                    Some(v) => {
                        r.unwrap();
                        model.insert(to, v);
                    }
                    None => assert_eq!(r, Err(Error::NotFound)),
                }
            }
        }
    }
    fs.check().unwrap();
    let img = fs.unmount().unwrap();
    let mut fs = ro(img.clone());
    assert_eq!(fs.read_dir(dir).unwrap().len(), model.len());
    for (name, want) in &model {
        let ino = fs.lookup(dir, name).unwrap();
        assert_eq!(&read_all(&mut fs, ino), want, "{name}");
    }
    e2fsck("random", &img);
}
