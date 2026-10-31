//! In-kernel self-tests of the VFS and the file systems mounted at boot.
//! They work below `/tmp` and `/boot/kselftest` and remove what they create.

use crate::devices::{self, CharDevice, DeviceKind};
use crate::vfs::{self, Lookup, OpenFile};
use crate::{kprintln, sched};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use osyx_abi::*;
use osyx_vfs::Cred;

type TestResult = Result<(), String>;

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

fn e(what: &str, err: Errno) -> String {
    format!("{what}: {err:?}")
}

fn root() -> Lookup {
    Lookup::kernel()
}

fn user(uid: u32) -> Lookup {
    Lookup { cred: Cred { uid, gid: uid }, cwd: String::from("/"), case_insensitive: false, path_policy: None }
}

fn create(cx: &Lookup, p: &str, mode: u32) -> Result<OpenFile, Errno> {
    vfs::open(cx, p, OPEN_READ | OPEN_WRITE | OPEN_CREATE | OPEN_TRUNCATE, mode)
}

fn write_file(cx: &Lookup, p: &str, data: &[u8]) -> Result<(), Errno> {
    let mut f = create(cx, p, 0o644)?;
    let mut done = 0;
    while done < data.len() {
        done += f.write(&data[done..])?;
    }
    Ok(())
}

fn read_file(cx: &Lookup, p: &str) -> Result<Vec<u8>, Errno> {
    let mut f = vfs::open(cx, p, OPEN_READ, 0)?;
    let mut out = Vec::new();
    let mut buf = alloc::vec![0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        f.advance(n);
        out.extend_from_slice(&buf[..n]);
    }
}

/// Removes a directory tree (best effort, as root).
fn remove_tree(p: &str) {
    let cx = root();
    if let Ok(mut d) = vfs::open(&cx, p, OPEN_READ | OPEN_DIRECTORY | OPEN_NOFOLLOW, 0) {
        let mut buf = alloc::vec![0u8; 4096];
        let mut names = Vec::new();
        while let Ok(n) = d.readdir(&mut buf) {
            if n == 0 {
                break;
            }
            let mut off = 0;
            while let Some((r, name, len)) = DirRecord::decode(&buf[off..n]) {
                names.push((String::from_utf8_lossy(name).into_owned(), r.kind));
                off += len;
            }
        }
        drop(d);
        for (name, kind) in names {
            let child = format!("{p}/{name}");
            if kind == KIND_DIR {
                remove_tree(&child);
            } else {
                let _ = vfs::unlink(&cx, &child);
            }
        }
        let _ = vfs::rmdir(&cx, p);
    } else {
        let _ = vfs::unlink(&cx, p);
    }
}

fn listing(cx: &Lookup, p: &str) -> Result<Vec<(String, u32)>, Errno> {
    let mut d = vfs::open(cx, p, OPEN_READ | OPEN_DIRECTORY, 0)?;
    let mut buf = alloc::vec![0u8; 4096];
    let mut out = Vec::new();
    loop {
        let n = d.readdir(&mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        let mut off = 0;
        while let Some((r, name, len)) = DirRecord::decode(&buf[off..n]) {
            out.push((String::from_utf8_lossy(name).into_owned(), r.kind));
            off += len;
        }
    }
}

pub fn tmpfs_files() -> TestResult {
    let cx = root();
    let d = "/tmp/kst";
    remove_tree(d);
    vfs::mkdir(&cx, d, 0o755).map_err(|x| e("mkdir", x))?;
    let mut f = create(&cx, "/tmp/kst/a.txt", 0o640).map_err(|x| e("create", x))?;
    f.write(b"Hello, ").map_err(|x| e("write", x))?;
    f.write(b"VFS").map_err(|x| e("write", x))?;
    ensure!(f.seek(-3, SEEK_END) == Ok(7), "seek from end");
    let mut buf = [0u8; 16];
    let n = f.read(&mut buf).map_err(|x| e("read", x))?;
    ensure!(&buf[..n] == b"VFS", "read back {:?}", &buf[..n]);
    let st = f.stat().map_err(|x| e("fstat", x))?;
    ensure!((st.size, st.kind, st.mode, st.nlink) == (10, KIND_FILE, 0o640, 1), "fstat {st:?}");
    ensure!(st.mtime_ns > 1_600_000_000_000_000_000, "mtime {} is not a plausible wall-clock time", st.mtime_ns);
    f.truncate(5).map_err(|x| e("truncate", x))?;
    drop(f);
    let mut a = vfs::open(&cx, "/tmp/kst/a.txt", OPEN_WRITE | OPEN_APPEND, 0).map_err(|x| e("open append", x))?;
    a.write(b"!").map_err(|x| e("append", x))?;
    drop(a);
    ensure!(read_file(&cx, "/tmp/kst/a.txt") == Ok(b"Hello!".to_vec()), "contents after append");
    let flags = OPEN_WRITE | OPEN_CREATE | OPEN_EXCLUSIVE;
    ensure!(vfs::open(&cx, "/tmp/kst/a.txt", flags, 0o644).err() == Some(Errno::AlreadyExists), "exclusive create");
    ensure!(vfs::open(&cx, "/tmp/kst/missing", OPEN_READ, 0).err() == Some(Errno::NotFound), "missing file");
    ensure!(vfs::open(&cx, "/tmp/kst/a.txt/x", OPEN_READ, 0).err() == Some(Errno::NotADirectory), "file as directory");
    ensure!(vfs::open(&cx, "/tmp/kst/a.txt", OPEN_CREATE, 0).err() == Some(Errno::InvalidArgument), "create without write");
    ensure!(vfs::open(&cx, "/tmp/kst/a.txt", OPEN_READ | OPEN_DIRECTORY, 0).err() == Some(Errno::NotADirectory), "O_DIRECTORY");
    let rel = Lookup { cwd: String::from("/tmp/kst"), ..root() };
    ensure!(read_file(&rel, "a.txt") == Ok(b"Hello!".to_vec()), "relative path from cwd");
    ensure!(read_file(&rel, "../kst/./a.txt").is_ok(), "relative path with ..");
    vfs::mkdir(&cx, "/tmp/kst/sub", 0o755).map_err(|x| e("mkdir sub", x))?;
    ensure!(vfs::mkdir(&cx, "/tmp/kst/sub", 0o755) == Err(Errno::AlreadyExists), "mkdir twice");
    vfs::rename(&cx, "/tmp/kst/a.txt", "/tmp/kst/sub/./../sub/moved.txt").map_err(|x| e("rename", x))?;
    ensure!(vfs::rmdir(&cx, "/tmp/kst/sub") == Err(Errno::DirectoryNotEmpty), "removed a non-empty directory");
    ensure!(listing(&cx, "/tmp/kst/sub") == Ok(alloc::vec![(String::from("moved.txt"), KIND_FILE)]), "listing");
    ensure!(vfs::open(&cx, "/tmp/kst/sub", OPEN_WRITE, 0).err() == Some(Errno::IsADirectory), "directory opened for writing");
    // A removed file stays readable through an open handle.
    let mut h = vfs::open(&cx, "/tmp/kst/sub/moved.txt", OPEN_READ, 0).map_err(|x| e("open", x))?;
    vfs::unlink(&cx, "/tmp/kst/sub/moved.txt").map_err(|x| e("unlink", x))?;
    ensure!(vfs::stat(&cx, "/tmp/kst/sub/moved.txt") == Err(Errno::NotFound), "name still there");
    let n = h.read(&mut buf).map_err(|x| e("read unlinked", x))?;
    ensure!(&buf[..n] == b"Hello!", "unlinked file data");
    drop(h);
    vfs::rmdir(&cx, "/tmp/kst/sub").map_err(|x| e("rmdir", x))?;
    ensure!(vfs::unlink(&cx, "/tmp") == Err(Errno::Busy), "removing a mount point");
    ensure!(vfs::rmdir(&cx, "/") == Err(Errno::InvalidArgument), "rmdir /");
    let fs = vfs::statfs(&cx, "/tmp/kst").map_err(|x| e("statfs", x))?;
    ensure!(&fs.fstype[..5] == b"tmpfs" && fs.total_blocks > 0, "statfs {:?}", fs);
    vfs::rmdir(&cx, d).map_err(|x| e("rmdir kst", x))?;
    Ok(())
}

pub fn links_cwd_perms() -> TestResult {
    let cx = root();
    let d = "/tmp/lk";
    remove_tree(d);
    vfs::mkdir(&cx, d, 0o755).map_err(|x| e("mkdir", x))?;
    write_file(&cx, "/tmp/lk/target.txt", b"T").map_err(|x| e("target", x))?;
    vfs::symlink(&cx, "target.txt", "/tmp/lk/rel").map_err(|x| e("symlink rel", x))?;
    vfs::symlink(&cx, "/tmp/lk/target.txt", "/tmp/lk/abs").map_err(|x| e("symlink abs", x))?;
    vfs::symlink(&cx, "../lk/rel", "/tmp/lk/chain").map_err(|x| e("symlink chain", x))?;
    for l in ["rel", "abs", "chain"] {
        ensure!(vfs::stat(&cx, &format!("/tmp/lk/{l}")).map(|s| s.size) == Ok(1), "stat through {l}");
    }
    ensure!(vfs::lstat(&cx, "/tmp/lk/rel").map(|s| s.kind) == Ok(KIND_SYMLINK), "lstat");
    ensure!(vfs::readlink(&cx, "/tmp/lk/rel").as_deref() == Ok("target.txt"), "readlink");
    ensure!(vfs::readlink(&cx, "/tmp/lk/target.txt") == Err(Errno::InvalidArgument), "readlink on a file");
    vfs::symlink(&cx, "loop2", "/tmp/lk/loop1").map_err(|x| e("loop1", x))?;
    vfs::symlink(&cx, "loop1", "/tmp/lk/loop2").map_err(|x| e("loop2", x))?;
    ensure!(vfs::stat(&cx, "/tmp/lk/loop1") == Err(Errno::Loop), "symlink loop");
    ensure!(vfs::open(&cx, "/tmp/lk/rel", OPEN_READ | OPEN_NOFOLLOW, 0).err() == Some(Errno::Loop), "O_NOFOLLOW");
    vfs::symlink(&cx, "/tmp/lk", "/tmp/lk/self").map_err(|x| e("self", x))?;
    ensure!(vfs::stat(&cx, "/tmp/lk/self/self/self/target.txt").is_ok(), "directory symlinks");
    // A link into another file system, and `..` after following it.
    vfs::symlink(&cx, "/dev", "/tmp/lk/devlink").map_err(|x| e("devlink", x))?;
    ensure!(vfs::stat(&cx, "/tmp/lk/devlink/null").map(|s| s.kind) == Ok(KIND_CHAR_DEVICE), "link across mounts");
    let up = vfs::walk(&cx, "/tmp/lk/devlink/..", true).map_err(|x| e("walk ..", x))?;
    ensure!(up.path == "/", ".. after a symlink is physical: got {}", up.path);
    vfs::symlink(&cx, "missing", "/tmp/lk/dangle").map_err(|x| e("dangle", x))?;
    ensure!(vfs::stat(&cx, "/tmp/lk/dangle") == Err(Errno::NotFound) && vfs::lstat(&cx, "/tmp/lk/dangle").is_ok(), "dangling link");
    let in_lk = Lookup { cwd: String::from("/tmp/lk"), ..root() };
    ensure!(vfs::chdir(&in_lk, "../lk/./self").as_deref() == Ok("/tmp/lk"), "chdir canonicalises through links");
    ensure!(vfs::chdir(&in_lk, "target.txt") == Err(Errno::NotADirectory), "chdir to a file");
    // Case-insensitive resolution (the Windows compatibility hook).
    write_file(&cx, "/tmp/lk/CaseFile.Txt", b"c").map_err(|x| e("case file", x))?;
    ensure!(vfs::open(&cx, "/TMP/LK/casefile.txt", OPEN_READ, 0).err() == Some(Errno::NotFound), "case-sensitive by default");
    let ci = vfs::open(&cx, "/TMP/LK/casefile.txt", OPEN_READ | OPEN_CASE_INSENSITIVE, 0);
    ensure!(ci.is_ok(), "OPEN_CASE_INSENSITIVE: {:?}", ci.err());
    let ci_root = Lookup { case_insensitive: true, ..root() };
    ensure!(vfs::walk(&ci_root, "/TMP/Lk/CASEFILE.TXT", true).map(|n| n.path).as_deref() == Ok("/tmp/lk/CaseFile.Txt"), "canonical spelling");
    ensure!(vfs::statfs(&ci_root, "/TMP").map(|s| s.fstype[0]) == Ok(b't'), "mount point found case-insensitively");
    // Permissions.
    let u = user(1000);
    let other = user(1001);
    write_file(&cx, "/tmp/lk/secret", b"s").map_err(|x| e("secret", x))?;
    vfs::chmod(&cx, "/tmp/lk/secret", 0o600).map_err(|x| e("chmod", x))?;
    ensure!(vfs::open(&u, "/tmp/lk/secret", OPEN_READ, 0).err() == Some(Errno::PermissionDenied), "0600 root file readable by a user");
    ensure!(vfs::chmod(&u, "/tmp/lk/secret", 0o666) == Err(Errno::PermissionDenied), "user chmod of a root file");
    vfs::chmod(&cx, "/tmp/lk/secret", 0o644).map_err(|x| e("chmod 644", x))?;
    ensure!(read_file(&u, "/tmp/lk/secret") == Ok(b"s".to_vec()), "0644 file readable");
    ensure!(vfs::open(&u, "/tmp/lk/secret", OPEN_WRITE, 0).err() == Some(Errno::PermissionDenied), "0644 file writable by others");
    ensure!(create(&u, "/tmp/lk/mine", 0o644).err() == Some(Errno::PermissionDenied), "create in a 0755 root directory");
    vfs::mkdir(&cx, "/tmp/lk/private", 0o700).map_err(|x| e("private", x))?;
    ensure!(vfs::stat(&u, "/tmp/lk/private/x") == Err(Errno::PermissionDenied), "search without x permission");
    // Sticky /tmp: users create their own files and cannot remove others'.
    write_file(&u, "/tmp/kst-user.txt", b"u").map_err(|x| e("user file in /tmp", x))?;
    ensure!(vfs::stat(&cx, "/tmp/kst-user.txt").map(|s| s.uid) == Ok(1000), "owner of a new file");
    ensure!(vfs::unlink(&other, "/tmp/kst-user.txt") == Err(Errno::PermissionDenied), "sticky bit");
    ensure!(vfs::rename(&other, "/tmp/kst-user.txt", "/tmp/kst-stolen") == Err(Errno::PermissionDenied), "sticky rename");
    vfs::unlink(&u, "/tmp/kst-user.txt").map_err(|x| e("owner unlink", x))?;
    ensure!(
        vfs::mount(&u, "", "/tmp/lk", "tmpfs", 0, 0) == Err(Errno::PermissionDenied),
        "mount by an ordinary user"
    );
    remove_tree(d);
    ensure!(vfs::stat(&cx, d) == Err(Errno::NotFound), "cleanup");
    Ok(())
}

pub fn mount_unmount() -> TestResult {
    let cx = root();
    let m = "/tmp/kst-mnt";
    remove_tree(m);
    let before = vfs::statfs(&cx, "/tmp").map_err(|x| e("statfs /tmp", x))?;
    vfs::mkdir(&cx, m, 0o755).map_err(|x| e("mkdir", x))?;
    vfs::mount(&cx, "", m, "tmpfs", 0, 64 * 1024).map_err(|x| e("mount tmpfs", x))?;
    let st = vfs::statfs(&cx, m).map_err(|x| e("statfs", x))?;
    ensure!(st.total_blocks * st.block_size == 64 * 1024 && st.dev != before.dev, "new volume {:?}", st);
    // The limit holds.
    let mut f = create(&cx, &format!("{m}/big"), 0o644).map_err(|x| e("create big", x))?;
    let chunk = alloc::vec![0xAB; 16 * 1024];
    let mut total = 0;
    let err = loop {
        match f.write(&chunk) {
            Ok(n) => total += n,
            Err(x) => break x,
        }
        ensure!(total <= 64 * 1024, "wrote {total} bytes into a 64 KiB tmpfs");
    };
    ensure!(err == Errno::NoSpace && total > 32 * 1024, "limit: {err:?} after {total} bytes");
    // Busy while a file is open, and while another volume is mounted below.
    vfs::mkdir(&cx, &format!("{m}/inner"), 0o755).map_err(|x| e("mkdir inner", x))?;
    ensure!(vfs::unmount(&cx, m) == Err(Errno::Busy), "unmount with an open file");
    drop(f);
    vfs::mount(&cx, "", &format!("{m}/inner"), "tmpfs", MOUNT_READ_ONLY, 0).map_err(|x| e("nested mount", x))?;
    ensure!(create(&cx, &format!("{m}/inner/x"), 0o644).err() == Some(Errno::ReadOnly), "read-only mount");
    ensure!(vfs::unmount(&cx, m) == Err(Errno::Busy), "unmount with a nested mount");
    ensure!(vfs::rmdir(&cx, &format!("{m}/inner")) == Err(Errno::Busy), "rmdir of a mount point");
    vfs::unmount(&cx, &format!("{m}/inner")).map_err(|x| e("unmount inner", x))?;
    vfs::unmount(&cx, m).map_err(|x| e("unmount", x))?;
    ensure!(listing(&cx, m) == Ok(Vec::new()), "the covered directory is visible again and empty");
    ensure!(vfs::unmount(&cx, m) == Err(Errno::InvalidArgument), "unmount of a plain directory");
    ensure!(vfs::unmount(&cx, "/") == Err(Errno::Busy), "unmount /");
    ensure!(vfs::mount(&cx, "", m, "nosuchfs", 0, 0) == Err(Errno::InvalidArgument), "unknown file system type");
    ensure!(vfs::mount(&cx, "", "/tmp/kst-none", "tmpfs", 0, 0) == Err(Errno::NotFound), "missing mount point");
    vfs::rmdir(&cx, m).map_err(|x| e("rmdir", x))?;
    // Memory used by deleted files goes back to /tmp.
    write_file(&cx, "/tmp/kst-reclaim", &alloc::vec![1u8; 1 << 20]).map_err(|x| e("1 MiB file", x))?;
    let full = vfs::statfs(&cx, "/tmp").map_err(|x| e("statfs", x))?;
    vfs::unlink(&cx, "/tmp/kst-reclaim").map_err(|x| e("unlink", x))?;
    let after = vfs::statfs(&cx, "/tmp").map_err(|x| e("statfs", x))?;
    ensure!(full.free_blocks + 256 <= after.free_blocks, "1 MiB not charged/reclaimed: {} -> {}", full.free_blocks, after.free_blocks);
    ensure!(after.free_blocks == before.free_blocks, "/tmp usage changed: {} -> {}", before.free_blocks, after.free_blocks);
    Ok(())
}

struct Probe;
impl CharDevice for Probe {
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        buf.fill(b'p');
        Ok(buf.len())
    }
    fn write(&self, d: &[u8]) -> Result<usize, Errno> {
        Ok(d.len())
    }
}

pub fn devfs() -> TestResult {
    let cx = root();
    let mut null = vfs::open(&cx, "/dev/null", OPEN_READ | OPEN_WRITE, 0).map_err(|x| e("null", x))?;
    let mut buf = [0xFFu8; 64];
    ensure!(null.read(&mut buf) == Ok(0) && null.write(b"gone") == Ok(4), "/dev/null");
    let mut zero = vfs::open(&cx, "/dev/zero", OPEN_READ, 0).map_err(|x| e("zero", x))?;
    ensure!(zero.read(&mut buf) == Ok(64) && buf == [0; 64], "/dev/zero");
    if crate::random::is_seeded() {
        let mut r = vfs::open(&cx, "/dev/random", OPEN_READ, 0).map_err(|x| e("random", x))?;
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        ensure!(r.read(&mut a) == Ok(64) && r.read(&mut b) == Ok(64), "random reads");
        ensure!(a != b && a != [0; 64] && b != [0; 64], "random output repeats or is zero");
        kprintln!("[test]   /dev/random seeded from {}", crate::random::sources());
    } else {
        ensure!(vfs::stat(&cx, "/dev/random") == Err(Errno::NotFound), "/dev/random without entropy");
        kprintln!("[test]   no entropy source: /dev/random absent");
    }
    let mut con = vfs::open(&cx, "/dev/console", OPEN_READ | OPEN_WRITE, 0).map_err(|x| e("console", x))?;
    ensure!(con.write(b"[kernel self-test via /dev/console]\n") == Ok(36), "console write");
    ensure!(con.read(&mut buf) == Err(Errno::NotSupported), "console read without an input driver");
    let names: Vec<String> = listing(&cx, "/dev").map_err(|x| e("ls /dev", x))?.into_iter().map(|(n, _)| n).collect();
    for want in ["null", "zero", "console", "disks"] {
        ensure!(names.iter().any(|n| n == want), "/dev lacks {want}: {names:?}");
    }
    // /dev/input: the seat stream of the input core, plus one node per
    // attached device and nothing else.
    ensure!(names.iter().any(|n| n == "input"), "/dev lacks input: {names:?}");
    let inputs = listing(&cx, "/dev/input").map_err(|x| e("ls /dev/input", x))?;
    ensure!(inputs.iter().any(|(n, k)| n == "seat0" && *k == KIND_CHAR_DEVICE), "no seat0 in {inputs:?}");
    let attached: Vec<String> = crate::input::devices().iter().map(|d| format!("event{}", d.0)).collect();
    for (n, _) in &inputs {
        ensure!(n == "seat0" || attached.contains(n), "/dev/input/{n} without an attached device ({attached:?})");
    }
    let seat = vfs::stat(&cx, "/dev/input/seat0").map_err(|x| e("stat seat0", x))?;
    ensure!(seat.mode == 0o600 && seat.uid == 0, "seat0 mode {:o}", seat.mode);
    ensure!(vfs::open(&user(1000), "/dev/input/seat0", OPEN_READ, 0).err() == Some(Errno::PermissionDenied), "seat0 open by a user");
    {
        let first = vfs::open(&cx, "/dev/input/seat0", OPEN_READ, 0).map_err(|x| e("open seat0", x))?;
        ensure!(vfs::open(&cx, "/dev/input/seat0", OPEN_READ, 0).err() == Some(Errno::Busy), "seat0 is exclusive");
        drop(first);
    }
    ensure!(vfs::open(&cx, "/dev/input/seat0", OPEN_READ, 0).is_ok(), "seat0 reopens after close");
    kprintln!("[test]   /dev/input: seat0 exclusive and root-only, {} attached device node(s)", inputs.len() - 1);
    let disks = listing(&cx, "/dev/disks").map_err(|x| e("ls /dev/disks", x))?;
    ensure!(!disks.is_empty() && disks.iter().all(|(_, k)| *k == KIND_BLOCK_DEVICE), "disks {disks:?}");
    let first = format!("/dev/disks/{}", disks[0].0);
    let st = vfs::stat(&cx, &first).map_err(|x| e("stat disk", x))?;
    ensure!(st.mode == 0o600 && st.uid == 0 && st.size > 0, "disk node {st:?}");
    ensure!(vfs::open(&user(1000), &first, OPEN_READ, 0).err() == Some(Errno::PermissionDenied), "raw disk readable by a user");
    let mut disk = vfs::open(&cx, &first, OPEN_READ, 0).map_err(|x| e("open disk", x))?;
    let mut s0 = [0u8; 512];
    ensure!(disk.read(&mut s0) == Ok(512) && s0[510..] == [0x55, 0xAA], "sector 0 of {first}");
    ensure!(disk.seek(0, SEEK_END) == Ok(st.size), "seek to the end of a disk");
    drop(disk);
    if vfs::device_in_use(&disks[0].0) {
        ensure!(vfs::open(&cx, &first, OPEN_WRITE, 0).err() == Some(Errno::Busy), "raw write to a mounted disk");
    }
    // Dynamic registration.
    devices::register("kselftest/probe", DeviceKind::Char(Arc::new(Probe)), 0o666, 0).map_err(|x| e("register", x))?;
    ensure!(read_first(&cx, "/dev/kselftest/probe") == Ok(b'p'), "registered device");
    ensure!(devices::register("kselftest/probe", DeviceKind::Char(Arc::new(Probe)), 0o666, 0).is_err(), "duplicate registration");
    devices::unregister("kselftest/probe").map_err(|x| e("unregister", x))?;
    ensure!(vfs::stat(&cx, "/dev/kselftest") == Err(Errno::NotFound), "empty devfs directory still visible");
    ensure!(create(&cx, "/dev/newfile", 0o644).err() == Some(Errno::PermissionDenied), "creating files in /dev");
    Ok(())
}

fn read_first(cx: &Lookup, p: &str) -> Result<u8, Errno> {
    let mut f = vfs::open(cx, p, OPEN_READ, 0)?;
    let mut b = [0u8; 1];
    f.read(&mut b)?;
    Ok(b[0])
}

fn boot_fat() -> Option<Arc<vfs::Mount>> {
    vfs::mounts().into_iter().find(|m| m.path == "/boot" && m.fs.fs_type() == "fat32" && !m.read_only())
}

pub fn fat_boot() -> TestResult {
    let Some(m) = boot_fat() else {
        kprintln!("[test]   skipped: no writable FAT32 volume at /boot");
        return Ok(());
    };
    let cx = root();
    let d = "/boot/kselftest";
    remove_tree(d);
    ensure!(vfs::stat(&cx, "/boot/EFI/BOOT/BOOTX64.EFI").map(|s| s.kind) == Ok(KIND_FILE), "loader on the ESP");
    ensure!(vfs::stat(&cx, "/boot/efi/boot/bootx64.efi").is_ok(), "FAT names are case-insensitive");
    vfs::mkdir(&cx, d, 0o755).map_err(|x| e("mkdir", x))?;
    let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7 + 3) as u8).collect();
    write_file(&cx, "/boot/kselftest/Mixed Case Name.TXT", &data).map_err(|x| e("write", x))?;
    ensure!(read_file(&cx, "/boot/kselftest/mixed case name.txt") == Ok(data.clone()), "read back 100 KB");
    let names = listing(&cx, d).map_err(|x| e("ls", x))?;
    ensure!(names == alloc::vec![(String::from("Mixed Case Name.TXT"), KIND_FILE)], "long name kept: {names:?}");
    ensure!(vfs::stat(&cx, "/boot/kselftest/ż.txt") == Err(Errno::NotFound), "cache Unicode miss");
    write_file(&cx, "/boot/kselftest/Ż.txt", b"unicode").map_err(|x| e("Unicode file", x))?;
    ensure!(read_file(&cx, "/boot/kselftest/ż.txt") == Ok(b"unicode".to_vec()), "Unicode miss invalidated on create");
    vfs::unlink(&cx, "/boot/kselftest/Ż.txt").map_err(|x| e("unlink Unicode file", x))?;
    ensure!(vfs::stat(&cx, "/boot/kselftest/ż.txt") == Err(Errno::NotFound), "Unicode hit invalidated on unlink");
    ensure!(vfs::stat(&cx, "/boot/kselftest/Ος.txt") == Err(Errno::NotFound), "cache contextual Unicode miss");
    write_file(&cx, "/boot/kselftest/ΟΣ.txt", b"unicode").map_err(|x| e("contextual Unicode file", x))?;
    ensure!(read_file(&cx, "/boot/kselftest/Ος.txt") == Ok(b"unicode".to_vec()), "contextual Unicode miss invalidated on create");
    vfs::unlink(&cx, "/boot/kselftest/ΟΣ.txt").map_err(|x| e("unlink contextual Unicode file", x))?;
    ensure!(vfs::stat(&cx, "/boot/kselftest/Ος.txt") == Err(Errno::NotFound), "contextual Unicode hit invalidated on unlink");
    vfs::rename(&cx, "/boot/kselftest/Mixed Case Name.TXT", "/boot/kselftest/renamed.bin").map_err(|x| e("rename", x))?;
    let h = vfs::open(&cx, "/boot/kselftest/renamed.bin", OPEN_READ, 0).map_err(|x| e("open", x))?;
    ensure!(vfs::unlink(&cx, "/boot/kselftest/renamed.bin") == Err(Errno::Busy), "FAT refuses to remove an open file");
    drop(h);
    ensure!(vfs::symlink(&cx, "x", "/boot/kselftest/link") == Err(Errno::NotSupported), "symlink on FAT");
    ensure!(vfs::chmod(&cx, "/boot/kselftest/renamed.bin", 0o600) == Err(Errno::NotSupported), "chmod on FAT");
    ensure!(vfs::stat(&cx, "/boot/kselftest/renamed.bin").map(|s| (s.mode, s.uid)) == Ok((0o644, 0)), "FAT permissions");
    ensure!(vfs::open(&user(1000), "/boot/kselftest/renamed.bin", OPEN_WRITE, 0).err() == Some(Errno::PermissionDenied), "user write to /boot");
    remove_tree(d);
    match m.fs.fsck() {
        Some(Ok(s)) => kprintln!("[test]   /boot ({}): {s}, consistent", m.source),
        Some(Err(p)) => return Err(format!("/boot inconsistent: {p}")),
        None => return Err(String::from("FAT32 driver has no checker")),
    }
    Ok(())
}

fn root_ext4() -> Option<Arc<vfs::Mount>> {
    vfs::mounts().into_iter().find(|m| m.path == "/" && m.fs.fs_type() == "ext4" && !m.read_only())
}

pub fn ext4_root() -> TestResult {
    let Some(m) = root_ext4() else {
        kprintln!("[test]   skipped: no writable ext4 root");
        return Ok(());
    };
    let cx = root();
    let release = format!("OSyx {}\n", include_str!("../../VERSION").trim());
    ensure!(read_file(&cx, "/etc/osyx-release") == Ok(release.into_bytes()), "/etc/osyx-release");
    let st = vfs::stat(&cx, "/osyx-seed/secret").map_err(|x| e("stat secret", x))?;
    ensure!((st.mode, st.uid, st.kind) == (0o600, 0, KIND_FILE), "ext4 ownership and mode {st:?}");
    ensure!(vfs::open(&user(1000), "/osyx-seed/secret", OPEN_READ, 0).err() == Some(Errno::PermissionDenied), "ext4 permissions");
    ensure!(vfs::stat(&cx, "/home/user").map(|s| s.uid) == Ok(1000), "home directory owner");
    ensure!(vfs::readlink(&cx, "/osyx-seed/link").as_deref() == Ok("hello.txt"), "ext4 symlink");
    ensure!(vfs::stat(&cx, "/osyx-seed/sparse.bin").map(|s| s.size) == Ok((5 << 30) + 3), "large sparse file");
    let d = "/kselftest-ext4";
    remove_tree(d);
    vfs::mkdir(&cx, d, 0o755).map_err(|x| e("mkdir", x))?;
    let data: Vec<u8> = (0..100_000u32).map(|i| (i * 13 + 1) as u8).collect();
    write_file(&cx, "/kselftest-ext4/data.bin", &data).map_err(|x| e("write", x))?;
    ensure!(read_file(&cx, "/kselftest-ext4/data.bin") == Ok(data.clone()), "read back 100 KB");
    vfs::rename(&cx, "/kselftest-ext4/data.bin", "/kselftest-ext4/renamed.bin").map_err(|x| e("rename", x))?;
    vfs::symlink(&cx, "renamed.bin", "/kselftest-ext4/link").map_err(|x| e("symlink", x))?;
    ensure!(vfs::stat(&cx, "/kselftest-ext4/link").map(|s| s.size) == Ok(100_000), "ext4 symlink to a new file");
    vfs::chmod(&cx, "/kselftest-ext4/renamed.bin", 0o600).map_err(|x| e("chmod", x))?;
    ensure!(vfs::stat(&cx, "/kselftest-ext4/renamed.bin").map(|s| s.mode) == Ok(0o600), "chmod persisted");
    // Removed while open: data stays until the handle closes.
    let mut h = vfs::open(&cx, "/kselftest-ext4/renamed.bin", OPEN_READ, 0).map_err(|x| e("open", x))?;
    vfs::unlink(&cx, "/kselftest-ext4/renamed.bin").map_err(|x| e("unlink open file", x))?;
    let mut buf = [0u8; 16];
    ensure!(h.read(&mut buf) == Ok(16) && buf[..] == data[..16], "orphaned data readable");
    let before = vfs::statfs(&cx, "/").map_err(|x| e("statfs", x))?.free_blocks;
    drop(h);
    let after = vfs::statfs(&cx, "/").map_err(|x| e("statfs", x))?.free_blocks;
    ensure!(after > before, "blocks of the removed file freed on close ({before} -> {after})");
    remove_tree(d);
    ensure!(vfs::stat(&cx, d) == Err(Errno::NotFound), "cleanup");
    match m.fs.fsck() {
        Some(Ok(s)) => kprintln!("[test]   / ({}): {s}", m.source),
        Some(Err(p)) => return Err(format!("ext4 root inconsistent: {p}")),
        None => return Err(String::from("ext4 driver has no checker")),
    }
    Ok(())
}

static WORKER_OK: [AtomicBool; 6] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

fn pattern(seed: u64, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u64 * 31 + seed * 7) as u8).collect()
}

/// Writes its own file in chunks (yielding in between), reads it back.
fn worker(slot: u64, _: u64) {
    let dir = match slot {
        0 | 1 => "/tmp",
        2 | 3 => "/boot",
        _ => "",
    };
    let path = format!("{dir}/kst-worker-{slot}.bin");
    let data = pattern(slot, 20_000);
    let r = (|| -> Result<(), Errno> {
        let cx = root();
        let mut f = create(&cx, &path, 0o644)?;
        for chunk in data.chunks(3000) {
            f.write(chunk)?;
            sched::yield_now();
        }
        f.seek(0, SEEK_SET)?;
        let mut back = alloc::vec![0u8; data.len() + 10];
        let n = f.read(&mut back)?;
        if back[..n] != data[..] {
            return Err(Errno::Io);
        }
        drop(f);
        vfs::unlink(&cx, &path)
    })();
    if let Err(x) = r {
        kprintln!("[test]   worker {slot} ({path}): {x:?}");
    }
    WORKER_OK[slot as usize].store(r.is_ok(), Ordering::Relaxed);
}

pub fn concurrent() -> TestResult {
    let mut slots: Vec<u64> = alloc::vec![0, 1];
    if boot_fat().is_some() {
        slots.extend([2, 3]);
    }
    if root_ext4().is_some() {
        slots.extend([4, 5]);
    }
    let tids: Vec<_> = slots.iter().map(|&s| sched::spawn_kernel("vfs-worker", worker, s, 0)).collect();
    for t in tids {
        sched::join(t);
    }
    for s in slots {
        ensure!(WORKER_OK[s as usize].load(Ordering::Relaxed), "worker {s} failed");
    }
    for m in [boot_fat(), root_ext4()].into_iter().flatten() {
        if let Some(Err(p)) = m.fs.fsck() {
            return Err(format!("{} inconsistent after concurrent writes: {p}", m.path));
        }
    }
    Ok(())
}

/// Checks path rules on opens without claiming a complete sandbox.
pub fn restricted_opens() -> TestResult {
    use osyx_vfs::{sandbox::PathPolicy, Access};
    let root = root();
    let dir = "/tmp/kst-sandbox";
    remove_tree(dir);
    vfs::mkdir(&root, dir, 0o755).map_err(|err| e("mkdir", err))?;
    let result = (|| -> TestResult {
        let inside = format!("{dir}/inside");
        let outside = "/tmp/kst-sandbox-outside";
        write_file(&root, &inside, b"inside").map_err(|err| e("write inside", err))?;
        write_file(&root, outside, b"outside").map_err(|err| e("write outside", err))?;
        vfs::symlink(&root, outside, &format!("{dir}/escape")).map_err(|err| e("symlink", err))?;
        let policy = PathPolicy::new(&[(dir, Access::READ)]).map_err(|err| e("policy", err))?;
        let restricted = Lookup { path_policy: Some(Arc::new(policy)), ..root.clone() };
        ensure!(read_file(&restricted, &inside).is_ok(), "allowed file denied");
        ensure!(vfs::stat(&restricted, "/tmp").is_ok(), "allowed ancestor metadata denied");
        ensure!(matches!(vfs::open(&restricted, "/tmp", OPEN_READ | OPEN_DIRECTORY, 0), Err(Errno::PermissionDenied)), "ancestor listing allowed");
        ensure!(matches!(vfs::open(&restricted, outside, OPEN_READ, 0), Err(Errno::PermissionDenied)), "outside file allowed");
        ensure!(matches!(vfs::open(&restricted, &format!("{dir}/escape"), OPEN_READ, 0), Err(Errno::PermissionDenied)), "symlink escape allowed");
        ensure!(matches!(vfs::open(&restricted, &inside, OPEN_WRITE, 0), Err(Errno::PermissionDenied)), "write allowed");
        ensure!(matches!(vfs::open_exec(&restricted, &inside), Err(Errno::PermissionDenied)), "execute allowed");
        ensure!(matches!(vfs::stat(&restricted, outside), Err(Errno::PermissionDenied)), "outside stat allowed");
        ensure!(matches!(vfs::unlink(&restricted, &inside), Err(Errno::PermissionDenied)), "unlink allowed");
        ensure!(matches!(vfs::rename(&restricted, &inside, &format!("{dir}/renamed")), Err(Errno::PermissionDenied)), "rename allowed");
        ensure!(matches!(vfs::chmod(&restricted, &inside, 0o777), Err(Errno::PermissionDenied)), "chmod allowed");
        ensure!(matches!(vfs::mkdir(&restricted, &format!("{dir}/subdir"), 0o755), Err(Errno::PermissionDenied)), "mkdir allowed");
        ensure!(matches!(vfs::symlink(&restricted, outside, &format!("{dir}/newlink")), Err(Errno::PermissionDenied)), "symlink allowed");
        let new = format!("{dir}/new");
        ensure!(matches!(create(&restricted, &new, 0o644), Err(Errno::PermissionDenied)), "create allowed");
        ensure!(matches!(vfs::stat(&root, &new), Err(Errno::NotFound)), "denied create left a file");
        let rw = Access { read: true, write: true, exec: false };
        let writable = Lookup { path_policy: Some(Arc::new(PathPolicy::new(&[(dir, rw)]).map_err(|err| e("write policy", err))?)), ..root.clone() };
        write_file(&writable, &new, b"new").map_err(|err| e("allowed create", err))?;
        let renamed = format!("{dir}/renamed");
        vfs::rename(&writable, &new, &renamed).map_err(|err| e("allowed rename", err))?;
        ensure!(matches!(vfs::rename(&writable, &renamed, outside), Err(Errno::PermissionDenied)), "rename escape allowed");
        vfs::unlink(&writable, &renamed).map_err(|err| e("allowed unlink", err))?;
        let _ = vfs::unlink(&root, outside);
        Ok(())
    })();
    let _ = vfs::unlink(&root, "/tmp/kst-sandbox-outside");
    remove_tree(dir);
    result
}

/// Exercise kernel-installed restrictions in a real process and its child.
pub fn restricted_process() -> TestResult {
    use crate::{exec::ExecRequest, process};
    use osyx_abi::{nr, sandbox::SyscallPolicy};
    use osyx_vfs::{sandbox::PathPolicy, Access};
    let req = ExecRequest::new("/bin/worker", &["worker", "sandbox"], &[]).map_err(|err| e("request", err))?;
    let denied_paths = Arc::new(PathPolicy::default());
    let allowed: Vec<u64> = (0..256).filter(|n| *n != nr::CPU_INFO).collect();
    let syscalls = Arc::new(SyscallPolicy::new(&allowed));
    ensure!(matches!(process::spawn_kernel_restricted(&req, denied_paths, syscalls.clone()), Err(process::ExecError::Load(Errno::PermissionDenied))), "executable loaded without permission");
    let access = Access { read: true, write: false, exec: true };
    let paths = Arc::new(PathPolicy::new(&[("/bin", access)]).map_err(|err| e("policy", err))?);
    let pid = process::spawn_kernel_restricted(&req, paths, syscalls).map_err(|err| format!("spawn: {err}"))?;
    let (_, status) = process::wait(process::KERNEL_PID, pid).map_err(|err| e("wait", err))?;
    ensure!(status == 0, "restricted worker exited with status {status}");
    let broker = ExecRequest::new("/bin/worker", &["worker", "sandbox-broker"], &[]).map_err(|err| e("broker request", err))?;
    let pid = process::spawn(process::KERNEL_PID, &broker).map_err(|err| format!("broker spawn: {err}"))?;
    let (_, status) = process::wait(process::KERNEL_PID, pid).map_err(|err| e("broker wait", err))?;
    ensure!(status == 0, "broker test exited with status {status}");
    Ok(())
}

/// Verify a held child cannot execute before resume or after termination.
pub fn suspended_process() -> TestResult {
    use crate::{exec::ExecRequest, process};
    let req = ExecRequest::new("/bin/worker", &["worker", "suspend-test"], &[]).map_err(|err| e("request", err))?;
    let pid = process::spawn(process::KERNEL_PID, &req).map_err(|err| format!("spawn: {err}"))?;
    let (_, status) = process::wait(process::KERNEL_PID, pid).map_err(|err| e("wait", err))?;
    ensure!(status == 0, "suspended process test exited with status {status}");
    Ok(())
}

/// Run only in an explicitly requested test boot with a fixture, never replace
/// an installed browser. The caller supplies winrun and sandboxpe modules.
pub fn restricted_winrun() -> TestResult {
    use crate::{exec::ExecRequest, process};
    let cx = root();
    let image = read_file(&cx, "/bin/sandboxpe").map_err(|err| e("read PE fixture", err))?;
    if vfs::stat(&cx, "/opt/zen/zen.exe").is_ok() {
        return Err(String::from("refusing to replace an installed browser"));
    }
    let opt_created = vfs::mkdir(&cx, "/opt", 0o755).is_ok();
    let zen_created = vfs::mkdir(&cx, "/opt/zen", 0o755).is_ok();
    let mut fixture_created = false;
    let mut secret_created = false;
    let result = (|| -> TestResult {
        // Exclusive creation protects an existing browser even if it appears
        // after the check above.
        let mut file = vfs::open(&cx, "/opt/zen/zen.exe", OPEN_WRITE | OPEN_CREATE | OPEN_EXCLUSIVE, 0o755).map_err(|err| e("create PE fixture", err))?;
        fixture_created = true;
        let mut done = 0;
        while done < image.len() {
            let n = file.write(&image[done..]).map_err(|err| e("write PE fixture", err))?;
            if n == 0 { return Err(String::from("short write of PE fixture")); }
            done += n;
        }
        drop(file);
        let mut secret = vfs::open(&cx, "/tmp/sandbox-winrun-secret", OPEN_WRITE | OPEN_CREATE | OPEN_EXCLUSIVE, 0o600).map_err(|err| e("create secret", err))?;
        secret_created = true;
        secret.write(b"private").map_err(|err| e("write secret", err))?;
        drop(secret);
        let req = ExecRequest::new("/bin/winrun", &["winrun", "/opt/zen/zen.exe"], &["OSYX_EXPERIMENTAL_CONTENT_SANDBOX=1"]).map_err(|err| e("request", err))?;
        let pid = process::spawn(process::KERNEL_PID, &req).map_err(|err| format!("winrun spawn: {err}"))?;
        let (_, status) = process::wait(process::KERNEL_PID, pid).map_err(|err| e("winrun wait", err))?;
        ensure!(status == 0, "Winrun PE fixture exited with status {status}");
        Ok(())
    })();
    if fixture_created { let _ = vfs::unlink(&cx, "/opt/zen/zen.exe"); }
    if secret_created { let _ = vfs::unlink(&cx, "/tmp/sandbox-winrun-secret"); }
    if zen_created { let _ = vfs::rmdir(&cx, "/opt/zen"); }
    if opt_created { let _ = vfs::rmdir(&cx, "/opt"); }
    result
}

/// The program loader's lookup and refusals (`spawn` / `execve`), without
/// running anything: search path, permissions, non-ELF files, limits.
pub fn program_loader() -> TestResult {
    use crate::exec::{self, ExecRequest};
    use crate::process::{self, ExecError};
    let cx = root();
    let load = |cx: &Lookup, p: &str| exec::load(cx, p).map(|prog| prog.path);
    match load(&cx, "init") {
        Ok(p) => {
            ensure!(p == "/bin/init", "init found at {p}");
            let prog = exec::load(&cx, "/bin/../bin/init").map_err(|err| e("load by path", err))?;
            ensure!(prog.image.starts_with(b"\x7fELF"), "/bin/init is not ELF");
        }
        Err(Errno::NotFound) => kprintln!("[test]   no /bin/init on this root; search path checked without it"),
        Err(err) => return Err(e("load init", err)),
    }
    ensure!(load(&cx, "no-such-program") == Err(Errno::NotFound), "missing program not NotFound");
    ensure!(load(&cx, "/bin/no-such-program") == Err(Errno::NotFound), "missing path not NotFound");
    ensure!(load(&cx, "..") == Err(Errno::InvalidArgument), "'..' accepted as a program name");

    let dir = "/tmp/loader-test";
    remove_tree(dir);
    vfs::mkdir(&cx, dir, 0o755).map_err(|err| e("mkdir", err))?;
    let r = (|| -> TestResult {
        let elf = &b"\x7fELF\x02\x01\x01"[..];
        write_file(&cx, &format!("{dir}/plain"), elf).map_err(|err| e("write plain", err))?;
        ensure!(load(&cx, &format!("{dir}/plain")) == Err(Errno::PermissionDenied), "0644 file executable by root");
        ensure!(load(&cx, dir) == Err(Errno::PermissionDenied), "directory executable");
        write_file(&cx, &format!("{dir}/garbage"), b"#!/bin/sh\necho no interpreters\n").map_err(|err| e("write", err))?;
        vfs::chmod(&cx, &format!("{dir}/garbage"), 0o700).map_err(|err| e("chmod", err))?;
        ensure!(load(&cx, &format!("{dir}/garbage")).is_ok(), "0700 file not loadable by root");
        ensure!(load(&user(1000), &format!("{dir}/garbage")) == Err(Errno::PermissionDenied), "0700 root file loadable by a user");
        let req = ExecRequest::new(&format!("{dir}/garbage"), &["garbage"], &[]).map_err(|err| e("request", err))?;
        let r = process::spawn(process::KERNEL_PID, &req);
        ensure!(matches!(r, Err(ExecError::BadImage(_))), "non-ELF file spawned: {:?}", r.map_err(|e| e.errno()));
        ensure!(ExecError::BadImage(osyx_elf::ElfError::BadMagic).errno() == Errno::BadExecutable, "errno of a bad image");
        // A relative path resolves from the current directory.
        let here = Lookup { cwd: String::from(dir), ..root() };
        ensure!(load(&here, "./garbage").map(|p| p == format!("{dir}/garbage")) == Ok(true), "relative path");
        Ok(())
    })();
    remove_tree(dir);
    r?;

    let big = "x".repeat(MAX_EXEC_ARGS);
    ensure!(ExecRequest::new("init", &["init", &big], &[]).err() == Some(Errno::InvalidArgument), "oversized argv accepted");
    let many = alloc::vec!["A=1"; MAX_EXEC_STRINGS + 1];
    ensure!(ExecRequest::new("init", &["init"], &many).err() == Some(Errno::InvalidArgument), "too many env strings accepted");
    ensure!(ExecRequest::new("init", &["a\0b"], &[]).err() == Some(Errno::InvalidArgument), "NUL in argv accepted");
    let ok = ExecRequest::new("/usr/bin/probe", &["probe"], &["K=V"]).map_err(|err| e("request", err))?;
    ensure!(ok.name() == "probe", "process name {:?}", ok.name());
    Ok(())
}
