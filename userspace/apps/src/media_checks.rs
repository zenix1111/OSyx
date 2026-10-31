//! USB media scenario run by `init tests media` (see
//! `scripts/usb-storage-test.ps1`, which plugs and unplugs the stick through
//! QMP when it sees the `MEDIA_*` markers on the serial console).
//!
//! 1. A stick (FAT32 in an MBR partition, label `PENDRIVE`) is attached at
//!    boot: it must be mounted at `/media/PENDRIVE`, `HELLO.TXT` readable,
//!    a new file writable.
//! 2. Ejecting with a file open must fail with `Busy` and change nothing;
//!    after closing it the eject works, the mount point goes away and the
//!    status says `ejected`.
//! 3. The script unplugs and replugs the stick: it is mounted again and the
//!    file written in step 1 is still there.
//! 4. With a file open on it, the script pulls the stick out: the kernel
//!    must survive, the volume vanish, and the open handle fail instead of
//!    hanging.

use os_std::error::ErrorKind;
use os_std::fs::{self, OpenOptions};
use os_std::io::{Read, Write};
use os_std::prelude::*;
use os_std::thread;
use os_std::time::{Duration, Instant};

const STICK: &str = "/media/PENDRIVE";
const NOTE: &str = "written to the stick by OSyx\n";

use osyx_abi::media::{self, Disk, DiskState};

fn status() -> Vec<Disk> {
    media::parse(&fs::read_to_string(media::STATUS_PATH).unwrap_or_default())
}

fn mounted_at(d: &Disk, path: &str) -> bool {
    d.volumes.iter().any(|v| v.mount.as_deref() == Some(path))
}

fn wait_for(what: &str, seconds: u64, mut ok: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < end {
        if ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    println!("MEDIA_TIMEOUT {what}");
    false
}

fn eject(disk: &str) -> Result<(), ErrorKind> {
    let mut f = OpenOptions::new().write(true).open(media::CONTROL_PATH).map_err(|e| e.kind())?;
    f.write_all(format!("eject {disk}\n").as_bytes()).map_err(|e| e.kind())
}

fn step(name: &str, ok: bool) -> bool {
    println!("{} {name}", if ok { "MEDIA_OK" } else { "MEDIA_FAIL" });
    ok
}

pub fn run() -> i32 {
    let mut failed = 0;
    let mut check = |name: &str, ok: bool| {
        if !step(name, ok) {
            failed += 1;
        }
    };

    // 1. Automount at boot.
    let mounted = wait_for("automount", 90, || status().iter().any(|d| d.state == DiskState::Mounted && mounted_at(d, STICK)));
    check("automount at /media/PENDRIVE", mounted);
    if !mounted {
        println!("status: {:?}", fs::read_to_string(media::STATUS_PATH));
        return 1;
    }
    let disk = status().into_iter().find(|d| mounted_at(d, STICK)).map(|d| d.name).unwrap_or_default();
    check("read HELLO.TXT", fs::read_to_string(format!("{STICK}/HELLO.TXT")).is_ok_and(|s| s.starts_with("Hello")));
    let wrote = fs::write(format!("{STICK}/OSYX.TXT"), NOTE).is_ok();
    check("write OSYX.TXT", wrote);
    check("files on the stick belong to the desktop user", fs::metadata(format!("{STICK}/OSYX.TXT")).is_ok_and(|m| m.uid() == media::OWNER_UID && m.gid() == media::OWNER_GID));
    let statfs_ok = os_std::os::statfs(STICK).is_ok_and(|s| s.total_blocks > 0);
    check("statfs of the stick", statfs_ok);

    // 2. Busy, then a clean eject.
    let held = OpenOptions::new().read(true).open(format!("{STICK}/HELLO.TXT"));
    check("open file on the stick", held.is_ok());
    check("eject with an open file is refused (Busy)", eject(&disk) == Err(ErrorKind::ResourceBusy));
    check("volume still mounted after the refusal", status().iter().any(|d| mounted_at(d, STICK)));
    check("file still readable after the refusal", fs::read_to_string(format!("{STICK}/OSYX.TXT")).as_deref() == Ok(NOTE));
    drop(held);
    check("eject after closing the file", eject(&disk).is_ok());
    check("mount point gone", fs::metadata(STICK).is_err());
    check("status says ejected", status().iter().any(|d| d.name == disk && d.state == DiskState::Ejected));
    println!("MEDIA_EJECTED {disk}");

    // 3. The script replugs the stick: a new disk, same volume.
    let again = wait_for("remount after replug", 90, || status().iter().any(|d| d.state == DiskState::Mounted && mounted_at(d, STICK)));
    check("stick mounted again after replug", again);
    check("old disk entry removed after the unplug", !status().iter().any(|d| d.name == disk));
    check("file written before the eject survived", fs::read_to_string(format!("{STICK}/OSYX.TXT")).as_deref() == Ok(NOTE));
    let disk2 = status().into_iter().find(|d| mounted_at(d, STICK)).map(|d| d.name).unwrap_or_default();

    // 4. Pulled out while a file is open.
    let mut open = OpenOptions::new().read(true).write(true).open(format!("{STICK}/OSYX.TXT"));
    check("open file before the yank", open.is_ok());
    println!("MEDIA_READY_YANK {disk2}");
    let gone = wait_for("volume removal after yank", 60, || !status().iter().any(|d| d.name == disk2));
    check("volume removed after the yank", gone);
    check("mount point gone after the yank", fs::metadata(STICK).is_err());
    if let Ok(f) = open.as_mut() {
        let mut buf = [0u8; 64];
        let r = f.read(&mut buf);
        println!("MEDIA_YANK_READ {:?}", r.as_ref().map(|n| *n).map_err(|e| e.kind()));
        // Either an error or cached data is fine; hanging or crashing is not.
        check("read on the open handle returns", true);
        let w = f.write_all(b"x");
        check("write on the open handle fails", w.is_err());
    }
    drop(open);
    println!("MEDIA_YANK_DONE");
    println!("media checks: {failed} failed");
    failed
}
