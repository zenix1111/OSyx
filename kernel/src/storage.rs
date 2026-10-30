//! Boot-time storage setup: find disks and partitions, mount the file
//! system tree.
//!
//! Layout:
//!
//! | Mount point | File system | Source |
//! |---|---|---|
//! | `/` | ext4 | GPT partition of type "Linux root (x86-64)", or `root=<dev>` |
//! | `/boot` | FAT32 | the EFI system partition OSyx started from |
//! | `/dev` | devfs | the device registry |
//! | `/tmp` | tmpfs | RAM, mode 1777 |
//! | `/run` | tmpfs | RAM, mode 0755 |
//!
//! Without a usable root partition a small tmpfs becomes `/` so the rest
//! of the tree still works (and the log says so); the boot modules from
//! `\EFI\OSYX\BIN` become its `/bin`. Other FAT32/ext4 volumes are mounted
//! below `/mnt/<device>`; removable media (USB sticks) go to
//! `/media/<label>` instead, see `media`.

use crate::block::{self, BlockDev};
use crate::vfs::{self, devfs::DevFs, tmpfs::TmpfsVolume, Filesystem, Lookup};
use crate::{kprintln, live, modules, BootData};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use osyx_abi::{MOUNT_READ_ONLY, OPEN_CREATE, OPEN_TRUNCATE, OPEN_WRITE};

const TMP_LIMIT: u64 = 64 << 20;
const RUN_LIMIT: u64 = 8 << 20;
// The live root unpacks into this tmpfs; the installed fallback (boot
// modules only) uses a few MiB of it. tmpfs charges only what is stored.
const FALLBACK_ROOT_LIMIT: u64 = 256 << 20;

/// What ended up mounted, for the boot summary and tests.
pub struct Summary {
    pub root: String,
    pub mounts: usize,
}

pub(crate) fn probe_fs(disk: &Arc<dyn BlockDev>) -> Option<&'static str> {
    let mut s = [0u8; block::SECTOR_SIZE * 4];
    block::read(&**disk, 0, &mut s).ok()?;
    // ext2/3/4: superblock at byte 1024, magic 0xEF53 at offset 56.
    if s[1024 + 56] == 0x53 && s[1024 + 57] == 0xEF {
        return Some("ext4");
    }
    // exFAT: file system name in the boot sector.
    if &s[3..11] == b"EXFAT   " && s[510] == 0x55 && s[511] == 0xAA {
        return Some("exfat");
    }
    // FAT32: boot signature and "FAT32   " file system type string.
    if s[510] == 0x55 && s[511] == 0xAA && &s[82..90] == b"FAT32   " {
        return Some("fat32");
    }
    None
}

/// Mounts the recognisable volumes of a disk that appeared after boot (a
/// USB stick) at `/mnt/<device>`, like the volumes found at boot.
pub fn mount_hotplugged(disk: &str) {
    let candidates: Vec<Arc<dyn BlockDev>> = block::devices()
        .into_iter()
        .filter(|d| d.name() == disk || d.parent_name() == Some(disk))
        .filter(|d| {
            // A partitioned disk itself holds no file system.
            d.partition().is_some() || !block::devices().iter().any(|p| p.parent_name() == Some(d.name()))
        })
        .collect();
    for d in candidates {
        let name = String::from(d.name());
        if vfs::mounts().iter().any(|m| m.fs.backing_device().is_some_and(|b| b == name)) {
            continue;
        }
        let Some(fstype) = probe_fs(&d) else { continue };
        let at = alloc::format!("/mnt/{name}");
        if vfs::mkdir(&Lookup::kernel(), &at, 0o755).is_err() && vfs::stat(&Lookup::kernel(), &at).is_err() {
            continue;
        }
        let ro = d.read_only();
        if try_mount(fstype, d, &at, ro) {
            kprintln!("storage: {name} ({fstype}) mounted at {at}");
        }
    }
}

fn try_mount(fstype: &str, disk: Arc<dyn BlockDev>, at: &str, read_only: bool) -> bool {
    let name = String::from(disk.name());
    match vfs::mount_disk(fstype, disk, read_only) {
        Ok(fs) => match vfs::mount_fs(at, &alloc::format!("/dev/disks/{name}"), if read_only { MOUNT_READ_ONLY } else { 0 }, fs) {
            Ok(_) => true,
            Err(e) => {
                kprintln!("storage: mounting {name} at {at} failed: {e:?}");
                false
            }
        },
        Err(e) => {
            kprintln!("storage: {name}: {fstype} not mountable: {e:?}");
            false
        }
    }
}

/// The whole disk a partition belongs to: `vda2` -> `vda`,
/// `nvme0n1p2` -> `nvme0n1`.
fn disk_of(partition: &str) -> &str {
    let base = partition.trim_end_matches(|c: char| c.is_ascii_digit());
    match base.strip_suffix('p') {
        Some(d) if d.ends_with(|c: char| c.is_ascii_digit()) => d,
        _ => base,
    }
}

/// Mounts at `/boot` the EFI system partition OSyx started from. A machine
/// often has several (the internal disk's, the live stick's): taking the
/// first one found would mount another system's ESP and make its disk look
/// busy to Setup. Installed systems use the ESP on the root's disk; a live
/// boot uses the ESP holding the live archive and leaves the others alone.
fn mount_boot(esps: &[Arc<dyn BlockDev>], root: Option<&str>, live: bool, used: &mut Vec<String>) {
    let cx = Lookup::kernel();
    for dev in esps {
        let name = String::from(dev.name());
        if let Some(root) = root {
            if disk_of(&name) != disk_of(root) {
                continue;
            }
        }
        if probe_fs(dev) != Some("fat32") {
            kprintln!("storage: EFI system partition {name} is not a FAT32 volume");
            continue;
        }
        if !try_mount("fat32", dev.clone(), "/boot", false) {
            continue;
        }
        if live && vfs::stat(&cx, "/boot/EFI/OSYX/BIN/rootfs.z").is_err() {
            kprintln!("storage: {name} is not the live medium's EFI partition; not mounted");
            if let Err(e) = vfs::unmount(&cx, "/boot") {
                kprintln!("storage: cannot unmount {name} from /boot: {e:?}");
                used.push(name);
                return;
            }
            continue;
        }
        used.push(name);
        return;
    }
    if root.is_some() {
        // No ESP beside the root: fall back to any, as before.
        mount_boot(esps, None, live, used);
    }
}

/// Creates the standard mount points on a fresh fallback root and installs
/// the boot modules as programs in `/bin`.
fn populate_fallback_root() {
    let cx = Lookup::kernel();
    for d in ["boot", "dev", "tmp", "run", "mnt", "bin"] {
        if let Err(e) = vfs::mkdir(&cx, &alloc::format!("/{d}"), 0o755) {
            kprintln!("storage: cannot create /{d} on the fallback root: {e:?}");
        }
    }
    for (name, data) in modules::all() {
        let path = alloc::format!("/bin/{name}");
        let flags = OPEN_WRITE | OPEN_CREATE | OPEN_TRUNCATE;
        let r = vfs::open(&cx, &path, flags, 0o755).and_then(|mut f| {
            let mut done = 0;
            while done < data.len() {
                match f.write(&data[done..])? {
                    0 => return Err(osyx_abi::Errno::NoSpace),
                    n => done += n,
                }
            }
            Ok(())
        });
        match r {
            Ok(()) => kprintln!("storage: boot module {name} installed as {path}"),
            Err(e) => kprintln!("storage: cannot install {path}: {e:?}"),
        }
    }
}

pub fn mount_all(boot: &BootData) -> Summary {
    let disks = block::devices();
    let esps: Vec<Arc<dyn BlockDev>> =
        disks.iter().filter(|d| d.partition().is_some_and(|p| p.type_guid == osyx_part::TYPE_ESP)).cloned().collect();
    let wanted_root = boot.option_value("root");
    // A live boot keeps every disk untouched: the whole system comes from
    // the compressed archive in \EFI\OSYX\BIN.
    let root_dev = if boot.has_option("live") {
        kprintln!("storage: live boot; disk roots ignored");
        None
    } else {
        match wanted_root {
            Some(name) => disks.iter().find(|d| d.name() == name).cloned(),
            None => disks.iter().find(|d| d.partition().is_some_and(|p| p.type_guid == osyx_part::TYPE_ROOT_X86_64)).cloned(),
        }
    };
    let root_ro = boot.has_option("ro");
    let mut used: Vec<String> = Vec::new();
    let mut root = String::from("tmpfs (fallback)");
    let mut have_root = false;
    if let Some(dev) = root_dev {
        match probe_fs(&dev) {
            Some(fstype) => {
                let name = String::from(dev.name());
                if try_mount(fstype, dev, "/", root_ro) {
                    root = alloc::format!("{fstype} on {name}");
                    used.push(name);
                    have_root = true;
                }
            }
            None => kprintln!("storage: root device {} holds no known file system", dev.name()),
        }
    } else if let Some(name) = wanted_root {
        kprintln!("storage: root={name}: no such block device");
    }
    if !have_root {
        kprintln!("storage: no root file system; using a {} MiB tmpfs as /", FALLBACK_ROOT_LIMIT >> 20);
        let fs: Arc<dyn Filesystem> = Arc::new(TmpfsVolume::new(FALLBACK_ROOT_LIMIT, 0o755));
        vfs::mount_fs("/", "tmpfs", 0, fs).expect("mounting a fresh tmpfs at / cannot fail");
        if live::present() {
            match live::unpack() {
                Ok(n) => {
                    kprintln!("storage: live root unpacked ({} entries)", n);
                    root = alloc::format!("tmpfs (live root, {n} entries)");
                }
                Err(e) => {
                    kprintln!("storage: live root unusable: {e}");
                    populate_fallback_root();
                }
            }
        } else {
            populate_fallback_root();
        }
    }
    let mount_virtual = |at: &str, fs: Arc<dyn Filesystem>, src: &str| {
        if let Err(e) = vfs::mount_fs(at, src, 0, fs) {
            kprintln!("storage: cannot mount {src} at {at}: {e:?}");
        }
    };
    mount_virtual("/dev", Arc::new(DevFs::new()), "devfs");
    mount_virtual("/tmp", Arc::new(TmpfsVolume::new(TMP_LIMIT, 0o1777)), "tmpfs");
    mount_virtual("/run", Arc::new(TmpfsVolume::new(RUN_LIMIT, 0o755)), "tmpfs");
    let root_name = if have_root { used.first().cloned() } else { None };
    mount_boot(&esps, root_name.as_deref(), boot.has_option("live"), &mut used);
    // Remaining recognisable volumes go to /mnt/<device>.
    for d in disks {
        let name = String::from(d.name());
        // USB sticks and other removable disks belong to the media manager
        // (`/media/<label>`, eject), below.
        if d.removable() {
            continue;
        }
        let covered = used.iter().any(|u| *u == name || u.starts_with(&name) || name.starts_with(u.as_str()));
        let is_partitioned_disk = d.partition().is_none() && block::devices().iter().any(|p| p.parent_name() == Some(name.as_str()));
        if covered || is_partitioned_disk {
            continue;
        }
        if let Some(fstype) = probe_fs(&d) {
            let at = alloc::format!("/mnt/{name}");
            if vfs::mkdir(&Lookup::kernel(), &at, 0o755).is_ok() || vfs::stat(&Lookup::kernel(), &at).is_ok() {
                let ro = d.read_only();
                if try_mount(fstype, d, &at, ro) {
                    used.push(name);
                }
            }
        }
    }
    crate::media::init();
    crate::media::attach_boot_media();
    Summary { root, mounts: vfs::mounts().len() }
}
