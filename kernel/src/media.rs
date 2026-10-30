//! Removable media: mounts USB sticks and disks when they appear, ejects
//! them safely, and cleans up when one is pulled out.
//!
//! * Automount: when the block layer has scanned a removable disk
//!   ([`disk_ready`]), every recognisable volume on it is mounted at
//!   `/media/<label>` (FAT32, exFAT, ext4; the device name stands in for a
//!   missing label, `-2`, `-3`, ... keep names unique). A volume without a
//!   known file system is listed but not mounted. Disks that hold a mounted
//!   system volume (booting from a USB stick) are not removable media here.
//! * Safe eject ([`eject`], `eject <disk>` written to `/dev/media`): every
//!   volume is synced, then all of them are detached in one step, or none
//!   if any is in use (`Busy`, with the path in the status file). The disk
//!   cache is flushed, the drive is stopped, and the block devices go away.
//!   The medium stays listed as "ejected" until it is physically removed.
//! * Surprise removal ([`disk_gone`]): the driver has already made the
//!   disk fail all I/O; its volumes are detached by force, open files fail
//!   with I/O errors, and nothing in the kernel waits for the dead device.
//!
//! `/run/media.status` lists the media for the desktop, rewritten on every
//! change; its format is `osyx_abi::media`.

use crate::block::{self, BlockDev};
use crate::devices::{self, CharDevice, DeviceKind};
use crate::sync::KMutex;
use crate::vfs::{self, Lookup};
use crate::{kprintln, sched, storage};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use osyx_abi::media::{self as status, Disk, DiskState, Volume};
use osyx_abi::{Errno, MOUNT_READ_ONLY, OPEN_CREATE, OPEN_TRUNCATE, OPEN_WRITE};

const STATUS_TMP: &str = "/run/media.status.tmp";
const ROOTS: [&str; 2] = ["/media", "/run/media"];

static MEDIA: KMutex<Vec<Disk>> = KMutex::new(Vec::new());
/// One operation (mount, eject, removal) at a time.
static OP: KMutex<()> = KMutex::new(());
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// A mount point name from a volume label: letters, digits and `-_.`
/// stay, everything else becomes `_`, at most 32 characters.
pub fn sanitize_label(label: &str) -> String {
    let mut out: String = label
        .chars()
        .take(32)
        .map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    // "." and ".." are not names.
    if out.chars().all(|c| c == '.') {
        out.clear();
    }
    out
}

fn media_root(cx: &Lookup) -> Option<&'static str> {
    ROOTS.iter().copied().find(|root| {
        vfs::stat(cx, root).is_ok() || {
            // `/run/media` needs `/run` first; `/media` is created on the root.
            vfs::mkdir(cx, root, 0o755).is_ok()
        }
    })
}

fn mount_point(cx: &Lookup, root: &str, label: &str, device: &str) -> String {
    let base = match sanitize_label(label) {
        s if s.is_empty() => String::from(device),
        s => s,
    };
    let taken = |p: &str| vfs::stat(cx, p).is_ok() || vfs::mounts().iter().any(|m| m.path == p);
    let first = format!("{root}/{base}");
    if !taken(&first) {
        return first;
    }
    (2..1000).map(|n| format!("{root}/{base}-{n}")).find(|p| !taken(p)).unwrap_or(first)
}

/// Recognisable volumes of a disk: its partitions, or the disk itself when
/// it has none.
fn volume_devices(disk: &Arc<dyn BlockDev>) -> Vec<Arc<dyn BlockDev>> {
    let all = block::devices();
    let parts: Vec<Arc<dyn BlockDev>> = all.iter().filter(|d| d.parent_name() == Some(disk.name())).cloned().collect();
    if parts.is_empty() {
        alloc::vec![disk.clone()]
    } else {
        parts
    }
}

/// Called once a removable disk and its partitions are registered (by the
/// scan thread for hot-plugged disks, at the end of boot for the others).
pub fn disk_ready(disk: &Arc<dyn BlockDev>) {
    if !disk.removable() {
        storage::mount_hotplugged(disk.name());
        return;
    }
    let _op = OP.lock();
    if !disk.present() {
        return;
    }
    let cx = Lookup::kernel();
    let volumes = volume_devices(disk);
    // A disk with a mounted system volume (live or installed system on a
    // USB stick) is part of the running system, not removable media.
    if volumes.iter().any(|v| vfs::device_in_use(v.name())) {
        kprintln!("media: {} holds the running system; not treated as removable media", disk.name());
        return;
    }
    if MEDIA.lock().iter().any(|m| m.name == disk.name()) {
        return;
    }
    let root = media_root(&cx);
    let mut recorded = Vec::new();
    for dev in volumes {
        let bytes = dev.sector_count() * block::SECTOR_SIZE as u64;
        let mut vol = Volume {
            device: String::from(dev.name()),
            fstype: String::from("unknown"),
            label: String::new(),
            mount: None,
            bytes,
            read_only: dev.read_only(),
        };
        if let Some(fstype) = storage::probe_fs(&dev) {
            vol.fstype = String::from(fstype);
            match mount_volume(&cx, root, &dev, fstype) {
                Some((label, at)) => {
                    vol.label = label;
                    vol.mount = Some(at);
                }
                None => kprintln!("media: {} ({}) could not be mounted", dev.name(), fstype),
            }
        } else {
            kprintln!("media: {}: no supported file system", dev.name());
        }
        recorded.push(vol);
    }
    let mounted = recorded.iter().filter(|v| v.mount.is_some()).count();
    kprintln!("media: {} \"{}\": {} volume(s), {} mounted", disk.name(), disk.model(), recorded.len(), mounted);
    MEDIA.lock().push(Disk {
        name: String::from(disk.name()),
        model: disk.model(),
        bytes: disk.sector_count() * block::SECTOR_SIZE as u64,
        state: DiskState::Mounted,
        volumes: recorded,
        note: String::new(),
    });
    publish();
}

/// Mounts `dev` at a fresh `/media/<label>`; returns the label and path.
fn mount_volume(cx: &Lookup, root: Option<&str>, dev: &Arc<dyn BlockDev>, fstype: &str) -> Option<(String, String)> {
    let root = root?;
    let read_only = dev.read_only();
    let owner = Some((status::OWNER_UID, status::OWNER_GID));
    let fs = match vfs::mount_disk_owned(fstype, dev.clone(), read_only, owner) {
        Ok(fs) => fs,
        Err(e) => {
            kprintln!("media: {}: {} not mountable: {:?}", dev.name(), fstype, e);
            return None;
        }
    };
    let label = fs.label();
    let at = mount_point(cx, root, &label, dev.name());
    if let Err(e) = vfs::mkdir(cx, &at, 0o755) {
        kprintln!("media: cannot create {at}: {e:?}");
        let _ = fs.unmount();
        return None;
    }
    let flags = if read_only { MOUNT_READ_ONLY } else { 0 };
    match vfs::mount_fs(&at, &format!("/dev/disks/{}", dev.name()), flags, fs.clone()) {
        Ok(_) => {
            kprintln!("media: {} ({fstype}) mounted at {at}", dev.name());
            Some((label, at))
        }
        Err(e) => {
            kprintln!("media: mounting {} at {at} failed: {e:?}", dev.name());
            let _ = fs.unmount();
            let _ = vfs::rmdir(cx, &at);
            None
        }
    }
}

fn mount_paths(volumes: &[Volume]) -> Vec<String> {
    volumes.iter().filter_map(|v| v.mount.clone()).collect()
}

/// Unmounts the detached volumes and removes their mount point directories.
/// Returns false if a volume could not write its last data.
fn finish_unmount(cx: &Lookup, detached: Vec<Arc<vfs::Mount>>) -> bool {
    let mut clean = true;
    for m in detached {
        if let Err(e) = m.fs.unmount() {
            kprintln!("media: unmounting {} reported {:?}", m.path, e);
            clean = false;
        }
        kprintln!("media: {} unmounted from {}", m.fs.fs_type(), m.path);
        let _ = vfs::rmdir(cx, &m.path);
    }
    clean
}

/// Safely removes a disk: sync, unmount all of its volumes (or none), flush
/// and stop the drive. `Busy` if a volume is in use, `NotFound` for an
/// unknown disk.
pub fn eject(disk: &str) -> Result<(), Errno> {
    let _op = OP.lock();
    let cx = Lookup::kernel();
    let (paths, state) = {
        let media = MEDIA.lock();
        let m = media.iter().find(|m| m.name == disk).ok_or(Errno::NotFound)?;
        (mount_paths(&m.volumes), m.state)
    };
    if state == DiskState::Ejected {
        return Ok(());
    }
    // Write everything out first, so the unmount itself is quick and a
    // failing disk is noticed while the volumes are still mounted.
    for m in vfs::mounts().iter().filter(|m| paths.contains(&m.path)) {
        if let Err(e) = m.fs.sync() {
            kprintln!("media: eject {disk}: syncing {} failed: {:?}", m.path, e);
            set_note(disk, &format!("write error on {}", m.path));
            return Err(e);
        }
    }
    let detached = match vfs::detach_volumes(&paths, false) {
        Ok(d) => d,
        Err(e) => {
            // The list holds one reference beside the table's: more than two
            // means open files or an operation in progress.
            let busy = vfs::mounts()
                .iter()
                .filter(|m| paths.contains(&m.path) && Arc::strong_count(m) > 2)
                .map(|m| m.path.clone())
                .next()
                .unwrap_or_else(|| paths.first().cloned().unwrap_or_default());
            kprintln!("media: eject {disk} refused: {:?} ({busy})", e);
            set_note(disk, &format!("busy {busy}"));
            return Err(e);
        }
    };
    let mut result = if finish_unmount(&cx, detached) { Ok(()) } else { Err(Errno::Io) };
    if let Some(dev) = block::devices().into_iter().find(|d| d.name() == disk) {
        if dev.eject().is_err() {
            kprintln!("media: eject {disk}: the drive reported an error while stopping");
            result = result.and(Err(Errno::Io));
        }
    }
    block::unregister(disk);
    {
        let mut media = MEDIA.lock();
        if let Some(m) = media.iter_mut().find(|m| m.name == disk) {
            m.state = DiskState::Ejected;
            m.volumes.clear();
            m.note = match result {
                Ok(()) => String::new(),
                Err(_) => String::from("write error while ejecting"),
            };
        }
    }
    kprintln!("media: {disk} ejected: it is safe to remove it");
    publish();
    result
}

fn set_note(disk: &str, text: &str) {
    if let Some(m) = MEDIA.lock().iter_mut().find(|m| m.name == disk) {
        m.note = String::from(text);
    }
    publish();
}

/// A mass-storage drive was unplugged. Called from the USB controller
/// thread, which must not wait: the work goes to a thread of its own.
pub fn disk_gone(disk: &str) {
    let arg = Box::into_raw(Box::new(String::from(disk))) as u64;
    sched::spawn_kernel("media-gone", gone_thread, arg, 0);
}

fn gone_thread(arg: u64, _: u64) {
    // SAFETY: `arg` is the Box leaked by `disk_gone` for this thread.
    let disk = *unsafe { Box::from_raw(arg as *mut String) };
    let _op = OP.lock();
    let cx = Lookup::kernel();
    let paths = MEDIA.lock().iter().find(|m| m.name == disk).map(|m| mount_paths(&m.volumes)).unwrap_or_default();
    let ejected = MEDIA.lock().iter().any(|m| m.name == disk && m.state == DiskState::Ejected);
    if !paths.is_empty() {
        kprintln!("media: {disk} was removed while mounted; detaching {} volume(s)", paths.len());
    }
    if let Ok(detached) = vfs::detach_volumes(&paths, true) {
        finish_unmount(&cx, detached);
    }
    block::unregister(&disk);
    MEDIA.lock().retain(|m| m.name != disk);
    if ejected {
        kprintln!("media: {disk} unplugged after eject");
    } else {
        kprintln!("media: {disk} removed");
    }
    publish();
}

/// Mounts the removable disks that were already attached at boot.
pub fn attach_boot_media() {
    let disks: Vec<Arc<dyn BlockDev>> = block::devices().into_iter().filter(|d| d.removable() && d.parent_name().is_none()).collect();
    for disk in disks {
        disk_ready(&disk);
    }
}

fn status_text() -> String {
    status::render(&MEDIA.lock(), GENERATION.load(Ordering::Relaxed))
}

/// Rewrites `/run/media.status` (complete file, then renamed over the old
/// one so a reader never sees a half-written list).
fn publish() {
    GENERATION.fetch_add(1, Ordering::Relaxed);
    let text = status_text();
    let cx = Lookup::kernel();
    let written = vfs::open(&cx, STATUS_TMP, OPEN_WRITE | OPEN_CREATE | OPEN_TRUNCATE, 0o644).and_then(|mut f| {
        let mut done = 0;
        while done < text.len() {
            match f.write(&text.as_bytes()[done..])? {
                0 => return Err(Errno::NoSpace),
                n => done += n,
            }
        }
        Ok(())
    });
    if written.is_ok() {
        let _ = vfs::rename(&cx, STATUS_TMP, status::STATUS_PATH);
    }
}

/// `/dev/media`: write `eject <disk>` to eject a disk. The result is the
/// write's: `Busy` while a volume is in use.
struct Control;

impl CharDevice for Control {
    fn read(&self, _buf: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }

    fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        let text = core::str::from_utf8(data).map_err(|_| Errno::InvalidArgument)?;
        let mut words = text.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            (Some("eject"), Some(disk), None) => eject(disk).map(|_| data.len()),
            _ => Err(Errno::InvalidArgument),
        }
    }
}

/// Adds `/dev/media` and an empty `/run/media.status`.
pub fn init() {
    if let Err(e) = devices::register("media", DeviceKind::Char(Arc::new(Control)), 0o666, 0) {
        kprintln!("media: cannot add /dev/media: {:?}", e);
    }
    publish();
}

#[cfg(test)]
mod tests {
    use super::sanitize_label;

    #[test]
    fn labels_become_safe_names() {
        assert_eq!(sanitize_label("PENDRIVE"), "PENDRIVE");
        assert_eq!(sanitize_label("My Stick/2"), "My_Stick_2");
        assert_eq!(sanitize_label(".."), "");
        assert_eq!(sanitize_label(&"x".repeat(40)).len(), 32);
        assert_eq!(sanitize_label("Zażółć"), "Zażółć");
    }
}
