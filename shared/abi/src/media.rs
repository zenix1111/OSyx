//! Removable media (USB sticks and disks) as the kernel's media manager
//! publishes them in [`STATUS_PATH`] and takes eject requests in
//! [`CONTROL_PATH`].
//!
//! The status file is rewritten on every change (tab-separated records, one
//! per line, see [`render`]):
//!
//! ```text
//! generation <n>
//! disk <name> <mounted|ejected> <bytes> <model>
//! vol <device> <fstype> <label> <mount point or -> <bytes> <ro 0|1>
//! note <disk> <text>
//! ```
//!
//! `vol` lines belong to the `disk` line above them. `note` is `busy <path>`
//! after an eject was refused because that volume is in use, or a short
//! description of a write error.
//!
//! To eject, write `eject <disk>\n` to [`CONTROL_PATH`]; the write fails
//! with `Busy` while a volume is in use and with `Io` if the last data could
//! not be written. After a successful eject the disk stays listed as
//! `ejected` ("safe to remove") until it is unplugged.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write};

pub const STATUS_PATH: &str = "/run/media.status";
pub const CONTROL_PATH: &str = "/dev/media";

/// The owner of the files on a mounted FAT32 or exFAT volume: the desktop
/// user (uid 1000 in the administrators group 27, as `run-app` runs
/// programs), who can then read and write a stick.
pub const OWNER_UID: u32 = 1000;
pub const OWNER_GID: u32 = 27;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskState {
    Mounted,
    Ejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    /// Block device node name below `/dev/disks`.
    pub device: String,
    /// `fat32`, `exfat`, `ext4` or `unknown`.
    pub fstype: String,
    pub label: String,
    /// `None` if the volume is not mounted (no supported file system).
    pub mount: Option<String>,
    pub bytes: u64,
    pub read_only: bool,
}

impl Volume {
    /// The label, or the device name for a volume without one.
    pub fn name(&self) -> &str {
        if self.label.is_empty() {
            &self.device
        } else {
            &self.label
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disk {
    pub name: String,
    pub state: DiskState,
    pub bytes: u64,
    pub model: String,
    pub volumes: Vec<Volume>,
    pub note: String,
}

impl Disk {
    /// The mount point of a volume in use that kept an eject from
    /// succeeding.
    pub fn busy_path(&self) -> Option<&str> {
        self.note.strip_prefix("busy ")
    }
}

/// Keeps a field free of the separators and of control characters.
fn clean(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    for c in s.chars() {
        f.write_char(if c.is_control() { ' ' } else { c })?;
    }
    Ok(())
}

struct Field<'a>(&'a str);

impl fmt::Display for Field<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        clean(f, self.0)
    }
}

/// The status file for `disks`.
pub fn render(disks: &[Disk], generation: u64) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "generation\t{generation}");
    for d in disks {
        let state = if d.state == DiskState::Mounted { "mounted" } else { "ejected" };
        let _ = writeln!(out, "disk\t{}\t{}\t{}\t{}", Field(&d.name), state, d.bytes, Field(&d.model));
        for v in &d.volumes {
            let mount = v.mount.as_deref().unwrap_or("-");
            let _ = writeln!(
                out,
                "vol\t{}\t{}\t{}\t{}\t{}\t{}",
                Field(&v.device),
                Field(&v.fstype),
                Field(&v.label),
                Field(mount),
                v.bytes,
                v.read_only as u8
            );
        }
        if !d.note.is_empty() {
            let _ = writeln!(out, "note\t{}\t{}", Field(&d.name), Field(&d.note));
        }
    }
    out
}

/// Parses a status file; lines it does not understand are skipped.
pub fn parse(text: &str) -> Vec<Disk> {
    let mut disks: Vec<Disk> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["disk", name, state, bytes, rest @ ..] => disks.push(Disk {
                name: String::from(*name),
                state: if *state == "ejected" { DiskState::Ejected } else { DiskState::Mounted },
                bytes: bytes.parse().unwrap_or(0),
                model: String::from(rest.first().copied().unwrap_or("")),
                volumes: Vec::new(),
                note: String::new(),
            }),
            ["vol", device, fstype, label, mount, bytes, ro] => {
                if let Some(d) = disks.last_mut() {
                    d.volumes.push(Volume {
                        device: String::from(*device),
                        fstype: String::from(*fstype),
                        label: String::from(*label),
                        mount: (*mount != "-").then(|| String::from(*mount)),
                        bytes: bytes.parse().unwrap_or(0),
                        read_only: *ro == "1",
                    });
                }
            }
            ["note", disk, text @ ..] => {
                if let Some(d) = disks.iter_mut().find(|d| d.name == *disk) {
                    d.note = String::from(text.first().copied().unwrap_or(""));
                }
            }
            _ => {}
        }
    }
    disks
}

/// What happened between two status files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// A disk appeared.
    Connected(Disk),
    /// A disk was ejected and is safe to remove.
    Ejected(Disk),
    /// A disk is gone: `Disk::state` tells whether it was ejected first.
    Unplugged(Disk),
}

/// The changes from `old` to `new`, in the order the user would notice them.
pub fn diff(old: &[Disk], new: &[Disk]) -> Vec<Change> {
    let mut out = Vec::new();
    for o in old {
        if !new.iter().any(|d| d.name == o.name) {
            out.push(Change::Unplugged(o.clone()));
        }
    }
    for d in new {
        match old.iter().find(|o| o.name == d.name) {
            None => out.push(Change::Connected(d.clone())),
            Some(o) if o.state == DiskState::Mounted && d.state == DiskState::Ejected => out.push(Change::Ejected(d.clone())),
            Some(_) => {}
        }
    }
    out
}

/// "14.5 GB" style size in decimal units, as drive makers and file
/// managers write them.
pub struct Size(pub u64);

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        const UNITS: [(&str, u64); 4] = [("TB", 1_000_000_000_000), ("GB", 1_000_000_000), ("MB", 1_000_000), ("KB", 1_000)];
        for (unit, size) in UNITS {
            if b >= size {
                let tenths = b * 10 / size;
                return if tenths >= 1000 || b.is_multiple_of(size) { write!(f, "{} {unit}", tenths / 10) } else { write!(f, "{}.{} {unit}", tenths / 10, tenths % 10) };
            }
        }
        write!(f, "{b} B")
    }
}

/// Upper-case name of a file system for display.
pub fn fs_name(fstype: &str) -> &str {
    match fstype {
        "fat32" => "FAT32",
        "exfat" => "exFAT",
        "ext4" => "ext4",
        _ => "unknown file system",
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn sample() -> Vec<Disk> {
        vec![
            Disk {
                name: "usb0".into(),
                state: DiskState::Mounted,
                bytes: 15_523_119_104,
                model: "Kingston DataTraveler 3.0".into(),
                volumes: vec![
                    Volume {
                        device: "usb0p1".into(),
                        fstype: "exfat".into(),
                        label: "PENDRIVE".into(),
                        mount: Some("/media/PENDRIVE".into()),
                        bytes: 15_000_000_000,
                        read_only: false,
                    },
                    Volume { device: "usb0p2".into(), fstype: "unknown".into(), label: "".into(), mount: None, bytes: 500_000_000, read_only: false },
                ],
                note: "busy /media/PENDRIVE".into(),
            },
            Disk { name: "usb1".into(), state: DiskState::Ejected, bytes: 1_000_000, model: "".into(), volumes: vec![], note: "".into() },
        ]
    }

    #[test]
    fn round_trip() {
        let disks = sample();
        let text = render(&disks, 7);
        assert!(text.starts_with("generation\t7\ndisk\tusb0\tmounted\t15523119104\tKingston DataTraveler 3.0\n"), "{text}");
        assert_eq!(parse(&text), disks);
        assert_eq!(disks[0].busy_path(), Some("/media/PENDRIVE"));
        assert_eq!(disks[0].volumes[1].name(), "usb0p2");
    }

    #[test]
    fn hostile_labels_cannot_forge_records() {
        let mut disks = sample();
        disks[0].volumes[0].label = "x\nvol\tusb9\text4\tevil\t/media/evil\t1\t0\t".into();
        disks[0].model = "a\tb\nc".into();
        let parsed = parse(&render(&disks, 1));
        assert_eq!(parsed[0].volumes.len(), 2, "no extra volume appeared");
        assert_eq!(parsed[0].volumes[0].mount.as_deref(), Some("/media/PENDRIVE"));
        assert_eq!(parsed[0].model, "a b c");
    }

    #[test]
    fn tolerates_junk() {
        assert!(parse("").is_empty());
        assert!(parse("garbage\nvol\tonly\tthree\n").is_empty());
        let d = parse("disk\tusb0\tmounted\tnot-a-number\n");
        assert_eq!((d.len(), d[0].bytes, d[0].model.as_str()), (1, 0, ""));
    }

    #[test]
    fn changes_between_status_files() {
        let mut a = sample();
        a.truncate(1);
        assert_eq!(diff(&[], &a), vec![Change::Connected(a[0].clone())]);
        assert_eq!(diff(&a, &a), vec![]);
        let mut ejected = a.clone();
        ejected[0].state = DiskState::Ejected;
        ejected[0].volumes.clear();
        assert_eq!(diff(&a, &ejected), vec![Change::Ejected(ejected[0].clone())]);
        // Unplugged after an eject: the old entry says so.
        assert_eq!(diff(&ejected, &[]), vec![Change::Unplugged(ejected[0].clone())]);
        assert_eq!(diff(&a, &[]), vec![Change::Unplugged(a[0].clone())]);
        // A note changing (an eject refused) is not a change of the media.
        let mut busy = a.clone();
        busy[0].note = "busy /media/PENDRIVE".into();
        assert_eq!(diff(&a, &busy), vec![]);
        // One unplugged, another connected.
        let b = vec![Disk { name: "usb2".into(), ..a[0].clone() }];
        assert_eq!(diff(&a, &b), vec![Change::Unplugged(a[0].clone()), Change::Connected(b[0].clone())]);
    }

    #[test]
    fn sizes() {
        assert_eq!(Size(0).to_string(), "0 B");
        assert_eq!(Size(999).to_string(), "999 B");
        assert_eq!(Size(1_500).to_string(), "1.5 KB");
        assert_eq!(Size(15_523_119_104).to_string(), "15.5 GB");
        assert_eq!(Size(32_000_000_000).to_string(), "32 GB");
        assert_eq!(Size(256_060_514_304).to_string(), "256 GB");
        assert_eq!(Size(2_000_000_000_000).to_string(), "2 TB");
    }
}
