//! Block layer: a registry of disks and range-checked sector I/O on them.
//!
//! Drivers implement [`BlockDev`]; everything above (file systems, tests)
//! goes through [`read`] / [`write`], which validate the range, enforce
//! read-only devices and split transfers into what the driver accepts.

use crate::pci;
use crate::sched;
use crate::sync::IrqSpinLock;
use crate::{drivers, kprintln};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static READ_BYTES: AtomicU64 = AtomicU64::new(0);
static WRITE_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn io_bytes() -> (u64, u64) {
    (READ_BYTES.load(Ordering::Relaxed), WRITE_BYTES.load(Ordering::Relaxed))
}

pub const SECTOR_SIZE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// Out of range, or a buffer that is not a whole number of sectors.
    InvalidRequest,
    ReadOnly,
    Io,
}

/// A disk of 512-byte sectors. Implementations serialise their own I/O.
pub trait BlockDev: Send + Sync {
    fn name(&self) -> &str;
    fn describe(&self) -> String;
    fn sector_count(&self) -> u64;
    fn read_only(&self) -> bool;
    /// Largest transfer, in sectors, of one `read_blocks` / `write_blocks`.
    fn max_sectors(&self) -> usize;
    fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError>;
    fn write_blocks(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError>;
    fn flush(&self) -> Result<(), BlockError>;
    /// The GPT entry, if this device is a partition.
    fn partition(&self) -> Option<&osyx_part::Partition> {
        None
    }
    /// True for media that can be unplugged (USB sticks): the storage
    /// manager mounts them under `/media` and offers to eject them.
    fn removable(&self) -> bool {
        false
    }
    /// False once the device is gone or ejected; I/O fails from then on.
    fn present(&self) -> bool {
        true
    }
    /// Vendor and product, for the media list (empty if unknown).
    fn model(&self) -> String {
        String::new()
    }
    /// The whole disk a partition lives on.
    fn parent_name(&self) -> Option<&str> {
        None
    }
    /// Prepares the device for removal: flushes its cache and stops it. The
    /// device refuses all I/O afterwards.
    fn eject(&self) -> Result<(), BlockError> {
        self.flush()
    }
}

static DEVICES: IrqSpinLock<Vec<Arc<dyn BlockDev>>> = IrqSpinLock::new(Vec::new());

fn check(dev: &(impl BlockDev + ?Sized), lba: u64, len: usize) -> Result<(), BlockError> {
    if !len.is_multiple_of(SECTOR_SIZE) {
        return Err(BlockError::InvalidRequest);
    }
    let sectors = (len / SECTOR_SIZE) as u64;
    match lba.checked_add(sectors) {
        Some(end) if end <= dev.sector_count() => Ok(()),
        _ => Err(BlockError::InvalidRequest),
    }
}

pub fn read(dev: &dyn BlockDev, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
    check(dev, lba, buf.len())?;
    let step = dev.max_sectors() * SECTOR_SIZE;
    for (i, chunk) in buf.chunks_mut(step).enumerate() {
        dev.read_blocks(lba + (i * dev.max_sectors()) as u64, chunk)?;
        if dev.partition().is_none() {
            READ_BYTES.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    }
    Ok(())
}

pub fn write(dev: &dyn BlockDev, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
    if dev.read_only() {
        return Err(BlockError::ReadOnly);
    }
    check(dev, lba, buf.len())?;
    let step = dev.max_sectors() * SECTOR_SIZE;
    for (i, chunk) in buf.chunks(step).enumerate() {
        dev.write_blocks(lba + (i * dev.max_sectors()) as u64, chunk)?;
        if dev.partition().is_none() {
            WRITE_BYTES.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// Progress of the boot-time partition scan. A whole disk registered after
/// it finished (USB hot-plug) is scanned by its own kernel thread; one that
/// appears while it runs is queued and scanned before it ends.
struct ScanState {
    started: bool,
    done: bool,
    pending: Vec<Arc<dyn BlockDev>>,
}

static SCAN: IrqSpinLock<ScanState> =
    IrqSpinLock::new(ScanState { started: false, done: false, pending: Vec::new() });

pub fn register(dev: Arc<dyn BlockDev>) {
    crate::devices::disk_added(&dev);
    {
        let mut devs = DEVICES.lock();
        // A disk that is both in the boot scan's snapshot and in its
        // pending queue must not register its partitions twice.
        if dev.partition().is_some() && devs.iter().any(|d| d.name() == dev.name() && d.partition().is_some()) {
            return;
        }
        devs.push(dev.clone());
    }
    if dev.partition().is_some() {
        return;
    }
    // The state is read only after the disk is visible in `DEVICES`: a
    // scan that starts after this point finds it in its snapshot, and one
    // that started earlier sees it queued here.
    let mut late = false;
    {
        let mut s = SCAN.lock();
        if s.done {
            late = true;
        } else if s.started {
            s.pending.push(dev.clone());
        }
    }
    if late {
        spawn_scan(dev);
    }
}

pub fn devices() -> Vec<Arc<dyn BlockDev>> {
    DEVICES.lock().clone()
}

/// Removes a whole disk and its partitions from the registry and from
/// `/dev/disks`. Open handles keep the objects alive but their I/O fails
/// once the disk reports itself gone. Returns the names removed.
pub fn unregister(disk: &str) -> Vec<String> {
    let removed: Vec<Arc<dyn BlockDev>> = {
        let mut devs = DEVICES.lock();
        let (gone, kept): (Vec<_>, Vec<_>) = devs.drain(..).partition(|d| d.name() == disk || d.parent_name() == Some(disk));
        *devs = kept;
        gone
    };
    {
        let mut s = SCAN.lock();
        s.pending.retain(|d| d.name() != disk);
    }
    removed
        .into_iter()
        .map(|d| {
            crate::devices::disk_removed(d.name());
            String::from(d.name())
        })
        .collect()
}

/// Starts a driver for every supported storage controller among `pci`:
/// virtio-blk (vda, vdb, ...), NVMe (nvme0n1, ...) and AHCI/SATA (sda, ...).
pub fn probe(pci: &[pci::Device]) -> usize {
    let mut found = 0;
    let mut virtio = 0;
    for d in pci {
        if d.vendor == drivers::virtio::VENDOR && drivers::virtio_blk::DEVICE_IDS.contains(&d.device) {
            let name = format!("vd{}", (b'a' + virtio as u8) as char);
            match drivers::virtio_blk::VirtioBlk::probe(d, name) {
                Ok(dev) => {
                    register(Arc::new(dev));
                    virtio += 1;
                    found += 1;
                }
                Err(e) => kprintln!("virtio-blk at {}: not usable: {:?}", d.addr, e),
            }
        } else if d.class == 0x01 && d.subclass == 0x08 {
            let disks = drivers::nvme::probe(d);
            found += disks.len();
            for disk in disks {
                register(disk);
            }
        } else if d.class == 0x01 && d.subclass == 0x06 && d.prog_if == 0x01 {
            let disks = drivers::ahci::probe(d);
            found += disks.len();
            for disk in disks {
                register(disk);
            }
        }
    }
    found
}

/// A GPT partition of a disk, registered as `<disk><number>` (e.g. `vda2`).
pub struct Partition {
    name: String,
    parent: Arc<dyn BlockDev>,
    start: u64,
    sectors: u64,
    pub info: osyx_part::Partition,
}

impl BlockDev for Partition {
    fn name(&self) -> &str {
        &self.name
    }

    fn describe(&self) -> String {
        format!(
            "partition {} of {} ({}, \"{}\")",
            self.info.number,
            self.parent.name(),
            self.info.type_guid,
            self.info.name
        )
    }

    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read_only(&self) -> bool {
        self.parent.read_only()
    }

    fn max_sectors(&self) -> usize {
        self.parent.max_sectors()
    }

    fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check(self, lba, buf.len())?;
        self.parent.read_blocks(self.start + lba, buf)
    }

    fn write_blocks(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        check(self, lba, buf.len())?;
        self.parent.write_blocks(self.start + lba, buf)
    }

    fn flush(&self) -> Result<(), BlockError> {
        self.parent.flush()
    }

    fn partition(&self) -> Option<&osyx_part::Partition> {
        Some(&self.info)
    }

    fn removable(&self) -> bool {
        self.parent.removable()
    }

    fn present(&self) -> bool {
        self.parent.present()
    }

    fn model(&self) -> String {
        self.parent.model()
    }

    fn parent_name(&self) -> Option<&str> {
        Some(self.parent.name())
    }

    fn eject(&self) -> Result<(), BlockError> {
        self.parent.eject()
    }
}

struct Reader<'a>(&'a dyn BlockDev);

impl osyx_part::SectorReader for Reader<'_> {
    fn sectors(&self) -> u64 {
        self.0.sector_count()
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), osyx_part::GptError> {
        read(self.0, lba, buf).map_err(|_| osyx_part::GptError::Io)
    }
}

/// `vda` + 2 -> `vda2`; a disk name that ends in a digit gets a `p`
/// (`nvme0n1p2`, `usb0p1`) so `usb1` + 1 cannot be taken for `usb11`.
pub fn partition_name(disk: &str, number: u32) -> String {
    if disk.ends_with(|c: char| c.is_ascii_digit()) {
        format!("{disk}p{number}")
    } else {
        format!("{disk}{number}")
    }
}

/// Reads the GPT of one whole disk and registers its partitions.
fn scan_disk(disk: &Arc<dyn BlockDev>) -> usize {
    let mut found = 0;
    match osyx_part::parse(&mut Reader(&**disk)) {
        Ok(t) => {
            if t.used_backup {
                kprintln!("gpt {}: primary table damaged, using the backup", disk.name());
            }
            for p in t.partitions {
                let part = Partition {
                    name: partition_name(disk.name(), p.number),
                    parent: disk.clone(),
                    start: p.first_lba,
                    sectors: p.sectors(),
                    info: p,
                };
                kprintln!("gpt {}: {} {} MiB, {}", disk.name(), part.name, part.sectors >> 11, part.describe());
                register(Arc::new(part));
                found += 1;
            }
        }
        // MBR tables are read on removable disks only: a fixed disk with one
        // (another system's) keeps being left alone.
        Err(osyx_part::GptError::NotGpt) if disk.removable() => found += scan_mbr(disk),
        Err(osyx_part::GptError::NotGpt) => {}
        Err(e) => kprintln!("gpt {}: unusable partition table: {:?}", disk.name(), e),
    }
    found
}

/// Partitions of a classic MBR (what Windows writes to USB sticks), named
/// like GPT ones: `<disk><slot>`. Only whole disks that are not themselves a
/// volume (the sector holds no file system boot record) have any.
fn scan_mbr(disk: &Arc<dyn BlockDev>) -> usize {
    let mut found = 0;
    if let Ok(entries) = osyx_part::parse_mbr(&mut Reader(&**disk)) {
        for e in entries {
            let info = osyx_part::Partition {
                number: e.number,
                type_guid: osyx_part::Guid::default(),
                unique_guid: osyx_part::Guid::default(),
                first_lba: e.first_lba,
                last_lba: e.first_lba + e.sectors - 1,
                attributes: 0,
                name: format!("MBR type {:#04x}", e.kind),
            };
            let part = Partition {
                name: partition_name(disk.name(), e.number),
                parent: disk.clone(),
                start: e.first_lba,
                sectors: e.sectors,
                info,
            };
            kprintln!("mbr {}: {} {} MiB, type {:#04x}", disk.name(), part.name, part.sectors >> 11, e.kind);
            register(Arc::new(part));
            found += 1;
        }
    }
    found
}

/// Reads the GPT of every whole disk and registers its partitions. Disks
/// that appear while this runs are scanned here too; disks that appear
/// later are scanned by their own thread from [`register`].
pub fn scan_partitions() -> usize {
    SCAN.lock().started = true;
    let mut found = 0;
    for disk in devices().into_iter().filter(|d| d.partition().is_none()) {
        found += scan_disk(&disk);
    }
    let pending = {
        let mut s = SCAN.lock();
        s.done = true;
        core::mem::take(&mut s.pending)
    };
    for disk in pending {
        found += scan_disk(&disk);
    }
    found
}

/// Scans a disk that appeared after the boot-time scan.
fn spawn_scan(disk: Arc<dyn BlockDev>) {
    let arg = Box::into_raw(Box::new(disk)) as u64;
    sched::spawn_kernel("disk-scan", scan_thread, arg, 0);
}

fn scan_thread(arg: u64, _: u64) {
    // SAFETY: `arg` is the Box leaked by `spawn_scan` for this thread.
    let disk = *unsafe { Box::from_raw(arg as *mut Arc<dyn BlockDev>) };
    let found = scan_disk(&disk);
    kprintln!("gpt {}: hot-plug scan found {} partition(s)", disk.name(), found);
    crate::media::disk_ready(&disk);
}

/// Adapter that lets a file system driver use a registered disk.
pub struct Disk(pub Arc<dyn BlockDev>);

impl osyx_fat::BlockDevice for Disk {
    fn sector_count(&self) -> u64 {
        self.0.sector_count()
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> osyx_fat::Result<()> {
        read(&*self.0, lba, buf).map_err(|_| osyx_fat::FsError::Io)
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> osyx_fat::Result<()> {
        write(&*self.0, lba, buf).map_err(|_| osyx_fat::FsError::Io)
    }

    fn flush(&mut self) -> osyx_fat::Result<()> {
        self.0.flush().map_err(|_| osyx_fat::FsError::Io)
    }
}

impl osyx_exfat::BlockDevice for Disk {
    fn sector_count(&self) -> u64 {
        self.0.sector_count()
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> osyx_exfat::Result<()> {
        read(&*self.0, lba, buf).map_err(|_| osyx_exfat::FsError::Io)
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> osyx_exfat::Result<()> {
        write(&*self.0, lba, buf).map_err(|_| osyx_exfat::FsError::Io)
    }

    fn flush(&mut self) -> osyx_exfat::Result<()> {
        self.0.flush().map_err(|_| osyx_exfat::FsError::Io)
    }
}

impl osyx_ext4::BlockDevice for Disk {
    fn sector_count(&self) -> u64 {
        self.0.sector_count()
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> osyx_ext4::Result<()> {
        read(&*self.0, lba, buf).map_err(|_| osyx_ext4::Error::Io)
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> osyx_ext4::Result<()> {
        write(&*self.0, lba, buf).map_err(|_| osyx_ext4::Error::Io)
    }

    fn flush(&mut self) -> osyx_ext4::Result<()> {
        self.0.flush().map_err(|_| osyx_ext4::Error::Io)
    }
}
