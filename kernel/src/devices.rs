//! Device manager: the registry of device nodes that devfs (`/dev`)
//! shows, and the file operations of character and block devices.
//!
//! Drivers register nodes at run time ([`register`] / [`unregister`]);
//! devfs reflects the registry immediately. Only devices that exist and
//! work are registered: `/dev/input/event<N>` appear when the USB HID
//! drivers attach a keyboard or mouse (and vanish when it is unplugged),
//! and `/dev/console` is write-only.
//!
//! Block device nodes (`/dev/disks/*`) are owned by root with mode 0600, so
//! ordinary users get no raw disk access, and even root cannot write raw
//! sectors of a disk or partition while a volume on it is mounted.

use crate::block::{self, BlockDev, SECTOR_SIZE};
use crate::sync::IrqSpinLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use osyx_abi::Errno;

pub trait CharDevice: Send + Sync {
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno>;
    fn write(&self, data: &[u8]) -> Result<usize, Errno>;
    /// `wait_handles` readiness (`WAIT_*`); devices that never block are
    /// always ready.
    fn poll(&self) -> u32 {
        osyx_abi::ipc::WAIT_READABLE | osyx_abi::ipc::WAIT_WRITABLE
    }
    /// Signalled when `poll` may have changed.
    fn wait_queue(&self) -> Option<&crate::waitq::WaitQueue> {
        None
    }
    /// A handle is being opened (a device may refuse, e.g. `Busy` for an
    /// exclusive one).
    fn open(&self) -> Result<(), Errno> {
        Ok(())
    }
    /// A handle was closed.
    fn close(&self) {}
}

pub enum DeviceKind {
    Char(Arc<dyn CharDevice>),
    Block(Arc<dyn BlockDev>),
}

pub struct DeviceNode {
    /// Path below `/dev`, e.g. `null` or `disks/vda`.
    pub path: String,
    pub kind: DeviceKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Device number (major << 8 | minor).
    pub rdev: u32,
    pub ino: u64,
}

static NODES: IrqSpinLock<Vec<Arc<DeviceNode>>> = IrqSpinLock::new(Vec::new());
/// devfs directories use small inode numbers; device nodes start here.
pub const FIRST_NODE_INO: u64 = 1 << 32;
static NEXT_INO: AtomicU64 = AtomicU64::new(FIRST_NODE_INO);
/// Set once `init` has registered the built-in nodes; from then on disks
/// that register later (USB hotplug) get their node immediately.
static DISKS_WATCHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static NEXT_DISK_MINOR: AtomicU64 = AtomicU64::new(0);

/// Adds `/dev/<path>`. Fails with `AlreadyExists` if the name (or a
/// directory of that name) is taken.
pub fn register(path: &str, kind: DeviceKind, mode: u32, rdev: u32) -> Result<Arc<DeviceNode>, Errno> {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        return Err(Errno::InvalidArgument);
    }
    for c in path.split('/') {
        osyx_vfs::path::validate_name(c)?;
    }
    let mut nodes = NODES.lock();
    let clash = |p: &str| p == path || p.starts_with(&alloc::format!("{path}/")) || path.starts_with(&alloc::format!("{p}/"));
    if nodes.iter().any(|n| clash(&n.path)) {
        return Err(Errno::AlreadyExists);
    }
    let node = Arc::new(DeviceNode {
        path: String::from(path),
        kind,
        mode: mode & osyx_abi::MODE_PERMS,
        uid: 0,
        gid: 0,
        rdev,
        ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
    });
    nodes.push(node.clone());
    Ok(node)
}

/// Removes `/dev/<path>`. Open handles keep the device object alive.
pub fn unregister(path: &str) -> Result<(), Errno> {
    let mut nodes = NODES.lock();
    let i = nodes.iter().position(|n| n.path == path).ok_or(Errno::NotFound)?;
    nodes.remove(i);
    Ok(())
}

pub fn list() -> Vec<Arc<DeviceNode>> {
    NODES.lock().clone()
}

pub fn count() -> usize {
    NODES.lock().len()
}

/// The device side of an open device node.
#[derive(Clone)]
pub struct DeviceFile(pub Arc<DeviceNode>);

impl DeviceFile {
    pub fn block(&self) -> Option<Arc<dyn BlockDev>> {
        match &self.0.kind {
            DeviceKind::Block(b) => Some(b.clone()),
            DeviceKind::Char(_) => None,
        }
    }

    /// Size in bytes (block devices only).
    pub fn size(&self) -> Option<u64> {
        self.block().map(|b| b.sector_count() * SECTOR_SIZE as u64)
    }

    pub fn check_open(&self, write: bool) -> Result<(), Errno> {
        match &self.0.kind {
            DeviceKind::Block(b) if write => {
                if b.read_only() {
                    Err(Errno::ReadOnly)
                } else if crate::vfs::device_in_use(b.name()) {
                    Err(Errno::Busy)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    pub fn read(&self, pos: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        match &self.0.kind {
            DeviceKind::Char(c) => c.read(buf),
            DeviceKind::Block(b) => {
                let size = b.sector_count() * SECTOR_SIZE as u64;
                if pos >= size {
                    return Ok(0);
                }
                let len = (buf.len() as u64).min(size - pos) as usize;
                let first = pos / SECTOR_SIZE as u64;
                let last = (pos + len as u64).div_ceil(SECTOR_SIZE as u64);
                let mut bounce = alloc::vec![0u8; ((last - first) as usize) * SECTOR_SIZE];
                block::read(&**b, first, &mut bounce).map_err(|_| Errno::Io)?;
                let skip = (pos % SECTOR_SIZE as u64) as usize;
                buf[..len].copy_from_slice(&bounce[skip..skip + len]);
                Ok(len)
            }
        }
    }

    pub fn write(&self, pos: u64, data: &[u8]) -> Result<usize, Errno> {
        match &self.0.kind {
            DeviceKind::Char(c) => c.write(data),
            DeviceKind::Block(b) => {
                self.check_open(true)?;
                if !pos.is_multiple_of(SECTOR_SIZE as u64) || !data.len().is_multiple_of(SECTOR_SIZE) {
                    return Err(Errno::InvalidArgument);
                }
                block::write(&**b, pos / SECTOR_SIZE as u64, data).map_err(|e| match e {
                    block::BlockError::InvalidRequest => Errno::InvalidArgument,
                    block::BlockError::ReadOnly => Errno::ReadOnly,
                    block::BlockError::Io => Errno::Io,
                })?;
                Ok(data.len())
            }
        }
    }

    pub fn flush(&self) -> Result<(), Errno> {
        match &self.0.kind {
            DeviceKind::Block(b) => b.flush().map_err(|_| Errno::Io),
            DeviceKind::Char(_) => Ok(()),
        }
    }

    pub fn poll(&self) -> u32 {
        match &self.0.kind {
            DeviceKind::Char(c) => c.poll(),
            DeviceKind::Block(_) => osyx_abi::ipc::WAIT_READABLE | osyx_abi::ipc::WAIT_WRITABLE,
        }
    }

    pub fn wait_queue(&self) -> Option<&crate::waitq::WaitQueue> {
        match &self.0.kind {
            DeviceKind::Char(c) => c.wait_queue(),
            DeviceKind::Block(_) => None,
        }
    }

    pub fn open(&self) -> Result<(), Errno> {
        match &self.0.kind {
            DeviceKind::Char(c) => c.open(),
            DeviceKind::Block(_) => Ok(()),
        }
    }

    pub fn close(&self) {
        if let DeviceKind::Char(c) = &self.0.kind {
            c.close();
        }
    }
}

// ---- built-in character devices ---------------------------------------------

struct Null;
impl CharDevice for Null {
    fn read(&self, _buf: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }
    fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        Ok(data.len())
    }
}

struct Zero;
impl CharDevice for Zero {
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        buf.fill(0);
        Ok(buf.len())
    }
    fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        Ok(data.len())
    }
}

struct Random;
impl CharDevice for Random {
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        crate::random::fill(buf)?;
        Ok(buf.len())
    }
    /// Writing does not credit entropy; the data is ignored.
    fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        Ok(data.len())
    }
}

/// The kernel console: output goes to the serial log and the status
/// screen, attributed to the writing process. No input device exists yet.
struct Console;
impl CharDevice for Console {
    fn read(&self, _buf: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::NotSupported)
    }
    fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        crate::process::write_output(data);
        Ok(data.len())
    }
}

/// Device numbers (Linux-compatible majors for the memory devices).
const fn dev(major: u32, minor: u32) -> u32 {
    major << 8 | minor
}

fn add_disk(b: Arc<dyn BlockDev>) {
    let minor = NEXT_DISK_MINOR.fetch_add(1, Ordering::Relaxed) as u32;
    let path = alloc::format!("disks/{}", b.name());
    match register(&path, DeviceKind::Block(b), 0o600, dev(8, minor)) {
        Ok(_) => {}
        Err(Errno::AlreadyExists) => {}
        Err(e) => crate::kprintln!("devices: cannot register {path}: {e:?}"),
    }
}

/// Called by the block layer for every disk it registers: devices that
/// appear after `init` (USB mass storage on hotplug) still get a node.
pub fn disk_added(b: &Arc<dyn BlockDev>) {
    if DISKS_WATCHED.load(Ordering::Acquire) {
        add_disk(b.clone());
        crate::kprintln!("devfs: /dev/disks/{}", b.name());
    }
}

/// Called by the block layer when a disk is unregistered (unplugged or
/// ejected): its node leaves `/dev/disks`.
pub fn disk_removed(name: &str) {
    if DISKS_WATCHED.load(Ordering::Acquire) {
        let _ = unregister(&alloc::format!("disks/{name}"));
    }
}

/// Registers the built-in devices and one node per block device.
pub fn init() {
    let builtin: [(&str, Arc<dyn CharDevice>, u32, u32); 3] = [
        ("null", Arc::new(Null), 0o666, dev(1, 3)),
        ("zero", Arc::new(Zero), 0o666, dev(1, 5)),
        ("console", Arc::new(Console), 0o620, dev(5, 1)),
    ];
    for (name, d, mode, rdev) in builtin {
        register(name, DeviceKind::Char(d), mode, rdev).expect("built-in device names are unique");
    }
    // Only offer randomness the generator can actually produce.
    if crate::random::is_seeded() {
        register("random", DeviceKind::Char(Arc::new(Random)), 0o444, dev(1, 8)).expect("unique");
    }
    DISKS_WATCHED.store(true, Ordering::Release);
    for b in block::devices() {
        add_disk(b);
    }
}
