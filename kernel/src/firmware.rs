//! Firmware access for a privileged user-space ACPI service (`batteryd`):
//! ACPI table bytes, I/O ports, physical memory outside the kernel's RAM,
//! and PCI configuration space. Interpreting AML in user space keeps the
//! kernel out of the firmware's byte code: an unknown construct ends that
//! process, not the system.
//!
//! Every operation is root only. Physical memory the kernel owns (usable
//! RAM, the kernel image and its boot data) is refused, as are the I/O
//! ports of devices the kernel drives itself.

use crate::sync::IrqSpinLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use osyx_abi::{firmware as op, Errno};
use osyx_bootinfo::{MemoryDescriptor, MemoryKind};

/// Physical ranges [start, end) of RAM the kernel owns.
static KERNEL_RAM: IrqSpinLock<Vec<(u64, u64)>> = IrqSpinLock::new(Vec::new());
/// Firmware pages mapped so far (physical page -> kernel virtual address).
static MAPPED: IrqSpinLock<BTreeMap<u64, u64>> = IrqSpinLock::new(BTreeMap::new());

/// Remembers which physical memory belongs to the kernel.
pub fn init(map: &[MemoryDescriptor]) {
    let owned = map
        .iter()
        .filter(|d| {
            matches!(
                d.kind,
                MemoryKind::Usable | MemoryKind::BootloaderReclaimable | MemoryKind::KernelImage | MemoryKind::KernelData
            )
        })
        .map(|d| (d.phys_start, d.phys_start + d.page_count * crate::mem::PAGE_SIZE))
        .collect();
    *KERNEL_RAM.lock() = owned;
}

/// Ports of devices the kernel drives: PIC, PIT, PS/2, CMOS/RTC, COM1, PCI
/// configuration, QEMU's debug exit.
fn port_reserved(port: u16) -> bool {
    matches!(port, 0x20..=0x21 | 0xA0..=0xA1 | 0x40..=0x43 | 0x60 | 0x64 | 0x70..=0x71 | 0x3F8..=0x3FF | 0xCF8..=0xCFF | 0xF4)
}

/// Whether `[start, start + len)` overlaps RAM the kernel owns.
pub fn overlaps_kernel_ram(start: u64, len: u64) -> bool {
    let Some(end) = start.checked_add(len) else { return true };
    KERNEL_RAM.lock().iter().any(|&(s, e)| start < e && end > s)
}

/// `buf`, `len`: an encoded `osyx_i2c::spec` description (at most
/// `spec::MAX_BYTES`); returns the number of devices the kernel claimed.
fn i2c_hid(buf: u64, len: u64) -> Result<u64, Errno> {
    if len == 0 || len > osyx_i2c::spec::MAX_BYTES as u64 {
        return Err(Errno::InvalidArgument);
    }
    let mut bytes = alloc::vec![0u8; len as usize];
    crate::fixup::copy_from_user(&mut bytes, buf)?;
    crate::drivers::i2c::register(&bytes).map(|n| n as u64)
}

fn width_ok(width: u64) -> bool {
    matches!(width, 1 | 2 | 4 | 8)
}

/// `firmware(op, a, b, c, d)`; see `osyx_abi::firmware`.
pub fn syscall(code: u64, a: u64, b: u64, c: u64, d: u64) -> Result<u64, Errno> {
    if !crate::process::current_identity().0.is_root() {
        return Err(Errno::PermissionDenied);
    }
    match code {
        op::TABLE => table(a as u32, b as usize, c, d),
        op::PORT => port(a, b, c, d != 0),
        op::PHYS => phys(a, b, c, d != 0),
        op::PCI => pci(a, b, c, d),
        op::I2C_HID => i2c_hid(a, b),
        _ => Err(Errno::InvalidArgument),
    }
}

/// Copies table `sig` (little-endian signature), instance `n`, to `buf`;
/// returns its full length (copying at most `len` bytes).
fn table(sig: u32, n: usize, buf: u64, len: u64) -> Result<u64, Errno> {
    let bytes = crate::acpi::table_bytes(&sig.to_le_bytes(), n).ok_or(Errno::NotFound)?;
    let k = bytes.len().min(len as usize);
    if k > 0 {
        crate::fixup::copy_to_user(buf, &bytes[..k])?;
    }
    Ok(bytes.len() as u64)
}

fn port(port: u64, width: u64, value: u64, write: bool) -> Result<u64, Errno> {
    let p = u16::try_from(port).map_err(|_| Errno::InvalidArgument)?;
    if !matches!(width, 1 | 2 | 4) || (0..width as u16).any(|i| port_reserved(p.wrapping_add(i))) {
        return Err(Errno::PermissionDenied);
    }
    use crate::arch::cpu;
    // SAFETY: a port outside the kernel's devices, accessed on behalf of the
    // firmware's own code (AML).
    unsafe {
        Ok(match (width, write) {
            (1, false) => cpu::inb(p) as u64,
            (2, false) => cpu::inw(p) as u64,
            (4, false) => cpu::inl(p) as u64,
            (1, true) => {
                cpu::outb(p, value as u8);
                0
            }
            (2, true) => {
                cpu::outw(p, value as u16);
                0
            }
            _ => {
                cpu::outl(p, value as u32);
                0
            }
        })
    }
}

fn phys(addr: u64, width: u64, value: u64, write: bool) -> Result<u64, Errno> {
    if !width_ok(width) || !addr.is_multiple_of(width) {
        return Err(Errno::InvalidArgument);
    }
    let end = addr.checked_add(width).ok_or(Errno::InvalidArgument)?;
    if overlaps_kernel_ram(addr, end - addr) {
        return Err(Errno::PermissionDenied);
    }
    let page = addr & !(crate::mem::PAGE_SIZE - 1);
    let va = {
        let mut mapped = MAPPED.lock();
        match mapped.get(&page) {
            Some(&va) => va,
            None => {
                if mapped.len() >= 1024 {
                    return Err(Errno::NoMemory);
                }
                let va = crate::mem::map_mmio(page, crate::mem::PAGE_SIZE).map_err(|_| Errno::NoMemory)?;
                mapped.insert(page, va);
                va
            }
        }
    } + (addr - page);
    // SAFETY: `va` maps firmware memory (not kernel RAM), uncached; the access
    // is aligned to its width, so it stays inside the mapped page.
    unsafe {
        Ok(match (width, write) {
            (1, false) => core::ptr::read_volatile(va as *const u8) as u64,
            (2, false) => core::ptr::read_volatile(va as *const u16) as u64,
            (4, false) => core::ptr::read_volatile(va as *const u32) as u64,
            (8, false) => core::ptr::read_volatile(va as *const u64),
            (1, true) => {
                core::ptr::write_volatile(va as *mut u8, value as u8);
                0
            }
            (2, true) => {
                core::ptr::write_volatile(va as *mut u16, value as u16);
                0
            }
            (4, true) => {
                core::ptr::write_volatile(va as *mut u32, value as u32);
                0
            }
            _ => {
                core::ptr::write_volatile(va as *mut u64, value);
                0
            }
        })
    }
}

/// `a` = bus << 16 | device << 8 | function, `b` = offset, `c` = width |
/// 0x100 for a write, `d` = value. Segment 0, the first 256 bytes only.
fn pci(a: u64, b: u64, c: u64, d: u64) -> Result<u64, Errno> {
    let (width, write) = (c & 0xff, c & 0x100 != 0);
    let offset = u8::try_from(b).map_err(|_| Errno::InvalidArgument)?;
    if !matches!(width, 1 | 2 | 4) || !(b as u64).is_multiple_of(width) || b + width > 256 {
        return Err(Errno::InvalidArgument);
    }
    let addr = crate::pci::Address { bus: (a >> 16) as u8, device: ((a >> 8) & 0x1f) as u8, function: (a & 7) as u8 };
    Ok(match (width, write) {
        (1, false) => addr.read8(offset) as u64,
        (2, false) => addr.read16(offset) as u64,
        (4, false) => addr.read32(offset) as u64,
        (1, true) => {
            let shift = (offset & 3) * 8;
            let old = addr.read32(offset & !3) & !(0xff << shift);
            addr.write32(offset & !3, old | ((d as u32 & 0xff) << shift));
            0
        }
        (2, true) => {
            addr.write16(offset, d as u16);
            0
        }
        _ => {
            addr.write32(offset, d as u32);
            0
        }
    })
}
