//! AMD display hardware discovery.
//!
//! Native DCN modesetting needs the VBIOS IP discovery table (or the
//! per-ASIC register bases it replaces), the display microcontroller
//! firmware and the DCN state tables. None of that is implemented: this
//! module identifies an AMD display function, reads the start of its VBIOS
//! and says so in the boot log. The firmware framebuffer (GOP) stays in
//! use.
//!
//! The VBIOS window is enabled only for the read and restored afterwards.
//! Nothing is written to the device.

use crate::pci::{self, Bar, CMD_MEMORY};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use osyx_display::amd::{self, DcnVersion};

/// PCI configuration offset of the expansion ROM base address register.
const ROM_BAR: u8 = 0x30;
/// Address bits of the ROM BAR; bits 10:1 are reserved.
const ROM_MASK: u32 = 0xFFFF_F800;
/// The part of the ROM that is read. Every known VBIOS places its ATOM
/// header in the first eight KiB.
const ROM_SCAN: u64 = 64 * 1024;

/// Logs every AMD display function and its VBIOS. Returns how many were
/// found.
pub fn probe(devices: &[pci::Device]) -> u32 {
    let mut found = 0;
    for dev in devices {
        if !amd::is_amd_display(dev.vendor, dev.class) {
            continue;
        }
        found += 1;
        let dcn = DcnVersion::for_device(dev.device).map(|d| d.name()).unwrap_or("unrecognised DCN generation");
        let framebuffer = match dev.bar(0) {
            Some(Bar::Memory { base, size, .. }) => alloc::format!("BAR0 {:#x} ({} MiB)", base, size >> 20),
            _ => String::from("no memory BAR0"),
        };
        crate::kprintln!("amdgpu: {:04x}:{:04x} at {}, {}, {}", dev.vendor, dev.device, dev.addr, dcn, framebuffer);
        match rom_size(dev).and_then(|size| read_rom(dev, size).map(|rom| (size, rom))) {
            Some((size, rom)) => match amd::atom_header_offset(&rom) {
                Some(offset) => crate::kprintln!(
                    "amdgpu: VBIOS {} KiB, ATOM header at {:#x}; native DCN modesetting is not implemented, the firmware framebuffer stays in use",
                    size >> 10,
                    offset
                ),
                None => crate::kprintln!(
                    "amdgpu: VBIOS {} KiB without an ATOM header; native DCN modesetting is not implemented",
                    size >> 10
                ),
            },
            None => crate::kprintln!("amdgpu: no readable VBIOS ROM; native DCN modesetting is not implemented"),
        }
    }
    found
}

/// Size of the expansion ROM window in bytes, or `None` when the function
/// has no ROM.
fn rom_size(dev: &pci::Device) -> Option<u64> {
    let original = dev.addr.read32(ROM_BAR);
    if original & ROM_MASK == 0 {
        return None;
    }
    dev.addr.write32(ROM_BAR, ROM_MASK);
    let mask = dev.addr.read32(ROM_BAR) & ROM_MASK;
    dev.addr.write32(ROM_BAR, original);
    if mask == 0 {
        return None;
    }
    Some((!mask).wrapping_add(1) as u64)
}

/// Reads up to [`ROM_SCAN`] bytes of the ROM without touching the device.
fn read_rom(dev: &pci::Device, size: u64) -> Option<Vec<u8>> {
    let original = dev.addr.read32(ROM_BAR);
    let base = (original & ROM_MASK) as u64;
    if base == 0 || size < 2 {
        return None;
    }
    let len = size.min(ROM_SCAN);
    let command = dev.command();
    dev.addr.write16(0x04, command | CMD_MEMORY);
    dev.addr.write32(ROM_BAR, base as u32 | 1);
    let mut rom = vec![0u8; len as usize];
    let mapped = crate::mem::map_mmio(base, len);
    if let Ok(va) = mapped {
        for (i, byte) in rom.iter_mut().enumerate() {
            // SAFETY: `va` maps `len` bytes of the ROM window.
            *byte = unsafe { core::ptr::read_volatile((va as *const u8).add(i)) };
        }
    }
    // Close the window before restoring the command register, in the order
    // the firmware left them.
    dev.addr.write32(ROM_BAR, original);
    dev.addr.write16(0x04, command);
    mapped.ok().map(|_| rom)
}
