//! Power off and reboot.
//!
//! Every volume is synced and unmounted first. Power off enters ACPI S5:
//! the PM1 control blocks come from the FADT and SLP_TYP from the DSDT's
//! `\_S5` package (ACPI is enabled through SMI_CMD first if the firmware
//! left it off). Without usable tables the chipset's power management
//! block is found through PCI (ICH9 LPC, PIIX4 PM) with QEMU's SLP_TYP 0.
//! Reboot uses the FADT reset register, then the reset control register
//! 0xCF9, the keyboard controller and finally a triple fault.

use crate::arch::cpu;
use crate::{kprintln, pci};
use osyx_abi::Errno;

const SLP_EN: u16 = 1 << 13;
const SLP_TYP_S5: u16 = 0;

/// The PM1a control port, if the chipset is one we know.
fn pm1a_control() -> Option<u16> {
    for d in pci::enumerate() {
        let base_reg = match (d.vendor, d.device) {
            (0x8086, 0x2918) => 0x40, // ICH9 LPC: PMBASE
            (0x8086, 0x7113) => 0x40, // PIIX4 PM: PMBA
            _ => continue,
        };
        let base = (d.addr.read32(base_reg) & 0xFF80) as u16;
        if base != 0 {
            return Some(base + 4);
        }
    }
    None
}

fn shutdown_volumes(what: &str) {
    crate::drivers::i2c::quiesce();
    kprintln!("power: {what}: unmounting volumes");
    crate::vfs::shutdown();
}

/// Never returns on success.
pub fn request(reboot: bool) -> Result<u64, Errno> {
    if reboot {
        shutdown_volumes("reboot");
        kprintln!("power: resetting the machine");
        // SAFETY: the reset registers reset the CPU; nothing needs to survive.
        unsafe {
            match crate::acpi::power().and_then(|p| p.reset) {
                Some(crate::acpi::Reset::Io(port, v)) => {
                    kprintln!("power: FADT reset register: port {port:#x} <- {v:#x}");
                    cpu::outb(port, v);
                }
                Some(crate::acpi::Reset::Pci(dev, func, reg, v)) => {
                    kprintln!("power: FADT reset register: PCI 00:{dev:02x}.{func} [{reg:#x}] <- {v:#x}");
                    let addr = 0x8000_0000u32 | (dev as u32) << 11 | (func as u32) << 8 | (reg as u32 & 0xFC);
                    cpu_outl(0xCF8, addr);
                    cpu::outb(0xCFC + (reg as u16 & 3), v);
                }
                None => {}
            }
            for _ in 0..100_000 {
                core::hint::spin_loop();
            }
            cpu::outb(0xCF9, 0x02);
            cpu::outb(0xCF9, 0x06);
            for _ in 0..100_000 {
                core::hint::spin_loop();
            }
            cpu::outb(0x64, 0xFE);
            for _ in 0..100_000 {
                core::hint::spin_loop();
            }
            // Triple fault: an empty IDT and an interrupt.
            let empty: [u8; 10] = [0; 10];
            core::arch::asm!("lidt [{}]", "int3", in(reg) &empty, options(nostack));
        }
        cpu::halt_forever()
    }
    // (PM1a, PM1b, SLP_TYPa, SLP_TYPb) from the tables, else the chipset.
    let acpi = crate::acpi::power();
    let target = match &acpi {
        Some(p) => Some((p.pm1a_cnt, p.pm1b_cnt, p.s5.map_or(SLP_TYP_S5, |s| s.0 as u16), p.s5.map_or(SLP_TYP_S5, |s| s.1 as u16))),
        None => pm1a_control().map(|port| (port, None, SLP_TYP_S5, SLP_TYP_S5)),
    };
    shutdown_volumes("power off");
    let Some((pm1a, pm1b, typ_a, typ_b)) = target else {
        kprintln!("power: no ACPI power management block; volumes are clean, power off by hand");
        return Err(Errno::NotSupported);
    };
    // SAFETY: port I/O on the ACPI fixed hardware the FADT describes.
    unsafe {
        if let Some(p) = &acpi {
            // SCI_EN clear: the firmware still owns ACPI; ask for it.
            if cpu_inw(pm1a) & 1 == 0 && p.smi_cmd != 0 && p.acpi_enable != 0 {
                cpu::outb(p.smi_cmd, p.acpi_enable);
                for _ in 0..3_000_000 {
                    if cpu_inw(pm1a) & 1 != 0 {
                        break;
                    }
                    core::hint::spin_loop();
                }
            }
        }
        kprintln!(
            "power: entering ACPI S5 (PM1a_CNT {:#x}, SLP_TYPa {}, {})",
            pm1a,
            typ_a,
            if acpi.as_ref().is_some_and(|p| p.s5.is_some()) { "from the DSDT" } else { "default" }
        );
        if let Some(b) = pm1b {
            let v = cpu_inw(b);
            cpu_outw(b, (v & !(7 << 10)) | (typ_b << 10) | SLP_EN);
        }
        let v = cpu_inw(pm1a);
        cpu_outw(pm1a, (v & !(7 << 10)) | (typ_a << 10) | SLP_EN);
    }
    for _ in 0..10_000_000 {
        core::hint::spin_loop();
    }
    kprintln!("power: still running after the S5 request");
    Err(Errno::NotSupported)
}

/// # Safety
/// Port I/O on a power management register.
unsafe fn cpu_inw(port: u16) -> u16 {
    let v: u16;
    core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags));
    v
}

/// # Safety
/// See [`cpu_inw`].
unsafe fn cpu_outl(port: u16, v: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags));
}

/// # Safety
/// Port I/O with side effects.
unsafe fn cpu_outw(port: u16, v: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags));
}
