//! The machine as the AML interpreter sees it: I/O ports, physical memory,
//! PCI configuration and the embedded controller (EC).
//!
//! The EC protocol (ACPI 12.2) is spoken here on top of [`Hardware`], with
//! every wait bounded by time. A transaction that fails is counted in
//! [`Stats`] instead of returning a made-up zero, so the caller can tell a
//! bad reading from a real one and discard it.

use aml::Handler;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

/// Raw access to the machine. Reads return `u64::MAX` when the access
/// failed or was refused.
pub trait Hardware: Send + Sync {
    fn port_in(&self, port: u16, width: u8) -> u64;
    fn port_out(&self, port: u16, width: u8, value: u64);
    fn phys_read(&self, address: u64, width: u8) -> u64;
    fn phys_write(&self, address: u64, width: u8, value: u64);
    /// `bdf` is `bus << 16 | device << 8 | function`.
    fn pci_read(&self, bdf: u64, offset: u64, width: u8) -> u64;
    fn pci_write(&self, bdf: u64, offset: u64, width: u8, value: u64);
    /// Milliseconds from any fixed point; used for EC time-outs.
    fn now_ms(&self) -> u64;
}

/// The EC's command/status and data ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcPorts {
    pub command: u16,
    pub data: u16,
}

impl EcPorts {
    /// The ports every PC firmware uses.
    pub const LEGACY: EcPorts = EcPorts { command: 0x66, data: 0x62 };

    /// From the ECDT table (ACPI 5.2.15): after the 36-byte header come
    /// EC_CONTROL (the command/status port) and EC_DATA, each a 12-byte
    /// generic address structure (space id, widths, then the 8-byte address
    /// at +4). `None` if the table is missing, short, or names anything but
    /// system I/O ports: the caller then asks the EC device's `_CRS`.
    pub fn from_ecdt(table: Option<&[u8]>) -> Option<EcPorts> {
        const SYSTEM_IO: u8 = 1;
        let t = table?;
        let gas = |at: usize| -> Option<u16> {
            let g = t.get(at..at + 12)?;
            let address = u64::from_le_bytes(g[4..12].try_into().ok()?);
            (g[0] == SYSTEM_IO && address != 0 && address <= u16::MAX as u64).then_some(address as u16)
        };
        Some(EcPorts { command: gas(36)?, data: gas(48)? })
    }

    /// From an EC device's `_CRS` buffer: the first I/O port descriptor is
    /// the data port, the second the command/status port (ACPI 12.11).
    /// Small I/O (0x47) and fixed I/O (0x4B) descriptors count; the rest is
    /// skipped by length.
    pub fn from_crs(crs: &[u8]) -> Option<EcPorts> {
        let mut ports = [0u16; 2];
        let mut found = 0;
        let mut at = 0;
        while at < crs.len() && found < 2 {
            let tag = crs[at];
            if tag & 0x80 != 0 {
                // Large item: a 16-bit length follows the tag.
                let len = u16::from_le_bytes([*crs.get(at + 1)?, *crs.get(at + 2)?]) as usize;
                at += 3 + len;
                continue;
            }
            let len = (tag & 7) as usize;
            match tag >> 3 {
                0x08 if len >= 7 => {
                    // I/O port descriptor: info, min (2), max (2), align, length.
                    ports[found] = u16::from_le_bytes([*crs.get(at + 2)?, *crs.get(at + 3)?]);
                    found += 1;
                }
                0x09 if len >= 3 => {
                    // Fixed location I/O port: base (2), length.
                    ports[found] = u16::from_le_bytes([*crs.get(at + 1)?, *crs.get(at + 2)?]);
                    found += 1;
                }
                0x0F => break, // end tag
                _ => {}
            }
            at += 1 + len;
        }
        (found == 2 && ports[0] != 0 && ports[1] != 0).then_some(EcPorts { command: ports[1], data: ports[0] })
    }
}

/// The EC's ports, settable after the interpreter started: they come from
/// the ECDT, or from the EC device's `_CRS` once the namespace is loaded.
/// Zero means none; otherwise command << 16 | data.
#[derive(Default)]
pub struct EcCell(AtomicU32);

impl EcCell {
    pub fn get(&self) -> Option<EcPorts> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            v => Some(EcPorts { command: (v >> 16) as u16, data: v as u16 }),
        }
    }

    pub fn set(&self, ports: Option<EcPorts>) {
        self.0.store(ports.map_or(0, |p| (p.command as u32) << 16 | p.data as u32), Ordering::Relaxed);
    }
}

const EC_OBF: u64 = 1;
const EC_IBF: u64 = 2;
const EC_READ: u64 = 0x80;
const EC_WRITE: u64 = 0x81;
/// Longest wait for one EC handshake step.
pub const EC_TIMEOUT_MS: u64 = 100;

/// Counters shared with the owner of the interpreter, which only sees what
/// AML returns: failed EC transactions are invisible there.
#[derive(Default)]
pub struct Stats {
    pub ec_errors: AtomicU32,
    pub ec_transactions: AtomicU32,
}

impl Stats {
    pub fn errors(&self) -> u32 {
        self.ec_errors.load(Ordering::Relaxed)
    }
}

pub struct Firmware<H: Hardware> {
    hw: H,
    ec: Arc<EcCell>,
    stats: Arc<Stats>,
}

impl<H: Hardware> Firmware<H> {
    pub fn new(hw: H, ec: Option<EcPorts>, stats: Arc<Stats>) -> Self {
        let cell = EcCell::default();
        cell.set(ec);
        Firmware { hw, ec: Arc::new(cell), stats }
    }

    /// The EC ports, shared with whoever sets them later.
    pub fn ec_cell(&self) -> Arc<EcCell> {
        self.ec.clone()
    }

    fn status(&self, ec: EcPorts) -> u64 {
        self.hw.port_in(ec.command, 1)
    }

    /// Waits until `(status & mask == 0) == clear`.
    fn wait(&self, ec: EcPorts, mask: u64, clear: bool) -> bool {
        let start = self.hw.now_ms();
        loop {
            let s = self.status(ec);
            if s != u64::MAX && (s & mask == 0) == clear {
                return true;
            }
            if self.hw.now_ms().saturating_sub(start) >= EC_TIMEOUT_MS {
                return false;
            }
        }
    }

    /// After a failed transaction: empties the output buffer so the next
    /// one does not read stale data.
    fn recover(&self, ec: EcPorts) {
        let s = self.status(ec);
        if s != u64::MAX && s & EC_OBF != 0 {
            let _ = self.hw.port_in(ec.data, 1);
        }
    }

    fn fail(&self, ec: EcPorts) {
        self.stats.ec_errors.fetch_add(1, Ordering::Relaxed);
        self.recover(ec);
    }

    fn out(&self, port: u16, value: u64) {
        self.hw.port_out(port, 1, value);
    }

    /// Reads EC register `addr`; `None` after a time-out (counted).
    pub fn ec_read(&self, addr: u8) -> Option<u8> {
        let ec = self.ec.get()?;
        self.stats.ec_transactions.fetch_add(1, Ordering::Relaxed);
        let ok = self.wait(ec, EC_IBF, true) && {
            self.out(ec.command, EC_READ);
            self.wait(ec, EC_IBF, true)
        } && {
            self.out(ec.data, addr as u64);
            self.wait(ec, EC_OBF, false)
        };
        if !ok {
            self.fail(ec);
            return None;
        }
        match self.hw.port_in(ec.data, 1) {
            u64::MAX => {
                self.fail(ec);
                None
            }
            v => Some(v as u8),
        }
    }

    pub fn ec_write(&self, addr: u8, value: u8) -> bool {
        let Some(ec) = self.ec.get() else { return false };
        self.stats.ec_transactions.fetch_add(1, Ordering::Relaxed);
        let ok = self.wait(ec, EC_IBF, true) && {
            self.out(ec.command, EC_WRITE);
            self.wait(ec, EC_IBF, true)
        } && {
            self.out(ec.data, addr as u64);
            self.wait(ec, EC_IBF, true)
        } && {
            self.out(ec.data, value as u64);
            self.wait(ec, EC_IBF, true)
        };
        if !ok {
            self.fail(ec);
        }
        ok
    }
}

fn pci_address(bus: u8, device: u8, function: u8) -> u64 {
    (bus as u64) << 16 | (device as u64) << 8 | function as u64
}

impl<H: Hardware> Handler for Firmware<H> {
    fn read_u8(&self, address: usize) -> u8 {
        self.hw.phys_read(address as u64, 1) as u8
    }
    fn read_u16(&self, address: usize) -> u16 {
        self.hw.phys_read(address as u64, 2) as u16
    }
    fn read_u32(&self, address: usize) -> u32 {
        self.hw.phys_read(address as u64, 4) as u32
    }
    fn read_u64(&self, address: usize) -> u64 {
        self.hw.phys_read(address as u64, 8)
    }
    fn write_u8(&mut self, address: usize, value: u8) {
        self.hw.phys_write(address as u64, 1, value as u64);
    }
    fn write_u16(&mut self, address: usize, value: u16) {
        self.hw.phys_write(address as u64, 2, value as u64);
    }
    fn write_u32(&mut self, address: usize, value: u32) {
        self.hw.phys_write(address as u64, 4, value as u64);
    }
    fn write_u64(&mut self, address: usize, value: u64) {
        self.hw.phys_write(address as u64, 8, value);
    }
    fn read_io_u8(&self, port: u16) -> u8 {
        self.hw.port_in(port, 1) as u8
    }
    fn read_io_u16(&self, port: u16) -> u16 {
        self.hw.port_in(port, 2) as u16
    }
    fn read_io_u32(&self, port: u16) -> u32 {
        self.hw.port_in(port, 4) as u32
    }
    fn write_io_u8(&self, port: u16, value: u8) {
        self.hw.port_out(port, 1, value as u64);
    }
    fn write_io_u16(&self, port: u16, value: u16) {
        self.hw.port_out(port, 2, value as u64);
    }
    fn write_io_u32(&self, port: u16, value: u32) {
        self.hw.port_out(port, 4, value as u64);
    }
    fn read_pci_u8(&self, segment: u16, bus: u8, device: u8, function: u8, offset: u16) -> u8 {
        if segment != 0 {
            return 0xff;
        }
        self.hw.pci_read(pci_address(bus, device, function), offset as u64, 1) as u8
    }
    fn read_pci_u16(&self, segment: u16, bus: u8, device: u8, function: u8, offset: u16) -> u16 {
        if segment != 0 {
            return 0xffff;
        }
        self.hw.pci_read(pci_address(bus, device, function), offset as u64, 2) as u16
    }
    fn read_pci_u32(&self, segment: u16, bus: u8, device: u8, function: u8, offset: u16) -> u32 {
        if segment != 0 {
            return u32::MAX;
        }
        self.hw.pci_read(pci_address(bus, device, function), offset as u64, 4) as u32
    }
    fn write_pci_u8(&self, segment: u16, bus: u8, device: u8, function: u8, offset: u16, value: u8) {
        if segment == 0 {
            self.hw.pci_write(pci_address(bus, device, function), offset as u64, 1, value as u64);
        }
    }
    fn write_pci_u16(&self, segment: u16, bus: u8, device: u8, function: u8, offset: u16, value: u16) {
        if segment == 0 {
            self.hw.pci_write(pci_address(bus, device, function), offset as u64, 2, value as u64);
        }
    }
    fn write_pci_u32(&self, segment: u16, bus: u8, device: u8, function: u8, offset: u16, value: u32) {
        if segment == 0 {
            self.hw.pci_write(pci_address(bus, device, function), offset as u64, 4, value as u64);
        }
    }
    fn read_ec_u8(&self, offset: u8) -> u8 {
        // A failed transaction is counted in `Stats`; AML gets a zero it
        // cannot tell apart, so the poll that read it is discarded.
        self.ec_read(offset).unwrap_or(0)
    }
    fn write_ec_u8(&self, offset: u8, value: u8) {
        let _ = self.ec_write(offset, value);
    }
    fn handle_fatal_error(&self, _fatal_type: u8, _fatal_code: u32, _fatal_arg: u64) {
        // The interpreter must not take the daemon down with it: the
        // failing method returns an error instead.
        self.stats.ec_errors.fetch_add(1, Ordering::Relaxed);
    }
}
