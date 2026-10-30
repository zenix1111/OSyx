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

    /// From the ECDT table (control register at byte 44, data at 56, as
    /// generic addresses whose address starts 4 bytes in); the legacy ports
    /// if the table is missing or empty.
    pub fn from_ecdt(table: Option<&[u8]>) -> EcPorts {
        let gas = |t: &[u8], at: usize| t.get(at + 4..at + 6).map(|b| u16::from_le_bytes([b[0], b[1]]));
        match table {
            Some(t) => match (gas(t, 44), gas(t, 56)) {
                (Some(command), Some(data)) if command != 0 && data != 0 => EcPorts { command, data },
                _ => EcPorts::LEGACY,
            },
            None => EcPorts::LEGACY,
        }
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
    ec: Option<EcPorts>,
    stats: Arc<Stats>,
}

impl<H: Hardware> Firmware<H> {
    pub fn new(hw: H, ec: Option<EcPorts>, stats: Arc<Stats>) -> Self {
        Firmware { hw, ec, stats }
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
        let ec = self.ec?;
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
        let Some(ec) = self.ec else { return false };
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
