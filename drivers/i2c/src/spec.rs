//! The description of HID over I2C devices that the user-space ACPI service
//! passes to the kernel (`firmware` operation `I2C_HID`).
//!
//! The service evaluates the firmware's AML; the kernel never does. What
//! crosses the boundary is plain data, and the kernel checks all of it
//! again: the decoder rejects anything truncated, oversized or malformed.

use crate::designware::{SclTiming, Timing};
use alloc::string::String;
use alloc::vec::Vec;

/// "I2HD", little-endian.
pub const MAGIC: u32 = 0x4448_3249;
pub const VERSION: u16 = 1;
/// Devices in one description and bytes of one encoded description.
pub const MAX_DEVICES: usize = 16;
pub const MAX_BYTES: usize = 16 * 1024;
const MAX_NAME: usize = 120;

/// Where a controller's registers are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    /// A PCI function (Intel LPSS); the registers are in BAR 0.
    Pci { bus: u8, device: u8, function: u8 },
    /// An ACPI device with a fixed memory resource (AMD).
    Mmio { base: u64, len: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerSpec {
    /// ACPI path, for the log.
    pub path: String,
    /// `_HID` (or the `_CID`) of an ACPI controller, empty for PCI ones.
    pub hid: String,
    pub uid: u32,
    pub location: Location,
    pub timing: Timing,
}

/// How the device would signal an input report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Interrupt {
    None,
    /// An interrupt resource (global system interrupt).
    Gsi(u32),
    /// A GPIO interrupt: pin number and the GPIO controller's ACPI path.
    Gpio { pin: u16, controller: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSpec {
    /// ACPI path, for the log.
    pub path: String,
    /// 7-bit target address.
    pub address: u8,
    /// Fastest speed the firmware allows for the connection.
    pub speed_hz: u32,
    /// The HID descriptor register, from the `_DSM`.
    pub descriptor_register: u16,
    pub interrupt: Interrupt,
    pub controller: ControllerSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecError {
    Truncated,
    BadMagic,
    BadVersion,
    TooMany,
    TooLarge,
    BadString,
    BadValue,
    /// Bytes after the last device.
    Trailing,
}

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn string(&mut self, s: &str) {
        let b = s.as_bytes();
        let n = b.len().min(MAX_NAME);
        self.u8(n as u8);
        self.0.extend_from_slice(&b[..n]);
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], SpecError> {
        if self.0.len() < n {
            return Err(SpecError::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, SpecError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, SpecError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, SpecError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, SpecError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    fn string(&mut self) -> Result<String, SpecError> {
        let n = self.u8()? as usize;
        if n > MAX_NAME {
            return Err(SpecError::BadString);
        }
        let b = self.take(n)?;
        // ACPI names and ids are ASCII; anything else is not a name.
        if !b.iter().all(|&c| (0x20..0x7F).contains(&c)) {
            return Err(SpecError::BadString);
        }
        Ok(b.iter().map(|&c| c as char).collect())
    }
}

/// Encodes `devices` (at most [`MAX_DEVICES`]).
pub fn encode(devices: &[DeviceSpec]) -> Result<Vec<u8>, SpecError> {
    if devices.len() > MAX_DEVICES {
        return Err(SpecError::TooMany);
    }
    let mut w = Writer(Vec::new());
    w.u32(MAGIC);
    w.u16(VERSION);
    w.u16(devices.len() as u16);
    for d in devices {
        w.string(&d.path);
        w.u8(d.address);
        w.u32(d.speed_hz);
        w.u16(d.descriptor_register);
        match &d.interrupt {
            Interrupt::None => w.u8(0),
            Interrupt::Gsi(n) => {
                w.u8(1);
                w.u32(*n);
            }
            Interrupt::Gpio { pin, controller } => {
                w.u8(2);
                w.u16(*pin);
                w.string(controller);
            }
        }
        let c = &d.controller;
        w.string(&c.path);
        w.string(&c.hid);
        w.u32(c.uid);
        match c.location {
            Location::Pci { bus, device, function } => {
                w.u8(0);
                w.u8(bus);
                w.u8(device);
                w.u8(function);
            }
            Location::Mmio { base, len } => {
                w.u8(1);
                w.u64(base);
                w.u32(len);
            }
        }
        let t = &c.timing;
        let flags = u8::from(t.standard.is_some()) | u8::from(t.fast.is_some()) << 1 | u8::from(t.sda_hold.is_some()) << 2;
        w.u8(flags);
        for v in [t.standard.map(|s| (s.hcnt, s.lcnt)), t.fast.map(|s| (s.hcnt, s.lcnt))] {
            let (h, l) = v.unwrap_or((0, 0));
            w.u32(h);
            w.u32(l);
        }
        w.u32(t.sda_hold.unwrap_or(0));
    }
    if w.0.len() > MAX_BYTES {
        return Err(SpecError::TooLarge);
    }
    Ok(w.0)
}

/// Decodes and validates a description.
pub fn decode(bytes: &[u8]) -> Result<Vec<DeviceSpec>, SpecError> {
    if bytes.len() > MAX_BYTES {
        return Err(SpecError::TooLarge);
    }
    let mut r = Reader(bytes);
    if r.u32()? != MAGIC {
        return Err(SpecError::BadMagic);
    }
    if r.u16()? != VERSION {
        return Err(SpecError::BadVersion);
    }
    let count = r.u16()? as usize;
    if count > MAX_DEVICES {
        return Err(SpecError::TooMany);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let path = r.string()?;
        let address = r.u8()?;
        if address == 0 || address > 0x7F {
            return Err(SpecError::BadValue);
        }
        let speed_hz = r.u32()?;
        let descriptor_register = r.u16()?;
        let interrupt = match r.u8()? {
            0 => Interrupt::None,
            1 => Interrupt::Gsi(r.u32()?),
            2 => {
                let pin = r.u16()?;
                Interrupt::Gpio { pin, controller: r.string()? }
            }
            _ => return Err(SpecError::BadValue),
        };
        let cpath = r.string()?;
        let hid = r.string()?;
        let uid = r.u32()?;
        let location = match r.u8()? {
            0 => {
                let (bus, device, function) = (r.u8()?, r.u8()?, r.u8()?);
                if device > 31 || function > 7 {
                    return Err(SpecError::BadValue);
                }
                Location::Pci { bus, device, function }
            }
            1 => {
                let base = r.u64()?;
                let len = r.u32()?;
                // A DesignWare register block is 256 bytes; one page is
                // plenty, and nothing larger than 64 KiB is a controller.
                if base == 0 || !(0x100..=0x10000).contains(&len) || base.checked_add(len as u64).is_none() {
                    return Err(SpecError::BadValue);
                }
                Location::Mmio { base, len }
            }
            _ => return Err(SpecError::BadValue),
        };
        let flags = r.u8()?;
        let (sh, sl, fh, fl, hold) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        let timing = Timing {
            standard: (flags & 1 != 0).then_some(SclTiming { hcnt: sh, lcnt: sl }),
            fast: (flags & 2 != 0).then_some(SclTiming { hcnt: fh, lcnt: fl }),
            sda_hold: (flags & 4 != 0).then_some(hold),
        };
        out.push(DeviceSpec {
            path,
            address,
            speed_hz,
            descriptor_register,
            interrupt,
            controller: ControllerSpec { path: cpath, hid, uid, location, timing },
        });
    }
    if !r.0.is_empty() {
        return Err(SpecError::Trailing);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn sample(n: u8) -> DeviceSpec {
        DeviceSpec {
            path: "\\_SB_.PCI0.I2C1.TPD0".into(),
            address: 0x2C + n,
            speed_hz: 400_000,
            descriptor_register: 0x20,
            interrupt: Interrupt::Gpio { pin: 0x42, controller: "\\_SB_.GPI0".into() },
            controller: ControllerSpec {
                path: "\\_SB_.PCI0.I2C1".into(),
                hid: String::new(),
                uid: 1,
                location: Location::Pci { bus: 0, device: 0x15, function: 1 },
                timing: Timing {
                    standard: Some(SclTiming { hcnt: 0x1D0, lcnt: 0x1F7 }),
                    fast: None,
                    sda_hold: Some(0x1E),
                },
            },
        }
    }

    #[test]
    fn round_trip() {
        let mut amd = sample(1);
        amd.interrupt = Interrupt::Gsi(7);
        amd.controller.hid = "AMDI0010".into();
        amd.controller.location = Location::Mmio { base: 0xFEDC_2000, len: 0x1000 };
        amd.controller.timing = Timing::default();
        let mut none = sample(2);
        none.interrupt = Interrupt::None;
        let all = std::vec![sample(0), amd, none];
        assert_eq!(decode(&encode(&all).unwrap()).unwrap(), all);
        assert_eq!(decode(&encode(&[]).unwrap()).unwrap(), []);
    }

    #[test]
    fn truncation_is_an_error_at_every_length() {
        let blob = encode(&[sample(0), sample(1)]).unwrap();
        for cut in 0..blob.len() {
            assert!(decode(&blob[..cut]).is_err(), "cut at {cut}");
        }
        let mut longer = blob.clone();
        longer.push(0);
        assert_eq!(decode(&longer), Err(SpecError::Trailing));
    }

    #[test]
    fn bad_headers_and_values() {
        let blob = encode(&[sample(0)]).unwrap();
        let mut b = blob.clone();
        b[0] ^= 1;
        assert_eq!(decode(&b), Err(SpecError::BadMagic));
        let mut b = blob.clone();
        b[4] = 9;
        assert_eq!(decode(&b), Err(SpecError::BadVersion));
        let mut b = blob.clone();
        b[6] = 17; // count
        assert_eq!(decode(&b), Err(SpecError::TooMany));
        // Address 0 and 0x80 are not 7-bit target addresses.
        for bad in [0u8, 0x80] {
            let mut d = sample(0);
            d.address = bad;
            assert_eq!(decode(&encode(&[d]).unwrap()), Err(SpecError::BadValue));
        }
        let mut d = sample(0);
        d.controller.location = Location::Mmio { base: 0, len: 0x1000 };
        assert_eq!(decode(&encode(&[d]).unwrap()), Err(SpecError::BadValue));
        let mut d = sample(0);
        d.controller.location = Location::Mmio { base: 0x1000, len: 1 << 30 };
        assert_eq!(decode(&encode(&[d]).unwrap()), Err(SpecError::BadValue));
        let mut d = sample(0);
        d.controller.location = Location::Pci { bus: 0, device: 32, function: 0 };
        assert_eq!(decode(&encode(&[d]).unwrap()), Err(SpecError::BadValue));
        assert_eq!(decode(&std::vec![0u8; MAX_BYTES + 1]), Err(SpecError::TooLarge));
    }

    #[test]
    fn non_ascii_names_are_rejected() {
        let mut blob = encode(&[sample(0)]).unwrap();
        blob[9] = 0xC3; // first byte of the path
        assert_eq!(decode(&blob), Err(SpecError::BadString));
    }
}
