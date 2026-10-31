//! ACPI facts about HID over I2C devices: their ids, the `_DSM` that gives
//! the HID descriptor register, and the resource descriptors of `_CRS`.
//!
//! The AML interpreter evaluates the methods (in user space, see
//! `userspace/i2chid`); this module only decodes the byte strings it
//! returns. The resource parser is written here because the one in the AML
//! crate does not know serial bus or GPIO connections (it panics on them).

use alloc::string::String;
use alloc::vec::Vec;

/// `_HID`/`_CID` of a HID over I2C device.
pub const HID_IDS: [&str; 2] = ["PNP0C50", "ACPI0C50"];

/// `_HID`/`_CID` values of DesignWare controllers that are ACPI devices
/// (PCI ones have an `_ADR` instead).
pub const DESIGNWARE_IDS: [&str; 4] = ["AMDI0010", "AMDI0510", "APMC0D0F", "INT33C2"];

pub fn is_hid_over_i2c(id: &str) -> bool {
    HID_IDS.contains(&id)
}

/// The `_DSM` UUID of HID over I2C (3CDFF6F7-4267-4555-AD05-B30A3D8938DE)
/// as the 16-byte buffer AML passes (first three fields little-endian).
pub const DSM_UUID: [u8; 16] = [0xF7, 0xF6, 0xDF, 0x3C, 0x67, 0x42, 0x55, 0x45, 0xAD, 0x05, 0xB3, 0x0A, 0x3D, 0x89, 0x38, 0xDE];
/// Revision and function index of the descriptor register query.
pub const DSM_REVISION: u64 = 1;
pub const DSM_FUNCTION_DESCRIPTOR_ADDRESS: u64 = 1;

/// A compressed EISA id (what `EisaId("PNP0C50")` compiles to, as the
/// integer AML returns) as text, "PNP0C50".
pub fn eisa_id_text(value: u32) -> String {
    let id = value.swap_bytes();
    let letter = |shift: u32| (((id >> shift) & 0x1F) as u8 + b'@') as char;
    let mut s = String::new();
    s.push(letter(26));
    s.push(letter(21));
    s.push(letter(16));
    for shift in [12, 8, 4, 0] {
        s.push(char::from_digit((id >> shift) & 0xF, 16).unwrap_or('0').to_ascii_uppercase());
    }
    s
}

/// An I2C serial bus connection (a target on a bus).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I2cConnection {
    pub address: u16,
    pub ten_bit: bool,
    pub speed_hz: u32,
    /// The controller device that the connection is on (an ACPI path).
    pub source: String,
}

/// A GPIO connection used as an interrupt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpioInterrupt {
    pub pin: u16,
    /// The GPIO controller device (an ACPI path).
    pub source: String,
    pub edge: bool,
    pub active_low: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resources {
    pub i2c: Vec<I2cConnection>,
    pub gpio_interrupts: Vec<GpioInterrupt>,
    /// Interrupt numbers (global system interrupts) of extended interrupt
    /// descriptors.
    pub interrupts: Vec<u32>,
    /// (base, length) of fixed and plain 32-bit memory descriptors.
    pub memory: Vec<(u64, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceError {
    /// A descriptor runs past the end of the buffer or of its own length.
    Truncated,
    /// A string or table offset points outside its descriptor.
    BadOffset,
}

fn u16_at(d: &[u8], at: usize) -> Result<u16, ResourceError> {
    d.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or(ResourceError::Truncated)
}

fn u32_at(d: &[u8], at: usize) -> Result<u32, ResourceError> {
    d.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or(ResourceError::Truncated)
}

/// The NUL-terminated string at `at` in `d`.
fn string_at(d: &[u8], at: usize) -> Result<String, ResourceError> {
    let rest = d.get(at..).ok_or(ResourceError::BadOffset)?;
    let end = rest.iter().position(|&b| b == 0).ok_or(ResourceError::BadOffset)?;
    Ok(rest[..end].iter().map(|&b| if b.is_ascii() { b as char } else { '?' }).collect())
}

/// Decodes a `_CRS` buffer. Descriptors of other kinds are skipped; the
/// list ends at the end tag or at the end of the buffer.
pub fn parse_resources(buf: &[u8]) -> Result<Resources, ResourceError> {
    let mut out = Resources::default();
    let mut i = 0;
    while i < buf.len() {
        let tag = buf[i];
        if tag & 0x80 == 0 {
            // Small item: type in bits 6:3, length in bits 2:0.
            let len = (tag & 7) as usize;
            if (tag >> 3) & 0xF == 0xF {
                break;
            }
            i += 1 + len;
            if i > buf.len() {
                return Err(ResourceError::Truncated);
            }
            continue;
        }
        let len = u16_at(buf, i + 1)? as usize;
        let d = buf.get(i..i + 3 + len).ok_or(ResourceError::Truncated)?;
        match tag & 0x7F {
            // Fixed 32-bit memory range: flags, base, length.
            0x06 if len >= 9 => out.memory.push((u32_at(d, 4)? as u64, u32_at(d, 8)?)),
            // 32-bit memory range: flags, minimum, maximum, alignment, length.
            0x05 if len >= 17 => out.memory.push((u32_at(d, 4)? as u64, u32_at(d, 16)?)),
            0x09 => {
                let count = *d.get(4).ok_or(ResourceError::Truncated)? as usize;
                for n in 0..count {
                    out.interrupts.push(u32_at(d, 5 + 4 * n)?);
                }
            }
            0x0C => {
                // GPIO connection; only interrupt connections matter.
                let kind = *d.get(4).ok_or(ResourceError::Truncated)?;
                if kind == 0 {
                    let int_flags = u16_at(d, 7)?;
                    let table = u16_at(d, 14)? as usize;
                    let name = u16_at(d, 17)? as usize;
                    if table > name || name > d.len() {
                        return Err(ResourceError::BadOffset);
                    }
                    let source = string_at(d, name)?;
                    for p in (table..name).step_by(2) {
                        out.gpio_interrupts.push(GpioInterrupt {
                            pin: u16_at(d, p)?,
                            source: source.clone(),
                            edge: int_flags & 1 != 0,
                            active_low: (int_flags >> 1) & 3 == 1,
                        });
                    }
                }
            }
            0x0E => {
                let bus_type = *d.get(5).ok_or(ResourceError::Truncated)?;
                if bus_type == 1 {
                    let flags = u16_at(d, 8)?;
                    let data_len = u16_at(d, 11)? as usize;
                    if data_len < 6 {
                        return Err(ResourceError::Truncated);
                    }
                    let source = string_at(d, 13 + data_len)?;
                    out.i2c.push(I2cConnection { address: u16_at(d, 17)?, ten_bit: flags & 1 != 0, speed_hz: u32_at(d, 13)?, source });
                }
            }
            _ => {}
        }
        i += 3 + len;
    }
    Ok(out)
}

/// Builders for `_CRS` buffers; the tests (here and in the user-space
/// service) use them to describe machines.
pub mod build {
    use alloc::vec::Vec;

    fn finish(mut d: Vec<u8>) -> Vec<u8> {
        let len = (d.len() - 3) as u16;
        d[1..3].copy_from_slice(&len.to_le_bytes());
        d
    }

    pub fn i2c_connection(address: u16, speed_hz: u32, source: &str) -> Vec<u8> {
        let mut d = Vec::from([0x8E, 0, 0]);
        d.push(1); // revision
        d.push(0); // resource source index
        d.push(1); // I2C
        d.extend_from_slice(&0u16.to_le_bytes()); // general flags: controller initiated
        d.extend_from_slice(&0u16.to_le_bytes()); // type specific flags: 7 bit
        d.push(1); // type specific revision
        d.extend_from_slice(&6u16.to_le_bytes()); // type data length
        d.extend_from_slice(&speed_hz.to_le_bytes());
        d.extend_from_slice(&address.to_le_bytes());
        d.extend_from_slice(source.as_bytes());
        d.push(0);
        finish(d)
    }

    pub fn gpio_interrupt(pin: u16, source: &str, edge: bool, active_low: bool) -> Vec<u8> {
        let mut d = Vec::from([0x8C, 0, 0]);
        d.push(1); // revision
        d.push(0); // interrupt connection
        d.extend_from_slice(&0u16.to_le_bytes()); // general flags
        let flags = u16::from(edge) | if active_low { 1 << 1 } else { 0 };
        d.extend_from_slice(&flags.to_le_bytes());
        d.push(0); // pin configuration
        d.extend_from_slice(&0u16.to_le_bytes()); // drive strength
        d.extend_from_slice(&0u16.to_le_bytes()); // debounce
        let table = 23u16;
        d.extend_from_slice(&table.to_le_bytes()); // pin table offset
        d.push(0); // resource source index
        d.extend_from_slice(&(table + 2).to_le_bytes()); // source name offset
        d.extend_from_slice(&0u16.to_le_bytes()); // vendor offset
        d.extend_from_slice(&0u16.to_le_bytes()); // vendor length
        d.extend_from_slice(&pin.to_le_bytes());
        d.extend_from_slice(source.as_bytes());
        d.push(0);
        finish(d)
    }

    pub fn memory32_fixed(base: u32, len: u32) -> Vec<u8> {
        let mut d = Vec::from([0x86, 9, 0, 1]);
        d.extend_from_slice(&base.to_le_bytes());
        d.extend_from_slice(&len.to_le_bytes());
        d
    }

    pub fn interrupt(gsi: u32) -> Vec<u8> {
        let mut d = Vec::from([0x89, 6, 0, 1, 1]);
        d.extend_from_slice(&gsi.to_le_bytes());
        d
    }

    pub fn end() -> Vec<u8> {
        Vec::from([0x79, 0])
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn eisa() {
        // EisaId("PNP0C50") as AML returns it.
        assert_eq!(eisa_id_text(0x500C_D041), "PNP0C50");
        assert_eq!(eisa_id_text(0x0A0C_D041), "PNP0C0A");
    }

    #[test]
    fn i2c_gpio_and_end() {
        let mut crs = build::i2c_connection(0x2C, 400_000, "\\_SB.PCI0.I2C1");
        crs.extend(build::gpio_interrupt(0x42, "\\_SB.GPI0", false, true));
        crs.extend(build::end());
        let r = parse_resources(&crs).unwrap();
        assert_eq!(r.i2c, [I2cConnection { address: 0x2C, ten_bit: false, speed_hz: 400_000, source: "\\_SB.PCI0.I2C1".into() }]);
        assert_eq!(r.gpio_interrupts, [GpioInterrupt { pin: 0x42, source: "\\_SB.GPI0".into(), edge: false, active_low: true }]);
        assert!(r.interrupts.is_empty());
    }

    #[test]
    fn memory_and_interrupt() {
        let mut crs = build::memory32_fixed(0xFEDC_2000, 0x1000);
        crs.extend(build::interrupt(7));
        crs.extend(build::end());
        let r = parse_resources(&crs).unwrap();
        assert_eq!(r.memory, [(0xFEDC_2000, 0x1000)]);
        assert_eq!(r.interrupts, [7]);
    }

    #[test]
    fn truncated_and_bad_offsets_are_errors() {
        let good = build::i2c_connection(0x15, 100_000, "\\_SB.I2C0");
        for cut in 1..good.len() {
            assert!(parse_resources(&good[..cut]).is_err(), "cut at {cut}");
        }
        // Unterminated source string.
        let mut bad = good.clone();
        *bad.last_mut().unwrap() = b'X';
        assert_eq!(parse_resources(&bad), Err(ResourceError::BadOffset));
        // A pin table that starts behind the source name.
        let mut gpio = build::gpio_interrupt(1, "\\GPIO", true, false);
        gpio[14] = 0xF0;
        assert!(parse_resources(&gpio).is_err());
    }

    #[test]
    fn unknown_descriptors_are_skipped() {
        // A small IRQ descriptor, a vendor large item, then an I2C one.
        let mut crs = std::vec![0x22, 0x20, 0x00];
        crs.extend([0x84, 3, 0, 1, 2, 3]);
        crs.extend(build::i2c_connection(0x10, 100_000, "\\I2C"));
        let r = parse_resources(&crs).unwrap();
        assert_eq!(r.i2c.len(), 1);
    }

    #[test]
    fn dsm_uuid_bytes() {
        assert_eq!(&DSM_UUID[..4], &0x3CDF_F6F7u32.to_le_bytes());
        assert_eq!(&DSM_UUID[4..6], &0x4267u16.to_le_bytes());
        assert_eq!(&DSM_UUID[6..8], &0x4555u16.to_le_bytes());
        assert_eq!(&DSM_UUID[8..], &[0xAD, 0x05, 0xB3, 0x0A, 0x3D, 0x89, 0x38, 0xDE]);
    }
}
