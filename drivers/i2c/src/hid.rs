//! HID over I2C, Microsoft "HID over I2C Protocol Specification" 1.0.
//!
//! Registers are 16 bits wide and are written little-endian as the first
//! two bytes of a transfer. The HID descriptor register comes from the
//! ACPI `_DSM`; it names the registers of everything else.
//!
//! The device is claimed only after its answers make sense: a valid HID
//! descriptor, a reset response, a report descriptor of the announced
//! length, and (for polling) an idle signal that can be told from a report.
//! Failures are returned, never papered over.

use crate::bus::{Clock, I2cBus, I2cError};
use alloc::vec;
use alloc::vec::Vec;

pub const HID_DESCRIPTOR_LENGTH: usize = 30;
pub const BCD_VERSION: u16 = 0x0100;
/// Larger report descriptors are not real.
pub const MAX_REPORT_DESCRIPTOR: usize = 8192;
/// Largest `wMaxInputLength` accepted.
pub const MAX_INPUT_LENGTH: usize = 4096;

/// How long the device may take to answer a reset (the Linux driver waits
/// one second as well).
pub const RESET_TIMEOUT_MS: u32 = 1000;
const RESET_POLL_MS: u32 = 5;

const OPCODE_RESET: u8 = 0x01;
const OPCODE_SET_POWER: u8 = 0x08;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidError {
    Bus(I2cError),
    /// The HID descriptor is shorter than 30 bytes or says it is not 30.
    BadDescriptorLength,
    /// `bcdVersion` is not 0x0100.
    UnsupportedVersion(u16),
    /// A field of the HID descriptor is out of range.
    BadDescriptor,
    /// No reset response within [`RESET_TIMEOUT_MS`].
    NoResetResponse,
    /// An input report whose length field is impossible.
    BadReportLength(u16),
    /// The device returns reports (or garbage) where it should signal
    /// "nothing to read"; without an interrupt line it cannot be polled.
    NoIdleSignal,
}

impl From<I2cError> for HidError {
    fn from(e: I2cError) -> Self {
        HidError::Bus(e)
    }
}

/// The 30-byte HID descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HidDescriptor {
    pub report_descriptor_length: u16,
    pub report_descriptor_register: u16,
    pub input_register: u16,
    pub max_input_length: u16,
    pub output_register: u16,
    pub max_output_length: u16,
    pub command_register: u16,
    pub data_register: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    pub version_id: u16,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

impl HidDescriptor {
    pub fn parse(b: &[u8]) -> Result<HidDescriptor, HidError> {
        if b.len() < HID_DESCRIPTOR_LENGTH || le16(b, 0) as usize != HID_DESCRIPTOR_LENGTH {
            return Err(HidError::BadDescriptorLength);
        }
        let version = le16(b, 2);
        if version != BCD_VERSION {
            return Err(HidError::UnsupportedVersion(version));
        }
        let d = HidDescriptor {
            report_descriptor_length: le16(b, 4),
            report_descriptor_register: le16(b, 6),
            input_register: le16(b, 8),
            max_input_length: le16(b, 10),
            output_register: le16(b, 12),
            max_output_length: le16(b, 14),
            command_register: le16(b, 16),
            data_register: le16(b, 18),
            vendor_id: le16(b, 20),
            product_id: le16(b, 22),
            version_id: le16(b, 24),
        };
        // Input reports start with a 2-byte length. The report descriptor
        // is never empty. A zero command register cannot be written.
        if d.report_descriptor_length == 0 || d.report_descriptor_length as usize > MAX_REPORT_DESCRIPTOR {
            return Err(HidError::BadDescriptor);
        }
        if d.max_input_length < 2 || d.max_input_length as usize > MAX_INPUT_LENGTH || d.command_register == 0 {
            return Err(HidError::BadDescriptor);
        }
        Ok(d)
    }
}

/// `RESET`: command register, then the two command bytes.
pub fn reset_command(d: &HidDescriptor) -> [u8; 4] {
    let r = d.command_register.to_le_bytes();
    [r[0], r[1], 0x00, OPCODE_RESET]
}

/// `SET_POWER`: 0 = on, 1 = sleep.
pub fn set_power_command(d: &HidDescriptor, on: bool) -> [u8; 4] {
    let r = d.command_register.to_le_bytes();
    [r[0], r[1], if on { 0 } else { 1 }, OPCODE_SET_POWER]
}

/// An opened device: the bus, its address and what it announced.
pub struct I2cHid<B: I2cBus> {
    bus: B,
    address: u8,
    descriptor: HidDescriptor,
    report_descriptor: Vec<u8>,
    powered: bool,
    buffer: Vec<u8>,
}

/// The outcome of one look at the input register.
#[derive(Debug, PartialEq, Eq)]
pub enum Poll<'a> {
    /// Nothing to read: a zero length, or the device did not answer.
    Idle,
    /// One input report (with its report id byte, if the device uses ids).
    Report(&'a [u8]),
}

impl<B: I2cBus> I2cHid<B> {
    /// Reads the HID descriptor from `register`, powers the device on,
    /// resets it and reads the report descriptor.
    pub fn open(mut bus: B, clock: &dyn Clock, address: u8, register: u16) -> Result<Self, HidError> {
        let mut raw = [0u8; HID_DESCRIPTOR_LENGTH];
        bus.transfer(address, &register.to_le_bytes(), &mut raw)?;
        let descriptor = HidDescriptor::parse(&raw)?;
        let mut dev = I2cHid {
            bus,
            address,
            descriptor,
            report_descriptor: Vec::new(),
            powered: false,
            buffer: vec![0; descriptor.max_input_length as usize],
        };
        dev.set_power(clock, true)?;
        dev.reset(clock)?;
        let mut rd = vec![0u8; descriptor.report_descriptor_length as usize];
        dev.bus.transfer(address, &descriptor.report_descriptor_register.to_le_bytes(), &mut rd)?;
        dev.report_descriptor = rd;
        Ok(dev)
    }

    pub fn descriptor(&self) -> &HidDescriptor {
        &self.descriptor
    }

    pub fn report_descriptor(&self) -> &[u8] {
        &self.report_descriptor
    }

    pub fn address(&self) -> u8 {
        self.address
    }

    pub fn is_powered(&self) -> bool {
        self.powered
    }

    pub fn bus_mut(&mut self) -> &mut B {
        &mut self.bus
    }

    /// `SET_POWER`. A device needs a moment after wake-up.
    pub fn set_power(&mut self, clock: &dyn Clock, on: bool) -> Result<(), HidError> {
        let cmd = set_power_command(&self.descriptor, on);
        self.bus.transfer(self.address, &cmd, &mut [])?;
        self.powered = on;
        if on {
            clock.sleep_ms(1);
        }
        Ok(())
    }

    /// `RESET`, then waits for the reset response (a zero-length input
    /// report). Until the device is ready it may refuse the read.
    pub fn reset(&mut self, clock: &dyn Clock) -> Result<(), HidError> {
        let cmd = reset_command(&self.descriptor);
        self.bus.transfer(self.address, &cmd, &mut [])?;
        let mut waited = 0;
        while waited <= RESET_TIMEOUT_MS {
            clock.sleep_ms(RESET_POLL_MS);
            waited += RESET_POLL_MS;
            let mut len = [0xFFu8; 2];
            match self.bus.transfer(self.address, &[], &mut len) {
                Ok(()) if len == [0, 0] => return Ok(()),
                // Not ready yet, or a report that was queued before the
                // reset: keep waiting.
                Ok(()) | Err(I2cError::Nack) | Err(I2cError::Timeout) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(HidError::NoResetResponse)
    }

    /// Reads the input register once. A device without an interrupt line
    /// answers a read with no report pending by a zero length (or not at
    /// all); both are [`Poll::Idle`].
    pub fn poll_input(&mut self) -> Result<Poll<'_>, HidError> {
        let max = self.buffer.len();
        match self.bus.transfer(self.address, &[], &mut self.buffer[..max]) {
            Ok(()) => {}
            Err(I2cError::Nack) => return Ok(Poll::Idle),
            Err(e) => return Err(e.into()),
        }
        let len = le16(&self.buffer, 0);
        match len {
            0 => Ok(Poll::Idle),
            // A length that is shorter than its own field or longer than
            // the buffer is garbage (0xFFFF when nobody drives the bus).
            1 => Err(HidError::BadReportLength(len)),
            n if n as usize > max => Err(HidError::BadReportLength(n)),
            n => Ok(Poll::Report(&self.buffer[2..n as usize])),
        }
    }

    /// Checks that the device can be polled: with nothing happening, at
    /// least one of `attempts` reads must come back idle. A device that
    /// answers every read with data (it repeats its last report) would
    /// make the pointer drift on its own.
    pub fn verify_idle_signal(&mut self, clock: &dyn Clock, attempts: u32) -> Result<(), HidError> {
        for _ in 0..attempts {
            if matches!(self.poll_input(), Ok(Poll::Idle)) {
                return Ok(());
            }
            clock.sleep_ms(RESET_POLL_MS);
        }
        Err(HidError::NoIdleSignal)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn descriptor_bytes() -> [u8; 30] {
        let mut b = [0u8; 30];
        let w = |b: &mut [u8; 30], at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
        w(&mut b, 0, 30);
        w(&mut b, 2, 0x0100);
        w(&mut b, 4, 0x2A3); // report descriptor length
        w(&mut b, 6, 0x0002); // report descriptor register
        w(&mut b, 8, 0x0003); // input register
        w(&mut b, 10, 0x0040); // max input length
        w(&mut b, 12, 0x0004);
        w(&mut b, 14, 0x0040);
        w(&mut b, 16, 0x0005); // command register
        w(&mut b, 18, 0x0006); // data register
        w(&mut b, 20, 0x04F3);
        w(&mut b, 22, 0x3140);
        w(&mut b, 24, 0x0100);
        b
    }

    #[test]
    fn parses_a_descriptor() {
        let d = HidDescriptor::parse(&descriptor_bytes()).unwrap();
        assert_eq!(d.report_descriptor_length, 0x2A3);
        assert_eq!(d.report_descriptor_register, 2);
        assert_eq!(d.input_register, 3);
        assert_eq!(d.max_input_length, 0x40);
        assert_eq!(d.command_register, 5);
        assert_eq!((d.vendor_id, d.product_id, d.version_id), (0x04F3, 0x3140, 0x0100));
    }

    #[test]
    fn rejects_bad_descriptors() {
        let good = descriptor_bytes();
        assert_eq!(HidDescriptor::parse(&good[..29]), Err(HidError::BadDescriptorLength));
        let mut b = good;
        b[0] = 0x1F;
        assert_eq!(HidDescriptor::parse(&b), Err(HidError::BadDescriptorLength));
        let mut b = good;
        b[3] = 0x02;
        assert_eq!(HidDescriptor::parse(&b), Err(HidError::UnsupportedVersion(0x0200)));
        let mut b = good;
        b[4] = 0;
        b[5] = 0;
        assert_eq!(HidDescriptor::parse(&b), Err(HidError::BadDescriptor));
        let mut b = good;
        b[5] = 0x40; // 16 KiB report descriptor
        assert_eq!(HidDescriptor::parse(&b), Err(HidError::BadDescriptor));
        let mut b = good;
        b[10] = 1; // max input length below its own length field
        b[11] = 0;
        assert_eq!(HidDescriptor::parse(&b), Err(HidError::BadDescriptor));
        let mut b = good;
        b[16] = 0;
        b[17] = 0;
        assert_eq!(HidDescriptor::parse(&b), Err(HidError::BadDescriptor));
        // All ones: what an absent device on a floating bus reads as.
        assert!(HidDescriptor::parse(&[0xFF; 30]).is_err());
    }

    #[test]
    fn commands() {
        let d = HidDescriptor::parse(&descriptor_bytes()).unwrap();
        assert_eq!(reset_command(&d), [0x05, 0x00, 0x00, 0x01]);
        assert_eq!(set_power_command(&d, true), [0x05, 0x00, 0x00, 0x08]);
        assert_eq!(set_power_command(&d, false), [0x05, 0x00, 0x01, 0x08]);
    }
}
