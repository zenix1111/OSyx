//! Hardware-independent parts of the OSyx I2C and HID-over-I2C stack.
//!
//! Laptop touchpads, touchscreens and some keyboards sit on an I2C bus and
//! speak HID over I2C (Microsoft, "HID over I2C Protocol Specification",
//! version 1.0). The ACPI devices are `PNP0C50` or `ACPI0C50`. This crate
//! holds everything that can run on the development host:
//!
//! * [`bus`]: the traits a platform provides ([`bus::Mmio`], [`bus::Clock`])
//!   and the one it gets back ([`bus::I2cBus`]);
//! * [`designware`]: the Synopsys DesignWare I2C master (Intel LPSS PCI
//!   functions and AMD `AMDI0010`/`AMDI0510`), polled, every wait bounded;
//! * [`hid`]: the HID over I2C protocol: descriptor, reset, power, input;
//! * [`report`]: HID report descriptors turned into key, button, motion and
//!   wheel changes (keyboards, mice, precision touchpads);
//! * [`acpi`]: the `_CRS` resources (I2C connection, GPIO and interrupt
//!   descriptors) and the `_DSM` GUID of the protocol;
//! * [`spec`]: the device description that the user-space ACPI service
//!   hands to the kernel;
//! * [`sim`]: a register-level DesignWare model with a simulated HID
//!   device, for the host tests and the kernel boot test.
//!
//! Nothing here trusts the device or the firmware: lengths, offsets and
//! register values are checked and errors returned instead of panicking.

#![no_std]

extern crate alloc;

pub mod acpi;
pub mod bus;
pub mod designware;
pub mod hid;
pub mod report;
pub mod sim;
pub mod spec;
