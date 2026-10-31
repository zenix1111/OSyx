//! Hardware-independent display building blocks.
//!
//! Everything here is plain data manipulation that can be unit-tested on the
//! development host: EDID base blocks and CEA-861 extension blocks, detailed
//! timing descriptors, mode enumeration and preferred-mode selection, plus
//! the identification data a native AMD DCN driver needs first. The kernel
//! driver (`kernel/src/drivers/amdgpu.rs`) supplies PCI access and MMIO.
//!
//! References: VESA Enhanced EDID Standard 1.4 (and 1.3), CEA-861-F.
//!
//! Device data is never trusted: every length, offset and checksum is
//! checked, malformed blocks are rejected and no parser panics.

#![no_std]

extern crate alloc;

pub mod amd;
pub mod edid;

pub use edid::{Edid, EdidError, Features, Mode, Timing};
