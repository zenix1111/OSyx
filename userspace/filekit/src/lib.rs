//! The logic of the Files application that needs no screen: what kind a
//! file is, which programs open it ("Open with"), tar and zip archives, and
//! the arithmetic of multi-selection and copy names. Host-tested.

#![no_std]

extern crate alloc;

pub mod gzip;
pub mod kind;
pub mod openwith;
pub mod select;
pub mod tar;
pub mod zip;

pub use kind::{classify, Kind};
