//! Battery and AC adapter state from ACPI, for `batteryd`.
//!
//! * [`hw`]: the machine as the AML interpreter sees it, and the embedded
//!   controller protocol with time-outs and error counting.
//! * [`acpi`]: runs the firmware's own battery methods.
//! * [`model`]: units, several batteries, charge state, time estimates, and
//!   what to publish when the firmware misbehaves.
//!
//! Everything but the access to the real machine is plain code that the
//! host tests drive with a mock machine and hand-assembled AML.

#![no_std]

extern crate alloc;

pub mod acpi;
pub mod hw;
pub mod model;

pub use acpi::Acpi;
pub use hw::{EcPorts, Hardware};
pub use model::{Monitor, Poll, Sample};
