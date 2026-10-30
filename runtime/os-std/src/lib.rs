//! OSyx Std: the standard library for native OSyx programs.
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//! use os_std::prelude::*;
//!
//! os_std::entry!(main);
//!
//! fn main() {
//!     println!("Hello from OSyx!");
//!     let mut values = Vec::new();
//!     values.push(10);
//!     println!("Values: {:?}", values);
//! }
//! ```
//!
//! This crate is the *convenience* standard library: it builds on upstream
//! `core` and `alloc` (so `Vec`, `String`, `Box`, `BTreeMap`, `format!` are the
//! real ones) and adds OSyx platform services. It is not yet a target-specific
//! implementation of Rust's `std` (see docs/rust-std.md), which is why
//! programs still declare `#![no_std]` / `#![no_main]` and use [`entry!`].
//!
//! Platform back ends (exactly one is compiled):
//! * `osyx`: the real one, on `x86_64-unknown-none` user programs. System
//!   calls via `os-sys`, heap on anonymous `map` memory, `_start`, panic handler.
//! * `host`: only for unit-testing this crate on the development host. It is
//!   implemented with the host's Rust std and proves nothing about OSyx itself.

#![no_std]

extern crate alloc;
#[cfg(not(target_os = "none"))]
extern crate std;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[path = "sys/osyx.rs"]
mod sys;

#[cfg(not(target_os = "none"))]
#[path = "sys/host.rs"]
mod sys;

pub mod env;
pub mod error;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod fastfloat;
pub mod fs;
pub mod io;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod ipc;
pub mod mpsc;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod net;
pub mod os;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod system;
pub mod path;
pub mod process;
pub mod rt;
pub mod sync;
pub mod thread;
pub mod time;
mod tls;

pub use alloc::{borrow, boxed, collections, fmt, format, rc, string, vec};
pub use core::{array, cell, cmp, convert, hash, hint, iter, marker, mem, ops, option, ptr, result, slice, str};

/// Name of the platform back end this build uses (`"osyx"` or `"host"`).
pub const BACKEND: &str = sys::NAME;

/// The usual imports for OSyx programs.
pub mod prelude {
    pub use crate::error::{Error, ErrorKind};
    pub use crate::io::{Read as _, Seek as _, Write as _};
    pub use crate::sync::{Arc, Condvar, Mutex};
    pub use crate::{eprint, eprintln, print, println};
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
    pub use alloc::{format, vec};
}

/// Prints to standard output.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::io::_print($crate::io::Stream::Stdout, format_args!($($arg)*)) };
}

/// Prints to standard output, with a newline.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {
        $crate::io::_print($crate::io::Stream::Stdout, format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// Prints to standard error.
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => { $crate::io::_print($crate::io::Stream::Stderr, format_args!($($arg)*)) };
}

/// Prints to standard error, with a newline.
#[macro_export]
macro_rules! eprintln {
    () => { $crate::eprint!("\n") };
    ($($arg:tt)*) => {
        $crate::io::_print($crate::io::Stream::Stderr, format_args!("{}\n", format_args!($($arg)*)))
    };
}
