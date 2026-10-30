//! batteryd: battery and AC adapter state from ACPI, for the taskbar.
//!
//! Loads the DSDT and SSDTs into the AML interpreter (`third_party/aml`) and
//! evaluates the firmware's own methods: `_STA`, `_BIF`/`_BIX` and `_BST` of
//! every battery device (`PNP0C0A`), `_PSR` of the AC adapter (`ACPI0003`).
//! Their fields usually live in the embedded controller, which is driven
//! through its two I/O ports. The `osyx-battery` crate does the work (units,
//! several batteries, time estimates, EC time-outs); this program supplies
//! the machine and the schedule.
//!
//! Every five seconds (two while the firmware misbehaves) the state goes to
//! `osyx_abi::BATTERY_STATUS_PATH` in the format of `osyx_abi::battery`. A
//! reading taken while the embedded controller failed is never published:
//! the last good state is kept, marked stale, and after three bad polls it
//! turns "unknown".
//!
//! The interpreter runs here, not in the kernel: firmware byte code this
//! interpreter does not handle ends this process, never the system.
#![no_std]
#![no_main]

use os_std::prelude::*;
use os_std::time::{Duration, Instant};
use os_std::{fs, thread};
use osyx_abi::battery::Status;
use osyx_abi::firmware as op;
use osyx_battery::{Acpi, EcPorts, Hardware, Monitor};

os_std::entry!(main);

/// The machine through `nr::FIRMWARE`.
struct Machine {
    start: Instant,
}

fn fw(code: u64, a: u64, b: u64, c: u64, d: u64) -> u64 {
    os_sys::firmware(code, a, b, c, d).unwrap_or(u64::MAX)
}

impl Hardware for Machine {
    fn port_in(&self, port: u16, width: u8) -> u64 {
        fw(op::PORT, port as u64, width as u64, 0, 0)
    }
    fn port_out(&self, port: u16, width: u8, value: u64) {
        fw(op::PORT, port as u64, width as u64, value, 1);
    }
    fn phys_read(&self, address: u64, width: u8) -> u64 {
        fw(op::PHYS, address, width as u64, 0, 0)
    }
    fn phys_write(&self, address: u64, width: u8, value: u64) {
        fw(op::PHYS, address, width as u64, value, 1);
    }
    fn pci_read(&self, bdf: u64, offset: u64, width: u8) -> u64 {
        fw(op::PCI, bdf, offset, width as u64, 0)
    }
    fn pci_write(&self, bdf: u64, offset: u64, width: u8, value: u64) {
        fw(op::PCI, bdf, offset, 0x100 | width as u64, value);
    }
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

/// The `n`-th ACPI table with signature `sig`.
fn table(sig: &[u8; 4], n: u64) -> Option<Vec<u8>> {
    let sig = u32::from_le_bytes(*sig) as u64;
    let len = os_sys::firmware(op::TABLE, sig, n, 0, 0).ok()? as usize;
    let mut buf = vec![0u8; len];
    os_sys::firmware(op::TABLE, sig, n, buf.as_mut_ptr() as u64, len as u64).ok()?;
    Some(buf)
}

fn write_status(text: &str) {
    let tmp = "/run/battery.tmp";
    if fs::write(tmp, text).is_ok() {
        let _ = fs::rename(tmp, osyx_abi::BATTERY_STATUS_PATH);
    }
}

fn main() -> i32 {
    let _ = os_std::system::thread_priority(0, os_std::system::priority::BELOW_NORMAL);
    let Some(dsdt) = table(b"DSDT", 0) else {
        eprintln!("batteryd: no DSDT");
        write_status(&Status::NONE.to_string());
        return 0;
    };
    let mut tables = vec![dsdt];
    for n in 0.. {
        let Some(ssdt) = table(b"SSDT", n) else { break };
        tables.push(ssdt);
    }
    let ec = EcPorts::from_ecdt(table(b"ECDT", 0).as_deref());
    let machine = Machine { start: Instant::now() };
    let mut acpi = Acpi::load(machine, Some(ec), &tables, &mut |problem| eprintln!("batteryd: {problem}"));
    println!("batteryd: {} battery device(s), {} AC adapter(s)", acpi.battery_devices(), acpi.adapter_devices());
    if acpi.battery_devices() == 0 {
        write_status(&Status::NONE.to_string());
        return 0;
    }
    let mut monitor = Monitor::new();
    let mut last = String::new();
    loop {
        let poll = acpi.poll();
        let status = monitor.update(&poll);
        let text = status.to_string();
        if text != last {
            println!("batteryd: {}", text.trim_end().replace('\n', " | "));
            write_status(&text);
            last = text;
        }
        // Look again soon after a bad poll; the EC usually recovers.
        let wait = if monitor.bad_polls() > 0 { 2 } else { 5 };
        thread::sleep(Duration::from_secs(wait));
    }
}
