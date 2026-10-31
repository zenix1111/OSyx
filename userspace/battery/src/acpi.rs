//! The firmware's own battery methods, run by the AML interpreter:
//! `_STA`, `_BIF`/`_BIX` and `_BST` of every battery device (`PNP0C0A`),
//! `_PSR` of every AC adapter (`ACPI0003`).

use crate::hw::{EcCell, EcPorts, Firmware, Hardware, Stats};
use crate::model::{field, Poll, Sample};
use aml::value::Args;
use aml::{AmlContext, AmlName, AmlValue, DebugVerbosity, LevelType};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

/// `_BIF`/`_BIX` change rarely (the last full capacity creeps down over
/// months) and each call costs many EC reads: ask again after this many polls.
const STATIC_INFO_POLLS: u32 = 24;

#[derive(Clone, Copy, Debug, Default)]
struct StaticInfo {
    amp_units: bool,
    design_capacity: Option<u32>,
    last_full_capacity: Option<u32>,
    design_voltage: Option<u32>,
}

struct Battery {
    name: AmlName,
    info: Option<StaticInfo>,
    info_age: u32,
}

pub struct Acpi {
    ctx: AmlContext,
    batteries: Vec<Battery>,
    adapters: Vec<AmlName>,
    ec_devices: Vec<AmlName>,
    stats: Arc<Stats>,
    polls: u32,
    ec_cell: Arc<EcCell>,
    ec_source: &'static str,
}

/// An `_HID` as text: EISA IDs are compressed into integers.
fn hid_text(v: &AmlValue, ctx: &AmlContext) -> Option<String> {
    match v {
        AmlValue::String(s) => Some(s.clone()),
        _ => {
            let id = v.as_integer(ctx).ok()? as u32;
            let id = id.swap_bytes();
            let letter = |shift: u32| (((id >> shift) & 0x1f) as u8 + b'@') as char;
            Some(format!("{}{}{}{:04X}", letter(26), letter(21), letter(16), id & 0xffff))
        }
    }
}

fn path(base: &AmlName, child: &str) -> Option<AmlName> {
    AmlName::from_str(&format!("{}.{}", base.as_string(), child)).ok()
}

fn call(ctx: &mut AmlContext, base: &AmlName, method: &str, args: Args) -> Option<AmlValue> {
    ctx.invoke_method(&path(base, method)?, args).ok()
}

fn integer(ctx: &AmlContext, v: &AmlValue) -> Option<u64> {
    v.as_integer(ctx).ok()
}

fn package(v: Option<AmlValue>) -> Option<Vec<AmlValue>> {
    match v? {
        AmlValue::Package(items) => Some(items),
        _ => None,
    }
}

/// The EC ports an EC device's `_CRS` names.
fn crs_ports(ctx: &mut AmlContext, dev: &AmlName) -> Option<EcPorts> {
    match call(ctx, dev, "_CRS", Args::EMPTY)? {
        AmlValue::Buffer(bytes) => EcPorts::from_crs(&bytes.lock()),
        _ => None,
    }
}

/// Devices by `_HID`.
fn devices(ctx: &mut AmlContext, wanted: &[&str]) -> Vec<AmlName> {
    let mut all = Vec::new();
    let _ = ctx.namespace.traverse(|name, level| {
        if level.typ == LevelType::Device {
            all.push(name.clone());
        }
        Ok(true)
    });
    let mut found = Vec::new();
    for name in all {
        let Some(hid) = call(ctx, &name, "_HID", Args::EMPTY) else { continue };
        if hid_text(&hid, ctx).is_some_and(|t| wanted.contains(&t.as_str())) {
            found.push(name);
        }
    }
    found
}

impl Acpi {
    /// Loads the DSDT and SSDTs (whole tables, header included) and finds
    /// the devices. Tables that fail to parse are skipped: a battery method
    /// this interpreter cannot run costs that battery, not the daemon.
    ///
    /// `ec` are the ports the ECDT gave; with `None` the EC device's `_CRS`
    /// is asked, and the legacy ports (0x62/0x66) are the last resort. The
    /// ports are fixed before `initialize_objects`, whose `_INI` methods may
    /// already read the EC.
    pub fn load<H: Hardware + 'static>(hw: H, ec: Option<EcPorts>, tables: &[Vec<u8>], log: &mut dyn FnMut(&str)) -> Acpi {
        let stats = Arc::new(Stats::default());
        let firmware = Firmware::new(hw, ec, stats.clone());
        let ec_cell = firmware.ec_cell();
        let mut ctx = AmlContext::new(Box::new(firmware), DebugVerbosity::None);
        for (i, t) in tables.iter().enumerate() {
            if let Err(e) = ctx.parse_table(&t[36.min(t.len())..]) {
                log(&format!("table {i}: {e:?}"));
            }
        }
        let ec_devices = devices(&mut ctx, &["PNP0C09"]);
        let ec_source = if ec.is_some() {
            "ECDT"
        } else if let Some(ports) = ec_devices.iter().find_map(|d| crs_ports(&mut ctx, d)) {
            ec_cell.set(Some(ports));
            "_CRS"
        } else {
            ec_cell.set(Some(EcPorts::LEGACY));
            "legacy ports"
        };
        if let Err(e) = ctx.initialize_objects() {
            log(&format!("initialising objects: {e:?}"));
        }
        let mut acpi = Acpi {
            ctx,
            batteries: Vec::new(),
            adapters: Vec::new(),
            ec_devices,
            stats,
            polls: 0,
            ec_cell,
            ec_source,
        };
        acpi.connect_ec();
        acpi.batteries = devices(&mut acpi.ctx, &["PNP0C0A"]).into_iter().map(|name| Battery { name, info: None, info_age: 0 }).collect();
        acpi.adapters = devices(&mut acpi.ctx, &["ACPI0003"]);
        acpi
    }

    /// Tells the firmware its embedded controller region may be used
    /// (`_REG(EmbeddedControl, connected)`); battery methods check this.
    pub fn connect_ec(&mut self) {
        for dev in self.ec_devices.clone() {
            if let Ok(args) = Args::from_list(vec![AmlValue::Integer(3), AmlValue::Integer(1)]) {
                let _ = call(&mut self.ctx, &dev, "_REG", args);
            }
        }
    }

    /// The EC ports in use and where they came from.
    pub fn ec_ports(&self) -> (Option<EcPorts>, &'static str) {
        (self.ec_cell.get(), self.ec_source)
    }

    /// How many EC tables, devices ... the namespace holds: EC devices found.
    pub fn ec_devices(&self) -> usize {
        self.ec_devices.len()
    }

    pub fn battery_devices(&self) -> usize {
        self.batteries.len()
    }

    pub fn adapter_devices(&self) -> usize {
        self.adapters.len()
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// `_STA` bit 4: a battery is inserted. No `_STA` means present; a
    /// failing one counts as present, the readings then decide.
    fn present(ctx: &mut AmlContext, dev: &AmlName) -> bool {
        match call(ctx, dev, "_STA", Args::EMPTY) {
            Some(v) => integer(ctx, &v).is_none_or(|s| s & 0x10 != 0),
            None => true,
        }
    }

    fn static_info(ctx: &mut AmlContext, dev: &AmlName) -> Option<StaticInfo> {
        // `_BIX` starts with a revision, so its fields are one slot later:
        // unit at 1, design capacity 2, last full 3, design voltage 5.
        // `_BIF`: unit 0, design capacity 1, last full 2, design voltage 4.
        let (p, base) = match package(call(ctx, dev, "_BIX", Args::EMPTY)) {
            Some(p) if p.len() > 5 => (p, 1),
            _ => (package(call(ctx, dev, "_BIF", Args::EMPTY))?, 0),
        };
        let get = |ctx: &AmlContext, i: usize| p.get(base + i).and_then(|v| integer(ctx, v)).and_then(field);
        Some(StaticInfo {
            amp_units: p.get(base).and_then(|v| integer(ctx, v)) == Some(1),
            design_capacity: get(ctx, 1),
            last_full_capacity: get(ctx, 2),
            design_voltage: get(ctx, 4),
        })
    }

    fn sample(ctx: &mut AmlContext, b: &mut Battery) -> Option<Sample> {
        if b.info.is_none() || b.info_age >= STATIC_INFO_POLLS {
            match Self::static_info(ctx, &b.name) {
                Some(i) => {
                    b.info = Some(i);
                    b.info_age = 0;
                }
                // Keep using the old values if the refresh failed.
                None if b.info.is_some() => {}
                None => return None,
            }
        }
        b.info_age += 1;
        let info = b.info?;
        let st = package(call(ctx, &b.name, "_BST", Args::EMPTY))?;
        let num = |i: usize| st.get(i).and_then(|v| integer(ctx, v));
        let state = num(0)?;
        Some(Sample {
            amp_units: info.amp_units,
            design_capacity: info.design_capacity,
            last_full_capacity: info.last_full_capacity,
            design_voltage: info.design_voltage,
            remaining: num(2).and_then(field),
            rate: num(1).and_then(field),
            voltage: num(3).and_then(field),
            discharging: state & 1 != 0,
            charging: state & 2 != 0,
            critical: state & 4 != 0,
        })
    }

    /// Runs the firmware's methods once.
    pub fn poll(&mut self) -> Poll {
        self.polls += 1;
        let errors_before = self.stats.errors();
        let mut out = Poll { devices: self.batteries.len(), ..Poll::default() };
        let mut batteries = core::mem::take(&mut self.batteries);
        for b in batteries.iter_mut() {
            if !Self::present(&mut self.ctx, &b.name) {
                // Removed or never inserted: its cached numbers are stale.
                b.info = None;
                continue;
            }
            out.batteries.push(Self::sample(&mut self.ctx, b));
        }
        self.batteries = batteries;
        for a in self.adapters.clone() {
            if let Some(v) = call(&mut self.ctx, &a, "_PSR", Args::EMPTY) {
                if let Some(n) = integer(&self.ctx, &v) {
                    out.ac = Some(out.ac.unwrap_or(false) | (n == 1));
                }
            }
        }
        out.ec_errors = self.stats.errors().wrapping_sub(errors_before);
        if out.ec_errors > 0 {
            // The EC may have lost its connection to the firmware (a
            // resume, a reset): announce it again for the next poll, and
            // do not trust the cached static numbers either.
            self.connect_ec();
            for b in self.batteries.iter_mut() {
                b.info_age = STATIC_INFO_POLLS;
            }
        }
        out
    }
}
