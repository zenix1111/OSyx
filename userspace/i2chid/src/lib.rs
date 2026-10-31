//! HID over I2C discovery for `i2chidd`.
//!
//! Evaluates the firmware's AML (`third_party/aml`, in user space like
//! `batteryd`) and describes every HID over I2C device (`_HID` or `_CID`
//! `PNP0C50`/`ACPI0C50`) that the kernel could drive:
//!
//! * `_STA` says the device is present, enabled and working;
//! * `_CRS` has an I2C serial bus connection (7-bit address, speed, the
//!   controller's path), and maybe a GPIO or plain interrupt;
//! * `_DSM` with GUID `3CDFF6F7-4267-4555-AD05-B30A3D8938DE`, revision 1,
//!   function 1, gives the HID descriptor register;
//! * the controller (the connection's resource source) is either a PCI
//!   function directly below a PCI host bridge (`_ADR`; Intel LPSS) or an
//!   ACPI device with a memory resource (AMD `AMDI0010`/`AMDI0510`), and
//!   `SSCN`/`FMCN` give its SCL timing.
//!
//! Whatever is missing or does not make sense is logged with its reason and
//! the device is left out; nothing is guessed.

#![no_std]

extern crate alloc;

use aml::value::Args;
use aml::{AmlContext, AmlName, AmlValue, DebugVerbosity, LevelType};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use osyx_battery::hw::{Firmware, Hardware, Stats};
use osyx_i2c::acpi::{self, parse_resources, Resources, DESIGNWARE_IDS};
use osyx_i2c::designware::{SclTiming, Timing};
use osyx_i2c::spec::{ControllerSpec, DeviceSpec, Interrupt, Location};

/// Loads the tables (whole tables, header included) into a new interpreter
/// and runs the `_INI` methods. Tables that fail to parse are logged and
/// skipped. The embedded controller is not touched: another service owns it.
pub fn load<H: Hardware + 'static>(hw: H, tables: &[Vec<u8>], log: &mut dyn FnMut(&str)) -> AmlContext {
    let mut ctx = AmlContext::new(Box::new(Firmware::new(hw, None, Arc::new(Stats::default()))), DebugVerbosity::None);
    for (i, t) in tables.iter().enumerate() {
        if let Err(e) = ctx.parse_table(&t[36.min(t.len())..]) {
            log(&format!("table {i}: {e:?}"));
        }
    }
    if let Err(e) = ctx.initialize_objects() {
        log(&format!("initialising objects: {e:?}"));
    }
    ctx
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

/// An id value as text: EISA ids are compressed into integers.
fn id_text(ctx: &AmlContext, v: &AmlValue) -> Option<String> {
    match v {
        AmlValue::String(s) => Some(s.clone()),
        AmlValue::Integer(n) => Some(acpi::eisa_id_text(*n as u32)),
        other => other.as_integer(ctx).ok().map(|n| acpi::eisa_id_text(n as u32)),
    }
}

/// `_HID` and `_CID` (one id or a package of them) of a device.
fn ids_of(ctx: &mut AmlContext, dev: &AmlName) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(v) = call(ctx, dev, "_HID", Args::EMPTY) {
        out.extend(id_text(ctx, &v));
    }
    match call(ctx, dev, "_CID", Args::EMPTY) {
        Some(AmlValue::Package(items)) => out.extend(items.iter().filter_map(|v| id_text(ctx, v))),
        Some(v) => out.extend(id_text(ctx, &v)),
        None => {}
    }
    out
}

/// `_STA`: present, enabled and functioning. No `_STA` means all three.
fn usable(ctx: &mut AmlContext, dev: &AmlName) -> Result<(), String> {
    let Some(v) = call(ctx, dev, "_STA", Args::EMPTY) else {
        // Distinguish "no _STA" from "_STA failed".
        return match path(dev, "_STA").map(|p| ctx.namespace.get_by_path(&p).is_ok()) {
            Some(true) => Err(String::from("_STA failed")),
            _ => Ok(()),
        };
    };
    let sta = integer(ctx, &v).ok_or_else(|| String::from("_STA is not an integer"))?;
    if sta & 0b1011 == 0b1011 {
        Ok(())
    } else {
        Err(format!("_STA is {sta:#x}: not present, enabled and functioning"))
    }
}

fn resources_of(ctx: &mut AmlContext, dev: &AmlName) -> Result<Resources, String> {
    let v = call(ctx, dev, "_CRS", Args::EMPTY).ok_or_else(|| String::from("_CRS missing or failed"))?;
    let AmlValue::Buffer(buf) = v else { return Err(String::from("_CRS is not a buffer")) };
    let bytes = buf.lock().clone();
    parse_resources(&bytes).map_err(|e| format!("_CRS: {e:?}"))
}

/// `SSCN` or `FMCN`: a package of SCL high count, low count and SDA hold.
fn scl_package(ctx: &mut AmlContext, ctrl: &AmlName, method: &str) -> Option<(SclTiming, u32)> {
    let AmlValue::Package(items) = call(ctx, ctrl, method, Args::EMPTY)? else { return None };
    let n = |i: usize| items.get(i).and_then(|v| integer(ctx, v));
    let (hcnt, lcnt) = (u32::try_from(n(0)?).ok()?, u32::try_from(n(1)?).ok()?);
    Some((SclTiming { hcnt, lcnt }, n(2).and_then(|v| u32::try_from(v).ok()).unwrap_or(0)))
}

fn parent(name: &AmlName) -> Option<AmlName> {
    let s = name.as_string();
    let at = s.rfind('.')?;
    AmlName::from_str(&s[..at]).ok()
}

fn controller(ctx: &mut AmlContext, source: &str) -> Result<ControllerSpec, String> {
    if !source.starts_with('\\') {
        return Err(format!("controller path \"{source}\" is not absolute"));
    }
    let name = AmlName::from_str(source).map_err(|e| format!("controller path \"{source}\": {e:?}"))?;
    if !matches!(ctx.namespace.get_by_path(&name), Ok(AmlValue::Device)) {
        return Err(format!("{source} is not a device"));
    }
    usable(ctx, &name).map_err(|e| format!("controller {source}: {e}"))?;
    let ids = ids_of(ctx, &name);
    let uid = call(ctx, &name, "_UID", Args::EMPTY).and_then(|v| integer(ctx, &v)).unwrap_or(0) as u32;
    let ss = scl_package(ctx, &name, "SSCN");
    let fs = scl_package(ctx, &name, "FMCN");
    let timing = Timing {
        standard: ss.map(|t| t.0),
        fast: fs.map(|t| t.0),
        sda_hold: [ss, fs].into_iter().flatten().map(|t| t.1).find(|&h| h != 0),
    };
    let text = name.as_string();
    if let Some(adr) = call(ctx, &name, "_ADR", Args::EMPTY).and_then(|v| integer(ctx, &v)) {
        // A PCI function. Its bus is only known for a function directly
        // below a host bridge.
        let (device, function) = ((adr >> 16) as u32, (adr & 0xFFFF) as u32);
        if device > 31 || function > 7 {
            return Err(format!("controller {text}: _ADR {adr:#x} is not a PCI device/function"));
        }
        let bridge = parent(&name).ok_or_else(|| format!("controller {text} has no parent"))?;
        if !ids_of(ctx, &bridge).iter().any(|i| i == "PNP0A03" || i == "PNP0A08") {
            return Err(format!("controller {text} is not directly below a PCI host bridge, its PCI bus is unknown"));
        }
        let bus = call(ctx, &bridge, "_BBN", Args::EMPTY).and_then(|v| integer(ctx, &v)).unwrap_or(0);
        let bus = u8::try_from(bus).map_err(|_| format!("controller {text}: bus number {bus} too large"))?;
        return Ok(ControllerSpec {
            path: text,
            hid: String::new(),
            uid,
            location: Location::Pci { bus, device: device as u8, function: function as u8 },
            timing,
        });
    }
    let Some(hid) = ids.iter().find(|i| DESIGNWARE_IDS.contains(&i.as_str())).cloned() else {
        return Err(format!("controller {text} (ids {ids:?}) is neither a PCI function nor a known DesignWare ACPI device"));
    };
    let res = resources_of(ctx, &name).map_err(|e| format!("controller {text}: {e}"))?;
    let &(base, len) = res.memory.first().ok_or_else(|| format!("controller {text}: no memory resource"))?;
    Ok(ControllerSpec { path: text, hid, uid, location: Location::Mmio { base, len }, timing })
}

fn descriptor_register(ctx: &mut AmlContext, dev: &AmlName) -> Result<u16, String> {
    let uuid = AmlValue::Buffer(Arc::new(spinning_top::Spinlock::new(acpi::DSM_UUID.to_vec())));
    let args = Args::from_list(vec![
        uuid,
        AmlValue::Integer(acpi::DSM_REVISION),
        AmlValue::Integer(acpi::DSM_FUNCTION_DESCRIPTOR_ADDRESS),
        AmlValue::Package(Vec::new()),
    ])
    .map_err(|e| format!("_DSM arguments: {e:?}"))?;
    let v = ctx.invoke_method(&path(dev, "_DSM").ok_or_else(|| String::from("bad path"))?, args).map_err(|e| format!("_DSM failed: {e:?}"))?;
    let AmlValue::Integer(reg) = v else { return Err(String::from("_DSM did not return the HID descriptor register (not an integer)")) };
    u16::try_from(reg).map_err(|_| format!("_DSM returned {reg:#x}, which is not a 16-bit register"))
}

/// Describes every usable HID over I2C device. Reasons for leaving a device
/// out go to `log`.
pub fn enumerate(ctx: &mut AmlContext, log: &mut dyn FnMut(&str)) -> Vec<DeviceSpec> {
    let mut all = Vec::new();
    let _ = ctx.namespace.traverse(|name, level| {
        if level.typ == LevelType::Device {
            all.push(name.clone());
        }
        Ok(true)
    });
    let mut out = Vec::new();
    for dev in all {
        if !ids_of(ctx, &dev).iter().any(|i| acpi::is_hid_over_i2c(i)) {
            continue;
        }
        let text = dev.as_string();
        match describe(ctx, &dev) {
            Ok(spec) => {
                log(&format!(
                    "{text}: address {:#04x} on {} ({} Hz), descriptor register {:#06x}",
                    spec.address, spec.controller.path, spec.speed_hz, spec.descriptor_register
                ));
                out.push(spec);
            }
            Err(why) => log(&format!("{text}: skipped: {why}")),
        }
    }
    out
}

fn describe(ctx: &mut AmlContext, dev: &AmlName) -> Result<DeviceSpec, String> {
    usable(ctx, dev)?;
    let res = resources_of(ctx, dev)?;
    let conn = res.i2c.first().ok_or_else(|| String::from("_CRS has no I2C serial bus connection"))?;
    if conn.ten_bit {
        return Err(String::from("10-bit addressing is not supported"));
    }
    let address = u8::try_from(conn.address).ok().filter(|a| (1..=0x7F).contains(a)).ok_or_else(|| format!("address {:#x} is not a 7-bit target address", conn.address))?;
    let register = descriptor_register(ctx, dev)?;
    let controller = controller(ctx, &conn.source)?;
    let interrupt = match (res.gpio_interrupts.first(), res.interrupts.first()) {
        (Some(g), _) => Interrupt::Gpio { pin: g.pin, controller: g.source.clone() },
        (None, Some(&n)) => Interrupt::Gsi(n),
        (None, None) => Interrupt::None,
    };
    Ok(DeviceSpec { path: dev.as_string(), address, speed_hz: conn.speed_hz, descriptor_register: register, interrupt, controller })
}
