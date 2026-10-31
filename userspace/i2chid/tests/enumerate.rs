//! Discovery against hand-assembled AML tables: an Intel-style machine (PCI
//! controller below a host bridge, GPIO interrupt) and an AMD-style one (ACPI
//! controller with a memory resource), plus every reason to leave a device out.

use osyx_battery::Hardware;
use osyx_i2c::acpi::{build, DSM_UUID};
use osyx_i2c::designware::{SclTiming, Timing};
use osyx_i2c::spec::{DeviceSpec, Interrupt, Location};
use osyx_i2chid::{enumerate, load};
use std::sync::atomic::{AtomicU64, Ordering};

// ---- the machine ------------------------------------------------------------------------------

/// Nothing behind any port or address; AML that touches hardware reads ones.
struct Machine(AtomicU64);

impl Hardware for Machine {
    fn port_in(&self, _: u16, _: u8) -> u64 {
        u64::MAX
    }
    fn port_out(&self, _: u16, _: u8, _: u64) {}
    fn phys_read(&self, _: u64, _: u8) -> u64 {
        u64::MAX
    }
    fn phys_write(&self, _: u64, _: u8, _: u64) {}
    fn pci_read(&self, _: u64, _: u64, _: u8) -> u64 {
        u64::MAX
    }
    fn pci_write(&self, _: u64, _: u64, _: u8, _: u64) {}
    fn now_ms(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

// ---- AML assembly -----------------------------------------------------------------------------

fn seg(s: &str) -> Vec<u8> {
    assert_eq!(s.len(), 4);
    s.as_bytes().to_vec()
}

fn pkg_len(body: usize) -> Vec<u8> {
    if body < 0x3F {
        vec![(body + 1) as u8]
    } else {
        let total = body + 2;
        assert!(total < 0x1000);
        vec![0x40 | (total & 0xF) as u8, (total >> 4) as u8]
    }
}

fn int(v: u64) -> Vec<u8> {
    match v {
        0 => vec![0x00],
        1 => vec![0x01],
        2..=0xFF => vec![0x0A, v as u8],
        0x100..=0xFFFF => vec![0x0B, v as u8, (v >> 8) as u8],
        _ => {
            let mut o = vec![0x0C];
            o.extend_from_slice(&(v as u32).to_le_bytes());
            o
        }
    }
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

fn name(n: &str, value: Vec<u8>) -> Vec<u8> {
    cat(&[vec![0x08], seg(n), value])
}

fn ret(v: Vec<u8>) -> Vec<u8> {
    cat(&[vec![0xA4], v])
}

fn method(n: &str, args: u8, body: Vec<u8>) -> Vec<u8> {
    let inner = cat(&[seg(n), vec![args], body]);
    cat(&[vec![0x14], pkg_len(inner.len()), inner])
}

fn package(items: Vec<Vec<u8>>) -> Vec<u8> {
    let inner = cat(&[vec![items.len() as u8], items.concat()]);
    cat(&[vec![0x12], pkg_len(inner.len()), inner])
}

fn buffer(bytes: &[u8]) -> Vec<u8> {
    let inner = cat(&[int(bytes.len() as u64), bytes.to_vec()]);
    cat(&[vec![0x11], pkg_len(inner.len()), inner])
}

fn device(n: &str, body: Vec<u8>) -> Vec<u8> {
    let inner = cat(&[seg(n), body]);
    cat(&[vec![0x5B, 0x82], pkg_len(inner.len()), inner])
}

fn string(s: &str) -> Vec<u8> {
    let mut v = vec![0x0D];
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}

fn eisa(id: &str) -> Vec<u8> {
    let b = id.as_bytes();
    let letter = |c: u8| (c - b'@') as u32;
    let hex = |c: u8| (c as char).to_digit(16).unwrap();
    let be: u32 = letter(b[0]) << 26 | letter(b[1]) << 21 | letter(b[2]) << 16 | hex(b[3]) << 12 | hex(b[4]) << 8 | hex(b[5]) << 4 | hex(b[6]);
    let mut v = vec![0x0C];
    v.extend_from_slice(&be.swap_bytes().to_le_bytes());
    v
}

fn scope_sb(body: Vec<u8>) -> Vec<u8> {
    let inner = cat(&[vec![0x5C], seg("_SB_"), body]);
    cat(&[vec![0x10], pkg_len(inner.len()), inner])
}

fn table(aml: Vec<u8>) -> Vec<u8> {
    let mut t = vec![0u8; 36];
    t.extend(aml);
    t
}

fn if_(predicate: Vec<u8>, body: Vec<u8>) -> Vec<u8> {
    cat(&[vec![0xA0], pkg_len(predicate.len() + body.len()), predicate, body])
}

/// The shape of every firmware `_DSM`: function 0 lists the functions, function 1 gives the
/// register, and the last `If` ends its block (the interpreter once failed on that).
///
/// ```text
/// Method (_DSM, 4) {
///     If (Arg0 == UUID) {
///         If (Arg2 == 0) { Return (Buffer {0x03}) }
///         If (Arg2 == 1) { Return (register) }
///     }
///     Return (Buffer {0})
/// }
/// ```
fn dsm(uuid: &[u8], register: u64) -> Vec<u8> {
    let f0 = if_(cat(&[vec![0x93, 0x6A], int(0)]), ret(buffer(&[3])));
    let f1 = if_(cat(&[vec![0x93, 0x6A], int(1)]), ret(int(register)));
    let outer = if_(cat(&[vec![0x93, 0x68], buffer(uuid)]), cat(&[f0, f1]));
    method("_DSM", 4, cat(&[outer, ret(buffer(&[0]))]))
}

fn crs(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = parts.concat();
    bytes.extend(build::end());
    name("_CRS", buffer(&bytes))
}

/// SSCN/FMCN: `Return (Package () {hcnt, lcnt, hold})`.
fn timing_method(n: &str, hcnt: u64, lcnt: u64, hold: u64) -> Vec<u8> {
    method(n, 0, ret(package(vec![int(hcnt), int(lcnt), int(hold)])))
}

/// An Intel-style PCI I2C controller (device 0x15, function 1) with a touchpad below it.
fn intel_controller(children: Vec<u8>) -> Vec<u8> {
    device(
        "PCI0",
        cat(&[
            name("_HID", eisa("PNP0A08")),
            name("_BBN", int(0)),
            device("I2C1", cat(&[name("_ADR", int(0x0015_0001)), timing_method("SSCN", 0x1D0, 0x1F7, 0x1E), timing_method("FMCN", 0x80, 0xA0, 0x1E), children])),
        ]),
    )
}

fn touchpad(n: &str, connection: Vec<u8>, extra: Vec<u8>, dsm_method: Vec<u8>) -> Vec<u8> {
    device(n, cat(&[name("_HID", string("ELAN0001")), name("_CID", string("PNP0C50")), crs(&[connection, extra]), dsm_method]))
}

fn run(tables: Vec<Vec<u8>>) -> (Vec<DeviceSpec>, Vec<String>) {
    let mut load_log = |s: &str| panic!("AML load problem: {s}");
    let mut ctx = load(Machine(AtomicU64::new(0)), &tables, &mut load_log);
    let mut lines = Vec::new();
    let specs = enumerate(&mut ctx, &mut |s| lines.push(s.to_string()));
    (specs, lines)
}

// ---- tests ------------------------------------------------------------------------------------

#[test]
fn intel_style_touchpad_is_described_completely() {
    let pad = touchpad(
        "TPD0",
        build::i2c_connection(0x15, 400_000, "\\_SB.PCI0.I2C1"),
        build::gpio_interrupt(0x42, "\\_SB.GPI0", false, true),
        dsm(&DSM_UUID, 0x0001),
    );
    let (specs, log) = run(vec![table(scope_sb(intel_controller(pad)))]);
    assert_eq!(specs.len(), 1, "{log:?}");
    let s = &specs[0];
    assert_eq!(s.address, 0x15);
    assert_eq!(s.speed_hz, 400_000);
    assert_eq!(s.descriptor_register, 1);
    assert_eq!(s.interrupt, Interrupt::Gpio { pin: 0x42, controller: "\\_SB.GPI0".into() });
    assert_eq!(s.controller.location, Location::Pci { bus: 0, device: 0x15, function: 1 });
    assert_eq!(
        s.controller.timing,
        Timing { standard: Some(SclTiming { hcnt: 0x1D0, lcnt: 0x1F7 }), fast: Some(SclTiming { hcnt: 0x80, lcnt: 0xA0 }), sda_hold: Some(0x1E) }
    );
    assert!(s.path.ends_with("TPD0"), "{}", s.path);
    assert!(s.controller.path.ends_with("I2C1"), "{}", s.controller.path);
    // What the kernel is sent survives the wire format.
    let blob = osyx_i2c::spec::encode(&specs).unwrap();
    assert_eq!(osyx_i2c::spec::decode(&blob).unwrap(), specs);
}

#[test]
fn amd_style_controller_with_a_memory_resource() {
    let controller = device(
        "I2CA",
        cat(&[
            name("_HID", string("AMDI0010")),
            name("_UID", int(0)),
            crs(&[build::memory32_fixed(0xFEDC_2000, 0x1000), build::interrupt(10)]),
            device(
                "TPNL",
                cat(&[name("_HID", string("ACPI0C50")), crs(&[build::i2c_connection(0x2C, 100_000, "\\_SB.I2CA"), build::interrupt(31)]), dsm(&DSM_UUID, 0x20)]),
            ),
        ]),
    );
    let (specs, log) = run(vec![table(scope_sb(controller))]);
    assert_eq!(specs.len(), 1, "{log:?}");
    let s = &specs[0];
    assert_eq!((s.address, s.speed_hz, s.descriptor_register), (0x2C, 100_000, 0x20));
    assert_eq!(s.interrupt, Interrupt::Gsi(31));
    assert_eq!(s.controller.location, Location::Mmio { base: 0xFEDC_2000, len: 0x1000 });
    assert_eq!(s.controller.hid, "AMDI0010");
    // No SSCN/FMCN: the kernel will use the controller's own values or refuse.
    assert_eq!(s.controller.timing, Timing::default());
}

#[test]
fn a_device_split_over_two_tables_is_found() {
    // The controller in the DSDT, the touchpad in an SSDT that extends it.
    let pad = touchpad("TPD0", build::i2c_connection(0x15, 400_000, "\\_SB.PCI0.I2C1"), vec![], dsm(&DSM_UUID, 0x01));
    let dsdt = table(scope_sb(intel_controller(vec![])));
    let ssdt = {
        // Scope (\_SB.PCI0.I2C1) { Device (TPD0) {...} }
        let body = cat(&[vec![0x5C, 0x2F, 0x03], seg("_SB_"), seg("PCI0"), seg("I2C1"), pad]);
        table(cat(&[vec![0x10], pkg_len(body.len()), body]))
    };
    let (specs, log) = run(vec![dsdt, ssdt]);
    assert_eq!(specs.len(), 1, "{log:?}");
}

fn skipped(pad: Vec<u8>, controller_wrapper: impl Fn(Vec<u8>) -> Vec<u8>, reason: &str) {
    let (specs, log) = run(vec![table(scope_sb(controller_wrapper(pad)))]);
    assert!(specs.is_empty(), "{specs:?}");
    assert!(log.iter().any(|l| l.contains("skipped") && l.contains(reason)), "wanted \"{reason}\" in {log:?}");
}

#[test]
fn devices_that_cannot_be_driven_are_left_out_with_a_reason() {
    let conn = || build::i2c_connection(0x15, 400_000, "\\_SB.PCI0.I2C1");
    // Wrong GUID: the _DSM answers a buffer, not the register.
    let other_uuid = [0u8; 16];
    skipped(touchpad("TPD0", conn(), vec![], dsm(&other_uuid, 1)), intel_controller, "_DSM did not return");
    // No _DSM at all.
    skipped(touchpad("TPD0", conn(), vec![], vec![]), intel_controller, "_DSM failed");
    // A register that does not fit 16 bits.
    skipped(touchpad("TPD0", conn(), vec![], dsm(&DSM_UUID, 0x1_0000)), intel_controller, "not a 16-bit register");
    // _STA says not present.
    let absent = device(
        "TPD0",
        cat(&[name("_HID", string("PNP0C50")), name("_STA", int(0)), crs(&[conn()]), dsm(&DSM_UUID, 1)]),
    );
    skipped(absent, intel_controller, "_STA is 0x0");
    // No I2C connection in _CRS.
    let nothing = device("TPD0", cat(&[name("_HID", string("PNP0C50")), crs(&[build::interrupt(5)]), dsm(&DSM_UUID, 1)]));
    skipped(nothing, intel_controller, "no I2C serial bus connection");
    // The connection names a controller that is not there.
    skipped(
        touchpad("TPD0", build::i2c_connection(0x15, 400_000, "\\_SB.PCI0.NOPE"), vec![], dsm(&DSM_UUID, 1)),
        intel_controller,
        "is not a device",
    );
    // Not an absolute path.
    skipped(touchpad("TPD0", build::i2c_connection(0x15, 400_000, "I2C1"), vec![], dsm(&DSM_UUID, 1)), intel_controller, "not absolute");
}

#[test]
fn controllers_the_kernel_cannot_locate_are_refused() {
    // A PCI function that is not directly below a host bridge: its bus is unknown.
    let pad = touchpad("TPD0", build::i2c_connection(0x15, 400_000, "\\_SB.BRG0.I2C1"), vec![], dsm(&DSM_UUID, 1));
    let behind_a_bridge = |pad: Vec<u8>| device("BRG0", cat(&[name("_HID", string("PNP0A08X")), device("I2C1", cat(&[name("_ADR", int(0x0015_0001)), pad]))]));
    skipped(pad, behind_a_bridge, "not directly below a PCI host bridge");
    // An ACPI controller of a kind the kernel has no driver for.
    let pad = touchpad("TPD0", build::i2c_connection(0x15, 400_000, "\\_SB.I2CB"), vec![], dsm(&DSM_UUID, 1));
    let unknown = |pad: Vec<u8>| device("I2CB", cat(&[name("_HID", string("XYZ0001")), crs(&[build::memory32_fixed(0xFED0_0000, 0x1000)]), pad]));
    skipped(pad, unknown, "neither a PCI function nor a known DesignWare");
    // A DesignWare ACPI controller without a memory resource.
    let pad = touchpad("TPD0", build::i2c_connection(0x15, 400_000, "\\_SB.I2CB"), vec![], dsm(&DSM_UUID, 1));
    let no_memory = |pad: Vec<u8>| device("I2CB", cat(&[name("_HID", string("AMDI0510")), crs(&[build::interrupt(3)]), pad]));
    skipped(pad, no_memory, "no memory resource");
}

#[test]
fn other_devices_are_ignored() {
    let (specs, log) = run(vec![table(scope_sb(device("BAT0", name("_HID", eisa("PNP0C0A")))))]);
    assert!(specs.is_empty());
    assert!(log.is_empty(), "{log:?}");
    // A machine with no namespace at all.
    let (specs, _) = run(vec![]);
    assert!(specs.is_empty());
}

#[test]
fn ten_bit_and_out_of_range_addresses_are_skipped() {
    let mut conn = build::i2c_connection(0x15, 400_000, "\\_SB.PCI0.I2C1");
    conn[8] = 1; // type specific flags: 10-bit addressing (offset 8 of the descriptor)
    skipped(touchpad("TPD0", conn, vec![], dsm(&DSM_UUID, 1)), intel_controller, "10-bit");
    skipped(touchpad("TPD0", build::i2c_connection(0x90, 400_000, "\\_SB.PCI0.I2C1"), vec![], dsm(&DSM_UUID, 1)), intel_controller, "not a 7-bit target address");
}
