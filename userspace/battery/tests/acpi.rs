//! The battery stack against a mock machine: an embedded controller that
//! speaks the ACPI protocol, and hand-assembled AML tables.

use osyx_abi::battery::State;
use osyx_battery::hw::{Firmware, Stats};
use osyx_battery::model::Monitor;
use osyx_battery::{Acpi, EcPorts, Hardware};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ---- the machine ------------------------------------------------------------------------------

struct EcState {
    regs: [u8; 256],
    /// 0 idle, 1 got READ, 2 got WRITE, 3 got WRITE address
    phase: u8,
    addr: u8,
    out: Option<u8>,
    /// The EC does not answer (IBF never clears).
    hung: bool,
    /// Make `n` reads fail at the handshake, then recover.
    fail_reads: u32,
}

#[derive(Clone)]
struct Machine {
    ec: Arc<Mutex<EcState>>,
    clock: Arc<AtomicU64>,
}

impl Machine {
    fn new() -> Machine {
        let ec = EcState { regs: [0; 256], phase: 0, addr: 0, out: None, hung: false, fail_reads: 0 };
        Machine { ec: Arc::new(Mutex::new(ec)), clock: Arc::new(AtomicU64::new(0)) }
    }

    fn set(&self, addr: usize, bytes: &[u8]) {
        self.ec.lock().unwrap().regs[addr..addr + bytes.len()].copy_from_slice(bytes);
    }
}

impl Hardware for Machine {
    fn port_in(&self, port: u16, _width: u8) -> u64 {
        let mut ec = self.ec.lock().unwrap();
        match port {
            0x66 => {
                let mut s = 0u64;
                if ec.out.is_some() {
                    s |= 1;
                }
                if ec.hung {
                    s |= 2;
                }
                s
            }
            0x62 => ec.out.take().map_or(0xFF, |v| v as u64),
            _ => u64::MAX,
        }
    }

    fn port_out(&self, port: u16, _width: u8, value: u64) {
        let mut ec = self.ec.lock().unwrap();
        if ec.hung {
            return;
        }
        match (port, ec.phase) {
            (0x66, _) => {
                ec.phase = match value {
                    0x80 => 1,
                    0x81 => 2,
                    _ => 0,
                }
            }
            (0x62, 1) => {
                if ec.fail_reads > 0 {
                    ec.fail_reads -= 1;
                    // The reply never comes.
                } else {
                    let a = value as usize & 0xFF;
                    ec.out = Some(ec.regs[a]);
                }
                ec.phase = 0;
            }
            (0x62, 2) => {
                ec.addr = value as u8;
                ec.phase = 3;
            }
            (0x62, 3) => {
                let a = ec.addr as usize;
                ec.regs[a] = value as u8;
                ec.phase = 0;
            }
            _ => {}
        }
    }

    fn phys_read(&self, _: u64, _: u8) -> u64 {
        u64::MAX
    }
    fn phys_write(&self, _: u64, _: u8, _: u64) {}
    fn pci_read(&self, _: u64, _: u64, _: u8) -> u64 {
        u64::MAX
    }
    fn pci_write(&self, _: u64, _: u64, _: u8, _: u64) {}

    fn now_ms(&self) -> u64 {
        // Every look at the clock is a millisecond: time-outs come quickly.
        self.clock.fetch_add(1, Ordering::Relaxed)
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

fn method(n: &str, body: Vec<u8>) -> Vec<u8> {
    let inner = cat(&[seg(n), vec![0x00], body]);
    cat(&[vec![0x14], pkg_len(inner.len()), inner])
}

fn package(items: Vec<Vec<u8>>) -> Vec<u8> {
    let n = items.len() as u8;
    let inner = cat(&[vec![n], items.concat()]);
    cat(&[vec![0x12], pkg_len(inner.len()), inner])
}

fn ints(values: &[u64]) -> Vec<Vec<u8>> {
    values.iter().map(|&v| int(v)).collect()
}

fn device(n: &str, body: Vec<u8>) -> Vec<u8> {
    let inner = cat(&[seg(n), body]);
    cat(&[vec![0x5B, 0x82], pkg_len(inner.len()), inner])
}

/// `EisaId("PNP0C0A")` and friends.
fn eisa(id: &str) -> Vec<u8> {
    let b = id.as_bytes();
    let letter = |c: u8| (c - b'@') as u32;
    let hex = |c: u8| (c as char).to_digit(16).unwrap();
    let be: u32 = letter(b[0]) << 26 | letter(b[1]) << 21 | letter(b[2]) << 16 | hex(b[3]) << 12 | hex(b[4]) << 8 | hex(b[5]) << 4 | hex(b[6]);
    let mut v = vec![0x0C];
    v.extend_from_slice(&be.swap_bytes().to_le_bytes());
    v
}

fn string(s: &str) -> Vec<u8> {
    let mut v = vec![0x0D];
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}

fn scope_sb(body: Vec<u8>) -> Vec<u8> {
    let inner = cat(&[vec![0x5C], seg("_SB_"), body]);
    cat(&[vec![0x10], pkg_len(inner.len()), inner])
}

/// A table: 36 header bytes (never looked at) and the AML.
fn table(aml: Vec<u8>) -> Vec<u8> {
    let mut t = vec![0u8; 36];
    t.extend(aml);
    t
}

/// A battery with constant `_BIF` and `_BST`.
fn battery(n: &str, status: Option<u64>, bif: &[u64], bst: &[u64]) -> Vec<u8> {
    device(
        n,
        cat(&[
            name("_HID", eisa("PNP0C0A")),
            status.map_or(vec![], |s| method("_STA", ret(int(s)))),
            method("_BIF", ret(package(ints(bif)))),
            method("_BST", ret(package(ints(bst)))),
        ]),
    )
}

fn adapter(online: u64) -> Vec<u8> {
    device("AC__", cat(&[name("_HID", string("ACPI0003")), method("_PSR", ret(int(online)))]))
}

fn load(m: &Machine, tables: Vec<Vec<u8>>) -> Acpi {
    let mut log = |s: &str| panic!("AML load problem: {s}");
    Acpi::load(m.clone(), Some(EcPorts::LEGACY), &tables, &mut log)
}

// ---- tests ------------------------------------------------------------------------------------

#[test]
fn constant_battery_and_adapter() {
    let m = Machine::new();
    // _BIF: unit mWh, design 50000, last full 45000, technology, design voltage 11400.
    let bif = [0, 50_000, 45_000, 1, 11_400, 0, 0, 0, 0];
    // _BST: discharging, 9000 mW, 22500 mWh, 11000 mV.
    let bst = [1, 9_000, 22_500, 11_000];
    let t = table(scope_sb(cat(&[battery("BAT0", Some(0x1F), &bif, &bst), adapter(0)])));
    let mut acpi = load(&m, vec![t]);
    assert_eq!((acpi.battery_devices(), acpi.adapter_devices()), (1, 1));
    let poll = acpi.poll();
    assert_eq!((poll.batteries.len(), poll.ac, poll.ec_errors), (1, Some(false), 0));
    let st = Monitor::new().update(&poll);
    assert_eq!((st.state, st.percent, st.ac), (State::Discharging, 50, false));
    assert_eq!(st.minutes_to_empty, Some(150));
    assert_eq!(st.capacity_mwh, Some(45_000));
    assert_eq!(st.design_mwh, Some(50_000));
    assert_eq!(st.health_percent(), Some(90));
}

#[test]
fn bix_with_amp_hours_and_two_batteries() {
    let m = Machine::new();
    // _BIX: revision, unit mAh, design 4000, last full 3800, technology, cycles?, design voltage...
    // (fields at 1: unit, 2: design capacity, 3: last full, 4: technology, 5: design voltage).
    let bix = |n: &str, remaining: u64| {
        device(
            n,
            cat(&[
                name("_HID", eisa("PNP0C0A")),
                method("_STA", ret(int(0x1F))),
                method("_BIX", ret(package(ints(&[0, 1, 4_000, 3_800, 1, 11_400, 0, 0, 0, 0])))),
                method("_BST", ret(package(ints(&[2, 1_000, remaining, 11_500])))),
            ]),
        )
    };
    let t = table(scope_sb(cat(&[bix("BAT0", 1_900), bix("BAT1", 3_800), adapter(1)])));
    let mut acpi = load(&m, vec![t]);
    let poll = acpi.poll();
    assert_eq!(poll.batteries.len(), 2);
    let st = Monitor::new().update(&poll);
    assert_eq!(st.batteries, 2);
    assert_eq!(st.state, State::Charging);
    assert_eq!(st.percent, 75, "(1900 + 3800) of 7600 mAh");
    assert!(st.ac);
    // 1900 mAh at 11.5 V = 21850 mWh remaining of 87400 mWh, charging at 2 * 11.5 W.
    assert_eq!(st.capacity_mwh, Some(87_400));
    assert_eq!(st.energy_mwh, Some(65_550));
    assert_eq!(st.rate_mw, Some(23_000));
    assert_eq!(st.minutes_to_full, Some(57));
}

#[test]
fn missing_battery_and_hotplug() {
    let m = Machine::new();
    // _STA without the "battery present" bit.
    let t = table(scope_sb(battery("BAT0", Some(0x0F), &[0, 50_000, 45_000, 1, 11_400], &[1, 9_000, 22_500, 11_000])));
    let mut acpi = load(&m, vec![t]);
    let poll = acpi.poll();
    assert_eq!((poll.batteries.len(), poll.devices), (0, 1));
    assert_eq!(Monitor::new().update(&poll), osyx_abi::battery::Status::NONE);
}

#[test]
fn unknown_values_are_not_taken_literally() {
    let m = Machine::new();
    // Rate and voltage unknown (0xFFFFFFFF); last full capacity unknown: use design.
    let bif = [0, 50_000, 0xFFFF_FFFF, 1, 11_400];
    let bst = [1, 0xFFFF_FFFF, 25_000, 0xFFFF_FFFF];
    let t = table(scope_sb(battery("BAT0", None, &bif, &bst)));
    let mut acpi = load(&m, vec![t]);
    let st = Monitor::new().update(&acpi.poll());
    assert_eq!((st.state, st.percent), (State::Discharging, 50));
    assert_eq!((st.rate_mw, st.minutes_to_empty), (None, None));
}

/// `Store(field, Index(PBST, i))`.
fn store_index(field: &str, i: u64) -> Vec<u8> {
    // The field lives in the EC's scope: \_SB_.EC__.<field>.
    let full = cat(&[vec![0x5C, 0x2F, 3], seg("_SB_"), seg("EC__"), seg(field)]);
    cat(&[vec![0x70], full, vec![0x88], seg("PBST"), int(i), vec![0x00]])
}

/// A battery whose `_BST` reads the embedded controller.
fn ec_battery() -> Vec<u8> {
    let region = cat(&[vec![0x5B, 0x80], seg("ECOR"), vec![0x03], int(0), int(0x100)]);
    let field_body = cat(&[seg("ECOR"), vec![0x01], seg("B0ST"), vec![8], seg("RATE"), vec![16], seg("REMN"), vec![16], seg("VOLT"), vec![16]]);
    let field = cat(&[vec![0x5B, 0x81], pkg_len(field_body.len()), field_body]);
    let ec = device("EC__", cat(&[name("_HID", eisa("PNP0C09")), region, field]));
    let bat = device(
        "BAT0",
        cat(&[
            name("_HID", eisa("PNP0C0A")),
            method("_STA", ret(int(0x1F))),
            method("_BIF", ret(package(ints(&[0, 50_000, 45_000, 1, 11_400])))),
            name("PBST", package(ints(&[0, 0, 0, 0]))),
            method("_BST", cat(&[
                store_index("B0ST", 0),
                store_index("RATE", 1),
                store_index("REMN", 2),
                store_index("VOLT", 3),
                ret(seg("PBST")),
            ])),
        ]),
    );
    table(scope_sb(cat(&[ec, bat])))
}

fn set_bst(m: &Machine, state: u8, rate: u16, remaining: u16, volt: u16) {
    m.set(0, &[state]);
    m.set(1, &rate.to_le_bytes());
    m.set(3, &remaining.to_le_bytes());
    m.set(5, &volt.to_le_bytes());
}

#[test]
fn readings_through_the_embedded_controller() {
    let m = Machine::new();
    set_bst(&m, 1, 9_000, 22_500, 11_000);
    let mut acpi = load(&m, vec![ec_battery()]);
    let mut monitor = Monitor::new();
    let poll = acpi.poll();
    assert_eq!(poll.ec_errors, 0);
    let st = monitor.update(&poll);
    assert_eq!((st.state, st.percent, st.minutes_to_empty), (State::Discharging, 50, Some(150)));
    assert!(acpi.stats().ec_transactions.load(Ordering::Relaxed) > 0, "the values came from the EC");

    // The EC hangs: the zeros AML reads must not become "0 %".
    m.ec.lock().unwrap().hung = true;
    let poll = acpi.poll();
    assert!(poll.ec_errors > 0);
    let st = monitor.update(&poll);
    assert_eq!((st.percent, st.stale, st.state), (50, true, State::Discharging));

    // It comes back (and the leftover state is cleaned up).
    {
        let mut ec = m.ec.lock().unwrap();
        ec.hung = false;
        ec.phase = 0;
        ec.out = Some(0x55);
    }
    set_bst(&m, 1, 9_000, 20_250, 11_000);
    let mut st = monitor.update(&acpi.poll());
    if st.stale {
        // The first poll after an outage may still hit the stale byte.
        st = monitor.update(&acpi.poll());
    }
    assert_eq!((st.percent, st.stale), (45, false));
}

#[test]
fn a_single_failed_transaction_is_noticed_and_retried() {
    let m = Machine::new();
    set_bst(&m, 2, 15_000, 11_250, 11_000);
    let mut acpi = load(&m, vec![ec_battery()]);
    let mut monitor = Monitor::new();
    assert_eq!(monitor.update(&acpi.poll()).percent, 25);
    m.ec.lock().unwrap().fail_reads = 1;
    let poll = acpi.poll();
    assert_eq!(poll.ec_errors, 1);
    let st = monitor.update(&poll);
    assert!(st.stale && st.percent == 25);
    let st = monitor.update(&acpi.poll());
    assert!(!st.stale);
    assert_eq!((st.state, st.percent), (State::Charging, 25));
}

#[test]
fn ec_protocol_basics() {
    let m = Machine::new();
    m.set(0x10, &[0xAB]);
    let stats = Arc::new(Stats::default());
    let fw = Firmware::new(m.clone(), Some(EcPorts::LEGACY), stats.clone());
    assert_eq!(fw.ec_read(0x10), Some(0xAB));
    assert!(fw.ec_write(0x11, 0x42));
    assert_eq!(m.ec.lock().unwrap().regs[0x11], 0x42);
    assert_eq!(stats.errors(), 0);
    // A hung EC times out instead of spinning forever.
    m.ec.lock().unwrap().hung = true;
    assert_eq!(fw.ec_read(0x10), None);
    assert!(!fw.ec_write(0x11, 1));
    assert_eq!(stats.errors(), 2);
    // No EC at all.
    let none = Firmware::new(m, None, Arc::new(Stats::default()));
    assert_eq!(none.ec_read(0), None);
}

#[test]
fn ecdt_ports() {
    let mut t = vec![0u8; 80];
    t[44 + 4..44 + 6].copy_from_slice(&0x1604u16.to_le_bytes());
    t[56 + 4..56 + 6].copy_from_slice(&0x1600u16.to_le_bytes());
    assert_eq!(EcPorts::from_ecdt(Some(&t)), EcPorts { command: 0x1604, data: 0x1600 });
    assert_eq!(EcPorts::from_ecdt(Some(&vec![0u8; 80])), EcPorts::LEGACY);
    assert_eq!(EcPorts::from_ecdt(Some(&[0u8; 10])), EcPorts::LEGACY);
    assert_eq!(EcPorts::from_ecdt(None), EcPorts::LEGACY);
}



/// `_BST` as real firmware writes it: arithmetic in locals, then a package
/// of locals.
#[test]
fn firmware_arithmetic_and_packages_of_locals() {
    let m = Machine::new();
    let store = |expr: Vec<u8>, local: u8| cat(&[vec![0x70], expr, vec![local]]);
    let body = cat(&[
        // Local0 = 100 * 10; Local1 = Local0 - 1; Divide(Local0, 10, Local2, Local3)
        store(cat(&[vec![0x77], int(100), int(10), vec![0x00]]), 0x60),
        store(cat(&[vec![0x74, 0x60], int(1), vec![0x00]]), 0x61),
        cat(&[vec![0x78, 0x60], int(10), vec![0x62, 0x63]]),
        // Local4 = Or(Local2, 2): the state "charging" (the remainder is 0).
        store(cat(&[vec![0x7D, 0x62], int(2), vec![0x00]]), 0x64),
        ret(cat(&[vec![0x12], pkg_len(5), vec![4], vec![0x64, 0x60, 0x61, 0x63]])),
    ]);
    let dev = device(
        "BAT0",
        cat(&[
            name("_HID", eisa("PNP0C0A")),
            method("_BIF", ret(package(ints(&[0, 1_000, 1_000, 1, 11_400])))),
            method("_BST", body),
        ]),
    );
    let mut acpi = load(&m, vec![table(scope_sb(dev))]);
    let p = acpi.poll();
    let s = p.batteries[0].expect("the method ran");
    assert_eq!((s.charging, s.rate, s.remaining, s.voltage), (true, Some(1000), Some(999), Some(100)));
}

/// `Store(x, Index(PKG, i))` into a package that lives in a local.
#[test]
fn index_store_into_a_local_package() {
    let m = Machine::new();
    let store_into = |i: u64, v: u64| cat(&[vec![0x70], int(v), vec![0x88, 0x60], int(i), vec![0x00]]);
    let body = cat(&[
        cat(&[vec![0x70], package(ints(&[0, 0, 0, 0])), vec![0x60]]),
        store_into(0, 1),
        store_into(1, 500),
        store_into(2, 250),
        store_into(3, 12_000),
        // DerefOf(Index(Local0, 2)) read back.
        cat(&[vec![0x70, 0x83, 0x88, 0x60], int(2), vec![0x00], vec![0x61]]),
        ret(vec![0x60]),
    ]);
    let dev = device(
        "BAT0",
        cat(&[
            name("_HID", eisa("PNP0C0A")),
            method("_BIF", ret(package(ints(&[0, 1_000, 1_000, 1, 11_400])))),
            method("_BST", body),
        ]),
    );
    let mut acpi = load(&m, vec![table(scope_sb(dev))]);
    let s = acpi.poll().batteries[0].expect("the method ran");
    assert_eq!((s.discharging, s.rate, s.remaining, s.voltage), (true, Some(500), Some(250), Some(12_000)));
}
