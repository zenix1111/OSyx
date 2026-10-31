//! The DesignWare driver, the HID over I2C protocol and the report decoder
//! against the register-level simulation in `osyx_i2c::sim`.

use osyx_i2c::bus::{I2cBus, I2cError};
use osyx_i2c::designware::{BusSpeed, ConfigError, DesignWare, ProbeError, SclTiming, Timing, TimingSource};
use osyx_i2c::hid::{HidError, I2cHid, Poll};
use osyx_i2c::report::{Action, DecodeError, DeviceClass, ReportDecoder};
use osyx_i2c::sim::{IdleMode, SimClock, SimHid, SimMmio, Target};
use osyx_usb::hid::ReportError;

// ---- report descriptors -----------------------------------------------------------------------

const BOOT_KEYBOARD: &[u8] = &[
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75,
    0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06, 0x75, 0x08,
    0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xC0,
];

const BOOT_MOUSE: &[u8] = &[
    0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x01, 0xA1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81,
    0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x03, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06,
    0xC0, 0xC0,
];

/// `descriptor` with a report id after the first Collection (Application).
fn with_report_id(descriptor: &[u8], id: u8) -> Vec<u8> {
    let at = descriptor.windows(2).position(|w| w == [0xA1, 0x01]).unwrap() + 2;
    let mut d = descriptor[..at].to_vec();
    d.extend([0x85, id]);
    d.extend(&descriptor[at..]);
    d
}

/// A precision touchpad's PTP collection (report id 4): `fingers` contacts of
/// [confidence, tip, 2 bits padding, 4 bits id, X 16 bits, Y 16 bits], scan
/// time (16), contact count (8), button 1 (+7 bits padding). The pad is
/// 160 x 80 mm with 4096 x 4096 units.
fn ptp(fingers: usize) -> Vec<u8> {
    let mut d = vec![0x05, 0x0D, 0x09, 0x05, 0xA1, 0x01, 0x85, 0x04];
    for _ in 0..fingers {
        d.extend([
            0x05, 0x0D, 0x09, 0x22, 0xA1, 0x02, 0x15, 0x00, 0x25, 0x01, 0x09, 0x47, 0x09, 0x42, 0x75, 0x01, 0x95, 0x02, 0x81, 0x02, 0x95, 0x02, 0x81, 0x03, 0x75,
            0x04, 0x95, 0x01, 0x25, 0x0F, 0x09, 0x51, 0x81, 0x02, 0x05, 0x01, 0x15, 0x00, 0x26, 0xFF, 0x0F, 0x75, 0x10, 0x55, 0x0E, 0x65, 0x11, 0x09, 0x30,
            0x35, 0x00, 0x46, 0x40, 0x06, 0x95, 0x01, 0x81, 0x02, 0x46, 0x20, 0x03, 0x09, 0x31, 0x81, 0x02, 0xC0,
        ]);
    }
    d.extend([
        0x05, 0x0D, 0x55, 0x0C, 0x66, 0x01, 0x10, 0x15, 0x00, 0x27, 0xFF, 0xFF, 0x00, 0x00, 0x75, 0x10, 0x95, 0x01, 0x09, 0x56, 0x81, 0x02, 0x09, 0x54, 0x25,
        0x7F, 0x75, 0x08, 0x81, 0x02, 0x05, 0x09, 0x09, 0x01, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02, 0x95, 0x07, 0x81, 0x03, 0xC0,
    ]);
    d
}

fn put(buf: &mut [u8], offset: usize, size: usize, value: u32) {
    for i in 0..size {
        if value & (1 << i) != 0 {
            buf[(offset + i) / 8] |= 1 << ((offset + i) % 8);
        }
    }
}

/// A PTP report for `fingers.len()` contacts: (tip, id, x, y) each.
fn ptp_report(fingers: &[(bool, u32, u32, u32)], count: u32, button: bool) -> Vec<u8> {
    let bits = fingers.len() * 40 + 16 + 8 + 8;
    let mut r = vec![0u8; 1 + bits / 8];
    r[0] = 4;
    let data = &mut r[1..];
    for (n, &(tip, id, x, y)) in fingers.iter().enumerate() {
        let base = n * 40;
        put(data, base, 1, 1); // confident
        put(data, base + 1, 1, tip as u32);
        put(data, base + 4, 4, id);
        put(data, base + 8, 16, x);
        put(data, base + 24, 16, y);
    }
    let after = fingers.len() * 40;
    put(data, after, 16, 1234);
    put(data, after + 16, 8, count);
    put(data, after + 24, 1, button as u32);
    r
}

// ---- helpers ----------------------------------------------------------------------------------

fn controller(tx: u32, rx: u32) -> (SimMmio, DesignWare<SimMmio, SimClock>, SimClock) {
    let mmio = SimMmio::new(tx, rx);
    let clock = SimClock::new();
    let dw = DesignWare::probe(mmio.clone(), clock.clone()).expect("probe");
    (mmio, dw, clock)
}

fn configured(tx: u32, rx: u32) -> (SimMmio, DesignWare<SimMmio, SimClock>, SimClock) {
    let (mmio, mut dw, clock) = controller(tx, rx);
    dw.configure(BusSpeed::Fast, &Timing::default()).expect("configure");
    (mmio, dw, clock)
}

/// A bus device that stores what it is written and sends it back.
struct Echo {
    address: u8,
    data: Vec<u8>,
    pos: usize,
    nack_data_after: Option<usize>,
}

impl Target for Echo {
    fn address(&self) -> u8 {
        self.address
    }
    fn start(&mut self, read: bool) -> bool {
        if read {
            self.pos = 0;
        } else {
            self.data.clear();
        }
        true
    }
    fn write(&mut self, byte: u8) -> bool {
        if self.nack_data_after.is_some_and(|n| self.data.len() >= n) {
            return false;
        }
        self.data.push(byte);
        true
    }
    fn read(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0xEE);
        self.pos += 1;
        b
    }
    fn stop(&mut self) {}
}

fn echo(address: u8) -> Echo {
    Echo { address, data: Vec::new(), pos: 0, nack_data_after: None }
}

// ---- DesignWare -------------------------------------------------------------------------------

#[test]
fn probe_checks_signature_and_fifo_parameters() {
    let mmio = SimMmio::new(16, 16);
    mmio.with(|m| m.comp_type = 0x1234_5678);
    assert_eq!(DesignWare::probe(mmio.clone(), SimClock::new()).err(), Some(ProbeError::NotDesignWare(0x1234_5678)));
    mmio.with(|m| m.comp_type = 0xFFFF_FFFF);
    assert_eq!(DesignWare::probe(mmio.clone(), SimClock::new()).err(), Some(ProbeError::NotDesignWare(0xFFFF_FFFF)));
    mmio.with(|m| {
        m.comp_type = osyx_i2c::designware::COMP_TYPE_MAGIC;
        m.comp_param = Some(0);
    });
    assert_eq!(DesignWare::probe(mmio.clone(), SimClock::new()).err(), Some(ProbeError::FifoUnknown(0)));
    mmio.with(|m| m.comp_param = None);
    let dw = DesignWare::probe(mmio.clone(), SimClock::new()).unwrap();
    assert_eq!(dw.fifo_depths(), (16, 16));
    assert_eq!(dw.version(), 0x3230_312A);
    // A controller that will not switch off is refused, not waited for.
    mmio.with(|m| m.stuck_enabled = true);
    assert_eq!(DesignWare::probe(mmio, SimClock::new()).err(), Some(ProbeError::Stuck));
}

#[test]
fn firmware_timing_is_programmed_for_the_chosen_speed() {
    let (mmio, mut dw, _) = controller(16, 16);
    let timing = Timing {
        standard: Some(SclTiming { hcnt: 0x1D0, lcnt: 0x1F7 }),
        fast: Some(SclTiming { hcnt: 0x80, lcnt: 0xA0 }),
        sda_hold: Some(0x1E),
    };
    assert_eq!(dw.configure(BusSpeed::Fast, &timing), Ok(TimingSource::Firmware));
    mmio.with(|m| {
        assert_eq!((m.fs_hcnt, m.fs_lcnt), (0x80, 0xA0));
        // The other speed's registers are not touched.
        assert_eq!((m.ss_hcnt, m.ss_lcnt), (0x190, 0x1D6));
        assert_eq!(m.sda_hold, 0x1E);
        assert_eq!(m.con & 0b110, 0b100, "fast mode");
        assert_eq!(m.con & 1, 1, "master");
        assert!(m.violations.is_empty(), "{:?}", m.violations);
    });
    assert_eq!(dw.configure(BusSpeed::Standard, &timing), Ok(TimingSource::Firmware));
    mmio.with(|m| {
        assert_eq!((m.ss_hcnt, m.ss_lcnt), (0x1D0, 0x1F7));
        assert_eq!(m.con & 0b110, 0b010, "standard mode");
    });
}

#[test]
fn controller_defaults_are_used_only_if_plausible() {
    let (mmio, mut dw, _) = controller(16, 16);
    assert_eq!(dw.configure(BusSpeed::Fast, &Timing::default()), Ok(TimingSource::ControllerDefault));
    // Firmware counts below the databook minimum are ignored, the defaults stay.
    let bad = Timing { fast: Some(SclTiming { hcnt: 2, lcnt: 3 }), ..Timing::default() };
    assert_eq!(dw.configure(BusSpeed::Fast, &bad), Ok(TimingSource::ControllerDefault));
    mmio.with(|m| assert_eq!((m.fs_hcnt, m.fs_lcnt), (0x64, 0x96)));
    // Nothing usable anywhere: refuse instead of guessing a clock.
    mmio.with(|m| m.fs_hcnt = 0);
    assert_eq!(dw.configure(BusSpeed::Fast, &bad), Err(ConfigError::NoTiming));
    assert_eq!(dw.configure(BusSpeed::Fast, &Timing::default()), Err(ConfigError::NoTiming));
}

#[test]
fn speed_follows_the_firmware_connection_speed() {
    assert_eq!(BusSpeed::from_hz(0), BusSpeed::Standard);
    assert_eq!(BusSpeed::from_hz(100_000), BusSpeed::Standard);
    assert_eq!(BusSpeed::from_hz(400_000), BusSpeed::Fast);
    assert_eq!(BusSpeed::from_hz(1_000_000), BusSpeed::Fast);
}

#[test]
fn transfer_requires_configuration_and_sane_arguments() {
    let (mmio, mut dw, _) = controller(16, 16);
    mmio.attach(echo(0x10));
    assert_eq!(dw.transfer(0x10, &[1], &mut []), Err(I2cError::Controller));
    dw.configure(BusSpeed::Fast, &Timing::default()).unwrap();
    assert_eq!(dw.transfer(0x10, &[], &mut []), Err(I2cError::InvalidLength));
    assert_eq!(dw.transfer(0x80, &[1], &mut []), Err(I2cError::InvalidLength));
    assert_eq!(dw.transfer(0x10, &vec![0; 8193], &mut []), Err(I2cError::InvalidLength));
}

#[test]
fn write_then_read_returns_the_data() {
    let (mmio, mut dw, _) = configured(16, 16);
    mmio.attach(echo(0x10));
    let mut back = [0u8; 4];
    dw.transfer(0x10, &[1, 2, 3, 4], &mut []).unwrap();
    dw.transfer(0x10, &[], &mut back).unwrap();
    assert_eq!(back, [1, 2, 3, 4]);
    // Write, restart, read in one transfer: the echo target restarts its position.
    let mut again = [0u8; 2];
    dw.transfer(0x10, &[9, 8], &mut again).unwrap();
    assert_eq!(again, [9, 8]);
    mmio.with(|m| {
        assert!(m.violations.is_empty(), "{:?}", m.violations);
        assert_eq!(m.completed_transfers, 3);
    });
}

#[test]
fn long_transfers_respect_the_fifo_depths() {
    // Shallow FIFOs: 100 bytes in each direction must be fed in pieces, and
    // reads must never run ahead of the receive FIFO.
    let (mmio, mut dw, _) = configured(4, 4);
    mmio.attach(echo(0x10));
    let data: Vec<u8> = (0..100).collect();
    let mut back = vec![0u8; 100];
    dw.transfer(0x10, &data, &mut back).unwrap();
    assert_eq!(back, data);
    mmio.with(|m| assert!(m.violations.is_empty(), "{:?}", m.violations));
}

#[test]
fn absent_address_is_a_nack_and_the_controller_recovers() {
    let (mmio, mut dw, _) = configured(16, 16);
    mmio.attach(echo(0x10));
    assert_eq!(dw.transfer(0x2C, &[0, 1], &mut []), Err(I2cError::Nack));
    let mut b = [0u8; 1];
    assert_eq!(dw.transfer(0x2C, &[], &mut b), Err(I2cError::Nack));
    // A data NACK is also a NACK.
    mmio.attach(Echo { nack_data_after: Some(1), ..echo(0x11) });
    assert_eq!(dw.transfer(0x11, &[1, 2, 3], &mut []), Err(I2cError::Nack));
    // The abort did not leave the controller stuck.
    dw.transfer(0x10, &[5], &mut []).unwrap();
    dw.transfer(0x10, &[], &mut b).unwrap();
    assert_eq!(b, [5]);
    mmio.with(|m| assert!(m.violations.is_empty(), "{:?}", m.violations));
}

#[test]
fn a_stuck_bus_times_out_in_bounded_time() {
    let (mmio, mut dw, clock) = configured(16, 16);
    mmio.attach(echo(0x10));
    mmio.with(|m| m.stuck_bus = true);
    use osyx_i2c::bus::Clock;
    let start = clock.now_us();
    assert_eq!(dw.transfer(0x10, &[1], &mut []), Err(I2cError::Timeout));
    let spent = clock.now_us() - start;
    assert!(spent < 300_000, "took {spent} us of virtual time");
    // Once the bus frees up, the controller works again.
    mmio.with(|m| m.stuck_bus = false);
    dw.transfer(0x10, &[1], &mut []).unwrap();
}

#[test]
fn a_controller_that_will_not_switch_off_is_an_error() {
    let (mmio, mut dw, _) = configured(16, 16);
    mmio.attach(echo(0x10));
    mmio.with(|m| m.stuck_enabled = true);
    assert_eq!(dw.transfer(0x10, &[1], &mut []), Err(I2cError::Controller));
}

// ---- HID over I2C -----------------------------------------------------------------------------

fn hid_stack(report_descriptor: &[u8]) -> (SimMmio, SimHid, DesignWare<SimMmio, SimClock>, SimClock) {
    let (mmio, dw, clock) = configured(16, 16);
    let hid = SimHid::new(0x2C, 0x0020, report_descriptor);
    mmio.attach(hid.clone());
    (mmio, hid, dw, clock)
}

#[test]
fn open_reads_descriptors_powers_on_and_resets() {
    let (mmio, hid, dw, clock) = hid_stack(BOOT_MOUSE);
    hid.with(|h| h.reset_delay_reads = 3);
    let dev = I2cHid::open(dw, &clock, 0x2C, 0x0020).unwrap();
    assert_eq!(dev.report_descriptor(), BOOT_MOUSE);
    let d = dev.descriptor();
    assert_eq!((d.vendor_id, d.product_id), (0x1234, 0x5678));
    assert_eq!(d.report_descriptor_length as usize, BOOT_MOUSE.len());
    assert!(dev.is_powered());
    hid.with(|h| {
        assert_eq!(h.resets, 1);
        assert!(h.powered);
    });
    mmio.with(|m| assert!(m.violations.is_empty(), "{:?}", m.violations));
}

#[test]
fn open_fails_cleanly_on_a_bad_device() {
    // Nothing at the address.
    let (_, _, dw, clock) = hid_stack(BOOT_MOUSE);
    assert_eq!(I2cHid::open(dw, &clock, 0x50, 0x0020).err(), Some(HidError::Bus(I2cError::Nack)));
    // Wrong descriptor register: the device does not answer it.
    let (_, _, dw, clock) = hid_stack(BOOT_MOUSE);
    assert_eq!(I2cHid::open(dw, &clock, 0x2C, 0x0099).err(), Some(HidError::Bus(I2cError::Nack)));
    // A descriptor of another version.
    let (_, hid, dw, clock) = hid_stack(BOOT_MOUSE);
    hid.with(|h| h.bad_version = true);
    assert_eq!(I2cHid::open(dw, &clock, 0x2C, 0x0020).err(), Some(HidError::UnsupportedVersion(0x0200)));
    // No reset response: gives up after the time-out, in bounded time.
    let (_, hid, dw, clock) = hid_stack(BOOT_MOUSE);
    hid.with(|h| h.no_reset_response = true);
    assert_eq!(I2cHid::open(dw, &clock, 0x2C, 0x0020).err(), Some(HidError::NoResetResponse));
}

fn open(report_descriptor: &[u8]) -> (SimHid, I2cHid<DesignWare<SimMmio, SimClock>>, SimClock) {
    let (_, hid, dw, clock) = hid_stack(report_descriptor);
    let dev = I2cHid::open(dw, &clock, 0x2C, 0x0020).unwrap();
    (hid, dev, clock)
}

#[test]
fn input_reports_are_read_in_order_and_idle_is_idle() {
    let (hid, mut dev, _) = open(BOOT_MOUSE);
    assert_eq!(dev.poll_input().unwrap(), Poll::Idle);
    hid.push_report(&[1, 5, 0xFB]);
    hid.push_report(&[0, 0, 0]);
    assert_eq!(dev.poll_input().unwrap(), Poll::Report(&[1, 5, 0xFB]));
    assert_eq!(dev.poll_input().unwrap(), Poll::Report(&[0, 0, 0]));
    assert_eq!(dev.poll_input().unwrap(), Poll::Idle);
    // A device that NACKs when it has nothing is idle too.
    hid.with(|h| h.idle = IdleMode::Nack);
    assert_eq!(dev.poll_input().unwrap(), Poll::Idle);
}

#[test]
fn impossible_lengths_are_errors_not_reports() {
    let (hid, mut dev, _) = open(BOOT_MOUSE);
    // The device announces a report longer than its maximum input length
    // (64): 70 bytes of data plus the length field.
    hid.push_report(&[0u8; 70]);
    assert!(matches!(dev.poll_input(), Err(HidError::BadReportLength(72))));
    // And the bus keeps working afterwards.
    assert_eq!(dev.poll_input().unwrap(), Poll::Idle);
}

#[test]
fn poll_verification_refuses_a_device_that_repeats_reports() {
    let (hid, mut dev, clock) = open(BOOT_MOUSE);
    assert_eq!(dev.verify_idle_signal(&clock, 8), Ok(()));
    hid.push_report(&[1, 2, 3]);
    assert_eq!(dev.poll_input().unwrap(), Poll::Report(&[1, 2, 3]));
    hid.with(|h| h.idle = IdleMode::RepeatLast);
    assert_eq!(dev.verify_idle_signal(&clock, 8), Err(HidError::NoIdleSignal));
}

#[test]
fn power_can_be_switched_off_and_on() {
    let (hid, mut dev, clock) = open(BOOT_MOUSE);
    dev.set_power(&clock, false).unwrap();
    assert!(!dev.is_powered());
    hid.with(|h| assert!(!h.powered));
    dev.set_power(&clock, true).unwrap();
    hid.with(|h| assert!(h.powered));
}

// ---- report decoding --------------------------------------------------------------------------

fn decode(d: &mut ReportDecoder, report: &[u8]) -> Vec<Action> {
    let mut out = Vec::new();
    d.decode(report, &mut out).unwrap();
    out
}

#[test]
fn keyboard_reports_become_key_changes() {
    let mut d = ReportDecoder::from_descriptor(BOOT_KEYBOARD).unwrap();
    assert_eq!(d.class(), DeviceClass::Keyboard);
    // Left shift + A.
    assert_eq!(
        decode(&mut d, &[0x02, 0, 0x04, 0, 0, 0, 0, 0]),
        [Action::Key { usage: 0xE1, down: true }, Action::Key { usage: 0x04, down: true }]
    );
    // A stays, B joins, shift is released: releases first.
    assert_eq!(
        decode(&mut d, &[0x00, 0, 0x04, 0x05, 0, 0, 0, 0]),
        [Action::Key { usage: 0xE1, down: false }, Action::Key { usage: 0x05, down: true }]
    );
    assert_eq!(decode(&mut d, &[0; 8]), [Action::Key { usage: 0x04, down: false }, Action::Key { usage: 0x05, down: false }]);
    // Rollover keeps the state and reports the error.
    decode(&mut d, &[0, 0, 0x04, 0, 0, 0, 0, 0]);
    let mut out = Vec::new();
    assert_eq!(d.decode(&[0, 0, 1, 1, 1, 1, 1, 1], &mut out), Err(ReportError::Rollover));
    assert!(out.is_empty());
    assert_eq!(decode(&mut d, &[0; 8]), [Action::Key { usage: 0x04, down: false }]);
    assert_eq!(d.decode(&[0; 4], &mut out), Err(ReportError::Truncated));
}

#[test]
fn mouse_reports_become_buttons_motion_and_wheel() {
    let mut d = ReportDecoder::from_descriptor(BOOT_MOUSE).unwrap();
    assert_eq!(d.class(), DeviceClass::Pointer);
    assert_eq!(
        decode(&mut d, &[0b101, 5, 0xFB, 0xFF]),
        [
            Action::Button { number: 1, down: true },
            Action::Button { number: 3, down: true },
            Action::Motion { dx: 5, dy: -5 },
            Action::Wheel { vertical: -1, horizontal: 0 }
        ]
    );
    assert_eq!(decode(&mut d, &[0, 0, 0, 0]), [Action::Button { number: 1, down: false }, Action::Button { number: 3, down: false }]);
}

#[test]
fn report_ids_select_the_layout() {
    let mut desc = with_report_id(BOOT_KEYBOARD, 1);
    desc.extend(with_report_id(BOOT_MOUSE, 2));
    let mut d = ReportDecoder::from_descriptor(&desc).unwrap();
    assert_eq!(d.kinds(), (true, true, false));
    assert_eq!(d.class(), DeviceClass::Keyboard);
    assert_eq!(decode(&mut d, &[1, 0, 0, 0x04, 0, 0, 0, 0, 0]), [Action::Key { usage: 0x04, down: true }]);
    assert_eq!(decode(&mut d, &[2, 0, 3, 4, 0]), [Action::Motion { dx: 3, dy: 4 }]);
    let mut out = Vec::new();
    assert_eq!(d.decode(&[7, 0, 0, 0], &mut out), Err(ReportError::UnknownReportId));
    assert_eq!(d.decode(&[], &mut out), Err(ReportError::Truncated));
}

#[test]
fn a_precision_touchpad_moves_the_pointer_and_clicks() {
    let desc = ptp(2);
    let mut d = ReportDecoder::from_descriptor(&desc).unwrap();
    assert_eq!(d.kinds(), (false, false, true));
    assert_eq!(d.class(), DeviceClass::Pointer);
    // Touch down: no motion yet.
    assert_eq!(decode(&mut d, &ptp_report(&[(true, 1, 1000, 1000), (false, 0, 0, 0)], 1, false)), []);
    // 160 mm over 4095 units, 8 px per mm: 80/256 px per unit in x, 40/256 in y.
    assert_eq!(
        decode(&mut d, &ptp_report(&[(true, 1, 1256, 1000), (false, 0, 0, 0)], 1, false)),
        [Action::Motion { dx: 80, dy: 0 }]
    );
    // Small steps add up instead of being rounded away: 100 units in y is 15.6 px.
    let mut y = 1000;
    let mut total = 0;
    for _ in 0..16 {
        y += 100;
        for a in decode(&mut d, &ptp_report(&[(true, 1, 1256, y), (false, 0, 0, 0)], 1, false)) {
            match a {
                Action::Motion { dx: 0, dy } => total += dy,
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    assert_eq!(total, 1600 * 40 / 256);
    // Click, then release, with the finger still down.
    assert_eq!(
        decode(&mut d, &ptp_report(&[(true, 1, 1256, y), (false, 0, 0, 0)], 1, true)),
        [Action::Button { number: 1, down: true }]
    );
    assert_eq!(
        decode(&mut d, &ptp_report(&[(true, 1, 1256, y), (false, 0, 0, 0)], 1, false)),
        [Action::Button { number: 1, down: false }]
    );
    // Lift: the next touch starts without a jump.
    assert_eq!(decode(&mut d, &ptp_report(&[(false, 1, 1256, y), (false, 0, 0, 0)], 0, false)), []);
    assert_eq!(decode(&mut d, &ptp_report(&[(true, 2, 3000, 3000), (false, 0, 0, 0)], 1, false)), []);
    assert_eq!(
        decode(&mut d, &ptp_report(&[(true, 2, 3256, 3000), (false, 0, 0, 0)], 1, false)),
        [Action::Motion { dx: 80, dy: 0 }]
    );
}

#[test]
fn a_second_finger_does_not_steal_the_pointer() {
    let desc = ptp(2);
    let mut d = ReportDecoder::from_descriptor(&desc).unwrap();
    decode(&mut d, &ptp_report(&[(true, 1, 1000, 1000), (false, 0, 0, 0)], 1, false));
    // Finger 2 lands elsewhere: the pointer does not jump.
    assert_eq!(decode(&mut d, &ptp_report(&[(true, 1, 1000, 1000), (true, 2, 3000, 3000)], 2, false)), []);
    assert_eq!(
        decode(&mut d, &ptp_report(&[(true, 1, 1256, 1000), (true, 2, 3500, 3500)], 2, false)),
        [Action::Motion { dx: 80, dy: 0 }]
    );
    // The tracked finger's slot may be listed second in the next report.
    assert_eq!(
        decode(&mut d, &ptp_report(&[(true, 2, 3500, 3500), (true, 1, 1512, 1000)], 2, false)),
        [Action::Motion { dx: 80, dy: 0 }]
    );
}

#[test]
fn palms_are_ignored() {
    let desc = ptp(1);
    let mut d = ReportDecoder::from_descriptor(&desc).unwrap();
    // Clear the confidence bit of a touching contact.
    let mut r = ptp_report(&[(true, 1, 1000, 1000)], 1, false);
    r[1] &= !1;
    assert_eq!(decode(&mut d, &r), []);
    let mut r = ptp_report(&[(true, 1, 2000, 2000)], 1, false);
    r[1] &= !1;
    assert_eq!(decode(&mut d, &r), []);
}

#[test]
fn touchpad_with_a_mouse_collection_uses_the_mouse_in_default_mode() {
    let mut desc = with_report_id(BOOT_MOUSE, 2);
    desc.extend(ptp(1));
    let mut d = ReportDecoder::from_descriptor(&desc).unwrap();
    assert_eq!(d.kinds(), (false, true, true));
    assert_eq!(decode(&mut d, &[2, 0, 7, 9, 0]), [Action::Motion { dx: 7, dy: 9 }]);
    assert_eq!(decode(&mut d, &ptp_report(&[(true, 1, 10, 10)], 1, true)), [Action::Button { number: 1, down: true }]);
}

#[test]
fn touchscreens_and_junk_are_unsupported() {
    // Contacts without a button: a touchscreen. The input core has no absolute events.
    let mut screen = ptp(1);
    let n = screen.len();
    // Drop the button field (05 09 09 01 25 01 75 01 95 01 81 02) and its padding.
    screen.drain(n - 15..n - 1);
    assert_eq!(ReportDecoder::from_descriptor(&screen).err(), Some(DecodeError::Unsupported));
    // A vendor-defined device.
    let vendor = [0x06, 0x00, 0xFF, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x02, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x04, 0x81, 0x02, 0xC0];
    assert_eq!(ReportDecoder::from_descriptor(&vendor).err(), Some(DecodeError::Unsupported));
    // Garbage and truncated descriptors are errors, not panics.
    assert!(ReportDecoder::from_descriptor(&[0x05]).is_err());
    assert!(ReportDecoder::from_descriptor(&[0xA1, 0x01]).is_err());
    for cut in 0..BOOT_KEYBOARD.len() {
        let _ = ReportDecoder::from_descriptor(&BOOT_KEYBOARD[..cut]);
    }
}

// ---- the whole stack --------------------------------------------------------------------------

#[test]
fn touchpad_end_to_end_through_the_controller() {
    let mut desc = with_report_id(BOOT_MOUSE, 2);
    desc.extend(ptp(1));
    let (hid, mut dev, clock) = open(&desc);
    assert_eq!(dev.verify_idle_signal(&clock, 4), Ok(()));
    let mut decoder = ReportDecoder::from_descriptor(dev.report_descriptor()).unwrap();
    hid.push_report(&[2, 1, 4, 0xFC, 0]);
    hid.push_report(&[2, 0, 0, 0, 0]);
    let mut actions = Vec::new();
    for _ in 0..3 {
        match dev.poll_input().unwrap() {
            Poll::Report(r) => decoder.decode(r, &mut actions).unwrap(),
            Poll::Idle => {}
        }
    }
    assert_eq!(actions, [Action::Button { number: 1, down: true }, Action::Motion { dx: 4, dy: -4 }, Action::Button { number: 1, down: false }]);
}

#[test]
fn keyboard_and_touchpad_share_one_controller() {
    let (mmio, mut dw, clock) = controller(16, 16);
    dw.configure(BusSpeed::Fast, &Timing::default()).unwrap();
    let kbd = SimHid::new(0x3A, 0x0001, BOOT_KEYBOARD);
    mmio.attach(kbd.clone());
    let pad = SimHid::new(0x2C, 0x0020, BOOT_MOUSE);
    mmio.attach(pad.clone());
    // Two devices on one bus: the bus is lent to each in turn.
    struct Shared<'a>(&'a std::cell::RefCell<DesignWare<SimMmio, SimClock>>);
    impl I2cBus for Shared<'_> {
        fn transfer(&mut self, a: u8, w: &[u8], r: &mut [u8]) -> Result<(), I2cError> {
            self.0.borrow_mut().transfer(a, w, r)
        }
    }
    let bus = std::cell::RefCell::new(dw);
    let mut k = I2cHid::open(Shared(&bus), &clock, 0x3A, 0x0001).unwrap();
    let mut p = I2cHid::open(Shared(&bus), &clock, 0x2C, 0x0020).unwrap();
    kbd.push_report(&[0, 0, 0x04, 0, 0, 0, 0, 0]);
    pad.push_report(&[0, 1, 1, 0]);
    assert_eq!(k.poll_input().unwrap(), Poll::Report(&[0, 0, 0x04, 0, 0, 0, 0, 0]));
    assert_eq!(p.poll_input().unwrap(), Poll::Report(&[0, 1, 1, 0]));
    mmio.with(|m| assert!(m.violations.is_empty(), "{:?}", m.violations));
}

#[test]
fn release_all_lets_go_of_everything() {
    let mut desc = with_report_id(BOOT_KEYBOARD, 1);
    desc.extend(with_report_id(BOOT_MOUSE, 2));
    desc.extend(ptp(1));
    let mut d = ReportDecoder::from_descriptor(&desc).unwrap();
    decode(&mut d, &[1, 0x02, 0, 0x04, 0, 0, 0, 0, 0]);
    decode(&mut d, &[2, 0b11, 0, 0, 0]);
    decode(&mut d, &ptp_report(&[(true, 1, 10, 10)], 1, true));
    let mut out = Vec::new();
    d.release_all(&mut out);
    out.sort_by_key(|a| format!("{a:?}"));
    assert_eq!(
        out,
        [
            Action::Button { number: 1, down: false },
            Action::Button { number: 1, down: false },
            Action::Button { number: 2, down: false },
            Action::Key { usage: 0xE1, down: false },
            Action::Key { usage: 0x04, down: false },
        ]
    );
    out.clear();
    d.release_all(&mut out);
    assert!(out.is_empty());
}
