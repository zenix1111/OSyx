//! HID over I2C: laptop touchpads and keyboards behind a DesignWare I2C
//! controller (Intel LPSS PCI functions, AMD `AMDI0010`/`AMDI0510`).
//!
//! The kernel does not read ACPI. A privileged user-space service
//! (`i2chidd`) evaluates the firmware's AML and passes the devices it found
//! to [`register`] (`firmware` operation `I2C_HID`): the controller, the
//! target address and speed, the HID descriptor register from the `_DSM`,
//! the SCL timing and the interrupt resource. Everything in that
//! description is checked again here.
//!
//! Controllers and devices that cannot be driven are left alone with a log
//! line that says why; nothing is reported as working that did not answer.
//!
//! Input reports are **polled**. The device's INT# line is a GPIO pin (or a
//! global system interrupt) on these machines, and the kernel has neither a
//! GPIO controller driver nor an I/O APIC driver, so there is no interrupt to
//! take. Each device gets a kernel thread that reads its input register
//! every 4 ms while it is in use and every 16 ms otherwise. A device is only
//! polled if it answers a read with nothing pending by a zero length or a
//! NACK; one that repeats its last report would make the pointer drift and
//! is refused (see `osyx_i2c::hid::I2cHid::verify_idle_signal`). Reading
//! the input register is destructive, so the idle poll reads the whole
//! report length (`wMaxInputLength`); the bus load is the price of having
//! no interrupt.
//!
//! The reports are decoded by `osyx_i2c::report` (keyboards, mice and
//! precision touchpads) and delivered to the input core. On power off or
//! reboot the devices are put to sleep (`SET_POWER`).

use crate::arch::timer;
use crate::pci::{self, Bar};
use crate::sync::KMutex;
use crate::{input, interrupts, kprintln, sched};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use osyx_abi::Errno;
use osyx_i2c::bus::{Clock, I2cBus, I2cError, Mmio};
use osyx_i2c::designware::{BusSpeed, DesignWare, ProbeError, Timing};
use osyx_i2c::hid::{HidError, I2cHid, Poll};
use osyx_i2c::report::{Action, DecodeError, DeviceClass, ReportDecoder};
use osyx_i2c::spec::{self, ControllerSpec, Interrupt, Location};

/// Poll interval while reports are arriving, and otherwise.
const POLL_ACTIVE_MS: u64 = 4;
const POLL_IDLE_MS: u64 = 16;
/// How long after the last report a device counts as in use.
const ACTIVE_WINDOW_MS: u64 = 300;
/// Consecutive failed reads before the device is reset, and failed resets
/// before it is given up.
const ERRORS_BEFORE_RESET: u32 = 20;
const RESETS_BEFORE_GIVING_UP: u32 = 3;
/// How long [`register`] waits for the devices to be probed.
const PROBE_WAIT_MS: u64 = 5_000;
/// How long [`quiesce`] waits for the devices to go to sleep.
const QUIESCE_WAIT_MS: u64 = 1_000;
/// Reads that must contain an idle answer before a device is polled.
const IDLE_ATTEMPTS: u32 = 8;

/// Time source of the drivers: the kernel's monotonic clock.
struct KernelClock;

impl Clock for KernelClock {
    fn now_us(&self) -> u64 {
        interrupts::monotonic_ns() / 1000
    }
    fn relax(&self) {
        sched::yield_now();
    }
    fn sleep_ms(&self, ms: u32) {
        timer::sleep_ms(ms as u64);
    }
}

/// Uncached controller registers.
#[derive(Clone, Copy)]
struct KernelMmio {
    base: u64,
    len: usize,
}

impl Mmio for KernelMmio {
    fn read32(&self, offset: usize) -> u32 {
        if !offset.is_multiple_of(4) || offset + 4 > self.len {
            return u32::MAX;
        }
        // SAFETY: `base` maps `len` bytes of device memory (map_mmio) and the
        // offset is aligned and inside it.
        unsafe { core::ptr::read_volatile((self.base + offset as u64) as *const u32) }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        if !offset.is_multiple_of(4) || offset + 4 > self.len {
            return;
        }
        // SAFETY: as in `read32`.
        unsafe { core::ptr::write_volatile((self.base + offset as u64) as *mut u32, value) }
    }
}

// ---- controllers ------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Key {
    Pci(u8, u8, u8),
    Mmio(u64),
}

struct Hardware {
    dw: DesignWare<KernelMmio, KernelClock>,
    /// The mode the controller is set up for.
    speed: Option<BusSpeed>,
    timing: Timing,
}

struct Controller {
    name: String,
    hw: KMutex<Hardware>,
}

/// One device's view of its controller: the bus, at the device's speed.
struct DeviceBus {
    controller: Arc<Controller>,
    speed: BusSpeed,
}

impl I2cBus for DeviceBus {
    fn transfer(&mut self, address: u8, write: &[u8], read: &mut [u8]) -> Result<(), I2cError> {
        let mut g = self.controller.hw.lock();
        let hw = &mut *g;
        if hw.speed != Some(self.speed) {
            hw.dw.configure(self.speed, &hw.timing).map_err(|_| I2cError::Controller)?;
            hw.speed = Some(self.speed);
        }
        hw.dw.transfer(address, write, read)
    }
}

struct Registry {
    controllers: Vec<(Key, Result<Arc<Controller>, String>)>,
    /// (controller, target address) of every device handed out.
    devices: Vec<(Key, u8)>,
}

static REGISTRY: KMutex<Registry> = KMutex::new(Registry { controllers: Vec::new(), devices: Vec::new() });

/// Devices with a running input thread, and the request to put them to sleep.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static QUIESCE: AtomicBool = AtomicBool::new(false);

const PCI_CAP_PM: u8 = 0x01;
const INTEL: u16 = 0x8086;
/// Intel LPSS private registers inside the function's BAR 0.
const LPSS_PRIV_RESETS: usize = 0x204;
const LPSS_RESETS_DEASSERT: u32 = 0x7;

fn probe_error(e: ProbeError) -> String {
    match e {
        ProbeError::NotDesignWare(v) => format!("not a DesignWare controller (IC_COMP_TYPE {v:#010x})"),
        ProbeError::FifoUnknown(p) => format!("FIFO depths unreadable (IC_COMP_PARAM_1 {p:#010x})"),
        ProbeError::Stuck => String::from("the controller does not switch off"),
    }
}

fn open_pci(bus: u8, device: u8, function: u8) -> Result<KernelMmio, String> {
    let dev = pci::enumerate()
        .into_iter()
        .find(|d| d.addr.bus == bus && d.addr.device == device && d.addr.function == function)
        .ok_or_else(|| String::from("no such PCI function"))?;
    if dev.header_type & 0x7F != 0 {
        return Err(String::from("not a PCI endpoint"));
    }
    let Some(Bar::Memory { base, size, .. }) = dev.bar(0) else { return Err(String::from("BAR 0 is not memory")) };
    if base == 0 || size < 0x100 {
        return Err(format!("BAR 0 unassigned (base {base:#x}, size {size:#x})"));
    }
    // Wake the function (D3hot -> D0 needs 10 ms) and switch memory decoding on.
    if let Some(cap) = dev.find_capability(PCI_CAP_PM) {
        let pmcsr = dev.addr.read16(cap + 4);
        if pmcsr & 3 != 0 {
            dev.addr.write16(cap + 4, pmcsr & !3);
            timer::sleep_ms(10);
        }
    }
    dev.addr.write16(0x04, dev.command() | pci::CMD_MEMORY);
    let len = size.min(0x1_0000);
    let virt = crate::mem::map_mmio(base, len).map_err(|e| format!("cannot map BAR 0: {e:?}"))?;
    let mut mmio = KernelMmio { base: virt, len: len as usize };
    // An Intel LPSS function can come up held in reset: its DesignWare
    // registers read as zero or ones until the private reset is released.
    let is_lpss = dev.vendor == INTEL && dev.class == 0x0C && dev.subclass == 0x80 && len >= 0x400;
    if is_lpss && mmio.read32(osyx_i2c::designware::reg::COMP_TYPE) != osyx_i2c::designware::COMP_TYPE_MAGIC {
        kprintln!("i2c: {}: LPSS function in reset, releasing it", dev.addr);
        mmio.write32(LPSS_PRIV_RESETS, LPSS_RESETS_DEASSERT);
        timer::sleep_ms(1);
    }
    Ok(mmio)
}

fn open_mmio(base: u64, len: u32) -> Result<KernelMmio, String> {
    if crate::firmware::overlaps_kernel_ram(base, len as u64) {
        return Err(format!("{base:#x}+{len:#x} is kernel RAM"));
    }
    let virt = crate::mem::map_mmio(base, len as u64).map_err(|e| format!("cannot map {base:#x}: {e:?}"))?;
    Ok(KernelMmio { base: virt, len: len as usize })
}

fn claim_controller(spec: &ControllerSpec, speed: BusSpeed) -> Result<Arc<Controller>, String> {
    let (mmio, what) = match spec.location {
        Location::Pci { bus, device, function } => (open_pci(bus, device, function)?, format!("PCI {bus:02x}:{device:02x}.{function}")),
        Location::Mmio { base, len } => (open_mmio(base, len)?, format!("MMIO {base:#x} ({})", spec.hid)),
    };
    let mut dw = DesignWare::probe(mmio, KernelClock).map_err(probe_error)?;
    let source = dw.configure(speed, &spec.timing).map_err(|e| format!("no usable SCL timing ({e:?}): the firmware gives none and the controller has none set"))?;
    let (tx, rx) = dw.fifo_depths();
    kprintln!(
        "i2c: controller {} at {what}: DesignWare {:#x}, FIFOs {tx}/{rx}, {} Hz, SCL timing from the {}",
        spec.path,
        dw.version(),
        speed.hz(),
        match source {
            osyx_i2c::designware::TimingSource::Firmware => "firmware",
            osyx_i2c::designware::TimingSource::ControllerDefault => "controller defaults",
        }
    );
    Ok(Arc::new(Controller { name: spec.path.clone(), hw: KMutex::new(Hardware { dw, speed: Some(speed), timing: spec.timing }) }))
}

fn key_of(spec: &ControllerSpec) -> Key {
    match spec.location {
        Location::Pci { bus, device, function } => Key::Pci(bus, device, function),
        Location::Mmio { base, .. } => Key::Mmio(base),
    }
}

// ---- devices ----------------------------------------------------------------------------------

const PENDING: u8 = 0;
const CLAIMED: u8 = 1;
const REFUSED: u8 = 2;

struct Task {
    path: String,
    address: u8,
    register: u16,
    speed: BusSpeed,
    interrupt: Interrupt,
    controller: Arc<Controller>,
    outcome: Arc<AtomicU8>,
}

/// Parses `blob` (an `osyx_i2c::spec` description) and starts a thread per
/// new device. Waits (bounded) until every device is probed and returns how
/// many were claimed.
pub fn register(blob: &[u8]) -> Result<usize, Errno> {
    let specs = spec::decode(blob).map_err(|e| {
        kprintln!("i2c: rejected the device description: {e:?}");
        Errno::InvalidArgument
    })?;
    let mut outcomes: Vec<Arc<AtomicU8>> = Vec::new();
    {
        let mut reg = REGISTRY.lock();
        for d in &specs {
            let key = key_of(&d.controller);
            if reg.devices.contains(&(key, d.address)) {
                kprintln!("i2c: {}: already handed to the driver", d.path);
                continue;
            }
            let speed = BusSpeed::from_hz(d.speed_hz);
            let controller = match reg.controllers.iter().find(|(k, _)| *k == key) {
                Some((_, r)) => r.clone(),
                None => {
                    let r = claim_controller(&d.controller, speed);
                    if let Err(why) = &r {
                        kprintln!("i2c: controller {} not claimed: {why}", d.controller.path);
                    }
                    reg.controllers.push((key, r.clone()));
                    r
                }
            };
            reg.devices.push((key, d.address));
            let Ok(controller) = controller else {
                kprintln!("i2c: {}: not claimed, its controller is unusable", d.path);
                continue;
            };
            let outcome = Arc::new(AtomicU8::new(PENDING));
            outcomes.push(outcome.clone());
            let task = Box::new(Task {
                path: d.path.clone(),
                address: d.address,
                register: d.descriptor_register,
                speed,
                interrupt: d.interrupt.clone(),
                controller,
                outcome,
            });
            sched::spawn_kernel("i2c-hid", device_thread, Box::into_raw(task) as u64, 0);
        }
    }
    let deadline = timer::Deadline::after_ms(PROBE_WAIT_MS);
    while outcomes.iter().any(|o| o.load(Ordering::Acquire) == PENDING) && !deadline.expired() {
        timer::sleep_ms(5);
    }
    let claimed = outcomes.iter().filter(|o| o.load(Ordering::Acquire) == CLAIMED).count();
    kprintln!("i2c: {} of {} HID over I2C device(s) claimed", claimed, specs.len());
    Ok(claimed)
}

fn device_thread(arg: u64, _: u64) {
    // SAFETY: `register` leaked this Box for exactly one thread.
    let task = unsafe { Box::from_raw(arg as *mut Task) };
    let outcome = task.outcome.clone();
    let claimed = run(&task);
    // `run` sets CLAIMED itself once the input device exists; a device that
    // never got that far is refused.
    if !claimed {
        outcome.store(REFUSED, Ordering::Release);
    }
}

/// Delivers one decoded change to the input core.
pub fn apply(id: u32, a: &Action) {
    match *a {
        Action::Key { usage, down } => input::key(id, usage, down),
        Action::Button { number, down } => input::button(id, number as u16, down),
        Action::Motion { dx, dy } => input::motion(id, dx, dy),
        Action::Wheel { vertical, horizontal } => input::wheel(id, vertical, horizontal),
    }
}

fn describe_interrupt(i: &Interrupt) -> String {
    match i {
        Interrupt::None => String::from("no interrupt resource"),
        Interrupt::Gsi(n) => format!("interrupt GSI {n}, no I/O APIC driver"),
        Interrupt::Gpio { pin, controller } => format!("INT# is GPIO pin {pin} of {controller}, no GPIO driver"),
    }
}

/// Opens the device and serves it. Returns false if it was refused.
fn run(t: &Task) -> bool {
    let clock = KernelClock;
    let bus = DeviceBus { controller: t.controller.clone(), speed: t.speed };
    let mut dev = match I2cHid::open(bus, &clock, t.address, t.register) {
        Ok(d) => d,
        Err(e) => {
            kprintln!("i2c-hid {}: not claimed: {}", t.path, hid_error(&e));
            return false;
        }
    };
    let (vid, pid) = (dev.descriptor().vendor_id, dev.descriptor().product_id);
    let mut decoder = match ReportDecoder::from_descriptor(dev.report_descriptor()) {
        Ok(d) => d,
        Err(e) => {
            let why = match e {
                DecodeError::Unsupported => String::from("no keyboard, mouse or precision touchpad in its report descriptor (touchscreens need absolute events, which the input core lacks)"),
                DecodeError::Parse(p) => format!("bad report descriptor ({p:?})"),
            };
            kprintln!("i2c-hid {}: {vid:04x}:{pid:04x} not claimed: {why}", t.path);
            let _ = dev.set_power(&clock, false);
            return false;
        }
    };
    if let Err(e) = dev.verify_idle_signal(&clock, IDLE_ATTEMPTS) {
        kprintln!(
            "i2c-hid {}: {vid:04x}:{pid:04x} not claimed: {}; without an interrupt ({}) it cannot be polled safely",
            t.path,
            hid_error(&e),
            describe_interrupt(&t.interrupt)
        );
        let _ = dev.set_power(&clock, false);
        return false;
    }
    let (keyboard, mouse, touchpad) = decoder.kinds();
    let class = match decoder.class() {
        DeviceClass::Keyboard => input::class::KEYBOARD,
        DeviceClass::Pointer => input::class::MOUSE,
    };
    let id = input::register(&format!("I2C HID {vid:04x}:{pid:04x}"), class);
    kprintln!(
        "i2c-hid {}: {vid:04x}:{pid:04x} at {:#04x}, {} Hz: {}{}{} -> input device {id}; polling every {POLL_ACTIVE_MS}/{POLL_IDLE_MS} ms ({})",
        t.path,
        t.address,
        t.speed.hz(),
        if keyboard { "keyboard " } else { "" },
        if mouse { "mouse " } else { "" },
        if touchpad { "touchpad" } else { "" },
        describe_interrupt(&t.interrupt)
    );
    ACTIVE.fetch_add(1, Ordering::AcqRel);
    t.outcome.store(CLAIMED, Ordering::Release);
    serve(t, &mut dev, &mut decoder, id);
    input::unregister(id);
    ACTIVE.fetch_sub(1, Ordering::AcqRel);
    true
}

fn hid_error(e: &HidError) -> String {
    match e {
        HidError::Bus(b) => format!("bus error {b:?}"),
        HidError::BadDescriptorLength => String::from("HID descriptor has the wrong length"),
        HidError::UnsupportedVersion(v) => format!("HID descriptor version {v:#06x} (only 0x0100 exists)"),
        HidError::BadDescriptor => String::from("HID descriptor has impossible fields"),
        HidError::NoResetResponse => String::from("no reset response within 1 s"),
        HidError::BadReportLength(n) => format!("input report length {n} is impossible"),
        HidError::NoIdleSignal => String::from("it answers a read with no report pending by data, not by a zero length or NACK"),
    }
}

/// Polls until the device fails for good or the machine powers off.
fn serve<B: I2cBus>(t: &Task, dev: &mut I2cHid<B>, decoder: &mut ReportDecoder, id: u32) {
    let clock = KernelClock;
    let mut actions: Vec<Action> = Vec::new();
    let (mut errors, mut failed_resets, mut bad_reports) = (0u32, 0u32, 0u64);
    let mut active_until = 0u64;
    loop {
        if QUIESCE.load(Ordering::Acquire) {
            let _ = dev.set_power(&clock, false);
            kprintln!("i2c-hid {}: powered down", t.path);
            return;
        }
        match dev.poll_input() {
            Ok(Poll::Report(report)) => {
                errors = 0;
                active_until = interrupts::uptime_ms() + ACTIVE_WINDOW_MS;
                actions.clear();
                if let Err(e) = decoder.decode(report, &mut actions) {
                    bad_reports += 1;
                    if bad_reports <= 3 || bad_reports % 1000 == 0 {
                        kprintln!("i2c-hid {}: bad report ({e:?}), {bad_reports} so far", t.path);
                    }
                }
                for a in &actions {
                    apply(id, a);
                }
            }
            Ok(Poll::Idle) => errors = 0,
            Err(e) => {
                errors += 1;
                if errors == 1 {
                    kprintln!("i2c-hid {}: read failed: {}", t.path, hid_error(&e));
                }
                if errors >= ERRORS_BEFORE_RESET {
                    errors = 0;
                    kprintln!("i2c-hid {}: resetting the device", t.path);
                    match dev.reset(&clock) {
                        Ok(()) => {
                            failed_resets = 0;
                            // The device forgot what it had reported.
                            actions.clear();
                            decoder.release_all(&mut actions);
                            for a in &actions {
                                apply(id, a);
                            }
                        }
                        Err(e) => {
                            failed_resets += 1;
                            kprintln!("i2c-hid {}: reset failed: {}", t.path, hid_error(&e));
                            if failed_resets >= RESETS_BEFORE_GIVING_UP {
                                kprintln!("i2c-hid {}: giving up on the device", t.path);
                                let _ = dev.set_power(&clock, false);
                                return;
                            }
                        }
                    }
                }
            }
        }
        timer::sleep_ms(if interrupts::uptime_ms() < active_until { POLL_ACTIVE_MS } else { POLL_IDLE_MS });
    }
}

/// Puts every claimed device to sleep (power off, reboot). Bounded.
pub fn quiesce() {
    if ACTIVE.load(Ordering::Acquire) == 0 {
        return;
    }
    QUIESCE.store(true, Ordering::Release);
    let deadline = timer::Deadline::after_ms(QUIESCE_WAIT_MS);
    while ACTIVE.load(Ordering::Acquire) != 0 && !deadline.expired() {
        timer::sleep_ms(5);
    }
    let left = ACTIVE.load(Ordering::Acquire);
    if left != 0 {
        kprintln!("i2c: {left} HID over I2C device(s) did not power down in time");
    }
}

/// Names of the controllers and devices handed out, for the log.
pub fn status() -> Vec<String> {
    let reg = REGISTRY.lock();
    reg.controllers
        .iter()
        .map(|(k, r)| match r {
            Ok(c) => format!("{k:?}: {} claimed", c.name),
            Err(why) => format!("{k:?}: refused ({why})"),
        })
        .collect()
}

/// The whole stack against the register-level simulation: controller
/// driver, protocol, report decoding and the real input core. Only real
/// hardware can show that a given laptop's controller behaves like the model.
pub fn selftest() -> Result<(), String> {
    use osyx_i2c::sim::{SimClock, SimHid, SimMmio};
    // Keyboard (id 1) and mouse (id 2) in one device.
    const DESCRIPTOR: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95,
        0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xC0, 0x05, 0x01, 0x09,
        0x02, 0xA1, 0x01, 0x85, 0x02, 0x09, 0x01, 0xA1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02,
        0x95, 0x01, 0x75, 0x05, 0x81, 0x03, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x02, 0x81, 0x06, 0xC0, 0xC0,
    ];
    let mmio = SimMmio::new(8, 8);
    let clock = SimClock::new();
    let mut dw = DesignWare::probe(mmio.clone(), clock.clone()).map_err(probe_error)?;
    dw.configure(BusSpeed::Fast, &Timing::default()).map_err(|e| format!("configure: {e:?}"))?;
    let hid = SimHid::new(0x2C, 0x0020, DESCRIPTOR);
    mmio.attach(hid.clone());
    let mut dev = I2cHid::open(dw, &clock, 0x2C, 0x0020).map_err(|e| hid_error(&e))?;
    let mut decoder = ReportDecoder::from_descriptor(dev.report_descriptor()).map_err(|e| format!("descriptor: {e:?}"))?;
    dev.verify_idle_signal(&clock, IDLE_ATTEMPTS).map_err(|e| hid_error(&e))?;
    let id = input::register("I2C HID selftest", input::class::KEYBOARD);
    // 'A' down and up; left button down with motion (5, -3).
    hid.push_report(&[1, 0, 0, 0x04, 0, 0, 0, 0, 0]);
    hid.push_report(&[1, 0, 0, 0, 0, 0, 0, 0, 0]);
    hid.push_report(&[2, 1, 5, 0xFD]);
    let mut actions = Vec::new();
    for _ in 0..4 {
        match dev.poll_input().map_err(|e| hid_error(&e))? {
            Poll::Report(r) => decoder.decode(r, &mut actions).map_err(|e| format!("decode: {e:?}"))?,
            Poll::Idle => {}
        }
    }
    for a in &actions {
        apply(id, a);
    }
    let events = input::devices().into_iter().find(|d| d.0 == id).map(|d| d.3);
    input::unregister(id);
    let violations = mmio.with(|m| m.violations.clone());
    if !violations.is_empty() {
        return Err(format!("the controller model saw rule violations: {violations:?}"));
    }
    if actions.len() != 4 || events != Some(4) {
        return Err(format!("expected 4 actions and 4 input events, got {} and {events:?}", actions.len()));
    }
    Ok(())
}
