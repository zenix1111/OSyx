//! Native xHCI (USB 3.x host controller) driver.
//!
//! Every PCI function with class 0x0C, subclass 0x03, programming
//! interface 0x30 gets a kernel thread that owns the controller completely:
//! it takes the controller from the firmware (USB legacy support
//! handoff), resets it, builds the data structures the controller reads
//! (device context base address array, scratchpads, command ring, event
//! ring and its segment table), routes the event interrupt through MSI-X
//! or MSI to the local APIC, and then serves root hub ports: connect,
//! reset, slot enable, addressing, descriptor reads, configuration,
//! interrupt endpoints for HID devices, and teardown on disconnect.
//!
//! Hardware facts are read from the controller (capability registers,
//! extended capabilities, port speeds, context size, scratchpad count,
//! 64-bit addressing); nothing about QEMU is assumed. The interrupt handler
//! only counts and wakes the thread; all ring processing happens in the
//! thread, which also polls once per timer tick when no MSI is available.
//! Every wait has a timeout, and an unresponsive controller or device is
//! reported and abandoned instead of hanging the kernel.

mod bt;
pub mod dma;
mod hid;
mod storage;

use crate::arch::timer::{self, Deadline};
use crate::sync::IrqSpinLock;
use crate::waitq::{block_on, WaitQueue};
use crate::{input, interrupts, irq, kprintln, pci, sched};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, AtomicBool, AtomicU64, AtomicUsize, Ordering};
use dma::{DmaError, DmaPage, DmaRing};
use hid::{HidFunction, HidKind};
use storage::StorageState;
use osyx_usb::descriptor::{self, Configuration, DescriptorError, DeviceDescriptor, Interface, SetupPacket};
use osyx_usb::hid::{parse_report_descriptor, BootKeyboard, MouseLayout};
use osyx_usb::xhci::context::{self, ContextLayout, EndpointContext, EndpointType, SlotContext};
use osyx_usb::xhci::regs::{self, ext, op, portsc, rt, usbcmd, usbsts, Capabilities, SupportedProtocol};
use osyx_usb::xhci::ring::{erst_entry, EventRing, ProducerRing, RingError, TrbMemory};
use osyx_usb::xhci::trb::{CompletionCode, Trb, TrbType};
use osyx_usb::Speed;

const MAX_CONTROLLERS: usize = 4;
const COMMAND_TIMEOUT_MS: u64 = 1000;
const TRANSFER_TIMEOUT_MS: u64 = 1000;
const RESET_TIMEOUT_MS: u64 = 1000;
/// How long the firmware gets to release the controller (Linux waits 1 s).
const HANDOFF_TIMEOUT_MS: u64 = 1000;
const PORT_RESET_TIMEOUT_MS: u64 = 500;
/// Enumeration attempts per connect. Real devices often fail the first
/// transfers after a reset with a transaction error; Linux and Windows reset
/// the port and try again.
const ATTACH_ATTEMPTS: u32 = 3;
/// Connect debounce before the first port reset (USB 2.0 7.1.7.3: 100 ms).
const DEBOUNCE_MS: u64 = 100;
/// Interrupt moderation interval, in 250 ns units (40 us).
const IMOD_INTERVAL: u32 = 160;
/// Consecutive transfer errors after which an endpoint is given up.
const MAX_ENDPOINT_ERRORS: u32 = 20;

static WAKE: [WaitQueue; MAX_CONTROLLERS] = [const { WaitQueue::new() }; MAX_CONTROLLERS];
static IRQS: [AtomicU64; MAX_CONTROLLERS] = [const { AtomicU64::new(0) }; MAX_CONTROLLERS];
static CONTROLLERS: AtomicUsize = AtomicUsize::new(0);
/// Set once a controller finished its first port sweep (and with it every
/// storage setup); `wait_ready` uses it to know when disks are registered.
static READY: [AtomicBool; MAX_CONTROLLERS] = [const { AtomicBool::new(false) }; MAX_CONTROLLERS];
/// One status line per controller, for diagnostics and tests.
static STATUS: IrqSpinLock<Vec<String>> = IrqSpinLock::new(Vec::new());

#[derive(Debug)]
pub enum XhciError {
    Bar(&'static str),
    Caps(regs::CapError),
    Dma(DmaError),
    Timeout(&'static str),
    Command(CompletionCode),
    Transfer(CompletionCode),
    /// A SCSI command completed with a non-zero status byte.
    Scsi(u8),
    Ring(RingError),
    Descriptor(DescriptorError),
    BadSlot,
    PortGone,
    Unsupported(&'static str),
}

impl fmt::Display for XhciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XhciError::Bar(s) => write!(f, "BAR: {s}"),
            XhciError::Caps(e) => write!(f, "capability registers: {e:?}"),
            XhciError::Dma(e) => write!(f, "DMA memory: {e:?}"),
            XhciError::Timeout(s) => write!(f, "timeout: {s}"),
            XhciError::Command(c) => write!(f, "command failed: {c:?}"),
            XhciError::Transfer(c) => write!(f, "transfer failed: {c:?}"),
            XhciError::Scsi(s) => write!(f, "SCSI command failed with status {s}"),
            XhciError::Ring(e) => write!(f, "ring: {e:?}"),
            XhciError::Descriptor(e) => write!(f, "malformed descriptor: {e:?}"),
            XhciError::BadSlot => write!(f, "controller returned an invalid slot id"),
            XhciError::PortGone => write!(f, "device disconnected"),
            XhciError::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}

impl From<DmaError> for XhciError {
    fn from(e: DmaError) -> Self {
        XhciError::Dma(e)
    }
}

impl From<RingError> for XhciError {
    fn from(e: RingError) -> Self {
        XhciError::Ring(e)
    }
}

impl From<DescriptorError> for XhciError {
    fn from(e: DescriptorError) -> Self {
        XhciError::Descriptor(e)
    }
}

type Result<T> = core::result::Result<T, XhciError>;

/// Volatile access to the controller's register BAR.
#[derive(Clone, Copy)]
struct Mmio(u64);

impl Mmio {
    fn r32(self, off: u64) -> u32 {
        // SAFETY: `self.0` maps the whole register BAR uncached; offsets come
        // from validated capability registers.
        unsafe { read_volatile((self.0 + off) as *const u32) }
    }
    fn w32(self, off: u64, v: u32) {
        // SAFETY: as in `r32`.
        unsafe { write_volatile((self.0 + off) as *mut u32, v) }
    }
    fn r64(self, off: u64) -> u64 {
        self.r32(off) as u64 | (self.r32(off + 4) as u64) << 32
    }
    /// 64-bit registers are written low dword first (xHCI 5.1).
    fn w64(self, off: u64, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }
}

/// Probes every xHCI controller; each gets its own thread. Returns how
/// many were found.
pub fn probe(devs: &[pci::Device]) -> usize {
    let mut found = 0;
    for d in devs.iter().filter(|d| d.class == 0x0C && d.subclass == 0x03 && d.prog_if == 0x30) {
        let index = CONTROLLERS.fetch_add(1, Ordering::Relaxed);
        found += 1;
        if index >= MAX_CONTROLLERS {
            kprintln!("xhci: controller at {} ignored (only {} supported)", d.addr, MAX_CONTROLLERS);
            continue;
        }
        kprintln!("xhci{}: USB 3 host controller {:04x}:{:04x} at {}", index, d.vendor, d.device, d.addr);
        let dev = Box::into_raw(Box::new(*d)) as u64;
        sched::spawn_kernel("xhci", controller_thread, index as u64, dev);
    }
    found
}

/// One line per controller ("xhci0: running, MSI-X, 2 devices").
pub fn status() -> Vec<String> {
    STATUS.lock().clone()
}

fn set_status(index: usize, s: String) {
    let mut st = STATUS.lock();
    if st.len() <= index {
        st.resize(index + 1, String::new());
    }
    st[index] = s;
}

fn controller_thread(index: u64, dev: u64) {
    // SAFETY: `dev` is the Box leaked by `probe` for exactly this thread.
    let dev = *unsafe { Box::from_raw(dev as *mut pci::Device) };
    let index = index as usize;
    match Xhci::start(index, dev) {
        Ok(mut hc) => hc.run(),
        Err(e) => {
            kprintln!("xhci{}: initialisation failed: {}", index, e);
            set_status(index, alloc::format!("xhci{index}: failed: {e}"));
            // Nothing will ever enumerate on this controller; do not hold
            // the boot back waiting for it.
            READY[index].store(true, Ordering::Release);
        }
    }
}

fn irq_handler(index: u64) {
    IRQS[index as usize].fetch_add(1, Ordering::Relaxed);
    WAKE[index as usize].wake_all();
}

/// Wakes a controller thread (work was queued for it).
pub fn wake(index: usize) {
    if let Some(w) = WAKE.get(index) {
        w.wake_all();
    }
}

/// Waits (bounded) until every controller has finished its first port
/// sweep, i.e. every mass-storage disk that was attached at boot has been
/// registered with the block layer.
pub fn wait_ready(timeout_ms: u64) {
    let deadline = Deadline::after_ms(timeout_ms);
    let total = CONTROLLERS.load(Ordering::Relaxed).min(MAX_CONTROLLERS);
    let done = |i: usize| READY[i].load(Ordering::Acquire);
    if (0..total).all(done) {
        return;
    }
    kprintln!("usb: waiting up to {} ms for devices to enumerate", timeout_ms);
    while !(0..total).all(done) && !deadline.expired() {
        timer::sleep_ms(5);
    }
    if (0..total).all(done) {
        kprintln!("usb: enumeration complete");
    } else {
        kprintln!("usb: WARNING: not every controller finished enumeration; continuing");
    }
}

/// Waits until `done()` with pauses of one tick, for at most `timeout_ms`
/// (by ticks or, if they stall, the TSC); false on timeout.
fn poll_mmio(timeout_ms: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Deadline::after_ms(timeout_ms);
    loop {
        if done() {
            return true;
        }
        if deadline.expired() {
            return done();
        }
        timer::pause_tick();
    }
}

/// A HID interrupt IN endpoint with its transfer ring and report buffer.
struct InterruptEndpoint {
    dci: u8,
    ring: ProducerRing,
    mem: DmaRing,
    buffer: DmaPage,
    len: u16,
    /// TRB of the transfer in flight.
    pending: Option<u64>,
    errors: u32,
    function: HidFunction,
}

/// A bulk endpoint (mass storage) with its transfer ring.
struct BulkEndpoint {
    dci: u8,
    in_endpoint: bool,
    ring: ProducerRing,
    mem: DmaRing,
    /// TRB of the transfer in flight.
    pending: Option<u64>,
    /// Completion of the transfer in flight: (TRB, code, residual).
    last: Option<(u64, CompletionCode, u32)>,
}

/// An addressed USB device in a slot.
struct Device {
    port: u8,
    speed: Speed,
    output: DmaPage,
    input: DmaPage,
    ep0: ProducerRing,
    ep0_mem: DmaRing,
    ep0_max_packet: u16,
    /// Data stage buffer of control transfers.
    buffer: DmaPage,
    /// Transfer events of the default control endpoint not consumed yet.
    ep0_events: Vec<Trb>,
    interrupt: Vec<InterruptEndpoint>,
    bulk: Vec<BulkEndpoint>,
    storage: Option<StorageState>,
    /// Set when the device is a Bluetooth controller.
    bt: Option<bt::BtState>,
    name: String,
    /// Route string (hub ports below the root port, 4 bits per tier).
    route: u32,
    /// Hubs between the root port and this device.
    depth: u8,
    /// Transaction translator (hub slot, hub port) serving a low/full-speed
    /// device behind a high-speed hub; (0, 0) when none.
    tt: (u8, u8),
    /// Set when the device is a hub.
    hub: Option<Hub>,
}

/// A USB 2.0 (or 1.1) hub: its ports and the slots of their devices.
struct Hub {
    ports: u8,
    mtt: bool,
    ttt: u8,
    /// Hub port -> slot of the device on it.
    children: BTreeMap<u8, u8>,
}

/// Hub class requests and port features (USB 2.0 chapter 11).
mod hubreq {
    use osyx_usb::descriptor::SetupPacket;
    pub const PORT_RESET: u16 = 4;
    pub const PORT_POWER: u16 = 8;
    pub const C_PORT_CONNECTION: u16 = 16;
    pub const C_PORT_ENABLE: u16 = 17;
    pub const C_PORT_RESET: u16 = 20;
    pub const CONNECTION: u16 = 1 << 0;
    pub const ENABLE: u16 = 1 << 1;
    pub const LOW_SPEED: u16 = 1 << 9;
    pub const HIGH_SPEED: u16 = 1 << 10;
    pub const CHANGE_CONNECTION: u16 = 1 << 0;
    pub const CHANGE_RESET: u16 = 1 << 4;

    pub fn hub_descriptor() -> SetupPacket {
        SetupPacket { request_type: 0xA0, request: 6, value: 0x2900, index: 0, length: 9 }
    }
    pub fn port_status(port: u8) -> SetupPacket {
        SetupPacket { request_type: 0xA3, request: 0, value: 0, index: port as u16, length: 4 }
    }
    pub fn set_port(port: u8, feature: u16) -> SetupPacket {
        SetupPacket { request_type: 0x23, request: 3, value: feature, index: port as u16, length: 0 }
    }
    pub fn clear_port(port: u8, feature: u16) -> SetupPacket {
        SetupPacket { request_type: 0x23, request: 1, value: feature, index: port as u16, length: 0 }
    }
}

impl Device {
    /// The Slot Context of this device with `entries` endpoint contexts.
    fn slot_context(&self, entries: u8) -> SlotContext {
        let (ports, mtt, ttt) = self.hub.as_ref().map_or((0, false, 0), |h| (h.ports, h.mtt, h.ttt));
        SlotContext {
            route_string: self.route,
            speed: self.speed,
            context_entries: entries,
            root_port: self.port,
            interrupter: 0,
            hub_ports: ports,
            mtt,
            ttt,
            tt_slot: self.tt.0,
            tt_port: self.tt.1,
        }
    }

    fn new(port: u8, speed: Speed, ac64: bool) -> Result<Device> {
        let ep0_mem = DmaRing::new(ac64)?;
        Ok(Device {
            port,
            speed,
            output: DmaPage::new(ac64)?,
            input: DmaPage::new(ac64)?,
            ep0: ProducerRing::new(&ep0_mem),
            ep0_mem,
            ep0_max_packet: speed.default_max_packet0(),
            buffer: DmaPage::new(ac64)?,
            ep0_events: Vec::new(),
            interrupt: Vec::new(),
            bulk: Vec::new(),
            storage: None,
            bt: None,
            name: String::new(),
            route: 0,
            depth: 0,
            tt: (0, 0),
            hub: None,
        })
    }
}

pub struct Xhci {
    index: usize,
    pci: pci::Device,
    mmio: Mmio,
    caps: Capabilities,
    layout: ContextLayout,
    max_slots: u8,
    protocols: Vec<SupportedProtocol>,
    dcbaa: DmaPage,
    _scratchpad_array: Option<DmaPage>,
    _scratchpads: Vec<DmaPage>,
    cmd: ProducerRing,
    cmd_mem: DmaRing,
    events: EventRing,
    event_mem: DmaRing,
    _erst: DmaPage,
    /// Command completion events by command TRB address.
    completions: BTreeMap<u64, Trb>,
    devices: BTreeMap<u8, Device>,
    /// Root hub port -> slot.
    ports: BTreeMap<u8, u8>,
    pending_ports: VecDeque<u8>,
    irq_vector: Option<u8>,
    irq_mode: &'static str,
    seen_irqs: u64,
}

impl Xhci {
    fn op(&self, reg: u64) -> u64 {
        self.caps.op_reg(reg)
    }

    fn ir(&self, reg: u64) -> u64 {
        self.caps.interrupter_reg(0, reg)
    }

    fn portsc(&self, port: u8) -> u32 {
        self.mmio.r32(self.op(op::portsc(port)))
    }

    fn write_portsc(&self, port: u8, v: u32) {
        self.mmio.w32(self.op(op::portsc(port)), v);
    }

    /// Waits until `done()` with pauses of one tick; false on timeout.
    fn poll_until(&self, timeout_ms: u64, mut done: impl FnMut(&Xhci) -> bool) -> bool {
        poll_mmio(timeout_ms, || done(self))
    }

    // ---- bring-up ------------------------------------------------------------------

    fn start(index: usize, pci: pci::Device) -> Result<Xhci> {
        set_status(index, alloc::format!("xhci{index}: initialising"));
        let Some(pci::Bar::Memory { base, size, .. }) = pci.bar(0) else { return Err(XhciError::Bar("BAR0 is not a memory BAR")) };
        if base == 0 || size < 0x1000 {
            return Err(XhciError::Bar("BAR0 unassigned or too small"));
        }
        let virt = crate::mem::map_mmio(base, size).map_err(|_| XhciError::Bar("cannot map BAR0"))?;
        let mmio = Mmio(virt);
        // Memory decoding and bus mastering (DMA) on, legacy INTx off.
        pci.addr.write16(0x04, pci.command() | pci::CMD_MEMORY | pci::CMD_BUS_MASTER | pci::CMD_INTX_DISABLE);
        let caps = Capabilities::read(|o| mmio.r32(o), size).map_err(XhciError::Caps)?;
        let (maj, min) = caps.version_str();
        kprintln!(
            "xhci{}: version {}.{:02x}, {} slots, {} ports, {} interrupters, {}-byte contexts, {}-bit DMA, {} scratchpads, BAR0 {:#x} ({} KiB)",
            index,
            maj,
            min,
            caps.max_slots,
            caps.max_ports,
            caps.max_interrupters,
            caps.context_size(),
            if caps.ac64 { 64 } else { 32 },
            caps.max_scratchpad,
            base,
            size >> 10
        );
        let ext_caps = regs::ext_caps(|o| mmio.r32(o), caps.xecp, size);
        let mut protocols = Vec::new();
        let mut legacy = None;
        for c in &ext_caps {
            match c.id {
                ext::LEGACY_SUPPORT => legacy = Some(c.offset),
                ext::SUPPORTED_PROTOCOL => {
                    if let Some(p) = SupportedProtocol::read(|o| mmio.r32(o), c.offset) {
                        kprintln!(
                            "xhci{}: ports {}-{}: USB {}.{}",
                            index,
                            p.first_port,
                            p.first_port as u16 + p.port_count as u16 - 1,
                            p.major,
                            p.minor >> 4
                        );
                        protocols.push(p);
                    }
                }
                _ => {}
            }
        }
        if let Some(off) = legacy {
            take_ownership(index, mmio, off);
        }
        let ac64 = caps.ac64;
        let cmd_mem = DmaRing::new(ac64)?;
        let event_mem = DmaRing::new(ac64)?;
        let mut hc = Xhci {
            index,
            pci,
            mmio,
            caps,
            layout: ContextLayout::new(caps.csz64),
            max_slots: caps.max_slots,
            protocols,
            dcbaa: DmaPage::new(ac64)?,
            _scratchpad_array: None,
            _scratchpads: Vec::new(),
            cmd: ProducerRing::new(&cmd_mem),
            cmd_mem,
            events: EventRing::new(&event_mem),
            event_mem,
            _erst: DmaPage::new(ac64)?,
            completions: BTreeMap::new(),
            devices: BTreeMap::new(),
            ports: BTreeMap::new(),
            pending_ports: VecDeque::new(),
            irq_vector: None,
            irq_mode: "polling",
            seen_irqs: 0,
        };
        hc.reset()?;
        hc.setup_structures()?;
        hc.setup_interrupts();
        hc.run_controller()?;
        // Prove the command ring works before touching devices.
        hc.command(Trb::noop_command())?;
        kprintln!("xhci{}: running ({} interrupts), command ring verified with a no-op", index, hc.irq_mode);
        set_status(index, alloc::format!("xhci{index}: running, {} interrupts", hc.irq_mode));
        Ok(hc)
    }

    fn reset(&mut self) -> Result<()> {
        let cmd = self.op(op::USBCMD);
        let sts = self.op(op::USBSTS);
        let m = self.mmio;
        if m.r32(sts) == u32::MAX {
            return Err(XhciError::Unsupported("controller registers read all ones (powered down or gone)"));
        }
        // No operational register may be written while CNR is set (xHCI 4.2).
        if !self.poll_until(RESET_TIMEOUT_MS, |h| h.mmio.r32(sts) & usbsts::CNR == 0) {
            return Err(XhciError::Timeout("controller not ready"));
        }
        if m.r32(sts) & usbsts::HCH == 0 {
            m.w32(cmd, m.r32(cmd) & !usbcmd::RUN);
            if !self.poll_until(RESET_TIMEOUT_MS, |h| h.mmio.r32(sts) & usbsts::HCH != 0) {
                return Err(XhciError::Timeout("controller did not halt"));
            }
        }
        m.w32(cmd, usbcmd::HCRST);
        if !self.poll_until(RESET_TIMEOUT_MS, |h| h.mmio.r32(cmd) & usbcmd::HCRST == 0 && h.mmio.r32(sts) & usbsts::CNR == 0) {
            return Err(XhciError::Timeout("controller reset did not complete"));
        }
        if m.r32(self.op(op::PAGESIZE)) & 1 == 0 {
            return Err(XhciError::Unsupported("controller without 4 KiB page support"));
        }
        Ok(())
    }

    fn setup_structures(&mut self) -> Result<()> {
        let m = self.mmio;
        let ac64 = self.caps.ac64;
        m.w32(self.op(op::CONFIG), self.max_slots as u32);
        // Scratchpad buffers: an array of page pointers in DCBAA entry 0.
        let n = self.caps.max_scratchpad as usize;
        if n > 0 {
            if n > 512 {
                return Err(XhciError::Unsupported("more than 512 scratchpad buffers"));
            }
            let array = DmaPage::new(ac64)?;
            for i in 0..n {
                let page = DmaPage::new(ac64)?;
                array.write64(i * 8, page.phys());
                self._scratchpads.push(page);
            }
            self.dcbaa.write64(0, array.phys());
            self._scratchpad_array = Some(array);
        }
        m.w64(self.op(op::DCBAAP), self.dcbaa.phys());
        let (cmd_start, cycle) = self.cmd.start();
        m.w64(self.op(op::CRCR), cmd_start | u64::from(cycle));
        // Event ring: one segment, interrupter 0.
        let e = erst_entry(self.event_mem.phys(), self.events.segment_len() as u16);
        self._erst.write_dwords(0, &e);
        m.w32(self.ir(rt::ERSTSZ), 1);
        m.w64(self.ir(rt::ERDP), self.events.dequeue_phys());
        m.w64(self.ir(rt::ERSTBA), self._erst.phys());
        m.w32(self.ir(rt::IMOD), IMOD_INTERVAL);
        m.w32(self.ir(rt::IMAN), rt::IMAN_IE | rt::IMAN_IP);
        Ok(())
    }

    fn setup_interrupts(&mut self) {
        let Some(vector) = irq::allocate(irq_handler, self.index as u64) else {
            kprintln!("xhci{}: no MSI vector available, polling every timer tick", self.index);
            return;
        };
        let (address, data) = crate::arch::apic::msi_message(vector);
        let mode = match self.pci.enable_msix(address, data) {
            Ok(()) => Some("MSI-X"),
            Err(why) => {
                kprintln!("xhci{}: MSI-X unavailable ({}), trying MSI", self.index, why);
                match self.pci.enable_msi(address, data) {
                    Ok(()) => Some("MSI"),
                    Err(why) => {
                        kprintln!("xhci{}: MSI unavailable ({}), polling every timer tick", self.index, why);
                        None
                    }
                }
            }
        };
        match mode {
            Some(m) => {
                self.irq_vector = Some(vector);
                self.irq_mode = m;
                kprintln!("xhci{}: event interrupts via {} on vector {:#x}", self.index, m, vector);
            }
            None => irq::free(vector),
        }
    }

    fn run_controller(&mut self) -> Result<()> {
        let m = self.mmio;
        let mut cmd = usbcmd::RUN | usbcmd::HSEE;
        if self.irq_vector.is_some() {
            cmd |= usbcmd::INTE;
        }
        m.w32(self.op(op::USBCMD), cmd);
        let sts = self.op(op::USBSTS);
        if !self.poll_until(RESET_TIMEOUT_MS, |h| h.mmio.r32(sts) & usbsts::HCH == 0) {
            return Err(XhciError::Timeout("controller did not start"));
        }
        // Power every port if the controller lets software switch power.
        if self.caps.ppc {
            for p in 1..=self.caps.max_ports {
                let v = self.portsc(p);
                if v & portsc::PP == 0 {
                    self.write_portsc(p, portsc::neutral(v) | portsc::PP);
                }
            }
            timer::sleep_ms(20);
        }
        Ok(())
    }

    fn port_is_usb3(&self, port: u8) -> bool {
        self.protocols.iter().any(|p| p.major >= 3 && p.contains(port))
    }

    // ---- events ----------------------------------------------------------------------

    /// Consumes every pending event. Command completions are stored for
    /// their waiters, control endpoint events go to their device, interrupt
    /// endpoint events are handled at once (HID reports), port changes are
    /// queued for the main loop.
    fn pump(&mut self) -> usize {
        let m = self.mmio;
        // Acknowledge the interrupt before reading, so an event that arrives
        // meanwhile raises a new one.
        m.w32(self.ir(rt::IMAN), rt::IMAN_IE | rt::IMAN_IP);
        m.w32(self.op(op::USBSTS), usbsts::EINT);
        let mut n = 0;
        while let Some(ev) = self.events.pop(&self.event_mem) {
            n += 1;
            match ev.trb_type() {
                Some(TrbType::CommandCompletion) => {
                    let ptr = ev.param() & !0xF;
                    let _ = self.cmd.retire(ptr);
                    self.completions.insert(ptr, ev);
                }
                Some(TrbType::TransferEvent) => self.transfer_event(ev),
                Some(TrbType::PortStatusChange) => {
                    let p = ev.port_id();
                    if !self.pending_ports.contains(&p) {
                        self.pending_ports.push_back(p);
                    }
                }
                Some(TrbType::HostController) => {
                    kprintln!("xhci{}: host controller event: {:?}", self.index, ev.completion_code());
                }
                _ => {}
            }
        }
        if n > 0 {
            // New dequeue pointer; writing EHB clears the busy flag.
            m.w64(self.ir(rt::ERDP), self.events.dequeue_phys() | rt::ERDP_EHB);
        }
        let status = m.r32(self.op(op::USBSTS));
        if status & (usbsts::HSE | usbsts::HCE) != 0 {
            kprintln!("xhci{}: controller error, USBSTS {:#x}", self.index, status);
        }
        n
    }

    fn transfer_event(&mut self, ev: Trb) {
        let (slot, dci) = (ev.slot_id(), ev.endpoint_id());
        let Some(dev) = self.devices.get_mut(&slot) else { return }; // stale: device gone
        if dci == 1 {
            let _ = dev.ep0.retire(ev.param() & !0xF);
            dev.ep0_events.push(ev);
            return;
        }
        if dev.bt.as_ref().is_some_and(|b| b.owns(dci)) {
            self.bt_transfer_event(slot, ev);
            return;
        }
        if let Some(i) = dev.interrupt.iter().position(|e| e.dci == dci) {
            let ep = &mut dev.interrupt[i];
            let ptr = ev.param() & !0xF;
            let _ = ep.ring.retire(ptr);
            if ep.pending != Some(ptr) {
                return;
            }
            ep.pending = None;
            let code = ev.completion_code();
            if code.is_ok() {
                ep.errors = 0;
                let len = (ep.len as u32).saturating_sub(ev.transfer_residual()) as usize;
                let mut data = [0u8; 64];
                ep.buffer.copy_out(&mut data[..len.min(64)]);
                if let Err(e) = ep.function.report(&data[..len.min(64)]) {
                    if ep.function.bad_reports <= 3 {
                        kprintln!("usb {}: ignored a malformed HID report ({:?}, {} bytes)", dev.name, e, len);
                    }
                }
            } else {
                ep.errors += 1;
                if ep.errors <= 3 || ep.errors == MAX_ENDPOINT_ERRORS {
                    kprintln!("usb {}: interrupt endpoint {} transfer error {:?} ({} in a row)", dev.name, dci, code, ep.errors);
                }
                if code.halts_endpoint() {
                    let s = slot;
                    self.recover_endpoint(s, dci);
                }
            }
            let s = slot;
            self.queue_interrupt(s, dci);
            return;
        }
        // Bulk endpoints: hand the completion to the transfer in flight.
        if let Some(ep) = dev.bulk.iter_mut().find(|e| e.dci == dci) {
            let ptr = ev.param() & !0xF;
            let _ = ep.ring.retire(ptr);
            if ep.pending == Some(ptr) {
                ep.pending = None;
                ep.last = Some((ptr, ev.completion_code(), ev.transfer_residual()));
            }
        }
    }

    /// Blocks until an interrupt (or one tick when polling), a queued
    /// storage request (only when `allow_storage`, because the controller
    /// thread is the only one that may run them), or `deadline_tick`.
    fn wait_activity(&mut self, deadline_tick: u64, allow_storage: bool) {
        let index = self.index;
        let seen = self.seen_irqs;
        if !timer::healthy() {
            // No ticks to end a blocking wait: poll once per (spun) tick.
            timer::pause_tick();
            self.seen_irqs = IRQS[index].load(Ordering::Relaxed);
            return;
        }
        let polling = self.irq_vector.is_none();
        let limit = if polling { (interrupts::ticks() + 1).min(deadline_tick) } else { deadline_tick };
        let events = &self.events;
        let mem = &self.event_mem;
        let _ = block_on(&[&WAKE[index], &storage::WAKE], Some(limit), || {
            let work = allow_storage && (storage::has_work(index) || crate::bluetooth::has_tx(index));
            (IRQS[index].load(Ordering::Relaxed) != seen || work || events.ready(mem)).then_some(())
        });
        self.seen_irqs = IRQS[index].load(Ordering::Relaxed);
    }

    // ---- commands and transfers ----------------------------------------------------------

    fn command(&mut self, trb: Trb) -> Result<Trb> {
        let ptr = self.cmd.push_td(&mut self.cmd_mem, &[trb])?;
        fence(Ordering::SeqCst);
        self.mmio.w32(self.caps.doorbell(0), 0);
        let deadline = Deadline::after_ms(COMMAND_TIMEOUT_MS);
        loop {
            self.pump();
            if let Some(ev) = self.completions.remove(&ptr) {
                return match ev.completion_code() {
                    CompletionCode::Success => Ok(ev),
                    c => Err(XhciError::Command(c)),
                };
            }
            if deadline.expired() {
                self.abort_command();
                return Err(XhciError::Timeout("command"));
            }
            self.wait_activity(deadline.tick(), false);
        }
    }

    /// Stops a command the controller did not complete (xHCI 4.6.1.2).
    fn abort_command(&mut self) {
        let crcr = self.op(op::CRCR);
        self.mmio.w64(crcr, regs::crcr::CA);
        let stopped = self.poll_until(COMMAND_TIMEOUT_MS, |h| h.mmio.r64(crcr) & regs::crcr::CRR == 0);
        kprintln!("xhci{}: command timed out; ring {}", self.index, if stopped { "stopped" } else { "did not stop" });
        self.pump();
    }

    fn ring_doorbell(&self, slot: u8, target: u8) {
        fence(Ordering::SeqCst);
        self.mmio.w32(self.caps.doorbell(slot), target as u32);
    }

    /// A control transfer on the default endpoint; `data` is the OUT data
    /// or the IN buffer. Returns the bytes transferred in the data stage.
    fn control(&mut self, slot: u8, setup: SetupPacket, data: &mut [u8]) -> Result<usize> {
        let len = setup.length as usize;
        if len > data.len() || len > 4096 {
            return Err(XhciError::Unsupported("control transfer larger than 4 KiB"));
        }
        let dir_in = setup.is_in();
        let (status_ptr, data_present) = {
            let dev = self.devices.get_mut(&slot).ok_or(XhciError::BadSlot)?;
            if !dir_in && len > 0 {
                dev.buffer.copy_in(&data[..len]);
            }
            let mut trbs = vec![Trb::setup(&setup)];
            if len > 0 {
                trbs.push(Trb::data(dev.buffer.phys(), len as u32, dir_in));
            }
            trbs.push(Trb::status_stage(dir_in, len > 0));
            dev.ep0_events.clear();
            // Each stage is its own TD (xHCI 4.11.2.2): chaining Setup into
            // Data sets a reserved bit, which real controllers answer with a
            // USB Transaction Error. The doorbell follows the last stage.
            let mut last = 0;
            for trb in &trbs {
                last = dev.ep0.push_td(&mut dev.ep0_mem, core::slice::from_ref(trb))?;
            }
            (last, len > 0)
        };
        self.ring_doorbell(slot, 1);
        let deadline = Deadline::after_ms(TRANSFER_TIMEOUT_MS);
        loop {
            self.pump();
            let dev = self.devices.get_mut(&slot).ok_or(XhciError::PortGone)?;
            if let Some(bad) = dev.ep0_events.iter().find(|e| !e.completion_code().is_ok()) {
                let code = bad.completion_code();
                dev.ep0_events.clear();
                if code.halts_endpoint() {
                    self.recover_endpoint(slot, 1);
                }
                return Err(XhciError::Transfer(code));
            }
            if dev.ep0_events.iter().any(|e| e.param() & !0xF == status_ptr) {
                let short = dev.ep0_events.iter().find(|e| e.completion_code() == CompletionCode::ShortPacket);
                let done = match short {
                    Some(e) if data_present => len.saturating_sub(e.transfer_residual() as usize),
                    _ => len,
                };
                dev.ep0_events.clear();
                if dir_in && done > 0 {
                    dev.buffer.copy_out(&mut data[..done]);
                }
                return Ok(done);
            }
            if deadline.expired() {
                return Err(XhciError::Timeout("control transfer"));
            }
            self.wait_activity(deadline.tick(), false);
        }
    }

    fn control_in(&mut self, slot: u8, setup: SetupPacket, buf: &mut [u8]) -> Result<usize> {
        self.control(slot, setup, buf)
    }

    fn control_out(&mut self, slot: u8, setup: SetupPacket, data: &[u8]) -> Result<()> {
        let mut copy = data.to_vec();
        self.control(slot, setup, &mut copy).map(|_| ())
    }

    /// Resets a halted endpoint and moves its dequeue pointer past whatever
    /// was in flight (xHCI 4.6.8, 4.6.10).
    fn recover_endpoint(&mut self, slot: u8, dci: u8) {
        if let Err(e) = self.command(Trb::reset_endpoint(slot, dci)) {
            kprintln!("xhci{}: reset of slot {} endpoint {} failed: {}", self.index, slot, dci, e);
            return;
        }
        let Some(dev) = self.devices.get_mut(&slot) else { return };
        let (ptr, cycle) = if dci == 1 {
            dev.ep0.reset_dequeue();
            dev.ep0.start()
        } else if let Some(ep) = dev.interrupt.iter_mut().find(|e| e.dci == dci) {
            ep.ring.reset_dequeue();
            ep.pending = None;
            ep.ring.start()
        } else if let Some(ep) = dev.bulk.iter_mut().find(|e| e.dci == dci) {
            ep.ring.reset_dequeue();
            ep.pending = None;
            ep.last = None;
            ep.ring.start()
        } else {
            return;
        };
        if let Err(e) = self.command(Trb::set_tr_dequeue(ptr, cycle, slot, dci)) {
            kprintln!("xhci{}: moving the dequeue pointer of slot {} endpoint {} failed: {}", self.index, slot, dci, e);
        }
    }

    /// Queues the next interrupt IN transfer of an endpoint.
    fn queue_interrupt(&mut self, slot: u8, dci: u8) {
        let Some(dev) = self.devices.get_mut(&slot) else { return };
        let Some(ep) = dev.interrupt.iter_mut().find(|e| e.dci == dci) else { return };
        if ep.pending.is_some() || ep.errors >= MAX_ENDPOINT_ERRORS {
            return;
        }
        let trb = Trb::normal(ep.buffer.phys(), ep.len as u32, true);
        match ep.ring.push_td(&mut ep.mem, &[trb]) {
            Ok(ptr) => {
                ep.pending = Some(ptr);
                self.ring_doorbell(slot, dci);
            }
            Err(e) => kprintln!("usb {}: cannot queue an interrupt transfer: {:?}", dev.name, e),
        }
    }

    // ---- ports and devices --------------------------------------------------------------

    fn port_changed(&mut self, port: u8) {
        if port == 0 || port > self.caps.max_ports {
            return;
        }
        let v = self.portsc(port);
        // Acknowledge the change bits.
        self.write_portsc(port, portsc::neutral(v) | (v & portsc::CHANGE_BITS));
        let connected = v & portsc::CCS != 0;
        let attached = self.ports.contains_key(&port);
        let replaced = connected && attached && v & portsc::CSC != 0;
        if attached && (!connected || replaced) {
            self.detach(port);
        }
        if connected && (!attached || replaced) {
            match self.attach(port) {
                Ok(()) => {}
                Err(e) => {
                    kprintln!("usb: port {}: device not usable: {}", port, e);
                    if let Some(slot) = self.ports.get(&port).copied() {
                        self.release_slot(port, slot);
                    }
                }
            }
        }
        let n = self.devices.len();
        set_status(self.index, alloc::format!("xhci{}: running, {} interrupts, {} devices", self.index, self.irq_mode, n));
    }

    fn reset_port(&mut self, port: u8) -> Result<()> {
        let v = self.portsc(port);
        self.write_portsc(port, portsc::neutral(v) | portsc::PR);
        let ok = self.poll_until(PORT_RESET_TIMEOUT_MS, |h| {
            let v = h.portsc(port);
            v & portsc::PRC != 0 || v & portsc::CCS == 0
        });
        let v = self.portsc(port);
        self.write_portsc(port, portsc::neutral(v) | (v & portsc::CHANGE_BITS));
        if v & portsc::CCS == 0 {
            return Err(XhciError::PortGone);
        }
        if !ok {
            return Err(XhciError::Timeout("port reset"));
        }
        Ok(())
    }

    fn attach(&mut self, port: u8) -> Result<()> {
        timer::sleep_ms(DEBOUNCE_MS);
        let mut attempt = 1;
        loop {
            match self.attach_once(port, attempt > 1) {
                Ok(()) => return Ok(()),
                Err(XhciError::PortGone) => return Err(XhciError::PortGone),
                Err(e) if attempt == ATTACH_ATTEMPTS => return Err(e),
                Err(e) => {
                    kprintln!("usb: port {}: attempt {} failed: {}; resetting the port again", port, attempt, e);
                    if let Some(slot) = self.ports.get(&port).copied() {
                        self.release_slot(port, slot);
                    }
                    timer::sleep_ms(DEBOUNCE_MS);
                    attempt += 1;
                }
            }
        }
    }

    /// One reset-address-enumerate pass. `force_reset` also resets a USB 3
    /// port that is already enabled.
    fn attach_once(&mut self, port: u8, force_reset: bool) -> Result<()> {
        let usb3 = self.port_is_usb3(port);
        if force_reset || !usb3 || self.portsc(port) & portsc::PED == 0 {
            self.reset_port(port)?;
        }
        let v = self.portsc(port);
        if v & portsc::CCS == 0 {
            return Err(XhciError::PortGone);
        }
        if v & portsc::PED == 0 {
            return Err(XhciError::Unsupported("port not enabled after reset"));
        }
        let speed = Speed::from_psi(portsc::speed(v)).ok_or(XhciError::Unsupported("unknown port speed"))?;
        kprintln!("usb: port {}: {} device connected (USB {} port)", port, speed.name(), if usb3 { 3 } else { 2 });
        // Reset recovery time (USB 2.0 7.1.7.5: 10 ms).
        timer::sleep_ms(10);
        let ev = self.command(Trb::enable_slot(0))?;
        let slot = ev.slot_id();
        if slot == 0 || slot > self.max_slots {
            return Err(XhciError::BadSlot);
        }
        let dev = Device::new(port, speed, self.caps.ac64)?;
        self.dcbaa.write64(slot as usize * 8, dev.output.phys());
        self.devices.insert(slot, dev);
        self.ports.insert(port, slot);
        self.address_device(slot)?;
        self.enumerate(slot)
    }

    fn address_device(&mut self, slot: u8) -> Result<()> {
        let l = self.layout;
        let dev = self.devices.get_mut(&slot).ok_or(XhciError::BadSlot)?;
        dev.input.zero();
        dev.input.write_dwords(l.input_control(), &context::input_control(0b11, 0));
        let sc = dev.slot_context(1);
        dev.input.write_dwords(l.input_slot(), &sc.encode());
        let (deq, dcs) = dev.ep0.start();
        let ep0 = EndpointContext {
            ep_type: EndpointType::Control,
            max_packet: dev.ep0_max_packet,
            max_burst: 0,
            interval: 0,
            dequeue: deq,
            dcs,
            average_trb_length: 8,
            max_esit_payload: 0,
            error_count: 3,
        };
        dev.input.write_dwords(l.input_endpoint(1), &ep0.encode());
        let input = dev.input.phys();
        self.command(Trb::address_device(input, slot, false))?;
        let dev = &self.devices[&slot];
        let mut out = [0u32; 8];
        dev.output.read_dwords(l.device_slot(), &mut out);
        let st = context::SlotState::decode(&out);
        kprintln!("usb: port {}: slot {} addressed, USB address {}", dev.port, slot, st.device_address);
        // SET_ADDRESS recovery (USB 2.0 9.2.6.3 allows 2 ms; Linux gives 10).
        timer::sleep_ms(10);
        Ok(())
    }

    /// Updates the default endpoint's max packet size (Evaluate Context).
    fn set_ep0_max_packet(&mut self, slot: u8, mps: u16) -> Result<()> {
        let l = self.layout;
        let dev = self.devices.get_mut(&slot).ok_or(XhciError::BadSlot)?;
        dev.ep0_max_packet = mps;
        dev.input.zero();
        dev.input.write_dwords(l.input_control(), &context::input_control(0b10, 0));
        let (deq, dcs) = dev.ep0.start();
        let ep0 = EndpointContext {
            ep_type: EndpointType::Control,
            max_packet: mps,
            max_burst: 0,
            interval: 0,
            dequeue: deq,
            dcs,
            average_trb_length: 8,
            max_esit_payload: 0,
            error_count: 3,
        };
        dev.input.write_dwords(l.input_endpoint(1), &ep0.encode());
        let input = dev.input.phys();
        self.command(Trb::evaluate_context(input, slot)).map(|_| ())
    }

    fn string(&mut self, slot: u8, index: u8, lang: u16) -> Option<String> {
        if index == 0 {
            return None;
        }
        let mut buf = [0u8; 255];
        let n = self.control_in(slot, SetupPacket::get_descriptor(descriptor::DESC_STRING, index, lang, 255), &mut buf).ok()?;
        descriptor::parse_string(&buf[..n]).ok().map(|s| String::from(s.trim()))
    }

    fn enumerate(&mut self, slot: u8) -> Result<()> {
        let usb3 = self.devices[&slot].speed.is_superspeed();
        // The first 8 bytes tell the real max packet size of endpoint 0.
        let mut head = [0u8; 8];
        let n = self.control_in(slot, SetupPacket::get_descriptor(descriptor::DESC_DEVICE, 0, 0, 8), &mut head)?;
        let raw = DeviceDescriptor::max_packet0_from_prefix(&head[..n])?;
        let mps = if usb3 { 1u16 << raw.min(15) } else { raw as u16 };
        if mps != 0 && mps != self.devices[&slot].ep0_max_packet {
            self.set_ep0_max_packet(slot, mps)?;
        }
        let mut dd = [0u8; DeviceDescriptor::LEN];
        let n = self.control_in(slot, SetupPacket::get_descriptor(descriptor::DESC_DEVICE, 0, 0, DeviceDescriptor::LEN as u16), &mut dd)?;
        let desc = DeviceDescriptor::parse(&dd[..n])?;
        let mut c9 = [0u8; 9];
        let n = self.control_in(slot, SetupPacket::get_descriptor(descriptor::DESC_CONFIGURATION, 0, 0, 9), &mut c9)?;
        let total = descriptor::configuration_total_length(&c9[..n])? as usize;
        if total > 4096 {
            return Err(XhciError::Unsupported("configuration descriptor larger than 4 KiB"));
        }
        let mut raw_cfg = vec![0u8; total];
        let n = self.control_in(slot, SetupPacket::get_descriptor(descriptor::DESC_CONFIGURATION, 0, 0, total as u16), &mut raw_cfg)?;
        let cfg = Configuration::parse(&raw_cfg[..n])?;
        let mut langs = [0u8; 4];
        let lang = self
            .control_in(slot, SetupPacket::get_descriptor(descriptor::DESC_STRING, 0, 0, 4), &mut langs)
            .ok()
            .and_then(|n| descriptor::first_language(&langs[..n]))
            .unwrap_or(0x0409);
        let manufacturer = self.string(slot, desc.manufacturer_index, lang).unwrap_or_default();
        let product = self.string(slot, desc.product_index, lang).unwrap_or_default();
        let port = self.devices[&slot].port;
        let name = if product.is_empty() { alloc::format!("{:04x}:{:04x}", desc.vendor, desc.product) } else { product.clone() };
        kprintln!(
            "usb: port {}: {:04x}:{:04x} \"{}\" \"{}\", USB {:x}.{:02x}, class {:02x}, {} configuration(s), {} interface(s), EP0 max packet {}",
            port,
            desc.vendor,
            desc.product,
            manufacturer,
            product,
            desc.usb_version >> 8,
            desc.usb_version & 0xFF,
            desc.class,
            desc.num_configurations,
            cfg.interfaces.len(),
            mps
        );
        let route = self.devices[&slot].route;
        self.devices.get_mut(&slot).expect("device exists").name = if route == 0 {
            alloc::format!("{}-{} ({})", self.index + 1, port, name)
        } else {
            alloc::format!("{}-{}.{:x} ({})", self.index + 1, port, route, name)
        };
        if desc.class == descriptor::CLASS_HUB {
            return self.setup_hub(slot, cfg.value);
        }
        // Functions this driver supports: HID and mass storage (SCSI,
        // bulk-only transport).
        let hid: Vec<Interface> = cfg
            .default_interfaces()
            .filter(|i| i.class == descriptor::CLASS_HID && i.interrupt_in().is_some())
            .cloned()
            .collect();
        let storage: Option<Interface> = cfg
            .default_interfaces()
            .find(|i| {
                i.class == descriptor::CLASS_MASS_STORAGE
                    && i.subclass == descriptor::MASS_STORAGE_SCSI
                    && i.protocol == descriptor::MASS_STORAGE_BOT
                    && i.bulk_in().is_some()
                    && i.bulk_out().is_some()
            })
            .cloned();
        // Bluetooth controllers (interface 0 of class E0/01/01).
        if let Some(iface) = cfg.default_interfaces().find(|i| (i.class, i.subclass, i.protocol) == bt::CLASS && i.number == 0).cloned() {
            let devname = self.devices[&slot].name.clone();
            crate::wireless::usb_device(desc.vendor, desc.product, bt::CLASS, &devname);
            return self.setup_bt(slot, cfg.value, &iface, desc.vendor, desc.product);
        }
        if hid.is_empty() && storage.is_none() {
            // Class 0 devices name their function in the interfaces.
            let class = match (desc.class, cfg.default_interfaces().next()) {
                (0, Some(i)) => (i.class, i.subclass, i.protocol),
                _ => (desc.class, desc.subclass, desc.protocol),
            };
            let devname = self.devices[&slot].name.clone();
            if !crate::wireless::usb_device(desc.vendor, desc.product, class, &devname) {
                kprintln!("usb {}: no supported function (not HID or mass storage); left unconfigured", devname);
            }
            return Ok(());
        }
        self.control_out(slot, SetupPacket::set_configuration(cfg.value), &[])?;
        let mut configured = Vec::new();
        for iface in &hid {
            match self.setup_hid(slot, iface, &name) {
                Ok(Some(f)) => configured.push((iface.clone(), f)),
                Ok(None) => {}
                Err(e) => kprintln!("usb {}: interface {}: {}", self.devices[&slot].name, iface.number, e),
            }
        }
        if configured.is_empty() && storage.is_none() {
            return Ok(());
        }
        self.configure_endpoints(slot, configured, storage.as_ref())?;
        if storage.is_some() {
            if let Err(e) = self.setup_storage(slot) {
                kprintln!("usb {}: mass storage: {}", self.devices[&slot].name, e);
            }
        }
        Ok(())
    }

    /// Prepares a HID interface: protocol, idle rate, report layout.
    fn setup_hid(&mut self, slot: u8, iface: &Interface, name: &str) -> Result<Option<HidFunction>> {
        let devname = self.devices[&slot].name.clone();
        let boot = iface.subclass == descriptor::HID_SUBCLASS_BOOT;
        if iface.is_hid_boot(descriptor::HID_PROTOCOL_KEYBOARD) {
            self.control_out(slot, SetupPacket::hid_set_protocol(iface.number, false), &[])?;
            // Report only on change; some keyboards stall this request.
            let _ = self.control_out(slot, SetupPacket::hid_set_idle(iface.number, 0), &[]);
            let id = input::register(name, input::class::KEYBOARD);
            kprintln!("usb {}: HID boot keyboard on interface {} -> input device {}", devname, iface.number, id);
            return Ok(Some(HidFunction {
                interface: iface.number,
                input_id: id,
                kind: HidKind::Keyboard { state: BootKeyboard::new(), applied_leds: 0 },
                reports: 0,
                bad_reports: 0,
            }));
        }
        // A pointer: prefer the report descriptor (wheel, more buttons).
        let mut layout = None;
        let len = iface.hid.map_or(0, |h| h.report_length).min(1024);
        if len > 0 {
            let mut rd = vec![0u8; len as usize];
            match self.control_in(slot, SetupPacket::get_interface_descriptor(descriptor::DESC_HID_REPORT, iface.number, len), &mut rd) {
                Ok(n) => match parse_report_descriptor(&rd[..n]) {
                    Ok(fields) => layout = MouseLayout::from_fields(&fields),
                    Err(e) => kprintln!("usb {}: interface {}: report descriptor rejected: {:?}", devname, iface.number, e),
                },
                Err(e) => kprintln!("usb {}: interface {}: no report descriptor: {}", devname, iface.number, e),
            }
        }
        let is_boot_mouse = iface.is_hid_boot(descriptor::HID_PROTOCOL_MOUSE);
        let how = match (&layout, is_boot_mouse) {
            (Some(l), _) => {
                if boot {
                    self.control_out(slot, SetupPacket::hid_set_protocol(iface.number, true), &[])?;
                }
                alloc::format!(
                    "report protocol: {} buttons, {}-bit X/Y{}{}",
                    l.buttons.len(),
                    l.x.size,
                    if l.wheel.is_some() { ", wheel" } else { "" },
                    if l.pan.is_some() { ", horizontal wheel" } else { "" }
                )
            }
            (None, true) => {
                self.control_out(slot, SetupPacket::hid_set_protocol(iface.number, false), &[])?;
                String::from("boot protocol: 3 buttons, 8-bit X/Y")
            }
            (None, false) => {
                kprintln!(
                    "usb {}: HID interface {} (subclass {}, protocol {}) is not a boot keyboard or relative pointer: not supported",
                    devname,
                    iface.number,
                    iface.subclass,
                    iface.protocol
                );
                return Ok(None);
            }
        };
        let _ = self.control_out(slot, SetupPacket::hid_set_idle(iface.number, 0), &[]);
        let id = input::register(name, input::class::MOUSE);
        kprintln!("usb {}: HID mouse on interface {} ({}) -> input device {}", devname, iface.number, how, id);
        Ok(Some(HidFunction { interface: iface.number, input_id: id, kind: HidKind::Mouse { layout, buttons: 0 }, reports: 0, bad_reports: 0 }))
    }

    /// Configure Endpoint for every HID interrupt IN endpoint and for the
    /// mass-storage bulk endpoints, then starts the interrupt transfers.
    fn configure_endpoints(&mut self, slot: u8, functions: Vec<(Interface, HidFunction)>, storage: Option<&Interface>) -> Result<()> {
        let l = self.layout;
        let ac64 = self.caps.ac64;
        let dev = self.devices.get_mut(&slot).ok_or(XhciError::BadSlot)?;
        dev.input.zero();
        let mut add = 1u32; // slot context
        let mut max_dci = 1;
        let mut endpoints = Vec::new();
        for (iface, function) in functions {
            let ep = *iface.interrupt_in().expect("filtered for an interrupt IN endpoint");
            let dci = osyx_usb::xhci::dci(ep.address);
            let mem = DmaRing::new(ac64)?;
            let ring = ProducerRing::new(&mem);
            let (deq, dcs) = ring.start();
            let ep_type = EndpointType::InterruptIn;
            let max_packet = ep.max_packet.max(1);
            let payload = max_packet as u32 * (ep.mult as u32 + 1) * (ep.max_burst as u32 + 1);
            let ctx = EndpointContext {
                ep_type,
                max_packet,
                max_burst: ep.max_burst,
                interval: context::periodic_interval(dev.speed, ep_type, ep.interval),
                dequeue: deq,
                dcs,
                average_trb_length: max_packet,
                max_esit_payload: payload,
                error_count: 3,
            };
            dev.input.write_dwords(l.input_endpoint(dci), &ctx.encode());
            add |= 1 << dci;
            max_dci = max_dci.max(dci);
            kprintln!(
                "usb {}: endpoint {:#04x} (DCI {}): interrupt IN, {} bytes, bInterval {}, xHCI interval {}",
                dev.name,
                ep.address,
                dci,
                max_packet,
                ep.interval,
                ctx.interval
            );
            endpoints.push(InterruptEndpoint {
                dci,
                ring,
                mem,
                buffer: DmaPage::new(ac64)?,
                len: max_packet.min(64),
                pending: None,
                errors: 0,
                function,
            });
        }
        let mut bulks = Vec::new();
        if let Some(iface) = storage {
            for (ep, ep_type) in [(iface.bulk_out(), EndpointType::BulkOut), (iface.bulk_in(), EndpointType::BulkIn)] {
                let Some(ep) = ep else { continue };
                let dci = osyx_usb::xhci::dci(ep.address);
                let mem = DmaRing::new(ac64)?;
                let ring = ProducerRing::new(&mem);
                let (deq, dcs) = ring.start();
                let max_packet = ep.max_packet.max(1);
                let ctx = EndpointContext {
                    ep_type,
                    max_packet,
                    max_burst: ep.max_burst,
                    interval: 0,
                    dequeue: deq,
                    dcs,
                    average_trb_length: max_packet,
                    max_esit_payload: 0,
                    error_count: 3,
                };
                dev.input.write_dwords(l.input_endpoint(dci), &ctx.encode());
                add |= 1 << dci;
                max_dci = max_dci.max(dci);
                kprintln!(
                    "usb {}: endpoint {:#04x} (DCI {}): bulk {}, {} bytes, max burst {}",
                    dev.name,
                    ep.address,
                    dci,
                    if ep.is_in() { "IN" } else { "OUT" },
                    max_packet,
                    ep.max_burst
                );
                bulks.push(BulkEndpoint { dci, in_endpoint: ep.is_in(), ring, mem, pending: None, last: None });
            }
        }
        dev.input.write_dwords(l.input_control(), &context::input_control(add, 0));
        let sc = dev.slot_context(max_dci);
        dev.input.write_dwords(l.input_slot(), &sc.encode());
        let input = dev.input.phys();
        dev.interrupt = endpoints;
        dev.bulk = bulks;
        if let Err(e) = self.command(Trb::configure_endpoint(input, slot, false)) {
            // The functions were registered with the input core: undo that.
            if let Some(dev) = self.devices.get_mut(&slot) {
                for ep in dev.interrupt.drain(..) {
                    input::unregister(ep.function.input_id);
                }
                dev.bulk.clear();
            }
            return Err(e);
        }
        let dcis: Vec<u8> = self.devices[&slot].interrupt.iter().map(|e| e.dci).collect();
        for dci in dcis {
            self.queue_interrupt(slot, dci);
        }
        Ok(())
    }

    fn detach(&mut self, port: u8) {
        let Some(slot) = self.ports.get(&port).copied() else { return };
        let name = self.devices.get(&slot).map_or(String::new(), |d| d.name.clone());
        kprintln!("usb {}: disconnected from port {}", name, port);
        self.release_slot(port, slot);
    }

    /// Tells the input core the functions are gone, disables the slot (the
    /// controller stops every endpoint) and only then frees the memory the
    /// controller used.
    fn release_slot(&mut self, port: u8, slot: u8) {
        self.release_device(slot);
        self.ports.remove(&port);
        kprintln!("usb: port {}: slot {} released", port, slot);
    }

    /// Releases a device and, for a hub, every device behind it first.
    fn release_device(&mut self, slot: u8) {
        let children: Vec<u8> = self.devices.get(&slot).and_then(|d| d.hub.as_ref()).map_or(Vec::new(), |h| h.children.values().copied().collect());
        for child in children {
            if let Some(name) = self.devices.get(&child).map(|d| d.name.clone()) {
                kprintln!("usb {}: gone with its hub", name);
            }
            self.release_device(child);
        }
        if let Some(dev) = self.devices.get_mut(&slot) {
            // A mass-storage drive: its I/O fails from now on, queued
            // requests end at once, and the storage manager takes the
            // volumes away (from its own thread: unmounting writes to the
            // disk through this very controller thread).
            if let Some(state) = &dev.storage {
                state.gone.store(true, Ordering::Release);
                storage::fail_pending(self.index, slot);
                kprintln!("usb {}: storage {} removed", dev.name, state.disk_name);
                if !state.disk_name.is_empty() {
                    crate::media::disk_gone(&state.disk_name);
                }
            }
            crate::wireless::usb_gone(&dev.name);
            if let Some(bt) = &dev.bt {
                crate::bluetooth::unregister(bt.unit());
            }
            for ep in &dev.interrupt {
                input::unregister(ep.function.input_id);
            }
            let reports: u64 = dev.interrupt.iter().map(|e| e.function.reports).sum();
            if !dev.interrupt.is_empty() {
                kprintln!("usb {}: {} HID reports processed", dev.name, reports);
            }
        }
        match self.command(Trb::disable_slot(slot)) {
            Ok(_) => {}
            Err(e) => kprintln!("xhci{}: disable slot {} failed: {}", self.index, slot, e),
        }
        self.dcbaa.write64(slot as usize * 8, 0);
        self.devices.remove(&slot);
    }

    // ---- hubs -----------------------------------------------------------------------------

    /// Configures a hub, powers its ports and attaches what is connected.
    fn setup_hub(&mut self, slot: u8, config: u8) -> Result<()> {
        if self.devices[&slot].depth >= 5 {
            return Err(XhciError::Unsupported("more than five tiers of hubs"));
        }
        if self.devices[&slot].speed.is_superspeed() {
            return Err(XhciError::Unsupported("SuperSpeed hubs (their USB 2.0 half is used instead)"));
        }
        self.control_out(slot, SetupPacket::set_configuration(config), &[])?;
        let mut d = [0u8; 9];
        let n = self.control_in(slot, hubreq::hub_descriptor(), &mut d)?;
        if n < 7 || d[1] != 0x29 {
            return Err(XhciError::Unsupported("hub descriptor"));
        }
        let ports = d[2].min(15);
        let characteristics = u16::from_le_bytes([d[3], d[4]]);
        let power_on_ms = d[5] as u64 * 2;
        // A high-speed hub with one TT per port reports protocol 2.
        let mtt = self.devices[&slot].speed == Speed::High && self.interface_protocol(slot) == 2;
        let ttt = ((characteristics >> 5) & 3) as u8;
        let dev = self.devices.get_mut(&slot).ok_or(XhciError::BadSlot)?;
        dev.hub = Some(Hub { ports, mtt, ttt, children: BTreeMap::new() });
        // Tell the controller it is a hub (Configure Endpoint, slot only).
        let l = self.layout;
        dev.input.zero();
        dev.input.write_dwords(l.input_control(), &context::input_control(1, 0));
        let sc = dev.slot_context(1);
        dev.input.write_dwords(l.input_slot(), &sc.encode());
        let input = dev.input.phys();
        let name = dev.name.clone();
        self.command(Trb::configure_endpoint(input, slot, false))?;
        kprintln!("usb {}: hub with {} ports{}", name, ports, if mtt { ", one TT per port" } else { "" });
        for p in 1..=ports {
            self.control_out(slot, hubreq::set_port(p, hubreq::PORT_POWER), &[])?;
        }
        timer::sleep_ms(power_on_ms.max(20) + 100);
        for p in 1..=ports {
            self.hub_port_changed(slot, p, true);
        }
        Ok(())
    }

    /// bInterfaceProtocol of the hub's interface (1 single TT, 2 multi TT).
    fn interface_protocol(&mut self, slot: u8) -> u8 {
        let mut c = [0u8; 18];
        match self.control_in(slot, SetupPacket::get_descriptor(descriptor::DESC_CONFIGURATION, 0, 0, 18), &mut c) {
            Ok(n) if n >= 18 => c[16],
            _ => 0,
        }
    }

    fn hub_port_status(&mut self, slot: u8, port: u8) -> Option<(u16, u16)> {
        let mut st = [0u8; 4];
        match self.control_in(slot, hubreq::port_status(port), &mut st) {
            Ok(4) => Some((u16::from_le_bytes([st[0], st[1]]), u16::from_le_bytes([st[2], st[3]]))),
            _ => None,
        }
    }

    /// Handles a connect or disconnect on a hub port (`initial`: the first
    /// scan after the hub was configured, where nothing is attached yet).
    fn hub_port_changed(&mut self, hub_slot: u8, port: u8, initial: bool) {
        let Some((status, change)) = self.hub_port_status(hub_slot, port) else { return };
        if !initial && change & hubreq::CHANGE_CONNECTION == 0 {
            return;
        }
        if change & hubreq::CHANGE_CONNECTION != 0 {
            let _ = self.control_out(hub_slot, hubreq::clear_port(port, hubreq::C_PORT_CONNECTION), &[]);
        }
        let existing = self.devices.get(&hub_slot).and_then(|d| d.hub.as_ref()).and_then(|h| h.children.get(&port).copied());
        if let Some(child) = existing {
            if let Some(name) = self.devices.get(&child).map(|d| d.name.clone()) {
                kprintln!("usb {}: disconnected from its hub", name);
            }
            self.release_device(child);
            if let Some(h) = self.devices.get_mut(&hub_slot).and_then(|d| d.hub.as_mut()) {
                h.children.remove(&port);
            }
        }
        if status & hubreq::CONNECTION == 0 {
            return;
        }
        for attempt in 1..=ATTACH_ATTEMPTS {
            let Err(e) = self.attach_behind_hub(hub_slot, port) else { break };
            let hub = self.devices.get(&hub_slot).map_or(String::new(), |d| d.name.clone());
            if matches!(e, XhciError::PortGone) || attempt == ATTACH_ATTEMPTS {
                kprintln!("usb {}: port {}: device not usable: {}", hub, port, e);
                break;
            }
            kprintln!("usb {}: port {}: attempt {} failed: {}; resetting the port again", hub, port, attempt, e);
        }
    }

    fn attach_behind_hub(&mut self, hub_slot: u8, port: u8) -> Result<()> {
        // Debounce, reset, wait for the reset to finish.
        timer::sleep_ms(100);
        self.control_out(hub_slot, hubreq::set_port(port, hubreq::PORT_RESET), &[])?;
        let mut status = 0;
        let mut done = false;
        for _ in 0..50 {
            timer::sleep_ms(10);
            if let Some((s, c)) = self.hub_port_status(hub_slot, port) {
                status = s;
                if c & hubreq::CHANGE_RESET != 0 {
                    done = true;
                    break;
                }
            }
        }
        let _ = self.control_out(hub_slot, hubreq::clear_port(port, hubreq::C_PORT_RESET), &[]);
        let _ = self.control_out(hub_slot, hubreq::clear_port(port, hubreq::C_PORT_ENABLE), &[]);
        if !done {
            return Err(XhciError::Timeout("hub port reset"));
        }
        if status & hubreq::CONNECTION == 0 {
            return Err(XhciError::PortGone);
        }
        if status & hubreq::ENABLE == 0 {
            return Err(XhciError::Unsupported("hub port not enabled after reset"));
        }
        timer::sleep_ms(10);
        let speed = if status & hubreq::LOW_SPEED != 0 {
            Speed::Low
        } else if status & hubreq::HIGH_SPEED != 0 {
            Speed::High
        } else {
            Speed::Full
        };
        let hub = &self.devices[&hub_slot];
        let (root, route, depth) = (hub.port, hub.route | ((port as u32 & 0xF) << (4 * hub.depth)), hub.depth + 1);
        // The nearest high-speed hub translates for low/full-speed devices.
        let tt = if hub.speed == Speed::High && matches!(speed, Speed::Low | Speed::Full) { (hub_slot, port) } else { hub.tt };
        let hub_name = hub.name.clone();
        kprintln!("usb {}: port {}: {} device connected", hub_name, port, speed.name());
        let ev = self.command(Trb::enable_slot(0))?;
        let slot = ev.slot_id();
        if slot == 0 || slot > self.max_slots {
            return Err(XhciError::BadSlot);
        }
        let mut dev = Device::new(root, speed, self.caps.ac64)?;
        dev.route = route;
        dev.depth = depth;
        dev.tt = tt;
        self.dcbaa.write64(slot as usize * 8, dev.output.phys());
        self.devices.insert(slot, dev);
        if let Some(h) = self.devices.get_mut(&hub_slot).and_then(|d| d.hub.as_mut()) {
            h.children.insert(port, slot);
        }
        let result = self.address_device(slot).and_then(|_| self.enumerate(slot));
        if result.is_err() {
            self.release_device(slot);
            if let Some(h) = self.devices.get_mut(&hub_slot).and_then(|d| d.hub.as_mut()) {
                h.children.remove(&port);
            }
        }
        result
    }

    /// Looks for connects and disconnects on every hub's ports.
    fn scan_hubs(&mut self) {
        let hubs: Vec<(u8, u8)> = self.devices.iter().filter_map(|(s, d)| d.hub.as_ref().map(|h| (*s, h.ports))).collect();
        for (slot, ports) in hubs {
            for p in 1..=ports {
                if self.devices.contains_key(&slot) {
                    self.hub_port_changed(slot, p, false);
                }
            }
        }
    }

    /// Applies the keyboard LED state of the input core (Caps/Num Lock).
    fn update_leds(&mut self) {
        let want = input::leds();
        let mut todo = Vec::new();
        for (slot, dev) in &self.devices {
            for ep in &dev.interrupt {
                if let HidKind::Keyboard { applied_leds, .. } = ep.function.kind {
                    if applied_leds != want {
                        todo.push((*slot, ep.dci, ep.function.interface));
                    }
                }
            }
        }
        for (slot, dci, iface) in todo {
            let ok = self.control_out(slot, SetupPacket::hid_set_output_report(iface, 0, 1), &[want]).is_ok();
            if let Some(ep) = self.devices.get_mut(&slot).and_then(|d| d.interrupt.iter_mut().find(|e| e.dci == dci)) {
                if let HidKind::Keyboard { applied_leds, .. } = &mut ep.function.kind {
                    // A keyboard without LEDs may stall: do not retry forever.
                    *applied_leds = want;
                }
            }
            if !ok {
                kprintln!("usb: keyboard in slot {} did not accept the LED report", slot);
            }
        }
    }

    fn run(&mut self) -> ! {
        for p in 1..=self.caps.max_ports {
            if self.portsc(p) & portsc::CCS != 0 && !self.pending_ports.contains(&p) {
                self.pending_ports.push_back(p);
            }
        }
        let mut announced = false;
        loop {
            self.pump();
            self.service_storage();
            self.service_bt();
            while let Some(p) = self.pending_ports.pop_front() {
                self.port_changed(p);
                self.pump();
            }
            if !announced {
                announced = true;
                READY[self.index].store(true, Ordering::Release);
            }
            self.update_leds();
            self.scan_hubs();
            let deadline = interrupts::ticks() + timer::ms_to_ticks(1000);
            self.wait_activity(deadline, true);
        }
    }
}

/// USB legacy support (USBLEGSUP): asks the firmware to release the
/// controller, waits a bounded time for it, and disables its SMIs (xHCI
/// 4.22.1). Firmware that keeps the controller (or whose SMI handler
/// hangs) costs at most `HANDOFF_TIMEOUT_MS`; the controller is then
/// taken anyway, and a failing reset afterwards only fails this controller.
fn take_ownership(index: usize, m: Mmio, off: u64) {
    let v = m.r32(off);
    if v == u32::MAX {
        kprintln!("xhci{}: legacy support register reads all ones; skipping the firmware handoff", index);
        return;
    }
    if v & ext::BIOS_OWNED != 0 {
        kprintln!("xhci{}: firmware owns the controller (USBLEGSUP {:#x}); requesting handoff", index, v);
        m.w32(off, v | ext::OS_OWNED);
        let released = poll_mmio(HANDOFF_TIMEOUT_MS, || m.r32(off) & ext::BIOS_OWNED == 0);
        if released {
            kprintln!("xhci{}: ownership handed over by the firmware", index);
        } else {
            kprintln!(
                "xhci{}: WARNING: firmware did not release the controller within {} ms; taking it anyway",
                index,
                HANDOFF_TIMEOUT_MS
            );
            m.w32(off, (m.r32(off) & !ext::BIOS_OWNED) | ext::OS_OWNED);
        }
    } else {
        m.w32(off, v | ext::OS_OWNED);
    }
    let ctl = m.r32(off + 4);
    m.w32(off + 4, (ctl & ext::LEGCTL_KEEP) | ext::LEGCTL_SMI_EVENTS);
}

/// Number of xHCI controllers found.
pub fn controllers() -> usize {
    CONTROLLERS.load(Ordering::Relaxed).min(MAX_CONTROLLERS)
}

/// Interrupts received by controller `index`.
pub fn interrupts_of(index: usize) -> u64 {
    IRQS.get(index).map_or(0, |c| c.load(Ordering::Relaxed))
}
