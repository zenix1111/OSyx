//! A register-level model of the DesignWare controller with simulated I2C
//! targets, for the host tests and the kernel's boot test.
//!
//! The model follows the databook where the driver depends on it: the
//! controller must be disabled to change the target address, the transmit
//! FIFO has a depth, a read command stalls while the receive FIFO is full
//! (a driver that issues too many reads loses data on real hardware), and
//! a NACK sets `TX_ABRT` and flushes the transmit FIFO. Violations of the
//! rules are recorded in [`DwModel::violations`] instead of being
//! silently accepted. Time is virtual: every look at the clock costs a few
//! microseconds, so time-outs come quickly.

use crate::bus::{Clock, Mmio};
use crate::designware::{reg, COMP_TYPE_MAGIC};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

/// Virtual time shared by the clock and the tests.
#[derive(Clone, Default)]
pub struct SimClock(Rc<Cell<u64>>);

impl SimClock {
    pub fn new() -> SimClock {
        SimClock::default()
    }
}

impl Clock for SimClock {
    fn now_us(&self) -> u64 {
        // Reading the clock costs time, so no loop can spin forever.
        self.0.set(self.0.get() + 1);
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get() + 10);
    }
    fn sleep_ms(&self, ms: u32) {
        self.0.set(self.0.get() + ms as u64 * 1000);
    }
}

/// A device on the simulated bus.
pub trait Target {
    fn address(&self) -> u8;
    /// A start condition addressed to this target; false = NACK.
    fn start(&mut self, read: bool) -> bool;
    /// One data byte from the master; false = NACK.
    fn write(&mut self, byte: u8) -> bool;
    fn read(&mut self) -> u8;
    fn stop(&mut self);
}

const CMD_READ: u32 = 1 << 8;
const CMD_STOP: u32 = 1 << 9;
const CMD_RESTART: u32 = 1 << 10;
const RAW_STOP_DET: u32 = 1 << 9;
const RAW_TX_ABRT: u32 = 1 << 6;
const ABRT_ADDR_NOACK: u32 = 1 << 0;
const ABRT_TXDATA_NOACK: u32 = 1 << 3;

struct Txn {
    target: usize,
    read: bool,
}

pub struct DwModel {
    pub tx_depth: u32,
    pub rx_depth: u32,
    /// What `IC_COMP_TYPE` reads as.
    pub comp_type: u32,
    /// What `IC_COMP_PARAM_1` reads as, instead of the depths.
    pub comp_param: Option<u32>,
    pub con: u32,
    pub tar: u32,
    pub ss_hcnt: u32,
    pub ss_lcnt: u32,
    pub fs_hcnt: u32,
    pub fs_lcnt: u32,
    pub sda_hold: u32,
    intr_mask: u32,
    rx_tl: u32,
    tx_tl: u32,
    enabled: bool,
    /// A controller that never switches off (`ENABLE_STATUS` stays 1).
    pub stuck_enabled: bool,
    /// A bus that never completes anything (a target holding SCL low).
    pub stuck_bus: bool,
    tx: VecDeque<u32>,
    rx: VecDeque<u8>,
    raw: u32,
    abort_source: u32,
    txn: Option<Txn>,
    targets: Vec<Box<dyn Target>>,
    /// Rule violations by the driver, for the tests to assert on.
    pub violations: Vec<&'static str>,
    pub completed_transfers: u32,
}

impl DwModel {
    fn new(tx_depth: u32, rx_depth: u32) -> DwModel {
        DwModel {
            tx_depth,
            rx_depth,
            comp_type: COMP_TYPE_MAGIC,
            comp_param: None,
            con: 0,
            tar: 0,
            ss_hcnt: 0x190,
            ss_lcnt: 0x1D6,
            fs_hcnt: 0x64,
            fs_lcnt: 0x96,
            sda_hold: 0,
            intr_mask: 0,
            rx_tl: 0,
            tx_tl: 0,
            enabled: false,
            stuck_enabled: false,
            stuck_bus: false,
            tx: VecDeque::new(),
            rx: VecDeque::new(),
            raw: 0,
            abort_source: 0,
            txn: None,
            targets: Vec::new(),
            violations: Vec::new(),
            completed_transfers: 0,
        }
    }

    fn abort(&mut self, source: u32) {
        self.raw |= RAW_TX_ABRT;
        self.abort_source |= source;
        self.tx.clear();
        if let Some(t) = self.txn.take() {
            self.targets[t.target].stop();
        }
    }

    /// Runs queued commands until the FIFOs stall.
    fn drain(&mut self) {
        if self.stuck_bus {
            return;
        }
        while let Some(&cmd) = self.tx.front() {
            let is_read = cmd & CMD_READ != 0;
            if is_read && self.rx.len() as u32 >= self.rx_depth {
                break;
            }
            self.tx.pop_front();
            let started = match &self.txn {
                None => {
                    let addr = (self.tar & 0x7F) as u8;
                    match self.targets.iter().position(|t| t.address() == addr) {
                        Some(i) if self.targets[i].start(is_read) => {
                            self.txn = Some(Txn { target: i, read: is_read });
                            true
                        }
                        _ => {
                            self.abort(ABRT_ADDR_NOACK);
                            false
                        }
                    }
                }
                Some(t) if t.read != is_read => {
                    if cmd & CMD_RESTART == 0 {
                        self.violations.push("direction change without RESTART");
                    }
                    let i = t.target;
                    if self.targets[i].start(is_read) {
                        self.txn = Some(Txn { target: i, read: is_read });
                        true
                    } else {
                        self.abort(ABRT_ADDR_NOACK);
                        false
                    }
                }
                Some(_) => true,
            };
            if !started {
                continue;
            }
            let i = self.txn.as_ref().expect("transaction started").target;
            if is_read {
                let b = self.targets[i].read();
                self.rx.push_back(b);
            } else if !self.targets[i].write(cmd as u8) {
                self.abort(ABRT_TXDATA_NOACK);
                continue;
            }
            if cmd & CMD_STOP != 0 {
                self.targets[i].stop();
                self.txn = None;
                self.raw |= RAW_STOP_DET;
                self.completed_transfers += 1;
            }
        }
    }

    fn read(&mut self, offset: usize) -> u32 {
        match offset {
            reg::CON => self.con,
            reg::TAR => self.tar,
            reg::DATA_CMD => match self.rx.pop_front() {
                Some(b) => b as u32,
                None => {
                    self.violations.push("read of an empty receive FIFO");
                    0
                }
            },
            reg::SS_SCL_HCNT => self.ss_hcnt,
            reg::SS_SCL_LCNT => self.ss_lcnt,
            reg::FS_SCL_HCNT => self.fs_hcnt,
            reg::FS_SCL_LCNT => self.fs_lcnt,
            reg::INTR_STAT => self.raw & self.intr_mask,
            reg::INTR_MASK => self.intr_mask,
            reg::RAW_INTR_STAT => self.raw,
            reg::RX_TL => self.rx_tl,
            reg::TX_TL => self.tx_tl,
            reg::CLR_INTR => {
                self.raw &= RAW_TX_ABRT;
                0
            }
            reg::CLR_TX_ABRT => {
                self.raw &= !RAW_TX_ABRT;
                self.abort_source = 0;
                0
            }
            reg::ENABLE => self.enabled as u32,
            reg::STATUS => {
                let busy = self.txn.is_some() || !self.tx.is_empty();
                (busy as u32)
                    | ((self.tx.len() < self.tx_depth as usize) as u32) << 1
                    | (self.tx.is_empty() as u32) << 2
                    | (!self.rx.is_empty() as u32) << 3
                    | ((self.rx.len() as u32 >= self.rx_depth) as u32) << 4
                    | (busy as u32) << 5
            }
            reg::TXFLR => self.tx.len() as u32,
            reg::RXFLR => self.rx.len() as u32,
            reg::SDA_HOLD => self.sda_hold,
            reg::TX_ABRT_SOURCE => self.abort_source,
            reg::ENABLE_STATUS => (self.enabled || self.stuck_enabled) as u32,
            reg::COMP_PARAM_1 => self.comp_param.unwrap_or(((self.tx_depth - 1) << 16) | ((self.rx_depth - 1) << 8) | 0x2 << 2),
            reg::COMP_VERSION => 0x3230_312A,
            reg::COMP_TYPE => self.comp_type,
            _ => 0,
        }
    }

    fn write(&mut self, offset: usize, v: u32) {
        match offset {
            reg::CON => {
                if self.enabled {
                    self.violations.push("IC_CON written while enabled");
                }
                self.con = v;
            }
            reg::TAR => {
                if self.enabled {
                    self.violations.push("IC_TAR written while enabled");
                }
                self.tar = v;
            }
            reg::DATA_CMD => {
                if !self.enabled {
                    self.violations.push("data written while disabled");
                    return;
                }
                // After an abort the transmit FIFO stays flushed until the
                // abort is cleared: new commands are discarded.
                if self.raw & RAW_TX_ABRT != 0 {
                    return;
                }
                if self.tx.len() as u32 >= self.tx_depth {
                    self.violations.push("transmit FIFO overflow");
                    return;
                }
                self.tx.push_back(v);
                self.drain();
            }
            reg::SS_SCL_HCNT | reg::SS_SCL_LCNT | reg::FS_SCL_HCNT | reg::FS_SCL_LCNT | reg::SDA_HOLD => {
                if self.enabled {
                    self.violations.push("timing written while enabled");
                }
                match offset {
                    reg::SS_SCL_HCNT => self.ss_hcnt = v,
                    reg::SS_SCL_LCNT => self.ss_lcnt = v,
                    reg::FS_SCL_HCNT => self.fs_hcnt = v,
                    reg::FS_SCL_LCNT => self.fs_lcnt = v,
                    _ => self.sda_hold = v,
                }
            }
            reg::INTR_MASK => self.intr_mask = v,
            reg::RX_TL => self.rx_tl = v,
            reg::TX_TL => self.tx_tl = v,
            reg::ENABLE => {
                let on = v & 1 != 0;
                if !on && self.enabled {
                    // Switching off flushes both FIFOs and ends any transfer.
                    self.tx.clear();
                    self.rx.clear();
                    if let Some(t) = self.txn.take() {
                        self.targets[t.target].stop();
                    }
                }
                self.enabled = on;
            }
            _ => {}
        }
    }
}

/// The controller registers; clone it to keep a handle for the test while
/// the driver owns another.
#[derive(Clone)]
pub struct SimMmio(Rc<RefCell<DwModel>>);

impl SimMmio {
    pub fn new(tx_depth: u32, rx_depth: u32) -> SimMmio {
        SimMmio(Rc::new(RefCell::new(DwModel::new(tx_depth, rx_depth))))
    }

    pub fn attach(&self, target: impl Target + 'static) {
        self.0.borrow_mut().targets.push(Box::new(target));
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut DwModel) -> R) -> R {
        f(&mut self.0.borrow_mut())
    }
}

impl Mmio for SimMmio {
    fn read32(&self, offset: usize) -> u32 {
        self.0.borrow_mut().read(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.0.borrow_mut().write(offset, value);
    }
}

// ---- a HID over I2C device --------------------------------------------------------------------

/// What the simulated device answers to a read when no report is pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleMode {
    /// A zero length (what well-behaved devices do).
    ZeroLength,
    /// The address is not acknowledged.
    Nack,
    /// The last report again (a device that cannot be polled).
    RepeatLast,
}

pub struct HidState {
    pub address: u8,
    pub descriptor_register: u16,
    pub report_descriptor: Vec<u8>,
    pub max_input_length: u16,
    pub idle: IdleMode,
    pub powered: bool,
    pub resets: u32,
    /// Reads after a reset that are refused before the reset response.
    pub reset_delay_reads: u32,
    /// Never sends the reset response.
    pub no_reset_response: bool,
    /// Reports waiting to be read (with report id byte if used).
    pub pending: VecDeque<Vec<u8>>,
    /// Corrupts the HID descriptor version.
    pub bad_version: bool,
    last: Vec<u8>,
    reset_owed: bool,
    writing: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    in_write: bool,
}

const REPORT_DESCRIPTOR_REGISTER: u16 = 0x0002;
const INPUT_REGISTER: u16 = 0x0003;
const COMMAND_REGISTER: u16 = 0x0005;
const DATA_REGISTER: u16 = 0x0006;

impl HidState {
    fn hid_descriptor(&self) -> Vec<u8> {
        let mut d = Vec::new();
        let mut w = |v: u16| d.extend_from_slice(&v.to_le_bytes());
        w(30);
        w(if self.bad_version { 0x0200 } else { 0x0100 });
        w(self.report_descriptor.len() as u16);
        w(REPORT_DESCRIPTOR_REGISTER);
        w(INPUT_REGISTER);
        w(self.max_input_length);
        w(0x0004); // output register
        w(self.max_input_length);
        w(COMMAND_REGISTER);
        w(DATA_REGISTER);
        w(0x1234); // vendor
        w(0x5678); // product
        w(0x0001); // version
        d.extend_from_slice(&[0; 4]);
        d
    }

    fn input_read(&mut self) -> Option<Vec<u8>> {
        if self.reset_owed {
            if self.no_reset_response {
                return None;
            }
            if self.reset_delay_reads > 0 {
                self.reset_delay_reads -= 1;
                return None;
            }
            self.reset_owed = false;
            return Some(Vec::from([0, 0]));
        }
        let report = match self.pending.pop_front() {
            Some(r) => {
                self.last = r.clone();
                r
            }
            None => match self.idle {
                IdleMode::ZeroLength => return Some(Vec::from([0, 0])),
                IdleMode::Nack => return None,
                IdleMode::RepeatLast if self.last.is_empty() => return Some(Vec::from([0, 0])),
                IdleMode::RepeatLast => self.last.clone(),
            },
        };
        let mut out = Vec::from(((report.len() + 2) as u16).to_le_bytes());
        out.extend(report);
        Some(out)
    }

    fn command(&mut self) {
        let w = &self.writing;
        if w.len() == 4 && u16::from_le_bytes([w[0], w[1]]) == COMMAND_REGISTER {
            match w[3] & 0x0F {
                0x01 => {
                    self.resets += 1;
                    self.pending.clear();
                    self.last.clear();
                    self.reset_owed = true;
                }
                0x08 => self.powered = w[2] & 3 == 0,
                _ => {}
            }
        }
    }
}

/// A simulated HID over I2C device; clone to keep a handle.
#[derive(Clone)]
pub struct SimHid(Rc<RefCell<HidState>>);

impl SimHid {
    /// A device at `address` with its HID descriptor at `descriptor_register`.
    pub fn new(address: u8, descriptor_register: u16, report_descriptor: &[u8]) -> SimHid {
        SimHid(Rc::new(RefCell::new(HidState {
            address,
            descriptor_register,
            report_descriptor: report_descriptor.to_vec(),
            max_input_length: 64,
            idle: IdleMode::ZeroLength,
            powered: false,
            resets: 0,
            reset_delay_reads: 0,
            no_reset_response: false,
            pending: VecDeque::new(),
            bad_version: false,
            last: Vec::new(),
            reset_owed: false,
            writing: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            in_write: false,
        })))
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut HidState) -> R) -> R {
        f(&mut self.0.borrow_mut())
    }

    /// Queues an input report (with its report id byte if the descriptor
    /// uses ids).
    pub fn push_report(&self, report: &[u8]) {
        self.0.borrow_mut().pending.push_back(report.to_vec());
    }
}

impl Target for SimHid {
    fn address(&self) -> u8 {
        self.0.borrow().address
    }

    fn start(&mut self, read: bool) -> bool {
        let mut s = self.0.borrow_mut();
        if !read {
            s.writing.clear();
            s.in_write = true;
            return true;
        }
        s.in_write = false;
        let reg = (s.writing.len() == 2).then(|| u16::from_le_bytes([s.writing[0], s.writing[1]]));
        let out = match reg {
            Some(r) if r == s.descriptor_register => Some(s.hid_descriptor()),
            Some(REPORT_DESCRIPTOR_REGISTER) => Some(s.report_descriptor.clone()),
            Some(_) => None,
            None if s.writing.is_empty() => s.input_read(),
            None => None,
        };
        s.writing.clear();
        match out {
            Some(o) => {
                s.out = o;
                s.out_pos = 0;
                true
            }
            None => false,
        }
    }

    fn write(&mut self, byte: u8) -> bool {
        self.0.borrow_mut().writing.push(byte);
        true
    }

    fn read(&mut self) -> u8 {
        let mut s = self.0.borrow_mut();
        let b = s.out.get(s.out_pos).copied().unwrap_or(0);
        s.out_pos += 1;
        b
    }

    fn stop(&mut self) {
        let mut s = self.0.borrow_mut();
        if s.in_write {
            s.command();
        }
        s.in_write = false;
        s.writing.clear();
    }
}
