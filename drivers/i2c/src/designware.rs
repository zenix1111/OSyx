//! Synopsys DesignWare I2C master (DW_apb_i2c), as used by Intel LPSS PCI
//! functions and the AMD `AMDI0010`/`AMDI0510` ACPI devices.
//!
//! The driver is polled: it never needs the controller's interrupt, and
//! every wait is bounded by a [`Clock`] deadline. 7-bit addresses, standard
//! (100 kHz) and fast (400 kHz) mode. The SCL timing comes from the
//! firmware (`SSCN`/`FMCN`) when it gives one; otherwise the controller's
//! own reset values are used if they are plausible, and the controller is
//! refused if not. Nothing is computed from a clock rate the driver does
//! not know.
//!
//! Register layout: DesignWare DW_apb_i2c databook, as also documented by
//! the Linux `i2c-designware` driver.

use crate::bus::{wait_until, Clock, I2cBus, I2cError, Mmio, MAX_TRANSFER};

pub mod reg {
    pub const CON: usize = 0x00;
    pub const TAR: usize = 0x04;
    pub const DATA_CMD: usize = 0x10;
    pub const SS_SCL_HCNT: usize = 0x14;
    pub const SS_SCL_LCNT: usize = 0x18;
    pub const FS_SCL_HCNT: usize = 0x1C;
    pub const FS_SCL_LCNT: usize = 0x20;
    pub const INTR_STAT: usize = 0x2C;
    pub const INTR_MASK: usize = 0x30;
    pub const RAW_INTR_STAT: usize = 0x34;
    pub const RX_TL: usize = 0x38;
    pub const TX_TL: usize = 0x3C;
    pub const CLR_INTR: usize = 0x40;
    pub const CLR_TX_ABRT: usize = 0x54;
    pub const ENABLE: usize = 0x6C;
    pub const STATUS: usize = 0x70;
    pub const TXFLR: usize = 0x74;
    pub const RXFLR: usize = 0x78;
    pub const SDA_HOLD: usize = 0x7C;
    pub const TX_ABRT_SOURCE: usize = 0x80;
    pub const ENABLE_STATUS: usize = 0x9C;
    pub const COMP_PARAM_1: usize = 0xF4;
    pub const COMP_VERSION: usize = 0xF8;
    pub const COMP_TYPE: usize = 0xFC;
}

/// `IC_COMP_TYPE` of every DesignWare I2C ("DW" 0x0140).
pub const COMP_TYPE_MAGIC: u32 = 0x4457_0140;

const CON_MASTER: u32 = 1 << 0;
const CON_SPEED_STANDARD: u32 = 1 << 1;
const CON_SPEED_FAST: u32 = 2 << 1;
const CON_RESTART_EN: u32 = 1 << 5;
const CON_SLAVE_DISABLE: u32 = 1 << 6;

const CMD_READ: u32 = 1 << 8;
const CMD_STOP: u32 = 1 << 9;
const CMD_RESTART: u32 = 1 << 10;

const STATUS_TFE: u32 = 1 << 2;
const STATUS_MST_ACTIVITY: u32 = 1 << 5;

const INTR_TX_ABRT: u32 = 1 << 6;

const ABRT_7B_ADDR_NOACK: u32 = 1 << 0;
const ABRT_10B_ADDR1_NOACK: u32 = 1 << 1;
const ABRT_10B_ADDR2_NOACK: u32 = 1 << 2;
const ABRT_TXDATA_NOACK: u32 = 1 << 3;
const ABRT_ARB_LOST: u32 = 1 << 12;

/// Longest wait for the controller to switch off or on.
const ENABLE_TIMEOUT_US: u64 = 100_000;
/// A transfer gets this long plus [`PER_BYTE_US`] per byte (100 kHz, 9
/// clocks per byte is 90 us; the rest is room for clock stretching).
const TRANSFER_BASE_US: u64 = 100_000;
const PER_BYTE_US: u64 = 250;

/// Smallest counts the databook allows.
const MIN_HCNT: u32 = 6;
const MIN_LCNT: u32 = 8;

/// Bus speed of one transfer setup. Faster targets are run in fast mode
/// (400 kHz): fast-mode plus and high-speed mode are not supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusSpeed {
    Standard,
    Fast,
}

impl BusSpeed {
    /// The mode for a target that supports up to `hz` (0 = unknown: the
    /// slower mode is chosen).
    pub fn from_hz(hz: u32) -> BusSpeed {
        if hz > 100_000 {
            BusSpeed::Fast
        } else {
            BusSpeed::Standard
        }
    }

    pub fn hz(self) -> u32 {
        match self {
            BusSpeed::Standard => 100_000,
            BusSpeed::Fast => 400_000,
        }
    }
}

/// SCL high and low counts, in cycles of the controller's input clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SclTiming {
    pub hcnt: u32,
    pub lcnt: u32,
}

impl SclTiming {
    fn plausible(self) -> bool {
        (MIN_HCNT..=0xFFFF).contains(&self.hcnt) && (MIN_LCNT..=0xFFFF).contains(&self.lcnt)
    }
}

/// What the firmware says about the bus timing (ACPI `SSCN`, `FMCN`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timing {
    pub standard: Option<SclTiming>,
    pub fast: Option<SclTiming>,
    /// SDA hold time in input clock cycles.
    pub sda_hold: Option<u32>,
}

/// Where the SCL counts in use came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingSource {
    Firmware,
    /// The values the controller (or the boot firmware that set it up) had.
    ControllerDefault,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `IC_COMP_TYPE` is not the DesignWare signature (the value read).
    NotDesignWare(u32),
    /// The FIFO depths are not readable from `IC_COMP_PARAM_1`.
    FifoUnknown(u32),
    /// The controller would not switch off.
    Stuck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Neither the firmware nor the controller gives usable SCL counts.
    NoTiming,
    Stuck,
}

pub struct DesignWare<M: Mmio, C: Clock> {
    mmio: M,
    clock: C,
    version: u32,
    tx_depth: u32,
    rx_depth: u32,
    configured: bool,
}

impl<M: Mmio, C: Clock> DesignWare<M, C> {
    /// Identifies the controller and leaves it disabled. Does not change
    /// any setting.
    pub fn probe(mmio: M, clock: C) -> Result<Self, ProbeError> {
        let ty = mmio.read32(reg::COMP_TYPE);
        if ty != COMP_TYPE_MAGIC {
            return Err(ProbeError::NotDesignWare(ty));
        }
        let param = mmio.read32(reg::COMP_PARAM_1);
        // 0 and all-ones mean the parameters were not synthesised / the
        // device is gone.
        if param == 0 || param == u32::MAX {
            return Err(ProbeError::FifoUnknown(param));
        }
        let tx_depth = ((param >> 16) & 0xFF) + 1;
        let rx_depth = ((param >> 8) & 0xFF) + 1;
        let version = mmio.read32(reg::COMP_VERSION);
        let mut dw = DesignWare { mmio, clock, version, tx_depth, rx_depth, configured: false };
        dw.disable().map_err(|_| ProbeError::Stuck)?;
        Ok(dw)
    }

    /// `IC_COMP_VERSION` (ASCII, e.g. `0x3230312A` for "201*").
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn fifo_depths(&self) -> (u32, u32) {
        (self.tx_depth, self.rx_depth)
    }

    pub fn mmio(&self) -> &M {
        &self.mmio
    }

    pub fn mmio_mut(&mut self) -> &mut M {
        &mut self.mmio
    }

    fn rd(&self, r: usize) -> u32 {
        self.mmio.read32(r)
    }

    fn wr(&mut self, r: usize, v: u32) {
        self.mmio.write32(r, v);
    }

    fn disable(&mut self) -> Result<(), I2cError> {
        self.wr(reg::ENABLE, 0);
        let (m, c) = (&self.mmio, &self.clock);
        if wait_until(c, ENABLE_TIMEOUT_US, || m.read32(reg::ENABLE_STATUS) & 1 == 0) {
            Ok(())
        } else {
            Err(I2cError::Controller)
        }
    }

    fn enable(&mut self) -> Result<(), I2cError> {
        self.wr(reg::ENABLE, 1);
        let (m, c) = (&self.mmio, &self.clock);
        if wait_until(c, ENABLE_TIMEOUT_US, || m.read32(reg::ENABLE_STATUS) & 1 != 0) {
            Ok(())
        } else {
            Err(I2cError::Controller)
        }
    }

    /// Sets master mode, the speed and the SCL timing. Returns where the
    /// SCL counts came from.
    pub fn configure(&mut self, speed: BusSpeed, timing: &Timing) -> Result<TimingSource, ConfigError> {
        self.disable().map_err(|_| ConfigError::Stuck)?;
        let (hreg, lreg, wanted) = match speed {
            BusSpeed::Standard => (reg::SS_SCL_HCNT, reg::SS_SCL_LCNT, timing.standard),
            BusSpeed::Fast => (reg::FS_SCL_HCNT, reg::FS_SCL_LCNT, timing.fast),
        };
        let source = match wanted.filter(|t| t.plausible()) {
            Some(t) => {
                self.wr(hreg, t.hcnt);
                self.wr(lreg, t.lcnt);
                TimingSource::Firmware
            }
            None => {
                let have = SclTiming { hcnt: self.rd(hreg), lcnt: self.rd(lreg) };
                if !have.plausible() {
                    return Err(ConfigError::NoTiming);
                }
                TimingSource::ControllerDefault
            }
        };
        if let Some(hold) = timing.sda_hold.filter(|&h| h != 0 && h <= 0xFFFF) {
            self.wr(reg::SDA_HOLD, hold);
        }
        let mode = match speed {
            BusSpeed::Standard => CON_SPEED_STANDARD,
            BusSpeed::Fast => CON_SPEED_FAST,
        };
        self.wr(reg::CON, CON_MASTER | mode | CON_RESTART_EN | CON_SLAVE_DISABLE);
        // Polled: no interrupt is wanted, FIFO thresholds stay at 0.
        self.wr(reg::INTR_MASK, 0);
        self.wr(reg::RX_TL, 0);
        self.wr(reg::TX_TL, 0);
        self.configured = true;
        Ok(source)
    }

    /// Reads and clears the abort reason.
    fn abort_error(&mut self) -> I2cError {
        let src = self.rd(reg::TX_ABRT_SOURCE);
        let _ = self.rd(reg::CLR_TX_ABRT);
        if src & ABRT_ARB_LOST != 0 {
            I2cError::ArbitrationLost
        } else if src & (ABRT_7B_ADDR_NOACK | ABRT_10B_ADDR1_NOACK | ABRT_10B_ADDR2_NOACK | ABRT_TXDATA_NOACK) != 0 {
            I2cError::Nack
        } else {
            I2cError::Abort(src)
        }
    }

    fn run(&mut self, address: u8, write: &[u8], read: &mut [u8]) -> Result<(), I2cError> {
        self.disable()?;
        self.wr(reg::TAR, address as u32 & 0x7F);
        self.wr(reg::INTR_MASK, 0);
        self.enable()?;
        // Drop whatever an earlier transfer left behind.
        let _ = self.rd(reg::CLR_INTR);

        let total = write.len() + read.len();
        let start = self.clock.now_us();
        let limit = TRANSFER_BASE_US + PER_BYTE_US * total as u64;
        let (mut sent, mut got, mut reads_issued) = (0usize, 0usize, 0usize);
        loop {
            if self.rd(reg::RAW_INTR_STAT) & INTR_TX_ABRT != 0 {
                return Err(self.abort_error());
            }
            while got < read.len() && self.rd(reg::RXFLR) > 0 {
                read[got] = self.rd(reg::DATA_CMD) as u8;
                got += 1;
            }
            if sent < total {
                let mut room = self.tx_depth.saturating_sub(self.rd(reg::TXFLR));
                while sent < total && room > 0 {
                    let cmd = if sent < write.len() {
                        let stop = if read.is_empty() && sent + 1 == write.len() { CMD_STOP } else { 0 };
                        write[sent] as u32 | stop
                    } else {
                        // Never ask for more bytes than the receive FIFO can
                        // hold: the controller would overrun it.
                        if reads_issued - got >= self.rx_depth as usize {
                            break;
                        }
                        let i = sent - write.len();
                        let restart = if i == 0 && !write.is_empty() { CMD_RESTART } else { 0 };
                        let stop = if i + 1 == read.len() { CMD_STOP } else { 0 };
                        reads_issued += 1;
                        CMD_READ | restart | stop
                    };
                    self.wr(reg::DATA_CMD, cmd);
                    sent += 1;
                    room -= 1;
                }
            }
            if sent == total && got == read.len() {
                let st = self.rd(reg::STATUS);
                if st & STATUS_TFE != 0 && st & STATUS_MST_ACTIVITY == 0 {
                    // The FIFO is empty and the bus idle: a transfer that
                    // was refused looks the same, until the abort is read.
                    if self.rd(reg::RAW_INTR_STAT) & INTR_TX_ABRT != 0 {
                        return Err(self.abort_error());
                    }
                    return Ok(());
                }
            }
            if self.clock.now_us().saturating_sub(start) >= limit {
                return Err(I2cError::Timeout);
            }
            self.clock.relax();
        }
    }
}

impl<M: Mmio, C: Clock> I2cBus for DesignWare<M, C> {
    fn transfer(&mut self, address: u8, write: &[u8], read: &mut [u8]) -> Result<(), I2cError> {
        if (write.is_empty() && read.is_empty()) || write.len() > MAX_TRANSFER || read.len() > MAX_TRANSFER || address > 0x7F {
            return Err(I2cError::InvalidLength);
        }
        if !self.configured {
            return Err(I2cError::Controller);
        }
        let result = self.run(address, write, read);
        // Always leave the controller off: a failed transfer must not keep
        // the bus busy, and the next one reprograms the target address.
        let off = self.disable();
        match (result, off) {
            (Err(e), _) => Err(e),
            (Ok(()), Err(e)) => Err(e),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}
