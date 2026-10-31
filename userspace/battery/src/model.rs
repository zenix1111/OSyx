//! From readings of the firmware's battery objects to one [`Status`]:
//! units, several batteries, charge state, time estimates and what to do
//! with readings that cannot be trusted.

use alloc::vec::Vec;
use osyx_abi::battery::{State, Status};

/// ACPI's "unknown" for capacity, rate and voltage fields.
pub const UNKNOWN: u64 = 0xFFFF_FFFF;

/// One battery as `_STA`, `_BIF`/`_BIX` and `_BST` describe it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Sample {
    /// `_BIF`/`_BIX` power unit: capacities and rate in mAh/mA instead of
    /// mWh/mW.
    pub amp_units: bool,
    pub design_capacity: Option<u32>,
    pub last_full_capacity: Option<u32>,
    /// Design voltage, mV.
    pub design_voltage: Option<u32>,
    pub remaining: Option<u32>,
    pub rate: Option<u32>,
    /// Present voltage, mV.
    pub voltage: Option<u32>,
    pub discharging: bool,
    pub charging: bool,
    pub critical: bool,
}

/// Values above this are not a plausible rate or capacity in mW/mA.
const IMPLAUSIBLE: u64 = 10_000_000;

/// A `_BST`/`_BIF` number: `None` for "unknown" and for nonsense.
pub fn field(v: u64) -> Option<u32> {
    (v != UNKNOWN && v < IMPLAUSIBLE).then_some(v as u32)
}

impl Sample {
    /// The full-charge capacity to measure against: the last measured one,
    /// else the design capacity.
    pub fn full(&self) -> Option<u32> {
        self.last_full_capacity.filter(|&c| c > 0).or(self.design_capacity.filter(|&c| c > 0))
    }

    fn volts(&self) -> Option<u32> {
        self.voltage.filter(|&v| v > 0).or(self.design_voltage.filter(|&v| v > 0))
    }

    /// Converts a capacity or rate of this battery to mWh/mW.
    fn to_milli_watt(&self, v: u32) -> Option<u64> {
        if self.amp_units {
            Some(v as u64 * self.volts()? as u64 / 1000)
        } else {
            Some(v as u64)
        }
    }

    /// The charge level as a fraction of full, in 1/1000.
    fn permille(&self) -> Option<u64> {
        let (rem, full) = (self.remaining? as u64, self.full()? as u64);
        Some((rem.min(full * 2) * 1000 / full).min(1000))
    }

    /// Whether the numbers contradict each other (charge far above full,
    /// both directions at once): the firmware or the EC misreported.
    pub fn plausible(&self) -> bool {
        match (self.remaining, self.full()) {
            (Some(r), Some(f)) => r as u64 <= f as u64 * 12 / 10 && !(self.charging && self.discharging),
            _ => false,
        }
    }
}

/// Smooths the power reading: EC values jump, and a time estimate that
/// swings by the minute is worse than none.
#[derive(Clone, Copy, Debug, Default)]
pub struct RateFilter {
    mw: Option<u64>,
    direction: i8,
}

impl RateFilter {
    fn feed(&mut self, mw: Option<u64>, direction: i8) -> Option<u64> {
        if direction != self.direction {
            self.mw = None;
            self.direction = direction;
        }
        self.mw = match (self.mw, mw) {
            (Some(old), Some(new)) => Some((old * 3 + new) / 4),
            (None, Some(new)) => Some(new),
            (old, None) => old,
        };
        self.mw
    }
}

/// Longest estimate shown; beyond it the rate is too small to mean much.
const MAX_MINUTES: u64 = 99 * 60;
/// A battery this close to full counts as full.
const FULL_PERMILLE: u64 = 985;

/// Combines the batteries and the AC adapter into a [`Status`]. `ac` is
/// `None` when no adapter object answered; the charge state decides then.
pub fn aggregate(samples: &[Sample], ac: Option<bool>, filter: &mut RateFilter) -> Status {
    if samples.is_empty() {
        return Status::NONE;
    }
    let charging = samples.iter().any(|s| s.charging);
    let discharging = samples.iter().any(|s| s.discharging);
    let ac_online = ac.unwrap_or(charging && !discharging);

    // Energy in mWh for every battery that can be converted; the others
    // contribute their level only.
    let mut energy = 0u64;
    let mut capacity = 0u64;
    let mut design = 0u64;
    let mut converted = 0usize;
    let mut permille_sum = 0u64;
    let mut rate_in = 0u64;
    let mut rate_out = 0u64;
    let mut rate_known = false;
    let mut volt_sum = 0u64;
    let mut volts = 0u64;
    for s in samples {
        permille_sum += s.permille().unwrap_or(0);
        if let (Some(rem), Some(full)) = (s.remaining.and_then(|v| s.to_milli_watt(v)), s.full().and_then(|v| s.to_milli_watt(v))) {
            energy += rem.min(full * 2);
            capacity += full;
            converted += 1;
            if let Some(d) = s.design_capacity.and_then(|v| s.to_milli_watt(v)) {
                design += d;
            }
        }
        if let Some(r) = s.rate.and_then(|r| s.to_milli_watt(r)) {
            rate_known = true;
            if s.charging {
                rate_in += r;
            } else if s.discharging {
                rate_out += r;
            }
        }
        if let Some(v) = s.volts() {
            volt_sum += v as u64;
            volts += 1;
        }
    }
    let all_converted = converted == samples.len();
    let permille = if all_converted && capacity > 0 {
        (energy * 1000 / capacity).min(1000)
    } else {
        permille_sum / samples.len() as u64
    };
    let percent = ((permille + 5) / 10).min(100) as u8;

    let state = if discharging && (!charging || !ac_online) {
        State::Discharging
    } else if charging {
        State::Charging
    } else if ac_online {
        if permille >= FULL_PERMILLE {
            State::Full
        } else {
            State::Idle
        }
    } else {
        // Neither direction and no AC: the machine runs on the battery.
        State::Discharging
    };

    let direction = match state {
        State::Charging => 1,
        State::Discharging => -1,
        _ => 0,
    };
    let mw = match state {
        State::Charging if rate_known => Some(rate_in),
        State::Discharging if rate_known => Some(rate_out),
        _ => None,
    };
    let mw = filter.feed(mw.filter(|&r| r > 0), direction);
    let (mut to_empty, mut to_full) = (None, None);
    if all_converted && capacity > 0 {
        if let Some(r) = mw {
            match state {
                State::Discharging => to_empty = Some(energy * 60 / r).filter(|&m| m <= MAX_MINUTES),
                State::Charging => to_full = Some(capacity.saturating_sub(energy) * 60 / r).filter(|&m| m <= MAX_MINUTES),
                _ => {}
            }
        }
    }
    Status {
        state,
        percent,
        ac: ac_online,
        batteries: samples.len().min(255) as u8,
        minutes_to_empty: to_empty.map(|m| m as u32),
        minutes_to_full: to_full.map(|m| m as u32),
        energy_mwh: (all_converted && capacity > 0).then_some(energy as u32),
        capacity_mwh: (all_converted && capacity > 0).then_some(capacity as u32),
        design_mwh: (all_converted && design > 0).then_some(design as u32),
        rate_mw: mw.map(|r| r as u32),
        voltage_mv: (volts > 0).then(|| (volt_sum / volts) as u32),
        stale: false,
    }
}

/// What one poll of the firmware produced.
#[derive(Clone, Debug, Default)]
pub struct Poll {
    /// One entry per battery that is present; `None` where the firmware
    /// failed to answer.
    pub batteries: Vec<Option<Sample>>,
    /// `Some(online)` if any adapter answered.
    pub ac: Option<bool>,
    /// Failed EC transactions during the poll.
    pub ec_errors: u32,
    /// Battery devices the firmware has, present or not.
    pub devices: usize,
}

/// Consecutive bad polls tolerated before the last good state is
/// declared unknown.
const TOLERATED_BAD_POLLS: u32 = 3;

/// Keeps the last good state across polls the firmware botched.
#[derive(Debug, Default)]
pub struct Monitor {
    filter: RateFilter,
    last_good: Option<Status>,
    bad_streak: u32,
}

impl Monitor {
    pub fn new() -> Monitor {
        Monitor::default()
    }

    pub fn bad_polls(&self) -> u32 {
        self.bad_streak
    }

    /// The state to publish after `poll`.
    pub fn update(&mut self, poll: &Poll) -> Status {
        let present = poll.batteries.len();
        if present == 0 {
            // The firmware answered and said there is no battery (or has
            // none): trust that unless the EC was failing meanwhile.
            if poll.ec_errors == 0 || poll.devices == 0 {
                self.bad_streak = 0;
                self.last_good = None;
                return Status::NONE;
            }
        }
        let good: Vec<Sample> = poll.batteries.iter().flatten().copied().filter(Sample::plausible).collect();
        let reliable = present > 0 && good.len() == present && poll.ec_errors == 0;
        if reliable {
            self.bad_streak = 0;
            let s = aggregate(&good, poll.ac, &mut self.filter);
            self.last_good = Some(s);
            return s;
        }
        self.bad_streak += 1;
        match self.last_good {
            Some(mut s) if self.bad_streak <= TOLERATED_BAD_POLLS => {
                s.stale = true;
                s
            }
            Some(mut s) => {
                s.state = State::Unknown;
                s.stale = true;
                s.minutes_to_empty = None;
                s.minutes_to_full = None;
                s.rate_mw = None;
                s
            }
            None => {
                // Never a good reading: show a battery without a number.
                let mut s = Status { state: State::Unknown, batteries: present.max(poll.devices).min(255) as u8, stale: true, ..Status::NONE };
                if let Some(ac) = poll.ac {
                    s.ac = ac;
                }
                // Readings that were merely implausible are still better
                // than none for the percentage.
                let any: Vec<Sample> = poll.batteries.iter().flatten().copied().collect();
                if poll.ec_errors == 0 && !any.is_empty() {
                    let a = aggregate(&any, poll.ac, &mut RateFilter::default());
                    s.percent = a.percent;
                }
                s
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn mwh(rem: u32, full: u32, rate: u32) -> Sample {
        Sample {
            amp_units: false,
            design_capacity: Some(full + 5000),
            last_full_capacity: Some(full),
            design_voltage: Some(11400),
            remaining: Some(rem),
            rate: Some(rate),
            voltage: Some(11300),
            discharging: false,
            charging: false,
            critical: false,
        }
    }

    #[test]
    fn discharging_with_time() {
        let s = Sample { discharging: true, ..mwh(20_000, 40_000, 10_000) };
        let st = aggregate(&[s], Some(false), &mut RateFilter::default());
        assert_eq!((st.state, st.percent, st.ac), (State::Discharging, 50, false));
        assert_eq!(st.minutes_to_empty, Some(120));
        assert_eq!(st.minutes_to_full, None);
        assert_eq!(st.energy_mwh, Some(20_000));
        assert_eq!(st.capacity_mwh, Some(40_000));
        assert_eq!(st.design_mwh, Some(45_000));
    }

    #[test]
    fn charging_with_time() {
        let s = Sample { charging: true, ..mwh(10_000, 40_000, 15_000) };
        let st = aggregate(&[s], Some(true), &mut RateFilter::default());
        assert_eq!((st.state, st.percent, st.ac), (State::Charging, 25, true));
        assert_eq!(st.minutes_to_full, Some(120));
    }

    #[test]
    fn full_idle_and_threshold() {
        let full = mwh(40_000, 40_000, 0);
        let st = aggregate(&[full], Some(true), &mut RateFilter::default());
        assert_eq!((st.state, st.percent), (State::Full, 100));
        // On AC, not charging, at 80 %: a charge threshold.
        let held = mwh(32_000, 40_000, 0);
        let st = aggregate(&[held], Some(true), &mut RateFilter::default());
        assert_eq!((st.state, st.percent), (State::Idle, 80));
        assert_eq!(st.minutes_to_empty, None);
    }

    #[test]
    fn rounding_and_clamping() {
        let s = Sample { discharging: true, ..mwh(39_990, 40_000, 5000) };
        assert_eq!(aggregate(&[s], Some(false), &mut RateFilter::default()).percent, 100);
        let s = Sample { discharging: true, ..mwh(1, 40_000, 5000) };
        assert_eq!(aggregate(&[s], Some(false), &mut RateFilter::default()).percent, 0);
        // Remaining above full (firmware rounding) is clamped.
        let s = Sample { discharging: true, ..mwh(41_000, 40_000, 5000) };
        assert_eq!(aggregate(&[s], Some(false), &mut RateFilter::default()).percent, 100);
    }

    #[test]
    fn amp_hour_units_convert_with_the_voltage() {
        let s = Sample {
            amp_units: true,
            design_capacity: Some(4500),
            last_full_capacity: Some(4000),
            design_voltage: Some(11_400),
            remaining: Some(2000),
            rate: Some(1000),
            voltage: Some(11_000),
            discharging: true,
            ..Sample::default()
        };
        let st = aggregate(&[s], Some(false), &mut RateFilter::default());
        assert_eq!(st.percent, 50);
        assert_eq!(st.energy_mwh, Some(22_000));
        assert_eq!(st.rate_mw, Some(11_000));
        assert_eq!(st.minutes_to_empty, Some(120));
        // Without any voltage nothing can be converted: the level is kept,
        // the energy and times are not claimed.
        let nov = Sample { voltage: None, design_voltage: None, ..s };
        let st = aggregate(&[nov], Some(false), &mut RateFilter::default());
        assert_eq!(st.percent, 50);
        assert_eq!((st.energy_mwh, st.minutes_to_empty), (None, None));
    }

    #[test]
    fn two_batteries_add_up() {
        let a = Sample { discharging: true, ..mwh(10_000, 40_000, 6_000) };
        let b = Sample { discharging: true, ..mwh(30_000, 40_000, 4_000) };
        let st = aggregate(&[a, b], Some(false), &mut RateFilter::default());
        assert_eq!(st.percent, 50);
        assert_eq!(st.batteries, 2);
        assert_eq!(st.rate_mw, Some(10_000));
        assert_eq!(st.minutes_to_empty, Some(240));
        // One charging while the other discharges, on AC: charging.
        let c = Sample { charging: true, ..mwh(10_000, 40_000, 6_000) };
        let d = Sample { discharging: true, ..mwh(30_000, 40_000, 4_000) };
        assert_eq!(aggregate(&[c, d], Some(true), &mut RateFilter::default()).state, State::Charging);
        assert_eq!(aggregate(&[c, d], Some(false), &mut RateFilter::default()).state, State::Discharging);
    }

    #[test]
    fn ac_is_inferred_without_an_adapter_object() {
        let c = Sample { charging: true, ..mwh(10_000, 40_000, 15_000) };
        assert!(aggregate(&[c], None, &mut RateFilter::default()).ac);
        let d = Sample { discharging: true, ..mwh(10_000, 40_000, 15_000) };
        assert!(!aggregate(&[d], None, &mut RateFilter::default()).ac);
    }

    #[test]
    fn rate_is_smoothed_and_reset_on_direction_change() {
        let mut f = RateFilter::default();
        let d = |rate| Sample { discharging: true, ..mwh(20_000, 40_000, rate) };
        assert_eq!(aggregate(&[d(10_000)], Some(false), &mut f).rate_mw, Some(10_000));
        assert_eq!(aggregate(&[d(18_000)], Some(false), &mut f).rate_mw, Some(12_000));
        let c = Sample { charging: true, ..mwh(20_000, 40_000, 30_000) };
        assert_eq!(aggregate(&[c], Some(true), &mut f).rate_mw, Some(30_000));
    }

    #[test]
    fn implausible_estimates_are_dropped() {
        let s = Sample { discharging: true, ..mwh(40_000, 40_000, 10) };
        assert_eq!(aggregate(&[s], Some(false), &mut RateFilter::default()).minutes_to_empty, None, "4000 hours");
        let z = Sample { discharging: true, ..mwh(40_000, 40_000, 0) };
        let st = aggregate(&[z], Some(false), &mut RateFilter::default());
        assert_eq!((st.minutes_to_empty, st.rate_mw), (None, None), "rate 0 is unknown");
    }

    #[test]
    fn fields() {
        assert_eq!(field(0xFFFF_FFFF), None);
        assert_eq!(field(0xFFFF_FFF0), None);
        assert_eq!(field(0), Some(0));
        assert_eq!(field(45_000), Some(45_000));
    }

    fn poll(samples: &[Option<Sample>], errors: u32) -> Poll {
        Poll { batteries: samples.to_vec(), ac: Some(false), ec_errors: errors, devices: 1 }
    }

    #[test]
    fn monitor_keeps_the_last_good_state_through_ec_errors() {
        let mut m = Monitor::new();
        let good = Sample { discharging: true, ..mwh(20_000, 40_000, 10_000) };
        let first = m.update(&poll(&[Some(good)], 0));
        assert_eq!((first.percent, first.stale), (50, false));
        // The EC fails: values read as zero must not reach the screen.
        let zero = Sample { remaining: Some(0), ..good };
        for _ in 0..3 {
            let s = m.update(&poll(&[Some(zero)], 2));
            assert_eq!((s.percent, s.stale, s.state), (50, true, State::Discharging));
        }
        let s = m.update(&poll(&[Some(zero)], 2));
        assert_eq!((s.state, s.stale, s.minutes_to_empty), (State::Unknown, true, None));
        assert_eq!(s.percent, 50, "the last known level stays");
        // Recovery.
        let s = m.update(&poll(&[Some(Sample { remaining: Some(19_000), ..good })], 0));
        assert_eq!((s.percent, s.stale, s.state), (48, false, State::Discharging));
        assert_eq!(m.bad_polls(), 0);
    }

    #[test]
    fn monitor_without_any_good_reading() {
        let mut m = Monitor::new();
        let s = m.update(&poll(&[None], 0));
        assert_eq!((s.state, s.stale, s.batteries), (State::Unknown, true, 1));
        // A battery that reports charge far above full is not believed.
        let bad = Sample { discharging: true, ..mwh(90_000, 40_000, 10_000) };
        let s = m.update(&poll(&[Some(bad)], 0));
        assert_eq!(s.state, State::Unknown);
    }

    #[test]
    fn monitor_reports_no_battery() {
        let mut m = Monitor::new();
        assert_eq!(m.update(&Poll { devices: 1, ..Poll::default() }), Status::NONE);
        assert_eq!(m.update(&Poll::default()), Status::NONE);
        // Removed battery: the previous state is forgotten.
        let good = Sample { discharging: true, ..mwh(20_000, 40_000, 10_000) };
        m.update(&poll(&[Some(good)], 0));
        assert_eq!(m.update(&Poll { devices: 1, ac: Some(true), ..Poll::default() }), Status::NONE);
    }

    #[test]
    fn contradictory_directions_are_not_believed() {
        let s = Sample { charging: true, discharging: true, ..mwh(20_000, 40_000, 1000) };
        assert!(!s.plausible());
    }
}
