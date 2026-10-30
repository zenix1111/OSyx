//! Battery state as published by the ACPI service in
//! [`crate::BATTERY_STATUS_PATH`] and read by the desktop.
//!
//! The file holds one or two lines. The first is the original format and
//! stays readable by old readers: `percent charging ac` (`percent` 0-100,
//! `charging` and `ac` 0 or 1), or `none` when the machine has no battery.
//! The second line adds `key=value` pairs separated by spaces:
//!
//! | Key | Meaning |
//! |---|---|
//! | `state` | `charging`, `discharging`, `full`, `idle` (on AC, not charging), `unknown` |
//! | `empty` | minutes until empty, while discharging |
//! | `full` | minutes until full, while charging |
//! | `batteries` | number of batteries present |
//! | `energy`, `capacity`, `design` | remaining, last full and design capacity in mWh |
//! | `rate` | charge or discharge power in mW |
//! | `voltage` | in mV |
//! | `stale` | 1 when the values are the last good ones after errors reading the firmware |
//!
//! Unknown keys are ignored, a missing key means "not known".

use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum State {
    /// No battery in the machine.
    #[default]
    None,
    /// A battery is there, but its state is not known (firmware errors).
    Unknown,
    Charging,
    Discharging,
    /// On AC power and full.
    Full,
    /// On AC power, not charging (a charge threshold, or a battery that is
    /// not full but is not taking charge).
    Idle,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::None => "none",
            State::Unknown => "unknown",
            State::Charging => "charging",
            State::Discharging => "discharging",
            State::Full => "full",
            State::Idle => "idle",
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        Some(match s {
            "none" => State::None,
            "unknown" => State::Unknown,
            "charging" => State::Charging,
            "discharging" => State::Discharging,
            "full" => State::Full,
            "idle" => State::Idle,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Status {
    pub state: State,
    /// 0-100.
    pub percent: u8,
    pub ac: bool,
    pub batteries: u8,
    pub minutes_to_empty: Option<u32>,
    pub minutes_to_full: Option<u32>,
    pub energy_mwh: Option<u32>,
    pub capacity_mwh: Option<u32>,
    pub design_mwh: Option<u32>,
    pub rate_mw: Option<u32>,
    pub voltage_mv: Option<u32>,
    pub stale: bool,
}

impl Status {
    pub const NONE: Status = Status {
        state: State::None,
        percent: 0,
        ac: false,
        batteries: 0,
        minutes_to_empty: None,
        minutes_to_full: None,
        energy_mwh: None,
        capacity_mwh: None,
        design_mwh: None,
        rate_mw: None,
        voltage_mv: None,
        stale: false,
    };

    pub fn present(&self) -> bool {
        self.state != State::None
    }

    pub fn charging(&self) -> bool {
        self.state == State::Charging
    }

    /// Parses the file; `None` for text that is not a battery state.
    pub fn parse(text: &str) -> Option<Status> {
        let mut lines = text.lines();
        let first = lines.next()?.trim();
        if first == "none" {
            return Some(Status::NONE);
        }
        let mut f = first.split_whitespace();
        let percent: u32 = f.next()?.parse().ok()?;
        let charging = f.next()? == "1";
        let ac = f.next()? == "1";
        let mut s = Status {
            state: if charging { State::Charging } else { State::Unknown },
            percent: percent.min(100) as u8,
            ac,
            batteries: 1,
            ..Status::NONE
        };
        let mut explicit = false;
        for pair in lines.next().unwrap_or("").split_whitespace() {
            let Some((k, v)) = pair.split_once('=') else { continue };
            let num = || v.parse::<u32>().ok();
            match k {
                "state" => {
                    if let Some(st) = State::parse(v) {
                        s.state = st;
                        explicit = true;
                    }
                }
                "empty" => s.minutes_to_empty = num(),
                "full" => s.minutes_to_full = num(),
                "batteries" => s.batteries = num().unwrap_or(1).min(255) as u8,
                "energy" => s.energy_mwh = num(),
                "capacity" => s.capacity_mwh = num(),
                "design" => s.design_mwh = num(),
                "rate" => s.rate_mw = num(),
                "voltage" => s.voltage_mv = num(),
                "stale" => s.stale = v == "1",
                _ => {}
            }
        }
        if !explicit && !charging {
            // The old format cannot tell discharging from idle or full.
            s.state = if ac { State::Idle } else { State::Discharging };
        }
        Some(s)
    }

    /// Remaining time as "2 h 05 min"; `None` when it is not known.
    pub fn time_text(&self) -> Option<TimeText> {
        let m = match self.state {
            State::Discharging => self.minutes_to_empty?,
            State::Charging => self.minutes_to_full?,
            _ => return None,
        };
        Some(TimeText(m))
    }

    /// Health: last full capacity against design capacity, in percent.
    pub fn health_percent(&self) -> Option<u32> {
        let (full, design) = (self.capacity_mwh?, self.design_mwh?);
        (design > 0).then(|| (full as u64 * 100 / design as u64).min(100) as u32)
    }
}

/// `h:mm` style text of a number of minutes.
pub struct TimeText(pub u32);

impl fmt::Display for TimeText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.0 / 60, self.0 % 60) {
            (0, m) => write!(f, "{m} min"),
            (h, 0) => write!(f, "{h} h"),
            (h, m) => write!(f, "{h} h {m:02} min"),
        }
    }
}

impl fmt::Display for Status {
    /// The file contents, newline included.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.state == State::None {
            return writeln!(f, "none");
        }
        writeln!(f, "{} {} {}", self.percent.min(100), self.charging() as u8, self.ac as u8)?;
        write!(f, "state={} batteries={}", self.state.as_str(), self.batteries)?;
        let mut num = |k: &str, v: Option<u32>| -> fmt::Result {
            match v {
                Some(v) => write!(f, " {k}={v}"),
                None => Ok(()),
            }
        };
        num("empty", self.minutes_to_empty)?;
        num("full", self.minutes_to_full)?;
        num("energy", self.energy_mwh)?;
        num("capacity", self.capacity_mwh)?;
        num("design", self.design_mwh)?;
        num("rate", self.rate_mw)?;
        num("voltage", self.voltage_mv)?;
        if self.stale {
            write!(f, " stale=1")?;
        }
        writeln!(f)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::ToString;

    #[test]
    fn old_format_still_parses() {
        let s = Status::parse("73 1 1\n").unwrap();
        assert_eq!((s.percent, s.state, s.ac), (73, State::Charging, true));
        let s = Status::parse("12 0 0\n").unwrap();
        assert_eq!((s.percent, s.state, s.ac), (12, State::Discharging, false));
        let s = Status::parse("100 0 1\n").unwrap();
        assert_eq!(s.state, State::Idle);
        assert_eq!(Status::parse("none\n"), Some(Status::NONE));
        assert!(Status::parse("").is_none());
        assert!(Status::parse("garbage").is_none());
        assert_eq!(Status::parse("250 0 0").unwrap().percent, 100);
    }

    #[test]
    fn round_trip() {
        let s = Status {
            state: State::Discharging,
            percent: 42,
            ac: false,
            batteries: 2,
            minutes_to_empty: Some(135),
            energy_mwh: Some(20_000),
            capacity_mwh: Some(45_000),
            design_mwh: Some(50_000),
            rate_mw: Some(9_500),
            voltage_mv: Some(11_400),
            ..Status::NONE
        };
        let text = s.to_string();
        assert!(text.starts_with("42 0 0\nstate=discharging batteries=2 empty=135 "), "{text}");
        assert_eq!(Status::parse(&text), Some(s));
        assert_eq!(s.health_percent(), Some(90));
        assert_eq!(s.time_text().unwrap().to_string(), "2 h 15 min");
        assert_eq!(Status::NONE.to_string(), "none\n");
        let stale = Status { stale: true, state: State::Unknown, percent: 50, batteries: 1, ..Status::NONE };
        assert_eq!(Status::parse(&stale.to_string()), Some(stale));
    }

    #[test]
    fn unknown_keys_and_values_are_ignored() {
        let s = Status::parse("50 1 1\nstate=charging future=7 full=bad full=30 junk\n").unwrap();
        assert_eq!(s.minutes_to_full, Some(30));
        assert_eq!(s.state, State::Charging);
        let s = Status::parse("50 0 1\nstate=weird\n").unwrap();
        assert_eq!(s.state, State::Idle, "an unknown state falls back to the first line");
    }

    #[test]
    fn time_text() {
        assert_eq!(TimeText(5).to_string(), "5 min");
        assert_eq!(TimeText(60).to_string(), "1 h");
        assert_eq!(TimeText(61).to_string(), "1 h 01 min");
    }
}
