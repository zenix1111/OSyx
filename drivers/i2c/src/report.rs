//! HID input reports as key, button, motion and wheel changes.
//!
//! The report descriptor is parsed with the same parser as USB HID
//! (`osyx_usb::hid`). Three kinds of input are recognised, in any
//! combination and with report ids:
//!
//! * keyboards: modifier bits, key arrays and key bitmaps (usage page 7);
//! * mice: relative X/Y, buttons and wheels, through the USB mouse layout.
//!   Precision touchpads start in this mode (the Windows Precision
//!   Touchpad specification makes mouse the default), so pointer motion
//!   and clicks work without switching the device mode;
//! * precision touchpads in their own mode: one finger moves the pointer,
//!   scaled by the pad's physical size, and the pad's button 1 is the left
//!   button. Gestures (tap, scroll) are not interpreted.
//!
//! Touchscreens (contacts without a button) are not supported: the input
//! core has no absolute events.

use alloc::vec::Vec;
use osyx_usb::hid::{self, Field, MouseLayout, ParseError, ReportError, PAGE_BUTTON, PAGE_GENERIC_DESKTOP, PAGE_KEYBOARD, USAGE_X, USAGE_Y};

/// One change for the input core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// HID keyboard usage (page 7).
    Key { usage: u16, down: bool },
    /// Button number starting at 1 (left, right, middle, ...).
    Button { number: u8, down: bool },
    Motion { dx: i32, dy: i32 },
    Wheel { vertical: i32, horizontal: i32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceClass {
    Keyboard,
    Pointer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Parse(ParseError),
    /// The descriptor describes no keyboard, mouse or touchpad this driver
    /// can use (a touchscreen, a sensor hub, a vendor device).
    Unsupported,
}

const PAGE_DIGITIZER: u16 = 0x0D;
const USAGE_TIP_SWITCH: u16 = 0x42;
const USAGE_CONFIDENCE: u16 = 0x47;
const USAGE_CONTACT_ID: u16 = 0x51;
const USAGE_CONTACT_COUNT: u16 = 0x54;

/// Micrometres of finger travel that move the pointer one pixel (8 pixels
/// per millimetre: a 100 mm pad crosses 800 pixels).
const UM_PER_PIXEL: i64 = 125;
/// Assumed pad size when the descriptor gives no physical range.
const DEFAULT_WIDTH_UM: i64 = 100_000;
const DEFAULT_HEIGHT_UM: i64 = 70_000;
/// Sub-pixel resolution of the touchpad motion accumulator.
const FRACTION: i64 = 256;

// ---- keyboards --------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct KeyboardLayout {
    report_id: u8,
    modifiers: Vec<(u16, Field)>,
    array: Vec<Field>,
    bitmap: Vec<(u16, Field)>,
}

impl KeyboardLayout {
    fn from_fields(fields: &[Field]) -> Option<KeyboardLayout> {
        let keys = || fields.iter().filter(|f| f.page == PAGE_KEYBOARD && !f.relative);
        let report_id = keys().find(|f| f.usage == 0 || (4..=0xE7).contains(&f.usage))?.report_id;
        let mut k = KeyboardLayout { report_id, modifiers: Vec::new(), array: Vec::new(), bitmap: Vec::new() };
        for f in keys().filter(|f| f.report_id == report_id) {
            match f.usage {
                0 if f.size >= 8 => k.array.push(*f),
                0xE0..=0xE7 if f.size == 1 => k.modifiers.push((f.usage, *f)),
                4..=0xDF if f.size == 1 => k.bitmap.push((f.usage, *f)),
                _ => {}
            }
        }
        (!k.modifiers.is_empty() || !k.array.is_empty() || !k.bitmap.is_empty()).then_some(k)
    }

    /// The keys held according to `data`.
    fn pressed(&self, data: &[u8]) -> Result<Vec<u16>, ReportError> {
        let mut now = Vec::new();
        for (usage, f) in &self.modifiers {
            if f.read(data).ok_or(ReportError::Truncated)? != 0 {
                now.push(*usage);
            }
        }
        // Modifiers come first, in field order; the other keys by usage.
        let keys_from = now.len();
        for f in &self.array {
            let v = f.read(data).ok_or(ReportError::Truncated)?;
            match v {
                0 => {}
                // ErrorRollOver, POSTFail, ErrorUndefined.
                1..=3 => return Err(ReportError::Rollover),
                v if v > 0xFFFF => {}
                v => now.push(v as u16),
            }
        }
        for (usage, f) in &self.bitmap {
            if f.read(data).ok_or(ReportError::Truncated)? != 0 {
                now.push(*usage);
            }
        }
        now[keys_from..].sort_unstable();
        now.dedup();
        Ok(now)
    }
}

// ---- precision touchpads ----------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Contact {
    confidence: Option<Field>,
    tip: Field,
    id: Option<Field>,
    x: Field,
    y: Field,
}

#[derive(Default)]
struct ContactBuilder {
    confidence: Option<Field>,
    tip: Option<Field>,
    id: Option<Field>,
    x: Option<Field>,
    y: Option<Field>,
}

impl ContactBuilder {
    fn finish(&self) -> Option<Contact> {
        Some(Contact { confidence: self.confidence, tip: self.tip?, id: self.id, x: self.x?, y: self.y? })
    }
}

#[derive(Clone, Debug)]
struct TouchLayout {
    report_id: u8,
    contacts: Vec<Contact>,
    count: Option<Field>,
    button: Field,
    /// Fixed-point (1/FRACTION pixel) per logical unit.
    scale_x: i64,
    scale_y: i64,
}

/// The extent of a field's physical range in micrometres, if the
/// descriptor declares it in centimetres or inches.
fn extent_um(f: &Field) -> Option<i64> {
    let span = (f.physical_max as i64).checked_sub(f.physical_min as i64)?;
    if span <= 0 {
        return None;
    }
    let unit_um: i64 = match f.unit {
        0x11 => 10_000,
        0x13 => 25_400,
        _ => return None,
    };
    let mut v = span.checked_mul(unit_um)?;
    let e = f.unit_exponent as i32;
    for _ in 0..e.max(0) {
        v = v.checked_mul(10)?;
    }
    for _ in 0..(-e).max(0) {
        v /= 10;
    }
    (v > 0).then_some(v)
}

impl TouchLayout {
    fn from_fields(fields: &[Field]) -> Option<TouchLayout> {
        let report_id = fields.iter().find(|f| f.page == PAGE_DIGITIZER && f.usage == USAGE_TIP_SWITCH)?.report_id;
        let mut contacts = Vec::new();
        let mut cur = ContactBuilder::default();
        let mut count = None;
        let mut button = None;
        for f in fields.iter().filter(|f| f.report_id == report_id) {
            // A field that the current contact already has starts the next one.
            macro_rules! slot {
                ($slot:ident) => {{
                    if cur.$slot.is_some() {
                        contacts.extend(cur.finish());
                        cur = ContactBuilder::default();
                    }
                    cur.$slot = Some(*f);
                }};
            }
            match (f.page, f.usage) {
                (PAGE_DIGITIZER, USAGE_CONFIDENCE) => slot!(confidence),
                (PAGE_DIGITIZER, USAGE_TIP_SWITCH) => slot!(tip),
                (PAGE_DIGITIZER, USAGE_CONTACT_ID) => slot!(id),
                (PAGE_GENERIC_DESKTOP, USAGE_X) if !f.relative => slot!(x),
                (PAGE_GENERIC_DESKTOP, USAGE_Y) if !f.relative => slot!(y),
                (PAGE_DIGITIZER, USAGE_CONTACT_COUNT) => count = Some(*f),
                (PAGE_BUTTON, 1) if button.is_none() => button = Some(*f),
                _ => {}
            }
        }
        contacts.extend(cur.finish());
        // A touchpad has a button; a touchscreen does not.
        let button = button?;
        let first = contacts.first()?;
        let scale = |f: &Field, default_um: i64| {
            let range = (f.logical_max as i64 - f.logical_min as i64).max(1);
            let extent = extent_um(f).unwrap_or(default_um);
            (extent * FRACTION / (range * UM_PER_PIXEL)).max(1)
        };
        Some(TouchLayout {
            report_id,
            scale_x: scale(&first.x, DEFAULT_WIDTH_UM),
            scale_y: scale(&first.y, DEFAULT_HEIGHT_UM),
            contacts,
            count,
            button,
        })
    }
}

#[derive(Default)]
struct TouchState {
    /// The finger that moves the pointer: contact id and last position.
    tracked: Option<(i32, i32, i32)>,
    remainder: (i64, i64),
    button: bool,
}

struct Finger {
    id: i32,
    tip: bool,
    x: i32,
    y: i32,
}

impl TouchState {
    fn decode(&mut self, l: &TouchLayout, data: &[u8], out: &mut Vec<Action>) -> Result<(), ReportError> {
        let mut fingers = Vec::new();
        for (n, c) in l.contacts.iter().enumerate() {
            let tip = c.tip.read(data).ok_or(ReportError::Truncated)? != 0;
            // A palm or an unsure contact is not a finger.
            let confident = c.confidence.is_none_or(|f| f.read(data).is_none_or(|v| v != 0));
            let id = c.id.and_then(|f| f.read(data)).unwrap_or(n as i32);
            let x = c.x.read(data).ok_or(ReportError::Truncated)?;
            let y = c.y.read(data).ok_or(ReportError::Truncated)?;
            fingers.push(Finger { id, tip: tip && confident, x, y });
        }
        let count = l.count.and_then(|f| f.read(data));
        match self.tracked {
            Some((id, px, py)) => match fingers.iter().find(|f| f.id == id) {
                Some(f) if f.tip => {
                    let (dx, dy) = (f.x as i64 - px as i64, f.y as i64 - py as i64);
                    self.tracked = Some((id, f.x, f.y));
                    self.remainder.0 += dx * l.scale_x;
                    self.remainder.1 += dy * l.scale_y;
                    let (mx, my) = (self.remainder.0 / FRACTION, self.remainder.1 / FRACTION);
                    self.remainder.0 -= mx * FRACTION;
                    self.remainder.1 -= my * FRACTION;
                    if mx != 0 || my != 0 {
                        out.push(Action::Motion { dx: mx as i32, dy: my as i32 });
                    }
                }
                Some(_) => self.lift(),
                // Not listed: either a report that carries only some of
                // the contacts, or the end of the touch.
                None if count == Some(0) => self.lift(),
                None => {}
            },
            None => {
                if let Some(f) = fingers.iter().find(|f| f.tip) {
                    self.tracked = Some((f.id, f.x, f.y));
                    self.remainder = (0, 0);
                }
            }
        }
        let down = l.button.read(data).ok_or(ReportError::Truncated)? != 0;
        if down != self.button {
            self.button = down;
            out.push(Action::Button { number: 1, down });
        }
        Ok(())
    }

    fn lift(&mut self) {
        self.tracked = None;
        self.remainder = (0, 0);
    }
}

// ---- the decoder ------------------------------------------------------------------------------

pub struct ReportDecoder {
    uses_ids: bool,
    keyboard: Option<(KeyboardLayout, Vec<u16>)>,
    mouse: Option<(MouseLayout, u32)>,
    touch: Option<(TouchLayout, TouchState)>,
}

impl ReportDecoder {
    pub fn from_descriptor(desc: &[u8]) -> Result<ReportDecoder, DecodeError> {
        let fields = hid::parse_report_descriptor(desc).map_err(DecodeError::Parse)?;
        let d = ReportDecoder {
            uses_ids: fields.iter().any(|f| f.report_id != 0),
            keyboard: KeyboardLayout::from_fields(&fields).map(|l| (l, Vec::new())),
            mouse: MouseLayout::from_fields(&fields).map(|l| (l, 0)),
            touch: TouchLayout::from_fields(&fields).map(|l| (l, TouchState::default())),
        };
        if d.keyboard.is_none() && d.mouse.is_none() && d.touch.is_none() {
            return Err(DecodeError::Unsupported);
        }
        Ok(d)
    }

    pub fn class(&self) -> DeviceClass {
        if self.keyboard.is_some() {
            DeviceClass::Keyboard
        } else {
            DeviceClass::Pointer
        }
    }

    /// (keyboard, mouse, touchpad): what the descriptor offers.
    pub fn kinds(&self) -> (bool, bool, bool) {
        (self.keyboard.is_some(), self.mouse.is_some(), self.touch.is_some())
    }

    /// Releases everything that is held (after a device reset, when the
    /// device has forgotten what it reported).
    pub fn release_all(&mut self, out: &mut Vec<Action>) {
        if let Some((_, held)) = &mut self.keyboard {
            out.extend(held.drain(..).map(|usage| Action::Key { usage, down: false }));
        }
        if let Some((_, buttons)) = &mut self.mouse {
            out.extend((0..32u8).filter(|b| *buttons & (1 << b) != 0).map(|b| Action::Button { number: b + 1, down: false }));
            *buttons = 0;
        }
        if let Some((_, state)) = &mut self.touch {
            if state.button {
                out.push(Action::Button { number: 1, down: false });
            }
            *state = TouchState::default();
        }
    }

    /// Decodes one input report (starting with its report id if the
    /// descriptor uses ids) and appends the changes.
    pub fn decode(&mut self, report: &[u8], out: &mut Vec<Action>) -> Result<(), ReportError> {
        let (id, data) = if self.uses_ids {
            match report.split_first() {
                Some((&id, rest)) => (id, rest),
                None => return Err(ReportError::Truncated),
            }
        } else {
            (0, report)
        };
        let mut known = false;
        let mut result = Ok(());
        if let Some((l, held)) = &mut self.keyboard {
            if l.report_id == id {
                known = true;
                match l.pressed(data) {
                    Ok(now) => {
                        for &u in held.iter().filter(|u| !now.contains(u)) {
                            out.push(Action::Key { usage: u, down: false });
                        }
                        for &u in now.iter().filter(|u| !held.contains(u)) {
                            out.push(Action::Key { usage: u, down: true });
                        }
                        *held = now;
                    }
                    Err(e) => result = Err(e),
                }
            }
        }
        if let Some((l, buttons)) = &mut self.mouse {
            if l.report_id == id {
                known = true;
                match l.decode_data(data) {
                    Ok(r) => {
                        let changed = r.buttons ^ *buttons;
                        for b in 0..32u8 {
                            if changed & (1 << b) != 0 {
                                out.push(Action::Button { number: b + 1, down: r.buttons & (1 << b) != 0 });
                            }
                        }
                        *buttons = r.buttons;
                        if r.dx != 0 || r.dy != 0 {
                            out.push(Action::Motion { dx: r.dx, dy: r.dy });
                        }
                        if r.wheel != 0 || r.pan != 0 {
                            out.push(Action::Wheel { vertical: r.wheel, horizontal: r.pan });
                        }
                    }
                    Err(e) => result = Err(e),
                }
            }
        }
        if let Some((l, state)) = &mut self.touch {
            if l.report_id == id {
                known = true;
                if let Err(e) = state.decode(l, data, out) {
                    result = Err(e);
                }
            }
        }
        if !known {
            return Err(ReportError::UnknownReportId);
        }
        result
    }
}
