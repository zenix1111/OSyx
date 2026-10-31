//! i8042 PS/2 controller: the built-in keyboard (and, in its PS/2 mouse
//! emulation, the touchpad) of most laptops, and the PS/2 ports of desktops.
//!
//! The controller is polled from its own kernel thread once per timer tick
//! (1 kHz) instead of taking IRQ 1/12, which would need an I/O APIC driver.
//! Nothing is lost while the thread is away: the controller holds the
//! device clock low while its one-byte output buffer is full, and the
//! keyboard and mouse buffer what they have to send meanwhile.
//!
//! The keyboard runs scan code set 2 with the controller translating to set
//! 1, which is converted to HID usages for the input core. The mouse is
//! reset and switched to IntelliMouse mode when it supports it (wheel,
//! 4-byte packets); touchpads behind I2C rather than PS/2 are in `drivers::i2c`.

use crate::arch::cpu::{inb, outb};
use crate::arch::timer::{self, Deadline};
use crate::{input, kprintln, sched};

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;

const ST_OUTPUT_FULL: u8 = 1 << 0;
const ST_INPUT_FULL: u8 = 1 << 1;
const ST_AUX_DATA: u8 = 1 << 5;

const CFG_KBD_IRQ: u8 = 1 << 0;
const CFG_AUX_IRQ: u8 = 1 << 1;
const CFG_KBD_CLOCK_OFF: u8 = 1 << 4;
const CFG_AUX_CLOCK_OFF: u8 = 1 << 5;
const CFG_TRANSLATE: u8 = 1 << 6;

const ACK: u8 = 0xFA;
const RESEND: u8 = 0xFE;

/// Starts the controller thread. Call after the xHCI handoff, so that USB
/// legacy emulation no longer traps ports 0x60/0x64.
pub fn start() {
    sched::spawn_kernel("ps2", thread, 0, 0);
}

fn thread(_: u64, _: u64) {
    let Some(mut c) = Controller::init() else { return };
    loop {
        c.poll();
        timer::sleep_ms(1);
    }
}

fn status() -> u8 {
    // SAFETY: reading the i8042 status register has no side effects.
    unsafe { inb(STATUS) }
}

/// Waits until the controller accepts a byte; false if it never does.
fn wait_input_empty() -> bool {
    let d = Deadline::after_ms(50);
    while status() & ST_INPUT_FULL != 0 {
        if d.expired() {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

fn command(c: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    // SAFETY: i8042 command port, owned by this driver.
    unsafe { outb(COMMAND, c) };
    true
}

fn write_data(b: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    // SAFETY: i8042 data port, owned by this driver.
    unsafe { outb(DATA, b) };
    true
}

/// Next byte from either device within `ms`: (byte, from the aux port).
fn read(ms: u64) -> Option<(u8, bool)> {
    let d = Deadline::after_ms(ms);
    loop {
        let s = status();
        if s & ST_OUTPUT_FULL != 0 {
            // SAFETY: the output buffer is full, so this read consumes it.
            return Some((unsafe { inb(DATA) }, s & ST_AUX_DATA != 0));
        }
        if d.expired() {
            return None;
        }
        timer::sleep_ms(1);
    }
}

fn flush() {
    for _ in 0..64 {
        if status() & ST_OUTPUT_FULL == 0 {
            break;
        }
        // SAFETY: discards a pending byte.
        unsafe { inb(DATA) };
    }
}

/// Sends a byte to the keyboard (or the aux device) and returns its answer
/// (normally ACK), resending on RESEND.
fn device_write(aux: bool, b: u8) -> Option<u8> {
    for _ in 0..3 {
        if aux && !command(0xD4) {
            return None;
        }
        if !write_data(b) {
            return None;
        }
        let d = Deadline::after_ms(250);
        while !d.expired() {
            match read(250) {
                Some((RESEND, a)) if a == aux => break,
                Some((r, a)) if a == aux => return Some(r),
                Some(_) => continue,
                None => return None,
            }
        }
    }
    None
}

fn device_cmd(aux: bool, b: u8) -> bool {
    device_write(aux, b) == Some(ACK)
}

fn read_config() -> Option<u8> {
    if !command(0x20) {
        return None;
    }
    read(100).map(|(b, _)| b)
}

fn write_config(cfg: u8) -> bool {
    command(0x60) && write_data(cfg)
}

struct Keyboard {
    id: u32,
    extended: bool,
    /// Bytes left of the 6-byte Pause sequence (E1 1D 45 E1 9D C5).
    pause_left: u8,
}

struct Mouse {
    id: u32,
    packet: [u8; 4],
    len: usize,
    have: usize,
}

struct Controller {
    keyboard: Option<Keyboard>,
    mouse: Option<Mouse>,
}

impl Controller {
    fn init() -> Option<Controller> {
        if status() == 0xFF {
            kprintln!("ps2: no i8042 controller");
            return None;
        }
        // Both ports off while the configuration changes.
        command(0xAD);
        command(0xA7);
        flush();
        let Some(cfg) = read_config() else {
            kprintln!("ps2: i8042 does not answer; no PS/2 input");
            return None;
        };
        // Polled: no IRQs. Translation on: the keyboard's set 2 arrives as set 1.
        let cfg = (cfg & !(CFG_KBD_IRQ | CFG_AUX_IRQ | CFG_KBD_CLOCK_OFF)) | CFG_TRANSLATE;
        write_config(cfg);
        // A second port exists if enabling it clears its clock-off bit.
        command(0xA8);
        let aux_present = read_config().is_some_and(|c| c & CFG_AUX_CLOCK_OFF == 0);
        command(0xA7);
        flush();

        command(0xAE);
        let keyboard = Self::init_keyboard();
        let mouse = if aux_present {
            command(0xA8);
            Self::init_mouse()
        } else {
            None
        };
        if let Some(c) = read_config() {
            write_config(c & !(CFG_KBD_IRQ | CFG_AUX_IRQ));
        }
        flush();
        kprintln!(
            "ps2: i8042 ready: keyboard {}, aux port {}",
            if keyboard.is_some() { "found" } else { "not answering" },
            match (&mouse, aux_present) {
                (Some(m), _) if m.len == 4 => "mouse with wheel",
                (Some(_), _) => "mouse",
                (None, true) => "present, no mouse answering",
                (None, false) => "absent",
            }
        );
        if keyboard.is_none() && mouse.is_none() {
            return None;
        }
        Some(Controller { keyboard, mouse })
    }

    fn init_keyboard() -> Option<Keyboard> {
        // Stop scanning, select set 2 (translated to set 1), scan again.
        if !device_cmd(false, 0xF5) {
            return None;
        }
        if device_cmd(false, 0xF0) {
            device_cmd(false, 0x02);
        }
        device_cmd(false, 0xF4);
        let id = input::register("PS/2 keyboard", osyx_input::class::KEYBOARD);
        Some(Keyboard { id, extended: false, pause_left: 0 })
    }

    fn init_mouse() -> Option<Mouse> {
        if device_write(true, 0xFF) != Some(ACK) {
            return None;
        }
        // Self-test result (AA) and device id (00) follow the reset.
        let mut passed = false;
        let d = Deadline::after_ms(1500);
        while !d.expired() {
            match read(100) {
                Some((0xAA, true)) => passed = true,
                Some((0x00, true)) if passed => break,
                _ => {}
            }
        }
        if !passed {
            return None;
        }
        device_cmd(true, 0xF6);
        // IntelliMouse knock: sample rates 200, 100, 80, then id 3 = wheel.
        let mut len = 3;
        if [200u8, 100, 80].iter().all(|&r| device_cmd(true, 0xF3) && device_cmd(true, r)) && device_cmd(true, 0xF2) {
            if let Some((3, true)) = read(100) {
                len = 4;
            }
        }
        if !device_cmd(true, 0xF4) {
            return None;
        }
        let id = input::register("PS/2 mouse", osyx_input::class::MOUSE);
        Some(Mouse { id, packet: [0; 4], len, have: 0 })
    }

    fn poll(&mut self) {
        for _ in 0..64 {
            let s = status();
            if s & ST_OUTPUT_FULL == 0 {
                return;
            }
            // SAFETY: the output buffer is full, so this read consumes it.
            let b = unsafe { inb(DATA) };
            if s & ST_AUX_DATA != 0 {
                if let Some(m) = self.mouse.as_mut() {
                    m.byte(b);
                }
            } else if let Some(k) = self.keyboard.as_mut() {
                k.byte(b);
            }
        }
    }
}

impl Keyboard {
    fn byte(&mut self, b: u8) {
        if self.pause_left > 0 {
            self.pause_left -= 1;
            if self.pause_left == 0 {
                input::key(self.id, 0x48, true);
                input::key(self.id, 0x48, false);
            }
            return;
        }
        match b {
            0xE0 => {
                self.extended = true;
                return;
            }
            0xE1 => {
                self.pause_left = 5;
                return;
            }
            // Overrun / acknowledge bytes, not key codes.
            0x00 | 0xFF | ACK | RESEND => return,
            _ => {}
        }
        let down = b & 0x80 == 0;
        let usage = if self.extended { set1_extended(b & 0x7F) } else { set1(b & 0x7F) };
        self.extended = false;
        if usage != 0 {
            input::key(self.id, usage, down);
        }
    }
}

impl Mouse {
    fn byte(&mut self, b: u8) {
        // Bit 3 of the first byte is always set; anything else means the
        // stream is out of step, so wait for the next plausible start.
        if self.have == 0 && b & 0x08 == 0 {
            return;
        }
        self.packet[self.have] = b;
        self.have += 1;
        if self.have < self.len {
            return;
        }
        self.have = 0;
        let p = self.packet;
        if p[0] & 0xC0 != 0 {
            return; // X/Y overflow
        }
        let dx = p[1] as i32 - if p[0] & 0x10 != 0 { 256 } else { 0 };
        let dy = p[2] as i32 - if p[0] & 0x20 != 0 { 256 } else { 0 };
        for (i, bit) in [1u8, 2, 4].into_iter().enumerate() {
            input::button(self.id, i as u16 + 1, p[0] & bit != 0);
        }
        // PS/2 Y grows upwards, the input core's (like HID's) downwards.
        input::motion(self.id, dx, -dy);
        if self.len == 4 {
            // 4-bit signed Z, positive when scrolling down.
            let z = (((p[3] & 0x0F) << 4) as i8 >> 4) as i32;
            input::wheel(self.id, -z, 0);
        }
    }
}

/// Scan code set 1 (make codes 0x01..=0x58) to HID keyboard usages.
#[rustfmt::skip]
const SET1: [u8; 0x59] = [
    0x00, 0x29, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2D, 0x2E, 0x2A, 0x2B, // 00-0F
    0x14, 0x1A, 0x08, 0x15, 0x17, 0x1C, 0x18, 0x0C, 0x12, 0x13, 0x2F, 0x30, 0x28, 0xE0, 0x04, 0x16, // 10-1F
    0x07, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F, 0x33, 0x34, 0x35, 0xE1, 0x31, 0x1D, 0x1B, 0x06, 0x19, // 20-2F
    0x05, 0x11, 0x10, 0x36, 0x37, 0x38, 0xE5, 0x55, 0xE2, 0x2C, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, // 30-3F
    0x3F, 0x40, 0x41, 0x42, 0x43, 0x53, 0x47, 0x5F, 0x60, 0x61, 0x56, 0x5C, 0x5D, 0x5E, 0x57, 0x59, // 40-4F
    0x5A, 0x5B, 0x62, 0x63, 0x00, 0x00, 0x64, 0x44, 0x45,                                           // 50-58
];

fn set1(code: u8) -> u16 {
    SET1.get(code as usize).copied().unwrap_or(0) as u16
}

/// E0-prefixed set 1 codes. The fake shifts around some of them (E0 2A,
/// E0 36) map to nothing.
fn set1_extended(code: u8) -> u16 {
    match code {
        0x1C => 0x58, // keypad Enter
        0x1D => 0xE4, // right Ctrl
        0x20 => 0x7F, // Mute
        0x2E => 0x81, // Volume Down
        0x30 => 0x80, // Volume Up
        0x35 => 0x54, // keypad /
        0x37 => 0x46, // Print Screen
        0x38 => 0xE6, // right Alt (AltGr)
        0x47 => 0x4A, // Home
        0x48 => 0x52, // Up
        0x49 => 0x4B, // Page Up
        0x4B => 0x50, // Left
        0x4D => 0x4F, // Right
        0x4F => 0x4D, // End
        0x50 => 0x51, // Down
        0x51 => 0x4E, // Page Down
        0x52 => 0x49, // Insert
        0x53 => 0x4C, // Delete
        0x5B => 0xE3, // left GUI
        0x5C => 0xE7, // right GUI
        0x5D => 0x65, // Application
        _ => 0,
    }
}

