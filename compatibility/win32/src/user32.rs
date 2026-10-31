//! user32.dll and gdi32.dll on PRISM.
//!
//! Every top-level Win32 window is a PRISM window: PRISM draws the frame
//! and title bar, the window's client area is the PRISM surface, so the
//! client size is the PRISM content size (AdjustWindowRect is therefore an
//! identity). Messages come from PRISM events (configure → WM_SIZE, close
//! button → WM_CLOSE, keyboard → WM_KEYDOWN/UP and WM_CHAR, pointer →
//! WM_MOUSEMOVE / WM_xBUTTONDOWN/UP / WM_MOUSEWHEEL) plus the program's own
//! posted messages, timers and WM_PAINT for invalid areas. GDI draws with
//! OSyx's software renderer into the surface; EndPaint/ReleaseDC present
//! the damaged rectangle to PRISM. Child windows (controls) are not
//! implemented: CreateWindowEx with WS_CHILD fails with ERROR_NOT_SUPPORTED.
//!
//! Window procedures are never called while the GUI lock is held.

#![allow(non_snake_case)]

use crate::error::*;
use crate::kernel32::{fail, out_a, out_w, Bool, FALSE, TRUE};
use crate::{path, teb};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;
use os_std::sync::Mutex;
use os_std::time::Instant;
use osyx_gfx::prop::PropFont;
use osyx_gfx::text::Font as MonoFont;
use osyx_gfx::{Color, Rect, Surface};
use prism_client::{proto, Connection, Event, Window, WindowSpec};

mod gdi;
mod keyboard;
pub(crate) mod dialogs;
use gdi::{Bitmap, GdiPath, Region, Xform};

static SANS14: &[u8] = include_bytes!("../../../graphics/assets/sans14.osxp");
static SANS14B: &[u8] = include_bytes!("../../../graphics/assets/sans14b.osxp");
static SANS20: &[u8] = include_bytes!("../../../graphics/assets/sans20.osxp");
static MONO15: &[u8] = include_bytes!("../../../graphics/assets/mono15.osxf");

// ---- messages ------------------------------------------------------------------------

pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_SIZE: u32 = 0x0005;
const WM_MOVE: u32 = 0x0003;
const WM_WINDOWPOSCHANGING: u32 = 0x0046;
const WM_WINDOWPOSCHANGED: u32 = 0x0047;
pub const WM_ACTIVATE: u32 = 0x0006;
pub const WM_SETFOCUS: u32 = 0x0007;
pub const WM_KILLFOCUS: u32 = 0x0008;
pub const WM_SETTEXT: u32 = 0x000C;
const WM_GETTEXT: u32 = 0x000D;
pub const WM_GETTEXTLENGTH: u32 = 0x000E;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_ERASEBKGND: u32 = 0x0014;
pub const WM_SHOWWINDOW: u32 = 0x0018;
pub const WM_NCCREATE: u32 = 0x0081;
pub const WM_NCDESTROY: u32 = 0x0082;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_LBUTTONDBLCLK: u32 = 0x0203;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MBUTTONUP: u32 = 0x0208;
pub const WM_MOUSEWHEEL: u32 = 0x020A;
const WM_CAPTURECHANGED: u32 = 0x0215;
const WM_OSYX_FILE_DROP: u32 = 0x7fff_ff01;
const WM_MOUSELEAVE: u32 = 0x02A3;

const WS_CHILD: u32 = 0x4000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_MINIMIZE: u32 = 0x2000_0000;
const WS_MAXIMIZE: u32 = 0x0100_0000;
const CW_USEDEFAULT: i32 = 0x8000_0000u32 as i32;

type WndProc = extern "win64" fn(u64, u32, u64, i64) -> i64;
type TimerProc = extern "win64" fn(u64, u32, u64, u32);

#[derive(Clone, Copy)]
struct Msg {
    hwnd: u64,
    msg: u32,
    wparam: u64,
    lparam: i64,
    time: u32,
    pt: (i32, i32),
    /// The thread whose queue holds it: the window's, or the poster's for
    /// a thread message.
    thread: u64,
}

#[repr(C)]
struct WindowPos {
    hwnd: u64,
    after: u64,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: u32,
    padding: u32,
}

struct Class {
    name: String,
    wndproc: u64,
    background: u64,
    style: u32,
}

struct Win {
    class: usize,
    /// The thread that created the window (EnumThreadWindows).
    thread: u64,
    wndproc: u64,
    title: String,
    style: u32,
    ex_style: u32,
    owner: u64,
    win: Window,
    pos: (i32, i32),
    size: (u32, u32),
    /// The most recent normal geometry, preserved while maximized/minimized.
    normal: Rect,
    /// ShowWindow changes state synchronously; older Configure events must
    /// not undo it while the compositor is acknowledging the request.
    pending_state: Option<u32>,
    restore_maximized: bool,
    /// Last size reported with WM_SIZE.
    reported: Option<(u32, u32)>,
    visible: bool,
    invalid: Option<Rect>,
    erase: bool,
    user_data: i64,
    /// Rectangle drawn since the last present (BeginPaint/GetDC).
    drawn: Option<Rect>,
}

/// ICONINFO: icon or cursor, hotspot, and its own mask and colour bitmaps.
struct Icon {
    is_icon: bool,
    hotspot: (u32, u32),
    mask: u64,
    color: u64,
}

struct Timer {
    /// The window's thread, or SetTimer's caller for a thread timer.
    thread: u64,
    hwnd: u64,
    id: u64,
    interval: u64,
    due: Instant,
    proc_: u64,
}

#[derive(Clone, Copy)]
enum FontKind {
    Sans,
    SansBold,
    Large,
    Mono,
}

#[derive(Clone, Copy)]
enum Gdi {
    Brush(Color),
    NullBrush,
    Pen(Color, u32),
    NullPen,
    Font(FontKind),
    Bitmap,
    Region,
}

#[derive(Clone)]
struct Dc {
    hwnd: u64,
    made: Instant,
    paint: Rect,
    text: Color,
    bk: Color,
    opaque: bool,
    brush: u64,
    pen: u64,
    font: u64,
    pos: (i32, i32),
    bitmap: u64,
    memory: bool,
    clip: Option<Region>,
    transform: Xform,
    align: u32,
    graphics_mode: i32,
    map_mode: i32,
    poly_mode: i32,
    stretch_mode: i32,
    miter: f32,
    saved: Vec<Dc>,
    path: GdiPath,
}

struct Gui {
    conn: Option<Connection>,
    sync_cookie: u32,
    sync_done: u32,
    classes: Vec<Class>,
    windows: BTreeMap<u64, Win>,
    /// PRISM window id → HWND.
    by_prism: BTreeMap<u32, u64>,
    queue: VecDeque<Msg>,
    /// Nonqueued frame notifications, dispatched on the window's thread.
    pending_frames: BTreeMap<u64, u32>,
    timers: Vec<Timer>,
    /// Per thread: the exit code PostQuitMessage left for WM_QUIT.
    quit: BTreeMap<u64, i32>,
    focus: u64,
    /// Characters of key presses waiting for TranslateMessage (vk, char).
    chars: VecDeque<(u32, char)>,
    gdi: BTreeMap<u64, Gdi>,
    dcs: BTreeMap<u64, Dc>,
    bitmaps: BTreeMap<u64, Bitmap>,
    /// Pixel storage of deleted large bitmaps, reused so freshly created
    /// DIB sections do not fault in new zero pages every frame.
    bitmap_pool: Vec<Vec<u32>>,
    regions: BTreeMap<u64, Region>,
    next: u64,
    keys: [bool; 256],
    /// Toggle state (Caps Lock, Num Lock, Scroll Lock...): the low bit of
    /// GetKeyState/GetKeyboardState.
    toggles: [bool; 256],
    /// SetCapture's window (0: none).
    capture: u64,
    /// GetTickCount of the last keyboard or pointer input.
    last_input: u32,
    /// Windows that asked TrackMouseEvent for WM_MOUSELEAVE.
    track_leave: Vec<u64>,
    /// Icons and cursors from CreateIconIndirect.
    icons: BTreeMap<u64, Icon>,
    /// The window that has the clipboard open (Some(0): opened without one).
    clipboard_open: Option<u64>,
    /// The system clipboard as last reported by the compositor (registered
    /// formats resolved to this process's ids).
    clipboard: Vec<proto::ClipEntry>,
    clipboard_seq: u32,
    /// What SetClipboardData put there since EmptyClipboard; published to
    /// the compositor when the clipboard is closed.
    clipboard_own: Vec<proto::ClipEntry>,
    /// HGLOBALs handed out by GetClipboardData for the current contents.
    clipboard_handles: BTreeMap<u32, u64>,
    /// Last pointer position in the window that received it, and on screen.
    pointer: (i32, i32),
    screen_pointer: (i32, i32),
    last_click: (u64, u32, Instant),
    start: Instant,
    /// QS_* kinds queued since the thread last looked (GetQueueStatus'
    /// low word; MsgWaitForMultipleObjects without MWMO_INPUTAVAILABLE).
    fresh: BTreeMap<u64, u32>,
}

static GUI: Mutex<Option<Gui>> = Mutex::new(None);

// Stock objects: fixed handle values.
const STOCK_BASE: u64 = 0x9000;
const WHITE_BRUSH: u32 = 0;
const LTGRAY_BRUSH: u32 = 1;
const GRAY_BRUSH: u32 = 2;
const DKGRAY_BRUSH: u32 = 3;
const BLACK_BRUSH: u32 = 4;
const NULL_BRUSH: u32 = 5;
const WHITE_PEN: u32 = 6;
const BLACK_PEN: u32 = 7;
const NULL_PEN: u32 = 8;
const ANSI_FIXED_FONT: u32 = 11;
const DEFAULT_GUI_FONT: u32 = 17;
const SYSTEM_FONT: u32 = 13;

fn with<R>(f: impl FnOnce(&mut Gui) -> R) -> R {
    let mut g = GUI.lock().unwrap();
    let gui = g.get_or_insert_with(|| {
        let mut gdi = BTreeMap::new();
        for (i, o) in [
            (WHITE_BRUSH, Gdi::Brush(rgb(255, 255, 255))),
            (LTGRAY_BRUSH, Gdi::Brush(rgb(192, 192, 192))),
            (GRAY_BRUSH, Gdi::Brush(rgb(128, 128, 128))),
            (DKGRAY_BRUSH, Gdi::Brush(rgb(64, 64, 64))),
            (BLACK_BRUSH, Gdi::Brush(rgb(0, 0, 0))),
            (NULL_BRUSH, Gdi::NullBrush),
            (WHITE_PEN, Gdi::Pen(rgb(255, 255, 255), 1)),
            (BLACK_PEN, Gdi::Pen(rgb(0, 0, 0), 1)),
            (NULL_PEN, Gdi::NullPen),
            (ANSI_FIXED_FONT, Gdi::Font(FontKind::Mono)),
            (12, Gdi::Font(FontKind::Sans)),
            (SYSTEM_FONT, Gdi::Font(FontKind::Sans)),
            (14, Gdi::Font(FontKind::Sans)),
            (15, Gdi::Font(FontKind::Sans)),
            (16, Gdi::Font(FontKind::Mono)),
            (DEFAULT_GUI_FONT, Gdi::Font(FontKind::Sans)),
        ] {
            gdi.insert(STOCK_BASE + i as u64, o);
        }
        Gui {
            conn: None,
            classes: Vec::new(),
            windows: BTreeMap::new(),
            by_prism: BTreeMap::new(),
            queue: VecDeque::new(),
            pending_frames: BTreeMap::new(),
            sync_cookie: 0,
            sync_done: 0,
            timers: Vec::new(),
            quit: BTreeMap::new(),
            focus: 0,
            chars: VecDeque::new(),
            gdi,
            dcs: BTreeMap::new(),
            bitmaps: BTreeMap::new(),
            bitmap_pool: Vec::new(),
            regions: BTreeMap::new(),
            next: 0x2_0000,
            keys: [false; 256],
            toggles: [false; 256],
            capture: 0,
            last_input: 0,
            track_leave: Vec::new(),
            icons: BTreeMap::new(),
            clipboard_open: None,
            clipboard: Vec::new(),
            clipboard_seq: 0,
            clipboard_own: Vec::new(),
            clipboard_handles: BTreeMap::new(),
            pointer: (0, 0),
            screen_pointer: (0, 0),
            last_click: (0, 0, Instant::now()),
            start: Instant::now(),
            fresh: BTreeMap::new(),
        }
    });
    f(gui)
}

fn rgb(r: u8, g: u8, b: u8) -> Color {
    osyx_gfx::rgb(r, g, b)
}

/// COLORREF (0x00BBGGRR) → OSyx color.
fn colorref(c: u32) -> Color {
    rgb(c as u8, (c >> 8) as u8, (c >> 16) as u8)
}

fn to_colorref(c: Color) -> u32 {
    let (r, g, b) = ((c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF);
    r | g << 8 | b << 16
}

/// GetSysColor: a light Windows-like palette.
fn sys_color(i: u32) -> Color {
    match i {
        5 => rgb(255, 255, 255),  // COLOR_WINDOW
        8 => rgb(0, 0, 0),        // COLOR_WINDOWTEXT
        15 => rgb(240, 240, 240), // COLOR_BTNFACE
        16 => rgb(160, 160, 160), // COLOR_BTNSHADOW
        18 => rgb(0, 0, 0),       // COLOR_BTNTEXT
        13 => rgb(0, 120, 215),   // COLOR_HIGHLIGHT
        14 => rgb(255, 255, 255), // COLOR_HIGHLIGHTTEXT
        17 => rgb(109, 109, 109), // COLOR_GRAYTEXT
        1 => rgb(0, 0, 0),        // COLOR_BACKGROUND
        _ => rgb(240, 240, 240),
    }
}

impl Gui {
    fn handle(&mut self) -> u64 {
        self.next += 4;
        self.next
    }

    /// Zeroed pixel storage for a bitmap. Deleted large buffers are reused so
    /// their pages stay mapped: a fresh 1280x972 DIB faults in ~1200 pages on
    /// first write, which costs more than the drawing itself.
    fn take_bitmap_storage(&mut self, words: usize) -> Vec<u32> {
        const MIN_WORDS: usize = 64 * 1024;
        if words >= MIN_WORDS {
            if let Some(i) = self.bitmap_pool.iter().position(|v| v.capacity() >= words) {
                let mut v = self.bitmap_pool.swap_remove(i);
                v.clear();
                v.resize(words, 0);
                return v;
            }
        }
        alloc::vec![0; words]
    }

    fn recycle_bitmap_storage(&mut self, storage: Vec<u32>) {
        const MIN_WORDS: usize = 64 * 1024;
        // 48 MiB of pooled pixels at most.
        const MAX_WORDS: usize = 12 * 1024 * 1024;
        if storage.capacity() < MIN_WORDS {
            return;
        }
        let pooled: usize = self.bitmap_pool.iter().map(|v| v.capacity()).sum();
        if pooled + storage.capacity() > MAX_WORDS {
            return;
        }
        self.bitmap_pool.push(storage);
    }

    fn now_ms(&self) -> u32 {
        self.start.elapsed().as_millis() as u32
    }

    fn conn(&mut self) -> Result<&mut Connection, u32> {
        if self.conn.is_none() {
            let name = alloc::format!(
                "win32:{}",
                crate::kernel32::with_process(|p| p.exe_path.rsplit('/').next().unwrap_or("app").to_string())
            );
            match Connection::connect(&name, false) {
                Ok(c) => {
                    start_prism_waker(c.handle());
                    self.conn = Some(c);
                }
                Err(e) => {
                    os_std::eprintln!("winrun: cannot reach PRISM (no desktop session?): {e}");
                    return Err(ERROR_NOT_SUPPORTED);
                }
            }
        }
        Ok(self.conn.as_mut().expect("connected"))
    }

    /// The thread that owns `hwnd`'s messages (0: the calling thread).
    fn owner(&self, hwnd: u64) -> u64 {
        self.windows.get(&hwnd).map_or_else(os_sys::gettid, |w| w.thread)
    }

    fn post(&mut self, hwnd: u64, msg: u32, wparam: u64, lparam: i64) {
        let time = self.now_ms();
        // MSG.pt is in screen coordinates, like GetMessagePos.
        let pt = self.screen_pointer;
        let thread = self.owner(hwnd);
        self.queue.push_back(Msg { hwnd, msg, wparam, lparam, time, pt, thread });
        *self.fresh.entry(thread).or_insert(0) |= qs_kind(msg);
        // Wake MsgWaitForMultipleObjects and GetMessage. Threads that are
        // not sleeping see the queue on their next look, so a post storm from
        // worker threads costs no futex wake when nobody waits. The posting
        // thread itself cannot be asleep in a wait, so it is not woken.
        if thread != teb::current_tid() && IDLE_WAITERS.load(core::sync::atomic::Ordering::Relaxed) != 0 {
            crate::objects::signal_all();
        }
    }

    /// QS_* kinds of what get/peek would return now on the calling thread.
    fn status(&self) -> u32 {
        let me = teb::current_tid();
        let mut s = self.queue.iter().filter(|m| m.thread == me).fold(0, |s, m| s | qs_kind(m.msg));
        if self.quit.contains_key(&me) {
            s |= QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;
        }
        if self.pending_frames.keys().any(|h| self.owner(*h) == me) { s |= QS_SENDMESSAGE; }
        let now = Instant::now();
        if self.timers.iter().any(|t| t.thread == me && t.due <= now) {
            s |= QS_TIMER;
        }
        if self.windows.values().any(|w| w.thread == me && w.visible && w.invalid.is_some() && w.win.is_configured()) {
            s |= QS_PAINT;
        }
        s
    }

    /// The calling thread's QS_* kinds queued since it last looked.
    fn fresh_bits(&self) -> u32 {
        self.fresh.get(&teb::current_tid()).copied().unwrap_or(0)
    }

    fn set_fresh(&mut self, bits: u32) {
        self.fresh.insert(teb::current_tid(), bits);
    }

    fn invalidate(&mut self, hwnd: u64, r: Option<Rect>, erase: bool) {
        if let Some(w) = self.windows.get_mut(&hwnd) {
            let full = Rect::new(0, 0, w.size.0, w.size.1);
            let r = r.unwrap_or(full).intersect(&full);
            if r.w == 0 || r.h == 0 { return; }
            if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
                os_std::eprintln!("winrun: invalidate hwnd={hwnd:#x} {}x{} at ({},{})", r.w, r.h, r.x, r.y);
            }
            w.invalid = Some(match w.invalid {
                Some(o) => o.union(&r),
                None => r,
            });
            w.erase |= erase;
        }
    }

    /// Applies one PRISM event: window bookkeeping and queued messages.
    fn on_event(&mut self, ev: Event) {
        if let Event::SyncDone { cookie } = ev { self.sync_done = cookie; return; }
        if let Event::ClipboardChanged { seq, entries } = ev {
            self.set_clipboard(seq, entries);
            return;
        }
        let target = match &ev {
            Event::Configure { window, .. }
            | Event::FocusChanged { window, .. }
            | Event::Key { window, .. }
            | Event::Pointer { window, .. }
            | Event::FileDrop { window, .. }
            | Event::CloseRequest { window } => self.by_prism.get(window).copied(),
            Event::BufferRelease { surface } | Event::FrameDone { surface, .. } => self.by_prism.get(surface).copied(),
            _ => None,
        };
        let Some(hwnd) = target else { return };
        if let Event::Configure { states, .. } = &ev {
            let state = if states & proto::state::MINIMIZED != 0 { WS_MINIMIZE }
                else if states & proto::state::MAXIMIZED != 0 { WS_MAXIMIZE } else { 0 };
            if self.windows.get(&hwnd).is_some_and(|w| w.pending_state.is_some_and(|expected| expected != state)) { return; }
        }
        if matches!(ev, Event::Key { .. } | Event::Pointer { .. } | Event::CloseRequest { .. }) && self.windows.get(&hwnd).is_some_and(|w| w.style & 0x08000000 != 0) { return; }
        if let Some(w) = self.windows.get_mut(&hwnd) {
            w.win.on_event(&ev);
        }
        match ev {
            Event::Configure { width, height, states, .. } => {
                let Some(w) = self.windows.get_mut(&hwnd) else { return };
                let next_state = if states & proto::state::MINIMIZED != 0 { WS_MINIMIZE }
                    else if states & proto::state::MAXIMIZED != 0 { WS_MAXIMIZE } else { 0 };
                w.pending_state = None;
                let previous_state = w.style & (WS_MINIMIZE | WS_MAXIMIZE);
                w.style = (w.style & !(WS_MINIMIZE | WS_MAXIMIZE)) | next_state;
                let changed = previous_state != w.style & (WS_MINIMIZE | WS_MAXIMIZE);
                w.size = (width, height);
                if next_state == 0 { w.normal = Rect::new(w.pos.0, w.pos.1, width, height); }
                if changed || w.reported != Some((width, height)) {
                    w.reported = Some((width, height));
                    self.queue.retain(|m| m.hwnd != hwnd || m.msg != WM_SIZE);
                    self.pending_frames.insert(hwnd, 0x2); // SWP_NOMOVE
                    *self.fresh.entry(self.owner(hwnd)).or_insert(0) |= QS_SENDMESSAGE;
                    crate::objects::signal_all();
                    self.invalidate(hwnd, None, true);
                }
            }
            Event::FocusChanged { focused, .. } => {
                if focused {
                    self.focus = hwnd;
                    self.post(hwnd, WM_SETFOCUS, 0, 0);
                    self.post(hwnd, WM_ACTIVATE, 1, 0);
                } else {
                    self.post(hwnd, WM_KILLFOCUS, 0, 0);
                    self.post(hwnd, WM_ACTIVATE, 0, 0);
                }
            }
            Event::FileDrop { path, x, y, .. } => {
                if let Some(w) = self.windows.get(&hwnd) {
                    let token = crate::ole32::queue_file_drop(hwnd, path, w.pos.0 + x, w.pos.1 + y);
                    if token != 0 { self.post(hwnd, WM_OSYX_FILE_DROP, token, 0); }
                }
            }
            Event::CloseRequest { .. } => self.post(hwnd, WM_CLOSE, 0, 0),
            Event::Key { usage, state, modifiers, text, .. } => {
                self.last_input = crate::kernel32::tick_ms();
                let vk = vk_of(usage);
                if vk == 0 {
                    return;
                }
                {
                    let us = Instant::now().as_nanos_since_boot() / 1000;
                    os_std::eprintln!("winrun: t keyrecv {us} hwnd={hwnd:#x} vk={vk:#x} state={state}");
                }
                let down = state != proto::key_state::UP;
                let repeat = state == proto::key_state::REPEAT;
                if down && !repeat && !self.keys[vk as usize] {
                    self.toggles[vk as usize] ^= true;
                }
                self.keys[vk as usize] = down;
                let alt = modifiers & osyx_input::modifier::ALT != 0;
                let scan = scan_of(vk);
                let lparam = 1
                    | ((scan as i64 & 0xFF) << 16)
                    | if scan & 0xE000 == 0xE000 || matches!(vk, 0x21..=0x28 | 0x2D | 0x2E) { 1 << 24 } else { 0 }
                    | if repeat { 1 << 30 } else { 0 }
                    | if down { 0 } else { (1 << 30) | (1 << 31) };
                let msg = match (down, alt) {
                    (true, false) => WM_KEYDOWN,
                    (false, false) => WM_KEYUP,
                    (true, true) => WM_SYSKEYDOWN,
                    (false, true) => WM_SYSKEYUP,
                };
                self.post(hwnd, msg, vk as u64, lparam);
                if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
                    os_std::eprintln!("winrun: key hwnd={hwnd:#x} vk={vk:#x} down={down} repeat={repeat} text={text:?}");
                }
                if down {
                    let ch = match vk {
                        0x08 => Some('\u{8}'),
                        0x09 => Some('\t'),
                        0x0D => Some('\r'),
                        0x1B => Some('\u{1b}'),
                        _ => text.filter(|_| modifiers & osyx_input::modifier::CTRL == 0),
                    };
                    if let Some(c) = ch {
                        self.chars.push_back((vk, c));
                    }
                }
            }
            Event::Pointer { kind, x, y, screen_x, screen_y, button, pressed, wheel_v, .. } => {
                self.last_input = crate::kernel32::tick_ms();
                // A tracked window the pointer moves out of gets WM_MOUSELEAVE.
                let leave: Vec<u64> = self.track_leave.iter().copied().filter(|&w| w != hwnd).collect();
                for w in leave {
                    self.track_leave.retain(|&t| t != w);
                    self.post(w, WM_MOUSELEAVE, 0, 0);
                }
                self.pointer = (x, y);
                self.screen_pointer = (screen_x, screen_y);
                let lp = (x as i64 & 0xFFFF) | ((y as i64 & 0xFFFF) << 16);
                let screen_lp = (screen_x as i64 & 0xFFFF) | ((screen_y as i64 & 0xFFFF) << 16);
                let mk = self.mouse_keys();
                match kind {
                    proto::pointer::MOTION => self.post(hwnd, WM_MOUSEMOVE, mk, lp),
                    proto::pointer::BUTTON => {
                        let (vk, down_msg, up_msg) = match button {
                            osyx_input::button::LEFT => (0x01, WM_LBUTTONDOWN, WM_LBUTTONUP),
                            osyx_input::button::RIGHT => (0x02, WM_RBUTTONDOWN, WM_RBUTTONUP),
                            osyx_input::button::MIDDLE => (0x04, WM_MBUTTONDOWN, WM_MBUTTONUP),
                            _ => return,
                        };
                        self.keys[vk] = pressed;
                        let mk = self.mouse_keys();
                        if pressed {
                            let dbl = down_msg == WM_LBUTTONDOWN
                                && self.last_click.0 == hwnd
                                && self.last_click.2.elapsed() < Duration::from_millis(500);
                            self.last_click = (hwnd, down_msg, Instant::now());
                            let class_dbl = self
                                .windows
                                .get(&hwnd)
                                .and_then(|w| self.classes.get(w.class))
                                .is_some_and(|c| c.style & 0x8 != 0); // CS_DBLCLKS
                            self.post(hwnd, if dbl && class_dbl { WM_LBUTTONDBLCLK } else { down_msg }, mk, lp);
                        } else {
                            self.post(hwnd, up_msg, mk, lp);
                        }
                    }
                    proto::pointer::WHEEL if wheel_v != 0 => {
                        // Windows reports 120 per detent, positive away from
                        // the user, and the wheel's lParam is screen coordinates
                        // (WM_MOUSEMOVE and the button messages use client ones).
                        let delta = (wheel_v * 120) as i16 as u16 as u64;
                        self.post(hwnd, WM_MOUSEWHEEL, mk | delta << 16, screen_lp);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Adopts clipboard contents reported by the compositor, resolving
    /// registered format names to this process's format ids.
    fn set_clipboard(&mut self, seq: u32, entries: Vec<proto::ClipEntry>) {
        self.clipboard_seq = seq;
        self.clipboard = entries
            .into_iter()
            .map(|mut e| {
                if let Some(name) = &e.name {
                    e.format = registered_id(name);
                }
                e
            })
            .collect();
        self.drop_clipboard_handles();
    }

    /// Replaces the system clipboard (local format ids; registered formats
    /// carry their names so other processes map them to their own ids).
    fn publish_clipboard(&mut self, entries: Vec<proto::ClipEntry>) {
        self.clipboard = entries.clone();
        self.drop_clipboard_handles();
        let Some(c) = self.conn.as_mut() else { return };
        let wire: Vec<proto::ClipEntry> = entries
            .into_iter()
            .map(|mut e| {
                if e.format >= 0xC000 {
                    e.name = registered_name(e.format);
                }
                e
            })
            .collect();
        let _ = c.send(&proto::Request::ClipboardSet { entries: wire }, &[]);
    }

    fn drop_clipboard_handles(&mut self) {
        for (_, h) in core::mem::take(&mut self.clipboard_handles) {
            crate::kernel32::global_free(h);
        }
    }

    fn mouse_keys(&self) -> u64 {
        let mut m = 0;
        if self.keys[0x01] {
            m |= 0x1;
        }
        if self.keys[0x02] {
            m |= 0x2;
        }
        if self.keys[0x10] {
            m |= 0x4;
        }
        if self.keys[0x11] {
            m |= 0x8;
        }
        if self.keys[0x04] {
            m |= 0x10;
        }
        m
    }

    /// Reads every pending PRISM event.
    fn pump(&mut self) {
        static PUMPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        static KINDS: [core::sync::atomic::AtomicU64; 13] = [const { core::sync::atomic::AtomicU64::new(0) }; 13];
        let n = PUMPS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
        diag(|d| d.pump += 1);
        let mut evs = Vec::new();
        if let Some(c) = self.conn.as_mut() {
            while let Ok(Some(ev)) = c.poll() {
                evs.push(ev);
            }
        }
        for ev in evs {
            let k = match &ev {
                Event::SyncDone { .. } => 0,
                Event::Hello { .. } => 1,
                Event::Configure { .. } => 2,
                Event::FocusChanged { .. } => 3,
                Event::Key { .. } => 4,
                Event::Pointer { .. } => 5,
                Event::CloseRequest { .. } => 6,
                Event::BufferRelease { .. } => 7,
                Event::FrameDone { .. } => 8,
                Event::WindowList { .. } => 9,
                Event::Notification { .. } => 10,
                Event::Error { .. } => 11,
                Event::ClipboardChanged { .. } => 12,
                Event::FileDrop { .. } => 5,
            };
            KINDS[k].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            diag(|d| {
                d.pump_events += 1;
                d.pump_kinds.add(k as u64 + 1);
            });
            self.on_event(ev);
        }
        if n.is_multiple_of(20_000) && crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
            let k: Vec<u64> = KINDS.iter().map(|c| c.load(core::sync::atomic::Ordering::Relaxed)).collect();
            os_std::eprintln!("winrun: pump n={n} tid={} kinds={k:?}", os_sys::gettid());
        }
    }

    /// Waits up to `timeout` for PRISM events, then reads them.
    fn wait(&mut self, timeout: Duration) {
        if let Some(c) = self.conn.as_mut() {
            let _ = c.wait(&mut [], Some(timeout));
        } else {
            os_std::thread::sleep(timeout);
        }
        self.pump();
    }

    /// Complete earlier geometry requests before synchronous Win32 callbacks.
    /// No window procedure is called while this GUI mutex is held.
    fn synchronize(&mut self) {
        self.sync_cookie = self.sync_cookie.wrapping_add(1);
        let cookie = self.sync_cookie;
        let Some(c) = self.conn.as_mut() else { return };
        if c.send(&proto::Request::Sync { cookie }, &[]).is_err() { return; }
        let deadline = Instant::now() + Duration::from_secs(1);
        while self.sync_done != cookie && Instant::now() < deadline {
            self.wait(Duration::from_millis(1));
        }
    }

    /// Next matching message on this thread. A filtered peek must leave
    /// unrelated work alone: Gecko uses paint-only nested message pumps.
    fn next_message(&mut self, filter: u64, min: u32, max: u32, kinds: u32, remove: bool) -> Option<Msg> {
        let me = teb::current_tid();
        let window_matches = |hwnd: u64| filter == 0 || if filter == u64::MAX { hwnd == 0 } else { hwnd == filter };
        let min = min & 0xffff;
        let max = max & 0xffff;
        let message_matches = |msg: u32| {
            ((min == 0 && max == 0) || (min..=max).contains(&msg)) && (kinds == 0 || qs_kind(msg) & kinds != 0)
        };
        let matches = |m: &Msg| m.thread == me && window_matches(m.hwnd) && message_matches(m.msg);
        if let Some(i) = self.queue.iter().position(matches) {
            return if remove { self.queue.remove(i) } else { self.queue.get(i).copied() };
        }
        // WM_QUIT ignores the range and window filter and survives a peek.
        if let Some(&code) = self.quit.get(&me) {
            if remove { self.quit.remove(&me); }
            return Some(Msg {
                hwnd: 0,
                msg: WM_QUIT,
                wparam: code as u64,
                lparam: 0,
                time: self.now_ms(),
                pt: self.screen_pointer,
                thread: me,
            });
        }
        let paint = self
            .windows
            .iter()
            .find(|(h, w)| w.thread == me && window_matches(**h) && message_matches(WM_PAINT) && w.visible && w.invalid.is_some() && w.win.is_configured())
            .map(|(h, _)| *h);
        if let Some(hwnd) = paint {
            if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
                let inv = self.windows.get(&hwnd).and_then(|w| w.invalid);
                os_std::eprintln!("winrun: paint synth hwnd={hwnd:#x} invalid={inv:?}");
            }
            return Some(Msg { hwnd, msg: WM_PAINT, wparam: 0, lparam: 0, time: self.now_ms(), pt: self.screen_pointer, thread: me });
        }
        let now = Instant::now();
        let t = self.timers.iter_mut().find(|t| t.thread == me && window_matches(t.hwnd) && message_matches(WM_TIMER) && t.due <= now)?;
        t.due = now + Duration::from_millis(t.interval);
        let m = Msg { hwnd: t.hwnd, msg: WM_TIMER, wparam: t.id, lparam: t.proc_ as i64, time: 0, pt: (0, 0), thread: me };
        let interval = t.interval;
        let m = Msg { time: self.now_ms(), pt: self.screen_pointer, ..m };
        if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
            static FIRED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
            let n = FIRED.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
            if n.is_multiple_of(500) {
                os_std::eprintln!("winrun: timer fire n={n} hwnd={:#x} id={} interval={interval}", m.hwnd, m.wparam);
            }
        }
        // Once generated, a timer is a queued message. PM_NOREMOVE and
        // KillTimer must not silently consume it.
        if !remove { self.queue.push_back(m); }
        Some(m)
    }

    /// How long until the next timer that this peek could return fires.
    /// Timers outside the caller's window/message filter must not shorten
    /// the wait: a due but unreachable timer would otherwise busy-spin the
    /// caller through zero timeouts.
    fn next_timer_in(&self, filter: u64, lo: u32, hi: u32, kinds: u32) -> Duration {
        let now = Instant::now();
        let me = teb::current_tid();
        let window_matches = |hwnd: u64| filter == 0 || if filter == u64::MAX { hwnd == 0 } else { hwnd == filter };
        let lo = lo & 0xffff;
        let hi = hi & 0xffff;
        let message_matches = |msg: u32| {
            ((lo == 0 && hi == 0) || (lo..=hi).contains(&msg)) && (kinds == 0 || qs_kind(msg) & kinds != 0)
        };
        self.timers
            .iter()
            .filter(|t| t.thread == me && window_matches(t.hwnd) && message_matches(WM_TIMER))
            .map(|t| if t.due > now { t.due - now } else { Duration::ZERO })
            .min()
            .unwrap_or(Duration::from_millis(500))
            .min(Duration::from_millis(500))
    }
}

/// USB HID usage → Windows virtual-key code (0: none).
fn vk_of(u: u16) -> u32 {
    match u {
        0x04..=0x1D => (b'A' as u32) + (u as u32 - 0x04),
        0x1E..=0x26 => (b'1' as u32) + (u as u32 - 0x1E),
        0x27 => b'0' as u32,
        0x28 | 0x58 => 0x0D,
        0x29 => 0x1B,
        0x2A => 0x08,
        0x2B => 0x09,
        0x2C => 0x20,
        0x2D => 0xBD,
        0x2E => 0xBB,
        0x2F => 0xDB,
        0x30 => 0xDD,
        0x31 => 0xDC,
        0x33 => 0xBA,
        0x34 => 0xDE,
        0x35 => 0xC0,
        0x36 => 0xBC,
        0x37 => 0xBE,
        0x38 => 0xBF,
        0x39 => 0x14,
        0x3A..=0x45 => 0x70 + (u as u32 - 0x3A),
        0x49 => 0x2D,
        0x4A => 0x24,
        0x4B => 0x21,
        0x4C => 0x2E,
        0x4D => 0x23,
        0x4E => 0x22,
        0x4F => 0x27,
        0x50 => 0x25,
        0x51 => 0x28,
        0x52 => 0x26,
        0xE0 | 0xE4 => 0x11,
        0xE1 | 0xE5 => 0x10,
        0xE2 | 0xE6 => 0x12,
        0xE3 | 0xE7 => 0x5B,
        _ => 0,
    }
}

fn call(proc_: u64, hwnd: u64, msg: u32, w: u64, l: i64) -> i64 {
    let wake = wake_msg();
    let is_wake = wake != 0 && msg == wake;
    if matches!(msg, WM_CHAR | WM_KEYDOWN | WM_KEYUP) {
        let us = Instant::now().as_nanos_since_boot() / 1000;
        os_std::eprintln!("winrun: t dispatch {us} msg={msg:#x} hwnd={hwnd:#x} w={w:#x}");
    }
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && matches!(msg, WM_CHAR | WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP | WM_LBUTTONDOWN | WM_LBUTTONUP | WM_SETFOCUS | WM_KILLFOCUS | WM_ACTIVATE) {
        os_std::eprintln!("winrun: call msg={msg:#x} hwnd={hwnd:#x} w={w:#x}");
    }
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && msg == WM_CHAR {
        os_std::eprintln!("winrun: wndproc char hwnd={hwnd:#x} c={:#x}", w);
    }
    if proc_ == 0 {
        return DefWindowProcA(hwnd, msg, w, l);
    }
    // SAFETY: a window procedure registered by the program (or ours).
    let f: WndProc = unsafe { core::mem::transmute(proc_ as usize) };
    let t0 = Instant::now();
    let r = f(hwnd, msg, w, l);
    if is_wake {
        let dur = Instant::now().duration_since(t0).as_micros() as u64;
        diag(|d| {
            d.wake_calls += 1;
            d.wake_us += dur;
            d.wake_dur.add(dur.min(50_000));
        });
        let events = crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed);
        let slow_us = if events { 20_000 } else { 5_000 };
        if dur >= slow_us && (events || crate::COUNT.load(core::sync::atomic::Ordering::Relaxed)) {
            let us = Instant::now().as_nanos_since_boot() / 1000;
            os_std::eprintln!("winrun: wake slow us={us} hwnd={hwnd:#x} dur_us={dur} tid={}", teb::current_tid());
        }
    }
    if matches!(msg, WM_CHAR | WM_KEYDOWN | WM_KEYUP) {
        let us = Instant::now().as_nanos_since_boot() / 1000;
        let dur = Instant::now().duration_since(t0).as_micros();
        os_std::eprintln!("winrun: t done {us} msg={msg:#x} hwnd={hwnd:#x} w={w:#x} dur_us={dur}");
    }
    r
}

fn wndproc_of(hwnd: u64) -> Option<u64> {
    with(|g| g.windows.get(&hwnd).map(|w| w.wndproc))
}

fn current_window_pos(hwnd: u64, flags: u32) -> Option<WindowPos> {
    with(|g| g.windows.get(&hwnd).map(|w| WindowPos {
        hwnd, after: 0, x: w.pos.0, y: w.pos.1, cx: w.size.0 as i32, cy: w.size.1 as i32, flags, padding: 0,
    }))
}

fn notify_window_pos(hwnd: u64, flags: u32, changing: bool) {
    let Some(mut position) = current_window_pos(hwnd, flags) else { return };
    let Some(proc) = wndproc_of(hwnd) else { return };
    let pointer = (&mut position as *mut WindowPos) as i64;
    if changing { call(proc, hwnd, WM_WINDOWPOSCHANGING, 0, pointer); }
    if is_window(hwnd) { call(proc, hwnd, WM_WINDOWPOSCHANGED, 0, pointer); }
}

/// PRISM events can arrive on the rendering thread. Deliver their frame
/// callbacks only when the owner pumps messages, outside the GUI mutex.
fn dispatch_pending_frames() {
    let (frames, dirty) = with(|g| {
        g.pump();
        let me = teb::current_tid();
        let frames: Vec<_> = g.pending_frames.iter().filter(|(h, _)| g.owner(**h) == me).map(|(&h, &flags)| (h, flags)).collect();
        for (h, _) in &frames { g.pending_frames.remove(h); }
        // Win32 blits land in the window surface without a paint cycle;
        // winrun must commit them or PRISM keeps showing the previous frame.
        let dirty: Vec<u64> = g
            .windows
            .iter()
            .filter(|(_, w)| w.drawn.is_some() && w.visible && w.win.is_configured())
            .map(|(&h, _)| h)
            .collect();
        (frames, dirty)
    });
    for (hwnd, flags) in frames { notify_window_pos(hwnd, flags, true); }
    for hwnd in dirty { present(hwnd, None); }
}

// ---- classes and windows ------------------------------------------------------------

/// WNDCLASSA/W (72 bytes): style, lpfnWndProc @8, cbClsExtra, cbWndExtra,
/// hInstance @24, hIcon, hCursor, hbrBackground @48, lpszMenuName,
/// lpszClassName @64.
fn register_class(wc: *const u8, wide: bool) -> u16 {
    if wc.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's WNDCLASS.
    let (style, proc_, bg, name_p): (u32, u64, u64, u64) =
        unsafe { (teb::get(wc as u64, 0), teb::get(wc as u64, 8), teb::get(wc as u64, 48), teb::get(wc as u64, 64)) };
    // SAFETY: a NUL-terminated class name.
    let name = unsafe {
        if wide {
            path::wide_to_string(name_p as *const u16)
        } else {
            path::ansi_to_string(name_p as *const u8)
        }
    };
    let Some(name) = name else { return fail(ERROR_INVALID_PARAMETER, 0) };
    with(|g| {
        if g.classes.iter().any(|c| c.name.eq_ignore_ascii_case(&name)) {
            return fail(ERROR_CLASS_ALREADY_EXISTS, 0);
        }
        g.classes.push(Class { name, wndproc: proc_, background: bg, style });
        0xC000 + g.classes.len() as u16
    })
}

extern "win64" fn RegisterClassA(wc: *const u8) -> u16 {
    register_class(wc, false)
}

extern "win64" fn RegisterClassW(wc: *const u8) -> u16 {
    register_class(wc, true)
}

/// WNDCLASSEX: cbSize, then the WNDCLASS fields shifted by 4 (style at 4,
/// lpfnWndProc at 8 ...): the same offsets for what is read here except
/// style and the extra hIconSm at the end.
extern "win64" fn RegisterClassExA(wc: *const u8) -> u16 {
    register_class_ex(wc, false)
}

extern "win64" fn RegisterClassExW(wc: *const u8) -> u16 {
    register_class_ex(wc, true)
}

fn register_class_ex(wc: *const u8, wide: bool) -> u16 {
    if wc.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // WNDCLASSEX: cbSize@0 style@4 proc@8 cls@16 wnd@20 inst@24 icon@32
    // cursor@40 bg@48 menu@56 name@64 iconsm@72.
    let mut tmp = [0u8; 72];
    // SAFETY: the caller's WNDCLASSEX (80 bytes).
    unsafe { core::ptr::copy_nonoverlapping(wc, tmp.as_mut_ptr(), 72) };
    let style = u32::from_le_bytes([tmp[4], tmp[5], tmp[6], tmp[7]]);
    tmp[0..4].copy_from_slice(&style.to_le_bytes());
    register_class(tmp.as_ptr(), wide)
}

extern "win64" fn UnregisterClassA(_name: *const u8, _inst: u64) -> Bool {
    TRUE
}

fn class_name(p: u64, wide: bool) -> Option<String> {
    if p < 0x10000 {
        // An atom from RegisterClass.
        return with(|g| g.classes.get((p as usize).checked_sub(0xC001)?).map(|c| c.name.clone()));
    }
    // SAFETY: a NUL-terminated class name.
    unsafe {
        if wide {
            path::wide_to_string(p as *const u16)
        } else {
            path::ansi_to_string(p as *const u8)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn create_window(
    ex_style: u32,
    class: Option<String>,
    title: Option<String>,
    style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    parent: u64,
    param: u64,
    class_p: u64,
    title_p: u64,
) -> u64 {
    let Some(class) = class else { return fail(ERROR_CANNOT_FIND_WND_CLASS, 0) };
    if style & WS_CHILD != 0 || parent != 0 && style & WS_CHILD != 0 {
        return fail(ERROR_NOT_SUPPORTED, 0); // controls / child windows
    }
    let title = title.unwrap_or_default();
    let created = with(|g| -> Result<u64, u32> {
        let ci =
            g.classes.iter().position(|c| c.name.eq_ignore_ascii_case(&class)).ok_or(ERROR_CANNOT_FIND_WND_CLASS)?;
        let (cw, ch) = g.conn().map(|c| (c.screen_width, c.screen_height))?;
        let width = if w == CW_USEDEFAULT || w <= 0 { (cw * 2 / 3).max(320) } else { w as u32 };
        let height = if h == CW_USEDEFAULT || h <= 0 { (ch * 2 / 3).max(200) } else { h as u32 };
        if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
            os_std::eprintln!(
                "winrun: create {class:?} style={style:#x} at ({x},{y}) req={w}x{h} -> {width}x{height} screen={cw}x{ch}"
            );
        }
        let mut spec = WindowSpec::normal(&title, width, height);
        spec.flags |= proto::window_flags::HIDDEN;
        // Win32 message-only, tool, nonactivating and owned windows are
        // implementation details of their application, not separate tasks.
        const WS_EX_TOOLWINDOW: u32 = 0x80;
        const WS_EX_APPWINDOW: u32 = 0x40000;
        const WS_EX_NOACTIVATE: u32 = 0x08000000;
        if parent == (-3i64) as u64 || ex_style & (WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE) != 0
            || (parent != 0 && ex_style & WS_EX_APPWINDOW == 0) {
            spec.flags |= proto::window_flags::SKIP_TASKBAR;
        }
        spec.parent = g.windows.get(&parent).map_or(0, |w| w.win.id);
        spec.min_width = 120;
        spec.min_height = 80;
        if x != CW_USEDEFAULT {
            spec.x = x;
            spec.y = y;
        }
        let win = g.conn()?.create_window(spec).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
        let hwnd = g.handle();
        g.by_prism.insert(win.id, hwnd);
        let wndproc = g.classes[ci].wndproc;
        g.windows.insert(
            hwnd,
            Win {
                class: ci,
                thread: teb::current_tid(),
                wndproc,
                title: title.clone(),
                style,
                ex_style,
                owner: parent,
                win,
                pos: (x.max(0), y.max(0)),
                size: (width, height),
                normal: Rect::new(x.max(0), y.max(0), width, height),
                pending_state: None,
                restore_maximized: false,
                reported: None,
                visible: false,
                invalid: None,
                erase: true,
                user_data: 0,
                drawn: None,
            },
        );
        Ok(hwnd)
    });
    let hwnd = match created {
        Ok(h) => h,
        Err(e) => return fail(e, 0),
    };
    crate::winsta::note_gui();
    let wndproc = wndproc_of(hwnd).unwrap_or(0);
    // CREATESTRUCT (80 bytes) for WM_NCCREATE / WM_CREATE.
    let mut cs = [0u8; 80];
    let put = |cs: &mut [u8; 80], off: usize, v: &[u8]| cs[off..off + v.len()].copy_from_slice(v);
    put(&mut cs, 0, &param.to_le_bytes());
    put(&mut cs, 24, &parent.to_le_bytes());
    put(&mut cs, 32, &h.to_le_bytes());
    put(&mut cs, 36, &w.to_le_bytes());
    put(&mut cs, 40, &y.to_le_bytes());
    put(&mut cs, 44, &x.to_le_bytes());
    put(&mut cs, 48, &style.to_le_bytes());
    put(&mut cs, 56, &title_p.to_le_bytes());
    put(&mut cs, 64, &class_p.to_le_bytes());
    put(&mut cs, 72, &ex_style.to_le_bytes());
    let csp = cs.as_ptr() as i64;
    if call(wndproc, hwnd, WM_NCCREATE, 0, csp) == 0 || call(wndproc, hwnd, WM_CREATE, 0, csp) == -1 {
        destroy(hwnd, false);
        return fail(ERROR_GEN_FAILURE, 0);
    }
    if style & WS_VISIBLE != 0 {
        ShowWindow(hwnd, 1);
    }
    hwnd
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn CreateWindowExA(
    ex: u32,
    class: *const u8,
    title: *const u8,
    style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    parent: u64,
    _menu: u64,
    _inst: u64,
    param: u64,
) -> u64 {
    // SAFETY: NUL-terminated title (or NULL).
    let t = unsafe { path::ansi_to_string(title) };
    create_window(ex, class_name(class as u64, false), t, style, x, y, w, h, parent, param, class as u64, title as u64)
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn CreateWindowExW(
    ex: u32,
    class: *const u16,
    title: *const u16,
    style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    parent: u64,
    _menu: u64,
    _inst: u64,
    param: u64,
) -> u64 {
    // SAFETY: NUL-terminated title (or NULL).
    let t = unsafe { path::wide_to_string(title) };
    create_window(ex, class_name(class as u64, true), t, style, x, y, w, h, parent, param, class as u64, title as u64)
}

fn destroy(hwnd: u64, notify: bool) -> bool {
    let Some(proc_) = wndproc_of(hwnd) else { return false };
    let owned: Vec<u64> = with(|g| g.windows.iter().filter_map(|(&id, w)| (id != hwnd && w.owner == hwnd).then_some(id)).collect());
    for child in owned { destroy(child, notify); }
    if notify {
        call(proc_, hwnd, WM_DESTROY, 0, 0);
        call(proc_, hwnd, WM_NCDESTROY, 0, 0);
    }
    with(|g| {
        if let Some(w) = g.windows.remove(&hwnd) {
            g.by_prism.remove(&w.win.id);
            if let Some(c) = g.conn.as_mut() {
                let _ = w.win.destroy(c);
            }
        }
        g.timers.retain(|t| t.hwnd != hwnd);
        g.queue.retain(|m| m.hwnd != hwnd);
        g.pending_frames.remove(&hwnd);
        if g.focus == hwnd {
            g.focus = 0;
        }
    });
    true
}

extern "win64" fn DestroyWindow(hwnd: u64) -> Bool {
    if destroy(hwnd, true) {
        TRUE
    } else {
        fail(ERROR_INVALID_WINDOW_HANDLE, FALSE)
    }
}

pub(crate) fn is_window(hwnd: u64) -> bool {
    with(|g| g.windows.contains_key(&hwnd))
}

extern "win64" fn IsWindow(hwnd: u64) -> Bool {
    is_window(hwnd) as Bool
}

extern "win64" fn IsWindowVisible(hwnd: u64) -> Bool {
    with(|g| g.windows.get(&hwnd).is_some_and(|w| w.visible)) as Bool
}

/// No shaped-window API is exposed yet, so every valid window has the
/// default rectangle and no explicit region. Windows reports ERROR (0),
/// leaving the supplied region untouched in this case.
extern "win64" fn GetWindowRgn(hwnd: u64, region: u64) -> i32 {
    with(|g| {
        if !g.windows.contains_key(&hwnd) { return fail(ERROR_INVALID_WINDOW_HANDLE, 0); }
        if !g.regions.contains_key(&region) { return fail(ERROR_INVALID_HANDLE, 0); }
        0
    })
}

extern "win64" fn ShowWindow(hwnd: u64, cmd: i32) -> Bool {
    if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
        os_std::eprintln!("winrun: ShowWindow({hwnd:#x}, {cmd})");
        if cmd == 9 { crate::exceptions::trace_current(); }
    }
    let r = with(|g| {
        g.synchronize();
        let w = g.windows.get_mut(&hwnd)?;
        let was = w.visible;
        let previous_state = w.style & (WS_MINIMIZE | WS_MAXIMIZE);
        let action = match cmd {
            0 => None,                                       // SW_HIDE
            2 | 6 | 7 | 11 => Some(proto::Action::Minimize), // SW_SHOWMINIMIZED, SW_MINIMIZE, ...
            3 => Some(proto::Action::Maximize),              // SW_MAXIMIZE
            9 => Some(proto::Action::Restore),               // SW_RESTORE
            1 | 4 if previous_state != 0 => Some(proto::Action::Restore),
            _ => None,
        };
        w.visible = cmd != 0;
        if w.visible { w.style |= WS_VISIBLE; } else { w.style &= !WS_VISIBLE; }
        match cmd {
            2 | 6 | 7 | 11 => {
                if previous_state & WS_MINIMIZE == 0 { w.restore_maximized = previous_state & WS_MAXIMIZE != 0; }
                w.style = (w.style & !WS_MAXIMIZE) | WS_MINIMIZE;
            }
            3 => { w.style = (w.style & !WS_MINIMIZE) | WS_MAXIMIZE; }
            9 if previous_state & WS_MINIMIZE != 0 && w.restore_maximized => { w.style = (w.style & !WS_MINIMIZE) | WS_MAXIMIZE; }
            1 | 4 | 9 => { w.style &= !(WS_MINIMIZE | WS_MAXIMIZE); }
            _ => {}
        }
        let changed = previous_state != w.style & (WS_MINIMIZE | WS_MAXIMIZE);
        if action.is_some() && (changed || !was || w.pending_state.is_some()) { w.pending_state = Some(w.style & (WS_MINIMIZE | WS_MAXIMIZE)); }
        let size = w.size;
        if changed { g.queue.retain(|m| m.hwnd != hwnd || m.msg != WM_SIZE); }
        if let (Some(a), Some(c)) = (action, g.conn.as_mut()) {
            if matches!(cmd, 1 | 4) && previous_state & WS_MINIMIZE != 0 {
                let _ = g.windows.get_mut(&hwnd)?.win.action(c, proto::Action::Activate);
            }
            let _ = g.windows.get_mut(&hwnd)?.win.action(c, a);
        }
        if !was && cmd != 0 {
            g.invalidate(hwnd, None, true);
        }
        Some((was, changed, size))
    });
    match r {
        Some((was, changed, size)) => {
            sync_window_visibility(hwnd);
            // Windows completes the state/geometry transition before
            // calling WM_SIZE. Wait only for the compositor acknowledgement,
            // without holding the GUI mutex or invoking window procedures.
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                let pending = with(|g| {
                    g.pump();
                    g.windows.get(&hwnd).is_some_and(|w| w.pending_state.is_some())
                });
                if !pending || Instant::now() >= deadline { break; }
                os_std::thread::sleep(Duration::from_millis(1));
            }
            let current_size = with(|g| {
                let size = g.windows.get(&hwnd).map(|w| w.size);
                g.queue.retain(|m| m.hwnd != hwnd || m.msg != WM_SIZE);
                g.pending_frames.remove(&hwnd);
                size
            });
            if changed || current_size.is_some_and(|current| current != size) || was != (cmd != 0) {
                let flags = 0x6 | if cmd == 0 { 0x80 } else { 0x40 }
                    | if !changed && current_size == Some(size) { 0x1 } else { 0 };
                notify_window_pos(hwnd, flags, true);
            }
            if !was && cmd != 0 {
                if let Some(p) = wndproc_of(hwnd) {
                    call(p, hwnd, WM_SHOWWINDOW, 1, 0);
                }
            }
            was as Bool
        }
        None => fail(ERROR_INVALID_WINDOW_HANDLE, FALSE),
    }
}

fn sync_window_visibility(hwnd: u64) {
    with(|g| {
        let Some(w) = g.windows.get(&hwnd) else { return };
        let auxiliary = w.owner == (-3i64) as u64 || w.ex_style & (0x80 | 0x08000000) != 0
            || (w.owner != 0 && w.ex_style & 0x40000 == 0);
        let request = proto::Request::SetWindowVisibility {
            window: w.win.id, visible: w.visible && w.owner != (-3i64) as u64,
            taskbar: w.visible && !auxiliary,
        };
        if let Some(c) = g.conn.as_mut() { let _ = c.send(&request, &[]); }
    });
}

extern "win64" fn UpdateWindow(hwnd: u64) -> Bool {
    dispatch_pending_frames();
    // Wait (bounded) for PRISM to configure a new window, then paint now.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let ready = with(|g| {
            g.pump();
            g.windows.get(&hwnd).map(|w| (w.win.is_configured(), w.invalid.is_some() && w.visible))
        });
        match ready {
            None => return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE),
            Some((true, true)) => {
                if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
                    static N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
                    let n = N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    if n < 40 || n.is_multiple_of(600) {
                        let inv = with(|g| g.windows.get(&hwnd).and_then(|w| w.invalid));
                        os_std::eprintln!("winrun: updatewindow paint n={n} hwnd={hwnd:#x} invalid={inv:?}");
                    }
                }
                if let Some(p) = wndproc_of(hwnd) {
                    call(p, hwnd, WM_PAINT, 0, 0);
                }
                return TRUE;
            }
            Some((true, false)) => return TRUE,
            Some((false, _)) if Instant::now() < deadline => with(|g| g.wait(Duration::from_millis(20))),
            Some((false, _)) => return TRUE,
        }
    }
}

extern "win64" fn InvalidateRect(hwnd: u64, r: *const i32, erase: Bool) -> Bool {
    let rect = read_rect(r);
    with(|g| {
        if hwnd == 0 {
            let all: Vec<u64> = g.windows.keys().copied().collect();
            for h in all {
                g.invalidate(h, rect, erase != 0);
            }
        } else {
            g.invalidate(hwnd, rect, erase != 0);
        }
    });
    TRUE
}

extern "win64" fn ValidateRect(hwnd: u64, _r: *const i32) -> Bool {
    with(|g| {
        if let Some(w) = g.windows.get_mut(&hwnd) {
            w.invalid = None;
        }
    });
    TRUE
}

/// RECT {left, top, right, bottom} → Rect.
fn read_rect(r: *const i32) -> Option<Rect> {
    if r.is_null() {
        return None;
    }
    // SAFETY: the caller's RECT.
    let (l, t, rr, b) = unsafe { (*r, *r.add(1), *r.add(2), *r.add(3)) };
    Some(Rect::new(l, t, (rr - l).max(0) as u32, (b - t).max(0) as u32))
}

fn write_rect(r: *mut i32, x: Rect) {
    if !r.is_null() {
        // SAFETY: the caller's RECT.
        unsafe {
            *r = x.x;
            *r.add(1) = x.y;
            *r.add(2) = x.x + x.w as i32;
            *r.add(3) = x.y + x.h as i32;
        }
    }
}

extern "win64" fn GetClientRect(hwnd: u64, r: *mut i32) -> Bool {
    match with(|g| g.windows.get(&hwnd).map(|w| w.size)) {
        Some((w, h)) => {
            write_rect(r, Rect::new(0, 0, w, h));
            TRUE
        }
        None => fail(ERROR_INVALID_WINDOW_HANDLE, FALSE),
    }
}

/// The window's RECT (left, top, right, bottom) in screen coordinates.
pub(crate) fn window_rect(hwnd: u64) -> Option<[i32; 4]> {
    with(|g| g.windows.get(&hwnd).map(|w| [w.pos.0, w.pos.1, w.pos.0 + w.size.0 as i32, w.pos.1 + w.size.1 as i32]))
}

extern "win64" fn GetWindowRect(hwnd: u64, r: *mut i32) -> Bool {
    match with(|g| g.windows.get(&hwnd).map(|w| (w.pos, w.size))) {
        Some(((x, y), (w, h))) => {
            write_rect(r, Rect::new(x, y, w, h));
            TRUE
        }
        None => fail(ERROR_INVALID_WINDOW_HANDLE, FALSE),
    }
}

/// The client area is the whole PRISM surface: no frame to add.
extern "win64" fn AdjustWindowRect(r: *mut i32, _style: u32, _menu: Bool) -> Bool {
    (!r.is_null()) as Bool
}

extern "win64" fn AdjustWindowRectEx(r: *mut i32, _style: u32, _menu: Bool, _ex: u32) -> Bool {
    (!r.is_null()) as Bool
}

extern "win64" fn SetWindowPos(hwnd: u64, after: u64, x: i32, y: i32, cx: i32, cy: i32, flags: u32) -> Bool {
    if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed)
        || crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed)
    {
        os_std::eprintln!("winrun: SetWindowPos({hwnd:#x}, {x},{y}, {cx}x{cy}, flags {flags:#x})");
        static SMALL_RESIZES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
        if flags & 1 == 0 && cx <= 160 && cy <= 80 && SMALL_RESIZES.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 8 {
            crate::exceptions::trace_current();
        }
    }
    let Some(proc) = wndproc_of(hwnd) else { return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE) };
    let mut position = WindowPos { hwnd, after, x, y, cx, cy, flags, padding: 0 };
    if flags & 0x400 == 0 { call(proc, hwnd, WM_WINDOWPOSCHANGING, 0, (&mut position as *mut WindowPos) as i64); }
    let WindowPos { x, y, cx, cy, flags, .. } = position;
    let r = with(|g| {
        let w = g.windows.get_mut(&hwnd)?;
        let previous_pos = w.pos;
        if flags & 0x2 == 0 {
            w.pos = (x, y);
        }
        let (nw, nh) = if flags & 0x1 == 0 { (cx.max(1) as u32, cy.max(1) as u32) } else { w.size };
        let resized = w.size != (nw, nh);
        w.size = (nw, nh);
        if w.style & (WS_MINIMIZE | WS_MAXIMIZE) == 0 { w.normal = Rect::new(w.pos.0, w.pos.1, nw, nh); }
        if resized { w.reported = Some((nw, nh)); }
        let (px, py) = w.pos;
        if flags & 0x40 != 0 {
            w.visible = true;
            w.style |= WS_VISIBLE;
        }
        if flags & 0x80 != 0 {
            w.visible = false;
            w.style &= !WS_VISIBLE;
        }
        let c = g.conn.as_mut()?;
        let _ = g.windows.get_mut(&hwnd)?.win.set_geometry(
            c,
            if flags & 0x2 == 0 { px } else { -1 },
            if flags & 0x2 == 0 { py } else { -1 },
            nw,
            nh,
        );
        if resized { g.invalidate(hwnd, None, true); }
        if resized { g.queue.retain(|m| m.hwnd != hwnd || m.msg != WM_SIZE); }
        g.synchronize();
        g.queue.retain(|m| m.hwnd != hwnd || m.msg != WM_SIZE);
        g.pending_frames.remove(&hwnd);
        Some((resized, previous_pos != (px, py)))
    });
    match r {
        Some((resized, moved)) => {
            if flags & (0x40 | 0x80) != 0 { sync_window_visibility(hwnd); }
            notify_window_pos(hwnd, flags | if !resized { 0x800 } else { 0 } | if !moved { 0x1000 } else { 0 }, false);
            TRUE
        }
        None => fail(ERROR_INVALID_WINDOW_HANDLE, FALSE),
    }
}

extern "win64" fn MoveWindow(hwnd: u64, x: i32, y: i32, w: i32, h: i32, repaint: Bool) -> Bool {
    let r = SetWindowPos(hwnd, 0, x, y, w, h, 0x4);
    if repaint != 0 {
        InvalidateRect(hwnd, core::ptr::null(), TRUE);
    }
    r
}

fn set_title(hwnd: u64, t: String) -> Bool {
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
        os_std::eprintln!("winrun: title hwnd={hwnd:#x} text={t}");
    }
    let ok = with(|g| {
        let w = g.windows.get_mut(&hwnd)?;
        w.title = t.clone();
        let c = g.conn.as_mut()?;
        let _ = g.windows.get_mut(&hwnd)?.win.set_title(c, &t);
        Some(())
    });
    ok.map_or_else(|| fail(ERROR_INVALID_WINDOW_HANDLE, FALSE), |_| TRUE)
}

extern "win64" fn SetWindowTextA(hwnd: u64, t: *const u8) -> Bool {
    // SAFETY: a NUL-terminated string.
    set_title(hwnd, unsafe { path::ansi_to_string(t) }.unwrap_or_default())
}

extern "win64" fn SetWindowTextW(hwnd: u64, t: *const u16) -> Bool {
    // SAFETY: a NUL-terminated string.
    set_title(hwnd, unsafe { path::wide_to_string(t) }.unwrap_or_default())
}

/// Returns the length copied (truncating like Windows), 0 on error.
extern "win64" fn GetWindowTextA(hwnd: u64, buf: *mut u8, size: i32) -> i32 {
    let Some(t) = with(|g| g.windows.get(&hwnd).map(|w| w.title.clone())) else {
        return fail(ERROR_INVALID_WINDOW_HANDLE, 0);
    };
    if size <= 0 {
        return 0;
    }
    let mut s = t;
    while s.len() + 1 > size as usize {
        s.pop();
    }
    out_a(&s, buf, size as u32) as i32
}

extern "win64" fn GetWindowTextW(hwnd: u64, buf: *mut u16, size: i32) -> i32 {
    let Some(t) = with(|g| g.windows.get(&hwnd).map(|w| w.title.clone())) else {
        return fail(ERROR_INVALID_WINDOW_HANDLE, 0);
    };
    if size <= 0 {
        return 0;
    }
    let mut s = t;
    while s.encode_utf16().count() + 1 > size as usize {
        s.pop();
    }
    out_w(&s, buf, size as u32) as i32
}

extern "win64" fn GetWindowTextLengthA(hwnd: u64) -> i32 {
    with(|g| g.windows.get(&hwnd).map_or(0, |w| w.title.len() as i32))
}

extern "win64" fn wvsprintfW(out: *mut u16, fmt: *const u16, args: *const u64) -> i32 {
    if out.is_null() { return fail(ERROR_INVALID_PARAMETER, 0); }
    let Some(fmt) = wide(fmt) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let units: Vec<u16> = fmt.encode_utf16().collect();
    let Some(text) = crate::ucrt::printf::win32_wide(&units, args) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let n = text.len().min(1023);
    // SAFETY: wsprintf requires room for up to 1024 output units.
    unsafe { core::ptr::copy_nonoverlapping(text.as_ptr(), out, n); *out.add(n) = 0; }
    n as i32
}

extern "win64" fn wvsprintfA(out: *mut u8, fmt: *const u8, args: *const u64) -> i32 {
    if out.is_null() { return fail(ERROR_INVALID_PARAMETER, 0); }
    let Some(fmt) = (unsafe { path::ansi_to_string(fmt) }) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let Some(text) = crate::ucrt::printf::win32_narrow(fmt.as_bytes(), args) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let n = text.len().min(1023);
    // SAFETY: wsprintf requires room for up to 1024 output bytes.
    unsafe { core::ptr::copy_nonoverlapping(text.as_ptr(), out, n); *out.add(n) = 0; }
    n as i32
}

#[unsafe(naked)]
extern "win64" fn wsprintfW() {
    core::arch::naked_asm!("mov [rsp+24], r8", "mov [rsp+32], r9", "lea r8, [rsp+24]", "jmp {target}", target = sym wvsprintfW)
}

#[unsafe(naked)]
extern "win64" fn wsprintfA() {
    core::arch::naked_asm!("mov [rsp+24], r8", "mov [rsp+32], r9", "lea r8, [rsp+24]", "jmp {target}", target = sym wvsprintfA)
}

const GWLP_WNDPROC: i32 = -4;
const GWL_STYLE: i32 = -16;
const GWLP_USERDATA: i32 = -21;

extern "win64" fn GetWindowLongPtrA(hwnd: u64, idx: i32) -> i64 {
    with(|g| {
        let Some(w) = g.windows.get(&hwnd) else { return fail(ERROR_INVALID_WINDOW_HANDLE, 0) };
        match idx {
            GWLP_WNDPROC => w.wndproc as i64,
            GWL_STYLE => w.style as i64,
            -20 => w.ex_style as i64, // GWL_EXSTYLE
            -8 => w.owner as i64, // GWLP_HWNDPARENT
            GWLP_USERDATA => w.user_data,
            -12 => 0, // GWLP_ID: no child controls
            _ => {
                if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
                    os_std::eprintln!("winrun: GetWindowLongPtr({hwnd:#x}, {idx}) unsupported index");
                }
                fail(ERROR_INVALID_PARAMETER, 0)
            }
        }
    })
}

extern "win64" fn SetWindowLongPtrA(hwnd: u64, idx: i32, v: i64) -> i64 {
    let previous = with(|g| {
        let Some(w) = g.windows.get_mut(&hwnd) else { return fail(ERROR_INVALID_WINDOW_HANDLE, 0) };
        match idx {
            GWLP_WNDPROC => core::mem::replace(&mut w.wndproc, v as u64) as i64,
            GWL_STYLE => {
                w.visible = v as u32 & WS_VISIBLE != 0;
                core::mem::replace(&mut w.style, v as u32) as i64
            }
            -20 => core::mem::replace(&mut w.ex_style, v as u32) as i64,
            GWLP_USERDATA => core::mem::replace(&mut w.user_data, v),
            _ => fail(ERROR_INVALID_PARAMETER, 0),
        }
    });
    if idx == -20 || idx == GWL_STYLE { sync_window_visibility(hwnd); }
    previous
}

extern "win64" fn GetWindowLongA(hwnd: u64, idx: i32) -> i32 {
    GetWindowLongPtrA(hwnd, idx) as i32
}

extern "win64" fn SetWindowLongA(hwnd: u64, idx: i32, v: i32) -> i32 {
    SetWindowLongPtrA(hwnd, idx, v as i64) as i32
}

// ---- messages -------------------------------------------------------------------------

const QS_KEY: u32 = 0x1;
const QS_MOUSEMOVE: u32 = 0x2;
const QS_MOUSEBUTTON: u32 = 0x4;
const QS_POSTMESSAGE: u32 = 0x8;
const QS_TIMER: u32 = 0x10;
const QS_PAINT: u32 = 0x20;
const QS_SENDMESSAGE: u32 = 0x40;
const QS_ALLPOSTMESSAGE: u32 = 0x100;
const MWMO_WAITALL: u32 = 1;
const MWMO_INPUTAVAILABLE: u32 = 4;

/// Wakes object waiters when PRISM makes the connection readable. Without
/// it every message loop has to poll the channel (a 10 ms timeout per idle
/// wait, i.e. a permanent 100 Hz wake-up per waiting thread); with it an
/// idle wait sleeps until input or a frame callback actually arrives.
fn start_prism_waker(chan: u64) {
    use core::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::Relaxed) {
        return;
    }
    let _ = os_std::thread::Builder::new().stack_size(64 << 10).spawn(move || loop {
        let mut it = [os_std::ipc::item(chan, os_std::ipc::WAIT_READABLE)];
        if os_std::ipc::wait(&mut it, None).is_err() {
            return;
        }
        let read = it[0].revents & os_std::ipc::WAIT_READABLE != 0;
        if read {
            crate::objects::signal_all();
        }
        if !read || it[0].revents & os_std::ipc::WAIT_HANGUP != 0 {
            return;
        }
        // The message loop drains the channel under the GUI lock; sleeping
        // here keeps this thread from signalling in a tight loop while the
        // loop is busy elsewhere.
        os_std::thread::sleep(Duration::from_millis(1));
    });
}

/// The QS_* kind of a queued message.
fn qs_kind(msg: u32) -> u32 {
    match msg {
        WM_MOUSEMOVE => QS_MOUSEMOVE,
        0x0201..=0x020E => QS_MOUSEBUTTON,
        0x0100..=0x0109 => QS_KEY,
        _ => QS_POSTMESSAGE | QS_ALLPOSTMESSAGE,
    }
}

/// Threads about to sleep in `idle`; a post wakes them only when non-zero.
static IDLE_WAITERS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Decrements [`IDLE_WAITERS`] however the caller leaves the wait.
struct IdleGuard;
impl Drop for IdleGuard {
    fn drop(&mut self) {
        IDLE_WAITERS.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Sleeps without the GUI lock until another thread posts or signals an
/// object (after `seq`) or the timeout passes. The caller registered in
/// [`IDLE_WAITERS`] while the GUI lock was held; the PRISM waker signals
/// when input or a frame callback arrives.
/// The caller registered in [`IDLE_WAITERS`] while the GUI lock was held.
fn idle(seq: u32, timeout: Duration) {
    let woken = crate::objects::wait_for_change(seq, timeout);
    diag(|d| {
        d.idle += 1;
        if woken {
            d.idle_woken += 1;
        }
    });
}

// ---- counting (`OSYX_WINRUN_COUNT=1`) ---------------------------------------------

const HIST_SLOTS: usize = 12;

/// A small key/count table. The least frequent key gives way once every
/// slot is taken: only the hot keys matter for a diagnosis.
#[derive(Clone, Copy)]
struct Hist {
    slots: [(u64, u64); HIST_SLOTS],
}

impl Hist {
    const fn new() -> Hist {
        Hist { slots: [(0, 0); HIST_SLOTS] }
    }

    fn add(&mut self, key: u64) {
        if key == 0 {
            return;
        }
        let mut least = 0;
        for i in 0..HIST_SLOTS {
            let (k, c) = self.slots[i];
            if c == 0 {
                self.slots[i] = (key, 1);
                return;
            }
            if k == key {
                self.slots[i].1 += 1;
                return;
            }
            if c < self.slots[least].1 {
                least = i;
            }
        }
        self.slots[least] = (key, 1);
    }

    /// Entries that grew since `older`, hottest first.
    fn delta(&self, older: &Hist) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for (k, c) in self.slots {
            let before = older.slots.iter().find(|(ok, _)| *ok == k).map_or(0, |(_, oc)| *oc);
            if c > before {
                out.push((k, c - before));
            }
        }
        out.sort_by_key(|a| core::cmp::Reverse(a.1));
        out
    }
}

#[derive(Clone, Copy)]
struct Diag {
    peek: u64,
    peek_hit: u64,
    getmsg: u64,
    msgwait: u64,
    msgwait_input: u64,
    msgwait_timeout: u64,
    qstatus: u64,
    post: u64,
    dispatch: u64,
    idle: u64,
    idle_woken: u64,
    pump: u64,
    pump_events: u64,
    wake_calls: u64,
    wake_us: u64,
    wake_self: u64,
    wake_tids: Hist,
    wake_dur: Hist,
    peek_msgs: Hist,
    peek_flags: Hist,
    post_msgs: Hist,
    msgwait_masks: Hist,
    peek_sites: Hist,
    post_sites: Hist,
    pump_kinds: Hist,
}

impl Diag {
    const fn new() -> Diag {
        Diag {
            peek: 0,
            peek_hit: 0,
            getmsg: 0,
            msgwait: 0,
            msgwait_input: 0,
            msgwait_timeout: 0,
            qstatus: 0,
            post: 0,
            dispatch: 0,
            idle: 0,
            idle_woken: 0,
            pump: 0,
            pump_events: 0,
            wake_calls: 0,
            wake_us: 0,
            wake_self: 0,
            wake_tids: Hist::new(),
            wake_dur: Hist::new(),
            peek_msgs: Hist::new(),
            peek_flags: Hist::new(),
            post_msgs: Hist::new(),
            msgwait_masks: Hist::new(),
            peek_sites: Hist::new(),
            post_sites: Hist::new(),
            pump_kinds: Hist::new(),
        }
    }
}

static DIAG: Mutex<Diag> = Mutex::new(Diag::new());

fn diag(f: impl FnOnce(&mut Diag)) {
    if !crate::COUNT.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    if let Ok(mut d) = DIAG.lock() {
        f(&mut d);
    }
}

/// Every 64th call records its caller: `loader::where_is` is not free.
fn sample() -> bool {
    static N: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    N.fetch_add(1, core::sync::atomic::Ordering::Relaxed).is_multiple_of(64)
}

/// The first stack word that points into a loaded module is the return
/// address of the caller (the prologue may have moved `rsp`).
fn caller_site() -> u64 {
    let mut sp: u64;
    // SAFETY: reading this thread's own stack, which is mapped.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack)) };
    for i in 0..128u64 {
        // SAFETY: within the calling thread's stack, above `rsp`.
        let v = unsafe { core::ptr::read_volatile((sp + i * 8) as *const u64) };
        if crate::loader::where_is(v).is_some() {
            return v;
        }
    }
    0
}

fn site() -> u64 {
    if crate::COUNT.load(core::sync::atomic::Ordering::Relaxed) && sample() { caller_site() } else { 0 }
}

fn print_hist(name: &str, h: &[(u64, u64)], module: bool) {
    let mut s = String::new();
    for &(k, c) in h.iter().take(6) {
        if module {
            match crate::loader::where_is(k) {
                Some((m, o)) => s.push_str(&alloc::format!(" {m}+{o:#x}={c}")),
                None => s.push_str(&alloc::format!(" {k:#x}={c}")),
            }
        } else {
            s.push_str(&alloc::format!(" {k:#x}={c}"));
        }
    }
    os_std::eprintln!("winrun: cnt {name}{s}");
}

/// Prints message-loop rates and their call sites every two seconds.
pub(crate) fn start_counter() {
    let _ = os_std::thread::Builder::new().stack_size(128 << 10).spawn(|| {
        let mut prev = Diag::new();
        let mut prev_signals = 0u64;
        loop {
            os_std::thread::sleep(Duration::from_secs(2));
            let Ok(cur) = DIAG.lock().map(|d| *d) else { continue };
            let signals = crate::objects::SIGNALS.load(core::sync::atomic::Ordering::Relaxed);
            os_std::eprintln!(
                "winrun: cnt t={}s peek={} hit={} getmsg={} msgwait={} inp={} to={} qstat={} post={} disp={} idle={} woken={} pump={} ev={} sig={}",
                crate::kernel32::tick_ms() / 1000,
                cur.peek - prev.peek,
                cur.peek_hit - prev.peek_hit,
                cur.getmsg - prev.getmsg,
                cur.msgwait - prev.msgwait,
                cur.msgwait_input - prev.msgwait_input,
                cur.msgwait_timeout - prev.msgwait_timeout,
                cur.qstatus - prev.qstatus,
                cur.post - prev.post,
                cur.dispatch - prev.dispatch,
                cur.idle - prev.idle,
                cur.idle_woken - prev.idle_woken,
                cur.pump - prev.pump,
                cur.pump_events - prev.pump_events,
                signals - prev_signals,
            );
            print_hist("peek-msg", &cur.peek_msgs.delta(&prev.peek_msgs), false);
            print_hist("post-msg", &cur.post_msgs.delta(&prev.post_msgs), false);
            let wake_n = cur.wake_calls - prev.wake_calls;
            let wake_us = (cur.wake_us - prev.wake_us) / wake_n.max(1);
            os_std::eprintln!(
                "winrun: cnt wake n={wake_n} self={} avg_us={wake_us}",
                cur.wake_self - prev.wake_self
            );
            print_hist("wake-tid", &cur.wake_tids.delta(&prev.wake_tids), false);
            print_hist("wake-dur", &cur.wake_dur.delta(&prev.wake_dur), false);
            print_hist("peek-flags", &cur.peek_flags.delta(&prev.peek_flags), false);
            print_hist("msgwait-mask", &cur.msgwait_masks.delta(&prev.msgwait_masks), false);
            print_hist("pump-kind", &cur.pump_kinds.delta(&prev.pump_kinds), false);
            print_hist("peek-site", &cur.peek_sites.delta(&prev.peek_sites), true);
            print_hist("post-site", &cur.post_sites.delta(&prev.post_sites), true);
            prev = cur;
            prev_signals = signals;
        }
    });
}

/// MSG (48 bytes): hwnd, message @8, wParam @16, lParam @24, time @32, pt @36.
fn write_msg(p: *mut u8, m: &Msg) {
    // SAFETY: the caller's MSG.
    unsafe {
        teb::put(p as u64, 0, m.hwnd);
        teb::put(p as u64, 8, m.msg);
        teb::put(p as u64, 16, m.wparam);
        teb::put(p as u64, 24, m.lparam);
        teb::put(p as u64, 32, m.time);
        teb::put(p as u64, 36, m.pt.0);
        teb::put(p as u64, 40, m.pt.1);
    }
}

fn read_msg(p: *const u8) -> Msg {
    // SAFETY: the caller's MSG.
    unsafe {
        Msg {
            hwnd: teb::get(p as u64, 0),
            msg: teb::get(p as u64, 8),
            wparam: teb::get(p as u64, 16),
            lparam: teb::get(p as u64, 24),
            time: teb::get(p as u64, 32),
            pt: (teb::get(p as u64, 36), teb::get(p as u64, 40)),
            thread: teb::current_tid(),
        }
    }
}

extern "win64" fn GetMessageA(msg: *mut u8, hwnd: u64, min: u32, max: u32) -> Bool {
    if msg.is_null() {
        return fail(ERROR_INVALID_PARAMETER, -1);
    }
    diag(|d| d.getmsg += 1);
    static ITERS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    loop {
        dispatch_pending_frames();
        let r = with(|g| {
            g.set_fresh(0);
            if let Some(m) = g.next_message(hwnd, min, max, 0, true) {
                return Ok(m);
            }
            // Registered under the GUI lock, together with the sequence read:
            // a post cannot slip in between and skip its wake.
            IDLE_WAITERS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Err((crate::objects::sequence(), g.next_timer_in(hwnd, min, max, 0)))
        });
        match r {
            Ok(m) => {
                if m.msg == WM_CHAR {
                    let us = Instant::now().as_nanos_since_boot() / 1000;
                    os_std::eprintln!("winrun: t getchar {us} hwnd={:#x} c={:#x} msgtime={} tid={}", m.hwnd, m.wparam, m.time, teb::current_tid());
                }
                write_msg(msg, &m);
                return (m.msg != WM_QUIT) as Bool;
            }
            Err((seq, t)) => {
                let _idle = IdleGuard;
                let it = ITERS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if crate::COUNT.load(core::sync::atomic::Ordering::Relaxed) && it.is_multiple_of(10_000) {
                    os_std::eprintln!("winrun: getmsg it={it} tid={} hwnd={hwnd:#x} range={min:#x}..{max:#x} wait={t:?}", teb::current_tid());
                }
                crate::winsta::note_idle();
                idle(seq, t);
            }
        }
    }
}

extern "win64" fn GetMessageW(msg: *mut u8, hwnd: u64, min: u32, max: u32) -> Bool {
    GetMessageA(msg, hwnd, min, max)
}

const PM_REMOVE: u32 = 1;

extern "win64" fn PeekMessageA(msg: *mut u8, hwnd: u64, min: u32, max: u32, flags: u32) -> Bool {
    let callsite = site();
    dispatch_pending_frames();
    let m = with(|g| {
        g.set_fresh(0);
        g.next_message(hwnd, min, max, flags >> 16, flags & PM_REMOVE != 0)
    });
    diag(|d| {
        d.peek += 1;
        d.peek_flags.add(flags as u64);
        if let Some(m) = &m {
            d.peek_hit += 1;
            d.peek_msgs.add(m.msg as u64);
        }
        d.peek_sites.add(callsite);
    });
    static PEEKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let pk = PEEKS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    static LAST_MSGS: [core::sync::atomic::AtomicU32; 16] = [const { core::sync::atomic::AtomicU32::new(0) }; 16];
    static LAST_SEQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    if let Some(m) = &m {
        let s = LAST_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        LAST_MSGS[s as usize % 16].store(m.msg, core::sync::atomic::Ordering::Relaxed);
    }
    if crate::COUNT.load(core::sync::atomic::Ordering::Relaxed) && pk.is_multiple_of(10_000) {
        let mut ring = [0u32; 16];
        for (i, slot) in LAST_MSGS.iter().enumerate() {
            ring[i] = slot.load(core::sync::atomic::Ordering::Relaxed);
        }
        os_std::eprintln!(
            "winrun: peek it={pk} tid={} flags={flags:#x} hwnd={hwnd:#x} -> {} last={ring:x?}",
            teb::current_tid(),
            m.as_ref().map_or(0, |m| m.msg)
        );
    }
    match m {
        Some(m) => {
            if m.msg == WM_CHAR && flags & PM_REMOVE != 0 {
                let us = Instant::now().as_nanos_since_boot() / 1000;
                os_std::eprintln!("winrun: t peekchar {us} hwnd={:#x} c={:#x} flags={flags:#x} tid={}", m.hwnd, m.wparam, teb::current_tid());
            }
            if !msg.is_null() {
                write_msg(msg, &m);
            }
            TRUE
        }
        None => FALSE,
    }
}

extern "win64" fn PeekMessageW(msg: *mut u8, hwnd: u64, min: u32, max: u32, flags: u32) -> Bool {
    PeekMessageA(msg, hwnd, min, max, flags)
}

extern "win64" fn TranslateMessage(msg: *const u8) -> Bool {
    if msg.is_null() {
        return FALSE;
    }
    let m = read_msg(msg);
    if m.msg != WM_KEYDOWN && m.msg != WM_SYSKEYDOWN {
        return FALSE;
    }
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
        let n = with(|g| g.chars.len());
        os_std::eprintln!("winrun: translate vk={:#x} chars={n}", m.wparam);
    }
    with(|g| {
        if let Some(i) = g.chars.iter().position(|(vk, _)| *vk as u64 == m.wparam) {
            let (_, c) = g.chars.remove(i).expect("found");
            let us = Instant::now().as_nanos_since_boot() / 1000;
            os_std::eprintln!("winrun: t translate {us} vk={:#x} c={:#x} tid={}", m.wparam, c as u32, teb::current_tid());
            let time = m.time;
            g.queue.push_front(Msg { hwnd: m.hwnd, msg: WM_CHAR, wparam: c as u64, lparam: m.lparam, time, pt: m.pt, thread: m.thread });
            TRUE
        } else {
            FALSE
        }
    })
}

extern "win64" fn DispatchMessageA(msg: *const u8) -> i64 {
    if msg.is_null() {
        return 0;
    }
    diag(|d| d.dispatch += 1);
    let m = read_msg(msg);
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
        static N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
        if N.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 60 {
            os_std::eprintln!("winrun: dispatch enter msg={:#x} hwnd={:#x}", m.msg, m.hwnd);
        }
        if m.msg == 0xc001 {
            static C1: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
            let n = C1.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
            if n.is_multiple_of(1000) {
                os_std::eprintln!("winrun: dispatch c001 n={n} hwnd={:#x} w={:#x} tid={}", m.hwnd, m.wparam, teb::current_tid());
            }
        }
    }
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && matches!(m.msg, WM_CHAR | WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP) {
        os_std::eprintln!("winrun: dispatch msg={:#x} hwnd={:#x} w={:#x}", m.msg, m.hwnd, m.wparam);
    }
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && m.msg == WM_CHAR {
        os_std::eprintln!("winrun: char hwnd={:#x} c={:#x} ({})", m.hwnd, m.wparam, m.wparam as u8 as char);
    }
    if m.msg == WM_OSYX_FILE_DROP {
        crate::ole32::dispatch_file_drop(m.hwnd, m.wparam);
        return 0;
    }
    if m.msg == WM_TIMER && m.lparam != 0 {
        // SAFETY: a TIMERPROC passed to SetTimer.
        let f: TimerProc = unsafe { core::mem::transmute(m.lparam as usize) };
        f(m.hwnd, WM_TIMER, m.wparam, m.time);
        return 0;
    }
    let proc_ = wndproc_of(m.hwnd);

    match proc_ {
        Some(p) => call(p, m.hwnd, m.msg, m.wparam, m.lparam),
        None => 0,
    }
}

extern "win64" fn DispatchMessageW(msg: *const u8) -> i64 {
    DispatchMessageA(msg)
}

extern "win64" fn SendMessageA(hwnd: u64, msg: u32, w: u64, l: i64) -> i64 {
    match wndproc_of(hwnd) {
        Some(p) => call(p, hwnd, msg, w, l),
        None => fail(ERROR_INVALID_WINDOW_HANDLE, 0),
    }
}

extern "win64" fn SendMessageW(hwnd: u64, msg: u32, w: u64, l: i64) -> i64 {
    SendMessageA(hwnd, msg, w, l)
}

extern "win64" fn PostMessageA(hwnd: u64, msg: u32, w: u64, l: i64) -> Bool {
    let callsite = site();
    diag(|d| {
        d.post += 1;
        d.post_msgs.add(msg as u64);
        d.post_sites.add(callsite);
    });
    with(|g| {
        static POSTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let n = POSTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
        let wake = wake_msg();
        if wake != 0 && msg == wake {
            let me = teb::current_tid();
            let owner = g.windows.get(&hwnd).map(|w| w.thread);
            diag(|d| {
                d.wake_tids.add(me);
                if owner == Some(me) {
                    d.wake_self += 1;
                }
            });
            if n.is_multiple_of(1000) && crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
                let class = g.windows.get(&hwnd).and_then(|w| g.classes.get(w.class)).map_or("?", |c| c.name.as_str());
                let ra = caller_site();
                let at = crate::loader::where_is(ra).map_or_else(|| alloc::format!("{ra:#x}"), |(m, o)| alloc::format!("{m}+{o:#x}"));
                os_std::eprintln!("winrun: post n={n} msg={msg:#x} hwnd={hwnd:#x} class={class} w={w:#x} l={l:#x} tid={me} owner={owner:?} ra={at}");
            }
        } else if n.is_multiple_of(1000) && crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
            let class = g.windows.get(&hwnd).and_then(|w| g.classes.get(w.class)).map_or("?", |c| c.name.as_str());
            os_std::eprintln!("winrun: post n={n} msg={msg:#x} hwnd={hwnd:#x} class={class} w={w:#x} l={l:#x} tid={}", os_sys::gettid());
        }
        if hwnd != 0 && !g.windows.contains_key(&hwnd) {
            return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE);
        }
        g.post(hwnd, msg, w, l);
        TRUE
    })
}

extern "win64" fn PostMessageW(hwnd: u64, msg: u32, w: u64, l: i64) -> Bool {
    PostMessageA(hwnd, msg, w, l)
}

extern "win64" fn PostQuitMessage(code: i32) {
    with(|g| g.quit.insert(teb::current_tid(), code));
}

extern "win64" fn DefWindowProcA(hwnd: u64, msg: u32, _w: u64, l: i64) -> i64 {
    match msg {
        WM_WINDOWPOSCHANGED if l != 0 => {
            // SAFETY: this message supplies a WINDOWPOS during the callback.
            let flags = unsafe { teb::get::<u32>(l as u64, 32) };
            if let Some((kind, pos, size)) = with(|g| g.windows.get(&hwnd).map(|w| (
                if w.style & WS_MINIMIZE != 0 { 1 } else if w.style & WS_MAXIMIZE != 0 { 2 } else { 0 }, w.pos, w.size))) {
                if let Some(proc) = wndproc_of(hwnd) {
                    if flags & (0x1 | 0x800) == 0 { call(proc, hwnd, WM_SIZE, kind, if kind == 1 { 0 } else { (size.0 as i64 & 0xffff) | ((size.1 as i64 & 0xffff) << 16) }); }
                    if flags & (0x2 | 0x1000) == 0 { call(proc, hwnd, WM_MOVE, 0, (pos.0 as i64 & 0xffff) | ((pos.1 as i64 & 0xffff) << 16)); }
                }
            }
            0
        }
        WM_NCCREATE => 1,
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_PAINT => {
            let mut ps = [0u8; 72];
            BeginPaint(hwnd, ps.as_mut_ptr());
            EndPaint(hwnd, ps.as_ptr());
            0
        }
        WM_ERASEBKGND => {
            let dc = _w;
            let r = with(|g| g.windows.get(&hwnd).map(|w| (w.size, g.classes[w.class].background)));
            if let Some(((w, h), bg)) = r {
                if bg != 0 {
                    fill(dc, Rect::new(0, 0, w, h), bg);
                }
            }
            1
        }
        WM_GETTEXTLENGTH => GetWindowTextLengthA(hwnd) as i64,
        WM_GETTEXT => GetWindowTextA(hwnd, l as *mut u8, _w as i32) as i64,
        WM_SETTEXT => {
            // SAFETY: lParam is a NUL-terminated string.
            set_title(hwnd, unsafe { path::ansi_to_string(l as *const u8) }.unwrap_or_default()) as i64
        }
        _ => 0,
    }
}

/// The text messages carry UTF-16 here; everything else is as DefWindowProcA.
extern "win64" fn DefWindowProcW(hwnd: u64, msg: u32, w: u64, l: i64) -> i64 {
    match msg {
        WM_SETTEXT => {
            // SAFETY: lParam is a NUL-terminated UTF-16 string.
            set_title(hwnd, unsafe { path::wide_to_string(l as *const u16) }.unwrap_or_default()) as i64
        }
        WM_GETTEXT => GetWindowTextW(hwnd, l as *mut u16, w as i32) as i64,
        WM_GETTEXTLENGTH => GetWindowTextLengthW(hwnd) as i64,
        _ => DefWindowProcA(hwnd, msg, w, l),
    }
}

extern "win64" fn SetTimer(hwnd: u64, id: u64, ms: u32, proc_: u64) -> u64 {
    with(|g| {
        if hwnd != 0 && !g.windows.contains_key(&hwnd) {
            return fail(ERROR_INVALID_WINDOW_HANDLE, 0);
        }
        let id = if hwnd == 0 { g.handle() } else { id };
        if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
            static SETS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
            let n = SETS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
            if n.is_multiple_of(200) {
                os_std::eprintln!("winrun: settimer n={n} hwnd={hwnd:#x} id={id} ms={ms} tid={}", os_sys::gettid());
            }
        }
        let interval = (ms as u64).max(10);
        g.timers.retain(|t| !(t.hwnd == hwnd && t.id == id));
        let thread = g.owner(hwnd);
        g.timers.push(Timer { thread, hwnd, id, interval, due: Instant::now() + Duration::from_millis(interval), proc_ });
        if id == 0 {
            1
        } else {
            id
        }
    })
}

extern "win64" fn KillTimer(hwnd: u64, id: u64) -> Bool {
    with(|g| {
        let n = g.timers.len();
        g.timers.retain(|t| !(t.hwnd == hwnd && t.id == id));
        (g.timers.len() != n) as Bool
    })
}

extern "win64" fn GetFocus() -> u64 {
    with(|g| g.focus)
}

extern "win64" fn SetFocus(hwnd: u64) -> u64 {
    with(|g| core::mem::replace(&mut g.focus, hwnd))
}

extern "win64" fn GetActiveWindow() -> u64 {
    with(|g| g.focus)
}

/// PRISM delivers a pressed button's motion to its window anyway; the
/// capture window is recorded for GetCapture.
extern "win64" fn SetCapture(hwnd: u64) -> u64 {
    with(|g| {
        let new = if g.windows.contains_key(&hwnd) { hwnd } else { 0 };
        core::mem::replace(&mut g.capture, new)
    })
}

extern "win64" fn ReleaseCapture() -> Bool {
    let old = with(|g| core::mem::replace(&mut g.capture, 0));
    if old != 0 {
        SendMessageW(old, WM_CAPTURECHANGED, 0, 0);
    }
    TRUE
}

extern "win64" fn GetCapture() -> u64 {
    with(|g| if g.windows.contains_key(&g.capture) { g.capture } else { 0 })
}

const TME_LEAVE: u32 = 0x2;
const TME_CANCEL: u32 = 0x8000_0000;
const TME_QUERY: u32 = 0x4000_0000;

/// TRACKMOUSEEVENT: cbSize, dwFlags @4, hwndTrack @8, dwHoverTime @16.
/// Leaving is reported; hover (TME_HOVER) is accepted and never fires.
extern "win64" fn TrackMouseEvent(tme: *mut u8) -> Bool {
    if tme.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    // SAFETY: the caller's TRACKMOUSEEVENT.
    let (size, flags, hwnd) = unsafe { (teb::get::<u32>(tme as u64, 0), teb::get::<u32>(tme as u64, 4), teb::get::<u64>(tme as u64, 8)) };
    if size != 24 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    with(|g| {
        if flags & TME_QUERY != 0 {
            let leave = g.track_leave.first().copied();
            // SAFETY: as above.
            unsafe {
                teb::put(tme as u64, 4, if leave.is_some() { TME_LEAVE } else { 0u32 });
                teb::put(tme as u64, 8, leave.unwrap_or(0));
            }
            return TRUE;
        }
        if !g.windows.contains_key(&hwnd) {
            return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE);
        }
        if flags & TME_LEAVE != 0 {
            g.track_leave.retain(|&w| w != hwnd);
            if flags & TME_CANCEL == 0 {
                g.track_leave.push(hwnd);
            }
        }
        TRUE
    })
}

extern "win64" fn GetLastInputInfo(info: *mut u32) -> Bool {
    // SAFETY: the caller's LASTINPUTINFO (cbSize, dwTime).
    if info.is_null() || unsafe { *info } != 8 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    // SAFETY: as above.
    unsafe { *info.add(1) = with(|g| g.last_input) };
    TRUE
}

extern "win64" fn GetKeyState(vk: i32) -> i16 {
    with(|g| {
        let i = vk as usize & 0xFF;
        (if g.keys[i] { -0x8000i16 } else { 0 }) | g.toggles[i] as i16
    })
}

// ---- keyboard layout ------------------------------------------------------------------

/// The one keyboard layout: US English, locale 0409, device 0409.
const HKL_US: u64 = 0x0409_0409;
const HKL_PREV: u64 = 0;
const HKL_NEXT: u64 = 1;

fn key_of(vk: u32) -> Option<&'static keyboard::Key> {
    keyboard::KEYS.iter().find(|k| k.vk as u32 == vk)
}

/// The scan code of a virtual key (0xE0nn for extended keys; 0: none).
fn scan_of(vk: u32) -> u32 {
    key_of(vk).map_or(0, |k| k.scan as u32)
}

extern "win64" fn GetKeyboardLayout(_thread: u32) -> u64 {
    HKL_US
}

extern "win64" fn GetKeyboardLayoutList(n: i32, out: *mut u64) -> i32 {
    if n > 0 && !out.is_null() {
        // SAFETY: the caller's array of at least one HKL.
        unsafe { *out = HKL_US };
    }
    1
}

extern "win64" fn GetKeyboardLayoutNameW(out: *mut u16) -> Bool {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    for (i, c) in "00000409\0".encode_utf16().enumerate() {
        // SAFETY: the caller's KL_NAMELENGTH (9) buffer.
        unsafe { *out.add(i) = c };
    }
    TRUE
}

extern "win64" fn GetKeyboardLayoutNameA(out: *mut u8) -> Bool {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    // SAFETY: the caller's KL_NAMELENGTH (9) buffer.
    unsafe { core::ptr::copy_nonoverlapping(c"00000409".as_ptr() as *const u8, out, 9) };
    TRUE
}

/// Switching among the one layout returns it as the previous one.
extern "win64" fn ActivateKeyboardLayout(hkl: u64, _flags: u32) -> u64 {
    match hkl {
        HKL_US | HKL_PREV | HKL_NEXT => HKL_US,
        _ => fail(ERROR_INVALID_PARAMETER, 0),
    }
}

/// Only the US layout (KLID 00000409) can be loaded.
extern "win64" fn LoadKeyboardLayoutA(name: *const u8, _flags: u32) -> u64 {
    // SAFETY: the caller's NUL-terminated KLID.
    let id = unsafe { path::ansi_to_string(name) };
    if id.is_some_and(|s| u32::from_str_radix(&s, 16) == Ok(0x409)) {
        HKL_US
    } else {
        fail(ERROR_INVALID_PARAMETER, 0)
    }
}

extern "win64" fn UnloadKeyboardLayout(hkl: u64) -> Bool {
    if hkl == HKL_US { TRUE } else { fail(ERROR_INVALID_PARAMETER, FALSE) }
}

const MAPVK_VK_TO_VSC: u32 = 0;
const MAPVK_VSC_TO_VK: u32 = 1;
const MAPVK_VK_TO_CHAR: u32 = 2;
const MAPVK_VSC_TO_VK_EX: u32 = 3;
const MAPVK_VK_TO_VSC_EX: u32 = 4;

extern "win64" fn MapVirtualKeyExW(code: u32, kind: u32, _hkl: u64) -> u32 {
    let scan_table = |t: &[u8; 128], s: u32| if s < 128 { t[s as usize] as u32 } else { 0 };
    match kind {
        MAPVK_VK_TO_VSC => scan_of(code) & 0xFF,
        MAPVK_VK_TO_VSC_EX => scan_of(code),
        MAPVK_VK_TO_CHAR => key_of(code).map_or(0, |k| k.map_char as u32),
        MAPVK_VSC_TO_VK => scan_table(&keyboard::SCAN_TO_VK, code & 0xFF),
        MAPVK_VSC_TO_VK_EX if code & 0xFF00 == 0xE000 => scan_table(&keyboard::E0_SCAN_TO_VK_EX, code & 0xFF),
        MAPVK_VSC_TO_VK_EX if code < 0x100 => scan_table(&keyboard::SCAN_TO_VK_EX, code),
        _ => 0,
    }
}

extern "win64" fn MapVirtualKeyW(code: u32, kind: u32) -> u32 {
    MapVirtualKeyExW(code, kind, HKL_US)
}

/// The character a key makes in the given keyboard state. The US layout
/// has no dead keys and nothing on AltGr (Ctrl+Alt); key releases make
/// nothing.
extern "win64" fn ToUnicodeEx(vk: u32, scan: u32, state: *const u8, out: *mut u16, cch: i32, _flags: u32, _hkl: u64) -> i32 {
    if state.is_null() || scan & 0x8000 != 0 {
        return 0;
    }
    // SAFETY: the caller's 256-byte keyboard state.
    let s = |k: usize| unsafe { *state.add(k) };
    let down = |k: usize| s(k) & 0x80 != 0;
    let shift = down(0x10) || down(0xA0) || down(0xA1);
    let ctrl = down(0x11) || down(0xA2) || down(0xA3);
    let alt = down(0x12) || down(0xA4) || down(0xA5);
    if ctrl && alt {
        return 0;
    }
    let row = if ctrl { 2 } else if s(0x14) & 1 != 0 { 4 } else { 0 } + shift as usize;
    let Some(c) = key_of(vk).map(|k| k.chars[row]).filter(|&c| c != keyboard::NONE) else { return 0 };
    if !out.is_null() && cch > 0 {
        // SAFETY: the caller's buffer of `cch` units.
        unsafe {
            *out = c;
            if cch > 1 {
                *out.add(1) = 0;
            }
        }
    }
    1
}

extern "win64" fn ToUnicode(vk: u32, scan: u32, state: *const u8, out: *mut u16, cch: i32, flags: u32) -> i32 {
    ToUnicodeEx(vk, scan, state, out, cch, flags, HKL_US)
}

extern "win64" fn GetKeyboardState(out: *mut u8) -> Bool {
    if out.is_null() {
        return fail(ERROR_NOACCESS, FALSE);
    }
    with(|g| {
        for i in 0..256 {
            // SAFETY: the caller's 256-byte array.
            unsafe { *out.add(i) = if g.keys[i] { 0x80 } else { 0 } | g.toggles[i] as u8 };
        }
    });
    TRUE
}

extern "win64" fn SetKeyboardState(state: *const u8) -> Bool {
    if state.is_null() {
        return fail(ERROR_NOACCESS, FALSE);
    }
    with(|g| {
        for i in 0..256 {
            // SAFETY: the caller's 256-byte array.
            let v = unsafe { *state.add(i) };
            g.keys[i] = v & 0x80 != 0;
            g.toggles[i] = v & 1 != 0;
        }
    });
    TRUE
}

extern "win64" fn GetAsyncKeyState(vk: i32) -> i16 {
    GetKeyState(vk)
}

extern "win64" fn GetCursorPos(p: *mut i32) -> Bool {
    let (x, y) = with(|g| g.screen_pointer);
    if !p.is_null() {
        // SAFETY: the caller's POINT.
        unsafe {
            *p = x;
            *p.add(1) = y;
        }
    }
    TRUE
}

extern "win64" fn ScreenToClient(hwnd: u64, p: *mut i32) -> Bool {
    let Some((x, y)) = with(|g| g.windows.get(&hwnd).map(|w| w.pos)) else { return FALSE };
    if !p.is_null() {
        // SAFETY: the caller's POINT.
        unsafe {
            *p -= x;
            *p.add(1) -= y;
        }
    }
    TRUE
}

extern "win64" fn ClientToScreen(hwnd: u64, p: *mut i32) -> Bool {
    let Some((x, y)) = with(|g| g.windows.get(&hwnd).map(|w| w.pos)) else { return FALSE };
    if !p.is_null() {
        // SAFETY: the caller's POINT.
        unsafe {
            *p += x;
            *p.add(1) += y;
        }
    }
    TRUE
}

/// The topmost visible window under a screen point (windows are top level
/// and PRISM keeps no stacking order here: the newest wins).
extern "win64" fn WindowFromPoint(x: i32, y: i32) -> u64 {
    with(|g| {
        g.windows
            .iter()
            .rev()
            .find(|(_, w)| {
                w.visible && x >= w.pos.0 && y >= w.pos.1 && x < w.pos.0 + w.size.0 as i32 && y < w.pos.1 + w.size.1 as i32
            })
            .map_or(0, |(h, _)| *h)
    })
}

/// Client coordinates of `from` to those of `to` (0: the screen). Returns
/// the horizontal offset in the low word and the vertical in the high.
extern "win64" fn MapWindowPoints(from: u64, to: u64, pts: *mut i32, n: u32) -> i32 {
    let origin = |h: u64| if h == 0 { Some((0, 0)) } else { with(|g| g.windows.get(&h).map(|w| w.pos)) };
    let (Some(a), Some(b)) = (origin(from), origin(to)) else { return fail(ERROR_INVALID_WINDOW_HANDLE, 0) };
    let (dx, dy) = (a.0 - b.0, a.1 - b.1);
    if !pts.is_null() {
        for i in 0..n as usize {
            // SAFETY: the caller's array of `n` POINTs.
            unsafe {
                *pts.add(2 * i) += dx;
                *pts.add(2 * i + 1) += dy;
            }
        }
    }
    ((dx as u16 as u32) | ((dy as u16 as u32) << 16)) as i32
}

extern "win64" fn GetSystemMetrics(i: i32) -> i32 {
    let v = with(|g| {
        let (w, h) = g.conn().map(|c| (c.screen_width as i32, c.screen_height as i32)).unwrap_or((1024, 768));
        match i {
            0 | 16 | 78 => w, // SM_CXSCREEN, SM_CXFULLSCREEN, SM_CXVIRTUALSCREEN
            1 | 17 | 79 => h,
            4 => 30,       // SM_CYCAPTION
            5 | 6 => 1,    // SM_CXBORDER / SM_CYBORDER
            11 | 12 => 32, // SM_CXICON / SM_CYICON
            13 | 14 => 32, // SM_CXCURSOR
            80 => 1,       // SM_CMONITORS
            _ => 0,
        }
    });
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
        static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        if N.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 80 {
            os_std::eprintln!("winrun: sysmetrics i={i} -> {v}");
        }
    }
    v
}

/// The system-wide settings a program reads. OSyx has one configuration, so
/// the queries answer from it and a change request is refused: the desktop
/// keeps its own appearance, and `SystemParametersInfo` is how Windows
/// programs learn about it rather than how they set it.
extern "win64" fn SystemParametersInfoW(action: u32, param: u32, value: *mut u8, _ini: u32) -> Bool {
    system_parameters(action, param, value, true)
}

extern "win64" fn SystemParametersInfoA(action: u32, param: u32, value: *mut u8, _ini: u32) -> Bool {
    system_parameters(action, param, value, false)
}

const SPI_GETWORKAREA: u32 = 0x0030;

/// A BOOL or integer setting, as Windows reports it on a stock desktop.
fn parameter_value(action: u32) -> Option<i32> {
    Some(match action {
        0x000A => 31,  // SPI_GETKEYBOARDSPEED
        0x000D => 75,  // SPI_ICONHORIZONTALSPACING
        0x000E => 0,   // SPI_GETSCREENSAVETIMEOUT
        0x0010 => 0,   // SPI_GETSCREENSAVEACTIVE
        0x0016 => 1,   // SPI_GETKEYBOARDDELAY
        0x0018 => 75,  // SPI_ICONVERTICALSPACING
        0x0019 => 1,   // SPI_GETICONTITLEWRAP
        0x004A => 0,   // SPI_GETFONTSMOOTHING: the renderer has no ClearType
        0x0066 => 400, // SPI_GETMOUSEHOVERTIME
        0x0068 => 3,   // SPI_GETWHEELSCROLLLINES
        0x006A => 400, // SPI_GETMENUSHOWDELAY
        0x0070 => 10,  // SPI_GETMOUSESPEED
        0x0072 => 2,   // SPI_GETMOUSEWHEELROUTING: to the window with focus
        0x1002 => 0,   // SPI_GETMENUANIMATION
        0x1004 => 0,   // SPI_GETCOMBOBOXANIMATION
        0x1008 => 0,   // SPI_GETGRADIENTCAPTIONS
        0x100A => 1,   // SPI_GETKEYBOARDCUES
        0x1012 => 0,   // SPI_GETSELECTIONFADE
        0x1014 => 0,   // SPI_GETTOOLTIPANIMATION
        0x1016 => 0,   // SPI_GETTOOLTIPFADE
        0x1018 => 0,   // SPI_GETCURSORSHADOW
        0x101E => 0,   // SPI_GETMENUFADE
        0x1022 => 1,   // SPI_GETFLATMENU
        0x1024 => 3,   // SPI_GETWHEELSCROLLCHARS
        0x103E => 1,   // SPI_GETUIEFFECTS
        0x1042 => 1,   // SPI_GETCLIENTAREAANIMATION
        _ => return None,
    })
}

/// A usable system UI font backed by the installed OFL TrueType family.
fn system_logfont(value: *mut u8, wide: bool) {
    // SAFETY: the caller has a LOGFONTA (60 bytes) or LOGFONTW (92 bytes).
    unsafe {
        core::ptr::write_bytes(value, 0, if wide { 92 } else { 60 });
        teb::put(value as u64, 0, -12i32);
        teb::put(value as u64, 16, 400i32);
        *value.add(23) = 1; // DEFAULT_CHARSET
        if wide { out_w("Lato", value.add(28).cast(), 32); }
        else { out_a("Lato", value.add(28), 32); }
    }
}

fn system_parameters(action: u32, _param: u32, value: *mut u8, wide: bool) -> Bool {
    if value.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    if action == 0x1f { // SPI_GETICONTITLELOGFONT
        system_logfont(value, wide);
        return TRUE;
    }
    if action == 0x29 { // SPI_GETNONCLIENTMETRICS
        let font_bytes = if wide { 92 } else { 60 };
        let legacy_size = 40 + 5 * font_bytes;
        // SAFETY: NONCLIENTMETRICS begins with cbSize.
        let size = unsafe { teb::get::<u32>(value as u64, 0) } as usize;
        if size != legacy_size && size != legacy_size + 4 { return fail(ERROR_INVALID_PARAMETER, FALSE); }
        // SAFETY: the exact ANSI/wide modern or legacy structure size.
        unsafe {
            core::ptr::write_bytes(value.add(4), 0, size - 4);
            for (offset, dimension) in [(4, 1i32), (8, 17), (12, 17), (16, 18), (20, 23),
                (24 + font_bytes, 18), (28 + font_bytes, 19), (32 + 2 * font_bytes, 18), (36 + 2 * font_bytes, 19)] {
                teb::put(value as u64, offset, dimension);
            }
            for offset in [24, 32 + font_bytes, 40 + 2 * font_bytes, 40 + 3 * font_bytes, 40 + 4 * font_bytes] {
                system_logfont(value.add(offset), wide);
            }
        }
        return TRUE;
    }
    if action == SPI_GETWORKAREA {
        let (w, h) = with(|g| g.conn().map(|c| (c.screen_width as i32, c.screen_height as i32)).unwrap_or((1024, 768)));
        if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
            static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
            if N.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 8 {
                os_std::eprintln!("winrun: workarea -> {w}x{h}");
            }
        }
        // SAFETY: the caller's RECT, 16 bytes.
        unsafe {
            teb::put(value as u64, 0, 0i32);
            teb::put(value as u64, 4, 0i32);
            teb::put(value as u64, 8, w);
            teb::put(value as u64, 12, h);
        }
        return TRUE;
    }
    match parameter_value(action) {
        Some(v) => {
            // SAFETY: the caller's BOOL or integer, 4 bytes.
            unsafe { teb::put(value as u64, 0, v) };
            TRUE
        }
        None => {
            if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
                os_std::eprintln!("winrun: SystemParametersInfo({action:#x}) unsupported setting");
            }
            fail(ERROR_INVALID_PARAMETER, FALSE)
        }
    }
}

/// Predefined cursors and icons: the resource id is the handle (PRISM
/// draws its own pointer).
extern "win64" fn LoadCursorA(_inst: u64, id: u64) -> u64 {
    if id < 0x10000 {
        0x1_0000 + id
    } else {
        fail(ERROR_NOT_SUPPORTED, 0)
    }
}

/// ICONINFO (32 bytes): fIcon, xHotspot @4, yHotspot @8, hbmMask @16,
/// hbmColor @24. The bitmaps are copied, as on Windows.
extern "win64" fn CreateIconIndirect(info: *const u8) -> u64 {
    if info.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's ICONINFO.
    let (is_icon, hx, hy, mask, color) = unsafe {
        let p = info as u64;
        (teb::get::<u32>(p, 0) != 0, teb::get::<u32>(p, 4), teb::get::<u32>(p, 8), teb::get::<u64>(p, 16), teb::get::<u64>(p, 24))
    };
    with(|g| {
        let Some(m) = gdi::duplicate_bitmap(g, mask) else { return fail(ERROR_INVALID_PARAMETER, 0) };
        let c = if color == 0 { 0 } else { gdi::duplicate_bitmap(g, color).unwrap_or(0) };
        let h = g.handle();
        let hotspot = if is_icon { (0, 0) } else { (hx, hy) };
        g.icons.insert(h, Icon { is_icon, hotspot, mask: m, color: c });
        h
    })
}

/// GetIconInfo hands out copies the caller deletes.
extern "win64" fn GetIconInfo(icon: u64, out: *mut u8) -> Bool {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    with(|g| {
        let Some((is_icon, hotspot, mask, color)) = g.icons.get(&icon).map(|i| (i.is_icon, i.hotspot, i.mask, i.color)) else {
            return fail(ERROR_INVALID_CURSOR_HANDLE, FALSE);
        };
        let m = gdi::duplicate_bitmap(g, mask).unwrap_or(0);
        let c = if color == 0 { 0 } else { gdi::duplicate_bitmap(g, color).unwrap_or(0) };
        // SAFETY: the caller's ICONINFO.
        unsafe {
            let p = out as u64;
            teb::put(p, 0, is_icon as u32);
            teb::put(p, 4, hotspot.0);
            teb::put(p, 8, hotspot.1);
            teb::put(p, 16, m);
            teb::put(p, 24, c);
        }
        TRUE
    })
}

extern "win64" fn DestroyIcon(icon: u64) -> Bool {
    with(|g| match g.icons.remove(&icon) {
        Some(i) => {
            g.bitmaps.remove(&i.mask);
            g.gdi.remove(&i.mask);
            g.bitmaps.remove(&i.color);
            g.gdi.remove(&i.color);
            TRUE
        }
        // Shared system icons (LoadIcon) are never destroyed.
        None if (0x1_0000..0x2_0000).contains(&icon) => TRUE,
        None => fail(ERROR_INVALID_CURSOR_HANDLE, FALSE),
    })
}

const IMAGE_ICON: u32 = 1;
const IMAGE_CURSOR: u32 = 2;
const LR_LOADFROMFILE: u32 = 0x10;

/// System icons and cursors by ordinal; images from resources or files
/// are not supported (OSyx has no image resources to give).
extern "win64" fn LoadImageW(inst: u64, name: u64, kind: u32, _w: i32, _h: i32, flags: u32) -> u64 {
    if inst == 0 && name < 0x10000 && flags & LR_LOADFROMFILE == 0 && matches!(kind, IMAGE_ICON | IMAGE_CURSOR) {
        return LoadCursorA(0, name);
    }
    fail(ERROR_RESOURCE_NAME_NOT_FOUND, 0)
}

extern "win64" fn LoadCursorW(inst: u64, id: u64) -> u64 {
    LoadCursorA(inst, id)
}

extern "win64" fn LoadIconA(inst: u64, id: u64) -> u64 {
    LoadCursorA(inst, id)
}

extern "win64" fn LoadIconW(inst: u64, id: u64) -> u64 {
    LoadCursorA(inst, id)
}

extern "win64" fn SetCursor(c: u64) -> u64 {
    c
}

extern "win64" fn GetSysColor(i: i32) -> u32 {
    to_colorref(sys_color(i as u32))
}

extern "win64" fn GetSysColorBrush(i: i32) -> u64 {
    with(|g| {
        let h = g.handle();
        g.gdi.insert(h, Gdi::Brush(sys_color(i as u32)));
        h
    })
}

extern "win64" fn MessageBeep(_t: u32) -> Bool {
    TRUE
}

// ---- painting -------------------------------------------------------------------------

/// Waits (bounded) until PRISM released the window's buffer.
fn wait_drawable(hwnd: u64) -> bool {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(2);
    loop {
        let ok = with(|g| {
            g.pump();
            g.windows.get(&hwnd).map(|w| w.win.can_draw())
        });
        match ok {
            Some(true) => {
                let waited = started.elapsed();
                if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && waited > Duration::from_millis(30) {
                    os_std::eprintln!("winrun: wait_drawable hwnd={hwnd:#x} took {} ms", waited.as_millis());
                }
                return true;
            }
            Some(false) if Instant::now() < deadline => with(|g| g.wait(Duration::from_millis(5))),
            other => {
                if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
                    os_std::eprintln!("winrun: wait_drawable hwnd={hwnd:#x} failed other={other:?} after {} ms", started.elapsed().as_millis());
                }
                return false;
            }
        }
    }
}

fn new_dc(g: &mut Gui, hwnd: u64, paint: Rect) -> u64 {
    let h = g.handle();
    g.dcs.insert(
        h,
        Dc {
            hwnd,
            made: Instant::now(),
            paint,
            text: rgb(0, 0, 0),
            bk: rgb(255, 255, 255),
            opaque: true,
            brush: STOCK_BASE + WHITE_BRUSH as u64,
            pen: STOCK_BASE + BLACK_PEN as u64,
            font: STOCK_BASE + SYSTEM_FONT as u64,
            pos: (0, 0),
            bitmap: 0,
            memory: false,
            clip: None,
            transform: Xform::IDENTITY,
            align: 0,
            graphics_mode: 1,
            map_mode: 1,
            poly_mode: 1,
            stretch_mode: 1,
            miter: 10.0,
            saved: Vec::new(),
            path: GdiPath::default(),
        },
    );
    h
}

/// PAINTSTRUCT (72 bytes): hdc, fErase @8, rcPaint @12, ...
extern "win64" fn BeginPaint(hwnd: u64, ps: *mut u8) -> u64 {
    if !wait_drawable(hwnd) {
        return fail(ERROR_INVALID_WINDOW_HANDLE, 0);
    }
    let r = with(|g| {
        let w = g.windows.get_mut(&hwnd)?;
        let full = Rect::new(0, 0, w.size.0, w.size.1);
        let paint = w.invalid.take().unwrap_or(full);
        let erase = core::mem::replace(&mut w.erase, false);
        let dc = new_dc(g, hwnd, paint);
        Some((dc, paint, erase))
    });
    let Some((dc, paint, erase)) = r else { return fail(ERROR_INVALID_WINDOW_HANDLE, 0) };
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
        os_std::eprintln!("winrun: beginpaint hwnd={hwnd:#x} {}x{} at ({},{})", paint.w, paint.h, paint.x, paint.y);
    }
    if erase {
        if let Some(p) = wndproc_of(hwnd) {
            call(p, hwnd, WM_ERASEBKGND, dc, 0);
        }
    }
    if !ps.is_null() {
        // SAFETY: the caller's PAINTSTRUCT.
        unsafe {
            core::ptr::write_bytes(ps, 0, 72);
            teb::put(ps as u64, 0, dc);
            teb::put(ps as u64, 8, erase as i32);
        }
        write_rect((ps as usize + 12) as *mut i32, paint);
    }
    dc
}

/// Sampled hash of a surface rectangle for diagnosing which regions change.
fn band_hash(s: &osyx_gfx::Surface<'_>, r: Rect) -> u32 {
    let mut h = 2_166_136_261u32;
    let x0 = r.x.max(0) as u32;
    let x1 = (r.x + r.w as i32).max(0) as u32;
    let y0 = r.y.max(0) as u32;
    let y1 = (r.y + r.h as i32).max(0) as u32;
    for y in (y0..y1.min(s.height())).step_by(5) {
        let row = s.row(y);
        let mut x = x0 as usize;
        while x < (x1 as usize).min(row.len()) {
            h ^= row[x];
            h = h.wrapping_mul(16_777_619);
            x += 16;
        }
    }
    h
}

/// Sampled row hash for diagnosing which window bands actually change.
fn band_hash_rows(s: &osyx_gfx::Surface<'_>, y0: u32, y1: u32) -> u32 {
    band_hash(s, Rect::new(0, y0 as i32, s.width(), y1.saturating_sub(y0)))
}

fn present(hwnd: u64, r: Option<Rect>) {
    with(|g| {
        let Some(w) = g.windows.get_mut(&hwnd) else { return };
        let full = Rect::new(0, 0, w.size.0, w.size.1);
        // PRISM copies only the committed rects, so a paint present must also
        // cover everything drawn through the DC outside its paint rectangle.
        let damage = match (r, w.drawn.take()) {
            (Some(a), Some(b)) => a.union(&b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => full,
        }
        .intersect(&full);
        if damage.w == 0 || damage.h == 0 {
            return;
        }
        if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
            let (top, page, popup, url) = match w.win.surface() {
                Ok(s) => (
                    band_hash_rows(&s, 0, 170),
                    band_hash_rows(&s, 170, 700),
                    band_hash(&s, Rect::new(260, 290, 780, 320)),
                    band_hash(&s, Rect::new(0, 40, 260, 120)),
                ),
                Err(_) => (0, 0, 0, 0),
            };
            os_std::eprintln!(
                "winrun: present hwnd={hwnd:#x} damage={}x{} at ({},{}) top={top:08x} page={page:08x} popup={popup:08x} url={url:08x}",
                damage.w,
                damage.h,
                damage.x,
                damage.y
            );
        }
        if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
            static FRAMES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
            if FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 32 {
                if let Ok(surface) = w.win.surface() {
                    os_std::eprintln!("winrun: window frame {hwnd:#x} damage={damage:?} size={:?} pixels={:x?}", surface.bounds(), &surface.pixels()[..surface.pixels().len().min(8)]);
                }
            }
        }
        let rect = proto::Rect { x: damage.x, y: damage.y, w: damage.w, h: damage.h };
        let Some(c) = g.conn.as_mut() else { return };
        let t = Instant::now();
        let r = g.windows.get_mut(&hwnd).map(|w| w.win.present(c, Some(rect)));
        let us = t.elapsed().as_micros();
        if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && us >= 20_000 {
            os_std::eprintln!("winrun: presentsess hwnd={hwnd:#x} tid={} us={us}", teb::current_tid());
        }
        if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && r.as_ref().is_some_and(|r| r.is_err()) {
            os_std::eprintln!("winrun: present hwnd={hwnd:#x} failed");
        }
    });
}

extern "win64" fn EndPaint(hwnd: u64, ps: *const u8) -> Bool {
    if ps.is_null() {
        return FALSE;
    }
    // SAFETY: the caller's PAINTSTRUCT from BeginPaint.
    let dc: u64 = unsafe { teb::get(ps as u64, 0) };
    let paint = with(|g| g.dcs.remove(&dc).map(|d| {
        if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
            let drawn = g.windows.get(&hwnd).and_then(|w| w.drawn);
            os_std::eprintln!(
                "winrun: dcsess endpaint hwnd={hwnd:#x} tid={} us={} paint={}x{} drawn={:?}",
                teb::current_tid(),
                d.made.elapsed().as_micros(),
                d.paint.w,
                d.paint.h,
                drawn.map(|r| (r.x, r.y, r.w, r.h))
            );
        }
        d.paint
    }));
    present(hwnd, paint);
    TRUE
}

extern "win64" fn GetDC(hwnd: u64) -> u64 {
    if hwnd == 0 {
        return gdi::display_dc();
    }
    if !wait_drawable(hwnd) {
        return fail(ERROR_NOT_SUPPORTED, 0); // no drawing on the whole screen
    }
    with(|g| {
        let Some(size) = g.windows.get(&hwnd).map(|w| w.size) else { return 0 };
        new_dc(g, hwnd, Rect::new(0, 0, size.0, size.1))
    })
}

extern "win64" fn ReleaseDC(hwnd: u64, dc: u64) -> i32 {
    let info = with(|g| g.dcs.remove(&dc).map(|d| (d.made, d.paint)));
    let had = info.is_some();
    if let Some((made, paint)) = info {
        if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && hwnd != 0 {
            let drawn = with(|g| g.windows.get(&hwnd).and_then(|w| w.drawn));
            os_std::eprintln!(
                "winrun: dcsess release hwnd={hwnd:#x} tid={} us={} paint={}x{} drawn={:?}",
                teb::current_tid(),
                made.elapsed().as_micros(),
                paint.w,
                paint.h,
                drawn.map(|r| (r.x, r.y, r.w, r.h))
            );
        }
        present(hwnd, None);
    }
    had as i32
}

/// PRISM draws decorations outside the application's surface, so its
/// window and client drawing areas share the same origin and dimensions.
extern "win64" fn GetWindowDC(hwnd: u64) -> u64 {
    GetDC(hwnd)
}

/// Runs `f` on the DC's window surface, clipped to its paint rectangle;
/// records what was drawn for the next present.
fn draw<R>(dc: u64, f: impl FnMut(&mut Surface, &Dc, &BTreeMap<u64, Gdi>, Rect) -> (R, Rect)) -> Option<R> {
    gdi::draw_dc(dc, f)
}

/// A brush handle, or a system color index + 1 (as in WNDCLASS.hbrBackground).
fn brush_color(gdi: &BTreeMap<u64, Gdi>, b: u64) -> Option<Color> {
    match gdi.get(&b) {
        Some(Gdi::Brush(c)) => Some(*c),
        Some(_) => None,
        None if (1..=31).contains(&b) => Some(sys_color(b as u32 - 1)),
        None => None,
    }
}

fn fill(dc: u64, r: Rect, brush: u64) -> bool {
    draw(dc, |s, _, gdi, clip| match brush_color(gdi, brush) {
        Some(c) => {
            let r2 = r.intersect(&clip);
            s.fill_rect(r2, c);
            (true, r2)
        }
        None => (false, Rect::EMPTY),
    })
    .unwrap_or(false)
}

extern "win64" fn FillRect(dc: u64, r: *const i32, brush: u64) -> i32 {
    match read_rect(r) {
        Some(rect) => fill(dc, rect, brush) as i32,
        None => 0,
    }
}

extern "win64" fn FrameRect(dc: u64, r: *const i32, brush: u64) -> i32 {
    let Some(r) = read_rect(r) else { return 0 };
    draw(dc, |s, _, gdi, clip| {
        let Some(c) = brush_color(gdi, brush) else { return (0, Rect::EMPTY) };
        for e in [
            Rect::new(r.x, r.y, r.w, 1),
            Rect::new(r.x, r.y + r.h as i32 - 1, r.w, 1),
            Rect::new(r.x, r.y, 1, r.h),
            Rect::new(r.x + r.w as i32 - 1, r.y, 1, r.h),
        ] {
            s.fill_rect(e.intersect(&clip), c);
        }
        (1, r)
    })
    .unwrap_or(0)
}

// ---- fonts and text -----------------------------------------------------------------

struct Fonts {
    sans: PropFont<'static>,
    bold: PropFont<'static>,
    large: PropFont<'static>,
    mono: MonoFont<'static>,
}

fn fonts() -> &'static Fonts {
    static F: Mutex<Option<&'static Fonts>> = Mutex::new(None);
    let mut g = F.lock().unwrap();
    g.get_or_insert_with(|| {
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Fonts {
            sans: PropFont::parse(SANS14).expect("embedded sans14"),
            bold: PropFont::parse(SANS14B).expect("embedded sans14b"),
            large: PropFont::parse(SANS20).expect("embedded sans20"),
            mono: MonoFont::parse(MONO15).expect("embedded mono15"),
        }))
    })
}

fn font_of(gdi: &BTreeMap<u64, Gdi>, h: u64) -> FontKind {
    match gdi.get(&h) {
        Some(Gdi::Font(k)) => *k,
        _ => FontKind::Sans,
    }
}

fn line_height(k: FontKind) -> u32 {
    let f = fonts();
    match k {
        FontKind::Sans => f.sans.line_height(),
        FontKind::SansBold => f.bold.line_height(),
        FontKind::Large => f.large.line_height(),
        FontKind::Mono => f.mono.line_height(),
    }
}

fn measure(k: FontKind, t: &str) -> u32 {
    let f = fonts();
    match k {
        FontKind::Sans => f.sans.measure(t),
        FontKind::SansBold => f.bold.measure(t),
        FontKind::Large => f.large.measure(t),
        FontKind::Mono => f.mono.measure(t),
    }
}

fn draw_text(s: &mut Surface, k: FontKind, x: i32, y: i32, t: &str, c: Color, clip: Rect) -> Rect {
    let f = fonts();
    match k {
        FontKind::Sans => f.sans.draw_clipped(s, x, y, t, c, 255, clip),
        FontKind::SansBold => f.bold.draw_clipped(s, x, y, t, c, 255, clip),
        FontKind::Large => f.large.draw_clipped(s, x, y, t, c, 255, clip),
        FontKind::Mono => {
            // The cell font has no clipped variant. Rasterize coverage in a
            // temporary surface, then blend only the visible part.
            let r = Rect::new(x, y, f.mono.measure(t), f.mono.line_height()).intersect(&clip);
            if r.w > 0 && r.h > 0 {
                let (w,h)=(f.mono.measure(t),f.mono.line_height());
                let mut pixels=alloc::vec![0;(w*h) as usize];
                let mut mask=Surface::new(&mut pixels,w,h,w).expect("font cell surface");
                f.mono.draw(&mut mask,0,0,t,0xffffff,255);
                for dy in r.y..r.y+r.h as i32 { for dx in r.x..r.x+r.w as i32 {
                    s.blend_px(dx,dy,c,mask.get(dx-x,dy-y).unwrap_or(0)&255);
                } }
            }
            r
        }
    }
}

fn text_out(dc: u64, x: i32, y: i32, t: &str) -> Bool {
    gdi::text_out_ex(dc, x, y, t, 0, None, None)
}

extern "win64" fn TextOutA(dc: u64, x: i32, y: i32, s: *const u8, n: i32) -> Bool {
    // SAFETY: the caller's buffer of `n` bytes.
    let b = unsafe { core::slice::from_raw_parts(s, n.max(0) as usize) };
    text_out(dc, x, y, &String::from_utf8_lossy(b))
}

extern "win64" fn TextOutW(dc: u64, x: i32, y: i32, s: *const u16, n: i32) -> Bool {
    // SAFETY: the caller's buffer of `n` units.
    let u = unsafe { core::slice::from_raw_parts(s, n.max(0) as usize) };
    let t: String = char::decode_utf16(u.iter().copied()).map(|c| c.unwrap_or('\u{FFFD}')).collect();
    text_out(dc, x, y, &t)
}

const DT_CENTER: u32 = 0x1;
const DT_RIGHT: u32 = 0x2;
const DT_VCENTER: u32 = 0x4;
const DT_BOTTOM: u32 = 0x8;
const DT_WORDBREAK: u32 = 0x10;
const DT_SINGLELINE: u32 = 0x20;
const DT_CALCRECT: u32 = 0x400;

fn draw_text_impl(dc: u64, text: &str, r: *mut i32, fmt: u32) -> i32 {
    let Some(area) = read_rect(r) else { return 0 };
    let res = draw(dc, |s, d, gdi, clip| {
        let k = font_of(gdi, d.font);
        let lh = line_height(k) as i32;
        // Lines: explicit breaks, then word wrapping inside the width.
        let mut lines: Vec<String> = Vec::new();
        let paras: Vec<&str> = if fmt & DT_SINGLELINE != 0 { alloc::vec![text] } else { text.split('\n').collect() };
        for p in paras {
            let p = p.trim_end_matches('\r');
            if fmt & DT_WORDBREAK == 0 {
                lines.push(p.to_string());
                continue;
            }
            let mut cur = String::new();
            for word in p.split(' ') {
                let cand = if cur.is_empty() { word.to_string() } else { alloc::format!("{cur} {word}") };
                if measure(k, &cand) > area.w && !cur.is_empty() {
                    lines.push(core::mem::take(&mut cur));
                    cur = word.to_string();
                } else {
                    cur = cand;
                }
            }
            lines.push(cur);
        }
        let height = lh * lines.len() as i32;
        let width = lines.iter().map(|l| measure(k, l)).max().unwrap_or(0);
        if fmt & DT_CALCRECT != 0 {
            return ((height, Some((width, height))), Rect::EMPTY);
        }
        let mut y = area.y;
        if fmt & DT_SINGLELINE != 0 && fmt & DT_VCENTER != 0 {
            y = area.y + (area.h as i32 - lh) / 2;
        } else if fmt & DT_SINGLELINE != 0 && fmt & DT_BOTTOM != 0 {
            y = area.y + area.h as i32 - lh;
        }
        let clip2 = clip.intersect(&area);
        for l in &lines {
            let w = measure(k, l) as i32;
            let x = if fmt & DT_CENTER != 0 {
                area.x + (area.w as i32 - w) / 2
            } else if fmt & DT_RIGHT != 0 {
                area.x + area.w as i32 - w
            } else {
                area.x
            };
            if d.opaque {
                s.fill_rect(Rect::new(x, y, w as u32, lh as u32).intersect(&clip2), d.bk);
            }
            draw_text(s, k, x, y, l, d.text, clip2);
            y += lh;
        }
        ((height, None), area)
    });
    match res {
        Some((h, Some((w, hh)))) => {
            write_rect(r, Rect::new(area.x, area.y, w, hh as u32));
            h
        }
        Some((h, None)) => h,
        None => 0,
    }
}

extern "win64" fn DrawTextA(dc: u64, s: *const u8, n: i32, r: *mut i32, fmt: u32) -> i32 {
    let t = if n < 0 {
        // SAFETY: NUL-terminated text.
        unsafe { path::ansi_to_string(s) }.unwrap_or_default()
    } else {
        // SAFETY: the caller's buffer of `n` bytes.
        String::from_utf8_lossy(unsafe { core::slice::from_raw_parts(s, n as usize) }).into_owned()
    };
    draw_text_impl(dc, &t, r, fmt)
}

extern "win64" fn DrawTextW(dc: u64, s: *const u16, n: i32, r: *mut i32, fmt: u32) -> i32 {
    let t = if n < 0 {
        // SAFETY: NUL-terminated text.
        unsafe { path::wide_to_string(s) }.unwrap_or_default()
    } else {
        // SAFETY: the caller's buffer of `n` units.
        let u = unsafe { core::slice::from_raw_parts(s, n as usize) };
        char::decode_utf16(u.iter().copied()).map(|c| c.unwrap_or('\u{FFFD}')).collect()
    };
    draw_text_impl(dc, &t, r, fmt)
}

fn extent(dc: u64, t: &str, out: *mut i32) -> Bool {
    let k = with(|g| g.dcs.get(&dc).map(|d| font_of(&g.gdi, d.font)));
    let Some(k) = k else { return FALSE };
    if !out.is_null() {
        // SAFETY: the caller's SIZE.
        unsafe {
            *out = measure(k, t) as i32;
            *out.add(1) = line_height(k) as i32;
        }
    }
    TRUE
}

extern "win64" fn GetTextExtentPoint32A(dc: u64, s: *const u8, n: i32, out: *mut i32) -> Bool {
    // SAFETY: the caller's buffer of `n` bytes.
    let b = unsafe { core::slice::from_raw_parts(s, n.max(0) as usize) };
    extent(dc, &String::from_utf8_lossy(b), out)
}

extern "win64" fn GetTextExtentPoint32W(dc: u64, s: *const u16, n: i32, out: *mut i32) -> Bool {
    // SAFETY: the caller's buffer of `n` units.
    let u = unsafe { core::slice::from_raw_parts(s, n.max(0) as usize) };
    let t: String = char::decode_utf16(u.iter().copied()).map(|c| c.unwrap_or('\u{FFFD}')).collect();
    extent(dc, &t, out)
}

/// TEXTMETRICA (56 bytes): tmHeight, tmAscent, tmDescent, tmInternalLeading,
/// tmExternalLeading, tmAveCharWidth, tmMaxCharWidth, ...
extern "win64" fn GetTextMetricsA(dc: u64, tm: *mut u8) -> Bool {
    let k = with(|g| g.dcs.get(&dc).map(|d| font_of(&g.gdi, d.font)));
    let (Some(k), false) = (k, tm.is_null()) else { return FALSE };
    let h = line_height(k) as i32;
    let avg = measure(k, "x") as i32;
    let max = measure(k, "W") as i32;
    // SAFETY: the caller's TEXTMETRIC (at least 56 bytes).
    unsafe {
        core::ptr::write_bytes(tm, 0, 56);
        teb::put(tm as u64, 0, h);
        teb::put(tm as u64, 4, h * 4 / 5);
        teb::put(tm as u64, 8, h - h * 4 / 5);
        teb::put(tm as u64, 20, avg);
        teb::put(tm as u64, 24, max);
        teb::put(tm as u64, 28, if matches!(k, FontKind::SansBold) { 700i32 } else { 400 });
    }
    TRUE
}

extern "win64" fn GetTextMetricsW(dc: u64, tm: *mut u8) -> Bool {
    GetTextMetricsA(dc, tm)
}

fn dc_set<R>(dc: u64, f: impl FnOnce(&mut Dc) -> R) -> Option<R> {
    with(|g| g.dcs.get_mut(&dc).map(f))
}

extern "win64" fn SetTextColor(dc: u64, c: u32) -> u32 {
    dc_set(dc, |d| to_colorref(core::mem::replace(&mut d.text, colorref(c)))).unwrap_or(0xFFFF_FFFF)
}

extern "win64" fn SetBkColor(dc: u64, c: u32) -> u32 {
    dc_set(dc, |d| to_colorref(core::mem::replace(&mut d.bk, colorref(c)))).unwrap_or(0xFFFF_FFFF)
}

extern "win64" fn SetBkMode(dc: u64, mode: i32) -> i32 {
    dc_set(dc, |d| {
        let old = if d.opaque { 2 } else { 1 };
        d.opaque = mode == 2;
        old
    })
    .unwrap_or(0)
}

extern "win64" fn CreateSolidBrush(c: u32) -> u64 {
    with(|g| {
        let h = g.handle();
        g.gdi.insert(h, Gdi::Brush(colorref(c)));
        h
    })
}

extern "win64" fn CreatePen(style: i32, width: i32, c: u32) -> u64 {
    with(|g| {
        let h = g.handle();
        g.gdi.insert(h, if style == 5 { Gdi::NullPen } else { Gdi::Pen(colorref(c), width.max(1) as u32) });
        h
    })
}

fn create_font(height: i32, weight: i32, pitch: u32, face: Option<String>) -> u64 {
    let fixed = pitch & 0x3 == 1
        || pitch & 0xF0 == 0x30
        || face.as_deref().is_some_and(|f| {
            let f = f.to_ascii_lowercase();
            f.contains("consol") || f.contains("courier") || f.contains("mono")
        });
    let kind = if fixed {
        FontKind::Mono
    } else if height.unsigned_abs() >= 20 {
        FontKind::Large
    } else if weight >= 600 {
        FontKind::SansBold
    } else {
        FontKind::Sans
    };
    with(|g| {
        let h = g.handle();
        g.gdi.insert(h, Gdi::Font(kind));
        h
    })
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn CreateFontA(
    h: i32,
    _w: i32,
    _esc: i32,
    _or: i32,
    weight: i32,
    _it: u32,
    _ul: u32,
    _so: u32,
    _cs: u32,
    _op: u32,
    _cp: u32,
    _q: u32,
    pitch: u32,
    face: *const u8,
) -> u64 {
    // SAFETY: NULL or a NUL-terminated face name.
    create_font(h, weight, pitch, unsafe { path::ansi_to_string(face) })
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn CreateFontW(
    h: i32,
    _w: i32,
    _esc: i32,
    _or: i32,
    weight: i32,
    _it: u32,
    _ul: u32,
    _so: u32,
    _cs: u32,
    _op: u32,
    _cp: u32,
    _q: u32,
    pitch: u32,
    face: *const u16,
) -> u64 {
    // SAFETY: as above.
    create_font(h, weight, pitch, unsafe { path::wide_to_string(face) })
}

/// LOGFONTW: lfHeight @0, lfWeight @16, lfPitchAndFamily @27, lfFaceName @28.
extern "win64" fn CreateFontIndirectW(lf: *const u8) -> u64 {
    if lf.is_null() {
        return 0;
    }
    // SAFETY: the caller's LOGFONTW.
    unsafe {
        create_font(
            teb::get(lf as u64, 0),
            teb::get(lf as u64, 16),
            teb::get::<u8>(lf as u64, 27) as u32,
            path::wide_to_string(lf.add(28) as *const u16),
        )
    }
}

extern "win64" fn GetStockObject(i: i32) -> u64 {
    if with(|g| g.gdi.contains_key(&(STOCK_BASE + i as u64))) {
        STOCK_BASE + i as u64
    } else {
        0
    }
}

extern "win64" fn SelectObject(dc: u64, obj: u64) -> u64 {
    with(|g| {
        let kind = g.gdi.get(&obj).copied();
        let d = g.dcs.get_mut(&dc)?;
        Some(match kind? {
            Gdi::Brush(_) | Gdi::NullBrush => core::mem::replace(&mut d.brush, obj),
            Gdi::Pen(..) | Gdi::NullPen => core::mem::replace(&mut d.pen, obj),
            Gdi::Font(_) => core::mem::replace(&mut d.font, obj),
            Gdi::Bitmap if d.memory => {
                if obj != STOCK_BASE + 21 && g.dcs.iter().any(|(&h, d)| h != dc && d.bitmap == obj) {
                    return None;
                }
                let d = g.dcs.get_mut(&dc)?;
                core::mem::replace(&mut d.bitmap, obj)
            }
            _ => return None,
        })
    })
    .unwrap_or(0)
}

extern "win64" fn DeleteObject(obj: u64) -> Bool {
    if (STOCK_BASE..STOCK_BASE + 32).contains(&obj) {
        return TRUE; // stock objects are never deleted
    }
    with(|g| {
        if g.dcs.values().any(|d| d.bitmap == obj || d.saved.iter().any(|s| s.bitmap == obj)) {
            return false;
        }
        if let Some(b) = g.bitmaps.remove(&obj) {
            g.recycle_bitmap_storage(b.into_storage());
        }
        g.regions.remove(&obj);
        g.gdi.remove(&obj).is_some()
    }) as Bool
}

extern "win64" fn MoveToEx(dc: u64, x: i32, y: i32, old: *mut i32) -> Bool {
    dc_set(dc, |d| {
        if !old.is_null() {
            // SAFETY: the caller's POINT.
            unsafe {
                *old = d.pos.0;
                *old.add(1) = d.pos.1;
            }
        }
        d.pos = (x, y);
        if d.path.active {
            d.path.move_to(d.transform.point(x, y));
        }
    })
    .is_some() as Bool
}

extern "win64" fn LineTo(dc: u64, x: i32, y: i32) -> Bool {
    if dc_set(dc, |d| {
        if !d.path.active {
            return false;
        }
        d.path.line_to(d.transform.point(x, y));
        d.pos = (x, y);
        true
    })
    .unwrap_or(false)
    {
        return TRUE;
    }
    let r = draw(dc, |s, d, gdi, clip| {
        let (x0, y0) = d.transform.point(d.pos.0, d.pos.1);
        let (x, y) = d.transform.point(x, y);
        let touched = Rect::new(x0.min(x), y0.min(y), (x0 - x).unsigned_abs() + 1, (y0 - y).unsigned_abs() + 1);
        if let Some(Gdi::Pen(c, width)) = gdi.get(&d.pen) {
            for o in 0..*width as i32 {
                line_clipped(
                    s,
                    x0 + o * (y0 != y) as i32,
                    y0 + o * (y0 == y) as i32,
                    x + o * (y0 != y) as i32,
                    y + o * (y0 == y) as i32,
                    *c,
                    clip,
                );
            }
        }
        ((), touched)
    });
    dc_set(dc, |d| d.pos = (x, y));
    r.is_some() as Bool
}

fn line_clipped(s: &mut Surface, x0: i32, y0: i32, x1: i32, y1: i32, c: Color, clip: Rect) {
    // Bresenham with per-pixel clipping.
    let (dx, dy) = ((x1 - x0).abs(), -(y1 - y0).abs());
    let (sx, sy) = (if x0 < x1 { 1 } else { -1 }, if y0 < y1 { 1 } else { -1 });
    let (mut x, mut y, mut e) = (x0, y0, dx + dy);
    loop {
        if x >= clip.x && y >= clip.y && x < clip.x + clip.w as i32 && y < clip.y + clip.h as i32 {
            s.put(x, y, c);
        }
        if x == x1 && y == y1 {
            break;
        }
        let e2 = 2 * e;
        if e2 >= dy {
            e += dy;
            x += sx;
        }
        if e2 <= dx {
            e += dx;
            y += sy;
        }
    }
}

extern "win64" fn Rectangle(dc: u64, l: i32, t: i32, r: i32, b: i32) -> Bool {
    if dc_set(dc, |d| {
        if !d.path.active {
            return false;
        }
        d.path.rect(d.transform.rect((l, t, r, b)));
        true
    })
    .unwrap_or(false)
    {
        return TRUE;
    }
    let rect = Rect::new(l, t, (r - l).max(0) as u32, (b - t).max(0) as u32);
    draw(dc, |s, d, gdi, clip| {
        let rect = d.transform.rect((rect.x, rect.y, rect.x + rect.w as i32, rect.y + rect.h as i32));
        let (l, t, r, b) = (rect.x, rect.y, rect.x + rect.w as i32, rect.y + rect.h as i32);
        if let Some(c) = brush_color(gdi, d.brush) {
            s.fill_rect(rect.intersect(&clip), c);
        }
        if let Some(Gdi::Pen(c, _)) = gdi.get(&d.pen) {
            for e in [
                Rect::new(l, t, rect.w, 1),
                Rect::new(l, b - 1, rect.w, 1),
                Rect::new(l, t, 1, rect.h),
                Rect::new(r - 1, t, 1, rect.h),
            ] {
                s.fill_rect(e.intersect(&clip), *c);
            }
        }
        (TRUE, rect)
    })
    .unwrap_or(FALSE)
}

extern "win64" fn RoundRect(dc: u64, l: i32, t: i32, r: i32, b: i32, w: i32, _h: i32) -> Bool {
    let rect = Rect::new(l, t, (r - l).max(0) as u32, (b - t).max(0) as u32);
    draw(dc, |s, d, gdi, clip| {
        if let Some(c) = brush_color(gdi, d.brush) {
            if clip.intersect(&rect) == rect {
                s.rounded_rect(rect, (w / 2).max(0) as u32, c, 255);
            } else {
                s.fill_rect(rect.intersect(&clip), c);
            }
        }
        (TRUE, rect)
    })
    .unwrap_or(FALSE)
}

extern "win64" fn SetPixel(dc: u64, x: i32, y: i32, c: u32) -> u32 {
    let mut written=false;
    let result=draw(dc, |s, d, _, clip| {
        let (x, y) = d.transform.point(x, y);
        if x >= clip.x && y >= clip.y && x < clip.x + clip.w as i32 && y < clip.y + clip.h as i32 {
            s.put(x, y, colorref(c));
            written=true;
        }
        ((), Rect::new(x, y, 1, 1))
    });
    if result.is_some() && written { c } else { 0xffff_ffff }
}

/// A PRISM dialog implementing MB_OK and MB_OKCANCEL. Other button sets
/// fail explicitly; Escape/close cancel a dialog that offers Cancel.
fn message_box(owner: u64, text: String, caption: String, flags: u32) -> i32 {
    let cancel = match flags & 15 { 0 => false, 1 => true, _ => return fail(ERROR_NOT_SUPPORTED, 0) };
    let _ = owner;
    let lines: Vec<&str> = text.split('\n').collect();
    let k = FontKind::Sans;
    let width = (lines.iter().map(|l| measure(k, l)).max().unwrap_or(100) + 48).clamp(260, 900);
    let height = 70 + line_height(k) * lines.len() as u32 + 40;
    let made = with(|g| -> Option<Window> {
        let mut spec = WindowSpec::normal(&caption, width, height);
        spec.flags = proto::window_flags::DECORATED;
        spec.min_width = width;
        spec.min_height = height;
        g.conn().ok()?.create_window(spec).ok()
    });
    let Some(mut win) = made else { return fail(ERROR_NOT_SUPPORTED, 0) };
    let mut drawn = false;
    let button = Rect::new(width as i32 - if cancel { 200 } else { 104 }, height as i32 - 44, 88, 30);
    let cancel_button = Rect::new(width as i32 - 104, height as i32 - 44, 88, 30);
    let mut result = 1;
    loop {
        let evs: Vec<Event> = with(|g| {
            let mut v = Vec::new();
            if let Some(c) = g.conn.as_mut() {
                let _ = c.wait(&mut [], Some(Duration::from_millis(100)));
                while let Ok(Some(e)) = c.poll() {
                    v.push(e);
                }
            }
            v
        });
        let mut done = false;
        let mut other = Vec::new();
        for ev in evs {
            if !win.on_event(&ev) {
                other.push(ev);
                continue;
            }
            match ev {
                Event::CloseRequest { .. } => { result = if cancel { 2 } else { 1 }; done = true; },
                Event::Key { usage, state, .. }
                    if state == proto::key_state::DOWN && (usage == 0x28 || usage == 0x29 || usage == 0x58) =>
                {
                    result = if cancel && usage == 0x29 { 2 } else { 1 };
                    done = true
                }
                Event::Pointer { kind, x, y, pressed, .. }
                    if kind == proto::pointer::BUTTON
                        && pressed
                        && x >= button.x
                        && y >= button.y
                        && x < button.x + 88
                        && y < button.y + 30 =>
                {
                    done = true
                }
                Event::Pointer { kind, x, y, pressed, .. }
                    if cancel && kind == proto::pointer::BUTTON && pressed
                        && x >= cancel_button.x && y >= cancel_button.y
                        && x < cancel_button.x + 88 && y < cancel_button.y + 30 =>
                { result = 2; done = true; }
                _ => {}
            }
        }
        with(|g| {
            for e in other {
                g.on_event(e);
            }
        });
        if done {
            break;
        }
        if !drawn && win.can_draw() {
            if let Ok(mut s) = win.surface() {
                s.fill(rgb(243, 243, 243));
                let lh = line_height(k) as i32;
                for (i, l) in lines.iter().enumerate() {
                    draw_text(&mut s, k, 24, 24 + i as i32 * lh, l, rgb(20, 20, 20), Rect::new(0, 0, width, height));
                }
                s.fill_rect(Rect::new(0, height as i32 - 60, width, 60), rgb(230, 230, 230));
                s.rounded_rect(button, 4, rgb(0, 95, 184), 255);
                if cancel {
                    s.rounded_rect(cancel_button, 4, rgb(210, 210, 210), 255);
                    draw_text(&mut s, k, cancel_button.x + 20, cancel_button.y + 6, "Cancel", rgb(20,20,20), cancel_button);
                }
                let tw = measure(k, "OK") as i32;
                draw_text(
                    &mut s,
                    k,
                    button.x + (88 - tw) / 2,
                    button.y + (30 - lh) / 2,
                    "OK",
                    rgb(255, 255, 255),
                    button,
                );
            }
            with(|g| {
                if let Some(c) = g.conn.as_mut() {
                    let _ = win.present(c, None);
                }
            });
            drawn = true;
        }
    }
    with(|g| {
        if let Some(c) = g.conn.as_mut() {
            let _ = win.destroy(c);
        }
    });
    result
}

extern "win64" fn MessageBoxA(owner: u64, text: *const u8, caption: *const u8, flags: u32) -> i32 {
    // SAFETY: NUL-terminated strings (or NULL).
    let (t, c) = unsafe { (path::ansi_to_string(text), path::ansi_to_string(caption)) };
    message_box(owner, t.unwrap_or_default(), c.unwrap_or_else(|| String::from("Error")), flags)
}

extern "win64" fn MessageBoxW(owner: u64, text: *const u16, caption: *const u16, flags: u32) -> i32 {
    // SAFETY: as above.
    let (t, c) = unsafe { (path::wide_to_string(text), path::wide_to_string(caption)) };
    message_box(owner, t.unwrap_or_default(), c.unwrap_or_else(|| String::from("Error")), flags)
}

// ---- window geometry, caret, queries, monitors ---------------------------------------------

/// A RECT as Windows lays it out: four LONGs.
type Rect4 = (i32, i32, i32, i32);

fn rect_at(p: *const u8) -> Rect4 {
    // SAFETY: the caller's RECT (16 bytes).
    unsafe { (teb::get(p as u64, 0), teb::get(p as u64, 4), teb::get(p as u64, 8), teb::get(p as u64, 12)) }
}

fn put_rect(p: *mut u8, r: Rect4) {
    // SAFETY: the caller's RECT (16 bytes).
    unsafe {
        teb::put(p as u64, 0, r.0);
        teb::put(p as u64, 4, r.1);
        teb::put(p as u64, 8, r.2);
        teb::put(p as u64, 12, r.3);
    }
}

fn empty(r: Rect4) -> bool {
    r.2 <= r.0 || r.3 <= r.1
}

extern "win64" fn EqualRect(a: *const u8, b: *const u8) -> Bool {
    if a.is_null() || b.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    (rect_at(a) == rect_at(b)) as Bool
}

extern "win64" fn InflateRect(p: *mut u8, dx: i32, dy: i32) -> Bool {
    if p.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let (l, t, r, b) = rect_at(p);
    put_rect(p, (l - dx, t - dy, r + dx, b + dy));
    TRUE
}

extern "win64" fn OffsetRect(p: *mut u8, dx: i32, dy: i32) -> Bool {
    if p.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let (l, t, r, b) = rect_at(p);
    put_rect(p, (l + dx, t + dy, r + dx, b + dy));
    TRUE
}

extern "win64" fn IntersectRect(dst: *mut u8, a: *const u8, b: *const u8) -> Bool {
    if dst.is_null() || a.is_null() || b.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let (al, at, ar, ab) = rect_at(a);
    let (bl, bt, br, bb) = rect_at(b);
    let r = (al.max(bl), at.max(bt), ar.min(br), ab.min(bb));
    put_rect(dst, r);
    (!empty(r)) as Bool
}

extern "win64" fn IsRectEmpty(p: *const u8) -> Bool {
    if p.is_null() {
        return TRUE;
    }
    empty(rect_at(p)) as Bool
}

/// `PtInRect`: the POINT travels in one register, x in the low half.
extern "win64" fn PtInRect(p: *const u8, point: u64) -> Bool {
    if p.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let (l, t, r, b) = rect_at(p);
    let x = point as u32 as i32;
    let y = (point >> 32) as u32 as i32;
    (x >= l && x < r && y >= t && y < b) as Bool
}

extern "win64" fn SetRect(p: *mut u8, l: i32, t: i32, r: i32, b: i32) -> Bool {
    if p.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    put_rect(p, (l, t, r, b));
    TRUE
}

extern "win64" fn SetRectEmpty(p: *mut u8) -> Bool {
    if p.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    put_rect(p, (0, 0, 0, 0));
    TRUE
}

/// The caret blinks at Windows' default rate: 530 ms.
extern "win64" fn GetCaretBlinkTime() -> u32 {
    530
}

extern "win64" fn GetDoubleClickTime() -> u32 {
    500
}

/// The caret is drawn by the program into its own window; the runtime only
/// keeps Windows' bookkeeping answers.
extern "win64" fn CreateCaret(_wnd: u64, _bitmap: u64, _w: i32, _h: i32) -> Bool {
    TRUE
}

extern "win64" fn DestroyCaret() -> Bool {
    TRUE
}

extern "win64" fn ShowCaret(_wnd: u64) -> Bool {
    TRUE
}

extern "win64" fn HideCaret(_wnd: u64) -> Bool {
    TRUE
}

extern "win64" fn SetCaretPos(_x: i32, _y: i32) -> Bool {
    TRUE
}

/// One pointer, always visible: PRISM draws it from the pointer position.
extern "win64" fn ShowCursor(_show: Bool) -> i32 {
    0
}

/// PRISM owns the pointer, so this only updates what the cursor APIs report.
extern "win64" fn SetCursorPos(x: i32, y: i32) -> Bool {
    with(|g| g.screen_pointer = (x, y));
    TRUE
}

extern "win64" fn ClipCursor(_rect: *const u8) -> Bool {
    TRUE
}

extern "win64" fn GetCursorInfo(out: *mut u8) -> Bool {
    // CURSORINFO: cbSize, flags, hCursor, ptScreenPos.
    if out.is_null() || unsafe { teb::get::<u32>(out as u64, 0) } < 20 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let (x, y) = with(|g| g.screen_pointer);
    // SAFETY: the caller's CURSORINFO of at least 20 bytes.
    unsafe {
        teb::put(out as u64, 4, 1u32); // CURSOR_SHOWING
        teb::put(out as u64, 8, 0x1_0000u64); // the arrow's id, as LoadCursor hands it out
        teb::put(out as u64, 16, x);
        teb::put(out as u64, 20, y);
    }
    TRUE
}

extern "win64" fn GetMessagePos() -> u32 {
    with(|g| ((g.screen_pointer.1 as u32) << 16) | (g.screen_pointer.0 as u32 & 0xffff))
}

extern "win64" fn GetMessageTime() -> i32 {
    with(|g| g.now_ms() as i32)
}

extern "win64" fn GetMessageExtraInfo() -> i64 {
    0
}

/// High word: kinds of messages waiting; low word: kinds added since the
/// last GetQueueStatus, GetMessage or PeekMessage.
extern "win64" fn GetQueueStatus(flags: u32) -> u32 {
    diag(|d| d.qstatus += 1);
    dispatch_pending_frames();
    with(|g| {
        let now = g.status() & flags;
        let new = g.fresh_bits() & now;
        let left = g.fresh_bits() & !flags;
        g.set_fresh(left);
        (now << 16) | new
    })
}

/// Waits for objects or for messages of `mask`'s kinds. Without
/// MWMO_INPUTAVAILABLE only messages queued since the thread last looked
/// count, as on Windows. Returns WAIT_OBJECT_0 + n for input.
extern "win64" fn MsgWaitForMultipleObjectsEx(n: u32, hs: *const u64, ms: u32, mask: u32, flags: u32) -> u32 {
    use crate::objects::{INFINITE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    diag(|d| {
        d.msgwait += 1;
        d.msgwait_masks.add(mask as u64);
    });
    if n > 63 || (n > 0 && hs.is_null()) {
        return fail(ERROR_INVALID_PARAMETER, WAIT_FAILED);
    }
    let list: &[u64] = if n == 0 {
        &[]
    } else {
        // SAFETY: the caller's array of `n` handles.
        unsafe { core::slice::from_raw_parts(hs, n as usize) }
    };
    let all = flags & MWMO_WAITALL != 0;
    let deadline = (ms != INFINITE).then(|| Instant::now() + Duration::from_millis(ms as u64));
    static ITERS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    loop {
        dispatch_pending_frames();
        let (seq, input, timer, st) = with(|g| {
            let have = if flags & MWMO_INPUTAVAILABLE != 0 { g.status() } else { g.fresh_bits() & g.status() };
            IDLE_WAITERS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let seq = crate::objects::sequence();
            (seq, have & mask != 0, g.next_timer_in(0, 0, 0, mask), have)
        });
        let _idle = IdleGuard;
        let it = ITERS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if crate::COUNT.load(core::sync::atomic::Ordering::Relaxed) && it.is_multiple_of(10_000) {
            os_std::eprintln!(
                "winrun: msgwait it={it} ms={ms} mask={mask:#x} flags={flags:#x} input={input} have={st:#x} timer={timer:?}"
            );
        }
        // With MWMO_WAITALL the objects count only together with input.
        if !list.is_empty() && (!all || input) {
            match crate::objects::wait(list, all, 0) {
                Ok(WAIT_TIMEOUT) => {}
                Ok(r) if all => return r.min(WAIT_OBJECT_0 + n),
                Ok(r) => return r,
                Err(e) => return fail(e, WAIT_FAILED),
            }
        }
        if input && (!all || list.is_empty()) {
            diag(|d| d.msgwait_input += 1);
            return WAIT_OBJECT_0 + n;
        }
        let left = match deadline {
            Some(d) => match d.checked_duration_since(Instant::now()) {
                Some(l) if !l.is_zero() => l,
                _ => {
                    diag(|d| d.msgwait_timeout += 1);
                    return WAIT_TIMEOUT;
                }
            },
            None => Duration::from_secs(3600),
        };
        crate::winsta::note_idle();
        idle(seq, left.min(timer));
    }
}

extern "win64" fn MsgWaitForMultipleObjects(n: u32, hs: *const u64, wait_all: Bool, ms: u32, mask: u32) -> u32 {
    MsgWaitForMultipleObjectsEx(n, hs, ms, mask, if wait_all != 0 { MWMO_WAITALL } else { 0 })
}

extern "win64" fn ReplyMessage(_result: i64) -> Bool {
    TRUE
}

/// OSyx never delivers a message from another process's SendMessage in a way
/// the receiver could answer, so every thread is outside a send.
extern "win64" fn InSendMessage() -> Bool {
    FALSE
}

extern "win64" fn InSendMessageEx(_reserved: u64) -> u32 {
    0 // ISMEX_NOSEND
}

extern "win64" fn CallNextHookEx(_hook: u64, _code: i32, _w: u64, _l: i64) -> i64 {
    0
}

extern "win64" fn SetWinEventHook(_min: u32, _max: u32, _module: u64, _proc_: u64, _process: u32, _thread: u32, _flags: u32) -> u64 {
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
        os_std::eprintln!("winrun: SetWinEventHook min={_min:#x} max={_max:#x} pid={_process} tid={_thread} flags={_flags:#x}");
    }
    0 // no accessibility events are raised
}

extern "win64" fn UnhookWinEvent(_hook: u64) -> Bool {
    TRUE
}

extern "win64" fn NotifyWinEvent(_event: u32, _wnd: u64, _object: i32, _child: i32) {}

extern "win64" fn SetWindowsHookExW(_id: i32, _proc_: u64, _module: u64, _thread: u32) -> u64 {
    0 // no hooks are installed or called
}

extern "win64" fn UnhookWindowsHookEx(_hook: u64) -> Bool {
    TRUE
}

extern "win64" fn GetPropW(_wnd: u64, _name: *const u16) -> u64 {
    0
}

extern "win64" fn SetPropW(_wnd: u64, _name: *const u16, _data: u64) -> Bool {
    TRUE
}

extern "win64" fn RemovePropW(_wnd: u64, _name: *const u16) -> u64 {
    0
}

extern "win64" fn GetParent(wnd: u64) -> u64 {
    with(|g| g.windows.get(&wnd).filter(|w| w.style & 0x80000000 != 0).map_or(0, |w| w.owner))
}

extern "win64" fn GetAncestor(wnd: u64, flags: u32) -> u64 {
    match flags {
        1 => 0, // GA_PARENT: no child controls yet.
        2 => if is_window(wnd) { wnd } else { 0 }, // GA_ROOT
        3 => with(|g| {
            let mut root = wnd;
            for _ in 0..g.windows.len() {
                let Some(w) = g.windows.get(&root) else { return 0 };
                if !g.windows.contains_key(&w.owner) { return root; }
                root = w.owner;
            }
            root
        }),
        _ => 0,
    }
}

extern "win64" fn IsChild(_parent: u64, _wnd: u64) -> Bool {
    FALSE
}

extern "win64" fn GetWindow(wnd: u64, cmd: u32) -> u64 {
    if cmd == 4 { // GW_OWNER
        with(|g| g.windows.get(&wnd).map_or(0, |w| if w.owner != wnd && g.windows.contains_key(&w.owner) { w.owner } else { 0 }))
    } else { 0 }
}

extern "win64" fn GetTopWindow(_wnd: u64) -> u64 {
    0
}

extern "win64" fn SetParent(wnd: u64, _parent: u64) -> u64 {
    wnd
}

extern "win64" fn SetForegroundWindow(_wnd: u64) -> Bool {
    TRUE
}

extern "win64" fn GetForegroundWindow() -> u64 {
    with(|g| g.focus)
}

extern "win64" fn BringWindowToTop(_wnd: u64) -> Bool {
    TRUE
}

extern "win64" fn IsIconic(wnd: u64) -> Bool {
    with(|g| g.windows.get(&wnd).is_some_and(|w| w.style & WS_MINIMIZE != 0)) as Bool
}

extern "win64" fn IsZoomed(wnd: u64) -> Bool {
    with(|g| g.windows.get(&wnd).is_some_and(|w| w.style & WS_MAXIMIZE != 0)) as Bool
}

extern "win64" fn IsWindowArranged(wnd: u64) -> Bool {
    // PRISM exposes normal, maximized and minimized windows, but no Snap
    // arrangement. Maximization is explicitly distinct from arrangement.
    if !is_window(wnd) { return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE); }
    FALSE
}

extern "win64" fn IsWindowEnabled(wnd: u64) -> Bool {
    (with(|g| g.windows.get(&wnd).is_some_and(|w| w.style & 0x08000000 == 0))) as Bool
}

extern "win64" fn EnableWindow(wnd: u64, enable: Bool) -> Bool {
    with(|g| {
        let Some(w) = g.windows.get_mut(&wnd) else { return FALSE };
        let disabled = w.style & 0x08000000 != 0;
        if enable != 0 { w.style &= !0x08000000; } else { w.style |= 0x08000000; }
        disabled as Bool
    })
}

extern "win64" fn GetWindowThreadProcessId(wnd: u64, pid_out: *mut u32) -> u32 {
    let thread = with(|g| g.windows.get(&wnd).map_or(0, |w| w.thread as u32));
    if !pid_out.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *pid_out = if thread != 0 { crate::kernel32::pid() as u32 } else { 0 } };
    }
    thread
}

extern "win64" fn GetClassNameW(wnd: u64, buf: *mut u16, size: i32) -> i32 {
    if buf.is_null() || size <= 0 {
        return 0;
    }
    let name = with(|g| g.windows.get(&wnd).and_then(|w| g.classes.get(w.class)).map(|c| c.name.clone()));
    match name {
        Some(n) => {
            let units: Vec<u16> = n.encode_utf16().collect();
            let n = units.len().min(size as usize - 1);
            // SAFETY: the caller's buffer of `size` units.
            unsafe {
                core::ptr::copy_nonoverlapping(units.as_ptr(), buf, n);
                *buf.add(n) = 0;
            }
            n as i32
        }
        None => 0,
    }
}

// ---- monitors ------------------------------------------------------------------------------

fn screen_rect() -> Rect4 {
    let (w, h) = with(|g| g.conn().map(|c| (c.screen_width as i32, c.screen_height as i32)).unwrap_or((1024, 768)));
    (0, 0, w, h)
}

/// MONITOR_DEFAULTTONULL is 0: a rectangle that touches nothing then has no
/// monitor. OSyx has one screen, so everything else belongs to it.
fn monitor_from(r: Rect4, flags: u32) -> u64 {
    if !empty(r) {
        let s = screen_rect();
        if r.0 < s.2 && r.2 > s.0 && r.1 < s.3 && r.3 > s.1 {
            return crate::minordlls::PRIMARY_MONITOR;
        }
    }
    if flags == 0 {
        0
    } else {
        crate::minordlls::PRIMARY_MONITOR
    }
}

extern "win64" fn MonitorFromPoint(point: u64, flags: u32) -> u64 {
    let x = point as u32 as i32;
    let y = (point >> 32) as u32 as i32;
    monitor_from((x, y, x + 1, y + 1), flags)
}

extern "win64" fn MonitorFromRect(rect: *const u8, flags: u32) -> u64 {
    if rect.is_null() {
        return crate::minordlls::PRIMARY_MONITOR;
    }
    monitor_from(rect_at(rect), flags)
}

extern "win64" fn MonitorFromWindow(wnd: u64, flags: u32) -> u64 {
    let r = with(|g| g.windows.get(&wnd).map(|w| (w.pos.0, w.pos.1, w.pos.0 + w.size.0 as i32, w.pos.1 + w.size.1 as i32)));
    match r {
        Some(r) => monitor_from(r, flags),
        None => crate::minordlls::PRIMARY_MONITOR,
    }
}

extern "win64" fn GetMonitorInfoW(monitor: u64, out: *mut u8) -> Bool {
    monitor_info(monitor, out, true)
}

fn monitor_info(monitor: u64, out: *mut u8, wide: bool) -> Bool {
    if monitor != crate::minordlls::PRIMARY_MONITOR || out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    // MONITORINFO is 40 bytes; MONITORINFOEX adds 32 TCHARs naming the
    // adapter. Screen enumeration uses this name with CreateDC.
    let size = unsafe { teb::get::<u32>(out as u64, 0) };
    let extended = if wide { 104 } else { 72 };
    if size != 40 && size != extended { return fail(ERROR_INVALID_PARAMETER, FALSE); }
    let s = screen_rect();
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
        static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        if N.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 12 {
            os_std::eprintln!("winrun: monitorinfo size={size} rect={s:?}");
        }
    }
    // MONITORINFO: cbSize, rcMonitor, rcWork, dwFlags.
    // SAFETY: the caller's MONITORINFO of at least 40 bytes.
    unsafe {
        put_rect(out.add(4), s);
        put_rect(out.add(20), s);
        teb::put(out as u64, 36, 1u32); // MONITORINFOF_PRIMARY
        if size == extended {
            core::ptr::write_bytes(out.add(40), 0, (extended - 40) as usize);
            if wide {
                put_wide(out.add(40), 32, DISPLAY_NAME);
            } else {
                core::ptr::copy_nonoverlapping(DISPLAY_NAME.as_ptr(), out.add(40), DISPLAY_NAME.len());
            }
        }
    }
    TRUE
}

extern "win64" fn GetMonitorInfoA(monitor: u64, out: *mut u8) -> Bool {
    monitor_info(monitor, out, false)
}

/// Messages a program registers by name: the same name gets the same id for
/// the life of the process, in the range Windows uses for them.
static REGISTERED_MESSAGES: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// The id Gecko registered for `nsAppShell:EventID` (its message-loop wakeup).
static WAKEUP_MSG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn wake_msg() -> u32 {
    WAKEUP_MSG.load(core::sync::atomic::Ordering::Relaxed)
}

/// Id of the registered name `text`, registering it on first use.
fn registered_id(text: &str) -> u32 {
    const BASE: u32 = 0xC000;
    let mut list = REGISTERED_MESSAGES.lock().unwrap();
    let id = match list.iter().position(|n| n.eq_ignore_ascii_case(text)) {
        Some(i) => BASE + i as u32,
        None => {
            let id = BASE + list.len() as u32;
            if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) {
                os_std::eprintln!("winrun: register id={id:#x} name={text} tid={}", os_sys::gettid());
            }
            list.push(text.to_string());
            id
        }
    };
    if text.to_ascii_lowercase().contains("eventid") {
        WAKEUP_MSG.store(id, core::sync::atomic::Ordering::Relaxed);
    }
    id
}

/// The registered name of `format`, if it is a registered one.
fn registered_name(format: u32) -> Option<String> {
    REGISTERED_MESSAGES.lock().unwrap().get(format.checked_sub(0xC000)? as usize).cloned()
}

extern "win64" fn RegisterWindowMessageW(name: *const u16) -> u32 {
    if name.is_null() {
        return 0;
    }
    // SAFETY: a NUL-terminated string from the caller.
    let Some(text) = (unsafe { path::wide_to_string(name) }) else { return 0 };
    registered_id(&text)
}

// ---- window classes, enumeration and the small window API ----------------------------------

fn wide(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut s = String::new();
    let mut i = 0;
    // SAFETY: a NUL-terminated string from the caller.
    loop {
        let c = unsafe { *p.add(i) };
        if c == 0 {
            return Some(s);
        }
        s.push(char::from_u32(c as u32).unwrap_or('\u{fffd}'));
        i += 1;
    }
}

extern "win64" fn GetClassInfoW(_inst: u64, name: *const u16, out: *mut u8) -> Bool {
    let Some(want) = wide(name) else { return fail(ERROR_INVALID_PARAMETER, FALSE) };
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let found = with(|g| {
        g.classes
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(&want))
            .map(|c| (c.wndproc, c.background, c.style))
    });
    let Some((wndproc, background, style)) = found else { return fail(ERROR_CANNOT_FIND_WND_CLASS, FALSE) };
    // WNDCLASSW (72 bytes): style, wndproc, cbClsExtra, cbWndExtra, instance,
    // icon, cursor, background, menu name, class name. The string pointers are
    // left null: the names live in this runtime, not in the caller's memory.
    // SAFETY: the caller's WNDCLASSW.
    unsafe {
        core::ptr::write_bytes(out, 0, 72);
        teb::put(out as u64, 0, style);
        teb::put(out as u64, 8, wndproc);
        teb::put(out as u64, 48, background);
    }
    TRUE
}

extern "win64" fn GetClassInfoA(inst: u64, name: *const u8, out: *mut u8) -> Bool {
    // The class names are ASCII in practice; widen the caller's name.
    if name.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let mut units = Vec::new();
    let mut i = 0;
    // SAFETY: a NUL-terminated string from the caller.
    loop {
        let c = unsafe { *name.add(i) };
        units.push(c as u16);
        if c == 0 {
            break;
        }
        i += 1;
    }
    GetClassInfoW(inst, units.as_ptr(), out)
}

extern "win64" fn UnregisterClassW(name: *const u16, _inst: u64) -> Bool {
    if wide(name).is_none() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    TRUE // the class table lives as long as the process
}

extern "win64" fn GetClassLongPtrW(_wnd: u64, _index: i32) -> u64 {
    0
}

extern "win64" fn SetClassLongPtrW(_wnd: u64, _index: i32, _value: u64) -> u64 {
    0
}

extern "win64" fn GetClassWord(_wnd: u64, _index: i32) -> u16 {
    0
}

extern "win64" fn FindWindowW(class: *const u16, title: *const u16) -> u64 {
    let (c, t) = (wide(class), wide(title));
    with(|g| {
        g.windows
            .iter()
            .find(|(_, w)| {
                let class_ok = c.as_ref().is_none_or(|want| g.classes.get(w.class).is_some_and(|k| k.name.eq_ignore_ascii_case(want)));
                let title_ok = t.as_ref().is_none_or(|want| w.title == *want);
                class_ok && title_ok
            })
            .map(|(h, _)| *h)
            .unwrap_or(0)
    })
}

extern "win64" fn FindWindowExW(_parent: u64, _after: u64, class: *const u16, title: *const u16) -> u64 {
    FindWindowW(class, title)
}

// ---- displays ----------------------------------------------------------------------------

const DISPLAY_NAME: &str = r"\\.\DISPLAY1";

fn put_wide(p: *mut u8, max_chars: usize, s: &str) {
    for (i, c) in s.encode_utf16().chain(core::iter::once(0)).take(max_chars).enumerate() {
        // SAFETY: the caller's field of `max_chars` WCHARs.
        unsafe { teb::put(p as u64, i * 2, c) };
    }
}

/// DISPLAY_DEVICEW (840 bytes): the one PRISM display adapter, and below it
/// the one monitor.
extern "win64" fn EnumDisplayDevicesW(device: *const u16, index: u32, out: *mut u8, _flags: u32) -> Bool {
    // SAFETY: the caller's DISPLAY_DEVICEW starts with cb.
    if out.is_null() || unsafe { teb::get::<u32>(out as u64, 0) } < 840 || index != 0 {
        return FALSE;
    }
    // SAFETY: a NUL-terminated device name, or NULL.
    let parent = unsafe { path::wide_to_string(device) };
    let (name, text, flags) = match parent.as_deref() {
        None | Some("") => (String::from(DISPLAY_NAME), "OSyx PRISM display", 0x1 | 0x4), // ATTACHED_TO_DESKTOP | PRIMARY_DEVICE
        Some(p) if p.eq_ignore_ascii_case(DISPLAY_NAME) => (alloc::format!(r"{DISPLAY_NAME}\Monitor0"), "Generic PnP Monitor", 0x1 | 0x2), // ACTIVE | ATTACHED
        _ => return FALSE,
    };
    // SAFETY: the caller's 840-byte DISPLAY_DEVICEW.
    unsafe {
        core::ptr::write_bytes(out.add(4), 0, 836);
        put_wide(out.add(4), 32, &name);
        put_wide(out.add(68), 128, text);
        teb::put(out as u64, 324, flags as u32);
    }
    TRUE
}

const ENUM_CURRENT_SETTINGS: u32 = 0xFFFF_FFFF;
const ENUM_REGISTRY_SETTINGS: u32 = 0xFFFF_FFFE;

/// DEVMODEW (220 bytes) of the display's one mode: the screen at 32 bpp
/// and 60 Hz.
extern "win64" fn EnumDisplaySettingsExW(device: *const u16, mode: u32, out: *mut u8, _flags: u32) -> Bool {
    if out.is_null() || !matches!(mode, ENUM_CURRENT_SETTINGS | ENUM_REGISTRY_SETTINGS | 0) {
        return FALSE;
    }
    // SAFETY: a NUL-terminated device name, or NULL.
    if let Some(d) = unsafe { path::wide_to_string(device) } {
        if !d.is_empty() && !d.eq_ignore_ascii_case(DISPLAY_NAME) {
            return FALSE;
        }
    }
    let (_, _, w, h) = screen_rect();
    // SAFETY: the caller's DEVMODEW: dmSize/dmDriverExtra at 68/70 say how
    // much it is; the public fields fit in 220 bytes.
    unsafe {
        core::ptr::write_bytes(out, 0, 220);
        put_wide(out, 32, "DISPLAY1");
        teb::put(out as u64, 64, 0x0401u16); // dmSpecVersion (DM_SPECVERSION)
        teb::put(out as u64, 68, 220u16); // dmSize
        // DM_POSITION | DM_DISPLAYORIENTATION | DM_BITSPERPEL | DM_PELSWIDTH
        // | DM_PELSHEIGHT | DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY
        teb::put(out as u64, 72, 0x20u32 | 0x80 | 0x4_0000 | 0x8_0000 | 0x10_0000 | 0x20_0000 | 0x40_0000);
        teb::put(out as u64, 166, 96u16); // dmLogPixels
        teb::put(out as u64, 168, 32u32); // dmBitsPerPel
        teb::put(out as u64, 172, w as u32);
        teb::put(out as u64, 176, h as u32);
        teb::put(out as u64, 184, 60u32); // dmDisplayFrequency
    }
    TRUE
}

extern "win64" fn EnumDisplaySettingsW(device: *const u16, mode: u32, out: *mut u8) -> Bool {
    EnumDisplaySettingsExW(device, mode, out, 0)
}

const AR_NOSENSOR: u32 = 0x10;

extern "win64" fn GetAutoRotationState(out: *mut u32) -> Bool {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    // SAFETY: the caller's AR_STATE.
    unsafe { *out = AR_NOSENSOR };
    TRUE
}

/// No touch screen or gesture input exists: registering is accepted and no
/// WM_TOUCH or WM_GESTURE is ever sent.
extern "win64" fn RegisterTouchWindow(hwnd: u64, _flags: u32) -> Bool {
    if is_window(hwnd) { TRUE } else { fail(ERROR_INVALID_WINDOW_HANDLE, FALSE) }
}

extern "win64" fn SetGestureConfig(hwnd: u64, _reserved: u32, _n: u32, _configs: *const u8, _size: u32) -> Bool {
    if is_window(hwnd) { TRUE } else { fail(ERROR_INVALID_WINDOW_HANDLE, FALSE) }
}

/// RAWINPUTDEVICE (16 bytes) registrations are accepted; OSyx delivers
/// input as window messages only, never WM_INPUT.
extern "win64" fn RegisterRawInputDevices(devices: *const u8, n: u32, size: u32) -> Bool {
    if devices.is_null() || n == 0 || size != 16 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    TRUE
}

// ---- clipboard --------------------------------------------------------------------------

extern "win64" fn GetRawInputDeviceList(_list: *mut u8, num_devices: *mut u32, size: u32) -> u32 {
    if num_devices.is_null() || size != 16 {
        return fail(ERROR_INVALID_PARAMETER, u32::MAX);
    }
    unsafe { *num_devices = 0 };
    0
}

extern "win64" fn GetRawInputDeviceInfoA(_device: u64, _cmd: u32, _data: *mut u8, _size: *mut u32) -> u32 {
    fail(ERROR_INVALID_HANDLE, u32::MAX)
}

extern "win64" fn GetRawInputDeviceInfoW(_device: u64, _cmd: u32, _data: *mut u8, _size: *mut u32) -> u32 {
    fail(ERROR_INVALID_HANDLE, u32::MAX)
}

extern "win64" fn GetRawInputData(_raw_input: u64, _cmd: u32, _data: *mut u8, _size: *mut u32, size_header: u32) -> u32 {
    fail(if size_header != 24 { ERROR_INVALID_PARAMETER } else { ERROR_INVALID_HANDLE }, u32::MAX)
}

extern "win64" fn GetTouchInputInfo(_handle: u64, _inputs: u32, _data: *mut u8, _size: i32) -> Bool {
    fail(ERROR_INVALID_HANDLE, FALSE)
}

extern "win64" fn CloseTouchInputHandle(_handle: u64) -> Bool {
    fail(ERROR_INVALID_HANDLE, FALSE)
}

extern "win64" fn GetGestureInfo(_handle: u64, _info: *mut u8) -> Bool {
    fail(ERROR_INVALID_HANDLE, FALSE)
}

extern "win64" fn CloseGestureInfoHandle(_handle: u64) -> Bool {
    fail(ERROR_INVALID_HANDLE, FALSE)
}

extern "win64" fn GetPointerType(_pointer_id: u32, _pointer_type: *mut u32) -> Bool {
    fail(ERROR_INVALID_PARAMETER, FALSE)
}

extern "win64" fn GetPointerFrameTouchInfo(_pointer_id: u32, _pointer_count: *mut u32, _touch_info: *mut u8) -> Bool {
    fail(ERROR_INVALID_PARAMETER, FALSE)
}

extern "win64" fn CreateSyntheticPointerDevice(_pointer_type: u32, _max_count: u32, _mode: u32) -> u64 {
    fail(ERROR_NOT_SUPPORTED, 0)
}

extern "win64" fn InjectSyntheticPointerInput(_device: u64, _pointer_info: *const u8, _count: u32) -> Bool {
    fail(ERROR_INVALID_HANDLE, FALSE)
}

extern "win64" fn GetDlgItem(dlg: u64, _id: i32) -> u64 {
    if !is_window(dlg) {
        return fail(ERROR_INVALID_WINDOW_HANDLE, 0);
    }
    fail(1421, 0) // ERROR_CONTROL_ID_NOT_FOUND
}

extern "win64" fn GetLayeredWindowAttributes(hwnd: u64, cr_key: *mut u32, alpha: *mut u8, flags: *mut u32) -> Bool {
    if !is_window(hwnd) {
        return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE);
    }
    unsafe {
        if !cr_key.is_null() {
            *cr_key = 0;
        }
        if !alpha.is_null() {
            *alpha = 255;
        }
        if !flags.is_null() {
            *flags = 2; // LWA_ALPHA
        }
    }
    TRUE
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn UpdateLayeredWindow(
    hwnd: u64,
    _hdc_dst: u64,
    ppt_dst: *const i32,
    psize: *const i32,
    hdc_src: u64,
    ppt_src: *const i32,
    _cr_key: u32,
    _pblend: *const u8,
    _flags: u32,
) -> Bool {
    let Some((cur_pos, cur_size)) = with(|g| g.windows.get(&hwnd).map(|w| (w.pos, w.size))) else {
        return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE);
    };
    let (x, y) = if ppt_dst.is_null() {
        cur_pos
    } else {
        unsafe { (*ppt_dst, *ppt_dst.add(1)) }
    };
    let (w, h) = if psize.is_null() {
        (cur_size.0 as i32, cur_size.1 as i32)
    } else {
        unsafe { (*psize, *psize.add(1)) }
    };
    if w < 0 || h < 0 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    if (x, y) != cur_pos || (w as u32, h as u32) != cur_size {
        SetWindowPos(hwnd, 0, x, y, w, h, 0x14);
    }
    if hdc_src != 0 && w > 0 && h > 0 {
        let (sx, sy) = if ppt_src.is_null() {
            (0, 0)
        } else {
            unsafe { (*ppt_src, *ppt_src.add(1)) }
        };
        let dst = GetDC(hwnd);
        if dst != 0 {
            gdi::BitBlt(dst, 0, 0, w, h, hdc_src, sx, sy, 0x00CC_0020);
            ReleaseDC(hwnd, dst);
        }
    }
    TRUE
}

extern "win64" fn PrintWindow(hwnd: u64, hdc_blt: u64, _flags: u32) -> Bool {
    let Some((w, h)) = with(|g| g.windows.get(&hwnd).map(|w| w.size)) else {
        return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE);
    };
    if hdc_blt == 0 {
        return fail(ERROR_INVALID_HANDLE, FALSE);
    }
    let src = GetDC(hwnd);
    if src == 0 {
        return FALSE;
    }
    let ok = gdi::BitBlt(hdc_blt, 0, 0, w as i32, h as i32, src, 0, 0, 0x00CC_0020);
    ReleaseDC(hwnd, src);
    ok
}

/// INPUT on x64 is 40 bytes: type (u32) at +0, union at +8.
extern "win64" fn SendInput(count: u32, inputs: *const u8, size: i32) -> u32 {
    if count == 0 || inputs.is_null() || size != 40 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    with(|g| {
        let target = g.focus;
        for i in 0..count as usize {
            let p = unsafe { inputs.add(i * 40) as u64 };
            let kind = unsafe { teb::get::<u32>(p, 0) };
            if kind == 1 {
                // INPUT_KEYBOARD: wVk (u16) @8, wScan (u16) @10, dwFlags (u32) @12
                let vk = unsafe { teb::get::<u16>(p, 8) } as usize;
                let scan = unsafe { teb::get::<u16>(p, 10) } as u32;
                let flags = unsafe { teb::get::<u32>(p, 12) };
                let up = flags & 2 != 0;
                if flags & 4 != 0 {
                    // KEYEVENTF_UNICODE
                    if !up && target != 0 {
                        g.post(target, WM_CHAR, scan as u64, 1);
                    }
                } else {
                    if vk < 256 {
                        g.keys[vk] = !up;
                        if !up {
                            g.toggles[vk] = !g.toggles[vk];
                        }
                    }
                    if target != 0 {
                        let msg = if up { WM_KEYUP } else { WM_KEYDOWN };
                        let lparam = 1i64 | ((scan as i64 & 0xff) << 16) | if up { 3i64 << 30 } else { 0 };
                        g.post(target, msg, vk as u64, lparam);
                    }
                }
            }
        }
    });
    count
}

extern "win64" fn BroadcastSystemMessageW(_flags: u32, _recipients: *mut u32, msg: u32, wparam: u64, lparam: i64) -> i32 {
    if msg == 0 {
        return fail(ERROR_INVALID_PARAMETER, -1);
    }
    with(|g| {
        let hwnds: Vec<u64> = g.windows.keys().copied().collect();
        for hwnd in hwnds {
            g.post(hwnd, msg, wparam, lparam);
        }
    });
    1
}
//
// One system clipboard, owned by the compositor and broadcast to every
// client; user32's classic API and ole32's data objects both go through it.
// SetClipboardData copies the caller's HGLOBAL at once (all fixed blocks),
// and CloseClipboard publishes the result.

/// Registers a clipboard format name and returns its id (the same table as
/// registered window messages, as on Windows).
pub(crate) fn register_format(name: &str) -> u32 {
    registered_id(name)
}

/// The system clipboard in this process's format ids.
pub(crate) fn clipboard_contents() -> Vec<proto::ClipEntry> {
    with(|g| {
        let mut entries = g.clipboard.clone();
        if !entries.iter().any(|e| e.format == 15) {
            if let Some(data) = proto::clipboard_hdrop(&entries) {
                entries.push(proto::ClipEntry { format: 15, name: None, data });
            }
        }
        if !entries.iter().any(|e| e.name.as_deref() == Some("Preferred DropEffect")) {
            if let Some(data) = proto::clipboard_file_effect(&entries) {
                entries.push(proto::ClipEntry { format: register_format("Preferred DropEffect"), name: None, data });
            }
        }
        entries
    })
}

/// Replaces the system clipboard (data rendered from an OLE data object).
pub(crate) fn publish_clipboard(entries: Vec<proto::ClipEntry>) {
    with(|g| g.publish_clipboard(entries))
}

extern "win64" fn OpenClipboard(hwnd: u64) -> Bool {
    with(|g| match g.clipboard_open {
        Some(_) => fail(ERROR_ACCESS_DENIED, FALSE),
        None => {
            g.clipboard_open = Some(hwnd);
            TRUE
        }
    })
}

extern "win64" fn CloseClipboard() -> Bool {
    with(|g| match g.clipboard_open.take() {
        Some(_) => {
            if !g.clipboard_own.is_empty() {
                let own = core::mem::take(&mut g.clipboard_own);
                g.publish_clipboard(own);
            }
            TRUE
        }
        None => fail(ERROR_CLIPBOARD_NOT_OPEN, FALSE),
    })
}

/// Emptying the clipboard makes this process the owner: the system
/// clipboard is cleared for everyone at once.
extern "win64" fn EmptyClipboard() -> Bool {
    with(|g| {
        if g.clipboard_open.is_none() {
            return fail(ERROR_CLIPBOARD_NOT_OPEN, FALSE);
        }
        g.clipboard_own.clear();
        g.publish_clipboard(Vec::new());
        TRUE
    })
}

extern "win64" fn GetOpenClipboardWindow() -> u64 {
    with(|g| g.clipboard_open.unwrap_or(0))
}

extern "win64" fn SetClipboardData(format: u32, h: u64) -> u64 {
    with(|g| {
        if g.clipboard_open.is_none() {
            return fail(ERROR_CLIPBOARD_NOT_OPEN, 0);
        }
        if h == 0 {
            return 0; // delayed rendering: the caller keeps ownership
        }
        let size = crate::kernel32::heap_size(h);
        // SAFETY: an HGLOBAL from GlobalAlloc is a fixed block of `size` bytes.
        let data = unsafe { core::slice::from_raw_parts(h as *const u8, size) }.to_vec();
        let entry = proto::ClipEntry { format, name: None, data };
        match g.clipboard_own.iter_mut().find(|e| e.format == format) {
            Some(e) => *e = entry,
            None => g.clipboard_own.push(entry),
        }
        h
    })
}

extern "win64" fn GetClipboardData(format: u32) -> u64 {
    with(|g| {
        if g.clipboard_open.is_none() {
            return fail(ERROR_CLIPBOARD_NOT_OPEN, 0);
        }
        if let Some(&h) = g.clipboard_handles.get(&format) {
            return h;
        }
        let entries: Vec<_> = g.clipboard_own.iter().chain(g.clipboard.iter()).cloned().collect();
        let data = proto::clipboard_text_format(&entries, format)
            .or_else(|| (format == 15).then(|| proto::clipboard_hdrop(&entries)).flatten())
            .or_else(|| (format == register_format("Preferred DropEffect")).then(|| proto::clipboard_file_effect(&entries)).flatten());
        let Some(data) = data else { return 0 };
        let Some(h) = crate::kernel32::heap_alloc(data.len().max(1), true) else {
            return fail(ERROR_NOT_ENOUGH_MEMORY, 0);
        };
        // SAFETY: a fresh block of at least `data.len()` bytes.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), h as *mut u8, data.len()) };
        g.clipboard_handles.insert(format, h);
        h
    })
}

/// The clipboard must be open to ask for its data.
extern "win64" fn IsClipboardFormatAvailable(format: u32) -> Bool {
    with(|g| {
        let entries: Vec<_> = g.clipboard_own.iter().chain(g.clipboard.iter()).cloned().collect();
        (proto::clipboard_text_format(&entries, format).is_some()
            || (format == 15 && proto::clipboard_hdrop(&entries).is_some())
            || (format == register_format("Preferred DropEffect") && proto::clipboard_file_effect(&entries).is_some())) as Bool
    })
}

extern "win64" fn GetClipboardSequenceNumber() -> u32 {
    with(|g| g.clipboard_seq)
}

extern "win64" fn EnumClipboardFormats(next: u32) -> u32 {
    with(|g| {
        let mut formats: Vec<u32> = Vec::new();
        for e in g.clipboard_own.iter().chain(g.clipboard.iter()) {
            if !formats.contains(&e.format) {
                formats.push(e.format);
            }
        }
        let entries: Vec<_> = g.clipboard_own.iter().chain(g.clipboard.iter()).cloned().collect();
        for format in [1, proto::CLIP_UNICODE_TEXT, 15, register_format("Preferred DropEffect")] {
            if !formats.contains(&format) && (proto::clipboard_text_format(&entries, format).is_some()
                || (format == 15 && proto::clipboard_hdrop(&entries).is_some())
                || (format == register_format("Preferred DropEffect") && proto::clipboard_file_effect(&entries).is_some())) {
                formats.push(format);
            }
        }
        if next == 0 {
            return formats.first().copied().unwrap_or(0);
        }
        formats.iter().position(|&f| f == next).and_then(|i| formats.get(i + 1)).copied().unwrap_or(0)
    })
}

extern "win64" fn GetClipboardFormatNameW(format: u32, buf: *mut u16, n: i32) -> i32 {
    let list = REGISTERED_MESSAGES.lock().unwrap();
    let Some(name) = format.checked_sub(0xC000).and_then(|i| list.get(i as usize)) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    if buf.is_null() || n <= 0 {
        return 0;
    }
    let units: Vec<u16> = name.encode_utf16().take(n as usize - 1).collect();
    // SAFETY: the caller's buffer of `n` WCHARs.
    unsafe {
        core::ptr::copy_nonoverlapping(units.as_ptr(), buf, units.len());
        *buf.add(units.len()) = 0;
    }
    units.len() as i32
}

/// Clipboard formats share the atom table of registered window messages.
extern "win64" fn RegisterClipboardFormatW(name: *const u16) -> u32 {
    RegisterWindowMessageW(name)
}

extern "win64" fn EnumThreadWindows(thread: u32, proc_: u64, param: u64) -> Bool {
    if proc_ == 0 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let list: Vec<u64> = with(|g| g.windows.iter().filter(|(_, w)| w.thread as u32 == thread).map(|(h, _)| *h).collect());
    if list.is_empty() {
        return FALSE;
    }
    // SAFETY: a caller-supplied WNDENUMPROC of the Windows x64 ABI.
    let f: extern "win64" fn(u64, i64) -> i32 = unsafe { core::mem::transmute(proc_ as usize) };
    for h in list {
        if f(h, param as i64) == 0 {
            break;
        }
    }
    TRUE
}

/// Windows here have no children to enumerate.
extern "win64" fn EnumChildWindows(_parent: u64, _proc: u64, _param: u64) -> Bool {
    FALSE
}

extern "win64" fn EnumWindows(proc_: u64, param: u64) -> Bool {
    if proc_ == 0 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let list: Vec<u64> = with(|g| g.windows.keys().copied().collect());
    // SAFETY: a caller-supplied WNDENUMPROC of the Windows x64 ABI.
    let f: extern "win64" fn(u64, i64) -> i32 = unsafe { core::mem::transmute(proc_ as usize) };
    for h in list {
        if f(h, param as i64) == 0 {
            break;
        }
    }
    TRUE
}

extern "win64" fn GetUpdateRect(wnd: u64, rect: *mut u8, erase: Bool) -> Bool {
    let Some((invalid, needs_erase)) = with(|g| g.windows.get(&wnd).map(|w| (w.invalid, w.erase))) else {
        return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE);
    };
    write_rect(rect.cast(), invalid.unwrap_or(Rect::EMPTY));
    if invalid.is_some() && needs_erase && erase != 0 {
        let dc = GetDC(wnd);
        if dc != 0 {
            let erased = wndproc_of(wnd).is_some_and(|p| call(p, wnd, WM_ERASEBKGND, dc, 0) != 0);
            if erased { with(|g| { if let Some(w) = g.windows.get_mut(&wnd) { w.erase = false; } }); }
            ReleaseDC(wnd, dc);
        }
    }
    invalid.is_some() as Bool
}

extern "win64" fn RedrawWindow(wnd: u64, _rect: *const u8, _rgn: u64, flags: u32) -> Bool {
    static N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && (n < 40 || n.is_multiple_of(600)) {
        let size = with(|g| g.windows.get(&wnd).map(|w| w.size));
        os_std::eprintln!("winrun: redrawwindow n={n} hwnd={wnd:#x} flags={flags:#x} size={size:?}");
    }
    if flags & 0x1 != 0 {
        // RDW_INVALIDATE: queue a paint for the whole window.
        with(|g| {
            if let Some(w) = g.windows.get_mut(&wnd) {
                w.invalid = Some(Rect { x: 0, y: 0, w: w.size.0, h: w.size.1 });
            }
        });
    }
    TRUE
}

extern "win64" fn AnimateWindow(_wnd: u64, _time: u32, _flags: u32) -> Bool {
    TRUE // no animation: the window is simply shown
}

extern "win64" fn FlashWindowEx(_info: *const u8) -> Bool {
    FALSE
}

extern "win64" fn GetMenu(_wnd: u64) -> u64 {
    0 // no window here has a menu bar
}

extern "win64" fn GetSystemMenu(_wnd: u64, _revert: Bool) -> u64 {
    0
}

extern "win64" fn SetMenuItemInfoW(_menu: u64, _item: u32, _by_pos: Bool, _info: *const u8) -> Bool {
    FALSE
}

extern "win64" fn TrackPopupMenu(_menu: u64, _flags: u32, _x: i32, _y: i32, _reserved: i32, _wnd: u64, _rect: *const u8) -> Bool {
    FALSE
}

extern "win64" fn GetWindowTextLengthW(wnd: u64) -> i32 {
    with(|g| g.windows.get(&wnd).map(|w| w.title.encode_utf16().count() as i32).unwrap_or(0))
}

extern "win64" fn GetWindowPlacement(wnd: u64, out: *mut u8) -> Bool {
    if out.is_null() || unsafe { teb::get::<u32>(out as u64, 0) } < 44 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let Some((normal, style)) = with(|g| {
        g.windows.get(&wnd).map(|w| (w.normal, w.style))
    }) else { return fail(ERROR_INVALID_WINDOW_HANDLE, FALSE) };
    // WINDOWPLACEMENT: length, flags, showCmd, ptMin, ptMax, rcNormal.
    // SAFETY: the caller's WINDOWPLACEMENT of at least 44 bytes.
    unsafe {
        teb::put(out as u64, 4, 0u32);
        teb::put(out as u64, 8, if style & WS_MINIMIZE != 0 { 2u32 } else if style & WS_MAXIMIZE != 0 { 3u32 } else { 1u32 });
        teb::put(out as u64, 12, (-1i32, -1i32));
        teb::put(out as u64, 20, (-1i32, -1i32));
        write_rect(out.add(28).cast(), normal);
    }
    TRUE
}

extern "win64" fn SetWindowPlacement(wnd: u64, place: *const u8) -> Bool {
    if place.is_null() || unsafe { teb::get::<u32>(place as u64, 0) } < 44 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let r = rect_at(unsafe { place.add(28) });
    if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
        os_std::eprintln!("winrun: SetWindowPlacement({wnd:#x}, normal {r:?}, show {})", unsafe { teb::get::<u32>(place as u64, 8) });
    }
    if r.2 <= r.0 || r.3 <= r.1 { return fail(ERROR_INVALID_PARAMETER, FALSE); }
    if SetWindowPos(wnd, 0, r.0, r.1, r.2 - r.0, r.3 - r.1, 0x14) == FALSE { return FALSE; }
    with(|g| { if let Some(w) = g.windows.get_mut(&wnd) { w.normal = Rect::new(r.0, r.1, (r.2 - r.0) as u32, (r.3 - r.1) as u32); } });
    // SAFETY: the caller's WINDOWPLACEMENT has its showCmd at offset 8.
    ShowWindow(wnd, unsafe { teb::get::<u32>(place as u64, 8) } as i32);
    TRUE
}

extern "win64" fn CharLowerW(s: *mut u16) -> *mut u16 {
    if s.is_null() {
        return s;
    }
    let mut i = 0;
    // SAFETY: a NUL-terminated string from the caller, modified in place.
    unsafe {
        while *s.add(i) != 0 {
            let c = *s.add(i);
            if (0x41..=0x5a).contains(&c) {
                *s.add(i) = c + 0x20;
            }
            i += 1;
        }
    }
    s
}

extern "win64" fn IsGUIThread(_convert: Bool) -> Bool {
    TRUE // winrun's threads are user-interface threads
}

extern "win64" fn GetGUIThreadInfo(_thread: u32, out: *mut u8) -> Bool {
    if out.is_null() || unsafe { teb::get::<u32>(out as u64, 0) } < 72 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let focus = with(|g| g.focus);
    // GUITHREADINFO: cbSize, flags, hwndActive, hwndFocus, hwndCapture,
    // hwndMenuOwner, hwndMoveSize, hwndCaret, rcCaret.
    // SAFETY: the caller's GUITHREADINFO of at least 72 bytes.
    unsafe {
        core::ptr::write_bytes(out, 0, 72);
        teb::put(out as u64, 8, focus);
        teb::put(out as u64, 16, focus);
    }
    TRUE
}

extern "win64" fn SetSysColors(_count: i32, _elements: *const i32, _colors: *const u32) -> Bool {
    TRUE // the desktop's palette is fixed
}

extern "win64" fn OpenInputDesktop(_flags: u32, _inherit: Bool, _access: u32) -> u64 {
    0x20_0001 // one input desktop, always open
}

extern "win64" fn SetThreadDesktop(_desktop: u64) -> Bool {
    TRUE
}

/// Device and power notifications are accepted and never delivered: OSyx
/// reports no device arrival and has no power events to send.
extern "win64" fn RegisterDeviceNotificationW(_recipient: u64, _filter: *const u8, _flags: u32) -> u64 {
    0x30_0001
}

extern "win64" fn UnregisterDeviceNotification(_notify: u64) -> Bool {
    TRUE
}

extern "win64" fn RegisterPowerSettingNotification(_recipient: u64, _guid: *const u8, _flags: u32) -> u64 {
    0x30_0002
}

extern "win64" fn UnregisterPowerSettingNotification(_notify: u64) -> Bool {
    TRUE
}

extern "win64" fn SendNotifyMessageW(wnd: u64, msg: u32, wparam: u64, lparam: i64) -> Bool {
    with(|g| g.post(wnd, msg, wparam, lparam));
    TRUE
}

/// `SendMessageTimeoutW`: the message is delivered directly and the answer
/// written out; nothing here can block for long enough to hit the timeout.
extern "win64" fn SendMessageTimeoutW(wnd: u64, msg: u32, wparam: u64, lparam: i64, _flags: u32, _timeout: u32, out: *mut u64) -> i64 {
    let result = match wndproc_of(wnd) {
        Some(p) => call(p, wnd, msg, wparam, lparam),
        None => 0,
    };
    if !out.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = result as u64 };
    }
    1
}

extern "win64" fn CallWindowProcW(proc_: u64, wnd: u64, msg: u32, wparam: u64, lparam: i64) -> i64 {
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && matches!(msg, WM_CHAR | WM_KEYDOWN | WM_KEYUP | WM_LBUTTONDOWN | WM_LBUTTONUP) {
        os_std::eprintln!("winrun: callwndproc msg={msg:#x} hwnd={wnd:#x} w={wparam:#x}");
    }
    if proc_ == 0 {
        return 0;
    }
    // SAFETY: a caller-supplied window procedure of the Windows x64 ABI.
    let f: extern "win64" fn(u64, u32, u64, i64) -> i64 = unsafe { core::mem::transmute(proc_ as usize) };
    f(wnd, msg, wparam, lparam)
}

/// OSyx has one screen described by MonitorFromWindow/GetMonitorInfo; the
/// DisplayConfig path model (paths, sources, targets, modes) is not built, so
/// these report ERROR_NOT_SUPPORTED and callers fall back to the monitor API.
const ERROR_NOT_SUPPORTED_WIN: u32 = 50;

extern "win64" fn GetDisplayConfigBufferSizes(_flags: u32, paths: *mut u32, modes: *mut u32) -> u32 {
    if paths.is_null() || modes.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the caller's out pointers.
    unsafe {
        *paths = 0;
        *modes = 0;
    }
    ERROR_NOT_SUPPORTED_WIN
}

extern "win64" fn QueryDisplayConfig(_flags: u32, paths: *mut u32, _path: *mut u8, modes: *mut u32, _mode: *mut u8, _topology: *mut u32) -> u32 {
    if paths.is_null() || modes.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    ERROR_NOT_SUPPORTED_WIN
}

extern "win64" fn DisplayConfigGetDeviceInfo(_packet: *mut u8) -> u32 {
    ERROR_NOT_SUPPORTED_WIN
}

extern "win64" fn EnumDisplayMonitors(_dc: u64, _clip: *const u8, proc_: u64, data: u64) -> Bool {
    if proc_ == 0 {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let r = screen_rect();
    let mut rect = [0i32; 4];
    rect.copy_from_slice(&[r.0, r.1, r.2, r.3]);
    // SAFETY: a caller-supplied MONITORENUMPROC of the Windows x64 ABI.
    let f: extern "win64" fn(u64, u64, *const u8, i64) -> i32 = unsafe { core::mem::transmute(proc_ as usize) };
    f(crate::minordlls::PRIMARY_MONITOR, _dc, rect.as_ptr() as *const u8, data as i64);
    TRUE
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        RegisterClassA,
        RegisterClassW,
        RegisterClassExA,
        RegisterClassExW,
        UnregisterClassA,
        CreateWindowExA,
        CreateWindowExW,
        DestroyWindow,
        IsWindow,
        IsWindowVisible,
        GetWindowRgn,
        ShowWindow,
        UpdateWindow,
        InvalidateRect,
        ValidateRect,
        GetClientRect,
        GetWindowRect,
        AdjustWindowRect,
        AdjustWindowRectEx,
        SetWindowPos,
        MoveWindow,
        SetWindowTextA,
        SetWindowTextW,
        GetWindowTextA,
        GetWindowTextW,
        GetWindowTextLengthA,
        wsprintfA,
        wsprintfW,
        wvsprintfA,
        wvsprintfW,
        GetWindowLongPtrA,
        SetWindowLongPtrA,
        GetWindowLongA,
        SetWindowLongA,
        GetMessageA,
        GetMessageW,
        PeekMessageA,
        PeekMessageW,
        TranslateMessage,
        DispatchMessageA,
        DispatchMessageW,
        SendMessageA,
        SendMessageW,
        PostMessageA,
        PostMessageW,
        PostQuitMessage,
        DefWindowProcA,
        DefWindowProcW,
        SetTimer,
        KillTimer,
        GetFocus,
        SetFocus,
        GetActiveWindow,
        SetCapture,
        ReleaseCapture,
        GetKeyState,
        GetAsyncKeyState,
        GetCursorPos,
        ScreenToClient,
        ClientToScreen,
        GetSystemMetrics,
        SystemParametersInfoA,
        SystemParametersInfoW,
        EqualRect,
        InflateRect,
        OffsetRect,
        IntersectRect,
        IsRectEmpty,
        PtInRect,
        SetRect,
        SetRectEmpty,
        GetCaretBlinkTime,
        GetDoubleClickTime,
        CreateCaret,
        DestroyCaret,
        ShowCaret,
        HideCaret,
        SetCaretPos,
        ShowCursor,
        SetCursorPos,
        ClipCursor,
        GetCursorInfo,
        GetMessagePos,
        GetMessageTime,
        GetMessageExtraInfo,
        GetQueueStatus,
        GetCapture,
        CreateIconIndirect,
        GetIconInfo,
        DestroyIcon,
        LoadImageW,
        OpenClipboard,
        CloseClipboard,
        EmptyClipboard,
        GetOpenClipboardWindow,
        SetClipboardData,
        GetClipboardData,
        IsClipboardFormatAvailable,
        GetClipboardSequenceNumber,
        EnumClipboardFormats,
        GetClipboardFormatNameW,
        EnumDisplayDevicesW,
        EnumDisplaySettingsExW,
        EnumDisplaySettingsW,
        GetAutoRotationState,
        RegisterTouchWindow,
        SetGestureConfig,
        RegisterRawInputDevices,
        GetRawInputDeviceList,
        GetRawInputDeviceInfoA,
        GetRawInputDeviceInfoW,
        GetRawInputData,
        GetTouchInputInfo,
        CloseTouchInputHandle,
        GetGestureInfo,
        CloseGestureInfoHandle,
        GetPointerType,
        GetPointerFrameTouchInfo,
        CreateSyntheticPointerDevice,
        InjectSyntheticPointerInput,
        GetDlgItem,
        GetLayeredWindowAttributes,
        UpdateLayeredWindow,
        PrintWindow,
        SendInput,
        BroadcastSystemMessageW,
        RegisterClipboardFormatW,
        TrackMouseEvent,
        GetLastInputInfo,
        WindowFromPoint,
        MapWindowPoints,
        EnumThreadWindows,
        EnumChildWindows,
        GetKeyboardLayout,
        GetKeyboardLayoutList,
        GetKeyboardLayoutNameW,
        GetKeyboardLayoutNameA,
        ActivateKeyboardLayout,
        LoadKeyboardLayoutA,
        UnloadKeyboardLayout,
        MapVirtualKeyExW,
        MapVirtualKeyW,
        ToUnicodeEx,
        ToUnicode,
        GetKeyboardState,
        SetKeyboardState,
        MsgWaitForMultipleObjects,
        MsgWaitForMultipleObjectsEx,
        ReplyMessage,
        InSendMessage,
        InSendMessageEx,
        CallNextHookEx,
        SetWinEventHook,
        UnhookWinEvent,
        NotifyWinEvent,
        SetWindowsHookExW,
        UnhookWindowsHookEx,
        GetPropW,
        SetPropW,
        RemovePropW,
        GetParent,
        GetAncestor,
        IsChild,
        GetWindow,
        GetTopWindow,
        SetParent,
        SetForegroundWindow,
        GetForegroundWindow,
        BringWindowToTop,
        IsIconic,
        IsZoomed,
        IsWindowArranged,
        IsWindowEnabled,
        EnableWindow,
        GetWindowThreadProcessId,
        GetClassNameW,
        MonitorFromPoint,
        MonitorFromRect,
        MonitorFromWindow,
        GetMonitorInfoW,
        GetMonitorInfoA,
        RegisterWindowMessageW,
        GetClassInfoW,
        GetClassInfoA,
        UnregisterClassW,
        GetClassLongPtrW,
        SetClassLongPtrW,
        GetClassWord,
        FindWindowW,
        FindWindowExW,
        EnumWindows,
        GetUpdateRect,
        RedrawWindow,
        AnimateWindow,
        FlashWindowEx,
        GetMenu,
        GetSystemMenu,
        SetMenuItemInfoW,
        TrackPopupMenu,
        GetWindowTextLengthW,
        GetWindowPlacement,
        SetWindowPlacement,
        CharLowerW,
        IsGUIThread,
        GetGUIThreadInfo,
        SetSysColors,
        OpenInputDesktop,
        SetThreadDesktop,
        RegisterDeviceNotificationW,
        UnregisterDeviceNotification,
        RegisterPowerSettingNotification,
        UnregisterPowerSettingNotification,
        SendNotifyMessageW,
        SendMessageTimeoutW,
        CallWindowProcW,
        GetDisplayConfigBufferSizes,
        QueryDisplayConfig,
        DisplayConfigGetDeviceInfo,
        EnumDisplayMonitors,
        LoadCursorA,
        LoadCursorW,
        LoadIconA,
        LoadIconW,
        SetCursor,
        GetSysColor,
        GetSysColorBrush,
        MessageBeep,
        BeginPaint,
        EndPaint,
        GetDC,
        GetWindowDC,
        ReleaseDC,
        FillRect,
        FrameRect,
        DrawTextA,
        DrawTextW,
        MessageBoxA,
        MessageBoxW,
    ]
    .into_iter()
    .chain([
        ("GetWindowLongPtrW", GetWindowLongPtrA as *const () as usize as u64),
        ("SetWindowLongPtrW", SetWindowLongPtrA as *const () as usize as u64),
        ("GetWindowLongW", GetWindowLongA as *const () as usize as u64),
        ("SetWindowLongW", SetWindowLongA as *const () as usize as u64),
    ])
    .collect()
}

// ---- device contexts -----------------------------------------------------------------------

/// `GetDeviceCaps`: OSyx's screens are 32-bit colour at 96 DPI, which is the
/// one configuration the software compositor draws.
extern "win64" fn GetDeviceCaps(_dc: u64, index: i32) -> i32 {
    let (w, h) = {
        let r = screen_rect();
        (r.2 - r.0, r.3 - r.1)
    };
    match index {
        2 => 1,                       // TECHNOLOGY: DT_RASDISPLAY
        4 => w * 254 / 960,           // HORZSIZE, from 96 DPI
        6 => h * 254 / 960,           // VERTSIZE
        8 => w,                       // HORZRES
        10 => h,                      // VERTRES
        12 => 32,                     // BITSPIXEL
        14 => 1,                      // PLANES
        24 => -1,                     // NUMCOLORS: more than 256 (true colour)
        38 => 0x0001 | 0x0100,        // RASTERCAPS: RC_BITBLT | RC_BITMAP64
        40 | 42 => 36,                // ASPECTX / ASPECTY
        88 | 90 => 96,                // LOGPIXELSX / LOGPIXELSY
        104 => 0,                     // SIZEPALETTE
        110 => w,                     // PHYSICALWIDTH
        111 => h,                     // PHYSICALHEIGHT
        112 | 113 => 0,               // PHYSICALOFFSETX / Y
        116 => 60,                    // VREFRESH
        117 => h,                     // DESKTOPVERTRES
        118 => w,                     // DESKTOPHORZRES
        _ => 0,
    }
}

extern "win64" fn GdiFlush() -> Bool {
    TRUE // drawing reaches PRISM in order already
}

/// Printing goes nowhere: there is no spooler, but a program that opens a
/// job and ends it sees the calls succeed rather than fail mid-print.
extern "win64" fn StartDocW(_dc: u64, _doc: *const u8) -> i32 {
    1
}

extern "win64" fn EndDoc(_dc: u64) -> i32 {
    1
}

extern "win64" fn StartPage(_dc: u64) -> i32 {
    1
}

extern "win64" fn EndPage(_dc: u64) -> i32 {
    1
}

extern "win64" fn AbortDoc(_dc: u64) -> i32 {
    1
}

pub fn gdi_exports() -> Vec<(&'static str, u64)> {
    export_table![
        TextOutA,
        TextOutW,
        GetTextExtentPoint32A,
        GetTextExtentPoint32W,
        GetTextMetricsA,
        GetTextMetricsW,
        SetTextColor,
        SetBkColor,
        SetBkMode,
        CreateSolidBrush,
        CreatePen,
        CreateFontA,
        CreateFontW,
        CreateFontIndirectW,
        GetStockObject,
        SelectObject,
        DeleteObject,
        MoveToEx,
        LineTo,
        Rectangle,
        RoundRect,
        SetPixel,
        GetDeviceCaps,
        GdiFlush,
        StartDocW,
        EndDoc,
        StartPage,
        EndPage,
        AbortDoc,
    ]
    .into_iter()
    .chain(gdi::exports())
    .collect()
}
