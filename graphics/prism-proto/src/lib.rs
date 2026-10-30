//! The PRISM window protocol, version 1.
//!
//! PRISM ("many surfaces, one vision") is the OSyx compositor. Clients talk
//! to it over a kernel IPC channel registered under [`SERVICE`]; every
//! channel message is one protocol message:
//!
//! ```text
//! offset size  field
//!      0    2  opcode        (requests 0x01.., events 0x81..)
//!      2    2  reserved, 0
//!      4    4  payload length (message length - 16)
//!      8    4  serial        (chosen by the sender, echoed in errors)
//!     12    4  reserved, 0
//!     16    n  payload       (little-endian fields, see below)
//! ```
//!
//! Strings are a `u16` byte length followed by UTF-8. Every message is
//! validated completely before it is acted on: exact payload length, no
//! trailing bytes, bounded strings and dimensions, valid enum values. A
//! client that sends a malformed message receives [`Event::Error`] and is
//! disconnected; its windows and buffers are released.
//!
//! Pixel buffers travel out of band: `ATTACH_BUFFER` carries a shared
//! memory handle in the channel message's handle slot 0. The compositor
//! maps it read-only, checks that `offset + stride * height` fits, copies
//! the damaged region at `COMMIT_SURFACE` and answers with
//! `BUFFER_RELEASE`, after which the client may draw into the buffer again.
//!
//! Object ids (surfaces, windows) are chosen by the client, unique per
//! connection, never 0. Window ids in `WINDOW_LIST` and shell
//! `WINDOW_ACTION`s are global ids chosen by the compositor.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Name of the compositor's IPC service.
pub const SERVICE: &str = "prism";
pub const VERSION: u16 = 1;
pub const MIN_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;
/// Largest protocol message (header included), the kernel's channel limit.
pub const MAX_MESSAGE: usize = 64 * 1024;
/// Longest window title / client name (bytes of UTF-8).
pub const MAX_TITLE: usize = 256;
/// Longest notification body or error text.
pub const MAX_TEXT: usize = 1024;
/// Largest surface edge in pixels.
pub const MAX_DIMENSION: u32 = 8192;
/// Most entries in one `WINDOW_LIST`.
pub const MAX_LIST: usize = 64;
/// Most clipboard formats in one contents set.
pub const MAX_CLIPBOARD: usize = 16;
/// Largest total clipboard payload in one set (leaves room for framing).
pub const MAX_CLIPBOARD_BYTES: usize = 56 * 1024;

pub mod opcode {
    pub const HELLO: u16 = 0x01;
    pub const CREATE_SURFACE: u16 = 0x02;
    pub const DESTROY_SURFACE: u16 = 0x03;
    pub const CREATE_WINDOW: u16 = 0x04;
    pub const DESTROY_WINDOW: u16 = 0x05;
    pub const ATTACH_BUFFER: u16 = 0x06;
    pub const DAMAGE: u16 = 0x07;
    pub const COMMIT_SURFACE: u16 = 0x08;
    pub const SET_TITLE: u16 = 0x09;
    pub const SET_GEOMETRY: u16 = 0x0A;
    pub const WINDOW_ACTION: u16 = 0x0B;
    pub const NOTIFY: u16 = 0x0C;
    pub const DESTROY_BUFFER: u16 = 0x0D;
    pub const SET_WINDOW_VISIBILITY: u16 = 0x0E;
    pub const SYNC: u16 = 0x0F;
    pub const CLIPBOARD_SET: u16 = 0x10;
    pub const FILE_DRAG: u16 = 0x11;

    pub const EV_HELLO: u16 = 0x81;
    pub const CONFIGURE: u16 = 0x82;
    pub const FOCUS_CHANGED: u16 = 0x83;
    pub const KEY_EVENT: u16 = 0x84;
    pub const POINTER_EVENT: u16 = 0x85;
    pub const CLOSE_REQUEST: u16 = 0x86;
    pub const BUFFER_RELEASE: u16 = 0x87;
    pub const FRAME_DONE: u16 = 0x88;
    pub const WINDOW_LIST: u16 = 0x89;
    pub const NOTIFICATION: u16 = 0x8A;
    pub const ERROR: u16 = 0x8B;
    pub const SYNC_DONE: u16 = 0x8C;
    pub const CLIPBOARD_CHANGED: u16 = 0x8D;
    pub const FILE_DROP: u16 = 0x8E;
}

/// `HELLO` flags.
pub mod hello {
    /// Request (and, in the reply, grant) the desktop shell role: window
    /// list updates, global window actions, notifications.
    pub const SHELL: u32 = 1 << 0;
}

/// Pixel formats of attached buffers (32 bits per pixel, `0xAARRGGBB` in a
/// little-endian `u32`).
pub mod format {
    /// Alpha ignored: the surface is opaque.
    pub const XRGB8888: u32 = 1;
    /// Premultiplied alpha.
    pub const ARGB8888: u32 = 2;
}

/// What a window is for; decides stacking and decorations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// An application window: decorated, movable, in the normal layer.
    Normal = 0,
    /// The desktop background: full screen, below everything (shell only).
    Desktop = 1,
    /// A panel (task bar / dock) above normal windows (shell only).
    Panel = 2,
    /// A menu or popup: undecorated, above everything, closed when focus
    /// moves elsewhere.
    Popup = 3,
    /// A notification bubble (shell only): above panels, never focused.
    Notification = 4,
    /// The lock screen (shell only): full screen above everything; while
    /// one exists every key goes to it, whatever has the focus.
    Lock = 5,
}

impl Role {
    pub fn from_raw(v: u8) -> Option<Role> {
        Some(match v {
            0 => Role::Normal,
            1 => Role::Desktop,
            2 => Role::Panel,
            3 => Role::Popup,
            4 => Role::Notification,
            5 => Role::Lock,
            _ => return None,
        })
    }

    /// Roles only the shell may create.
    pub fn shell_only(self) -> bool {
        matches!(self, Role::Desktop | Role::Panel | Role::Notification | Role::Lock)
    }
}

/// `CREATE_WINDOW` flags.
pub mod window_flags {
    /// The user may resize the window.
    pub const RESIZABLE: u32 = 1 << 0;
    /// Draw server-side decorations (title bar, border, shadow).
    pub const DECORATED: u32 = 1 << 1;
    /// Start maximized.
    pub const MAXIMIZED: u32 = 1 << 2;
    /// Auxiliary/owned windows do not get an independent taskbar entry.
    pub const SKIP_TASKBAR: u32 = 1 << 3;
    pub const HIDDEN: u32 = 1 << 4;
    pub const ALL: u32 = RESIZABLE | DECORATED | MAXIMIZED | SKIP_TASKBAR | HIDDEN;
}

/// `CONFIGURE` states and `WINDOW_LIST` flags.
pub mod state {
    pub const MAXIMIZED: u32 = 1 << 0;
    /// The window has keyboard focus.
    pub const ACTIVATED: u32 = 1 << 1;
    pub const MINIMIZED: u32 = 1 << 2;
    /// An interactive resize is in progress.
    pub const RESIZING: u32 = 1 << 3;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Activate = 0,
    Minimize = 1,
    Maximize = 2,
    Restore = 3,
    /// Ask the owner to close (it receives `CLOSE_REQUEST`).
    Close = 4,
    ToggleMaximize = 5,
}

impl Action {
    pub fn from_raw(v: u8) -> Option<Action> {
        Some(match v {
            0 => Action::Activate,
            1 => Action::Minimize,
            2 => Action::Maximize,
            3 => Action::Restore,
            4 => Action::Close,
            5 => Action::ToggleMaximize,
            _ => return None,
        })
    }
}

/// `POINTER_EVENT` kinds.
pub mod pointer {
    pub const ENTER: u8 = 0;
    pub const LEAVE: u8 = 1;
    pub const MOTION: u8 = 2;
    pub const BUTTON: u8 = 3;
    pub const WHEEL: u8 = 4;
}

/// `KEY_EVENT` states (as in `osyx_input`: up, down, repeat).
pub mod key_state {
    pub const UP: u8 = 0;
    pub const DOWN: u8 = 1;
    pub const REPEAT: u8 = 2;
}

/// `ERROR` codes.
pub mod error {
    pub const MALFORMED: u32 = 1;
    pub const BAD_VERSION: u32 = 2;
    pub const UNKNOWN_OBJECT: u32 = 3;
    pub const DUPLICATE_ID: u32 = 4;
    pub const BAD_BUFFER: u32 = 5;
    pub const NOT_ALLOWED: u32 = 6;
    pub const LIMIT: u32 = 7;
    pub const NOT_INITIALISED: u32 = 8;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowInfo {
    pub id: u32,
    pub pid: u32,
    /// [`state`] bits.
    pub flags: u32,
    pub title: String,
}

/// One clipboard format: `format` below 0xC000 is a Win32 CF_* constant,
/// otherwise it is a registered format and `name` carries its registered
/// name (ids of registered formats are per process).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipEntry {
    pub format: u32,
    pub name: Option<String>,
    pub data: Vec<u8>,
}

/// Win32 CF_UNICODETEXT, also used by native clients for shared text.
pub const CLIP_UNICODE_TEXT: u32 = 13;
/// Registered clipboard format for absolute OSyx file paths.
pub const CLIP_FILES_NAME: &str = "application/x-osyx-files";

/// Encode a file selection without relying on delimiters in file names.
pub fn clipboard_files_entry(paths: &[String], cut: bool) -> Option<ClipEntry> {
    if paths.is_empty() || paths.len() > u16::MAX as usize { return None; }
    let mut data = Vec::new();
    data.push(u8::from(cut));
    data.extend_from_slice(&(paths.len() as u16).to_le_bytes());
    for path in paths {
        if !path.starts_with('/') || path.contains('\0') { return None; }
        let len = u32::try_from(path.len()).ok()?;
        if data.len().checked_add(4 + path.len())? > MAX_CLIPBOARD_BYTES { return None; }
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(path.as_bytes());
    }
    Some(ClipEntry { format: 0xc000, name: Some(String::from(CLIP_FILES_NAME)), data })
}

/// Decode a complete file selection; reject malformed or relative paths.
pub fn clipboard_files(entries: &[ClipEntry]) -> Option<(Vec<String>, bool)> {
    let Some(entry) = entries.iter().find(|entry| entry.name.as_deref() == Some(CLIP_FILES_NAME)) else {
        return clipboard_hdrop_files(entries);
    };
    let data = &entry.data;
    if data.len() < 3 || data.len() > MAX_CLIPBOARD_BYTES || data[0] > 1 { return None; }
    let count = u16::from_le_bytes([data[1], data[2]]) as usize;
    if count == 0 { return None; }
    let mut at = 3usize;
    let mut paths = Vec::new();
    for _ in 0..count {
        let b = data.get(at..at.checked_add(4)?)?;
        let len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        at += 4;
        let end = at.checked_add(len)?;
        let path = core::str::from_utf8(data.get(at..end)?).ok()?;
        if !path.starts_with('/') || path.contains('\0') { return None; }
        paths.push(String::from(path));
        at = end;
    }
    if at != data.len() { return None; }
    Some((paths, data[0] != 0))
}

/// Decode local C: paths from a Windows CF_HDROP clipboard entry.
fn clipboard_hdrop_files(entries: &[ClipEntry]) -> Option<(Vec<String>, bool)> {
    let data = &entries.iter().find(|e| e.format == 15)?.data;
    if data.len() < 20 || data.len() > MAX_CLIPBOARD_BYTES { return None; }
    let offset = u32::from_le_bytes(data.get(0..4)?.try_into().ok()?) as usize;
    if offset < 20 { return None; }
    let wide = u32::from_le_bytes(data.get(16..20)?.try_into().ok()?) != 0;
    let bytes = data.get(offset..)?;
    let units: Vec<u16> = if wide {
        if bytes.len() % 2 != 0 { return None; }
        bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect()
    } else {
        core::str::from_utf8(bytes).ok()?.encode_utf16().collect()
    };
    let mut paths = Vec::new();
    let mut at = 0;
    loop {
        let end = units[at..].iter().position(|u| *u == 0)? + at;
        if end == at { break; }
        let win = String::from_utf16(&units[at..end]).ok()?;
        let raw = win.as_bytes();
        if raw.len() < 3 || !raw[0].eq_ignore_ascii_case(&b'c') || raw[1] != b':' || raw[2] != b'\\' { return None; }
        let path = win[2..].replace('\\', "/");
        if path.split('/').any(|part| part == "." || part == ".."
            || part.contains([':', '<', '>', '"', '|', '?', '*'])
            || part.ends_with(['.', ' '])) { return None; }
        paths.push(path);
        at = end + 1;
        if at >= units.len() { return None; }
    }
    if paths.is_empty() { return None; }
    let cut = entries.iter().find(|e| e.name.as_deref() == Some("Preferred DropEffect"))
        .and_then(|e| e.data.get(..4)).is_some_and(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) == 2);
    Some((paths, cut))
}

/// Convert native file paths to a wide Windows CF_HDROP payload.
pub fn clipboard_hdrop(entries: &[ClipEntry]) -> Option<Vec<u8>> {
    let (paths, _) = clipboard_files(entries)?;
    let mut data = alloc::vec![0u8; 20];
    data[0..4].copy_from_slice(&20u32.to_le_bytes());
    data[16..20].copy_from_slice(&1u32.to_le_bytes());
    for path in paths {
        // Windows would reinterpret these names or path components.
        if path.split('/').any(|part| part == "." || part == ".."
            || part.contains(['\\', ':', '<', '>', '"', '|', '?', '*'])
            || part.ends_with(['.', ' '])) { return None; }
        for c in "C:".chars().chain(path.chars().map(|c| if c == '/' { '\\' } else { c })) {
            let mut units = [0u16; 2];
            for u in c.encode_utf16(&mut units) {
                data.extend_from_slice(&u.to_le_bytes());
            }
        }
        data.extend_from_slice(&[0, 0]);
        if data.len() > MAX_CLIPBOARD_BYTES - 2 { return None; }
    }
    data.extend_from_slice(&[0, 0]);
    Some(data)
}

/// Preferred Windows drop effect for a native file selection.
pub fn clipboard_file_effect(entries: &[ClipEntry]) -> Option<Vec<u8>> {
    let native = entries.iter().find(|e| e.name.as_deref() == Some(CLIP_FILES_NAME))?;
    let (_, cut) = clipboard_files(core::slice::from_ref(native))?;
    Some((if cut { 2u32 } else { 1u32 }).to_le_bytes().to_vec())
}

/// Encode text as a NUL-terminated UTF-16LE clipboard entry.
pub fn clipboard_text_entry(text: &str) -> ClipEntry {
    let mut data = Vec::new();
    for ch in text.chars() {
        if ch == '\0' { break; }
        let mut units = [0u16; 2];
        let units = ch.encode_utf16(&mut units);
        if data.len() + units.len() * 2 + 2 > MAX_CLIPBOARD_BYTES { break; }
        for unit in units { data.extend_from_slice(&unit.to_le_bytes()); }
    }
    data.extend_from_slice(&[0, 0]);
    ClipEntry { format: CLIP_UNICODE_TEXT, name: None, data }
}

/// Decode the first CF_UNICODETEXT entry, ignoring any bytes after NUL.
pub fn clipboard_text(entries: &[ClipEntry]) -> Option<String> {
    if let Some(entry) = entries.iter().find(|e| e.format == CLIP_UNICODE_TEXT) {
        if entry.data.len() % 2 != 0 { return None; }
        let units: Vec<u16> = entry.data.chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .take_while(|u| *u != 0).collect();
        return Some(String::from_utf16_lossy(&units));
    }
    // OSyx's Windows ANSI code page is UTF-8.
    let entry = entries.iter().find(|e| e.format == 1)?;
    let end = entry.data.iter().position(|b| *b == 0).unwrap_or(entry.data.len());
    Some(String::from_utf8_lossy(&entry.data[..end]).into_owned())
}

/// Return a text format, synthesizing it from the other text format if needed.
/// OSyx Win32 uses UTF-8 for its ANSI code page.
pub fn clipboard_text_format(entries: &[ClipEntry], format: u32) -> Option<Vec<u8>> {
    if let Some(entry) = entries.iter().find(|entry| entry.format == format) {
        return Some(entry.data.clone());
    }
    let text = clipboard_text(entries)?;
    match format {
        CLIP_UNICODE_TEXT => Some(clipboard_text_entry(&text).data),
        1 => {
            let mut data = text.into_bytes();
            data.push(0);
            Some(data)
        }
        _ => None,
    }
}

/// Client -> compositor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Hello { min_version: u16, max_version: u16, flags: u32, name: String },
    CreateSurface { surface: u32 },
    DestroySurface { surface: u32 },
    /// `parent`: for popups, the client window whose content origin `x`/`y`
    /// are relative to (0: screen coordinates, shell only). Normal windows:
    /// `x`/`y` are a placement hint, negative = let the compositor choose.
    CreateWindow {
        window: u32,
        surface: u32,
        parent: u32,
        role: Role,
        flags: u32,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        min_width: u32,
        min_height: u32,
        title: String,
    },
    DestroyWindow { window: u32 },
    /// Attaches buffer `buffer` to the surface. If the channel message carries a
    /// shared memory handle (slot 0), it (re)defines `buffer`; otherwise
    /// `buffer` must name a buffer defined earlier (buffers are reused frame
    /// after frame without mapping them again).
    AttachBuffer { surface: u32, buffer: u32, width: u32, height: u32, stride: u32, format: u32, offset: u32 },
    DestroyBuffer { buffer: u32 },
    Damage { surface: u32, rect: Rect },
    Commit { surface: u32 },
    SetTitle { window: u32, title: String },
    SetGeometry { window: u32, x: i32, y: i32, width: u32, height: u32 },
    SetWindowVisibility { window: u32, visible: bool, taskbar: bool },
    /// Acknowledged after all preceding requests on this connection.
    Sync { cookie: u32 },
    /// `global`: `target` is a compositor-wide id (shell only); otherwise
    /// one of the client's own window ids.
    WindowAction { target: u32, action: Action, global: bool },
    Notify { title: String, body: String },
    /// Replaces the system clipboard contents.
    ClipboardSet { entries: Vec<ClipEntry> },
    FileDrag { window: u32, path: String },
}

/// Compositor -> client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    SyncDone { cookie: u32 },
    Hello { version: u16, client_id: u32, flags: u32, screen_width: u32, screen_height: u32 },
    Configure { window: u32, width: u32, height: u32, states: u32 },
    FocusChanged { window: u32, focused: bool },
    Key { window: u32, usage: u16, state: u8, modifiers: u32, text: Option<char> },
    Pointer {
        window: u32,
        kind: u8,
        /// Pointer position in the window's client area.
        x: i32,
        y: i32,
        /// Pointer position on the screen (compositor space).
        screen_x: i32,
        screen_y: i32,
        button: u16,
        pressed: bool,
        wheel_v: i32,
        wheel_h: i32,
        buttons: u32,
        modifiers: u32,
    },
    CloseRequest { window: u32 },
    BufferRelease { surface: u32 },
    FrameDone { surface: u32, time_ms: u64 },
    WindowList { windows: Vec<WindowInfo> },
    Notification { from_pid: u32, title: String, body: String },
    /// The system clipboard contents, broadcast on every change and once to
    /// each client after `HELLO`. `seq` is monotonic, 0 for "never set".
    ClipboardChanged { seq: u32, entries: Vec<ClipEntry> },
    FileDrop { window: u32, x: i32, y: i32, path: String },
    Error { code: u32, serial: u32, message: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// Shorter than a header, or the header's length disagrees with the data.
    BadLength,
    /// Reserved header fields are not zero.
    BadHeader,
    UnknownOpcode(u16),
    /// The payload is shorter or longer than its opcode requires.
    BadPayload,
    /// A string is too long or not UTF-8.
    BadString,
    /// An enum field holds an undefined value.
    BadValue,
    /// A dimension or count is out of range.
    OutOfRange,
    TooLarge,
}

// ---- encoding ----------------------------------------------------------------

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new(opcode: u16, serial: u32) -> Writer {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&opcode.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&serial.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        Writer { buf }
    }
    fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn i32(&mut self, v: i32) -> &mut Self {
        self.u32(v as u32)
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn str(&mut self, s: &str, max: usize) -> &mut Self {
        // Over-long strings are cut at a character boundary.
        let mut end = s.len().min(max);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        self.u16(end as u16);
        self.buf.extend_from_slice(&s.as_bytes()[..end]);
        self
    }
    fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    fn finish(mut self) -> Vec<u8> {
        let len = (self.buf.len() - HEADER_LEN) as u32;
        self.buf[4..8].copy_from_slice(&len.to_le_bytes());
        self.buf
    }
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.b.len() < n {
            return Err(ProtoError::BadPayload);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtoError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, ProtoError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn i32(&mut self) -> Result<i32, ProtoError> {
        Ok(self.u32()? as i32)
    }
    fn u64(&mut self) -> Result<u64, ProtoError> {
        let lo = self.u32()? as u64;
        let hi = self.u32()? as u64;
        Ok(lo | hi << 32)
    }
    fn bool(&mut self) -> Result<bool, ProtoError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtoError::BadValue),
        }
    }
    fn str(&mut self, max: usize) -> Result<String, ProtoError> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(ProtoError::BadString);
        }
        let b = self.take(n)?;
        let s = core::str::from_utf8(b).map_err(|_| ProtoError::BadString)?;
        Ok(String::from(s))
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if n > MAX_CLIPBOARD_BYTES {
            return Err(ProtoError::OutOfRange);
        }
        self.take(n)
    }
    fn dim(&mut self) -> Result<u32, ProtoError> {
        let v = self.u32()?;
        if v == 0 || v > MAX_DIMENSION {
            return Err(ProtoError::OutOfRange);
        }
        Ok(v)
    }
    fn id(&mut self) -> Result<u32, ProtoError> {
        match self.u32()? {
            0 => Err(ProtoError::OutOfRange),
            v => Ok(v),
        }
    }
    fn end(&self) -> Result<(), ProtoError> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(ProtoError::BadPayload)
        }
    }
}

/// Splits a message into (opcode, serial, payload) after checking the header.
pub fn parse_header(msg: &[u8]) -> Result<(u16, u32, &[u8]), ProtoError> {
    if msg.len() < HEADER_LEN {
        return Err(ProtoError::BadLength);
    }
    if msg.len() > MAX_MESSAGE {
        return Err(ProtoError::TooLarge);
    }
    let opcode = u16::from_le_bytes([msg[0], msg[1]]);
    let reserved = u16::from_le_bytes([msg[2], msg[3]]);
    let len = u32::from_le_bytes(msg[4..8].try_into().map_err(|_| ProtoError::BadLength)?) as usize;
    let serial = u32::from_le_bytes(msg[8..12].try_into().map_err(|_| ProtoError::BadLength)?);
    let reserved2 = u32::from_le_bytes(msg[12..16].try_into().map_err(|_| ProtoError::BadLength)?);
    if reserved != 0 || reserved2 != 0 {
        return Err(ProtoError::BadHeader);
    }
    if len != msg.len() - HEADER_LEN {
        return Err(ProtoError::BadLength);
    }
    Ok((opcode, serial, &msg[HEADER_LEN..]))
}

fn rect(r: &mut Reader) -> Result<Rect, ProtoError> {
    let x = r.i32()?;
    let y = r.i32()?;
    let w = r.u32()?;
    let h = r.u32()?;
    if w > MAX_DIMENSION || h > MAX_DIMENSION {
        return Err(ProtoError::OutOfRange);
    }
    Ok(Rect { x, y, w, h })
}

fn clip_entries(w: &mut Writer, entries: &[ClipEntry]) {
    let n = entries.len().min(MAX_CLIPBOARD);
    w.u8(n as u8);
    for e in &entries[..n] {
        w.u32(e.format);
        match &e.name {
            Some(name) => {
                w.u8(1).str(name, MAX_TITLE);
            }
            None => {
                w.u8(0);
            }
        }
        w.u32(e.data.len() as u32).raw(&e.data);
    }
}

fn read_clip_entries(r: &mut Reader) -> Result<Vec<ClipEntry>, ProtoError> {
    let n = r.u8()? as usize;
    if n > MAX_CLIPBOARD {
        return Err(ProtoError::OutOfRange);
    }
    let mut entries = Vec::with_capacity(n);
    let mut total = 0usize;
    for _ in 0..n {
        let format = r.u32()?;
        let name = match r.u8()? {
            0 => None,
            1 => Some(r.str(MAX_TITLE)?),
            _ => return Err(ProtoError::BadValue),
        };
        let len = r.u32()? as usize;
        total += len;
        if total > MAX_CLIPBOARD_BYTES {
            return Err(ProtoError::OutOfRange);
        }
        entries.push(ClipEntry { format, name, data: r.bytes(len)?.to_vec() });
    }
    Ok(entries)
}

impl Request {
    pub fn opcode(&self) -> u16 {
        use opcode::*;
        match self {
            Request::Hello { .. } => HELLO,
            Request::CreateSurface { .. } => CREATE_SURFACE,
            Request::DestroySurface { .. } => DESTROY_SURFACE,
            Request::CreateWindow { .. } => CREATE_WINDOW,
            Request::DestroyWindow { .. } => DESTROY_WINDOW,
            Request::AttachBuffer { .. } => ATTACH_BUFFER,
            Request::Damage { .. } => DAMAGE,
            Request::Commit { .. } => COMMIT_SURFACE,
            Request::SetTitle { .. } => SET_TITLE,
            Request::SetGeometry { .. } => SET_GEOMETRY,
            Request::Sync { .. } => SYNC,
            Request::SetWindowVisibility { .. } => SET_WINDOW_VISIBILITY,
            Request::WindowAction { .. } => WINDOW_ACTION,
            Request::Notify { .. } => NOTIFY,
            Request::DestroyBuffer { .. } => DESTROY_BUFFER,
            Request::ClipboardSet { .. } => CLIPBOARD_SET,
            Request::FileDrag { .. } => FILE_DRAG,
        }
    }

    pub fn encode(&self, serial: u32) -> Vec<u8> {
        let mut w = Writer::new(self.opcode(), serial);
        match self {
            Request::Hello { min_version, max_version, flags, name } => {
                w.u16(*min_version).u16(*max_version).u32(*flags).str(name, MAX_TITLE);
            }
            Request::CreateSurface { surface } | Request::DestroySurface { surface } | Request::Commit { surface } => {
                w.u32(*surface);
            }
            Request::CreateWindow { window, surface, parent, role, flags, x, y, width, height, min_width, min_height, title } => {
                w.u32(*window)
                    .u32(*surface)
                    .u32(*parent)
                    .u8(*role as u8)
                    .u32(*flags)
                    .i32(*x)
                    .i32(*y)
                    .u32(*width)
                    .u32(*height)
                    .u32(*min_width)
                    .u32(*min_height)
                    .str(title, MAX_TITLE);
            }
            Request::DestroyWindow { window } => {
                w.u32(*window);
            }
            Request::DestroyBuffer { buffer } => {
                w.u32(*buffer);
            }
            Request::AttachBuffer { surface, buffer, width, height, stride, format, offset } => {
                w.u32(*surface).u32(*buffer).u32(*width).u32(*height).u32(*stride).u32(*format).u32(*offset);
            }
            Request::Damage { surface, rect } => {
                w.u32(*surface).i32(rect.x).i32(rect.y).u32(rect.w).u32(rect.h);
            }
            Request::SetTitle { window, title } => {
                w.u32(*window).str(title, MAX_TITLE);
            }
            Request::SetGeometry { window, x, y, width, height } => {
                w.u32(*window).i32(*x).i32(*y).u32(*width).u32(*height);
            }
            Request::WindowAction { target, action, global } => {
                w.u32(*target).u8(*action as u8).u8(u8::from(*global));
            }
            Request::SetWindowVisibility { window, visible, taskbar } => {
                w.u32(*window).u8(u8::from(*visible)).u8(u8::from(*taskbar));
            }
            Request::Notify { title, body } => {
                w.str(title, MAX_TITLE).str(body, MAX_TEXT);
            }
            Request::Sync { cookie } => { w.u32(*cookie); }
            Request::ClipboardSet { entries } => {
                clip_entries(&mut w, entries);
            }
            Request::FileDrag { window, path } => { w.u32(*window).str(path, MAX_TEXT); }
        }
        w.finish()
    }

    /// Decodes and validates one message; returns it with its serial.
    pub fn decode(msg: &[u8]) -> Result<(Request, u32), ProtoError> {
        let (op, serial, payload) = parse_header(msg)?;
        let mut r = Reader { b: payload };
        let req = match op {
            opcode::HELLO => {
                let min_version = r.u16()?;
                let max_version = r.u16()?;
                if min_version == 0 || min_version > max_version {
                    return Err(ProtoError::BadValue);
                }
                Request::Hello { min_version, max_version, flags: r.u32()?, name: r.str(MAX_TITLE)? }
            }
            opcode::CREATE_SURFACE => Request::CreateSurface { surface: r.id()? },
            opcode::DESTROY_SURFACE => Request::DestroySurface { surface: r.id()? },
            opcode::COMMIT_SURFACE => Request::Commit { surface: r.id()? },
            opcode::CREATE_WINDOW => {
                let window = r.id()?;
                let surface = r.id()?;
                let parent = r.u32()?;
                let role = Role::from_raw(r.u8()?).ok_or(ProtoError::BadValue)?;
                let flags = r.u32()?;
                if flags & !window_flags::ALL != 0 {
                    return Err(ProtoError::BadValue);
                }
                let x = r.i32()?;
                let y = r.i32()?;
                let width = r.dim()?;
                let height = r.dim()?;
                let min_width = r.u32()?;
                let min_height = r.u32()?;
                if min_width > MAX_DIMENSION || min_height > MAX_DIMENSION {
                    return Err(ProtoError::OutOfRange);
                }
                Request::CreateWindow { window, surface, parent, role, flags, x, y, width, height, min_width, min_height, title: r.str(MAX_TITLE)? }
            }
            opcode::DESTROY_WINDOW => Request::DestroyWindow { window: r.id()? },
            opcode::ATTACH_BUFFER => {
                let surface = r.id()?;
                let buffer = r.id()?;
                let width = r.dim()?;
                let height = r.dim()?;
                let stride = r.u32()?;
                let format = r.u32()?;
                let offset = r.u32()?;
                if format != format::XRGB8888 && format != format::ARGB8888 {
                    return Err(ProtoError::BadValue);
                }
                if (stride as u64) < width as u64 * 4 || stride % 4 != 0 || offset % 4 != 0 {
                    return Err(ProtoError::OutOfRange);
                }
                Request::AttachBuffer { surface, buffer, width, height, stride, format, offset }
            }
            opcode::DESTROY_BUFFER => Request::DestroyBuffer { buffer: r.id()? },
            opcode::DAMAGE => Request::Damage { surface: r.id()?, rect: rect(&mut r)? },
            opcode::SET_TITLE => Request::SetTitle { window: r.id()?, title: r.str(MAX_TITLE)? },
            opcode::SET_WINDOW_VISIBILITY => Request::SetWindowVisibility { window: r.id()?, visible: r.bool()?, taskbar: r.bool()? },
            opcode::SET_GEOMETRY => {
                Request::SetGeometry { window: r.id()?, x: r.i32()?, y: r.i32()?, width: r.dim()?, height: r.dim()? }
            }
            opcode::WINDOW_ACTION => {
                let target = r.id()?;
                let action = Action::from_raw(r.u8()?).ok_or(ProtoError::BadValue)?;
                Request::WindowAction { target, action, global: r.bool()? }
            }
            opcode::NOTIFY => Request::Notify { title: r.str(MAX_TITLE)?, body: r.str(MAX_TEXT)? },
            opcode::SYNC => Request::Sync { cookie: r.u32()? },
            opcode::CLIPBOARD_SET => Request::ClipboardSet { entries: read_clip_entries(&mut r)? },
            opcode::FILE_DRAG => Request::FileDrag { window: r.id()?, path: r.str(MAX_TEXT)? },
            op => return Err(ProtoError::UnknownOpcode(op)),
        };
        r.end()?;
        Ok((req, serial))
    }
}

impl Event {
    pub fn opcode(&self) -> u16 {
        use opcode::*;
        match self {
            Event::Hello { .. } => EV_HELLO,
            Event::Configure { .. } => CONFIGURE,
            Event::FocusChanged { .. } => FOCUS_CHANGED,
            Event::Key { .. } => KEY_EVENT,
            Event::Pointer { .. } => POINTER_EVENT,
            Event::CloseRequest { .. } => CLOSE_REQUEST,
            Event::BufferRelease { .. } => BUFFER_RELEASE,
            Event::FrameDone { .. } => FRAME_DONE,
            Event::WindowList { .. } => WINDOW_LIST,
            Event::Notification { .. } => NOTIFICATION,
            Event::ClipboardChanged { .. } => CLIPBOARD_CHANGED,
            Event::FileDrop { .. } => FILE_DROP,
            Event::Error { .. } => ERROR,
            Event::SyncDone { .. } => SYNC_DONE,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let serial = match self {
            Event::Error { serial, .. } => *serial,
            _ => 0,
        };
        let mut w = Writer::new(self.opcode(), serial);
        match self {
            Event::SyncDone { cookie } => { w.u32(*cookie); }
            Event::Hello { version, client_id, flags, screen_width, screen_height } => {
                w.u16(*version).u32(*client_id).u32(*flags).u32(*screen_width).u32(*screen_height);
            }
            Event::Configure { window, width, height, states } => {
                w.u32(*window).u32(*width).u32(*height).u32(*states);
            }
            Event::FocusChanged { window, focused } => {
                w.u32(*window).u8(u8::from(*focused));
            }
            Event::Key { window, usage, state, modifiers, text } => {
                w.u32(*window).u16(*usage).u8(*state).u32(*modifiers).u32(text.map_or(0, |c| c as u32));
            }
            Event::Pointer {
                window, kind, x, y, screen_x, screen_y, button, pressed, wheel_v, wheel_h, buttons, modifiers,
            } => {
                w.u32(*window)
                    .u8(*kind)
                    .i32(*x)
                    .i32(*y)
                    .i32(*screen_x)
                    .i32(*screen_y)
                    .u16(*button)
                    .u8(u8::from(*pressed))
                    .i32(*wheel_v)
                    .i32(*wheel_h)
                    .u32(*buttons)
                    .u32(*modifiers);
            }
            Event::CloseRequest { window } => {
                w.u32(*window);
            }
            Event::BufferRelease { surface } => {
                w.u32(*surface);
            }
            Event::FrameDone { surface, time_ms } => {
                w.u32(*surface).u64(*time_ms);
            }
            Event::WindowList { windows } => {
                let n = windows.len().min(MAX_LIST);
                w.u16(n as u16);
                for e in &windows[..n] {
                    w.u32(e.id).u32(e.pid).u32(e.flags).str(&e.title, MAX_TITLE);
                }
            }
            Event::Notification { from_pid, title, body } => {
                w.u32(*from_pid).str(title, MAX_TITLE).str(body, MAX_TEXT);
            }
            Event::ClipboardChanged { seq, entries } => {
                w.u32(*seq);
                clip_entries(&mut w, entries);
            }
            Event::FileDrop { window, x, y, path } => { w.u32(*window).i32(*x).i32(*y).str(path, MAX_TEXT); }
            Event::Error { code, message, .. } => {
                w.u32(*code).str(message, MAX_TEXT);
            }
        }
        w.finish()
    }

    pub fn decode(msg: &[u8]) -> Result<Event, ProtoError> {
        let (op, serial, payload) = parse_header(msg)?;
        let mut r = Reader { b: payload };
        let ev = match op {
            opcode::SYNC_DONE => Event::SyncDone { cookie: r.u32()? },
            opcode::EV_HELLO => Event::Hello {
                version: r.u16()?,
                client_id: r.u32()?,
                flags: r.u32()?,
                screen_width: r.u32()?,
                screen_height: r.u32()?,
            },
            opcode::CONFIGURE => Event::Configure { window: r.u32()?, width: r.dim()?, height: r.dim()?, states: r.u32()? },
            opcode::FOCUS_CHANGED => Event::FocusChanged { window: r.u32()?, focused: r.bool()? },
            opcode::KEY_EVENT => {
                let window = r.u32()?;
                let usage = r.u16()?;
                let state = r.u8()?;
                if state > key_state::REPEAT {
                    return Err(ProtoError::BadValue);
                }
                let modifiers = r.u32()?;
                let text = match r.u32()? {
                    0 => None,
                    c => Some(char::from_u32(c).ok_or(ProtoError::BadValue)?),
                };
                Event::Key { window, usage, state, modifiers, text }
            }
            opcode::POINTER_EVENT => {
                let window = r.u32()?;
                let kind = r.u8()?;
                if kind > pointer::WHEEL {
                    return Err(ProtoError::BadValue);
                }
                Event::Pointer {
                    window,
                    kind,
                    x: r.i32()?,
                    y: r.i32()?,
                    screen_x: r.i32()?,
                    screen_y: r.i32()?,
                    button: r.u16()?,
                    pressed: r.bool()?,
                    wheel_v: r.i32()?,
                    wheel_h: r.i32()?,
                    buttons: r.u32()?,
                    modifiers: r.u32()?,
                }
            }
            opcode::CLOSE_REQUEST => Event::CloseRequest { window: r.u32()? },
            opcode::BUFFER_RELEASE => Event::BufferRelease { surface: r.u32()? },
            opcode::FRAME_DONE => Event::FrameDone { surface: r.u32()?, time_ms: r.u64()? },
            opcode::WINDOW_LIST => {
                let n = r.u16()? as usize;
                if n > MAX_LIST {
                    return Err(ProtoError::OutOfRange);
                }
                let mut windows = Vec::with_capacity(n);
                for _ in 0..n {
                    windows.push(WindowInfo { id: r.u32()?, pid: r.u32()?, flags: r.u32()?, title: r.str(MAX_TITLE)? });
                }
                Event::WindowList { windows }
            }
            opcode::NOTIFICATION => Event::Notification { from_pid: r.u32()?, title: r.str(MAX_TITLE)?, body: r.str(MAX_TEXT)? },
            opcode::CLIPBOARD_CHANGED => Event::ClipboardChanged { seq: r.u32()?, entries: read_clip_entries(&mut r)? },
            opcode::FILE_DROP => Event::FileDrop { window: r.id()?, x: r.i32()?, y: r.i32()?, path: r.str(MAX_TEXT)? },
            opcode::ERROR => Event::Error { code: r.u32()?, serial, message: r.str(MAX_TEXT)? },
            op => return Err(ProtoError::UnknownOpcode(op)),
        };
        r.end()?;
        Ok(ev)
    }
}

/// Negotiates the version for a client offering `min..=max`.
pub fn negotiate(min: u16, max: u16) -> Option<u16> {
    let v = max.min(VERSION);
    (v >= min && v >= MIN_VERSION).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn sample_requests() -> Vec<Request> {
        vec![
            Request::Hello { min_version: 1, max_version: 3, flags: hello::SHELL, name: "osyx-desktop".to_string() },
            Request::CreateSurface { surface: 1 },
            Request::DestroySurface { surface: 9 },
            Request::CreateWindow {
                window: 2,
                surface: 1,
                parent: 0,
                role: Role::Normal,
                flags: window_flags::RESIZABLE | window_flags::DECORATED,
                x: -20,
                y: 40,
                width: 640,
                height: 480,
                min_width: 200,
                min_height: 120,
                title: "Files — /home/żółw".to_string(),
            },
            Request::DestroyWindow { window: 2 },
            Request::AttachBuffer { surface: 1, buffer: 3, width: 640, height: 480, stride: 2560, format: format::ARGB8888, offset: 0 },
            Request::DestroyBuffer { buffer: 3 },
            Request::Damage { surface: 1, rect: Rect { x: 0, y: -3, w: 640, h: 20 } },
            Request::Commit { surface: 1 },
            Request::SetTitle { window: 2, title: String::new() },
            Request::SetWindowVisibility { window: 2, visible: false, taskbar: false },
            Request::SetGeometry { window: 2, x: 5, y: 6, width: 300, height: 200 },
            Request::Sync { cookie: 42 },
            Request::WindowAction { target: 77, action: Action::ToggleMaximize, global: true },
            Request::Notify { title: "Build".to_string(), body: "done".to_string() },
            Request::ClipboardSet {
                entries: vec![
                    ClipEntry { format: 13, name: None, data: vec![b'h', 0, b'i', 0, 0, 0] },
                    ClipEntry { format: 0xC001, name: Some("HTML Format".to_string()), data: b"<b>x</b>".to_vec() },
                ],
            },
        ]
    }

    fn sample_events() -> Vec<Event> {
        vec![
            Event::SyncDone { cookie: 42 },
            Event::Hello { version: 1, client_id: 4, flags: 1, screen_width: 1280, screen_height: 800 },
            Event::Configure { window: 2, width: 800, height: 600, states: state::ACTIVATED | state::MAXIMIZED },
            Event::FocusChanged { window: 2, focused: true },
            Event::Key { window: 2, usage: 0x04, state: key_state::DOWN, modifiers: 0x40, text: Some('ą') },
            Event::Key { window: 2, usage: 0x28, state: key_state::UP, modifiers: 0, text: None },
            Event::Pointer {
                window: 2,
                kind: pointer::BUTTON,
                x: 10,
                y: -2,
                screen_x: 210,
                screen_y: 98,
                button: 1,
                pressed: true,
                wheel_v: 0,
                wheel_h: 0,
                buttons: 1,
                modifiers: 0,
            },
            Event::CloseRequest { window: 2 },
            Event::BufferRelease { surface: 1 },
            Event::FrameDone { surface: 1, time_ms: 1 << 40 },
            Event::WindowList {
                windows: vec![
                    WindowInfo { id: 1, pid: 7, flags: state::ACTIVATED, title: "Terminal".to_string() },
                    WindowInfo { id: 3, pid: 9, flags: state::MINIMIZED, title: "Files".to_string() },
                ],
            },
            Event::Notification { from_pid: 9, title: "Copied".to_string(), body: "3 files".to_string() },
            Event::ClipboardChanged { seq: 3, entries: Vec::new() },
            Event::ClipboardChanged {
                seq: 4,
                entries: vec![ClipEntry { format: 1, name: None, data: b"plain".to_vec() }],
            },
            Event::Error { code: error::MALFORMED, serial: 42, message: "bad payload".to_string() },
        ]
    }

    #[test]
    fn requests_round_trip() {
        for (i, r) in sample_requests().into_iter().enumerate() {
            let bytes = r.encode(i as u32 + 100);
            assert!(bytes.len() <= MAX_MESSAGE);
            assert_eq!(Request::decode(&bytes), Ok((r, i as u32 + 100)));
        }
    }

    #[test]
    fn events_round_trip() {
        for e in sample_events() {
            let bytes = e.encode();
            assert_eq!(Event::decode(&bytes), Ok(e));
        }
    }

    #[test]
    fn header_validation() {
        let good = Request::Commit { surface: 1 }.encode(0);
        assert_eq!(parse_header(&good[..15]), Err(ProtoError::BadLength));
        let mut bad = good.clone();
        bad[4] = 9;
        assert_eq!(Request::decode(&bad), Err(ProtoError::BadLength));
        let mut bad = good.clone();
        bad[2] = 1;
        assert_eq!(Request::decode(&bad), Err(ProtoError::BadHeader));
        let mut bad = good.clone();
        bad[13] = 1;
        assert_eq!(Request::decode(&bad), Err(ProtoError::BadHeader));
        let mut bad = good.clone();
        bad[0] = 0x7F;
        assert_eq!(Request::decode(&bad), Err(ProtoError::UnknownOpcode(0x7F)));
        // Trailing byte with a consistent header.
        let mut bad = good.clone();
        bad.push(0);
        bad[4] += 1;
        assert_eq!(Request::decode(&bad), Err(ProtoError::BadPayload));
        let huge = vec![0u8; MAX_MESSAGE + 1];
        assert_eq!(parse_header(&huge), Err(ProtoError::TooLarge));
        // An event is not a request.
        assert!(matches!(Request::decode(&Event::CloseRequest { window: 1 }.encode()), Err(ProtoError::UnknownOpcode(_))));
    }

    #[test]
    fn payload_validation() {
        let mk = |r: Request| r.encode(0);
        let w = |width: u32, height: u32| {
            mk(Request::CreateWindow {
                window: 1,
                surface: 1,
                parent: 0,
                role: Role::Normal,
                flags: 0,
                x: 0,
                y: 0,
                width,
                height,
                min_width: 0,
                min_height: 0,
                title: String::new(),
            })
        };
        assert_eq!(Request::decode(&w(0, 10)), Err(ProtoError::OutOfRange));
        assert_eq!(Request::decode(&w(10, MAX_DIMENSION + 1)), Err(ProtoError::OutOfRange));
        assert!(Request::decode(&w(MAX_DIMENSION, 1)).is_ok());
        // Id 0 is reserved.
        assert_eq!(Request::decode(&mk(Request::Commit { surface: 0 })), Err(ProtoError::OutOfRange));
        // Stride too small for the width, unknown format, misaligned offset.
        let ab = |stride, format, offset| mk(Request::AttachBuffer { surface: 1, buffer: 1, width: 10, height: 10, stride, format, offset });
        assert_eq!(Request::decode(&ab(39, format::XRGB8888, 0)), Err(ProtoError::OutOfRange));
        assert_eq!(Request::decode(&ab(40, 3, 0)), Err(ProtoError::BadValue));
        assert_eq!(Request::decode(&ab(40, format::XRGB8888, 2)), Err(ProtoError::OutOfRange));
        assert!(Request::decode(&ab(40, format::XRGB8888, 4)).is_ok());
        // Bad enum values.
        let mut m = w(10, 10);
        m[HEADER_LEN + 12] = 9; // role
        assert_eq!(Request::decode(&m), Err(ProtoError::BadValue));
        let mut m = mk(Request::WindowAction { target: 1, action: Action::Close, global: false });
        m[HEADER_LEN + 4] = 6;
        assert_eq!(Request::decode(&m), Err(ProtoError::BadValue));
        let mut m = mk(Request::WindowAction { target: 1, action: Action::Close, global: false });
        m[HEADER_LEN + 5] = 2;
        assert_eq!(Request::decode(&m), Err(ProtoError::BadValue));
        // Version range.
        let h = mk(Request::Hello { min_version: 2, max_version: 1, flags: 0, name: String::new() });
        assert_eq!(Request::decode(&h), Err(ProtoError::BadValue));
        // Unknown window flags.
        let mut m = w(10, 10);
        m[HEADER_LEN + 13] = 0x80;
        assert_eq!(Request::decode(&m), Err(ProtoError::BadValue));
    }

    #[test]
    fn strings_are_bounded_and_utf8() {
        let long = "x".repeat(MAX_TITLE + 50);
        let m = Request::SetTitle { window: 1, title: long }.encode(0);
        let (r, _) = Request::decode(&m).unwrap();
        assert_eq!(r, Request::SetTitle { window: 1, title: "x".repeat(MAX_TITLE) }, "encoder truncates");
        // Truncation never splits a character.
        let polish = "ż".repeat(200);
        let (r, _) = Request::decode(&Request::SetTitle { window: 1, title: polish }.encode(0)).unwrap();
        let Request::SetTitle { title, .. } = r else { panic!() };
        assert_eq!(title.chars().count(), MAX_TITLE / 2);
        // A forged length beyond the limit, and invalid UTF-8.
        let mut m = Request::SetTitle { window: 1, title: "ab".to_string() }.encode(0);
        m[HEADER_LEN + 4..HEADER_LEN + 6].copy_from_slice(&(MAX_TITLE as u16 + 1).to_le_bytes());
        assert_eq!(Request::decode(&m), Err(ProtoError::BadString));
        let mut m = Request::SetTitle { window: 1, title: "ab".to_string() }.encode(0);
        m[HEADER_LEN + 6] = 0xFF;
        assert_eq!(Request::decode(&m), Err(ProtoError::BadString));
        // Text that is a surrogate code point is rejected.
        let mut m = Event::Key { window: 1, usage: 4, state: 1, modifiers: 0, text: Some('a') }.encode();
        let n = m.len();
        m[n - 4..].copy_from_slice(&0xD800u32.to_le_bytes());
        assert_eq!(Event::decode(&m), Err(ProtoError::BadValue));
    }

    #[test]
    fn file_clipboard_round_trips_and_rejects_bad_paths() {
        let paths = vec![String::from("/home/user/a\nb"), String::from("/tmp/ż")];
        let entry = clipboard_files_entry(&paths, true).unwrap();
        assert_eq!(clipboard_file_effect(&[entry.clone()]), Some(2u32.to_le_bytes().to_vec()));
        assert_eq!(clipboard_file_effect(&[clipboard_files_entry(&paths, false).unwrap()]), Some(1u32.to_le_bytes().to_vec()));
        let hdrop = clipboard_hdrop(&[entry.clone()]).unwrap();
        assert_eq!(&hdrop[..4], &20u32.to_le_bytes());
        assert_eq!(&hdrop[16..20], &1u32.to_le_bytes());
        let units: Vec<u16> = hdrop[20..].chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        assert_eq!(units, "C:\\home\\user\\a\nb\0C:\\tmp\\ż\0\0".encode_utf16().collect::<Vec<_>>());
        let windows = ClipEntry { format: 15, name: None, data: hdrop };
        assert_eq!(clipboard_files(&[windows.clone()]), Some((paths.clone(), false)));
        let effect = ClipEntry { format: 0xc001, name: Some(String::from("Preferred DropEffect")), data: 2u32.to_le_bytes().to_vec() };
        assert_eq!(clipboard_files(&[windows, effect]), Some((paths.clone(), true)));
        let mut invalid = alloc::vec![0u8; 20];
        invalid[0..4].copy_from_slice(&20u32.to_le_bytes());
        invalid[16..20].copy_from_slice(&1u32.to_le_bytes());
        for u in "C:\\..\\secret\0\0".encode_utf16() { invalid.extend_from_slice(&u.to_le_bytes()); }
        let invalid = ClipEntry { format: 15, name: None, data: invalid };
        assert_eq!(clipboard_files(&[invalid]), None);
        let mut invalid = alloc::vec![0u8; 20];
        invalid[0..4].copy_from_slice(&20u32.to_le_bytes());
        invalid[16..20].copy_from_slice(&1u32.to_le_bytes());
        for u in "C:\\name:stream\0\0".encode_utf16() { invalid.extend_from_slice(&u.to_le_bytes()); }
        assert_eq!(clipboard_files(&[ClipEntry { format: 15, name: None, data: invalid }]), None);
        let invalid = clipboard_files_entry(&[String::from("/tmp/a\\b")], false).unwrap();
        assert!(clipboard_hdrop(&[invalid]).is_none());
        assert_eq!(clipboard_files(&[entry.clone()]), Some((paths, true)));
        let mut broken = entry;
        broken.data.pop();
        assert_eq!(clipboard_files(&[broken]), None);
        assert!(clipboard_files_entry(&[String::from("relative")], false).is_none());
    }

    #[test]
    fn unicode_clipboard_text_round_trips_and_is_bounded() {
        let entry = clipboard_text_entry("Zażółć 🌍");
        assert_eq!(clipboard_text(&[entry]), Some(String::from("Zażółć 🌍")));
        let entry = clipboard_text_entry(&"🌍".repeat(MAX_CLIPBOARD_BYTES));
        assert!(entry.data.len() <= MAX_CLIPBOARD_BYTES);
        assert!(clipboard_text(&[entry]).unwrap().chars().all(|c| c == '🌍'));
        let malformed = ClipEntry { format: CLIP_UNICODE_TEXT, name: None, data: vec![1] };
        assert_eq!(clipboard_text(&[malformed]), None);
        let ansi = ClipEntry { format: 1, name: None, data: b"test\0ignored".to_vec() };
        assert_eq!(clipboard_text(&[ansi]).as_deref(), Some("test"));
        let unicode = clipboard_text_entry("Zażółć");
        assert_eq!(clipboard_text_format(&[unicode], 1), Some("Zażółć\0".as_bytes().to_vec()));
        let ansi = ClipEntry { format: 1, name: None, data: b"test\0".to_vec() };
        assert_eq!(clipboard_text_format(&[ansi], CLIP_UNICODE_TEXT), Some(clipboard_text_entry("test").data));
    }

    #[test]
    fn clipboard_contents_are_bounded() {
        let entries = |n: usize| (0..n as u32).map(|format| ClipEntry { format, name: None, data: vec![b'x'; 4] }).collect();
        assert!(Request::decode(&Request::ClipboardSet { entries: entries(MAX_CLIPBOARD) }.encode(0)).is_ok(), "the cap itself fits");
        // The encoder drops formats past the cap instead of breaking framing.
        let (r, _) = Request::decode(&Request::ClipboardSet { entries: entries(MAX_CLIPBOARD + 3) }.encode(0)).unwrap();
        let Request::ClipboardSet { entries: kept } = r else { panic!() };
        assert_eq!(kept.len(), MAX_CLIPBOARD);
        // A forged format count over the cap.
        let mut m = Request::ClipboardSet { entries: entries(1) }.encode(0);
        m[HEADER_LEN] = MAX_CLIPBOARD as u8 + 1;
        assert_eq!(Request::decode(&m), Err(ProtoError::OutOfRange));
        // A forged data length over the payload cap.
        let mut m = Request::ClipboardSet { entries: entries(1) }.encode(0);
        m[HEADER_LEN + 6..HEADER_LEN + 10].copy_from_slice(&(MAX_CLIPBOARD_BYTES as u32 + 1).to_le_bytes());
        assert_eq!(Request::decode(&m), Err(ProtoError::OutOfRange));
    }

    #[test]
    fn truncations_and_mutations_never_panic() {
        let mut all: Vec<Vec<u8>> = sample_requests().iter().map(|r| r.encode(1)).collect();
        all.extend(sample_events().iter().map(|e| e.encode()));
        for m in &all {
            for cut in 0..m.len() {
                let _ = Request::decode(&m[..cut]);
                let _ = Event::decode(&m[..cut]);
            }
            for i in 0..m.len() {
                for v in [0u8, 1, 0x7F, 0x80, 0xFF] {
                    let mut x = m.clone();
                    x[i] = v;
                    let _ = Request::decode(&x);
                    let _ = Event::decode(&x);
                }
            }
        }
    }

    #[test]
    fn window_list_limit() {
        let many = (0..MAX_LIST as u32 + 10).map(|i| WindowInfo { id: i + 1, pid: 1, flags: 0, title: String::new() }).collect();
        let Ok(Event::WindowList { windows }) = Event::decode(&Event::WindowList { windows: many }.encode()) else { panic!() };
        assert_eq!(windows.len(), MAX_LIST);
        let mut m = Event::WindowList { windows: vec![] }.encode();
        m[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&(MAX_LIST as u16 + 1).to_le_bytes());
        assert_eq!(Event::decode(&m), Err(ProtoError::OutOfRange));
    }

    #[test]
    fn version_negotiation() {
        assert_eq!(negotiate(1, 1), Some(1));
        assert_eq!(negotiate(1, 5), Some(VERSION));
        assert_eq!(negotiate(2, 5), None);
        assert_eq!(negotiate(0, 0), None);
    }
}
