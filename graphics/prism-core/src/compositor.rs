//! The compositor: clients, surfaces, windows, input routing and
//! composition.
//!
//! The platform drives it with four calls: [`Compositor::handle`] for each
//! client message (with the shared memory buffer it carried, if any),
//! [`Compositor::input`] for each input event, [`Compositor::render`] to
//! recompose the damaged screen areas into a back buffer, and
//! [`Compositor::take_messages`] to collect the encoded events to send.
//! Time is passed in explicitly (milliseconds of a monotonic clock).
//!
//! Isolation rules enforced here:
//! * a client only ever names its own objects (ids are per client);
//! * buffers are read through bounds-checked views and copied at commit,
//!   so a client cannot change what is on screen afterwards nor make the
//!   compositor read outside its buffer;
//! * shell-only roles and global window actions need the shell role,
//!   which the platform grants to one process (see [`Compositor::set_shell_pid`]);
//! * per-client limits bound surfaces, windows, buffers and pixel memory.

use crate::damage::Damage;
use crate::draw::{self, corner, Cursor, CursorShape, Pixels, ShadowTables};
use crate::theme;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use osyx_gfx::{PropFont, Rect, Surface};
use osyx_input::layout::Layout;
use osyx_input::{key, kind, modifier, InputEvent};
use prism_proto::{self as proto, window_flags, Action, Event, Request, Role};

pub type ClientId = u32;
pub type WindowId = u32;

static TITLE_FONT: &[u8] = include_bytes!("../../assets/sans14b.osxp");

/// A client's shared buffer as the compositor sees it (mapped read-only).
pub trait PixelSource {
    /// The whole buffer as 32-bit words.
    fn words(&self) -> &[u32];
}

impl PixelSource for Vec<u32> {
    fn words(&self) -> &[u32] {
        self
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub width: u32,
    pub height: u32,
    pub layout: Layout,
    pub max_surfaces: usize,
    pub max_windows: usize,
    pub max_buffers: usize,
    /// Pixels of committed surface content a client may hold.
    pub max_client_pixels: usize,
    pub max_notifications: u32,
}

impl Config {
    pub fn new(width: u32, height: u32) -> Config {
        Config {
            width,
            height,
            layout: Layout::Us,
            max_surfaces: 32,
            max_windows: 32,
            max_buffers: 16,
            max_client_pixels: 24 * 1024 * 1024 / 4 * 4,
            max_notifications: 64,
        }
    }
}

/// Why a client is being disconnected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: u32,
    pub message: String,
}

fn err<T>(code: u32, message: &str) -> Result<T, ProtocolError> {
    Err(ProtocolError { code, message: message.to_string() })
}

#[derive(Clone, Copy)]
struct Attached {
    buffer: u32,
    width: u32,
    height: u32,
    stride_px: u32,
    offset_px: u32,
    alpha: bool,
}

struct SurfaceState {
    width: u32,
    height: u32,
    pixels: Vec<u32>,
    alpha: bool,
    attached: Option<Attached>,
    damage: Vec<proto::Rect>,
    damage_all: bool,
    frame_pending: bool,
    window: Option<WindowId>,
}

struct Client {
    pid: u32,
    name: String,
    version: Option<u16>,
    shell: bool,
    surfaces: BTreeMap<u32, SurfaceState>,
    buffers: BTreeMap<u32, Box<dyn PixelSource>>,
    windows: BTreeMap<u32, WindowId>,
    notifications: u32,
    dead: bool,
}

impl Client {
    fn pixels_held(&self) -> usize {
        self.surfaces.values().map(|s| s.pixels.len()).sum()
    }
}

/// Edges of a resize grab.
pub mod edge {
    pub const LEFT: u8 = 1;
    pub const RIGHT: u8 = 2;
    pub const TOP: u8 = 4;
    pub const BOTTOM: u8 = 8;
}

/// What the pointer is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Content,
    Title,
    Close,
    Maximize,
    Minimize,
    Resize(u8),
}

#[derive(Clone, Copy, Debug)]
struct Fade {
    start: u64,
    from: u32,
    to: u32,
    dur: u64,
}

impl Fade {
    fn value(&self, now: u64) -> u32 {
        let t = now.saturating_sub(self.start).min(self.dur);
        let span = self.to as i64 - self.from as i64;
        // Ease out: 1 - (1 - t)^2.
        let x = t as i64 * 256 / self.dur.max(1) as i64;
        let eased = 256 - (256 - x) * (256 - x) / 256;
        (self.from as i64 + span * eased / 256) as u32
    }

    fn done(&self, now: u64) -> bool {
        now >= self.start + self.dur
    }
}

struct Window {
    id: WindowId,
    client: ClientId,
    local: u32,
    surface: u32,
    parent: Option<WindowId>,
    role: Role,
    title: String,
    resizable: bool,
    decorated: bool,
    skip_taskbar: bool,
    shown: bool,
    /// Content rectangle in screen coordinates (the configured size).
    rect: Rect,
    min_w: u32,
    min_h: u32,
    maximized: bool,
    minimized: bool,
    restore: Rect,
    mapped: bool,
    fade: Option<Fade>,
    seq: u64,
}

impl Window {
    fn layer(&self) -> u8 {
        match self.role {
            Role::Desktop => 0,
            Role::Normal => 1,
            Role::Panel => 2,
            Role::Popup => 3,
            Role::Notification => 4,
            Role::Lock => 5,
        }
    }

    fn title_height(&self) -> u32 {
        if self.decorated {
            theme::TITLE_HEIGHT
        } else {
            0
        }
    }

    /// Content plus title bar.
    fn frame(&self) -> Rect {
        let t = self.title_height();
        Rect::new(self.rect.x, self.rect.y - t as i32, self.rect.w, self.rect.h + t)
    }

    fn has_shadow(&self) -> bool {
        matches!(self.role, Role::Normal | Role::Popup | Role::Notification)
    }

    /// Everything drawing this window can touch (frame, shadow, resize border).
    fn bounds(&self) -> Rect {
        let f = self.frame();
        if self.has_shadow() {
            f.inflate(theme::SHADOW as i32 + 2).union(&Rect::new(f.x, f.y + theme::SHADOW_OFFSET_Y, f.w, f.h).inflate(theme::SHADOW as i32 + 2))
        } else {
            f
        }
    }

    fn visible(&self) -> bool {
        self.mapped && self.shown && !self.minimized
    }

    fn opacity(&self, now: u64) -> u32 {
        self.fade.map_or(256, |f| f.value(now))
    }

    fn states(&self, focused: bool) -> u32 {
        let mut s = 0;
        if self.maximized {
            s |= proto::state::MAXIMIZED;
        }
        if focused {
            s |= proto::state::ACTIVATED;
        }
        if self.minimized {
            s |= proto::state::MINIMIZED;
        }
        s
    }

    /// Screen rectangles of the minimize, maximize and close buttons.
    fn buttons(&self) -> [(Part, Rect); 3] {
        let f = self.frame();
        let size = theme::BUTTON;
        let y = f.y + ((theme::TITLE_HEIGHT - size) / 2) as i32;
        let right = f.x + f.w as i32 - theme::BUTTON_MARGIN as i32;
        let at = |i: i32| Rect::new(right - (i + 1) * size as i32 - i * theme::BUTTON_GAP as i32, y, size, size);
        [(Part::Minimize, at(2)), (Part::Maximize, at(1)), (Part::Close, at(0))]
    }
}

/// A destroyed window fading out: a snapshot of its last content.
struct Ghost {
    rect: Rect,
    decorated: bool,
    title: String,
    pixels: Vec<u32>,
    width: u32,
    height: u32,
    alpha: bool,
    fade: Fade,
}

impl Ghost {
    fn bounds(&self) -> Rect {
        let t = if self.decorated { theme::TITLE_HEIGHT } else { 0 };
        let f = Rect::new(self.rect.x, self.rect.y - t as i32, self.rect.w, self.rect.h + t);
        f.inflate(theme::SHADOW as i32 + 2).union(&Rect::new(f.x, f.y + theme::SHADOW_OFFSET_Y, f.w, f.h).inflate(theme::SHADOW as i32 + 2))
    }
}

#[derive(Clone, Copy, Debug)]
enum Grab {
    Move { win: WindowId, dx: i32, dy: i32 },
    Resize { win: WindowId, edges: u8, start: Rect, px: i32, py: i32 },
    Content { win: WindowId },
    Button { win: WindowId, part: Part },
}

/// Composition statistics (for measuring, not guessing, performance).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub frames: u64,
    pub pixels: u64,
    pub commits: u64,
    pub input_events: u64,
}

/// A snapshot of one window for tests and diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowSnapshot {
    pub id: WindowId,
    pub client: ClientId,
    pub local: u32,
    pub role: Role,
    pub title: String,
    pub rect: Rect,
    pub maximized: bool,
    pub minimized: bool,
    pub mapped: bool,
}

pub struct Compositor {
    cfg: Config,
    screen: Rect,
    clients: BTreeMap<ClientId, Client>,
    next_client: ClientId,
    windows: BTreeMap<WindowId, Window>,
    next_window: WindowId,
    next_seq: u64,
    /// Bottom to top.
    stack: Vec<WindowId>,
    focus: Option<WindowId>,
    /// Normal windows, most recently focused first (Alt+Tab order).
    mru: Vec<WindowId>,
    ptr_x: i32,
    ptr_y: i32,
    buttons: u32,
    hover: Option<(WindowId, Part)>,
    pointer_in: Option<WindowId>,
    grab: Option<Grab>,
    file_drag: Option<(WindowId, String, i32, i32)>,
    modifiers: u32,
    damage: Damage,
    ghosts: Vec<Ghost>,
    outbox: Vec<(ClientId, Event)>,
    list_dirty: bool,
    shell_pid: Option<u32>,
    cursor: Cursor,
    cursor_overlay: bool,
    shadow: ShadowTables,
    popup_shadow: ShadowTables,
    font: PropFont<'static>,
    last_title_click: Option<(WindowId, u64)>,
    alt_tab: Option<usize>,
    cascade: i32,
    now: u64,
    stats: Stats,
    /// The system clipboard, shared by every client; `clipboard_seq` is 0
    /// until something is put there.
    clipboard: Vec<proto::ClipEntry>,
    clipboard_seq: u32,
    /// PrintScreen was pressed; the platform saves the next frame.
    screenshot_requested: bool,
}

const DOUBLE_CLICK_MS: u64 = 400;
const MAX_DAMAGE_PER_SURFACE: usize = 32;

impl Compositor {
    pub fn new(cfg: Config) -> Compositor {
        let screen = Rect::new(0, 0, cfg.width, cfg.height);
        let mut c = Compositor {
            cfg,
            screen,
            clients: BTreeMap::new(),
            next_client: 1,
            windows: BTreeMap::new(),
            next_window: 1,
            next_seq: 1,
            stack: Vec::new(),
            focus: None,
            mru: Vec::new(),
            ptr_x: (cfg.width / 2) as i32,
            ptr_y: (cfg.height / 2) as i32,
            buttons: 0,
            hover: None,
            pointer_in: None,
            grab: None,
            file_drag: None,
            modifiers: 0,
            damage: Damage::new(),
            ghosts: Vec::new(),
            outbox: Vec::new(),
            list_dirty: false,
            shell_pid: None,
            cursor: Cursor::new(CursorShape::Arrow),
            cursor_overlay: false,
            clipboard: Vec::new(),
            clipboard_seq: 0,
            shadow: ShadowTables::new(theme::SHADOW, theme::RADIUS),
            popup_shadow: ShadowTables::new(12, theme::RADIUS),
            font: PropFont::parse(TITLE_FONT).expect("embedded title font"),
            last_title_click: None,
            alt_tab: None,
            screenshot_requested: false,
            cascade: 0,
            now: 0,
            stats: Stats::default(),
        };
        c.damage.add(screen, screen);
        c
    }

    pub fn screen(&self) -> Rect {
        self.screen
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn set_layout(&mut self, layout: Layout) {
        self.cfg.layout = layout;
    }

    /// The process allowed to take the shell role.
    pub fn set_shell_pid(&mut self, pid: Option<u32>) {
        self.shell_pid = pid;
    }

    pub fn pointer(&self) -> (i32, i32) {
        (self.ptr_x, self.ptr_y)
    }

    /// The platform can draw the small cursor overlay independently of the
    /// application frame deadline. Cursor motion then causes no composition.
    pub fn set_cursor_overlay(&mut self, enabled: bool) { self.cursor_overlay = enabled; }

    pub fn cursor_state(&self) -> (i32, i32, CursorShape) { (self.ptr_x, self.ptr_y, self.cursor.shape) }

    pub fn cursor_area(&self) -> Rect { self.cursor.area(self.ptr_x, self.ptr_y).intersect(&self.screen) }

    pub fn draw_cursor_overlay(&self, target: &mut Surface) { self.cursor.draw(target, self.ptr_x, self.ptr_y, self.screen); }

    pub fn focused(&self) -> Option<WindowId> {
        self.focus
    }

    /// Windows bottom to top.
    pub fn snapshot(&self) -> Vec<WindowSnapshot> {
        self.stack
            .iter()
            .filter_map(|id| self.windows.get(id))
            .map(|w| WindowSnapshot {
                id: w.id,
                client: w.client,
                local: w.local,
                role: w.role,
                title: w.title.clone(),
                rect: w.rect,
                maximized: w.maximized,
                minimized: w.minimized,
                mapped: w.mapped,
            })
            .collect()
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// (surfaces, buffers, windows, pixels) held for a client.
    pub fn client_resources(&self, c: ClientId) -> Option<(usize, usize, usize, usize)> {
        self.clients.get(&c).map(|cl| (cl.surfaces.len(), cl.buffers.len(), cl.windows.len(), cl.pixels_held()))
    }

    pub fn client_pid(&self, c: ClientId) -> Option<u32> {
        self.clients.get(&c).map(|cl| cl.pid)
    }

    // ---- clients ---------------------------------------------------------------

    /// A new connection from process `pid`.
    pub fn connect(&mut self, pid: u32) -> ClientId {
        let id = self.next_client;
        self.next_client += 1;
        self.clients.insert(
            id,
            Client {
                pid,
                name: String::new(),
                version: None,
                shell: false,
                surfaces: BTreeMap::new(),
                buffers: BTreeMap::new(),
                windows: BTreeMap::new(),
                notifications: 0,
                dead: false,
            },
        );
        id
    }

    /// Removes a client and everything it owns (its windows fade out).
    pub fn disconnect(&mut self, c: ClientId) {
        let Some(cl) = self.clients.get(&c) else { return };
        let wins: Vec<WindowId> = cl.windows.values().copied().collect();
        for w in wins {
            self.destroy_window(w, true);
        }
        if self.file_drag.as_ref().is_some_and(|(id, _, _, _)| !self.windows.contains_key(id)) { self.file_drag = None; }
        self.clients.remove(&c);
        self.outbox.retain(|(to, _)| *to != c);
        if let Some(Grab::Content { win } | Grab::Move { win, .. } | Grab::Resize { win, .. } | Grab::Button { win, .. }) = self.grab {
            if !self.windows.contains_key(&win) {
                self.grab = None;
            }
        }
    }

    /// True if the client broke the protocol and must be disconnected once
    /// its error event has been sent.
    pub fn is_dead(&self, c: ClientId) -> bool {
        self.clients.get(&c).is_none_or(|cl| cl.dead)
    }

    /// Handles one message from client `c`. `buffer` is the shared memory
    /// the message carried (only meaningful for `ATTACH_BUFFER`). On a
    /// protocol violation an `ERROR` event is queued and the error is
    /// returned; the platform then flushes and disconnects the client.
    pub fn handle(&mut self, c: ClientId, msg: &[u8], buffer: Option<Box<dyn PixelSource>>, now: u64) -> Result<(), ProtocolError> {
        self.now = now;
        if self.is_dead(c) {
            return err(proto::error::NOT_ALLOWED, "client is disconnected");
        }
        let r = match Request::decode(msg) {
            Ok((req, serial)) => self.apply(c, req, buffer).map_err(|e| (e, serial)),
            Err(e) => Err((ProtocolError { code: proto::error::MALFORMED, message: alloc::format!("{e:?}") }, 0)),
        };
        if let Err((e, serial)) = r {
            self.outbox.push((c, Event::Error { code: e.code, serial, message: e.message.clone() }));
            if let Some(cl) = self.clients.get_mut(&c) {
                cl.dead = true;
            }
            return Err(e);
        }
        Ok(())
    }

    fn send(&mut self, c: ClientId, e: Event) {
        if self.clients.get(&c).is_some_and(|cl| !cl.dead) {
            self.outbox.push((c, e));
        }
    }

    /// Encoded events to deliver, in order.
    pub fn take_messages(&mut self) -> Vec<(ClientId, Vec<u8>)> {
        if self.list_dirty {
            self.list_dirty = false;
            let list = self.window_list();
            let shells: Vec<ClientId> = self.clients.iter().filter(|(_, cl)| cl.shell && !cl.dead).map(|(id, _)| *id).collect();
            for s in shells {
                self.outbox.push((s, Event::WindowList { windows: list.clone() }));
            }
        }
        core::mem::take(&mut self.outbox).into_iter().map(|(c, e)| (c, e.encode())).collect()
    }

    fn window_list(&self) -> Vec<proto::WindowInfo> {
        let mut v: Vec<&Window> = self.windows.values()
            .filter(|w| w.role == Role::Normal && w.shown && !w.skip_taskbar && (w.mapped || w.minimized)).collect();
        v.sort_by_key(|w| w.seq);
        v.into_iter()
            .map(|w| proto::WindowInfo {
                id: w.id,
                pid: self.clients.get(&w.client).map_or(0, |c| c.pid),
                flags: w.states(self.focus_owned_by(w.id)),
                title: w.title.clone(),
            })
            .collect()
    }

    fn focus_owned_by(&self, owner: WindowId) -> bool {
        let mut current = self.focus;
        for _ in 0..self.windows.len() {
            let Some(id) = current else { return false };
            if id == owner { return true; }
            current = self.windows.get(&id).and_then(|w| w.parent);
        }
        false
    }

    // ---- protocol ----------------------------------------------------------------

    fn apply(&mut self, c: ClientId, req: Request, buffer: Option<Box<dyn PixelSource>>) -> Result<(), ProtocolError> {
        let initialised = self.clients.get(&c).is_some_and(|cl| cl.version.is_some());
        if !initialised && !matches!(req, Request::Hello { .. }) {
            return err(proto::error::NOT_INITIALISED, "HELLO must be the first message");
        }
        if buffer.is_some() && !matches!(req, Request::AttachBuffer { .. }) {
            return err(proto::error::MALFORMED, "only ATTACH_BUFFER carries a buffer");
        }
        match req {
            Request::Hello { min_version, max_version, flags, name } => {
                if initialised {
                    return err(proto::error::MALFORMED, "duplicate HELLO");
                }
                let version = proto::negotiate(min_version, max_version)
                    .ok_or_else(|| ProtocolError { code: proto::error::BAD_VERSION, message: "no common protocol version".to_string() })?;
                let cl = self.clients.get_mut(&c).expect("client exists");
                cl.version = Some(version);
                cl.name = name;
                let wants_shell = flags & proto::hello::SHELL != 0;
                cl.shell = wants_shell && self.shell_pid == Some(cl.pid);
                let granted = if cl.shell { proto::hello::SHELL } else { 0 };
                self.send(
                    c,
                    Event::Hello { version, client_id: c, flags: granted, screen_width: self.screen.w, screen_height: self.screen.h },
                );
                let (seq, entries) = (self.clipboard_seq, self.clipboard.clone());
                self.send(c, Event::ClipboardChanged { seq, entries });
                if granted != 0 {
                    self.list_dirty = true;
                }
                Ok(())
            }
            Request::CreateSurface { surface } => {
                let max = self.cfg.max_surfaces;
                let cl = self.clients.get_mut(&c).expect("client exists");
                if cl.surfaces.contains_key(&surface) {
                    return err(proto::error::DUPLICATE_ID, "surface id in use");
                }
                if cl.surfaces.len() >= max {
                    return err(proto::error::LIMIT, "too many surfaces");
                }
                cl.surfaces.insert(
                    surface,
                    SurfaceState {
                        width: 0,
                        height: 0,
                        pixels: Vec::new(),
                        alpha: false,
                        attached: None,
                        damage: Vec::new(),
                        damage_all: false,
                        frame_pending: false,
                        window: None,
                    },
                );
                Ok(())
            }
            Request::DestroySurface { surface } => {
                let cl = self.clients.get_mut(&c).expect("client exists");
                let s = cl.surfaces.remove(&surface).ok_or_else(unknown)?;
                if let Some(w) = s.window {
                    self.destroy_window(w, true);
                }
                Ok(())
            }
            Request::CreateWindow { window, surface, parent, role, flags, x, y, width, height, min_width, min_height, title } => {
                self.create_window(c, window, surface, parent, role, flags, (x, y, width, height), (min_width, min_height), title)
            }
            Request::DestroyWindow { window } => {
                let id = self.local_window(c, window)?;
                self.destroy_window(id, true);
                Ok(())
            }
            Request::AttachBuffer { surface, buffer: buf_id, width, height, stride, format, offset } => {
                let max_buffers = self.cfg.max_buffers;
                let cl = self.clients.get_mut(&c).expect("client exists");
                if !cl.surfaces.contains_key(&surface) {
                    return err(proto::error::UNKNOWN_OBJECT, "unknown surface");
                }
                if let Some(b) = buffer {
                    if !cl.buffers.contains_key(&buf_id) && cl.buffers.len() >= max_buffers {
                        return err(proto::error::LIMIT, "too many buffers");
                    }
                    cl.buffers.insert(buf_id, b);
                }
                let words = cl.buffers.get(&buf_id).ok_or_else(|| ProtocolError {
                    code: proto::error::UNKNOWN_OBJECT,
                    message: "unknown buffer".to_string(),
                })?;
                let stride_px = stride / 4;
                let offset_px = offset / 4;
                let needed = (offset_px as u64) + (stride_px as u64) * (height as u64 - 1) + width as u64;
                if needed > words.words().len() as u64 {
                    return err(proto::error::BAD_BUFFER, "buffer smaller than its geometry");
                }
                let s = cl.surfaces.get_mut(&surface).expect("checked above");
                s.attached =
                    Some(Attached { buffer: buf_id, width, height, stride_px, offset_px, alpha: format == proto::format::ARGB8888 });
                Ok(())
            }
            Request::DestroyBuffer { buffer } => {
                let cl = self.clients.get_mut(&c).expect("client exists");
                cl.buffers.remove(&buffer).ok_or_else(unknown)?;
                for s in cl.surfaces.values_mut() {
                    if s.attached.is_some_and(|a| a.buffer == buffer) {
                        s.attached = None;
                    }
                }
                Ok(())
            }
            Request::Damage { surface, rect } => {
                let cl = self.clients.get_mut(&c).expect("client exists");
                let s = cl.surfaces.get_mut(&surface).ok_or_else(unknown)?;
                if s.damage.len() >= MAX_DAMAGE_PER_SURFACE {
                    s.damage_all = true;
                } else if rect.w > 0 && rect.h > 0 {
                    s.damage.push(rect);
                }
                Ok(())
            }
            Request::Commit { surface } => self.commit(c, surface),
            Request::SetTitle { window, title } => {
                let id = self.local_window(c, window)?;
                let w = self.windows.get_mut(&id).expect("window exists");
                if w.title != title {
                    w.title = title;
                    let f = w.frame();
                    let tb = Rect::new(f.x, f.y, f.w, theme::TITLE_HEIGHT);
                    if w.decorated {
                        self.damage.add(tb, self.screen);
                    }
                    self.list_dirty = true;
                }
                Ok(())
            }
            Request::SetGeometry { window, x, y, width, height } => {
                let id = self.local_window(c, window)?;
                self.set_geometry(id, x, y, width, height);
                Ok(())
            }
            Request::Sync { cookie } => {
                self.send(c, Event::SyncDone { cookie });
                Ok(())
            }
            Request::SetWindowVisibility { window, visible, taskbar } => {
                let id = self.local_window(c, window)?;
                let w = self.windows.get_mut(&id).expect("window exists");
                let was_shown = w.shown;
                self.damage.add(w.bounds(), self.screen);
                w.shown = visible;
                w.skip_taskbar = !taskbar;
                self.list_dirty = true;
                if !visible && self.focus == Some(id) {
                    self.set_focus(self.next_focus_candidate());
                } else if visible && !was_shown && taskbar {
                    self.set_focus(Some(id));
                }
                Ok(())
            }
            Request::WindowAction { target, action, global } => {
                let id = if global {
                    if !self.clients.get(&c).is_some_and(|cl| cl.shell) {
                        return err(proto::error::NOT_ALLOWED, "global window actions need the shell role");
                    }
                    if !self.windows.contains_key(&target) {
                        // The window may have closed meanwhile: not an error.
                        return Ok(());
                    }
                    target
                } else {
                    self.local_window(c, target)?
                };
                self.window_action(id, action);
                Ok(())
            }
            Request::FileDrag { window, path } => {
                let id = self.local_window(c, window)?;
                if matches!(self.grab, Some(Grab::Content { win }) if win == id)
                    && self.buttons & 1 != 0 && path.starts_with('/') && !path.contains('\0') && !path.is_empty() {
                    self.file_drag = Some((id, path, self.ptr_x, self.ptr_y));
                }
                Ok(())
            }
            Request::ClipboardSet { entries } => {
                self.clipboard = entries;
                self.clipboard_seq += 1;
                let ev = Event::ClipboardChanged { seq: self.clipboard_seq, entries: self.clipboard.clone() };
                let ids: Vec<ClientId> =
                    self.clients.iter().filter(|(_, cl)| cl.version.is_some() && !cl.dead).map(|(id, _)| *id).collect();
                for id in ids {
                    self.outbox.push((id, ev.clone()));
                }
                Ok(())
            }
            Request::Notify { title, body } => {
                let max = self.cfg.max_notifications;
                let cl = self.clients.get_mut(&c).expect("client exists");
                if cl.notifications >= max {
                    return Ok(()); // quietly dropped: rate limit
                }
                cl.notifications += 1;
                let from_pid = cl.pid;
                let shells: Vec<ClientId> = self.clients.iter().filter(|(_, cl)| cl.shell).map(|(id, _)| *id).collect();
                for s in shells {
                    self.send(s, Event::Notification { from_pid, title: title.clone(), body: body.clone() });
                }
                Ok(())
            }
        }
    }

    fn local_window(&self, c: ClientId, local: u32) -> Result<WindowId, ProtocolError> {
        self.clients.get(&c).and_then(|cl| cl.windows.get(&local)).copied().ok_or_else(unknown)
    }

    /// The area normal windows may use: the screen minus panels at its edges.
    pub fn work_area(&self) -> Rect {
        let mut wa = self.screen;
        for w in self.windows.values().filter(|w| w.role == Role::Panel && w.visible()) {
            let r = w.rect;
            if r.w * 2 < self.screen.w {
                continue; // a small panel does not reserve an edge
            }
            if r.bottom() >= self.screen.bottom() && r.y > self.screen.h as i32 / 2 {
                wa.h = wa.h.min((r.y - wa.y).max(0) as u32);
            } else if r.y <= 0 {
                let top = r.bottom() as i32;
                wa.h = wa.h.saturating_sub((top - wa.y).max(0) as u32);
                wa.y = wa.y.max(top);
            }
        }
        wa
    }

    #[allow(clippy::too_many_arguments)]
    fn create_window(
        &mut self,
        c: ClientId,
        local: u32,
        surface: u32,
        parent: u32,
        role: Role,
        flags: u32,
        (x, y, width, height): (i32, i32, u32, u32),
        (min_w, min_h): (u32, u32),
        title: String,
    ) -> Result<(), ProtocolError> {
        let max_windows = self.cfg.max_windows;
        let cl = self.clients.get(&c).expect("client exists");
        if cl.windows.contains_key(&local) {
            return err(proto::error::DUPLICATE_ID, "window id in use");
        }
        if cl.windows.len() >= max_windows {
            return err(proto::error::LIMIT, "too many windows");
        }
        let s = cl.surfaces.get(&surface).ok_or_else(unknown)?;
        if s.window.is_some() {
            return err(proto::error::DUPLICATE_ID, "surface already has a window");
        }
        if role.shell_only() && !cl.shell {
            return err(proto::error::NOT_ALLOWED, "this role needs the shell role");
        }
        let parent_id = match parent {
            0 => None,
            p => Some(*cl.windows.get(&p).ok_or_else(unknown)?),
        };
        if role == Role::Popup && parent_id.is_none() && !cl.shell {
            return err(proto::error::NOT_ALLOWED, "popups need a parent window");
        }
        let decorated = role == Role::Normal && flags & window_flags::DECORATED != 0;
        let resizable = role == Role::Normal && flags & window_flags::RESIZABLE != 0;
        let wa = self.work_area();
        let t = if decorated { theme::TITLE_HEIGHT } else { 0 };
        let (mut w, mut h) = (width.min(self.screen.w), height.min(self.screen.h));
        let rect = match role {
            Role::Desktop | Role::Lock => self.screen,
            Role::Panel | Role::Notification => Rect::new(x, y, w, h),
            Role::Popup => {
                let origin = parent_id.and_then(|p| self.windows.get(&p)).map_or((0, 0), |p| (p.rect.x, p.rect.y));
                let mut r = Rect::new(origin.0.saturating_add(x), origin.1.saturating_add(y), w, h);
                // Keep popups on screen.
                r.x = r.x.min(self.screen.right() as i32 - w as i32).max(0);
                r.y = r.y.min(self.screen.bottom() as i32 - h as i32).max(0);
                r
            }
            Role::Normal => {
                w = w.min(wa.w).max(min_w.min(wa.w)).max(1);
                h = h.min(wa.h.saturating_sub(t)).max(min_h.min(wa.h)).max(1);
                let (px, py) = if x >= 0 && y >= 0 {
                    (x, y.max(t as i32))
                } else {
                    // Cascade from the top-left of the work area.
                    let step = 32 * (self.cascade % 8);
                    self.cascade += 1;
                    let cx = wa.x + 80 + step;
                    let cy = wa.y + 56 + step + t as i32;
                    (cx.min(wa.right() as i32 - w as i32).max(wa.x), cy.min(wa.bottom() as i32 - h as i32).max(wa.y + t as i32))
                };
                Rect::new(px, py, w, h)
            }
        };
        let id = self.next_window;
        self.next_window += 1;
        let seq = self.next_seq;
        self.next_seq += 1;
        let mut win = Window {
            id,
            client: c,
            local,
            surface,
            parent: parent_id,
            role,
            title,
            resizable,
            decorated,
            skip_taskbar: flags & window_flags::SKIP_TASKBAR != 0,
            shown: flags & window_flags::HIDDEN == 0,
            rect,
            min_w: min_w.max(if decorated { 160 } else { 1 }),
            min_h: min_h.max(if decorated { 48 } else { 1 }),
            maximized: false,
            minimized: false,
            restore: rect,
            mapped: false,
            fade: None,
            seq,
        };
        if role == Role::Normal && flags & window_flags::MAXIMIZED != 0 {
            win.maximized = true;
            win.rect = Rect::new(wa.x, wa.y + t as i32, wa.w, wa.h.saturating_sub(t).max(1));
        }
        let configure = Event::Configure { window: local, width: win.rect.w, height: win.rect.h, states: win.states(false) };
        let layer = win.layer();
        self.windows.insert(id, win);
        let pos = self.stack.iter().position(|o| self.windows[o].layer() > layer).unwrap_or(self.stack.len());
        self.stack.insert(pos, id);
        let cl = self.clients.get_mut(&c).expect("client exists");
        cl.windows.insert(local, id);
        cl.surfaces.get_mut(&surface).expect("checked above").window = Some(id);
        self.send(c, configure);
        if role == Role::Normal {
            self.mru.insert(0, id);
            self.list_dirty = true;
        }
        if flags & window_flags::HIDDEN == 0 && matches!(role, Role::Normal | Role::Popup) {
            self.set_focus(Some(id));
        }
        Ok(())
    }

    fn destroy_window(&mut self, id: WindowId, animate: bool) {
        // Popups belonging to the window go first.
        let children: Vec<WindowId> = self.windows.values().filter(|w| w.parent == Some(id)).map(|w| w.id).collect();
        for ch in children {
            self.destroy_window(ch, false);
        }
        let Some(w) = self.windows.remove(&id) else { return };
        self.stack.retain(|&s| s != id);
        self.mru.retain(|&s| s != id);
        self.damage.add(w.bounds(), self.screen);
        if let Some(cl) = self.clients.get_mut(&w.client) {
            cl.windows.remove(&w.local);
            if let Some(s) = cl.surfaces.get_mut(&w.surface) {
                s.window = None;
                if animate && w.visible() && w.role == Role::Normal && !s.pixels.is_empty() {
                    self.ghosts.push(Ghost {
                        rect: w.rect,
                        decorated: w.decorated,
                        title: w.title.clone(),
                        pixels: s.pixels.clone(),
                        width: s.width,
                        height: s.height,
                        alpha: s.alpha,
                        fade: Fade { start: self.now, from: w.opacity(self.now), to: 0, dur: theme::FADE_OUT_MS },
                    });
                }
            }
        }
        if self.file_drag.as_ref().is_some_and(|(source, _, _, _)| *source == id) { self.file_drag = None; }
        if self.pointer_in == Some(id) {
            self.pointer_in = None;
        }
        if self.hover.is_some_and(|(h, _)| h == id) {
            self.hover = None;
        }
        if let Some(Grab::Content { win } | Grab::Move { win, .. } | Grab::Resize { win, .. } | Grab::Button { win, .. }) = self.grab {
            if win == id {
                self.grab = None;
            }
        }
        if w.role == Role::Normal {
            self.list_dirty = true;
        }
        if self.focus == Some(id) {
            self.focus = None;
            // A popup hands focus back to its parent, a window to the next one.
            let next = w.parent.filter(|p| self.windows.contains_key(p)).or_else(|| self.next_focus_candidate());
            self.set_focus(next);
        }
    }

    fn next_focus_candidate(&self) -> Option<WindowId> {
        self.mru.iter().copied().find(|id| self.windows.get(id).is_some_and(|w| w.visible()))
    }

    fn commit(&mut self, c: ClientId, surface: u32) -> Result<(), ProtocolError> {
        let max_pixels = self.cfg.max_client_pixels;
        let cl = self.clients.get_mut(&c).expect("client exists");
        let held_other: usize = cl.surfaces.iter().filter(|(id, _)| **id != surface).map(|(_, s)| s.pixels.len()).sum();
        let s = cl.surfaces.get_mut(&surface).ok_or_else(unknown)?;
        let a = s.attached.ok_or_else(|| ProtocolError { code: proto::error::BAD_BUFFER, message: "commit without a buffer".to_string() })?;
        let src = cl.buffers.get(&a.buffer).ok_or_else(unknown)?;
        let words = src.words();
        // Re-validate: the buffer may have been redefined since ATTACH.
        let needed = a.offset_px as u64 + a.stride_px as u64 * (a.height as u64 - 1) + a.width as u64;
        if needed > words.len() as u64 {
            return err(proto::error::BAD_BUFFER, "buffer smaller than its geometry");
        }
        let resized = s.width != a.width || s.height != a.height || s.pixels.is_empty();
        if resized {
            let n = a.width as usize * a.height as usize;
            if held_other + n > max_pixels {
                return err(proto::error::LIMIT, "surface memory limit exceeded");
            }
            s.width = a.width;
            s.height = a.height;
            s.pixels = vec![0; n];
        }
        let full = proto::Rect { x: 0, y: 0, w: a.width, h: a.height };
        let rects: Vec<proto::Rect> = if resized || s.damage_all || s.alpha != a.alpha {
            vec![full]
        } else {
            core::mem::take(&mut s.damage)
        };
        s.damage.clear();
        s.damage_all = false;
        s.alpha = a.alpha;
        let bounds = Rect::new(0, 0, a.width, a.height);
        let mut copied = Vec::with_capacity(rects.len());
        for r in rects {
            let r = Rect::new(r.x, r.y, r.w, r.h).intersect(&bounds);
            if r.is_empty() {
                continue;
            }
            for row in r.y..r.y + r.h as i32 {
                let src_start = a.offset_px as usize + row as usize * a.stride_px as usize + r.x as usize;
                let dst_start = row as usize * a.width as usize + r.x as usize;
                s.pixels[dst_start..dst_start + r.w as usize].copy_from_slice(&words[src_start..src_start + r.w as usize]);
            }
            copied.push(r);
        }
        s.frame_pending = true;
        let window = s.window;
        self.stats.commits += 1;
        self.send(c, Event::BufferRelease { surface });
        if let Some(wid) = window {
            let now = self.now;
            let w = self.windows.get_mut(&wid).expect("window of a surface exists");
            if !w.mapped {
                w.mapped = true;
                self.list_dirty = true;
                if w.role == Role::Normal || w.role == Role::Popup || w.role == Role::Notification {
                    w.fade = Some(Fade { start: now, from: 0, to: 256, dur: theme::FADE_IN_MS });
                }
                let b = w.bounds();
                self.damage.add(b, self.screen);
                if w.role == Role::Panel {
                    self.relayout_maximized();
                }
            } else {
                let origin = (w.rect.x, w.rect.y);
                let clip = w.rect;
                for r in copied {
                    self.damage.add(Rect::new(r.x + origin.0, r.y + origin.1, r.w, r.h).intersect(&clip), self.screen);
                }
                if resized {
                    let b = w.bounds();
                    self.damage.add(b, self.screen);
                }
            }
        }
        Ok(())
    }

    fn set_geometry(&mut self, id: WindowId, x: i32, y: i32, width: u32, height: u32) {
        let screen = self.screen;
        let wa = self.work_area();
        let Some(w) = self.windows.get(&id) else { return };
        let old = w.bounds();
        let (role, maximized, resizable, client, local) = (w.role, w.maximized, w.resizable, w.client, w.local);
        let parent_origin = w.parent.and_then(|p| self.windows.get(&p)).map(|p| (p.rect.x, p.rect.y));
        let w = self.windows.get_mut(&id).expect("window exists");
        match role {
            Role::Desktop | Role::Lock => return,
            Role::Panel | Role::Notification => w.rect = Rect::new(x, y, width.min(screen.w), height.min(screen.h)),
            Role::Popup => {
                let (ox, oy) = parent_origin.unwrap_or((0, 0));
                w.rect = Rect::new(ox.saturating_add(x), oy.saturating_add(y), width.min(screen.w), height.min(screen.h));
            }
            Role::Normal => {
                if maximized {
                    return;
                }
                let t = w.title_height();
                let nw = if resizable { width.max(w.min_w).min(wa.w) } else { w.rect.w };
                let nh = if resizable { height.max(w.min_h).min(wa.h.saturating_sub(t)) } else { w.rect.h };
                let py = if y == -1 { w.rect.y } else if y >= 0 { y.max(t as i32) } else { y };
                w.rect = Rect::new(if x == -1 { w.rect.x } else { x }, py, nw.max(1), nh.max(1));
            }
        }
        let (rw, rh, states) = (w.rect.w, w.rect.h, w.states(false));
        let new = w.bounds();
        self.damage.add(old, screen);
        self.damage.add(new, screen);
        let focused = self.focus == Some(id);
        self.send(client, Event::Configure { window: local, width: rw, height: rh, states: states | if focused { proto::state::ACTIVATED } else { 0 } });
        if role == Role::Panel {
            self.relayout_maximized();
        }
    }

    /// Re-fits maximized windows after the work area changed.
    fn relayout_maximized(&mut self) {
        let ids: Vec<WindowId> = self.windows.values().filter(|w| w.maximized).map(|w| w.id).collect();
        for id in ids {
            self.apply_maximize(id, true);
        }
    }

    fn apply_maximize(&mut self, id: WindowId, on: bool) {
        let wa = self.work_area();
        let screen = self.screen;
        let focused = self.focus == Some(id);
        let Some(w) = self.windows.get_mut(&id) else { return };
        if w.role != Role::Normal {
            return;
        }
        let old = w.bounds();
        if on {
            w.minimized = false;
            if !w.maximized {
                w.restore = w.rect;
            }
            let t = w.title_height();
            w.maximized = true;
            w.rect = Rect::new(wa.x, wa.y + t as i32, wa.w, wa.h.saturating_sub(t).max(1));
        } else if w.maximized {
            w.maximized = false;
            w.rect = w.restore;
        }
        let (client, local, rw, rh, states, new) = (w.client, w.local, w.rect.w, w.rect.h, w.states(focused), w.bounds());
        self.damage.add(old, screen);
        self.damage.add(new, screen);
        self.list_dirty = true;
        self.send(client, Event::Configure { window: local, width: rw, height: rh, states });
    }

    fn window_action(&mut self, id: WindowId, action: Action) {
        let Some(w) = self.windows.get(&id) else { return };
        let (client, local, maximized) = (w.client, w.local, w.maximized);
        match action {
            Action::Activate => {
                let was_minimized = self.windows.get(&id).is_some_and(|w| w.minimized);
                if let Some(w) = self.windows.get_mut(&id) {
                    if w.minimized {
                        w.minimized = false;
                        w.fade = Some(Fade { start: self.now, from: 64, to: 256, dur: theme::FADE_IN_MS });
                        let b = w.bounds();
                        self.damage.add(b, self.screen);
                        self.list_dirty = true;
                    }
                }
                self.raise(id);
                self.set_focus(Some(id));
                if was_minimized {
                    if let Some(w) = self.windows.get(&id) {
                        self.send(client, Event::Configure { window: local, width: w.rect.w, height: w.rect.h, states: w.states(true) });
                    }
                }
            }
            Action::Minimize => {
                if let Some(w) = self.windows.get_mut(&id) {
                    if w.role != Role::Normal || w.minimized {
                        return;
                    }
                    w.minimized = true;
                    let b = w.bounds();
                    self.damage.add(b, self.screen);
                    self.list_dirty = true;
                }
                if self.focus == Some(id) {
                    self.focus = None;
                    self.send(client, Event::FocusChanged { window: local, focused: false });
                    let next = self.next_focus_candidate();
                    self.set_focus(next);
                }
                if let Some(w) = self.windows.get(&id) {
                    self.send(client, Event::Configure { window: local, width: w.rect.w, height: w.rect.h, states: w.states(false) });
                }
            }
            Action::Maximize => self.apply_maximize(id, true),
            Action::Restore => {
                if self.windows.get(&id).is_some_and(|w| w.minimized) {
                    self.window_action(id, Action::Activate);
                } else {
                    self.apply_maximize(id, false);
                }
            }
            Action::ToggleMaximize => self.apply_maximize(id, !maximized),
            Action::Close => self.send(client, Event::CloseRequest { window: local }),
        }
    }

    fn raise(&mut self, id: WindowId) {
        let Some(w) = self.windows.get(&id) else { return };
        let layer = w.layer();
        let b = w.bounds();
        let Some(pos) = self.stack.iter().position(|&s| s == id) else { return };
        self.stack.remove(pos);
        let top_of_layer = self.stack.iter().position(|o| self.windows[o].layer() > layer).unwrap_or(self.stack.len());
        self.stack.insert(top_of_layer, id);
        if top_of_layer != pos {
            self.damage.add(b, self.screen);
        }
        // Its popups stay above it.
        let children: Vec<WindowId> = self.stack.iter().copied().filter(|c| self.windows[c].parent == Some(id)).collect();
        for ch in children {
            self.raise(ch);
        }
    }

    fn set_focus(&mut self, id: Option<WindowId>) {
        if self.focus == id {
            return;
        }
        if let Some(old) = self.focus.take() {
            if let Some(w) = self.windows.get(&old) {
                let (c, l, f) = (w.client, w.local, w.frame());
                self.damage.add(f.inflate(2), self.screen);
                self.send(c, Event::FocusChanged { window: l, focused: false });
            }
        }
        if let Some(new) = id {
            if let Some(w) = self.windows.get(&new) {
                let (c, l, f, role) = (w.client, w.local, w.frame(), w.role);
                self.damage.add(f.inflate(2), self.screen);
                self.send(c, Event::FocusChanged { window: l, focused: true });
                if role == Role::Normal {
                    self.mru.retain(|&m| m != new);
                    self.mru.insert(0, new);
                }
                self.focus = Some(new);
            }
        }
        self.list_dirty = true;
    }

    // ---- input ---------------------------------------------------------------------

    /// Routes one event from the input core.
    pub fn input(&mut self, ev: &InputEvent, now: u64) {
        self.now = now;
        self.stats.input_events += 1;
        self.modifiers = ev.modifiers;
        match ev.kind {
            kind::MOTION => self.pointer_motion(ev.value, ev.value2),
            kind::BUTTON => self.pointer_button(ev.code, ev.value != 0),
            kind::WHEEL => self.pointer_wheel(ev.value, ev.value2),
            kind::KEY => self.key(ev.code, ev.value),
            kind::DEVICE if ev.code == osyx_input::DEVICE_REMOVED && ev.value == osyx_input::class::MOUSE && self.buttons != 0 => {
                // A mouse vanished mid-drag: end grabs as if released.
                for b in 1..=5u16 {
                    if self.buttons & (1 << (b - 1)) != 0 {
                        self.pointer_button(b, false);
                    }
                }
            }
            _ => {}
        }
    }

    fn top_window_at(&self, x: i32, y: i32) -> Option<(WindowId, Part)> {
        for &id in self.stack.iter().rev() {
            let w = &self.windows[&id];
            if !w.visible() {
                continue;
            }
            let f = w.frame();
            let inside = |r: &Rect| x >= r.x && y >= r.y && (x as i64) < r.right() && (y as i64) < r.bottom();
            if w.resizable && !w.maximized {
                let outer = f.inflate(theme::RESIZE_BORDER as i32);
                if inside(&outer) && !inside(&f) {
                    let (right, bottom) = (f.right() as i32, f.bottom() as i32);
                    let grip = 16;
                    let mut e = 0;
                    if x < f.x {
                        e |= edge::LEFT;
                    } else if x >= right {
                        e |= edge::RIGHT;
                    }
                    if y < f.y {
                        e |= edge::TOP;
                    } else if y >= bottom {
                        e |= edge::BOTTOM;
                    }
                    // Corner grips extend a little along each edge.
                    if e == edge::LEFT || e == edge::RIGHT {
                        if y < f.y + grip {
                            e |= edge::TOP;
                        } else if y >= bottom - grip {
                            e |= edge::BOTTOM;
                        }
                    } else if e == edge::TOP || e == edge::BOTTOM {
                        if x < f.x + grip {
                            e |= edge::LEFT;
                        } else if x >= right - grip {
                            e |= edge::RIGHT;
                        }
                    }
                    return Some((id, Part::Resize(e)));
                }
            }
            if !inside(&f) {
                continue;
            }
            if w.decorated && y < w.rect.y {
                for (part, r) in w.buttons() {
                    if inside(&r) {
                        return Some((id, part));
                    }
                }
                return Some((id, Part::Title));
            }
            return Some((id, Part::Content));
        }
        None
    }

    fn set_cursor(&mut self, shape: CursorShape) {
        if self.cursor.shape != shape {
            let old = self.cursor.area(self.ptr_x, self.ptr_y);
            self.cursor = Cursor::new(shape);
            let new = self.cursor.area(self.ptr_x, self.ptr_y);
            if !self.cursor_overlay {
                self.damage.add(old, self.screen);
                self.damage.add(new, self.screen);
            }
        }
    }

    fn local_pos(&self, id: WindowId) -> (i32, i32) {
        let w = &self.windows[&id];
        (self.ptr_x - w.rect.x, self.ptr_y - w.rect.y)
    }

    fn pointer_event(&mut self, id: WindowId, kind: u8, button: u16, pressed: bool, wheel: (i32, i32)) {
        let (x, y) = self.local_pos(id);
        let w = &self.windows[&id];
        let (c, l) = (w.client, w.local);
        let (buttons, modifiers) = (self.buttons, self.modifiers);
        // Win32 code (Gecko's scroll targeting) needs the screen position:
        // GetMessagePos and WM_MOUSEWHEEL work in screen coordinates.
        let (screen_x, screen_y) = (self.ptr_x, self.ptr_y);
        self.send(
            c,
            Event::Pointer {
                window: l,
                kind,
                x,
                y,
                screen_x,
                screen_y,
                button,
                pressed,
                wheel_v: wheel.0,
                wheel_h: wheel.1,
                buttons,
                modifiers,
            },
        );
    }

    fn pointer_motion(&mut self, dx: i32, dy: i32) {
        let old = self.cursor.area(self.ptr_x, self.ptr_y);
        self.ptr_x = self.ptr_x.saturating_add(dx).clamp(0, self.screen.w as i32 - 1);
        self.ptr_y = self.ptr_y.saturating_add(dy).clamp(0, self.screen.h as i32 - 1);
        let new = self.cursor.area(self.ptr_x, self.ptr_y);
        if !self.cursor_overlay {
            self.damage.add(old, self.screen);
            self.damage.add(new, self.screen);
        }
        match self.grab {
            Some(Grab::Move { win, dx, dy }) => {
                let screen = self.screen;
                if let Some(w) = self.windows.get_mut(&win) {
                    let old = w.bounds();
                    let t = w.title_height() as i32;
                    let nx = self.ptr_x - dx;
                    // Keep the title bar reachable.
                    let ny = (self.ptr_y - dy).clamp(t, screen.h as i32 - 8);
                    if (nx, ny) != (w.rect.x, w.rect.y) {
                        w.rect.x = nx;
                        w.rect.y = ny;
                        let new = w.bounds();
                        self.damage.add(old, screen);
                        self.damage.add(new, screen);
                    }
                }
                return;
            }
            Some(Grab::Resize { win, edges, start, px, py }) => {
                self.resize_to(win, edges, start, self.ptr_x - px, self.ptr_y - py);
                return;
            }
            Some(Grab::Content { win }) => {
                if self.windows.contains_key(&win) {
                    self.pointer_event(win, proto::pointer::MOTION, 0, false, (0, 0));
                }
                return;
            }
            Some(Grab::Button { .. }) => {
                self.update_hover();
                return;
            }
            None => {}
        }
        self.update_hover();
        if let Some((id, Part::Content)) = self.hover {
            self.pointer_event(id, proto::pointer::MOTION, 0, false, (0, 0));
        }
    }

    /// Recomputes what is under the pointer: enter/leave events, button
    /// hover highlights and the cursor shape.
    fn update_hover(&mut self) {
        let hit = self.top_window_at(self.ptr_x, self.ptr_y);
        if hit != self.hover {
            for h in [self.hover, hit].into_iter().flatten() {
                if matches!(h.1, Part::Close | Part::Maximize | Part::Minimize) {
                    if let Some(w) = self.windows.get(&h.0) {
                        let f = w.frame();
                        self.damage.add(Rect::new(f.x, f.y, f.w, theme::TITLE_HEIGHT), self.screen);
                    }
                }
            }
            self.hover = hit;
        }
        let content = match hit {
            Some((id, Part::Content)) => Some(id),
            _ => None,
        };
        if content != self.pointer_in && !matches!(self.grab, Some(Grab::Content { .. })) {
            if let Some(old) = self.pointer_in.take() {
                if self.windows.contains_key(&old) {
                    self.pointer_event(old, proto::pointer::LEAVE, 0, false, (0, 0));
                }
            }
            if let Some(new) = content {
                self.pointer_event(new, proto::pointer::ENTER, 0, false, (0, 0));
            }
            self.pointer_in = content;
        }
        let shape = match hit {
            Some((_, Part::Resize(e))) => match e {
                e if e == edge::LEFT | edge::TOP || e == edge::RIGHT | edge::BOTTOM => CursorShape::ResizeNwse,
                e if e == edge::RIGHT | edge::TOP || e == edge::LEFT | edge::BOTTOM => CursorShape::ResizeNesw,
                e if e & (edge::LEFT | edge::RIGHT) != 0 => CursorShape::ResizeH,
                _ => CursorShape::ResizeV,
            },
            _ => CursorShape::Arrow,
        };
        let shape = if matches!(self.grab, Some(Grab::Move { .. })) { CursorShape::Move } else { shape };
        self.set_cursor(shape);
    }

    fn resize_to(&mut self, win: WindowId, edges: u8, start: Rect, dx: i32, dy: i32) {
        let screen = self.screen;
        let Some(w) = self.windows.get_mut(&win) else { return };
        let old = w.bounds();
        let (minw, minh) = (w.min_w as i32, w.min_h as i32);
        let (mut x0, mut y0, mut x1, mut y1) = (start.x, start.y, start.x + start.w as i32, start.y + start.h as i32);
        if edges & edge::LEFT != 0 {
            x0 = (x0 + dx).min(x1 - minw);
        }
        if edges & edge::RIGHT != 0 {
            x1 = (x1 + dx).max(x0 + minw);
        }
        if edges & edge::TOP != 0 {
            y0 = (y0 + dy).min(y1 - minh).max(w.title_height() as i32);
        }
        if edges & edge::BOTTOM != 0 {
            y1 = (y1 + dy).max(y0 + minh);
        }
        let r = Rect::new(x0, y0, (x1 - x0).clamp(1, proto::MAX_DIMENSION as i32) as u32, (y1 - y0).clamp(1, proto::MAX_DIMENSION as i32) as u32);
        if r == w.rect {
            return;
        }
        let size_changed = (r.w, r.h) != (w.rect.w, w.rect.h);
        w.rect = r;
        let (c, l, states, new) = (w.client, w.local, w.states(true) | proto::state::RESIZING, w.bounds());
        self.damage.add(old, screen);
        self.damage.add(new, screen);
        if size_changed {
            self.send(c, Event::Configure { window: l, width: r.w, height: r.h, states });
        }
    }

    fn close_popups_except(&mut self, keep: Option<WindowId>) {
        // A popup survives if the click hit it or one of its own popups.
        let keep_chain: Vec<WindowId> = {
            let mut v = Vec::new();
            let mut cur = keep;
            while let Some(id) = cur {
                v.push(id);
                cur = self.windows.get(&id).and_then(|w| w.parent);
            }
            v
        };
        let popups: Vec<(ClientId, u32, WindowId)> = self
            .windows
            .values()
            .filter(|w| w.role == Role::Popup && !keep_chain.contains(&w.id))
            .map(|w| (w.client, w.local, w.id))
            .collect();
        for (c, l, _) in popups {
            self.send(c, Event::CloseRequest { window: l });
        }
    }

    fn pointer_button(&mut self, button: u16, pressed: bool) {
        if button == 0 || button > 32 {
            return;
        }
        let bit = 1u32 << (button - 1);
        if pressed {
            self.buttons |= bit;
        } else {
            self.buttons &= !bit;
        }
        if !pressed {
            if button == 1 {
                if let Some((source, path, x, y)) = self.file_drag.take() {
                    if (self.ptr_x - x).abs().max((self.ptr_y - y).abs()) > 5 {
                        if let Some((id, Part::Content)) = self.top_window_at(self.ptr_x, self.ptr_y) {
                            if id != source {
                                if let Some(w) = self.windows.get(&id) {
                                    let (client, window, x, y) = (w.client, w.local, self.ptr_x - w.rect.x, self.ptr_y - w.rect.y);
                                    self.send(client, Event::FileDrop { window, x, y, path });
                                }
                            }
                        }
                    }
                }
            }
            match self.grab {
                Some(Grab::Content { win }) => {
                    if self.windows.contains_key(&win) {
                        self.pointer_event(win, proto::pointer::BUTTON, button, false, (0, 0));
                    }
                    if self.buttons == 0 {
                        self.grab = None;
                        self.update_hover();
                    }
                }
                Some(Grab::Button { win, part }) => {
                    self.grab = None;
                    let over = self.top_window_at(self.ptr_x, self.ptr_y);
                    if over == Some((win, part)) {
                        let action = match part {
                            Part::Close => Some(Action::Close),
                            Part::Maximize => Some(Action::ToggleMaximize),
                            Part::Minimize => Some(Action::Minimize),
                            _ => None,
                        };
                        if let Some(a) = action {
                            self.window_action(win, a);
                        }
                    }
                    if let Some(w) = self.windows.get(&win) {
                        let f = w.frame();
                        self.damage.add(Rect::new(f.x, f.y, f.w, theme::TITLE_HEIGHT), self.screen);
                    }
                    self.update_hover();
                }
                Some(Grab::Move { .. }) | Some(Grab::Resize { .. }) => {
                    if let Some(Grab::Resize { win, .. }) = self.grab {
                        // Final configure without the RESIZING state.
                        if let Some(w) = self.windows.get(&win) {
                            let (c, l, rw, rh, st) = (w.client, w.local, w.rect.w, w.rect.h, w.states(true));
                            self.send(c, Event::Configure { window: l, width: rw, height: rh, states: st });
                        }
                    }
                    self.grab = None;
                    self.update_hover();
                }
                None => {
                    if let Some((id, Part::Content)) = self.hover {
                        self.pointer_event(id, proto::pointer::BUTTON, button, false, (0, 0));
                    }
                }
            }
            return;
        }
        if let Some(Grab::Content { win }) = self.grab {
            // Further buttons during a drag go to the same window.
            if self.windows.contains_key(&win) {
                self.pointer_event(win, proto::pointer::BUTTON, button, true, (0, 0));
            }
            return;
        }
        if self.grab.is_some() {
            return;
        }
        let hit = self.top_window_at(self.ptr_x, self.ptr_y);
        self.close_popups_except(hit.map(|h| h.0));
        let Some((id, part)) = hit else {
            self.set_focus(None);
            return;
        };
        let role = self.windows[&id].role;
        match role {
            Role::Normal | Role::Popup => {
                self.raise(id);
                self.set_focus(Some(id));
            }
            Role::Desktop | Role::Lock => self.set_focus(Some(id)),
            Role::Panel | Role::Notification => {}
        }
        let w = &self.windows[&id];
        match part {
            Part::Content => {
                self.grab = Some(Grab::Content { win: id });
                self.pointer_event(id, proto::pointer::BUTTON, button, true, (0, 0));
            }
            Part::Title if button == osyx_input::button::LEFT => {
                let now = self.now;
                if self.last_title_click.is_some_and(|(wid, t)| wid == id && now.saturating_sub(t) <= DOUBLE_CLICK_MS) {
                    self.last_title_click = None;
                    if w.resizable {
                        self.window_action(id, Action::ToggleMaximize);
                    }
                    return;
                }
                self.last_title_click = Some((id, now));
                if !w.maximized {
                    self.grab = Some(Grab::Move { win: id, dx: self.ptr_x - w.rect.x, dy: self.ptr_y - w.rect.y });
                    self.set_cursor(CursorShape::Move);
                }
            }
            Part::Close | Part::Maximize | Part::Minimize if button == osyx_input::button::LEFT => {
                if part == Part::Maximize && !w.resizable {
                    return;
                }
                self.grab = Some(Grab::Button { win: id, part });
                let f = w.frame();
                self.damage.add(Rect::new(f.x, f.y, f.w, theme::TITLE_HEIGHT), self.screen);
            }
            Part::Resize(edges) if button == osyx_input::button::LEFT => {
                self.grab = Some(Grab::Resize { win: id, edges, start: w.rect, px: self.ptr_x, py: self.ptr_y });
            }
            _ => {}
        }
    }

    fn pointer_wheel(&mut self, v: i32, h: i32) {
        let target = match self.grab {
            Some(Grab::Content { win }) => Some(win),
            _ => match self.hover {
                Some((id, Part::Content)) => Some(id),
                _ => None,
            },
        };
        if let Some(id) = target.filter(|id| self.windows.contains_key(id)) {
            self.pointer_event(id, proto::pointer::WHEEL, 0, false, (v, h));
        }
    }

    fn shell_panel(&self) -> Option<(ClientId, u32)> {
        self.windows
            .values()
            .find(|w| w.role == Role::Panel && self.clients.get(&w.client).is_some_and(|c| c.shell))
            .map(|w| (w.client, w.local))
    }

    /// True once per PrintScreen press.
    pub fn take_screenshot_request(&mut self) -> bool {
        core::mem::take(&mut self.screenshot_requested)
    }

    /// A notification from PRISM itself (process id 0) to the shell.
    pub fn notify_shell(&mut self, title: &str, body: &str) {
        let shells: Vec<ClientId> = self.clients.iter().filter(|(_, cl)| cl.shell).map(|(id, _)| *id).collect();
        for s in shells {
            self.send(s, Event::Notification { from_pid: 0, title: String::from(title), body: String::from(body) });
        }
    }

    /// The lock screen window, if the shell has one up.
    fn lock_window(&self) -> Option<(ClientId, u32)> {
        self.windows.values().find(|w| w.role == Role::Lock).map(|w| (w.client, w.local))
    }

    fn key(&mut self, usage: u16, value: i32) {
        let down = value == osyx_input::KEY_DOWN;
        let mods = self.modifiers;
        // While locked, every key (shortcuts included) goes to the lock screen.
        if let Some((c, l)) = self.lock_window() {
            let state = match value {
                osyx_input::KEY_UP => proto::key_state::UP,
                osyx_input::KEY_REPEAT => proto::key_state::REPEAT,
                _ => proto::key_state::DOWN,
            };
            let text = if state != proto::key_state::UP { self.cfg.layout.translate(usage, mods) } else { None };
            self.send(c, Event::Key { window: l, usage, state, modifiers: mods, text });
            return;
        }
        // PrintScreen belongs to PRISM, whoever has focus.
        if usage == key::PRINT_SCREEN {
            if down {
                self.screenshot_requested = true;
                // A frame follows even when nothing else changed.
                self.damage.add(Rect::new(self.screen.x, self.screen.y, 1, 1), self.screen);
            }
            return;
        }
        // Alt+Tab cycles through normal windows while Alt is held.
        if down && usage == key::TAB && mods & modifier::LEFT_ALT != 0 {
            let candidates: Vec<WindowId> = self.mru.clone();
            if !candidates.is_empty() {
                let i = self.alt_tab.map_or(1, |i| i + 1) % candidates.len();
                self.alt_tab = Some(i);
                self.window_action(candidates[i], Action::Activate);
            }
            return;
        }
        if !down && (usage == key::LEFT_ALT) {
            self.alt_tab = None;
        }
        if down && usage == 0x3D && mods & modifier::LEFT_ALT != 0 {
            // Alt+F4
            if let Some(f) = self.focus.filter(|f| self.windows.get(f).is_some_and(|w| w.role == Role::Normal)) {
                self.window_action(f, Action::Close);
            }
            return;
        }
        let state = match value {
            osyx_input::KEY_UP => proto::key_state::UP,
            osyx_input::KEY_REPEAT => proto::key_state::REPEAT,
            _ => proto::key_state::DOWN,
        };
        // The Super key, Super+key shortcuts and the volume keys belong to
        // the shell, whoever has focus.
        let shell_key = matches!(usage, key::LEFT_GUI | key::RIGHT_GUI | key::MUTE | key::VOLUME_UP | key::VOLUME_DOWN);
        if shell_key || mods & (modifier::LEFT_GUI | modifier::RIGHT_GUI) != 0 {
            if let Some((c, l)) = self.shell_panel() {
                self.send(c, Event::Key { window: l, usage, state, modifiers: mods, text: None });
            }
            return;
        }
        let Some(f) = self.focus else { return };
        let Some(w) = self.windows.get(&f) else { return };
        let (c, l) = (w.client, w.local);
        let text = if state != proto::key_state::UP { self.cfg.layout.translate(usage, mods) } else { None };
        self.send(c, Event::Key { window: l, usage, state, modifiers: mods, text });
    }

    // ---- composition ---------------------------------------------------------------

    /// Milliseconds until the next frame is needed: 0 = now (damage
    /// pending), `None` = idle.
    pub fn next_frame_in(&self, now: u64) -> Option<u64> {
        let anim = self.windows.values().any(|w| w.fade.is_some()) || !self.ghosts.is_empty();
        if !self.damage.is_empty() || anim {
            return Some(0);
        }
        let _ = now;
        None
    }

    pub fn has_damage(&self) -> bool {
        !self.damage.is_empty()
    }

    /// Recomposes every damaged area into `target` (the back buffer, screen
    /// sized) and returns the rectangles that changed.
    pub fn render(&mut self, target: &mut Surface, now: u64) -> Vec<Rect> {
        self.now = now;
        // Animations damage their windows every frame until they finish.
        let screen = self.screen;
        let mut anim_damage = Vec::new();
        for w in self.windows.values_mut() {
            if let Some(f) = w.fade {
                anim_damage.push(w.bounds());
                if f.done(now) {
                    w.fade = None;
                }
            }
        }
        for g in &self.ghosts {
            anim_damage.push(g.bounds());
        }
        for r in anim_damage {
            self.damage.add(r, screen);
        }
        let rects = self.damage.take();
        for r in &rects {
            self.compose(target, *r, now);
        }
        self.ghosts.retain(|g| !g.fade.done(now));
        // Frame callbacks for content that has now reached the screen.
        let mut done = Vec::new();
        for (cid, cl) in self.clients.iter_mut() {
            for (sid, s) in cl.surfaces.iter_mut() {
                if s.frame_pending {
                    s.frame_pending = false;
                    done.push((*cid, *sid));
                }
            }
        }
        for (c, s) in done {
            self.send(c, Event::FrameDone { surface: s, time_ms: now });
        }
        if !rects.is_empty() {
            self.stats.frames += 1;
            self.stats.pixels += rects.iter().map(|r| r.w as u64 * r.h as u64).sum::<u64>();
        }
        rects
    }

    fn compose(&self, target: &mut Surface, clip: Rect, now: u64) {
        let has_desktop = self
            .stack
            .first()
            .and_then(|id| self.windows.get(id))
            .is_some_and(|w| w.role == Role::Desktop && w.visible() && w.fade.is_none());
        if !has_desktop {
            target.fill_rect(clip, theme::DESKTOP_FALLBACK);
        }
        for id in &self.stack {
            let w = &self.windows[id];
            if !w.visible() || w.bounds().intersect(&clip).is_empty() {
                continue;
            }
            self.draw_window(target, w, clip, now);
        }
        for g in &self.ghosts {
            if !g.bounds().intersect(&clip).is_empty() {
                self.draw_ghost(target, g, clip, now);
            }
        }
        if !self.cursor_overlay && !self.cursor.area(self.ptr_x, self.ptr_y).intersect(&clip).is_empty() {
            self.cursor.draw(target, self.ptr_x, self.ptr_y, clip);
        }
    }

    fn surface_pixels(&self, w: &Window) -> Option<Pixels<'_>> {
        let s = self.clients.get(&w.client)?.surfaces.get(&w.surface)?;
        Pixels::new(&s.pixels, s.width, s.height, s.width, s.alpha)
    }

    fn draw_window(&self, target: &mut Surface, w: &Window, clip: Rect, now: u64) {
        let opacity = w.opacity(now);
        let focused = self.focus == Some(w.id);
        let frame = w.frame();
        if w.has_shadow() {
            let strength = if focused { theme::SHADOW_ALPHA_ACTIVE } else { theme::SHADOW_ALPHA_INACTIVE } * opacity / 256;
            let tables = if w.decorated { &self.shadow } else { &self.popup_shadow };
            let sr = Rect::new(frame.x, frame.y + if w.decorated { theme::SHADOW_OFFSET_Y } else { 3 }, frame.w, frame.h);
            tables.draw(target, sr, frame, strength, clip);
        }
        if w.decorated {
            self.draw_title_bar(target, w, focused, opacity, clip);
        }
        self.draw_content(target, w, opacity, clip);
        if w.decorated {
            let (c, a) = if focused { (theme::ACCENT, 70) } else { (theme::OUTLINE_INACTIVE, 22) };
            draw::outline_rounded(target, frame, theme::RADIUS, c, a * opacity / 256, clip);
        }
    }

    fn draw_content(&self, target: &mut Surface, w: &Window, opacity: u32, clip: Rect) {
        let rect = w.rect;
        let area = rect.intersect(&clip);
        if area.is_empty() {
            return;
        }
        let rounded = if w.decorated { corner::BOTTOM } else { 0 };
        let radius = if w.decorated { theme::RADIUS.min(rect.w / 2).min(rect.h / 2) as i32 } else { 0 };
        // The part of the content rect the surface does not cover (a client
        // that has not caught up with a resize yet) shows the body colour.
        let px = self.surface_pixels(w);
        let covered = px.map_or(Rect::EMPTY, |p| Rect::new(rect.x, rect.y, p.width.min(rect.w), p.height.min(rect.h)));
        // Bottom corner squares are blended per pixel; everything else in bulk.
        let corner_rows = if radius > 0 { Rect::new(rect.x, rect.bottom() as i32 - radius, rect.w, radius as u32) } else { Rect::EMPTY };
        let bulk_clip = |r: Rect| -> [Rect; 3] {
            if corner_rows.is_empty() {
                return [r, Rect::EMPTY, Rect::EMPTY];
            }
            let above = Rect::new(rect.x, rect.y, rect.w, rect.h - radius as u32).intersect(&r);
            let middle = Rect::new(rect.x + radius, corner_rows.y, rect.w.saturating_sub(2 * radius as u32), radius as u32).intersect(&r);
            [above, middle, Rect::EMPTY]
        };
        for part in bulk_clip(area) {
            if part.is_empty() {
                continue;
            }
            // Body behind uncovered or translucent content.
            if px.is_none_or(|p| p.alpha) || covered.intersect(&part) != part {
                fill_body(target, part, covered, px.is_some_and(|p| p.alpha), opacity);
            }
            if let Some(p) = &px {
                draw::blit(target, rect.x, rect.y, p, opacity, part.intersect(&covered));
            }
        }
        if !corner_rows.is_empty() {
            for (cx, bit) in [(rect.x, corner::BOTTOM_LEFT), (rect.right() as i32 - radius, corner::BOTTOM_RIGHT)] {
                let sq = Rect::new(cx, corner_rows.y, radius as u32, radius as u32).intersect(&clip);
                for py in sq.y..sq.y + sq.h as i32 {
                    for pxx in sq.x..sq.x + sq.w as i32 {
                        let cov = draw::corner_coverage(pxx - rect.x, py - rect.y, rect.w as i32, rect.h as i32, radius, bit & rounded);
                        if cov == 0 {
                            continue;
                        }
                        let a = cov * opacity / 256;
                        let lx = (pxx - rect.x) as u32;
                        let ly = (py - rect.y) as u32;
                        let dst = &mut target.row_mut(py as u32)[pxx as usize];
                        let body = draw::tint(*dst, theme::WINDOW_BODY, a);
                        *dst = match &px {
                            Some(p) if lx < p.width && ly < p.height => {
                                let s = p.get(lx, ly);
                                if p.alpha {
                                    draw::over(body, s, a)
                                } else {
                                    draw::tint(*dst, s & 0x00FF_FFFF, a)
                                }
                            }
                            _ => body,
                        };
                    }
                }
            }
        }
    }

    fn draw_title_bar(&self, target: &mut Surface, w: &Window, focused: bool, opacity: u32, clip: Rect) {
        let f = w.frame();
        let bar = Rect::new(f.x, f.y, f.w, theme::TITLE_HEIGHT);
        if bar.intersect(&clip).is_empty() {
            return;
        }
        let bg = if focused { theme::TITLE_ACTIVE } else { theme::TITLE_INACTIVE };
        draw::fill_rounded(target, bar, theme::RADIUS, corner::TOP, bg, opacity, clip);
        // Title text, ellipsized before the buttons.
        let buttons = w.buttons();
        let text_x = bar.x + 16;
        let text_max = (buttons[0].1.x - 12 - text_x).max(0) as u32;
        let (shown, cut) = self.font.ellipsize(&w.title, text_max);
        let ty = bar.y + ((theme::TITLE_HEIGHT - self.font.line_height()) / 2) as i32;
        let color = if focused { theme::TITLE_TEXT } else { theme::TITLE_TEXT_INACTIVE };
        let text_clip = Rect::new(text_x, bar.y, text_max + self.font.advance('…'), bar.h).intersect(&clip);
        let alpha = 255 * opacity / 256;
        let end = self.font.draw_clipped(target, text_x, ty, shown, color, alpha, text_clip);
        if cut {
            self.font.draw_clipped(target, end.x + end.w as i32, ty, "…", color, alpha, text_clip);
        }
        // Buttons.
        let pressed = match self.grab {
            Some(Grab::Button { win, part }) if win == w.id => Some(part),
            _ => None,
        };
        let hovered = match self.hover {
            Some((id, p)) if id == w.id => Some(p),
            _ => None,
        };
        for (part, r) in buttons {
            if r.intersect(&clip).is_empty() {
                continue;
            }
            if part == Part::Maximize && !w.resizable {
                continue;
            }
            let is_hover = hovered == Some(part);
            if pressed == Some(part) {
                let c = if part == Part::Close { theme::CLOSE_HOVER } else { theme::BUTTON_PRESSED };
                draw::fill_rounded(target, r, 7, corner::ALL, c, opacity, clip);
            } else if is_hover {
                let c = if part == Part::Close { theme::CLOSE_HOVER } else { theme::BUTTON_HOVER };
                draw::fill_rounded(target, r, 7, corner::ALL, c, opacity, clip);
            }
            let glyph = if is_hover && part == Part::Close { 0xFFFFFF } else if focused { theme::GLYPH } else { theme::TITLE_TEXT_INACTIVE };
            draw_button_glyph(target, part, r, w.maximized, glyph, opacity, clip);
        }
    }

    fn draw_ghost(&self, target: &mut Surface, g: &Ghost, clip: Rect, now: u64) {
        let opacity = g.fade.value(now);
        if opacity == 0 {
            return;
        }
        let t = if g.decorated { theme::TITLE_HEIGHT } else { 0 };
        let frame = Rect::new(g.rect.x, g.rect.y - t as i32, g.rect.w, g.rect.h + t);
        self.shadow.draw(target, Rect::new(frame.x, frame.y + theme::SHADOW_OFFSET_Y, frame.w, frame.h), frame, theme::SHADOW_ALPHA_INACTIVE * opacity / 256, clip);
        if g.decorated {
            let bar = Rect::new(frame.x, frame.y, frame.w, t);
            draw::fill_rounded(target, bar, theme::RADIUS, corner::TOP, theme::TITLE_INACTIVE, opacity, clip);
            let ty = bar.y + ((t - self.font.line_height()) / 2) as i32;
            let (shown, _) = self.font.ellipsize(&g.title, frame.w.saturating_sub(120));
            self.font.draw_clipped(target, bar.x + 16, ty, shown, theme::TITLE_TEXT_INACTIVE, 255 * opacity / 256, bar.intersect(&clip));
        }
        let body = Rect::new(g.rect.x, g.rect.y, g.rect.w, g.rect.h).intersect(&clip);
        target.blend_rect(body, theme::WINDOW_BODY, 255 * opacity / 256);
        if let Some(p) = Pixels::new(&g.pixels, g.width, g.height, g.width, g.alpha) {
            draw::blit(target, g.rect.x, g.rect.y, &p, opacity, g.rect.intersect(&clip));
        }
    }
}

fn unknown() -> ProtocolError {
    ProtocolError { code: proto::error::UNKNOWN_OBJECT, message: "unknown object id".to_string() }
}

/// Fills the window body colour in `part` where the surface does not
/// cover it (or everywhere, under translucent content).
fn fill_body(target: &mut Surface, part: Rect, covered: Rect, translucent: bool, opacity: u32) {
    let alpha = 255 * opacity / 256;
    if translucent {
        target.blend_rect(part, theme::WINDOW_BODY, alpha);
        return;
    }
    // Up to four strips around the covered area.
    let c = covered.intersect(&part);
    if c.is_empty() {
        target.blend_rect(part, theme::WINDOW_BODY, alpha);
        return;
    }
    let strips = [
        Rect::new(part.x, part.y, part.w, (c.y - part.y) as u32),
        Rect::new(part.x, c.bottom() as i32, part.w, (part.bottom() - c.bottom()) as u32),
        Rect::new(part.x, c.y, (c.x - part.x) as u32, c.h),
        Rect::new(c.right() as i32, c.y, (part.right() - c.right()) as u32, c.h),
    ];
    for s in strips {
        if !s.is_empty() {
            target.blend_rect(s, theme::WINDOW_BODY, alpha);
        }
    }
}

/// Minimize, maximize/restore and close glyphs.
fn draw_button_glyph(target: &mut Surface, part: Part, r: Rect, maximized: bool, c: u32, opacity: u32, clip: Rect) {
    let cx = r.x + r.w as i32 / 2;
    let cy = r.y + r.h as i32 / 2;
    let a = opacity;
    let mut px = |x: i32, y: i32, cov: u32| {
        if x >= clip.x && y >= clip.y && (x as i64) < clip.right() && (y as i64) < clip.bottom() && target.bounds().intersect(&Rect::new(x, y, 1, 1)) == Rect::new(x, y, 1, 1) {
            let p = &mut target.row_mut(y as u32)[x as usize];
            *p = draw::tint(*p, c, cov * a / 256);
        }
    };
    match part {
        Part::Minimize => {
            for x in cx - 5..=cx + 5 {
                px(x, cy + 1, 256);
                px(x, cy + 2, 90);
            }
        }
        Part::Maximize => {
            let box_at = |px: &mut dyn FnMut(i32, i32, u32), x0: i32, y0: i32, s: i32| {
                for i in 0..=s {
                    px(x0 + i, y0, 256);
                    px(x0 + i, y0 + s, 256);
                    px(x0, y0 + i, 256);
                    px(x0 + s, y0 + i, 256);
                }
            };
            if maximized {
                box_at(&mut px, cx - 2, cy - 5, 7);
                box_at(&mut px, cx - 5, cy - 2, 7);
            } else {
                box_at(&mut px, cx - 5, cy - 5, 10);
            }
        }
        Part::Close => {
            for i in -5..=5 {
                px(cx + i, cy + i, 256);
                px(cx + i, cy - i, 256);
                px(cx + i + 1, cy + i, 110);
                px(cx + i + 1, cy - i, 110);
            }
        }
        _ => {}
    }
}
