//! Pieces shared by the desktop programs: the event loop of a one-window
//! application, privilege dropping, application entries, formatting.
//! (Each program uses a different subset.)

#![allow(dead_code)]

use os_std::ipc::WaitItem;
use os_std::prelude::*;
use os_std::time::Duration;
use os_std::{env, fs, os};
use osyx_ui::{Event as Ui, Fonts, Icon, Painter, Theme};
use prism_client::ui::Adapter;
use prism_client::{Connection, Event, WindowSpec};

/// What an application tells the event loop.
pub struct Ctx {
    pub fonts: Fonts,
    pub theme: Theme,
    /// The window has keyboard focus.
    pub focused: bool,
    /// Set to leave the event loop (the window is destroyed).
    pub quit: bool,
    /// A new window title.
    pub title: Option<String>,
    /// Notifications to post: (title, body).
    pub notes: Vec<(String, String)>,
    pub drag_file: Option<String>,
}

/// A program with one PRISM window driven by [`run_app`].
pub trait App {
    /// The window content size changed (also called before the first draw).
    fn layout(&mut self, w: u32, h: u32, cx: &mut Ctx);
    /// A toolkit event; returns true if the window must be redrawn.
    fn event(&mut self, ev: Ui, cx: &mut Ctx) -> bool;
    fn file_drop(&mut self, _path: &str, _x: i32, _y: i32, _cx: &mut Ctx) -> bool { false }
    fn draw(&mut self, p: &mut Painter, w: u32, h: u32, cx: &Ctx);
    /// Extra handles to wait on (pipes, ...).
    fn wait_items(&self) -> Vec<WaitItem> {
        Vec::new()
    }
    /// Some of [`App::wait_items`] are ready; returns true to redraw.
    fn ready(&mut self, _items: &[WaitItem], _cx: &mut Ctx) -> bool {
        false
    }
    /// Periodic work every [`App::tick_ms`]; returns true to redraw.
    fn tick(&mut self, _cx: &mut Ctx) -> bool {
        false
    }
    fn tick_ms(&self) -> Option<u64> {
        None
    }
    /// The user asked to close the window; true to quit.
    fn close_requested(&mut self, _cx: &mut Ctx) -> bool {
        true
    }
}

/// Connects to PRISM, opens the window and runs `app` until it quits or
/// PRISM goes away. Returns the program's exit status.
pub fn run_app(name: &str, spec: WindowSpec, app: &mut dyn App) -> i32 {
    let mut conn = match Connection::connect(name, false) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{name}: cannot connect to PRISM: {e}");
            return 1;
        }
    };
    let mut win = match conn.create_window(spec) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{name}: cannot create a window: {e}");
            return 1;
        }
    };
    let mut cx = Ctx {
        fonts: Fonts::load(),
        theme: configured_theme(),
        focused: false,
        quit: false,
        title: None,
        notes: Vec::new(),
        drag_file: None,
    };
    let mut adapter = Adapter::default();
    let mut size = (0, 0);
    let mut last_tick = os_std::time::Instant::now();
    loop {
        let mut extra = app.wait_items();
        let timeout =
            app.tick_ms().map(|ms| Duration::from_millis(ms.saturating_sub(last_tick.elapsed().as_millis() as u64)));
        if let Err(e) = conn.wait(&mut extra, timeout) {
            eprintln!("{name}: lost PRISM: {e}");
            return 2;
        }
        if extra.iter().any(|i| i.revents != 0) && app.ready(&extra, &mut cx) {
            win.dirty = true;
        }
        loop {
            let ev = match conn.poll() {
                Ok(Some(ev)) => ev,
                Ok(None) => break,
                Err(e) => {
                    eprintln!("{name}: lost PRISM: {e}");
                    return 2;
                }
            };
            win.on_event(&ev);
            match &ev {
                Event::FocusChanged { focused, .. } => {
                    cx.focused = *focused;
                    win.dirty = true;
                }
                Event::CloseRequest { .. } => {
                    if app.close_requested(&mut cx) {
                        cx.quit = true;
                    }
                }
                Event::FileDrop { window, path, x, y } if *window == win.id => {
                    if app.file_drop(path, *x, *y, &mut cx) { win.dirty = true; }
                }
                Event::Error { message, .. } => eprintln!("{name}: PRISM error: {message}"),
                _ => {}
            }
            if (win.width, win.height) != size && win.is_configured() {
                size = (win.width, win.height);
                app.layout(size.0, size.1, &mut cx);
                win.dirty = true;
            }
            if let Some((_, ui)) = adapter.translate(&ev) {
                if app.event(ui, &mut cx) {
                    win.dirty = true;
                }
                if let Some(path) = cx.drag_file.take() {
                    let _ = conn.send(&prism_client::Request::FileDrag { window: win.id, path }, &[]);
                }
            }
        }
        if let Some(ms) = app.tick_ms() {
            if last_tick.elapsed() >= Duration::from_millis(ms) {
                last_tick = os_std::time::Instant::now();
                if app.tick(&mut cx) {
                    win.dirty = true;
                }
            }
        }
        if let Some(t) = cx.title.take() {
            let _ = win.set_title(&mut conn, &t);
        }
        for (t, b) in core::mem::take(&mut cx.notes) {
            let _ = conn.notify(&t, &b);
        }
        if cx.quit {
            let _ = win.destroy(&mut conn);
            return 0;
        }
        if win.dirty && win.can_draw() && size.0 > 0 {
            let (w, h) = size;
            match win.surface() {
                Ok(mut s) => {
                    let (theme, fonts) = (cx.theme, cx.fonts);
                    let mut p = Painter::new(&mut s, &theme, &fonts);
                    app.draw(&mut p, w, h, &cx);
                }
                Err(e) => {
                    eprintln!("{name}: no drawing buffer: {e}");
                    continue;
                }
            }
            if let Err(e) = win.present(&mut conn, None) {
                eprintln!("{name}: present failed: {e}");
            }
        }
    }
}

/// Applications run as the desktop user, not as root.
pub const USER_UID: u32 = 1000;
/// The administrators group ("sudo"), the desktop user's primary group: it
/// may change the system settings.
pub const ADMIN_GID: u32 = 27;
pub const USER_HOME: &str = "/home/user";

/// Drops root privileges (programs started by the shell run as root until
/// they call this) and sets the user's environment.
pub fn become_user() {
    if os::getuid().0 == 0 {
        if let Err(e) = os::setuid(USER_UID, ADMIN_GID) {
            eprintln!("cannot drop privileges: {e}");
        }
    }
    env::set_var("HOME", USER_HOME);
    env::set_var("USER", "user");
    let _ = env::set_current_dir(USER_HOME);
}

/// An installed application (`/system/share/applications/*.app`):
/// `key=value` lines with `Name`, `Exec`, `Icon` and `Comment`.
#[derive(Clone, Debug)]
pub struct AppEntry {
    pub source: String,
    pub name: String,
    pub exec: String,
    pub icon: Icon,
    pub comment: String,
}

pub const APP_DIR: &str = "/system/share/applications";
pub const DESKTOP_DIR: &str = "/home/user/Desktop";

pub fn configured_theme() -> Theme {
    let mut theme = Theme::default();
    let name = fs::read_to_string("/etc/osyx/accent").unwrap_or_default();
    let (r, g, b) = match name.trim() {
        "Purple" => (160, 110, 240),
        "Pink" => (236, 92, 160),
        "Red" => (240, 84, 84),
        "Orange" => (245, 150, 60),
        "Yellow" => (240, 200, 60),
        "Green" => (80, 196, 120),
        "Graphite" => (140, 146, 160),
        _ => (76, 141, 255),
    };
    theme.accent = osyx_gfx::rgb(r, g, b);
    theme.accent_hover = osyx_gfx::rgb(r.saturating_add(20), g.saturating_add(20), b.saturating_add(20));
    theme.accent_pressed = osyx_gfx::rgb(r.saturating_sub(20), g.saturating_sub(20), b.saturating_sub(20));
    theme
}

pub fn icon_by_name(name: &str) -> Icon {
    match name {
        "terminal" => Icon::Terminal,
        "files" | "folder" => Icon::Folder,
        "info" | "sysinfo" => Icon::Info,
        "zen" | "browser" => Icon::Browser,
        _ => Icon::Program,
    }
}

pub fn load_apps() -> Vec<AppEntry> {
    load_apps_from(APP_DIR)
}

pub fn load_apps_from(path: &str) -> Vec<AppEntry> {
    let mut apps = Vec::new();
    let Ok(dir) = fs::read_dir(path) else { return apps };
    let mut names: Vec<String> = dir.map(|e| String::from(e.file_name())).filter(|n| n.ends_with(".app")).collect();
    names.sort();
    for n in names {
        if let Some(app) = load_app(&format!("{path}/{n}")) {
            apps.push(app);
        }
    }
    apps
}

pub fn load_app(path: &str) -> Option<AppEntry> {
    let text = fs::read_to_string(path).ok()?;
    let mut e = AppEntry {
        source: String::from(path),
        name: String::new(),
        exec: String::new(),
        icon: Icon::Program,
        comment: String::new(),
    };
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        match k.trim() {
            "Name" => e.name = String::from(v.trim()),
            "Exec" => e.exec = String::from(v.trim()),
            "Icon" => e.icon = icon_by_name(v.trim()),
            "Comment" => e.comment = String::from(v.trim()),
            _ => {}
        }
    }
    if !e.name.is_empty() && e.exec.starts_with('/') {
        Some(e)
    } else {
        None
    }
}

/// `1.5 MiB`
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut u = 0;
    let mut div = 1u128;
    while bytes as u128 / div >= 1024 && u < UNITS.len() - 1 {
        div *= 1024;
        u += 1;
    }
    let tenths = ((bytes as u128 * 10 + div / 2) / div) as u64;
    if tenths >= 100 {
        format!("{} {}", tenths / 10, UNITS[u])
    } else {
        format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[u])
    }
}

/// `3 h 07 min`, `42 s`
pub fn human_duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d} d {h} h {m:02} min")
    } else if h > 0 {
        format!("{h} h {m:02} min")
    } else if m > 0 {
        format!("{m} min {s:02} s")
    } else {
        format!("{s} s")
    }
}

/// The configured time zone (`/etc/TZ`, a POSIX TZ string), UTC otherwise.
pub fn system_tz() -> osyx_ui::time::Tz {
    fs::read_to_string("/etc/TZ")
        .ok()
        .and_then(|s| osyx_ui::time::Tz::parse(s.trim()))
        .unwrap_or_else(osyx_ui::time::Tz::utc)
}

/// Seconds since the Unix epoch from the real-time clock.
pub fn unix_now() -> i64 {
    os_std::time::SystemTime::now()
        .duration_since(os_std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
