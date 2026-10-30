//! The OSyx desktop shell (`/system/bin/desktop`), started by PRISM and
//! granted the shell role. A separate process from the compositor: if it
//! crashes, PRISM keeps every application window and starts it again.
//!
//! It provides the desktop background, the task bar (launcher, running
//! windows with the active one marked, quick settings, clock, power
//! button), the
//! application launcher (applications installed on the root file system
//! under `/system/share/applications`), the desktop context menu,
//! notification bubbles and the shut down / restart dialog.

#![no_std]
#![no_main]

#[path = "../shell_common.rs"]
mod common;

use common::{load_apps, system_tz, unix_now, AppEntry};
use os_std::prelude::*;
use os_std::process::{self, Command};
use os_std::time::{Duration, Instant};
use os_std::{system, thread};
use osyx_gfx::{rgb, Color, Rect, Surface};
use osyx_input::{button, key};
use osyx_ui::layout::{contains, inset};
use osyx_ui::time::Tz;
use osyx_ui::widget::{Button, ButtonStyle, Checkbox, Column, Dialog, ListItem, ListView, Menu, MenuItem, TextField};
use osyx_ui::{icon, Align, Event as Ui, FontKind, Fonts, Icon, Painter, Response, Theme};
use prism_client::ui::Adapter;
use prism_client::{proto, Action, Connection, Event, Role, Window, WindowSpec};
use prism_proto::{state, WindowInfo};

os_std::entry!(main);

const PANEL_H: u32 = 52;
const NOTE_W: u32 = 360;
const NOTE_H: u32 = 84;
const NOTE_MS: u64 = 6000;
const MAX_NOTES: usize = 4;
const LAUNCHER_W: u32 = 380;
const LAUNCHER_H: u32 = 470;
const CLOCK_W: u32 = 132;
/// Quick settings button (network and sound icons) and its panel.
const QUICK_W: u32 = 64;
const QUICK_PANEL_W: u32 = 360;
const QUICK_PANEL_H: u32 = 316;
const WIFI_PANEL_H: u32 = 400;
/// Opened by the network tile; the Win32 Network Center.
const NETWORK_APP: &str = "/opt/apps/netcenter.exe";
const SETTINGS_APP: &str = "/system/bin/settings";
/// Procedural backgrounds after the default image.
const WALLPAPERS: usize = 4;
/// The default wallpaper on the root file system (OSXI, converted from PNG at build time).
const DEFAULT_WALLPAPER: &str = "/system/share/wallpapers/default.osxi";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MenuPurpose {
    Desktop,
    Power,
    Application(usize),
    Shortcut(usize),
}

const CONFIRM_OFF: u32 = 1;
const CONFIRM_REBOOT: u32 = 2;

enum PopupKind {
    Launcher { search: TextField, list: ListView, shown: Vec<usize>, list_focus: bool },
    Menu { menu: Menu, purpose: MenuPurpose },
    Confirm { dialog: Dialog },
    Quick { net: NetSummary, radios: Radios, sound: Option<Sound>, dragging: bool, hover: Option<QuickItem> },
    /// The Wi-Fi network picker; `pass` is the password prompt for a
    /// secured network, with its "Show password" box.
    Wifi { state: WifiState, list: ListView, pass: Option<(String, TextField, Checkbox)>, message: String },
}

/// Battery indicator width on the panel.
const BATTERY_W: u32 = 78;

/// The battery state `batteryd` publishes (`percent charging ac`).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Battery {
    percent: u32,
    charging: bool,
    ac: bool,
}

impl Battery {
    fn read() -> Option<Battery> {
        let text = os_std::fs::read_to_string(osyx_abi::BATTERY_STATUS_PATH).ok()?;
        let mut f = text.split_whitespace();
        let percent = f.next()?.parse().ok()?;
        let flag = |s: Option<&str>| s == Some("1");
        Some(Battery { percent, charging: flag(f.next()), ac: flag(f.next()) })
    }
}

/// The sound card and volume from the kernel's `/run/audio.status`.
#[derive(Clone)]
struct Sound {
    device: String,
    volume: u32,
    muted: bool,
}

impl Sound {
    fn read() -> Option<Sound> {
        let text = os_std::fs::read_to_string("/run/audio.status").ok()?;
        let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).map(str::trim));
        Some(Sound {
            device: String::from(field("device=")?),
            volume: field("volume=").and_then(|v| v.parse().ok()).unwrap_or(0),
            muted: field("mute=") == Some("1"),
        })
    }

    /// Sends the volume and mute state to the kernel mixer.
    fn apply(&self) {
        use os_std::io::Write;
        let line = format!("volume={}\nmute={}\n", self.volume, self.muted as u8);
        match os_std::fs::OpenOptions::new().write(true).open("/dev/mixer") {
            Ok(mut f) => {
                let _ = f.write_all(line.as_bytes());
            }
            Err(e) => eprintln!("desktop: /dev/mixer: {e}"),
        }
    }
}

/// Volume slider geometry in the quick settings panel.
const VOLUME_Y: i32 = 170;
fn volume_track() -> Rect {
    Rect::new(54, VOLUME_Y + 38, QUICK_PANEL_W - 54 - 24, 6)
}
fn volume_at(x: i32) -> u32 {
    let t = volume_track();
    ((x - t.x).clamp(0, t.w as i32) * 100 / t.w as i32) as u32
}

/// Wi-Fi and Bluetooth hardware the kernel identified (no drivers yet).
#[derive(Clone, Default)]
struct Radios {
    wifi: Option<String>,
    bluetooth: Option<String>,
    /// From the kernel's `/run/wifi.status` when a Wi-Fi driver runs.
    wifi_state: Option<WifiState>,
}

#[derive(Clone, Default)]
struct WifiState {
    state: String,
    ssid: Option<String>,
    /// The WPA handshake finished (or the network is open).
    keys: bool,
    /// "wrong-password" when the handshake failed.
    error: Option<String>,
    last_error: Option<String>,
    /// Joins the kernel has applied (the state belongs to the last one).
    join: u64,
    diagnostics: Vec<String>,
    /// Saved networks (the kernel keeps their passphrases).
    known: Vec<String>,
    /// (RSSI, SSID, security) of the networks seen, strongest first.
    networks: Vec<(u32, String, String)>,
}

impl WifiState {
    fn read() -> Option<WifiState> {
        let text = os_std::fs::read_to_string("/run/wifi.status").ok()?;
        let mut w = WifiState::default();
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if let Some(s) = line.strip_prefix("state ") {
                w.state = String::from(s);
            } else if let Some(s) = line.strip_prefix("ssid ") {
                w.ssid = Some(String::from(s));
            } else if let Some(s) = line.strip_prefix("keys ") {
                w.keys = s == "yes";
            } else if let Some(s) = line.strip_prefix("error ") {
                w.error = Some(String::from(s));
            } else if let Some(s) = line.strip_prefix("last_error ") {
                w.last_error = Some(String::from(s));
            } else if let Some(s) = line.strip_prefix("join ") {
                w.join = s.parse().unwrap_or(0);
            } else if let Some(s) = line.strip_prefix("known\t") {
                w.known.push(String::from(s));
            } else if f.len() >= 5 && f[0] == "net" && !w.networks.iter().any(|n| n.1 == f[1]) {
                w.networks.push((f[2].parse().unwrap_or(0), String::from(f[1]), String::from(f[4])));
            }
        }
        w.networks.sort_by_key(|n| core::cmp::Reverse(n.0));
        if let Some(i) = os_std::net::interfaces().ok().and_then(|v| v.into_iter().find(|i| i.flags & os_std::net::IFF_WIRELESS != 0)) {
            let ip = os_std::net::Ipv4Addr(i.addr);
            let gw = os_std::net::Ipv4Addr(i.gateway);
            w.diagnostics.push(format!("IP: {ip}   Gateway: {gw}"));
            let phase = os_std::net::DHCP_PHASE_NAMES.get(i.dhcp_phase as usize).copied().unwrap_or("unknown");
            w.diagnostics.push(if i.method == os_std::net::CONFIG_DHCP { format!("DHCP: {phase}   Lease: {} s", i.lease_left) } else { String::from("DHCP: not enabled") });
        } else {
            w.diagnostics.push(String::from("No Wi-Fi interface"));
        }
        let dns = os_std::net::dns_servers().unwrap_or_default().iter().map(|d| format!("{d}")).collect::<Vec<_>>().join(", ");
        w.diagnostics.push(format!("DNS: {}", if dns.is_empty() { "none" } else { &dns }));
        let health = os_std::fs::read_to_string("/run/wifi.health").unwrap_or_default();
        if let Some(line) = health.lines().find_map(|l| l.strip_prefix("status ")) { w.diagnostics.push(format!("Recovery: {line}")); }
        let health_error = health.lines().find_map(|l| l.strip_prefix("last_error ")).filter(|s| !s.is_empty());
        w.diagnostics.push(format!("Last error: {}", w.last_error.as_deref().or(w.error.as_deref()).or(health_error).unwrap_or("none")));
        Some(w)
    }
}

impl Radios {
    fn read() -> Radios {
        let field = |b: &[u8]| {
            let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            String::from(core::str::from_utf8(&b[..n]).unwrap_or(""))
        };
        let mut r = Radios::default();
        for d in system::devices().unwrap_or_default() {
            match field(&d.class).as_str() {
                "Wireless" if r.wifi.is_none() => r.wifi = Some(field(&d.description)),
                "Bluetooth" if r.bluetooth.is_none() => r.bluetooth = Some(field(&d.description)),
                _ => {}
            }
        }
        r.wifi_state = WifiState::read();
        r
    }
}

/// "Intel Wi-Fi 6 AX200" -> "AX200", "Intel AX200 Bluetooth" -> "AX200".
fn chip_short(name: &str) -> &str {
    name.trim_end_matches(" Bluetooth").rsplit(' ').next().unwrap_or(name)
}

/// What the quick settings panel shows about the first network adapter.
#[derive(Clone)]
struct NetSummary {
    present: bool,
    connected: bool,
    detail: String,
}

impl NetSummary {
    fn read() -> NetSummary {
        let Some(i) = os_std::net::interfaces()
            .ok()
            .and_then(|v| os_std::net::preferred_ethernet(&v))
        else {
            return NetSummary { present: false, connected: false, detail: String::from("No adapter") };
        };
        let link = i.flags & os_std::net::IFF_LINK != 0;
        let connected = link && i.addr != [0; 4];
        let detail = if connected {
            format!("{}.{}.{}.{}", i.addr[0], i.addr[1], i.addr[2], i.addr[3])
        } else if link {
            String::from("No address yet")
        } else {
            String::from("Cable unplugged")
        };
        NetSummary { present: true, connected, detail }
    }
}

/// Clickable parts of the quick settings panel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum QuickItem {
    Network,
    Wifi,
    Bluetooth,
    Settings,
    /// The volume slider (track with some room around it).
    Volume,
    /// The speaker icon: mute toggle.
    Mute,
}

impl QuickItem {
    const ALL: [QuickItem; 6] =
        [QuickItem::Network, QuickItem::Wifi, QuickItem::Bluetooth, QuickItem::Settings, QuickItem::Volume, QuickItem::Mute];

    fn rect(self) -> Rect {
        let tile_w = (QUICK_PANEL_W - 40 - 2 * 10) / 3;
        let tile = |i: i32| Rect::new(20 + i * (tile_w as i32 + 10), 56, tile_w, 92);
        match self {
            QuickItem::Network => tile(0),
            QuickItem::Wifi => tile(1),
            QuickItem::Bluetooth => tile(2),
            QuickItem::Settings => Rect::new((QUICK_PANEL_W - 20 - 150) as i32, (QUICK_PANEL_H - 52) as i32, 150, 36),
            QuickItem::Volume => {
                let t = volume_track();
                Rect::new(t.x - 10, t.y - 12, t.w + 20, 30)
            }
            QuickItem::Mute => Rect::new(14, VOLUME_Y + 24, 34, 34),
        }
    }

    fn at(x: i32, y: i32) -> Option<QuickItem> {
        Self::ALL.into_iter().find(|i| contains(&i.rect(), x, y))
    }
}

struct Popup {
    win: Window,
    kind: PopupKind,
    x: i32,
    y: i32,
}

impl Popup {
    fn tag(&self) -> PopupTag {
        match &self.kind {
            PopupKind::Launcher { .. } => PopupTag::Launcher,
            PopupKind::Menu { purpose: MenuPurpose::Power, .. } => PopupTag::PowerMenu,
            PopupKind::Quick { .. } => PopupTag::Quick,
            _ => PopupTag::Other,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PopupTag {
    Launcher,
    PowerMenu,
    Quick,
    Other,
}

struct Note {
    win: Window,
    title: String,
    body: String,
    born: u64,
}

struct IconDrag {
    index: usize,
    start: (i32, i32),
    pointer: (i32, i32),
    moved: bool,
}

enum PanelAction {
    Launcher,
    Power,
    Task(usize),
    Clock,
    Quick,
}

/// Exits of the shell's children, collected by the reaper thread.
static EXITS: os_std::sync::Mutex<Vec<(u64, i32)>> = os_std::sync::Mutex::new(Vec::new());

struct Shell {
    conn: Connection,
    fonts: Fonts,
    theme: Theme,
    adapter: Adapter,
    start: Instant,
    w: u32,
    h: u32,
    desktop: Window,
    wallpaper: Vec<u32>,
    /// The default wallpaper image file, if installed.
    image: Option<Vec<u8>>,
    style: usize,
    panel: Window,
    launcher_btn: Button,
    power_btn: Button,
    tasks: Vec<Button>,
    windows: Vec<WindowInfo>,
    clock: (String, String),
    clock_hover: bool,
    quick_hover: bool,
    tz: Tz,
    popup: Option<Popup>,
    /// When PRISM last closed a popup (a click on the popup's own toggle
    /// button must not reopen it at once).
    popup_closed: Option<(u64, PopupTag)>,
    notes: Vec<Note>,
    apps: Vec<AppEntry>,
    shortcuts: Vec<AppEntry>,
    selected_shortcut: Option<usize>,
    shortcut_scan: u64,
    /// Wi-Fi network being joined, when (ms) and the kernel's join count
    /// before it: watched until the kernel applied this join and it
    /// connects or reports a wrong password.
    wifi_joining: Option<(String, u64, u64)>,
    wifi_checked: u64,
    wifi_popup_checked: u64,
    /// When `/run/update.status` was last read (ms), and whether an
    /// installed system update was announced.
    update_checked: u64,
    update_announced: bool,
    /// The battery from `/run/battery` (None without one) and when it was
    /// last read (ms).
    battery: Option<Battery>,
    battery_checked: u64,
    shortcut_cells: Vec<usize>,
    icon_drag: Option<IconDrag>,
    /// (pid, application name) of programs started from the shell.
    children: Vec<(u64, String)>,
    lock: Option<LockScreen>,
    /// A key was pressed while Super was held (no launcher on release).
    super_used: bool,
}

/// The lock screen: a full-screen window above everything with a
/// password field; the password is the desktop user's from /etc/shadow.
struct LockScreen {
    win: Window,
    field: TextField,
    message: String,
    last_failure: u64,
}

/// Whether `entered` is the desktop user's password. Without a password
/// (live system, or none set at installation) any input unlocks.
fn password_ok(entered: &str) -> bool {
    let Ok(shadow) = os_std::fs::read_to_string("/etc/shadow") else { return true };
    let secret = shadow.lines().find_map(|l| {
        let mut f = l.split(':');
        let (name, secret) = (f.next()?, f.next()?);
        (name != "root").then(|| String::from(secret))
    });
    let Some(secret) = secret.filter(|s| !s.is_empty()) else { return true };
    let parts: Vec<&str> = secret.split('$').collect();
    if parts.len() != 4 || parts[0] != "sha256-iter" || parts[2].len() != 32 {
        return false;
    }
    let mut salt = [0u8; 16];
    for (i, b) in salt.iter_mut().enumerate() {
        match u8::from_str_radix(&parts[2][i * 2..i * 2 + 2], 16) {
            Ok(v) => *b = v,
            Err(_) => return false,
        }
    }
    osyx_install::hash_password(entered, &salt) == secret
}

fn main() -> i32 {
    // The shell (taskbar, launcher) stays responsive under application load.
    let _ = os_std::system::thread_priority(0, os_std::system::priority::ABOVE_NORMAL);
    let mut conn = match Connection::connect("desktop", true) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("desktop: cannot connect to PRISM: {e}");
            return 1;
        }
    };
    if !conn.shell {
        eprintln!("desktop: PRISM did not grant the shell role");
        return 1;
    }
    let (w, h) = (conn.screen_width, conn.screen_height);
    let windows = conn.create_window(WindowSpec::with_role(Role::Desktop, 0, 0, w, h)).and_then(|d| {
        conn.create_window(WindowSpec::with_role(Role::Panel, 0, (h - PANEL_H) as i32, w, PANEL_H)).map(|p| (d, p))
    });
    let (desktop, panel) = match windows {
        Ok(v) => v,
        Err(e) => {
            eprintln!("desktop: cannot create the desktop windows: {e}");
            return 1;
        }
    };
    thread::spawn(reaper);
    let fonts = Fonts::load();
    let mut shell = Shell {
        conn,
        fonts,
        theme: common::configured_theme(),
        adapter: Adapter::default(),
        start: Instant::now(),
        w,
        h,
        desktop,
        wallpaper: vec![0; (w * h) as usize],
        image: os_std::fs::read(DEFAULT_WALLPAPER).ok().filter(|d| osyx_gfx::Image::parse(d).is_ok()),
        style: os_std::fs::read_to_string("/etc/osyx/wallpaper")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0)
            % WALLPAPERS,
        panel,
        launcher_btn: Button::new(0, "", ButtonStyle::Flat).with_icon(Icon::Apps),
        power_btn: Button::new(0, "", ButtonStyle::Flat).with_icon(Icon::Power),
        tasks: Vec::new(),
        windows: Vec::new(),
        clock: (String::new(), String::new()),
        clock_hover: false,
        quick_hover: false,
        tz: system_tz(),
        popup: None,
        popup_closed: None,
        notes: Vec::new(),
        apps: load_apps(),
        shortcuts: common::load_apps_from(common::DESKTOP_DIR),
        selected_shortcut: None,
        shortcut_scan: 0,
        wifi_joining: None,
        wifi_checked: 0,
        wifi_popup_checked: 0,
        update_checked: 0,
        update_announced: false,
        battery: None,
        battery_checked: 0,
        shortcut_cells: Vec::new(),
        icon_drag: None,
        children: Vec::new(),
        lock: None,
        super_used: false,
    };
    let t0 = Instant::now();
    if shell.image.is_none() {
        eprintln!("desktop: {DEFAULT_WALLPAPER} missing or invalid; using a drawn background");
        shell.style = 1;
    }
    paint_wallpaper(&mut shell.wallpaper, w, h, shell.style, shell.image.as_deref(), &shell.fonts);
    println!("desktop: wallpaper {} drawn in {} ms", shell.style, t0.elapsed().as_millis());
    shell.layout_panel();
    shell.load_shortcut_layout();
    println!("desktop: {} shortcut(s) in {}", shell.shortcuts.len(), common::DESKTOP_DIR);
    shell.update_clock();
    println!(
        "desktop: shell ready on a {}x{} screen, {} application(s) in {}, time zone {}",
        w,
        h,
        shell.apps.len(),
        common::APP_DIR,
        shell.tz.std_name
    );
    shell.run()
}

/// Collects the exit status of every application the shell started.
fn reaper() {
    loop {
        match process::wait_any() {
            Ok((pid, status)) => {
                if let Ok(mut q) = EXITS.lock() {
                    q.push((pid, status.raw()));
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(250)),
        }
    }
}

impl Shell {
    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn run(&mut self) -> i32 {
        loop {
            let timeout = if self.notes.is_empty() { 1000 } else { 250 };
            if let Err(e) = self.conn.wait(&mut [], Some(Duration::from_millis(timeout))) {
                eprintln!("desktop: lost PRISM: {e}");
                return 2;
            }
            loop {
                match self.conn.poll() {
                    Ok(Some(ev)) => self.event(ev),
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("desktop: lost PRISM: {e}");
                        return 2;
                    }
                }
            }
            self.update_clock();
            if self.now().saturating_sub(self.battery_checked) >= 2000 {
                self.battery_checked = self.now();
                self.update_battery();
            }
            self.expire_notes();
            self.collect_exits();
            if self.now().saturating_sub(self.shortcut_scan) >= 2000 {
                self.refresh_shortcuts();
            }
            if self.wifi_joining.is_some() && self.now().saturating_sub(self.wifi_checked) >= 1000 {
                self.wifi_checked = self.now();
                self.check_wifi_join();
            }
            if self.now().saturating_sub(self.wifi_popup_checked) >= 2000 {
                self.wifi_popup_checked = self.now();
                if let Some(p) = self.popup.as_mut() {
                    if let PopupKind::Wifi { state, .. } = &mut p.kind {
                        if let Some(fresh) = WifiState::read() {
                            state.state = fresh.state;
                            state.ssid = fresh.ssid;
                            state.keys = fresh.keys;
                            state.error = fresh.error;
                            state.last_error = fresh.last_error;
                            state.diagnostics = fresh.diagnostics;
                            p.win.dirty = true;
                        }
                    }
                }
            }
            if !self.update_announced && self.now().saturating_sub(self.update_checked) >= 5000 {
                self.update_checked = self.now();
                self.check_update();
            }
            if let Err(e) = self.redraw() {
                eprintln!("desktop: drawing failed: {e}");
            }
        }
    }

    // ---- events ------------------------------------------------------------

    fn event(&mut self, ev: Event) {
        match &ev {
            Event::WindowList { windows } => {
                let processes = system::processes().unwrap_or_default();
                let families: Vec<_> = processes
                    .iter()
                    .map(|p| prism_core::taskbar::Process {
                        pid: p.pid as u32,
                        parent: p.parent as u32,
                        win32: system::process_name(p) == "winrun",
                    })
                    .collect();
                self.windows = prism_core::taskbar::group(windows, &families);
                self.layout_panel();
                return;
            }
            Event::Notification { from_pid, title, body } => {
                println!("desktop: notification from process {from_pid}: {title}");
                let (t, b) = (title.clone(), body.clone());
                self.show_note(&t, &b);
                return;
            }
            Event::Error { code, message, .. } => {
                eprintln!("desktop: PRISM error {code}: {message}");
                return;
            }
            _ => {}
        }
        self.desktop.on_event(&ev);
        self.panel.on_event(&ev);
        if let Some(p) = &mut self.popup {
            p.win.on_event(&ev);
        }
        for n in &mut self.notes {
            n.win.on_event(&ev);
        }
        if let Some(l) = &mut self.lock {
            l.win.on_event(&ev);
        }
        if let Event::CloseRequest { window } = ev {
            if self.popup.as_ref().is_some_and(|p| p.win.id == window) {
                let tag = self.popup.as_ref().map_or(PopupTag::Other, Popup::tag);
                self.popup_closed = Some((self.now(), tag));
                self.close_popup();
            }
            return;
        }
        if let Event::Key { window, usage, state: s, .. } = ev {
            // Super and Super+key shortcuts reach the panel wherever the
            // focus is. Super alone opens the launcher when released.
            if window == self.panel.id {
                if matches!(usage, key::MUTE | key::VOLUME_UP | key::VOLUME_DOWN) {
                    if s != proto::key_state::UP {
                        self.volume_key(usage);
                    }
                    return;
                }
                let gui = usage == key::LEFT_GUI || usage == key::RIGHT_GUI;
                if gui && s == proto::key_state::DOWN {
                    self.super_used = false;
                } else if gui && s == proto::key_state::UP {
                    if !self.super_used {
                        self.toggle_launcher();
                    }
                } else if s == proto::key_state::DOWN {
                    self.super_used = true;
                    self.super_shortcut(usage);
                }
                return;
            }
        }
        let Some((win, ui)) = self.adapter.translate(&ev) else { return };
        if win == self.desktop.id {
            self.desktop_input(ui);
        } else if win == self.panel.id {
            self.panel_input(ui);
        } else if self.popup.as_ref().is_some_and(|p| p.win.id == win) {
            self.popup_input(ui);
        } else if self.lock.as_ref().is_some_and(|l| l.win.id == win) {
            self.lock_input(ui);
        } else if let Some(i) = self.notes.iter().position(|n| n.win.id == win) {
            if matches!(ui, Ui::PointerDown { .. }) {
                let n = self.notes.remove(i);
                let _ = n.win.destroy(&mut self.conn);
                self.restack_notes();
            }
        }
    }

    /// Super+key shortcuts.
    fn super_shortcut(&mut self, usage: u16) {
        if usage == key::L {
            self.lock_screen();
        }
    }

    fn lock_screen(&mut self) {
        if self.lock.is_some() {
            return;
        }
        self.close_popup();
        match self.conn.create_window(WindowSpec::with_role(Role::Lock, 0, 0, self.w, self.h)) {
            Ok(win) => {
                let mut field = TextField::new("");
                field.masked = true;
                field.placeholder = String::from("Password");
                let fw = 320;
                field.rect = Rect::new((self.w as i32 - fw) / 2, self.h as i32 / 2 + 40, fw as u32, 40);
                println!("desktop: screen locked");
                self.lock = Some(LockScreen { win, field, message: String::new(), last_failure: 0 });
            }
            Err(e) => eprintln!("desktop: cannot lock the screen: {e}"),
        }
    }

    fn lock_input(&mut self, ui: Ui) {
        let fonts = self.fonts;
        let now = self.now();
        let Some(l) = &mut self.lock else { return };
        match l.field.event(&ui, true, &fonts) {
            Response::Submitted => {
                // One attempt per second against guessing.
                if now.saturating_sub(l.last_failure) < 1000 {
                    return;
                }
                if password_ok(l.field.text()) {
                    let l = self.lock.take().expect("locked");
                    let _ = l.win.destroy(&mut self.conn);
                    println!("desktop: screen unlocked");
                    self.desktop.dirty = true;
                    self.panel.dirty = true;
                } else {
                    println!("desktop: wrong password on the lock screen");
                    l.last_failure = self.start.elapsed().as_millis() as u64;
                    l.message = String::from("Wrong password. Try again.");
                    l.field.set_text("");
                    l.win.dirty = true;
                }
            }
            r if r.needs_redraw() => l.win.dirty = true,
            _ => {}
        }
    }

    fn desktop_input(&mut self, ui: Ui) {
        if let Ui::PointerMove { x, y } = ui {
            if let Some(drag) = &mut self.icon_drag {
                drag.pointer = (x, y);
                drag.moved |= (x - drag.start.0).abs() + (y - drag.start.1).abs() > 6;
                self.desktop.dirty |= drag.moved;
            }
        }
        if let Ui::PointerUp { x, y, button: button::LEFT } = ui {
            if let Some(drag) = self.icon_drag.take().filter(|d| d.moved) {
                let rows = shortcut_rows(self.h);
                let columns = (self.w.saturating_sub(32) / 116).max(1) as usize;
                let col = ((x - 16).max(0) as usize / 116).min(columns - 1);
                let row = ((y - 16).max(0) as usize / 100).min(rows - 1);
                let cell = col * rows + row;
                let old = self.shortcut_cells[drag.index];
                if let Some(other) = self.shortcut_cells.iter().position(|&c| c == cell) {
                    self.shortcut_cells[other] = old;
                }
                self.shortcut_cells[drag.index] = cell;
                self.save_shortcut_layout();
                println!("desktop: icon moved: {} to grid ({col}, {row})", self.shortcuts[drag.index].name);
                self.desktop.dirty = true;
            }
        }
        if let Ui::Key(k) = ui {
            if !k.down {
                return;
            }
            match k.key {
                key::ENTER => {
                    if let Some(i) = self.selected_shortcut {
                        self.launch_shortcut(i);
                    }
                }
                key::DELETE => {
                    if let Some(i) = self.selected_shortcut {
                        self.remove_shortcut(i);
                    }
                }
                key::F5 => self.refresh_shortcuts(),
                key::UP | key::DOWN | key::LEFT | key::RIGHT if !self.shortcuts.is_empty() => {
                    let rows = shortcut_rows(self.h);
                    let delta = match k.key {
                        key::UP => -1,
                        key::DOWN => 1,
                        key::LEFT => -(rows as i32),
                        _ => rows as i32,
                    };
                    self.selected_shortcut = Some(
                        self.selected_shortcut
                            .map_or(0, |i| (i as i32 + delta).clamp(0, self.shortcuts.len() as i32 - 1) as usize),
                    );
                    self.desktop.dirty = true;
                }
                _ => {}
            }
        }
        if let Ui::PointerDown { x, y, button: b, clicks } = ui {
            let hit =
                (0..self.shortcuts.len()).find(|&i| contains(&shortcut_rect(self.shortcut_cells[i], self.h), x, y));
            self.selected_shortcut = hit;
            self.desktop.dirty = true;
            if let Some(i) = hit {
                if b == button::LEFT && clicks >= 2 {
                    self.icon_drag = None;
                    self.launch_shortcut(i);
                } else if b == button::LEFT {
                    self.icon_drag = Some(IconDrag { index: i, start: (x, y), pointer: (x, y), moved: false });
                } else if b == button::RIGHT {
                    self.open_menu(
                        vec![
                            MenuItem::new("Open", Some(Icon::Program)),
                            MenuItem::new("Remove shortcut", Some(Icon::Trash)),
                        ],
                        MenuPurpose::Shortcut(i),
                        x,
                        y,
                    );
                }
                return;
            }
            if b == button::RIGHT {
                let items = vec![
                    MenuItem::new("Open Terminal", Some(Icon::Terminal)),
                    MenuItem::new("Open Files", Some(Icon::Folder)),
                    MenuItem::new("System Information", Some(Icon::Info)),
                    MenuItem::new("Next wallpaper", Some(Icon::Refresh)).separated(),
                    MenuItem::new("About OSyx", Some(Icon::Bell)),
                    MenuItem::new("Add application shortcut...", Some(Icon::Apps)).separated(),
                    MenuItem::new("Refresh desktop", Some(Icon::Refresh)),
                ];
                self.open_menu(items, MenuPurpose::Desktop, x, y);
            }
        }
    }

    fn panel_input(&mut self, ui: Ui) {
        let mut action = None;
        let mut redraw = false;
        match self.launcher_btn.event(&ui, false) {
            Response::Activated(_) => action = Some(PanelAction::Launcher),
            r => redraw |= r.needs_redraw(),
        }
        match self.power_btn.event(&ui, false) {
            Response::Activated(_) => action = Some(PanelAction::Power),
            r => redraw |= r.needs_redraw(),
        }
        for b in &mut self.tasks {
            match b.event(&ui, false) {
                Response::Activated(i) => action = Some(PanelAction::Task(i)),
                r => redraw |= r.needs_redraw(),
            }
        }
        let clock = self.clock_rect();
        let quick = self.quick_rect();
        match ui {
            Ui::PointerMove { x, y } => {
                let h = contains(&clock, x, y);
                redraw |= h != self.clock_hover;
                self.clock_hover = h;
                let q = contains(&quick, x, y);
                redraw |= q != self.quick_hover;
                self.quick_hover = q;
            }
            Ui::PointerLeave => {
                redraw |= self.clock_hover || self.quick_hover;
                self.clock_hover = false;
                self.quick_hover = false;
            }
            Ui::PointerDown { x, y, button: b, .. } if b == button::LEFT && contains(&clock, x, y) => {
                action = Some(PanelAction::Clock)
            }
            Ui::PointerDown { x, y, button: b, .. } if b == button::LEFT && contains(&quick, x, y) => {
                action = Some(PanelAction::Quick)
            }
            _ => {}
        }
        self.panel.dirty |= redraw;
        match action {
            Some(PanelAction::Launcher) => self.toggle_launcher(),
            Some(PanelAction::Quick) => self.toggle_quick(),
            Some(PanelAction::Power) => {
                if self.recently_closed(PopupTag::PowerMenu) {
                    return;
                }
                let items = vec![
                    MenuItem::new("Lock", Some(Icon::Lock)),
                    MenuItem::new("Restart", Some(Icon::Restart)),
                    MenuItem::new("Shut down", Some(Icon::Power)).danger(),
                ];
                let (mw, mh) = Menu::new(items.clone()).size(&self.fonts);
                let r = self.power_btn.rect;
                let x = r.right() as i32 - mw as i32;
                let y = (self.h - PANEL_H) as i32 - mh as i32 - 8;
                self.open_menu(items, MenuPurpose::Power, x, y);
            }
            Some(PanelAction::Task(i)) => {
                if let Some(info) = self.windows.get(i) {
                    let active = info.flags & state::ACTIVATED != 0 && info.flags & state::MINIMIZED == 0;
                    let a = if active { Action::Minimize } else { Action::Activate };
                    println!("desktop: task bar: {:?} window {} \"{}\"", a, info.id, info.title);
                    let _ = self.conn.window_action(info.id, a, true);
                }
            }
            Some(PanelAction::Clock) => {
                let l = self.tz.local(unix_now());
                let off = l.offset.abs();
                let sign = if l.offset < 0 { '-' } else { '+' };
                let body = format!("{} {} (UTC{}{:02}:{:02})", l.iso(), l.zone, sign, off / 3600, off / 60 % 60);
                let title = l.long_date();
                self.show_note(&title, &body);
            }
            None => {}
        }
    }

    fn popup_input(&mut self, ui: Ui) {
        let fonts = self.fonts;
        let Some(p) = &mut self.popup else { return };
        let mut launch = None;
        let mut pick = None;
        let mut confirm = None;
        let mut close = false;
        let mut app_menu = None;
        let mut quick = None;
        let mut radio_note: Option<(&str, Option<String>)> = None;
        let mut wifi_open: Option<WifiState> = None;
        let mut wifi_join: Option<(String, String)> = None;
        let mut wifi_forget: Option<String> = None;
        let mut wifi_reconnect = false;
        match &mut p.kind {
            PopupKind::Launcher { search, list, shown, list_focus } => {
                if let Ui::PointerDown { x, y, button: button::RIGHT, .. } = ui {
                    app_menu = list.row_at(x, y).and_then(|i| shown.get(i).copied()).map(|i| (i, p.x + x, p.y + y));
                }
                // Arrow keys and Enter in the search field drive the list.
                if let Ui::Key(k) = ui {
                    if k.down && matches!(k.key, key::UP | key::DOWN | key::PAGE_UP | key::PAGE_DOWN) {
                        if list.selected().is_none() && !shown.is_empty() {
                            list.select(Some(0));
                        } else {
                            list.event(&ui, true);
                        }
                        p.win.dirty = true;
                        return;
                    }
                    if k.down && k.key == key::TAB {
                        *list_focus = !*list_focus;
                        p.win.dirty = true;
                        return;
                    }
                }
                let before = String::from(search.text());
                match search.event(&ui, !*list_focus, &fonts) {
                    Response::Submitted => {
                        launch = list
                            .selected()
                            .or(if shown.is_empty() { None } else { Some(0) })
                            .and_then(|i| shown.get(i).copied());
                    }
                    Response::Cancelled => close = true,
                    r if r.needs_redraw() => p.win.dirty = true,
                    _ => {}
                }
                if search.text() != before {
                    *shown = filter_apps(&self.apps, search.text());
                    list.set_items(app_items(&self.apps, shown));
                    list.select(if shown.is_empty() { None } else { Some(0) });
                }
                match list.event(&ui, *list_focus) {
                    Response::Activated(i) => launch = shown.get(i).copied(),
                    r if r.needs_redraw() => p.win.dirty = true,
                    _ => {}
                }
                if let Ui::PointerDown { x, y, .. } = ui {
                    if contains(&list.rect, x, y) {
                        *list_focus = true;
                    } else if contains(&search.rect, x, y) {
                        *list_focus = false;
                    }
                }
                if let Ui::Key(k) = ui {
                    if k.down && k.key == key::ESCAPE {
                        close = true;
                    }
                }
            }
            PopupKind::Menu { menu, purpose } => match menu.event(&ui) {
                Response::Activated(i) => pick = Some((*purpose, i)),
                Response::Cancelled => close = true,
                r if r.needs_redraw() => p.win.dirty = true,
                _ => {}
            },
            PopupKind::Confirm { dialog } => match dialog.event(&ui, &fonts) {
                Response::Activated(1) => confirm = Some(dialog.tag),
                Response::Activated(_) | Response::Cancelled => close = true,
                r if r.needs_redraw() => p.win.dirty = true,
                _ => {}
            },
            PopupKind::Wifi { state, list, pass, message } => {
                if let Some((ssid, field, show)) = pass {
                    let toggled = show.event(&ui, false);
                    if matches!(toggled, Response::Changed) {
                        // The password stays readable while the box is ticked.
                        field.masked = !show.checked;
                    }
                    if toggled.needs_redraw() {
                        p.win.dirty = true;
                    }
                    match field.event(&ui, true, &fonts) {
                        Response::Submitted => {
                            let pw = String::from(field.text());
                            if (8..=63).contains(&pw.len()) {
                                wifi_join = Some((ssid.clone(), pw));
                            } else {
                                *message = String::from("A WPA password has 8 to 63 characters.");
                                p.win.dirty = true;
                            }
                        }
                        Response::Cancelled => {
                            *pass = None;
                            message.clear();
                            p.win.dirty = true;
                        }
                        r if r.needs_redraw() => p.win.dirty = true,
                        _ => {}
                    }
                } else {
                    if let Ui::PointerDown { x, y, button: button::LEFT, .. } = ui {
                        if contains(&wifi_reconnect_rect(), x, y) { wifi_reconnect = true; }
                    }
                    match list.event(&ui, true) {
                        Response::Activated(i) => {
                            if let Some((_, ssid, sec)) = state.networks.get(i) {
                                // A saved network joins with the passphrase the kernel keeps.
                                if sec == "open" || state.known.contains(ssid) {
                                    wifi_join = Some((ssid.clone(), String::new()));
                                } else {
                                    let mut f = TextField::new("");
                                    f.masked = true;
                                    f.placeholder = String::from("Password");
                                    f.rect = Rect::new(20, (WIFI_PANEL_H - 120) as i32, QUICK_PANEL_W - 40, 36);
                                    let mut show = Checkbox::new("Show password", false);
                                    show.rect = Rect::new(20, f.rect.bottom() as i32 + 36, QUICK_PANEL_W - 40, 24);
                                    *pass = Some((ssid.clone(), f, show));
                                    message.clear();
                                    p.win.dirty = true;
                                }
                            }
                        }
                        Response::Cancelled => close = true,
                        r if r.needs_redraw() => p.win.dirty = true,
                        _ => {}
                    }
                    if let Ui::Key(k) = ui {
                        if k.down && k.key == key::ESCAPE {
                            close = true;
                        }
                        if k.down && k.key == key::DELETE {
                            let picked = list.selected().and_then(|i| state.networks.get(i)).map(|n| n.1.clone());
                            if let Some(ssid) = picked.filter(|s| state.known.contains(s)) {
                                wifi_forget = Some(ssid);
                            }
                        }
                    }
                }
            }
            PopupKind::Quick { net, radios, sound, dragging, hover } => match ui {
                Ui::PointerMove { x, y } => {
                    let h = QuickItem::at(x, y);
                    p.win.dirty |= h != *hover;
                    *hover = h;
                    if let (true, Some(s)) = (*dragging, sound.as_mut()) {
                        let v = volume_at(x);
                        if v != s.volume {
                            s.volume = v;
                            s.muted = false;
                            s.apply();
                            p.win.dirty = true;
                        }
                    }
                }
                Ui::PointerUp { .. } => *dragging = false,
                Ui::PointerLeave => {
                    p.win.dirty |= hover.is_some();
                    *hover = None;
                }
                Ui::PointerDown { x, y, button: button::LEFT, .. } => match QuickItem::at(x, y) {
                    Some(QuickItem::Network) if net.present => quick = Some(QuickItem::Network),
                    Some(QuickItem::Wifi) if radios.wifi_state.is_some() => wifi_open = radios.wifi_state.clone(),
                    Some(QuickItem::Volume) if sound.is_some() => {
                        let s = sound.as_mut().expect("checked");
                        s.volume = volume_at(x);
                        s.muted = false;
                        s.apply();
                        *dragging = true;
                        p.win.dirty = true;
                    }
                    Some(QuickItem::Mute) if sound.is_some() => {
                        let s = sound.as_mut().expect("checked");
                        s.muted = !s.muted;
                        s.apply();
                        p.win.dirty = true;
                    }
                    Some(QuickItem::Wifi) => radio_note = Some(("Wi-Fi", radios.wifi.clone())),
                    Some(QuickItem::Bluetooth) => radio_note = Some(("Bluetooth", radios.bluetooth.clone())),
                    Some(QuickItem::Settings) => quick = Some(QuickItem::Settings),
                    _ => {}
                },
                Ui::Key(k) if k.down && k.key == key::ESCAPE => close = true,
                _ => {}
            },
        }
        if close
            || launch.is_some()
            || pick.is_some()
            || confirm.is_some()
            || app_menu.is_some()
            || quick.is_some()
            || wifi_open.is_some()
            || wifi_join.is_some()
            || wifi_forget.is_some()
            || wifi_reconnect
        {
            self.close_popup();
        }
        if let Some(w) = wifi_open {
            self.open_wifi(w);
        }
        if let Some((ssid, pass)) = wifi_join {
            let joins_before = WifiState::read().map_or(0, |w| w.join);
            // The kernel rereads this file and joins (bsd::wifi_housekeeping).
            match os_std::fs::write("/etc/osyx/wifi.conf", format!("ssid={ssid}\npsk={pass}\n")) {
                Ok(()) => {
                    println!("desktop: joining Wi-Fi network {ssid}");
                    self.show_note("Wi-Fi", &format!("Joining {ssid}..."));
                    self.wifi_joining = Some((String::from(&ssid[..]), self.now(), joins_before));
                }
                Err(e) => self.show_note("Wi-Fi", &format!("Cannot save the network: {e}")),
            }
        }
        if wifi_reconnect {
            let request = format!("manual {}\n", self.now());
            match os_std::fs::write("/run/wifi.reconnect", request) {
                Ok(()) => self.show_note("Wi-Fi", "Reconnect requested."),
                Err(e) => self.show_note("Wi-Fi", &format!("Cannot reconnect: {e}")),
            }
        }
        if let Some(ssid) = wifi_forget {
            // The kernel drops the saved network and its passphrase.
            match os_std::fs::write("/etc/osyx/wifi.conf", format!("forget={ssid}\n")) {
                Ok(()) => self.show_note("Wi-Fi", &format!("{ssid} forgotten")),
                Err(e) => self.show_note("Wi-Fi", &format!("Cannot forget the network: {e}")),
            }
        }
        match radio_note {
            Some((what, Some(chip))) => self.show_note(
                what,
                &format!("{chip} found, but its driver did not start, so it cannot be switched on. The reason is in AXIS Terminal: dmesg {}", if what == "Wi-Fi" { "bsd" } else { "bluetooth" }),
            ),
            Some((what, None)) => self.show_note(what, &format!("No {what} adapter was found in this computer.")),
            None => {}
        }
        match quick {
            Some(QuickItem::Network) => self.launch("Network Center", NETWORK_APP),
            Some(QuickItem::Settings) => self.launch("Settings", SETTINGS_APP),
            _ => {}
        }
        if let Some(i) = launch {
            let app = self.apps[i].clone();
            self.launch(&app.name, &app.exec);
        }
        if let Some((purpose, i)) = pick {
            self.menu_pick(purpose, i);
        }
        if let Some(tag) = confirm {
            self.power(tag);
        }
        if let Some((i, x, y)) = app_menu {
            self.open_menu(vec![MenuItem::new("Add to desktop", Some(Icon::Link))], MenuPurpose::Application(i), x, y);
        }
    }

    fn menu_pick(&mut self, purpose: MenuPurpose, i: usize) {
        match (purpose, i) {
            (MenuPurpose::Application(app), 0) => self.add_shortcut(app),
            (MenuPurpose::Shortcut(app), 0) => self.launch_shortcut(app),
            (MenuPurpose::Shortcut(app), 1) => self.remove_shortcut(app),
            (MenuPurpose::Desktop, 5) => {
                self.toggle_launcher();
                self.show_note(
                    "Desktop shortcuts",
                    "Right-click an application in the launcher and choose Add to desktop.",
                );
            }
            (MenuPurpose::Desktop, 6) => self.refresh_shortcuts(),
            (MenuPurpose::Desktop, 0) => self.launch("Terminal", "/system/bin/terminal"),
            (MenuPurpose::Desktop, 1) => self.launch("Files", "/system/bin/files"),
            (MenuPurpose::Desktop, 2) => self.launch("System Information", "/system/bin/sysinfo"),
            (MenuPurpose::Desktop, 3) => {
                self.style = (self.style + 1) % WALLPAPERS;
                if self.style == 0 && self.image.is_none() {
                    self.style = 1;
                }
                paint_wallpaper(&mut self.wallpaper, self.w, self.h, self.style, self.image.as_deref(), &self.fonts);
                self.desktop.dirty = true;
                println!("desktop: wallpaper {}", self.style);
                let _ = os_std::fs::write("/etc/osyx/wallpaper", format!("{}\n", self.style));
            }
            (MenuPurpose::Desktop, 4) => {
                let info = os_std::os::sysinfo().ok();
                let version = info.as_ref().map_or("?", os_std::os::kernel_version);
                let body = format!("Kernel {version}, PRISM compositor, AXIS shell. Many surfaces. One vision.");
                self.show_note("OSyx", &body);
            }
            (MenuPurpose::Power, 0) => self.lock_screen(),
            (MenuPurpose::Power, 1) => self.confirm(
                CONFIRM_REBOOT,
                "Restart OSyx?",
                "All applications will be closed and the computer restarts.",
                "Restart",
            ),
            (MenuPurpose::Power, 2) => self.confirm(
                CONFIRM_OFF,
                "Shut down OSyx?",
                "All applications will be closed, file systems unmounted and the computer switched off.",
                "Shut down",
            ),
            _ => {}
        }
    }

    fn power(&mut self, tag: u32) {
        println!("desktop: {} requested", if tag == CONFIRM_OFF { "power off" } else { "restart" });
        let e = if tag == CONFIRM_OFF { system::power_off() } else { system::reboot() };
        // Only reached if the kernel refused.
        eprintln!("desktop: power request failed: {e}");
        self.show_note("Power", &format!("The system refused: {e}"));
    }

    /// System programs that need root (Setup writes whole disks) and are
    /// started without run-app's drop to the desktop user. Matched exactly,
    /// so a user-edited shortcut can start them but cannot add arguments.
    const PRIVILEGED: &'static [&'static str] = &["/system/bin/setup"];

    fn launch(&mut self, name: &str, exec: &str) {
        if exec == "/system/bin/zen" && self.children.iter().any(|(_, n)| n == name) {
            if let Some(window) = self.windows.iter().find(|w| w.title.contains("Zen")) {
                let _ = self.conn.window_action(window.id, Action::Activate, true);
            } else {
                self.show_note("Zen Browser", "Zen is starting. Its window will appear when startup finishes.");
            }
            return;
        }
        let command = if Self::PRIVILEGED.contains(&exec) {
            Command::new(exec)
        } else {
            let mut c = Command::new("/system/bin/run-app");
            c.arg(exec);
            c
        };
        match command.spawn() {
            Ok(child) => {
                println!("desktop: launched {} ({}) as process {}", name, exec, child.id());
                self.children.push((child.id(), String::from(name)));
                // The reaper thread collects it (dropping a Child does not wait).
            }
            Err(e) => {
                eprintln!("desktop: cannot start {exec}: {e}");
                self.show_note(&format!("Cannot start {name}"), &format!("{exec}: {e}"));
            }
        }
    }

    fn refresh_shortcuts(&mut self) {
        self.shortcut_scan = self.now();
        let entries = common::load_apps_from(common::DESKTOP_DIR);
        if entries.len() != self.shortcuts.len()
            || entries
                .iter()
                .zip(&self.shortcuts)
                .any(|(a, b)| a.source != b.source || a.name != b.name || a.exec != b.exec || a.icon != b.icon)
        {
            self.shortcuts = entries;
            self.icon_drag = None;
            self.load_shortcut_layout();
            self.selected_shortcut = None;
            self.desktop.dirty = true;
            println!("desktop: {} shortcut(s) in {}", self.shortcuts.len(), common::DESKTOP_DIR);
        }
    }

    fn add_shortcut(&mut self, i: usize) {
        let Some(app) = self.apps.get(i) else { return };
        let name = app.name.clone();
        let file = app.source.rsplit('/').next().unwrap_or("application.app");
        let target = format!("{}/{file}", common::DESKTOP_DIR);
        let result = os_std::fs::create_dir_all(common::DESKTOP_DIR)
            .and_then(|_| os_std::fs::read(&app.source))
            .and_then(|data| os_std::fs::write(&target, data));
        match result {
            Ok(()) => {
                println!("desktop: shortcut added: {name} -> {target}");
                self.refresh_shortcuts();
                self.show_note("Desktop shortcut", &format!("{name} added to the desktop."));
            }
            Err(e) => self.show_note("Cannot add shortcut", &format!("{e}")),
        }
    }

    fn launch_shortcut(&mut self, i: usize) {
        if let Some(app) = self.shortcuts.get(i).cloned() {
            self.launch(&app.name, &app.exec);
        }
    }

    fn load_shortcut_layout(&mut self) {
        let text = os_std::fs::read_to_string(format!("{}/.layout", common::DESKTOP_DIR)).unwrap_or_default();
        self.shortcut_cells.clear();
        let rows = shortcut_rows(self.h);
        let columns = (self.w.saturating_sub(32) / 116).max(1) as usize;
        let saved: Vec<Option<usize>> = self
            .shortcuts
            .iter()
            .map(|app| {
                let file = app.source.rsplit('/').next().unwrap_or("");
                text.lines().find_map(|line| {
                    let mut fields = line.split('\t');
                    if fields.next()? != file {
                        return None;
                    }
                    let col = fields.next()?.parse::<usize>().ok()?;
                    let row = fields.next()?.parse::<usize>().ok()?;
                    (col < columns && row < rows).then_some(col * rows + row)
                })
            })
            .collect();
        for cell in &saved {
            let cell = cell.filter(|c| !self.shortcut_cells.contains(c));
            let cell = cell.unwrap_or_else(|| {
                (0..).find(|c| !self.shortcut_cells.contains(c) && !saved.contains(&Some(*c))).unwrap_or(0)
            });
            self.shortcut_cells.push(cell);
        }
    }

    fn save_shortcut_layout(&mut self) {
        let rows = shortcut_rows(self.h);
        let mut text = String::new();
        for (app, &cell) in self.shortcuts.iter().zip(&self.shortcut_cells) {
            let file = app.source.rsplit('/').next().unwrap_or("");
            text.push_str(&format!("{file}\t{}\t{}\n", cell / rows, cell % rows));
        }
        let temp = format!("{}/.layout.tmp", common::DESKTOP_DIR);
        let target = format!("{}/.layout", common::DESKTOP_DIR);
        if let Err(e) = os_std::fs::write(&temp, text).and_then(|_| os_std::fs::rename(&temp, &target)) {
            self.show_note("Cannot save icon positions", &format!("{e}"));
        }
    }

    fn remove_shortcut(&mut self, i: usize) {
        let Some(app) = self.shortcuts.get(i) else { return };
        match os_std::fs::remove_file(&app.source) {
            Ok(()) => {
                println!("desktop: shortcut removed: {}", app.name);
                self.refresh_shortcuts();
            }
            Err(e) => self.show_note("Cannot remove shortcut", &format!("{e}")),
        }
    }

    fn collect_exits(&mut self) {
        let exits: Vec<(u64, i32)> = match EXITS.lock() {
            Ok(mut q) => core::mem::take(&mut *q),
            Err(_) => return,
        };
        for (pid, raw) in exits {
            let name = self.children.iter().position(|(p, _)| *p == pid).map(|i| self.children.remove(i).1);
            let name = name.unwrap_or_else(|| format!("process {pid}"));
            let st = os_std::process::ExitStatus::from_raw(raw);
            if st.success() {
                println!("desktop: {name} (process {pid}) exited");
            } else if let Some(v) = st.exception() {
                println!("desktop: {name} (process {pid}) crashed with CPU exception {v}");
                self.show_note(&format!("{name} crashed"), &format!("Process {pid} was stopped by CPU exception {v}. Its windows are gone; the desktop keeps running."));
            } else {
                println!("desktop: {name} (process {pid}) exited with status {raw}");
                if raw == 101 {
                    self.show_note(&format!("{name} stopped"), &format!("Process {pid} panicked (exit status 101)."));
                }
            }
        }
    }

    // ---- popups ------------------------------------------------------------

    fn recently_closed(&self, tag: PopupTag) -> bool {
        self.popup_closed.is_some_and(|(t, g)| g == tag && self.now().saturating_sub(t) < 400)
    }

    fn close_popup(&mut self) {
        if let Some(p) = self.popup.take() {
            let _ = p.win.destroy(&mut self.conn);
        }
        self.launcher_btn.active = false;
        self.panel.dirty = true;
    }

    fn open_popup(&mut self, x: i32, y: i32, w: u32, h: u32, kind: PopupKind) {
        self.close_popup();
        let mut spec = WindowSpec::with_role(Role::Popup, x, y, w, h);
        spec.title = String::from("popup");
        match self.conn.create_window(spec) {
            Ok(win) => self.popup = Some(Popup { win, kind, x, y }),
            Err(e) => eprintln!("desktop: cannot open a popup: {e}"),
        }
    }

    fn open_menu(&mut self, items: Vec<MenuItem>, purpose: MenuPurpose, x: i32, y: i32) {
        let mut menu = Menu::new(items);
        let (w, h) = menu.size(&self.fonts);
        menu.rect = Rect::new(0, 0, w, h);
        println!("desktop: {:?} menu opened at ({}, {})", purpose, x, y);
        self.open_popup(x, y, w, h, PopupKind::Menu { menu, purpose });
    }

    fn toggle_launcher(&mut self) {
        if self.popup.as_ref().is_some_and(|p| p.tag() == PopupTag::Launcher) {
            self.close_popup();
            return;
        }
        if self.recently_closed(PopupTag::Launcher) {
            return;
        }
        let mut search = TextField::new("");
        search.placeholder = String::from("Search applications");
        search.rect = Rect::new(16, 60, LAUNCHER_W - 32, 36);
        let mut list = ListView::new(vec![Column::new("Application", 0, Align::Left)]);
        list.row_height = 44;
        list.rect = Rect::new(8, 108, LAUNCHER_W - 16, LAUNCHER_H - 108 - 48);
        // Programs installed while the session runs appear at once.
        self.apps = load_apps();
        let shown = filter_apps(&self.apps, "");
        list.set_items(app_items(&self.apps, &shown));
        list.select(if shown.is_empty() { None } else { Some(0) });
        let y = (self.h - PANEL_H) as i32 - LAUNCHER_H as i32 - 8;
        println!("desktop: launcher opened ({} applications)", shown.len());
        self.open_popup(8, y, LAUNCHER_W, LAUNCHER_H, PopupKind::Launcher { search, list, shown, list_focus: false });
        self.launcher_btn.active = true;
        self.panel.dirty = true;
    }

    fn open_wifi(&mut self, state: WifiState) {
        let mut list = ListView::new(vec![Column::new("Network", 0, Align::Left), Column::new("Security", 120, Align::Right)]);
        list.show_header = false;
        list.row_height = 40;
        list.rect = Rect::new(8, 180, QUICK_PANEL_W - 16, WIFI_PANEL_H - 180 - 40);
        let items = state
            .networks
            .iter()
            .map(|(_, ssid, sec)| {
                let sec = match sec.as_str() {
                    "open" => "Open",
                    "wep" => "WEP",
                    _ => "WPA2",
                };
                let sec = if state.known.contains(ssid) { format!("{sec}, saved") } else { String::from(sec) };
                ListItem::new(Some(Icon::Wifi), &[ssid, &sec])
            })
            .collect();
        list.set_items(items);
        let x = self.w as i32 - QUICK_PANEL_W as i32 - 8;
        let y = (self.h - PANEL_H) as i32 - WIFI_PANEL_H as i32 - 8;
        println!("desktop: Wi-Fi picker opened ({} networks)", state.networks.len());
        self.open_popup(x, y, QUICK_PANEL_W, WIFI_PANEL_H, PopupKind::Wifi { state, list, pass: None, message: String::new() });
    }

    fn toggle_quick(&mut self) {
        if self.popup.as_ref().is_some_and(|p| p.tag() == PopupTag::Quick) {
            self.close_popup();
            return;
        }
        if self.recently_closed(PopupTag::Quick) {
            return;
        }
        let net = NetSummary::read();
        let radios = Radios::read();
        let sound = Sound::read();
        let x = self.w as i32 - QUICK_PANEL_W as i32 - 8;
        let y = (self.h - PANEL_H) as i32 - QUICK_PANEL_H as i32 - 8;
        println!(
            "desktop: quick settings opened (network: {}, sound: {})",
            net.detail,
            sound.as_ref().map_or("none", |s| s.device.as_str())
        );
        self.open_popup(x, y, QUICK_PANEL_W, QUICK_PANEL_H, PopupKind::Quick { net, radios, sound, dragging: false, hover: None });
        self.panel.dirty = true;
    }

    fn confirm(&mut self, tag: u32, title: &str, message: &str, action: &str) {
        let mut dialog =
            Dialog::new(tag, title, message, &[("Cancel", ButtonStyle::Secondary), (action, ButtonStyle::Danger)]);
        let w = 440;
        let h = dialog.height_for(w, &self.fonts);
        dialog.layout_card(Rect::new(0, 0, w, h), &self.fonts);
        let x = (self.w as i32 - w as i32) / 2;
        let y = (self.h as i32 - h as i32) / 2;
        self.open_popup(x, y, w, h, PopupKind::Confirm { dialog });
    }

    /// Volume Up/Down (5 % steps) and Mute keys: the kernel mixer, and one
    /// notification showing the level (replaced on every press).
    fn volume_key(&mut self, usage: u16) {
        let Some(mut s) = Sound::read() else { return };
        match usage {
            key::MUTE => s.muted = !s.muted,
            key::VOLUME_UP => {
                s.volume = (s.volume + 5).min(100);
                s.muted = false;
            }
            _ => s.volume = s.volume.saturating_sub(5),
        }
        s.apply();
        if let Some(i) = self.notes.iter().position(|n| n.title == "Volume") {
            let old = self.notes.remove(i);
            let _ = old.win.destroy(&mut self.conn);
        }
        let level = if s.muted { String::from("Muted") } else { format!("{} %", s.volume) };
        self.show_note("Volume", &level);
    }

    /// Announces a system update that /bin/osyx-update installed.
    fn check_update(&mut self) {
        let Ok(text) = os_std::fs::read_to_string("/run/update.status") else { return };
        if text.lines().any(|l| l == "state installed") {
            let version = text.lines().find_map(|l| l.strip_prefix("version ")).unwrap_or("");
            println!("desktop: system update {version} installed");
            self.show_note("System update", &format!("OSyx {version} is installed. Restart the computer to finish."));
            self.update_announced = true;
        }
    }

    /// Tells the user how joining the chosen Wi-Fi network ended: connected,
    /// or a wrong password (the kernel's WPA handshake watch).
    fn check_wifi_join(&mut self) {
        let Some((ssid, since, joins_before)) = self.wifi_joining.clone() else { return };
        let Some(w) = WifiState::read() else { return };
        // Until the kernel has applied this join, the state is the previous
        // attempt's (a wrong password among it).
        if w.join <= joins_before {
            if self.now().saturating_sub(since) > 60_000 {
                self.show_note("Wi-Fi", &format!("Could not connect to {ssid}."));
                self.wifi_joining = None;
            }
            return;
        }
        if w.error.as_deref() == Some("wrong-password") {
            println!("desktop: wrong Wi-Fi password for {ssid}");
            self.show_note("Wi-Fi: wrong password", &format!("{ssid} did not accept the password. Open Wi-Fi in Quick Settings and try again."));
            self.wifi_joining = None;
        } else if w.keys && w.ssid.as_deref() == Some(ssid.as_str()) {
            self.show_note("Wi-Fi", &format!("Connected to {ssid}"));
            self.wifi_joining = None;
        } else if self.now().saturating_sub(since) > 60_000 {
            self.show_note("Wi-Fi", &format!("Could not connect to {ssid}."));
            self.wifi_joining = None;
        }
    }

    // ---- notifications -----------------------------------------------------

    fn show_note(&mut self, title: &str, body: &str) {
        if self.notes.len() >= MAX_NOTES {
            let old = self.notes.remove(0);
            let _ = old.win.destroy(&mut self.conn);
        }
        let i = self.notes.len() as i32;
        let x = (self.w - NOTE_W - 16) as i32;
        let y = 16 + i * (NOTE_H as i32 + 10);
        match self.conn.create_window(WindowSpec::with_role(Role::Notification, x, y, NOTE_W, NOTE_H)) {
            Ok(win) => {
                let born = self.now();
                self.notes.push(Note { win, title: String::from(title), body: String::from(body), born });
            }
            Err(e) => eprintln!("desktop: cannot show a notification: {e}"),
        }
    }

    fn expire_notes(&mut self) {
        let now = self.now();
        let before = self.notes.len();
        let mut i = 0;
        while i < self.notes.len() {
            if now.saturating_sub(self.notes[i].born) >= NOTE_MS {
                let n = self.notes.remove(i);
                let _ = n.win.destroy(&mut self.conn);
            } else {
                i += 1;
            }
        }
        if self.notes.len() != before {
            self.restack_notes();
        }
    }

    fn restack_notes(&mut self) {
        let x = (self.w - NOTE_W - 16) as i32;
        for (i, n) in self.notes.iter_mut().enumerate() {
            let y = 16 + i as i32 * (NOTE_H as i32 + 10);
            let _ = n.win.set_geometry(&mut self.conn, x, y, NOTE_W, NOTE_H);
        }
    }

    // ---- panel ---------------------------------------------------------------

    fn quick_rect(&self) -> Rect {
        let r = self.power_btn.rect;
        Rect::new(r.x - 12 - QUICK_W as i32, 8, QUICK_W, PANEL_H - 16)
    }

    /// The battery indicator left of quick settings, when there is a battery.
    fn battery_rect(&self) -> Option<Rect> {
        self.battery?;
        let r = self.quick_rect();
        Some(Rect::new(r.x - 4 - BATTERY_W as i32, 8, BATTERY_W, PANEL_H - 16))
    }

    fn clock_rect(&self) -> Rect {
        let r = self.battery_rect().unwrap_or(self.quick_rect());
        Rect::new(r.x - 4 - CLOCK_W as i32, 6, CLOCK_W, PANEL_H - 12)
    }

    fn update_battery(&mut self) {
        let b = Battery::read();
        if b != self.battery {
            let appeared = b.is_some() != self.battery.is_some();
            self.battery = b;
            if appeared {
                // The clock moves, and with it the room for task buttons.
                self.layout_panel();
            }
            self.panel.dirty = true;
        }
    }

    fn update_clock(&mut self) {
        self.tz = system_tz();
        if let Some(style) = os_std::fs::read_to_string("/etc/osyx/wallpaper")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&s| s < WALLPAPERS)
        {
            if style != self.style && (style != 0 || self.image.is_some()) {
                self.style = style;
                paint_wallpaper(&mut self.wallpaper, self.w, self.h, style, self.image.as_deref(), &self.fonts);
                self.desktop.dirty = true;
                println!("desktop: wallpaper {style}");
            }
        }
        let l = self.tz.local(unix_now());
        let c = (l.hm(), l.short_date());
        if c != self.clock {
            self.clock = c;
            self.panel.dirty = true;
        }
    }

    fn layout_panel(&mut self) {
        let h = PANEL_H;
        self.launcher_btn.rect = Rect::new(8, 8, 44, h as i32 as u32 - 16);
        self.power_btn.rect = Rect::new(self.w as i32 - 8 - 40, 8, 40, h - 16);
        let left = 64;
        let right = self.clock_rect().x - 12;
        let n = self.windows.len().max(1) as i32;
        let avail = (right - left).max(0);
        let each = (avail / n).clamp(40, 220);
        self.tasks = self
            .windows
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let mut b = Button::new(i, &w.title, ButtonStyle::Flat).with_icon(task_icon(&w.title));
                b.rect = Rect::new(left + i as i32 * (each + 4), 8, (each - 4).max(36) as u32, h - 16);
                b.active = w.flags & state::ACTIVATED != 0 && w.flags & state::MINIMIZED == 0;
                b
            })
            .collect();
        self.panel.dirty = true;
    }

    // ---- drawing ---------------------------------------------------------------

    fn redraw(&mut self) -> os_std::error::Result<()> {
        let (theme, fonts) = (self.theme, self.fonts);
        if self.desktop.dirty && self.desktop.can_draw() {
            let (w, h) = (self.desktop.width, self.desktop.height);
            if (w, h) == (self.w, self.h) {
                let mut s = self.desktop.surface()?;
                for y in 0..h {
                    let row = &self.wallpaper[(y * w) as usize..][..w as usize];
                    s.row_mut(y).copy_from_slice(row);
                }
                let mut p = Painter::new(&mut s, &theme, &fonts);
                for (i, app) in self.shortcuts.iter().enumerate() {
                    let mut r = shortcut_rect(self.shortcut_cells[i], h);
                    if let Some(drag) = &self.icon_drag {
                        if drag.index == i && drag.moved {
                            r.x += drag.pointer.0 - drag.start.0;
                            r.y += drag.pointer.1 - drag.start.1;
                        }
                    }
                    if r.right() > w as i64 {
                        continue;
                    }
                    p.rounded(r, 10, rgb(10, 16, 28), if self.selected_shortcut == Some(i) { 205 } else { 100 });
                    if self.selected_shortcut == Some(i) {
                        p.rounded(r, 10, theme.accent, 65);
                    }
                    icon::draw(&mut p, app.icon, Rect::new(r.x + 32, r.y + 8, 40, 40), rgb(235, 240, 255));
                    icon::draw(&mut p, Icon::Link, Rect::new(r.x + 28, r.y + 36, 16, 16), theme.accent);
                    p.text_in(
                        FontKind::Ui,
                        Rect::new(r.x + 4, r.y + 54, r.w - 8, 30),
                        &app.name,
                        rgb(250, 251, 255),
                        Align::Center,
                    );
                }
            }
            self.desktop.present(&mut self.conn, None)?;
        }
        if self.panel.dirty && self.panel.can_draw() {
            let clock = self.clock_rect();
            let quick = (
                self.quick_rect(),
                self.quick_hover,
                self.popup.as_ref().is_some_and(|p| p.tag() == PopupTag::Quick),
            );
            let battery = self.battery_rect().zip(self.battery);
            let mut s = self.panel.surface()?;
            let mut p = Painter::new(&mut s, &theme, &fonts);
            draw_panel(
                &mut p,
                &self.launcher_btn,
                &self.power_btn,
                &self.tasks,
                &self.clock,
                clock,
                self.clock_hover,
                quick,
                battery,
                self.windows.is_empty(),
            );
            self.panel.present(&mut self.conn, None)?;
        }
        if let Some(pop) = &mut self.popup {
            if pop.win.dirty && pop.win.can_draw() {
                let mut s = pop.win.surface()?;
                let mut p = Painter::new(&mut s, &theme, &fonts);
                draw_popup(&mut p, &pop.kind, &self.apps);
                pop.win.present(&mut self.conn, None)?;
            }
        }
        for n in &mut self.notes {
            if n.win.dirty && n.win.can_draw() {
                let mut s = n.win.surface()?;
                let mut p = Painter::new(&mut s, &theme, &fonts);
                draw_note(&mut p, &n.title, &n.body);
                n.win.present(&mut self.conn, None)?;
            }
        }
        if let Some(l) = &mut self.lock {
            if l.win.dirty && l.win.can_draw() && (l.win.width, l.win.height) == (self.w, self.h) {
                let mut s = l.win.surface()?;
                for y in 0..self.h {
                    let row = &self.wallpaper[(y * self.w) as usize..][..self.w as usize];
                    s.row_mut(y).copy_from_slice(row);
                }
                let mut p = Painter::new(&mut s, &theme, &fonts);
                draw_lock(&mut p, &l.field, &l.message, &self.clock);
                l.win.present(&mut self.conn, None)?;
            }
        }
        Ok(())
    }
}

fn draw_lock(p: &mut Painter, field: &TextField, message: &str, clock: &(String, String)) {
    let t = *p.theme;
    let full = p.s.bounds();
    p.blend(full, rgb(4, 8, 18), 150);
    let cx = full.w as i32 / 2;
    let cy = full.h as i32 / 2;
    let big = p.fonts.line_height(FontKind::Display);
    p.text_in(FontKind::Display, Rect::new(0, cy - 150, full.w, big), &clock.0, rgb(245, 248, 255), Align::Center);
    let lh = p.fonts.line_height(FontKind::Large);
    p.text_in(FontKind::Large, Rect::new(0, cy - 150 + big as i32 + 4, full.w, lh), &clock.1, rgb(210, 220, 240), Align::Center);
    icon::draw(p, Icon::Lock, Rect::new(cx - 14, cy - 10, 28, 28), rgb(230, 236, 250));
    let r = field.rect;
    let card = Rect::new(r.x - 6, r.y - 6, r.w + 12, r.h + 12);
    p.rounded(card, t.radius, rgb(10, 14, 24), 200);
    field.draw(p, true);
    let ul = p.fonts.line_height(FontKind::Ui);
    let below = field.rect.bottom() as i32 + 14;
    let (msg, color) = if message.is_empty() {
        ("Type your password and press Enter", rgb(190, 200, 220))
    } else {
        (message, t.danger)
    };
    p.text_in(FontKind::Ui, Rect::new(0, below, full.w, ul), msg, color, Align::Center);
}

fn task_icon(title: &str) -> Icon {
    if title.contains("Zen") {
        Icon::Browser
    } else if title.contains("Terminal") {
        Icon::Terminal
    } else if title.contains("Files") {
        Icon::Folder
    } else if title.contains("System") {
        Icon::Info
    } else {
        Icon::Program
    }
}

fn shortcut_rows(h: u32) -> usize {
    (h.saturating_sub(PANEL_H + 32) / 100).max(1) as usize
}

fn shortcut_rect(i: usize, h: u32) -> Rect {
    let rows = shortcut_rows(h);
    Rect::new(16 + (i / rows) as i32 * 116, 16 + (i % rows) as i32 * 100, 104, 92)
}

fn filter_apps(apps: &[AppEntry], q: &str) -> Vec<usize> {
    let q = q.to_lowercase();
    (0..apps.len())
        .filter(|&i| {
            q.is_empty() || apps[i].name.to_lowercase().contains(&q) || apps[i].comment.to_lowercase().contains(&q)
        })
        .collect()
}

fn app_items(apps: &[AppEntry], shown: &[usize]) -> Vec<ListItem> {
    shown.iter().map(|&i| ListItem::new(Some(apps[i].icon), &[&apps[i].name])).collect()
}

const PANEL_BG: Color = rgb(11, 14, 21);
const PANEL_LINE: Color = rgb(34, 41, 56);

#[allow(clippy::too_many_arguments)]
fn draw_panel(
    p: &mut Painter,
    launcher: &Button,
    power: &Button,
    tasks: &[Button],
    clock: &(String, String),
    clock_rect: Rect,
    clock_hover: bool,
    (quick_rect, quick_hover, quick_open): (Rect, bool, bool),
    battery: Option<(Rect, Battery)>,
    empty: bool,
) {
    let t = *p.theme;
    let full = p.s.bounds();
    p.fill(full, PANEL_BG);
    p.hline(0, 0, full.w, PANEL_LINE);
    launcher.draw(p, false);
    for b in tasks {
        b.draw(p, false);
    }
    if empty {
        let r = Rect::new(72, 0, 460, full.h);
        p.text_in(
            FontKind::Ui,
            r,
            "Press Super or click the launcher to start an application",
            t.text_faint,
            Align::Left,
        );
    }
    if clock_hover {
        p.rounded(clock_rect, t.radius_small, t.raised, 255);
    }
    let lh = p.fonts.line_height(FontKind::Bold);
    let top = Rect::new(clock_rect.x, clock_rect.y + 2, clock_rect.w - 10, lh);
    p.text_in(FontKind::Bold, top, &clock.0, t.text, Align::Right);
    let bottom = Rect::new(clock_rect.x, clock_rect.y + 2 + lh as i32, clock_rect.w - 10, lh);
    p.text_in(FontKind::Ui, bottom, &clock.1, t.text_dim, Align::Right);
    if quick_hover || quick_open {
        p.rounded(quick_rect, t.radius_small, if quick_open { t.selection } else { t.raised }, 255);
    }
    let icon_y = quick_rect.y + (quick_rect.h as i32 - 20) / 2;
    icon::draw(p, Icon::Network, Rect::new(quick_rect.x + 10, icon_y, 20, 20), t.text);
    icon::draw(p, Icon::Volume, Rect::new(quick_rect.x + 36, icon_y, 20, 20), t.text);
    if let Some((r, b)) = battery {
        draw_battery(p, r, b);
    }
    p.vline(quick_rect.right() as i32 + 5, 12, full.h - 24, PANEL_LINE);
    power.draw(p, false);
}

/// Battery cell with its charge level, a lightning bolt while charging, and
/// the percentage beside it.
fn draw_battery(p: &mut Painter, r: Rect, b: Battery) {
    let t = *p.theme;
    let (body_w, body_h) = (26u32, 14u32);
    let x = r.x + 4;
    let y = r.y + (r.h as i32 - body_h as i32) / 2;
    let level = if b.charging {
        rgb(80, 200, 120)
    } else if b.percent <= 15 {
        rgb(232, 72, 72)
    } else {
        t.text
    };
    // Outline (two pixels) and the terminal nub on the right.
    for i in 0..2 {
        p.hline(x, y + i, body_w, t.text);
        p.hline(x, y + body_h as i32 - 1 - i, body_w, t.text);
        p.vline(x + i, y, body_h, t.text);
        p.vline(x + body_w as i32 - 1 - i, y, body_h, t.text);
    }
    p.fill(Rect::new(x + body_w as i32, y + 4, 3, body_h - 8), t.text);
    // Charge level inside a one-pixel gap.
    let inner_w = body_w - 6;
    let filled = (inner_w * b.percent.min(100)).div_ceil(100).max(u32::from(b.percent > 0));
    p.fill(Rect::new(x + 3, y + 3, filled, body_h - 6), level);
    if b.charging {
        // A bolt across the cell: down-left stroke, short bar, down-left stroke.
        let (cx, cy) = (x + body_w as i32 / 2, y + body_h as i32 / 2);
        for dx in 0..2 {
            p.line(cx + 3 + dx, y - 3, cx - 2 + dx, cy + 1, PANEL_BG);
            p.line(cx - 2 + dx, cy, cx + 3 + dx, cy, PANEL_BG);
            p.line(cx + 2 + dx, cy - 1, cx - 3 + dx, y + body_h as i32 + 2, PANEL_BG);
        }
        p.line(cx + 4, y - 2, cx - 1, cy, rgb(255, 214, 64));
        p.line(cx - 1, cy, cx + 4, cy, rgb(255, 214, 64));
        p.line(cx + 3, cy, cx - 2, y + body_h as i32 + 1, rgb(255, 214, 64));
    }
    let text = format!("{}%", b.percent.min(100));
    let tr = Rect::new(x + body_w as i32 + 7, r.y, r.w.saturating_sub(body_w + 11), r.h);
    p.text_in(FontKind::Ui, tr, &text, if b.percent <= 15 && !b.charging { level } else { t.text }, Align::Left);
}

/// Controls without a working driver are shown but disabled (naming the
/// chip when the kernel identified one) rather than pretending to work.
fn draw_quick(p: &mut Painter, net: &NetSummary, radios: &Radios, sound: Option<&Sound>, hover: Option<QuickItem>) {
    let t = *p.theme;
    p.text(FontKind::Large, 20, 16, "Quick settings", t.text);
    // A found chip without a driver is named but stays off.
    let wifi_detail = match &radios.wifi_state {
        Some(w) => w.ssid.clone().unwrap_or_else(|| w.state.clone()),
        None => String::from(radios.wifi.as_deref().map_or("No adapter", chip_short)),
    };
    let wifi_on = radios.wifi_state.as_ref().is_some_and(|w| w.ssid.is_some());
    let bt = radios.bluetooth.as_deref().map_or("No adapter", chip_short);
    let tiles = [
        (QuickItem::Network, Icon::Network, "Ethernet", net.detail.as_str(), net.present, net.connected),
        (QuickItem::Wifi, Icon::Wifi, "Wi-Fi", wifi_detail.as_str(), radios.wifi_state.is_some(), wifi_on),
        (QuickItem::Bluetooth, Icon::Bluetooth, "Bluetooth", bt, false, false),
    ];
    let lh = p.fonts.line_height(FontKind::Bold);
    for (item, ic, title, detail, enabled, on) in tiles {
        let r = item.rect();
        let hovered = hover == Some(item);
        let (bg, fg, sub) = match (enabled, on) {
            (true, true) => (if hovered { t.accent_hover } else { t.accent }, t.on_accent, t.on_accent),
            (true, false) => (if hovered { t.selection } else { t.raised }, t.text, t.text_dim),
            _ => (t.window, t.text_faint, t.text_faint),
        };
        p.rounded(r, t.radius, bg, 255);
        icon::draw(p, ic, Rect::new(r.x + 12, r.y + 12, 26, 26), fg);
        p.text_in(FontKind::Bold, Rect::new(r.x + 12, r.y + 46, r.w - 20, lh), title, fg, Align::Left);
        p.text_in(FontKind::Ui, Rect::new(r.x + 12, r.y + 46 + lh as i32, r.w - 16, lh), detail, sub, Align::Left);
    }
    // Volume: a working slider with a sound driver, a disabled one without.
    let y = VOLUME_Y;
    let track = volume_track();
    p.rounded(track, 3, t.raised, 255);
    match sound {
        Some(s) => {
            let shown = if s.muted { 0 } else { s.volume };
            p.text(FontKind::Bold, 20, y, &format!("Volume  {}%", shown), t.text);
            let mute_bg = if hover == Some(QuickItem::Mute) { t.selection } else { t.surface };
            p.rounded(QuickItem::Mute.rect(), t.radius_small, mute_bg, 255);
            icon::draw(p, Icon::Volume, Rect::new(20, y + 30, 22, 22), if s.muted { t.text_faint } else { t.text });
            let knob = track.x + (track.w * shown / 100) as i32;
            p.rounded(Rect::new(track.x, track.y, (knob - track.x).max(0) as u32, track.h), 3, t.accent, 255);
            p.disc(knob, track.y + 3, 8, if hover == Some(QuickItem::Volume) { t.accent_hover } else { t.accent }, 255);
            let detail = if s.muted { format!("{} (muted)", s.device) } else { s.device.clone() };
            p.text(FontKind::Ui, 54, y + 52, &detail, t.text_dim);
        }
        None => {
            p.text(FontKind::Bold, 20, y, "Volume", t.text_dim);
            icon::draw(p, Icon::Volume, Rect::new(20, y + 30, 22, 22), t.text_faint);
            p.disc(track.x, track.y + 3, 8, t.text_faint, 255);
            p.text(FontKind::Ui, 54, y + 52, "No sound device found", t.text_faint);
        }
    }
    // Footer.
    let fy = (QUICK_PANEL_H - 64) as i32;
    p.hline(12, fy, QUICK_PANEL_W - 24, t.border);
    let s = QuickItem::Settings.rect();
    p.rounded(s, t.radius_small, if hover == Some(QuickItem::Settings) { t.selection } else { t.raised }, 255);
    icon::draw(p, Icon::Settings, Rect::new(s.x + 12, s.y + 8, 20, 20), t.text);
    p.text_in(FontKind::Ui, Rect::new(s.x + 40, s.y, s.w - 48, s.h), "All settings", t.text, Align::Left);
}

fn wifi_reconnect_rect() -> Rect { Rect::new(220, 14, 120, 32) }

fn draw_wifi(p: &mut Painter, state: &WifiState, list: &ListView, pass: Option<&(String, TextField, Checkbox)>, message: &str) {
    let t = *p.theme;
    p.text(FontKind::Large, 20, 16, "Wi-Fi", t.text);
    let status = match &state.ssid {
        Some(s) if state.keys => format!("Connected to {s}"),
        Some(s) => format!("Connecting to {s}"),
        None => format!("Not connected ({})", state.state),
    };
    p.text(FontKind::Ui, 20, 52, &status, t.text_dim);
    if pass.is_none() {
        let r = wifi_reconnect_rect();
        p.rounded(r, t.radius_small, t.raised, 255);
        p.text_in(FontKind::Ui, r, "Reconnect", t.text, Align::Center);
        for (i, line) in state.diagnostics.iter().take(5).enumerate() {
            p.text(FontKind::Ui, 20, 76 + i as i32 * 19, line, t.text_dim);
        }
    }
    match pass {
        Some((ssid, field, show)) => {
            show.draw(p, false);
            let lh = p.fonts.line_height(FontKind::Bold);
            let top = field.rect.y - 2 * lh as i32 - 12;
            p.text(FontKind::Bold, 20, top, &format!("Password for {ssid}"), t.text);
            field.draw(p, true);
            let (msg, color) = if message.is_empty() { ("Enter to join, Esc to go back", t.text_faint) } else { (message, t.danger) };
            p.text(FontKind::Ui, 20, field.rect.bottom() as i32 + 10, msg, color);
        }
        None if state.networks.is_empty() => {
            p.text_in(FontKind::Ui, list.rect, "No networks seen yet. Scanning...", t.text_faint, Align::Center);
        }
        None => {
            list.draw(p, true);
            let hint = if state.known.is_empty() { "Enter to join" } else { "Enter to join, Delete to forget a saved network" };
            p.text(FontKind::Ui, 20, (WIFI_PANEL_H - 34) as i32, hint, t.text_faint);
        }
    }
}

fn draw_popup(p: &mut Painter, kind: &PopupKind, apps: &[AppEntry]) {
    let t = *p.theme;
    let full = p.s.bounds();
    p.fill(full, t.surface);
    match kind {
        PopupKind::Launcher { search, list, shown, list_focus } => {
            p.text(FontKind::Large, 20, 18, "Applications", t.text);
            search.draw(p, !*list_focus);
            if shown.is_empty() {
                let r = list.rect;
                p.text_in(
                    FontKind::Ui,
                    r,
                    if apps.is_empty() { "No applications installed" } else { "Nothing matches" },
                    t.text_faint,
                    Align::Center,
                );
            } else {
                list.draw(p, true);
            }
            let footer = Rect::new(20, (LAUNCHER_H - 44) as i32, LAUNCHER_W - 40, 40);
            p.hline(12, footer.y, LAUNCHER_W - 24, t.border);
            let comment = list.selected().and_then(|i| shown.get(i)).map_or("", |&i| apps[i].comment.as_str());
            p.text_in(FontKind::Ui, footer, comment, t.text_dim, Align::Left);
        }
        PopupKind::Menu { menu, .. } => menu.draw(p),
        PopupKind::Confirm { dialog } => dialog.draw(p),
        PopupKind::Quick { net, radios, sound, hover, .. } => draw_quick(p, net, radios, sound.as_ref(), *hover),
        PopupKind::Wifi { state, list, pass, message } => draw_wifi(p, state, list, pass.as_ref(), message),
    }
    // A one pixel frame (popups are square; PRISM adds the shadow).
    p.fill(Rect::new(0, 0, full.w, 1), t.border);
    p.fill(Rect::new(0, full.h as i32 - 1, full.w, 1), t.border);
    p.fill(Rect::new(0, 0, 1, full.h), t.border);
    p.fill(Rect::new(full.w as i32 - 1, 0, 1, full.h), t.border);
}

fn draw_note(p: &mut Painter, title: &str, body: &str) {
    let t = *p.theme;
    let full = p.s.bounds();
    p.fill(full, t.surface);
    p.fill(Rect::new(0, 0, 3, full.h), t.accent);
    icon::draw(p, Icon::Bell, Rect::new(16, 16, 20, 20), t.accent);
    let lh = p.fonts.line_height(FontKind::Bold);
    p.text_in(FontKind::Bold, Rect::new(48, 12, full.w - 60, lh), title, t.text, Align::Left);
    let lines = osyx_ui::widget::wrap_text(p.fonts, FontKind::Ui, body, full.w - 60);
    let ul = p.fonts.line_height(FontKind::Ui);
    for (i, l) in lines.iter().take(2).enumerate() {
        p.text(FontKind::Ui, 48, 14 + lh as i32 + 4 + i as i32 * ul as i32, l, t.text_dim);
    }
    let r = inset(full, 0);
    p.fill(Rect::new(r.x, r.bottom() as i32 - 1, r.w, 1), t.border);
}

/// Draws one of the desktop backgrounds. Style 0 is the OSyx wallpaper
/// image, scaled to cover the screen; styles 1..=3 are drawn: a deep
/// midnight gradient lit by soft glows and a prism refracting a beam of
/// light into restrained blues and violets.
fn paint_wallpaper(buf: &mut [u32], w: u32, h: u32, style: usize, image: Option<&[u8]>, fonts: &Fonts) {
    let theme = Theme::default();
    let Ok(mut s) = Surface::new(buf, w, h, w) else { return };
    if style == 0 {
        if let Some(img) = image.and_then(|d| osyx_gfx::Image::parse(d).ok()) {
            // Cover: fill the screen keeping the aspect ratio, centred.
            let (iw, ih) = (img.width() as u64, img.height() as u64);
            let (dw, dh) = if w as u64 * ih > h as u64 * iw {
                (w as u64, ih * w as u64 / iw)
            } else {
                (iw * h as u64 / ih, h as u64)
            };
            let dst = Rect::new((w as i32 - dw as i32) / 2, (h as i32 - dh as i32) / 2, dw as u32, dh as u32);
            s.fill(rgb(4, 8, 20));
            img.draw_scaled(&mut s, dst, 255);
            return;
        }
    }
    let (top, bottom, glow_a, glow_b) = match style {
        2 => (rgb(22, 16, 34), rgb(8, 7, 14), rgb(92, 52, 150), rgb(30, 70, 140)),
        3 => (rgb(9, 16, 22), rgb(4, 7, 10), rgb(20, 90, 110), rgb(26, 50, 110)),
        _ => (rgb(14, 19, 33), rgb(6, 8, 14), rgb(34, 64, 150), rgb(20, 88, 122)),
    };
    s.gradient_v(Rect::new(0, 0, w, h), top, bottom);
    let (fw, fh) = (w as i32, h as i32);
    s.radial_glow(fw * 18 / 100, fh * 12 / 100, w * 55 / 100, glow_a, 80);
    s.radial_glow(fw * 88 / 100, fh * 92 / 100, w * 45 / 100, glow_b, 55);
    let mut p = Painter::new(&mut s, &theme, fonts);
    if style != 3 {
        // The prism: an equilateral-ish triangle right of centre.
        let cx = fw * 60 / 100;
        let cy = fh * 46 / 100;
        let size = fh * 30 / 100;
        let apex = (cx, cy - size / 2);
        let left = (cx - size * 58 / 100, cy + size / 2);
        let right = (cx + size * 58 / 100, cy + size / 2);
        let fx = |(x, y): (i32, i32)| (x << 8, y << 8);
        // Incoming white beam hitting the left face.
        let hit = ((apex.0 + left.0) / 2, (apex.1 + left.1) / 2);
        let beam_from = (0, cy + size / 6);
        p.segment(fx(beam_from), fx(hit), 8 << 8, rgb(190, 205, 235), 18);
        p.segment(fx(beam_from), fx(hit), 2 << 8, rgb(220, 228, 245), 90);
        // Refracted fan leaving the right face.
        let exit = ((apex.0 + right.0) / 2 + 4, (apex.1 + right.1) / 2 + 6);
        let colors = [rgb(120, 140, 255), rgb(96, 170, 245), rgb(88, 200, 210), rgb(150, 130, 240), rgb(196, 128, 220)];
        for (i, c) in colors.iter().enumerate() {
            let spread = (i as i32 - 2) * fh * 7 / 100;
            let to = (fw + 40, cy + size / 3 + spread + fh * 8 / 100);
            p.segment(fx(exit), fx(to), 14 << 8, *c, 14);
            p.segment(fx(exit), fx(to), 3 << 8, *c, if style == 2 { 70 } else { 55 });
        }
        // Glass body: faint fill by horizontal spans, bright edges.
        for y in apex.1..left.1 {
            let t = (y - apex.1) * 256 / (left.1 - apex.1).max(1);
            let x0 = apex.0 + (left.0 - apex.0) * t / 256;
            let x1 = apex.0 + (right.0 - apex.0) * t / 256;
            p.blend(Rect::new(x0, y, (x1 - x0).max(0) as u32, 1), rgb(120, 150, 220), 14 + (t as u32 * 10 / 256));
        }
        for (a, b) in [(apex, left), (left, right), (right, apex)] {
            p.segment(fx(a), fx(b), 6 << 8, rgb(150, 178, 240), 22);
            p.segment(fx(a), fx(b), 3 << 7, rgb(200, 215, 248), 150);
        }
    }
    let lh = fonts.line_height(FontKind::Ui);
    let label = "OSyx  ·  PRISM";
    let tw = fonts.measure(FontKind::Ui, label);
    p.text_alpha(FontKind::Ui, fw - tw as i32 - 24, fh - PANEL_H as i32 - lh as i32 - 16, label, theme.text_dim, 110);
}
