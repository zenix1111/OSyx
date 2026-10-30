//! OSyx Settings (`/system/bin/settings`): a sidebar of categories and a
//! panel of grouped options, in the style of a modern desktop settings
//! app. Every option writes real system configuration:
//!
//! * Appearance: accent colour (`/etc/osyx/accent`, read by every OSyx
//!   application when it starts) and the desktop background
//!   (`/etc/osyx/wallpaper`, applied by the desktop shell within seconds);
//! * Keyboard: layout (`/etc/osyx/keyboard`, read by PRISM at start);
//! * Date & Time: time zone (`/etc/TZ`, a POSIX TZ string);
//! * Network: DHCP or a static IPv4 address for each interface (the
//!   kernel's network configuration, `net_config`);
//! * General: host name (`/etc/hostname`);
//! * Display, Storage and About show the live system state.
//!
//! Settings runs as root (it changes system files); it does not drop to
//! the desktop user like the other applications.

#![no_std]
#![no_main]

#[path = "../shell_common.rs"]
mod common;

use common::{human_size, run_app, App, Ctx};
use os_std::prelude::*;
use os_std::{fs, os, system};
use osyx_gfx::{Color, Rect};
use osyx_ui::widget::{Button, ButtonStyle, TextField};
use osyx_ui::{icon, Align, Event as Ui, FontKind, Icon, Painter, Response};
use prism_client::WindowSpec;

os_std::entry!(main);

const SIDEBAR: u32 = 240;
/// Written by the update daemon (root) and read here.
const UPDATE_STATUS: &str = "/run/update.status";
/// Where Settings asks the daemon (`osyx-update --daemon`, root) for a check
/// (`check`) or an installation (`install`); the daemon removes it.
const UPDATE_REQUEST: &str = "/etc/osyx/update.request";

/// State of the system update service: (state, version, detail).
fn update_state() -> (String, String, String) {
    let text = fs::read_to_string(UPDATE_STATUS).unwrap_or_default();
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).map(|v| String::from(v.trim()))).unwrap_or_default();
    (field("state "), field("version "), field("detail "))
}

/// What to tell the user about the update service.
fn update_text() -> String {
    if fs::metadata("/etc/osyx/installed").is_err() {
        return String::from("Updates are only available on an installed system");
    }
    if fs::metadata("/etc/osyx/update.conf").is_err() {
        return String::from("Updates are not configured (no /etc/osyx/update.conf)");
    }
    let (state, version, detail) = update_state();
    match state.as_str() {
        "checking" => String::from("Checking for updates..."),
        "up-to-date" => String::from("OSyx is up to date"),
        "available" => format!("Version {version} is available"),
        "downloading" => format!("Downloading {version} {detail}"),
        "installing" => format!("Installing {version}..."),
        "installed" => format!("{version} is installed: restart to finish"),
        "failed" => format!("Failed: {detail}"),
        _ => String::from("Not checked yet (the service checks once a day)"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    General,
    Appearance,
    Display,
    Keyboard,
    DateTime,
    Network,
    Storage,
    About,
}

const SECTIONS: [(Section, &str, Icon); 8] = [
    (Section::General, "General", Icon::Program),
    (Section::Appearance, "Appearance", Icon::Apps),
    (Section::Display, "Displays", Icon::Device),
    (Section::Keyboard, "Keyboard", Icon::Device),
    (Section::DateTime, "Date & Time", Icon::Bell),
    (Section::Network, "Network", Icon::Link),
    (Section::Storage, "Storage", Icon::Drive),
    (Section::About, "About", Icon::Info),
];

pub const ACCENTS: [(&str, Color); 8] = [
    ("Blue", osyx_gfx::rgb(76, 141, 255)),
    ("Purple", osyx_gfx::rgb(160, 110, 240)),
    ("Pink", osyx_gfx::rgb(236, 92, 160)),
    ("Red", osyx_gfx::rgb(240, 84, 84)),
    ("Orange", osyx_gfx::rgb(245, 150, 60)),
    ("Yellow", osyx_gfx::rgb(240, 200, 60)),
    ("Green", osyx_gfx::rgb(80, 196, 120)),
    ("Graphite", osyx_gfx::rgb(140, 146, 160)),
];

const WALLPAPERS: [&str; 4] = ["OSyx", "Deep blue", "Aurora", "Graphite"];
const LAYOUTS: [(&str, &str); 2] = [("us", "English (US)"), ("pl", "Polish (Programmer)")];
const ZONES: [(&str, &str); 6] = [
    ("UTC0", "UTC"),
    ("CET-1CEST,M3.5.0,M10.5.0/3", "Central European (Warsaw, Berlin)"),
    ("GMT0BST,M3.5.0/1,M10.5.0", "United Kingdom (London)"),
    ("EST5EDT,M3.2.0,M11.1.0", "US Eastern (New York)"),
    ("PST8PDT,M3.2.0,M11.1.0", "US Pacific (Los Angeles)"),
    ("JST-9", "Japan (Tokyo)"),
];

struct Settings {
    section: Section,
    size: (u32, u32),
    accent: usize,
    wallpaper: usize,
    layout: usize,
    zone: usize,
    hostname: TextField,
    save_host: Button,
    dhcp: Button,
    static_btn: Button,
    addr: TextField,
    gateway: TextField,
    apply_net: Button,
    check_update: Button,
    install_update: Button,
    status: String,
    focus: usize,
}

fn read(path: &str) -> String {
    fs::read_to_string(path).map(|s| String::from(s.trim())).unwrap_or_default()
}

fn write(path: &str, value: &str) -> String {
    let _ = fs::create_dir("/etc/osyx");
    match fs::write(path, format!("{value}\n").as_bytes()) {
        Ok(()) => {
            println!("settings: saved {path}={value}");
            format!("Saved {path}")
        },
        Err(e) => format!("Cannot write {path}: {e}"),
    }
}

/// Clickable option rows: (rect, index).
fn option_rows(area: Rect, n: usize, top: i32) -> Vec<Rect> {
    (0..n).map(|i| Rect::new(area.x + 20, top + i as i32 * 40, area.w.saturating_sub(40), 36)).collect()
}

fn inside(r: Rect, x: i32, y: i32) -> bool {
    x >= r.x && y >= r.y && x < r.x + r.w as i32 && y < r.y + r.h as i32
}

impl Settings {
    fn configure_network(&self, dhcp: bool) -> os_std::error::Result<()> {
        use os_std::error::{Error, ErrorKind};
        use os_std::net::{self, Ipv4Addr, NetConfig};
        let bad = |s| Error::new(ErrorKind::InvalidInput, s);
        let iface = Self::net_iface().ok_or(bad("no network adapter"))?;
        let mut config = NetConfig { iface: iface.index as u32, method: net::CONFIG_DHCP as u32, ..Default::default() };
        if !dhcp {
            let (ip, prefix) = self.addr.text().split_once('/').ok_or(bad("use address/prefix"))?;
            config.method = net::CONFIG_STATIC as u32;
            config.addr = Ipv4Addr::parse(ip).ok_or(bad("invalid IPv4 address"))?.0;
            config.prefix = prefix.parse().ok().filter(|&p| p <= 32).ok_or(bad("invalid prefix"))?;
            config.gateway = Ipv4Addr::parse(self.gateway.text()).ok_or(bad("invalid gateway"))?.0;
        }
        net::configure(&config)
    }
    fn content(&self) -> Rect {
        let (w, h) = self.size;
        Rect::new(SIDEBAR as i32 + 16, 16, w.saturating_sub(SIDEBAR + 32), h.saturating_sub(32))
    }

    fn group(p: &mut Painter, r: Rect, title: &str) -> Rect {
        let t = *p.theme;
        p.text(FontKind::Bold, r.x, r.y, title, t.text);
        let card = Rect::new(r.x, r.y + 26, r.w, r.h.saturating_sub(26));
        p.card(card, 10, osyx_gfx::rgb(36, 39, 49), t.border);
        card
    }

    fn row(p: &mut Painter, r: Rect, label: &str, value: &str) {
        let t = *p.theme;
        p.text(FontKind::Ui, r.x + 16, r.y + 10, label, t.text);
        p.text_in(FontKind::Ui, Rect::new(r.x, r.y + 10, r.w.saturating_sub(16), 20), value, t.text_dim, Align::Right);
    }

    fn choices(p: &mut Painter, rows: &[Rect], labels: &[&str], selected: usize) {
        let t = *p.theme;
        for (i, (r, l)) in rows.iter().zip(labels).enumerate() {
            if i == selected {
                p.rounded(*r, 6, t.selection, 255);
            }
            p.ring(r.x + 18, r.y + 18, 7, 2, if i == selected { t.accent } else { t.text_faint }, 255, false);
            if i == selected {
                p.disc(r.x + 18, r.y + 18, 4, t.accent, 255);
            }
            p.text(FontKind::Ui, r.x + 36, r.y + 9, l, t.text);
        }
    }

    fn net_iface() -> Option<osyx_abi::net::NetIface> {
        os_std::net::preferred_ethernet(&os_std::net::interfaces().ok()?)
    }
}

impl App for Settings {
    fn layout(&mut self, w: u32, h: u32, _cx: &mut Ctx) {
        self.size = (w, h);
        let c = self.content();
        self.hostname.rect = Rect::new(c.x + 36, c.y + 112, c.w.saturating_sub(200).min(360), 34);
        self.save_host.rect = Rect::new(self.hostname.rect.x + self.hostname.rect.w as i32 + 12, c.y + 112, 100, 34);
        self.dhcp.rect = Rect::new(c.x + 36, c.y + 210, 150, 34);
        self.static_btn.rect = Rect::new(c.x + 196, c.y + 210, 150, 34);
        self.addr.rect = Rect::new(c.x + 160, c.y + 262, 220, 34);
        self.gateway.rect = Rect::new(c.x + 160, c.y + 306, 220, 34);
        self.apply_net.rect = Rect::new(c.x + 390, c.y + 306, 120, 34);
        self.check_update.rect = Rect::new(c.x + 16, c.y + 419, 180, 34);
        self.install_update.rect = Rect::new(c.x + 206, c.y + 419, 160, 34);
    }

    fn event(&mut self, ev: Ui, cx: &mut Ctx) -> bool {
        let c = self.content();
        if let Ui::PointerDown { x, y, .. } = ev {
            if inside(self.hostname.rect, x, y) {
                self.focus = 0;
            }
            if inside(self.addr.rect, x, y) {
                self.focus = 1;
            }
            if inside(self.gateway.rect, x, y) {
                self.focus = 2;
            }
            if x < SIDEBAR as i32 {
                for (i, (s, _, _)) in SECTIONS.iter().enumerate() {
                    if inside(Rect::new(10, 64 + i as i32 * 40, SIDEBAR - 20, 36), x, y) {
                        self.section = *s;
                        self.status.clear();
                        return true;
                    }
                }
                return false;
            }
            match self.section {
                Section::Appearance => {
                    for (i, accent) in ACCENTS.iter().enumerate() {
                        let r = Rect::new(c.x + 20 + i as i32 * 52, c.y + 80, 40, 40);
                        if inside(r, x, y) {
                            self.accent = i;
                            self.status =
                                write("/etc/osyx/accent", accent.0) + " (applies to applications started from now on)";
                            return true;
                        }
                    }
                    for (i, r) in option_rows(c, WALLPAPERS.len(), c.y + 200).into_iter().enumerate() {
                        if inside(r, x, y) {
                            self.wallpaper = i;
                            self.status = write("/etc/osyx/wallpaper", &format!("{i}"));
                            return true;
                        }
                    }
                }
                Section::Keyboard => {
                    for (i, r) in option_rows(c, LAYOUTS.len(), c.y + 60).into_iter().enumerate() {
                        if inside(r, x, y) {
                            self.layout = i;
                            self.status =
                                write("/etc/osyx/keyboard", LAYOUTS[i].0) + " (takes effect when the session restarts)";
                            return true;
                        }
                    }
                }
                Section::DateTime => {
                    for (i, r) in option_rows(c, ZONES.len(), c.y + 100).into_iter().enumerate() {
                        if inside(r, x, y) {
                            self.zone = i;
                            self.status = write("/etc/TZ", ZONES[i].0);
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        let mut redraw = false;
        match self.section {
            Section::General => {
                let typed = self.hostname.event_with_clipboard(&ev, cx.focused && self.focus == 0, &cx.fonts, &mut cx.clipboard);
                redraw |= typed.needs_redraw();
                let activated = matches!(self.save_host.event(&ev, cx.focused), Response::Activated(_));
                if activated || typed == Response::Submitted {
                    let h = self.hostname.text().trim().to_string();
                    self.status =
                        if h.is_empty() || h.len() > 63 || !h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                            String::from("A host name has 1-63 letters, digits or '-'")
                        } else {
                            write("/etc/hostname", &h)
                        };
                    redraw = true;
                }
            }
            Section::About => {
                let can_ask = fs::metadata("/etc/osyx/installed").is_ok();
                let available = update_state().0 == "available";
                if matches!(self.check_update.event(&ev, cx.focused), Response::Activated(_)) {
                    self.status = if !can_ask {
                        String::from("Updates are only available on an installed system")
                    } else {
                        match fs::write(UPDATE_REQUEST, "check\n") {
                            Ok(()) => String::from("Checking for updates..."),
                            Err(e) => format!("Cannot ask the update service: {e}"),
                        }
                    };
                    redraw = true;
                }
                if available && matches!(self.install_update.event(&ev, cx.focused), Response::Activated(_)) {
                    self.status = match fs::write(UPDATE_REQUEST, "install\n") {
                        Ok(()) => String::from("Installing the update: the status above follows the download"),
                        Err(e) => format!("Cannot ask the update service: {e}"),
                    };
                    redraw = true;
                }
            }
            Section::Network => {
                redraw |= self.addr.event_with_clipboard(&ev, cx.focused && self.focus == 1, &cx.fonts, &mut cx.clipboard).needs_redraw();
                redraw |= self.gateway.event_with_clipboard(&ev, cx.focused && self.focus == 2, &cx.fonts, &mut cx.clipboard).needs_redraw();
                if matches!(self.dhcp.event(&ev, cx.focused), Response::Activated(_)) {
                    self.status = match self.configure_network(true) {
                        Ok(()) => String::from("DHCP requested"),
                        Err(e) => format!("Cannot switch to DHCP: {e}"),
                    };
                    redraw = true;
                }
                let _ = self.static_btn.event(&ev, cx.focused);
                if matches!(self.apply_net.event(&ev, cx.focused), Response::Activated(_)) {
                    self.status = match self.configure_network(false) {
                        Ok(()) => format!("Static address {} applied", self.addr.text()),
                        Err(e) => format!("Cannot apply the static address: {e}"),
                    };
                    redraw = true;
                }
            }
            _ => {}
        }
        redraw
    }

    fn tick_ms(&self) -> Option<u64> {
        Some(2000)
    }

    fn tick(&mut self, _cx: &mut Ctx) -> bool {
        matches!(self.section, Section::Network | Section::Storage | Section::Display | Section::About)
    }

    fn draw(&mut self, p: &mut Painter, w: u32, h: u32, cx: &Ctx) {
        let t = cx.theme;
        p.fill(Rect::new(0, 0, w, h), osyx_gfx::rgb(28, 30, 38));
        // Sidebar.
        p.fill(Rect::new(0, 0, SIDEBAR, h), osyx_gfx::rgb(34, 37, 46));
        p.text(FontKind::Large, 20, 18, "Settings", t.text);
        for (i, (s, label, ic)) in SECTIONS.iter().enumerate() {
            let r = Rect::new(10, 64 + i as i32 * 40, SIDEBAR - 20, 36);
            if *s == self.section {
                p.rounded(r, 7, t.accent, 255);
            }
            p.rounded(
                Rect::new(r.x + 8, r.y + 6, 24, 24),
                6,
                if *s == self.section { osyx_gfx::rgb(255, 255, 255) } else { t.accent },
                if *s == self.section { 60 } else { 255 },
            );
            icon::draw(p, *ic, Rect::new(r.x + 11, r.y + 9, 18, 18), osyx_gfx::rgb(255, 255, 255));
            p.text(FontKind::Ui, r.x + 44, r.y + 9, label, if *s == self.section { t.on_accent } else { t.text });
        }
        let c = self.content();
        let title = SECTIONS.iter().find(|(s, _, _)| *s == self.section).map_or("", |(_, l, _)| *l);
        p.text(FontKind::Large, c.x + 4, c.y, title, t.text);
        match self.section {
            Section::General => {
                let g = Self::group(p, Rect::new(c.x, c.y + 50, c.w, 120), "Host name");
                p.text(FontKind::Ui, g.x + 16, g.y + 12, "The name of this computer on the network", t.text_dim);
                self.hostname.draw(p, cx.focused && self.focus == 0);
                self.save_host.draw(p, cx.focused);
                let si = os::sysinfo().ok();
                let g2 = Self::group(p, Rect::new(c.x, c.y + 190, c.w, 26 + 3 * 40), "This computer");
                Self::row(p, Rect::new(g2.x, g2.y, g2.w, 40), "Host name", &read("/etc/hostname"));
                Self::row(
                    p,
                    Rect::new(g2.x, g2.y + 40, g2.w, 40),
                    "Memory",
                    &si.as_ref().map_or(String::new(), |i| human_size(i.total_memory)),
                );
                Self::row(
                    p,
                    Rect::new(g2.x, g2.y + 80, g2.w, 40),
                    "Up time",
                    &si.as_ref().map_or(String::new(), |i| common::human_duration(i.uptime_ns / 1_000_000_000)),
                );
            }
            Section::Appearance => {
                let g = Self::group(p, Rect::new(c.x, c.y + 40, c.w, 110), "Accent colour");
                for (i, (name, col)) in ACCENTS.iter().enumerate() {
                    let r = Rect::new(g.x + 20 + i as i32 * 52, g.y + 14, 40, 40);
                    if i == self.accent {
                        p.ring(r.x + 20, r.y + 20, 20, 2, osyx_gfx::rgb(255, 255, 255), 255, false);
                    }
                    p.disc(r.x + 20, r.y + 20, 15, *col, 255);
                    if i == self.accent {
                        p.text_in(FontKind::Ui, Rect::new(g.x, g.y + 58, g.w, 20), name, t.text_dim, Align::Center);
                    }
                }
                let rows = option_rows(c, WALLPAPERS.len(), c.y + 200);
                let _ = Self::group(
                    p,
                    Rect::new(c.x, c.y + 166, c.w, 34 + WALLPAPERS.len() as u32 * 40 + 8),
                    "Desktop background",
                );
                Self::choices(p, &rows, &WALLPAPERS, self.wallpaper);
            }
            Section::Display => {
                let d = system::display_info().ok();
                let g = Self::group(p, Rect::new(c.x, c.y + 40, c.w, 26 + 5 * 40), "Built-in display");
                let rows = [
                    ("Resolution", d.map_or(String::from("none"), |d| format!("{} x {}", d.width, d.height))),
                    (
                        "Preferred mode",
                        d.filter(|d| d.native_width > 0)
                            .map_or(String::from("unknown"), |d| format!("{} x {}", d.native_width, d.native_height)),
                    ),
                    (
                        "Output",
                        d.map_or(String::new(), |d| {
                            String::from(if d.backend == system::BACKEND_VIRTIO_GPU {
                                "VirtIO-GPU 2D scanout"
                            } else {
                                "UEFI GOP framebuffer"
                            })
                        }),
                    ),
                    (
                        "Colour format",
                        d.map_or(String::new(), |d| {
                            String::from(if d.format == system::pixel::RGBX { "32-bit RGBX" } else { "32-bit BGRX" })
                        }),
                    ),
                    (
                        "Compositor",
                        d.filter(|d| d.owner != 0)
                            .map_or(String::from("kernel console"), |d| format!("PRISM (process {})", d.owner)),
                    ),
                ];
                for (i, (k, v)) in rows.iter().enumerate() {
                    Self::row(p, Rect::new(g.x, g.y + i as i32 * 40, g.w, 40), k, v);
                }
                p.text(
                    FontKind::Ui,
                    c.x + 4,
                    g.y + g.h as i32 + 16,
                    "Resolution changes need the compositor to restart; boot with display.mode=WIDTHxHEIGHT.",
                    t.text_faint,
                );
            }
            Section::Keyboard => {
                let rows = option_rows(c, LAYOUTS.len(), c.y + 60);
                let _ =
                    Self::group(p, Rect::new(c.x, c.y + 26, c.w, 34 + LAYOUTS.len() as u32 * 40 + 8), "Input source");
                let labels: Vec<&str> = LAYOUTS.iter().map(|(_, l)| *l).collect();
                Self::choices(p, &rows, &labels, self.layout);
            }
            Section::DateTime => {
                let now = common::system_tz().local(common::unix_now());
                p.text(FontKind::Display, c.x + 4, c.y + 34, &format!("{:02}:{:02}", now.hour, now.minute), t.text);
                let rows = option_rows(c, ZONES.len(), c.y + 100);
                let _ = Self::group(p, Rect::new(c.x, c.y + 66, c.w, 34 + ZONES.len() as u32 * 40 + 8), "Time zone");
                let labels: Vec<&str> = ZONES.iter().map(|(_, l)| *l).collect();
                Self::choices(p, &rows, &labels, self.zone);
            }
            Section::Network => {
                let i = Self::net_iface();
                let g = Self::group(p, Rect::new(c.x, c.y + 40, c.w, 26 + 3 * 40), "Ethernet");
                let name =
                    i.as_ref().map_or(String::from("no network adapter"), |i| String::from(system::field_str(&i.name)));
                let ip = i.as_ref().map_or(String::from("-"), |i| {
                    format!("{}.{}.{}.{}/{}", i.addr[0], i.addr[1], i.addr[2], i.addr[3], i.prefix)
                });
                let method = i.as_ref().map_or("", |i| match i.method {
                    osyx_abi::net::CONFIG_DHCP => "DHCP",
                    osyx_abi::net::CONFIG_STATIC => "Static",
                    _ => "Not configured",
                });
                Self::row(p, Rect::new(g.x, g.y, g.w, 40), "Adapter", &name);
                Self::row(p, Rect::new(g.x, g.y + 40, g.w, 40), "IPv4 address", &ip);
                Self::row(p, Rect::new(g.x, g.y + 80, g.w, 40), "Configured by", method);
                p.text(FontKind::Bold, c.x, c.y + 186, "Configure IPv4", t.text);
                self.dhcp.draw(p, cx.focused);
                self.static_btn.draw(p, cx.focused);
                p.text(FontKind::Ui, c.x + 36, c.y + 270, "Address/prefix", t.text_dim);
                p.text(FontKind::Ui, c.x + 36, c.y + 314, "Gateway", t.text_dim);
                self.addr.draw(p, cx.focused && self.focus == 1);
                self.gateway.draw(p, cx.focused && self.focus == 2);
                self.apply_net.draw(p, cx.focused);
            }
            Section::Storage => {
                let mounts = system::mounts().unwrap_or_default();
                let g = Self::group(p, Rect::new(c.x, c.y + 40, c.w, 26 + mounts.len() as u32 * 56), "Volumes");
                for (k, m) in mounts.iter().enumerate() {
                    let path = system::field_str(&m.path);
                    let (total, free) = os::statfs(path)
                        .map_or((0, 0), |s| (s.total_blocks * s.block_size, s.free_blocks * s.block_size));
                    let y = g.y + 8 + k as i32 * 56;
                    p.text(
                        FontKind::Ui,
                        g.x + 16,
                        y,
                        &format!("{path}  ·  {}  ·  {}", system::field_str(&m.fstype), system::field_str(&m.source)),
                        t.text,
                    );
                    let v = if total > 0 {
                        format!("{} free of {}", human_size(free), human_size(total))
                    } else {
                        String::from("virtual")
                    };
                    p.text_in(
                        FontKind::Ui,
                        Rect::new(g.x, y, g.w.saturating_sub(16), 20),
                        &v,
                        t.text_dim,
                        Align::Right,
                    );
                    let bar = Rect::new(g.x + 16, y + 26, g.w.saturating_sub(32), 8);
                    p.rounded(bar, 4, t.field, 255);
                    if let Some(used) = total.saturating_sub(free).saturating_mul(bar.w as u64).checked_div(total) {
                        let used = used as u32;
                        if used > 0 {
                            p.rounded(Rect::new(bar.x, bar.y, used.max(8), 8), 4, t.accent, 255);
                        }
                    }
                }
            }
            Section::About => {
                let si = os::sysinfo().ok();
                p.text(FontKind::Display, c.x + 4, c.y + 40, "OSyx", t.text);
                let g = Self::group(p, Rect::new(c.x, c.y + 110, c.w, 26 + 5 * 40), "Software");
                let rows = [
                    ("Version", read("/etc/osyx-release")),
                    ("Kernel", si.as_ref().map_or(String::new(), |i| String::from(os::kernel_version(i)))),
                    ("System call ABI", si.as_ref().map_or(String::new(), |i| format!("{}", i.abi_version))),
                    ("Compositor", String::from("PRISM")),
                    (
                        "Windows programs",
                        String::from(if fs::metadata("/bin/winrun").is_ok() {
                            "winrun (PE32+, Win32 subset)"
                        } else {
                            "not installed"
                        }),
                    ),
                ];
                for (i, (k, v)) in rows.iter().enumerate() {
                    Self::row(p, Rect::new(g.x, g.y + i as i32 * 40, g.w, 40), k, v);
                }
                let u = Self::group(p, Rect::new(c.x, c.y + 350, c.w, 26 + 2 * 40), "System update");
                Self::row(p, Rect::new(u.x, u.y, u.w, 40), "Status", &update_text());
                self.check_update.draw(p, cx.focused);
                if update_state().0 == "available" {
                    self.install_update.draw(p, cx.focused);
                }
            }
        }
        if !self.status.is_empty() {
            p.text_in(
                FontKind::Ui,
                Rect::new(c.x, c.y + c.h as i32 - 22, c.w, 20),
                &self.status,
                t.text_dim,
                Align::Left,
            );
        }
    }
}

fn main() -> i32 {
    let accent = read("/etc/osyx/accent");
    let wallpaper: usize = read("/etc/osyx/wallpaper").parse().unwrap_or(0);
    let layout = read("/etc/osyx/keyboard");
    let zone = read("/etc/TZ");
    let host = read("/etc/hostname");
    let mut hostname = TextField::new("");
    hostname.set_text(&host);
    let mut app = Settings {
        section: Section::General,
        size: (0, 0),
        accent: ACCENTS.iter().position(|(n, _)| n.eq_ignore_ascii_case(&accent)).unwrap_or(0),
        wallpaper: wallpaper.min(WALLPAPERS.len() - 1),
        layout: LAYOUTS.iter().position(|(k, _)| *k == layout).unwrap_or(0),
        zone: ZONES.iter().position(|(k, _)| *k == zone).unwrap_or(0),
        hostname,
        save_host: Button::new(1, "Save", ButtonStyle::Primary),
        dhcp: Button::new(2, "Use DHCP", ButtonStyle::Secondary),
        static_btn: Button::new(3, "Static address:", ButtonStyle::Flat),
        addr: TextField::new(
            &Settings::net_iface().map_or(String::new(), |i| format!("{}/{}", os_std::net::Ipv4Addr(i.addr), i.prefix)),
        ),
        gateway: TextField::new(
            &Settings::net_iface().map_or(String::from("0.0.0.0"), |i| format!("{}", os_std::net::Ipv4Addr(i.gateway))),
        ),
        apply_net: Button::new(4, "Apply", ButtonStyle::Primary),
        check_update: Button::new(5, "Check for updates", ButtonStyle::Secondary),
        install_update: Button::new(6, "Install update", ButtonStyle::Primary),
        status: String::new(),
        focus: 0,
    };
    println!("settings: started");
    let mut spec = WindowSpec::normal("Settings", 960, 640);
    spec.min_width = 760;
    spec.min_height = 520;
    run_app("settings", spec, &mut app)
}
