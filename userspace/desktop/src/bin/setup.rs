//! OSyx Setup (`/system/bin/setup`): the graphical installer of the live
//! system. A step list on the left (Welcome, Disk, Account, Options,
//! Summary, Install, Finish) and one page per step, in the style of
//! Calamares. The work is done by `osyx-install` on the raw disk node
//! (`/dev/disks/<name>`). The disk the running system uses (`/` or
//! `/boot`, i.e. the live medium) is shown as unavailable; other disks
//! whose volumes are merely mounted (below `/mnt`) can be chosen, and
//! Setup unmounts those volumes before it writes.
//!
//! Nothing is written before the user confirms, in a separate dialog, that
//! the named disk will be erased. `--auto` runs the same pages without
//! input (QEMU tests); it requires `--confirm-erase <disk>` naming the
//! same disk as `--disk`.
//!
//! The installer runs as root (it opens raw disks). Its log goes to
//! `/tmp/osyx-install.log` here and to `/var/log/osyx-install.log` on the
//! installed system.

#![no_std]
#![no_main]

#[path = "../shell_common.rs"]
mod common;

use common::{human_size, run_app, App, Ctx};
use os_std::io::{Read, Seek, SeekFrom, Write};
use os_std::prelude::*;
use os_std::{env, fs, os, system};
use osyx_gfx::{Color, Rect};
use osyx_install::{Config, Disk, Kind, Layout, Plan, Progress, Source, SourceEntry, Stage};
use osyx_ui::widget::{Button, ButtonStyle, Checkbox, Dialog, TextField};
use osyx_ui::{icon, Align, Event as Ui, FontKind, Icon, Painter, Response};
use prism_client::WindowSpec;

os_std::entry!(main);

const SIDEBAR: u32 = 230;
const PAYLOAD: &str = "/system/share/osyx-setup";
const LOG: &str = "/tmp/osyx-install.log";
/// The live system's "Install OSyx" entries (not part of the installed system).
const LIVE_ENTRIES: [&str; 2] = ["/home/user/Desktop/05-setup.app", "/system/share/applications/05-setup.app"];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Step {
    Welcome,
    Disk,
    Account,
    Options,
    Summary,
    Install,
    Finish,
}

const STEPS: [(Step, &str); 7] = [
    (Step::Welcome, "Welcome"),
    (Step::Disk, "Disk"),
    (Step::Account, "Account"),
    (Step::Options, "Options"),
    (Step::Summary, "Summary"),
    (Step::Install, "Install"),
    (Step::Finish, "Finish"),
];

// ---- disks -------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct DiskInfo {
    name: String,
    bytes: u64,
    partitions: usize,
    /// Why it cannot be used, if it cannot.
    blocked: Option<String>,
    /// Mount points of its volumes, unmounted before installing.
    mounted: Vec<String>,
}

fn c_str(b: &[u8]) -> &str {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    core::str::from_utf8(&b[..n]).unwrap_or("")
}

/// Mount points of the volumes on `disk` (the disk itself or one of its
/// partitions), innermost first.
fn mounts_of(disk: &str) -> Vec<String> {
    let prefix = format!("/dev/disks/{disk}");
    let mut v: Vec<String> = system::mounts()
        .unwrap_or_default()
        .iter()
        .filter(|m| {
            let src = c_str(&m.source);
            src == prefix || src.strip_prefix(prefix.as_str()).is_some_and(|r| {
                let r = r.trim_start_matches('p');
                !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit())
            })
        })
        .map(|m| String::from(c_str(&m.path)))
        .collect();
    v.sort_by_key(|p| core::cmp::Reverse(p.len()));
    v
}

/// Unmounts every volume of `disk` so its raw node can be opened for writing.
fn release_disk(disk: &str) -> Result<(), String> {
    for at in mounts_of(disk) {
        if at == "/" || at == "/boot" {
            return Err(format!("{disk} holds the running system ({at})"));
        }
        os::unmount(&at).map_err(|e| format!("cannot unmount {at}: {e} (close programs that use it)"))?;
        println!("setup: unmounted {at} from {disk}");
    }
    Ok(())
}

/// Whole disks below `/dev/disks` (partition nodes are named after their
/// disk plus a number, optionally after a `p`).
fn scan_disks() -> Vec<DiskInfo> {
    let mut names: Vec<String> = match fs::read_dir("/dev/disks") {
        Ok(d) => d.map(|e| String::from(e.file_name())).collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    let is_part_of = |p: &str, d: &str| {
        p.len() > d.len() && p.starts_with(d) && {
            let rest = p[d.len()..].trim_start_matches('p');
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
        }
    };
    let mut disks = Vec::new();
    for n in &names {
        if names.iter().any(|d| is_part_of(n, d)) {
            continue;
        }
        let path = format!("/dev/disks/{n}");
        let bytes = fs::metadata(&path).map_or(0, |m| m.len());
        let partitions = names.iter().filter(|p| is_part_of(p, n)).count();
        let mut mounted = Vec::new();
        let blocked = if bytes < osyx_install::MIN_DISK_MIB << 20 {
            Some(format!("too small (OSyx needs {} MiB)", osyx_install::MIN_DISK_MIB))
        } else {
            match fs::OpenOptions::new().read(true).write(true).open(&path) {
                Ok(_) => None,
                Err(e) if e.kind() == os_std::error::ErrorKind::ResourceBusy => {
                    mounted = mounts_of(n);
                    if mounted.iter().any(|m| m == "/" || m == "/boot") {
                        Some(String::from("OSyx is running from this disk"))
                    } else if mounted.is_empty() {
                        Some(String::from("in use by the running system"))
                    } else {
                        None
                    }
                }
                Err(e) => Some(format!("cannot be opened: {e}")),
            }
        };
        disks.push(DiskInfo { name: n.clone(), bytes, partitions, blocked, mounted });
    }
    disks
}

/// A raw disk node.
struct RawDisk {
    file: fs::File,
    sectors: u64,
}

impl RawDisk {
    fn open(name: &str) -> Result<RawDisk, String> {
        let path = format!("/dev/disks/{name}");
        let file = fs::OpenOptions::new().read(true).write(true).open(&path).map_err(|e| format!("{path}: {e}"))?;
        let sectors = file.metadata().map_err(|e| format!("{path}: {e}"))?.len() / osyx_install::SECTOR;
        Ok(RawDisk { file, sectors })
    }
}

impl Disk for RawDisk {
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), String> {
        self.file.seek(SeekFrom::Start(lba * osyx_install::SECTOR)).map_err(|e| format!("seek: {e}"))?;
        self.file.read_exact(buf).map_err(|e| format!("read at sector {lba}: {e}"))
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), String> {
        self.file.seek(SeekFrom::Start(lba * osyx_install::SECTOR)).map_err(|e| format!("seek: {e}"))?;
        self.file.write_all(buf).map_err(|e| format!("write at sector {lba}: {e}"))
    }
    fn flush(&mut self) -> Result<(), String> {
        self.file.sync_all().map_err(|e| format!("flush: {e}"))
    }
}

// ---- the running system as the source -------------------------------------------

struct LiveSource;

fn collect_files(dir: &str, rel: &str, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), String> {
    for e in fs::read_dir(dir).map_err(|e| format!("{dir}: {e}"))? {
        let name = String::from(e.file_name());
        let path = format!("{dir}/{name}");
        let r = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let m = fs::symlink_metadata(&path).map_err(|e| format!("{path}: {e}"))?;
        if m.is_dir() {
            collect_files(&path, &r, out)?;
        } else if m.is_file() {
            out.push((r, fs::read(&path).map_err(|e| format!("{path}: {e}"))?));
        }
    }
    Ok(())
}

impl Source for LiveSource {
    fn list(&mut self, path: &str) -> Result<Vec<SourceEntry>, String> {
        let mut out = Vec::new();
        for e in fs::read_dir(path).map_err(|e| format!("{path}: {e}"))? {
            let name = String::from(e.file_name());
            let full = if path == "/" { format!("/{name}") } else { format!("{path}/{name}") };
            let m = fs::symlink_metadata(&full).map_err(|e| format!("{full}: {e}"))?;
            let kind = if m.is_symlink() {
                Kind::Symlink(String::from(fs::read_link(&full).map_err(|e| format!("{full}: {e}"))?.as_str()))
            } else if m.is_dir() {
                Kind::Dir
            } else if m.is_file() {
                Kind::File
            } else {
                continue; // devices, pipes: never part of the installed tree
            };
            let mode = (m.permissions().mode() & 0o7777) as u16;
            out.push(SourceEntry { name, kind, mode, uid: m.uid(), gid: m.gid(), size: m.len() });
        }
        Ok(out)
    }

    fn read(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize, String> {
        let mut f = fs::File::open(path).map_err(|e| format!("{e}"))?;
        f.seek(SeekFrom::Start(offset)).map_err(|e| format!("{e}"))?;
        let mut done = 0;
        while done < buf.len() {
            let n = f.read(&mut buf[done..]).map_err(|e| format!("{e}"))?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    fn boot_files(&mut self) -> Result<Vec<(String, Vec<u8>)>, String> {
        let mut files = Vec::new();
        collect_files(&format!("{PAYLOAD}/esp"), "", &mut files)?;
        // The live command line ("live ...") must not reach the new system.
        files.retain(|(p, _)| !p.eq_ignore_ascii_case("EFI/OSYX/CMDLINE.TXT"));
        Ok(files)
    }
}

// ---- the installation job ------------------------------------------------------------

#[derive(Default)]
struct JobState {
    stage: Option<Stage>,
    fraction: f32,
    lines: Vec<String>,
    result: Option<Result<String, String>>,
}

struct Reporter {
    state: Arc<Mutex<JobState>>,
    file: Option<fs::File>,
}

impl Progress for Reporter {
    fn stage(&mut self, stage: Stage, fraction: f32) {
        let mut s = self.state.lock().unwrap();
        if s.stage != Some(stage) {
            println!("setup: {} ({:.0}%)", stage.describe(), fraction * 100.0);
        }
        s.stage = Some(stage);
        s.fraction = fraction;
    }
    fn log(&mut self, line: &str) {
        println!("setup: {line}");
        if let Some(f) = &mut self.file {
            let _ = f.write_all(format!("{line}\n").as_bytes());
        }
        self.state.lock().unwrap().lines.push(String::from(line));
    }
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    if let Ok(mut f) = fs::File::open("/dev/random") {
        if f.read_exact(&mut seed).is_ok() {
            return seed;
        }
    }
    // No entropy device: condense the clock and process state.
    let mut h = osyx_crypto::Sha256::new();
    h.update(&common::unix_now().to_le_bytes());
    h.update(&os_std::time::Instant::now().as_nanos_since_boot().to_le_bytes());
    h.finish()
}

fn start_job(disk: String, plan: Plan, config: Config) -> Arc<Mutex<JobState>> {
    let state = Arc::new(Mutex::new(JobState::default()));
    let shared = state.clone();
    os_std::thread::spawn(move || {
        let file = fs::File::create(LOG).ok();
        let mut rep = Reporter { state: shared.clone(), file };
        rep.log(&format!("OSyx Setup: installing on /dev/disks/{disk} for host {}", config.hostname));
        let result = release_disk(&disk)
            .and_then(|_| RawDisk::open(&disk))
            .map_err(osyx_install::Error::Io)
            .and_then(|mut d| osyx_install::install(&mut d, &plan, &mut LiveSource, &config, &mut rep));
        let outcome = match result {
            Ok(r) => {
                let msg = format!("{} files ({}) copied to {disk}", r.files, human_size(r.bytes));
                println!("SETUP_RESULT ok {msg}");
                Ok(msg)
            }
            Err(e) => {
                let msg = format!("{e}");
                rep.log(&format!("installation failed: {msg}"));
                println!("SETUP_RESULT failed {msg}");
                Err(msg)
            }
        };
        shared.lock().unwrap().result = Some(outcome);
    });
    state
}

// ---- the window ------------------------------------------------------------------------

struct Setup {
    step: Step,
    size: (u32, u32),
    disks: Vec<DiskInfo>,
    disk: Option<usize>,
    manual: bool,
    esp_mib: TextField,
    root_mib: TextField,
    full_name: TextField,
    user_name: TextField,
    password: TextField,
    password2: TextField,
    hostname: TextField,
    zen: Checkbox,
    back: Button,
    next: Button,
    rescan: Button,
    reboot: Button,
    focus: usize,
    message: String,
    dialog: Option<Dialog>,
    job: Option<Arc<Mutex<JobState>>>,
    auto: Option<AutoPlan>,
}

/// `--auto` settings.
struct AutoPlan {
    reboot: bool,
    reboot_at: Option<os_std::time::Instant>,
}

fn inside(r: Rect, x: i32, y: i32) -> bool {
    x >= r.x && y >= r.y && x < r.x + r.w as i32 && y < r.y + r.h as i32
}

impl Setup {
    fn content(&self) -> Rect {
        let (w, h) = self.size;
        Rect::new(SIDEBAR as i32 + 28, 24, w.saturating_sub(SIDEBAR + 56), h.saturating_sub(24 + 72))
    }

    fn layout_choice(&self) -> Result<Layout, String> {
        if !self.manual {
            return Ok(Layout::Automatic);
        }
        let esp = self.esp_mib.text().trim().parse::<u64>().map_err(|_| String::from("Enter the EFI partition size in MiB."))?;
        let root = self.root_mib.text().trim().parse::<u64>().map_err(|_| String::from("Enter the OSyx partition size in MiB (0 = rest of the disk)."))?;
        Ok(Layout::Manual { esp_mib: esp, root_mib: root })
    }

    fn plan(&self) -> Result<Plan, String> {
        let d = self.disk.and_then(|i| self.disks.get(i)).ok_or_else(|| String::from("Choose the disk to install OSyx on."))?;
        if let Some(why) = &d.blocked {
            return Err(format!("{} cannot be used: {why}.", d.name));
        }
        osyx_install::plan(d.bytes / osyx_install::SECTOR, self.layout_choice()?).map_err(|e| format!("{e}"))
    }

    fn config(&self) -> Config {
        let pw = self.password.text();
        Config {
            hostname: String::from(self.hostname.text().trim()),
            user_name: String::from(self.user_name.text().trim()),
            full_name: String::from(self.full_name.text().trim()),
            password: if pw.is_empty() { None } else { Some(String::from(pw)) },
            install_zen: self.zen.checked,
            seed: random_seed(),
            time: common::unix_now(),
            skip: [PAYLOAD].iter().chain(LIVE_ENTRIES.iter()).map(|s| String::from(*s)).collect(),
            cmdline: String::new(),
        }
    }

    /// Checks the current page before moving on; returns a message.
    fn check_page(&self) -> Result<(), String> {
        /// A network interface with an IPv4 address (a DHCP lease implies a
        /// working link; Wi-Fi does not always report its link flag).
        fn online() -> bool {
            os_std::net::interfaces()
                .is_ok_and(|v| v.iter().any(|i| i.flags & os_std::net::IFF_LOOPBACK == 0 && i.addr != [0; 4]))
        }
        match self.step {
            // The installed system downloads its applications (Zen Browser)
            // on its first start. Unattended runs (QEMU tests) are offline.
            Step::Welcome if self.auto.is_none() && !online() => Err(String::from(
                "Connect to the Internet first (Wi-Fi or a cable): the installed system downloads its applications.",
            )),
            Step::Disk => self.plan().map(|_| ()),
            Step::Account => {
                if self.password.text() != self.password2.text() {
                    return Err(String::from("The passwords do not match."));
                }
                osyx_install::validate(&self.config())
            }
            _ => Ok(()),
        }
    }

    fn go_next(&mut self) {
        if let Err(m) = self.check_page() {
            self.message = m;
            return;
        }
        self.message.clear();
        self.step = match self.step {
            Step::Welcome => Step::Disk,
            Step::Disk => Step::Account,
            Step::Account => Step::Options,
            Step::Options => Step::Summary,
            Step::Summary => {
                self.confirm();
                Step::Summary
            }
            s => s,
        };
        self.focus = 0;
    }

    fn confirm(&mut self) {
        let Some(d) = self.disk.and_then(|i| self.disks.get(i)) else { return };
        let text = format!(
            "Everything on {} ({}, {} partition(s)) will be erased and replaced by OSyx. This cannot be undone.",
            d.name,
            human_size(d.bytes),
            d.partitions
        );
        self.dialog = Some(Dialog::new(
            1,
            "Erase this disk?",
            &text,
            &[("Cancel", ButtonStyle::Secondary), (&format!("Erase {} and install", d.name), ButtonStyle::Danger)],
        ));
    }

    fn begin(&mut self) {
        let Ok(plan) = self.plan() else { return };
        let disk = self.disks[self.disk.unwrap_or(0)].name.clone();
        println!("setup: user confirmed erasing {disk}; plan {plan:?}");
        self.job = Some(start_job(disk, plan, self.config()));
        self.step = Step::Install;
    }

    fn page_title(&self) -> &'static str {
        match self.step {
            Step::Welcome => "Welcome to OSyx",
            Step::Disk => "Where should OSyx be installed?",
            Step::Account => "Who will use this computer?",
            Step::Options => "Additional software",
            Step::Summary => "Ready to install",
            Step::Install => "Installing OSyx",
            Step::Finish => "Finished",
        }
    }

    fn fields(&mut self) -> Vec<&mut TextField> {
        match self.step {
            Step::Disk if self.manual => vec![&mut self.esp_mib, &mut self.root_mib],
            Step::Account => vec![&mut self.full_name, &mut self.user_name, &mut self.password, &mut self.password2, &mut self.hostname],
            _ => Vec::new(),
        }
    }

    fn disk_rows(&self) -> Vec<Rect> {
        let c = self.content();
        (0..self.disks.len()).map(|i| Rect::new(c.x, c.y + 70 + i as i32 * 52, c.w, 46)).collect()
    }

    fn mode_rows(&self) -> [Rect; 2] {
        let c = self.content();
        let y = c.y + 90 + self.disks.len().max(1) as i32 * 52;
        [Rect::new(c.x, y, c.w, 36), Rect::new(c.x, y + 40, c.w, 36)]
    }
}

impl App for Setup {
    fn layout(&mut self, w: u32, h: u32, _cx: &mut Ctx) {
        self.size = (w, h);
        let c = self.content();
        let by = h as i32 - 56;
        self.next.rect = Rect::new(w as i32 - 28 - 160, by, 160, 36);
        self.back.rect = Rect::new(w as i32 - 28 - 160 - 12 - 110, by, 110, 36);
        self.rescan.rect = Rect::new(c.x + c.w as i32 - 130, c.y + 26, 130, 32);
        self.reboot.rect = Rect::new(c.x, c.y + 150, 180, 38);
        let [_, manual] = self.mode_rows();
        self.esp_mib.rect = Rect::new(c.x + 150, manual.y + 44, 110, 32);
        self.root_mib.rect = Rect::new(c.x + 430, manual.y + 44, 110, 32);
        let fw = c.w.min(420);
        for (i, f) in [&mut self.full_name, &mut self.user_name, &mut self.password, &mut self.password2, &mut self.hostname].into_iter().enumerate() {
            f.rect = Rect::new(c.x + 200, c.y + 70 + i as i32 * 52, fw, 34);
        }
        self.zen.rect = Rect::new(c.x, c.y + 70, c.w, 30);
        if let Some(d) = &mut self.dialog {
            d.layout(Rect::new(0, 0, w, h), &_cx.fonts);
        }
    }

    fn event(&mut self, ev: Ui, cx: &mut Ctx) -> bool {
        if let Some(d) = &mut self.dialog {
            match d.event_with_clipboard(&ev, &cx.fonts, &mut cx.clipboard) {
                Response::Activated(1) => {
                    self.dialog = None;
                    self.begin();
                    return true;
                }
                Response::Activated(_) | Response::Cancelled => {
                    self.dialog = None;
                    println!("setup: erase cancelled by the user");
                    return true;
                }
                r => return r.needs_redraw(),
            }
        }
        let mut redraw = false;
        if let Ui::PointerDown { x, y, .. } = ev {
            match self.step {
                Step::Disk => {
                    for (i, r) in self.disk_rows().into_iter().enumerate() {
                        if inside(r, x, y) {
                            self.disk = Some(i);
                            self.message.clear();
                            redraw = true;
                        }
                    }
                    let [auto, manual] = self.mode_rows();
                    if inside(auto, x, y) {
                        self.manual = false;
                        redraw = true;
                    }
                    if inside(manual, x, y) {
                        self.manual = true;
                        redraw = true;
                    }
                }
                Step::Welcome | Step::Options | Step::Summary | Step::Install | Step::Finish => {}
                Step::Account => {}
            }
            let mut hit = None;
            for (i, f) in self.fields().into_iter().enumerate() {
                if inside(f.rect, x, y) {
                    hit = Some(i);
                }
            }
            if let Some(i) = hit {
                self.focus = i;
                redraw = true;
            }
        }
        if let Ui::Key(k) = &ev {
            if k.down && k.key == osyx_input::key::TAB {
                let n = self.fields().len().max(1);
                self.focus = if k.shift() { (self.focus + n - 1) % n } else { (self.focus + 1) % n };
                return true;
            }
        }
        let focus = self.focus;
        let focused = cx.focused;
        for (i, f) in self.fields().into_iter().enumerate() {
            match f.event_with_clipboard(&ev, focused && i == focus, &cx.fonts, &mut cx.clipboard) {
                Response::Submitted => {}
                r => redraw |= r.needs_redraw(),
            }
        }
        if self.step == Step::Options {
            redraw |= self.zen.event(&ev, focused).needs_redraw();
        }
        if self.step == Step::Disk && self.rescan.event(&ev, focused) == Response::Activated(self.rescan.id) {
            self.disks = scan_disks();
            self.disk = None;
            redraw = true;
        }
        let navigating = self.step < Step::Install;
        if navigating && self.step > Step::Welcome && self.back.event(&ev, focused) == Response::Activated(self.back.id) {
            self.message.clear();
            self.step = match self.step {
                Step::Disk => Step::Welcome,
                Step::Account => Step::Disk,
                Step::Options => Step::Account,
                Step::Summary => Step::Options,
                s => s,
            };
            self.focus = 0;
            redraw = true;
        }
        if navigating && self.next.event(&ev, focused) == Response::Activated(self.next.id) {
            self.go_next();
            redraw = true;
        }
        if self.step == Step::Finish && self.reboot.event(&ev, focused) == Response::Activated(self.reboot.id) {
            let done = self.job.as_ref().is_some_and(|j| matches!(j.lock().unwrap().result, Some(Ok(_))));
            if done {
                println!("setup: restarting into the installed system");
                let e = system::reboot();
                self.message = format!("Cannot restart: {e}");
            } else {
                // After a failure the button offers another attempt.
                self.job = None;
                self.step = Step::Summary;
            }
            redraw = true;
        }
        if self.dialog.is_some() {
            let (w, h) = self.size;
            if let Some(d) = &mut self.dialog {
                d.layout(Rect::new(0, 0, w, h), &cx.fonts);
            }
        }
        redraw
    }

    fn tick_ms(&self) -> Option<u64> {
        Some(if self.job.is_some() || self.auto.is_some() { 200 } else { 1000 })
    }

    fn tick(&mut self, _cx: &mut Ctx) -> bool {
        if self.step == Step::Install {
            let finished = self.job.as_ref().is_some_and(|j| j.lock().unwrap().result.is_some());
            if finished {
                self.step = Step::Finish;
                if let Some(a) = &mut self.auto {
                    if a.reboot && self.job.as_ref().is_some_and(|j| matches!(j.lock().unwrap().result, Some(Ok(_)))) {
                        a.reboot_at = Some(os_std::time::Instant::now());
                    }
                }
            }
            return true;
        }
        if let Some(at) = self.auto.as_ref().and_then(|a| a.reboot_at) {
            if at.elapsed().as_millis() >= 3000 {
                println!("setup: automatic restart into the installed system");
                let e = system::reboot();
                eprintln!("setup: cannot restart: {e}");
                self.auto = None;
            }
        }
        self.step == Step::Finish
    }

    fn draw(&mut self, p: &mut Painter, w: u32, h: u32, cx: &Ctx) {
        let t = cx.theme;
        p.fill(Rect::new(0, 0, w, h), osyx_gfx::rgb(28, 30, 38));
        // Steps.
        p.vertical_gradient(Rect::new(0, 0, SIDEBAR, h), osyx_gfx::rgb(22, 40, 84), osyx_gfx::rgb(14, 20, 40));
        p.text(FontKind::Large, 24, 22, "OSyx Setup", osyx_gfx::rgb(255, 255, 255));
        for (i, (s, label)) in STEPS.iter().enumerate() {
            let r = Rect::new(14, 76 + i as i32 * 44, SIDEBAR - 28, 36);
            let current = *s == self.step;
            let done = *s < self.step;
            if current {
                p.rounded(r, 8, osyx_gfx::rgb(255, 255, 255), 36);
            }
            let dot: Color = if current || done { t.accent } else { osyx_gfx::rgb(90, 100, 130) };
            p.disc(r.x + 18, r.y + 18, 9, dot, 255);
            if done {
                // A check mark (as the toolkit's check box draws it).
                let pt = |fx: i32, fy: i32| (((r.x + 9) << 8) + 18 * fx * 256 / 100, ((r.y + 9) << 8) + 18 * fy * 256 / 100);
                p.segment(pt(26, 52), pt(44, 70), 520, osyx_gfx::rgb(255, 255, 255), 255);
                p.segment(pt(44, 70), pt(76, 32), 520, osyx_gfx::rgb(255, 255, 255), 255);
            } else {
                p.text_in(FontKind::Ui, Rect::new(r.x + 9, r.y + 9, 18, 18), &format!("{}", i + 1), osyx_gfx::rgb(255, 255, 255), Align::Center);
            }
            p.text(if current { FontKind::Bold } else { FontKind::Ui }, r.x + 40, r.y + 9, label, if current || done { osyx_gfx::rgb(255, 255, 255) } else { osyx_gfx::rgb(170, 180, 205) });
        }
        let c = self.content();
        p.text(FontKind::Large, c.x, c.y, self.page_title(), t.text);
        let focused = cx.focused;
        match self.step {
            Step::Welcome => {
                let lines = [
                    "This assistant installs OSyx on a disk of this computer.",
                    "",
                    "You will choose the disk and how to divide it, create your user",
                    "account and name the computer. Nothing is written to any disk",
                    "until you confirm the summary.",
                    "",
                    "Installed system: UEFI boot loader on a FAT32 EFI system partition,",
                    "OSyx on a journalled ext4 partition, the PRISM desktop and the",
                    "Windows program runtime.",
                ];
                for (i, l) in lines.iter().enumerate() {
                    p.text(FontKind::Ui, c.x, c.y + 60 + i as i32 * 24, l, t.text_dim);
                }
                let si = os::sysinfo().ok();
                let mem = si.map_or(String::new(), |i| human_size(i.total_memory));
                let usable = self.disks.iter().filter(|d| d.blocked.is_none()).count();
                p.text(FontKind::Bold, c.x, c.y + 300, &format!("Memory: {mem}    Disks: {} found, {usable} usable", self.disks.len()), t.text);
            }
            Step::Disk => {
                p.text(FontKind::Ui, c.x, c.y + 36, "Select a disk. The disk OSyx is running from cannot be chosen.", t.text_dim);
                self.rescan.draw(p, focused);
                if self.disks.is_empty() {
                    p.text(FontKind::Ui, c.x, c.y + 80, "No disks found.", t.text);
                }
                for (i, (d, r)) in self.disks.iter().zip(self.disk_rows()).enumerate() {
                    let sel = self.disk == Some(i);
                    p.card(r, 8, if sel { t.selection } else { osyx_gfx::rgb(36, 39, 49) }, if sel { t.accent } else { t.border });
                    icon::draw(p, Icon::Drive, Rect::new(r.x + 14, r.y + 12, 22, 22), if d.blocked.is_some() { t.text_faint } else { t.accent });
                    p.text(FontKind::Bold, r.x + 50, r.y + 6, &format!("/dev/disks/{}", d.name), if d.blocked.is_some() { t.text_faint } else { t.text });
                    let info = format!("{}  ·  {} partition(s)", human_size(d.bytes), d.partitions);
                    p.text(FontKind::Ui, r.x + 50, r.y + 24, &info, t.text_dim);
                    let status = match (&d.blocked, d.mounted.first()) {
                        (Some(why), _) => why.clone(),
                        (None, Some(at)) => format!("available (mounted at {at}; will be unmounted)"),
                        (None, None) => String::from("available"),
                    };
                    p.text_in(FontKind::Ui, Rect::new(r.x, r.y + 14, r.w - 16, 20), &status, if d.blocked.is_some() { osyx_gfx::rgb(240, 150, 90) } else { osyx_gfx::rgb(110, 200, 130) }, Align::Right);
                }
                let [auto, manual] = self.mode_rows();
                for (r, on, label) in [
                    (auto, !self.manual, "Erase the disk and divide it automatically (256 MiB EFI, the rest for OSyx)"),
                    (manual, self.manual, "Manual partitioning: choose the partition sizes"),
                ] {
                    p.ring(r.x + 12, r.y + 18, 8, 2, if on { t.accent } else { t.text_faint }, 255, false);
                    if on {
                        p.disc(r.x + 12, r.y + 18, 4, t.accent, 255);
                    }
                    p.text(FontKind::Ui, r.x + 30, r.y + 9, label, t.text);
                }
                if self.manual {
                    p.text(FontKind::Ui, manual.x + 30, self.esp_mib.rect.y + 7, "EFI (MiB)", t.text_dim);
                    p.text(FontKind::Ui, manual.x + 290, self.root_mib.rect.y + 7, "OSyx (MiB, 0 = rest)", t.text_dim);
                    let f = self.focus;
                    self.esp_mib.draw(p, focused && f == 0);
                    self.root_mib.draw(p, focused && f == 1);
                }
                // The planned layout as a bar.
                if let Ok(plan) = self.plan() {
                    let y = manual.y + if self.manual { 92 } else { 52 };
                    let bar = Rect::new(c.x, y, c.w, 26);
                    p.rounded(bar, 6, t.field, 255);
                    let total = plan.disk_sectors.max(1);
                    let px = |s: u64| (s as u128 * bar.w as u128 / total as u128) as u32;
                    let esp_w = px(plan.esp_sectors).max(6);
                    let root_x = bar.x + px(plan.root_first) as i32;
                    p.rounded(Rect::new(bar.x + px(plan.esp_first) as i32, y, esp_w, 26), 6, osyx_gfx::rgb(240, 180, 70), 255);
                    p.rounded(Rect::new(root_x, y, px(plan.root_sectors).max(6), 26), 6, t.accent, 255);
                    p.text(FontKind::Ui, c.x, y + 32, &format!("EFI system partition {} MiB (FAT32)   ·   OSyx {} MiB (ext4)", plan.esp_mib(), plan.root_mib()), t.text_dim);
                }
            }
            Step::Account => {
                let labels = ["Your name", "User name", "Password", "Repeat password", "Computer name"];
                let f = self.focus;
                for (i, (l, field)) in labels.iter().zip([&self.full_name, &self.user_name, &self.password, &self.password2, &self.hostname]).enumerate() {
                    p.text(FontKind::Ui, c.x, field.rect.y + 8, l, t.text_dim);
                    field.draw(p, focused && f == i);
                }
                p.text(FontKind::Ui, c.x, c.y + 340, "The password may stay empty. The desktop session runs as this user.", t.text_faint);
            }
            Step::Options => {
                self.zen.draw(p, focused);
                let lines = [
                    "Zen Browser is not part of OSyx. When this is checked, the installed",
                    "system downloads the official Windows installer of Zen Browser from",
                    "github.com/zen-browser on its first start, runs it, and adds Zen to",
                    "the applications and the desktop. This needs an Internet connection;",
                    "without one the download is retried on later starts.",
                ];
                for (i, l) in lines.iter().enumerate() {
                    p.text(FontKind::Ui, c.x + 28, c.y + 112 + i as i32 * 22, l, t.text_dim);
                }
            }
            Step::Summary => {
                let d = self.disk.and_then(|i| self.disks.get(i));
                let plan = self.plan().ok();
                let rows = [
                    ("Disk", d.map_or(String::new(), |d| format!("/dev/disks/{} ({}) — will be ERASED", d.name, human_size(d.bytes)))),
                    ("Partitions", plan.map_or(String::new(), |p| format!("EFI {} MiB FAT32, OSyx {} MiB ext4", p.esp_mib(), p.root_mib()))),
                    ("User", format!("{} ({})", self.user_name.text(), self.full_name.text())),
                    ("Password", String::from(if self.password.text().is_empty() { "none" } else { "set" })),
                    ("Computer name", String::from(self.hostname.text())),
                    ("Zen Browser", String::from(if self.zen.checked { "download and install on first start" } else { "no" })),
                ];
                let card = Rect::new(c.x, c.y + 56, c.w, rows.len() as u32 * 40 + 8);
                p.card(card, 10, osyx_gfx::rgb(36, 39, 49), t.border);
                for (i, (k, v)) in rows.iter().enumerate() {
                    let y = card.y + 12 + i as i32 * 40;
                    p.text(FontKind::Ui, card.x + 16, y, k, t.text_dim);
                    p.text(FontKind::Bold, card.x + 180, y, v, t.text);
                }
            }
            Step::Install | Step::Finish => {
                let (stage, frac, lines, result) = match &self.job {
                    Some(j) => {
                        let s = j.lock().unwrap();
                        (s.stage, s.fraction, s.lines.clone(), s.result.clone())
                    }
                    None => (None, 0.0, Vec::new(), None),
                };
                let headline = match &result {
                    Some(Ok(m)) => format!("OSyx was installed: {m}."),
                    Some(Err(m)) => format!("The installation failed: {m}"),
                    None => String::from(stage.map_or("Starting", |s| s.describe())),
                };
                p.text(FontKind::Bold, c.x, c.y + 50, &headline, t.text);
                let bar = Rect::new(c.x, c.y + 84, c.w, 14);
                p.rounded(bar, 7, t.field, 255);
                let fw = ((frac.clamp(0.0, 1.0) * bar.w as f32) as u32).max(14);
                let color = if matches!(result, Some(Err(_))) { osyx_gfx::rgb(230, 90, 90) } else { t.accent };
                p.rounded(Rect::new(bar.x, bar.y, fw, 14), 7, color, 255);
                p.text_in(FontKind::Ui, Rect::new(c.x, c.y + 102, c.w, 18), &format!("{:.0}%", frac * 100.0), t.text_dim, Align::Right);
                if self.step == Step::Finish {
                    self.reboot.label = String::from(if matches!(result, Some(Ok(_))) { "Restart now" } else { "Try again" });
                    self.reboot.draw(p, focused);
                    let note = if matches!(result, Some(Ok(_))) {
                        "Remove the installation medium, then restart."
                    } else {
                        "The disk is not bootable. The full log is in /tmp/osyx-install.log."
                    };
                    p.text(FontKind::Ui, c.x + 196, c.y + 160, note, t.text_dim);
                }
                let log = Rect::new(c.x, c.y + 206, c.w, c.h.saturating_sub(206));
                p.card(log, 8, osyx_gfx::rgb(20, 22, 28), t.border);
                let n = (log.h / 20).saturating_sub(1) as usize;
                for (i, l) in lines.iter().rev().take(n).rev().enumerate() {
                    p.text_in(FontKind::Ui, Rect::new(log.x + 10, log.y + 8 + i as i32 * 20, log.w - 20, 18), l, t.text_dim, Align::Left);
                }
            }
        }
        if !self.message.is_empty() {
            p.text(FontKind::Ui, c.x, h as i32 - 48, &self.message, osyx_gfx::rgb(240, 150, 90));
        }
        if self.step < Step::Install {
            if self.step > Step::Welcome {
                self.back.draw(p, focused);
            }
            self.next.label = String::from(if self.step == Step::Summary { "Install" } else { "Next" });
            self.next.draw(p, focused);
        }
        if let Some(d) = &self.dialog {
            d.draw(p);
        }
    }
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn main() -> i32 {
    let args: Vec<String> = env::args().collect();
    let hostname = fs::read_to_string("/etc/hostname").map(|s| String::from(s.trim())).unwrap_or_default();
    let field = |s: &str| TextField::new(s);
    let mut password = field("");
    password.masked = true;
    let mut password2 = field("");
    password2.masked = true;
    let mut app = Setup {
        step: Step::Welcome,
        size: (0, 0),
        disks: scan_disks(),
        disk: None,
        manual: false,
        esp_mib: field("256"),
        root_mib: field("0"),
        full_name: field(""),
        user_name: field("user"),
        password,
        password2,
        hostname: field(if hostname.is_empty() || hostname == "osyx-live" { "osyx" } else { &hostname }),
        zen: Checkbox::new("Download and install Zen Browser (official Windows installer)", true),
        back: Button::new(1, "Back", ButtonStyle::Secondary),
        next: Button::new(2, "Next", ButtonStyle::Primary),
        rescan: Button::new(3, "Refresh", ButtonStyle::Secondary),
        reboot: Button::new(4, "Restart now", ButtonStyle::Primary),
        focus: 0,
        message: String::new(),
        dialog: None,
        job: None,
        auto: None,
    };
    for d in &app.disks {
        println!("setup: disk {} {} bytes, {} partition(s), {}", d.name, d.bytes, d.partitions, d.blocked.as_deref().unwrap_or("available"));
    }
    if args.iter().any(|a| a == "--auto") {
        let disk = arg_value(&args, "--disk").unwrap_or_default();
        if arg_value(&args, "--confirm-erase").as_deref() != Some(disk.as_str()) || disk.is_empty() {
            eprintln!("setup: --auto needs --disk <name> and --confirm-erase <the same name>");
            println!("SETUP_RESULT refused no confirmation");
            return 2;
        }
        app.disk = app.disks.iter().position(|d| d.name == disk);
        if let Some(v) = arg_value(&args, "--hostname") {
            app.hostname.set_text(&v);
        }
        if let Some(v) = arg_value(&args, "--user") {
            app.user_name.set_text(&v);
        }
        if let Some(v) = arg_value(&args, "--full-name") {
            app.full_name.set_text(&v);
        }
        if let Some(v) = arg_value(&args, "--password") {
            app.password.set_text(&v);
            app.password2.set_text(&v);
        }
        app.zen.checked = args.iter().any(|a| a == "--zen");
        for step in [Step::Disk, Step::Account] {
            app.step = step;
            if let Err(m) = app.check_page() {
                eprintln!("setup: {m}");
                println!("SETUP_RESULT refused {m}");
                return 2;
            }
        }
        println!("setup: unattended installation on {disk} confirmed by --confirm-erase");
        app.begin();
        app.auto = Some(AutoPlan { reboot: args.iter().any(|a| a == "--reboot"), reboot_at: None });
    }
    println!("setup: started");
    // Started together with the session: wait until PRISM accepts clients.
    let tries = if args.iter().any(|a| a == "--wait-session") { 60 } else { 1 };
    for attempt in 1..=tries {
        if prism_client::Connection::connect("setup-probe", false).is_ok() || attempt == tries {
            break;
        }
        os_std::thread::sleep(os_std::time::Duration::from_millis(500));
    }
    let mut spec = WindowSpec::normal("OSyx Setup", 1000, 680);
    spec.min_width = 900;
    spec.min_height = 620;
    let code = run_app("setup", spec, &mut app);
    // Without a window (no session) an unattended installation still
    // finishes, and still restarts when asked to.
    if let (Some(job), Some(auto)) = (&app.job, &app.auto) {
        println!("setup: no window (status {code}); finishing without one");
        while job.lock().unwrap().result.is_none() {
            os_std::thread::sleep(os_std::time::Duration::from_millis(200));
        }
        let ok = matches!(job.lock().unwrap().result, Some(Ok(_)));
        if ok && auto.reboot {
            os_std::thread::sleep(os_std::time::Duration::from_secs(2));
            println!("setup: automatic restart into the installed system");
            let e = system::reboot();
            eprintln!("setup: cannot restart: {e}");
        }
        return if ok { 0 } else { 1 };
    }
    code
}
