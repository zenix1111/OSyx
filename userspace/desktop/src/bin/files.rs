//! Files (`/system/bin/files`): the OSyx file manager. Everything goes
//! through `os_std::fs` on the mounted file systems (ext4 `/`, FAT32
//! `/boot`, tmpfs `/tmp` and `/run`, devfs `/dev`).
//!
//! Double click / Enter opens: folders are entered, programs started,
//! other files shown in a text (or hex) viewer. A row dragged onto a folder
//! row or a place (Home, Desktop, a volume) moves the file or folder there.
//! Tool bar and keys: Back (Alt+Left), Up (Backspace), Home, New folder
//! (Ctrl+N), Rename (F2), Delete (Del: moves to the Trash; in the Trash it
//! deletes permanently), Restore from the Trash, Properties (Ctrl+I),
//! Refresh (F5, also picks up USB sticks plugged in), hidden files (Ctrl+H).
//!
//! Several files at once: Ctrl+click toggles a row, Shift+click (or
//! Shift+arrows) selects a range, a rubber band dragged over empty space
//! selects the rows it touches, Ctrl+A selects all. Copy (Ctrl+C), Cut
//! (Ctrl+X) and Paste (Ctrl+V), Delete, Pack into a tar archive (Ctrl+P),
//! Extract here (Ctrl+E: tar, tar.gz, zip, 7z, gz) and dragging act on the
//! whole selection. The context menu (right click) has "Open with": a file
//! opens with the program the user chose for its type, else with what
//! `/system/share/applications/*.app` registers (`Handles=`), else by itself
//! (text viewer, hex viewer, default browser for images and pages).

#![no_std]
#![no_main]

#[path = "../fileops.rs"]
mod fileops;
#[path = "../shell_common.rs"]
mod common;

use common::{become_user, human_size, run_app, system_tz, App, Ctx, USER_HOME};
use os_std::fs::{self, Metadata};
use os_std::prelude::*;
use os_std::process::Command;
use os_std::time::{Duration, Instant};
use os_std::{env, system, thread};
use osyx_filekit::openwith::{self, Builtin, Choices, Handler, Target};
use osyx_filekit::{classify, select, Kind};
use osyx_gfx::Rect;
use osyx_input::{button, key, modifier};
use osyx_ui::layout::{contains, inset, split_bottom, split_left, split_top};
use osyx_ui::time::Tz;
use osyx_ui::widget::{Button, ButtonStyle, Checkbox, Column, Dialog, ListItem, ListView, Menu, MenuItem, ScrollView, TextField};
use osyx_ui::{icon, Align, Event as Ui, FontKind, Icon, Painter, Response};
use prism_client::WindowSpec;

os_std::entry!(main);

const TOOLBAR: u32 = 52;
const SIDEBAR: u32 = 190;
const STATUS: u32 = 30;
const PREVIEW_LIMIT: usize = 256 * 1024;

const D_NEW: u32 = 1;
const D_RENAME: u32 = 2;
const D_DELETE: u32 = 3;
/// The desktop user's trash (freedesktop.org layout): deleted files in
/// `files/`, where each came from in `info/<name>.trashinfo`.
const TRASH: &str = "/home/user/.local/share/Trash";
const TRASH_FILES: &str = "/home/user/.local/share/Trash/files";
const D_INFO: u32 = 4;
/// Home, Desktop, Trash and Root come before the mounted volumes.
const BUILTIN_PLACES: usize = 4;

/// Mounted volumes other than `/` for the side bar. USB sticks and disks
/// the media manager mounted show their volume label.
fn volume_places() -> Vec<(String, String, Icon)> {
    let Ok(mounts) = system::mounts() else { return Vec::new() };
    let media = osyx_abi::media::parse(&fs::read_to_string(osyx_abi::media::STATUS_PATH).unwrap_or_default());
    mounts
        .iter()
        .map(|m| (system::field_str(&m.path), system::field_str(&m.fstype)))
        .filter(|(path, _)| *path != "/")
        .map(|(path, fstype)| {
            let volume = media.iter().flat_map(|d| d.volumes.iter()).find(|v| v.mount.as_deref() == Some(&path[..]));
            let label = match volume {
                Some(v) => format!("{} ({})", v.name(), osyx_abi::media::fs_name(&v.fstype)),
                None => format!("{path} ({fstype})"),
            };
            (label, String::from(path), Icon::Drive)
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tool {
    Back,
    Up,
    Home,
    NewFolder,
    Rename,
    Delete,
    Restore,
    Info,
    Refresh,
}

const TOOLS: [(Tool, Icon, &str); 9] = [
    (Tool::Back, Icon::Up, "Back"),
    (Tool::Up, Icon::Up, "Up one level"),
    (Tool::Home, Icon::Home, "Home folder"),
    (Tool::NewFolder, Icon::NewFolder, "New folder"),
    (Tool::Rename, Icon::Rename, "Rename"),
    (Tool::Delete, Icon::Trash, "Move to Trash (in the Trash: delete permanently)"),
    (Tool::Restore, Icon::Restart, "Restore from the Trash"),
    (Tool::Info, Icon::Info, "Properties"),
    (Tool::Refresh, Icon::Refresh, "Refresh"),
];

struct Entry {
    name: String,
    meta: Option<Metadata>,
}

/// A Windows program (.exe): run by winrun even without the executable bit,
/// which downloads and FAT32 volumes do not set.
fn is_win_program(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".exe")
}

impl Entry {
    fn is_dir(&self) -> bool {
        self.meta.as_ref().is_some_and(|m| m.is_dir())
    }

    fn is_program(&self) -> bool {
        self.meta.as_ref().is_some_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }

    fn kind(&self) -> (&'static str, Icon) {
        let Some(m) = &self.meta else { return ("Unreadable", Icon::File) };
        let ft = m.file_type();
        if m.is_dir() {
            ("Folder", Icon::Folder)
        } else if m.is_symlink() {
            ("Symbolic link", Icon::Link)
        } else if ft.is_char_device() || ft.is_block_device() {
            ("Device", Icon::Device)
        } else if self.is_program() || is_win_program(&self.name) {
            ("Program", Icon::Program)
        } else {
            let k = classify(&self.name);
            (k.label(), if k.viewable() && k != Kind::Other { Icon::TextFile } else { Icon::File })
        }
    }

    fn file_kind(&self) -> Kind {
        classify(&self.name)
    }
}

struct Preview {
    path: String,
    lines: Vec<String>,
    view: ScrollView,
    close: Button,
    hex: bool,
}

struct FileDrag {
    index: usize,
    start: (i32, i32),
    pointer: (i32, i32),
    moved: bool,
}

struct Files {
    cwd: String,
    back: Vec<String>,
    entries: Vec<Entry>,
    list: ListView,
    path: TextField,
    path_focus: bool,
    tools: Vec<(Tool, Button)>,
    places: Vec<(String, String, Icon)>,
    place_hover: Option<usize>,
    hidden: Checkbox,
    status: String,
    status_error: bool,
    dialog: Option<Dialog>,
    preview: Option<Preview>,
    drag: Option<FileDrag>,
    pending_move: Option<(String, Instant)>,
    tz: Tz,
    size: (u32, u32),
    hint: Option<&'static str>,
    /// Modifier keys as of the last key event (pointer events carry none).
    mods: u32,
    /// Where a Shift range starts.
    anchor: Option<usize>,
    /// Copied or cut paths and whether they are to be moved.
    clipboard: Option<(Vec<String>, bool)>,
    /// Applications registered for file types, the user's choices, and
    /// whether a default browser exists.
    handlers: Vec<Handler>,
    choices: Choices,
    browser: bool,
    menu: Option<ContextMenu>,
    band: Option<Band>,
    /// Names a pending delete dialog is about.
    delete_names: Vec<String>,
}

const CHOICES_FILE: &str = "/home/user/.config/osyx/openwith.conf";

/// What a context menu item does.
#[derive(Clone, Debug)]
enum Act {
    Open,
    With(Target),
    Default(Target),
    Copy,
    Cut,
    Paste,
    Trash,
    Pack,
    Extract,
    Rename,
    Info,
    NewFolder,
}

struct ContextMenu {
    menu: Menu,
    acts: Vec<Act>,
}

/// A rubber band being dragged over the list.
struct Band {
    start: (i32, i32),
    pointer: (i32, i32),
    /// `list.content_y` of the start, so scrolling keeps the band anchored.
    start_content: i32,
    moved: bool,
}

fn load_handlers() -> Vec<Handler> {
    common::load_app_texts().iter().filter_map(|t| Handler::parse(t)).collect()
}

fn main() -> i32 {
    become_user();
    let start = env::args().nth(1).unwrap_or_else(|| String::from(USER_HOME));
    let mut list = ListView::new(vec![
        Column::new("Name", 0, Align::Left),
        Column::new("Size", 86, Align::Right),
        Column::new("Type", 118, Align::Left),
        Column::new("Modified", 140, Align::Left),
    ]);
    list.row_height = 30;
    let mut places = vec![
        (String::from("Home"), String::from(USER_HOME), Icon::Home),
        (String::from("Desktop"), String::from(common::DESKTOP_DIR), Icon::Apps),
        (String::from("Trash"), String::from(TRASH_FILES), Icon::Trash),
        (String::from("Root (ext4)"), String::from("/"), Icon::Drive),
    ];
    let _ = fs::create_dir_all(TRASH_FILES);
    let _ = fs::create_dir_all(format!("{TRASH}/info"));
    places.extend(volume_places());
    let mut f = Files {
        cwd: String::new(),
        back: Vec::new(),
        entries: Vec::new(),
        list,
        path: TextField::new(""),
        path_focus: false,
        tools: TOOLS.iter().map(|(t, i, _)| (*t, Button::new(0, "", ButtonStyle::Flat).with_icon(*i))).collect(),
        places,
        place_hover: None,
        hidden: Checkbox::new("Show hidden files", false),
        status: String::new(),
        status_error: false,
        dialog: None,
        preview: None,
        drag: None,
        pending_move: None,
        tz: system_tz(),
        size: (0, 0),
        hint: None,
        mods: 0,
        anchor: None,
        clipboard: None,
        handlers: load_handlers(),
        choices: Choices::parse(&fs::read_to_string(CHOICES_FILE).unwrap_or_default()),
        browser: fs::read_to_string("/etc/osyx/default-browser").is_ok_and(|b| b.trim().starts_with('/')),
        menu: None,
        band: None,
        delete_names: Vec::new(),
    };
    f.navigate(&start, false);
    let spec = WindowSpec::normal(&format!("Files — {}", f.cwd), 860, 540);
    run_app("files", spec, &mut f)
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn parent(path: &str) -> String {
    match path.trim_end_matches('/').rfind('/') {
        Some(0) | None => String::from("/"),
        Some(i) => String::from(&path[..i]),
    }
}

fn mode_string(mode: u32) -> String {
    let mut s = String::new();
    for shift in [6, 3, 0] {
        let m = mode >> shift;
        s.push(if m & 4 != 0 { 'r' } else { '-' });
        s.push(if m & 2 != 0 { 'w' } else { '-' });
        s.push(if m & 1 != 0 { 'x' } else { '-' });
    }
    s
}

impl Files {
    fn set_status(&mut self, s: String, error: bool) {
        if error {
            eprintln!("files: {s}");
        }
        self.status = s;
        self.status_error = error;
    }

    /// Lists `path`; on success it becomes the current folder.
    fn navigate(&mut self, path: &str, remember: bool) -> bool {
        let path = if path.is_empty() { "/" } else { path };
        let mut entries: Vec<Entry> = match fs::read_dir(path) {
            Ok(d) => d.map(|e| Entry { meta: e.metadata().ok(), name: String::from(e.file_name()) }).collect(),
            Err(e) => {
                self.set_status(format!("Cannot open {path}: {e}"), true);
                return false;
            }
        };
        if !self.hidden.checked {
            entries.retain(|e| !e.name.starts_with('.'));
        }
        entries.sort_by(|a, b| {
            b.is_dir().cmp(&a.is_dir()).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        if remember && self.cwd != path {
            self.back.push(self.cwd.clone());
        }
        let changed_dir = self.cwd != path;
        self.cwd = String::from(path);
        self.entries = entries;
        let items = self
            .entries
            .iter()
            .map(|e| {
                let (kind, ic) = e.kind();
                let size = match &e.meta {
                    Some(m) if !m.is_dir() => human_size(m.len()),
                    _ => String::new(),
                };
                let modified = e.meta.as_ref().and_then(|m| m.modified().ok()).map_or(String::new(), |t| {
                    let secs = t.duration_since(os_std::time::SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
                    let l = self.tz.local(secs);
                    format!("{:04}-{:02}-{:02} {:02}:{:02}", l.year, l.month, l.day, l.hour, l.minute)
                });
                ListItem::new(Some(ic), &[&e.name, &size, kind, &modified])
            })
            .collect();
        self.list.set_items(items);
        if changed_dir {
            self.list.select(if self.entries.is_empty() { None } else { Some(0) });
            self.list.scroll.offset = 0;
        }
        self.path.set_text(path);
        let folders = self.entries.iter().filter(|e| e.is_dir()).count();
        self.set_status(
            format!("{} items ({} folders, {} files)", self.entries.len(), folders, self.entries.len() - folders),
            false,
        );
        println!("files: listed {} ({} entries)", self.cwd, self.entries.len());
        true
    }

    fn refresh(&mut self) {
        let cwd = self.cwd.clone();
        let sel = self.list.selected();
        self.navigate(&cwd, false);
        self.list.select(sel);
        // Volumes mounted meanwhile (a USB stick plugged in).
        self.places.truncate(BUILTIN_PLACES);
        self.places.extend(volume_places());
    }

    fn selected(&self) -> Option<&Entry> {
        self.list.selected().and_then(|i| self.entries.get(i))
    }

    /// The folder a drag at (`x`, `y`) would drop into: another row that is
    /// a folder, or a place in the side bar.
    fn drop_folder(&self, x: i32, y: i32, source: usize) -> Option<(String, String)> {
        if let Some(i) = self.list.row_at(x, y) {
            if i != source {
                let e = self.entries.get(i)?;
                if e.is_dir() {
                    return Some((join(&self.cwd, &e.name), e.name.clone()));
                }
            }
            return None;
        }
        for (r, (label, path, _)) in self.place_rects().iter().zip(&self.places) {
            if contains(r, x, y) {
                let path = path.trim_end_matches('/');
                if path != self.cwd.trim_end_matches('/') {
                    return Some((String::from(path), label.clone()));
                }
            }
        }
        None
    }

    fn move_entry(&mut self, index: usize, target: &str, label: &str) {
        let Some(e) = self.entries.get(index) else { return };
        let name = e.name.clone();
        let is_dir = e.is_dir();
        let from = join(&self.cwd, &name);
        let to = join(target, &name);
        if fs::symlink_metadata(&to).is_ok() {
            self.set_status(format!("\"{name}\" already exists in {label}"), true);
            return;
        }
        let moved = if is_dir {
            fs::rename(&from, &to).map(|_| ())
        } else {
            match fs::rename(&from, &to) {
                Ok(()) => Ok(()),
                // Another volume: rename cannot cross file systems.
                Err(_) => fs::copy(&from, &to).map(|_| ()).and_then(|_| fs::remove_file(&from)),
            }
        };
        match moved {
            Ok(()) => {
                println!("files: moved {from} to {to}");
                self.refresh();
                self.set_status(format!("Moved {name} to {label}"), false);
            }
            Err(err) => self.set_status(format!("Cannot move {from}: {err}"), true),
        }
    }

    fn open(&mut self, i: usize, cx: &mut Ctx) {
        let Some(e) = self.entries.get(i) else { return };
        let path = join(&self.cwd, &e.name);
        if e.is_dir() {
            if self.navigate(&path, true) {
                cx.title = Some(format!("Files — {}", self.cwd));
            }
        } else if e.is_program() || is_win_program(&e.name) || e.name.ends_with(".app") {
            let shortcut = if e.name.ends_with(".app") { common::load_app(&path) } else { None };
            let command = if let Some(app) = &shortcut {
                let windows = is_win_program(&app.exec);
                let mut c = Command::new(if windows { "/bin/winrun" } else { &app.exec });
                if windows {
                    c.arg(&app.exec);
                }
                c
            } else if e.is_program() || is_win_program(&e.name) {
                let windows = is_win_program(&path);
                let mut c = Command::new(if windows { "/bin/winrun" } else { &path });
                if windows {
                    c.arg(&path);
                }
                c
            } else {
                self.set_status(format!("Invalid application shortcut: {path}"), true);
                return;
            };
            self.spawn(command, &e.name.clone(), &path);
        } else {
            let (name, kind) = (e.name.clone(), e.file_kind());
            match openwith::default_target(&name, kind, &self.handlers, &self.choices, self.browser) {
                Some(t) => self.run_target(&path, &t),
                None => {
                    let what = osyx_filekit::kind::extension(&name).map_or(String::from("this kind of file"), |x| format!(".{x} files"));
                    self.set_status(
                        format!("No application is registered for {what}: add Handles=... to an application's .app file, or use Open with > Hex viewer"),
                        true,
                    );
                }
            }
        }
    }

    fn spawn(&mut self, mut command: Command, name: &str, path: &str) {
        match command.spawn() {
            Ok(child) => {
                let pid = child.id();
                self.set_status(format!("Started {name} as process {pid}"), false);
                println!("files: started program {path} as process {pid}");
                thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            Err(err) => self.set_status(format!("Cannot start {path}: {err}"), true),
        }
    }

    /// Opens `path` the way `target` says.
    fn run_target(&mut self, path: &str, target: &Target) {
        match target {
            Target::Builtin(Builtin::Viewer) => self.preview(String::from(path), false),
            Target::Builtin(Builtin::Hex) => self.preview(String::from(path), true),
            Target::Builtin(Builtin::Browser) => {
                let mut c = Command::new("/bin/open");
                c.arg(path);
                let name = path.rsplit('/').next().unwrap_or(path).to_string();
                self.spawn(c, &name, path);
            }
            Target::Builtin(Builtin::Extract) => self.extract_paths(&[String::from(path)]),
            Target::Exec(exec) => {
                let windows = is_win_program(exec);
                let mut c = Command::new(if windows { "/bin/winrun" } else { exec });
                if windows {
                    c.arg(exec);
                }
                c.arg(path);
                println!("files: opening {path} with {exec}");
                let name = path.rsplit('/').next().unwrap_or(path).to_string();
                self.spawn(c, &name, path);
            }
        }
    }

    fn preview(&mut self, path: String, force_hex: bool) {
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                self.set_status(format!("Cannot open {path}: {e}"), true);
                return;
            }
        };
        let shown = &data[..data.len().min(PREVIEW_LIMIT)];
        let text = core::str::from_utf8(shown).ok().filter(|t| !t.contains('\0') && !force_hex);
        let (lines, hex) = match text {
            Some(t) => (t.lines().map(|l| l.replace('\t', "    ")).collect::<Vec<_>>(), false),
            None => {
                let mut v = Vec::new();
                for (row, chunk) in shown[..shown.len().min(16 * 1024)].chunks(16).enumerate() {
                    let hexs: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    let ascii: String =
                        chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
                    v.push(format!("{:08x}  {:<47}  {}", row * 16, hexs.join(" "), ascii));
                }
                (v, true)
            }
        };
        println!("files: opened {} ({} bytes, {})", path, data.len(), if hex { "hex view" } else { "text view" });
        let mut note = format!("Viewing {} ({})", path, human_size(data.len() as u64));
        if data.len() > PREVIEW_LIMIT {
            note.push_str(", first 256 KiB");
        }
        self.set_status(note, false);
        self.preview = Some(Preview {
            path,
            lines,
            view: ScrollView::default(),
            close: Button::new(0, "Close", ButtonStyle::Secondary),
            hex,
        });
        let (w, h) = self.size;
        self.layout_inner(w, h);
    }

    fn in_trash(&self) -> bool {
        self.cwd == TRASH_FILES || self.cwd.starts_with(&format!("{TRASH_FILES}/"))
    }

    /// Moves `name` (in the current folder) into the Trash under a free
    /// name, recording where it came from. Fails across volumes (the Trash
    /// is on the root file system).
    fn move_to_trash(&self, name: &str) -> Result<String, String> {
        let from = join(&self.cwd, name);
        let _ = fs::create_dir_all(TRASH_FILES);
        let _ = fs::create_dir_all(format!("{TRASH}/info"));
        let free = |n: &str| fs::symlink_metadata(join(TRASH_FILES, n)).is_err() && fs::metadata(format!("{TRASH}/info/{n}.trashinfo")).is_err();
        let trashed = (1..).map(|i| if i == 1 { String::from(name) } else { format!("{name}.{i}") }).find(|n| free(n)).unwrap_or_default();
        fs::rename(&from, join(TRASH_FILES, &trashed)).map_err(|e| format!("{e}"))?;
        let when = os_std::time::SystemTime::now()
            .duration_since(os_std::time::SystemTime::UNIX_EPOCH)
            .map_or(String::new(), |d| self.tz.local(d.as_secs() as i64).iso());
        let info = format!("[Trash Info]\nPath={from}\nDeletionDate={when}\n");
        if let Err(e) = fs::write(format!("{TRASH}/info/{trashed}.trashinfo"), info.as_bytes()) {
            // Without its record the file could not be restored: put it back.
            let _ = fs::rename(join(TRASH_FILES, &trashed), &from);
            return Err(format!("{e}"));
        }
        Ok(format!("Moved {name} to the Trash"))
    }

    /// Puts `name` from the Trash back where it was deleted from.
    fn restore_from_trash(&self, name: &str) -> Result<String, String> {
        let info_path = format!("{TRASH}/info/{name}.trashinfo");
        let info = fs::read_to_string(&info_path).map_err(|_| format!("{name}: where it came from is unknown"))?;
        let to = info.lines().find_map(|l| l.strip_prefix("Path=")).map(String::from).ok_or_else(|| format!("{name}: where it came from is unknown"))?;
        if fs::symlink_metadata(&to).is_ok() {
            return Err(format!("{to} exists already; rename it first"));
        }
        let _ = fs::create_dir_all(&parent(&to));
        fs::rename(join(TRASH_FILES, name), &to).map_err(|e| format!("Cannot restore {to}: {e}"))?;
        let _ = fs::remove_file(&info_path);
        Ok(format!("Restored {to}"))
    }

    fn tool(&mut self, t: Tool, cx: &mut Ctx) {
        match t {
            Tool::Back => {
                if let Some(prev) = self.back.pop() {
                    self.navigate(&prev, false);
                }
            }
            Tool::Up => {
                let p = parent(&self.cwd);
                self.navigate(&p, true);
            }
            Tool::Home => {
                self.navigate(USER_HOME, true);
            }
            Tool::Refresh => self.refresh(),
            Tool::NewFolder => {
                self.dialog = Some(
                    Dialog::new(
                        D_NEW,
                        "New folder",
                        &format!("Create a folder in {}", self.cwd),
                        &[("Cancel", ButtonStyle::Secondary), ("Create", ButtonStyle::Primary)],
                    )
                    .with_input("New folder", "Folder name"),
                );
            }
            Tool::Rename => {
                if let Some(e) = self.selected() {
                    let name = e.name.clone();
                    self.dialog = Some(
                        Dialog::new(
                            D_RENAME,
                            "Rename",
                            &format!("New name for \"{name}\""),
                            &[("Cancel", ButtonStyle::Secondary), ("Rename", ButtonStyle::Primary)],
                        )
                        .with_input(&name, "Name"),
                    );
                }
            }
            Tool::Delete => self.trash_selection(),
            Tool::Restore => {
                if let Some(name) = self.selected().map(|e| e.name.clone()) {
                    let (msg, err) = match self.restore_from_trash(&name) {
                        Ok(m) => (m, false),
                        Err(m) => (m, true),
                    };
                    println!("files: {msg}");
                    self.refresh();
                    self.set_status(msg, err);
                }
            }
            Tool::Info => {
                if let Some(e) = self.selected() {
                    let path = join(&self.cwd, &e.name);
                    let msg = match fs::symlink_metadata(&path) {
                        Ok(m) => {
                            let time = |t: os_std::error::Result<os_std::time::SystemTime>| {
                                t.ok()
                                    .and_then(|t| t.duration_since(os_std::time::SystemTime::UNIX_EPOCH).ok())
                                    .map_or(String::from("-"), |d| self.tz.local(d.as_secs() as i64).iso())
                            };
                            let mode = m.permissions().mode();
                            let target = if m.is_symlink() {
                                fs::read_link(&path).map(|p| format!("\nPoints to: {}", p.as_str())).unwrap_or_default()
                            } else {
                                String::new()
                            };
                            format!(
                                "Location: {}\nType: {}\nSize: {} ({} bytes)\nPermissions: {} ({:04o})\nOwner: uid {}, gid {}\nInode {} on volume {}, {} link(s)\nModified: {}\nAccessed: {}{}",
                                self.cwd,
                                e.kind().0,
                                human_size(m.len()),
                                m.len(),
                                mode_string(mode),
                                mode & 0o7777,
                                m.uid(),
                                m.gid(),
                                m.ino(),
                                m.dev(),
                                m.nlink(),
                                time(m.modified()),
                                time(m.accessed()),
                                target
                            )
                        }
                        Err(err) => format!("Cannot read the properties: {err}"),
                    };
                    let title = e.name.clone();
                    self.dialog = Some(Dialog::new(D_INFO, &title, &msg, &[("Close", ButtonStyle::Primary)]));
                }
            }
        }
        cx.title = Some(format!("Files — {}", self.cwd));
        let (w, h) = self.size;
        self.layout_inner(w, h);
    }

    fn dialog_done(&mut self, tag: u32, input: String) {
        let sel = self.selected().map(|e| e.name.clone());
        let result = match tag {
            D_NEW => {
                let name = input.trim();
                if name.is_empty() || name.contains('/') {
                    Err(format!("\"{name}\" is not a valid folder name"))
                } else {
                    let p = join(&self.cwd, name);
                    fs::create_dir(&p)
                        .map(|_| format!("Created folder {p}"))
                        .map_err(|e| format!("Cannot create {p}: {e}"))
                }
            }
            D_RENAME => match sel {
                Some(old) => {
                    let new = input.trim();
                    if new.is_empty() || new.contains('/') {
                        Err(format!("\"{new}\" is not a valid name"))
                    } else {
                        let (from, to) = (join(&self.cwd, &old), join(&self.cwd, new));
                        fs::rename(&from, &to)
                            .map(|_| format!("Renamed {old} to {new}"))
                            .map_err(|e| format!("Cannot rename {from}: {e}"))
                    }
                }
                None => return,
            },
            D_DELETE => {
                let names = core::mem::take(&mut self.delete_names);
                let mut failed = None;
                for name in &names {
                    let p = join(&self.cwd, name);
                    match remove_any(&p) {
                        Ok(()) if self.in_trash() => {
                            let _ = fs::remove_file(format!("{TRASH}/info/{name}.trashinfo"));
                        }
                        Ok(()) => {}
                        Err(e) => {
                            failed = Some(format!("Cannot delete {p}: {e}"));
                            break;
                        }
                    }
                }
                match failed {
                    Some(f) => Err(f),
                    None => Ok(format!("Deleted {} item(s)", names.len())),
                }
            }
            _ => return,
        };
        let (msg, err) = match result {
            Ok(m) => (m, false),
            Err(m) => (m, true),
        };
        println!("files: {msg}");
        self.refresh();
        self.set_status(msg, err);
    }

    fn layout_inner(&mut self, w: u32, h: u32) {
        let full = Rect::new(0, 0, w, h);
        let (bar, rest) = split_top(full, TOOLBAR);
        let (rest, _status) = split_bottom(rest, STATUS);
        let (side, main) = split_left(rest, SIDEBAR);
        let mut x = 10;
        let (in_trash, selected) = (self.in_trash(), self.list.selected().is_some());
        for (i, (t, b)) in self.tools.iter_mut().enumerate() {
            if i == 3 {
                // Path field between navigation and file operations.
                let right_tools = 6 * 40 + 10;
                let pw = (w as i32 - x - right_tools - 10).max(80) as u32;
                self.path.rect = Rect::new(x + 4, 9, pw, TOOLBAR - 18);
                x += pw as i32 + 14;
            }
            b.rect = Rect::new(x, 8, 36, TOOLBAR - 16);
            b.enabled = match t {
                Tool::Back => !self.back.is_empty(),
                Tool::Up => self.cwd != "/",
                Tool::Rename | Tool::Delete | Tool::Info => selected || !self.list.marked().is_empty(),
                Tool::Restore => in_trash && selected,
                _ => true,
            };
            x += 40;
        }
        let _ = bar;
        self.hidden.rect = Rect::new(side.x + 14, side.bottom() as i32 - 40, side.w - 20, 28);
        self.list.rect = inset(main, 0);
        if let Some(p) = &mut self.preview {
            let (head, body) = split_top(main, 44);
            p.close.rect = Rect::new(head.right() as i32 - 96, head.y + 6, 84, 32);
            p.view.rect = Rect::new(body.x, body.y, body.w, body.h);
            p.view.set_content_height(p.lines.len() as u32 * 20 + 20);
        }
        if let Some(d) = &mut self.dialog {
            let fonts = osyx_ui::Fonts::load();
            d.layout(full, &fonts);
        }
    }

    fn place_rects(&self) -> Vec<Rect> {
        let (w, h) = self.size;
        let full = Rect::new(0, 0, w, h);
        let rest = split_top(full, TOOLBAR).1;
        let side = split_left(split_bottom(rest, STATUS).0, SIDEBAR).0;
        (0..self.places.len()).map(|i| Rect::new(side.x + 8, side.y + 40 + i as i32 * 34, side.w - 16, 32)).collect()
    }
}

/// Selection, clipboard, pack and extract, and the context menu.
impl Files {
    /// Names of the marked rows, or of the selected row.
    fn chosen_names(&self) -> Vec<String> {
        self.list.chosen().into_iter().filter_map(|i| self.entries.get(i)).map(|e| e.name.clone()).collect()
    }

    fn chosen_paths(&self) -> Vec<String> {
        self.chosen_names().iter().map(|n| join(&self.cwd, n)).collect()
    }

    fn describe_selection(&mut self) {
        let chosen = self.list.chosen();
        if chosen.len() > 1 {
            let bytes: u64 = chosen.iter().filter_map(|&i| self.entries.get(i)).filter_map(|e| e.meta.as_ref()).filter(|m| !m.is_dir()).map(|m| m.len()).sum();
            self.set_status(format!("{} items selected ({})", chosen.len(), human_size(bytes)), false);
            println!("files: {} items selected", chosen.len());
        }
    }

    fn note_result(&mut self, r: Result<String, String>) {
        let (msg, err) = match r {
            Ok(m) => (m, false),
            Err(m) => (m, true),
        };
        println!("files: {msg}");
        self.refresh();
        self.set_status(msg, err);
    }

    fn copy_selection(&mut self, cut: bool, cx: &mut Ctx) {
        let paths = self.chosen_paths();
        if paths.is_empty() {
            return;
        }
        let n = paths.len();
        let Some(entry) = prism_client::proto::clipboard_files_entry(&paths, cut) else {
            self.set_status(String::from("Selection is too large for the clipboard"), true);
            return;
        };
        self.clipboard = Some((paths.clone(), cut));
        cx.file_clipboard = Some((paths, cut));
        cx.clipboard_entries = Some(vec![entry]);
        self.set_status(format!("{} {n} item(s): paste with Ctrl+V", if cut { "Cut" } else { "Copied" }), false);
        println!("files: {} {n} item(s)", if cut { "cut" } else { "copied" });
    }

    fn paste(&mut self, cx: &mut Ctx) {
        let Some((paths, cut)) = self.clipboard.clone() else {
            self.set_status(String::from("Nothing to paste"), true);
            return;
        };
        let (mut done, mut failure) = (0usize, None);
        let mut processed = 0usize;
        for p in &paths {
            let name = p.rsplit('/').next().unwrap_or(p);
            let source_is_dir = fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
            if source_is_dir && select::is_inside(&self.cwd, p) {
                failure = Some(format!("Cannot put the folder {name} into itself"));
                break;
            }
            if cut && parent(p) == self.cwd.trim_end_matches('/') {
                processed += 1;
                continue;
            }
            let cwd = self.cwd.clone();
            let free = select::free_name(name, |n| fs::symlink_metadata(join(&cwd, n)).is_ok());
            let to = join(&cwd, &free);
            let r = if cut {
                fs::rename(p, &to).map_err(|e| e.to_string()).or_else(|_| fileops::copy_tree(p, &to).and_then(|_| remove_any(p)))
            } else {
                fileops::copy_tree(p, &to).map(|_| ())
            };
            match r {
                Ok(()) => { done += 1; processed += 1; }
                Err(e) => {
                    failure = Some(format!("Cannot {} {name}: {e}", if cut { "move" } else { "copy" }));
                    break;
                }
            }
        }
        if cut {
            let remaining = &paths[processed..];
            if remaining.is_empty() {
                self.clipboard = None;
                cx.file_clipboard = None;
                cx.clipboard_entries = Some(Vec::new());
            } else if processed > 0 {
                let remaining = remaining.to_vec();
                if let Some(entry) = prism_client::proto::clipboard_files_entry(&remaining, true) {
                    self.clipboard = Some((remaining.clone(), true));
                    cx.file_clipboard = Some((remaining, true));
                    cx.clipboard_entries = Some(vec![entry]);
                }
            }
        }
        let r = match failure {
            Some(f) => Err(f),
            None => Ok(format!("{} {done} item(s)", if cut { "Moved" } else { "Pasted" })),
        };
        if let Ok(m) = &r {
            println!("files: pasted: {m}");
        }
        self.note_result(r);
    }

    fn trash_selection(&mut self) {
        let names = self.chosen_names();
        if names.is_empty() {
            return;
        }
        if !self.in_trash() {
            let mut why = None;
            let mut done = 0;
            for n in &names {
                match self.move_to_trash(n) {
                    Ok(_) => done += 1,
                    Err(w) => {
                        why = Some(w);
                        break;
                    }
                }
            }
            match why {
                None => {
                    self.note_result(Ok(format!("Moved {} item(s) to the Trash", names.len())));
                    return;
                }
                Some(w) => {
                    self.delete_names = names[done..].to_vec();
                    self.refresh();
                    self.ask_delete(&format!(" They cannot go to the Trash ({w})."));
                    return;
                }
            }
        }
        self.delete_names = names;
        self.ask_delete("");
    }

    fn ask_delete(&mut self, reason: &str) {
        let n = self.delete_names.len();
        let what = match (n, self.delete_names.first()) {
            (1, Some(name)) => format!("\"{name}\""),
            _ => format!("{n} items"),
        };
        let msg = format!("Delete {what} permanently? This cannot be undone. Folders are deleted with everything inside them.{reason}");
        self.dialog = Some(Dialog::new(D_DELETE, "Delete", &msg, &[("Cancel", ButtonStyle::Secondary), ("Delete", ButtonStyle::Danger)]));
    }

    fn pack_selection(&mut self) {
        let names = self.chosen_names();
        if names.is_empty() {
            return;
        }
        let base = if names.len() == 1 { names[0].clone() } else { String::from("archive") };
        let cwd = self.cwd.clone();
        let out_name = select::free_name(&format!("{base}.tar"), |n| fs::symlink_metadata(join(&cwd, n)).is_ok());
        let out = join(&cwd, &out_name);
        let r = fileops::pack(&cwd, &names, &out).map(|n| format!("Packed {n} item(s) into {out_name}"));
        self.note_result(r);
    }

    fn extract_paths(&mut self, paths: &[String]) {
        let (mut done, mut failure) = (0usize, None);
        for p in paths {
            let name = p.rsplit('/').next().unwrap_or(p);
            // A folder named after the archive, next to it.
            let stem = ["tar.gz", "tgz", "tar", "zip", "7z", "gz"]
                .iter()
                .find_map(|ext| name.to_ascii_lowercase().strip_suffix(&format!(".{ext}")).map(|s| s.len()))
                .map_or(name, |len| &name[..len]);
            let dir = parent(p);
            let free = select::free_name(stem, |n| fs::symlink_metadata(join(&dir, n)).is_ok());
            match fileops::extract(p, &join(&dir, &free)) {
                Ok(n) => {
                    println!("files: extracted {name} into {free} ({n} files)");
                    done += n;
                }
                Err(e) => {
                    failure = Some(format!("Cannot extract {name}: {e}"));
                    break;
                }
            }
        }
        let r = match failure {
            Some(f) => Err(f),
            None => Ok(format!("Extracted {done} file(s)")),
        };
        self.note_result(r);
    }

    fn extract_selection(&mut self) {
        let paths: Vec<String> = self
            .chosen_names()
            .into_iter()
            .filter(|n| fileops::is_archive(n))
            .map(|n| join(&self.cwd, &n))
            .collect();
        if paths.is_empty() {
            self.set_status(String::from("Select an archive (tar, tar.gz, zip, 7z, gz) to extract"), true);
            return;
        }
        self.extract_paths(&paths);
    }

    fn save_choices(&mut self) {
        let _ = fs::create_dir_all("/home/user/.config/osyx");
        if let Err(e) = fs::write(CHOICES_FILE, self.choices.render().as_bytes()) {
            self.set_status(format!("Cannot save the choice: {e}"), true);
        }
    }

    fn open_context_menu(&mut self, x: i32, y: i32, fonts: &osyx_ui::Fonts) {
        let mut items: Vec<MenuItem> = Vec::new();
        let mut acts: Vec<Act> = Vec::new();
        let mut add = |items: &mut Vec<MenuItem>, acts: &mut Vec<Act>, item: MenuItem, act: Act| {
            items.push(item);
            acts.push(act);
        };
        let chosen = self.chosen_names();
        let has_clip = self.clipboard.is_some();
        if let [name] = chosen.as_slice() {
            let entry = self.entries.iter().find(|e| &e.name == name);
            let is_dir = entry.is_some_and(|e| e.is_dir());
            add(&mut items, &mut acts, MenuItem::new("Open", Some(Icon::Folder)), Act::Open);
            if !is_dir {
                let kind = classify(name);
                let list = openwith::candidates(name, kind, &self.handlers, self.browser);
                let current = openwith::default_target(name, kind, &self.handlers, &self.choices, self.browser);
                for (n, c) in list.iter().enumerate() {
                    let mut item = MenuItem::new(&format!("Open with {}", c.label), None);
                    if n == 0 {
                        item = item.separated();
                    }
                    add(&mut items, &mut acts, item, Act::With(c.target.clone()));
                }
                let ext = osyx_filekit::kind::extension(name).map_or(String::from("this type"), |x| format!(".{x}"));
                for c in list.iter().filter(|c| Some(&c.target) != current.as_ref()).take(3) {
                    add(&mut items, &mut acts, MenuItem::new(&format!("Always open {ext} with {}", c.label), None), Act::Default(c.target.clone()));
                }
            }
        } else if chosen.len() > 1 {
            let mut head = MenuItem::new(&format!("{} items selected", chosen.len()), None);
            head.enabled = false;
            add(&mut items, &mut acts, head, Act::Open);
        }
        if !chosen.is_empty() {
            add(&mut items, &mut acts, MenuItem::new("Copy", None).hint("Ctrl+C").separated(), Act::Copy);
            add(&mut items, &mut acts, MenuItem::new("Cut", None).hint("Ctrl+X"), Act::Cut);
        }
        let mut paste = MenuItem::new("Paste", None).hint("Ctrl+V");
        paste.enabled = has_clip;
        if chosen.is_empty() {
            paste = paste.separated();
        }
        add(&mut items, &mut acts, paste, Act::Paste);
        if !chosen.is_empty() {
            add(&mut items, &mut acts, MenuItem::new("Pack into a tar archive", None).hint("Ctrl+P").separated(), Act::Pack);
            if chosen.iter().any(|n| fileops::is_archive(n)) {
                add(&mut items, &mut acts, MenuItem::new("Extract here", None).hint("Ctrl+E"), Act::Extract);
            }
            if chosen.len() == 1 {
                add(&mut items, &mut acts, MenuItem::new("Rename", Some(Icon::Rename)).hint("F2").separated(), Act::Rename);
            }
            add(&mut items, &mut acts, MenuItem::new("Move to Trash", Some(Icon::Trash)).hint("Del").danger(), Act::Trash);
            if chosen.len() == 1 {
                add(&mut items, &mut acts, MenuItem::new("Properties", Some(Icon::Info)).hint("Ctrl+I"), Act::Info);
            }
        } else {
            add(&mut items, &mut acts, MenuItem::new("New folder", Some(Icon::NewFolder)).hint("Ctrl+N"), Act::NewFolder);
        }
        let mut menu = Menu::new(items);
        let (w, h) = menu.size(fonts);
        let (sw, sh) = self.size;
        let mx = x.min(sw as i32 - w as i32 - 4).max(4);
        let my = y.min(sh as i32 - h as i32 - 4).max(4);
        menu.rect = Rect::new(mx, my, w, h);
        self.menu = Some(ContextMenu { menu, acts });
    }

    fn do_act(&mut self, act: Act, cx: &mut Ctx) {
        let first = self.list.chosen().first().copied();
        match act {
            Act::Open => {
                if let Some(i) = first {
                    self.open(i, cx);
                }
            }
            Act::With(t) => {
                if let Some(name) = self.chosen_names().first() {
                    let path = join(&self.cwd, name);
                    self.run_target(&path, &t);
                }
            }
            Act::Default(t) => {
                if let Some(name) = self.chosen_names().first().cloned() {
                    let kind = classify(&name);
                    self.choices.set(&name, kind, t.clone());
                    self.save_choices();
                    let ext = osyx_filekit::kind::extension(&name).map_or(String::from("this type"), |x| format!(".{x}"));
                    println!("files: default for {ext} set");
                    self.set_status(format!("{ext} files now open with the chosen program"), false);
                }
            }
            Act::Copy => self.copy_selection(false, cx),
            Act::Cut => self.copy_selection(true, cx),
            Act::Paste => self.paste(cx),
            Act::Trash => self.trash_selection(),
            Act::Pack => self.pack_selection(),
            Act::Extract => self.extract_selection(),
            Act::Rename => self.tool(Tool::Rename, cx),
            Act::Info => self.tool(Tool::Info, cx),
            Act::NewFolder => self.tool(Tool::NewFolder, cx),
        }
        let (w, h) = self.size;
        self.layout_inner(w, h);
    }
}

fn remove_any(p: &str) -> Result<(), String> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        Ok(_) => fs::remove_file(p),
        Err(e) => Err(e),
    }
    .map_err(|e| e.to_string())
}

impl App for Files {
    fn layout(&mut self, w: u32, h: u32, _cx: &mut Ctx) {
        self.size = (w, h);
        self.layout_inner(w, h);
    }

    fn event(&mut self, ev: Ui, cx: &mut Ctx) -> bool {
        let fonts = cx.fonts;
        self.clipboard = cx.file_clipboard.clone();
        if let Ui::Key(k) = ev {
            self.mods = k.mods;
        }
        // The context menu takes everything while it is open.
        if let Some(cm) = &mut self.menu {
            match cm.menu.event(&ev) {
                Response::Activated(i) => {
                    let act = self.menu.take().and_then(|m| m.acts.get(i).cloned());
                    if let Some(a) = act {
                        self.do_act(a, cx);
                    }
                    return true;
                }
                Response::Cancelled => {
                    self.menu = None;
                    return true;
                }
                r => return r.needs_redraw() || !matches!(ev, Ui::PointerMove { .. }),
            }
        }
        // A dialog is modal.
        if let Some(d) = &mut self.dialog {
            let r = d.event_with_clipboard(&ev, &fonts, &mut cx.clipboard);
            match r {
                Response::Activated(b) => {
                    let (tag, input) = (d.tag, String::from(d.input_text()));
                    self.dialog = None;
                    let ok = b == 1 || (tag == D_INFO && b == 0);
                    if ok && tag != D_INFO {
                        self.dialog_done(tag, input);
                    }
                    let (w, h) = self.size;
                    self.layout_inner(w, h);
                    return true;
                }
                Response::Cancelled => {
                    self.dialog = None;
                    return true;
                }
                r => return r.needs_redraw(),
            }
        }
        if let Some(p) = &mut self.preview {
            let mut close = false;
            let mut redraw = p.view.event(&ev).needs_redraw();
            match p.close.event(&ev, false) {
                Response::Activated(_) => close = true,
                r => redraw |= r.needs_redraw(),
            }
            if let Ui::Key(k) = ev {
                if k.down {
                    match k.key {
                        key::ESCAPE | key::BACKSPACE => close = true,
                        key::DOWN => redraw |= p.view.scroll.scroll_by(20),
                        key::UP => redraw |= p.view.scroll.scroll_by(-20),
                        key::PAGE_DOWN => redraw |= p.view.scroll.scroll_by(p.view.rect.h as i64 - 40),
                        key::PAGE_UP => redraw |= p.view.scroll.scroll_by(-(p.view.rect.h as i64 - 40)),
                        key::HOME => redraw |= p.view.scroll.scroll_to(0),
                        key::END => redraw |= p.view.scroll.scroll_to(i64::MAX),
                        _ => {}
                    }
                }
            }
            if close {
                self.preview = None;
                let n = self.entries.len();
                self.set_status(format!("{n} items"), false);
                return true;
            }
            // The tool bar and side bar stay usable while previewing.
            if !matches!(ev, Ui::PointerDown { .. } | Ui::PointerUp { .. } | Ui::PointerMove { .. }) {
                return redraw;
            }
            if let Some((x, y)) = ev.position() {
                if contains(&p.view.rect, x, y) || contains(&p.close.rect, x, y) {
                    return redraw;
                }
            }
        }
        let mut redraw = false;
        // A drag that started on a row: follow the pointer and move the
        // entry when it is released over a folder row or a place.
        match ev {
            Ui::PointerMove { x, y } => {
                if let Some(b) = &mut self.band {
                    b.pointer = (x, y);
                    if (x - b.start.0).abs().max((y - b.start.1).abs()) > 4 {
                        b.moved = true;
                    }
                    let (y0, y1) = (b.start_content, self.list.content_y(y));
                    let rows = select::rows_in_band(y0, y1, self.list.row_height, self.entries.len());
                    self.list.set_marked(&rows);
                    return true;
                }
                if let Some(d) = &mut self.drag {
                    d.pointer = (x, y);
                    if (x - d.start.0).abs().max((y - d.start.1).abs()) > 5 {
                        d.moved = true;
                    }
                }
            }
            Ui::PointerUp { x, y, button: b } if b == button::LEFT => {
                if self.band.take().is_some() {
                    self.describe_selection();
                    return true;
                }
                if let Some(d) = self.drag.take() {
                    if !d.moved && self.list.marked().len() > 1 && self.mods & (modifier::CTRL | modifier::SHIFT) == 0 {
                        // A plain click inside a multi-selection selects that row only.
                        self.list.clear_marks();
                        self.list.select(Some(d.index));
                        return true;
                    }
                    if d.moved {
                        if let Some((target, label)) = self.drop_folder(x, y, d.index) {
                            let indexes: Vec<usize> = if self.list.is_marked(d.index) { self.list.marked() } else { vec![d.index] };
                            for i in indexes.into_iter().rev() {
                                self.move_entry(i, &target, &label);
                            }
                            let (w, h) = self.size;
                            self.layout_inner(w, h);
                        } else if let Some(entry) = self.entries.get(d.index) {
                            self.pending_move = Some((join(&self.cwd, &entry.name), Instant::now()));
                        }
                        return true;
                    }
                }
            }
            _ => {}
        }
        // Keyboard shortcuts.
        if let Ui::Key(k) = ev {
            if k.down {
                let tool = match k.key {
                    key::TAB => {
                        self.path_focus = !self.path_focus;
                        return true;
                    }
                    key::BACKSPACE if !self.path_focus => Some(Tool::Up),
                    key::LEFT if k.alt() => Some(Tool::Back),
                    0x3B if !self.path_focus => Some(Tool::Rename), // F2
                    0x3E => Some(Tool::Refresh),                    // F5
                    key::DELETE if !self.path_focus => Some(Tool::Delete),
                    key::A if k.ctrl() && !self.path_focus => {
                        self.list.mark_all();
                        self.describe_selection();
                        return true;
                    }
                    key::C if k.ctrl() && !self.path_focus => {
                        self.copy_selection(false, cx);
                        return true;
                    }
                    key::X if k.ctrl() && !self.path_focus => {
                        self.copy_selection(true, cx);
                        return true;
                    }
                    key::V if k.ctrl() && !self.path_focus => {
                        self.paste(cx);
                        return true;
                    }
                    key::P if k.ctrl() => {
                        self.pack_selection();
                        return true;
                    }
                    key::E if k.ctrl() => {
                        self.extract_selection();
                        return true;
                    }
                    key::N if k.ctrl() => Some(Tool::NewFolder),
                    key::I if k.ctrl() => Some(Tool::Info),
                    key::H if k.ctrl() => {
                        self.hidden.checked = !self.hidden.checked;
                        self.refresh();
                        return true;
                    }
                    _ => None,
                };
                if let Some(t) = tool {
                    self.tool(t, cx);
                    return true;
                }
            }
        }
        // Path field.
        match self.path.event_with_clipboard(&ev, self.path_focus, &fonts, &mut cx.clipboard) {
            Response::Submitted => {
                let target = String::from(self.path.text().trim());
                if self.navigate(&target, true) {
                    cx.title = Some(format!("Files — {}", self.cwd));
                    self.path_focus = false;
                }
                let (w, h) = self.size;
                self.layout_inner(w, h);
                return true;
            }
            Response::Cancelled => {
                let cwd = self.cwd.clone();
                self.path.set_text(&cwd);
                self.path_focus = false;
                return true;
            }
            r => redraw |= r.needs_redraw(),
        }
        if let Ui::PointerDown { x, y, .. } = ev {
            let in_path = contains(&self.path.rect, x, y);
            if in_path != self.path_focus {
                self.path_focus = in_path;
                redraw = true;
            }
        }
        // Tool bar.
        let mut pressed = None;
        for (t, b) in &mut self.tools {
            match b.event(&ev, false) {
                Response::Activated(_) => pressed = Some(*t),
                r => redraw |= r.needs_redraw(),
            }
        }
        if let Ui::PointerMove { x, y } = ev {
            let hint = self
                .tools
                .iter()
                .find(|(_, b)| contains(&b.rect, x, y))
                .and_then(|(t, _)| TOOLS.iter().find(|(tt, _, _)| tt == t))
                .map(|(_, _, h)| *h);
            if hint != self.hint {
                self.hint = hint;
                redraw = true;
            }
        }
        if let Some(t) = pressed {
            self.tool(t, cx);
            return true;
        }
        // Places.
        let rects = self.place_rects();
        match ev {
            Ui::PointerMove { x, y } => {
                let h = rects.iter().position(|r| contains(r, x, y));
                if h != self.place_hover {
                    self.place_hover = h;
                    redraw = true;
                }
            }
            Ui::PointerDown { x, y, button: b, .. } if b == button::LEFT => {
                if let Some(i) = rects.iter().position(|r| contains(r, x, y)) {
                    let target = self.places[i].1.clone();
                    self.preview = None;
                    if self.navigate(&target, true) {
                        cx.title = Some(format!("Files — {}", self.cwd));
                    }
                    let (w, h) = self.size;
                    self.layout_inner(w, h);
                    return true;
                }
            }
            _ => {}
        }
        if self.hidden.event(&ev, false) == Response::Changed {
            self.refresh();
            return true;
        }
        // Right click: the context menu (the row under the pointer joins the
        // selection unless it is already part of it).
        if let Ui::PointerDown { x, y, button: b, .. } = ev {
            if b == button::RIGHT && self.preview.is_none() && contains(&self.list.rect, x, y) {
                match self.list.row_at(x, y) {
                    Some(i) => {
                        if !self.list.is_marked(i) {
                            self.list.clear_marks();
                            self.list.select(Some(i));
                        }
                    }
                    None => {
                        self.list.clear_marks();
                        self.list.select(None);
                    }
                }
                self.open_context_menu(x, y, &fonts);
                return true;
            }
        }
        // A left press on a row: Ctrl toggles it, Shift selects a range,
        // otherwise it is a possible drag (the list also selects it).
        if let Ui::PointerDown { x, y, button: b, clicks } = ev {
            if b == button::LEFT && clicks == 1 && self.preview.is_none() {
                match self.list.row_at(x, y) {
                    Some(i) => {
                        let (ctrl, shift) = (self.mods & modifier::CTRL != 0, self.mods & modifier::SHIFT != 0);
                        if ctrl {
                            if self.list.marked().is_empty() {
                                if let Some(sel) = self.list.selected() {
                                    self.list.toggle_mark(sel);
                                }
                            }
                            self.list.toggle_mark(i);
                            self.list.select(Some(i));
                            self.anchor = Some(i);
                            self.describe_selection();
                            return true;
                        }
                        if shift {
                            let from = self.anchor.or(self.list.selected()).unwrap_or(i);
                            self.list.set_marked(&select::range(from, i));
                            self.list.select(Some(i));
                            self.describe_selection();
                            return true;
                        }
                        if !self.list.is_marked(i) {
                            self.list.clear_marks();
                        }
                        self.anchor = Some(i);
                        cx.drag_file = self.entries.get(i).map(|entry| join(&self.cwd, &entry.name));
                        self.drag = Some(FileDrag { index: i, start: (x, y), pointer: (x, y), moved: false });
                    }
                    None if self.list.in_body(x, y) && !self.entries.is_empty() => {
                        // Empty space: a rubber band.
                        if self.mods & (modifier::CTRL | modifier::SHIFT) == 0 {
                            self.list.clear_marks();
                        }
                        self.band = Some(Band { start: (x, y), pointer: (x, y), start_content: self.list.content_y(y), moved: false });
                    }
                    None => {}
                }
            }
        }
        // The list.
        match self.list.event(&ev, !self.path_focus) {
            Response::Activated(i) => {
                self.open(i, cx);
                let (w, h) = self.size;
                self.layout_inner(w, h);
                return true;
            }
            Response::Changed => {
                let (w, h) = self.size;
                self.layout_inner(w, h);
                if let Ui::Key(k) = ev {
                    // Arrow keys: Shift extends the range from the anchor, plain keys drop it.
                    if k.shift() {
                        if let (Some(a), Some(c)) = (self.anchor.or(self.list.selected()), self.list.selected()) {
                            self.list.set_marked(&select::range(a, c));
                        }
                    } else {
                        self.list.clear_marks();
                        self.anchor = self.list.selected();
                    }
                }
                if self.list.marked().len() > 1 {
                    self.describe_selection();
                    return true;
                }
                if let Some(e) = self.selected() {
                    let detail = e
                        .meta
                        .as_ref()
                        .map_or(String::new(), |m| format!(" — {}, {}", e.kind().0, human_size(m.len())));
                    let msg = format!("{}{}", e.name, detail);
                    self.set_status(msg, false);
                }
                redraw = true;
            }
            r => redraw |= r.needs_redraw(),
        }
        redraw
    }

    fn tick_ms(&self) -> Option<u64> { self.pending_move.as_ref().map(|_| 500) }

    fn tick(&mut self, _cx: &mut Ctx) -> bool {
        let Some((path, since)) = &self.pending_move else { return false };
        if fs::symlink_metadata(path).is_err_and(|e| e.kind() == os_std::error::ErrorKind::NotFound) {
            self.pending_move = None;
            self.refresh();
            return true;
        }
        if since.elapsed() >= Duration::from_secs(10) { self.pending_move = None; }
        false
    }

    fn file_drop(&mut self, path: &str, x: i32, y: i32, _cx: &mut Ctx) -> bool {
        if self.preview.is_some() || self.dialog.is_some() || !path.starts_with('/') { return false; }
        let name = path.rsplit('/').next().unwrap_or("");
        if name.is_empty() || name == "." || name == ".." { return false; }
        let target = self.list.row_at(x, y).and_then(|i| self.entries.get(i))
            .filter(|e| e.is_dir()).map(|e| join(&self.cwd, &e.name))
            .or_else(|| self.place_rects().iter().zip(&self.places).find(|(r, _)| contains(r, x, y)).map(|(_, p)| p.1.clone()))
            .or_else(|| contains(&self.list.rect, x, y).then(|| self.cwd.clone()));
        let Some(target) = target else { return false };
        let to = join(&target, name);
        if path == to || fs::symlink_metadata(&to).is_ok() {
            self.set_status(format!("Cannot move {name}: destination already exists"), true);
            return true;
        }
        let result = match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() => fs::rename(path, &to).or_else(|_| fs::copy(path, &to).map(|_| ()).and_then(|_| fs::remove_file(path))),
            Ok(_) => fs::rename(path, &to),
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => { self.refresh(); self.set_status(format!("Moved {name} to {target}"), false); }
            Err(e) => self.set_status(format!("Cannot move {name}: {e}"), true),
        }
        true
    }

    fn draw(&mut self, p: &mut Painter, w: u32, h: u32, cx: &Ctx) {
        let t = cx.theme;
        let full = Rect::new(0, 0, w, h);
        p.fill(full, t.window);
        let (bar, rest) = split_top(full, TOOLBAR);
        let (rest, status) = split_bottom(rest, STATUS);
        let (side, main) = split_left(rest, SIDEBAR);
        // Tool bar.
        p.fill(bar, t.surface);
        p.hline(0, bar.bottom() as i32 - 1, w, t.border);
        for (_, b) in &self.tools {
            b.draw(p, false);
        }
        self.path.draw(p, self.path_focus);
        // Side bar.
        p.fill(side, t.surface);
        p.vline(side.right() as i32 - 1, side.y, side.h, t.border);
        p.text(FontKind::Bold, side.x + 16, side.y + 14, "Places", t.text_dim);
        for (i, (r, (label, path, ic))) in self.place_rects().iter().zip(&self.places).enumerate() {
            let current = *path == self.cwd;
            if current {
                p.rounded(*r, t.radius_small, t.selection, 255);
            } else if self.place_hover == Some(i) {
                p.rounded(*r, t.radius_small, t.raised, 255);
            }
            icon::draw(p, *ic, Rect::new(r.x + 10, r.y + 7, 18, 18), if current { t.text } else { t.text_dim });
            p.text_in(FontKind::Ui, Rect::new(r.x + 38, r.y, r.w - 44, r.h), label, t.text, Align::Left);
        }
        self.hidden.draw(p, false);
        // Main area.
        match &self.preview {
            Some(pv) => {
                let (head, body) = split_top(main, 44);
                p.fill(head, t.surface);
                p.hline(head.x, head.bottom() as i32 - 1, head.w, t.border);
                icon::draw(
                    p,
                    if pv.hex { Icon::File } else { Icon::TextFile },
                    Rect::new(head.x + 14, head.y + 12, 20, 20),
                    t.text_dim,
                );
                p.text_in(
                    FontKind::Bold,
                    Rect::new(head.x + 44, head.y, head.w.saturating_sub(160), head.h),
                    &pv.path,
                    t.text,
                    Align::Left,
                );
                pv.close.draw(p, false);
                p.fill(body, t.field);
                let content = pv.view.content();
                let old = p.push_clip(content);
                let lh = 20;
                let first = pv.view.scroll.offset / lh;
                let rows = content.h / lh + 2;
                for i in first..(first + rows).min(pv.lines.len() as u32) {
                    let y = content.y + 10 + (i * lh) as i32 - pv.view.scroll.offset as i32;
                    p.text(FontKind::Mono, content.x + 14, y, &pv.lines[i as usize], t.text);
                }
                p.restore_clip(old);
                pv.view.draw_bar(p);
            }
            None => {
                if self.entries.is_empty() {
                    p.text_in(FontKind::Ui, main, "This folder is empty", t.text_faint, Align::Center);
                    if self.list.show_header {
                        // Keep the column headers for orientation.
                        self.list.draw(p, false);
                    }
                } else {
                    self.list.draw(p, !self.path_focus && cx.focused);
                }
            }
        }
        if let Some(b) = &self.band {
            if b.moved {
                let r = Rect::new(b.start.0.min(b.pointer.0), b.start.1.min(b.pointer.1), (b.start.0 - b.pointer.0).unsigned_abs(), (b.start.1 - b.pointer.1).unsigned_abs());
                p.blend(r, t.accent, 40);
                p.hline(r.x, r.y, r.w, t.accent);
                p.hline(r.x, r.bottom() as i32 - 1, r.w, t.accent);
                p.vline(r.x, r.y, r.h, t.accent);
                p.vline(r.right() as i32 - 1, r.y, r.h, t.accent);
            }
        }
        // Status bar.
        p.fill(status, t.surface);
        p.hline(0, status.y, w, t.border);
        let msg = self.hint.map(String::from).unwrap_or_else(|| self.status.clone());
        let c = if self.status_error && self.hint.is_none() { t.danger_hover } else { t.text_dim };
        p.text_in(FontKind::Ui, Rect::new(14, status.y, w - 28, status.h), &msg, c, Align::Left);
        if let Some(d) = &self.dialog {
            d.draw(p);
        }
        if let Some(m) = &self.menu {
            m.menu.draw(p);
        }
    }
}
