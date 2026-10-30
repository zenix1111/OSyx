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

#![no_std]
#![no_main]

#[path = "../shell_common.rs"]
mod common;

use common::{become_user, human_size, run_app, system_tz, App, Ctx, USER_HOME};
use os_std::fs::{self, Metadata};
use os_std::prelude::*;
use os_std::process::Command;
use os_std::time::{Duration, Instant};
use os_std::{env, system, thread};
use osyx_gfx::Rect;
use osyx_input::{button, key};
use osyx_ui::layout::{contains, inset, split_bottom, split_left, split_top};
use osyx_ui::time::Tz;
use osyx_ui::widget::{Button, ButtonStyle, Checkbox, Column, Dialog, ListItem, ListView, ScrollView, TextField};
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

/// Mounted volumes other than `/` for the side bar.
fn volume_places() -> Vec<(String, String, Icon)> {
    let Ok(mounts) = system::mounts() else { return Vec::new() };
    mounts
        .iter()
        .map(|m| (system::field_str(&m.path), system::field_str(&m.fstype)))
        .filter(|(path, _)| *path != "/")
        .map(|(path, fstype)| (format!("{path} ({fstype})"), String::from(path), Icon::Drive))
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
        } else if [".txt", ".md", ".rs", ".ax", ".toml", ".conf", ".app", ".log", ".sh", ".py"]
            .iter()
            .any(|e| self.name.ends_with(e))
            || !self.name.contains('.')
        {
            ("Text document", Icon::TextFile)
        } else {
            ("File", Icon::File)
        }
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
        } else if e.is_program()
            || is_win_program(&e.name)
            || e.name.ends_with(".app")
            || [".html", ".htm", ".xhtml", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"].iter().any(|ext| e.name.to_ascii_lowercase().ends_with(ext))
        {
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
            } else if e.name.ends_with(".app") {
                self.set_status(format!("Invalid application shortcut: {path}"), true);
                return;
            } else {
                let mut c = Command::new("/bin/open");
                c.arg(&path);
                c
            };
            match command.spawn() {
                Ok(child) => {
                    let pid = child.id();
                    self.set_status(format!("Started {} as process {pid}", e.name), false);
                    println!("files: started program {path} as process {pid}");
                    thread::spawn(move || {
                        let _ = child.wait();
                    });
                }
                Err(err) => self.set_status(format!("Cannot start {path}: {err}"), true),
            }
        } else {
            self.preview(path);
        }
    }

    fn preview(&mut self, path: String) {
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                self.set_status(format!("Cannot open {path}: {e}"), true);
                return;
            }
        };
        let shown = &data[..data.len().min(PREVIEW_LIMIT)];
        let text = core::str::from_utf8(shown).ok().filter(|t| !t.contains('\0'));
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
            Tool::Delete => {
                if let Some(e) = self.selected() {
                    let name = e.name.clone();
                    // Outside the Trash a delete is a move into it.
                    let reason = if self.in_trash() {
                        String::new()
                    } else {
                        match self.move_to_trash(&name) {
                            Ok(msg) => {
                                println!("files: {msg}");
                                self.refresh();
                                self.set_status(msg, false);
                                return;
                            }
                            Err(why) => format!(" It cannot go to the Trash ({why})."),
                        }
                    };
                    let Some(e) = self.selected() else { return };
                    let what = if e.is_dir() { "the folder" } else { "the file" };
                    let msg = format!(
                        "Delete {what} \"{}\" permanently? This cannot be undone.{}{reason}",
                        e.name,
                        if e.is_dir() { " Everything inside it is deleted too." } else { "" }
                    );
                    self.dialog = Some(Dialog::new(
                        D_DELETE,
                        "Delete",
                        &msg,
                        &[("Cancel", ButtonStyle::Secondary), ("Delete", ButtonStyle::Danger)],
                    ));
                }
            }
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
            D_DELETE => match sel {
                Some(name) => {
                    let p = join(&self.cwd, &name);
                    let r = match fs::symlink_metadata(&p) {
                        Ok(m) if m.is_dir() => fs::remove_dir_all(&p),
                        Ok(_) => fs::remove_file(&p),
                        Err(e) => Err(e),
                    };
                    if r.is_ok() && self.in_trash() {
                        let _ = fs::remove_file(format!("{TRASH}/info/{name}.trashinfo"));
                    }
                    r.map(|_| format!("Deleted {p}")).map_err(|e| format!("Cannot delete {p}: {e}"))
                }
                None => return,
            },
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
                Tool::Rename | Tool::Delete | Tool::Info => selected,
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

impl App for Files {
    fn layout(&mut self, w: u32, h: u32, _cx: &mut Ctx) {
        self.size = (w, h);
        self.layout_inner(w, h);
    }

    fn event(&mut self, ev: Ui, cx: &mut Ctx) -> bool {
        let fonts = cx.fonts;
        // A dialog is modal.
        if let Some(d) = &mut self.dialog {
            let r = d.event(&ev, &fonts);
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
                if let Some(d) = &mut self.drag {
                    d.pointer = (x, y);
                    if (x - d.start.0).abs().max((y - d.start.1).abs()) > 5 {
                        d.moved = true;
                    }
                }
            }
            Ui::PointerUp { x, y, button: b } if b == button::LEFT => {
                if let Some(d) = self.drag.take() {
                    if d.moved {
                        if let Some((target, label)) = self.drop_folder(x, y, d.index) {
                            self.move_entry(d.index, &target, &label);
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
        match self.path.event(&ev, self.path_focus, &fonts) {
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
        // A left press on a row is a possible drag (the list also selects it).
        if let Ui::PointerDown { x, y, button: b, clicks } = ev {
            if b == button::LEFT && clicks == 1 && self.preview.is_none() {
                if let Some(i) = self.list.row_at(x, y) {
                    cx.drag_file = self.entries.get(i).map(|entry| join(&self.cwd, &entry.name));
                    self.drag = Some(FileDrag { index: i, start: (x, y), pointer: (x, y), moved: false });
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
        // Status bar.
        p.fill(status, t.surface);
        p.hline(0, status.y, w, t.border);
        let msg = self.hint.map(String::from).unwrap_or_else(|| self.status.clone());
        let c = if self.status_error && self.hint.is_none() { t.danger_hover } else { t.text_dim };
        p.text_in(FontKind::Ui, Rect::new(14, status.y, w - 28, status.h), &msg, c, Align::Left);
        if let Some(d) = &self.dialog {
            d.draw(p);
        }
    }
}
