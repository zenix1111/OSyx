//! The removable drives popup of the desktop shell: every USB stick or disk
//! the kernel's media manager lists (`osyx_abi::media`), its volumes with
//! label, file system, size and use, an Open button (file manager) and an
//! Eject button (safe removal) per disk.
//!
//! [`rows`] places everything from the list alone, so drawing and hit
//! testing always agree.

use os_std::prelude::*;
use osyx_abi::media::{fs_name, Disk, DiskState, Size, Volume};
use osyx_gfx::Rect;
use osyx_ui::layout::contains;
use osyx_ui::{icon, Align, FontKind, Icon, Painter};

pub const WIDTH: u32 = 400;
const HEADER: i32 = 52;
const DISK_ROW: i32 = 58;
const VOLUME_ROW: i32 = 62;
const NOTE_ROW: i32 = 32;
const MESSAGE_ROW: i32 = 54;
const GAP: i32 = 8;
const MAX_HEIGHT: i32 = 560;
const PAD: i32 = 16;
const BUTTON_W: u32 = 76;
const BUTTON_H: u32 = 30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hit {
    /// Open the volume mounted at this path in the file manager.
    Open(String),
    /// Eject this disk.
    Eject(String),
}

/// What the popup shows.
pub struct View {
    pub disks: Vec<Disk>,
    /// (mount point, total bytes, free bytes) of the mounted volumes.
    pub usage: Vec<(String, u64, u64)>,
    /// Shown at the bottom: why an eject was refused, or a write error.
    pub message: String,
    /// Disks an eject was requested for and has not finished.
    pub ejecting: Vec<String>,
    pub hover: Option<Hit>,
}

enum Kind {
    Disk(usize),
    Volume(usize, usize),
    /// A disk with nothing to show under it: no volumes, or ejected.
    Note(usize),
}

struct Row {
    kind: Kind,
    rect: Rect,
    hit: Option<(Rect, Hit)>,
}

fn button(row: Rect, h: u32) -> Rect {
    Rect::new(row.right() as i32 - PAD - BUTTON_W as i32, row.y + (row.h as i32 - h as i32) / 2, BUTTON_W, h)
}

fn rows(disks: &[Disk]) -> (Vec<Row>, i32) {
    let mut out = Vec::new();
    let mut y = HEADER;
    for (di, d) in disks.iter().enumerate() {
        if di > 0 {
            y += GAP;
        }
        let rect = Rect::new(0, y, WIDTH, DISK_ROW as u32);
        let hit = (d.state == DiskState::Mounted).then(|| (button(rect, BUTTON_H), Hit::Eject(d.name.clone())));
        out.push(Row { kind: Kind::Disk(di), rect, hit });
        y += DISK_ROW;
        if d.state == DiskState::Ejected || d.volumes.is_empty() {
            out.push(Row { kind: Kind::Note(di), rect: Rect::new(0, y, WIDTH, NOTE_ROW as u32), hit: None });
            y += NOTE_ROW;
            continue;
        }
        for (vi, v) in d.volumes.iter().enumerate() {
            let rect = Rect::new(0, y, WIDTH, VOLUME_ROW as u32);
            let hit = v.mount.as_ref().map(|m| (button(rect, BUTTON_H - 2), Hit::Open(m.clone())));
            out.push(Row { kind: Kind::Volume(di, vi), rect, hit });
            y += VOLUME_ROW;
        }
    }
    (out, y)
}

/// Height of the popup for `disks`, with room for a message.
pub fn height(disks: &[Disk], message: bool) -> u32 {
    let (_, y) = rows(disks);
    (y + if message { MESSAGE_ROW } else { 0 } + 12).clamp(HEADER + NOTE_ROW + 12, MAX_HEIGHT) as u32
}

/// The button under (`x`, `y`).
pub fn hit(disks: &[Disk], x: i32, y: i32) -> Option<Hit> {
    rows(disks).0.into_iter().find_map(|r| r.hit.filter(|(rect, _)| contains(rect, x, y)).map(|(_, h)| h))
}

/// "exFAT, 12.1 GB free of 14.5 GB" for a mounted volume.
fn volume_detail(v: &Volume, usage: &[(String, u64, u64)]) -> String {
    let fs = fs_name(&v.fstype);
    let ro = if v.read_only { ", read-only" } else { "" };
    match v.mount.as_ref().and_then(|m| usage.iter().find(|u| &u.0 == m)) {
        Some(&(_, total, free)) if total > 0 => format!("{fs}, {} free of {}{ro}", Size(free), Size(total)),
        _ if v.mount.is_some() => format!("{fs}, {}{ro}", Size(v.bytes)),
        _ => format!("{fs}, {} (not mounted)", Size(v.bytes)),
    }
}

pub fn draw(p: &mut Painter, view: &View) {
    let t = *p.theme;
    p.text(FontKind::Large, 20, 16, "Removable drives", t.text);
    let (rows, end) = rows(&view.disks);
    let lh = p.fonts.line_height(FontKind::Bold) as i32;
    let ul = p.fonts.line_height(FontKind::Ui) as i32;
    for row in &rows {
        match row.kind {
            Kind::Disk(di) => {
                let d = &view.disks[di];
                p.hline(12, row.rect.y - 1, WIDTH - 24, t.border);
                let ic = Rect::new(PAD, row.rect.y + (DISK_ROW - 30) / 2, 30, 30);
                icon::draw(p, Icon::Drive, ic, if d.state == DiskState::Ejected { t.text_faint } else { t.text });
                let tx = PAD + 42;
                let width = (row.rect.w as i32 - tx - BUTTON_W as i32 - 2 * PAD).max(40) as u32;
                let title = if d.model.is_empty() { "USB drive" } else { d.model.as_str() };
                p.text_in(FontKind::Bold, Rect::new(tx, row.rect.y + 9, width, lh as u32), title, t.text, Align::Left);
                let (sub, color) = match d.state {
                    DiskState::Ejected => (String::from("Safe to remove"), t.success),
                    DiskState::Mounted => (Size(d.bytes).to_string(), t.text_dim),
                };
                p.text_in(FontKind::Ui, Rect::new(tx, row.rect.y + 9 + lh, width, ul as u32), &sub, color, Align::Left);
                if let Some((r, h)) = &row.hit {
                    let busy = view.ejecting.contains(&d.name);
                    let hovered = view.hover.as_ref() == Some(h) && !busy;
                    p.rounded(*r, t.radius_small, if hovered { t.selection } else { t.raised }, 255);
                    p.text_in(FontKind::Ui, *r, if busy { "Ejecting..." } else { "Eject" }, if busy { t.text_faint } else { t.text }, Align::Center);
                }
            }
            Kind::Volume(di, vi) => {
                let v = &view.disks[di].volumes[vi];
                let tx = PAD + 42;
                let width = (row.rect.w as i32 - tx - BUTTON_W as i32 - 2 * PAD).max(40) as u32;
                p.text_in(FontKind::Bold, Rect::new(tx, row.rect.y + 6, width, lh as u32), v.name(), t.text, Align::Left);
                p.text_in(FontKind::Ui, Rect::new(tx, row.rect.y + 6 + lh, width, ul as u32), &volume_detail(v, &view.usage), t.text_dim, Align::Left);
                // Use of the volume.
                if let Some(&(_, total, free)) = v.mount.as_ref().and_then(|m| view.usage.iter().find(|u| &u.0 == m)) {
                    if total > 0 {
                        let track = Rect::new(tx, row.rect.y + 6 + lh + ul + 5, width, 6);
                        p.rounded(track, 3, t.raised, 255);
                        let used = total.saturating_sub(free);
                        let w = ((track.w as u64 * used / total) as u32).max(if used > 0 { 4 } else { 0 });
                        if w > 0 {
                            let color = if used * 10 >= total * 9 { t.warning } else { t.accent };
                            p.rounded(Rect::new(track.x, track.y, w, track.h), 3, color, 255);
                        }
                    }
                }
                if let Some((r, h)) = &row.hit {
                    let hovered = view.hover.as_ref() == Some(h);
                    p.rounded(*r, t.radius_small, if hovered { t.accent_hover } else { t.accent }, 255);
                    p.text_in(FontKind::Ui, *r, "Open", t.on_accent, Align::Center);
                }
            }
            Kind::Note(di) => {
                let d = &view.disks[di];
                let text = if d.state == DiskState::Ejected {
                    "You can unplug it now."
                } else {
                    "No supported file system (FAT32, exFAT or ext4)."
                };
                p.text_in(FontKind::Ui, Rect::new(PAD + 42, row.rect.y, WIDTH - 2 * PAD as u32 - 42, row.rect.h), text, t.text_faint, Align::Left);
            }
        }
    }
    if rows.is_empty() {
        p.text_in(FontKind::Ui, Rect::new(0, HEADER, WIDTH, 60), "No removable drives", t.text_faint, Align::Center);
    }
    if !view.message.is_empty() {
        let y = end.max(HEADER + 60);
        p.hline(12, y, WIDTH - 24, t.border);
        let lines = osyx_ui::widget::wrap_text(p.fonts, FontKind::Ui, &view.message, WIDTH - 2 * PAD as u32);
        for (i, l) in lines.iter().take(2).enumerate() {
            p.text(FontKind::Ui, PAD, y + 10 + i as i32 * ul, l, t.warning);
        }
    }
}

/// The text of the "connected" notification.
pub fn connected_text(d: &Disk) -> (String, String) {
    let name = d.volumes.iter().find(|v| v.mount.is_some()).map_or_else(
        || if d.model.is_empty() { String::from("USB drive") } else { d.model.clone() },
        |v| String::from(v.name()),
    );
    let mounted: Vec<&Volume> = d.volumes.iter().filter(|v| v.mount.is_some()).collect();
    let body = match mounted.as_slice() {
        [] => String::from("No supported file system (FAT32, exFAT or ext4), so it was not mounted."),
        [v] => format!("{}, {}. Open it from the drives button in the task bar.", fs_name(&v.fstype), Size(v.bytes)),
        many => format!("{} volumes mounted. Open them from the drives button in the task bar.", many.len()),
    };
    (format!("{name} connected"), body)
}
