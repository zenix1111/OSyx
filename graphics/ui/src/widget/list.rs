use super::scroll::{Scroll, BAR};
use crate::event::{Event, Response};
use crate::icon::{self, Icon};
use crate::layout::{contains, split_right, split_top};
use crate::paint::{Align, FontKind, Painter};
use alloc::string::String;
use alloc::vec::Vec;
use osyx_gfx::Rect;
use osyx_input::{button, key};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub title: String,
    /// Fixed width in pixels; 0 = takes the remaining width (one column).
    pub width: u32,
    pub align: Align,
}

impl Column {
    pub fn new(title: &str, width: u32, align: Align) -> Column {
        Column { title: String::from(title), width, align }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListItem {
    pub icon: Option<Icon>,
    /// One text per column (the first one next to the icon).
    pub cells: Vec<String>,
    /// Drawn dimmed (e.g. a zombie process).
    pub dim: bool,
}

impl ListItem {
    pub fn new(icon: Option<Icon>, cells: &[&str]) -> ListItem {
        ListItem { icon, cells: cells.iter().map(|s| String::from(*s)).collect(), dim: false }
    }
}

/// A scrolling list of rows with optional column headers, single selection,
/// keyboard navigation and activation (double click or Enter).
#[derive(Clone, Debug)]
pub struct ListView {
    pub rect: Rect,
    pub columns: Vec<Column>,
    pub show_header: bool,
    pub row_height: u32,
    items: Vec<ListItem>,
    selected: Option<usize>,
    /// Rows marked in addition to the selected one (multi-selection); the
    /// caller decides when to mark (Ctrl, Shift, a rubber band).
    marked: Vec<bool>,
    hovered: Option<usize>,
    pub scroll: Scroll,
    /// Row pressed and not yet released (activation needs press + release).
    pressed: Option<usize>,
}

const HEADER: u32 = 28;

impl ListView {
    pub fn new(columns: Vec<Column>) -> ListView {
        let show_header = columns.len() > 1;
        ListView {
            rect: Rect::EMPTY,
            columns,
            show_header,
            row_height: 30,
            items: Vec::new(),
            selected: None,
            marked: Vec::new(),
            hovered: None,
            scroll: Scroll::default(),
            pressed: None,
        }
    }

    pub fn items(&self) -> &[ListItem] {
        &self.items
    }

    /// Replaces the rows, keeping the selection index if still valid.
    pub fn set_items(&mut self, items: Vec<ListItem>) {
        self.items = items;
        self.marked.clear();
        self.marked.resize(self.items.len(), false);
        if self.selected.is_some_and(|s| s >= self.items.len()) {
            self.selected = if self.items.is_empty() { None } else { Some(self.items.len() - 1) };
        }
        self.hovered = None;
        self.update_scroll();
    }

    pub fn selected(&self) -> Option<usize> {
        self.selected
    }

    /// The marked rows, in order.
    pub fn marked(&self) -> Vec<usize> {
        self.marked.iter().enumerate().filter(|(_, m)| **m).map(|(i, _)| i).collect()
    }

    pub fn is_marked(&self, i: usize) -> bool {
        self.marked.get(i).copied().unwrap_or(false)
    }

    /// The marked rows, or the selected row if none is marked.
    pub fn chosen(&self) -> Vec<usize> {
        let m = self.marked();
        if m.is_empty() {
            self.selected.into_iter().collect()
        } else {
            m
        }
    }

    pub fn toggle_mark(&mut self, i: usize) {
        if let Some(m) = self.marked.get_mut(i) {
            *m = !*m;
        }
    }

    /// Marks exactly the rows in `rows`.
    pub fn set_marked(&mut self, rows: &[usize]) {
        self.marked.iter_mut().for_each(|m| *m = false);
        for &i in rows {
            if let Some(m) = self.marked.get_mut(i) {
                *m = true;
            }
        }
    }

    pub fn clear_marks(&mut self) {
        self.marked.iter_mut().for_each(|m| *m = false);
    }

    pub fn mark_all(&mut self) {
        self.marked.iter_mut().for_each(|m| *m = true);
    }

    pub fn select(&mut self, i: Option<usize>) {
        self.selected = i.filter(|&i| i < self.items.len());
        if let Some(i) = self.selected {
            self.update_scroll();
            self.scroll.ensure_visible(i as u32 * self.row_height, self.row_height);
        }
    }

    fn body(&self) -> Rect {
        if self.show_header {
            split_top(self.rect, HEADER).1
        } else {
            self.rect
        }
    }

    fn track(&self) -> Rect {
        split_right(self.body(), BAR).1
    }

    fn rows_area(&self) -> Rect {
        let b = self.body();
        if self.scroll.needed() {
            split_right(b, BAR + 2).0
        } else {
            b
        }
    }

    fn update_scroll(&mut self) {
        let h = self.body().h;
        self.scroll.set_sizes(self.items.len() as u32 * self.row_height, h);
    }

    /// The row under (`x`, `y`), if any.
    pub fn row_at(&self, x: i32, y: i32) -> Option<usize> {
        let area = self.rows_area();
        if !contains(&area, x, y) {
            return None;
        }
        let i = ((y - area.y) as u32 + self.scroll.offset) / self.row_height;
        ((i as usize) < self.items.len()).then_some(i as usize)
    }

    /// Whether (`x`, `y`) is in the rows area (below the header).
    pub fn in_body(&self, x: i32, y: i32) -> bool {
        contains(&self.body(), x, y)
    }

    /// `y` as a distance from the top of the first row (scrolling included),
    /// for rubber-band selection; negative above the first row.
    pub fn content_y(&self, y: i32) -> i32 {
        y - self.body().y + self.scroll.offset as i32
    }

    /// Column cells of a row: (x, width) for each column.
    fn column_spans(&self, area: Rect) -> Vec<(i32, u32)> {
        let fixed: u32 = self.columns.iter().map(|c| c.width).sum();
        let gaps = 12 * self.columns.len().saturating_sub(1) as u32;
        let flex = area.w.saturating_sub(fixed + gaps + 24);
        let mut x = area.x + 12;
        self.columns
            .iter()
            .map(|c| {
                let w = if c.width == 0 { flex } else { c.width };
                let span = (x, w);
                x += w as i32 + 12;
                span
            })
            .collect()
    }

    pub fn event(&mut self, ev: &Event, focused: bool) -> Response {
        self.update_scroll();
        let track = self.track();
        let body = self.body();
        let r = self.scroll.event(ev, track, body);
        if r.handled() && !matches!(ev, Event::PointerMove { .. }) {
            return r;
        }
        let scrolled = r.needs_redraw();
        let resp = match *ev {
            Event::PointerMove { x, y } => {
                let h = if self.scroll.is_dragging() { None } else { self.row_at(x, y) };
                if h != self.hovered {
                    self.hovered = h;
                    Response::Redraw
                } else {
                    Response::Ignored
                }
            }
            Event::PointerLeave => {
                self.pressed = None;
                if self.hovered.take().is_some() {
                    Response::Redraw
                } else {
                    Response::Ignored
                }
            }
            Event::PointerDown { x, y, button: b, clicks } if contains(&body, x, y) => match self.row_at(x, y) {
                Some(i) => {
                    let changed = self.selected != Some(i);
                    self.selected = Some(i);
                    if b == button::LEFT && clicks >= 2 {
                        self.pressed = None;
                        return Response::Activated(i);
                    }
                    self.pressed = Some(i);
                    if changed {
                        Response::Changed
                    } else {
                        Response::Consumed
                    }
                }
                None => {
                    if self.selected.take().is_some() {
                        Response::Changed
                    } else {
                        Response::Consumed
                    }
                }
            },
            Event::PointerUp { .. } => {
                self.pressed = None;
                Response::Ignored
            }
            Event::Key(k) if focused && k.down => {
                let n = self.items.len();
                if n == 0 {
                    return Response::Ignored;
                }
                let page = (self.body().h / self.row_height).max(1) as usize;
                let cur = self.selected;
                let next = match k.key {
                    key::DOWN => Some(cur.map_or(0, |c| (c + 1).min(n - 1))),
                    key::UP => Some(cur.map_or(0, |c| c.saturating_sub(1))),
                    key::PAGE_DOWN => Some(cur.map_or(0, |c| (c + page).min(n - 1))),
                    key::PAGE_UP => Some(cur.map_or(0, |c| c.saturating_sub(page))),
                    key::HOME => Some(0),
                    key::END => Some(n - 1),
                    key::ENTER | key::KP_ENTER => return cur.map_or(Response::Ignored, Response::Activated),
                    _ => None,
                };
                match next {
                    Some(i) => {
                        self.select(Some(i));
                        if cur != Some(i) {
                            Response::Changed
                        } else {
                            Response::Consumed
                        }
                    }
                    None => Response::Ignored,
                }
            }
            _ => Response::Ignored,
        };
        if scrolled && !resp.needs_redraw() {
            Response::Redraw
        } else {
            resp
        }
    }

    pub fn draw(&self, p: &mut Painter, focused: bool) {
        let t = *p.theme;
        let mut s = self.scroll;
        s.set_sizes(self.items.len() as u32 * self.row_height, self.body().h);
        let area = self.rows_area();
        let spans = self.column_spans(area);
        if self.show_header {
            let hr = split_top(self.rect, HEADER).0;
            p.fill(hr, t.surface);
            p.hline(hr.x, hr.bottom() as i32 - 1, hr.w, t.border);
            for (c, (x, w)) in self.columns.iter().zip(&spans) {
                p.text_in(FontKind::Bold, Rect::new(*x, hr.y, *w, hr.h), &c.title, t.text_dim, c.align);
            }
        }
        let old = p.push_clip(self.body());
        let first = (s.offset / self.row_height) as usize;
        let visible = (area.h / self.row_height + 2) as usize;
        for i in first..(first + visible).min(self.items.len()) {
            let y = area.y + (i as u32 * self.row_height) as i32 - s.offset as i32;
            let row = Rect::new(area.x + 4, y + 1, area.w.saturating_sub(8), self.row_height - 2);
            if self.is_marked(i) || self.selected == Some(i) {
                p.rounded(row, t.radius_small, if focused { t.selection } else { osyx_gfx::lerp(t.raised, t.selection, 100) }, 255);
            } else if self.hovered == Some(i) {
                p.rounded(row, t.radius_small, t.raised, 255);
            }
            let item = &self.items[i];
            let color = if item.dim { t.text_faint } else { t.text };
            for (ci, (x, w)) in spans.iter().enumerate() {
                let Some(text) = item.cells.get(ci) else { continue };
                let mut cell = Rect::new(*x, row.y, *w, row.h);
                if ci == 0 {
                    if let Some(ic) = item.icon {
                        let size = 18.min(row.h - 4);
                        icon::draw(p, ic, Rect::new(cell.x, row.y + (row.h as i32 - size as i32) / 2, size, size), t.text_dim);
                        cell = Rect::new(cell.x + size as i32 + 10, cell.y, cell.w.saturating_sub(size + 10), cell.h);
                    }
                }
                let align = self.columns.get(ci).map_or(Align::Left, |c| c.align);
                let c = if ci == 0 { color } else { t.text_dim };
                p.text_in(FontKind::Ui, cell, text, c, align);
            }
        }
        p.restore_clip(old);
        s.draw(p, self.track());
    }
}
