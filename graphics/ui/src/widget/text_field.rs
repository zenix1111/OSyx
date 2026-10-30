use crate::event::{Event, KeyEvent, Response};
use crate::clipboard::Clipboard;
use crate::layout::{contains, inset_xy};
use crate::paint::{Align, FontKind, Fonts, Painter};
use alloc::string::String;
use osyx_gfx::Rect;
use osyx_input::{button, key};

/// A single-line text input with a cursor, selection and horizontal scrolling.
#[derive(Clone, Debug)]
pub struct TextField {
    pub rect: Rect,
    pub placeholder: String,
    pub font: FontKind,
    text: String,
    /// Byte index of the cursor (always a character boundary).
    cursor: usize,
    /// Other end of the selection, if any.
    anchor: Option<usize>,
    /// Pixels of text scrolled out on the left.
    scroll: u32,
    hovered: bool,
    dragging: bool,
    /// Longest accepted text (bytes).
    pub max_len: usize,
    /// Shows every character as a bullet (passwords).
    pub masked: bool,
}

const PAD: u32 = 10;

impl TextField {
    pub fn new(text: &str) -> TextField {
        TextField {
            rect: Rect::EMPTY,
            placeholder: String::new(),
            font: FontKind::Ui,
            text: String::from(text),
            cursor: text.len(),
            anchor: None,
            scroll: 0,
            hovered: false,
            dragging: false,
            max_len: 1024,
            masked: false,
        }
    }

    /// The text as drawn: bullets when masked.
    fn shown(&self, end: usize) -> String {
        if self.masked {
            self.text[..end].chars().map(|_| '*').collect()
        } else {
            String::from(&self.text[..end])
        }
    }

    /// Byte index in `text` of the position at byte `i` of [`Self::shown`].
    fn index_of_shown(&self, i: usize) -> usize {
        if self.masked {
            self.text.char_indices().nth(i).map_or(self.text.len(), |(b, _)| b)
        } else {
            i
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The selected byte range, if any.
    pub fn selection(&self) -> Option<(usize, usize)> {
        let a = self.anchor?;
        if a == self.cursor {
            return None;
        }
        Some((a.min(self.cursor), a.max(self.cursor)))
    }

    pub fn set_text(&mut self, s: &str) {
        self.text = String::from(s);
        self.cursor = self.text.len();
        self.anchor = None;
        self.scroll = 0;
    }

    pub fn select_all(&mut self) {
        self.anchor = Some(0);
        self.cursor = self.text.len();
    }

    fn inner(&self) -> Rect {
        inset_xy(self.rect, PAD, 0)
    }

    fn prev_boundary(&self, i: usize) -> usize {
        self.text[..i].char_indices().next_back().map_or(0, |(p, _)| p)
    }

    fn next_boundary(&self, i: usize) -> usize {
        self.text[i..].chars().next().map_or(i, |c| i + c.len_utf8())
    }

    fn word_left(&self, i: usize) -> usize {
        let mut p = i;
        while p > 0 && self.text[..p].ends_with(' ') {
            p = self.prev_boundary(p);
        }
        while p > 0 && !self.text[..p].ends_with(' ') {
            p = self.prev_boundary(p);
        }
        p
    }

    fn word_right(&self, i: usize) -> usize {
        let mut p = i;
        while p < self.text.len() && self.text[p..].starts_with(' ') {
            p = self.next_boundary(p);
        }
        while p < self.text.len() && !self.text[p..].starts_with(' ') {
            p = self.next_boundary(p);
        }
        p
    }

    fn delete_selection(&mut self) -> bool {
        if let Some((a, b)) = self.selection() {
            self.text.replace_range(a..b, "");
            self.cursor = a;
            self.anchor = None;
            return true;
        }
        self.anchor = None;
        false
    }

    /// Inserts `s` at the cursor (replacing the selection).
    pub fn insert(&mut self, s: &str) {
        self.delete_selection();
        let room = self.max_len.saturating_sub(self.text.len());
        let mut end = s.len().min(room);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        self.text.insert_str(self.cursor, &s[..end]);
        self.cursor += end;
    }

    fn move_to(&mut self, pos: usize, extend: bool) {
        if extend {
            if self.anchor.is_none() {
                self.anchor = Some(self.cursor);
            }
        } else {
            self.anchor = None;
        }
        self.cursor = pos;
    }

    /// Keeps the cursor inside the visible part of the field.
    fn ensure_visible(&mut self, fonts: &Fonts) {
        let w = self.inner().w;
        let x = fonts.measure(self.font, &self.shown(self.cursor));
        if x < self.scroll {
            self.scroll = x;
        } else if x > self.scroll + w.saturating_sub(2) {
            self.scroll = x - w.saturating_sub(2);
        }
        let total = fonts.measure(self.font, &self.shown(self.text.len()));
        if total < self.scroll + w {
            self.scroll = total.saturating_sub(w.saturating_sub(2));
        }
    }

    fn hit(&self, fonts: &Fonts, x: i32) -> usize {
        self.index_of_shown(fonts.hit(self.font, &self.shown(self.text.len()), x - self.inner().x + self.scroll as i32))
    }

    fn key(&mut self, k: &KeyEvent) -> Response {
        if !k.down {
            return Response::Ignored;
        }
        let shift = k.shift();
        let ctrl = k.ctrl();
        let len = self.text.len();
        match k.key {
            key::ENTER | key::KP_ENTER => return Response::Submitted,
            key::ESCAPE => return Response::Cancelled,
            key::LEFT => {
                let p = if !shift && self.selection().is_some() {
                    self.selection().map_or(0, |s| s.0)
                } else if ctrl {
                    self.word_left(self.cursor)
                } else {
                    self.prev_boundary(self.cursor)
                };
                self.move_to(p, shift);
                return Response::Redraw;
            }
            key::RIGHT => {
                let p = if !shift && self.selection().is_some() {
                    self.selection().map_or(len, |s| s.1)
                } else if ctrl {
                    self.word_right(self.cursor)
                } else {
                    self.next_boundary(self.cursor)
                };
                self.move_to(p, shift);
                return Response::Redraw;
            }
            key::HOME => {
                self.move_to(0, shift);
                return Response::Redraw;
            }
            key::END => {
                self.move_to(len, shift);
                return Response::Redraw;
            }
            key::BACKSPACE => {
                if !self.delete_selection() && self.cursor > 0 {
                    let from = if ctrl { self.word_left(self.cursor) } else { self.prev_boundary(self.cursor) };
                    self.text.replace_range(from..self.cursor, "");
                    self.cursor = from;
                }
                return Response::Changed;
            }
            key::DELETE => {
                if !self.delete_selection() && self.cursor < len {
                    let to = if ctrl { self.word_right(self.cursor) } else { self.next_boundary(self.cursor) };
                    self.text.replace_range(self.cursor..to, "");
                }
                return Response::Changed;
            }
            key::A if ctrl => {
                self.select_all();
                return Response::Redraw;
            }
            _ => {}
        }
        if let Some(c) = k.insertable() {
            let mut b = [0u8; 4];
            self.insert(c.encode_utf8(&mut b));
            return Response::Changed;
        }
        Response::Ignored
    }

    pub fn event(&mut self, ev: &Event, focused: bool, fonts: &Fonts) -> Response {
        let r = match *ev {
            Event::PointerMove { x, y } => {
                if self.dragging {
                    let p = self.hit(fonts, x);
                    if p != self.cursor {
                        self.cursor = p;
                        Response::Redraw
                    } else {
                        Response::Consumed
                    }
                } else {
                    let h = contains(&self.rect, x, y);
                    if h != self.hovered {
                        self.hovered = h;
                        Response::Redraw
                    } else {
                        Response::Ignored
                    }
                }
            }
            Event::PointerLeave => {
                self.hovered = false;
                Response::Ignored
            }
            Event::PointerDown { x, y, button: b, clicks } if b == button::LEFT && contains(&self.rect, x, y) => {
                if clicks >= 2 {
                    self.select_all();
                } else {
                    let p = self.hit(fonts, x);
                    self.anchor = Some(p);
                    self.cursor = p;
                    self.dragging = true;
                }
                Response::Redraw
            }
            Event::PointerUp { .. } if self.dragging => {
                self.dragging = false;
                Response::Consumed
            }
            Event::Key(k) if focused => self.key(&k),
            _ => Response::Ignored,
        };
        if r.needs_redraw() {
            self.ensure_visible(fonts);
        }
        r
    }

    /// Handles text clipboard shortcuts before the regular editing keys.
    pub fn event_with_clipboard(&mut self, ev: &Event, focused: bool, fonts: &Fonts, clipboard: &mut Clipboard) -> Response {
        if let Event::Key(k) = ev {
            if focused && k.down && k.ctrl() {
                match k.key {
                    key::C | key::X => {
                        if !self.masked {
                            if let Some((a, b)) = self.selection() {
                                clipboard.set(&self.text[a..b]);
                                if k.key == key::X {
                                    self.delete_selection();
                                    self.ensure_visible(fonts);
                                    return Response::Changed;
                                }
                            }
                        }
                        return Response::Consumed;
                    }
                    key::V => {
                        if let Some(text) = clipboard.text() {
                            // A single-line field must not insert control characters.
                            let text: String = text.chars().filter(|c| !c.is_control()).collect();
                            self.insert(&text);
                            self.ensure_visible(fonts);
                            return Response::Changed;
                        }
                        return Response::Consumed;
                    }
                    _ => {}
                }
            }
        }
        self.event(ev, focused, fonts)
    }

    pub fn draw(&self, p: &mut Painter, focused: bool) {
        let t = *p.theme;
        let border = if focused {
            t.accent
        } else if self.hovered {
            t.scrollbar_hover
        } else {
            t.field_border
        };
        p.card(self.rect, t.radius_small, t.field, border);
        let inner = self.inner();
        let old = p.push_clip(inner);
        let lh = p.fonts.line_height(self.font);
        let y = inner.y + (inner.h as i32 - lh as i32) / 2;
        let x0 = inner.x - self.scroll as i32;
        if self.text.is_empty() && !focused {
            p.text_in(self.font, inner, &self.placeholder, t.text_faint, Align::Left);
        } else {
            if let (true, Some((a, b))) = (focused, self.selection()) {
                let sx = x0 + p.fonts.measure(self.font, &self.shown(a)) as i32;
                let sw = p.fonts.measure(self.font, &self.shown(b)).saturating_sub(sx as u32 - x0 as u32);
                p.fill(Rect::new(sx, y, sw, lh), t.selection);
            }
            p.text(self.font, x0, y, &self.shown(self.text.len()), t.text);
            if focused {
                let cx = x0 + p.fonts.measure(self.font, &self.shown(self.cursor)) as i32;
                p.fill(Rect::new(cx, y + 1, 2, lh.saturating_sub(2)), t.accent);
            }
        }
        p.restore_clip(old);
    }
}
