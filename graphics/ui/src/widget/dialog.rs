use super::button::{Button, ButtonStyle};
use super::text_field::TextField;
use super::wrap_text;
use crate::event::{Event, Response};
use crate::layout::{center, contains, inset};
use crate::paint::{Align, FontKind, Fonts, Painter};
use alloc::string::String;
use alloc::vec::Vec;
use osyx_gfx::Rect;
use osyx_input::key;

/// A modal dialog drawn over a window's content: title, message, an
/// optional text input and a row of buttons (the last one is the default,
/// triggered by Enter; Escape cancels).
#[derive(Clone, Debug)]
pub struct Dialog {
    pub title: String,
    pub message: String,
    pub input: Option<TextField>,
    pub buttons: Vec<Button>,
    /// Application-defined purpose of the dialog.
    pub tag: u32,
    /// The card, set by [`Dialog::layout`].
    pub rect: Rect,
    area: Rect,
    /// Focus: 0 = input (if any), then the buttons.
    focus: usize,
    lines: Vec<String>,
}

impl Dialog {
    /// `buttons`: labels left to right; the last is the default action.
    pub fn new(tag: u32, title: &str, message: &str, buttons: &[(&str, ButtonStyle)]) -> Dialog {
        Dialog {
            title: String::from(title),
            message: String::from(message),
            input: None,
            buttons: buttons.iter().enumerate().map(|(i, (l, s))| Button::new(i, l, *s)).collect(),
            tag,
            rect: Rect::EMPTY,
            area: Rect::EMPTY,
            // Without an input the default (last) button has the focus.
            focus: buttons.len().saturating_sub(1),
            lines: Vec::new(),
        }
    }

    pub fn with_input(mut self, text: &str, placeholder: &str) -> Dialog {
        let mut f = TextField::new(text);
        f.placeholder = String::from(placeholder);
        f.select_all();
        self.input = Some(f);
        self.focus = 0;
        self
    }

    pub fn input_text(&self) -> &str {
        self.input.as_ref().map_or("", |f| f.text())
    }

    fn focusables(&self) -> usize {
        self.buttons.len() + usize::from(self.input.is_some())
    }

    fn default_button(&self) -> usize {
        self.buttons.len().saturating_sub(1)
    }

    /// Height of the card at width `w`.
    pub fn height_for(&mut self, w: u32, fonts: &Fonts) -> u32 {
        self.lines = wrap_text(fonts, FontKind::Ui, &self.message, w.saturating_sub(48));
        let lh = fonts.line_height(FontKind::Ui);
        let title_h = fonts.line_height(FontKind::Large);
        let input_h = if self.input.is_some() { 36 + 14 } else { 0 };
        24 + title_h + 12 + self.lines.len() as u32 * lh + 18 + input_h + 34 + 24
    }

    /// Centres the card in `area` (the window content), dimming the rest.
    pub fn layout(&mut self, area: Rect, fonts: &Fonts) {
        let w = 420.min(area.w.saturating_sub(32)).max(200);
        let h = self.height_for(w, fonts);
        self.place(area, center(area, w, h), fonts);
    }

    /// Makes `card` the whole dialog (a dialog that is its own window).
    pub fn layout_card(&mut self, card: Rect, fonts: &Fonts) {
        self.height_for(card.w, fonts);
        self.place(card, card, fonts);
    }

    fn place(&mut self, area: Rect, card: Rect, fonts: &Fonts) {
        self.area = area;
        self.rect = card;
        let lh = fonts.line_height(FontKind::Ui);
        let title_h = fonts.line_height(FontKind::Large);
        let inner = inset(self.rect, 24);
        let mut y = inner.y + title_h as i32 + 12 + (self.lines.len() as u32 * lh) as i32 + 18;
        if let Some(f) = &mut self.input {
            f.rect = Rect::new(inner.x, y, inner.w, 36);
            y += 36 + 14;
        }
        let mut x = inner.right() as i32;
        for b in self.buttons.iter_mut().rev() {
            let bw = b.preferred_width(fonts).max(96);
            x -= bw as i32;
            b.rect = Rect::new(x, y, bw, 34);
            x -= 10;
        }
    }

    pub fn event(&mut self, ev: &Event, fonts: &Fonts) -> Response {
        self.event_inner(ev, fonts, None)
    }

    pub fn event_with_clipboard(&mut self, ev: &Event, fonts: &Fonts, clipboard: &mut crate::Clipboard) -> Response {
        self.event_inner(ev, fonts, Some(clipboard))
    }

    fn event_inner(&mut self, ev: &Event, fonts: &Fonts, clipboard: Option<&mut crate::Clipboard>) -> Response {
        let has_input = usize::from(self.input.is_some());
        if let Event::Key(k) = ev {
            if k.down && k.key == key::TAB {
                let n = self.focusables();
                self.focus = if k.shift() { (self.focus + n - 1) % n } else { (self.focus + 1) % n };
                return Response::Redraw;
            }
            if k.down && k.key == key::ESCAPE {
                return Response::Cancelled;
            }
            if k.down && (k.key == key::ENTER || k.key == key::KP_ENTER) {
                // Enter activates the focused button, or the default one.
                let b = self.focus.checked_sub(has_input).unwrap_or(self.default_button());
                return Response::Activated(b.min(self.default_button()));
            }
        }
        let mut redraw = false;
        if let Some(f) = &mut self.input {
            let r = match clipboard {
                Some(clipboard) => f.event_with_clipboard(ev, self.focus == 0, fonts, clipboard),
                None => f.event(ev, self.focus == 0, fonts),
            };
            if matches!(ev, Event::PointerDown { x, y, .. } if contains(&f.rect, *x, *y)) {
                self.focus = 0;
            }
            match r {
                Response::Submitted => return Response::Activated(self.default_button()),
                Response::Cancelled => return Response::Cancelled,
                r if r.needs_redraw() => redraw = true,
                _ => {}
            }
        }
        for (i, b) in self.buttons.iter_mut().enumerate() {
            match b.event(ev, self.focus == i + has_input) {
                Response::Activated(id) => return Response::Activated(id),
                r if r.needs_redraw() => redraw = true,
                _ => {}
            }
        }
        // The dialog is modal: everything inside the area is consumed.
        if redraw {
            Response::Redraw
        } else if ev.position().is_some_and(|(x, y)| contains(&self.area, x, y)) || matches!(ev, Event::Key(_)) {
            Response::Consumed
        } else {
            Response::Ignored
        }
    }

    pub fn draw(&self, p: &mut Painter) {
        let t = *p.theme;
        if self.area != self.rect {
            p.blend(self.area, t.scrim, 150);
            p.card(self.rect, t.radius, t.surface, t.border);
        } else {
            p.fill(self.rect, t.surface);
        }
        let inner = inset(self.rect, 24);
        let title_h = p.fonts.line_height(FontKind::Large);
        p.text_in(FontKind::Large, Rect::new(inner.x, inner.y, inner.w, title_h), &self.title, t.text, Align::Left);
        let lh = p.fonts.line_height(FontKind::Ui);
        let mut y = inner.y + title_h as i32 + 12;
        for line in &self.lines {
            p.text(FontKind::Ui, inner.x, y, line, t.text_dim);
            y += lh as i32;
        }
        let has_input = usize::from(self.input.is_some());
        if let Some(f) = &self.input {
            f.draw(p, self.focus == 0);
        }
        for (i, b) in self.buttons.iter().enumerate() {
            b.draw(p, self.focus == i + has_input && (has_input == 0 || self.focus > 0));
        }
    }
}
