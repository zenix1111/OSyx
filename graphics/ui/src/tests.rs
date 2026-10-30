extern crate std;

use crate::event::{ClickCounter, Event, KeyEvent, Response};
use crate::focus::FocusChain;
use crate::icon::{self, Icon};
use crate::layout::*;
use crate::paint::{Align, FontKind, Fonts, Painter};
use crate::theme::MIDNIGHT;
use crate::time::{civil_from_days, days_from_civil, Tz};
use crate::widget::*;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use osyx_gfx::{Rect, Surface};
use osyx_input::{button, key, modifier};

fn key_down(k: u16, text: Option<char>, mods: u32) -> Event {
    Event::Key(KeyEvent { key: k, text, mods, down: true, repeat: false })
}

fn typed(c: char) -> Event {
    key_down(0, Some(c), 0)
}

fn click(x: i32, y: i32, clicks: u8) -> [Event; 2] {
    [Event::PointerDown { x, y, button: button::LEFT, clicks }, Event::PointerUp { x, y, button: button::LEFT }]
}

#[test]
fn layout_splits_and_rows() {
    let r = Rect::new(10, 20, 300, 200);
    let (top, rest) = split_top(r, 40);
    assert_eq!(top, Rect::new(10, 20, 300, 40));
    assert_eq!(rest, Rect::new(10, 60, 300, 160));
    let (rest, bottom) = split_bottom(r, 500);
    assert_eq!((rest.h, bottom), (0, r), "oversized splits take everything");
    let [a, b, c] = row(Rect::new(0, 0, 100, 10), [20, 30, 40], 5);
    assert_eq!((a.x, b.x, c.x, c.w), (0, 25, 60, 40));
    let [x, y] = row_right(Rect::new(0, 0, 100, 10), [20, 30], 5);
    assert_eq!((x.x, y.x), (80, 45));
    let cols: Vec<Rect> = columns(Rect::new(0, 0, 100, 10), 3, 5).collect();
    assert_eq!(cols.iter().map(|c| c.x).collect::<Vec<_>>(), [0, 35, 70]);
    assert_eq!(center(Rect::new(0, 0, 100, 100), 20, 10), Rect::new(40, 45, 20, 10));
    assert_eq!(inset(Rect::new(0, 0, 10, 10), 8), Rect::new(8, 8, 0, 0));
    assert!(contains(&r, 10, 20) && !contains(&r, 310, 20));
}

#[test]
fn focus_chain_cycles_with_tab_and_shift_tab() {
    let mut f = FocusChain::new(&[3, 5, 9]);
    assert_eq!(f.focused(), Some(3));
    let tab = KeyEvent { key: key::TAB, text: None, mods: 0, down: true, repeat: false };
    assert!(f.handle_key(&tab));
    assert!(f.is(5));
    assert!(f.handle_key(&KeyEvent { mods: modifier::LEFT_SHIFT, ..tab }));
    assert!(f.handle_key(&KeyEvent { mods: modifier::LEFT_SHIFT, ..tab }));
    assert_eq!(f.focused(), Some(9), "shift+tab wraps backwards");
    assert!(f.set(5) && !f.set(42));
    assert!(!f.handle_key(&KeyEvent { mods: modifier::LEFT_ALT, ..tab }), "alt+tab belongs to PRISM");
    assert_eq!(FocusChain::new(&[]).focused(), None);
}

#[test]
fn click_counter_detects_double_clicks() {
    let mut c = ClickCounter::default();
    assert_eq!(c.press(1000, 10, 10, 1), 1);
    assert_eq!(c.press(1200, 12, 11, 1), 2);
    assert_eq!(c.press(1300, 12, 11, 1), 3);
    assert_eq!(c.press(2000, 12, 11, 1), 1, "too slow");
    assert_eq!(c.press(2100, 40, 11, 1), 1, "moved too far");
    assert_eq!(c.press(2200, 40, 11, 2), 1, "other button");
}

#[test]
fn button_activates_on_release_inside_and_by_keyboard() {
    let mut b = Button::new(7, "OK", ButtonStyle::Primary);
    b.rect = Rect::new(10, 10, 80, 30);
    assert_eq!(b.event(&Event::PointerMove { x: 20, y: 20 }, false), Response::Redraw);
    assert!(b.is_hovered());
    assert_eq!(b.event(&Event::PointerDown { x: 20, y: 20, button: button::LEFT, clicks: 1 }, false), Response::Redraw);
    assert_eq!(b.event(&Event::PointerUp { x: 21, y: 21, button: button::LEFT }, false), Response::Activated(7));
    // Press inside, release outside: no activation.
    b.event(&Event::PointerDown { x: 20, y: 20, button: button::LEFT, clicks: 1 }, false);
    assert_eq!(b.event(&Event::PointerUp { x: 200, y: 20, button: button::LEFT }, false), Response::Redraw);
    assert_eq!(b.event(&key_down(key::ENTER, None, 0), true), Response::Activated(7));
    assert_eq!(b.event(&key_down(key::ENTER, None, 0), false), Response::Ignored, "keys only when focused");
    b.enabled = false;
    for e in click(20, 20, 1) {
        assert!(!matches!(b.event(&e, false), Response::Activated(_)));
    }
}

#[test]
fn checkbox_toggles() {
    let mut c = Checkbox::new("Show hidden files", false);
    c.rect = Rect::new(0, 0, 200, 24);
    let [d, u] = click(5, 5, 1);
    c.event(&d, false);
    assert_eq!(c.event(&u, false), Response::Changed);
    assert!(c.checked);
    assert_eq!(c.event(&key_down(key::SPACE, Some(' '), 0), true), Response::Changed);
    assert!(!c.checked);
}

#[test]
fn text_field_editing() {
    let fonts = Fonts::load();
    let mut f = TextField::new("");
    f.rect = Rect::new(0, 0, 200, 32);
    for c in "zażółć gęślą".chars() {
        assert_eq!(f.event(&typed(c), true, &fonts), Response::Changed);
    }
    assert_eq!(f.text(), "zażółć gęślą");
    f.event(&key_down(key::BACKSPACE, None, 0), true, &fonts);
    assert_eq!(f.text(), "zażółć gęśl", "backspace removes one character, not one byte");
    f.event(&key_down(key::BACKSPACE, None, modifier::LEFT_CTRL), true, &fonts);
    assert_eq!(f.text(), "zażółć ", "ctrl+backspace removes a word");
    f.event(&key_down(key::HOME, None, 0), true, &fonts);
    f.event(&key_down(key::RIGHT, None, modifier::LEFT_SHIFT), true, &fonts);
    f.event(&key_down(key::RIGHT, None, modifier::LEFT_SHIFT), true, &fonts);
    f.event(&key_down(key::RIGHT, None, modifier::LEFT_SHIFT), true, &fonts);
    assert_eq!(f.selection(), Some((0, 4)), "three characters, four bytes");
    f.event(&typed('X'), true, &fonts);
    assert_eq!(f.text(), "Xółć ");
    f.event(&key_down(key::END, None, 0), true, &fonts);
    f.event(&key_down(key::DELETE, None, 0), true, &fonts);
    assert_eq!(f.text(), "Xółć ", "delete at the end does nothing");
    f.event(&key_down(key::A, Some('a'), modifier::LEFT_CTRL), true, &fonts);
    assert_eq!(f.selection(), Some((0, f.text().len())), "ctrl+a selects all and types nothing");
    assert_eq!(f.event(&key_down(key::ENTER, None, 0), true, &fonts), Response::Submitted);
    assert_eq!(f.event(&key_down(key::ESCAPE, None, 0), true, &fonts), Response::Cancelled);
    assert_eq!(f.event(&typed('q'), false, &fonts), Response::Ignored, "unfocused fields ignore keys");
    // Control characters and Ctrl/Alt combinations insert nothing.
    f.set_text("ab");
    f.event(&key_down(key::C, Some('c'), modifier::LEFT_CTRL), true, &fonts);
    f.event(&typed('\u{7}'), true, &fonts);
    assert_eq!(f.text(), "ab");
    f.max_len = 3;
    f.event(&typed('ż'), true, &fonts);
    assert_eq!(f.text(), "ab", "a two-byte character does not fit in one byte");
    f.event(&typed('c'), true, &fonts);
    assert_eq!(f.text(), "abc");
}

#[test]
fn text_field_clipboard_shortcuts_preserve_unicode_and_masked_text() {
    let fonts = Fonts::load();
    let mut clipboard = crate::Clipboard::default();
    let mut field = TextField::new("Zażółć 🌍");
    field.select_all();
    field.event_with_clipboard(&key_down(key::C, Some('c'), modifier::LEFT_CTRL), true, &fonts, &mut clipboard);
    assert_eq!(clipboard.text(), Some("Zażółć 🌍"));
    field.event_with_clipboard(&key_down(key::X, Some('x'), modifier::LEFT_CTRL), true, &fonts, &mut clipboard);
    assert_eq!(field.text(), "");
    field.event_with_clipboard(&key_down(key::V, Some('v'), modifier::LEFT_CTRL), true, &fonts, &mut clipboard);
    assert_eq!(field.text(), "Zażółć 🌍");
    field.masked = true;
    field.select_all();
    clipboard.receive(Some("safe".into()));
    field.event_with_clipboard(&key_down(key::C, Some('c'), modifier::LEFT_CTRL), true, &fonts, &mut clipboard);
    assert_eq!(clipboard.text(), Some("safe"));
}

#[test]
fn text_field_click_places_the_cursor() {
    let fonts = Fonts::load();
    let mut f = TextField::new("hello world");
    f.rect = Rect::new(0, 0, 300, 32);
    let w = fonts.measure(FontKind::Ui, "hello") as i32;
    f.event(&Event::PointerDown { x: 10 + w, y: 10, button: button::LEFT, clicks: 1 }, true, &fonts);
    f.event(&Event::PointerUp { x: 10 + w, y: 10, button: button::LEFT }, true, &fonts);
    assert_eq!(f.cursor(), 5);
    f.event(&Event::PointerDown { x: 12, y: 10, button: button::LEFT, clicks: 2 }, true, &fonts);
    assert_eq!(f.selection(), Some((0, 11)), "double click selects everything");
}

fn list_with(n: usize) -> ListView {
    let mut l = ListView::new(vec![Column::new("Name", 0, Align::Left), Column::new("Size", 80, Align::Right)]);
    l.rect = Rect::new(0, 0, 300, 28 + 30 * 5);
    l.set_items((0..n).map(|i| ListItem::new(Some(Icon::File), &[&std::format!("file{i}"), "1 KiB"])).collect());
    l
}

#[test]
fn list_selection_activation_and_keyboard() {
    let mut l = list_with(20);
    // Row 1 is at y = 28 (header) + 30..60.
    let [d, u] = click(50, 28 + 45, 1);
    assert_eq!(l.event(&d, true), Response::Changed);
    l.event(&u, true);
    assert_eq!(l.selected(), Some(1));
    assert_eq!(l.event(&Event::PointerDown { x: 50, y: 28 + 45, button: button::LEFT, clicks: 2 }, true), Response::Activated(1));
    assert_eq!(l.event(&key_down(key::DOWN, None, 0), true), Response::Changed);
    assert_eq!(l.selected(), Some(2));
    l.event(&key_down(key::END, None, 0), true);
    assert_eq!(l.selected(), Some(19));
    assert!(l.scroll.offset > 0, "the selection is scrolled into view");
    assert_eq!(l.scroll.offset, 20 * 30 - 150);
    assert_eq!(l.event(&key_down(key::ENTER, None, 0), true), Response::Activated(19));
    l.event(&key_down(key::HOME, None, 0), true);
    assert_eq!((l.selected(), l.scroll.offset), (Some(0), 0));
    l.event(&key_down(key::PAGE_DOWN, None, 0), true);
    assert_eq!(l.selected(), Some(5));
    // A click below the last row clears the selection.
    let mut short = list_with(2);
    short.select(Some(1));
    assert_eq!(short.event(&Event::PointerDown { x: 50, y: 28 + 140, button: button::LEFT, clicks: 1 }, true), Response::Changed);
    assert_eq!(short.selected(), None);
}

#[test]
fn list_scrolls_with_the_wheel_and_clamps() {
    let mut l = list_with(20);
    assert_eq!(l.event(&Event::Wheel { x: 50, y: 100, dy: -1 }, false), Response::Redraw);
    assert_eq!(l.scroll.offset, 48);
    for _ in 0..50 {
        l.event(&Event::Wheel { x: 50, y: 100, dy: -1 }, false);
    }
    assert_eq!(l.scroll.offset, l.scroll.max_offset(), "never past the end");
    assert_eq!(l.row_at(50, 28 + 149), Some(19));
    // Replacing the items with fewer rows keeps everything in range.
    l.select(Some(19));
    l.set_items(vec![ListItem::new(None, &["only"])]);
    assert_eq!((l.selected(), l.scroll.offset), (Some(0), 0));
}

#[test]
fn scroll_thumb_drag_maps_to_offset() {
    let mut s = Scroll::default();
    s.set_sizes(1000, 100);
    let track = Rect::new(90, 0, 10, 100);
    let th = s.thumb(track).unwrap();
    assert_eq!(th.h, 24, "minimum thumb size");
    s.event(&Event::PointerDown { x: 95, y: th.y + 5, button: button::LEFT, clicks: 1 }, track, track);
    s.event(&Event::PointerMove { x: 95, y: th.y + 5 + 76 }, track, track);
    assert_eq!(s.offset, 900, "dragging the thumb to the bottom shows the end");
    s.event(&Event::PointerUp { x: 95, y: 0, button: button::LEFT }, track, track);
    assert!(!s.is_dragging());
    assert!(s.ensure_visible(0, 10));
    assert_eq!(s.offset, 0);
    let mut fits = Scroll::default();
    fits.set_sizes(50, 100);
    assert!(fits.thumb(track).is_none());
}

#[test]
fn menu_keyboard_and_pointer() {
    let fonts = Fonts::load();
    let mut items = vec![MenuItem::new("Open Terminal", Some(Icon::Terminal)), MenuItem::new("Disabled", None), MenuItem::new("Files", None)];
    items[1].enabled = false;
    let mut m = Menu::new(items);
    let (w, h) = m.size(&fonts);
    assert!(w >= 180 && h == 3 * 32 + 12);
    m.rect = Rect::new(0, 0, w, h);
    assert_eq!(m.event(&key_down(key::DOWN, None, 0)), Response::Redraw);
    assert_eq!(m.hovered(), Some(0));
    m.event(&key_down(key::DOWN, None, 0));
    assert_eq!(m.hovered(), Some(2), "disabled items are skipped");
    assert_eq!(m.event(&key_down(key::ENTER, None, 0)), Response::Activated(2));
    let [d, u] = click(20, 6 + 16, 1);
    m.event(&d);
    assert_eq!(m.event(&u), Response::Activated(0));
    let [d, u] = click(20, 6 + 32 + 16, 1);
    m.event(&d);
    assert_eq!(m.event(&u), Response::Ignored, "disabled item");
    assert_eq!(m.event(&Event::PointerDown { x: 900, y: 900, button: button::LEFT, clicks: 1 }), Response::Cancelled);
    assert_eq!(m.event(&key_down(key::ESCAPE, None, 0)), Response::Cancelled);
}

#[test]
fn dialog_input_and_buttons() {
    let fonts = Fonts::load();
    let mut d = Dialog::new(1, "New folder", "Name of the new folder:", &[("Cancel", ButtonStyle::Secondary), ("Create", ButtonStyle::Primary)])
        .with_input("Untitled", "Folder name");
    d.layout(Rect::new(0, 0, 640, 480), &fonts);
    assert!(contains(&Rect::new(0, 0, 640, 480), d.rect.x, d.rect.y));
    // The initial text is selected: typing replaces it.
    for c in "Projekty".chars() {
        d.event(&typed(c), &fonts);
    }
    assert_eq!(d.input_text(), "Projekty");
    assert_eq!(d.event(&key_down(key::ENTER, None, 0), &fonts), Response::Activated(1), "Enter = default button");
    assert_eq!(d.event(&key_down(key::ESCAPE, None, 0), &fonts), Response::Cancelled);
    let cancel = d.buttons[0].rect;
    let [down, up] = click(cancel.x + 5, cancel.y + 5, 1);
    d.event(&down, &fonts);
    assert_eq!(d.event(&up, &fonts), Response::Activated(0));
    // Clicks elsewhere in the window are swallowed (modal).
    assert_eq!(d.event(&Event::PointerDown { x: 2, y: 2, button: button::LEFT, clicks: 1 }, &fonts), Response::Consumed);
    // Without an input the default button has the focus.
    let mut q = Dialog::new(2, "Delete?", "x", &[("Cancel", ButtonStyle::Secondary), ("Delete", ButtonStyle::Danger)]);
    q.layout(Rect::new(0, 0, 640, 480), &fonts);
    assert_eq!(q.event(&key_down(key::ENTER, None, 0), &fonts), Response::Activated(1));
    q.event(&key_down(key::TAB, None, 0), &fonts);
    assert_eq!(q.event(&key_down(key::ENTER, None, 0), &fonts), Response::Activated(0), "tab moved to Cancel");
}

#[test]
fn wrap_text_respects_width() {
    let fonts = Fonts::load();
    let lines = wrap_text(&fonts, FontKind::Ui, "The quick brown fox jumps over the lazy dog\nsecond", 120);
    assert!(lines.len() >= 4);
    assert!(lines.iter().all(|l| fonts.measure(FontKind::Ui, l) <= 120));
    assert_eq!(lines.last().map(String::as_str), Some("second"));
    let long = wrap_text(&fonts, FontKind::Ui, "/a/very/long/path/without/any/spaces/at/all", 80);
    assert!(long.len() > 1 && long.iter().all(|l| fonts.measure(FontKind::Ui, l) <= 80));
    assert_eq!(long.concat(), "/a/very/long/path/without/any/spaces/at/all");
}

#[test]
fn painter_never_draws_outside_its_clip() {
    let fonts = Fonts::load();
    let mut px = vec![0u32; 120 * 80];
    let mut s = Surface::new(&mut px, 120, 80, 120).unwrap();
    let mut p = Painter::new(&mut s, &MIDNIGHT, &fonts);
    let clip = Rect::new(20, 10, 50, 30);
    let old = p.push_clip(clip);
    p.rounded(Rect::new(-10, -10, 200, 200), 12, 0xFFFFFF, 255);
    p.disc(40, 20, 50, 0xFFFFFF, 255);
    p.segment((0, 0), (120 << 8, 80 << 8), 2048, 0xFFFFFF, 255);
    p.text(FontKind::Large, 0, 0, "OSyx PRISM", 0xFFFFFF);
    p.text(FontKind::Mono, 0, 12, "terminal text", 0xFFFFFF);
    p.ring(40, 30, 30, 4, 0xFFFFFF, 255, true);
    icon::draw(&mut p, Icon::Folder, Rect::new(0, 0, 120, 80), 0xFFFFFF);
    p.restore_clip(old);
    for y in 0..80 {
        for x in 0..120 {
            let inside = contains(&clip, x, y);
            let v = s.get(x, y).unwrap();
            assert!(inside || v == 0, "pixel ({x},{y}) drawn outside the clip");
        }
    }
    assert!(s.get(30, 20).unwrap() != 0, "something was drawn inside");
}

#[test]
fn every_icon_stays_in_its_box() {
    let fonts = Fonts::load();
    let all = [
        Icon::Folder,
        Icon::File,
        Icon::TextFile,
        Icon::Program,
        Icon::Terminal,
        Icon::Info,
        Icon::Power,
        Icon::Restart,
        Icon::Apps,
        Icon::Up,
        Icon::NewFolder,
        Icon::Rename,
        Icon::Trash,
        Icon::Refresh,
        Icon::Home,
        Icon::Drive,
        Icon::Close,
        Icon::Bell,
        Icon::Link,
        Icon::Device,
    ];
    for ic in all {
        let mut px = vec![0u32; 64 * 64];
        let mut s = Surface::new(&mut px, 64, 64, 64).unwrap();
        let mut p = Painter::new(&mut s, &MIDNIGHT, &fonts);
        icon::draw(&mut p, ic, Rect::new(16, 16, 32, 32), 0xFFFFFF);
        let mut ink = 0;
        for y in 0..64 {
            for x in 0..64 {
                if s.get(x, y).unwrap() != 0 {
                    ink += 1;
                    assert!((14..50).contains(&x) && (14..50).contains(&y), "{ic:?} drew at ({x},{y})");
                }
            }
        }
        assert!(ink > 20, "{ic:?} is visible");
    }
}

#[test]
fn civil_dates_round_trip() {
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    assert_eq!(civil_from_days(days_from_civil(2026, 10, 23)), (2026, 10, 23));
    assert_eq!(civil_from_days(days_from_civil(2024, 2, 29)), (2024, 2, 29));
    assert_eq!(crate::time::weekday(days_from_civil(2026, 10, 23)), 5, "a Friday");
    for d in [-1_000_000i64, -1, 59, 60, 365, 20_000, 2_000_000] {
        let (y, m, dd) = civil_from_days(d);
        assert_eq!(days_from_civil(y, m, dd), d);
    }
}

#[test]
fn posix_time_zones() {
    let warsaw = Tz::parse("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
    // 2026-10-23 09:00 UTC is 11:00 CEST.
    let t = days_from_civil(2026, 10, 23) * 86_400 + 9 * 3600;
    let l = warsaw.local(t);
    assert_eq!((l.hour, l.minute, l.zone.as_str(), l.offset), (11, 0, "CEST", 7200));
    assert_eq!(l.short_date(), "Fri 23 Oct");
    assert_eq!(l.long_date(), "Friday, 23 October 2026");
    // DST ends 2026-10-25 01:00 UTC (03:00 CEST -> 02:00 CET).
    let end = days_from_civil(2026, 10, 25) * 86_400 + 3600;
    assert_eq!(warsaw.offset_at(end - 1).0, 7200);
    assert_eq!(warsaw.offset_at(end).0, 3600);
    // DST starts 2026-03-29 01:00 UTC.
    let start = days_from_civil(2026, 3, 29) * 86_400 + 3600;
    assert_eq!(warsaw.offset_at(start - 1).1, "CET");
    assert_eq!(warsaw.offset_at(start).1, "CEST");
    assert_eq!(warsaw.local(start).iso(), "2026-03-29 03:00:00");
    // Southern hemisphere: DST across the new year.
    let sydney = Tz::parse("AEST-10AEDT,M10.1.0,M4.1.0/3").unwrap();
    assert_eq!(sydney.offset_at(days_from_civil(2026, 1, 15) * 86_400).1, "AEDT");
    assert_eq!(sydney.offset_at(days_from_civil(2026, 7, 15) * 86_400).1, "AEST");
    let india = Tz::parse("<+0530>-5:30").unwrap();
    assert_eq!(india.local(0).hm(), "05:30");
    assert_eq!(Tz::parse("UTC0").unwrap().local(0).iso(), "1970-01-01 00:00:00");
    for bad in ["", "U", "CET", "CET-1CEST,M13.5.0,M10.5.0", "CET-1CEST,J60,M10.5.0", "CET-200", "CET-1CEST,M3.5.0"] {
        assert!(Tz::parse(bad).is_none(), "{bad:?} must be rejected");
    }
}

#[test]
fn list_marks_for_multi_selection() {
    use crate::widget::{Column, ListItem, ListView};
    let mut l = ListView::new(vec![Column::new("Name", 0, Align::Left)]);
    l.set_items((0..5).map(|i| ListItem::new(None, &[&alloc::format!("row {i}")])).collect());
    assert!(l.marked().is_empty());
    l.select(Some(1));
    assert_eq!(l.chosen(), [1], "without marks the selected row is chosen");
    l.toggle_mark(3);
    l.toggle_mark(4);
    assert_eq!(l.marked(), [3, 4]);
    assert_eq!(l.chosen(), [3, 4]);
    l.toggle_mark(3);
    assert_eq!(l.marked(), [4]);
    l.set_marked(&[0, 2, 9]);
    assert_eq!(l.marked(), [0, 2], "rows past the end are ignored");
    l.mark_all();
    assert_eq!(l.marked().len(), 5);
    l.clear_marks();
    assert!(l.marked().is_empty());
    // New items reset the marks.
    l.mark_all();
    l.set_items(vec![ListItem::new(None, &["only"])]);
    assert!(l.marked().is_empty());
}
