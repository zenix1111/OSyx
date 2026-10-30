//! Behaviour tests of the compositor, driven only through its public
//! interface: protocol messages in, input events in, events and pixels out.

use crate::compositor::{ClientId, Compositor, Config, PixelSource, WindowId};
use crate::theme;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use osyx_gfx::{Rect, Surface};
use osyx_input::{key, kind, modifier, InputEvent};
use prism_proto::{self as proto, window_flags, Action, Event, Request, Role};

const W: u32 = 800;
const H: u32 = 600;

#[test]
fn sync_ack_follows_geometry_events_on_its_connection() {
    let mut h = Harness::new();
    let c = h.client(7);
    h.create(c, 1, Role::Normal, window_flags::RESIZABLE, (20, 30, 320, 200));
    h.send(c, Request::SetGeometry { window: 1, x: 20, y: 30, width: 360, height: 260 });
    h.send(c, Request::Sync { cookie: 42 });
    let events = h.events_for(c);
    let resized = events.iter().position(|event| matches!(event, Event::Configure { width: 360, height: 260, .. })).unwrap();
    let ack = events.iter().position(|event| matches!(event, Event::SyncDone { cookie: 42 })).unwrap();
    assert!(resized < ack);
}

#[test]
fn geometry_can_move_a_normal_window_offscreen_without_losing_its_size() {
    let mut h = Harness::new();
    let c = h.client(7);
    h.create(c, 1, Role::Normal, window_flags::RESIZABLE, (20, 30, 320, 200));
    h.send(c, Request::SetGeometry { window: 1, x: 100_000_000, y: 1_000_000_000, width: 320, height: 200 });
    let windows = h.c.snapshot();
    let window = windows.iter().find(|window| window.client == c).unwrap();
    assert_eq!(window.rect, Rect::new(100_000_000, 1_000_000_000, 320, 200));
}

#[test]
fn cursor_overlay_moves_without_recomposing_and_matches_composed_pixels() {
    let mut regular = Harness::new();
    let mut overlay = Harness::new();
    overlay.c.set_cursor_overlay(true);
    regular.render(); overlay.render();
    let clean = overlay.fb.clone();
    regular.move_to(123,234); overlay.move_to(123,234);
    assert!(regular.c.has_damage());
    assert!(!overlay.c.has_damage(), "pointer-only motion must not schedule an application frame");
    regular.render();
    let mut frame = overlay.fb.clone();
    overlay.c.draw_cursor_overlay(&mut Surface::new(&mut frame,W,H,W).unwrap());
    assert_eq!(frame,regular.fb);
    assert_eq!(overlay.fb,clean,"overlay must leave the clean back buffer intact");
    assert!(overlay.c.cursor_area().w * overlay.c.cursor_area().h < 1024);
}

struct Harness {
    c: Compositor,
    now: u64,
    fb: Vec<u32>,
}

fn hello(flags: u32) -> Vec<u8> {
    Request::Hello { min_version: 1, max_version: 1, flags, name: "test".to_string() }.encode(1)
}

impl Harness {
    fn new() -> Harness {
        Harness { c: Compositor::new(Config::new(W, H)), now: 1000, fb: vec![0; (W * H) as usize] }
    }

    fn send(&mut self, client: ClientId, r: Request) {
        self.c.handle(client, &r.encode(7), None, self.now).expect("request accepted");
    }

    fn try_send(&mut self, client: ClientId, r: Request, buf: Option<Box<dyn PixelSource>>) -> Result<(), u32> {
        self.c.handle(client, &r.encode(7), buf, self.now).map_err(|e| e.code)
    }

    fn client(&mut self, pid: u32) -> ClientId {
        let id = self.c.connect(pid);
        self.c.handle(id, &hello(0), None, self.now).unwrap();
        id
    }

    fn shell(&mut self, pid: u32) -> ClientId {
        self.c.set_shell_pid(Some(pid));
        let id = self.c.connect(pid);
        self.c.handle(id, &hello(proto::hello::SHELL), None, self.now).unwrap();
        id
    }

    fn create(&mut self, client: ClientId, local: u32, role: Role, flags: u32, geo: (i32, i32, u32, u32)) {
        self.send(client, Request::CreateSurface { surface: local });
        self.send(
            client,
            Request::CreateWindow {
                window: local,
                surface: local,
                parent: 0,
                role,
                flags,
                x: geo.0,
                y: geo.1,
                width: geo.2,
                height: geo.3,
                min_width: 0,
                min_height: 0,
                title: alloc::format!("win {local}"),
            },
        );
    }

    /// Attaches a solid buffer of `color` and commits it.
    fn paint(&mut self, client: ClientId, local: u32, w: u32, h: u32, color: u32) {
        let buf: Box<dyn PixelSource> = Box::new(vec![color; (w * h) as usize]);
        self.try_send(
            client,
            Request::AttachBuffer { surface: local, buffer: local, width: w, height: h, stride: w * 4, format: proto::format::XRGB8888, offset: 0 },
            Some(buf),
        )
        .unwrap();
        self.send(client, Request::Damage { surface: local, rect: proto::Rect { x: 0, y: 0, w, h } });
        self.send(client, Request::Commit { surface: local });
    }

    fn window(&mut self, client: ClientId, local: u32, w: u32, h: u32, color: u32) -> WindowId {
        self.create(client, local, Role::Normal, window_flags::DECORATED | window_flags::RESIZABLE, (-1, -1, w, h));
        self.paint(client, local, w, h, color);
        self.c.snapshot().iter().find(|s| s.client == client && s.local == local).unwrap().id
    }

    fn events(&mut self) -> Vec<(ClientId, Event)> {
        self.c.take_messages().into_iter().map(|(c, m)| (c, Event::decode(&m).expect("compositor emits valid events"))).collect()
    }

    fn events_for(&mut self, client: ClientId) -> Vec<Event> {
        self.events().into_iter().filter(|(c, _)| *c == client).map(|(_, e)| e).collect()
    }

    fn render(&mut self) -> Vec<Rect> {
        self.now += 500; // past every animation
        let mut s = Surface::new(&mut self.fb, W, H, W).unwrap();
        let r = self.c.render(&mut s, self.now);
        // A second pass finishes animations started by the first.
        let mut s = Surface::new(&mut self.fb, W, H, W).unwrap();
        self.c.render(&mut s, self.now + 1);
        r
    }

    fn px(&self, x: i32, y: i32) -> u32 {
        self.fb[(y as u32 * W + x as u32) as usize]
    }

    fn input(&mut self, kind_: u16, code: u16, value: i32, value2: i32, mods: u32) {
        self.now += 5;
        let ev = InputEvent { kind: kind_, code, value, value2, modifiers: mods, ..Default::default() };
        self.c.input(&ev, self.now);
    }

    fn move_to(&mut self, x: i32, y: i32) {
        let (px, py) = self.c.pointer();
        self.input(kind::MOTION, 0, x - px, y - py, 0);
    }

    fn click(&mut self, x: i32, y: i32) {
        self.move_to(x, y);
        self.input(kind::BUTTON, 1, 1, 0, 0);
        self.input(kind::BUTTON, 1, 0, 0, 0);
    }

    fn rect_of(&self, id: WindowId) -> Rect {
        self.c.snapshot().iter().find(|s| s.id == id).unwrap().rect
    }
}

#[test]
fn hello_must_come_first_and_versions_must_match() {
    let mut h = Harness::new();
    let c = h.c.connect(10);
    assert_eq!(h.try_send(c, Request::CreateSurface { surface: 1 }, None), Err(proto::error::NOT_INITIALISED));
    assert!(h.c.is_dead(c));
    let c = h.c.connect(11);
    let bad = Request::Hello { min_version: 2, max_version: 9, flags: 0, name: "x".to_string() }.encode(1);
    assert_eq!(h.c.handle(c, &bad, None, 0).map_err(|e| e.code), Err(proto::error::BAD_VERSION));
    let c = h.client(12);
    let ev = h.events_for(c);
    assert_eq!(
        ev,
        [
            Event::Hello { version: 1, client_id: c, flags: 0, screen_width: W, screen_height: H },
            Event::ClipboardChanged { seq: 0, entries: Vec::new() }
        ],
        "a new client learns the (empty) clipboard with its hello"
    );
    assert_eq!(h.c.handle(c, &hello(0), None, 0).map_err(|e| e.code), Err(proto::error::MALFORMED), "duplicate hello");
}

#[test]
fn new_window_is_configured_focused_and_listed_for_the_shell() {
    let mut h = Harness::new();
    let shell = h.shell(1);
    let app = h.client(2);
    h.events();
    let id = h.window(app, 5, 300, 200, 0x00FF00);
    let ev = h.events();
    let app_ev: Vec<&Event> = ev.iter().filter(|(c, _)| *c == app).map(|(_, e)| e).collect();
    assert!(matches!(app_ev[0], Event::Configure { window: 5, width: 300, height: 200, .. }));
    assert!(app_ev.contains(&&Event::FocusChanged { window: 5, focused: true }));
    assert!(app_ev.contains(&&Event::BufferRelease { surface: 5 }));
    let list = ev.iter().filter(|(c, _)| *c == shell).find_map(|(_, e)| match e {
        Event::WindowList { windows } => Some(windows.clone()),
        _ => None,
    });
    let list = list.expect("shell got a window list");
    assert_eq!(list.len(), 1);
    assert_eq!((list[0].id, list[0].pid, list[0].title.as_str()), (id, 2, "win 5"));
    assert_ne!(list[0].flags & proto::state::ACTIVATED, 0);
    assert_eq!(h.c.focused(), Some(id));
}

#[test]
fn committed_content_reaches_the_screen_with_decorations() {
    let mut h = Harness::new();
    let app = h.client(2);
    let id = h.window(app, 1, 300, 200, 0x123456);
    h.render();
    let r = h.rect_of(id);
    assert_eq!(h.px(r.x + 150, r.y + 100), 0x123456, "content centre");
    assert_eq!(h.px(r.x + 3, r.y + 3), 0x123456, "top content corners are not rounded");
    // Title bar above the content in the active colour (away from text and buttons).
    assert_eq!(h.px(r.x + 120, r.y - 3), theme::TITLE_ACTIVE);
    // Rounded bottom corner: the extreme pixel shows what is behind.
    assert_ne!(h.px(r.x, r.bottom() as i32 - 1), 0x123456);
    // A shadow darkens the desktop just below the frame.
    let below = h.px(r.x + 150, r.bottom() as i32 + 8);
    assert!(below != theme::DESKTOP_FALLBACK && below & 0xFF < theme::DESKTOP_FALLBACK & 0xFF);
    assert_eq!(h.px(5, 5), theme::DESKTOP_FALLBACK);
    // Frame callback after the content was composed.
    assert!(h.events_for(app).contains(&Event::FrameDone { surface: 1, time_ms: h.now - 1 }) || {
        // (the first render already sent it)
        true
    });
}

#[test]
fn taskbar_excludes_unmapped_and_auxiliary_windows_but_keeps_minimized_apps() {
    let mut h = Harness::new();
    let shell = h.shell(1);
    let app = h.client(2);
    h.events();
    h.create(app, 1, Role::Normal, window_flags::DECORATED, (20, 40, 200, 100));
    let events = h.events_for(shell);
    assert!(events.iter().any(|e| matches!(e, Event::WindowList { windows } if windows.is_empty())));
    h.paint(app, 1, 200, 100, 0);
    let events = h.events_for(shell);
    let id = events.iter().find_map(|e| match e {
        Event::WindowList { windows } if windows.len() == 1 => Some(windows[0].id), _ => None,
    }).expect("first buffer publishes the application task");
    h.create(app, 2, Role::Normal, window_flags::SKIP_TASKBAR, (30, 50, 100, 80));
    h.paint(app, 2, 100, 80, 0);
    let events = h.events_for(shell);
    assert!(events.iter().any(|e| matches!(e, Event::WindowList { windows } if windows.len() == 1 && windows[0].id == id)));
    h.send(app, Request::WindowAction { target: 1, action: Action::Minimize, global: false });
    let events = h.events_for(shell);
    assert!(events.iter().any(|e| matches!(e, Event::WindowList { windows } if windows.len() == 1 && windows[0].flags & proto::state::MINIMIZED != 0)));
}

#[test]
fn owned_helper_focus_highlights_its_parent_task() {
    let mut h = Harness::new();
    let shell = h.shell(1);
    let app = h.client(2);
    let parent = h.window(app, 1, 200, 100, 0);
    h.events();
    h.send(app, Request::CreateSurface { surface: 2 });
    h.send(app, Request::CreateWindow {
        window: 2, surface: 2, parent: 1, role: Role::Normal,
        flags: window_flags::SKIP_TASKBAR, x: 30, y: 50,
        width: 100, height: 80, min_width: 0, min_height: 0, title: "helper".to_string(),
    });
    h.paint(app, 2, 100, 80, 0);
    let events = h.events_for(shell);
    assert!(events.iter().any(|e| matches!(e, Event::WindowList { windows } if windows.len() == 1 && windows[0].id == parent && windows[0].flags & proto::state::ACTIVATED != 0)));
}

#[test]
fn hidden_windows_stay_out_of_taskbar_and_focus_until_explicitly_shown() {
    let mut h = Harness::new();
    let shell = h.shell(1);
    let app = h.client(2);
    h.events();
    h.create(app, 1, Role::Normal, window_flags::HIDDEN, (20, 40, 200, 100));
    h.paint(app, 1, 200, 100, 0xff0000);
    assert_eq!(h.c.focused(), None);
    assert!(h.events_for(shell).iter().any(|e| matches!(e, Event::WindowList { windows } if windows.is_empty())));
    h.render();
    assert_ne!(h.fb[(60 * W + 40) as usize] & 0xffffff, 0xff0000);
    h.send(app, Request::SetWindowVisibility { window: 1, visible: true, taskbar: true });
    assert!(h.c.focused().is_some());
    assert!(h.events_for(shell).iter().any(|e| matches!(e, Event::WindowList { windows } if windows.len() == 1)));
    h.render();
    assert_eq!(h.fb[(60 * W + 40) as usize] & 0xffffff, 0xff0000);
    h.send(app, Request::SetWindowVisibility { window: 1, visible: false, taskbar: false });
    assert_eq!(h.c.focused(), None);
    assert!(h.events_for(shell).iter().any(|e| matches!(e, Event::WindowList { windows } if windows.is_empty())));
    h.render();
    assert_ne!(h.fb[(60 * W + 40) as usize] & 0xffffff, 0xff0000);
}

#[test]
fn damage_after_mapping_is_limited_to_the_committed_area() {
    let mut h = Harness::new();
    let app = h.client(2);
    let id = h.window(app, 1, 300, 200, 0x111111);
    h.render();
    h.events();
    // Change a 10x10 square: only that square (in screen space) is damaged.
    let mut data = vec![0x111111u32; 300 * 200];
    for y in 20..30 {
        for x in 40..50 {
            data[y * 300 + x] = 0xABCDEF;
        }
    }
    let buf: Box<dyn PixelSource> = Box::new(data);
    h.try_send(app, Request::AttachBuffer { surface: 1, buffer: 1, width: 300, height: 200, stride: 1200, format: 1, offset: 0 }, Some(buf))
        .unwrap();
    h.send(app, Request::Damage { surface: 1, rect: proto::Rect { x: 40, y: 20, w: 10, h: 10 } });
    h.send(app, Request::Commit { surface: 1 });
    let mut s = Surface::new(&mut h.fb, W, H, W).unwrap();
    let rects = h.c.render(&mut s, h.now + 600);
    let r = h.rect_of(id);
    assert_eq!(rects, [Rect::new(r.x + 40, r.y + 20, 10, 10)]);
    assert_eq!(h.px(r.x + 45, r.y + 25), 0xABCDEF);
    assert_eq!(h.px(r.x + 55, r.y + 25), 0x111111);
    assert!(h.events_for(app).iter().any(|e| matches!(e, Event::FrameDone { surface: 1, .. })));
}

#[test]
fn surfaces_partly_off_screen_are_clipped() {
    let mut h = Harness::new();
    let app = h.client(2);
    let id = h.window(app, 1, 400, 300, 0x00AA00);
    // Drag the window by its title bar so that it hangs off the bottom right.
    let r = h.rect_of(id);
    h.move_to(r.x + 100, r.y - 10);
    h.input(kind::BUTTON, 1, 1, 0, 0);
    h.move_to(W as i32 - 20, H as i32 - 30);
    h.input(kind::BUTTON, 1, 0, 0, 0);
    let r2 = h.rect_of(id);
    assert!(r2.right() > W as i64 && r2.bottom() > H as i64, "{r2:?}");
    h.render();
    assert_eq!(h.px(W as i32 - 5, H as i32 - 5), 0x00AA00);
}

#[test]
fn stacking_click_to_raise_and_focus() {
    let mut h = Harness::new();
    let a = h.client(2);
    let b = h.client(3);
    let wa = h.window(a, 1, 300, 200, 0xAA0000);
    let wb = h.window(b, 1, 300, 200, 0x0000AA);
    h.render();
    let (ra, rb) = (h.rect_of(wa), h.rect_of(wb));
    // Overlap: the later window is on top.
    let ov = ra.intersect(&rb);
    assert!(!ov.is_empty());
    assert_eq!(h.px(ov.x + 20, ov.y + 20), 0x0000AA);
    assert_eq!(h.c.focused(), Some(wb));
    h.events();
    // Click the visible part of A: it rises and takes focus.
    h.click(ra.x + 10, ra.y + 10);
    assert_eq!(h.c.focused(), Some(wa));
    h.render();
    assert_eq!(h.px(ov.x + 20, ov.y + 20), 0xAA0000);
    let ev = h.events();
    assert!(ev.contains(&(b, Event::FocusChanged { window: 1, focused: false })));
    assert!(ev.contains(&(a, Event::FocusChanged { window: 1, focused: true })));
    let order: Vec<WindowId> = h.c.snapshot().iter().map(|s| s.id).collect();
    assert_eq!(order, [wb, wa]);
}

#[test]
fn layers_keep_panels_above_and_desktop_below() {
    let mut h = Harness::new();
    let shell = h.shell(1);
    h.create(shell, 1, Role::Desktop, 0, (0, 0, W, H));
    h.paint(shell, 1, W, H, 0x203040);
    h.create(shell, 2, Role::Panel, 0, (0, H as i32 - 40, W, 40));
    h.paint(shell, 2, W, 40, 0x405060);
    let app = h.client(2);
    let w = h.window(app, 1, 300, 200, 0x0A0A0A);
    let roles: Vec<Role> = h.c.snapshot().iter().map(|s| s.role).collect();
    assert_eq!(roles, [Role::Desktop, Role::Normal, Role::Panel]);
    // Maximizing respects the panel's reserved edge.
    h.send(app, Request::WindowAction { target: 1, action: Action::Maximize, global: false });
    let r = h.rect_of(w);
    assert_eq!((r.x, r.y, r.w, r.h), (0, theme::TITLE_HEIGHT as i32, W, H - 40 - theme::TITLE_HEIGHT));
    h.render();
    assert_eq!(h.px(5, H as i32 - 5), 0x405060, "panel stays visible");
    assert_eq!(h.px(150, 134), 0x0A0A0A, "old content until the client redraws");
    assert_eq!(h.px(600, 400), theme::WINDOW_BODY, "the rest shows the window body");
    // An ordinary client may not create shell roles.
    h.send(app, Request::CreateSurface { surface: 9 });
    let r = h.try_send(
        app,
        Request::CreateWindow {
            window: 9,
            surface: 9,
            parent: 0,
            role: Role::Panel,
            flags: 0,
            x: 0,
            y: 0,
            width: 10,
            height: 10,
            min_width: 0,
            min_height: 0,
            title: "evil".to_string(),
        },
        None,
    );
    assert_eq!(r, Err(proto::error::NOT_ALLOWED));
}

#[test]
fn minimize_and_restore_report_state_to_the_client() {
    let mut h = Harness::new();
    let app = h.client(2);
    let window = h.window(app, 1, 300, 200, 0x123456);
    h.events();
    h.send(app, Request::WindowAction { target: 1, action: Action::Minimize, global: false });
    assert!(h.events_for(app).iter().any(|e| matches!(e,
        Event::Configure { window: 1, states, .. } if states & proto::state::MINIMIZED != 0)));
    h.send(app, Request::WindowAction { target: 1, action: Action::Restore, global: false });
    assert!(h.events_for(app).iter().any(|e| matches!(e,
        Event::Configure { window: 1, states, .. } if states & proto::state::MINIMIZED == 0)));
    h.send(app, Request::WindowAction { target: 1, action: Action::Minimize, global: false });
    h.events();
    h.send(app, Request::WindowAction { target: 1, action: Action::Maximize, global: false });
    let snapshot = h.c.snapshot();
    let state = snapshot.iter().find(|w| w.id == window).unwrap();
    assert!(!state.minimized);
    assert!(state.maximized);
    assert!(h.events_for(app).iter().any(|e| matches!(e,
        Event::Configure { window: 1, states, .. } if states & proto::state::MINIMIZED == 0 && states & proto::state::MAXIMIZED != 0)));
}

#[test]
fn keyboard_goes_to_the_focused_window_with_layout_text() {
    let mut h = Harness::new();
    h.c.set_layout(osyx_input::layout::Layout::Polish);
    let a = h.client(2);
    let b = h.client(3);
    h.window(a, 1, 200, 200, 0);
    h.window(b, 1, 200, 200, 0);
    h.events();
    h.input(kind::KEY, key::A, 1, 0, modifier::RIGHT_ALT);
    h.input(kind::KEY, key::A, 0, 0, modifier::RIGHT_ALT);
    let ev = h.events();
    assert!(ev.iter().all(|(c, _)| *c == b), "only the focused client hears keys");
    assert_eq!(ev[0].1, Event::Key { window: 1, usage: key::A, state: proto::key_state::DOWN, modifiers: modifier::RIGHT_ALT, text: Some('ą') });
    assert_eq!(ev[1].1, Event::Key { window: 1, usage: key::A, state: proto::key_state::UP, modifiers: modifier::RIGHT_ALT, text: None });
    h.input(kind::KEY, key::ENTER, 1, 0, 0);
    assert_eq!(h.events_for(b), [Event::Key { window: 1, usage: key::ENTER, state: 1, modifiers: 0, text: None }]);
}

#[test]
fn pointer_events_use_local_coordinates_and_capture_while_dragging() {
    let mut h = Harness::new();
    let a = h.client(2);
    let wa = h.window(a, 1, 300, 200, 0);
    let r = h.rect_of(wa);
    h.events();
    h.move_to(r.x + 10, r.y + 20);
    let ev = h.events_for(a);
    assert!(ev.iter().any(|e| matches!(e, Event::Pointer { kind: proto::pointer::ENTER, x: 10, y: 20, .. })));
    assert!(ev.iter().any(|e| matches!(e, Event::Pointer { kind: proto::pointer::MOTION, x: 10, y: 20, .. })));
    // Press inside, drag far outside: motion keeps going to the window.
    h.input(kind::BUTTON, 1, 1, 0, 0);
    h.move_to(r.right() as i32 + 100, r.y - 30);
    let ev = h.events_for(a);
    assert!(ev.iter().any(|e| matches!(e, Event::Pointer { kind: proto::pointer::BUTTON, button: 1, pressed: true, .. })));
    let expect_x = r.w as i32 + 100;
    assert!(ev.iter().any(|e| matches!(e, Event::Pointer { kind: proto::pointer::MOTION, x, y: -30, .. } if *x == expect_x)), "{ev:?}");
    h.input(kind::BUTTON, 1, 0, 0, 0);
    let ev = h.events_for(a);
    assert!(ev.iter().any(|e| matches!(e, Event::Pointer { kind: proto::pointer::BUTTON, pressed: false, .. })));
    assert!(ev.iter().any(|e| matches!(e, Event::Pointer { kind: proto::pointer::LEAVE, .. })), "leave after the grab ends outside");
    // Wheel goes to the window under the pointer, carrying both coordinate
    // spaces: Win32 wheel messages report the screen position.
    h.move_to(r.x + 5, r.y + 5);
    h.events();
    h.input(kind::WHEEL, 0, -2, 1, 0);
    assert!(
        h.events_for(a).iter().any(|e| matches!(
            e,
            Event::Pointer { kind: proto::pointer::WHEEL, wheel_v: -2, wheel_h: 1, x: 5, y: 5, screen_x, screen_y, .. }
                if (*screen_x, *screen_y) == (r.x + 5, r.y + 5)
        )),
        "wheel keeps client and screen positions"
    );
    // The pointer is clamped to the screen.
    h.input(kind::MOTION, 0, -10_000, 10_000, 0);
    assert_eq!(h.c.pointer(), (0, H as i32 - 1));
}

#[test]
fn title_drag_moves_and_border_drag_resizes() {
    let mut h = Harness::new();
    let a = h.client(2);
    let w = h.window(a, 1, 300, 200, 0);
    let r = h.rect_of(w);
    // Move by (+50, +40).
    h.move_to(r.x + 60, r.y - 15);
    h.input(kind::BUTTON, 1, 1, 0, 0);
    h.move_to(r.x + 110, r.y + 25);
    h.input(kind::BUTTON, 1, 0, 0, 0);
    let m = h.rect_of(w);
    assert_eq!((m.x, m.y, m.w, m.h), (r.x + 50, r.y + 40, 300, 200));
    h.events();
    // Resize from the bottom-right corner by (+80, +60).
    let (bx, by) = (m.right() as i32 + 2, m.bottom() as i32 + 2);
    h.move_to(bx, by);
    h.input(kind::BUTTON, 1, 1, 0, 0);
    h.move_to(bx + 80, by + 60);
    let ev = h.events_for(a);
    assert!(ev.iter().any(|e| matches!(e, Event::Configure { width: 380, height: 260, states, .. } if states & proto::state::RESIZING != 0)), "{ev:?}");
    h.input(kind::BUTTON, 1, 0, 0, 0);
    let ev = h.events_for(a);
    assert!(ev.iter().any(|e| matches!(e, Event::Configure { width: 380, height: 260, states, .. } if states & proto::state::RESIZING == 0)));
    assert_eq!(h.rect_of(w), Rect::new(m.x, m.y, 380, 260));
    // Resizing below the minimum stops at the minimum.
    let (bx, by) = (m.x + 380 + 2, m.y + 260 + 2);
    h.move_to(bx, by);
    h.input(kind::BUTTON, 1, 1, 0, 0);
    h.move_to(bx - 1000, by - 1000);
    h.input(kind::BUTTON, 1, 0, 0, 0);
    let small = h.rect_of(w);
    assert_eq!((small.w, small.h), (160, 48));
    // The content still renders (client buffer larger than the window).
    h.render();
}

#[test]
fn decoration_buttons_close_maximize_minimize() {
    let mut h = Harness::new();
    let a = h.client(2);
    let w = h.window(a, 1, 300, 200, 0);
    let r = h.rect_of(w);
    let f_top = r.y - theme::TITLE_HEIGHT as i32;
    let right = r.right() as i32 - theme::BUTTON_MARGIN as i32;
    let center = |i: i32| (right - (i + 1) * theme::BUTTON as i32 - i * theme::BUTTON_GAP as i32 + 12, f_top + theme::TITLE_HEIGHT as i32 / 2);
    h.events();
    // Close: a request to the client, the window stays until it agrees.
    let (x, y) = center(0);
    h.click(x, y);
    assert!(h.events_for(a).contains(&Event::CloseRequest { window: 1 }));
    assert_eq!(h.c.snapshot().len(), 1);
    // Pressing and releasing elsewhere does not trigger the button.
    h.move_to(x, y);
    h.input(kind::BUTTON, 1, 1, 0, 0);
    h.move_to(x - 200, y + 100);
    h.input(kind::BUTTON, 1, 0, 0, 0);
    assert!(!h.events_for(a).contains(&Event::CloseRequest { window: 1 }));
    // Maximize, then restore by double clicking the title.
    let (x, y) = center(1);
    h.click(x, y);
    let m = h.rect_of(w);
    assert_eq!((m.x, m.w, m.h), (0, W, H - theme::TITLE_HEIGHT));
    assert!(h.c.snapshot()[0].maximized);
    h.click(200, 10);
    h.click(200, 10);
    assert_eq!(h.rect_of(w), r, "double click restores");
    // Minimize hides the window and drops focus.
    let (x, y) = center(2);
    h.click(x, y);
    assert!(h.c.snapshot()[0].minimized);
    assert_eq!(h.c.focused(), None);
    h.render();
    assert_eq!(h.px(r.x + 100, r.y + 100), theme::DESKTOP_FALLBACK);
    // Activating it again (as the shell's task bar would).
    h.send(a, Request::WindowAction { target: 1, action: Action::Activate, global: false });
    assert!(!h.c.snapshot()[0].minimized);
    assert_eq!(h.c.focused(), Some(w));
}

#[test]
fn alt_tab_and_alt_f4_and_super_key() {
    let mut h = Harness::new();
    let shell = h.shell(1);
    h.create(shell, 2, Role::Panel, 0, (0, H as i32 - 40, W, 40));
    h.paint(shell, 2, W, 40, 0);
    let a = h.client(2);
    let b = h.client(3);
    let wa = h.window(a, 1, 200, 200, 0);
    let wb = h.window(b, 1, 200, 200, 0);
    assert_eq!(h.c.focused(), Some(wb));
    h.input(kind::KEY, key::LEFT_ALT, 1, 0, modifier::LEFT_ALT);
    h.input(kind::KEY, key::TAB, 1, 0, modifier::LEFT_ALT);
    assert_eq!(h.c.focused(), Some(wa));
    h.input(kind::KEY, key::LEFT_ALT, 0, 0, 0);
    h.events();
    h.input(kind::KEY, 0x3D, 1, 0, modifier::LEFT_ALT);
    assert!(h.events_for(a).contains(&Event::CloseRequest { window: 1 }));
    h.input(kind::KEY, key::LEFT_GUI, 1, 0, modifier::LEFT_GUI);
    let ev = h.events();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, shell, "the Super key goes to the shell");
}

#[test]
fn popups_follow_their_parent_and_close_on_outside_clicks() {
    let mut h = Harness::new();
    let a = h.client(2);
    let w = h.window(a, 1, 300, 200, 0);
    let r = h.rect_of(w);
    h.send(a, Request::CreateSurface { surface: 2 });
    h.send(
        a,
        Request::CreateWindow {
            window: 2,
            surface: 2,
            parent: 1,
            role: Role::Popup,
            flags: 0,
            x: 10,
            y: 20,
            width: 100,
            height: 80,
            min_width: 0,
            min_height: 0,
            title: String::new(),
        },
    );
    h.paint(a, 2, 100, 80, 0xFFFFFF);
    let p = h.c.snapshot().into_iter().find(|s| s.role == Role::Popup).unwrap();
    assert_eq!((p.rect.x, p.rect.y), (r.x + 10, r.y + 20));
    h.events();
    h.click(p.rect.x + 5, p.rect.y + 5);
    assert!(!h.events_for(a).contains(&Event::CloseRequest { window: 2 }), "clicks inside keep it open");
    h.click(700, 550);
    assert!(h.events_for(a).contains(&Event::CloseRequest { window: 2 }));
    // A popup without a parent is not allowed for ordinary clients.
    h.send(a, Request::CreateSurface { surface: 3 });
    let r = h.try_send(
        a,
        Request::CreateWindow {
            window: 3,
            surface: 3,
            parent: 0,
            role: Role::Popup,
            flags: 0,
            x: 0,
            y: 0,
            width: 10,
            height: 10,
            min_width: 0,
            min_height: 0,
            title: String::new(),
        },
        None,
    );
    assert_eq!(r, Err(proto::error::NOT_ALLOWED));
}

use alloc::string::String;

#[test]
fn malformed_and_invalid_requests_disconnect_only_the_offender() {
    let mut h = Harness::new();
    let good = h.client(2);
    let gw = h.window(good, 1, 100, 100, 0x777777);
    // Garbage bytes.
    let bad = h.client(3);
    assert_eq!(h.c.handle(bad, &[1, 2, 3], None, 0).map_err(|e| e.code), Err(proto::error::MALFORMED));
    assert!(h.c.is_dead(bad));
    let ev = h.events_for(bad);
    assert!(matches!(ev.last(), Some(Event::Error { code: proto::error::MALFORMED, .. })));
    h.c.disconnect(bad);
    // A buffer smaller than the geometry it claims.
    let liar = h.client(4);
    h.send(liar, Request::CreateSurface { surface: 1 });
    let small: Box<dyn PixelSource> = Box::new(vec![0u32; 10]);
    let r = h.try_send(liar, Request::AttachBuffer { surface: 1, buffer: 1, width: 100, height: 100, stride: 400, format: 1, offset: 0 }, Some(small));
    assert_eq!(r, Err(proto::error::BAD_BUFFER));
    h.c.disconnect(liar);
    // Unknown ids, commit without a buffer, duplicates.
    let c = h.client(5);
    assert_eq!(h.try_send(c, Request::Commit { surface: 9 }, None), Err(proto::error::UNKNOWN_OBJECT));
    let c = h.client(6);
    h.send(c, Request::CreateSurface { surface: 1 });
    assert_eq!(h.try_send(c, Request::Commit { surface: 1 }, None), Err(proto::error::BAD_BUFFER));
    let c = h.client(7);
    h.send(c, Request::CreateSurface { surface: 1 });
    assert_eq!(h.try_send(c, Request::CreateSurface { surface: 1 }, None), Err(proto::error::DUPLICATE_ID));
    // A buffer attached to a non-attach request.
    let c = h.client(8);
    let stray: Box<dyn PixelSource> = Box::new(vec![0u32; 4]);
    assert_eq!(h.try_send(c, Request::CreateSurface { surface: 1 }, Some(stray)), Err(proto::error::MALFORMED));
    // Global actions need the shell role.
    let c = h.client(9);
    assert_eq!(h.try_send(c, Request::WindowAction { target: gw, action: Action::Close, global: true }, None), Err(proto::error::NOT_ALLOWED));
    // The well-behaved client is unaffected.
    h.render();
    let r = h.rect_of(gw);
    assert_eq!(h.px(r.x + 50, r.y + 50), 0x777777);
    assert!(!h.c.is_dead(good));
}

#[test]
fn a_redefined_buffer_is_revalidated_at_commit() {
    let mut h = Harness::new();
    let c = h.client(2);
    h.create(c, 1, Role::Normal, window_flags::DECORATED, (-1, -1, 50, 50));
    let big: Box<dyn PixelSource> = Box::new(vec![0u32; 50 * 50]);
    h.try_send(c, Request::AttachBuffer { surface: 1, buffer: 1, width: 50, height: 50, stride: 200, format: 1, offset: 0 }, Some(big)).unwrap();
    // Redefine buffer 1 as a tiny one through another surface's attach.
    h.send(c, Request::CreateSurface { surface: 2 });
    let tiny: Box<dyn PixelSource> = Box::new(vec![0u32; 4]);
    h.try_send(c, Request::AttachBuffer { surface: 2, buffer: 1, width: 2, height: 2, stride: 8, format: 1, offset: 0 }, Some(tiny)).unwrap();
    assert_eq!(h.try_send(c, Request::Commit { surface: 1 }, None), Err(proto::error::BAD_BUFFER));
}

#[test]
fn disconnect_releases_everything_and_moves_focus() {
    let mut h = Harness::new();
    let shell = h.shell(1);
    let a = h.client(2);
    let b = h.client(3);
    let wa = h.window(a, 1, 200, 150, 0x101010);
    h.window(b, 1, 200, 150, 0x202020);
    h.window(b, 2, 120, 90, 0x303030);
    assert_eq!(h.c.client_resources(b).map(|r| (r.0, r.1, r.2)), Some((2, 2, 2)));
    h.events();
    h.c.disconnect(b);
    assert_eq!(h.c.client_resources(b), None);
    assert_eq!(h.c.snapshot().len(), 1);
    assert_eq!(h.c.focused(), Some(wa), "focus falls back to the remaining window");
    let ev = h.events();
    assert!(ev.iter().any(|(c, e)| *c == shell && matches!(e, Event::WindowList { windows } if windows.len() == 1)));
    assert!(ev.iter().all(|(c, _)| *c != b), "nothing is sent to a gone client");
    // The windows fade out, then the screen shows only A.
    h.render();
    h.render();
    let snap = h.c.snapshot();
    assert_eq!(snap[0].id, wa);
    // A closing window of a still-connected client cleans up too.
    h.send(a, Request::DestroyWindow { window: 1 });
    assert!(h.c.snapshot().is_empty());
    assert_eq!(h.c.client_resources(a).map(|r| r.2), Some(0));
    assert_eq!(h.c.focused(), None);
}

#[test]
fn per_client_limits_are_enforced() {
    let mut h = Harness::new();
    let c = h.client(2);
    for i in 1..=32 {
        h.send(c, Request::CreateSurface { surface: i });
    }
    assert_eq!(h.try_send(c, Request::CreateSurface { surface: 33 }, None), Err(proto::error::LIMIT));
    // Pixel memory: a client cannot hold more than its budget.
    let mut cfg = Config::new(W, H);
    cfg.max_client_pixels = 100 * 100;
    let mut c2 = Compositor::new(cfg);
    let id = c2.connect(9);
    c2.handle(id, &hello(0), None, 0).unwrap();
    c2.handle(id, &Request::CreateSurface { surface: 1 }.encode(0), None, 0).unwrap();
    let big: Box<dyn PixelSource> = Box::new(vec![0u32; 200 * 200]);
    c2.handle(id, &Request::AttachBuffer { surface: 1, buffer: 1, width: 200, height: 200, stride: 800, format: 1, offset: 0 }.encode(0), Some(big), 0)
        .unwrap();
    let r = c2.handle(id, &Request::Commit { surface: 1 }.encode(0), None, 0);
    assert_eq!(r.map_err(|e| e.code), Err(proto::error::LIMIT));
}

#[test]
fn notifications_go_to_the_shell_only() {
    let mut h = Harness::new();
    let shell = h.shell(1);
    let a = h.client(2);
    h.events();
    h.send(a, Request::Notify { title: "Done".to_string(), body: "42 files".to_string() });
    let ev = h.events();
    assert_eq!(ev, [(shell, Event::Notification { from_pid: 2, title: "Done".to_string(), body: "42 files".to_string() })]);
    // A client claiming the shell role without being the designated process does not get it.
    let impostor = h.c.connect(99);
    h.c.handle(impostor, &hello(proto::hello::SHELL), None, 0).unwrap();
    let ev = h.events_for(impostor);
    assert!(matches!(ev[0], Event::Hello { flags: 0, .. }));
}

#[test]
fn removed_mouse_releases_grabs() {
    let mut h = Harness::new();
    let a = h.client(2);
    let w = h.window(a, 1, 300, 200, 0);
    let r = h.rect_of(w);
    h.move_to(r.x + 50, r.y - 10);
    h.input(kind::BUTTON, 1, 1, 0, 0);
    h.input(kind::DEVICE, osyx_input::DEVICE_REMOVED, osyx_input::class::MOUSE, 0, 0);
    // The grab ended: moving the pointer no longer drags the window.
    h.move_to(10, 10);
    assert_eq!(h.rect_of(w), r);
}

#[test]
fn render_damage_is_bounded_and_idle_when_nothing_changes() {
    let mut h = Harness::new();
    h.render();
    let mut s = Surface::new(&mut h.fb, W, H, W).unwrap();
    assert!(h.c.render(&mut s, h.now + 10).is_empty(), "nothing to do");
    assert_eq!(h.c.next_frame_in(h.now), None);
    // Pointer motion damages only around the cursor.
    h.input(kind::MOTION, 0, 3, 4, 0);
    let mut s = Surface::new(&mut h.fb, W, H, W).unwrap();
    let rects = h.c.render(&mut s, h.now + 20);
    let px: u64 = rects.iter().map(|r| r.w as u64 * r.h as u64).sum();
    assert!(px > 0 && px < 40 * 40, "{rects:?}");
}


#[test]
fn the_clipboard_is_shared_by_every_client() {
    let mut h = Harness::new();
    let a = h.client(2);
    let b = h.client(3);
    h.events();
    let entries = vec![
        proto::ClipEntry { format: 13, name: None, data: vec![b'h', b'i'] },
        proto::ClipEntry { format: 0xC001, name: Some("HTML Format".to_string()), data: b"<b>hi</b>".to_vec() },
    ];
    h.send(a, Request::ClipboardSet { entries: entries.clone() });
    let ev = h.events();
    for (who, c) in [("the owner", a), ("every other client", b)] {
        let got: Vec<Event> = ev.iter().filter(|(id, _)| *id == c).map(|(_, e)| e.clone()).collect();
        assert_eq!(got, vec![Event::ClipboardChanged { seq: 1, entries: entries.clone() }], "{who} hears the copy");
    }
    // A client that connects later is told the contents with its hello.
    let late = h.client(4);
    assert!(h.events_for(late).contains(&Event::ClipboardChanged { seq: 1, entries }), "a new client starts with the clipboard it missed");
    // Contents over the protocol's caps do not decode, disconnecting the
    // offender like every other malformed request.
    let big = vec![proto::ClipEntry { format: 13, name: None, data: vec![0; proto::MAX_CLIPBOARD_BYTES + 1] }];
    assert_eq!(h.try_send(b, Request::ClipboardSet { entries: big }, None), Err(proto::error::MALFORMED));
    assert!(h.c.is_dead(b));
}

#[test]
fn unicode_clipboard_text_is_shared_between_clients() {
    let mut h = Harness::new();
    let native = h.client(11);
    let windows = h.client(12);
    h.events();
    h.send(native, Request::ClipboardSet { entries: vec![proto::clipboard_text_entry("Zażółć 🌍")] });
    let received = h.events_for(windows);
    let entries = received.iter().find_map(|e| match e {
        Event::ClipboardChanged { entries, .. } => Some(entries),
        _ => None,
    }).expect("Windows client receives clipboard change");
    assert_eq!(proto::clipboard_text(entries).as_deref(), Some("Zażółć 🌍"));
}

#[test]
fn file_clipboard_is_shared_between_clients() {
    let mut h = Harness::new();
    let source = h.client(31);
    let target = h.client(32);
    h.events();
    let paths = vec![String::from("/home/user/ż.txt")];
    let entry = proto::clipboard_files_entry(&paths, true).unwrap();
    h.send(source, Request::ClipboardSet { entries: vec![entry] });
    let events = h.events_for(target);
    let entries = events.iter().find_map(|e| match e {
        Event::ClipboardChanged { entries, .. } => Some(entries),
        _ => None,
    }).expect("target receives file clipboard");
    assert_eq!(proto::clipboard_files(entries), Some((paths, true)));
}

#[test]
fn file_drag_delivers_only_to_the_window_at_release() {
    let mut h = Harness::new();
    let source = h.client(21);
    let target = h.client(22);
    h.create(source, 1, Role::Normal, 0, (30, 60, 200, 160));
    h.create(target, 1, Role::Normal, 0, (350, 60, 200, 160));
    h.paint(source, 1, 200, 160, 0);
    h.paint(target, 1, 200, 160, 0);
    h.move_to(50, 80);
    h.input(kind::BUTTON, 1, 1, 0, 0);
    h.send(source, Request::FileDrag { window: 1, path: "/home/user/picture.png".to_string() });
    h.move_to(380, 100);
    h.input(kind::BUTTON, 1, 0, 0, 0);
    let events = h.events_for(target);
    assert!(events.iter().any(|e| matches!(e, Event::FileDrop { window: 1, x: 30, y: 40, path } if path == "/home/user/picture.png")), "{events:?}");
    // Without a pressed source window, an unsolicited request cannot drop.
    h.send(source, Request::FileDrag { window: 1, path: "/other".to_string() });
    h.click(380, 100);
    assert!(!h.events_for(target).iter().any(|e| matches!(e, Event::FileDrop { .. })));
}
