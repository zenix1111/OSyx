//! AXIS Terminal (`/system/bin/terminal`): a graphical terminal running the
//! AXIS shell (`/bin/axis`) on pipes. Commands are real: the shell runs
//! them on the OSyx file systems and programs from the root file system,
//! and their output is what is shown.
//!
//! Keys: Enter runs the line, Up/Down walk the history, Ctrl+C stops the
//! shell and starts a new one, Ctrl+L clears, Ctrl+D ends the shell,
//! PageUp/PageDown and the wheel scroll back.

#![no_std]
#![no_main]

#[path = "../shell_common.rs"]
mod common;

use common::{become_user, run_app, App, Ctx};
use os_std::io::{Read, Write};
use os_std::ipc::{self, PipeReader, PipeWriter, WaitItem, WAIT_HANGUP, WAIT_READABLE};
use os_std::prelude::*;
use os_std::process::{Child, Command};
use os_std::system;
use osyx_gfx::{rgb, Color, Rect};
use osyx_input::key;
use osyx_ui::{Event as Ui, FontKind, Painter};
use prism_client::WindowSpec;

os_std::entry!(main);

const SHELL: &str = "/bin/axis";
const SCROLLBACK: usize = 3000;
const PAD: u32 = 10;

const BG: Color = rgb(9, 12, 18);
const FG: Color = rgb(214, 221, 234);
const CURSOR: Color = rgb(76, 141, 255);
const ANSI: [Color; 8] = [rgb(70, 78, 96), rgb(240, 98, 110), rgb(110, 214, 150), rgb(236, 190, 100), rgb(96, 150, 255), rgb(196, 136, 236), rgb(96, 206, 220), rgb(220, 226, 236)];
const ANSI_BRIGHT: [Color; 8] = [rgb(110, 118, 138), rgb(255, 130, 140), rgb(140, 236, 176), rgb(250, 214, 130), rgb(130, 176, 255), rgb(220, 166, 250), rgb(130, 226, 236), rgb(250, 252, 255)];

#[derive(Clone, Copy)]
struct Cell {
    ch: char,
    fg: Color,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Esc {
    None,
    Start,
    Csi,
}

struct Terminal {
    lines: VecDeque<Vec<Cell>>,
    cur: Vec<Cell>,
    col: usize,
    fg: Color,
    esc: Esc,
    csi: String,
    utf8: Vec<u8>,
    input: String,
    cursor: usize,
    history: Vec<String>,
    hist_pos: Option<usize>,
    /// Visual rows scrolled back from the bottom.
    scroll: usize,
    cols: usize,
    rows: usize,
    child: Option<Child>,
    stdin: Option<PipeWriter>,
    stdout: Option<PipeReader>,
    /// The shell ended with an error: Enter starts a new one.
    ended: bool,
}

fn main() -> i32 {
    become_user();
    let mut t = Terminal {
        lines: VecDeque::new(),
        cur: Vec::new(),
        col: 0,
        fg: FG,
        esc: Esc::None,
        csi: String::new(),
        utf8: Vec::new(),
        input: String::new(),
        cursor: 0,
        history: Vec::new(),
        hist_pos: None,
        scroll: 0,
        cols: 80,
        rows: 24,
        child: None,
        stdin: None,
        stdout: None,
        ended: false,
    };
    t.start_shell();
    let mut spec = WindowSpec::normal("AXIS Terminal", 800, 500);
    spec.min_width = 360;
    spec.min_height = 200;
    let r = run_app("terminal", spec, &mut t);
    t.stop_shell();
    r
}

impl Terminal {
    fn start_shell(&mut self) {
        match Command::new(SHELL).spawn_piped() {
            Ok((child, stdin, stdout)) => {
                println!("terminal: AXIS shell started as process {}", child.id());
                self.child = Some(child);
                self.stdin = Some(stdin);
                self.stdout = Some(stdout);
                self.ended = false;
            }
            Err(e) => {
                self.output(format!("\x1b[91mcannot start {SHELL}: {e}\x1b[0m\n").as_bytes());
                self.ended = true;
            }
        }
    }

    fn stop_shell(&mut self) {
        self.stdin = None;
        self.stdout = None;
        if let Some(c) = self.child.take() {
            let _ = system::kill(c.id());
            let _ = c.wait();
        }
    }

    fn newline(&mut self) {
        self.lines.push_back(core::mem::take(&mut self.cur));
        self.col = 0;
        while self.lines.len() > SCROLLBACK {
            self.lines.pop_front();
        }
    }

    fn put(&mut self, ch: char) {
        let cell = Cell { ch, fg: self.fg };
        if self.col < self.cur.len() {
            self.cur[self.col] = cell;
        } else {
            self.cur.push(cell);
        }
        self.col += 1;
    }

    fn sgr(&mut self) {
        let params: Vec<u32> = if self.csi.is_empty() { vec![0] } else { self.csi.split(';').map(|p| p.parse().unwrap_or(0)).collect() };
        for p in params {
            self.fg = match p {
                0 | 39 => FG,
                30..=37 => ANSI[(p - 30) as usize],
                90..=97 => ANSI_BRIGHT[(p - 90) as usize],
                _ => self.fg,
            };
        }
    }

    fn control(&mut self, ch: char) {
        match self.esc {
            Esc::Start => {
                self.esc = if ch == '[' { Esc::Csi } else { Esc::None };
                self.csi.clear();
            }
            Esc::Csi => {
                if ch.is_ascii_digit() || ch == ';' {
                    if self.csi.len() < 32 {
                        self.csi.push(ch);
                    }
                    return;
                }
                self.esc = Esc::None;
                match ch {
                    'm' => self.sgr(),
                    'J' => self.clear(),
                    'K' => self.cur.truncate(self.col),
                    _ => {}
                }
            }
            Esc::None => {}
        }
    }

    fn clear(&mut self) {
        self.lines.clear();
        self.cur.clear();
        self.col = 0;
        self.scroll = 0;
    }

    /// Feeds shell output (UTF-8, possibly split mid-character).
    fn output(&mut self, bytes: &[u8]) {
        self.utf8.extend_from_slice(bytes);
        let data = core::mem::take(&mut self.utf8);
        let (text, rest) = match core::str::from_utf8(&data) {
            Ok(s) => (String::from(s), Vec::new()),
            Err(e) if e.error_len().is_none() => {
                let valid = e.valid_up_to();
                (String::from_utf8_lossy(&data[..valid]).into_owned(), data[valid..].to_vec())
            }
            Err(_) => (String::from_utf8_lossy(&data).into_owned(), Vec::new()),
        };
        self.utf8 = rest;
        for ch in text.chars() {
            if self.esc != Esc::None {
                self.control(ch);
                continue;
            }
            match ch {
                '\x1b' => self.esc = Esc::Start,
                '\n' => self.newline(),
                '\r' => self.col = 0,
                '\x08' => self.col = self.col.saturating_sub(1),
                '\t' => {
                    let to = (self.col / 8 + 1) * 8;
                    while self.col < to {
                        self.put(' ');
                    }
                }
                '\x0c' => self.clear(),
                c if c.is_control() => {}
                c => self.put(c),
            }
        }
        self.scroll = 0;
    }

    fn send_line(&mut self) {
        let line = core::mem::take(&mut self.input);
        self.cursor = 0;
        self.hist_pos = None;
        // Echo the line after the prompt, like a terminal in line mode.
        let fg = self.fg;
        self.fg = FG;
        for c in line.chars() {
            self.put(c);
        }
        self.fg = fg;
        self.newline();
        println!("terminal: command {line:?}");
        if !line.trim().is_empty() && self.history.last() != Some(&line) {
            self.history.push(line.clone());
        }
        if self.ended {
            self.start_shell();
            return;
        }
        if let Some(w) = &mut self.stdin {
            let mut data = line.into_bytes();
            data.push(b'\n');
            if let Err(e) = w.write_all(&data) {
                self.output(format!("\x1b[91m[cannot reach the shell: {e}]\x1b[0m\n").as_bytes());
            }
        }
    }

    fn key(&mut self, k: osyx_ui::KeyEvent) -> bool {
        if !k.down {
            return false;
        }
        if k.ctrl() {
            match k.key {
                key::C => {
                    self.output(b"^C\n");
                    self.stop_shell();
                    self.output(b"\x1b[93m[shell stopped; starting a new one]\x1b[0m\n");
                    self.input.clear();
                    self.cursor = 0;
                    self.start_shell();
                    return true;
                }
                key::L => {
                    self.clear();
                    return true;
                }
                key::D if self.input.is_empty() => {
                    self.stdin = None; // end of input: the shell exits
                    return true;
                }
                _ => return false,
            }
        }
        match k.key {
            key::ENTER | key::KP_ENTER => self.send_line(),
            key::BACKSPACE => {
                if let Some((i, _)) = self.input[..self.cursor].char_indices().next_back() {
                    self.input.replace_range(i..self.cursor, "");
                    self.cursor = i;
                }
            }
            key::DELETE => {
                if let Some(c) = self.input[self.cursor..].chars().next() {
                    self.input.replace_range(self.cursor..self.cursor + c.len_utf8(), "");
                }
            }
            key::LEFT => self.cursor = self.input[..self.cursor].char_indices().next_back().map_or(0, |(i, _)| i),
            key::RIGHT => self.cursor = self.input[self.cursor..].chars().next().map_or(self.cursor, |c| self.cursor + c.len_utf8()),
            key::HOME => self.cursor = 0,
            key::END => self.cursor = self.input.len(),
            key::UP | key::DOWN => {
                if self.history.is_empty() {
                    return false;
                }
                let n = self.history.len();
                let pos = match (self.hist_pos, k.key == key::UP) {
                    (None, true) => Some(n - 1),
                    (None, false) => None,
                    (Some(p), true) => Some(p.saturating_sub(1)),
                    (Some(p), false) if p + 1 < n => Some(p + 1),
                    (Some(_), false) => None,
                };
                self.hist_pos = pos;
                self.input = pos.map_or_else(String::new, |p| self.history[p].clone());
                self.cursor = self.input.len();
            }
            key::PAGE_UP => {
                self.scroll += self.rows.saturating_sub(2).max(1);
                return true;
            }
            key::PAGE_DOWN => {
                self.scroll = self.scroll.saturating_sub(self.rows.saturating_sub(2).max(1));
                return true;
            }
            _ => match k.insertable() {
                Some(c) => {
                    self.input.insert(self.cursor, c);
                    self.cursor += c.len_utf8();
                }
                None => return false,
            },
        }
        self.scroll = 0;
        true
    }

    /// Visual rows: every logical line cut into `cols` cells; the last line
    /// is the current output line followed by the input being typed.
    fn visual_rows(&self) -> (Vec<Vec<Cell>>, Option<(usize, usize)>) {
        let cols = self.cols.max(1);
        let mut rows = Vec::new();
        for l in &self.lines {
            if l.is_empty() {
                rows.push(Vec::new());
            }
            for chunk in l.chunks(cols) {
                rows.push(chunk.to_vec());
            }
        }
        let mut last: Vec<Cell> = self.cur.clone();
        let cursor_index = last.len() + self.input[..self.cursor].chars().count();
        last.extend(self.input.chars().map(|ch| Cell { ch, fg: FG }));
        let first_row = rows.len();
        if last.is_empty() {
            rows.push(Vec::new());
        }
        for chunk in last.chunks(cols) {
            rows.push(chunk.to_vec());
        }
        if cursor_index == last.len() && !last.is_empty() && last.len().is_multiple_of(cols) {
            rows.push(Vec::new());
        }
        let cursor = (first_row + cursor_index / cols, cursor_index % cols);
        (rows, Some(cursor))
    }
}

impl App for Terminal {
    fn layout(&mut self, w: u32, h: u32, cx: &mut Ctx) {
        let cw = cx.fonts.mono.cell_width().max(1);
        let ch = cx.fonts.mono.line_height().max(1);
        self.cols = (w.saturating_sub(2 * PAD) / cw).max(10) as usize;
        self.rows = (h.saturating_sub(2 * PAD) / ch).max(3) as usize;
    }

    fn event(&mut self, ev: Ui, cx: &mut Ctx) -> bool {
        match ev {
            Ui::Key(k) if k.down && k.ctrl() && k.key == key::V => {
                if let Some(text) = cx.clipboard.text() {
                    // Keep pasted newlines from executing commands implicitly.
                    let text: String = text.chars().filter(|c| !c.is_control()).collect();
                    self.input.insert_str(self.cursor, &text);
                    self.cursor += text.len();
                    self.scroll = 0;
                    true
                } else {
                    false
                }
            }
            Ui::Key(k) => self.key(k),
            Ui::Wheel { dy, .. } => {
                let before = self.scroll;
                if dy > 0 {
                    self.scroll += 3 * dy as usize;
                } else {
                    self.scroll = self.scroll.saturating_sub(3 * (-dy) as usize);
                }
                before != self.scroll
            }
            _ => false,
        }
    }

    fn wait_items(&self) -> Vec<WaitItem> {
        self.stdout.as_ref().map(|r| vec![ipc::item(r.handle(), WAIT_READABLE)]).unwrap_or_default()
    }

    fn ready(&mut self, items: &[WaitItem], cx: &mut Ctx) -> bool {
        if items.first().is_none_or(|i| i.revents & (WAIT_READABLE | WAIT_HANGUP) == 0) {
            return false;
        }
        let mut buf = [0u8; 4096];
        let n = match self.stdout.as_mut().map(|r| r.read(&mut buf)) {
            Some(Ok(n)) => n,
            Some(Err(_)) | None => 0,
        };
        if n > 0 {
            self.output(&buf[..n]);
            return true;
        }
        // End of output: the shell has exited.
        self.stdout = None;
        self.stdin = None;
        let status = self.child.take().and_then(|c| c.wait().ok());
        match status {
            Some(s) if s.success() => {
                println!("terminal: shell exited; closing");
                cx.quit = true;
            }
            Some(s) => {
                self.output(format!("\x1b[93m[AXIS ended with status {:#x}; press Enter for a new shell]\x1b[0m\n", s.raw()).as_bytes());
                self.ended = true;
            }
            None => self.ended = true,
        }
        true
    }

    fn draw(&mut self, p: &mut Painter, w: u32, h: u32, cx: &Ctx) {
        p.fill(Rect::new(0, 0, w, h), BG);
        let cw = cx.fonts.mono.cell_width() as i32;
        let ch = cx.fonts.mono.line_height() as i32;
        let (rows, cursor) = self.visual_rows();
        let max_scroll = rows.len().saturating_sub(self.rows);
        self.scroll = self.scroll.min(max_scroll);
        let end = rows.len() - self.scroll;
        let start = end.saturating_sub(self.rows);
        let mut buf = [0u8; 4];
        for (vi, row) in rows[start..end].iter().enumerate() {
            let y = PAD as i32 + vi as i32 * ch;
            // Runs of one colour are drawn as one string.
            let mut x = PAD as i32;
            let mut i = 0;
            while i < row.len() {
                let fg = row[i].fg;
                let mut s = String::new();
                while i < row.len() && row[i].fg == fg {
                    s.push_str(row[i].ch.encode_utf8(&mut buf));
                    i += 1;
                }
                let n = s.chars().count() as i32;
                p.text(FontKind::Mono, x, y, &s, fg);
                x += n * cw;
            }
        }
        if let Some((cr, cc)) = cursor {
            if cr >= start && cr < end {
                let x = PAD as i32 + cc as i32 * cw;
                let y = PAD as i32 + (cr - start) as i32 * ch;
                if cx.focused {
                    p.fill(Rect::new(x, y + 1, cw as u32, (ch - 2) as u32), CURSOR);
                    let under = rows[cr].get(cc).map(|c| c.ch).unwrap_or(' ');
                    if under != ' ' {
                        p.text(FontKind::Mono, x, y, under.encode_utf8(&mut buf), BG);
                    }
                } else {
                    p.fill(Rect::new(x, y + ch - 3, cw as u32, 2), CURSOR);
                }
            }
        }
        if self.scroll > 0 {
            let label = format!("scrolled back {} lines", self.scroll);
            let lw = cx.fonts.measure(FontKind::Ui, &label) + 20;
            let r = Rect::new(w as i32 - lw as i32 - 12, 8, lw, 26);
            p.rounded(r, 8, cx.theme.raised, 230);
            p.text_in(FontKind::Ui, r, &label, cx.theme.text_dim, osyx_ui::Align::Center);
        }
    }

    fn close_requested(&mut self, _cx: &mut Ctx) -> bool {
        self.stop_shell();
        true
    }
}
