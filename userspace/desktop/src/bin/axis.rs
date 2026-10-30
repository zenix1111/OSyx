//! AXIS, the OSyx command shell (`/bin/axis`), first version.
//!
//! Reads commands from standard input (the AXIS Terminal connects it to
//! pipes) or from a script file (`axis script.ax`). A line is either a
//! command or a small Python-flavoured statement:
//!
//! ```text
//! ls -l /osyx-seed            # built-in commands work on the real file systems
//! name = "OSyx"               # variables
//! count = 2 + 3
//! print("Hello from", name, count)
//! echo $name has $count       # $variables expand in command words; $? = last status
//! worker exit 3               # anything else runs a program from /bin, /usr/bin, /system/bin
//! ```
//!
//! Programs inherit the shell's standard streams, so their output appears
//! in the terminal. `<`, `>` and `>>` redirect standard input/output of a
//! command (built-ins included) and `|` connects programs into a pipeline
//! (one built-in per pipeline). `if cond { ... } else { ... }` and
//! `for name in words { ... }` group lines; `cond` is an expression with
//! `== != < > <= >=`. Not implemented yet: job control.

#![no_std]
#![no_main]

use os_std::fs::{self, File};
use os_std::os::raw::HANDLE_NONE;
use os_std::prelude::*;
use os_std::process::{Command, ExitStatus};
use os_std::time::Instant;
use os_std::{env, io, ipc, os, system};
use osyx_shell::block::{self, Stmt};
use osyx_shell::{parse, Stage};

os_std::entry!(main);

const SEARCH: [&str; 3] = ["/bin", "/usr/bin", "/system/bin"];

struct Shell {
    vars: BTreeMap<String, String>,
    last: i32,
    history: Vec<String>,
}

fn main() -> i32 {
    let args: Vec<String> = env::args().collect();
    let mut sh = Shell { vars: BTreeMap::new(), last: 0, history: Vec::new() };
    if let Some(script) = args.get(1) {
        return match fs::read_to_string(script) {
            Ok(text) => {
                let lines: Vec<&str> = text.lines().collect();
                match block::parse_script(&lines) {
                    Ok(stmts) => {
                        sh.run(&stmts);
                        sh.last
                    }
                    Err(e) => {
                        eprintln!("axis: {script}: {e}");
                        2
                    }
                }
            }
            Err(e) => {
                eprintln!("axis: {script}: {e}");
                127
            }
        };
    }
    println!("AXIS shell on OSyx {} - type `help` for commands", kernel_version());
    let mut pending = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        prompt();
        let mut lines: Vec<String> = Vec::new();
        loop {
            let Some(line) = read_line(&mut pending, &mut buf) else { return sh.last };
            let line = String::from(line.trim_end_matches('\r'));
            if !line.trim().is_empty() {
                sh.history.push(line.clone());
            }
            lines.push(line);
            let block_lines: Vec<&str> = lines.iter().map(String::as_str).collect();
            let d = match block::depth(&block_lines) {
                Ok(d) => d,
                Err(e) => {
                    sh.fail(&e);
                    break;
                }
            };
            if d > 0 {
                print!("... ");
                let _ = io::Write::flush(&mut io::stdout());
                continue;
            }
            if d < 0 {
                sh.fail("unexpected `}`");
                break;
            }
            match block::parse_script(&block_lines) {
                Ok(stmts) => {
                    if sh.run(&stmts).is_break() {
                        return sh.last;
                    }
                }
                Err(e) => sh.fail(&e),
            }
            break;
        }
    }
}

/// One line from standard input (it arrives in chunks); `None` at end.
fn read_line(pending: &mut Vec<u8>, buf: &mut [u8]) -> Option<String> {
    loop {
        if let Some(nl) = pending.iter().position(|&b| b == b'\n') {
            let rest = pending.split_off(nl + 1);
            let line = String::from_utf8_lossy(&pending[..nl]).into_owned();
            *pending = rest;
            return Some(line);
        }
        match io::Read::read(&mut io::stdin(), buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
        }
    }
}

fn kernel_version() -> String {
    os::sysinfo().map(|i| String::from(os::kernel_version(&i))).unwrap_or_else(|_| String::from("?"))
}

fn prompt() {
    let cwd = env::current_dir().map(|p| String::from(p.as_str())).unwrap_or_else(|_| String::from("?"));
    let home = env::var("HOME").unwrap_or_default();
    let shown = if !home.is_empty() && cwd.starts_with(&home) { format!("~{}", &cwd[home.len()..]) } else { cwd };
    let user = if os::getuid().0 == 0 { "root" } else { "user" };
    // ESC[...m colours are understood by the AXIS Terminal.
    print!("\x1b[94m{user}@osyx\x1b[0m:\x1b[96m{shown}\x1b[0m> ");
    let _ = io::Write::flush(&mut io::stdout());
}

enum Flow {
    Continue,
    Exit,
}

impl Flow {
    fn is_break(&self) -> bool {
        matches!(self, Flow::Exit)
    }
}

/// A value of the expression language.
#[derive(Clone, Debug)]
enum Value {
    Str(String),
    Int(i64),
}

impl Value {
    fn text(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Int(i) => format!("{i}"),
        }
    }
}

impl Shell {
    /// Runs parsed statements: commands, `if` and `for` blocks.
    fn run(&mut self, stmts: &[Stmt]) -> Flow {
        for st in stmts {
            let flow = match st {
                Stmt::Command(line) => self.line(line),
                Stmt::If { cond, then, alt } => match self.expr(cond) {
                    Ok(v) if truthy(&v) => self.run(then),
                    Ok(_) => self.run(alt),
                    Err(e) => {
                        self.fail(&e);
                        Flow::Continue
                    }
                },
                Stmt::For { name, words, body } => self.run_for(name, words, body),
            };
            if flow.is_break() {
                return flow;
            }
        }
        Flow::Continue
    }

    fn run_for(&mut self, name: &str, words: &str, body: &[Stmt]) -> Flow {
        let items = match self.words(words) {
            Ok(items) => items,
            Err(e) => {
                self.fail(&e);
                return Flow::Continue;
            }
        };
        for item in items {
            self.vars.insert(String::from(name), item);
            let flow = self.run(body);
            if flow.is_break() {
                return flow;
            }
        }
        Flow::Continue
    }

    fn line(&mut self, line: &str) -> Flow {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            return Flow::Continue;
        }
        // Statements: `print(...)`, `name = expr`.
        if let Some(inner) = line.strip_prefix("print(").and_then(|r| r.strip_suffix(')')) {
            match self.args_list(inner) {
                Ok(vals) => {
                    println!("{}", vals.iter().map(Value::text).collect::<Vec<_>>().join(" "));
                    self.last = 0;
                }
                Err(e) => self.fail(&e),
            }
            return Flow::Continue;
        }
        if let Some((name, expr)) = assignment(line) {
            match self.expr(expr) {
                Ok(v) => {
                    self.vars.insert(String::from(name), v.text());
                    self.last = 0;
                }
                Err(e) => self.fail(&e),
            }
            return Flow::Continue;
        }
        let stages = match parse(line) {
            Ok(s) => s,
            Err(e) => {
                self.fail(&e);
                return Flow::Continue;
            }
        };
        if stages.is_empty() {
            return Flow::Continue;
        }
        self.last = match self.pipeline(&stages) {
            Ok(code) => code,
            Err(Exit) => return Flow::Exit,
        };
        Flow::Continue
    }

    fn fail(&mut self, msg: &str) {
        eprintln!("axis: {msg}");
        self.last = 2;
    }

    // ---- expressions ---------------------------------------------------------

    fn args_list(&self, s: &str) -> Result<Vec<Value>, String> {
        split_top_level(s, ',').iter().filter(|p| !p.trim().is_empty()).map(|p| self.expr(p)).collect()
    }

    /// A comparison of two sums, or just a sum. Comparisons yield `Int(0)`
    /// or `Int(1)`.
    fn expr(&self, s: &str) -> Result<Value, String> {
        let toks = tokenize_expr(s)?;
        match toks.iter().position(|t| is_cmp(t)) {
            Some(i) => {
                if toks[i + 1..].iter().any(|t| is_cmp(t)) {
                    return Err(String::from("only one comparison per expression"));
                }
                let l = self.sum(&toks[..i])?;
                let r = self.sum(&toks[i + 1..])?;
                compare(&toks[i], &l, &r).map(|b| Value::Int(b as i64))
            }
            None => self.sum(&toks),
        }
    }

    /// `term (+|-|*) term ...`, left to right; `+` concatenates when either
    /// side is a string.
    fn sum(&self, toks: &[String]) -> Result<Value, String> {
        let mut it = toks.iter();
        let mut acc = self.term(it.next().ok_or("empty expression")?.clone())?;
        while let Some(op) = it.next() {
            let rhs = self.term(it.next().ok_or("operator without a right-hand side")?.clone())?;
            acc = match (op.as_str(), acc, rhs) {
                ("+", Value::Int(a), Value::Int(b)) => Value::Int(a.checked_add(b).ok_or("integer overflow")?),
                ("-", Value::Int(a), Value::Int(b)) => Value::Int(a.checked_sub(b).ok_or("integer overflow")?),
                ("*", Value::Int(a), Value::Int(b)) => Value::Int(a.checked_mul(b).ok_or("integer overflow")?),
                ("+", a, b) => Value::Str(a.text() + &b.text()),
                (op, _, _) => return Err(format!("unsupported operator {op:?} for strings")),
            };
        }
        Ok(acc)
    }

    fn term(&self, t: String) -> Result<Value, String> {
        if let Some(s) = t.strip_prefix('\u{1}') {
            return Ok(Value::Str(String::from(s)));
        }
        if let Some(name) = t.strip_prefix('$') {
            if name == "?" {
                return Ok(Value::Int(self.last as i64));
            }
            return self.term(String::from(name));
        }
        if let Ok(i) = t.parse::<i64>() {
            return Ok(Value::Int(i));
        }
        match t.as_str() {
            "cwd()" => return Ok(Value::Str(env::current_dir().map(|p| String::from(p.as_str())).unwrap_or_default())),
            "status" => return Ok(Value::Int(self.last as i64)),
            _ => {}
        }
        match self.vars.get(&t) {
            Some(v) => Ok(v.parse::<i64>().map(Value::Int).unwrap_or_else(|_| Value::Str(v.clone()))),
            None => env::var(&t).map(Value::Str).map_err(|_| format!("name {t:?} is not defined")),
        }
    }

    /// Splits a command line into words: quotes group, `$name` expands.
    fn words(&self, line: &str) -> Result<Vec<String>, String> {
        let mut words = Vec::new();
        let mut cur = String::new();
        let mut in_word = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' | '\'' => {
                    in_word = true;
                    loop {
                        match chars.next() {
                            Some(q) if q == c => break,
                            Some('$') if c == '"' => cur.push_str(&self.expand_var(&mut chars)),
                            Some(ch) => cur.push(ch),
                            None => return Err(String::from("unterminated quote")),
                        }
                    }
                }
                '$' => {
                    in_word = true;
                    cur.push_str(&self.expand_var(&mut chars));
                }
                c if c.is_whitespace() => {
                    if in_word {
                        words.push(core::mem::take(&mut cur));
                        in_word = false;
                    }
                }
                c => {
                    in_word = true;
                    cur.push(c);
                }
            }
        }
        if in_word {
            words.push(cur);
        }
        Ok(words)
    }

    fn expand_var(&self, chars: &mut core::iter::Peekable<core::str::Chars>) -> String {
        if chars.peek() == Some(&'?') {
            chars.next();
            return format!("{}", self.last);
        }
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_alphanumeric() || c == '_' {
                name.push(c);
                chars.next();
            } else {
                break;
            }
        }
        if name.is_empty() {
            return String::from("$");
        }
        self.vars.get(&name).cloned().or_else(|| env::var(&name).ok()).unwrap_or_default()
    }

    // ---- commands --------------------------------------------------------------

    fn builtin(&mut self, cmd: &str, args: &[&str]) -> Option<Result<i32, Exit>> {
        let r = match cmd {
            "exit" => return Some(Err(Exit)),
            "help" => {
                println!("Built-in commands:");
                println!("  cd pwd ls cat echo mkdir rmdir rm touch mv cp stat");
                println!("  ps kill mounts df free uptime uname whoami env history clear help exit");
                println!("  devices [WORD]  (alias lsdev): hardware, e.g. `devices wireless`, `devices bluetooth`");
                println!("  wifi [status|scan|connect SSID [PASSWORD]|disconnect]: Wi-Fi");
                println!("  volume [0-100|mute|unmute], beep [HZ [MS]], play FILE.wav: sound");
                println!("  dmesg [WORD]: kernel log (only lines containing WORD), e.g. `dmesg iwm`");
                println!("Statements: name = expr   print(expr, ...)   $name in commands, $? = last status");
                println!("Blocks: if a == b {{ ... }} else {{ ... }}   for x in a b {{ ... }}");
                println!("Redirection: cmd < in, cmd > out, cmd >> out; pipelines: cmd | cmd | ...");
                println!("Network: ping HOST, net list|info|configure, dns lookup NAME, netstat [-a|-s], nc");
                println!("Other words run programs from /bin, /usr/bin and /system/bin.");
                Ok(0)
            }
            "pwd" => env::current_dir().map(|p| println!("{}", p.as_str())).map(|_| 0),
            "cd" => {
                let home = env::var("HOME").unwrap_or_else(|_| String::from("/"));
                let target = args.first().copied().unwrap_or(&home);
                env::set_current_dir(target).map(|_| 0)
            }
            "echo" => {
                println!("{}", args.join(" "));
                Ok(0)
            }
            "ls" => cmd_ls(args),
            "cat" => cmd_cat(args),
            "mkdir" => each(args, |a| fs::create_dir(a)),
            "rmdir" => each(args, |a| fs::remove_dir(a)),
            "rm" => {
                let recursive = args.first() == Some(&"-r");
                let rest = if recursive { &args[1..] } else { args };
                each(rest, |a| if recursive { fs::remove_dir_all(a) } else { fs::remove_file(a) })
            }
            "touch" => each(args, |a| File::options().write(true).create(true).open(a).map(|_| ())),
            "mv" if args.len() == 2 => fs::rename(args[0], args[1]).map(|_| 0),
            "cp" if args.len() == 2 => fs::copy(args[0], args[1]).map(|_| 0),
            "mv" | "cp" => {
                eprintln!("usage: {cmd} <from> <to>");
                Ok(2)
            }
            "stat" => each(args, |a| {
                let m = fs::symlink_metadata(a)?;
                let kind = if m.is_dir() {
                    "directory"
                } else if m.is_symlink() {
                    "symbolic link"
                } else if m.file_type().is_char_device() {
                    "character device"
                } else if m.file_type().is_block_device() {
                    "block device"
                } else {
                    "regular file"
                };
                println!("{a}: {kind}, {} bytes, mode {:o}, uid {} gid {}, inode {}, {} link(s)", m.len(), m.permissions().mode() & 0o7777, m.uid(), m.gid(), m.ino(), m.nlink());
                Ok(())
            }),
            "ps" => cmd_ps(),
            "kill" => each(args, |a| match a.parse::<u64>() {
                Ok(pid) => system::kill(pid),
                Err(_) => Err(os_std::error::Error::new(os_std::error::ErrorKind::InvalidInput, "not a process id")),
            }),
            "mounts" | "df" => cmd_mounts(),
            "devices" | "lsdev" => cmd_devices(args),
            "wifi" => cmd_wifi(args),
            "volume" => cmd_volume(args),
            "dmesg" => cmd_dmesg(args),
            "beep" => cmd_beep(args),
            "play" => cmd_play(args),
            "free" => os::sysinfo().map(|i| {
                println!("total {} KiB, free {} KiB, used {} KiB", i.total_memory / 1024, i.free_memory / 1024, (i.total_memory - i.free_memory) / 1024);
                0
            }),
            "uptime" => {
                let s = Instant::now().as_nanos_since_boot() / 1_000_000_000;
                println!("up {} h {:02} min {:02} s", s / 3600, s / 60 % 60, s % 60);
                Ok(0)
            }
            "uname" => {
                println!("OSyx {} x86_64", kernel_version());
                Ok(0)
            }
            "whoami" => {
                let (uid, gid) = os::getuid();
                println!("{} (uid {uid}, gid {gid})", if uid == 0 { "root" } else { "user" });
                Ok(0)
            }
            "env" => {
                for (k, v) in env::vars() {
                    println!("{k}={v}");
                }
                for (k, v) in &self.vars {
                    println!("{k}={v}  (shell)");
                }
                Ok(0)
            }
            "history" => {
                for (i, h) in self.history.iter().enumerate() {
                    println!("{:4}  {h}", i + 1);
                }
                Ok(0)
            }
            "clear" => {
                print!("\x0c");
                Ok(0)
            }
            _ => return None,
        };
        Some(Ok(match r {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{cmd}: {e}");
                1
            }
        }))
    }

    fn program(&self, cmd: &str) -> Option<String> {
        if cmd.contains('/') {
            return Some(String::from(cmd));
        }
        SEARCH.iter().map(|d| format!("{d}/{cmd}")).find(|p| fs::metadata(p).is_ok_and(|m| m.is_file()))
    }

    fn external(&mut self, cmd: &str, args: &[&str]) -> i32 {
        let Some(path) = self.program(cmd) else {
            eprintln!("axis: {cmd}: command not found (try `help`)");
            return 127;
        };
        let mut c = Command::new(&path);
        c.arg0(cmd).args(args);
        // Children get our standard streams (the terminal's pipes); when
        // they are not redirected objects that fails and output goes to the
        // kernel log instead.
        let child = c.spawn_stdio([0, 1, 2]).or_else(|_| c.spawn_stdio([HANDLE_NONE, HANDLE_NONE, HANDLE_NONE]));
        match child.and_then(|ch| ch.wait()) {
            Ok(st) => report(cmd, st),
            Err(e) => {
                eprintln!("axis: {cmd}: {e}");
                126
            }
        }
    }

    // ---- pipelines and redirections -------------------------------------------

    /// Runs a parsed line: one command with redirections, or a pipeline.
    fn pipeline(&mut self, stages: &[Stage]) -> Result<i32, Exit> {
        let mut cmds = Vec::with_capacity(stages.len());
        for st in stages {
            match self.words(&st.command) {
                Ok(w) if !w.is_empty() => cmds.push(w),
                Ok(_) => {
                    self.fail("missing command");
                    return Ok(2);
                }
                Err(e) => {
                    self.fail(&e);
                    return Ok(2);
                }
            }
        }
        if stages.len() == 1 {
            return self.command(&stages[0], &cmds[0]);
        }
        let builtins = cmds.iter().filter(|w| is_builtin(&w[0])).count();
        if builtins > 1 {
            self.fail("only one built-in command per pipeline");
            return Ok(2);
        }
        self.pipe(stages, &cmds)
    }

    /// Expands a redirection target to its single path word.
    fn target(&self, raw: &str) -> Result<String, String> {
        let mut words = self.words(raw)?;
        if words.len() != 1 {
            return Err(String::from("redirection target must be a single word"));
        }
        Ok(words.pop().unwrap())
    }

    fn input(&self, st: &Stage) -> Result<Option<File>, String> {
        match &st.stdin {
            None => Ok(None),
            Some(raw) => {
                let path = self.target(raw)?;
                File::open(&path).map(Some).map_err(|e| format!("{path}: {e}"))
            }
        }
    }

    fn output(&self, st: &Stage) -> Result<Option<File>, String> {
        match &st.stdout {
            Some(r) => {
                let path = self.target(&r.path)?;
                let f = if r.append {
                    File::options().write(true).append(true).create(true).open(&path)
                } else {
                    File::create(&path)
                };
                f.map(Some).map_err(|e| format!("{path}: {e}"))
            }
            None => Ok(None),
        }
    }

    /// One command of a line, with its redirections.
    fn command(&mut self, st: &Stage, words: &[String]) -> Result<i32, Exit> {
        let cmd = words[0].as_str();
        let args: Vec<&str> = words[1..].iter().map(String::as_str).collect();
        let input = match self.input(st) {
            Ok(f) => f,
            Err(e) => {
                self.fail(&e);
                return Ok(2);
            }
        };
        let output = match self.output(st) {
            Ok(f) => f,
            Err(e) => {
                self.fail(&e);
                return Ok(2);
            }
        };
        if is_builtin(cmd) {
            // Built-ins read and print through `os_std::io`, so a temporary
            // redirect gives them the same file the programs would get.
            io::redirect_stdin(input.as_ref().map(File::handle));
            io::redirect_stdout(output.as_ref().map(File::handle));
            let r = self.builtin(cmd, &args);
            io::redirect_stdin(None);
            io::redirect_stdout(None);
            return match r {
                Some(Ok(code)) => Ok(code),
                Some(Err(Exit)) => Err(Exit),
                None => Ok(127),
            };
        }
        let Some(path) = self.program(cmd) else {
            eprintln!("axis: {cmd}: command not found (try `help`)");
            return Ok(127);
        };
        if input.is_none() && output.is_none() {
            return Ok(self.external(cmd, &args));
        }
        let mut c = Command::new(&path);
        c.arg0(cmd).args(&args);
        let stdio = [input.as_ref().map_or(osyx_abi::STDIN, File::handle), output.as_ref().map_or(osyx_abi::STDOUT, File::handle), osyx_abi::STDERR];
        match c.spawn_stdio(stdio).and_then(|ch| ch.wait()) {
            Ok(st) => Ok(report(cmd, st)),
            Err(e) => {
                eprintln!("axis: {cmd}: {e}");
                Ok(126)
            }
        }
    }

    /// Every stage after the first reads the previous stage's pipe. At most
    /// one stage is a built-in: it runs in the shell process after the
    /// programs around it have started, so waiting for output never deadlocks.
    fn pipe(&mut self, stages: &[Stage], cmds: &[Vec<String>]) -> Result<i32, Exit> {
        let mut inputs = Vec::with_capacity(stages.len());
        let mut outputs = Vec::with_capacity(stages.len());
        for st in stages {
            match (self.input(st), self.output(st)) {
                (Ok(i), Ok(o)) => {
                    inputs.push(i);
                    outputs.push(o);
                }
                (Err(e), _) | (_, Err(e)) => {
                    self.fail(&e);
                    return Ok(2);
                }
            }
        }
        let mut paths = Vec::with_capacity(stages.len());
        let mut builtin = None;
        for (i, words) in cmds.iter().enumerate() {
            if is_builtin(&words[0]) {
                builtin = Some(i);
                paths.push(String::new());
                continue;
            }
            let Some(p) = self.program(&words[0]) else {
                eprintln!("axis: {}: command not found (try `help`)", words[0]);
                return Ok(127);
            };
            paths.push(p);
        }
        let mut links = Vec::with_capacity(stages.len() - 1);
        for _ in 1..stages.len() {
            match ipc::pipe() {
                Ok((r, w)) => links.push((Some(r), Some(w))),
                Err(e) => {
                    self.fail(&format!("pipe: {e}"));
                    return Ok(2);
                }
            }
        }
        let mut spawned = Vec::with_capacity(stages.len());
        for (i, words) in cmds.iter().enumerate() {
            if Some(i) == builtin {
                continue;
            }
            let stdin = match inputs[i].as_ref() {
                Some(f) => f.handle(),
                None if i > 0 => links[i - 1].0.as_ref().map_or(osyx_abi::STDIN, |r| r.handle()),
                None => osyx_abi::STDIN,
            };
            let stdout = match outputs[i].as_ref() {
                Some(f) => f.handle(),
                None if i + 1 < cmds.len() => links[i].1.as_ref().map_or(osyx_abi::STDOUT, |w| w.handle()),
                None => osyx_abi::STDOUT,
            };
            let mut c = Command::new(&paths[i]);
            c.arg0(&words[0]).args(&words[1..]);
            match c.spawn_stdio([stdin, stdout, osyx_abi::STDERR]) {
                Ok(ch) => spawned.push((i, ch)),
                Err(e) => {
                    eprintln!("axis: {}: {e}", words[0]);
                    drop(links);
                    drop(inputs);
                    drop(outputs);
                    for (_, ch) in spawned {
                        let _ = ch.wait();
                    }
                    return Ok(126);
                }
            }
        }
        let mut statuses = Vec::new();
        statuses.resize(stages.len(), 0);
        let mut leave = false;
        if let Some(i) = builtin {
            // Keep only the pipe ends the built-in itself uses; every other
            // copy is closed here so the programs see end of data.
            for (j, (r, w)) in links.iter_mut().enumerate() {
                if !(inputs[i].is_none() && j + 1 == i) {
                    *r = None;
                }
                if !(outputs[i].is_none() && j == i) {
                    *w = None;
                }
            }
            let stdin = match inputs[i].as_ref() {
                Some(f) => f.handle(),
                None if i > 0 => links[i - 1].0.as_ref().map_or(osyx_abi::STDIN, |r| r.handle()),
                None => osyx_abi::STDIN,
            };
            let stdout = match outputs[i].as_ref() {
                Some(f) => f.handle(),
                None if i + 1 < cmds.len() => links[i].1.as_ref().map_or(osyx_abi::STDOUT, |w| w.handle()),
                None => osyx_abi::STDOUT,
            };
            io::redirect_stdin(Some(stdin));
            io::redirect_stdout(Some(stdout));
            let args: Vec<&str> = cmds[i][1..].iter().map(String::as_str).collect();
            match self.builtin(&cmds[i][0], &args) {
                Some(Ok(code)) => statuses[i] = code,
                Some(Err(Exit)) => {
                    leave = true;
                    statuses[i] = self.last;
                }
                None => statuses[i] = 127,
            }
            io::redirect_stdin(None);
            io::redirect_stdout(None);
        }
        // Our copies of the pipe ends would keep readers waiting for end of
        // data; the children hold their own.
        drop(links);
        drop(inputs);
        drop(outputs);
        for (i, ch) in spawned {
            statuses[i] = match ch.wait() {
                Ok(st) => report(&cmds[i][0], st),
                Err(e) => {
                    eprintln!("axis: {}: {e}", cmds[i][0]);
                    126
                }
            };
        }
        if leave {
            return Err(Exit);
        }
        Ok(statuses.pop().unwrap_or(0))
    }
}

/// Commands AXIS answers itself instead of running a program.
fn is_builtin(cmd: &str) -> bool {
    matches!(
        cmd,
        "exit"
            | "help"
            | "pwd"
            | "cd"
            | "echo"
            | "ls"
            | "cat"
            | "mkdir"
            | "rmdir"
            | "rm"
            | "touch"
            | "mv"
            | "cp"
            | "stat"
            | "ps"
            | "kill"
            | "mounts"
            | "df"
            | "devices"
            | "lsdev"
            | "wifi"
            | "volume"
            | "dmesg"
            | "beep"
            | "play"
            | "free"
            | "uptime"
            | "uname"
            | "whoami"
            | "env"
            | "history"
            | "clear"
    )
}

struct Exit;

fn report(cmd: &str, st: ExitStatus) -> i32 {
    if let Some(v) = st.exception() {
        eprintln!("axis: {cmd}: stopped by CPU exception {v}");
        return 128 + v as i32;
    }
    let code = st.code().unwrap_or(st.raw());
    if code != 0 && code != 1 {
        eprintln!("axis: {cmd}: exit status {code}");
    }
    code
}

fn each(args: &[&str], mut f: impl FnMut(&str) -> os_std::error::Result<()>) -> os_std::error::Result<i32> {
    if args.is_empty() {
        eprintln!("missing operand");
        return Ok(2);
    }
    let mut status = 0;
    for a in args {
        if let Err(e) = f(a) {
            eprintln!("{a}: {e}");
            status = 1;
        }
    }
    Ok(status)
}

fn cmd_ls(args: &[&str]) -> os_std::error::Result<i32> {
    let long = args.iter().any(|a| *a == "-l" || *a == "-la" || *a == "-al");
    let all = args.iter().any(|a| a.contains('a') && a.starts_with('-'));
    let paths: Vec<&str> = args.iter().copied().filter(|a| !a.starts_with('-')).collect();
    let paths = if paths.is_empty() { vec!["."] } else { paths };
    let mut status = 0;
    for (i, p) in paths.iter().enumerate() {
        if paths.len() > 1 {
            if i > 0 {
                println!();
            }
            println!("{p}:");
        }
        let meta = match fs::metadata(p) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("ls: {p}: {e}");
                status = 1;
                continue;
            }
        };
        if !meta.is_dir() {
            println!("{p}");
            continue;
        }
        let mut entries: Vec<(String, Option<fs::Metadata>)> = match fs::read_dir(p) {
            Ok(d) => d.map(|e| (String::from(e.file_name()), e.metadata().ok())).collect(),
            Err(e) => {
                eprintln!("ls: {p}: {e}");
                status = 1;
                continue;
            }
        };
        entries.retain(|(n, _)| all || !n.starts_with('.'));
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, m) in entries {
            let dir = m.as_ref().is_some_and(|m| m.is_dir());
            let shown = if dir { format!("\x1b[94m{name}/\x1b[0m") } else { name };
            if long {
                let (mode, size) = m.as_ref().map_or((0, 0), |m| (m.permissions().mode(), m.len()));
                println!("{} {:>10}  {shown}", mode_string(mode, dir), size);
            } else {
                println!("{shown}");
            }
        }
    }
    Ok(status)
}

fn mode_string(mode: u32, dir: bool) -> String {
    let mut s = String::from(if dir { "d" } else { "-" });
    for shift in [6, 3, 0] {
        let m = mode >> shift;
        s.push(if m & 4 != 0 { 'r' } else { '-' });
        s.push(if m & 2 != 0 { 'w' } else { '-' });
        s.push(if m & 1 != 0 { 'x' } else { '-' });
    }
    s
}

fn cmd_cat(args: &[&str]) -> os_std::error::Result<i32> {
    if args.is_empty() {
        let mut input = io::stdin();
        let mut output = io::stdout();
        let mut buf = [0u8; 4096];
        loop {
            let n = io::Read::read(&mut input, &mut buf)?;
            if n == 0 {
                return Ok(0);
            }
            io::Write::write_all(&mut output, &buf[..n])?;
        }
    }
    each(args, |a| {
        let data = fs::read(a)?;
        let text = String::from_utf8_lossy(&data);
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
        Ok(())
    })
}

fn cmd_ps() -> os_std::error::Result<i32> {
    let procs = system::processes()?;
    println!("{:>5} {:>6} {:>5} {:>7} {:>9}  NAME", "PID", "PARENT", "UID", "THREADS", "MEMORY");
    for p in procs {
        let state = if p.state == system::PROC_ZOMBIE { " (zombie)" } else { "" };
        println!("{:>5} {:>6} {:>5} {:>7} {:>6} KiB  {}{}", p.pid, p.parent, p.uid, p.threads, p.frames * 4, system::process_name(&p), state);
    }
    Ok(0)
}

fn cmd_mounts() -> os_std::error::Result<i32> {
    println!("{:<14} {:<8} {:>10} {:>10}  SOURCE", "MOUNT", "TYPE", "SIZE", "FREE");
    for m in system::mounts()? {
        let path = system::field_str(&m.path);
        let (size, free) = os::statfs(path).map_or((0, 0), |s| (s.total_blocks * s.block_size, s.free_blocks * s.block_size));
        println!("{:<14} {:<8} {:>7} KiB {:>7} KiB  {}", path, system::field_str(&m.fstype), size / 1024, free / 1024, system::field_str(&m.source));
    }
    Ok(0)
}

/// Wi-Fi through the kernel's OpenBSD net80211 layer: it reads the
/// network to join from `/etc/osyx/wifi.conf` and reports the state and
/// scan results in `/run/wifi.status`.
fn cmd_wifi(args: &[&str]) -> os_std::error::Result<i32> {
    const CONF: &str = "/etc/osyx/wifi.conf";
    const STATUS: &str = "/run/wifi.status";
    match args {
        ["connect", ssid] | ["connect", ssid, _] => {
            let pass = args.get(2).copied().unwrap_or("");
            if !pass.is_empty() && !(8..=63).contains(&pass.len()) {
                eprintln!("wifi: a WPA password has 8 to 63 characters");
                return Ok(2);
            }
            fs::write(CONF, format!("ssid={ssid}\npsk={pass}\n"))?;
            println!("wifi: joining \"{ssid}\" (see `wifi status` in a few seconds)");
            Ok(0)
        }
        ["disconnect"] => {
            fs::write(CONF, "ssid=\n")?;
            println!("wifi: disconnected");
            Ok(0)
        }
        [] | ["status"] | ["scan"] => {
            let Ok(text) = fs::read_to_string(STATUS) else {
                println!("wifi: no Wi-Fi adapter with a driver (see `devices wireless`)");
                return Ok(1);
            };
            let mut nets: Vec<(u32, String)> = Vec::new();
            for line in text.lines() {
                let f: Vec<&str> = line.split('\t').collect();
                if f.first() == Some(&"net") && f.len() >= 5 {
                    let rssi = f[2].parse().unwrap_or(0);
                    nets.push((rssi, format!("{:<32} {:>4} {:>4}  {}", f[1], f[2], f[3], f[4])));
                } else if args.first() != Some(&"scan") {
                    println!("{line}");
                }
            }
            nets.sort_by_key(|n| core::cmp::Reverse(n.0));
            nets.dedup_by(|a, b| a.1 == b.1);
            println!("{:<32} {:>4} {:>4}  SECURITY", "NETWORK", "RSSI", "CHAN");
            for (_, n) in &nets {
                println!("{n}");
            }
            if nets.is_empty() {
                println!("(no networks seen yet)");
            }
            Ok(0)
        }
        _ => {
            eprintln!("usage: wifi [status|scan|connect SSID [PASSWORD]|disconnect]");
            Ok(2)
        }
    }
}

/// The kernel log (`/run/kernel.log`, refreshed every two seconds); with
/// words only the lines containing one of them (any case).
fn cmd_dmesg(args: &[&str]) -> os_std::error::Result<i32> {
    let text = fs::read_to_string("/run/kernel.log")?;
    let words: Vec<String> = args.iter().map(|w| w.to_lowercase()).collect();
    for line in text.lines() {
        let lower = line.to_lowercase();
        if words.is_empty() || words.iter().any(|w| lower.contains(w.as_str())) {
            println!("{line}");
        }
    }
    Ok(0)
}

// ---- sound: /dev/audio takes 48 kHz signed 16-bit stereo -------------------------

const AUDIO_RATE: u32 = 48_000;

fn cmd_volume(args: &[&str]) -> os_std::error::Result<i32> {
    let line = match args {
        [] => {
            match fs::read_to_string("/run/audio.status") {
                Ok(t) => print!("{t}"),
                Err(_) => println!("volume: no sound card with a driver (see `devices audio`)"),
            }
            return Ok(0);
        }
        ["mute"] => String::from("mute=1"),
        ["unmute"] => String::from("mute=0"),
        [n] if n.parse::<u32>().is_ok_and(|v| v <= 100) => format!("volume={n}
mute=0"),
        _ => {
            eprintln!("usage: volume [0-100|mute|unmute]");
            return Ok(2);
        }
    };
    let mut f = fs::OpenOptions::new().write(true).open("/dev/mixer")?;
    f.write_all(line.as_bytes())?;
    Ok(0)
}

/// cos(x) for |x| <= pi (Taylor series; enough for tone generation).
fn cos(x: f64) -> f64 {
    let (x2, mut term, mut sum) = (x * x, 1.0, 1.0);
    for k in 1..12 {
        term *= -x2 / ((2 * k - 1) * (2 * k)) as f64;
        sum += term;
    }
    sum
}

fn cmd_beep(args: &[&str]) -> os_std::error::Result<i32> {
    let hz: f64 = args.first().and_then(|a| a.parse().ok()).unwrap_or(880.0);
    let ms: u32 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(300);
    if !(20.0..=20_000.0).contains(&hz) || ms > 10_000 {
        eprintln!("usage: beep [HZ (20-20000) [MS (up to 10000)]]");
        return Ok(2);
    }
    // A sine from the recurrence y[n] = 2cos(w) y[n-1] - y[n-2].
    let w = 2.0 * core::f64::consts::PI * hz / AUDIO_RATE as f64;
    let c = 2.0 * cos(w);
    let (mut y1, mut y2) = (0.0f64, -cos(core::f64::consts::FRAC_PI_2 - w));
    let frames = AUDIO_RATE as usize * ms as usize / 1000;
    let fade = (AUDIO_RATE as usize / 200).min(frames / 2).max(1);
    let mut pcm = Vec::with_capacity(frames * 4);
    for n in 0..frames {
        let y = c * y1 - y2;
        y2 = y1;
        y1 = y;
        let env = n.min(frames - 1 - n).min(fade) as f64 / fade as f64;
        let s = (y * env * 12_000.0) as i16;
        pcm.extend_from_slice(&s.to_le_bytes());
        pcm.extend_from_slice(&s.to_le_bytes());
    }
    play_pcm(&pcm)
}

fn play_pcm(pcm: &[u8]) -> os_std::error::Result<i32> {
    let mut f = match fs::OpenOptions::new().write(true).open("/dev/audio") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("sound: /dev/audio: {e} (see `devices audio`)");
            return Ok(1);
        }
    };
    f.write_all(pcm)?;
    Ok(0)
}

/// Plays an uncompressed WAV file (8/16-bit PCM, mono or stereo, any
/// rate: converted to 48 kHz stereo).
fn cmd_play(args: &[&str]) -> os_std::error::Result<i32> {
    let [path] = args else {
        eprintln!("usage: play FILE.wav");
        return Ok(2);
    };
    let data = fs::read(path)?;
    let pcm = match wav_to_pcm(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("play: {path}: {e}");
            return Ok(1);
        }
    };
    println!("play: {} s", pcm.len() / 4 / AUDIO_RATE as usize);
    play_pcm(&pcm)
}

fn wav_to_pcm(d: &[u8]) -> Result<Vec<u8>, &'static str> {
    if d.len() < 12 || &d[0..4] != b"RIFF" || &d[8..12] != b"WAVE" {
        return Err("not a WAV file");
    }
    let u16_at = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]);
    let u32_at = |i: usize| u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
    let (mut fmt, mut body) = (None, None);
    let mut i = 12;
    while i + 8 <= d.len() {
        let len = u32_at(i + 4) as usize;
        let end = (i + 8 + len).min(d.len());
        match &d[i..i + 4] {
            b"fmt " if len >= 16 => fmt = Some((u16_at(i + 8), u16_at(i + 10), u32_at(i + 12), u16_at(i + 22))),
            b"data" => body = Some(&d[i + 8..end]),
            _ => {}
        }
        i = i + 8 + len + (len & 1);
    }
    let (Some((format, channels, rate, bits)), Some(body)) = (fmt, body) else { return Err("no fmt or data chunk") };
    if format != 1 && format != 0xfffe {
        return Err("only uncompressed PCM is supported");
    }
    if !(1..=2).contains(&channels) || !(bits == 8 || bits == 16) || rate == 0 {
        return Err("only 8/16-bit mono or stereo is supported");
    }
    let step = (channels * bits / 8) as usize;
    let sample = |f: usize, ch: usize| -> i32 {
        let o = f * step + ch.min(channels as usize - 1) * (bits as usize / 8);
        if bits == 8 { (body[o] as i32 - 128) << 8 } else { i16::from_le_bytes([body[o], body[o + 1]]) as i32 }
    };
    let frames = body.len() / step;
    let out_frames = (frames as u64 * AUDIO_RATE as u64 / rate as u64) as usize;
    let mut out = Vec::with_capacity(out_frames * 4);
    for n in 0..out_frames {
        // Linear interpolation between the two nearest source frames.
        let pos = n as u64 * rate as u64;
        let (f, frac) = ((pos / AUDIO_RATE as u64) as usize, (pos % AUDIO_RATE as u64) as i32);
        let g = (f + 1).min(frames - 1);
        for ch in 0..2 {
            let (a, b) = (sample(f, ch), sample(g, ch));
            let s = a + (b - a) * frac / AUDIO_RATE as i32;
            out.extend_from_slice(&(s as i16).to_le_bytes());
        }
    }
    Ok(out)
}

/// The kernel's device list; with arguments only the lines containing one
/// of the words (any case), e.g. `devices wireless bluetooth`.
fn cmd_devices(args: &[&str]) -> os_std::error::Result<i32> {
    let words: Vec<String> = args.iter().map(|a| a.to_lowercase()).collect();
    let mut shown = 0;
    println!("{:<10} {:<36} {:<28} LOCATION", "CLASS", "DEVICE", "HARDWARE ID");
    for d in system::devices()? {
        let (class, desc) = (system::field_str(&d.class), system::field_str(&d.description));
        let (id, loc) = (system::field_str(&d.hardware_id), system::field_str(&d.location));
        let line = format!("{class:<10} {desc:<36} {id:<28} {loc}");
        let lower = line.to_lowercase();
        if words.is_empty() || words.iter().any(|w| lower.contains(w.as_str())) {
            println!("{line}");
            shown += 1;
        }
    }
    if shown == 0 {
        println!("(nothing matches)");
    }
    Ok(0)
}

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '#') => return &line[..i],
            _ => {}
        }
    }
    line
}

/// `name = expr` (a Python-style identifier on the left, not `==`).
fn assignment(line: &str) -> Option<(&str, &str)> {
    let (l, r) = line.split_once('=')?;
    let name = l.trim();
    let valid = !name.is_empty()
        && name.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_alphanumeric() || c == '_');
    (valid && !r.starts_with('=')).then_some((name, r.trim()))
}

fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quote = None;
    let mut depth = 0i32;
    for c in s.chars() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '(') => depth += 1,
            (None, ')') => depth -= 1,
            (None, c) if c == sep && depth == 0 => {
                parts.push(core::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    parts.push(cur);
    parts
}

/// Tokens of an expression: string literals (marked with a leading \x01),
/// numbers, names and the operators + - *.
fn tokenize_expr(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut chars = s.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' => {
                chars.next();
            }
            '"' | '\'' => {
                chars.next();
                let mut lit = String::from('\u{1}');
                loop {
                    match chars.next() {
                        Some(q) if q == c => break,
                        Some('\\') => match chars.next() {
                            Some('n') => lit.push('\n'),
                            Some('t') => lit.push('\t'),
                            Some(o) => lit.push(o),
                            None => return Err(String::from("unterminated string")),
                        },
                        Some(ch) => lit.push(ch),
                        None => return Err(String::from("unterminated string")),
                    }
                }
                out.push(lit);
            }
            '+' | '-' | '*' | '=' | '!' | '<' | '>' if !out.is_empty() && !is_op(out.last()) => {
                chars.next();
                let mut op = String::from(c);
                if chars.peek() == Some(&'=') {
                    chars.next();
                    op.push('=');
                }
                out.push(op);
            }
            _ => {
                let mut t = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == ' ' || (matches!(ch, '+' | '*' | '-' | '=' | '!' | '<' | '>') && !t.is_empty()) {
                        break;
                    }
                    t.push(ch);
                    chars.next();
                }
                out.push(t);
            }
        }
    }
    Ok(out)
}

fn is_op(t: Option<&String>) -> bool {
    t.is_some_and(|t| matches!(t.as_str(), "+" | "-" | "*" | "==" | "!=" | "<" | ">" | "<=" | ">="))
}

fn is_cmp(t: &str) -> bool {
    matches!(t, "==" | "!=" | "<" | ">" | "<=" | ">=")
}

fn compare(op: &str, l: &Value, r: &Value) -> Result<bool, String> {
    use core::cmp::Ordering;
    let ord = match (l, r) {
        (Value::Int(a), Value::Int(b)) => a.cmp(b),
        (a, b) => a.text().cmp(&b.text()),
    };
    Ok(match op {
        "==" => ord == Ordering::Equal,
        "!=" => ord != Ordering::Equal,
        "<" => ord == Ordering::Less,
        ">" => ord == Ordering::Greater,
        "<=" => ord != Ordering::Greater,
        ">=" => ord != Ordering::Less,
        _ => return Err(format!("unknown operator {op:?}")),
    })
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Int(i) => *i != 0,
        Value::Str(s) => !s.is_empty(),
    }
}
