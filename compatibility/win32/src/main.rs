//! `winrun` — runs Windows x64 (PE32+) and 32-bit (PE32) programs on OSyx.
//!
//! `winrun [-v] program.exe [arguments...]` loads the program and the DLLs
//! it needs through the OSyx PE loader (`osyx-pe-loader`), with OSyx's own
//! implementations of ntdll, kernel32/kernelbase, user32, gdi32 and ws2_32
//! (no Windows code), sets up the PEB, the main thread's TEB (GS), TLS and
//! a Windows-sized stack, runs DLL initialisation and calls the entry
//! point. The program's exit code is winrun's exit code. A fault in the
//! program ends only this process.
//!
//! A PE32 program is mapped below 4 GiB and entered in compatibility mode
//! through the 32-bit bridge; winrun itself is linked at 0x4000_0000 so all
//! of its code stays addressable by 32-bit code.

#![no_std]
#![no_main]

extern crate alloc;

/// Export table of a built-in DLL: `[(name, address)]` from function names.
macro_rules! export_table {
    ($($f:ident),* $(,)?) => {
        alloc::vec![$((stringify!($f), $f as *const () as usize as u64)),*]
    };
}

mod crypt32;
mod commdlg;
mod comctl32;
mod cryptbase;
mod dbghelp;
mod error;
mod eventlog;
mod exceptions;
mod files;
mod fls;
mod heaps;
mod ini;
mod ktm;
mod iphlpapi;
mod kernel32;
mod keyed;
mod loader;
mod locale;
mod mapping;
mod mem;
mod ntdll;
mod objects;
mod objsec;
mod path;
mod ole32;
mod oleaut32;
mod setupapi;
mod shell32;
mod shlwapi;
mod security;
mod seh;
mod teb;
mod ucrt;
mod user32;
mod userenv;
mod volumes;
mod winmm;
mod winsta;
mod version;
mod synch;
mod process;
mod psapi;
mod registry;
mod rtl;
mod sysext;
mod unwind;
mod threadpool;
mod timers;
mod tokens;
mod tz;
mod zone;
mod nls;
mod procinfo;
mod etw;
mod credman;
mod accounts;
mod capi;
mod bcrypt;
mod newlibs;
mod minordlls;
mod dwmapi;
mod dwrite;
mod inherit;
mod propsys;
mod pipes;
mod ws2_32;
mod wow64;

use alloc::string::String;
use alloc::vec::Vec;
use os_std::prelude::*;
use osyx_pe::PeFile;

/// `-v`: the module summary, every thread as it starts, and the loader's
/// diagnostics. Set once in `main` before anything else runs.
pub(crate) static VERBOSE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// `OSYX_WINRUN_EVENTS=1`: timestamped input, title and present events.
pub(crate) static EVENTS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// `OSYX_WINRUN_COUNT=1`: per-2 s rates of the message-loop APIs and their
/// call sites (diagnostics; off in normal runs).
pub(crate) static COUNT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

os_std::entry!(main);

/// Quotes an argument the way the Windows command-line parser expects.
fn quote(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return String::from(a);
    }
    let mut s = String::from("\"");
    s.push_str(&a.replace('"', "\\\""));
    s.push('"');
    s
}

fn main() -> i32 {
    let mut args: Vec<String> = os_std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--exports") {
        loader::print_capabilities();
        return 0;
    }
    if args.iter().any(|a| a == "--mathbench") {
        let n = 200_000;
        let [h, e, a] = ucrt::libm::bench_math(n);
        println!("mathbench {n} calls: hypot={h}us exp2={e}us add={a}us");
        return 0;
    }
    let verbose = args.first().is_some_and(|a| a == "-v");
    VERBOSE.store(verbose, core::sync::atomic::Ordering::Relaxed);
    EVENTS.store(
        os_std::env::var("OSYX_WINRUN_EVENTS").is_ok_and(|v| v == "1"),
        core::sync::atomic::Ordering::Relaxed,
    );
    COUNT.store(
        os_std::env::var("OSYX_WINRUN_COUNT").is_ok_and(|v| v == "1"),
        core::sync::atomic::Ordering::Relaxed,
    );
    if COUNT.load(core::sync::atomic::Ordering::Relaxed) {
        user32::start_counter();
    }
    if verbose && os_std::env::var("OSYX_WINRUN_TRACE").is_ok_and(|v| v == "1") {
        kernel32::TRACE.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    if verbose {
        args.remove(0);
    }
    let Some(program) = args.first().cloned() else {
        eprintln!("usage: winrun [-v] program.exe [arguments...]");
        return 2;
    };
    // The program may be named with an OSyx path or a Windows path.
    let cwd = os_std::env::current_dir().map(|p| path::to_windows(p.as_str())).unwrap_or_else(|_| String::from("C:\\"));
    let osyx = if program.starts_with('/') {
        program.clone()
    } else {
        path::to_osyx(&program, &cwd).unwrap_or(program.clone())
    };
    let exe = match path::resolve(&osyx) {
        Ok((p, true)) => p,
        _ => {
            eprintln!("winrun: {program}: no such file");
            return 2;
        }
    };
    let win_exe = path::to_windows(&exe);
    let mut cmd = quote(&win_exe);
    for a in &args[1..] {
        cmd.push(' ');
        cmd.push_str(&quote(a));
    }
    // CreateProcessW's working directory for a Windows child.
    let mut env: Vec<(String, String)> = os_std::env::vars().collect();
    inherit::start_service();
    // Inherited handles come first, at their own values (see inherit.rs).
    if let Some(i) = env.iter().position(|(k, _)| k == inherit::ENV) {
        let (_, name) = env.remove(i);
        match inherit::receive(&name) {
            Ok(n) if verbose => eprintln!("winrun: inherited {n} handles"),
            Ok(_) => {}
            Err(e) => {
                eprintln!("winrun: cannot take inherited handles: {e}");
                return 126;
            }
        }
    }
    if let Some(i) = env.iter().position(|(k, _)| k == "OSYX_WINRUN_CWD") {
        let (_, dir) = env.remove(i);
        if let Err(e) = os_sys::chdir(&dir) {
            eprintln!("winrun: cannot enter {dir}: {e:?}");
            return 126;
        }
    }
    // The profile variables every Windows process has, matching shell32's
    // known folders (the profile is $HOME).
    let home = os_std::env::var("HOME").unwrap_or_else(|_| String::from("/home/user"));
    let home = home.trim_end_matches('/');
    let profile = path::to_windows(if home.is_empty() { "/" } else { home });
    let base = profile.trim_end_matches('\\');
    let user = base.rsplit('\\').next().filter(|u| !u.is_empty() && !u.ends_with(':')).unwrap_or("user").to_string();
    let home_path = profile.strip_prefix("C:").unwrap_or(&profile).to_string();
    // A Windows profile always has these folders (created at first logon);
    // programs read them without asking for creation.
    if os_sys::stat(if home.is_empty() { "/" } else { home }).is_ok() {
        for d in ["AppData", "AppData/Roaming", "AppData/Local", "AppData/LocalLow", "AppData/Local/Temp", "AppData/Local/Microsoft", "AppData/Local/Microsoft/Windows", "AppData/Local/Microsoft/Windows/INetCache", "AppData/Local/Microsoft/Windows/INetCookies", "AppData/Local/Microsoft/Windows/History"] {
            let _ = os_sys::mkdir(&format!("{home}/{d}"), 0o755);
        }
    }
    for (k, v) in [
        ("USERPROFILE", profile.clone()),
        ("APPDATA", format!("{base}\\AppData\\Roaming")),
        ("LOCALAPPDATA", format!("{base}\\AppData\\Local")),
        ("HOMEDRIVE", String::from("C:")),
        ("HOMEPATH", home_path),
        ("USERNAME", user),
    ] {
        if !env.iter().any(|(e, _)| e.eq_ignore_ascii_case(k)) {
            env.push((String::from(k), v));
        }
    }
    for (k, v) in [
        ("ALLUSERSPROFILE", "C:\\ProgramData"),
        ("ProgramData", "C:\\ProgramData"),
        ("ProgramFiles", "C:\\Program Files"),
        ("SystemRoot", "C:\\Windows"),
        ("windir", "C:\\Windows"),
        ("COMPUTERNAME", "OSYX"),
        ("OS", "Windows_NT"),
        ("OSYX", "1"),
        ("SystemDrive", "C:"),
        ("TEMP", "C:\\tmp"),
        ("TMP", "C:\\tmp"),
        ("PROCESSOR_ARCHITECTURE", "AMD64"),
    ] {
        if !env.iter().any(|(e, _)| e.eq_ignore_ascii_case(k)) {
            env.push((String::from(k), String::from(v)));
        }
    }
    // A 32-bit program reads pointers the runtime hands out (command line,
    // environment, heap blocks): from here on all memory the runtime maps
    // must be below 4 GiB, above the program, the bridge arena and winrun.
    let pe32_bytes = os_std::fs::read(&exe).ok().filter(|b| PeFile::parse_any(b).is_ok_and(|pe| pe.is_pe32()));
    if pe32_bytes.is_some() {
        os_sys::set_low_map(0x5000_0000);
    }
    let env_strings: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    kernel32::init_process(&exe, &cmd, env);
    winsta::clear_markers();
    exceptions::install();
    // A 32-bit image cannot start through the PE32+ path: it is linked at
    // 0x400000, must stay below 4 GiB and is entered in compatibility mode
    // through the bridge. Read the file to tell the widths apart; the PE32+
    // path below reads it again exactly as before.
    if let Some(bytes) = pe32_bytes {
        let mut args = args.clone();
        if let Some(a) = args.first_mut() {
            *a = exe.clone();
        }
        if let Err(e) = loader::run_pe32(bytes, &args, &cmd, &env_strings) {
            eprintln!("winrun: {e}");
            return 126;
        }
        return 0;
    }
    let started = match loader::start(&exe, &cmd, &env_strings) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("winrun: {e}");
            return 126;
        }
    };
    if verbose {
        for (name, base, builtin, relocs, imports) in loader::summary() {
            println!(
                "winrun: {name:<16} {base:#014x} {} {relocs} relocations, {imports} imports bound",
                if builtin { "built-in" } else { "PE image" }
            );
        }
        println!("winrun: entry {:#x}, stack {:#x}..{:#x}", started.entry, started.stack_limit, started.stack_top);
    }
    if COUNT.load(core::sync::atomic::Ordering::Relaxed) {
        // RIP samples name code by module and offset.
        for (name, base, _, _, _) in loader::summary() {
            eprintln!("winrun: cnt module {name} {base:#x}");
        }
    }
    if started.entry == 0 {
        eprintln!("winrun: {win_exe} has no entry point");
        return 126;
    }
    // The process entry gets the PEB in RCX, as from RtlUserThreadStart.
    let code = loader::run_on_stack(started.entry, started.peb, started.stack_top) as u32;
    kernel32::ExitProcess(code)
}
