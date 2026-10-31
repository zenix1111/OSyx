//! Windows compatibility checks (`init win,<tcp>,<udp>`): the PE32+ and PE32
//! test programs in /opt/wintests (built from compatibility/win32/tests/src by
//! scripts/build-wintests.ps1) run under /bin/winrun. Each program prints
//! its own checks to the log and exits with its failure count; the GUI
//! program runs inside a PRISM session started here.

use crate::Tests;
use os_std::prelude::*;
use os_std::process::Command;
use os_std::time::{Duration, Instant};
use os_std::{fs, thread};

const DIR: &str = "/opt/wintests";

fn run(exe: &str, args: &[&str]) -> Option<i32> {
    let t = Instant::now();
    let mut c = Command::new("/bin/winrun");
    c.arg(&format!("{DIR}/{exe}"));
    c.args(args);
    let r = c.status().ok().and_then(|s| s.code());
    println!("win: {exe} exited with {:?} after {} ms", r, t.elapsed().as_millis());
    r
}

pub fn run_all(t: &mut Tests, tcp: u16, udp: u16) {
    t.check("native file sections: rights, sharing, writeback and truncation", || {
        Command::new("worker").arg("filemap-checks").status().is_ok_and(|s| s.success())
    });
    t.check("native CPU fault delivery and safe context resumption", || {
        Command::new("worker").arg("fault-checks").status().is_ok_and(|s|s.success())
    });
    if fs::metadata(DIR).is_err() {
        println!("win: {DIR} is missing (the Windows test programs were not built)");
        t.check("Windows test programs installed", || false);
        return;
    }
    t.check("PE32+ minimal program: relocated, exit code 42 (target A)", || run("minimal.exe", &[]) == Some(42));
    t.check("kernel32 console program: TEB/PEB, last error, modules (target B)", || {
        run("hello.exe", &["first arg", "second"]) == Some(0)
    });
    // 32-bit PE32 image: the loader maps it and i386 code runs; it exits 7.
    t.check("PE32 32-bit program: i386 code runs and exits 7", || run("hello32.exe", &[]) == Some(7));
    // 32-bit calls through the bridge signatures; exit code = failures.
    t.check("PE32 32-bit program: kernel32, INI files and registry through the bridge", || run("api32.exe", &[]) == Some(0));
    t.check("PE32 32-bit program: CreateThread, 32-bit start routines and concurrent bridge calls", || {
        run("thread32.exe", &[]) == Some(0)
    });
    t.check("Windows file I/O on OSyx file systems (target C)", || run("fileio.exe", &[]) == Some(0));
    t.check("Windows volume, device and adapter inventory", || run("sysadmin.exe", &[]) == Some(0));
    t.check("Windows file version resources and queries", || run("version.exe", &[]) == Some(0));
    t.check("Windows vectored hardware exceptions and context resumption", || run("exceptions.exe", &[]) == Some(0));
    t.check("Windows file mappings: shared, read-only and copy-on-write views", || run("mapping.exe", &[]) == Some(0));
    t.check("NT runtime: Rtl strings and heap, SLists, unwinding, times, registry", || run("runtime.exe", &[]) == Some(0));
    t.check("structured exception handling, unwinding, consolidation and FLS", || run("seh.exe", &[]) == Some(0));
    t.check("newer Win32: files, NLS, thread pool, processes, jobs, shlwapi, WinRT", || run("platform.exe", &[]) == Some(0));
    t.check("shell32 known folders and the ole32 task allocator", || run("shell.exe", &[]) == Some(0));
    t.check("bcrypt hashes and random, secur32, shfolder, winspool, uiautomationcore, oleacc and msvcrt libraries", || run("newlibs.exe", &[]) == Some(0));
    t.check("heaps, critical sections, thread library calls, foreground window and attribute lists", || run("stubfix.exe", &[]) == Some(0));
    t.check("winmm timers at the kernel tick resolution", || run("winmm.exe", &[]) == Some(0));
    t.check("object security, ACLs, AccessCheck, restricted tokens and the event log", || run("sandbox.exe", &[]) == Some(0));
    t.check("US keyboard layout, key mapping and keyboard state", || run("keyboard.exe", &[]) == Some(0));
    t.check("shlwapi paths, environment folders, StrStrIW and IsOS", || run("shlpath.exe", &[]) == Some(0));
    t.check("security descriptors on sections and new directories", || run("secattr.exe", &[]) == Some(0));
    t.check("handle inheritance and DuplicateHandle between processes", || run("childproc.exe", &[]) == Some(0));
    t.check("executable images shared copy-on-write between processes", || run("imageshare.exe", &[]) == Some(0));
    t.check("named pipes work as the unprivileged desktop user", || {
        Command::new("/system/bin/run-app").arg("/opt/wintests/pipes.exe").status().is_ok_and(|s|s.success())
    });
    t.check("child handle inheritance works as the unprivileged desktop user", || {
        Command::new("/system/bin/run-app").arg("/opt/wintests/childproc.exe").status().is_ok_and(|s|s.success())
    });
    t.check("DirectWrite fonts, faces, metrics and glyph rasterization", || run("dwrite.exe", &[]) == Some(0));
    t.check("COM apartments, BSTRs, window stations, dbghelp and crypt32", || run("interop.exe", &[]) == Some(0));
    t.check("Windows SID ACL descriptor and token data", || run("security.exe", &[]) == Some(0));
    t.check("Universal C Runtime through the api-ms-win-crt contracts", || {
        run("ucrt.exe", &["one", "two words", "a\\b", "x\"y"]) == Some(0)
    });
    t.check("C Runtime extended math and floating-point edge cases", || run("crt2.exe", &[]) == Some(0));
    t.check("C Runtime scanf, floating-point control, diagnostics and local time", || run("crt3.exe", &[]) == Some(0));
    t.check("C Runtime file metadata, temporary names, environment and multibyte conversion", || run("crt4.exe", &[]) == Some(0));
    t.check("Windows tokens follow native uid after dropping root", || {
        Command::new("worker").args(["exec-as", "1000", "/bin/winrun", "/opt/wintests/security.exe"])
            .env("WIN_EXPECT_UID", "1000").status().is_ok_and(|s|s.success())
    });
    t.check("Windows shared locks, once initialization, condition variables and modules", || run("synch.exe", &[]) == Some(0));
    t.check("critical sections pass priority inheritance and survive contention", || run("prio.exe", &[]) == Some(0));
    t.check("threads, synchronisation, TLS, virtual memory, DLL loading (target D)", || {
        run("threads.exe", &[]) == Some(0)
    });
    let (tp, up) = (format!("{tcp}"), format!("{udp}"));
    t.check("Winsock over the OSyx network stack (target F)", || run("winsock.exe", &[&tp, &up]) == Some(0));
    t.check("legacy Winsock 1.1 through wsock32.dll ordinals", || run("wsock32.exe", &[]) == Some(0));
    t.check("Winsock 2 extensions, address text and the provider catalog", || run("wsaext.exe", &[]) == Some(0));
    t.check("ANSI file and process calls, file locks, pipes and memory status", || run("k32ansi.exe", &[]) == Some(0));
    t.check("time zones, en-US formatting, named objects and machine information", || run("k32xul.exe", &[]) == Some(0));
    t.check("registry enumeration and notification, CryptoAPI hashes, credentials, ETW and accounts", || run("advapi.exe", &[]) == Some(0));
    t.check("rpcrt4, cfgmgr32, propsys, bcryptprimitives, shcore and ntdll additions", || run("newdlls.exe", &[]) == Some(0));
    t.check("named pipes across processes with overlapped I/O and completion ports", || run("pipes.exe", &[]) == Some(0));
    t.check("a missing program is reported", || {
        Command::new("/bin/winrun").arg("/opt/wintests/none.exe").status().ok().and_then(|s| s.code()) == Some(2)
    });
    t.check("a non-PE file is rejected without crashing", || {
        Command::new("/bin/winrun").arg("/bin/init").status().ok().and_then(|s| s.code()) == Some(126)
    });
    // The GUI program needs a compositor: start PRISM (with the desktop
    // shell) in the background, then run it as a client.
    let prism = Command::new("/system/bin/prism").spawn();
    t.check("Win32 GDI surfaces, pixel copies, regions, paths and DC state", || {
        if prism.is_err() {
            return false;
        }
        thread::sleep(Duration::from_millis(500));
        run("gdi2.exe", &[]) == Some(0)
    });
    t.check("Win32 GUI window through PRISM (target E)", || {
        prism.is_ok() && run("gui.exe", &[]) == Some(0)
    });
    t.check("PE32 window, child controls and paint through PRISM", || prism.is_ok() && run("gui32.exe", &[]) == Some(0));
    // These create windows too.
    t.check("OLE apartments, GUID strings, drag-drop registration and the OLE clipboard", || {
        prism.is_ok() && run("ole2.exe", &[]) == Some(0)
    });
    t.check("message-queue waits and window property stores", || prism.is_ok() && run("msgwait.exe", &[]) == Some(0));
    t.check("DWM window attributes and timing, imm32 and wtsapi32", || prism.is_ok() && run("dwm.exe", &[]) == Some(0));
    t.check("mouse capture and tracking, displays and input registrations", || {
        prism.is_ok() && run("input.exe", &[]) == Some(0)
    });
    if let Ok(p) = prism {
        let _ = os_std::system::kill(p.id());
        let _ = p.wait();
    }
}
