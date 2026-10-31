//! The init program (`/bin/init` on the root file system). Runs in ring 3
//! and checks OSyx Std, the kernel's system call validation, processes
//! (spawn / wait / zombies / orphans) and the preemptive scheduler from the
//! user side, using `worker` as the child program, the file systems through
//! `os_std::fs` (see `fs_checks.rs`) and the program loader with `probe`
//! (see `exec_checks.rs`).
//!
//! Arguments (kernel command line `init.args=...`):
//! * none / desktop: start the graphical desktop (no tests)
//! * tests:         run the checks; exit status = number of failed checks
//!   Other diagnostic modes below require `init.args=tests,<mode>,...`.
//! * `fault`:       dereference an unmapped address (the kernel must kill us)
//! * `panic`:       panic (OSyx Std must report it and exit with 101)
//! * `exit,<code>`: exit with `<code>`
//! * `i2c`:         run /bin/i2chidd (HID over I2C discovery) and exit with its status
//! * `swap-stress`: exercise compressible anonymous pages under memory pressure
//! * `crash-prep`:  leave an open, removed file on / for the power-cut test
//! * `net,<tcp>,<udp>`: network checks against the host's echo servers on
//!   10.0.2.2 (see `net_checks.rs`); exit status = failed checks
//! * `media`:      USB stick automount / eject / unplug checks (see
//!   `media_checks.rs`); exit status = failed checks
//! * `win,<tcp>,<udp>`: Windows PE32+ programs under /bin/winrun (see
//!   `win_checks.rs`); exit status = failed checks

#![no_std]
#![no_main]

use os_std::error::ErrorKind;
use os_std::os::raw::{self, Errno, PROT_EXEC, PROT_READ, PROT_WRITE};
use os_std::prelude::*;
use os_std::process::{Child, Command};
use os_std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use os_std::mpsc;
use os_std::sync::{Once, OnceLock, RwLock};
use os_std::time::{Duration, Instant};
use os_std::{env, fs, os, process, thread};

#[path = "../exec_checks.rs"]
mod exec_checks;
#[path = "../fpu.rs"]
mod fpu;
#[path = "../fs_checks.rs"]
mod fs_checks;
#[path = "../ipc_checks.rs"]
mod ipc_checks;
#[path = "../media_checks.rs"]
mod media_checks;
#[path = "../net_checks.rs"]
mod net_checks;
#[path = "../win_checks.rs"]
mod win_checks;
#[path = "../smp_checks.rs"]
mod smp_checks;
#[path = "../prio_checks.rs"]
mod prio_checks;

os_std::entry!(main);

static RODATA: [u8; 64] = [0x5A; 64];

fn main() -> i32 {
    println!("Hello from OSyx userspace!");
    let args: Vec<String> = env::args().collect();
    println!("args: {:?}", args);
    if args.get(1).map(String::as_str) == Some("setup") {
        return setup_session(&args[2..]);
    }
    if args.get(1).map(String::as_str) != Some("tests") {
        return desktop_session();
    }
    // Keep submode argument positions stable after removing the explicit
    // test-mode gate. No diagnostic/fault branch is reachable otherwise.
    let mut args = args;
    args.remove(1);

    match args.get(1).map(String::as_str) {
        Some("fault") => {
            println!("reading unmapped address 0x1000 ...");
            // SAFETY: deliberately invalid; the kernel terminates the process.
            let v = unsafe { core::ptr::read_volatile(0x1000 as *const u64) };
            println!("unreachable: read {v}");
            return 99;
        }
        Some("panic") => panic!("panic requested by command line"),
        // Writes a file without fsync and waits: the write-back test cuts
        // the power afterwards and reads the disk.
        Some("dirty") => {
            let data = "written without fsync\n".repeat(1000);
            match fs::write("/home/user/writeback.txt", data.as_bytes()) {
                Ok(()) => println!("WRITEBACK_WRITTEN {} bytes", data.len()),
                Err(e) => println!("WRITEBACK_FAILED {e}"),
            }
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }
        Some("poweroff") => {
            let e = os_std::system::power_off();
            eprintln!("power off failed: {e}");
            return 1;
        }
        Some("reboot") => {
            let e = os_std::system::reboot();
            eprintln!("reboot failed: {e}");
            return 1;
        }
        Some("exit") => {
            let code = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            process::exit(code);
        }
        // `tests,i2c`: run the HID over I2C discovery service (ACPI -> kernel
        // driver) and exit with its status. The i2c-hid-test script gives the
        // VM an SSDT with a touchpad whose controller does not exist.
        Some("i2c") => {
            return match Command::new("/bin/i2chidd").status() {
                Ok(s) => {
                    println!("init: i2chidd exit status {:?}", s.code());
                    s.code().unwrap_or(1)
                }
                Err(e) => {
                    eprintln!("init: cannot run /bin/i2chidd: {e}");
                    1
                }
            };
        }
        Some("desktop") => return desktop_session(),
        // QEMU has no battery: after batteryd has reported none, publish a
        // charging battery at 73 %, then a discharging one at 12 %, so the
        // taskbar indicator and its details can be checked.
        Some("battery-demo") => {
            use osyx_abi::battery::{State, Status};
            thread::spawn(|| {
                let charging = Status {
                    state: State::Charging,
                    percent: 73,
                    ac: true,
                    batteries: 1,
                    minutes_to_full: Some(35),
                    energy_mwh: Some(35_000),
                    capacity_mwh: Some(48_000),
                    design_mwh: Some(57_000),
                    rate_mw: Some(22_000),
                    voltage_mv: Some(12_100),
                    ..Status::NONE
                };
                let discharging = Status {
                    state: State::Discharging,
                    percent: 12,
                    ac: false,
                    minutes_to_full: None,
                    minutes_to_empty: Some(40),
                    energy_mwh: Some(5_800),
                    rate_mw: Some(8_700),
                    ..charging
                };
                for (delay, state) in [(10, charging), (8, discharging)] {
                    thread::sleep(Duration::from_secs(delay));
                    let text = state.to_string();
                    let _ = fs::write(osyx_abi::BATTERY_STATUS_PATH, &text);
                    println!("BATTERY_DEMO {}", text.trim_end().replace('\n', " | "));
                }
            });
            return desktop_session();
        }
        Some("swap-stress") => return swap_stress(),
        Some("zen-probe") => {
            let mode = args.get(3).map(String::as_str).unwrap_or("");
            return zen_probe(args.get(2).map(String::as_str), mode == "trace", mode == "mozlog", mode == "events", mode == "count", false, mode == "prof");
        }
        Some("zen-installed") => {
            let mode = args.get(3).map(String::as_str).unwrap_or("");
            return zen_probe(args.get(2).map(String::as_str), mode == "trace", mode == "mozlog", mode == "events", mode == "count", true, mode == "prof");
        }
        // `init tests winapp <program> [args...]`: PRISM and then one Windows
        // GUI program (an installer, for instance) with winrun's verbose log.
        Some("winapp") => {
            if let Err(e) = Command::new("/system/bin/prism").spawn() {
                println!("winapp: PRISM did not start: {e}");
                return 1;
            }
            thread::sleep(Duration::from_secs(2));
            let mut c = Command::new("/bin/winrun");
            c.arg("-v");
            for a in &args[2..] {
                c.arg(a);
            }
            let code = c.status().ok().and_then(|s| s.code()).unwrap_or(1);
            println!("winapp: exit status {code}");
            return code;
        }
        // `init winrun <program> [args...]`: one Windows program with no
        // sessions around it, for bring-up diagnostics.
        Some("winrun") => {
            let mut c = Command::new("/bin/winrun");
            c.arg("-v");
            for a in &args[2..] {
                c.arg(a);
            }
            return c.status().ok().and_then(|s| s.code()).unwrap_or(1);
        }
        // USB stick scenario driven by scripts/usb-storage-test.ps1.
        Some("media") => return media_checks::run(),
        Some("net") => {
            let port = |i: usize, d: u16| args.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
            let mut t = Tests::default();
            net_checks::run(&mut t, port(2, 7101), port(3, 7102));
            println!("net checks: {} passed, {} failed", t.passed, t.failed);
            return t.failed as i32;
        }
        Some("win") => {
            let port = |i: usize, d: u16| args.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
            let mut t = Tests::default();
            win_checks::run_all(&mut t, port(2, 7101), port(3, 7102));
            println!("win checks: {} passed, {} failed", t.passed, t.failed);
            return t.failed as i32;
        }
        Some("smp") => {
            let mut t = Tests::default();
            smp_checks::run(&mut t);
            prio_checks::run(&mut t);
            println!("smp checks: {} passed, {} failed",t.passed,t.failed);
            return t.failed as i32;
        }
        Some("crash-prep") => {
            // Leave a removed-but-open file on the ext4 root, then exit
            // (the kernel's test.power-cut stops the machine right after).
            let _holder = worker(&["hold-orphan", "/crash-orphan.bin"]).spawn();
            thread::sleep(Duration::from_millis(500));
            println!("crash-prep: orphan held by a child; exiting");
            return 0;
        }
        _ => {}
    }

    let mut t = Tests::default();
    t.check("std-style collections", || {
        let mut values = Vec::new();
        for v in [10, 20] {
            values.push(v);
        }
        println!("Values: {:?}", values);
        let mut words: BTreeMap<String, usize> = BTreeMap::new();
        for w in "the quick brown fox jumps over the lazy dog the end".split(' ') {
            *words.entry(w.to_string()).or_default() += 1;
        }
        values == [10, 20] && words["the"] == 3 && words.len() == 9
    });
    t.check("heap: 2 MiB vector and many small boxes", || {
        let big = vec![0xA5u8; 2 << 20];
        let boxes: Vec<Box<u64>> = (0..10_000).map(Box::new).collect();
        big.iter().all(|&b| b == 0xA5) && boxes.iter().map(|b| **b).sum::<u64>() == 49_995_000
    });
    t.check("string formatting", || {
        format!("{:>8.3}|{:#x}|{:?}", "OSyx Std", 255, Some("x")) == "     OSy|0xff|Some(\"x\")"
    });
    t.check("sysinfo", || match os::sysinfo() {
        Ok(info) => {
            println!(
                "kernel {} | ABI {} | pid {} | {} MiB free of {} MiB | page {} B",
                os::kernel_version(&info),
                info.abi_version,
                info.pid,
                info.free_memory >> 20,
                info.total_memory >> 20,
                info.page_size
            );
            info.abi_version == raw::ABI_VERSION && info.page_size == 4096 && info.free_memory <= info.total_memory
        }
        Err(e) => {
            println!("sysinfo failed: {e}");
            false
        }
    });
    t.check("display: mode setting (VirtIO-GPU switches, GOP keeps its mode)", || {
        let Ok(d) = os_std::system::display_info() else { return true }; // headless
        let same = os_std::system::display_set_mode(d.width, d.height).is_ok();
        if d.backend == os_std::system::BACKEND_VIRTIO_GPU {
            let switched = os_std::system::display_set_mode(800, 600).is_ok()
                && os_std::system::display_info().is_ok_and(|n| (n.width, n.height, n.stride) == (800, 600, 800));
            let back = os_std::system::display_set_mode(d.width, d.height).is_ok()
                && os_std::system::display_info().is_ok_and(|n| (n.width, n.height) == (d.width, d.height));
            println!("display: virtio-gpu {}x{} -> 800x600 -> back: {}", d.width, d.height, switched && back);
            same && switched && back
        } else {
            let refused =
                os_std::system::display_set_mode(800, 600).err().map(|e| e.kind()) == Some(ErrorKind::Unsupported);
            same && refused
        }
    });
    t.check("memory: protect, fixed and 64 KiB aligned mappings", || {
        let Ok(p) = raw::map_ex(0, 3 * 4096, PROT_READ | PROT_WRITE, raw::MAP_ALIGN_64K) else { return false };
        let aligned = (p as usize).is_multiple_of(0x10000);
        // SAFETY: `p` maps three fresh pages.
        unsafe { p.add(4096).write(7) };
        // SAFETY: the middle page becomes read-only; it is not written again.
        let ro = unsafe { raw::protect(p.add(4096), 4096, PROT_READ) }.is_ok();
        // W^X: writable + executable is refused; outside a mapping is invalid.
        // SAFETY: the calls are expected to fail and change nothing.
        let wx = unsafe { raw::protect(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) } == Err(Errno::PermissionDenied);
        // SAFETY: as above.
        let outside = unsafe { raw::protect(p.add(16 * 4096), 4096, PROT_READ) } == Err(Errno::InvalidArgument);
        // SAFETY: the page is still readable.
        let kept = unsafe { p.add(4096).read() } == 7;
        let fixed_at = p as usize + 0x100_0000;
        let fixed = raw::map_ex(fixed_at, 4096, PROT_READ | PROT_WRITE, raw::MAP_FIXED) == Ok(fixed_at as *mut u8);
        let taken = raw::map_ex(fixed_at, 4096, PROT_READ, raw::MAP_FIXED) == Err(Errno::AlreadyExists);
        // SAFETY: both regions were mapped above with these lengths.
        let freed = unsafe { raw::unmap(p, 3 * 4096).is_ok() && raw::unmap(fixed_at as *mut u8, 4096).is_ok() };
        aligned && ro && wx && outside && kept && fixed && taken && freed
    });
    t.check("GS base per thread (set_gs_base)", || {
        let read_gs = || {
            let v: u64;
            // SAFETY: gs:[0] is readable whenever the GS base points at `cell`.
            unsafe { core::arch::asm!("mov {}, gs:[0]", out(reg) v, options(nostack, readonly)) };
            v
        };
        let cell = Box::new(0x5EED_u64);
        if raw::set_gs_base(&*cell as *const u64 as usize).is_err() {
            return false;
        }
        let mine = read_gs() == 0x5EED;
        // Another thread has its own GS base (0 until it sets one).
        let other = thread::spawn(move || {
            let cell2 = Box::new(0xBEEF_u64);
            raw::set_gs_base(&*cell2 as *const u64 as usize).is_ok() && {
                let v: u64;
                // SAFETY: as above, for this thread's cell.
                unsafe { core::arch::asm!("mov {}, gs:[0]", out(reg) v, options(nostack, readonly)) };
                v == 0xBEEF
            }
        })
        .join()
        .unwrap_or(false);
        thread::yield_now();
        let still = read_gs() == 0x5EED;
        let _ = raw::set_gs_base(0);
        mine && other && still
    });
    t.check("monotonic clock", || {
        let a = Instant::now();
        let b = Instant::now();
        b >= a
    });
    t.check("kernel rejects kernel-space pointer", || raw::write_raw(1, 0xFFFF_8000_0000_0000, 8) == Err(Errno::Fault));
    t.check("kernel rejects null pointer", || raw::write_raw(1, 0, 4) == Err(Errno::Fault));
    t.check("kernel rejects unmapped user pointer", || raw::write_raw(1, 0x7000_0000_0000, 16) == Err(Errno::Fault));
    t.check("kernel rejects bad handle", || raw::write_raw(42, RODATA.as_ptr() as usize, 1) == Err(Errno::BadHandle));
    t.check("kernel refuses to write into read-only memory", || {
        raw::sysinfo_raw(RODATA.as_ptr() as usize) == Err(Errno::Fault) && RODATA[0] == 0x5A
    });
    t.check("unknown system call", || raw::raw_syscall(999, 0, 0, 0) == Err(Errno::NotSupported));
    t.check("W^X: writable+executable mapping refused", || {
        raw::map(4096, PROT_READ | PROT_WRITE | PROT_EXEC).err() == Some(Errno::PermissionDenied)
    });
    t.check("map / unmap round trip", || {
        let Ok(p) = raw::map(3 * 4096, PROT_READ | PROT_WRITE) else { return false };
        // SAFETY: freshly mapped, zeroed, writable, 3 pages long.
        let ok = unsafe {
            let s = core::slice::from_raw_parts_mut(p, 3 * 4096);
            let zeroed = s.iter().all(|&b| b == 0);
            s.fill(7);
            zeroed && s[3 * 4096 - 1] == 7
        };
        // SAFETY: no references into the region remain.
        ok && unsafe { raw::unmap(p, 3 * 4096) }.is_ok() && unsafe { raw::unmap(p, 3 * 4096) }.is_err()
    });
    t.check("memory: demand-zero pages, kernel access and discard", || {
        const GIB: usize = 1 << 30;
        let free = || os::sysinfo().map_or(0, |i| i.free_memory);
        let before = free();
        // A 1 GiB reservation costs no frames until its pages are touched.
        let Ok(p) = raw::map(GIB, PROT_READ | PROT_WRITE) else { return false };
        let cheap = before.saturating_sub(free()) < 4 << 20;
        // SAFETY: inside the fresh mapping.
        let touched = unsafe {
            let q = p.add(GIB / 2);
            let zero = q.read() == 0;
            q.write(9);
            zero && q.read() == 9
        };
        // The kernel fills an untouched page through a user copy.
        let kernel = raw::sysinfo_raw(p as usize + 700 * (1 << 20)).is_ok();
        // A fixed mapping may not land on untouched pages of the region.
        let taken = raw::map_ex(p as usize + GIB - 4096, 4096, PROT_READ, raw::MAP_FIXED) == Err(Errno::AlreadyExists);
        // SAFETY: the discarded page is only read again, as zeros.
        let discarded = unsafe { raw::discard(p.add(GIB / 2), 4096).is_ok() && p.add(GIB / 2).read() == 0 };
        // SAFETY: all three pages are inside the mapping and are read as zeros.
        let discarded_range = unsafe {
            let q = p.add(GIB / 2 + 3 * 4096);
            q.write(1);
            q.add(4096).write(2);
            q.add(8192).write(3);
            raw::discard(q, 3 * 4096).is_ok() && q.read() == 0 && q.add(4096).read() == 0 && q.add(8192).read() == 0
        };
        // SAFETY: no references into the region remain.
        let freed = unsafe { raw::unmap(p, GIB) }.is_ok();
        cheap && touched && kernel && taken && discarded && discarded_range && freed
    });
    t.check("memory: main stack demand-zero growth", || {
        let mut stack = [0u8; 256 * 1024];
        for page in stack.chunks_mut(4096) {
            page[0] = 1;
        }
        core::hint::black_box(stack.as_slice()).iter().map(|&b| b as u64).sum::<u64>() == 64
    });

    process_checks(&mut t);
    thread_checks(&mut t);
    fs_checks::run(&mut t);
    exec_checks::run(&mut t);
    ipc_checks::run(&mut t);

    println!("user checks: {} passed, {} failed", t.passed, t.failed);
    t.failed as i32
}

/// Diagnostic mode for a small VM: fill enough private memory to cross the
/// reclaim watermark, allow aging, then verify every page after it may have
/// been evicted and restored. The serial swap counters prove reclaim ran.
fn swap_stress() -> i32 {
    const PAGE: usize = 4096;
    let free = os::sysinfo().map_or(0, |i| i.free_memory as usize);
    let bytes = free.saturating_sub(24 << 20).min(256 << 20) / PAGE * PAGE;
    if bytes < 16 << 20 {
        eprintln!("swap-stress: insufficient free memory");
        return 1;
    }
    let Ok(p) = raw::map(bytes, PROT_READ | PROT_WRITE) else { return 1 };
    println!("swap-stress: filling {} pages", bytes / PAGE);
    for i in 0..bytes / PAGE {
        // SAFETY: each address belongs to the writable mapping.
        unsafe {
            p.add(i * PAGE).write_volatile((i % 251 + 1) as u8);
            p.add(i * PAGE + PAGE - 1).write_volatile((i % 239 + 1) as u8);
        }
    }
    thread::sleep(Duration::from_secs(3));
    for i in 0..bytes / PAGE {
        // SAFETY: the mapping is still live; reads may fault pages back in.
        let valid = unsafe {
            p.add(i * PAGE).read_volatile() == (i % 251 + 1) as u8
                && p.add(i * PAGE + PAGE - 1).read_volatile() == (i % 239 + 1) as u8
        };
        if !valid {
            eprintln!("swap-stress: data mismatch at page {i}");
            return 1;
        }
    }
    // SAFETY: no references into the region remain.
    if unsafe { raw::unmap(p, bytes) }.is_err() { return 1; }
    println!("swap-stress: verified {} pages", bytes / PAGE);
    0
}

/// `init desktop`: runs the graphical session (PRISM from the root file
/// system, which starts the desktop shell) and restarts it if it fails. If
/// it cannot be brought up, init exits and the kernel's status screen
/// stays as the diagnostic fallback.
fn zen_probe(url: Option<&str>, network_trace: bool, mozlog: bool, events: bool, count: bool, installed: bool, prof: bool) -> i32 {
    println!("zen-probe: official /opt/zen/zen.exe via /bin/winrun; no substitute browser");
    let mut prism_cmd = Command::new("/system/bin/prism");
    // Trace only on request: serial output is slow and the compositor's
    // per-frame logging costs more than a full frame at 1080p.
    if network_trace { prism_cmd.env("OSYX_PRISM_TRACE", "1"); }
    if events { prism_cmd.env("OSYX_PRISM_EVENTS", "1"); }
    let prism = prism_cmd.spawn();
    if let Err(e) = &prism { println!("ZEN_PROBE_RESULT infrastructure=prism_start_failed: {e}"); return 1; }
    // Prism clients retry service lookup and wait for the HELLO response, so
    // launching Zen immediately cannot race compositor startup.
    // OSyx has no Direct3D driver. Use Gecko's software WebRender path
    // explicitly instead of repeatedly probing unsupported DXGI devices.
    // Keep repeated boots of a diagnostic image independent, including
    // window-placement preferences and incomplete startup caches. Each run
    // leaves a ~30 MiB browser cache behind, which would otherwise fill the
    // 1 GiB root file system after a few dozen boots.
    if let Ok(entries) = os_std::fs::read_dir("/home") {
        for entry in entries {
            if entry.file_name().starts_with("zen-probe-profile-") {
                let _ = os_std::fs::remove_dir_all(entry.path());
            }
        }
    }
    let stamp = os_std::time::SystemTime::now().duration_since(os_std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let profile = format!("/home/zen-probe-profile-{stamp}");
    println!("zen-probe: profile {profile}");
    let mut prefs = String::from(
        r#"user_pref("gfx.webrender.software", true);
user_pref("gfx.webrender.software.d3d11", false);
user_pref("gfx.webrender.compositor", false);
user_pref("layout.frame_rate", 60);
user_pref("layers.acceleration.disabled", true);
user_pref("layers.gpu-process.enabled", false);
user_pref("layers.gpu-process.force-enabled", false);
user_pref("zen.welcome-screen.seen", true);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("fission.autostart", false);
user_pref("fission.webContentIsolationStrategy", 0);
user_pref("browser.tabs.remote.autostart", false);
user_pref("browser.tabs.remote.autostart.2", false);
user_pref("browser.tabs.remote.separatePrivilegedContentProcess", false);
user_pref("browser.tabs.remote.separateFileUriProcess", false);
user_pref("browser.tabs.remote.separatePrivilegedMozillaWebContentProcess", false);
user_pref("dom.ipc.processCount", 1);
user_pref("dom.ipc.processCount.webIsolated", 1);
user_pref("dom.ipc.processCount.file", 1);
user_pref("dom.ipc.processCount.privilegedabout", 1);
user_pref("dom.ipc.processCount.privilegedmozilla", 1);
user_pref("dom.ipc.processPrelaunch.enabled", false);
user_pref("dom.ipc.keepProcessesAlive.web", 0);
user_pref("dom.ipc.keepProcessesAlive.privilegedabout", 0);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("media.gmp-manager.updateEnabled", false);
user_pref("media.gmp-provider.enabled", false);
user_pref("media.gmp-widevinecdm.enabled", false);
user_pref("media.gmp-widevinecdm.visible", false);
user_pref("media.gmp-gmpopenh264.enabled", false);
user_pref("media.gmp-gmpopenh264.autoupdate", false);
user_pref("app.update.enabled", false);
user_pref("app.update.auto", false);
user_pref("app.update.background.scheduling.enabled", false);
user_pref("extensions.update.enabled", false);
user_pref("extensions.getAddons.cache.enabled", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
"#,
    );
    if network_trace {
        prefs.push_str("user_pref(\"devtools.console.stdout.chrome\", true);\nuser_pref(\"devtools.console.stdout.content\", true);\n");
    }
    if os_std::fs::create_dir_all(&profile).and_then(|_| os_std::fs::write(
        format!("{profile}/user.js"),
        prefs,
    )).and_then(|_| os_std::fs::write(
        "/tmp/zen-probe-page.html",
        "<!doctype html><meta charset=utf-8><title>OSyx Zen rendering test</title><style>body{margin:40px;background:#dbeafe;color:#172554;font:20px Lato,sans-serif}button{font:inherit;padding:16px}#box{width:240px;height:120px;background:#16a34a;margin:24px 0}</style><h1>Zen renders HTML</h1><p>This page is rendered by the unmodified browser.</p><input id=inp autofocus oninput=\"document.title='INPUT:'+this.value\" style=\"font:20px Lato,sans-serif;padding:8px;width:320px;caret-color:transparent\"><div id=box></div><button onclick=\"document.title='OSyx click verified';this.textContent='Click verified';document.getElementById('box').style.background='#f97316'\">Verify click</button><p><a target=_blank href=https://example.com/>Open example.com over HTTPS</a></p><script>addEventListener('keydown',e=>{document.title='KD:'+(e.target.id||e.target.nodeName)+':'+e.key});addEventListener('keypress',e=>{document.title='KP:'+e.key})</script>",
    )).is_err() {
        println!("ZEN_PROBE_RESULT infrastructure=profile_creation_failed");
        if let Ok(p) = prism { let _ = os_std::system::kill(p.id()); let _ = p.wait(); }
        return 1;
    }
    let mut zen = Command::new(if installed { "/system/bin/zen" } else { "/bin/winrun" });
    // The session runs as root, so Gecko's launcher would start the browser
    // with a de-elevated token, which OSyx cannot run: keep its own. The
    // probe has its own temporary profile with software-rendering prefs.
    if !installed {
        if network_trace { zen.arg("-v"); }
        zen.args(["/opt/zen/zen.exe", "--no-remote", "-profile"]);
    }
    let url = url.unwrap_or("file:///C:/tmp/zen-probe-page.html");
    println!("zen-probe: URL {url}");
    if events {
        // TEMP clock-check: RDTSC fast clock vs kernel tick clock, once the
        // windowed TSC rate has matured, while Zen is loading.
        thread::spawn(|| {
            thread::sleep(Duration::from_millis(8000));
            let mut a = [0u64; 4];
            let _ = raw::raw_syscall(raw::nr::TIME_CALIB, a.as_mut_ptr() as u64, 0, 0);
            let t0 = Instant::now();
            let r0 = unsafe { core::arch::x86_64::_rdtsc() };
            let c0 = raw::raw_syscall(raw::nr::CLOCK, 0, 0, 0).unwrap_or(0);
            thread::sleep(Duration::from_millis(2000));
            let r1 = unsafe { core::arch::x86_64::_rdtsc() };
            let fast = t0.elapsed().as_millis() as u64;
            let c1 = raw::raw_syscall(raw::nr::CLOCK, 0, 0, 0).unwrap_or(0);
            let mut b = [0u64; 4];
            let _ = raw::raw_syscall(raw::nr::TIME_CALIB, b.as_mut_ptr() as u64, 0, 0);
            let rd = r1.wrapping_sub(r0);
            let kd = b[0].wrapping_sub(a[0]);
            println!(
                "clock-check: fast={fast}ms clock={}ms kern_dt={}ms per0={} per1={} tsc={} real_per={}",
                (c1 - c0) / 1_000_000,
                kd / 1_000_000,
                a[2],
                b[2],
                rd,
                if kd != 0 { (rd as u128 * 1_000_000 / kd as u128) as u64 } else { 0 },
            );
        });
    }
    if !installed { zen.arg(&format!("C:{}", profile.replace('/', "\\"))); }
    zen.arg(url);
    // This bootstrap flag also reaches Gecko's command-line handler, which
    // still sees it as unknown and skips the following argument. Keep it
    // last so that the requested URL is not silently discarded.
    if !installed { zen.arg("-no-deelevate"); }
    else if network_trace {
        zen.env("OSYX_ZEN_TRACE", "1");
    }
    // Gecko's Windows sandbox broker starts its children suspended and
    // patches their memory, which OSyx gives no process the right to do:
    // Mozilla's own switches start them unsandboxed instead.
    if network_trace || mozlog {
        if network_trace {
            // Every failing Windows API call goes to the serial log (bring-up).
            zen.env("OSYX_WINRUN_TRACE", "1");
        }        let log_modules = if network_trace {
            "timestamp,sync,nsDocShell:5,DocLoader:5,nsStreamPump:5,nsSocketTransport:2,nsHostResolver:3,pipnss:4,nsHttp:5,nsChannelClassifier:5"
        } else {
            "timestamp,sync,nsDocShell:5,DocLoader:5,nsHttp:5,PresShell:4,RefreshDriver:5,Vsync:5,Compositor:5"
        };
        zen.env("MOZ_LOG", log_modules);
    }
    if events || mozlog { zen.env("OSYX_WINRUN_EVENTS", "1"); }
    if count { zen.env("OSYX_WINRUN_COUNT", "1"); }
    // Module bases for the kernel profiler's user-mode samples.
    if prof { zen.env("OSYX_WINRUN_MODULES", "1"); }
    for kind in ["CONTENT", "GPU", "RDD", "SOCKET_PROCESS", "GMP", "UTILITY", "VR"] {
        zen.env(&format!("MOZ_DISABLE_{kind}_SANDBOX"), "1");
    }
    if count || network_trace {
        // Diagnostic: which process uses the CPU during startup.
        thread::spawn(|| {
            let mut prev: Vec<(u64, u64)> = Vec::new();
            let mut prev_ticks = 0u64;
            loop {
                thread::sleep(Duration::from_secs(2));
                let Ok(list) = os_std::system::processes() else { continue };
                let ticks = os_std::os::sysinfo().map(|s| s.ticks).unwrap_or(prev_ticks);
                let dt = ticks.saturating_sub(prev_ticks).max(1);
                let mut rows: Vec<(u64, String, u32, u64)> = Vec::new();
                for p in &list {
                    let before = prev.iter().find(|(pid, _)| *pid == p.pid).map(|(_, t)| *t).unwrap_or(p.cpu_ticks);
                    let delta = p.cpu_ticks.saturating_sub(before);
                    if delta > 0 {
                        rows.push((delta * 100 / dt, os_std::system::process_name(p), p.threads, p.pid));
                    }
                }
                rows.sort_by_key(|a| core::cmp::Reverse(a.0));
                let mut line = String::from("cpuwatch:");
                for (pct, name, threads, pid) in rows.iter().take(6) {
                    line.push_str(&format!(" {name}[{pid}]={pct}%/{threads}t"));
                }
                println!("{line}");
                prev = list.iter().map(|p| (p.pid, p.cpu_ticks)).collect();
                prev_ticks = ticks;
            }
        });
    }
    let result = zen.status();
    println!("ZEN_PROBE_RESULT exit={:?}", result.as_ref().ok().and_then(|s| s.code()));
    if let Ok(p) = prism { let _ = os_std::system::kill(p.id()); let _ = p.wait(); }
    // Boot completion is separate from browser success; the host reads
    // the actual winrun exit above and never treats this as a browser pass.
    0
}

fn desktop_session() -> i32 {
    const PRISM: &str = "/system/bin/prism";
    // Tasks the installer left for the first start; they run beside the
    // session (a download must not hold up the desktop).
    if fs::metadata("/etc/osyx/firstboot.conf").is_ok() {
        match Command::new("/bin/firstboot").spawn() {
            Ok(c) => println!("init: first-boot tasks running (process {})", c.id()),
            Err(e) => eprintln!("init: cannot start /bin/firstboot: {e}"),
        }
    }
    // Battery and AC state for the taskbar (ACPI; runs as root). The AML
    // interpreter can meet firmware it cannot handle and end the process:
    // it is started again a few times.
    thread::spawn(|| {
        const GIVE_UP_AFTER: u32 = 8;
        let mut quick_failures = 0;
        loop {
            let started = Instant::now();
            match Command::new("/bin/batteryd").status() {
                Ok(s) if s.success() => {
                    println!("init: batteryd finished");
                    return;
                }
                Ok(s) => eprintln!("init: batteryd ended with status {:#x}", s.raw()),
                Err(e) => {
                    eprintln!("init: cannot start /bin/batteryd: {e}");
                    return;
                }
            }
            // A run of a minute or more was working: it starts the count over.
            quick_failures = if started.elapsed() >= Duration::from_secs(60) { 1 } else { quick_failures + 1 };
            if quick_failures >= GIVE_UP_AFTER {
                eprintln!("init: batteryd keeps failing; no battery state will be published");
                return;
            }
            thread::sleep(Duration::from_secs(5 * quick_failures as u64));
        }
    });
    println!("init: battery state kept by /bin/batteryd");
    // Touchpads and keyboards on I2C (HID over I2C): ACPI discovery, then the
    // kernel driver takes over. Runs as root and exits when done.
    match Command::new("/bin/i2chidd").spawn() {
        Ok(c) => println!("init: HID over I2C discovery running (process {})", c.id()),
        Err(e) => eprintln!("init: cannot start /bin/i2chidd: {e}"),
    }
    // Recover an established Wi-Fi connection when its gateway stops responding.
    match Command::new("/bin/wifi-watch").spawn() {
        Ok(c) => println!("init: Wi-Fi recovery running (process {})", c.id()),
        Err(e) => eprintln!("init: cannot start /bin/wifi-watch: {e}"),
    }
    // Network time: the clock is set once a network is up.
    match Command::new("/bin/timesync").arg("--daemon").spawn() {
        Ok(c) => println!("init: network time kept by process {}", c.id()),
        Err(e) => eprintln!("init: cannot start /bin/timesync: {e}"),
    }
    // System updates of an installed system (checks once a day).
    if fs::metadata("/etc/osyx/installed").is_ok() {
        match Command::new("/bin/osyx-update").arg("--daemon").spawn() {
            Ok(c) => println!("init: system updates checked by process {}", c.id()),
            Err(e) => eprintln!("init: cannot start /bin/osyx-update: {e}"),
        }
    }
    if let Ok(h) = fs::read_to_string("/etc/hostname") {
        println!("init: host name {}", h.trim());
    }
    for attempt in 1..=3 {
        println!("starting the graphical session: {PRISM} (attempt {attempt})");
        match Command::new(PRISM).status() {
            Ok(s) if s.success() => return 0,
            Ok(s) => eprintln!("{PRISM} ended with status {:#x}", s.raw()),
            Err(e) => {
                eprintln!("cannot start {PRISM}: {e}");
                return 1;
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
    eprintln!("the graphical session keeps failing; the kernel console stays");
    1
}

/// The live installation session: the desktop with OSyx Setup opened on
/// it. `extra` goes to the installer (`--auto ...` in tests).
fn setup_session(extra: &[String]) -> i32 {
    const SETUP: &str = "/system/bin/setup";
    let mut c = Command::new(SETUP);
    c.arg("--wait-session");
    for a in extra {
        c.arg(a);
    }
    match c.spawn() {
        Ok(child) => println!("init: started {SETUP} (process {})", child.id()),
        Err(e) => eprintln!("init: cannot start {SETUP}: {e}"),
    }
    desktop_session()
}

fn worker(args: &[&str]) -> Command {
    let mut c = Command::new("worker");
    c.args(args);
    c
}

fn process_checks(t: &mut Tests) {
    t.check(
        "spawn + wait: child exit code",
        || matches!(worker(&["exit", "7"]).status(), Ok(s) if s.code() == Some(7)),
    );
    t.check("spawn: unknown program is NotFound", || {
        Command::new("no-such-program").spawn().map(|c| c.id()).map_err(|e| e.kind()) == Err(ErrorKind::NotFound)
    });
    t.check("wait: no such child", || raw::wait_raw(9999, 0) == Err(Errno::NoChild));
    t.check("wait: bad status pointer keeps the child waitable", || {
        let Ok(child) = worker(&["exit", "5"]).spawn() else { return false };
        let bad = raw::wait_raw(child.id(), 0xFFFF_8000_0000_0000) == Err(Errno::Fault);
        bad && matches!(child.wait(), Ok(s) if s.code() == Some(5))
    });
    t.check("wait_any collects every child once", || {
        let a = worker(&["exit", "11"]).spawn();
        let b = worker(&["exit", "12"]).spawn();
        if a.is_err() || b.is_err() {
            return false;
        }
        let mut codes = Vec::new();
        for _ in 0..2 {
            match process::wait_any() {
                Ok((_, s)) => codes.push(s.code().unwrap_or(-1)),
                Err(_) => return false,
            }
        }
        codes.sort();
        codes == [11, 12] && process::wait_any().map_err(|e| e.kind()).err() == Some(ErrorKind::NoChild)
    });
    t.check("nested spawn (grandchild)", || matches!(worker(&["child", "9"]).status(), Ok(s) if s.code() == Some(9)));
    t.check(
        "child CPU exception is reported",
        || matches!(worker(&["fault"]).status(), Ok(s) if s.exception() == Some(14) && s.code().is_none()),
    );
    t.check("sleep blocks for the requested time", || {
        let start = Instant::now();
        thread::sleep(Duration::from_millis(50));
        thread::yield_now();
        start.elapsed() >= Duration::from_millis(50)
    });
    t.check("preemption: 3 busy children run concurrently", || {
        // Each child spins 300 ms without yielding. Run one after another
        // they would need ~900 ms; preempted round robin, ~300 ms.
        let start = Instant::now();
        let kids: Vec<Child> = (0..3).filter_map(|_| worker(&["spin", "300"]).spawn().ok()).collect();
        let n = kids.len();
        let all_ok = kids.into_iter().all(|k| matches!(k.wait(), Ok(s) if s.success()));
        let took = start.elapsed();
        println!("3 x 300 ms spinners finished in {} ms", took.as_millis());
        n == 3 && all_ok && took >= Duration::from_millis(300) && took < Duration::from_millis(650)
    });
    t.check("FPU/SSE registers survive preemption", || {
        let mut kids_ok = false;
        // init keeps its own pattern in xmm0-15 while two children spin with
        // different patterns in theirs.
        let mine = fpu::preserved_across(0xAAAA_0000_0000_0000, || {
            let a = worker(&["fpu", "1", "200"]).spawn();
            let b = worker(&["fpu", "2", "200"]).spawn();
            if let (Ok(a), Ok(b)) = (a, b) {
                let sa = a.wait();
                let sb = b.wait();
                kids_ok = matches!(sa, Ok(s) if s.success()) && matches!(sb, Ok(s) if s.success());
            }
        });
        mine && kids_ok
    });
    t.check("orphaned grandchild is adopted by the kernel", || {
        let ok = matches!(worker(&["orphan"]).status(), Ok(s) if s.success());
        // Give the orphan (sleeping 100 ms) time to exit before init does.
        thread::sleep(Duration::from_millis(200));
        ok && process::wait_any().map_err(|e| e.kind()).err() == Some(ErrorKind::NoChild)
    });
    t.check("process id from sysinfo", || process::id().is_ok_and(|p| p >= 1));
}

#[derive(Default)]
struct Tests {
    passed: u32,
    failed: u32,
}

impl Tests {
    fn check(&mut self, name: &str, f: impl FnOnce() -> bool) {
        if f() {
            println!("[user] {name} ... ok");
            self.passed += 1;
        } else {
            eprintln!("[user] {name} ... FAILED");
            self.failed += 1;
        }
    }
}

os_std::thread_local! {
    static LOCAL_ID: core::cell::Cell<u64> = core::cell::Cell::new(0);
    static DROP_PROBE: DropProbe = DropProbe;
}

static TLS_DROPS: AtomicUsize = AtomicUsize::new(0);

struct DropProbe;

impl Drop for DropProbe {
    fn drop(&mut self) {
        TLS_DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

fn thread_checks(t: &mut Tests) {
    t.check("threads: spawn and join return values", || {
        let hs: Vec<_> = (1..=4u64).map(|i| thread::spawn(move || (1..=i * 10_000).sum::<u64>())).collect();
        let sums: Vec<u64> = hs.into_iter().filter_map(|h| h.join().ok()).collect();
        sums == [50_005_000, 200_010_000, 450_015_000, 800_020_000]
    });
    t.check("threads: distinct ids and names", || {
        let main_id = thread::current().id();
        let h = thread::Builder::new()
            .name(String::from("named"))
            .spawn(|| (thread::current().id(), thread::current().name().map(String::from)))
            .unwrap();
        let (id, name) = h.join().unwrap();
        id != main_id && name.as_deref() == Some("named") && thread::current().name() == Some("main")
    });
    t.check("Mutex: 4 threads x 20000 slow increments under preemption", || {
        // Read, delay, write inside the lock: if the mutex did not exclude,
        // a preemption between read and write would lose increments.
        let m = Arc::new(Mutex::new(0u64));
        let contended = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let m = m.clone();
                let contended = contended.clone();
                thread::spawn(move || {
                    for _ in 0..20_000 {
                        let mut g = match m.try_lock() {
                            Ok(g) => g,
                            Err(_) => {
                                contended.fetch_add(1, Ordering::Relaxed);
                                m.lock().unwrap()
                            }
                        };
                        let v = *g;
                        for _ in 0..40 {
                            core::hint::spin_loop();
                        }
                        *g = v + 1;
                    }
                })
            })
            .collect();
        let joined = hs.into_iter().all(|h| h.join().is_ok());
        let total = *m.lock().unwrap();
        let waits = contended.load(Ordering::Relaxed);
        println!("mutex counter: {total} in {} ms, {waits} contended acquisitions", start.elapsed().as_millis());
        joined && total == 80_000 && waits > 0
    });
    t.check("Condvar: producer / 3 consumers", || {
        let q = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let consumers: Vec<_> = (0..3)
            .map(|_| {
                let q = q.clone();
                thread::spawn(move || {
                    let (m, cv) = &*q;
                    let mut sum = 0u64;
                    loop {
                        let mut g = cv.wait_while(m.lock().unwrap(), |q: &mut VecDeque<u64>| q.is_empty()).unwrap();
                        match g.pop_front() {
                            Some(0) | None => return sum,
                            Some(v) => sum += v,
                        }
                    }
                })
            })
            .collect();
        let (m, cv) = &*q;
        for v in 1..=500u64 {
            m.lock().unwrap().push_back(v);
            cv.notify_one();
            if v % 50 == 0 {
                thread::yield_now();
            }
        }
        m.lock().unwrap().extend([0, 0, 0]);
        cv.notify_all();
        let total: u64 = consumers.into_iter().filter_map(|h| h.join().ok()).sum();
        total == 125_250
    });
    t.check("Condvar: wait_timeout expires", || {
        let m = Mutex::new(());
        let cv = Condvar::new();
        let start = Instant::now();
        let (_g, r) = cv.wait_timeout(m.lock().unwrap(), Duration::from_millis(30)).unwrap();
        r.timed_out() && start.elapsed() >= Duration::from_millis(30)
    });
    t.check("RwLock: readers share, writers exclude", || {
        // The pair must never be seen half-updated: a writer between the two
        // stores would be caught by a concurrent reader.
        let lock = Arc::new(RwLock::new((0u64, 0u64)));
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let lock = lock.clone();
                thread::spawn(move || {
                    for _ in 0..4_000 {
                        let g = lock.read().unwrap();
                        if g.0 != g.1 {
                            return false;
                        }
                        core::hint::spin_loop();
                    }
                    true
                })
            })
            .collect();
        let writer = {
            let lock = lock.clone();
            thread::spawn(move || {
                for _ in 0..1_000 {
                    let mut g = lock.write().unwrap();
                    g.0 += 1;
                    core::hint::spin_loop();
                    g.1 += 1;
                }
            })
        };
        let readers_ok = readers.into_iter().all(|h| h.join().unwrap_or(false));
        readers_ok && writer.join().is_ok() && *lock.read().unwrap() == (1_000, 1_000)
    });
    t.check("Once / OnceLock: initialise exactly once", || {
        let once = Arc::new(Once::new());
        let runs = Arc::new(AtomicU32::new(0));
        let cell = Arc::new(OnceLock::<u64>::new());
        let hs: Vec<_> = (0..4u64)
            .map(|i| {
                let once = once.clone();
                let runs = runs.clone();
                let cell = cell.clone();
                thread::spawn(move || {
                    once.call_once(|| {
                        runs.fetch_add(1, Ordering::Relaxed);
                    });
                    *cell.get_or_init(|| i * 10)
                })
            })
            .collect();
        let values: Vec<u64> = hs.into_iter().filter_map(|h| h.join().ok()).collect();
        let expected = cell.get().copied();
        runs.load(Ordering::Relaxed) == 1
            && values.len() == 4
            && values.iter().all(|v| Some(*v) == expected)
    });
    t.check("mpsc: 4 senders, bounded try_send, timeout", || {
        let (tx, rx) = mpsc::channel::<u64>();
        let hs: Vec<_> = (0..4u64)
            .map(|i| {
                let tx = tx.clone();
                thread::spawn(move || {
                    for j in 0..100 {
                        tx.send(i * 100 + j).unwrap();
                    }
                })
            })
            .collect();
        drop(tx);
        let mut sum = 0;
        while let Ok(v) = rx.recv() {
            sum += v;
        }
        for h in hs {
            h.join().unwrap();
        }
        let full_ok = {
            let (stx, srx) = mpsc::sync_channel::<u8>(1);
            stx.try_send(1).is_ok()
                && matches!(stx.try_send(2), Err(mpsc::TrySendError::Full(2)))
                && srx.recv() == Ok(1)
        };
        let (ktx, krx) = mpsc::channel::<u8>();
        let timeout_ok = krx.recv_timeout(Duration::from_millis(10)) == Err(mpsc::RecvTimeoutError::Timeout);
        drop(ktx);
        sum == 100 * (0..4u64).sum::<u64>() * 100 + 4 * (0..100u64).sum::<u64>() && full_ok && timeout_ok
    });
    t.check("futex: value mismatch and timeout", || {
        let word = AtomicU32::new(0);
        let mismatch = raw::futex_wait(word.as_ptr(), 1, 0) == Err(Errno::WouldBlock);
        let start = Instant::now();
        let timed = raw::futex_wait(word.as_ptr(), 0, 30_000_000) == Err(Errno::TimedOut);
        let unaligned =
            raw::futex_wait((word.as_ptr() as usize + 1) as *const u32, 0, 1) == Err(Errno::InvalidArgument);
        mismatch
            && timed
            && unaligned
            && start.elapsed() >= Duration::from_millis(30)
            && raw::futex_wake(word.as_ptr(), 1) == 0
    });
    t.check("TLS: thread_local! per thread, destructors run", || {
        LOCAL_ID.with(|c| c.set(1));
        let before = TLS_DROPS.load(Ordering::SeqCst);
        let hs: Vec<_> = (2..=4u64)
            .map(|i| {
                thread::spawn(move || {
                    DROP_PROBE.with(|_| ());
                    LOCAL_ID.with(|c| {
                        let initial = c.get();
                        c.set(i);
                        thread::sleep(Duration::from_millis(20)); // let the others run
                        (initial, c.get())
                    })
                })
            })
            .collect();
        let results: Vec<(u64, u64)> = hs.into_iter().filter_map(|h| h.join().ok()).collect();
        results == [(0, 2), (0, 3), (0, 4)]
            && LOCAL_ID.with(|c| c.get()) == 1
            && TLS_DROPS.load(Ordering::SeqCst) == before + 3
    });
    t.check("detached threads are reaped", || {
        let flag = Arc::new(AtomicU32::new(0));
        let f = flag.clone();
        drop(thread::spawn(move || f.store(1, Ordering::SeqCst)));
        let start = Instant::now();
        while thread::detached_pending() > 0 && start.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(10));
        }
        flag.load(Ordering::SeqCst) == 1 && thread::detached_pending() == 0
    });
    t.check(
        "exit with blocked threads ends the process",
        || matches!(worker(&["threads-exit"]).status(), Ok(s) if s.code() == Some(42)),
    );
    t.check(
        "process lives until its last thread exits",
        || matches!(worker(&["thread-last"]).status(), Ok(s) if s.code() == Some(9)),
    );
    t.check(
        "fault in a spawned thread ends the process",
        || matches!(worker(&["thread-fault"]).status(), Ok(s) if s.exception() == Some(14)),
    );
    t.check(
        "panic in a spawned thread exits with 101",
        || matches!(worker(&["thread-panic"]).status(), Ok(s) if s.code() == Some(101)),
    );
}
