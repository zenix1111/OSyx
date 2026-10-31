//! Window stations, desktops and WaitForInputIdle.
//!
//! OSyx has one interactive session: the window station "WinSta0" with the
//! desktop "Default", where every window of this process appears (in its
//! PRISM session). Other window stations and desktops can be created,
//! named, queried, secured (objsec.rs) and made the process's window
//! station, but they are not separate display surfaces: OSyx cannot hide
//! a desktop's windows from the user, so no thread is ever switched to
//! one (SetThreadDesktop is not provided) and CreateProcess does not start
//! programs on them. Names are per process, like other object names.
//!
//! WaitForInputIdle: a Windows program becomes "input idle" when its GUI
//! thread first waits for messages with an empty queue. winrun records the
//! two steps for its parent in /tmp/.winrun-<pid>.gui (first window) and
//! /tmp/.winrun-<pid>.idle (first wait on an empty queue).
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{self, fail},
    objects::{self, Object},
    objsec, path,
};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use os_std::sync::Mutex;

const ERROR_BUSY: u32 = 170;
const ERROR_NOT_GUI_PROCESS: u32 = 1471;
const CWF_CREATE_ONLY: u32 = 1;
const WSF_VISIBLE: u32 = 1;
const UOI_FLAGS: u32 = 1;
const UOI_NAME: u32 = 2;
const UOI_TYPE: u32 = 3;
const UOI_USER_SID: u32 = 4;
const UOI_HEAPSIZE: u32 = 5;
const UOI_IO: u32 = 6;
/// The desktop heap size Windows reports for interactive desktops (KB).
const HEAP_KB: u32 = 20480;

pub struct Station {
    pub name: String,
    interactive: bool,
    desktops: Mutex<Vec<Arc<DesktopObj>>>,
}

pub struct DesktopObj {
    pub name: String,
    station: Arc<Station>,
    flags: u32,
    interactive: bool,
}

static STATIONS: Mutex<Vec<Arc<Station>>> = Mutex::new(Vec::new());
/// The process's window station handle (GetProcessWindowStation).
static PROCESS_STATION: Mutex<u64> = Mutex::new(0);
/// The handle of the interactive desktop every thread is on.
static THREAD_DESKTOP: Mutex<u64> = Mutex::new(0);
static GENERATED: AtomicU32 = AtomicU32::new(1);

fn interactive() -> Arc<Station> {
    let mut s = STATIONS.lock().unwrap();
    if let Some(w) = s.iter().find(|w| w.interactive) {
        return w.clone();
    }
    let w = Arc::new(Station { name: String::from("WinSta0"), interactive: true, desktops: Mutex::new(Vec::new()) });
    let d = Arc::new(DesktopObj { name: String::from("Default"), station: w.clone(), flags: 0, interactive: true });
    w.desktops.lock().unwrap().push(d);
    s.push(w.clone());
    w
}

fn station(h: u64) -> Result<Arc<Station>, u32> {
    match objects::get(h) {
        Some(Object::WindowStation(w)) => Ok(w),
        _ => Err(ERROR_INVALID_HANDLE),
    }
}

extern "win64" fn CreateWindowStationW(name: *const u16, flags: u32, _access: u32, sa: u64) -> u64 {
    if flags & !CWF_CREATE_ONLY != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if crate::security::inherit_flag(sa) {
        return fail(ERROR_NOT_SUPPORTED, 0); // window stations stay in this process
    }
    let sd = match objsec::initial_sd(sa, &objsec::WINSTA) {
        Ok(s) => s,
        Err(e) => return fail(e, 0),
    };
    // SAFETY: NULL or a NUL-terminated name.
    let name = unsafe { path::wide_to_string(name) }.filter(|n| !n.is_empty());
    if name.as_deref().is_some_and(|n| n.contains('\\')) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    interactive();
    let mut stations = STATIONS.lock().unwrap();
    let name = name.unwrap_or_else(|| format!("Service-0x0-{:x}$", GENERATED.fetch_add(1, Ordering::Relaxed)));
    if let Some(w) = stations.iter().find(|w| w.name.eq_ignore_ascii_case(&name)) {
        if flags & CWF_CREATE_ONLY != 0 {
            return fail(ERROR_ACCESS_DENIED, 0);
        }
        let h = objects::insert(Object::WindowStation(w.clone()));
        drop(stations);
        crate::teb::set_last_error(ERROR_ALREADY_EXISTS);
        return h;
    }
    let w = Arc::new(Station { name, interactive: false, desktops: Mutex::new(Vec::new()) });
    stations.push(w.clone());
    drop(stations);
    let h = objects::insert(Object::WindowStation(w));
    objsec::set_initial(h, sd);
    crate::teb::set_last_error(0);
    h
}

extern "win64" fn CreateDesktopW(name: *const u16, device: *const u16, mode: u64, flags: u32, _access: u32, sa: u64) -> u64 {
    if !device.is_null() || mode != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0); // reserved; must be NULL
    }
    if flags & !1 != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0); // DF_ALLOWOTHERACCOUNTHOOK only
    }
    // SAFETY: NUL-terminated name.
    let Some(name) = (unsafe { path::wide_to_string(name) }).filter(|n| !n.is_empty() && !n.contains('\\')) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    if crate::security::inherit_flag(sa) {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    let sd = match objsec::initial_sd(sa, &objsec::DESKTOP) {
        Ok(s) => s,
        Err(e) => return fail(e, 0),
    };
    let station = match station(GetProcessWindowStation()) {
        Ok(w) => w,
        Err(e) => return fail(e, 0),
    };
    let mut desktops = station.desktops.lock().unwrap();
    if let Some(d) = desktops.iter().find(|d| d.name.eq_ignore_ascii_case(&name)) {
        let h = objects::insert(Object::Desktop(d.clone()));
        crate::teb::set_last_error(ERROR_ALREADY_EXISTS);
        return h;
    }
    let d = Arc::new(DesktopObj { name, station: station.clone(), flags, interactive: false });
    desktops.push(d.clone());
    drop(desktops);
    let h = objects::insert(Object::Desktop(d));
    objsec::set_initial(h, sd);
    crate::teb::set_last_error(0);
    h
}

extern "win64" fn GetProcessWindowStation() -> u64 {
    let mut p = PROCESS_STATION.lock().unwrap();
    if *p == 0 {
        *p = objects::insert(Object::WindowStation(interactive()));
    }
    *p
}

extern "win64" fn SetProcessWindowStation(h: u64) -> i32 {
    if let Err(e) = station(h) {
        return fail(e, 0);
    }
    *PROCESS_STATION.lock().unwrap() = h;
    1
}

/// Whether `tid` is a thread of this process.
fn own_thread(tid: u64) -> bool {
    tid == os_sys::gettid() || objects::any(|o| matches!(o, Object::Thread(t) if t.tid.load(Ordering::SeqCst) as u64 == tid))
}

extern "win64" fn GetThreadDesktop(tid: u32) -> u64 {
    if !own_thread(tid as u64) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut d = THREAD_DESKTOP.lock().unwrap();
    if *d == 0 {
        let desktop = interactive().desktops.lock().unwrap().iter().find(|d| d.interactive).cloned().expect("the default desktop");
        *d = objects::insert(Object::Desktop(desktop));
    }
    *d
}

/// Makes `h` (a desktop handle of this process) the thread's desktop. A
/// thread that owns windows cannot change desktop (ERROR_BUSY). The desktop is
/// kept per process here, as GetThreadDesktop reports it.
extern "win64" fn SetThreadDesktop(h: u64) -> i32 {
    if !matches!(objects::get(h), Some(Object::Desktop(_))) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    if crate::user32::thread_has_windows() {
        return fail(ERROR_BUSY, 0);
    }
    *THREAD_DESKTOP.lock().unwrap() = h;
    1
}

/// A handle to the desktop that receives input: the default desktop of the
/// interactive window station (OSyx has one). `flags` may only be
/// DF_ALLOWOTHERACCOUNTHOOK (1).
extern "win64" fn OpenInputDesktop(flags: u32, _inherit: i32, _access: u32) -> u64 {
    if flags & !1 != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let desktop = interactive().desktops.lock().unwrap().iter().find(|d| d.interactive).cloned().expect("the default desktop");
    objects::insert(Object::Desktop(desktop))
}

extern "win64" fn CloseWindowStation(h: u64) -> i32 {
    if let Err(e) = station(h) {
        return fail(e, 0);
    }
    if *PROCESS_STATION.lock().unwrap() == h {
        return fail(ERROR_BUSY, 0); // the process's own window station
    }
    objects::close(h);
    forget_unused();
    1
}

extern "win64" fn CloseDesktop(h: u64) -> i32 {
    if !matches!(objects::get(h), Some(Object::Desktop(_))) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    if *THREAD_DESKTOP.lock().unwrap() == h {
        return fail(ERROR_BUSY, 0); // a thread's desktop
    }
    objects::close(h);
    forget_unused();
    1
}

/// Drops created window stations and desktops no handle refers to.
fn forget_unused() {
    let mut stations = STATIONS.lock().unwrap();
    for w in stations.iter() {
        // One reference in the station's list; any other is a handle.
        w.desktops.lock().unwrap().retain(|d| d.interactive || Arc::strong_count(d) > 1);
    }
    // The list and each desktop's back reference; any other is a handle.
    stations.retain(|w| w.interactive || Arc::strong_count(w) > 1 + w.desktops.lock().unwrap().len());
}

fn put_info(out: *mut u8, size: u32, needed: *mut u32, data: &[u8]) -> i32 {
    if !needed.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *needed = data.len() as u32 };
    }
    if (size as usize) < data.len() || (out.is_null() && !data.is_empty()) {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    // SAFETY: `size` >= data.len() bytes at `out`.
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len()) };
    1
}

fn wide(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(|c| c.to_le_bytes()).collect()
}

extern "win64" fn GetUserObjectInformationW(h: u64, index: u32, out: *mut u8, size: u32, needed: *mut u32) -> i32 {
    let (name, kind, flags, io, desktop) = match objects::get(h) {
        Some(Object::WindowStation(w)) => (w.name.clone(), "WindowStation", if w.interactive { WSF_VISIBLE } else { 0 }, w.interactive, false),
        Some(Object::Desktop(d)) => (d.name.clone(), "Desktop", d.flags, d.interactive && d.station.interactive, true),
        _ => return fail(ERROR_INVALID_HANDLE, 0),
    };
    let data = match index {
        UOI_FLAGS => [0u32, 0, flags].iter().flat_map(|v| v.to_le_bytes()).collect(), // fInherit, fReserved, dwFlags
        UOI_NAME => wide(&name),
        UOI_TYPE => wide(kind),
        // OSyx tokens have no logon SID, so no object is tied to one.
        UOI_USER_SID => Vec::new(),
        UOI_HEAPSIZE if desktop => HEAP_KB.to_le_bytes().to_vec(),
        UOI_IO => (io as u32).to_le_bytes().to_vec(),
        _ => return fail(ERROR_INVALID_PARAMETER, 0),
    };
    put_info(out, size, needed, &data)
}

// ---- input idle -------------------------------------------------------------------------------

static GUI_NOTED: AtomicBool = AtomicBool::new(false);
static IDLE_NOTED: AtomicBool = AtomicBool::new(false);

fn marker(pid: u64, what: &str) -> String {
    format!("/tmp/.winrun-{pid}.{what}")
}

fn touch(p: &str) {
    if let Ok(fd) = os_sys::open(p, osyx_abi::OPEN_WRITE | osyx_abi::OPEN_CREATE, 0o644) {
        let _ = os_sys::close(fd);
    }
}

/// Removes this process's markers (at start, so a reused pid does not
/// inherit them, and at exit).
pub fn clear_markers() {
    let pid = kernel32::pid();
    for w in ["gui", "idle"] {
        let _ = os_sys::unlink(&marker(pid, w));
    }
}

/// The process created its first window.
pub fn note_gui() {
    if !GUI_NOTED.swap(true, Ordering::Relaxed) {
        touch(&marker(kernel32::pid(), "gui"));
    }
}

/// A GUI thread is about to wait for messages with an empty queue.
pub fn note_idle() {
    if GUI_NOTED.load(Ordering::Relaxed) && !IDLE_NOTED.swap(true, Ordering::Relaxed) {
        touch(&marker(kernel32::pid(), "idle"));
    }
}

extern "win64" fn WaitForInputIdle(h: u64, timeout: u32) -> u32 {
    let (pid, done) = if h == objects::CURRENT_PROCESS {
        (kernel32::pid(), None)
    } else {
        match objects::get(h) {
            Some(Object::Process(p)) => (p.pid, Some(p)),
            _ => return fail(ERROR_INVALID_HANDLE, objects::WAIT_FAILED),
        }
    };
    let exists = |w: &str| os_sys::stat(&marker(pid, w)).is_ok();
    let start = kernel32::now_ns();
    static ITERS: AtomicU64 = AtomicU64::new(0);
    loop {
        let it = ITERS.fetch_add(1, Ordering::Relaxed) + 1;
        if it.is_multiple_of(200) && crate::EVENTS.load(Ordering::Relaxed) {
            os_std::eprintln!("winrun: waitforinputidle it={it} pid={pid} timeout={timeout}");
        }
        if exists("idle") {
            return 0;
        }
        if done.as_ref().is_some_and(|p| p.done.load(Ordering::SeqCst)) {
            return fail(ERROR_INVALID_PARAMETER, objects::WAIT_FAILED); // it exited
        }
        if !exists("gui") {
            return fail(ERROR_NOT_GUI_PROCESS, objects::WAIT_FAILED);
        }
        if timeout != objects::INFINITE && kernel32::now_ns() - start >= timeout as u64 * 1_000_000 {
            return objects::WAIT_TIMEOUT;
        }
        os_std::thread::sleep(os_std::time::Duration::from_millis(10));
    }
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        OpenInputDesktop,
        SetThreadDesktop,
        CreateWindowStationW,
        CreateDesktopW,
        GetProcessWindowStation,
        SetProcessWindowStation,
        GetThreadDesktop,
        CloseWindowStation,
        CloseDesktop,
        GetUserObjectInformationW,
        WaitForInputIdle,
    ]
}
