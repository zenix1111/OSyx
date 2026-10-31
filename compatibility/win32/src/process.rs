//! Processes: CreateProcessW (PE programs run under a child winrun,
//! native OSyx programs directly), waitable process handles, job objects,
//! process/thread attribute lists, and the "remote" memory calls on the
//! calling process itself.
//!
//! OSyx gives a process no access to another process's memory or
//! threads: Read/WriteProcessMemory, VirtualAllocEx and friends and
//! CreateRemoteThread work on the current process and fail with
//! ERROR_ACCESS_DENIED for others. Handles are not inherited (only the
//! standard handles reach the child), CREATE_SUSPENDED is not supported,
//! and a child's primary thread is represented by its process (waitable,
//! with the process's id).
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{self, fail},
    mem, objects::{self, Object}, path, teb,
};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use os_std::sync::Mutex;

const STILL_ACTIVE: u32 = 259;
const ERROR_PARTIAL_COPY: u32 = 299;

pub struct ProcessObj {
    pub pid: u64,
    /// A child of this process (waitable, killable).
    child: bool,
    pub done: AtomicBool,
    exit_code: AtomicU32,
    /// Assigned to a job object.
    jobbed: AtomicBool,
}

static CHILDREN: Mutex<Vec<Arc<ProcessObj>>> = Mutex::new(Vec::new());

/// Experimental deny-by-default profile. It is not a validated Gecko policy.
fn spawn_content_candidate(path: &str, argv: &[u8], env: &[u8], channel: u64, channels: &[u64], suspended: bool) -> Result<u64, osyx_abi::Errno> {
    use osyx_abi::{nr, sandbox::{PathRule, PATH_EXEC, PATH_READ}};
    let prefixes = ["/bin", "/opt/zen", "/system", "/Windows", "/usr", "/etc"];
    let mut rules: Vec<PathRule> = prefixes.iter().map(|p| PathRule {
        path: p.as_ptr() as u64, path_len: p.len() as u64, access: PATH_READ | PATH_EXEC,
    }).collect();
    // Gecko's ProcessPrng requires the kernel CSPRNG, not other devices.
    let random = "/dev/random";
    rules.push(PathRule { path: random.as_ptr() as u64, path_len: random.len() as u64, access: PATH_READ });
    let calls = [
        nr::EXIT, nr::WRITE, nr::MAP, nr::UNMAP, nr::SYSINFO, nr::CLOCK, nr::YIELD, nr::SLEEP,
        nr::THREAD_SPAWN, nr::THREAD_EXIT, nr::FUTEX_WAIT, nr::FUTEX_WAKE, nr::SET_FS_BASE, nr::GETTID,
        nr::OPEN, nr::CLOSE, nr::READ, nr::SEEK, nr::FSTAT, nr::STAT, nr::READDIR, nr::GETCWD,
        nr::CHDIR, nr::READLINK, nr::LSTAT, nr::GETUID, nr::STATFS, nr::CHANNEL_SEND, nr::CHANNEL_RECV,
        nr::CHANNEL_PEER, nr::SHM_CREATE, nr::SHM_MAP, nr::SHM_SIZE, nr::WAIT_HANDLES,
        nr::SET_GS_BASE, nr::PROTECT, nr::MAP_EX, nr::FAULT_HANDLER, nr::FAULT_RETURN, nr::DISCARD,
        nr::FILEMAP_CREATE, nr::FILEMAP_MAP, nr::CPU_INFO, nr::THREAD_AFFINITY, nr::PROCESS_WRITE_BARRIER,
        nr::PREFAULT, nr::TIME_CALIB, nr::IMAGE_MAP, nr::IMAGE_QUERY, nr::THREAD_PRIORITY,
        nr::FUTEX_WAIT_OWNED, nr::SET_FS32_BASE,
    ];
    let flags = if suspended { osyx_abi::sandbox::SPAWN_SUSPENDED } else { 0 };
    os_sys::spawn_restricted_with_channels(path, argv, env, &rules, &calls, channel, flags, channels)
}

pub fn exit_code(p: &ProcessObj) -> u32 {
    if p.done.load(Ordering::SeqCst) { p.exit_code.load(Ordering::SeqCst) } else { STILL_ACTIVE }
}

pub fn resume_primary(p: &ProcessObj) -> Result<u32, u32> {
    if !p.child || p.done.load(Ordering::SeqCst) { return Err(ERROR_ACCESS_DENIED); }
    os_sys::resume_child(p.pid).map(|n| n as u32).map_err(errno_to_win32)
}

pub fn terminate(p: &ProcessObj, _code: u32) -> Result<(), u32> {
    if p.pid == kernel32::pid() {
        kernel32::ExitProcess(_code);
    }
    if !p.child {
        return Err(ERROR_ACCESS_DENIED);
    }
    if p.done.load(Ordering::SeqCst) {
        return Err(ERROR_ACCESS_DENIED); // Windows: the process has exited
    }
    // OSyx's kill does not carry an exit code; the child's status is the
    // kernel's termination status.
    os_sys::kill(p.pid).map_err(errno_to_win32)
}

// ---- command lines ------------------------------------------------------------------

/// CommandLineToArgvW rules: whitespace separates, quotes group, 2n
/// backslashes before a quote → n and a quote toggle, 2n+1 → n and a quote.
fn split_command_line(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut have = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            let mut n = 0;
            while i < chars.len() && chars[i] == '\\' {
                n += 1;
                i += 1;
            }
            if i < chars.len() && chars[i] == '"' {
                cur.extend(core::iter::repeat_n('\\', n / 2));
                if n % 2 == 1 {
                    cur.push('"');
                    i += 1;
                }
            } else {
                cur.extend(core::iter::repeat_n('\\', n));
            }
            have = true;
            continue;
        }
        if c == '"' {
            if in_quotes && chars.get(i + 1) == Some(&'"') {
                cur.push('"');
                i += 2;
                continue;
            }
            in_quotes = !in_quotes;
            have = true;
        } else if (c == ' ' || c == '\t') && !in_quotes {
            if have {
                args.push(core::mem::take(&mut cur));
                have = false;
            }
        } else {
            cur.push(c);
            have = true;
        }
        i += 1;
    }
    if have {
        args.push(cur);
    }
    args
}

/// Finds a program like CreateProcess: as given, with ".exe" appended,
/// in the application directory, the current directory and PATH.
fn find_program(name: &str) -> Option<String> {
    let cwd = kernel32::cwd_win();
    let with_ext = |n: &str| -> Vec<String> {
        let leaf = n.rsplit(['\\', '/']).next().unwrap_or(n);
        if leaf.contains('.') { alloc::vec![String::from(n)] } else { alloc::vec![format!("{n}.exe"), String::from(n)] }
    };
    let exists = |w: &str| path::to_osyx(w, &cwd).ok().and_then(|p| match path::resolve(&p) {
        Ok((p, true)) => Some(p),
        _ => None,
    });
    if name.contains(['\\', '/']) || name.as_bytes().get(1) == Some(&b':') {
        return with_ext(name).iter().find_map(|c| exists(c));
    }
    let mut dirs: Vec<String> = Vec::new();
    if let Some(exe) = kernel32::module_name(0) {
        if let Some((d, _)) = exe.rsplit_once('\\') {
            dirs.push(String::from(d));
        }
    }
    dirs.push(cwd.clone());
    if let Some(p) = kernel32::env_get("PATH") {
        dirs.extend(p.split(';').filter(|s| !s.is_empty()).map(String::from));
    }
    dirs.iter().find_map(|d| with_ext(&format!("{}\\{}", d.trim_end_matches('\\'), name)).iter().find_map(|c| exists(c)))
}

fn is_pe(osyx: &str) -> bool {
    let Ok(fd) = os_sys::open(osyx, osyx_abi::OPEN_READ, 0) else { return false };
    let mut b = [0u8; 2];
    let ok = os_sys::read_raw(fd, b.as_mut_ptr() as usize, 2) == Ok(2) && b == *b"MZ";
    let _ = os_sys::close(fd);
    ok
}

/// The environment block: NUL-separated "k=v" strings ending in an
/// empty string, UTF-16 with CREATE_UNICODE_ENVIRONMENT.
fn environment_block(p: u64, unicode: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = p;
    loop {
        // SAFETY: the caller's environment block.
        let s = unsafe { if unicode { path::wide_to_string(at as *const u16) } else { path::ansi_to_string(at as *const u8) } };
        let Some(s) = s.filter(|s| !s.is_empty()) else { break };
        at += if unicode { (s.encode_utf16().count() as u64 + 1) * 2 } else { s.len() as u64 + 1 };
        out.push(s);
    }
    out
}

fn encode(list: &[String]) -> Vec<u8> {
    os_std::process::encode_args(list).unwrap_or_default()
}

/// The OSyx file descriptor behind a standard handle; None for console
/// streams and anything else, which the child gets from the console.
fn std_file(h: u64) -> Option<u64> {
    match objects::get(h)? {
        Object::File(f) => Some(f.fd),
        _ => None,
    }
}

const CREATE_SUSPENDED: u32 = 0x4;
const DEBUG_PROCESS: u32 = 0x1;
const DEBUG_ONLY_THIS_PROCESS: u32 = 0x2;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x80000;
const STARTF_USESTDHANDLES: u32 = 0x100;
pub(crate) const STD_HANDLES_ENV: &str = "OSYX_WINRUN_STD_HANDLES";
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: u64 = 0x20002;

/// STARTUPINFOA differs from STARTUPINFOW only in the string pointers
/// (lpReserved, lpDesktop, lpTitle), which CreateProcessW does not read; an
/// ANSI environment block is what CreateProcessW expects without
/// CREATE_UNICODE_ENVIRONMENT.
#[allow(clippy::too_many_arguments)]
extern "win64" fn CreateProcessA(
    app: *const u8,
    cmdline: *mut u8,
    psa: u64,
    tsa: u64,
    inherit: i32,
    flags: u32,
    env: u64,
    cwd: *const u8,
    startup: *const u8,
    info: *mut u64,
) -> i32 {
    // SAFETY: NULL or NUL-terminated strings from the caller.
    let (app, mut line, cwd) = unsafe { (path::ansi_to_wide(app), path::ansi_to_wide(cmdline), path::ansi_to_wide(cwd)) };
    let p = |w: &Option<Vec<u16>>| w.as_ref().map_or(core::ptr::null(), |w| w.as_ptr());
    let line_p = line.as_mut().map_or(core::ptr::null_mut(), |w| w.as_mut_ptr());
    CreateProcessW(p(&app), line_p, psa, tsa, inherit, flags, env, p(&cwd), startup, info)
}

#[allow(clippy::too_many_arguments)]
pub(crate) extern "win64" fn CreateProcessW(
    app: *const u16,
    cmdline: *mut u16,
    psa: u64,
    tsa: u64,
    inherit: i32,
    flags: u32,
    env: u64,
    cwd: *const u16,
    startup: *const u8,
    info: *mut u64,
) -> i32 {
    if let Err(e) = crate::security::validate_attributes(psa).and_then(|()| crate::security::validate_attributes(tsa)) {
        return fail(e, 0);
    }
    if flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS) != 0 {
        if crate::VERBOSE.load(Ordering::Relaxed) {
            os_std::eprintln!("winrun: CreateProcessW unsupported creation flags {flags:#x}");
        }
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    if startup.is_null() || info.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's STARTUPINFO(EX)W.
    let (si_flags, std_handles, attrs) = unsafe {
        let f = teb::get::<u32>(startup as u64, 60);
        let handles = [teb::get::<u64>(startup as u64, 80), teb::get::<u64>(startup as u64, 88), teb::get::<u64>(startup as u64, 96)];
        let attrs = if flags & EXTENDED_STARTUPINFO_PRESENT != 0 { teb::get::<u64>(startup as u64, 104) } else { 0 };
        (f, handles, attrs)
    };
    // With bInheritHandles, the child gets the handle list's handles (each
    // must be inheritable), or else every inheritable handle.
    let mut handle_list: Option<Vec<u64>> = None;
    if attrs != 0 {
        // SAFETY: a list made by InitializeProcThreadAttributeList below.
        let list = unsafe { &*(attrs as *const AttributeList) };
        for &(attribute, value, size) in &list.entries[..list.used as usize] {
            if attribute != PROC_THREAD_ATTRIBUTE_HANDLE_LIST {
                if crate::VERBOSE.load(Ordering::Relaxed) { os_std::eprintln!("winrun: unsupported process attribute {attribute:#x}"); }
                return fail(ERROR_NOT_SUPPORTED, 0);
            }
            if value == 0 || size % 8 != 0 {
                return fail(ERROR_INVALID_PARAMETER, 0);
            }
            // SAFETY: the caller's array of `size` bytes of HANDLEs.
            let hs = unsafe { core::slice::from_raw_parts(value as *const u64, size as usize / 8) };
            handle_list.get_or_insert_with(Vec::new).extend_from_slice(hs);
        }
    }
    let inherited: Vec<u64> = if inherit == 0 {
        Vec::new()
    } else {
        match handle_list {
            Some(list) => {
                if list.iter().any(|&h| !objects::is_inheritable(h)) {
                    return fail(ERROR_INVALID_PARAMETER, 0);
                }
                list
            }
            None => objects::inheritable(),
        }
    };
    // The standard handles reach the child as its console streams.
    let inherited: Vec<u64> = inherited.into_iter().filter(|h| !std_handles.contains(h)).collect();
    // SAFETY: NULL or NUL-terminated strings.
    let (app, line) = unsafe { (path::wide_to_string(app), path::wide_to_string(cmdline)) };
    let args = line.as_deref().map(split_command_line).unwrap_or_default();
    let Some(program) = app.clone().or_else(|| args.first().cloned()) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let Some(exe) = find_program(&program) else { return fail(ERROR_FILE_NOT_FOUND, 0) };
    let rest: Vec<String> = if app.is_some() { args.iter().skip(1).cloned().collect() } else { args.into_iter().skip(1).collect() };
    let restricted = exe.eq_ignore_ascii_case("/opt/zen/zen.exe")
        && rest.iter().any(|arg| arg.eq_ignore_ascii_case("-contentproc"))
        && os_std::env::var("OSYX_EXPERIMENTAL_CONTENT_SANDBOX").is_ok_and(|v| v == "1");
    if crate::VERBOSE.load(Ordering::Relaxed) && rest.iter().any(|arg| arg.eq_ignore_ascii_case("-contentproc")) {
        os_std::eprintln!("winrun: content child {exe}, flags {flags:#x}, inherit {}, sandbox {restricted}", inherited.len());
    }
    let mut environment: Vec<String> =
        if env != 0 { environment_block(env, flags & CREATE_UNICODE_ENVIRONMENT != 0) } else { kernel32::env_vars().into_iter().map(|(k, v)| format!("{k}={v}")).collect() };
    // SAFETY: as above.
    if let Some(dir) = unsafe { path::wide_to_string(cwd) } {
        match path::to_osyx(&dir, &kernel32::cwd_win()).and_then(|p| path::resolve(&p)) {
            Ok((p, true)) => environment.push(format!("OSYX_WINRUN_CWD={p}")),
            _ => return fail(ERROR_DIRECTORY, 0),
        }
    }
    if let Some(i) = environment.iter().position(|e| e.starts_with(crate::inherit::ENV) && e[crate::inherit::ENV.len()..].starts_with('=')) {
        environment.remove(i);
    }
    environment.retain(|e| !e.split_once('=').is_some_and(|(key, _)| key.eq_ignore_ascii_case(STD_HANDLES_ENV)));
    let mut broker = None;
    let mut child_channel = None;
    let mut inherited_channels = Vec::new();
    if restricted {
        if si_flags & STARTF_USESTDHANDLES != 0 {
            let mut std_spec = String::new();
            for (i, handle) in std_handles.iter().enumerate() {
                if *handle == 0 || *handle == u64::MAX {
                    std_spec.push(if *handle == 0 { 'n' } else { 'i' });
                    continue;
                }
                let supported = matches!((i, objects::get(*handle)),
                    (0, Some(Object::Console(objects::Console::In)))
                    | (1, Some(Object::Console(objects::Console::Out)))
                    | (2, Some(Object::Console(objects::Console::Err))));
                if !supported {
                    if crate::VERBOSE.load(Ordering::Relaxed) { os_std::eprintln!("winrun: restricted child unsupported standard handle {i}: {handle:#x}"); }
                    return fail(ERROR_NOT_SUPPORTED, 0);
                }
                std_spec.push('c');
            }
            environment.push(format!("{STD_HANDLES_ENV}={std_spec}"));
        }
        let (parent_end, child_end) = match os_sys::channel_pair() {
            Ok(pair) => pair,
            Err(e) => return fail(errno_to_win32(e), 0),
        };
        inherited_channels = match crate::inherit::offer_on_channel(&inherited, parent_end) {
            Ok(channels) => channels,
            Err(e) => {
                if crate::VERBOSE.load(Ordering::Relaxed) { os_std::eprintln!("winrun: restricted child cannot inherit handles: error {e}"); }
                let _ = os_sys::close(parent_end);
                let _ = os_sys::close(child_end);
                return fail(e, 0);
            }
        };
        broker = Some(parent_end);
        child_channel = Some(child_end);
        environment.push(format!("{}={}", crate::inherit::ENV, crate::inherit::DIRECT_CHANNEL));
    } else {
        match crate::inherit::offer(&inherited) {
            Ok(Some(entry)) => environment.push(entry),
            Ok(None) => {}
            Err(e) => return fail(e, 0),
        }
    }
    let (path, argv): (String, Vec<String>) = if is_pe(&exe) {
        let mut a = alloc::vec![String::from("/bin/winrun")];
        // A traced winrun traces its Windows children too.
        if crate::VERBOSE.load(Ordering::Relaxed) {
            a.push(String::from("-v"));
        }
        a.push(exe.clone());
        a.extend(rest);
        (String::from("/bin/winrun"), a)
    } else {
        let mut a = alloc::vec![exe.clone()];
        a.extend(rest);
        (exe.clone(), a)
    };
    // (handle, is a console stream) per standard stream.
    let streams: [(u64, bool); 3] = core::array::from_fn(|i| {
        let file = if si_flags & STARTF_USESTDHANDLES != 0 { std_file(std_handles[i]) } else { None };
        file.map_or((i as u64, true), |fd| (fd, false))
    });
    let stdio = streams.map(|(h, _)| h);
    let (argv, environment) = (encode(&argv), encode(&environment));
    // Console streams are kernel handles 0-2 only when our own stdio was
    // redirected; otherwise they are passed as HANDLE_NONE (inherit).
    let console = streams.map(|(h, console)| if console { os_sys::HANDLE_NONE } else { h });
    let spawned = match child_channel {
        Some(channel) => {
            let channels: Vec<u64> = inherited_channels.iter().map(|c| c.0).collect();
            let result = spawn_content_candidate(&path, &argv, &environment, channel, &channels, flags & CREATE_SUSPENDED != 0);
            let _ = os_sys::close(channel);
            result
        }
        None => match if flags & CREATE_SUSPENDED != 0 {
            os_sys::spawn_stdio_suspended(&path, &argv, &environment, stdio)
        } else {
            os_sys::spawn_stdio(&path, &argv, &environment, stdio)
        } {
            Err(osyx_abi::Errno::BadHandle) if console != stdio => if flags & CREATE_SUSPENDED != 0 {
                os_sys::spawn_stdio_suspended(&path, &argv, &environment, console)
            } else {
                os_sys::spawn_stdio(&path, &argv, &environment, console)
            },
            r => r,
        },
    };
    let pid = match spawned {
        Ok(p) => p,
        Err(e) => {
            if let Some(channel) = broker { let _ = os_sys::close(channel); }
            return fail(errno_to_win32(e), 0);
        }
    };
    let p = Arc::new(ProcessObj { pid, child: true, done: AtomicBool::new(false), exit_code: AtomicU32::new(STILL_ACTIVE), jobbed: AtomicBool::new(false) });
    if let Some(channel) = broker { crate::inherit::register_broker(pid, channel); }
    CHILDREN.lock().unwrap().push(p.clone());
    let watcher = p.clone();
    let watching = os_std::thread::Builder::new().stack_size(64 << 10).spawn(move || {
        if let Ok((_, status)) = os_sys::wait(watcher.pid) {
            watcher.exit_code.store(status as u32, Ordering::SeqCst);
        }
        watcher.done.store(true, Ordering::SeqCst);
        objects::signal_all();
        if broker.is_some() { crate::inherit::unregister_broker(watcher.pid); }
    });
    if watching.is_err() {
        if broker.is_some() { crate::inherit::unregister_broker(pid); }
    }
    let hp = objects::insert(Object::Process(p.clone()));
    let ht = objects::insert(Object::Process(p));
    // SAFETY: the caller's PROCESS_INFORMATION.
    unsafe {
        *info = hp;
        *info.add(1) = ht;
        *(info.add(2) as *mut u32) = pid as u32;
        *(info.add(2) as *mut u32).add(1) = pid as u32;
    }
    1
}

extern "win64" fn OpenProcess(_access: u32, inherit: i32, pid: u32) -> u64 {
    if inherit != 0 {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    if pid as u64 == kernel32::pid() {
        let me = Arc::new(ProcessObj { pid: pid as u64, child: false, done: AtomicBool::new(false), exit_code: AtomicU32::new(STILL_ACTIVE), jobbed: AtomicBool::new(false) });
        return objects::insert(Object::Process(me));
    }
    if let Some(p) = CHILDREN.lock().unwrap().iter().find(|p| p.pid == pid as u64) {
        return objects::insert(Object::Process(p.clone()));
    }
    if os_sys::proc_info(pid as u64).is_err() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // Another process (a Windows child's parent, say): it can be waited
    // for and named in DuplicateHandle, but not terminated or read.
    let p = Arc::new(ProcessObj { pid: pid as u64, child: false, done: AtomicBool::new(false), exit_code: AtomicU32::new(STILL_ACTIVE), jobbed: AtomicBool::new(false) });
    let watcher = p.clone();
    let _ = os_std::thread::Builder::new().stack_size(64 << 10).spawn(move || {
        // OSyx reports only a child's exit, so poll the process record.
        loop {
            os_std::thread::sleep(core::time::Duration::from_millis(250));
            if os_sys::proc_info(watcher.pid) == Err(osyx_abi::Errno::NotFound) {
                break;
            }
        }
        watcher.done.store(true, Ordering::SeqCst);
        objects::signal_all();
    });
    objects::insert(Object::Process(p))
}

/// The process id a process handle names, if it is not this process.
pub fn other_pid(h: u64) -> Result<Option<u64>, u32> {
    process_of(h).map(|p| p.map(|p| p.pid))
}

fn process_of(h: u64) -> Result<Option<Arc<ProcessObj>>, u32> {
    if h == objects::CURRENT_PROCESS {
        return Ok(None);
    }
    match objects::get(h) {
        Some(Object::Process(p)) if p.pid == kernel32::pid() => Ok(None),
        Some(Object::Process(p)) => Ok(Some(p)),
        _ => Err(ERROR_INVALID_HANDLE),
    }
}

/// Self only; other processes' memory is out of reach on OSyx.
fn local(h: u64) -> Result<(), u32> {
    match process_of(h)? {
        None => Ok(()),
        Some(_) => Err(ERROR_ACCESS_DENIED),
    }
}

pub(crate) extern "win64" fn QueryFullProcessImageNameW(h: u64, flags: u32, buf: *mut u16, size: *mut u32) -> i32 {
    if flags & !1 != 0 || size.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if let Err(e) = local(h) {
        return fail(e, 0);
    }
    let Some(name) = kernel32::module_name(0) else { return fail(ERROR_GEN_FAILURE, 0) };
    // SAFETY: the caller's in/out size.
    let cap = unsafe { *size };
    let r = kernel32::out_w(&name, buf, cap);
    if r >= cap {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    // SAFETY: as above.
    unsafe { *size = r };
    1
}

/// Copies between our own addresses, refusing unreadable or unwritable
/// pages instead of faulting; Windows lets a process write its own
/// read-only and code pages through WriteProcessMemory, so those are made
/// writable for the copy and restored.
fn copy_self(dst: u64, src: u64, len: usize, write: bool) -> Result<(), u32> {
    if len == 0 {
        return Ok(());
    }
    let probe = if write { dst } else { src };
    if crate::sysext::is_bad_read(src, len) || crate::sysext::is_bad_read(dst, len) {
        return Err(ERROR_PARTIAL_COPY);
    }
    if !write {
        // SAFETY: both ranges were probed readable; `dst` is the caller's buffer.
        unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, len) };
        return Ok(());
    }
    let first = probe & !(mem::PAGE as u64 - 1);
    let end = (probe + len as u64).next_multiple_of(mem::PAGE as u64);
    let span = (end - first) as usize;
    let info = mem::virtual_query(first);
    let writable = info.as_ref().is_some_and(|i| matches!(i.protect, mem::PAGE_READWRITE | mem::PAGE_WRITECOPY));
    let image = info.as_ref().is_some_and(|i| i.kind == mem::MEM_IMAGE);
    if !writable && !image && info.is_some() {
        // A VirtualAlloc region: through its own protection bookkeeping.
        let old = mem::virtual_protect(first, span, mem::PAGE_READWRITE).map_err(status_to_win32)?;
        // SAFETY: the pages are now writable.
        unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, len) };
        mem::virtual_protect(first, span, old).map_err(status_to_win32)?;
        return Ok(());
    }
    if image {
        // Image pages: their section protection is restored afterwards.
        let executable = crate::loader::is_executable(first);
        mem::protect(first, span, mem::Prot::ReadWrite).map_err(errno_to_win32)?;
        // SAFETY: as above.
        unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, len) };
        let back = if executable { mem::Prot::ExecuteRead } else { mem::Prot::ReadOnly };
        mem::protect(first, span, back).map_err(errno_to_win32)?;
        return Ok(());
    }
    // Ordinary writable memory (stacks, heap).
    // SAFETY: probed above; writing faults are not expected here.
    unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, len) };
    Ok(())
}

extern "win64" fn ReadProcessMemory(h: u64, addr: u64, buf: u64, len: usize, done: *mut usize) -> i32 {
    let r = local(h).and_then(|()| copy_self(buf, addr, len, false));
    if !done.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *done = if r.is_ok() { len } else { 0 } };
    }
    r.map_or_else(|e| fail(e, 0), |()| 1)
}

extern "win64" fn WriteProcessMemory(h: u64, addr: u64, buf: u64, len: usize, done: *mut usize) -> i32 {
    let r = local(h).and_then(|()| copy_self(addr, buf, len, true));
    if !done.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *done = if r.is_ok() { len } else { 0 } };
    }
    r.map_or_else(|e| fail(e, 0), |()| 1)
}

extern "win64" fn NtReadVirtualMemory(h: u64, addr: u64, buf: u64, len: usize, done: *mut usize) -> NtStatus {
    let r = local(h).and_then(|()| copy_self(buf, addr, len, false));
    if !done.is_null() {
        // SAFETY: as above.
        unsafe { *done = if r.is_ok() { len } else { 0 } };
    }
    match r {
        Ok(()) => STATUS_SUCCESS,
        Err(ERROR_ACCESS_DENIED) => STATUS_ACCESS_DENIED,
        Err(_) => 0x8000_000D, // STATUS_PARTIAL_COPY
    }
}

extern "win64" fn VirtualAllocEx(h: u64, addr: u64, size: usize, kind: u32, protect: u32) -> u64 {
    match local(h) {
        Ok(()) => mem::virtual_alloc(addr, size, kind, protect).unwrap_or_else(|s| fail(status_to_win32(s), 0)),
        Err(e) => fail(e, 0),
    }
}

extern "win64" fn VirtualFreeEx(h: u64, addr: u64, size: usize, kind: u32) -> i32 {
    match local(h).and_then(|()| mem::virtual_free(addr, size, kind).map_err(status_to_win32)) {
        Ok(()) => 1,
        Err(e) => fail(e, 0),
    }
}

extern "win64" fn VirtualProtectEx(h: u64, addr: u64, size: usize, protect: u32, old: *mut u32) -> i32 {
    match local(h).and_then(|()| mem::virtual_protect(addr, size, protect).map_err(status_to_win32)) {
        Ok(o) => {
            if !old.is_null() {
                // SAFETY: the caller's out pointer.
                unsafe { *old = o };
            }
            1
        }
        Err(e) => fail(e, 0),
    }
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn CreateRemoteThread(h: u64, sa: u64, stack: usize, start: u64, param: u64, flags: u32, tid: *mut u32) -> u64 {
    if let Err(e) = local(h) {
        return fail(e, 0);
    }
    kernel32::CreateThread(sa, stack, start, param, flags, tid)
}

extern "win64" fn GetProcessId(h: u64) -> u32 {
    match process_of(h) {
        Ok(None) => kernel32::pid() as u32,
        Ok(Some(p)) => p.pid as u32,
        Err(e) => fail(e, 0),
    }
}

// ---- process/thread attribute lists ------------------------------------------------

const MAX_ATTRIBUTES: usize = 8;

/// Our layout of the opaque PROC_THREAD_ATTRIBUTE_LIST.
#[repr(C)]
struct AttributeList {
    capacity: u32,
    used: u32,
    entries: [(u64, u64, u64); MAX_ATTRIBUTES],
}

extern "win64" fn InitializeProcThreadAttributeList(list: *mut AttributeList, count: u32, flags: u32, size: *mut usize) -> i32 {
    if flags != 0 || size.is_null() || count as usize > MAX_ATTRIBUTES {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let need = core::mem::size_of::<AttributeList>();
    // SAFETY: the caller's size and (if large enough) list buffer.
    unsafe {
        let have = *size;
        *size = need;
        if list.is_null() || have < need {
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        list.write(AttributeList { capacity: count, used: 0, entries: [(0, 0, 0); MAX_ATTRIBUTES] });
    }
    1
}

extern "win64" fn UpdateProcThreadAttribute(list: *mut AttributeList, flags: u32, attribute: u64, value: u64, size: usize, previous: u64, ret: u64) -> i32 {
    if list.is_null() || flags != 0 || previous != 0 || ret != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: a list initialised above.
    let l = unsafe { &mut *list };
    if l.used >= l.capacity {
        return fail(ERROR_GEN_FAILURE, 0);
    }
    l.entries[l.used as usize] = (attribute, value, size as u64);
    l.used += 1;
    1
}

/// The list holds no resource of its own; deleting it leaves it unusable
/// (no capacity), so a later UpdateProcThreadAttribute fails instead of
/// writing into a list its owner has given up.
extern "win64" fn DeleteProcThreadAttributeList(list: *mut AttributeList) {
    if !list.is_null() {
        // SAFETY: a list the caller initialised.
        unsafe {
            (*list).capacity = 0;
            (*list).used = 0;
        }
    }
}

// ---- job objects -----------------------------------------------------------------

const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
const JOB_OBJECT_LIMIT_BREAKAWAY_OK: u32 = 0x800;
const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK: u32 = 0x1000;
const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x400;

pub struct JobObj {
    processes: Mutex<Vec<Arc<ProcessObj>>>,
    limits: AtomicU32,
}

impl Drop for JobObj {
    fn drop(&mut self) {
        if self.limits.load(Ordering::SeqCst) & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0 {
            for p in self.processes.lock().unwrap().iter() {
                let _ = terminate(p, 0);
            }
        }
    }
}

extern "win64" fn CreateJobObjectW(sa: u64, name: *const u16) -> u64 {
    if let Err(e) = crate::security::validate_attributes(sa) {
        return fail(e, 0);
    }
    if !name.is_null() {
        return fail(ERROR_NOT_SUPPORTED, 0); // named jobs
    }
    objects::insert(Object::Job(Arc::new(JobObj { processes: Mutex::new(Vec::new()), limits: AtomicU32::new(0) })))
}

fn job(h: u64) -> Result<Arc<JobObj>, u32> {
    match objects::get(h) {
        Some(Object::Job(j)) => Ok(j),
        _ => Err(ERROR_INVALID_HANDLE),
    }
}

extern "win64" fn AssignProcessToJobObject(h: u64, process: u64) -> i32 {
    let j = match job(h) {
        Ok(j) => j,
        Err(e) => return fail(e, 0),
    };
    match process_of(process) {
        Ok(Some(p)) if p.child => {
            p.jobbed.store(true, Ordering::SeqCst);
            j.processes.lock().unwrap().push(p);
            1
        }
        Ok(_) => fail(ERROR_NOT_SUPPORTED, 0), // the job would have to contain winrun itself
        Err(e) => fail(e, 0),
    }
}

/// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags is at offset 16 in both
/// the basic (2) and extended (9) limit classes.
extern "win64" fn SetInformationJobObject(h: u64, class: u32, info: *const u8, len: u32) -> i32 {
    let j = match job(h) {
        Ok(j) => j,
        Err(e) => return fail(e, 0),
    };
    let need = match class {
        2 => 64,
        9 => 144,
        _ => return fail(ERROR_NOT_SUPPORTED, 0),
    };
    if info.is_null() || len < need {
        return fail(ERROR_BAD_LENGTH, 0);
    }
    // SAFETY: the caller's structure of `need` bytes.
    let flags = unsafe { teb::get::<u32>(info as u64, 16) };
    let supported = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_BREAKAWAY_OK
        | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if flags & !supported != 0 {
        return fail(ERROR_NOT_SUPPORTED, 0); // memory, time, process-count limits...
    }
    j.limits.store(flags, Ordering::SeqCst);
    1
}

const ERROR_BAD_LENGTH: u32 = 24;

extern "win64" fn QueryInformationJobObject(h: u64, class: u32, info: *mut u8, len: u32, ret: *mut u32) -> i32 {
    let j = match job(h) {
        Ok(j) => j,
        Err(e) => return fail(e, 0),
    };
    let processes = j.processes.lock().unwrap();
    let active = processes.iter().filter(|p| !p.done.load(Ordering::SeqCst)).count() as u32;
    let size: u32 = match class {
        1 => 48,
        2 => 64,
        3 => 8 + 8 * processes.len() as u32,
        9 => 144,
        _ => return fail(ERROR_NOT_SUPPORTED, 0),
    };
    if !ret.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *ret = size };
    }
    if info.is_null() || len < size.min(if class == 3 { 8 } else { size }) {
        return fail(ERROR_BAD_LENGTH, 0);
    }
    // SAFETY: the caller's buffer of `len` bytes.
    unsafe {
        core::ptr::write_bytes(info, 0, len.min(size) as usize);
        match class {
            1 => {
                // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION: times, then counts.
                teb::put(info as u64, 36, processes.len() as u32);
                teb::put(info as u64, 40, active);
            }
            2 | 9 => teb::put(info as u64, 16, j.limits.load(Ordering::SeqCst)),
            _ => {
                let fit = ((len - 8) / 8).min(processes.len() as u32);
                teb::put(info as u64, 0, processes.len() as u32);
                teb::put(info as u64, 4, fit);
                for (i, p) in processes.iter().take(fit as usize).enumerate() {
                    teb::put(info as u64, 8 + i * 8, p.pid);
                }
                if fit < processes.len() as u32 {
                    return fail(ERROR_MORE_DATA, 0);
                }
            }
        }
    }
    1
}

const ERROR_MORE_DATA: u32 = 234;

extern "win64" fn TerminateJobObject(h: u64, code: u32) -> i32 {
    let j = match job(h) {
        Ok(j) => j,
        Err(e) => return fail(e, 0),
    };
    for p in j.processes.lock().unwrap().iter().filter(|p| !p.done.load(Ordering::SeqCst)) {
        let _ = terminate(p, code);
    }
    1
}

extern "win64" fn IsProcessInJob(process: u64, h: u64, result: *mut i32) -> i32 {
    if result.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let found = match (process_of(process), h) {
        (Ok(None), _) => false, // winrun is never in a job
        (Ok(Some(p)), 0) => p.jobbed.load(Ordering::SeqCst),
        (Ok(Some(p)), h) => match job(h) {
            Ok(j) => j.processes.lock().unwrap().iter().any(|x| x.pid == p.pid),
            Err(e) => return fail(e, 0),
        },
        (Err(e), _) => return fail(e, 0),
    };
    // SAFETY: the caller's out pointer.
    unsafe { *result = i32::from(found) };
    1
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        CreateProcessW,
        CreateProcessA,
        OpenProcess,
        QueryFullProcessImageNameW,
        ReadProcessMemory,
        WriteProcessMemory,
        VirtualAllocEx,
        VirtualFreeEx,
        VirtualProtectEx,
        CreateRemoteThread,
        GetProcessId,
        InitializeProcThreadAttributeList,
        UpdateProcThreadAttribute,
        DeleteProcThreadAttributeList,
        CreateJobObjectW,
        AssignProcessToJobObject,
        SetInformationJobObject,
        QueryInformationJobObject,
        TerminateJobObject,
        IsProcessInJob,
    ]
}

pub fn ntdll_exports() -> Vec<(&'static str, u64)> {
    export_table![NtReadVirtualMemory]
}
