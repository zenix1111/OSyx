//! Process and thread start-up and termination (runtime contract): the
//! initializer tables, onexit/atexit tables, argv from the command line
//! (with the Windows quoting rules and optional wildcard expansion),
//! errno access, exit/_exit/abort/terminate, the C signals and the SEH
//! filters built on them, and `_beginthreadex`.

use super::*;
use crate::kernel32;
use alloc::string::String;
use core::sync::atomic::{AtomicI32, AtomicU32};

type Pvfv = extern "win64" fn();
type Pifv = extern "win64" fn() -> i32;

// ---- initializers ----------------------------------------------------------------------

extern "win64" fn _initterm(first: *const u64, last: *const u64) {
    let mut p = first;
    while p < last {
        // SAFETY: [first, last) is the caller's table of function pointers
        // (NULL entries are skipped).
        let f = unsafe { *p };
        if f != 0 {
            // SAFETY: an initializer of the calling module.
            let f: Pvfv = unsafe { core::mem::transmute(f as usize) };
            f();
        }
        // SAFETY: still within the table.
        p = unsafe { p.add(1) };
    }
}

extern "win64" fn _initterm_e(first: *const u64, last: *const u64) -> i32 {
    let mut p = first;
    while p < last {
        // SAFETY: as in `_initterm`.
        let f = unsafe { *p };
        if f != 0 {
            // SAFETY: as in `_initterm`.
            let f: Pifv = unsafe { core::mem::transmute(f as usize) };
            let r = f();
            if r != 0 {
                return r;
            }
        }
        // SAFETY: still within the table.
        p = unsafe { p.add(1) };
    }
    0
}

// ---- onexit tables ---------------------------------------------------------------------

/// `_onexit_table_t`: first, last, end (function pointers, not encoded:
/// only these functions read the table).
#[repr(C)]
pub struct OnexitTable {
    first: *mut u64,
    last: *mut u64,
    end: *mut u64,
}

static ONEXIT_LOCK: RLock = RLock::new();
/// The process atexit and at_quick_exit tables.
static mut ATEXIT: OnexitTable =
    OnexitTable { first: core::ptr::null_mut(), last: core::ptr::null_mut(), end: core::ptr::null_mut() };
static mut AT_QUICK_EXIT: OnexitTable =
    OnexitTable { first: core::ptr::null_mut(), last: core::ptr::null_mut(), end: core::ptr::null_mut() };

fn table_ptr(quick: bool) -> *mut OnexitTable {
    if quick { core::ptr::addr_of_mut!(AT_QUICK_EXIT) } else { core::ptr::addr_of_mut!(ATEXIT) }
}

extern "win64" fn _initialize_onexit_table(t: *mut OnexitTable) -> i32 {
    if t.is_null() {
        return -1;
    }
    // A table that already has entries (or the -1 "use the process
    // table" marker) stays as it is.
    0
}

extern "win64" fn _register_onexit_function(t: *mut OnexitTable, f: u64) -> i32 {
    if t.is_null() {
        return -1;
    }
    ONEXIT_LOCK.lock();
    // SAFETY: the caller's table, only changed under ONEXIT_LOCK.
    let r = unsafe {
        let t = &mut *t;
        if t.first as isize == -1 {
            -1
        } else {
            if t.last == t.end {
                let n = t.end.offset_from(t.first).max(0) as usize;
                let cap = if n == 0 { 32 } else { n * 2 };
                let used = t.last.offset_from(t.first).max(0) as usize;
                let new = crt_malloc(cap * 8) as *mut u64;
                if new.is_null() {
                    ONEXIT_LOCK.unlock();
                    return -1;
                }
                if !t.first.is_null() {
                    core::ptr::copy_nonoverlapping(t.first, new, used);
                    crt_free(t.first as *mut u8);
                }
                t.first = new;
                t.last = new.add(used);
                t.end = new.add(cap);
            }
            *t.last = f;
            t.last = t.last.add(1);
            0
        }
    };
    ONEXIT_LOCK.unlock();
    r
}

/// Runs a table's functions in reverse order of registration; functions
/// registered while it runs are run too.
extern "win64" fn _execute_onexit_table(t: *mut OnexitTable) -> i32 {
    if t.is_null() {
        return -1;
    }
    ONEXIT_LOCK.lock();
    // SAFETY: the caller's table, under ONEXIT_LOCK (recursive, so the
    // functions may register more).
    unsafe {
        let t = &mut *t;
        let mut first = t.first;
        if first.is_null() || first as isize == -1 {
            ONEXIT_LOCK.unlock();
            return 0;
        }
        let mut last = t.last;
        loop {
            while last > first && *last.sub(1) == 0 {
                last = last.sub(1);
            }
            if last <= first {
                break;
            }
            last = last.sub(1);
            let f = *last;
            *last = 0;
            let f: Pvfv = core::mem::transmute(f as usize);
            let (saved_first, saved_last) = (t.first, t.last);
            f();
            if t.first != saved_first || t.last != saved_last {
                first = t.first;
                last = t.last;
            }
        }
        crt_free(t.first as *mut u8);
        t.first = core::ptr::null_mut();
        t.last = core::ptr::null_mut();
        t.end = core::ptr::null_mut();
    }
    ONEXIT_LOCK.unlock();
    0
}

extern "win64" fn _crt_atexit(f: u64) -> i32 {
    _register_onexit_function(table_ptr(false), f)
}

extern "win64" fn _crt_at_quick_exit(f: u64) -> i32 {
    _register_onexit_function(table_ptr(true), f)
}

extern "win64" fn atexit(f: u64) -> i32 {
    _crt_atexit(f)
}

extern "win64" fn at_quick_exit(f: u64) -> i32 {
    _crt_at_quick_exit(f)
}

static TLS_EXIT_CALLBACK: AtomicU64 = AtomicU64::new(0);

extern "win64" fn _register_thread_local_exe_atexit_callback(f: u64) {
    // Only the executable registers this, once.
    if TLS_EXIT_CALLBACK.swap(f, Ordering::SeqCst) != 0 {
        fast_fail(7); // FAST_FAIL_FATAL_APP_EXIT
    }
}

// ---- process exit -------------------------------------------------------------------------

#[derive(PartialEq)]
enum Cleanup {
    Full,
    Quick,
    None,
}

static EXIT_LOCK: RLock = RLock::new();

/// The UCRT's `common_exit`.
fn common_exit(code: u32, cleanup: Cleanup, terminate: bool) {
    EXIT_LOCK.lock();
    if cleanup == Cleanup::Full {
        let cb = TLS_EXIT_CALLBACK.swap(0, Ordering::SeqCst);
        if cb != 0 {
            // SAFETY: the TLS callback the executable registered.
            let f: extern "win64" fn(u64, u32, u64) = unsafe { core::mem::transmute(cb as usize) };
            f(0, crate::loader::DLL_PROCESS_DETACH, 0);
        }
    }
    match cleanup {
        Cleanup::Full => {
            _execute_onexit_table(table_ptr(false));
            super::stdio::flush_all();
        }
        Cleanup::Quick => {
            _execute_onexit_table(table_ptr(true));
        }
        Cleanup::None => {}
    }
    if terminate {
        kernel32::ExitProcess(code)
    }
    EXIT_LOCK.unlock();
}

extern "win64" fn exit(code: i32) -> ! {
    common_exit(code as u32, Cleanup::Full, true);
    unreachable!()
}

extern "win64" fn _exit(code: i32) -> ! {
    common_exit(code as u32, Cleanup::None, true);
    unreachable!()
}

extern "win64" fn quick_exit(code: i32) -> ! {
    common_exit(code as u32, Cleanup::Quick, true);
    unreachable!()
}

extern "win64" fn _cexit() {
    common_exit(0, Cleanup::Full, false)
}

extern "win64" fn _c_exit() {
    common_exit(0, Cleanup::None, false)
}

const CALL_REPORTFAULT: u32 = 2;
static ABORT_BEHAVIOR: AtomicU32 = AtomicU32::new(CALL_REPORTFAULT);

extern "win64" fn _set_abort_behavior(flags: u32, mask: u32) -> u32 {
    let old = ABORT_BEHAVIOR.load(Ordering::SeqCst);
    ABORT_BEHAVIOR.store((old & !mask) | (flags & mask), Ordering::SeqCst);
    old
}

pub extern "win64" fn abort() -> ! {
    if signal_handler(SIGABRT) != SIG_DFL {
        raise(SIGABRT);
    }
    // The release UCRT writes no abort message (_WRITE_ABORT_MSG is a
    // debug-runtime behaviour); it reports the fault by fail-fast.
    if ABORT_BEHAVIOR.load(Ordering::SeqCst) & CALL_REPORTFAULT != 0 {
        fast_fail(7); // FAST_FAIL_FATAL_APP_EXIT
    }
    _exit(3)
}

static TERMINATE_HANDLER: AtomicU64 = AtomicU64::new(0);

extern "win64" fn set_terminate(f: u64) -> u64 {
    TERMINATE_HANDLER.swap(f, Ordering::SeqCst)
}

extern "win64" fn _get_terminate() -> u64 {
    TERMINATE_HANDLER.load(Ordering::SeqCst)
}

extern "win64" fn terminate() -> ! {
    let h = TERMINATE_HANDLER.load(Ordering::SeqCst);
    if h != 0 {
        // SAFETY: a terminate handler installed by the program.
        let f: Pvfv = unsafe { core::mem::transmute(h as usize) };
        f();
    }
    abort()
}

// ---- signals ----------------------------------------------------------------------------

const SIGINT: i32 = 2;
const SIGILL: i32 = 4;
const SIGABRT_COMPAT: i32 = 6;
const SIGFPE: i32 = 8;
const SIGSEGV: i32 = 11;
const SIGTERM: i32 = 15;
const SIGBREAK: i32 = 21;
const SIGABRT: i32 = 22;
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIG_ERR: u64 = u64::MAX;

static HANDLERS: [AtomicU64; 7] = [const { AtomicU64::new(SIG_DFL) }; 7];

fn slot(sig: i32) -> Option<usize> {
    Some(match sig {
        SIGINT => 0,
        SIGILL => 1,
        SIGFPE => 2,
        SIGSEGV => 3,
        SIGTERM => 4,
        SIGBREAK => 5,
        SIGABRT | SIGABRT_COMPAT => 6,
        _ => return None,
    })
}

fn signal_handler(sig: i32) -> u64 {
    slot(sig).map_or(SIG_DFL, |i| HANDLERS[i].load(Ordering::SeqCst))
}

/// `signal`: OSyx delivers no console control events to Windows programs,
/// so SIGINT/SIGBREAK handlers run only through `raise`.
extern "win64" fn signal(sig: i32, h: u64) -> u64 {
    let Some(i) = slot(sig) else {
        set_errno(EINVAL);
        invalid_parameter();
        return SIG_ERR;
    };
    if h == 4 || h == 3 {
        // SIG_SGE / SIG_ACK are not handler actions.
        set_errno(EINVAL);
        invalid_parameter();
        return SIG_ERR;
    }
    HANDLERS[i].swap(h, Ordering::SeqCst)
}

extern "win64" fn raise(sig: i32) -> i32 {
    let Some(i) = slot(sig) else {
        set_errno(EINVAL);
        invalid_parameter();
        return -1;
    };
    let h = HANDLERS[i].load(Ordering::SeqCst);
    match h {
        SIG_IGN => 0,
        SIG_DFL => {
            // The default action of every C signal ends the process.
            _exit(3)
        }
        _ => {
            // One-shot: the handler is reset before it runs (except SIGFPE
            // keeps the C semantics of the UCRT, which also resets it).
            HANDLERS[i].store(SIG_DFL, Ordering::SeqCst);
            // SAFETY: a handler installed by the program.
            let f: extern "win64" fn(i32) = unsafe { core::mem::transmute(h as usize) };
            f(sig);
            0
        }
    }
}

const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

fn exception_signal(code: u32) -> Option<i32> {
    Some(match code {
        0xC000_0005 => SIGSEGV,
        0xC000_001D | 0xC000_0096 => SIGILL,
        0xC000_008D..=0xC000_0093 | 0xC000_02B4 | 0xC000_02B5 => SIGFPE,
        _ => return None,
    })
}

/// The C signal view of a structured exception: a program's SIGSEGV,
/// SIGILL or SIGFPE handler runs for the matching fault.
extern "win64" fn _seh_filter_exe(code: u32, _ptrs: u64) -> i32 {
    let Some(sig) = exception_signal(code) else { return EXCEPTION_CONTINUE_SEARCH };
    let i = slot(sig).expect("C signal");
    let h = HANDLERS[i].load(Ordering::SeqCst);
    match h {
        SIG_DFL => EXCEPTION_CONTINUE_SEARCH,
        SIG_IGN => EXCEPTION_CONTINUE_EXECUTION,
        _ => {
            HANDLERS[i].store(SIG_DFL, Ordering::SeqCst);
            // SAFETY: a handler installed by the program.
            let f: extern "win64" fn(i32) = unsafe { core::mem::transmute(h as usize) };
            f(sig);
            EXCEPTION_CONTINUE_EXECUTION
        }
    }
}

/// For DLLs only the C++ exception code reaches the signal filter.
extern "win64" fn _seh_filter_dll(code: u32, ptrs: u64) -> i32 {
    if code != 0xE06D_7363 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    _seh_filter_exe(code, ptrs)
}

// ---- application type, errno ---------------------------------------------------------------

static APP_TYPE: AtomicI32 = AtomicI32::new(0);

extern "win64" fn _set_app_type(t: i32) {
    APP_TYPE.store(t, Ordering::SeqCst)
}

extern "win64" fn _query_app_type() -> i32 {
    APP_TYPE.load(Ordering::SeqCst)
}

static ERROR_MODE: AtomicI32 = AtomicI32::new(0);

extern "win64" fn _set_error_mode(m: i32) -> i32 {
    match m {
        0..=2 => ERROR_MODE.swap(m, Ordering::SeqCst),
        3 => ERROR_MODE.load(Ordering::SeqCst), // _REPORT_ERRMODE
        _ => {
            set_errno(EINVAL);
            invalid_parameter();
            -1
        }
    }
}

extern "win64" fn _errno() -> *mut i32 {
    &mut ptd().errno
}

extern "win64" fn __doserrno() -> *mut u32 {
    &mut ptd().doserrno
}

extern "win64" fn _get_errno(out: *mut i32) -> i32 {
    validate!(!out.is_null(), EINVAL, EINVAL);
    // SAFETY: validated.
    unsafe { *out = ptd().errno };
    0
}

extern "win64" fn _set_errno(v: i32) -> i32 {
    ptd().errno = v;
    0
}

extern "win64" fn _get_doserrno(out: *mut u32) -> i32 {
    validate!(!out.is_null(), EINVAL, EINVAL);
    // SAFETY: validated.
    unsafe { *out = ptd().doserrno };
    0
}

extern "win64" fn _set_doserrno(v: u32) -> i32 {
    ptd().doserrno = v;
    0
}

extern "win64" fn _getpid() -> i32 {
    kernel32::pid() as i32
}

extern "win64" fn __threadid() -> u32 {
    crate::teb::current_tid() as u32
}

extern "win64" fn __threadhandle() -> u64 {
    crate::objects::CURRENT_THREAD
}

// ---- command line -------------------------------------------------------------------------

/// Splits a command line by the Windows rules (program name up to the
/// next quote or blank; then blanks separate, quotes group, 2n
/// backslashes + quote give n backslashes and toggle quoting, 2n+1 give
/// n backslashes and a literal quote, "" inside quotes is a quote).
pub fn split_command_line(cmd: &[u16]) -> Vec<Vec<u16>> {
    const Q: u16 = b'"' as u16;
    const BS: u16 = b'\\' as u16;
    let blank = |c: u16| c == b' ' as u16 || c == b'\t' as u16;
    let mut args = Vec::new();
    let mut i = 0;
    let mut prog = Vec::new();
    if cmd.first() == Some(&Q) {
        i = 1;
        while i < cmd.len() && cmd[i] != Q {
            prog.push(cmd[i]);
            i += 1;
        }
        if i < cmd.len() {
            i += 1;
        }
    } else {
        while i < cmd.len() && !blank(cmd[i]) {
            prog.push(cmd[i]);
            i += 1;
        }
    }
    args.push(prog);
    loop {
        while i < cmd.len() && blank(cmd[i]) {
            i += 1;
        }
        if i >= cmd.len() {
            break;
        }
        let mut arg = Vec::new();
        let mut quoted = false;
        while i < cmd.len() {
            let mut slashes = 0;
            while i < cmd.len() && cmd[i] == BS {
                slashes += 1;
                i += 1;
            }
            if i < cmd.len() && cmd[i] == Q {
                arg.extend(core::iter::repeat_n(BS, slashes / 2));
                if slashes % 2 == 1 {
                    arg.push(Q);
                    i += 1;
                    continue;
                }
                if quoted && cmd.get(i + 1) == Some(&Q) {
                    arg.push(Q);
                    i += 2;
                    continue;
                }
                quoted = !quoted;
                i += 1;
                continue;
            }
            arg.extend(core::iter::repeat_n(BS, slashes));
            if i >= cmd.len() || (!quoted && blank(cmd[i])) {
                break;
            }
            arg.push(cmd[i]);
            i += 1;
        }
        args.push(arg);
    }
    args
}

k32fn!(fn find_first_file = "FindFirstFileW"(pattern: *const u16, data: *mut u8) -> u64);
k32fn!(fn find_next_file = "FindNextFileW"(h: u64, data: *mut u8) -> i32);
k32fn!(fn find_close = "FindClose"(h: u64) -> i32);

/// `_crt_argv_expanded_arguments`: an argument with * or ? in its last
/// component becomes the matching names (sorted), or stays as it is when
/// nothing matches.
fn expand(arg: Vec<u16>) -> Vec<Vec<u16>> {
    let wild = |c: &u16| *c == b'*' as u16 || *c == b'?' as u16;
    if !arg.iter().any(wild) {
        return alloc::vec![arg];
    }
    let dir_end = arg.iter().rposition(|&c| c == b'\\' as u16 || c == b'/' as u16 || c == b':' as u16);
    let prefix: Vec<u16> = dir_end.map_or(Vec::new(), |i| arg[..=i].to_vec());
    if prefix.iter().any(wild) {
        return alloc::vec![arg];
    }
    let mut pattern = arg.clone();
    pattern.push(0);
    // WIN32_FIND_DATAW: 592 bytes, cFileName at offset 44.
    let mut data = [0u8; 592];
    let h = find_first_file(pattern.as_ptr(), data.as_mut_ptr());
    if h == u64::MAX {
        return alloc::vec![arg];
    }
    let mut names: Vec<Vec<u16>> = Vec::new();
    loop {
        let name: Vec<u16> =
            data[44..44 + 520].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
        let dots = name == [b'.' as u16] || name == [b'.' as u16, b'.' as u16];
        if !dots {
            let mut full = prefix.clone();
            full.extend(name);
            names.push(full);
        }
        if find_next_file(h, data.as_mut_ptr()) == 0 {
            break;
        }
    }
    find_close(h);
    if names.is_empty() {
        return alloc::vec![arg];
    }
    names.sort_by_key(|n| String::from_utf16_lossy(n).to_lowercase());
    names
}

static ARGC: AtomicI32 = AtomicI32::new(0);
static ARGV: AtomicU64 = AtomicU64::new(0);
static WARGV: AtomicU64 = AtomicU64::new(0);
static PGMPTR: AtomicU64 = AtomicU64::new(0);
static WPGMPTR: AtomicU64 = AtomicU64::new(0);
static ACMDLN: AtomicU64 = AtomicU64::new(0);
static WCMDLN: AtomicU64 = AtomicU64::new(0);

k32fn!(fn get_command_line_w = "GetCommandLineW"() -> u64);
k32fn!(fn get_command_line_a = "GetCommandLineA"() -> u64);

fn module_path() -> Vec<u16> {
    let exe = kernel32::with_process(|p| p.exe_path.clone());
    crate::path::to_windows(&exe).encode_utf16().collect()
}

fn configure_argv(mode: i32, wide: bool) -> i32 {
    validate!((0..=2).contains(&mode), EINVAL, EINVAL);
    if (if wide { &WPGMPTR } else { &PGMPTR }).load(Ordering::SeqCst) == 0 {
        let path = module_path();
        let p = if wide { heap_wstr(&path) as u64 } else { heap_cstr(&String::from_utf16_lossy(&path).into_bytes()) as u64 };
        (if wide { &WPGMPTR } else { &PGMPTR }).store(p, Ordering::SeqCst);
    }
    if mode == 0 {
        return 0;
    }
    // SAFETY: the process command line, NUL-terminated.
    let cmd = unsafe { wstr(get_command_line_w() as *const u16) };
    let mut args = split_command_line(cmd);
    if mode == 2 {
        let first = args.remove(0);
        let mut all = alloc::vec![first];
        for a in args {
            all.extend(expand(a));
        }
        args = all;
    }
    let arr = crt_malloc((args.len() + 1) * 8) as *mut u64;
    if arr.is_null() {
        set_errno(ENOMEM);
        return ENOMEM;
    }
    for (i, a) in args.iter().enumerate() {
        let s = if wide { heap_wstr(a) as u64 } else { heap_cstr(&String::from_utf16_lossy(a).into_bytes()) as u64 };
        // SAFETY: `arr` holds len + 1 entries.
        unsafe { *arr.add(i) = s };
    }
    // SAFETY: as above.
    unsafe { *arr.add(args.len()) = 0 };
    ARGC.store(args.len() as i32, Ordering::SeqCst);
    let old = (if wide { &WARGV } else { &ARGV }).swap(arr as u64, Ordering::SeqCst);
    let _ = old; // a previous argv may still be referenced by the program
    0
}

extern "win64" fn _configure_narrow_argv(mode: i32) -> i32 {
    configure_argv(mode, false)
}

extern "win64" fn _configure_wide_argv(mode: i32) -> i32 {
    configure_argv(mode, true)
}

extern "win64" fn __p___argc() -> u64 {
    ARGC.as_ptr() as u64
}

extern "win64" fn __p___argv() -> u64 {
    ARGV.as_ptr() as u64
}

extern "win64" fn __p___wargv() -> u64 {
    WARGV.as_ptr() as u64
}

extern "win64" fn __p__pgmptr() -> u64 {
    PGMPTR.as_ptr() as u64
}

extern "win64" fn __p__wpgmptr() -> u64 {
    WPGMPTR.as_ptr() as u64
}

extern "win64" fn _get_pgmptr(out: *mut u64) -> i32 {
    validate!(!out.is_null() && PGMPTR.load(Ordering::SeqCst) != 0, EINVAL, EINVAL);
    // SAFETY: validated.
    unsafe { *out = PGMPTR.load(Ordering::SeqCst) };
    0
}

extern "win64" fn _get_wpgmptr(out: *mut u64) -> i32 {
    validate!(!out.is_null() && WPGMPTR.load(Ordering::SeqCst) != 0, EINVAL, EINVAL);
    // SAFETY: validated.
    unsafe { *out = WPGMPTR.load(Ordering::SeqCst) };
    0
}

extern "win64" fn __p__acmdln() -> u64 {
    ACMDLN.store(get_command_line_a(), Ordering::SeqCst);
    ACMDLN.as_ptr() as u64
}

extern "win64" fn __p__wcmdln() -> u64 {
    WCMDLN.store(get_command_line_w(), Ordering::SeqCst);
    WCMDLN.as_ptr() as u64
}

/// The command line after the program name and the blanks after it.
fn winmain_tail(cmd: u64, unit: usize) -> u64 {
    let get = |i: usize| -> u32 {
        // SAFETY: the NUL-terminated process command line.
        unsafe { if unit == 1 { *(cmd as *const u8).add(i) as u32 } else { *(cmd as *const u16).add(i) as u32 } }
    };
    let mut i = 0;
    let mut quoted = false;
    while get(i) != 0 && (quoted || (get(i) != b' ' as u32 && get(i) != b'\t' as u32)) {
        if get(i) == b'"' as u32 {
            quoted = !quoted;
        }
        i += 1;
    }
    while get(i) == b' ' as u32 || get(i) == b'\t' as u32 {
        i += 1;
    }
    cmd + (i * unit) as u64
}

extern "win64" fn _get_narrow_winmain_command_line() -> u64 {
    winmain_tail(get_command_line_a(), 1)
}

extern "win64" fn _get_wide_winmain_command_line() -> u64 {
    winmain_tail(get_command_line_w(), 2)
}

extern "win64" fn _initialize_narrow_environment() -> i32 {
    super::env::init(false);
    if super::env::environ_ptr(false) == 0 { -1 } else { 0 }
}

extern "win64" fn _initialize_wide_environment() -> i32 {
    super::env::init(true);
    if super::env::environ_ptr(true) == 0 { -1 } else { 0 }
}

extern "win64" fn _get_initial_narrow_environment() -> u64 {
    super::env::init(false);
    super::env::environ_ptr(false)
}

extern "win64" fn _get_initial_wide_environment() -> u64 {
    super::env::init(true);
    super::env::environ_ptr(true)
}

// ---- threads ------------------------------------------------------------------------------

struct Start {
    func: u64,
    arg: u64,
}

/// Runs a `_beginthreadex` thread procedure on the new thread's Windows
/// stack, then releases its C runtime data.
extern "win64" fn thread_start(param: u64) -> u32 {
    // SAFETY: the box made by `_beginthreadex` for this thread.
    let Start { func, arg } = *unsafe { Box::from_raw(param as *mut Start) };
    let code = if crate::wow64::is_active() {
        crate::wow64::run_thread32(func as u32, arg as u32)
    } else {
        // SAFETY: the program's `unsigned (__stdcall *)(void *)`.
        let f: extern "win64" fn(u64) -> u32 = unsafe { core::mem::transmute(func as usize) };
        f(arg)
    };
    release_ptd();
    code
}

const CREATE_SUSPENDED: u32 = 4;
const STACK_SIZE_PARAM_IS_A_RESERVATION: u32 = 0x10000;

extern "win64" fn _beginthreadex(
    security: u64,
    stack: u32,
    func: u64,
    arg: u64,
    flags: u32,
    tid: *mut u32,
) -> u64 {
    validate!(func != 0, EINVAL, 0);
    if flags & !(CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION) != 0 {
        set_errno(EINVAL);
        return 0;
    }
    if let Err(e) = crate::security::validate_attributes(security) {
        dosmaperr(e);
        return 0;
    }
    if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
        static STARTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        let n = STARTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if n < 128 || n.is_multiple_of(1024) {
            let at = crate::loader::where_is(func);
            os_std::eprintln!("winrun: _beginthreadex #{} callback={func:#x} module={at:?}", n + 1);
        }
    }
    let start = Box::into_raw(Box::new(Start { func, arg })) as u64;
    let size = if stack == 0 { kernel32::DEFAULT_STACK } else { stack as usize };
    match kernel32::spawn_thread(thread_start as *const () as u64, start, size, flags & CREATE_SUSPENDED != 0) {
        Ok(t) => {
            if !tid.is_null() {
                // SAFETY: the caller's out pointer.
                unsafe { *tid = t.tid.load(Ordering::SeqCst) };
            }
            crate::objects::insert(crate::objects::Object::Thread(t))
        }
        Err(e) => {
            // SAFETY: the thread never started; the box is still ours.
            drop(unsafe { Box::from_raw(start as *mut Start) });
            dosmaperr(e);
            0
        }
    }
}

extern "win64" fn _endthreadex(code: u32) -> ! {
    release_ptd();
    crate::loader::exit_thread(code)
}

pub fn exports() -> Vec<(&'static str, u64)> {
    let mut v = export_table![
        _initterm,
        _initterm_e,
        _initialize_onexit_table,
        _register_onexit_function,
        _execute_onexit_table,
        _crt_atexit,
        _crt_at_quick_exit,
        atexit,
        at_quick_exit,
        _register_thread_local_exe_atexit_callback,
        exit,
        _exit,
        quick_exit,
        _cexit,
        _c_exit,
        _set_abort_behavior,
        abort,
        set_terminate,
        _get_terminate,
        terminate,
        signal,
        raise,
        _seh_filter_exe,
        _seh_filter_dll,
        _set_app_type,
        _query_app_type,
        _set_error_mode,
        _errno,
        __doserrno,
        _get_errno,
        _set_errno,
        _get_doserrno,
        _set_doserrno,
        _getpid,
        __threadid,
        __threadhandle,
        _configure_narrow_argv,
        _configure_wide_argv,
        __p___argc,
        __p___argv,
        __p___wargv,
        __p__pgmptr,
        __p__wpgmptr,
        _get_pgmptr,
        _get_wpgmptr,
        __p__acmdln,
        __p__wcmdln,
        _get_narrow_winmain_command_line,
        _get_wide_winmain_command_line,
        _initialize_narrow_environment,
        _initialize_wide_environment,
        _get_initial_narrow_environment,
        _get_initial_wide_environment,
        _beginthreadex,
        _endthreadex,
    ];
    v.push(("_Exit", _exit as *const () as u64));
    v
}
