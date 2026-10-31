//! Process/system queries mozglue needs at start-up: calendar time,
//! interrupt time, process times, version verification, pointer probes,
//! path search and message formatting.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{self, fail},
    mem, objects, path, teb,
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use os_std::sync::Mutex;

/// Wall-clock time the process started (ns since 1970), set by init_process.
static START_NS: AtomicU64 = AtomicU64::new(0);

/// Real-time clock (ns since the Unix epoch) when the process started.
pub(crate) fn process_start_ns() -> u64 {
    START_NS.load(Ordering::Relaxed)
}

pub fn mark_start() {
    START_NS.store(os_sys::clock(osyx_abi::CLOCK_REALTIME).unwrap_or(0), Ordering::Relaxed);
}

// ---- calendar time ----------------------------------------------------------------

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// SYSTEMTIME: year, month, day of week, day, hour, minute, second, ms.
pub(crate) fn system_time(ft: u64) -> [u16; 8] {
    let ms_total = ft / 10_000;
    let days = (ms_total / 86_400_000) as i64 - 134_774; // 1601 → 1970
    let ms_day = ms_total % 86_400_000;
    let (y, m, d) = civil(days);
    let weekday = (days + 4).rem_euclid(7) as u16; // 1970-01-01 was a Thursday
    [
        y as u16,
        m as u16,
        weekday,
        d as u16,
        (ms_day / 3_600_000) as u16,
        (ms_day / 60_000 % 60) as u16,
        (ms_day / 1000 % 60) as u16,
        (ms_day % 1000) as u16,
    ]
}

pub(crate) fn now_filetime() -> u64 {
    kernel32::filetime(os_sys::clock(osyx_abi::CLOCK_REALTIME).unwrap_or(0) as i64)
}

extern "win64" fn GetSystemTime(out: *mut [u16; 8]) {
    if !out.is_null() {
        // SAFETY: the caller's SYSTEMTIME.
        unsafe { *out = system_time(now_filetime()) };
    }
}

pub(crate) extern "win64" fn SystemTimeToFileTime(st: *const [u16; 8], out: *mut u64) -> i32 {
    if st.is_null() || out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's SYSTEMTIME.
    let [y, m, _, d, h, min, s, ms] = unsafe { *st };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1601..=30827).contains(&y) || !(1..=12).contains(&m) || d == 0 || d > month_days[m as usize - 1] || h > 23 || min > 59 || s > 59 || ms > 999 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let days = days_from_civil(y as i64, m as u32, d as u32) + 134_774;
    let ms_total = days as u64 * 86_400_000 + h as u64 * 3_600_000 + min as u64 * 60_000 + s as u64 * 1000 + ms as u64;
    // SAFETY: the caller's FILETIME.
    unsafe { core::ptr::write_unaligned(out, ms_total * 10_000) };
    1
}

/// Interrupt time in 100 ns units. OSyx's monotonic clock does not advance
/// while the machine is suspended, so it is already unbiased.
extern "win64" fn QueryUnbiasedInterruptTime(out: *mut u64) -> i32 {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = os_sys::clock(osyx_abi::CLOCK_MONOTONIC).unwrap_or(0) / 100 };
    1
}

extern "win64" fn QueryUnbiasedInterruptTimePrecise(out: *mut u64) {
    if !out.is_null() {
        // SAFETY: as above.
        unsafe { *out = os_sys::clock(osyx_abi::CLOCK_MONOTONIC).unwrap_or(0) / 100 };
    }
}

/// Creation time is when winrun started the process. CPU time comes from
/// the kernel's per-process scheduler samples (1 kHz); OSyx does not
/// separate kernel from user time, so it is all reported as user time.
extern "win64" fn GetProcessTimes(process: u64, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> i32 {
    if process != objects::CURRENT_PROCESS {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    if creation.is_null() || exit.is_null() || kernel.is_null() || user.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let info = match os_sys::proc_info(kernel32::pid()) {
        Ok(info) => info,
        Err(osyx_abi::Errno::NotFound) => return fail(ERROR_GEN_FAILURE, 0),
        Err(e) => return fail(errno_to_win32(e), 0),
    };
    // SAFETY: the caller's FILETIMEs.
    unsafe {
        core::ptr::write_unaligned(creation, kernel32::filetime(START_NS.load(Ordering::Relaxed) as i64));
        core::ptr::write_unaligned(exit, 0);
        core::ptr::write_unaligned(kernel, 0);
        core::ptr::write_unaligned(user, info.cpu_ticks * 10_000);
    }
    1
}

// ---- version verification ---------------------------------------------------------

const VER_MINORVERSION: u32 = 0x1;
const VER_MAJORVERSION: u32 = 0x2;
const VER_BUILDNUMBER: u32 = 0x4;
const VER_PLATFORMID: u32 = 0x8;
const VER_SERVICEPACKMINOR: u32 = 0x10;
const VER_SERVICEPACKMAJOR: u32 = 0x20;
const VER_SUITENAME: u32 = 0x40;
const VER_PRODUCT_TYPE: u32 = 0x80;
const ERROR_OLD_WIN_VERSION: u32 = 1150;

/// The version GetVersionExW reports (kernel32.rs): 10.0.19041,
/// VER_PLATFORM_WIN32_NT, no service pack, workstation, no suites.
const OS: [u32; 8] = [0, 10, 19041, 2, 0, 0, 0, 1];

/// Bit index of a VER_* type → its slot in the condition mask.
fn slot(type_bit: u32) -> Option<usize> {
    [VER_MINORVERSION, VER_MAJORVERSION, VER_BUILDNUMBER, VER_PLATFORMID, VER_SERVICEPACKMINOR, VER_SERVICEPACKMAJOR, VER_SUITENAME, VER_PRODUCT_TYPE]
        .iter()
        .position(|&b| b == type_bit)
}

extern "win64" fn VerSetConditionMask(mask: u64, type_mask: u32, condition: u8) -> u64 {
    // Like Windows, one type per call: the highest-priority bit given.
    let order = [VER_PRODUCT_TYPE, VER_SUITENAME, VER_SERVICEPACKMAJOR, VER_SERVICEPACKMINOR, VER_PLATFORMID, VER_BUILDNUMBER, VER_MAJORVERSION, VER_MINORVERSION];
    match order.iter().find(|&&b| type_mask & b != 0).and_then(|&b| slot(b)) {
        // Windows also sets bit 63 in every mask it builds.
        Some(i) => mask | 1 << 63 | ((condition as u64 & 7) << (i * 3)),
        None => mask,
    }
}

fn compare(have: u32, want: u32, condition: u64) -> Option<bool> {
    Some(match condition {
        1 => have == want,
        2 => have > want,
        3 => have >= want,
        4 => have < want,
        5 => have <= want,
        _ => return None,
    })
}

extern "win64" fn VerifyVersionInfoW(info: *const u8, type_mask: u32, mask: u64) -> i32 {
    if info.is_null() || type_mask == 0 || mask == 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's OSVERSIONINFOEXW (284 bytes).
    let want = unsafe {
        let size: u32 = teb::get(info as u64, 0);
        if size < 284 {
            return fail(ERROR_INVALID_PARAMETER, 0);
        }
        let g32 = |o: usize| teb::get::<u32>(info as u64, o);
        let g16 = |o: usize| teb::get::<u16>(info as u64, o) as u32;
        [g32(8), g32(4), g32(12), g32(16), g16(278), g16(276), g16(280), teb::get::<u8>(info as u64, 282) as u32]
    };
    let cond = |i: usize| (mask >> (i * 3)) & 7;
    // Major, minor and service pack compare as one version tuple.
    let tuple = [(1usize, VER_MAJORVERSION), (0, VER_MINORVERSION), (5, VER_SERVICEPACKMAJOR), (4, VER_SERVICEPACKMINOR)];
    let mut ok = true;
    let mut decided = false;
    for &(i, bit) in &tuple {
        if decided || type_mask & bit == 0 {
            continue;
        }
        let Some(r) = compare(OS[i], want[i], cond(i)) else { return fail(ERROR_INVALID_PARAMETER, 0) };
        if OS[i] != want[i] {
            ok = r;
            decided = true;
        } else if !r {
            ok = false;
            decided = true;
        }
    }
    for (i, bit) in [(2usize, VER_BUILDNUMBER), (3, VER_PLATFORMID), (7, VER_PRODUCT_TYPE)] {
        if type_mask & bit != 0 {
            match compare(OS[i], want[i], cond(i)) {
                Some(r) => ok &= r,
                None => return fail(ERROR_INVALID_PARAMETER, 0),
            }
        }
    }
    if type_mask & VER_SUITENAME != 0 {
        ok &= match cond(6) {
            6 => OS[6] & want[6] == want[6], // VER_AND: all requested suites
            7 => OS[6] & want[6] != 0,       // VER_OR: any of them
            _ => return fail(ERROR_INVALID_PARAMETER, 0),
        };
    }
    if ok { 1 } else { fail(ERROR_OLD_WIN_VERSION, 0) }
}

// ---- pointer probes ---------------------------------------------------------------

/// A pipe the kernel copies probe bytes through: a write from an unmapped
/// or unreadable address fails with EFAULT instead of faulting here.
static PROBE: Mutex<Option<(u64, u64)>> = Mutex::new(None);

fn readable(addr: u64) -> bool {
    let mut g = PROBE.lock().unwrap();
    if g.is_none() {
        *g = os_sys::pipe().ok();
    }
    let Some((r, w)) = *g else { return false };
    if os_sys::write_raw(w, addr as usize, 1) != Ok(1) {
        return false;
    }
    let mut b = 0u8;
    let _ = os_sys::read_raw(r, &mut b as *mut u8 as usize, 1);
    true
}

extern "win64" fn IsBadReadPtr(p: u64, len: usize) -> i32 {
    i32::from(is_bad_read(p, len))
}

/// Whether any byte of [p, p+len) cannot be read.
pub fn is_bad_read(p: u64, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    if p == 0 {
        return true;
    }
    let Some(last) = p.checked_add(len as u64 - 1) else { return true };
    // PAGE_NOACCESS memory is mapped readable on OSyx (mem.rs): consult
    // the recorded protection first.
    let mut page = p & !(mem::PAGE as u64 - 1);
    while page <= last {
        if let Some(info) = mem::virtual_query(page) {
            if info.state != mem::MEM_COMMIT || info.protect & (mem::PAGE_NOACCESS | mem::PAGE_GUARD) != 0 {
                return true;
            }
        }
        if !readable(page.max(p)) {
            return true;
        }
        page += mem::PAGE as u64;
    }
    !readable(last)
}

// ---- Windows Error Reporting runtime exception modules ------------------------------------
//
// WerRegisterRuntimeExceptionModule records a (module path, context) pair
// for the process; WerUnregisterRuntimeExceptionModule removes the same
// pair. The list is what Windows keeps: OSyx has no out-of-process crash
// handler, so a registered module is never loaded after a crash.

const E_INVALIDARG_HR: u32 = 0x8007_0057;
const HR_FILE_NOT_FOUND: u32 = 0x8007_0002;

static WER_MODULES: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());

extern "win64" fn WerRegisterRuntimeExceptionModule(dll: *const u16, context: u64) -> u32 {
    // SAFETY: a NUL-terminated module path or NULL.
    let Some(path) = (unsafe { kernel32::sw(dll) }) else { return E_INVALIDARG_HR };
    WER_MODULES.lock().unwrap().push((path, context));
    0 // S_OK
}

extern "win64" fn WerUnregisterRuntimeExceptionModule(dll: *const u16, context: u64) -> u32 {
    // SAFETY: a NUL-terminated module path or NULL.
    let Some(path) = (unsafe { kernel32::sw(dll) }) else { return E_INVALIDARG_HR };
    let mut list = WER_MODULES.lock().unwrap();
    match list.iter().position(|(p, c)| *c == context && p.eq_ignore_ascii_case(&path)) {
        Some(i) => {
            list.remove(i);
            0 // S_OK
        }
        None => HR_FILE_NOT_FOUND,
    }
}

// ---- SearchPath -------------------------------------------------------------------

fn exists(win: &str) -> Option<String> {
    let cwd = os_std::env::current_dir().map(|p| path::to_windows(p.as_str())).unwrap_or_else(|_| String::from("C:\\"));
    let osyx = path::to_osyx(win, &cwd).ok()?;
    match path::resolve(&osyx) {
        Ok((p, true)) => Some(path::to_windows(&p)),
        _ => None,
    }
}

extern "win64" fn SearchPathW(dirs: *const u16, file: *const u16, ext: *const u16, size: u32, buf: *mut u16, part: *mut *mut u16) -> u32 {
    // SAFETY: NULL or NUL-terminated strings from the caller.
    let (dirs, file, ext) = unsafe { (path::wide_to_string(dirs), path::wide_to_string(file), path::wide_to_string(ext)) };
    let Some(mut file) = file.filter(|f| !f.is_empty()) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let leaf = file.rsplit(['\\', '/']).next().unwrap_or(&file);
    if let Some(e) = ext {
        if !leaf.contains('.') {
            file.push_str(&e);
        }
    }
    let explicit = file.contains(['\\', '/']) || file.as_bytes().get(1) == Some(&b':');
    let found = if explicit {
        exists(&file)
    } else {
        let list: Vec<String> = match dirs {
            Some(d) => d.split(';').filter(|s| !s.is_empty()).map(String::from).collect(),
            None => {
                let mut v = Vec::new();
                if let Some(exe) = kernel32::module_name(0) {
                    if let Some((dir, _)) = exe.rsplit_once('\\') {
                        v.push(String::from(dir));
                    }
                }
                v.push(String::from("."));
                v.push(String::from("C:\\Windows\\System32"));
                v.push(String::from("C:\\Windows"));
                if let Some(p) = kernel32::env_get("PATH") {
                    v.extend(p.split(';').filter(|s| !s.is_empty()).map(String::from));
                }
                v
            }
        };
        list.iter().find_map(|d| exists(&alloc::format!("{}\\{}", d.trim_end_matches('\\'), file)))
    };
    let Some(full) = found else { return fail(ERROR_FILE_NOT_FOUND, 0) };
    let units: Vec<u16> = full.encode_utf16().collect();
    if (size as usize) <= units.len() || buf.is_null() {
        return units.len() as u32 + 1;
    }
    // SAFETY: the caller's buffer of `size` units.
    unsafe {
        core::ptr::copy_nonoverlapping(units.as_ptr(), buf, units.len());
        *buf.add(units.len()) = 0;
        if !part.is_null() {
            let at = units.iter().rposition(|&c| c == b'\\' as u16).map_or(0, |i| i + 1);
            *part = buf.add(at);
        }
    }
    teb::set_last_error(ERROR_SUCCESS);
    units.len() as u32
}

// ---- FormatMessage ----------------------------------------------------------------

const ALLOCATE_BUFFER: u32 = 0x100;
const IGNORE_INSERTS: u32 = 0x200;
const FROM_STRING: u32 = 0x400;
const FROM_HMODULE: u32 = 0x800;
const FROM_SYSTEM: u32 = 0x1000;
const ARGUMENT_ARRAY: u32 = 0x2000;
const ERROR_MR_MID_NOT_FOUND: u32 = 317;

/// The system message table entries for the errors OSyx's runtime reports.
fn system_message(id: u32) -> Option<&'static str> {
    Some(match id {
        0 => "The operation completed successfully.\r\n",
        1 => "Incorrect function.\r\n",
        2 => "The system cannot find the file specified.\r\n",
        3 => "The system cannot find the path specified.\r\n",
        4 => "The system cannot open the file.\r\n",
        5 => "Access is denied.\r\n",
        6 => "The handle is invalid.\r\n",
        8 => "Not enough memory resources are available to process this command.\r\n",
        14 => "Not enough memory resources are available to complete this operation.\r\n",
        17 => "The system cannot move the file to a different disk drive.\r\n",
        19 => "The media is write protected.\r\n",
        31 => "A device attached to the system is not functioning.\r\n",
        32 => "The process cannot access the file because it is being used by another process.\r\n",
        38 => "Reached the end of the file.\r\n",
        50 => "The request is not supported.\r\n",
        80 => "The file exists.\r\n",
        87 => "The parameter is incorrect.\r\n",
        112 => "There is not enough space on the disk.\r\n",
        120 => "This function is not supported on this system.\r\n",
        122 => "The data area passed to a system call is too small.\r\n",
        123 => "The filename, directory name, or volume label syntax is incorrect.\r\n",
        126 => "The specified module could not be found.\r\n",
        127 => "The specified procedure could not be found.\r\n",
        145 => "The directory is not empty.\r\n",
        183 => "Cannot create a file when that file already exists.\r\n",
        193 => "%1 is not a valid Win32 application.\r\n",
        203 => "The system could not find the environment option that was entered.\r\n",
        206 => "The filename or extension is too long.\r\n",
        259 => "No more data is available.\r\n",
        267 => "The directory name is invalid.\r\n",
        487 => "Attempt to access invalid address.\r\n",
        1114 => "A dynamic link library (DLL) initialization routine failed.\r\n",
        1150 => "The specified program requires a newer version of Windows.\r\n",
        1460 => "This operation returned because the timeout period expired.\r\n",
        _ => return None,
    })
}

/// Expands `%n`-style inserts. `args` is the va_list / argument array
/// (one 8-byte slot per argument on x64); `wide` selects the default
/// string width of `!s!`.
fn expand(text: &str, flags: u32, args: *const u64, wide: bool) -> Result<String, u32> {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    let width = flags & 0xff;
    while let Some(c) = chars.next() {
        if c != '%' {
            if width == 0xff && (c == '\r' || c == '\n') {
                if c == '\n' || chars.peek() != Some(&'\n') {
                    out.push(' ');
                }
                continue;
            }
            out.push(c);
            continue;
        }
        let Some(&n) = chars.peek() else { break };
        match n {
            '0' => break,
            'n' => {
                chars.next();
                out.push_str("\r\n");
            }
            't' => {
                chars.next();
                out.push('\t');
            }
            'r' => {
                chars.next();
                out.push('\r');
            }
            '%' | '.' | '!' | ' ' => {
                chars.next();
                out.push(n);
            }
            '1'..='9' => {
                let mut index = 0usize;
                while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
                    index = index * 10 + d as usize;
                    chars.next();
                }
                let mut spec = String::new();
                if chars.peek() == Some(&'!') {
                    chars.next();
                    for s in chars.by_ref() {
                        if s == '!' {
                            break;
                        }
                        spec.push(s);
                    }
                }
                if flags & IGNORE_INSERTS != 0 {
                    out.push('%');
                    out.push_str(&index.to_string());
                    if !spec.is_empty() {
                        out.push('!');
                        out.push_str(&spec);
                        out.push('!');
                    }
                    continue;
                }
                if args.is_null() || index > 99 {
                    return Err(ERROR_INVALID_PARAMETER);
                }
                // SAFETY: the caller supplies at least `index` arguments.
                let v = unsafe { *args.add(index - 1) };
                out.push_str(&format_arg(v, if spec.is_empty() { "s" } else { &spec }, wide)?);
            }
            _ => {
                chars.next();
                out.push(n);
            }
        }
    }
    Ok(out)
}

/// One printf conversion of an insert: s/S strings, d/i/u/x/X/c, with an
/// optional l/h/I64 size prefix and a width.
fn format_arg(v: u64, spec: &str, wide: bool) -> Result<String, u32> {
    let conv = spec.chars().last().ok_or(ERROR_INVALID_PARAMETER)?;
    let body = &spec[..spec.len() - 1];
    let pad: usize = body.trim_start_matches(['-', '0']).trim_end_matches(['l', 'h', 'w']).trim_end_matches("I64").parse().unwrap_or(0);
    let left = body.starts_with('-');
    let zero = body.starts_with('0');
    let long64 = body.contains("I64") || body.contains("ll");
    let text = match conv {
        's' | 'S' => {
            let wide_str = (conv == 's') == wide || body.contains(['l', 'w']);
            // SAFETY: the argument is a NUL-terminated string of that width.
            unsafe {
                if wide_str { path::wide_to_string(v as *const u16) } else { path::ansi_to_string(v as *const u8) }
            }
            .unwrap_or_else(|| String::from("(null)"))
        }
        'd' | 'i' => if long64 { (v as i64).to_string() } else { (v as i32).to_string() },
        'u' => if long64 { v.to_string() } else { (v as u32).to_string() },
        'x' => if long64 { alloc::format!("{v:x}") } else { alloc::format!("{:x}", v as u32) },
        'X' => if long64 { alloc::format!("{v:X}") } else { alloc::format!("{:X}", v as u32) },
        'c' | 'C' => char::from_u32(v as u32).map(String::from).unwrap_or_default(),
        'p' => alloc::format!("{v:016X}"),
        _ => return Err(ERROR_INVALID_PARAMETER),
    };
    let len = text.chars().count();
    if len >= pad {
        return Ok(text);
    }
    let fill: String = core::iter::repeat_n(if zero && !left { '0' } else { ' ' }, pad - len).collect();
    Ok(if left { text + &fill } else { fill + &text })
}

/// The message text, before inserts.
fn source_text(flags: u32, source: u64, id: u32, wide: bool) -> Result<String, u32> {
    if flags & FROM_STRING != 0 {
        // SAFETY: the caller's NUL-terminated format string.
        let s = unsafe { if wide { path::wide_to_string(source as *const u16) } else { path::ansi_to_string(source as *const u8) } };
        return s.ok_or(ERROR_INVALID_PARAMETER);
    }
    if flags & FROM_HMODULE != 0 && source != 0 {
        // Message-table resources of PE modules are not parsed yet.
        return Err(ERROR_NOT_SUPPORTED);
    }
    if flags & (FROM_SYSTEM | FROM_HMODULE) == 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let id = if id & 0xffff_0000 == 0x8007_0000 { id & 0xffff } else { id }; // HRESULT_FROM_WIN32
    system_message(id).map(String::from).ok_or(ERROR_MR_MID_NOT_FOUND)
}

/// Shared body of FormatMessageA/W; writes `units` (bytes or UTF-16).
#[allow(clippy::too_many_arguments)]
fn format_message(flags: u32, source: u64, id: u32, lang: u32, buf: u64, size: u32, args: u64, wide: bool) -> u32 {
    if lang != 0 && lang & 0x3ff != 0x09 {
        return fail(1815, 0); // ERROR_RESOURCE_LANG_NOT_FOUND: only English text
    }
    let args = if args == 0 {
        core::ptr::null()
    } else if flags & ARGUMENT_ARRAY != 0 {
        args as *const u64
    } else {
        // A va_list on x64 is a pointer to the next argument slot.
        // SAFETY: the caller's va_list.
        unsafe { *(args as *const u64) as *const u64 }
    };
    let text = match source_text(flags, source, id, wide).and_then(|t| expand(&t, flags, args, wide)) {
        Ok(t) => t,
        Err(e) => return fail(e, 0),
    };
    let units: Vec<u16> = text.encode_utf16().collect();
    let count = if wide { units.len() } else { text.len() };
    let unit = if wide { 2 } else { 1 };
    let dst = if flags & ALLOCATE_BUFFER != 0 {
        let Some(p) = kernel32::heap_alloc((count.max(size as usize) + 1) * unit, false) else {
            return fail(ERROR_NOT_ENOUGH_MEMORY, 0);
        };
        // SAFETY: `buf` is the caller's pointer-sized out parameter.
        unsafe { *(buf as *mut u64) = p };
        p
    } else {
        if buf == 0 || count + 1 > size as usize {
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        buf
    };
    // SAFETY: `dst` holds count + 1 units.
    unsafe {
        if wide {
            core::ptr::copy_nonoverlapping(units.as_ptr(), dst as *mut u16, count);
            *(dst as *mut u16).add(count) = 0;
        } else {
            core::ptr::copy_nonoverlapping(text.as_ptr(), dst as *mut u8, count);
            *(dst as *mut u8).add(count) = 0;
        }
    }
    count as u32
}

extern "win64" fn FormatMessageA(flags: u32, source: u64, id: u32, lang: u32, buf: u64, size: u32, args: u64) -> u32 {
    format_message(flags, source, id, lang, buf, size, args, false)
}

extern "win64" fn FormatMessageW(flags: u32, source: u64, id: u32, lang: u32, buf: u64, size: u32, args: u64) -> u32 {
    format_message(flags, source, id, lang, buf, size, args, true)
}

// ---- processors ---------------------------------------------------------------------
//
// OSyx reports online logical CPUs and supports native thread affinity.

extern "win64" fn GetCurrentProcessorNumber() -> u32 {
    os_sys::cpu_info().map_or(0, |(_,cpu)|cpu)
}

/// With one CPU, a fence orders this thread's stores before any other
/// thread runs; there are no other processors' write buffers.
extern "win64" fn FlushProcessWriteBuffers() {
    let _=os_sys::process_write_barrier();
}

/// CPUID leaf 4 (deterministic cache parameters): (level, type, ways,
/// line size, size, fully associative) per cache.
fn caches() -> Vec<(u8, u32, u32, u16, u32, bool)> {
    let mut out = Vec::new();
    let max = core::arch::x86_64::__cpuid(0).eax;
    if max < 4 {
        return out;
    }
    for i in 0..16 {
        let r = core::arch::x86_64::__cpuid_count(4, i);
        let kind = r.eax & 0x1f;
        if kind == 0 {
            break;
        }
        let level = ((r.eax >> 5) & 7) as u8;
        let ways = (r.ebx >> 22) + 1;
        let partitions = ((r.ebx >> 12) & 0x3ff) + 1;
        let line = (r.ebx & 0xfff) + 1;
        let sets = r.ecx + 1;
        // Windows PROCESSOR_CACHE_TYPE: Unified 0, Instruction 1, Data 2.
        let t = match kind {
            1 => 2,
            2 => 1,
            _ => 0,
        };
        out.push((level, t, ways, line as u16, ways * partitions * line * sets, r.eax & 0x200 != 0));
    }
    out
}

/// SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX records for one processor:
/// core (0), NUMA node (1), caches (2), package (3), group (4).
extern "win64" fn GetLogicalProcessorInformationEx(relation: u32, buf: *mut u8, len: *mut u32) -> i32 {
    if len.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let all = relation == 0xffff;
    if !all && relation > 4 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut record = |kind: u32, body: &[u8]| {
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32 + 8).to_le_bytes());
        out.extend_from_slice(body);
    };
    // GROUP_AFFINITY: mask 1 in group 0.
    let mut affinity = [0u8; 16];
    let count = os_sys::cpu_info().map_or(1, |(count,_)|count);
    let mask = (1u64<<count)-1;
    affinity[..8].copy_from_slice(&mask.to_le_bytes());
    let processor = |b: &mut Vec<u8>| {
        b.extend_from_slice(&[0u8; 22]); // Flags, EfficiencyClass, Reserved
        b.extend_from_slice(&1u16.to_le_bytes()); // GroupCount
        b.extend_from_slice(&affinity);
    };
    if all || relation == 0 {
        for cpu in 0..count {
            let mut b = Vec::new();
            processor(&mut b);
            b[24..32].copy_from_slice(&(1u64<<cpu).to_le_bytes());
            record(0, &b);
        }
    }
    if all || relation == 1 {
        // NodeNumber 0, 18 reserved bytes, GroupCount 1, GroupMask.
        let mut b = alloc::vec![0u8; 22];
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&affinity);
        record(1, &b);
    }
    if all || relation == 2 {
        for (level, kind, ways, line, size, full) in caches() {
            let mut b = Vec::new();
            b.push(level);
            b.push(if full { 0xff } else { ways.min(0xfe) as u8 });
            b.extend_from_slice(&line.to_le_bytes());
            b.extend_from_slice(&size.to_le_bytes());
            b.extend_from_slice(&kind.to_le_bytes());
            b.extend_from_slice(&[0u8; 18]);
            b.extend_from_slice(&1u16.to_le_bytes());
            b.extend_from_slice(&affinity);
            record(2, &b);
        }
    }
    if all || relation == 3 {
        let mut b = Vec::new();
        processor(&mut b);
        record(3, &b);
    }
    if all || relation == 4 {
        let mut b = Vec::new();
        b.extend_from_slice(&1u16.to_le_bytes()); // MaximumGroupCount
        b.extend_from_slice(&1u16.to_le_bytes()); // ActiveGroupCount
        b.extend_from_slice(&[0u8; 20]);
        b.push(count as u8); // MaximumProcessorCount
        b.push(count as u8); // ActiveProcessorCount
        b.extend_from_slice(&[0u8; 38]);
        b.extend_from_slice(&mask.to_le_bytes()); // ActiveProcessorMask
        record(4, &b);
    }
    // SAFETY: the caller's in/out length and buffer of that length.
    unsafe {
        let have = *len as usize;
        *len = out.len() as u32;
        if buf.is_null() || have < out.len() {
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        core::ptr::copy_nonoverlapping(out.as_ptr(), buf, out.len());
    }
    1
}

extern "win64" fn SetThreadAffinityMask(thread: u64, mask: u64) -> u64 {
    if mask==0 {return fail(ERROR_INVALID_PARAMETER,0);}
    if !(thread == objects::CURRENT_THREAD || matches!(objects::get(thread), Some(objects::Object::Thread(_)))) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    let tid=crate::kernel32::GetThreadId(thread);
    os_sys::thread_affinity(tid as u64,mask).unwrap_or_else(|e| fail(crate::error::errno_to_win32(e),0))
}

// ---- process information ------------------------------------------------------------

extern "win64" fn IsWow64Process(process: u64, out: *mut i32) -> i32 {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if process != objects::CURRENT_PROCESS && !matches!(objects::get(process), Some(objects::Object::Process(_))) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    // SAFETY: the caller's out pointer. Every OSyx Windows process is x64.
    unsafe { *out = 0 };
    1
}

extern "win64" fn GetProcessHandleCount(process: u64, out: *mut u32) -> i32 {
    if process != objects::CURRENT_PROCESS || out.is_null() {
        return fail(if out.is_null() { ERROR_INVALID_PARAMETER } else { ERROR_ACCESS_DENIED }, 0);
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = objects::count() as u32 };
    1
}

/// The process heap, then the heaps made by HeapCreate. Returns how many
/// there are; at most `n` handles are written.
extern "win64" fn GetProcessHeaps(n: u32, out: *mut u64) -> u32 {
    let all = crate::heaps::all();
    if !out.is_null() {
        for (i, h) in all.iter().take(n as usize).enumerate() {
            // SAFETY: the caller's array of `n` handles (4 bytes each for a
            // 32-bit caller).
            unsafe {
                if crate::wow64::is_active() { *(out as *mut u32).add(i) = *h as u32 } else { *out.add(i) = *h }
            }
        }
    }
    all.len() as u32
}

const HEAP_COMPATIBILITY_INFORMATION: u32 = 0;
const HEAP_ENABLE_TERMINATION_ON_CORRUPTION: u32 = 1;

/// Both classes of Windows are hints: the low-fragmentation setting (a
/// ULONG, 0, 1 or 2) and terminate-on-corruption (heap NULL or any heap, no
/// data). The shared allocator has one behaviour, so a valid hint is
/// accepted; any other class or size is ERROR_INVALID_PARAMETER.
extern "win64" fn HeapSetInformation(_heap: u64, class: u32, info: u64, len: usize) -> i32 {
    match class {
        HEAP_ENABLE_TERMINATION_ON_CORRUPTION if len == 0 => 1,
        HEAP_COMPATIBILITY_INFORMATION if len == 4 && info != 0 => {
            // SAFETY: the caller passes a ULONG of `len` bytes.
            if unsafe { *(info as *const u32) } <= 2 {
                1
            } else {
                fail(ERROR_INVALID_PARAMETER, 0)
            }
        }
        _ => fail(ERROR_INVALID_PARAMETER, 0),
    }
}

const HANDLE_FLAG_INHERIT: u32 = 1;
const HANDLE_FLAG_PROTECT_FROM_CLOSE: u32 = 2;

/// HANDLE_FLAG_INHERIT is kept per handle (CreateProcess passes such
/// handles on, see inherit.rs); protecting a handle from CloseHandle is not
/// supported.
extern "win64" fn SetHandleInformation(h: u64, mask: u32, flags: u32) -> i32 {
    if objects::get(h).is_none() {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    if mask & !(HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if flags & mask & HANDLE_FLAG_PROTECT_FROM_CLOSE != 0 {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    if mask & HANDLE_FLAG_INHERIT != 0 {
        objects::set_inheritable(h, flags & HANDLE_FLAG_INHERIT != 0);
    }
    1
}

/// The handle's HANDLE_FLAG_INHERIT; handles are never protected.
extern "win64" fn GetHandleInformation(h: u64, flags: *mut u32) -> i32 {
    if objects::get(h).is_none() {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    if flags.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's out pointer.
    unsafe { *flags = if objects::is_inheritable(h) { HANDLE_FLAG_INHERIT } else { 0 } };
    1
}

// ---- thread information ----------------------------------------------------------------------
//
// SetThreadInformation / GetThreadInformation keep the values per thread id
// and answer a query with what was set. The OSyx scheduler has no page
// priority, absolute CPU priority or power throttling to apply them to;
// that is the same position as a Windows machine ignoring a hint.

const THREAD_MEMORY_PRIORITY: u32 = 0;
const THREAD_ABSOLUTE_CPU_PRIORITY: u32 = 1;
const THREAD_DYNAMIC_CODE_POLICY: u32 = 2;
const THREAD_POWER_THROTTLING: u32 = 3;
const MEMORY_PRIORITY_NORMAL: u32 = 5;
const POWER_THROTTLING_EXECUTION_SPEED: u32 = 1;
const ERROR_BAD_LENGTH_W: u32 = 24;

#[derive(Clone, Copy)]
struct ThreadInfo {
    memory: u32,
    absolute: u32,
    dynamic_code: u32,
    throttle_control: u32,
    throttle_state: u32,
}

const THREAD_INFO_DEFAULT: ThreadInfo = ThreadInfo { memory: MEMORY_PRIORITY_NORMAL, absolute: 0, dynamic_code: 0, throttle_control: 0, throttle_state: 0 };

static THREAD_INFO: Mutex<alloc::collections::BTreeMap<u32, ThreadInfo>> = Mutex::new(alloc::collections::BTreeMap::new());

fn thread_tid(h: u64) -> Option<u32> {
    if h == objects::CURRENT_THREAD || matches!(objects::get(h), Some(objects::Object::Thread(_))) {
        Some(kernel32::GetThreadId(h))
    } else {
        None
    }
}

/// The byte size of each information class.
fn thread_info_size(class: u32) -> Option<u32> {
    match class {
        THREAD_MEMORY_PRIORITY | THREAD_ABSOLUTE_CPU_PRIORITY | THREAD_DYNAMIC_CODE_POLICY => Some(4),
        THREAD_POWER_THROTTLING => Some(12),
        _ => None,
    }
}

extern "win64" fn SetThreadInformation(thread: u64, class: u32, info: u64, len: u32) -> i32 {
    let Some(tid) = thread_tid(thread) else { return fail(ERROR_INVALID_HANDLE, 0) };
    let Some(size) = thread_info_size(class) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    if info == 0 {
        return fail(ERROR_NOACCESS, 0);
    }
    if len != size {
        return fail(ERROR_BAD_LENGTH_W, 0);
    }
    // SAFETY: the caller's information block of `len` bytes.
    let word = |i: u64| unsafe { core::ptr::read_unaligned((info + i * 4) as *const u32) };
    let mut all = THREAD_INFO.lock().unwrap();
    let slot = all.entry(tid).or_insert(THREAD_INFO_DEFAULT);
    match class {
        THREAD_MEMORY_PRIORITY => {
            if word(0) > MEMORY_PRIORITY_NORMAL {
                return fail(ERROR_INVALID_PARAMETER, 0);
            }
            slot.memory = word(0);
        }
        THREAD_ABSOLUTE_CPU_PRIORITY => slot.absolute = word(0),
        THREAD_DYNAMIC_CODE_POLICY => {
            if word(0) > 1 {
                return fail(ERROR_INVALID_PARAMETER, 0);
            }
            slot.dynamic_code = word(0);
        }
        _ => {
            // THREAD_POWER_THROTTLING_STATE: Version (1), ControlMask, StateMask.
            let (version, control, state) = (word(0), word(1), word(2));
            if version != 1 || control & !POWER_THROTTLING_EXECUTION_SPEED != 0 || state & !control != 0 {
                return fail(ERROR_INVALID_PARAMETER, 0);
            }
            slot.throttle_control = control;
            slot.throttle_state = state;
        }
    }
    1
}

extern "win64" fn GetThreadInformation(thread: u64, class: u32, info: u64, len: u32) -> i32 {
    let Some(tid) = thread_tid(thread) else { return fail(ERROR_INVALID_HANDLE, 0) };
    if !matches!(class, THREAD_MEMORY_PRIORITY | THREAD_POWER_THROTTLING) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let size = thread_info_size(class).unwrap_or(0);
    if info == 0 {
        return fail(ERROR_NOACCESS, 0);
    }
    if len != size {
        return fail(ERROR_BAD_LENGTH_W, 0);
    }
    let cur = THREAD_INFO.lock().unwrap().get(&tid).copied().unwrap_or(THREAD_INFO_DEFAULT);
    // SAFETY: the caller's information block of `len` bytes.
    unsafe {
        let out = info as *mut u32;
        if class == THREAD_MEMORY_PRIORITY {
            core::ptr::write_unaligned(out, cur.memory);
        } else {
            core::ptr::write_unaligned(out, 1);
            core::ptr::write_unaligned(out.add(1), cur.throttle_control);
            core::ptr::write_unaligned(out.add(2), cur.throttle_state);
        }
    }
    1
}

// PROCESS_MITIGATION_POLICY classes reported as they are on OSyx: data
// execution prevention is always on (NX and W^X); the others are not
// enforced and read as all-zero flags.
const PROCESS_DEP_POLICY: u32 = 0;

extern "win64" fn GetProcessMitigationPolicy(process: u64, policy: u32, buf: *mut u8, len: usize) -> i32 {
    if process != objects::CURRENT_PROCESS {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    let need = if policy == PROCESS_DEP_POLICY { 8 } else { 4 };
    if buf.is_null() || len < need || policy > 16 || policy == 5 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's buffer of `len` bytes.
    unsafe {
        core::ptr::write_bytes(buf, 0, need);
        if policy == PROCESS_DEP_POLICY {
            teb::put(buf as u64, 0, 0x1u32); // Enable
            teb::put(buf as u64, 4, 1u8); // Permanent
        }
    }
    1
}

const PROCESS_EXTENSION_POINT_DISABLE_POLICY: u32 = 6;
const PROCESS_IMAGE_LOAD_POLICY: u32 = 10;

/// Policies OSyx already satisfies are accepted: DEP; disabled extension
/// points (OSyx loads no AppInit, shim or IME DLLs into processes); and the
/// image load policy's NoRemoteImages, NoLowMandatoryLabelImages and
/// PreferSystem32Images (no network images or integrity labels exist, and
/// system DLL names resolve to winrun's own before any folder). Others
/// cannot be enforced.
extern "win64" fn SetProcessMitigationPolicy(policy: u32, buf: *const u8, len: usize) -> i32 {
    if buf.is_null() || len < 4 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's policy structure.
    let flags = unsafe { teb::get::<u32>(buf as u64, 0) };
    let ok = match policy {
        PROCESS_DEP_POLICY => flags & !0x3 == 0 && flags & 1 != 0,
        PROCESS_EXTENSION_POINT_DISABLE_POLICY => flags & !1 == 0,
        PROCESS_IMAGE_LOAD_POLICY => flags & !0x7 == 0,
        _ => false,
    };
    if ok {
        return 1;
    }
    if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
        os_std::eprintln!("winrun: SetProcessMitigationPolicy({policy}, {flags:#x}) is not supported");
    }
    fail(ERROR_NOT_SUPPORTED, 0)
}

const APPMODEL_ERROR_NO_PACKAGE: u32 = 15700;

extern "win64" fn GetCurrentPackageFullName(len: *mut u32, _buf: *mut u16) -> u32 {
    if len.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    APPMODEL_ERROR_NO_PACKAGE
}

/// PRODUCT_UNDEFINED: OSyx is not a Windows edition.
extern "win64" fn GetProductInfo(_major: u32, _minor: u32, _sp_major: u32, _sp_minor: u32, out: *mut u32) -> i32 {
    if out.is_null() {
        return 0;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = 0 };
    1
}

extern "win64" fn GetSystemDirectoryW(buf: *mut u16, size: u32) -> u32 {
    kernel32::out_w("C:\\Windows\\System32", buf, size)
}

extern "win64" fn GetWindowsDirectoryW(buf: *mut u16, size: u32) -> u32 {
    kernel32::out_w("C:\\Windows", buf, size)
}

/// One installation, no per-session Windows directory.
extern "win64" fn GetSystemWindowsDirectoryW(buf: *mut u16, size: u32) -> u32 {
    GetWindowsDirectoryW(buf, size)
}

extern "win64" fn ExpandEnvironmentStringsW(src: *const u16, dst: *mut u16, size: u32) -> u32 {
    // SAFETY: a NUL-terminated string.
    let Some(s) = (unsafe { path::wide_to_string(src) }) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let expanded = crate::registry::expand_env(&s);
    // Returns the size including the terminator, whether or not it fits.
    let r = kernel32::out_w(&expanded, dst, size);
    if r >= size { r } else { r + 1 }
}

extern "win64" fn DebugBreak() {
    // SAFETY: raises EXCEPTION_BREAKPOINT through the normal dispatch.
    unsafe { core::arch::asm!("int3") };
}

const ATTACH_PARENT_PROCESS: u32 = u32::MAX;

/// Every winrun process already has the OSyx console as its standard
/// handles, which Windows reports as "already attached".
extern "win64" fn AttachConsole(pid: u32) -> i32 {
    let _ = ATTACH_PARENT_PROCESS;
    let _ = pid;
    fail(ERROR_ACCESS_DENIED, 0)
}

// ---- DLL search -------------------------------------------------------------------

const LOAD_LIBRARY_SEARCH_DEFAULT_FLAGS: u32 = 0x1e00;
static SAFE_SEARCH: AtomicU64 = AtomicU64::new(0);
static DLL_DIR: Mutex<Option<String>> = Mutex::new(None);

fn apply_search() {
    let dir = DLL_DIR.lock().unwrap().clone();
    // The current directory is searched only in the original default order.
    let cwd = SAFE_SEARCH.load(Ordering::Relaxed) == 0 && dir.is_none();
    crate::loader::set_dll_search(dir, cwd);
}

extern "win64" fn SetDefaultDllDirectories(flags: u32) -> i32 {
    if flags == 0 || flags & !LOAD_LIBRARY_SEARCH_DEFAULT_FLAGS != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    SAFE_SEARCH.store(flags as u64, Ordering::Relaxed);
    apply_search();
    1
}

extern "win64" fn SetDllDirectoryW(dir: *const u16) -> i32 {
    // SAFETY: NULL or a NUL-terminated string.
    let d = unsafe { path::wide_to_string(dir) };
    let null = d.is_none();
    let new = match d {
        None => None,
        Some(s) if s.is_empty() => {
            // "" removes the current directory without adding one.
            SAFE_SEARCH.fetch_or(1 << 32, Ordering::Relaxed);
            None
        }
        Some(s) => match path::to_osyx(&s, &kernel32::cwd_win()).and_then(|p| path::resolve(&p)) {
            Ok((p, true)) => Some(p),
            _ => return fail(ERROR_PATH_NOT_FOUND, 0),
        },
    };
    if null {
        SAFE_SEARCH.fetch_and(!(1 << 32), Ordering::Relaxed);
    }
    *DLL_DIR.lock().unwrap() = new;
    apply_search();
    1
}

extern "win64" fn CreateSemaphoreExW(sa: u64, initial: i32, max: i32, name: *const u16, flags: u32, _access: u32) -> u64 {
    if flags != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if !name.is_null() {
        return fail(ERROR_NOT_SUPPORTED, 0); // semaphores are unnamed here
    }
    kernel32::CreateSemaphoreA(sa, initial, max, core::ptr::null())
}

/// ObjectBasicInformation (0) and ObjectTypeInformation (2) for handles
/// of this process; names (1) are not tracked.
extern "win64" fn NtQueryObject(h: u64, class: u32, buf: *mut u8, len: u32, ret: *mut u32) -> NtStatus {
    let Some(o) = objects::get(h) else { return STATUS_INVALID_HANDLE };
    match class {
        0 => {
            if len < 56 || buf.is_null() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // SAFETY: the caller's 56-byte OBJECT_BASIC_INFORMATION.
            unsafe {
                core::ptr::write_bytes(buf, 0, 56);
                teb::put(buf as u64, 8, 1u32); // HandleCount (this handle)
                teb::put(buf as u64, 12, 1u32); // PointerCount
                if !ret.is_null() {
                    *ret = 56;
                }
            }
            STATUS_SUCCESS
        }
        2 => {
            let name = match o {
                objects::Object::File(_) | objects::Object::Console(_) | objects::Object::Null | objects::Object::Pipe(_) => "File",
                objects::Object::Directory(_) => "Directory",
                objects::Object::Transaction(_) => "Transaction",
                objects::Object::Thread(_) => "Thread",
                objects::Object::Event(_) => "Event",
                objects::Object::KeyedEvent(_) => "KeyedEvent",
                objects::Object::Timer(_) => "Timer",
                objects::Object::Mutex(_) => "Mutant",
                objects::Object::Semaphore(_) => "Semaphore",
                objects::Object::Section(_) => "Section",
                objects::Object::Token(_) => "Token",
                objects::Object::Port(_) => "IoCompletion",
                objects::Object::Process(_) => "Process",
                objects::Object::Job(_) => "Job",
                objects::Object::WindowStation(_) => "WindowStation",
                objects::Object::Desktop(_) => "Desktop",
            };
            // OBJECT_TYPE_INFORMATION: UNICODE_STRING TypeName, then
            // counters (zero here); the name follows the 104-byte header.
            let units: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
            let need = 104 + units.len() as u32 * 2;
            if !ret.is_null() {
                // SAFETY: the caller's out pointer.
                unsafe { *ret = need };
            }
            if len < need || buf.is_null() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // SAFETY: the caller's buffer of `need` bytes.
            unsafe {
                core::ptr::write_bytes(buf, 0, 104);
                teb::put(buf as u64, 0, ((units.len() - 1) * 2) as u16);
                teb::put(buf as u64, 2, (units.len() * 2) as u16);
                teb::put(buf as u64, 8, buf as u64 + 104);
                core::ptr::copy_nonoverlapping(units.as_ptr(), buf.add(104) as *mut u16, units.len());
            }
            STATUS_SUCCESS
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}

/// ntdll is VerSetConditionMask's real home; kernel32's forwards to it.
pub fn ntdll_exports() -> Vec<(&'static str, u64)> {
    export_table![VerSetConditionMask, NtQueryObject]
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        GetSystemTime,
        SystemTimeToFileTime,
        QueryUnbiasedInterruptTime,
        QueryUnbiasedInterruptTimePrecise,
        GetProcessTimes,
        VerSetConditionMask,
        VerifyVersionInfoW,
        IsBadReadPtr,
        WerRegisterRuntimeExceptionModule,
        WerUnregisterRuntimeExceptionModule,
        SearchPathW,
        FormatMessageA,
        FormatMessageW,
        GetCurrentProcessorNumber,
        FlushProcessWriteBuffers,
        GetLogicalProcessorInformationEx,
        SetThreadAffinityMask,
        IsWow64Process,
        GetProcessHandleCount,
        GetProcessHeaps,
        HeapSetInformation,
        GetThreadInformation,
        SetHandleInformation,
        GetHandleInformation,
        SetThreadInformation,
        GetProcessMitigationPolicy,
        SetProcessMitigationPolicy,
        GetCurrentPackageFullName,
        GetProductInfo,
        GetSystemDirectoryW,
        GetWindowsDirectoryW,
        GetSystemWindowsDirectoryW,
        ExpandEnvironmentStringsW,
        DebugBreak,
        AttachConsole,
        SetDefaultDllDirectories,
        SetDllDirectoryW,
        CreateSemaphoreExW,
    ]
}
