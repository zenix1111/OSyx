//! Time (time contract): the wall clock, UTC calendar conversion and
//! strftime with the C locale's names and formats (also as the
//! `__crt_lc_time_data` that msvcp140 passes back to `_Strftime`).
//!
//! Uses the OSyx system zone from /etc/TZ, with the CRT's TZ variable
//! override ("XXX[+|-]h[:mm[:ss]][YYY]" and POSIX transition rules).

use super::*;
use alloc::string::String;

const DAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const SDATE: &str = "MM/dd/yy";
const LDATE: &str = "dddd, MMMM dd, yyyy";
const TIME: &str = "HH:mm:ss";

fn now_secs() -> i64 {
    (os_sys::clock(osyx_abi::CLOCK_REALTIME).unwrap_or(0) / 1_000_000_000) as i64
}

extern "win64" fn _time64(out: *mut i64) -> i64 {
    let t = now_secs();
    if !out.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = t };
    }
    t
}

extern "win64" fn _time32(out: *mut i32) -> i32 {
    let t = now_secs();
    if t > i32::MAX as i64 {
        set_errno(ERANGE);
        return -1;
    }
    if !out.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = t as i32 };
    }
    t as i32
}

/// Legacy MSVCRT `time`: 32-bit time_t on x86 and 64-bit time_t on x64.
extern "win64" fn time(out: *mut u8) -> i64 {
    if crate::wow64::is_active() {
        _time32(out.cast()) as i64
    } else {
        _time64(out.cast())
    }
}

/// `struct tm`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Tm {
    sec: i32,
    min: i32,
    hour: i32,
    mday: i32,
    mon: i32,
    year: i32,
    wday: i32,
    yday: i32,
    isdst: i32,
}

fn leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Days from 1970-01-01 to y-m-d (proleptic Gregorian, m 1..=12).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

/// `_MAX__TIME64_T`: 3000-12-31 23:59:59 UTC.
const MAX_TIME64: i64 = 32_535_215_999;

fn to_tm(t: i64) -> Tm {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let yday = days - days_from_civil(y, 1, 1);
    Tm {
        sec: (secs % 60) as i32,
        min: (secs / 60 % 60) as i32,
        hour: (secs / 3600) as i32,
        mday: d as i32,
        mon: (m - 1) as i32,
        year: (y - 1900) as i32,
        wday: (days + 4).rem_euclid(7) as i32,
        yday: yday as i32,
        isdst: 0,
    }
}

extern "win64" fn _gmtime64_s(out: *mut Tm, t: *const i64) -> i32 {
    validate!(!out.is_null(), EINVAL, EINVAL);
    // SAFETY: validated; filled with -1 on failure as the UCRT does.
    unsafe { core::ptr::write_bytes(out as *mut u8, 0xFF, core::mem::size_of::<Tm>()) };
    validate!(!t.is_null(), EINVAL, EINVAL);
    // SAFETY: the caller's time value.
    let t = unsafe { *t };
    validate!((0..=MAX_TIME64).contains(&t), EINVAL, EINVAL);
    // SAFETY: validated out pointer.
    unsafe { *out = to_tm(t) };
    0
}

extern "win64" fn _gmtime64(t: *const i64) -> *mut Tm {
    let out = &raw mut ptd().calendar;
    if _gmtime64_s(out, t) != 0 {
        core::ptr::null_mut()
    } else {
        out
    }
}

/// `_mkgmtime64`: normalises the fields and returns the UTC time.
extern "win64" fn _mkgmtime64(tm: *mut Tm) -> i64 {
    validate!(!tm.is_null(), EINVAL, -1);
    // SAFETY: validated.
    let v = unsafe { *tm };
    let mon = v.mon as i64;
    let y = v.year as i64 + 1900 + mon.div_euclid(12);
    let m = mon.rem_euclid(12) + 1;
    let days = days_from_civil(y, m, 1) + v.mday as i64 - 1;
    let t = days * 86_400 + v.hour as i64 * 3600 + v.min as i64 * 60 + v.sec as i64;
    if !(0..=MAX_TIME64).contains(&t) {
        set_errno(EINVAL);
        return -1;
    }
    // SAFETY: validated.
    unsafe { *tm = to_tm(t) };
    t
}

extern "win64" fn _difftime64_soft(a: i64, b: i64) -> f64 {
    (a - b) as f64
}

// ---- time zone ---------------------------------------------------------------------------

/// (standard name, daylight name, seconds west of UTC) of the C runtime's zone.
fn zone() -> (String, String, i64) {
    let tz = crate::tz::crt();
    let dst = tz.dst.as_ref().map(|d| d.0.clone()).unwrap_or_default();
    (tz.std_name.clone(), dst, -tz.std_offset)
}

/// The globals `_tzset` fills: _timezone (seconds west), _daylight,
/// _dstbias (seconds, daylight minus standard, negated) and _tzname.
static TIMEZONE: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
static DAYLIGHT: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
static DSTBIAS: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(-3600);
static TZ_SET: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static TZ_LOCK: RLock = RLock::new();
/// _tzname: two 64-byte name buffers and the array of pointers to them.
static mut TZNAME_BUF: [[u8; 64]; 2] = [[0; 64]; 2];
static mut TZNAME: [*mut u8; 2] = [core::ptr::null_mut(); 2];

extern "win64" fn _tzset() {
    TZ_LOCK.lock();
    let tz = crate::tz::crt();
    TIMEZONE.store(-tz.std_offset as i32, Ordering::SeqCst);
    DAYLIGHT.store(tz.dst.is_some() as i32, Ordering::SeqCst);
    DSTBIAS.store(tz.dst.as_ref().map_or(-3600, |d| -(d.1 - tz.std_offset)) as i32, Ordering::SeqCst);
    let dst = tz.dst.as_ref().map(|d| d.0.clone()).unwrap_or_default();
    // SAFETY: the buffers are written only here, with TZ_LOCK held.
    unsafe {
        let bufs = &mut *core::ptr::addr_of_mut!(TZNAME_BUF);
        for (i, name) in [tz.std_name.as_bytes(), dst.as_bytes()].iter().enumerate() {
            let n = name.len().min(63);
            bufs[i] = [0; 64];
            bufs[i][..n].copy_from_slice(&name[..n]);
        }
        let names = &mut *core::ptr::addr_of_mut!(TZNAME);
        names[0] = bufs[0].as_mut_ptr();
        names[1] = bufs[1].as_mut_ptr();
    }
    TZ_SET.store(true, Ordering::SeqCst);
    TZ_LOCK.unlock();
}

fn tzset_once() {
    if !TZ_SET.load(Ordering::SeqCst) {
        _tzset();
    }
}

extern "win64" fn __timezone() -> *mut i32 {
    tzset_once();
    TIMEZONE.as_ptr()
}

extern "win64" fn __daylight() -> *mut i32 {
    tzset_once();
    DAYLIGHT.as_ptr()
}

extern "win64" fn __dstbias() -> *mut i32 {
    tzset_once();
    DSTBIAS.as_ptr()
}

extern "win64" fn __tzname() -> *mut *mut u8 {
    tzset_once();
    core::ptr::addr_of_mut!(TZNAME) as *mut *mut u8
}

extern "win64" fn _get_timezone(out: *mut i32) -> i32 {
    validate!(!out.is_null(), EINVAL, EINVAL);
    tzset_once();
    // SAFETY: validated.
    unsafe { *out = TIMEZONE.load(Ordering::SeqCst) };
    0
}

extern "win64" fn _get_daylight(out: *mut i32) -> i32 {
    validate!(!out.is_null(), EINVAL, EINVAL);
    tzset_once();
    // SAFETY: validated.
    unsafe { *out = DAYLIGHT.load(Ordering::SeqCst) };
    0
}

extern "win64" fn _get_dstbias(out: *mut i32) -> i32 {
    validate!(!out.is_null(), EINVAL, EINVAL);
    tzset_once();
    // SAFETY: validated.
    unsafe { *out = DSTBIAS.load(Ordering::SeqCst) };
    0
}

/// Local time of `t` and whether daylight time applies.
fn local_tm(t: i64) -> Tm {
    let tz = crate::tz::crt();
    let (off, _) = tz.offset_at(t);
    let mut tm = to_tm(t + off);
    tm.isdst = (tz.dst.is_some() && off != tz.std_offset) as i32;
    tm
}

extern "win64" fn _localtime64_s(out: *mut Tm, t: *const i64) -> i32 {
    validate!(!out.is_null(), EINVAL, EINVAL);
    // SAFETY: validated; filled with -1 on failure as the UCRT does.
    unsafe { core::ptr::write_bytes(out as *mut u8, 0xFF, core::mem::size_of::<Tm>()) };
    validate!(!t.is_null(), EINVAL, EINVAL);
    // SAFETY: the caller's time value.
    let t = unsafe { *t };
    validate!((0..=MAX_TIME64).contains(&t), EINVAL, EINVAL);
    tzset_once();
    // SAFETY: validated out pointer.
    unsafe { *out = local_tm(t) };
    0
}

extern "win64" fn _localtime64(t: *const i64) -> *mut Tm {
    let out = &raw mut ptd().calendar;
    if _localtime64_s(out, t) != 0 {
        core::ptr::null_mut()
    } else {
        out
    }
}

/// `_mktime64`: the fields as local time (tm_isdst > 0 daylight, 0
/// standard, < 0 whichever applies), normalised in place.
extern "win64" fn _mktime64(tm: *mut Tm) -> i64 {
    validate!(!tm.is_null(), EINVAL, -1);
    tzset_once();
    // SAFETY: validated.
    let v = unsafe { *tm };
    let mon = v.mon as i64;
    let y = v.year as i64 + 1900 + mon.div_euclid(12);
    let m = mon.rem_euclid(12) + 1;
    let days = days_from_civil(y, m, 1) + v.mday as i64 - 1;
    let local = days * 86_400 + v.hour as i64 * 3600 + v.min as i64 * 60 + v.sec as i64;
    let tz = crate::tz::crt();
    let dst = match v.isdst {
        i32::MIN..=-1 => None,
        0 => Some(false),
        _ => Some(tz.dst.is_some()),
    };
    let t = crate::tz::to_utc(&tz, local, dst);
    if !(0..=MAX_TIME64).contains(&t) {
        set_errno(EINVAL);
        return -1;
    }
    // SAFETY: validated.
    unsafe { *tm = local_tm(t) };
    t
}

/// `struct __timeb64`: time, millitm, timezone (minutes west), dstflag.
#[repr(C)]
struct Timeb {
    time: i64,
    millitm: u16,
    timezone: i16,
    dstflag: i16,
}

extern "win64" fn _ftime64(out: *mut Timeb) {
    if out.is_null() {
        invalid(EINVAL, ());
        return;
    }
    tzset_once();
    let ns = os_sys::clock(osyx_abi::CLOCK_REALTIME).unwrap_or(0);
    let t = (ns / 1_000_000_000) as i64;
    // _ftime's dstflag reports the system's daylight status even when
    // TZ overrides the CRT's _timezone value (as on Windows).
    let tz = crate::tz::system();
    let (off, _) = tz.offset_at(t);
    // SAFETY: the caller's structure.
    unsafe {
        *out = Timeb {
            time: t,
            millitm: (ns / 1_000_000 % 1000) as u16,
            timezone: (TIMEZONE.load(Ordering::SeqCst) / 60) as i16,
            dstflag: (tz.dst.is_some() && off != tz.std_offset) as i16,
        };
    }
}
// ---- names -------------------------------------------------------------------------------

fn names_text(months: bool) -> String {
    let mut s = String::new();
    let list: &[&str] = if months { &MONTHS } else { &DAYS };
    for n in list {
        s.push(':');
        s.push_str(&n[..3]);
        s.push(':');
        s.push_str(n);
    }
    s
}

extern "win64" fn _Getdays() -> *mut u8 {
    heap_cstr(names_text(false).as_bytes())
}

extern "win64" fn _Getmonths() -> *mut u8 {
    heap_cstr(names_text(true).as_bytes())
}

extern "win64" fn _W_Getdays() -> *mut u16 {
    heap_wstr(&names_text(false).encode_utf16().collect::<Vec<u16>>())
}

extern "win64" fn _W_Getmonths() -> *mut u16 {
    heap_wstr(&names_text(true).encode_utf16().collect::<Vec<u16>>())
}

/// Offsets in `__crt_lc_time_data`.
const NARROW_PTRS: usize = 43; // wday_abbr..ww_timefmt
const WIDE_AT: usize = NARROW_PTRS * 8 + 8; // after caltype and refcount
const WIDE_PTRS: usize = 44; // _W_wday_abbr.._W_ww_locale_name
const STRUCT_SIZE: usize = WIDE_AT + WIDE_PTRS * 8;

/// The C locale's strings in `__crt_lc_time_data` order.
fn time_strings() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    v.extend(DAYS.iter().map(|d| String::from(&d[..3])));
    v.extend(DAYS.iter().map(|d| String::from(*d)));
    v.extend(MONTHS.iter().map(|m| String::from(&m[..3])));
    v.extend(MONTHS.iter().map(|m| String::from(*m)));
    v.extend([String::from("AM"), String::from("PM"), String::from(SDATE), String::from(LDATE), String::from(TIME)]);
    v
}

/// One heap block: the structure followed by its narrow and wide strings
/// (free() releases it all, as callers do).
fn time_data() -> *mut u8 {
    let strs = time_strings();
    let narrow: usize = strs.iter().map(|s| s.len() + 1).sum();
    let wide: usize = strs.iter().map(|s| (s.len() + 1) * 2).sum();
    let total = STRUCT_SIZE + narrow + wide + 2;
    let p = crt_malloc(total);
    if p.is_null() {
        return p;
    }
    // SAFETY: a fresh block of `total` bytes, written within its bounds.
    unsafe {
        core::ptr::write_bytes(p, 0, total);
        let mut at = p.add(STRUCT_SIZE);
        for (i, s) in strs.iter().enumerate() {
            *(p.add(i * 8) as *mut u64) = at as u64;
            core::ptr::copy_nonoverlapping(s.as_ptr(), at, s.len());
            at = at.add(s.len() + 1);
        }
        *(p.add(NARROW_PTRS * 8 + 4) as *mut i32) = 1; // refcount
        let mut w = at.add((at as usize) & 1) as *mut u16;
        for (i, s) in strs.iter().enumerate() {
            *(p.add(WIDE_AT + i * 8) as *mut u64) = w as u64;
            for (k, u) in s.encode_utf16().enumerate() {
                *w.add(k) = u;
            }
            w = w.add(s.len() + 1);
        }
        // _W_ww_locale_name stays NULL: no locale name.
    }
    p
}

extern "win64" fn _Gettnames() -> *mut u8 {
    time_data()
}

extern "win64" fn _W_Gettnames() -> *mut u8 {
    time_data()
}

// ---- strftime ----------------------------------------------------------------------------

/// Reads string `i` of a `__crt_lc_time_data` (narrow table).
fn data_str(data: u64, i: usize) -> String {
    if data == 0 {
        return time_strings().swap_remove(i);
    }
    // SAFETY: a structure from `_Gettnames` (or of the same layout).
    let p = unsafe { *((data as usize + i * 8) as *const *const u8) };
    // SAFETY: its NUL-terminated string.
    String::from_utf8_lossy(unsafe { cstr(p) }).into_owned()
}

fn iso_week(tm: &Tm) -> (i64, i32) {
    let wday = (tm.wday + 6) % 7; // Monday = 0
    let year = tm.year as i64 + 1900;
    let week = (tm.yday - wday + 10) / 7;
    if week < 1 {
        let py = year - 1;
        let pdays = if leap(py) { 366 } else { 365 };
        let yday = tm.yday + pdays;
        return (py, (yday - wday + 10) / 7);
    }
    let days = if leap(year) { 366 } else { 365 };
    if week == 53 && tm.yday - wday + 3 >= days {
        return (year + 1, 1);
    }
    (year, week)
}

/// Expands a format; Err(()) for an invalid specifier or field.
fn format(fmt: &[u32], tm: &Tm, data: u64, out: &mut String) -> Result<(), ()> {
    let mut i = 0;
    let num = |out: &mut String, v: i64, width: usize, alt: bool| {
        if alt {
            out.push_str(&alloc::format!("{v}"));
        } else {
            out.push_str(&alloc::format!("{v:0width$}"));
        }
    };
    let check = |ok: bool| if ok { Ok(()) } else { Err(()) };
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c != b'%' as u32 {
            out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
            continue;
        }
        let mut alt = false;
        let mut spec = *fmt.get(i).ok_or(())?;
        i += 1;
        if spec == b'#' as u32 {
            alt = true;
            spec = *fmt.get(i).ok_or(())?;
            i += 1;
        } else if spec == b'E' as u32 || spec == b'O' as u32 {
            spec = *fmt.get(i).ok_or(())?;
            i += 1;
        }
        let spec = char::from_u32(spec).ok_or(())?;
        match spec {
            'a' => {
                check((0..7).contains(&tm.wday))?;
                out.push_str(&data_str(data, tm.wday as usize));
            }
            'A' => {
                check((0..7).contains(&tm.wday))?;
                out.push_str(&data_str(data, 7 + tm.wday as usize));
            }
            'b' | 'h' => {
                check((0..12).contains(&tm.mon))?;
                out.push_str(&data_str(data, 14 + tm.mon as usize));
            }
            'B' => {
                check((0..12).contains(&tm.mon))?;
                out.push_str(&data_str(data, 26 + tm.mon as usize));
            }
            'c' => {
                let f = if alt { "%#x %H:%M:%S" } else { "%a %b %e %H:%M:%S %Y" };
                format(&f.chars().map(|c| c as u32).collect::<Vec<u32>>(), tm, data, out)?;
            }
            'x' => {
                let f = if alt { "%A, %B %d, %Y" } else { "%m/%d/%y" };
                format(&f.chars().map(|c| c as u32).collect::<Vec<u32>>(), tm, data, out)?;
            }
            'X' | 'T' => format(&"%H:%M:%S".chars().map(|c| c as u32).collect::<Vec<u32>>(), tm, data, out)?,
            'D' => format(&"%m/%d/%y".chars().map(|c| c as u32).collect::<Vec<u32>>(), tm, data, out)?,
            'F' => format(&"%Y-%m-%d".chars().map(|c| c as u32).collect::<Vec<u32>>(), tm, data, out)?,
            'r' => format(&"%I:%M:%S %p".chars().map(|c| c as u32).collect::<Vec<u32>>(), tm, data, out)?,
            'R' => format(&"%H:%M".chars().map(|c| c as u32).collect::<Vec<u32>>(), tm, data, out)?,
            'd' => {
                check((1..=31).contains(&tm.mday))?;
                num(out, tm.mday as i64, 2, alt);
            }
            'e' => {
                check((1..=31).contains(&tm.mday))?;
                if alt {
                    num(out, tm.mday as i64, 0, true);
                } else {
                    out.push_str(&alloc::format!("{:2}", tm.mday));
                }
            }
            'H' => {
                check((0..=23).contains(&tm.hour))?;
                num(out, tm.hour as i64, 2, alt);
            }
            'I' => {
                check((0..=23).contains(&tm.hour))?;
                let h = tm.hour % 12;
                num(out, if h == 0 { 12 } else { h } as i64, 2, alt);
            }
            'j' => {
                check((0..=365).contains(&tm.yday))?;
                num(out, tm.yday as i64 + 1, 3, alt);
            }
            'm' => {
                check((0..12).contains(&tm.mon))?;
                num(out, tm.mon as i64 + 1, 2, alt);
            }
            'M' => {
                check((0..=59).contains(&tm.min))?;
                num(out, tm.min as i64, 2, alt);
            }
            'S' => {
                check((0..=60).contains(&tm.sec))?;
                num(out, tm.sec as i64, 2, alt);
            }
            'p' => {
                check((0..=23).contains(&tm.hour))?;
                out.push_str(&data_str(data, if tm.hour < 12 { 38 } else { 39 }));
            }
            'U' | 'W' => {
                check((0..7).contains(&tm.wday) && (0..=365).contains(&tm.yday))?;
                let wd = if spec == 'U' { tm.wday } else { (tm.wday + 6) % 7 };
                num(out, ((tm.yday + 7 - wd) / 7) as i64, 2, alt);
            }
            'w' => {
                check((0..7).contains(&tm.wday))?;
                num(out, tm.wday as i64, 1, alt);
            }
            'u' => {
                check((0..7).contains(&tm.wday))?;
                num(out, if tm.wday == 0 { 7 } else { tm.wday } as i64, 1, alt);
            }
            'y' => num(out, (tm.year as i64 + 1900).rem_euclid(100), 2, alt),
            'Y' => num(out, tm.year as i64 + 1900, 4, alt),
            'C' => num(out, (tm.year as i64 + 1900).div_euclid(100), 2, alt),
            'g' | 'G' | 'V' => {
                check((0..7).contains(&tm.wday) && (0..=365).contains(&tm.yday))?;
                let (y, w) = iso_week(tm);
                match spec {
                    'g' => num(out, y.rem_euclid(100), 2, alt),
                    'G' => num(out, y, 4, alt),
                    _ => num(out, w as i64, 2, alt),
                }
            }
            'z' => {
                let tz = crate::tz::crt();
                let east = match (&tz.dst, tm.isdst > 0) {
                    (Some(d), true) => d.1,
                    _ => tz.std_offset,
                };
                let sign = if east < 0 { '-' } else { '+' };
                let a = east.abs();
                out.push_str(&alloc::format!("{sign}{:02}{:02}", a / 3600, a / 60 % 60));
            }
            'Z' => {
                let (std, dst, _) = zone();
                out.push_str(if tm.isdst > 0 && !dst.is_empty() { &dst } else { &std });
            }
            'n' => out.push('\n'),
            't' => out.push('\t'),
            '%' => out.push('%'),
            _ => return Err(()),
        }
    }
    Ok(())
}

/// Common body of the strftime family: returns the units written
/// (without NUL), or 0 with errno.
fn strftime_common<T: Copy + From<u8>>(
    buf: *mut T,
    max: usize,
    fmt: Vec<u32>,
    tm: *const Tm,
    data: u64,
    encode: fn(&str) -> Vec<T>,
) -> usize {
    validate!(!buf.is_null() && max > 0, EINVAL, 0);
    // SAFETY: validated buffer.
    unsafe { *buf = T::from(0) };
    validate!(!tm.is_null(), EINVAL, 0);
    let mut s = String::new();
    // SAFETY: the caller's struct tm.
    if format(&fmt, unsafe { &*tm }, data, &mut s).is_err() {
        set_errno(EINVAL);
        invalid_parameter();
        return 0;
    }
    let units = encode(&s);
    if units.len() >= max {
        set_errno(ERANGE);
        return 0;
    }
    // SAFETY: len + 1 <= max units.
    unsafe {
        core::ptr::copy_nonoverlapping(units.as_ptr(), buf, units.len());
        *buf.add(units.len()) = T::from(0);
    }
    units.len()
}

fn enc_narrow(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn enc_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn narrow_fmt(f: *const u8) -> Option<Vec<u32>> {
    if f.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated format.
    Some(String::from_utf8_lossy(unsafe { cstr(f) }).chars().map(|c| c as u32).collect())
}

fn wide_fmt(f: *const u16) -> Option<Vec<u32>> {
    if f.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated format.
    Some(char::decode_utf16(unsafe { wstr(f) }.iter().copied()).map(|c| c.map_or(0xFFFD, |c| c as u32)).collect())
}

extern "win64" fn _Strftime(buf: *mut u8, max: usize, fmt: *const u8, tm: *const Tm, data: u64) -> usize {
    let Some(f) = narrow_fmt(fmt) else { return invalid(EINVAL, 0) };
    strftime_common(buf, max, f, tm, data, enc_narrow)
}

extern "win64" fn _Wcsftime(buf: *mut u16, max: usize, fmt: *const u16, tm: *const Tm, data: u64) -> usize {
    let Some(f) = wide_fmt(fmt) else { return invalid(EINVAL, 0) };
    strftime_common(buf, max, f, tm, data, enc_wide)
}

extern "win64" fn strftime(buf: *mut u8, max: usize, fmt: *const u8, tm: *const Tm) -> usize {
    _Strftime(buf, max, fmt, tm, 0)
}

extern "win64" fn wcsftime(buf: *mut u16, max: usize, fmt: *const u16, tm: *const Tm) -> usize {
    _Wcsftime(buf, max, fmt, tm, 0)
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        _time64,
        _time32,
        time,
        _gmtime64_s,
        _gmtime64,
        _mkgmtime64,
        _difftime64,
        _tzset,
        __timezone,
        __daylight,
        __dstbias,
        __tzname,
        _get_timezone,
        _get_daylight,
        _get_dstbias,
        _localtime64_s,
        _localtime64,
        _mktime64,
        _ftime64,
        _Getdays,
        _Getmonths,
        _W_Getdays,
        _W_Getmonths,
        _Gettnames,
        _W_Gettnames,
        _Strftime,
        _Wcsftime,
        strftime,
        wcsftime,
    ]
}

xmm_abi! {
    _difftime64 => _difftime64_soft [] "movq xmm0, rax";
}
