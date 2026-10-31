//! National language support for OSyx's one locale. OSyx has no locale
//! database: the system and user locale is English (United States), LCID
//! 0x0409, consistent with its US keyboard layout, and every code page is
//! UTF-8 (GetACP/GetOEMCP report 65001). Other locale names fail.
//!
//! String comparison and sort keys order by case-folded Unicode scalar
//! values, then lower case before upper case. That is a deterministic
//! linguistic-style order, not Windows' full sorting tables; flags that
//! need those tables (ignoring accents, digits as numbers, kana) fail with
//! ERROR_NOT_SUPPORTED. Character types come from Unicode properties.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{self, fail},
    path, teb,
};
use alloc::{string::String, vec::Vec};
use core::cmp::Ordering;

const ERROR_INVALID_FLAGS: u32 = 1004;
const LCID_EN_US: u32 = 0x0409;

/// The locale a name denotes: Some(true) for en-US, Some(false) for the
/// invariant locale.
pub(crate) fn locale(name: *const u16) -> Option<bool> {
    // SAFETY: NULL or a NUL-terminated name.
    match unsafe { path::wide_to_string(name) } {
        None => Some(true), // LOCALE_NAME_USER_DEFAULT
        Some(n) if n.is_empty() => Some(false),
        Some(n) if n.eq_ignore_ascii_case("en-US") || n.eq_ignore_ascii_case("en") || n == "!x-sys-default-locale" => Some(true),
        Some(_) => None,
    }
}

fn units(s: *const u16, n: i32) -> Option<Vec<u16>> {
    if s.is_null() {
        return None;
    }
    let len = if n < 0 {
        let mut i = 0;
        // SAFETY: a NUL-terminated string.
        while unsafe { *s.add(i) } != 0 {
            i += 1;
        }
        i
    } else {
        n as usize
    };
    // SAFETY: `len` units of the caller's string.
    Some(unsafe { core::slice::from_raw_parts(s, len) }.to_vec())
}

fn chars(u: &[u16]) -> Vec<char> {
    char::decode_utf16(u.iter().copied()).map(|c| c.unwrap_or('\u{FFFD}')).collect()
}

fn fold(c: char) -> char {
    let mut l = c.to_lowercase();
    match (l.next(), l.next()) {
        (Some(x), None) => x,
        _ => c,
    }
}

const NORM_IGNORECASE: u32 = 0x1;
const LINGUISTIC_IGNORECASE: u32 = 0x10;
const SORT_STRINGSORT: u32 = 0x1000;
const NORM_LINGUISTIC_CASING: u32 = 0x0800_0000;

fn compare(a: &[char], b: &[char], ignore_case: bool) -> Ordering {
    let primary = a.iter().map(|&c| fold(c)).cmp(b.iter().map(|&c| fold(c)));
    if primary != Ordering::Equal || ignore_case {
        return primary;
    }
    // Same letters: lower case sorts first (as on Windows: "a" < "A").
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return if x.is_lowercase() { Ordering::Less } else { Ordering::Greater };
        }
    }
    Ordering::Equal
}

#[allow(clippy::too_many_arguments)]
/// Compares two NUL-terminated strings in CompareString order.
/// [`compare_wide`] for NUL-terminated ANSI strings (UTF-8 with Latin-1
/// fallback, as everywhere in the runtime).
pub(crate) fn compare_ansi(a: *const u8, b: *const u8, ignore_case: bool) -> Ordering {
    let decode = |s: *const u8| -> Vec<char> {
        // SAFETY: the caller passes NUL-terminated strings.
        let bytes = unsafe { core::ffi::CStr::from_ptr(s.cast()) }.to_bytes();
        match core::str::from_utf8(bytes) {
            Ok(t) => t.chars().collect(),
            Err(_) => bytes.iter().map(|&b| b as char).collect(),
        }
    };
    compare(&decode(a), &decode(b), ignore_case)
}

pub(crate) fn compare_wide(a: *const u16, b: *const u16, ignore_case: bool) -> Ordering {
    let (Some(x), Some(y)) = (units(a, -1), units(b, -1)) else { return Ordering::Equal };
    compare(&chars(&x), &chars(&y), ignore_case)
}

extern "win64" fn CompareStringEx(
    name: *const u16,
    flags: u32,
    s1: *const u16,
    n1: i32,
    s2: *const u16,
    n2: i32,
    version: u64,
    reserved: u64,
    param: u64,
) -> i32 {
    if reserved != 0 || param != 0 || version != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if flags & !(NORM_IGNORECASE | LINGUISTIC_IGNORECASE | SORT_STRINGSORT | NORM_LINGUISTIC_CASING) != 0 {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    if locale(name).is_none() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let (Some(a), Some(b)) = (units(s1, n1), units(s2, n2)) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    match compare(&chars(&a), &chars(&b), flags & (NORM_IGNORECASE | LINGUISTIC_IGNORECASE) != 0) {
        Ordering::Less => 1,
        Ordering::Equal => 2,
        Ordering::Greater => 3,
    }
}

const LCMAP_LOWERCASE: u32 = 0x100;
const LCMAP_UPPERCASE: u32 = 0x200;
const LCMAP_SORTKEY: u32 = 0x400;
const LCMAP_LINGUISTIC_CASING: u32 = 0x0100_0000;

/// Sort key: case-folded scalars (3 bytes each, big endian), 0x01, one
/// case byte per character (0 lower/other, 1 upper), 0x00. memcmp of two
/// keys orders like `compare`.
fn sort_key(s: &[char], ignore_case: bool) -> Vec<u8> {
    let mut k = Vec::with_capacity(s.len() * 4 + 2);
    for &c in s {
        let f = fold(c) as u32 + 2; // above the separator bytes
        k.extend_from_slice(&[(f >> 16) as u8, (f >> 8) as u8, f as u8]);
    }
    k.push(1);
    if !ignore_case {
        k.extend(s.iter().map(|c| u8::from(c.is_uppercase()) + 2));
    }
    k.push(0);
    k
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn LCMapStringEx(
    name: *const u16,
    flags: u32,
    src: *const u16,
    n: i32,
    dst: *mut u16,
    cap: i32,
    version: u64,
    reserved: u64,
    param: u64,
) -> i32 {
    if reserved != 0 || param != 0 || version != 0 || n == 0 || cap < 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if locale(name).is_none() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(input) = units(src, n) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let text = chars(&input);
    let case_flags = flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE);
    if flags & LCMAP_SORTKEY != 0 {
        if flags & !(LCMAP_SORTKEY | NORM_IGNORECASE | LINGUISTIC_IGNORECASE | SORT_STRINGSORT) != 0 {
            return fail(ERROR_INVALID_FLAGS, 0);
        }
        let key = sort_key(&text, flags & (NORM_IGNORECASE | LINGUISTIC_IGNORECASE) != 0);
        if cap == 0 {
            return key.len() as i32;
        }
        if (cap as usize) < key.len() {
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        // SAFETY: for sort keys the destination is a byte buffer of `cap` bytes.
        unsafe { core::ptr::copy_nonoverlapping(key.as_ptr(), dst as *mut u8, key.len()) };
        return key.len() as i32;
    }
    if case_flags == (LCMAP_LOWERCASE | LCMAP_UPPERCASE) || flags & !(case_flags | LCMAP_LINGUISTIC_CASING) != 0 || case_flags == 0 {
        return fail(if flags & !(case_flags | LCMAP_LINGUISTIC_CASING) != 0 { ERROR_NOT_SUPPORTED } else { ERROR_INVALID_FLAGS }, 0);
    }
    // Simple (one-to-one) case mapping keeps the length, as Windows does.
    let mapped: String = text
        .iter()
        .map(|&c| {
            let mut m: Vec<char> = if case_flags == LCMAP_LOWERCASE { c.to_lowercase().collect() } else { c.to_uppercase().collect() };
            if m.len() == 1 && (m[0] as u32 > 0xffff) == (c as u32 > 0xffff) { m.pop().unwrap() } else { c }
        })
        .collect();
    // A NUL-terminated source (n < 0) maps its terminator too.
    let out: Vec<u16> = mapped.encode_utf16().chain((n < 0).then_some(0)).collect();
    if cap == 0 {
        return out.len() as i32;
    }
    if (cap as usize) < out.len() {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    // SAFETY: the caller's buffer of `cap` units.
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), dst, out.len()) };
    out.len() as i32
}

const CT_CTYPE1: u32 = 1;
const CT_CTYPE2: u32 = 2;
const CT_CTYPE3: u32 = 4;

fn ctype1(c: char) -> u16 {
    let mut t = 0x200; // C1_DEFINED
    if c.is_uppercase() {
        t |= 0x1;
    }
    if c.is_lowercase() {
        t |= 0x2;
    }
    if c.is_ascii_digit() {
        t |= 0x4;
    }
    if c.is_whitespace() {
        t |= 0x8;
    }
    if c.is_ascii_punctuation() || (!c.is_alphanumeric() && !c.is_whitespace() && !c.is_control() && c as u32 > 0x7f) {
        t |= 0x10;
    }
    if c.is_control() {
        t |= 0x20;
    }
    if c == ' ' || c == '\t' {
        t |= 0x40;
    }
    if c.is_ascii_hexdigit() {
        t |= 0x80;
    }
    if c.is_alphabetic() {
        t |= 0x100;
    }
    t
}

/// Bidirectional category, from the general properties available here.
fn ctype2(c: char) -> u16 {
    if c.is_ascii_digit() {
        3 // C2_EUROPENUMBER
    } else if c.is_alphabetic() {
        1 // C2_LEFTTORIGHT
    } else if c == '\n' || c == '\r' {
        8 // C2_BLOCKSEPARATOR
    } else if c == '\t' {
        9 // C2_SEGMENTSEPARATOR
    } else if c.is_whitespace() {
        10 // C2_WHITESPACE
    } else if c.is_control() {
        0 // C2_NOTAPPLICABLE
    } else {
        11 // C2_OTHERNEUTRAL
    }
}

fn ctype3(c: char) -> u16 {
    let mut t = 0;
    if c.is_alphabetic() {
        t |= 0x8000; // C3_ALPHA
    }
    if (c as u32) < 0x80 {
        t |= 0x40; // C3_HALFWIDTH
    }
    if !c.is_alphanumeric() && !c.is_whitespace() && !c.is_control() {
        t |= 0x8; // C3_SYMBOL
    }
    t
}

extern "win64" fn GetStringTypeW(kind: u32, src: *const u16, n: i32, out: *mut u16) -> i32 {
    let f: fn(char) -> u16 = match kind {
        CT_CTYPE1 => ctype1,
        CT_CTYPE2 => ctype2,
        CT_CTYPE3 => ctype3,
        _ => return fail(ERROR_INVALID_FLAGS, 0),
    };
    let (Some(u), false) = (units(src, n), out.is_null()) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    // One result per UTF-16 unit; a surrogate pair gets its character's type twice.
    let mut i = 0;
    for c in char::decode_utf16(u.iter().copied()) {
        let (t, width) = match c {
            Ok(c) => (f(c), c.len_utf16()),
            Err(_) => (0, 1),
        };
        for _ in 0..width {
            // SAFETY: the caller's array of one entry per unit.
            unsafe { *out.add(i) = t };
            i += 1;
        }
    }
    1
}

/// CPINFO for UTF-8, the only code page: MaxCharSize 4, default '?'.
extern "win64" fn GetCPInfo(cp: u32, out: *mut u8) -> i32 {
    if !matches!(cp, 0 | 1 | 3 | 65001) || out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's 20-byte CPINFO.
    unsafe {
        core::ptr::write_bytes(out, 0, 20);
        teb::put(out as u64, 0, 4u32);
        teb::put(out as u64, 4, b'?');
    }
    1
}

const LOCALE_RETURN_NUMBER: u32 = 0x2000_0000;
const LOCALE_NOUSEROVERRIDE: u32 = 0x8000_0000;

/// en-US locale data (the invariant locale differs only in its names).
fn locale_info(lctype: u32, en_us: bool) -> Option<String> {
    const DAYS: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    const MONTHS: [&str; 12] =
        ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    let s = match lctype {
        0x01 => if en_us { "0409" } else { "007f" },               // LOCALE_ILANGUAGE
        0x02 | 0x72 | 0x73 => if en_us { "English (United States)" } else { "Invariant Language (Invariant Country)" },
        0x03 => if en_us { "ENU" } else { "IVL" },                  // LOCALE_SABBREVLANGNAME
        0x04 | 0x6f | 0x1001 => if en_us { "English" } else { "Invariant Language" },
        0x06 | 0x1002 | 0x08 => if en_us { "United States" } else { "Invariant Country" },
        0x0B => "65001",                                            // LOCALE_IDEFAULTCODEPAGE
        0x1004 => "65001",                                          // LOCALE_IDEFAULTANSICODEPAGE
        0x0D => if en_us { "1" } else { "0" },                      // LOCALE_IMEASURE
        0x0E => ".",
        0x0F => ",",
        0x10 => "3;0",
        0x11 => "2",
        0x12 => "1",
        0x13 => "0123456789",
        0x14 => if en_us { "$" } else { "\u{a4}" },
        0x15 => if en_us { "USD" } else { "XDR" },
        0x16 => ".",
        0x17 => ",",
        0x18 => "3;0",
        0x19 => "2",
        0x1B => "0",
        0x1C => "0",
        0x1D => "/",
        0x1E => ":",
        0x1F => if en_us { "M/d/yyyy" } else { "MM/dd/yyyy" },
        0x20 => if en_us { "dddd, MMMM d, yyyy" } else { "dddd, dd MMMM yyyy" },
        0x1003 => if en_us { "h:mm:ss tt" } else { "HH:mm:ss" },
        0x1009 => "1",                                              // LOCALE_ICALENDARTYPE: Gregorian
        0x100C => "6",                                              // LOCALE_IFIRSTDAYOFWEEK: Sunday
        0x1010 => "1",
        0x28 => "AM",
        0x29 => "PM",
        0x2A..=0x30 => DAYS[(lctype - 0x2A) as usize],
        0x31..=0x37 => &DAYS[(lctype - 0x31) as usize][..3],
        0x38..=0x43 => MONTHS[(lctype - 0x38) as usize],
        0x44..=0x4F => &MONTHS[(lctype - 0x44) as usize][..3],
        0x50 => "",
        0x51 => "-",
        0x59 => if en_us { "en" } else { "iv" },                    // LOCALE_SISO639LANGNAME
        0x5A => if en_us { "US" } else { "IV" },                    // LOCALE_SISO3166CTRYNAME
        0x5C => if en_us { "en-US" } else { "" },                   // LOCALE_SNAME
        0x69 => "NaN",
        0x6A => "Infinity",
        0x6B => "-Infinity",
        0x6D => if en_us { "en" } else { "" },                      // LOCALE_SPARENT
        _ => return None,
    };
    Some(String::from(s))
}

pub(crate) extern "win64" fn GetLocaleInfoEx(name: *const u16, lctype: u32, buf: *mut u16, size: i32) -> i32 {
    let Some(en_us) = locale(name) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let kind = lctype & !(LOCALE_RETURN_NUMBER | LOCALE_NOUSEROVERRIDE | 0x0400_0000);
    let Some(v) = locale_info(kind, en_us) else { return fail(ERROR_INVALID_FLAGS, 0) };
    if lctype & LOCALE_RETURN_NUMBER != 0 {
        let radix = if kind == 0x01 { 16 } else { 10 };
        let Ok(n) = u32::from_str_radix(&v, radix) else { return fail(ERROR_INVALID_FLAGS, 0) };
        if size == 0 {
            return 2;
        }
        if size < 2 || buf.is_null() {
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        // SAFETY: two units of the caller's buffer hold the DWORD.
        unsafe { core::ptr::write_unaligned(buf as *mut u32, n) };
        return 2;
    }
    let r = kernel32::out_w(&v, buf, size as u32);
    if size == 0 {
        return r as i32;
    }
    if r >= size as u32 {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    r as i32 + 1
}

extern "win64" fn GetUserDefaultLangID() -> u16 {
    LCID_EN_US as u16
}

extern "win64" fn GetUserDefaultUILanguage() -> u16 {
    LCID_EN_US as u16
}

extern "win64" fn GetUserDefaultLCID() -> u32 {
    LCID_EN_US
}

extern "win64" fn GetUserDefaultLocaleName(buf: *mut u16, size: i32) -> i32 {
    let r = kernel32::out_w("en-US", buf, size as u32);
    if r >= size as u32 {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    r as i32 + 1
}

/// LOCALE_ENUMPROCEX(name, flags, param) → continue?
extern "win64" fn EnumSystemLocalesEx(proc_: u64, flags: u32, param: u64, reserved: u64) -> i32 {
    if proc_ == 0 || reserved != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    type Proc = extern "win64" fn(*const u16, u32, u64) -> i32;
    // SAFETY: the caller's callback.
    let f: Proc = unsafe { core::mem::transmute(proc_ as usize) };
    let all = flags & 0x30 == 0;
    let mut list: Vec<(&str, u32)> = Vec::new();
    if all || flags & 0x10 != 0 {
        list.push(("en", 0x10)); // LOCALE_NEUTRALDATA
    }
    if all || flags & 0x20 != 0 {
        list.push(("en-US", 0x21)); // LOCALE_SPECIFICDATA | LOCALE_WINDOWS
    }
    for (name, kind) in list {
        let w: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        if f(w.as_ptr(), kind, param) == 0 {
            break;
        }
    }
    1
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        CompareStringEx,
        LCMapStringEx,
        GetStringTypeW,
        GetCPInfo,
        GetLocaleInfoEx,
        GetUserDefaultLangID,
        GetUserDefaultUILanguage,
        GetUserDefaultLCID,
        GetUserDefaultLocaleName,
        EnumSystemLocalesEx,
    ]
}
