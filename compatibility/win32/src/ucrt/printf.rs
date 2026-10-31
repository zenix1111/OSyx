//! The printf family (`__stdio_common_v*printf*`): one formatter for
//! narrow and wide output honouring the UCRT option bits — legacy and
//! standard snprintf termination, legacy wide specifiers (%s/%c in wide
//! functions), legacy three-digit exponents and standard (round half to
//! even) or legacy (round half away from zero) decimal rounding — with
//! the UCRT's spellings (`-nan(ind)`, `nan(snan)`, `%p` as 16 hex
//! digits), `%Z` counted strings and `%n` only after
//! `_set_printf_count_output`. Floating-point values are converted from
//! their exact decimal expansion, so every digit printed is correct.

use super::locale;
use super::stdio::{self, File};
use super::*;
use alloc::string::String;
use core::sync::atomic::AtomicI32;

pub const LEGACY_VSPRINTF_NULL_TERMINATION: u64 = 1;
pub const STANDARD_SNPRINTF_BEHAVIOR: u64 = 2;
pub const LEGACY_WIDE_SPECIFIERS: u64 = 4;
pub const LEGACY_THREE_DIGIT_EXPONENTS: u64 = 16;
pub const STANDARD_ROUNDING: u64 = 32;

static COUNT_OUTPUT: AtomicI32 = AtomicI32::new(0);

extern "win64" fn _set_printf_count_output(on: i32) -> i32 {
    COUNT_OUTPUT.swap((on != 0) as i32, Ordering::SeqCst)
}

extern "win64" fn _get_printf_count_output() -> i32 {
    COUNT_OUTPUT.load(Ordering::SeqCst)
}

/// A format or output character: u8 (narrow) or u16 (wide).
pub trait Ch: Copy + PartialEq + Default + 'static {
    const WIDE: bool;
    fn of(c: u8) -> Self;
    /// A UTF-16 unit as an output unit (wide output only).
    fn unit(u: u16) -> Self;
    fn code(self) -> u32;
}

impl Ch for u8 {
    const WIDE: bool = false;
    fn of(c: u8) -> u8 {
        c
    }
    fn unit(u: u16) -> u8 {
        u as u8
    }
    fn code(self) -> u32 {
        self as u32
    }
}

impl Ch for u16 {
    const WIDE: bool = true;
    fn of(c: u8) -> u16 {
        c as u16
    }
    fn unit(u: u16) -> u16 {
        u
    }
    fn code(self) -> u32 {
        self as u32
    }
}

/// Windows x64 uses 8-byte slots; i386 uses 4-byte stack slots.
struct Args { ptr: *const u8, pe32: bool }

impl Args {
    fn next(&mut self) -> u64 {
        // SAFETY: the caller's va_list holds an argument for every
        // conversion of its format (C contract).
        let v = unsafe { if self.pe32 { core::ptr::read_unaligned(self.ptr.cast::<u32>()) as u64 } else { core::ptr::read_unaligned(self.ptr.cast::<u64>()) } };
        // SAFETY: as above.
        self.ptr = unsafe { self.ptr.add(if self.pe32 { 4 } else { 8 }) };
        v
    }

    fn next64(&mut self) -> u64 {
        let low = self.next();
        if self.pe32 { low | (self.next() << 32) } else { low }
    }

    fn float(&mut self) -> f64 {
        f64::from_bits(self.next64())
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Size {
    None,
    Char,  // hh
    Short, // h
    Long,  // l (32-bit), also w
    LongLong,
    Ptr, // I, z, t, j
    I32,
    LongDouble, // L
    Wide,       // w
}

#[derive(Default)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alt: bool,
    zero: bool,
    width: usize,
    prec: Option<usize>,
}

/// Why formatting failed: errno for the caller.
pub struct Failed(pub i32);

struct Out<C: Ch> {
    v: Vec<C>,
}

impl<C: Ch> Out<C> {
    fn ascii(&mut self, s: &[u8]) {
        self.v.extend(s.iter().map(|&b| C::of(b)));
    }

    fn pad(&mut self, c: u8, n: usize) {
        self.v.extend(core::iter::repeat_n(C::of(c), n));
    }

    /// Emits `body` (already in output units) with `prefix` (sign and
    /// radix prefix) and the field width.
    fn field(&mut self, sp: &Spec, prefix: &[u8], body: &[C], zero_ok: bool) {
        let len = prefix.len() + body.len();
        let fill = sp.width.saturating_sub(len);
        if sp.left {
            self.ascii(prefix);
            self.v.extend_from_slice(body);
            self.pad(b' ', fill);
        } else if sp.zero && zero_ok {
            self.ascii(prefix);
            self.pad(b'0', fill);
            self.v.extend_from_slice(body);
        } else {
            self.pad(b' ', fill);
            self.ascii(prefix);
            self.v.extend_from_slice(body);
        }
    }
}

fn units<C: Ch>(s: &[u8]) -> Vec<C> {
    s.iter().map(|&b| C::of(b)).collect()
}

// ---- strings ---------------------------------------------------------------------------

/// Narrow text for narrow output, or widened for wide output (through the
/// locale's code page). `max`: precision in output units.
fn narrow_text<C: Ch>(bytes: &[u8], max: Option<usize>) -> Result<Vec<C>, Failed> {
    if !C::WIDE {
        let n = max.map_or(bytes.len(), |m| m.min(bytes.len()));
        return Ok(units(&bytes[..n]));
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() && max.is_none_or(|m| out.len() < m) {
        let Some((cp, n)) = locale::mb_char(&bytes[i..]) else { return Err(Failed(EILSEQ)) };
        let mut tmp = [0u16; 2];
        let enc = char::from_u32(cp).map(|c| c.encode_utf16(&mut tmp).len()).unwrap_or(0);
        if enc == 0 {
            return Err(Failed(EILSEQ));
        }
        if max.is_some_and(|m| out.len() + enc > m) {
            break;
        }
        out.extend(tmp[..enc].iter().map(|&u| C::unit(u)));
        i += n.max(1);
    }
    Ok(out)
}

/// Wide text for wide output, or converted to multibyte for narrow
/// output, stopping before a character that would exceed `max` units.
fn wide_text<C: Ch>(w: &[u16], max: Option<usize>) -> Result<Vec<C>, Failed> {
    if C::WIDE {
        let n = max.map_or(w.len(), |m| m.min(w.len()));
        return Ok(w[..n].iter().map(|&u| C::unit(u)).collect());
    }
    let mut out: Vec<C> = Vec::new();
    let mut i = 0;
    while i < w.len() {
        let n = if (0xD800..0xDC00).contains(&w[i]) && i + 1 < w.len() { 2 } else { 1 };
        let mut mb = Vec::new();
        locale::wide_to_mb(&w[i..i + n], &mut mb).map_err(|_| Failed(EILSEQ))?;
        if max.is_some_and(|m| out.len() + mb.len() > m) {
            break;
        }
        out.extend(mb.iter().map(|&b| C::of(b)));
        i += n;
    }
    Ok(out)
}

fn cstr_n(p: *const u8, max: Option<usize>) -> &'static [u8] {
    let mut n = 0;
    // SAFETY: a NUL-terminated string (or readable up to the precision).
    while max.is_none_or(|m| n < m) && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `n` bytes were just read.
    unsafe { core::slice::from_raw_parts(p, n) }
}

fn wstr_n(p: *const u16, max: Option<usize>) -> &'static [u16] {
    let mut n = 0;
    // SAFETY: as above, for UTF-16. For narrow output the precision
    // counts bytes, so wide input is bounded only by its terminator.
    while max.is_none_or(|m| n < m) && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `n` units were just read.
    unsafe { core::slice::from_raw_parts(p, n) }
}

// ---- integers ----------------------------------------------------------------------------

fn int_body(mut v: u64, radix: u64, upper: bool, prec: Option<usize>) -> Vec<u8> {
    let mut d = Vec::new();
    while v != 0 {
        let x = (v % radix) as u8;
        d.push(match x {
            0..=9 => b'0' + x,
            _ if upper => b'A' + x - 10,
            _ => b'a' + x - 10,
        });
        v /= radix;
    }
    let min = prec.unwrap_or(1);
    while d.len() < min {
        d.push(b'0');
    }
    d.reverse();
    d
}

// ---- floating point ----------------------------------------------------------------------

// TEMP: how often printf does an exact (767-digit) float conversion.
static EXACT_CALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The exact decimal expansion of |x| (finite, nonzero): digits d1 d2 ...
/// and E with |x| = d1.d2d3... * 10^E.
fn exact(x: f64) -> (Vec<u8>, i32) {
    let c = EXACT_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
    if c.is_multiple_of(2_000) {
        os_std::eprintln!("winrun: exct n={c} x={x:e} tid={}", os_sys::gettid());
    }
    // 767 fractional digits hold every double exactly.
    let s = alloc::format!("{:.767e}", if x < 0.0 { -x } else { x });
    let (m, e) = s.split_once('e').unwrap_or((&s, "0"));
    let mut digits: Vec<u8> = m.bytes().filter(|b| b.is_ascii_digit()).collect();
    while digits.len() > 1 && digits.last() == Some(&b'0') {
        digits.pop();
    }
    (digits, e.parse().unwrap_or(0))
}

/// Rounds `digits` (value d1.d2... * 10^e) to `n` digits (n may be <= 0:
/// rounding to a position left of the first digit). Returns the kept
/// digits (padded with zeros to n) and the possibly bumped exponent.
fn round_digits(digits: &[u8], e: i32, n: i64, standard: bool) -> (Vec<u8>, i32) {
    if n < 0 {
        return (Vec::new(), e);
    }
    let n = n as usize;
    if n >= digits.len() {
        let mut d = digits.to_vec();
        d.resize(n, b'0');
        return (d, e);
    }
    let first = digits[n];
    let rest_zero = digits[n + 1..].iter().all(|&c| c == b'0');
    let prev_odd = n > 0 && (digits[n - 1] - b'0') % 2 == 1;
    let up = if standard { first > b'5' || (first == b'5' && (!rest_zero || prev_odd)) } else { first >= b'5' };
    let mut d = digits[..n].to_vec();
    if !up {
        return (d, e);
    }
    let mut i = d.len();
    loop {
        if i == 0 {
            d.insert(0, b'1');
            d.truncate(n.max(1));
            if n == 0 {
                d.clear();
                d.push(b'1');
            }
            return (d, e + 1);
        }
        i -= 1;
        if d[i] == b'9' {
            d[i] = b'0';
        } else {
            d[i] += 1;
            return (d, e);
        }
    }
}

struct FloatFmt {
    upper: bool,
    standard: bool,
    three_digit: bool,
}

fn exponent_text(e: i32, upper: bool, three: bool, out: &mut Vec<u8>) {
    out.push(if upper { b'E' } else { b'e' });
    out.push(if e < 0 { b'-' } else { b'+' });
    let s = alloc::format!("{:0w$}", e.unsigned_abs(), w = if three { 3 } else { 2 });
    out.extend_from_slice(s.as_bytes());
}

/// %e body (no sign).
fn fmt_e(x: f64, prec: usize, alt: bool, f: &FloatFmt) -> Vec<u8> {
    let (digits, e) = if x == 0.0 { (Vec::new(), 0) } else { exact(x) };
    let (d, e) = if digits.is_empty() {
        (alloc::vec![b'0'; prec + 1], 0)
    } else {
        round_digits(&digits, e, prec as i64 + 1, f.standard)
    };
    let mut out = alloc::vec![d[0]];
    if prec > 0 || alt {
        out.push(b'.');
    }
    out.extend_from_slice(&d[1..]);
    exponent_text(e, f.upper, f.three_digit, &mut out);
    out
}

/// %f body (no sign).
fn fmt_f(x: f64, prec: usize, alt: bool, f: &FloatFmt) -> Vec<u8> {
    let mut out = Vec::new();
    let (int, frac) = if x == 0.0 {
        (alloc::vec![b'0'], alloc::vec![b'0'; prec])
    } else {
        let (digits, e) = exact(x);
        // Digits up to 10^-prec: e + 1 + prec of them.
        let (d, e) = round_digits(&digits, e, e as i64 + 1 + prec as i64, f.standard);
        if d.is_empty() {
            (alloc::vec![b'0'], alloc::vec![b'0'; prec])
        } else if e < 0 {
            // 0.000ddd
            let mut fr = alloc::vec![b'0'; (-e - 1) as usize];
            fr.extend_from_slice(&d);
            fr.resize(prec, b'0');
            (alloc::vec![b'0'], fr)
        } else {
            let k = e as usize + 1;
            let mut all = d;
            if all.len() < k + prec {
                all.resize(k + prec, b'0');
            }
            (all[..k].to_vec(), all[k..k + prec].to_vec())
        }
    };
    out.extend_from_slice(&int);
    if prec > 0 || alt {
        out.push(b'.');
    }
    out.extend_from_slice(&frac);
    out
}

/// %g body (no sign).
fn fmt_g(x: f64, prec: usize, alt: bool, f: &FloatFmt) -> Vec<u8> {
    let p = if prec == 0 { 1 } else { prec };
    let xexp = if x == 0.0 {
        0
    } else {
        let (digits, e) = exact(x);
        round_digits(&digits, e, p as i64, f.standard).1
    };
    let mut body = if (xexp as i64) < p as i64 && xexp >= -4 {
        fmt_f(x, (p as i64 - 1 - xexp as i64) as usize, alt, f)
    } else {
        fmt_e(x, p - 1, alt, f)
    };
    if !alt {
        // Strip trailing zeros of the fraction (and a bare point).
        let epos = body.iter().position(|&c| c == b'e' || c == b'E').unwrap_or(body.len());
        let (mant, exp) = body.split_at(epos);
        let mut m = mant.to_vec();
        if m.contains(&b'.') {
            while m.last() == Some(&b'0') {
                m.pop();
            }
            if m.last() == Some(&b'.') {
                m.pop();
            }
        }
        m.extend_from_slice(exp);
        body = m;
    }
    body
}

/// %a body (no sign): hexadecimal significand and binary exponent.
fn fmt_a(x: f64, prec: Option<usize>, alt: bool, f: &FloatFmt) -> Vec<u8> {
    let bits = x.to_bits();
    let bexp = ((bits >> 52) & 0x7FF) as i32;
    let mut mant = bits & ((1u64 << 52) - 1);
    let (mut lead, e) = if bexp == 0 {
        (0u64, if mant == 0 { 0 } else { -1022 })
    } else {
        (1u64, bexp - 1023)
    };
    let p = prec.unwrap_or(13);
    if p < 13 {
        let shift = 4 * (13 - p) as u32;
        let rem = mant & ((1u64 << shift) - 1);
        let half = 1u64 << (shift - 1);
        mant >>= shift;
        let odd = mant & 1 == 1;
        let up = if f.standard { rem > half || (rem == half && odd) } else { rem >= half };
        if up {
            mant += 1;
            if mant >> (4 * p as u32) != 0 {
                mant &= (1u64 << (4 * p as u32)) - 1;
                lead += 1;
            }
        }
    }
    let hex = |v: u64| -> u8 {
        let v = v as u8;
        if v < 10 {
            b'0' + v
        } else if f.upper {
            b'A' + v - 10
        } else {
            b'a' + v - 10
        }
    };
    let mut out = alloc::vec![b'0', if f.upper { b'X' } else { b'x' }, hex(lead)];
    if p > 0 || alt {
        out.push(b'.');
    }
    let shown = p.min(13);
    for i in (0..shown).rev() {
        out.push(hex((mant >> (4 * i)) & 0xF));
    }
    out.extend(core::iter::repeat_n(b'0', p - shown));
    out.push(if f.upper { b'P' } else { b'p' });
    out.push(if e < 0 { b'-' } else { b'+' });
    out.extend_from_slice(alloc::format!("{}", e.unsigned_abs()).as_bytes());
    out
}

/// inf / nan spellings of the UCRT.
fn special(x: f64, upper: bool) -> (bool, &'static [u8]) {
    let neg = x.is_sign_negative();
    if x.is_infinite() {
        return (neg, if upper { b"INF" } else { b"inf" });
    }
    let bits = x.to_bits();
    let quiet = bits & (1u64 << 51) != 0;
    if !quiet {
        return (neg, if upper { b"NAN(SNAN)" } else { b"nan(snan)" });
    }
    if bits == 0xFFF8_0000_0000_0000 {
        return (true, if upper { b"NAN(IND)" } else { b"nan(ind)" });
    }
    (neg, if upper { b"NAN" } else { b"nan" })
}

// ---- the formatter ---------------------------------------------------------------------------

/// Formats `fmt` with `args`. `secure`: the `_s` validation (unknown
/// conversions and %n are invalid parameters).
fn format<C: Ch>(opts: u64, fmt: &[C], args: *const u64, secure: bool, pe32: bool) -> Result<Vec<C>, Failed> {
    let mut out = Out { v: Vec::new() };
    let mut a = Args { ptr: args.cast(), pe32 };
    let ffmt = |upper: bool| FloatFmt {
        upper,
        standard: opts & STANDARD_ROUNDING != 0,
        three_digit: opts & LEGACY_THREE_DIGIT_EXPONENTS != 0,
    };
    let legacy_wide = opts & LEGACY_WIDE_SPECIFIERS != 0;
    let invalid = || -> Failed {
        set_errno(EINVAL);
        invalid_parameter();
        Failed(EINVAL)
    };
    let mut i = 0;
    let at = |i: usize| fmt.get(i).map_or(0, |c| c.code());
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c.code() != b'%' as u32 {
            out.v.push(c);
            continue;
        }
        if i >= fmt.len() {
            break; // a lone % at the end prints nothing
        }
        let mut sp = Spec::default();
        // Flags.
        loop {
            match at(i) {
                0x2D => sp.left = true,
                0x2B => sp.plus = true,
                0x20 => sp.space = true,
                0x23 => sp.alt = true,
                0x30 => sp.zero = true,
                _ => break,
            }
            i += 1;
        }
        // Width.
        if at(i) == b'*' as u32 {
            let w = a.next() as i32;
            if w < 0 {
                sp.left = true;
            }
            sp.width = w.unsigned_abs() as usize;
            i += 1;
        } else {
            while (0x30..=0x39).contains(&at(i)) {
                sp.width = sp.width.saturating_mul(10).saturating_add((at(i) - 0x30) as usize);
                i += 1;
            }
        }
        // Precision.
        if at(i) == b'.' as u32 {
            i += 1;
            if at(i) == b'*' as u32 {
                let p = a.next() as i32;
                sp.prec = if p < 0 { None } else { Some(p as usize) };
                i += 1;
            } else {
                let mut p = 0usize;
                while (0x30..=0x39).contains(&at(i)) {
                    p = p.saturating_mul(10).saturating_add((at(i) - 0x30) as usize);
                    i += 1;
                }
                sp.prec = Some(p);
            }
        }
        // Size.
        let mut size = Size::None;
        let ch = |i: usize| char::from_u32(at(i)).unwrap_or('\0');
        match ch(i) {
            'h' if ch(i + 1) == 'h' => {
                size = Size::Char;
                i += 2;
            }
            'h' => {
                size = Size::Short;
                i += 1;
            }
            'l' if ch(i + 1) == 'l' => {
                size = Size::LongLong;
                i += 2;
            }
            'l' => {
                size = Size::Long;
                i += 1;
            }
            'w' => {
                size = Size::Wide;
                i += 1;
            }
            'L' => {
                size = Size::LongDouble;
                i += 1;
            }
            'z' | 't' | 'j' => {
                size = if ch(i) == 'j' { Size::LongLong } else { Size::Ptr };
                i += 1;
            }
            'I' if ch(i + 1) == '6' && ch(i + 2) == '4' => {
                size = Size::LongLong;
                i += 3;
            }
            'I' if ch(i + 1) == '3' && ch(i + 2) == '2' => {
                size = Size::I32;
                i += 3;
            }
            'I' => {
                size = Size::Ptr;
                i += 1;
            }
            _ => {}
        }
        if i >= fmt.len() {
            break;
        }
        let ty = ch(i);
        i += 1;
        if size != Size::None && matches!(ty, 'h' | 'l' | 'w' | 'L' | 'z' | 't' | 'j' | 'I') {
            return Err(invalid());
        }
        let is_int_size = |s: Size| !matches!(s, Size::LongDouble | Size::Wide);
        match ty {
            'd' | 'i' | 'o' | 'u' | 'x' | 'X' | 'p' => {
                if ty != 'p' && !is_int_size(size) {
                    return Err(invalid());
                }
                let raw = if size == Size::LongLong { a.next64() } else { a.next() };
                let signed = matches!(ty, 'd' | 'i');
                let (neg, mag) = if ty == 'p' {
                    (false, raw)
                } else {
                    let v: i128 = match (size, signed) {
                        (Size::Char, true) => raw as i8 as i128,
                        (Size::Char, false) => raw as u8 as i128,
                        (Size::Short, true) => raw as i16 as i128,
                        (Size::Short, false) => raw as u16 as i128,
                        (Size::Ptr, true) if pe32 => raw as i32 as i128,
                        (Size::LongLong | Size::Ptr, true) => raw as i64 as i128,
                        (Size::LongLong | Size::Ptr, false) => raw as i128,
                        (_, true) => raw as i32 as i128,
                        (_, false) => raw as u32 as i128,
                    };
                    (v < 0, v.unsigned_abs() as u64)
                };
                let (radix, upper) = match ty {
                    'o' => (8, false),
                    'x' => (16, false),
                    'X' | 'p' => (16, true),
                    _ => (10, false),
                };
                let ptr_digits = if pe32 { 8 } else { 16 };
                let prec = if ty == 'p' { Some(sp.prec.unwrap_or(ptr_digits).max(ptr_digits)) } else { sp.prec };
                let mut body = if mag == 0 && prec == Some(0) { Vec::new() } else { int_body(mag, radix, upper, prec) };
                let mut prefix: Vec<u8> = Vec::new();
                if signed {
                    if neg {
                        prefix.push(b'-');
                    } else if sp.plus {
                        prefix.push(b'+');
                    } else if sp.space {
                        prefix.push(b' ');
                    }
                }
                if sp.alt {
                    match ty {
                        'o' if body.first() != Some(&b'0') => body.insert(0, b'0'),
                        'x' if mag != 0 => prefix.extend_from_slice(b"0x"),
                        'X' if mag != 0 => prefix.extend_from_slice(b"0X"),
                        _ => {}
                    }
                }
                let zero_ok = sp.prec.is_none() || ty == 'p';
                out.field(&sp, &prefix, &units::<C>(&body), zero_ok);
            }
            'c' | 'C' => {
                // %c is the function's own width (wide only with the
                // legacy specifiers), %C the other one; h and l/w force.
                let wide_arg = match size {
                    Size::Short => false,
                    Size::Long | Size::Wide => true,
                    _ if ty == 'c' => C::WIDE && legacy_wide,
                    _ => !(C::WIDE && legacy_wide),
                };
                let raw = a.next();
                let body: Vec<C> = if wide_arg {
                    match wide_text::<C>(&[raw as u16], None) {
                        Ok(b) => b,
                        Err(Failed(e)) => {
                            set_errno(e);
                            Vec::new()
                        }
                    }
                } else {
                    narrow_text::<C>(&[raw as u8], None).unwrap_or_else(|Failed(e)| {
                        set_errno(e);
                        Vec::new()
                    })
                };
                out.field(&sp, b"", &body, true);
            }
            's' | 'S' => {
                let wide_arg = match size {
                    Size::Short => false,
                    Size::Long | Size::Wide => true,
                    _ => {
                        if ty == 's' {
                            C::WIDE && legacy_wide
                        } else {
                            !(C::WIDE && legacy_wide)
                        }
                    }
                };
                let p = a.next();
                let body: Vec<C> = if p == 0 {
                    let n = sp.prec.map_or(6, |m| m.min(6));
                    units(&b"(null)"[..n])
                } else if wide_arg {
                    let w = wstr_n(p as *const u16, if C::WIDE { sp.prec } else { None });
                    wide_text::<C>(w, sp.prec)?
                } else {
                    let s = cstr_n(p as *const u8, if C::WIDE { None } else { sp.prec });
                    narrow_text::<C>(s, sp.prec)?
                };
                out.field(&sp, b"", &body, true);
            }
            'Z' => {
                let wide_arg = matches!(size, Size::Long | Size::Wide);
                let p = a.next();
                // ANSI_STRING / UNICODE_STRING: Length (bytes), Maximum, Buffer.
                // SAFETY: the caller's counted-string structure.
                let (len, buf) = if p == 0 { (0, 0) } else { unsafe {
                    (*(p as *const u16) as usize, if pe32 { *((p + 4) as *const u32) as u64 } else { *((p + 8) as *const u64) })
                } };
                let body: Vec<C> = if buf == 0 {
                    units(b"(null)")
                } else if wide_arg {
                    // SAFETY: `len` bytes of UTF-16 at `buf`.
                    let w = unsafe { core::slice::from_raw_parts(buf as *const u16, len / 2) };
                    wide_text::<C>(w, sp.prec)?
                } else {
                    // SAFETY: `len` bytes at `buf`.
                    let s = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
                    narrow_text::<C>(s, sp.prec)?
                };
                out.field(&sp, b"", &body, true);
            }
            'e' | 'E' | 'f' | 'F' | 'g' | 'G' | 'a' | 'A' => {
                if matches!(size, Size::Char | Size::Short | Size::LongLong | Size::Ptr | Size::I32 | Size::Wide) {
                    return Err(invalid());
                }
                let c = EXACT_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
                if c.is_multiple_of(2_000) {
                    os_std::eprintln!("winrun: pfct n={c} conv={} tid={}", { ty }, os_sys::gettid());
                }
                let x = a.float();
                let upper = ty.is_ascii_uppercase();
                let mut prefix: Vec<u8> = Vec::new();
                if !x.is_finite() {
                    let (neg, text) = special(x, upper);
                    if neg {
                        prefix.push(b'-');
                    } else if sp.plus {
                        prefix.push(b'+');
                    } else if sp.space {
                        prefix.push(b' ');
                    }
                    out.field(&sp, &prefix, &units::<C>(text), false);
                    continue;
                }
                if x.is_sign_negative() {
                    prefix.push(b'-');
                } else if sp.plus {
                    prefix.push(b'+');
                } else if sp.space {
                    prefix.push(b' ');
                }
                let f = ffmt(upper);
                let body = match ty {
                    'e' | 'E' => fmt_e(x, sp.prec.unwrap_or(6), sp.alt, &f),
                    'f' | 'F' => fmt_f(x, sp.prec.unwrap_or(6), sp.alt, &f),
                    'g' | 'G' => fmt_g(x, sp.prec.unwrap_or(6), sp.alt, &f),
                    _ => {
                        let b = fmt_a(x, sp.prec, sp.alt, &f);
                        // The "0x" belongs before zero padding.
                        prefix.extend_from_slice(&b[..2]);
                        b[2..].to_vec()
                    }
                };
                out.field(&sp, &prefix, &units::<C>(&body), true);
            }
            'n' => {
                let p = a.next();
                if secure || COUNT_OUTPUT.load(Ordering::SeqCst) == 0 {
                    return Err(invalid());
                }
                let n = out.v.len();
                // SAFETY: the caller's pointer of the size the modifier names.
                unsafe {
                    match size {
                        Size::Char => *(p as *mut i8) = n as i8,
                        Size::Short => *(p as *mut i16) = n as i16,
                        Size::Ptr if pe32 => *(p as *mut i32) = n as i32,
                        Size::LongLong | Size::Ptr => *(p as *mut i64) = n as i64,
                        _ => *(p as *mut i32) = n as i32,
                    }
                }
            }
            _ => {
                if secure {
                    return Err(invalid());
                }
                // Not a conversion: the character itself is printed.
                out.v.push(fmt[i - 1]);
            }
        }
    }
    Ok(out.v)
}

/// Reads a NUL-terminated format.
fn fmt_units<C: Ch>(p: *const C) -> &'static [C] {
    let mut n = 0;
    // SAFETY: a NUL-terminated format string.
    while unsafe { *p.add(n) } != C::default() {
        n += 1;
    }
    // SAFETY: `n` units were just read.
    unsafe { core::slice::from_raw_parts(p, n) }
}

// ---- string output -----------------------------------------------------------------------------

fn put<C: Ch>(buf: *mut C, i: usize, c: C) {
    // SAFETY: callers stay within the buffer's `count` units.
    unsafe { *buf.add(i) = c };
}

fn copy_out<C: Ch>(buf: *mut C, s: &[C], n: usize) {
    // SAFETY: callers pass n <= the buffer's size.
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), buf, n) };
}

/// `__stdio_common_vsprintf` / `vswprintf`.
fn vsprintf<C: Ch>(opts: u64, buf: *mut C, count: usize, fmt: *const C, args: *const u64) -> i32 {
    validate!(!fmt.is_null(), EINVAL, -1);
    validate!(count == 0 || !buf.is_null(), EINVAL, -1);
    let s = match format(opts, fmt_units(fmt), args, false, false) {
        Ok(s) => s,
        Err(Failed(e)) => {
            set_errno(e);
            if count > 0 {
                put(buf, 0, C::default());
            }
            return -1;
        }
    };
    let r = s.len();
    if buf.is_null() {
        return r as i32;
    }
    if opts & LEGACY_VSPRINTF_NULL_TERMINATION != 0 {
        let n = r.min(count);
        copy_out(buf, &s, n);
        if r < count {
            put(buf, r, C::default());
        }
        return if r > count { -1 } else { r as i32 };
    }
    if opts & STANDARD_SNPRINTF_BEHAVIOR != 0 {
        if count == 0 {
            return r as i32;
        }
        let n = r.min(count - 1);
        copy_out(buf, &s, n);
        put(buf, n, C::default());
        return r as i32;
    }
    if count == 0 {
        return -1;
    }
    if r >= count {
        copy_out(buf, &s, count - 1);
        put(buf, count - 1, C::default());
        return -2;
    }
    copy_out(buf, &s, r);
    put(buf, r, C::default());
    r as i32
}

/// `__stdio_common_vsprintf_s` / `vswprintf_s`.
fn vsprintf_s<C: Ch>(opts: u64, buf: *mut C, count: usize, fmt: *const C, args: *const u64) -> i32 {
    validate!(!fmt.is_null(), EINVAL, -1);
    validate!(!buf.is_null() && count > 0, EINVAL, -1);
    let s = match format(opts, fmt_units(fmt), args, true, false) {
        Ok(s) => s,
        Err(Failed(e)) => {
            set_errno(e);
            put(buf, 0, C::default());
            return -1;
        }
    };
    if s.len() >= count {
        put(buf, 0, C::default());
        validate!(false, ERANGE, -1);
    }
    copy_out(buf, &s, s.len());
    put(buf, s.len(), C::default());
    s.len() as i32
}

const TRUNCATE: usize = usize::MAX;

/// `__stdio_common_vsnprintf_s` / `vsnwprintf_s`.
fn vsnprintf_s<C: Ch>(opts: u64, buf: *mut C, size: usize, count: usize, fmt: *const C, args: *const u64) -> i32 {
    validate!(!fmt.is_null(), EINVAL, -1);
    if count == 0 && buf.is_null() && size == 0 {
        return 0;
    }
    validate!(!buf.is_null() && size > 0, EINVAL, -1);
    let s = match format(opts, fmt_units(fmt), args, true, false) {
        Ok(s) => s,
        Err(Failed(e)) => {
            set_errno(e);
            put(buf, 0, C::default());
            return -1;
        }
    };
    let r = s.len();
    if count == TRUNCATE || count < size {
        let limit = if count == TRUNCATE { size - 1 } else { count };
        let n = r.min(limit);
        copy_out(buf, &s, n);
        put(buf, n, C::default());
        return if r > limit { -1 } else { r as i32 };
    }
    if r >= size {
        put(buf, 0, C::default());
        validate!(false, ERANGE, -1);
    }
    copy_out(buf, &s, r);
    put(buf, r, C::default());
    r as i32
}

extern "win64" fn __stdio_common_vsprintf(o: u64, b: *mut u8, n: usize, f: *const u8, _l: u64, a: *const u64) -> i32 {
    vsprintf(o, b, n, f, a)
}
extern "win64" fn __stdio_common_vswprintf(o: u64, b: *mut u16, n: usize, f: *const u16, _l: u64, a: *const u64) -> i32 {
    vsprintf(o, b, n, f, a)
}
extern "win64" fn __stdio_common_vsprintf_s(o: u64, b: *mut u8, n: usize, f: *const u8, _l: u64, a: *const u64) -> i32 {
    vsprintf_s(o, b, n, f, a)
}
extern "win64" fn __stdio_common_vswprintf_s(o: u64, b: *mut u16, n: usize, f: *const u16, _l: u64, a: *const u64) -> i32 {
    vsprintf_s(o, b, n, f, a)
}
extern "win64" fn __stdio_common_vsnprintf_s(
    o: u64,
    b: *mut u8,
    n: usize,
    c: usize,
    f: *const u8,
    _l: u64,
    a: *const u64,
) -> i32 {
    vsnprintf_s(o, b, n, c, f, a)
}
extern "win64" fn __stdio_common_vsnwprintf_s(
    o: u64,
    b: *mut u16,
    n: usize,
    c: usize,
    f: *const u16,
    _l: u64,
    a: *const u64,
) -> i32 {
    vsnprintf_s(o, b, n, c, f, a)
}

// ---- stream output -----------------------------------------------------------------------------

/// Formats to a stream: narrow output as bytes; wide output as wide
/// characters through `fputwc` rules (the stream's mode decides how they
/// are stored).
fn vfprintf<C: Ch>(opts: u64, f: *mut File, fmt: *const C, args: *const u64, secure: bool) -> i32 {
    validate!(!f.is_null() && !fmt.is_null(), EINVAL, -1);
    let s = match format(opts, fmt_units(fmt), args, secure, false) {
        Ok(s) => s,
        Err(Failed(e)) => {
            set_errno(e);
            return -1;
        }
    };
    // SAFETY: a FILE of this runtime (validated non-NULL).
    let file = unsafe { &mut *f };
    file.lock();
    let ok = if C::WIDE {
        s.iter().all(|&u| stdio::putwc_nolock(u.code() as u16, file) != 0xFFFF)
    } else {
        let b: Vec<u8> = s.iter().map(|&c| c.code() as u8).collect();
        stdio::write_nolock(&b, file) == b.len()
    };
    file.unlock();
    if ok { s.len() as i32 } else { -1 }
}

extern "win64" fn __stdio_common_vfprintf(o: u64, f: *mut File, fmt: *const u8, _l: u64, a: *const u64) -> i32 {
    vfprintf(o, f, fmt, a, false)
}
extern "win64" fn __stdio_common_vfprintf_s(o: u64, f: *mut File, fmt: *const u8, _l: u64, a: *const u64) -> i32 {
    vfprintf(o, f, fmt, a, true)
}
extern "win64" fn __stdio_common_vfwprintf(o: u64, f: *mut File, fmt: *const u16, _l: u64, a: *const u64) -> i32 {
    vfprintf(o, f, fmt, a, false)
}
extern "win64" fn __stdio_common_vfwprintf_s(o: u64, f: *mut File, fmt: *const u16, _l: u64, a: *const u64) -> i32 {
    vfprintf(o, f, fmt, a, true)
}

/// For tests of the formatter from Rust: narrow formatting with the
/// given options.
#[allow(dead_code)]
pub fn format_narrow(opts: u64, fmt: &[u8], args: &[u64]) -> Option<String> {
    format::<u8>(opts, fmt, args.as_ptr(), false, false).ok().map(|v| String::from_utf8_lossy(&v).into_owned())
}

pub(crate) fn win32_wide(fmt: &[u16], args: *const u64) -> Option<Vec<u16>> {
    format(LEGACY_WIDE_SPECIFIERS, fmt, args, false, false).ok()
}

pub(crate) fn win32_narrow(fmt: &[u8], args: *const u64) -> Option<Vec<u8>> {
    format(0, fmt, args, false, false).ok()
}

pub(crate) fn win32_wide32(fmt: &[u16], args: *const u32) -> Option<Vec<u16>> {
    format(LEGACY_WIDE_SPECIFIERS, fmt, args.cast(), false, true).ok()
}

pub(crate) fn win32_narrow32(fmt: &[u8], args: *const u32) -> Option<Vec<u8>> {
    format(0, fmt, args.cast(), false, true).ok()
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        _set_printf_count_output,
        _get_printf_count_output,
        __stdio_common_vsprintf,
        __stdio_common_vswprintf,
        __stdio_common_vsprintf_s,
        __stdio_common_vswprintf_s,
        __stdio_common_vsnprintf_s,
        __stdio_common_vsnwprintf_s,
        __stdio_common_vfprintf,
        __stdio_common_vfprintf_s,
        __stdio_common_vfwprintf,
        __stdio_common_vfwprintf_s,
    ]
}
