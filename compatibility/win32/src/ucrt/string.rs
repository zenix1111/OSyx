//! Strings and character classes (string contract): the C functions, the
//! bounds-checked `_s` forms with their invalid-parameter rules, and the
//! C-locale ctype/case mapping (ASCII; both OSyx locales use it).

use super::locale::{self, ALPHA, BLANK, CONTROL, DIGIT, HEX, LOWER, PUNCT, SPACE, UPPER};
use super::*;

/// `_NLSCMPERROR`.
const NLSCMPERROR: i32 = 0x7FFF_FFFF;
const TRUNCATE: usize = usize::MAX;

// ---- character classes ------------------------------------------------------------

fn is(c: i32, mask: u16) -> i32 {
    (locale::ctype(c) & mask) as i32
}

extern "win64" fn isupper(c: i32) -> i32 {
    is(c, UPPER)
}
extern "win64" fn islower(c: i32) -> i32 {
    is(c, LOWER)
}
extern "win64" fn isdigit(c: i32) -> i32 {
    is(c, DIGIT)
}
extern "win64" fn isxdigit(c: i32) -> i32 {
    is(c, HEX)
}
extern "win64" fn isspace(c: i32) -> i32 {
    is(c, SPACE)
}
extern "win64" fn ispunct(c: i32) -> i32 {
    is(c, PUNCT)
}
extern "win64" fn isalpha(c: i32) -> i32 {
    is(c, ALPHA)
}
extern "win64" fn isalnum(c: i32) -> i32 {
    is(c, ALPHA | DIGIT)
}
extern "win64" fn isprint(c: i32) -> i32 {
    is(c, BLANK | PUNCT | ALPHA | DIGIT)
}
extern "win64" fn isgraph(c: i32) -> i32 {
    is(c, PUNCT | ALPHA | DIGIT)
}
extern "win64" fn iscntrl(c: i32) -> i32 {
    is(c, CONTROL)
}
extern "win64" fn isblank(c: i32) -> i32 {
    if c == b'\t' as i32 { BLANK as i32 } else { is(c, BLANK) }
}

fn lower(c: i32) -> i32 {
    if (b'A' as i32..=b'Z' as i32).contains(&c) { c + 32 } else { c }
}

fn upper(c: i32) -> i32 {
    if (b'a' as i32..=b'z' as i32).contains(&c) { c - 32 } else { c }
}

extern "win64" fn tolower(c: i32) -> i32 {
    lower(c)
}
extern "win64" fn toupper(c: i32) -> i32 {
    upper(c)
}
extern "win64" fn _tolower(c: i32) -> i32 {
    c - b'A' as i32 + b'a' as i32
}
extern "win64" fn _toupper(c: i32) -> i32 {
    c - b'a' as i32 + b'A' as i32
}
extern "win64" fn towlower(c: u16) -> u16 {
    lower(c as i32) as u16
}
extern "win64" fn towupper(c: u16) -> u16 {
    upper(c as i32) as u16
}

fn wis(c: u16, mask: u16) -> i32 {
    if c < 256 { is(c as i32, mask) } else { 0 }
}
extern "win64" fn iswspace(c: u16) -> i32 {
    wis(c, SPACE)
}
extern "win64" fn iswdigit(c: u16) -> i32 {
    wis(c, DIGIT)
}
extern "win64" fn iswalpha(c: u16) -> i32 {
    wis(c, ALPHA)
}
extern "win64" fn iswupper(c: u16) -> i32 {
    wis(c, UPPER)
}
extern "win64" fn iswlower(c: u16) -> i32 {
    wis(c, LOWER)
}
extern "win64" fn iswxdigit(c: u16) -> i32 {
    wis(c, HEX)
}
extern "win64" fn iswalnum(c: u16) -> i32 {
    wis(c, ALPHA | DIGIT)
}
extern "win64" fn iswpunct(c: u16) -> i32 {
    wis(c, PUNCT)
}
extern "win64" fn iswcntrl(c: u16) -> i32 {
    wis(c, CONTROL)
}

// ---- lengths and comparisons ---------------------------------------------------------

extern "win64" fn strlen(s: *const u8) -> usize {
    // SAFETY: a NUL-terminated string (C contract).
    unsafe { cstr(s) }.len()
}

extern "win64" fn wcslen(s: *const u16) -> usize {
    // SAFETY: as above.
    unsafe { wstr(s) }.len()
}

extern "win64" fn wcschr(s: *const u16, c: u16) -> *const u16 {
    let mut p = s;
    loop {
        // SAFETY: the caller supplies a NUL-terminated wide string.
        let ch = unsafe { *p };
        if ch == c { return p; }
        if ch == 0 { return core::ptr::null(); }
        // SAFETY: the current character is not the terminator.
        p = unsafe { p.add(1) };
    }
}

fn bounded<T: Copy + PartialEq + Default>(s: *const T, max: usize) -> usize {
    let mut n = 0;
    // SAFETY: the caller's string is readable up to its NUL or `max`.
    while n < max && unsafe { *s.add(n) } != T::default() {
        n += 1;
    }
    n
}

extern "win64" fn strnlen(s: *const u8, max: usize) -> usize {
    bounded(s, max)
}

extern "win64" fn wcsnlen(s: *const u16, max: usize) -> usize {
    bounded(s, max)
}

extern "win64" fn __strncnt(s: *const u8, max: usize) -> usize {
    bounded(s, max)
}

extern "win64" fn __wcsncnt(s: *const u16, max: usize) -> usize {
    bounded(s, max)
}

/// Compares up to `n` units with `map` applied, returning the difference
/// of the first unequal pair (or 0).
fn compare<T: Copy + Into<i32>>(a: *const T, b: *const T, n: usize, map: fn(i32) -> i32) -> i32 {
    for i in 0..n {
        // SAFETY: both strings are readable up to their terminator; the
        // loop stops at the first NUL.
        let (x, y) = unsafe { (map((*a.add(i)).into()), map((*b.add(i)).into())) };
        if x != y || x == 0 {
            return x - y;
        }
    }
    0
}

fn same(c: i32) -> i32 {
    c
}

extern "win64" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    compare(a, b, usize::MAX, same).signum()
}

extern "win64" fn strncmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    compare(a, b, n, same).signum()
}

extern "win64" fn wcscmp(a: *const u16, b: *const u16) -> i32 {
    compare(a, b, usize::MAX, same).signum()
}

extern "win64" fn wcsncmp(a: *const u16, b: *const u16, n: usize) -> i32 {
    compare(a, b, n, same).signum()
}

extern "win64" fn _stricmp(a: *const u8, b: *const u8) -> i32 {
    validate!(!a.is_null() && !b.is_null(), EINVAL, NLSCMPERROR);
    compare(a, b, usize::MAX, lower)
}

extern "win64" fn _strnicmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    validate!(!a.is_null() && !b.is_null(), EINVAL, NLSCMPERROR);
    compare(a, b, n, lower)
}

extern "win64" fn _wcsicmp(a: *const u16, b: *const u16) -> i32 {
    validate!(!a.is_null() && !b.is_null(), EINVAL, NLSCMPERROR);
    compare(a, b, usize::MAX, lower)
}

extern "win64" fn _wcsnicmp(a: *const u16, b: *const u16, n: usize) -> i32 {
    validate!(!a.is_null() && !b.is_null(), EINVAL, NLSCMPERROR);
    compare(a, b, n, lower)
}

extern "win64" fn strcoll(a: *const u8, b: *const u8) -> i32 {
    strcmp(a, b)
}

extern "win64" fn wcscoll(a: *const u16, b: *const u16) -> i32 {
    wcscmp(a, b)
}

// ---- copying ------------------------------------------------------------------------

fn copy_with_nul<T: Copy + PartialEq + Default>(d: *mut T, s: *const T) -> *mut T {
    let mut i = 0;
    loop {
        // SAFETY: C contract: `d` has room for `s` and its terminator.
        unsafe {
            let c = *s.add(i);
            *d.add(i) = c;
            if c == T::default() {
                return d;
            }
        }
        i += 1;
    }
}

extern "win64" fn strcpy(d: *mut u8, s: *const u8) -> *mut u8 {
    copy_with_nul(d, s)
}

extern "win64" fn wcscpy(d: *mut u16, s: *const u16) -> *mut u16 {
    copy_with_nul(d, s)
}

extern "win64" fn strcat(d: *mut u8, s: *const u8) -> *mut u8 {
    // SAFETY: C contract: `d` is a string with room for `s`.
    copy_with_nul(unsafe { d.add(bounded(d, usize::MAX)) }, s);
    d
}

extern "win64" fn wcscat(d: *mut u16, s: *const u16) -> *mut u16 {
    // SAFETY: as above.
    copy_with_nul(unsafe { d.add(bounded(d, usize::MAX)) }, s);
    d
}

/// strncpy: copies at most `n` units and pads the rest of `n` with NULs.
fn ncopy<T: Copy + PartialEq + Default>(d: *mut T, s: *const T, n: usize) -> *mut T {
    let len = bounded(s, n);
    // SAFETY: C contract: `d` holds `n` units, `s` is readable for `len`.
    unsafe {
        core::ptr::copy(s, d, len);
        for i in len..n {
            *d.add(i) = T::default();
        }
    }
    d
}

extern "win64" fn strncpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    ncopy(d, s, n)
}

extern "win64" fn wcsncpy(d: *mut u16, s: *const u16, n: usize) -> *mut u16 {
    ncopy(d, s, n)
}

fn ncat<T: Copy + PartialEq + Default>(d: *mut T, s: *const T, n: usize) -> *mut T {
    let end = bounded(d, usize::MAX);
    let len = bounded(s, n);
    // SAFETY: C contract: `d` has room for `len` more units and a NUL.
    unsafe {
        core::ptr::copy(s, d.add(end), len);
        *d.add(end + len) = T::default();
    }
    d
}

extern "win64" fn strncat(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    ncat(d, s, n)
}

extern "win64" fn wcsncat(d: *mut u16, s: *const u16, n: usize) -> *mut u16 {
    ncat(d, s, n)
}

/// Writes `v` to d[0] (the `_s` functions' reset of a destination).
fn reset<T: Default>(d: *mut T) {
    // SAFETY: called only for a validated non-NULL destination of size > 0.
    unsafe { *d = T::default() };
}

/// strcpy_s / wcscpy_s.
fn copy_s<T: Copy + PartialEq + Default>(d: *mut T, size: usize, s: *const T) -> i32 {
    validate!(!d.is_null() && size > 0, EINVAL, EINVAL);
    if s.is_null() {
        reset(d);
        validate!(false, EINVAL, EINVAL);
    }
    let len = bounded(s, size);
    if len == size {
        reset(d);
        validate!(false, ERANGE, ERANGE);
    }
    // SAFETY: `len + 1 <= size` units fit in `d`.
    unsafe {
        core::ptr::copy(s, d, len);
        *d.add(len) = T::default();
    }
    0
}

extern "win64" fn strcpy_s(d: *mut u8, size: usize, s: *const u8) -> i32 {
    copy_s(d, size, s)
}

extern "win64" fn wcscpy_s(d: *mut u16, size: usize, s: *const u16) -> i32 {
    copy_s(d, size, s)
}

/// strcat_s / wcscat_s.
fn cat_s<T: Copy + PartialEq + Default>(d: *mut T, size: usize, s: *const T) -> i32 {
    validate!(!d.is_null() && size > 0, EINVAL, EINVAL);
    if s.is_null() {
        reset(d);
        validate!(false, EINVAL, EINVAL);
    }
    let end = bounded(d, size);
    if end == size {
        reset(d);
        validate!(false, EINVAL, EINVAL); // destination not terminated
    }
    let len = bounded(s, size - end);
    if end + len == size {
        reset(d);
        validate!(false, ERANGE, ERANGE);
    }
    // SAFETY: end + len + 1 <= size.
    unsafe {
        core::ptr::copy(s, d.add(end), len);
        *d.add(end + len) = T::default();
    }
    0
}

extern "win64" fn strcat_s(d: *mut u8, size: usize, s: *const u8) -> i32 {
    cat_s(d, size, s)
}

extern "win64" fn wcscat_s(d: *mut u16, size: usize, s: *const u16) -> i32 {
    cat_s(d, size, s)
}

/// strncpy_s / wcsncpy_s (`count` may be _TRUNCATE).
fn ncopy_s<T: Copy + PartialEq + Default>(d: *mut T, size: usize, s: *const T, count: usize) -> i32 {
    if count == 0 && d.is_null() && size == 0 {
        return 0;
    }
    validate!(!d.is_null() && size > 0, EINVAL, EINVAL);
    if count == 0 {
        reset(d);
        return 0;
    }
    if s.is_null() {
        reset(d);
        validate!(false, EINVAL, EINVAL);
    }
    if count == TRUNCATE {
        let len = bounded(s, size);
        let (n, r) = if len == size { (size - 1, STRUNCATE) } else { (len, 0) };
        // SAFETY: n + 1 <= size.
        unsafe {
            core::ptr::copy(s, d, n);
            *d.add(n) = T::default();
        }
        return r;
    }
    let len = bounded(s, count);
    if len >= size {
        reset(d);
        validate!(false, ERANGE, ERANGE);
    }
    // SAFETY: len + 1 <= size.
    unsafe {
        core::ptr::copy(s, d, len);
        *d.add(len) = T::default();
    }
    0
}

extern "win64" fn strncpy_s(d: *mut u8, size: usize, s: *const u8, count: usize) -> i32 {
    ncopy_s(d, size, s, count)
}

extern "win64" fn wcsncpy_s(d: *mut u16, size: usize, s: *const u16, count: usize) -> i32 {
    ncopy_s(d, size, s, count)
}

/// strncat_s / wcsncat_s.
fn ncat_s<T: Copy + PartialEq + Default>(d: *mut T, size: usize, s: *const T, count: usize) -> i32 {
    if count == 0 && d.is_null() && size == 0 {
        return 0;
    }
    validate!(!d.is_null() && size > 0, EINVAL, EINVAL);
    if s.is_null() && count != 0 {
        reset(d);
        validate!(false, EINVAL, EINVAL);
    }
    let end = bounded(d, size);
    if end == size {
        reset(d);
        validate!(false, EINVAL, EINVAL);
    }
    let room = size - end;
    if count == TRUNCATE {
        let len = bounded(s, room);
        let (n, r) = if len == room { (room - 1, STRUNCATE) } else { (len, 0) };
        // SAFETY: end + n + 1 <= size.
        unsafe {
            core::ptr::copy(s, d.add(end), n);
            *d.add(end + n) = T::default();
        }
        return r;
    }
    let len = if count == 0 { 0 } else { bounded(s, count) };
    if len >= room {
        reset(d);
        validate!(false, ERANGE, ERANGE);
    }
    // SAFETY: end + len + 1 <= size.
    unsafe {
        core::ptr::copy(s, d.add(end), len);
        *d.add(end + len) = T::default();
    }
    0
}

extern "win64" fn strncat_s(d: *mut u8, size: usize, s: *const u8, count: usize) -> i32 {
    ncat_s(d, size, s, count)
}

extern "win64" fn wcsncat_s(d: *mut u16, size: usize, s: *const u16, count: usize) -> i32 {
    ncat_s(d, size, s, count)
}

extern "win64" fn memcpy_s(d: *mut u8, size: usize, s: *const u8, count: usize) -> i32 {
    if count == 0 {
        return 0;
    }
    validate!(!d.is_null(), EINVAL, EINVAL);
    if s.is_null() || size < count {
        // SAFETY: `d` holds `size` bytes.
        unsafe { core::ptr::write_bytes(d, 0, size) };
        validate!(!s.is_null(), EINVAL, EINVAL);
        validate!(false, ERANGE, ERANGE);
    }
    // SAFETY: both hold `count` bytes; memcpy_s requires no overlap.
    unsafe { core::ptr::copy_nonoverlapping(s, d, count) };
    0
}

extern "win64" fn memmove_s(d: *mut u8, size: usize, s: *const u8, count: usize) -> i32 {
    if count == 0 {
        return 0;
    }
    validate!(!d.is_null() && !s.is_null(), EINVAL, EINVAL);
    validate!(size >= count, ERANGE, ERANGE);
    // SAFETY: both hold `count` bytes.
    unsafe { core::ptr::copy(s, d, count) };
    0
}

extern "win64" fn _strdup(s: *const u8) -> *mut u8 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: a NUL-terminated string.
    heap_cstr(unsafe { cstr(s) })
}

extern "win64" fn _wcsdup(s: *const u16) -> *mut u16 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: as above.
    heap_wstr(unsafe { wstr(s) })
}

// ---- case conversion in place --------------------------------------------------------

/// _strupr_s / _wcslwr_s and friends: the string must be terminated
/// within `size`.
fn map_s<T: Copy + PartialEq + Default + Into<i32>>(s: *mut T, size: usize, f: fn(i32) -> i32, from: fn(i32) -> T) -> i32 {
    validate!(!s.is_null(), EINVAL, EINVAL);
    let len = bounded(s, size);
    if len == size {
        if size > 0 {
            reset(s);
        }
        validate!(false, EINVAL, EINVAL);
    }
    for i in 0..len {
        // SAFETY: within the string.
        unsafe { *s.add(i) = from(f((*s.add(i)).into())) };
    }
    0
}

fn to_u8(c: i32) -> u8 {
    c as u8
}

fn to_u16(c: i32) -> u16 {
    c as u16
}

extern "win64" fn _strupr_s(s: *mut u8, size: usize) -> i32 {
    map_s(s, size, upper, to_u8)
}

extern "win64" fn _strlwr_s(s: *mut u8, size: usize) -> i32 {
    map_s(s, size, lower, to_u8)
}

extern "win64" fn _wcsupr_s(s: *mut u16, size: usize) -> i32 {
    map_s(s, size, upper, to_u16)
}

extern "win64" fn _wcslwr_s(s: *mut u16, size: usize) -> i32 {
    map_s(s, size, lower, to_u16)
}

extern "win64" fn _strupr(s: *mut u8) -> *mut u8 {
    map_s(s, usize::MAX, upper, to_u8);
    s
}

extern "win64" fn _strlwr(s: *mut u8) -> *mut u8 {
    map_s(s, usize::MAX, lower, to_u8);
    s
}

extern "win64" fn _wcsupr(s: *mut u16) -> *mut u16 {
    map_s(s, usize::MAX, upper, to_u16);
    s
}

extern "win64" fn _wcslwr(s: *mut u16) -> *mut u16 {
    map_s(s, usize::MAX, lower, to_u16);
    s
}

// ---- searching ------------------------------------------------------------------------

/// Whether `c` occurs in the NUL-terminated set.
fn in_set<T: Copy + PartialEq + Default>(set: *const T, c: T) -> bool {
    let mut i = 0;
    loop {
        // SAFETY: the set is NUL-terminated.
        let x = unsafe { *set.add(i) };
        if x == T::default() {
            return false;
        }
        if x == c {
            return true;
        }
        i += 1;
    }
}

/// Length of the prefix of `s` whose units are (`accept`) or are not in
/// `set`.
fn span<T: Copy + PartialEq + Default>(s: *const T, set: *const T, accept: bool) -> usize {
    let mut n = 0;
    loop {
        // SAFETY: `s` is NUL-terminated.
        let c = unsafe { *s.add(n) };
        if c == T::default() || in_set(set, c) != accept {
            return n;
        }
        n += 1;
    }
}

extern "win64" fn strspn(s: *const u8, set: *const u8) -> usize {
    span(s, set, true)
}

extern "win64" fn strcspn(s: *const u8, set: *const u8) -> usize {
    span(s, set, false)
}

extern "win64" fn wcsspn(s: *const u16, set: *const u16) -> usize {
    span(s, set, true)
}

extern "win64" fn wcscspn(s: *const u16, set: *const u16) -> usize {
    span(s, set, false)
}

fn pbrk<T: Copy + PartialEq + Default>(s: *const T, set: *const T) -> *const T {
    let n = span(s, set, false);
    // SAFETY: `n` is within the string (at most its terminator).
    if unsafe { *s.add(n) } == T::default() { core::ptr::null() } else { unsafe { s.add(n) } }
}

extern "win64" fn strpbrk(s: *const u8, set: *const u8) -> *const u8 {
    pbrk(s, set)
}

extern "win64" fn wcspbrk(s: *const u16, set: *const u16) -> *const u16 {
    pbrk(s, set)
}

/// The strtok state machine over a continuation pointer.
fn tok<T: Copy + PartialEq + Default>(s: *mut T, delim: *const T, ctx: &mut usize) -> *mut T {
    let start = if s.is_null() { *ctx as *mut T } else { s };
    if start.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `start` is inside the caller's NUL-terminated string.
    unsafe {
        let t = start.add(span(start, delim, true));
        if *t == T::default() {
            *ctx = t as usize;
            return core::ptr::null_mut();
        }
        let e = t.add(span(t, delim, false));
        if *e == T::default() {
            *ctx = e as usize;
        } else {
            *e = T::default();
            *ctx = e.add(1) as usize;
        }
        t
    }
}

extern "win64" fn strtok(s: *mut u8, delim: *const u8) -> *mut u8 {
    tok(s, delim, &mut ptd().strtok)
}

extern "win64" fn wcstok(s: *mut u16, delim: *const u16, ctx: *mut usize) -> *mut u16 {
    if ctx.is_null() {
        return tok(s, delim, &mut ptd().wcstok);
    }
    // SAFETY: the caller's context pointer.
    tok(s, delim, unsafe { &mut *ctx })
}

extern "win64" fn strtok_s(s: *mut u8, delim: *const u8, ctx: *mut usize) -> *mut u8 {
    validate!(!ctx.is_null() && !delim.is_null(), EINVAL, core::ptr::null_mut());
    // SAFETY: validated.
    validate!(!s.is_null() || unsafe { *ctx } != 0, EINVAL, core::ptr::null_mut());
    // SAFETY: validated.
    tok(s, delim, unsafe { &mut *ctx })
}

extern "win64" fn wcstok_s(s: *mut u16, delim: *const u16, ctx: *mut usize) -> *mut u16 {
    validate!(!ctx.is_null() && !delim.is_null(), EINVAL, core::ptr::null_mut());
    // SAFETY: validated.
    validate!(!s.is_null() || unsafe { *ctx } != 0, EINVAL, core::ptr::null_mut());
    // SAFETY: validated.
    tok(s, delim, unsafe { &mut *ctx })
}

extern "win64" fn strxfrm(d: *mut u8, s: *const u8, n: usize) -> usize {
    // C collation is byte order: the transformation is the identity.
    let len = strlen(s);
    if len < n && !d.is_null() {
        copy_with_nul(d, s);
    }
    len
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        isupper, islower, isdigit, isxdigit, isspace, ispunct, isalpha, isalnum, isprint, isgraph, iscntrl, isblank,
        tolower, toupper, _tolower, _toupper, towlower, towupper, iswspace, iswdigit, iswalpha, iswupper, iswlower,
        iswxdigit, iswalnum, iswpunct, iswcntrl, strlen, wcslen, wcschr, strnlen, wcsnlen, __strncnt, __wcsncnt, strcmp,
        strncmp, wcscmp, wcsncmp, _stricmp, _strnicmp, _wcsicmp, _wcsnicmp, strcoll, wcscoll, strcpy, wcscpy, strcat,
        wcscat, strncpy, wcsncpy, strncat, wcsncat, strcpy_s, wcscpy_s, strcat_s, wcscat_s, strncpy_s, wcsncpy_s,
        strncat_s, wcsncat_s, memcpy_s, memmove_s, _strdup, _wcsdup, _strupr_s, _strlwr_s, _wcsupr_s, _wcslwr_s,
        _strupr, _strlwr, _wcsupr, _wcslwr, strspn, strcspn, wcsspn, wcscspn, strpbrk, wcspbrk, strtok, wcstok,
        strtok_s, wcstok_s, strxfrm,
    ]
}
