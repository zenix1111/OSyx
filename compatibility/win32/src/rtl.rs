//! NT runtime library pieces (ntdll `Rtl*`, `mem*`) and the kernel32 calls
//! that share them: heap access, counted strings, interlocked singly linked
//! lists, pointer encoding. Heaps are the one process allocator
//! (kernel32's `heap_*`); SRW locks, run-once and condition variables are
//! kernel32's implementations under their NT names and NTSTATUS results.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{self, fail},
    objects, synch,
};
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

const STATUS_BUFFER_OVERFLOW: NtStatus = 0x8000_0005;
const HEAP_ZERO_MEMORY: u32 = 0x8;
const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x10;

// ---- heap ---------------------------------------------------------------------

extern "win64" fn RtlAllocateHeap(heap: u64, flags: u32, size: usize) -> u64 {
    if crate::heaps::is_private(heap) {
        return crate::heaps::alloc(heap, flags, size);
    }
    kernel32::heap_alloc(size, flags & HEAP_ZERO_MEMORY != 0).unwrap_or(0)
}

extern "win64" fn RtlFreeHeap(heap: u64, flags: u32, p: u64) -> u8 {
    if crate::heaps::is_private(heap) {
        return u8::from(crate::heaps::free(heap, flags, p) != 0);
    }
    u8::from(kernel32::heap_free(p))
}

/// Blocks never grow in place (one allocator, exact-size blocks), so
/// HEAP_REALLOC_IN_PLACE_ONLY succeeds only when shrinking or equal.
extern "win64" fn RtlReAllocateHeap(heap: u64, flags: u32, p: u64, size: usize) -> u64 {
    if crate::heaps::is_private(heap) {
        return crate::heaps::realloc(heap, flags, p, size);
    }
    if p == 0 {
        return 0;
    }
    let old = kernel32::heap_size(p);
    if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
        // The header's size also frees the block, so it stays as it is;
        // the block still holds at least `size` bytes.
        return if size > old { 0 } else { p };
    }
    let Some(n) = kernel32::heap_alloc(size, flags & HEAP_ZERO_MEMORY != 0) else { return 0 };
    // SAFETY: both blocks are valid for min(old, size) bytes.
    unsafe { core::ptr::copy_nonoverlapping(p as *const u8, n as *mut u8, old.min(size)) };
    kernel32::heap_free(p);
    n
}

// ---- counted strings ----------------------------------------------------------

/// UNICODE_STRING / ANSI_STRING: lengths in bytes, then the buffer.
#[repr(C)]
struct Counted<T> {
    len: u16,
    max: u16,
    buffer: *mut T,
}

extern "win64" fn RtlInitUnicodeString(dst: *mut Counted<u16>, src: *const u16) {
    let mut n = 0usize;
    if !src.is_null() {
        // SAFETY: a NUL-terminated string.
        while unsafe { *src.add(n) } != 0 {
            n += 1;
        }
    }
    let bytes = (n * 2).min(0xfffc) as u16;
    // SAFETY: the caller's structure.
    unsafe {
        *dst = Counted { len: bytes, max: if src.is_null() { 0 } else { bytes + 2 }, buffer: src as *mut u16 };
    }
}

extern "win64" fn RtlInitAnsiString(dst: *mut Counted<u8>, src: *const u8) {
    let mut n = 0usize;
    if !src.is_null() {
        // SAFETY: a NUL-terminated string.
        while unsafe { *src.add(n) } != 0 {
            n += 1;
        }
    }
    let bytes = n.min(0xfffe) as u16;
    // SAFETY: the caller's structure.
    unsafe {
        *dst = Counted { len: bytes, max: if src.is_null() { 0 } else { bytes + 1 }, buffer: src as *mut u8 };
    }
}

/// Converts with the process ANSI code page (UTF-8 on OSyx, see path.rs).
extern "win64" fn RtlAnsiStringToUnicodeString(dst: *mut Counted<u16>, src: *const Counted<u8>, allocate: u8) -> NtStatus {
    if dst.is_null() || src.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's structures and their buffers.
    let bytes = unsafe { core::slice::from_raw_parts((*src).buffer, (*src).len as usize) };
    let text = match core::str::from_utf8(bytes) {
        Ok(s) => alloc::string::String::from(s),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    };
    let units: Vec<u16> = text.encode_utf16().collect();
    let need = units.len() * 2;
    if need > 0xfffc {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: as above.
    unsafe {
        if allocate != 0 {
            let Some(p) = kernel32::heap_alloc(need + 2, false) else { return STATUS_NO_MEMORY };
            (*dst).buffer = p as *mut u16;
            (*dst).max = need as u16 + 2;
        } else if need > (*dst).max as usize {
            return STATUS_BUFFER_OVERFLOW;
        }
        core::ptr::copy_nonoverlapping(units.as_ptr(), (*dst).buffer, units.len());
        if need + 2 <= (*dst).max as usize {
            *(*dst).buffer.add(units.len()) = 0;
        }
        (*dst).len = need as u16;
    }
    STATUS_SUCCESS
}

const DUPLICATE_NULL_TERMINATE: u32 = 1;
const DUPLICATE_ALLOCATE_NULL_STRING: u32 = 2;

extern "win64" fn RtlDuplicateUnicodeString(flags: u32, src: *const Counted<u16>, dst: *mut Counted<u16>) -> NtStatus {
    if dst.is_null() || flags & !3 != 0 || (!src.is_null() && unsafe { !(*src).len.is_multiple_of(2) }) {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's structures.
    let len = if src.is_null() { 0 } else { unsafe { (*src).len as usize } };
    let terminate = flags & DUPLICATE_NULL_TERMINATE != 0;
    if len == 0 && flags & DUPLICATE_ALLOCATE_NULL_STRING == 0 {
        // SAFETY: as above.
        unsafe { *dst = Counted { len: 0, max: 0, buffer: core::ptr::null_mut() } };
        return STATUS_SUCCESS;
    }
    let size = len + if terminate { 2 } else { 0 };
    if size > 0xffff {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(p) = kernel32::heap_alloc(size.max(2), false) else { return STATUS_NO_MEMORY };
    // SAFETY: `p` holds `size` bytes; the source holds `len`.
    unsafe {
        if len > 0 {
            core::ptr::copy_nonoverlapping((*src).buffer as *const u8, p as *mut u8, len);
        }
        if terminate || len == 0 {
            *((p as usize + len) as *mut u16) = 0;
        }
        *dst = Counted { len: len as u16, max: size.max(2) as u16, buffer: p as *mut u16 };
    }
    STATUS_SUCCESS
}

extern "win64" fn RtlFreeUnicodeString(s: *mut Counted<u16>) {
    if s.is_null() {
        return;
    }
    // SAFETY: a string allocated by the Rtl functions above.
    unsafe {
        if !(*s).buffer.is_null() {
            kernel32::heap_free((*s).buffer as u64);
        }
        *s = Counted { len: 0, max: 0, buffer: core::ptr::null_mut() };
    }
}

fn upcase(c: u16) -> u16 {
    match char::from_u32(c as u32) {
        Some(ch) => {
            let mut up = ch.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) if (u as u32) < 0x10000 => u as u16,
                _ => c,
            }
        }
        None => c,
    }
}

/// # Safety
/// `s` must be a valid UNICODE_STRING.
unsafe fn units<'a>(s: *const Counted<u16>) -> &'a [u16] {
    // SAFETY: the caller's guarantee.
    unsafe {
        if (*s).len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts((*s).buffer, (*s).len as usize / 2)
        }
    }
}

extern "win64" fn RtlCompareUnicodeString(a: *const Counted<u16>, b: *const Counted<u16>, ci: u8) -> i32 {
    // SAFETY: the caller's strings.
    let (x, y) = unsafe { (units(a), units(b)) };
    for (&p, &q) in x.iter().zip(y) {
        let (p, q) = if ci != 0 { (upcase(p), upcase(q)) } else { (p, q) };
        if p != q {
            return p as i32 - q as i32;
        }
    }
    x.len() as i32 - y.len() as i32
}

extern "win64" fn RtlEqualUnicodeString(a: *const Counted<u16>, b: *const Counted<u16>, ci: u8) -> u8 {
    // SAFETY: the caller's strings.
    let same_len = unsafe { (*a).len == (*b).len };
    u8::from(same_len && RtlCompareUnicodeString(a, b, ci) == 0)
}

// ---- memory -----------------------------------------------------------------------

extern "win64" fn RtlCompareMemory(a: *const u8, b: *const u8, len: usize) -> usize {
    let mut i = 0;
    // SAFETY: both ranges are readable for `len` bytes.
    while i < len && unsafe { *a.add(i) == *b.add(i) } {
        i += 1;
    }
    i
}

extern "win64" fn memcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    for i in 0..len {
        // SAFETY: as above.
        let (x, y) = unsafe { (*a.add(i), *b.add(i)) };
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}

extern "win64" fn memcpy(d: *mut u8, s: *const u8, len: usize) -> *mut u8 {
    // SAFETY: the caller's buffers (overlap allowed, as ntdll's memcpy is memmove).
    unsafe { core::ptr::copy(s, d, len) };
    d
}

extern "win64" fn memmove(d: *mut u8, s: *const u8, len: usize) -> *mut u8 {
    // SAFETY: the caller's buffers.
    unsafe { core::ptr::copy(s, d, len) };
    d
}

extern "win64" fn memset(d: *mut u8, c: i32, len: usize) -> *mut u8 {
    // SAFETY: the caller's buffer.
    unsafe { core::ptr::write_bytes(d, c as u8, len) };
    d
}

/// x86 keeps instruction fetch coherent with stores; changing protection
/// to executable already went through the kernel. Only this process.
extern "win64" fn FlushInstructionCache(process: u64, _addr: u64, _len: usize) -> i32 {
    if process != objects::CURRENT_PROCESS {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    1
}

extern "win64" fn NtFlushInstructionCache(process: u64, _addr: u64, _len: usize) -> NtStatus {
    if process != objects::CURRENT_PROCESS { STATUS_INVALID_HANDLE } else { STATUS_SUCCESS }
}

// ---- NT names of kernel32 synchronisation ---------------------------------------

extern "win64" fn RtlAcquireSRWLockExclusive(l: u64) {
    kernel32::AcquireSRWLockExclusive(l)
}
extern "win64" fn RtlReleaseSRWLockExclusive(l: u64) {
    kernel32::ReleaseSRWLockExclusive(l)
}
extern "win64" fn RtlAcquireSRWLockShared(l: u64) {
    kernel32::AcquireSRWLockShared(l)
}
extern "win64" fn RtlReleaseSRWLockShared(l: u64) {
    kernel32::ReleaseSRWLockShared(l)
}
extern "win64" fn RtlRunOnceInitialize(once: u64) {
    synch::InitOnceInitialize(once)
}
extern "win64" fn RtlRunOnceExecuteOnce(once: u64, callback: u64, parameter: u64, context: *mut u64) -> NtStatus {
    if synch::InitOnceExecuteOnce(once, callback, parameter, context) != 0 { STATUS_SUCCESS } else { STATUS_UNSUCCESSFUL }
}
extern "win64" fn RtlWakeAllConditionVariable(cv: u64) {
    synch::WakeAllConditionVariable(cv)
}
extern "win64" fn RtlWakeConditionVariable(cv: u64) {
    synch::WakeConditionVariable(cv)
}

/// LARGE_INTEGER timeout: NULL waits forever, negative is relative and
/// positive absolute, in 100 ns units.
fn timeout_ms(timeout: *const i64) -> u32 {
    if timeout.is_null() {
        return u32::MAX;
    }
    // SAFETY: the caller's LARGE_INTEGER.
    let t = unsafe { core::ptr::read_unaligned(timeout) };
    let units = if t < 0 {
        t.unsigned_abs()
    } else {
        let now = kernel32::filetime(os_sys::clock(osyx_abi::CLOCK_REALTIME).unwrap_or(0) as i64);
        (t as u64).saturating_sub(now)
    };
    units.div_ceil(10_000).min(u32::MAX as u64 - 1) as u32
}

extern "win64" fn RtlSleepConditionVariableSRW(cv: u64, lock: u64, timeout: *const i64, flags: u32) -> NtStatus {
    if synch::SleepConditionVariableSRW(cv, lock, timeout_ms(timeout), flags) != 0 {
        STATUS_SUCCESS
    } else if crate::teb::last_error() == ERROR_TIMEOUT {
        STATUS_TIMEOUT
    } else {
        STATUS_INVALID_PARAMETER
    }
}

extern "win64" fn RtlQueryPerformanceCounter(out: *mut i64) -> u8 {
    if out.is_null() {
        return 0;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = os_sys::clock(osyx_abi::CLOCK_MONOTONIC).unwrap_or(0) as i64 };
    1
}

extern "win64" fn RtlQueryPerformanceFrequency(out: *mut i64) -> u8 {
    if out.is_null() {
        return 0;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = 1_000_000_000 };
    1
}

// ---- pointer encoding -----------------------------------------------------------

static COOKIE: AtomicU64 = AtomicU64::new(0);

/// A per-process secret from the kernel entropy device; without one the
/// clocks and process id are mixed in (the encoding still round-trips).
fn cookie() -> u64 {
    let c = COOKIE.load(Ordering::Relaxed);
    if c != 0 {
        return c;
    }
    let mut bytes = [0u8; 8];
    let fresh = match os_sys::open("/dev/random", osyx_abi::OPEN_READ, 0) {
        Ok(fd) => {
            let ok = os_sys::read_raw(fd, bytes.as_mut_ptr() as usize, 8) == Ok(8);
            let _ = os_sys::close(fd);
            ok
        }
        Err(_) => false,
    };
    let mut c = u64::from_le_bytes(bytes);
    if !fresh {
        c = os_sys::clock(osyx_abi::CLOCK_MONOTONIC).unwrap_or(0).rotate_left(29)
            ^ os_sys::clock(osyx_abi::CLOCK_REALTIME).unwrap_or(0)
            ^ kernel32::pid().wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    let c = c | 1;
    match COOKIE.compare_exchange(0, c, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => c,
        Err(existing) => existing,
    }
}

extern "win64" fn EncodePointer(p: u64) -> u64 {
    let c = cookie();
    (p ^ c).rotate_right((c & 63) as u32)
}

extern "win64" fn DecodePointer(p: u64) -> u64 {
    let c = cookie();
    p.rotate_left((c & 63) as u32) ^ c
}

// ---- interlocked singly linked lists ----------------------------------------------
//
// SLIST_HEADER (x64): word 0 = Depth:16 | Sequence:48; word 1 =
// HeaderType:1 | Init:1 | Reserved:2 | NextEntry:60 (entry address, which
// is 16-byte aligned, in bits 4..63). Updates are one CMPXCHG16B.

/// # Safety
/// `p` is a 16-byte aligned SLIST_HEADER.
unsafe fn cas16(p: *mut u64, old: [u64; 2], new: [u64; 2]) -> bool {
    let ok: u8;
    // SAFETY: the caller's header; RBX is saved around the instruction.
    // Every scratch register is explicit: an unconstrained byte output
    // may be BL, whose SETE result would be overwritten by restoring RBX.
    // The address must not be allocated in RBX either, since we exchange it.
    unsafe {
        asm!(
            "xchg r9, rbx",
            "lock cmpxchg16b [r8]",
            "sete r11b",
            "mov rbx, r9",
            in("r8") p,
            inout("r9") new[0] => _,
            out("r11b") ok,
            inout("rax") old[0] => _,
            inout("rdx") old[1] => _,
            in("rcx") new[1],
        );
    }
    ok != 0
}

/// # Safety
/// As for `cas16`.
unsafe fn load16(p: *mut u64) -> [u64; 2] {
    // SAFETY: the header is readable; a torn read just fails the CAS.
    unsafe { [core::ptr::read_volatile(p), core::ptr::read_volatile(p.add(1))] }
}

fn header(h: u64) -> Option<*mut u64> {
    (h != 0 && h.is_multiple_of(16)).then_some(h as *mut u64)
}

extern "win64" fn InitializeSListHead(h: u64) {
    if let Some(p) = header(h) {
        // SAFETY: the caller's header.
        unsafe {
            *p = 0;
            *p.add(1) = 1; // HeaderType: x64 layout
        }
    }
}

extern "win64" fn InterlockedPushEntrySList(h: u64, entry: u64) -> u64 {
    let Some(p) = header(h) else { return 0 };
    loop {
        // SAFETY: the caller's header and 16-byte aligned entry.
        let old = unsafe { load16(p) };
        let first = old[1] & !0xf;
        unsafe { *(entry as *mut u64) = first };
        let depth = (old[0] & 0xffff) + 1;
        let seq = ((old[0] >> 16) + 1) & 0xffff_ffff_ffff;
        let new = [depth & 0xffff | seq << 16, (entry & !0xf) | (old[1] & 0xf)];
        if unsafe { cas16(p, old, new) } {
            return first;
        }
    }
}

extern "win64" fn InterlockedPopEntrySList(h: u64) -> u64 {
    let Some(p) = header(h) else { return 0 };
    loop {
        // SAFETY: as above.
        let old = unsafe { load16(p) };
        let first = old[1] & !0xf;
        if first == 0 {
            return 0;
        }
        let next = unsafe { core::ptr::read_volatile(first as *const u64) };
        let depth = (old[0] & 0xffff).wrapping_sub(1) & 0xffff;
        let seq = ((old[0] >> 16) + 1) & 0xffff_ffff_ffff;
        let new = [depth | seq << 16, (next & !0xf) | (old[1] & 0xf)];
        if unsafe { cas16(p, old, new) } {
            return first;
        }
    }
}

extern "win64" fn InterlockedFlushSList(h: u64) -> u64 {
    let Some(p) = header(h) else { return 0 };
    loop {
        // SAFETY: as above.
        let old = unsafe { load16(p) };
        let first = old[1] & !0xf;
        if first == 0 {
            return 0;
        }
        let seq = ((old[0] >> 16) + 1) & 0xffff_ffff_ffff;
        if unsafe { cas16(p, old, [seq << 16, old[1] & 0xf]) } {
            return first;
        }
    }
}

extern "win64" fn QueryDepthSList(h: u64) -> u16 {
    // SAFETY: the caller's header.
    header(h).map_or(0, |p| unsafe { (load16(p)[0] & 0xffff) as u16 })
}

extern "win64" fn RtlFirstEntrySList(h: u64) -> u64 {
    // SAFETY: the caller's header.
    header(h).map_or(0, |p| unsafe { load16(p)[1] & !0xf })
}

pub fn ntdll_exports() -> Vec<(&'static str, u64)> {
    let mut e = export_table![
        RtlAllocateHeap,
        RtlFreeHeap,
        RtlReAllocateHeap,
        RtlInitUnicodeString,
        RtlInitAnsiString,
        RtlAnsiStringToUnicodeString,
        RtlDuplicateUnicodeString,
        RtlFreeUnicodeString,
        RtlCompareUnicodeString,
        RtlEqualUnicodeString,
        RtlCompareMemory,
        memcmp,
        memcpy,
        memmove,
        memset,
        NtFlushInstructionCache,
        RtlAcquireSRWLockExclusive,
        RtlReleaseSRWLockExclusive,
        RtlAcquireSRWLockShared,
        RtlReleaseSRWLockShared,
        RtlRunOnceInitialize,
        RtlRunOnceExecuteOnce,
        RtlWakeAllConditionVariable,
        RtlWakeConditionVariable,
        RtlSleepConditionVariableSRW,
        RtlQueryPerformanceCounter,
        RtlQueryPerformanceFrequency,
        RtlFirstEntrySList,
    ];
    e.extend([
        ("RtlEncodePointer", EncodePointer as *const () as u64),
        ("RtlDecodePointer", DecodePointer as *const () as u64),
        ("RtlInitializeSListHead", InitializeSListHead as *const () as u64),
        ("RtlInterlockedPushEntrySList", InterlockedPushEntrySList as *const () as u64),
        ("RtlInterlockedPopEntrySList", InterlockedPopEntrySList as *const () as u64),
        ("RtlInterlockedFlushSList", InterlockedFlushSList as *const () as u64),
        ("RtlQueryDepthSList", QueryDepthSList as *const () as u64),
    ]);
    e
}

pub fn kernel32_exports() -> Vec<(&'static str, u64)> {
    export_table![
        EncodePointer,
        DecodePointer,
        FlushInstructionCache,
        InitializeSListHead,
        InterlockedPushEntrySList,
        InterlockedPopEntrySList,
        InterlockedFlushSList,
        QueryDepthSList,
        RtlCompareMemory,
    ]
}
