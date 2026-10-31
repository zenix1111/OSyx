//! ntdll.dll: the NT native API subset OSyx implements, over the same
//! objects and OSyx facilities as kernel32 (files, sections as shared
//! memory, virtual memory, threads, waits, delays), with NTSTATUS results.

#![allow(non_snake_case)]

use crate::error::*;
use crate::kernel32;
use crate::objects::{self, Object};
use crate::{mapping, mem, teb};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// UNICODE_STRING at `p` → String.
///
/// # Safety
/// `p` must point to a valid UNICODE_STRING.
unsafe fn unicode(p: u64) -> Option<String> {
    if p == 0 {
        return None;
    }
    // SAFETY: the caller's UNICODE_STRING (Length, MaximumLength, Buffer).
    unsafe {
        let len: u16 = teb::get(p, 0);
        let buf: u64 = teb::get(p, 8);
        if buf == 0 {
            return Some(String::new());
        }
        let units = core::slice::from_raw_parts(buf as *const u16, len as usize / 2);
        Some(char::decode_utf16(units.iter().copied()).map(|c| c.unwrap_or('\u{FFFD}')).collect())
    }
}

/// OBJECT_ATTRIBUTES (Length, RootDirectory, ObjectName, ...) → the NT
/// name, with the `\??\` DOS-device prefix removed.
///
/// # Safety
/// `oa` must point to a valid OBJECT_ATTRIBUTES.
unsafe fn object_name(oa: u64) -> Option<String> {
    if oa == 0 {
        return None;
    }
    // SAFETY: as above; ObjectName is at offset 16.
    let n = unsafe { unicode(teb::get(oa, 16))? };
    Some(n.strip_prefix("\\??\\").map(String::from).unwrap_or(n))
}

/// IO_STATUS_BLOCK: Status, Information.
fn iosb(p: u64, status: NtStatus, info: u64) {
    if p != 0 {
        // SAFETY: the caller's IO_STATUS_BLOCK.
        unsafe {
            teb::put(p, 0, status as u64);
            teb::put(p, 8, info);
        }
    }
}

fn win32_to_status(e: u32) -> NtStatus {
    match e {
        ERROR_FILE_NOT_FOUND => STATUS_OBJECT_NAME_NOT_FOUND,
        ERROR_PATH_NOT_FOUND => STATUS_OBJECT_PATH_NOT_FOUND,
        ERROR_ACCESS_DENIED => STATUS_ACCESS_DENIED,
        ERROR_INVALID_HANDLE => STATUS_INVALID_HANDLE,
        ERROR_SHARING_VIOLATION => STATUS_SHARING_VIOLATION,
        ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => STATUS_OBJECT_NAME_COLLISION,
        ERROR_INVALID_NAME => STATUS_OBJECT_NAME_INVALID,
        ERROR_NOT_ENOUGH_MEMORY => STATUS_NO_MEMORY,
        ERROR_DISK_FULL => STATUS_DISK_FULL,
        ERROR_DIR_NOT_EMPTY => STATUS_DIRECTORY_NOT_EMPTY,
        ERROR_NOT_SUPPORTED => STATUS_NOT_SUPPORTED,
        _ => STATUS_INVALID_PARAMETER,
    }
}

// NtCreateFile CreateDisposition → CreateFile disposition.
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

extern "win64" fn NtCreateFile(
    handle: *mut u64,
    access: u32,
    oa: u64,
    io: u64,
    _alloc: u64,
    _attrs: u32,
    share: u32,
    disposition: u32,
    options: u32,
    _ea: u64,
    _ea_len: u32,
) -> NtStatus {
    // SAFETY: the caller's OBJECT_ATTRIBUTES.
    let Some(name) = (unsafe { object_name(oa) }) else { return STATUS_INVALID_PARAMETER };
    let disp = match disposition {
        FILE_SUPERSEDE | FILE_OVERWRITE_IF => 2,
        FILE_OPEN => 3,
        FILE_CREATE => 1,
        FILE_OPEN_IF => 4,
        FILE_OVERWRITE => 5,
        _ => return STATUS_INVALID_PARAMETER,
    };
    let mut flags = 0;
    if options & FILE_DIRECTORY_FILE != 0 {
        flags |= 0x0200_0000;
    }
    if options & FILE_DELETE_ON_CLOSE != 0 {
        flags |= 0x0400_0000;
    }
    match kernel32::create_file(&name, access, share, disp, flags) {
        Ok((h, existed)) => {
            // SAFETY: the caller's out pointer.
            unsafe { *handle = h };
            iosb(io, STATUS_SUCCESS, if existed { 1 } else { 2 }); // FILE_OPENED / FILE_CREATED
            STATUS_SUCCESS
        }
        Err(e) => {
            let s = win32_to_status(e);
            iosb(io, s, 0);
            s
        }
    }
}

extern "win64" fn NtOpenFile(handle: *mut u64, access: u32, oa: u64, io: u64, share: u32, options: u32) -> NtStatus {
    NtCreateFile(handle, access, oa, io, 0, 0, share, FILE_OPEN, options, 0, 0)
}

fn byte_offset(p: *const i64) -> Option<u64> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's LARGE_INTEGER.
        let v = unsafe { *p };
        (v >= 0).then_some(v as u64)
    }
}

extern "win64" fn NtReadFile(
    h: u64,
    _event: u64,
    _apc: u64,
    _ctx: u64,
    io: u64,
    buf: *mut u8,
    len: u32,
    offset: *const i64,
    _key: u64,
) -> NtStatus {
    match kernel32::read_handle(h, buf, len, byte_offset(offset)) {
        Ok(0) if len > 0 => {
            iosb(io, STATUS_END_OF_FILE, 0);
            STATUS_END_OF_FILE
        }
        Ok(n) => {
            iosb(io, STATUS_SUCCESS, n as u64);
            STATUS_SUCCESS
        }
        Err(e) => win32_to_status(e),
    }
}

extern "win64" fn NtWriteFile(
    h: u64,
    _event: u64,
    _apc: u64,
    _ctx: u64,
    io: u64,
    buf: *const u8,
    len: u32,
    offset: *const i64,
    _key: u64,
) -> NtStatus {
    match kernel32::write_handle(h, buf, len, byte_offset(offset)) {
        Ok(n) => {
            iosb(io, STATUS_SUCCESS, n as u64);
            STATUS_SUCCESS
        }
        Err(e) => win32_to_status(e),
    }
}

const FILE_BASIC_INFORMATION: u32 = 4;
const FILE_STANDARD_INFORMATION: u32 = 5;
const FILE_POSITION_INFORMATION: u32 = 14;

extern "win64" fn NtQueryInformationFile(h: u64, io: u64, out: *mut u8, len: u32, class: u32) -> NtStatus {
    let f = match objects::file(h) {
        Ok(f) => f,
        Err(_) => return STATUS_INVALID_HANDLE,
    };
    let s = match os_sys::fstat(f.fd) {
        Ok(s) => s,
        Err(e) => return errno_to_status(e),
    };
    let o = out as u64;
    // SAFETY: each branch checks `len` against the structure it writes.
    unsafe {
        match class {
            FILE_BASIC_INFORMATION if len >= 40 => {
                teb::put(o, 0, kernel32::filetime(s.ctime_ns));
                teb::put(o, 8, kernel32::filetime(s.atime_ns));
                teb::put(o, 16, kernel32::filetime(s.mtime_ns));
                teb::put(o, 24, kernel32::filetime(s.ctime_ns));
                teb::put(o, 32, kernel32::attributes(&s));
                iosb(io, STATUS_SUCCESS, 40);
            }
            FILE_STANDARD_INFORMATION if len >= 24 => {
                teb::put(o, 0, s.blocks * 512);
                teb::put(o, 8, s.size);
                teb::put(o, 16, s.nlink);
                teb::put(o, 20, f.delete_on_close.load(Ordering::Relaxed) as u8);
                teb::put(o, 21, f.is_dir as u8);
                iosb(io, STATUS_SUCCESS, 24);
            }
            FILE_POSITION_INFORMATION if len >= 8 => {
                let pos = os_sys::seek(f.fd, 0, osyx_abi::SEEK_CUR).unwrap_or(0);
                teb::put(o, 0, pos);
                iosb(io, STATUS_SUCCESS, 8);
            }
            FILE_BASIC_INFORMATION | FILE_STANDARD_INFORMATION | FILE_POSITION_INFORMATION => {
                return STATUS_INFO_LENGTH_MISMATCH
            }
            _ => return STATUS_INVALID_INFO_CLASS,
        }
    }
    STATUS_SUCCESS
}

extern "win64" fn NtClose(h: u64) -> NtStatus {
    if objects::close(h) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_HANDLE
    }
}

/// Sections of the page file or of a file handle (mapping.rs). Names in
/// the object attributes are not read: NT sections here are unnamed.
const STATUS_SECTION_NOT_IMAGE: NtStatus = 0xC000_0049;
const SEC_FILE: u32 = 0x80_0000;
const SEC_COMMIT: u32 = 0x800_0000;

/// SectionBasicInformation (0): base address (none: sections are not
/// based), allocation attributes and size (24 bytes). Sections here are
/// never images (SectionImageInformation fails as for a data section).
extern "win64" fn NtQuerySection(h: u64, class: u32, out: *mut u8, len: u32, ret: *mut u32) -> NtStatus {
    let Some(Object::Section(s)) = objects::get(h) else { return STATUS_INVALID_HANDLE };
    match class {
        0 => {
            if (len as usize) < 24 || out.is_null() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // SAFETY: the caller's SECTION_BASIC_INFORMATION.
            unsafe {
                core::ptr::write_bytes(out, 0, 24);
                teb::put(out as u64, 8, if s.file.is_some() { SEC_FILE } else { SEC_COMMIT });
                teb::put(out as u64, 16, s.size);
            }
            if !ret.is_null() {
                // SAFETY: the caller's out pointer.
                unsafe { *ret = 24 };
            }
            0
        }
        1 => STATUS_SECTION_NOT_IMAGE,
        _ => STATUS_INVALID_INFO_CLASS,
    }
}

extern "win64" fn NtCreateSection(
    out: *mut u64,
    _access: u32,
    _oa: u64,
    size: *const i64,
    protect: u32,
    attrs: u32,
    file: u64,
) -> NtStatus {
    let size = byte_offset(size).unwrap_or(0);
    match mapping::create((file != 0).then_some(file), protect | (attrs & !0xFF), size, None) {
        Ok((h, _)) => {
            // SAFETY: the caller's out pointer.
            unsafe { *out = h };
            STATUS_SUCCESS
        }
        Err(s) => s,
    }
}

extern "win64" fn NtMapViewOfSection(
    section: u64,
    process: u64,
    base: *mut u64,
    _zero_bits: u64,
    _commit: usize,
    offset: *const i64,
    view_size: *mut usize,
    _inherit: u32,
    _kind: u32,
    protect: u32,
) -> NtStatus {
    if process != objects::CURRENT_PROCESS {
        return STATUS_NOT_SUPPORTED;
    }
    // SAFETY: the caller's in/out pointers.
    if !base.is_null() && unsafe { *base } != 0 {
        return STATUS_NOT_SUPPORTED; // placement at a chosen address
    }
    let access = match protect & 0xFF {
        mem::PAGE_READWRITE => mapping::FILE_MAP_WRITE | mapping::FILE_MAP_READ,
        mem::PAGE_WRITECOPY => mapping::FILE_MAP_COPY,
        mem::PAGE_EXECUTE_READ => mapping::FILE_MAP_EXECUTE | mapping::FILE_MAP_READ,
        _ => mapping::FILE_MAP_READ,
    };
    // SAFETY: as above.
    let len = if view_size.is_null() { 0 } else { (unsafe { *view_size }) as u64 };
    match mapping::map(section, access, byte_offset(offset).unwrap_or(0), len) {
        Ok((p, size)) => {
            // SAFETY: the caller's in/out pointers.
            unsafe {
                *base = p;
                if !view_size.is_null() {
                    *view_size = size as usize;
                }
            }
            STATUS_SUCCESS
        }
        Err(s) => s,
    }
}

extern "win64" fn NtUnmapViewOfSection(process: u64, base: u64) -> NtStatus {
    if process != objects::CURRENT_PROCESS {
        return STATUS_NOT_SUPPORTED;
    }
    match mapping::unmap(base) {
        Ok(()) => STATUS_SUCCESS,
        Err(s) => s,
    }
}

extern "win64" fn NtAllocateVirtualMemory(
    process: u64,
    base: *mut u64,
    _zero_bits: u64,
    size: *mut usize,
    kind: u32,
    protect: u32,
) -> NtStatus {
    if process != objects::CURRENT_PROCESS || base.is_null() || size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's in/out pointers.
    unsafe {
        match mem::virtual_alloc(*base, *size, kind, protect) {
            Ok(b) => {
                *base = b;
                *size = (*size).next_multiple_of(mem::PAGE);
                STATUS_SUCCESS
            }
            Err(s) => s,
        }
    }
}

extern "win64" fn NtFreeVirtualMemory(process: u64, base: *mut u64, size: *mut usize, kind: u32) -> NtStatus {
    if process != objects::CURRENT_PROCESS || base.is_null() || size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's pointers.
    unsafe { mem::virtual_free(*base, *size, kind).err().unwrap_or(STATUS_SUCCESS) }
}

extern "win64" fn NtProtectVirtualMemory(
    process: u64,
    base: *mut u64,
    size: *mut usize,
    protect: u32,
    old: *mut u32,
) -> NtStatus {
    if process != objects::CURRENT_PROCESS || base.is_null() || size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's pointers.
    unsafe {
        match mem::virtual_protect(*base, *size, protect) {
            Ok(o) => {
                if !old.is_null() {
                    *old = o;
                }
                STATUS_SUCCESS
            }
            Err(s) => s,
        }
    }
}

extern "win64" fn NtQueryVirtualMemory(
    process: u64,
    addr: u64,
    class: u32,
    out: *mut u8,
    len: usize,
    ret: *mut usize,
) -> NtStatus {
    if process != objects::CURRENT_PROCESS {
        return STATUS_NOT_SUPPORTED;
    }
    if class != 0 {
        return STATUS_INVALID_INFO_CLASS; // MemoryBasicInformation only
    }
    if out.is_null() || len < 48 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    match mem::virtual_query(addr) {
        Some(i) => {
            kernel32::write_mbi(out, &i);
            if !ret.is_null() {
                // SAFETY: the caller's out pointer.
                unsafe { *ret = 48 };
            }
            STATUS_SUCCESS
        }
        None => STATUS_INVALID_PARAMETER,
    }
}

extern "win64" fn NtCreateThreadEx(
    out: *mut u64,
    _access: u32,
    _oa: u64,
    process: u64,
    start: u64,
    arg: u64,
    flags: u32,
    _zero_bits: usize,
    _stack_commit: usize,
    stack_reserve: usize,
    _attrs: u64,
) -> NtStatus {
    if process != objects::CURRENT_PROCESS || start == 0 || out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let size = kernel32::stack_reserve(stack_reserve, true);
    match kernel32::spawn_thread(start, arg, size, flags & 1 != 0) {
        Ok(t) => {
            // SAFETY: the caller's out pointer.
            unsafe { *out = objects::insert(Object::Thread(t)) };
            STATUS_SUCCESS
        }
        Err(_) => STATUS_NO_MEMORY,
    }
}

/// Timeouts: negative = relative, in 100 ns units; NULL = forever.
pub(crate) fn timeout_ms(t: *const i64) -> Result<u32, NtStatus> {
    if t.is_null() {
        return Ok(objects::INFINITE);
    }
    // SAFETY: the caller's LARGE_INTEGER.
    let v = unsafe { *t };
    let units = if v > 0 {
        let ns = os_sys::clock(osyx_abi::CLOCK_REALTIME).map_err(errno_to_status)? as i64;
        (v as u64).saturating_sub(kernel32::filetime(ns))
    } else { v.unsigned_abs() };
    Ok(units.div_ceil(10_000).min(objects::INFINITE as u64 - 1) as u32)
}

extern "win64" fn NtWaitForSingleObject(h: u64, _alertable: u8, timeout: *const i64) -> NtStatus {
    let ms = match timeout_ms(timeout) {
        Ok(ms) => ms,
        Err(s) => return s,
    };
    match objects::wait(&[h], false, ms) {
        Ok(objects::WAIT_TIMEOUT) => STATUS_TIMEOUT,
        Ok(r) => r,
        Err(_) => STATUS_INVALID_HANDLE,
    }
}

extern "win64" fn NtDelayExecution(_alertable: u8, interval: *const i64) -> NtStatus {
    match timeout_ms(interval) {
        Ok(objects::INFINITE) => loop {
            os_std::thread::sleep(core::time::Duration::from_secs(3600));
        },
        Ok(0) => os_std::thread::yield_now(),
        Ok(ms) => os_std::thread::sleep(core::time::Duration::from_millis(ms as u64)),
        Err(s) => return s,
    }
    STATUS_SUCCESS
}

const PROCESS_BASIC_INFORMATION: u32 = 0;

extern "win64" fn NtQueryInformationProcess(
    process: u64,
    class: u32,
    out: *mut u8,
    len: u32,
    ret: *mut u32,
) -> NtStatus {
    if process != objects::CURRENT_PROCESS {
        return STATUS_NOT_SUPPORTED;
    }
    if class != PROCESS_BASIC_INFORMATION {
        return STATUS_INVALID_INFO_CLASS;
    }
    if out.is_null() || len < 48 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: PROCESS_BASIC_INFORMATION is 48 bytes (checked).
    unsafe {
        core::ptr::write_bytes(out, 0, 48);
        teb::put(out as u64, 0, 259u64); // ExitStatus: STILL_ACTIVE
        teb::put(out as u64, 8, teb::peb());
        teb::put(out as u64, 16, 1u64); // affinity
        teb::put(out as u64, 24, 8u64); // base priority
        teb::put(out as u64, 32, kernel32::pid());
        if !ret.is_null() {
            *ret = 48;
        }
    }
    STATUS_SUCCESS
}

extern "win64" fn NtTerminateProcess(process: u64, status: u32) -> NtStatus {
    if process == objects::CURRENT_PROCESS || process == 0 {
        kernel32::ExitProcess(status);
    }
    STATUS_ACCESS_DENIED
}

extern "win64" fn NtQuerySystemTime(out: *mut u64) -> NtStatus {
    if out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let ns = os_sys::clock(osyx_abi::CLOCK_REALTIME).unwrap_or(0) as i64;
    // SAFETY: the caller's LARGE_INTEGER.
    unsafe { *out = kernel32::filetime(ns) };
    STATUS_SUCCESS
}

extern "win64" fn RtlNtStatusToDosError(s: NtStatus) -> u32 {
    status_to_win32(s)
}

extern "win64" fn RtlGetLastWin32Error() -> u32 {
    teb::last_error()
}

extern "win64" fn RtlSetLastWin32Error(e: u32) {
    teb::set_last_error(e)
}

extern "win64" fn RtlGetCurrentPeb() -> u64 {
    teb::peb()
}

/// RTL_OSVERSIONINFOW: the presented Windows version (10.0.19041).
extern "win64" fn RtlGetVersion(info: *mut u8) -> NtStatus {
    if info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the structure starts with its size and holds the 4 DWORDs written.
    unsafe {
        teb::put(info as u64, 4, 10u32);
        teb::put(info as u64, 8, 0u32);
        teb::put(info as u64, 12, 19041u32);
        teb::put(info as u64, 16, 2u32);
    }
    STATUS_SUCCESS
}


const STATUS_NOT_FOUND: NtStatus = 0xC000_0225;
const STATUS_INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010;

/// Nothing is ever pending (kernel32's CancelIoEx says the same).
extern "win64" fn NtCancelIoFileEx(h: u64, _io: u64, _status: u64) -> NtStatus {
    if objects::get(h).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    STATUS_NOT_FOUND
}

/// No device controls are implemented for OSyx's files and devices.
#[allow(clippy::too_many_arguments)]
extern "win64" fn NtDeviceIoControlFile(h: u64, _e: u64, _apc: u64, _ctx: u64, _io: u64, _code: u32, _i: u64, _il: u32, _o: u64, _ol: u32) -> NtStatus {
    if objects::get(h).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    STATUS_INVALID_DEVICE_REQUEST
}

const STATUS_NO_MORE_ENTRIES: NtStatus = 0x8000_001A;
const STATUS_OBJECT_PATH_SYNTAX_BAD: NtStatus = 0xC000_003B;
const STATUS_ACCESS_VIOLATION: NtStatus = 0xC000_0005;
const STATUS_MORE_ENTRIES: NtStatus = 0x0000_0105;
const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;
const DIRECTORY_QUERY: u32 = 1;

/// The object namespace OSyx offers: the root, holding `BaseNamedObjects`,
/// which holds the named events, mutexes, semaphores, timers and sections
/// of the process.
fn directory_path(name: &str) -> Option<&'static str> {
    match name.trim_end_matches('\\').to_ascii_lowercase().as_str() {
        "" => Some("\\"),
        "\\basenamedobjects" => Some("\\BaseNamedObjects"),
        _ => None,
    }
}

/// NtOpenDirectoryObject(&handle, access, &OBJECT_ATTRIBUTES): opens `\\` or
/// `\\BaseNamedObjects` (also relative to an open directory).
extern "win64" fn NtOpenDirectoryObject(handle: *mut u64, _access: u32, oa: u64) -> NtStatus {
    if handle.is_null() || oa == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: an OBJECT_ATTRIBUTES: RootDirectory at 8, ObjectName at 16.
    let (root, name_ptr) = unsafe { (core::ptr::read_unaligned((oa + 8) as *const u64), core::ptr::read_unaligned((oa + 16) as *const u64)) };
    if name_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: a UNICODE_STRING: Length at 0, Buffer at 8.
    let name = unsafe {
        let len = core::ptr::read_unaligned(name_ptr as *const u16) as usize / 2;
        let buf = core::ptr::read_unaligned((name_ptr + 8) as *const u64) as *const u16;
        if buf.is_null() { String::new() } else { String::from_utf16_lossy(core::slice::from_raw_parts(buf, len)) }
    };
    let full = if root != 0 {
        let Some(Object::Directory(d)) = objects::get(root) else { return STATUS_INVALID_HANDLE };
        alloc::format!("{}\\{}", d.path.trim_end_matches('\\'), name)
    } else {
        if !name.starts_with('\\') {
            return STATUS_OBJECT_PATH_SYNTAX_BAD;
        }
        name
    };
    let Some(path) = directory_path(&full) else { return STATUS_OBJECT_NAME_NOT_FOUND };
    // SAFETY: the caller's out pointer.
    unsafe { *handle = objects::insert(Object::Directory(alloc::sync::Arc::new(objects::DirectoryObj { path: String::from(path) }))) };
    0
}

/// The (name, type) entries of a directory.
fn directory_entries(path: &str) -> Vec<(String, &'static str)> {
    if path == "\\" {
        alloc::vec![(String::from("BaseNamedObjects"), "Directory")]
    } else {
        objects::named_objects()
    }
}

/// NtQueryDirectoryObject: an array of OBJECT_DIRECTORY_INFORMATION (a name
/// and a type name, both UNICODE_STRINGs) ended by a zero entry, then the
/// strings. `ctx` is the index of the next entry: it counts up as entries
/// are returned and `restart` sets it back to 0. STATUS_MORE_ENTRIES means
/// more remain after those that fit, STATUS_NO_MORE_ENTRIES that none are
/// left, STATUS_BUFFER_TOO_SMALL that not even one fits (`ret` has the size
/// that one needs).
#[allow(clippy::too_many_arguments)]
extern "win64" fn NtQueryDirectoryObject(h: u64, buf: u64, len: u32, single: u8, restart: u8, ctx: *mut u32, ret: *mut u32) -> NtStatus {
    let Some(Object::Directory(dir)) = objects::get(h) else { return STATUS_INVALID_HANDLE };
    if ctx.is_null() {
        return STATUS_ACCESS_VIOLATION;
    }
    let entries = directory_entries(&dir.path);
    // SAFETY: the caller's context word.
    let start = if restart != 0 { 0 } else { unsafe { *ctx } } as usize;
    if start >= entries.len() {
        // SAFETY: the caller's context word.
        unsafe { *ctx = start as u32 };
        return STATUS_NO_MORE_ENTRIES;
    }
    // Bytes of one entry's strings, with their NULs, and the fixed part: the
    // entries so far plus the terminating zero entry.
    let strings = |e: &(String, &'static str)| (e.0.encode_utf16().count() + 1) * 2 + (e.1.encode_utf16().count() + 1) * 2;
    let want = if single != 0 { 1 } else { entries.len() - start };
    let mut fit = 0usize;
    let mut need = 32usize;
    for e in entries[start..].iter().take(want) {
        let next = need + 32 + strings(e);
        if next > len as usize && fit > 0 {
            break;
        }
        need = next;
        fit += 1;
        if next > len as usize {
            break;
        }
    }
    if buf == 0 || need > len as usize {
        if !ret.is_null() {
            // SAFETY: the caller's out pointer.
            unsafe { *ret = need as u32 };
        }
        return STATUS_BUFFER_TOO_SMALL;
    }
    let mut text = buf + 32 * (fit as u64 + 1);
    // SAFETY: the caller's buffer holds `len` bytes, of which `need` are used.
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, 32 * (fit + 1));
        for (i, e) in entries[start..start + fit].iter().enumerate() {
            let at = buf + 32 * i as u64;
            for (k, s) in [(0u64, e.0.as_str()), (16, e.1)] {
                let units: Vec<u16> = s.encode_utf16().collect();
                let bytes = units.len() * 2;
                core::ptr::copy_nonoverlapping(units.as_ptr() as *const u8, text as *mut u8, bytes);
                core::ptr::write_unaligned((text + bytes as u64) as *mut u16, 0);
                core::ptr::write_unaligned((at + k) as *mut u16, bytes as u16);
                core::ptr::write_unaligned((at + k + 2) as *mut u16, bytes as u16 + 2);
                core::ptr::write_unaligned((at + k + 8) as *mut u64, text);
                text += bytes as u64 + 2;
            }
        }
        *ctx = (start + fit) as u32;
        if !ret.is_null() {
            *ret = need as u32;
        }
    }
    if start + fit < entries.len() && single == 0 { STATUS_MORE_ENTRIES } else { 0 }
}

/// SystemBasicInformation (0) and SystemProcessorPerformanceInformation
/// (8) from the kernel's memory and scheduler counters; other classes are
/// not available.
extern "win64" fn NtQuerySystemInformation(class: u32, buf: *mut u8, len: u32, ret: *mut u32) -> NtStatus {
    let Ok(info) = os_sys::sysinfo() else { return STATUS_UNSUCCESSFUL };
    let need: u32 = match class {
        0 => 64,
        8 => 48,
        _ => return STATUS_INVALID_INFO_CLASS,
    };
    if !ret.is_null() {
        // SAFETY: the caller's out length.
        unsafe { *ret = need };
    }
    if buf.is_null() || len != need {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    let p = buf as u64;
    // SAFETY: the caller's buffer of `need` bytes.
    unsafe {
        core::ptr::write_bytes(buf, 0, need as usize);
        match class {
            0 => {
                teb::put(p, 4, 156_250u32); // timer resolution: 15.625 ms in 100 ns units
                teb::put(p, 8, 4096u32);
                teb::put(p, 12, (info.total_memory / 4096) as u32);
                teb::put(p, 16, 1u32);
                teb::put(p, 20, (info.total_memory / 4096) as u32);
                teb::put(p, 24, 0x10000u32);
                teb::put(p, 32, 0x10000u64);
                teb::put(p, 40, 0x7FFF_FFFE_FFFFu64);
                teb::put(p, 48, 1u64);
                teb::put(p, 56, 1u8);
            }
            _ => {
                // Samples are 1 ms; kernel time includes idle time.
                let idle = info.idle_ticks * 10_000;
                let busy = info.ticks.saturating_sub(info.idle_ticks) * 10_000;
                teb::put(p, 0, idle);
                teb::put(p, 8, idle);
                teb::put(p, 16, busy);
            }
        }
    }
    STATUS_SUCCESS
}

/// DOS path → "\??\C:\..." NT path in a process-heap UNICODE_STRING
/// (RtlFreeUnicodeString frees it), with the file part pointed to.
extern "win64" fn RtlDosPathNameToNtPathName_U_WithStatus(dos: *const u16, nt: *mut u8, file_part: *mut u64, relative: *mut u8) -> NtStatus {
    if nt.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: a NUL-terminated name.
    let Some(name) = (unsafe { crate::path::wide_to_string(dos) }) else { return STATUS_OBJECT_NAME_INVALID };
    let full = match kernel32::full_path(Some(name)) {
        Ok(f) => f,
        Err(_) => return STATUS_OBJECT_NAME_INVALID,
    };
    let text = alloc::format!("{0}??{0}{full}", BACKSLASH);
    let w: Vec<u16> = text.encode_utf16().chain(core::iter::once(0)).collect();
    let Some(p) = kernel32::heap_alloc(w.len() * 2, false) else { return STATUS_NO_MEMORY };
    // SAFETY: a fresh block for the string; the caller's structures.
    unsafe {
        core::ptr::copy_nonoverlapping(w.as_ptr(), p as *mut u16, w.len());
        teb::put(nt as u64, 0, ((w.len() - 1) * 2) as u16);
        teb::put(nt as u64, 2, (w.len() * 2) as u16);
        teb::put(nt as u64, 8, p);
        if !file_part.is_null() {
            let last = text.rfind(BACKSLASH).map_or(0, |i| text[..=i].encode_utf16().count());
            *file_part = if last < w.len() - 1 { p + last as u64 * 2 } else { 0 };
        }
        if !relative.is_null() {
            core::ptr::write_bytes(relative, 0, 32); // RTL_RELATIVE_NAME_U: none
        }
    }
    STATUS_SUCCESS
}

const BACKSLASH: char = '\\';

pub fn exports() -> Vec<(&'static str, u64)> {
    let mut exports=export_table![
        NtCreateFile,
        NtOpenFile,
        NtReadFile,
        NtWriteFile,
        NtQueryInformationFile,
        NtClose,
        NtCreateSection,
        NtQuerySection,
        NtMapViewOfSection,
        NtUnmapViewOfSection,
        NtAllocateVirtualMemory,
        NtFreeVirtualMemory,
        NtProtectVirtualMemory,
        NtQueryVirtualMemory,
        NtCreateThreadEx,
        NtWaitForSingleObject,
        NtDelayExecution,
        NtQueryInformationProcess,
        NtTerminateProcess,
        NtQuerySystemTime,
        RtlNtStatusToDosError,
        RtlGetLastWin32Error,
        RtlSetLastWin32Error,
        RtlGetCurrentPeb,
        RtlGetVersion,
        NtCancelIoFileEx,
        NtDeviceIoControlFile,
        NtOpenDirectoryObject,
        NtQueryDirectoryObject,
        NtQuerySystemInformation,
        RtlDosPathNameToNtPathName_U_WithStatus,
    ];
    exports.extend(crate::exceptions::native_exports());
    exports.extend(crate::rtl::ntdll_exports());
    exports.extend(crate::unwind::ntdll_exports());
    exports.extend(crate::sysext::ntdll_exports());
    exports.extend(crate::seh::ntdll_exports());
    exports.extend(crate::process::ntdll_exports());
    exports.extend(crate::keyed::exports());
    exports
}
