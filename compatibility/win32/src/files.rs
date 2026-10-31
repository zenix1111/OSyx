//! File APIs of the newer Win32 surface (msvcp140's std::filesystem and
//! zen.exe use them): CreateFile2, CopyFile2/CopyFileW, extended
//! attribute and handle information, symbolic links.
//!
//! OSyx's file systems keep POSIX metadata: only the read-only attribute
//! maps to something stored (the owner write bit); setting timestamps,
//! hidden/system attributes and hard links are not supported by the
//! kernel interface and fail with ERROR_NOT_SUPPORTED.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{self, fail},
    objects, path, teb,
};
use alloc::{string::String, vec::Vec};
use core::sync::atomic::Ordering;

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

fn name(p: *const u16) -> Option<String> {
    // SAFETY: NULL or a NUL-terminated string from the caller.
    unsafe { path::wide_to_string(p) }
}

/// (OSyx path, stat) of an existing Windows path.
fn stat_of(win: &str) -> Result<(String, osyx_abi::FileStat), u32> {
    match kernel32::locate(win)? {
        (p, true) => {
            path::note_stat(&p, "stat_of");
            let st = os_sys::stat(&p).map_err(errno_to_win32)?;
            Ok((p, st))
        }
        _ => Err(ERROR_FILE_NOT_FOUND),
    }
}

extern "win64" fn AreFileApisANSI() -> i32 {
    1 // SetFileApisToOEM is not offered: file APIs always use the ANSI code page.
}

/// CREATEFILE2_EXTENDED_PARAMETERS: size, attributes, flags, security QoS,
/// security attributes, template.
extern "win64" fn CreateFile2(name_w: *const u16, access: u32, share: u32, disposition: u32, params: *const u8) -> u64 {
    let mut flags = 0;
    if !params.is_null() {
        // SAFETY: the caller's structure.
        unsafe {
            if teb::get::<u32>(params as u64, 0) < 32 {
                return fail(ERROR_INVALID_PARAMETER, u64::MAX);
            }
            flags = teb::get::<u32>(params as u64, 4) | teb::get::<u32>(params as u64, 8);
            if let Err(e) = crate::security::validate_attributes(teb::get::<u64>(params as u64, 16)) {
                return fail(e, u64::MAX);
            }
            if teb::get::<u64>(params as u64, 24) != 0 {
                return fail(ERROR_NOT_SUPPORTED, u64::MAX); // template files
            }
        }
    }
    kernel32::create_file_common(name(name_w), access, share, disposition, flags)
}

/// Copies data and the read-only bit; `fail_if_exists` like CopyFileW.
fn copy(from: &str, to: &str, fail_if_exists: bool) -> Result<(), u32> {
    let (src, st) = stat_of(from)?;
    if st.kind == osyx_abi::KIND_DIR {
        return Err(ERROR_ACCESS_DENIED);
    }
    let dst = path::to_osyx(to, &kernel32::cwd_win())?;
    if fail_if_exists && os_sys::stat(&dst).is_ok() {
        return Err(ERROR_FILE_EXISTS);
    }
    let input = os_sys::open(&src, osyx_abi::OPEN_READ, 0).map_err(errno_to_win32)?;
    let output = match os_sys::open(&dst, osyx_abi::OPEN_WRITE | osyx_abi::OPEN_CREATE | osyx_abi::OPEN_TRUNCATE, st.mode | 0o200) {
        Ok(h) => h,
        Err(e) => {
            let _ = os_sys::close(input);
            return Err(errno_to_win32(e));
        }
    };
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let mut result = Ok(());
    loop {
        match os_sys::read_raw(input, buf.as_mut_ptr() as usize, buf.len()) {
            Ok(0) => break,
            Ok(n) => {
                let mut done = 0;
                while done < n {
                    match os_sys::write_raw(output, buf.as_ptr() as usize + done, n - done) {
                        Ok(w) if w > 0 => done += w,
                        Ok(_) => {
                            result = Err(ERROR_DISK_FULL);
                            break;
                        }
                        Err(e) => {
                            result = Err(errno_to_win32(e));
                            break;
                        }
                    }
                }
                if result.is_err() {
                    break;
                }
            }
            Err(e) => {
                result = Err(errno_to_win32(e));
                break;
            }
        }
    }
    let _ = os_sys::close(input);
    let _ = os_sys::close(output);
    if result.is_ok() && st.mode & 0o200 == 0 {
        result = os_sys::chmod(&dst, st.mode).map_err(errno_to_win32);
    }
    if result.is_err() {
        let _ = os_sys::unlink(&dst);
    }
    result
}

extern "win64" fn CopyFileW(from: *const u16, to: *const u16, fail_if_exists: i32) -> i32 {
    let (Some(f), Some(t)) = (name(from), name(to)) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    match copy(&f, &t, fail_if_exists != 0) {
        Ok(()) => 1,
        Err(e) => fail(e, 0),
    }
}

const COPY_FILE_FAIL_IF_EXISTS: u32 = 0x1;

/// CopyFileEx: the copy is one step, so a progress routine is called once
/// with the whole size when it is done (PROGRESS_CANCEL or _STOP then
/// removes the copy, as an interrupted copy would).
extern "win64" fn CopyFileExW(from: *const u16, to: *const u16, progress: u64, data: u64, cancel: *const i32, flags: u32) -> i32 {
    if flags & !COPY_FILE_FAIL_IF_EXISTS != 0 {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    // SAFETY: NULL or the caller's cancel flag.
    if !cancel.is_null() && unsafe { *cancel } != 0 {
        return fail(ERROR_REQUEST_ABORTED, 0);
    }
    let (Some(f), Some(t)) = (name(from), name(to)) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    if let Err(e) = copy(&f, &t, flags & COPY_FILE_FAIL_IF_EXISTS != 0) {
        return fail(e, 0);
    }
    if progress != 0 {
        let size = stat_of(&t).map_or(0, |(_, st)| st.size as i64);
        type Progress = extern "win64" fn(i64, i64, i64, i64, u32, u32, u64, u64, u64) -> u32;
        // SAFETY: the caller's LPPROGRESS_ROUTINE.
        let f: Progress = unsafe { core::mem::transmute(progress as usize) };
        // CALLBACK_CHUNK_FINISHED (0), stream 1, no handles.
        if matches!(f(size, size, size, size, 1, 0, 0, 0, data), 1 | 2) {
            if let Ok((p, true)) = kernel32::locate(&t) {
                let _ = os_sys::unlink(&p);
            }
            return fail(ERROR_REQUEST_ABORTED, 0);
        }
    }
    1
}

/// ReplaceFile: `replacement` takes `replaced`'s name, after `replaced`
/// is moved to `backup` when one is given. Attributes and ACLs are not
/// merged (OSyx keeps only the read-only bit).
extern "win64" fn ReplaceFileA(replaced: *const u8, replacement: *const u8, backup: *const u8, flags: u32, _e: u64, _r: u64) -> i32 {
    // SAFETY: NULL or NUL-terminated names.
    let (Some(old), Some(new), b) = (unsafe { path::ansi_to_string(replaced) }, unsafe { path::ansi_to_string(replacement) }, unsafe { path::ansi_to_string(backup) }) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    if flags & !0x6 != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if stat_of(&old).is_err() {
        return fail(1176, 0); // ERROR_UNABLE_TO_REMOVE_REPLACED
    }
    if stat_of(&new).is_err() {
        return fail(ERROR_FILE_NOT_FOUND, 0);
    }
    if let Some(b) = b {
        if kernel32::move_file(Some(old.clone()), Some(b), 1) == 0 {
            return fail(1176, 0);
        }
    }
    if kernel32::move_file(Some(new), Some(old), 1) == 0 {
        return fail(1177, 0); // ERROR_UNABLE_TO_MOVE_REPLACEMENT
    }
    1
}

/// OSyx file systems have no 8.3 names: the long and the short form of an
/// existing path are the path itself.
fn same_name(src: *const u16, buf: *mut u16, len: u32) -> u32 {
    let Some(n) = name(src) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    if let Err(e) = stat_of(&n) {
        return fail(e, 0);
    }
    kernel32::out_w(&n, buf, len)
}

extern "win64" fn GetLongPathNameW(src: *const u16, buf: *mut u16, len: u32) -> u32 {
    same_name(src, buf, len)
}

extern "win64" fn GetShortPathNameW(src: *const u16, buf: *mut u16, len: u32) -> u32 {
    same_name(src, buf, len)
}

/// The path an open handle was opened with, in DOS form (with the
/// long-path prefix), NT device form (HarddiskVolume1) or volume-relative.
extern "win64" fn GetFinalPathNameByHandleW(h: u64, buf: *mut u16, len: u32, flags: u32) -> u32 {
    let f = match objects::file(h) {
        Ok(f) if !f.path.is_empty() => f,
        Ok(_) => return fail(ERROR_INVALID_FUNCTION, 0), // a pipe
        Err(e) => return fail(e, 0),
    };
    let win = path::to_windows(&f.path);
    let rest = win.get(2..).unwrap_or("\\");
    let s = match flags & 0x7 {
        0 => alloc::format!("\\\\?\\{win}"), // VOLUME_NAME_DOS
        2 => alloc::format!("\\Device\\HarddiskVolume1{rest}"), // VOLUME_NAME_NT
        4 => String::from(rest), // VOLUME_NAME_NONE
        _ => return fail(ERROR_NOT_SUPPORTED, 0), // VOLUME_NAME_GUID
    };
    kernel32::out_w(&s, buf, len)
}

/// COPYFILE2_EXTENDED_PARAMETERS: size, flags, cancel flag, progress
/// routine, context. Returns an HRESULT.
extern "win64" fn CopyFile2(from: *const u16, to: *const u16, params: *const u8) -> u32 {
    let mut flags = 0;
    if !params.is_null() {
        // SAFETY: the caller's structure.
        unsafe {
            flags = teb::get::<u32>(params as u64, 4);
            if teb::get::<u64>(params as u64, 16) != 0 {
                return 0x8000_4001; // E_NOTIMPL: progress callbacks
            }
            let cancel = teb::get::<u64>(params as u64, 8);
            if cancel != 0 && *(cancel as *const i32) != 0 {
                return 0x8007_04c7; // HRESULT_FROM_WIN32(ERROR_CANCELLED)
            }
        }
        if flags & !COPY_FILE_FAIL_IF_EXISTS != 0 {
            return 0x8007_0032; // HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)
        }
    }
    let (Some(f), Some(t)) = (name(from), name(to)) else { return 0x8007_0057 };
    match copy(&f, &t, flags & COPY_FILE_FAIL_IF_EXISTS != 0) {
        Ok(()) => 0,
        Err(e) => 0x8007_0000 | e,
    }
}

/// CreateHardLinkW(new, existing, reserved): a second name for a file.
/// Errors are those of Windows: an existing target name is
/// ERROR_ALREADY_EXISTS, a missing source ERROR_FILE_NOT_FOUND, a directory
/// source ERROR_ACCESS_DENIED, another volume ERROR_NOT_SAME_DEVICE and a
/// volume without hard links (FAT) ERROR_INVALID_FUNCTION.
extern "win64" fn CreateHardLinkW(new: *const u16, existing: *const u16, sa: u64) -> i32 {
    if let Err(e) = crate::security::validate_attributes(sa) {
        return fail(e, 0);
    }
    // SAFETY: NUL-terminated names.
    let (Some(new), Some(existing)) = (unsafe { kernel32::sw(new) }, unsafe { kernel32::sw(existing) }) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    let src = match kernel32::locate(&existing) {
        Ok((p, true)) => p,
        Ok((_, false)) => return fail(ERROR_FILE_NOT_FOUND, 0),
        Err(e) => return fail(e, 0),
    };
    let (dst, exists) = match kernel32::locate(&new) {
        Ok(x) => x,
        Err(e) => return fail(e, 0),
    };
    if exists {
        return fail(ERROR_ALREADY_EXISTS, 0);
    }
    if os_sys::lstat(&src).is_ok_and(|s| s.kind == osyx_abi::KIND_DIR) {
        return fail(ERROR_ACCESS_DENIED, 0);
    }
    match os_sys::link(&src, &dst) {
        Ok(()) => 1,
        Err(osyx_abi::Errno::NotSupported) => fail(ERROR_INVALID_FUNCTION, 0),
        Err(osyx_abi::Errno::NotFound) => fail(ERROR_PATH_NOT_FOUND, 0),
        Err(e) => fail(errno_to_win32(e), 0),
    }
}

const SYMBOLIC_LINK_FLAG_DIRECTORY: u32 = 0x1;
const SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE: u32 = 0x2;

/// The link stores its target as an OSyx path (relative targets stay
/// relative, with '/' separators).
extern "win64" fn CreateSymbolicLinkW(link: *const u16, target: *const u16, flags: u32) -> u8 {
    if flags & !(SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let (Some(l), Some(t)) = (name(link), name(target)) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let at = match path::to_osyx(&l, &kernel32::cwd_win()) {
        Ok(p) => p,
        Err(e) => return fail(e, 0),
    };
    let absolute = t.starts_with(['\\', '/']) || t.as_bytes().get(1) == Some(&b':');
    let to = if absolute {
        match path::to_osyx(&t, &kernel32::cwd_win()) {
            Ok(p) => p,
            Err(e) => return fail(e, 0),
        }
    } else {
        t.replace('\\', "/")
    };
    match os_sys::symlink(&to, &at) {
        Ok(()) => 1,
        Err(e) => fail(errno_to_win32(e), 0),
    }
}

/// FINDEX_INFO_LEVELS: standard (0) and basic (1, no short names, which
/// OSyx never has); FINDEX_SEARCH_OPS: name match (0) and the advisory
/// directory filter (1).
extern "win64" fn FindFirstFileExW(pattern: *const u16, level: u32, data: u64, op: u32, filter: u64, flags: u32) -> u64 {
    if level > 1 || op > 1 || filter != 0 || flags & !0x7 != 0 {
        return fail(ERROR_INVALID_PARAMETER, u64::MAX);
    }
    if flags & 0x1 != 0 {
        return fail(ERROR_NOT_SUPPORTED, u64::MAX); // FIND_FIRST_EX_CASE_SENSITIVE
    }
    crate::volumes::FindFirstFileW(pattern, data)
}

/// WIN32_FILE_ATTRIBUTE_DATA: attributes, creation, access and write
/// times, size high and low.
extern "win64" fn GetFileAttributesExW(name_w: *const u16, level: u32, out: u64) -> i32 {
    if level != 0 || out == 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(n) = name(name_w) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let st = match stat_of(&n) {
        Ok((_, st)) => st,
        Err(e) => {
            if kernel32::TRACE.load(core::sync::atomic::Ordering::Relaxed) {
                os_std::eprintln!("winrun: GetFileAttributesExW({n}) failed: {e}");
            }
            return fail(e, 0);
        }
    };
    // SAFETY: the caller's 36-byte structure.
    unsafe {
        teb::put(out, 0, kernel32::attributes(&st));
        teb::put(out, 4, kernel32::filetime(st.ctime_ns));
        teb::put(out, 12, kernel32::filetime(st.atime_ns));
        teb::put(out, 20, kernel32::filetime(st.mtime_ns));
        teb::put(out, 28, (st.size >> 32) as u32);
        teb::put(out, 32, st.size as u32);
    }
    1
}

extern "win64" fn GetFileAttributesExA(name_a: *const u8, level: u32, out: u64) -> i32 {
    // SAFETY: NULL or a NUL-terminated string from the caller.
    let Some(w) = (unsafe { path::ansi_to_wide(name_a) }) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    GetFileAttributesExW(w.as_ptr(), level, out)
}

// ---- byte-range locks ------------------------------------------------------------
//
// Locks belong to a file object (all handles duplicated from one open) and
// are released when it closes. Like the sharing modes they are kept in
// this process: they order the threads of one Windows program, as SQLite
// and NSPR need, but neither bind other processes nor make ReadFile and
// WriteFile fail inside a region another handle locked.

struct Lock {
    owner: usize,
    start: u64,
    len: u64,
    exclusive: bool,
}

static LOCKS: os_std::sync::Mutex<alloc::collections::BTreeMap<(u64, u64), Vec<Lock>>> =
    os_std::sync::Mutex::new(alloc::collections::BTreeMap::new());

const LOCKFILE_FAIL_IMMEDIATELY: u32 = 1;
const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;

fn overlaps(a: u64, alen: u64, b: u64, blen: u64) -> bool {
    alen != 0 && blen != 0 && a < b.saturating_add(blen) && b < a.saturating_add(alen)
}

/// The file object behind `h`: (sharing key, owner identity).
fn lock_target(h: u64) -> Result<(alloc::sync::Arc<objects::FileObj>, usize), u32> {
    let f = objects::file(h)?;
    let owner = alloc::sync::Arc::as_ptr(&f) as usize;
    Ok((f, owner))
}

fn lock(h: u64, start: u64, len: u64, exclusive: bool, wait: bool) -> Result<(), u32> {
    let (f, owner) = lock_target(h)?;
    loop {
        {
            let mut all = LOCKS.lock().unwrap();
            let list = all.entry(f.key).or_default();
            // Exclusive locks overlap nothing; shared ones overlap only shared.
            if !list.iter().any(|l| overlaps(l.start, l.len, start, len) && (exclusive || l.exclusive)) {
                list.push(Lock { owner, start, len, exclusive });
                return Ok(());
            }
        }
        if !wait {
            return Err(ERROR_LOCK_VIOLATION);
        }
        os_sys::sleep(1_000_000);
    }
}

fn unlock(h: u64, start: u64, len: u64) -> Result<(), u32> {
    let (f, owner) = lock_target(h)?;
    let mut all = LOCKS.lock().unwrap();
    let list = all.get_mut(&f.key).ok_or(ERROR_NOT_LOCKED)?;
    let i = list.iter().position(|l| l.owner == owner && l.start == start && l.len == len).ok_or(ERROR_NOT_LOCKED)?;
    list.remove(i);
    if list.is_empty() {
        all.remove(&f.key);
    }
    Ok(())
}

/// Drops the locks of a closing file object.
pub(crate) fn release_locks(key: (u64, u64), owner: usize) {
    let mut all = LOCKS.lock().unwrap();
    if let Some(list) = all.get_mut(&key) {
        list.retain(|l| l.owner != owner);
        if list.is_empty() {
            all.remove(&key);
        }
    }
}

fn split(low: u32, high: u32) -> u64 {
    (high as u64) << 32 | low as u64
}

fn result(r: Result<(), u32>) -> i32 {
    r.map_or_else(|e| fail(e, 0), |()| 1)
}

extern "win64" fn LockFile(h: u64, off_low: u32, off_high: u32, len_low: u32, len_high: u32) -> i32 {
    result(lock(h, split(off_low, off_high), split(len_low, len_high), true, false))
}

extern "win64" fn UnlockFile(h: u64, off_low: u32, off_high: u32, len_low: u32, len_high: u32) -> i32 {
    result(unlock(h, split(off_low, off_high), split(len_low, len_high)))
}

extern "win64" fn LockFileEx(h: u64, flags: u32, reserved: u32, len_low: u32, len_high: u32, ov: *const u8) -> i32 {
    if reserved != 0 || ov.is_null() || flags & !(LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK) != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let start = kernel32::overlapped_offset(ov).unwrap_or(0);
    let exclusive = flags & LOCKFILE_EXCLUSIVE_LOCK != 0;
    result(lock(h, start, split(len_low, len_high), exclusive, flags & LOCKFILE_FAIL_IMMEDIATELY == 0))
}

extern "win64" fn UnlockFileEx(h: u64, reserved: u32, len_low: u32, len_high: u32, ov: *const u8) -> i32 {
    if reserved != 0 || ov.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    result(unlock(h, kernel32::overlapped_offset(ov).unwrap_or(0), split(len_low, len_high)))
}

/// Only read-only can be stored; ARCHIVE and NORMAL carry no state here.
fn set_attributes(p: &str, st: &osyx_abi::FileStat, attrs: u32) -> Result<(), u32> {
    if attrs & !(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL | 0x10) != 0 {
        return Err(ERROR_NOT_SUPPORTED);
    }
    let mode = if attrs & FILE_ATTRIBUTE_READONLY != 0 { st.mode & !0o222 } else { st.mode | 0o200 };
    if mode == st.mode {
        return Ok(());
    }
    os_sys::chmod(p, mode).map_err(errno_to_win32)
}

extern "win64" fn SetFileAttributesW(name_w: *const u16, attrs: u32) -> i32 {
    let Some(n) = name(name_w) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    match stat_of(&n).and_then(|(p, st)| set_attributes(&p, &st, attrs)) {
        Ok(()) => 1,
        Err(e) => fail(e, 0),
    }
}

extern "win64" fn SetFileTime(h: u64, creation: *const u64, access: *const u64, write: *const u64) -> i32 {
    if objects::file(h).is_err() {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    // NULL (or 0) leaves a time unchanged; anything else needs utimes,
    // which OSyx does not have.
    // SAFETY: NULL or the caller's FILETIMEs.
    let change = [creation, access, write].iter().any(|&t| !t.is_null() && unsafe { core::ptr::read_unaligned(t) } != 0);
    if change { fail(ERROR_NOT_SUPPORTED, 0) } else { 1 }
}

// FILE_INFO_BY_HANDLE_CLASS values handled below.
const FILE_BASIC_INFO: u32 = 0;
const FILE_STANDARD_INFO: u32 = 1;
const FILE_NAME_INFO: u32 = 2;
const FILE_RENAME_INFO: u32 = 3;
const FILE_DISPOSITION_INFO: u32 = 4;
const FILE_ALLOCATION_INFO: u32 = 5;
const FILE_END_OF_FILE_INFO: u32 = 6;
const FILE_ATTRIBUTE_TAG_INFO: u32 = 9;
const FILE_ID_INFO: u32 = 18;
const FILE_DISPOSITION_INFO_EX: u32 = 21;
const ERROR_BAD_LENGTH: u32 = 24;
const ERROR_MORE_DATA: u32 = 234;

extern "win64" fn GetFileInformationByHandleEx(h: u64, class: u32, out: u64, size: u32) -> i32 {
    let f = match objects::file(h) {
        Ok(f) => f,
        Err(e) => return fail(e, 0),
    };
    let st = match os_sys::fstat(f.fd) {
        Ok(s) => s,
        Err(e) => return fail(errno_to_win32(e), 0),
    };
    let need = |n: u32| if size < n || out == 0 { Err(ERROR_BAD_LENGTH) } else { Ok(()) };
    // SAFETY: `out` holds `size` bytes, checked per class.
    let r = unsafe {
        match class {
            FILE_BASIC_INFO => need(40).map(|()| {
                teb::put(out, 0, kernel32::filetime(st.ctime_ns));
                teb::put(out, 8, kernel32::filetime(st.atime_ns));
                teb::put(out, 16, kernel32::filetime(st.mtime_ns));
                teb::put(out, 24, kernel32::filetime(st.ctime_ns)); // change time
                teb::put(out, 32, kernel32::attributes(&st));
                teb::put(out, 36, 0u32);
            }),
            FILE_STANDARD_INFO => need(24).map(|()| {
                teb::put(out, 0, st.blocks * 512);
                teb::put(out, 8, st.size);
                teb::put(out, 16, st.nlink);
                teb::put(out, 20, u8::from(f.delete_on_close.load(Ordering::SeqCst)));
                teb::put(out, 21, u8::from(st.kind == osyx_abi::KIND_DIR));
                teb::put(out, 22, 0u16);
            }),
            FILE_NAME_INFO => need(6).and_then(|()| {
                // The path without the drive, like Windows (\dir\file).
                let w = path::to_windows(&f.path);
                let units: Vec<u16> = w.get(2..).unwrap_or("").encode_utf16().collect();
                teb::put(out, 0, (units.len() * 2) as u32);
                let room = (size as usize - 4) / 2;
                core::ptr::copy_nonoverlapping(units.as_ptr(), (out + 4) as *mut u16, units.len().min(room));
                if units.len() > room { Err(ERROR_MORE_DATA) } else { Ok(()) }
            }),
            FILE_ATTRIBUTE_TAG_INFO => need(8).map(|()| {
                teb::put(out, 0, kernel32::attributes(&st));
                teb::put(out, 4, 0u32);
            }),
            FILE_ID_INFO => need(24).map(|()| {
                teb::put(out, 0, st.dev);
                teb::put(out, 8, st.ino);
                teb::put(out, 16, 0u64);
            }),
            _ => Err(ERROR_INVALID_PARAMETER),
        }
    };
    match r {
        Ok(()) => 1,
        Err(e) => fail(e, 0),
    }
}

extern "win64" fn SetFileInformationByHandle(h: u64, class: u32, data: u64, size: u32) -> i32 {
    let f = match objects::file(h) {
        Ok(f) => f,
        Err(e) => return fail(e, 0),
    };
    if data == 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let need = |n: u32| if size < n { Err(ERROR_BAD_LENGTH) } else { Ok(()) };
    // SAFETY: `data` holds `size` bytes, checked per class.
    let r = unsafe {
        match class {
            FILE_END_OF_FILE_INFO | FILE_ALLOCATION_INFO => need(8).and_then(|()| {
                if !f.access.1 {
                    return Err(ERROR_ACCESS_DENIED);
                }
                let len = teb::get::<u64>(data, 0);
                let st = os_sys::fstat(f.fd).map_err(errno_to_win32)?;
                // Allocation is advisory: it only truncates when smaller.
                if class == FILE_END_OF_FILE_INFO || len < st.size {
                    os_sys::ftruncate(f.fd, len).map_err(errno_to_win32)?;
                }
                Ok(())
            }),
            FILE_DISPOSITION_INFO => need(1).map(|()| f.delete_on_close.store(teb::get::<u8>(data, 0) != 0, Ordering::SeqCst)),
            FILE_DISPOSITION_INFO_EX => need(4).and_then(|()| {
                let flags = teb::get::<u32>(data, 0);
                if flags & !0x3 != 0 {
                    return Err(ERROR_NOT_SUPPORTED); // POSIX semantics, ignore read-only, ...
                }
                f.delete_on_close.store(flags & 1 != 0, Ordering::SeqCst);
                Ok(())
            }),
            FILE_RENAME_INFO => need(24).and_then(|()| {
                // ReplaceIfExists (u8), RootDirectory, FileNameLength, FileName.
                let replace = teb::get::<u8>(data, 0) != 0;
                if teb::get::<u64>(data, 8) != 0 {
                    return Err(ERROR_NOT_SUPPORTED);
                }
                let len = teb::get::<u32>(data, 16) as usize / 2;
                if 20 + len * 2 > size as usize {
                    return Err(ERROR_BAD_LENGTH);
                }
                let units = core::slice::from_raw_parts((data + 20) as *const u16, len);
                let to = String::from_utf16_lossy(units);
                let from = path::to_windows(&f.path);
                if kernel32::move_file(Some(from), Some(to), u32::from(replace)) != 0 { Ok(()) } else { Err(teb::last_error()) }
            }),
            FILE_BASIC_INFO => need(36).and_then(|()| {
                if (0..4).any(|i| teb::get::<u64>(data, i * 8) != 0) {
                    return Err(ERROR_NOT_SUPPORTED);
                }
                let attrs = teb::get::<u32>(data, 32);
                if attrs == 0 {
                    return Ok(());
                }
                let st = os_sys::fstat(f.fd).map_err(errno_to_win32)?;
                set_attributes(&f.path, &st, attrs)
            }),
            _ => Err(ERROR_INVALID_PARAMETER),
        }
    };
    match r {
        Ok(()) => 1,
        Err(e) => fail(e, 0),
    }
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        AreFileApisANSI,
        CreateFile2,
        CopyFileW,
        CopyFile2,
        CreateHardLinkW,
        CreateSymbolicLinkW,
        FindFirstFileExW,
        GetFileAttributesExW,
        GetFileAttributesExA,
        CopyFileExW,
        ReplaceFileA,
        GetLongPathNameW,
        GetShortPathNameW,
        GetFinalPathNameByHandleW,
        LockFile,
        UnlockFile,
        LockFileEx,
        UnlockFileEx,
        SetFileAttributesW,
        SetFileTime,
        GetFileInformationByHandleEx,
        SetFileInformationByHandle,
    ]
}
