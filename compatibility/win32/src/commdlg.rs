//! Classic Windows common file dialogs backed by the OSyx system picker.
//! ANSI/UTF-16 buffers, default extensions, filters and cancellation follow
//! OPENFILENAME. Hooks, custom templates and multi-selection fail explicitly.
#![allow(non_snake_case)]
use crate::{kernel32, path, teb, user32};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use os_std::sync::Mutex;
use user32::dialogs::{FileOptions, FileSelection};

static ERRORS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());
fn set_error(error: u32) {
    ERRORS.lock().unwrap().insert(os_sys::gettid(), error);
}
extern "win64" fn CommDlgExtendedError() -> u32 {
    ERRORS.lock().unwrap().get(&os_sys::gettid()).copied().unwrap_or(0)
}

unsafe fn string(pointer: u64, wide: bool) -> String {
    unsafe {
        if wide {
            path::wide_to_string(pointer as *const u16)
        } else {
            path::ansi_to_string(pointer as *const u8)
        }
    }
    .unwrap_or_default()
}

unsafe fn bounded(pointer: u64, capacity: usize, wide: bool) -> Option<String> {
    if pointer == 0 {
        return None;
    }
    if wide {
        let data = unsafe { core::slice::from_raw_parts(pointer as *const u16, capacity) };
        Some(String::from_utf16_lossy(&data[..data.iter().position(|&c| c == 0)?]))
    } else {
        let data = unsafe { core::slice::from_raw_parts(pointer as *const u8, capacity) };
        let end = data.iter().position(|&c| c == 0)?;
        Some(String::from_utf8_lossy(&data[..end]).into_owned())
    }
}

unsafe fn write_string(pointer: u64, capacity: usize, text: &str, wide: bool) -> bool {
    if pointer == 0 || capacity == 0 {
        return false;
    }
    if wide {
        let data: Vec<u16> = text.encode_utf16().chain(core::iter::once(0)).collect();
        if data.len() > capacity {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), pointer as *mut u16, data.len());
        }
    } else {
        if text.len() + 1 > capacity {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(text.as_ptr(), pointer as *mut u8, text.len());
            *(pointer as *mut u8).add(text.len()) = 0;
        }
    }
    true
}

/// OPENFILENAME of a 32-bit caller (76 bytes, or 88 with the Windows 2000
/// fields) widened into the 136-byte x64 layout and copied back.
fn dialog32(ofn: u64, wide: bool, save: bool) -> i32 {
    set_error(0);
    if ofn == 0 {
        set_error(2);
        return 0;
    }
    // SAFETY: the caller's OPENFILENAME; its size is checked first.
    let size = unsafe { teb::get::<u32>(ofn, 0) };
    if size != 76 && size != 88 {
        set_error(1);
        return 0;
    }
    #[repr(align(8))]
    struct Native([u8; 136]);
    let mut native = Native([0; 136]);
    let n = native.0.as_mut_ptr() as u64;
    // SAFETY: both structures are large enough for the offsets used.
    unsafe {
        teb::put(n, 0, 136u32);
        teb::put(n, 8, teb::get::<i32>(ofn, 4) as i64 as u64);
        for (from, to) in [(12, 24), (28, 48), (36, 64), (44, 80), (48, 88), (60, 104)] {
            teb::put(n, to, teb::get::<u32>(ofn, from) as u64);
        }
        for (from, to) in [(24, 44), (32, 56), (40, 72), (52, 96)] {
            teb::put(n, to, teb::get::<u32>(ofn, from));
        }
    }
    let result = dialog(n, wide, save);
    // SAFETY: as above.
    unsafe {
        teb::put(ofn, 24, teb::get::<u32>(n, 44));
        teb::put(ofn, 52, teb::get::<u32>(n, 96));
        teb::put(ofn, 56, teb::get::<u16>(n, 100));
        teb::put(ofn, 58, teb::get::<u16>(n, 102));
    }
    result
}

fn dialog(ofn: u64, wide: bool, save: bool) -> i32 {
    set_error(0);
    if ofn == 0 {
        set_error(2);
        return 0;
    }
    // OPENFILENAME x64 offsets, including its NT4 (136-byte) form.
    let size = unsafe { teb::get::<u32>(ofn, 0) };
    if size != 136 && size != 152 {
        set_error(1);
        return 0;
    }
    let owner = unsafe { teb::get::<u64>(ofn, 8) };
    let file = unsafe { teb::get::<u64>(ofn, 48) };
    let capacity = unsafe { teb::get::<u32>(ofn, 56) } as usize;
    let flags = unsafe { teb::get::<u32>(ofn, 96) };
    if flags & (0x20 | 0x40 | 0x80 | 0x200) != 0 {
        set_error(2);
        return 0;
    }
    if capacity == 0 || capacity > 1_048_576 || file == 0 {
        set_error(2);
        return 0;
    }
    let Some(filename) = (unsafe { bounded(file, capacity, wide) }) else {
        set_error(0x3002);
        return 0;
    };
    let read = |offset| unsafe { string(teb::get::<u64>(ofn, offset), wide) };
    let directory = read(80);
    let title = read(88);
    let extension = read(104);
    let mut filters = Vec::new();
    let filter_pointer = unsafe { teb::get::<u64>(ofn, 24) };
    if filter_pointer != 0 {
        let mut offset = 0usize;
        while offset < 8192 {
            let label = unsafe { string(filter_pointer + offset as u64 * if wide { 2 } else { 1 }, wide) };
            if label.is_empty() {
                break;
            }
            offset += if wide { label.encode_utf16().count() } else { label.len() } + 1;
            let pattern = unsafe { string(filter_pointer + offset as u64 * if wide { 2 } else { 1 }, wide) };
            if pattern.is_empty() {
                break;
            }
            offset += if wide { pattern.encode_utf16().count() } else { pattern.len() } + 1;
            filters.push((label, pattern));
        }
    }
    let filter = unsafe { teb::get::<u32>(ofn, 44) }.saturating_sub(1) as usize;
    let fallback =
        os_std::env::var("HOME").ok().filter(|p| p != "/").unwrap_or_else(|| String::from("/home/user/Documents"));
    let mut directory = if directory.is_empty() {
        fallback
    } else {
        kernel32::locate(&directory).ok().filter(|(_, exists)| *exists).map(|(p, _)| p).unwrap_or(fallback)
    };
    let mut filename = filename;
    if filename.contains(['\\', '/']) || filename.as_bytes().get(1) == Some(&b':') {
        if let Ok(p) = path::to_osyx(&filename, &kernel32::cwd_win()) {
            if let Some((parent, name)) = p.rsplit_once('/') {
                directory = String::from(if parent.is_empty() { "/" } else { parent });
                filename = String::from(name);
            }
        }
    }
    let options = FileOptions {
        owner,
        title: if title.is_empty() { String::from(if save { "Save as" } else { "Open file" }) } else { title },
        directory,
        filename,
        save,
        folder: false,
        must_exist: !save && flags & 0x1000 != 0,
        overwrite: flags & 2 != 0,
        extension: extension.clone(),
        filters,
        filter,
    };
    let selection = match user32::dialogs::show(options) {
        Ok(Some(s)) => s,
        Ok(None) => return 0,
        Err(_) => {
            set_error(2);
            return 0;
        }
    };
    let text = path::to_windows(&selection.path);
    let required = if wide { text.encode_utf16().count() + 1 } else { text.len() + 1 };
    if !unsafe { write_string(file, capacity, &text, wide) } {
        // FNERR_BUFFERTOOSMALL stores the required character count in the
        // first WORD of lpstrFile (only when those two bytes are writable).
        if capacity * if wide { 2 } else { 1 } >= 2 {
            unsafe {
                teb::put(file, 0, required.min(u16::MAX as usize) as u16);
            }
        }
        set_error(0x3003);
        return 0;
    }
    let name = text.rsplit('\\').next().unwrap_or("");
    let prefix = &text[..text.len() - name.len()];
    let offset = if wide { prefix.encode_utf16().count() } else { prefix.len() };
    let ext_offset =
        name.rfind('.').map_or(0, |i| offset + if wide { name[..i + 1].encode_utf16().count() } else { i + 1 });
    unsafe {
        teb::put(ofn, 44, (selection.filter + 1) as u32);
        teb::put(ofn, 100, offset as u16);
        teb::put(ofn, 102, ext_offset as u16);
        let title = teb::get::<u64>(ofn, 64);
        let max = teb::get::<u32>(ofn, 72) as usize;
        if title != 0 && max > 0 {
            write_string(title, max, name, wide);
        }
        let actual = name.rsplit_once('.').map_or("", |(_, e)| e);
        teb::put(
            ofn,
            96,
            if !extension.is_empty() && !actual.eq_ignore_ascii_case(&extension) {
                flags | 0x400
            } else {
                flags & !0x400
            },
        );
    }
    if flags & 8 == 0 {
        if let Some((parent, _)) = selection.path.rsplit_once('/') {
            let _ = os_std::env::set_current_dir(if parent.is_empty() { "/" } else { parent });
        }
    }
    1
}

extern "win64" fn GetOpenFileNameW(ofn: u64) -> i32 {
    if crate::wow64::is_active() {
        return dialog32(ofn, true, false);
    }
    dialog(ofn, true, false)
}
extern "win64" fn GetOpenFileNameA(ofn: u64) -> i32 {
    if crate::wow64::is_active() {
        return dialog32(ofn, false, false);
    }
    dialog(ofn, false, false)
}
extern "win64" fn GetSaveFileNameW(ofn: u64) -> i32 {
    if crate::wow64::is_active() {
        return dialog32(ofn, true, true);
    }
    dialog(ofn, true, true)
}
extern "win64" fn GetSaveFileNameA(ofn: u64) -> i32 {
    if crate::wow64::is_active() {
        return dialog32(ofn, false, true);
    }
    dialog(ofn, false, true)
}

// A filesystem PIDL: one SHITEMID containing an OSyx tag and UTF-8 path,
// followed by the terminating zero SHITEMID. Owned by CoTaskMemFree.
fn make_pidl(path: &str) -> u64 {
    let size = 2 + 4 + path.len() + 1;
    if size > u16::MAX as usize {
        return 0;
    }
    let p = crate::ole32::CoTaskMemAlloc(size + 2);
    if p == 0 {
        return 0;
    }
    unsafe {
        teb::put(p, 0, size as u16);
        core::ptr::copy_nonoverlapping(b"OSYX".as_ptr(), (p + 2) as *mut u8, 4);
        core::ptr::copy_nonoverlapping(path.as_ptr(), (p + 6) as *mut u8, path.len());
        teb::put(p, 6 + path.len(), 0u8);
        teb::put(p, size, 0u16);
    }
    p
}

fn pidl_path(p: u64) -> Option<String> {
    if p == 0 {
        return None;
    }
    let size = unsafe { teb::get::<u16>(p, 0) } as usize;
    if size < 8 || unsafe { core::slice::from_raw_parts((p + 2) as *const u8, 4) } != b"OSYX" {
        return None;
    }
    unsafe { bounded(p + 6, size - 6, false) }
}

/// The OSyx path of a PIDL this module made (shell32's SHOpenFolderAndSelectItems).
pub(crate) fn pidl_file_path(p: u64) -> Option<String> {
    pidl_path(p)
}

/// A new PIDL for `path`, owned by the caller (CoTaskMemFree / ILFree).
pub(crate) fn allocate_pidl(path: &str) -> u64 {
    make_pidl(path)
}

/// ILFree's address, for shell32's ordinal export table (#155).
pub(crate) fn il_free_address() -> u64 {
    ILFree as *const () as u64
}

fn browse(info: u64, wide: bool) -> u64 {
    if info == 0 {
        return 0;
    }
    let (owner, root, display, title, callback) = unsafe {
        if crate::wow64::is_active() {
            (teb::get::<u32>(info, 0) as u64, teb::get::<u32>(info, 4) as u64,
             teb::get::<u32>(info, 8) as u64, string(teb::get::<u32>(info, 12) as u64, wide),
             teb::get::<u32>(info, 20) as u64)
        } else {
        (
            teb::get::<u64>(info, 0),
            teb::get::<u64>(info, 8),
            teb::get::<u64>(info, 16),
            string(teb::get::<u64>(info, 24), wide),
            teb::get::<u64>(info, 40),
        )
        }
    };
    // Callback/window-message customization is not silently ignored.
    if callback != 0 || root != 0 && pidl_path(root).is_none() {
        return 0;
    }
    let directory = pidl_path(root).unwrap_or_else(|| String::from("/home/user"));
    let options = FileOptions {
        owner,
        title: if title.is_empty() { String::from("Select folder") } else { title },
        directory,
        filename: String::new(),
        save: false,
        folder: true,
        must_exist: true,
        overwrite: false,
        extension: String::new(),
        filters: Vec::new(),
        filter: 0,
    };
    let selection: FileSelection = match user32::dialogs::show(options) {
        Ok(Some(s)) => s,
        _ => return 0,
    };
    let pidl = make_pidl(&selection.path);
    if pidl != 0 {
        unsafe {
            write_string(display, 260, selection.path.rsplit('/').next().unwrap_or("C:"), wide);
            teb::put(info, if crate::wow64::is_active() { 28 } else { 56 }, 0i32);
        }
    }
    pidl
}
pub(crate) extern "win64" fn SHBrowseForFolderW(info: u64) -> u64 {
    browse(info, true)
}
extern "win64" fn SHBrowseForFolderA(info: u64) -> u64 {
    browse(info, false)
}
extern "win64" fn SHGetPathFromIDListW(pidl: u64, out: u64) -> i32 {
    pidl_path(pidl).is_some_and(|p| unsafe { write_string(out, 260, &path::to_windows(&p), true) }) as i32
}
extern "win64" fn SHGetPathFromIDListA(pidl: u64, out: u64) -> i32 {
    pidl_path(pidl).is_some_and(|p| unsafe { write_string(out, 260, &path::to_windows(&p), false) }) as i32
}
extern "win64" fn SHGetPathFromIDListEx(pidl: u64, out: u64, size: u32, _flags: u32) -> i32 {
    pidl_path(pidl).is_some_and(|p| unsafe { write_string(out, size as usize, &path::to_windows(&p), true) }) as i32
}
extern "win64" fn ILFree(pidl: u64) {
    crate::ole32::CoTaskMemFree(pidl);
}

extern "win64" fn ChooseColorW(cc: u64) -> i32 {
    set_error(0);
    if cc == 0 {
        set_error(2); // CDERR_INITIALIZATION
        return 0;
    }
    if unsafe { teb::get::<u32>(cc, 0) } != 72 {
        set_error(1); // CDERR_STRUCTSIZE
        return 0;
    }
    0 // cancelled
}

extern "win64" fn PrintDlgExW(pd: u64) -> u32 {
    if pd == 0 || unsafe { teb::get::<u32>(pd, 0) } != 136 {
        return 0x8007_0057; // E_INVALIDARG
    }
    // PD_RETURNDEFAULT = 0x0400: OSyx has no default printer.
    if unsafe { teb::get::<u32>(pd, 28) } & 0x0400 != 0 {
        set_error(0x1008); // PDERR_NODEFAULTPRN
        return 0x8000_4005; // E_FAIL
    }
    unsafe { teb::put(pd, 128, 0u32) }; // PD_RESULT_CANCEL
    0 // S_OK
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        GetOpenFileNameW,
        GetOpenFileNameA,
        GetSaveFileNameW,
        GetSaveFileNameA,
        ChooseColorW,
        PrintDlgExW,
        CommDlgExtendedError
    ]
}
pub fn shell_exports() -> Vec<(&'static str, u64)> {
    export_table![
        SHBrowseForFolderW,
        SHBrowseForFolderA,
        SHGetPathFromIDListW,
        SHGetPathFromIDListA,
        SHGetPathFromIDListEx,
        ILFree
    ]
}
