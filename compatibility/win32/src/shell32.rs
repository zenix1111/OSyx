//! shell32 known folders. The user profile is $HOME, with the Windows
//! layout below it (AppData\Roaming, AppData\Local, Documents, ...); the
//! machine folders are the fixed C:\ paths the rest of winrun reports
//! (GetWindowsDirectory). A folder that does not exist is reported as
//! missing unless the caller asks for it to be created (KF_FLAG_CREATE /
//! CSIDL_FLAG_CREATE) or not verified (KF_FLAG_DONT_VERIFY). Folders of
//! other users (a token other than the caller's) are not supported.
//! Explicit AppUserModelIDs are process metadata: every thread sees the
//! latest value and each successful query returns a task-allocator copy.
#![allow(non_snake_case)]
use crate::{kernel32, path};
use alloc::{format, string::String, vec::Vec};
use os_std::sync::Mutex;

const S_OK: u32 = 0;
const E_INVALIDARG: u32 = 0x8007_0057;
const E_OUTOFMEMORY: u32 = 0x8007_000e;
const E_FAIL: u32 = 0x8000_4005;
const E_POINTER: u32 = 0x8000_4003;
const HRESULT_FILE_NOT_FOUND: u32 = 0x8007_0002;
const HRESULT_NOT_SUPPORTED: u32 = 0x8007_0032;

const fn hresult(win32: u32) -> u32 {
    if win32 == 0 { S_OK } else { 0x8007_0000 | (win32 & 0xffff) }
}

#[derive(Clone, Copy)]
enum Base {
    /// Relative to the user profile ("" is the profile itself).
    Profile(&'static str),
    /// A fixed machine path.
    Machine(&'static str),
}

/// (FOLDERID as its GUID fields, CSIDL or 0, location).
type Folder = ((u32, u16, u16, [u8; 8]), u32, Base);

const FOLDERS: &[Folder] = &[
    ((0xAE50C081, 0xEBD2, 0x438A, [0x86, 0x55, 0x8A, 0x09, 0x2E, 0x34, 0x98, 0x7A]), 0x08, Base::Profile("AppData\\Roaming\\Microsoft\\Windows\\Recent")),
    ((0x5E6C858F, 0x0E22, 0x4760, [0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73]), 0x28, Base::Profile("")),
    ((0x3EB685DB, 0x65F9, 0x4CF6, [0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D]), 0x1A, Base::Profile("AppData\\Roaming")),
    ((0xF1B32785, 0x6FBA, 0x4FCF, [0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91]), 0x1C, Base::Profile("AppData\\Local")),
    ((0x352481E8, 0x33BE, 0x4251, [0xBA, 0x85, 0x60, 0x07, 0xCA, 0xED, 0xCF, 0x9D]), 0x20, Base::Profile("AppData\\Local\\Microsoft\\Windows\\INetCache")),
    ((0x2B0F765D, 0xC0E9, 0x4171, [0x90, 0x8E, 0x08, 0xA6, 0x11, 0xB6, 0xFC, 0x84]), 0x21, Base::Profile("AppData\\Local\\Microsoft\\Windows\\INetCookies")),
    ((0xD9DC8A3B, 0xB784, 0x432E, [0xA7, 0x81, 0x5A, 0x11, 0x30, 0xA7, 0x59, 0x63]), 0x22, Base::Profile("AppData\\Local\\Microsoft\\Windows\\History")),
    ((0xA520A1A4, 0x1780, 0x4FF6, [0xBD, 0x18, 0x16, 0x73, 0x43, 0xC5, 0xAF, 0x16]), 0, Base::Profile("AppData\\LocalLow")),
    ((0xB4BFCC3A, 0xDB2C, 0x424C, [0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41]), 0x10, Base::Profile("Desktop")),
    ((0xFDD39AD0, 0x238F, 0x46AF, [0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7]), 0x05, Base::Profile("Documents")),
    ((0x374DE290, 0x123F, 0x4565, [0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B]), 0, Base::Profile("Downloads")),
    ((0x33E28130, 0x4E1E, 0x4676, [0x83, 0x5A, 0x98, 0x39, 0x5C, 0x3B, 0xC3, 0xBB]), 0x27, Base::Profile("Pictures")),
    ((0x4BD8D571, 0x6D19, 0x48D3, [0xBE, 0x97, 0x42, 0x22, 0x20, 0x08, 0x0E, 0x43]), 0x0D, Base::Profile("Music")),
    ((0x18989B1D, 0x99B5, 0x455B, [0x84, 0x1C, 0xAB, 0x7C, 0x74, 0xE4, 0xDD, 0xFC]), 0x0E, Base::Profile("Videos")),
    ((0x5CD7AEE2, 0x2219, 0x4A67, [0xB8, 0x5D, 0x6C, 0x9C, 0xE1, 0x56, 0x60, 0xCB]), 0, Base::Profile("AppData\\Local\\Programs")),
    ((0x62AB5D82, 0xFDC1, 0x4DC3, [0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97]), 0x23, Base::Machine("C:\\ProgramData")),
    ((0xF38BF404, 0x1D43, 0x42F2, [0x93, 0x05, 0x67, 0xDE, 0x0B, 0x28, 0xFC, 0x23]), 0x24, Base::Machine("C:\\Windows")),
    ((0x1AC14E77, 0x02E7, 0x4E5D, [0xB7, 0x44, 0x2E, 0xB1, 0xAE, 0x51, 0x98, 0xB7]), 0x25, Base::Machine("C:\\Windows\\System32")),
    ((0xFD228CB7, 0xAE11, 0x4AE3, [0x86, 0x4C, 0x16, 0xF3, 0x91, 0x0A, 0xB8, 0xFE]), 0x14, Base::Machine("C:\\Windows\\Fonts")),
    ((0x905E63B6, 0xC1BF, 0x494E, [0xB2, 0x9C, 0x65, 0xB7, 0x32, 0xD3, 0xD2, 0x1A]), 0x26, Base::Machine("C:\\Program Files")),
    ((0x6D809377, 0x6AF0, 0x444B, [0x89, 0x57, 0xA3, 0x77, 0x3F, 0x02, 0x20, 0x0E]), 0, Base::Machine("C:\\Program Files")),
];

/// The profile directory as a Windows path.
fn profile() -> String {
    let home = os_std::env::var("HOME").unwrap_or_else(|_| String::from("/home/user"));
    let home = home.trim_end_matches('/');
    path::to_windows(if home.is_empty() { "/" } else { home })
}

fn location(base: Base) -> String {
    match base {
        Base::Profile("") => profile(),
        Base::Profile(rel) => format!("{}\\{rel}", profile().trim_end_matches('\\')),
        Base::Machine(p) => String::from(p),
    }
}

/// Creates the directory and its missing parents.
fn create_all(win: &str) -> Result<(), u32> {
    let full = path::to_osyx(win, &kernel32::cwd_win())?;
    let mut at = String::new();
    for part in full.split('/').filter(|p| !p.is_empty()) {
        at.push('/');
        at.push_str(part);
        match os_sys::mkdir(&at, 0o755) {
            Ok(()) | Err(osyx_abi::Errno::AlreadyExists) => {}
            Err(e) => return Err(crate::error::errno_to_win32(e)),
        }
    }
    Ok(())
}

/// Whether the folder exists as a directory.
fn exists(win: &str) -> Result<bool, u32> {
    match kernel32::locate(win) {
        Ok((p, true)) => Ok(os_sys::stat(&p).is_ok_and(|s| s.kind == osyx_abi::KIND_DIR)),
        Ok((_, false)) | Err(3) => Ok(false), // ERROR_PATH_NOT_FOUND: a parent is missing
        Err(e) => Err(e),
    }
}

/// Resolves a folder: Ok(path) or Err(HRESULT).
fn resolve(base: Base, create: bool, verify: bool) -> Result<String, u32> {
    let p = location(base);
    if create {
        create_all(&p).map_err(hresult)?;
    } else if verify && !exists(&p).map_err(hresult)? {
        return Err(HRESULT_FILE_NOT_FOUND);
    }
    Ok(p)
}

const KF_FLAG_DONT_VERIFY: u32 = 0x4000;
const KF_FLAG_CREATE: u32 = 0x8000;
/// Flags with no effect here: no folder redirection, aliases or
/// unexpanded environment strings exist, so the default path is the path;
/// KF_FLAG_SIMPLE_IDLIST only shapes ID lists; and with no packages or app
/// containers, their (no-)redirection flags change nothing.
const KF_FLAGS_NO_EFFECT: u32 =
    0x0000_0100 | 0x0000_0200 | 0x0000_0400 | 0x0000_0800 | 0x0000_1000 | 0x0000_2000 | 0x0001_0000 | 0x0002_0000;

/// A token other than the caller's (NULL) would name another user.
fn token_ok(token: u64) -> bool {
    token == 0
}

extern "win64" fn SHGetKnownFolderPath(id: *const u8, flags: u32, token: u64, out: *mut u64) -> u32 {
    let hr = known_folder_path(id, flags, token, out);
    if hr != S_OK && crate::kernel32::TRACE.load(core::sync::atomic::Ordering::Relaxed) {
        // SAFETY: the caller's KNOWNFOLDERID, if any.
        let d1 = if id.is_null() { 0 } else { unsafe { core::ptr::read_unaligned(id as *const u32) } };
        os_std::eprintln!("winrun: SHGetKnownFolderPath({d1:08x}-..., flags {flags:#x}) failed: {hr:#x}");
    }
    hr
}

fn known_folder_path(id: *const u8, flags: u32, token: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's out pointer; NULL on every failure, as Windows does.
    unsafe { *out = 0 };
    if id.is_null() || flags & !(KF_FLAG_DONT_VERIFY | KF_FLAG_CREATE | KF_FLAGS_NO_EFFECT) != 0 {
        return E_INVALIDARG;
    }
    if !token_ok(token) {
        return HRESULT_NOT_SUPPORTED;
    }
    // SAFETY: the caller's KNOWNFOLDERID (a GUID).
    let guid = unsafe {
        (
            core::ptr::read_unaligned(id as *const u32),
            core::ptr::read_unaligned(id.add(4) as *const u16),
            core::ptr::read_unaligned(id.add(6) as *const u16),
            core::ptr::read_unaligned(id.add(8) as *const [u8; 8]),
        )
    };
    let Some(&(_, _, base)) = FOLDERS.iter().find(|f| f.0 == guid) else { return HRESULT_FILE_NOT_FOUND };
    let p = match resolve(base, flags & KF_FLAG_CREATE != 0, flags & KF_FLAG_DONT_VERIFY == 0) {
        Ok(p) => p,
        Err(hr) => return hr,
    };
    let units: Vec<u16> = p.encode_utf16().chain(core::iter::once(0)).collect();
    let block = crate::ole32::CoTaskMemAlloc(units.len() * 2);
    if block == 0 {
        return E_OUTOFMEMORY;
    }
    // SAFETY: a fresh block of units.len() units; the caller's out pointer.
    unsafe {
        core::ptr::copy_nonoverlapping(units.as_ptr(), block as *mut u16, units.len());
        *out = block;
    }
    S_OK
}

const CSIDL_FLAG_CREATE: u32 = 0x8000;
const CSIDL_FLAG_DONT_VERIFY: u32 = 0x4000;
const MAX_PATH: usize = 260;

pub(crate) extern "win64" fn SHGetFolderPathW(_hwnd: u64, csidl: u32, token: u64, kind: u32, out: *mut u16) -> u32 {
    if out.is_null() || kind > 1 {
        return E_INVALIDARG; // SHGFP_TYPE_CURRENT (0) and SHGFP_TYPE_DEFAULT (1) agree here
    }
    // SAFETY: the caller's MAX_PATH buffer; empty on failure.
    unsafe { *out = 0 };
    if !token_ok(token) {
        return HRESULT_NOT_SUPPORTED;
    }
    // CSIDL_DESKTOP (0) resolves to the desktop directory (0x10) as on Windows.
    let id = match csidl & !(CSIDL_FLAG_CREATE | CSIDL_FLAG_DONT_VERIFY) {
        0 => 0x10,
        id => id,
    };
    let Some(&(_, _, base)) = FOLDERS.iter().find(|f| f.1 == id) else { return E_INVALIDARG };
    let p = match resolve(base, csidl & CSIDL_FLAG_CREATE != 0, csidl & CSIDL_FLAG_DONT_VERIFY == 0) {
        Ok(p) => p,
        Err(hr) => return hr,
    };
    let units: Vec<u16> = p.encode_utf16().collect();
    if units.len() >= MAX_PATH {
        return hresult(206); // ERROR_FILENAME_EXCED_RANGE
    }
    // SAFETY: as above; units.len() < MAX_PATH.
    unsafe {
        core::ptr::copy_nonoverlapping(units.as_ptr(), out, units.len());
        *out.add(units.len()) = 0;
    }
    S_OK
}

/// Splits a Windows command line into arguments with the rules
/// `CommandLineToArgvW` documents: whitespace separates, double quotes group
/// (and a doubled quote inside them is one quote), and 2n backslashes before
/// a quote become n backslashes with the quote taking effect, 2n+1 become n
/// backslashes and a literal quote.
fn split_command_line(s: &[u16]) -> Vec<Vec<u16>> {
    let is_space = |c: u16| c == 0x20 || c == 0x09;
    let mut args = Vec::new();
    let mut i = 0;
    while i < s.len() {
        while i < s.len() && is_space(s[i]) {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        let mut arg: Vec<u16> = Vec::new();
        let mut quoted = false;
        while i < s.len() {
            match s[i] {
                c if c == b'\\' as u16 => {
                    let mut n = 0;
                    while i < s.len() && s[i] == b'\\' as u16 {
                        n += 1;
                        i += 1;
                    }
                    let quoted_quote = i < s.len() && s[i] == b'"' as u16;
                    let slashes = if quoted_quote { n / 2 } else { n };
                    for _ in 0..slashes {
                        arg.push(b'\\' as u16);
                    }
                    if quoted_quote && n % 2 == 1 {
                        arg.push(b'"' as u16);
                        i += 1;
                    }
                }
                c if c == b'"' as u16 => {
                    i += 1;
                    if quoted && i < s.len() && s[i] == b'"' as u16 {
                        arg.push(b'"' as u16);
                        i += 1;
                    } else {
                        quoted = !quoted;
                    }
                }
                c if !quoted && is_space(c) => break,
                c => {
                    arg.push(c);
                    i += 1;
                }
            }
        }
        args.push(arg);
    }
    args
}

/// `CommandLineToArgvW`: the program's arguments in one LocalAlloc block.
/// The pointer array comes first, because that is the pointer handed back
/// (and the block `LocalFree` must free here); the strings follow it.
extern "win64" fn CommandLineToArgvW(cmdline: *const u16, count: *mut i32) -> u64 {
    if count.is_null() {
        return 0;
    }
    // SAFETY: the caller's out parameter.
    unsafe { *count = 0 };
    if cmdline.is_null() {
        return 0;
    }
    let mut len = 0;
    // SAFETY: a NUL-terminated command line from the caller.
    while unsafe { *cmdline.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units, as read above.
    let text = unsafe { core::slice::from_raw_parts(cmdline, len) };
    let args = if text.is_empty() {
        // Windows reports the program path as the only argument.
        let path: Vec<u16> = kernel32::module_name(0).unwrap_or_default().encode_utf16().collect();
        alloc::vec![path]
    } else {
        split_command_line(text)
    };
    let array = (args.len() + 1) * 8;
    let total: usize = array + args.iter().map(|a| (a.len() + 1) * 2).sum::<usize>();
    let Some(block) = kernel32::heap_alloc(total, true) else { return 0 };
    let mut at = block + array as u64;
    for (i, arg) in args.iter().enumerate() {
        // SAFETY: inside the block just allocated, zeroed and big enough.
        unsafe {
            core::ptr::copy_nonoverlapping(arg.as_ptr(), at as *mut u16, arg.len());
            *((block + (i * 8) as u64) as *mut u64) = at;
        }
        at += ((arg.len() + 1) * 2) as u64;
    }
    // SAFETY: the caller's out parameter; the array's spare entry stays 0.
    unsafe { *count = args.len() as i32 };
    block
}

// Explicit identity belongs to this process, independently of COM apartments
// and the thread that sets it. Store UTF-16 verbatim (including its NUL).
static APP_ID: Mutex<Option<Vec<u16>>> = Mutex::new(None);

extern "win64" fn GetCurrentProcessExplicitAppUserModelID(out: *mut u64) -> u32 {
    if out.is_null() {
        return E_POINTER;
    }
    // SAFETY: caller supplies a PWSTR output slot, cleared on failure.
    unsafe { *out = 0 };
    let state = APP_ID.lock().unwrap();
    let Some(id) = state.as_ref() else { return E_FAIL };
    let block = crate::ole32::CoTaskMemAlloc(id.len() * 2);
    if block == 0 {
        return E_OUTOFMEMORY;
    }
    // SAFETY: fresh task-allocator block of id.len() UTF-16 units.
    unsafe {
        core::ptr::copy_nonoverlapping(id.as_ptr(), block as *mut u16, id.len());
        *out = block;
    }
    S_OK
}

extern "win64" fn SetCurrentProcessExplicitAppUserModelID(id: *const u16) -> u32 {
    if id.is_null() {
        // Windows clears the old value even though NULL returns E_INVALIDARG.
        *APP_ID.lock().unwrap() = None;
        return E_INVALIDARG;
    }
    let mut units = Vec::new();
    // Windows accepts at most 127 UTF-16 units plus the terminator. A longer
    // value fails without changing the old ID; empty successfully removes it.
    for i in 0..128 {
        // SAFETY: caller supplies a NUL-terminated string; read only up to
        // the maximum accepted length when rejecting an oversized input.
        let unit = unsafe { *id.add(i) };
        units.push(unit);
        if unit == 0 {
            *APP_ID.lock().unwrap() = if i == 0 { None } else { Some(units) };
            return S_OK;
        }
    }
    E_INVALIDARG
}

/// The window's property store (taskbar identity and relaunch properties):
/// values are kept but OSyx has no taskbar that groups windows by them.
extern "win64" fn SHGetPropertyStoreForWindow(hwnd: u64, riid: *const [u8; 16], out: *mut u64) -> u32 {
    crate::propsys::window_property_store(hwnd, riid, out)
}

// ---- SHGetFileInfo ---------------------------------------------------------

const SHGFI_PIDL: u32 = 0x0000_0008;
const SHGFI_USEFILEATTRIBUTES: u32 = 0x0000_0010;
const SHGFI_DISPLAYNAME: u32 = 0x0000_0200;
const SHGFI_TYPENAME: u32 = 0x0000_0400;
const SHGFI_ATTRIBUTES: u32 = 0x0000_0800;
const SHGFI_ICONLOCATION: u32 = 0x0000_1000;
const SHGFI_EXETYPE: u32 = 0x0000_2000;

// Shell item attributes, not FILE_ATTRIBUTE_*, in dwAttributes.
const SFGAO_STREAM: u32 = 0x0040_0000;
const SFGAO_FILESYSANCESTOR: u32 = 0x1000_0000;
const SFGAO_FOLDER: u32 = 0x2000_0000;
const SFGAO_FILESYSTEM: u32 = 0x4000_0000;

/// `SHFILEINFOW`: hIcon, iIcon, dwAttributes, szDisplayName[MAX_PATH],
/// szTypeName[80].
#[repr(C)]
struct ShFileInfoW {
    icon: u64,
    index: i32,
    attributes: u32,
    display: [u16; MAX_PATH],
    kind: [u16; 80],
}
const SHFILEINFO_SIZE: u32 = 696;

fn put_units(dst: &mut [u16], text: &str) {
    let mut n = 0;
    for unit in text.encode_utf16() {
        if n + 1 >= dst.len() {
            break;
        }
        dst[n] = unit;
        n += 1;
    }
    dst[n] = 0;
}

fn extension(name: &str) -> &str {
    name.rsplit_once('.').map_or("", |(_, e)| e)
}

fn file_kind(is_dir: bool, name: &str) -> &'static str {
    if is_dir {
        return "Folder";
    }
    match extension(name) {
        e if e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("com") => "Application",
        e if e.eq_ignore_ascii_case("bat") || e.eq_ignore_ascii_case("cmd") => "Windows Command Script",
        e if e.eq_ignore_ascii_case("msi") => "Windows Installer Package",
        e if e.eq_ignore_ascii_case("txt") || e.eq_ignore_ascii_case("log") || e.eq_ignore_ascii_case("ini") || e.eq_ignore_ascii_case("md") => "Text Document",
        e if e.eq_ignore_ascii_case("pdf") => "PDF Document",
        e if e.eq_ignore_ascii_case("zip") => "Compressed (zipped) Folder",
        e if e.eq_ignore_ascii_case("7z") || e.eq_ignore_ascii_case("rar") || e.eq_ignore_ascii_case("gz") || e.eq_ignore_ascii_case("xz") => "Compressed Archive",
        e if e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm") => "HTML Document",
        e if e.eq_ignore_ascii_case("png") || e.eq_ignore_ascii_case("jpg") || e.eq_ignore_ascii_case("jpeg") || e.eq_ignore_ascii_case("gif") || e.eq_ignore_ascii_case("webp") || e.eq_ignore_ascii_case("bmp") || e.eq_ignore_ascii_case("ico") => "Image",
        e if e.eq_ignore_ascii_case("mp3") || e.eq_ignore_ascii_case("wav") || e.eq_ignore_ascii_case("flac") || e.eq_ignore_ascii_case("ogg") || e.eq_ignore_ascii_case("m4a") => "Audio",
        e if e.eq_ignore_ascii_case("mp4") || e.eq_ignore_ascii_case("mkv") || e.eq_ignore_ascii_case("webm") || e.eq_ignore_ascii_case("avi") => "Video",
        _ => "File",
    }
}

/// Value `SHGetFileInfo` returns for SHGFI_EXETYPE.
fn exetype(name: &str) -> u64 {
    let ext = extension(name);
    if ext.eq_ignore_ascii_case("exe") {
        (0x4550 << 16) | 0x5A4D // PE signature high, "MZ" low
    } else if ext.eq_ignore_ascii_case("com") {
        0x5A4D
    } else if ext.eq_ignore_ascii_case("bat") {
        0x4261_546D // "Ba" high, "tM" low
    } else {
        0
    }
}

/// No icons: hIcon stays NULL and the caller uses its generic icon (Firefox
/// renders a fallback for a NULL icon). PIDLs belong to the shell namespace,
/// which exists only for the file dialogs' own PIDLs; return 0 for those.
fn sh_get_file_info(path: *const u16, input: u32, info: *mut u8, cb: u32, flags: u32) -> u64 {
    if flags & SHGFI_PIDL != 0 || path.is_null() || (flags != SHGFI_EXETYPE && (info.is_null() || cb < SHFILEINFO_SIZE)) {
        return 0;
    }
    if !info.is_null() && cb >= SHFILEINFO_SIZE {
        // SAFETY: the caller's struct; its size was checked above.
        unsafe { core::ptr::write_bytes(info, 0, SHFILEINFO_SIZE as usize) };
    }
    // SAFETY: NUL-terminated path from the caller.
    let Some(win) = (unsafe { path::wide_to_string(path) }) else { return 0 };
    if win.is_empty() {
        return 0;
    }
    let (attributes, is_dir) = if flags & SHGFI_USEFILEATTRIBUTES != 0 {
        (input, input & kernel32::FILE_ATTRIBUTE_DIRECTORY != 0)
    } else {
        match kernel32::locate(&win) {
            Ok((p, true)) => match os_sys::stat(&p) {
                Ok(st) => (kernel32::attributes(&st), st.kind == osyx_abi::KIND_DIR),
                Err(_) => return 0,
            },
            _ => return 0,
        }
    };
    let name = win.rsplit(['\\', '/']).next().unwrap_or(&win);
    if flags & SHGFI_EXETYPE != 0 {
        return if is_dir { 0 } else { exetype(name) };
    }
    // SAFETY: the caller's struct, zeroed above and at least SHFILEINFO_SIZE.
    let sfi = info as *mut ShFileInfoW;
    unsafe {
        (*sfi).attributes = if flags & SHGFI_ATTRIBUTES != 0 {
            if is_dir {
                SFGAO_FILESYSTEM | SFGAO_FOLDER | SFGAO_FILESYSANCESTOR
            } else {
                SFGAO_FILESYSTEM | SFGAO_STREAM
            }
        } else {
            attributes
        };
        if flags & SHGFI_ICONLOCATION != 0 {
            put_units(&mut (*sfi).display, &win);
        } else if flags & SHGFI_DISPLAYNAME != 0 {
            put_units(&mut (*sfi).display, name);
        }
        if flags & SHGFI_TYPENAME != 0 {
            put_units(&mut (*sfi).kind, file_kind(is_dir, name));
        }
    }
    1
}

pub(crate) extern "win64" fn SHGetFileInfoW(p: *const u16, input: u32, info: *mut u8, cb: u32, flags: u32) -> u64 {
    if crate::wow64::is_active() {
        if flags != SHGFI_EXETYPE && (info.is_null() || cb < 692) { return 0; }
        let mut host = [0u64; 87];
        let result = sh_get_file_info(p, input, host.as_mut_ptr().cast(), SHFILEINFO_SIZE, flags);
        if !info.is_null() && cb >= 692 {
            // SAFETY: the guest provided a 692-byte SHFILEINFOW buffer.
            unsafe {
                core::ptr::write_unaligned(info.cast::<u32>(), host[0] as u32);
                core::ptr::copy_nonoverlapping(host.as_ptr().cast::<u8>().add(8), info.add(4), 688);
            }
        }
        return result;
    }
    sh_get_file_info(p, input, info, cb, flags)
}

fn fileop_error(e: os_std::error::Error) -> u32 {
    e.raw_os_error().map_or(31, crate::error::errno_to_win32)
}

/// Reads a double-NUL-terminated list with bounded length and entry count.
unsafe fn fileop_paths(ptr: *const u16) -> Result<Vec<String>, u32> {
    if ptr.is_null() { return Err(87); }
    let mut paths = Vec::new();
    let mut start = 0usize;
    for at in 0..65536usize {
        let c = unsafe { core::ptr::read_unaligned(ptr.add(at)) };
        if c != 0 { continue; }
        if at == start { return Ok(paths); }
        if at - start > path::MAX_PATH_CHARS || paths.len() >= 1024 { return Err(206); }
        let units = unsafe { core::slice::from_raw_parts(ptr.add(start), at - start) };
        let name = String::from_utf16(units).map_err(|_| 123u32)?;
        paths.push(name);
        start = at + 1;
    }
    Err(206)
}

fn copy_tree(src: &str, dst: &str, depth: u32) -> Result<(), u32> {
    use os_std::fs;
    if depth > 128 { return Err(206); }
    let meta = fs::symlink_metadata(src).map_err(fileop_error)?;
    if meta.is_symlink() { return Err(50); }
    if !meta.is_dir() { fs::copy(src, dst).map_err(fileop_error)?; return Ok(()); }
    fs::create_dir_all(dst).map_err(fileop_error)?;
    for item in fs::read_dir(src).map_err(fileop_error)? {
        let name = item.file_name();
        copy_tree(&format!("{src}/{name}"), &format!("{dst}/{name}"), depth + 1)?;
    }
    Ok(())
}

extern "win64" fn SHFileOperationW(op: *mut u8) -> i32 {
    use os_std::fs;
    if op.is_null() { return 87; }
    let is32 = crate::wow64::is_active();
    let base = op as u64;
    // SAFETY: the caller supplies a SHFILEOPSTRUCTW for its ABI.
    let (function, from, to, flags) = unsafe {
        if is32 {
            (crate::teb::get::<u32>(base, 4), crate::teb::get::<u32>(base, 8) as u64,
             crate::teb::get::<u32>(base, 12) as u64, crate::teb::get::<u16>(base, 16))
        } else {
            (crate::teb::get::<u32>(base, 8), crate::teb::get::<u64>(base, 16),
             crate::teb::get::<u64>(base, 24), crate::teb::get::<u16>(base, 32))
        }
    };
    let aborted = if is32 { 20 } else { 36 };
    unsafe { crate::teb::put(base, aborted, 0u32) };
    let result = (|| -> Result<(), u32> {
        if !matches!(function, 1..=4) { return Err(87); }
        // Recycle bin, wildcard expansion and rename-on-collision are not
        // implemented; never silently perform a different operation.
        if flags & (0x0040 | 0x0008 | 0x0080) != 0 { return Err(50); }
        let sources = unsafe { fileop_paths(from as *const u16) }?;
        if sources.is_empty() { return Err(87); }
        let destinations = if function == 3 { Vec::new() } else { unsafe { fileop_paths(to as *const u16) }? };
        if function != 3 && (destinations.is_empty() || flags & 1 != 0 && destinations.len() != sources.len()) { return Err(87); }
        for (index, source) in sources.iter().enumerate() {
            let (src, exists) = kernel32::locate(source)?;
            if !exists { return Err(2); }
            if src == "/" { return Err(5); }
            let metadata = fs::symlink_metadata(&src).map_err(fileop_error)?;
            if function == 3 {
                if metadata.is_dir() && !metadata.is_symlink() { fs::remove_dir_all(&src) } else { fs::remove_file(&src) }.map_err(fileop_error)?;
                continue;
            }
            let dst_win = if flags & 1 != 0 { &destinations[index] } else { &destinations[0] };
            let (mut dst, dst_exists) = kernel32::locate(dst_win)?;
            if dst_exists && fs::metadata(&dst).map_err(fileop_error)?.is_dir() {
                let name = src.rsplit('/').next().ok_or(87u32)?;
                dst = format!("{}/{name}", dst.trim_end_matches('/'));
            }
            if dst == src || metadata.is_dir() && dst.starts_with(&format!("{src}/")) { return Err(87); }
            if let Ok(target) = fs::symlink_metadata(&dst) {
                if target.is_symlink() { return Err(50); }
                if target.dev() == metadata.dev() && target.ino() == metadata.ino() { return Err(87); }
            }
            if function == 2 { copy_tree(&src, &dst, 0)?; }
            else { fs::rename(&src, &dst).map_err(fileop_error)?; }
        }
        Ok(())
    })();
    match result { Ok(()) => 0, Err(e) => { unsafe { crate::teb::put(base, aborted, 1u32) }; e as i32 } }
}

extern "win64" fn SHGetFileInfoA(p: *const u8, input: u32, info: *mut u8, cb: u32, flags: u32) -> u64 {
    // SAFETY: NUL-terminated ANSI path; the wide copy lives for this call.
    let Some(wide) = (unsafe { path::ansi_to_wide(p) }) else { return 0 };
    sh_get_file_info(wide.as_ptr(), input, info, cb, flags)
}

extern "win64" fn SHGetSpecialFolderPathA(_hwnd: u64, out: *mut u8, csidl: u32, create: i32) -> i32 {
    if out.is_null() {
        return 0;
    }
    // SAFETY: the caller's MAX_PATH buffer.
    unsafe { *out = 0 };
    let id = match csidl & !(CSIDL_FLAG_CREATE | CSIDL_FLAG_DONT_VERIFY) {
        0 => 0x10,
        id => id,
    };
    let Some(&(_, _, base)) = FOLDERS.iter().find(|f| f.1 == id) else { return 0 };
    match resolve(base, create != 0 || csidl & CSIDL_FLAG_CREATE != 0, csidl & CSIDL_FLAG_DONT_VERIFY == 0) {
        Ok(p) => {
            kernel32::out_a(&p, out, MAX_PATH as u32);
            1
        }
        Err(_) => 0,
    }
}

// ---- Shell functions without a shell ---------------------------------------
//
// Firefox delay-loads these; before they existed here, the first call raised
// a delay-load exception that terminated the whole browser (a finished
// download called SHGetFileInfoW through nsLocalFile::GetDisplayName). Each
// one below fails in the way its callers already handle, so clicking a
// download or a link cannot kill the process.

const E_NOTIMPL: u32 = 0x8000_4001;

extern "win64" fn SHGetSpecialFolderLocation(_hwnd: u64, _csidl: u32, pidl: *mut u64) -> u32 {
    if !pidl.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *pidl = 0 };
    }
    E_INVALIDARG // no shell namespace: only the file dialogs' PIDLs exist
}

// ---- stock icons ------------------------------------------------------------------------------
//
// SHGetStockIconInfo names an icon by SHSTOCKICONID. Locations and system
// image list indices are those of Windows (imageres.dll, shell32.dll,
// imagesp1.dll, mydocs.dll under System32): (icon index, DLL, system index).
// OSyx has no such DLLs, so SHGSI_ICON draws a simple icon of the right kind
// (folder, document, drive or a generic one) at the size asked for.

const STOCK_ICONS: [(i16, u8, i16); 181] = [
    (-2, 0, 0), (-90, 0, 1), (-15, 0, 2), (-3, 0, 3), (-4, 0, 4), (-29, 0, 5),
    (-28, 0, 6), (-35, 0, 7), (-32, 0, 8), (-33, 0, 9), (-31, 0, 10), (-30, 0, 11),
    (-34, 0, 12), (-152, 0, 13), (-15, 1, 14), (-109, 0, 15), (-51, 0, 16), (-25, 0, 17),
    (-19, 1, 18), (-20, 1, 19), (-21, 1, 20), (-27, 0, 21), (-177, 0, 22), (-99, 0, 23),
    (-100, 0, 24), (-101, 0, 25), (-27, 1, 26), (-28, 1, 27), (-164, 0, 28), (-163, 0, 29),
    (-97, 0, 30), (-55, 0, 31), (-54, 0, 32), (-34, 1, 33), (-110, 0, 34), (-137, 1, 35),
    (-37, 1, 36), (-26, 0, 37), (-77, 0, 38), (-80, 0, 39), (-85, 0, 40), (-42, 1, 41),
    (-43, 1, 42), (-44, 1, 43), (-45, 1, 44), (-46, 1, 45), (-47, 1, 46), (-48, 1, 47),
    (-49, 1, 48), (-8, 0, 50), (-53, 0, 51), (-143, 0, 52), (-76, 0, 53), (-199, 1, 54),
    (-52, 0, 55), (-148, 0, 56), (-142, 0, 57), (-162, 0, 58), (-75, 0, 59), (-37, 0, 60),
    (-56, 0, 61), (-39, 0, 62), (-41, 0, 63), (-38, 0, 64), (-40, 0, 65), (-180, 0, 66),
    (-64, 0, 67), (-62, 0, 68), (-155, 0, 69), (-61, 0, 70), (-63, 0, 71), (-131, 0, 72),
    (-132, 0, 73), (-133, 0, 74), (-134, 0, 75), (-5, 0, 76), (-6, 0, 77), (-78, 0, 78),
    (-84, 0, 79), (-81, 0, 80), (-98, 0, 81), (-82, 0, 82), (-161, 0, 83), (-94, 0, 84),
    (-89, 0, 85), (-135, 0, 86), (-136, 0, 87), (-137, 0, 88), (-138, 0, 89), (-139, 0, 90),
    (-140, 0, 91), (-141, 0, 92), (-172, 0, 93), (-173, 0, 94), (-109, 0, 15), (-119, 0, 95),
    (-88, 0, 96), (-60, 0, 97), (-65, 0, 98), (-47, 0, 99), (-57, 0, 100), (-46, 0, 101),
    (-66, 0, 102), (-171, 0, 103), (-120, 0, 104), (-174, 0, 105), (-121, 0, 106), (-36, 0, 107),
    (-87, 0, 108), (-108, 0, 109), (-101, 3, 110), (-238, 1, 111), (-18, 0, 112), (-139, 1, 113),
    (-171, 1, 114), (-17, 0, 115), (-103, 0, 116), (-50, 0, 117), (-48, 0, 118), (-198, 1, 119),
    (-49, 0, 120), (-197, 1, 121), (-19, 0, 122), (-20, 0, 123), (-21, 0, 124), (-22, 0, 125),
    (-23, 0, 126), (-79, 0, 127), (-104, 0, 128), (-105, 0, 129), (-106, 0, 130), (-107, 0, 131),
    (-200, 2, 132), (-201, 2, 133), (-202, 2, 134), (-203, 2, 135), (-204, 2, 136), (-205, 2, 137),
    (-206, 2, 138), (-207, 2, 139), (-208, 2, 140), (-208, 2, 140), (-208, 2, 140), (-208, 2, 140),
    (-208, 2, 140), (-208, 2, 140), (-208, 2, 140), (-208, 2, 140), (-208, 2, 140), (-208, 2, 140),
    (-208, 2, 140), (-208, 2, 140), (-208, 2, 140), (-208, 2, 140), (-208, 2, 140), (-208, 2, 140),
    (-208, 2, 140), (-208, 2, 140), (-208, 2, 140), (-208, 2, 140), (-1015, 0, 141), (-1017, 0, 142),
    (-1018, 0, 143), (-1026, 0, 144), (-1030, 0, 145), (-1031, 0, 146), (-1032, 0, 147), (-1033, 0, 148),
    (-1034, 0, 149), (-1035, 0, 150), (-1036, 0, 151), (-1037, 0, 152), (-1001, 0, 153), (-157, 0, 49),
    (-5201, 0, 154), (-5, 0, 76), (-3, 0, 3), (-162, 0, 58), (-1304, 0, 155), (-1305, 0, 156),
    (-1306, 0, 157),
];
const STOCK_DLLS: [&str; 4] = ["imageres.dll", "shell32.dll", "imagesp1.dll", "mydocs.dll"];
const SHSTOCKICONINFO_SIZE: u32 = 544;
const SHGSI_ICON: u32 = 0x100;
const SHGSI_SYSICONINDEX: u32 = 0x4000;
const SHGSI_LINKOVERLAY: u32 = 0x8000;
const SHGSI_SELECTED: u32 = 0x1_0000;
const SHGSI_SMALLICON: u32 = 0x1;
const SHGSI_SHELLICONSIZE: u32 = 0x4;
const SHGSI_VALID: u32 = SHGSI_ICON | SHGSI_SYSICONINDEX | SHGSI_LINKOVERLAY | SHGSI_SELECTED | SHGSI_SMALLICON | SHGSI_SHELLICONSIZE;

/// SHGetStockIconInfo(id, flags, &SHSTOCKICONINFO): the struct is cbSize,
/// hIcon @8, iSysImageIndex @16, iIcon @20 and szPath[260] @24. E_INVALIDARG
/// for an unknown id, unknown flags or a struct of the wrong size.
extern "win64" fn SHGetStockIconInfo(id: i32, flags: u32, info: *mut u8) -> u32 {
    if info.is_null() || id < 0 || id as usize >= STOCK_ICONS.len() || flags & !SHGSI_VALID != 0 {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's SHSTOCKICONINFO; cbSize is checked before more is written.
    unsafe {
        if core::ptr::read_unaligned(info as *const u32) != SHSTOCKICONINFO_SIZE {
            return E_INVALIDARG;
        }
        core::ptr::write_bytes(info.add(8), 0, SHSTOCKICONINFO_SIZE as usize - 8);
    }
    let (index, dll, system) = STOCK_ICONS[id as usize];
    let path = alloc::format!("C:\\Windows\\System32\\{}", STOCK_DLLS[dll as usize]);
    // SAFETY: as above; the path fits szPath (260 UTF-16 units).
    unsafe {
        core::ptr::write_unaligned(info.add(16) as *mut i32, if flags & SHGSI_SYSICONINDEX != 0 { system as i32 } else { -1 });
        core::ptr::write_unaligned(info.add(20) as *mut i32, index as i32);
        for (i, c) in path.encode_utf16().take(259).enumerate() {
            core::ptr::write_unaligned(info.add(24 + 2 * i) as *mut u16, c);
        }
        if flags & SHGSI_ICON != 0 {
            let size = if flags & SHGSI_SMALLICON != 0 { 16 } else { 32 };
            let kind = match id {
                3 | 4 | 175 | 176 => 1,        // folders
                0..=2 => 2,                     // documents
                5..=12 => 3,                    // drives
                _ => 0,
            };
            core::ptr::write_unaligned(info.add(8) as *mut u64, crate::user32::stock_icon(kind, size));
        }
    }
    S_OK
}

extern "win64" fn SHQueryUserNotificationState(out: *mut u32) -> u32 {
    if out.is_null() {
        return E_POINTER;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = 5 }; // QUNS_ACCEPTS_NOTIFICATIONS
    S_OK
}

/// The Recent folder as an OSyx path.
fn recent_dir() -> Option<String> {
    let win = location(Base::Profile("AppData\\Roaming\\Microsoft\\Windows\\Recent"));
    path::to_osyx(&win, "C:\\").ok()
}

/// A minimal Shell Link (MS-SHLLINK): header, then a LinkInfo block with the
/// local base path of the target, which is all Windows needs to resolve it.
fn shell_link(target: &str, directory: bool) -> Vec<u8> {
    let mut path = target.as_bytes().to_vec();
    path.push(0);
    let volume_id: [u8; 17] = {
        let mut v = [0u8; 17];
        v[0..4].copy_from_slice(&17u32.to_le_bytes()); // VolumeIDSize
        v[4..8].copy_from_slice(&3u32.to_le_bytes()); // DRIVE_FIXED
        v[12..16].copy_from_slice(&16u32.to_le_bytes()); // VolumeLabelOffset: an empty label
        v
    };
    let info_size = 0x1C + volume_id.len() + path.len() + 1;
    let mut l = Vec::new();
    l.extend_from_slice(&0x4Cu32.to_le_bytes());
    l.extend_from_slice(&[0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);
    l.extend_from_slice(&(0x2u32 | 0x80 | 0x10_0000).to_le_bytes()); // HasLinkInfo, IsUnicode, ForceNoLinkTrack
    l.extend_from_slice(&(if directory { 0x10u32 } else { 0x20 }).to_le_bytes());
    l.extend_from_slice(&[0u8; 24]); // creation, access and write times
    l.extend_from_slice(&0u32.to_le_bytes()); // file size
    l.extend_from_slice(&0u32.to_le_bytes()); // icon index
    l.extend_from_slice(&1u32.to_le_bytes()); // SW_SHOWNORMAL
    l.extend_from_slice(&[0u8; 10]); // hot key and reserved fields
    l.extend_from_slice(&(info_size as u32).to_le_bytes());
    l.extend_from_slice(&0x1Cu32.to_le_bytes()); // LinkInfoHeaderSize
    l.extend_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    l.extend_from_slice(&0x1Cu32.to_le_bytes()); // VolumeIDOffset
    l.extend_from_slice(&((0x1C + volume_id.len()) as u32).to_le_bytes()); // LocalBasePathOffset
    l.extend_from_slice(&0u32.to_le_bytes()); // CommonNetworkRelativeLinkOffset
    l.extend_from_slice(&((0x1C + volume_id.len() + path.len()) as u32).to_le_bytes()); // CommonPathSuffixOffset
    l.extend_from_slice(&volume_id);
    l.extend_from_slice(&path);
    l.push(0); // empty CommonPathSuffix
    l
}

/// SHARD_PIDL (1), SHARD_PATHA (2) and SHARD_PATHW (3) put a shortcut to the
/// file in the Recent folder; NULL empties it. Other kinds (application
/// ids, shell links) are not handled; the function cannot report that.
extern "win64" fn SHAddToRecentDocs(flags: u32, item: u64) {
    let Some(dir) = recent_dir() else { return };
    if item == 0 {
        if let Ok(entries) = os_std::fs::read_dir(&dir) {
            for e in entries {
                if e.file_name().ends_with(".lnk") {
                    let _ = os_std::fs::remove_file(e.path());
                }
            }
        }
        return;
    }
    // SAFETY: a PIDL of this module or a NUL-terminated string, by `flags`.
    let target = unsafe {
        match flags {
            1 => crate::commdlg::pidl_file_path(item).map(|p| path::to_windows(&p)),
            2 => path::ansi_to_string(item as *const u8),
            3 => path::wide_to_string(item as *const u16),
            _ => None,
        }
    };
    let Some(target) = target.filter(|t| !t.is_empty()) else { return };
    let directory = kernel32::locate(&target).ok().is_some_and(|(p, exists)| exists && os_sys::stat(&p).is_ok_and(|s| s.kind == osyx_abi::KIND_DIR));
    let name = target.trim_end_matches('\\').rsplit('\\').next().unwrap_or("");
    if name.is_empty() || os_std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let _ = os_std::fs::write(format!("{dir}/{name}.lnk"), shell_link(&target, directory));
}

extern "win64" fn SHChangeNotify(_event: i32, _flags: u32, _a: u64, _b: u64) {}

extern "win64" fn SHOpenFolderAndSelectItems(folder: u64, _count: u32, _items: u64, _flags: u32) -> u32 {
    // A PIDL from this runtime names one OSyx path; show its folder.
    let Some(path) = crate::commdlg::pidl_file_path(folder) else { return E_FAIL };
    let dir = parent_dir(&path).trim_end_matches('/');
    let dir = if dir.is_empty() { "/" } else { dir };
    match spawn_line(&format!("/system/bin/files {}", quote_win_arg(dir)), None) {
        Ok(handle) => {
            crate::objects::close(handle);
            S_OK
        }
        Err(_) => E_FAIL,
    }
}

extern "win64" fn SHParseDisplayName(_name: *const u16, _bind: u64, pidl: *mut u64, _in: u32, out: *mut u32) -> u32 {
    if !pidl.is_null() {
        // SAFETY: the caller's out pointers.
        unsafe { *pidl = 0 };
    }
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    E_NOTIMPL
}

extern "win64" fn SHCreateItemFromParsingName(_name: *const u16, _bind: u64, _riid: *const u8, out: *mut u64) -> u32 {
    if !out.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = 0 };
    }
    E_NOTIMPL
}

extern "win64" fn SHGetKnownFolderItem(_id: *const u8, _flags: u32, _token: u64, _riid: *const u8, out: *mut u64) -> u32 {
    if !out.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = 0 };
    }
    E_NOTIMPL
}

const SE_ERR_FNF: u64 = 2;
const SE_ERR_ACCESSDENIED: u64 = 5;
const SE_ERR_OOM: u64 = 8;
const SE_ERR_NOASSOC: u64 = 31;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_ASSOCIATION: u32 = 1155;

/// One argument for a Windows command line.
fn quote_win_arg(s: &str) -> String {
    if !s.is_empty() && !s.contains([' ', '\t', '"']) {
        return String::from(s);
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in s.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                for _ in 0..backslashes + 1 {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push(c);
                backslashes = 0;
            }
        }
    }
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Starts one command line through CreateProcessW, the same path a Windows
/// program uses for its children (a PE runs under a child winrun).
fn spawn_line(line: &str, dir: Option<&str>) -> Result<u64, u32> {
    let mut line: Vec<u16> = line.encode_utf16().chain(core::iter::once(0)).collect();
    let mut dir: Option<Vec<u16>> = dir.map(|d| d.encode_utf16().chain(core::iter::once(0)).collect());
    let mut startup = [0u64; 13];
    startup[0] = 104; // cb = sizeof(STARTUPINFOW)
    let mut process = [0u64; 3];
    // SAFETY: all buffers are valid for the call; startup declares 104
    // bytes and CreateProcessW writes one PROCESS_INFORMATION.
    let ok = crate::process::CreateProcessW(
        core::ptr::null(),
        line.as_mut_ptr(),
        0,
        0,
        0,
        0,
        0,
        dir.as_mut().map_or(core::ptr::null(), |d| d.as_mut_ptr()),
        startup.as_ptr() as *const u8,
        process.as_mut_ptr(),
    );
    if ok == 0 {
        return Err(crate::teb::last_error());
    }
    crate::objects::close(process[1]);
    Ok(process[0])
}

fn parent_dir(path: &str) -> &str {
    match path.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((dir, _)) => dir,
    }
}

/// The ShellExecute error that matches a CreateProcess error.
fn se_error(win32: u32) -> u64 {
    match win32 {
        ERROR_FILE_NOT_FOUND | 3 => SE_ERR_FNF,
        5 => SE_ERR_ACCESSDENIED,
        8 => SE_ERR_OOM,
        1155 => SE_ERR_NOASSOC,
        _ => SE_ERR_NOASSOC,
    }
}

/// ShellExecute's "open" and "explore" on OSyx: Windows programs run under
/// a child winrun, folders open in Files, web files and URLs in the default
/// browser. Anything else has no registered handler, which callers like
/// Firefox already report to the user.
fn shell_launch(verb: &str, file: &str, params: Option<&str>, dir: Option<&str>) -> Result<u64, (u64, u32)> {
    let file = file.trim();
    if file.is_empty() {
        return Err((SE_ERR_FNF, ERROR_FILE_NOT_FOUND));
    }
    if ["http://", "https://", "file://", "about:"].iter().any(|p| file.starts_with(p)) {
        return spawn_line(&format!("/bin/open {}", quote_win_arg(file)), None)
            .map_err(|e| (se_error(e), e));
    }
    // SAFETY: a NUL-terminated path from the caller.
    let Ok((osyx, true)) = kernel32::locate(file) else {
        return Err((SE_ERR_FNF, ERROR_FILE_NOT_FOUND));
    };
    let Ok(stat) = os_sys::stat(&osyx) else { return Err((SE_ERR_FNF, ERROR_FILE_NOT_FOUND)) };
    if stat.kind == osyx_abi::KIND_DIR {
        if matches!(verb, "" | "open" | "explore") {
            return spawn_line(&format!("/system/bin/files {}", quote_win_arg(&osyx)), None)
                .map_err(|e| (se_error(e), e));
        }
        return Err((SE_ERR_NOASSOC, ERROR_NO_ASSOCIATION));
    }
    if verb == "explore" {
        return spawn_line(&format!("/system/bin/files {}", quote_win_arg(parent_dir(&osyx))), None)
            .map_err(|e| (se_error(e), e));
    }
    if !verb.is_empty() && verb != "open" {
        return Err((SE_ERR_NOASSOC, ERROR_NO_ASSOCIATION));
    }
    let lower = osyx.to_ascii_lowercase();
    if lower.ends_with(".exe") {
        let mut line = quote_win_arg(&osyx);
        if let Some(p) = params.map(str::trim).filter(|p| !p.is_empty()) {
            line.push(' ');
            line.push_str(p);
        }
        return spawn_line(&line, dir).map_err(|e| (se_error(e), e));
    }
    if [".html", ".htm", ".xhtml"].iter().any(|e| lower.ends_with(e)) {
        return spawn_line(&format!("/bin/open {}", quote_win_arg(&osyx)), None).map_err(|e| (se_error(e), e));
    }
    Err((SE_ERR_NOASSOC, ERROR_NO_ASSOCIATION))
}

extern "win64" fn ShellExecuteW(_hwnd: u64, op: *const u16, file: *const u16, params: *const u16, dir: *const u16, _show: i32) -> u64 {
    // SAFETY: NULL or NUL-terminated strings from the caller.
    let (verb, file, params, dir) = unsafe {
        (path::wide_to_string(op), path::wide_to_string(file), path::wide_to_string(params), path::wide_to_string(dir))
    };
    let Some(file) = file else {
        crate::teb::set_last_error(ERROR_NO_ASSOCIATION);
        return SE_ERR_FNF;
    };
    let verb = verb.unwrap_or_default().to_ascii_lowercase();
    match shell_launch(&verb, &file, params.as_deref(), dir.as_deref()) {
        Ok(handle) => {
            crate::objects::close(handle);
            42 // > 32: success, as on Windows
        }
        Err((error, win32)) => {
            crate::teb::set_last_error(win32);
            error
        }
    }
}

/// SHELLEXECUTEINFOW.hInstApp, at byte 56 of the x64 layout.
const SHELLEXECUTEINFO_HINSTAPP: usize = 56;
const SHELLEXECUTEINFO_HPROCESS: usize = 104;
const SHELLEXECUTEINFO_SIZE: u32 = 112;
const SEE_MASK_NOCLOSEPROCESS: u32 = 0x40;
const ERROR_INVALID_PARAMETER: u32 = 87;

extern "win64" fn ShellExecuteExW(info: *mut u8) -> i32 {
    if info.is_null() {
        crate::teb::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: cbSize is the first field of the caller's struct.
    let (cb, mask) = unsafe {
        (core::ptr::read_unaligned(info as *const u32), core::ptr::read_unaligned((info as *const u32).add(1)))
    };
    if cb < SHELLEXECUTEINFO_SIZE {
        crate::teb::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the validated struct has every field below; strings are NULL
    // or NUL-terminated.
    let (verb, file, params, dir) = unsafe {
        let field = |at: usize| core::ptr::read_unaligned(info.add(at) as *const u64) as *const u16;
        (path::wide_to_string(field(16)), path::wide_to_string(field(24)), path::wide_to_string(field(32)), path::wide_to_string(field(40)))
    };
    // SAFETY: inside the validated struct.
    let (hinst, hprocess) = unsafe {
        ((info.add(SHELLEXECUTEINFO_HINSTAPP) as *mut u64), (info.add(SHELLEXECUTEINFO_HPROCESS) as *mut u64))
    };
    unsafe { hprocess.write_unaligned(0) };
    let Some(file) = file else {
        crate::teb::set_last_error(ERROR_NO_ASSOCIATION);
        unsafe { hinst.write_unaligned(SE_ERR_FNF) };
        return 0;
    };
    let verb = verb.unwrap_or_default().to_ascii_lowercase();
    match shell_launch(&verb, &file, params.as_deref(), dir.as_deref()) {
        Ok(handle) => {
            unsafe { hinst.write_unaligned(42) };
            if mask & SEE_MASK_NOCLOSEPROCESS != 0 {
                unsafe { hprocess.write_unaligned(handle) };
            } else {
                crate::objects::close(handle);
            }
            1
        }
        Err((error, win32)) => {
            crate::teb::set_last_error(win32);
            unsafe { hinst.write_unaligned(error) };
            0
        }
    }
}


extern "win64" fn Shell_NotifyIconW(_message: u32, _data: u64) -> i32 {
    // There is no notification area: the icon cannot be added, changed or removed.
    crate::kernel32::fail(crate::error::ERROR_NOT_SUPPORTED, 0)
}

extern "win64" fn DragQueryFileW(drop: u64, index: u32, buf: *mut u16, count: u32) -> u32 {
    if drop == 0 { return 0; }
    // SAFETY: HDROP is an HGLOBAL returned by the data object.
    let len = kernel32::heap_size(drop);
    if len < 20 { return 0; }
    let data = unsafe { core::slice::from_raw_parts(drop as *const u8, len) };
    let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let wide = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) != 0;
    let Some(bytes) = data.get(offset..) else { return 0 };
    let units: Vec<u16> = if wide { bytes.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect() }
        else { bytes.iter().map(|&b| b as u16).collect() };
    let mut files = Vec::new();
    let mut start = 0;
    while start < units.len() {
        let Some(end) = units[start..].iter().position(|&u| u == 0).map(|n| start + n) else { return 0 };
        if end == start { break; }
        files.push(&units[start..end]);
        start = end + 1;
    }
    if index == u32::MAX { return files.len() as u32; }
    let Some(file) = files.get(index as usize) else { return 0 };
    if !buf.is_null() && count > 0 {
        let n = file.len().min(count as usize - 1);
        // SAFETY: the caller supplies a writable buffer of `count` WCHARs.
        unsafe { core::ptr::copy_nonoverlapping(file.as_ptr(), buf, n); *buf.add(n) = 0; }
        return n as u32;
    }
    file.len() as u32
}

extern "win64" fn ILCreateFromPathW(path: *const u16) -> u64 {
    // SAFETY: NULL or NUL-terminated path from the caller.
    let Some(win) = (unsafe { path::wide_to_string(path) }) else { return 0 };
    match kernel32::locate(&win) {
        Ok((osyx, true)) => crate::commdlg::allocate_pidl(&osyx),
        _ => 0,
    }
}

extern "win64" fn ILCreateFromPathA(path: *const u8) -> u64 {
    // SAFETY: NULL or NUL-terminated ANSI path; the wide copy lives for this call.
    let Some(wide) = (unsafe { path::ansi_to_wide(path) }) else { return 0 };
    ILCreateFromPathW(wide.as_ptr())
}

/// Functions xul.dll delay-imports by number; the numbers are the Windows
/// shell32 ordinals (155 ILFree, 190 ILCreateFromPathW).
extern "win64" fn IsUserAnAdmin() -> i32 {
    crate::accounts::is_admin() as i32
}

pub fn ordinals() -> Vec<(u16, u64)> {
    alloc::vec![(155, crate::commdlg::il_free_address()), (190, ILCreateFromPathW as *const () as u64), (680, IsUserAnAdmin as *const () as u64)]
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        IsUserAnAdmin,
        SHGetKnownFolderPath,
        SHGetFolderPathW,
        SHGetSpecialFolderPathA,
        SHGetSpecialFolderLocation,
        SHGetFileInfoW,
        SHFileOperationW,
        SHGetFileInfoA,
        SHGetStockIconInfo,
        SHQueryUserNotificationState,
        SHAddToRecentDocs,
        SHChangeNotify,
        SHOpenFolderAndSelectItems,
        SHParseDisplayName,
        SHCreateItemFromParsingName,
        SHGetKnownFolderItem,
        ILCreateFromPathW,
        ILCreateFromPathA,
        ShellExecuteW,
        ShellExecuteExW,
        Shell_NotifyIconW,
        DragQueryFileW,
        CommandLineToArgvW,
        GetCurrentProcessExplicitAppUserModelID,
        SetCurrentProcessExplicitAppUserModelID,
        SHGetPropertyStoreForWindow,
    ]
}
