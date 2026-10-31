//! Small system DLLs xul.dll links against: rpcrt4 (UUID strings),
//! cfgmgr32 (device interfaces and notifications), ktmw32 (transactions),
//! windowscodecs (format conversion), bcryptprimitives (the process
//! random generator) and shcore (monitor scaling).
//!
//! OSyx has one display at 96 DPI and 100% scale, exposes no Windows
//! device interfaces (lists are empty and no device arrival is ever
//! reported to a registered notification), has no Kernel Transaction
//! Manager, and no WIC codecs.
#![allow(non_snake_case)]
use crate::{error::*, kernel32::fail, path, teb};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use os_std::io::{Read as _, Seek as _, SeekFrom};
use os_std::sync::Mutex;

// ---- rpcrt4 ------------------------------------------------------------------------

const RPC_S_OK: u32 = 0;
const RPC_S_OUT_OF_MEMORY: u32 = 14;
const RPC_S_INVALID_STRING_UUID: u32 = 1705;

/// GUID { Data1 u32, Data2 u16, Data3 u16, Data4 [u8; 8] } as text.
fn uuid_text(u: *const u8) -> String {
    // SAFETY: the caller's 16-byte UUID.
    let (d1, d2, d3, d4) = unsafe { (teb::get::<u32>(u as u64, 0), teb::get::<u16>(u as u64, 4), teb::get::<u16>(u as u64, 6), teb::get::<[u8; 8]>(u as u64, 8)) };
    alloc::format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    )
}

extern "win64" fn UuidToStringA(u: *const u8, out: *mut u64) -> u32 {
    if u.is_null() || out.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let t = uuid_text(u);
    let Some(p) = crate::kernel32::heap_alloc(t.len() + 1, true) else { return RPC_S_OUT_OF_MEMORY };
    // SAFETY: a fresh zeroed block with room for the NUL.
    unsafe {
        core::ptr::copy_nonoverlapping(t.as_ptr(), p as *mut u8, t.len());
        *out = p;
    }
    RPC_S_OK
}

extern "win64" fn UuidToStringW(u: *const u8, out: *mut u64) -> u32 {
    if u.is_null() || out.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let w: Vec<u16> = uuid_text(u).encode_utf16().chain(core::iter::once(0)).collect();
    let Some(p) = crate::kernel32::heap_alloc(w.len() * 2, false) else { return RPC_S_OUT_OF_MEMORY };
    // SAFETY: a fresh block of w.len() units.
    unsafe {
        core::ptr::copy_nonoverlapping(w.as_ptr(), p as *mut u16, w.len());
        *out = p;
    }
    RPC_S_OK
}

/// NULL gives the nil UUID, as on Windows.
extern "win64" fn UuidFromStringW(s: *const u16, out: *mut u8) -> u32 {
    if out.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: NULL or a NUL-terminated string.
    let text = unsafe { path::wide_to_string(s) };
    let mut bytes = [0u8; 16];
    if let Some(t) = text {
        let parts: Vec<&str> = t.split('-').collect();
        let lens = [8, 4, 4, 4, 12];
        if parts.len() != 5 || parts.iter().zip(lens).any(|(p, l)| p.len() != l || !p.bytes().all(|b| b.is_ascii_hexdigit())) {
            return RPC_S_INVALID_STRING_UUID;
        }
        let hex = |s: &str| u64::from_str_radix(s, 16).unwrap_or(0);
        bytes[0..4].copy_from_slice(&(hex(parts[0]) as u32).to_le_bytes());
        bytes[4..6].copy_from_slice(&(hex(parts[1]) as u16).to_le_bytes());
        bytes[6..8].copy_from_slice(&(hex(parts[2]) as u16).to_le_bytes());
        bytes[8..10].copy_from_slice(&(hex(parts[3]) as u16).to_be_bytes());
        bytes[10..16].copy_from_slice(&hex(parts[4]).to_be_bytes()[2..]);
    }
    // SAFETY: the caller's 16-byte UUID.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 16) };
    RPC_S_OK
}

fn string_free(p: *mut u64) -> u32 {
    if p.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the caller's string pointer.
    unsafe {
        if *p != 0 {
            crate::kernel32::heap_free(*p);
        }
        *p = 0;
    }
    RPC_S_OK
}

extern "win64" fn RpcStringFreeA(p: *mut u64) -> u32 {
    string_free(p)
}

extern "win64" fn RpcStringFreeW(p: *mut u64) -> u32 {
    string_free(p)
}

pub fn rpcrt4_exports() -> Vec<(&'static str, u64)> {
    export_table![UuidToStringA, UuidToStringW, UuidFromStringW, RpcStringFreeA, RpcStringFreeW]
}

// ---- cfgmgr32 --------------------------------------------------------------------------

const CR_SUCCESS: u32 = 0;
const CR_INVALID_POINTER: u32 = 3;
const CR_INVALID_FLAG: u32 = 4;
const CR_INVALID_DEVNODE: u32 = 5;
const CR_INVALID_DATA: u32 = 31;

/// No Windows device instances exist, so no DEVINST is valid.
extern "win64" fn CM_Get_Device_IDW(_devinst: u32, buf: *mut u16, _len: u32, flags: u32) -> u32 {
    if buf.is_null() {
        return CR_INVALID_POINTER;
    }
    if flags != 0 {
        return CR_INVALID_FLAG;
    }
    CR_INVALID_DEVNODE
}

/// Interface lists are empty: one NUL closes the empty multi-string.
extern "win64" fn CM_Get_Device_Interface_List_SizeW(len: *mut u32, class: *const u8, _device: *const u16, flags: u32) -> u32 {
    if len.is_null() || class.is_null() {
        return CR_INVALID_POINTER;
    }
    if flags & !1 != 0 {
        return CR_INVALID_FLAG;
    }
    // SAFETY: the caller's out length.
    unsafe { *len = 1 };
    CR_SUCCESS
}

static NOTIFICATIONS: AtomicU64 = AtomicU64::new(0x0c3f_0000);
static OPEN_NOTIFICATIONS: os_std::sync::Mutex<Vec<u64>> = os_std::sync::Mutex::new(Vec::new());

/// CM_NOTIFY_FILTER: registration succeeds; no device event is delivered.
extern "win64" fn CM_Register_Notification(filter: *const u8, _context: u64, callback: u64, out: *mut u64) -> u32 {
    if filter.is_null() || callback == 0 || out.is_null() {
        return CR_INVALID_POINTER;
    }
    // SAFETY: the filter's cbSize.
    if unsafe { teb::get::<u32>(filter as u64, 0) } < 8 {
        return CR_INVALID_DATA;
    }
    let h = NOTIFICATIONS.fetch_add(4, Ordering::Relaxed);
    OPEN_NOTIFICATIONS.lock().unwrap().push(h);
    // SAFETY: the caller's out pointer.
    unsafe { *out = h };
    CR_SUCCESS
}

extern "win64" fn CM_Unregister_Notification(h: u64) -> u32 {
    let mut open = OPEN_NOTIFICATIONS.lock().unwrap();
    match open.iter().position(|&x| x == h) {
        Some(i) => {
            open.remove(i);
            CR_SUCCESS
        }
        None => CR_INVALID_DATA,
    }
}

pub fn cfgmgr32_exports() -> Vec<(&'static str, u64)> {
    export_table![CM_Get_Device_IDW, CM_Get_Device_Interface_List_SizeW, CM_Register_Notification, CM_Unregister_Notification]
}

// ---- ktmw32 ------------------------------------------------------------------------------

pub fn ktmw32_exports() -> Vec<(&'static str, u64)> {
    crate::ktm::exports()
}

// ---- windowscodecs -------------------------------------------------------------------------

/// No WIC components are installed to convert with.
extern "win64" fn WICConvertBitmapSource(_format: *const u8, source: u64, out: *mut u64) -> u32 {
    if source == 0 || out.is_null() {
        return 0x8007_0057; // E_INVALIDARG
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = 0 };
    0x8898_2F50 // WINCODEC_ERR_COMPONENTNOTFOUND
}

pub fn windowscodecs_exports() -> Vec<(&'static str, u64)> {
    export_table![WICConvertBitmapSource]
}

// ---- uxtheme ---------------------------------------------------------------------------------

/// Visual styles are off: the desktop draws its own widgets, so there is no
/// theme to hand out and every query says so. Programs then take the classic
/// drawing path, which is the one OSyx implements (user32/gdi32), instead of
/// asking for theme parts OSyx cannot draw.
extern "win64" fn IsThemeActive() -> u8 {
    0
}

extern "win64" fn IsAppThemed() -> u8 {
    0
}

extern "win64" fn OpenThemeData(_wnd: u64, _classes: *const u16) -> u64 {
    0 // no theme: callers fall back to classic drawing
}

extern "win64" fn CloseThemeData(theme: u64) -> u32 {
    if theme == 0 {
        E_INVALIDARG
    } else {
        0 // S_OK
    }
}

extern "win64" fn GetThemeColor(theme: u64, _part: i32, _state: i32, _property: i32, out: *mut u32) -> u32 {
    if theme == 0 || out.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's COLORREF.
    unsafe { *out = 0 };
    E_INVALIDARG // no theme colours exist without a theme
}

/// Touch panning feedback needs a themed window manager.
extern "win64" fn BeginPanningFeedback(_wnd: u64) -> i32 {
    crate::kernel32::fail(crate::error::ERROR_NOT_SUPPORTED, 0)
}

extern "win64" fn UpdatePanningFeedback(_wnd: u64, _x: i32, _y: i32, _overshoot: i32) -> i32 {
    crate::kernel32::fail(crate::error::ERROR_NOT_SUPPORTED, 0)
}

extern "win64" fn EndPanningFeedback(_wnd: u64, _animate: i32) -> i32 {
    crate::kernel32::fail(crate::error::ERROR_NOT_SUPPORTED, 0)
}

pub fn uxtheme_exports() -> Vec<(&'static str, u64)> {
    export_table![
        IsThemeActive,
        IsAppThemed,
        OpenThemeData,
        CloseThemeData,
        GetThemeColor,
        BeginPanningFeedback,
        UpdatePanningFeedback,
        EndPanningFeedback
    ]
}

// ---- bcryptprimitives ------------------------------------------------------------------------

/// Fills `buf` from the kernel's CSPRNG (/dev/random). Windows documents
/// ProcessPrng as never failing; if the device is unreadable OSyx has no
/// safe answer, so the process ends rather than use predictable bytes.
extern "win64" fn ProcessPrng(buf: *mut u8, len: usize) -> i32 {
    if len == 0 {
        return 1;
    }
    // SAFETY: the caller's buffer of `len` bytes.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    if !crate::ucrt::entropy(out) {
        os_std::process::exit(0x4000_0000 | 0xC000_0001u32 as i32 & 0x0FFF_FFFF);
    }
    1
}

pub fn bcryptprimitives_exports() -> Vec<(&'static str, u64)> {
    export_table![ProcessPrng]
}

// ---- shcore ------------------------------------------------------------------------------------

/// The one monitor's handle (MonitorFromWindow and friends return it).
pub const PRIMARY_MONITOR: u64 = 0x0001_0001;
const E_INVALIDARG: u32 = 0x8007_0057;
/// HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE): not a monitor handle.
const E_HANDLE: u32 = 0x8007_0006;

extern "win64" fn GetDpiForMonitor(monitor: u64, kind: u32, x: *mut u32, y: *mut u32) -> u32 {
    if monitor != PRIMARY_MONITOR {
        return E_HANDLE;
    }
    if kind > 2 || x.is_null() || y.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's out pointers.
    unsafe {
        *x = 96;
        *y = 96;
    }
    0
}

extern "win64" fn GetScaleFactorForMonitor(monitor: u64, scale: *mut u32) -> u32 {
    if monitor != PRIMARY_MONITOR {
        return E_HANDLE;
    }
    if scale.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *scale = 100 }; // SCALE_100_PERCENT
    0
}

pub fn shcore_exports() -> Vec<(&'static str, u64)> {
    export_table![GetDpiForMonitor, GetScaleFactorForMonitor]
}

// ---- wininet -----------------------------------------------------------------------------------

/// Networking here is plain sockets over the emulated LAN, so the Internet
/// connection is always up; Gecko only asks wininet whether it is.
const INTERNET_CONNECTION_LAN: u32 = 0x02;
const INTERNET_CONNECTION_CONFIGURED: u32 = 0x04;

extern "win64" fn InternetGetConnectedState(flags: *mut u32, _reserved: u32) -> crate::kernel32::Bool {
    if !flags.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *flags = INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_CONFIGURED };
    }
    crate::kernel32::TRUE
}

extern "win64" fn InternetGetConnectedStateExW(
    flags: *mut u32,
    name: *mut u16,
    name_len: u32,
    _reserved: u32,
) -> crate::kernel32::Bool {
    if !flags.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *flags = INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_CONFIGURED };
    }
    if !name.is_null() && name_len > 1 {
        // SAFETY: room for name_len UTF-16 units, as the caller promises.
        unsafe {
            *name = b'L' as u16;
            *name.add(1) = 0;
        }
    }
    crate::kernel32::TRUE
}

extern "win64" fn InternetGetConnectedStateExA(
    flags: *mut u32,
    name: *mut u8,
    name_len: u32,
    _reserved: u32,
) -> crate::kernel32::Bool {
    if !flags.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *flags = INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_CONFIGURED };
    }
    if !name.is_null() && name_len > 1 {
        // SAFETY: room for name_len bytes, as the caller promises.
        unsafe {
            *name = b'L';
            *name.add(1) = 0;
        }
    }
    crate::kernel32::TRUE
}

/// Whether the system has a network connection: an adapter with an
/// address. FLAG_ICC_FORCE_CONNECTION (a connection attempt to the URL) is
/// not supported.
extern "win64" fn InternetCheckConnectionW(_url: *const u16, flags: u32, reserved: u32) -> crate::kernel32::Bool {
    if reserved != 0 || flags & !1 != 0 {
        return crate::kernel32::fail(ERROR_INVALID_PARAMETER, crate::kernel32::FALSE);
    }
    if flags & 1 != 0 {
        return crate::kernel32::fail(crate::error::ERROR_NOT_SUPPORTED, crate::kernel32::FALSE);
    }
    if crate::iphlpapi::has_connectivity() {
        crate::kernel32::TRUE
    } else {
        crate::kernel32::fail(12163, crate::kernel32::FALSE) // ERROR_INTERNET_DISCONNECTED
    }
}

/// ERROR_SUCCESS when a network adapter has an address, otherwise
/// ERROR_INTERNET_DISCONNECTED.
extern "win64" fn InternetAttemptConnect(reserved: u32) -> u32 {
    if reserved != 0 {
        return ERROR_INVALID_PARAMETER;
    }
    if crate::iphlpapi::has_connectivity() { ERROR_SUCCESS } else { 12163 }
}

/// There is no WinINet session state to query; callers fall back to a
/// direct connection.
extern "win64" fn InternetQueryOptionW(_session: u64, _option: u32, _buffer: *mut u8, _len: *mut u32) -> crate::kernel32::Bool {
    crate::kernel32::fail(ERROR_INVALID_PARAMETER, crate::kernel32::FALSE)
}

/// OSyx has no WinINet sessions: only the process-wide options (handle
/// NULL) INTERNET_OPTION_REFRESH (37) and INTERNET_OPTION_SETTINGS_CHANGED
/// (39) exist, and with no cached proxy or settings state they have nothing
/// to refresh. Anything else is an invalid handle or option.
extern "win64" fn InternetSetOptionW(session: u64, option: u32, _buffer: *const u8, _len: u32) -> crate::kernel32::Bool {
    if session != 0 {
        return crate::kernel32::fail(ERROR_INVALID_HANDLE, crate::kernel32::FALSE);
    }
    match option {
        37 | 39 => crate::kernel32::TRUE,
        _ => crate::kernel32::fail(12009, crate::kernel32::FALSE), // ERROR_INTERNET_INVALID_OPTION
    }
}

/// No WinINet function here creates a handle, so every handle is invalid.
extern "win64" fn InternetCloseHandle(_session: u64) -> crate::kernel32::Bool {
    crate::kernel32::fail(ERROR_INVALID_HANDLE, crate::kernel32::FALSE)
}

pub fn wininet_exports() -> Vec<(&'static str, u64)> {
    export_table![
        InternetGetConnectedState,
        InternetGetConnectedStateExW,
        InternetGetConnectedStateExA,
        InternetCheckConnectionW,
        InternetAttemptConnect,
        InternetQueryOptionW,
        InternetSetOptionW,
        InternetCloseHandle,
    ]
}

// ---- wintrust -----------------------------------------------------------------------

// WINTRUST_DATA and WINTRUST_FILE_INFO field offsets, x86-64.
const WTD_UNION_CHOICE: usize = 32;
const WTD_FILE_INFO: usize = 40;
const WTD_STATE_ACTION: usize = 48;
const WTD_STATE_DATA: usize = 56;
const WTD_MIN_CB: u32 = 64;
const WTFI_PATH: usize = 8;
const WTFI_MIN_CB: u32 = 24;

const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
const WTD_CHOICE_FILE: u32 = 1;

/// WINTRUST_ACTION_GENERIC_VERIFY_V2, the only action OSyx implements.
const WINTRUST_ACTION_GENERIC_VERIFY_V2: [u8; 16] =
    [0x6b, 0xc5, 0xaa, 0x00, 0x44, 0xcd, 0xd0, 0x11, 0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee];

const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800b_0003;
const TRUST_E_NOSIGNATURE: u32 = 0x800b_0100;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
const HRESULT_FILE_NOT_FOUND: u32 = 0x8007_0002;

/// sizeof(CRYPT_PROVIDER_DATA); callers read csSigners at offset 120.
const PROVIDER_DATA_SIZE: usize = 224;
/// A PKCS#7 blob in a certificate table is a few tens of kilobytes.
const SIGNATURE_MAX: u64 = 4 << 20;

/// Live CRYPT_PROVIDER_DATA blocks, keyed by the handle returned to callers.
static PROVIDER_STATES: Mutex<Vec<u64>> = Mutex::new(Vec::new());

enum PeSignature {
    /// No Authenticode signature, or the file is not a PE image.
    None,
    /// A certificate table or PKCS#7 signature that cannot be decoded.
    Malformed,
    Signed,
}

fn read_at(f: &mut os_std::fs::File, at: u64, buf: &mut [u8]) -> bool {
    f.seek(SeekFrom::Start(at)).is_ok() && f.read_exact(buf).is_ok()
}

/// Finds and decodes the PKCS#7 signature in the image's certificate table
/// (data directory 4). The file is read in place: only the headers and the
/// signature blob, never the whole image.
fn pe_signature(f: &mut os_std::fs::File) -> PeSignature {
    let mut dos = [0u8; 64];
    if !read_at(f, 0, &mut dos) || &dos[..2] != b"MZ" {
        return PeSignature::None;
    }
    let e_lfanew = u32::from_le_bytes([dos[0x3c], dos[0x3d], dos[0x3e], dos[0x3f]]) as u64;
    let mut coff = [0u8; 24];
    if !read_at(f, e_lfanew, &mut coff) || &coff[..4] != b"PE\0\0" {
        return PeSignature::None;
    }
    let opt_size = u16::from_le_bytes([coff[20], coff[21]]) as u64;
    let opt = e_lfanew + 24;
    let mut magic = [0u8; 2];
    if !read_at(f, opt, &mut magic) {
        return PeSignature::None;
    }
    let dirs = match u16::from_le_bytes(magic) {
        0x10b => 96,  // PE32
        0x20b => 112, // PE32+
        _ => return PeSignature::None,
    };
    let mut directory = [0u8; 8];
    if opt_size < dirs + 5 * 8 || !read_at(f, opt + dirs + 4 * 8, &mut directory) {
        return PeSignature::None;
    }
    let offset = u32::from_le_bytes([directory[0], directory[1], directory[2], directory[3]]) as u64;
    let size = u32::from_le_bytes([directory[4], directory[5], directory[6], directory[7]]) as u64;
    if size == 0 {
        return PeSignature::None;
    }
    let Ok(meta) = f.metadata() else { return PeSignature::None };
    if offset.checked_add(size).is_none_or(|end| end > meta.len() || offset < opt + opt_size || size < 8) {
        return PeSignature::Malformed;
    }
    let mut at = 0;
    while at + 8 <= size {
        let mut header = [0u8; 8];
        if !read_at(f, offset + at, &mut header) {
            return PeSignature::Malformed;
        }
        let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as u64;
        let kind = u16::from_le_bytes([header[6], header[7]]);
        if len < 8 || at + len > size || len > SIGNATURE_MAX {
            return PeSignature::Malformed;
        }
        if kind == 2 {
            // WIN_CERT_TYPE_PKCS_SIGNED_DATA
            let mut der = alloc::vec![0u8; (len - 8) as usize];
            if !read_at(f, offset + at + 8, &mut der) {
                return PeSignature::Malformed;
            }
            return if crate::crypt32::authenticode_has_signer(&der) {
                PeSignature::Signed
            } else {
                PeSignature::Malformed
            };
        }
        at += (len + 7) & !7;
    }
    PeSignature::None
}

/// Checks the WINTRUST_DATA of a WTD_STATEACTION_VERIFY call and, when the
/// file carries a decodable Authenticode signature, records provider state.
/// OSyx has no trust store: the signature's chain and digest are not
/// evaluated, so this is a structural check, not a trust decision.
fn verify_authenticode(wtd: *mut u8) -> Result<(), u32> {
    let choice = unsafe { teb::get::<u32>(wtd as u64, WTD_UNION_CHOICE) };
    if choice != WTD_CHOICE_FILE {
        return Err(TRUST_E_SUBJECT_FORM_UNKNOWN);
    }
    let info = unsafe { teb::get::<u64>(wtd as u64, WTD_FILE_INFO) };
    if info == 0 || unsafe { teb::get::<u32>(info, 0) } < WTFI_MIN_CB {
        return Err(E_INVALIDARG);
    }
    let path_ptr = unsafe { teb::get::<u64>(info, WTFI_PATH) };
    let Some(win) = (unsafe { path::wide_to_string(path_ptr as *const u16) }) else {
        return Err(E_INVALIDARG);
    };
    let Ok(os) = path::to_osyx(&win, &crate::kernel32::cwd_win()) else {
        return Err(HRESULT_FILE_NOT_FOUND);
    };
    let Ok(mut file) = os_std::fs::File::open(&os) else {
        return Err(HRESULT_FILE_NOT_FOUND);
    };
    match pe_signature(&mut file) {
        PeSignature::Signed => {
            provider_state(wtd);
            Ok(())
        }
        PeSignature::None => Err(TRUST_E_NOSIGNATURE),
        PeSignature::Malformed => Err(TRUST_E_BAD_DIGEST),
    }
}

/// Allocates and registers the zeroed CRYPT_PROVIDER_DATA handed back as
/// hWVTStateData. csSigners stays 0, so callers skip chain processing but
/// still close the state afterwards.
fn provider_state(wtd: *mut u8) {
    let block = Box::into_raw(Box::new([0u8; PROVIDER_DATA_SIZE]));
    let at = block as u64;
    // SAFETY: `block` is a live PROVIDER_DATA_SIZE-byte allocation and
    // `wtd` points at a writable WINTRUST_DATA (cbStruct was checked).
    unsafe {
        teb::put::<u32>(at, 0, PROVIDER_DATA_SIZE as u32);
        teb::put::<u64>(at, 8, wtd as u64); // pWintrustData
        teb::put::<u64>(wtd as u64, WTD_STATE_DATA, at);
    }
    PROVIDER_STATES.lock().unwrap().push(at);
}

extern "win64" fn WinVerifyTrust(_hwnd: u64, action: *const u8, data: *mut u8) -> i32 {
    if action.is_null() || data.is_null() {
        return E_INVALIDARG as i32;
    }
    // SAFETY: per the API contract `action` is a GUID and `data` a
    // WINTRUST_DATA; their cbStruct fields are checked below.
    let act = unsafe { teb::get::<[u8; 16]>(action as u64, 0) };
    if act != WINTRUST_ACTION_GENERIC_VERIFY_V2 {
        return TRUST_E_SUBJECT_FORM_UNKNOWN as i32;
    }
    if unsafe { teb::get::<u32>(data as u64, 0) } < WTD_MIN_CB {
        return E_INVALIDARG as i32;
    }
    let state_action = unsafe { teb::get::<u32>(data as u64, WTD_STATE_ACTION) };
    let state = unsafe { teb::get::<u64>(data as u64, WTD_STATE_DATA) };
    match state_action {
        WTD_STATEACTION_CLOSE => {
            if state != 0 {
                let mut states = PROVIDER_STATES.lock().unwrap();
                let Some(i) = states.iter().position(|&s| s == state) else {
                    return E_INVALIDARG as i32;
                };
                states.remove(i);
                drop(states);
                // SAFETY: only blocks allocated by provider_state are registered.
                drop(unsafe { Box::from_raw(state as *mut [u8; PROVIDER_DATA_SIZE]) });
                // SAFETY: the state field was writable for the VERIFY call.
                unsafe { teb::put::<u64>(data as u64, WTD_STATE_DATA, 0) };
            }
            0
        }
        WTD_STATEACTION_VERIFY => {
            if state != 0 && PROVIDER_STATES.lock().unwrap().contains(&state) {
                return 0; // an already verified state is reused as on Windows
            }
            match verify_authenticode(data) {
                Ok(()) => 0,
                Err(e) => e as i32,
            }
        }
        _ => E_INVALIDARG as i32,
    }
}

extern "win64" fn WTHelperProvDataFromStateData(state: u64) -> *mut u8 {
    if state == 0 || !PROVIDER_STATES.lock().unwrap().contains(&state) {
        return core::ptr::null_mut();
    }
    state as *mut u8
}

pub fn wintrust_exports() -> Vec<(&'static str, u64)> {
    export_table![WinVerifyTrust, WTHelperProvDataFromStateData]
}

// ---- avrt ----------------------------------------------------------------------------

/// Pseudo handle for a thread's multimedia class registration.
const AVRT_HANDLE: u64 = 0xA7A7;

/// avrt.dll (MMCSS). Windows always has it, and audio code (cubeb's WASAPI
/// backend) calls it from its audio thread; without it a function pointer
/// stayed null there. OSyx has no multimedia scheduling classes, so
/// registering succeeds without changing the thread's priority.
pub fn avrt_exports() -> Vec<(&'static str, u64)> {
    export_table![
        AvSetMmThreadCharacteristicsW,
        AvSetMmThreadCharacteristicsA,
        AvSetMmMaxThreadCharacteristicsW,
        AvSetMmMaxThreadCharacteristicsA,
        AvRevertMmThreadCharacteristics,
        AvSetMmThreadPriority,
    ]
}

/// MMCSS task names that ask for audio-grade scheduling; others ("Games",
/// "Capture", ...) get above-normal priority.
fn avrt_level(task: &str) -> u64 {
    match task.to_ascii_lowercase().as_str() {
        "pro audio" | "audio" | "playback" | "window manager" => osyx_abi::priority::REALTIME,
        _ => osyx_abi::priority::ABOVE_NORMAL,
    }
}

fn avrt_register(task: Option<String>, task_index: *mut u32) -> u64 {
    let level = task.as_deref().map_or(osyx_abi::priority::ABOVE_NORMAL, avrt_level);
    let _ = os_sys::thread_priority(0, level);
    if !task_index.is_null() {
        // SAFETY: the caller's task index out parameter.
        unsafe { *task_index = 1 };
    }
    AVRT_HANDLE
}

extern "win64" fn AvSetMmThreadCharacteristicsW(task: *const u16, task_index: *mut u32) -> u64 {
    avrt_register(unsafe { path::wide_to_string(task) }, task_index)
}

extern "win64" fn AvSetMmThreadCharacteristicsA(task: *const u8, task_index: *mut u32) -> u64 {
    avrt_register(unsafe { path::ansi_to_string(task) }, task_index)
}

extern "win64" fn AvSetMmMaxThreadCharacteristicsW(first: *const u16, _second: *const u16, task_index: *mut u32) -> u64 {
    avrt_register(unsafe { path::wide_to_string(first) }, task_index)
}

extern "win64" fn AvSetMmMaxThreadCharacteristicsA(first: *const u8, _second: *const u8, task_index: *mut u32) -> u64 {
    avrt_register(unsafe { path::ansi_to_string(first) }, task_index)
}

extern "win64" fn AvRevertMmThreadCharacteristics(handle: u64) -> i32 {
    if handle == AVRT_HANDLE {
        let _ = os_sys::thread_priority(0, osyx_abi::priority::NORMAL);
        1
    } else { fail(ERROR_INVALID_HANDLE, 0) }
}

extern "win64" fn AvSetMmThreadPriority(handle: u64, _priority: i32) -> i32 {
    if handle == AVRT_HANDLE { 1 } else { fail(ERROR_INVALID_HANDLE, 0) }
}
