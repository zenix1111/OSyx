//! Small system libraries: `secur32.dll`, `shfolder.dll`, `winspool.drv`,
//! `uiautomationcore.dll` and `oleacc.dll`. Each does what OSyx can really
//! do (user names, folder paths, an empty printer list, "no UI Automation
//! client") and fails with the documented error for the rest.
#![allow(non_snake_case)]

use crate::error::*;
use crate::kernel32::fail;
use alloc::string::String;
use alloc::vec::Vec;

const E_NOTIMPL: u32 = 0x8000_4001;
const E_NOINTERFACE: u32 = 0x8000_4002;
const E_POINTER: u32 = 0x8000_4003;
const S_OK: u32 = 0;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

// ---- secur32.dll ------------------------------------------------------------------------

const ERROR_NONE_MAPPED: u32 = 1332;
const ERROR_MORE_DATA: u32 = 234;

/// EXTENDED_NAME_FORMAT: NameSamCompatible (2) is "COMPUTER\user" and
/// NameDisplay (3) the user name; the directory-based formats (distinguished
/// name, canonical, UPN ...) do not exist for a local account
/// (ERROR_NONE_MAPPED). `*size` is the buffer size in characters, then the
/// length without the NUL; too small is ERROR_MORE_DATA with the size needed.
extern "win64" fn GetUserNameExW(format: u32, buf: *mut u16, size: *mut u32) -> u32 {
    if size.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let user = crate::accounts::current_user_name();
    let name = match format {
        2 => alloc::format!("{}\\{}", crate::accounts::computer_name(), user),
        3 => user,
        1 | 4..=13 => return fail(ERROR_NONE_MAPPED, 0),
        _ => return fail(ERROR_INVALID_PARAMETER, 0),
    };
    let units: Vec<u16> = name.encode_utf16().collect();
    // SAFETY: the caller's in/out size and buffer.
    unsafe {
        if buf.is_null() || (*size as usize) < units.len() + 1 {
            *size = units.len() as u32 + 1;
            return fail(ERROR_MORE_DATA, 0);
        }
        core::ptr::copy_nonoverlapping(units.as_ptr(), buf, units.len());
        *buf.add(units.len()) = 0;
        *size = units.len() as u32;
    }
    1
}

/// Every SSPI entry point of this table: there are no security packages, so
/// each call fails with SEC_E_UNSUPPORTED_FUNCTION.
extern "win64" fn sspi_unsupported() -> u32 {
    0x8009_0302
}

/// SecurityFunctionTableW, version 1: dwVersion (padded to 8 bytes) and the
/// 28 entry points that follow.
#[repr(C)]
struct SspiTable {
    version: u64,
    entries: [*const (); 28],
}

// SAFETY: immutable function pointers.
unsafe impl Sync for SspiTable {}

static SSPI_TABLE: SspiTable = SspiTable { version: 1, entries: [sspi_unsupported as *const (); 28] };

/// A real function table whose calls report that no package is available,
/// as Windows does for an unknown package, instead of a NULL table.
extern "win64" fn InitSecurityInterfaceW() -> *const SspiTable {
    &SSPI_TABLE
}

// ---- the local security authority ------------------------------------------------------------
//
// LSA handles come from LsaConnectUntrusted (any process) or
// LsaRegisterLogonProcess (SeTcbPrivilege). Only a registered logon process
// may call LsaLogonUser; authentication packages are found by name. Logons
// check /etc/shadow (accounts.rs). Results the LSA allocates are tracked so
// LsaFreeReturnBuffer frees only those.

const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0041;
const STATUS_NO_SUCH_PACKAGE: u32 = 0xC000_00FE;
const STATUS_MEMORY_NOT_ALLOCATED: u32 = 0xC000_00A0;
const STATUS_RPC_INVALID_BINDING: u32 = 0xC003_0005;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const STATUS_NO_SUCH_USER: u32 = 0xC000_0064;
const STATUS_WRONG_PASSWORD: u32 = 0xC000_006A;
const SE_TCB_PRIVILEGE: u32 = 7;

/// Authentication package ids (the values a Windows 11 machine reports).
const PACKAGE_NEGOTIATE: u32 = 0;
const PACKAGE_KERBEROS: u32 = 2;
const PACKAGE_MSV1_0: u32 = 11;

static LSA_HANDLES: os_std::sync::Mutex<alloc::collections::BTreeMap<u64, bool>> = os_std::sync::Mutex::new(alloc::collections::BTreeMap::new());
static LSA_BUFFERS: os_std::sync::Mutex<alloc::collections::BTreeSet<u64>> = os_std::sync::Mutex::new(alloc::collections::BTreeSet::new());
static NEXT_LSA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x1a50);
static NEXT_LUID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0x3e8f0);

fn new_lsa_handle(trusted: bool) -> u64 {
    let h = NEXT_LSA.fetch_add(8, core::sync::atomic::Ordering::Relaxed);
    LSA_HANDLES.lock().unwrap().insert(h, trusted);
    h
}

/// A connection with no privilege: it may look up packages but not log on.
extern "win64" fn LsaConnectUntrusted(handle: *mut u64) -> u32 {
    if handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *handle = new_lsa_handle(false) };
    0
}

/// A logon process connection: the caller's token must hold SeTcbPrivilege.
extern "win64" fn LsaRegisterLogonProcess(name: *const u8, handle: *mut u64, mode: *mut u32) -> u32 {
    if name.is_null() || handle.is_null() || mode.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if !crate::tokens::process_data().privileges.iter().any(|&(luid, _)| luid == SE_TCB_PRIVILEGE) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    // SAFETY: the caller's out pointers.
    unsafe {
        *handle = new_lsa_handle(true);
        *mode = 0;
    }
    0
}

/// Closes a connection; an unknown or already closed handle is an invalid
/// RPC binding.
extern "win64" fn LsaDeregisterLogonProcess(handle: u64) -> u32 {
    if LSA_HANDLES.lock().unwrap().remove(&handle).is_some() { 0 } else { STATUS_RPC_INVALID_BINDING }
}

/// Reads an LSA_STRING (Length, MaximumLength, 4 bytes of padding, Buffer).
fn lsa_string(p: *const u8) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: an LSA_STRING whose buffer holds `Length` bytes.
    unsafe {
        let len = core::ptr::read_unaligned(p as *const u16) as usize;
        let buf = core::ptr::read_unaligned(p.add(8) as *const u64) as *const u8;
        if buf.is_null() {
            return None;
        }
        Some(String::from_utf8_lossy(core::slice::from_raw_parts(buf, len)).into_owned())
    }
}

/// Finds an authentication package by name.
extern "win64" fn LsaLookupAuthenticationPackage(handle: u64, name: *const u8, id: *mut u32) -> u32 {
    if !LSA_HANDLES.lock().unwrap().contains_key(&handle) {
        return STATUS_RPC_INVALID_BINDING;
    }
    let Some(name) = lsa_string(name).filter(|_| !id.is_null()) else { return STATUS_INVALID_PARAMETER };
    let found = match name.as_str() {
        "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" => PACKAGE_MSV1_0,
        "Negotiate" => PACKAGE_NEGOTIATE,
        "Kerberos" => PACKAGE_KERBEROS,
        _ => {
            // SAFETY: the caller's out pointer.
            unsafe { *id = u32::MAX };
            return STATUS_NO_SUCH_PACKAGE;
        }
    };
    // SAFETY: the caller's out pointer.
    unsafe { *id = found };
    0
}

/// Frees a buffer an LSA call returned; anything else is not allocated.
extern "win64" fn LsaFreeReturnBuffer(buffer: u64) -> u32 {
    if LSA_BUFFERS.lock().unwrap().remove(&buffer) {
        crate::kernel32::heap_free(buffer);
        0
    } else {
        STATUS_MEMORY_NOT_ALLOCATED
    }
}

/// Reads a UNICODE_STRING (Length, MaximumLength, 4 bytes of padding, Buffer).
fn unicode_string(p: *const u8) -> String {
    // SAFETY: a UNICODE_STRING whose buffer holds `Length` bytes.
    unsafe {
        let len = core::ptr::read_unaligned(p as *const u16) as usize / 2;
        let buf = core::ptr::read_unaligned(p.add(8) as *const u64) as *const u16;
        if buf.is_null() || len == 0 {
            return String::new();
        }
        String::from_utf16_lossy(core::slice::from_raw_parts(buf, len))
    }
}

const MSV1_0_INTERACTIVE_LOGON_SIZE: u32 = 56;
const MSV1_0_INTERACTIVE_PROFILE_SIZE: usize = 160;
const MSV1_0_INTERACTIVE_LOGON: u32 = 2;
const MSV1_0_INTERACTIVE_PROFILE: u32 = 2;

/// LsaLogonUser for the MSV1_0 package with an MSV1_0_INTERACTIVE_LOGON
/// block (domain, user, password): checks the password against /etc/shadow
/// and returns a token, the logon session id and an interactive profile.
/// Only a registered logon process may call it; the Kerberos and Negotiate
/// packages need a domain controller that does not exist here.
#[allow(clippy::too_many_arguments)]
extern "win64" fn LsaLogonUser(
    handle: u64,
    origin: *const u8,
    kind: u32,
    package: u32,
    info: *const u8,
    info_len: u32,
    _groups: u64,
    source: *const u8,
    profile: *mut u64,
    profile_len: *mut u32,
    luid: *mut u32,
    token: *mut u64,
    quotas: *mut u8,
    substatus: *mut u32,
) -> u32 {
    let Some(trusted) = LSA_HANDLES.lock().unwrap().get(&handle).copied() else { return STATUS_RPC_INVALID_BINDING };
    if !matches!(package, PACKAGE_NEGOTIATE | PACKAGE_KERBEROS | PACKAGE_MSV1_0) {
        return STATUS_NOT_SUPPORTED;
    }
    if !trusted || origin.is_null() || source.is_null() || info.is_null() || info_len < MSV1_0_INTERACTIVE_LOGON_SIZE || profile.is_null() || profile_len.is_null() || luid.is_null() || token.is_null() || quotas.is_null() || substatus.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if package != PACKAGE_MSV1_0 || !matches!(kind, 2 | 3 | 4 | 5 | 7 | 8 | 9) {
        return STATUS_NOT_SUPPORTED;
    }
    // SAFETY: an MSV1_0_INTERACTIVE_LOGON of at least 56 bytes: MessageType,
    // then the LogonDomainName, UserName and Password UNICODE_STRINGs.
    let (message, domain, user, password) = unsafe { (core::ptr::read_unaligned(info as *const u32), unicode_string(info.add(8)), unicode_string(info.add(24)), unicode_string(info.add(40))) };
    if message != MSV1_0_INTERACTIVE_LOGON {
        return STATUS_INVALID_PARAMETER;
    }
    let verdict = if crate::accounts::domain_is_local(&domain) { crate::accounts::logon(&user, &password) } else { Err(crate::accounts::LogonFailure::NoSuchUser) };
    let (uid, gid) = match verdict {
        Ok(ids) => ids,
        Err(why) => {
            // SAFETY: the caller's out pointer.
            unsafe {
                *substatus = if why == crate::accounts::LogonFailure::NoSuchUser { STATUS_NO_SUCH_USER } else { STATUS_WRONG_PASSWORD };
            }
            return STATUS_LOGON_FAILURE;
        }
    };
    let Some(block) = crate::kernel32::heap_alloc(MSV1_0_INTERACTIVE_PROFILE_SIZE, true) else { return 0xC000_0017 };
    LSA_BUFFERS.lock().unwrap().insert(block);
    let session = NEXT_LUID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: the caller's out pointers; `block` holds the profile.
    unsafe {
        core::ptr::write_unaligned(block as *mut u32, MSV1_0_INTERACTIVE_PROFILE);
        core::ptr::write_unaligned((block + 8) as *mut i64, crate::kernel32::filetime(os_sys::clock(osyx_abi::CLOCK_REALTIME).unwrap_or(0) as i64) as i64);
        *profile = block;
        *profile_len = MSV1_0_INTERACTIVE_PROFILE_SIZE as u32;
        *luid = session;
        *luid.add(1) = 0;
        *token = crate::accounts::logon_token(uid, gid, kind == 3);
        core::ptr::write_bytes(quotas, 0, 48);
        *substatus = 0;
    }
    0
}

pub fn secur32_exports() -> Vec<(&'static str, u64)> {
    export_table![
        GetUserNameExW,
        InitSecurityInterfaceW,
        LsaConnectUntrusted,
        LsaRegisterLogonProcess,
        LsaDeregisterLogonProcess,
        LsaLookupAuthenticationPackage,
        LsaFreeReturnBuffer,
        LsaLogonUser
    ]
}

// ---- shfolder.dll -----------------------------------------------------------------------

/// SHGetFolderPathA: the wide function, in the ANSI code page (UTF-8).
extern "win64" fn SHGetFolderPathA(hwnd: u64, csidl: u32, token: u64, kind: u32, out: *mut u8) -> u32 {
    if out.is_null() {
        return 0x8007_0057; // E_INVALIDARG
    }
    let mut wide = [0u16; 260];
    let hr = crate::shell32::SHGetFolderPathW(hwnd, csidl, token, kind, wide.as_mut_ptr());
    if hr != S_OK {
        return hr;
    }
    let len = wide.iter().position(|&u| u == 0).unwrap_or(wide.len());
    let text = String::from_utf16_lossy(&wide[..len]);
    // SAFETY: the caller's buffer of MAX_PATH bytes.
    unsafe {
        let n = text.len().min(259);
        core::ptr::copy_nonoverlapping(text.as_ptr(), out, n);
        *out.add(n) = 0;
    }
    S_OK
}

pub fn shfolder_exports() -> Vec<(&'static str, u64)> {
    alloc::vec![
        ("SHGetFolderPathW", crate::shell32::SHGetFolderPathW as *const () as u64),
        ("SHGetFolderPathA", SHGetFolderPathA as *const () as u64),
    ]
}

// ---- winspool.drv -----------------------------------------------------------------------

const ERROR_INVALID_PRINTER_NAME: u32 = 1801;
const ERROR_INVALID_LEVEL: u32 = 124;

/// OSyx has no printers: no name can be opened.
extern "win64" fn OpenPrinterW(_name: *const u16, handle: *mut u64, _defaults: u64) -> i32 {
    if handle.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's out pointer.
    unsafe { *handle = 0 };
    fail(ERROR_INVALID_PRINTER_NAME, 0)
}

/// No printer handle exists, so every handle is invalid.
extern "win64" fn ClosePrinter(_handle: u64) -> i32 {
    fail(ERROR_INVALID_HANDLE, 0)
}

/// The list of printers is empty: success with zero bytes needed and zero
/// entries, for the levels Windows defines (1, 2, 4, 5).
extern "win64" fn EnumPrintersW(_flags: u32, _name: *const u16, level: u32, _buf: *mut u8, _size: u32, needed: *mut u32, returned: *mut u32) -> i32 {
    if needed.is_null() || returned.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if !matches!(level, 1 | 2 | 4 | 5) {
        return fail(ERROR_INVALID_LEVEL, 0);
    }
    // SAFETY: the caller's out pointers.
    unsafe {
        *needed = 0;
        *returned = 0;
    }
    1
}

/// There is no printer to ask: -1 with ERROR_INVALID_PRINTER_NAME.
extern "win64" fn DeviceCapabilitiesW(_device: *const u16, _port: *const u16, _capability: u16, _out: *mut u16, _mode: u64) -> i32 {
    fail(ERROR_INVALID_PRINTER_NAME, -1)
}

extern "win64" fn DocumentPropertiesW(_hwnd: u64, _printer: u64, _device: *const u16, _out: u64, _input: u64, _mode: u32) -> i32 {
    fail(ERROR_INVALID_PRINTER_NAME, -1)
}

pub fn winspool_exports() -> Vec<(&'static str, u64)> {
    export_table![OpenPrinterW, ClosePrinter, EnumPrintersW, DeviceCapabilitiesW, DocumentPropertiesW]
}

// ---- uiautomationcore.dll and oleacc.dll -------------------------------------------------

/// A COM object with only IUnknown: the singletons UIA hands out for
/// "not supported" and "mixed attribute".
#[repr(C)]
struct Singleton {
    vtable: *const VTable,
}

/// The three IUnknown slots.
#[repr(transparent)]
struct VTable([*const (); 3]);

// SAFETY: immutable function pointers.
unsafe impl Sync for VTable {}

extern "win64" fn singleton_query(this: u64, iid: *const u8, out: *mut u64) -> u32 {
    if out.is_null() || iid.is_null() {
        return E_POINTER;
    }
    // IID_IUnknown {00000000-0000-0000-C000-000000000046}
    const IUNKNOWN: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
    // SAFETY: the caller's 16-byte IID and out pointer.
    unsafe {
        if core::slice::from_raw_parts(iid, 16) == IUNKNOWN {
            *out = this;
            S_OK
        } else {
            *out = 0;
            E_NOINTERFACE
        }
    }
}

extern "win64" fn singleton_ref(_this: u64) -> u32 {
    1 // the objects are static: their count never changes
}

static SINGLETON_VTABLE: VTable = VTable([singleton_query as *const (), singleton_ref as *const (), singleton_ref as *const ()]);
static NOT_SUPPORTED_VALUE: Singleton = Singleton { vtable: &SINGLETON_VTABLE };
static MIXED_VALUE: Singleton = Singleton { vtable: &SINGLETON_VTABLE };

// SAFETY: the singletons are immutable.
unsafe impl Sync for Singleton {}

extern "win64" fn UiaGetReservedNotSupportedValue(out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG_UIA;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = &NOT_SUPPORTED_VALUE as *const Singleton as u64 };
    S_OK
}

extern "win64" fn UiaGetReservedMixedAttributeValue(out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG_UIA;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = &MIXED_VALUE as *const Singleton as u64 };
    S_OK
}

const E_INVALIDARG_UIA: u32 = 0x8007_0057;

/// No UI Automation client exists in OSyx, so nobody is listening.
extern "win64" fn UiaClientsAreListening() -> i32 {
    0
}

/// With no client asking, a window has nothing to answer WM_GETOBJECT with.
extern "win64" fn UiaReturnRawElementProvider(_hwnd: u64, _wparam: u64, _lparam: i64, _provider: u64) -> i64 {
    0
}

/// Without a listening client an event has nobody to reach (S_OK, as on
/// Windows when no client subscribed).
extern "win64" fn UiaRaiseAutomationEvent(_provider: u64, _event: i32) -> u32 {
    S_OK
}

extern "win64" fn UiaRaiseAutomationPropertyChangedEvent(_provider: u64, _property: i32, _old: u64, _new: u64) -> u32 {
    S_OK
}

/// UI Automation hosting of a window needs the UIA runtime: not available.
extern "win64" fn UiaHostProviderFromHwnd(_hwnd: u64, out: *mut u64) -> u32 {
    if !out.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = 0 };
    }
    E_NOTIMPL
}

pub fn uiautomationcore_exports() -> Vec<(&'static str, u64)> {
    export_table![
        UiaGetReservedNotSupportedValue,
        UiaGetReservedMixedAttributeValue,
        UiaClientsAreListening,
        UiaReturnRawElementProvider,
        UiaRaiseAutomationEvent,
        UiaRaiseAutomationPropertyChangedEvent,
        UiaHostProviderFromHwnd,
    ]
}

/// Active Accessibility objects are not provided.
extern "win64" fn CreateStdAccessibleObject(_hwnd: u64, _object: i32, _iid: *const u8, out: *mut u64) -> u32 {
    if !out.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = 0 };
    }
    E_NOTIMPL
}

extern "win64" fn LresultFromObject(_iid: *const u8, _wparam: u64, _object: u64) -> i64 {
    E_NOTIMPL as i32 as i64
}

extern "win64" fn AccessibleObjectFromWindow(_hwnd: u64, _object: u32, _iid: *const u8, out: *mut u64) -> u32 {
    if !out.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = 0 };
    }
    E_NOTIMPL
}

pub fn oleacc_exports() -> Vec<(&'static str, u64)> {
    export_table![CreateStdAccessibleObject, LresultFromObject, AccessibleObjectFromWindow]
}

// ---- msvcrt.dll -------------------------------------------------------------------------

/// The C runtime of old programs: the same functions as the UCRT, plus the
/// C++ allocation operators under their msvcrt names (operator new / delete,
/// 32-bit and 64-bit decoration). Unlike msvcrt's operator new this one
/// returns NULL when memory runs out instead of throwing std::bad_alloc.
pub fn msvcrt_exports() -> Vec<(&'static str, u64)> {
    let mut e = crate::ucrt::exports();
    let find = |e: &Vec<(&'static str, u64)>, n: &str| e.iter().find(|(k, _)| *k == n).map(|(_, a)| *a);
    if let (Some(malloc), Some(free)) = (find(&e, "malloc"), find(&e, "free")) {
        for n in ["??2@YAPAXI@Z", "??2@YAPEAX_K@Z"] {
            e.push((n, malloc));
        }
        for n in ["??3@YAXPAX@Z", "??3@YAXPEAX@Z"] {
            e.push((n, free));
        }
    }
    e
}
