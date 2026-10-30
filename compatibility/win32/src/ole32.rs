//! ole32: the task allocator (CoTaskMemAlloc/Realloc/Free) over the
//! process heap, which blocks shell32 hands out (SHGetKnownFolderPath)
//! come from, and COM apartments.
//!
//! Threads enter and leave apartments as on Windows (a thread-local STA or
//! the process-wide MTA, with the same counting and mode conflicts).
//! OLE initialization owns separate per-thread nesting while acquiring one
//! COM STA reference per successful call. Data-transfer APIs are separate.
//! OSyx has no COM class registrations and no COM servers, in process or
//! out of it, so class activation reports every class as not registered.
#![allow(non_snake_case)]
use crate::kernel32;
use alloc::{boxed::Box, collections::BTreeMap, string::{String, ToString}, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use os_std::sync::Mutex;
use prism_client::proto;

const S_OK: u32 = 0;
const S_FALSE: u32 = 1;
const E_POINTER: u32 = 0x8000_4003;
const E_INVALIDARG: u32 = 0x8007_0057;
const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;
const RPC_E_TOO_LATE: u32 = 0x8001_0119;
const CO_E_NOTINITIALIZED: u32 = 0x8004_01f0;
const REGDB_E_CLASSNOTREG: u32 = 0x8004_0154;
const CLASS_E_NOAGGREGATION: u32 = 0x8004_0110;
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const COINIT_KNOWN: u32 = 0x2 | 0x4 | 0x8; // apartment, disable OLE1 DDE, speed over memory

// APTTYPE / APTTYPEQUALIFIER, from the COM apartment API.
const APTTYPE_STA: i32 = 0;
const APTTYPE_MTA: i32 = 1;
const APTTYPEQUALIFIER_NONE: i32 = 0;
const APTTYPEQUALIFIER_IMPLICIT_MTA: i32 = 1;

pub extern "win64" fn CoTaskMemAlloc(size: usize) -> u64 {
    kernel32::heap_alloc(size, false).unwrap_or(0)
}

pub extern "win64" fn CoTaskMemFree(p: u64) {
    kernel32::heap_free(p);
}

extern "win64" fn CoTaskMemRealloc(p: u64, size: usize) -> u64 {
    if p == 0 {
        return CoTaskMemAlloc(size);
    }
    if size == 0 {
        kernel32::heap_free(p);
        return 0;
    }
    let Some(n) = kernel32::heap_alloc(size, false) else { return 0 };
    // SAFETY: both blocks are live heap blocks; the copy fits the smaller.
    unsafe { core::ptr::copy_nonoverlapping(p as *const u8, n as *mut u8, kernel32::heap_size(p).min(size)) };
    kernel32::heap_free(p);
    n
}

// ---- apartments -----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Apartment {
    Single,
    Multi,
}

struct Com {
    /// Per thread: its apartment and CoInitialize count.
    threads: BTreeMap<u64, (Apartment, u32)>,
    /// OleInitialize has its own nesting count, even in an existing COM STA.
    ole_threads: BTreeMap<u64, u32>,
    security_set: bool,
    /// CoIncrementMTAUsage references keeping the MTA alive.
    mta_usage: u32,
}

static COM: Mutex<Com> = Mutex::new(Com {
    threads: BTreeMap::new(),
    ole_threads: BTreeMap::new(),
    security_set: false,
    mta_usage: 0,
});

impl Com {
    /// Whether the process has an MTA (any thread entered one), which is what
    /// makes every other thread implicitly part of it.
    fn mta_exists(&self) -> bool {
        self.mta_usage > 0 || self.threads.values().any(|(apartment, _)| *apartment == Apartment::Multi)
    }
}

fn initialized() -> bool {
    COM.lock().unwrap().threads.contains_key(&os_sys::gettid())
}

fn initialize_apartment(com: &mut Com, tid: u64, kind: Apartment) -> u32 {
    match com.threads.get_mut(&tid) {
        Some((k, _)) if *k != kind => RPC_E_CHANGED_MODE,
        Some((_, n)) => {
            *n += 1;
            S_FALSE
        }
        None => {
            com.threads.insert(tid, (kind, 1));
            S_OK
        }
    }
}

extern "win64" fn CoInitializeEx(reserved: u64, flags: u32) -> u32 {
    if reserved != 0 || flags & !COINIT_KNOWN != 0 {
        return E_INVALIDARG;
    }
    let kind = if flags & COINIT_APARTMENTTHREADED != 0 { Apartment::Single } else { Apartment::Multi };
    initialize_apartment(&mut COM.lock().unwrap(), os_sys::gettid(), kind)
}

extern "win64" fn CoInitialize(reserved: u64) -> u32 {
    CoInitializeEx(reserved, COINIT_APARTMENTTHREADED)
}

fn uninitialize_apartment(com: &mut Com, tid: u64) {
    if let Some((_, n)) = com.threads.get_mut(&tid) {
        *n -= 1;
        if *n == 0 {
            com.threads.remove(&tid);
        }
    }
}

extern "win64" fn CoUninitialize() {
    uninitialize_apartment(&mut COM.lock().unwrap(), os_sys::gettid());
}

// Windows also exposes these OLE Automation functions through ole32.
use crate::oleaut32::{GetErrorInfo, SetErrorInfo};

extern "win64" fn OleInitialize(reserved: u64) -> u32 {
    if reserved != 0 {
        return E_INVALIDARG;
    }
    let tid = os_sys::gettid();
    let mut com = COM.lock().unwrap();
    let hr = initialize_apartment(&mut com, tid, Apartment::Single);
    if hr != S_OK && hr != S_FALSE {
        return hr;
    }
    let count = com.ole_threads.entry(tid).or_insert(0);
    let hr = if *count == 0 { S_OK } else { S_FALSE };
    *count += 1;
    hr
}

extern "win64" fn OleUninitialize() {
    let tid = os_sys::gettid();
    let mut com = COM.lock().unwrap();
    let Some(count) = com.ole_threads.get_mut(&tid) else { return };
    *count -= 1;
    if *count == 0 {
        com.ole_threads.remove(&tid);
    }
    uninitialize_apartment(&mut com, tid);
}

/// The calling thread's apartment, and whether it is in it explicitly or
/// only because the process has an MTA (Windows puts every thread of such a
/// process into the MTA implicitly).
extern "win64" fn CoGetApartmentType(kind: *mut i32, qualifier: *mut i32) -> u32 {
    if kind.is_null() || qualifier.is_null() {
        return E_POINTER;
    }
    let com = COM.lock().unwrap();
    let (t, q) = match (com.threads.get(&os_sys::gettid()), com.mta_exists()) {
        (Some((Apartment::Single, _)), _) => (APTTYPE_STA, APTTYPEQUALIFIER_NONE),
        (Some((Apartment::Multi, _)), _) => (APTTYPE_MTA, APTTYPEQUALIFIER_NONE),
        (None, true) => (APTTYPE_MTA, APTTYPEQUALIFIER_IMPLICIT_MTA),
        (None, false) => return CO_E_NOTINITIALIZED,
    };
    // SAFETY: both out pointers were checked above.
    unsafe {
        *kind = t;
        *qualifier = q;
    }
    S_OK
}

/// Records the process's COM security. With no COM servers or remote
/// calls on OSyx nothing ever authenticates with it, but it can be set
/// once, after the caller has entered an apartment, as on Windows.
#[allow(clippy::too_many_arguments)]
extern "win64" fn CoInitializeSecurity(_sd: u64, _count: i32, _services: u64, _r1: u64, _authn: u32, _imp: u32, _list: u64, _caps: u32, _r3: u64) -> u32 {
    let tid = os_sys::gettid();
    let mut com = COM.lock().unwrap();
    if !com.threads.contains_key(&tid) {
        return CO_E_NOTINITIALIZED;
    }
    if com.security_set {
        return RPC_E_TOO_LATE;
    }
    com.security_set = true;
    S_OK
}

extern "win64" fn CoCreateInstance(_clsid: *const u8, outer: u64, _context: u32, _iid: *const u8, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_POINTER;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = 0 };
    if !initialized() {
        return CO_E_NOTINITIALIZED;
    }
    if outer != 0 {
        return CLASS_E_NOAGGREGATION;
    }
    REGDB_E_CLASSNOTREG // no COM classes are registered on OSyx
}

/// IID_IForegroundTransfer {00000145-0000-0000-C000-000000000046}.
const IID_IFOREGROUND_TRANSFER: [u8; 16] = [0x45, 0x01, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];

type QueryInterface = extern "win64" fn(u64, *const u8, *mut u64) -> u32;
type Release = extern "win64" fn(u64) -> u32;
type AllowForegroundTransfer = extern "win64" fn(u64, u64) -> u32;

/// Asks the object (through IForegroundTransfer) to let its server take
/// the foreground.
extern "win64" fn CoAllowSetForegroundWindow(unk: u64, reserved: u64) -> u32 {
    if unk == 0 || reserved != 0 {
        return E_INVALIDARG;
    }
    let mut ft = 0u64;
    // SAFETY: `unk` is a COM object: its first word is its vtable.
    unsafe {
        let vtbl = *(unk as *const *const u64);
        let qi: QueryInterface = core::mem::transmute(*vtbl);
        let hr = qi(unk, IID_IFOREGROUND_TRANSFER.as_ptr(), &mut ft);
        if hr != S_OK || ft == 0 {
            return hr;
        }
        let fvtbl = *(ft as *const *const u64);
        let allow: AllowForegroundTransfer = core::mem::transmute(*fvtbl.add(3));
        let release: Release = core::mem::transmute(*fvtbl.add(2));
        let hr = allow(ft, 0);
        release(ft);
        hr
    }
}

/// Keeps the MTA in existence without entering it (the cookie is opaque).
extern "win64" fn CoIncrementMTAUsage(cookie: *mut u64) -> u32 {
    if cookie.is_null() {
        return E_INVALIDARG;
    }
    let mut com = COM.lock().unwrap();
    com.mta_usage += 1;
    // SAFETY: the caller's CO_MTA_USAGE_COOKIE.
    unsafe { *cookie = 0x4d54_4100 + com.mta_usage as u64 };
    S_OK
}

extern "win64" fn CoDecrementMTAUsage(cookie: u64) -> u32 {
    let mut com = COM.lock().unwrap();
    if cookie == 0 || com.mta_usage == 0 {
        return E_INVALIDARG;
    }
    com.mta_usage -= 1;
    S_OK
}

/// Outside an incoming call (there never is one here) the caller's thread
/// is unknown: 0, with S_OK, as Windows reports it.
extern "win64" fn CoGetCallerTID(tid: *mut u32) -> u32 {
    if tid.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's DWORD.
    unsafe { *tid = 0 };
    S_OK
}

// ---- GUID strings ------------------------------------------------------------------------

const CO_E_CLASSSTRING: u32 = 0x8004_01F3;
const E_OUTOFMEMORY: u32 = 0x8007_000E;

/// "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}", as StringFromGUID2 writes it.
fn guid_string(g: *const u8) -> String {
    // SAFETY: the caller's 16-byte GUID.
    let b = unsafe { core::slice::from_raw_parts(g, 16) };
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    alloc::format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// A braced GUID string (exactly 38 characters), or None.
fn parse_guid(s: &str) -> Option<[u8; 16]> {
    let inner = s.strip_prefix('{')?.strip_suffix('}')?;
    let parts: Vec<&str> = inner.split('-').collect();
    if parts.len() != 5 || parts.iter().zip([8, 4, 4, 4, 12]).any(|(p, l)| p.len() != l || !p.bytes().all(|c| c.is_ascii_hexdigit())) {
        return None;
    }
    let hex = |s: &str| u64::from_str_radix(s, 16).ok();
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&(hex(parts[0])? as u32).to_le_bytes());
    g[4..6].copy_from_slice(&(hex(parts[1])? as u16).to_le_bytes());
    g[6..8].copy_from_slice(&(hex(parts[2])? as u16).to_le_bytes());
    g[8..10].copy_from_slice(&(hex(parts[3])? as u16).to_be_bytes());
    g[10..16].copy_from_slice(&hex(parts[4])?.to_be_bytes()[2..]);
    Some(g)
}

/// NULL reads as the nil GUID; anything else must be a braced GUID.
fn guid_from(s: *const u16, out: *mut u8, bad: u32) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let g = if s.is_null() {
        [0u8; 16]
    } else {
        // SAFETY: a NUL-terminated string.
        match unsafe { crate::path::wide_to_string(s) }.as_deref().and_then(parse_guid) {
            Some(g) => g,
            None => return bad,
        }
    };
    // SAFETY: the caller's 16-byte GUID.
    unsafe { core::ptr::copy_nonoverlapping(g.as_ptr(), out, 16) };
    S_OK
}

/// OSyx registers no ProgIDs, so only GUID strings name a class.
extern "win64" fn CLSIDFromString(s: *const u16, out: *mut u8) -> u32 {
    guid_from(s, out, CO_E_CLASSSTRING)
}

extern "win64" fn IIDFromString(s: *const u16, out: *mut u8) -> u32 {
    guid_from(s, out, E_INVALIDARG)
}

extern "win64" fn StringFromGUID2(g: *const u8, buf: *mut u16, cch: i32) -> i32 {
    if g.is_null() || buf.is_null() || cch < 39 {
        return 0;
    }
    for (i, c) in guid_string(g).encode_utf16().chain(core::iter::once(0)).enumerate() {
        // SAFETY: the caller's buffer of at least 39 WCHARs.
        unsafe { *buf.add(i) = c };
    }
    39
}

extern "win64" fn StringFromCLSID(g: *const u8, out: *mut u64) -> u32 {
    if g.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    let p = CoTaskMemAlloc(39 * 2);
    if p == 0 {
        return E_OUTOFMEMORY;
    }
    StringFromGUID2(g, p as *mut u16, 39);
    // SAFETY: the caller's out pointer.
    unsafe { *out = p };
    S_OK
}

extern "win64" fn StringFromIID(g: *const u8, out: *mut u64) -> u32 {
    StringFromCLSID(g, out)
}

// ---- drag and drop, the OLE clipboard -------------------------------------------------------
//
// Drop targets are registered per window. Native file drops are delivered
// on the target window thread. Win32-origin drags are not implemented yet.

const DRAGDROP_E_NOTREGISTERED: u32 = 0x8004_0100;
const DRAGDROP_E_ALREADYREGISTERED: u32 = 0x8004_0101;
const DRAGDROP_E_INVALIDHWND: u32 = 0x8004_0102;
const DRAGDROP_S_CANCEL: u32 = 0x0004_0101;
const E_FAIL: u32 = 0x8000_4005;

/// HWND to its IDropTarget (one reference held).
static DROP_TARGETS: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());
/// The IDataObject OleSetClipboard put on the system clipboard and the
/// contents it published there (one reference).
static CLIPBOARD: Mutex<(u64, Vec<proto::ClipEntry>)> = Mutex::new((0, Vec::new()));

/// IUnknown::AddRef (slot 1) or Release (slot 2) of a COM object.
fn com_call(obj: u64, slot: usize) -> u32 {
    // SAFETY: a COM object: its first word is its vtable; slots 1 and 2
    // take only `this`.
    unsafe {
        let vtbl = *(obj as *const *const u64);
        let f: extern "win64" fn(u64) -> u32 = core::mem::transmute(*vtbl.add(slot));
        f(obj)
    }
}

fn ole_initialized() -> bool {
    COM.lock().unwrap().ole_threads.contains_key(&os_sys::gettid())
}

extern "win64" fn RegisterDragDrop(hwnd: u64, target: u64) -> u32 {
    if !ole_initialized() {
        return E_OUTOFMEMORY; // what Windows returns before OleInitialize
    }
    if target == 0 {
        return E_INVALIDARG;
    }
    if !crate::user32::is_window(hwnd) {
        return DRAGDROP_E_INVALIDHWND;
    }
    let mut t = DROP_TARGETS.lock().unwrap();
    if t.contains_key(&hwnd) {
        return DRAGDROP_E_ALREADYREGISTERED;
    }
    com_call(target, 1);
    t.insert(hwnd, target);
    S_OK
}

extern "win64" fn RevokeDragDrop(hwnd: u64) -> u32 {
    if !crate::user32::is_window(hwnd) {
        return DRAGDROP_E_INVALIDHWND;
    }
    let target = DROP_TARGETS.lock().unwrap().remove(&hwnd);
    match target {
        Some(t) => {
            com_call(t, 2);
            S_OK
        }
        None => DRAGDROP_E_NOTREGISTERED,
    }
}

extern "win64" fn DoDragDrop(data: u64, source: u64, _ok: u32, effect: *mut u32) -> u32 {
    if data == 0 || source == 0 || effect.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's DWORD.
    unsafe { *effect = 0 }; // DROPEFFECT_NONE
    DRAGDROP_S_CANCEL
}

/// Drops are dispatched on the window's message thread, outside user32's lock.
static FILE_DROPS: Mutex<BTreeMap<u64, (u64, String, i32, i32)>> = Mutex::new(BTreeMap::new());
static NEXT_FILE_DROP: AtomicU32 = AtomicU32::new(1);

pub(crate) fn queue_file_drop(hwnd: u64, path: String, x: i32, y: i32) -> u64 {
    let mut drops = FILE_DROPS.lock().unwrap();
    if drops.len() >= 32 { return 0; }
    let token = NEXT_FILE_DROP.fetch_add(1, Ordering::Relaxed) as u64;
    drops.insert(token, (hwnd, path, x, y));
    token
}

pub(crate) fn dispatch_file_drop(hwnd: u64, token: u64) {
    let Some((owner, path, x, y)) = FILE_DROPS.lock().unwrap().remove(&token) else { return };
    if owner != hwnd { return; }
    let target = {
        let targets = DROP_TARGETS.lock().unwrap();
        let Some(&target) = targets.get(&hwnd) else { return };
        com_call(target, 1);
        target
    };
    // DROPFILES with a double-NUL-terminated UTF-16 Windows path.
    let mut bytes = alloc::vec![0u8; 20];
    bytes[0..4].copy_from_slice(&20u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    for unit in crate::path::to_windows(&path).encode_utf16().chain([0, 0]) {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let data = make_data_object(alloc::vec![proto::ClipEntry { format: CF_HDROP, name: None, data: bytes }]);
    let point = (x as u32 as u64) | ((y as u32 as u64) << 32);
    let mut effect = 1u32; // DROPEFFECT_COPY: the source retains its file.
    // SAFETY: a registered IDropTarget and our live IDataObject, invoked
    // on the window's thread after releasing the user32 lock. POINTL is 8 bytes.
    unsafe {
        let vtbl = *(target as *const *const u64);
        let enter: extern "win64" fn(u64, u64, u32, u64, *mut u32) -> u32 = core::mem::transmute(*vtbl.add(3));
        let leave: extern "win64" fn(u64) -> u32 = core::mem::transmute(*vtbl.add(5));
        let drop_: extern "win64" fn(u64, u64, u32, u64, *mut u32) -> u32 = core::mem::transmute(*vtbl.add(6));
        if enter(target, data, 0, point, &mut effect) == S_OK && effect != 0 {
            drop_(target, data, 0, point, &mut effect);
        } else {
            leave(target);
        }
    }
    DataRelease(data);
    com_call(target, 2);
}

/// The data object's formats are rendered to bytes now: other processes get
/// their clipboard contents through the compositor, which carries bytes, not
/// a live object. Text comes first so it survives the payload cap.
extern "win64" fn OleSetClipboard(data: u64) -> u32 {
    if data != 0 {
        com_call(data, 1);
    }
    let entries = if data != 0 { render_entries(data) } else { Vec::new() };
    let old = core::mem::replace(&mut *CLIPBOARD.lock().unwrap(), (data, entries.clone()));
    if old.0 != 0 {
        com_call(old.0, 2);
    }
    crate::user32::publish_clipboard(entries);
    S_OK
}

/// This process's object while it still owns the clipboard, otherwise one
/// built from the system contents (data another process put there).
extern "win64" fn OleGetClipboard(out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let contents = crate::user32::clipboard_contents();
    let (data, own) = {
        let clip = CLIPBOARD.lock().unwrap();
        (clip.0, clip.1.clone())
    };
    if data != 0 && own == contents {
        com_call(data, 1);
        // SAFETY: the caller's out pointer.
        unsafe { *out = data };
        return S_OK;
    }
    if contents.is_empty() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = 0 };
        return E_FAIL; // nothing on the clipboard
    }
    // SAFETY: the caller's out pointer.
    unsafe { *out = make_data_object(contents) };
    S_OK
}

/// The data stays available after the flush, as rendered data would.
extern "win64" fn OleFlushClipboard() -> u32 {
    S_OK
}

extern "win64" fn OleIsCurrentClipboard(data: u64) -> u32 {
    if data != 0 && data == CLIPBOARD.lock().unwrap().0 { S_OK } else { S_FALSE }
}

const TYMED_HGLOBAL: u32 = 1;
const TYMED_ISTREAM: u32 = 4;
const TYMED_ISTORAGE: u32 = 8;

/// STGMEDIUM: tymed, its handle or interface @8, pUnkForRelease @16.
extern "win64" fn ReleaseStgMedium(m: *mut u8) {
    if m.is_null() {
        return;
    }
    // SAFETY: the caller's STGMEDIUM.
    let (tymed, handle, unk) = unsafe { (*(m as *const u32), *(m.add(8) as *const u64), *(m.add(16) as *const u64)) };
    if unk != 0 {
        com_call(unk, 2);
    } else if handle != 0 {
        match tymed {
            TYMED_HGLOBAL => crate::kernel32::global_free(handle),
            TYMED_ISTREAM | TYMED_ISTORAGE => {
                com_call(handle, 2);
            }
            _ => {}
        }
    }
    // SAFETY: as above.
    unsafe { core::ptr::write_bytes(m, 0, 24) };
}

// ---- data transfer ----------------------------------------------------------------------
//
// FORMATETC and STGMEDIUM in their x64 layout, and a small IDataObject that
// serves the system clipboard's bytes to programs that paste through OLE
// (Gecko does: it never uses the classic user32 clipboard API).

const CF_TEXT: u32 = 1;
const CF_UNICODETEXT: u32 = 13;
const CF_HDROP: u32 = 15;
const DVASPECT_CONTENT: u32 = 1;
const DATADIR_GET: u32 = 1;
const DATA_S_SAMEFORMATETC: u32 = 0x0004_0130;
const DV_E_FORMATETC: u32 = 0x8004_0064;
const DV_E_TYMED: u32 = 0x8004_0069;
const OLE_E_ADVISENOTSUPPORTED: u32 = 0x8004_0003;
const E_NOINTERFACE: u32 = 0x8000_4002;
const E_NOTIMPL: u32 = 0x8000_4001;

const IID_IUNKNOWN: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
/// {0000010E-0000-0000-C000-000000000046}
const IID_IDATAOBJECT: [u8; 16] = [0x0E, 0x01, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
/// {00000103-0000-0000-C000-000000000046}
const IID_IENUMFORMATECT: [u8; 16] = [0x03, 0x01, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];

#[derive(Clone, Copy)]
#[repr(C)]
struct FormatEtc {
    cf: u16,
    ptd: u64,
    aspect: u32,
    lindex: i32,
    tymed: u32,
}

#[repr(C)]
struct StgMedium {
    tymed: u32,
    pad: u32,
    handle: u64,
    unk: u64,
}

fn format_etc(format: u32) -> FormatEtc {
    FormatEtc { cf: format as u16, ptd: 0, aspect: DVASPECT_CONTENT, lindex: -1, tymed: TYMED_HGLOBAL }
}

/// Formats a copy publishes, text first so it survives the payload cap.
const RENDER: [(u32, Option<&str>); 5] =
    [(CF_UNICODETEXT, None), (CF_TEXT, None), (CF_HDROP, None), (0, Some("HTML Format")), (0, Some("text/html"))];

/// One format of a program's data object as bytes (IDataObject::GetData,
/// slot 3). Formats it cannot render come back as None.
fn get_data(data: u64, format: u32) -> Option<Vec<u8>> {
    let f = format_etc(format);
    let mut m = StgMedium { tymed: 0, pad: 0, handle: 0, unk: 0 };
    // SAFETY: the caller's IDataObject; the structs outlive the call.
    let hr = unsafe {
        let vtbl = *(data as *const *const u64);
        let get: extern "win64" fn(u64, *const FormatEtc, *mut StgMedium) -> u32 = core::mem::transmute(*vtbl.add(3));
        get(data, &f, &mut m)
    };
    if hr != S_OK || m.tymed != TYMED_HGLOBAL || m.handle == 0 {
        ReleaseStgMedium(&mut m as *mut StgMedium as *mut u8);
        return None;
    }
    let size = kernel32::heap_size(m.handle);
    // SAFETY: an HGLOBAL is a fixed block of `size` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(m.handle as *const u8, size) }.to_vec();
    ReleaseStgMedium(&mut m as *mut StgMedium as *mut u8);
    if bytes.is_empty() { None } else { Some(bytes) }
}

fn render_entries(data: u64) -> Vec<proto::ClipEntry> {
    let mut out: Vec<proto::ClipEntry> = Vec::new();
    let mut used = 0usize;
    for &(format, name) in &RENDER {
        let format = name.map_or(format, crate::user32::register_format);
        let Some(bytes) = get_data(data, format) else { continue };
        if out.len() >= proto::MAX_CLIPBOARD || used + bytes.len() > proto::MAX_CLIPBOARD_BYTES {
            continue;
        }
        used += bytes.len();
        out.push(proto::ClipEntry { format, name: name.map(str::to_string), data: bytes });
    }
    out
}

/// IDataObject's vtable: IUnknown, then GetData, GetDataHere,
/// QueryGetData, GetCanonicalFormatEtc, SetData, EnumFormatEtc, DAdvise,
/// DUnadvise, EnumDAdvise.
#[repr(C)]
struct DataVtbl {
    query_interface: extern "win64" fn(u64, *const [u8; 16], *mut u64) -> u32,
    add_ref: extern "win64" fn(u64) -> u32,
    release: extern "win64" fn(u64) -> u32,
    get_data: extern "win64" fn(u64, *const FormatEtc, *mut StgMedium) -> u32,
    get_data_here: extern "win64" fn(u64, *const FormatEtc, *mut StgMedium) -> u32,
    query_get_data: extern "win64" fn(u64, *const FormatEtc) -> u32,
    get_canonical: extern "win64" fn(u64, *const FormatEtc, *mut FormatEtc) -> u32,
    set_data: extern "win64" fn(u64, *const FormatEtc, *mut StgMedium, i32) -> u32,
    enum_format_etc: extern "win64" fn(u64, u32, *mut u64) -> u32,
    d_advise: extern "win64" fn(u64, *const FormatEtc, u32, u64, *mut u32) -> u32,
    d_unadvise: extern "win64" fn(u64, u32) -> u32,
    enum_d_advise: extern "win64" fn(u64, *mut u64) -> u32,
}

/// The system clipboard's bytes as a data object.
#[repr(C)]
struct ClipData {
    vtbl: &'static DataVtbl,
    refs: AtomicU32,
    entries: Vec<proto::ClipEntry>,
}

static DATA_VTBL: DataVtbl = DataVtbl {
    query_interface: DataQueryInterface,
    add_ref: DataAddRef,
    release: DataRelease,
    get_data: DataGetData,
    get_data_here: DataNotImpl,
    query_get_data: DataQueryGetData,
    get_canonical: DataGetCanonical,
    set_data: DataSetData,
    enum_format_etc: DataEnumFormatEtc,
    d_advise: DataDAdvise,
    d_unadvise: DataDUnadvise,
    enum_d_advise: DataEnumDAdvise,
};

/// A data object with one reference, handed out by OleGetClipboard.
fn make_data_object(entries: Vec<proto::ClipEntry>) -> u64 {
    Box::into_raw(Box::new(ClipData { vtbl: &DATA_VTBL, refs: AtomicU32::new(1), entries })) as u64
}

fn clip<'a>(this: u64) -> &'a ClipData {
    // SAFETY: a ClipData made by `make_data_object`.
    unsafe { &*(this as *const ClipData) }
}

fn entry(this: u64, want: u32) -> Option<Vec<u8>> {
    clip(this).entries.iter().find(|e| e.format == want).map(|e| e.data.clone())
}

extern "win64" fn DataQueryInterface(this: u64, riid: *const [u8; 16], out: *mut u64) -> u32 {
    if riid.is_null() || out.is_null() {
        return E_POINTER;
    }
    // SAFETY: the caller's IID and out pointer.
    unsafe {
        if *riid == IID_IUNKNOWN || *riid == IID_IDATAOBJECT {
            DataAddRef(this);
            *out = this;
            return S_OK;
        }
        *out = 0;
    }
    E_NOINTERFACE
}

extern "win64" fn DataAddRef(this: u64) -> u32 {
    clip(this).refs.fetch_add(1, Ordering::AcqRel) + 1
}

extern "win64" fn DataRelease(this: u64) -> u32 {
    let left = clip(this).refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        // SAFETY: the last reference: the Box from `make_data_object`.
        drop(unsafe { Box::from_raw(this as *mut ClipData) });
    }
    left
}

extern "win64" fn DataGetData(this: u64, f: *const FormatEtc, m: *mut StgMedium) -> u32 {
    if f.is_null() || m.is_null() {
        return E_POINTER;
    }
    // SAFETY: the caller's FORMATETC.
    let (want, tymed) = unsafe { ((*f).cf as u32, (*f).tymed) };
    let Some(data) = entry(this, want) else { return DV_E_FORMATETC };
    if tymed & TYMED_HGLOBAL == 0 {
        return DV_E_TYMED;
    }
    let Some(h) = kernel32::heap_alloc(data.len().max(1), true) else { return E_OUTOFMEMORY };
    // SAFETY: a fresh block of at least `data.len()` bytes.
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), h as *mut u8, data.len()) };
    // SAFETY: the caller's STGMEDIUM; the block is ours to hand over.
    unsafe { *m = StgMedium { tymed: TYMED_HGLOBAL, pad: 0, handle: h, unk: 0 } };
    S_OK
}

extern "win64" fn DataQueryGetData(this: u64, f: *const FormatEtc) -> u32 {
    if f.is_null() {
        return E_POINTER;
    }
    // SAFETY: the caller's FORMATETC.
    let want = unsafe { (*f).cf as u32 };
    if entry(this, want).is_some() { S_OK } else { DV_E_FORMATETC }
}

extern "win64" fn DataGetCanonical(_this: u64, f: *const FormatEtc, out: *mut FormatEtc) -> u32 {
    if f.is_null() || out.is_null() {
        return E_POINTER;
    }
    // SAFETY: the caller's FORMATETCs.
    unsafe { *out = FormatEtc { ptd: 0, ..*f } };
    DATA_S_SAMEFORMATETC
}

extern "win64" fn DataEnumFormatEtc(this: u64, dir: u32, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_POINTER;
    }
    if dir != DATADIR_GET {
        // SAFETY: the caller's out pointer.
        unsafe { *out = 0 };
        return E_NOTIMPL;
    }
    let formats = clip(this).entries.iter().map(|e| format_etc(e.format)).collect();
    // SAFETY: the caller's out pointer.
    unsafe { *out = make_format_enum(formats) };
    S_OK
}

/// Writing into the clipboard object is not part of the contract here.
extern "win64" fn DataSetData(_this: u64, _f: *const FormatEtc, _m: *mut StgMedium, _release: i32) -> u32 {
    E_NOTIMPL
}

extern "win64" fn DataNotImpl(_this: u64, _f: *const FormatEtc, _m: *mut StgMedium) -> u32 {
    E_NOTIMPL
}

extern "win64" fn DataDAdvise(_this: u64, _f: *const FormatEtc, _advf: u32, _sink: u64, _conn: *mut u32) -> u32 {
    OLE_E_ADVISENOTSUPPORTED
}

extern "win64" fn DataDUnadvise(_this: u64, _conn: u32) -> u32 {
    OLE_E_ADVISENOTSUPPORTED
}

extern "win64" fn DataEnumDAdvise(_this: u64, _out: *mut u64) -> u32 {
    OLE_E_ADVISENOTSUPPORTED
}

/// IEnumFORMATETC: IUnknown, then Next, Skip, Reset, Clone.
#[repr(C)]
struct EnumVtbl {
    query_interface: extern "win64" fn(u64, *const [u8; 16], *mut u64) -> u32,
    add_ref: extern "win64" fn(u64) -> u32,
    release: extern "win64" fn(u64) -> u32,
    next: extern "win64" fn(u64, u32, *mut FormatEtc, *mut u32) -> u32,
    skip: extern "win64" fn(u64, u32) -> u32,
    reset: extern "win64" fn(u64) -> u32,
    clone: extern "win64" fn(u64, *mut u64) -> u32,
}

#[repr(C)]
struct FormatEnum {
    vtbl: &'static EnumVtbl,
    refs: AtomicU32,
    formats: Vec<FormatEtc>,
    pos: usize,
}

static ENUM_VTBL: EnumVtbl = EnumVtbl {
    query_interface: EnumQueryInterface,
    add_ref: EnumAddRef,
    release: EnumRelease,
    next: EnumNext,
    skip: EnumSkip,
    reset: EnumReset,
    clone: EnumClone,
};

fn make_format_enum(formats: Vec<FormatEtc>) -> u64 {
    Box::into_raw(Box::new(FormatEnum { vtbl: &ENUM_VTBL, refs: AtomicU32::new(1), formats, pos: 0 })) as u64
}

fn formats_mut<'a>(this: u64) -> &'a mut FormatEnum {
    // SAFETY: a FormatEnum made by `make_format_enum`.
    unsafe { &mut *(this as *mut FormatEnum) }
}

fn formats<'a>(this: u64) -> &'a FormatEnum {
    // SAFETY: a FormatEnum made by `make_format_enum`.
    unsafe { &*(this as *const FormatEnum) }
}

extern "win64" fn EnumQueryInterface(this: u64, riid: *const [u8; 16], out: *mut u64) -> u32 {
    if riid.is_null() || out.is_null() {
        return E_POINTER;
    }
    // SAFETY: the caller's IID and out pointer.
    unsafe {
        if *riid == IID_IUNKNOWN || *riid == IID_IENUMFORMATECT {
            EnumAddRef(this);
            *out = this;
            return S_OK;
        }
        *out = 0;
    }
    E_NOINTERFACE
}

extern "win64" fn EnumAddRef(this: u64) -> u32 {
    formats(this).refs.fetch_add(1, Ordering::AcqRel) + 1
}

extern "win64" fn EnumRelease(this: u64) -> u32 {
    let left = formats(this).refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        // SAFETY: the last reference: the Box from `make_format_enum`.
        drop(unsafe { Box::from_raw(this as *mut FormatEnum) });
    }
    left
}

extern "win64" fn EnumNext(this: u64, count: u32, out: *mut FormatEtc, fetched: *mut u32) -> u32 {
    if out.is_null() {
        return E_POINTER;
    }
    let e = formats_mut(this);
    let left = e.formats.len().saturating_sub(e.pos);
    let n = (count as usize).min(left);
    for i in 0..n {
        // SAFETY: the caller's array of `count` FORMATETCs.
        unsafe { *out.add(i) = e.formats[e.pos + i] };
    }
    e.pos += n;
    if !fetched.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *fetched = n as u32 };
    }
    if n as u32 == count { S_OK } else { S_FALSE }
}

extern "win64" fn EnumSkip(this: u64, count: u32) -> u32 {
    let e = formats_mut(this);
    let left = e.formats.len().saturating_sub(e.pos);
    if count as usize > left {
        e.pos = e.formats.len();
        return S_FALSE;
    }
    e.pos += count as usize;
    S_OK
}

extern "win64" fn EnumReset(this: u64) -> u32 {
    formats_mut(this).pos = 0;
    S_OK
}

extern "win64" fn EnumClone(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_POINTER;
    }
    let e = formats(this);
    // SAFETY: the caller's out pointer.
    unsafe { *out = Box::into_raw(Box::new(FormatEnum { vtbl: &ENUM_VTBL, refs: AtomicU32::new(1), formats: e.formats.clone(), pos: e.pos })) as u64 };
    S_OK
}

pub fn exports() -> Vec<(&'static str, u64)> {
    let mut e = export_table![
        CoTaskMemAlloc,
        CoTaskMemFree,
        CoTaskMemRealloc,
        CoInitializeEx,
        CoInitialize,
        CoUninitialize,
        GetErrorInfo,
        SetErrorInfo,
        OleInitialize,
        OleUninitialize,
        CoInitializeSecurity,
        CoGetApartmentType,
        CoCreateInstance,
        CoAllowSetForegroundWindow,
        CoIncrementMTAUsage,
        CoDecrementMTAUsage,
        CoGetCallerTID,
        CLSIDFromString,
        IIDFromString,
        StringFromGUID2,
        StringFromCLSID,
        StringFromIID,
        RegisterDragDrop,
        RevokeDragDrop,
        DoDragDrop,
        OleSetClipboard,
        OleGetClipboard,
        OleFlushClipboard,
        OleIsCurrentClipboard,
        ReleaseStgMedium
    ];
    e.push(("PropVariantClear", crate::propsys::PropVariantClear as *const () as u64));
    e
}
