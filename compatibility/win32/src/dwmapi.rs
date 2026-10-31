//! dwmapi (the Desktop Window Manager's per-window attributes and frame
//! timing), imm32 and wtsapi32.
//!
//! PRISM composes every window, so composition is always on. Attributes a
//! program sets are kept per window and read back where Windows reports
//! them (DWMWA_CLOAKED); PRISM does not draw caption colours, rounded
//! corners or backdrops, and cloaking does not hide a window. Windows have
//! no invisible resize borders, so the extended frame is the window
//! rectangle. Frame timing is a 60 Hz clock on the performance counter;
//! DwmFlush waits for its next tick. Taskbar thumbnails are accepted and
//! never shown.
//!
//! OSyx has no input method editors: threads have no input context
//! (ImmGetContext returns NULL, as for a thread with IMM disabled) and
//! keyboard layouts are not IMEs. There are no terminal-services sessions
//! to switch, so a session notification is registered and never sent.
//! dnsapi answers no record queries (see below).
//!
//! There is no GPU: d3d11 creates no device (DXGI_ERROR_UNSUPPORTED, as
//! for a driver type the machine lacks), dxgi makes no factory and the
//! shader compiler compiles nothing, so programs take their software paths.
#![allow(non_snake_case)]
use crate::error::*;
use crate::kernel32::{fail, Bool, FALSE, TRUE};
use crate::teb;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use os_std::sync::Mutex;

const S_OK: u32 = 0;
const E_INVALIDARG: u32 = 0x8007_0057;
const E_HANDLE: u32 = 0x8007_0006;
/// What Windows 10.0.26300 returns for a DWM_TIMING_INFO of the wrong size.
const DWM_E_BAD_TIMING_SIZE: u32 = 0x8898_0090;

const DWMWA_NCRENDERING_ENABLED: u32 = 1;
const DWMWA_EXTENDED_FRAME_BOUNDS: u32 = 9;
const DWMWA_CLOAK: u32 = 13;
const DWMWA_CLOAKED: u32 = 14;
const DWMWA_VISIBLE_FRAME_BORDER_THICKNESS: u32 = 37;
const DWM_CLOAKED_APP: u32 = 1;
/// Attributes a program can set (each a DWORD or BOOL).
const SETTABLE: &[u32] = &[2, 3, 4, 6, 7, 8, 10, 11, 12, DWMWA_CLOAK, 15, 16, 17, 19, 20, 33, 34, 35, 36, 38];

/// (HWND, attribute) → the value last set.
static ATTRS: Mutex<BTreeMap<(u64, u32), u32>> = Mutex::new(BTreeMap::new());

/// One refresh of the composition clock, in performance-counter units (ns).
const REFRESH_NS: u64 = 1_000_000_000 / 60;

extern "win64" fn DwmIsCompositionEnabled(out: *mut Bool) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's BOOL.
    unsafe { *out = TRUE };
    S_OK
}

extern "win64" fn DwmSetWindowAttribute(hwnd: u64, attr: u32, value: *const u8, size: u32) -> u32 {
    if !crate::user32::is_window(hwnd) {
        return E_HANDLE;
    }
    if !SETTABLE.contains(&attr) || value.is_null() || size != 4 {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's 4-byte value.
    let v = unsafe { teb::get::<u32>(value as u64, 0) };
    let mut attrs = ATTRS.lock().unwrap();
    attrs.retain(|&(w, _), _| crate::user32::is_window(w));
    attrs.insert((hwnd, attr), v);
    S_OK
}

extern "win64" fn DwmGetWindowAttribute(hwnd: u64, attr: u32, out: *mut u8, size: u32) -> u32 {
    if !crate::user32::is_window(hwnd) {
        return E_HANDLE;
    }
    if out.is_null() {
        return E_INVALIDARG;
    }
    let dword = |v: u32| {
        if size != 4 {
            return E_INVALIDARG;
        }
        // SAFETY: the caller's 4-byte buffer.
        unsafe { teb::put(out as u64, 0, v) };
        S_OK
    };
    match attr {
        DWMWA_NCRENDERING_ENABLED => dword(1),
        DWMWA_CLOAKED => {
            let cloaked = ATTRS.lock().unwrap().get(&(hwnd, DWMWA_CLOAK)).is_some_and(|&v| v != 0);
            dword(if cloaked { DWM_CLOAKED_APP } else { 0 })
        }
        DWMWA_VISIBLE_FRAME_BORDER_THICKNESS => dword(0),
        DWMWA_EXTENDED_FRAME_BOUNDS => {
            if size != 16 {
                return E_INVALIDARG;
            }
            match crate::user32::window_rect(hwnd) {
                Some(r) => {
                    // SAFETY: the caller's RECT.
                    unsafe { teb::put(out as u64, 0, r) };
                    S_OK
                }
                None => E_HANDLE,
            }
        }
        _ => E_INVALIDARG,
    }
}

/// The frame already is the whole client area: nothing to extend.
extern "win64" fn DwmExtendFrameIntoClientArea(hwnd: u64, _margins: *const i32) -> u32 {
    if crate::user32::is_window(hwnd) { S_OK } else { E_INVALIDARG }
}

/// Waits for the next tick of the composition clock.
extern "win64" fn DwmFlush() -> u32 {
    static N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && (n < 20 || n.is_multiple_of(600)) {
        os_std::eprintln!("winrun: dwmflush n={n}");
    }
    let now = crate::kernel32::now_ns();
    let next = (now / REFRESH_NS + 1) * REFRESH_NS;
    os_std::thread::sleep(core::time::Duration::from_nanos(next - now));
    S_OK
}

/// DWM_TIMING_INFO (292 bytes, packed): the refresh rate and period, the
/// last vertical blank and the refresh count; frame statistics are zero.
extern "win64" fn DwmGetCompositionTimingInfo(hwnd: u64, info: *mut u8) -> u32 {
    static N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let log = crate::EVENTS.load(core::sync::atomic::Ordering::Relaxed) && (n < 20 || n.is_multiple_of(600));
    if hwnd != 0 || info.is_null() {
        if log {
            os_std::eprintln!("winrun: dwmtiming n={n} hwnd={hwnd:#x} badarg");
        }
        return E_INVALIDARG;
    }
    // SAFETY: the caller's structure starts with its size.
    let size = unsafe { teb::get::<u32>(info as u64, 0) };
    if log {
        os_std::eprintln!("winrun: dwmtiming n={n} hwnd={hwnd:#x} size={size}");
    }
    if size != 292 {
        return DWM_E_BAD_TIMING_SIZE;
    }
    let now = crate::kernel32::now_ns();
    let count = now / REFRESH_NS;
    let vblank = count * REFRESH_NS;
    // SAFETY: the caller's 292-byte DWM_TIMING_INFO.
    unsafe {
        core::ptr::write_bytes(info.add(4), 0, 288);
        let p = info as u64;
        teb::put(p, 4, 60u32); // rateRefresh
        teb::put(p, 8, 1u32);
        teb::put(p, 12, REFRESH_NS); // qpcRefreshPeriod
        teb::put(p, 20, 60u32); // rateCompose
        teb::put(p, 24, 1u32);
        teb::put(p, 28, vblank); // qpcVBlank
        teb::put(p, 36, count); // cRefresh
        teb::put(p, 48, vblank + REFRESH_NS); // qpcCompose
    }
    S_OK
}

/// Taskbar thumbnails and peek bitmaps: accepted for a window, never shown.
extern "win64" fn DwmSetIconicThumbnail(hwnd: u64, _bitmap: u64, _flags: u32) -> u32 {
    if crate::user32::is_window(hwnd) { S_OK } else { E_INVALIDARG }
}

extern "win64" fn DwmSetIconicLivePreviewBitmap(hwnd: u64, _bitmap: u64, _offset: *const i32, _flags: u32) -> u32 {
    if crate::user32::is_window(hwnd) { S_OK } else { E_INVALIDARG }
}

extern "win64" fn DwmInvalidateIconicBitmaps(hwnd: u64) -> u32 {
    if crate::user32::is_window(hwnd) { S_OK } else { E_INVALIDARG }
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        DwmIsCompositionEnabled,
        DwmSetWindowAttribute,
        DwmGetWindowAttribute,
        DwmExtendFrameIntoClientArea,
        DwmFlush,
        DwmGetCompositionTimingInfo,
        DwmSetIconicThumbnail,
        DwmSetIconicLivePreviewBitmap,
        DwmInvalidateIconicBitmaps,
    ]
}

// ---- imm32 ----------------------------------------------------------------------------------





extern "win64" fn ImmAssociateContextEx(hwnd: u64, _himc: u64, _flags: u32) -> Bool {
    crate::user32::is_window(hwnd) as Bool
}



/// No layout is an IME: no properties, description or IME file.






/// Every remaining call takes an input context, and there never is one.


















// ---- imm32: input contexts -------------------------------------------------
// OSyx has no input method editor: every window can have a default input
// context (closed, nothing being composed) and the keyboard layout has no IME.
// The context keeps the state applications set on it.

const HKL_US: u64 = 0x0409_0409;
const IMM_ERROR_GENERAL: i32 = -2;

struct InputContext {
    wnd: u64,
    open: bool,
    composition_window: [u8; 28],
    font: [u8; 92],
    candidates: [[u8; 32]; 4],
}

static CONTEXTS: Mutex<BTreeMap<u64, InputContext>> = Mutex::new(BTreeMap::new());

fn with_context<R>(himc: u64, f: impl FnOnce(&mut InputContext) -> R) -> Option<R> {
    CONTEXTS.lock().unwrap().get_mut(&himc).map(f)
}

/// The default input context of a window, made on first use.
extern "win64" fn ImmGetContext(hwnd: u64) -> u64 {
    if !crate::user32::is_window(hwnd) {
        return fail(1400, 0); // ERROR_INVALID_WINDOW_HANDLE
    }
    let himc = 0x4000_0000 | hwnd;
    CONTEXTS.lock().unwrap().entry(himc).or_insert(InputContext { wnd: hwnd, open: false, composition_window: [0; 28], font: [0; 92], candidates: [[0; 32]; 4] });
    himc
}

/// Releasing NULL succeeds, as on Windows; otherwise the context must be the
/// window's.
extern "win64" fn ImmReleaseContext(hwnd: u64, himc: u64) -> i32 {
    if himc == 0 {
        return 1;
    }
    with_context(himc, |c| c.wnd == hwnd).unwrap_or(false) as i32
}

extern "win64" fn ImmGetOpenStatus(himc: u64) -> i32 {
    with_context(himc, |c| c.open).unwrap_or(false) as i32
}

extern "win64" fn ImmSetOpenStatus(himc: u64, open: i32) -> i32 {
    with_context(himc, |c| c.open = open != 0).is_some() as i32
}

/// COMPOSITIONFORM (28 bytes: style, point, rectangle).
extern "win64" fn ImmSetCompositionWindow(himc: u64, form: *const u8) -> i32 {
    if form.is_null() {
        return 0;
    }
    // SAFETY: the caller's COMPOSITIONFORM.
    let bytes = unsafe { core::ptr::read_unaligned(form as *const [u8; 28]) };
    with_context(himc, |c| c.composition_window = bytes).is_some() as i32
}

/// CANDIDATEFORM (32 bytes: index, style, point, rectangle); the index
/// (0..3) says which candidate window it describes.
extern "win64" fn ImmSetCandidateWindow(himc: u64, form: *const u8) -> i32 {
    if form.is_null() {
        return 0;
    }
    // SAFETY: the caller's CANDIDATEFORM.
    let bytes = unsafe { core::ptr::read_unaligned(form as *const [u8; 32]) };
    let index = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if index >= 4 {
        return 0;
    }
    with_context(himc, |c| c.candidates[index] = bytes).is_some() as i32
}

/// LOGFONTW (92 bytes).
extern "win64" fn ImmSetCompositionFontW(himc: u64, font: *const u8) -> i32 {
    if font.is_null() {
        return 0;
    }
    // SAFETY: the caller's LOGFONTW.
    let bytes = unsafe { core::ptr::read_unaligned(font as *const [u8; 92]) };
    with_context(himc, |c| c.font = bytes).is_some() as i32
}

extern "win64" fn ImmGetCompositionFontW(himc: u64, font: *mut u8) -> i32 {
    if font.is_null() {
        return 0;
    }
    match with_context(himc, |c| c.font) {
        Some(bytes) => {
            // SAFETY: the caller's LOGFONTW.
            unsafe { core::ptr::write_unaligned(font as *mut [u8; 92], bytes) };
            1
        }
        None => 0,
    }
}

/// Nothing is ever being composed: every known string index has length 0,
/// an unknown index or context is IMM_ERROR_GENERAL.
fn composition_length(himc: u64, index: u32) -> i32 {
    const KNOWN: u32 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x2000;
    if himc == 0 {
        return 0; // as on Windows
    }
    if index == 0 || index & !KNOWN != 0 || with_context(himc, |_| ()).is_none() {
        return IMM_ERROR_GENERAL;
    }
    0
}

extern "win64" fn ImmGetCompositionStringW(himc: u64, index: u32, _buf: *mut u8, _len: u32) -> i32 {
    composition_length(himc, index)
}

extern "win64" fn ImmGetCompositionStringA(himc: u64, index: u32, _buf: *mut u8, _len: u32) -> i32 {
    composition_length(himc, index)
}

/// NI_COMPOSITIONSTR (0x15) with CPS_COMPLETE (1) or CPS_CANCEL (4) has
/// nothing to complete or cancel and succeeds; other requests are refused.
extern "win64" fn ImmNotifyIME(himc: u64, action: u32, index: u32, _value: u32) -> i32 {
    (with_context(himc, |_| ()).is_some() && action == 0x15 && matches!(index, 1 | 4)) as i32
}

/// The IME window of a window: there is none.
extern "win64" fn ImmGetDefaultIMEWnd(hwnd: u64) -> u64 {
    if !crate::user32::is_window(hwnd) {
        return fail(1400, 0);
    }
    0
}

/// The only keyboard layout (US) has no IME: no properties, no name, no file.
fn ime_free_layout(hkl: u64) -> bool {
    hkl == HKL_US
}

extern "win64" fn ImmGetProperty(hkl: u64, _index: u32) -> u32 {
    if !ime_free_layout(hkl) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    0
}

extern "win64" fn ImmGetDescriptionW(hkl: u64, _buf: *mut u16, _len: u32) -> u32 {
    if !ime_free_layout(hkl) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    0
}

extern "win64" fn ImmGetIMEFileNameW(hkl: u64, _buf: *mut u16, _len: u32) -> u32 {
    if !ime_free_layout(hkl) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    0
}

pub fn imm32_exports() -> Vec<(&'static str, u64)> {
    export_table![
        ImmGetContext,
        ImmReleaseContext,
        ImmAssociateContextEx,
        ImmGetDefaultIMEWnd,
        ImmGetProperty,
        ImmGetDescriptionW,
        ImmGetIMEFileNameW,
        ImmGetOpenStatus,
        ImmSetOpenStatus,
        ImmNotifyIME,
        ImmGetCompositionStringW,
        ImmGetCompositionStringA,
        ImmSetCompositionWindow,
        ImmSetCandidateWindow,
        ImmGetCompositionFontW,
        ImmSetCompositionFontW,
    ]
}

// ---- d3d11, dxgi, d3dcompiler ----------------------------------------------------------------

const DXGI_ERROR_UNSUPPORTED: u32 = 0x887A_0004;
const E_FAIL: u32 = 0x8000_4005;

fn clear_out(p: *mut u64) {
    if !p.is_null() {
        // SAFETY: the caller's interface out pointer.
        unsafe { *p = 0 };
    }
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn D3D11CreateDevice(
    _adapter: u64,
    _driver: u32,
    _software: u64,
    _flags: u32,
    _levels: *const u32,
    _n: u32,
    _sdk: u32,
    device: *mut u64,
    level: *mut u32,
    context: *mut u64,
) -> u32 {
    clear_out(device);
    clear_out(context);
    if !level.is_null() {
        // SAFETY: the caller's D3D_FEATURE_LEVEL.
        unsafe { *level = 0 };
    }
    DXGI_ERROR_UNSUPPORTED
}

extern "win64" fn CreateDXGIFactory1(_riid: *const u8, out: *mut u64) -> u32 {
    clear_out(out);
    DXGI_ERROR_UNSUPPORTED
}

extern "win64" fn CreateDXGIFactory(riid: *const u8, out: *mut u64) -> u32 {
    CreateDXGIFactory1(riid, out)
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn D3DCompile(
    _src: *const u8,
    _len: usize,
    _name: *const u8,
    _defines: *const u8,
    _include: u64,
    _entry: *const u8,
    _target: *const u8,
    _flags1: u32,
    _flags2: u32,
    code: *mut u64,
    errors: *mut u64,
) -> u32 {
    clear_out(code);
    clear_out(errors);
    E_FAIL
}

pub fn d3d11_exports() -> Vec<(&'static str, u64)> {
    export_table![D3D11CreateDevice]
}

pub fn dxgi_exports() -> Vec<(&'static str, u64)> {
    export_table![CreateDXGIFactory1, CreateDXGIFactory]
}

pub fn d3dcompiler_exports() -> Vec<(&'static str, u64)> {
    export_table![D3DCompile]
}

// ---- dnsapi ------------------------------------------------------------------------------------
//
// Names resolve through ws2_32 (getaddrinfo). OSyx's resolver answers no
// other record types, so DnsQuery reports that the name has none.

const DNS_INFO_NO_RECORDS: u32 = 9501;

extern "win64" fn DnsQuery_A(name: *const u8, _kind: u16, _options: u32, _extra: u64, results: *mut u64, _reserved: u64) -> u32 {
    if name.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if !results.is_null() {
        // SAFETY: the caller's PDNS_RECORD.
        unsafe { *results = 0 };
    }
    DNS_INFO_NO_RECORDS
}

extern "win64" fn DnsQuery_W(name: *const u16, kind: u16, options: u32, extra: u64, results: *mut u64, reserved: u64) -> u32 {
    DnsQuery_A(name as *const u8, kind, options, extra, results, reserved)
}

/// There are never records to free.
extern "win64" fn DnsFree(_data: u64, _kind: u32) {}

pub fn dnsapi_exports() -> Vec<(&'static str, u64)> {
    export_table![DnsQuery_A, DnsQuery_W, DnsFree]
}

// ---- wtsapi32 -------------------------------------------------------------------------------

extern "win64" fn WTSRegisterSessionNotification(hwnd: u64, _flags: u32) -> Bool {
    if crate::user32::is_window(hwnd) { TRUE } else { fail(ERROR_INVALID_PARAMETER, FALSE) }
}

extern "win64" fn WTSUnRegisterSessionNotification(hwnd: u64) -> Bool {
    if crate::user32::is_window(hwnd) { TRUE } else { fail(ERROR_INVALID_PARAMETER, FALSE) }
}

pub fn wtsapi32_exports() -> Vec<(&'static str, u64)> {
    export_table![WTSRegisterSessionNotification, WTSUnRegisterSessionNotification]
}
