//! oleaut32: BSTRs and VARIANT initialisation and clearing.
//!
//! A BSTR is a UTF-16 string preceded by its byte length (a DWORD) and
//! followed by a NUL; the pointer handed out is the string itself. Blocks
//! come from the process heap and are never cached, so SetOaNoCache has
//! nothing to turn off. VARIANTs holding SAFEARRAYs or records are not
//! supported (no SAFEARRAY or IRecordInfo implementation): clearing one
//! fails with DISP_E_BADVARTYPE and leaves it untouched.
#![allow(non_snake_case)]
use crate::kernel32;
use alloc::{collections::BTreeMap, vec::Vec};
use os_std::sync::Mutex;

const S_OK: u32 = 0;
const E_INVALIDARG: u32 = 0x8007_0057;
const E_OUTOFMEMORY: u32 = 0x8007_000e;
const DISP_E_BADVARTYPE: u32 = 0x8002_0008;

static ERROR_INFO: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

pub fn thread_exit() {
    let info = ERROR_INFO.lock().unwrap().remove(&os_sys::gettid());
    if let Some(info) = info {
        error_ref(info, 2);
    }
}

fn error_ref(info: u64, slot: usize) {
    // SAFETY: SetErrorInfo accepts an IErrorInfo, whose first three slots
    // are IUnknown; the retained reference keeps it alive until removal.
    unsafe {
        let vtable = *(info as *const *const u64);
        let f: extern "win64" fn(u64) -> u32 = core::mem::transmute(*vtable.add(slot));
        f(info);
    }
}

pub(crate) extern "win64" fn SetErrorInfo(reserved: u32, info: u64) -> u32 {
    if reserved != 0 {
        return E_INVALIDARG;
    }
    if info != 0 {
        error_ref(info, 1);
    }
    let old = {
        let mut errors = ERROR_INFO.lock().unwrap();
        if info == 0 { errors.remove(&os_sys::gettid()) } else { errors.insert(os_sys::gettid(), info) }
    };
    if let Some(old) = old {
        error_ref(old, 2);
    }
    S_OK
}

pub(crate) extern "win64" fn GetErrorInfo(reserved: u32, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller supplies an IErrorInfo* output.
    unsafe { *out = 0 };
    if reserved != 0 {
        return E_INVALIDARG;
    }
    let info = ERROR_INFO.lock().unwrap().remove(&os_sys::gettid());
    if let Some(info) = info {
        // Transfer the thread's retained reference to the caller.
        unsafe { *out = info };
        S_OK
    } else {
        1 // S_FALSE: no error object on this thread.
    }
}

/// The heap block of a BSTR: the 4-byte length sits right before the
/// string, at the end of a 16-byte header.
const HEADER: u64 = 16;

/// A BSTR of `bytes` bytes, copied from `src` (or zeroed when NULL).
fn alloc_bstr(src: *const u8, bytes: u32) -> u64 {
    let Some(block) = kernel32::heap_alloc(HEADER as usize + bytes as usize + 2, true) else { return 0 };
    let s = block + HEADER;
    // SAFETY: a fresh block of HEADER + bytes + 2 bytes; `src` has `bytes`.
    unsafe {
        *((s - 4) as *mut u32) = bytes;
        if !src.is_null() {
            core::ptr::copy_nonoverlapping(src, s as *mut u8, bytes as usize);
        }
    }
    s
}

fn wide_len(p: *const u16) -> usize {
    let mut n = 0;
    // SAFETY: a NUL-terminated UTF-16 string.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

extern "win64" fn SysAllocString(s: *const u16) -> u64 {
    if s.is_null() {
        return 0;
    }
    alloc_bstr(s as *const u8, (wide_len(s) * 2) as u32)
}

extern "win64" fn SysAllocStringLen(s: *const u16, len: u32) -> u64 {
    if len > u32::MAX / 2 - 16 {
        return 0;
    }
    alloc_bstr(s as *const u8, len * 2)
}

extern "win64" fn SysAllocStringByteLen(s: *const u8, len: u32) -> u64 {
    if len > u32::MAX - 32 {
        return 0;
    }
    alloc_bstr(s, len)
}

extern "win64" fn SysFreeString(s: u64) {
    if s != 0 {
        kernel32::heap_free(s - HEADER);
    }
}

extern "win64" fn SysStringByteLen(s: u64) -> u32 {
    if s == 0 {
        return 0;
    }
    // SAFETY: a BSTR: its length precedes it.
    unsafe { *((s - 4) as *const u32) }
}

extern "win64" fn SysStringLen(s: u64) -> u32 {
    SysStringByteLen(s) / 2
}

/// Replaces *old with a new BSTR (the source may overlap the old one).
fn realloc(old: *mut u64, src: *const u8, bytes: u32) -> i32 {
    if old.is_null() {
        return 0;
    }
    let new = alloc_bstr(src, bytes);
    if new == 0 {
        return 0;
    }
    // SAFETY: the caller's BSTR pointer.
    unsafe {
        SysFreeString(*old);
        *old = new;
    }
    1
}

extern "win64" fn SysReAllocString(old: *mut u64, s: *const u16) -> i32 {
    if s.is_null() {
        return realloc(old, core::ptr::null(), 0);
    }
    realloc(old, s as *const u8, (wide_len(s) * 2) as u32)
}

extern "win64" fn SysReAllocStringLen(old: *mut u64, s: *const u16, len: u32) -> i32 {
    if len > u32::MAX / 2 - 16 {
        return 0;
    }
    realloc(old, s as *const u8, len * 2)
}

extern "win64" fn SetOaNoCache() {}

// ---- VARIANT ----------------------------------------------------------------------------

const VT_EMPTY: u16 = 0;
const VT_BSTR: u16 = 8;
const VT_DISPATCH: u16 = 9;
const VT_UNKNOWN: u16 = 13;
const VT_RECORD: u16 = 36;
const VT_ARRAY: u16 = 0x2000;
const VT_BYREF: u16 = 0x4000;

/// Types a VARIANT holds by value without owning anything.
fn plain(vt: u16) -> bool {
    matches!(vt, 0..=7 | 10 | 11 | 14 | 16..=23 | 25 | 26)
}

/// A copy of a BSTR (PropVariantCopy uses it).
pub(crate) fn copy_bstr(b: u64) -> u64 {
    SysAllocStringByteLen(b as *const u8, SysStringByteLen(b))
}

pub(crate) fn free_bstr(b: u64) {
    SysFreeString(b);
}

extern "win64" fn VariantInit(v: *mut u8) {
    if !v.is_null() {
        // SAFETY: the caller's 24-byte VARIANT; only vt and the reserved words are set.
        unsafe { core::ptr::write_bytes(v, 0, 8) };
    }
}

extern "win64" fn VariantClear(v: *mut u8) -> u32 {
    if v.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's VARIANT.
    let vt = unsafe { *(v as *const u16) };
    let value = unsafe { *(v.add(8) as *const u64) };
    if vt & VT_BYREF != 0 {
        // References are not owned; only the type must be valid.
        if !plain(vt & !VT_BYREF) && ![VT_BSTR, VT_DISPATCH, VT_UNKNOWN, 12].contains(&(vt & !VT_BYREF)) {
            return DISP_E_BADVARTYPE;
        }
    } else if vt & VT_ARRAY != 0 {
        if value != 0 {
            let hr = SafeArrayDestroy(value);
            if hr != S_OK {
                return hr;
            }
        }
    } else if vt == VT_RECORD {
        return if value == 0 { S_OK } else { DISP_E_BADVARTYPE };
    } else if vt == VT_BSTR {
        SysFreeString(value);
    } else if vt == VT_DISPATCH || vt == VT_UNKNOWN {
        if value != 0 {
            // SAFETY: a COM interface pointer: IUnknown::Release is vtable slot 2.
            unsafe {
                let vtbl = *(value as *const *const u64);
                let release: extern "win64" fn(u64) -> u32 = core::mem::transmute(*vtbl.add(2));
                release(value);
            }
        }
    } else if !plain(vt) {
        return DISP_E_BADVARTYPE;
    }
    // SAFETY: as above.
    unsafe { *(v as *mut u16) = VT_EMPTY };
    S_OK
}

extern "win64" fn VariantCopy(dst: *mut u8, src: *const u8) -> u32 {
    if dst.is_null() || src.is_null() {
        return E_INVALIDARG;
    }
    if core::ptr::eq(dst, src) {
        return S_OK;
    }
    // SAFETY: the caller's VARIANTs (24 bytes each).
    let (vt, value) = unsafe { (*(src as *const u16), *(src.add(8) as *const u64)) };
    if vt & VT_ARRAY != 0 && vt & VT_BYREF == 0 || vt == VT_RECORD {
        return DISP_E_BADVARTYPE; // no SAFEARRAY or record copies
    }
    let hr = VariantClear(dst);
    if hr != S_OK {
        return hr;
    }
    // SAFETY: as above.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, 24) };
    if vt == VT_BSTR && value != 0 {
        let copy = SysAllocStringByteLen(value as *const u8, SysStringByteLen(value));
        if copy == 0 {
            // SAFETY: as above.
            unsafe { *(dst as *mut u16) = VT_EMPTY };
            return E_OUTOFMEMORY;
        }
        // SAFETY: as above.
        unsafe { *(dst.add(8) as *mut u64) = copy };
    } else if (vt == VT_DISPATCH || vt == VT_UNKNOWN) && value != 0 {
        // SAFETY: IUnknown::AddRef is vtable slot 1.
        unsafe {
            let vtbl = *(value as *const *const u64);
            let add_ref: extern "win64" fn(u64) -> u32 = core::mem::transmute(*vtbl.add(1));
            add_ref(value);
        }
    }
    S_OK
}

// ---- SAFEARRAY and type library / dispatch helpers --------------------------------------

const DISP_E_BADINDEX: u32 = 0x8002_000b;
const DISP_E_ARRAYISLOCKED: u32 = 0x8002_000d;
const TYPE_E_LIBNOTREGISTERED: u32 = 0x8002_801d;
const E_UNEXPECTED: u32 = 0x8000_ffff;
const E_NOTIMPL: u32 = 0x8000_4001;

const FADF_HAVEVARTYPE: u16 = 0x0080;
const FADF_BSTR: u16 = 0x0100;
const FADF_UNKNOWN: u16 = 0x0200;
const FADF_DISPATCH: u16 = 0x0400;
const FADF_VARIANT: u16 = 0x0800;

fn elem_size_and_features(vt: u16) -> Option<(u32, u16)> {
    let (cb, feat) = match vt {
        16 | 17 => (1, FADF_HAVEVARTYPE),
        2 | 18 | 11 => (2, FADF_HAVEVARTYPE),
        3 | 19 | 4 | 22 | 23 | 10 => (4, FADF_HAVEVARTYPE),
        20 | 21 | 5 | 6 | 7 => (8, FADF_HAVEVARTYPE),
        VT_BSTR => (8, FADF_HAVEVARTYPE | FADF_BSTR),
        VT_DISPATCH => (8, FADF_HAVEVARTYPE | FADF_DISPATCH),
        VT_UNKNOWN => (8, FADF_HAVEVARTYPE | FADF_UNKNOWN),
        12 => (24, FADF_HAVEVARTYPE | FADF_VARIANT),
        _ => return None,
    };
    Some((cb, feat))
}

/// SAFEARRAY (32 bytes on x64): cDims(2), fFeatures(2), cbElements(4),
/// cLocks(4), pad(4), pvData(8), rgsabound[0]{cElements(4), lLbound(4)}.
/// A 16-byte prefix before the header stores the VARTYPE at `psa - 4`.
extern "win64" fn SafeArrayCreateVector(vt: u16, lbound: i32, count: u32) -> u64 {
    let Some((cb, feat)) = elem_size_and_features(vt) else { return 0 };
    let Some(data_bytes) = (count as usize).checked_mul(cb as usize) else { return 0 };
    let Some(block) = kernel32::heap_alloc(16 + 32 + data_bytes, true) else { return 0 };
    let psa = block + 16;
    let pv_data = psa + 32;
    unsafe {
        *((psa - 4) as *mut u32) = vt as u32;
        *(psa as *mut u16) = 1; // cDims
        *((psa + 2) as *mut u16) = feat;
        *((psa + 4) as *mut u32) = cb;
        *((psa + 8) as *mut u32) = 0; // cLocks
        *((psa + 16) as *mut u64) = pv_data;
        *((psa + 24) as *mut u32) = count;
        *((psa + 28) as *mut i32) = lbound;
    }
    psa
}

extern "win64" fn SafeArrayDestroy(psa: u64) -> u32 {
    if psa == 0 {
        return S_OK;
    }
    let (dims, feat, cb, locks, pv_data, count) = unsafe {
        (
            *(psa as *const u16),
            *((psa + 2) as *const u16),
            *((psa + 4) as *const u32),
            *((psa + 8) as *const u32),
            *((psa + 16) as *const u64),
            *((psa + 24) as *const u32),
        )
    };
    if locks != 0 {
        return DISP_E_ARRAYISLOCKED;
    }
    if dims == 1 && pv_data != 0 {
        for i in 0..count as u64 {
            let elem = pv_data + i * cb as u64;
            if feat & FADF_BSTR != 0 {
                SysFreeString(unsafe { *(elem as *const u64) });
            } else if feat & (FADF_UNKNOWN | FADF_DISPATCH) != 0 {
                let p = unsafe { *(elem as *const u64) };
                if p != 0 {
                    error_ref(p, 2);
                }
            } else if feat & FADF_VARIANT != 0 {
                VariantClear(elem as *mut u8);
            }
        }
    }
    kernel32::heap_free(psa - 16);
    S_OK
}

extern "win64" fn SafeArrayAccessData(psa: u64, out: *mut u64) -> u32 {
    if psa == 0 || out.is_null() {
        return E_INVALIDARG;
    }
    unsafe {
        let locks = *((psa + 8) as *const u32);
        if locks >= 0xffff {
            return E_UNEXPECTED;
        }
        *((psa + 8) as *mut u32) = locks + 1;
        *out = *((psa + 16) as *const u64);
    }
    S_OK
}

extern "win64" fn SafeArrayUnaccessData(psa: u64) -> u32 {
    if psa == 0 {
        return E_INVALIDARG;
    }
    unsafe {
        let locks = *((psa + 8) as *const u32);
        if locks == 0 {
            return E_UNEXPECTED;
        }
        *((psa + 8) as *mut u32) = locks - 1;
    }
    S_OK
}

extern "win64" fn SafeArrayPutElement(psa: u64, indices: *const i32, pv: *const u8) -> u32 {
    if psa == 0 || indices.is_null() {
        return E_INVALIDARG;
    }
    let (dims, feat, cb, pv_data, count, lbound) = unsafe {
        (
            *(psa as *const u16),
            *((psa + 2) as *const u16),
            *((psa + 4) as *const u32),
            *((psa + 16) as *const u64),
            *((psa + 24) as *const u32),
            *((psa + 28) as *const i32),
        )
    };
    if dims != 1 || pv_data == 0 {
        return DISP_E_BADINDEX;
    }
    let idx = (unsafe { *indices }).wrapping_sub(lbound) as u32;
    if idx >= count {
        return DISP_E_BADINDEX;
    }
    let elem = pv_data + idx as u64 * cb as u64;
    if feat & FADF_BSTR != 0 {
        let copy = if pv.is_null() {
            0
        } else {
            let b = pv as u64;
            let s = SysAllocStringByteLen(b as *const u8, SysStringByteLen(b));
            if s == 0 {
                return E_OUTOFMEMORY;
            }
            s
        };
        unsafe {
            SysFreeString(*(elem as *const u64));
            *(elem as *mut u64) = copy;
        }
        S_OK
    } else if feat & (FADF_UNKNOWN | FADF_DISPATCH) != 0 {
        let p = pv as u64;
        if p != 0 {
            error_ref(p, 1);
        }
        unsafe {
            let old = *(elem as *const u64);
            if old != 0 {
                error_ref(old, 2);
            }
            *(elem as *mut u64) = p;
        }
        S_OK
    } else if feat & FADF_VARIANT != 0 {
        if pv.is_null() {
            return E_INVALIDARG;
        }
        VariantCopy(elem as *mut u8, pv)
    } else {
        if pv.is_null() {
            return E_INVALIDARG;
        }
        unsafe { core::ptr::copy_nonoverlapping(pv, elem as *mut u8, cb as usize) };
        S_OK
    }
}

extern "win64" fn SafeArrayGetElement(psa: u64, indices: *const i32, pv: *mut u8) -> u32 {
    if psa == 0 || indices.is_null() || pv.is_null() {
        return E_INVALIDARG;
    }
    let (dims, feat, cb, pv_data, count, lbound) = unsafe {
        (
            *(psa as *const u16),
            *((psa + 2) as *const u16),
            *((psa + 4) as *const u32),
            *((psa + 16) as *const u64),
            *((psa + 24) as *const u32),
            *((psa + 28) as *const i32),
        )
    };
    if dims != 1 || pv_data == 0 {
        return DISP_E_BADINDEX;
    }
    let idx = (unsafe { *indices }).wrapping_sub(lbound) as u32;
    if idx >= count {
        return DISP_E_BADINDEX;
    }
    let elem = pv_data + idx as u64 * cb as u64;
    if feat & FADF_BSTR != 0 {
        let src = unsafe { *(elem as *const u64) };
        let copy = if src == 0 { 0 } else { copy_bstr(src) };
        if src != 0 && copy == 0 {
            return E_OUTOFMEMORY;
        }
        unsafe { *(pv as *mut u64) = copy };
        S_OK
    } else if feat & (FADF_UNKNOWN | FADF_DISPATCH) != 0 {
        let p = unsafe { *(elem as *const u64) };
        if p != 0 {
            error_ref(p, 1);
        }
        unsafe { *(pv as *mut u64) = p };
        S_OK
    } else if feat & FADF_VARIANT != 0 {
        VariantInit(pv);
        VariantCopy(pv, elem as *const u8)
    } else {
        unsafe { core::ptr::copy_nonoverlapping(elem as *const u8, pv, cb as usize) };
        S_OK
    }
}

extern "win64" fn SafeArrayGetLBound(psa: u64, dim: u32, out: *mut i32) -> u32 {
    if psa == 0 || out.is_null() {
        return E_INVALIDARG;
    }
    let dims = unsafe { *(psa as *const u16) } as u32;
    if dim == 0 || dim > dims {
        return DISP_E_BADINDEX;
    }
    unsafe { *out = *((psa + 28) as *const i32) };
    S_OK
}

extern "win64" fn SafeArrayGetUBound(psa: u64, dim: u32, out: *mut i32) -> u32 {
    if psa == 0 || out.is_null() {
        return E_INVALIDARG;
    }
    let dims = unsafe { *(psa as *const u16) } as u32;
    if dim == 0 || dim > dims {
        return DISP_E_BADINDEX;
    }
    let (count, lbound) = unsafe { (*((psa + 24) as *const u32), *((psa + 28) as *const i32)) };
    unsafe { *out = lbound.wrapping_add(count as i32).wrapping_sub(1) };
    S_OK
}

extern "win64" fn SafeArrayGetVartype(psa: u64, out: *mut u16) -> u32 {
    if psa == 0 || out.is_null() {
        return E_INVALIDARG;
    }
    let feat = unsafe { *((psa + 2) as *const u16) };
    if feat & FADF_HAVEVARTYPE == 0 {
        return E_INVALIDARG;
    }
    unsafe { *out = *((psa - 4) as *const u32) as u16 };
    S_OK
}

extern "win64" fn DispGetIDsOfNames(ptinfo: u64, names: *const u64, count: u32, dispids: *mut i32) -> u32 {
    if ptinfo == 0 || (count > 0 && (names.is_null() || dispids.is_null())) {
        return E_INVALIDARG;
    }
    // SAFETY: ITypeInfo::GetIDsOfNames is vtable slot 10.
    unsafe {
        let vtbl = *(ptinfo as *const *const u64);
        let f: extern "win64" fn(u64, *const u64, u32, *mut i32) -> u32 = core::mem::transmute(*vtbl.add(10));
        f(ptinfo, names, count, dispids)
    }
}

extern "win64" fn LoadRegTypeLib(_rguid: *const u8, _ver_major: u16, _ver_minor: u16, _lcid: u32, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    unsafe { *out = 0 };
    TYPE_E_LIBNOTREGISTERED
}

extern "win64" fn CreateStdDispatch(_outer: u64, pv_this: u64, ptinfo: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    unsafe { *out = 0 };
    if pv_this == 0 || ptinfo == 0 {
        return E_INVALIDARG;
    }
    E_NOTIMPL
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn OleCreatePropertyFrame(
    _hwnd_owner: u64,
    _x: u32,
    _y: u32,
    _caption: *const u16,
    _objects: u32,
    _unk: *const u64,
    _pages: u32,
    _clsids: *const u8,
    _lcid: u32,
    _reserved: u32,
    _pv_reserved: u64,
) -> u32 {
    E_NOTIMPL
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        SysAllocString,
        SysReAllocString,
        SysAllocStringLen,
        SysReAllocStringLen,
        SysAllocStringByteLen,
        SysFreeString,
        SysStringLen,
        SysStringByteLen,
        SetOaNoCache,
        VariantInit,
        VariantClear,
        VariantCopy,
        GetErrorInfo,
        SetErrorInfo,
        SafeArrayCreateVector,
        SafeArrayDestroy,
        SafeArrayAccessData,
        SafeArrayUnaccessData,
        SafeArrayPutElement,
        SafeArrayGetElement,
        SafeArrayGetLBound,
        SafeArrayGetUBound,
        SafeArrayGetVartype,
        DispGetIDsOfNames,
        LoadRegTypeLib,
        CreateStdDispatch,
        OleCreatePropertyFrame,
    ]
}

/// The ordinals programs import these by.
pub fn ordinals() -> Vec<(u16, u64)> {
    let f = |p: *const ()| p as usize as u64;
    alloc::vec![
        (2, f(SysAllocString as *const ())),
        (3, f(SysReAllocString as *const ())),
        (4, f(SysAllocStringLen as *const ())),
        (5, f(SysReAllocStringLen as *const ())),
        (6, f(SysFreeString as *const ())),
        (7, f(SysStringLen as *const ())),
        (8, f(VariantInit as *const ())),
        (9, f(VariantClear as *const ())),
        (10, f(VariantCopy as *const ())),
        (16, f(SafeArrayDestroy as *const ())),
        (19, f(SafeArrayGetUBound as *const ())),
        (20, f(SafeArrayGetLBound as *const ())),
        (23, f(SafeArrayAccessData as *const ())),
        (24, f(SafeArrayUnaccessData as *const ())),
        (25, f(SafeArrayGetElement as *const ())),
        (26, f(SafeArrayPutElement as *const ())),
        (29, f(DispGetIDsOfNames as *const ())),
        (32, f(CreateStdDispatch as *const ())),
        (77, f(SafeArrayGetVartype as *const ())),
        (162, f(LoadRegTypeLib as *const ())),
        (411, f(SafeArrayCreateVector as *const ())),
        (417, f(OleCreatePropertyFrame as *const ())),
        (149, f(SysStringByteLen as *const ())),
        (150, f(SysAllocStringByteLen as *const ())),
        (200, f(GetErrorInfo as *const ())),
        (201, f(SetErrorInfo as *const ())),
        (327, f(SetOaNoCache as *const ())),
    ]
}
