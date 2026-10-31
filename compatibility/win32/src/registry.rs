//! The Windows registry as persistent hives on the OSyx file system:
//! HKEY_LOCAL_MACHINE in /etc/osyx/registry/machine.reg and
//! HKEY_CURRENT_USER in $HOME/.osyx-registry/user.reg (each written whole
//! to a temporary file and renamed over the old one). HKEY_CLASSES_ROOT is
//! HKLM\Software\Classes. Volatile keys live in memory only. Writing a
//! hive the user cannot write fails with that file system error. Other
//! predefined keys and remote registries are not supported.
#![allow(non_snake_case)]
use crate::{error::*, path};
use alloc::{
    collections::BTreeMap,
    format,
    string::String,
    vec::Vec,
};
use os_std::sync::Mutex;

const HKEY_CLASSES_ROOT: u64 = 0x8000_0000;
const HKEY_CURRENT_USER: u64 = 0x8000_0001;
const HKEY_LOCAL_MACHINE: u64 = 0x8000_0002;

const KEY_QUERY_VALUE: u32 = 0x1;
const KEY_SET_VALUE: u32 = 0x2;
const KEY_CREATE_SUB_KEY: u32 = 0x4;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const REG_OPTION_VOLATILE: u32 = 1;
const REG_CREATED_NEW_KEY: u32 = 1;
const REG_OPENED_EXISTING_KEY: u32 = 2;

const REG_NONE: u32 = 0;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_DWORD_BIG_ENDIAN: u32 = 5;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

const ERROR_MORE_DATA: u32 = 234;
const ERROR_UNSUPPORTED_TYPE: u32 = 1630;
const ERROR_KEY_DELETED: u32 = 1018;
const ERROR_CHILD_MUST_BE_VOLATILE: u32 = 1021;
const ERROR_NO_MORE_ITEMS: u32 = 259;

const REG_NOTIFY_CHANGE_NAME: u32 = 0x1;
const REG_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x2;
const REG_NOTIFY_CHANGE_LAST_SET: u32 = 0x4;
const REG_NOTIFY_CHANGE_SECURITY: u32 = 0x8;
const REG_NOTIFY_THREAD_AGNOSTIC: u32 = 0x1000_0000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Hive {
    Machine,
    User,
}

#[derive(Clone)]
struct Value {
    name: String,
    kind: u32,
    data: Vec<u8>,
}

#[derive(Clone, Default)]
struct Key {
    /// Path with its original case ("Software\Mozilla").
    name: String,
    volatile: bool,
    /// By lower-case name.
    values: BTreeMap<String, Value>,
}

#[derive(Default)]
struct HiveData {
    loaded: bool,
    /// By lower-case path; "" is the hive root.
    keys: BTreeMap<String, Key>,
}

struct Handle {
    hive: Hive,
    path: String,
    access: u32,
}

/// A RegNotifyChangeKeyValue request: signals `event` once, on the first
/// matching change made through this process's registry.
struct Watch {
    hive: Hive,
    /// Lower-case path of the watched key.
    path: String,
    subtree: bool,
    filter: u32,
    event: u64,
}

struct Registry {
    hives: [HiveData; 2],
    handles: BTreeMap<u64, Handle>,
    next: u64,
    watches: Vec<Watch>,
}

static REG: Mutex<Registry> = Mutex::new(Registry {
    hives: [HiveData { loaded: false, keys: BTreeMap::new() }, HiveData { loaded: false, keys: BTreeMap::new() }],
    handles: BTreeMap::new(),
    next: 0x7000_0000,
    watches: Vec::new(),
});

/// Signals the watches a change of `kind` (REG_NOTIFY_CHANGE_*) to key
/// `path` concerns: watches of the key itself, and subtree watches of its
/// ancestors. A name change (a key added, removed or renamed) is also a
/// change of the parent key.
fn changed(r: &mut Registry, hive: Hive, path: &str, kind: u32) {
    let lower = path.to_lowercase();
    let parent = lower.rsplit_once('\\').map_or(String::new(), |(p, _)| String::from(p));
    let hit = |w: &Watch| {
        if w.hive != hive || w.filter & kind == 0 {
            return false;
        }
        let under = w.path.is_empty() || lower == w.path || lower.starts_with(&format!("{}\\", w.path));
        lower == w.path || (kind == REG_NOTIFY_CHANGE_NAME && parent == w.path) || (w.subtree && under)
    };
    let (fire, keep): (Vec<Watch>, Vec<Watch>) = core::mem::take(&mut r.watches).into_iter().partition(|w| hit(w));
    r.watches = keep;
    for w in fire {
        crate::kernel32::set_event(w.event);
    }
}

fn hive_file(h: Hive) -> (String, String) {
    match h {
        Hive::Machine => (String::from("/etc/osyx/registry"), String::from("/etc/osyx/registry/machine.reg")),
        Hive::User => {
            let home = os_std::env::var("HOME").unwrap_or_else(|_| String::from("/home/user"));
            let dir = format!("{}/.osyx-registry", home.trim_end_matches('/'));
            let file = format!("{dir}/user.reg");
            (dir, file)
        }
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Text format, one record per line, fields separated by tabs and the
/// names hex-encoded UTF-8: `K <path>` or `V <path> <name> <type> <data>`.
fn load(h: Hive, d: &mut HiveData) {
    if d.loaded {
        return;
    }
    d.loaded = true;
    d.keys.insert(String::new(), Key::default());
    let (_, file) = hive_file(h);
    let Ok(bytes) = os_std::fs::read(&file) else { return };
    let text = String::from_utf8_lossy(&bytes);
    let decode = |s: &str| unhex(s).and_then(|b| String::from_utf8(b).ok());
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["K", p] => {
                if let Some(p) = decode(p) {
                    d.keys.entry(p.to_lowercase()).or_insert(Key { name: p, ..Key::default() });
                }
            }
            ["V", p, n, t, data] => {
                if let (Some(p), Some(n), Ok(t), Some(data)) = (decode(p), decode(n), t.parse(), unhex(data)) {
                    let key = d.keys.entry(p.to_lowercase()).or_insert(Key { name: p, ..Key::default() });
                    key.values.insert(n.to_lowercase(), Value { name: n, kind: t, data });
                }
            }
            _ => {}
        }
    }
}

fn save(h: Hive, d: &HiveData) -> Result<(), u32> {
    let mut text = String::new();
    for k in d.keys.values().filter(|k| !k.volatile) {
        text.push_str(&format!("K\t{}\n", hex(k.name.as_bytes())));
        for v in k.values.values() {
            text.push_str(&format!("V\t{}\t{}\t{}\t{}\n", hex(k.name.as_bytes()), hex(v.name.as_bytes()), v.kind, hex(&v.data)));
        }
    }
    let (dir, file) = hive_file(h);
    if os_sys::stat(&dir).is_err() {
        os_sys::mkdir(&dir, 0o755).map_err(errno_to_win32)?;
    }
    let tmp = format!("{file}.{}.tmp", crate::kernel32::pid());
    let fd = os_sys::open(&tmp, osyx_abi::OPEN_WRITE | osyx_abi::OPEN_CREATE | osyx_abi::OPEN_TRUNCATE, 0o644).map_err(errno_to_win32)?;
    let mut done = 0;
    let mut result = Ok(());
    while done < text.len() {
        match os_sys::write_raw(fd, text.as_ptr() as usize + done, text.len() - done) {
            Ok(n) if n > 0 => done += n,
            Ok(_) => break,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    let result = result.and_then(|()| os_sys::fsync(fd));
    let _ = os_sys::close(fd);
    if let Err(e) = result {
        let _ = os_sys::unlink(&tmp);
        return Err(errno_to_win32(e));
    }
    os_sys::rename(&tmp, &file).map_err(|e| {
        let _ = os_sys::unlink(&tmp);
        errno_to_win32(e)
    })
}

fn root(hkey: u64) -> Option<(Hive, String)> {
    // winreg.h defines them as (HKEY)(ULONG_PTR)(LONG)0x8000000x: sign-extended.
    if hkey >> 32 != 0xffff_ffff {
        return None;
    }
    match hkey & 0xffff_ffff {
        HKEY_LOCAL_MACHINE => Some((Hive::Machine, String::new())),
        HKEY_CURRENT_USER => Some((Hive::User, String::new())),
        HKEY_CLASSES_ROOT => Some((Hive::Machine, String::from("Software\\Classes"))),
        _ => None,
    }
}

/// Grants for a requested SAM: generic rights mapped, MAXIMUM_ALLOWED as all.
fn grant(sam: u32) -> u32 {
    let mut a = sam & 0xffff;
    if sam & (GENERIC_READ | GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        a |= 0x19;
    }
    if sam & (GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        a |= 0x6;
    }
    a
}

fn join(base: &str, sub: &str) -> Result<String, u32> {
    let sub = sub.trim_matches('\\');
    if sub.split('\\').any(|c| c.is_empty() && !sub.is_empty()) || sub.len() > 255 * 32 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    Ok(match (base.is_empty(), sub.is_empty()) {
        (_, true) => String::from(base),
        (true, false) => String::from(sub),
        (false, false) => format!("{base}\\{sub}"),
    })
}

/// (hive, path, access) of an open or predefined key.
fn resolve(r: &mut Registry, hkey: u64) -> Result<(Hive, String, u32), u32> {
    if let Some((h, p)) = root(hkey) {
        load(h, &mut r.hives[h as usize]);
        return Ok((h, p, 0xf003f));
    }
    let k = r.handles.get(&hkey).ok_or(ERROR_INVALID_HANDLE)?;
    let (h, p, a) = (k.hive, k.path.clone(), k.access);
    if !r.hives[h as usize].keys.contains_key(&p.to_lowercase()) {
        return Err(ERROR_KEY_DELETED);
    }
    Ok((h, p, a))
}

fn new_handle(r: &mut Registry, hive: Hive, path: String, access: u32) -> u64 {
    let h = r.next;
    r.next += 4;
    r.handles.insert(h, Handle { hive, path, access });
    h
}

/// # Safety
/// `p` is NULL or a NUL-terminated UTF-16 string.
unsafe fn ws(p: *const u16) -> String {
    // SAFETY: the caller's guarantee.
    unsafe { path::wide_to_string(p) }.unwrap_or_default()
}

extern "win64" fn RegOpenKeyExW(hkey: u64, sub: *const u16, options: u32, sam: u32, out: *mut u64) -> u32 {
    if out.is_null() || options & !0x8 != 0 {
        return ERROR_INVALID_PARAMETER;
    }
    let mut r = REG.lock().unwrap();
    let (hive, base, _) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // SAFETY: the caller's string.
    let path = match join(&base, &unsafe { ws(sub) }) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if !r.hives[hive as usize].keys.contains_key(&path.to_lowercase()) {
        return ERROR_FILE_NOT_FOUND;
    }
    let h = new_handle(&mut r, hive, path, grant(sam));
    // SAFETY: the caller's out pointer.
    unsafe { *out = h };
    ERROR_SUCCESS
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn RegCreateKeyExW(
    hkey: u64,
    sub: *const u16,
    _reserved: u32,
    _class: *const u16,
    options: u32,
    sam: u32,
    attributes: u64,
    out: *mut u64,
    disposition: *mut u32,
) -> u32 {
    if out.is_null() || options & !REG_OPTION_VOLATILE != 0 {
        return if options & 0x2 != 0 { ERROR_NOT_SUPPORTED } else { ERROR_INVALID_PARAMETER }; // CREATE_LINK
    }
    if let Err(e) = crate::security::validate_attributes(attributes) {
        return e;
    }
    let mut r = REG.lock().unwrap();
    let (hive, base, access) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // SAFETY: the caller's string.
    let path = match join(&base, &unsafe { ws(sub) }) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let d = &mut r.hives[hive as usize];
    let existed = d.keys.contains_key(&path.to_lowercase());
    if !existed {
        if access & KEY_CREATE_SUB_KEY == 0 {
            return ERROR_ACCESS_DENIED;
        }
        let volatile = options & REG_OPTION_VOLATILE != 0;
        // Create every missing ancestor; a stable key cannot live under a volatile one.
        let mut prefix = String::new();
        for part in path.split('\\') {
            prefix = if prefix.is_empty() { String::from(part) } else { format!("{prefix}\\{part}") };
            let lower = prefix.to_lowercase();
            match d.keys.get(&lower) {
                Some(k) if k.volatile && !volatile => return ERROR_CHILD_MUST_BE_VOLATILE,
                Some(_) => {}
                None => {
                    d.keys.insert(lower, Key { name: prefix.clone(), volatile, values: BTreeMap::new() });
                }
            }
        }
        if !volatile {
            if let Err(e) = save(hive, d) {
                // Undo: the hive on disk did not change.
                d.loaded = false;
                d.keys.clear();
                return e;
            }
        }
        changed(&mut r, hive, &path, REG_NOTIFY_CHANGE_NAME);
    }
    let h = new_handle(&mut r, hive, path, grant(sam));
    // SAFETY: the caller's out pointers.
    unsafe {
        *out = h;
        if !disposition.is_null() {
            *disposition = if existed { REG_OPENED_EXISTING_KEY } else { REG_CREATED_NEW_KEY };
        }
    }
    ERROR_SUCCESS
}

extern "win64" fn RegCloseKey(hkey: u64) -> u32 {
    if root(hkey).is_some() {
        return ERROR_SUCCESS;
    }
    if REG.lock().unwrap().handles.remove(&hkey).is_some() { ERROR_SUCCESS } else { ERROR_INVALID_HANDLE }
}

fn get_value(hkey: u64, sub: Option<String>, name: &str, need: u32) -> Result<Value, u32> {
    let mut r = REG.lock().unwrap();
    let (hive, base, access) = resolve(&mut r, hkey)?;
    if access & need == 0 && sub.is_none() {
        return Err(ERROR_ACCESS_DENIED);
    }
    let path = join(&base, sub.as_deref().unwrap_or(""))?;
    let key = r.hives[hive as usize].keys.get(&path.to_lowercase()).ok_or(ERROR_FILE_NOT_FOUND)?;
    key.values.get(&name.to_lowercase()).cloned().ok_or(ERROR_FILE_NOT_FOUND)
}

/// The string values (REG_SZ) of HKLM\`path`, as (name, text) pairs.
pub(crate) fn machine_strings(path: &str) -> Vec<(String, String)> {
    let mut r = REG.lock().unwrap();
    let d = &mut r.hives[Hive::Machine as usize];
    load(Hive::Machine, d);
    d.keys.get(&path.to_lowercase()).map_or_else(Vec::new, |k| {
        k.values.values().filter(|v| v.kind == 1).map(|v| (v.name.clone(), utf16_string(&v.data))).collect()
    })
}

/// Copies `data` out like RegQueryValueEx: size query, ERROR_MORE_DATA.
fn copy_out(data: &[u8], buf: *mut u8, size: *mut u32) -> u32 {
    if size.is_null() {
        return if buf.is_null() { ERROR_SUCCESS } else { ERROR_INVALID_PARAMETER };
    }
    // SAFETY: the caller's in/out size and buffer of that size.
    unsafe {
        let have = *size as usize;
        *size = data.len() as u32;
        if buf.is_null() {
            return ERROR_SUCCESS;
        }
        if have < data.len() {
            return ERROR_MORE_DATA;
        }
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
    }
    ERROR_SUCCESS
}

extern "win64" fn RegQueryValueExW(hkey: u64, name: *const u16, reserved: *const u32, kind: *mut u32, buf: *mut u8, size: *mut u32) -> u32 {
    if !reserved.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the caller's string.
    let v = match get_value(hkey, None, &unsafe { ws(name) }, KEY_QUERY_VALUE) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !kind.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *kind = v.kind };
    }
    copy_out(&v.data, buf, size)
}

const RRF_RT_REG_NONE: u32 = 0x1;
const RRF_RT_REG_SZ: u32 = 0x2;
const RRF_RT_REG_EXPAND_SZ: u32 = 0x4;
const RRF_RT_REG_BINARY: u32 = 0x8;
const RRF_RT_REG_DWORD: u32 = 0x10;
const RRF_RT_REG_MULTI_SZ: u32 = 0x20;
const RRF_RT_REG_QWORD: u32 = 0x40;
const RRF_NOEXPAND: u32 = 0x1000_0000;
const RRF_ZEROONFAILURE: u32 = 0x2000_0000;

/// Expands %NAME% references from the program's environment (unknown ones stay).
pub(crate) fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) => {
                let name = &after[..j];
                match crate::kernel32::env_get(name).filter(|_| !name.is_empty()) {
                    Some(v) => out.push_str(&v),
                    None => out.push_str(&rest[i..i + j + 2]),
                }
                rest = &after[j + 1..];
            }
            None => {
                out.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn utf16_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().chain(core::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect()
}

fn utf16_string(data: &[u8]) -> String {
    let units: Vec<u16> = data.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn RegGetValueW(hkey: u64, sub: *const u16, name: *const u16, flags: u32, kind: *mut u32, buf: *mut u8, size: *mut u32) -> u32 {
    let types = flags & 0xffff;
    if types == 0 || (types == RRF_RT_REG_EXPAND_SZ && flags & RRF_NOEXPAND == 0) || (!buf.is_null() && size.is_null()) {
        return ERROR_INVALID_PARAMETER;
    }
    let zero = |r: u32| {
        if r != ERROR_SUCCESS && r != ERROR_MORE_DATA && flags & RRF_ZEROONFAILURE != 0 && !buf.is_null() && !size.is_null() {
            // SAFETY: the caller's buffer of *size bytes.
            unsafe { core::ptr::write_bytes(buf, 0, *size as usize) };
        }
        r
    };
    // SAFETY: the caller's strings.
    let (sub, name) = unsafe { (path::wide_to_string(sub).filter(|s| !s.is_empty()), ws(name)) };
    let v = match get_value(hkey, sub, &name, KEY_QUERY_VALUE) {
        Ok(v) => v,
        Err(e) => return zero(e),
    };
    let (mut kind_out, mut data) = (v.kind, v.data);
    if kind_out == REG_EXPAND_SZ && flags & RRF_NOEXPAND == 0 {
        data = utf16_bytes(&expand_env(&utf16_string(&data)));
        kind_out = REG_SZ;
    }
    let bit = match kind_out {
        REG_NONE => RRF_RT_REG_NONE,
        REG_SZ => RRF_RT_REG_SZ,
        REG_EXPAND_SZ => RRF_RT_REG_EXPAND_SZ,
        REG_BINARY => RRF_RT_REG_BINARY,
        REG_DWORD if data.len() == 4 => RRF_RT_REG_DWORD,
        REG_MULTI_SZ => RRF_RT_REG_MULTI_SZ,
        REG_QWORD if data.len() == 8 => RRF_RT_REG_QWORD,
        _ => 0,
    };
    if bit & types == 0 && !(kind_out == REG_BINARY && ((types & RRF_RT_REG_DWORD != 0 && data.len() == 4) || (types & RRF_RT_REG_QWORD != 0 && data.len() == 8))) {
        return zero(ERROR_UNSUPPORTED_TYPE);
    }
    // Strings come back NUL-terminated even when stored without one.
    if matches!(kind_out, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ) && (data.len() < 2 || data[data.len() - 2..] != [0, 0]) {
        data.extend_from_slice(&[0, 0]);
    }
    if !kind.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *kind = kind_out };
    }
    zero(copy_out(&data, buf, size))
}

extern "win64" fn RegSetValueExW(hkey: u64, name: *const u16, _reserved: u32, kind: u32, data: *const u8, size: u32) -> u32 {
    if data.is_null() && size != 0 {
        return ERROR_NOACCESS;
    }
    if (kind == REG_DWORD || kind == REG_DWORD_BIG_ENDIAN) && size != 4 || kind == REG_QWORD && size != 8 {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the caller's string and `size` bytes of data.
    let (name, bytes) = unsafe { (ws(name), if size == 0 { Vec::new() } else { core::slice::from_raw_parts(data, size as usize).to_vec() }) };
    if name.len() > 16383 {
        return ERROR_INVALID_PARAMETER;
    }
    let mut r = REG.lock().unwrap();
    let (hive, path, access) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if access & KEY_SET_VALUE == 0 {
        return ERROR_ACCESS_DENIED;
    }
    let d = &mut r.hives[hive as usize];
    let key = d.keys.get_mut(&path.to_lowercase()).expect("resolved key exists");
    let old = key.values.insert(name.to_lowercase(), Value { name: name.clone(), kind, data: bytes });
    if key.volatile {
        changed(&mut r, hive, &path, REG_NOTIFY_CHANGE_LAST_SET);
        return ERROR_SUCCESS;
    }
    match save(hive, d) {
        Ok(()) => {
            changed(&mut r, hive, &path, REG_NOTIFY_CHANGE_LAST_SET);
            ERROR_SUCCESS
        }
        Err(e) => {
            let key = d.keys.get_mut(&path.to_lowercase()).expect("resolved key exists");
            match old {
                Some(v) => key.values.insert(name.to_lowercase(), v),
                None => key.values.remove(&name.to_lowercase()),
            };
            e
        }
    }
}

extern "win64" fn RegDeleteValueW(hkey: u64, name: *const u16) -> u32 {
    let mut r = REG.lock().unwrap();
    let (hive, path, access) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if access & KEY_SET_VALUE == 0 {
        return ERROR_ACCESS_DENIED;
    }
    // SAFETY: the caller's string.
    let name = unsafe { ws(name) }.to_lowercase();
    let d = &mut r.hives[hive as usize];
    let key = d.keys.get_mut(&path.to_lowercase()).expect("resolved key exists");
    let Some(old) = key.values.remove(&name) else { return ERROR_FILE_NOT_FOUND };
    if key.volatile {
        changed(&mut r, hive, &path, REG_NOTIFY_CHANGE_LAST_SET);
        return ERROR_SUCCESS;
    }
    match save(hive, d) {
        Ok(()) => {
            changed(&mut r, hive, &path, REG_NOTIFY_CHANGE_LAST_SET);
            ERROR_SUCCESS
        }
        Err(e) => {
            d.keys.get_mut(&path.to_lowercase()).expect("resolved key exists").values.insert(name, old);
            e
        }
    }
}

/// Deletes a key without subkeys, as Windows does.
extern "win64" fn RegDeleteKeyW(hkey: u64, sub: *const u16) -> u32 {
    let mut r = REG.lock().unwrap();
    let (hive, base, _) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // SAFETY: the caller's string.
    let sub = unsafe { ws(sub) };
    if sub.is_empty() {
        return ERROR_INVALID_PARAMETER;
    }
    let path = match join(&base, &sub) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let lower = path.to_lowercase();
    let d = &mut r.hives[hive as usize];
    if !d.keys.contains_key(&lower) {
        return ERROR_FILE_NOT_FOUND;
    }
    let child = format!("{lower}\\");
    if d.keys.keys().any(|k| k.starts_with(&child)) {
        return ERROR_ACCESS_DENIED;
    }
    let old = d.keys.remove(&lower).expect("checked");
    if old.volatile {
        changed(&mut r, hive, &path, REG_NOTIFY_CHANGE_NAME);
        return ERROR_SUCCESS;
    }
    match save(hive, d) {
        Ok(()) => {
            changed(&mut r, hive, &path, REG_NOTIFY_CHANGE_NAME);
            ERROR_SUCCESS
        }
        Err(e) => {
            d.keys.insert(lower, old);
            e
        }
    }
}

const ERROR_NOACCESS: u32 = 998;

/// The direct subkeys of `path` (lower-case), in name order.
fn children<'a>(d: &'a HiveData, path: &str) -> Vec<&'a Key> {
    let lower = path.to_lowercase();
    let prefix = if lower.is_empty() { String::new() } else { format!("{lower}\\") };
    d.keys.iter().filter(|(k, _)| !k.is_empty() && k.starts_with(&prefix) && !k[prefix.len()..].contains('\\')).map(|(_, v)| v).collect()
}

fn last_component(name: &str) -> &str {
    name.rsplit('\\').next().unwrap_or(name)
}

/// Copies a name into a WCHAR buffer of `*len` units: on success `*len`
/// is its length without the NUL, else ERROR_MORE_DATA.
fn name_out(s: &str, buf: *mut u16, len: *mut u32) -> u32 {
    if len.is_null() || buf.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let units: Vec<u16> = s.encode_utf16().collect();
    // SAFETY: the caller's in/out length and buffer of that many units.
    unsafe {
        if (*len as usize) <= units.len() {
            return ERROR_MORE_DATA;
        }
        core::ptr::copy_nonoverlapping(units.as_ptr(), buf, units.len());
        *buf.add(units.len()) = 0;
        *len = units.len() as u32;
    }
    ERROR_SUCCESS
}

/// Subkeys in name order. Classes and write times are not kept: the class
/// is empty and the time is zero.
#[allow(clippy::too_many_arguments)]
extern "win64" fn RegEnumKeyExW(
    hkey: u64,
    index: u32,
    name: *mut u16,
    name_len: *mut u32,
    reserved: *const u32,
    class: *mut u16,
    class_len: *mut u32,
    written: *mut u64,
) -> u32 {
    if !reserved.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let mut r = REG.lock().unwrap();
    let (hive, path, access) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if access & 0x8 == 0 {
        return ERROR_ACCESS_DENIED; // KEY_ENUMERATE_SUB_KEYS
    }
    let kids = children(&r.hives[hive as usize], &path);
    let Some(k) = kids.get(index as usize) else { return ERROR_NO_MORE_ITEMS };
    let e = name_out(last_component(&k.name), name, name_len);
    if e != ERROR_SUCCESS {
        return e;
    }
    // SAFETY: the caller's optional out pointers.
    unsafe {
        if !class.is_null() && !class_len.is_null() && *class_len > 0 {
            *class = 0;
            *class_len = 0;
        }
        if !written.is_null() {
            *written = 0;
        }
    }
    ERROR_SUCCESS
}

extern "win64" fn RegEnumKeyW(hkey: u64, index: u32, name: *mut u16, mut name_len: u32) -> u32 {
    RegEnumKeyExW(hkey, index, name, &mut name_len, core::ptr::null(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut())
}

/// Values in name order (Windows keeps insertion order; neither is
/// documented).
#[allow(clippy::too_many_arguments)]
extern "win64" fn RegEnumValueW(
    hkey: u64,
    index: u32,
    name: *mut u16,
    name_len: *mut u32,
    reserved: *const u32,
    kind: *mut u32,
    data: *mut u8,
    data_len: *mut u32,
) -> u32 {
    if !reserved.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let mut r = REG.lock().unwrap();
    let (hive, path, access) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if access & KEY_QUERY_VALUE == 0 {
        return ERROR_ACCESS_DENIED;
    }
    let key = r.hives[hive as usize].keys.get(&path.to_lowercase()).expect("resolved key exists");
    let Some(v) = key.values.values().nth(index as usize).cloned() else { return ERROR_NO_MORE_ITEMS };
    drop(r);
    let e = name_out(&v.name, name, name_len);
    if e != ERROR_SUCCESS {
        return e;
    }
    if !kind.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *kind = v.kind };
    }
    copy_out(&v.data, data, data_len)
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn RegQueryInfoKeyW(
    hkey: u64,
    class: *mut u16,
    class_len: *mut u32,
    reserved: *const u32,
    subkeys: *mut u32,
    max_subkey: *mut u32,
    max_class: *mut u32,
    values: *mut u32,
    max_value_name: *mut u32,
    max_value: *mut u32,
    security: *mut u32,
    written: *mut u64,
) -> u32 {
    if !reserved.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let mut r = REG.lock().unwrap();
    let (hive, path, _) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let d = &r.hives[hive as usize];
    let kids = children(d, &path);
    let key = d.keys.get(&path.to_lowercase()).expect("resolved key exists");
    let put = |p: *mut u32, v: usize| {
        if !p.is_null() {
            // SAFETY: the caller's out pointer.
            unsafe { *p = v as u32 };
        }
    };
    if !class.is_null() && !class_len.is_null() {
        // SAFETY: as above; the class is empty.
        unsafe {
            if *class_len > 0 {
                *class = 0;
            }
        }
    }
    put(class_len, 0);
    put(subkeys, kids.len());
    put(max_subkey, kids.iter().map(|k| last_component(&k.name).encode_utf16().count()).max().unwrap_or(0));
    put(max_class, 0);
    put(values, key.values.len());
    put(max_value_name, key.values.values().map(|v| v.name.encode_utf16().count()).max().unwrap_or(0));
    put(max_value, key.values.values().map(|v| v.data.len()).max().unwrap_or(0));
    put(security, 0);
    if !written.is_null() {
        // SAFETY: the caller's FILETIME.
        unsafe { *written = 0 };
    }
    ERROR_SUCCESS
}

/// Deletes `sub` and everything below it; with no `sub`, the subkeys and
/// values of the key itself (which stays).
extern "win64" fn RegDeleteTreeW(hkey: u64, sub: *const u16) -> u32 {
    let mut r = REG.lock().unwrap();
    let (hive, base, access) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // SAFETY: the caller's string.
    let sub = unsafe { ws(sub) };
    let path = match join(&base, &sub) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let lower = path.to_lowercase();
    let d = &mut r.hives[hive as usize];
    if !d.keys.contains_key(&lower) {
        return ERROR_FILE_NOT_FOUND;
    }
    if sub.is_empty() && access & KEY_SET_VALUE == 0 {
        return ERROR_ACCESS_DENIED;
    }
    let before = d.keys.clone();
    let prefix = format!("{lower}\\");
    d.keys.retain(|k, _| !(k.starts_with(&prefix) || (!sub.is_empty() && *k == lower) || (lower.is_empty() && !k.is_empty())));
    if sub.is_empty() {
        if let Some(k) = d.keys.get_mut(&lower) {
            k.values.clear();
        }
    }
    if let Err(e) = save(hive, d) {
        d.keys = before;
        return e;
    }
    changed(&mut r, hive, &path, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET);
    ERROR_SUCCESS
}

/// Opens `sub` of `hkey` for a single value operation.
fn sub_key(hkey: u64, sub: *const u16, sam: u32, create: bool) -> Result<(u64, bool), u32> {
    // SAFETY: the caller's string.
    if unsafe { path::wide_to_string(sub) }.is_none_or(|s| s.is_empty()) {
        return Ok((hkey, false));
    }
    let mut h = 0u64;
    let e = if create {
        RegCreateKeyExW(hkey, sub, 0, core::ptr::null(), 0, sam, 0, &mut h, core::ptr::null_mut())
    } else {
        RegOpenKeyExW(hkey, sub, 0, sam, &mut h)
    };
    if e != ERROR_SUCCESS {
        return Err(e);
    }
    Ok((h, true))
}

extern "win64" fn RegDeleteKeyValueW(hkey: u64, sub: *const u16, name: *const u16) -> u32 {
    let (h, opened) = match sub_key(hkey, sub, KEY_SET_VALUE, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let e = RegDeleteValueW(h, name);
    if opened {
        RegCloseKey(h);
    }
    e
}

/// Creates `sub` when it does not exist, as Windows does.
extern "win64" fn RegSetKeyValueW(hkey: u64, sub: *const u16, name: *const u16, kind: u32, data: *const u8, size: u32) -> u32 {
    let (h, opened) = match sub_key(hkey, sub, KEY_SET_VALUE, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let e = RegSetValueExW(h, name, 0, kind, data, size);
    if opened {
        RegCloseKey(h);
    }
    e
}

/// Renames `sub` (or the key itself) and all its descendants.
extern "win64" fn RegRenameKey(hkey: u64, sub: *const u16, new_name: *const u16) -> u32 {
    let mut r = REG.lock().unwrap();
    let (hive, base, _) = match resolve(&mut r, hkey) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // SAFETY: the caller's strings.
    let (sub, new) = unsafe { (ws(sub), ws(new_name)) };
    if new.is_empty() || new.contains('\\') {
        return ERROR_INVALID_PARAMETER;
    }
    let old_path = match join(&base, &sub) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if old_path.is_empty() {
        return ERROR_ACCESS_DENIED; // a hive root
    }
    let new_path = match old_path.rsplit_once('\\') {
        Some((parent, _)) => format!("{parent}\\{new}"),
        None => new.clone(),
    };
    let (old_l, new_l) = (old_path.to_lowercase(), new_path.to_lowercase());
    let d = &mut r.hives[hive as usize];
    if !d.keys.contains_key(&old_l) {
        return ERROR_FILE_NOT_FOUND;
    }
    if d.keys.contains_key(&new_l) {
        return ERROR_ACCESS_DENIED;
    }
    let before = d.keys.clone();
    let moved: Vec<(String, Key)> = d
        .keys
        .iter()
        .filter(|(k, _)| **k == old_l || k.starts_with(&format!("{old_l}\\")))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (k, mut v) in moved {
        d.keys.remove(&k);
        let rest = &v.name[old_path.len()..];
        v.name = format!("{new_path}{rest}");
        d.keys.insert(v.name.to_lowercase(), v);
    }
    if let Err(e) = save(hive, d) {
        d.keys = before;
        return e;
    }
    // Open handles follow the key.
    for h in r.handles.values_mut().filter(|h| h.hive == hive) {
        let l = h.path.to_lowercase();
        if l == old_l || l.starts_with(&format!("{old_l}\\")) {
            h.path = format!("{new_path}{}", &h.path[old_path.len()..]);
        }
    }
    changed(&mut r, hive, &old_path, REG_NOTIFY_CHANGE_NAME);
    ERROR_SUCCESS
}

/// Removes the key a rolled-back transaction created, if it is still there
/// and has no subkeys (children made later by others are theirs).
pub(crate) fn undo_create(hive: usize, path: &str) {
    let mut r = REG.lock().unwrap();
    let Some(d) = r.hives.get_mut(hive) else { return };
    let lower = path.to_lowercase();
    let child = alloc::format!("{lower}\\");
    if d.keys.keys().any(|k| k.starts_with(&child)) {
        return;
    }
    if d.keys.remove(&lower).is_some() {
        let h = if hive == Hive::Machine as usize { Hive::Machine } else { Hive::User };
        let _ = save(h, &r.hives[hive]);
        changed(&mut r, h, path, REG_NOTIFY_CHANGE_NAME);
    }
}

/// RegCreateKeyTransactedW: RegCreateKeyExW whose new keys the transaction
/// remembers, so that a rollback removes them again. The handle must be an
/// active transaction.
#[allow(clippy::too_many_arguments)]
extern "win64" fn RegCreateKeyTransactedW(
    hkey: u64,
    sub: *const u16,
    reserved: u32,
    class: *const u16,
    options: u32,
    sam: u32,
    attributes: u64,
    out: *mut u64,
    disposition: *mut u32,
    transaction: u64,
    extended: u64,
) -> u32 {
    let tx = match crate::ktm::active(transaction) {
        Ok(t) => t,
        Err(e) => return e,
    };
    if extended != 0 {
        return ERROR_INVALID_PARAMETER;
    }
    // The keys on the path that do not exist yet, outermost first.
    let new_keys: Vec<(usize, String)> = {
        let mut r = REG.lock().unwrap();
        match resolve(&mut r, hkey) {
            Ok((hive, base, _)) => {
                // SAFETY: the caller's string.
                let sub_name = unsafe { ws(sub) };
                let mut missing = Vec::new();
                let mut path = base.clone();
                for part in sub_name.split('\\').filter(|p| !p.is_empty()) {
                    path = match join(&path, part) {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    if !r.hives[hive as usize].keys.contains_key(&path.to_lowercase()) {
                        missing.push((hive as usize, path.clone()));
                    }
                }
                missing
            }
            Err(_) => Vec::new(),
        }
    };
    let rc = RegCreateKeyExW(hkey, sub, reserved, class, options, sam, attributes, out, disposition);
    if rc == ERROR_SUCCESS {
        for (hive, path) in new_keys {
            tx.record(crate::ktm::Undo::RegistryKey(hive, path));
        }
    }
    rc
}

/// Changes made by this process signal the event (asynchronous form) or
/// end the wait (synchronous form). Changes another process makes to the
/// hive files are not observed.
extern "win64" fn RegNotifyChangeKeyValue(hkey: u64, subtree: i32, filter: u32, event: u64, asynchronous: i32) -> u32 {
    let all = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY;
    if filter & !(all | REG_NOTIFY_THREAD_AGNOSTIC) != 0 || filter & all == 0 || (asynchronous != 0 && event == 0) {
        return ERROR_INVALID_PARAMETER;
    }
    let wait_on = if asynchronous != 0 { event } else { crate::kernel32::new_event(false, false) };
    {
        let mut r = REG.lock().unwrap();
        let (hive, path, _) = match resolve(&mut r, hkey) {
            Ok(v) => v,
            Err(e) => return e,
        };
        r.watches.push(Watch { hive, path: path.to_lowercase(), subtree: subtree != 0, filter, event: wait_on });
    }
    if asynchronous == 0 {
        let _ = crate::objects::wait(&[wait_on], false, u32::MAX);
        crate::objects::close(wait_on);
    }
    ERROR_SUCCESS
}

/// HKEY_CURRENT_USER is resolved on every use and never cached: a thread
/// can only impersonate a token of the process's own user (tokens.rs), so
/// there is no per-user handle to stop caching.
extern "win64" fn RegDisablePredefinedCache() -> u32 {
    ERROR_SUCCESS
}

extern "win64" fn RegDisablePredefinedCacheEx() -> u32 {
    ERROR_SUCCESS
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        RegOpenKeyExW,
        RegCreateKeyExW,
        RegCloseKey,
        RegQueryValueExW,
        RegGetValueW,
        RegSetValueExW,
        RegDeleteValueW,
        RegDeleteKeyW,
        RegDisablePredefinedCache,
        RegDisablePredefinedCacheEx,
        RegEnumKeyExW,
        RegEnumKeyW,
        RegEnumValueW,
        RegQueryInfoKeyW,
        RegDeleteTreeW,
        RegDeleteKeyValueW,
        RegSetKeyValueW,
        RegRenameKey,
        RegCreateKeyTransactedW,
        RegNotifyChangeKeyValue,
    ]
}
