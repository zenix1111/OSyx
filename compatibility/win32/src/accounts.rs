//! Account and service calls of advapi32. A process's user is its uid,
//! named by $USER ("root" for uid 0), with the SID tokens.rs assigns; the
//! domain of local accounts is the computer's NetBIOS name, as on a
//! stand-alone Windows machine. The accounts are those of /etc/passwd, and
//! LogonUser and LsaLogonUser check passwords against /etc/shadow (see
//! below). There are no Windows services: the service manager opens but
//! knows no service.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{self, fail},
    path, tokens,
};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use os_std::sync::Mutex;

const ERROR_NONE_MAPPED: u32 = 1332;
const ERROR_INVALID_SID: u32 = 1337;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const SID_TYPE_USER: u32 = 1;

fn user_name(uid: u32) -> String {
    if uid == 0 {
        return String::from("root");
    }
    crate::kernel32::env_get("USER").or_else(|| crate::kernel32::env_get("USERNAME")).unwrap_or_else(|| alloc::format!("user{uid}"))
}

/// The user of the calling thread's token, as GetUserNameW reports it.
pub(crate) fn current_user_name() -> String {
    user_name(tokens::effective().uid)
}

/// The computer name, as GetComputerNameW reports it.
pub(crate) fn computer_name() -> String {
    computer()
}

fn computer() -> String {
    let name = os_std::fs::read_to_string("/etc/hostname").map(|s| String::from(s.trim())).unwrap_or_else(|_| String::from("osyx"));
    name.to_uppercase().chars().take(15).collect()
}

/// The user of the calling thread's token, with the NUL in `*len`.
extern "win64" fn GetUserNameW(buf: *mut u16, len: *mut u32) -> i32 {
    if len.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let name: Vec<u16> = user_name(tokens::effective().uid).encode_utf16().chain(core::iter::once(0)).collect();
    // SAFETY: the caller's in/out length and buffer.
    unsafe {
        if buf.is_null() || (*len as usize) < name.len() {
            *len = name.len() as u32;
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        core::ptr::copy_nonoverlapping(name.as_ptr(), buf, name.len());
        *len = name.len() as u32;
    }
    1
}

/// Local names ("name", "COMPUTER\name", ".\name") of the process's user
/// and of root map to their SIDs.
#[allow(clippy::too_many_arguments)]
extern "win64" fn LookupAccountNameW(
    system: *const u16,
    name: *const u16,
    sid: *mut u8,
    sid_len: *mut u32,
    domain: *mut u16,
    domain_len: *mut u32,
    use_: *mut u32,
) -> i32 {
    // SAFETY: NULL or NUL-terminated strings.
    let (sys, n) = unsafe { (path::wide_to_string(system), path::wide_to_string(name)) };
    if sys.is_some_and(|s| !s.is_empty()) {
        return fail(ERROR_NOT_SUPPORTED, 0); // remote systems
    }
    let Some(n) = n else { return fail(ERROR_INVALID_PARAMETER, 0) };
    if sid_len.is_null() || domain_len.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let dom = computer();
    let account = match n.split_once('\\') {
        Some((d, a)) if d == "." || d.eq_ignore_ascii_case(&dom) => a,
        Some(_) => return fail(ERROR_NONE_MAPPED, 0),
        None => &n,
    };
    let me = os_sys::getuid().0;
    let uid = if account.eq_ignore_ascii_case(&user_name(me)) {
        me
    } else if account.eq_ignore_ascii_case("root") {
        0
    } else {
        return fail(ERROR_NONE_MAPPED, 0);
    };
    let s = tokens::user_sid(uid);
    let d: Vec<u16> = dom.encode_utf16().collect();
    // SAFETY: the caller's in/out lengths and buffers.
    unsafe {
        let fits = !sid.is_null() && *sid_len as usize >= s.len() && !domain.is_null() && *domain_len as usize > d.len();
        if !fits {
            *sid_len = s.len() as u32;
            *domain_len = d.len() as u32 + 1;
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        core::ptr::copy_nonoverlapping(s.as_ptr(), sid, s.len());
        core::ptr::copy_nonoverlapping(d.as_ptr(), domain, d.len());
        *domain.add(d.len()) = 0;
        *sid_len = s.len() as u32;
        *domain_len = d.len() as u32;
        if !use_.is_null() {
            *use_ = SID_TYPE_USER;
        }
    }
    1
}

extern "win64" fn ConvertSidToStringSidA(s: *const u8, out: *mut u64) -> i32 {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: NULL or the caller's SID.
    let Ok(v) = (unsafe { crate::security::sid_bytes(s) }) else { return fail(ERROR_INVALID_SID, 0) };
    let text = crate::objsec::sid_string(&v);
    let Some(p) = kernel32::heap_alloc(text.len() + 1, true) else { return fail(ERROR_NOT_ENOUGH_MEMORY, 0) };
    // SAFETY: a fresh zeroed block with room for the NUL.
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), p as *mut u8, text.len());
        *out = p;
    }
    1
}

/// Whether `sid` is an enabled group (or the user) of `token`; token 0 is
/// the calling thread's effective token.
extern "win64" fn CheckTokenMembership(token: u64, sid: *const u8, member: *mut i32) -> i32 {
    if member.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: NULL or the caller's SID.
    let Ok(s) = (unsafe { crate::security::sid_bytes(sid) }) else { return fail(ERROR_INVALID_SID, 0) };
    let t = if token == 0 {
        tokens::effective()
    } else {
        match tokens::token(token) {
            Ok(t) => t,
            Err(e) => return fail(e, 0),
        }
    };
    let data = t.state.data.lock().unwrap().clone();
    let (allow, _) = tokens::access_sids(t.uid, t.gid, &data);
    // SAFETY: the caller's out pointer.
    unsafe { *member = allow.contains(&s) as i32 };
    1
}

/// Whether the calling thread's effective token is in BUILTIN\Administrators
/// (S-1-5-32-544), as `IsUserAnAdmin` asks.
pub(crate) fn is_admin() -> bool {
    const ADMINISTRATORS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0];
    let t = tokens::effective();
    let data = t.state.data.lock().unwrap().clone();
    let (allow, _) = tokens::access_sids(t.uid, t.gid, &data);
    allow.iter().any(|s| s.as_slice() == ADMINISTRATORS)
}

/// Locally unique within this boot: the process id in the high part, a
/// per-process counter in the low part.
extern "win64" fn AllocateLocallyUniqueId(luid: *mut u32) -> i32 {
    static NEXT: AtomicU32 = AtomicU32::new(0x1000);
    if luid.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's LUID (LowPart, HighPart).
    unsafe {
        *luid = NEXT.fetch_add(1, Ordering::Relaxed);
        *luid.add(1) = kernel32::pid() as u32;
    }
    1
}

/// Building a descriptor from parent and creator descriptors with
/// inheritance is not implemented.
#[allow(clippy::too_many_arguments)]
extern "win64" fn CreatePrivateObjectSecurityEx(
    _parent: u64,
    _creator: u64,
    out: *mut u64,
    _type: u64,
    _container: i32,
    _flags: u32,
    _token: u64,
    _mapping: u64,
) -> i32 {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    fail(ERROR_NOT_SUPPORTED, 0)
}

extern "win64" fn DestroyPrivateObjectSecurity(sd: *mut u64) -> i32 {
    if sd.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's descriptor pointer.
    let p = unsafe { *sd };
    if p != 0 {
        kernel32::heap_free(p);
    }
    1
}

// ---- local accounts and logon ----------------------------------------------------------------
//
// The account database is the one the installer writes: `/etc/passwd`
// (name:x:uid:gid:...) and `/etc/shadow` (`sha256-iter$rounds$salt$hash`).
// A logon checks the password against it; an account without a password
// (a live system) accepts any.

/// A local account of /etc/passwd.
pub(crate) struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

pub(crate) fn local_accounts() -> Vec<Account> {
    let Ok(text) = os_std::fs::read_to_string("/etc/passwd") else { return Vec::new() };
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let _ = f.next()?;
            Some(Account { name: String::from(name), uid: f.next()?.parse().ok()?, gid: f.next()?.parse().ok()? })
        })
        .collect()
}

/// Why a logon failed: the second status LsaLogonUser reports.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogonFailure {
    NoSuchUser,
    WrongPassword,
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

/// Whether `password` matches a shadow secret `sha256-iter$rounds$salt$hash`.
fn secret_matches(secret: &str, password: &str) -> bool {
    let parts: Vec<&str> = secret.split('$').collect();
    if parts.len() != 4 || parts[0] != "sha256-iter" {
        return false;
    }
    let (Ok(rounds), Some(salt), Some(want)) = (parts[1].parse::<u32>(), hex_bytes(parts[2]), hex_bytes(parts[3])) else { return false };
    if rounds == 0 {
        return false;
    }
    let mut h = osyx_crypto::Sha256::new();
    h.update(&salt);
    h.update(password.as_bytes());
    let mut d = h.finish();
    for _ in 1..rounds {
        let mut h = osyx_crypto::Sha256::new();
        h.update(&d);
        h.update(&salt);
        h.update(password.as_bytes());
        d = h.finish();
    }
    d[..] == want[..]
}

/// Checks a user name and password against the local accounts; the uid and
/// gid of the account on success. Names compare without regard to case, as
/// Windows account names do.
pub(crate) fn logon(user: &str, password: &str) -> Result<(u32, u32), LogonFailure> {
    let account = local_accounts().into_iter().find(|a| a.name.eq_ignore_ascii_case(user)).ok_or(LogonFailure::NoSuchUser)?;
    let secret = os_std::fs::read_to_string("/etc/shadow").ok().and_then(|text| {
        text.lines().find_map(|l| {
            let mut f = l.split(':');
            let (name, secret) = (f.next()?, f.next()?);
            (name == account.name).then(|| String::from(secret))
        })
    });
    match secret {
        Some(s) if !s.is_empty() && !secret_matches(&s, password) => Err(LogonFailure::WrongPassword),
        _ => Ok((account.uid, account.gid)),
    }
}

/// The domain part of a logon: empty or "." mean this computer, as does the
/// computer's own name.
pub(crate) fn domain_is_local(domain: &str) -> bool {
    domain.is_empty() || domain == "." || domain.eq_ignore_ascii_case(&computer_name())
}

const LOGON32_LOGON_INTERACTIVE: u32 = 2;
const LOGON32_LOGON_NETWORK: u32 = 3;
const LOGON32_LOGON_BATCH: u32 = 4;
const LOGON32_LOGON_SERVICE: u32 = 5;
const LOGON32_LOGON_UNLOCK: u32 = 7;
const LOGON32_LOGON_NETWORK_CLEARTEXT: u32 = 8;
const LOGON32_LOGON_NEW_CREDENTIALS: u32 = 9;
const ERROR_LOGON_FAILURE: u32 = 1326;

/// A token for a verified logon: primary, except a network logon, which
/// yields an impersonation token (SecurityImpersonation, level 2).
pub(crate) fn logon_token(uid: u32, gid: u32, network: bool) -> u64 {
    let mut data = tokens::initial(uid, gid);
    if network {
        data.impersonation = Some(2);
    }
    tokens::new_handle(uid, gid, tokens::TOKEN_ALL, data)
}

/// LogonUserW: checks the password in /etc/shadow and returns a token. A
/// wrong user, password or domain is ERROR_LOGON_FAILURE; an unknown logon
/// type or provider ERROR_INVALID_PARAMETER.
extern "win64" fn LogonUserW(user: *const u16, domain: *const u16, password: *const u16, kind: u32, provider: u32, out: *mut u64) -> i32 {
    if out.is_null() || user.is_null() || provider > 3 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if !matches!(kind, LOGON32_LOGON_INTERACTIVE | LOGON32_LOGON_NETWORK | LOGON32_LOGON_BATCH | LOGON32_LOGON_SERVICE | LOGON32_LOGON_UNLOCK | LOGON32_LOGON_NETWORK_CLEARTEXT | LOGON32_LOGON_NEW_CREDENTIALS) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: NUL-terminated strings or NULL.
    let (user, domain, password) = unsafe { (kernel32::sw(user), kernel32::sw(domain), kernel32::sw(password)) };
    let (Some(user), domain, password) = (user, domain.unwrap_or_default(), password.unwrap_or_default()) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    if !domain_is_local(&domain) {
        return fail(ERROR_LOGON_FAILURE, 0);
    }
    match logon(&user, &password) {
        Ok((uid, gid)) => {
            // SAFETY: the caller's out pointer.
            unsafe { *out = logon_token(uid, gid, kind == LOGON32_LOGON_NETWORK) };
            1
        }
        Err(_) => fail(ERROR_LOGON_FAILURE, 0),
    }
}

extern "win64" fn LsaNtStatusToWinError(status: u32) -> u32 {
    status_to_win32(status as NtStatus)
}

// ---- service control manager -----------------------------------------------------------

/// Open service manager handles (SC_HANDLEs are not kernel handles).
static MANAGERS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());
static NEXT_SC: AtomicU32 = AtomicU32::new(0x5c00);

extern "win64" fn OpenSCManagerW(machine: *const u16, database: *const u16, _access: u32) -> u64 {
    // SAFETY: NULL or NUL-terminated names.
    let (m, d) = unsafe { (path::wide_to_string(machine), path::wide_to_string(database)) };
    if m.is_some_and(|m| !m.is_empty()) {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    if d.is_some_and(|d| d != "ServicesActive") {
        return fail(1065, 0); // ERROR_DATABASE_DOES_NOT_EXIST
    }
    let h = NEXT_SC.fetch_add(4, Ordering::Relaxed) as u64;
    MANAGERS.lock().unwrap().insert(h);
    h
}

extern "win64" fn OpenServiceW(manager: u64, name: *const u16, _access: u32) -> u64 {
    if !MANAGERS.lock().unwrap().contains(&manager) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    // SAFETY: a NUL-terminated name.
    if unsafe { path::wide_to_string(name) }.is_none() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    fail(ERROR_SERVICE_DOES_NOT_EXIST, 0)
}

/// Only manager handles exist, and they have no service status.
extern "win64" fn QueryServiceStatus(_h: u64, _status: *mut u8) -> i32 {
    fail(ERROR_INVALID_HANDLE, 0)
}

extern "win64" fn CloseServiceHandle(h: u64) -> i32 {
    if MANAGERS.lock().unwrap().remove(&h) { 1 } else { fail(ERROR_INVALID_HANDLE, 0) }
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        GetUserNameW,
        LookupAccountNameW,
        ConvertSidToStringSidA,
        CheckTokenMembership,
        AllocateLocallyUniqueId,
        CreatePrivateObjectSecurityEx,
        DestroyPrivateObjectSecurity,
        LogonUserW,
        LsaNtStatusToWinError,
        OpenSCManagerW,
        OpenServiceW,
        QueryServiceStatus,
        CloseServiceHandle,
    ]
}
