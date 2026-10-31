//! Access tokens. A token's identity is the kernel's actual uid/gid; its
//! groups, privileges, integrity level, default DACL and restrictions are
//! real token state that GetTokenInformation reports and AccessCheck
//! (objsec.rs) evaluates. The process token is root: High integrity with
//! the administrator's privileges; other users: Medium.
//!
//! OSyx enforces file and process access by uid alone, so code can only
//! *run* with a token whose restrictions OSyx would honour: one equivalent
//! to the process token. Impersonating or starting a process with a
//! restricted, deny-only, lower-integrity or privilege-reduced token fails
//! with ERROR_NOT_SUPPORTED, and the process token's own integrity level
//! cannot be changed. Restricted tokens themselves can be created,
//! duplicated, queried and used in AccessCheck.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::fail,
    objects::{self, Object},
    security::{self, rd, sid, sid_len, Token},
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::ptr::copy_nonoverlapping;
use os_std::sync::Mutex;

const ERROR_NO_TOKEN: u32 = 1008;
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
const ERROR_INVALID_OWNER: u32 = 1307;
const ERROR_INVALID_PRIMARY_GROUP: u32 = 1308;
const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;
pub const ERROR_BAD_IMPERSONATION_LEVEL: u32 = 1346;
const ERROR_BAD_TOKEN_TYPE: u32 = 1349;
const ERROR_INVALID_SID: u32 = 1337;
const ERROR_INVALID_ACL: u32 = 1336;

pub const TOKEN_DUPLICATE: u32 = 0x2;
pub const TOKEN_IMPERSONATE: u32 = 0x4;
pub const TOKEN_QUERY: u32 = 0x8;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x20;
const TOKEN_ADJUST_DEFAULT: u32 = 0x80;
const TOKEN_ASSIGN_PRIMARY: u32 = 0x1;
pub const TOKEN_ALL: u32 = 0x000f_01ff;

// SID_AND_ATTRIBUTES attributes of groups.
pub const SE_GROUP_MANDATORY: u32 = 0x1;
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x2;
pub const SE_GROUP_ENABLED: u32 = 0x4;
pub const SE_GROUP_OWNER: u32 = 0x8;
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
pub const SE_GROUP_INTEGRITY: u32 = 0x20;
pub const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x40;
const GROUP_ON: u32 = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;

const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x1;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x2;
const SE_PRIVILEGE_REMOVED: u32 = 0x4;
pub const SE_SECURITY_PRIVILEGE: u32 = 8;
pub const SE_TAKE_OWNERSHIP_PRIVILEGE: u32 = 9;
const SE_CHANGE_NOTIFY_PRIVILEGE: u32 = 23;

pub const INTEGRITY_MEDIUM: u32 = 0x2000;
pub const INTEGRITY_HIGH: u32 = 0x3000;
/// TOKEN_MANDATORY_POLICY_NO_WRITE_UP.
const POLICY_NO_WRITE_UP: u32 = 1;

/// The mutable state of one token, shared by all its handles.
pub struct TokenState {
    pub data: Mutex<TokenData>,
}

#[derive(Clone, PartialEq)]
pub struct TokenData {
    /// None: a primary token; Some(level): an impersonation token
    /// (SecurityAnonymous 0 .. SecurityDelegation 3).
    pub impersonation: Option<u32>,
    pub integrity: u32,
    /// User and group SIDs that only match deny ACEs.
    pub deny_only: Vec<Vec<u8>>,
    /// Restricting SIDs: access must also be granted to one of them.
    pub restricting: Vec<Vec<u8>>,
    /// Restricting SIDs are checked for write access only.
    pub write_restricted: bool,
    pub sandbox_inert: bool,
    /// (LUID, attributes) of the privileges the token holds.
    pub privileges: Vec<(u32, u32)>,
    /// None: a NULL default DACL.
    pub default_dacl: Option<Vec<u8>>,
    pub owner: Vec<u8>,
    pub primary_group: Vec<u8>,
    pub mandatory_policy: u32,
}

pub fn user_sid(uid: u32) -> Vec<u8> {
    sid(22, &[1, uid])
}

pub fn group_sid(gid: u32) -> Vec<u8> {
    sid(22, &[2, gid])
}

pub fn integrity_sid(level: u32) -> Vec<u8> {
    sid(16, &[level])
}

/// The token's groups with their attributes (deny-only ones marked).
pub fn groups(uid: u32, gid: u32, d: &TokenData) -> Vec<(Vec<u8>, u32)> {
    let mut g = alloc::vec![
        (group_sid(gid), GROUP_ON),
        (sid(1, &[0]), GROUP_ON),
        (sid(5, &[11]), GROUP_ON),
        (sid(5, &[32, 545]), GROUP_ON),
    ];
    if uid == 0 {
        g.push((sid(5, &[32, 544]), GROUP_ON | SE_GROUP_OWNER));
    }
    for (s, attrs) in g.iter_mut() {
        if d.deny_only.contains(s) {
            *attrs = SE_GROUP_USE_FOR_DENY_ONLY | (*attrs & SE_GROUP_OWNER);
        }
    }
    g.push((integrity_sid(d.integrity), SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED));
    g
}

/// SIDs that match allow ACEs, and SIDs that match deny ACEs.
pub fn access_sids(uid: u32, gid: u32, d: &TokenData) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let user = user_sid(uid);
    let mut allow = Vec::new();
    let mut deny = alloc::vec![user.clone()];
    if !d.deny_only.contains(&user) {
        allow.push(user);
    }
    for (s, attrs) in groups(uid, gid, d) {
        if attrs & SE_GROUP_INTEGRITY != 0 {
            continue;
        }
        if attrs & SE_GROUP_ENABLED != 0 {
            allow.push(s.clone());
        }
        deny.push(s);
    }
    (allow, deny)
}

fn privileges_for(uid: u32) -> Vec<(u32, u32)> {
    let on = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    if uid == 0 {
        [5, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 22, 23, 24, 25, 28, 29, 30, 33, 34, 35, 36]
            .iter()
            .map(|&l| (l, if matches!(l, 23 | 29 | 30) { on } else { 0 }))
            .collect()
    } else {
        alloc::vec![(19, 0), (23, on), (25, 0), (33, 0), (34, 0)]
    }
}

/// The default DACL: GENERIC_ALL for the user and SYSTEM.
fn default_dacl(uid: u32) -> Vec<u8> {
    security::build_acl(&[(0, 0, 0x1000_0000, user_sid(uid)), (0, 0, 0x1000_0000, sid(5, &[18]))])
}

pub(crate) fn initial(uid: u32, gid: u32) -> TokenData {
    TokenData {
        impersonation: None,
        integrity: if uid == 0 { INTEGRITY_HIGH } else { INTEGRITY_MEDIUM },
        deny_only: Vec::new(),
        restricting: Vec::new(),
        write_restricted: false,
        sandbox_inert: false,
        privileges: privileges_for(uid),
        default_dacl: Some(default_dacl(uid)),
        owner: user_sid(uid),
        primary_group: group_sid(gid),
        mandatory_policy: POLICY_NO_WRITE_UP,
    }
}

static PROCESS: Mutex<Option<Arc<TokenState>>> = Mutex::new(None);

/// The process's primary token (one token, shared by every handle).
pub fn process_state() -> Arc<TokenState> {
    let mut p = PROCESS.lock().unwrap();
    p.get_or_insert_with(|| {
        let (uid, gid) = os_sys::getuid();
        Arc::new(TokenState { data: Mutex::new(initial(uid, gid)) })
    })
    .clone()
}

pub fn process_data() -> TokenData {
    process_state().data.lock().unwrap().clone()
}

/// Thread impersonation tokens by thread id.
static IMPERSONATING: Mutex<BTreeMap<u64, Token>> = Mutex::new(BTreeMap::new());

/// The token access checks of the calling thread use: its impersonation
/// token, else the process token.
pub fn effective() -> Token {
    if let Some(t) = IMPERSONATING.lock().unwrap().get(&os_sys::gettid()) {
        return t.clone();
    }
    let (uid, gid) = os_sys::getuid();
    Token { uid, gid, access: TOKEN_ALL, state: process_state() }
}

/// The state of the token access checks of the calling thread use.
pub fn effective_data() -> TokenData {
    effective().state.data.lock().unwrap().clone()
}

pub fn token(h: u64) -> Result<Token, u32> {
    match objects::get(h) {
        Some(Object::Token(t)) => Ok((*t).clone()),
        _ => Err(ERROR_INVALID_HANDLE),
    }
}

fn need(t: &Token, access: u32) -> Result<(), u32> {
    if t.access & access == access { Ok(()) } else { Err(ERROR_ACCESS_DENIED) }
}

/// Whether code may run with this token on OSyx: it must grant and deny
/// exactly what the process token does.
fn runnable(t: &Token, d: &TokenData) -> bool {
    let (uid, gid) = os_sys::getuid();
    let p = process_data();
    let lids = |v: &[(u32, u32)]| v.iter().map(|x| x.0).collect::<Vec<_>>();
    t.uid == uid
        && t.gid == gid
        && d.integrity == p.integrity
        && d.deny_only.is_empty()
        && d.restricting.is_empty()
        && lids(&d.privileges) == lids(&p.privileges)
}

// ---- queries ----------------------------------------------------------------------

fn put_sid(data: &mut Vec<u8>, at: usize, s: &[u8], base: u64) {
    let offset = data.len();
    data[at..at + 8].copy_from_slice(&(base + offset as u64).to_le_bytes());
    data.extend_from_slice(s);
}

fn sid_groups(list: &[(Vec<u8>, u32)], base: u64) -> Vec<u8> {
    let mut data = alloc::vec![0; 8 + 16 * list.len()];
    data[..4].copy_from_slice(&(list.len() as u32).to_le_bytes());
    for (i, (s, attrs)) in list.iter().enumerate() {
        let at = 8 + 16 * i;
        data[at + 8..at + 12].copy_from_slice(&attrs.to_le_bytes());
        put_sid(&mut data, at, s, base);
    }
    data
}

fn privileges_block(list: &[(u32, u32)]) -> Vec<u8> {
    let mut data = (list.len() as u32).to_le_bytes().to_vec();
    for &(luid, attrs) in list {
        data.extend_from_slice(&luid.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&attrs.to_le_bytes());
    }
    data
}

fn token_info(t: &Token, d: &TokenData, class: u32, base: u64) -> Result<Vec<u8>, u32> {
    let u32b = |v: u32| v.to_le_bytes().to_vec();
    let mut data;
    match class {
        1 => {
            data = alloc::vec![0; 16];
            let user = user_sid(t.uid);
            if d.deny_only.contains(&user) {
                data[8..12].copy_from_slice(&SE_GROUP_USE_FOR_DENY_ONLY.to_le_bytes());
            }
            put_sid(&mut data, 0, &user, base);
        }
        2 => data = sid_groups(&groups(t.uid, t.gid, d), base),
        3 => data = privileges_block(&d.privileges),
        4 | 5 => {
            data = alloc::vec![0; 8];
            put_sid(&mut data, 0, if class == 4 { &d.owner } else { &d.primary_group }, base);
        }
        6 => {
            data = alloc::vec![0; 8];
            if let Some(acl) = &d.default_dacl {
                let at = data.len();
                data[..8].copy_from_slice(&(base + at as u64).to_le_bytes());
                data.extend_from_slice(acl);
            }
        }
        8 => data = u32b(if d.impersonation.is_some() { 2 } else { 1 }),
        9 => data = u32b(d.impersonation.ok_or(ERROR_INVALID_PARAMETER)?),
        11 => data = sid_groups(&d.restricting.iter().map(|s| (s.clone(), GROUP_ON)).collect::<Vec<_>>(), base),
        12 => data = u32b(1), // OSyx has one interactive session
        // TokenElevationType: OSyx has no split (filtered) admin tokens.
        18 => data = u32b(1),
        20 => data = u32b(u32::from(t.uid == 0)),
        25 => {
            data = alloc::vec![0; 16];
            data[8..12].copy_from_slice(&(SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED).to_le_bytes());
            put_sid(&mut data, 0, &integrity_sid(d.integrity), base);
        }
        27 => data = u32b(d.mandatory_policy),
        29 => data = u32b(0), // TokenIsAppContainer
        _ => return Err(ERROR_NOT_SUPPORTED),
    }
    Ok(data)
}

extern "win64" fn GetTokenInformation(h: u64, class: u32, out: *mut u8, size: u32, needed: *mut u32) -> i32 {
    let t = match token(h).and_then(|t| need(&t, TOKEN_QUERY).map(|()| t)) {
        Ok(t) => t,
        Err(e) => return fail(e, 0),
    };
    if needed.is_null() || out.is_null() && size != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let d = t.state.data.lock().unwrap().clone();
    let data = match token_info(&t, &d, class, out as u64) {
        Ok(v) => v,
        Err(e) => return fail(e, 0),
    };
    // SAFETY: the caller's out pointer.
    unsafe { *needed = data.len() as u32 };
    if size < data.len() as u32 || out.is_null() {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    // SAFETY: `size` bytes at `out`.
    unsafe { copy_nonoverlapping(data.as_ptr(), out, data.len()) };
    1
}

// ---- opening and duplicating ------------------------------------------------------------

pub(crate) fn new_handle(uid: u32, gid: u32, access: u32, d: TokenData) -> u64 {
    objects::insert(Object::Token(Arc::new(Token { uid, gid, access, state: Arc::new(TokenState { data: Mutex::new(d) }) })))
}

pub(crate) extern "win64" fn OpenProcessToken(process: u64, access: u32, out: *mut u64) -> i32 {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if process != objects::CURRENT_PROCESS {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    let access = match security::token_access(access) {
        Ok(v) => v,
        Err(e) => return fail(e, 0),
    };
    let (uid, gid) = os_sys::getuid();
    // SAFETY: the caller's out pointer.
    unsafe { *out = objects::insert(Object::Token(Arc::new(Token { uid, gid, access, state: process_state() }))) };
    1
}

/// The thread id behind a thread handle (or the pseudo-handle).
fn thread_id(h: u64) -> Result<u64, u32> {
    if h == objects::CURRENT_THREAD {
        return Ok(os_sys::gettid());
    }
    match objects::get(h) {
        Some(Object::Thread(t)) => Ok(t.tid.load(core::sync::atomic::Ordering::SeqCst) as u64),
        _ => Err(ERROR_INVALID_HANDLE),
    }
}

extern "win64" fn OpenThreadToken(thread: u64, access: u32, _as_self: i32, out: *mut u64) -> i32 {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let tid = match thread_id(thread) {
        Ok(t) => t,
        Err(e) => return fail(e, 0),
    };
    let access = match security::token_access(access) {
        Ok(v) => v,
        Err(e) => return fail(e, 0),
    };
    let Some(t) = IMPERSONATING.lock().unwrap().get(&tid).cloned() else { return fail(ERROR_NO_TOKEN, 0) };
    // SAFETY: the caller's out pointer.
    unsafe { *out = objects::insert(Object::Token(Arc::new(Token { access, ..t }))) };
    1
}

extern "win64" fn DuplicateTokenEx(h: u64, access: u32, sa: u64, level: u32, kind: u32, out: *mut u64) -> i32 {
    let t = match token(h).and_then(|t| need(&t, TOKEN_DUPLICATE).map(|()| t)) {
        Ok(t) => t,
        Err(e) => return fail(e, 0),
    };
    if let Err(e) = security::validate_attributes(sa) {
        return fail(e, 0);
    }
    if out.is_null() || level > 3 || !(1..=2).contains(&kind) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let access = if access == 0 {
        t.access
    } else {
        match security::token_access(access) {
            Ok(v) => v,
            Err(e) => return fail(e, 0),
        }
    };
    let mut d = t.state.data.lock().unwrap().clone();
    // An impersonation token below SecurityImpersonation cannot become primary.
    if kind == 1 && d.impersonation.is_some_and(|l| l < 2) {
        return fail(ERROR_BAD_IMPERSONATION_LEVEL, 0);
    }
    d.impersonation = (kind == 2).then_some(level);
    // SAFETY: the caller's out pointer.
    unsafe { *out = new_handle(t.uid, t.gid, access, d) };
    1
}

extern "win64" fn DuplicateToken(h: u64, level: u32, out: *mut u64) -> i32 {
    DuplicateTokenEx(h, TOKEN_IMPERSONATE | TOKEN_QUERY, 0, level, 2, out)
}

const DISABLE_MAX_PRIVILEGE: u32 = 0x1;
const SANDBOX_INERT: u32 = 0x2;
const WRITE_RESTRICTED: u32 = 0x8;

/// `count` SID_AND_ATTRIBUTES entries (16 bytes each) â†’ SIDs.
fn sid_list(p: *const u8, count: u32) -> Result<Vec<Vec<u8>>, u32> {
    if count != 0 && p.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    (0..count as usize)
        .map(|i| {
            // SAFETY: the caller's array of `count` entries.
            let s = unsafe { rd::<u64>(p, i * 16) } as *const u8;
            let n = unsafe { sid_len(s) }.ok_or(ERROR_INVALID_SID)?;
            // SAFETY: a valid SID of n bytes.
            Ok(unsafe { core::slice::from_raw_parts(s, n) }.to_vec())
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn CreateRestrictedToken(
    h: u64,
    flags: u32,
    disable_count: u32,
    disable: *const u8,
    delete_count: u32,
    delete: *const u8,
    restrict_count: u32,
    restrict: *const u8,
    out: *mut u64,
) -> i32 {
    let t = match token(h).and_then(|t| need(&t, TOKEN_DUPLICATE).map(|()| t)) {
        Ok(t) => t,
        Err(e) => return fail(e, 0),
    };
    if out.is_null() || flags & !(DISABLE_MAX_PRIVILEGE | SANDBOX_INERT | WRITE_RESTRICTED) != 0 {
        // LUA_TOKEN (a UAC-filtered token) has no meaning without UAC.
        return fail(if out.is_null() { ERROR_INVALID_PARAMETER } else { ERROR_NOT_SUPPORTED }, 0);
    }
    let (disabled, restricting) = match (sid_list(disable, disable_count), sid_list(restrict, restrict_count)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return fail(e, 0),
    };
    if delete_count != 0 && delete.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut d = t.state.data.lock().unwrap().clone();
    // Only the token's own user and groups become deny-only; the integrity
    // SID and SIDs the token does not have are ignored, as on Windows.
    let mut own: Vec<Vec<u8>> = groups(t.uid, t.gid, &d).into_iter().filter(|g| g.1 & SE_GROUP_INTEGRITY == 0).map(|g| g.0).collect();
    own.push(user_sid(t.uid));
    for s in disabled {
        if own.contains(&s) && !d.deny_only.contains(&s) {
            d.deny_only.push(s);
        }
    }
    if flags & DISABLE_MAX_PRIVILEGE != 0 {
        d.privileges.retain(|p| p.0 == SE_CHANGE_NOTIFY_PRIVILEGE);
    }
    for i in 0..delete_count as usize {
        // SAFETY: the caller's LUID_AND_ATTRIBUTES array (12 bytes each).
        let luid = unsafe { rd::<u32>(delete, i * 12) };
        d.privileges.retain(|p| p.0 != luid);
    }
    for s in restricting {
        if !d.restricting.contains(&s) {
            d.restricting.push(s);
        }
    }
    d.write_restricted |= flags & WRITE_RESTRICTED != 0;
    d.sandbox_inert |= flags & SANDBOX_INERT != 0;
    // SAFETY: the caller's out pointer.
    unsafe { *out = new_handle(t.uid, t.gid, TOKEN_ALL, d) };
    1
}

// ---- changing tokens -----------------------------------------------------------------------

fn sid_at(p: *const u8) -> Result<Vec<u8>, u32> {
    // SAFETY: NULL or the caller's SID, validated by sid_bytes.
    unsafe { security::sid_bytes(p) }
}

fn set_info(t: &Token, class: u32, info: *const u8, len: u32) -> Result<(), u32> {
    let is_process = Arc::ptr_eq(&t.state, &process_state());
    let mut d = t.state.data.lock().unwrap();
    let need_len = |n: u32| if len < n || info.is_null() { Err(ERROR_BAD_LENGTH) } else { Ok(()) };
    match class {
        4 | 5 => {
            need(t, TOKEN_ADJUST_DEFAULT)?;
            need_len(8)?;
            // SAFETY: a TOKEN_OWNER / TOKEN_PRIMARY_GROUP (one SID pointer).
            let s = sid_at(unsafe { rd::<u64>(info, 0) } as *const u8)?;
            let g = groups(t.uid, t.gid, &d);
            if class == 4 {
                let ok = s == user_sid(t.uid) || g.iter().any(|(x, a)| *x == s && a & SE_GROUP_OWNER != 0);
                if !ok {
                    return Err(ERROR_INVALID_OWNER);
                }
                d.owner = s;
            } else {
                if !g.iter().any(|(x, a)| *x == s && a & SE_GROUP_INTEGRITY == 0) {
                    return Err(ERROR_INVALID_PRIMARY_GROUP);
                }
                d.primary_group = s;
            }
        }
        6 => {
            need(t, TOKEN_ADJUST_DEFAULT)?;
            need_len(8)?;
            // SAFETY: a TOKEN_DEFAULT_DACL (one ACL pointer, NULL allowed).
            let acl = unsafe { rd::<u64>(info, 0) } as *const u8;
            // SAFETY: NULL or the caller's ACL, validated by acl_bytes.
            d.default_dacl = if acl.is_null() { None } else { Some(unsafe { security::acl_bytes(acl) }.map_err(|_| ERROR_INVALID_ACL)?) };
        }
        // TokenSessionId and TokenMandatoryPolicy need SeTcbPrivilege.
        12 | 27 => return Err(ERROR_PRIVILEGE_NOT_HELD),
        25 => {
            need(t, TOKEN_ADJUST_DEFAULT)?;
            need_len(16)?;
            // SAFETY: a TOKEN_MANDATORY_LABEL.
            let s = sid_at(unsafe { rd::<u64>(info, 0) } as *const u8)?;
            if s.len() != 12 || s[1] != 1 || s[2..8] != [0, 0, 0, 0, 0, 16] {
                return Err(ERROR_INVALID_SID);
            }
            let level = u32::from_le_bytes([s[8], s[9], s[10], s[11]]);
            if level > d.integrity {
                return Err(ERROR_PRIVILEGE_NOT_HELD); // raising needs SeTcbPrivilege
            }
            if is_process && level != d.integrity {
                // OSyx cannot confine this process to a lower integrity level.
                return Err(ERROR_NOT_SUPPORTED);
            }
            d.integrity = level;
        }
        _ => return Err(ERROR_NOT_SUPPORTED),
    }
    Ok(())
}

const ERROR_BAD_LENGTH: u32 = 24;

extern "win64" fn SetTokenInformation(h: u64, class: u32, info: *const u8, len: u32) -> i32 {
    match token(h).and_then(|t| set_info(&t, class, info, len)) {
        Ok(()) => 1,
        Err(e) => fail(e, 0),
    }
}

extern "win64" fn AdjustTokenPrivileges(h: u64, disable_all: i32, new: *const u8, _len: u32, prev: *mut u8, ret: *mut u32) -> i32 {
    let t = match token(h).and_then(|t| need(&t, TOKEN_ADJUST_PRIVILEGES).map(|()| t)) {
        Ok(t) => t,
        Err(e) => return fail(e, 0),
    };
    if !prev.is_null() && (ret.is_null() || need(&t, TOKEN_QUERY).is_err()) {
        return fail(if ret.is_null() { ERROR_INVALID_PARAMETER } else { ERROR_ACCESS_DENIED }, 0);
    }
    if disable_all == 0 && new.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut d = t.state.data.lock().unwrap();
    // (luid, new attributes) requested.
    let requests: Vec<(u32, u32)> = if disable_all != 0 {
        d.privileges.iter().map(|p| (p.0, 0)).collect()
    } else {
        // SAFETY: the caller's TOKEN_PRIVILEGES.
        let n = unsafe { rd::<u32>(new, 0) } as usize;
        (0..n).map(|i| unsafe { (rd::<u32>(new, 4 + i * 12), rd::<u32>(new, 12 + i * 12)) }).collect()
    };
    let mut changed = Vec::new();
    let mut all = true;
    let mut next = d.privileges.clone();
    for (luid, attrs) in requests {
        let Some(i) = next.iter().position(|p| p.0 == luid) else {
            all = false;
            continue;
        };
        let old = next[i];
        if attrs & SE_PRIVILEGE_REMOVED != 0 {
            next.remove(i);
        } else {
            next[i].1 = (old.1 & SE_PRIVILEGE_ENABLED_BY_DEFAULT) | (attrs & SE_PRIVILEGE_ENABLED);
        }
        if !changed.iter().any(|c: &(u32, u32)| c.0 == luid) {
            changed.push(old);
        }
    }
    if !prev.is_null() {
        let block = privileges_block(&changed);
        // SAFETY: the caller's out pointers; `_len` bytes at `prev`.
        unsafe {
            *ret = block.len() as u32;
            if (_len as usize) < block.len() {
                return fail(ERROR_INSUFFICIENT_BUFFER, 0);
            }
            copy_nonoverlapping(block.as_ptr(), prev, block.len());
        }
    }
    d.privileges = next;
    crate::teb::set_last_error(if all { 0 } else { ERROR_NOT_ALL_ASSIGNED });
    1
}

// ---- impersonation ---------------------------------------------------------------------------

extern "win64" fn SetThreadToken(thread: *const u64, h: u64) -> i32 {
    // SAFETY: NULL (the calling thread) or the caller's thread handle.
    let tid = match if thread.is_null() { Ok(os_sys::gettid()) } else { thread_id(unsafe { *thread }) } {
        Ok(t) => t,
        Err(e) => return fail(e, 0),
    };
    if h == 0 {
        IMPERSONATING.lock().unwrap().remove(&tid);
        return 1;
    }
    let t = match token(h).and_then(|t| need(&t, TOKEN_IMPERSONATE).map(|()| t)) {
        Ok(t) => t,
        Err(e) => return fail(e, 0),
    };
    let d = t.state.data.lock().unwrap().clone();
    if d.impersonation.is_none() {
        return fail(ERROR_BAD_TOKEN_TYPE, 0);
    }
    if !runnable(&t, &d) {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    IMPERSONATING.lock().unwrap().insert(tid, t);
    1
}

extern "win64" fn RevertToSelf() -> i32 {
    IMPERSONATING.lock().unwrap().remove(&os_sys::gettid());
    1
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn CreateProcessAsUserW(
    h: u64,
    app: *const u16,
    cmd: *mut u16,
    psa: u64,
    tsa: u64,
    inherit: i32,
    flags: u32,
    env: u64,
    cwd: *const u16,
    startup: *const u8,
    info: *mut u64,
) -> i32 {
    let t = if h == 0 {
        effective()
    } else {
        match token(h).and_then(|t| need(&t, TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY).map(|()| t)) {
            Ok(t) => t,
            Err(e) => return fail(e, 0),
        }
    };
    let d = t.state.data.lock().unwrap().clone();
    if h != 0 && d.impersonation.is_some() {
        return fail(ERROR_BAD_TOKEN_TYPE, 0);
    }
    if !runnable(&t, &d) {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    crate::process::CreateProcessW(app, cmd, psa, tsa, inherit, flags, env, cwd, startup, info)
}

// ---- privilege names -----------------------------------------------------------------------

/// Privilege names by LUID (2 = SeCreateTokenPrivilege ... 36), as on Windows.
const PRIVILEGES: [&str; 35] = [
    "SeCreateTokenPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLockMemoryPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeMachineAccountPrivilege",
    "SeTcbPrivilege",
    "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeSystemProfilePrivilege",
    "SeSystemtimePrivilege",
    "SeProfileSingleProcessPrivilege",
    "SeIncreaseBasePriorityPrivilege",
    "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeShutdownPrivilege",
    "SeDebugPrivilege",
    "SeAuditPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeChangeNotifyPrivilege",
    "SeRemoteShutdownPrivilege",
    "SeUndockPrivilege",
    "SeSyncAgentPrivilege",
    "SeEnableDelegationPrivilege",
    "SeManageVolumePrivilege",
    "SeImpersonatePrivilege",
    "SeCreateGlobalPrivilege",
    "SeTrustedCredManAccessPrivilege",
    "SeRelabelPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeTimeZonePrivilege",
    "SeCreateSymbolicLinkPrivilege",
    "SeDelegateSessionUserImpersonatePrivilege",
];
const ERROR_NO_SUCH_PRIVILEGE: u32 = 1313;

fn lookup_value(system: Option<alloc::string::String>, name: Option<alloc::string::String>, luid: *mut u32) -> i32 {
    if system.is_some_and(|s| !s.is_empty()) {
        return fail(ERROR_NOT_SUPPORTED, 0); // remote systems
    }
    let Some(name) = name else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let Some(i) = PRIVILEGES.iter().position(|p| p.eq_ignore_ascii_case(&name)) else { return fail(ERROR_NO_SUCH_PRIVILEGE, 0) };
    if luid.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's LUID.
    unsafe {
        *luid = i as u32 + 2;
        *luid.add(1) = 0;
    }
    1
}

extern "win64" fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut u32) -> i32 {
    // SAFETY: NULL or NUL-terminated strings.
    unsafe { lookup_value(crate::path::wide_to_string(system), crate::path::wide_to_string(name), luid) }
}

extern "win64" fn LookupPrivilegeValueA(system: *const u8, name: *const u8, luid: *mut u32) -> i32 {
    // SAFETY: NULL or NUL-terminated strings.
    unsafe { lookup_value(crate::path::ansi_to_string(system), crate::path::ansi_to_string(name), luid) }
}

extern "win64" fn LookupPrivilegeNameW(system: *const u16, luid: *const u32, out: *mut u16, len: *mut u32) -> i32 {
    // SAFETY: NULL or a NUL-terminated string; the caller's LUID and length.
    if unsafe { crate::path::wide_to_string(system) }.is_some_and(|s| !s.is_empty()) {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    if luid.is_null() || len.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let (low, high) = unsafe { (*luid, *luid.add(1)) };
    let Some(name) = (high == 0).then(|| low.checked_sub(2).and_then(|i| PRIVILEGES.get(i as usize))).flatten() else {
        return fail(ERROR_NO_SUCH_PRIVILEGE, 0);
    };
    let w: Vec<u16> = name.encode_utf16().collect();
    // SAFETY: the caller's buffer of *len characters.
    unsafe {
        if out.is_null() || (*len as usize) <= w.len() {
            *len = w.len() as u32 + 1;
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        core::ptr::copy_nonoverlapping(w.as_ptr(), out, w.len());
        *out.add(w.len()) = 0;
        *len = w.len() as u32;
    }
    1
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        LookupPrivilegeValueW,
        LookupPrivilegeValueA,
        LookupPrivilegeNameW,
        OpenProcessToken,
        OpenThreadToken,
        GetTokenInformation,
        SetTokenInformation,
        DuplicateTokenEx,
        DuplicateToken,
        CreateRestrictedToken,
        AdjustTokenPrivileges,
        SetThreadToken,
        RevertToSelf,
        CreateProcessAsUserW,
    ]
}
