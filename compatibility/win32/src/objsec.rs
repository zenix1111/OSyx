//! Object security: the security descriptors of kernel objects, window
//! stations, desktops and files; Get/SetSecurityInfo and the named and
//! kernel-object variants, SetEntriesInAclW and trustees, string SIDs,
//! MapGenericMask and AccessCheck.
//!
//! A kernel object gets its descriptor when first asked for: owner and
//! primary group from the process token, the token's default DACL with its
//! generic rights mapped to the object type's, and no label (which Windows
//! treats as Medium integrity). Set*SecurityInfo replaces it. The
//! descriptor lives with the object for as long as a handle to it does.
//! As on Windows, unnamed events, mutexes, semaphores, timers, sections,
//! completion ports and jobs have no security at all.
//! Windows evaluates it when the object is opened by name; OSyx names are
//! per process and code only runs with the process token or one that
//! grants exactly the same (tokens.rs), so stored descriptors are reported
//! and used by AccessCheck but do not gate this process's own opens.
//!
//! A file's descriptor is its OSyx owner, group and mode: an allow ACE for
//! each of the owner, the group and Everyone with the rights of its rwx
//! bits, and full access for Administrators (root, which OSyx does not
//! check against the mode). Setting a file DACL changes the mode, and only
//! a DACL the mode can express exactly is accepted; file owners, groups,
//! labels and audit ACEs cannot be changed on OSyx (ERROR_NOT_SUPPORTED).
//! OSyx has no auditing: a SACL with audit ACEs is not stored.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{self, fail},
    objects::{self, Object},
    path,
    security::{self, acl_aces, build_acl, rd, sid, sid_bytes, wr, Ace, ACCESS_ALLOWED, ACCESS_DENIED, MANDATORY_LABEL, SYSTEM_AUDIT},
    tokens::{self, TokenData},
};
use alloc::{
    collections::BTreeMap,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::any::Any;
use core::ptr::copy_nonoverlapping;
use os_std::sync::Mutex;

const ERROR_INVALID_OWNER: u32 = 1307;
const ERROR_NO_IMPERSONATION_TOKEN: u32 = 1309;
const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;
const ERROR_NONE_MAPPED: u32 = 1332;
const ERROR_INVALID_ACL: u32 = 1336;
const ERROR_INVALID_SID: u32 = 1337;
const ERROR_INVALID_SECURITY_DESCR: u32 = 1338;
const ERROR_NO_SECURITY_ON_OBJECT: u32 = 1350;
const ERROR_GENERIC_NOT_MAPPED: u32 = 1360;

// SECURITY_INFORMATION bits.
const OWNER: u32 = 0x1;
const GROUP: u32 = 0x2;
const DACL: u32 = 0x4;
const SACL: u32 = 0x8;
const LABEL: u32 = 0x10;
const UNPROTECTED_SACL: u32 = 0x1000_0000;
const UNPROTECTED_DACL: u32 = 0x2000_0000;
const PROTECTED_SACL: u32 = 0x4000_0000;
const PROTECTED_DACL: u32 = 0x8000_0000;
const KNOWN_INFO: u32 = OWNER | GROUP | DACL | SACL | LABEL | UNPROTECTED_SACL | UNPROTECTED_DACL | PROTECTED_SACL | PROTECTED_DACL;

// SECURITY_DESCRIPTOR_CONTROL bits.
const SE_DACL_PRESENT: u16 = 0x4;
const SE_SACL_PRESENT: u16 = 0x10;
const SE_DACL_AUTO_INHERITED: u16 = 0x400;
const SE_SACL_AUTO_INHERITED: u16 = 0x800;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_SACL_PROTECTED: u16 = 0x2000;
const SE_SELF_RELATIVE: u16 = 0x8000;

// SE_OBJECT_TYPE.
const SE_FILE_OBJECT: u32 = 1;
const SE_KERNEL_OBJECT: u32 = 6;
const SE_WINDOW_OBJECT: u32 = 7;

// ACE flags.
const OBJECT_INHERIT_ACE: u8 = 0x1;
const CONTAINER_INHERIT_ACE: u8 = 0x2;
const INHERIT_ONLY_ACE: u8 = 0x8;
const INHERITED_ACE: u8 = 0x10;
const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;

const STANDARD_RIGHTS_ALL: u32 = 0x1f_0000;
const SYNCHRONIZE: u32 = 0x10_0000;
const READ_CONTROL: u32 = 0x2_0000;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_BITS: u32 = 0xf000_0000;

// Mandatory label policy.
const NO_WRITE_UP: u32 = 0x1;
const NO_READ_UP: u32 = 0x2;
const NO_EXECUTE_UP: u32 = 0x4;

/// GENERIC_MAPPING: read, write, execute, all.
pub type Mapping = [u32; 4];
const FILE: Mapping = [0x0012_0089, 0x0012_0116, 0x0012_00a0, 0x001f_01ff];
const EVENT: Mapping = [0x0002_0001, 0x0002_0002, 0x0010_0000, 0x001f_0003];
const MUTEX: Mapping = [0x0002_0001, 0x0002_0000, 0x0010_0000, 0x001f_0001];
pub const SECTION: Mapping = [0x0002_0005, 0x0002_0002, 0x0002_0008, 0x000f_001f];
const PROCESS: Mapping = [0x0002_0410, 0x0002_0bea, 0x0012_1000, 0x001f_ffff];
const THREAD: Mapping = [0x0002_0048, 0x0002_0037, 0x0012_1400, 0x001f_ffff];
const TOKEN: Mapping = [0x0002_0008, 0x0002_00e0, 0x0002_0000, 0x000f_01ff];
const JOB: Mapping = [0x0002_0004, 0x0002_000b, 0x0010_0000, 0x001f_003f];
pub const WINSTA: Mapping = [0x0002_0303, 0x0002_001c, 0x0002_0060, 0x000f_037f];
pub const DESKTOP: Mapping = [0x0002_0041, 0x0002_00be, 0x0002_0100, 0x000f_01ff];

/// Replaces generic rights in `mask` by the object type's specific ones.
pub fn map_generic(mask: u32, m: &Mapping) -> u32 {
    let mut out = mask & !GENERIC_BITS;
    for (bit, i) in [(0x8000_0000u32, 0), (0x4000_0000, 1), (0x2000_0000, 2), (GENERIC_ALL, 3)] {
        if mask & bit != 0 {
            out |= m[i];
        }
    }
    out
}

/// An object's security descriptor, in parts.
#[derive(Clone, PartialEq, Debug)]
pub struct Sd {
    pub owner: Vec<u8>,
    pub group: Vec<u8>,
    /// None: a NULL DACL (everyone gets every right).
    pub dacl: Option<Vec<Ace>>,
    /// Audit and mandatory label ACEs.
    pub sacl: Vec<Ace>,
    /// SE_DACL_PROTECTED and friends.
    pub control: u16,
}

impl Sd {
    /// The label: (integrity level, policy); Medium with no-write-up if
    /// the object has none.
    pub fn label(&self) -> (u32, u32) {
        self.sacl
            .iter()
            .find(|a| a.0 == MANDATORY_LABEL && a.1 & INHERIT_ONLY_ACE == 0)
            .map_or((tokens::INTEGRITY_MEDIUM, NO_WRITE_UP), |a| (label_level(&a.3).unwrap_or(tokens::INTEGRITY_MEDIUM), a.2))
    }
}

/// The level of a mandatory label SID (S-1-16-level).
fn label_level(s: &[u8]) -> Option<u32> {
    (s.len() == 12 && s[1] == 1 && s[2..8] == [0, 0, 0, 0, 0, 16]).then(|| u32::from_le_bytes([s[8], s[9], s[10], s[11]]))
}

/// The descriptor a new object of mapping `m` gets from the token `d`.
pub fn default_sd(d: &TokenData, m: &Mapping) -> Sd {
    let dacl = d.default_dacl.as_ref().map(|acl| {
        // SAFETY: the token's own well-formed ACL.
        let aces = unsafe { acl_aces(acl.as_ptr()) }.unwrap_or_default();
        aces.into_iter().map(|(k, f, mask, s)| (k, f, map_generic(mask, m), s)).collect()
    });
    Sd { owner: d.owner.clone(), group: d.primary_group.clone(), dacl, sacl: Vec::new(), control: 0 }
}

// ---- self-relative descriptors -------------------------------------------------------

/// A self-relative SECURITY_DESCRIPTOR_RELATIVE holding the parts `info`
/// asks for.
pub fn to_relative(sd: &Sd, info: u32) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 20];
    v[0] = 1;
    let mut control = SE_SELF_RELATIVE | (sd.control & (SE_DACL_PROTECTED | SE_SACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_SACL_AUTO_INHERITED));
    let put = |v: &mut Vec<u8>, field: usize, data: &[u8]| {
        let at = v.len() as u32;
        v[4 + field * 4..8 + field * 4].copy_from_slice(&at.to_le_bytes());
        v.extend_from_slice(data);
    };
    if info & OWNER != 0 {
        put(&mut v, 0, &sd.owner);
    }
    if info & GROUP != 0 {
        put(&mut v, 1, &sd.group);
    }
    if info & (SACL | LABEL) != 0 {
        let aces: Vec<Ace> = sd
            .sacl
            .iter()
            .filter(|a| (a.0 == MANDATORY_LABEL && info & LABEL != 0) || (a.0 == SYSTEM_AUDIT && info & SACL != 0))
            .cloned()
            .collect();
        if !aces.is_empty() || info & SACL != 0 {
            control |= SE_SACL_PRESENT;
            put(&mut v, 2, &build_acl(&aces));
        }
    }
    if info & DACL != 0 {
        control |= SE_DACL_PRESENT;
        if let Some(d) = &sd.dacl {
            put(&mut v, 3, &build_acl(d));
        }
    }
    v[2..4].copy_from_slice(&control.to_le_bytes());
    v
}

/// The parts of a caller's descriptor (absolute or self-relative):
/// (owner, group, DACL, SACL, control). A part is Ok(None) when absent;
/// a present NULL DACL is Some(None).
#[allow(clippy::type_complexity)]
unsafe fn parse_sd(p: *const u8) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Option<Vec<Ace>>>, Option<Vec<Ace>>, u16), u32> {
    let control = unsafe { security::descriptor_control(p) }?;
    let part = |field: usize| unsafe { security::component(p, field) };
    let owner = part(0)?;
    let group = part(1)?;
    let owner = if owner.is_null() { None } else { Some(unsafe { sid_bytes(owner) }?) };
    let group = if group.is_null() { None } else { Some(unsafe { sid_bytes(group) }?) };
    let dacl = if control & SE_DACL_PRESENT != 0 {
        let a = part(3)?;
        Some(if a.is_null() { None } else { Some(unsafe { acl_aces(a) }?) })
    } else {
        None
    };
    let sacl = if control & SE_SACL_PRESENT != 0 {
        let a = part(2)?;
        Some(if a.is_null() { Vec::new() } else { unsafe { acl_aces(a) }? })
    } else {
        None
    };
    Ok((owner, group, dacl, sacl, control))
}

/// (owner, group, DACL, SACL) of a caller's descriptor, as parse_sd.
#[allow(clippy::type_complexity)]
pub unsafe fn sd_parts(p: *const u8) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Option<Vec<Ace>>>, Option<Vec<Ace>>), u32> {
    let (o, g, d, s, _) = unsafe { parse_sd(p) }?;
    Ok((o, g, d, s))
}

// ---- kernel and window objects -----------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Ptr(usize),
    ThisProcess,
    Thread(u64),
}

struct Stored {
    alive: Option<Weak<dyn Any + Send + Sync>>,
    sd: Sd,
}

static STORE: Mutex<BTreeMap<Key, Stored>> = Mutex::new(BTreeMap::new());

fn weak<T: Any + Send + Sync>(a: &Arc<T>) -> (Key, Option<Weak<dyn Any + Send + Sync>>) {
    let w: Weak<dyn Any + Send + Sync> = Arc::downgrade(a) as Weak<dyn Any + Send + Sync>;
    (Key::Ptr(Arc::as_ptr(a) as *const u8 as usize), Some(w))
}

/// A kernel or window object: its identity and generic mapping.
struct Target {
    key: Key,
    alive: Option<Weak<dyn Any + Send + Sync>>,
    mapping: Mapping,
    /// Unnamed events, mutexes, semaphores, timers, sections, completion
    /// ports and jobs have no security on Windows: reading it gives an
    /// empty descriptor, setting it ERROR_NO_SECURITY_ON_OBJECT.
    secured: bool,
}

fn target(h: u64) -> Result<Target, u32> {
    let own = |key, mapping| Target { key, alive: None, mapping, secured: true };
    if h == objects::CURRENT_PROCESS {
        return Ok(own(Key::ThisProcess, PROCESS));
    }
    if h == objects::CURRENT_THREAD {
        return Ok(own(Key::Thread(os_sys::gettid()), THREAD));
    }
    let o = objects::get(h).ok_or(ERROR_INVALID_HANDLE)?;
    let (mapping, secured, (key, alive)) = match &o {
        Object::Event(a) => (EVENT, a.name.is_some(), weak(a)),
        Object::KeyedEvent(a) => (EVENT, false, weak(a)),
        Object::Timer(a) => (EVENT, a.name.is_some(), weak(a)),
        Object::Mutex(a) => (MUTEX, a.name.is_some(), weak(a)),
        Object::Semaphore(a) => (EVENT, false, weak(a)), // OSyx semaphores have no names
        Object::Section(a) => (SECTION, a.name.is_some(), weak(a)),
        Object::Token(a) => (TOKEN, true, weak(&a.state)),
        Object::Port(a) => (EVENT, false, weak(a)),
        Object::Job(a) => (JOB, false, weak(a)),
        Object::Thread(t) => (THREAD, true, (Key::Thread(t.tid.load(core::sync::atomic::Ordering::SeqCst) as u64), None)),
        Object::Process(p) if p.pid == kernel32::pid() => (PROCESS, true, (Key::ThisProcess, None)),
        Object::Process(a) => (PROCESS, true, weak(a)),
        Object::WindowStation(a) => (WINSTA, true, weak(a)),
        Object::Desktop(a) => (DESKTOP, true, weak(a)),
        Object::File(_) | Object::Console(_) | Object::Null | Object::Pipe(_) | Object::Directory(_) | Object::Transaction(_) => return Err(ERROR_NOT_SUPPORTED),
    };
    Ok(Target { key, alive, mapping, secured })
}
fn stored(t: &Target) -> Sd {
    let mut s = STORE.lock().unwrap();
    s.retain(|_, v| v.alive.as_ref().is_none_or(|w| w.strong_count() > 0));
    if let Some(v) = s.get(&t.key) {
        return v.sd.clone();
    }
    let sd = default_sd(&tokens::effective_data(), &t.mapping);
    s.insert(t.key, Stored { alive: t.alive.clone(), sd: sd.clone() });
    sd
}

fn store(t: &Target, sd: Sd) {
    STORE.lock().unwrap().insert(t.key, Stored { alive: t.alive.clone(), sd });
}

/// The descriptor of a window station or desktop being created with
/// `sa` (default security when NULL).
pub fn set_initial(h: u64, sd: Option<Sd>) {
    if let (Ok(t), Some(sd)) = (target(h), sd) {
        store(&t, sd);
    }
}

// ---- files -----------------------------------------------------------------------------

const R: u32 = 4;
const W: u32 = 2;
const X: u32 = 1;
const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const FILE_EXECUTE: u32 = 0x20;
const FILE_DELETE_CHILD: u32 = 0x40;
const DELETE: u32 = 0x1_0000;

fn bits_mask(bits: u32, dir: bool) -> u32 {
    let mut m = 0;
    if bits & R != 0 {
        m |= FILE[0];
    }
    if bits & W != 0 {
        m |= FILE[1] | if dir { FILE_DELETE_CHILD } else { 0 };
    }
    if bits & X != 0 {
        m |= FILE[2];
    }
    m
}

fn mask_bits(mask: u32) -> u32 {
    let m = map_generic(mask, &FILE);
    let mut b = 0;
    if m & FILE_READ_DATA != 0 {
        b |= R;
    }
    if m & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0 {
        b |= W;
    }
    if m & FILE_EXECUTE != 0 {
        b |= X;
    }
    b
}

fn everyone() -> Vec<u8> {
    sid(1, &[0])
}

/// BUILTIN\Users (S-1-5-32-545).
fn users() -> Vec<u8> {
    sid(5, &[32, 545])
}

/// NT AUTHORITY\Authenticated Users (S-1-5-11).
fn authenticated_users() -> Vec<u8> {
    sid(5, &[11])
}

fn administrators() -> Vec<u8> {
    sid(5, &[32, 544])
}

fn system() -> Vec<u8> {
    sid(5, &[18])
}

fn file_sd(st: &osyx_abi::FileStat) -> Sd {
    let dir = st.kind == osyx_abi::KIND_DIR;
    let full = FILE[3] | WRITE_DAC | WRITE_OWNER;
    let owner_mask = bits_mask(st.mode >> 6 & 7, dir) | READ_CONTROL | WRITE_DAC | DELETE;
    let aces = alloc::vec![
        (ACCESS_ALLOWED, 0, owner_mask, tokens::user_sid(st.uid)),
        (ACCESS_ALLOWED, 0, bits_mask(st.mode >> 3 & 7, dir), tokens::group_sid(st.gid)),
        (ACCESS_ALLOWED, 0, bits_mask(st.mode & 7, dir), everyone()),
        (ACCESS_ALLOWED, 0, full, administrators()),
    ];
    Sd { owner: tokens::user_sid(st.uid), group: tokens::group_sid(st.gid), dacl: Some(aces), sacl: Vec::new(), control: 0 }
}

/// The mode a DACL gives a file of `st`, if the mode can express it.
fn dacl_mode(st: &osyx_abi::FileStat, dacl: &Option<Vec<Ace>>) -> Result<u32, u32> {
    let Some(aces) = dacl else { return Ok(0o777) };
    let (user, group) = (tokens::user_sid(st.uid), tokens::group_sid(st.gid));
    let (mut u, mut g, mut o) = (0, 0, 0);
    for (kind, flags, mask, s) in aces {
        if *kind != ACCESS_ALLOWED || flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE) != 0 {
            return Err(ERROR_NOT_SUPPORTED);
        }
        let bits = mask_bits(*mask);
        if *s == user {
            u |= bits;
        } else if *s == group {
            g |= bits;
        } else if *s == everyone() || *s == users() || *s == authenticated_users() {
            // OSyx has no group of all users other than "others".
            o |= bits;
        } else if *s != administrators() && *s != system() {
            return Err(ERROR_NOT_SUPPORTED); // OSyx files have no other principals
        }
    }
    // Everyone's rights reach the owner and the group too.
    Ok((u | o) << 6 | (g | o) << 3 | o)
}

/// An OSyx path from a Windows name.
fn file_path(name: &str) -> Result<String, u32> {
    let p = path::to_osyx(name, &kernel32::cwd_win())?;
    match path::resolve(&p) {
        Ok((p, true)) => Ok(p),
        _ => Err(ERROR_FILE_NOT_FOUND),
    }
}

fn get_file(p: &str) -> Result<Sd, u32> {
    os_sys::stat(p).map(|st| file_sd(&st)).map_err(errno_to_win32)
}

fn set_file(p: &str, info: u32, owner: Option<&[u8]>, group: Option<&[u8]>, dacl: Option<&Option<Vec<Ace>>>, sacl: Option<&[Ace]>) -> Result<(), u32> {
    let st = os_sys::stat(p).map_err(errno_to_win32)?;
    let current = file_sd(&st);
    if owner.is_some_and(|o| o != current.owner) || group.is_some_and(|g| g != current.group) {
        return Err(ERROR_NOT_SUPPORTED); // no chown on OSyx
    }
    if info & (SACL | LABEL) != 0 && sacl.is_some_and(|s| !s.is_empty()) {
        return Err(ERROR_NOT_SUPPORTED); // no labels or auditing on OSyx files
    }
    if let Some(d) = dacl {
        let mode = dacl_mode(&st, d)?;
        if mode != st.mode & 0o777 {
            os_sys::chmod(p, mode).map_err(errno_to_win32)?;
        }
    }
    Ok(())
}

/// Apply the requested parts of a file descriptor using the same native
/// permission mapping as SetNamedSecurityInfoW.
pub(crate) fn set_file_security(name: *const u16, info: u32, sd: *const u8) -> Result<(), u32> {
    if info == 0 || info & !(OWNER | GROUP | DACL | SACL) != 0 { return Err(ERROR_INVALID_PARAMETER); }
    let name = unsafe { path::wide_to_string(name) }.ok_or(ERROR_INVALID_PARAMETER)?;
    let (owner, group, dacl, sacl, _) = unsafe { parse_sd(sd) }?;
    if info & OWNER != 0 && owner.is_none() || info & GROUP != 0 && group.is_none() ||
       info & DACL != 0 && dacl.is_none() || info & SACL != 0 && sacl.is_none() {
        return Err(ERROR_INVALID_SECURITY_DESCR);
    }
    check_get_info(info & SACL)?;
    let file = file_path(&name)?;
    set_file(&file, info,
        if info & OWNER != 0 { owner.as_deref() } else { None },
        if info & GROUP != 0 { group.as_deref() } else { None },
        if info & DACL != 0 { dacl.as_ref() } else { None },
        if info & SACL != 0 { sacl.as_deref() } else { None })
}

/// The security descriptor of an object created with SECURITY_ATTRIBUTES
/// `sa` (NULL: the token's default security).
pub fn initial_sd(sa: u64, mapping: &Mapping) -> Result<Option<Sd>, u32> {
    if sa == 0 {
        return Ok(None);
    }
    // SAFETY: the caller's SECURITY_ATTRIBUTES (24 bytes).
    let (len, sd, inherit) = unsafe { (*(sa as *const u32), *((sa + 8) as *const u64), *((sa + 16) as *const i32)) };
    if len != 24 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let _ = inherit; // callers decide whether their handles can be inherited
    if sd == 0 {
        return Ok(None);
    }
    let mut out = default_sd(&tokens::effective_data(), mapping);
    // SAFETY: the caller's descriptor.
    let (owner, group, dacl, sacl) = unsafe { sd_parts(sd as *const u8) }?;
    if let Some(o) = owner {
        out.owner = o;
    }
    if let Some(g) = group {
        out.group = g;
    }
    if let Some(d) = dacl {
        out.dacl = d.map(|aces| aces.into_iter().map(|(k, f, m, s)| (k, f, map_generic(m, mapping), s)).collect());
    }
    if let Some(s) = sacl {
        if s.iter().any(|a| a.0 != MANDATORY_LABEL) {
            return Err(ERROR_NOT_SUPPORTED); // no auditing on OSyx
        }
        out.sacl = s;
    }
    Ok(Some(out))
}

/// Applies the descriptor of a new file or directory's SECURITY_ATTRIBUTES
/// to it: its DACL becomes the mode (see `dacl_mode`). Inheritable ACEs
/// describe what children get; OSyx gives new files their own mode, so
/// inherit-only ACEs are left out and the rest apply to the object itself.
pub fn apply_new_file_sd(p: &str, sd: u64) -> Result<(), u32> {
    // SAFETY: the caller's descriptor; sd_parts reads its native guest layout.
    let (owner, group, dacl, sacl) = unsafe { sd_parts(sd as *const u8) }?;
    let dacl = dacl.map(|d| {
        d.map(|aces| {
            aces.into_iter()
                .filter(|a| a.1 & INHERIT_ONLY_ACE == 0)
                .map(|(k, f, m, s)| (k, f & !(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE), m, s))
                .collect()
        })
    });
    // OSyx files record only a uid and a gid: the creating user stays the
    // owner. Windows lets a caller name itself or a group of its token that
    // may own objects (Administrators for an administrator) as the owner of
    // a new object, and does not check the primary group at all; any other
    // owner is refused as there.
    if let Some(o) = &owner {
        let token = tokens::effective();
        let data = tokens::effective_data();
        let assignable = *o == tokens::user_sid(token.uid)
            || tokens::groups(token.uid, token.gid, &data).iter().any(|(s, a)| s == o && a & tokens::SE_GROUP_OWNER != 0);
        if !assignable {
            return Err(ERROR_INVALID_OWNER);
        }
    }
    let r = set_file(p, DACL, None, None, dacl.as_ref(), sacl.as_deref());
    if r.is_err() && crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
        os_std::eprintln!("winrun: new file security not supported for {p}: owner {} group {} dacl {:?}", owner.is_some(), group.is_some(), dacl.as_ref().map(|d| d.as_ref().map(|a| a.iter().map(|x| (x.0, x.1, x.2, sid_string(&x.3))).collect::<Vec<_>>())));
    }
    r
}

// ---- changing descriptors ---------------------------------------------------------------

/// Applies the parts `info` names to `sd`, checking them against the
/// caller's token.
fn apply(sd: &mut Sd, info: u32, owner: Option<Vec<u8>>, group: Option<Vec<u8>>, dacl: Option<Option<Vec<Ace>>>, sacl: Option<Vec<Ace>>, m: &Mapping) -> Result<(), u32> {
    let token = tokens::effective();
    let d = tokens::effective_data();
    if info & OWNER != 0 {
        let o = owner.ok_or(ERROR_INVALID_OWNER)?;
        let ok = o == tokens::user_sid(token.uid)
            || tokens::groups(token.uid, token.gid, &d).iter().any(|(s, a)| *s == o && a & tokens::SE_GROUP_OWNER != 0);
        if !ok {
            return Err(ERROR_INVALID_OWNER);
        }
        sd.owner = o;
    }
    if info & GROUP != 0 {
        sd.group = group.ok_or(ERROR_INVALID_PARAMETER)?;
    }
    if info & DACL != 0 {
        let dacl = dacl.unwrap_or(None);
        sd.dacl = dacl.map(|aces| aces.into_iter().map(|(k, f, mask, s)| (k, f, map_generic(mask, m), s)).collect());
    }
    if info & PROTECTED_DACL != 0 {
        sd.control |= SE_DACL_PROTECTED;
    } else if info & UNPROTECTED_DACL != 0 {
        sd.control &= !SE_DACL_PROTECTED;
    }
    if info & PROTECTED_SACL != 0 {
        sd.control |= SE_SACL_PROTECTED;
    } else if info & UNPROTECTED_SACL != 0 {
        sd.control &= !SE_SACL_PROTECTED;
    }
    let new = sacl.unwrap_or_default();
    if info & SACL != 0 {
        if !d.privileges.iter().any(|p| p.0 == tokens::SE_SECURITY_PRIVILEGE && p.1 & tokens::SE_PRIVILEGE_ENABLED != 0) {
            return Err(ERROR_PRIVILEGE_NOT_HELD);
        }
        if new.iter().any(|a| a.0 == SYSTEM_AUDIT) {
            return Err(ERROR_NOT_SUPPORTED); // OSyx has no auditing
        }
        sd.sacl.retain(|a| a.0 != SYSTEM_AUDIT);
    }
    if info & LABEL != 0 {
        let labels: Vec<Ace> = new.iter().filter(|a| a.0 == MANDATORY_LABEL).cloned().collect();
        if labels.len() > 1 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        if let Some(l) = labels.first() {
            let level = label_level(&l.3).ok_or(ERROR_INVALID_SID)?;
            // Raising a label above one's own integrity needs SeRelabelPrivilege.
            if level > d.integrity {
                return Err(ERROR_PRIVILEGE_NOT_HELD);
            }
            if l.2 & !(NO_WRITE_UP | NO_READ_UP | NO_EXECUTE_UP) != 0 {
                return Err(ERROR_INVALID_PARAMETER);
            }
        }
        sd.sacl.retain(|a| a.0 != MANDATORY_LABEL);
        sd.sacl.extend(labels);
    }
    Ok(())
}

fn set_object(h: u64, kind: Option<u32>, info: u32, parts: Parts) -> Result<(), u32> {
    if info & !KNOWN_INFO != 0 {
        return Err(ERROR_NOT_SUPPORTED); // attribute, scope and trust labels
    }
    if let Some(Object::File(f)) = objects::get(h) {
        if kind.is_some_and(|k| k != SE_FILE_OBJECT && k != SE_KERNEL_OBJECT) {
            return Err(ERROR_INVALID_PARAMETER);
        }
        return set_file(&f.path, info, parts.0.as_deref(), parts.1.as_deref(), parts.2.as_ref(), parts.3.as_deref());
    }
    let t = target(h)?;
    // Window stations and desktops are kernel objects too: either type works.
    if kind.is_some_and(|k| k != SE_KERNEL_OBJECT && k != SE_WINDOW_OBJECT) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if !t.secured {
        return Err(ERROR_NO_SECURITY_ON_OBJECT);
    }
    let mut sd = stored(&t);
    apply(&mut sd, info, parts.0, parts.1, parts.2, parts.3, &t.mapping)?;
    store(&t, sd);
    Ok(())
}

/// (owner, group, DACL, SACL) given to a Set call.
type Parts = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Option<Vec<Ace>>>, Option<Vec<Ace>>);

/// The Set*SecurityInfo arguments as parts; a NULL DACL pointer is a
/// NULL DACL.
fn parts(info: u32, owner: *const u8, group: *const u8, dacl: *const u8, sacl: *const u8) -> Result<Parts, u32> {
    // SAFETY: NULL or the caller's SIDs and ACLs, validated here.
    unsafe {
        let s = |p: *const u8| if p.is_null() { Ok(None) } else { sid_bytes(p).map(Some) };
        let acl = |p: *const u8| if p.is_null() { Ok(None) } else { acl_aces(p).map(Some).map_err(|_| ERROR_INVALID_ACL) };
        Ok((
            if info & OWNER != 0 { s(owner)? } else { None },
            if info & GROUP != 0 { s(group)? } else { None },
            if info & DACL != 0 { Some(acl(dacl)?) } else { None },
            if info & (SACL | LABEL) != 0 { Some(acl(sacl)?.unwrap_or_default()) } else { None },
        ))
    }
}

// ---- the API ---------------------------------------------------------------------------------

/// The descriptor of an object without security: nothing present.
const EMPTY: [u8; 20] = [1, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Copies a self-relative descriptor to LocalAlloc memory and writes the
/// part pointers into it.
fn hand_out(bytes: &[u8], owner: *mut u64, group: *mut u64, dacl: *mut u64, sacl: *mut u64, out: *mut u64) -> u32 {
    if out.is_null() && !(owner.is_null() && group.is_null() && dacl.is_null() && sacl.is_null()) {
        return ERROR_INVALID_PARAMETER;
    }
    let Some(p) = kernel32::heap_alloc(bytes.len(), false) else { return ERROR_NOT_ENOUGH_MEMORY };
    // SAFETY: a fresh allocation of bytes.len() bytes; the caller's pointers.
    unsafe {
        copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len());
        let at = |field: usize| {
            let off = rd::<u32>(p as *const u8, 4 + field * 4) as u64;
            if off == 0 { 0 } else { p + off }
        };
        for (ptr, field) in [(owner, 0), (group, 1), (sacl, 2), (dacl, 3)] {
            if !ptr.is_null() {
                *ptr = at(field);
            }
        }
        if out.is_null() {
            kernel32::heap_free(p);
        } else {
            *out = p;
        }
    }
    ERROR_SUCCESS
}

/// An object's descriptor; None for an object without security.
fn get_object(h: u64, kind: u32) -> Result<Option<Sd>, u32> {
    if let Some(Object::File(f)) = objects::get(h) {
        return if kind == SE_FILE_OBJECT || kind == SE_KERNEL_OBJECT { get_file(&f.path).map(Some) } else { Err(ERROR_INVALID_PARAMETER) };
    }
    let t = target(h)?;
    match kind {
        SE_KERNEL_OBJECT | SE_WINDOW_OBJECT => Ok(t.secured.then(|| stored(&t))),
        SE_FILE_OBJECT => Err(ERROR_INVALID_PARAMETER),
        _ => Err(ERROR_NOT_SUPPORTED), // services, printers, registry keys, shares
    }
}

fn check_get_info(info: u32) -> Result<(), u32> {
    if info & !(OWNER | GROUP | DACL | SACL | LABEL) != 0 {
        return Err(ERROR_NOT_SUPPORTED);
    }
    if info & SACL != 0 {
        let d = tokens::effective_data();
        if !d.privileges.iter().any(|p| p.0 == tokens::SE_SECURITY_PRIVILEGE && p.1 & tokens::SE_PRIVILEGE_ENABLED != 0) {
            return Err(ERROR_PRIVILEGE_NOT_HELD);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn GetSecurityInfo(h: u64, kind: u32, info: u32, owner: *mut u64, group: *mut u64, dacl: *mut u64, sacl: *mut u64, out: *mut u64) -> u32 {
    match check_get_info(info).and_then(|()| get_object(h, kind)) {
        Ok(Some(sd)) => hand_out(&to_relative(&sd, info), owner, group, dacl, sacl, out),
        Ok(None) => hand_out(&EMPTY, owner, group, dacl, sacl, out),
        Err(e) => e,
    }
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn GetNamedSecurityInfoW(name: *const u16, kind: u32, info: u32, owner: *mut u64, group: *mut u64, dacl: *mut u64, sacl: *mut u64, out: *mut u64) -> u32 {
    // SAFETY: NUL-terminated name.
    let Some(name) = (unsafe { path::wide_to_string(name) }) else { return ERROR_INVALID_PARAMETER };
    if kind != SE_FILE_OBJECT {
        return ERROR_NOT_SUPPORTED; // named kernel objects, services, registry keys
    }
    match check_get_info(info).and_then(|()| file_path(&name)).and_then(|p| get_file(&p)) {
        Ok(sd) => hand_out(&to_relative(&sd, info), owner, group, dacl, sacl, out),
        Err(e) => e,
    }
}

extern "win64" fn SetSecurityInfo(h: u64, kind: u32, info: u32, owner: *const u8, group: *const u8, dacl: *const u8, sacl: *const u8) -> u32 {
    match parts(info, owner, group, dacl, sacl).and_then(|p| set_object(h, Some(kind), info, p)) {
        Ok(()) => ERROR_SUCCESS,
        Err(e) => e,
    }
}

extern "win64" fn SetNamedSecurityInfoW(name: *mut u16, kind: u32, info: u32, owner: *const u8, group: *const u8, dacl: *const u8, sacl: *const u8) -> u32 {
    // SAFETY: NUL-terminated name.
    let Some(name) = (unsafe { path::wide_to_string(name) }) else { return ERROR_INVALID_PARAMETER };
    if kind != SE_FILE_OBJECT {
        return ERROR_NOT_SUPPORTED;
    }
    if info & !KNOWN_INFO != 0 {
        return ERROR_NOT_SUPPORTED;
    }
    let r = parts(info, owner, group, dacl, sacl)
        .and_then(|p| file_path(&name).and_then(|f| set_file(&f, info, p.0.as_deref(), p.1.as_deref(), p.2.as_ref(), p.3.as_deref())));
    match r {
        Ok(()) => ERROR_SUCCESS,
        Err(e) => e,
    }
}

extern "win64" fn SetKernelObjectSecurity(h: u64, info: u32, sd: *const u8) -> i32 {
    // SAFETY: the caller's descriptor, validated by parse_sd.
    let parsed = match unsafe { parse_sd(sd) } {
        Ok(p) => p,
        Err(e) => return fail(e, 0),
    };
    let (owner, group, dacl, sacl, _) = parsed;
    let parts: Parts = (
        owner.filter(|_| info & OWNER != 0),
        group.filter(|_| info & GROUP != 0),
        if info & DACL != 0 { Some(dacl.unwrap_or(None)) } else { None },
        if info & (SACL | LABEL) != 0 { Some(sacl.unwrap_or_default()) } else { None },
    );
    match set_object(h, None, info, parts) {
        Ok(()) => 1,
        Err(e) => fail(e, 0),
    }
}

extern "win64" fn GetKernelObjectSecurity(h: u64, info: u32, out: *mut u8, size: u32, needed: *mut u32) -> i32 {
    if needed.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let bytes = match check_get_info(info).and_then(|()| {
        if let Some(Object::File(f)) = objects::get(h) { get_file(&f.path).map(Some) } else { target(h).map(|t| t.secured.then(|| stored(&t))) }
    }) {
        Ok(Some(sd)) => to_relative(&sd, info),
        Ok(None) => EMPTY.to_vec(),
        Err(e) => return fail(e, 0),
    };
    // SAFETY: the caller's out pointers; `size` bytes at `out`.
    unsafe {
        *needed = bytes.len() as u32;
        if out.is_null() || (size as usize) < bytes.len() {
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    }
    1
}

// ---- building ACLs -------------------------------------------------------------------------

// TRUSTEE_FORM.
const TRUSTEE_IS_SID: u32 = 0;
const TRUSTEE_IS_NAME: u32 = 1;
const TRUSTEE_IS_OBJECTS_AND_SID: u32 = 3;
const TRUSTEE_IS_OBJECTS_AND_NAME: u32 = 4;

/// The SID a TRUSTEE_W names.
fn trustee_sid(t: *const u8) -> Result<Vec<u8>, u32> {
    // SAFETY: the caller's TRUSTEE_W (32 bytes).
    let (multiple, op, form, name) = unsafe { (rd::<u64>(t, 0), rd::<u32>(t, 8), rd::<u32>(t, 12), rd::<u64>(t, 24)) };
    if multiple != 0 || op != 0 {
        return Err(ERROR_NOT_SUPPORTED); // impersonation trustees
    }
    match form {
        // SAFETY: the trustee's SID.
        TRUSTEE_IS_SID => unsafe { sid_bytes(name as *const u8) },
        TRUSTEE_IS_NAME => {
            // SAFETY: the trustee's NUL-terminated name.
            let n = unsafe { path::wide_to_string(name as *const u16) }.ok_or(ERROR_INVALID_PARAMETER)?;
            if n.eq_ignore_ascii_case("CURRENT_USER") {
                Ok(tokens::user_sid(tokens::effective().uid))
            } else {
                string_sid(&n).ok_or(ERROR_NONE_MAPPED)
            }
        }
        // Object ACEs (directory service objects) are not supported.
        TRUSTEE_IS_OBJECTS_AND_SID | TRUSTEE_IS_OBJECTS_AND_NAME => Err(ERROR_NOT_SUPPORTED),
        _ => Err(ERROR_INVALID_PARAMETER),
    }
}

extern "win64" fn BuildTrusteeWithSidW(t: *mut u8, s: *const u8) {
    if t.is_null() {
        return;
    }
    // SAFETY: the caller's TRUSTEE_W.
    unsafe {
        wr(t, 0, 0u64);
        wr(t, 8, 0u32); // NO_MULTIPLE_TRUSTEE
        wr(t, 12, TRUSTEE_IS_SID);
        wr(t, 16, 0u32); // TRUSTEE_IS_UNKNOWN
        wr(t, 24, s as u64);
    }
}

// ACCESS_MODE.
const GRANT_ACCESS: u32 = 1;
const SET_ACCESS: u32 = 2;
const DENY_ACCESS: u32 = 3;
const REVOKE_ACCESS: u32 = 4;
const SET_AUDIT_SUCCESS: u32 = 5;
const SET_AUDIT_FAILURE: u32 = 6;

/// Adds an ACE, merging it into an explicit one of the same kind, flags
/// and trustee.
fn merge(list: &mut Vec<Ace>, ace: Ace) {
    match list.iter_mut().find(|a| a.0 == ace.0 && a.1 == ace.1 && a.3 == ace.3) {
        Some(a) => a.2 |= ace.2,
        None => list.push(ace),
    }
}

/// SetEntriesInAcl: the old ACL's ACEs with the entries applied, in
/// canonical order (explicit deny, explicit allow and audit, inherited).
fn entries_in_acl(entries: &[(u32, u32, u32, Vec<u8>)], old: Vec<Ace>) -> Result<Vec<Ace>, u32> {
    let (inherited, mut explicit): (Vec<Ace>, Vec<Ace>) = old.into_iter().partition(|a| a.1 & INHERITED_ACE != 0);
    for (_, mode, _, s) in entries {
        match *mode {
            SET_ACCESS => explicit.retain(|a| !((a.0 == ACCESS_ALLOWED || a.0 == ACCESS_DENIED) && a.3 == *s)),
            REVOKE_ACCESS => explicit.retain(|a| !((a.0 == ACCESS_ALLOWED || a.0 == SYSTEM_AUDIT) && a.3 == *s)),
            _ => {}
        }
    }
    let (mut deny, mut rest): (Vec<Ace>, Vec<Ace>) = explicit.into_iter().partition(|a| a.0 == ACCESS_DENIED);
    for (mask, mode, inherit, s) in entries {
        let flags = (*inherit & 0x1f) as u8;
        if inherit & !0x1f != 0 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        match *mode {
            0 | REVOKE_ACCESS => {}
            GRANT_ACCESS | SET_ACCESS => merge(&mut rest, (ACCESS_ALLOWED, flags, *mask, s.clone())),
            DENY_ACCESS => merge(&mut deny, (ACCESS_DENIED, flags, *mask, s.clone())),
            SET_AUDIT_SUCCESS => merge(&mut rest, (SYSTEM_AUDIT, flags | SUCCESSFUL_ACCESS_ACE_FLAG, *mask, s.clone())),
            SET_AUDIT_FAILURE => merge(&mut rest, (SYSTEM_AUDIT, flags | FAILED_ACCESS_ACE_FLAG, *mask, s.clone())),
            _ => return Err(ERROR_INVALID_PARAMETER),
        }
    }
    deny.extend(rest);
    deny.extend(inherited);
    Ok(deny)
}

extern "win64" fn SetEntriesInAclW(count: u32, list: *const u8, old: *const u8, out: *mut u64) -> u32 {
    if out.is_null() || (count != 0 && list.is_null()) {
        return ERROR_INVALID_PARAMETER;
    }
    let mut entries = Vec::new();
    for i in 0..count as usize {
        // SAFETY: the caller's EXPLICIT_ACCESS_W array (48 bytes each).
        let e = unsafe { list.add(i * 48) };
        let (mask, mode, inherit) = unsafe { (rd::<u32>(e, 0), rd::<u32>(e, 4), rd::<u32>(e, 8)) };
        if mode == 0 {
            continue; // NOT_USED_ACCESS
        }
        match trustee_sid(unsafe { e.add(16) }) {
            Ok(s) => entries.push((mask, mode, inherit, s)),
            Err(e) => return e,
        }
    }
    // SAFETY: NULL or the caller's ACL.
    let old_aces = if old.is_null() {
        None
    } else {
        match unsafe { acl_aces(old) } {
            Ok(a) => Some(a),
            Err(_) => return ERROR_INVALID_ACL,
        }
    };
    if entries.is_empty() && old_aces.is_none() {
        // SAFETY: the caller's out pointer.
        unsafe { *out = 0 };
        return ERROR_SUCCESS;
    }
    let aces = match entries_in_acl(&entries, old_aces.unwrap_or_default()) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let acl = build_acl(&aces);
    let Some(p) = kernel32::heap_alloc(acl.len(), false) else { return ERROR_NOT_ENOUGH_MEMORY };
    // SAFETY: a fresh allocation; the caller's out pointer.
    unsafe {
        copy_nonoverlapping(acl.as_ptr(), p as *mut u8, acl.len());
        *out = p;
    }
    ERROR_SUCCESS
}

extern "win64" fn AddMandatoryAce(acl: *mut u8, revision: u32, flags: u32, policy: u32, label: *const u8) -> i32 {
    // SAFETY: NULL or the caller's SID.
    let level = unsafe { sid_bytes(label) }.ok().and_then(|s| label_level(&s));
    if level.is_none() || policy & !(NO_WRITE_UP | NO_READ_UP | NO_EXECUTE_UP) != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    security::add_ace(acl, revision, flags, policy, label, MANDATORY_LABEL)
}

extern "win64" fn MapGenericMask(mask: *mut u32, m: *const u32) {
    if mask.is_null() || m.is_null() {
        return;
    }
    // SAFETY: the caller's mask and GENERIC_MAPPING.
    unsafe {
        let mapping = [*m, *m.add(1), *m.add(2), *m.add(3)];
        *mask = map_generic(*mask, &mapping);
    }
}

// ---- SIDs as strings and on the heap ---------------------------------------------------------

/// SDDL SID aliases that need no domain.
const ALIASES: &[(&str, u64, &[u32])] = &[
    ("WD", 1, &[0]),
    ("CO", 3, &[0]),
    ("CG", 3, &[1]),
    ("OW", 3, &[4]),
    ("NU", 5, &[2]),
    ("IU", 5, &[4]),
    ("SU", 5, &[6]),
    ("AN", 5, &[7]),
    ("ED", 5, &[9]),
    ("PS", 5, &[10]),
    ("AU", 5, &[11]),
    ("RC", 5, &[12]),
    ("SY", 5, &[18]),
    ("LS", 5, &[19]),
    ("NS", 5, &[20]),
    ("WR", 5, &[33]),
    ("BA", 5, &[32, 544]),
    ("BU", 5, &[32, 545]),
    ("BG", 5, &[32, 546]),
    ("PU", 5, &[32, 547]),
    ("AO", 5, &[32, 548]),
    ("SO", 5, &[32, 549]),
    ("PO", 5, &[32, 550]),
    ("BO", 5, &[32, 551]),
    ("RE", 5, &[32, 552]),
    ("RU", 5, &[32, 554]),
    ("RD", 5, &[32, 555]),
    ("NO", 5, &[32, 556]),
    ("MU", 5, &[32, 558]),
    ("LU", 5, &[32, 559]),
    ("AC", 15, &[2, 1]),
    ("LW", 16, &[4096]),
    ("ME", 16, &[8192]),
    ("MP", 16, &[8448]),
    ("HI", 16, &[12288]),
    ("SI", 16, &[16384]),
    ("UD", 5, &[84, 0, 0, 0, 0, 0]),
];

/// A SID from its string form ("S-1-5-32-544") or an SDDL alias ("BA").
pub fn string_sid(s: &str) -> Option<Vec<u8>> {
    if let Some(a) = ALIASES.iter().find(|a| a.0.eq_ignore_ascii_case(s)) {
        return Some(sid(a.1, a.2));
    }
    let mut parts = s.split('-');
    if !parts.next()?.eq_ignore_ascii_case("S") || parts.next()? != "1" {
        return None;
    }
    let auth = parts.next()?;
    let authority = if let Some(hex) = auth.strip_prefix("0x").or_else(|| auth.strip_prefix("0X")) {
        if hex.len() != 12 {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()?
    } else {
        let v: u64 = auth.parse().ok()?;
        if v > u32::MAX as u64 || auth.starts_with('+') {
            return None;
        }
        v
    };
    let mut sub = Vec::new();
    for p in parts {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        sub.push(p.parse::<u32>().ok()?);
    }
    (sub.len() <= 15).then(|| sid(authority, &sub))
}

/// A heap copy of `bytes` (LocalFree / FreeSid releases it).
fn heap_copy(bytes: &[u8]) -> Option<u64> {
    let p = kernel32::heap_alloc(bytes.len(), false)?;
    // SAFETY: a fresh allocation of bytes.len() bytes.
    unsafe { copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len()) };
    Some(p)
}

extern "win64" fn ConvertStringSidToSidW(s: *const u16, out: *mut u64) -> i32 {
    if s.is_null() || out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: NUL-terminated string.
    let Some(v) = (unsafe { path::wide_to_string(s) }).and_then(|t| string_sid(&t)) else { return fail(ERROR_INVALID_SID, 0) };
    match heap_copy(&v) {
        // SAFETY: the caller's out pointer.
        Some(p) => unsafe {
            *out = p;
            1
        },
        None => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// The string form of a valid SID.
pub fn sid_string(s: &[u8]) -> String {
    let auth = s[2..8].iter().fold(0u64, |a, &b| a << 8 | b as u64);
    let mut out = if auth >> 32 == 0 { alloc::format!("S-1-{auth}") } else { alloc::format!("S-1-0x{auth:012X}") };
    for i in 0..s[1] as usize {
        let at = 8 + i * 4;
        out.push_str(&alloc::format!("-{}", u32::from_le_bytes([s[at], s[at + 1], s[at + 2], s[at + 3]])));
    }
    out
}

extern "win64" fn ConvertSidToStringSidW(s: *const u8, out: *mut u64) -> i32 {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: NULL or the caller's SID.
    let Ok(v) = (unsafe { sid_bytes(s) }) else { return fail(ERROR_INVALID_SID, 0) };
    let mut w: Vec<u16> = sid_string(&v).encode_utf16().collect();
    w.push(0);
    // SAFETY: plain u16 data viewed as bytes.
    let bytes = unsafe { core::slice::from_raw_parts(w.as_ptr() as *const u8, w.len() * 2) };
    match heap_copy(bytes) {
        // SAFETY: the caller's out pointer.
        Some(p) => unsafe {
            *out = p;
            1
        },
        None => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn AllocateAndInitializeSid(
    authority: *const u8,
    count: u8,
    s0: u32,
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    s5: u32,
    s6: u32,
    s7: u32,
    out: *mut u64,
) -> i32 {
    if authority.is_null() || out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if count > 8 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's 6-byte SID_IDENTIFIER_AUTHORITY.
    let auth = (0..6).fold(0u64, |a, i| a << 8 | unsafe { *authority.add(i) } as u64);
    let v = sid(auth, &[s0, s1, s2, s3, s4, s5, s6, s7][..count as usize]);
    match heap_copy(&v) {
        // SAFETY: the caller's out pointer.
        Some(p) => unsafe {
            *out = p;
            1
        },
        None => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// Frees a SID from AllocateAndInitializeSid (or the userenv functions).
pub extern "win64" fn FreeSid(s: u64) -> u64 {
    if s != 0 && !kernel32::heap_free(s) {
        return s; // not a SID this process allocated
    }
    0
}

// ---- access checks ---------------------------------------------------------------------------

/// The rights the DACL grants a set of SIDs, and those it denies, walking
/// ACEs in order: a right is decided by the first ACE that names it.
fn walk(sd: &Sd, allow: &[Vec<u8>], deny: &[Vec<u8>], owner_rights: u32, m: &Mapping, wanted: u32) -> u32 {
    let Some(dacl) = &sd.dacl else { return m[3] | STANDARD_RIGHTS_ALL };
    let mut granted = owner_rights;
    let mut denied = 0;
    for (kind, flags, mask, s) in dacl {
        if flags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let mask = map_generic(*mask, m);
        match *kind {
            ACCESS_ALLOWED if allow.contains(s) => granted |= mask & !denied,
            ACCESS_DENIED if deny.contains(s) => denied |= mask & !granted,
            _ => {}
        }
        if granted & wanted == wanted && wanted != MAXIMUM_ALLOWED {
            break;
        }
    }
    granted
}

/// The access `token` (data `d`) gets to an object with descriptor `sd`.
pub fn check(t: &crate::security::Token, d: &TokenData, sd: &Sd, desired: u32, m: &Mapping) -> (u32, Vec<u32>) {
    let mut used_privileges = Vec::new();
    let enabled = |l: u32| d.privileges.iter().any(|p| p.0 == l && p.1 & tokens::SE_PRIVILEGE_ENABLED != 0);
    let (allow, deny) = tokens::access_sids(t.uid, t.gid, d);
    let owner_rights_sid = sid(3, &[4]);
    let has_owner_rights = sd.dacl.as_ref().is_some_and(|a| a.iter().any(|x| x.3 == owner_rights_sid));
    let mut allow_o = allow.clone();
    let mut deny_o = deny.clone();
    let is_owner = allow.contains(&sd.owner);
    if is_owner {
        allow_o.push(owner_rights_sid.clone());
        deny_o.push(owner_rights_sid.clone());
    }
    let implicit = if is_owner && !has_owner_rights { READ_CONTROL | WRITE_DAC } else { 0 };
    let wanted = desired & !(MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
    let mut granted = walk(sd, &allow_o, &deny_o, implicit, m, if desired & MAXIMUM_ALLOWED != 0 { MAXIMUM_ALLOWED } else { wanted });
    // A restricted token: the restricting SIDs must grant it too (only
    // write rights for a write-restricted token).
    if !d.restricting.is_empty() {
        let r = &d.restricting;
        let r_owner = r.contains(&sd.owner);
        let r_implicit = if r_owner && !has_owner_rights { READ_CONTROL | WRITE_DAC } else { 0 };
        let second = walk(sd, r, r, r_implicit, m, if desired & MAXIMUM_ALLOWED != 0 { MAXIMUM_ALLOWED } else { wanted });
        granted &= if d.write_restricted { second | !m[1] } else { second };
    }
    // Mandatory integrity.
    let (level, policy) = sd.label();
    if d.integrity < level {
        let mut blocked = 0;
        if policy & NO_WRITE_UP != 0 {
            blocked |= m[1] & !(READ_CONTROL | SYNCHRONIZE);
        }
        if policy & NO_READ_UP != 0 {
            blocked |= m[0] & !(READ_CONTROL | SYNCHRONIZE);
        }
        if policy & NO_EXECUTE_UP != 0 {
            blocked |= m[2] & !(READ_CONTROL | SYNCHRONIZE);
        }
        granted &= !blocked;
    }
    if desired & ACCESS_SYSTEM_SECURITY != 0 && enabled(tokens::SE_SECURITY_PRIVILEGE) {
        granted |= ACCESS_SYSTEM_SECURITY;
        used_privileges.push(tokens::SE_SECURITY_PRIVILEGE);
    }
    if desired & WRITE_OWNER != 0 && granted & WRITE_OWNER == 0 && enabled(tokens::SE_TAKE_OWNERSHIP_PRIVILEGE) {
        granted |= WRITE_OWNER;
        used_privileges.push(tokens::SE_TAKE_OWNERSHIP_PRIVILEGE);
    }
    (granted, used_privileges)
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn AccessCheck(
    sd: *const u8,
    token: u64,
    desired: u32,
    mapping: *const u32,
    privileges: *mut u8,
    privileges_len: *mut u32,
    granted_out: *mut u32,
    status: *mut i32,
) -> i32 {
    if mapping.is_null() || privileges_len.is_null() || granted_out.is_null() || status.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if desired & GENERIC_BITS != 0 {
        return fail(ERROR_GENERIC_NOT_MAPPED, 0);
    }
    let t = match tokens::token(token) {
        Ok(t) => t,
        Err(e) => return fail(e, 0),
    };
    if t.access & tokens::TOKEN_QUERY == 0 {
        return fail(ERROR_ACCESS_DENIED, 0);
    }
    let d = t.state.data.lock().unwrap().clone();
    if d.impersonation.is_none() {
        return fail(ERROR_NO_IMPERSONATION_TOKEN, 0);
    }
    if d.impersonation.is_some_and(|l| l < 1) {
        return fail(tokens::ERROR_BAD_IMPERSONATION_LEVEL, 0); // SecurityAnonymous
    }
    // SAFETY: the caller's descriptor, validated by parse_sd.
    let (owner, group, dacl, sacl, _) = match unsafe { parse_sd(sd) } {
        Ok(p) => p,
        Err(e) => return fail(e, 0),
    };
    let (Some(owner), Some(group)) = (owner, group) else { return fail(ERROR_INVALID_SECURITY_DESCR, 0) };
    // SAFETY: the caller's GENERIC_MAPPING.
    let m: Mapping = unsafe { [*mapping, *mapping.add(1), *mapping.add(2), *mapping.add(3)] };
    let sd = Sd { owner, group, dacl: dacl.unwrap_or(None), sacl: sacl.unwrap_or_default(), control: 0 };
    let (granted, used) = check(&t, &d, &sd, desired, &m);
    let need = 8 + 12 * used.len().max(1) as u32;
    // SAFETY: the caller's PRIVILEGE_SET of *privileges_len bytes.
    unsafe {
        if privileges.is_null() || *privileges_len < need {
            *privileges_len = need;
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        wr(privileges, 0, used.len() as u32);
        wr(privileges, 4, 0u32);
        for (i, l) in used.iter().enumerate() {
            wr(privileges, 8 + i * 12, *l);
            wr(privileges, 12 + i * 12, 0u32);
            wr(privileges, 16 + i * 12, 0x8000_0000u32); // SE_PRIVILEGE_USED_FOR_ACCESS
        }
    }
    let wanted = desired & !MAXIMUM_ALLOWED;
    let ok = granted & wanted == wanted && (desired & MAXIMUM_ALLOWED == 0 || granted != 0);
    // SAFETY: the caller's out pointers.
    unsafe {
        *granted_out = if !ok { 0 } else if desired & MAXIMUM_ALLOWED != 0 { granted } else { wanted };
        *status = ok as i32;
    }
    if !ok {
        crate::teb::set_last_error(ERROR_ACCESS_DENIED);
    }
    1
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        GetSecurityInfo,
        GetNamedSecurityInfoW,
        SetSecurityInfo,
        SetNamedSecurityInfoW,
        SetKernelObjectSecurity,
        GetKernelObjectSecurity,
        BuildTrusteeWithSidW,
        SetEntriesInAclW,
        AddMandatoryAce,
        MapGenericMask,
        ConvertStringSidToSidW,
        ConvertSidToStringSidW,
        AllocateAndInitializeSid,
        FreeSid,
        AccessCheck,
    ]
}
