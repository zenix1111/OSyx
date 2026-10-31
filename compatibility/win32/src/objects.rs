//! The per-process Windows handle table and the objects behind handles:
//! files (OSyx kernel file handles with Windows sharing and delete-on-close
//! rules on top), console streams, threads, events, mutexes and sections.
//!
//! Handle values are multiples of 4 from 0x100, like Windows'; the pseudo
//! handles -1 (current process) and -2 (current thread) are understood
//! where Windows accepts them. Kernel pointers never reach the program:
//! a handle is an index into this table.
//!
//! Waiting: every object that can become signalled bumps one global
//! sequence word and wakes its futex; waiters re-check their objects and
//! sleep on the word again. Simple, lossless, and bounded by the timeout.

use crate::error::*;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use os_std::sync::Mutex;
use os_std::time::{Duration, Instant};

pub const CURRENT_PROCESS: u64 = u64::MAX;
pub const CURRENT_THREAD: u64 = u64::MAX - 1;

// ---- access and sharing -----------------------------------------------------

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const FILE_READ_DATA: u32 = 0x1;
pub const FILE_WRITE_DATA: u32 = 0x2;
pub const FILE_APPEND_DATA: u32 = 0x4;
pub const DELETE: u32 = 0x1_0000;
pub const FILE_SHARE_READ: u32 = 1;
pub const FILE_SHARE_WRITE: u32 = 2;
pub const FILE_SHARE_DELETE: u32 = 4;

/// (read, write, delete) rights an access mask asks for.
pub fn rights(access: u32) -> (bool, bool, bool) {
    let all = access & GENERIC_ALL != 0;
    (
        all || access & (GENERIC_READ | GENERIC_EXECUTE | FILE_READ_DATA) != 0,
        all || access & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA) != 0,
        all || access & DELETE != 0,
    )
}

struct OpenRecord {
    id: u64,
    access: (bool, bool, bool),
    share: u32,
}

/// Open files by (volume, inode) for sharing-mode checks.
static SHARES: Mutex<BTreeMap<(u64, u64), Vec<OpenRecord>>> = Mutex::new(BTreeMap::new());
static NEXT_OPEN: AtomicU64 = AtomicU64::new(1);

/// Registers an open of (dev, ino); `ERROR_SHARING_VIOLATION` if it
/// conflicts with an existing open (either side's share mode).
pub fn share_open(key: (u64, u64), access: (bool, bool, bool), share: u32) -> Result<u64, u32> {
    let mut s = SHARES.lock().unwrap();
    let list = s.entry(key).or_default();
    for o in list.iter() {
        let conflict = (access.0 && o.share & FILE_SHARE_READ == 0)
            || (access.1 && o.share & FILE_SHARE_WRITE == 0)
            || (access.2 && o.share & FILE_SHARE_DELETE == 0)
            || (o.access.0 && share & FILE_SHARE_READ == 0)
            || (o.access.1 && share & FILE_SHARE_WRITE == 0)
            || (o.access.2 && share & FILE_SHARE_DELETE == 0);
        if conflict {
            return Err(ERROR_SHARING_VIOLATION);
        }
    }
    let id = NEXT_OPEN.fetch_add(1, Ordering::Relaxed);
    list.push(OpenRecord { id, access, share });
    Ok(id)
}

fn share_close(key: (u64, u64), id: u64) {
    let mut s = SHARES.lock().unwrap();
    if let Some(list) = s.get_mut(&key) {
        list.retain(|o| o.id != id);
        if list.is_empty() {
            s.remove(&key);
        }
    }
}

/// Whether anything holds (dev, ino) open without sharing delete access
/// (DeleteFile and MoveFile must then fail like on Windows).
pub fn delete_blocked(key: (u64, u64)) -> bool {
    SHARES.lock().unwrap().get(&key).is_some_and(|l| l.iter().any(|o| o.share & FILE_SHARE_DELETE == 0))
}

// ---- objects ----------------------------------------------------------------

/// The `key.0` of an anonymous pipe end (its `key.1` is the kernel handle).
pub const PIPE_DEV: u64 = u64::MAX;

pub struct FileObj {
    /// OSyx kernel file handle.
    pub fd: u64,
    /// Canonical OSyx path (for delete-on-close and names).
    pub path: String,
    pub access: (bool, bool, bool),
    pub key: (u64, u64),
    open_id: u64,
    pub is_dir: bool,
    pub delete_on_close: AtomicBool,
    pub append: bool,
}

impl FileObj {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fd: u64,
        path: String,
        access: (bool, bool, bool),
        key: (u64, u64),
        open_id: u64,
        is_dir: bool,
        delete_on_close: bool,
        append: bool,
    ) -> FileObj {
        FileObj { fd, path, access, key, open_id, is_dir, delete_on_close: AtomicBool::new(delete_on_close), append }
    }
}

impl Drop for FileObj {
    fn drop(&mut self) {
        let _ = os_sys::close(self.fd);
        share_close(self.key, self.open_id);
        crate::files::release_locks(self.key, self as *const FileObj as usize);
        if self.delete_on_close.load(Ordering::Relaxed) {
            let r = if self.is_dir { os_sys::rmdir(&self.path) } else { os_sys::unlink(&self.path) };
            let _ = r;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Console {
    In,
    Out,
    Err,
}

pub struct ThreadObj {
    pub tid: AtomicU32,
    pub done: AtomicBool,
    pub exit_code: AtomicU32,
    /// CREATE_SUSPENDED: the thread waits until this is cleared.
    pub suspended: AtomicU32,
    /// The thread's TEB (0 until it runs).
    pub teb: AtomicU64,
    /// Real-time clock (ns since the Unix epoch) at creation and at exit
    /// (0 while it runs), and the scheduler samples it used when it ended.
    pub created_ns: AtomicU64,
    pub exited_ns: AtomicU64,
    pub final_ticks: AtomicU64,
}

/// An event's state is one word: 1 signalled, 0 not. It lives in the
/// object until the event is passed to another process; then it moves to a
/// page of shared memory both processes map, and setting it also wakes
/// waiters there (a futex on shared memory).
pub struct EventObj {
    local: AtomicU32,
    /// The word in use: `local`, or the shared page.
    word: core::sync::atomic::AtomicPtr<AtomicU32>,
    /// The shared memory object and its mapping, once shared.
    shared: Mutex<Option<(u64, u64)>>,
    pub manual: bool,
    pub name: Option<String>,
}

impl EventObj {
    pub fn new(signaled: bool, manual: bool, name: Option<String>) -> Arc<EventObj> {
        let e = Arc::new(EventObj {
            local: AtomicU32::new(signaled as u32),
            word: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            shared: Mutex::new(None),
            manual,
            name,
        });
        e.word.store(&e.local as *const AtomicU32 as *mut AtomicU32, Ordering::SeqCst);
        e
    }

    /// An event whose state is the first word of shared memory object `shm`.
    pub fn from_shared(shm: u64, manual: bool) -> Option<Arc<EventObj>> {
        let base = os_sys::shm_map(shm, true).ok()? as u64;
        let e = Arc::new(EventObj {
            local: AtomicU32::new(0),
            word: core::sync::atomic::AtomicPtr::new(base as *mut AtomicU32),
            shared: Mutex::new(Some((shm, base))),
            manual,
            name: None,
        });
        Some(e)
    }

    fn word(&self) -> &AtomicU32 {
        // SAFETY: `local`, or the shared page this object keeps mapped.
        unsafe { &*self.word.load(Ordering::SeqCst) }
    }

    pub fn is_shared(&self) -> bool {
        self.shared.lock().unwrap().is_some()
    }

    pub fn is_set(&self) -> bool {
        self.word().load(Ordering::SeqCst) != 0
    }

    pub fn set(&self, on: bool) {
        self.word().store(on as u32, Ordering::SeqCst);
        if on {
            if self.is_shared() {
                os_sys::futex_wake(self.word().as_ptr(), u32::MAX);
            }
            signal_all();
        }
    }

    /// Resets an auto-reset event that is set; true if it was.
    pub fn take(&self) -> bool {
        self.word().compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    /// The shared memory object holding the state, moving it there first.
    pub fn share(&self) -> Result<u64, u32> {
        let mut s = self.shared.lock().unwrap();
        if let Some((shm, _)) = *s {
            return Ok(shm);
        }
        let shm = os_sys::shm_create(4096).map_err(errno_to_win32)?;
        let base = match os_sys::shm_map(shm, true) {
            Ok(b) => b as u64,
            Err(e) => {
                let _ = os_sys::close(shm);
                return Err(errno_to_win32(e));
            }
        };
        // SAFETY: the fresh page's first word.
        let w = unsafe { &*(base as *const AtomicU32) };
        w.store(self.local.load(Ordering::SeqCst), Ordering::SeqCst);
        self.word.store(base as *mut AtomicU32, Ordering::SeqCst);
        // A set that raced with the move landed in `local`: carry it over.
        if self.local.load(Ordering::SeqCst) != 0 {
            w.store(1, Ordering::SeqCst);
        }
        *s = Some((shm, base));
        Ok(shm)
    }

    /// The futex word waiters of a shared event sleep on.
    fn futex_word(&self) -> *const u32 {
        self.word().as_ptr()
    }
}

impl Drop for EventObj {
    fn drop(&mut self) {
        if let Some((shm, base)) = *self.shared.lock().unwrap() {
            // SAFETY: the mapping made in share/from_shared.
            let _ = unsafe { os_sys::unmap(base as *mut u8, 4096) };
            let _ = os_sys::close(shm);
        }
    }
}

pub struct TimerState {
    pub due: Option<Instant>,
    pub period: Duration,
    pub signaled: bool,
}
pub struct TimerObj {
    pub manual: bool,
    pub name: Option<String>,
    pub state: Mutex<TimerState>,
}
impl TimerObj {
    pub(crate) fn ready(&self, consume: bool) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        if let Some(due) = state.due.filter(|&due| now >= due) {
            state.signaled = true;
            state.due = if state.period.is_zero() {
                None
            } else {
                let steps = (now - due).as_nanos() / state.period.as_nanos() + 1;
                u64::try_from(state.period.as_nanos() * steps)
                    .ok()
                    .and_then(|ns| due.checked_add(Duration::from_nanos(ns)))
            };
        }
        let result = state.signaled;
        if result && consume && !self.manual {
            state.signaled = false;
        }
        result
    }
}

pub struct MutexObj {
    /// Owning thread id (0: free) and recursion count, under one lock.
    pub state: Mutex<(u32, u32)>,
    pub name: Option<String>,
}

pub struct SemaphoreObj {
    pub count: Mutex<i32>,
    pub max: i32,
}

/// A section (file mapping): page-file memory as an OSyx shared memory
/// object (`shm`), or the file it maps (`shm` 0); see mapping.rs.
pub struct SectionObj {
    pub shm: u64,
    /// shm names a kernel file-section capability instead of page-file RAM.
    pub file_mapping: bool,
    pub size: u64,
    pub writable: bool,
    pub executable: bool,
    pub file: Option<Arc<FileObj>>,
    pub name: Option<String>,
}

impl Drop for SectionObj {
    fn drop(&mut self) {
        if self.shm != 0 {
            let _ = os_sys::close(self.shm);
        }
    }
}

#[derive(Clone)]
pub enum Object {
    File(Arc<FileObj>),
    Console(Console),
    Null,
    Thread(Arc<ThreadObj>),
    Event(Arc<EventObj>),
    KeyedEvent(Arc<crate::keyed::KeyedEvent>),
    Timer(Arc<TimerObj>),
    Mutex(Arc<MutexObj>),
    Semaphore(Arc<SemaphoreObj>),
    Section(Arc<SectionObj>),
    Token(Arc<crate::security::Token>),
    Port(Arc<crate::threadpool::PortObj>),
    Process(Arc<crate::process::ProcessObj>),
    Job(Arc<crate::process::JobObj>),
    WindowStation(Arc<crate::winsta::Station>),
    Desktop(Arc<crate::winsta::DesktopObj>),
    Pipe(Arc<crate::pipes::PipeObj>),
    /// A directory of the NT object namespace (NtOpenDirectoryObject).
    Directory(Arc<DirectoryObj>),
    /// A KTM transaction (CreateTransaction).
    Transaction(Arc<crate::ktm::TransactionObj>),
}

/// An open object directory: `\\` or `\\BaseNamedObjects`.
pub struct DirectoryObj {
    pub path: String,
}

struct Table {
    map: BTreeMap<u64, Object>,
    next: u64,
    /// Handles marked HANDLE_FLAG_INHERIT.
    inheritable: alloc::collections::BTreeSet<u64>,
}

static TABLE: Mutex<Table> =
    Mutex::new(Table { map: BTreeMap::new(), next: 0x100, inheritable: alloc::collections::BTreeSet::new() });

/// Puts `o` at the handle value `h` (an inherited handle keeps its value);
/// false if `h` is taken or not a handle value.
pub fn insert_at(h: u64, o: Object) -> bool {
    let mut t = TABLE.lock().unwrap();
    if h == 0 || !h.is_multiple_of(4) || t.map.contains_key(&h) {
        return false;
    }
    t.map.insert(h, o);
    true
}

/// Marks a handle inheritable or not; false if it is not open.
pub fn set_inheritable(h: u64, on: bool) -> bool {
    let mut t = TABLE.lock().unwrap();
    if !t.map.contains_key(&h) {
        return false;
    }
    if on {
        t.inheritable.insert(h);
    } else {
        t.inheritable.remove(&h);
    }
    true
}

pub fn is_inheritable(h: u64) -> bool {
    TABLE.lock().unwrap().inheritable.contains(&h)
}

/// The open handles marked inheritable.
pub fn inheritable() -> alloc::vec::Vec<u64> {
    TABLE.lock().unwrap().inheritable.iter().copied().collect()
}

pub fn insert(o: Object) -> u64 {
    let mut t = TABLE.lock().unwrap();
    while t.map.contains_key(&t.next) {
        t.next += 4;
    }
    let h = t.next;
    t.next += 4;
    t.map.insert(h, o);
    h
}

/// The object type, for diagnostics.
pub fn kind_name(o: &Object) -> &'static str {
    match o {
        Object::File(_) => "file",
        Object::Console(_) => "console",
        Object::Null => "null device",
        Object::Thread(_) => "thread",
        Object::Event(_) => "event",
        Object::KeyedEvent(_) => "keyed event",
        Object::Timer(_) => "timer",
        Object::Mutex(_) => "mutex",
        Object::Semaphore(_) => "semaphore",
        Object::Section(_) => "section",
        Object::Token(_) => "token",
        Object::Port(_) => "completion port",
        Object::Process(_) => "process",
        Object::Job(_) => "job",
        Object::WindowStation(_) => "window station",
        Object::Desktop(_) => "desktop",
        Object::Pipe(_) => "pipe",
        Object::Directory(_) => "directory",
        Object::Transaction(_) => "transaction",
    }
}

/// Open handles of this process.
pub fn count() -> usize {
    TABLE.lock().unwrap().map.len()
}

pub fn get(h: u64) -> Option<Object> {
    TABLE.lock().unwrap().map.get(&h).cloned()
}

/// Whether any open handle's object satisfies `f`.
pub fn any(f: impl Fn(&Object) -> bool) -> bool {
    TABLE.lock().unwrap().map.values().any(f)
}

/// Removes a handle; the object goes away with its last handle.
pub fn close(h: u64) -> bool {
    let mut t = TABLE.lock().unwrap();
    t.inheritable.remove(&h);
    let removed = t.map.remove(&h);
    drop(t);
    removed.is_some()
}

pub fn file(h: u64) -> Result<Arc<FileObj>, u32> {
    match get(h) {
        Some(Object::File(f)) => Ok(f),
        _ => Err(ERROR_INVALID_HANDLE),
    }
}

// ---- waiting ----------------------------------------------------------------

static SEQ: AtomicU32 = AtomicU32::new(0);
/// Threads inside a futex sleep on [`SEQ`] (or about to enter one): a
/// signal only needs a wake when this is non-zero. A thread that read an
/// older sequence returns from its wait at once anyway.
static WAITERS: AtomicU32 = AtomicU32::new(0);
/// Serialises check-and-consume of wait conditions (auto-reset events,
/// mutex ownership, semaphore counts, wait-all).
static WAIT_LOCK: Mutex<()> = Mutex::new(());

/// How many `signal_all` calls have run (`OSYX_WINRUN_COUNT` diagnostics).
pub static SIGNALS: AtomicU64 = AtomicU64::new(0);

/// Wakes every waiter to re-check its objects.
pub fn signal_all() {
    SIGNALS.fetch_add(1, Ordering::Relaxed);
    SEQ.fetch_add(1, Ordering::SeqCst);
    if WAITERS.load(Ordering::SeqCst) != 0 {
        os_sys::futex_wake(SEQ.as_ptr(), u32::MAX);
    }
}

/// The change sequence, read before checking a condition that a later
/// `signal_all` may change (see `wait_for_change`).
pub fn sequence() -> u32 {
    SEQ.load(Ordering::SeqCst)
}

/// Sleeps until `signal_all` runs after `seq` was read, or `timeout` passes.
/// Returns true when a signal cut the sleep short.
pub fn wait_for_change(seq: u32, timeout: Duration) -> bool {
    WAITERS.fetch_add(1, Ordering::SeqCst);
    let ns = timeout.as_nanos().max(1) as u64;
    let r = os_sys::futex_wait(SEQ.as_ptr(), seq, ns);
    WAITERS.fetch_sub(1, Ordering::SeqCst);
    matches!(r, Err(osyx_abi::Errno::WouldBlock))
}

pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 0x102;
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;
pub const INFINITE: u32 = 0xFFFF_FFFF;

/// Whether `o` is signalled for the calling thread (`consume` also takes
/// it: resets auto-reset events, acquires mutexes, decrements semaphores).
fn ready(o: &Object, consume: bool, me: u32) -> Result<bool, u32> {
    Ok(match o {
        Object::Thread(t) => t.done.load(Ordering::SeqCst),
        Object::Timer(t) => t.ready(consume),
        Object::Event(e) => {
            if e.manual || !consume {
                e.is_set()
            } else {
                e.take()
            }
        }
        Object::Mutex(m) => {
            let mut s = m.state.lock().unwrap();
            let free = s.0 == 0 || s.0 == me;
            if free && consume {
                s.0 = me;
                s.1 += 1;
            }
            free
        }
        Object::Semaphore(s) => {
            let mut c = s.count.lock().unwrap();
            let free = *c > 0;
            if free && consume {
                *c -= 1;
            }
            free
        }
        Object::Console(_) | Object::File(_) | Object::Null | Object::Pipe(_) => true,
        Object::Process(p) => p.done.load(Ordering::SeqCst),
        Object::KeyedEvent(_) | Object::Section(_) | Object::Token(_) | Object::Port(_) | Object::Job(_) | Object::WindowStation(_) | Object::Desktop(_) | Object::Directory(_) | Object::Transaction(_) => {
            return Err(ERROR_INVALID_HANDLE)
        }
    })
}

/// `WaitForMultipleObjects` semantics (a single object is a list of one).
/// Returns `WAIT_OBJECT_0 + i`, `WAIT_TIMEOUT` or Err(Win32 error).
pub fn wait(handles: &[u64], all: bool, timeout_ms: u32) -> Result<u32, u32> {
    if handles.is_empty() || handles.len() > 64 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let me = os_sys::gettid() as u32;
    let mut objs = Vec::with_capacity(handles.len());
    for &h in handles {
        let o = match h {
            CURRENT_THREAD | CURRENT_PROCESS => {
                // Waiting for oneself never ends: only a timeout can.
                None
            }
            h => Some(get(h).ok_or(ERROR_INVALID_HANDLE)?),
        };
        objs.push(o);
    }
    let deadline = (timeout_ms != INFINITE).then(|| Instant::now() + Duration::from_millis(timeout_ms as u64));
    loop {
        let seq = SEQ.load(Ordering::SeqCst);
        {
            let _g = WAIT_LOCK.lock().unwrap();
            if all {
                let mut every = true;
                for o in &objs {
                    match o {
                        Some(o) => every &= ready(o, false, me)?,
                        None => every = false,
                    }
                }
                if every {
                    for o in objs.iter().flatten() {
                        ready(o, true, me)?;
                    }
                    return Ok(WAIT_OBJECT_0);
                }
            } else {
                for (i, o) in objs.iter().enumerate() {
                    if let Some(o) = o {
                        if ready(o, true, me)? {
                            return Ok(WAIT_OBJECT_0 + i as u32);
                        }
                    }
                }
            }
        }
        // futex_wait: 0 means no timeout.
        let timer_due = objs
            .iter()
            .filter_map(|o| match o {
                Some(Object::Timer(t)) => t.state.lock().unwrap().due,
                _ => None,
            })
            .min();
        let next = match (deadline, timer_due) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(WAIT_TIMEOUT);
        }
        let wait_ns = match next {
            None => 0,
            Some(d) => {
                let now = Instant::now();
                (d - now).as_nanos().max(1) as u64
            }
        };
        // Another process sets a shared event without touching SEQ: one
        // shared event is waited for on its own word, several objects
        // including one are polled.
        let mut shared = objs.iter().filter_map(|o| match o {
            Some(Object::Event(e)) if e.is_shared() => Some(e),
            _ => None,
        });
        match (shared.next(), shared.next()) {
            (Some(e), _) if objs.len() == 1 => {
                let _ = os_sys::futex_wait(e.futex_word(), 0, wait_ns);
            }
            (None, _) => {
                WAITERS.fetch_add(1, Ordering::SeqCst);
                let _ = os_sys::futex_wait(SEQ.as_ptr(), seq, wait_ns);
                WAITERS.fetch_sub(1, Ordering::SeqCst);
            }
            _ => {
                let slice = if wait_ns == 0 { SHARED_POLL_NS } else { wait_ns.min(SHARED_POLL_NS) };
                WAITERS.fetch_add(1, Ordering::SeqCst);
                let _ = os_sys::futex_wait(SEQ.as_ptr(), seq, slice);
                WAITERS.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

/// How often a wait that includes a shared event looks at it again.
const SHARED_POLL_NS: u64 = 2_000_000;

/// An existing named event or mutex (names are per process here: OSyx
/// has no cross-process Win32 object namespace).
/// The first open object that satisfies `f`.
pub fn find(f: impl Fn(&Object) -> bool) -> Option<Object> {
    TABLE.lock().unwrap().map.values().find(|o| f(o)).cloned()
}

/// The named objects of this process, as (name, NT type name), sorted by
/// name: what `\\BaseNamedObjects` holds.
pub fn named_objects() -> Vec<(String, &'static str)> {
    let t = TABLE.lock().unwrap();
    let mut out: Vec<(String, &'static str)> = t
        .map
        .values()
        .filter_map(|o| match o {
            Object::Event(e) => e.name.clone().map(|n| (n, "Event")),
            Object::Timer(x) => x.name.clone().map(|n| (n, "Timer")),
            Object::Mutex(m) => m.name.clone().map(|n| (n, "Mutant")),
            Object::Section(x) => x.name.clone().map(|n| (n, "Section")),
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn find_named(name: &str) -> Option<Object> {
    let t = TABLE.lock().unwrap();
    t.map
        .values()
        .find(|o| match o {
            Object::Event(e) => e.name.as_deref().is_some_and(|n| n == name),
            Object::Timer(t) => t.name.as_deref().is_some_and(|n| n == name),
            Object::Mutex(m) => m.name.as_deref().is_some_and(|n| n == name),
            Object::Section(s) => s.name.as_deref().is_some_and(|n| n == name),
            _ => false,
        })
        .cloned()
}
