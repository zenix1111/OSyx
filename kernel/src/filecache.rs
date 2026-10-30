//! Read-through page cache for regular files. Pages are keyed by
//! (volume, inode, page index) and filled from the file system on first
//! access, so programs that load the same images repeatedly (every Windows
//! process reads the same DLLs) touch the disk only once. Writes and
//! truncation invalidate the whole inode; the cache is best-effort and
//! bounded, falling back to direct reads when memory runs out.
//!
//! Cached pages are reference counted: data is copied out after releasing
//! the cache lock, and the disk is never touched while holding it.
use crate::{mem, shm::SharedMemory, sync::KMutex};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use osyx_abi::Errno;

type Key = (u64, u64);
pub(crate) type Page = (Arc<SharedMemory>, usize);

struct Entry {
    pages: BTreeMap<u64, Page>,
    used: u64,
    bytes: usize,
    /// Page expected next by a sequential reader; a miss there reads ahead.
    next: u64,
    /// Pages the next sequential miss reads: doubles while the reader stays
    /// sequential, back to the start after a random access.
    window: u64,
}

struct Cache {
    entries: BTreeMap<Key, Entry>,
    bytes: usize,
    clock: u64,
    generation: u64,
    cap: usize,
}

static CACHE: KMutex<Cache> = KMutex::new(Cache { entries: BTreeMap::new(), bytes: 0, clock: 0, generation: 0, cap: 0 });

// TEMP: page cache and recent-write overlay hit counters.
static FC_HITS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static FC_MISSES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static RECENT_HITS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn hit_stats() -> (u64, u64, u64) {
    (
        FC_HITS.load(core::sync::atomic::Ordering::Relaxed),
        FC_MISSES.load(core::sync::atomic::Ordering::Relaxed),
        RECENT_HITS.load(core::sync::atomic::Ordering::Relaxed),
    )
}

fn cap() -> usize {
    let (_, total) = mem::frame_stats();
    let bytes = total as usize * mem::PAGE_SIZE as usize;
    (bytes / 8).clamp(16 * 1024 * 1024, 512 * 1024 * 1024)
}

/// Drops every cached page of one inode (before and after a write).
pub fn invalidate(key: Key) {
    let mut c = CACHE.lock();
    c.generation += 1;
    if let Some(e) = c.entries.remove(&key) {
        c.bytes -= e.bytes;
    }
}

/// Drops the cached pages and the recent-write overlay: for anything that
/// replaces the file's contents behind the cache (truncation, a writable
/// mapping).
pub fn forget(key: Key) {
    invalidate(key);
    let mut r = RECENT.lock();
    if let Some(e) = r.entries.remove(&key) {
        r.bytes -= e.1.len();
    }
}

pub fn clear() {
    let mut c = CACHE.lock();
    c.generation += 1;
    c.entries.clear();
    c.bytes = 0;
    let mut r = RECENT.lock();
    r.entries.clear();
    r.bytes = 0;
}

/// Bytes of recently written data served to reads without touching the
/// disk. A SQLite WAL frame is read back right after it is written, and a
/// disk round trip at that moment costs tens to hundreds of milliseconds
/// while the writer keeps the device busy.
struct Recent {
    /// (first offset, data, last use)
    entries: BTreeMap<Key, (u64, Vec<u8>, u64)>,
    bytes: usize,
    clock: u64,
}

static RECENT: KMutex<Recent> = KMutex::new(Recent { entries: BTreeMap::new(), bytes: 0, clock: 0 });

/// Data kept per file; writes are sequential, so a tail of this size covers
/// what a reader normally asks for again.
const RECENT_FILE: usize = 4 * 1024 * 1024;
const RECENT_TOTAL: usize = 16 * 1024 * 1024;

fn recent_evict_extra(r: &mut Recent, keep: Key) {
    while r.bytes > RECENT_TOTAL {
        let victim = r.entries.iter().filter(|(k, _)| **k != keep).min_by_key(|(_, e)| e.2).map(|(k, _)| *k);
        let Some(victim) = victim else { break };
        if let Some(e) = r.entries.remove(&victim) {
            r.bytes -= e.1.len();
        }
    }
}

fn recent_read(key: Key, offset: u64, out: &mut [u8]) -> bool {
    let mut r = RECENT.lock();
    r.clock += 1;
    let clock = r.clock;
    let Some((start, data, used)) = r.entries.get_mut(&key) else { return false };
    let Some(lo) = offset.checked_sub(*start) else { return false };
    let lo = lo as usize;
    if lo + out.len() > data.len() {
        return false;
    }
    *used = clock;
    out.copy_from_slice(&data[lo..lo + out.len()]);
    true
}

/// Copies bytes a write just stored into the cached copies of the pages it
/// touched, keeping them resident. A database writes a page and reads it back
/// immediately; dropping the page sent that read to a disk the same writer
/// keeps busy (tens to hundreds of milliseconds under load). Pages that are
/// not cached are left to the next read; a cached short (final) page that the
/// write extends is dropped, since its length would still report the old end
/// of the file.
pub fn update_write(key: Key, offset: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let page = mem::PAGE_SIZE;
    let mut c = CACHE.lock();
    c.clock += 1;
    // A fill that started before this write may still be in flight; keep it
    // from inserting data read from the file before the write landed.
    c.generation += 1;
    let clock = c.clock;
    let Some(e) = c.entries.get_mut(&key) else { return };
    let mut dropped = 0;
    let mut at = 0usize;
    while at < data.len() {
        let pos = offset + at as u64;
        let index = pos / page;
        let within = (pos % page) as usize;
        let n = (page as usize - within).min(data.len() - at);
        let Some((shm, len)) = e.pages.get(&index) else {
            at += n;
            continue;
        };
        if within + n > *len {
            e.pages.remove(&index);
            e.bytes -= page as usize;
            dropped += page as usize;
            at += n;
            continue;
        }
        // SAFETY: the SharedMemory keeps this RAM page mapped and alive while
        // the cache entry holds it.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data[at..].as_ptr(),
                (mem::phys_to_virt(shm.frames()[0]) as *mut u8).add(within),
                n,
            );
        }
        e.used = clock;
        at += n;
    }
    c.bytes -= dropped;
}

/// Records bytes just written to `key`, so `read` can serve them while they
/// are still the newest content of the file.
pub fn note_write(key: Key, offset: u64, data: &[u8]) {
    if data.is_empty() || data.len() >= RECENT_FILE {
        return;
    }
    let mut r = RECENT.lock();
    r.clock += 1;
    let clock = r.clock;
    match r.entries.get_mut(&key) {
        Some((start, buf, used)) => {
            *used = clock;
            if offset == *start + buf.len() as u64 {
                buf.extend_from_slice(data);
            } else {
                *start = offset;
                buf.clear();
                buf.extend_from_slice(data);
            }
            if buf.len() > RECENT_FILE {
                let drop = buf.len() - RECENT_FILE;
                buf.drain(..drop);
                *start += drop as u64;
            }
        }
        None => {
            r.entries.insert(key, (offset, data.to_vec(), clock));
        }
    }
    r.bytes = r.entries.values().map(|e| e.1.len()).sum();
    recent_evict_extra(&mut r, key);
}

/// Reads `out` at `offset` through the cache; `fill` is the file system's
/// own read. `source`, when given, lets a background thread extend the
/// read-ahead window past what this call reads. Any cache failure falls back
/// to reading directly.
pub fn read(key: Key, offset: u64, out: &mut [u8], fill: impl Fn(u64, &mut [u8]) -> Result<usize, Errno>, source: Option<&Source>) -> Result<usize, Errno> {
    if recent_read(key, offset, out) {
        RECENT_HITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return Ok(out.len());
    }
    let mut done = 0;
    while done < out.len() {
        let at = offset + done as u64;
        let index = at / mem::PAGE_SIZE;
        let within = (at % mem::PAGE_SIZE) as usize;
        let cached = match page(key, index, &fill, source) {
            Ok(p) => p,
            Err(Errno::NoMemory) => None,
            Err(e) => return Err(e),
        };
        let Some((page, len)) = cached else {
            // End of file, or no memory for a cached copy: read the rest
            // straight from the file system.
            if done == 0 {
                return fill(at, out);
            }
            let n = fill(at, &mut out[done..])?;
            return Ok(done + n);
        };
        if within >= len {
            break;
        }
        let n = (len - within).min(out.len() - done);
        // SAFETY: the SharedMemory keeps this RAM page mapped and alive
        // while the reference counted page is held here.
        let src = unsafe {
            core::slice::from_raw_parts((mem::phys_to_virt(page.frames()[0]) as *const u8).add(within), n)
        };
        out[done..done + n].copy_from_slice(src);
        done += n;
    }
    Ok(done)
}

/// Copies bytes of the recent-write overlay into `out`; false when the
/// overlay does not cover the whole request.
fn recent_snapshot(key: Key, offset: u64, out: &mut [u8]) -> bool {
    let mut r = RECENT.lock();
    r.clock += 1;
    let clock = r.clock;
    let Some((start, data, used)) = r.entries.get_mut(&key) else { return false };
    let Some(lo) = offset.checked_sub(*start).map(|v| v as usize) else { return false };
    if lo + out.len() > data.len() {
        return false;
    }
    *used = clock;
    out.copy_from_slice(&data[lo..lo + out.len()]);
    true
}

/// Serves a read of at most one page straight from RAM to user memory.
///
/// Returns `None` when the data is not cached (or the destination cannot be
/// written), so the caller can run the normal path, which may touch the file
/// system and the kernel entry lock. Data is snapshotted while the cache lock
/// is held — a writer on another CPU must not tear it — and copied to user
/// memory only after the lock is released, because a copying fault takes the
/// entry lock and must never be requested under a cache lock.
pub fn read_cached_to_user(key: Key, offset: u64, dst: u64, len: usize) -> Option<Result<usize, Errno>> {
    if len == 0 || len > mem::PAGE_SIZE as usize {
        return None;
    }
    let mut buf = [0u8; mem::PAGE_SIZE as usize];
    if recent_snapshot(key, offset, &mut buf[..len]) {
        let r = crate::fixup::copy_to_user(dst, &buf[..len]).map(|_| len);
        if r.is_ok() {
            RECENT_HITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        return Some(r);
    }
    let within = (offset % mem::PAGE_SIZE) as usize;
    let index = offset / mem::PAGE_SIZE;
    let n = {
        let mut c = CACHE.lock();
        c.clock += 1;
        let clock = c.clock;
        let e = c.entries.get_mut(&key)?;
        let (shm, page_len) = e.pages.get(&index).cloned()?;
        e.used = clock;
        // A short page may predate a write that extended the file; only the
        // normal path knows whether this is really the end of the file.
        if within >= page_len {
            return None;
        }
        let n = (page_len - within).min(len);
        // SAFETY: the shared page keeps the frame mapped while it is alive.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (mem::phys_to_virt(shm.frames()[0]) as *const u8).add(within),
                buf.as_mut_ptr(),
                n,
            );
        }
        n
    };
    let r = crate::fixup::copy_to_user(dst, &buf[..n]).map(|_| n);
    if r.is_ok() {
        FC_HITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    Some(r)
}

/// A cached page, without touching the file system on a miss.
pub(crate) fn peek(key: Key, index: u64) -> Option<Page> {
    let mut c = CACHE.lock();
    let clock = c.clock + 1;
    let e = c.entries.get_mut(&key)?;
    let page = e.pages.get(&index).cloned();
    if page.is_some() {
        e.used = clock;
        c.clock = clock;
    }
    page
}

/// Read-ahead window for sequential readers, in pages: it starts small and
/// doubles with every sequential miss. The reader gets the first pages of the
/// window before its read returns; a background thread reads the rest, so a
/// long run does not make the reader wait behind the disk.
const READAHEAD_START: u64 = 8;
const READAHEAD_MAX: u64 = 128;
/// Pages a sequential miss reads before returning; the rest of the window is
/// queued for the read-ahead thread.
const READAHEAD_SYNC: u64 = 8;

/// What the read-ahead thread needs to read a file without the caller.
#[derive(Clone)]
pub struct Source {
    pub fs: Arc<dyn crate::vfs::Filesystem>,
    pub ino: u64,
}

struct Job {
    key: Key,
    source: Source,
    first: u64,
    count: u64,
    generation: u64,
}

static JOBS: KMutex<Vec<Job>> = KMutex::new(Vec::new());
const JOBS_MAX: usize = 8;

/// Starts the read-ahead thread: it reads queued windows into the cache.
pub fn start_readahead() {
    crate::sched::spawn_kernel("readahead", readahead_thread, 0, 0);
}

fn readahead_thread(_: u64, _: u64) {
    loop {
        let job = {
            let mut q = JOBS.lock();
            if q.is_empty() { None } else { Some(q.remove(0)) }
        };
        match job {
            Some(job) => readahead(job),
            None => crate::sched::sleep_ticks(crate::arch::timer::ms_to_ticks(5)),
        }
    }
}

fn queue_readahead(key: Key, source: &Source, first: u64, count: u64, generation: u64) {
    if count == 0 {
        return;
    }
    let mut q = JOBS.lock();
    // A newer window of the same file replaces an older one; otherwise the
    // reader has moved on and the old pages are no longer worth reading.
    q.retain(|j| j.key != key);
    if q.len() == JOBS_MAX {
        q.remove(0);
    }
    q.push(Job { key, source: source.clone(), first, count, generation });
}

fn readahead(job: Job) {
    let mut scratch = alloc::vec![0u8; mem::PAGE_SIZE as usize];
    for index in job.first..job.first + job.count {
        if peek(job.key, index).is_some() {
            continue;
        }
        let mut len = 0;
        while len < scratch.len() {
            match job.source.fs.read(job.source.ino, index * mem::PAGE_SIZE + len as u64, &mut scratch[len..]) {
                Ok(0) => break,
                Ok(n) => len += n,
                // Best effort: the reader reads the page itself on a miss.
                Err(_) => return,
            }
        }
        if len == 0 {
            return;
        }
        let Ok(shm) = SharedMemory::page_from(&scratch[..len]) else { return };
        if insert(job.key, index, job.generation, &[(index, shm, len)]).is_none() {
            // The cache was invalidated: the rest of the window is stale.
            return;
        }
    }
}

/// Caches freshly read pages; returns the page at `index` if it landed.
fn insert(key: Key, index: u64, generation: u64, fresh: &[(u64, Arc<SharedMemory>, usize)]) -> Option<Page> {
    let mut c = CACHE.lock();
    if c.generation != generation {
        return None;
    }
    if c.cap == 0 {
        c.cap = cap();
    }
    c.clock += 1;
    let clock = c.clock;
    let added = {
        let e = c.entries.entry(key).or_insert_with(|| Entry { pages: BTreeMap::new(), used: clock, bytes: 0, next: index, window: READAHEAD_START });
        e.used = clock;
        let mut added = 0;
        for (i, shm, n) in fresh {
            if !e.pages.contains_key(i) {
                e.pages.insert(*i, (shm.clone(), *n));
                e.bytes += mem::PAGE_SIZE as usize;
                added += mem::PAGE_SIZE as usize;
            }
        }
        if let Some((last, _, _)) = fresh.last() {
            e.next = last + 1;
        }
        added
    };
    c.bytes += added;
    while c.bytes > c.cap {
        let victim = c.entries.iter().filter(|(k, _)| **k != key).min_by_key(|(_, e)| e.used).map(|(k, _)| *k);
        let Some(victim) = victim else { break };
        if let Some(e) = c.entries.remove(&victim) {
            c.bytes -= e.bytes;
        }
    }
    c.entries.get(&key).and_then(|e| e.pages.get(&index)).cloned()
}

pub(crate) fn page(key: Key, index: u64, fill: &impl Fn(u64, &mut [u8]) -> Result<usize, Errno>, source: Option<&Source>) -> Result<Option<Page>, Errno> {
    let (generation, want) = {
        let mut c = CACHE.lock();
        c.clock += 1;
        let clock = c.clock;
        let generation = c.generation;
        let want = match c.entries.get_mut(&key) {
            Some(e) => {
                e.used = clock;
                if let Some((p, len)) = e.pages.get(&index) {
                    FC_HITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    return Ok(Some((p.clone(), *len)));
                }
                if index == e.next {
                    e.window = (e.window * 2).clamp(READAHEAD_START, READAHEAD_MAX);
                    e.window
                } else {
                    e.window = READAHEAD_START;
                    1
                }
            }
            None => READAHEAD_START,
        };
        // Under the entry lock a long read would hold up every other CPU.
        (generation, if crate::smp::owner_is_me() { want.min(32) } else { want })
    };
    FC_MISSES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let sync = want.min(READAHEAD_SYNC).max(1);
    let mut buf = alloc::vec![0u8; (sync * mem::PAGE_SIZE) as usize];
    let started = crate::interrupts::uptime_ms();
    let mut len = 0;
    while len < buf.len() {
        let n = fill(index * mem::PAGE_SIZE + len as u64, &mut buf[len..])?;
        if n == 0 {
            break;
        }
        len += n;
    }
    let elapsed = crate::interrupts::uptime_ms().saturating_sub(started);
    if elapsed >= 50 {
        crate::kprintln!("filecache: {} KiB in {} ms", len >> 10, elapsed);
    }
    if len == 0 {
        return Ok(None);
    }
    let count = len.div_ceil(mem::PAGE_SIZE as usize);
    let mut fresh: Vec<(u64, Arc<SharedMemory>, usize)> = Vec::with_capacity(count);
    for k in 0..count {
        let start = k * mem::PAGE_SIZE as usize;
        let n = (len - start).min(mem::PAGE_SIZE as usize);
        // The page is filled from `buf` once; clearing it first was the top
        // kernel cost of reading a browser's files (see `SharedMemory::page_from`).
        let shm = SharedMemory::page_from(&buf[start..start + n])?;
        fresh.push((index + k as u64, shm, n));
    }
    let page = insert(key, index, generation, &fresh);
    if want > sync {
        if let Some(source) = source {
            queue_readahead(key, source, index + count as u64, want - count as u64, generation);
        }
    }
    if let Some(page) = page {
        return Ok(Some(page));
    }
    // The cache was invalidated while reading: return the bytes without
    // inserting them. `fresh` starts at `index`.
    let (_, shm, n) = fresh.into_iter().next().expect("at least one page");
    Ok(Some((shm, n)))
}
