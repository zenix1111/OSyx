//! Heaps: the process heap and private heaps made by `HeapCreate`.
//!
//! All blocks come from the runtime's allocator and carry a 16-byte header
//! (size, owner). The owner word is 0 for the process heap and the heap
//! handle for a private heap, so a free or size query with the wrong heap is
//! caught, and `HeapDestroy` can release every block of its heap. Private
//! heaps keep the set of their live blocks (for validation, walking and
//! destruction), a byte limit when a maximum size was given, and a lock.
//!
//! Limits, as the Windows documentation puts them where OSyx differs:
//! * `HeapValidate(process heap, NULL)` checks only the handle: the process
//!   heap's blocks are not tracked (allocation speed of the C runtime), so a
//!   whole-heap walk is possible for private heaps only.
//! * `HEAP_GENERATE_EXCEPTIONS` is accepted and ignored: failures return NULL.
//! * `HeapReAlloc` with `HEAP_REALLOC_IN_PLACE_ONLY` succeeds when the size
//!   does not grow (the block keeps its size), as in rtl.rs.

use crate::error::*;
use crate::kernel32::{self, fail, Bool, FALSE, TRUE};
use crate::{mem, teb};
use alloc::collections::{BTreeMap, BTreeSet};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
use os_std::sync::Mutex;

const HEAP_ZERO_MEMORY: u32 = 0x8;
const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x10;
const ERROR_NOT_OWNER: u32 = 288;

struct Heap {
    /// 0: growable. Otherwise the most the live blocks may add up to.
    max: usize,
    used: usize,
    blocks: BTreeSet<u64>,
    /// Thread that holds HeapLock (0: none) and its nesting depth.
    owner: u64,
    depth: u32,
}

static HEAPS: Mutex<BTreeMap<u64, Heap>> = Mutex::new(BTreeMap::new());
static PROCESS_OWNER: AtomicU64 = AtomicU64::new(0);
static PROCESS_DEPTH: AtomicU32 = AtomicU32::new(0);

fn is_process(h: u64) -> bool {
    h == kernel32::process_heap()
}

/// Whether `h` is a heap made by HeapCreate and not yet destroyed.
pub fn is_private(h: u64) -> bool {
    h != 0 && HEAPS.lock().unwrap().contains_key(&h)
}

/// Waits while another thread holds the process heap's lock (HeapLock).
pub fn gate_process() {
    let owner = PROCESS_OWNER.load(Ordering::Relaxed);
    if owner != 0 && owner != teb::current_tid() {
        wait_free(kernel32::process_heap());
    }
}

fn wait_free(h: u64) {
    let me = teb::current_tid();
    loop {
        let owner = if is_process(h) {
            PROCESS_OWNER.load(Ordering::Acquire)
        } else {
            HEAPS.lock().unwrap().get(&h).map_or(0, |x| x.owner)
        };
        if owner == 0 || owner == me {
            return;
        }
        os_std::thread::sleep(Duration::from_millis(1));
    }
}

pub fn create(_options: u32, initial: usize, max: usize) -> u64 {
    // A maximum smaller than the initial size is raised to it, and Windows
    // accepts unknown option bits.
    let max = if max != 0 && max < initial { initial } else { max };
    let handle = mem::arena_alloc(16, 16);
    if handle == 0 {
        return fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    }
    HEAPS.lock().unwrap().insert(handle, Heap { max, used: 0, blocks: BTreeSet::new(), owner: 0, depth: 0 });
    handle
}

pub fn destroy(h: u64) -> Bool {
    if h == 0 {
        return TRUE; // as on Windows
    }
    if is_process(h) {
        return fail(ERROR_INVALID_HANDLE, FALSE);
    }
    wait_free(h);
    let Some(heap) = HEAPS.lock().unwrap().remove(&h) else { return fail(ERROR_INVALID_HANDLE, FALSE) };
    for p in heap.blocks {
        kernel32::heap_free(p);
    }
    TRUE
}

pub fn alloc(h: u64, flags: u32, size: usize) -> u64 {
    let zero = flags & HEAP_ZERO_MEMORY != 0;
    if is_process(h) {
        return kernel32::heap_alloc(size, zero).unwrap_or_else(|| fail(ERROR_NOT_ENOUGH_MEMORY, 0));
    }
    wait_free(h);
    let mut g = HEAPS.lock().unwrap();
    let Some(heap) = g.get_mut(&h) else { return fail(ERROR_INVALID_HANDLE, 0) };
    if heap.max != 0 && heap.used.saturating_add(size) > heap.max {
        return fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    }
    match kernel32::heap_alloc_for(h, size, zero) {
        Some(p) => {
            heap.blocks.insert(p);
            heap.used += size;
            p
        }
        None => fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// Whether `p` is a live block of heap `h`. For the process heap that is
/// read from the block header, so `p` must at least be a plausible pointer.
fn owns(h: u64, p: u64) -> bool {
    if is_process(h) {
        return p >= 0x10000 && p % 16 == 0 && kernel32::heap_owner(p) == 0;
    }
    HEAPS.lock().unwrap().get(&h).is_some_and(|x| x.blocks.contains(&p))
}

pub fn free(h: u64, _flags: u32, p: u64) -> Bool {
    if h == 0 || !(is_process(h) || is_private(h)) {
        return fail(ERROR_INVALID_HANDLE, FALSE);
    }
    if p == 0 {
        return TRUE;
    }
    wait_free(h);
    if !owns(h, p) {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    if !is_process(h) {
        let size = kernel32::heap_size(p);
        let mut g = HEAPS.lock().unwrap();
        let Some(heap) = g.get_mut(&h) else { return fail(ERROR_INVALID_HANDLE, FALSE) };
        if !heap.blocks.remove(&p) {
            return fail(ERROR_INVALID_PARAMETER, FALSE);
        }
        heap.used = heap.used.saturating_sub(size);
    }
    kernel32::heap_free(p);
    TRUE
}

/// The size, or `usize::MAX` for a block that is not one of the heap.
pub fn size(h: u64, _flags: u32, p: u64) -> usize {
    if h == 0 || !(is_process(h) || is_private(h)) {
        return fail(ERROR_INVALID_HANDLE, usize::MAX as u64) as usize;
    }
    wait_free(h);
    if p == 0 || !owns(h, p) {
        return fail(ERROR_INVALID_PARAMETER, usize::MAX as u64) as usize;
    }
    kernel32::heap_size(p)
}

pub fn realloc(h: u64, flags: u32, p: u64, size: usize) -> u64 {
    if p == 0 {
        return alloc(h, flags, size);
    }
    if h == 0 || !(is_process(h) || is_private(h)) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    wait_free(h);
    if !owns(h, p) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let old = kernel32::heap_size(p);
    if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
        return if size > old { fail(ERROR_NOT_ENOUGH_MEMORY, 0) } else { p };
    }
    let n = alloc(h, flags & HEAP_ZERO_MEMORY, size);
    if n == 0 {
        return 0; // the old block is untouched
    }
    // SAFETY: both blocks are valid for min(old, size) bytes.
    unsafe { core::ptr::copy_nonoverlapping(p as *const u8, n as *mut u8, old.min(size)) };
    free(h, 0, p);
    n
}

/// A block of the heap (`p != 0`), or the whole heap (`p == 0`: every block
/// of a private heap is looked at; see the module notes for the process heap).
pub fn validate(h: u64, _flags: u32, p: u64) -> Bool {
    if h == 0 || !(is_process(h) || is_private(h)) {
        return fail(ERROR_INVALID_HANDLE, FALSE);
    }
    wait_free(h);
    if p != 0 {
        return owns(h, p) as Bool;
    }
    if is_process(h) {
        return TRUE;
    }
    let g = HEAPS.lock().unwrap();
    let Some(heap) = g.get(&h) else { return fail(ERROR_INVALID_HANDLE, FALSE) };
    let intact = heap.blocks.iter().all(|&b| kernel32::heap_owner(b) == h);
    let total: usize = heap.blocks.iter().map(|&b| kernel32::heap_size(b)).sum();
    (intact && total == heap.used) as Bool
}

pub fn lock(h: u64) -> Bool {
    let me = teb::current_tid();
    loop {
        if is_process(h) {
            match PROCESS_OWNER.compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    PROCESS_DEPTH.store(1, Ordering::Relaxed);
                    return TRUE;
                }
                Err(owner) if owner == me => {
                    PROCESS_DEPTH.fetch_add(1, Ordering::Relaxed);
                    return TRUE;
                }
                Err(_) => {}
            }
        } else {
            let mut g = HEAPS.lock().unwrap();
            let Some(heap) = g.get_mut(&h) else { return fail(ERROR_INVALID_HANDLE, FALSE) };
            if heap.owner == 0 || heap.owner == me {
                heap.owner = me;
                heap.depth += 1;
                return TRUE;
            }
        }
        os_std::thread::sleep(Duration::from_millis(1));
    }
}

/// Unlocking a heap that is not locked succeeds, as on Windows; one locked
/// by another thread is refused.
pub fn unlock(h: u64) -> Bool {
    let me = teb::current_tid();
    if is_process(h) {
        let owner = PROCESS_OWNER.load(Ordering::Acquire);
        if owner == 0 {
            return TRUE;
        }
        if owner != me {
            return fail(ERROR_NOT_OWNER, FALSE);
        }
        if PROCESS_DEPTH.fetch_sub(1, Ordering::Relaxed) <= 1 {
            PROCESS_DEPTH.store(0, Ordering::Relaxed);
            PROCESS_OWNER.store(0, Ordering::Release);
        }
        return TRUE;
    }
    let mut g = HEAPS.lock().unwrap();
    let Some(heap) = g.get_mut(&h) else { return fail(ERROR_INVALID_HANDLE, FALSE) };
    if heap.owner == 0 {
        return TRUE;
    }
    if heap.owner != me {
        return fail(ERROR_NOT_OWNER, FALSE);
    }
    heap.depth -= 1;
    if heap.depth == 0 {
        heap.owner = 0;
    }
    TRUE
}

/// HeapWalk of a private heap: every live block in address order, each as a
/// busy PROCESS_HEAP_ENTRY (x64 layout: lpData @0, cbData @8, cbOverhead @12,
/// iRegionIndex @13, wFlags @14). An entry with lpData NULL starts the walk;
/// after the last block the call fails with ERROR_NO_MORE_ITEMS. Regions and
/// uncommitted ranges are not reported, and the process heap is not walkable
/// (its blocks are not tracked).
pub fn walk(h: u64, entry: *mut u8) -> Bool {
    const PROCESS_HEAP_ENTRY_BUSY: u16 = 4;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    if entry.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    if crate::wow64::is_active() || is_process(h) {
        return fail(ERROR_NOT_SUPPORTED, FALSE);
    }
    if !is_private(h) {
        return fail(ERROR_INVALID_HANDLE, FALSE);
    }
    wait_free(h);
    // SAFETY: the caller's PROCESS_HEAP_ENTRY (40 bytes).
    let last = unsafe { teb::get::<u64>(entry as u64, 0) };
    let g = HEAPS.lock().unwrap();
    let Some(heap) = g.get(&h) else { return fail(ERROR_INVALID_HANDLE, FALSE) };
    let next = if last == 0 { heap.blocks.iter().next() } else { heap.blocks.range(last + 1..).next() };
    let Some(&block) = next else { return fail(ERROR_NO_MORE_ITEMS, FALSE) };
    // SAFETY: as above; the block header is the allocator's own.
    unsafe {
        core::ptr::write_bytes(entry, 0, 40);
        teb::put(entry as u64, 0, block);
        teb::put(entry as u64, 8, kernel32::heap_size(block) as u32);
        teb::put(entry as u64, 12, 16u8);
        teb::put(entry as u64, 14, PROCESS_HEAP_ENTRY_BUSY);
    }
    TRUE
}

/// The process heap followed by every live private heap.
pub fn all() -> alloc::vec::Vec<u64> {
    let mut v = alloc::vec![kernel32::process_heap()];
    v.extend(HEAPS.lock().unwrap().keys().copied());
    v
}
