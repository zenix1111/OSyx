//! Synchronisation: futex-based `Mutex`, `RwLock`, `Condvar`, `Once` and
//! `OnceLock`, plus re-exports of `Arc`, `Weak` and the atomics.
//!
//! The API mirrors `std::sync`. Because a panic ends the whole process,
//! locks are never poisoned: `lock()` returns `LockResult` for source
//! compatibility, but it is always `Ok`.

use crate::sys;
use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

pub use alloc::sync::{Arc, Weak};
pub use core::sync::atomic;

/// Never constructed (see the module docs); kept for `std` compatibility.
pub struct PoisonError<G> {
    guard: G,
}

impl<G> PoisonError<G> {
    pub fn into_inner(self) -> G {
        self.guard
    }
}

impl<G> fmt::Debug for PoisonError<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PoisonError")
    }
}

pub type LockResult<G> = Result<G, PoisonError<G>>;

#[derive(Debug)]
pub enum TryLockError<G> {
    Poisoned(PoisonError<G>),
    WouldBlock,
}

pub type TryLockResult<G> = Result<G, TryLockError<G>>;

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;
/// Locked, and at least one thread may be sleeping on the futex.
const CONTENDED: u32 = 2;

/// A mutual exclusion lock. Uncontended lock/unlock are a single atomic
/// operation; waiters sleep in the kernel (`futex_wait`) instead of spinning.
/// The holder's thread id is recorded so that a waiter can lend it its
/// priority (priority inheritance).
pub struct Mutex<T: ?Sized> {
    futex: AtomicU32,
    owner: AtomicU64,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialised by the lock.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

/// RAII guard; the lock is released when it is dropped.
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    lock: &'a Mutex<T>,
    _not_send: PhantomData<*const ()>,
}

// SAFETY: sharing the guard only shares `&T`.
unsafe impl<T: ?Sized + Sync> Sync for MutexGuard<'_, T> {}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Mutex<T> {
        Mutex { futex: AtomicU32::new(UNLOCKED), owner: AtomicU64::new(0), data: UnsafeCell::new(value) }
    }

    pub fn into_inner(self) -> LockResult<T> {
        Ok(self.data.into_inner())
    }
}

impl<T: ?Sized> Mutex<T> {
    fn raw_lock(&self) {
        self.acquire();
        self.owner.store(sys::current_tid(), Ordering::Relaxed);
    }

    fn acquire(&self) {
        if self.futex.compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return;
        }
        // Brief spin: the holder is often about to release the lock.
        for _ in 0..100 {
            core::hint::spin_loop();
            if self.futex.load(Ordering::Relaxed) == UNLOCKED
                && self.futex.compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed).is_ok()
            {
                return;
            }
        }
        // Mark the lock contended so the holder wakes someone on unlock.
        while self.futex.swap(CONTENDED, Ordering::Acquire) != UNLOCKED {
            // The recorded holder may already be stale; the kernel only lends
            // priority to a thread of this process while this wait lasts.
            sys::futex_wait_owned(&self.futex, CONTENDED, self.owner.load(Ordering::Relaxed));
        }
    }

    fn raw_unlock(&self) {
        self.owner.store(0, Ordering::Relaxed);
        if self.futex.swap(UNLOCKED, Ordering::Release) == CONTENDED {
            sys::futex_wake(&self.futex, 1);
        }
    }

    pub fn lock(&self) -> LockResult<MutexGuard<'_, T>> {
        self.raw_lock();
        Ok(MutexGuard { lock: self, _not_send: PhantomData })
    }

    pub fn try_lock(&self) -> TryLockResult<MutexGuard<'_, T>> {
        match self.futex.compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => {
                self.owner.store(sys::current_tid(), Ordering::Relaxed);
                Ok(MutexGuard { lock: self, _not_send: PhantomData })
            }
            Err(_) => Err(TryLockError::WouldBlock),
        }
    }

    pub fn get_mut(&mut self) -> LockResult<&mut T> {
        Ok(self.data.get_mut())
    }

    pub fn is_poisoned(&self) -> bool {
        false
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Mutex<T> {
        Mutex::new(T::default())
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_lock() {
            Ok(g) => f.debug_struct("Mutex").field("data", &&*g).finish(),
            Err(_) => f.write_str("Mutex { <locked> }"),
        }
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.raw_unlock();
    }
}

/// Result of [`Condvar::wait_timeout`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitTimeoutResult(bool);

impl WaitTimeoutResult {
    pub fn timed_out(&self) -> bool {
        self.0
    }
}

/// A condition variable. `notify_*` bump a sequence number and wake futex
/// waiters; a waiter that saw an older number returns at once, so
/// notifications sent between unlocking the mutex and sleeping are not lost.
/// Spurious wake-ups are possible, as with `std`: use `wait_while`.
pub struct Condvar {
    seq: AtomicU32,
}

impl Default for Condvar {
    fn default() -> Condvar {
        Condvar::new()
    }
}

impl fmt::Debug for Condvar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Condvar")
    }
}

impl Condvar {
    pub const fn new() -> Condvar {
        Condvar { seq: AtomicU32::new(0) }
    }

    fn wait_inner<'a, T: ?Sized>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout: Option<Duration>,
    ) -> (MutexGuard<'a, T>, bool) {
        let lock = guard.lock;
        let seen = self.seq.load(Ordering::Relaxed);
        drop(guard);
        let woken = sys::futex_wait(&self.seq, seen, timeout);
        lock.raw_lock();
        (MutexGuard { lock, _not_send: PhantomData }, !woken)
    }

    pub fn wait<'a, T: ?Sized>(&self, guard: MutexGuard<'a, T>) -> LockResult<MutexGuard<'a, T>> {
        Ok(self.wait_inner(guard, None).0)
    }

    pub fn wait_while<'a, T: ?Sized, F: FnMut(&mut T) -> bool>(
        &self,
        mut guard: MutexGuard<'a, T>,
        mut condition: F,
    ) -> LockResult<MutexGuard<'a, T>> {
        while condition(&mut *guard) {
            guard = self.wait_inner(guard, None).0;
        }
        Ok(guard)
    }

    pub fn wait_timeout<'a, T: ?Sized>(
        &self,
        guard: MutexGuard<'a, T>,
        dur: Duration,
    ) -> LockResult<(MutexGuard<'a, T>, WaitTimeoutResult)> {
        let (g, timed_out) = self.wait_inner(guard, Some(dur));
        Ok((g, WaitTimeoutResult(timed_out)))
    }

    pub fn notify_one(&self) {
        self.seq.fetch_add(1, Ordering::Relaxed);
        sys::futex_wake(&self.seq, 1);
    }

    pub fn notify_all(&self) {
        self.seq.fetch_add(1, Ordering::Relaxed);
        sys::futex_wake(&self.seq, u32::MAX);
    }
}

/// A reader-writer lock. Readers share the lock; a writer has it alone.
/// Fresh readers are kept out once a writer is queued, so a stream of
/// readers cannot starve it.
pub struct RwLock<T: ?Sized> {
    /// Bit 31: a writer holds the lock. Bit 30: a writer is waiting.
    /// The low 30 bits count the readers.
    state: AtomicU32,
    data: UnsafeCell<T>,
}

const WRITER: u32 = 1 << 31;
const WRITER_WAITING: u32 = 1 << 30;
const READERS_MASK: u32 = WRITER_WAITING - 1;

// SAFETY: access to `data` is serialised by the lock.
unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}

/// RAII read guard; the lock is released when it is dropped.
pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
    lock: &'a RwLock<T>,
    _not_send: PhantomData<*const ()>,
}

// SAFETY: sharing the guard only shares `&T`.
unsafe impl<T: ?Sized + Sync> Sync for RwLockReadGuard<'_, T> {}

/// RAII write guard; the lock is released when it is dropped.
pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
    lock: &'a RwLock<T>,
    _not_send: PhantomData<*const ()>,
}

// SAFETY: sharing the guard only shares `&T`.
unsafe impl<T: ?Sized + Sync> Sync for RwLockWriteGuard<'_, T> {}

impl<T> RwLock<T> {
    pub const fn new(value: T) -> RwLock<T> {
        RwLock { state: AtomicU32::new(0), data: UnsafeCell::new(value) }
    }

    pub fn into_inner(self) -> LockResult<T> {
        Ok(self.data.into_inner())
    }
}

impl<T: ?Sized> RwLock<T> {
    fn read_acquire(&self) -> bool {
        let mut s = self.state.load(Ordering::Relaxed);
        loop {
            if s & (WRITER | WRITER_WAITING) != 0 || s & READERS_MASK == READERS_MASK {
                return false;
            }
            match self.state.compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(now) => s = now,
            }
        }
    }

    fn wait_reader(&self) {
        let s = self.state.load(Ordering::Relaxed);
        if s & (WRITER | WRITER_WAITING) == 0 && s & READERS_MASK != READERS_MASK {
            return; // became free: retry instead of sleeping
        }
        sys::futex_wait(&self.state, s, None);
    }

    fn wait_writer(&self) {
        let s = self.state.load(Ordering::Relaxed);
        if s & WRITER == 0 && s & READERS_MASK == 0 {
            return; // became free: retry instead of sleeping
        }
        sys::futex_wait(&self.state, s, None);
    }

    pub fn read(&self) -> LockResult<RwLockReadGuard<'_, T>> {
        loop {
            if self.read_acquire() {
                return Ok(RwLockReadGuard { lock: self, _not_send: PhantomData });
            }
            self.wait_reader();
        }
    }

    pub fn try_read(&self) -> TryLockResult<RwLockReadGuard<'_, T>> {
        if self.read_acquire() {
            Ok(RwLockReadGuard { lock: self, _not_send: PhantomData })
        } else {
            Err(TryLockError::WouldBlock)
        }
    }

    pub fn write(&self) -> LockResult<RwLockWriteGuard<'_, T>> {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & WRITER == 0 && s & READERS_MASK == 0 {
                // No readers: take it, even if a `WRITER_WAITING` bit is
                // left over from a writer that lost the race.
                if self.state.compare_exchange(s, WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    return Ok(RwLockWriteGuard { lock: self, _not_send: PhantomData });
                }
                continue;
            }
            // Announce the queued writer so new readers step aside.
            if s & WRITER == 0 && s & WRITER_WAITING == 0 {
                let _ = self.state.compare_exchange(s, s | WRITER_WAITING, Ordering::Relaxed, Ordering::Relaxed);
            }
            self.wait_writer();
        }
    }

    pub fn try_write(&self) -> TryLockResult<RwLockWriteGuard<'_, T>> {
        match self.state.compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => Ok(RwLockWriteGuard { lock: self, _not_send: PhantomData }),
            Err(_) => Err(TryLockError::WouldBlock),
        }
    }

    pub fn get_mut(&mut self) -> LockResult<&mut T> {
        Ok(self.data.get_mut())
    }

    pub fn is_poisoned(&self) -> bool {
        false
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> RwLock<T> {
        RwLock::new(T::default())
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_read() {
            Ok(g) => f.debug_struct("RwLock").field("data", &&*g).finish(),
            Err(_) => f.write_str("RwLock { <locked> }"),
        }
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        let old = self.lock.state.fetch_sub(1, Ordering::Release);
        if old & READERS_MASK == 1 {
            // Last reader: a writer may be waiting.
            sys::futex_wake(&self.lock.state, u32::MAX);
        }
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
        sys::futex_wake(&self.lock.state, u32::MAX);
    }
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the read lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the write lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the write lock.
        unsafe { &mut *self.lock.data.get() }
    }
}

const ONCE_INCOMPLETE: u32 = 0;
const ONCE_RUNNING: u32 = 1;
const ONCE_COMPLETE: u32 = 2;

/// Runs a closure at most once, ever. Other callers block until the first
/// one finishes; a panic inside it still marks the `Once` complete, as in
/// `std`.
pub struct Once {
    state: AtomicU32,
}

impl Default for Once {
    fn default() -> Once {
        Once::new()
    }
}

impl fmt::Debug for Once {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_completed() { "Once { complete }" } else { "Once { incomplete }" })
    }
}

impl Once {
    pub const fn new() -> Once {
        Once { state: AtomicU32::new(ONCE_INCOMPLETE) }
    }

    pub fn call_once<F: FnOnce()>(&self, f: F) {
        if self.state.load(Ordering::Acquire) == ONCE_COMPLETE {
            return;
        }
        if self.state.compare_exchange(ONCE_INCOMPLETE, ONCE_RUNNING, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            let guard = OnceGuard { state: &self.state };
            f();
            drop(guard);
            return;
        }
        while self.state.load(Ordering::Acquire) != ONCE_COMPLETE {
            sys::futex_wait(&self.state, ONCE_RUNNING, None);
        }
    }

    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == ONCE_COMPLETE
    }
}

struct OnceGuard<'a> {
    state: &'a AtomicU32,
}

impl Drop for OnceGuard<'_> {
    fn drop(&mut self) {
        self.state.store(ONCE_COMPLETE, Ordering::Release);
        sys::futex_wake(self.state, u32::MAX);
    }
}

/// A cell initialised at most once; the first caller to [`get_or_init`]
/// supplies the value and later callers read it. Lock-free after setup.
///
/// [`get_or_init`]: OnceLock::get_or_init
pub struct OnceLock<T> {
    once: Once,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the value is written once, before `once` reports completion.
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}
unsafe impl<T: Send> Send for OnceLock<T> {}

impl<T> OnceLock<T> {
    pub const fn new() -> OnceLock<T> {
        OnceLock { once: Once::new(), value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    pub fn get(&self) -> Option<&T> {
        if self.once.is_completed() {
            // SAFETY: completion is published after the write.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }

    pub fn get_mut(&mut self) -> Option<&mut T> {
        if self.once.is_completed() {
            // SAFETY: `&mut self` excludes other accesses.
            Some(unsafe { (*self.value.get()).assume_init_mut() })
        } else {
            None
        }
    }

    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
        if self.get().is_none() {
            self.once.call_once(|| {
                // SAFETY: only the thread that won `call_once` writes.
                unsafe { (*self.value.get()).write(f()) };
            });
        }
        // SAFETY: completion is published after the write.
        unsafe { (*self.value.get()).assume_init_ref() }
    }

    pub fn set(&self, value: T) -> Result<(), T> {
        let mut value = Some(value);
        self.once.call_once(|| {
            // SAFETY: only the thread that won `call_once` writes.
            unsafe { (*self.value.get()).write(value.take().unwrap()) };
        });
        match value {
            Some(v) => Err(v),
            None => Ok(()),
        }
    }

    pub fn take(&mut self) -> Option<T> {
        if self.once.is_completed() {
            // SAFETY: `&mut self`; resetting `once` stops `Drop` from
            // reading the value twice.
            let value = unsafe { self.value.get_mut().assume_init_read() };
            self.once = Once::new();
            Some(value)
        } else {
            None
        }
    }

    pub fn into_inner(mut self) -> Option<T> {
        self.take()
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> OnceLock<T> {
        OnceLock::new()
    }
}

impl<T> Drop for OnceLock<T> {
    fn drop(&mut self) {
        if self.once.is_completed() {
            // SAFETY: the value was written and `&mut self` excludes readers.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for OnceLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get() {
            Some(v) => f.debug_tuple("OnceLock").field(v).finish(),
            None => f.write_str("OnceLock { <uninit> }"),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::thread;
    use crate::time::Instant;
    use alloc::collections::VecDeque;
    use alloc::string::String;
    use alloc::vec::Vec;

    #[test]
    fn mutex_counts_correctly_under_contention() {
        let m = Arc::new(Mutex::new(0u64));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let m = m.clone();
                thread::spawn(move || {
                    for _ in 0..20_000 {
                        *m.lock().unwrap() += 1;
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(*m.lock().unwrap(), 160_000);
    }

    #[test]
    fn try_lock_and_into_inner() {
        let m = Mutex::new(5);
        let g = m.lock().unwrap();
        assert!(matches!(m.try_lock(), Err(TryLockError::WouldBlock)));
        drop(g);
        assert_eq!(*m.try_lock().ok().unwrap(), 5);
        assert_eq!(m.into_inner().ok(), Some(5));
    }

    #[test]
    fn condvar_producer_consumer() {
        let q = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let consumers: Vec<_> = (0..3)
            .map(|_| {
                let q = q.clone();
                thread::spawn(move || {
                    let mut sum = 0u64;
                    loop {
                        let (m, cv) = &*q;
                        let mut g = cv.wait_while(m.lock().unwrap(), |q: &mut VecDeque<u64>| q.is_empty()).unwrap();
                        match g.pop_front() {
                            Some(0) => return sum,
                            Some(v) => sum += v,
                            None => unreachable!(),
                        }
                    }
                })
            })
            .collect();
        {
            let (m, cv) = &*q;
            for v in 1..=1000u64 {
                m.lock().unwrap().push_back(v);
                cv.notify_one();
            }
            for _ in 0..3 {
                m.lock().unwrap().push_back(0);
            }
            cv.notify_all();
        }
        let total: u64 = consumers.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 500_500);
    }

    #[test]
    fn condvar_wait_timeout_expires() {
        let m = Mutex::new(());
        let cv = Condvar::new();
        let start = Instant::now();
        let (_g, r) = cv.wait_timeout(m.lock().unwrap(), Duration::from_millis(30)).unwrap();
        assert!(r.timed_out());
        assert!(start.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn rwlock_readers_share_and_writers_exclude() {
        let l = Arc::new(RwLock::new((0u64, 0u64)));
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let l = l.clone();
                thread::spawn(move || {
                    for _ in 0..5_000 {
                        let g = l.read().unwrap();
                        assert_eq!(g.0, g.1, "reader saw a partial update");
                    }
                })
            })
            .collect();
        let writer = {
            let l = l.clone();
            thread::spawn(move || {
                for _ in 0..2_000 {
                    let mut g = l.write().unwrap();
                    g.0 += 1;
                    g.1 += 1;
                }
            })
        };
        for h in readers {
            h.join().unwrap();
        }
        writer.join().unwrap();
        assert_eq!(*l.read().unwrap(), (2_000, 2_000));
    }

    #[test]
    fn rwlock_try_and_into_inner() {
        let mut l = RwLock::new(5);
        {
            let _r = l.read().unwrap();
            assert!(matches!(l.try_write(), Err(TryLockError::WouldBlock)));
            assert_eq!(*l.try_read().ok().unwrap(), 5);
        }
        {
            let mut w = l.try_write().ok().unwrap();
            *w = 6;
            assert!(matches!(l.try_read(), Err(TryLockError::WouldBlock)));
        }
        assert_eq!(*l.get_mut().unwrap(), 6);
        assert_eq!(l.into_inner().ok(), Some(6));
    }

    #[test]
    fn once_runs_a_single_time_under_contention() {
        let once = Arc::new(Once::new());
        let runs = Arc::new(AtomicU32::new(0));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let once = once.clone();
                let runs = runs.clone();
                thread::spawn(move || {
                    once.call_once(|| {
                        runs.fetch_add(1, Ordering::Relaxed);
                    })
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(runs.load(Ordering::Relaxed), 1);
        assert!(once.is_completed());
    }

    #[test]
    fn once_lock_set_get_and_take() {
        let cell = OnceLock::new();
        assert_eq!(cell.get(), None);
        assert_eq!(cell.set(7), Ok(()));
        assert_eq!(cell.set(8), Err(8));
        assert_eq!(cell.get(), Some(&7));
        assert_eq!(*cell.get_or_init(|| 9), 7);
        let mut cell = cell;
        assert_eq!(cell.get_mut(), Some(&mut 7));
        assert_eq!(cell.take(), Some(7));
        assert_eq!(cell.get(), None);
        assert_eq!(cell.into_inner(), None);
    }

    #[test]
    fn once_lock_init_once_across_threads() {
        let cell = Arc::new(OnceLock::<String>::new());
        let runs = Arc::new(AtomicU32::new(0));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let cell = cell.clone();
                let runs = runs.clone();
                thread::spawn(move || {
                    let v = cell.get_or_init(|| {
                        runs.fetch_add(1, Ordering::Relaxed);
                        String::from("value")
                    });
                    assert_eq!(v, "value");
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(runs.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn once_lock_drops_initialised_value() {
        struct Counts(Arc<AtomicU32>);
        impl Drop for Counts {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let drops = Arc::new(AtomicU32::new(0));
        {
            let cell = OnceLock::new();
            cell.set(Counts(drops.clone())).ok().unwrap();
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        }
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        let mut cell = OnceLock::new();
        cell.set(Counts(drops.clone())).ok().unwrap();
        drop(cell.take());
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }
}
