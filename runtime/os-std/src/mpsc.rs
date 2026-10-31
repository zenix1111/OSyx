//! Multi-producer, single-consumer queues: [`channel`] (unbounded) and
//! [`sync_channel`] (bounded), modelled on `std::sync::mpsc`.
//!
//! The queue is a [`Mutex<VecDeque<T>>`] plus two condition variables: one
//! for receivers waiting for data, one for senders waiting for space. A
//! sender count lets receivers see a disconnect; a receiver count lets
//! blocked senders fail when the last receiver goes away.

use crate::sync::{Arc, Condvar, Mutex};
use crate::time::{Duration, Instant};
use alloc::collections::VecDeque;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Error returned by [`Sender::send`] and [`SyncSender::send`] when the
/// receiver has been dropped. Carries the value back.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SendError<T>(pub T);

impl<T> fmt::Debug for SendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SendError(..)")
    }
}

impl<T> SendError<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Error returned by [`SyncSender::try_send`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrySendError<T> {
    /// The queue is full; try again later.
    Full(T),
    /// The receiver has been dropped.
    Disconnected(T),
}

impl<T> fmt::Debug for TrySendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TrySendError::Full(_) => "Full(..)",
            TrySendError::Disconnected(_) => "Disconnected(..)",
        })
    }
}

impl<T> TrySendError<T> {
    pub fn into_inner(self) -> T {
        match self {
            TrySendError::Full(v) | TrySendError::Disconnected(v) => v,
        }
    }
}

/// Error returned by [`Receiver::recv`]: every sender is gone and the queue
/// is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvError;

/// Error returned by [`Receiver::try_recv`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TryRecvError {
    /// The queue is empty but senders still exist.
    Empty,
    /// Every sender is gone and the queue is empty.
    Disconnected,
}

/// Error returned by [`Receiver::recv_timeout`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvTimeoutError {
    /// No message arrived before the deadline.
    Timeout,
    /// Every sender is gone and the queue is empty.
    Disconnected,
}

struct Shared<T> {
    queue: Mutex<VecDeque<T>>,
    /// Data or disconnect notifications for receivers.
    available: Condvar,
    /// Space notifications for senders of a bounded queue.
    space: Condvar,
    /// Capacity; 0 means unbounded.
    bound: usize,
    senders: AtomicUsize,
    receivers: AtomicUsize,
}

impl<T> Shared<T> {
    fn new(bound: usize) -> Shared<T> {
        Shared {
            queue: Mutex::new(VecDeque::new()),
            available: Condvar::new(),
            space: Condvar::new(),
            bound,
            senders: AtomicUsize::new(1),
            receivers: AtomicUsize::new(1),
        }
    }

    fn send(&self, value: T, block: bool) -> Result<(), TrySendError<T>> {
        let mut q = self.queue.lock().unwrap();
        if self.bound != 0 {
            while q.len() >= self.bound {
                if self.receivers.load(Ordering::Acquire) == 0 {
                    return Err(TrySendError::Disconnected(value));
                }
                if !block {
                    return Err(TrySendError::Full(value));
                }
                q = self.space.wait(q).unwrap();
            }
        }
        if self.receivers.load(Ordering::Acquire) == 0 {
            return Err(TrySendError::Disconnected(value));
        }
        q.push_back(value);
        self.available.notify_one();
        Ok(())
    }
}

/// The sending half of an unbounded [`channel`].
pub struct Sender<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Sender<T> {
        self.shared.senders.fetch_add(1, Ordering::Relaxed);
        Sender { shared: self.shared.clone() }
    }
}

impl<T> Sender<T> {
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        self.shared.send(value, true).map_err(|e| SendError(e.into_inner()))
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        if self.shared.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.available.notify_all();
        }
    }
}

impl<T> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sender { .. }")
    }
}

/// The sending half of a bounded [`sync_channel`].
pub struct SyncSender<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for SyncSender<T> {
    fn clone(&self) -> SyncSender<T> {
        self.shared.senders.fetch_add(1, Ordering::Relaxed);
        SyncSender { shared: self.shared.clone() }
    }
}

impl<T> SyncSender<T> {
    /// Blocks while the queue is full.
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        self.shared.send(value, true).map_err(|e| SendError(e.into_inner()))
    }

    /// Fails with [`TrySendError::Full`] instead of blocking.
    pub fn try_send(&self, value: T) -> Result<(), TrySendError<T>> {
        self.shared.send(value, false)
    }
}

impl<T> Drop for SyncSender<T> {
    fn drop(&mut self) {
        if self.shared.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.available.notify_all();
        }
    }
}

impl<T> fmt::Debug for SyncSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SyncSender { .. }")
    }
}

/// The receiving half of a channel.
pub struct Receiver<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Receiver<T> {
    /// Blocks until a value arrives or every sender is dropped.
    pub fn recv(&self) -> Result<T, RecvError> {
        let mut q = self.shared.queue.lock().unwrap();
        loop {
            if let Some(v) = q.pop_front() {
                self.shared.space.notify_one();
                return Ok(v);
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                return Err(RecvError);
            }
            q = self.shared.available.wait(q).unwrap();
        }
    }

    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut q = self.shared.queue.lock().unwrap();
        match q.pop_front() {
            Some(v) => {
                self.shared.space.notify_one();
                Ok(v)
            }
            None if self.shared.senders.load(Ordering::Acquire) == 0 => Err(TryRecvError::Disconnected),
            None => Err(TryRecvError::Empty),
        }
    }

    /// Blocks until a value arrives, the senders are gone, or `timeout`
    /// elapses.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<T, RecvTimeoutError> {
        let start = Instant::now();
        let mut q = self.shared.queue.lock().unwrap();
        loop {
            if let Some(v) = q.pop_front() {
                self.shared.space.notify_one();
                return Ok(v);
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                return Err(RecvTimeoutError::Disconnected);
            }
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(RecvTimeoutError::Timeout);
            }
            q = self.shared.available.wait_timeout(q, timeout - elapsed).unwrap().0;
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        if self.shared.receivers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.space.notify_all();
            self.shared.available.notify_all();
        }
    }
}

impl<T> fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Receiver { .. }")
    }
}

/// Creates an unbounded channel: [`Sender::send`] never blocks.
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let shared = Arc::new(Shared::new(0));
    (Sender { shared: shared.clone() }, Receiver { shared })
}

/// Creates a bounded channel: at most `bound` values wait in the queue.
pub fn sync_channel<T>(bound: usize) -> (SyncSender<T>, Receiver<T>) {
    let shared = Arc::new(Shared::new(bound));
    (SyncSender { shared: shared.clone() }, Receiver { shared })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::thread;
    use alloc::vec::Vec;

    #[test]
    fn sends_from_many_clones_arrive() {
        let (tx, rx) = channel::<u64>();
        let hs: Vec<_> = (0..4)
            .map(|i| {
                let tx = tx.clone();
                thread::spawn(move || {
                    for j in 0..25 {
                        tx.send(i * 100 + j).unwrap();
                    }
                })
            })
            .collect();
        drop(tx);
        let mut sum = 0;
        for _ in 0..100 {
            sum += rx.recv().unwrap();
        }
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(sum, 100 * (0..4).sum::<u64>() * 25 + 4 * (0..25).sum::<u64>());
        assert_eq!(rx.recv(), Err(RecvError));
    }

    #[test]
    fn try_recv_reports_empty_and_disconnect() {
        let (tx, rx) = channel::<u8>();
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        tx.send(7).unwrap();
        assert_eq!(rx.try_recv(), Ok(7));
        drop(tx);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn sync_channel_rejects_when_full_and_recovers() {
        let (tx, rx) = sync_channel::<u8>(2);
        tx.try_send(1).unwrap();
        tx.try_send(2).unwrap();
        assert_eq!(tx.try_send(3), Err(TrySendError::Full(3)));
        assert_eq!(rx.recv(), Ok(1));
        tx.try_send(3).unwrap();
        assert_eq!(rx.recv(), Ok(2));
        assert_eq!(rx.recv(), Ok(3));
    }

    #[test]
    fn blocked_sender_fails_when_receiver_drops() {
        let (tx, rx) = sync_channel::<u8>(1);
        tx.send(1).unwrap();
        let h = thread::spawn(move || tx.send(2));
        thread::sleep(Duration::from_millis(20));
        drop(rx);
        assert_eq!(h.join().unwrap(), Err(SendError(2)));
    }

    #[test]
    fn recv_timeout_expires() {
        let (_tx, rx) = channel::<u8>();
        let start = Instant::now();
        assert_eq!(rx.recv_timeout(Duration::from_millis(30)), Err(RecvTimeoutError::Timeout));
        assert!(start.elapsed() >= Duration::from_millis(30));
    }
}
