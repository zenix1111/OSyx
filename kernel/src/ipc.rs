//! IPC channels: bidirectional, message-oriented connections to named
//! services.
//!
//! A server registers a name with [`listen`]; a client [`connect`]s and gets
//! one end of a new channel while the other end waits in the listener's
//! backlog for [`Listener::accept`]. Messages are byte strings of at most
//! `MAX_MESSAGE` bytes that may carry a few handles (shared memory and pipe
//! ends; never channels, so no reference cycles can form). Queues are
//! bounded per direction and sending never blocks, so a stuck receiver
//! cannot stall its peer: the sender gets `WouldBlock` and decides (the
//! compositor drops such clients). Each end knows the pid and uid of its
//! peer, recorded by the kernel at connection time.

use crate::object::Object;
use crate::sync::IrqSpinLock;
use crate::waitq::WaitQueue;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use osyx_abi::ipc::{
    MAX_BACKLOG, MAX_MESSAGE, MAX_QUEUED_BYTES, MAX_QUEUED_MESSAGES, MAX_SERVICE_NAME, WAIT_HANGUP, WAIT_READABLE, WAIT_WRITABLE,
};
use osyx_abi::Errno;

pub struct Message {
    pub data: Vec<u8>,
    pub objects: Vec<Object>,
}

#[derive(Default)]
struct Side {
    /// Messages addressed to this side.
    queue: VecDeque<Message>,
    bytes: usize,
    /// This side's endpoint is gone.
    closed: bool,
}

pub struct Channel {
    sides: IrqSpinLock<[Side; 2]>,
    /// Signalled for side `i` when a message arrives for it or its peer leaves.
    waitq: [WaitQueue; 2],
    /// (pid, uid) of the process behind each side.
    owners: [(u64, u32); 2],
}

pub struct Endpoint {
    ch: Arc<Channel>,
    side: usize,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        // Undelivered messages (and the handles they carry) are dropped
        // outside the lock: dropping a pipe end wakes its waiters.
        let undelivered = {
            let mut s = self.ch.sides.lock();
            s[self.side].closed = true;
            s[self.side].bytes = 0;
            core::mem::take(&mut s[self.side].queue)
        };
        drop(undelivered);
        self.ch.waitq[1 - self.side].wake_all();
    }
}

impl Endpoint {
    fn peer(&self) -> usize {
        1 - self.side
    }

    /// (pid, uid) of the other end's process.
    pub fn peer_identity(&self) -> (u64, u32) {
        self.ch.owners[self.peer()]
    }

    pub fn send(&self, data: Vec<u8>, objects: Vec<Object>) -> Result<(), Errno> {
        if data.len() > MAX_MESSAGE || objects.len() > osyx_abi::ipc::MAX_MESSAGE_HANDLES {
            return Err(Errno::InvalidArgument);
        }
        {
            let mut s = self.ch.sides.lock();
            let p = &mut s[self.peer()];
            if p.closed {
                return Err(Errno::BrokenPipe);
            }
            if p.queue.len() >= MAX_QUEUED_MESSAGES || p.bytes + data.len() > MAX_QUEUED_BYTES {
                return Err(Errno::WouldBlock);
            }
            p.bytes += data.len();
            p.queue.push_back(Message { data, objects });
        }
        self.ch.waitq[self.peer()].wake_all();
        Ok(())
    }

    /// The next message if it fits `capacity` bytes and carries at most
    /// `max_objects` handles (otherwise `InvalidArgument`, and it stays queued).
    pub fn recv(&self, capacity: usize, max_objects: usize) -> Result<Message, Errno> {
        let msg = {
            let mut s = self.ch.sides.lock();
            let peer_closed = s[self.peer()].closed;
            let me = &mut s[self.side];
            match me.queue.front() {
                None if peer_closed => return Err(Errno::BrokenPipe),
                None => return Err(Errno::WouldBlock),
                Some(m) if m.data.len() > capacity || m.objects.len() > max_objects => return Err(Errno::InvalidArgument),
                Some(_) => {}
            }
            let m = me.queue.pop_front().expect("checked above");
            me.bytes -= m.data.len();
            m
        };
        // The peer may be waiting for queue space.
        self.ch.waitq[self.peer()].wake_all();
        Ok(msg)
    }

    pub fn poll(&self) -> u32 {
        let s = self.ch.sides.lock();
        let mut r = 0;
        if !s[self.side].queue.is_empty() {
            r |= WAIT_READABLE;
        }
        let p = &s[self.peer()];
        if p.closed {
            r |= WAIT_HANGUP | WAIT_READABLE;
        } else if p.queue.len() < MAX_QUEUED_MESSAGES && p.bytes < MAX_QUEUED_BYTES {
            r |= WAIT_WRITABLE;
        }
        r
    }

    pub fn queue(&self) -> &WaitQueue {
        &self.ch.waitq[self.side]
    }
}

/// A named service accepting connections.
pub struct Listener {
    name: String,
    owner: (u64, u32),
    backlog: IrqSpinLock<VecDeque<Endpoint>>,
    waitq: WaitQueue,
}

static SERVICES: IrqSpinLock<BTreeMap<String, Weak<Listener>>> = IrqSpinLock::new(BTreeMap::new());

/// Anonymous endpoints are never published in the service namespace.
pub fn pair(pid: u64, uid: u32) -> (Endpoint, Endpoint) {
    let ch = Arc::new(Channel {
        sides: IrqSpinLock::new([Side::default(), Side::default()]),
        waitq: [WaitQueue::new(), WaitQueue::new()],
        owners: [(pid, uid), (pid, uid)],
    });
    (Endpoint { ch: ch.clone(), side: 0 }, Endpoint { ch, side: 1 })
}

fn check_name(name: &str) -> Result<(), Errno> {
    let ok = !name.is_empty()
        && name.len() <= MAX_SERVICE_NAME
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(Errno::InvalidArgument)
    }
}

/// Registers service `name` for process `pid` (uid `uid`).
pub fn listen(name: &str, pid: u64, uid: u32) -> Result<Arc<Listener>, Errno> {
    check_name(name)?;
    let mut services = SERVICES.lock();
    if services.get(name).is_some_and(|w| w.strong_count() > 0) {
        return Err(Errno::AlreadyExists);
    }
    let l = Arc::new(Listener {
        name: String::from(name),
        owner: (pid, uid),
        backlog: IrqSpinLock::new(VecDeque::new()),
        waitq: WaitQueue::new(),
    });
    services.insert(String::from(name), Arc::downgrade(&l));
    Ok(l)
}

/// Connects process `pid` (uid `uid`) to service `name`; returns the
/// client end.
pub fn connect(name: &str, pid: u64, uid: u32) -> Result<Endpoint, Errno> {
    check_name(name)?;
    let l = SERVICES.lock().get(name).and_then(Weak::upgrade).ok_or(Errno::NotFound)?;
    if l.owner.1 != 0 && uid != 0 && uid != l.owner.1 {
        return Err(Errno::PermissionDenied);
    }
    let ch = Arc::new(Channel {
        sides: IrqSpinLock::new([Side::default(), Side::default()]),
        waitq: [WaitQueue::new(), WaitQueue::new()],
        owners: [(pid, uid), l.owner],
    });
    let client = Endpoint { ch: ch.clone(), side: 0 };
    let server = Endpoint { ch, side: 1 };
    {
        let mut b = l.backlog.lock();
        if b.len() >= MAX_BACKLOG {
            drop(b);
            drop(server);
            return Err(Errno::Busy);
        }
        b.push_back(server);
    }
    l.waitq.wake_all();
    Ok(client)
}

impl Listener {
    pub fn accept(&self) -> Result<Endpoint, Errno> {
        self.backlog.lock().pop_front().ok_or(Errno::WouldBlock)
    }

    pub fn poll(&self) -> u32 {
        if self.backlog.lock().is_empty() {
            0
        } else {
            WAIT_READABLE
        }
    }

    pub fn queue(&self) -> &WaitQueue {
        &self.waitq
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let pending = core::mem::take(&mut *self.backlog.lock());
        drop(pending);
        let mut services = SERVICES.lock();
        if services.get(&self.name).is_some_and(|w| w.strong_count() == 0) {
            services.remove(&self.name);
        }
    }
}

/// Names of the registered services (diagnostics).
pub fn services() -> Vec<String> {
    SERVICES.lock().iter().filter(|(_, w)| w.strong_count() > 0).map(|(n, _)| n.clone()).collect()
}
