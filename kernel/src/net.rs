//! Networking: the `osyx_net` stack, its network thread, socket objects
//! and the ABI v8 system calls.
//!
//! Locking: the stack sits behind one sleeping mutex (`STACK`); it never
//! blocks inside. Frames it produces are handed to the drivers after the
//! mutex is released. Socket readiness is copied into each socket object's
//! atomic flags after every stack operation, so `wait_handles` can poll a
//! socket with interrupts disabled without touching the stack; waiters
//! sleep on `CHANGED` and re-check.
//!
//! The network thread wakes on device interrupts and on the stack's next
//! timer deadline: it collects received frames, runs the timers, transmits
//! and releases sockets whose handles were closed (closing only queues the
//! id, so dropping a handle never takes the stack lock).

use crate::drivers::virtio_net::{self, VirtioNet};
use crate::drivers::e1000::{self, E1000};
use crate::drivers::rtl8168::{self, Rtl8168};
use crate::fixup::{copy_from_user, copy_to_user, user_range_ok};
use crate::object::Object;
use crate::sync::{IrqSpinLock, KMutex};
use crate::waitq::{block_on, deadline_after_ns, WaitQueue};
use crate::{interrupts, kprintln, pci, process, sched};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use osyx_abi::net::{self as abi, SockAddr};
use osyx_abi::Errno;
use osyx_net::stack::{IcmpEvent, NetError, Resolve, Stack};
use osyx_net::wire::{Endpoint, Ipv4Addr};

static STACK: KMutex<Option<Stack>> = KMutex::new(None);
trait NetDevice: Send + Sync {
    fn is_wireless(&self) -> bool { false }
    fn link_up(&self) -> bool;
    fn has_interrupts(&self) -> bool;
    fn counters(&self) -> virtio_net::Counters;
    fn receive(&self, frames: &mut Vec<Vec<u8>>);
    fn transmit(&self, frames: &[Vec<u8>]) -> usize;
    fn recover(&self) -> bool;
    fn description(&self) -> String;
}

macro_rules! impl_net_device {
    ($ty:ty, $kind:literal) => {
        impl NetDevice for $ty {
            fn link_up(&self) -> bool { self.link_up() }
            fn has_interrupts(&self) -> bool { self.has_interrupts() }
            fn counters(&self) -> virtio_net::Counters { self.counters() }
            fn receive(&self, frames: &mut Vec<Vec<u8>>) { self.receive(frames) }
            fn transmit(&self, frames: &[Vec<u8>]) -> usize { self.transmit(frames) }
            fn recover(&self) -> bool { self.recover() }
            fn description(&self) -> String { alloc::format!("{} ({} at {})", self.name, $kind, self.location) }
        }
    };
}
impl_net_device!(VirtioNet, "virtio-net");
impl_net_device!(E1000, "e1000");
impl_net_device!(Rtl8168, "rtl8168");
impl NetDevice for crate::bsd::BsdNic {
    fn is_wireless(&self) -> bool { self.is_wireless() }
    fn link_up(&self) -> bool { self.link_up() }
    fn has_interrupts(&self) -> bool { self.has_interrupts() }
    fn counters(&self) -> virtio_net::Counters { self.counters() }
    fn receive(&self, frames: &mut Vec<Vec<u8>>) { self.receive(frames) }
    fn transmit(&self, frames: &[Vec<u8>]) -> usize { self.transmit(frames) }
    fn recover(&self) -> bool { self.recover() }
    fn description(&self) -> String { alloc::format!("{} (openbsd at {})", self.name, self.location) }
}
type Devices = Vec<(usize, Arc<dyn NetDevice>)>;
static DEVICES: IrqSpinLock<Devices> = IrqSpinLock::new(Vec::new());
/// The network thread sleeps here; device interrupts wake it.
static WAKE: WaitQueue = WaitQueue::new();
static KICK: AtomicBool = AtomicBool::new(false);
/// Socket waiters sleep here; woken whenever any socket changed.
static CHANGED: WaitQueue = WaitQueue::new();
static GENERATION: AtomicU64 = AtomicU64::new(0);
static SOCKETS: IrqSpinLock<Vec<Weak<SocketObj>>> = IrqSpinLock::new(Vec::new());
/// Stack sockets whose handles were closed: (id, reset).
static CLOSING: IrqSpinLock<Vec<(u32, bool)>> = IrqSpinLock::new(Vec::new());
static ENABLED: AtomicBool = AtomicBool::new(false);

const READABLE: u32 = osyx_abi::ipc::WAIT_READABLE;
const WRITABLE: u32 = osyx_abi::ipc::WAIT_WRITABLE;
const HANGUP: u32 = osyx_abi::ipc::WAIT_HANGUP;
/// Longest a name lookup may take.
const RESOLVE_TIMEOUT_NS: u64 = 10_000_000_000;

/// Wakes the network thread (interrupt-safe).
pub fn wake() {
    KICK.store(true, Ordering::Release);
    WAKE.wake_all();
}

fn now_ms() -> u64 {
    interrupts::uptime_ms()
}

/// Runs `f` on the stack, then transmits its output, logs its events and
/// refreshes socket readiness. `None` if networking is off.
fn with_stack<R>(f: impl FnOnce(&mut Stack) -> R) -> Option<R> {
    let (r, tx, log, changed) = {
        let mut g = STACK.lock();
        let s = g.as_mut()?;
        s.set_now(now_ms());
        let r = f(s);
        let changed = s.take_changed();
        refresh_readiness(s);
        (r, s.take_tx(), s.take_log(), changed)
    };
    for line in log {
        kprintln!("net: {}", line);
    }
    transmit(tx);
    // Readiness may have changed even when the stack did not flag it (a
    // socket's own operation), so waiters always re-check.
    let _ = changed;
    GENERATION.fetch_add(1, Ordering::Release);
    CHANGED.wake_all();
    Some(r)
}

fn transmit(frames: Vec<(usize, Vec<u8>)>) {
    if frames.is_empty() {
        return;
    }
    let devs = DEVICES.lock().clone();
    for (iface, dev) in devs {
        let mine: Vec<Vec<u8>> = frames.iter().filter(|(i, _)| *i == iface).map(|(_, f)| f.clone()).collect();
        if !mine.is_empty() {
            dev.transmit(&mine);
        }
    }
}

fn refresh_readiness(s: &Stack) {
    let mut list = SOCKETS.lock();
    list.retain(|w| w.strong_count() > 0);
    for w in list.iter() {
        if let Some(obj) = w.upgrade() {
            let id = obj.state.lock().id;
            let bits = match id {
                Some(id) => {
                    let (r, w, h) = s.poll_socket(id);
                    (if r { READABLE } else { 0 }) | (if w { WRITABLE } else { 0 }) | (if h { HANGUP } else { 0 })
                }
                // Not yet bound/connected: sending binds implicitly.
                None => WRITABLE,
            };
            obj.ready.store(bits, Ordering::Release);
        }
    }
}

/// Probes the network devices, builds the stack and starts its thread.
/// Command line: `net=off`, `net.ip=A.B.C.D/P`, `net.gw=A.B.C.D`,
/// `net.dns=A.B.C.D[,A.B.C.D]`; without `net.ip` every interface uses DHCP.
pub fn init(devices: &[pci::Device], boot: &crate::BootData) -> usize {
    if boot.has_option("net=off") {
        kprintln!("net: disabled on the command line");
        crate::bsd::after_mount();
        return 0;
    }
    let mut seed = [0u8; 8];
    let _ = crate::random::fill(&mut seed);
    let mut stack = Stack::new(u64::from_le_bytes(seed) ^ interrupts::ticks());
    let mut found = 0;
    for d in devices.iter().filter(|d| d.vendor == crate::drivers::virtio::VENDOR && virtio_net::DEVICE_IDS.contains(&d.device)) {
        let name = alloc::format!("eth{}", found);
        match VirtioNet::probe(d, &name) {
            Ok(dev) => {
                let idx = stack.add_ethernet(&name, dev.mac, dev.mtu);
                stack.set_link(idx, dev.link_up());
                DEVICES.lock().push((idx, Arc::new(dev)));
                found += 1;
            }
            Err(e) => kprintln!("virtio-net at {}: probe failed: {:?}", d.addr, e),
        }
    }
    for d in devices.iter().filter(|d| d.vendor == 0x8086 && e1000::DEVICE_IDS.contains(&d.device)) {
        let name = alloc::format!("eth{}", found);
        match E1000::probe(d, &name) {
            Ok(dev) => {
                let idx = stack.add_ethernet(&name, dev.mac, 1500);
                stack.set_link(idx, dev.link_up());
                DEVICES.lock().push((idx, Arc::new(dev)));
                found += 1;
            }
            Err(e) => kprintln!("e1000 at {}: probe failed: {}", d.addr, e),
        }
    }
    // OpenBSD drivers (re, rl) first: the native rtl8168 driver only takes
    // what they left.
    let bsd = crate::bsd::probe(devices);
    // iwm reads its firmware and obtains its real MAC during mountroot.
    // Do this before creating network interfaces and DHCP clients.
    crate::bsd::after_mount();
    for nic in &bsd {
        let name = alloc::format!("eth{}", found);
        kprintln!("net: {} is {} (OpenBSD driver) at {}", name, nic.name, nic.location);
        let idx = stack.add_ethernet(&name, nic.mac_address(), 1500);
        stack.set_link(idx, nic.link_up());
        DEVICES.lock().push((idx, nic.clone()));
        found += 1;
    }
    for d in devices.iter().filter(|d| rtl8168::supports(d) && !bsd.iter().any(|n| n.location == d.addr)) {
        let name = alloc::format!("eth{}", found);
        match Rtl8168::probe(d, &name) {
            Ok(dev) => {
                let idx = stack.add_ethernet(&name, dev.mac, 1500);
                stack.set_link(idx, dev.link_up());
                DEVICES.lock().push((idx, Arc::new(dev)));
                found += 1;
            }
            Err(e) => kprintln!("rtl8168 at {}: probe failed: {}", d.addr, e),
        }
    }
    let static_ip = boot.option_value("net.ip").and_then(parse_cidr);
    for i in 1..=found {
        match static_ip {
            Some((addr, prefix)) if i == 1 => {
                let gw = boot.option_value("net.gw").and_then(Ipv4Addr::parse);
                if let Err(e) = stack.configure_static(i, addr, prefix, gw) {
                    kprintln!("net: static configuration rejected: {}", e.name());
                }
            }
            _ => {
                let _ = stack.enable_dhcp(i);
            }
        }
    }
    if let Some(dns) = boot.option_value("net.dns") {
        let servers: Vec<Ipv4Addr> = dns.split(',').filter_map(Ipv4Addr::parse).collect();
        stack.set_dns_servers(&servers);
    }
    for line in stack.take_log() {
        kprintln!("net: {}", line);
    }
    *STACK.lock() = Some(stack);
    ENABLED.store(true, Ordering::Release);
    sched::spawn_kernel("net", net_thread, 0, 0);
    kprintln!("net: {} interface(s) besides loopback, network thread started", found);
    found
}

fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (a, p) = s.split_once('/').unwrap_or((s, "24"));
    let p: u8 = p.parse().ok()?;
    (p <= 32).then_some((Ipv4Addr::parse(a)?, p))
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// TEMP: TCP flow-control snapshot for the periodic stats.
pub fn debug_lines() -> Vec<String> {
    STACK.lock().as_ref().map(|s| s.tcp_snapshot()).unwrap_or_default()
}

fn net_thread(_: u64, _: u64) {
    let mut last_health = 0;
    loop {
        let (deadline_ms, polled) = {
            let g = STACK.lock();
            let d = g.as_ref().and_then(|s| s.next_deadline());
            let polled = DEVICES.lock().iter().any(|(_, d)| !d.has_interrupts());
            (d, polled)
        };
        let now = now_ms();
        // Sleep until the next timer, an interrupt, or at most a second.
        let mut wait_ms = deadline_ms.map_or(1000, |d| d.saturating_sub(now)).min(1000);
        if polled {
            wait_ms = wait_ms.min(1);
        }
        if wait_ms > 0 && !KICK.load(Ordering::Acquire) && CLOSING.lock().is_empty() {
            let deadline = Some(interrupts::ticks() + crate::arch::timer::ms_to_ticks(wait_ms));
            let _ = block_on(&[&WAKE], deadline, || KICK.load(Ordering::Acquire).then_some(()));
        }
        KICK.store(false, Ordering::Release);
        let devs = DEVICES.lock().clone();
        let mut rx: Vec<(usize, Vec<Vec<u8>>)> = Vec::new();
        let check_health = now_ms() >= last_health + 1000;
        for (iface, dev) in &devs {
            if check_health {
                dev.recover();
            }
            let mut frames = Vec::new();
            dev.receive(&mut frames);
            rx.push((*iface, frames));
        }
        if check_health {
            last_health = now_ms();
        }
        let closing = core::mem::take(&mut *CLOSING.lock());
        let links: Vec<(usize, bool)> = if check_health { devs.iter().map(|(i, d)| (*i, d.link_up())).collect() } else { Vec::new() };
        with_stack(|s| {
            for (id, reset) in closing {
                s.close(id, reset);
            }
            for (iface, up) in links {
                s.set_link(iface, up);
            }
            for (iface, frames) in &rx {
                for f in frames {
                    s.receive(*iface, f);
                }
            }
            s.poll();
        });
    }
}

// ----- socket objects -------------------------------------------------------------

struct SockState {
    id: Option<u32>,
    bound: Option<Endpoint>,
    listening: bool,
}

/// A socket handle's kernel object.
pub struct SocketObj {
    kind: u64,
    state: IrqSpinLock<SockState>,
    ready: AtomicU32,
    nonblock: AtomicBool,
    broadcast: AtomicBool,
    reset_on_close: AtomicBool,
    recv_timeout: AtomicU64,
    send_timeout: AtomicU64,
    connect_timeout: AtomicU64,
}

impl SocketObj {
    /// Readiness for `wait_handles` (spinlock-free).
    pub fn poll(&self) -> u32 {
        self.ready.load(Ordering::Acquire)
    }

    fn id(&self) -> Option<u32> {
        self.state.lock().id
    }
}

impl Drop for SocketObj {
    fn drop(&mut self) {
        if let Some(id) = self.state.lock().id {
            CLOSING.lock().push((id, self.reset_on_close.load(Ordering::Relaxed)));
            wake();
        }
    }
}

/// Queue socket waiters sleep on.
pub fn socket_queue() -> &'static WaitQueue {
    &CHANGED
}

fn errno(e: NetError) -> Errno {
    match e {
        NetError::WouldBlock => Errno::WouldBlock,
        NetError::InvalidArgument => Errno::InvalidArgument,
        NetError::AddrInUse => Errno::AddrInUse,
        NetError::AddrNotAvailable => Errno::AddrNotAvailable,
        NetError::NoRoute => Errno::NetUnreachable,
        NetError::HostUnreachable => Errno::HostUnreachable,
        NetError::PortUnreachable | NetError::ConnRefused => Errno::ConnRefused,
        NetError::ConnReset => Errno::ConnReset,
        NetError::TimedOut => Errno::TimedOut,
        NetError::NotConnected => Errno::NotConnected,
        NetError::AlreadyConnected => Errno::AlreadyConnected,
        NetError::MessageTooLong => Errno::MessageTooLong,
        NetError::NoBuffers => Errno::NoMemory,
        NetError::Shutdown => Errno::BrokenPipe,
        NetError::NameNotFound => Errno::NameNotFound,
        NetError::DnsFailure => Errno::DnsFailure,
        NetError::BadSocket => Errno::BadHandle,
    }
}

fn get_user<T: Copy + Default>(addr: u64) -> Result<T, Errno> {
    let mut v = T::default();
    // SAFETY: only used with padding-free repr(C) ABI structs.
    let bytes = unsafe { core::slice::from_raw_parts_mut(&mut v as *mut T as *mut u8, core::mem::size_of::<T>()) };
    copy_from_user(bytes, addr)?;
    Ok(v)
}

fn put_user<T: Copy>(addr: u64, v: &T) -> Result<(), Errno> {
    // SAFETY: as in `get_user`.
    let bytes = unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) };
    copy_to_user(addr, bytes)
}

fn to_ep(a: SockAddr) -> Endpoint {
    Endpoint::new(Ipv4Addr(a.addr), a.port)
}

fn to_sa(e: Endpoint) -> SockAddr {
    SockAddr::new(e.addr.0, e.port)
}

fn socket_of(h: u64) -> Result<Arc<SocketObj>, Errno> {
    match process::get_object(h)? {
        Object::Socket(s) => Ok(s),
        _ => Err(Errno::BadHandle),
    }
}

fn stack_call<R>(f: impl FnOnce(&mut Stack) -> Result<R, NetError>) -> Result<R, Errno> {
    with_stack(f).ok_or(Errno::NotSupported)?.map_err(errno)
}

/// Retries `op` until it stops saying `WouldBlock`, sleeping until the
/// socket shows one of `want` (or hangs up) in between.
fn blocking<R>(s: &SocketObj, want: u32, timeout_ns: u64, mut op: impl FnMut(&mut Stack) -> Result<R, NetError>) -> Result<R, Errno> {
    let deadline = if timeout_ns == 0 { None } else { deadline_after_ns(timeout_ns) };
    loop {
        match stack_call(&mut op) {
            Err(Errno::WouldBlock) if !s.nonblock.load(Ordering::Relaxed) => {
                let seen = GENERATION.load(Ordering::Acquire);
                block_on(&[&CHANGED], deadline, || {
                    (s.ready.load(Ordering::Acquire) & (want | HANGUP) != 0 || GENERATION.load(Ordering::Acquire) != seen).then_some(())
                })?;
            }
            r => return r,
        }
    }
}

pub fn sys_socket(kind: u64) -> Result<u64, Errno> {
    if !enabled() {
        return Err(Errno::NotSupported);
    }
    if !matches!(kind, abi::SOCK_STREAM | abi::SOCK_DGRAM | abi::SOCK_PING) {
        return Err(Errno::InvalidArgument);
    }
    let id = if kind == abi::SOCK_PING { Some(stack_call(|s| s.icmp_open())?) } else { None };
    let obj = Arc::new(SocketObj {
        kind,
        state: IrqSpinLock::new(SockState { id, bound: None, listening: false }),
        ready: AtomicU32::new(WRITABLE),
        nonblock: AtomicBool::new(false),
        broadcast: AtomicBool::new(false),
        reset_on_close: AtomicBool::new(false),
        recv_timeout: AtomicU64::new(0),
        send_timeout: AtomicU64::new(0),
        connect_timeout: AtomicU64::new(0),
    });
    SOCKETS.lock().push(Arc::downgrade(&obj));
    process::add_object(Object::Socket(obj))
}

/// Creates the stack's UDP socket on first use (bind or send).
fn ensure_udp(s: &SocketObj, local: Option<Endpoint>) -> Result<u32, Errno> {
    if let Some(id) = s.id() {
        if local.is_some() {
            return Err(Errno::InvalidArgument); // already bound
        }
        return Ok(id);
    }
    let ep = local.unwrap_or_default();
    let id = stack_call(|st| st.udp_bind(ep))?;
    if s.broadcast.load(Ordering::Relaxed) {
        let _ = stack_call(|st| st.udp_set_broadcast(id, true));
    }
    let mut g = s.state.lock();
    if let Some(existing) = g.id {
        // Another caller bound first. Release our stack socket through the
        // network thread, outside the socket state lock.
        drop(g);
        CLOSING.lock().push((id, false));
        wake();
        return if local.is_some() { Err(Errno::InvalidArgument) } else { Ok(existing) };
    }
    g.id = Some(id);
    g.bound = Some(ep);
    Ok(id)
}

pub fn sys_bind(h: u64, addr: u64) -> Result<u64, Errno> {
    let s = socket_of(h)?;
    let ep = to_ep(get_user::<SockAddr>(addr)?);
    match s.kind {
        abi::SOCK_DGRAM => ensure_udp(&s, Some(ep)).map(|_| 0),
        abi::SOCK_STREAM => {
            if s.id().is_some() {
                return Err(Errno::InvalidArgument);
            }
            let (id, local) = stack_call(|st| {
                let id = st.tcp_bind(ep)?;
                Ok((id, st.tcp_bound_local(id)?))
            })?;
            let mut g = s.state.lock();
            if g.id.is_some() {
                // Another bind won the race. Release our unused reservation
                // through the network thread, outside the socket state lock.
                CLOSING.lock().push((id, false));
                wake();
                return Err(Errno::InvalidArgument);
            }
            g.id = Some(id);
            g.bound = Some(local);
            drop(g);
            with_stack(|_| ());
            Ok(0)
        }
        _ => Err(Errno::NotSupported),
    }
}

pub fn sys_listen(h: u64, backlog: u64) -> Result<u64, Errno> {
    let s = socket_of(h)?;
    if s.kind != abi::SOCK_STREAM {
        return Err(Errno::NotSupported);
    }
    let id = {
        let g = s.state.lock();
        if g.listening || g.bound.is_none() {
            return Err(Errno::InvalidArgument);
        }
        g.id.ok_or(Errno::InvalidArgument)?
    };
    stack_call(|st| st.tcp_listen_bound(id, backlog as usize))?;
    let mut g = s.state.lock();
    g.id = Some(id);
    g.listening = true;
    Ok(0)
}

pub fn sys_accept(h: u64, peer: u64) -> Result<u64, Errno> {
    let s = socket_of(h)?;
    let (id, listening) = {
        let g = s.state.lock();
        (g.id, g.listening)
    };
    let id = id.filter(|_| listening).ok_or(Errno::InvalidArgument)?;
    if peer != 0 && !user_range_ok(peer, 8) {
        return Err(Errno::Fault);
    }
    let (conn, remote) = blocking(&s, READABLE, s.recv_timeout.load(Ordering::Relaxed), |st| st.tcp_accept(id))?;
    let obj = Arc::new(SocketObj {
        kind: abi::SOCK_STREAM,
        state: IrqSpinLock::new(SockState { id: Some(conn), bound: None, listening: false }),
        ready: AtomicU32::new(WRITABLE),
        nonblock: AtomicBool::new(false),
        broadcast: AtomicBool::new(false),
        reset_on_close: AtomicBool::new(false),
        recv_timeout: AtomicU64::new(0),
        send_timeout: AtomicU64::new(0),
        connect_timeout: AtomicU64::new(0),
    });
    SOCKETS.lock().push(Arc::downgrade(&obj));
    // Readiness of the new socket.
    with_stack(|_| ());
    let handle = process::add_object(Object::Socket(obj))?;
    if peer != 0 {
        put_user(peer, &to_sa(remote))?;
    }
    Ok(handle)
}

pub fn sys_connect(h: u64, addr: u64) -> Result<u64, Errno> {
    let s = socket_of(h)?;
    let remote = to_ep(get_user::<SockAddr>(addr)?);
    match s.kind {
        abi::SOCK_DGRAM => {
            let id = ensure_udp(&s, None)?;
            stack_call(|st| st.udp_connect(id, remote)).map(|_| 0)
        }
        abi::SOCK_STREAM => {
            let id = match s.id() {
                Some(id) => {
                    // A connect already in progress (non-blocking retry).
                    if s.state.lock().listening {
                        return Err(Errno::InvalidArgument);
                    }
                    if s.state.lock().bound.is_some() {
                        stack_call(|st| st.tcp_connect_bound(id, remote))?;
                        s.state.lock().bound = None;
                    } else if stack_call(|st| st.tcp_connected(id))? {
                        return Err(Errno::AlreadyConnected);
                    }
                    id
                }
                None => {
                    let local = s.state.lock().bound;
                    let id = stack_call(|st| st.tcp_connect(local, remote))?;
                    let mut g = s.state.lock();
                    g.id = Some(id);
                    // The stack socket now owns the local port; stop
                    // reporting the bind reservation and never reuse it.
                    g.bound = None;
                    drop(g);
                    with_stack(|_| ());
                    id
                }
            };
            let timeout = s.connect_timeout.load(Ordering::Relaxed);
            let r = blocking(&s, WRITABLE, timeout, |st| {
                let (state, err) = st.tcp_state(id)?;
                if let Some(e) = err {
                    return Err(e);
                }
                match state {
                    osyx_net::tcp::State::SynSent | osyx_net::tcp::State::SynReceived => Err(NetError::WouldBlock),
                    osyx_net::tcp::State::Closed => Err(NetError::NotConnected),
                    _ => Ok(0),
                }
            });
            if let Err(Errno::TimedOut) = r {
                // Our own connect timeout: give the connection up.
                let _ = stack_call(|st| {
                    st.close(id, true);
                    Ok(())
                });
                s.state.lock().id = None;
            }
            r
        }
        _ => Err(Errno::NotSupported),
    }
}

const MAX_IO: usize = 256 * 1024;

/// One receive attempt: (bytes copied, sender).
type RecvOp<'a> = dyn FnMut(&mut Stack) -> Result<(usize, Option<SockAddr>), NetError> + 'a;

pub fn sys_send(h: u64, buf: u64, len: u64, to: u64, flags: u64) -> Result<u64, Errno> {
    let s = socket_of(h)?;
    let len = (len as usize).min(match s.kind {
        abi::SOCK_STREAM => MAX_IO,
        _ => osyx_net::stack::MAX_UDP_PAYLOAD + 1,
    });
    let mut data = alloc::vec![0u8; len];
    copy_from_user(&mut data, buf)?;
    let dest = if to != 0 { Some(get_user::<SockAddr>(to)?) } else { None };
    let nonblock = flags & abi::MSG_DONTWAIT != 0;
    match s.kind {
        abi::SOCK_DGRAM => {
            let id = ensure_udp(&s, None)?;
            stack_call(|st| st.udp_send_to(id, dest.map(to_ep), &data)).map(|n| n as u64)
        }
        abi::SOCK_PING => {
            let d = dest.ok_or(Errno::InvalidArgument)?;
            let id = s.id().ok_or(Errno::BadHandle)?;
            stack_call(|st| st.icmp_echo(id, Ipv4Addr(d.addr), d.port, &data)).map(|_| len as u64)
        }
        abi::SOCK_STREAM => {
            let id = s.id().ok_or(Errno::NotConnected)?;
            if s.state.lock().listening {
                return Err(Errno::NotConnected);
            }
            // Blocking sends deliver everything (or fail after a partial write).
            let mut done = 0;
            while done < data.len() {
                let r = if nonblock || done > 0 && s.nonblock.load(Ordering::Relaxed) {
                    stack_call(|st| st.tcp_send(id, &data[done..]))
                } else {
                    blocking(&s, WRITABLE, s.send_timeout.load(Ordering::Relaxed), |st| st.tcp_send(id, &data[done..]))
                };
                match r {
                    Ok(n) => done += n,
                    Err(e) if done == 0 => return Err(e),
                    Err(_) => break,
                }
                if nonblock {
                    break;
                }
            }
            Ok(done as u64)
        }
        _ => Err(Errno::NotSupported),
    }
}

pub fn sys_recv(h: u64, buf: u64, len: u64, from: u64, flags: u64) -> Result<u64, Errno> {
    let s = socket_of(h)?;
    let len = (len as usize).min(MAX_IO);
    if !user_range_ok(buf, len as u64) || (from != 0 && !user_range_ok(from, 8)) {
        return Err(Errno::Fault);
    }
    let timeout = s.recv_timeout.load(Ordering::Relaxed);
    let nonblock = flags & abi::MSG_DONTWAIT != 0;
    let peek = flags & abi::MSG_PEEK != 0;
    let mut k = alloc::vec![0u8; len];
    let run = |op: &mut RecvOp| {
        if nonblock {
            stack_call(op)
        } else {
            blocking(&s, READABLE, timeout, op)
        }
    };
    let (n, addr) = match s.kind {
        abi::SOCK_DGRAM => {
            let id = ensure_udp(&s, None)?;
            run(&mut |st| {
                let r = if peek { st.udp_peek_from(id, &mut k) } else { st.udp_recv_from(id, &mut k) };
                r.map(|(f, n, _)| (n, Some(to_sa(f))))
            })?
        }
        abi::SOCK_PING => {
            if peek {
                return Err(Errno::NotSupported);
            }
            let id = s.id().ok_or(Errno::BadHandle)?;
            run(&mut |st| match st.icmp_recv(id)? {
                IcmpEvent::Reply { from, seq, ttl, data } => {
                    let n = data.len().min(k.len());
                    k[..n].copy_from_slice(&data[..n]);
                    Ok((n, Some(SockAddr { addr: from.0, port: seq, ttl, reserved: 0 })))
                }
                IcmpEvent::Error { error, .. } => Err(error),
            })?
        }
        abi::SOCK_STREAM => {
            let id = s.id().ok_or(Errno::NotConnected)?;
            run(&mut |st| {
                let r = if peek { st.tcp_peek(id, &mut k) } else { st.tcp_recv(id, &mut k) };
                r.map(|n| (n, None))
            })?
        }
        _ => return Err(Errno::NotSupported),
    };
    copy_to_user(buf, &k[..n])?;
    if from != 0 {
        if let Some(a) = addr {
            put_user(from, &a)?;
        }
    }
    Ok(n as u64)
}

pub fn sys_ctl(h: u64, op: u64, arg: u64) -> Result<u64, Errno> {
    let s = socket_of(h)?;
    match op {
        abi::ctl::NONBLOCK => s.nonblock.store(arg != 0, Ordering::Relaxed),
        abi::ctl::RECV_TIMEOUT => s.recv_timeout.store(arg, Ordering::Relaxed),
        abi::ctl::SEND_TIMEOUT => s.send_timeout.store(arg, Ordering::Relaxed),
        abi::ctl::CONNECT_TIMEOUT => s.connect_timeout.store(arg, Ordering::Relaxed),
        abi::ctl::RESET_ON_CLOSE => s.reset_on_close.store(arg != 0, Ordering::Relaxed),
        abi::ctl::BROADCAST => {
            s.broadcast.store(arg != 0, Ordering::Relaxed);
            if let (abi::SOCK_DGRAM, Some(id)) = (s.kind, s.id()) {
                stack_call(|st| st.udp_set_broadcast(id, arg != 0))?;
            }
        }
        abi::ctl::SHUTDOWN_WRITE => {
            let id = s.id().filter(|_| s.kind == abi::SOCK_STREAM).ok_or(Errno::NotConnected)?;
            stack_call(|st| st.tcp_shutdown(id))?;
        }
        abi::ctl::LOCAL_ADDR | abi::ctl::PEER_ADDR => {
            let id = s.id();
            let bound = s.state.lock().bound;
            let peer = op == abi::ctl::PEER_ADDR;
            let ep = match (s.kind, id) {
                (abi::SOCK_STREAM, Some(id)) if s.state.lock().listening => {
                    if peer {
                        return Err(Errno::NotConnected);
                    }
                    stack_call(|st| st.listener_local(id))?
                }
                (abi::SOCK_STREAM, Some(id)) => {
                    if let Some(local) = bound {
                        if peer { return Err(Errno::NotConnected); }
                        local
                    } else {
                        let (l, r) = stack_call(|st| st.tcp_endpoints(id))?;
                        if peer { r } else { l }
                    }
                }
                (abi::SOCK_DGRAM, Some(id)) if !peer => stack_call(|st| st.udp_local(id))?,
                (_, _) if !peer => bound.unwrap_or_default(),
                _ => return Err(Errno::NotConnected),
            };
            put_user(arg, &to_sa(ep))?;
        }
        abi::ctl::STATE => {
            let id = s.id().filter(|_| s.kind == abi::SOCK_STREAM).ok_or(Errno::NotConnected)?;
            if s.state.lock().listening {
                return Ok(1);
            }
            let (st, _) = stack_call(|st| st.tcp_state(id))?;
            return Ok(tcp_state_index(st));
        }
        abi::ctl::ERROR => {
            if s.kind != abi::SOCK_STREAM {
                return Ok(0);
            }
            let Some(id) = s.id() else { return Ok(0) };
            let err = stack_call(|st| st.tcp_take_error(id)).ok().flatten();
            return Ok(err.map_or(0, |e| errno(e) as u64));
        }
        abi::ctl::AVAILABLE => {
            let id = s.id().ok_or(Errno::NotConnected)?;
            return Ok(stack_call(|st| st.available(id))? as u64);
        }
        _ => return Err(Errno::InvalidArgument),
    }
    Ok(0)
}

fn tcp_state_index(s: osyx_net::tcp::State) -> u64 {
    abi::TCP_STATE_NAMES.iter().position(|n| *n == s.name()).unwrap_or(0) as u64
}

pub fn sys_resolve(name: u64, len: u64, out: u64, max: u64) -> Result<u64, Errno> {
    if len == 0 || len > 255 {
        return Err(Errno::InvalidArgument);
    }
    let mut b = alloc::vec![0u8; len as usize];
    copy_from_user(&mut b, name)?;
    let name = String::from_utf8(b).map_err(|_| Errno::InvalidArgument)?;
    let max = (max as usize).min(abi::MAX_RESOLVE);
    if !user_range_ok(out, max as u64 * 4) {
        return Err(Errno::Fault);
    }
    let r = with_stack(|s| s.resolve(&name)).ok_or(Errno::NotSupported)?;
    let addrs = match r {
        Resolve::Done(r) => r.map_err(errno)?,
        Resolve::Pending(q) => {
            let deadline = deadline_after_ns(RESOLVE_TIMEOUT_NS);
            loop {
                if let Some(r) = with_stack(|s| s.resolve_result(q)).flatten() {
                    break r.map_err(errno)?;
                }
                let seen = GENERATION.load(Ordering::Acquire);
                if let Err(e) = block_on(&[&CHANGED], deadline, || (GENERATION.load(Ordering::Acquire) != seen).then_some(())) {
                    with_stack(|s| s.resolve_cancel(q));
                    return Err(e);
                }
            }
        }
    };
    let n = addrs.len().min(max);
    let flat: Vec<u8> = addrs[..n].iter().flat_map(|a| a.0).collect();
    copy_to_user(out, &flat)?;
    Ok(n as u64)
}

fn put_records<T: Copy>(buf: u64, len: u64, items: &[T]) -> Result<u64, Errno> {
    let size = core::mem::size_of::<T>();
    let n = (len as usize / size).min(items.len());
    // SAFETY: padding-free repr(C) records.
    let bytes = unsafe { core::slice::from_raw_parts(items.as_ptr() as *const u8, n * size) };
    copy_to_user(buf, bytes)?;
    Ok((n * size) as u64)
}

pub fn sys_query(kind: u64, buf: u64, len: u64) -> Result<u64, Errno> {
    let interrupts = virtio_net::INTERRUPTS.load(Ordering::Relaxed) + e1000::INTERRUPTS.load(Ordering::Relaxed) + rtl8168::INTERRUPTS.load(Ordering::Relaxed);
    let irq_devs: Vec<usize> = DEVICES.lock().iter().filter(|(_, d)| d.has_interrupts()).map(|(i, _)| *i).collect();
    let wireless_devs: Vec<usize> = DEVICES.lock().iter().filter(|(_, d)| d.is_wireless()).map(|(i, _)| *i).collect();
    let r = with_stack(|s| -> Result<u64, Errno> {
        let now = s.now();
        match kind {
            abi::query::IFACES => {
                let dns = s.dns_servers().first().copied().unwrap_or_default();
                let list: Vec<abi::NetIface> = s
                    .interfaces()
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        let mut r = abi::NetIface { index: i as u8, mtu: f.mtu as u32, mac: f.mac.0, ..Default::default() };
                        osyx_abi::ipc::fill_field(&mut r.name, &f.name);
                        r.flags = abi::IFF_UP
                            | if f.link_up { abi::IFF_LINK } else { 0 }
                            | if f.kind == osyx_net::stack::IfaceKind::Loopback { abi::IFF_LOOPBACK } else { 0 }
                            | if irq_devs.contains(&i) { abi::IFF_INTERRUPTS } else { 0 }
                            | if wireless_devs.contains(&i) { abi::IFF_WIRELESS } else { 0 };
                        if let Some((a, p)) = f.addr {
                            r.addr = a.0;
                            r.prefix = p;
                        }
                        r.gateway = s.routes().iter().find(|rt| rt.iface == i && rt.prefix == 0).and_then(|rt| rt.gateway).unwrap_or_default().0;
                        if i > 0 {
                            r.dns = dns.0;
                        }
                        r.method = match f.method {
                            osyx_net::stack::ConfigMethod::None => abi::CONFIG_NONE,
                            osyx_net::stack::ConfigMethod::Static => abi::CONFIG_STATIC,
                            osyx_net::stack::ConfigMethod::Dhcp => abi::CONFIG_DHCP,
                        };
                        if let Some((phase, lease)) = s.dhcp_state(i) {
                            r.dhcp_phase = 1 + phase as u8;
                            r.lease_left = lease.map_or(0, |l| l.expires().saturating_sub(now) / 1000);
                        }
                        r.interrupts = if i > 0 { interrupts as u32 } else { 0 };
                        let st = f.stats;
                        r.rx_packets = st.rx_packets;
                        r.rx_bytes = st.rx_bytes;
                        r.tx_packets = st.tx_packets;
                        r.tx_bytes = st.tx_bytes;
                        r.rx_dropped = st.rx_dropped;
                        r.rx_errors = st.rx_errors;
                        r.tx_dropped = st.tx_dropped;
                        r
                    })
                    .collect();
                put_records(buf, len, &list)
            }
            abi::query::ROUTES => {
                let list: Vec<abi::NetRoute> = s
                    .routes()
                    .iter()
                    .map(|r| abi::NetRoute {
                        dest: r.dest.0,
                        gateway: r.gateway.unwrap_or_default().0,
                        prefix: r.prefix,
                        iface: r.iface as u8,
                        origin: r.origin as u8,
                        reserved: 0,
                    })
                    .collect();
                put_records(buf, len, &list)
            }
            abi::query::ARP => {
                let mut list = Vec::new();
                for i in 0..s.interfaces().len() {
                    for (a, mac, left) in s.arp_entries(i) {
                        list.push(abi::NetArp {
                            addr: a.0,
                            mac: mac.unwrap_or_default().0,
                            iface: i as u8,
                            resolved: mac.is_some() as u8,
                            expires_ms: left.min(u32::MAX as u64) as u32,
                        });
                    }
                }
                put_records(buf, len, &list)
            }
            abi::query::SOCKETS => {
                let list: Vec<abi::NetSocket> = s
                    .sockets()
                    .iter()
                    .map(|i| {
                        let mut r = abi::NetSocket {
                            local: to_sa(i.local),
                            remote: i.remote.map(to_sa).unwrap_or_default(),
                            rx_queue: i.rx_queue as u32,
                            tx_queue: i.tx_queue as u32,
                            internal: i.internal as u32,
                            ..Default::default()
                        };
                        osyx_abi::ipc::fill_field(&mut r.kind, i.kind);
                        osyx_abi::ipc::fill_field(&mut r.state, i.state);
                        r
                    })
                    .collect();
                put_records(buf, len, &list)
            }
            abi::query::STATS => {
                let t = s.stats;
                let c = [
                    t.ip_in,
                    t.ip_out,
                    t.ip_bad,
                    t.ip_fragments_in,
                    t.ip_reassembled,
                    t.ip_not_for_us,
                    t.icmp_in,
                    t.icmp_out,
                    t.icmp_echo_answered,
                    t.udp_in,
                    t.udp_out,
                    t.udp_bad,
                    t.udp_no_port,
                    t.tcp_in,
                    t.tcp_out,
                    t.tcp_bad,
                    t.tcp_resets_sent,
                    t.tcp_retransmits,
                    t.arp_in,
                    t.arp_out,
                    t.arp_bad,
                    t.frames_bad,
                    t.dns_queries,
                    t.dns_rejected,
                    s.dns_cache.hits,
                    s.dns_cache.misses,
                    interrupts,
                    s.socket_count() as u64,
                ];
                put_records(buf, len, &[abi::NetStats { counters: c }])
            }
            abi::query::DNS_CACHE => {
                let list: Vec<abi::NetDnsEntry> = s
                    .dns_cache
                    .entries(now)
                    .iter()
                    .map(|(name, addrs, left)| {
                        let mut e = abi::NetDnsEntry {
                            addr: addrs.first().copied().unwrap_or_default().0,
                            count: addrs.len() as u32,
                            ttl_left: *left as u32,
                            ..Default::default()
                        };
                        osyx_abi::ipc::fill_field(&mut e.name, name);
                        e
                    })
                    .collect();
                put_records(buf, len, &list)
            }
            abi::query::DNS_SERVERS => {
                let list: Vec<[u8; 4]> = s.dns_servers().iter().map(|a| a.0).collect();
                put_records(buf, len, &list)
            }
            _ => Err(Errno::InvalidArgument),
        }
    });
    r.ok_or(Errno::NotSupported)?
}

pub fn sys_config(args: u64) -> Result<u64, Errno> {
    let (cred, _) = process::current_identity();
    if !cred.is_root() {
        return Err(Errno::PermissionDenied);
    }
    let c: abi::NetConfig = get_user(args)?;
    let iface = c.iface as usize;
    let r = with_stack(|s| -> Result<(), NetError> {
        if iface == 0 || iface >= s.interfaces().len() {
            return Err(NetError::InvalidArgument);
        }
        match c.method as u8 {
            abi::CONFIG_DHCP => s.enable_dhcp(iface)?,
            abi::CONFIG_STATIC => {
                let gw = Ipv4Addr(c.gateway);
                s.configure_static(iface, Ipv4Addr(c.addr), c.prefix, (!gw.is_unspecified()).then_some(gw))?
            }
            abi::CONFIG_DOWN => s.deconfigure(iface)?,
            _ => return Err(NetError::InvalidArgument),
        }
        if c.dns_count > 0 {
            let n = (c.dns_count as usize).min(2);
            let servers: Vec<Ipv4Addr> = c.dns[..n].iter().map(|a| Ipv4Addr(*a)).collect();
            s.set_dns_servers(&servers);
        }
        Ok(())
    });
    r.ok_or(Errno::NotSupported)?.map_err(errno)?;
    wake();
    Ok(0)
}

/// Summary for the boot log once init finished.
pub fn log_summary() {
    if !enabled() {
        return;
    }
    let lines = with_stack(|s| {
        let mut v = Vec::new();
        for i in s.interfaces() {
            let st = i.stats;
            v.push(alloc::format!(
                "{}: {} rx {} packets / {} bytes, tx {} packets / {} bytes",
                i.name,
                i.addr.map(|(a, p)| alloc::format!("{a}/{p}")).unwrap_or_else(|| "unconfigured".into()),
                st.rx_packets,
                st.rx_bytes,
                st.tx_packets,
                st.tx_bytes
            ));
        }
        v.push(alloc::format!(
            "tcp in {} out {} retransmits {} resets {}, udp in {} out {}, icmp in {} out {}, {} sockets",
            s.stats.tcp_in,
            s.stats.tcp_out,
            s.stats.tcp_retransmits,
            s.stats.tcp_resets_sent,
            s.stats.udp_in,
            s.stats.udp_out,
            s.stats.icmp_in,
            s.stats.icmp_out,
            s.socket_count()
        ));
        v
    })
    .unwrap_or_default();
    for l in lines {
        kprintln!("net: {}", l);
    }
    for (_, d) in DEVICES.lock().iter() {
        let c = d.counters();
        kprintln!(
            "net: {}: {} frames in, {} out, {} rx errors, {} tx ring full, {} resets, {} interrupts",
            d.description(),
            c.rx_frames,
            c.tx_frames,
            c.rx_errors,
            c.tx_full,
            c.resets,
            virtio_net::INTERRUPTS.load(Ordering::Relaxed) + e1000::INTERRUPTS.load(Ordering::Relaxed) + rtl8168::INTERRUPTS.load(Ordering::Relaxed)
        );
    }
}
