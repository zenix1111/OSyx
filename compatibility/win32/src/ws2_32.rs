//! ws2_32.dll: Winsock 2 over the OSyx network stack. A SOCKET is an entry
//! in this table that owns an OSyx kernel socket (TCP or UDP, IPv4);
//! blocking calls block in the kernel, names resolve through the kernel's
//! DNS resolver, and errors are the documented WSA codes (also returned by
//! GetLastError, as on Windows).

#![allow(non_snake_case)]

use crate::teb;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use os_std::sync::Mutex;
use os_sys::net::{self, SockAddr};
use osyx_abi::Errno;

const INVALID_SOCKET: u64 = u64::MAX;
const SOCKET_ERROR: i32 = -1;
const AF_INET: u16 = 2;
const AF_INET6: i32 = 23;
const AI_PASSIVE: i32 = 1;
const AI_NUMERICHOST: i32 = 4;
const AI_NUMERICSERV: i32 = 8;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOL_SOCKET: i32 = 0xFFFF;
const SO_REUSEADDR: i32 = 0x4;
const SO_KEEPALIVE: i32 = 0x8;
const SO_BROADCAST: i32 = 0x20;
const SO_SNDTIMEO: i32 = 0x1005;
const SO_RCVTIMEO: i32 = 0x1006;
const SO_ERROR: i32 = 0x1007;
const SO_TYPE: i32 = 0x1008;
const IPPROTO_TCP: i32 = 6;
const TCP_NODELAY: i32 = 1;
const FIONBIO: u32 = 0x8004_667E;
const MSG_PEEK: i32 = 2;

const WSAEINTR: u32 = 10004;
const WSAEFAULT: u32 = 10014;
const WSAEINVAL: u32 = 10022;
const WSAEMFILE: u32 = 10024;
const WSAEWOULDBLOCK: u32 = 10035;
const WSAENOTSOCK: u32 = 10038;
const WSAEMSGSIZE: u32 = 10040;
const WSAENOPROTOOPT: u32 = 10042;
const WSAEPROTONOSUPPORT: u32 = 10043;
const WSAEOPNOTSUPP: u32 = 10045;
const WSAEAFNOSUPPORT: u32 = 10047;
const WSAEADDRINUSE: u32 = 10048;
const WSAEADDRNOTAVAIL: u32 = 10049;
const WSAENETUNREACH: u32 = 10051;
const WSAECONNRESET: u32 = 10054;
const WSAENOBUFS: u32 = 10055;
const WSAEISCONN: u32 = 10056;
const WSAENOTCONN: u32 = 10057;
const WSAETIMEDOUT: u32 = 10060;
const WSAECONNREFUSED: u32 = 10061;
const WSAEHOSTUNREACH: u32 = 10065;
const WSANOTINITIALISED: u32 = 10093;
const WSAHOST_NOT_FOUND: u32 = 11001;
const WSATRY_AGAIN: u32 = 11002;
const WSAVERNOTSUPPORTED: u32 = 10092;
const WSANO_DATA: u32 = 11004;
const WSAEINVALIDPROVIDER: u32 = 10105;
const ERROR_INVALID_PARAMETER: u32 = 87;

fn wsa(e: Errno) -> u32 {
    match e {
        Errno::WouldBlock => WSAEWOULDBLOCK,
        Errno::TimedOut => WSAETIMEDOUT,
        Errno::AddrInUse => WSAEADDRINUSE,
        Errno::AddrNotAvailable => WSAEADDRNOTAVAIL,
        Errno::NetUnreachable => WSAENETUNREACH,
        Errno::HostUnreachable => WSAEHOSTUNREACH,
        Errno::ConnRefused => WSAECONNREFUSED,
        Errno::ConnReset | Errno::BrokenPipe => WSAECONNRESET,
        Errno::NotConnected => WSAENOTCONN,
        Errno::AlreadyConnected => WSAEISCONN,
        Errno::MessageTooLong => WSAEMSGSIZE,
        Errno::NameNotFound => WSAHOST_NOT_FOUND,
        Errno::DnsFailure => WSATRY_AGAIN,
        Errno::Interrupted => WSAEINTR,
        Errno::Fault => WSAEFAULT,
        Errno::NoMemory => WSAENOBUFS,
        Errno::TooManyHandles => WSAEMFILE,
        Errno::NotSupported | Errno::Unsupported => WSAEOPNOTSUPP,
        _ => WSAEINVAL,
    }
}

#[track_caller]
fn err<T>(code: u32, v: T) -> T {
    static ERRORS: AtomicU32 = AtomicU32::new(0);
    if code != WSAEWOULDBLOCK && crate::VERBOSE.load(Ordering::Relaxed) && ERRORS.fetch_add(1, Ordering::Relaxed) < 128 {
        os_std::eprintln!("winrun: Winsock error {code} in thread {} at {}", os_sys::gettid(), core::panic::Location::caller());
    }
    teb::set_last_error(code);
    v
}

#[derive(Clone, Copy)]
struct Sock {
    fd: u64,
    stream: bool,
    nonblocking: bool,
}

static SOCKETS: Mutex<BTreeMap<u64, Sock>> = Mutex::new(BTreeMap::new());
static NEXT: Mutex<u64> = Mutex::new(0x1000);
static STARTED: AtomicU32 = AtomicU32::new(0);

fn trace_io(args: core::fmt::Arguments<'_>) {
    static LINES: AtomicU32 = AtomicU32::new(0);
    if crate::kernel32::TRACE.load(Ordering::Relaxed) && LINES.fetch_add(1, Ordering::Relaxed) < 96 {
        os_std::eprintln!("winrun: socket I/O thread {}: {args}", os_sys::gettid());
    }
}

fn started() -> bool {
    STARTED.load(Ordering::SeqCst) > 0
}

/// The kernel socket of SOCKET `s`.
fn fd(s: u64) -> Result<(u64, bool), u32> {
    socket_state(s).map(|s| (s.fd, s.stream))
}

fn socket_state(s: u64) -> Result<Sock, u32> {
    if !started() {
        return Err(WSANOTINITIALISED);
    }
    SOCKETS.lock().unwrap().get(&s).copied().ok_or(WSAENOTSOCK)
}

/// sockaddr_in (family, port big-endian, address, zero[8]) → SockAddr.
fn read_addr(p: *const u8, len: i32) -> Result<SockAddr, u32> {
    if p.is_null() || len < 16 {
        return Err(WSAEFAULT);
    }
    // SAFETY: the caller's sockaddr of at least 16 bytes.
    let b = unsafe { core::slice::from_raw_parts(p, 16) };
    if u16::from_le_bytes([b[0], b[1]]) != AF_INET {
        return Err(WSAEAFNOSUPPORT);
    }
    Ok(SockAddr::new([b[4], b[5], b[6], b[7]], u16::from_be_bytes([b[2], b[3]])))
}

fn write_addr(a: &SockAddr, p: *mut u8, len: *mut i32) {
    if p.is_null() {
        return;
    }
    // SAFETY: the caller's buffer; `len` (when given) says it holds 16 bytes.
    unsafe {
        if !len.is_null() {
            if *len < 16 {
                return;
            }
            *len = 16;
        }
        let mut b = [0u8; 16];
        b[..2].copy_from_slice(&AF_INET.to_le_bytes());
        b[2..4].copy_from_slice(&a.port.to_be_bytes());
        b[4..8].copy_from_slice(&a.addr);
        core::ptr::copy_nonoverlapping(b.as_ptr(), p, 16);
    }
}

/// Winsock 1.0 to 2.2 are accepted (wsock32 users ask for 1.1); a newer
/// request negotiates 2.2, as on Windows.
extern "win64" fn WSAStartup(version: u16, data: *mut u8) -> i32 {
    let (major, minor) = (version & 0xFF, version >> 8);
    if major == 0 {
        return WSAVERNOTSUPPORTED as i32;
    }
    if !data.is_null() {
        // SAFETY: the caller's WSADATA (408 bytes on x64).
        unsafe {
            core::ptr::write_bytes(data, 0, 408);
            teb::put(data as u64, 0, if major == 1 || (major == 2 && minor <= 2) { version } else { 0x0202u16 });
            teb::put(data as u64, 2, 0x0202u16);
            let desc = b"OSyx Winsock 2.2 (native TCP/IP stack)";
            core::ptr::copy_nonoverlapping(desc.as_ptr(), data.add(16), desc.len());
            let status = b"Running";
            core::ptr::copy_nonoverlapping(status.as_ptr(), data.add(273), status.len());
        }
    }
    STARTED.fetch_add(1, Ordering::SeqCst);
    0
}

extern "win64" fn WSACleanup() -> i32 {
    if STARTED.load(Ordering::SeqCst) == 0 {
        return err(WSANOTINITIALISED, SOCKET_ERROR);
    }
    if STARTED.fetch_sub(1, Ordering::SeqCst) == 1 {
        let all: Vec<Sock> = core::mem::take(&mut *SOCKETS.lock().unwrap()).into_values().collect();
        for s in all {
            let _ = os_sys::close(s.fd);
        }
    }
    0
}

extern "win64" fn WSAGetLastError() -> i32 {
    teb::last_error() as i32
}

extern "win64" fn WSASetLastError(e: i32) {
    teb::set_last_error(e as u32)
}

extern "win64" fn socket(af: i32, kind: i32, proto: i32) -> u64 {
    if crate::VERBOSE.load(Ordering::Relaxed) {
        os_std::eprintln!("winrun: socket family {af}, kind {kind}, protocol {proto}, started {}", started());
    }
    if !started() {
        return err(WSANOTINITIALISED, INVALID_SOCKET);
    }
    if af != AF_INET as i32 {
        return err(WSAEAFNOSUPPORT, INVALID_SOCKET);
    }
    let (k, stream) = match (kind, proto) {
        (SOCK_STREAM, 0 | 6) => (net::SOCK_STREAM, true),
        (SOCK_DGRAM, 0 | 17) => (net::SOCK_DGRAM, false),
        _ => return err(WSAEPROTONOSUPPORT, INVALID_SOCKET),
    };
    match os_sys::socket(k) {
        Ok(fd) => {
            let mut n = NEXT.lock().unwrap();
            let s = *n;
            *n += 4;
            SOCKETS.lock().unwrap().insert(s, Sock { fd, stream, nonblocking: false });
            s
        }
        Err(e) => err(wsa(e), INVALID_SOCKET),
    }
}

extern "win64" fn closesocket(s: u64) -> i32 {
    if !started() {
        return err(WSANOTINITIALISED, SOCKET_ERROR);
    }
    match SOCKETS.lock().unwrap().remove(&s) {
        Some(k) => {
            let _ = os_sys::close(k.fd);
            0
        }
        None => err(WSAENOTSOCK, SOCKET_ERROR),
    }
}

fn result(r: Result<(), u32>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => err(e, SOCKET_ERROR),
    }
}

extern "win64" fn bind(s: u64, addr: *const u8, len: i32) -> i32 {
    result((|| {
        let (fd, _) = fd(s)?;
        let a = read_addr(addr, len)?;
        os_sys::sock_bind(fd, &a).map_err(wsa)
    })())
}

extern "win64" fn connect(s: u64, addr: *const u8, len: i32) -> i32 {
    result((|| {
        let (fd, _) = fd(s)?;
        let a = read_addr(addr, len)?;
        os_sys::sock_connect(fd, &a).map_err(wsa)
    })())
}

extern "win64" fn listen(s: u64, backlog: i32) -> i32 {
    result((|| {
        let (fd, stream) = fd(s)?;
        if !stream {
            return Err(WSAEOPNOTSUPP);
        }
        os_sys::sock_listen(fd, backlog.clamp(1, 128) as u32).map_err(wsa)
    })())
}

extern "win64" fn accept(s: u64, addr: *mut u8, len: *mut i32) -> u64 {
    let r = (|| {
        let listener = socket_state(s)?;
        if !listener.stream {
            return Err(WSAEOPNOTSUPP);
        }
        let (nfd, peer) = os_sys::sock_accept(listener.fd).map_err(wsa)?;
        // Winsock accept inherits the listener's blocking mode. OSyx's
        // native accept creates a blocking endpoint, so apply it here.
        if listener.nonblocking {
            if let Err(e) = os_sys::sock_ctl(nfd, net::ctl::NONBLOCK, 1) {
                let _ = os_sys::close(nfd);
                return Err(wsa(e));
            }
        }
        write_addr(&peer, addr, len);
        let mut n = NEXT.lock().unwrap();
        let ns = *n;
        *n += 4;
        SOCKETS.lock().unwrap().insert(ns, Sock { fd: nfd, stream: true, nonblocking: listener.nonblocking });
        Ok(ns)
    })();
    r.unwrap_or_else(|e| err(e, INVALID_SOCKET))
}

fn flags(f: i32) -> Result<u64, u32> {
    if f & !MSG_PEEK != 0 {
        return Err(WSAEOPNOTSUPP);
    }
    Ok(if f & MSG_PEEK != 0 { net::MSG_PEEK } else { 0 })
}

extern "win64" fn send(s: u64, buf: *const u8, len: i32, f: i32) -> i32 {
    trace_io(format_args!("send({s:#x}, {len}) begin"));
    let r = (|| {
        let (fd, _) = fd(s)?;
        if f != 0 {
            return Err(WSAEOPNOTSUPP);
        }
        // SAFETY: the caller's buffer of `len` bytes.
        let data = unsafe { core::slice::from_raw_parts(buf, len.max(0) as usize) };
        os_sys::sock_send(fd, data, None, 0).map_err(wsa)
    })();
    trace_io(format_args!("send({s:#x}) -> {r:?}"));
    r.map_or_else(|e| err(e, SOCKET_ERROR), |n| n as i32)
}

extern "win64" fn sendto(s: u64, buf: *const u8, len: i32, f: i32, to: *const u8, tolen: i32) -> i32 {
    let r = (|| {
        let (fd, _) = fd(s)?;
        if f != 0 {
            return Err(WSAEOPNOTSUPP);
        }
        let a = if to.is_null() { None } else { Some(read_addr(to, tolen)?) };
        // SAFETY: the caller's buffer of `len` bytes.
        let data = unsafe { core::slice::from_raw_parts(buf, len.max(0) as usize) };
        os_sys::sock_send(fd, data, a.as_ref(), 0).map_err(wsa)
    })();
    r.map_or_else(|e| err(e, SOCKET_ERROR), |n| n as i32)
}

extern "win64" fn recv(s: u64, buf: *mut u8, len: i32, f: i32) -> i32 {
    recvfrom(s, buf, len, f, core::ptr::null_mut(), core::ptr::null_mut())
}

extern "win64" fn recvfrom(s: u64, buf: *mut u8, len: i32, f: i32, from: *mut u8, fromlen: *mut i32) -> i32 {
    trace_io(format_args!("recv({s:#x}, {len}) begin"));
    let r = (|| {
        let (fd, _) = fd(s)?;
        let fl = flags(f)?;
        // SAFETY: the caller's buffer of `len` bytes.
        let data = unsafe { core::slice::from_raw_parts_mut(buf, len.max(0) as usize) };
        let (n, peer) = os_sys::sock_recv(fd, data, fl).map_err(wsa)?;
        write_addr(&peer, from, fromlen);
        Ok(n)
    })();
    trace_io(format_args!("recv({s:#x}) -> {r:?}"));
    r.map_or_else(|e| err(e, SOCKET_ERROR), |n| n as i32)
}

extern "win64" fn shutdown(s: u64, how: i32) -> i32 {
    result((|| {
        let (fd, _) = fd(s)?;
        match how {
            0 => Ok(()), // SD_RECEIVE: nothing to tell the peer
            1 | 2 => os_sys::sock_ctl(fd, net::ctl::SHUTDOWN_WRITE, 0).map(|_| ()).map_err(wsa),
            _ => Err(WSAEINVAL),
        }
    })())
}

extern "win64" fn setsockopt(s: u64, level: i32, name: i32, val: *const u8, len: i32) -> i32 {
    if crate::VERBOSE.load(Ordering::Relaxed) {
        os_std::eprintln!("winrun: setsockopt {s:#x} level {level:#x}, option {name:#x}, len {len}");
    }
    result((|| {
        let (fd, _) = fd(s)?;
        let int = || -> Result<u32, u32> {
            if val.is_null() || len < 4 {
                return Err(WSAEFAULT);
            }
            // SAFETY: the caller's 4-byte option value.
            Ok(unsafe { core::ptr::read_unaligned(val as *const u32) })
        };
        match (level, name) {
            (SOL_SOCKET, SO_RCVTIMEO) => {
                os_sys::sock_ctl(fd, net::ctl::RECV_TIMEOUT, int()? as u64 * 1_000_000).map(|_| ()).map_err(wsa)
            }
            (SOL_SOCKET, SO_SNDTIMEO) => {
                os_sys::sock_ctl(fd, net::ctl::SEND_TIMEOUT, int()? as u64 * 1_000_000).map(|_| ()).map_err(wsa)
            }
            (SOL_SOCKET, SO_BROADCAST) => {
                os_sys::sock_ctl(fd, net::ctl::BROADCAST, (int()? != 0) as u64).map(|_| ()).map_err(wsa)
            }
            // OSyx lets a port be bound again once its old connection is
            // gone, and does not delay small segments: both are the default.
            (SOL_SOCKET, SO_REUSEADDR) | (IPPROTO_TCP, TCP_NODELAY) => int().map(|_| ()),
            _ => Err(WSAENOPROTOOPT),
        }
    })())
}

/// The options OSyx can report: the socket type, the pending connect error
/// (a failed non-blocking connect is otherwise only visible on the next
/// call) and the fixed behaviours setsockopt accepts.
extern "win64" fn getsockopt(s: u64, level: i32, name: i32, val: *mut u8, len: *mut i32) -> i32 {
    result((|| {
        let (fd, stream) = fd(s)?;
        let v: u32 = match (level, name) {
            (SOL_SOCKET, SO_TYPE) => {
                if stream {
                    SOCK_STREAM as u32
                } else {
                    SOCK_DGRAM as u32
                }
            }
            // A non-blocking connect reports its failure through SO_ERROR.
            (SOL_SOCKET, SO_ERROR) => {
                let code = os_sys::sock_ctl(fd, net::ctl::ERROR, 0).unwrap_or(0);
                Errno::from_raw(code).map_or(0, wsa)
            }
            (SOL_SOCKET, SO_REUSEADDR | SO_KEEPALIVE) => 0,
            (IPPROTO_TCP, TCP_NODELAY) if stream => 1,
            _ => return Err(WSAENOPROTOOPT),
        };
        // SAFETY: the caller's value buffer of `*len` bytes.
        unsafe {
            if val.is_null() || len.is_null() || *len < 4 {
                return Err(WSAEFAULT);
            }
            core::ptr::write_unaligned(val as *mut u32, v);
            *len = 4;
        }
        Ok(())
    })())
}

extern "win64" fn ioctlsocket(s: u64, cmd: u32, arg: *mut u32) -> i32 {
    result((|| {
        let (fd, _) = fd(s)?;
        if arg.is_null() {
            return Err(WSAEINVAL);
        }
        match cmd {
            FIONBIO => {
                // SAFETY: the caller's argument.
                let on = unsafe { *arg } != 0;
                os_sys::sock_ctl(fd, net::ctl::NONBLOCK, on as u64).map_err(wsa)?;
                SOCKETS.lock().unwrap().get_mut(&s).ok_or(WSAENOTSOCK)?.nonblocking = on;
            }
            FIONREAD => {
                let n = os_sys::sock_ctl(fd, net::ctl::AVAILABLE, 0).map_err(wsa)?;
                // SAFETY: the caller's 4-byte out argument.
                unsafe { core::ptr::write_unaligned(arg, n as u32) };
            }
            _ => return Err(WSAEINVAL),
        }
        Ok(())
    })())
}

extern "win64" fn getsockname(s: u64, addr: *mut u8, len: *mut i32) -> i32 {
    sock_name(s, net::ctl::LOCAL_ADDR, addr, len)
}

extern "win64" fn getpeername(s: u64, addr: *mut u8, len: *mut i32) -> i32 {
    sock_name(s, net::ctl::PEER_ADDR, addr, len)
}

fn sock_name(s: u64, op: u64, addr: *mut u8, len: *mut i32) -> i32 {
    result((|| {
        let (fd, _) = fd(s)?;
        if addr.is_null() || len.is_null() || unsafe { *len } < 16 {
            return Err(WSAEFAULT);
        }
        let mut a = SockAddr::default();
        os_sys::sock_ctl(fd, op, &mut a as *mut SockAddr as u64).map_err(wsa)?;
        write_addr(&a, addr, len);
        Ok(())
    })())
}

extern "win64" fn htons(v: u16) -> u16 {
    v.to_be()
}

extern "win64" fn ntohs(v: u16) -> u16 {
    u16::from_be(v)
}

extern "win64" fn htonl(v: u32) -> u32 {
    v.to_be()
}

extern "win64" fn ntohl(v: u32) -> u32 {
    u32::from_be(v)
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for o in out.iter_mut() {
        *o = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// The address in network byte order (as stored in memory), or INADDR_NONE.
extern "win64" fn inet_addr(s: *const u8) -> u32 {
    // SAFETY: a NUL-terminated string.
    match unsafe { crate::path::ansi_to_string(s) }.and_then(|s| parse_ipv4(&s)) {
        Some(a) => u32::from_le_bytes(a),
        None => u32::MAX,
    }
}

/// Per-thread result buffers (hostent, inet_ntoa), as Windows keeps them.
static BUFFERS: Mutex<BTreeMap<(u64, u8), u64>> = Mutex::new(BTreeMap::new());

fn thread_buffer(kind: u8, size: usize) -> u64 {
    let key = (os_sys::gettid(), kind);
    let mut b = BUFFERS.lock().unwrap();
    *b.entry(key).or_insert_with(|| crate::mem::arena_alloc(size, 16))
}

extern "win64" fn inet_ntoa(a: u32) -> u64 {
    let s = alloc::format!("{}\0", core::net::Ipv4Addr::from(a.to_le_bytes()));
    let p = thread_buffer(1, 16);
    // SAFETY: the 16-byte buffer holds "255.255.255.255\0".
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), p as *mut u8, s.len()) };
    p
}

fn resolve(name: &str) -> Result<Vec<[u8; 4]>, u32> {
    if let Some(a) = parse_ipv4(name) {
        return Ok(alloc::vec![a]);
    }
    let mut out = [[0u8; 4]; 8];
    let n = os_sys::resolve(name, &mut out).map_err(wsa)?;
    Ok(out[..n].to_vec())
}

/// hostent (x64): h_name, h_aliases, h_addrtype (i16), h_length (i16),
/// h_addr_list — in a per-thread buffer with up to 8 addresses.
extern "win64" fn gethostbyname(name: *const u8) -> u64 {
    if !started() {
        return err(WSANOTINITIALISED, 0);
    }
    // SAFETY: a NUL-terminated name.
    let Some(n) = (unsafe { crate::path::ansi_to_string(name) }) else { return err(WSAEFAULT, 0) };
    let addrs = match resolve(&n) {
        Ok(a) if !a.is_empty() => a,
        Ok(_) => return err(WSAHOST_NOT_FOUND, 0),
        Err(e) => return err(e, 0),
    };
    hostent(&n, &addrs)
}

/// Fills this thread's hostent buffer.
fn hostent(n: &str, addrs: &[[u8; 4]]) -> u64 {
    let buf = thread_buffer(0, 512);
    let name_bytes: Vec<u8> = n.bytes().take(255).chain(core::iter::once(0)).collect();
    // SAFETY: a 512-byte buffer: hostent (32) + 9 pointers (72) + 8
    // addresses (32) + aliases terminator (8) + the name (<= 256).
    unsafe {
        let list = buf + 32;
        let data = list + 72;
        let aliases = data + 32;
        let name_p = aliases + 8;
        for (i, a) in addrs.iter().take(8).enumerate() {
            core::ptr::copy_nonoverlapping(a.as_ptr(), (data + i as u64 * 4) as *mut u8, 4);
            teb::put(list, i * 8, data + i as u64 * 4);
        }
        teb::put(list, addrs.len().min(8) * 8, 0u64);
        teb::put(aliases, 0, 0u64);
        core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_p as *mut u8, name_bytes.len());
        teb::put(buf, 0, name_p);
        teb::put(buf, 8, aliases);
        teb::put(buf, 16, AF_INET as i16);
        teb::put(buf, 18, 4i16);
        teb::put(buf, 24, list);
    }
    buf
}

fn host_name() -> String {
    os_std::fs::read_to_string("/etc/hostname").map(|s| String::from(s.trim())).unwrap_or_else(|_| String::from("osyx"))
}

/// Loopback addresses name this machine, as on Windows. OSyx's resolver
/// has no reverse (PTR) lookup, so any other address is not found.
extern "win64" fn gethostbyaddr(addr: *const u8, len: i32, kind: i32) -> u64 {
    if !started() {
        return err(WSANOTINITIALISED, 0);
    }
    if kind != AF_INET as i32 {
        return err(WSAEAFNOSUPPORT, 0);
    }
    if addr.is_null() || len < 4 {
        return err(WSAEFAULT, 0);
    }
    let mut a = [0u8; 4];
    // SAFETY: the caller's 4-byte address.
    unsafe { core::ptr::copy_nonoverlapping(addr, a.as_mut_ptr(), 4) };
    if a[0] != 127 {
        return err(WSAHOST_NOT_FOUND, 0);
    }
    hostent(&host_name(), &[a])
}

/// The protocols of Windows' default etc\protocol that OSyx implements.
const PROTOCOLS: [(&str, i16); 4] = [("ip", 0), ("icmp", 1), ("tcp", 6), ("udp", 17)];

/// protoent (x64): p_name, p_aliases, p_proto (i16), in a per-thread buffer.
fn protoent(name: &str, proto: i16) -> u64 {
    let buf = thread_buffer(2, 64);
    // SAFETY: a 64-byte buffer: protoent (24) + aliases terminator (8) +
    // the NUL-terminated name (<= 32).
    unsafe {
        let aliases = buf + 24;
        let name_p = aliases + 8;
        teb::put(aliases, 0, 0u64);
        core::ptr::write_bytes(name_p as *mut u8, 0, 32);
        core::ptr::copy_nonoverlapping(name.as_ptr(), name_p as *mut u8, name.len());
        teb::put(buf, 0, name_p);
        teb::put(buf, 8, aliases);
        teb::put(buf, 16, proto);
    }
    buf
}

extern "win64" fn getprotobyname(name: *const u8) -> u64 {
    if !started() {
        return err(WSANOTINITIALISED, 0);
    }
    // SAFETY: a NUL-terminated name.
    let Some(n) = (unsafe { crate::path::ansi_to_string(name) }) else { return err(WSAEFAULT, 0) };
    match PROTOCOLS.iter().find(|(p, _)| p.eq_ignore_ascii_case(&n)) {
        Some(&(p, v)) => protoent(p, v),
        None => err(WSANO_DATA, 0),
    }
}

extern "win64" fn getprotobynumber(number: i32) -> u64 {
    if !started() {
        return err(WSANOTINITIALISED, 0);
    }
    match PROTOCOLS.iter().find(|(_, v)| *v as i32 == number) {
        Some(&(p, v)) => protoent(p, v),
        None => err(WSANO_DATA, 0),
    }
}

extern "win64" fn gethostname(buf: *mut u8, len: i32) -> i32 {
    let name = host_name();
    if buf.is_null() || (len as usize) < name.len() + 1 {
        return err(WSAEFAULT, SOCKET_ERROR);
    }
    // SAFETY: the caller's buffer holds the name and its NUL.
    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), buf, name.len());
        *buf.add(name.len()) = 0;
    }
    0
}

/// ADDRINFOA (48 bytes) + sockaddr_in per address, one heap block each;
/// freed by freeaddrinfo.
extern "win64" fn getaddrinfo(node: *const u8, service: *const u8, hints: *const u8, res: *mut u64) -> i32 {
    if !started() {
        return WSANOTINITIALISED as i32;
    }
    // SAFETY: NULL or NUL-terminated strings.
    let (n, svc) = unsafe { (crate::path::ansi_to_string(node), crate::path::ansi_to_string(service)) };
    let (mut flags, mut socktype, mut proto) = (0i32, 0i32, 0i32);
    if !hints.is_null() {
        // SAFETY: the caller's ADDRINFOA hints.
        unsafe {
            flags = teb::get(hints as u64, 0);
            let family: i32 = teb::get(hints as u64, 4);
            if family != 0 && family != AF_INET as i32 {
                return WSAEAFNOSUPPORT as i32;
            }
            socktype = teb::get(hints as u64, 8);
            proto = teb::get(hints as u64, 12);
        }
    }
    let port: u16 = match svc.as_deref() {
        None => 0,
        Some(s) => match s.parse() {
            Ok(p) => p,
            // A named service needs the services database, which OSyx has not.
            Err(_) if flags & AI_NUMERICSERV == 0 => return WSATRY_AGAIN as i32,
            Err(_) => return WSAHOST_NOT_FOUND as i32,
        },
    };
    if flags & AI_NUMERICHOST != 0 {
        if let Some(name) = n.as_deref() {
            if parse_ipv4(name).is_none() {
                return WSAHOST_NOT_FOUND as i32;
            }
        }
    }
    let addrs = match n {
        Some(n) => match resolve(&n) {
            Ok(a) => a,
            Err(e) => return e as i32,
        },
        // AI_PASSIVE without a node means "any local address".
        None if flags & AI_PASSIVE != 0 => alloc::vec![[0, 0, 0, 0]],
        None => alloc::vec![[127, 0, 0, 1]],
    };
    let mut head = 0u64;
    for a in addrs.iter().rev() {
        let Some(block) = crate::kernel32::heap_alloc(48 + 16, true) else { return WSAENOBUFS as i32 };
        let sa = block + 48;
        write_addr(&SockAddr::new(*a, port), sa as *mut u8, core::ptr::null_mut());
        // SAFETY: a fresh zeroed 64-byte block.
        unsafe {
            teb::put(block, 4, AF_INET as i32);
            teb::put(block, 8, socktype);
            teb::put(block, 12, proto);
            teb::put(block, 16, 16u64);
            teb::put(block, 32, sa);
            teb::put(block, 40, head);
        }
        head = block;
    }
    if head == 0 {
        return WSAHOST_NOT_FOUND as i32;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *res = head };
    0
}

extern "win64" fn freeaddrinfo(mut p: u64) {
    while p != 0 {
        // SAFETY: a block made by getaddrinfo (ai_next at offset 40).
        let next: u64 = unsafe { teb::get(p, 40) };
        crate::kernel32::heap_free(p);
        p = next;
    }
}

/// WSASocketW: a plain socket. Overlapped I/O is not offered (calls block
/// or fail with WSAEWOULDBLOCK), so WSA_FLAG_OVERLAPPED changes nothing;
/// a specific provider (WSAPROTOCOL_INFOW) is not supported.
extern "win64" fn WSASocketW(af: i32, kind: i32, proto: i32, info: *const u8, group: u32, _flags: u32) -> u64 {
    if crate::VERBOSE.load(Ordering::Relaxed) {
        os_std::eprintln!("winrun: WSASocket family {af}, kind {kind}, protocol {proto}, provider {}, group {group}, flags {_flags:#x}", !info.is_null());
    }
    if !info.is_null() || group != 0 {
        return err(WSAEINVAL, INVALID_SOCKET);
    }
    socket(af, kind, proto)
}

const FIONREAD: u32 = 0x4004_667F;

/// WSAIoctl: FIONBIO and FIONREAD only, synchronously. Extension functions
/// (SIO_GET_EXTENSION_FUNCTION_POINTER: ConnectEx, AcceptEx, ...) need
/// overlapped I/O and are reported unsupported, so callers fall back.
#[allow(clippy::too_many_arguments)]
extern "win64" fn WSAIoctl(
    s: u64,
    code: u32,
    input: *const u8,
    in_len: u32,
    output: *mut u8,
    out_len: u32,
    returned: *mut u32,
    overlapped: *mut u8,
    completion: u64,
) -> i32 {
    result((|| {
        let (fd, _) = fd(s)?;
        if !overlapped.is_null() || completion != 0 {
            return Err(WSAEOPNOTSUPP);
        }
        let written = match code {
            FIONBIO => {
                if input.is_null() || in_len < 4 {
                    return Err(WSAEFAULT);
                }
                // SAFETY: the caller's 4-byte input.
                let mut v = unsafe { core::ptr::read_unaligned(input as *const u32) };
                if ioctlsocket(s, FIONBIO, &mut v) != 0 {
                    return Err(teb::last_error());
                }
                0
            }
            FIONREAD => {
                if output.is_null() || out_len < 4 {
                    return Err(WSAEFAULT);
                }
                let n = os_sys::sock_ctl(fd, net::ctl::AVAILABLE, 0).map_err(wsa)?;
                // SAFETY: the caller's 4-byte output buffer.
                unsafe { core::ptr::write_unaligned(output as *mut u32, n as u32) };
                4
            }
            _ => return Err(WSAEINVAL),
        };
        if !returned.is_null() {
            // SAFETY: the caller's out count.
            unsafe { *returned = written };
        }
        Ok(())
    })())
}

/// WSASendMsg: WSAMSG { name, namelen, lpBuffers, dwBufferCount, Control,
/// dwFlags } with the buffers gathered into one datagram or stream write.
/// Control data (ancillary messages) is not supported.
extern "win64" fn WSASendMsg(s: u64, msg: *const u8, f: u32, sent: *mut u32, overlapped: *mut u8, completion: u64) -> i32 {
    let r = (|| {
        let (fd, _) = fd(s)?;
        if msg.is_null() {
            return Err(WSAEFAULT);
        }
        if f != 0 || !overlapped.is_null() || completion != 0 {
            return Err(WSAEOPNOTSUPP);
        }
        // SAFETY: the caller's WSAMSG (x64 layout: 56 bytes) and WSABUFs.
        let (to, data) = unsafe {
            let m = msg as u64;
            let name: u64 = teb::get(m, 0);
            let name_len: i32 = teb::get(m, 8);
            let bufs: u64 = teb::get(m, 16);
            let count: u32 = teb::get(m, 24);
            if teb::get::<u32>(m, 32) != 0 {
                return Err(WSAEINVAL);
            }
            let to = if name == 0 { None } else { Some(read_addr(name as *const u8, name_len)?) };
            let mut data = Vec::new();
            for i in 0..count as u64 {
                let len: u32 = teb::get(bufs, (i * 16) as usize);
                let p: u64 = teb::get(bufs, (i * 16 + 8) as usize);
                data.extend_from_slice(core::slice::from_raw_parts(p as *const u8, len as usize));
            }
            (to, data)
        };
        os_sys::sock_send(fd, &data, to.as_ref(), 0).map_err(wsa)
    })();
    match r {
        Ok(n) => {
            if !sent.is_null() {
                // SAFETY: the caller's out count.
                unsafe { *sent = n as u32 };
            }
            0
        }
        Err(e) => err(e, SOCKET_ERROR),
    }
}

/// inet_pton: dotted-decimal IPv4 or textual IPv6 into network order.
extern "win64" fn inet_pton(af: i32, src: *const u8, dst: *mut u8) -> i32 {
    if src.is_null() || dst.is_null() {
        return err(WSAEFAULT, -1);
    }
    // SAFETY: a NUL-terminated string.
    let Some(text) = (unsafe { crate::path::ansi_to_string(src) }) else { return err(WSAEFAULT, -1) };
    let bytes: Vec<u8> = match af {
        a if a == AF_INET as i32 => match text.parse::<core::net::Ipv4Addr>() {
            Ok(a) => a.octets().to_vec(),
            Err(_) => return 0,
        },
        AF_INET6 => match text.parse::<core::net::Ipv6Addr>() {
            Ok(a) => a.octets().to_vec(),
            Err(_) => return 0,
        },
        _ => return err(WSAEAFNOSUPPORT, -1),
    };
    // SAFETY: the caller's in_addr / in6_addr.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    1
}

/// inet_ntop: the RFC 5952 text of an IPv4 or IPv6 address.
extern "win64" fn inet_ntop(af: i32, src: *const u8, dst: *mut u8, size: usize) -> u64 {
    if src.is_null() || dst.is_null() {
        return err(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's in_addr (4 bytes) / in6_addr (16 bytes).
    let text = unsafe {
        match af {
            a if a == AF_INET as i32 => {
                let mut b = [0u8; 4];
                core::ptr::copy_nonoverlapping(src, b.as_mut_ptr(), 4);
                alloc::format!("{}", core::net::Ipv4Addr::from(b))
            }
            AF_INET6 => {
                let mut b = [0u8; 16];
                core::ptr::copy_nonoverlapping(src, b.as_mut_ptr(), 16);
                alloc::format!("{}", core::net::Ipv6Addr::from(b))
            }
            _ => return err(WSAEAFNOSUPPORT, 0),
        }
    };
    if size < text.len() + 1 {
        return err(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's buffer of `size` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), dst, text.len());
        *dst.add(text.len()) = 0;
    }
    dst as u64
}

/// The catalog: one base provider each for TCP and UDP over IPv4, both
/// served by OSyx's own stack. No layered (LSP) providers exist.
const PROVIDER_ID: [u8; 16] = *b"OSyx-Winsock-TCP";
const PROTOCOL_INFO_SIZE: usize = 628;
const PROVIDER_PATH: &str = "%SystemRoot%\\system32\\mswsock.dll";

/// WSAPROTOCOL_INFOW of catalog entry `(socket type, protocol)`.
fn protocol_info(p: u64, kind: i32, proto: i32) {
    // XP1_GUARANTEED_DELIVERY | GUARANTEED_ORDER | GRACEFUL_CLOSE for TCP;
    // XP1_CONNECTIONLESS | MESSAGE_ORIENTED | SUPPORT_BROADCAST for UDP.
    let (flags, msg_size, name) = if kind == SOCK_STREAM {
        (0x26u32, 0u32, "OSyx TCP/IP [TCP/IP]")
    } else {
        (0x209, 65507, "OSyx TCP/IP [UDP/IP]")
    };
    // SAFETY: the caller's 628-byte WSAPROTOCOL_INFOW.
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, PROTOCOL_INFO_SIZE);
        teb::put(p, 0, flags);
        core::ptr::copy_nonoverlapping(PROVIDER_ID.as_ptr(), (p + 20) as *mut u8, 16);
        teb::put(p, 36, 1000 + proto as u32);
        teb::put(p, 40, 1i32); // ProtocolChain.ChainLen: BASE_PROTOCOL
        teb::put(p, 72, 2i32); // iVersion
        teb::put(p, 76, AF_INET as i32);
        teb::put(p, 80, 16i32);
        teb::put(p, 84, 16i32);
        teb::put(p, 88, kind);
        teb::put(p, 92, proto);
        teb::put(p, 108, msg_size);
        for (i, c) in name.encode_utf16().enumerate() {
            teb::put(p, 116 + i * 2, c);
        }
    }
}

extern "win64" fn WSCEnumProtocols(filter: *const i32, buf: *mut u8, len: *mut u32, errno: *mut i32) -> i32 {
    let set_errno = |e: u32| {
        if !errno.is_null() {
            // SAFETY: the caller's error out-parameter.
            unsafe { *errno = e as i32 };
        }
    };
    let wanted = |proto: i32| -> bool {
        if filter.is_null() {
            return true;
        }
        // SAFETY: the caller's zero-terminated protocol list.
        unsafe { (0..).map(|i| *filter.add(i)).take_while(|&v| v != 0).any(|v| v == proto) }
    };
    let entries: Vec<(i32, i32)> =
        [(SOCK_STREAM, IPPROTO_TCP), (SOCK_DGRAM, 17)].into_iter().filter(|&(_, p)| wanted(p)).collect();
    if len.is_null() {
        set_errno(WSAEFAULT);
        return SOCKET_ERROR;
    }
    let need = (entries.len() * PROTOCOL_INFO_SIZE) as u32;
    // SAFETY: the caller's buffer length.
    unsafe {
        if buf.is_null() || *len < need {
            *len = need;
            set_errno(WSAENOBUFS);
            return SOCKET_ERROR;
        }
    }
    for (i, &(kind, proto)) in entries.iter().enumerate() {
        protocol_info(buf as u64 + (i * PROTOCOL_INFO_SIZE) as u64, kind, proto);
    }
    entries.len() as i32
}

/// Whether `id` points at OSyx's provider GUID.
fn our_provider(id: *const u8) -> bool {
    // SAFETY: the caller's GUID.
    !id.is_null() && unsafe { core::slice::from_raw_parts(id, 16) } == PROVIDER_ID
}

/// WSCGetProviderInfo: LSP categories are recorded only for layered
/// providers (WSCSetProviderInfo); for a base provider Windows reports
/// WSAEINVALIDPROVIDER, and so does OSyx, which has only base providers.
extern "win64" fn WSCGetProviderInfo(id: *const u8, _kind: i32, _info: *mut u8, _size: *mut usize, _flags: u32, errno: *mut i32) -> i32 {
    if !errno.is_null() {
        // SAFETY: the caller's error out-parameter.
        unsafe { *errno = if our_provider(id) { WSAEINVALIDPROVIDER } else { WSAEINVAL } as i32 };
    }
    SOCKET_ERROR
}

extern "win64" fn WSCGetProviderPath(id: *const u8, path: *mut u16, len: *mut i32, errno: *mut i32) -> i32 {
    let fail = |e: u32| {
        if !errno.is_null() {
            // SAFETY: the caller's error out-parameter.
            unsafe { *errno = e as i32 };
        }
        SOCKET_ERROR
    };
    if !our_provider(id) {
        return fail(WSAEINVAL);
    }
    let w: Vec<u16> = PROVIDER_PATH.encode_utf16().chain(core::iter::once(0)).collect();
    if len.is_null() {
        return fail(WSAEFAULT);
    }
    // SAFETY: the caller's length (in characters) and buffer.
    unsafe {
        if path.is_null() || (*len as usize) < w.len() {
            *len = w.len() as i32;
            return fail(WSAEFAULT);
        }
        core::ptr::copy_nonoverlapping(w.as_ptr(), path, w.len());
    }
    0
}

/// FD_ISSET: whether fd_set `set` holds `s`.
extern "win64" fn __WSAFDIsSet(s: u64, set: *const u8) -> i32 {
    if set.is_null() {
        return 0;
    }
    // SAFETY: the caller's fd_set { u32 count; SOCKET array[64] }.
    unsafe {
        let n: u32 = teb::get(set as u64, 0);
        (0..n.min(64) as usize).any(|i| teb::get::<u64>(set as u64, 8 + i * 8) == s) as i32
    }
}

/// select over fd_set { u32 count; SOCKET array[64] } for reading and
/// writing (the exception set is reported empty); timeval {sec, usec}.
extern "win64" fn select(_nfds: i32, rd: *mut u8, wr: *mut u8, ex: *mut u8, timeout: *const i32) -> i32 {
    trace_io(format_args!("select begin"));
    let read_set = |p: *mut u8| -> Vec<u64> {
        if p.is_null() {
            return Vec::new();
        }
        // SAFETY: the caller's fd_set.
        unsafe {
            let n: u32 = teb::get(p as u64, 0);
            (0..n.min(64) as usize).map(|i| teb::get::<u64>(p as u64, 8 + i * 8)).collect()
        }
    };
    let (r, w) = (read_set(rd), read_set(wr));
    let mut items = Vec::new();
    for (&s, ev) in
        r.iter().map(|s| (s, osyx_abi::ipc::WAIT_READABLE)).chain(w.iter().map(|s| (s, osyx_abi::ipc::WAIT_WRITABLE)))
    {
        match fd(s) {
            Ok((f, _)) => items.push((s, os_sys::ipc::WaitItem { handle: f, events: ev, revents: 0 })),
            Err(e) => return err(e, SOCKET_ERROR),
        }
    }
    let ns = if timeout.is_null() {
        u64::MAX
    } else {
        // SAFETY: the caller's timeval.
        unsafe { (*timeout).max(0) as u64 * 1_000_000_000 + (*timeout.add(1)).max(0) as u64 * 1000 }
    };
    let mut raw: Vec<os_sys::ipc::WaitItem> = items.iter().map(|(_, i)| *i).collect();
    if let Err(e) = os_sys::wait_handles(&mut raw, ns) {
        if e != Errno::TimedOut {
            return err(wsa(e), SOCKET_ERROR);
        }
    }
    trace_io(format_args!("select woke: {raw:?}"));
    let mut count = 0;
    let write_set = |p: *mut u8, list: &[u64]| {
        if p.is_null() {
            return;
        }
        // SAFETY: the caller's fd_set.
        unsafe {
            teb::put(p as u64, 0, list.len() as u32);
            for (i, s) in list.iter().enumerate() {
                teb::put(p as u64, 8 + i * 8, *s);
            }
        }
    };
    let ready = |ev: u32| -> Vec<u64> {
        items
            .iter()
            .zip(&raw)
            .filter(|((_, i), r)| i.events == ev && r.revents & (ev | osyx_abi::ipc::WAIT_HANGUP) != 0)
            .map(|((s, _), _)| *s)
            .collect()
    };
    let (rr, wr2) = (ready(osyx_abi::ipc::WAIT_READABLE), ready(osyx_abi::ipc::WAIT_WRITABLE));
    count += rr.len() + wr2.len();
    write_set(rd, &rr);
    write_set(wr, &wr2);
    write_set(ex, &[]);
    count as i32
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        WSAStartup,
        WSACleanup,
        WSAGetLastError,
        WSASetLastError,
        socket,
        closesocket,
        bind,
        connect,
        listen,
        accept,
        send,
        sendto,
        recv,
        recvfrom,
        shutdown,
        setsockopt,
        getsockopt,
        ioctlsocket,
        getsockname,
        getpeername,
        htons,
        ntohs,
        htonl,
        ntohl,
        inet_addr,
        inet_ntoa,
        gethostbyname,
        gethostbyaddr,
        getprotobyname,
        getprotobynumber,
        gethostname,
        getaddrinfo,
        freeaddrinfo,
        select,
        __WSAFDIsSet,
        WSASocketW,
        WSAIoctl,
        WSASendMsg,
        inet_pton,
        inet_ntop,
        WSCEnumProtocols,
        WSCGetProviderInfo,
        WSCGetProviderPath,
    ]
}

/// Winsock 2 export ordinals. The legacy DLL differs at ordinals 10-12.
pub fn ordinals() -> Vec<(u16, u64)> {
    let f = |p: usize| p as u64;
    alloc::vec![
        (1, f(accept as *const () as usize)),
        (2, f(bind as *const () as usize)),
        (3, f(closesocket as *const () as usize)),
        (4, f(connect as *const () as usize)),
        (5, f(getpeername as *const () as usize)),
        (6, f(getsockname as *const () as usize)),
        (7, f(getsockopt as *const () as usize)),
        (8, f(htonl as *const () as usize)),
        (9, f(htons as *const () as usize)),
        (10, f(ioctlsocket as *const () as usize)),
        (11, f(inet_addr as *const () as usize)),
        (12, f(inet_ntoa as *const () as usize)),
        (13, f(listen as *const () as usize)),
        (14, f(ntohl as *const () as usize)),
        (15, f(ntohs as *const () as usize)),
        (16, f(recv as *const () as usize)),
        (17, f(recvfrom as *const () as usize)),
        (18, f(select as *const () as usize)),
        (19, f(send as *const () as usize)),
        (20, f(sendto as *const () as usize)),
        (21, f(setsockopt as *const () as usize)),
        (22, f(shutdown as *const () as usize)),
        (23, f(socket as *const () as usize)),
        (51, f(gethostbyaddr as *const () as usize)),
        (52, f(gethostbyname as *const () as usize)),
        (53, f(getprotobyname as *const () as usize)),
        (54, f(getprotobynumber as *const () as usize)),
        (57, f(gethostname as *const () as usize)),
        (111, f(WSAGetLastError as *const () as usize)),
        (112, f(WSASetLastError as *const () as usize)),
        (115, f(WSAStartup as *const () as usize)),
        (116, f(WSACleanup as *const () as usize)),
        (151, f(__WSAFDIsSet as *const () as usize)),
    ]
}

/// WSOCK32 preserves its older order: inet_addr, inet_ntoa, ioctlsocket.
/// NSPR imports ordinal 12 rather than the function name.
pub fn legacy_ordinals() -> Vec<(u16, u64)> {
    let mut entries = ordinals();
    for (ordinal, address) in &mut entries {
        *address = match *ordinal {
            10 => inet_addr as *const () as u64,
            11 => inet_ntoa as *const () as u64,
            12 => ioctlsocket as *const () as u64,
            _ => *address,
        };
    }
    entries
}
