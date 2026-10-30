//! Interfaces, routing, sockets and the DNS resolver on top of the
//! protocol modules.
//!
//! The stack is a single-threaded state machine (`&mut self`); the kernel
//! keeps it behind one lock. Time comes from [`Stack::set_now`]
//! (milliseconds); frames to transmit accumulate in an outbox that the
//! caller drains with [`Stack::take_tx`] after releasing the lock, so no
//! device I/O ever happens inside the stack.

use crate::arp::{self, Lookup};
use crate::dhcp;
use crate::dns;
use crate::ethernet::{self, ETHERTYPE_ARP, ETHERTYPE_IPV4};
use crate::icmp::{self, Message};
use crate::ipv4::{self, Reassembler, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::tcp::{self, Tcb, TcpError};
use crate::udp;
use crate::wire::{be16, Endpoint, Ipv4Addr, MacAddr};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

pub type SocketId = u32;

/// Socket and resolver errors (mapped to `Errno` by the kernel).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    WouldBlock,
    InvalidArgument,
    AddrInUse,
    /// The local address is not configured on any interface.
    AddrNotAvailable,
    NoRoute,
    HostUnreachable,
    PortUnreachable,
    ConnRefused,
    ConnReset,
    TimedOut,
    NotConnected,
    AlreadyConnected,
    /// The datagram exceeds what can be sent (or `DF` would fragment it).
    MessageTooLong,
    /// A queue or table limit was reached.
    NoBuffers,
    /// The socket was shut down for this direction.
    Shutdown,
    /// DNS: the name does not exist.
    NameNotFound,
    /// DNS: no server, a server failure or an unusable answer.
    DnsFailure,
    BadSocket,
}

impl NetError {
    pub fn name(self) -> &'static str {
        match self {
            NetError::WouldBlock => "operation would block",
            NetError::InvalidArgument => "invalid argument",
            NetError::AddrInUse => "address in use",
            NetError::AddrNotAvailable => "address not available",
            NetError::NoRoute => "no route to network",
            NetError::HostUnreachable => "host unreachable",
            NetError::PortUnreachable => "port unreachable",
            NetError::ConnRefused => "connection refused",
            NetError::ConnReset => "connection reset",
            NetError::TimedOut => "timed out",
            NetError::NotConnected => "not connected",
            NetError::AlreadyConnected => "already connected",
            NetError::MessageTooLong => "message too long",
            NetError::NoBuffers => "no buffer space",
            NetError::Shutdown => "socket shut down",
            NetError::NameNotFound => "name not found",
            NetError::DnsFailure => "DNS failure",
            NetError::BadSocket => "bad socket",
        }
    }
}

fn tcp_error(e: TcpError) -> NetError {
    match e {
        TcpError::Refused => NetError::ConnRefused,
        TcpError::Reset => NetError::ConnReset,
        TcpError::TimedOut => NetError::TimedOut,
        TcpError::NotConnected => NetError::NotConnected,
        TcpError::Closed => NetError::Shutdown,
        TcpError::WouldBlock => NetError::WouldBlock,
    }
}

/// Limits.
pub const MAX_SOCKETS: usize = 256;
pub const UDP_QUEUE_DATAGRAMS: usize = 64;
pub const UDP_QUEUE_BYTES: usize = 256 * 1024;
pub const ICMP_QUEUE: usize = 32;
pub const MAX_BACKLOG: usize = 32;
pub const MAX_TX_QUEUE: usize = 1024;
pub const MAX_UDP_PAYLOAD: usize = ipv4::MAX_DATAGRAM - ipv4::MIN_HEADER - udp::HEADER_LEN;
const EPHEMERAL: core::ops::RangeInclusive<u16> = 49152..=65535;
const LOOPBACK_MTU: usize = 16384;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IfStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_dropped: u64,
    pub rx_errors: u64,
    pub tx_dropped: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfaceKind {
    Loopback,
    Ethernet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigMethod {
    None,
    Static,
    Dhcp,
}

pub struct Interface {
    pub name: String,
    pub kind: IfaceKind,
    pub mac: MacAddr,
    pub mtu: usize,
    pub link_up: bool,
    pub addr: Option<(Ipv4Addr, u8)>,
    pub method: ConfigMethod,
    pub stats: IfStats,
    arp: arp::Cache,
    dhcp: Option<dhcp::Client>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteOrigin {
    Connected,
    Static,
    Dhcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub dest: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub iface: usize,
    pub origin: RouteOrigin,
}

/// An echo reply or ICMP error delivered to an ICMP socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IcmpEvent {
    Reply { from: Ipv4Addr, seq: u16, ttl: u8, data: Vec<u8> },
    Error { from: Ipv4Addr, seq: u16, error: NetError, code: u8 },
}

struct UdpSocket {
    local: Endpoint,
    remote: Option<Endpoint>,
    rx: VecDeque<(Endpoint, Vec<u8>)>,
    rx_bytes: usize,
    error: Option<NetError>,
    dropped: u64,
    broadcast: bool,
}

struct IcmpSocket {
    ident: u16,
    rx: VecDeque<IcmpEvent>,
    /// Destinations with requests outstanding (for unreachable reports).
    targets: Vec<(Ipv4Addr, u16)>,
}

struct Listener {
    local: Endpoint,
    backlog: usize,
    /// Accepted by TCP, not yet by the application.
    ready: VecDeque<SocketId>,
}

struct TcpSocket {
    tcb: Tcb,
    /// The listener this connection arrived on, until it is accepted.
    parent: Option<SocketId>,
    /// The application released it: remove once the connection is done.
    released: bool,
    /// Counted in its parent's backlog.
    accepted: bool,
}

enum Socket {
    Udp(UdpSocket),
    Icmp(IcmpSocket),
    BoundTcp(Endpoint),
    Listener(Listener),
    Tcp(alloc::boxed::Box<TcpSocket>),
}

/// One row of [`Stack::sockets`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketInfo {
    pub id: SocketId,
    pub kind: &'static str,
    pub local: Endpoint,
    pub remote: Option<Endpoint>,
    pub state: &'static str,
    pub rx_queue: usize,
    pub tx_queue: usize,
    pub internal: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub ip_in: u64,
    pub ip_out: u64,
    pub ip_bad: u64,
    pub ip_fragments_in: u64,
    pub ip_reassembled: u64,
    pub ip_not_for_us: u64,
    pub icmp_in: u64,
    pub icmp_out: u64,
    pub icmp_echo_answered: u64,
    pub udp_in: u64,
    pub udp_out: u64,
    pub udp_bad: u64,
    pub udp_no_port: u64,
    pub tcp_in: u64,
    pub tcp_out: u64,
    pub tcp_bad: u64,
    pub tcp_resets_sent: u64,
    pub tcp_retransmits: u64,
    pub arp_in: u64,
    pub arp_out: u64,
    pub arp_bad: u64,
    pub frames_bad: u64,
    pub dns_queries: u64,
    pub dns_rejected: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Udp(SocketId),
    /// TCP fallback: connection and bytes of the length-prefixed reply.
    Tcp(SocketId),
}

struct Query {
    id: u16,
    name: String,
    server: usize,
    attempt: u32,
    deadline: u64,
    transport: Transport,
    reply: Vec<u8>,
    /// Through which server address (validated against the reply source).
    server_addr: Ipv4Addr,
}

pub type QueryId = u32;

/// Result of [`Stack::resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolve {
    Done(Result<Vec<Ipv4Addr>, NetError>),
    Pending(QueryId),
}

pub const DNS_TIMEOUT_MS: u64 = 2_000;
pub const DNS_ATTEMPTS: u32 = 2;
const MAX_QUERIES: usize = 32;

/// A line for the kernel log (configuration changes and notable events).
pub type LogLine = String;

pub struct Stack {
    ifaces: Vec<Interface>,
    routes: Vec<Route>,
    sockets: BTreeMap<SocketId, Socket>,
    /// Sockets owned by the stack itself (DNS).
    internal: Vec<SocketId>,
    next_socket: SocketId,
    next_ephemeral: u16,
    ident: u16,
    rng: u64,
    secret: u64,
    now: u64,
    tx: VecDeque<(usize, Vec<u8>)>,
    loopback: VecDeque<Vec<u8>>,
    reasm: Reassembler,
    pub stats: Stats,
    changed: bool,
    log: Vec<LogLine>,
    dns_servers: Vec<Ipv4Addr>,
    dns_static: bool,
    pub dns_cache: dns::Cache,
    queries: BTreeMap<QueryId, Query>,
    results: BTreeMap<QueryId, Result<Vec<Ipv4Addr>, NetError>>,
    next_query: QueryId,
    dns_changed: bool,
    hostname: String,
}

impl Stack {
    /// A stack with the loopback interface `lo` (127.0.0.1/8). `seed`
    /// randomises sequence numbers, ports and transaction ids.
    pub fn new(seed: u64) -> Stack {
        let mut s = Stack {
            ifaces: Vec::new(),
            routes: Vec::new(),
            sockets: BTreeMap::new(),
            internal: Vec::new(),
            next_socket: 1,
            next_ephemeral: 0,
            ident: seed as u16,
            rng: seed | 1,
            secret: seed.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15,
            now: 0,
            tx: VecDeque::new(),
            loopback: VecDeque::new(),
            reasm: Reassembler::new(),
            stats: Stats::default(),
            changed: false,
            log: Vec::new(),
            dns_servers: Vec::new(),
            dns_static: false,
            dns_cache: dns::Cache::new(),
            queries: BTreeMap::new(),
            results: BTreeMap::new(),
            next_query: 1,
            dns_changed: false,
            hostname: String::from("osyx"),
        };
        s.next_ephemeral = *EPHEMERAL.start() + (s.rand() % 16000) as u16;
        s.ifaces.push(Interface {
            name: "lo".into(),
            kind: IfaceKind::Loopback,
            mac: MacAddr::ZERO,
            mtu: LOOPBACK_MTU,
            link_up: true,
            addr: Some((Ipv4Addr::LOOPBACK, 8)),
            method: ConfigMethod::Static,
            stats: IfStats::default(),
            arp: arp::Cache::new(),
            dhcp: None,
        });
        s.routes.push(Route { dest: Ipv4Addr::new(127, 0, 0, 0), prefix: 8, gateway: None, iface: 0, origin: RouteOrigin::Connected });
        s
    }

    fn rand(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn set_now(&mut self, now_ms: u64) {
        self.now = now_ms.max(self.now);
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    pub fn set_hostname(&mut self, name: &str) {
        self.hostname = name.into();
    }

    fn logf(&mut self, line: String) {
        if self.log.len() < 256 {
            self.log.push(line);
        }
    }

    /// Log lines since the last call.
    pub fn take_log(&mut self) -> Vec<LogLine> {
        core::mem::take(&mut self.log)
    }

    /// Frames to transmit: (interface index, frame).
    pub fn take_tx(&mut self) -> Vec<(usize, Vec<u8>)> {
        self.tx.drain(..).collect()
    }

    /// Whether any socket or query changed state since the last call
    /// (waiters should re-check).
    pub fn take_changed(&mut self) -> bool {
        let c = self.changed || self.dns_changed;
        self.changed = false;
        self.dns_changed = false;
        c
    }

    // ----- interfaces and configuration -------------------------------------

    pub fn add_ethernet(&mut self, name: &str, mac: MacAddr, mtu: usize) -> usize {
        self.ifaces.push(Interface {
            name: name.into(),
            kind: IfaceKind::Ethernet,
            mac,
            mtu: mtu.clamp(576, ethernet::MTU),
            link_up: true,
            addr: None,
            method: ConfigMethod::None,
            stats: IfStats::default(),
            arp: arp::Cache::new(),
            dhcp: None,
        });
        let i = self.ifaces.len() - 1;
        self.logf(alloc::format!("{}: Ethernet {} mtu {}", name, mac, self.ifaces[i].mtu));
        i
    }

    pub fn interfaces(&self) -> &[Interface] {
        &self.ifaces
    }

    pub fn iface_by_name(&self, name: &str) -> Option<usize> {
        self.ifaces.iter().position(|i| i.name == name)
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn dns_servers(&self) -> &[Ipv4Addr] {
        &self.dns_servers
    }

    pub fn dhcp_state(&self, iface: usize) -> Option<(dhcp::Phase, Option<&dhcp::Lease>)> {
        self.ifaces.get(iface)?.dhcp.as_ref().map(|d| (d.phase(), d.lease()))
    }

    pub fn arp_entries(&self, iface: usize) -> Vec<(Ipv4Addr, Option<MacAddr>, u64)> {
        self.ifaces.get(iface).map(|i| i.arp.entries(self.now)).unwrap_or_default()
    }

    pub fn set_link(&mut self, iface: usize, up: bool) {
        let mut restart = false;
        if let Some(i) = self.ifaces.get_mut(iface) {
            if i.link_up != up {
                i.link_up = up;
                // Reacquire configuration after a link change: Wi-Fi may have
                // rejoined a different network while the old lease is valid.
                restart = up && i.dhcp.is_some();
                if up {
                    i.arp.flush();
                }
                let line = alloc::format!("{}: link {}", i.name, if up { "up" } else { "down" });
                self.logf(line);
            }
        }
        if restart {
            self.dns_cache.flush();
            let _ = self.enable_dhcp(iface);
        }
    }

    fn set_address(&mut self, iface: usize, addr: Option<(Ipv4Addr, u8)>, gateway: Option<Ipv4Addr>, origin: RouteOrigin) {
        self.routes.retain(|r| r.iface != iface);
        let i = &mut self.ifaces[iface];
        i.addr = addr;
        i.arp.flush();
        if let Some((a, p)) = addr {
            let net = Ipv4Addr::from_u32(a.to_u32() & crate::wire::prefix_mask(p));
            self.routes.push(Route { dest: net, prefix: p, gateway: None, iface, origin: RouteOrigin::Connected });
            if let Some(g) = gateway {
                self.routes.push(Route { dest: Ipv4Addr::UNSPECIFIED, prefix: 0, gateway: Some(g), iface, origin });
            }
        }
        self.changed = true;
    }

    /// Static configuration (disables DHCP on the interface).
    pub fn configure_static(&mut self, iface: usize, addr: Ipv4Addr, prefix: u8, gateway: Option<Ipv4Addr>) -> Result<(), NetError> {
        if iface >= self.ifaces.len() || self.ifaces[iface].kind != IfaceKind::Ethernet || prefix > 32 {
            return Err(NetError::InvalidArgument);
        }
        if addr.is_unspecified() || addr.is_broadcast() || addr.is_multicast() || addr.is_loopback() {
            return Err(NetError::InvalidArgument);
        }
        if let Some(g) = gateway {
            if !g.in_subnet(addr, prefix) {
                return Err(NetError::InvalidArgument);
            }
        }
        self.ifaces[iface].dhcp = None;
        self.ifaces[iface].method = ConfigMethod::Static;
        self.set_address(iface, Some((addr, prefix)), gateway, RouteOrigin::Static);
        let line = alloc::format!(
            "{}: static {}/{}{}",
            self.ifaces[iface].name,
            addr,
            prefix,
            gateway.map(|g| alloc::format!(" via {g}")).unwrap_or_default()
        );
        self.logf(line);
        Ok(())
    }

    /// Starts (or restarts) DHCP on an interface.
    pub fn enable_dhcp(&mut self, iface: usize) -> Result<(), NetError> {
        if iface >= self.ifaces.len() || self.ifaces[iface].kind != IfaceKind::Ethernet {
            return Err(NetError::InvalidArgument);
        }
        let seed = self.rand() as u32;
        let i = &mut self.ifaces[iface];
        i.dhcp = Some(dhcp::Client::new(i.mac, seed, &self.hostname));
        i.method = ConfigMethod::Dhcp;
        let name = i.name.clone();
        self.set_address(iface, None, None, RouteOrigin::Dhcp);
        self.logf(alloc::format!("{}: DHCP started", name));
        Ok(())
    }

    /// Removes the address and stops DHCP.
    pub fn deconfigure(&mut self, iface: usize) -> Result<(), NetError> {
        if iface >= self.ifaces.len() || self.ifaces[iface].kind != IfaceKind::Ethernet {
            return Err(NetError::InvalidArgument);
        }
        self.ifaces[iface].dhcp = None;
        self.ifaces[iface].method = ConfigMethod::None;
        self.set_address(iface, None, None, RouteOrigin::Static);
        Ok(())
    }

    pub fn set_dns_servers(&mut self, servers: &[Ipv4Addr]) {
        self.dns_servers = servers.to_vec();
        self.dns_static = !servers.is_empty();
        self.dns_cache.flush();
    }

    fn local_addrs(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.ifaces.iter().filter_map(|i| i.addr.map(|a| a.0))
    }

    fn is_local(&self, a: Ipv4Addr) -> bool {
        a.is_loopback() || self.local_addrs().any(|l| l == a)
    }

    /// Interface and next hop for `dst` (longest prefix match).
    pub fn route(&self, dst: Ipv4Addr) -> Option<(usize, Ipv4Addr)> {
        let r = self
            .routes
            .iter()
            .filter(|r| dst.in_subnet(r.dest, r.prefix) && self.ifaces[r.iface].link_up)
            .max_by_key(|r| r.prefix)?;
        Some((r.iface, r.gateway.unwrap_or(dst)))
    }

    fn source_for(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        if dst.is_loopback() {
            return Some(Ipv4Addr::LOOPBACK);
        }
        if self.is_local(dst) {
            return Some(dst);
        }
        let (iface, _) = self.route(dst)?;
        self.ifaces[iface].addr.map(|a| a.0)
    }

    // ----- transmit path --------------------------------------------------------

    fn push_frame(&mut self, iface: usize, frame: Vec<u8>) {
        if self.tx.len() >= MAX_TX_QUEUE {
            self.ifaces[iface].stats.tx_dropped += 1;
            return;
        }
        let i = &mut self.ifaces[iface];
        i.stats.tx_packets += 1;
        i.stats.tx_bytes += frame.len() as u64;
        self.tx.push_back((iface, frame));
    }

    fn send_arp(&mut self, iface: usize, op: u16, target_mac: MacAddr, target_ip: Ipv4Addr, dst: MacAddr) {
        let i = &self.ifaces[iface];
        let Some((own, _)) = i.addr else { return };
        let p = arp::Packet { op, sender_mac: i.mac, sender_ip: own, target_mac, target_ip };
        let frame = ethernet::build(dst, i.mac, ETHERTYPE_ARP, &p.emit());
        self.stats.arp_out += 1;
        self.push_frame(iface, frame);
    }

    /// Sends one IP packet to `next_hop` on an Ethernet interface,
    /// resolving the hardware address first.
    fn send_packet_on(&mut self, iface: usize, next_hop: Ipv4Addr, packet: Vec<u8>, broadcast: bool) {
        let i = &self.ifaces[iface];
        let directed = i.addr.is_some_and(|(a, p)| {
            next_hop.in_subnet(a, p) && next_hop.to_u32() | crate::wire::prefix_mask(p) == next_hop.to_u32()
        });
        if broadcast || next_hop.is_broadcast() || directed {
            let frame = ethernet::build(MacAddr::BROADCAST, i.mac, ETHERTYPE_IPV4, &packet);
            self.push_frame(iface, frame);
            return;
        }
        let now = self.now;
        match self.ifaces[iface].arp.resolve(next_hop, packet, now) {
            Lookup::Found(mac, packet) => {
                let frame = ethernet::build(mac, self.ifaces[iface].mac, ETHERTYPE_IPV4, &packet);
                self.push_frame(iface, frame);
            }
            Lookup::Queued { probe } => {
                if probe {
                    self.send_arp(iface, arp::OP_REQUEST, MacAddr::ZERO, next_hop, MacAddr::BROADCAST);
                }
            }
            Lookup::Dropped => self.ifaces[iface].stats.tx_dropped += 1,
        }
    }

    fn send_ip_packets(&mut self, dst: Ipv4Addr, packets: Vec<Vec<u8>>, broadcast_iface: Option<usize>) -> Result<(), NetError> {
        self.stats.ip_out += packets.len() as u64;
        if self.is_local(dst) {
            for p in packets {
                if self.loopback.len() < MAX_TX_QUEUE {
                    let lo = &mut self.ifaces[0].stats;
                    lo.tx_packets += 1;
                    lo.tx_bytes += p.len() as u64;
                    self.loopback.push_back(p);
                }
            }
            return Ok(());
        }
        let (iface, hop) = match broadcast_iface {
            Some(i) => (i, Ipv4Addr::BROADCAST),
            None => self.route(dst).ok_or(NetError::NoRoute)?,
        };
        for p in packets {
            let now = self.now;
            if broadcast_iface.is_none() && !hop.is_broadcast() {
                if let Some(mac) = self.ifaces[iface].arp.get(hop, now) {
                    let i = &self.ifaces[iface];
                    let frame = ethernet::build(mac, i.mac, ETHERTYPE_IPV4, &p);
                    self.push_frame(iface, frame);
                    continue;
                }
            }
            self.send_packet_on(iface, hop, p, broadcast_iface.is_some());
        }
        Ok(())
    }

    /// Builds and sends an IP datagram (fragmented if needed).
    fn send_ip(&mut self, src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8], df: bool) -> Result<(), NetError> {
        let mtu = if self.is_local(dst) {
            LOOPBACK_MTU
        } else {
            let (iface, _) = self.route(dst).ok_or(NetError::NoRoute)?;
            self.ifaces[iface].mtu
        };
        self.ident = self.ident.wrapping_add(1);
        let packets = ipv4::build(src, dst, proto, ipv4::DEFAULT_TTL, self.ident, payload, mtu, df).ok_or(NetError::MessageTooLong)?;
        self.send_ip_packets(dst, packets, None)
    }

    /// Limited broadcast out of one interface (DHCP before configuration).
    fn send_broadcast(&mut self, iface: usize, src: Ipv4Addr, proto: u8, payload: &[u8]) -> Result<(), NetError> {
        self.ident = self.ident.wrapping_add(1);
        let mtu = self.ifaces[iface].mtu;
        let packets =
            ipv4::build(src, Ipv4Addr::BROADCAST, proto, ipv4::DEFAULT_TTL, self.ident, payload, mtu, false).ok_or(NetError::MessageTooLong)?;
        self.send_ip_packets(Ipv4Addr::BROADCAST, packets, Some(iface))
    }

    /// Sends a DHCP renewal using only routes belonging to its interface.
    fn send_dhcp_unicast(&mut self, iface: usize, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Result<(), NetError> {
        let route = self.routes.iter()
            .filter(|r| r.iface == iface && self.ifaces[iface].link_up && dst.in_subnet(r.dest, r.prefix))
            .max_by_key(|r| r.prefix)
            .ok_or(NetError::NoRoute)?;
        let hop = route.gateway.unwrap_or(dst);
        let mtu = self.ifaces[iface].mtu;
        self.ident = self.ident.wrapping_add(1);
        let packets = ipv4::build(src, dst, PROTO_UDP, ipv4::DEFAULT_TTL, self.ident, payload, mtu, false)
            .ok_or(NetError::MessageTooLong)?;
        self.stats.ip_out += packets.len() as u64;
        for packet in packets {
            self.send_packet_on(iface, hop, packet, false);
        }
        Ok(())
    }

    fn send_icmp_error(&mut self, kind: u8, code: u8, original: &[u8], to: Ipv4Addr, from: Ipv4Addr) {
        if to.is_unspecified() || to.is_broadcast() || to.is_multicast() {
            return;
        }
        let msg = icmp::error(kind, code, original);
        self.stats.icmp_out += 1;
        let _ = self.send_ip(from, to, PROTO_ICMP, &msg, false);
    }

    // ----- receive path ---------------------------------------------------------

    /// Processes a frame received on `iface`.
    pub fn receive(&mut self, iface: usize, frame: &[u8]) {
        let Some(i) = self.ifaces.get_mut(iface) else { return };
        i.stats.rx_packets += 1;
        i.stats.rx_bytes += frame.len() as u64;
        let (h, payload) = match ethernet::parse(frame) {
            Ok(v) => v,
            Err(_) => {
                i.stats.rx_errors += 1;
                self.stats.frames_bad += 1;
                return;
            }
        };
        if !ethernet::accepts(i.mac, h.dst, false) {
            i.stats.rx_dropped += 1;
            return;
        }
        match h.ethertype {
            ETHERTYPE_ARP => self.receive_arp(iface, payload),
            ETHERTYPE_IPV4 => self.receive_ipv4(iface, payload),
            _ => self.ifaces[iface].stats.rx_dropped += 1,
        }
        self.flush();
    }

    fn receive_arp(&mut self, iface: usize, payload: &[u8]) {
        self.stats.arp_in += 1;
        let p = match arp::Packet::parse(payload) {
            Ok(p) => p,
            Err(_) => {
                self.stats.arp_bad += 1;
                return;
            }
        };
        let now = self.now;
        let own = self.ifaces[iface].addr.map(|a| a.0);
        let for_us = own == Some(p.target_ip);
        if own == Some(p.sender_ip) && p.sender_mac != self.ifaces[iface].mac {
            let line = alloc::format!("{}: address conflict: {} claimed by {}", self.ifaces[iface].name, p.sender_ip, p.sender_mac);
            self.logf(line);
            return;
        }
        let released = self.ifaces[iface].arp.learn(p.sender_ip, p.sender_mac, now, for_us);
        if !released.is_empty() {
            let mac = p.sender_mac;
            for packet in released {
                let frame = ethernet::build(mac, self.ifaces[iface].mac, ETHERTYPE_IPV4, &packet);
                self.push_frame(iface, frame);
            }
        }
        if for_us && p.op == arp::OP_REQUEST {
            self.send_arp(iface, arp::OP_REPLY, p.sender_mac, p.sender_ip, p.sender_mac);
        }
    }

    /// Processes an IP packet (from an interface or the loopback queue).
    fn receive_ipv4(&mut self, iface: usize, packet: &[u8]) {
        self.stats.ip_in += 1;
        let (h, payload) = match ipv4::parse(packet) {
            Ok(v) => v,
            Err(_) => {
                self.stats.ip_bad += 1;
                return;
            }
        };
        let i = &self.ifaces[iface];
        let unconfigured = i.addr.is_none();
        let subnet_broadcast = i.addr.is_some_and(|(a, p)| {
            h.dst.in_subnet(a, p) && h.dst.to_u32() | crate::wire::prefix_mask(p) == h.dst.to_u32()
        });
        let broadcast = h.dst.is_broadcast() || subnet_broadcast;
        let to_us = self.is_local(h.dst) && (iface == 0 || !h.dst.is_loopback());
        // While unconfigured, DHCP replies may be unicast to the offered address.
        let dhcp_unicast = unconfigured && h.protocol == PROTO_UDP;
        if !(to_us || broadcast || dhcp_unicast) {
            self.stats.ip_not_for_us += 1;
            return;
        }
        let owned;
        let (h, payload) = if h.is_fragment() {
            self.stats.ip_fragments_in += 1;
            match self.reasm.add(&h, payload, self.now) {
                Some((h, data)) => {
                    self.stats.ip_reassembled += 1;
                    owned = data;
                    (h, &owned[..])
                }
                None => return,
            }
        } else {
            (h, payload)
        };
        match h.protocol {
            PROTO_ICMP => self.receive_icmp(&h, payload, packet, broadcast),
            PROTO_UDP => self.receive_udp(iface, &h, payload, packet, broadcast),
            PROTO_TCP if !broadcast => self.receive_tcp(&h, payload),
            _ if to_us && !broadcast => {
                let quote = &packet[..h.total_len.min(packet.len())];
                self.send_icmp_error(icmp::DEST_UNREACHABLE, icmp::UNREACH_PROTOCOL, quote, h.src, h.dst);
            }
            _ => {}
        }
    }

    fn receive_icmp(&mut self, h: &ipv4::Header, payload: &[u8], _packet: &[u8], broadcast: bool) {
        self.stats.icmp_in += 1;
        let Ok(m) = icmp::parse(payload) else {
            self.stats.ip_bad += 1;
            return;
        };
        match m {
            Message::EchoRequest { ident, seq, data } if !broadcast => {
                let reply = icmp::echo(icmp::ECHO_REPLY, ident, seq, data);
                self.stats.icmp_out += 1;
                self.stats.icmp_echo_answered += 1;
                let _ = self.send_ip(h.dst, h.src, PROTO_ICMP, &reply, false);
            }
            Message::EchoReply { ident, seq, data } => {
                let ttl = h.ttl;
                let from = h.src;
                for s in self.sockets.values_mut() {
                    if let Socket::Icmp(sock) = s {
                        if sock.ident == ident {
                            sock.targets.retain(|&(a, sq)| !(a == from && sq == seq));
                            if sock.rx.len() < ICMP_QUEUE {
                                sock.rx.push_back(IcmpEvent::Reply { from, seq, ttl, data: data.to_vec() });
                                self.changed = true;
                            }
                        }
                    }
                }
            }
            Message::Unreachable { code, original } => self.icmp_error(h.src, code, original, true),
            Message::TimeExceeded { code, original } => self.icmp_error(h.src, code, original, false),
            _ => {}
        }
    }

    /// Delivers an ICMP error to the socket that sent the quoted datagram.
    fn icmp_error(&mut self, from: Ipv4Addr, code: u8, original: &[u8], unreachable: bool) {
        let Ok((oh, rest)) = ipv4::parse_quoted(original) else { return };
        let error = if !unreachable {
            NetError::HostUnreachable
        } else {
            match code {
                icmp::UNREACH_PORT => NetError::PortUnreachable,
                icmp::UNREACH_NET => NetError::NoRoute,
                icmp::UNREACH_FRAG_NEEDED => NetError::MessageTooLong,
                _ => NetError::HostUnreachable,
            }
        };
        match oh.protocol {
            PROTO_ICMP if rest.len() >= 8 && rest[0] == icmp::ECHO_REQUEST => {
                let (ident, seq) = (be16(rest, 4), be16(rest, 6));
                for s in self.sockets.values_mut() {
                    if let Socket::Icmp(sock) = s {
                        if sock.ident == ident && sock.rx.len() < ICMP_QUEUE {
                            sock.targets.retain(|&(a, sq)| !(a == oh.dst && sq == seq));
                            sock.rx.push_back(IcmpEvent::Error { from, seq, error, code });
                            self.changed = true;
                        }
                    }
                }
            }
            PROTO_UDP if rest.len() >= 4 => {
                let (sport, dport) = (be16(rest, 0), be16(rest, 2));
                for s in self.sockets.values_mut() {
                    if let Socket::Udp(u) = s {
                        if u.local.port == sport && u.remote == Some(Endpoint::new(oh.dst, dport)) {
                            u.error = Some(error);
                            self.changed = true;
                        }
                    }
                }
            }
            PROTO_TCP if rest.len() >= 4 => {
                let (sport, dport) = (be16(rest, 0), be16(rest, 2));
                for s in self.sockets.values_mut() {
                    if let Socket::Tcp(t) = s {
                        // RFC 1122 4.2.3.9: port/protocol unreachable aborts a connection attempt.
                        if t.tcb.local.port == sport
                            && t.tcb.remote == Endpoint::new(oh.dst, dport)
                            && t.tcb.state() == tcp::State::SynSent
                            && matches!(code, icmp::UNREACH_PORT | icmp::UNREACH_PROTOCOL)
                        {
                            let _ = t.tcb.abort();
                            self.changed = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn receive_udp(&mut self, iface: usize, h: &ipv4::Header, payload: &[u8], packet: &[u8], broadcast: bool) {
        self.stats.udp_in += 1;
        let (uh, data) = match udp::parse(h.src, h.dst, payload) {
            Ok(v) => v,
            Err(_) => {
                self.stats.udp_bad += 1;
                return;
            }
        };
        if uh.dst_port == dhcp::CLIENT_PORT && uh.src_port == dhcp::SERVER_PORT {
            if let Some(c) = self.ifaces[iface].dhcp.as_mut() {
                let now = self.now;
                let (tx, ev) = c.input(data, now);
                self.dhcp_output(iface, tx, ev);
                return;
            }
        }
        let from = Endpoint::new(h.src, uh.src_port);
        let mut delivered = false;
        for s in self.sockets.values_mut() {
            let Socket::Udp(u) = s else { continue };
            if u.local.port != uh.dst_port {
                continue;
            }
            if !u.local.addr.is_unspecified() && u.local.addr != h.dst && !broadcast {
                continue;
            }
            if broadcast && !u.broadcast && !u.local.addr.is_unspecified() {
                continue;
            }
            if let Some(r) = u.remote {
                if r != from {
                    continue;
                }
            }
            delivered = true;
            if u.rx.len() >= UDP_QUEUE_DATAGRAMS || u.rx_bytes + data.len() > UDP_QUEUE_BYTES {
                u.dropped += 1;
            } else {
                u.rx_bytes += data.len();
                u.rx.push_back((from, data.to_vec()));
                self.changed = true;
            }
            if !broadcast {
                break;
            }
        }
        if !delivered {
            self.stats.udp_no_port += 1;
            if !broadcast {
                let quote = &packet[..h.total_len.min(packet.len())];
                self.send_icmp_error(icmp::DEST_UNREACHABLE, icmp::UNREACH_PORT, quote, h.src, h.dst);
            }
        }
    }

    fn receive_tcp(&mut self, h: &ipv4::Header, payload: &[u8]) {
        self.stats.tcp_in += 1;
        let seg = match tcp::parse(h.src, h.dst, payload) {
            Ok(s) => s,
            Err(_) => {
                self.stats.tcp_bad += 1;
                return;
            }
        };
        let local = Endpoint::new(h.dst, seg.dst_port);
        let remote = Endpoint::new(h.src, seg.src_port);
        let now = self.now;
        let conn = self.sockets.iter_mut().find_map(|(id, s)| match s {
            Socket::Tcp(t) if t.tcb.local == local && t.tcb.remote == remote && !t.tcb.finished() => Some((*id, t)),
            _ => None,
        });
        if let Some((_, t)) = conn {
            t.tcb.input(&seg, now);
            if t.tcb.changed {
                self.changed = true;
            }
            return;
        }
        // A listener on this port?
        let listener = self.sockets.iter().find_map(|(id, s)| match s {
            Socket::Listener(l) if l.local.port == local.port && (l.local.addr.is_unspecified() || l.local.addr == local.addr) => {
                Some((*id, l.backlog))
            }
            _ => None,
        });
        if let (Some((lid, backlog)), true) = (listener, seg.has(tcp::SYN) && !seg.has(tcp::ACK) && !seg.has(tcp::RST)) {
            let queued = self.sockets.values().filter(|s| matches!(s, Socket::Tcp(t) if t.parent == Some(lid))).count();
            if queued >= backlog || self.sockets.len() >= MAX_SOCKETS {
                return; // the peer retransmits its SYN later
            }
            let iss = self.isn(local, remote);
            let mss = self.mss_for(remote.addr);
            let tcb = Tcb::accept(local, remote, &seg, iss, mss, now);
            let id = self.alloc_id();
            self.sockets.insert(id, Socket::Tcp(alloc::boxed::Box::new(TcpSocket { tcb, parent: Some(lid), released: false, accepted: false })));
            return;
        }
        if let Some(rst) = tcp::reset_for(&seg) {
            self.stats.tcp_resets_sent += 1;
            let bytes = rst.encode(local, remote);
            let _ = self.send_ip(local.addr, remote.addr, PROTO_TCP, &bytes, false);
        }
    }

    fn isn(&mut self, local: Endpoint, remote: Endpoint) -> u32 {
        // RFC 6528: a clock plus a keyed hash of the connection identity.
        let mut x = self.secret;
        for v in [local.addr.to_u32() as u64, remote.addr.to_u32() as u64, local.port as u64, remote.port as u64] {
            x ^= v;
            x = x.wrapping_mul(0x100_0000_01B3);
            x ^= x >> 29;
        }
        (self.now.wrapping_mul(250) as u32).wrapping_add(x as u32)
    }

    fn mss_for(&self, dst: Ipv4Addr) -> u16 {
        let mtu = if self.is_local(dst) {
            LOOPBACK_MTU
        } else {
            self.route(dst).map(|(i, _)| self.ifaces[i].mtu).unwrap_or(576)
        };
        (mtu - ipv4::MIN_HEADER - tcp::HEADER_LEN).min(u16::MAX as usize) as u16
    }

    // ----- timers and output -----------------------------------------------------------

    fn dhcp_output(&mut self, iface: usize, tx: Option<dhcp::Transmit>, ev: Option<dhcp::Event>) {
        if let Some(t) = tx {
            let dgram = udp::build(t.src, t.dst, dhcp::CLIENT_PORT, dhcp::SERVER_PORT, &t.payload);
            self.stats.udp_out += 1;
            let r = if t.dst.is_broadcast() {
                self.send_broadcast(iface, t.src, PROTO_UDP, &dgram)
            } else {
                self.send_dhcp_unicast(iface, t.src, t.dst, &dgram)
            };
            let _ = r;
        }
        match ev {
            Some(dhcp::Event::Bound(l)) | Some(dhcp::Event::Renewed(l)) => {
                let name = self.ifaces[iface].name.clone();
                self.set_address(iface, Some((l.addr, l.prefix)), l.router, RouteOrigin::Dhcp);
                if !self.dns_static && self.dns_servers != l.dns {
                    self.dns_servers = l.dns.clone();
                    self.dns_cache.flush();
                }
                let dns: Vec<String> = l.dns.iter().map(|d| alloc::format!("{d}")).collect();
                self.logf(alloc::format!(
                    "{}: DHCP lease {}/{} from {}, router {}, DNS [{}], {} s",
                    name,
                    l.addr,
                    l.prefix,
                    l.server,
                    l.router.map(|r| alloc::format!("{r}")).unwrap_or_else(|| "none".into()),
                    dns.join(", "),
                    l.lease_ms / 1000
                ));
                // Announce the address (gratuitous ARP).
                self.send_arp(iface, arp::OP_REQUEST, MacAddr::ZERO, l.addr, MacAddr::BROADCAST);
                self.changed = true;
            }
            Some(dhcp::Event::Lost) => {
                let name = self.ifaces[iface].name.clone();
                self.set_address(iface, None, None, RouteOrigin::Dhcp);
                if !self.dns_static {
                    self.dns_servers.clear();
                    self.dns_cache.flush();
                }
                self.logf(alloc::format!("{}: DHCP lease lost", name));
            }
            None => {}
        }
    }

    /// Runs every timer and flushes pending output.
    pub fn poll(&mut self) {
        let now = self.now;
        for iface in 0..self.ifaces.len() {
            let actions = self.ifaces[iface].arp.poll(now);
            for a in actions {
                match a {
                    arp::Action::Probe(ip) => self.send_arp(iface, arp::OP_REQUEST, MacAddr::ZERO, ip, MacAddr::BROADCAST),
                    arp::Action::Unreachable(ip, _) => self.host_unreachable(ip),
                }
            }
            if self.ifaces[iface].link_up {
                if let Some(c) = self.ifaces[iface].dhcp.as_mut() {
                    let (tx, ev) = c.poll(now);
                    self.dhcp_output(iface, tx, ev);
                }
            }
        }
        self.reasm.expire(now);
        for s in self.sockets.values_mut() {
            if let Socket::Tcp(t) = s {
                t.tcb.poll(now);
            }
        }
        self.dns_poll();
        self.flush();
    }

    fn host_unreachable(&mut self, ip: Ipv4Addr) {
        for s in self.sockets.values_mut() {
            match s {
                Socket::Icmp(sock) => {
                    let lost: Vec<u16> = sock.targets.iter().filter(|t| t.0 == ip).map(|t| t.1).collect();
                    sock.targets.retain(|t| t.0 != ip);
                    for seq in lost {
                        if sock.rx.len() < ICMP_QUEUE {
                            sock.rx.push_back(IcmpEvent::Error { from: ip, seq, error: NetError::HostUnreachable, code: icmp::UNREACH_HOST });
                            self.changed = true;
                        }
                    }
                }
                Socket::Udp(u) if u.remote.is_some_and(|r| r.addr == ip) => {
                    u.error = Some(NetError::HostUnreachable);
                    self.changed = true;
                }
                _ => {}
            }
        }
    }

    /// Delivers loopback packets, sends TCP output, promotes accepted
    /// connections and reaps finished sockets.
    fn flush(&mut self) {
        for _ in 0..4 {
            let mut rounds = 0;
            while let Some(p) = self.loopback.pop_front() {
                let lo = &mut self.ifaces[0].stats;
                lo.rx_packets += 1;
                lo.rx_bytes += p.len() as u64;
                self.receive_ipv4(0, &p);
                rounds += 1;
                if rounds > 256 {
                    break;
                }
            }
            let now = self.now;
            let mut out: Vec<(Endpoint, Endpoint, tcp::OutSegment)> = Vec::new();
            for s in self.sockets.values_mut() {
                if let Socket::Tcp(t) = s {
                    let before = t.tcb.stats.retransmits + t.tcb.stats.fast_retransmits;
                    for seg in t.tcb.output(now) {
                        out.push((t.tcb.local, t.tcb.remote, seg));
                    }
                    self.stats.tcp_retransmits += t.tcb.stats.retransmits + t.tcb.stats.fast_retransmits - before;
                    if t.tcb.changed {
                        t.tcb.changed = false;
                        self.changed = true;
                    }
                }
            }
            if out.is_empty() && self.loopback.is_empty() {
                break;
            }
            for (l, r, seg) in out {
                self.stats.tcp_out += 1;
                let bytes = seg.encode(l, r);
                let _ = self.send_ip(l.addr, r.addr, PROTO_TCP, &bytes, false);
            }
            if self.loopback.is_empty() {
                break;
            }
        }
        self.promote_accepted();
        self.reap();
    }

    fn promote_accepted(&mut self) {
        let ready: Vec<(SocketId, SocketId)> = self
            .sockets
            .iter()
            .filter_map(|(id, s)| match s {
                Socket::Tcp(t) if !t.accepted && t.tcb.connected() => t.parent.map(|p| (*id, p)),
                _ => None,
            })
            .collect();
        for (id, parent) in ready {
            if let Some(Socket::Listener(l)) = self.sockets.get_mut(&parent) {
                l.ready.push_back(id);
                self.changed = true;
            }
            if let Some(Socket::Tcp(t)) = self.sockets.get_mut(&id) {
                t.accepted = true;
            }
        }
    }

    fn reap(&mut self) {
        let dead: Vec<SocketId> = self
            .sockets
            .iter()
            .filter_map(|(id, s)| match s {
                // Released, or a half-open connection of a listener that failed.
                Socket::Tcp(t) if t.tcb.finished() && (t.released || (t.parent.is_some() && !t.accepted)) => Some(*id),
                _ => None,
            })
            .collect();
        for id in dead {
            self.sockets.remove(&id);
        }
    }

    /// Earliest time `poll` should run again.
    pub fn next_deadline(&self) -> Option<u64> {
        let mut d: Option<u64> = None;
        let mut take = |t: Option<u64>| {
            if let Some(t) = t {
                d = Some(d.map_or(t, |x| x.min(t)));
            }
        };
        for i in &self.ifaces {
            take(i.arp.next_deadline());
            if i.link_up {
                take(i.dhcp.as_ref().and_then(|c| c.next_deadline()));
            }
        }
        for s in self.sockets.values() {
            if let Socket::Tcp(t) = s {
                take(t.tcb.next_deadline());
            }
        }
        for q in self.queries.values() {
            take(Some(q.deadline));
        }
        if self.reasm.pending() > 0 {
            take(Some(self.now + 1000));
        }
        d
    }

    // ----- sockets ----------------------------------------------------------------

    fn alloc_id(&mut self) -> SocketId {
        let id = self.next_socket;
        self.next_socket = self.next_socket.wrapping_add(1).max(1);
        id
    }

    fn port_in_use(&self, port: u16, udp: bool) -> bool {
        self.sockets.values().any(|s| match s {
            Socket::Udp(u) => udp && u.local.port == port,
            Socket::Listener(l) => !udp && l.local.port == port,
            Socket::BoundTcp(local) => !udp && local.port == port,
            Socket::Tcp(t) => !udp && t.tcb.local.port == port && t.parent.is_none(),
            Socket::Icmp(_) => false,
        })
    }

    fn ephemeral(&mut self, udp: bool) -> Result<u16, NetError> {
        let span = (*EPHEMERAL.end() - *EPHEMERAL.start()) as u32 + 1;
        for _ in 0..span {
            let p = self.next_ephemeral;
            self.next_ephemeral = if p >= *EPHEMERAL.end() { *EPHEMERAL.start() } else { p + 1 };
            if !self.port_in_use(p, udp) {
                return Ok(p);
            }
        }
        Err(NetError::AddrInUse)
    }

    fn check_local(&self, addr: Ipv4Addr) -> Result<(), NetError> {
        if addr.is_unspecified() || self.is_local(addr) {
            Ok(())
        } else {
            Err(NetError::AddrNotAvailable)
        }
    }

    fn insert(&mut self, s: Socket) -> Result<SocketId, NetError> {
        if self.sockets.len() >= MAX_SOCKETS {
            return Err(NetError::NoBuffers);
        }
        let id = self.alloc_id();
        self.sockets.insert(id, s);
        Ok(id)
    }

    /// A UDP socket bound to `local` (port 0: an ephemeral port).
    pub fn udp_bind(&mut self, local: Endpoint) -> Result<SocketId, NetError> {
        self.check_local(local.addr)?;
        let port = if local.port == 0 { self.ephemeral(true)? } else { local.port };
        if local.port != 0 && self.port_in_use(port, true) {
            return Err(NetError::AddrInUse);
        }
        self.insert(Socket::Udp(UdpSocket {
            local: Endpoint::new(local.addr, port),
            remote: None,
            rx: VecDeque::new(),
            rx_bytes: 0,
            error: None,
            dropped: 0,
            broadcast: false,
        }))
    }

    fn udp(&mut self, id: SocketId) -> Result<&mut UdpSocket, NetError> {
        match self.sockets.get_mut(&id) {
            Some(Socket::Udp(u)) => Ok(u),
            _ => Err(NetError::BadSocket),
        }
    }

    /// Fixes the peer: only its datagrams are received, `udp_send` goes there.
    pub fn udp_connect(&mut self, id: SocketId, remote: Endpoint) -> Result<(), NetError> {
        if remote.port == 0 || remote.addr.is_unspecified() {
            return Err(NetError::InvalidArgument);
        }
        let u = self.udp(id)?;
        u.remote = Some(remote);
        u.error = None;
        Ok(())
    }

    pub fn udp_set_broadcast(&mut self, id: SocketId, on: bool) -> Result<(), NetError> {
        self.udp(id)?.broadcast = on;
        Ok(())
    }

    pub fn udp_send_to(&mut self, id: SocketId, to: Option<Endpoint>, data: &[u8]) -> Result<usize, NetError> {
        if data.len() > MAX_UDP_PAYLOAD {
            return Err(NetError::MessageTooLong);
        }
        let (local, remote, broadcast) = {
            let u = self.udp(id)?;
            if let Some(e) = u.error.take() {
                return Err(e);
            }
            let remote = to.or(u.remote).ok_or(NetError::NotConnected)?;
            (u.local, remote, u.broadcast)
        };
        if remote.port == 0 {
            return Err(NetError::InvalidArgument);
        }
        if remote.addr.is_broadcast() && !broadcast {
            return Err(NetError::InvalidArgument);
        }
        let src = if local.addr.is_unspecified() {
            if remote.addr.is_broadcast() {
                self.ifaces.iter().find(|i| i.kind == IfaceKind::Ethernet).and_then(|i| i.addr).map(|a| a.0).unwrap_or_default()
            } else {
                self.source_for(remote.addr).ok_or(NetError::NoRoute)?
            }
        } else {
            local.addr
        };
        let dgram = udp::build(src, remote.addr, local.port, remote.port, data);
        self.stats.udp_out += 1;
        if remote.addr.is_broadcast() {
            let iface = self.ifaces.iter().position(|i| i.kind == IfaceKind::Ethernet && i.link_up).ok_or(NetError::NoRoute)?;
            self.send_broadcast(iface, src, PROTO_UDP, &dgram)?;
        } else {
            self.send_ip(src, remote.addr, PROTO_UDP, &dgram, false)?;
        }
        self.flush();
        Ok(data.len())
    }

    /// The next datagram: (sender, bytes copied); a datagram longer than
    /// `buf` is truncated (the rest is discarded).
    pub fn udp_recv_from(&mut self, id: SocketId, buf: &mut [u8]) -> Result<(Endpoint, usize, usize), NetError> {
        let u = self.udp(id)?;
        if let Some((from, d)) = u.rx.pop_front() {
            u.rx_bytes -= d.len();
            let n = d.len().min(buf.len());
            buf[..n].copy_from_slice(&d[..n]);
            return Ok((from, n, d.len()));
        }
        if let Some(e) = u.error.take() {
            return Err(e);
        }
        Err(NetError::WouldBlock)
    }

    pub fn udp_local(&mut self, id: SocketId) -> Result<Endpoint, NetError> {
        Ok(self.udp(id)?.local)
    }

    /// An ICMP echo socket (like a Linux "ping socket"): it sends echo
    /// requests with its own identifier and receives the matching replies
    /// and errors.
    pub fn icmp_open(&mut self) -> Result<SocketId, NetError> {
        let mut ident = self.rand() as u16;
        while self.sockets.values().any(|s| matches!(s, Socket::Icmp(i) if i.ident == ident)) {
            ident = ident.wrapping_add(1);
        }
        self.insert(Socket::Icmp(IcmpSocket { ident, rx: VecDeque::new(), targets: Vec::new() }))
    }

    pub fn icmp_ident(&self, id: SocketId) -> Result<u16, NetError> {
        match self.sockets.get(&id) {
            Some(Socket::Icmp(i)) => Ok(i.ident),
            _ => Err(NetError::BadSocket),
        }
    }

    pub fn icmp_echo(&mut self, id: SocketId, to: Ipv4Addr, seq: u16, data: &[u8]) -> Result<(), NetError> {
        if data.len() > 65_000 {
            return Err(NetError::MessageTooLong);
        }
        let ident = match self.sockets.get_mut(&id) {
            Some(Socket::Icmp(i)) => {
                if i.targets.len() >= 64 {
                    i.targets.remove(0);
                }
                i.targets.push((to, seq));
                i.ident
            }
            _ => return Err(NetError::BadSocket),
        };
        let src = self.source_for(to).ok_or(NetError::NoRoute)?;
        let msg = icmp::echo(icmp::ECHO_REQUEST, ident, seq, data);
        self.stats.icmp_out += 1;
        self.send_ip(src, to, PROTO_ICMP, &msg, false)?;
        self.flush();
        Ok(())
    }

    pub fn icmp_recv(&mut self, id: SocketId) -> Result<IcmpEvent, NetError> {
        match self.sockets.get_mut(&id) {
            Some(Socket::Icmp(i)) => i.rx.pop_front().ok_or(NetError::WouldBlock),
            _ => Err(NetError::BadSocket),
        }
    }

    /// Reserves the local endpoint immediately, including a dynamic port.
    /// The reservation survives until listen, connect or close.
    pub fn tcp_bind(&mut self, local: Endpoint) -> Result<SocketId, NetError> {
        self.check_local(local.addr)?;
        let port = if local.port == 0 { self.ephemeral(false)? } else { local.port };
        if self.port_in_use(port, false) {
            return Err(NetError::AddrInUse);
        }
        self.insert(Socket::BoundTcp(Endpoint::new(local.addr, port)))
    }

    pub fn tcp_bound_local(&self, id: SocketId) -> Result<Endpoint, NetError> {
        match self.sockets.get(&id) {
            Some(Socket::BoundTcp(local)) => Ok(*local),
            _ => Err(NetError::BadSocket),
        }
    }

    pub fn tcp_listen_bound(&mut self, id: SocketId, backlog: usize) -> Result<(), NetError> {
        let local = self.tcp_bound_local(id)?;
        self.sockets.insert(id, Socket::Listener(Listener { local, backlog: backlog.clamp(1, MAX_BACKLOG), ready: VecDeque::new() }));
        Ok(())
    }

    pub fn tcp_listen(&mut self, local: Endpoint, backlog: usize) -> Result<SocketId, NetError> {
        let id = self.tcp_bind(local)?;
        self.tcp_listen_bound(id, backlog)?;
        Ok(id)
    }

    /// Starts a connection; it completes asynchronously (see `tcp_state`).
    pub fn tcp_connect(&mut self, local: Option<Endpoint>, remote: Endpoint) -> Result<SocketId, NetError> {
        self.tcp_connect_inner(None, local, remote)
    }

    pub fn tcp_connect_bound(&mut self, id: SocketId, remote: Endpoint) -> Result<SocketId, NetError> {
        let local = self.tcp_bound_local(id)?;
        self.tcp_connect_inner(Some(id), Some(local), remote)
    }

    fn tcp_connect_inner(&mut self, bound: Option<SocketId>, local: Option<Endpoint>, remote: Endpoint) -> Result<SocketId, NetError> {
        if remote.port == 0 || remote.addr.is_unspecified() || remote.addr.is_broadcast() || remote.addr.is_multicast() {
            return Err(NetError::InvalidArgument);
        }
        let src = match local {
            Some(l) if !l.addr.is_unspecified() => {
                self.check_local(l.addr)?;
                l.addr
            }
            _ => self.source_for(remote.addr).ok_or(NetError::NoRoute)?,
        };
        let port = match local {
            Some(l) if l.port != 0 => {
                if bound.is_none() && self.port_in_use(l.port, false) {
                    return Err(NetError::AddrInUse);
                }
                l.port
            }
            _ => self.ephemeral(false)?,
        };
        let l = Endpoint::new(src, port);
        let iss = self.isn(l, remote);
        let mss = self.mss_for(remote.addr);
        let tcb = Tcb::connect(l, remote, iss, mss);
        let socket = Socket::Tcp(alloc::boxed::Box::new(TcpSocket { tcb, parent: None, released: false, accepted: true }));
        let id = match bound {
            Some(id) => { self.sockets.insert(id, socket); id }
            None => self.insert(socket)?,
        };
        self.flush();
        Ok(id)
    }

    /// The next established connection of a listener.
    pub fn tcp_accept(&mut self, id: SocketId) -> Result<(SocketId, Endpoint), NetError> {
        let next = match self.sockets.get_mut(&id) {
            Some(Socket::Listener(l)) => l.ready.pop_front().ok_or(NetError::WouldBlock)?,
            _ => return Err(NetError::BadSocket),
        };
        match self.sockets.get_mut(&next) {
            Some(Socket::Tcp(t)) => {
                t.parent = None;
                Ok((next, t.tcb.remote))
            }
            _ => Err(NetError::WouldBlock),
        }
    }

    fn tcb(&mut self, id: SocketId) -> Result<&mut Tcb, NetError> {
        match self.sockets.get_mut(&id) {
            Some(Socket::Tcp(t)) => Ok(&mut t.tcb),
            Some(Socket::BoundTcp(_)) => Err(NetError::NotConnected),
            _ => Err(NetError::BadSocket),
        }
    }

    /// (state, connected, error) of a connection.
    pub fn tcp_state(&mut self, id: SocketId) -> Result<(tcp::State, Option<NetError>), NetError> {
        let t = self.tcb(id)?;
        Ok((t.state(), t.error().map(tcp_error)))
    }

    pub fn tcp_send(&mut self, id: SocketId, data: &[u8]) -> Result<usize, NetError> {
        let n = self.tcb(id)?.send(data).map_err(tcp_error)?;
        self.flush();
        Ok(n)
    }

    pub fn tcp_recv(&mut self, id: SocketId, buf: &mut [u8]) -> Result<usize, NetError> {
        let n = self.tcb(id)?.recv(buf).map_err(tcp_error)?;
        self.flush(); // window updates
        Ok(n)
    }

    /// Half-close: no more data from us (a FIN follows the queued data).
    pub fn tcp_shutdown(&mut self, id: SocketId) -> Result<(), NetError> {
        self.tcb(id)?.close();
        self.flush();
        Ok(())
    }

    pub fn tcp_endpoints(&mut self, id: SocketId) -> Result<(Endpoint, Endpoint), NetError> {
        let t = self.tcb(id)?;
        Ok((t.local, t.remote))
    }

    pub fn listener_local(&self, id: SocketId) -> Result<Endpoint, NetError> {
        match self.sockets.get(&id) {
            Some(Socket::Listener(l)) => Ok(l.local),
            _ => Err(NetError::BadSocket),
        }
    }

    /// Readiness of a socket: (readable, writable, hang-up).
    pub fn poll_socket(&self, id: SocketId) -> (bool, bool, bool) {
        match self.sockets.get(&id) {
            Some(Socket::Udp(u)) => (!u.rx.is_empty() || u.error.is_some(), true, false),
            Some(Socket::Icmp(i)) => (!i.rx.is_empty(), true, false),
            Some(Socket::Listener(l)) => (!l.ready.is_empty(), false, false),
            Some(Socket::BoundTcp(_)) => (false, false, false),
            Some(Socket::Tcp(t)) => {
                let s = t.tcb.state();
                let hup = t.tcb.error().is_some() || s == tcp::State::Closed;
                (t.tcb.readable(), t.tcb.writable(), hup)
            }
            None => (false, false, true),
        }
    }

    /// The application released the socket. TCP connections finish
    /// gracefully (FIN, then TIME-WAIT) before they disappear; `abort`
    /// sends a reset instead.
    pub fn close(&mut self, id: SocketId, abort: bool) {
        let mut rst = None;
        let mut remove = false;
        let mut children = Vec::new();
        match self.sockets.get_mut(&id) {
            Some(Socket::Tcp(t)) => {
                if abort {
                    rst = t.tcb.abort().map(|s| (t.tcb.local, t.tcb.remote, s));
                } else {
                    // Unread data at close: RFC 2525 says reset.
                    if t.tcb.recv_queue() > 0 {
                        rst = t.tcb.abort().map(|s| (t.tcb.local, t.tcb.remote, s));
                    } else {
                        t.tcb.close();
                    }
                }
                t.released = true;
            }
            Some(Socket::Listener(l)) => {
                children.extend(l.ready.iter().copied());
                remove = true;
            }
            Some(_) => remove = true,
            None => {}
        }
        if remove {
            self.sockets.remove(&id);
            // Connections not yet accepted are reset.
            let pending: Vec<SocketId> =
                self.sockets.iter().filter(|(_, s)| matches!(s, Socket::Tcp(t) if t.parent == Some(id))).map(|(i, _)| *i).collect();
            children.extend(pending);
            for c in children {
                let mut rst = None;
                if let Some(Socket::Tcp(t)) = self.sockets.get_mut(&c) {
                    rst = t.tcb.abort().map(|s| (t.tcb.local, t.tcb.remote, s));
                    t.released = true;
                }
                if let Some((l, r, s)) = rst {
                    let bytes = s.encode(l, r);
                    let _ = self.send_ip(l.addr, r.addr, PROTO_TCP, &bytes, false);
                }
            }
        }
        if let Some((l, r, s)) = rst {
            self.stats.tcp_resets_sent += 1;
            let bytes = s.encode(l, r);
            let _ = self.send_ip(l.addr, r.addr, PROTO_TCP, &bytes, false);
        }
        self.flush();
    }

    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }

    /// TEMP: flow-control snapshot of every TCP connection with data in or
    /// out, for the periodic stats.
    pub fn tcp_snapshot(&self) -> Vec<String> {
        self.sockets
            .iter()
            .filter_map(|(id, s)| match s {
                Socket::Tcp(t) if t.tcb.stats.bytes_in > 0 || t.tcb.stats.bytes_out > 0 => {
                    Some(alloc::format!("{}@{} {}", id, t.tcb.remote.addr, t.tcb.debug_line()))
                }
                _ => None,
            })
            .collect()
    }

    /// Every socket (for `netstat`).
    pub fn sockets(&self) -> Vec<SocketInfo> {
        self.sockets
            .iter()
            .map(|(id, s)| {
                let internal = self.internal.contains(id);
                match s {
                    Socket::BoundTcp(local) => SocketInfo {
                        id: *id, kind: "tcp", local: *local, remote: None,
                        state: "BOUND", rx_queue: 0, tx_queue: 0, internal,
                    },
                    Socket::Udp(u) => SocketInfo {
                        id: *id,
                        kind: "udp",
                        local: u.local,
                        remote: u.remote,
                        state: if u.remote.is_some() { "CONNECTED" } else { "BOUND" },
                        rx_queue: u.rx_bytes,
                        tx_queue: 0,
                        internal,
                    },
                    Socket::Icmp(i) => SocketInfo {
                        id: *id,
                        kind: "icmp",
                        local: Endpoint::new(Ipv4Addr::UNSPECIFIED, i.ident),
                        remote: None,
                        state: "ECHO",
                        rx_queue: i.rx.len(),
                        tx_queue: 0,
                        internal,
                    },
                    Socket::Listener(l) => SocketInfo {
                        id: *id,
                        kind: "tcp",
                        local: l.local,
                        remote: None,
                        state: "LISTEN",
                        rx_queue: l.ready.len(),
                        tx_queue: 0,
                        internal,
                    },
                    Socket::Tcp(t) => SocketInfo {
                        id: *id,
                        kind: "tcp",
                        local: t.tcb.local,
                        remote: Some(t.tcb.remote),
                        state: t.tcb.state().name(),
                        rx_queue: t.tcb.recv_queue(),
                        tx_queue: t.tcb.send_queue(),
                        internal,
                    },
                }
            })
            .collect()
    }

    /// RTO, SRTT and congestion window of a connection (diagnostics).
    pub fn tcp_info(&mut self, id: SocketId) -> Result<(u64, Option<u64>, u32, tcp::Stats), NetError> {
        let t = self.tcb(id)?;
        Ok((t.rto_ms(), t.srtt_ms(), t.cwnd(), t.stats))
    }

    // ----- DNS ------------------------------------------------------------------------

    /// Starts resolving `name` to IPv4 addresses. Dotted quads, `localhost`
    /// and cached names complete at once.
    pub fn resolve(&mut self, name: &str) -> Resolve {
        if let Some(a) = Ipv4Addr::parse(name) {
            return Resolve::Done(Ok(alloc::vec![a]));
        }
        let Some(n) = dns::normalize(name) else { return Resolve::Done(Err(NetError::InvalidArgument)) };
        if n == "localhost" || n.ends_with(".localhost") {
            return Resolve::Done(Ok(alloc::vec![Ipv4Addr::LOOPBACK]));
        }
        if n == self.hostname {
            let own = self.ifaces.iter().skip(1).find_map(|i| i.addr).map(|a| a.0).unwrap_or(Ipv4Addr::LOOPBACK);
            return Resolve::Done(Ok(alloc::vec![own]));
        }
        let now = self.now;
        if let Some(addrs) = self.dns_cache.get(&n, now) {
            return Resolve::Done(if addrs.is_empty() { Err(NetError::NameNotFound) } else { Ok(addrs) });
        }
        if self.dns_servers.is_empty() {
            return Resolve::Done(Err(NetError::DnsFailure));
        }
        if self.queries.len() >= MAX_QUERIES {
            return Resolve::Done(Err(NetError::NoBuffers));
        }
        // Share an outstanding query for the same name.
        if let Some((qid, _)) = self.queries.iter().find(|(_, q)| q.name == n) {
            return Resolve::Pending(*qid);
        }
        let qid = self.next_query;
        self.next_query = self.next_query.wrapping_add(1).max(1);
        let id = self.rand() as u16;
        let q = Query {
            id,
            name: n,
            server: 0,
            attempt: 0,
            deadline: 0,
            transport: Transport::Udp(0),
            reply: Vec::new(),
            server_addr: Ipv4Addr::UNSPECIFIED,
        };
        self.queries.insert(qid, q);
        self.dns_send(qid);
        self.flush();
        Resolve::Pending(qid)
    }

    /// Takes the result of a query started by `resolve`.
    pub fn resolve_result(&mut self, qid: QueryId) -> Option<Result<Vec<Ipv4Addr>, NetError>> {
        if self.queries.contains_key(&qid) {
            return None;
        }
        Some(self.results.remove(&qid).unwrap_or(Err(NetError::DnsFailure)))
    }

    /// Forgets a query whose caller gave up.
    pub fn resolve_cancel(&mut self, qid: QueryId) {
        self.results.remove(&qid);
        if let Some(q) = self.queries.remove(&qid) {
            self.drop_transport(q.transport);
        }
    }

    fn drop_transport(&mut self, t: Transport) {
        let id = match t {
            Transport::Udp(id) | Transport::Tcp(id) => id,
        };
        if id != 0 {
            self.internal.retain(|&i| i != id);
            self.close(id, matches!(t, Transport::Tcp(_)));
        }
    }

    /// (Re)sends a query over UDP to its current server.
    fn dns_send(&mut self, qid: QueryId) {
        let Some(q) = self.queries.get(&qid) else { return };
        let servers = self.dns_servers.len();
        if servers == 0 || q.server >= servers {
            self.finish_query(qid, Err(NetError::TimedOut));
            return;
        }
        let old = q.transport;
        self.drop_transport(old);
        let server = self.dns_servers[self.queries[&qid].server];
        // A fresh random source port for every attempt (RFC 5452).
        let sock = match self.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)) {
            Ok(s) => s,
            Err(e) => {
                self.finish_query(qid, Err(e));
                return;
            }
        };
        self.internal.push(sock);
        let now = self.now;
        let q = self.queries.get_mut(&qid).expect("query exists");
        q.id = q.id.wrapping_mul(31).wrapping_add(qid as u16).wrapping_add(q.attempt as u16 * 7919);
        q.transport = Transport::Udp(sock);
        q.deadline = now + DNS_TIMEOUT_MS;
        q.server_addr = server;
        let msg = dns::build_query(q.id, &q.name, dns::TYPE_A);
        self.stats.dns_queries += 1;
        if self.udp_send_to(sock, Some(Endpoint::new(server, dns::PORT)), &msg).is_err() {
            // No route yet: the timeout moves on to the next attempt.
        }
    }

    fn finish_query(&mut self, qid: QueryId, r: Result<Vec<Ipv4Addr>, NetError>) {
        if let Some(q) = self.queries.remove(&qid) {
            self.drop_transport(q.transport);
            if self.results.len() > 64 {
                if let Some(&k) = self.results.keys().next() {
                    self.results.remove(&k);
                }
            }
            self.results.insert(qid, r);
            self.dns_changed = true;
        }
    }

    /// Handles a reply message for `qid`; returns true when the query ended.
    fn dns_reply(&mut self, qid: QueryId, msg: &[u8], over_tcp: bool) -> bool {
        let now = self.now;
        let (id, name) = {
            let q = &self.queries[&qid];
            (q.id, q.name.clone())
        };
        let r = match dns::parse_response(msg, id, &name, dns::TYPE_A) {
            Ok(r) => r,
            Err(_) => {
                self.stats.dns_rejected += 1;
                return false;
            }
        };
        if r.truncated && !over_tcp {
            // Retry the same server over TCP.
            let server = self.queries[&qid].server_addr;
            let old = self.queries[&qid].transport;
            self.drop_transport(old);
            match self.tcp_connect(None, Endpoint::new(server, dns::PORT)) {
                Ok(c) => {
                    self.internal.push(c);
                    let mut framed = Vec::new();
                    let m = dns::build_query(id, &name, dns::TYPE_A);
                    framed.extend_from_slice(&(m.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&m);
                    let _ = self.tcp_send(c, &framed);
                    let q = self.queries.get_mut(&qid).expect("query exists");
                    q.transport = Transport::Tcp(c);
                    q.reply.clear();
                    q.deadline = now + 2 * DNS_TIMEOUT_MS;
                }
                Err(e) => self.finish_query(qid, Err(e)),
            }
            return false;
        }
        match r.rcode {
            dns::RCODE_OK => match dns::chase(&name, &r.answers) {
                Ok(Some(a)) => {
                    self.dns_cache.put(&name, a.addrs.clone(), a.ttl, now);
                    self.finish_query(qid, Ok(a.addrs));
                }
                Ok(None) => {
                    let ttl = r.negative_ttl.unwrap_or(dns::NEGATIVE_TTL);
                    self.dns_cache.put(&name, Vec::new(), ttl, now);
                    self.finish_query(qid, Err(NetError::NameNotFound));
                }
                Err(_) => self.finish_query(qid, Err(NetError::DnsFailure)),
            },
            dns::RCODE_NXDOMAIN => {
                let ttl = r.negative_ttl.unwrap_or(dns::NEGATIVE_TTL);
                self.dns_cache.put(&name, Vec::new(), ttl, now);
                self.finish_query(qid, Err(NetError::NameNotFound));
            }
            _ => {
                // Server failure or refusal: try the next server.
                let q = self.queries.get_mut(&qid).expect("query exists");
                q.server += 1;
                q.attempt = 0;
                self.dns_send(qid);
                return !self.queries.contains_key(&qid);
            }
        }
        true
    }

    fn dns_poll(&mut self) {
        let now = self.now;
        let ids: Vec<QueryId> = self.queries.keys().copied().collect();
        for qid in ids {
            let Some(q) = self.queries.get(&qid) else { continue };
            match q.transport {
                Transport::Udp(sock) if sock != 0 => {
                    let mut buf = [0u8; dns::MAX_UDP];
                    let server = q.server_addr;
                    let mut ended = false;
                    while let Ok((from, n, _)) = self.udp_recv_from(sock, &mut buf) {
                        // Only the server we asked, from port 53.
                        if from != Endpoint::new(server, dns::PORT) {
                            self.stats.dns_rejected += 1;
                            continue;
                        }
                        if self.dns_reply(qid, &buf[..n], false) {
                            ended = true;
                            break;
                        }
                        if !matches!(self.queries.get(&qid).map(|q| q.transport), Some(Transport::Udp(s)) if s == sock) {
                            break;
                        }
                    }
                    if ended {
                        continue;
                    }
                }
                Transport::Tcp(c) => {
                    let mut buf = [0u8; 2048];
                    loop {
                        match self.tcp_recv(c, &mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let q = self.queries.get_mut(&qid).expect("query exists");
                                if q.reply.len() + n > 65_537 {
                                    break;
                                }
                                q.reply.extend_from_slice(&buf[..n]);
                            }
                            Err(_) => break,
                        }
                    }
                    let q = &self.queries[&qid];
                    if q.reply.len() >= 2 {
                        let len = be16(&q.reply, 0) as usize;
                        if q.reply.len() >= 2 + len {
                            let msg = q.reply[2..2 + len].to_vec();
                            if !self.dns_reply(qid, &msg, true) && self.queries.contains_key(&qid) {
                                self.finish_query(qid, Err(NetError::DnsFailure));
                            }
                            continue;
                        }
                    }
                }
                _ => {}
            }
            let Some(q) = self.queries.get_mut(&qid) else { continue };
            if now >= q.deadline {
                q.attempt += 1;
                if q.attempt >= DNS_ATTEMPTS {
                    q.attempt = 0;
                    q.server += 1;
                }
                self.dns_send(qid);
            }
        }
    }
}
