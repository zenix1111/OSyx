//! Structures of the ABI v8 network system calls (`nr::SOCKET` ..
//! `nr::NET_CONFIG`). All are `repr(C)` without padding; addresses are in
//! network byte order, ports in host order.

/// Socket kinds for `socket`.
pub const SOCK_STREAM: u64 = 1;
pub const SOCK_DGRAM: u64 = 2;
/// ICMP echo ("ping") socket: `send` with `SockAddr::port` = sequence
/// number sends an echo request; `recv` returns a reply's payload with the
/// sender, sequence number and TTL, or the error an ICMP message reported.
pub const SOCK_PING: u64 = 3;

/// `send`/`recv` flags.
pub const MSG_DONTWAIT: u64 = 1;
/// `recv`: return data but leave it queued (ping sockets: not supported).
pub const MSG_PEEK: u64 = 2;

/// `sock_ctl` operations.
pub mod ctl {
    /// arg 1: calls fail with `WouldBlock` instead of waiting.
    pub const NONBLOCK: u64 = 1;
    /// arg: nanoseconds a blocking receive waits (0 = forever).
    pub const RECV_TIMEOUT: u64 = 2;
    pub const SEND_TIMEOUT: u64 = 3;
    /// arg 1: allow sending to 255.255.255.255 (UDP).
    pub const BROADCAST: u64 = 4;
    /// TCP: no more data from us (FIN after queued data).
    pub const SHUTDOWN_WRITE: u64 = 5;
    /// arg: `*mut SockAddr` for the local address.
    pub const LOCAL_ADDR: u64 = 6;
    /// arg: `*mut SockAddr` for the peer.
    pub const PEER_ADDR: u64 = 7;
    /// Returns the TCP state (`TCP_*`).
    pub const STATE: u64 = 8;
    /// arg 1: closing the handle resets the connection instead of a FIN.
    pub const RESET_ON_CLOSE: u64 = 9;
    /// arg: connect timeout in nanoseconds (0 = the TCP default).
    pub const CONNECT_TIMEOUT: u64 = 10;
    /// Pending connection error as an `Errno` number (0 = none): the SYN
    /// failed after a non-blocking `connect` returned `WouldBlock`.
    pub const ERROR: u64 = 11;
    /// Bytes ready to read without blocking: queued TCP data or the size
    /// of the next UDP datagram (0 if none). Winsock FIONREAD.
    pub const AVAILABLE: u64 = 12;
}

/// TCP states reported by `ctl::STATE` and `NetSocket::state`.
pub const TCP_STATE_NAMES: [&str; 11] = [
    "CLOSED",
    "LISTEN",
    "SYN-SENT",
    "SYN-RECEIVED",
    "ESTABLISHED",
    "FIN-WAIT-1",
    "FIN-WAIT-2",
    "CLOSE-WAIT",
    "CLOSING",
    "LAST-ACK",
    "TIME-WAIT",
];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockAddr {
    pub addr: [u8; 4],
    pub port: u16,
    /// `recv` on a ping socket: TTL of the reply.
    pub ttl: u8,
    pub reserved: u8,
}

impl SockAddr {
    pub const fn new(addr: [u8; 4], port: u16) -> SockAddr {
        SockAddr { addr, port, ttl: 0, reserved: 0 }
    }
}

/// `net_query` kinds.
pub mod query {
    /// `[NetIface]`
    pub const IFACES: u64 = 1;
    /// `[NetRoute]`
    pub const ROUTES: u64 = 2;
    /// `[NetArp]`
    pub const ARP: u64 = 3;
    /// `[NetSocket]`
    pub const SOCKETS: u64 = 4;
    /// One `NetStats`.
    pub const STATS: u64 = 5;
    /// `[NetDnsEntry]` of the resolver cache.
    pub const DNS_CACHE: u64 = 6;
    /// `[[u8; 4]]` DNS servers in use.
    pub const DNS_SERVERS: u64 = 7;
}

/// `NetIface::flags`
pub const IFF_UP: u16 = 1;
pub const IFF_LINK: u16 = 2;
pub const IFF_LOOPBACK: u16 = 4;
pub const IFF_INTERRUPTS: u16 = 8;
/// Interface is wireless, even if it carries Ethernet frames.
pub const IFF_WIRELESS: u16 = 16;

/// `NetIface::method` / `NetConfig::method`
pub const CONFIG_NONE: u8 = 0;
pub const CONFIG_STATIC: u8 = 1;
pub const CONFIG_DHCP: u8 = 2;
/// `NetConfig::method`: remove the address.
pub const CONFIG_DOWN: u8 = 3;

/// DHCP client phases in `NetIface::dhcp_phase`.
pub const DHCP_PHASE_NAMES: [&str; 8] = ["-", "init", "selecting", "requesting", "bound", "renewing", "rebinding", "stopped"];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetIface {
    /// NUL-padded.
    pub name: [u8; 16],
    pub mac: [u8; 6],
    pub flags: u16,
    pub addr: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
    pub prefix: u8,
    pub method: u8,
    pub dhcp_phase: u8,
    pub index: u8,
    pub mtu: u32,
    pub interrupts: u32,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_dropped: u64,
    pub rx_errors: u64,
    pub tx_dropped: u64,
    /// Seconds until the DHCP lease expires (0 without one).
    pub lease_left: u64,
}

/// Select a wired interface, preferring one with an address or active link.
pub fn preferred_ethernet(ifaces: &[NetIface]) -> Option<NetIface> {
    ifaces.iter().filter(|i| i.flags & (IFF_LOOPBACK | IFF_WIRELESS) == 0)
        .max_by_key(|i| (i.flags & IFF_LINK != 0 && i.addr != [0; 4], i.flags & IFF_LINK != 0, core::cmp::Reverse(i.index)))
        .copied()
}

#[cfg(test)]
mod ethernet_selection_tests {
    use super::*;

    #[test]
    fn prefers_connected_wired_adapter_over_wifi_and_disconnected_ports() {
        let wifi = NetIface { index: 1, flags: IFF_WIRELESS | IFF_LINK, addr: [10, 0, 0, 2], ..Default::default() };
        let unplugged = NetIface { index: 2, ..Default::default() };
        let wired = NetIface { index: 3, flags: IFF_LINK, addr: [10, 0, 0, 3], ..Default::default() };
        assert_eq!(preferred_ethernet(&[wifi, unplugged, wired]).unwrap().index, 3);
        assert_eq!(preferred_ethernet(&[wifi, unplugged]).unwrap().index, 2);
        assert!(preferred_ethernet(&[wifi]).is_none());
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetRoute {
    pub dest: [u8; 4],
    /// All zero: directly connected.
    pub gateway: [u8; 4],
    pub prefix: u8,
    pub iface: u8,
    /// 0 connected, 1 static, 2 DHCP.
    pub origin: u8,
    pub reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetArp {
    pub addr: [u8; 4],
    pub mac: [u8; 6],
    pub iface: u8,
    /// 0 while the request is outstanding.
    pub resolved: u8,
    /// Milliseconds until expiry (or the next probe).
    pub expires_ms: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetSocket {
    /// "tcp", "udp" or "icmp", NUL-padded.
    pub kind: [u8; 8],
    /// State name, NUL-padded.
    pub state: [u8; 16],
    pub local: SockAddr,
    /// All zero when not connected.
    pub remote: SockAddr,
    pub rx_queue: u32,
    pub tx_queue: u32,
    /// 1: owned by the kernel (the DNS resolver).
    pub internal: u32,
    pub reserved: u32,
}

/// Number of counters in `NetStats`.
pub const NET_STATS: usize = 28;
/// Names of the `NetStats::counters`, in order.
pub const NET_STAT_NAMES: [&str; NET_STATS] = [
    "ip_in",
    "ip_out",
    "ip_bad",
    "ip_fragments_in",
    "ip_reassembled",
    "ip_not_for_us",
    "icmp_in",
    "icmp_out",
    "icmp_echo_answered",
    "udp_in",
    "udp_out",
    "udp_bad",
    "udp_no_port",
    "tcp_in",
    "tcp_out",
    "tcp_bad",
    "tcp_resets_sent",
    "tcp_retransmits",
    "arp_in",
    "arp_out",
    "arp_bad",
    "frames_bad",
    "dns_queries",
    "dns_rejected",
    "dns_cache_hits",
    "dns_cache_misses",
    "nic_interrupts",
    "sockets",
];

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetStats {
    pub counters: [u64; NET_STATS],
}

impl Default for NetStats {
    fn default() -> Self {
        NetStats { counters: [0; NET_STATS] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetDnsEntry {
    /// NUL-padded (cut at 64 bytes).
    pub name: [u8; 64],
    /// First address (all zero for a cached "does not exist").
    pub addr: [u8; 4],
    pub count: u32,
    pub ttl_left: u32,
    pub reserved: u32,
}

impl Default for NetDnsEntry {
    fn default() -> Self {
        NetDnsEntry { name: [0; 64], addr: [0; 4], count: 0, ttl_left: 0, reserved: 0 }
    }
}

/// Argument block of `net_config` (root only).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetConfig {
    /// Interface index (`NetIface::index`).
    pub iface: u32,
    /// `CONFIG_STATIC`, `CONFIG_DHCP` or `CONFIG_DOWN`.
    pub method: u32,
    pub addr: [u8; 4],
    /// All zero: no default route.
    pub gateway: [u8; 4],
    pub dns: [[u8; 4]; 2],
    pub prefix: u8,
    /// DNS servers given (0 keeps the current ones).
    pub dns_count: u8,
    pub reserved: [u8; 2],
}

/// Most addresses `resolve` returns.
pub const MAX_RESOLVE: usize = 16;
