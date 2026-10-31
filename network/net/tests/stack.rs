//! Two stacks talking over a simulated link: ARP, ping, UDP, TCP under
//! loss and reordering, DHCP and DNS against test servers.

mod common;

use common::*;
use osyx_net::stack::{IcmpEvent, NetError, Resolve};
use osyx_net::tcp::State;
use osyx_net::wire::{Endpoint, Ipv4Addr};
use osyx_net::{dhcp, dns};

#[test]
fn arp_resolves_and_ping_gets_a_reply() {
    let mut n = Net::new();
    let s = n.a.icmp_open().unwrap();
    n.a.icmp_echo(s, B_IP, 1, b"hello").unwrap();
    assert!(n.run_until(100, |n| matches!(n.a.icmp_recv(s), Ok(IcmpEvent::Reply { from, seq: 1, ref data, .. }) if from == B_IP && data == b"hello")));
    // Both sides learnt each other.
    assert!(n.a.arp_entries(1).iter().any(|e| e.0 == B_IP && e.1 == Some(B_MAC)));
    assert!(n.b.arp_entries(1).iter().any(|e| e.0 == A_IP && e.1 == Some(A_MAC)));
    assert_eq!(n.b.stats.icmp_echo_answered, 1);
    // A second ping needs no ARP.
    let before = n.a.stats.arp_out;
    n.a.icmp_echo(s, B_IP, 2, b"again").unwrap();
    assert!(n.run_until(100, |n| matches!(n.a.icmp_recv(s), Ok(IcmpEvent::Reply { seq: 2, .. }))));
    assert_eq!(n.a.stats.arp_out, before);
}

#[test]
fn ping_to_a_missing_host_reports_unreachable() {
    let mut n = Net::new();
    let s = n.a.icmp_open().unwrap();
    n.a.icmp_echo(s, Ipv4Addr::new(10, 0, 0, 99), 5, b"anyone?").unwrap();
    let mut got = None;
    assert!(n.run_until(10_000, |n| {
        if let Ok(e) = n.a.icmp_recv(s) {
            got = Some(e);
        }
        got.is_some()
    }));
    assert!(matches!(got, Some(IcmpEvent::Error { error: NetError::HostUnreachable, seq: 5, .. })), "{got:?}");
    // Off-subnet without a gateway: no route.
    assert_eq!(n.a.icmp_echo(s, Ipv4Addr::new(8, 8, 8, 8), 1, b""), Err(NetError::NoRoute));
}

#[test]
fn loopback_ping_and_udp_work_without_a_link() {
    let mut n = Net::new();
    let s = n.a.icmp_open().unwrap();
    n.a.icmp_echo(s, Ipv4Addr::LOOPBACK, 9, b"me").unwrap();
    assert!(matches!(n.a.icmp_recv(s), Ok(IcmpEvent::Reply { from, seq: 9, .. }) if from == Ipv4Addr::LOOPBACK));
    let u1 = n.a.udp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 7000)).unwrap();
    let u2 = n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    n.a.udp_send_to(u2, Some(Endpoint::new(Ipv4Addr::LOOPBACK, 7000)), b"loop").unwrap();
    let mut buf = [0u8; 16];
    let (from, len, _) = n.a.udp_recv_from(u1, &mut buf).unwrap();
    assert_eq!(&buf[..len], b"loop");
    assert_eq!(from.addr, Ipv4Addr::LOOPBACK);
    // Our own interface address is local too.
    n.a.icmp_echo(s, A_IP, 10, b"").unwrap();
    assert!(matches!(n.a.icmp_recv(s), Ok(IcmpEvent::Reply { seq: 10, .. })));
    assert_eq!(n.delivered, 0, "nothing went over the link");
}

#[test]
fn echo_replies_must_match_a_sent_request() {
    let mut n = Net::new();
    let s = n.a.icmp_open().unwrap();
    let ident = n.a.icmp_ident(s).unwrap();
    let inject = |n: &mut Net, from: Ipv4Addr, seq: u16| {
        let reply = osyx_net::icmp::echo(osyx_net::icmp::ECHO_REPLY, ident, seq, b"spoof");
        let pkt = osyx_net::ipv4::build(from, A_IP, 1, 64, 9, &reply, 1500, false).unwrap().remove(0);
        let frame = osyx_net::ethernet::build(A_MAC, B_MAC, 0x0800, &pkt);
        n.a.receive(1, &frame);
    };
    inject(&mut n, B_IP, 42);
    assert_eq!(n.a.icmp_recv(s), Err(NetError::WouldBlock), "unsolicited reply");
    // A send that never left the host leaves no request to answer.
    assert_eq!(n.a.icmp_echo(s, Ipv4Addr::new(8, 8, 8, 8), 43, b""), Err(NetError::NoRoute));
    inject(&mut n, Ipv4Addr::new(8, 8, 8, 8), 43);
    assert_eq!(n.a.icmp_recv(s), Err(NetError::WouldBlock), "reply to a request that never left");
    n.a.icmp_echo(s, B_IP, 42, b"real").unwrap();
    assert!(n.run_until(100, |n| matches!(n.a.icmp_recv(s), Ok(IcmpEvent::Reply { from, seq: 42, .. }) if from == B_IP)));
}

#[test]
fn peeks_leave_the_data_queued() {
    let mut n = Net::new();
    let ping = n.a.icmp_open().unwrap();
    n.a.icmp_echo(ping, Ipv4Addr::LOOPBACK, 11, b"me").unwrap();
    assert!(matches!(n.a.icmp_peek(ping), Ok(IcmpEvent::Reply { seq: 11, .. })));
    assert!(matches!(n.a.icmp_recv(ping), Ok(IcmpEvent::Reply { seq: 11, .. })));
    assert_eq!(n.a.icmp_peek(ping), Err(NetError::WouldBlock));

    let u1 = n.a.udp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 7001)).unwrap();
    let u2 = n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    n.a.udp_send_to(u2, Some(Endpoint::new(Ipv4Addr::LOOPBACK, 7001)), b"peek").unwrap();
    let mut buf = [0u8; 8];
    let (from, len, total) = n.a.udp_peek_from(u1, &mut buf).unwrap();
    assert_eq!((&buf[..len], total, from.addr), (&b"peek"[..], 4, Ipv4Addr::LOOPBACK));
    assert_eq!(n.a.recv_available(u1), Ok(4), "a peek consumes nothing");
    let (from, len, _) = n.a.udp_recv_from(u1, &mut buf).unwrap();
    assert_eq!((&buf[..len], from.addr), (&b"peek"[..], Ipv4Addr::LOOPBACK));

    let (c, s) = connect(&mut n, 6160);
    assert_eq!(n.a.tcp_send(c, b"peek at me").unwrap(), 10);
    assert!(n.run_until(1000, |n| n.b.recv_available(s) == Ok(10)));
    let mut part = [0u8; 5];
    assert_eq!(n.b.tcp_peek(s, &mut part), Ok(5));
    assert_eq!(&part, b"peek ");
    assert_eq!(n.b.recv_available(s), Ok(10), "a peek consumes nothing");
    let mut all = [0u8; 10];
    assert_eq!(n.b.tcp_recv(s, &mut all), Ok(10));
    assert_eq!(&all, b"peek at me");
}

#[test]
fn udp_connect_reports_its_peer() {
    let mut n = Net::new();
    let u = n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    assert_eq!(n.a.udp_peer(u), Err(NetError::NotConnected));
    let peer = Endpoint::new(B_IP, 9000);
    n.a.udp_connect(u, peer).unwrap();
    assert_eq!(n.a.udp_peer(u), Ok(peer));
}

#[test]
fn broadcast_reaches_only_sockets_bound_to_it_or_the_wildcard() {
    let mut n = Net::new();
    let specific = n.a.udp_bind(Endpoint::new(A_IP, 9100)).unwrap();
    n.a.udp_set_broadcast(specific, true).unwrap();
    let wildcard = n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 9102)).unwrap();
    let sender = n.b.udp_bind(Endpoint::new(B_IP, 9101)).unwrap();
    let bcast = Ipv4Addr::new(10, 0, 0, 255);
    // A directed broadcast is still a broadcast: without SO_BROADCAST the
    // send fails, exactly as for the limited broadcast address.
    assert_eq!(n.b.udp_send_to(sender, Some(Endpoint::new(bcast, 9100)), b"narrow"), Err(NetError::AccessDenied));
    n.b.udp_set_broadcast(sender, true).unwrap();
    n.b.udp_send_to(sender, Some(Endpoint::new(bcast, 9100)), b"narrow").unwrap();
    n.b.udp_send_to(sender, Some(Endpoint::new(bcast, 9102)), b"wild").unwrap();
    let mut buf = [0u8; 8];
    assert!(n.run_until(100, |n| n.a.udp_recv_from(wildcard, &mut buf).is_ok()));
    assert_eq!(&buf[..4], b"wild");
    // SO_BROADCAST permits sending; it does not make a unicast-bound socket
    // accept broadcasts.
    assert_eq!(n.a.udp_recv_from(specific, &mut buf), Err(NetError::WouldBlock));
}

#[test]
fn tcp_bind_reserves_a_dynamic_port_before_listen_or_connect() {
    let mut n = Net::new();
    let bound = n.a.tcp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 0)).unwrap();
    let local = n.a.tcp_bound_local(bound).unwrap();
    assert_ne!(local.port, 0);
    assert_eq!(local.addr, Ipv4Addr::LOOPBACK);
    assert_eq!(n.a.tcp_bind(local), Err(NetError::AddrInUse));
    assert_eq!(n.a.tcp_listen(local, 1), Err(NetError::AddrInUse));
    assert_eq!(n.a.tcp_send(bound, b"x"), Err(NetError::NotConnected));
    assert_eq!(n.a.poll_socket(bound), (false, false, false));
    assert!(n.a.sockets().iter().any(|s| s.id == bound && s.state == "BOUND" && s.local == local));
    // Rejected connect attempts keep the reservation available for listen.
    assert_eq!(n.a.tcp_connect_bound(bound, Endpoint::new(Ipv4Addr::LOOPBACK, 0)), Err(NetError::InvalidArgument));
    assert_eq!(n.a.tcp_bound_local(bound), Ok(local));
    n.a.tcp_listen_bound(bound, 5).unwrap();
    assert_eq!(n.a.listener_local(bound), Ok(local));
    let client = n.a.tcp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let client_port = n.a.tcp_bound_local(client).unwrap().port;
    assert_ne!(client_port, local.port);
    assert_eq!(n.a.tcp_connect_bound(client, local), Ok(client));
    assert_eq!(n.a.tcp_endpoints(client).unwrap().0, Endpoint::new(Ipv4Addr::LOOPBACK, client_port));
    let (server, _) = n.a.tcp_accept(bound).unwrap();
    assert_eq!(n.a.tcp_send(client, b"wake"), Ok(4));
    let mut data = [0; 4];
    assert_eq!(n.a.tcp_recv(server, &mut data), Ok(4));
    assert_eq!(&data, b"wake");
    let reservation = n.a.tcp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 0)).unwrap();
    let released = n.a.tcp_bound_local(reservation).unwrap();
    n.a.close(reservation, false);
    assert!(n.a.tcp_listen(released, 1).is_ok());
}

#[test]
fn binds_only_conflict_on_the_same_address() {
    let mut n = Net::new();
    let lo = n.a.tcp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 7100)).unwrap();
    // Another local address on the same port is a different endpoint.
    assert!(n.a.tcp_bind(Endpoint::new(A_IP, 7100)).is_ok());
    // The wildcard covers every address, so it collides with both.
    assert_eq!(n.a.tcp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 7100)), Err(NetError::AddrInUse));
    assert_eq!(n.a.tcp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 7100)), Err(NetError::AddrInUse));
    let listener = n.a.tcp_listen(Endpoint::new(Ipv4Addr::LOOPBACK, 7101), 1).unwrap();
    assert_eq!(n.a.tcp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 7101)), Err(NetError::AddrInUse));
    n.a.close(lo, false);
    n.a.close(listener, false);

    let udp = n.a.udp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 7102)).unwrap();
    assert!(n.a.udp_bind(Endpoint::new(A_IP, 7102)).is_ok());
    assert_eq!(n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 7102)), Err(NetError::AddrInUse));
    // TCP and UDP port spaces are independent.
    assert!(n.a.tcp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 7102)).is_ok());
    n.a.close(udp, false);
}

#[test]
fn udp_datagrams_flow_and_errors_are_reported() {
    let mut n = Net::new();
    let server = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 9000)).unwrap();
    assert_eq!(n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 9000)), Err(NetError::AddrInUse));
    assert_eq!(n.b.udp_bind(Endpoint::new(Ipv4Addr::new(10, 9, 9, 9), 1)), Err(NetError::AddrNotAvailable));
    let client = n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let port = n.a.udp_local(client).unwrap().port;
    assert!((49152..=65535).contains(&port));
    for i in 0..10u8 {
        n.a.udp_send_to(client, Some(Endpoint::new(B_IP, 9000)), &[i; 100]).unwrap();
    }
    let mut got = Vec::new();
    assert!(n.run_until(100, |n| {
        let mut buf = [0u8; 200];
        while let Ok((from, len, _)) = n.b.udp_recv_from(server, &mut buf) {
            assert_eq!(from, Endpoint::new(A_IP, port));
            got.push(buf[..len].to_vec());
        }
        got.len() == 10
    }));
    assert_eq!(got[3], vec![3; 100]);
    // A large datagram is fragmented and reassembled.
    n.a.udp_send_to(client, Some(Endpoint::new(B_IP, 9000)), &vec![0x5A; 8000]).unwrap();
    let mut big = vec![0u8; 9000];
    let mut len = 0;
    assert!(n.run_until(100, |n| match n.b.udp_recv_from(server, &mut big) {
        Ok((_, l, _)) => {
            len = l;
            true
        }
        Err(_) => false,
    }));
    assert_eq!(len, 8000);
    assert!(n.b.stats.ip_reassembled >= 1);
    // Sending to a closed port: the connected socket gets the ICMP error.
    n.a.udp_connect(client, Endpoint::new(B_IP, 9999)).unwrap();
    n.a.udp_send_to(client, None, b"nobody").unwrap();
    let mut buf = [0u8; 8];
    assert!(n.run_until(100, |n| n.a.udp_recv_from(client, &mut buf) == Err(NetError::PortUnreachable)));
    assert_eq!(n.a.udp_send_to(client, Some(Endpoint::new(B_IP, 9000)), &vec![0; 70_000]), Err(NetError::MessageTooLong));
    // The receive queue is bounded.
    for _ in 0..200 {
        n.a.udp_send_to(client, Some(Endpoint::new(B_IP, 9000)), b"flood").unwrap();
        n.step();
    }
    n.run(50);
    let mut count = 0;
    while n.b.udp_recv_from(server, &mut buf).is_ok() {
        count += 1;
    }
    assert!(count <= osyx_net::stack::UDP_QUEUE_DATAGRAMS);
    n.a.close(client, false);
    n.b.close(server, false);
    assert_eq!(n.a.socket_count(), 0);
}

/// Connects A to a listener on B; returns (client, server) socket ids.
fn connect(n: &mut Net, port: u16) -> (u32, u32) {
    let l = n.b.tcp_listen(Endpoint::new(Ipv4Addr::UNSPECIFIED, port), 8).unwrap();
    let c = n.a.tcp_connect(None, Endpoint::new(B_IP, port)).unwrap();
    let mut s = None;
    assert!(n.run_until(30_000, |n| {
        if s.is_none() {
            s = n.b.tcp_accept(l).ok().map(|x| x.0);
        }
        s.is_some() && n.a.tcp_state(c).unwrap().0 == State::Established
    }));
    n.b.close(l, false);
    assert_eq!(n.a.tcp_connected(c), Ok(true));
    (c, s.unwrap())
}

/// Moves `data` from `tx` on one side to the other and returns what arrived.
fn transfer(n: &mut Net, from_a: bool, tx: u32, rx: u32, data: &[u8], max_ms: u64) -> Vec<u8> {
    let mut sent = 0;
    let mut got = Vec::new();
    let ok = n.run_until(max_ms, |n| {
        let (s, r) = if from_a { (&mut n.a, &mut n.b) } else { (&mut n.b, &mut n.a) };
        if sent < data.len() {
            if let Ok(k) = s.tcp_send(tx, &data[sent..]) {
                sent += k;
            }
        }
        let mut buf = [0u8; 4096];
        while let Ok(k) = r.tcp_recv(rx, &mut buf) {
            if k == 0 {
                break;
            }
            got.extend_from_slice(&buf[..k]);
        }
        got.len() >= data.len()
    });
    assert!(ok, "transfer stalled at {} of {} bytes", got.len(), data.len());
    got
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[test]
fn tcp_handshake_transfer_and_orderly_teardown() {
    let mut n = Net::new();
    let (c, s) = connect(&mut n, 8080);
    let up = pattern(300_000, 1);
    assert_eq!(transfer(&mut n, true, c, s, &up, 30_000), up);
    let down = pattern(100_000, 2);
    assert_eq!(transfer(&mut n, false, s, c, &down, 30_000), down);
    // Client closes first: FIN-WAIT-2 then TIME-WAIT; server sees EOF.
    n.a.tcp_shutdown(c).unwrap();
    let mut buf = [0u8; 8];
    assert!(n.run_until(1000, |n| n.b.tcp_recv(s, &mut buf) == Ok(0)));
    assert_eq!(n.b.tcp_state(s).unwrap().0, State::CloseWait);
    assert!(n.run_until(100, |n| n.a.tcp_state(c).unwrap().0 == State::FinWait2), "our FIN was acknowledged");
    n.b.close(s, false);
    assert!(n.run_until(1000, |n| n.a.tcp_state(c).map(|s| s.0) == Ok(State::TimeWait)));
    assert!(n.run_until(100, |n| n.b.socket_count() == 0), "LAST-ACK finished and the socket is gone");
    n.a.close(c, false);
    assert_eq!(n.a.socket_count(), 1, "TIME-WAIT keeps the connection");
    n.run(osyx_net::tcp::TIME_WAIT_MS + 100);
    assert_eq!(n.a.socket_count(), 0);
}

#[test]
fn tcp_receive_availability_reports_queued_bytes() {
    let mut n = Net::new();
    let (c, s) = connect(&mut n, 6150);
    assert_eq!(n.b.recv_available(s), Ok(0));
    let data = b"how much is queued?";
    assert_eq!(n.a.tcp_send(c, data).unwrap(), data.len());
    assert!(n.run_until(1000, |n| n.b.recv_available(s) == Ok(data.len())), "all sent bytes are queued");
    let mut buf = [0u8; 4];
    assert_eq!(n.b.tcp_recv(s, &mut buf).unwrap(), 4);
    assert!(n.run_until(100, |n| n.b.recv_available(s) == Ok(data.len() - 4)), "reading consumes the reported bytes");
}

#[test]
fn tcp_survives_loss_duplication_and_reordering() {
    let mut n = Net::new();
    n.loss = 50; // 5 %
    n.dup = 20;
    n.jitter = 8;
    let (c, s) = connect(&mut n, 9000);
    let data = pattern(200_000, 3);
    assert_eq!(transfer(&mut n, true, c, s, &data, 120_000), data);
    let back = pattern(50_000, 4);
    assert_eq!(transfer(&mut n, false, s, c, &back, 120_000), back);
    let (_, _, _, st) = n.a.tcp_info(c).unwrap();
    assert!(st.retransmits + st.fast_retransmits > 0, "loss caused retransmissions: {st:?}");
    let (_, _, _, rs) = n.b.tcp_info(s).unwrap();
    assert!(rs.out_of_order > 0, "reordering was handled: {rs:?}");
    assert!(rs.duplicates > 0, "duplicates were discarded: {rs:?}");
    assert!(n.a.tcp_info(c).unwrap().1.is_some(), "RTT was measured");
}

#[test]
fn tcp_retransmits_a_lost_syn_and_data() {
    let mut n = Net::new();
    // Drop the first SYN and the first data segment.
    let mut syns = 0;
    let mut datas = 0;
    n.filter = Some(Box::new(move |to_b, f| {
        if to_b && f.len() > 34 + 13 && f[23] == 6 {
            let flags = f[34 + 13];
            let ihl = (f[14] & 0x0F) as usize * 4;
            let tcp_hl = (f[14 + ihl + 12] >> 4) as usize * 4;
            let total = u16::from_be_bytes([f[16], f[17]]) as usize;
            let payload = total - ihl - tcp_hl;
            if flags & 0x02 != 0 {
                syns += 1;
                if syns == 1 {
                    return false;
                }
            } else if payload > 0 {
                datas += 1;
                if datas == 1 {
                    return false;
                }
            }
        }
        true
    }));
    let start = n.now;
    let (c, s) = connect(&mut n, 7000);
    assert!(n.now - start >= osyx_net::tcp::INITIAL_RTO_MS, "the SYN was retransmitted after the RTO");
    let data = pattern(1000, 5);
    assert_eq!(transfer(&mut n, true, c, s, &data, 10_000), data);
    assert!(n.a.tcp_info(c).unwrap().3.retransmits >= 1);
}

#[test]
fn tcp_connect_to_a_closed_port_is_refused() {
    let mut n = Net::new();
    let c = n.a.tcp_connect(None, Endpoint::new(B_IP, 1234)).unwrap();
    assert!(n.run_until(1000, |n| n.a.tcp_state(c).unwrap().1 == Some(NetError::ConnRefused)));
    assert!(n.b.stats.tcp_resets_sent >= 1);
    // SO_ERROR reports the failure once, like getsockopt does.
    assert_eq!(n.a.tcp_take_error(c), Ok(Some(NetError::ConnRefused)));
    assert_eq!(n.a.tcp_take_error(c), Ok(None));
    assert_eq!(n.a.tcp_state(c).unwrap().1, None);
    let mut buf = [0u8; 4];
    assert_eq!(n.a.tcp_recv(c, &mut buf), Err(NetError::NotConnected));
}

#[test]
fn tcp_connect_to_a_silent_host_times_out() {
    let mut n = Net::new();
    n.filter = Some(Box::new(|to_b, _| !to_b)); // B never hears anything
    let c = n.a.tcp_connect(None, Endpoint::new(B_IP, 80)).unwrap();
    assert_eq!(n.a.tcp_connected(c), Ok(false), "a SYN in flight is not connected");
    assert!(n.run_until(200_000, |n| n.a.tcp_state(c).unwrap().1 == Some(NetError::TimedOut)));
}

#[test]
fn tcp_reset_aborts_the_peer() {
    let mut n = Net::new();
    let (c, s) = connect(&mut n, 6000);
    n.b.close(s, true);
    let mut buf = [0u8; 4];
    assert!(n.run_until(1000, |n| n.a.tcp_recv(c, &mut buf) == Err(NetError::ConnReset)));
    assert_eq!(n.a.tcp_send(c, b"x"), Err(NetError::ConnReset));
}

#[test]
fn tcp_flow_control_stops_and_resumes_on_a_full_window() {
    let mut n = Net::new();
    let (c, s) = connect(&mut n, 6100);
    // The receiver does not read: the sender fills the window and stalls.
    let data = pattern(osyx_net::tcp::RECV_BUFFER + 100_000, 6);
    let mut sent = 0;
    n.run_until(5000, |n| {
        if let Ok(k) = n.a.tcp_send(c, &data[sent..]) {
            sent += k;
        }
        false
    });
    let receiver_queue = n.b.tcp_info(s).map(|_| ()).ok();
    assert!(receiver_queue.is_some());
    assert!(sent < data.len(), "the sender is blocked by the window");
    let rx = n.b.sockets().into_iter().find(|i| i.id == s).unwrap().rx_queue;
    assert_eq!(rx, osyx_net::tcp::RECV_BUFFER, "the receive buffer is full, not overrun");
    // Reading reopens the window and the rest flows.
    let rest = transfer(&mut n, true, c, s, &data[sent..], 60_000);
    let _ = rest;
}

#[test]
fn many_concurrent_connections() {
    let mut n = Net::new();
    let l = n.b.tcp_listen(Endpoint::new(Ipv4Addr::UNSPECIFIED, 5000), 16).unwrap();
    let clients: Vec<u32> = (0..12).map(|_| n.a.tcp_connect(None, Endpoint::new(B_IP, 5000)).unwrap()).collect();
    let mut servers = Vec::new();
    assert!(n.run_until(5000, |n| {
        while let Ok((s, _)) = n.b.tcp_accept(l) {
            servers.push(s);
        }
        servers.len() == clients.len()
    }));
    // Every client sends its own pattern; servers echo it back.
    let mut done = vec![false; clients.len()];
    let mut inbox: Vec<Vec<u8>> = vec![Vec::new(); clients.len()];
    for (i, &c) in clients.iter().enumerate() {
        n.a.tcp_send(c, &pattern(20_000, i as u32 + 10)).unwrap();
    }
    assert!(n.run_until(30_000, |n| {
        for &s in &servers {
            let mut buf = [0u8; 4096];
            while let Ok(k) = n.b.tcp_recv(s, &mut buf) {
                if k == 0 {
                    break;
                }
                let _ = n.b.tcp_send(s, &buf[..k]);
            }
        }
        for (i, &c) in clients.iter().enumerate() {
            let mut buf = [0u8; 4096];
            while let Ok(k) = n.a.tcp_recv(c, &mut buf) {
                if k == 0 {
                    break;
                }
                inbox[i].extend_from_slice(&buf[..k]);
            }
            done[i] = inbox[i].len() >= 20_000;
        }
        done.iter().all(|&d| d)
    }));
    for (i, got) in inbox.iter().enumerate() {
        assert_eq!(*got, pattern(20_000, i as u32 + 10), "connection {i} kept its own data");
    }
    let est = n.a.sockets().iter().filter(|s| s.state == "ESTABLISHED").count();
    assert_eq!(est, clients.len());
    for &c in &clients {
        n.a.close(c, true);
    }
    assert!(n.run_until(1000, |n| n.b.sockets().iter().all(|s| s.state != "ESTABLISHED")));
}

#[test]
fn listener_backlog_is_bounded_and_closing_it_resets_pending() {
    let mut n = Net::new();
    let l = n.b.tcp_listen(Endpoint::new(Ipv4Addr::UNSPECIFIED, 4000), 2).unwrap();
    // Receiving from a listener is not connected, not a bad socket.
    let mut buf = [0u8; 4];
    assert_eq!(n.b.tcp_recv(l, &mut buf), Err(NetError::NotConnected));
    assert_eq!(n.b.tcp_peek(l, &mut buf), Err(NetError::NotConnected));
    let clients: Vec<u32> = (0..5).map(|_| n.a.tcp_connect(None, Endpoint::new(B_IP, 4000)).unwrap()).collect();
    n.run(200);
    let established = clients.iter().filter(|&&c| n.a.tcp_state(c).unwrap().0 == State::Established).count();
    assert_eq!(established, 2, "only the backlog completes the handshake");
    n.b.close(l, false);
    assert!(n.run_until(5000, |n| clients.iter().all(|&c| n.a.tcp_state(c).unwrap().0 != State::Established)));
}

/// A DHCP server on B for A (A has no address).
#[test]
fn dhcp_configures_address_route_and_dns() {
    let mut n = Net::unconfigured();
    n.b.configure_static(1, Ipv4Addr::new(10, 0, 2, 2), 24, None).unwrap();
    let srv = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, dhcp::SERVER_PORT)).unwrap();
    n.b.udp_set_broadcast(srv, true).unwrap();
    n.a.enable_dhcp(1).unwrap();
    let server = Ipv4Addr::new(10, 0, 2, 2);
    let ok = n.run_until(10_000, |n| {
        let mut buf = [0u8; 600];
        while let Ok((_, len, _)) = n.b.udp_recv_from(srv, &mut buf) {
            let m = dhcp::Message::parse(&buf[..len]).unwrap();
            let kind = match m.msg_type {
                dhcp::DISCOVER => dhcp::OFFER,
                dhcp::REQUEST => dhcp::ACK,
                _ => continue,
            };
            let reply = dhcp::build_reply(
                kind,
                m.xid,
                m.chaddr,
                Ipv4Addr::new(10, 0, 2, 15),
                server,
                Ipv4Addr::new(255, 255, 255, 0),
                server,
                Ipv4Addr::new(10, 0, 2, 3),
                3600,
            );
            n.b.udp_send_to(srv, Some(Endpoint::new(Ipv4Addr::BROADCAST, dhcp::CLIENT_PORT)), &reply).unwrap();
        }
        n.a.interfaces()[1].addr == Some((Ipv4Addr::new(10, 0, 2, 15), 24))
    });
    assert!(ok, "DHCP did not complete");
    assert_eq!(n.a.dns_servers(), &[Ipv4Addr::new(10, 0, 2, 3)]);
    assert_eq!(n.a.route(Ipv4Addr::new(8, 8, 8, 8)), Some((1, server)), "default route via the router");
    assert_eq!(n.a.dhcp_state(1).unwrap().0, dhcp::Phase::Bound);
    let log = n.a.take_log().join("\n");
    assert!(log.contains("DHCP lease 10.0.2.15/24 from 10.0.2.2"), "{log}");
    // And the address works: B can ping A.
    let p = n.b.icmp_open().unwrap();
    n.b.icmp_echo(p, Ipv4Addr::new(10, 0, 2, 15), 1, b"hi").unwrap();
    assert!(n.run_until(100, |n| matches!(n.b.icmp_recv(p), Ok(IcmpEvent::Reply { .. }))));
    // A second interface on the same subnet must not steal DHCP renewals.
    let other = n.a.add_ethernet("eth1", osyx_net::wire::MacAddr([0x52, 0x54, 0, 0, 0, 3]), 1500);
    n.a.configure_static(other, Ipv4Addr::new(10, 0, 2, 16), 24, Some(server)).unwrap();
    let renew_at = n.a.dhcp_state(1).unwrap().1.unwrap().t1;
    n.a.take_tx();
    n.a.set_now(renew_at);
    n.a.poll();
    let frames = n.a.take_tx();
    assert!(!frames.is_empty(), "DHCP renewal produced no frames");
    assert!(frames.iter().all(|(iface, _)| *iface == 1), "DHCP renewal left through the wrong interface");
    // Reassociation must not reuse an address from the previous network.
    n.a.dns_cache.put("old.example", vec![server], 3600, n.now);
    n.a.set_link(1, false);
    n.a.set_link(1, true);
    assert_eq!(n.a.dns_cache.get("old.example", n.now), None);
    assert_eq!(n.a.interfaces()[1].addr, None);
    assert_eq!(n.a.dhcp_state(1).unwrap().0, dhcp::Phase::Init);
    n.a.poll();
    assert_eq!(n.a.dhcp_state(1).unwrap().0, dhcp::Phase::Selecting);
}

/// A tiny DNS server on B: answers A queries from a table, can truncate.
fn serve_dns(n: &mut Net, sock: u32, tcp_listener: Option<u32>, table: &[(&str, [u8; 4])], truncate: bool, tcp_conns: &mut Vec<u32>) {
    let mut buf = [0u8; 600];
    while let Ok((from, len, _)) = n.b.udp_recv_from(sock, &mut buf) {
        let reply = dns_answer(&buf[..len], table, truncate);
        n.b.udp_send_to(sock, Some(from), &reply).unwrap();
    }
    if let Some(l) = tcp_listener {
        while let Ok((c, _)) = n.b.tcp_accept(l) {
            tcp_conns.push(c);
        }
        for &c in tcp_conns.iter() {
            let mut b = [0u8; 600];
            if let Ok(k) = n.b.tcp_recv(c, &mut b) {
                if k > 2 {
                    let reply = dns_answer(&b[2..k], table, false);
                    let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&reply);
                    n.b.tcp_send(c, &framed).unwrap();
                }
            }
        }
    }
}

fn dns_answer(q: &[u8], table: &[(&str, [u8; 4])], truncate: bool) -> Vec<u8> {
    let (name, end) = dns::read_name(q, 12).unwrap();
    let mut r = q[..end + 4].to_vec();
    r[2] = 0x81 | if truncate { 0x02 } else { 0 };
    r[3] = 0x80;
    match table.iter().find(|(n, _)| *n == name) {
        Some((_, addr)) if !truncate => {
            r[7] = 1;
            r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
            r.extend_from_slice(addr);
        }
        Some(_) => {}
        None => r[3] = 0x83, // NXDOMAIN
    }
    r
}

#[test]
fn dns_resolves_caches_and_reports_missing_names() {
    let mut n = Net::new();
    n.a.set_dns_servers(&[B_IP]);
    let sock = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 53)).unwrap();
    let table = [("example.com", [93, 184, 215, 14])];
    let Resolve::Pending(q) = n.a.resolve("Example.COM") else { panic!("expected a query") };
    let mut result = None;
    let mut conns = Vec::new();
    assert!(n.run_until(1000, |n| {
        serve_dns(n, sock, None, &table, false, &mut conns);
        result = n.a.resolve_result(q);
        result.is_some()
    }));
    assert_eq!(result, Some(Ok(vec![Ipv4Addr::new(93, 184, 215, 14)])));
    // The second lookup comes from the cache.
    let queries = n.a.stats.dns_queries;
    assert_eq!(n.a.resolve("example.com"), Resolve::Done(Ok(vec![Ipv4Addr::new(93, 184, 215, 14)])));
    assert_eq!(n.a.stats.dns_queries, queries);
    // Unknown names fail with NameNotFound (and are cached negatively).
    let Resolve::Pending(q) = n.a.resolve("nowhere.test") else { panic!() };
    let mut result = None;
    assert!(n.run_until(1000, |n| {
        serve_dns(n, sock, None, &table, false, &mut conns);
        result = n.a.resolve_result(q);
        result.is_some()
    }));
    assert_eq!(result, Some(Err(NetError::NameNotFound)));
    assert_eq!(n.a.resolve("nowhere.test"), Resolve::Done(Err(NetError::NameNotFound)));
    // Literals and localhost need no server.
    assert_eq!(n.a.resolve("10.0.0.2"), Resolve::Done(Ok(vec![B_IP])));
    assert_eq!(n.a.resolve("localhost"), Resolve::Done(Ok(vec![Ipv4Addr::LOOPBACK])));
    assert_eq!(n.a.resolve("bad..name"), Resolve::Done(Err(NetError::InvalidArgument)));
    // The cache expires with the TTL (30 s).
    n.run(31_000);
    assert!(matches!(n.a.resolve("example.com"), Resolve::Pending(_)));
}

#[test]
fn dns_falls_back_to_tcp_for_truncated_answers() {
    let mut n = Net::new();
    n.a.set_dns_servers(&[B_IP]);
    let sock = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 53)).unwrap();
    let l = n.b.tcp_listen(Endpoint::new(Ipv4Addr::UNSPECIFIED, 53), 4).unwrap();
    let table = [("big.test", [10, 1, 2, 3])];
    let Resolve::Pending(q) = n.a.resolve("big.test") else { panic!() };
    let mut result = None;
    let mut conns = Vec::new();
    assert!(n.run_until(5000, |n| {
        serve_dns(n, sock, Some(l), &table, true, &mut conns);
        result = n.a.resolve_result(q);
        result.is_some()
    }));
    assert_eq!(result, Some(Ok(vec![Ipv4Addr::new(10, 1, 2, 3)])));
    assert!(!conns.is_empty(), "the answer came over TCP");
}

#[test]
fn dns_rejects_truncated_tcp_answers() {
    let mut n = Net::new();
    n.a.set_dns_servers(&[B_IP]);
    let sock = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 53)).unwrap();
    let l = n.b.tcp_listen(Endpoint::new(Ipv4Addr::UNSPECIFIED, 53), 4).unwrap();
    let table = [("big.test", [10, 1, 2, 3])];
    let Resolve::Pending(q) = n.a.resolve("big.test") else { panic!("expected a query") };
    let mut result = None;
    let mut conns: Vec<u32> = Vec::new();
    // Every answer, over UDP and over TCP, is truncated.
    assert!(n.run_until(60_000, |n| {
        let mut buf = [0u8; 600];
        while let Ok((from, len, _)) = n.b.udp_recv_from(sock, &mut buf) {
            let reply = dns_answer(&buf[..len], &table, true);
            n.b.udp_send_to(sock, Some(from), &reply).unwrap();
        }
        while let Ok((c, _)) = n.b.tcp_accept(l) {
            conns.push(c);
        }
        for &c in &conns {
            let mut b = [0u8; 600];
            while let Ok(k) = n.b.tcp_recv(c, &mut b) {
                if k > 2 {
                    let reply = dns_answer(&b[2..k], &table, true);
                    let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&reply);
                    let _ = n.b.tcp_send(c, &framed);
                }
            }
        }
        result = n.a.resolve_result(q);
        result.is_some()
    }));
    assert_eq!(result, Some(Err(NetError::DnsFailure)));
    // An unusable answer must not poison the cache with a negative entry.
    assert!(matches!(n.a.resolve("big.test"), Resolve::Pending(_)));
}

#[test]
fn dns_ignores_spoofed_replies_and_times_out() {
    let mut n = Net::new();
    n.a.set_dns_servers(&[B_IP]);
    // An attacker on B answers from the wrong port; the real server is silent.
    let spoof = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 5353)).unwrap();
    let real = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 53)).unwrap();
    let Resolve::Pending(q) = n.a.resolve("victim.test") else { panic!() };
    let mut result = None;
    assert!(n.run_until(20_000, |n| {
        let mut buf = [0u8; 600];
        while let Ok((from, len, _)) = n.b.udp_recv_from(real, &mut buf) {
            let reply = dns_answer(&buf[..len], &[("victim.test", [6, 6, 6, 6])], false);
            n.b.udp_send_to(spoof, Some(from), &reply).unwrap();
        }
        result = n.a.resolve_result(q);
        result.is_some()
    }));
    assert_eq!(result, Some(Err(NetError::TimedOut)));
    assert!(n.a.stats.dns_rejected >= 1);
    assert_eq!(n.a.socket_count(), 0, "query sockets are cleaned up");
}

#[test]
fn dns_shared_query_answers_every_waiter() {
    let mut n = Net::new();
    n.a.set_dns_servers(&[B_IP]);
    let sock = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 53)).unwrap();
    let table = [("shared.test", [10, 4, 4, 4])];
    let Resolve::Pending(q1) = n.a.resolve("shared.test") else { panic!() };
    let Resolve::Pending(q2) = n.a.resolve("shared.test") else { panic!() };
    assert_eq!(q1, q2, "the second caller shares the outstanding query");
    let mut conns = Vec::new();
    assert!(n.run_until(1000, |n| {
        serve_dns(n, sock, None, &table, false, &mut conns);
        n.a.resolve_result(q1).is_some()
    }));
    let want = Some(Ok(vec![Ipv4Addr::new(10, 4, 4, 4)]));
    assert_eq!(n.a.resolve_result(q1), want);
    assert_eq!(n.a.resolve_result(q2), want, "both waiters see the answer");
}

#[test]
fn cancelling_one_waiter_keeps_the_shared_query() {
    let mut n = Net::new();
    n.a.set_dns_servers(&[B_IP]);
    let sock = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 53)).unwrap();
    let table = [("shared.test", [10, 5, 5, 5])];
    let Resolve::Pending(q1) = n.a.resolve("shared.test") else { panic!() };
    let Resolve::Pending(q2) = n.a.resolve("shared.test") else { panic!() };
    assert_eq!(q1, q2);
    // The first caller gives up; the second still gets the answer.
    n.a.resolve_cancel(q1);
    let mut conns = Vec::new();
    let mut result = None;
    assert!(n.run_until(1000, |n| {
        serve_dns(n, sock, None, &table, false, &mut conns);
        result = n.a.resolve_result(q2);
        result.is_some()
    }));
    assert_eq!(result, Some(Ok(vec![Ipv4Addr::new(10, 5, 5, 5)])));
}

#[test]
fn dns_fails_over_to_the_next_server_after_one_timeout() {
    let mut n = Net::new();
    // The first server never answers (no host at 10.0.0.3); the second does.
    n.a.set_dns_servers(&[Ipv4Addr::new(10, 0, 0, 3), B_IP]);
    let sock = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 53)).unwrap();
    let table = [("failover.test", [10, 9, 8, 7])];
    let Resolve::Pending(q) = n.a.resolve("failover.test") else { panic!() };
    let mut conns = Vec::new();
    let before = n.now;
    let mut result = None;
    assert!(n.run_until(3500, |n| {
        serve_dns(n, sock, None, &table, false, &mut conns);
        result = n.a.resolve_result(q);
        result.is_some()
    }));
    assert_eq!(result, Some(Ok(vec![Ipv4Addr::new(10, 9, 8, 7)])));
    let elapsed = n.now - before;
    assert!(elapsed < 3000, "failover took {elapsed} ms");
    assert_eq!(n.a.stats.dns_queries, 2, "one query per server before the answer");
}

#[test]
fn malformed_frames_are_counted_not_trusted() {
    let mut n = Net::new();
    let mut seed = 0x5EED_u32;
    for _ in 0..3000 {
        let len = (seed % 200) as usize + 1;
        let mut f: Vec<u8> = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect();
        if f.len() > 14 {
            f[0..6].copy_from_slice(&B_MAC.0);
            f[6] = 0x52;
            f[12] = 0x08;
            f[13] = if seed.is_multiple_of(3) { 0x06 } else { 0x00 };
            if f.len() > 15 {
                f[14] = 0x45;
            }
        }
        n.b.receive(1, &f);
    }
    let st = n.b.stats;
    assert!(st.ip_bad + st.frames_bad + st.arp_bad > 0);
    // Still healthy afterwards.
    let s = n.a.icmp_open().unwrap();
    n.a.icmp_echo(s, B_IP, 1, b"ok").unwrap();
    assert!(n.run_until(100, |n| matches!(n.a.icmp_recv(s), Ok(IcmpEvent::Reply { .. }))));
}

#[test]
fn tcp_peek_leaves_the_data_queued() {
    let mut n = Net::new();
    let (c, s) = connect(&mut n, 7100);
    assert_eq!(n.a.tcp_send(c, b"peek me"), Ok(7));
    let mut buf = [0u8; 32];
    assert!(n.run_until(1000, |n| n.b.tcp_peek(s, &mut buf) == Ok(7)));
    assert_eq!(&buf[..7], b"peek me");
    // A second peek returns the same bytes: nothing was consumed.
    assert_eq!(n.b.tcp_peek(s, &mut buf), Ok(7));
    assert_eq!(&buf[..7], b"peek me");
    assert_eq!(n.b.tcp_recv(s, &mut buf), Ok(7));
    assert_eq!(&buf[..7], b"peek me");
    assert_eq!(n.b.tcp_peek(s, &mut buf), Err(NetError::WouldBlock));
}

#[test]
fn udp_peek_leaves_the_datagram_queued() {
    let mut n = Net::new();
    let rx = n.a.udp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 7001)).unwrap();
    let tx = n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    n.a.udp_send_to(tx, Some(Endpoint::new(Ipv4Addr::LOOPBACK, 7001)), b"peek").unwrap();
    let mut buf = [0u8; 8];
    let (from, len, total) = n.a.udp_peek_from(rx, &mut buf).unwrap();
    assert_eq!((&buf[..len], total), (&b"peek"[..], 4));
    assert_eq!(from.addr, Ipv4Addr::LOOPBACK);
    let (_, len, _) = n.a.udp_peek_from(rx, &mut buf).unwrap();
    assert_eq!(&buf[..len], b"peek");
    let (_, len, _) = n.a.udp_recv_from(rx, &mut buf).unwrap();
    assert_eq!(&buf[..len], b"peek");
    assert_eq!(n.a.udp_peek_from(rx, &mut buf), Err(NetError::WouldBlock));
}

#[test]
fn available_reports_queued_bytes() {
    let mut n = Net::new();
    let (c, s) = connect(&mut n, 7103);
    assert_eq!(n.b.recv_available(s), Ok(0));
    assert_eq!(n.a.tcp_send(c, b"count me"), Ok(8));
    assert!(n.run_until(1000, |n| n.b.recv_available(s) == Ok(8)));
    // Peeking does not change the count.
    assert_eq!(n.b.tcp_peek(s, &mut [0u8; 4]), Ok(4));
    assert_eq!(n.b.recv_available(s), Ok(8));
    let mut buf = [0u8; 16];
    assert_eq!(n.b.tcp_recv(s, &mut buf[..5]), Ok(5));
    assert_eq!(n.b.recv_available(s), Ok(3));
    assert_eq!(n.b.tcp_recv(s, &mut buf), Ok(3));
    assert_eq!(n.b.recv_available(s), Ok(0));

    let rx = n.a.udp_bind(Endpoint::new(Ipv4Addr::LOOPBACK, 7104)).unwrap();
    assert_eq!(n.a.recv_available(rx), Ok(0));
    let tx = n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    n.a.udp_send_to(tx, Some(Endpoint::new(Ipv4Addr::LOOPBACK, 7104)), b"12345").unwrap();
    assert_eq!(n.a.recv_available(rx), Ok(5));
    let mut ubuf = [0u8; 8];
    n.a.udp_recv_from(rx, &mut ubuf).unwrap();
    assert_eq!(n.a.recv_available(rx), Ok(0));
}

#[test]
fn udp_broadcast_needs_the_broadcast_option() {
    let mut n = Net::new();
    let tx = n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let rx = n.b.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 7002)).unwrap();
    let subnet_broadcast = Ipv4Addr::new(10, 0, 0, 255);
    assert_eq!(
        n.a.udp_send_to(tx, Some(Endpoint::new(subnet_broadcast, 7002)), b"x"),
        Err(NetError::AccessDenied),
        "subnet-directed broadcast without SO_BROADCAST"
    );
    n.a.udp_set_broadcast(tx, true).unwrap();
    n.a.take_tx();
    assert_eq!(n.a.udp_send_to(tx, Some(Endpoint::new(subnet_broadcast, 7002)), b"x"), Ok(1));
    // It goes out as a broadcast frame, not into ARP for a host address.
    let frames = n.a.take_tx();
    assert_eq!(frames.len(), 1, "one broadcast frame");
    assert_eq!(&frames[0].1[..6], &[0xFF; 6]);
    assert_eq!(&frames[0].1[30..34], &subnet_broadcast.0);
    // The peer accepts a broadcast datagram (sent again: the frame above
    // was taken out of the transmit queue for inspection).
    assert_eq!(n.a.udp_send_to(tx, Some(Endpoint::new(subnet_broadcast, 7002)), b"x"), Ok(1));
    let mut buf = [0u8; 8];
    assert!(n.run_until(10, |n| matches!(n.b.udp_recv_from(rx, &mut buf), Ok((_, 1, 1)))));
    assert_eq!(&buf[..1], b"x");
    // A unicast peer in the same subnet never needs the option.
    assert_eq!(n.a.udp_send_to(tx, Some(Endpoint::new(B_IP, 7002)), b"x"), Ok(1));
}

#[test]
fn udp_peek_does_not_consume_the_pending_error() {
    let mut n = Net::new();
    let client = n.a.udp_bind(Endpoint::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    n.a.udp_connect(client, Endpoint::new(B_IP, 9999)).unwrap();
    n.a.udp_send_to(client, None, b"nobody").unwrap();
    let mut buf = [0u8; 8];
    assert!(n.run_until(100, |n| n.a.udp_peek_from(client, &mut buf) == Err(NetError::PortUnreachable)));
    // ICMP unreachable stays pending until a real recv consumes it.
    assert_eq!(n.a.udp_peek_from(client, &mut buf), Err(NetError::PortUnreachable));
    assert_eq!(n.a.udp_recv_from(client, &mut buf), Err(NetError::PortUnreachable));
}
