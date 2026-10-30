//! Packet formats: checksums, parsing, generation and malformed input.

use osyx_net::wire::{self, Ipv4Addr, MacAddr};
use osyx_net::{arp, dhcp, dns, ethernet, icmp, ipv4, tcp, udp};

#[test]
fn internet_checksum_matches_rfc1071_example() {
    // RFC 1071 section 3: 00 01 f2 03 f4 f5 f6 f7 sums to ddf2.
    let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(wire::checksum(&data), !0xddf2);
    // Odd length: the last byte is padded with zero.
    assert_eq!(wire::checksum(&[0xAB]), !0xAB00);
    // A header with its checksum filled in sums to zero.
    let mut h = [0u8; 20];
    ipv4::write_header(&mut h, Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 2), 1, 64, 7, 100, 0, false, true);
    assert_eq!(wire::checksum(&h), 0);
}

#[test]
fn addresses_parse_and_print() {
    assert_eq!(Ipv4Addr::parse("10.0.2.15"), Some(Ipv4Addr::new(10, 0, 2, 15)));
    for bad in ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1..2.3", "a.b.c.d", " 1.2.3.4", "1.2.3.04444"] {
        assert_eq!(Ipv4Addr::parse(bad), None, "{bad:?}");
    }
    assert_eq!(format!("{}", Ipv4Addr::new(192, 168, 1, 255)), "192.168.1.255");
    assert_eq!(format!("{}", MacAddr([0x52, 0x54, 0, 0x12, 0x34, 0x56])), "52:54:00:12:34:56");
    assert_eq!(wire::mask_prefix(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
    assert_eq!(wire::mask_prefix(Ipv4Addr::new(255, 0, 255, 0)), None);
    assert!(Ipv4Addr::new(10, 0, 2, 99).in_subnet(Ipv4Addr::new(10, 0, 2, 0), 24));
    assert!(!Ipv4Addr::new(10, 0, 3, 1).in_subnet(Ipv4Addr::new(10, 0, 2, 0), 24));
}

#[test]
fn ethernet_frames_round_trip_and_reject_garbage() {
    let f = ethernet::build(MacAddr::BROADCAST, MacAddr([2, 0, 0, 0, 0, 1]), ethernet::ETHERTYPE_ARP, &[1, 2, 3]);
    assert_eq!(f.len(), ethernet::MIN_FRAME, "short frames are padded");
    let (h, payload) = ethernet::parse(&f).unwrap();
    assert_eq!(h.ethertype, ethernet::ETHERTYPE_ARP);
    assert_eq!(&payload[..3], &[1, 2, 3]);
    assert_eq!(ethernet::parse(&f[..13]), Err(ethernet::FrameError::Truncated));
    let mut len_field = f.clone();
    len_field[12] = 0x00;
    len_field[13] = 0x40;
    assert_eq!(ethernet::parse(&len_field), Err(ethernet::FrameError::NotEthernetII));
    let mut group_src = f.clone();
    group_src[6] = 0x01;
    assert_eq!(ethernet::parse(&group_src), Err(ethernet::FrameError::BadSource));
    assert_eq!(ethernet::parse(&vec![0u8; 2000]), Err(ethernet::FrameError::TooLong));
    let own = MacAddr([2, 0, 0, 0, 0, 9]);
    assert!(ethernet::accepts(own, own, false));
    assert!(ethernet::accepts(own, MacAddr::BROADCAST, false));
    assert!(!ethernet::accepts(own, MacAddr([2, 0, 0, 0, 0, 8]), false));
    assert!(!ethernet::accepts(own, MacAddr([1, 0, 0x5e, 0, 0, 1]), false));
}

#[test]
fn arp_packets_round_trip_and_reject_other_protocols() {
    let p = arp::Packet {
        op: arp::OP_REQUEST,
        sender_mac: MacAddr([2, 0, 0, 0, 0, 1]),
        sender_ip: Ipv4Addr::new(10, 0, 0, 1),
        target_mac: MacAddr::ZERO,
        target_ip: Ipv4Addr::new(10, 0, 0, 2),
    };
    let b = p.emit();
    assert_eq!(arp::Packet::parse(&b), Ok(p));
    assert_eq!(arp::Packet::parse(&b[..27]), Err(arp::ArpError::Truncated));
    let mut ipv6 = b;
    ipv6[3] = 0xDD;
    assert_eq!(arp::Packet::parse(&ipv6), Err(arp::ArpError::Unsupported));
    let mut op = b;
    op[7] = 9;
    assert_eq!(arp::Packet::parse(&op), Err(arp::ArpError::BadOperation));
}

#[test]
fn arp_cache_queues_retries_expires_and_bounds() {
    let mut c = arp::Cache::new();
    let ip = Ipv4Addr::new(10, 0, 0, 7);
    assert_eq!(c.resolve(ip, vec![1], 0), arp::Lookup::Queued { probe: true });
    assert_eq!(c.resolve(ip, vec![2], 0), arp::Lookup::Queued { probe: false });
    for i in 2..arp::MAX_PENDING {
        assert_eq!(c.resolve(ip, vec![i as u8], 0), arp::Lookup::Queued { probe: false });
    }
    assert_eq!(c.resolve(ip, vec![99], 0), arp::Lookup::Dropped, "pending queue is bounded");
    // Retries, then gives up and reports the dropped packets.
    assert_eq!(c.poll(arp::RETRY_MS), vec![arp::Action::Probe(ip)]);
    assert_eq!(c.poll(2 * arp::RETRY_MS), vec![arp::Action::Probe(ip)]);
    assert_eq!(c.poll(3 * arp::RETRY_MS), vec![arp::Action::Unreachable(ip, arp::MAX_PENDING)]);
    // A reply releases what waited, in order.
    let mac = MacAddr([2, 0, 0, 0, 0, 7]);
    c.resolve(ip, vec![1], 10_000);
    c.resolve(ip, vec![2], 10_000);
    assert_eq!(c.learn(ip, mac, 10_001, true), vec![vec![1], vec![2]]);
    assert_eq!(c.get(ip, 10_002), Some(mac));
    assert!(matches!(c.resolve(ip, vec![3], 10_003), arp::Lookup::Found(m, p) if m == mac && p == vec![3]));
    // A different MAC for the same address counts as a conflict.
    c.learn(ip, MacAddr([2, 0, 0, 0, 0, 8]), 10_004, false);
    assert_eq!(c.conflicts, 1);
    // Entries expire.
    assert_eq!(c.get(ip, 10_004 + arp::REACHABLE_MS + 1), None);
    // Unsolicited replies do not create entries; broadcast MACs are ignored.
    let other = Ipv4Addr::new(10, 0, 0, 8);
    c.learn(other, mac, 1, false);
    assert_eq!(c.get(other, 2), None);
    c.learn(other, MacAddr::BROADCAST, 1, true);
    assert_eq!(c.get(other, 2), None);
    // The table is bounded.
    for i in 0..200u32 {
        c.learn(Ipv4Addr::from_u32(0x0A01_0000 + i), mac, 20_000, true);
    }
    assert!(c.entries(20_000).len() <= arp::MAX_ENTRIES);
}

#[test]
fn ipv4_rejects_malformed_headers() {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    let p = ipv4::build(src, dst, ipv4::PROTO_UDP, 64, 1, &[0xAA; 40], 1500, false).unwrap().remove(0);
    let (h, payload) = ipv4::parse(&p).unwrap();
    assert_eq!((h.src, h.dst, h.protocol, payload.len()), (src, dst, ipv4::PROTO_UDP, 40));
    // Link padding beyond the total length is trimmed.
    let mut padded = p.clone();
    padded.extend_from_slice(&[0; 10]);
    assert_eq!(ipv4::parse(&padded).unwrap().1.len(), 40);
    assert_eq!(ipv4::parse(&p[..19]), Err(ipv4::IpError::Truncated));
    let mut v6 = p.clone();
    v6[0] = 0x65;
    assert_eq!(ipv4::parse(&v6), Err(ipv4::IpError::NotVersion4));
    let mut ihl = p.clone();
    ihl[0] = 0x44;
    assert_eq!(ipv4::parse(&ihl), Err(ipv4::IpError::BadHeaderLength));
    let mut ihl_big = p.clone();
    ihl_big[0] = 0x4F;
    assert_eq!(ipv4::parse(&ihl_big[..40]), Err(ipv4::IpError::BadHeaderLength));
    let mut total = p.clone();
    total[2] = 0x10; // 4096 > packet
    assert!(matches!(ipv4::parse(&total), Err(ipv4::IpError::BadTotalLength | ipv4::IpError::BadChecksum)));
    let mut sum = p.clone();
    sum[8] ^= 1;
    assert_eq!(ipv4::parse(&sum), Err(ipv4::IpError::BadChecksum));
    let bcast_src = ipv4::build(Ipv4Addr::BROADCAST, dst, 17, 64, 1, &[0; 8], 1500, false).unwrap().remove(0);
    assert_eq!(ipv4::parse(&bcast_src), Err(ipv4::IpError::BadSource));
    // Too large to send at all, or fragmenting with DF.
    assert!(ipv4::build(src, dst, 17, 64, 1, &vec![0; 70_000], 1500, false).is_none());
    assert!(ipv4::build(src, dst, 17, 64, 1, &[0; 2000], 1500, true).is_none());
}

#[test]
fn fragments_reassemble_in_any_order_with_duplicates() {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    let data: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
    let frags = ipv4::build(src, dst, ipv4::PROTO_UDP, 64, 42, &data, 576, false).unwrap();
    assert!(frags.len() >= 9);
    for f in &frags {
        assert!(f.len() <= 576);
    }
    let mut order: Vec<usize> = (0..frags.len()).rev().collect();
    order.insert(2, 0); // a duplicate of the last fragment we feed
    let mut r = ipv4::Reassembler::new();
    let mut done = None;
    for i in order {
        let (h, p) = ipv4::parse(&frags[i]).unwrap();
        assert!(h.is_fragment());
        if let Some(d) = r.add(&h, p, 0) {
            done = Some(d);
        }
    }
    let (h, payload) = done.expect("reassembled");
    assert_eq!(payload, data);
    assert!(!h.is_fragment());
    // The duplicate of fragment 0 that arrived after completion starts a
    // new datagram that never completes (it times out).
    assert_eq!(r.pending(), 1);
    r.expire(ipv4::REASSEMBLY_TIMEOUT_MS);
    assert_eq!(r.pending(), 0);
}

#[test]
fn reassembly_is_bounded_and_times_out() {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    let mut r = ipv4::Reassembler::new();
    // Many datagrams that never complete: only MAX_REASSEMBLY are kept.
    for id in 0..50u16 {
        let frags = ipv4::build(src, dst, 17, 64, id, &[1; 3000], 1500, false).unwrap();
        let (h, p) = ipv4::parse(&frags[0]).unwrap();
        assert!(r.add(&h, p, id as u64).is_none());
    }
    assert!(r.pending() <= ipv4::MAX_REASSEMBLY);
    assert!(r.dropped > 0);
    r.expire(ipv4::REASSEMBLY_TIMEOUT_MS + 100);
    assert_eq!(r.pending(), 0);
    // Conflicting final fragments discard the datagram.
    let frags = ipv4::build(src, dst, 17, 64, 77, &[2; 3000], 1500, false).unwrap();
    let (h0, p0) = ipv4::parse(&frags[0]).unwrap();
    let (hl, pl) = ipv4::parse(frags.last().unwrap()).unwrap();
    assert!(r.add(&hl, pl, 0).is_none());
    let mut short = hl;
    short.fragment_offset -= 8;
    assert!(r.add(&short, &pl[..8], 0).is_none());
    assert!(r.add(&h0, p0, 0).is_none());
}

#[test]
fn icmp_echo_round_trips_and_checks_checksum() {
    let m = icmp::echo(icmp::ECHO_REQUEST, 0x1234, 7, b"ping!");
    assert_eq!(icmp::parse(&m), Ok(icmp::Message::EchoRequest { ident: 0x1234, seq: 7, data: b"ping!" }));
    let mut bad = m.clone();
    bad[9] ^= 0xFF;
    assert_eq!(icmp::parse(&bad), Err(icmp::IcmpError::BadChecksum));
    assert_eq!(icmp::parse(&m[..7]), Err(icmp::IcmpError::Truncated));
    let e = icmp::error(icmp::DEST_UNREACHABLE, icmp::UNREACH_PORT, &[0x45; 100]);
    assert_eq!(e.len(), 8 + 64, "quotes are bounded");
    assert!(matches!(icmp::parse(&e), Ok(icmp::Message::Unreachable { code: 3, .. })));
}

#[test]
fn udp_checksum_and_lengths_are_validated() {
    let (s, d) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    let u = udp::build(s, d, 5000, 53, b"hello");
    let (h, data) = udp::parse(s, d, &u).unwrap();
    assert_eq!((h.src_port, h.dst_port, data), (5000, 53, &b"hello"[..]));
    assert_eq!(udp::parse(Ipv4Addr::new(10, 0, 0, 3), d, &u), Err(udp::UdpError::BadChecksum), "pseudo header covers addresses");
    let mut long = u.clone();
    long[5] = 200;
    assert_eq!(udp::parse(s, d, &long), Err(udp::UdpError::BadLength));
    let mut zero = u.clone();
    zero[6] = 0;
    zero[7] = 0;
    assert!(udp::parse(s, d, &zero).is_ok(), "checksum 0 means none");
    assert_eq!(udp::parse(s, d, &u[..7]), Err(udp::UdpError::Truncated));
}

#[test]
fn tcp_segments_round_trip_with_options_and_reject_garbage() {
    use osyx_net::wire::Endpoint;
    let a = Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 40000);
    let b = Endpoint::new(Ipv4Addr::new(10, 0, 0, 2), 80);
    let s = tcp::build(a, b, 1000, 0, tcp::SYN, 65535, Some(1460), Some(7), &[]);
    let seg = tcp::parse(a.addr, b.addr, &s).unwrap();
    assert_eq!((seg.seq, seg.flags, seg.mss, seg.window, seg.ws), (1000, tcp::SYN, Some(1460), 65535, Some(7)));
    let d = tcp::build(a, b, 5, 9, tcp::ACK | tcp::PSH, 100, None, None, b"data");
    assert_eq!(tcp::parse(a.addr, b.addr, &d).unwrap().payload, b"data");
    let mut bad = d.clone();
    bad[22] ^= 1;
    assert_eq!(tcp::parse(a.addr, b.addr, &bad), Err(tcp::SegmentError::BadChecksum));
    let mut off = d.clone();
    off[12] = 0x20; // 8-byte header
    assert_eq!(tcp::parse(a.addr, b.addr, &off), Err(tcp::SegmentError::BadOffset));
    // An option whose length runs past the header.
    let mut opt = s.clone();
    opt[21] = 40;
    let c = recompute_tcp_checksum(&mut opt, a.addr, b.addr);
    assert_eq!(tcp::parse(a.addr, b.addr, &c), Err(tcp::SegmentError::BadOption));
    assert!(tcp::seq_lt(0xFFFF_FFF0, 0x10), "sequence numbers wrap");
    assert!(tcp::seq_gt(0x10, 0xFFFF_FFF0));
}

fn recompute_tcp_checksum(s: &mut [u8], src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    s[16] = 0;
    s[17] = 0;
    let c = wire::transport_checksum(src, dst, ipv4::PROTO_TCP, s);
    s[16..18].copy_from_slice(&c.to_be_bytes());
    s.to_vec()
}

#[test]
fn dhcp_messages_round_trip() {
    let mac = MacAddr([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    let req = dhcp::build_request(dhcp::DISCOVER, 0xABCD, mac, Ipv4Addr::UNSPECIFIED, None, None, 0, "osyx");
    assert!(req.len() >= 300);
    let m = dhcp::Message::parse(&req).unwrap();
    assert_eq!((m.op, m.xid, m.chaddr, m.msg_type), (1, 0xABCD, mac, dhcp::DISCOVER));
    let reply = dhcp::build_reply(
        dhcp::OFFER,
        0xABCD,
        mac,
        Ipv4Addr::new(10, 0, 2, 15),
        Ipv4Addr::new(10, 0, 2, 2),
        Ipv4Addr::new(255, 255, 255, 0),
        Ipv4Addr::new(10, 0, 2, 2),
        Ipv4Addr::new(10, 0, 2, 3),
        86400,
    );
    let m = dhcp::Message::parse(&reply).unwrap();
    assert_eq!(m.yiaddr, Ipv4Addr::new(10, 0, 2, 15));
    assert_eq!(m.dns, vec![Ipv4Addr::new(10, 0, 2, 3)]);
    assert_eq!(m.lease_s, Some(86400));
    assert_eq!(dhcp::Message::parse(&reply[..200]), Err(dhcp::DhcpError::Truncated));
    let mut magic = reply.clone();
    magic[236] = 0;
    assert_eq!(dhcp::Message::parse(&magic), Err(dhcp::DhcpError::BadMagic));
    let mut opt = reply.clone();
    let n = opt.len();
    opt[n - 1] = 6; // option without its length byte
    assert_eq!(dhcp::Message::parse(&opt), Err(dhcp::DhcpError::BadOption));
}

#[test]
fn dhcp_client_walks_through_the_lease_states() {
    let mac = MacAddr([0x52, 0x54, 0, 0, 0, 9]);
    let mut c = dhcp::Client::new(mac, 7, "osyx");
    let (tx, _) = c.poll(0);
    let discover = dhcp::Message::parse(&tx.unwrap().payload).unwrap();
    assert_eq!(c.phase(), dhcp::Phase::Selecting);
    let server = Ipv4Addr::new(10, 0, 2, 2);
    let offer = |kind, xid| {
        dhcp::build_reply(kind, xid, mac, Ipv4Addr::new(10, 0, 2, 15), server, Ipv4Addr::new(255, 255, 255, 0), server, Ipv4Addr::new(10, 0, 2, 3), 120)
    };
    // A reply for another transaction is ignored.
    assert_eq!(c.input(&offer(dhcp::OFFER, discover.xid ^ 1), 10), (None, None));
    let (tx, ev) = c.input(&offer(dhcp::OFFER, discover.xid), 10);
    assert!(ev.is_none());
    let request = dhcp::Message::parse(&tx.unwrap().payload).unwrap();
    assert_eq!(request.msg_type, dhcp::REQUEST);
    assert_eq!(c.phase(), dhcp::Phase::Requesting);
    let (_, ev) = c.input(&offer(dhcp::ACK, request.xid), 20);
    let Some(dhcp::Event::Bound(lease)) = ev else { panic!("not bound: {ev:?}") };
    assert_eq!((lease.addr, lease.prefix, lease.router), (Ipv4Addr::new(10, 0, 2, 15), 24, Some(server)));
    assert_eq!(lease.t1, 20 + 60_000);
    // At T1 the client renews by unicast.
    let (tx, _) = c.poll(lease.t1);
    let tx = tx.unwrap();
    assert_eq!((tx.src, tx.dst), (lease.addr, server));
    assert_eq!(c.phase(), dhcp::Phase::Renewing);
    let renew = dhcp::Message::parse(&tx.payload).unwrap();
    let (_, ev) = c.input(&offer(dhcp::ACK, renew.xid), lease.t1 + 5);
    assert!(matches!(ev, Some(dhcp::Event::Renewed(_))));
    // A renewal ACK may omit yiaddr and network options; retain the lease.
    let renewed = c.lease().unwrap().clone();
    let (tx, _) = c.poll(renewed.t1);
    let xid = dhcp::Message::parse(&tx.unwrap().payload).unwrap().xid;
    let mut minimal = offer(dhcp::ACK, xid);
    minimal[16..20].fill(0);
    // Keep just message type, server ID and lease.
    minimal.truncate(240);
    minimal.extend_from_slice(&[53, 1, dhcp::ACK, 54, 4]);
    minimal.extend_from_slice(&server.0);
    minimal.extend_from_slice(&[51, 4, 0, 0, 0, 120, 255]);
    let (_, event) = c.input(&minimal, renewed.t1 + 1);
    let Some(dhcp::Event::Renewed(updated)) = event else { panic!("renewal failed: {event:?}") };
    assert_eq!((updated.addr, updated.prefix, updated.router, updated.dns),
        (renewed.addr, renewed.prefix, renewed.router, renewed.dns));
    // Without answers the lease runs out.
    let l = c.lease().unwrap().clone();
    let (tx, _) = c.poll(l.t2);
    assert_eq!(tx.unwrap().dst, Ipv4Addr::BROADCAST, "rebinding broadcasts");
    assert!(c.next_deadline().unwrap() > l.t2, "rebinding must not spin on the elapsed T2");
    let (_, ev) = c.poll(l.expires());
    assert_eq!(ev, Some(dhcp::Event::Lost));
    assert!(c.lease().is_none());
}

#[test]
fn dhcp_ignores_replies_from_unselected_server() {
    let mac = MacAddr([0x52, 0x54, 0, 0, 0, 9]);
    let mut client = dhcp::Client::new(mac, 7, "osyx");
    let xid = dhcp::Message::parse(&client.poll(0).0.unwrap().payload).unwrap().xid;
    let selected = Ipv4Addr::new(10, 0, 2, 2);
    let other = Ipv4Addr::new(10, 0, 2, 3);
    let address = Ipv4Addr::new(10, 0, 2, 15);
    let reply = |kind, xid, server, addr| dhcp::build_reply(kind, xid, mac, addr, server, Ipv4Addr::new(255, 255, 255, 0), server, server, 120);
    client.input(&reply(dhcp::OFFER, xid, selected, address), 10);
    for bad in [reply(dhcp::ACK, xid, other, address), reply(dhcp::NAK, xid, other, address), reply(dhcp::ACK, xid, selected, other)] {
        assert_eq!(client.input(&bad, 20), (None, None));
        assert_eq!(client.phase(), dhcp::Phase::Requesting);
    }
    let (_, event) = client.input(&reply(dhcp::ACK, xid, selected, address), 21);
    let Some(dhcp::Event::Bound(lease)) = event else { panic!("expected selected server ACK") };
    let renew = dhcp::Message::parse(&client.poll(lease.t1).0.unwrap().payload).unwrap();
    assert_eq!(client.input(&reply(dhcp::NAK, renew.xid, other, address), lease.t1 + 1), (None, None));
    assert_eq!(client.input(&reply(dhcp::ACK, renew.xid, selected, other), lease.t1 + 1), (None, None));
    let mut wrong_ciaddr = reply(dhcp::ACK, renew.xid, selected, address);
    wrong_ciaddr[12..16].copy_from_slice(&other.0);
    assert_eq!(client.input(&wrong_ciaddr, lease.t1 + 1), (None, None));
    assert_eq!(client.phase(), dhcp::Phase::Renewing);
    let rebind = dhcp::Message::parse(&client.poll(lease.t2).0.unwrap().payload).unwrap();
    assert_eq!(client.input(&reply(dhcp::ACK, rebind.xid, other, Ipv4Addr::BROADCAST), lease.t2 + 1), (None, None));
    let (_, event) = client.input(&reply(dhcp::ACK, rebind.xid, other, address), lease.t2 + 1);
    assert!(matches!(event, Some(dhcp::Event::Renewed(_))));
}

#[test]
fn dhcp_accepts_replies_without_server_identifier() {
    let mac = MacAddr([0x52, 0x54, 0, 0, 0, 9]);
    let server = Ipv4Addr::new(10, 0, 2, 2);
    let address = Ipv4Addr::new(10, 0, 2, 15);
    for kind in [dhcp::ACK, dhcp::NAK] {
        let mut client = dhcp::Client::new(mac, 7, "osyx");
        let xid = dhcp::Message::parse(&client.poll(0).0.unwrap().payload).unwrap().xid;
        let reply = |kind| dhcp::build_reply(kind, xid, mac, address, server, Ipv4Addr::new(255, 255, 255, 0), server, server, 120);
        client.input(&reply(dhcp::OFFER), 10);
        let mut reply = reply(kind);
        reply.drain(243..249);
        assert_eq!(dhcp::Message::parse(&reply).unwrap().server_id, None);
        let (_, event) = client.input(&reply, 20);
        if kind == dhcp::ACK {
            assert!(matches!(event, Some(dhcp::Event::Bound(_))));
        } else {
            assert_eq!((event, client.phase()), (None, dhcp::Phase::Init));
        }
    }
}

#[test]
fn dhcp_uses_ordered_lease_timers() {
    let mac = MacAddr([0x52, 0x54, 0, 0, 0, 9]);
    let server = Ipv4Addr::new(10, 0, 2, 2);
    let address = Ipv4Addr::new(10, 0, 2, 15);
    for (t1, t2, expected) in [(110, None, (60, 105)), (100, Some(90), (60, 105)), (0, Some(90), (60, 105)), (30, Some(90), (30, 90))] {
        let mut client = dhcp::Client::new(mac, 7, "osyx");
        let xid = dhcp::Message::parse(&client.poll(0).0.unwrap().payload).unwrap().xid;
        let reply = |kind| dhcp::build_reply(kind, xid, mac, address, server, Ipv4Addr::new(255, 255, 255, 0), server, server, 120);
        client.input(&reply(dhcp::OFFER), 10);
        let mut ack = reply(dhcp::ACK);
        ack.pop();
        ack.extend_from_slice(&[58, 4]);
        ack.extend_from_slice(&(t1 as u32).to_be_bytes());
        if let Some(t2) = t2 { ack.extend_from_slice(&[59, 4]); ack.extend_from_slice(&(t2 as u32).to_be_bytes()); }
        ack.push(255);
        let (_, event) = client.input(&ack, 20);
        let Some(dhcp::Event::Bound(lease)) = event else { panic!("expected lease") };
        assert_eq!((lease.t1, lease.t2), (20 + expected.0 * 1000, 20 + expected.1 * 1000));
    }
}

fn dns_response(id: u16, name: &str, answers: &[(&str, u16, &[u8])], rcode: u8, tc: bool) -> Vec<u8> {
    let mut m = dns::build_query(id, name, dns::TYPE_A);
    m[2] = 0x81 | if tc { 0x02 } else { 0 };
    m[3] = 0x80 | rcode;
    m[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    for (n, t, data) in answers {
        for l in n.split('.') {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&t.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&300u32.to_be_bytes());
        m.extend_from_slice(&(data.len() as u16).to_be_bytes());
        m.extend_from_slice(data);
    }
    m
}

fn encode_name(n: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for l in n.split('.') {
        v.push(l.len() as u8);
        v.extend_from_slice(l.as_bytes());
    }
    v.push(0);
    v
}

#[test]
fn dns_names_and_responses_parse_with_compression() {
    assert_eq!(dns::normalize("Example.COM."), Some("example.com".into()));
    assert_eq!(dns::normalize("bad..name"), None);
    assert_eq!(dns::normalize(&"a".repeat(64)), None);
    assert_eq!(dns::normalize("spa ce.com"), None);
    let target = encode_name("edge.example.net");
    let r = dns_response(
        0x4242,
        "www.example.com",
        &[("www.example.com", dns::TYPE_CNAME, &target), ("edge.example.net", dns::TYPE_A, &[93, 184, 215, 14])],
        0,
        false,
    );
    let resp = dns::parse_response(&r, 0x4242, "www.example.com", dns::TYPE_A).unwrap();
    assert_eq!(resp.answers.len(), 2);
    let a = dns::chase("www.example.com", &resp.answers).unwrap().unwrap();
    assert_eq!(a.addrs, vec![Ipv4Addr::new(93, 184, 215, 14)]);
    assert_eq!(a.canonical, "edge.example.net");
    // A compression pointer back to the question name.
    let mut c = dns::build_query(1, "example.com", dns::TYPE_A);
    c[2] = 0x81;
    c[3] = 0x80;
    c[7] = 1;
    c.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
    let resp = dns::parse_response(&c, 1, "example.com", dns::TYPE_A).unwrap();
    assert_eq!(resp.answers[0].name, "example.com");
    assert_eq!(resp.answers[0].data, dns::Data::A(Ipv4Addr::new(1, 2, 3, 4)));
}

#[test]
fn dns_rejects_malformed_and_spoofed_responses() {
    let ok = dns_response(7, "example.com", &[("example.com", dns::TYPE_A, &[1, 2, 3, 4])], 0, false);
    assert_eq!(dns::parse_response(&ok, 8, "example.com", dns::TYPE_A), Err(dns::DnsError::IdMismatch));
    assert_eq!(dns::parse_response(&ok, 7, "example.org", dns::TYPE_A), Err(dns::DnsError::QuestionMismatch));
    let mut query = ok.clone();
    query[2] &= 0x7F;
    assert_eq!(dns::parse_response(&query, 7, "example.com", dns::TYPE_A), Err(dns::DnsError::NotAResponse));
    assert_eq!(dns::parse_response(&ok[..ok.len() - 2], 7, "example.com", dns::TYPE_A), Err(dns::DnsError::Truncated));
    // A pointer to itself, and one pointing forward.
    let mut looped = dns::build_query(9, "example.com", dns::TYPE_A);
    looped[2] = 0x81;
    looped[7] = 1;
    let at = looped.len();
    looped.extend_from_slice(&[0xC0 | (at >> 8) as u8, at as u8, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 1, 1, 1]);
    assert_eq!(dns::parse_response(&looped, 9, "example.com", dns::TYPE_A), Err(dns::DnsError::BadPointer));
    let mut forward = dns::build_query(9, "example.com", dns::TYPE_A);
    forward[2] = 0x81;
    forward[7] = 1;
    forward.extend_from_slice(&[0xC0, 0xFF, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 1, 1, 1]);
    assert_eq!(dns::parse_response(&forward, 9, "example.com", dns::TYPE_A), Err(dns::DnsError::BadPointer));
    // A record with a wrong data length.
    let short = dns_response(7, "example.com", &[("example.com", dns::TYPE_A, &[1, 2, 3])], 0, false);
    assert_eq!(dns::parse_response(&short, 7, "example.com", dns::TYPE_A), Err(dns::DnsError::Truncated));
    let target = encode_name("edge.example.net");
    let mut cname = dns_response(7, "example.com", &[("example.com", dns::TYPE_CNAME, &target)], 0, false);
    let rdata = dns::build_query(7, "example.com", dns::TYPE_A).len() + encode_name("example.com").len() + 10;
    cname[rdata - 2..rdata].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(dns::parse_response(&cname, 7, "example.com", dns::TYPE_A), Err(dns::DnsError::Truncated));
    // CNAME loops are detected.
    let (x, y) = (encode_name("b.test"), encode_name("a.test"));
    let looped = dns_response(3, "a.test", &[("a.test", dns::TYPE_CNAME, &x), ("b.test", dns::TYPE_CNAME, &y)], 0, false);
    let r = dns::parse_response(&looped, 3, "a.test", dns::TYPE_A).unwrap();
    assert_eq!(dns::chase("a.test", &r.answers), Err(dns::DnsError::CnameLoop));
    // Random garbage never panics.
    let mut seed = 0x1234_5678u32;
    for _ in 0..2000 {
        let len = (seed % 300) as usize;
        let mut buf: Vec<u8> = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect();
        if buf.len() > 4 {
            buf[2] |= 0x80;
        }
        let _ = dns::parse_response(&buf, 0, "example.com", dns::TYPE_A);
    }
}

#[test]
fn dns_cache_honours_ttl_and_bounds() {
    let mut c = dns::Cache::new();
    c.put("a.test", vec![Ipv4Addr::new(1, 1, 1, 1)], 10, 0);
    assert_eq!(c.get("a.test", 9_000), Some(vec![Ipv4Addr::new(1, 1, 1, 1)]));
    assert_eq!(c.get("a.test", 10_001), None);
    c.put("gone.test", vec![], 1, 0);
    assert_eq!(c.get("gone.test", 4_000), Some(vec![]), "negative entries, at least MIN_TTL");
    for i in 0..500 {
        c.put(&format!("n{i}.test"), vec![Ipv4Addr::new(1, 0, 0, 1)], 3600, 0);
    }
    assert!(c.entries(0).len() <= dns::CACHE_ENTRIES);
}

#[test]
fn random_packets_never_panic_the_parsers() {
    let mut seed = 0xC0FF_EE11u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    let (s, d) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    for _ in 0..5000 {
        let len = (next() % 1600) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if !buf.is_empty() && next() % 2 == 0 {
            buf[0] = 0x45;
        }
        let _ = ethernet::parse(&buf);
        let _ = arp::Packet::parse(&buf);
        let _ = ipv4::parse(&buf);
        let _ = ipv4::parse_quoted(&buf);
        let _ = icmp::parse(&buf);
        let _ = udp::parse(s, d, &buf);
        let _ = tcp::parse(s, d, &buf);
        let _ = dhcp::Message::parse(&buf);
    }
}
