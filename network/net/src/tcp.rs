//! TCP (RFC 9293, the consolidated RFC 793) connections.
//!
//! [`Tcb`] is one connection's state machine. It is driven by three inputs
//! â€” arriving segments ([`Tcb::input`]), application calls (`send`, `recv`,
//! `close`, `abort`) and time ([`Tcb::poll`]) â€” and produces outgoing
//! segments through [`Tcb::output`]. It knows nothing about IP or sockets;
//! the stack routes segments to it by their address pair.
//!
//! Implemented:
//! * all eleven states, active and passive open, simultaneous open and
//!   close, TIME-WAIT for [`TIME_WAIT_MS`]
//! * MSS and window scale options (both sent on SYN, honoured from the
//!   peer); other options are parsed and ignored
//! * retransmission with RTO estimation (RFC 6298: SRTT/RTTVAR, Karn's
//!   algorithm, exponential back-off, [`MAX_RETRIES`] then the connection
//!   fails with [`TcpError::TimedOut`])
//! * Reno congestion control (RFC 5681: slow start, congestion avoidance,
//!   fast retransmit after three duplicate ACKs, fast recovery)
//! * flow control: the advertised receive window tracks free buffer space,
//!   window updates when the application reads, zero-window probing
//! * out-of-order segments buffered (bounded by the window) and merged,
//!   duplicates and old segments discarded with an ACK
//! * RFC 5961 checks for RST and SYN in synchronised states (challenge ACK)
//!
//! Not implemented: timestamps, SACK, urgent data (the URG flag is
//! ignored), delayed ACKs (every data segment is acknowledged when the
//! stack next flushes output), keep-alive.

use crate::ipv4::PROTO_TCP;
use crate::wire::{be16, be32, put16, put32, transport_checksum, Endpoint, Ipv4Addr};
use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub const HEADER_LEN: usize = 20;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

/// MSS assumed when the peer sends none (RFC 9293 3.7.1).
pub const DEFAULT_MSS: u16 = 536;
/// Bytes buffered in each direction. The receive buffer is larger than the
/// 64 KiB a window field can express; the window scale option advertises it,
/// so a busy application (a browser parsing a page) does not stall the peer.
pub const SEND_BUFFER: usize = 64 * 1024;
pub const RECV_BUFFER: usize = 256 * 1024;
/// Window scale shift announced in our SYN (RFC 7323). A larger receive
/// buffer needs a larger shift: the field is `window >> shift`.
pub const WINDOW_SCALE: u8 = 8;
pub const INITIAL_RTO_MS: u64 = 1_000;
pub const MIN_RTO_MS: u64 = 200;
pub const MAX_RTO_MS: u64 = 30_000;
/// Retransmissions of one segment before the connection fails.
pub const MAX_RETRIES: u32 = 8;
/// SYN retransmissions before `connect` fails.
pub const MAX_SYN_RETRIES: u32 = 5;
pub const TIME_WAIT_MS: u64 = 20_000;
/// Out-of-order segments kept at most.
pub const MAX_OOO_SEGMENTS: usize = 64;

/// Sequence number comparison modulo 2^32.
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

pub fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}

pub fn seq_ge(a: u32, b: u32) -> bool {
    seq_le(b, a)
}

/// A parsed segment (borrowing its payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    /// Window scale shift from a SYN's WS option.
    pub ws: Option<u8>,
    pub payload: &'a [u8],
}

impl Segment<'_> {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// Sequence space the segment occupies (SYN and FIN count as one).
    pub fn seq_len(&self) -> u32 {
        self.payload.len() as u32 + self.has(SYN) as u32 + self.has(FIN) as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentError {
    Truncated,
    BadOffset,
    BadChecksum,
    BadOption,
    ZeroPort,
}

pub fn parse(src: Ipv4Addr, dst: Ipv4Addr, b: &[u8]) -> Result<Segment<'_>, SegmentError> {
    if b.len() < HEADER_LEN {
        return Err(SegmentError::Truncated);
    }
    let off = (b[12] >> 4) as usize * 4;
    if off < HEADER_LEN || off > b.len() {
        return Err(SegmentError::BadOffset);
    }
    if transport_checksum(src, dst, PROTO_TCP, b) != 0 {
        return Err(SegmentError::BadChecksum);
    }
    let mut mss = None;
    let mut ws = None;
    let mut opts = &b[HEADER_LEN..off];
    while let Some(&kind) = opts.first() {
        match kind {
            0 => break,
            1 => opts = &opts[1..],
            _ => {
                let len = *opts.get(1).ok_or(SegmentError::BadOption)? as usize;
                if len < 2 || len > opts.len() {
                    return Err(SegmentError::BadOption);
                }
                if kind == 2 {
                    if len != 4 {
                        return Err(SegmentError::BadOption);
                    }
                    mss = Some(be16(opts, 2));
                } else if kind == 3 {
                    if len != 3 {
                        return Err(SegmentError::BadOption);
                    }
                    ws = Some(opts[2].min(14));
                }
                opts = &opts[len..];
            }
        }
    }
    let seg = Segment {
        src_port: be16(b, 0),
        dst_port: be16(b, 2),
        seq: be32(b, 4),
        ack: be32(b, 8),
        flags: b[13] & 0x3F,
        window: be16(b, 14),
        mss,
        ws,
        payload: &b[off..],
    };
    if seg.src_port == 0 || seg.dst_port == 0 {
        return Err(SegmentError::ZeroPort);
    }
    Ok(seg)
}

/// An outgoing segment produced by a [`Tcb`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutSegment {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    /// Window scale shift to announce in this segment's options (SYN only).
    pub ws: Option<u8>,
    pub payload: Vec<u8>,
}

impl OutSegment {
    pub fn encode(&self, local: Endpoint, remote: Endpoint) -> Vec<u8> {
        build(local, remote, self.seq, self.ack, self.flags, self.window, self.mss, self.ws, &self.payload)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    local: Endpoint,
    remote: Endpoint,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    ws: Option<u8>,
    payload: &[u8],
) -> Vec<u8> {
    // MSS (4 bytes) + WS (3 bytes) + END (1 byte) always fits the 4-byte
    // option alignment.
    let opt_len = if mss.is_some() && ws.is_some() {
        8
    } else if mss.is_some() || ws.is_some() {
        4
    } else {
        0
    };
    let hl = HEADER_LEN + opt_len;
    let mut s = alloc::vec![0u8; hl + payload.len()];
    put16(&mut s, 0, local.port);
    put16(&mut s, 2, remote.port);
    put32(&mut s, 4, seq);
    put32(&mut s, 8, ack);
    s[12] = ((hl / 4) as u8) << 4;
    s[13] = flags;
    put16(&mut s, 14, window);
    let mut o = HEADER_LEN;
    if let Some(m) = mss {
        s[o] = 2;
        s[o + 1] = 4;
        put16(&mut s, o + 2, m);
        o += 4;
    }
    if let Some(shift) = ws {
        s[o] = 3;
        s[o + 1] = 3;
        s[o + 2] = shift;
        o += 3;
        if mss.is_none() {
            s[o] = 0;
        }
    }
    s[hl..].copy_from_slice(payload);
    let c = transport_checksum(local.addr, remote.addr, PROTO_TCP, &s);
    put16(&mut s, 16, c);
    s
}

/// The reset answering a segment that belongs to no connection (RFC 9293
/// 3.10.7.1); `None` if the segment is itself a reset.
pub fn reset_for(seg: &Segment) -> Option<OutSegment> {
    if seg.has(RST) {
        return None;
    }
    Some(if seg.has(ACK) {
        OutSegment { seq: seg.ack, ack: 0, flags: RST, window: 0, mss: None, ws: None, payload: Vec::new() }
    } else {
        OutSegment { seq: 0, ack: seg.seq.wrapping_add(seg.seq_len()), flags: RST | ACK, window: 0, mss: None, ws: None, payload: Vec::new() }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Closed => "CLOSED",
            State::Listen => "LISTEN",
            State::SynSent => "SYN-SENT",
            State::SynReceived => "SYN-RECEIVED",
            State::Established => "ESTABLISHED",
            State::FinWait1 => "FIN-WAIT-1",
            State::FinWait2 => "FIN-WAIT-2",
            State::CloseWait => "CLOSE-WAIT",
            State::Closing => "CLOSING",
            State::LastAck => "LAST-ACK",
            State::TimeWait => "TIME-WAIT",
        }
    }

    fn synchronized(self) -> bool {
        !matches!(self, State::Closed | State::Listen | State::SynSent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpError {
    /// The peer answered the SYN with a reset.
    Refused,
    /// The peer reset an established connection.
    Reset,
    /// Retransmissions ran out.
    TimedOut,
    /// The connection is closed (or the call does not fit its state).
    NotConnected,
    /// Sending after `close`.
    Closed,
    WouldBlock,
}

/// Counters per connection (also summed by the stack).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub segments_in: u64,
    pub segments_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub retransmits: u64,
    pub fast_retransmits: u64,
    pub out_of_order: u64,
    pub duplicates: u64,
}

pub struct Tcb {
    pub local: Endpoint,
    pub remote: Endpoint,
    state: State,
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence number sent (snd_nxt may be rewound on timeout).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    irs: u32,
    rcv_nxt: u32,
    /// Unacknowledged and unsent data, starting at `snd_una` (after the SYN).
    send_buf: VecDeque<u8>,
    recv_buf: VecDeque<u8>,
    /// (seq, data, fin) received ahead of `rcv_nxt`.
    ooo: Vec<(u32, Vec<u8>, bool)>,
    /// The application called `close`: a FIN follows the data.
    fin_queued: bool,
    /// Sequence number of our FIN once it has been sent.
    fin_sent: Option<u32>,
    fin_received: bool,
    /// Our MSS (from the interface MTU) and the peer's.
    our_mss: u16,
    peer_mss: u16,
    /// Window scale shifts: ours (announced in the SYN) and the peer's
    /// (applied to every window field it sends after the handshake).
    our_scale: u8,
    peer_scale: u8,
    srtt: Option<u64>,
    rttvar: u64,
    rto: u64,
    /// RTT sample in progress: (sequence number to be acked, send time).
    rtt_probe: Option<(u32, u64)>,
    retransmit_at: Option<u64>,
    retries: u32,
    persist_at: Option<u64>,
    cwnd: u32,
    ssthresh: u32,
    dup_acks: u32,
    /// Fast recovery until this sequence number is acknowledged.
    recover: Option<u32>,
    time_wait_until: Option<u64>,
    ack_pending: bool,
    last_adv_wnd: u32,
    /// A reset to send in reply to an unacceptable segment.
    reset_reply: Option<OutSegment>,
    error: Option<TcpError>,
    pub stats: Stats,
    /// Set whenever something the application may wait for changed.
    pub changed: bool,
}

impl Tcb {
    fn new(local: Endpoint, remote: Endpoint, iss: u32, our_mss: u16, state: State) -> Tcb {
        Tcb {
            local,
            remote,
            state,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_max: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            irs: 0,
            rcv_nxt: 0,
            send_buf: VecDeque::new(),
            recv_buf: VecDeque::new(),
            ooo: Vec::new(),
            fin_queued: false,
            fin_sent: None,
            fin_received: false,
            our_mss,
            peer_mss: DEFAULT_MSS,
            our_scale: WINDOW_SCALE,
            peer_scale: 0,
            srtt: None,
            rttvar: 0,
            rto: INITIAL_RTO_MS,
            rtt_probe: None,
            retransmit_at: None,
            retries: 0,
            persist_at: None,
            cwnd: 0,
            ssthresh: u32::MAX,
            dup_acks: 0,
            recover: None,
            time_wait_until: None,
            ack_pending: false,
            last_adv_wnd: RECV_BUFFER as u32,
            reset_reply: None,
            error: None,
            stats: Stats::default(),
            changed: false,
        }
    }

    /// Active open: the SYN goes out on the next `output`.
    pub fn connect(local: Endpoint, remote: Endpoint, iss: u32, our_mss: u16) -> Tcb {
        Tcb::new(local, remote, iss, our_mss, State::SynSent)
    }

    /// Passive open from a listener that received `syn` (which must carry
    /// SYN and no ACK/RST). The SYN-ACK goes out on the next `output`.
    pub fn accept(local: Endpoint, remote: Endpoint, syn: &Segment, iss: u32, our_mss: u16, now: u64) -> Tcb {
        let mut t = Tcb::new(local, remote, iss, our_mss, State::SynReceived);
        t.irs = syn.seq;
        t.rcv_nxt = syn.seq.wrapping_add(1);
        t.peer_mss = syn.mss.unwrap_or(DEFAULT_MSS).max(64);
        t.peer_scale = syn.ws.unwrap_or(0);
        // Scaling only takes effect when both sides offered WS.
        if syn.ws.is_none() {
            t.our_scale = 0;
        }
        // RFC 7323 2.2: the window in the SYN itself is not scaled.
        t.snd_wnd = syn.window as u32;
        t.snd_wl1 = syn.seq;
        t.init_cwnd();
        t.stats.segments_in += 1;
        let _ = now;
        t
    }

    fn init_cwnd(&mut self) {
        // RFC 5681 initial window: up to four segments for small MSS.
        let mss = self.mss() as u32;
        self.cwnd = if mss > 2190 { 2 * mss } else if mss > 1095 { 3 * mss } else { 4 * mss };
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn error(&self) -> Option<TcpError> {
        self.error
    }

    /// Takes the pending error, as `getsockopt(SO_ERROR)` does.
    pub fn take_error(&mut self) -> Option<TcpError> {
        self.error.take()
    }

    /// Effective sending MSS.
    pub fn mss(&self) -> u16 {
        self.peer_mss.min(self.our_mss)
    }

    pub fn rto_ms(&self) -> u64 {
        self.rto
    }

    pub fn srtt_ms(&self) -> Option<u64> {
        self.srtt
    }

    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    pub fn send_queue(&self) -> usize {
        self.send_buf.len()
    }

    pub fn recv_queue(&self) -> usize {
        self.recv_buf.len()
    }

    fn set_state(&mut self, s: State) {
        if self.state != s {
            self.state = s;
            self.changed = true;
        }
    }

    fn fail(&mut self, e: TcpError) {
        self.error = Some(e);
        self.set_state(State::Closed);
        self.send_buf.clear();
        self.ooo.clear();
        self.retransmit_at = None;
        self.persist_at = None;
        self.changed = true;
    }

    fn rcv_wnd(&self) -> u32 {
        (RECV_BUFFER - self.recv_buf.len()) as u32
    }

    fn adv_window(&mut self) -> u16 {
        // `last_adv_wnd` stays in bytes; only the field is scaled.
        let w = self.rcv_wnd();
        self.last_adv_wnd = w;
        (w >> self.our_scale).min(u16::MAX as u32) as u16
    }

    /// A window field received after the handshake, in bytes.
    fn peer_window(&self, field: u16) -> u32 {
        (field as u32) << self.peer_scale
    }

    /// Sequence number of our FIN (valid when `fin_queued`).
    fn fin_seq(&self) -> u32 {
        self.data_start().wrapping_add(self.send_buf.len() as u32)
    }

    /// Sequence number of the first byte in `send_buf`.
    fn data_start(&self) -> u32 {
        if self.snd_una == self.iss {
            self.iss.wrapping_add(1) // the SYN is not acknowledged yet
        } else {
            self.snd_una
        }
    }

    fn our_fin_acked(&self) -> bool {
        self.fin_sent.is_some_and(|f| seq_gt(self.snd_una, f))
    }

    /// The FIN still has to go out (first time or retransmission).
    fn fin_pending(&self) -> bool {
        self.fin_queued && !self.our_fin_acked() && self.snd_nxt == self.fin_seq()
    }

    // ----- application side -------------------------------------------

    /// Queues data; returns how much fitted.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, TcpError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        match self.state {
            State::Established | State::CloseWait | State::SynSent | State::SynReceived => {}
            State::Closed | State::Listen => return Err(TcpError::NotConnected),
            _ => return Err(TcpError::Closed),
        }
        if self.fin_queued {
            return Err(TcpError::Closed);
        }
        let room = SEND_BUFFER - self.send_buf.len();
        if room == 0 {
            return Err(TcpError::WouldBlock);
        }
        let n = room.min(data.len());
        self.send_buf.extend(&data[..n]);
        Ok(n)
    }

    /// Takes received data. `Ok(0)` is the end of the stream (the peer
    /// closed and everything was read).
    pub fn recv(&mut self, out: &mut [u8]) -> Result<usize, TcpError> {
        if !self.recv_buf.is_empty() {
            let n = out.len().min(self.recv_buf.len());
            for (o, b) in out.iter_mut().zip(self.recv_buf.drain(..n)) {
                *o = b;
            }
            // Window update once a useful amount of space opened up
            // (receiver-side silly window avoidance, RFC 9293 3.8.6.2.2).
            let mss = self.mss() as u32;
            let w = self.rcv_wnd();
            if w >= self.last_adv_wnd + mss.max(RECV_BUFFER as u32 / 4) || (self.last_adv_wnd < mss && w >= mss) {
                self.ack_pending = true;
            }
            return Ok(n);
        }
        if self.fin_received {
            return Ok(0);
        }
        if let Some(e) = self.error {
            return Err(e);
        }
        match self.state {
            State::Closed | State::Listen => Err(TcpError::NotConnected),
            _ => Err(TcpError::WouldBlock),
        }
    }

    /// Like [`Tcb::recv`], but leaves the data queued (`MSG_PEEK`).
    pub fn peek(&self, out: &mut [u8]) -> Result<usize, TcpError> {
        if !self.recv_buf.is_empty() {
            let n = out.len().min(self.recv_buf.len());
            for (o, b) in out.iter_mut().zip(self.recv_buf.iter().take(n)) {
                *o = *b;
            }
            return Ok(n);
        }
        if self.fin_received {
            return Ok(0);
        }
        if let Some(e) = self.error {
            return Err(e);
        }
        match self.state {
            State::Closed | State::Listen => Err(TcpError::NotConnected),
            _ => Err(TcpError::WouldBlock),
        }
    }

    /// No more data will be sent: a FIN follows what is queued.
    pub fn close(&mut self) {
        match self.state {
            State::SynSent | State::Listen => self.set_state(State::Closed),
            State::SynReceived | State::Established => {
                self.fin_queued = true;
                self.set_state(State::FinWait1);
            }
            State::CloseWait => {
                self.fin_queued = true;
                self.set_state(State::LastAck);
            }
            _ => {}
        }
    }

    /// Drops the connection with a reset (returned for sending, if the
    /// peer knows the connection).
    pub fn abort(&mut self) -> Option<OutSegment> {
        let rst = self.state.synchronized().then(|| OutSegment {
            seq: self.snd_nxt,
            ack: 0,
            flags: RST,
            window: 0,
            mss: None,
            ws: None,
            payload: Vec::new(),
        });
        self.fail(TcpError::NotConnected);
        self.error = None;
        rst
    }

    pub fn readable(&self) -> bool {
        !self.recv_buf.is_empty() || self.fin_received || self.error.is_some()
    }

    /// TEMP: flow-control snapshot for the periodic stats.
    pub fn debug_line(&self) -> alloc::string::String {
        alloc::format!(
            ":{} rxq={} adv={} ws={}/{} sndw={} cwnd={} srtt={:?} in={} out={} ooo={} dup={} rt={}",
            self.remote.port,
            self.recv_buf.len(),
            self.rcv_wnd(),
            self.our_scale,
            self.peer_scale,
            self.snd_wnd,
            self.cwnd,
            self.srtt,
            self.stats.bytes_in,
            self.stats.bytes_out,
            self.stats.out_of_order,
            self.stats.duplicates,
            self.stats.retransmits,
        )
    }

    pub fn writable(&self) -> bool {
        self.error.is_some()
            || (matches!(self.state, State::Established | State::CloseWait) && !self.fin_queued && self.send_buf.len() < SEND_BUFFER)
    }

    /// The handshake is done (or failed).
    pub fn connected(&self) -> bool {
        self.state.synchronized() && self.state != State::SynReceived
    }

    /// Nothing left to do: the stack may forget this connection.
    pub fn finished(&self) -> bool {
        self.state == State::Closed
    }

    // ----- segment arrival ----------------------------------------------

    /// Processes one segment addressed to this connection.
    pub fn input(&mut self, seg: &Segment, now: u64) {
        self.stats.segments_in += 1;
        match self.state {
            State::Closed | State::Listen => {}
            State::SynSent => self.input_syn_sent(seg, now),
            _ => self.input_synchronized(seg, now),
        }
    }

    fn input_syn_sent(&mut self, seg: &Segment, now: u64) {
        if seg.has(ACK) && (seq_le(seg.ack, self.iss) || seq_gt(seg.ack, self.snd_max)) {
            // Not for this connection attempt; RFC 9293 answers with a
            // reset, which the stack sends for the caller.
            if !seg.has(RST) {
                self.reset_reply = Some(OutSegment { seq: seg.ack, ack: 0, flags: RST, window: 0, mss: None, ws: None, payload: Vec::new() });
            }
            return;
        }
        if seg.has(RST) {
            if seg.has(ACK) {
                self.fail(TcpError::Refused);
            }
            return;
        }
        if !seg.has(SYN) {
            return;
        }
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.peer_mss = seg.mss.unwrap_or(DEFAULT_MSS).max(64);
        self.peer_scale = seg.ws.unwrap_or(0);
        if seg.ws.is_none() {
            self.our_scale = 0;
        }
        self.init_cwnd();
        self.snd_wnd = seg.window as u32;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        if seg.has(ACK) {
            self.ack_advance(seg.ack, now);
            self.set_state(State::Established);
            self.ack_pending = true;
        } else {
            // Simultaneous open: answer with SYN-ACK (retransmit the SYN).
            self.set_state(State::SynReceived);
            self.snd_nxt = self.iss;
        }
    }

    /// Whether `seg` falls into the receive window (RFC 9293 3.10.7.4).
    fn acceptable(&self, seg: &Segment) -> bool {
        let wnd = self.rcv_wnd();
        let len = seg.seq_len();
        let in_window = |s: u32| seq_le(self.rcv_nxt, s) && seq_lt(s, self.rcv_nxt.wrapping_add(wnd));
        match (len, wnd) {
            (0, 0) => seg.seq == self.rcv_nxt,
            (0, _) => in_window(seg.seq),
            (_, 0) => false,
            _ => in_window(seg.seq) || in_window(seg.seq.wrapping_add(len - 1)),
        }
    }

    fn input_synchronized(&mut self, seg: &Segment, now: u64) {
        if !self.acceptable(seg) {
            // Old duplicate or beyond the window: re-acknowledge (unless RST).
            if !seg.has(RST) {
                if seg.seq_len() > 0 {
                    self.stats.duplicates += 1;
                }
                self.ack_pending = true;
            }
            // A zero-window probe still carries a window update.
            if seg.has(ACK) && self.state.synchronized() {
                self.window_update(seg);
            }
            return;
        }
        if seg.has(RST) {
            // RFC 5961 3.2: only an exact match resets; others get a challenge ACK.
            if seg.seq == self.rcv_nxt {
                if self.state == State::SynReceived {
                    self.fail(TcpError::Refused);
                } else if matches!(self.state, State::Closing | State::LastAck | State::TimeWait) {
                    self.set_state(State::Closed);
                } else {
                    self.fail(TcpError::Reset);
                }
            } else {
                self.ack_pending = true;
            }
            return;
        }
        if seg.has(SYN) {
            if self.state == State::SynReceived && seg.seq == self.irs {
                // Our SYN-ACK was lost: the SYN is retransmitted.
                self.snd_nxt = self.iss;
                return;
            }
            // RFC 5961 4.2: challenge ACK.
            self.ack_pending = true;
            return;
        }
        if !seg.has(ACK) {
            return;
        }
        if self.state == State::SynReceived {
            if seq_lt(self.snd_una, seg.ack) && seq_le(seg.ack, self.snd_max) {
                self.set_state(State::Established);
                self.snd_wnd = self.peer_window(seg.window);
                self.snd_wl1 = seg.seq;
                self.snd_wl2 = seg.ack;
            } else {
                self.reset_reply = Some(OutSegment { seq: seg.ack, ack: 0, flags: RST, window: 0, mss: None, ws: None, payload: Vec::new() });
                return;
            }
        }
        self.process_ack(seg, now);
        if self.state == State::Closed {
            return;
        }
        if !seg.payload.is_empty() || seg.has(FIN) {
            self.process_data(seg, now);
        }
    }

    fn window_update(&mut self, seg: &Segment) {
        if seq_lt(self.snd_wl1, seg.seq) || (self.snd_wl1 == seg.seq && seq_le(self.snd_wl2, seg.ack)) {
            let old = self.snd_wnd;
            self.snd_wnd = self.peer_window(seg.window);
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
            if old == 0 && self.snd_wnd > 0 {
                self.persist_at = None;
            }
        }
    }

    /// Moves `snd_una` to `ack`, dropping acknowledged data.
    fn ack_advance(&mut self, ack: u32, now: u64) {
        let mut acked = ack.wrapping_sub(self.snd_una);
        if self.snd_una == self.iss && acked > 0 {
            acked -= 1; // the SYN
        }
        let data = (acked as usize).min(self.send_buf.len());
        self.send_buf.drain(..data);
        self.snd_una = ack;
        if seq_lt(self.snd_nxt, ack) {
            self.snd_nxt = ack;
        }
        if let Some((s, t)) = self.rtt_probe {
            if seq_ge(ack, s) {
                self.rtt_sample(now.saturating_sub(t));
                self.rtt_probe = None;
            }
        }
        self.retries = 0;
        self.retransmit_at = if self.snd_una == self.snd_max { None } else { Some(now + self.rto) };
        if data > 0 {
            self.changed = true; // room in the send buffer
        }
    }

    /// RFC 6298 2.2-2.4.
    fn rtt_sample(&mut self, r: u64) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(s) => {
                let delta = s.abs_diff(r);
                self.rttvar = (3 * self.rttvar + delta) / 4;
                self.srtt = Some((7 * s + r) / 8);
            }
        }
        let srtt = self.srtt.unwrap_or(r);
        self.rto = (srtt + (4 * self.rttvar).max(10)).clamp(MIN_RTO_MS, MAX_RTO_MS);
    }

    fn flight(&self) -> u32 {
        self.snd_max.wrapping_sub(self.snd_una)
    }

    fn process_ack(&mut self, seg: &Segment, now: u64) {
        let mss = self.mss() as u32;
        if seq_gt(seg.ack, self.snd_max) {
            // Acknowledges something never sent.
            self.ack_pending = true;
            return;
        }
        if seq_gt(seg.ack, self.snd_una) {
            let newly = seg.ack.wrapping_sub(self.snd_una);
            self.ack_advance(seg.ack, now);
            match self.recover {
                Some(r) if seq_lt(seg.ack, r) => {
                    // Partial ACK in fast recovery: retransmit the next hole.
                    self.snd_nxt = self.snd_una;
                    self.cwnd = self.cwnd.saturating_sub(newly).max(mss) + mss;
                }
                Some(_) => {
                    self.recover = None;
                    self.cwnd = self.ssthresh.max(mss);
                }
                None if self.cwnd < self.ssthresh => self.cwnd = self.cwnd.saturating_add(newly.min(mss)),
                None => self.cwnd = self.cwnd.saturating_add((mss * mss / self.cwnd.max(1)).max(1)),
            }
            self.dup_acks = 0;
        } else if seg.ack == self.snd_una
            && seg.payload.is_empty()
            && !seg.has(FIN)
            && self.peer_window(seg.window) == self.snd_wnd
            && self.snd_max != self.snd_una
        {
            self.dup_acks += 1;
            if self.dup_acks == 3 && self.recover.is_none() {
                // Fast retransmit (RFC 5681 3.2).
                self.ssthresh = (self.flight() / 2).max(2 * mss);
                self.cwnd = self.ssthresh + 3 * mss;
                self.recover = Some(self.snd_max);
                self.snd_nxt = self.snd_una;
                self.rtt_probe = None;
                self.stats.fast_retransmits += 1;
            } else if self.dup_acks > 3 {
                self.cwnd = self.cwnd.saturating_add(mss);
            }
        }
        self.window_update(seg);
        if self.our_fin_acked() {
            match self.state {
                State::FinWait1 => self.set_state(State::FinWait2),
                State::Closing => self.enter_time_wait(now),
                State::LastAck => self.set_state(State::Closed),
                _ => {}
            }
        }
        if self.state == State::TimeWait && seg.has(FIN) {
            // Retransmitted FIN: acknowledge and restart the timer.
            self.ack_pending = true;
            self.time_wait_until = Some(now + TIME_WAIT_MS);
        }
    }

    fn enter_time_wait(&mut self, now: u64) {
        self.set_state(State::TimeWait);
        self.time_wait_until = Some(now + TIME_WAIT_MS);
        self.retransmit_at = None;
    }

    fn process_data(&mut self, seg: &Segment, now: u64) {
        if !matches!(self.state, State::Established | State::FinWait1 | State::FinWait2) {
            if seg.has(FIN) || !seg.payload.is_empty() {
                self.ack_pending = true;
            }
            return;
        }
        // Trim what was already received.
        let mut data = seg.payload;
        let mut seq = seg.seq;
        let mut syn_skip = seg.has(SYN) as u32;
        if seq_lt(seq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq);
            let skip_data = skip.saturating_sub(syn_skip) as usize;
            syn_skip = 0;
            if skip_data >= data.len() && !(seg.has(FIN) && skip_data == data.len()) {
                self.stats.duplicates += 1;
                self.ack_pending = true;
                return;
            }
            data = &data[skip_data.min(data.len())..];
            seq = self.rcv_nxt;
        }
        let seq = seq.wrapping_add(syn_skip);
        // Trim to the window.
        let wnd = self.rcv_wnd() as usize;
        let offset = seq.wrapping_sub(self.rcv_nxt) as usize;
        let mut fin = seg.has(FIN);
        if offset + data.len() > wnd {
            data = &data[..wnd.saturating_sub(offset)];
            fin = false;
        }
        self.ack_pending = true;
        if seq == self.rcv_nxt {
            self.deliver(data, fin, now);
            self.drain_ooo(now);
        } else {
            self.stats.out_of_order += 1;
            if self.ooo.len() < MAX_OOO_SEGMENTS && !self.ooo.iter().any(|(s, d, _)| *s == seq && d.len() >= data.len()) {
                self.ooo.push((seq, data.to_vec(), fin));
            }
        }
    }

    fn deliver(&mut self, data: &[u8], fin: bool, now: u64) {
        if !data.is_empty() {
            self.recv_buf.extend(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
            self.stats.bytes_in += data.len() as u64;
            self.changed = true;
        }
        if fin && !self.fin_received {
            self.fin_received = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.changed = true;
            match self.state {
                State::Established => self.set_state(State::CloseWait),
                State::FinWait1 => {
                    if self.our_fin_acked() {
                        self.enter_time_wait(now);
                    } else {
                        self.set_state(State::Closing);
                    }
                }
                State::FinWait2 => self.enter_time_wait(now),
                _ => {}
            }
        }
    }

    fn drain_ooo(&mut self, now: u64) {
        loop {
            let next = self.rcv_nxt;
            // Drop segments that are now entirely old.
            self.ooo.retain(|(s, d, f)| seq_gt(s.wrapping_add(d.len() as u32 + *f as u32), next));
            let Some(i) = self.ooo.iter().position(|(s, _, _)| seq_le(*s, next)) else { break };
            let (s, d, f) = self.ooo.swap_remove(i);
            let skip = next.wrapping_sub(s) as usize;
            if skip <= d.len() {
                let room = RECV_BUFFER - self.recv_buf.len();
                let part = &d[skip..];
                let take = part.len().min(room);
                self.deliver(&part[..take], f && take == part.len(), now);
            }
        }
    }

    // ----- timers ------------------------------------------------------------

    /// Runs the timers. Returns true if output may be needed.
    pub fn poll(&mut self, now: u64) -> bool {
        if let Some(t) = self.time_wait_until {
            if self.state == State::TimeWait && now >= t {
                self.set_state(State::Closed);
                self.time_wait_until = None;
            }
            if self.state == State::TimeWait {
                return self.ack_pending;
            }
        }
        if let Some(t) = self.retransmit_at {
            if now >= t {
                let limit = if self.state.synchronized() && self.state != State::SynReceived { MAX_RETRIES } else { MAX_SYN_RETRIES };
                if self.retries >= limit {
                    self.fail(TcpError::TimedOut);
                    return true;
                }
                self.retries += 1;
                self.stats.retransmits += 1;
                self.rto = (self.rto * 2).min(MAX_RTO_MS);
                let mss = self.mss() as u32;
                self.ssthresh = (self.flight() / 2).max(2 * mss);
                self.cwnd = mss;
                self.recover = None;
                self.dup_acks = 0;
                self.rtt_probe = None;
                self.snd_nxt = self.snd_una;
                self.retransmit_at = Some(now + self.rto);
                return true;
            }
        }
        if let Some(t) = self.persist_at {
            if now >= t {
                return true;
            }
        }
        self.ack_pending || self.wants_to_send()
    }

    fn wants_to_send(&self) -> bool {
        match self.state {
            State::SynSent | State::SynReceived => self.snd_nxt == self.iss,
            State::Established | State::CloseWait | State::FinWait1 | State::LastAck | State::Closing => {
                let sent = self.snd_nxt.wrapping_sub(self.data_start()) as usize;
                sent < self.send_buf.len() || self.fin_pending()
            }
            _ => false,
        }
    }

    /// Earliest time `poll` has work to do.
    pub fn next_deadline(&self) -> Option<u64> {
        [self.retransmit_at, self.persist_at, self.time_wait_until].into_iter().flatten().min()
    }

    // ----- output ------------------------------------------------------------

    fn segment(&mut self, seq: u32, flags: u8, payload: Vec<u8>) -> OutSegment {
        let mut flags = flags;
        let ack = if self.state == State::SynSent && flags & SYN != 0 {
            0
        } else {
            flags |= ACK;
            self.rcv_nxt
        };
        let mss = (flags & SYN != 0).then_some(self.our_mss);
        let ws = (flags & SYN != 0).then_some(self.our_scale);
        self.ack_pending = false;
        self.stats.segments_out += 1;
        // The SYN's own window is unscaled (RFC 7323 2.2).
        let window = if flags & SYN != 0 {
            self.last_adv_wnd = self.rcv_wnd();
            self.last_adv_wnd.min(u16::MAX as u32) as u16
        } else {
            self.adv_window()
        };
        OutSegment { seq, ack, flags, window, mss, ws, payload }
    }

    /// Segments to transmit now (SYN, data, FIN, retransmissions, ACKs).
    pub fn output(&mut self, now: u64) -> Vec<OutSegment> {
        let mut out = Vec::new();
        if let Some(r) = self.reset_reply.take() {
            out.push(r);
        }
        match self.state {
            State::Closed | State::Listen => return out,
            State::SynSent | State::SynReceived => {
                if self.snd_nxt == self.iss {
                    let flags = if self.state == State::SynSent { SYN } else { SYN | ACK };
                    let seg = self.segment(self.iss, flags, Vec::new());
                    out.push(seg);
                    self.snd_nxt = self.iss.wrapping_add(1);
                    if seq_gt(self.snd_nxt, self.snd_max) {
                        self.snd_max = self.snd_nxt;
                    }
                    if self.retransmit_at.is_none() {
                        self.retransmit_at = Some(now + self.rto);
                    }
                    if self.rtt_probe.is_none() && self.retries == 0 {
                        self.rtt_probe = Some((self.snd_nxt, now));
                    }
                } else if self.ack_pending && self.state == State::SynReceived {
                    let seg = self.segment(self.snd_nxt, 0, Vec::new());
                    out.push(seg);
                }
                return out;
            }
            _ => {}
        }
        let can_send_data = matches!(self.state, State::Established | State::CloseWait | State::FinWait1 | State::LastAck | State::Closing);
        if can_send_data {
            let mss = self.mss() as usize;
            loop {
                let start = self.data_start();
                let off = self.snd_nxt.wrapping_sub(start) as usize;
                let window = self.snd_wnd.min(self.cwnd);
                let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
                let room = window.saturating_sub(in_flight) as usize;
                let pending = self.send_buf.len().saturating_sub(off);
                if pending > 0 && room > 0 {
                    let n = pending.min(mss).min(room);
                    let payload: Vec<u8> = self.send_buf.range(off..off + n).copied().collect();
                    let last = off + n == self.send_buf.len();
                    let seq = self.snd_nxt;
                    let mut flags = if last { PSH } else { 0 };
                    let fin_now = last && self.fin_queued && !self.our_fin_acked();
                    if fin_now {
                        flags |= FIN;
                    }
                    let seg = self.segment(seq, flags, payload);
                    self.stats.bytes_out += n as u64;
                    out.push(seg);
                    if fin_now {
                        self.fin_sent = Some(seq.wrapping_add(n as u32));
                    }
                    self.after_send(seq, n as u32 + fin_now as u32, now);
                    continue;
                }
                if pending == 0 && self.fin_pending() {
                    let seq = self.snd_nxt;
                    let seg = self.segment(seq, FIN, Vec::new());
                    out.push(seg);
                    self.fin_sent = Some(seq);
                    self.after_send(seq, 1, now);
                    continue;
                }
                if pending > 0 && self.snd_wnd == 0 && in_flight == 0 {
                    // Zero window: probe with one byte when the persist timer fires.
                    match self.persist_at {
                        None => self.persist_at = Some(now + self.rto),
                        Some(t) if now >= t => {
                            let seq = self.snd_nxt;
                            let payload = alloc::vec![self.send_buf[off]];
                            let seg = self.segment(seq, 0, payload);
                            out.push(seg);
                            self.after_send(seq, 1, now);
                            self.persist_at = Some(now + (self.rto * 2).min(MAX_RTO_MS));
                        }
                        Some(_) => {}
                    }
                }
                break;
            }
        }
        if self.ack_pending {
            let seg = self.segment(self.snd_nxt, 0, Vec::new());
            out.push(seg);
        }
        out
    }

    fn after_send(&mut self, seq: u32, len: u32, now: u64) {
        let end = seq.wrapping_add(len);
        let retransmission = seq_lt(seq, self.snd_max);
        self.snd_nxt = end;
        if seq_gt(end, self.snd_max) {
            self.snd_max = end;
        }
        if retransmission {
            self.rtt_probe = None; // Karn's algorithm
        } else if self.rtt_probe.is_none() && self.retries == 0 {
            self.rtt_probe = Some((end, now));
        }
        if self.retransmit_at.is_none() {
            self.retransmit_at = Some(now + self.rto);
        }
    }
}
