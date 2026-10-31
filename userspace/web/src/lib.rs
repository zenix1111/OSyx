//! HTTPS for OSyx programs: HTTP/1.1 GET over TCP, with TLS 1.2/1.3 from
//! rustls (pure-Rust RustCrypto provider) and the Mozilla root store from
//! `webpki-roots`. Certificates are verified against those roots and the
//! host name, with the clock from the kernel's real-time clock.
//!
//! Randomness for TLS comes from `/dev/random` (the kernel's ChaCha20 DRBG,
//! present when a hardware entropy source seeded it). Without it TLS is
//! refused rather than run with predictable keys.
//!
//! The provider is `rustls-rustcrypto`, an alpha release that has not been
//! audited; its RSA and ECDSA code is only used to *verify* signatures here.
#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use alloc::format;
use os_std::io::{Read, Write};
use os_std::net::TcpStream;
use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};

const MAX_REDIRECTS: usize = 8;
const MAX_HEADER: usize = 64 * 1024;
const IO_TIMEOUT_SECS: u64 = 30;
/// One dead A record must not stall the whole request: give each address
/// this long before trying the next.
const CONNECT_TIMEOUT_SECS: u64 = 10;

fn osyx_random(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let mut f = os_std::fs::File::open("/dev/random").map_err(|_| getrandom::Error::UNSUPPORTED)?;
    f.read_exact(buf).map_err(|_| getrandom::Error::UNSUPPORTED)
}
getrandom::register_custom_getrandom!(osyx_random);

#[derive(Debug)]
struct Clock;

impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        let d = os_std::time::SystemTime::now().duration_since(os_std::time::SystemTime::UNIX_EPOCH).ok()?;
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(d.as_secs())))
    }
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let config = rustls::ClientConfig::builder_with_details(Arc::new(rustls_rustcrypto::provider()), Arc::new(Clock))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS configuration: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A parsed `http://` or `https://` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

pub fn parse_url(s: &str) -> Result<Url, String> {
    let (https, rest) = if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("not an http(s) URL: {s}"));
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, String::from("/")),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(format!("unsupported URL authority: {authority}"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| format!("bad port in {s}"))?),
        None => (authority, if https { 443 } else { 80 }),
    };
    Ok(Url { https, host: host.to_ascii_lowercase(), port, path })
}

fn connect(url: &Url) -> Result<TcpStream, String> {
    let addrs = os_std::net::lookup_host(&url.host).map_err(|e| format!("cannot resolve {}: {e}", url.host))?;
    let mut last = format!("{} has no IPv4 address", url.host);
    for a in addrs {
        let timeout = Some(os_std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS));
        match TcpStream::connect_timeout(&os_std::net::SocketAddr::new(a, url.port), timeout) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(os_std::time::Duration::from_secs(IO_TIMEOUT_SECS)));
                return Ok(s);
            }
            Err(e) => last = format!("cannot connect to {}:{} ({a}): {e}", url.host, url.port),
        }
    }
    Err(last)
}

/// A byte stream: plain TCP or TLS over TCP.
trait Stream {
    fn send(&mut self, data: &[u8]) -> Result<(), String>;
    /// 0 at the end of the stream.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, String>;
}

impl Stream for TcpStream {
    fn send(&mut self, data: &[u8]) -> Result<(), String> {
        self.write_all(data).map_err(|e| format!("send: {e}"))
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        self.read(buf).map_err(|e| format!("receive: {e}"))
    }
}

/// TLS client over a TCP stream, driven through rustls' unbuffered API.
struct Tls {
    conn: UnbufferedClientConnection,
    sock: TcpStream,
    incoming: Vec<u8>,
    used: usize,
    outgoing: Vec<u8>,
    out_len: usize,
    plain: Vec<u8>,
    plain_at: usize,
    /// The peer closed (close_notify or end of TCP).
    eof: bool,
}

impl Tls {
    fn new(sock: TcpStream, host: &str) -> Result<Tls, String> {
        let name = ServerName::try_from(host.to_string()).map_err(|_| format!("invalid server name {host}"))?;
        let conn = UnbufferedClientConnection::new(tls_config()?, name).map_err(|e| format!("TLS: {e}"))?;
        let mut t = Tls {
            conn,
            sock,
            incoming: vec![0; 32 * 1024],
            used: 0,
            outgoing: vec![0; 32 * 1024],
            out_len: 0,
            plain: Vec::new(),
            plain_at: 0,
            eof: false,
        };
        t.drive(None, false)?;
        Ok(t)
    }

    /// Runs the state machine until `write` was sent (and, with `read`,
    /// until application data or the end arrived). With neither, until the
    /// handshake is complete.
    fn drive(&mut self, mut write: Option<&[u8]>, read: bool) -> Result<(), String> {
        loop {
            if read && (self.plain_at < self.plain.len() || self.eof) && write.is_none() {
                return Ok(());
            }
            let Tls { conn, sock, incoming, used, outgoing, out_len, plain, eof, .. } = self;
            let UnbufferedStatus { mut discard, state } = conn.process_tls_records(&mut incoming[..*used]);
            let mut need_input = false;
            let mut done = false;
            match state.map_err(|e| format!("TLS: {e}"))? {
                ConnectionState::EncodeTlsData(mut s) => loop {
                    match s.encode(&mut outgoing[*out_len..]) {
                        Ok(n) => {
                            *out_len += n;
                            break;
                        }
                        Err(EncodeError::InsufficientSize(e)) => outgoing.resize(*out_len + e.required_size, 0),
                        Err(e) => return Err(format!("TLS encode: {e}")),
                    }
                },
                ConnectionState::TransmitTlsData(t) => {
                    sock.write_all(&outgoing[..*out_len]).map_err(|e| format!("send: {e}"))?;
                    *out_len = 0;
                    t.done();
                }
                ConnectionState::BlockedHandshake => need_input = true,
                ConnectionState::WriteTraffic(mut w) => {
                    if let Some(data) = write.take() {
                        let n = loop {
                            match w.encrypt(data, &mut outgoing[..]) {
                                Ok(n) => break n,
                                Err(EncryptError::InsufficientSize(e)) => outgoing.resize(e.required_size, 0),
                                Err(e) => return Err(format!("TLS encrypt: {e}")),
                            }
                        };
                        sock.write_all(&outgoing[..n]).map_err(|e| format!("send: {e}"))?;
                    } else if read && !*eof {
                        need_input = true;
                    } else {
                        done = true;
                    }
                }
                ConnectionState::ReadTraffic(mut r) => {
                    while let Some(rec) = r.next_record() {
                        let rec = rec.map_err(|e| format!("TLS: {e}"))?;
                        discard += rec.discard;
                        plain.extend_from_slice(rec.payload);
                    }
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    *eof = true;
                    done = write.is_none();
                }
                other => return Err(format!("TLS: unexpected state {other:?}")),
            }
            if discard > 0 {
                incoming.copy_within(discard..*used, 0);
                *used -= discard;
            }
            if need_input {
                if *used == incoming.len() {
                    let n = incoming.len() * 2;
                    incoming.resize(n, 0);
                }
                let n = sock.read(&mut incoming[*used..]).map_err(|e| format!("receive: {e}"))?;
                if n == 0 {
                    if !read {
                        return Err(String::from("TLS: the server closed the connection during the handshake"));
                    }
                    // No close_notify: callers check the body length.
                    *eof = true;
                }
                *used += n;
            }
            if done {
                return Ok(());
            }
        }
    }
}

impl Stream for Tls {
    fn send(&mut self, data: &[u8]) -> Result<(), String> {
        self.drive(Some(data), false)
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        if self.plain_at == self.plain.len() {
            self.plain.clear();
            self.plain_at = 0;
            self.drive(None, true)?;
        }
        let n = buf.len().min(self.plain.len() - self.plain_at);
        buf[..n].copy_from_slice(&self.plain[self.plain_at..self.plain_at + n]);
        self.plain_at += n;
        Ok(n)
    }
}

/// What [`get`] reports while downloading.
pub trait Sink {
    /// The final response started: status 200, total size if known.
    fn start(&mut self, url: &str, length: Option<u64>) -> Result<(), String>;
    fn data(&mut self, bytes: &[u8]) -> Result<(), String>;
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// Reads the status line and headers; returns them with the body bytes
/// already received.
/// Status, headers and the body bytes that arrived with them.
type Head = (u16, Vec<(String, String)>, Vec<u8>);

fn read_head(s: &mut dyn Stream) -> Result<Head, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER {
            return Err(String::from("HTTP: response header too large"));
        }
        let n = s.recv(&mut chunk)?;
        if n == 0 {
            return Err(String::from("HTTP: connection closed before the response header"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = core::str::from_utf8(&buf[..end]).map_err(|_| String::from("HTTP: header is not text"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("HTTP: bad status line {status_line:?}"))?;
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    Ok((status, headers, buf[end + 4..].to_vec()))
}

/// Streams a body of `length` bytes (or until the end, or chunked).
fn read_body(s: &mut dyn Stream, headers: &[(String, String)], first: Vec<u8>, sink: &mut dyn Sink) -> Result<u64, String> {
    let chunked = header(headers, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let length = header(headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    let mut buf = vec![0u8; 64 * 1024];
    if !chunked {
        let mut total = 0u64;
        let mut pending = first;
        loop {
            if !pending.is_empty() {
                let take = match length {
                    Some(l) => pending.len().min((l - total) as usize),
                    None => pending.len(),
                };
                sink.data(&pending[..take])?;
                total += take as u64;
                pending.clear();
            }
            if length.is_some_and(|l| total >= l) {
                return Ok(total);
            }
            let n = s.recv(&mut buf)?;
            if n == 0 {
                return match length {
                    Some(l) => Err(format!("HTTP: connection closed after {total} of {l} bytes")),
                    None => Ok(total),
                };
            }
            pending.extend_from_slice(&buf[..n]);
        }
    }
    // Chunked transfer coding.
    let mut data = first;
    let mut total = 0u64;
    let mut more = |data: &mut Vec<u8>, s: &mut dyn Stream| -> Result<(), String> {
        let n = s.recv(&mut buf)?;
        if n == 0 {
            return Err(String::from("HTTP: connection closed inside a chunked body"));
        }
        data.extend_from_slice(&buf[..n]);
        Ok(())
    };
    loop {
        let line_end = loop {
            if let Some(i) = data.windows(2).position(|w| w == b"\r\n") {
                break i;
            }
            more(&mut data, s)?;
        };
        let size_text = core::str::from_utf8(&data[..line_end]).map_err(|_| String::from("HTTP: bad chunk size"))?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16).map_err(|_| format!("HTTP: bad chunk size {size_text:?}"))?;
        data.drain(..line_end + 2);
        if size == 0 {
            return Ok(total);
        }
        while data.len() < size + 2 {
            more(&mut data, s)?;
        }
        sink.data(&data[..size])?;
        total += size as u64;
        data.drain(..size + 2);
    }
}

/// Downloads `url` into `sink`, following redirects. Returns the number of
/// body bytes. Only status 200 counts as success.
pub fn get(url: &str, sink: &mut dyn Sink) -> Result<u64, String> {
    let mut current = parse_url(url)?;
    for _ in 0..=MAX_REDIRECTS {
        let tcp = connect(&current)?;
        let mut stream: alloc::boxed::Box<dyn Stream> = if current.https {
            alloc::boxed::Box::new(Tls::new(tcp, &current.host)?)
        } else {
            alloc::boxed::Box::new(tcp)
        };
        let host = if (current.https && current.port == 443) || (!current.https && current.port == 80) {
            current.host.clone()
        } else {
            format!("{}:{}", current.host, current.port)
        };
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OSyx-fetch/0.1\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            current.path
        );
        stream.send(req.as_bytes())?;
        let (status, headers, first) = read_head(&mut *stream)?;
        match status {
            200 => {
                let length = header(&headers, "content-length").and_then(|v| v.parse().ok());
                let shown = format!("{}://{}{}", if current.https { "https" } else { "http" }, current.host, current.path);
                sink.start(&shown, length)?;
                return read_body(&mut *stream, &headers, first, sink);
            }
            301 | 302 | 303 | 307 | 308 => {
                let loc = header(&headers, "location").ok_or_else(|| format!("HTTP {status} without a Location"))?;
                current = if loc.starts_with('/') {
                    Url { path: loc.to_string(), ..current }
                } else {
                    parse_url(loc)?
                };
            }
            _ => return Err(format!("HTTP status {status} from {}", current.host)),
        }
    }
    Err(String::from("HTTP: too many redirects"))
}

/// Lower-case hex SHA-256 of a file.
pub fn sha256_file(path: &str) -> Result<String, String> {
    let mut f = os_std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut h = osyx_crypto::Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("{path}: {e}"))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finish().iter().map(|b| format!("{b:02x}")).collect())
}

/// Downloads `url` to `path` (through `path.part`, renamed when complete
/// and, with `sha256`, verified). `progress(done, total)` is called about
/// every MiB.
pub fn download(url: &str, path: &str, sha256: Option<&str>, progress: &mut dyn FnMut(u64, Option<u64>)) -> Result<u64, String> {
    struct FileSink<'a> {
        file: os_std::fs::File,
        done: u64,
        total: Option<u64>,
        progress: &'a mut dyn FnMut(u64, Option<u64>),
    }
    impl Sink for FileSink<'_> {
        fn start(&mut self, _url: &str, length: Option<u64>) -> Result<(), String> {
            self.total = length;
            (self.progress)(0, length);
            Ok(())
        }
        fn data(&mut self, bytes: &[u8]) -> Result<(), String> {
            self.file.write_all(bytes).map_err(|e| format!("write: {e}"))?;
            let before = self.done;
            self.done += bytes.len() as u64;
            if before >> 20 != self.done >> 20 {
                (self.progress)(self.done, self.total);
            }
            Ok(())
        }
    }
    let part = format!("{path}.part");
    let file = os_std::fs::File::create(&part).map_err(|e| format!("{part}: {e}"))?;
    let mut sink = FileSink { file, done: 0, total: None, progress };
    let n = get(url, &mut sink)?;
    sink.file.sync_all().map_err(|e| format!("{part}: {e}"))?;
    drop(sink);
    if let Some(want) = sha256 {
        let got = sha256_file(&part)?;
        if !got.eq_ignore_ascii_case(want) {
            let _ = os_std::fs::remove_file(&part);
            return Err(format!("SHA-256 mismatch: got {got}, expected {want}"));
        }
    }
    os_std::fs::rename(&part, path).map_err(|e| format!("{path}: {e}"))?;
    Ok(n)
}
