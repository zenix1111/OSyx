//! Watches an established Wi-Fi gateway and requests a bounded reconnect.
#![no_std]
#![no_main]
use os_std::net::{self, Ipv4Addr, PingSocket, IFF_LINK, IFF_WIRELESS};
use os_std::prelude::*;
use os_std::time::{Duration, Instant};
use os_std::{fs, thread};
os_std::entry!(main);

fn status(text: &str) {
    let prior = fs::read_to_string("/run/wifi.health").unwrap_or_default();
    let last_error = if matches!(text, "Gateway not responding" | "Could not request reconnect") {
        text
    } else {
        prior.lines().find_map(|line| line.strip_prefix("last_error ")).unwrap_or("")
    };
    let _ = fs::write("/run/wifi.health", format!("status {text}\nlast_error {last_error}\n"));
}

fn main() -> i32 {
    let start = Instant::now();
    let mut gateway = [0; 4];
    let mut verified = false;
    let mut failures = 0u32;
    let mut last_recovery = None;
    let mut seq = 0u16;
    loop {
        let iface = net::interfaces().unwrap_or_default().into_iter().find(|i| i.flags & (IFF_WIRELESS | IFF_LINK) == (IFF_WIRELESS | IFF_LINK) && i.addr != [0; 4] && i.gateway != [0; 4]);
        let Some(i) = iface else {
            verified = false; failures = 0; gateway = [0; 4];
            status("Waiting for Wi-Fi and gateway");
            thread::sleep(Duration::from_secs(15));
            continue;
        };
        // Ping follows the system route; do not test or reset Wi-Fi if another
        // interface owns the default route.
        let interfaces = net::interfaces().unwrap_or_default();
        let gateway_ip = u32::from_be_bytes(i.gateway);
        let owns_route = net::routes().unwrap_or_default().iter()
            .filter(|r| {
                let prefix = r.prefix.min(32);
                let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                gateway_ip & mask == u32::from_be_bytes(r.dest) & mask
                    && interfaces.iter().any(|n| n.index == r.iface && n.flags & IFF_LINK != 0)
            })
            .max_by_key(|r| r.prefix)
            .is_some_and(|r| r.iface == i.index);
        if !owns_route {
            verified = false; failures = 0; gateway = [0; 4];
            status("Gateway check unavailable");
            thread::sleep(Duration::from_secs(30));
            continue;
        }
        if gateway != i.gateway { gateway = i.gateway; verified = false; failures = 0; }
        seq = seq.wrapping_add(1);
        let answer = PingSocket::new().and_then(|s| {
            s.set_read_timeout(Some(Duration::from_secs(3)))?;
            s.send(Ipv4Addr(gateway), seq, b"osyx-wifi-health")?;
            let mut buf = [0u8; 64];
            let reply = s.recv(&mut buf)?;
            Ok(reply.seq == seq && reply.from == Ipv4Addr(gateway))
        }).unwrap_or(false);
        if answer {
            verified = true; failures = 0; status("Gateway reachable");
        } else if !verified {
            // Many routers do not answer ICMP; do not disrupt such networks.
            status("Gateway does not answer checks");
        } else {
            failures += 1;
            status("Gateway not responding");
            let now = start.elapsed().as_secs();
            if failures >= 3 && last_recovery.is_none_or(|t| now.saturating_sub(t) >= 300) {
                match fs::write("/run/wifi.reconnect", format!("automatic {now}\n")) {
                    Ok(()) => { status("Reconnect requested"); last_recovery = Some(now); failures = 0; verified = false; }
                    Err(_) => status("Could not request reconnect"),
                }
            }
        }
        thread::sleep(Duration::from_secs(30));
    }
}
