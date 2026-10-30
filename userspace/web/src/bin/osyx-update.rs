//! System updates of an installed OSyx (`/bin/osyx-update`).
//!
//! `osyx-update --daemon` (started by init as root beside the desktop):
//! waits for a network, checks the release in `/etc/osyx/update.conf`
//! (`url=` of a GitHub Releases download directory) and installs it when it
//! is newer than `/etc/osyx-release`; then checks again every day.
//! `osyx-update` runs one check and installation; `osyx-update --check`
//! only reports (it works for any user).
//!
//! Nothing is installed unless `manifest.txt` carries a valid Ed25519
//! signature of the release key built into the system (osyx-update crate).
//! The payload is checked against the manifest's SHA-256, every file again
//! against its own; all files are written next to their targets first and
//! only renamed into place once every one of them was written. The kernel
//! the update replaces stays on the EFI system partition as KERNEL.OLD.
//! /etc, /home and /var are never written (osyx_update::allowed_path).
//! The result goes to `/run/update.status` (the desktop announces an
//! installed update) and `/var/log/osyx-update.log`.
#![no_std]
#![no_main]

use os_std::io::{Read, Write};
use os_std::prelude::*;
use os_std::time::Duration;
use os_std::{env, fs, os, println, thread};
use osyx_update::{hex, Manifest};
use sha2::{Digest, Sha256};

os_std::entry!(main);

const CONF: &str = "/etc/osyx/update.conf";
const RELEASE: &str = "/etc/osyx-release";
const INSTALLED: &str = "/etc/osyx/installed";
const CACHE: &str = "/var/cache/osyx/update";
const STATUS: &str = "/run/update.status";
const LOG: &str = "/var/log/osyx-update.log";
/// The installed system's EFI system partition (mounted by the kernel).
const ESP: &str = "/boot";
const NETWORK_WAIT_SECS: u64 = 300;
const CHECK_INTERVAL_SECS: u64 = 24 * 3600;
const MANIFEST_MAX: usize = 4 << 20;
/// Suffix of a file written next to its target before the update commits.
const STAGED: &str = osyx_update::STAGED_SUFFIX;

struct Log(Option<fs::File>);

impl Log {
    fn line(&mut self, s: &str) {
        println!("osyx-update: {s}");
        if let Some(f) = &mut self.0 {
            let _ = f.write_all(format!("{s}\n").as_bytes());
        }
    }
}

/// `/run/update.status`: `state checking|up-to-date|available|installed|failed`
/// and `version`, `detail` lines.
fn status(state: &str, version: &str, detail: &str) {
    let _ = fs::write(STATUS, format!("state {state}\nversion {version}\ndetail {detail}\n"));
}

fn setting(text: &str, key: &str) -> Option<String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .find_map(|l| l.split_once('=').filter(|(k, _)| k.trim() == key).map(|(_, v)| String::from(v.trim())))
        .filter(|v| !v.is_empty())
}

/// Host part of an http(s) URL.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', ':']).next().unwrap_or(rest)
}

fn wait_for_network(log: &mut Log, host: &str) -> Result<(), String> {
    let mut waited = 0;
    loop {
        match os_std::net::lookup_host(host) {
            Ok(_) => return Ok(()),
            Err(e) if waited >= NETWORK_WAIT_SECS => return Err(format!("no network: cannot resolve {host} ({e})")),
            Err(_) => {
                if waited == 0 {
                    log.line(&format!("waiting up to {NETWORK_WAIT_SECS} s for a network connection"));
                }
                thread::sleep(Duration::from_secs(5));
                waited += 5;
            }
        }
    }
}

/// A small download kept in memory (the manifest and its signature).
fn fetch(url: &str) -> Result<Vec<u8>, String> {
    struct Buf(Vec<u8>);
    impl osyx_web::Sink for Buf {
        fn start(&mut self, _url: &str, length: Option<u64>) -> Result<(), String> {
            match length {
                Some(n) if n as usize > MANIFEST_MAX => Err(format!("{n} bytes is too large")),
                _ => Ok(()),
            }
        }
        fn data(&mut self, bytes: &[u8]) -> Result<(), String> {
            if self.0.len() + bytes.len() > MANIFEST_MAX {
                return Err(String::from("too large"));
            }
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }
    let mut b = Buf(Vec::new());
    osyx_web::get(url, &mut b).map_err(|e| format!("{url}: {e}"))?;
    Ok(b.0)
}

/// Where a manifest path lives on this system.
fn target(path: &str) -> String {
    match path.strip_prefix(osyx_update::ESP_PREFIX) {
        Some(rest) => format!("{ESP}/{rest}"),
        None => format!("/{path}"),
    }
}

fn file_sha256(path: &str) -> Option<[u8; 32]> {
    let mut f = fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => return Some(h.finalize().into()),
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return None,
        }
    }
}

/// Writes every changed file next to its target, then renames them all into
/// place. Returns the number of files replaced.
fn install(log: &mut Log, m: &Manifest, payload: &str) -> Result<usize, String> {
    let mut src = fs::File::open(payload).map_err(|e| format!("{payload}: {e}"))?;
    let mut staged: Vec<(String, bool)> = Vec::new();
    let mut temporary: Vec<String> = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    let result = (|| -> Result<(), String> {
        for e in &m.files {
            let to = target(&e.path);
            let esp = e.path.starts_with(osyx_update::ESP_PREFIX);
            let mode_matches = esp || fs::metadata(&to).is_ok_and(|m| m.permissions().mode() == e.mode);
            let unchanged = mode_matches && file_sha256(&to) == Some(e.sha256);
            let tmp = format!("{to}{STAGED}");
            let mut out = if unchanged {
                None
            } else {
                if let Some((dir, _)) = to.rsplit_once('/') {
                    fs::create_dir_all(dir).map_err(|err| format!("{dir}: {err}"))?;
                }
                let file = fs::File::create(&tmp).map_err(|err| format!("{tmp}: {err}"))?;
                temporary.push(tmp.clone());
                Some(file)
            };
            let mut h = Sha256::new();
            let mut left = e.size;
            while left > 0 {
                let want = (left as usize).min(buf.len());
                let n = src.read(&mut buf[..want]).map_err(|err| format!("{payload}: {err}"))?;
                if n == 0 {
                    return Err(format!("{payload} ends inside {}", e.path));
                }
                h.update(&buf[..n]);
                if let Some(f) = &mut out {
                    f.write_all(&buf[..n]).map_err(|err| format!("{tmp}: {err}"))?;
                }
                left -= n as u64;
            }
            if <[u8; 32]>::from(h.finalize()) != e.sha256 {
                return Err(format!("{} does not match its SHA-256 in the manifest", e.path));
            }
            if let Some(f) = out {
                f.sync_all().map_err(|err| format!("{tmp}: {err}"))?;
                drop(f);
                if !esp {
                    fs::set_permissions(&tmp, fs::Permissions::from_mode(e.mode)).map_err(|err| format!("{tmp}: {err}"))?;
                }
                staged.push((to, esp));
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        for path in &temporary {
            let _ = fs::remove_file(path);
        }
        return Err(e);
    }
    // Commit: the kernel being replaced stays as KERNEL.OLD.
    for (to, esp) in &staged {
        let tmp = format!("{to}{STAGED}");
        if to.ends_with("/KERNEL.ELF") && fs::metadata(to).is_ok() {
            let old = to.replace("/KERNEL.ELF", "/KERNEL.OLD");
            fs::copy(to, &old).map_err(|e| format!("{old}: {e}"))?;
        }
        fs::rename(&tmp, to).map_err(|e| format!("{to}: {e}"))?;
        if *esp {
            log.line(&format!("boot file {to} replaced"));
        }
    }
    Ok(staged.len())
}

/// One check, and the installation unless `check_only`. Returns the state
/// it ended in.
fn run_once(log: &mut Log, check_only: bool) -> Result<&'static str, String> {
    let Ok(conf) = fs::read_to_string(CONF) else {
        log.line(&format!("updates are not configured ({CONF} is missing)"));
        return Ok("up-to-date");
    };
    let Some(url) = setting(&conf, "url") else {
        log.line(&format!("updates are not configured (no url= in {CONF})"));
        return Ok("up-to-date");
    };
    let url = osyx_update::update_url(&url);
    let key = osyx_update::public_key().ok_or("this system has no release key built in")?;
    let current_text = fs::read_to_string(RELEASE).unwrap_or_default();
    let current = osyx_update::release_version(&current_text).unwrap_or("0");
    status("checking", current, url);
    wait_for_network(log, host_of(url))?;
    let manifest = fetch(&format!("{url}/{}", osyx_update::MANIFEST))?;
    let signature = fetch(&format!("{url}/{}", osyx_update::SIGNATURE))?;
    if !osyx_update::verify(&manifest, &signature, &key) {
        return Err(String::from("the release is not signed with the OSyx release key: not installed"));
    }
    let text = core::str::from_utf8(&manifest).map_err(|_| String::from("the manifest is not text"))?;
    let m = Manifest::parse(text)?;
    if !osyx_update::newer(&m.version, current) {
        log.line(&format!("OSyx {current} is up to date (latest release {})", m.version));
        status("up-to-date", current, "");
        return Ok("up-to-date");
    }
    log.line(&format!("OSyx {} is available (installed: {current}), {} files, {} MiB", m.version, m.files.len(), m.payload_size >> 20));
    if check_only {
        status("available", &m.version, "");
        return Ok("available");
    }
    if os::getuid().0 != 0 {
        return Err(String::from("installing needs root (init starts osyx-update --daemon as root)"));
    }
    status("downloading", &m.version, "");
    fs::create_dir_all(CACHE).map_err(|e| format!("{CACHE}: {e}"))?;
    let payload = format!("{CACHE}/payload-{}.bin", m.version);
    let mut shown = u64::MAX;
    osyx_web::download(&format!("{url}/{}", osyx_update::PAYLOAD), &payload, Some(&hex(&m.payload_sha256)), &mut |done, total| {
        if shown == u64::MAX || done >> 22 != shown >> 22 {
            shown = done;
            status("downloading", &m.version, &format!("{} / {} MiB", done >> 20, total.unwrap_or(m.payload_size) >> 20));
        }
    })
    .map_err(|e| format!("download: {e}"))?;
    log.line("payload downloaded, SHA-256 verified");
    status("installing", &m.version, "");
    let changed = install(log, &m, &payload)?;
    fs::write(RELEASE, format!("OSyx {}\n", m.version)).map_err(|e| format!("{RELEASE}: {e}"))?;
    let _ = fs::remove_file(&payload);
    log.line(&format!("OSyx {} installed ({changed} files replaced); restart to finish", m.version));
    status("installed", &m.version, "restart to finish");
    Ok("installed")
}

fn main() -> i32 {
    let _ = os_std::system::thread_priority(0, os_std::system::priority::LOW);
    let args: Vec<String> = env::args().collect();
    let daemon = args.iter().any(|a| a == "--daemon");
    let check_only = args.iter().any(|a| a == "--check");
    if fs::metadata(INSTALLED).is_err() {
        println!("osyx-update: not an installed system (live): nothing to update");
        return 0;
    }
    let _ = fs::create_dir_all("/var/log");
    let mut log = Log(fs::OpenOptions::new().append(true).create(true).open(LOG).ok());
    loop {
        let code = match run_once(&mut log, check_only) {
            Ok("installed") if daemon => return 0, // the next check after the restart
            Ok(_) => 0,
            Err(e) => {
                log.line(&format!("update failed: {e}"));
                let current = fs::read_to_string(RELEASE).unwrap_or_default();
                status("failed", osyx_update::release_version(&current).unwrap_or("0"), &e);
                1
            }
        };
        if !daemon {
            return code;
        }
        thread::sleep(Duration::from_secs(CHECK_INTERVAL_SECS));
    }
}
