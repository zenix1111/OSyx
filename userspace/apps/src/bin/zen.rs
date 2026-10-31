//! Installed Zen browser: the unmodified Windows payload, a persistent
//! per-user profile and the software rendering path supported by OSyx.
#![no_std]
#![no_main]

use os_std::prelude::*;
use os_std::process::Command;
use os_std::{env, fs, os};

os_std::entry!(main);

const PROFILE: &str = "/home/user/.config/zen/profile";
const PREFS: &str = r#"user_pref("gfx.webrender.software", true);
user_pref("gfx.webrender.software.d3d11", false);
user_pref("gfx.webrender.compositor", false);
user_pref("layout.frame_rate", 60);
user_pref("layers.acceleration.disabled", true);
user_pref("layers.gpu-process.enabled", false);
user_pref("layers.gpu-process.force-enabled", false);
user_pref("media.sanity-test.disabled", true);
user_pref("media.hardware-video-decoding.enabled", false);
user_pref("media.hardware-video-encoding.enabled", false);
user_pref("media.wmf.dxva.enabled", false);
user_pref("zen.welcome-screen.seen", true);
user_pref("zen.watermark.enabled", false);
user_pref("browser.startup.page", 3);
user_pref("browser.sessionstore.resume_from_crash", true);
user_pref("browser.cache.disk.enable", true);
user_pref("browser.cache.disk.capacity", 1048576);
user_pref("browser.cache.disk.smart_size.enabled", true);
user_pref("privacy.clearOnShutdown.cache", false);
user_pref("privacy.clearOnShutdown.cookies", false);
user_pref("privacy.clearOnShutdown.sessions", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("fission.autostart", false);
user_pref("fission.webContentIsolationStrategy", 0);
user_pref("browser.tabs.remote.autostart", false);
user_pref("browser.tabs.remote.autostart.2", false);
user_pref("browser.tabs.remote.separatePrivilegedContentProcess", false);
user_pref("browser.tabs.remote.separateFileUriProcess", false);
user_pref("browser.tabs.remote.separatePrivilegedMozillaWebContentProcess", false);
user_pref("dom.ipc.processCount", 1);
user_pref("dom.ipc.processCount.webIsolated", 1);
user_pref("dom.ipc.processCount.file", 1);
user_pref("dom.ipc.processCount.privilegedabout", 1);
user_pref("dom.ipc.processCount.privilegedmozilla", 1);
user_pref("dom.ipc.processPrelaunch.enabled", false);
user_pref("dom.ipc.keepProcessesAlive.web", 0);
user_pref("dom.ipc.keepProcessesAlive.privilegedabout", 0);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("media.gmp-manager.updateEnabled", false);
user_pref("media.gmp-provider.enabled", false);
user_pref("media.gmp-widevinecdm.enabled", false);
user_pref("media.gmp-widevinecdm.visible", false);
user_pref("media.gmp-gmpopenh264.enabled", false);
user_pref("media.gmp-gmpopenh264.autoupdate", false);
user_pref("app.update.enabled", false);
user_pref("app.update.auto", false);
user_pref("app.update.background.scheduling.enabled", false);
user_pref("extensions.update.enabled", false);
user_pref("extensions.getAddons.cache.enabled", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("browser.sessionhistory.max_total_viewers", 0);
user_pref("browser.sessionhistory.max_entries", 20);
user_pref("browser.sessionstore.max_tabs_undo", 3);
user_pref("browser.sessionstore.interval", 60000);
user_pref("browser.cache.memory.capacity", 16384);
user_pref("browser.cache.memory.max_entry_size", 2048);
user_pref("media.memory_cache_max_size", 16384);
user_pref("image.mem.surfacecache.max_size_kb", 65536);
user_pref("browser.tabs.unloadOnLowMemory", true);
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("browser.places.speculativeConnect.enabled", false);
user_pref("extensions.pocket.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("gfx.canvas.accelerated", false);
user_pref("toolkit.cosmeticAnimations.enabled", false);
user_pref("ui.prefersReducedMotion", 1);
"#;

fn main() -> i32 {
    if fs::metadata("/opt/zen/zen.exe").is_err() {
        eprintln!("zen: browser payload is missing; build with -ZenDirectory and -RootMiB 1024");
        return 1;
    }
    if os::getuid().0 == 0 {
        if let Err(e) = os::setuid(1000, 1000) {
            eprintln!("zen: cannot switch to desktop user: {e}");
            return 1;
        }
    }
    env::set_var("HOME", "/home/user");
    env::set_var("USER", "user");
    let profile = env::var("OSYX_ZEN_PROFILE").unwrap_or_else(|_| String::from(PROFILE));
    let trace = env::var("OSYX_ZEN_TRACE").is_ok_and(|value| value == "1");
    let prefs = if trace { format!("{PREFS}user_pref(\"devtools.console.stdout.chrome\", true);\nuser_pref(\"devtools.console.stdout.content\", true);\nuser_pref(\"browser.dom.window.dump.enabled\", true);\n") } else { String::from(PREFS) };
    if let Err(e) = fs::create_dir_all(&profile).and_then(|_| fs::write(format!("{profile}/user.js"), prefs)) {
        eprintln!("zen: cannot prepare profile: {e}");
        return 1;
    }
    let mut command = Command::new("/bin/winrun");
    if trace {
        command.arg("-v").env("OSYX_WINRUN_TRACE", "1");
    }
    command.args(["/opt/zen/zen.exe", "--no-remote", "-profile"]).arg(&format!("C:{}", profile.replace('/', "\\")));
    // Pass URLs as arguments, never through a shell. Native files are encoded
    // as file URLs so spaces, '#' and non-ASCII names reach Gecko intact.
    let mut has_target = false;
    for target in env::args().skip(1) {
        has_target = true;
        if target.starts_with('/') {
            command.arg(&file_url(&target));
        } else if target.starts_with("https://")
            || target.starts_with("http://")
            || target.starts_with("file://")
            || target.starts_with("about:")
        {
            command.arg(&target);
        } else {
            eprintln!("zen: expected an absolute path or web address: {target}");
            return 2;
        }
    }
    if !has_target { command.arg("about:blank"); }
    // Gecko's launcher flag must follow all URLs (its command-line handler
    // skips the argument immediately after this bootstrap-only flag).
    command.arg("-no-deelevate");
    // The Windows broker's remote-memory patching is not implemented yet.
    for kind in ["CONTENT", "GPU", "RDD", "SOCKET_PROCESS", "GMP", "UTILITY", "VR"] {
        command.env(&format!("MOZ_DISABLE_{kind}_SANDBOX"), "1");
    }
    println!("zen: launching installed browser with persistent profile {profile}");
    eprintln!("zen: {}", command.exec());
    1
}

fn file_url(path: &str) -> String {
    let mut url = String::from("file:///C:");
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
            url.push(b as char);
        } else {
            url.push_str(&format!("%{b:02X}"));
        }
    }
    url
}
