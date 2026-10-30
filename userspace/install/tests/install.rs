//! The installation engine on disk images: the result is read back with
//! the same storage crates the kernel uses (and kept for e2fsck/fatcheck
//! when OSYX_TEST_IMAGES names a directory).

use osyx_ext4::{Ext4, MountOptions};
use osyx_install::*;
use std::collections::BTreeMap;

#[test]
fn partition_window_rejects_out_of_bounds_and_unaligned_io() {
    let mut disk = vec![0u8; 4 * SECTOR as usize];
    {
        let mut window = Window::new(&mut disk, 1, 1);
        assert!(osyx_fat::BlockDevice::write_sectors(&mut window, 0, &[1; 512]).is_ok());
        assert!(osyx_fat::BlockDevice::write_sectors(&mut window, 0, &[2; 513]).is_err());
        assert!(osyx_ext4::BlockDevice::write_sectors(&mut window, 1, &[3; 1]).is_err());
        assert!(osyx_ext4::BlockDevice::read_sectors(&mut window, u64::MAX, &mut [0; 512]).is_err());
    }
    assert!(disk[1024..].iter().all(|&b| b == 0));
    let mut invalid = Window::new(&mut disk, u64::MAX, 2);
    assert!(osyx_fat::BlockDevice::read_sectors(&mut invalid, 1, &mut [0; 512]).is_err());
}

#[test]
fn memory_disk_rejects_overflowing_sector_offsets() {
    let mut disk = vec![0u8; 512];
    assert!(Disk::read(&mut disk, u64::MAX, &mut [0; 512]).is_err());
    assert!(Disk::write(&mut disk, u64::MAX, &[1; 512]).is_err());
    assert!(disk.iter().all(|&b| b == 0));
}

#[test]
fn plan_rejects_overflowing_partition_sizes() {
    assert!(plan(u64::MAX, Layout::Manual { esp_mib: u64::MAX, root_mib: 0 }).is_err());
    assert!(plan(u64::MAX, Layout::Manual { esp_mib: 256, root_mib: u64::MAX }).is_err());
    let p = plan(u64::MAX, Layout::Automatic).unwrap();
    assert_eq!(p.root_mib(), p.root_sectors / (1024 * 1024 / SECTOR));
}

/// A tree in memory: path -> entry, plus file contents.
struct MemSource {
    entries: BTreeMap<String, SourceEntry>,
    data: BTreeMap<String, Vec<u8>>,
    fail_at: Option<String>,
    boot_calls: usize,
    empty_boot: Option<String>,
    oversize_at: Option<String>,
    extra_boot: Option<String>,
    lower_cmdline: bool,
    fail_list: bool,
    long_cmdline: bool,
}

impl MemSource {
    fn new() -> MemSource {
        let mut s = MemSource { entries: BTreeMap::new(), data: BTreeMap::new(), fail_at: None, boot_calls: 0, empty_boot: None, oversize_at: None, extra_boot: None, lower_cmdline: false, fail_list: false, long_cmdline: false };
        for (d, mode, uid) in [("/bin", 0o755, 0), ("/etc", 0o755, 0), ("/etc/osyx", 0o755, 0), ("/dev", 0o755, 0), ("/tmp", 0o1777, 0), ("/home", 0o755, 0), ("/home/user", 0o755, 1000), ("/system", 0o755, 0), ("/system/share", 0o755, 0), ("/system/share/osyx-setup", 0o755, 0)] {
            s.dir(d, mode, uid);
        }
        s.file("/bin/init", &pattern(700_000, 1), 0o755);
        s.file("/bin/axis", &pattern(90_000, 2), 0o755);
        s.file("/etc/hostname", b"osyx-live\n", 0o644);
        s.file("/etc/osyx-release", b"OSyx 0.1.0\n", 0o644);
        s.file("/home/user/notes.txt", b"hello", 0o644);
        s.file("/dev/should-not-copy", b"x", 0o644);
        s.file("/system/share/osyx-setup/KERNEL.ELF", &pattern(2_000_000, 3), 0o644);
        s.entries.insert("/bin/sh".into(), SourceEntry { name: "sh".into(), kind: Kind::Symlink("axis".into()), mode: 0o777, uid: 0, gid: 0, size: 4 });
        s
    }
    fn dir(&mut self, p: &str, mode: u16, uid: u32) {
        let name = p.rsplit('/').next().unwrap().to_string();
        self.entries.insert(p.into(), SourceEntry { name, kind: Kind::Dir, mode, uid, gid: uid, size: 0 });
    }
    fn file(&mut self, p: &str, data: &[u8], mode: u16) {
        let name = p.rsplit('/').next().unwrap().to_string();
        self.entries.insert(p.into(), SourceEntry { name, kind: Kind::File, mode, uid: 0, gid: 0, size: data.len() as u64 });
        self.data.insert(p.into(), data.to_vec());
    }
}

impl Source for MemSource {
    fn list(&mut self, path: &str) -> std::result::Result<Vec<SourceEntry>, String> {
        if self.fail_list { return Err("simulated directory read error".into()); }
        let prefix = if path == "/" { "/".to_string() } else { format!("{path}/") };
        Ok(self
            .entries
            .iter()
            .filter(|(p, _)| p.starts_with(&prefix) && !p[prefix.len()..].contains('/') && p.len() > prefix.len())
            .map(|(_, e)| e.clone())
            .collect())
    }
    fn read(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> std::result::Result<usize, String> {
        if self.oversize_at.as_deref() == Some(path) {
            return Ok(buf.len() + 1);
        }
        if self.fail_at.as_deref() == Some(path) {
            return Err("simulated read error".into());
        }
        let d = self.data.get(path).ok_or("no such file")?;
        let at = (offset as usize).min(d.len());
        let n = buf.len().min(d.len() - at);
        buf[..n].copy_from_slice(&d[at..at + n]);
        Ok(n)
    }
    fn boot_files(&mut self) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
        self.boot_calls += 1;
        if self.boot_calls > 1 { return Err("boot files requested twice".into()); }
        let mut files = vec![
            ("EFI/BOOT/BOOTX64.EFI".into(), pattern(150_000, 7)),
            ("EFI/OSYX/KERNEL.ELF".into(), self.data["/system/share/osyx-setup/KERNEL.ELF"].clone()),
            ("EFI/OSYX/CMDLINE.TXT".into(), b"live".to_vec()),
        ];
        if let Some(path) = &self.empty_boot {
            for (name, data) in &mut files {
                if name == path { data.clear(); }
            }
        }
        if let Some(path) = &self.extra_boot { files.push((path.clone(), vec![1])); }
        if self.lower_cmdline { files[2].0 = "efi/osyx/cmdline.txt".into(); }
        if self.long_cmdline { files[2].1 = vec![b'x'; 4097]; }
        Ok(files)
    }
}

fn pattern(n: usize, seed: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + seed) % 253) as u8).collect()
}

#[derive(Default)]
struct Log {
    stages: Vec<Stage>,
    last: f32,
    lines: Vec<String>,
}

impl Progress for Log {
    fn stage(&mut self, stage: Stage, fraction: f32) {
        assert!(fraction >= self.last, "progress must not go back ({fraction} after {})", self.last);
        self.last = fraction;
        if self.stages.last() != Some(&stage) {
            self.stages.push(stage);
        }
    }
    fn log(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }
}

fn config() -> Config {
    Config {
        hostname: "workstation".into(),
        user_name: "ada".into(),
        full_name: "Ada Lovelace".into(),
        password: Some("analytical".into()),
        install_zen: true,
        seed: [7; 32],
        time: 1_761_200_000,
        skip: vec!["/system/share/osyx-setup".into()],
        cmdline: String::new(),
    }
}

#[test]
fn invalid_plan_never_writes_disk() {
    struct GuardDisk { writes: usize }
    impl Disk for GuardDisk {
        fn sectors(&self) -> u64 { 2_000_000 }
        fn read(&mut self, _: u64, _: &mut [u8]) -> std::result::Result<(), String> { Err("unexpected read".into()) }
        fn write(&mut self, _: u64, _: &[u8]) -> std::result::Result<(), String> { self.writes += 1; Err("unexpected write".into()) }
        fn flush(&mut self) -> std::result::Result<(), String> { Err("unexpected flush".into()) }
    }
    let good = plan(2_000_000, Layout::Automatic).unwrap();
    let cases = [
        Plan { esp_first: 0, ..good },
        Plan { root_first: good.esp_first, ..good },
        Plan { root_first: u64::MAX, ..good },
        Plan { root_sectors: 0, ..good },
    ];
    for p in cases {
        let mut disk = GuardDisk { writes: 0 };
        assert!(matches!(install(&mut disk, &p, &mut MemSource::new(), &config(), &mut Log::default()), Err(Error::Invalid(_))));
        assert_eq!(disk.writes, 0);
    }
    for path in ["EFI/BOOT/BOOTX64.EFI", "EFI/OSYX/KERNEL.ELF"] {
        let mut disk = GuardDisk { writes: 0 };
        let mut source = MemSource::new();
        source.empty_boot = Some(path.into());
        assert!(matches!(install(&mut disk, &good, &mut source, &config(), &mut Log::default()), Err(Error::Source(_))));
        assert_eq!(disk.writes, 0);
    }
    for path in ["EFI/BOOT/../BOOT/BOOTX64.EFI", "efi/osyx/kernel.elf", "/EFI/extra", "EFI\\extra", "EFI//extra"] {
        let mut disk = GuardDisk { writes: 0 };
        let mut source = MemSource::new();
        source.extra_boot = Some(path.into());
        assert!(matches!(install(&mut disk, &good, &mut source, &config(), &mut Log::default()), Err(Error::Source(_))));
        assert_eq!(disk.writes, 0);
    }
    for overflow in [false, true] {
        let mut disk = GuardDisk { writes: 0 };
        let mut source = MemSource::new();
        if overflow {
            source.entries.get_mut("/bin/init").unwrap().size = u64::MAX;
        } else {
            source.fail_list = true;
        }
        assert!(matches!(install(&mut disk, &good, &mut source, &config(), &mut Log::default()), Err(Error::Source(_))));
        assert_eq!(disk.writes, 0);
    }
    let mut disk = GuardDisk { writes: 0 };
    let mut source = MemSource::new();
    source.long_cmdline = true;
    assert!(matches!(install(&mut disk, &good, &mut source, &config(), &mut Log::default()), Err(Error::Source(_))));
    assert_eq!(disk.writes, 0);
}

fn keep(name: &str, img: &[u8]) {
    if let Ok(dir) = std::env::var("OSYX_TEST_IMAGES") {
        std::fs::write(std::path::Path::new(&dir).join(name), img).unwrap();
    }
}

fn read_file(fs: &mut Ext4<Window<'_, Vec<u8>>>, path: &str) -> Vec<u8> {
    let ino = fs.resolve(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let size = fs.stat(ino).unwrap().size as usize;
    let mut b = vec![0u8; size];
    let mut done = 0;
    while done < size {
        done += fs.read(ino, done as u64, &mut b[done..]).unwrap();
    }
    b
}

#[test]
fn installs_a_bootable_system_on_a_whole_disk() {
    let mut disk = vec![0x5Au8; 900 << 20];
    let plan = plan(disk.sectors(), Layout::Automatic).unwrap();
    assert_eq!(plan.esp_mib(), DEFAULT_ESP_MIB);
    let mut src = MemSource::new();
    let mut log = Log::default();
    let report = install(&mut disk, &plan, &mut src, &config(), &mut log).unwrap();
    assert_eq!(log.stages.first(), Some(&Stage::Partitioning));
    assert_eq!(log.stages.last(), Some(&Stage::Done));
    assert_eq!(report.files, 5, "init, axis, hostname, release, notes; /dev and the setup payload skipped");
    assert_eq!(report.links, 1);
    keep("installed.img", &disk);

    let p = plan;
    let mut fs = Ext4::mount(Window::new(&mut disk, p.root_first, p.root_sectors), MountOptions { read_only: true, clock: None }).unwrap();
    assert_eq!(read_file(&mut fs, "/bin/init"), pattern(700_000, 1));
    assert_eq!(read_file(&mut fs, "/etc/hostname"), b"workstation\n");
    let sh = fs.resolve("/bin/sh").unwrap();
    assert_eq!(fs.readlink(sh).unwrap(), "axis");
    let passwd = String::from_utf8(read_file(&mut fs, "/etc/passwd")).unwrap();
    assert!(passwd.contains("ada:x:1000:27:Ada Lovelace:/home/user:/bin/axis"), "{passwd}");
    assert!(String::from_utf8(read_file(&mut fs, "/etc/group")).unwrap().contains("sudo:x:27:ada\n"));
    let host = fs.resolve("/etc/hostname").unwrap();
    let host = fs.stat(host).unwrap();
    assert_eq!((host.gid, host.mode & 0o777), (27, 0o664), "administrators may rename the computer");
    let shadow = String::from_utf8(read_file(&mut fs, "/etc/shadow")).unwrap();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&config().seed[..16]);
    assert!(shadow.contains(&format!("ada:{}:", hash_password("analytical", &salt))));
    let sh = fs.resolve("/etc/shadow").unwrap();
    assert_eq!(fs.stat(sh).unwrap().mode & 0o777, 0o600);
    assert!(read_file(&mut fs, "/etc/osyx/firstboot.conf").ends_with(b"zen=1\n"));
    let h = fs.resolve("/home/user").unwrap();
    let home = fs.stat(h).unwrap();
    assert_eq!((home.uid, home.mode & 0o777), (1000, 0o755));
    let t = fs.resolve("/tmp").unwrap();
    let tmp = fs.stat(t).unwrap();
    assert_eq!(tmp.mode & 0o7777, 0o1777, "mount points keep their modes");
    assert!(fs.resolve("/dev/should-not-copy").is_err());
    assert!(fs.resolve("/system/share/osyx-setup").is_err());
    drop(fs);
    let mut esp = osyx_fat::FileSystem::mount(Window::new(&mut disk, p.esp_first, p.esp_sectors)).unwrap();
    assert_eq!(esp.metadata("/EFI/BOOT/BOOTX64.EFI").unwrap().size, 150_000);
    assert_eq!(esp.metadata("/EFI/OSYX/KERNEL.ELF").unwrap().size, 2_000_000);
}

#[test]
fn manual_layout_and_kernel_command_line() {
    let mut disk = vec![0u8; 1200 << 20];
    let plan = plan(disk.sectors(), Layout::Manual { esp_mib: 100, root_mib: 800 }).unwrap();
    assert_eq!((plan.esp_mib(), plan.root_mib()), (100, 800));
    let mut c = config();
    c.cmdline = "init.args=desktop".into();
    c.password = None;
    c.install_zen = false;
    let mut source = MemSource::new();
    source.lower_cmdline = true;
    install(&mut disk, &plan, &mut source, &c, &mut Log::default()).unwrap();
    let mut esp = osyx_fat::FileSystem::mount(Window::new(&mut disk, plan.esp_first, plan.esp_sectors)).unwrap();
    let mut f = esp.open("/EFI/OSYX/CMDLINE.TXT", osyx_fat::OpenOptions::default()).unwrap();
    let mut b = [0u8; 64];
    let n = esp.read(&mut f, 0, &mut b).unwrap();
    assert_eq!(&b[..n], b"init.args=desktop");
    esp.remove_file("/EFI/OSYX/CMDLINE.TXT").unwrap();
    esp.unmount().unwrap();
    let expected = [("EFI/OSYX/CMDLINE.TXT".to_string(), c.cmdline.len() as u64)];
    assert!(matches!(verify(&mut disk, &plan, &c, &expected), Err(Error::Verify(_))));
}

#[test]
fn plans_and_settings_are_checked() {
    let small = (MIN_DISK_MIB - 10) << 11;
    assert!(plan(small, Layout::Automatic).is_err());
    assert!(plan(4 << 21, Layout::Manual { esp_mib: 32, root_mib: 0 }).is_err());
    assert!(plan(4 << 21, Layout::Manual { esp_mib: 256, root_mib: 100 }).is_err());
    assert!(plan(1 << 21, Layout::Manual { esp_mib: 256, root_mib: 900 }).is_err(), "1 GiB disk cannot hold 1156 MiB");
    let ok = config();
    assert_eq!(validate(&ok), Ok(()));
    assert!(validate(&Config { cmdline: "x".repeat(4096), ..ok.clone() }).is_ok());
    assert!(validate(&Config { cmdline: "x".repeat(4097), ..ok.clone() }).is_err());
    assert!(validate(&Config { cmdline: "ą".repeat(2049), ..ok.clone() }).is_err());
    for bad in [
        Config { hostname: "".into(), ..ok.clone() },
        Config { hostname: "-x".into(), ..ok.clone() },
        Config { hostname: "a b".into(), ..ok.clone() },
        Config { user_name: "Ada".into(), ..ok.clone() },
        Config { user_name: "root".into(), ..ok.clone() },
        Config { full_name: "a:b".into(), ..ok.clone() },
        Config { password: Some("abc".into()), ..ok.clone() },
    ] {
        assert!(validate(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn an_interrupted_installation_is_not_bootable() {
    let mut disk = vec![0u8; 900 << 20];
    let plan = plan(disk.sectors(), Layout::Automatic).unwrap();
    let mut src = MemSource::new();
    src.fail_at = Some("/etc/hostname".into());
    let e = install(&mut disk, &plan, &mut src, &config(), &mut Log::default()).unwrap_err();
    assert!(matches!(e, Error::Source(_)), "{e}");
    let mut esp = osyx_fat::FileSystem::mount(Window::new(&mut disk, plan.esp_first, plan.esp_sectors)).unwrap();
    assert!(esp.metadata("/EFI/BOOT/BOOTX64.EFI").is_err(), "no boot loader on an incomplete disk");
    // A second attempt on the same disk starts over and succeeds.
    drop(esp);
    let mut bad_source = MemSource::new();
    bad_source.oversize_at = Some("/etc/hostname".into());
    assert!(matches!(install(&mut disk, &plan, &mut bad_source, &config(), &mut Log::default()), Err(Error::Source(_))));
    let mut esp = osyx_fat::FileSystem::mount(Window::new(&mut disk, plan.esp_first, plan.esp_sectors)).unwrap();
    assert!(esp.metadata("/EFI/BOOT/BOOTX64.EFI").is_err());
    drop(esp);
    let mut truncated = MemSource::new();
    truncated.data.get_mut("/bin/init").unwrap().truncate(1);
    assert!(matches!(install(&mut disk, &plan, &mut truncated, &config(), &mut Log::default()), Err(Error::Source(_))));
    let mut esp = osyx_fat::FileSystem::mount(Window::new(&mut disk, plan.esp_first, plan.esp_sectors)).unwrap();
    assert!(esp.metadata("/EFI/BOOT/BOOTX64.EFI").is_err());
    drop(esp);
    struct FailLoader<'a> { disk: &'a mut Vec<u8>, fail: bool, corrupt: bool }
    impl Disk for FailLoader<'_> {
        fn sectors(&self) -> u64 { self.disk.sectors() }
        fn read(&mut self, lba: u64, buf: &mut [u8]) -> std::result::Result<(), String> { Disk::read(self.disk, lba, buf) }
        fn write(&mut self, lba: u64, buf: &[u8]) -> std::result::Result<(), String> {
            if self.fail && buf.len() == 512 && buf == pattern(512, 7) {
                self.fail = false;
                if self.corrupt {
                    let mut changed = buf.to_vec();
                    changed[0] ^= 1;
                    return Disk::write(self.disk, lba, &changed);
                }
                return Err("injected boot loader write error".into());
            }
            Disk::write(self.disk, lba, buf)
        }
        fn flush(&mut self) -> std::result::Result<(), String> { Ok(()) }
    }
    let mut failing = FailLoader { disk: &mut disk, fail: true, corrupt: false };
    assert!(install(&mut failing, &plan, &mut MemSource::new(), &config(), &mut Log::default()).is_err());
    assert!(!failing.fail, "the loader write must have been interrupted");
    let mut esp = osyx_fat::FileSystem::mount(Window::new(&mut disk, plan.esp_first, plan.esp_sectors)).unwrap();
    assert!(esp.metadata("/EFI/BOOT/BOOTX64.EFI").is_err());
    drop(esp);
    let mut corrupting = FailLoader { disk: &mut disk, fail: true, corrupt: true };
    assert!(matches!(install(&mut corrupting, &plan, &mut MemSource::new(), &config(), &mut Log::default()), Err(Error::Verify(_))));
    assert!(!corrupting.fail, "the loader write must have been corrupted");
    let mut esp = osyx_fat::FileSystem::mount(Window::new(&mut disk, plan.esp_first, plan.esp_sectors)).unwrap();
    assert!(esp.metadata("/EFI/BOOT/BOOTX64.EFI").is_err());
    drop(esp);
    install(&mut disk, &plan, &mut MemSource::new(), &config(), &mut Log::default()).unwrap();
}
