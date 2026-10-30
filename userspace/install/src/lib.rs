//! The OSyx installation engine, shared by the graphical installer and its
//! host tests. It writes a complete, bootable OSyx system onto a whole disk:
//!
//! 1. a new GPT with an EFI system partition and an ext4 root partition of
//!    type "Linux root (x86-64)" (the kernel's default root);
//! 2. FAT32 on the ESP, ext4 (with a journal) on the root;
//! 3. a copy of the running system's tree, then the host name, the user
//!    account and the first-boot configuration;
//! 4. the boot files last: an interrupted installation leaves a disk the
//!    firmware does not boot instead of a half-written system that does.
//!
//! Everything goes through the existing storage crates (`osyx-part`,
//! `osyx-fat`, `osyx-ext4`) on top of [`Disk`], so the same code runs on a
//! raw `/dev/disks/*` node in OSyx and on a disk image in the host tests.
//! Nothing here decides *which* disk to use; callers must have the user's
//! explicit confirmation before calling [`install`].

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, Ordering};
use osyx_ext4::{Ext4, MountOptions, NewKind, ROOT_INO};
use osyx_part::{Guid, NewPartition};

pub const SECTOR: u64 = 512;
const MIB: u64 = 1 << 20;
/// Partitions start on 1 MiB boundaries.
const ALIGN: u64 = MIB / SECTOR;
pub const DEFAULT_ESP_MIB: u64 = 256;
pub const MIN_ESP_MIB: u64 = 64;
pub const MIN_ROOT_MIB: u64 = 512;
/// The smallest disk the automatic layout accepts.
pub const MIN_DISK_MIB: u64 = DEFAULT_ESP_MIB + MIN_ROOT_MIB + 2;
/// Uid of the desktop user (the session runs as this account).
pub const USER_ID: u32 = 1000;
/// The administrators group ("sudo"): the desktop user's primary group.
/// Its members may change the system settings (`/etc/osyx`, `/etc/TZ`,
/// `/etc/hostname`).
pub const ADMIN_GID: u32 = 27;
/// Home of the desktop user; the desktop shell and applications use it.
pub const USER_HOME: &str = "/home/user";
const PASSWORD_ROUNDS: u32 = 100_000;
/// Copy buffer for file contents.
const CHUNK: usize = 256 * 1024;
/// Maximum command-line size accepted by the UEFI loader.
const CMDLINE_MAX: usize = 4096;
const LOADER: &str = "EFI/BOOT/BOOTX64.EFI";
const LOADER_TEMP: &str = "EFI/BOOT/OSYX.TMP";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The disk or a file system on it failed.
    Io(String),
    /// The request does not fit the disk or is malformed.
    Invalid(String),
    /// Reading the system to copy failed.
    Source(String),
    /// The finished system did not pass the verification.
    Verify(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io(s) => write!(f, "disk error: {s}"),
            Error::Invalid(s) => write!(f, "{s}"),
            Error::Source(s) => write!(f, "cannot read the system to install: {s}"),
            Error::Verify(s) => write!(f, "verification failed: {s}"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// A whole disk of 512-byte sectors.
pub trait Disk {
    fn sectors(&self) -> u64;
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> core::result::Result<(), String>;
    fn write(&mut self, lba: u64, buf: &[u8]) -> core::result::Result<(), String>;
    fn flush(&mut self) -> core::result::Result<(), String>;
}

impl Disk for Vec<u8> {
    fn sectors(&self) -> u64 {
        self.len() as u64 / SECTOR
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> core::result::Result<(), String> {
        let range = disk_range(lba, buf.len()).ok_or("read past the end")?;
        buf.copy_from_slice(self.get(range).ok_or("read past the end")?);
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> core::result::Result<(), String> {
        let range = disk_range(lba, buf.len()).ok_or("write past the end")?;
        self.get_mut(range).ok_or("write past the end")?.copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> core::result::Result<(), String> {
        Ok(())
    }
}

fn disk_range(lba: u64, len: usize) -> Option<core::ops::Range<usize>> {
    let start = usize::try_from(lba.checked_mul(SECTOR)?).ok()?;
    Some(start..start.checked_add(len)?)
}

/// A partition of a [`Disk`] seen as a device of its own.
pub struct Window<'a, D: Disk> {
    disk: &'a mut D,
    first: u64,
    sectors: u64,
}

impl<'a, D: Disk> Window<'a, D> {
    pub fn new(disk: &'a mut D, first: u64, sectors: u64) -> Self {
        Window { disk, first, sectors }
    }

    fn check(&self, lba: u64, len: usize) -> bool {
        len.is_multiple_of(SECTOR as usize)
            && self.first.checked_add(self.sectors).is_some_and(|end| end <= self.disk.sectors())
            && lba.checked_add(len as u64 / SECTOR).is_some_and(|end| end <= self.sectors)
    }
}

impl<D: Disk> osyx_ext4::BlockDevice for Window<'_, D> {
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> osyx_ext4::Result<()> {
        if !self.check(lba, buf.len()) {
            return Err(osyx_ext4::Error::Io);
        }
        self.disk.read(self.first + lba, buf).map_err(|_| osyx_ext4::Error::Io)
    }
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> osyx_ext4::Result<()> {
        if !self.check(lba, buf.len()) {
            return Err(osyx_ext4::Error::Io);
        }
        self.disk.write(self.first + lba, buf).map_err(|_| osyx_ext4::Error::Io)
    }
    fn flush(&mut self) -> osyx_ext4::Result<()> {
        self.disk.flush().map_err(|_| osyx_ext4::Error::Io)
    }
}

impl<D: Disk> osyx_fat::BlockDevice for Window<'_, D> {
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> osyx_fat::Result<()> {
        if !self.check(lba, buf.len()) {
            return Err(osyx_fat::FsError::Io);
        }
        self.disk.read(self.first + lba, buf).map_err(|_| osyx_fat::FsError::Io)
    }
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> osyx_fat::Result<()> {
        if !self.check(lba, buf.len()) {
            return Err(osyx_fat::FsError::Io);
        }
        self.disk.write(self.first + lba, buf).map_err(|_| osyx_fat::FsError::Io)
    }
    fn flush(&mut self) -> osyx_fat::Result<()> {
        self.disk.flush().map_err(|_| osyx_fat::FsError::Io)
    }
}

// ---- partitioning -----------------------------------------------------------------

/// How the disk is divided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// A 256 MiB EFI system partition and the rest for the root.
    Automatic,
    /// Explicit sizes; `root_mib` 0 means "the rest of the disk". Space
    /// after the root partition stays unallocated.
    Manual { esp_mib: u64, root_mib: u64 },
}

/// Where the partitions go (sector numbers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub disk_sectors: u64,
    pub esp_first: u64,
    pub esp_sectors: u64,
    pub root_first: u64,
    pub root_sectors: u64,
}

impl Plan {
    pub fn esp_mib(&self) -> u64 {
        self.esp_sectors / ALIGN
    }
    pub fn root_mib(&self) -> u64 {
        self.root_sectors / ALIGN
    }
}

/// Plans `layout` on a disk of `disk_sectors` sectors.
pub fn plan(disk_sectors: u64, layout: Layout) -> Result<Plan> {
    // GPT: 34 sectors at the start (aligned up to 1 MiB) and 33 at the end.
    let usable_end = disk_sectors.checked_sub(34).ok_or_else(|| Error::Invalid("the disk is too small".into()))?;
    let (esp_mib, root_mib) = match layout {
        Layout::Automatic => (DEFAULT_ESP_MIB, 0),
        Layout::Manual { esp_mib, root_mib } => (esp_mib, root_mib),
    };
    if esp_mib < MIN_ESP_MIB {
        return Err(Error::Invalid(format!("the EFI system partition needs at least {MIN_ESP_MIB} MiB")));
    }
    if root_mib != 0 && root_mib < MIN_ROOT_MIB {
        return Err(Error::Invalid(format!("the system partition needs at least {MIN_ROOT_MIB} MiB")));
    }
    let esp_first = ALIGN;
    let too_large = || Error::Invalid("partition size is too large".into());
    let esp_sectors = esp_mib.checked_mul(ALIGN).ok_or_else(too_large)?;
    let root_first = esp_first.checked_add(esp_sectors).ok_or_else(too_large)?;
    let room = usable_end.saturating_sub(root_first) / ALIGN * ALIGN;
    let root_sectors = if root_mib == 0 { room } else { root_mib.checked_mul(ALIGN).ok_or_else(too_large)? };
    if root_sectors > room {
        return Err(Error::Invalid(format!(
            "the partitions need {} MiB but the disk has {} MiB",
            esp_mib.saturating_add(root_mib).saturating_add(2),
            disk_sectors / ALIGN
        )));
    }
    if root_sectors < MIN_ROOT_MIB * ALIGN {
        return Err(Error::Invalid(format!("the disk is too small: OSyx needs at least {MIN_DISK_MIB} MiB")));
    }
    Ok(Plan { disk_sectors, esp_first, esp_sectors, root_first, root_sectors })
}

// ---- what to install ----------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink(String),
}

/// One entry of the system tree to copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEntry {
    pub name: String,
    pub kind: Kind,
    /// Permission bits (`0o7777`).
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
}

/// The running system (or a test tree) the installer copies.
pub trait Source {
    /// Entries of directory `path` (absolute, `/` separated).
    fn list(&mut self, path: &str) -> core::result::Result<Vec<SourceEntry>, String>;
    /// Reads file `path` at `offset`; 0 at the end.
    fn read(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> core::result::Result<usize, String>;
    /// The EFI system partition files: (path below the ESP root, contents).
    /// `EFI/BOOT/BOOTX64.EFI` and `EFI/OSYX/KERNEL.ELF` are required.
    fn boot_files(&mut self) -> core::result::Result<Vec<(String, Vec<u8>)>, String>;
}

/// Top-level directories of the running system that hold mounts or
/// run-time state: created empty (with their modes), never copied.
pub const EMPTY_DIRS: &[&str] = &["/dev", "/tmp", "/run", "/mnt", "/boot", "/proc"];

/// Choices made in the installer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub hostname: String,
    /// Login name of the desktop user.
    pub user_name: String,
    pub full_name: String,
    /// `None`: an account without a password.
    pub password: Option<String>,
    /// Download and install Zen Browser on the first boot.
    pub install_zen: bool,
    /// Random bytes for GUIDs, the volume UUID and the password salt.
    pub seed: [u8; 32],
    /// Seconds since the Unix epoch (timestamps).
    pub time: i64,
    /// Paths of the source tree left out (for example the installer's own
    /// payload), in addition to [`EMPTY_DIRS`].
    pub skip: Vec<String>,
    /// Kernel command line of the installed system (empty: none).
    pub cmdline: String,
}

/// Checks the user-editable fields; returns a message for the user.
pub fn validate(c: &Config) -> core::result::Result<(), String> {
    let host = c.hostname.as_str();
    if host.is_empty() || host.len() > 63 {
        return Err("The computer name must have 1 to 63 characters.".into());
    }
    if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') || host.starts_with('-') || host.ends_with('-') {
        return Err("The computer name may contain letters, digits and '-' (not at the start or end).".into());
    }
    let user = c.user_name.as_str();
    if user.is_empty() || user.len() > 32 {
        return Err("The user name must have 1 to 32 characters.".into());
    }
    if !user.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        || !user.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err("The user name must start with a lowercase letter and use a-z, 0-9, '-' or '_'.".into());
    }
    if user == "root" {
        return Err("The user name 'root' is reserved.".into());
    }
    if c.full_name.contains(':') || c.full_name.contains('\n') {
        return Err("The full name may not contain ':' or line breaks.".into());
    }
    if c.password.as_ref().is_some_and(|p| p.chars().count() < 4) {
        return Err("The password must have at least 4 characters (or none).".into());
    }
    if c.cmdline.len() > CMDLINE_MAX {
        return Err("The kernel command line must not exceed 4096 bytes.".into());
    }
    Ok(())
}

/// `sha256-iter$<rounds>$<salt hex>$<hash hex>`: the salted password hash
/// stored in `/etc/shadow`.
pub fn hash_password(password: &str, salt: &[u8; 16]) -> String {
    let mut h = osyx_crypto::Sha256::new();
    h.update(salt);
    h.update(password.as_bytes());
    let mut d = h.finish();
    for _ in 1..PASSWORD_ROUNDS {
        let mut h = osyx_crypto::Sha256::new();
        h.update(&d);
        h.update(salt);
        h.update(password.as_bytes());
        d = h.finish();
    }
    format!("sha256-iter${PASSWORD_ROUNDS}${}${}", hex(salt), hex(&d))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- progress --------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Partitioning,
    FormatEsp,
    FormatRoot,
    Copying,
    Configuring,
    BootFiles,
    Verifying,
    Done,
}

impl Stage {
    pub fn describe(self) -> &'static str {
        match self {
            Stage::Partitioning => "Writing the partition table",
            Stage::FormatEsp => "Formatting the EFI system partition (FAT32)",
            Stage::FormatRoot => "Formatting the system partition (ext4)",
            Stage::Copying => "Copying the system",
            Stage::Configuring => "Configuring the computer name and user account",
            Stage::BootFiles => "Installing the boot loader",
            Stage::Verifying => "Verifying the installation",
            Stage::Done => "Installation complete",
        }
    }
}

/// Reports progress (`fraction` of the whole job, 0..=1) and log lines.
pub trait Progress {
    fn stage(&mut self, stage: Stage, fraction: f32);
    fn log(&mut self, line: &str);
}

/// What was installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub plan: Plan,
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub bytes: u64,
}

static CLOCK: AtomicI64 = AtomicI64::new(0);

fn clock() -> (i64, u32) {
    (CLOCK.load(Ordering::Relaxed), 0)
}

fn guid(seed: &[u8; 32], n: u8) -> Guid {
    let mut h = osyx_crypto::Sha256::new();
    h.update(seed);
    h.update(&[n]);
    let d = h.finish();
    let mut g = [0u8; 16];
    g.copy_from_slice(&d[..16]);
    // RFC 4122 version 4, variant 1 (byte 7 and 8 of the mixed-endian GUID).
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    Guid(g)
}

fn ext4_err(what: &str, e: osyx_ext4::Error) -> Error {
    Error::Io(format!("{what}: {e}"))
}

fn fat_err(what: &str, e: osyx_fat::FsError) -> Error {
    Error::Io(format!("{what}: {e:?}"))
}

/// Installs OSyx on the whole of `disk` following `plan`. Everything on the
/// disk is lost. The caller must have the user's explicit confirmation.
pub fn install<D: Disk, S: Source, P: Progress>(disk: &mut D, plan: &Plan, source: &mut S, config: &Config, progress: &mut P) -> Result<Report> {
    validate(config).map_err(Error::Invalid)?;
    if plan.disk_sectors != disk.sectors() {
        return Err(Error::Invalid("the plan was made for a different disk size".into()));
    }
    let invalid_plan = || Error::Invalid("invalid partition plan".into());
    let esp_end = plan.esp_first.checked_add(plan.esp_sectors).ok_or_else(invalid_plan)?;
    let root_end = plan.root_first.checked_add(plan.root_sectors).ok_or_else(invalid_plan)?;
    let usable_end = disk.sectors().checked_sub(33).ok_or_else(invalid_plan)?;
    if plan.esp_first < ALIGN || plan.esp_sectors < MIN_ESP_MIB * ALIGN
        || plan.root_sectors < MIN_ROOT_MIB * ALIGN || plan.root_first < esp_end || root_end > usable_end
    {
        return Err(invalid_plan());
    }
    let parts = [
        NewPartition { type_guid: osyx_part::TYPE_ESP, unique_guid: guid(&config.seed, 1), first_lba: plan.esp_first, sectors: plan.esp_sectors, name: "EFI system partition" },
        NewPartition { type_guid: osyx_part::TYPE_ROOT_X86_64, unique_guid: guid(&config.seed, 2), first_lba: plan.root_first, sectors: plan.root_sectors, name: "OSyx" },
    ];
    let table = osyx_part::build(disk.sectors(), guid(&config.seed, 0), &parts).map_err(|e| Error::Invalid(format!("partition table: {e:?}")))?;
    CLOCK.store(config.time, Ordering::Relaxed);
    // Fail before touching the disk if the boot files are missing.
    let boot = source.boot_files().map_err(Error::Source)?;
    for (index, (path, _)) in boot.iter().enumerate() {
        if path.contains('\\') || path.chars().any(char::is_control)
            || path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(Error::Source(format!("invalid boot file path: {path}")));
        }
        if boot[..index].iter().any(|(other, _)| other.to_lowercase() == path.to_lowercase()) {
            return Err(Error::Source(format!("duplicate boot file path: {path}")));
        }
    }
    if boot.iter().filter(|(p, _)| p.eq_ignore_ascii_case(LOADER)).count() != 1
        || boot.iter().any(|(p, _)| p.eq_ignore_ascii_case(LOADER_TEMP) || (p.eq_ignore_ascii_case(LOADER) && p != LOADER))
    {
        return Err(Error::Source("boot files contain a reserved loader path".into()));
    }
    for need in ["EFI/BOOT/BOOTX64.EFI", "EFI/OSYX/KERNEL.ELF"] {
        if !boot.iter().any(|(p, data)| p == need && !data.is_empty()) {
            return Err(Error::Source(format!("{need} is missing or empty")));
        }
    }
    if config.cmdline.is_empty() && boot.iter().any(|(path, data)| path.eq_ignore_ascii_case("EFI/OSYX/CMDLINE.TXT") && data.len() > CMDLINE_MAX) {
        return Err(Error::Source("the boot command line exceeds 4096 bytes".into()));
    }
    let total = estimate(source, "/", config).map_err(Error::Source)?.max(1);

    progress.stage(Stage::Partitioning, 0.0);
    // Wipe the first MiB of each partition so stale signatures never show
    // through, then the new table.
    let zero = vec![0u8; MIB as usize];
    for first in [plan.esp_first, plan.root_first] {
        disk.write(first, &zero).map_err(Error::Io)?;
    }
    for (lba, data) in table {
        disk.write(lba, &data).map_err(Error::Io)?;
    }
    disk.flush().map_err(Error::Io)?;
    progress.log(&format!(
        "GPT written: ESP {} MiB at sector {}, root {} MiB at sector {}",
        plan.esp_mib(),
        plan.esp_first,
        plan.root_mib(),
        plan.root_first
    ));

    progress.stage(Stage::FormatEsp, 0.02);
    let serial = u32::from_le_bytes(config.seed[20..24].try_into().expect("4 bytes"));
    osyx_fat::format(&mut Window::new(disk, plan.esp_first, plan.esp_sectors), "OSYX-ESP", serial)
        .map_err(|e| fat_err("formatting the ESP", e))?;
    progress.log("ESP formatted as FAT32");

    progress.stage(Stage::FormatRoot, 0.04);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&guid(&config.seed, 3).0);
    let opts = osyx_ext4::FormatOptions { label: "OSyx", uuid, time: config.time as u32 };
    let f = osyx_ext4::format(&mut Window::new(disk, plan.root_first, plan.root_sectors), &opts).map_err(|e| ext4_err("formatting the root", e))?;
    progress.log(&format!("root formatted as ext4: {} blocks, {} groups, {} inodes, journal {} blocks", f.blocks, f.groups, f.inodes, f.journal_blocks));

    let mut report = Report { plan: *plan, files: 0, dirs: 0, links: 0, bytes: 0 };
    {
        let mut fs = Ext4::mount(Window::new(disk, plan.root_first, plan.root_sectors), MountOptions { read_only: false, clock: Some(clock) })
            .map_err(|e| ext4_err("mounting the new root", e))?;
        if let Some(why) = fs.write_refusal() {
            return Err(Error::Io(format!("the new root is not writable: {why}")));
        }
        progress.stage(Stage::Copying, 0.06);
        progress.log(&format!("copying {} MiB of system files", total / MIB));
        let mut copy = Copy { fs: &mut fs, source, config, report: &mut report, total, progress, buf: vec![0u8; CHUNK] };
        copy.dir("/", ROOT_INO)?;
        progress.stage(Stage::Configuring, 0.90);
        configure(&mut fs, config)?;
        fs.sync().map_err(|e| ext4_err("writing the root", e))?;
        fs.unmount().map_err(|e| ext4_err("unmounting the root", e))?;
    }
    progress.log(&format!(
        "copied {} files ({} MiB), {} directories, {} links",
        report.files,
        report.bytes / MIB,
        report.dirs,
        report.links
    ));

    progress.stage(Stage::BootFiles, 0.94);
    let mut expected_boot = Vec::new();
    let mut boot_hashes = Vec::new();
    {
        let mut esp = osyx_fat::FileSystem::mount(Window::new(disk, plan.esp_first, plan.esp_sectors)).map_err(|e| fat_err("mounting the ESP", e))?;
        let mut files = boot;
        if !config.cmdline.is_empty() {
            files.retain(|(p, _)| !p.eq_ignore_ascii_case("EFI/OSYX/CMDLINE.TXT"));
            files.push(("EFI/OSYX/CMDLINE.TXT".to_string(), config.cmdline.as_bytes().to_vec()));
        }
        // Keep the loader under a temporary name until verification succeeds.
        files.sort_by_key(|(p, _)| p == "EFI/BOOT/BOOTX64.EFI");
        for (path, data) in &files {
            let written_path = if path == LOADER { LOADER_TEMP } else { path.as_str() };
            fat_write(&mut esp, written_path, data)?;
            expected_boot.push((written_path.to_string(), data.len() as u64));
            let mut hash = osyx_crypto::Sha256::new();
            hash.update(data);
            boot_hashes.push((written_path.to_string(), hash.finish()));
            progress.log(&format!("ESP: {path} ({} bytes)", data.len()));
        }
        esp.unmount().map_err(|e| fat_err("unmounting the ESP", e))?;
    }
    disk.flush().map_err(Error::Io)?;

    progress.stage(Stage::Verifying, 0.97);
    verify(disk, plan, config, &expected_boot)?;
    {
        let mut esp = osyx_fat::FileSystem::mount(Window::new(disk, plan.esp_first, plan.esp_sectors)).map_err(|e| fat_err("ESP", e))?;
        verify_boot_contents(&mut esp, &boot_hashes)?;
        esp.rename(LOADER_TEMP, LOADER).map_err(|e| fat_err("publishing the boot loader", e))?;
        esp.unmount().map_err(|e| fat_err("unmounting the ESP", e))?;
    }
    disk.flush().map_err(Error::Io)?;
    progress.log("verification passed");
    progress.stage(Stage::Done, 1.0);
    Ok(report)
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") }
}

fn skipped(path: &str, config: &Config) -> bool {
    config.skip.iter().any(|s| s == path)
}

/// Bytes of file data below `path` that will be copied.
fn estimate<S: Source>(source: &mut S, path: &str, config: &Config) -> core::result::Result<u64, String> {
    let mut sum = 0u64;
    for e in source.list(path)? {
        let p = join(path, &e.name);
        if EMPTY_DIRS.contains(&p.as_str()) || skipped(&p, config) {
            continue;
        }
        let size = match e.kind {
            Kind::File => e.size,
            Kind::Dir => estimate(source, &p, config)?,
            Kind::Symlink(_) => 0,
        };
        sum = sum.checked_add(size).ok_or_else(|| format!("{path}: source size overflow"))?;
    }
    Ok(sum)
}

struct Copy<'a, D: osyx_ext4::BlockDevice, S: Source, P: Progress> {
    fs: &'a mut Ext4<D>,
    source: &'a mut S,
    config: &'a Config,
    report: &'a mut Report,
    total: u64,
    progress: &'a mut P,
    buf: Vec<u8>,
}

impl<D: osyx_ext4::BlockDevice, S: Source, P: Progress> Copy<'_, D, S, P> {
    fn dir(&mut self, path: &str, ino: u32) -> Result<()> {
        let mut entries = self.source.list(path).map_err(|e| Error::Source(format!("{path}: {e}")))?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for e in entries {
            let p = join(path, &e.name);
            if skipped(&p, self.config) {
                continue;
            }
            match &e.kind {
                Kind::Dir => {
                    let child = self.fs.create(ino, &e.name, NewKind::Dir, e.mode, e.uid, e.gid).map_err(|x| ext4_err(&p, x))?;
                    self.report.dirs += 1;
                    if !EMPTY_DIRS.contains(&p.as_str()) {
                        self.dir(&p, child)?;
                    }
                }
                Kind::Symlink(target) => {
                    self.fs.create(ino, &e.name, NewKind::Symlink(target), 0o777, e.uid, e.gid).map_err(|x| ext4_err(&p, x))?;
                    self.report.links += 1;
                }
                Kind::File => {
                    let f = self.fs.create(ino, &e.name, NewKind::File, e.mode, e.uid, e.gid).map_err(|x| ext4_err(&p, x))?;
                    let mut at = 0u64;
                    loop {
                        let n = self.source.read(&p, at, &mut self.buf).map_err(|x| Error::Source(format!("{p}: {x}")))?;
                        if n > self.buf.len() {
                            return Err(Error::Source(format!("{p}: read returned more bytes than the buffer")));
                        }
                        if n == 0 {
                            break;
                        }
                        let mut done = 0;
                        while done < n {
                            let w = self.fs.write(f, at + done as u64, &self.buf[done..n]).map_err(|x| ext4_err(&p, x))?;
                            if w == 0 {
                                return Err(Error::Io(format!("{p}: short write")));
                            }
                            done += w;
                        }
                        at += n as u64;
                        let before = self.report.bytes;
                        self.report.bytes += n as u64;
                        // Report about every 4 MiB.
                        if before >> 22 != self.report.bytes >> 22 {
                            let frac = 0.06 + 0.84 * (self.report.bytes as f32 / self.total as f32).min(1.0);
                            self.progress.stage(Stage::Copying, frac);
                        }
                    }
                    if at != e.size {
                        return Err(Error::Source(format!("{p} changed size while copying ({} -> {at})", e.size)));
                    }
                    self.report.files += 1;
                }
            }
        }
        Ok(())
    }
}

/// Creates `path` (with parents) or returns the existing inode.
fn ensure_dir<D: osyx_ext4::BlockDevice>(fs: &mut Ext4<D>, path: &str, mode: u16, uid: u32, gid: u32) -> Result<u32> {
    let mut ino = ROOT_INO;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        ino = match fs.lookup(ino, part) {
            Ok(i) => i,
            Err(osyx_ext4::Error::NotFound) => fs.create(ino, part, NewKind::Dir, mode, uid, gid).map_err(|e| ext4_err(path, e))?,
            Err(e) => return Err(ext4_err(path, e)),
        };
    }
    Ok(ino)
}

/// Writes (or replaces) a whole file.
fn put_file<D: osyx_ext4::BlockDevice>(fs: &mut Ext4<D>, path: &str, data: &[u8], mode: u16, uid: u32, gid: u32) -> Result<()> {
    let (dir, name) = path.rsplit_once('/').ok_or_else(|| Error::Invalid(format!("{path}: not absolute")))?;
    let d = ensure_dir(fs, dir, 0o755, 0, 0)?;
    if fs.lookup(d, name).is_ok() {
        fs.unlink(d, name).map_err(|e| ext4_err(path, e))?;
    }
    let f = fs.create(d, name, NewKind::File, mode, uid, gid).map_err(|e| ext4_err(path, e))?;
    let mut done = 0;
    while done < data.len() {
        let n = fs.write(f, done as u64, &data[done..]).map_err(|e| ext4_err(path, e))?;
        done += n;
    }
    Ok(())
}

/// Host name, account, first-boot settings and the installation record.
fn configure<D: osyx_ext4::BlockDevice>(fs: &mut Ext4<D>, c: &Config) -> Result<()> {
    put_file(fs, "/etc/hostname", format!("{}\n", c.hostname).as_bytes(), 0o664, 0, ADMIN_GID)?;
    let gecos = if c.full_name.is_empty() { c.user_name.clone() } else { c.full_name.clone() };
    let passwd = format!("root:x:0:0:Administrator:/root:/bin/axis\n{}:x:{USER_ID}:{ADMIN_GID}:{gecos}:{USER_HOME}:/bin/axis\n", c.user_name);
    put_file(fs, "/etc/passwd", passwd.as_bytes(), 0o644, 0, 0)?;
    put_file(fs, "/etc/group", format!("root:x:0:\nsudo:x:{ADMIN_GID}:{}\n", c.user_name).as_bytes(), 0o644, 0, 0)?;
    let secret = match &c.password {
        Some(p) => {
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&c.seed[..16]);
            hash_password(p, &salt)
        }
        None => String::new(),
    };
    put_file(fs, "/etc/shadow", format!("root:!:\n{}:{secret}:\n", c.user_name).as_bytes(), 0o600, 0, 0)?;
    ensure_dir(fs, USER_HOME, 0o755, USER_ID, USER_ID)?;
    ensure_dir(fs, "/home/user/Desktop", 0o755, USER_ID, USER_ID)?;
    ensure_dir(fs, "/var/log", 0o755, 0, 0)?;
    ensure_dir(fs, "/etc/osyx", 0o755, 0, 0)?;
    put_file(
        fs,
        "/etc/osyx/firstboot.conf",
        format!("# Tasks for the first start of the installed system.\nzen={}\n", if c.install_zen { 1 } else { 0 }).as_bytes(),
        0o644,
        0,
        0,
    )?;
    put_file(
        fs,
        "/etc/osyx/installed",
        format!("installed={}\nhostname={}\nuser={}\n", c.time, c.hostname, c.user_name).as_bytes(),
        0o644,
        0,
        0,
    )?;
    Ok(())
}

fn fat_write<D: osyx_fat::BlockDevice>(fs: &mut osyx_fat::FileSystem<D>, path: &str, data: &[u8]) -> Result<()> {
    let mut at = String::new();
    let parts: Vec<&str> = path.split('/').collect();
    for dir in &parts[..parts.len() - 1] {
        at.push('/');
        at.push_str(dir);
        match fs.create_dir(&at) {
            Ok(()) | Err(osyx_fat::FsError::AlreadyExists) => {}
            Err(e) => return Err(fat_err(&at, e)),
        }
    }
    let full = format!("/{path}");
    let mut f = fs
        .open(&full, osyx_fat::OpenOptions { create: true, create_new: true, truncate: false })
        .map_err(|e| fat_err(&full, e))?;
    let mut done = 0;
    while done < data.len() {
        let n = fs.write(&mut f, done as u64, &data[done..]).map_err(|e| fat_err(&full, e))?;
        if n == 0 {
            return Err(Error::Io(format!("{full}: short write")));
        }
        done += n;
    }
    Ok(())
}

fn verify_boot_contents<D: osyx_fat::BlockDevice>(fs: &mut osyx_fat::FileSystem<D>, expected: &[(String, [u8; 32])]) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    for (path, digest) in expected {
        let mut file = fs.open(&format!("/{path}"), osyx_fat::OpenOptions::default())
            .map_err(|e| Error::Verify(format!("ESP {path}: {e:?}")))?;
        let mut hash = osyx_crypto::Sha256::new();
        let mut offset = 0u64;
        loop {
            let n = fs.read(&mut file, offset, &mut buf).map_err(|e| Error::Verify(format!("ESP {path}: {e:?}")))?;
            if n == 0 { break; }
            hash.update(&buf[..n]);
            offset += n as u64;
        }
        if hash.finish() != *digest {
            return Err(Error::Verify(format!("ESP {path}: contents differ from source")));
        }
    }
    Ok(())
}

/// Reads the new system back: partition table, ESP files and sizes, root
/// consistency and the configuration files.
pub fn verify<D: Disk>(disk: &mut D, plan: &Plan, config: &Config, boot: &[(String, u64)]) -> Result<()> {
    struct Reader<'a, D: Disk>(&'a mut D);
    impl<D: Disk> osyx_part::SectorReader for Reader<'_, D> {
        fn sectors(&self) -> u64 {
            self.0.sectors()
        }
        fn read(&mut self, lba: u64, buf: &mut [u8]) -> core::result::Result<(), osyx_part::GptError> {
            self.0.read(lba, buf).map_err(|_| osyx_part::GptError::Io)
        }
    }
    let table = osyx_part::parse(&mut Reader(disk)).map_err(|e| Error::Verify(format!("partition table: {e:?}")))?;
    let esp = table.partitions.iter().find(|p| p.type_guid == osyx_part::TYPE_ESP).ok_or_else(|| Error::Verify("no ESP".into()))?;
    let root = table.partitions.iter().find(|p| p.type_guid == osyx_part::TYPE_ROOT_X86_64).ok_or_else(|| Error::Verify("no root partition".into()))?;
    if (esp.first_lba, esp.sectors(), root.first_lba, root.sectors()) != (plan.esp_first, plan.esp_sectors, plan.root_first, plan.root_sectors) {
        return Err(Error::Verify("partitions differ from the plan".into()));
    }
    {
        let mut fs = osyx_fat::FileSystem::mount(Window::new(disk, plan.esp_first, plan.esp_sectors)).map_err(|e| fat_err("ESP", e))?;
        for (path, size) in boot {
            let m = fs.metadata(&format!("/{path}")).map_err(|e| Error::Verify(format!("ESP {path}: {e:?}")))?;
            if m.size as u64 != *size {
                return Err(Error::Verify(format!("ESP {path}: {} bytes instead of {size}", m.size)));
            }
        }
    }
    let mut fs = Ext4::mount(Window::new(disk, plan.root_first, plan.root_sectors), MountOptions { read_only: true, clock: None })
        .map_err(|e| ext4_err("root", e))?;
    fs.check().map_err(|e| Error::Verify(format!("root consistency: {e}")))?;
    for path in ["/etc/hostname", "/etc/passwd", "/etc/osyx/firstboot.conf", "/etc/osyx/installed"] {
        fs.resolve(path).map_err(|e| Error::Verify(format!("{path}: {e}")))?;
    }
    let host = fs.resolve("/etc/hostname").map_err(|e| ext4_err("hostname", e))?;
    let mut b = [0u8; 64];
    let n = fs.read(host, 0, &mut b).map_err(|e| ext4_err("hostname", e))?;
    if b[..n] != *format!("{}\n", config.hostname).as_bytes() {
        return Err(Error::Verify("/etc/hostname has the wrong contents".into()));
    }
    Ok(())
}

#[cfg(test)]
mod boot_tests {
    use super::*;

    #[test]
    fn boot_write_refuses_short_name_alias() {
        let mut image = vec![0; 64 * 1024 * 1024];
        osyx_fat::format(&mut image, "TEST", 1).unwrap();
        let mut fs = osyx_fat::FileSystem::mount(image).unwrap();
        fat_write(&mut fs, "EFI/long filename.txt", b"original").unwrap();
        assert!(fat_write(&mut fs, "EFI/LONGFI~1.TXT", b"replacement").is_err());
        let mut file = fs.open("/EFI/long filename.txt", osyx_fat::OpenOptions::default()).unwrap();
        let mut data = [0; 8];
        assert_eq!(fs.read(&mut file, 0, &mut data).unwrap(), 8);
        assert_eq!(&data, b"original");
    }

    #[test]
    fn boot_verification_detects_same_size_corruption() {
        let mut image = vec![0; 64 * 1024 * 1024];
        osyx_fat::format(&mut image, "TEST", 1).unwrap();
        let mut fs = osyx_fat::FileSystem::mount(image).unwrap();
        fat_write(&mut fs, "EFI/test.bin", b"original").unwrap();
        let mut hash = osyx_crypto::Sha256::new();
        hash.update(b"original");
        let expected = vec![(String::from("EFI/test.bin"), hash.finish())];
        verify_boot_contents(&mut fs, &expected).unwrap();
        let mut file = fs.open("/EFI/test.bin", osyx_fat::OpenOptions::default()).unwrap();
        fs.write(&mut file, 0, b"altered!").unwrap();
        assert!(matches!(verify_boot_contents(&mut fs, &expected), Err(Error::Verify(_))));
    }
}
