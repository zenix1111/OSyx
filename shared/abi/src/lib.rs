//! OSyx system call ABI, version 13.
//!
//! Version 13 adds SET_FS32_BASE: the FS base that 32-bit compatibility-mode
//! code uses (see [`wow64`]). 64-bit code keeps using SET_FS_BASE.
//!
//! Version 11 adds DISCARD for demand-zero anonymous memory.
//!
//! Version 10 includes device inventory. Compatible optional extensions add
//! resumable user exception delivery (FAULT_HANDLER/FAULT_RETURN); an older
//! kernel rejects these calls with NotSupported. Optional FILEMAP_CREATE,
//! FILEMAP_MAP and FILEMAP_FLUSH calls add coherent local file sections.
//! Optional IMAGE_MAP, IMAGE_PUBLISH and IMAGE_QUERY calls share laid-out executable
//! images between processes copy-on-write. Optional SET_TIME sets the
//! real-time clock (network time).
//! Existing call numbers and layouts stay unchanged.
//!
//! Version 9 adds what the Windows runtime and VirtIO-GPU need: a
//! per-thread GS base, page protection changes, placed and aligned
//! anonymous mappings, display damage flushing and mode setting, and a
//! larger [`ipc::DisplayInfo`] (`nr::SET_GS_BASE` .. `nr::DISPLAY_SET_MODE`).
//!
//! Version 8 adds networking (sockets, name resolution, interface
//! queries and configuration; see [`net`] and `nr::SOCKET` ..
//! `nr::NET_CONFIG`).
//!
//! Version 7 adds kernel objects beyond files (pipes, IPC channels and
//! listeners, shared memory), waiting on several handles at once, standard
//! stream redirection for children, display ownership, process and mount
//! listings, `kill` and power control (see [`ipc`] and `nr::PIPE` ..
//! `nr::KILL`).
//!
//! Calling convention (x86-64 `syscall` instruction):
//! * `rax` = system call number, arguments in `rdi, rsi, rdx, r10, r8, r9`.
//! * `rcx` and `r11` are clobbered by the CPU; all other registers are preserved.
//! * Return value in `rax`: a value in `0..=MAX_RESULT` is success; values
//!   `-1..=-4095` (as `i64`) are `-(Errno)`.
//!
//! The kernel never trusts user pointers: every buffer is range checked
//! against the user half of the address space and accessed with fault
//! recovery, so a bad pointer yields [`Errno::Fault`] instead of a crash.
//!
//! Process start-up state (System V x86-64 style):
//! `rsp` -> `argc`, `argv[0..argc]`, `NULL`, `envp[..]`, `NULL`, auxiliary
//! vector (`auxv::*` key/value pairs ending with `AT_NULL`); the strings,
//! 16 random bytes (`AT_RANDOM`) and the program path (`AT_EXECFN`) lie
//! above. `rsp` is 16-byte aligned; all other general purpose registers are
//! zero.

#![no_std]

extern crate alloc;

pub mod battery;
pub mod ipc;
pub mod media;
pub mod net;
pub mod wow64;

pub const ABI_VERSION: u32 = 13;
pub mod fault;

/// Highest user virtual address + 1 (the canonical lower half).
pub const USER_END: u64 = 0x0000_8000_0000_0000;

pub mod nr {
    /// `exit(code: i32) -> !`
    pub const EXIT: u64 = 0;
    /// `write(fd: u64, buf: *const u8, len: usize) -> usize`
    pub const WRITE: u64 = 1;
    /// `map(len: usize, prot: u64) -> *mut u8`: zeroed anonymous memory.
    pub const MAP: u64 = 2;
    /// `unmap(addr: *mut u8, len: usize) -> 0`: must match one whole `map`.
    pub const UNMAP: u64 = 3;
    /// `sysinfo(out: *mut SystemInfo) -> 0`
    pub const SYSINFO: u64 = 4;
    /// `clock(id: u64) -> u64` nanoseconds.
    pub const CLOCK: u64 = 5;
    /// `spawn(args: *const ExecArgs) -> pid`
    ///
    /// Starts the ELF64 program `path` as a child process with the given
    /// argument and environment blocks (see [`ExecArgs`](super::ExecArgs)).
    /// A path without `/` is searched in `/bin`, then `/usr/bin`; a path
    /// with `/` is resolved like any other (relative to the current
    /// directory). The file must be a regular file with execute permission
    /// for the caller. The child inherits credentials and current directory.
    pub const SPAWN: u64 = 6;
    /// `wait(pid: u64, status: *mut i32) -> pid`
    ///
    /// Blocks until the child `pid` (or any child if `pid == 0`) has exited,
    /// stores its exit status and releases it.
    pub const WAIT: u64 = 7;
    /// `yield() -> 0`: gives up the rest of the time slice.
    pub const YIELD: u64 = 8;
    /// `sleep(ns: u64) -> 0`: blocks for at least `ns` nanoseconds.
    pub const SLEEP: u64 = 9;
    /// `thread_spawn(entry: u64, stack_top: u64, arg: u64, fs_base: u64) -> tid`
    ///
    /// Starts a thread in the calling process at `entry` with `rsp =
    /// stack_top` (16-byte aligned), `rdi = arg` and FS base `fs_base`.
    pub const THREAD_SPAWN: u64 = 10;
    /// `thread_exit(code: i32, done_word: *mut u32) -> !`
    ///
    /// Ends the calling thread. If `done_word` is not null the kernel stores
    /// 1 there and wakes all futex waiters on it *after* the thread has left
    /// its user stack, so a joiner may free that stack. If it was the last
    /// thread, the process exits with `code`.
    pub const THREAD_EXIT: u64 = 11;
    /// `futex_wait(addr: *const u32, expected: u32, timeout_ns: u64) -> 0`
    ///
    /// Blocks while `*addr == expected` until a `futex_wake` on `addr`
    /// (`timeout_ns == 0`: no timeout). Fails with `WouldBlock` if the value
    /// differs, `TimedOut` on timeout. Spurious returns are allowed.
    pub const FUTEX_WAIT: u64 = 12;
    /// `futex_wake(addr: *const u32, count: u32) -> woken`
    pub const FUTEX_WAKE: u64 = 13;
    /// `set_fs_base(addr: u64) -> 0`: thread pointer for TLS (`fs:[0]`).
    pub const SET_FS_BASE: u64 = 14;
    /// `gettid() -> tid`
    pub const GETTID: u64 = 15;
    /// `open(path: *const u8, path_len: usize, flags: u64, mode: u32) -> handle`
    ///
    /// Opens a file, directory or device by path (`OPEN_*` flags). Relative
    /// paths start at the current directory. `mode` gives the permission
    /// bits of a file created by `OPEN_CREATE`. A directory can only be
    /// opened for reading and is then listed with `readdir`. Handles are per
    /// process, start at 3 and are closed when the process exits.
    pub const OPEN: u64 = 16;
    /// `close(handle) -> 0`
    pub const CLOSE: u64 = 17;
    /// `read(handle, buf: *mut u8, len: usize) -> bytes` (0 at end of file).
    /// `write` (number 1) also accepts file handles.
    pub const READ: u64 = 18;
    /// `seek(handle, offset: i64, whence: u64) -> new position` (`SEEK_*`).
    pub const SEEK: u64 = 19;
    /// `fstat(handle, out: *mut FileStat) -> 0`
    pub const FSTAT: u64 = 20;
    /// `stat(path, path_len, out: *mut FileStat) -> 0` (follows symbolic links)
    pub const STAT: u64 = 21;
    /// `readdir(handle, buf: *mut u8, len: usize) -> bytes`
    ///
    /// Fills `buf` with as many [`DirRecord`](super::DirRecord)s as fit and
    /// returns the number of bytes used; 0 means the listing is complete.
    /// `.` and `..` are not listed.
    pub const READDIR: u64 = 22;
    /// `mkdir(path, path_len, mode: u32) -> 0`
    pub const MKDIR: u64 = 23;
    /// `unlink(path, path_len) -> 0`: removes a file, symbolic link or device node.
    pub const UNLINK: u64 = 24;
    /// `rmdir(path, path_len) -> 0`: removes an empty directory.
    pub const RMDIR: u64 = 25;
    /// `rename(from, from_len, to, to_len) -> 0`: replaces an existing file
    /// at `to`; both paths must be on the same volume.
    pub const RENAME: u64 = 26;
    /// `ftruncate(handle, len: u64) -> 0`
    pub const FTRUNCATE: u64 = 27;
    /// `fsync(handle) -> 0`: writes cached data and metadata and flushes the disk.
    pub const FSYNC: u64 = 28;
    /// `chdir(path, path_len) -> 0`: sets the current directory.
    pub const CHDIR: u64 = 29;
    /// `getcwd(buf: *mut u8, len: usize) -> bytes`: the current directory
    /// (absolute, no trailing NUL); `InvalidArgument` if `buf` is too small.
    pub const GETCWD: u64 = 30;
    /// `symlink(target, target_len, path, path_len) -> 0`
    pub const SYMLINK: u64 = 31;
    /// `readlink(path, path_len, buf, buf_len) -> bytes` of the link target.
    pub const READLINK: u64 = 32;
    /// `lstat(path, path_len, out: *mut FileStat) -> 0` (does not follow a
    /// final symbolic link)
    pub const LSTAT: u64 = 33;
    /// `chmod(path, path_len, mode: u32) -> 0`: owner or root only.
    pub const CHMOD: u64 = 34;
    /// `mount(args: *const MountArgs) -> 0`: root only.
    pub const MOUNT: u64 = 35;
    /// `umount(path, path_len) -> 0`: root only; `Busy` while files on the
    /// volume are open or other volumes are mounted below it.
    pub const UMOUNT: u64 = 36;
    /// `getuid() -> uid | gid << 32`
    pub const GETUID: u64 = 37;
    /// `setuid(uid: u32, gid: u32) -> 0`: root only; children inherit it.
    pub const SETUID: u64 = 38;
    /// `statfs(path, path_len, out: *mut FsStat) -> 0`
    pub const STATFS: u64 = 39;
    /// `execve(args: *const ExecArgs) -> !`
    ///
    /// Replaces the calling process's program (same rules as `spawn`).
    /// pid, handles, credentials and current directory are kept; the
    /// address space, FS base and FPU state are new. Fails with `Busy` if
    /// the process has more than one thread. On any error the old program
    /// continues unchanged.
    pub const EXECVE: u64 = 40;
    /// `pipe(out: *mut [u64; 2]) -> 0`: a pipe; `out[0]` is the read end,
    /// `out[1]` the write end. Reads block until data arrives or every
    /// write end is closed (then 0); writes block while the pipe is full and
    /// fail with `BrokenPipe` once every read end is closed.
    pub const PIPE: u64 = 41;
    /// `spawn_stdio(args: *const ExecArgs, stdio: *const [u64; 3]) -> pid`:
    /// like `spawn`, with the caller's handles `stdio[i]` installed as the
    /// child's handles 0 (stdin), 1 (stdout) and 2 (stderr);
    /// [`HANDLE_NONE`](super::HANDLE_NONE) keeps the console for that stream.
    pub const SPAWN_STDIO: u64 = 42;
    /// `channel_listen(name, name_len) -> listener`: registers an IPC
    /// service (root, or a name in `user.<uid>.` owned by the caller;
    /// `AlreadyExists` while another listener has the name).
    pub const CHANNEL_LISTEN: u64 = 43;
    /// `channel_connect(name, name_len) -> channel`: connects to a service
    /// (`NotFound` if nobody listens, `Busy` if its backlog is full).
    pub const CHANNEL_CONNECT: u64 = 44;
    /// `channel_accept(listener) -> channel`: the next pending connection
    /// (`WouldBlock` if none; wait with `wait_handles`).
    pub const CHANNEL_ACCEPT: u64 = 45;
    /// `channel_send(channel, msg: *const ChannelMsg) -> 0`: queues one
    /// message with up to `MAX_MESSAGE_HANDLES` handles (shared memory and
    /// pipe ends) duplicated to the receiver. Never blocks: `WouldBlock`
    /// when the peer's queue is full, `BrokenPipe` when the peer is gone.
    pub const CHANNEL_SEND: u64 = 46;
    /// `channel_recv(channel, msg: *mut ChannelMsg) -> bytes`: takes the next
    /// message; the received handles are written to `msg.handles` and their
    /// number to `msg.handle_count`. `WouldBlock` if the queue is empty,
    /// `BrokenPipe` if it is empty and the peer is gone.
    pub const CHANNEL_RECV: u64 = 47;
    /// `channel_peer(channel) -> pid | uid << 32` of the other end.
    pub const CHANNEL_PEER: u64 = 48;
    /// `shm_create(size) -> handle`: zeroed shared memory (at most `MAX_SHM` bytes).
    pub const SHM_CREATE: u64 = 49;
    /// `shm_map(handle, prot) -> addr`: maps the whole object (`PROT_READ`,
    /// optionally `PROT_WRITE`); `unmap` releases the mapping.
    pub const SHM_MAP: u64 = 50;
    /// `shm_size(handle) -> bytes`
    pub const SHM_SIZE: u64 = 51;
    /// `wait_handles(items: *mut WaitItem, count, timeout_ns) -> ready`:
    /// blocks until at least one item is ready (`WAIT_*` events), the
    /// timeout expires (0 ready) or the process is exiting. `timeout_ns`
    /// 0 polls, `u64::MAX` waits forever.
    pub const WAIT_HANDLES: u64 = 52;
    /// `display_info(out: *mut DisplayInfo) -> 0`
    pub const DISPLAY_INFO: u64 = 53;
    /// `display_acquire() -> addr`: root only. Makes the caller the display
    /// owner (the kernel stops drawing) and maps the framebuffer into it.
    /// `Busy` while another process owns it. Ownership ends with
    /// `display_release` or the owner's exit; the kernel then draws its
    /// status screen again.
    pub const DISPLAY_ACQUIRE: u64 = 54;
    /// `display_release() -> 0`
    pub const DISPLAY_RELEASE: u64 = 55;
    /// `proc_list(buf: *mut ProcInfo, len) -> bytes`: one record per process.
    pub const PROC_LIST: u64 = 56;
    /// `mount_list(buf: *mut MountInfo, len) -> bytes`: one record per mount.
    pub const MOUNT_LIST: u64 = 57;
    /// `power(cmd) -> !`: root only; `POWER_OFF` or `POWER_REBOOT` after
    /// unmounting every volume. Returns `NotSupported` if the machine
    /// offers no known way to do it.
    pub const POWER: u64 = 58;
    /// `kill(pid) -> 0`: ends a process (status `KILLED_STATUS`). Root may
    /// kill any process, others only processes with their own uid.
    pub const KILL: u64 = 59;
    /// `socket(kind) -> handle`: a TCP (`net::SOCK_STREAM`), UDP
    /// (`SOCK_DGRAM`) or ICMP echo (`SOCK_PING`) socket.
    pub const SOCKET: u64 = 60;
    /// `sock_bind(h, addr: *const SockAddr) -> 0`: port 0 picks an
    /// ephemeral port; address 0.0.0.0 means any local address.
    pub const SOCK_BIND: u64 = 61;
    /// `sock_connect(h, addr: *const SockAddr) -> 0`: TCP waits for the
    /// handshake (`WouldBlock` when non-blocking: poll for writable);
    /// UDP fixes the peer.
    pub const SOCK_CONNECT: u64 = 62;
    /// `sock_listen(h, backlog) -> 0` (TCP, after `sock_bind`).
    pub const SOCK_LISTEN: u64 = 63;
    /// `sock_accept(h, peer: *mut SockAddr) -> handle` of the next connection.
    pub const SOCK_ACCEPT: u64 = 64;
    /// `sock_send(h, buf, len, to: *const SockAddr | 0, flags) -> bytes`.
    pub const SOCK_SEND: u64 = 65;
    /// `sock_recv(h, buf, len, from: *mut SockAddr | 0, flags) -> bytes`;
    /// 0 on a TCP socket is the end of the stream.
    pub const SOCK_RECV: u64 = 66;
    /// `sock_ctl(h, op, arg) -> value` (`net::ctl`).
    pub const SOCK_CTL: u64 = 67;
    /// `resolve(name, len, out: *mut [u8; 4], max) -> count`: IPv4
    /// addresses of a host name (DNS, cached by TTL). `NameNotFound` if it
    /// does not exist, `DnsFailure` / `TimedOut` otherwise.
    pub const RESOLVE: u64 = 68;
    /// `net_query(kind, buf, len) -> bytes` (`net::query`).
    pub const NET_QUERY: u64 = 69;
    /// `net_config(args: *const NetConfig) -> 0`: root only.
    pub const NET_CONFIG: u64 = 70;
    /// `set_gs_base(addr: u64) -> 0`: the calling thread's GS base (the
    /// kernel does not use GS; the Windows runtime keeps its TEB there).
    pub const SET_GS_BASE: u64 = 71;
    /// `protect(addr, len, prot) -> 0`: changes the protection of whole
    /// pages inside one anonymous mapping (W^X enforced).
    pub const PROTECT: u64 = 72;
    /// `map_ex(addr, len, prot, flags) -> addr`: anonymous zeroed memory
    /// like `map`; `MAP_FIXED` places it exactly at `addr` (`AlreadyExists`
    /// if anything is mapped there), `MAP_ALIGN_64K` aligns it to 64 KiB.
    pub const MAP_EX: u64 = 73;
    /// `display_flush(x, y, w, h) -> 0`: the display owner presents a
    /// changed rectangle (needed when `DisplayInfo::backend` is
    /// `BACKEND_VIRTIO_GPU`; a no-op on a linear framebuffer).
    pub const DISPLAY_FLUSH: u64 = 74;
    /// `display_set_mode(width, height) -> 0`: root only; switches the
    /// resolution while the kernel status screen or the caller owns the
    /// display. An owner must call `display_acquire` again for the new
    /// buffer (the old mapping stays valid but is no longer shown).
    pub const DISPLAY_SET_MODE: u64 = 75;
    /// `device_list(buf: *mut DeviceInfo, len_bytes) -> bytes`.
    pub const DEVICE_LIST: u64 = 76;
    /// `fault_handler(entry) -> 0`: register a System V user exception
    /// entry point receiving `*mut fault::Context`; 0 disables delivery.
    /// It must finish via FAULT_RETURN or exit. Reset on execve/exit.
    pub const FAULT_HANDLER: u64 = 77;
    /// `fault_return(context)`: resume an outstanding exception of this
    /// thread; success never returns. Invalid addresses/flags are rejected.
    pub const FAULT_RETURN: u64 = 78;
    /// `discard(addr, len) -> 0`: whole pages inside one anonymous mapping
    /// drop their contents and memory; the next access reads zeros.
    pub const DISCARD: u64 = 79;
    /// `filemap_create(file, size, writable) -> handle`: a coherent file
    /// section; size 0 uses the file length. Writable sections may grow it.
    pub const FILEMAP_CREATE: u64 = 80;
    /// `filemap_map(section, offset, len, writable) -> address`: page-aligned
    /// offset, nonzero view length; permissions cannot exceed the section.
    pub const FILEMAP_MAP: u64 = 81;
    /// `filemap_flush(section, offset, len) -> 0`: writes the requested range
    /// to the file without changing the open file position.
    pub const FILEMAP_FLUSH: u64 = 82;
    /// `cpu_info() -> online_count | current_cpu_index << 32`.
    pub const CPU_INFO: u64 = 83;
    /// `thread_affinity(tid, mask) -> previous_mask`; tid 0 is the caller,
    /// mask 0 queries without changing it.
    pub const THREAD_AFFINITY: u64 = 84;
    /// `process_write_barrier() -> 0`: serialize stores on all online CPUs.
    pub const PROCESS_WRITE_BARRIER: u64 = 85;
    /// `prefault(addr, len) -> 0`: allocate writable anonymous destination
    /// pages in batches before a bulk copy; faults still handle the rest.
    pub const PREFAULT: u64 = 86;
    /// `proc_info(pid, out: *mut ProcInfo) -> 0`: one process record;
    /// `NotFound` if no process with `pid` exists.
    pub const PROC_INFO: u64 = 87;
    /// `time_calib(out: *mut [u64; 4]) -> 0`: writes
    /// `[monotonic_ns, tsc, tsc_per_tick, realtime_ns]` sampled together, so
    /// a process can compute both clocks from RDTSC without further calls.
    /// `tsc_per_tick` is 0 until the kernel has calibrated the TSC.
    pub const TIME_CALIB: u64 = 88;
    /// `image_map(file, addr, len) -> 0`: maps the shared image of `file`
    /// laid out at `addr` into the untouched anonymous mapping that is
    /// exactly `[addr, addr + len)`, read-only with copy-on-write.
    /// `NotFound` if no process of this user published one.
    pub const IMAGE_MAP: u64 = 89;
    /// `image_publish(file, addr, len) -> 0`: the image of `file` laid out
    /// and relocated in the anonymous mapping `[addr, addr + len)` becomes
    /// shareable by later `image_map` calls of the same user. Its pages
    /// stay mapped read-only with copy-on-write. `AlreadyExists` if one is
    /// published already (nothing changes then).
    pub const IMAGE_PUBLISH: u64 = 90;
    /// `image_query(file) -> addr`: where a published image of `file` for
    /// this user lies; `NotFound` if there is none.
    pub const IMAGE_QUERY: u64 = 91;
    /// `set_time(unix_ns: u64) -> 0`: sets the real-time clock
    /// (`CLOCK_REALTIME`); root only.
    pub const SET_TIME: u64 = 92;
    /// `firmware(op, a, b, c, d) -> value`: firmware access for the ACPI
    /// service; root only. See [`crate::firmware`].
    pub const FIRMWARE: u64 = 93;
    /// `thread_priority(tid, priority) -> previous`: scheduling priority of
    /// a thread of the caller's process (tid 0 = the caller), one of
    /// [`crate::priority`]; `priority::QUERY` only reads it. Raising a
    /// thread above `NORMAL` keeps it time-sliced: waiting threads age
    /// towards it, so none starves.
    pub const THREAD_PRIORITY: u64 = 94;
    /// `futex_wait_owned(addr: *const u32, expected: u32, timeout_ns: u64,
    /// owner: tid) -> 0`: `futex_wait` on a lock held by thread `owner` of
    /// the caller's process (0: unknown), which inherits the caller's
    /// priority while it waits.
    pub const FUTEX_WAIT_OWNED: u64 = 95;
    /// `set_fs32_base(base: u64) -> 0`: FS base for 32-bit compatibility-mode
    /// code, which reads its TEB at `fs:[0x18]`. The kernel stores it in the
    /// thread's 32-bit FS data descriptor, switched in with the thread on
    /// every context switch. IA-32e keeps one hidden FS base, so a non-zero
    /// base also replaces what 64-bit code sees until it calls
    /// [`SET_FS_BASE`] again; 0 restores the thread's 64-bit base. `base`
    /// must be page-aligned, below 4 GiB and (unless 0) in the user half.
    pub const SET_FS32_BASE: u64 = 96;
}

/// Thread priorities (`nr::THREAD_PRIORITY`).
pub mod priority {
    pub const IDLE: u64 = 0;
    pub const LOW: u64 = 1;
    pub const BELOW_NORMAL: u64 = 2;
    pub const NORMAL: u64 = 3;
    pub const ABOVE_NORMAL: u64 = 4;
    pub const HIGH: u64 = 5;
    pub const REALTIME: u64 = 6;
    /// Reads the priority without changing it.
    pub const QUERY: u64 = u64::MAX;
    /// Reads the scheduler's view without changing anything: the own
    /// priority in bits 0..8, the effective one (boost and inheritance
    /// applied) in 8..16, the boost in 16..24 and the inherited priority
    /// in 24..32.
    pub const INFO: u64 = u64::MAX - 1;
}

/// Operations of `nr::FIRMWARE`.
pub mod firmware {
    /// `(sig, n, buf, len) -> table length`: copies the `n`-th ACPI table
    /// with little-endian signature `sig` ("DSDT", "SSDT", ...).
    pub const TABLE: u64 = 1;
    /// `(port, width, value, write) -> value read`: I/O port access
    /// (width 1, 2 or 4); ports of kernel devices are refused.
    pub const PORT: u64 = 2;
    /// `(phys, width, value, write) -> value read`: aligned physical memory
    /// access (width 1, 2, 4 or 8) outside the kernel's RAM.
    pub const PHYS: u64 = 3;
    /// `(bus << 16 | device << 8 | function, offset, width | 0x100 to
    /// write, value) -> value read`: PCI configuration, segment 0.
    pub const PCI: u64 = 4;
}

/// Battery state published by the ACPI service in [`BATTERY_STATUS_PATH`]:
/// a first line `percent charging ac` (`percent` 0-100, `charging` and
/// `ac` 0 or 1), or `none` when the machine reports no battery, and an
/// optional second line of `key=value` details. See [`battery`].
pub const BATTERY_STATUS_PATH: &str = "/run/battery";

/// `map_ex` flags.
pub const MAP_FIXED: u64 = 1;
pub const MAP_ALIGN_64K: u64 = 2;

/// "No handle" in `spawn_stdio`'s array.
pub const HANDLE_NONE: u64 = u64::MAX;
pub const STDIN: u64 = 0;
/// Exit status of a process ended by `kill`.
pub const KILLED_STATUS: i32 = 0x4000_0100;

pub const OPEN_READ: u64 = 1 << 0;
pub const OPEN_WRITE: u64 = 1 << 1;
/// Create the file if it does not exist (requires `OPEN_WRITE`).
pub const OPEN_CREATE: u64 = 1 << 2;
/// Truncate to zero length (requires `OPEN_WRITE`).
pub const OPEN_TRUNCATE: u64 = 1 << 3;
/// Every write goes to the end of the file.
pub const OPEN_APPEND: u64 = 1 << 4;
/// With `OPEN_CREATE`: fail with `AlreadyExists` if the file exists.
pub const OPEN_EXCLUSIVE: u64 = 1 << 5;
/// Fail with `NotADirectory` unless the path names a directory.
pub const OPEN_DIRECTORY: u64 = 1 << 6;
/// Fail with `Loop` if the final component is a symbolic link.
pub const OPEN_NOFOLLOW: u64 = 1 << 7;
/// Match every path component case-insensitively (ASCII), as Windows does.
/// Exact matches win; otherwise the first case-insensitive match is used.
pub const OPEN_CASE_INSENSITIVE: u64 = 1 << 8;
pub const OPEN_ALL: u64 = (1 << 9) - 1;

pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

/// Longest path accepted by the file system calls.
pub const MAX_PATH: usize = 1024;
/// Longest single path component.
pub const MAX_NAME_LEN: usize = 255;
/// Symbolic links followed while resolving one path.
pub const MAX_SYMLINKS: usize = 40;
/// Open handles per process.
pub const MAX_HANDLES: usize = 4096;
/// Largest single `read`.
pub const MAX_READ: usize = 1 << 20;
/// First handle number used for files (0-2 are the console streams).
pub const FIRST_FILE_HANDLE: u64 = 3;

pub const KIND_FILE: u32 = 1;
pub const KIND_DIR: u32 = 2;
pub const KIND_SYMLINK: u32 = 3;
pub const KIND_CHAR_DEVICE: u32 = 4;
pub const KIND_BLOCK_DEVICE: u32 = 5;

/// Permission bits (`FileStat::mode`).
pub const MODE_SETUID: u32 = 0o4000;
pub const MODE_SETGID: u32 = 0o2000;
/// On a directory: only the owner of an entry (or of the directory, or
/// root) may remove or rename it.
pub const MODE_STICKY: u32 = 0o1000;
pub const MODE_PERMS: u32 = 0o7777;

/// FAT attribute bits (`FileStat::attributes`, 0 on other file systems).
pub const ATTR_READ_ONLY: u32 = 0x01;
pub const ATTR_HIDDEN: u32 = 0x02;
pub const ATTR_SYSTEM: u32 = 0x04;
pub const ATTR_DIRECTORY: u32 = 0x10;
pub const ATTR_ARCHIVE: u32 = 0x20;

/// The super-user id: bypasses permission checks (not `setuid` limits).
pub const ROOT_UID: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileStat {
    pub size: u64,
    /// Inode number, unique within `dev`.
    pub ino: u64,
    /// Id of the mounted volume (stable while it stays mounted).
    pub dev: u64,
    /// Storage used, in 512-byte units.
    pub blocks: u64,
    /// Times in nanoseconds since 1970-01-01 UTC (0 = unknown).
    pub atime_ns: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    /// `KIND_*`.
    pub kind: u32,
    /// Permission bits (`MODE_*`, `0o777`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    /// FAT attribute bits (`ATTR_*`), 0 elsewhere.
    pub attributes: u32,
    /// Device number of a device node (0 otherwise).
    pub rdev: u32,
    pub reserved: u32,
}

/// One `readdir` record: this header, then `name_len` bytes of UTF-8 name,
/// padded so the next record starts 8-byte aligned (`record_len` bytes in all).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirRecord {
    pub ino: u64,
    /// `KIND_*` of the entry (without following symbolic links).
    pub kind: u32,
    pub reserved: u16,
    pub name_len: u16,
}

pub const DIR_RECORD_HEADER: usize = 16;

impl DirRecord {
    /// Total bytes of a record with a `name_len`-byte name.
    pub const fn record_len(name_len: usize) -> usize {
        (DIR_RECORD_HEADER + name_len + 7) & !7
    }

    pub fn encode(&self, name: &[u8], out: &mut [u8]) -> Option<usize> {
        let len = Self::record_len(name.len());
        if out.len() < len || name.len() != self.name_len as usize {
            return None;
        }
        out[0..8].copy_from_slice(&self.ino.to_le_bytes());
        out[8..12].copy_from_slice(&self.kind.to_le_bytes());
        out[12..14].copy_from_slice(&self.reserved.to_le_bytes());
        out[14..16].copy_from_slice(&self.name_len.to_le_bytes());
        out[16..16 + name.len()].copy_from_slice(name);
        out[16 + name.len()..len].fill(0);
        Some(len)
    }

    /// Parses the record at the start of `buf`: (record, name, record length).
    pub fn decode(buf: &[u8]) -> Option<(DirRecord, &[u8], usize)> {
        let h = buf.get(..DIR_RECORD_HEADER)?;
        let r = DirRecord {
            ino: u64::from_le_bytes(h[0..8].try_into().ok()?),
            kind: u32::from_le_bytes(h[8..12].try_into().ok()?),
            reserved: u16::from_le_bytes([h[12], h[13]]),
            name_len: u16::from_le_bytes([h[14], h[15]]),
        };
        let len = Self::record_len(r.name_len as usize);
        let name = buf.get(DIR_RECORD_HEADER..DIR_RECORD_HEADER + r.name_len as usize)?;
        (buf.len() >= len).then_some((r, name, len))
    }
}

/// Argument block of `mount`. Strings are UTF-8, not NUL-terminated.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MountArgs {
    /// Device path (e.g. `/dev/disks/vda2`); ignored by `tmpfs`.
    pub source: u64,
    pub source_len: u64,
    /// Existing directory to mount on.
    pub target: u64,
    pub target_len: u64,
    /// `"fat32"`, `"ext4"` or `"tmpfs"`.
    pub fstype: u64,
    pub fstype_len: u64,
    /// `MOUNT_*` flags.
    pub flags: u64,
    /// tmpfs: maximum bytes of memory (0 = default).
    pub size_limit: u64,
}

pub const MOUNT_READ_ONLY: u64 = 1 << 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsStat {
    /// Bytes per allocation unit.
    pub block_size: u64,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
    /// Volume id (`FileStat::dev`).
    pub dev: u64,
    /// `MOUNT_*` flags of the mount.
    pub flags: u64,
    /// NUL-padded file system type name.
    pub fstype: [u8; 16],
}

/// Maximum number of threads per process.
pub const MAX_THREADS: usize = 256;

/// Largest argument + environment block of `spawn` / `execve` (bytes).
pub const MAX_EXEC_ARGS: usize = 128 * 1024;
/// Most argument or environment strings.
pub const MAX_EXEC_STRINGS: usize = 4096;
/// Directories searched for a program name without `/`.
pub const PROGRAM_PATH: [&str; 2] = ["/bin", "/usr/bin"];

/// Argument block of `spawn` and `execve`. `argv` and `envp` are
/// NUL-terminated UTF-8 strings back to back (`argv_len` 0: `argv` is just
/// the path; `envp_len` 0: empty environment).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecArgs {
    pub path: u64,
    pub path_len: u64,
    pub argv: u64,
    pub argv_len: u64,
    pub envp: u64,
    pub envp_len: u64,
}

/// Auxiliary vector keys passed on the initial stack.
pub mod auxv {
    pub const AT_NULL: u64 = 0;
    /// Address of the program headers in memory.
    pub const AT_PHDR: u64 = 3;
    pub const AT_PHENT: u64 = 4;
    pub const AT_PHNUM: u64 = 5;
    pub const AT_PAGESZ: u64 = 6;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_UID: u64 = 11;
    pub const AT_EUID: u64 = 12;
    pub const AT_GID: u64 = 13;
    pub const AT_EGID: u64 = 14;
    /// 1 if the program runs with privileges it was not started with (never on OSyx).
    pub const AT_SECURE: u64 = 23;
    /// Address of 16 random bytes.
    pub const AT_RANDOM: u64 = 25;
    /// Address of the NUL-terminated path the program was loaded from.
    pub const AT_EXECFN: u64 = 31;
}

/// The initial stack of a new program: built by the kernel, read by the
/// program's runtime. Layout from `rsp` upwards: `argc`, `argv[]`, `NULL`,
/// `envp[]`, `NULL`, auxiliary pairs ending with `AT_NULL`, padding to 16
/// bytes, then the argument and environment strings, the 16 `AT_RANDOM`
/// bytes and the `AT_EXECFN` path, which ends right below the stack top.
pub mod startup {
    use super::auxv;

    pub const RANDOM_LEN: usize = 16;

    /// Contents of an initial stack.
    pub struct Image<'a> {
        pub argv: &'a [&'a [u8]],
        pub envp: &'a [&'a [u8]],
        /// Auxiliary entries; `AT_RANDOM`, `AT_EXECFN` and `AT_NULL` are added.
        pub aux: &'a [(u64, u64)],
        pub random: [u8; RANDOM_LEN],
        /// Path the program was loaded from (without NUL).
        pub execfn: &'a [u8],
    }

    impl Image<'_> {
        fn strings_len(&self) -> usize {
            let strs: usize = self.argv.iter().chain(self.envp).map(|s| s.len() + 1).sum();
            strs + RANDOM_LEN + self.execfn.len() + 1
        }

        fn words(&self) -> usize {
            1 + self.argv.len() + 1 + self.envp.len() + 1 + 2 * (self.aux.len() + 3)
        }

        /// Bytes the image occupies below a 16-byte aligned stack top.
        pub fn size(&self) -> usize {
            (self.strings_len() + self.words() * 8 + 15) & !15
        }

        /// Writes the image for a stack whose top is `top` (16-byte aligned)
        /// into `out`, which stands for the `size()` bytes below `top`.
        /// Returns the initial `rsp` (`top - size()`), or `None` if `top` is
        /// misaligned, `out` has the wrong length or a string contains NUL.
        pub fn build(&self, top: u64, out: &mut [u8]) -> Option<u64> {
            let size = self.size();
            if !top.is_multiple_of(16) || out.len() != size || (top as usize) < size {
                return None;
            }
            if self.argv.iter().chain(self.envp).chain([&self.execfn]).any(|s| s.contains(&0)) {
                return None;
            }
            let sp = top - size as u64;
            out.fill(0);
            // Strings in order argv, envp, random, execfn, ending at `top`.
            let mut s = size - self.strings_len();
            let mut w = 0;
            let mut word = |out: &mut [u8], v: u64| {
                out[w..w + 8].copy_from_slice(&v.to_le_bytes());
                w += 8;
            };
            word(out, self.argv.len() as u64);
            for list in [self.argv, self.envp] {
                for text in list {
                    out[s..s + text.len()].copy_from_slice(text);
                    word(out, sp + s as u64);
                    s += text.len() + 1;
                }
                word(out, 0);
            }
            let random = sp + s as u64;
            out[s..s + RANDOM_LEN].copy_from_slice(&self.random);
            s += RANDOM_LEN;
            let execfn = sp + s as u64;
            out[s..s + self.execfn.len()].copy_from_slice(self.execfn);
            for &(k, v) in
                self.aux.iter().chain(&[(auxv::AT_RANDOM, random), (auxv::AT_EXECFN, execfn), (auxv::AT_NULL, 0)])
            {
                word(out, k);
                word(out, v);
            }
            Some(sp)
        }
    }

    /// Where the parts of an initial stack are (addresses).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Layout {
        pub argc: u64,
        /// Address of `argv[0]` (the pointer).
        pub argv: u64,
        /// Address of `envp[0]`.
        pub envp: u64,
        /// Number of environment pointers before the `NULL`.
        pub envc: u64,
        /// Address of the first auxiliary pair.
        pub auxv: u64,
    }

    /// Finds the arrays of the initial stack at `sp`; `read` loads the
    /// 8-byte word at an address. At most `max_env` environment pointers are
    /// scanned for the terminating `NULL` (`None` if it is not found).
    pub fn locate(sp: u64, max_env: u64, read: impl Fn(u64) -> u64) -> Option<Layout> {
        let argc = read(sp);
        let argv = sp + 8;
        if read(argv + argc * 8) != 0 {
            return None;
        }
        let envp = argv + (argc + 1) * 8;
        let envc = (0..=max_env).find(|&i| read(envp + i * 8) == 0)?;
        Some(Layout { argc, argv, envp, envc, auxv: envp + (envc + 1) * 8 })
    }

    /// Value of auxiliary entry `key`, scanning at most `max` pairs.
    pub fn aux_value(auxv: u64, key: u64, max: u64, read: impl Fn(u64) -> u64) -> Option<u64> {
        for i in 0..max {
            let k = read(auxv + i * 16);
            if k == auxv::AT_NULL {
                return None;
            }
            if k == key {
                return Some(read(auxv + i * 16 + 8));
            }
        }
        None
    }
}

pub const STDOUT: u64 = 1;
pub const STDERR: u64 = 2;

pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;

/// Monotonic clock since boot.
pub const CLOCK_MONOTONIC: u64 = 0;
/// Wall-clock time: nanoseconds since 1970-01-01 UTC (from the RTC).
pub const CLOCK_REALTIME: u64 = 1;

pub const MAX_WRITE: usize = 1 << 20;

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno {
    /// An argument is malformed or out of range.
    InvalidArgument = 1,
    /// A user pointer is outside user space or not mapped.
    Fault = 2,
    /// Not enough memory.
    NoMemory = 3,
    /// The handle / file descriptor does not exist.
    BadHandle = 4,
    /// The system call number is unknown or the operation is unsupported.
    NotSupported = 5,
    /// The operation violates a security policy (e.g. writable + executable).
    PermissionDenied = 6,
    /// The named object (e.g. a program for `spawn`) does not exist.
    NotFound = 7,
    /// `wait` was called but the caller has no (matching) child.
    NoChild = 8,
    /// `futex_wait`: the value no longer matched; retry.
    WouldBlock = 9,
    /// A blocking call reached its timeout.
    TimedOut = 10,
    /// A blocking call was interrupted because the process is exiting.
    Interrupted = 11,
    AlreadyExists = 12,
    NotADirectory = 13,
    IsADirectory = 14,
    DirectoryNotEmpty = 15,
    /// The volume is full.
    NoSpace = 16,
    /// The device reported an error or the volume is damaged.
    Io = 17,
    /// The file would exceed the file system's size limit.
    FileTooLarge = 18,
    /// The volume or handle does not allow writing.
    ReadOnly = 19,
    /// The process already has `MAX_HANDLES` open handles.
    TooManyHandles = 20,
    /// `rename` between different volumes.
    CrossDevice = 21,
    /// The object is in use (`umount` of a volume with open files, raw
    /// writes to a mounted disk, removing an open file on FAT).
    Busy = 22,
    /// Too many symbolic links while resolving a path, or `OPEN_NOFOLLOW`
    /// on a link.
    Loop = 23,
    /// The volume uses a feature this driver does not implement (it is
    /// refused rather than risked).
    Unsupported = 24,
    /// `spawn` / `execve`: not a loadable ELF64 x86-64 executable (or one
    /// needing a dynamic linker).
    BadExecutable = 25,
    /// The other end of a pipe or channel is closed.
    BrokenPipe = 26,
    /// The local port (or address and port) is taken.
    AddrInUse = 27,
    /// The address is not configured on this machine.
    AddrNotAvailable = 28,
    /// No route to the destination network.
    NetUnreachable = 29,
    HostUnreachable = 30,
    /// The peer refused the connection (TCP reset, ICMP port unreachable).
    ConnRefused = 31,
    ConnReset = 32,
    NotConnected = 33,
    AlreadyConnected = 34,
    MessageTooLong = 35,
    /// The host name does not exist.
    NameNotFound = 36,
    /// Name resolution failed (no server, server failure, bad answer).
    DnsFailure = 37,
}

const ALL_ERRNOS: [Errno; 37] = [
    Errno::InvalidArgument,
    Errno::Fault,
    Errno::NoMemory,
    Errno::BadHandle,
    Errno::NotSupported,
    Errno::PermissionDenied,
    Errno::NotFound,
    Errno::NoChild,
    Errno::WouldBlock,
    Errno::TimedOut,
    Errno::Interrupted,
    Errno::AlreadyExists,
    Errno::NotADirectory,
    Errno::IsADirectory,
    Errno::DirectoryNotEmpty,
    Errno::NoSpace,
    Errno::Io,
    Errno::FileTooLarge,
    Errno::ReadOnly,
    Errno::TooManyHandles,
    Errno::CrossDevice,
    Errno::Busy,
    Errno::Loop,
    Errno::Unsupported,
    Errno::BadExecutable,
    Errno::BrokenPipe,
    Errno::AddrInUse,
    Errno::AddrNotAvailable,
    Errno::NetUnreachable,
    Errno::HostUnreachable,
    Errno::ConnRefused,
    Errno::ConnReset,
    Errno::NotConnected,
    Errno::AlreadyConnected,
    Errno::MessageTooLong,
    Errno::NameNotFound,
    Errno::DnsFailure,
];

impl Errno {
    pub fn from_raw(v: u64) -> Option<Errno> {
        ALL_ERRNOS.iter().copied().find(|&e| e as u64 == v)
    }

    pub fn name(self) -> &'static str {
        match self {
            Errno::InvalidArgument => "invalid argument",
            Errno::Fault => "bad address",
            Errno::NoMemory => "out of memory",
            Errno::BadHandle => "bad handle",
            Errno::NotSupported => "not supported",
            Errno::PermissionDenied => "permission denied",
            Errno::NotFound => "not found",
            Errno::NoChild => "no child process",
            Errno::WouldBlock => "operation would block",
            Errno::TimedOut => "timed out",
            Errno::Interrupted => "interrupted",
            Errno::AlreadyExists => "already exists",
            Errno::NotADirectory => "not a directory",
            Errno::IsADirectory => "is a directory",
            Errno::DirectoryNotEmpty => "directory not empty",
            Errno::NoSpace => "no space left on volume",
            Errno::Io => "I/O error",
            Errno::FileTooLarge => "file too large",
            Errno::ReadOnly => "read-only",
            Errno::TooManyHandles => "too many open handles",
            Errno::CrossDevice => "cross-volume operation",
            Errno::Busy => "resource busy",
            Errno::Loop => "too many symbolic links",
            Errno::Unsupported => "unsupported file system feature",
            Errno::BadExecutable => "not a loadable executable",
            Errno::BrokenPipe => "the other end is closed",
            Errno::AddrInUse => "address in use",
            Errno::AddrNotAvailable => "address not available",
            Errno::NetUnreachable => "network unreachable",
            Errno::HostUnreachable => "host unreachable",
            Errno::ConnRefused => "connection refused",
            Errno::ConnReset => "connection reset by peer",
            Errno::NotConnected => "not connected",
            Errno::AlreadyConnected => "already connected",
            Errno::MessageTooLong => "message too long",
            Errno::NameNotFound => "host name not found",
            Errno::DnsFailure => "name resolution failed",
        }
    }
}

/// Encodes a kernel result into the `rax` return value.
pub fn encode(r: Result<u64, Errno>) -> u64 {
    match r {
        Ok(v) => v,
        Err(e) => (-(e as i64)) as u64,
    }
}

/// Decodes a raw `rax` return value.
pub fn decode(raw: u64) -> Result<u64, Errno> {
    let signed = raw as i64;
    if (-4095..0).contains(&signed) {
        Err(Errno::from_raw((-signed) as u64).unwrap_or(Errno::NotSupported))
    } else {
        Ok(raw)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemInfo {
    pub abi_version: u32,
    pub page_size: u32,
    pub total_memory: u64,
    pub free_memory: u64,
    pub uptime_ns: u64,
    pub pid: u64,
    /// NUL-padded UTF-8 kernel version.
    pub kernel_version: [u8; 16],
    /// Scheduler timer samples summed across all online CPUs.
    pub ticks: u64,
    pub idle_ticks: u64,
    /// Successful physical block I/O, excluding partition wrapper duplicates.
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
}

/// Exit status reported when the kernel terminates a process because of a
/// CPU exception: `EXCEPTION_EXIT_BASE | vector`.
pub const EXCEPTION_EXIT_BASE: i32 = 0x4000_0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_encoding_round_trips() {
        for v in [0u64, 1, 4096, u64::MAX >> 1] {
            assert_eq!(decode(encode(Ok(v))), Ok(v));
        }
        for (i, e) in ALL_ERRNOS.into_iter().enumerate() {
            assert_eq!(e as usize, i + 1, "errno values are dense");
            assert_eq!(decode(encode(Err(e))), Err(e));
            assert_eq!(Errno::from_raw(e as u64), Some(e));
        }
        assert_eq!(Errno::from_raw(0), None);
        assert_eq!(Errno::from_raw(ALL_ERRNOS.len() as u64 + 1), None);
        // Large unsigned values outside the error window are successes.
        assert_eq!(decode(u64::MAX - 5000), Ok(u64::MAX - 5000));
        assert_eq!(decode((-99i64) as u64), Err(Errno::NotSupported));
    }

    #[test]
    fn sysinfo_layout_is_stable() {
        assert_eq!(core::mem::size_of::<SystemInfo>(), 88);
        assert_eq!(core::mem::size_of::<FileStat>(), 88);
        assert_eq!(core::mem::size_of::<DirRecord>(), DIR_RECORD_HEADER);
        assert_eq!(core::mem::size_of::<MountArgs>(), 64);
        assert_eq!(core::mem::size_of::<FsStat>(), 72);
        assert_eq!(core::mem::size_of::<ExecArgs>(), 48);
        assert_eq!(core::mem::size_of::<ipc::ChannelMsg>(), 32);
        assert_eq!(core::mem::size_of::<ipc::WaitItem>(), 16);
        assert_eq!(core::mem::size_of::<ipc::DisplayInfo>(), 48);
        assert_eq!(core::mem::size_of::<ipc::ProcInfo>(), 80);
        assert_eq!(core::mem::size_of::<ipc::MountInfo>(), 144);
        assert_eq!(core::mem::size_of::<net::SockAddr>(), 8);
        assert_eq!(core::mem::size_of::<net::NetIface>(), 112);
        assert_eq!(core::mem::size_of::<net::NetRoute>(), 12);
        assert_eq!(core::mem::size_of::<net::NetArp>(), 16);
        assert_eq!(core::mem::size_of::<net::NetSocket>(), 56);
        assert_eq!(core::mem::size_of::<net::NetStats>(), 8 * net::NET_STATS);
        assert_eq!(core::mem::size_of::<net::NetDnsEntry>(), 80);
        assert_eq!(core::mem::size_of::<net::NetConfig>(), 28);
        assert_eq!(core::mem::size_of::<net::SockAddr>(), 8);
        assert_eq!(core::mem::size_of::<net::NetIface>(), 112);
        assert_eq!(core::mem::size_of::<net::NetRoute>(), 12);
        assert_eq!(core::mem::size_of::<net::NetArp>(), 16);
        assert_eq!(core::mem::size_of::<net::NetSocket>(), 56);
        assert_eq!(core::mem::size_of::<net::NetStats>(), 8 * net::NET_STATS);
        assert_eq!(core::mem::size_of::<net::NetDnsEntry>(), 80);
        assert_eq!(core::mem::size_of::<net::NetConfig>(), 28);
    }

    /// Reads NUL-terminated bytes at `addr` of an image that ends at `top`.
    fn c_str(mem: &[u8], top: u64, addr: u64) -> &[u8] {
        let off = mem.len() - (top - addr) as usize;
        let len = mem[off..].iter().position(|&b| b == 0).unwrap();
        &mem[off..off + len]
    }

    #[test]
    fn startup_image_round_trips() {
        use startup::*;
        let top = 0x7FFF_FFFF_0000u64;
        let argv: [&[u8]; 3] = [b"/bin/probe", b"one", b""];
        let envp: [&[u8]; 2] = [b"PATH=/bin:/usr/bin", b"HOME=/"];
        let img = Image {
            argv: &argv,
            envp: &envp,
            aux: &[(auxv::AT_PAGESZ, 4096), (auxv::AT_ENTRY, 0x40_1000)],
            random: [7; RANDOM_LEN],
            execfn: b"/usr/bin/probe",
        };
        let mut mem = [0xEEu8; 512];
        let size = img.size();
        assert_eq!(size % 16, 0);
        assert!(img.build(top, &mut mem[..size - 8]).is_none(), "wrong buffer length");
        assert!(img.build(top + 8, &mut mem[..size]).is_none(), "misaligned top");
        let sp = img.build(top, &mut mem[..size]).unwrap();
        assert_eq!(sp, top - size as u64);
        assert_eq!(sp % 16, 0);
        let mem = &mem[..size];
        let read = |a: u64| {
            let off = (a - sp) as usize;
            u64::from_le_bytes(mem[off..off + 8].try_into().unwrap())
        };
        let l = locate(sp, 100, read).unwrap();
        assert_eq!((l.argc, l.envc), (3, 2));
        for (i, want) in argv.iter().enumerate() {
            assert_eq!(c_str(mem, top, read(l.argv + i as u64 * 8)), *want);
        }
        for (i, want) in envp.iter().enumerate() {
            assert_eq!(c_str(mem, top, read(l.envp + i as u64 * 8)), *want);
        }
        assert_eq!(aux_value(l.auxv, auxv::AT_PAGESZ, 64, read), Some(4096));
        assert_eq!(aux_value(l.auxv, auxv::AT_ENTRY, 64, read), Some(0x40_1000));
        assert_eq!(aux_value(l.auxv, auxv::AT_UID, 64, read), None);
        let random = aux_value(l.auxv, auxv::AT_RANDOM, 64, read).unwrap();
        let off = (random - sp) as usize;
        assert_eq!(&mem[off..off + RANDOM_LEN], &[7; RANDOM_LEN]);
        let execfn = aux_value(l.auxv, auxv::AT_EXECFN, 64, read).unwrap();
        assert_eq!(c_str(mem, top, execfn), b"/usr/bin/probe");
        // The path ends right below the top; nothing is written above it.
        assert_eq!(execfn + 15, top);
    }

    #[test]
    fn startup_image_edge_cases() {
        use startup::*;
        let empty = Image { argv: &[], envp: &[], aux: &[], random: [0; RANDOM_LEN], execfn: b"" };
        let mut buf = [0u8; 128];
        let sp = empty.build(0x1000, &mut buf[..empty.size()]).unwrap();
        let mem = &buf[..empty.size()];
        let read = |a: u64| u64::from_le_bytes(mem[(a - sp) as usize..(a - sp) as usize + 8].try_into().unwrap());
        let l = locate(sp, 0, read).unwrap();
        assert_eq!((l.argc, l.envc), (0, 0));
        assert!(aux_value(l.auxv, auxv::AT_EXECFN, 8, read).is_some());
        let nul: [&[u8]; 1] = [b"a\0b"];
        let bad = Image { argv: &nul, ..empty };
        assert!(bad.build(0x1000, &mut buf[..bad.size()]).is_none());
        // An environment longer than the scan limit is reported, not overrun.
        let many: [&[u8]; 5] = [b"A=1"; 5];
        let long = Image { envp: &many, argv: &[], aux: &[], random: [0; RANDOM_LEN], execfn: b"" };
        let mut buf = [0u8; 256];
        let sp = long.build(0x1000, &mut buf[..long.size()]).unwrap();
        let mem = &buf[..long.size()];
        let read = |a: u64| u64::from_le_bytes(mem[(a - sp) as usize..(a - sp) as usize + 8].try_into().unwrap());
        assert!(locate(sp, 4, read).is_none());
        assert_eq!(locate(sp, 5, read).map(|l| l.envc), Some(5));
    }

    #[test]
    fn dir_records_round_trip_and_reject_truncation() {
        let mut buf = [0xAAu8; 64];
        let rec = DirRecord { ino: 1234, kind: KIND_FILE, reserved: 0, name_len: 9 };
        let n = rec.encode(b"hello.txt", &mut buf).unwrap();
        assert_eq!(n, 32);
        let (r, name, len) = DirRecord::decode(&buf).unwrap();
        assert_eq!((r, name, len), (rec, &b"hello.txt"[..], 32));
        assert!(DirRecord::decode(&buf[..31]).is_none());
        assert!(rec.encode(b"hello.txt", &mut buf[..31]).is_none());
        assert!(rec.encode(b"wrong", &mut buf).is_none());
        assert_eq!(DirRecord::record_len(0), 16);
        assert_eq!(DirRecord::record_len(1), 24);
    }
}
