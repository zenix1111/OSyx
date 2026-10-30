# System call ABI (version 13)

Defined in `shared/abi`; kernel side in `kernel/src/syscall.rs`, user side in
`runtime/os-sys`. Version 13 adds `set_fs32_base` (96); the table below lists
the calls up to the file system set, newer numbers are documented in
`osyx_abi::nr`.

## Convention

ABI v10 appends `ticks`, `idle_ticks`, `disk_read_bytes`, `disk_write_bytes`
to SystemInfo (88 bytes), and `cpu_ticks` to ProcInfo (80 bytes). Programs
and kernel must be rebuilt together. Tick counters are single-CPU scheduler
samples, including kernel time on behalf of a process. Disk counters count
successful physical transfers once, excluding duplicate partition wrappers.
Call 76, `device_list(buf, len_bytes)`, copies 256-byte DeviceInfo records
(description[96], class[32], hardware_id[64], location[64], all NUL-padded
UTF-8). The inventory contains real PCI functions and attached HID inputs.

- `syscall` instruction; number in `rax`; arguments in `rdi, rsi, rdx, r10, r8, r9`.
- `rcx` and `r11` are clobbered; all other registers are preserved.
- Result in `rax`: success values are non-negative; errors are `-errno`
  (`-1 … -4095` as `i64`).
- Entry runs with interrupts masked (FMASK clears IF, TF, DF, NT, AC) until
  the stack switch, then re-enables them; a system call may be preempted and
  may block (`wait`, `sleep`).

## Calls

| # | Name | Arguments | Result |
|---|---|---|---|
| 0 | `exit` | `code: i32` | does not return |
| 1 | `write` | handle (1 stdout, 2 stderr, or a file), `buf`, `len ≤ 1 MiB` | bytes written |
| 2 | `map` | `len`, `prot` (R=1, W=2, X=4) | address of zeroed pages |
| 3 | `unmap` | `addr`, `len` (must match one whole `map`) | 0 |
| 4 | `sysinfo` | `out: *mut SystemInfo` (88 bytes) | 0 |
| 5 | `clock` | `id` (0 = monotonic since boot, 1 = wall clock since 1970 UTC) | nanoseconds (1 ms resolution) |
| 6 | `spawn` | `args: *const ExecArgs` (48 bytes) | child pid |
| 7 | `wait` | `pid` (0 = any child), `status: *mut i32` (may be null) | pid of the reaped child |
| 8 | `yield` | — | 0 |
| 9 | `sleep` | `ns` (rounded up to 1 ms ticks) | 0 |
| 10 | `thread_spawn` | `entry`, `stack_top` (16-byte aligned), `arg` (→ `rdi`), `fs_base` | thread id |
| 11 | `thread_exit` | `code`, `done_word: *mut u32` (may be null) | does not return |
| 12 | `futex_wait` | `addr` (4-byte aligned), `expected: u32`, `timeout_ns` (0 = none) | 0 |
| 13 | `futex_wake` | `addr`, `count` | threads woken |
| 14 | `set_fs_base` | `addr` (0 or a user address) | 0 |
| 15 | `gettid` | — | thread id |
| 16 | `open` | `path`, `path_len ≤ 1024`, `flags` (`OPEN_*`), `mode` (of a created file) | handle (≥ 3) |
| 17 | `close` | `handle` | 0 |
| 18 | `read` | `handle`, `buf`, `len ≤ 1 MiB` | bytes read (0 at end of file) |
| 19 | `seek` | `handle`, `offset: i64`, `whence` (0 set, 1 current, 2 end) | new position |
| 20 | `fstat` | `handle`, `out: *mut FileStat` (88 bytes) | 0 |
| 21 | `stat` | `path`, `path_len`, `out` (follows symbolic links) | 0 |
| 22 | `readdir` | `handle` (directory), `buf`, `len` | bytes of `DirRecord`s (0 = done) |
| 23 | `mkdir` | `path`, `path_len`, `mode` | 0 |
| 24 | `unlink` | `path`, `path_len` (file, link or device node) | 0 |
| 25 | `rmdir` | `path`, `path_len` (an empty directory) | 0 |
| 26 | `rename` | `from`, `from_len`, `to`, `to_len` (same volume; replaces a file or empty directory) | 0 |
| 27 | `ftruncate` | `handle`, `len` | 0 |
| 28 | `fsync` | `handle` | 0 |
| 29 | `chdir` | `path`, `path_len` | 0 |
| 30 | `getcwd` | `buf`, `len` | bytes (no NUL) |
| 31 | `symlink` | `target`, `target_len`, `path`, `path_len` | 0 |
| 32 | `readlink` | `path`, `path_len`, `buf`, `len` | bytes of the target |
| 33 | `lstat` | `path`, `path_len`, `out` (does not follow a final link) | 0 |
| 34 | `chmod` | `path`, `path_len`, `mode` (owner or root) | 0 |
| 35 | `mount` | `args: *const MountArgs` (root only) | 0 |
| 36 | `umount` | `path`, `path_len` (root only) | 0 |
| 37 | `getuid` | — | `uid \| gid << 32` |
| 38 | `setuid` | `uid`, `gid` (root only; inherited by children) | 0 |
| 39 | `statfs` | `path`, `path_len`, `out: *mut FsStat` (72 bytes) | 0 |
| 40 | `execve` | `args: *const ExecArgs` | does not return on success |

### Programs: `spawn` and `execve`

- `ExecArgs` (48 bytes): `path, path_len, argv, argv_len, envp, envp_len`.
  `argv` and `envp` are blocks of NUL-terminated UTF-8 strings back to back;
  `argv_len` 0 means `argv = [path]`, `envp_len` 0 an empty environment.
  Both blocks together are at most 128 KiB, each holds at most 4096
  strings, and a block must end with NUL.
- A `path` without `/` is searched in `/bin`, then `/usr/bin`; a path with
  `/` is resolved like any other (relative to the current directory). The
  file must be a regular file with execute permission for the caller (root:
  any execute bit), and every directory on the way must be searchable.
  Set-user-ID bits are not honoured. Programs are static ELF64 x86-64
  executables (`ET_EXEC`, no `PT_INTERP`/`PT_DYNAMIC`) with W^X, page-aligned
  segments below `0x1000_0000_0000`; see [kernel.md](kernel.md#program-loader).
- `spawn` starts a child with the caller's credentials and current
  directory and no open handles (except the console streams 0–2).
- `execve` replaces the calling program: pid, parent, children, open
  handles, credentials and current directory stay; the address space, FS
  base and x87/SSE state are new. The new image is built completely before
  the old one is touched, so on any error `execve` returns and the old
  program continues. It fails with `Busy` while the process has more than
  one thread.
- `wait` validates `status` before blocking, so a bad pointer returns
  `Fault` and leaves the child waitable.

### Files

- Paths are UTF-8 without NUL, at most 1024 bytes (255 per component),
  absolute or relative to the current directory; resolution is described in
  [storage.md](storage.md) (symbolic links, mount points, permissions).
- `OPEN_READ` 1, `OPEN_WRITE` 2, `OPEN_CREATE` 4, `OPEN_TRUNCATE` 8,
  `OPEN_APPEND` 16, `OPEN_EXCLUSIVE` 32, `OPEN_DIRECTORY` 64,
  `OPEN_NOFOLLOW` 128 (a final link fails with `Loop`),
  `OPEN_CASE_INSENSITIVE` 256 (every component matched ASCII
  case-insensitively, exact match first; for the Windows compatibility
  layer). At least one of read/write is required; create, truncate, append
  and exclusive require write; exclusive requires create. A directory can
  only be opened for reading.
- Handles are per process, numbered from 3, at most 64 open at once, and
  closed by the kernel when the process exits. Closing 0–2 fails with
  `BadHandle`. Device nodes (`/dev/*`) are opened like files.
- `read` copies to user memory before moving the position, so a bad buffer
  returns `Fault` without consuming data. With `OPEN_APPEND` every write goes
  to the current end of the file.
- `FileStat` (88 bytes): `size, ino, dev, blocks` (512-byte units),
  `atime_ns, mtime_ns, ctime_ns` (since 1970, 0 = unknown), `kind`
  (1 file, 2 directory, 3 symlink, 4 character device, 5 block device),
  `mode` (permission bits incl. setuid/setgid/sticky), `uid, gid, nlink`,
  `attributes` (FAT bits), `rdev`, reserved.
- `DirRecord`: `ino: u64, kind: u32, reserved: u16, name_len: u16`, then
  the UTF-8 name, padded to 8 bytes; `.` and `..` are not listed.
  `readdir` returns as many whole records as fit and `InvalidArgument` if
  not even one fits.
- `MountArgs`: source, target and file system type strings (pointer +
  length each), `flags` (`MOUNT_READ_ONLY` 1) and `size_limit` (tmpfs
  bytes). Types: `tmpfs`, `fat32`, `ext4` (source: a `/dev/disks/*` node).
- `FsStat`: block size, total/free blocks and inodes, volume id, mount
  flags, NUL-padded type name.
- Every call that changes a volume is durable when it returns (FAT: written
  through; ext4: journalled and checkpointed).
### Threads

- `thread_spawn` starts a thread in the calling process (at most 64 per
  process); every other register is zero. Thread ids are global.
- `thread_exit` ends the calling thread. The kernel then stores 1 to
  `done_word` and wakes all futex waiters on it; because this happens after
  the thread has left its user stack, a joiner that sees 1 may free that
  stack. When the last thread of a process ends, the process exits with
  `code` (unless `exit` set a status earlier).
- `exit` ends the whole process: every other thread is asked to stop and does
  so at its next safe point (return to user mode, or an interrupted
  `futex_wait`, `sleep` or `wait`, which fail with `Interrupted`). The last
  thread to stop releases the address space.
- A CPU exception in any thread ends the whole process.

### Futexes

`futex_wait` reads `*addr`, and only if it equals `expected` blocks until a
`futex_wake` on the same address in the same process, the timeout, or process
exit. Check, registration and blocking are atomic with respect to
`futex_wake`, so a wake that follows a store cannot be lost. Waiters are woken
in FIFO order; callers must tolerate spurious returns.

### Thread-local storage

Each thread has its own FS base, saved and restored on context switch.
OSyx Std points it at a thread control block whose first word is its own
address (`fs:[0]`).

`set_fs32_base` (96) sets the descriptor-based FS base of 32-bit
compatibility-mode code, which reads its TEB at `fs:[0x18]`. The value must
be page-aligned and below 4 GiB (and 0 or a user address); it is switched
with the thread and cleared by `execve`. IA-32e has one hidden FS base, so a
non-zero base also replaces the base 64-bit code sees until `set_fs_base`
(14) is called again; a zero base restores the thread's 64-bit base. A mixed
32/64-bit program switches the two at each mode crossing.

## Errors

| errno | Name | Typical cause |
|---|---|---|
| 1 | InvalidArgument | zero length, bad flags, unknown clock, partial unmap, malformed or oversized `ExecArgs` blocks |
| 2 | Fault | pointer outside user space, unmapped, or read-only for output |
| 3 | NoMemory | frames exhausted, 64 GiB per-process `map` address space, 512-process limit, 256 threads per process |
| 4 | BadHandle | unknown handle, or a handle without the needed access (write on a read-only handle) |
| 5 | NotSupported | unknown system call number |
| 6 | PermissionDenied | writable + executable mapping (W^X); file permission checks, sticky directories, root-only calls (`mount`, `setuid`), creating files in `/dev`; `spawn`/`execve` of a file without execute permission or of a directory |
| 7 | NotFound | missing file or directory; `spawn`/`execve` of a name found in neither `/bin` nor `/usr/bin` |
| 8 | NoChild | `wait` with no (matching) child |
| 9 | WouldBlock | `futex_wait`: the word did not hold `expected` |
| 10 | TimedOut | `futex_wait` timeout expired |
| 11 | Interrupted | a blocking call ended because the process is exiting |
| 12 | AlreadyExists | `OPEN_EXCLUSIVE` or `mkdir` of an existing name |
| 13 | NotADirectory | a path component or `readdir` handle is a file |
| 14 | IsADirectory | opening a directory for writing, `unlink` of a directory |
| 15 | DirectoryNotEmpty | `rmdir` of a non-empty directory |
| 16 | NoSpace | the volume is full |
| 17 | Io | device error or damaged volume |
| 18 | FileTooLarge | beyond FAT32's 4 GiB − 1 file size; an executable over 64 MiB |
| 19 | ReadOnly | writing to a read-only volume |
| 20 | TooManyHandles | the process already has 64 open handles |
| 21 | CrossDevice | `rename` between volumes |
| 22 | Busy | unmounting a volume in use, removing a mount point, raw writes to a mounted disk, removing an open file on FAT; `execve` with more than one thread |
| 23 | Loop | more than 40 symbolic links in one path; `OPEN_NOFOLLOW` on a link |
| 24 | Unsupported | a file system feature the driver refuses (e.g. ext4 inline data, adding to a hashed directory) |
| 25 | BadExecutable | `spawn`/`execve` of a file that is not a loadable static ELF64 x86-64 executable |

## Pointer validation

Every user buffer is checked to lie inside `[64 KiB, 0x8000_0000_0000)` with
overflow-checked arithmetic, then copied with a fault-recovering `rep movsb`
(`fixup.rs`). An unmapped page or a write to a read-only page therefore
returns `Fault`. These paths are exercised from ring 3 by `userspace/apps`
(`init`) in QEMU.

## Process start-up and exit

System V x86-64 layout, built by `osyx_abi::startup` (the same code
OSyx Std reads it with):

```
rsp ->  argc
        argv[0] … argv[argc-1], NULL
        envp[0] … envp[n-1], NULL
        auxv: (key, value) pairs …, (AT_NULL, 0)
        padding to 16 bytes
        argument and environment strings
        16 random bytes (AT_RANDOM)
        program path (AT_EXECFN), ending right below 0x7FFF_FFFF_0000
```

Auxiliary entries: `AT_PHDR` (3, when a loadable segment maps the program
headers, as OSyx programs do), `AT_PHENT` (4, 56), `AT_PHNUM` (5),
`AT_PAGESZ` (6, 4096), `AT_ENTRY` (9), `AT_UID`/`AT_EUID`/`AT_GID`/
`AT_EGID` (11–14), `AT_SECURE` (23, always 0), `AT_RANDOM` (25: from the
kernel CSPRNG; without an entropy source derived from the time stamp
counter) and `AT_EXECFN` (31: the canonical absolute path the program was
read from). The stack is 512 KiB; the start-up data may use at most three
quarters of it. `rsp` is 16-byte aligned and all other general purpose
registers are zero. SSE is enabled; each thread has its own x87/SSE state.
Fatal CPU exceptions terminate the process with status `0x4000_0000 | vector`.
