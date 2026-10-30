# OSyx Std and Rust `std`

There are two different milestones:

1. **OSyx Std (`runtime/os-std`)**: a convenience standard library crate.
   *Partially implemented and running on OSyx.*
2. **A genuine target-specific `std`** (so that unmodified `fn main` programs
   compile with plain `std`). *Planned; not started.*

## OSyx Std today

Programs look like this (see `userspace/apps`):

```rust
#![no_std]
#![no_main]
use os_std::prelude::*;
os_std::entry!(main);

fn main() {
    println!("Hello from our OS!");
    let mut values = Vec::new();
    values.push(10);
    values.push(20);
    println!("Values: {:?}", values);
}
```

`Vec`, `String`, `Box`, `BTreeMap`, `format!` are upstream `alloc`; OSyx Std
supplies the platform parts:

| Module | Status | Where it runs |
|---|---|---|
| `print!`/`println!`/`eprint!`/`eprintln!`, `io::Write`, `stdout`/`stderr` | Implemented | OSyx (tested), host back end (tested) |
| `io::{Read, Seek, SeekFrom}` (`read_exact`, `read_to_end`, `read_to_string`, `rewind`) | Implemented | OSyx (through `fs`) + host |
| `fs::{File, OpenOptions, Metadata, FileType, Permissions, DirEntry, ReadDir}`, `read`, `read_to_string`, `write`, `copy`, `read_dir`, `metadata`, `symlink_metadata`, `exists`, `create_dir(_all)`, `remove_file`, `remove_dir(_all)`, `rename`, `symlink`, `read_link`, `set_permissions`; `OpenOptions::mode`, `case_insensitive` | Implemented on ext4 `/`, FAT32 `/boot`, tmpfs `/tmp` `/run`, devfs `/dev` | OSyx (19 checks in `init`; files verified on the host with mtools, e2fsck and debugfs) + host (mapped below a temp directory; no symlinks or owners there) |
| `env::{current_dir, set_current_dir}` (relative paths everywhere) | Implemented; children inherit the directory | OSyx + host |
| `time::SystemTime`, `UNIX_EPOCH`, `Metadata::{modified, accessed, changed}` | Implemented (RTC wall clock) | OSyx + host |
| `os::{getuid, setuid, statfs, mount, unmount}` | Implemented (root-only where it matters) | OSyx |
| `path::{Path, PathBuf}` (UTF-8 only: `join`, `parent`, `file_name`, `extension`, `components`, `exists`) | Implemented | host tests + OSyx |
| global allocator | Implemented (heap on `map`) | OSyx (tested with 2 MiB + 10 000 allocations) |
| `error::{Error, ErrorKind}`, errno mapping | Implemented | host tests |
| `process::{exit, abort, id}` | Implemented | OSyx (tested) |
| `process::{Command, Child, ExitStatus, wait_any}`; `Command::{env, envs, env_remove, env_clear, arg0, get_envs, exec}` | Implemented: programs are ELF files found in `/bin`, `/usr/bin` or by path; `exec` replaces the running program | OSyx (spawn, wait, exit codes, exceptions, nested, orphans, 13 loader checks incl. `exec` chains and refusals); host returns `Unsupported` |
| `thread::{sleep, yield_now}` | Implemented | OSyx + host |
| `thread::{spawn, Builder, JoinHandle, current, Thread, ThreadId}` | Implemented; a panicking thread ends the process (panic = abort) | OSyx (join values, ids/names, detached reaping, faults and panics in threads) + host |
| `thread_local!`, `thread::LocalKey` | Implemented on the FS base (own TLS, not ELF TLS) with per-thread destructors | OSyx + host |
| `sync::{Mutex, Condvar, RwLock, Once, OnceLock}` (futex based), `mpsc`, `Arc`, `Weak`, `atomic` | Implemented; never poisoned; the mutex is not fair; a queued writer keeps new readers out | OSyx (contention under preemption, producer/consumer, timeouts, readers/writers, once across threads, mpsc senders/bounded/timeout) + host (8 parallel threads) |
| `time::{Instant, Duration}` | Implemented (1 ms resolution) | OSyx + host |
| `env::args` | Implemented | OSyx (tested with `init.args`) + host |
| `env::{var, vars, set_var, remove_var}` | Implemented: the `envp` block from the start-up stack, kept in a locked process-wide copy that children inherit | OSyx (inheritance, `env_clear`, exact `envp` in children) + host |
| `env::current_exe` | Implemented (`AT_EXECFN`: canonical path the kernel loaded) | OSyx + host |
| `os::{sysinfo, kernel_version, heap_stats, aux_value, raw}` | Implemented | OSyx |
| `rt`: `_start` (argv, envp and auxv located with `osyx_abi::startup`), `entry!`, `Termination`, panic → status 101 | Implemented | OSyx (tested) |
| `net`, `fs::hard_link`, `fs::canonicalize` | Planned | — |

On the host back end, futexes are emulated (per-address wake generations on
a global `std` condition variable) and threads are real host threads, so the
OSyx Std `Mutex`, `Condvar`, `thread` and TLS code is unit-tested under true
parallelism; the kernel side is tested by `init` on OSyx.

Back ends are selected at compile time: `sys/osyx.rs` on
`x86_64-unknown-none`, `sys/host.rs` elsewhere. The host back end exists only
for unit tests and is built on the host's std; host test results are not
evidence about OSyx.

## Build notes

User programs are built for `x86_64-unknown-none` with
`-C relocation-model=static -C code-model=small` (set by `scripts/build.ps1`)
and linked with `userspace/user.ld`. That target is soft-float. The kernel
does enable SSE and save x87/SSE state per thread (verified by `init` with
inline-assembly XMM patterns), so a hard-float user target is now possible;
switching requires a custom target spec (see below).

## Path to a genuine `std`

Requirements identified so far (not yet attempted):

- a custom target (`x86_64-unknown-osyx`) with `target_os = "osyx"`, which
  needs nightly `-Zbuild-std` until the target is upstream;
- a `std::sys::pal::osyx` implementation (stdio, alloc, args, exit, time,
  thread-local storage, thread spawn, synchronisation, fs, net);
- TLS: the kernel must set up FS base per thread;
- unwinding: start with `panic=abort`; unwinding needs `.eh_frame` handling;
- kernel prerequisites: threads per process, futexes, FS-base TLS,
  preemption, FPU state, file handles, a current directory, file
  permissions, `execve` and an environment block exist; sockets are still
  missing.

No claim of `std` compatibility will be made before real `std` programs
compile and run on OSyx.
