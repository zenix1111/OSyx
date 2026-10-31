//! SYSCALL/SYSRET entry and the system call dispatcher (ABI: `osyx_abi`).
//!
//! Entry: the CPU loads CS/SS from STAR, saves the user RIP in RCX and RFLAGS
//! in R11, and masks RFLAGS with FMASK (interrupts off). The stub switches to
//! the process's kernel stack and saves a [`SyscallFrame`]. The dispatcher takes
//! the kernel entry lock before enabling interrupts. SWAPGS selects the
//! current CPU's stack pointers; the inactive GS base preserves user TLS.

use crate::arch::cpu;
use crate::arch::gdt::{KERNEL_CS, USER_DS};
use crate::exec::ExecRequest;
use crate::fixup::{copy_from_user, copy_to_user};
use crate::object::Object;
use crate::vfs::Lookup;
use crate::{interrupts, mem, process, sched, sys_objects, vfs};
use core::arch::global_asm;
use osyx_abi::{nr, Errno, SystemInfo};
use osyx_vfs::Cred;

global_asm!(
    r#"
    .section .text
    .global osyx_syscall_entry
osyx_syscall_entry:
    swapgs
    mov gs:[8], rsp
    mov rsp, gs:[0]
    push qword ptr gs:[8]
    push r11
    push rcx
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    push r9
    push r8
    push r10
    push rdx
    push rsi
    push rdi
    push rax
    mov rdi, rsp
    call osyx_syscall_dispatch
    cli
    add rsp, 8
    pop rdi
    pop rsi
    pop rdx
    pop r10
    pop r8
    pop r9
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    pop rcx
    pop r11
    pop rsp
    swapgs
    sysretq

    // SYSCALL from 32-bit compatibility mode (AMD CPUs; Intel raises #UD).
    // Not a system call: return to the next instruction with rax = -1.
    // IRETQ, not SYSRET, restores the 32-bit code selector from the GDT.
    .global osyx_syscall32_entry
osyx_syscall32_entry:
    swapgs
    mov gs:[8], rsp
    mov rsp, gs:[0]
    push 0x1b
    push qword ptr gs:[8]
    push r11
    push 0x3b
    push rcx
    mov rax, -1
    swapgs
    iretq
    "#
);

extern "C" {
    fn osyx_syscall_entry();
    fn osyx_syscall32_entry();
}

/// Registers saved by the entry stub (lowest address first).
#[repr(C)]
pub struct SyscallFrame {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
}

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_CSTAR: u32 = 0xC000_0083;
const IA32_SYSENTER_CS: u32 = 0x174;
const IA32_FMASK: u32 = 0xC000_0084;

/// Enables SYSCALL and installs the entry point.
///
/// # Safety
/// Must run once after the GDT is loaded (STAR refers to its selectors).
pub unsafe fn init() {
    cpu::wrmsr(IA32_EFER, cpu::rdmsr(IA32_EFER) | 1); // SCE
                                                      // SYSCALL: CS = STAR[47:32], SS = +8.  SYSRET: CS = STAR[63:48] + 16, SS = +8.
    // SYSRET derives both selectors by adding to STAR[63:48]; not every
    // implementation forces RPL 3 on SS (WHPX on AMD loads 0x18 instead of
    // 0x1B), so the base itself must carry the user RPL.
    let sysret_base = USER_DS as u64 - 8;
    cpu::wrmsr(IA32_STAR, (sysret_base << 48) | ((KERNEL_CS as u64) << 32));
    cpu::wrmsr(IA32_LSTAR, osyx_syscall_entry as *const () as u64);
    // Ring 3 can run 32-bit code (gdt::USER_CS32): SYSCALL there enters
    // through CSTAR; a null SYSENTER_CS makes SYSENTER raise #GP.
    const _: () = assert!(USER_DS == 0x1b && crate::arch::gdt::USER_CS32 == 0x3b);
    cpu::wrmsr(IA32_CSTAR, osyx_syscall32_entry as *const () as u64);
    cpu::wrmsr(IA32_SYSENTER_CS, 0);
    // Clear IF, TF, DF, NT and AC on entry.
    cpu::wrmsr(IA32_FMASK, (1 << 9) | (1 << 8) | (1 << 10) | (1 << 14) | (1 << 18));
}

/// # Safety
/// `top` must be the top of the current process's kernel stack.
pub unsafe fn set_kernel_stack(top: u64) {
    crate::smp::set_kernel_stack(top);
}

#[no_mangle]
extern "C" fn osyx_syscall_dispatch(f: &mut SyscallFrame) -> u64 {
    crate::smp::note_last_syscall(crate::smp::cached_tid(), f.rip, f.rax);
    crate::prof::note_syscall(crate::smp::cached_tid(), f.rax);
    // Read-only queries that touch nothing but scheduler state or atomics
    // skip the global entry lock: user timers call CLOCK very frequently.
    match f.rax {
        nr::CLOCK => {
            let tid = crate::smp::cached_tid();
            crate::smp::note_syscall(f.rax);
            crate::smp::note_pid_syscall(crate::smp::cached_pid(), f.rax);
            crate::smp::note_tid_syscall(tid, f.rax);
            crate::smp::note_callsite(tid, f.rip, f.rax);
            return osyx_abi::encode(sys_clock(f.rdi));
        }
        nr::GETTID => {
            crate::smp::note_syscall(f.rax);
            return osyx_abi::encode(Ok(sched::current_tid()));
        }
        nr::CPU_INFO => {
            crate::smp::note_syscall(f.rax);
            return osyx_abi::encode(Ok(crate::smp::online() as u64 | (crate::smp::index() as u64) << 32));
        }
        nr::YIELD => {
            // Yield touches only the scheduler, which has its own lock. A
            // spinning user thread can call this tens of thousands of times
            // per second; taking the entry lock here makes every spin bounce
            // against the CPU doing real work.
            let tid = crate::smp::cached_tid();
            crate::smp::note_syscall(f.rax);
            crate::smp::note_pid_syscall(crate::smp::cached_pid(), f.rax);
            crate::smp::note_tid_syscall(tid, f.rax);
            crate::smp::note_tid_futex(tid, f.rax);
            cpu::enable_interrupts();
            sched::yield_now();
            return osyx_abi::encode(Ok(0));
        }
        // Futexes touch only their own wait table and the scheduler, both
        // protected by private locks. Windows critical sections and SRW locks
        // wake on every contended release, which makes this one of the hottest
        // syscalls while a browser runs; routing it through the entry lock
        // serialised both CPUs behind traffic that needs no global state.
        nr::FUTEX_WAIT | nr::FUTEX_WAIT_OWNED | nr::FUTEX_WAKE => {
            let tid = crate::smp::cached_tid();
            crate::smp::note_syscall(f.rax);
            crate::smp::note_pid_syscall(crate::smp::cached_pid(), f.rax);
            crate::smp::note_tid_syscall(tid, f.rax);
            crate::smp::note_tid_futex(tid, f.rax);
            crate::smp::note_callsite(tid, f.rip, f.rax);
            cpu::enable_interrupts();
            let r = if f.rax != nr::FUTEX_WAKE {
                let timeout = (f.rdx != 0).then(|| ns_to_ticks(f.rdx));
                let owner = if f.rax == nr::FUTEX_WAIT_OWNED { f.r10 } else { 0 };
                crate::futex::wait_owned(f.rdi, f.rsi as u32, timeout, owner).map(|_| 0)
            } else {
                crate::futex::wake(f.rdi, f.rsi as u32)
            };
            return osyx_abi::encode(r);
        }
        // Wait objects own their readiness state and waitqueues. In particular,
        // Winsock select() must not serialise both CPUs behind the entry lock
        // while it only polls socket atomics or sleeps on their waitqueue.
        nr::WAIT_HANDLES => {
            let tid = crate::smp::cached_tid();
            crate::smp::note_syscall(f.rax);
            crate::smp::note_pid_syscall(crate::smp::cached_pid(), f.rax);
            crate::smp::note_tid_syscall(tid, f.rax);
            crate::smp::note_callsite(tid, f.rip, f.rax);
            cpu::enable_interrupts();
            let r = sys_objects::wait_handles(f.rdi, f.rsi, f.rdx);
            if sched::current_kill_pending() {
                process::finish_current_thread(0);
            }
            return osyx_abi::encode(r);
        }
        // A regular file read touches only per-file state: the handle table,
        // the open file, the page cache and the volume have their own locks.
        // Databases issue thousands of small reads per second and the entry
        // lock was most of their cost; a miss can also wait on a busy disk
        // for hundreds of milliseconds. Pipes, sockets and buffers that are
        // not mapped yet stay on the normal path.
        nr::READ => {
            let r = read_cached(f.rdi, f.rsi, f.rdx).or_else(|| read_file(f.rdi, f.rsi, f.rdx));
            if let Some(r) = r {
                let tid = crate::smp::cached_tid();
                crate::smp::note_syscall(f.rax);
                crate::smp::note_pid_syscall(crate::smp::cached_pid(), f.rax);
                crate::smp::note_tid_syscall(tid, f.rax);
                crate::smp::note_callsite(tid, f.rip, f.rax);
                cpu::enable_interrupts();
                return osyx_abi::encode(r);
            }
        }
        // Seeking except relative to the end only rewrites this file's own
        // offset; SQLite seeks before every small read and write. Seeking to
        // the end needs the file size from the file system, so it stays on
        // the normal path.
        nr::SEEK if f.rdx != osyx_abi::SEEK_END => {
            let tid = crate::smp::cached_tid();
            crate::smp::note_syscall(f.rax);
            crate::smp::note_pid_syscall(crate::smp::cached_pid(), f.rax);
            crate::smp::note_tid_syscall(tid, f.rax);
            crate::smp::note_callsite(tid, f.rip, f.rax);
            cpu::enable_interrupts();
            return osyx_abi::encode(with_file(f.rdi, |o| o.seek(f.rsi as i64, f.rdx)));
        }
        _ => {}
    }
    crate::smp::note_pid_syscall(crate::smp::cached_pid(), f.rax);
    crate::smp::note_tid_syscall(crate::smp::cached_tid(), f.rax);
    if f.rax == nr::FUTEX_WAIT || f.rax == nr::FUTEX_WAIT_OWNED || f.rax == nr::FUTEX_WAKE || f.rax == nr::YIELD {
        crate::smp::note_tid_futex(crate::smp::cached_tid(), f.rax);
    }
    crate::smp::note_callsite(crate::smp::cached_tid(), f.rip, f.rax);
    // Bulk prefaulting maps and zeroes page runs with only its own locks
    // (process table, paging, frames). Holding the entry lock for a whole run
    // makes the other CPU spin and starve host I/O, so it re-enters in small
    // chunks instead.
    if f.rax == nr::PREFAULT {
        crate::smp::note_syscall(f.rax);
        cpu::enable_interrupts();
        return osyx_abi::encode(if !crate::fixup::user_range_ok(f.rdi, f.rsi) {
            Err(Errno::Fault)
        } else {
            process::prefault_write(f.rdi, f.rsi as usize);
            Ok(0)
        });
    }
    // Channel messages without handles and waits on channels, pipes,
    // listeners and sockets only take the spinlocks of those objects, the
    // handle table and the scheduler. IPC-heavy programs (a browser's
    // processes talk through channels all the time) must not queue every
    // message behind other CPUs' system calls.
    if let Some(r) = lock_free_ipc(f) {
        crate::smp::note_syscall(f.rax);
        if sched::current_kill_pending() {
            let _entry = crate::smp::KernelEntry::new_yielding();
            process::finish_current_thread(0);
        }
        return osyx_abi::encode(r);
    }
    let _entry = crate::smp::KernelEntry::new_yielding();
    crate::smp::set_lock_nr(f.rax);
    cpu::enable_interrupts();
    let r = match f.rax {
        nr::EXIT => process::exit_current(f.rdi as i32),
        nr::WRITE => sys_write(f.rdi, f.rsi, f.rdx),
        nr::MAP => process::map_anonymous(f.rdi, f.rsi),
        nr::UNMAP => process::unmap_region(f.rdi, f.rsi).map(|_| 0),
        nr::SYSINFO => sys_sysinfo(f.rdi),
        nr::CPU_INFO => Ok(crate::smp::online() as u64 | (crate::smp::index() as u64)<<32),
        nr::THREAD_AFFINITY => sched::set_affinity(f.rdi,f.rsi),
        nr::THREAD_PRIORITY => sched::set_priority(f.rdi, f.rsi),
        nr::THREAD_SUSPEND => sched::thread_suspend(f.rdi, f.rsi),
        nr::THREAD_TIMES => sched::thread_times(f.rdi),
        nr::WORKING_SET => sys_objects::working_set(f.rdi, f.rsi, f.rdx),
        nr::PROCESS_WRITE_BARRIER => {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            crate::smp::flush_remote(0,true);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            Ok(0)
        }
        nr::CLOCK => sys_clock(f.rdi),
        nr::SPAWN => ExecRequest::from_user(f.rdi)
            .and_then(|req| process::spawn(sched::current_pid(), &req).map_err(|e| e.errno())),
        nr::EXECVE => sys_execve(f.rdi),
        nr::WAIT => sys_wait(f.rdi, f.rsi),
        nr::YIELD => {
            sched::yield_now();
            Ok(0)
        }
        nr::SLEEP => {
            sched::sleep_ticks(ns_to_ticks(f.rdi));
            Ok(0)
        }
        nr::THREAD_SPAWN => process::spawn_thread(f.rdi, f.rsi, f.rdx, f.r10),
        nr::THREAD_EXIT => process::thread_exit(f.rdi as i32, f.rsi),
        nr::FUTEX_WAIT => {
            let timeout = (f.rdx != 0).then(|| ns_to_ticks(f.rdx));
            crate::futex::wait(f.rdi, f.rsi as u32, timeout).map(|_| 0)
        }
        nr::FUTEX_WAIT_OWNED => {
            let timeout = (f.rdx != 0).then(|| ns_to_ticks(f.rdx));
            crate::futex::wait_owned(f.rdi, f.rsi as u32, timeout, f.r10).map(|_| 0)
        }
        nr::FUTEX_WAKE => crate::futex::wake(f.rdi, f.rsi as u32),
        nr::SET_FS_BASE => {
            if f.rdi != 0 && !crate::fixup::user_range_ok(f.rdi, 1) {
                Err(Errno::InvalidArgument)
            } else {
                sched::set_current_fs_base(f.rdi);
                Ok(0)
            }
        }
        nr::SET_FS32_BASE => {
            // 32-bit code addresses 32 bits and the descriptor base field is
            // 32 bits wide: a base in the kernel half cannot be represented,
            // so it is refused rather than truncated. Page alignment keeps
            // the TEB and everything the loader maps around it in one page
            // frame, as Windows lays it out.
            if f.rdi >= 1 << 32
                || !f.rdi.is_multiple_of(mem::PAGE_SIZE)
                || (f.rdi != 0 && !crate::fixup::user_range_ok(f.rdi, 1))
            {
                Err(Errno::InvalidArgument)
            } else {
                sched::set_current_fs32_base(f.rdi);
                Ok(0)
            }
        }
        nr::GETTID => Ok(sched::current_tid()),
        nr::OPEN => user_path(f.rdi, f.rsi)
            .and_then(|p| vfs::open(&Lookup::current(), &p, f.rdx, f.r10 as u32))
            .and_then(process::add_handle),
        nr::CLOSE => process::close_handle(f.rdi).map(|_| 0),
        nr::READ => sys_read(f.rdi, f.rsi, f.rdx),
        nr::SEEK => with_file(f.rdi, |o| o.seek(f.rsi as i64, f.rdx)),
        nr::FSTAT => with_file(f.rdi, |o| o.stat()).and_then(|st| put_user(f.rsi, &st)),
        nr::STAT => {
            user_path(f.rdi, f.rsi).and_then(|p| vfs::stat(&Lookup::current(), &p)).and_then(|st| put_user(f.rdx, &st))
        }
        nr::LSTAT => {
            user_path(f.rdi, f.rsi).and_then(|p| vfs::lstat(&Lookup::current(), &p)).and_then(|st| put_user(f.rdx, &st))
        }
        nr::READDIR => sys_readdir(f.rdi, f.rsi, f.rdx),
        nr::MKDIR => user_path(f.rdi, f.rsi).and_then(|p| vfs::mkdir(&Lookup::current(), &p, f.rdx as u32)).map(|_| 0),
        nr::UNLINK => user_path(f.rdi, f.rsi).and_then(|p| vfs::unlink(&Lookup::current(), &p)).map(|_| 0),
        nr::RMDIR => user_path(f.rdi, f.rsi).and_then(|p| vfs::rmdir(&Lookup::current(), &p)).map(|_| 0),
        nr::RENAME => user_path(f.rdi, f.rsi)
            .and_then(|from| Ok((from, user_path(f.rdx, f.r10)?)))
            .and_then(|(from, to)| vfs::rename(&Lookup::current(), &from, &to))
            .map(|_| 0),
        nr::FTRUNCATE => (|| {
            let file = process::get_handle(f.rdi)?;
            let stat = file.lock().stat()?;
            crate::filemap::truncate((stat.dev, stat.ino), f.rsi, || file.lock().truncate(f.rsi)).map(|_| 0)
        })(),
        nr::FSYNC => with_file(f.rdi, |o| o.sync()).map(|_| 0),
        nr::CHDIR => user_path(f.rdi, f.rsi)
            .and_then(|p| vfs::chdir(&Lookup::current(), &p))
            .and_then(process::set_current_cwd)
            .map(|_| 0),
        nr::GETCWD => {
            let cwd = process::current_identity().1;
            if (cwd.len() as u64) > f.rsi {
                Err(Errno::InvalidArgument)
            } else {
                copy_to_user(f.rdi, cwd.as_bytes()).map(|_| cwd.len() as u64)
            }
        }
        nr::SYMLINK => user_path(f.rdi, f.rsi)
            .and_then(|target| Ok((target, user_path(f.rdx, f.r10)?)))
            .and_then(|(target, p)| vfs::symlink(&Lookup::current(), &target, &p))
            .map(|_| 0),
        nr::LINK => user_path(f.rdi, f.rsi)
            .and_then(|existing| Ok((existing, user_path(f.rdx, f.r10)?)))
            .and_then(|(existing, new)| vfs::link(&Lookup::current(), &existing, &new))
            .map(|_| 0),
        nr::READLINK => user_path(f.rdi, f.rsi).and_then(|p| vfs::readlink(&Lookup::current(), &p)).and_then(|t| {
            let n = t.len().min(f.r10 as usize);
            copy_to_user(f.rdx, &t.as_bytes()[..n]).map(|_| n as u64)
        }),
        nr::CHMOD => user_path(f.rdi, f.rsi).and_then(|p| vfs::chmod(&Lookup::current(), &p, f.rdx as u32)).map(|_| 0),
        nr::MOUNT => sys_mount(f.rdi),
        nr::UMOUNT => user_path(f.rdi, f.rsi).and_then(|p| sys_umount(&p)).map(|_| 0),
        nr::GETUID => {
            let c = process::current_identity().0;
            Ok(c.uid as u64 | (c.gid as u64) << 32)
        }
        nr::SETUID => process::set_current_cred(Cred { uid: f.rdi as u32, gid: f.rsi as u32 }).map(|_| 0),
        nr::SET_TIME => sys_set_time(f.rdi),
        nr::STATFS => user_path(f.rdi, f.rsi)
            .and_then(|p| vfs::statfs(&Lookup::current(), &p))
            .and_then(|st| put_user(f.rdx, &st)),
        nr::PIPE => sys_objects::pipe(f.rdi),
        nr::SPAWN_STDIO => sys_objects::spawn_stdio(f.rdi, f.rsi),
        nr::CHANNEL_LISTEN => sys_objects::channel_listen(f.rdi, f.rsi),
        nr::CHANNEL_CONNECT => sys_objects::channel_connect(f.rdi, f.rsi),
        nr::CHANNEL_ACCEPT => sys_objects::channel_accept(f.rdi),
        nr::CHANNEL_SEND => sys_objects::channel_send(f.rdi, f.rsi),
        nr::CHANNEL_RECV => sys_objects::channel_recv(f.rdi, f.rsi),
        nr::CHANNEL_PEER => sys_objects::channel_peer(f.rdi),
        nr::SHM_CREATE => sys_objects::shm_create(f.rdi),
        nr::SHM_MAP => sys_objects::shm_map(f.rdi, f.rsi),
        nr::FILEMAP_CREATE => sys_objects::filemap_create(f.rdi, f.rsi, f.rdx),
        nr::FILEMAP_MAP => sys_objects::filemap_map(f.rdi, f.rsi, f.rdx, f.r10),
        nr::FILEMAP_FLUSH => sys_objects::filemap_flush(f.rdi, f.rsi, f.rdx),
        nr::IMAGE_MAP => sys_objects::image_map(f.rdi, f.rsi, f.rdx),
        nr::IMAGE_PUBLISH => sys_objects::image_publish(f.rdi, f.rsi, f.rdx),
        nr::IMAGE_QUERY => sys_objects::image_query(f.rdi),
        nr::SHM_SIZE => sys_objects::shm_size(f.rdi),
        nr::WAIT_HANDLES => sys_objects::wait_handles(f.rdi, f.rsi, f.rdx),
        nr::DISPLAY_INFO => sys_objects::display_info(f.rdi),
        nr::DISPLAY_ACQUIRE => sys_objects::display_acquire(),
        nr::DISPLAY_RELEASE => sys_objects::display_release(),
        nr::PROC_LIST => sys_objects::proc_list(f.rdi, f.rsi),
        nr::PROC_INFO => sys_objects::proc_info(f.rdi, f.rsi),
        nr::DEVICE_LIST => sys_objects::device_list(f.rdi, f.rsi),
        nr::MOUNT_LIST => sys_objects::mount_list(f.rdi, f.rsi),
        nr::POWER => sys_objects::power(f.rdi),
        nr::KILL => sys_objects::kill(f.rdi),
        nr::SOCKET => crate::net::sys_socket(f.rdi),
        nr::SOCK_BIND => crate::net::sys_bind(f.rdi, f.rsi),
        nr::SOCK_CONNECT => crate::net::sys_connect(f.rdi, f.rsi),
        nr::SOCK_LISTEN => crate::net::sys_listen(f.rdi, f.rsi),
        nr::SOCK_ACCEPT => crate::net::sys_accept(f.rdi, f.rsi),
        nr::SOCK_SEND => crate::net::sys_send(f.rdi, f.rsi, f.rdx, f.r10, f.r8),
        nr::SOCK_RECV => crate::net::sys_recv(f.rdi, f.rsi, f.rdx, f.r10, f.r8),
        nr::SOCK_CTL => crate::net::sys_ctl(f.rdi, f.rsi, f.rdx),
        nr::RESOLVE => crate::net::sys_resolve(f.rdi, f.rsi, f.rdx, f.r10),
        nr::NET_QUERY => crate::net::sys_query(f.rdi, f.rsi, f.rdx),
        nr::NET_CONFIG => crate::net::sys_config(f.rdi),
        nr::SET_GS_BASE => {
            if f.rdi != 0 && !crate::fixup::user_range_ok(f.rdi, 1) {
                Err(Errno::InvalidArgument)
            } else {
                sched::set_current_gs_base(f.rdi);
                Ok(0)
            }
        }
        nr::PROTECT => process::protect(f.rdi, f.rsi, f.rdx).map(|_| 0),
        nr::MAP_EX => process::map_ex(f.rdi, f.rsi, f.rdx, f.r10),
        nr::DISCARD => process::discard(f.rdi, f.rsi).map(|_| 0),
        nr::TIME_CALIB => sys_time_calib(f.rdi),
        nr::DISPLAY_FLUSH => sys_objects::display_flush(f.rdi, f.rsi, f.rdx, f.r10),
        nr::DISPLAY_SET_MODE => sys_objects::display_set_mode(f.rdi, f.rsi),
        nr::FAULT_HANDLER => crate::user_fault::register(f.rdi),
        nr::FAULT_RETURN => crate::user_fault::resume(f.rdi),
        nr::FIRMWARE => crate::firmware::syscall(f.rdi, f.rsi, f.rdx, f.r10, f.r8),
        _ => Err(Errno::NotSupported),
    };
    // Safe point: a thread whose process is exiting ends here instead of
    // returning to user mode.
    if sched::current_kill_pending() {
        process::finish_current_thread(0);
    }
    // A suspended thread (SuspendThread) stops here, with no lock held.
    sched::park_if_suspended();
    osyx_abi::encode(r)
}

/// The IPC system calls that run without the entry lock, with interrupts
/// enabled; `None` sends the call down the normal path.
fn lock_free_ipc(f: &SyscallFrame) -> Option<Result<u64, Errno>> {
    let r = match f.rax {
        nr::CHANNEL_SEND => sys_objects::channel_send_unlocked(f.rdi, f.rsi),
        nr::CHANNEL_RECV => sys_objects::channel_recv_unlocked(f.rdi, f.rsi),
        nr::WAIT_HANDLES => sys_objects::wait_handles_unlocked(f.rdi, f.rsi, f.rdx),
        nr::WRITE => write_unlocked(f.rdi, f.rsi, f.rdx),
        // Futexes have their own waiter lock and recheck the word after
        // registering, so a wake on another CPU cannot be lost; user copies
        // happen without that lock held.
        nr::FUTEX_WAIT => {
            let timeout = (f.rdx != 0).then(|| ns_to_ticks(f.rdx));
            cpu::enable_interrupts();
            Some(crate::futex::wait(f.rdi, f.rsi as u32, timeout).map(|_| 0))
        }
        nr::FUTEX_WAKE => {
            cpu::enable_interrupts();
            Some(crate::futex::wake(f.rdi, f.rsi as u32))
        }
        _ => return None,
    };
    if r.is_some() {
        crate::smp::note_lock_free(f.rax);
    }
    r
}

/// `write` to a pipe or to the console (standard output or error without a
/// handle), which only take the pipe's and the process table's spinlocks
/// and the serial port's; files and sockets take the normal path.
fn write_unlocked(fd: u64, buf: u64, len: u64) -> Option<Result<u64, Errno>> {
    let object = process::get_object(fd);
    if !matches!(object, Ok(Object::Pipe(_))) && (object.is_ok() || (fd != osyx_abi::STDOUT && fd != osyx_abi::STDERR)) {
        return None;
    }
    cpu::enable_interrupts();
    Some(sys_write(fd, buf, len))
}

/// Nanoseconds to timer ticks, rounded up, plus one tick for ns > 0: the
/// caller may be anywhere inside the current tick, and CLOCK_MONOTONIC is
/// interpolated within it, so a wait must never end early by that clock.
fn ns_to_ticks(ns: u64) -> u64 {
    let tick_ns = 1_000_000_000 / crate::arch::pic::TIMER_HZ as u64;
    if ns == 0 {
        0
    } else {
        ns.div_ceil(tick_ns) + 1
    }
}

/// Bounce buffer size for file data between user memory and the VFS.
const FILE_CHUNK: usize = osyx_abi::MAX_READ;

fn sys_write(fd: u64, buf: u64, len: u64) -> Result<u64, Errno> {
    if len > osyx_abi::MAX_WRITE as u64 {
        return Err(Errno::InvalidArgument);
    }
    if !crate::fixup::user_range_ok(buf, len) {
        return Err(Errno::Fault);
    }
    // Any handle that exists, including standard streams redirected at spawn.
    match process::get_object(fd) {
        Ok(Object::File(_)) => return write_file(fd, buf, len as usize),
        Ok(Object::Pipe(p)) => return sys_objects::write_pipe(&p, buf, len),
        Ok(Object::Socket(_)) => return crate::net::sys_send(fd, buf, len, 0, 0),
        Ok(_) => return Err(Errno::BadHandle),
        Err(_) => {}
    }
    if fd != osyx_abi::STDOUT && fd != osyx_abi::STDERR {
        return Err(Errno::BadHandle);
    }
    let mut chunk = [0u8; 512];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(chunk.len() as u64) as usize;
        copy_from_user(&mut chunk[..n], buf + done)?;
        process::write_output(&chunk[..n]);
        done += n as u64;
    }
    Ok(len)
}

/// Copies a path argument (absolute or relative, UTF-8, no NUL) out of user memory.
fn user_path(ptr: u64, len: u64) -> Result<alloc::string::String, Errno> {
    if len == 0 || len > osyx_abi::MAX_PATH as u64 {
        return Err(Errno::InvalidArgument);
    }
    let mut buf = alloc::vec![0u8; len as usize];
    copy_from_user(&mut buf, ptr)?;
    if buf.contains(&0) {
        return Err(Errno::InvalidArgument);
    }
    alloc::string::String::from_utf8(buf).map_err(|_| Errno::InvalidArgument)
}

fn with_file<T>(handle: u64, op: impl FnOnce(&mut vfs::OpenFile) -> Result<T, Errno>) -> Result<T, Errno> {
    let file = process::get_handle(handle)?;
    let mut g = file.lock();
    op(&mut g)
}

/// Copies a plain `repr(C)` value to user memory.
fn put_user<T: Copy>(addr: u64, v: &T) -> Result<u64, Errno> {
    // SAFETY: only used with padding-free repr(C) ABI structs.
    let bytes = unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) };
    copy_to_user(addr, bytes)?;
    Ok(0)
}

/// True when every page of `[addr, addr + len)` is mapped, writable and
/// accessible from user mode in the current address space, so writing to it
/// cannot fault. A copy made without the entry lock must not fault: the fault
/// handler takes the entry lock, and its holder may be waiting for a lock
/// this thread holds.
fn user_write_ready(addr: u64, len: usize) -> bool {
    let page = crate::mem::PAGE_SIZE;
    let end = addr + len as u64;
    let mut at = addr & !(page - 1);
    while at < end {
        match crate::mem::paging::translate(at) {
            Some(t) if t.writable && t.user => {}
            _ => return false,
        }
        at += page;
    }
    true
}

/// Reads at the current position when the page cache already holds the data.
/// `None` means the normal path must run (cache miss, pipe, socket, large
/// request); `Some` is the result of the whole call.
fn read_cached(handle: u64, buf: u64, len: u64) -> Option<Result<u64, Errno>> {
    let len = len.min(osyx_abi::MAX_READ as u64) as usize;
    if len == 0 || len > crate::mem::PAGE_SIZE as usize {
        return None;
    }
    if !crate::fixup::user_range_ok(buf, len as u64) {
        return None;
    }
    let Object::File(file) = process::get_object(handle).ok()? else { return None };
    let mut f = file.lock();
    if !f.cache_readable() || !user_write_ready(buf, len) {
        return None;
    }
    // A destination page that is not mapped yet makes the copy fault; only
    // the normal path can resolve that (it prefaults under the entry lock).
    // Falling back also gets the page cache page out of the way for the
    // file system, so a short cached page never looks like end of file.
    let n = crate::filecache::read_cached_to_user(f.cache_key(), f.position(), buf, len)?.ok()?;
    f.advance(n);
    Some(Ok(n as u64))
}

/// Reads a regular file without the entry lock, including cache misses that
/// go to the disk. The handle table, the open file, the page cache and the
/// volume already have their own locks, and a fill that waits hundreds of
/// milliseconds for a busy disk must not hold up every other syscall.
/// `None` keeps pipes, sockets and buffers that would fault on the normal
/// path.
fn read_file(handle: u64, buf: u64, len: u64) -> Option<Result<u64, Errno>> {
    let len = len.min(osyx_abi::MAX_READ as u64) as usize;
    if len == 0 || !crate::fixup::user_range_ok(buf, len as u64) {
        return None;
    }
    let Object::File(file) = process::get_object(handle).ok()? else { return None };
    if !user_write_ready(buf, len) {
        return None;
    }
    cpu::enable_interrupts();
    let mut f = file.lock();
    if !f.cache_readable() {
        return None;
    }
    let mut k = alloc::vec![0u8; len.min(FILE_CHUNK)];
    let mut done = 0;
    while done < len {
        let want = (len - done).min(k.len());
        let read = f.read(&mut k[..want]);
        let n = match read.and_then(|n| copy_to_user(buf + done as u64, &k[..n]).map(|_| n)) {
            Ok(n) => n,
            Err(e) if done == 0 => return Some(Err(e)),
            Err(_) => break,
        };
        f.advance(n);
        done += n;
        if n < want {
            break;
        }
    }
    Some(Ok(done as u64))
}

/// Reads in chunks; after a chunk has been delivered, a later failure ends
/// the call with the bytes delivered so far (like a short read).
fn sys_read(handle: u64, buf: u64, len: u64) -> Result<u64, Errno> {
    match process::get_object(handle)? {
        Object::File(_) => {}
        Object::Pipe(_) => return sys_objects::read_stdio(handle, buf, len),
        Object::Socket(_) => return crate::net::sys_recv(handle, buf, len, 0, 0),
        _ => return Err(Errno::BadHandle),
    }
    let len = len.min(osyx_abi::MAX_READ as u64) as usize;
    if !crate::fixup::user_range_ok(buf, len as u64) {
        return Err(Errno::Fault);
    }
    process::prefault_write(buf, len);
    with_file(handle, |o| {
        let mut k = alloc::vec![0u8; len.min(FILE_CHUNK)];
        let mut done = 0;
        while done < len {
            let want = (len - done).min(k.len());
            let read = o.read(&mut k[..want]);
            let n = match read.and_then(|n| copy_to_user(buf + done as u64, &k[..n]).map(|_| n)) {
                Ok(n) => n,
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            };
            o.advance(n);
            done += n;
            if n < want {
                break;
            }
        }
        Ok(done as u64)
    })
}

fn write_file(handle: u64, buf: u64, len: usize) -> Result<u64, Errno> {
    with_file(handle, |o| {
        let mut k = alloc::vec![0u8; len.min(FILE_CHUNK)];
        let mut done = 0;
        while done < len {
            let n = (len - done).min(k.len());
            let r = copy_from_user(&mut k[..n], buf + done as u64).and_then(|_| o.write(&k[..n]));
            match r {
                Ok(w) => {
                    done += w;
                    if w < n {
                        break;
                    }
                }
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(done as u64)
    })
}

fn sys_readdir(handle: u64, buf: u64, len: u64) -> Result<u64, Errno> {
    let len = len.min(FILE_CHUNK as u64);
    if !crate::fixup::user_range_ok(buf, len) {
        return Err(Errno::Fault);
    }
    with_file(handle, |o| {
        let mut k = alloc::vec![0u8; len as usize];
        let n = o.readdir(&mut k)?;
        copy_to_user(buf, &k[..n])?;
        Ok(n as u64)
    })
}

/// A clock calibration pair, so a process can keep its own clocks from RDTSC.
/// The TSC is read after the clocks: the pair then describes a moment no
/// later than the TSC sample, and later samples never run behind it.
fn sys_time_calib(out: u64) -> Result<u64, Errno> {
    let mut v = [0u64; 4];
    v[0] = interrupts::monotonic_ns();
    v[3] = crate::time::now_ns().max(0) as u64;
    v[1] = crate::arch::timer::tsc();
    v[2] = interrupts::tsc_per_tick();
    crate::fixup::copy_to_user(out, unsafe {
        // SAFETY: the array is plain data of the given length.
        core::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 8)
    })?;
    Ok(0)
}

fn sys_sysinfo(out: u64) -> Result<u64, Errno> {
    let (free, total) = mem::frame_stats();
    let (ticks, idle_ticks) = sched::cpu_stats();
    let (disk_read_bytes, disk_write_bytes) = crate::block::io_bytes();
    let mut info = SystemInfo {
        abi_version: osyx_abi::ABI_VERSION,
        page_size: mem::PAGE_SIZE as u32,
        total_memory: total * mem::PAGE_SIZE,
        free_memory: free * mem::PAGE_SIZE,
        uptime_ns: interrupts::uptime_ms() * 1_000_000,
        pid: sched::current_pid(),
        kernel_version: [0; 16],
        ticks,
        idle_ticks,
        disk_read_bytes,
        disk_write_bytes,
    };
    let v = crate::VERSION.as_bytes();
    info.kernel_version[..v.len().min(16)].copy_from_slice(&v[..v.len().min(16)]);
    // SAFETY: SystemInfo is repr(C) plain data without padding-dependent
    // invariants; viewing it as bytes is sound.
    let bytes = unsafe {
        core::slice::from_raw_parts(&info as *const SystemInfo as *const u8, core::mem::size_of::<SystemInfo>())
    };
    copy_to_user(out, bytes)?;
    Ok(0)
}

fn sys_clock(id: u64) -> Result<u64, Errno> {
    match id {
        osyx_abi::CLOCK_MONOTONIC => Ok(interrupts::monotonic_ns()),
        osyx_abi::CLOCK_REALTIME => Ok(crate::time::now_ns().max(0) as u64),
        _ => Err(Errno::InvalidArgument),
    }
}

/// Sets the real-time clock (root only; 2020..2200 accepted).
fn sys_set_time(unix_ns: u64) -> Result<u64, Errno> {
    if !process::current_identity().0.is_root() {
        return Err(Errno::PermissionDenied);
    }
    const SEC: u64 = 1_000_000_000;
    if !(1_577_836_800 * SEC..7_258_118_400 * SEC).contains(&unix_ns) {
        return Err(Errno::InvalidArgument);
    }
    let off = crate::time::set_now_ns(unix_ns as i64);
    crate::kprintln!("time: set to {} UTC (the clock was off by {} ms)", crate::time::format_utc((unix_ns / SEC) as i64), off / 1_000_000);
    Ok(0)
}

/// Returns only on failure; on success the new program is running.
fn sys_execve(args_ptr: u64) -> Result<u64, Errno> {
    let req = ExecRequest::from_user(args_ptr)?;
    Err(process::exec_current(req).errno())
}

fn sys_wait(pid: u64, status_ptr: u64) -> Result<u64, Errno> {
    // Validate the output pointer before reaping, so a bad pointer cannot
    // lose the child's status.
    if status_ptr != 0 {
        copy_to_user(status_ptr, &0i32.to_le_bytes())?;
    }
    let (child, status) = process::wait(sched::current_pid(), pid)?;
    if status_ptr != 0 {
        copy_to_user(status_ptr, &status.to_le_bytes())?;
    }
    Ok(child)
}

fn user_string(ptr: u64, len: u64, max: usize) -> Result<alloc::string::String, Errno> {
    if len > max as u64 {
        return Err(Errno::InvalidArgument);
    }
    let mut buf = alloc::vec![0u8; len as usize];
    copy_from_user(&mut buf, ptr)?;
    alloc::string::String::from_utf8(buf).map_err(|_| Errno::InvalidArgument)
}

fn sys_mount(args_ptr: u64) -> Result<u64, Errno> {
    let mut raw = [0u8; core::mem::size_of::<osyx_abi::MountArgs>()];
    copy_from_user(&mut raw, args_ptr)?;
    // SAFETY: MountArgs is plain repr(C) data of exactly this size.
    let a: osyx_abi::MountArgs = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const osyx_abi::MountArgs) };
    let source = user_string(a.source, a.source_len, osyx_abi::MAX_PATH)?;
    let target = user_path(a.target, a.target_len)?;
    let fstype = user_string(a.fstype, a.fstype_len, 16)?;
    vfs::mount(&Lookup::current(), &source, &target, &fstype, a.flags, a.size_limit).map(|_| 0)
}

fn sys_umount(p: &str) -> Result<(), Errno> {
    let cx = Lookup::current();
    if !cx.cred.is_root() {
        return Err(Errno::PermissionDenied);
    }
    vfs::unmount(&cx, p)
}
