//! The 32-bit (PE32) API bridge.
//!
//! A PE32 program runs in IA-32e compatibility mode in the same process as
//! `winrun`. Every import is bound to a 12-byte stub in low memory; the stub
//! far-jumps to a 64-bit gate in `winrun`'s own text (which is linked below
//! 4 GiB), the gate calls the existing `extern "win64"` implementation
//! through a small assembly helper, and an `iretq` returns to the 32-bit
//! caller with the stdcall arguments removed.
//!
//! The arena at `0x2000_0000` (512 MiB, reserved with `MAP_FIXED`) holds
//! everything 32-bit code can address directly:
//!
//! ```text
//! 0x2000_0000  page 0       import stubs (12 bytes each; RX before entry)
//! 0x2000_1000  page 1       TEB32, the FS base of compatibility mode
//! 0x2000_2000  page 2       PEB32 (a small zeroed block)
//! 0x2000_3000  page 3       stack guard (read-only; OSyx has no no-access page)
//! 0x2000_4000  pages 4..    main 32-bit stack, 1 MiB
//! ```
//!
//! FS is one register shared by both modes. Kernel system call 96
//! (`set_fs32_base`) loads the TEB for 32-bit code and restores the thread's
//! 64-bit runtime base for 64-bit code, so every mode crossing flips it:
//! before `iretq` into the guest sets it to the TEB, and `bridge_dispatch`
//! clears it before calling any Rust or Win32 implementation (which may use
//! `os_std`'s FS-based TLS).
//!
//! Each thread that runs 32-bit code has a [`Ctx`], found by the gate at
//! TEB64 offset 0x100 (`WOW32Reserved` on Windows) through `gs`. The gate
//! keeps the per-call state (the caller's ESP) on its own 64-bit frame and
//! builds that frame below `Ctx::stack_top`, so the two directions nest:
//! a host function may call back into 32-bit code ([`call32`]: window
//! procedures, thread start routines), and that code may call imports
//! again. A callback returns through a 32-bit stub that far-jumps to
//! `osyx_wow64_callback_return`, which restores the 64-bit stack saved in
//! `Ctx::landing_rsp`.

use crate::mem::{self, Prot, PAGE};
use alloc::vec::Vec;
use core::arch::global_asm;
use core::sync::atomic::{AtomicPtr, Ordering};
use os_std::sync::Mutex;
use osyx_abi::wow64::{ENTRY_RFLAGS, USER_CS, USER_CS32, USER_DS};

// The ABI constants and the literals in the assembly below must not drift.
const _: () = assert!(USER_CS == 0x23 && USER_CS32 == 0x3B && USER_DS == 0x1B && ENTRY_RFLAGS == 0x202);

const ARENA_BASE: u32 = 0x2000_0000;
const ARENA_SIZE: usize = 4 << 20; // stubs, TEB, PEB, guard and a 1 MiB stack
const STUB_PAGE: u32 = ARENA_BASE;
const STUB_SIZE: u32 = 12;
/// The callback return stub: the last 16 bytes of the stub page.
const RET_STUB: u32 = STUB_PAGE + PAGE as u32 - 16;
/// Stubs that fit in one page (SteamSetup needs 166 imports).
const MAX_IMPORTS: usize = (PAGE - 16) / STUB_SIZE as usize;
const TEB32: u32 = ARENA_BASE + PAGE as u32;
const PEB32: u32 = TEB32 + PAGE as u32;
const GUARD32: u32 = PEB32 + PAGE as u32;
const STACK_BASE: u32 = GUARD32 + PAGE as u32;
const STACK_SIZE: u32 = 1 << 20; // 1 MiB
const STACK_TOP: u32 = STACK_BASE + STACK_SIZE;

// 32-bit TEB fields (NT_TIB and the first part of the TEB).
const TEB_EXCEPTION_LIST: u32 = 0x00;
const TEB_STACK_BASE: u32 = 0x04;
const TEB_STACK_LIMIT: u32 = 0x08;
const TEB_SELF: u32 = 0x18;
const TEB_PROCESS_ID: u32 = 0x20;
const TEB_THREAD_ID: u32 = 0x24;
const TEB_PEB: u32 = 0x30;

const BRIDGE_STACK_SIZE: usize = 64 * 1024;
/// 64-bit stack of each additional 32-bit thread's gate and host code.
const THREAD_HOST_STACK: usize = 256 * 1024;
/// 32-bit stack of an additional thread.
const THREAD_STACK32: usize = 1 << 20;
/// TEB64 offset of the thread's [`Ctx`].
const TEB64_CTX: u64 = 0x100;
const MAX_ARG_SLOTS: usize = 16;

/// How one 32-bit stack slot becomes a 64-bit Win64 argument.
#[allow(dead_code)] // the full vocabulary is part of the table design
#[derive(Clone, Copy)]
enum ArgKind {
    /// Pointer: zero-extend the 4-byte slot.
    Ptr,
    /// Unsigned 32-bit value: zero-extend.
    Uint,
    /// Signed 32-bit value: sign-extend.
    Int,
    /// HANDLE / HKEY / HWND: sign-extended, as WoW64 widens handles, so
    /// `INVALID_HANDLE_VALUE`, pseudo-handles (-1, -2) and the predefined
    /// registry keys (`(LONG)0x8000000x`) keep their 64-bit values.
    Handle,
    /// 64-bit value: join this slot (low) and the next (high).
    U64,
    /// Pointer to a pointer-sized output (HKEY, HANDLE, PIDL, DWORD_PTR):
    /// the host writes 8 bytes into a temporary, the 32-bit caller gets
    /// its low 4 bytes. A null pointer stays null.
    OutWide,
}

/// How the 64-bit result reaches 32-bit code.
#[allow(dead_code)] // the full vocabulary is part of the table design
#[derive(Clone, Copy)]
enum RetKind {
    Void,
    U32,
    I32,
    Ptr,
    Handle,
    /// Returned in EDX:EAX.
    I64,
}

struct Signature {
    name: &'static str,
    args: &'static [ArgKind],
    ret: RetKind,
    is_cdecl: bool,
}

mod sigs;
use sigs::SIGNATURES;

/// One bound import, indexed by the stub's `mov eax, index`.
#[derive(Clone, Copy)]
struct Entry {
    name: &'static str,
    host: u64,
    args: &'static [ArgKind],
    ret: RetKind,
    is_cdecl: bool,
}

/// The bridge whose stubs are live; set once, just before `iretq`.
static ACTIVE: AtomicPtr<Bridge> = AtomicPtr::new(core::ptr::null_mut());

/// Per-thread bridge state; the gate and the callback landing use the
/// offsets in the comments, keep them in sync with the assembly.
#[repr(C)]
pub(crate) struct Ctx {
    /// 0: the 32-bit stack pointer of the innermost gate entry; a callback
    /// builds its frame below it.
    esp: u64,
    /// 8: EDX for an I64 result.
    result_high: u32,
    /// 12: stdcall bytes the gate removes.
    cleanup: u32,
    /// 16: where the next gate entry puts its 64-bit frame.
    stack_top: u64,
    /// 24: the thread's TEB32 (its FS32 base).
    teb32: u64,
    /// 32: RSP that `osyx_wow64_callback_return` restores.
    landing_rsp: u64,
}

const _: () = assert!(core::mem::offset_of!(Ctx, stack_top) == 16 && core::mem::offset_of!(Ctx, landing_rsp) == 32);

/// The calling thread's [`Ctx`] (null when it never ran 32-bit code).
fn ctx() -> *mut Ctx {
    let teb = crate::teb::current();
    if teb == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: TEB_SIZE bytes; the slot holds 0 or a Ctx of this thread.
    unsafe { crate::teb::get::<u64>(teb, TEB64_CTX as usize) as *mut Ctx }
}

/// The main thread's 64-bit gate stack (other threads allocate theirs).
#[repr(align(16))]
#[allow(dead_code)] // the bytes are touched only by the assembly gate
struct BridgeStack([u8; BRIDGE_STACK_SIZE]);
static mut BRIDGE_STACK: BridgeStack = BridgeStack([0; BRIDGE_STACK_SIZE]);

global_asm!(
    r#"
    .section .text
    .balign 16
    .global osyx_wow64_gate
osyx_wow64_gate:
    // Entered from 32-bit code with EAX = import index and RSP = rsp32.
    // Compatibility mode leaves the upper halves undefined; make RSP a
    // usable 64-bit pointer (the arena is below 4 GiB).
    mov esp, esp
    cld                             // Rust and the Win64 ABI require DF = 0
    mov r10, rsp                    // rsp32
    mov r11, gs:[0x30]              // TEB64
    mov r11, [r11 + {teb64_ctx}]    // Ctx
    mov rsp, [r11 + 16]             // Ctx::stack_top
    and rsp, -16
    push qword ptr [r11]            // the enclosing entry's Ctx::esp
    push r10
    mov [r11], r10                  // callbacks build below this call
    mov ecx, eax                    // idx (Win64 argument 1)
    lea rdx, [r10 + 4]              // first 32-bit stack argument
    sub rsp, 32                     // Win64 shadow space
    call {dispatch}
    add rsp, 32
    // dispatch returned with EAX = low result and stored EDX and the
    // stdcall cleanup in the Ctx. An IRET from 64-bit mode into a
    // compatibility segment reloads SS:RSP from the frame even at the same
    // privilege, so the frame has five slots and RSP is the value the
    // caller resumes with.
    pop r10                         // rsp32 of this call
    mov r11, gs:[0x30]
    mov r11, [r11 + {teb64_ctx}]
    pop qword ptr [r11]             // restore the enclosing Ctx::esp
    mov edx, [r11 + 8]
    mov r8d, [r11 + 12]
    lea rcx, [r10 + r8 + 4]         // past the return address and arguments
    mov r9d, [r10]                  // RIP: the return address on the 32-bit stack
    lea rsp, [rcx - 40]             // frame below the resume stack pointer
    push 0x1B                       // SS: USER_DS
    push rcx                        // RSP after the return
    push 0x202                      // RFLAGS: IF set, everything else clear
    push 0x3B                       // CS: USER_CS32 (D=1, L=0)
    push r9                         // RIP
    // IRET does not reload DS/ES, and 64-bit code runs with a null DS, which
    // compatibility mode rejects on the first data access. Load the flat
    // ring-3 data selector at CPL 3.
    mov ecx, 0x1B
    mov ds, cx
    mov es, cx
    iretq

    // osyx_wow64_call32(target: u32, args: *const u32, n: u32, ctx: *mut Ctx) -> u32
    //
    // SysV entry. Pushes the stdcall arguments and the return stub below
    // Ctx::esp and enters `target` in compatibility mode; the callee's
    // `ret` reaches the stub, whose far jump lands in
    // osyx_wow64_callback_return with the result in EAX.
    .balign 16
    .global osyx_wow64_call32
osyx_wow64_call32:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rcx                    // Ctx
    push qword ptr [rbx + 16]       // enclosing Ctx::stack_top
    push qword ptr [rbx + 32]       // enclosing Ctx::landing_rsp
    mov [rbx + 32], rsp
    lea rax, [rsp - 64]
    mov [rbx + 16], rax             // gates the callee enters go below
    mov eax, [rbx]                  // Ctx::esp
    and eax, -4
    mov r8d, edx                    // n
    lea r9, [r8 * 4 + 4]
    sub rax, r9                     // the callee's ESP: return address, then arguments
    xor r10d, r10d
2:
    cmp r10d, r8d
    jae 3f
    mov r11d, [rsi + r10 * 4]
    mov [rax + r10 * 4 + 4], r11d
    inc r10d
    jmp 2b
3:
    mov dword ptr [rax], {ret_stub}
    push 0x1B                       // SS
    push rax                        // RSP
    push 0x202                      // RFLAGS
    push 0x3B                       // CS: compatibility mode
    mov edi, edi
    push rdi                        // RIP: the callback
    mov ecx, 0x1B
    mov ds, cx
    mov es, cx
    iretq

    .balign 16
    .global osyx_wow64_callback_return
osyx_wow64_callback_return:
    // From the return stub: EAX = result, all else undefined.
    cld
    mov r11, gs:[0x30]
    mov r11, [r11 + {teb64_ctx}]
    mov rsp, [r11 + 32]
    pop qword ptr [r11 + 32]
    pop qword ptr [r11 + 16]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    mov eax, eax
    ret

    .balign 16
    .global osyx_wow64_enter32
osyx_wow64_enter32:
    // OSyxWin32: fn(entry: u32, stack_top: u32) -> !, SysV arguments.
    // The frame is pushed on the 32-bit stack itself, below `stack_top`,
    // because the IRET takes RSP from the frame.
    mov edi, edi
    mov esi, esi
    lea rsp, [rsi - 40]             // five 8-byte slots below the initial RSP
    push 0x1B                       // SS: USER_DS
    push rsi                        // RSP: initial 32-bit stack pointer
    push 0x202                      // RFLAGS
    push 0x3B                       // CS: compatibility mode
    push rdi                        // entry point
    // 64-bit code runs with a null DS; compatibility mode faults on it.
    mov ecx, 0x1B
    mov ds, cx
    mov es, cx
    iretq

    // osyx_win64_invoke(f: u64, args: *const u64, n: u32) -> u64
    //
    // SysV entry (RDI/RSI/EDX). Loads RCX/RDX/R8/R9 from the argument
    // array and copies arguments 4..n to the Win64 stack argument area
    // above the 32-byte shadow space. The stack is 16-byte aligned before
    // the call, as the Win64 ABI requires.
    .balign 16
    .global osyx_win64_invoke
osyx_win64_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rbp, rsp                    // 16-byte aligned frame base
    mov rbx, rdi                    // host function
    mov r12, rsi                    // argument array
    mov r13d, edx                   // argument count
    xor r14d, r14d
    cmp r13d, 4
    jbe 1f
    lea r14, [r13*8 - 32]           // bytes above the shadow space
1:
    lea rax, [r14 + 47]             // 32 shadow + extra, rounded up to 16
    and rax, -16
    sub rsp, rax
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    test r13d, r13d
    jz 2f
    mov rcx, [r12]
    cmp r13d, 1
    je 2f
    mov rdx, [r12 + 8]
    cmp r13d, 2
    je 2f
    mov r8, [r12 + 16]
    cmp r13d, 3
    je 2f
    mov r9, [r12 + 24]
    lea r11, [rsp + 32]             // first stack argument
    mov r10d, 4
3:
    cmp r10d, r13d
    jae 2f
    mov rax, [r12 + r10*8]
    mov [r11], rax
    add r11, 8
    inc r10d
    jmp 3b
2:
    call rbx
    mov rsp, rbp
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    "#,
    teb64_ctx = const TEB64_CTX,
    ret_stub = const RET_STUB,
    dispatch = sym bridge_dispatch,
);

extern "C" {
    /// The 64-bit gate reached by a far jump from every 32-bit stub.
    fn osyx_wow64_gate();
    /// Builds an IRETQ frame to compatibility mode and never returns.
    fn osyx_wow64_enter32(entry: u32, stack_top: u32) -> !;
    /// Calls a dynamic Win64 function with `n` already-widened arguments.
    fn osyx_win64_invoke(host: u64, args: *const u64, n: u32) -> u64;
    /// Calls a 32-bit stdcall function; returns its EAX.
    fn osyx_wow64_call32(target: u32, args: *const u32, n: u32, ctx: *mut Ctx) -> u32;
    /// The 64-bit landing of the callback return stub.
    fn osyx_wow64_callback_return();
}

/// The 32-bit arena and the import dispatcher for one process.
pub struct Bridge {
    /// Physical (32-bit) address of the TEB, also the FS32 base.
    teb: u32,
    /// Initial 32-bit stack pointer.
    stack_top: u32,
    entries: Mutex<Vec<Entry>>,
}

impl Bridge {
    /// Maps the 32-bit arena: import-stub pages, TEB32, PEB32 and the
    /// initial 1 MiB stack above a guard page.
    pub fn new() -> Result<Bridge, &'static str> {
        let base = mem::alloc_fixed(ARENA_BASE as u64, ARENA_SIZE, Prot::ReadWrite)
            .ok_or("wow64: cannot reserve the 32-bit arena at 0x20000000")?;
        debug_assert_eq!(base, ARENA_BASE as u64);

        let pid = os_std::process::id().unwrap_or(0) as u32;
        let tid = os_sys::gettid() as u32;
        // SAFETY: these pages are inside the fresh arena mapping.
        unsafe {
            poke32(TEB32 + TEB_EXCEPTION_LIST, u32::MAX); // end of the SEH chain
            poke32(TEB32 + TEB_STACK_BASE, STACK_TOP);
            poke32(TEB32 + TEB_STACK_LIMIT, STACK_BASE);
            poke32(TEB32 + TEB_SELF, TEB32);
            poke32(TEB32 + TEB_PROCESS_ID, pid);
            poke32(TEB32 + TEB_THREAD_ID, tid);
            poke32(TEB32 + TEB_PEB, PEB32);
        }

        // The callback return stub: jmp far USER_CS:osyx_wow64_callback_return.
        let landing = osyx_wow64_callback_return as *const () as usize;
        assert!(landing != 0 && landing < 1usize << 32, "wow64: callback landing is not below 4 GiB");
        // SAFETY: the stub page is writable until `enter` protects it; the
        // last 16 bytes are reserved for this stub (MAX_IMPORTS).
        unsafe {
            let p = RET_STUB as *mut u8;
            *p = 0xEA;
            core::ptr::write_unaligned(p.add(1).cast::<u32>(), landing as u32);
            core::ptr::write_unaligned(p.add(5).cast::<u16>(), USER_CS);
        }

        // All gates are written before the page becomes executable. Later
        // imports only publish an entry, so they never change RX memory.
        let gate = osyx_wow64_gate as *const () as usize;
        assert!(gate != 0 && gate < 1usize << 32, "wow64: gate is not below 4 GiB");
        for index in 0..MAX_IMPORTS {
            let p = (STUB_PAGE + index as u32 * STUB_SIZE) as *mut u8;
            unsafe {
                *p = 0xB8;
                core::ptr::write_unaligned(p.add(1).cast::<u32>(), index as u32);
                *p.add(5) = 0xEA;
                core::ptr::write_unaligned(p.add(6).cast::<u32>(), gate as u32);
                core::ptr::write_unaligned(p.add(10).cast::<u16>(), USER_CS);
            }
        }

        // OSyx cannot map a page with no access; a read-only page is the
        // guard: a stack overflow writing into it faults.
        mem::protect(GUARD32 as u64, PAGE, Prot::ReadOnly)
            .map_err(|_| "wow64: cannot make the 32-bit stack guard page read-only")?;

        Ok(Bridge { teb: TEB32, stack_top: STACK_TOP, entries: Mutex::new(Vec::new()) })
    }

    /// `(limit, base)` of the 32-bit stack: the lowest valid address and the
    /// initial (highest) one, as Windows TEBs record them.
    pub fn stack(&self) -> (u64, u64) {
        (STACK_BASE as u64, STACK_TOP as u64)
    }

    /// Returns the 32-bit address of a stub for `symbol`, whose 64-bit
    /// implementation is at `host`, or `None` when no signature is known.
    pub fn import(&self, symbol: &str, host: u64) -> Option<u32> {
        let signature = SIGNATURES.iter().find(|s| s.name == symbol)?;
        let host = host_override(symbol).unwrap_or(host);
        assert!(signature.args.len() <= MAX_ARG_SLOTS, "wow64: import signature has too many arguments");
        let mut entries = self.entries.lock().unwrap();
        if let Some(index) = entries.iter().position(|e| e.name == signature.name && e.host == host) {
            return Some(STUB_PAGE + index as u32 * STUB_SIZE);
        }
        if entries.len() >= MAX_IMPORTS { return None; }
        let index = entries.len() as u32;
        let stub = STUB_PAGE + index * STUB_SIZE;
        entries.push(Entry {
            name: signature.name,
            host,
            args: signature.args,
            ret: signature.ret,
            is_cdecl: signature.is_cdecl,
        });

        if crate::VERBOSE.load(Ordering::Relaxed) {
            os_std::eprintln!("winrun: wow64 {symbol} -> stub {stub:#x}, host {host:#x}");
        }
        Some(stub)
    }

    /// Prepares the gate and main thread before delivering DLL callbacks.
    pub fn prepare(&mut self) -> Result<(), &'static str> {
        if let Err(e) = mem::protect(STUB_PAGE as u64, PAGE, Prot::ExecuteRead) {
            os_std::eprintln!("winrun: wow64: cannot make import stubs executable: {e:?}");
            return Err("wow64: cannot make import stubs executable");
        }
        ACTIVE.store(self as *mut Bridge, Ordering::Release);
        // The main thread's Ctx: the static gate stack and the arena TEB32.
        let host_top = core::ptr::addr_of_mut!(BRIDGE_STACK) as u64 + BRIDGE_STACK_SIZE as u64;
        install_ctx(self.stack_top as u64, host_top, self.teb as u64);
        Ok(())
    }

    /// Enters `entry` in compatibility mode. Never returns normally.
    pub fn enter(&mut self, entry: u32) -> ! {
        if crate::VERBOSE.load(Ordering::Relaxed) {
            os_std::eprintln!("winrun: wow64 enter {entry:#x}, rsp {:#x}, teb {:#x}", self.stack_top, self.teb);
        }
        // 32-bit code sees its TEB at fs:[0x18]; this also loads FS from the
        // per-thread descriptor immediately. Nothing may use os_std (FS TLS)
        // after this point until the bridge restores the 64-bit base.
        if let Err(e) = os_sys::set_fs32_base(self.teb as usize) {
            os_std::eprintln!("winrun: wow64: cannot set the 32-bit FS base: {e:?}");
            os_std::process::exit(126);
        }
        // SAFETY: the stub page is RX; the TEB and stack are mapped; the
        // IRETQ frame targets DPL-3 selectors from CPL 3.
        unsafe { osyx_wow64_enter32(entry, self.stack_top) }
    }
}

pub(crate) fn clear_active() {
    ACTIVE.store(core::ptr::null_mut(), Ordering::Release);
}

/// The Rust half of the gate. Called with the Win64 ABI on the bridge
/// stack, FS still pointing at TEB32.
#[inline(never)]
extern "win64" fn bridge_dispatch(index: u32, args: *const u32) -> u64 {
    let bridge = ACTIVE.load(Ordering::Relaxed);
    if bridge.is_null() {
        let _ = os_sys::set_fs32_base(0);
        os_std::eprintln!("winrun: wow64: gate entered without a bridge");
        os_std::process::exit(0xC000_0005u32 as i32);
    }
    // SAFETY: `ACTIVE` points at the Bridge whose `enter` built these
    // stubs; it lives until the 32-bit program ends. The gate found this
    // thread's Ctx through the same TEB64 slot.
    let bridge = unsafe { &*bridge };
    let ctx = unsafe { &mut *ctx() };
    let teb = ctx.teb32;

    // Rust (os_std) uses FS for TLS: restore the 64-bit base before any
    // implementation or allocator code runs.
    let _ = os_sys::set_fs32_base(0);
    let (low, high, cleanup) = dispatch(bridge, index, args);
    // Back to the mode the 32-bit caller is in (and to its stack, via the
    // IRETQ frame the gate builds).
    let _ = os_sys::set_fs32_base(teb as usize);

    ctx.cleanup = cleanup;
    ctx.result_high = high;
    low
}

/// Gives the calling thread (which has a TEB64) a [`Ctx`]: 32-bit code
/// starts at `esp`, gate frames go below `host_top`, FS32 is `teb32`.
fn install_ctx(esp: u64, host_top: u64, teb32: u64) {
    let c = alloc::boxed::Box::leak(alloc::boxed::Box::new(Ctx {
        esp,
        result_high: 0,
        cleanup: 0,
        stack_top: host_top,
        teb32,
        landing_rsp: 0,
    }));
    // SAFETY: the current thread's TEB64 (TEB_SIZE bytes).
    unsafe { crate::teb::put(crate::teb::current(), TEB64_CTX as usize, c as *mut Ctx as u64) };
}

/// Calls the 32-bit stdcall function `target` with `args` from 64-bit host
/// code running for a 32-bit thread (inside an import, or a thread's
/// start), and returns its EAX. The callee runs below the 32-bit stack
/// position of the innermost import call and may call imports itself.
pub(crate) fn call32(target: u32, args: &[u32]) -> u32 {
    let c = ctx();
    assert!(!c.is_null(), "wow64: call32 on a thread without 32-bit state");
    // SAFETY: this thread's Ctx; FS32 is restored before the host resumes.
    unsafe {
        let teb = (*c).teb32;
        if os_sys::set_fs32_base(teb as usize).is_err() {
            os_std::process::exit(0xC000_0005u32 as i32);
        }
        let r = osyx_wow64_call32(target, args.as_ptr(), args.len() as u32, c);
        let _ = os_sys::set_fs32_base(0);
        r
    }
}

// ---- threads -------------------------------------------------------------

/// Start of a 32-bit thread, handed to the host CreateThread.
struct ThreadStart {
    start: u32,
    param: u32,
}

/// CreateThread for 32-bit callers: `start` is a 32-bit
/// `DWORD WINAPI start(LPVOID)`. The host thread gets its own 32-bit
/// stack, TEB32 and 64-bit gate stack, then calls `start(param)`; its
/// return value is the thread's exit code.
#[allow(non_snake_case)] // the Win32 name
extern "win64" fn CreateThread32(attributes: u64, stack: usize, start: u64, param: u64, flags: u32, tid: *mut u32) -> u64 {
    let arg = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(ThreadStart { start: start as u32, param: param as u32 }));
    let h = crate::kernel32::CreateThread(attributes, stack, thread32_main as *const () as u64, arg as u64, flags, tid);
    if h == 0 {
        // SAFETY: not handed to any thread.
        drop(unsafe { alloc::boxed::Box::from_raw(arg) });
    }
    h
}

extern "win64" fn thread32_main(arg: u64) -> u32 {
    // SAFETY: the Box made by CreateThread32 for this thread.
    let ThreadStart { start, param } = *unsafe { alloc::boxed::Box::from_raw(arg as *mut ThreadStart) };
    run_thread32(start, param)
}

/// Set up a 32-bit callback thread and execute its start routine.
pub(crate) fn run_thread32(start: u32, param: u32) -> u32 {
    let stack32 = mem::alloc_pages(THREAD_STACK32 + PAGE, Prot::ReadWrite);
    let host = mem::alloc_pages(THREAD_HOST_STACK, Prot::ReadWrite);
    let (Some(stack32), Some(host)) = (stack32, host) else { return 0xC000_0017 }; // STATUS_NO_MEMORY
    // The TEB32 is the stack mapping's first page (the low-memory window is
    // below 2 GiB, so both are addressable by 32-bit code).
    let teb = stack32 as u32;
    let (limit, top) = (teb + PAGE as u32, teb + PAGE as u32 + THREAD_STACK32 as u32);
    // SAFETY: the fresh, writable page at `teb`.
    unsafe {
        poke32(teb + TEB_EXCEPTION_LIST, u32::MAX);
        poke32(teb + TEB_STACK_BASE, top);
        poke32(teb + TEB_STACK_LIMIT, limit);
        poke32(teb + TEB_SELF, teb);
        poke32(teb + TEB_PROCESS_ID, os_std::process::id().unwrap_or(0) as u32);
        poke32(teb + TEB_THREAD_ID, os_sys::gettid() as u32);
        poke32(teb + TEB_PEB, PEB32);
    }
    install_ctx(top as u64, host + THREAD_HOST_STACK as u64, teb as u64);
    call32(start, &[param])
}

/// Whether this process runs a 32-bit program (the bridge is live): host
/// code that reads caller structures with pointer-sized fields must then
/// use the 32-bit layout.
pub(crate) fn is_active() -> bool {
    !ACTIVE.load(Ordering::Relaxed).is_null()
}

/// STARTUPINFOW of a 32-bit caller (68 bytes) as the host's 64-bit layout
/// (104 bytes): dwFlags moves to 60 and the three handles, sign-extended,
/// to 80, 88 and 96. The string and reserved pointers are not read by the
/// host's `CreateProcessW`, so they stay zero.
fn startupinfo_to64(si: *const u8) -> Option<[u8; 104]> {
    // SAFETY: the caller's STARTUPINFOW; cb says how much of it exists.
    unsafe {
        let rd = |at: usize| core::ptr::read_unaligned(si.add(at).cast::<u32>());
        if rd(0) < 68 {
            return None;
        }
        let mut out = [0u8; 104];
        out[0..4].copy_from_slice(&104u32.to_le_bytes());
        out[60..64].copy_from_slice(&rd(44).to_le_bytes());
        out[64..66].copy_from_slice(&core::ptr::read_unaligned(si.add(48).cast::<u16>()).to_le_bytes());
        for (i, at) in [56, 60, 64].into_iter().enumerate() {
            out[80 + 8 * i..88 + 8 * i].copy_from_slice(&(rd(at) as i32 as i64 as u64).to_le_bytes());
        }
        Some(out)
    }
}

/// CreateProcessW for 32-bit callers: the STARTUPINFOW and
/// PROCESS_INFORMATION differ in layout (4-byte handles), everything else
/// is a pointer or integer the signature widens.
#[allow(non_snake_case, clippy::too_many_arguments)] // the Win32 name
extern "win64" fn CreateProcessW32(
    app: *const u16,
    cmdline: *mut u16,
    psa: u64,
    tsa: u64,
    inherit: i32,
    flags: u32,
    env: u64,
    cwd: *const u16,
    startup: *const u8,
    info: *mut u32,
) -> i32 {
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    if startup.is_null() || info.is_null() || flags & EXTENDED_STARTUPINFO_PRESENT != 0 {
        return crate::kernel32::fail(if flags & EXTENDED_STARTUPINFO_PRESENT != 0 { crate::error::ERROR_NOT_SUPPORTED } else { crate::error::ERROR_INVALID_PARAMETER }, 0);
    }
    let Some(si) = startupinfo_to64(startup) else {
        return crate::kernel32::fail(crate::error::ERROR_INVALID_PARAMETER, 0);
    };
    let mut pi = [0u64; 3];
    let r = crate::process::CreateProcessW(app, cmdline, psa, tsa, inherit, flags, env, cwd, si.as_ptr(), pi.as_mut_ptr());
    if r != 0 {
        // Handles are small table indices; a value that does not fit would
        // be silently truncated, so refuse it instead.
        if pi[0] > u32::MAX as u64 || pi[1] > u32::MAX as u64 {
            let _ = crate::kernel32::CloseHandle(pi[0]);
            let _ = crate::kernel32::CloseHandle(pi[1]);
            return crate::kernel32::fail(crate::error::ERROR_NOT_ENOUGH_MEMORY, 0);
        }
        // PROCESS_INFORMATION (16 bytes): hProcess, hThread, dwProcessId, dwThreadId.
        // SAFETY: the caller's 16-byte PROCESS_INFORMATION.
        unsafe {
            let ids = pi[2];
            core::ptr::write_unaligned(info, pi[0] as u32);
            core::ptr::write_unaligned(info.add(1), pi[1] as u32);
            core::ptr::write_unaligned(info.add(2), ids as u32);
            core::ptr::write_unaligned(info.add(3), (ids >> 32) as u32);
        }
    }
    r
}

/// Host functions that replace the built-in one for 32-bit callers.
#[allow(non_snake_case)]
extern "win64" fn MsgWaitForMultipleObjects32(n: u32, handles: *const u32, wait_all: i32, ms: u32, mask: u32) -> u32 {
    if n > 63 || (n != 0 && handles.is_null()) {
        return crate::user32::MsgWaitForMultipleObjects(n, core::ptr::null(), wait_all, ms, mask);
    }
    let mut widened = [0u64; 63];
    for (i, slot) in widened.iter_mut().take(n as usize).enumerate() {
        // SAFETY: the guest supplies an array of n 32-bit handles.
        *slot = unsafe { core::ptr::read_unaligned(handles.add(i)) } as i32 as i64 as u64;
    }
    crate::user32::MsgWaitForMultipleObjects(n, widened.as_ptr(), wait_all, ms, mask)
}

#[allow(non_snake_case)]
extern "win64" fn MsgWaitForMultipleObjectsEx32(n: u32, handles: *const u32, ms: u32, mask: u32, flags: u32) -> u32 {
    if n > 63 || (n != 0 && handles.is_null()) {
        return crate::user32::MsgWaitForMultipleObjectsEx(n, core::ptr::null(), ms, mask, flags);
    }
    let mut widened = [0u64; 63];
    for (i, slot) in widened.iter_mut().take(n as usize).enumerate() {
        // SAFETY: the guest supplies an array of n 32-bit handles.
        *slot = unsafe { core::ptr::read_unaligned(handles.add(i)) } as i32 as i64 as u64;
    }
    crate::user32::MsgWaitForMultipleObjectsEx(n, widened.as_ptr(), ms, mask, flags)
}

#[allow(non_snake_case)]
extern "win64" fn WaitForMultipleObjects32(n: u32, handles: *const u32, all: i32, ms: u32) -> u32 {
    WaitForMultipleObjectsEx32(n, handles, all, ms, 0)
}

#[allow(non_snake_case)]
extern "win64" fn WaitForMultipleObjectsEx32(n: u32, handles: *const u32, all: i32, ms: u32, alertable: i32) -> u32 {
    if n == 0 || n > 64 || handles.is_null() {
        return crate::kernel32::WaitForMultipleObjectsEx(n, core::ptr::null(), all, ms, alertable);
    }
    let mut widened = [0u64; 64];
    for (i, slot) in widened.iter_mut().take(n as usize).enumerate() {
        // SAFETY: the guest supplies an array of n 32-bit handles.
        *slot = unsafe { core::ptr::read_unaligned(handles.add(i)) } as i32 as i64 as u64;
    }
    crate::kernel32::WaitForMultipleObjectsEx(n, widened.as_ptr(), all, ms, alertable)
}

fn host_override(symbol: &str) -> Option<u64> {
    match symbol {
        "CreateThread" => Some(CreateThread32 as *const () as u64),
        "CreateProcessW" => Some(CreateProcessW32 as *const () as u64),
        "MsgWaitForMultipleObjects" => Some(MsgWaitForMultipleObjects32 as *const () as u64),
        "MsgWaitForMultipleObjectsEx" => Some(MsgWaitForMultipleObjectsEx32 as *const () as u64),
        "WaitForMultipleObjects" => Some(WaitForMultipleObjects32 as *const () as u64),
        "WaitForMultipleObjectsEx" => Some(WaitForMultipleObjectsEx32 as *const () as u64),
        _ => None,
    }
}

fn dispatch(bridge: &Bridge, index: u32, args: *const u32) -> (u64, u32, u32) {
    let Some(entry) = bridge.entries.lock().unwrap().get(index as usize).copied() else {
        os_std::eprintln!("winrun: wow64: bad import index {index}");
        os_std::process::exit(0xC000_0005u32 as i32);
    };

    if entry.name == "wsprintfW" || entry.name == "wsprintfA" {
        // SAFETY: the cdecl call supplies destination and format in its first
        // two slots; the formatter consumes additional stack slots as needed.
        let (out, fmt, rest) = unsafe { (*args, *args.add(1), args.add(2)) };
        let result = crate::user32::wsprintf32(entry.name == "wsprintfW", out, fmt, rest);
        return (result as u32 as u64, 0, 0);
    }

    if entry.name == "_snprintf" || entry.name == "_snwprintf" {
        // SAFETY: the cdecl call supplies buffer, count and format before the variadic arguments.
        let (out, count, fmt, rest) = unsafe { (*args, *args.add(1), *args.add(2), args.add(3)) };
        let result = crate::ucrt::printf::legacy_snprintf32(entry.name == "_snwprintf", out, count, fmt, rest);
        return (result as u32 as u64, 0, 0);
    }

    let mut values = [0u64; MAX_ARG_SLOTS];
    // Host-side temporaries for OutWide arguments: (guest address, value).
    let mut wide = [(0u32, 0u64); MAX_ARG_SLOTS];
    let mut nwide = 0;
    let mut guest_slot = 0usize;
    let mut out = 0usize;
    for &kind in entry.args {
        // SAFETY: the signature says these 4-byte slots are on the 32-bit
        // stack at `args`; the guest owns that stack.
        let word = |at: usize| unsafe { core::ptr::read_unaligned(args.add(at)) };
        values[out] = match kind {
            ArgKind::Ptr | ArgKind::Uint => word(guest_slot) as u64,
            ArgKind::Int | ArgKind::Handle => (word(guest_slot) as i32) as i64 as u64,
            ArgKind::U64 => {
                let low = word(guest_slot) as u64;
                let high = word(guest_slot + 1) as u64;
                low | high << 32
            }
            ArgKind::OutWide => match word(guest_slot) {
                0 => 0,
                guest => {
                    // SAFETY: the guest passes a pointer to its 4-byte slot.
                    wide[nwide] = (guest, unsafe { core::ptr::read_unaligned(guest as *const u32) } as u64);
                    nwide += 1;
                    &mut wide[nwide - 1].1 as *mut u64 as u64
                }
            },
        };
        out += 1;
        guest_slot += match kind {
            ArgKind::U64 => 2,
            _ => 1,
        };
    }

    let cleanup = if entry.is_cdecl { 0 } else { (guest_slot * 4) as u32 };
    // SAFETY: `entry.host` is a Win64 function with the signature recorded
    // in SIGNATURES; `values` has one 64-bit slot per argument.
    let result = unsafe { osyx_win64_invoke(entry.host, values.as_ptr(), out as u32) };
    for &(guest, value) in &wide[..nwide] {
        // SAFETY: as above; the 32-bit slot receives the low half.
        unsafe { core::ptr::write_unaligned(guest as *mut u32, value as u32) };
    }
    let high = match entry.ret {
        RetKind::I64 => (result >> 32) as u32,
        _ => 0,
    };
    (result, high, cleanup)
}

/// Resolve an additional gate after entry without making code writable.
pub(crate) fn import_active(symbol: &str, host: u64) -> Option<u32> {
    let bridge = ACTIVE.load(Ordering::Acquire);
    if bridge.is_null() { return None; }
    // SAFETY: the active bridge lives until process exit.
    unsafe { &*bridge }.import(symbol, host)
}

/// Writes a 32-bit field of the fresh TEB.
///
/// # Safety
/// `at` must point at writable memory in the 32-bit arena.
unsafe fn poke32(at: u32, value: u32) {
    // SAFETY: the caller guarantees the address.
    unsafe { core::ptr::write_unaligned(at as *mut u32, value) };
}
