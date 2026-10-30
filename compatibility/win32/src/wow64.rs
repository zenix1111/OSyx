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

use crate::mem::{self, Prot, PAGE};
use alloc::vec::Vec;
use core::arch::global_asm;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
use osyx_abi::wow64::{ENTRY_RFLAGS, USER_CS, USER_CS32, USER_DS};

// The ABI constants and the literals in the assembly below must not drift.
const _: () = assert!(USER_CS == 0x23 && USER_CS32 == 0x3B && USER_DS == 0x1B && ENTRY_RFLAGS == 0x202);

const ARENA_BASE: u32 = 0x2000_0000;
const ARENA_SIZE: usize = 4 << 20; // stubs, TEB, PEB, guard and a 1 MiB stack
const STUB_PAGE: u32 = ARENA_BASE;
const STUB_SIZE: u32 = 12;
/// Stubs that fit in one page (SteamSetup needs 166 imports).
const MAX_IMPORTS: usize = PAGE / STUB_SIZE as usize;
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
    /// HANDLE: `0xFFFF_FFFF` is `INVALID_HANDLE_VALUE` in 64 bits.
    Handle,
    /// 64-bit value: join this slot (low) and the next (high).
    U64,
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

/// The signatures the bridge knows. A symbol that is absent fails at load
/// time (`import` returns `None`), never at run time.
static SIGNATURES: &[Signature] = &[
    Signature { name: "GetStdHandle", args: &[ArgKind::Uint], ret: RetKind::Handle, is_cdecl: false },
    Signature {
        name: "WriteFile",
        args: &[ArgKind::Handle, ArgKind::Ptr, ArgKind::Uint, ArgKind::Ptr, ArgKind::Ptr],
        ret: RetKind::I32,
        is_cdecl: false,
    },
    Signature { name: "ExitProcess", args: &[ArgKind::Uint], ret: RetKind::Void, is_cdecl: false },
];

/// One bound import, indexed by the stub's `mov eax, index`.
struct Entry {
    host: u64,
    args: &'static [ArgKind],
    ret: RetKind,
    is_cdecl: bool,
}

/// The bridge whose stubs are live; set once, just before `iretq`.
static ACTIVE: AtomicPtr<Bridge> = AtomicPtr::new(core::ptr::null_mut());

/// Where the gate was entered from: the 32-bit RSP with the return address
/// on top. Written and read by the gate; dispatch does not touch it.
static SAVED_RSP: AtomicU64 = AtomicU64::new(0);
/// Stack bytes the gate must remove before returning (stdcall arguments).
static RESULT_CLEANUP: AtomicU32 = AtomicU32::new(0);
/// High 32 bits of an I64 result, for EDX.
static RESULT_HIGH: AtomicU32 = AtomicU32::new(0);

/// The dedicated 64-bit stack the gate switches to. It must be writable
/// and is never used by Rust; the gate resets RSP to its top on each call.
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
    mov [rip + {saved_rsp}], rsp
    mov ecx, eax                    // idx (Win64 argument 1)
    lea rdx, [rsp + 4]              // first 32-bit stack argument
    lea rsp, [rip + {bridge_stack}]
    add rsp, {stack_size}
    and rsp, -16
    sub rsp, 32                     // Win64 shadow space
    call {dispatch}
    // dispatch returned with EAX = low result; it stored EDX and the
    // stdcall cleanup in memory. An IRET from 64-bit mode into a
    // compatibility segment reloads SS:RSP from the frame even at the same
    // privilege, so the frame has five slots and RSP is the value the
    // caller resumes with.
    mov edx, [rip + {result_high}]
    mov ecx, [rip + {saved_rsp}]
    mov r8d, [rip + {result_cleanup}]
    lea rcx, [rcx + r8 + 4]         // past the return address and arguments
    mov r9, [rip + {saved_rsp}]
    mov r9d, [r9]                   // RIP: the return address on the 32-bit stack
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
    saved_rsp = sym SAVED_RSP,
    bridge_stack = sym BRIDGE_STACK,
    stack_size = const BRIDGE_STACK_SIZE,
    dispatch = sym bridge_dispatch,
    result_high = sym RESULT_HIGH,
    result_cleanup = sym RESULT_CLEANUP,
);

extern "C" {
    /// The 64-bit gate reached by a far jump from every 32-bit stub.
    fn osyx_wow64_gate();
    /// Builds an IRETQ frame to compatibility mode and never returns.
    fn osyx_wow64_enter32(entry: u32, stack_top: u32) -> !;
    /// Calls a dynamic Win64 function with `n` already-widened arguments.
    fn osyx_win64_invoke(host: u64, args: *const u64, n: u32) -> u64;
}

/// The 32-bit arena and the import dispatcher for one process.
pub struct Bridge {
    /// Physical (32-bit) address of the TEB, also the FS32 base.
    teb: u32,
    /// Initial 32-bit stack pointer.
    stack_top: u32,
    entries: Vec<Entry>,
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

        // OSyx cannot map a page with no access; a read-only page is the
        // guard: a stack overflow writing into it faults.
        mem::protect(GUARD32 as u64, PAGE, Prot::ReadOnly)
            .map_err(|_| "wow64: cannot make the 32-bit stack guard page read-only")?;

        Ok(Bridge { teb: TEB32, stack_top: STACK_TOP, entries: Vec::new() })
    }

    /// `(limit, base)` of the 32-bit stack: the lowest valid address and the
    /// initial (highest) one, as Windows TEBs record them.
    pub fn stack(&self) -> (u64, u64) {
        (STACK_BASE as u64, STACK_TOP as u64)
    }

    /// Returns the 32-bit address of a stub for `symbol`, whose 64-bit
    /// implementation is at `host`, or `None` when no signature is known.
    pub fn import(&mut self, symbol: &str, host: u64) -> Option<u32> {
        let signature = SIGNATURES.iter().find(|s| s.name == symbol)?;
        assert!(signature.args.len() <= MAX_ARG_SLOTS, "wow64: import signature has too many arguments");
        assert!(self.entries.len() < MAX_IMPORTS, "wow64: too many imports for the stub page");
        let gate = osyx_wow64_gate as *const () as usize;
        assert!(gate != 0 && gate < 1usize << 32, "wow64: gate is not below 4 GiB");

        let index = self.entries.len() as u32;
        let stub = STUB_PAGE + index * STUB_SIZE;
        assert!(stub + STUB_SIZE <= STUB_PAGE + PAGE as u32, "wow64: import stubs overflow their page");

        // mov eax, index; jmp far USER_CS:gate
        // SAFETY: the stub page is writable until `enter` protects it, and
        // 64 stubs of 12 bytes fit well inside the page.
        unsafe {
            let p = stub as *mut u8;
            *p = 0xB8;
            core::ptr::write_unaligned(p.add(1).cast::<u32>(), index);
            *p.add(5) = 0xEA;
            core::ptr::write_unaligned(p.add(6).cast::<u32>(), gate as u32);
            core::ptr::write_unaligned(p.add(10).cast::<u16>(), USER_CS);
        }
        self.entries.push(Entry {
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

    /// Enters `entry` in compatibility mode. Never returns normally.
    pub fn enter(&mut self, entry: u32) -> ! {
        if let Err(e) = mem::protect(STUB_PAGE as u64, PAGE, Prot::ExecuteRead) {
            os_std::eprintln!("winrun: wow64: cannot make import stubs executable: {e:?}");
            os_std::process::exit(126);
        }
        ACTIVE.store(self as *mut Bridge, Ordering::Relaxed);
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
    // stubs; it lives until the 32-bit program ends.
    let bridge = unsafe { &*bridge };
    let teb = bridge.teb;

    // Rust (os_std) uses FS for TLS: restore the 64-bit base before any
    // implementation or allocator code runs.
    let _ = os_sys::set_fs32_base(0);
    let (low, high, cleanup) = dispatch(bridge, index, args);
    // Back to the mode the 32-bit caller is in (and to its stack, via the
    // IRETQ frame the gate builds).
    let _ = os_sys::set_fs32_base(teb as usize);

    RESULT_CLEANUP.store(cleanup, Ordering::Relaxed);
    RESULT_HIGH.store(high, Ordering::Relaxed);
    low
}

fn dispatch(bridge: &Bridge, index: u32, args: *const u32) -> (u64, u32, u32) {
    let Some(entry) = bridge.entries.get(index as usize) else {
        os_std::eprintln!("winrun: wow64: bad import index {index}");
        os_std::process::exit(0xC000_0005u32 as i32);
    };

    let mut values = [0u64; MAX_ARG_SLOTS];
    let mut guest_slot = 0usize;
    let mut out = 0usize;
    for &kind in entry.args {
        // SAFETY: the signature says these 4-byte slots are on the 32-bit
        // stack at `args`; the guest owns that stack.
        let word = |at: usize| unsafe { core::ptr::read_unaligned(args.add(at)) };
        values[out] = match kind {
            ArgKind::Ptr | ArgKind::Uint => word(guest_slot) as u64,
            ArgKind::Int => (word(guest_slot) as i32) as i64 as u64,
            ArgKind::Handle => match word(guest_slot) {
                0xFFFF_FFFF => u64::MAX,
                value => value as u64,
            },
            ArgKind::U64 => {
                let low = word(guest_slot) as u64;
                let high = word(guest_slot + 1) as u64;
                low | high << 32
            }
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
    let high = match entry.ret {
        RetKind::I64 => (result >> 32) as u32,
        _ => 0,
    };
    (result, high, cleanup)
}

/// Writes a 32-bit field of the fresh TEB.
///
/// # Safety
/// `at` must point at writable memory in the 32-bit arena.
unsafe fn poke32(at: u32, value: u32) {
    // SAFETY: the caller guarantees the address.
    unsafe { core::ptr::write_unaligned(at as *mut u32, value) };
}
