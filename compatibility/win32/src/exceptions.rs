//! Vectored hardware exception callbacks over real resumable OSyx faults.
//! CONTEXT carries actual integer/control/x87/SSE state. Frame-based SEH,
//! debugger dispatch, nested hardware exceptions and AVX state are not yet
//! implemented; unhandled faults terminate rather than reporting success.
#![allow(non_snake_case)]
use crate::{error::*, kernel32::fail};
use alloc::{collections::BTreeMap, vec::Vec};
use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};
use os_std::sync::Mutex;
use osyx_abi::fault::{self, Context as NativeContext};
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub(crate) struct Context {
    home: [u64; 6],
    pub flags: u32,
    pub mxcsr: u32,
    segments: [u16; 6],
    pub eflags: u32,
    debug: [u64; 6],
    pub regs: [u64; 16],
    pub rip: u64,
    pub fx: [u8; 512],
    vectors: [u128; 26],
    vector_control: u64,
    debug_control: u64,
    last: [u64; 4],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Record {
    pub code: u32,
    pub flags: u32,
    pub nested: u64,
    pub address: u64,
    pub count: u32,
    pub reserved: u32,
    pub info: [u64; 15],
}
#[repr(C)]
struct Pointers {
    record: *mut Record,
    context: *mut Context,
}
const _: () = assert!(core::mem::size_of::<Context>() == 1232);
const _: () = assert!(core::mem::offset_of!(Context, regs) == 120);
const _: () = assert!(core::mem::offset_of!(Context, rip) == 248);
const _: () = assert!(core::mem::offset_of!(Context, fx) == 256);
const _: () = assert!(core::mem::size_of::<Record>() == 152);
const REGISTER_MAP: [usize; 16] = [
    fault::RAX,
    fault::RCX,
    fault::RDX,
    fault::RBX,
    fault::RSP,
    fault::RBP,
    fault::RSI,
    fault::RDI,
    fault::R8,
    fault::R9,
    fault::R10,
    fault::R11,
    fault::R12,
    fault::R13,
    fault::R14,
    fault::R15,
];
#[derive(Clone, Copy)]
struct Handler {
    id: u64,
    callback: u64,
    continuation: bool,
}
static HANDLERS: Mutex<Vec<Handler>> = Mutex::new(Vec::new());
static NEXT: AtomicU64 = AtomicU64::new(0x1000);
static FILTER: AtomicU64 = AtomicU64::new(0);
struct Software {
    record: Record,
    context: NativeContext,
}
static SOFTWARE: Mutex<BTreeMap<u64, Software>> = Mutex::new(BTreeMap::new());
global_asm!(
    r#"
.section .text
.global osyx_windows_raise_entry
osyx_windows_raise_entry:
    pushfq
    // 32 bytes of scratch below the Context, the 1024-byte Context itself
    // (osyx_windows_raise_captured copies all of it), 16-byte aligned.
    sub rsp,1088
    mov [rsp+32],rax
    mov [rsp+40],rbx
    mov [rsp+48],rcx
    mov [rsp+56],rdx
    mov [rsp+64],rsi
    mov [rsp+72],rdi
    mov [rsp+80],rbp
    mov [rsp+96],r8
    mov [rsp+104],r9
    mov [rsp+112],r10
    mov [rsp+120],r11
    mov [rsp+128],r12
    mov [rsp+136],r13
    mov [rsp+144],r14
    mov [rsp+152],r15
    lea rax,[rsp+1104]
    mov [rsp+88],rax
    mov rax,[rsp+1096]
    mov [rsp+160],rax
    mov rax,[rsp+1088]
    mov [rsp+168],rax
    // Exception selectors, x87/SSE/AVX state: clear the tail of the Context,
    // then overlay FXSAVE at fx (Context+192). XSTATE_BV stays 0, so XRSTOR
    // restores only the legacy components.
    cld
    lea rdi,[rsp+176]
    xor eax,eax
    mov ecx,110
    rep stosq
    fxsave64 [rsp+224]
    lea rcx,[rsp+32]
    call osyx_windows_raise_captured
    ud2
.global osyx_windows_raise_trap
osyx_windows_raise_trap:
    ud2
    ret
"#
);
extern "C" {
    fn osyx_windows_raise_trap();
}
extern "win64" {
    #[link_name = "osyx_windows_raise_entry"]
    pub(crate) fn RaiseException(code: u32, flags: u32, count: u32, args: *const u64);
}
/// Faults of Windows code always go through entry: frame-based handlers
/// (seh.rs) need no registration. Without kernel support, faults keep
/// terminating the process as before.
pub fn install() {
    // SAFETY: entry is a valid fault callback for the whole process.
    let _ = unsafe { os_sys::fault_handler(entry as *const () as u64) };
}
pub fn set_filter(callback: u64) -> u64 {
    let _handlers = HANDLERS.lock().unwrap();
    if let Err(e) = unsafe { os_sys::fault_handler(entry as *const () as u64) } {
        return fail(errno_to_win32(e), 0);
    }
    FILTER.swap(callback, Ordering::SeqCst)
}
#[no_mangle]
extern "win64" fn osyx_windows_raise_captured(captured: *const NativeContext) -> ! {
    let context = unsafe { *captured };
    let code = context.gpr[fault::RCX] as u32;
    let flags = context.gpr[fault::RDX] as u32;
    let count = context.gpr[fault::R8] as u32;
    let args = context.gpr[fault::R9] as *const u64;
    if count > 15 || count != 0 && args.is_null() {
        os_std::process::exit(0xc000000du32 as i32);
    }
    {
        let _handlers = HANDLERS.lock().unwrap();
        if unsafe { os_sys::fault_handler(entry as *const () as u64) }.is_err() {
            os_std::process::exit(code as i32);
        }
    }
    let mut r = Record {
        code: code & !0x10000000,
        flags: flags & 1,
        nested: 0,
        address: context.rip,
        count,
        reserved: 0,
        info: [0; 15],
    };
    for i in 0..count as usize {
        r.info[i] = unsafe { *args.add(i) };
    }
    let tid = os_sys::gettid();
    SOFTWARE.lock().unwrap().insert(tid, Software { record: r, context });
    // Use the real native trap delivery/return path, with registers/FPU
    // captured at the Windows entry thunk. Continuation skips these helper
    // frames and resumes the PE caller's actual return address and stack.
    unsafe {
        osyx_windows_raise_trap();
    }
    os_std::process::exit(0xc000000du32 as i32)
}
fn add(first: u32, callback: u64, continuation: bool) -> u64 {
    if callback == 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut handlers = HANDLERS.lock().unwrap();
    // Registration succeeds only when the kernel can deliver real faults.
    if let Err(e) = unsafe { os_sys::fault_handler(entry as *const () as u64) } {
        return fail(errno_to_win32(e), 0);
    }
    let h = Handler { id: NEXT.fetch_add(16, Ordering::Relaxed), callback, continuation };
    if first != 0 {
        handlers.insert(0, h);
    } else {
        handlers.push(h);
    }
    h.id
}
fn remove(id: u64, continuation: bool) -> u32 {
    let mut handlers = HANDLERS.lock().unwrap();
    let Some(at) = handlers.iter().position(|h| h.id == id && h.continuation == continuation) else { return 0 };
    handlers.remove(at);
    1
}
extern "win64" fn AddVectoredExceptionHandler(first: u32, callback: u64) -> u64 {
    add(first, callback, false)
}
extern "win64" fn RemoveVectoredExceptionHandler(id: u64) -> u32 {
    remove(id, false)
}
extern "win64" fn AddVectoredContinueHandler(first: u32, callback: u64) -> u64 {
    add(first, callback, true)
}
extern "win64" fn RemoveVectoredContinueHandler(id: u64) -> u32 {
    remove(id, true)
}
fn windows_context(n: &NativeContext) -> Context {
    let mut fx = [0u8; 512];
    fx.copy_from_slice(&n.fx[..512]);
    let mut c = Context {
        home: [0; 6],
        flags: 0x0010_000b,
        mxcsr: u32::from_le_bytes(n.fx[24..28].try_into().unwrap()),
        segments: [0x23, 0x1b, 0x1b, 0, 0, 0x1b],
        eflags: n.rflags as u32,
        debug: [0; 6],
        regs: [0; 16],
        rip: if n.vector == 3 { n.rip.saturating_sub(1) } else { n.rip },
        fx,
        vectors: [0; 26],
        vector_control: 0,
        debug_control: 0,
        last: [0; 4],
    };
    for (i, &index) in REGISTER_MAP.iter().enumerate() {
        c.regs[i] = n.gpr[index];
    }
    c
}
fn record(n: &NativeContext) -> Record {
    let code = match n.vector {
        0 => 0xc0000094,
        1 => 0x80000004,
        3 => 0x80000003,
        4 => 0xc0000095,
        5 => 0xc000008c,
        6 => 0xc000001d,
        13 | 14 => 0xc0000005,
        16 | 19 => 0xc0000090,
        17 => 0x80000002,
        _ => 0xc0000001,
    };
    let mut r = Record {
        code,
        flags: 0,
        nested: 0,
        address: if n.vector == 3 { n.rip.saturating_sub(1) } else { n.rip },
        count: 0,
        reserved: 0,
        info: [0; 15],
    };
    if n.vector == 13 || n.vector == 14 {
        r.count = 2;
        r.info[0] = if n.error & 16 != 0 {
            8
        } else if n.error & 2 != 0 {
            1
        } else {
            0
        };
        r.info[1] = n.address;
    }
    r
}
fn call(h: Handler, p: &mut Pointers) -> i32 {
    let callback: extern "win64" fn(*mut Pointers) -> i32 = unsafe { core::mem::transmute(h.callback) };
    callback(p)
}
fn apply(c: &Context, n: &mut NativeContext) {
    if c.flags & 1 != 0 {
        n.rip = c.rip;
        n.rflags = c.eflags as u64;
        n.gpr[fault::RSP] = c.regs[4];
    }
    if c.flags & 2 != 0 {
        for (i, &index) in REGISTER_MAP.iter().enumerate() {
            if index != fault::RSP {
                n.gpr[index] = c.regs[i];
            }
        }
    }
    if c.flags & 8 != 0 {
        let old_mxcsr = u32::from_le_bytes(n.fx[24..28].try_into().unwrap());
        n.fx[..512].copy_from_slice(&c.fx);
        if c.mxcsr != old_mxcsr {
            n.fx[24..28].copy_from_slice(&c.mxcsr.to_le_bytes());
        }
    }
}
/// Readable bytes at `addr`, at most `max`, if the memory is committed.
fn readable(addr: u64, max: usize) -> Option<&'static [u8]> {
    let info = crate::mem::virtual_query(addr)?;
    if info.state != crate::mem::MEM_COMMIT || info.protect == 0 || info.protect == 1 {
        return None;
    }
    let len = ((info.base + info.size - addr) as usize).min(max);
    // SAFETY: committed, accessible memory of at least `len` bytes.
    Some(unsafe { core::slice::from_raw_parts(addr as *const u8, len) })
}

/// After a Rust panic in a Windows program, the stack still holds pointers
/// to `core::panic::Location` values (file name, line, column). Prints the
/// ones found in the top of the stack, which name the panicking source line.
fn print_rust_locations(rsp: u64) {
    let Some(stack) = readable(rsp, 16 << 10) else { return };
    let mut shown = 0;
    let (words, _) = stack.as_chunks::<8>();
    for word in words {
        let p = u64::from_le_bytes(*word);
        let Some(loc) = readable(p, 24).filter(|l| l.len() == 24) else { continue };
        let file = u64::from_le_bytes(loc[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(loc[8..16].try_into().unwrap()) as usize;
        let line = u32::from_le_bytes(loc[16..20].try_into().unwrap());
        if !(4..300).contains(&len) {
            continue;
        }
        let Some(name) = readable(file, len).filter(|n| n.len() == len) else { continue };
        if name.ends_with(b".rs") && name.iter().all(|&b| (0x20..0x7f).contains(&b)) {
            os_std::eprintln!("winrun: ... rust location {}:{line}", core::str::from_utf8(name).unwrap_or(""));
            shown += 1;
            if shown == 6 {
                break;
            }
        }
    }
}

/// Every register of `c` into the native frame (RtlRestoreContext).
pub(crate) fn apply_all(c: &Context, n: &mut NativeContext) {
    let mut full = *c;
    full.flags |= 0xb;
    apply(&full, n);
}
extern "C" fn entry(native: *mut NativeContext) -> ! {
    let n = unsafe { &mut *native };
    if crate::mem::jit_fault(n) {
        // SAFETY: retry the original instruction with the kernel's
        // unchanged context after changing only its page permissions.
        let _ = unsafe { os_sys::fault_return(n) };
    }
    let mut context = windows_context(n);
    let mut record = record(n);
    let software = n.vector == 6 && n.rip == osyx_windows_raise_trap as *const () as u64;
    if software {
        if let Some(s) = SOFTWARE.lock().unwrap().remove(&os_sys::gettid()) {
            *n = s.context;
            record = s.record;
            context = windows_context(n);
        }
    }
    static REPORTS: Mutex<Vec<alloc::string::String>> = Mutex::new(Vec::new());
    let delay = delay_load_failure(&record); let verbose = crate::VERBOSE.load(Ordering::Relaxed); if delay.is_some() || verbose {
        let _ = &delay;
        let key = delay.clone().unwrap_or_else(|| alloc::format!("{:x}:{:x}", record.code, record.address));
        let report = {
            let mut seen = REPORTS.lock().unwrap();
            if seen.len() >= 32 || seen.contains(&key) { false } else { seen.push(key); true }
        };
        if report {
            if verbose { os_std::eprintln!("winrun: dispatching Windows exception {:#x} at {} in thread {}, info {:x?}", record.code, where_text(record.address), os_sys::gettid(), &record.info[..record.count.min(15) as usize]); }
            if let Some(what) = delay { os_std::eprintln!("winrun: delay-load exception: {what}"); }
        }
    }
    // Unwinding during this dispatch (RtlUnwindEx) starts at this context
    // and ends the kernel delivery through `native`.
    crate::seh::begin(native, &context);
    let mut p = Pointers { record: &mut record, context: &mut context };
    let handlers = HANDLERS.lock().unwrap().clone();
    let mut handled = handlers.iter().filter(|h| !h.continuation).any(|h| call(*h, &mut p) == -1);
    if !handled {
        // SAFETY: `p` points at this frame's record and context.
        handled = unsafe { crate::seh::dispatch(&mut *p.record, &mut *p.context) };
    }
    if !handled {
        let callback = FILTER.load(Ordering::SeqCst);
        if callback != 0 {
            handled = call(Handler { id: 0, callback, continuation: false }, &mut p) == -1;
        }
    }
    if handled {
        for h in handlers.iter().filter(|h| h.continuation) {
            if call(*h, &mut p) == -1 {
                break;
            }
        }
    }
    // fault_return never returns on success: explicitly release this heap
    // snapshot before abandoning the dispatcher's Rust stack frames.
    drop(handlers);
    crate::seh::end();
    if handled {
        if record.flags & 1 != 0 {
            os_std::process::exit(0xc0000025u32 as i32);
        }
        apply(&context, n);
        let error = unsafe { os_sys::fault_return(n) };
        os_std::eprintln!("winrun: exception continuation rejected: {error:?}");
        os_std::process::exit(0xc000000du32 as i32);
    }
    os_std::eprintln!(
        "winrun: unhandled Windows exception {:#x} at {:#x} ({}) in thread {}",
        record.code,
        record.address,
        where_text(record.address),
        os_sys::gettid()
    );
    crate::kernel32::print_failures();
    if record.code == 0x8000_0003 {
        // MOZ_CRASH-style helpers pass the reason text in R8 before int3.
        let r8 = context.regs[8];
        if let Some(info) = crate::mem::virtual_query(r8).filter(|i| i.state == crate::mem::MEM_COMMIT && i.protect != 0 && i.protect != 1) {
            let len = ((info.base + info.size - r8) as usize).min(256);
            // SAFETY: committed, accessible memory of at least `len` bytes.
            let bytes = unsafe { core::slice::from_raw_parts(r8 as *const u8, len) };
            let text = bytes.split(|&b| b == 0).next().unwrap_or(&[]);
            if !text.is_empty() && text.iter().all(|&b| (0x20..0x7f).contains(&b)) {
                os_std::eprintln!("winrun: ... reason in r8: {}", core::str::from_utf8(text).unwrap_or(""));
            }
        }
        print_rust_locations(context.regs[4]);
    }
    if record.code == 0xc000_0005 && record.count >= 2 {
        // EXCEPTION_ACCESS_VIOLATION: [0] read/write/execute, [1] the address.
        let kind = match record.info[0] {
            0 => "reading",
            1 => "writing",
            _ => "executing",
        };
        let t = crate::teb::current();
        // SAFETY: this thread's TEB.
        let (base, limit): (u64, u64) = unsafe { (crate::teb::get(t, crate::teb::TEB_STACK_BASE), crate::teb::get(t, crate::teb::TEB_STACK_LIMIT)) };
        os_std::eprintln!("winrun: ... {kind} {:#x} (stack {limit:#x}..{base:#x})", record.info[1]);
        if record.info[1] < limit && record.info[1] + 0x10000 >= limit {
            report_overflow(limit, base, n.gpr[fault::RSP], n.gpr[fault::RBP]);
        } else {
            trace(limit, base, n.gpr[fault::RSP]);
        }
    }
    if let Some(what) = delay_load_failure(&record) {
        os_std::eprintln!("winrun: delay load failed: {what}");
    }
    os_std::process::exit(record.code as i32)
}

/// `module+offset` for a code address, for crash reports.
fn where_text(addr: u64) -> alloc::string::String {
    match crate::loader::where_is(addr) {
        Some((module, offset)) => alloc::format!("{module}+{offset:#x}"),
        None => alloc::string::String::from("no module"),
    }
}

/// A poor man's backtrace for a fault that is not a stack overflow: the code
/// addresses on the stack above the faulting stack pointer, in the order they
/// appear (the innermost return addresses first). Unwinding the real frames
/// would be better, but this says which module failed without it.
pub(crate) fn trace_current() {
    let teb = crate::teb::current();
    if teb == 0 { return; }
    let (limit, base) = unsafe { (crate::teb::get::<u64>(teb, crate::teb::TEB_STACK_LIMIT), crate::teb::get::<u64>(teb, crate::teb::TEB_STACK_BASE)) };
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)); }
    trace(limit, base, rsp);
}

fn trace(limit: u64, base: u64, rsp: u64) {
    let start = rsp.max(limit).min(base);
    let end = start.saturating_add(16 << 10).min(base);
    let mut found: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    let mut at = start;
    while at + 8 <= end && found.len() < 12 {
        // SAFETY: inside this thread's stack, between its limit and base.
        let v: u64 = unsafe { core::ptr::read_volatile(at as *const u64) };
        if let Some((module, offset)) = crate::loader::where_is(v).filter(|_| crate::loader::is_executable(v)) {
            let entry = alloc::format!("{module}+{offset:#x}");
            if found.last() != Some(&entry) {
                found.push(entry);
            }
        }
        at += 8;
    }
    if found.is_empty() {
        return;
    }
    os_std::eprintln!("winrun: call chain guesses (innermost first): {}", found.join(", "));
}

/// A stack overflow: the code addresses found in the used part of the
/// thread's stack, most frequent first, as module+offset (a recursion shows
/// as a few addresses repeated many times; one huge frame shows a short
/// list).
///
/// Two windows are read, because they answer different questions: the
/// bottom one shows where the stack died, the top one shows the call chain
/// that got there when the stack pointer was moved rather than walked down.
/// Only addresses inside `[limit, base)` are read — anything outside may be
/// unmapped and a second fault here would lose the report.
fn report_overflow(limit: u64, base: u64, rsp: u64, rbp: u64) {
    let where_rsp = match rsp {
        r if r < limit => alloc::format!("{:#x} ({:#x} BELOW the stack limit)", r, limit - r),
        r if r >= base => alloc::format!("{r:#x} (ABOVE the stack base)"),
        r => alloc::format!("{r:#x} ({:#x} above the limit)", r - limit),
    };
    os_std::eprintln!("winrun: stack overflow: rsp {where_rsp}, rbp {rbp:#x}, limit {limit:#x}, base {base:#x}");
    for (what, start, end) in [
        ("bottom", limit, limit.saturating_add(0x4000).min(base)),
        ("top", base.saturating_sub(0x10000).max(limit), base),
    ] {
        let mut seen: alloc::collections::BTreeMap<u64, u32> = alloc::collections::BTreeMap::new();
        let (mut words, mut zero) = (0u32, 0u32);
        let mut at = start;
        while at + 8 <= end {
            // SAFETY: inside this thread's stack, between its limit and base.
            let v: u64 = unsafe { core::ptr::read_volatile(at as *const u64) };
            words += 1;
            if v == 0 {
                zero += 1;
            } else if crate::loader::where_is(v).is_some() {
                *seen.entry(v).or_default() += 1;
            }
            at += 8;
        }
        os_std::eprintln!(
            "winrun: {what} {start:#x}..{end:#x}: {words} words, {zero} zero, code addresses most frequent first:"
        );
        let mut top: alloc::vec::Vec<(u64, u32)> = seen.into_iter().collect();
        top.sort_by_key(|&(_, n)| core::cmp::Reverse(n));
        if top.is_empty() {
            os_std::eprintln!("winrun:   none: no word points into a loaded module");
        }
        for (pc, n) in top.into_iter().take(12) {
            os_std::eprintln!("winrun:   {n:4} x {}", where_text(pc));
        }
    }
}

/// The DLL and function of a failed delay load (VcppException codes
/// 0xC06D007E module / 0xC06D007F procedure not found), from the
/// DelayLoadInfo the delay-load helper raises with.
fn delay_load_failure(r: &Record) -> Option<alloc::string::String> {
    if !matches!(r.code, 0xc06d_007e | 0xc06d_007f) || r.count < 1 {
        return None;
    }
    // SAFETY (both closures): every address is probed readable first.
    let read = |a: u64| (a != 0 && !crate::sysext::is_bad_read(a, 8)).then(|| unsafe { core::ptr::read_unaligned(a as *const u64) });
    let text = |p: u64| -> Option<alloc::string::String> {
        let mut s = alloc::string::String::new();
        for i in 0..260 {
            let b = (!crate::sysext::is_bad_read(p + i, 1)).then(|| unsafe { *((p + i) as *const u8) })?;
            if b == 0 {
                return Some(s);
            }
            s.push(b as char);
        }
        Some(s)
    };
    // DelayLoadInfo: cb, pidd, ppfn, szDll, dlp { fImportByName, name/ordinal }.
    let info = r.info[0];
    let dll = text(read(info + 24)?)?;
    let by_name = read(info + 32)? as u32 != 0;
    let name = read(info + 40)?;
    Some(if by_name { alloc::format!("{dll}!{}", text(name)?) } else { alloc::format!("{dll}!#{}", name as u32) })
}
pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        AddVectoredExceptionHandler,
        RemoveVectoredExceptionHandler,
        AddVectoredContinueHandler,
        RemoveVectoredContinueHandler
    ]
}
pub fn native_exports() -> Vec<(&'static str, u64)> {
    alloc::vec![
        ("RtlAddVectoredExceptionHandler", AddVectoredExceptionHandler as *const () as u64),
        ("RtlRemoveVectoredExceptionHandler", RemoveVectoredExceptionHandler as *const () as u64),
        ("RtlAddVectoredContinueHandler", AddVectoredContinueHandler as *const () as u64),
        ("RtlRemoveVectoredContinueHandler", RemoveVectoredContinueHandler as *const () as u64)
    ]
}
