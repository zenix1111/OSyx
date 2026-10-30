//! CPU exception delivery to ring 3. The kernel retains trusted selectors,
//! checks continuation pointers and MXCSR before IRET/XRSTOR, sanitizes the
//! user-supplied XSAVE header, and never accepts a return without a matching
//! outstanding fault in this thread.
use crate::{
    arch::{cpu, idt::TrapFrame},
    fixup, sched,
    sync::IrqSpinLock,
};
use alloc::collections::BTreeMap;
use core::arch::global_asm;
use osyx_abi::{
    fault::{self, Context},
    Errno,
};
struct Pending {
    frame: TrapFrame,
    mxcsr_mask: u32,
}
struct Registration {
    entry: u64,
    active: BTreeMap<u64, Pending>,
}
static REG: IrqSpinLock<BTreeMap<u64, Registration>> = IrqSpinLock::new(BTreeMap::new());

global_asm!(
    r#"
.section .text
.global osyx_fault_resume
osyx_fault_resume:
    cli
    push rdi
    push rsi
    sub rsp,8
    call osyx_kernel_leave
    add rsp,8
    pop rsi
    pop rdi
    mov rax, cr4
    test rax, 0x40000
    jz 1f
    xor ecx, ecx
    xgetbv
    xrstor64 [rsi]
    jmp 2f
1:  fxrstor64 [rsi]
2:
    mov rsp,rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp,16
    swapgs
    iretq
"#
);
extern "C" {
    fn osyx_fault_resume(frame: *const TrapFrame, fx: *const u8) -> !;
}

pub fn register(entry: u64) -> Result<u64, Errno> {
    if entry != 0 && !fixup::user_range_ok(entry, 1) {
        return Err(Errno::InvalidArgument);
    }
    let mut registry = REG.lock();
    registry.entry(sched::current_pid()).or_insert_with(|| Registration { entry: 0, active: BTreeMap::new() }).entry =
        entry;
    Ok(0)
}
pub fn clear_process(pid: u64) {
    REG.lock().remove(&pid);
}
pub fn clear_thread(pid: u64, tid: u64) {
    if let Some(r) = REG.lock().get_mut(&pid) {
        r.active.remove(&tid);
    }
}
fn from_frame(f: &TrapFrame) -> Context {
    Context {
        gpr: [
            f.rax, f.rbx, f.rcx, f.rdx, f.rsi, f.rdi, f.rbp, f.rsp, f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14,
            f.r15,
        ],
        rip: f.rip,
        rflags: f.rflags,
        vector: f.vector,
        error: f.error_code,
        address: if f.vector == 14 { cpu::read_cr2() } else { 0 },
        ..Context::default()
    }
}
pub fn deliver(f: &mut TrapFrame) -> bool {
    if ![0, 1, 3, 4, 5, 6, 13, 14, 16, 17, 19].contains(&f.vector) {
        return false;
    }
    let pid = sched::current_pid();
    let tid = sched::current_tid();
    let mut registry = REG.lock();
    let Some(r) = registry.get_mut(&pid) else { return false };
    if r.entry == 0 || r.active.contains_key(&tid) {
        return false;
    }
    let mut c = from_frame(f);
    // The soft-float kernel has not changed the user's x87/SSE/AVX registers.
    unsafe {
        cpu::fpu_save(c.fx.as_mut_ptr());
    }
    let mask = u32::from_le_bytes(c.fx[28..32].try_into().unwrap());
    let Some(addr) = f.rsp.checked_sub(128 + core::mem::size_of::<Context>() as u64).map(|n| n & !63) else {
        return false;
    };
    let Some(stack) = addr.checked_sub(8) else { return false };
    let bytes =
        unsafe { core::slice::from_raw_parts(&c as *const Context as *const u8, core::mem::size_of::<Context>()) };
    if fixup::copy_to_user(addr, bytes).is_err() || fixup::copy_to_user(stack, &0u64.to_le_bytes()).is_err() {
        return false;
    }
    r.active.insert(tid, Pending { frame: *f, mxcsr_mask: if mask == 0 { 0xffbf } else { mask } });
    f.rip = r.entry;
    f.rdi = addr;
    f.rsp = stack;
    f.rflags = (f.rflags & !((1 << 8) | (1 << 10) | (1 << 16))) | 0x202;
    true
}

/// The XSAVE header comes from user memory: keep only enabled state
/// components, force the standard (non-compacted) format and zero the
/// reserved bytes so XRSTOR cannot fault or read offsets under user control.
fn sanitize_xsave(fx: &mut [u8]) {
    let mask = cpu::fpu_mask();
    if mask == 0 || fx.len() < 576 {
        return;
    }
    let bv = u64::from_le_bytes(fx[512..520].try_into().unwrap()) & mask;
    fx[512..520].copy_from_slice(&bv.to_le_bytes());
    fx[520..576].fill(0);
}
pub fn resume(addr: u64) -> Result<u64, Errno> {
    let mut c = Context::default();
    let bytes =
        unsafe { core::slice::from_raw_parts_mut(&mut c as *mut Context as *mut u8, core::mem::size_of::<Context>()) };
    fixup::copy_from_user(bytes, addr)?;
    sanitize_xsave(&mut c.fx);
    if !fixup::user_range_ok(c.rip, 1) || !fixup::user_range_ok(c.gpr[fault::RSP], 1) {
        return Err(Errno::InvalidArgument);
    }
    let pid = sched::current_pid();
    let tid = sched::current_tid();
    let were_enabled = cpu::interrupts_enabled();
    cpu::disable_interrupts();
    let outcome = (|| {
        let mut registry = REG.lock();
        let r = registry.get_mut(&pid).ok_or(Errno::InvalidArgument)?;
        let pending = r.active.get(&tid).ok_or(Errno::InvalidArgument)?;
        let mxcsr = u32::from_le_bytes(c.fx[24..28].try_into().unwrap());
        if mxcsr & !pending.mxcsr_mask != 0 {
            return Err(Errno::InvalidArgument);
        }
        Ok(r.active.remove(&tid).unwrap().frame)
    })();
    let mut f = match outcome {
        Ok(f) => f,
        Err(e) => {
            if were_enabled {
                cpu::enable_interrupts();
            }
            return Err(e);
        }
    };
    if sched::current_kill_pending() {
        crate::process::finish_current_thread(0);
    }
    [f.rax, f.rbx, f.rcx, f.rdx, f.rsi, f.rdi, f.rbp, f.rsp, f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14, f.r15] =
        c.gpr;
    f.rip = c.rip;
    // Arithmetic/trace/direction/resume/alignment flags only. In particular
    // IF stays enabled, IOPL/NT/VM are never accepted from user memory.
    f.rflags = (c.rflags & 0x0005_0dd5) | 0x202;
    // Original ring-3 CS/SS are retained. This trusted frame and aligned
    // FXSAVE image live on this thread's kernel stack until IRET completes.
    unsafe {
        osyx_fault_resume(&f, c.fx.as_ptr());
    }
}
