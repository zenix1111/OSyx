//! Real CPU faults, register/SSE resumption and hostile return contexts.
use core::arch::{asm, global_asm};
use os_std::os::raw::{
    self as os_sys,
    fault::{self, Context},
    Errno,
};
use os_std::{
    prelude::*,
    process::Command,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
static CALLBACKS: AtomicU32 = AtomicU32::new(0);
static GOOD: AtomicU32 = AtomicU32::new(0);
static NESTED: AtomicBool = AtomicBool::new(false);
static AVX_FAULT: AtomicBool = AtomicBool::new(false);
static AVX_GOOD: AtomicBool = AtomicBool::new(false);
const AVX_PATTERN: [u64; 4] = [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00, 0x0f1e_2d3c_4b5a_6978, 0x8877_6655_4433_2211];
global_asm!(
    r#"
.section .text
.global osyx_fault_register_probe
osyx_fault_register_probe:
    mov rcx,0x11223344
    mov r11,0x55667788
    mov r9,0x12345678
    mov eax,0x55aa
    movq xmm7,rax
    ud2
    cmp rcx,0x11223344
    jne 2f
    cmp r11,0x55667788
    jne 2f
    cmp r9,0x12345678
    jne 2f
    movq rax,xmm7
    cmp rax,0x55aa
    jne 2f
    pushfq
    pop rax
    and eax,0x27000
    jne 2f
    mov eax,1
    ret
2:  xor eax,eax
    ret
.global osyx_fault_bad_stack_probe
osyx_fault_bad_stack_probe:
    mov rsp,0x10000
    ud2
.global osyx_fault_avx_probe
osyx_fault_avx_probe:
    vmovdqu ymm7, [rip+osyx_fault_avx_pattern]
    ud2
    vmovdqu ymm6, [rip+osyx_fault_avx_pattern]
    vpcmpeqb ymm6, ymm6, ymm7
    vpmovmskb eax, ymm6
    cmp eax, -1
    sete al
    movzx eax, al
    vzeroupper
    ret
.section .rodata
.balign 32
osyx_fault_avx_pattern:
    .quad 0x1122334455667788
    .quad 0x99aabbccddeeff00
    .quad 0x0f1e2d3c4b5a6978
    .quad 0x8877665544332211
"#
);
extern "C" {
    fn osyx_fault_register_probe() -> u64;
    fn osyx_fault_bad_stack_probe() -> !;
    fn osyx_fault_avx_probe() -> u64;
}
extern "C" fn entry(p: *mut Context) -> ! {
    if NESTED.load(Ordering::Relaxed) {
        unsafe {
            asm!("ud2", options(noreturn));
        }
    }
    let c = unsafe { &mut *p };
    let original = c.rip;
    let mxcsr = u32::from_le_bytes(c.fx[24..28].try_into().unwrap());
    let saved = c.vector == 6
        && c.gpr[fault::RCX] == 0x11223344
        && c.gpr[fault::R11] == 0x55667788
        && c.fx[272..280] == 0x55aau64.to_le_bytes();
    if AVX_FAULT.load(Ordering::Relaxed) {
        // YMM upper 128 bits of ymm7 live in XSAVE component 2 (offset 576 +
        // 16 * 7); the low half stays in the legacy region.
        let upper = c.vector == 6
            && c.fx[688..696] == AVX_PATTERN[2].to_le_bytes()
            && c.fx[696..704] == AVX_PATTERN[3].to_le_bytes();
        AVX_GOOD.store(upper, Ordering::SeqCst);
        // The handler's own AVX state must not leak into the resumed context.
        unsafe {
            asm!("vpxor ymm7, ymm7, ymm7", out("ymm7") _, options(nostack));
        }
    }
    c.rip = 0xffff800000000000;
    let bad_ip = unsafe { os_sys::fault_return(c) } == Err(Errno::InvalidArgument);
    c.rip = original;
    let original_stack = c.gpr[fault::RSP];
    c.gpr[fault::RSP] = 0xffff800000000000;
    let bad_stack = unsafe { os_sys::fault_return(c) } == Err(Errno::InvalidArgument);
    c.gpr[fault::RSP] = original_stack;
    c.fx[24..28].copy_from_slice(&(mxcsr | 0x80000000).to_le_bytes());
    let bad_mxcsr = unsafe { os_sys::fault_return(c) } == Err(Errno::InvalidArgument);
    c.fx[24..28].copy_from_slice(&mxcsr.to_le_bytes());
    CALLBACKS.fetch_add(1, Ordering::SeqCst);
    if saved && bad_ip && bad_stack && bad_mxcsr {
        GOOD.fetch_add(1, Ordering::SeqCst);
    }
    c.rip = original + 2;
    c.rflags |= 0x27000;
    // The restored XMM7 must come from the context, not this handler.
    unsafe {
        asm!("pxor xmm7,xmm7",out("xmm7") _,options(nostack));
    }
    let e = unsafe { os_sys::fault_return(c) };
    eprintln!("native fault return unexpectedly returned: {e:?}");
    os_std::process::exit(1)
}
pub fn helper(mode: &str) -> i32 {
    match mode {
        "fault-no-handler" => unsafe {
            asm!("ud2", options(noreturn));
        },
        "fault-exec-reset" => {
            if unsafe { os_sys::fault_handler(entry as *const () as u64) }.is_err() {
                return 1;
            }
            let e = Command::new("worker").arg("fault-no-handler").exec();
            eprintln!("fault exec: {e}");
            1
        }
        "fault-nested" | "fault-bad-stack" => {
            if unsafe { os_sys::fault_handler(entry as *const () as u64) }.is_err() {
                return 1;
            }
            if mode == "fault-bad-stack" {
                unsafe {
                    osyx_fault_bad_stack_probe();
                }
            }
            NESTED.store(true, Ordering::Relaxed);
            unsafe {
                asm!("ud2", options(noreturn));
            }
        }
        _ => 2,
    }
}
fn avx_enabled() -> bool {
    let ecx = core::arch::x86_64::__cpuid(1).ecx;
    ecx & (1 << 28) != 0 && ecx & (1 << 27) != 0
}
pub fn run() -> i32 {    let mut passed = 0;
    let mut failed = 0;
    let mut check = |name: &str, ok: bool| {
        println!("native fault: {name} ... {}", if ok { "ok" } else { "FAILED" });
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
    };
    check(
        "kernel callback address rejected",
        unsafe { os_sys::fault_handler(0xffff800000000000) } == Err(Errno::InvalidArgument),
    );
    let mut c = Context { rip: entry as *const () as u64, ..Context::default() };
    c.gpr[fault::RSP] = &c as *const _ as u64;
    check(
        "return without an outstanding fault rejected",
        unsafe { os_sys::fault_return(&c) } == Err(Errno::InvalidArgument),
    );
    check("register user CPU exception handler", unsafe { os_sys::fault_handler(entry as *const () as u64) }.is_ok());
    check("UD2 resumes with caller registers SSE and safe flags", unsafe { osyx_fault_register_probe() } == 1);
    if avx_enabled() {
        AVX_GOOD.store(false, Ordering::SeqCst);
        AVX_FAULT.store(true, Ordering::SeqCst);
        let restored = unsafe { osyx_fault_avx_probe() } == 1;
        AVX_FAULT.store(false, Ordering::SeqCst);
        check(
            "YMM upper halves survive exception delivery",
            restored && AVX_GOOD.load(Ordering::SeqCst),
        );
    } else {
        println!("native fault: YMM upper halves ... skipped (CPU has no AVX)");
    }
    let a = os_std::thread::spawn(|| unsafe { osyx_fault_register_probe() });
    let b = os_std::thread::spawn(|| unsafe { osyx_fault_register_probe() });
    check("independent threads resume their own contexts", a.join() == Ok(1) && b.join() == Ok(1));
    check(
        "all contexts rejected kernel RIP RSP and invalid MXCSR",
        CALLBACKS.load(Ordering::SeqCst) == 3 && GOOD.load(Ordering::SeqCst) == 3,
    );
    for mode in ["fault-no-handler", "fault-exec-reset", "fault-nested", "fault-bad-stack"] {
        let status = Command::new("worker").arg(mode).status().ok().and_then(|s| s.exception());
        check(mode, status == Some(6));
    }
    check("disable callback", unsafe { os_sys::fault_handler(0) }.is_ok());
    println!("native fault checks: {passed} passed, {failed} failed");
    failed
}
