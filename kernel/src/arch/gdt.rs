//! Global Descriptor Table and Task State Segment.
//!
//! Selector layout is chosen for SYSCALL/SYSRET (STAR): kernel CS 0x08, SS
//! 0x10; user SS 0x18|3, CS 0x20|3. The TSS provides dedicated IST stacks for
//! exceptions that may arrive on a corrupted stack (#DF, NMI, #MC).
//!
//! Two slots after the TSS serve 32-bit compatibility-mode code: index 7 is
//! a ring-3 D=1/L=0 code segment and index 8 a ring-3 data segment whose base
//! is the per-thread 32-bit TEB (compatibility mode takes the FS base from
//! the descriptor, not from `IA32_FS_BASE`). Both descriptors sit above every
//! selector STAR/SYSRET derive, so the 64-bit path is unchanged.

use core::arch::asm;
use core::mem::size_of;
use core::ptr::addr_of;
use osyx_abi::wow64;

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16 = 0x18 | 3;
pub const USER_CS: u16 = 0x20 | 3;
pub const TSS_SEL: u16 = 0x28;
/// Ring-3 compatibility-mode code segment (index 7), also in [`wow64`].
pub const USER_CS32: u16 = wow64::USER_CS32;
/// Ring-3 data segment for the 32-bit FS base (index 8), also in [`wow64`].
pub const USER_FS32: u16 = wow64::USER_FS32;

// SYSRET loads SS = STAR[63:48] + 8 and CS = STAR[63:48] + 16 (RPL forced to
// 3), so the user data descriptor must directly precede user code. The
// compatibility entries live above the TSS (0x28, two slots: 0x38) and must
// not renumber anything STAR derives.
const _: () = assert!(
    USER_DS + 8 == USER_CS
        && KERNEL_DS == KERNEL_CS + 8
        && USER_CS32 == wow64::USER_CS32
        && USER_FS32 == wow64::USER_FS32
        && USER_CS32 & !3 == TSS_SEL + 16
        && USER_FS32 & !3 == TSS_SEL + 24
);

pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;

const IST_STACK_SIZE: usize = 16 * 1024;

#[repr(C, packed(4))]
struct Tss {
    _reserved0: u32,
    rsp: [u64; 3],
    _reserved1: u64,
    ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    iomap_base: u16,
}

#[repr(C, align(16))]
struct Stack([u8; IST_STACK_SIZE]);

/// GDT slots: null, kernel CS/SS, user SS/CS, TSS (two), 32-bit CS and FS.
const GDT_ENTRIES: usize = 9;
/// Index of the 32-bit FS data descriptor whose base follows the thread.
const FS32_INDEX: usize = 8;

struct CpuTables {
    stacks: [Stack; 3],
    tss: Tss,
    gdt: [u64; GDT_ENTRIES],
}
impl CpuTables {
    const fn new() -> Self {
        Self {
            stacks: [const { Stack([0; IST_STACK_SIZE]) }; 3],
            tss: Tss { _reserved0: 0, rsp: [0;3], _reserved1: 0, ist: [0;7], _reserved2: 0, _reserved3: 0, iomap_base: size_of::<Tss>() as u16 },
            gdt: [
                0,                              // 0x00 null
                0x00AF_9A00_0000_FFFF,          // 0x08 KERNEL_CS
                0x00CF_9200_0000_FFFF,          // 0x10 KERNEL_DS
                0x00CF_F200_0000_FFFF,          // 0x18 USER_DS
                0x00AF_FA00_0000_FFFF,          // 0x20 USER_CS (L=1)
                0, 0,                           // 0x28 TSS (low, high), filled in init_cpu
                wow64::code32_descriptor(),     // 0x38 USER_CS32 (D=1, L=0)
                wow64::data32_descriptor(0),    // 0x40 USER_FS32, base per thread
            ],
        }
    }
}
static mut TABLES: [CpuTables;crate::smp::MAX_CPUS] = [const { CpuTables::new() };crate::smp::MAX_CPUS];

/// Sets the stack the CPU switches to when an interrupt or exception arrives
/// while running in ring 3 (TSS.RSP0).
///
/// # Safety
/// `top` must be the 16-byte aligned top of a mapped kernel stack that stays
/// valid while user code runs.
pub unsafe fn set_kernel_stack(top: u64) {
    let tss = &raw mut (*(&raw mut TABLES).cast::<CpuTables>().add(crate::smp::index())).tss;
    // The TSS is packed: write the field without creating a reference.
    core::ptr::addr_of_mut!((*tss).rsp).write_unaligned([top, 0, 0]);
}

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

/// Loads the GDT, reloads all segment registers and the task register.
///
/// # Safety
/// Must be called once, on the boot CPU, before interrupts are enabled.
pub unsafe fn init() { init_cpu(0); }

/// # Safety
/// Each logical CPU calls this once with a distinct slot, interrupts off.
pub unsafe fn init_cpu(index: usize) {
    let state = (&raw mut TABLES).cast::<CpuTables>().add(index);
    let tss = &raw mut (*state).tss;
    let stacks = &raw const (*state).stacks;
    for (i, ist) in [IST_DOUBLE_FAULT, IST_NMI, IST_MACHINE_CHECK].iter().enumerate() {
        let top = addr_of!((*stacks)[i]) as u64 + IST_STACK_SIZE as u64;
        (*tss).ist[*ist as usize - 1] = top;
    }
    let base = tss as u64;
    let limit = (size_of::<Tss>() - 1) as u64;
    let gdt = &raw mut (*state).gdt;
    (*gdt)[5] = (limit & 0xFFFF)
        | ((base & 0xFF_FFFF) << 16)
        | (0x89 << 40) // present, 64-bit available TSS
        | (((limit >> 16) & 0xF) << 48)
        | (((base >> 24) & 0xFF) << 56);
    (*gdt)[6] = base >> 32;

    let ptr = Pointer { limit: (size_of::<[u64; GDT_ENTRIES]>() - 1) as u16, base: gdt as u64 };
    asm!(
        "lgdt [{ptr}]",
        // Reload CS with a far return.
        "push {cs}",
        "lea {tmp}, [rip + 2f]",
        "push {tmp}",
        "retfq",
        "2:",
        "mov ds, {ds:x}",
        "mov es, {ds:x}",
        "mov ss, {ds:x}",
        "xor {tmp:e}, {tmp:e}",
        "mov fs, {tmp:x}",
        "mov gs, {tmp:x}",
        "ltr {tss:x}",
        ptr = in(reg) &ptr,
        cs = in(reg) KERNEL_CS as u64,
        ds = in(reg) KERNEL_DS as u64,
        tss = in(reg) TSS_SEL as u64,
        tmp = out(reg) _,
    );
}

/// Descriptor `index` of the calling CPU's GDT (diagnostics and tests).
pub fn descriptor(index: usize) -> u64 {
    assert!(index < GDT_ENTRIES, "GDT index {index} out of range");
    // SAFETY: the index is in range and this CPU's slot lives as long as the
    // kernel; only this CPU writes it (entry 8, with interrupts off).
    unsafe { (*(&raw const TABLES).cast::<CpuTables>().add(crate::smp::index())).gdt[index] }
}

/// Keeps a 32-bit FS base representable and page-aligned.
///
/// A descriptor base is only 32 bits wide and 32-bit code cannot address
/// memory above 4 GiB anyway. A bad value is a kernel bug or a rejected
/// system call argument, so debug builds stop on it; release builds clamp it
/// (a wrong base only misplaces the 32-bit TEB, while an unclamped value
/// could not be represented at all).
#[inline]
fn fs32_base_bounded(base: u64) -> u64 {
    if cfg!(debug_assertions) {
        assert!(base < 1 << 32, "32-bit FS base {base:#x} is not below 4 GiB");
        assert!(base.is_multiple_of(4096), "32-bit FS base {base:#x} is not page-aligned");
        base
    } else {
        base & 0xFFFF_F000
    }
}

/// Sets the base of the calling CPU's 32-bit FS data descriptor (entry 8) and,
/// when `base` is not 0, loads FS with [`USER_FS32`].
///
/// In IA-32e mode the hidden FS base is one register: loading a selector
/// takes the base from the descriptor (the `IA32_FS_BASE` MSR aliases the
/// same register, which is how Linux switches 32-bit TLS segments), and
/// writing the MSR replaces it. A base of 0 means the thread has no 32-bit
/// TEB: its descriptor is patched so a stale one cannot point into this
/// thread's old TEB, but FS is not reloaded, because that would overwrite the
/// 64-bit FS base just written from the MSR.
///
/// # Safety
/// Interrupts must be off (the scheduler lock keeps them off), so no other
/// thread can observe a half-updated entry or run with the previous
/// selector. The GDT belongs to the calling CPU; other CPUs keep their own
/// copy and install the base of the thread they run.
pub unsafe fn set_fs32_base(base: u64) {
    let base = fs32_base_bounded(base);
    let state = (&raw mut TABLES).cast::<CpuTables>().add(crate::smp::index());
    let gdt = &raw mut (*state).gdt;
    (*gdt)[FS32_INDEX] = wow64::data32_descriptor(base as u32);
    if base != 0 {
        // Reloading the cached descriptor is required: a descriptor write
        // does not change the segment register's hidden base.
        asm!("mov fs, {sel:x}", sel = in(reg) USER_FS32 as u64, options(nostack, preserves_flags));
    }
}
