//! Segment selectors, GDT descriptors and the IRET frame for 32-bit
//! compatibility-mode user code.
//!
//! 32-bit programs run in the same process as the 64-bit runtime, in IA-32e
//! compatibility mode: their code segment is a ring-3 descriptor with D=1,
//! L=0, and their FS base comes from a ring-3 data descriptor instead of
//! `IA32_FS_BASE`. Both descriptors live in kernel GDT slots the 64-bit
//! selectors do not use, so the 64-bit path keeps its numbers:
//!
//! | GDT index | Selector | Meaning |
//! |---|---|---|
//! | 3 | `0x1B` | [`USER_DS`], ring-3 data (64-bit SS) |
//! | 4 | `0x23` | [`USER_CS`], ring-3 64-bit code |
//! | 7 | `0x3B` | [`USER_CS32`], ring-3 compatibility-mode code |
//! | 8 | `0x43` | [`USER_FS32`], ring-3 data, per-thread base |
//!
//! The bridge stubs far-jump between [`USER_CS32`] and [`USER_CS`]; the
//! kernel enters 32-bit code with a [`CompatIretFrame`].

/// Ring-3 data segment (index 3), also the SS of a 64-bit or 32-bit user
/// context.
pub const USER_DS: u16 = 0x18 | 3;
/// Ring-3 64-bit code segment (index 4).
pub const USER_CS: u16 = 0x20 | 3;
/// Ring-3 compatibility-mode code segment (index 7, D=1, L=0).
pub const USER_CS32: u16 = 0x38 | 3;
/// Ring-3 data segment used for FS in compatibility mode (index 8). Its base
/// is switched with the thread and is where 32-bit code finds its TEB.
pub const USER_FS32: u16 = 0x40 | 3;

/// The 32-bit selectors sit above the TSS (0x28, two slots) and leave the
/// SYSRET pair (0x18, 0x20) untouched.
const _: () = assert!(
    USER_DS + 8 == USER_CS
        && USER_CS32 & !3 == 0x38
        && USER_FS32 & !3 == 0x40
        && USER_CS32 & !3 >= 0x28 + 16
);

/// RFLAGS of a 32-bit entry: IF set; TF, DF, IOPL, NT and VM stay clear.
pub const ENTRY_RFLAGS: u64 = 0x202;

/// Descriptor of the flat compatibility-mode code segment: present, DPL 3,
/// S=1, code, readable, D=1, L=0, G=1, limit `0xFFFFF` (4 GiB).
pub const CODE32_DESCRIPTOR: u64 = 0x00CF_FA00_0000_FFFF;

/// Descriptor of the flat 32-bit FS data segment with base 0: present,
/// DPL 3, S=1, data, writable, D=1, L=0, G=1.
pub const DATA32_DESCRIPTOR: u64 = 0x00CF_F200_0000_FFFF;

/// The compatibility-mode code descriptor (entry 7 of the kernel GDT).
pub const fn code32_descriptor() -> u64 {
    CODE32_DESCRIPTOR
}

/// The 32-bit FS data descriptor with `base` in its base field (entry 8 of
/// the kernel GDT). Only the low 32 bits of `base` are representable.
pub const fn data32_descriptor(base: u32) -> u64 {
    let base = base as u64;
    DATA32_DESCRIPTOR | ((base & 0x00FF_FFFF) << 16) | ((base >> 24) << 56)
}

/// Base address encoded in a descriptor.
pub const fn descriptor_base(descriptor: u64) -> u32 {
    ((descriptor >> 16) & 0x00FF_FFFF) as u32 | (((descriptor >> 56) & 0xFF) as u32) << 24
}

/// Access byte of a descriptor (P, DPL, S, type).
pub const fn descriptor_access(descriptor: u64) -> u8 {
    ((descriptor >> 40) & 0xFF) as u8
}

/// Limit of a descriptor in bytes before scaling (with G=1 the effective
/// limit is `(limit << 12) | 0xFFF`).
pub const fn descriptor_limit(descriptor: u64) -> u32 {
    (descriptor & 0xFFFF) as u32 | (((descriptor >> 48) & 0xF) as u32) << 16
}

/// D/B bit: 1 for 32-bit segments, 0 for 64-bit code.
pub const fn descriptor_d(descriptor: u64) -> bool {
    (descriptor >> 54) & 1 != 0
}

/// L bit: 1 for 64-bit code, 0 elsewhere.
pub const fn descriptor_l(descriptor: u64) -> bool {
    (descriptor >> 53) & 1 != 0
}

/// G bit: limit in 4 KiB pages.
pub const fn descriptor_granularity(descriptor: u64) -> bool {
    (descriptor >> 55) & 1 != 0
}

/// IRETQ frame for entering compatibility mode: the five 64-bit slots the
/// CPU pops, lowest address first.
///
/// The 32-bit bridge passes this frame to the kernel's entry stub, which
/// `push`es its words and executes `iretq`. The CPU switches to compatibility
/// mode because `cs` has L=0, D=1 and DPL 3.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompatIretFrame {
    /// Entry point; the low 32 bits are used.
    pub rip: u64,
    /// [`USER_CS32`].
    pub cs: u64,
    /// [`ENTRY_RFLAGS`].
    pub rflags: u64,
    /// Initial stack pointer; the low 32 bits are used.
    pub rsp: u64,
    /// [`USER_DS`].
    pub ss: u64,
}

impl CompatIretFrame {
    /// The frame for entering `entry` with `rsp` in compatibility mode.
    ///
    /// `None` unless both addresses are non-zero and below 4 GiB (compat
    /// mode has 32-bit address size) and `rsp` is 16-byte aligned, which the
    /// i386 calling conventions require at a call boundary (a `call` then
    /// leaves the callee's stack frame aligned).
    pub const fn new(entry: u64, rsp: u64) -> Option<Self> {
        const LIMIT: u64 = 1 << 32;
        if entry == 0 || entry >= LIMIT || rsp == 0 || rsp >= LIMIT || !rsp.is_multiple_of(16) {
            return None;
        }
        Some(Self { rip: entry, cs: USER_CS32 as u64, rflags: ENTRY_RFLAGS, rsp, ss: USER_DS as u64 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_the_gdt_layout() {
        assert_eq!(USER_DS, 0x1B);
        assert_eq!(USER_CS, 0x23);
        assert_eq!(USER_CS32, 0x3B);
        assert_eq!(USER_FS32, 0x43);
        // New selectors sit above the TSS (0x28, two slots) and do not move
        // the STAR/SYSRET pair; the module-level assertions check the layout.
        assert_eq!(USER_CS32 & !3, 0x38);
        assert_eq!(USER_FS32 & !3, 0x40);
    }

    #[test]
    fn code32_descriptor_decodes_as_compatibility_code() {
        let d = code32_descriptor();
        assert_eq!(d, 0x00CF_FA00_0000_FFFF);
        assert_eq!(descriptor_base(d), 0);
        assert_eq!(descriptor_limit(d), 0xF_FFFF);
        assert!(descriptor_granularity(d), "G must be set for a flat 4 GiB limit");
        assert!(descriptor_d(d), "D=1 with L=0 selects compatibility mode");
        assert!(!descriptor_l(d), "L must be clear for compatibility mode");
        // Present, DPL 3, S=1, code, readable, not conforming.
        assert_eq!(descriptor_access(d), 0xFA);
    }

    #[test]
    fn data32_descriptor_carries_a_32_bit_base() {
        let d = data32_descriptor(0x7FFD_F000);
        assert!(descriptor_d(d) && !descriptor_l(d));
        assert_eq!(descriptor_access(d), 0xF2, "present, DPL 3, data, writable");
        assert_eq!(descriptor_base(d), 0x7FFD_F000);
        for base in [0u32, 1, 0x1000, 0x1234_5000, 0xFFFF_F000, u32::MAX] {
            let d = data32_descriptor(base);
            assert_eq!(descriptor_base(d), base);
            // Everything except the base fields is fixed.
            assert_eq!(descriptor_access(d), descriptor_access(DATA32_DESCRIPTOR));
            assert_eq!(descriptor_limit(d), descriptor_limit(DATA32_DESCRIPTOR));
            assert!(descriptor_d(d) && !descriptor_l(d) && descriptor_granularity(d));
        }
        assert_eq!(data32_descriptor(0), DATA32_DESCRIPTOR);
    }

    #[test]
    fn compat_iret_frame_is_below_4_gib_and_aligned() {
        let f = CompatIretFrame::new(0x0040_1000, 0x7FFE_0000).expect("valid compat frame");
        assert_eq!(f.rip, 0x0040_1000);
        assert_eq!(f.cs, 0x3B);
        assert_eq!(f.rflags, 0x202);
        assert_eq!(f.rsp, 0x7FFE_0000);
        assert_eq!(f.ss, 0x1B);
        assert_eq!(core::mem::size_of::<CompatIretFrame>(), 40);
        assert!(CompatIretFrame::new(0, 0x1000).is_none());
        assert!(CompatIretFrame::new(1 << 32, 0x1000).is_none());
        assert!(CompatIretFrame::new(0x1000, 0).is_none());
        assert!(CompatIretFrame::new(0x1000, 1 << 32).is_none());
        assert!(CompatIretFrame::new(0x1000, 0x1008).is_none(), "misaligned stack");
        assert!(CompatIretFrame::new(0x1000, 0x1000).is_some());
    }
}
