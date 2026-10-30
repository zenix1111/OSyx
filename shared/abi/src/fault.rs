//! Resumable user CPU exceptions. Registration is process-wide; delivery
//! and outstanding contexts are per-thread. At most one delivery may be
//! outstanding per thread; an exception in its handler terminates it.
//! Returning uses the kernel's original user selectors and sanitized flags.
pub const RAX: usize = 0;
pub const RBX: usize = 1;
pub const RCX: usize = 2;
pub const RDX: usize = 3;
pub const RSI: usize = 4;
pub const RDI: usize = 5;
pub const RBP: usize = 6;
pub const RSP: usize = 7;
pub const R8: usize = 8;
pub const R9: usize = 9;
pub const R10: usize = 10;
pub const R11: usize = 11;
pub const R12: usize = 12;
pub const R13: usize = 13;
pub const R14: usize = 14;
pub const R15: usize = 15;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct Context {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    pub vector: u64,
    pub error: u64,
    pub address: u64,
    pub reserved: u64,
    /// Padding so `fx` is 64-byte aligned for XSAVE/XRSTOR.
    pub _pad: [u8; 16],
    /// XSAVE64 image: x87, SSE and AVX state (XSTATE_BV, YMM upper halves).
    pub fx: [u8; 832],
}
impl Default for Context {
    fn default() -> Self {
        Self {
            gpr: [0; 16],
            rip: 0,
            rflags: 0,
            vector: 0,
            error: 0,
            address: 0,
            reserved: 0,
            _pad: [0; 16],
            fx: [0; 832],
        }
    }
}
const _: () = assert!(core::mem::size_of::<Context>() == 1024);
const _: () = assert!(core::mem::offset_of!(Context, fx) == 192);
