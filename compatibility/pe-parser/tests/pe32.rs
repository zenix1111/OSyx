//! A minimal 32-bit PE32 image: `parse` keeps refusing it, `parse_any`
//! accepts it and widens its fields.
use osyx_pe::{PeError, PeFile};

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// One `.text` section, no data directories, 32-bit optional header (96 bytes).
fn pe32() -> Vec<u8> {
    let mut b = vec![0u8; 0x400 + 0x200];
    b[0..2].copy_from_slice(b"MZ");
    put32(&mut b, 0x3C, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    let c = 0x84;
    put16(&mut b, c, 0x14C); // i386
    put16(&mut b, c + 2, 1); // one section
    put16(&mut b, c + 16, 96); // optional header size
    put16(&mut b, c + 18, 0x0102); // executable, 32-bit machine
    let o = c + 20;
    put16(&mut b, o, 0x10B);
    put32(&mut b, o + 16, 0x1000); // entry point
    put32(&mut b, o + 28, 0x0040_0000); // image base
    put32(&mut b, o + 32, 0x1000); // section alignment
    put32(&mut b, o + 36, 0x200); // file alignment
    put32(&mut b, o + 56, 0x2000); // size of image
    put32(&mut b, o + 60, 0x200); // size of headers
    put16(&mut b, o + 68, 3); // console subsystem
    put32(&mut b, o + 72, 0x10_0000); // stack reserve
    put32(&mut b, o + 92, 0); // no data directories
    let s = o + 96;
    b[s..s + 5].copy_from_slice(b".text");
    put32(&mut b, s + 8, 0x1000); // virtual size
    put32(&mut b, s + 12, 0x1000); // virtual address
    put32(&mut b, s + 16, 0x200); // raw size
    put32(&mut b, s + 20, 0x200); // raw offset
    put32(&mut b, s + 36, 0x6000_0020); // code, execute, read
    b
}

#[test]
fn strict_parse_refuses_pe32() {
    assert!(matches!(PeFile::parse(&pe32()), Err(PeError::NotPe32Plus { magic: 0x10B })));
}

#[test]
fn parse_any_reads_the_pe32_headers() {
    let data = pe32();
    let pe = PeFile::parse_any(&data).unwrap();
    assert!(pe.is_pe32());
    assert_eq!(pe.coff().machine, 0x14C);
    assert_eq!(pe.optional().image_base, 0x40_0000);
    assert_eq!(pe.optional().size_of_image, 0x2000);
    assert_eq!(pe.optional().address_of_entry_point, 0x1000);
    assert_eq!(pe.optional().size_of_stack_reserve, 0x10_0000);
    assert_eq!(pe.optional().subsystem, 3);
}
