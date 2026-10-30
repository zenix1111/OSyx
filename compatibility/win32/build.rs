fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    // winrun sits at 0x4000_0000: 32-bit (PE32) code running in compatibility
    // mode can only address the low 4 GiB.
    println!("cargo:rustc-link-arg-bins=-T{dir}/../../userspace/winrun.ld");
    println!("cargo:rustc-link-arg-bins=--no-dynamic-linker");
    println!("cargo:rerun-if-changed=../../userspace/winrun.ld");
}
