# aml 0.16.4 in OSyx

Source: crates.io `aml` 0.16.4, <https://github.com/rust-osdev/acpi>,
licensed MIT OR Apache-2.0 (copyright Isaac Woods and the rust-osdev
contributors). The license texts are those of the upstream repository.

Changes for OSyx (`src/lib.rs`):

- `Handler` has `read_ec_u8` / `write_ec_u8` (default: no embedded
  controller), and `EmbeddedControl` operation regions are read and written
  byte by byte through them. Laptop batteries (`_BST`, `_BIF`) and AC
  adapters (`_PSR`) usually read their fields from the EC.
- Region spaces the crate does not support return
  `AmlError::FieldInvalidAccessSize` instead of `unimplemented!()`.
- Operators firmware battery and EC methods use but 0.16.4 lacked:
  `Subtract`, `Multiply`, `Divide`, `Mod`, `Or`, `XOr`, `NAnd`, `NOr`, `Not`,
  `LNot`, `SizeOf`, `Index` and `DerefOf` (`Index` returns the element by
  value, so `DerefOf` passes it through).
- `Index` as a store target (`Store(x, Index(PKG, 2))`, the usual way a
  firmware method fills the `_BST` package), for named objects and locals
  holding packages (`Target::Index`).
- Package elements may be locals and arguments of the running method
  (`Package () { Local0, Local1 }`), taken by value.
