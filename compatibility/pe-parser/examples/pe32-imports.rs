//! Lists the imports of a PE32 or PE32+ image:
//! cargo run -p osyx-pe --example pe32-imports -- FILE.exe
use osyx_pe::{ImportEntry, PeFile};

fn main() {
    let path = std::env::args().nth(1).expect("usage: pe32-imports FILE");
    let data = std::fs::read(&path).expect("cannot read file");
    let pe = PeFile::parse_any(&data).expect("not a PE image");
    println!(
        "{path}: {} machine {:#x} subsystem {} entry {:#x} base {:#x} size {:#x}",
        if pe.is_pe32() { "PE32" } else { "PE32+" },
        pe.coff().machine,
        pe.optional().subsystem,
        pe.optional().address_of_entry_point,
        pe.optional().image_base,
        pe.optional().size_of_image
    );
    let mut total = 0;
    for import in pe.imports().expect("imports") {
        let import = import.expect("import descriptor");
        let mut names = Vec::new();
        for entry in import.entries() {
            match entry.expect("import entry") {
                ImportEntry::ByName { name, .. } => names.push(name.to_string()),
                ImportEntry::ByOrdinal { ordinal, .. } => names.push(format!("#{ordinal}")),
            }
        }
        total += names.len();
        println!("{} ({}): {}", import.dll, names.len(), names.join(" "));
    }
    println!("total imports: {total}");
}
