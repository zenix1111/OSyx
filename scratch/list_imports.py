import sys

with open('build/steam/core/SteamSetup.exe', 'rb') as f:
    data = f.read()

# PE header
pe_offset = int.from_bytes(data[0x3c:0x40], 'little')
magic = data[pe_offset:pe_offset+4]
assert magic == b'PE\0\0'

num_sections = int.from_bytes(data[pe_offset+6:pe_offset+8], 'little')
opt_header_offset = pe_offset + 24
opt_magic = int.from_bytes(data[opt_header_offset:opt_header_offset+2], 'little')
assert opt_magic == 0x10b # PE32

# Data directories: offset 96 from opt_header
import_dir_rva = int.from_bytes(data[opt_header_offset+96+8:opt_header_offset+96+12], 'little')
import_dir_size = int.from_bytes(data[opt_header_offset+96+12:opt_header_offset+96+16], 'little')

# Sections
section_header_offset = opt_header_offset + int.from_bytes(data[pe_offset+20:pe_offset+22], 'little')
sections = []
for i in range(num_sections):
    sh = data[section_header_offset + i*40 : section_header_offset + (i+1)*40]
    name = sh[:8].rstrip(b'\0').decode('latin1')
    vsize = int.from_bytes(sh[8:12], 'little')
    vrva = int.from_bytes(sh[12:16], 'little')
    rsize = int.from_bytes(sh[16:20], 'little')
    roff = int.from_bytes(sh[20:24], 'little')
    sections.append((name, vrva, vsize, roff, rsize))

def rva2off(rva):
    for name, vrva, vsize, roff, rsize in sections:
        if vrva <= rva < vrva + max(vsize, rsize):
            return roff + (rva - vrva)
    return None

def read_str(off):
    end = data.find(b'\0', off)
    return data[off:end].decode('ascii')

off = rva2off(import_dir_rva)
all_imports = {}
while True:
    entry = data[off:off+20]
    if entry == b'\0'*20:
        break
    ilt_rva = int.from_bytes(entry[0:4], 'little')
    name_rva = int.from_bytes(entry[12:16], 'little')
    iat_rva = int.from_bytes(entry[16:20], 'little')
    dll_name = read_str(rva2off(name_rva))
    
    thunk_rva = ilt_rva if ilt_rva else iat_rva
    thunk_off = rva2off(thunk_rva)
    imps = []
    while True:
        val = int.from_bytes(data[thunk_off:thunk_off+4], 'little')
        if val == 0:
            break
        if val & 0x80000000:
            imps.append(f"#{val & 0xffff}")
        else:
            hint_name_off = rva2off(val)
            name = read_str(hint_name_off + 2)
            imps.append(name)
        thunk_off += 4
    all_imports[dll_name] = imps
    off += 20

total = 0
for dll, imps in sorted(all_imports.items()):
    print(f"{dll} ({len(imps)}):")
    total += len(imps)
    for imp in imps:
        print(f"  {imp}")
print(f"TOTAL: {total}")
