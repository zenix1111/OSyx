import re

with open('compatibility/win32/src/wow64/sigs.rs') as f:
    sigs_src = f.read()

handled_sigs = set(re.findall(r'sig!\((\w+),', sigs_src))

with open('compatibility/win32/src/wow64.rs') as f:
    wow64_src = f.read()

overrides = set(re.findall(r'host_override\("(\w+)"', wow64_src))

all_handled = handled_sigs | overrides

with open('scratch/list_imports.py') as f:
    pass

import subprocess
out = subprocess.check_output(['python', 'scratch/list_imports.py']).decode()

missing_by_dll = {}
current_dll = None
for line in out.splitlines():
    if line.endswith('):') and not line.startswith('TOTAL'):
        current_dll = line.split()[0]
        missing_by_dll[current_dll] = []
    elif line.startswith('  ') and current_dll:
        imp = line.strip()
        if imp not in all_handled:
            missing_by_dll[current_dll].append(imp)

total_missing = 0
for dll, imps in missing_by_dll.items():
    print(f"{dll} missing ({len(imps)}):")
    total_missing += len(imps)
    for imp in imps:
        print(f"  {imp}")
print(f"TOTAL MISSING: {total_missing}")
