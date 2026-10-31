import re

missing = [
  "SetFileSecurityW", "RegEnumKeyW",
  "ImageList_AddMasked", "#17", "ImageList_Destroy", "ImageList_Create",
  "CreateBrushIndirect",
  "GetProcAddress", "LoadLibraryExW",
  "SHBrowseForFolderW", "SHGetFileInfoW", "SHFileOperationW",
  "SetClassLongW", "EnableMenuItem", "GetWindowLongW", "CheckDlgButton", "LoadBitmapW",
  "CallWindowProcW", "wsprintfW", "SetDlgItemTextW", "GetDlgItemTextW", "MessageBoxIndirectW",
  "CharPrevW", "CharNextA", "wsprintfA", "DispatchMessageW", "PeekMessageW", "BeginPaint",
  "EndDialog", "RegisterClassW", "CreateWindowExW", "GetClassInfoW", "DialogBoxParamW",
  "CharNextW", "ExitWindowsEx", "SetTimer", "GetDlgItem", "SetWindowLongW", "AppendMenuW",
  "CreatePopupMenu", "EndPaint", "CreateDialogParamW",
  "CoCreateInstance"
]

import os
rust_files = []
for root, dirs, files in os.walk('compatibility/win32/src'):
    for f in files:
        if f.endswith('.rs'):
            rust_files.append(os.path.join(root, f))

file_contents = {}
for rf in rust_files:
    with open(rf, encoding='utf-8', errors='ignore') as f:
        file_contents[rf] = f.read()

for m in missing:
    found = []
    for rf, content in file_contents.items():
        if m.startswith('#'):
            # ordinal 17
            if '17' in content and 'InitCommonControls' in content:
                found.append(rf)
        else:
            if re.search(r'\bfn\s+' + m + r'\b', content) or f'"{m}"' in content:
                found.append(rf)
    print(f"{m:25}: {found}")
