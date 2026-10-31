/* PE32 window callbacks, child controls and PAINTSTRUCT under PRISM. */
typedef unsigned long DWORD;
typedef void *HANDLE;
typedef unsigned short WCHAR;
typedef long (__stdcall *WNDPROC)(HANDLE, DWORD, DWORD, long);
typedef struct { DWORD style; WNDPROC proc; int cls, wnd; HANDLE instance, icon, cursor, brush; const WCHAR *menu, *name; } WNDCLASS32;
typedef struct { void *param; HANDLE instance, menu, parent; int h, w, y, x; DWORD style; const WCHAR *title, *class_name; DWORD ex; } CREATE32;
typedef struct { HANDLE dc; int erase; int left, top, right, bottom; int restore, update; char reserved[32]; } PAINT32;
_Static_assert(sizeof(CREATE32) == 48 && sizeof(PAINT32) == 64, "PE32 layouts");
__declspec(dllimport) void __stdcall ExitProcess(DWORD);
__declspec(dllimport) unsigned short __stdcall RegisterClassW(const WNDCLASS32 *);
__declspec(dllimport) HANDLE __stdcall CreateWindowExW(DWORD, const WCHAR *, const WCHAR *, DWORD, int, int, int, int, HANDLE, HANDLE, HANDLE, void *);
__declspec(dllimport) int __stdcall DestroyWindow(HANDLE);
__declspec(dllimport) HANDLE __stdcall GetDlgItem(HANDLE, int);
__declspec(dllimport) int __stdcall SetDlgItemTextW(HANDLE, int, const WCHAR *);
__declspec(dllimport) unsigned int __stdcall GetDlgItemTextW(HANDLE, int, WCHAR *, int);
__declspec(dllimport) int __stdcall CheckDlgButton(HANDLE, int, unsigned int);
__declspec(dllimport) long __stdcall SendMessageW(HANDLE, DWORD, DWORD, long);
__declspec(dllimport) HANDLE __stdcall BeginPaint(HANDLE, PAINT32 *);
__declspec(dllimport) int __stdcall EndPaint(HANDLE, const PAINT32 *);
__declspec(dllimport) DWORD __stdcall SetClassLongW(HANDLE, int, DWORD);
__declspec(dllimport) long __stdcall SetWindowLongW(HANDLE, int, long);
__declspec(dllimport) HANDLE __stdcall CreateDialogParamW(HANDLE, const WCHAR *, HANDLE, WNDPROC, long);
__declspec(dllimport) long __stdcall DialogBoxParamW(HANDLE, const WCHAR *, HANDLE, WNDPROC, long);
__declspec(dllimport) int __stdcall EndDialog(HANDLE, long);
__declspec(dllimport) int __stdcall PostMessageW(HANDLE, DWORD, DWORD, long);
__declspec(dllimport) int __stdcall IsChild(HANDLE, HANDLE);
__declspec(dllimport) HANDLE __stdcall GetTopWindow(HANDLE);
__declspec(dllimport) int __stdcall UnregisterClassW(const WCHAR *, HANDLE);
__declspec(dllimport) HANDLE __stdcall SetWindowsHookExW(int, void *, HANDLE, DWORD);
__declspec(dllimport) int __stdcall UnhookWindowsHookEx(HANDLE);
__declspec(dllimport) int __stdcall LoadStringW(HANDLE, DWORD, WCHAR *, int);
__declspec(dllimport) void __stdcall SetLastError(DWORD);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HANDLE __stdcall LoadBitmapW(HANDLE, const WCHAR *);
__declspec(dllimport) int __stdcall DeleteObject(HANDLE);
__declspec(dllimport) HANDLE __stdcall GetModuleHandleW(const WCHAR *);

static int create_ok;
static int dialog_init;
static long __stdcall dlgproc(HANDLE hwnd, DWORD msg, DWORD w, long l) {
    (void)w;
    if (msg == 0x110) {
        dialog_init += GetDlgItem(hwnd, 42) != 0;
        if (l == 2) PostMessageW(hwnd, 0x8001, 0, 0);
        return 1;
    }
    if (msg == 0x8001) { EndDialog(hwnd, 73); return 1; }
    return 0;
}
static long __stdcall proc(HANDLE hwnd, DWORD msg, DWORD w, long l) {
    (void)hwnd; (void)w;
    if (msg == 0x81) {
        CREATE32 *cs = (CREATE32 *)l;
        create_ok = cs && cs->param == (void *)0x1234 && cs->w == 200 && cs->h == 100;
        return 1;
    }
    return 0;
}

void __stdcall start(void) {
    static const WCHAR name[] = L"OSyxGui32";
    WNDCLASS32 wc = { 0, proc, 0, 0, 0, 0, 0, 0, 0, name };
    int failed = RegisterClassW(&wc) == 0;
    HANDLE parent = CreateWindowExW(0, name, L"parent", 0, 0, 0, 200, 100, 0, 0, 0, (void *)0x1234);
    if (!parent || !create_ok) failed++;
    if (parent && (SetClassLongW(parent, -12, 123) != 0 || SetClassLongW(parent, -12, 0) != 123)) failed++;
    HANDLE child = parent ? CreateWindowExW(0, L"BUTTON", L"old", 0x40000000, 0, 0, 60, 20, parent, (HANDLE)42, 0, 0) : 0;
    if (!child || GetDlgItem(parent, 42) != child) failed++;
    WCHAR text[8];
    if (!child || !SetDlgItemTextW(parent, 42, L"new") || GetDlgItemTextW(parent, 42, text, 8) != 3 ||
        text[0] != 'n' || text[1] != 'e' || text[2] != 'w' || text[3] != 0) failed++;
    if (!child || !CheckDlgButton(parent, 42, 1) || SendMessageW(child, 0xF0, 0, 0) != 1) failed++;
    if (child) {
        WNDPROC old = (WNDPROC)SetWindowLongW(child, -4, (long)proc);
        if (!old || old(child, 0x81, 0, 0) != 1) failed++;
        SetWindowLongW(child, -4, (long)old);
    }
    struct { PAINT32 paint; DWORD guard; } ps;
    ps.guard = 0xabcddcba;
    HANDLE dc = parent ? BeginPaint(parent, &ps.paint) : 0;
    if (!dc || ps.paint.dc != dc || ps.guard != 0xabcddcba || !EndPaint(parent, &ps.paint)) failed++;
    HANDLE modeless = CreateDialogParamW(0, (const WCHAR *)101, parent, dlgproc, 1);
    if (!modeless || dialog_init != 1 || !GetDlgItem(modeless, 42)) failed++;
    if (modeless && !DestroyWindow(modeless)) failed++;
    if (DialogBoxParamW(0, (const WCHAR *)101, parent, dlgproc, 2) != 73 || dialog_init != 2) failed++;
    if (!parent || !child || !IsChild(parent, child) || IsChild(child, parent)) failed++;
    if (!parent || GetTopWindow(parent) == 0) failed++;
    SetLastError(0);
    if (GetTopWindow((HANDLE)0x1234) != 0 || GetLastError() != 1400) failed++;
    SetLastError(0);
    if (UnregisterClassW(name, 0) || GetLastError() != 1412) failed++;
    SetLastError(0);
    if (UnregisterClassW(L"OSyxNoSuchClass", 0) || GetLastError() != 1411) failed++;
    SetLastError(0);
    if (SetWindowsHookExW(3, (void *)proc, 0, 0) != 0 || GetLastError() != 50) failed++;
    SetLastError(0);
    if (UnhookWindowsHookEx((HANDLE)0x1234) || GetLastError() != 1404) failed++;
    {
        WCHAR text[64];
        text[13] = 0x5a5a;
        if (LoadStringW(GetModuleHandleW(0), 3, text, 64) != 12 || text[0] != 'S' || text[12] != 0 || text[13] != 0x5a5a) failed++;
        if (LoadStringW(0, 19, text, 64) != 8 || text[0] != 'N') failed++;
        SetLastError(0);
        if (LoadStringW(0, 4, text, 64) != 0 || GetLastError() != 1814) failed++;
    }
    HANDLE bitmap = LoadBitmapW(GetModuleHandleW(0), (const WCHAR *)7);
    if (!bitmap || !DeleteObject(bitmap)) failed++;
    if (LoadBitmapW(GetModuleHandleW(0), (const WCHAR *)8) != 0) failed++;
    if (parent && !DestroyWindow(parent)) failed++;
    ExitProcess((DWORD)failed);
}
