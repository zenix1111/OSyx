/* Target: a 32-bit (PE32/i386) console program that calls built-in
 * functions through the WoW64 bridge signatures: strings, MulDiv, the tick
 * count, the command line and global memory (both must be addressable by
 * 32-bit code), initialization files, and the registry, whose HKEY outputs
 * are 64-bit values on the host side (OutWide). No C runtime.
 *
 * Prints "api32: ok NAME" / "api32: FAIL NAME" lines and a summary, and
 * exits with the number of failures. Runs only under /bin/winrun inside
 * QEMU (scripts/win-test.ps1). */
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HKEY;
typedef unsigned short WCHAR;

#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define HKEY_CURRENT_USER ((HKEY)(unsigned long)0x80000001)
#define KEY_ALL_ACCESS 0xF003F
#define REG_DWORD 4
#define GPTR 0x40

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD std_handle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE file, const void *buf, DWORD len, DWORD *written, void *overlapped);
__declspec(dllimport) void __stdcall ExitProcess(DWORD code);
__declspec(dllimport) int __stdcall lstrcmpiA(const char *a, const char *b);
__declspec(dllimport) int __stdcall lstrlenW(const WCHAR *s);
__declspec(dllimport) int __stdcall MulDiv(int a, int b, int c);
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) WCHAR *__stdcall GetCommandLineW(void);
__declspec(dllimport) void *__stdcall GlobalAlloc(DWORD flags, DWORD size);
__declspec(dllimport) void *__stdcall GlobalFree(void *mem);
__declspec(dllimport) DWORD __stdcall GetPrivateProfileStringW(const WCHAR *section, const WCHAR *key, const WCHAR *def,
                                                               WCHAR *buf, DWORD size, const WCHAR *file);
__declspec(dllimport) BOOL __stdcall WritePrivateProfileStringW(const WCHAR *section, const WCHAR *key, const WCHAR *value,
                                                                const WCHAR *file);
__declspec(dllimport) BOOL __stdcall DeleteFileW(const WCHAR *path);
__declspec(dllimport) DWORD __stdcall GetFileAttributesW(const WCHAR *path);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR *name, DWORD access, DWORD share, void *sa, DWORD disposition,
                                                   DWORD flags, HANDLE tmpl);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE file, void *buf, DWORD len, DWORD *read, void *overlapped);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE h);
__declspec(dllimport) HANDLE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) HANDLE __stdcall LoadLibraryExW(const WCHAR *name, HANDLE file, DWORD flags);
__declspec(dllimport) void *__stdcall GetProcAddress(HANDLE module, const char *name);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall FreeLibrary(HANDLE module);
__declspec(dllimport) HANDLE __stdcall LocalFree(HANDLE memory);
__declspec(dllimport) long __stdcall RegCreateKeyExW(HKEY key, const WCHAR *sub, DWORD reserved, WCHAR *cls, DWORD options,
                                                     DWORD sam, void *sa, HKEY *result, DWORD *disposition);
__declspec(dllimport) long __stdcall RegSetValueExW(HKEY key, const WCHAR *name, DWORD reserved, DWORD type,
                                                    const void *data, DWORD size);
__declspec(dllimport) long __stdcall RegQueryValueExW(HKEY key, const WCHAR *name, DWORD *reserved, DWORD *type,
                                                      void *data, DWORD *size);
__declspec(dllimport) long __stdcall RegCloseKey(HKEY key);
__declspec(dllimport) long __stdcall RegDeleteKeyW(HKEY key, const WCHAR *sub);
__declspec(dllimport) long __stdcall RegEnumKeyW(HKEY key, DWORD index, WCHAR *name, DWORD size);
__declspec(dllimport) BOOL __stdcall CreateDirectoryW(const WCHAR *name, void *attributes);
__declspec(dllimport) BOOL __stdcall RemoveDirectoryW(const WCHAR *name);
__declspec(dllimport) BOOL __stdcall SetFileSecurityW(const WCHAR *name, DWORD info, const void *descriptor);
__declspec(dllimport) DWORD __stdcall GetNamedSecurityInfoW(const WCHAR *name, DWORD kind, DWORD info,
                                                           void **owner, void **group, void **dacl, void **sacl, void **descriptor);

__declspec(dllimport) HANDLE __stdcall HeapCreate(DWORD options, DWORD initial, DWORD maximum);
__declspec(dllimport) BOOL __stdcall HeapDestroy(HANDLE heap);
__declspec(dllimport) void *__stdcall HeapAlloc(HANDLE heap, DWORD flags, DWORD size);
__declspec(dllimport) BOOL __stdcall HeapFree(HANDLE heap, DWORD flags, void *block);
__declspec(dllimport) DWORD __stdcall HeapSize(HANDLE heap, DWORD flags, const void *block);
__declspec(dllimport) BOOL __stdcall HeapValidate(HANDLE heap, DWORD flags, const void *block);
__declspec(dllimport) BOOL __stdcall HeapLock(HANDLE heap);
__declspec(dllimport) BOOL __stdcall HeapUnlock(HANDLE heap);
__declspec(dllimport) HANDLE __stdcall GetProcessHeap(void);
__declspec(dllimport) DWORD __stdcall GetProcessHeaps(DWORD count, HANDLE *heaps);
__declspec(dllimport) void __stdcall InitializeCriticalSection(void *section);
__declspec(dllimport) void __stdcall EnterCriticalSection(void *section);
__declspec(dllimport) void __stdcall LeaveCriticalSection(void *section);
__declspec(dllimport) BOOL __stdcall TryEnterCriticalSection(void *section);
__declspec(dllimport) void __stdcall DeleteCriticalSection(void *section);
__declspec(dllimport) BOOL __stdcall DisableThreadLibraryCalls(HANDLE module);
__declspec(dllimport) void __stdcall SetLastError(DWORD code);
__declspec(dllimport) BOOL __stdcall SetForegroundWindow(HANDLE window);
__declspec(dllimport) BOOL __stdcall BringWindowToTop(HANDLE window);
__declspec(dllimport) BOOL __stdcall TrackPopupMenu(HANDLE menu, DWORD flags, int x, int y, int reserved, HANDLE window, const void *rect);
__declspec(dllimport) BOOL __stdcall GetFileSizeEx(HANDLE file, long long *size);
__declspec(dllimport) BOOL __stdcall SetFilePointerEx(HANDLE file, long long distance, long long *position, DWORD method);
typedef struct { unsigned short year, month, weekday, day, hour, minute, second, millis; } SYSTIME32;
__declspec(dllimport) void __stdcall GetSystemTime(SYSTIME32 *time);
__declspec(dllimport) BOOL __stdcall SystemTimeToFileTime(const SYSTIME32 *time, unsigned long long *file_time);
__declspec(dllimport) unsigned long long __stdcall VerSetConditionMask(unsigned long long mask, DWORD type, unsigned char condition);
__declspec(dllimport) void *__stdcall GlobalReAlloc(void *block, DWORD size, DWORD flags);
__declspec(dllimport) HANDLE __stdcall CreateFileMappingW(HANDLE file, void *attributes, DWORD protect, DWORD high, DWORD low, const WCHAR *name);
__declspec(dllimport) void *__stdcall MapViewOfFile(HANDLE mapping, DWORD access, DWORD high, DWORD low, DWORD bytes);
__declspec(dllimport) BOOL __stdcall UnmapViewOfFile(const void *view);
__declspec(dllimport) BOOL __stdcall CreatePipe(HANDLE *read, HANDLE *write, void *attributes, DWORD size);
__declspec(dllimport) long __stdcall InterlockedIncrement(volatile long *p);
__declspec(dllimport) long __stdcall InterlockedDecrement(volatile long *p);
__declspec(dllimport) long __stdcall InterlockedExchange(volatile long *p, long value);
__declspec(dllimport) long __stdcall InterlockedExchangeAdd(volatile long *p, long value);
__declspec(dllimport) long __stdcall InterlockedCompareExchange(volatile long *p, long exchange, long comparand);
__declspec(dllimport) long long __stdcall InterlockedCompareExchange64(volatile long long *p, long long exchange, long long comparand);
__declspec(dllimport) long __stdcall CoInitialize(void *reserved);
__declspec(dllimport) void __stdcall CoUninitialize(void);
__declspec(dllimport) BOOL __stdcall InitializeSecurityDescriptor(void *descriptor, DWORD revision);
__declspec(dllimport) BOOL __stdcall SetSecurityDescriptorDacl(void *descriptor, BOOL present, void *acl, BOOL defaulted);
__declspec(dllimport) BOOL __stdcall SetSecurityDescriptorOwner(void *descriptor, void *owner, BOOL defaulted);
__declspec(dllimport) BOOL __stdcall GetSecurityDescriptorDacl(void *descriptor, BOOL *present, void **acl, BOOL *defaulted);
__declspec(dllimport) BOOL __stdcall GetSecurityDescriptorOwner(void *descriptor, void **owner, BOOL *defaulted);
__declspec(dllimport) BOOL __stdcall IsValidSecurityDescriptor(void *descriptor);
__declspec(dllimport) BOOL __stdcall InitializeAcl(void *acl, DWORD size, DWORD revision);
__declspec(dllimport) BOOL __stdcall AddAccessAllowedAce(void *acl, DWORD revision, DWORD access, void *sid);
__declspec(dllimport) BOOL __stdcall IsValidAcl(void *acl);
__declspec(dllimport) BOOL __stdcall AllocateAndInitializeSid(void *authority, unsigned char count, DWORD a0, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7, void **sid);
__declspec(dllimport) void *__stdcall FreeSid(void *sid);
__declspec(dllimport) DWORD __stdcall GetLengthSid(void *sid);
__declspec(dllimport) BOOL __stdcall IsValidSid(void *sid);
__declspec(dllimport) BOOL __stdcall EqualSid(void *a, void *b);
__declspec(dllimport) long __stdcall BCryptOpenAlgorithmProvider(HANDLE *algorithm, const WCHAR *id, const WCHAR *implementation, DWORD flags);
__declspec(dllimport) long __stdcall BCryptCloseAlgorithmProvider(HANDLE algorithm, DWORD flags);
__declspec(dllimport) long __stdcall BCryptGetProperty(HANDLE object, const WCHAR *property, unsigned char *out, DWORD size, DWORD *result, DWORD flags);
__declspec(dllimport) long __stdcall BCryptCreateHash(HANDLE algorithm, HANDLE *hash, unsigned char *object, DWORD object_size, unsigned char *secret, DWORD secret_size, DWORD flags);
__declspec(dllimport) long __stdcall BCryptHashData(HANDLE hash, unsigned char *data, DWORD size, DWORD flags);
__declspec(dllimport) long __stdcall BCryptFinishHash(HANDLE hash, unsigned char *out, DWORD size, DWORD flags);
__declspec(dllimport) long __stdcall BCryptDestroyHash(HANDLE hash);
__declspec(dllimport) long __stdcall BCryptHash(HANDLE algorithm, unsigned char *secret, DWORD secret_size, unsigned char *input, DWORD input_size, unsigned char *out, DWORD out_size);
__declspec(dllimport) long __stdcall BCryptGenRandom(HANDLE algorithm, unsigned char *out, DWORD size, DWORD flags);
__declspec(dllimport) BOOL __stdcall GetUserNameExW(DWORD format, WCHAR *name, DWORD *size);
typedef long (__stdcall *WNDPROC)(HANDLE, DWORD, DWORD, long);
typedef struct {
    DWORD style;
    WNDPROC proc;
    int cls_extra, wnd_extra;
    HANDLE instance, icon, cursor, background;
    const WCHAR *menu, *name;
} WNDCLASS32;
_Static_assert(sizeof(WNDCLASS32) == 40, "32-bit WNDCLASSW");
__declspec(dllimport) unsigned short __stdcall RegisterClassW(const WNDCLASS32 *wc);
__declspec(dllimport) BOOL __stdcall GetClassInfoW(HANDLE instance, const WCHAR *name, WNDCLASS32 *wc);
__declspec(dllimport) long __stdcall CallWindowProcW(WNDPROC proc, HANDLE hwnd, DWORD msg, DWORD w, long l);
__declspec(dllimport) const WCHAR *__stdcall CharPrevW(const WCHAR *start, const WCHAR *current);
__declspec(dllimport) const WCHAR *__stdcall CharNextW(const WCHAR *p);
__declspec(dllimport) const char *__stdcall CharNextA(const char *p);
typedef struct { HANDLE hwnd; DWORD message, wparam; long lparam; DWORD time; long x, y; } MSG32;
_Static_assert(sizeof(MSG32) == 28, "32-bit MSG");
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG32 *msg, HANDLE hwnd, DWORD min, DWORD max, DWORD flags);
__declspec(dllimport) long __stdcall DispatchMessageW(const MSG32 *msg);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
typedef struct { HANDLE icon; int index; DWORD attributes; WCHAR display[260], kind[80]; } SHFILEINFO32;
_Static_assert(sizeof(SHFILEINFO32) == 692, "32-bit SHFILEINFOW");
__declspec(dllimport) DWORD __stdcall SHGetFileInfoW(const WCHAR *path, DWORD attrs, SHFILEINFO32 *info, DWORD size, DWORD flags);
typedef struct { HANDLE owner; DWORD func; const WCHAR *from, *to; unsigned short flags; int aborted; HANDLE mappings; const WCHAR *title; } SHFILEOP32;
_Static_assert(sizeof(SHFILEOP32) == 32, "32-bit SHFILEOPSTRUCTW");
__declspec(dllimport) int __stdcall SHFileOperationW(SHFILEOP32 *op);
typedef struct { DWORD size; HANDLE owner, instance; const WCHAR *text, *caption; DWORD style; const WCHAR *icon; DWORD context, callback, language; } MSGBOXPARAMS32;
_Static_assert(sizeof(MSGBOXPARAMS32) == 40, "32-bit MSGBOXPARAMSW");
__declspec(dllimport) int __stdcall MessageBoxIndirectW(const MSGBOXPARAMS32 *params);
__declspec(dllimport) HANDLE __stdcall LoadBitmapW(HANDLE instance, const WCHAR *name);
__declspec(dllimport) void __stdcall InitCommonControls(void);
__declspec(dllimport) HANDLE __stdcall ImageList_Create(int cx, int cy, DWORD flags, int initial, int grow);
__declspec(dllimport) int __stdcall ImageList_AddMasked(HANDLE list, HANDLE bitmap, DWORD mask);
__declspec(dllimport) BOOL __stdcall ImageList_Destroy(HANDLE list);
__declspec(dllimport) HANDLE __stdcall CreateBitmap(int width, int height, DWORD planes, DWORD bpp, const void *bits);
__declspec(dllimport) BOOL __stdcall DeleteObject(HANDLE object);
__declspec(dllimport) int __cdecl wsprintfW(WCHAR *out, const WCHAR *format, ...);
__declspec(dllimport) int __cdecl wsprintfA(char *out, const char *format, ...);
__declspec(dllimport) HANDLE __stdcall CreatePopupMenu(void);
__declspec(dllimport) BOOL __stdcall AppendMenuW(HANDLE menu, DWORD flags, DWORD id, const WCHAR *text);
__declspec(dllimport) DWORD __stdcall EnableMenuItem(HANDLE menu, DWORD id, DWORD flags);
__declspec(dllimport) BOOL __stdcall DestroyMenu(HANDLE menu);
__declspec(dllimport) BOOL __stdcall ExitWindowsEx(DWORD flags, DWORD reason);

static long __stdcall test_wndproc(HANDLE hwnd, DWORD msg, DWORD w, long l) {
    return hwnd == (HANDLE)7 && msg == 8 && w == 9 && l == -10 ? -42 : 0;
}

typedef struct {
    DWORD cb;
    WCHAR *reserved, *desktop, *title;
    DWORD x, y, xsize, ysize, xchars, ychars, fill, flags;
    unsigned short show, cb_reserved2;
    unsigned char *reserved2;
    HANDLE std_in, std_out, std_err;
} STARTUPINFOW;
typedef struct {
    HANDLE hProcess, hThread;
    DWORD dwProcessId, dwThreadId;
} PROCESS_INFORMATION;
_Static_assert(sizeof(STARTUPINFOW) == 68, "32-bit STARTUPINFOW");
_Static_assert(sizeof(PROCESS_INFORMATION) == 16, "32-bit PROCESS_INFORMATION");

__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *app, WCHAR *cmdline, void *psa, void *tsa, BOOL inherit,
                                                    DWORD flags, void *env, const WCHAR *cwd, STARTUPINFOW *si,
                                                    PROCESS_INFORMATION *pi);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE h, DWORD ms);
__declspec(dllimport) BOOL __stdcall GetExitCodeProcess(HANDLE process, DWORD *code);

static HANDLE out;
static int failed;

static int len(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void say(const char *a, const char *b) {
    DWORD w;
    WriteFile(out, a, len(a), &w, 0);
    WriteFile(out, b, len(b), &w, 0);
    WriteFile(out, "\n", 1, &w, 0);
}

static void check(const char *name, int ok) {
    say(ok ? "api32: ok " : "api32: FAIL ", name);
    if (!ok) failed++;
}

/* "name 0x1234abcd" into buf. */
static const char *with_hex(char *buf, const char *name, unsigned long v) {
    int n = 0;
    while (*name) buf[n++] = *name++;
    buf[n++] = ' ', buf[n++] = '0', buf[n++] = 'x';
    for (int i = 7; i >= 0; i--) buf[n++] = "0123456789abcdef"[(v >> (i * 4)) & 15];
    buf[n] = 0;
    return buf;
}

static int wide_eq(const WCHAR *a, const char *b) {
    while (*b && *a == (WCHAR)*b) a++, b++;
    return *a == 0 && *b == 0;
}

void __stdcall start(void) {
    out = GetStdHandle(STD_OUTPUT_HANDLE);

    HANDLE kernel = GetModuleHandleW(L"kernel32.dll");
    check("GetModuleHandleW finds PE32 builtin", kernel != 0);
    HANDLE loaded_kernel = LoadLibraryExW(L"kernel32.dll", 0, 0);
    check("LoadLibraryExW returns builtin", kernel && loaded_kernel == kernel);
    typedef HANDLE (__stdcall *GetCurrentProcessFn)(void);
    GetCurrentProcessFn current = (GetCurrentProcessFn)GetProcAddress(kernel, "GetCurrentProcess");
    check("GetProcAddress creates callable PE32 gate", current && current() == (HANDLE)-1);
    check("GetProcAddress reuses PE32 gate", current && (void *)current == GetProcAddress(kernel, "GetCurrentProcess"));
    check("GetProcAddress reports missing export", GetProcAddress(kernel, "OSyxMissingExport") == 0 && GetLastError() == 127);
    check("FreeLibrary builtin", loaded_kernel && FreeLibrary(loaded_kernel));
    HANDLE plugin = LoadLibraryExW(L"plugin32.dll", 0, 0);
    check("LoadLibraryExW loads PE32 DLL", plugin != 0);
    typedef int (__cdecl *PluginValueFn)(void);
    PluginValueFn plugin_value = plugin ? (PluginValueFn)GetProcAddress(plugin, "plugin_value") : 0;
    check("PE32 export runs after DllMain and calls import", plugin_value && plugin_value() == 42);
    check("FreeLibrary PE32 DLL", plugin && FreeLibrary(plugin));

    static const WCHAR class_name[] = L"OSyxApi32Test";
    WNDCLASS32 wc = { 3, test_wndproc, 0, 0, 0, 0, 0, (HANDLE)17, 0, class_name };
    struct { WNDCLASS32 wc; DWORD guard; } info = { { 0 }, 0xfeedbeef };
    check("RegisterClassW 32-bit layout", RegisterClassW(&wc) != 0);
    check("GetClassInfoW 32-bit layout", GetClassInfoW(0, class_name, &info.wc) && info.wc.style == 3 &&
          info.wc.proc == test_wndproc && info.wc.background == (HANDLE)17 && info.guard == 0xfeedbeef);
    check("CallWindowProcW invokes 32-bit callback", CallWindowProcW(test_wndproc, (HANDLE)7, 8, 9, -10) == -42);
    const WCHAR *wide_text = L"ab";
    const char *ansi_text = "a";
    check("CharPrevW bounds", CharPrevW(wide_text, wide_text) == wide_text && CharPrevW(wide_text, wide_text + 2) == wide_text + 1);
    check("CharNextW terminator", CharNextW(wide_text) == wide_text + 1 && CharNextW(wide_text + 2) == wide_text + 2);
    check("CharNextA terminator", CharNextA(ansi_text) == ansi_text + 1 && CharNextA(ansi_text + 1) == ansi_text + 1);
    struct { MSG32 msg; DWORD guard; } message = { { 0 }, 0x1234abcd };
    PostQuitMessage(37);
    check("PeekMessageW writes 32-bit MSG", PeekMessageW(&message.msg, 0, 0, 0, 1) && message.msg.message == 0x12 &&
          message.msg.wparam == 37 && message.guard == 0x1234abcd);
    check("DispatchMessageW reads 32-bit MSG", DispatchMessageW(&message.msg) == 0);
    struct { SHFILEINFO32 info; DWORD guard; } fileinfo;
    fileinfo.guard = 0xdeadbeef;
    check("SHGetFileInfoW 32-bit layout", SHGetFileInfoW(L"C:\\test.txt", 0x80, &fileinfo.info, sizeof fileinfo.info,
          0x10 | 0x200 | 0x400) != 0 && wide_eq(fileinfo.info.display, "test.txt") &&
          wide_eq(fileinfo.info.kind, "Text Document") && fileinfo.guard == 0xdeadbeef);
    MSGBOXPARAMS32 box = { 40, 0, 0, 0, 0, 0, 0, 0, 1, 0 };
    check("MessageBoxIndirectW rejects unsupported callback", MessageBoxIndirectW(&box) == 0);
    check("LoadBitmapW reports missing resource", LoadBitmapW(0, (const WCHAR *)1) == 0);
    InitCommonControls();
    check("InitCommonControls ordinal 17 registers class", GetClassInfoW(0, L"msctls_progress32", &info.wc) != 0);
    HANDLE list = ImageList_Create(16, 16, 0, 1, 1);
    HANDLE bitmap = CreateBitmap(32, 16, 1, 32, 0);
    check("ImageList_Create and bitmap", list && bitmap);
    check("ImageList_AddMasked adds bitmap strip", list && bitmap && ImageList_AddMasked(list, bitmap, 0) == 0 &&
          ImageList_AddMasked(list, bitmap, 0) == 2);
    check("ImageList_Destroy validates handle", list && ImageList_Destroy(list) && !ImageList_Destroy(list));
    if (bitmap) DeleteObject(bitmap);
    WCHAR formatted[64];
    char formatted_a[64];
    check("wsprintfW reads i386 cdecl and 64-bit arguments", wsprintfW(formatted, L"%s:%d:%I64u", L"abc", -7, 0x100000002ULL) == 17 &&
          wide_eq(formatted, "abc:-7:4294967298"));
    check("wsprintfA reads i386 cdecl arguments", wsprintfA(formatted_a, "%08x %s", 42, "ok") == 11 &&
          lstrcmpiA(formatted_a, "0000002a ok") == 0);
    HANDLE menu = CreatePopupMenu(), submenu = CreatePopupMenu();
    check("popup menu stores nested items", menu && submenu && AppendMenuW(submenu, 0, 42, L"Item") &&
          AppendMenuW(menu, 0x10, (DWORD)submenu, L"Submenu"));
    check("EnableMenuItem updates and returns previous state", EnableMenuItem(menu, 42, 1) == 0 &&
          EnableMenuItem(menu, 42, 0) == 1 && EnableMenuItem(menu, 99, 0) == (DWORD)-1);
    check("DestroyMenu releases submenus", DestroyMenu(menu) && !DestroyMenu(submenu));
    check("ExitWindowsEx rejects invalid flags", !ExitWindowsEx(0x80, 0) && GetLastError() == 87);
    static const WCHAR source[] = L"C:\\tmp\\sh32-source.bin\0", copied[] = L"C:\\tmp\\sh32-copy.bin\0", moved[] = L"C:\\tmp\\sh32-moved.bin\0";
    DeleteFileW(source); DeleteFileW(copied); DeleteFileW(moved);
    {
        /* Self-relative descriptor, DACL only: allow Everyone (S-1-1-0). */
        static const unsigned char selfrel[] = {
            1, 0, 0x04, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
            2, 0, 28, 0, 1, 0, 0, 0,
            0, 0, 20, 0, 0xff, 0x01, 0x1f, 0x00, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
        struct { DWORD length; DWORD descriptor; int inherit; } attributes = { 12, (DWORD)selfrel, 0 };
        WCHAR directory[] = L"C:\\tmp\\sd32dir";
        RemoveDirectoryW(directory);
        check("CreateDirectoryW accepts a 12-byte SECURITY_ATTRIBUTES", CreateDirectoryW(directory, &attributes) &&
              GetFileAttributesW(directory) != (DWORD)-1);
        RemoveDirectoryW(directory);
        attributes.length = 24;
        check("CreateDirectoryW rejects a 64-bit SECURITY_ATTRIBUTES size", !CreateDirectoryW(directory, &attributes));
        RemoveDirectoryW(directory);
    }
    HANDLE source_file = CreateFileW(source, 0x40000000, 0, 0, 2, 0, 0);
    if (source_file && source_file != (HANDLE)-1) CloseHandle(source_file);
    SHFILEOP32 op = { 0, 2, source, copied, 0x14, 0, 0, 0 };
    check("SHFileOperationW copies PE32 path", source_file != (HANDLE)-1 && SHFileOperationW(&op) == 0 &&
          !op.aborted && GetFileAttributesW(copied) != (DWORD)-1);
    op.func = 1; op.from = copied; op.to = moved;
    check("SHFileOperationW moves PE32 path", SHFileOperationW(&op) == 0 && GetFileAttributesW(moved) != (DWORD)-1 &&
          GetFileAttributesW(copied) == (DWORD)-1);
    op.func = 3; op.from = moved; op.to = 0;
    check("SHFileOperationW deletes PE32 path", SHFileOperationW(&op) == 0 && GetFileAttributesW(moved) == (DWORD)-1);
    check("SHFileOperationW reports failure", SHFileOperationW(&op) != 0 && op.aborted);
    struct { unsigned char revision, reserved; unsigned short control; DWORD owner, group, sacl, dacl; } sec32 = { 1, 0, 4, 0, 0, 0, 0 };
    check("SetFileSecurityW validates descriptor", !SetFileSecurityW(source, 4, 0));
    check("SetFileSecurityW applies PE32 null DACL", SetFileSecurityW(source, 4, &sec32));
    unsigned char *acl = 0;
    void *security_descriptor = 0;
    DWORD status = GetNamedSecurityInfoW(source, 1, 4, 0, 0, (void **)&acl, 0, &security_descriptor);
    int everyone_write = 0;
    if (status == 0 && acl) {
        unsigned char *ace = acl + 8;
        for (int i = 0; i < 2; i++) ace += *(unsigned short *)(ace + 2);
        everyone_write = (*(DWORD *)(ace + 4) & 2) != 0;
    }
    check("SetFileSecurityW changes native permissions", status == 0 && everyone_write);
    if (security_descriptor) LocalFree(security_descriptor);
    DeleteFileW(source); DeleteFileW(copied); DeleteFileW(moved);

    {
        /* Heaps, critical sections and friends with the 32-bit layouts. */
        HANDLE process = GetProcessHeap();
        SetLastError(0);
        check("HeapDestroy(process heap) fails with ERROR_INVALID_HANDLE", !HeapDestroy(process) && GetLastError() == 6);
        HANDLE heap = HeapCreate(0, 0, 0);
        void *block = heap ? HeapAlloc(heap, 8, 100) : 0;
        check("HeapCreate, HeapAlloc zeroed, HeapSize", heap && heap != process && block && ((unsigned char *)block)[99] == 0 && HeapSize(heap, 0, block) == 100);
        check("HeapValidate of the block and of the heap", HeapValidate(heap, 0, block) && HeapValidate(heap, 0, 0));
        SetLastError(0);
        check("HeapFree with the wrong heap fails with ERROR_INVALID_PARAMETER", !HeapFree(process, 0, block) && GetLastError() == 87);
        HANDLE heaps[8];
        heaps[4] = (HANDLE)0x5a5a5a5a;
        DWORD count = GetProcessHeaps(4, heaps);
        int listed = 0;
        for (DWORD i = 0; i < count && i < 4; i++) listed += heaps[i] == heap;
        check("GetProcessHeaps writes 4-byte handles and lists the heap", listed == 1 && heaps[4] == (HANDLE)0x5a5a5a5a);
        check("HeapLock, HeapUnlock, HeapUnlock of an unlocked heap", HeapLock(heap) && HeapLock(heap) && HeapUnlock(heap) && HeapUnlock(heap) && HeapUnlock(heap));
        check("HeapDestroy releases the heap", HeapDestroy(heap));
        SetLastError(0);
        check("HeapAlloc from the destroyed heap fails with ERROR_INVALID_HANDLE", HeapAlloc(heap, 0, 8) == 0 && GetLastError() == 6);

        struct { DWORD fields[6]; DWORD guard[4]; } cs = { { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff }, { 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5 } };
        InitializeCriticalSection(&cs);
        int cleared = 1;
        for (int i = 0; i < 6; i++) cleared &= cs.fields[i] == 0;
        check("InitializeCriticalSection clears exactly 24 bytes", cleared && cs.guard[0] == 0xa5a5a5a5 && cs.guard[3] == 0xa5a5a5a5);
        EnterCriticalSection(&cs);
        EnterCriticalSection(&cs);
        check("critical section: owner, recursion count and TryEnter", cs.fields[3] != 0 && cs.fields[2] == 2 && TryEnterCriticalSection(&cs));
        LeaveCriticalSection(&cs); LeaveCriticalSection(&cs); LeaveCriticalSection(&cs);
        check("critical section is free after the last leave", cs.fields[3] == 0 && cs.fields[2] == 0 && cs.fields[1] == 0);
        cs.fields[2] = 7;
        DeleteCriticalSection(&cs);
        cleared = 1;
        for (int i = 0; i < 6; i++) cleared &= cs.fields[i] == 0;
        check("DeleteCriticalSection clears 24 bytes only", cleared && cs.guard[0] == 0xa5a5a5a5 && cs.guard[3] == 0xa5a5a5a5);

        SetLastError(0);
        check("DisableThreadLibraryCalls(bogus) fails with ERROR_MOD_NOT_FOUND", !DisableThreadLibraryCalls((HANDLE)0x1234) && GetLastError() == 126);
        SetLastError(0);
        check("SetForegroundWindow(bogus) fails with ERROR_INVALID_WINDOW_HANDLE", !SetForegroundWindow((HANDLE)0x1234) && GetLastError() == 1400);
        SetLastError(0);
        check("BringWindowToTop(bogus) fails with ERROR_INVALID_WINDOW_HANDLE", !BringWindowToTop((HANDLE)0x1234) && GetLastError() == 1400);
        SetLastError(0);
        check("TrackPopupMenu fails with ERROR_NOT_SUPPORTED", !TrackPopupMenu((HANDLE)1, 0, 0, 0, 0, 0, 0) && GetLastError() == 50);
    }

    {
        /* Interlocked operations. */
        volatile long v = 5;
        check("InterlockedIncrement/Decrement return the new value", InterlockedIncrement(&v) == 6 && InterlockedDecrement(&v) == 5 && v == 5);
        check("InterlockedExchange/ExchangeAdd return the old value", InterlockedExchange(&v, 9) == 5 && InterlockedExchangeAdd(&v, 3) == 9 && v == 12);
        check("InterlockedCompareExchange stores only on a match", InterlockedCompareExchange(&v, 1, 99) == 12 && v == 12 && InterlockedCompareExchange(&v, 1, 12) == 12 && v == 1);
        volatile long long w = 0x100000002LL;
        check("InterlockedCompareExchange64 on a 64-bit value", InterlockedCompareExchange64(&w, 7, 0x100000002LL) == 0x100000002LL && w == 7 &&
              InterlockedCompareExchange64(&w, 8, 5) == 7 && w == 7);

        /* 64-bit file offsets and sizes. */
        static const WCHAR big[] = L"C:\\tmp\\api32-seek.bin";
        HANDLE f = CreateFileW(big, 0xC0000000, 0, 0, 2, 0x80, 0);
        DWORD wrote = 0;
        if (f != (HANDLE)-1) WriteFile(f, "0123456789", 10, &wrote, 0);
        long long size = -1, pos = -1;
        check("GetFileSizeEx writes a 64-bit size", f != (HANDLE)-1 && GetFileSizeEx(f, &size) && size == 10);
        check("SetFilePointerEx from the end with a negative 64-bit distance", SetFilePointerEx(f, -3, &pos, 2) && pos == 7);
        check("SetFilePointerEx from the start", SetFilePointerEx(f, 4, &pos, 0) && pos == 4);
        if (f != (HANDLE)-1) CloseHandle(f);
        DeleteFileW(big);

        /* Time. */
        SYSTIME32 y2k = { 2000, 1, 6, 1, 0, 0, 0, 0 }, now;
        unsigned long long ft = 0;
        check("SystemTimeToFileTime of 2000-01-01", SystemTimeToFileTime(&y2k, &ft) && ft == 0x01BF53EB256D4000ULL);
        GetSystemTime(&now);
        check("GetSystemTime fills 16 bytes with a plausible date", now.year >= 2024 && now.month >= 1 && now.month <= 12 && now.day >= 1 && now.day <= 31);
        check("VerSetConditionMask places a 64-bit condition", VerSetConditionMask(0, 2, 3) == 0x8000000000000018ULL);

        /* GlobalReAlloc keeps the contents. */
        char *g = GlobalAlloc(0, 8);
        if (g) { for (int i = 0; i < 8; i++) g[i] = (char)(i + 1); }
        char *g2 = g ? GlobalReAlloc(g, 64, 2) : 0;
        check("GlobalReAlloc grows and keeps the bytes", g2 && g2[0] == 1 && g2[7] == 8);

        /* Mappings and pipes with 32-bit pointers and handles. */
        HANDLE section = CreateFileMappingW((HANDLE)-1, 0, 4, 0, 4096, 0);
        SetLastError(0);
        volatile unsigned char *view = section ? MapViewOfFile(section, 2, 0, 0, 0) : 0;
        /* The kernel places shared views high; a 32-bit caller gets an error, never a truncated pointer. */
        check("page-file view of a 32-bit caller is refused with ERROR_NOT_ENOUGH_MEMORY or lies below 2 GiB and works",
              section && ((view == 0 && GetLastError() == 8) || ((DWORD)view < 0x80000000u && (view[0] = 0x5a, view[4095] = 0xa5, view[0] == 0x5a && view[4095] == 0xa5))));
        if (view) UnmapViewOfFile((const void *)view);
        SetLastError(0);
        check("UnmapViewOfFile of an address that is not a view fails with ERROR_INVALID_ADDRESS", !UnmapViewOfFile((const void *)0x12340000) && GetLastError() == 487);
        if (section) CloseHandle(section);
        HANDLE pr = 0, pw = 0;
        char got[4] = { 0 };
        DWORD n = 0;
        check("CreatePipe writes two 4-byte handles; data goes through", CreatePipe(&pr, &pw, 0, 0) && pr && pw && pr != pw &&
              WriteFile(pw, "abc", 3, &n, 0) && n == 3 && ReadFile(pr, got, 3, &n, 0) && n == 3 && got[0] == 'a' && got[2] == 'c');
        if (pr) CloseHandle(pr);
        if (pw) CloseHandle(pw);

        /* COM apartments: first call S_OK, second S_FALSE. */
        long first = CoInitialize(0), second = CoInitialize(0);
        check("CoInitialize: S_OK then S_FALSE", first == 0 && second == 1);
        CoUninitialize(); CoUninitialize();

        /* Security descriptors in the 20-byte layout of a 32-bit program. */
        struct { unsigned char sd[20]; DWORD guard[2]; unsigned char acl[64]; } sec = { { 0xff }, { 0xa5a5a5a5, 0xa5a5a5a5 }, { 0 } };
        unsigned char world[6] = { 0, 0, 0, 0, 0, 1 };
        void *sid = 0;
        check("AllocateAndInitializeSid writes a 4-byte pointer", AllocateAndInitializeSid(world, 1, 0, 0, 0, 0, 0, 0, 0, 0, &sid) && sid);
        check("SID checks: valid, 12 bytes, equal to itself", sid && IsValidSid(sid) && GetLengthSid(sid) == 12 && EqualSid(sid, sid));
        check("InitializeAcl, AddAccessAllowedAce, IsValidAcl", InitializeAcl(sec.acl, 64, 2) && AddAccessAllowedAce(sec.acl, 2, 0x1f01ff, sid) && IsValidAcl(sec.acl));
        check("InitializeSecurityDescriptor clears 20 bytes only", InitializeSecurityDescriptor(sec.sd, 1) && sec.sd[0] == 1 && sec.sd[1] == 0 && sec.guard[0] == 0xa5a5a5a5 && sec.guard[1] == 0xa5a5a5a5);
        void *back = 0, *owner = 0;
        BOOL present = 0, defaulted = 1;
        check("SetSecurityDescriptorDacl / GetSecurityDescriptorDacl round trip with 4-byte pointers",
              SetSecurityDescriptorDacl(sec.sd, 1, sec.acl, 0) && GetSecurityDescriptorDacl(sec.sd, &present, &back, &defaulted) &&
              present == 1 && back == (void *)sec.acl && defaulted == 0 && sec.guard[0] == 0xa5a5a5a5);
        check("SetSecurityDescriptorOwner / GetSecurityDescriptorOwner", SetSecurityDescriptorOwner(sec.sd, sid, 0) && GetSecurityDescriptorOwner(sec.sd, &owner, &defaulted) && owner == sid);
        check("IsValidSecurityDescriptor accepts it", IsValidSecurityDescriptor(sec.sd));
        {
            check("clear descriptor owner before creating directory", SetSecurityDescriptorOwner(sec.sd, 0, 0));
            struct { DWORD length; DWORD descriptor; int inherit; } attributes = { 12, (DWORD)sec.sd, 0 };
            static const WCHAR dir[] = L"C:\\tmp\\sd32built";
            RemoveDirectoryW(dir);
            check("CreateDirectoryW with an absolute descriptor built through the bridge", CreateDirectoryW(dir, &attributes));
            *(DWORD *)(sec.acl + 12) = 0x120089; /* Everyone: read, but not write. */
            check("SetFileSecurityW applies a PE32 absolute DACL", SetFileSecurityW(dir, 4, sec.sd));
            unsigned char *actual_acl = 0;
            void *actual_sd = 0;
            DWORD result = GetNamedSecurityInfoW(dir, 1, 4, 0, 0, (void **)&actual_acl, 0, &actual_sd);
            int no_everyone_write = 0;
            if (result == 0 && actual_acl) {
                unsigned char *ace = actual_acl + 8;
                for (int i = 0; i < 2; i++) ace += *(unsigned short *)(ace + 2);
                no_everyone_write = (*(DWORD *)(ace + 4) & 2) == 0;
            }
            check("PE32 absolute DACL changes permissions", result == 0 && no_everyone_write);
            if (actual_sd) LocalFree(actual_sd);
            RemoveDirectoryW(dir);
        }
        check("FreeSid returns NULL", FreeSid(sid) == 0);
    }

    {
        /* bcrypt and secur32 through the bridge: 4-byte handles, 4-byte pointers. */
        HANDLE alg = 0, hash = 0;
        unsigned char sum[32], mac[32];
        check("BCryptOpenAlgorithmProvider writes a 4-byte handle", BCryptOpenAlgorithmProvider(&alg, L"SHA256", 0, 0) == 0 && alg);
        check("BCryptCreateHash / HashData / FinishHash of abc",
              BCryptCreateHash(alg, &hash, 0, 0, 0, 0, 0) == 0 && BCryptHashData(hash, (unsigned char *)"abc", 3, 0) == 0 && BCryptFinishHash(hash, sum, 32, 0) == 0 &&
              sum[0] == 0xba && sum[1] == 0x78 && sum[2] == 0x16 && sum[3] == 0xbf && sum[30] == 0x15 && sum[31] == 0xad);
        DWORD digest_length = 0, got = 0;
        check("BCryptGetProperty(HashDigestLength)", BCryptGetProperty(alg, L"HashDigestLength", (unsigned char *)&digest_length, 4, &got, 0) == 0 && digest_length == 32 && got == 4);
        check("BCryptHash equals the streamed digest", BCryptHash(alg, 0, 0, (unsigned char *)"abc", 3, mac, 32) == 0 && mac[0] == sum[0] && mac[15] == sum[15] && mac[31] == sum[31]);
        check("BCryptFinishHash with a wrong size is STATUS_INVALID_PARAMETER", BCryptFinishHash(hash, sum, 31, 0) == (long)0xC0000008 || BCryptFinishHash(hash, sum, 31, 0) == (long)0xC000000D);
        check("BCryptDestroyHash", BCryptDestroyHash(hash) == 0);
        check("BCryptDestroyHash again is STATUS_INVALID_PARAMETER", BCryptDestroyHash(hash) == (long)0xC000000D);
        check("BCryptCloseAlgorithmProvider", BCryptCloseAlgorithmProvider(alg, 0) == 0);
        unsigned char random[16] = { 0 };
        int nonzero = 0;
        check("BCryptGenRandom with the system RNG", BCryptGenRandom(0, random, 16, 2) == 0);
        for (int i = 0; i < 16; i++) nonzero |= random[i] != 0;
        check("the random bytes are not all zero", nonzero);
        WCHAR user[4];
        DWORD user_size = 4;
        SetLastError(0);
        check("GetUserNameExW with a small buffer: ERROR_MORE_DATA and the size", !GetUserNameExW(2, user, &user_size) && GetLastError() == 234 && user_size > 4);
    }

    {
        /* msvcrt and the new kernel32 entries through PE32 gates (cdecl and stdcall). */
        HANDLE crt = LoadLibraryExW(L"msvcrt.dll", 0, 0);
        void *(__cdecl *crt_calloc)(unsigned, unsigned) = crt ? GetProcAddress(crt, "calloc") : 0;
        void (__cdecl *crt_free)(void *) = crt ? GetProcAddress(crt, "free") : 0;
        unsigned (__cdecl *crt_msize)(void *) = crt ? GetProcAddress(crt, "_msize") : 0;
        int (__cdecl *crt_wcsicmp)(const WCHAR *, const WCHAR *) = crt ? GetProcAddress(crt, "_wcsicmp") : 0;
        int (__cdecl *crt_wcsnicmp)(const WCHAR *, const WCHAR *, unsigned) = crt ? GetProcAddress(crt, "_wcsnicmp") : 0;
        WCHAR *(__cdecl *crt_wcsncpy)(WCHAR *, const WCHAR *, unsigned) = crt ? GetProcAddress(crt, "wcsncpy") : 0;
        const WCHAR *(__cdecl *crt_wcschr)(const WCHAR *, WCHAR) = crt ? GetProcAddress(crt, "wcschr") : 0;
        int (__cdecl *crt_iswalnum)(unsigned) = crt ? GetProcAddress(crt, "iswalnum") : 0;
        int (__cdecl *crt_iswalpha)(unsigned) = crt ? GetProcAddress(crt, "iswalpha") : 0;
        int (__cdecl *crt_iswcntrl)(unsigned) = crt ? GetProcAddress(crt, "iswcntrl") : 0;
        int (__cdecl *crt_iswspace)(unsigned) = crt ? GetProcAddress(crt, "iswspace") : 0;
        int (__cdecl *crt_rand)(void) = crt ? GetProcAddress(crt, "rand") : 0;
        void (__cdecl *crt_srand)(unsigned) = crt ? GetProcAddress(crt, "srand") : 0;
        void *(__cdecl *crt_new)(unsigned) = crt ? GetProcAddress(crt, "??2@YAPAXI@Z") : 0;
        void (__cdecl *crt_delete)(void *) = crt ? GetProcAddress(crt, "??3@YAXPAX@Z") : 0;
        char *block = crt_calloc ? crt_calloc(4, 8) : 0;
        int zeroed = block != 0;
        for (int i = 0; block && i < 32; i++) zeroed &= block[i] == 0;
        check("msvcrt calloc returns zeroed memory", zeroed);
        check("msvcrt _msize is at least the requested size", block && crt_msize && crt_msize(block) >= 32);
        if (block && crt_free) crt_free(block);
        char *cpp_block = crt_new && crt_delete ? crt_new(24) : 0;
        if (cpp_block) { cpp_block[0] = 'O'; cpp_block[23] = 'x'; }
        check("msvcrt PE32 C++ new and delete", cpp_block && cpp_block[0] == 'O' && cpp_block[23] == 'x');
        if (cpp_block) crt_delete(cpp_block);
        if (crt_delete) crt_delete(0);
        check("msvcrt _wcsicmp ignores case", crt_wcsicmp && crt_wcsicmp(L"Steam", L"sTEAM") == 0 && crt_wcsicmp(L"a", L"b") < 0);
        check("msvcrt _wcsnicmp compares n characters", crt_wcsnicmp && crt_wcsnicmp(L"SteamX", L"steamY", 5) == 0 && crt_wcsnicmp(L"SteamX", L"steamY", 6) != 0);
        WCHAR copied[5] = {1, 1, 1, 1, 1};
        check("msvcrt wcsncpy copies and pads", crt_wcsncpy && crt_wcsncpy(copied, L"ab", 4) == copied && copied[0] == 'a' && copied[1] == 'b' && copied[2] == 0 && copied[3] == 0 && copied[4] == 1);
        static const WCHAR text[] = L"Steam";
        check("msvcrt wcschr finds characters and terminator", crt_wcschr && crt_wcschr(text, 'e') == text + 2 && crt_wcschr(text, 0) == text + 5 && !crt_wcschr(text, 'z'));
        int (__cdecl *crt_wcscmp)(const WCHAR *, const WCHAR *) = crt ? GetProcAddress(crt, "wcscmp") : 0;
        int (__cdecl *crt_wcsncmp)(const WCHAR *, const WCHAR *, unsigned) = crt ? GetProcAddress(crt, "wcsncmp") : 0;
        WCHAR *(__cdecl *crt_wcscpy)(WCHAR *, const WCHAR *) = crt ? GetProcAddress(crt, "wcscpy") : 0;
        WCHAR *(__cdecl *crt_wcscat)(WCHAR *, const WCHAR *) = crt ? GetProcAddress(crt, "wcscat") : 0;
        unsigned (__cdecl *crt_towlower)(unsigned) = crt ? GetProcAddress(crt, "towlower") : 0;
        int (__cdecl *crt_iswdigit)(unsigned) = crt ? GetProcAddress(crt, "iswdigit") : 0;
        WCHAR wide_buffer[12] = {0};
        check("msvcrt wide string copies, appends and compares", crt_wcscmp && crt_wcsncmp && crt_wcscpy && crt_wcscat && crt_wcscpy(wide_buffer, L"Ste") == wide_buffer && crt_wcscat(wide_buffer, L"am") == wide_buffer && crt_wcscmp(wide_buffer, text) == 0 && crt_wcsncmp(wide_buffer, L"Step", 3) == 0);
        check("msvcrt wide digit and case conversion", crt_towlower && crt_iswdigit && crt_towlower('A') == 'a' && crt_iswdigit('9') && !crt_iswdigit('a'));
        int (__cdecl *snprintf32)(char *, unsigned, const char *, ...) = crt ? GetProcAddress(crt, "_snprintf") : 0;
        int (__cdecl *snwprintf32)(WCHAR *, unsigned, const WCHAR *, ...) = crt ? GetProcAddress(crt, "_snwprintf") : 0;
        char fmtbuf[12] = {0};
        WCHAR wfmtbuf[12] = {0};
        check("_snprintf formats PE32 variadic arguments", snprintf32 && snprintf32(fmtbuf, 12, "%s:%d", "os", 42) == 5 && fmtbuf[0] == 'o' && fmtbuf[2] == ':' && fmtbuf[4] == '2' && fmtbuf[5] == 0);
        fmtbuf[4] = 'X';
        check("_snprintf truncates without a terminator", snprintf32 && snprintf32(fmtbuf, 4, "%s", "hello") == -1 && fmtbuf[0] == 'h' && fmtbuf[3] == 'l' && fmtbuf[4] == 'X');
        check("_snprintf exact fit has no terminator", snprintf32 && snprintf32(fmtbuf, 4, "%s", "test") == 4 && fmtbuf[3] == 't' && fmtbuf[4] == 'X');
        check("_snwprintf formats PE32 wide variadic arguments", snwprintf32 && snwprintf32(wfmtbuf, 12, L"%s:%u", L"os", 42) == 5 && wide_eq(wfmtbuf, "os:42"));
        wfmtbuf[4] = 'X';
        check("_snwprintf truncates in wide characters", snwprintf32 && snwprintf32(wfmtbuf, 4, L"%s", L"hello") == -1 && wfmtbuf[3] == 'l' && wfmtbuf[4] == 'X');
        check("_snprintf consumes 64-bit PE32 arguments", snprintf32 && snprintf32(fmtbuf, 12, "%I64x", 0x123456789ULL) == 9 && fmtbuf[0] == '1' && fmtbuf[8] == '9' && fmtbuf[9] == 0);
        int (__cdecl *crt_time)(int *) = crt ? GetProcAddress(crt, "time") : 0;
        struct { int seconds; DWORD guard; } now = { 0, 0xa5a5a5a5 };
        int time_result = crt_time ? crt_time(&now.seconds) : -1;
        check("msvcrt PE32 time writes exactly four bytes", crt_time && time_result > 0 && now.seconds == time_result && now.guard == 0xa5a5a5a5 && crt_time(0) >= time_result);
        check("msvcrt wide character classes", crt_iswalnum && crt_iswalpha && crt_iswcntrl && crt_iswspace && crt_iswalnum('3') && !crt_iswalnum('!') && crt_iswalpha('A') && !crt_iswalpha('3') && crt_iswcntrl('\n') && !crt_iswcntrl('A') && crt_iswspace(' ') && !crt_iswspace('A'));
        if (crt_srand) crt_srand(1);
        int first_rand = crt_rand ? crt_rand() : -1;
        if (crt_srand) crt_srand(1);
        check("msvcrt srand resets rand sequence", crt_srand && crt_rand && first_rand == 41 && crt_rand() == first_rand);
        HANDLE user = LoadLibraryExW(L"user32.dll", 0, 0);
        int (__stdcall *msg_a)(HANDLE, const char *, const char *, DWORD) = user ? GetProcAddress(user, "MessageBoxA") : 0;
        int (__stdcall *msg_w)(HANDLE, const WCHAR *, const WCHAR *, DWORD) = user ? GetProcAddress(user, "MessageBoxW") : 0;
        SetLastError(0);
        check("MessageBoxA bridge rejects unsupported button sets", msg_a && !msg_a(0, "test", "test", 2) && GetLastError() == 50);
        SetLastError(0);
        check("MessageBoxW bridge rejects unsupported button sets", msg_w && !msg_w(0, L"test", L"test", 2) && GetLastError() == 50);
        HANDLE (__stdcall *create_event)(void *, BOOL, BOOL, const WCHAR *) = GetProcAddress(kernel, "CreateEventW");
        BOOL (__stdcall *set_event)(HANDLE) = GetProcAddress(kernel, "SetEvent");
        BOOL (__stdcall *reset_event)(HANDLE) = GetProcAddress(kernel, "ResetEvent");
        DWORD (__stdcall *msg_wait)(DWORD, const HANDLE *, BOOL, DWORD, DWORD) = user ? GetProcAddress(user, "MsgWaitForMultipleObjects") : 0;
        HANDLE events[2] = { 0, 0 };
        if (create_event) { events[0] = create_event(0, 1, 0, 0); events[1] = create_event(0, 1, 1, 0); }
        check("MsgWait reads PE32 handle arrays", msg_wait && events[0] && events[1] && msg_wait(2, events, 0, 0, 0) == 1);
        check("event bridge resets and signals", msg_wait && set_event && reset_event && events[0] && events[1] && reset_event(events[1]) && msg_wait(2, events, 0, 0, 0) == 258 && set_event(events[0]) && msg_wait(2, events, 0, 0, 0) == 0);
        check("MsgWait rejects null handle arrays", msg_wait && msg_wait(1, 0, 0, 0, 0) == (DWORD)-1);
        DWORD (__stdcall *wait_many)(DWORD, const HANDLE *, BOOL, DWORD) = GetProcAddress(kernel, "WaitForMultipleObjects");
        DWORD (__stdcall *wait_many_ex)(DWORD, const HANDLE *, BOOL, DWORD, BOOL) = GetProcAddress(kernel, "WaitForMultipleObjectsEx");
        DWORD (__stdcall *msg_wait_ex)(DWORD, const HANDLE *, DWORD, DWORD, DWORD) = user ? GetProcAddress(user, "MsgWaitForMultipleObjectsEx") : 0;
        check("WaitForMultipleObjects reads PE32 arrays", wait_many && events[0] && events[1] && wait_many(2, events, 0, 0) == 0 && wait_many(2, events, 1, 0) == 258);
        check("WaitForMultipleObjectsEx reads PE32 arrays", wait_many_ex && events[0] && events[1] && wait_many_ex(2, events, 0, 0, 0) == 0 && wait_many_ex(2, events, 1, 0, 0) == 258);
        check("MsgWaitForMultipleObjectsEx reads PE32 arrays", msg_wait_ex && events[0] && events[1] && msg_wait_ex(2, events, 0, 0, 0) == 0 && msg_wait_ex(1, 0, 0, 0, 0) == (DWORD)-1);
        BOOL (__stdcall *post_a)(HANDLE, DWORD, DWORD, long) = user ? GetProcAddress(user, "PostMessageA") : 0;
        BOOL (__stdcall *peek_a)(void *, HANDLE, DWORD, DWORD, DWORD) = user ? GetProcAddress(user, "PeekMessageA") : 0;
        BOOL (__stdcall *get_a)(void *, HANDLE, DWORD, DWORD) = user ? GetProcAddress(user, "GetMessageA") : 0;
        struct { DWORD hwnd, message, wparam, lparam, time; long x, y; DWORD guard; } queued = {0};
        queued.guard = 0xabcddcba;
        BOOL posted = post_a && post_a(0, 0x8401, 0x1234, -9);
        check("MsgWaitEx observes posted thread messages", posted && msg_wait_ex && msg_wait_ex(0, 0, 0, 8, 4) == 0);
        check("PeekMessageA reads PE32 MSG without removing it", posted && peek_a && peek_a(&queued, 0, 0x8401, 0x8401, 0) && queued.message == 0x8401 && queued.wparam == 0x1234 && queued.lparam == (DWORD)-9 && queued.guard == 0xabcddcba);
        check("GetMessageA removes PE32 message", posted && get_a && get_a(&queued, 0, 0x8401, 0x8401) && queued.message == 0x8401 && queued.guard == 0xabcddcba);
        HANDLE (__stdcall *create_event_a)(void *, BOOL, BOOL, const char *) = GetProcAddress(kernel, "CreateEventA");
        HANDLE (__stdcall *open_event_a)(DWORD, BOOL, const char *) = GetProcAddress(kernel, "OpenEventA");
        HANDLE (__stdcall *create_event_ex)(void *, const WCHAR *, DWORD, DWORD) = GetProcAddress(kernel, "CreateEventExW");
        HANDLE named = create_event_a ? create_event_a(0, 1, 0, "OSyxApi32Event") : 0;
        HANDLE opened = open_event_a ? open_event_a(0, 0, "OSyxApi32Event") : 0;
        HANDLE ex_event = create_event_ex ? create_event_ex(0, 0, 3, 0x1f0003) : 0;
        check("ANSI named event opens the same object", named && opened && set_event && set_event(named) && WaitForSingleObject(opened, 0) == 0);
        check("CreateEventExW creates a signalled event", ex_event && WaitForSingleObject(ex_event, 0) == 0);
        if (named) CloseHandle(named);
        if (opened) CloseHandle(opened);
        if (ex_event) CloseHandle(ex_event);
        if (events[0]) CloseHandle(events[0]);
        if (events[1]) CloseHandle(events[1]);
        BOOL (__stdcall *set_info)(HANDLE, DWORD, void *, DWORD) = GetProcAddress(kernel, "HeapSetInformation");
        DWORD lfh = 2, bad = 9;
        check("HeapSetInformation accepts the low-fragmentation hint", set_info && set_info(0, 0, &lfh, 4));
        SetLastError(0);
        check("HeapSetInformation rejects an unknown class", set_info && !set_info(0, 77, &lfh, 4) && GetLastError() == 87);
        SetLastError(0);
        check("HeapSetInformation rejects an out-of-range value", set_info && !set_info(0, 0, &bad, 4) && GetLastError() == 87);
    }

    check("lstrcmpiA ignores case", lstrcmpiA("Steam", "sTEAM") == 0 && lstrcmpiA("a", "b") < 0);
    check("MulDiv rounds and rejects /0", MulDiv(10, 3, 4) == 8 && MulDiv(-10, 3, 4) == -8 && MulDiv(1, 1, 0) == -1);
    check("GetTickCount advances", GetTickCount() != 0);

    WCHAR *cmd = GetCommandLineW();
    check("GetCommandLineW is a readable 32-bit pointer", cmd != 0 && lstrlenW(cmd) > 0);

    char *mem = GlobalAlloc(GPTR, 4096);
    int zero = mem != 0;
    for (int i = 0; zero && i < 4096; i++) zero = mem[i] == 0;
    if (mem) mem[4095] = 1;
    check("GlobalAlloc(GPTR) returns zeroed 32-bit memory", zero && mem[4095] == 1);
    check("GlobalFree", mem && GlobalFree(mem) == 0);

    static const WCHAR ini[] = L"C:\\tmp\\api32.ini";
    WCHAR buf[64];
    DeleteFileW(ini);
    check("WritePrivateProfileStringW", WritePrivateProfileStringW(L"Setup", L"Path", L"C:\\Steam", ini));
    DWORD n = GetPrivateProfileStringW(L"setup", L"PATH", L"none", buf, 64, ini);
    check("GetPrivateProfileStringW reads it back", n == 8 && wide_eq(buf, "C:\\Steam"));
    n = GetPrivateProfileStringW(L"Setup", L"Missing", L"none", buf, 64, ini);
    check("GetPrivateProfileStringW default", n == 4 && wide_eq(buf, "none"));
    WritePrivateProfileStringW(L"Setup", L"Quoted", L"\"C:\\Program Files\"", ini);
    n = GetPrivateProfileStringW(L"Setup", L"Quoted", L"", buf, 64, ini);
    check("GetPrivateProfileStringW strips enclosing quotes", n == 16 && wide_eq(buf, "C:\\Program Files"));
    DeleteFileW(ini);
    buf[0] = buf[1] = 'x';
    n = GetPrivateProfileStringW(0, 0, L"none", buf, 64, ini);
    check("missing file: section list is empty", n == 0 && buf[0] == 0 && buf[1] == 0);

    /* An ANSI (non-UTF-8) byte in another line survives an update. */
    static const char ansi[] = "[A]\r\nk=caf\xe9\r\n";
    DWORD w;
    HANDLE f = CreateFileW(ini, 0x40000000, 0, 0, 2 /* CREATE_ALWAYS */, 0, 0);
    WriteFile(f, ansi, sizeof ansi - 1, &w, 0);
    CloseHandle(f);
    WritePrivateProfileStringW(L"A", L"n", L"1", ini);
    char raw[64];
    DWORD got_bytes = 0;
    f = CreateFileW(ini, 0x80000000, 1, 0, 3 /* OPEN_EXISTING */, 0, 0);
    ReadFile(f, raw, sizeof raw, &got_bytes, 0);
    CloseHandle(f);
    int e9 = 0, c3 = 0;
    for (DWORD i = 0; i < got_bytes; i++) e9 += (unsigned char)raw[i] == 0xe9, c3 += (unsigned char)raw[i] == 0xc3;
    check("WritePrivateProfileStringW keeps ANSI bytes", e9 == 1 && c3 == 0);
    DeleteFileW(ini);

    HKEY key = (HKEY)0x12345678;
    DWORD disp = 0;
    long e = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\OSyx\\api32", 0, 0, 0, KEY_ALL_ACCESS, 0, &key, &disp);
    char line[96];
    check(with_hex(line, "RegCreateKeyExW writes a 32-bit HKEY, error", (unsigned long)e),
          e == 0 && key != (HKEY)0x12345678 && key != 0);
    DWORD value = 0x5a5a1234, type = 0, got = 0, size = sizeof got;
    check("RegSetValueExW", e == 0 && RegSetValueExW(key, L"value", 0, REG_DWORD, &value, sizeof value) == 0);
    check("RegQueryValueExW", e == 0 && RegQueryValueExW(key, L"value", 0, &type, &got, &size) == 0 && type == REG_DWORD &&
                                  got == value && size == 4);
    HKEY child = 0;
    long child_result = RegCreateKeyExW(key, L"Child", 0, 0, 0, KEY_ALL_ACCESS, 0, &child, 0);
    check("RegEnumKeyW enumerates subkey", child_result == 0 && RegEnumKeyW(key, 0, buf, 64) == 0 && wide_eq(buf, "Child"));
    check("RegEnumKeyW rejects short buffer", RegEnumKeyW(key, 0, buf, 2) != 0);
    if (child) RegCloseKey(child);
    RegDeleteKeyW(key, L"Child");
    check("RegCloseKey", e == 0 && RegCloseKey(key) == 0);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\OSyx\\api32");

    /* CreateProcessW: the 32-bit STARTUPINFOW (68 bytes) and
     * PROCESS_INFORMATION (16 bytes, 4-byte handles) are converted; the
     * child is hello32.exe from this program's directory, which exits 7. */
    {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        WCHAR cmdline[] = L"hello32.exe";
        for (int i = 0; i < (int)sizeof si; i++) ((char *)&si)[i] = 0;
        for (int i = 0; i < (int)sizeof pi; i++) ((char *)&pi)[i] = 0;
        si.cb = sizeof si;
        BOOL made = CreateProcessW(0, cmdline, 0, 0, 0, 0, 0, 0, &si, &pi);
        check("CreateProcessW starts a 32-bit child", made && pi.hProcess && pi.hThread && pi.dwProcessId);
        DWORD code = 0;
        if (made) {
            WaitForSingleObject(pi.hProcess, 20000);
            GetExitCodeProcess(pi.hProcess, &code);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        check(with_hex(line, "GetExitCodeProcess returns the child's exit code", code), made && code == 7);
        BOOL missing = CreateProcessW(L"no-such-program32.exe", 0, 0, 0, 0, 0, 0, 0, &si, &pi);
        check("CreateProcessW reports a missing program", !missing);
    }

    say(failed ? "api32: summary FAIL" : "api32: summary ok", "");
    ExitProcess(failed);
}
