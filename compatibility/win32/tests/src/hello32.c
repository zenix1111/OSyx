/* Target: a 32-bit (PE32/i386) console program that proves the OSyx loader
 * maps a WoW64-style image and executes i386 code. Freestanding: no C
 * runtime, only kernel32 imports through an import library built from
 * kernel32_x86.def (the OSyx loader resolves imports by undecorated name).
 *
 * The i686 ABI decorates stdcall symbols (_GetStdHandle@4); the import
 * library therefore carries decorated symbols while the import table keeps
 * the plain names. This program runs only under /bin/winrun inside QEMU
 * (scripts/win-test.ps1); it exits 7 so the check can tell it apart from a
 * loader failure. */
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;

/* STD_OUTPUT_HANDLE from winbase.h. */
#define STD_OUTPUT_HANDLE ((DWORD)-11)

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD std_handle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE file, const void *buf,
                                               DWORD len, DWORD *written, void *overlapped);
__declspec(dllimport) void __stdcall ExitProcess(DWORD code);

void __stdcall start(void) {
    static const char msg[] = "hello32: 32-bit code ran\n";
    static const char failed[] = "hello32: WriteFile failed\n";
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    if (!out || out == (HANDLE)(long)-1) {
        ExitProcess(1);
    }
    if (!WriteFile(out, msg, sizeof(msg) - 1, &written, 0) || written != sizeof(msg) - 1) {
        WriteFile(out, failed, sizeof(failed) - 1, &written, 0);
        ExitProcess(1);
    }
    ExitProcess(7);
}
