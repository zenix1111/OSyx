/* Regression tests of APIs that used to return success without doing
 * anything: heaps (HeapCreate/Destroy/Validate/Lock/Unlock), critical
 * section deletion, DisableThreadLibraryCalls, SetForegroundWindow,
 * BringWindowToTop, TrackPopupMenu, DeleteProcThreadAttributeList.
 * Expected results come from real Windows where it defines them; where
 * Windows would crash on a bad handle, OSyx fails with an error and the
 * test names say so. */
#include "common.h"
#include <shlobj.h>
#include <imm.h>
#include <wininet.h>
#include <winuser.h>

static HANDLE gheap;
static volatile LONG started, finished;

static DWORD WINAPI heap_worker(void *unused) {
    (void)unused;
    started = 1;
    void *p = HeapAlloc(gheap, 0, 16);
    finished = 1;
    if (p) HeapFree(gheap, 0, p);
    return 0;
}

static void wait_started(void) {
    for (int i = 0; i < 200 && !started; i++) Sleep(5);
}

static void heaps(void) {
    HANDLE process = GetProcessHeap();
    SetLastError(0);
    check("HeapDestroy(process heap) fails with ERROR_INVALID_HANDLE", !HeapDestroy(process) && GetLastError() == ERROR_INVALID_HANDLE);
    check("HeapDestroy(NULL) succeeds as on Windows", HeapDestroy(NULL));

    HANDLE h = HeapCreate(0, 0, 0);
    check("HeapCreate returns a heap distinct from the process heap", h && h != process);
    void *p = HeapAlloc(h, HEAP_ZERO_MEMORY, 100);
    check("HeapAlloc from a private heap, zeroed", p && ((unsigned char *)p)[0] == 0 && ((unsigned char *)p)[99] == 0);
    check("HeapSize of the block", HeapSize(h, 0, p) == 100);
    check("HeapValidate(heap, block)", HeapValidate(h, 0, p));
    check("HeapValidate(heap, NULL) walks the heap", HeapValidate(h, 0, NULL));
    SetLastError(0);
    check("HeapValidate(process heap, private block) is FALSE", !HeapValidate(process, 0, p));
    SetLastError(0);
    check("HeapFree(process heap, private block) fails with ERROR_INVALID_PARAMETER (Windows would corrupt)",
          !HeapFree(process, 0, p) && GetLastError() == ERROR_INVALID_PARAMETER);
    check("HeapSize(process heap, private block) is (SIZE_T)-1", HeapSize(process, 0, p) == (SIZE_T)-1);
    check("HeapFree(heap, NULL) succeeds", HeapFree(h, 0, NULL));

    unsigned char *q = HeapAlloc(h, 0, 8);
    for (int i = 0; i < 8; i++) q[i] = (unsigned char)(i + 1);
    unsigned char *r = HeapReAlloc(h, HEAP_ZERO_MEMORY, q, 64);
    check("HeapReAlloc keeps the contents and zeroes the growth", r && r[7] == 8 && r[8] == 0 && r[63] == 0 && HeapSize(h, 0, r) == 64);
    check("HeapReAlloc with HEAP_REALLOC_IN_PLACE_ONLY refuses to grow", HeapReAlloc(h, HEAP_REALLOC_IN_PLACE_ONLY, r, 4096) == NULL);
    check("the refused block is still valid", HeapValidate(h, 0, r) && HeapSize(h, 0, r) == 64);

    PROCESS_HEAP_ENTRY entry = { 0 };
    int walked = 0;
    SIZE_T sizes = 0;
    while (HeapWalk(h, &entry)) {
        if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) { walked++; sizes += entry.cbData; }
    }
    check("HeapWalk visits the two live blocks of a private heap", walked == 2 && sizes == 164 && GetLastError() == ERROR_NO_MORE_ITEMS);
    SetLastError(0);
    PROCESS_HEAP_ENTRY first = { 0 };
    check("HeapWalk of the process heap fails with ERROR_NOT_SUPPORTED", !HeapWalk(process, &first) && GetLastError() == ERROR_NOT_SUPPORTED);

    HANDLE list[16];
    DWORD n = GetProcessHeaps(16, list);
    int found = 0, found_process = 0;
    for (DWORD i = 0; i < n && i < 16; i++) { found += list[i] == h; found_process += list[i] == process; }
    check("GetProcessHeaps lists the process heap and the private heap", found == 1 && found_process == 1);

    /* HeapLock: re-entrant, and another thread's heap calls wait for it. */
    gheap = h; started = 0; finished = 0;
    check("HeapLock", HeapLock(h));
    check("HeapLock again (re-entrant)", HeapLock(h));
    HANDLE t = CreateThread(NULL, 0, heap_worker, NULL, 0, NULL);
    wait_started();
    Sleep(60);
    check("HeapAlloc of another thread waits while the heap is locked", t && started && !finished);
    check("HeapUnlock (one level)", HeapUnlock(h));
    Sleep(60);
    check("still locked after one HeapUnlock of two", !finished);
    check("HeapUnlock (last level)", HeapUnlock(h));
    check("the waiting thread continues", t && WaitForSingleObject(t, 3000) == WAIT_OBJECT_0 && finished);
    if (t) CloseHandle(t);
    SetLastError(0);
    check("HeapUnlock of an unlocked heap succeeds as on Windows", HeapUnlock(h) && GetLastError() == 0);

    check("HeapLock/HeapUnlock of the process heap", HeapLock(process) && HeapLock(process) && HeapUnlock(process) && HeapUnlock(process));

    check("HeapDestroy(heap)", HeapDestroy(h));
    SetLastError(0);
    check("HeapDestroy of a destroyed heap fails with ERROR_INVALID_HANDLE (Windows would crash)", !HeapDestroy(h) && GetLastError() == ERROR_INVALID_HANDLE);
    SetLastError(0);
    check("HeapAlloc from a destroyed heap fails with ERROR_INVALID_HANDLE", HeapAlloc(h, 0, 8) == NULL && GetLastError() == ERROR_INVALID_HANDLE);
    SetLastError(0);
    check("HeapValidate of a destroyed heap fails with ERROR_INVALID_HANDLE", !HeapValidate(h, 0, NULL) && GetLastError() == ERROR_INVALID_HANDLE);
    SetLastError(0);
    check("HeapLock of a destroyed heap fails with ERROR_INVALID_HANDLE", !HeapLock(h) && GetLastError() == ERROR_INVALID_HANDLE);
    n = GetProcessHeaps(16, list);
    found = 0;
    for (DWORD i = 0; i < n && i < 16; i++) found += list[i] == h;
    check("GetProcessHeaps no longer lists it", found == 0);

    /* A fixed-size heap (maximum size given) refuses what does not fit. */
    HANDLE fixed = HeapCreate(0, 0, 0x10000);
    SetLastError(0);
    void *big = HeapAlloc(fixed, 0, 0x20000);
    check("HeapAlloc beyond a fixed heap's maximum fails with ERROR_NOT_ENOUGH_MEMORY", big == NULL && GetLastError() == ERROR_NOT_ENOUGH_MEMORY);
    void *fits = HeapAlloc(fixed, 0, 0x8000);
    check("HeapAlloc within the maximum succeeds", fits != NULL);
    check("a second allocation that no longer fits fails", HeapAlloc(fixed, 0, 0x9000) == NULL);
    HeapFree(fixed, 0, fits);
    check("freeing makes room again", HeapAlloc(fixed, 0, 0x9000) != NULL);
    check("HeapDestroy releases the blocks that were left", HeapDestroy(fixed));
}

static void critical_sections(void) {
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    EnterCriticalSection(&cs);
    EnterCriticalSection(&cs);
    check("TryEnterCriticalSection by the owner", TryEnterCriticalSection(&cs));
    LeaveCriticalSection(&cs); LeaveCriticalSection(&cs); LeaveCriticalSection(&cs);
    DeleteCriticalSection(&cs);
    unsigned char *b = (unsigned char *)&cs;
    int nonzero = 0;
    for (unsigned i = 0; i < sizeof cs; i++) nonzero += b[i] != 0;
    check("DeleteCriticalSection clears the structure", nonzero == 0 && cs.LockCount == 0 && cs.OwningThread == 0);
    InitializeCriticalSection(&cs);
    check("a deleted section can be initialised again and entered", TryEnterCriticalSection(&cs));
    LeaveCriticalSection(&cs);
    DeleteCriticalSection(&cs);
}

static DWORD WINAPI idle_thread(void *unused) { (void)unused; return 0; }

static void run_thread(void) {
    HANDLE t = CreateThread(NULL, 0, idle_thread, NULL, 0, NULL);
    if (t) { WaitForSingleObject(t, 3000); CloseHandle(t); }
    Sleep(20);
}

static void thread_library_calls(void) {
    SetLastError(0);
    check("DisableThreadLibraryCalls(NULL) fails with ERROR_MOD_NOT_FOUND", !DisableThreadLibraryCalls(NULL) && GetLastError() == ERROR_MOD_NOT_FOUND);
    SetLastError(0);
    check("DisableThreadLibraryCalls(bogus) fails with ERROR_MOD_NOT_FOUND", !DisableThreadLibraryCalls((HMODULE)0x1234) && GetLastError() == ERROR_MOD_NOT_FOUND);
    check("DisableThreadLibraryCalls(the program)", DisableThreadLibraryCalls(GetModuleHandleA(NULL)));

    HMODULE dll = LoadLibraryA("thrdll.dll");
    check("LoadLibraryA(thrdll.dll)", dll != NULL);
    if (!dll) return;
    LONG (*attaches)(void) = (LONG (*)(void))GetProcAddress(dll, "thread_attach_count");
    BOOL (*disable)(void) = (BOOL (*)(void))GetProcAddress(dll, "disable_calls");
    if (!attaches || !disable) { check("thrdll exports", 0); return; }
    LONG before = attaches();
    run_thread();
    check("a new thread reaches DllMain with DLL_THREAD_ATTACH", attaches() == before + 1);
    check("DisableThreadLibraryCalls(the DLL)", disable());
    LONG after = attaches();
    run_thread();
    run_thread();
    check("no DLL_THREAD_ATTACH after DisableThreadLibraryCalls", attaches() == after);
    FreeLibrary(dll);
}

static void windows_and_menus(void) {
    SetLastError(0);
    check("SetForegroundWindow(NULL) fails with ERROR_INVALID_WINDOW_HANDLE", !SetForegroundWindow(NULL) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);
    SetLastError(0);
    check("SetForegroundWindow(bogus) fails with ERROR_INVALID_WINDOW_HANDLE", !SetForegroundWindow((HWND)0x1234) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);
    SetLastError(0);
    check("BringWindowToTop(bogus) fails with ERROR_INVALID_WINDOW_HANDLE", !BringWindowToTop((HWND)0x1234) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);
    HMENU menu = CreatePopupMenu();
    SetLastError(0);
    check("TrackPopupMenu fails with ERROR_NOT_SUPPORTED instead of pretending a menu was shown",
          menu && !TrackPopupMenu(menu, 0, 0, 0, 0, NULL, NULL) && GetLastError() == ERROR_NOT_SUPPORTED);
    if (menu) DestroyMenu(menu);
}

static void without_windows(void) {
    DOCINFOW doc = { sizeof doc };
    SetLastError(0);
    check("StartDocW on a non-printer DC fails with SP_ERROR and ERROR_INVALID_HANDLE", StartDocW((HDC)0x1234, &doc) == -1 && GetLastError() == ERROR_INVALID_HANDLE);
    SetLastError(0);
    check("EndDoc on a non-printer DC fails with SP_ERROR and ERROR_INVALID_HANDLE", EndDoc((HDC)0x1234) == -1 && GetLastError() == ERROR_INVALID_HANDLE);
    SetLastError(0);
    check("StartPage/EndPage/AbortDoc on a non-printer DC fail with SP_ERROR", StartPage((HDC)0x1234) == -1 && EndPage((HDC)0x1234) == -1 && AbortDoc((HDC)0x1234) == -1 && GetLastError() == ERROR_INVALID_HANDLE);

    RECT clip = { 0, 0, 10, 10 };
    check("ClipCursor(NULL) releases a clip", ClipCursor(NULL));
    SetLastError(0);
    check("ClipCursor(rect) fails with ERROR_NOT_SUPPORTED (PRISM cannot confine the pointer)", !ClipCursor(&clip) && GetLastError() == ERROR_NOT_SUPPORTED);

    int count = ShowCursor(TRUE);
    check("ShowCursor keeps a display counter", ShowCursor(FALSE) == count - 1 && ShowCursor(FALSE) == count - 2 && ShowCursor(TRUE) == count - 1 && ShowCursor(TRUE) == count);

    check("GetMessageExtraInfo starts at 0", GetMessageExtraInfo() == 0);
    check("SetMessageExtraInfo returns the old value and GetMessageExtraInfo the new one", SetMessageExtraInfo(77) == 0 && GetMessageExtraInfo() == 77 && SetMessageExtraInfo(0) == 77);

    int element[1] = { COLOR_BTNFACE };
    COLORREF old = GetSysColor(COLOR_BTNFACE), color = RGB(1, 2, 3);
    check("SetSysColors changes GetSysColor", SetSysColors(1, element, &color) && GetSysColor(COLOR_BTNFACE) == color);
    SetSysColors(1, element, &old);
    check("SetSysColors restores the colour", GetSysColor(COLOR_BTNFACE) == old);
    int bad[1] = { 99 };
    SetLastError(0);
    check("SetSysColors rejects an index outside 0..30 with ERROR_INVALID_PARAMETER", !SetSysColors(1, bad, &color) && GetLastError() == ERROR_INVALID_PARAMETER);

    SetLastError(0);
    check("UnhookWinEvent(bogus) fails with ERROR_INVALID_HANDLE", !UnhookWinEvent((HWINEVENTHOOK)0x1234) && GetLastError() == ERROR_INVALID_HANDLE);
    SetLastError(0);
    check("SetThreadDesktop(bogus) fails with ERROR_INVALID_HANDLE", !SetThreadDesktop((HDESK)0x1234) && GetLastError() == ERROR_INVALID_HANDLE);
    SetLastError(0);
    check("MessageBeep returns TRUE for the default beep and for every icon, as Windows does", MessageBeep(MB_OK) && MessageBeep(MB_ICONHAND) && MessageBeep(MB_ICONQUESTION) && MessageBeep(MB_ICONEXCLAMATION) && MessageBeep(MB_ICONASTERISK) && MessageBeep(0xFFFFFFFF));
    check("ReplyMessage outside a sent message fails", !ReplyMessage(0));

    check("ImmGetOpenStatus(NULL) is FALSE", !ImmGetOpenStatus(NULL));
    check("ImmGetCompositionStringW(NULL) is 0", ImmGetCompositionStringW(NULL, GCS_COMPSTR, NULL, 0) == 0);
    check("ImmReleaseContext(window, NULL) succeeds as on Windows", ImmReleaseContext((HWND)0x1234, NULL));
    SetLastError(0);
    check("ImmGetContext(bogus) fails with ERROR_INVALID_WINDOW_HANDLE", ImmGetContext((HWND)0x1234) == NULL && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);

    check("InternetAttemptConnect succeeds while an adapter has an address", InternetAttemptConnect(0) == ERROR_SUCCESS);

    static const WCHAR recent[] = L"C:\\tmp\\recent-test.txt";
    WCHAR folder[MAX_PATH], link[MAX_PATH];
    check("CSIDL_RECENT resolves", SHGetFolderPathW(NULL, CSIDL_RECENT | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, folder) == S_OK);
    int n = 0;
    while (folder[n]) { link[n] = folder[n]; n++; }
    static const WCHAR tail[] = L"\\recent-test.txt.lnk";
    for (int i = 0; i < 20; i++) link[n + i] = tail[i];
    DeleteFileW(link);
    SHAddToRecentDocs(SHARD_PATHW, recent);
    DWORD attributes = GetFileAttributesW(link);
    check("SHAddToRecentDocs makes a shortcut in the Recent folder", attributes != INVALID_FILE_ATTRIBUTES);
    BYTE header[4] = { 0 };
    DWORD got = 0;
    HANDLE f = CreateFileW(link, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) { ReadFile(f, header, 4, &got, NULL); CloseHandle(f); }
    check("the shortcut starts with the Shell Link header size 0x4C", got == 4 && header[0] == 0x4c && header[1] == 0 && header[2] == 0 && header[3] == 0);
    SHAddToRecentDocs(SHARD_PATHW, NULL);
    check("SHAddToRecentDocs(NULL) empties the Recent folder", GetFileAttributesW(link) == INVALID_FILE_ATTRIBUTES);
}

static void wininet_and_desktops(void) {
    check("InternetCheckConnectionW reports the connection state", InternetCheckConnectionW(L"http://example.com", 0, 0) == (InternetAttemptConnect(0) == ERROR_SUCCESS));
    SetLastError(0);
    check("InternetCheckConnectionW with a reserved value fails with ERROR_INVALID_PARAMETER", !InternetCheckConnectionW(NULL, 0, 1) && GetLastError() == ERROR_INVALID_PARAMETER);
    SetLastError(0);
    check("InternetCheckConnectionW(FLAG_ICC_FORCE_CONNECTION) fails with ERROR_NOT_SUPPORTED", !InternetCheckConnectionW(L"http://example.com", FLAG_ICC_FORCE_CONNECTION, 0) && GetLastError() == ERROR_NOT_SUPPORTED);
    SetLastError(0);
    check("InternetCloseHandle(bogus) fails with ERROR_INVALID_HANDLE", !InternetCloseHandle((HINTERNET)0x1234) && GetLastError() == ERROR_INVALID_HANDLE);
    check("InternetSetOptionW(NULL, SETTINGS_CHANGED) succeeds", InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0));
    SetLastError(0);
    check("InternetSetOptionW with an unknown option fails with ERROR_INTERNET_INVALID_OPTION", !InternetSetOptionW(NULL, 9999, NULL, 0) && GetLastError() == ERROR_INTERNET_INVALID_OPTION);
    SetLastError(0);
    check("InternetSetOptionW on a bogus handle fails with ERROR_INVALID_HANDLE", !InternetSetOptionW((HINTERNET)0x1234, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0) && GetLastError() == ERROR_INVALID_HANDLE);

    HDESK input = OpenInputDesktop(0, FALSE, GENERIC_ALL);
    check("OpenInputDesktop returns a handle", input != NULL);
    check("CloseDesktop releases it", input && CloseDesktop(input));
    SetLastError(0);
    check("CloseDesktop of a released handle fails with ERROR_INVALID_HANDLE", !CloseDesktop(input) && GetLastError() == ERROR_INVALID_HANDLE);
    SetLastError(0);
    check("OpenInputDesktop with unknown flags fails with ERROR_INVALID_PARAMETER", OpenInputDesktop(0x80, FALSE, GENERIC_ALL) == NULL && GetLastError() == ERROR_INVALID_PARAMETER);
}

static void interlocked(void) {
    HMODULE k = GetModuleHandleA("kernel32.dll");
    LONG (WINAPI *inc)(volatile LONG *) = (LONG (WINAPI *)(volatile LONG *))GetProcAddress(k, "InterlockedIncrement");
    LONG (WINAPI *dec)(volatile LONG *) = (LONG (WINAPI *)(volatile LONG *))GetProcAddress(k, "InterlockedDecrement");
    LONG (WINAPI *xchg)(volatile LONG *, LONG) = (LONG (WINAPI *)(volatile LONG *, LONG))GetProcAddress(k, "InterlockedExchange");
    LONG (WINAPI *add)(volatile LONG *, LONG) = (LONG (WINAPI *)(volatile LONG *, LONG))GetProcAddress(k, "InterlockedExchangeAdd");
    LONG (WINAPI *cas)(volatile LONG *, LONG, LONG) = (LONG (WINAPI *)(volatile LONG *, LONG, LONG))GetProcAddress(k, "InterlockedCompareExchange");
    LONGLONG (WINAPI *cas64)(volatile LONGLONG *, LONGLONG, LONGLONG) = (LONGLONG (WINAPI *)(volatile LONGLONG *, LONGLONG, LONGLONG))GetProcAddress(k, "InterlockedCompareExchange64");
    check("kernel32 exports the Interlocked functions", inc && dec && xchg && add && cas && cas64);
    if (!(inc && dec && xchg && add && cas && cas64)) return;
    volatile LONG v = 5;
    check("InterlockedIncrement/Decrement return the new value", inc(&v) == 6 && dec(&v) == 5 && v == 5);
    check("InterlockedExchange/ExchangeAdd return the old value", xchg(&v, 9) == 5 && add(&v, 3) == 9 && v == 12);
    check("InterlockedCompareExchange stores only on a match", cas(&v, 1, 99) == 12 && v == 12 && cas(&v, 1, 12) == 12 && v == 1);
    volatile LONGLONG w = 0x100000002LL;
    check("InterlockedCompareExchange64", cas64(&w, 7, 0x100000002LL) == 0x100000002LL && w == 7 && cas64(&w, 8, 5) == 7 && w == 7);
    v = 0x7fffffff;
    check("InterlockedIncrement wraps like Windows", inc(&v) == (LONG)0x80000000);
}

static void attribute_lists(void) {
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    LPPROC_THREAD_ATTRIBUTE_LIST list = HeapAlloc(GetProcessHeap(), 0, size);
    HANDLE inherit = GetStdHandle(STD_OUTPUT_HANDLE);
    check("InitializeProcThreadAttributeList", list && InitializeProcThreadAttributeList(list, 1, 0, &size));
    check("UpdateProcThreadAttribute", UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherit, sizeof inherit, NULL, NULL));
    DeleteProcThreadAttributeList(list);
    SetLastError(0);
    check("a deleted attribute list cannot be updated", !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherit, sizeof inherit, NULL, NULL));
    if (list) HeapFree(GetProcessHeap(), 0, list);
}

void __stdcall start(void) {
    heaps();
    critical_sections();
    thread_library_calls();
    windows_and_menus();
    attribute_lists();
    without_windows();
    wininet_and_desktops();
    interlocked();
    finish("stubfix");
}
