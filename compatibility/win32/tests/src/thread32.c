/* Target: 32-bit (PE32/i386) threads. CreateThread starts 32-bit start
 * routines through the WoW64 bridge; two of them run at the same time and
 * call imports in a loop (each thread has its own 32-bit stack, TEB32 and
 * gate stack), and their return values become the exit codes. No C
 * runtime.
 *
 * Prints "thread32: ok NAME" / "thread32: FAIL NAME" and a summary, and
 * exits with the number of failures. Runs only under /bin/winrun inside
 * QEMU (scripts/win-test.ps1). */
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;

#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define WAIT_OBJECT_0 0

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD std_handle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE file, const void *buf, DWORD len, DWORD *written, void *overlapped);
__declspec(dllimport) void __stdcall ExitProcess(DWORD code);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *sa, DWORD stack, DWORD(__stdcall *start)(void *), void *param,
                                                    DWORD flags, DWORD *tid);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE h, DWORD ms);
__declspec(dllimport) BOOL __stdcall GetExitCodeThread(HANDLE h, DWORD *code);
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) void __stdcall Sleep(DWORD ms);
__declspec(dllimport) int __stdcall MulDiv(int a, int b, int c);

static HANDLE out;
static int failed;
static volatile DWORD results[2];

static int len(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void check(const char *name, int ok) {
    DWORD w;
    const char *p = ok ? "thread32: ok " : "thread32: FAIL ";
    WriteFile(out, p, len(p), &w, 0);
    WriteFile(out, name, len(name), &w, 0);
    WriteFile(out, "\n", 1, &w, 0);
    if (!ok) failed++;
}

/* Calls imports many times; the sum proves every call returned to the
 * right 32-bit frame with the right result. */
static DWORD __stdcall worker(void *param) {
    DWORD index = (DWORD)param, sum = 0;
    for (int i = 0; i < 500; i++) {
        sum += MulDiv(i, 2, 1);
        if (i % 100 == 0) Sleep(1);
        GetTickCount();
    }
    results[index] = sum; /* 2 * (0 + ... + 499) = 249500 */
    return 0x1000 + index;
}

void __stdcall start(void) {
    out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD tid[2] = {0, 0};
    HANDLE h[2];
    for (DWORD i = 0; i < 2; i++) h[i] = CreateThread(0, 0, worker, (void *)i, 0, &tid[i]);
    check("CreateThread returns handles and ids", h[0] && h[1] && tid[0] && tid[1] && tid[0] != tid[1]);
    /* The main thread keeps calling imports while the workers run. */
    DWORD own = 0;
    for (int i = 0; i < 500; i++) own += MulDiv(i, 2, 1);
    check("main thread imports during the workers", own == 249500);
    check("thread 0 finishes", h[0] && WaitForSingleObject(h[0], 10000) == WAIT_OBJECT_0);
    check("thread 1 finishes", h[1] && WaitForSingleObject(h[1], 10000) == WAIT_OBJECT_0);
    check("both threads computed through imports", results[0] == 249500 && results[1] == 249500);
    DWORD c0 = 0, c1 = 0;
    check("start routine return values are the exit codes",
          GetExitCodeThread(h[0], &c0) && GetExitCodeThread(h[1], &c1) && c0 == 0x1000 && c1 == 0x1001);
    WriteFile(out, failed ? "thread32: summary FAIL\n" : "thread32: summary ok\n", failed ? 23 : 21, &own, 0);
    ExitProcess(failed);
}
