/* A DLL that counts the DLL_THREAD_ATTACH/DETACH calls of its DllMain and can
 * turn them off with DisableThreadLibraryCalls (stubfix.exe). No C runtime. */
#include <windows.h>

static volatile LONG attaches, detaches;
static HINSTANCE self;

__declspec(dllexport) LONG thread_attach_count(void) { return attaches; }
__declspec(dllexport) LONG thread_detach_count(void) { return detaches; }
__declspec(dllexport) BOOL disable_calls(void) { return DisableThreadLibraryCalls(self); }

BOOL WINAPI DllMainCRTStartup(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) self = instance;
    if (reason == DLL_THREAD_ATTACH) InterlockedIncrement(&attaches);
    if (reason == DLL_THREAD_DETACH) InterlockedIncrement(&detaches);
    return TRUE;
}
