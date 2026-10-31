/* PE32 DLL used to test loading, imports, entry points and exported code. */
__declspec(dllimport) int __stdcall MulDiv(int, int, int);
static int attached;

int __stdcall DllMain(void *instance, unsigned long reason, void *reserved) {
    (void)instance;
    (void)reserved;
    if (reason == 1) attached++;
    return 1;
}

__declspec(dllexport) int plugin_value(void) {
    return attached == 1 ? MulDiv(6, 7, 1) : -1;
}
