/* Target E: a small Win32 GUI program. Registers a class, creates a
 * window (a PRISM window on OSyx), paints text and a filled rectangle
 * with GDI in WM_PAINT, uses a timer, invalidates itself, handles a
 * resize, and closes itself through WM_CLOSE -> DestroyWindow ->
 * PostQuitMessage. Every step is printed so the test can follow it. */
#include "common.h"
#include <dbt.h>
#include <imm.h>

static int paints, timers, sizes, created;
static HWND main_window;

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        created = 1;
        put("gui: WM_CREATE\r\n");
        return 0;
    case WM_SIZE:
        sizes++;
        put("gui: WM_SIZE ");
        put_uint(LOWORD(lp));
        put("x");
        put_uint(HIWORD(lp));
        put("\r\n");
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        HBRUSH blue = CreateSolidBrush(RGB(40, 90, 200));
        RECT band = {10, 10, rc.right - 10, 60};
        FillRect(dc, &band, blue);
        DeleteObject(blue);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(255, 255, 255));
        static const char title[] = "Hello from Win32 on OSyx";
        TextOutA(dc, 20, 26, title, sizeof title - 1);
        SetTextColor(dc, RGB(20, 20, 20));
        static const char line[] = "GDI text and rectangles drawn into a PRISM surface";
        TextOutA(dc, 20, 80, line, sizeof line - 1);
        /* Exercise the same memory-DC -> PRISM path Gecko's software renderer
         * needs, and read the window surface back before it is presented. */
        BITMAPINFO bi = {0};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = 16; bi.bmiHeader.biHeight = -16;
        bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
        DWORD *pixels = NULL;
        HBITMAP bitmap = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, (void **)&pixels, NULL, 0);
        HDC memory = CreateCompatibleDC(dc);
        check("PRISM raster source allocated", bitmap && memory && pixels);
        if (bitmap && memory && pixels) {
            for (int i = 0; i < 256; i++) pixels[i] = 0x0012ab34;
            HGDIOBJ saved = SelectObject(memory, bitmap);
            check("BitBlt memory DIB into PRISM", BitBlt(dc, 20, 110, 16, 16, memory, 0, 0, SRCCOPY));
            check_eq("PRISM surface contains copied pixel", GetPixel(dc, 24, 114), RGB(0x12, 0xab, 0x34));
            SelectObject(memory, saved);
        }
        if (memory) DeleteDC(memory);
        if (bitmap) DeleteObject(bitmap);
        EndPaint(hwnd, &ps);
        paints++;
        put("gui: WM_PAINT ");
        put_uint(paints);
        put("\r\n");
        if (paints == 1) SetTimer(hwnd, 1, 100, NULL);
        return 0;
    }
    case WM_TIMER:
        timers++;
        if (timers == 1) {
            InvalidateRect(hwnd, NULL, TRUE); /* second paint */
        } else if (timers == 2) {
            SetWindowPos(hwnd, NULL, 0, 0, 520, 300, SWP_NOMOVE | SWP_NOZORDER);
        } else if (timers == 4) {
            KillTimer(hwnd, 1);
            put("gui: closing\r\n");
            PostMessageA(hwnd, WM_CLOSE, 0, 0);
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        put("gui: WM_DESTROY\r\n");
        PostQuitMessage(7);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

struct enum_state { HWND seen[16]; int n, stop_after; };
static BOOL CALLBACK collect(HWND w, LPARAM l) {
    struct enum_state *e = (struct enum_state *)l;
    if (e->n < 16) e->seen[e->n++] = w;
    return !(e->stop_after && e->n >= e->stop_after);
}

void __stdcall start(void) {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "OSyxWin32Test";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    check("RegisterClassA", RegisterClassA(&wc) != 0);
    main_window = CreateWindowExA(0, "OSyxWin32Test", "Win32 on OSyx", WS_OVERLAPPEDWINDOW, 120, 90, 480, 260, NULL, NULL, wc.hInstance, NULL);
    check("CreateWindowExA", main_window != NULL && created);
    RECT before, after, outer;
    GetClientRect(main_window, &before);
    check("SetWindowPos completes the size change", SetWindowPos(main_window, NULL, 0, 0, 500, 280, SWP_NOMOVE | SWP_NOZORDER));
    check("window rectangle changes synchronously", GetWindowRect(main_window, &outer) && outer.right - outer.left == 500 && outer.bottom - outer.top == 280);
    check("client rectangle changes synchronously", GetClientRect(main_window, &after) && after.right - before.right == 20 && after.bottom - before.bottom == 20);
    SetWindowPos(main_window, NULL, 0, 0, 480, 260, SWP_NOMOVE | SWP_NOZORDER);
    char title[64];
    check("GetWindowTextA", GetWindowTextA(main_window, title, sizeof title) == 13);
    {
        HWND child = CreateWindowExA(0, "BUTTON", "child", WS_CHILD | WS_VISIBLE, 0, 0, 50, 20, main_window, (HMENU)(UINT_PTR)5, wc.hInstance, NULL);
        check("IsChild reports a child control", child && IsChild(main_window, child) && !IsChild(child, main_window));
        check("GetTopWindow(parent) is its newest child", GetTopWindow(main_window) == child);
        SetLastError(0);
        check("GetTopWindow(bogus) fails with ERROR_INVALID_WINDOW_HANDLE", GetTopWindow((HWND)0x1234) == NULL && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);
        SetLastError(0);
        check("UnregisterClassA of a class with windows fails with ERROR_CLASS_HAS_WINDOWS", !UnregisterClassA("OSyxWin32Test", wc.hInstance) && GetLastError() == ERROR_CLASS_HAS_WINDOWS);
        SetLastError(0);
        check("UnregisterClassA of an unknown class fails with ERROR_CLASS_DOES_NOT_EXIST", !UnregisterClassA("OSyxNoSuchClass", wc.hInstance) && GetLastError() == ERROR_CLASS_DOES_NOT_EXIST);
        WNDCLASSA temp = wc;
        temp.lpszClassName = "OSyxTempClass";
        BOOL again = RegisterClassA(&temp) && UnregisterClassA("OSyxTempClass", wc.hInstance) && !UnregisterClassA("OSyxTempClass", wc.hInstance) && RegisterClassA(&temp);
        check("a class without windows can be unregistered and registered again", again);
        UnregisterClassA("OSyxTempClass", wc.hInstance);
        SetLastError(0);
        check("SetWindowsHookExW is refused with ERROR_NOT_SUPPORTED", SetWindowsHookExW(WH_GETMESSAGE, (HOOKPROC)wndproc, NULL, GetCurrentThreadId()) == NULL && GetLastError() == ERROR_NOT_SUPPORTED);
        SetLastError(0);
        check("SetWindowsHookExW rejects a bad hook id with ERROR_INVALID_HOOK_FILTER", SetWindowsHookExW(99, (HOOKPROC)wndproc, NULL, 0) == NULL && GetLastError() == ERROR_INVALID_HOOK_FILTER);
        SetLastError(0);
        SetLastError(0);
        check("SetWindowsHookExW with a NULL procedure fails with ERROR_INVALID_FILTER_PROC", SetWindowsHookExW(WH_GETMESSAGE, NULL, NULL, 0) == NULL && GetLastError() == ERROR_INVALID_FILTER_PROC);
        SetLastError(0);
        check("UnhookWindowsHookEx(bogus) fails with ERROR_INVALID_HOOK_HANDLE", !UnhookWindowsHookEx((HHOOK)0x1234) && GetLastError() == ERROR_INVALID_HOOK_HANDLE);
    }
    {
        /* Carets: state per thread, errors as on Windows. */
        POINT pt = { -1, -1 };
        SetLastError(0);
        check("DestroyCaret without a caret fails with ERROR_ACCESS_DENIED", !DestroyCaret() && GetLastError() == ERROR_ACCESS_DENIED);
        SetLastError(0);
        check("SetCaretPos without a caret fails with ERROR_ACCESS_DENIED", !SetCaretPos(1, 2) && GetLastError() == ERROR_ACCESS_DENIED);
        SetLastError(0);
        check("ShowCaret/HideCaret without a caret fail with ERROR_ACCESS_DENIED", !ShowCaret(NULL) && !HideCaret(NULL) && GetLastError() == ERROR_ACCESS_DENIED);
        check("GetCaretPos without a caret succeeds with (0, 0)", GetCaretPos(&pt) && pt.x == 0 && pt.y == 0);
        SetLastError(0);
        check("CreateCaret(bogus window) fails with ERROR_INVALID_WINDOW_HANDLE", !CreateCaret((HWND)0x1234, NULL, 2, 8) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);
        check("CreateCaret", CreateCaret(main_window, NULL, 2, 8));
        check("SetCaretPos / GetCaretPos", SetCaretPos(5, 6) && GetCaretPos(&pt) && pt.x == 5 && pt.y == 6);
        check("ShowCaret and HideCaret nest", ShowCaret(main_window) && HideCaret(main_window) && HideCaret(main_window) && ShowCaret(main_window));
        SetLastError(0);
        check("ShowCaret(bogus window) fails with ERROR_INVALID_WINDOW_HANDLE", !ShowCaret((HWND)0x1234) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);
        check("DestroyCaret", DestroyCaret());

        /* Class words, menus, flashing, animation. */
        SetLastError(0);
        check("GetClassWord(GCW_ATOM) is the class atom", GetClassWord(main_window, GCW_ATOM) != 0);
        SetLastError(0);
        check("GetClassWord(0) fails with ERROR_INVALID_INDEX (no extra bytes)", GetClassWord(main_window, 0) == 0 && GetLastError() == ERROR_INVALID_INDEX);
        SetLastError(0);
        check("GetClassWord(bogus) fails with ERROR_INVALID_WINDOW_HANDLE", GetClassWord((HWND)0x1234, GCW_ATOM) == 0 && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);
        HMENU bar = CreateMenu();
        check("a window starts without a menu bar", GetMenu(main_window) == NULL);
        check("SetMenu / GetMenu", bar && SetMenu(main_window, bar) && GetMenu(main_window) == bar);
        SetLastError(0);
        check("SetMenu(bogus window) fails with ERROR_INVALID_WINDOW_HANDLE", !SetMenu((HWND)0x1234, bar) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);
        check("SetMenu(window, NULL) removes the bar", SetMenu(main_window, NULL) && GetMenu(main_window) == NULL);

        AppendMenuW(bar, MF_STRING, 7, L"Open");
        AppendMenuW(bar, MF_STRING, 8, L"Close");
        MENUITEMINFOW info = { sizeof info };
        info.fMask = MIIM_STATE | MIIM_ID | MIIM_STRING;
        info.fState = MFS_DISABLED;
        info.wID = 70;
        WCHAR renamed[] = L"Opened";
        info.dwTypeData = renamed;
        check("SetMenuItemInfoW by position: state, id and text", SetMenuItemInfoW(bar, 0, TRUE, &info));
        check("the item answers to its new id", (GetMenuState(bar, 70, MF_BYCOMMAND) & MF_DISABLED) != 0 && GetMenuState(bar, 7, MF_BYCOMMAND) == (UINT)-1);
        info.fMask = MIIM_BITMAP;
        SetLastError(0);
        check("SetMenuItemInfoW with a bitmap fails with ERROR_NOT_SUPPORTED", !SetMenuItemInfoW(bar, 8, FALSE, &info) && GetLastError() == ERROR_NOT_SUPPORTED);
        info.fMask = MIIM_STATE;
        SetLastError(0);
        check("SetMenuItemInfoW of a missing item fails with ERROR_MENU_ITEM_NOT_FOUND", !SetMenuItemInfoW(bar, 99, FALSE, &info) && GetLastError() == ERROR_MENU_ITEM_NOT_FOUND);
        DestroyMenu(bar);

        FLASHWINFO flash = { sizeof flash, main_window, FLASHW_STOP, 0, 0 };
        check("FlashWindowEx reports whether the window was active", FlashWindowEx(&flash) == (GetForegroundWindow() == main_window));
        FLASHWINFO bad_flash = { 5, main_window, FLASHW_STOP, 0, 0 };
        SetLastError(0);
        check("FlashWindowEx with a wrong cbSize fails with ERROR_INVALID_PARAMETER", !FlashWindowEx(&bad_flash) && GetLastError() == ERROR_INVALID_PARAMETER);

        check("AnimateWindow(AW_HIDE) on a hidden window fails", !AnimateWindow(main_window, 10, AW_HIDE | AW_BLEND) && !IsWindowVisible(main_window));
        check("AnimateWindow(AW_ACTIVATE) shows it", AnimateWindow(main_window, 10, AW_ACTIVATE | AW_BLEND) && IsWindowVisible(main_window));
        check("AnimateWindow(AW_ACTIVATE) on a visible window fails", !AnimateWindow(main_window, 10, AW_ACTIVATE | AW_BLEND));
        check("AnimateWindow(AW_HIDE) hides it", AnimateWindow(main_window, 10, AW_HIDE | AW_BLEND) && !IsWindowVisible(main_window));
        check("AnimateWindow(bogus) fails", !AnimateWindow((HWND)0x1234, 10, 0));

        /* EnumChildWindows. */
        HWND kids[3];
        for (int i = 0; i < 3; i++) kids[i] = CreateWindowExA(0, "BUTTON", "kid", WS_CHILD, 0, 0, 10, 10, main_window, (HMENU)(UINT_PTR)(20 + i), wc.hInstance, NULL);
        struct enum_state state = { { 0 }, 0, 0 };
        EnumChildWindows(main_window, collect, (LPARAM)&state);
        int found_all = state.n >= 3;
        for (int i = 0; i < 3; i++) { int hit = 0; for (int j = 0; j < state.n; j++) hit |= state.seen[j] == kids[i]; found_all &= hit; }
        check("EnumChildWindows visits every child", found_all);
        check("the newest child comes first (top of the z-order)", state.n >= 3 && state.seen[0] == kids[2]);
        state.n = 0; state.stop_after = 1;
        EnumChildWindows(main_window, collect, (LPARAM)&state);
        check("EnumChildWindows stops when the callback returns FALSE", state.n == 1);
        SetLastError(0);
        check("EnumChildWindows(bogus parent) fails with ERROR_INVALID_WINDOW_HANDLE", !EnumChildWindows((HWND)0x1234, collect, 0) && GetLastError() == ERROR_INVALID_WINDOW_HANDLE);

        /* Device notifications, input contexts, thread desktop. */
        DEV_BROADCAST_DEVICEINTERFACE_W filter = { sizeof filter, DBT_DEVTYP_DEVICEINTERFACE, 0, { 0xa5dcbf10, 0x6530, 0x11d2, { 0x90, 0x1f, 0x00, 0xc0, 0x4f, 0xb9, 0x51, 0xed } }, { 0 } };
        HDEVNOTIFY dn = RegisterDeviceNotificationW(main_window, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
        check("RegisterDeviceNotificationW returns a handle", dn != NULL);
        check("UnregisterDeviceNotification releases it", dn && UnregisterDeviceNotification(dn));
        SetLastError(0);
        check("UnregisterDeviceNotification of a released handle fails with ERROR_INVALID_HANDLE", !UnregisterDeviceNotification(dn) && GetLastError() == ERROR_INVALID_HANDLE);
        HIMC himc = ImmGetContext(main_window);
        check("ImmGetContext returns the window's input context", himc != NULL && ImmGetContext(main_window) == himc);
        check("the input context starts closed", himc && !ImmGetOpenStatus(himc));
        check("ImmSetOpenStatus / ImmGetOpenStatus", himc && ImmSetOpenStatus(himc, TRUE) && ImmGetOpenStatus(himc) && ImmSetOpenStatus(himc, FALSE) && !ImmGetOpenStatus(himc));
        LOGFONTW font = { 0 }, back = { 1 };
        font.lfHeight = -14;
        check("ImmSetCompositionFontW / ImmGetCompositionFontW", himc && ImmSetCompositionFontW(himc, &font) && ImmGetCompositionFontW(himc, &back) && back.lfHeight == -14);
        COMPOSITIONFORM form = { CFS_POINT, { 3, 4 }, { 0 } };
        check("ImmSetCompositionWindow", himc && ImmSetCompositionWindow(himc, &form));
        check("nothing is being composed", himc && ImmGetCompositionStringW(himc, GCS_COMPSTR, NULL, 0) == 0);
        check("ImmNotifyIME(CPS_CANCEL) with nothing to cancel succeeds", himc && ImmNotifyIME(himc, NI_COMPOSITIONSTR, CPS_CANCEL, 0));
        check("ImmReleaseContext", himc && ImmReleaseContext(main_window, himc));
        check("ImmGetDefaultIMEWnd is NULL (no IME)", ImmGetDefaultIMEWnd(main_window) == NULL);
        SetLastError(0);
        check("SetThreadDesktop fails with ERROR_BUSY while the thread owns windows", !SetThreadDesktop(GetThreadDesktop(GetCurrentThreadId())) && GetLastError() == ERROR_BUSY);
    }
    ShowWindow(main_window, SW_SHOW);
    UpdateWindow(main_window);
    MSG m;
    BOOL r;
    while ((r = GetMessageA(&m, NULL, 0, 0)) > 0) {
        TranslateMessage(&m);
        DispatchMessageA(&m);
    }
    check_eq("WM_QUIT carries PostQuitMessage's code", m.wParam, 7);
    check("painted at least twice (initial + InvalidateRect)", paints >= 2);
    check("timer messages arrived", timers >= 4);
    check("WM_SIZE after SetWindowPos", sizes >= 2);
    check("window handle is gone", !IsWindow(main_window));
    finish("gui");
}
