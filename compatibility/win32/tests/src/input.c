/* Mouse capture and tracking, input timing, coordinate mapping, window
   enumeration, display devices and modes, clipboard format atoms and
   touch/raw-input registration; also runs on Windows. */
#include "common.h"
_Static_assert(sizeof(DISPLAY_DEVICEW)==840 && sizeof(DEVMODEW)==220 && sizeof(TRACKMOUSEEVENT)==24,"user32 ABI");

static LRESULT CALLBACK proc(HWND w, UINT m, WPARAM wp, LPARAM lp) { return DefWindowProcW(w,m,wp,lp); }

static HWND found;
static BOOL CALLBACK enum_proc(HWND w, LPARAM want) { if(w==(HWND)want) found=w; return TRUE; }

static int wide_starts(const WCHAR *s, const WCHAR *p) { while(*p) if(*s++!=*p++) return 0; return 1; }

static void capture(HWND w) {
    check("no capture at first",GetCapture()==NULL);
    SetCapture(w);
    check("capture is recorded",GetCapture()==w);
    check("release capture",ReleaseCapture());
    check("capture released",GetCapture()==NULL);
    TRACKMOUSEEVENT t={sizeof t,TME_LEAVE,w,HOVER_DEFAULT};
    check("track leaving",TrackMouseEvent(&t));
    t.dwFlags=TME_LEAVE|TME_CANCEL;
    check("cancel tracking",TrackMouseEvent(&t));
    t.cbSize=8; SetLastError(0);
    check("wrong TRACKMOUSEEVENT size fails",!TrackMouseEvent(&t) && GetLastError()==ERROR_INVALID_PARAMETER);
    LASTINPUTINFO li={sizeof li,0};
    check("last input time",GetLastInputInfo(&li) && li.dwTime<=GetTickCount());
    li.cbSize=4;
    check("wrong LASTINPUTINFO size fails",!GetLastInputInfo(&li));
}

static void coordinates(HWND w) {
    POINT origin={0,0}, p[2]={{5,6},{0,0}};
    ClientToScreen(w,&origin);
    int r=MapWindowPoints(w,NULL,p,2);
    check("client to screen",p[0].x==origin.x+5 && p[0].y==origin.y+6 && p[1].x==origin.x && p[1].y==origin.y);
    check("offset in the result",(short)LOWORD(r)==origin.x && (short)HIWORD(r)==origin.y);
    MapWindowPoints(NULL,w,p,2);
    check("screen to client",p[0].x==5 && p[0].y==6);
    check_eq("same window: no offset",MapWindowPoints(w,w,p,1),0);
    found=NULL;
    check("enumerate the thread's windows",EnumThreadWindows(GetCurrentThreadId(),enum_proc,(LPARAM)w) && found==w);
}

static void displays(void) {
    DISPLAY_DEVICEW d={0}; d.cb=sizeof d;
    check("first display adapter",EnumDisplayDevicesW(NULL,0,&d,0));
    check("adapter is on the desktop",(d.StateFlags&DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)!=0);
    check("adapter name",wide_starts(d.DeviceName,L"\\\\.\\DISPLAY"));
    WCHAR adapter[32]; for(int i=0;i<32;i++) adapter[i]=d.DeviceName[i];
    DWORD primary=0;
    for(DWORD i=0;;i++){ DISPLAY_DEVICEW e={0}; e.cb=sizeof e; if(!EnumDisplayDevicesW(NULL,i,&e,0)) break; if(e.StateFlags&DISPLAY_DEVICE_PRIMARY_DEVICE) primary++; if(i>64) break; }
    check_eq("one primary adapter",primary,1);
    DISPLAY_DEVICEW m={0}; m.cb=sizeof m;
    check("adapter's monitor",EnumDisplayDevicesW(adapter,0,&m,0) && wide_starts(m.DeviceName,adapter));
    check("monitor is active",(m.StateFlags&DISPLAY_DEVICE_ACTIVE)!=0);
    d.cb=sizeof d;
    check("no adapter past the end",!EnumDisplayDevicesW(NULL,1000,&d,0));

    DEVMODEW dm={0}; dm.dmSize=sizeof dm;
    check("current mode",EnumDisplaySettingsW(NULL,ENUM_CURRENT_SETTINGS,&dm));
    check("mode has a size",(dm.dmFields&DM_PELSWIDTH) && (dm.dmFields&DM_PELSHEIGHT) && dm.dmPelsWidth>0 && dm.dmPelsHeight>0);
    check("mode depth",(dm.dmFields&DM_BITSPERPEL) && dm.dmBitsPerPel>=24);
    check("mode frequency",dm.dmDisplayFrequency>=1);
    check("mode of a named adapter",EnumDisplaySettingsExW(adapter,ENUM_CURRENT_SETTINGS,&dm,0));
    check("mode of an unknown adapter fails",!EnumDisplaySettingsW(L"\\\\.\\NODISPLAY",ENUM_CURRENT_SETTINGS,&dm));
    AR_STATE ar=0;
    check("auto-rotation state",GetAutoRotationState(&ar));
}

static void registrations(HWND w) {
    UINT a=RegisterClipboardFormatW(L"OSyx Test Format"), b=RegisterClipboardFormatW(L"osyx test format");
    check("clipboard format atom",a>=0xC000 && a==b);
    check("formats and window messages share atoms",RegisterWindowMessageW(L"OSyx Test Format")==a);
    check("register a touch window",RegisterTouchWindow(w,0));
    RAWINPUTDEVICE rid={1,2,0,w};
    SetLastError(0);
    check("raw input with a wrong size fails",!RegisterRawInputDevices(&rid,1,8) && GetLastError()==ERROR_INVALID_PARAMETER);
}

static void icons_and_clipboard(HWND w) {
    HBITMAP mask=CreateBitmap(16,16,1,1,NULL), color=CreateBitmap(16,16,1,32,NULL);
    ICONINFO ii={TRUE,0,0,mask,color};
    HICON icon=CreateIconIndirect(&ii);
    check("create an icon",icon!=NULL);
    DeleteObject(mask); DeleteObject(color);
    ICONINFO back={0};
    check("icon keeps its own bitmaps",icon && GetIconInfo(icon,&back) && back.fIcon && back.hbmMask && back.hbmColor);
    BITMAP bm={0};
    check("icon bitmap size",back.hbmColor && GetObjectW(back.hbmColor,sizeof bm,&bm) && bm.bmWidth==16 && bm.bmHeight==16);
    if(back.hbmMask) DeleteObject(back.hbmMask);
    if(back.hbmColor) DeleteObject(back.hbmColor);
    check("destroy the icon",icon && DestroyIcon(icon));
    SetLastError(0);
    check("system icon",LoadImageW(NULL,MAKEINTRESOURCEW(32512),IMAGE_ICON,0,0,LR_SHARED)!=NULL);

    check("open the clipboard",OpenClipboard(w));
    check("clipboard owner window",GetOpenClipboardWindow()==w);
    check("close the clipboard",CloseClipboard());
    SetLastError(0);
    check("close twice fails",!CloseClipboard() && GetLastError()==ERROR_CLIPBOARD_NOT_OPEN);
    SetLastError(0);
    check("data needs an open clipboard",GetClipboardData(CF_UNICODETEXT)==NULL && GetLastError()==ERROR_CLIPBOARD_NOT_OPEN);
    check("open clipboard for text conversion",OpenClipboard(w));
    check("empty clipboard",EmptyClipboard());
    HGLOBAL text=GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, 8);
    if (text) { WCHAR *p=(WCHAR *)text; p[0]='O'; p[1]='K'; }
    check("set unicode text",text && SetClipboardData(CF_UNICODETEXT,text)==text);
    check("synthesized ANSI format is available",IsClipboardFormatAvailable(CF_TEXT));
    const char *ansi=(const char *)GetClipboardData(CF_TEXT);
    check("unicode to ANSI clipboard",ansi && ansi[0]=='O' && ansi[1]=='K' && ansi[2]==0);
    check("clear clipboard for reverse conversion",EmptyClipboard());
    HGLOBAL narrow=GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, 4);
    if (narrow) { char *p=(char *)narrow; p[0]='h'; p[1]='i'; }
    check("set ANSI text",narrow && SetClipboardData(CF_TEXT,narrow)==narrow);
    const WCHAR *wide=(const WCHAR *)GetClipboardData(CF_UNICODETEXT);
    check("ANSI to unicode clipboard",wide && wide[0]=='h' && wide[1]=='i' && wide[2]==0);
    check("close clipboard after conversion",CloseClipboard());
    UINT f=RegisterClipboardFormatW(L"OSyx Named Format"); WCHAR name[64]={0};
    int n=GetClipboardFormatNameW(f,name,64);
    check("format name",n==17 && name[0]=='O' && name[16]=='t' && name[17]==0);
    check("format name is truncated",GetClipboardFormatNameW(f,name,5)==4 && name[4]==0);
}

void __stdcall start(void) {
    WNDCLASSW wc={0}; wc.lpfnWndProc=proc; wc.hInstance=GetModuleHandleW(NULL); wc.lpszClassName=L"input";
    RegisterClassW(&wc);
    HWND w=CreateWindowExW(0,L"input",L"input",WS_OVERLAPPED,40,50,200,100,NULL,NULL,wc.hInstance,NULL);
    check("create window",w!=NULL);
    capture(w);
    coordinates(w);
    displays();
    registrations(w);
    icons_and_clipboard(w);
    DestroyWindow(w);
    finish("input");
}
