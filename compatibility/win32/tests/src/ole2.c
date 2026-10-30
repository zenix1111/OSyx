/* OLE/COM apartment nesting and thread isolation; also runs on Windows. */
#include "common.h"
#include <objbase.h>
#define COBJMACROS
#include <ole2.h>
#include <shellapi.h>
_Static_assert(sizeof(HRESULT)==4 && sizeof(APTTYPE)==4 && sizeof(APTTYPEQUALIFIER)==4,"COM apartment ABI");

static int is_sta(void) {
    APTTYPE type; APTTYPEQUALIFIER qualifier;
    return CoGetApartmentType(&type,&qualifier)==S_OK && (type==APTTYPE_STA || type==APTTYPE_MAINSTA);
}

static DWORD WINAPI ole_worker(void *arg) {
    (void)arg;
    if(CoInitializeEx(NULL,COINIT_MULTITHREADED)!=S_OK) return 1;
    if(OleInitialize(NULL)!=RPC_E_CHANGED_MODE) return 2;
    OleUninitialize(); /* a failed call must not consume the MTA's reference */
    APTTYPE type; APTTYPEQUALIFIER qualifier;
    if(CoGetApartmentType(&type,&qualifier)!=S_OK || type!=APTTYPE_MTA) return 3;
    CoUninitialize();
    if(OleInitialize(NULL)!=S_OK || OleInitialize(NULL)!=S_FALSE) return 4;
    OleUninitialize(); OleUninitialize();
    if(CoInitializeEx(NULL,COINIT_MULTITHREADED)!=S_OK) return 5;
    CoUninitialize(); return 0;
}

static void ole_apartments(void) {
    check_eq("OleInitialize rejects reserved parameter",(DWORD)OleInitialize((void *)1),(DWORD)E_INVALIDARG);
    check_eq("OleInitialize first call",OleInitialize(NULL),S_OK);
    check_eq("OleInitialize nested call",OleInitialize(NULL),S_FALSE);
    check("OleInitialize enters an STA",is_sta());
    check_eq("OLE apartment rejects MTA switch",(DWORD)CoInitializeEx(NULL,COINIT_MULTITHREADED),(DWORD)RPC_E_CHANGED_MODE);
    HANDLE thread=CreateThread(NULL,0,ole_worker,NULL,0,NULL); DWORD code=99;
    check("OLE nesting and MTA conflicts are thread-local",thread && WaitForSingleObject(thread,5000)==WAIT_OBJECT_0 && GetExitCodeThread(thread,&code) && code==0);
    if(thread)CloseHandle(thread);
    check("OLE worker leaves main STA intact",is_sta());
    OleUninitialize();
    check_eq("one OleUninitialize retains the nested STA",CoInitializeEx(NULL,COINIT_APARTMENTTHREADED),S_FALSE);
    CoUninitialize(); OleUninitialize();
    check_eq("balanced OleUninitialize releases STA",CoInitializeEx(NULL,COINIT_MULTITHREADED),S_OK);
    check_eq("OleInitialize on an MTA fails",(DWORD)OleInitialize(NULL),(DWORD)RPC_E_CHANGED_MODE);
    OleUninitialize();
    check_eq("failed OleInitialize does not consume MTA reference",CoInitializeEx(NULL,COINIT_MULTITHREADED),S_FALSE);
    CoUninitialize(); CoUninitialize();
    check_eq("plain COM STA before OLE",CoInitializeEx(NULL,COINIT_APARTMENTTHREADED),S_OK);
    check_eq("first OLE call in existing COM STA returns S_OK",OleInitialize(NULL),S_OK);
    OleUninitialize(); OleUninitialize();
    check_eq("OleUninitialize preserves independently owned COM STA",CoInitializeEx(NULL,COINIT_APARTMENTTHREADED),S_FALSE);
    CoUninitialize(); CoUninitialize();
    check_eq("OLE and COM references are fully balanced",CoInitializeEx(NULL,COINIT_MULTITHREADED),S_OK);
    CoUninitialize();
}

static ULONG target_refs=1;
static HRESULT STDMETHODCALLTYPE dt_qi(IDropTarget *t, REFIID r, void **o) { (void)r; *o=t; return S_OK; }
static ULONG STDMETHODCALLTYPE dt_addref(IDropTarget *t) { (void)t; return ++target_refs; }
static ULONG STDMETHODCALLTYPE dt_release(IDropTarget *t) { (void)t; return --target_refs; }
static HRESULT STDMETHODCALLTYPE dt_enter(IDropTarget *t, IDataObject *d, DWORD k, POINTL p, DWORD *e) { (void)t;(void)d;(void)k;(void)p;(void)e; return S_OK; }
static HRESULT STDMETHODCALLTYPE dt_over(IDropTarget *t, DWORD k, POINTL p, DWORD *e) { (void)t;(void)k;(void)p;(void)e; return S_OK; }
static HRESULT STDMETHODCALLTYPE dt_leave(IDropTarget *t) { (void)t; return S_OK; }
static IDropTargetVtbl dt_vtbl={dt_qi,dt_addref,dt_release,dt_enter,dt_over,dt_leave,dt_enter};

static int wide_eq(const WCHAR *a, const WCHAR *b) { while(*a && *a==*b){a++;b++;} return *a==*b; }

static void guid_strings(void) {
    GUID g; WCHAR b[64]; LPOLESTR s=NULL;
    check_eq("CLSIDFromString",CLSIDFromString(L"{00000000-0000-0000-C000-000000000046}",&g),S_OK);
    check("CLSIDFromString value",g.Data1==0 && g.Data4[0]==0xc0 && g.Data4[7]==0x46);
    check_eq("lower-case hex",CLSIDFromString(L"{00000303-0000-0000-c000-000000000046}",&g),S_OK);
    check("lower-case value",g.Data1==0x303);
    check_eq("CLSID without braces",(DWORD)CLSIDFromString(L"00000000-0000-0000-C000-000000000046",&g),(DWORD)CO_E_CLASSSTRING);
    check_eq("CLSID with bad digits",(DWORD)CLSIDFromString(L"{zzzzzzzz-0000-0000-C000-000000000046}",&g),(DWORD)CO_E_CLASSSTRING);
    check_eq("unknown ProgID",(DWORD)CLSIDFromString(L"No.Such.ProgId",&g),(DWORD)CO_E_CLASSSTRING);
    check_eq("CLSID with trailing text",(DWORD)CLSIDFromString(L"{00000000-0000-0000-C000-000000000046}x",&g),(DWORD)CO_E_CLASSSTRING);
    g.Data1=5;
    check("NULL is the nil CLSID",CLSIDFromString(NULL,&g)==S_OK && g.Data1==0);
    check_eq("IIDFromString",IIDFromString(L"{00000000-0000-0000-C000-000000000046}",&g),S_OK);
    check_eq("IID without braces",(DWORD)IIDFromString(L"00000000-0000-0000-C000-000000000046",&g),(DWORD)E_INVALIDARG);
    check_eq("IID too short",(DWORD)IIDFromString(L"{00000000-0000-0000-C000-00000000004}",&g),(DWORD)E_INVALIDARG);
    check_eq("NULL is the nil IID",IIDFromString(NULL,&g),S_OK);
    GUID t={0x12345678,0xabcd,0xef01,{0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01}};
    check_eq("StringFromGUID2 length",StringFromGUID2(&t,b,64),39);
    check("StringFromGUID2 text",wide_eq(b,L"{12345678-ABCD-EF01-2345-6789ABCDEF01}"));
    check_eq("StringFromGUID2 needs 39",StringFromGUID2(&t,b,38),0);
    check("StringFromCLSID",StringFromCLSID(&t,&s)==S_OK && s && wide_eq(s,L"{12345678-ABCD-EF01-2345-6789ABCDEF01}"));
    CoTaskMemFree(s); s=NULL;
    check("StringFromIID",StringFromIID(&t,&s)==S_OK && s && wide_eq(s,L"{12345678-ABCD-EF01-2345-6789ABCDEF01}"));
    CoTaskMemFree(s);
}

static LRESULT CALLBACK wproc(HWND w, UINT m, WPARAM wp, LPARAM lp) { return DefWindowProcW(w,m,wp,lp); }

static void drag_drop(void) {
    WNDCLASSW wc={0}; wc.lpfnWndProc=wproc; wc.hInstance=GetModuleHandleW(NULL); wc.lpszClassName=L"ole2";
    RegisterClassW(&wc);
    HWND w=CreateWindowExW(0,L"ole2",L"ole2",WS_OVERLAPPED,0,0,50,50,NULL,NULL,wc.hInstance,NULL);
    IDropTarget dt={&dt_vtbl};
    OleInitialize(NULL);
    check_eq("register a drop target",(DWORD)RegisterDragDrop(w,&dt),S_OK);
    check_eq("registration holds a reference",target_refs,2);
    check_eq("register twice",(DWORD)RegisterDragDrop(w,&dt),(DWORD)DRAGDROP_E_ALREADYREGISTERED);
    check_eq("register on a non-window",(DWORD)RegisterDragDrop((HWND)0x1234,&dt),(DWORD)DRAGDROP_E_INVALIDHWND);
    check_eq("register NULL",(DWORD)RegisterDragDrop(w,NULL),(DWORD)E_INVALIDARG);
    check_eq("revoke",(DWORD)RevokeDragDrop(w),S_OK);
    check_eq("revoke releases",target_refs,1);
    check_eq("revoke twice",(DWORD)RevokeDragDrop(w),(DWORD)DRAGDROP_E_NOTREGISTERED);
    check_eq("revoke on a non-window",(DWORD)RevokeDragDrop((HWND)0x1234),(DWORD)DRAGDROP_E_INVALIDHWND);
    check_eq("NULL is not the clipboard",OleIsCurrentClipboard(NULL),S_FALSE);
    check_eq("clear the OLE clipboard",OleSetClipboard(NULL),S_OK);
    check_eq("flush the OLE clipboard",OleFlushClipboard(),S_OK);
    STGMEDIUM m={0}; m.tymed=TYMED_HGLOBAL; m.hGlobal=GlobalAlloc(GMEM_FIXED,16);
    ReleaseStgMedium(&m); /* frees the HGLOBAL */
    OleUninitialize();
    DestroyWindow(w);
}

static void file_drop_data(void) {
    const WCHAR path[] = L"C:\\Users\\user\\photo.png";
    struct DropHeader { DWORD offset; LONG x, y; BOOL nonclient, wide; };
    SIZE_T bytes = sizeof(struct DropHeader) + sizeof(path) + sizeof(WCHAR);
    HDROP drop = (HDROP)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, bytes);
    check("allocate file drop", drop != NULL);
    if (!drop) return;
    struct DropHeader *header = (struct DropHeader *)drop;
    header->offset = sizeof(struct DropHeader);
    header->wide = TRUE;
    memcpy((BYTE *)drop + sizeof(struct DropHeader), path, sizeof(path));
    WCHAR out[128];
    check_eq("file drop count", DragQueryFileW(drop, 0xffffffff, NULL, 0), 1);
    check_eq("file drop path length", DragQueryFileW(drop, 0, NULL, 0), (sizeof(path) / sizeof(WCHAR)) - 1);
    check("file drop path", DragQueryFileW(drop, 0, out, 128) == (sizeof(path) / sizeof(WCHAR)) - 1 && mem_eq(out, path, sizeof(path)));
    check_eq("file drop truncation", DragQueryFileW(drop, 0, out, 4), 3);
    GlobalFree((HGLOBAL)drop);
}

static void mta_usage(void) {
    CO_MTA_USAGE_COOKIE c=0;
    check_eq("CoIncrementMTAUsage",CoIncrementMTAUsage(&c),S_OK);
    APTTYPE t; APTTYPEQUALIFIER q;
    check("uninitialized thread joins the implicit MTA",CoGetApartmentType(&t,&q)==S_OK && t==APTTYPE_MTA && q==APTTYPEQUALIFIER_IMPLICIT_MTA);
    check_eq("CoDecrementMTAUsage",CoDecrementMTAUsage(c),S_OK);
    DWORD tid=7;
    check("no caller outside a call",CoGetCallerTID(&tid)==S_OK && tid==0);
}

void __stdcall start(void) {
    ole_apartments();
    guid_strings();
    drag_drop();
    file_drop_data();
    mta_usage();
    finish("ole2");
}
