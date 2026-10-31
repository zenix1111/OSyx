/* The rest of a browser launcher's start-up surface: COM apartments,
 * BSTRs and VARIANTs, window stations and desktops, WaitForInputIdle,
 * AppContainer SIDs, dbghelp symbols and crypt32 signed data. The same
 * PE runs on Windows; OSyx-specific checks are gated by OSYX. */
#include "common.h"
#include <objbase.h>
#include <oleauto.h>
#include <sddl.h>
#include <userenv.h>
#include <dbghelp.h>
#include <wincrypt.h>
#include "pkcs7_sample.h"

void WINAPI SetOaNoCache(void);

static int wcs_eq(const WCHAR *a, const WCHAR *b) {
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

static int str_ieq(const char *a, const char *b) {
    for (;; a++, b++) {
        char x = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a, y = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
        if (x != y) return 0;
        if (!x) return 1;
    }
}

static int str_eq(const char *a, const char *b) {
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

/* A COM object with IUnknown only, counting its references. */
static const GUID iid_unknown = {0, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
static const GUID iid_error_info = {0x1cf2b120, 0x547d, 0x101b, {0x8e, 0x65, 0x08, 0x00, 0x2b, 0x2b, 0xd1, 0x19}};
static LONG refs;
static HRESULT STDMETHODCALLTYPE qi(IUnknown *self, REFIID iid, void **out) {
    if (mem_eq(iid, &iid_unknown, sizeof iid_unknown) || mem_eq(iid, &iid_error_info, sizeof iid_error_info)) {
        *out = self;
        refs++;
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE add_ref(IUnknown *self) { (void)self; return ++refs; }
static ULONG STDMETHODCALLTYPE release(IUnknown *self) { (void)self; return --refs; }
static IUnknownVtbl unk_vtbl = {qi, add_ref, release};
static IUnknown unk_obj = {&unk_vtbl};

static DWORD WINAPI error_worker(void *arg) {
    (void)arg;
    IErrorInfo *info = (IErrorInfo *)(UINT_PTR)1;
    return GetErrorInfo(0, &info) == S_FALSE && info == NULL ? 0 : 1;
}

static void error_info_checks(void) {
    IErrorInfo *info = (IErrorInfo *)(UINT_PTR)1;
    SetErrorInfo(0, NULL);
    check("GetErrorInfo empty", GetErrorInfo(0, &info) == S_FALSE && info == NULL);
    refs = 1;
    check("SetErrorInfo retains a reference", SetErrorInfo(0, (IErrorInfo *)&unk_obj) == S_OK && refs == 2);
    check("SetErrorInfo replaces the same object", SetErrorInfo(0, (IErrorInfo *)&unk_obj) == S_OK && refs == 2);
    HANDLE thread = CreateThread(NULL, 0, error_worker, NULL, 0, NULL);
    DWORD code = 99;
    check("error information is thread-local", thread && WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0 &&
          GetExitCodeThread(thread, &code) && code == 0);
    if (thread) CloseHandle(thread);
    HRESULT err_hr = GetErrorInfo(0, &info);
    check("GetErrorInfo transfers the reference", err_hr == S_OK &&
          info == (IErrorInfo *)&unk_obj && refs == 2);
    if (info == (IErrorInfo *)&unk_obj) unk_obj.lpVtbl->Release((IUnknown *)info);
    check("GetErrorInfo consumes the thread value", GetErrorInfo(0, &info) == S_FALSE && info == NULL && refs == 1);
    SetErrorInfo(0, (IErrorInfo *)&unk_obj);
    check("SetErrorInfo clears and releases", SetErrorInfo(0, NULL) == S_OK && refs == 1);
    HMODULE ole = GetModuleHandleW(L"oleaut32.dll");
    check("GetErrorInfo ordinal 200", GetProcAddress(ole, (LPCSTR)200) == GetProcAddress(ole, "GetErrorInfo"));
    check("SetErrorInfo ordinal 201", GetProcAddress(ole, (LPCSTR)201) == GetProcAddress(ole, "SetErrorInfo"));
    refs = 0;
}

static int modules_seen, exe_seen;
static BOOL CALLBACK count_module(PCSTR name, DWORD64 base, ULONG size, PVOID ctx) {
    (void)name;
    (void)size;
    modules_seen++;
    if (base == (DWORD64)ctx) exe_seen = 1;
    return TRUE;
}

void __stdcall start(void) {
    error_info_checks();
    char marker[16];
    int native = GetEnvironmentVariableA("OSYX", marker, sizeof marker) > 0;
    const WCHAR *cl = GetCommandLineW();
    for (const WCHAR *p = cl; *p; p++)
        if (p[0] == ' ' && wcs_eq(p + 1, L"child")) {
            Sleep(400); /* a console child: never input idle */
            ExitProcess(0);
        }

    /* ---- COM apartments ---- */
    check("CoInitializeEx enters the MTA", CoInitializeEx(NULL, COINIT_MULTITHREADED) == S_OK);
    check("a second CoInitializeEx counts", CoInitializeEx(NULL, COINIT_MULTITHREADED) == S_FALSE);
    check("changing the apartment model fails", CoInitializeEx(NULL, COINIT_APARTMENTTHREADED) == RPC_E_CHANGED_MODE);
    check("CoInitializeSecurity once",
          CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL) == S_OK);
    check("CoInitializeSecurity again is too late",
          CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL) == RPC_E_TOO_LATE);
    static const GUID nowhere = {0x7a1e5e2b, 0x0c1a, 0x4d9b, {0x9c, 0x31, 0x5a, 0x05, 0x11, 0x02, 0x6e, 0x99}};
    void *obj = (void *)1;
    check("an unregistered class is not registered", CoCreateInstance(&nowhere, NULL, CLSCTX_ALL, &iid_unknown, &obj) == REGDB_E_CLASSNOTREG && obj == NULL);
    check("CoAllowSetForegroundWindow needs an object", CoAllowSetForegroundWindow(NULL, NULL) == E_INVALIDARG);
    refs = 1;
    check("CoAllowSetForegroundWindow asks for IForegroundTransfer", CoAllowSetForegroundWindow(&unk_obj, NULL) == E_NOINTERFACE && refs == 1);
    CoUninitialize();
    CoUninitialize();
    check("after CoUninitialize the thread may choose an STA", CoInitializeEx(NULL, COINIT_APARTMENTTHREADED) == S_OK);
    CoUninitialize();

    /* ---- BSTR and VARIANT ---- */
    BSTR b = SysAllocString(L"abc");
    check("SysAllocString", b && SysStringLen(b) == 3 && SysStringByteLen(b) == 6 && ((DWORD *)b)[-1] == 6 && wcs_eq(b, L"abc"));
    check("SysReAllocString", SysReAllocString(&b, L"longer text") && SysStringLen(b) == 11 && wcs_eq(b, L"longer text"));
    BSTR z = SysAllocStringLen(NULL, 4);
    check("SysAllocStringLen of NULL is zeroed", z && SysStringLen(z) == 4 && z[4] == 0);
    SysFreeString(z);
    SysFreeString(NULL);
    SetOaNoCache();
    VARIANT v, w;
    memset(&v, 0xcc, sizeof v);
    VariantInit(&v);
    check("VariantInit empties", v.vt == VT_EMPTY);
    v.vt = VT_BSTR;
    v.bstrVal = b;
    VariantInit(&w);
    check("VariantCopy copies a BSTR", VariantCopy(&w, &v) == S_OK && w.vt == VT_BSTR && w.bstrVal != b && wcs_eq(w.bstrVal, L"longer text"));
    check("VariantClear frees a BSTR", VariantClear(&v) == S_OK && v.vt == VT_EMPTY && VariantClear(&w) == S_OK);
    refs = 1;
    v.vt = VT_UNKNOWN;
    v.punkVal = &unk_obj;
    check("VariantCopy adds a reference", VariantCopy(&w, &v) == S_OK && refs == 2);
    check("VariantClear releases it", VariantClear(&w) == S_OK && refs == 1 && w.vt == VT_EMPTY);
    v.vt = 0x7f;
    check("VariantClear rejects an unknown type", VariantClear(&v) == DISP_E_BADVARTYPE);
    SAFEARRAY *sa = SafeArrayCreateVector(VT_I4, 0, 3);
    LONG idx = 1, val = 42, out_val = 0, lb = -1, ub = -1;
    void *sa_data = NULL;
    check("SafeArrayCreateVector and bounds", sa != NULL && SafeArrayGetLBound(sa, 1, &lb) == S_OK && lb == 0 && SafeArrayGetUBound(sa, 1, &ub) == S_OK && ub == 2);
    check("SafeArrayPutElement and GetElement", sa && SafeArrayPutElement(sa, &idx, &val) == S_OK && SafeArrayGetElement(sa, &idx, &out_val) == S_OK && out_val == 42);
    check("SafeArrayAccessData and UnaccessData", sa && SafeArrayAccessData(sa, &sa_data) == S_OK && ((LONG *)sa_data)[1] == 42 && SafeArrayUnaccessData(sa) == S_OK);
    v.vt = VT_ARRAY | VT_I4;
    v.parray = sa;
    check("VariantClear destroys a SAFEARRAY", VariantClear(&v) == S_OK && v.vt == VT_EMPTY);
    IStream *stm = NULL;
    HGLOBAL hstm = NULL;
    ULONG written = 0, read_cb = 0;
    char stm_buf[8] = {0};
    LARGE_INTEGER zero_pos = {0};
    check("CreateStreamOnHGlobal and GetHGlobalFromStream",
          CreateStreamOnHGlobal(NULL, TRUE, &stm) == S_OK && stm &&
          stm->lpVtbl->Write(stm, "OSyx", 4, &written) == S_OK && written == 4 &&
          stm->lpVtbl->Seek(stm, zero_pos, STREAM_SEEK_SET, NULL) == S_OK &&
          stm->lpVtbl->Read(stm, stm_buf, 4, &read_cb) == S_OK && read_cb == 4 && mem_eq(stm_buf, "OSyx", 4) &&
          GetHGlobalFromStream(stm, &hstm) == S_OK && hstm != NULL);
    if (stm) stm->lpVtbl->Release(stm);

    /* ---- window stations and desktops ---- */
    HWINSTA ws = GetProcessWindowStation();
    WCHAR name[64];
    DWORD need = 0;
    check("the process window station is WinSta0", ws && GetUserObjectInformationW(ws, UOI_NAME, name, sizeof name, &need) && wcs_eq(name, L"WinSta0") && need == 16);
    check("its type", GetUserObjectInformationW(ws, UOI_TYPE, name, sizeof name, &need) && wcs_eq(name, L"WindowStation"));
    USEROBJECTFLAGS uf;
    check("it is visible", GetUserObjectInformationW(ws, UOI_FLAGS, &uf, sizeof uf, &need) && (uf.dwFlags & WSF_VISIBLE));
    check("a short buffer reports the size", !GetUserObjectInformationW(ws, UOI_NAME, name, 4, &need) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && need == 16);
    HDESK desk = GetThreadDesktop(GetCurrentThreadId());
    check("the thread desktop is Default", desk && GetUserObjectInformationW(desk, UOI_NAME, name, sizeof name, &need) && wcs_eq(name, L"Default"));
    check("its type is Desktop", GetUserObjectInformationW(desk, UOI_TYPE, name, sizeof name, &need) && wcs_eq(name, L"Desktop"));
    if (native) check("the default desktop receives input", GetUserObjectInformationW(desk, UOI_IO, &uf, sizeof(BOOL), &need) && *(BOOL *)&uf);
    HWINSTA alt = CreateWindowStationW(NULL, 0, WINSTA_ALL_ACCESS, NULL);
    check("CreateWindowStationW makes a named station", alt && GetUserObjectInformationW(alt, UOI_NAME, name, sizeof name, &need) && name[0] == 'S' && name[7] == '-' && name[8] == '0' && name[9] == 'x');
    check("SetProcessWindowStation", alt && SetProcessWindowStation(alt));
    HDESK ad = CreateDesktopW(L"osyx-test", NULL, NULL, 0, GENERIC_ALL, NULL);
    check("CreateDesktopW on it", ad && GetUserObjectInformationW(ad, UOI_NAME, name, sizeof name, &need) && wcs_eq(name, L"osyx-test"));
    check("the new desktop does not receive input", ad && GetUserObjectInformationW(ad, UOI_IO, &uf, sizeof(BOOL), &need) && !*(BOOL *)&uf);
    check("back to WinSta0", SetProcessWindowStation(ws));
    check("CloseDesktop", ad && CloseDesktop(ad));
    check("CloseWindowStation", alt && CloseWindowStation(alt));
    check("the process's own station cannot be closed", !CloseWindowStation(ws));

    /* ---- WaitForInputIdle on a console child ---- */
    WCHAR self[MAX_PATH + 8];
    DWORD len = GetModuleFileNameW(NULL, self, MAX_PATH);
    WCHAR cmd[MAX_PATH + 16];
    cmd[0] = '"';
    memcpy(cmd + 1, self, len * 2);
    memcpy(cmd + 1 + len, L"\" child", 16);
    STARTUPINFOW si = {sizeof si};
    PROCESS_INFORMATION pi;
    BOOL started = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    check("the child starts", started);
    if (started) {
        DWORD wr = WaitForInputIdle(pi.hProcess, 100);
        check("a console child is not a GUI process", wr == WAIT_FAILED && GetLastError() == ERROR_NOT_GUI_PROCESS);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    /* ---- AppContainer SIDs ---- */
    PSID ac = NULL, ac2 = NULL;
    LPWSTR text = NULL;
    check("DeriveAppContainerSidFromAppContainerName",
          DeriveAppContainerSidFromAppContainerName(L"osyx.test", &ac) == S_OK && ConvertSidToStringSidW(ac, &text) &&
              wcs_eq(text, L"S-1-15-2-1002695779-2134444461-516762218-366317381-533294487-3848482040-3430533065"));
    check("AppContainer names are case-insensitive", DeriveAppContainerSidFromAppContainerName(L"OSyx.Test", &ac2) == S_OK && EqualSid(ac, ac2));
    check("an empty name is invalid", DeriveAppContainerSidFromAppContainerName(L"", &ac2) == E_INVALIDARG);
    LocalFree(text);
    FreeSid(ac);

    /* ---- dbghelp ---- */
    HANDLE me = GetCurrentProcess();
    check("SymSetOptions returns the options", SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS) == (SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS));
    check("SymInitializeW", SymInitializeW(me, NULL, TRUE));
    DWORD64 tick = (DWORD64)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount");
    BYTE symbuf[sizeof(SYMBOL_INFO) + 64];
    SYMBOL_INFO *sym = (SYMBOL_INFO *)symbuf;
    memset(symbuf, 0, sizeof symbuf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = 64;
    DWORD64 disp = 99;
    check("SymFromAddr names an export", SymFromAddr(me, tick, &disp, sym) && disp == 0 && str_eq(sym->Name, "GetTickCount") && sym->Address == tick);
    IMAGEHLP_MODULE64 mi;
    memset(&mi, 0, sizeof mi);
    mi.SizeOfStruct = sizeof mi;
    check("SymGetModuleInfo64 finds its module", SymGetModuleInfo64(me, tick, &mi) && (str_ieq(mi.ModuleName, "kernel32") || str_ieq(mi.ModuleName, "kernelbase")));
    modules_seen = exe_seen = 0;
    check("EnumerateLoadedModules64", EnumerateLoadedModules64(me, count_module, GetModuleHandleW(NULL)) && modules_seen >= 2 && exe_seen);
    if (native) {
        IMAGEHLP_LINE64 line = {sizeof line};
        DWORD ld = 0;
        check("no line information without PDBs", !SymGetLineFromAddr64(me, tick, &ld, &line));
    }
    check("SymCleanup", SymCleanup(me));

    /* ---- crypt32 ---- */
    CRYPT_DATA_BLOB blob = {sizeof pkcs7_sample, (BYTE *)pkcs7_sample};
    DWORD enc = 0, ctype = 0, fmt = 0;
    HCERTSTORE store = NULL;
    HCRYPTMSG msg = NULL;
    BOOL q = CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &enc, &ctype, &fmt, &store, &msg, NULL);
    check("CryptQueryObject reads PKCS#7 signed data", q && ctype == CERT_QUERY_CONTENT_PKCS7_SIGNED && enc == (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING) && fmt == CERT_QUERY_FORMAT_BINARY && store && msg);
    DWORD count = 0, cb = sizeof count;
    check("one signer", msg && CryptMsgGetParam(msg, CMSG_SIGNER_COUNT_PARAM, 0, &count, &cb) && count == 1);
    cb = 0;
    BOOL sized = msg && CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb);
    CMSG_SIGNER_INFO *signer = sized ? HeapAlloc(GetProcessHeap(), 0, cb) : NULL;
    check("signer info", signer && CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signer, &cb) && str_eq(signer->HashAlgorithm.pszObjId, "2.16.840.1.101.3.4.2.1") &&
                             signer->SerialNumber.cbData == 4 && signer->SerialNumber.pbData[0] == 0xcd && signer->AuthAttrs.cAttr >= 3);
    DWORD small = 8;
    BYTE tiny[8];
    check("a short parameter buffer reports ERROR_MORE_DATA", msg && !CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, tiny, &small) && GetLastError() == ERROR_MORE_DATA && small == cb);
    cb = 0;
    CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &cb);
    CERT_INFO *ci = cb ? HeapAlloc(GetProcessHeap(), 0, cb) : NULL;
    BOOL gotci = ci && CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, ci, &cb);
    PCCERT_CONTEXT cert = gotci ? CertFindCertificateInStore(store, enc, 0, CERT_FIND_SUBJECT_CERT, ci, NULL) : NULL;
    check("the signer's certificate is in the store", cert != NULL);
    WCHAR cn[64];
    check("its display name", cert && CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, cn, 64) == 17 && wcs_eq(cn, L"OSyx Test Signer"));
    check("its organization", cert && CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, szOID_ORGANIZATION_NAME, cn, 64) == 5 && wcs_eq(cn, L"OSyx"));
    check("the issuer's unit", cert && CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, szOID_ORGANIZATIONAL_UNIT_NAME, cn, 64) && wcs_eq(cn, L"Compatibility"));
    check("a missing attribute is empty", cert && CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, szOID_LOCALITY_NAME, cn, 64) == 1 && cn[0] == 0);
    check("the context decodes the certificate", cert && cert->pCertInfo->SerialNumber.cbData == 4 && cert->pCertInfo->SerialNumber.pbData[3] == 0x12 && cert->pCertInfo->dwVersion == CERT_V3);
    char x500[128] = {0};
    check("CertNameToStrA formats X500 subject", cert && CertNameToStrA(X509_ASN_ENCODING, &cert->pCertInfo->Subject, CERT_X500_NAME_STR, x500, sizeof x500) > 1 && str_eq(x500, "C=PL, O=OSyx, OU=Compatibility, CN=OSyx Test Signer"));
    check("only one certificate matches", cert && CertFindCertificateInStore(store, enc, 0, CERT_FIND_ANY, NULL, CertDuplicateCertificateContext(cert)) == NULL && GetLastError() == (DWORD)CRYPT_E_NOT_FOUND);
    CertFreeCertificateContext(cert);
    check("CertCloseStore", store && CertCloseStore(store, 0));
    check("CryptMsgClose", msg && CryptMsgClose(msg));
    HCRYPTMSG dec = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    check("a message that is not streamed comes in one piece", dec && !CryptMsgUpdate(dec, pkcs7_sample, 100, FALSE) && GetLastError() == (DWORD)CRYPT_E_MSG_ERROR);
    CryptMsgClose(dec);
    dec = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    BOOL fed = dec && CryptMsgUpdate(dec, pkcs7_sample, sizeof pkcs7_sample, TRUE);
    BYTE content[16];
    cb = sizeof content;
    check("CryptMsgUpdate decodes the message", fed && CryptMsgGetParam(dec, CMSG_CONTENT_PARAM, 0, content, &cb) && cb == 5 && mem_eq(content, "hello", 5));
    DWORD mtype = 0;
    cb = sizeof mtype;
    check("it is signed data", dec && CryptMsgGetParam(dec, CMSG_TYPE_PARAM, 0, &mtype, &cb) && mtype == CMSG_SIGNED);
    CryptMsgClose(dec);
    HCERTSTORE mem = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    check("an empty memory store", mem && CertFindCertificateInStore(mem, X509_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL) == NULL && GetLastError() == (DWORD)CRYPT_E_NOT_FOUND);
    CertCloseStore(mem, 0);
    WCHAR s64[32];
    DWORD n64 = 0;
    check("CryptBinaryToStringW sizes Base64", CryptBinaryToStringW((const BYTE *)"Hello", 5, CRYPT_STRING_BASE64, NULL, &n64) && n64 == 11);
    n64 = 32;
    check("Base64", CryptBinaryToStringW((const BYTE *)"Hello", 5, CRYPT_STRING_BASE64, s64, &n64) && n64 == 10 && wcs_eq(s64, L"SGVsbG8=\r\n"));
    n64 = 32;
    check("raw hex", CryptBinaryToStringW((const BYTE *)"Hello", 5, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, s64, &n64) && wcs_eq(s64, L"48656c6c6f"));
    n64 = 4;
    check("a short string buffer", !CryptBinaryToStringW((const BYTE *)"Hello", 5, CRYPT_STRING_BASE64, s64, &n64) && GetLastError() == ERROR_MORE_DATA);
    finish("interop");
}
