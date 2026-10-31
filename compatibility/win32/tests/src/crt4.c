/* Remaining CRT imports of xul.dll: independently checked Windows x64
 * stat layouts, filesystem behaviour, environment and string conversion. */
#include "common.h"
#include <stdint.h>
#include <stddef.h>
#pragma clang diagnostic ignored "-Wdll-attribute-on-redeclaration"
#define IMP __declspec(dllimport)
typedef struct _iobuf FILE;
typedef void (*iph)(const wchar_t *, const wchar_t *, const wchar_t *, unsigned, uintptr_t);
IMP iph _set_invalid_parameter_handler(iph);
IMP int *_errno(void);
IMP int _putenv(const char *);
IMP int getenv_s(size_t *, char *, size_t, const char *);
IMP wchar_t *_wgetdcwd(int, wchar_t *, int);
IMP wchar_t *_wgetcwd(wchar_t *, int);
IMP void free(void *);
IMP int strcmp(const char *, const char *);
IMP int wcscmp(const wchar_t *, const wchar_t *);
IMP unsigned long _getdrives(void);
IMP int _wchmod(const wchar_t *, int);
IMP int _mktemp_s(char *, size_t);
IMP int _wmktemp_s(wchar_t *, size_t);
IMP FILE *_wfopen(const wchar_t *, const wchar_t *);
IMP size_t fwrite(const void *, size_t, size_t, FILE *);
IMP int fflush(FILE *);
IMP int fclose(FILE *);
IMP int _fileno(FILE *);
IMP int _wremove(const wchar_t *);
IMP char *setlocale(int, const char *);
IMP size_t mbsrtowcs(wchar_t *, const char **, size_t, void *);
IMP unsigned char *_mbsinc(const unsigned char *);
IMP unsigned char *_mbsdec(const unsigned char *, const unsigned char *);
struct header_ { unsigned dev; unsigned short ino, mode; short nlink, uid, gid; unsigned rdev; };
struct stat64_ { struct header_ h; long long size, atime, mtime, ctime; };
struct stat64i32_ { struct header_ h; long size; long long atime, mtime, ctime; };
IMP int _wstat64(const wchar_t *, struct stat64_ *);
IMP int _wstat64i32(const wchar_t *, struct stat64i32_ *);
IMP int _fstat64i32(int, struct stat64i32_ *);
_Static_assert(sizeof(struct stat64_) == 56, "stat64 Windows x64 size");
_Static_assert(offsetof(struct stat64_, size) == 24, "stat64 size offset");
_Static_assert(sizeof(struct stat64i32_) == 48, "stat64i32 Windows x64 size");
_Static_assert(offsetof(struct stat64i32_, size) == 20, "stat64i32 size offset");
_Static_assert(offsetof(struct stat64i32_, atime) == 24, "stat64i32 time offset");
static int calls;
static void invalid(const wchar_t *a, const wchar_t *b, const wchar_t *c, unsigned d, uintptr_t e) {
    (void)a; (void)b; (void)c; (void)d; (void)e; calls++;
}
#define E (*_errno())
static void environment(void) {
    char b[32]; size_t need = 99;
    _putenv("OSYX_CRT4_ENV=hello");
    check("getenv_s queries size including NUL", getenv_s(&need,NULL,0,"OSYX_CRT4_ENV") == 0 && need == 6);
    check("getenv_s copies case-insensitive name", getenv_s(&need,b,sizeof b,"osyx_crt4_env") == 0 && need == 6 && strcmp(b,"hello") == 0);
    b[0]='X'; E=0;
    int r=getenv_s(&need,b,3,"OSYX_CRT4_ENV");
    check_eq("getenv_s short buffer result",r,34);
    check_eq("getenv_s short buffer required size",need,6);
    check_eq("getenv_s short buffer clears output",b[0],0);
    check_eq("getenv_s short buffer preserves errno",E,0);
    _putenv("OSYX_CRT4_ENV="); b[0]='X';
    check("getenv_s missing variable is empty", getenv_s(&need,b,sizeof b,"OSYX_CRT4_ENV") == 0 && need == 0 && b[0] == 0);
    calls=0; E=0;
    check("getenv_s validates size output", getenv_s(NULL,b,sizeof b,"x") == 22 && calls == 1 && E == 22);
    wchar_t w[512], cwd[512];
    check("wgetdcwd drive zero means current drive", _wgetdcwd(0,w,512) == w && _wgetcwd(cwd,512) == cwd && wcscmp(w,cwd) == 0);
    wchar_t *allocated = _wgetdcwd(0,NULL,0);
    check("wgetdcwd allocates through CRT heap", allocated && wcscmp(allocated,cwd) == 0);
    free(allocated);
    calls=0; E=0;
    check("wgetdcwd rejects invalid drive number", _wgetdcwd(27,w,512) == NULL);
    check_eq("wgetdcwd invalid drive errno",E,13);
    check("wgetdcwd invalid drive handler is invoked",calls > 0);
    check("getdrives includes C drive", (_getdrives() & 4) != 0);
}
static void files(void) {
    wchar_t path[64]=L"crt4-XXXXXX";
    check("wmktemp_s creates a candidate name", _wmktemp_s(path,64) == 0 && wcscmp(path,L"crt4-XXXXXX") != 0);
    check("temporary name is not yet a file", GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
    FILE *f = _wfopen(path,L"w+b");
    check("metadata fixture opens", f != NULL);
    if(f) {
        check("metadata fixture writes", fwrite("abcdef",1,6,f) == 6 && fflush(f) == 0);
        struct stat64_ s;
        struct stat64i32_ t;
        check("wstat64 Windows layout and file size", _wstat64(path,&s) == 0 && s.size == 6 && (s.h.mode & 0xf000) == 0x8000 && s.h.uid == 0 && s.h.gid == 0 && s.h.nlink >= 1);
        check("stat timestamps describe a real file", s.atime > 1600000000LL && s.mtime > 1600000000LL && s.ctime > 1600000000LL);
        check("wstat64i32 agrees with wstat64", _wstat64i32(path,&t) == 0 && t.size == 6 && t.mtime == s.mtime);
        check("fstat64i32 uses the actual CRT descriptor", _fstat64i32(_fileno(f),&t) == 0 && t.size == 6 && (t.h.mode & 0xf000) == 0x8000);
        fclose(f);
        check("wchmod sets readonly attribute", _wchmod(path,0x100) == 0 && (GetFileAttributesW(path) & FILE_ATTRIBUTE_READONLY));
        check("stat reports readonly mode", _wstat64(path,&s) == 0 && (s.h.mode & 0x80) == 0);
        check("wchmod restores writable attribute", _wchmod(path,0x180) == 0 && !(GetFileAttributesW(path) & FILE_ATTRIBUTE_READONLY));
        wchar_t another[64]=L"crt4-XXXXXX";
        check("wmktemp_s avoids an existing candidate", _wmktemp_s(another,64) == 0 && wcscmp(path,another) != 0);
        _wremove(path);
    }
    struct stat64_ s;
    struct stat64i32_ t;
    check("wstat64 identifies a directory", _wstat64(L".",&s) == 0 && (s.h.mode & 0xf000) == 0x4000);
    E=0;
    check("wstat64 missing path reports ENOENT", _wstat64(L"crt4-no-such-file.xyz",&s) == -1 && E == 2);
    calls=0; E=0;
    check("fstat validates descriptor", _fstat64i32(-1,&t) == -1 && E == 9 && calls == 1);
    char candidate[64]="crt4a-XXXXXX";
    check("mktemp_s changes six trailing Xs", _mktemp_s(candidate,64) == 0 && strcmp(candidate,"crt4a-XXXXXX") != 0);
    char bad[4]="bad"; calls=0; E=0;
    check("mktemp_s rejects a malformed template", _mktemp_s(bad,sizeof bad) == 22 && bad[0] == 0 && calls == 1 && E == 22);
}
static void multibyte(void) {
    wchar_t out[16]; uint64_t state=0;
    const char *p="abc", *original=p;
    setlocale(2,"C");
    check("mbsrtowcs size query preserves source", mbsrtowcs(NULL,&p,0,&state) == 3 && p == original && state == 0);
    check("mbsrtowcs bounded prefix preserves cursor", mbsrtowcs(out,&p,2,&state) == 2 && p == original+2 && out[0] == 'a' && out[1] == 'b');
    check("mbsrtowcs resumes and terminates", mbsrtowcs(out,&p,16,&state) == 1 && p == NULL && out[0] == 'c' && out[1] == 0 && state == 0);
    p="abc"; original=p;
    check("mbsrtowcs zero output length reads nothing", mbsrtowcs(out,&p,0,&state) == 0 && p == original);
    setlocale(2,".UTF-8"); p="\xc5\xbc";
    check("mbsrtowcs converts UTF8 into UTF16", mbsrtowcs(out,&p,16,&state) == 1 && out[0] == 0x17c && out[1] == 0 && p == NULL);
    p="\xc5"; E=0;
    check("mbsrtowcs rejects truncated UTF8", mbsrtowcs(out,&p,16,&state) == (size_t)-1 && E == 42);
    setlocale(2,"C");
    const unsigned char bytes[]="ab";
    check("mbsinc advances one C locale character", _mbsinc(bytes) == bytes+1);
    check("mbsdec finds the previous character", _mbsdec(bytes,bytes+2) == bytes+1 && _mbsdec(bytes,bytes) == NULL);
    char marker[8];
    if(GetEnvironmentVariableA("OSYX",marker,sizeof marker)) {
        setlocale(2,".UTF-8");
        const unsigned char utf[]="\xc5\xbc!";
        check("OSyx multibyte cursors respect UTF8 boundaries", _mbsinc(utf) == utf+2 && _mbsdec(utf,utf+2) == utf);
        setlocale(2,"C");
    }
}
static void legacy_format(void) {
    HMODULE crt = LoadLibraryA("msvcrt.dll");
    int (*narrow)(char *, size_t, const char *, ...) = crt ? (void *)GetProcAddress(crt, "_snprintf") : NULL;
    int (*wide)(wchar_t *, size_t, const wchar_t *, ...) = crt ? (void *)GetProcAddress(crt, "_snwprintf") : NULL;
    char buf[16] = {0}; wchar_t wbuf[16] = {0};
    check("_snprintf formats x64 variadic arguments", narrow && narrow(buf, sizeof buf, "%s:%d", "os", 42) == 5 && strcmp(buf, "os:42") == 0);
    check("_snwprintf formats x64 variadic arguments", wide && wide(wbuf, 16, L"%s:%u", L"os", 42) == 5 && wcscmp(wbuf, L"os:42") == 0);
    buf[4] = 'X';
    check("_snprintf truncates without writing a terminator", narrow && narrow(buf, 4, "%s", "hello") == -1 && buf[3] == 'l' && buf[4] == 'X');
    long long (*crt_time)(long long *) = crt ? (void *)GetProcAddress(crt, "time") : NULL;
    struct { long long seconds; uint64_t guard; } now = { 0, 0xa5a5a5a5a5a5a5a5ULL };
    long long seconds = crt_time ? crt_time(&now.seconds) : -1;
    check("msvcrt x64 time writes eight bytes", crt_time && seconds > 0 && now.seconds == seconds && now.guard == 0xa5a5a5a5a5a5a5a5ULL && crt_time(NULL) >= seconds);
}
void __stdcall start(void) {
    _set_invalid_parameter_handler(invalid);
    environment(); files(); multibyte(); legacy_format();
    finish("crt4");
}
