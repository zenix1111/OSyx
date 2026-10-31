#define _WIN32_WINNT 0x0602
#include "common.h"
#include <stddef.h>
_Static_assert(sizeof(CONTEXT)==1232,"Win64 context ABI");
_Static_assert(offsetof(CONTEXT,Rip)==248,"Win64 RIP offset");
_Static_assert(offsetof(CONTEXT,FltSave)==256,"Win64 FXSAVE offset");
_Static_assert(sizeof(EXCEPTION_RECORD)==152,"Win64 exception record ABI");
static LONG seen,continued,order_count,order[8],shape_ok=1;
static int ordering=1;
static ULONG_PTR write_address;
__attribute__((naked)) static ULONG64 illegal(void) {
    __asm__("mov $0x11223344,%ecx; ud2; cmp $0x4242,%rax; jne 2f; cmp $0x11223344,%rcx; jne 2f; movq %xmm0,%rax; cmp $0x7788,%rax; jne 2f; mov $1,%eax; ret; 2: xor %eax,%eax; ret");
}
__attribute__((naked)) static ULONG64 read_fault(void) {__asm__("mov $0x1000,%eax; mov (%rax),%eax; ret");}
__attribute__((naked)) static void write_fault(void *p __attribute__((unused))) {__asm__("movb $1,(%rcx); ret");}
__attribute__((naked)) static ULONG64 divide_fault(void) {__asm__("mov $1,%eax; xor %edx,%edx; xor %ecx,%ecx; div %ecx; ret");}
__attribute__((naked)) static void breakpoint(void) {__asm__("int3; ret");}
static LONG CALLBACK first(EXCEPTION_POINTERS *p) {
    if(ordering&&p->ExceptionRecord->ExceptionCode==EXCEPTION_ILLEGAL_INSTRUCTION)order[order_count++]=3;
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG CALLBACK observer(EXCEPTION_POINTERS *p) {
    if(ordering&&p->ExceptionRecord->ExceptionCode==EXCEPTION_ILLEGAL_INSTRUCTION)order[order_count++]=1;
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG CALLBACK recover(EXCEPTION_POINTERS *p) {
    EXCEPTION_RECORD *r=p->ExceptionRecord;CONTEXT *c=p->ContextRecord;
    InterlockedIncrement(&seen);
    if((c->ContextFlags&CONTEXT_FULL)!=CONTEXT_FULL)InterlockedExchange(&shape_ok,0);
    if(r->ExceptionCode==EXCEPTION_ILLEGAL_INSTRUCTION) {
        if(ordering)order[order_count++]=2;
        if(r->ExceptionAddress!=(void *)c->Rip)InterlockedExchange(&shape_ok,0);
        c->Rip+=2;c->Rax=0x4242;c->Xmm0.Low=0x7788;c->Xmm0.High=0;
    } else if(r->ExceptionCode==EXCEPTION_ACCESS_VIOLATION) {
        if(r->NumberParameters!=2)InterlockedExchange(&shape_ok,0);
        if(r->ExceptionInformation[0]==0&&r->ExceptionInformation[1]==0x1000) {c->Rip+=2;c->Rax=0xabcdef;}
        else if(r->ExceptionInformation[0]==1&&r->ExceptionInformation[1]==write_address) {c->Rip+=3;}
        else return EXCEPTION_CONTINUE_SEARCH;
    } else if(r->ExceptionCode==EXCEPTION_INT_DIVIDE_BY_ZERO) {c->Rip+=2;c->Rax=9;}
    else if(r->ExceptionCode==0xe0424242) {
        if(r->NumberParameters!=2||r->ExceptionInformation[0]!=0x1122334455667788ULL||r->ExceptionInformation[1]!=42)InterlockedExchange(&shape_ok,0);
    }
    else if(r->ExceptionCode==EXCEPTION_BREAKPOINT) {
        if(c->Rip!=(ULONG_PTR)r->ExceptionAddress)InterlockedExchange(&shape_ok,0);
        c->Rip=(ULONG_PTR)r->ExceptionAddress+1;
    } else return EXCEPTION_CONTINUE_SEARCH;
    return EXCEPTION_CONTINUE_EXECUTION;
}
static LONG CALLBACK continuation(EXCEPTION_POINTERS *p) {
    (void)p;InterlockedIncrement(&continued);return EXCEPTION_CONTINUE_SEARCH;
}
static DWORD WINAPI thread_probe(void *p) {(void)p;return illegal()==1?0:1;}
void __stdcall start(void) {
    PVOID a=AddVectoredExceptionHandler(0,observer),b=AddVectoredExceptionHandler(0,recover),c=AddVectoredExceptionHandler(1,first);
    PVOID d=AddVectoredContinueHandler(0,continuation);
    check("register real vectored handlers",a&&b&&c&&d);
    check("UD2 callback edits real integer and SSE context",illegal()==1);
    check("first and last vectored handler ordering",order_count==3&&order[0]==3&&order[1]==1&&order[2]==2);
    ordering=0;
    check("remove first handler",RemoveVectoredExceptionHandler(c)!=0);
    check("remove observer",RemoveVectoredExceptionHandler(a)!=0);
    check("read access violation has real fault address",read_fault()==0xabcdef);
    BYTE *page=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);DWORD old=0;
    BOOL protected=page&&VirtualProtect(page,4096,PAGE_READONLY,&old);write_address=(ULONG_PTR)page;
    if(protected)write_fault(page);
    check("write violation resumes without changing read-only page",protected&&*page==0);
    if(page)VirtualFree(page,0,MEM_RELEASE);
    check("integer divide fault resumes through CONTEXT",divide_fault()==9);
    breakpoint();check("INT3 reports Windows breakpoint context",seen==5&&shape_ok);
    ULONG_PTR arguments[2]={0x1122334455667788ULL,42};RaiseException(0xe0424242,0,2,arguments);
    check("RaiseException dispatches arguments and resumes its caller",seen==6&&shape_ok);
    HANDLE t1=CreateThread(NULL,0,thread_probe,NULL,0,NULL),t2=CreateThread(NULL,0,thread_probe,NULL,0,NULL);DWORD e1=99,e2=99;
    BOOL joined=t1&&t2&&WaitForSingleObject(t1,2000)==WAIT_OBJECT_0&&WaitForSingleObject(t2,2000)==WAIT_OBJECT_0&&GetExitCodeThread(t1,&e1)&&GetExitCodeThread(t2,&e2);
    if (!(joined&&e1==0&&e2==0&&seen==8&&shape_ok)) {
        put("exceptions: thread details joined="); put_uint(joined); put(" e1="); put_uint(e1);
        put(" e2="); put_uint(e2); put(" seen="); put_uint(seen); put(" shape="); put_uint(shape_ok); put("\r\n");
    }
    check("vectored faults resume separate Windows threads",joined&&e1==0&&e2==0&&seen==8&&shape_ok);
    if(t1)CloseHandle(t1);if(t2)CloseHandle(t2);
    check("vectored continuation callbacks run after recovery",continued==8);
    check("remove continuation handler",RemoveVectoredContinueHandler(d)!=0);
    check("remove recovery handler",RemoveVectoredExceptionHandler(b)!=0);
    LPTOP_LEVEL_EXCEPTION_FILTER previous=SetUnhandledExceptionFilter(recover);
    check("top-level exception filter can resume an unhandled fault",read_fault()==0xabcdef);
    check("restore top-level exception filter",SetUnhandledExceptionFilter(previous)==recover);
    finish("exceptions");
}
