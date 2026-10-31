#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <setupapi.h>
#include "common.h"

/* Verify the x64 public layouts independently of the Rust implementation. */
_Static_assert(sizeof(IP_ADAPTER_INFO) == 704, "adapter layout");
_Static_assert(sizeof(MIB_IFROW) == 860, "interface layout");
_Static_assert(sizeof(FIXED_INFO) == 600, "network layout");
_Static_assert(sizeof(ICMP_ECHO_REPLY) == 40, "icmp layout");
_Static_assert(sizeof(WIN32_FIND_DATAW) == 592, "find layout");

/* The interface-change callback OSyx registers but never calls. The types
 * are spelled out here because mingw's netioapi.h needs a newer target
 * version than this program sets. */
typedef void(WINAPI *ip_change_cb)(PVOID context, PVOID row, int type);

static void WINAPI on_interface_change(PVOID context, PVOID row, int type) {
    (void)context;
    (void)row;
    (void)type;
}

/* mingw's import library does not carry these, so they are resolved at run
 * time: the delay-load failure they cause is exactly what a missing export
 * looks like to a real program. */
typedef DWORD(WINAPI *notify_fn)(USHORT family, ip_change_cb callback, PVOID context, BOOLEAN initial, HANDLE *out);
typedef DWORD(WINAPI *cancel_fn)(HANDLE);

void __stdcall start(void) {
    WCHAR drives[8], fs[32], label[128];
    DWORD serial, flags, maxname;
    check("drive list reports C and double terminator", GetLogicalDriveStringsW(8, drives) == 4 && drives[0] == 'C' && drives[3] == 0 && drives[4] == 0);
    ULARGE_INTEGER total, freeb;
    check("volume capacity from root filesystem", GetDiskFreeSpaceExW(L"C:\\", NULL, &total, &freeb) && total.QuadPart > 0 && freeb.QuadPart <= total.QuadPart);
    check("volume filesystem name and source label", GetVolumeInformationW(L"C:\\", label, 128, &serial, &maxname, &flags, fs, 32) && fs[0] && maxname == 255);
    WIN32_FIND_DATAW fd;
    HANDLE search = FindFirstFileW(L"C:\\osyx-seed\\HELLO.*", &fd);
    check("directory search matches case-insensitive wildcard and size", search != INVALID_HANDLE_VALUE && fd.nFileSizeLow == sizeof("Hello from the OSyx root file system!\n") - 1 && fd.cFileName[0] == 'h');
    check("directory enumeration reaches end", !FindNextFileW(search, &fd) && GetLastError() == ERROR_NO_MORE_FILES);
    check("find handle closed once", FindClose(search) && !FindClose(search) && GetLastError() == ERROR_INVALID_HANDLE);
    check("change directory before root drive search", SetCurrentDirectoryW(L"C:\\home\\user"));
    search = FindFirstFileW(L"C:\\*", &fd);
    int root_seen = 0;
    if (search != INVALID_HANDLE_VALUE) {
        do { if (fd.cFileName[0] == 'b' && fd.cFileName[1] == 'i' && fd.cFileName[2] == 'n' && fd.cFileName[3] == 0) root_seen = 1; } while (FindNextFileW(search, &fd));
        FindClose(search);
    }
    check("C root wildcard ignores current directory", root_seen);
    SetCurrentDirectoryW(L"C:\\");
    check("unknown drive rejected", !GetDiskFreeSpaceExW(L"Z:\\", NULL, &total, &freeb) && GetLastError() == ERROR_PATH_NOT_FOUND);
    DWORD need = 0;
    check("adapter size query returns buffer overflow", GetAdaptersInfo(NULL, &need) == ERROR_BUFFER_OVERFLOW && need >= sizeof(IP_ADAPTER_INFO));
    IP_ADAPTER_INFO *a = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need);
    check("adapter reports real IPv4, MAC and interface", GetAdaptersInfo(a, &need) == NO_ERROR && a->Index && a->AddressLength == 6 && a->AdapterName[0] && a->IpAddressList.IpAddress.String[0]);
    ULONG n = 0;
    check("interface size query", GetIfTable(NULL, &n, TRUE) == ERROR_INSUFFICIENT_BUFFER && n >= sizeof(MIB_IFTABLE));
    MIB_IFTABLE *ifs = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
    check("interface counters and MTU", GetIfTable(ifs, &n, TRUE) == NO_ERROR && ifs->dwNumEntries > 0 && ifs->table[0].dwMtu > 0);
    ULONG nl = 0;
    check("network parameters size query", GetNetworkParams(NULL, &nl) == ERROR_BUFFER_OVERFLOW && nl >= sizeof(FIXED_INFO));
    FIXED_INFO *info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nl);
    check("host name and DNS server", GetNetworkParams(info, &nl) == NO_ERROR && info->HostName[0] && info->DnsServerList.IpAddress.String[0]);
    HMODULE ip = LoadLibraryA("iphlpapi.dll");
    notify_fn notify = (notify_fn)(ULONG_PTR)GetProcAddress(ip, "NotifyIpInterfaceChange");
    cancel_fn cancel = (cancel_fn)(ULONG_PTR)GetProcAddress(ip, "CancelMibChangeNotify2");
    HANDLE change = NULL;
    DWORD watched = (notify && cancel) ? notify(AF_INET, on_interface_change, NULL, FALSE, &change) : ERROR_CALL_NOT_IMPLEMENTED;
    check("interface change notification registers and cancels",
          watched == NO_ERROR && change != NULL && cancel(change) == NO_ERROR &&
              cancel(change) == ERROR_INVALID_PARAMETER);
    HANDLE ping = IcmpCreateFile();
    char reply[128], payload[] = "OSyx echo";
    DWORD replies = IcmpSendEcho(ping, 0x0100007f, payload, sizeof payload, NULL, reply, sizeof reply, 2000);
    ICMP_ECHO_REPLY *echo = (ICMP_ECHO_REPLY *)reply;
    check("native ICMP echo preserves payload", replies == 1 && echo->Status == 0 && echo->DataSize == sizeof payload && mem_eq(echo->Data, payload, sizeof payload));
    check("ICMP handle closed once", IcmpCloseHandle(ping) && !IcmpCloseHandle(ping) && GetLastError() == ERROR_INVALID_HANDLE);
    HDEVINFO set = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    SP_DEVINFO_DATA dev = {0}; dev.cbSize = sizeof dev;
    check("device inventory contains a real device", set != INVALID_HANDLE_VALUE && SetupDiEnumDeviceInfo(set, 0, &dev));
    DWORD prop_type, bytes = 0;
    check("device property reports required UTF16 bytes", !SetupDiGetDeviceRegistryPropertyW(set, &dev, SPDRP_HARDWAREID, &prop_type, NULL, 0, &bytes) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytes > 4 && prop_type == REG_MULTI_SZ);
    WCHAR hwid[128];
    check("device hardware ID is PCI", SetupDiGetDeviceRegistryPropertyW(set, &dev, SPDRP_HARDWAREID, &prop_type, (BYTE *)hwid, sizeof hwid, &bytes) && hwid[0] == 'P' && hwid[1] == 'C' && hwid[2] == 'I');
    check("device registry mutation is not claimed supported", !SetupDiGetDeviceRegistryPropertyW(set, &dev, SPDRP_SERVICE, &prop_type, (BYTE *)hwid, sizeof hwid, &bytes) && GetLastError() == ERROR_NOT_SUPPORTED);
    check("device set closed once", SetupDiDestroyDeviceInfoList(set) && !SetupDiDestroyDeviceInfoList(set) && GetLastError() == ERROR_INVALID_HANDLE);
    ULONG aa_size = 0;
    check("GetAdaptersAddresses size query", GetAdaptersAddresses(AF_INET, 0x90, NULL, NULL, &aa_size) == ERROR_BUFFER_OVERFLOW && aa_size >= sizeof(IP_ADAPTER_ADDRESSES));
    IP_ADAPTER_ADDRESSES *aa = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, aa_size);
    check("GetAdaptersAddresses populates unicast and friendly name",
          GetAdaptersAddresses(AF_INET, 0x90, NULL, aa, &aa_size) == NO_ERROR &&
          aa->FriendlyName && aa->FriendlyName[0] && aa->FirstUnicastAddress &&
          aa->FirstUnicastAddress->Address.lpSockaddr && aa->FirstUnicastAddress->Address.iSockaddrLength == 16);
    typedef DWORD(WINAPI *get_ip_if_table_fn)(USHORT, PVOID *);
    typedef void(WINAPI *free_mib_fn)(PVOID);
    typedef PCHAR(WINAPI *idx2name_fn)(ULONG, PCHAR);
    get_ip_if_table_fn get_if_table2 = (get_ip_if_table_fn)(ULONG_PTR)GetProcAddress(ip, "GetIpInterfaceTable");
    free_mib_fn free_mib = (free_mib_fn)(ULONG_PTR)GetProcAddress(ip, "FreeMibTable");
    idx2name_fn idx2name = (idx2name_fn)(ULONG_PTR)GetProcAddress(ip, "if_indextoname");
    ULONG *mib_tbl = NULL;
    check("GetIpInterfaceTable and FreeMibTable", get_if_table2 && free_mib && get_if_table2(AF_INET, (PVOID *)&mib_tbl) == NO_ERROR && mib_tbl && mib_tbl[0] > 0);
    if (mib_tbl) free_mib(mib_tbl);
    struct sockaddr_in dst_sa = {0};
    dst_sa.sin_family = AF_INET;
    dst_sa.sin_addr.s_addr = 0x0100007f;
    DWORD best_idx = 0;
    char ifname[256] = {0};
    check("GetBestInterfaceEx and if_indextoname", GetBestInterfaceEx((struct sockaddr *)&dst_sa, &best_idx) == NO_ERROR && idx2name && idx2name(best_idx, ifname) == ifname && ifname[0]);
    HeapFree(GetProcessHeap(), 0, aa);
    HeapFree(GetProcessHeap(), 0, a); HeapFree(GetProcessHeap(), 0, ifs); HeapFree(GetProcessHeap(), 0, info);
    finish("sysadmin");
}

