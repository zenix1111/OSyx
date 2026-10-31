# Windows compatibility

**Status: initial PE32+ runtime implemented and tested in QEMU.** The first
Windows 11 research pass (API set schema, export forwarding) is in
[research/windows11-apiset-and-forwarding.md](research/windows11-apiset-and-forwarding.md).

## Principles

- Independent implementation of observable behaviour; no Microsoft code,
  no redistributed Microsoft binaries, no Wine/Proton/ReactOS code.
- Research notes stay in `research/` (with question, Windows build,
  methodology, evidence, uncertainties, proposed implementation, regression
  tests) and are kept separate from implementation code.
- Host research uses small documented-API test programs and REA static
  analysis; nothing on the host is patched or replaced.
- Unsupported behaviour returns explicit NTSTATUS / Win32 errors; no stubs that
  pretend to succeed.

## Architecture and supported surface

`/bin/winrun program.exe [args...]` is a normal OSyx ring-3 program. It maps
validated PE images through `compatibility/pe-loader`, enforces W^X, applies
DIR64 relocations, resolves named/ordinal imports and export forwarders,
maps the implemented API set contracts, builds PEB/TEB and TLS state, runs
DLL/TLS initializers, then calls the entry using the Windows x64 ABI. GS
holds each Windows thread's TEB and is switched by the kernel. FS remains
available to the OSyx runtime. Supported exceptions may resume through a
registered vectored handler; unhandled faults terminate the OSyx process.

The built-in system DLLs take precedence over DLL files; other DLLs are
searched beside the executable and in the current directory. Missing DLLs
and symbols produce a loader diagnostic before the entry point executes.

| Module | Implemented subset |
|---|---|
| ntdll | File/section/memory operations, thread creation and waits, process/time queries, last-error/status helpers |
| kernel32 / kernelbase | Console and synchronous file I/O, handles, process/thread identity and exit, threads, events/mutexes/semaphores/waits, TLS, virtual memory/heap, clocks, environment/arguments, dynamic DLL loading, strings and UTF conversion |
| kernel32 volume APIs | C: root volume information/capacity, drive enumeration, UTF-16 FindFirstFile/FindNextFile/FindClose with ASCII-insensitive wildcards |
| user32 / gdi32 | Top-level PRISM windows, message queues, paint/input/timers, software GDI text/brushes/pens/rectangles, MB_OK and MB_OKCANCEL dialogs |
| ws2_32 | IPv4 TCP/UDP sockets, bind/connect/listen/accept, send/receive, basic socket options, DNS/getaddrinfo and ordinal imports |
| setupapi | Read-only ALLCLASSES/PRESENT inventory from real kernel PCI functions and attached HID inputs; descriptions, classes, hardware IDs, locations |
| iphlpapi | GetAdaptersInfo, GetIfTable, GetNetworkParams and synchronous ICMP echo, backed by OSyx interface counters/configuration, DNS and PingSocket |
| version | GetFileVersionInfoSizeW/GetFileVersionInfoW read actual PE RT_VERSION data; VerQueryValueW returns checked fixed, string and translation values |
| kernel32 synchronization | Shared/exclusive SRW locks, serialized InitOnceExecuteOnce with failure retry, condition variables with lock reacquisition, aligned 32-bit WaitOnAddress and wake operations |
| kernel32 waitable timers | Manual/automatic reset, relative/absolute deadlines, periodic timers, cancellation and object waits, using OSyx clocks/futexes |
| kernel32 / psapi | K32EnumProcessModules/Ex and EnumProcessModules/Ex report actual modules of the current process with byte-capacity checks |
| advapi32 / security-base | SID construction/copy/equality, common well-known SIDs, bounded ACL/ACE building and validation, absolute security-descriptor setters and absolute/self-relative getters; query-only process identity tokens |
| kernel32 / ntdll exception callbacks | Vectored hardware exceptions and continue handlers, top-level filter and continuable RaiseException; real Win64 CONTEXT integer/control/x87/SSE state over native CPU fault delivery |

SetupAPI rejects unsupported properties (including registry driver-service
information); it does not install drivers or fabricate driver names.
IP Helper reports unknown link speed as zero. Adapter statistics are the
real stack counters; MIB_IFROW's legacy DWORD counters wrap at 32 bits.
Version APIs do not merge MUI satellites. WaitOnAddress sizes other than
an aligned DWORD fail explicitly. Waitable timer APCs, suspend wakeups
and requested high-resolution timer creation are unsupported.
Timer creation currently accepts default security and TIMER_ALL_ACCESS;
custom security attributes or restricted access requests fail explicitly.
Module enumeration does not support remote processes or 32-bit module filters.
Process tokens derive user/group SIDs from actual kernel credentials as
S-1-22-1-uid / S-1-22-2-gid. Groups include World, Authenticated Users,
Builtin Users and, for native uid 0, Builtin Administrators. These are OSyx
identity mappings, not fabricated Windows accounts. Only TokenUser,
TokenGroups, TokenOwner, TokenPrimaryGroup and TokenType queries are supported.
Token handles enforce TOKEN_QUERY, including rights-reduced duplicates.
Impersonation, Windows privileges, token mutation and sandbox enforcement
are not implemented. Custom security descriptors/inheritable handles in
Win32 file/directory/thread/event/mutex/semaphore creation fail explicitly;
default attributes with a null descriptor and no inheritance are accepted.

## Software GDI surfaces

`user32/gdi.rs` supplies display/information DCs and memory DCs. Selected
bitmaps own stable DWORD-aligned storage; CreateDIBSection exposes that
storage until DeleteObject. Both DIB row orientations and BI_RGB
1/8/16/24/32-bpp data are decoded to the software renderer's 32-bit pixels;
16/32-bit BI_BITFIELDS masks are also accepted. SRCCOPY preserves all four
bytes between 32-bpp surfaces. Window drawing uses the same paint and region
clipping as memory drawing, and EndPaint/ReleaseDC present damage to PRISM.
Regions use nonoverlapping rectangles and preserve holes through boolean
operations. SaveDC/RestoreDC retain selections, colors, clip and transform.

This is still a software subset. Display DCs expose capabilities rather than
permission to overwrite the desktop. File-mapping-backed DIB sections, RLE,
DIB_PAL_COLORS, arbitrary raster operations and OpenGL pixel formats are
unsupported. Bitmap atlas fonts have no sfnt tables or TrueType outlines;
the compositor has no ICC profile. Those queries report failure. Glyph
indices are local atlas identities; glyph bitmaps support an identity MAT2.
Cubics are flattened to 24 line segments; geometric pen joins and transformed
rectangular paths use rectangle approximations. Matrix state composes fully;
raster blits and glyph images currently transform their origins without
resampling their pixels for scale/rotation. Only MM_TEXT is accepted. These
limits and a successful GDI fixture do not imply that Gecko can render a
browser window.

## Programs and tests

Shell process identity supports Get/SetCurrentProcessExplicitAppUserModelID.
The explicit UTF-16 ID is shared by the process's threads, starts unset in
each child process, and each query returns a separate CoTaskMemFree-owned
copy. These APIs store application metadata; PRISM taskbar grouping policy
is still separate.

`scripts/build-wintests.ps1` uses MSYS2 clang/lld and public import libraries
to build the test executables without a C runtime. `scripts/win-test.ps1`
boots `init.args=win,7111,7112 test.exit`, runs them on OSyx, and checks both
their own assertions and the host TCP/UDP echo server's log:

- `minimal.exe`: relocation and exit code 42.
- `shell.exe`: known folders, the task allocator, and explicit process
  AppUserModelIDs, including Unicode/copy ownership, length limits, clearing,
  cross-thread updates and child-process isolation.
- `ole2.exe`: OLE apartment initialization, nested counts separate from COM
  counts, STA/MTA conflicts, matching teardown and thread isolation; GUID
  strings (CLSIDFromString, IIDFromString, StringFromGUID2/CLSID/IID),
  drop-target registration, the OLE clipboard calls, ReleaseStgMedium and
  CoIncrementMTAUsage. No drag source exists between windows, so DoDragDrop
  ends as cancelled and no drop ever reaches a target; OleGetClipboard only
  returns a data object this process set.
- `msgwait.exe`: MsgWaitForMultipleObjects(Ex) and GetQueueStatus (current
  and new QS_* bits, MWMO_INPUTAVAILABLE, cross-thread post wake-up) and
  SHGetPropertyStoreForWindow (values shared per window as VT_LPWSTR text,
  S_FALSE for a stored value, dropped with the window).
- `dwm.exe`: dwmapi window attributes (cloaking, extended frame bounds),
  composition timing on a 60 Hz clock and DwmFlush; imm32 with no input
  context (OSyx has no IME); wtsapi32 session notifications.
- `keyboard.exe`: the US layout (00000409) through MapVirtualKeyEx and
  ToUnicodeEx, generated from Windows' own layout tables, layout queries and
  Get/SetKeyboardState.
- `input.exe`: capture, TrackMouseEvent (WM_MOUSELEAVE), GetLastInputInfo,
  MapWindowPoints, EnumThreadWindows, display devices and the current mode,
  clipboard format atoms, icons (CreateIconIndirect/GetIconInfo/DestroyIcon)
  and the user32 clipboard, which is always empty (OLE is the only writer).
- `shlpath.exe`: PathCombineW, PathFindFileNameW, PathIsNetworkPathW,
  PathUnExpandEnvStringsW, StrStrIW and IsOS (ordinal 437).
- `secattr.exe`: SECURITY_ATTRIBUTES with a descriptor on unnamed sections
  (ignored, as Windows does), named sections (stored and reported by
  GetSecurityInfo) and new directories (the DACL becomes the mode).
- `hello.exe`: console, command line, PEB/TEB, modules and errors.
- `fileio.exe`: files, sharing and delete-on-close inside one winrun process.
- `threads.exe` / `windll.dll`: synchronization, TLS, memory and DLL loading.
- `winsock.exe`: TCP and UDP against a host server.
- `gui.exe`: a real PRISM window, GDI painting and timers, including a
  32-bpp DIB copied from a memory DC into the PRISM surface and read back.
- `gdi2.exe`: native-Windows-verified DC/bitmap lifetimes, exposed DIB pixels,
  SRCCOPY (including overlap), BLACKNESS/WHITENESS, row order and partial
  scan lines, 32/24/16/8-bpp conversion, region holes and serialization,
  paths, saved DC state, XFORM composition, aligned/clipped text, font queries
  and unsupported OpenGL entry points. C static assertions verify the x64
  layouts independently of Rust.
- `sysadmin.exe`: volume/directory data, buffer sizing, device/adapter
  enumeration, handle lifetime and ICMP payload preservation. C static
  assertions independently verify the Windows x64 structure sizes.
- `version.exe`: real version-resource values, UTF-16 strings, translations,
  insufficient buffers and missing values; the same fixture also runs on Windows.
- `synch.exe`: concurrent readers, once success/failure retry, condition
  handoff/timeouts, futex wakeups, module handles/capacities and real timers.
- `security.exe`: independently encoded SID/ACE/descriptor fields, bounds
  and error paths, self-relative offsets, token sizes/pointers, query rights
  and handle lifetimes. Also run after native setuid(1000,1000) and exec.
- `exceptions.exe`: actual UD2, access faults, divide, INT3, software raise,
  CONTEXT edits, callback order, independent threads and top-level filter.
  Native `worker fault-checks` also verifies kernel continuation validation.

`scripts/build-winapps.ps1` builds four GUI applications from
`compatibility/win32/apps/src`: Text Editor, Disk Utility, Device Manager
and Network Center. The same PE files also run on Windows. `build.ps1`
installs them in `/opt/apps`; desktop entries invoke them through winrun.
The desktop integration test launches and closes each with USB input.

## Known limits

This is a small Win32 subset, not general Windows application compatibility.
UCRT, COM, registry, SEH, process creation and delay imports have partial
implementations. PE32/WoW64, .NET, Windows kernel drivers, general native
child-window controls and accelerated DirectX rendering are absent.
Imports outside the implemented surface fail, and arbitrary application
installers are unsupported. Anonymous memory is demand-zero;
PAGE_NOACCESS currently has a read-only backing mapping (see `mem.rs`).
File sharing and named synchronization lookup tables remain local to one
winrun process. ANSI strings are UTF-8 with Latin-1 fallback, not a full
Windows code-page implementation.

CreateProcess can inherit explicitly selected events, shared page-file
sections and connected pipes; DuplicateHandle transfers these objects
between Windows processes. File, mutex and semaphore inheritance is not
implemented. Shared events use shared memory and kernel futexes keyed by
the shared object, so a signal in one process wakes a waiter in another.
The Zen diagnostic launcher disables Gecko's Windows sandboxes through
Mozilla's environment switches; the Windows sandbox broker is unsupported.

Windows windows start hidden and follow ShowWindow/SetWindowPos visibility.
Message-only, tool and owned windows do not create separate taskbar items.
The desktop groups eligible windows from a winrun process and its Windows
descendants under the named parent window; unrelated applications retain
their own entries. Popup ownership is exposed through GetParent,
GetWindow(GW_OWNER) and GetAncestor(GA_ROOTOWNER). Native child controls
inside a parent client area remain unsupported.

DirectWrite exposes the original IDWriteFactory font/file/face APIs,
custom font loaders, metrics, character maps, TrueType, CFF and default-instance CFF2 outlines and glyph
coverage rasterization. The bundled unmodified Lato and KaTeX fonts and
their SIL OFL license are in `graphics/assets/fonts/windows`; registry
substitutes map common Windows family names to them. There is no hinting,
ClearType subpixel filtering, custom variation-axis selection, DirectWrite text
layout/analysis or newer factory interface support. Existing GDI atlas
fonts remain separate from these DirectWrite font faces.

Private PAGE_EXECUTE_READWRITE allocations support JIT code by alternating
individual pages between RW/NX and RX on write and instruction-fetch
faults. Kernel W^X remains enforced. The logical protection returned by
VirtualQuery remains PAGE_EXECUTE_READWRITE. Instructions that modify the
same page they execute from, and writable executable shared/file sections,
remain unsupported. JIT code patching and execution require external
synchronization as on Windows.

C: maps to `/`; other drive letters and UNC paths are rejected. Mounted
filesystems are available through paths such as `C:\boot` and `C:\tmp`.
Disk Utility currently lists C:; it does not manage partitions. Device
Manager reports OSyx's PCI/input inventory, not all Windows PnP properties.
Network Center supports IPv4; custom ICMP IP options fail explicitly.

## File system preparation (VFS)

The NT file semantics are meant to be implemented by the compatibility
layer on top of the VFS, not inside the file system drivers (ext4 stays a
plain ext4 driver):

| Windows concept | VFS support today | Still to build in the compatibility layer |
|---|---|---|
| Case-insensitive names | `OPEN_CASE_INSENSITIVE` / `Lookup::case_insensitive`: every component matched ASCII case-insensitively, exact match first, canonical spelling kept (mount points found too); FAT is case-insensitive natively | Unicode upcase table semantics, collisions (`a` and `A` in one ext4 directory) |
| Drive letters, `\` separators, `\\?\`, `\Device\…` | — | translation table `C:` → VFS path, object-namespace symbolic links to mount points |
| File handles | per-process handle tables of shared open files with reference counting | NT handle values, access masks, inheritance, `DuplicateHandle` |
| Sharing modes, byte-range locks | stable node identity `(FileStat::dev, FileStat::ino)` on every file system (FAT gets assigned numbers that survive renames) to key share/lock tables | the tables themselves, `ERROR_SHARING_VIOLATION`, delete-on-close |
| Removing open files | FAT refuses with `Busy` (like Windows); ext4/tmpfs allow it (POSIX) | Windows-style refusal for any volume when opened through the NT layer |
| Metadata | `FileStat`: size, times (ns), mode, owner, FAT attributes | creation time, attribute mapping for ext4, security descriptors |

## Compatibility matrix

The executable tests and the module table above are the current subset
matrix. See [testing.md](testing.md) for recorded validation results.
The unmodified official Zen Browser Windows x64 package remains blocked;
measured loader failures and package dependency gaps are documented in
[research/zen-bringup.md](research/zen-bringup.md). It is not a supported
desktop application and is not registered as the default browser.
