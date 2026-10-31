# Browser content sandbox: implementation notes

Status: experimental prototype, off by default. Gecko content processes are not
sandboxed yet.

Implemented and exercised by `scripts/sandbox-test.ps1` (also with `-Winrun`):
policy installation at child creation, inheritance through `exec`, VFS path
checks during resolution, handle restrictions, IPC isolation, deny-by-default
syscall filtering, broker channel grants and held-start children.

The VFS has experimental path checks when an explicit lookup policy is
supplied. An unrestricted parent can request both policies for a child before
loading its image; descendants inherit them. Restricted children cannot inherit
file stdio handles, receive file-backed sections over IPC, or publish shared
images. They cannot connect to or register global IPC services, and may kill
only themselves or direct children. A parent may grant one broker channel
as child handle 3, plus up to 32 channels in consecutive handles from 4.
The kernel validates every granted handle before starting the child. An
unrestricted parent may also grant a channel to its live, restricted direct
child after startup. Anonymous channel pairs avoid exposing a service name.
The channel's recorded peer identity describes its original
connection, not necessarily the child. Other handle and IPC paths remain
unreviewed. This is not a browser sandbox.
Installation and inheritance need adversarial runtime and concurrency tests.

Winrun has an experimental, opt-in `CreateProcess` path for `/opt/zen/zen.exe`
with `-contentproc`, enabled only by `OSYX_EXPERIMENTAL_CONTENT_SANDBOX=1`.
Its provisional read-only paths and syscall list have not been tested with
Gecko. The path fails closed when requested handles are unsupported. Winrun
can decode inherited page-file sections and events from the granted channel;
connected pipes use separately granted channel relays. The retained broker
channel can duplicate events, anonymous sections and connected pipes after
startup. It refuses files, file-backed sections and unsupported object types. The protocol and
the full set of grants Gecko requires still need validation.

A deny-by-default syscall allowlist is checked before the dispatcher's fast
paths and inherited by children. The set of calls Gecko needs and the handling
of arguments and handles have not been validated.

For diagnostic `sandbox` and `sandboxfat` probes only, init creates a fresh
registry hive that disables Mozilla's separate Windows launcher. That skips
its mitigations and is not a production workaround. It lets the probe reach
the browser while cross-process launcher setup remains unsupported. Mozilla's
[launcher registry implementation](https://github.com/mozilla-firefox/firefox/blob/main/toolkit/xre/LauncherRegistryInfo.cpp)
describes the force-disabled state.

An experimental FAT-backed QEMU probe of the official Zen 1.23.4b package
initially failed because the launcher requested `CREATE_SUSPENDED`. OSyx now
starts a held initial thread and supports resuming it from the parent. A
subsequent probe reached a denied cross-process memory operation and then
raised `0xc000001d` without the required CPU features. With SSE4.2 and the
diagnostic launcher bypass, Zen reaches content-process creation. It passes an
invalid standard input handle and a connected pipe. Winrun preserves invalid
and null standard handles, uses `/dev/random` for its CSPRNG, and can relay
connected pipes. A subsequent probe started Gecko children and loaded
`xul.dll`, but an unsupported post-start `DuplicateHandle` caused the content
IPC channel to close. A later probe reached a request to duplicate an audio
pipe; this is now supported experimentally. Other redirected standard handles remain unsupported.
The probes do not establish browser or sandbox functionality.

The initial thread is held before it can run, including for restricted
children. Only its direct parent can resume it. A held child whose parent exits
is terminated and reaped. Winrun currently represents the primary-thread
handle using the process object; full Windows thread-handle semantics and
remote-process memory operations remain unimplemented.

OSyx must enforce the boundary in the kernel, independently of the Win32
compatibility process. A command-line flag or environment variable alone is
not an authority to enter or leave the sandbox.

## Boundary

- A trusted browser parent requests a content-process policy at creation.
  The kernel installs it before the child can execute userspace code.
- Restrictions survive `exec` and propagate to every descendant. A child
  cannot relax them or create an unrestricted descendant.
- Deny access by default. Explicitly allow only the files, IPC endpoints,
  inherited objects and system calls needed by content processes. The exact
  policy must come from observing and testing a real Gecko content process.
- Check filesystem access during kernel path resolution, including symlink
  expansion, case-insensitive lookups, mount crossings, creation and rename.
  Checking a caller-supplied string alone is insufficient.
- Account for already-open and IPC-transferred handles. A path restriction
  must not be bypassed by receiving a file object or using an inherited one.
  Define and enforce which objects a trusted broker may grant to a child.
- Apply syscall restrictions before all dispatcher fast paths. Cover process
  control, privileged devices, networking, IPC, memory and handle operations;
  a filtered call must fail closed rather than silently succeed.

## Validation before enabling

Run `scripts/sandbox-test.ps1` to boot the sandbox-specific kernel tests with
an existing `build/esp` loader and a temporary FAT directory. This targeted
test does not replace the full system suite or a Gecko test. Add `-Winrun` to
build a small PE fixture and verify that a restricted Windows child cannot
read a file that its parent can read, and can use an inherited Windows event
and connected pipe, and that the parent can grant an event after startup
without granting a file.
This needs the MSVC Rust target.

Test direct and indirect file access, symlink and rename escapes, `exec` and
child inheritance, pre-opened and transferred objects, and access to other
processes. Exercise concurrent policy installation and process startup. Test
the intended broker exchanges and Gecko startup, page rendering and network
access under the actual policy. Keep the existing launcher behaviour until
these checks pass; a partial filter must not be described as a sandbox.
