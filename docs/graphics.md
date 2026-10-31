# Graphics, input and the desktop

PRISM — *many surfaces, one vision* — is the OSyx compositor. This document
covers the whole path from a USB device to a pixel on screen.

```
 USB keyboard / mouse
        │  xHCI (kernel/src/drivers/xhci)   interrupt-IN transfers, MSI-X
        ▼
 HID boot keyboard / report-protocol mouse drivers
        ▼
 input core (kernel/src/input.rs)  ── /dev/input/event<N> (per device, root)
        │                          ── /dev/input/seat0   (all devices, exclusive, root)
        ▼
 PRISM  /system/bin/prism  (ring 3, root)   ◄── display_acquire: framebuffer mapping
        │  kernel channels to the "prism" service + shared memory buffers
        ▼
 desktop shell /system/bin/desktop (shell role)   AXIS Terminal   Files   System Information
                         └── all built on prism-client + osyx-ui ──┘
```

## Kernel side

**xHCI** (`kernel/src/drivers/xhci`, structures and parsers in the
host-tested `drivers/usb` crate). Controllers are found by PCI class
0C/03/30; BAR0 is validated and mapped, bus mastering enabled, the USB legacy
handoff performed, the controller reset. Capability, operational, runtime and
doorbell registers and the extended capabilities (supported protocols →
USB 2 / USB 3 port ranges) are read from the hardware. DMA memory is
page-sized, physically contiguous kernel memory (64-bit addresses only when
the controller reports AC64); rings publish a TRB's cycle-bit dword last,
after a release fence, and ring the doorbell after a full fence. DCBAA,
scratchpads, command ring, event ring with its ERST, input/output contexts
(32- or 64-byte, as reported) and transfer rings with link TRBs are built per
the specification. Event interrupts arrive through MSI-X (or MSI) on a local
APIC vector; the handler only acknowledges and wakes the controller thread.
Every command and transfer has a timeout. Ports: connect/disconnect
detection, reset, slot enable, Address Device, GET_DESCRIPTOR (device,
configuration tree, strings), SET_CONFIGURATION, Configure Endpoint for
interrupt-IN endpoints, slot release on disconnect.

**HID**: boot-protocol keyboards (modifiers, six-key reports; rollover
error reports are detected and rejected; Caps/Num/Scroll Lock
LEDs follow the seat state) and mice in report protocol through a bounded
report-descriptor parser (buttons, X/Y, wheel), falling back to the boot
protocol (3 buttons, X/Y) when the descriptor is not understood. Only boot-protocol keyboards are supported; report-descriptor
keyboards are not yet.

**Input core**: one event format (`shared/input`, 32 bytes: time, device,
kind, code, values, modifier/lock state, sequence). Modifier and lock state
and key auto-repeat (500 ms / 33 ms) are per seat. Queues are bounded (256
per device, 1024 for the seat); overflow drops the oldest events and the
reader gets a `DROPPED` record. Removing a device releases its held keys and
buttons and posts `DEVICE_REMOVED`. Raw events never contain text: the
keyboard layout (US, Polish) is applied by PRISM.

**Display**: `display_info` (any process), `display_acquire` (root only; the
framebuffer is mapped write-combining into the caller, one owner at a time),
`display_release`. When the owner exits the kernel status screen returns.

**IPC** (ABI v7): pipes, named-service channels (`channel_listen` is root
only; messages up to 64 KiB with up to 4 passed handles; per-direction
bounds of 256 messages / 1 MiB, then `WouldBlock`), shared memory objects,
`wait_handles` over any mix of them and device files.

## PRISM

`graphics/prism-core` holds every decision and is unit tested on the host:
clients and their resources, protocol validation, window stacking by role
(desktop < normal < panel < popup < notification), focus and MRU order,
server-side decorations (title, minimize/maximize/close, rounded frame,
table-driven shadow), move/resize grabs, pointer capture, keyboard routing
(Alt+Tab, Alt+F4, Super to the shell), damage tracking, fade animations and
per-client limits. Client pixels are copied at commit, so a client can
neither change the screen afterwards nor make PRISM read outside its buffer.

`userspace/desktop/src/bin/prism.rs` is the platform: it waits on the
listener, the seat and every client channel at once, renders damaged areas
into a back buffer at most every 16 ms and copies them to the framebuffer
(converting to RGBX when needed). Clients that break the protocol get an
`ERROR` and are dropped; clients that stop reading their events (512
undelivered) are dropped; a vanished client's windows fade out. PRISM starts
the desktop shell and restarts it (up to 5 times) if it exits.

### Protocol (version 1, `graphics/prism-proto`)

16-byte header (opcode, length, serial), little-endian payload, strings
with a u16 length, exact length checks. Requests: HELLO, CREATE_SURFACE,
DESTROY_SURFACE, CREATE_WINDOW, DESTROY_WINDOW, ATTACH_BUFFER (shared memory
handle in the message's handle slot 0), DESTROY_BUFFER, DAMAGE,
COMMIT_SURFACE, SET_TITLE, SET_GEOMETRY, WINDOW_ACTION, NOTIFY. Events:
HELLO, CONFIGURE, FOCUS_CHANGED, KEY_EVENT (usage, state, modifiers and the
translated character), POINTER_EVENT, CLOSE_REQUEST, BUFFER_RELEASE,
FRAME_DONE, WINDOW_LIST and NOTIFICATION (shell only), ERROR.

The shell role (desktop/panel/notification windows, global window actions,
window list) is granted only to the process PRISM started as the shell.

## Client side

* `graphics/prism-client`: `Connection` (connect with retry, HELLO,
  bounded send, event queue, waiting together with other handles),
  `Window` (shared-memory buffer grown with headroom, attach/damage/commit,
  CONFIGURE and BUFFER_RELEASE handling), and an adapter to toolkit events
  with double-click detection.
* `graphics/ui` (`osyx-ui`, host tested): theme (midnight blue/charcoal,
  blue accent), Cantarell and Source Code Pro fonts with Polish letters, a
  clipping painter (anti-aliased rounded rectangles, discs, rings, thick
  segments), line icons, layout helpers, focus chain, and the widgets Label,
  Button, Checkbox, TextField, Panel, Menu, Dialog, ListView and
  ScrollView/Scroll. POSIX TZ parsing for the clock.

## Desktop and applications (`userspace/desktop`)

| Program | Path | Runs as |
|---|---|---|
| PRISM | `/system/bin/prism` | root (owns display and seat) |
| desktop shell | `/system/bin/desktop` | root (power control) |
| AXIS Terminal | `/system/bin/terminal` | user 1000 |
| Files | `/system/bin/files` | user 1000 |
| System Information | `/system/bin/sysinfo` | user 1000 |
| AXIS shell | `/bin/axis` | user 1000 (child of the terminal) |

The shell draws the wallpaper (`/system/share/wallpapers/default.osxi`,
converted at build time from `graphics/assets/wallpaper/osyx-default.png` by
`scripts/png2osxi.py`; three drawn alternatives via the context menu), the
task bar (launcher, one button per window with the active one marked,
minimize/activate on click, clock from the RTC in the zone of `/etc/TZ`,
power button), the launcher (entries from `/system/share/applications/*.app`
on the root file system, search, Enter), the desktop context menu,
notification bubbles (from any client, the clock, crashed applications) and
the restart / shut down confirmation (kernel `power`).

### Files

Several files at once: Ctrl+click marks a row, Shift+click or Shift+arrows a
range, a rubber band over empty space the rows it touches, Ctrl+A all. Copy
(Ctrl+C), Cut (Ctrl+X), Paste (Ctrl+V; a name that exists becomes
`name (copy).ext`), Delete (Trash), dragging, Pack (Ctrl+P: one uncompressed
`.tar`) and Extract here (Ctrl+E) work on the whole selection. Extraction
reads tar, tar.gz/tgz, zip (stored and deflated, CRC checked), 7z and single
.gz files into a folder named after the archive; paths that would leave it
are refused and a failed extraction leaves no folder behind.

A double click opens a file with the program the user chose for its
extension, else with an installed application that lists it, else by Files
itself: text and source in the viewer, images and web pages in the default
browser, archives are extracted. Audio, video and PDF need an application:
an application says so with `Handles=mp4,mkv,video` in its `.app` file
(extensions or the kinds `text source html image audio video pdf archive`).
The right-click menu has "Open with" for every program that can open the
file (the hex viewer always can) and "Always open .ext with ...", which is
saved in `~/.config/osyx/openwith.conf` (`mp4=/opt/player`). The logic is in
`userspace/filekit` (host-tested); the file operations in
`userspace/desktop/src/fileops.rs`.

AXIS is a first, small version of the shell: built-in commands on
`os_std::fs` (`ls cat cd mkdir rm mv cp stat ps kill mounts free uptime …`),
Python-style `name = expr` and `print(...)`, `$name` expansion, and every
other word runs a program from `/bin`, `/usr/bin`, `/system/bin` with the
terminal's pipes as its standard streams. `<`, `>` and `>>` redirect the
standard input and output of a command — built-ins included, using
`os_std::io::redirect_stdin`/`redirect_stdout` — and `|` connects programs
and at most one built-in into a pipeline. The built-in stage runs in the
shell process after the programs around it have started, so waiting for
output cannot deadlock. `if cond { ... } else { ... }` and
`for name in words { ... }` group lines; conditions are expressions with
`==`, `!=`, `<`, `>`, `<=` and `>=`. Still open: job control.

## Boot

`init.args=desktop` makes `/bin/init` run `/system/bin/prism` (restarting it
up to three times); without it init runs its checks as before. If PRISM
cannot start, init exits and the kernel status screen stays.

## Testing

* Host: `drivers/usb` (registers, TRBs, rings, contexts, descriptors, HID
  reports, malformed input), `graphics/prism-proto`, `graphics/prism-core`
  (blending, clipping, damage, stacking, focus, resizing, input routing,
  protocol validation, disconnect clean-up, limits), `graphics/ui` (layout,
  focus, every widget's behaviour, clipping, icons, dates and time zones).
* QEMU, `scripts/desktop-test.ps1` (stage 6 of `scripts/test.ps1`): boots
  into the desktop with `qemu-xhci`, `usb-kbd`, `usb-mouse` and no PS/2
  controller, and drives it only through QMP input injection: pointer
  motion and clicks, the context menu, the launcher with Super and typed
  search, commands typed into the terminal (a program spawned by AXIS),
  moving, resizing, maximizing, focusing, minimizing from the task bar and
  closing windows, the file manager on ext4 (navigate, open, create a
  folder), a third application, killing a client while PRISM keeps running,
  unplugging the USB keyboard, and PRISM's frame statistics. Screenshots are
  kept in `build/test/desktop-*.png`.

## Task Manager and Settings

`/system/bin/taskmgr` has Processes, Details and Performance pages. Its
60-sample CPU/memory/disk/network graphs use ABI v10 scheduler, frame,
physical block-I/O and interface counters. CPU is tick-sampled on the
single scheduled CPU; per-process totals retain samples of exited threads.
Rates divide by measured elapsed time. The sortable process list preserves
selection by PID; End task uses the existing kernel permission checks.

`/system/bin/settings` shows General, Appearance, Displays, Keyboard,
Date & Time, Network, Storage and About. Host name, accent, background,
US/Polish keyboard layout and POSIX time zone write system configuration;
DHCP/static IPv4 applies through the native net_config syscall. Keyboard
layout needs a session restart. The desktop reloads background/time zone;
new native application windows read the saved accent. Display information
is read-only. Settings retains root credentials for system configuration.

The application launcher also accepts `.exe` paths, invoking `/bin/winrun`.
The four Windows GUI utilities are installed in `/opt/apps` and have their
own launcher entries. They draw through the same PRISM compositor.

## Known limitations

* Software composition uses one compositor thread; applications can run on
  different CPUs. Cursor updates bypass the application frame limit and
  copy only the old/new pointer rectangles. Full-window commits from the
  toolkit applications (damage is tracked by PRISM, clients report it but
  the toolkit apps redraw whole windows).
* Popups and notifications are square (no per-pixel alpha in the toolkit
  yet; the protocol supports ARGB buffers).
* HID: boot-protocol keyboards; xHCI hubs are supported;
  no isochronous or bulk endpoints; no USB 3 streams.
* No IOMMU support (none is assumed); DMA buffers are kernel pages.
* AXIS is minimal (see above); the terminal is a line-mode terminal.
