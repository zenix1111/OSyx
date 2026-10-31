# Native AMD DCN modesetting

Status: EDID parsing and mode selection are implemented; AMD hardware
identification only. On AMD hardware the kernel still draws through the
firmware GOP framebuffer, and no DCN register is programmed.

The target is the display core of the ThinkPad T495 (Ryzen 7 PRO 3700U,
Picasso, PCI `1002:15d8`, DCN 1.0). QEMU cannot emulate AMD DCN, so every
step that programs the device needs hardware validation.

## Implemented

- `drivers/display` (host-tested `osyx-display`): EDID 1.3/1.4 base blocks
  and CEA-861 extension blocks, checksums, detailed timing descriptors,
  established and standard timings, CEA video descriptors, mode
  de-duplication and preferred-mode selection.
- VirtIO-GPU (`kernel/src/display.rs`): the preferred EDID mode starts the
  scanout; the scanout's own size is retried if the device refuses it, and
  `display.mode=WxH` overrides both.
- `kernel/src/drivers/amdgpu.rs`: finds AMD display functions, maps known
  device IDs to a DCN generation, reads the expansion ROM and locates the
  ATOM header. It logs what it found; it does not change the display.

## What a DCN 1.0 mode set needs

1. **Register bases.** DCN registers live in BAR0 behind a segment/bridge
   offset. The offsets come from the VBIOS IP discovery table; when the
   table is absent, per-ASIC constants are used. The ATOM header found at
   boot is the entry point to that table.
2. **GPU bring-up.** Before display programming the driver needs stable
   frame-buffer (VRAM) and GTT access, at least the display-related clock and
   power state, and the display microcontroller firmware. Firmware loading
   is not implemented anywhere in OSyx yet.
3. **DCN blocks in order.** DCCG (display clock generator, DP DTO),
   HUBP/HUBB (surface fetch and address), DPP (format, scaler), MPC
   (blending, output), OPTC (timing generator), and the link encoder.
   The timing generator takes the values already produced by
   `osyx_display::Timing` (active, blank, front porch, sync width, totals).
4. **The link.** On a laptop panel this is eDP: transmitter setup, link-rate
   and lane-count selection, link training over AUX, and backlight control.
   External outputs add HPD and DP/HDMI encoder selection.
5. **Display data.** EDID over DDC (I2C), not through the GOP. The T495
   panel path needs the AMD I2C/DDC controller; the host-tested I2C crate
   covers DesignWare controllers, which are not the AMD GPU controller.
6. **Framebuffer and scanout.** A VRAM or GTT allocation with the pitch and
   format DCN expects (linear, tiled, or DCC), the surface address, and the
   watermarks for the selected mode.

## Validation plan

- Host tests: EDID and timing parsing (done), DCN clock divider and watermark
  calculations once they exist.
- QEMU: no DCN device; only the existing VirtIO-GPU path can be exercised
  there (`scripts/desktop-test.ps1` with `-Gpu`).
- T495: boot with `log.screen`, check that the probe reports `DCN 1.0` and an
  ATOM header, then add one hardware-verified step at a time (register
  readback, framebuffer base, timing generator, panel link). Keep the GOP
  path as the fallback until the whole path has been tested, including
  hotplug and resume.

## Deliberately not done

The probe does not interpret the IP discovery table or program anything.
Claiming a mode set from register writes that were never run on hardware
would not be verifiable.
