# Project status

**OSyx is under active development and is not abandoned.**

The repository is the project's home: `main` receives changes regularly, the
automated CI runs portable host tests and freestanding target checks. QEMU
integration and Windows compatibility suites are also available for local
testing, and releases are built and signed from tagged source. Work also happens in bursts on feature branches with
open pull requests — a quiet week does not mean the project is dead.

## What is being worked on now

- **32-bit Windows programs (PE32 / WoW64)** — running 32-bit installers and
  applications such as `SteamSetup.exe` in IA-32e compatibility mode. The
  plan and current progress are in [docs/wow64.md](docs/wow64.md).
- **Windows compatibility layer** — more of kernel32, user32/gdi32,
  comdlg32, advapi32, shell32, Winsock, COM and the NT runtime in `winrun`.
- **Kernel and drivers** — SMP scheduling, memory management, the ext4
  driver, networking and hardware support on the ThinkPad T495 test machine.

## How to follow the work

- Commits on `main` and open pull requests are the ground truth.
- [Releases](https://github.com/OSyxSoftware/OSyx/releases) contain signed
  live images and updates; see the "Updates" section of the
  [README](README.md).
- Issues are the place for bug reports and feature requests.

## How to help

Build instructions are in the [README](README.md#build); development and
pull request rules are in [CONTRIBUTING.md](CONTRIBUTING.md). Testing on real
hardware, bug reports with serial logs, and patches for the Windows
compatibility layer are all welcome.

If you prefer to support the work financially, there are
[GitHub Sponsors](https://github.com/sponsors/v3nn7) and
[Ko-fi](https://ko-fi.com/v3nn7).
