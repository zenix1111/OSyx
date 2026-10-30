# Contributing to OSyx

Thank you for helping improve OSyx. Issues, documentation, tests and code are welcome.

## Before you start

- Search existing issues and pull requests for related work.
- For a substantial change, open an issue describing the problem and proposed behavior.
- Keep changes focused and preserve the project license, GPL-3.0-or-later.
- Never include passwords, Wi-Fi keys, signing keys, personal files or private logs in a report.

## Develop and test

The supported image-building host is Windows 11 with Rust, MSYS2 and WSL. See [README](README.md#build) and [testing](docs/testing.md) for dependencies and detailed commands.

```powershell
.\scripts\check-env.ps1
.\scripts\build.ps1 -NoZen
.\scripts\test.ps1
```

For a focused network change, run `cargo test -p osyx-net` and `./scripts/net-test.ps1`. For desktop changes, run `./scripts/desktop-test.ps1`. Include physical hardware and QEMU details when relevant. GitHub Actions runs portable host tests and checks the freestanding targets; it does not replace the full Windows/WSL and QEMU suite.

## Pull requests

1. Fork the repository, create a branch and describe the problem your change solves.
2. Add focused tests for behavior changes where practical; run the relevant checks.
3. Open a pull request against `main`. Explain the change, test results, and any limitations. Add screenshots for visible changes.
4. Respond to review and keep the branch up to date.

For security issues, follow [SECURITY.md](SECURITY.md) instead of filing a public issue.

## Merging without a release

Automatic releases run after CI passes on `main`. To merge without creating a
release, include `/norelease` in the merge commit title or description (including
the squash commit message). This does not disable manually dispatched releases.
The existing `[skip release]` marker also remains supported.
