# Win Parity Check

`scripts/winparity.py` (wrapper: `scripts/win-parity.ps1`) measures how much of the
Windows API the Win32 layer in `compatibility/win32` implements, for x64 and for
32-bit programs through WoW64, and how much of that is backed by executed tests.

```powershell
.\scripts\win-parity.ps1                   # scan; writes build\winparity\report.{json,html}
.\scripts\win-test.ps1 -Parity             # run the Windows tests, then scan their log
.\scripts\win-parity.ps1 -Test             # unit tests of the tool
.\scripts\win-parity.ps1 -FailOnRegression # exit 2 if a scan is worse than the previous one
.\scripts\win-parity.ps1 -Runtime          # boot OSyx and cross-check the source scan against
                                           # the compiled export tables (winrun --exports)
.\scripts\win-parity.ps1 -ExtractSteam     # add the NSIS plug-ins of SteamSetup.exe (needs 7-Zip)
.\scripts\win-parity.ps1 -Reference        # rebuild the reference dataset (see below)
```

## What is counted

* **Reference dataset** - `compatibility/win32/parity/reference`: the export tables of 44
  real Windows DLLs, read from the PE files of one Windows installation (x64 from
  `System32`, x86 from `SysWOW64`). `MANIFEST.json` records the Windows build; every DLL
  file carries its file version and SHA-256. Percentages are only meaningful against that
  build. Ordinal-only exports are recorded but not scored.
* **OSyx exports** - found by reading the sources: `builtins()` in `loader.rs` and the
  `exports()` functions it reaches. `-Runtime` compares that with the compiled tables.
* **Classes** (static heuristic over each exported function body, delegations followed):

  | class | meaning |
  | --- | --- |
  | `implemented` | real logic |
  | `partial` | real logic, but the body names unsupported cases (`ERROR_NOT_SUPPORTED`, "not implemented", TODO ...) |
  | `stub_success` | constant success, arguments ignored (fake success) |
  | `stub_empty` | constant `0`/`FALSE`/`()` without effect |
  | `placeholder` | `todo!()` / `unimplemented!()` |
  | `unsupported` | only returns an explicit not-supported error (honest, not counted) |
  | `unknown` | no function body found (macro or assembly); reported separately, never counted |
  | `missing` | not exported at all |

  A constant that is the correct Windows answer can be listed with its reason in
  `compatibility/win32/parity/allowlist.json`; the report names every allowlisted function.
* **Coverage** = (`implemented` + `partial`) / reference exports. **Strict** = `implemented` only.
  Stubs, unsupported and unknown never count.
* **x86 / WoW64** - an export counts only if it also has a bridge signature (`wow64/sigs.rs`)
  or an override in `wow64.rs`, against the `SysWOW64` export tables. Structure-layout
  adapters are not verified by this tool.
* **Behavioral parity** - only from executed tests, from the serial log of `win-test.ps1`
  (`build/test/win.serial.log`): an API counts when an `ok` check line cites its name
  (CamelCase names), or when a C test program that ran and met its expected exit code
  (`userspace/apps/src/win_checks.rs`) calls it. It is a floor for "tested", not proof of
  identical behaviour. Without a log it is reported as "not measured".
* **Profiles** - `compatibility/win32/parity/profiles.json` lists binaries (Steam setup and
  its plug-ins, Zen/Gecko). Their static and delay-load imports are classified, and the
  missing or stubbed ones are ranked by how many binaries need them. DLLs that are not
  built in are listed as external, not scored.
* **History** - every scan is stored in `build/winparity/history`; the next scan reports
  per-DLL changes, improvements and regressions (an API that fell to a weaker class or lost
  its test evidence, a test program that began to fail).

Percentages are measurements of the sources and logs at hand; they say nothing about
APIs that the tool classifies `unknown`, and nothing is estimated.

## Website

The Win Parity section of the website (`site/`) shows numbers from a scan, copied unchanged into `site/winparity.json`:

```
python scripts/winparity.py scan
python scripts/site-winparity.py
```

Commit the refreshed JSON together with the change that moved the numbers.
