# Builds the Windows PE32+ test programs of the OSyx Windows runtime
# (compatibility/win32/tests/src) with the MSYS2 clang + lld toolchain and no
# C runtime, into build/wintests. build.ps1 installs them as /opt/wintests on
# the root file system. Rebuilds only what changed; without clang it warns
# and builds nothing (the Windows tests are then skipped).
param([switch]$Force)
. (Join-Path $PSScriptRoot 'common.ps1')
$clang = Find-Tool 'clang' @('C:\msys64\ucrt64\bin\clang.exe')
$dlltool = Find-Tool 'dlltool' @('C:\msys64\ucrt64\bin\dlltool.exe')
$out = Join-Path $BuildDir 'wintests'
if (-not $clang -or -not $dlltool) {
    Write-Warning 'clang or dlltool not found (MSYS2 ucrt64): Windows test programs not built'
    return
}
$src = Join-Path $Root 'compatibility\win32\tests\src'
New-Item -ItemType Directory -Force $out | Out-Null
$common = @('--target=x86_64-w64-windows-gnu', '-fuse-ld=lld', '-nostdlib', '-ffreestanding', '-O2', '-Wall', '-Werror',
            '-Wl,--dynamicbase', '-Wl,--high-entropy-va', '-Wl,--nxcompat', '-Wl,--no-insert-timestamp', '-Wl,--build-id=none')

function Stale([string]$Target, [string[]]$Inputs) {
    if ($Force -or -not (Test-Path $Target)) { return $true }
    $t = (Get-Item $Target).LastWriteTime
    foreach ($i in $Inputs) { if ((Get-Item $i).LastWriteTime -gt $t) { return $true } }
    return $false
}

# Import library for the API set contract windll.dll imports through.
$versionObj = Join-Path $out 'version-resource.o'
if (Stale $versionObj @("$src\version.rc")) {
    $windres = Find-Tool 'windres' @('C:\msys64\ucrt64\bin\windres.exe')
    if (-not $windres) { throw 'windres required for version API regression fixture' }
    Invoke-Checked 'version resource' { & $windres "$src\version.rc" -O coff -o $versionObj }
}
# SEH cases need real __try scope tables: compiled for the MSVC ABI.
$sehObj = Join-Path $out 'seh-cases.o'
if (Stale $sehObj @("$src\seh_cases.c")) {
    Invoke-Checked 'seh cases' { & $clang --target=x86_64-pc-windows-msvc -O2 -Wall -Werror -c "$src\seh_cases.c" -o $sehObj }
}
$apisetLib = Join-Path $out 'libapiset-processthreads.a'
if (Stale $apisetLib @("$src\apiset-processthreads.def")) {
    Invoke-Checked 'apiset import library' { & $dlltool -d "$src\apiset-processthreads.def" -l $apisetLib -m i386:x86-64 }
}
$programs = [ordered]@{
    'filedialogs.exe' = @{ Src = @('filedialogs.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-lcomdlg32', '-lshell32', '-lole32', '-luser32', '-lkernel32') }
    'minimal.exe' = @{ Src = @('minimal.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'version.exe' = @{ Src = @('version.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', $versionObj, '-lversion', '-lkernel32') }
    'synch.exe' = @{ Src = @('synch.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32', '-lsynchronization') }
    'prio.exe' = @{ Src = @('prio.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'security.exe' = @{ Src = @('security.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-ladvapi32', '-lkernel32') }
    'exceptions.exe' = @{ Src = @('exceptions.c'); Args = @('-fasynchronous-unwind-tables', '-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'seh.exe' = @{ Src = @('seh.c'); Args = @('-fasynchronous-unwind-tables', $sehObj, '-Wl,--subsystem,console', '-Wl,-e,start', '-lntdll', '-lkernel32') }
    'runtime.exe' = @{ Src = @('runtime.c'); Args = @('-fasynchronous-unwind-tables', '-Wl,--subsystem,console', '-Wl,-e,start', '-lntdll', '-ladvapi32', '-lkernel32') }
    'mapping.exe' = @{ Src = @('mapping.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'winmm.exe' = @{ Src = @('winmm.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lwinmm', '-lkernel32') }
    'sandbox.exe' = @{ Src = @('sandbox.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-ladvapi32', '-lkernel32') }
    'ole2.exe' = @{ Src = @('ole2.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lole32', '-lshell32', '-luser32', '-lkernel32') }
    'interop.exe' = @{ Src = @('interop.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lole32', '-loleaut32', '-luser32', '-luserenv', '-ldbghelp', '-lcrypt32', '-ladvapi32', '-lkernel32') }
    'msgwait.exe' = @{ Src = @('msgwait.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lshell32', '-lole32', '-luser32', '-lgdi32', '-lkernel32') }
    'dwm.exe' = @{ Src = @('dwm.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-ldwmapi', '-limm32', '-lwtsapi32', '-luser32', '-lkernel32') }
    'keyboard.exe' = @{ Src = @('keyboard.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-luser32', '-lkernel32') }
    'input.exe' = @{ Src = @('input.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-luser32', '-lgdi32', '-lkernel32') }
    'shlpath.exe' = @{ Src = @('shlpath.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lshlwapi', '-lkernel32') }
    'secattr.exe' = @{ Src = @('secattr.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-ladvapi32', '-lkernel32') }
    'childproc.exe' = @{ Src = @('childproc.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'imageshare.exe' = @{ Src = @('imageshare.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'dwrite.exe' = @{ Src = @('dwrite.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-ldwrite', '-lkernel32') }
    'shell.exe' = @{ Src = @('shell.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lshell32', '-lole32', '-lkernel32') }
    'platform.exe' = @{ Src = @('platform.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lshlwapi', '-lruntimeobject', '-lkernel32') }
    # The real UCRT import library: every C runtime function comes through
    # the api-ms-win-crt-* contracts.
    'ucrt.exe'    = @{ Src = @('ucrt.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-lucrt', '-lkernel32') }
    'crt2.exe'    = @{ Src = @('crt2.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-lucrt', '-lkernel32') }
    'crt3.exe'    = @{ Src = @('crt3.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-lucrt', '-lkernel32') }
    'crt4.exe'    = @{ Src = @('crt4.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-lucrt', '-lkernel32') }
    'hello.exe'   = @{ Src = @('hello.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'fileio.exe'  = @{ Src = @('fileio.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'threads.exe' = @{ Src = @('threads.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'windll.dll'  = @{ Src = @('windll.c', 'windll.def'); Args = @('-shared', '-Wl,-e,DllMainCRTStartup', $apisetLib, '-lkernel32') }
    'gdi2.exe'    = @{ Src = @('gdi2.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-luser32', '-lgdi32', '-lkernel32') }
    'gui.exe'     = @{ Src = @('gui.c'); Args = @('-Wl,--subsystem,windows', '-Wl,-e,start', '-luser32', '-lgdi32', '-lkernel32') }
    'winsock.exe' = @{ Src = @('winsock.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lws2_32', '-lkernel32') }
    'wsock32.exe' = @{ Src = @('wsock32.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lwsock32', '-lkernel32') }
    'wsaext.exe'  = @{ Src = @('wsaext.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lws2_32', '-lkernel32') }
    'k32ansi.exe' = @{ Src = @('k32ansi.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'advapi.exe'  = @{ Src = @('advapi.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-ladvapi32', '-lkernel32') }
    'newdlls.exe' = @{ Src = @('newdlls.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-lrpcrt4', '-lcfgmgr32', '-lpropsys', '-loleaut32', '-lole32', '-lkernel32') }
    'pipes.exe'   = @{ Src = @('pipes.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'k32xul.exe'  = @{ Src = @('k32xul.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'sysadmin.exe' = @{ Src = @('sysadmin.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-liphlpapi', '-lsetupapi', '-lkernel32') }
}
foreach ($name in $programs.Keys) {
    $p = $programs[$name]
    $inputs = @($p.Src | ForEach-Object { Join-Path $src $_ }) + @("$src\common.h", (Join-Path $PSScriptRoot 'build-wintests.ps1'))
    if ($name -eq 'version.exe') { $inputs += $versionObj }
    if ($name -eq 'seh.exe') { $inputs += $sehObj }
    if ($name -in 'interop.exe', 'newdlls.exe') { $inputs += "$src\pkcs7_sample.h" }
    if ($name -eq 'crt2.exe') { $inputs += "$src\crtmath_cases.h" }
    $target = Join-Path $out $name
    if (Stale $target $inputs) {
        Invoke-Checked $name { & $clang @common @($p.Src | ForEach-Object { Join-Path $src $_ }) @($p.Args) -o $target }
    }
}
Remove-Item "$out\*.lib" -ErrorAction SilentlyContinue
Get-ChildItem $out -File -Include *.exe, *.dll -Recurse | ForEach-Object { Write-Host ("    {0,-14} {1,7} bytes" -f $_.Name, $_.Length) }
