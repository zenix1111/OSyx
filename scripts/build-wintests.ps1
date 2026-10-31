# Builds the Windows PE32+ and 32-bit PE32 test programs of the OSyx Windows
# runtime (compatibility/win32/tests/src) with the MSYS2 clang + lld toolchain
# and no C runtime, into build/wintests. build.ps1 installs them as
# /opt/wintests on the root file system. Rebuilds only what changed; without
# clang it warns and builds nothing (the Windows tests are then skipped).
param([switch]$Force)
. (Join-Path $PSScriptRoot 'common.ps1')
$clang = Find-Tool 'clang' @('C:\msys64\ucrt64\bin\clang.exe')
$dlltool = Find-Tool 'dlltool' @('C:\msys64\ucrt64\bin\dlltool.exe')
$lldLink = Find-Tool 'lld-link' @('C:\msys64\ucrt64\bin\lld-link.exe')
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
    'version.exe' = @{ Src = @('version.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', $versionObj, '-lversion', '-luser32', '-lkernel32') }
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
    'gui.exe'     = @{ Src = @('gui.c'); Args = @('-Wl,--subsystem,windows', '-Wl,-e,start', '-limm32', '-luser32', '-lgdi32', '-lkernel32') }
    'winsock.exe' = @{ Src = @('winsock.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lws2_32', '-lkernel32') }
    'wsock32.exe' = @{ Src = @('wsock32.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lwsock32', '-lkernel32') }
    'wsaext.exe'  = @{ Src = @('wsaext.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lws2_32', '-lkernel32') }
    'k32ansi.exe' = @{ Src = @('k32ansi.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'advapi.exe'  = @{ Src = @('advapi.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-ladvapi32', '-lkernel32') }
    'newdlls.exe' = @{ Src = @('newdlls.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-lrpcrt4', '-lcfgmgr32', '-lpropsys', '-loleaut32', '-lole32', '-lkernel32') }
    'pipes.exe'   = @{ Src = @('pipes.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'k32xul.exe'  = @{ Src = @('k32xul.c'); Args = @('-mno-stack-arg-probe', '-Wl,--subsystem,console', '-Wl,-e,start', '-lkernel32') }
    'newlibs.exe' = @{ Src = @('newlibs.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lbcrypt', '-lsecur32', '-ladvapi32', '-lwinspool', '-lole32', '-luuid', '-lwinmm', '-lshell32', '-luser32', '-lkernel32') }
    'stubfix.exe' = @{ Src = @('stubfix.c'); Args = @('-Wl,--subsystem,console', '-Wl,-e,start', '-lwininet', '-limm32', '-lshell32', '-lgdi32', '-luser32', '-lkernel32') }
    'thrdll.dll'  = @{ Src = @('thrdll.c'); Args = @('-shared', '-Wl,-e,DllMainCRTStartup', '-lkernel32') }
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
# 32-bit (PE32) fixtures. There is no i686 sysroot on this machine, so the
# programs import kernel32 through one import library built from
# kernel32_x86.def, and ld.lld's stdcall fixup maps the decorated i686
# references onto the plain import names. Compile and link run through clang
# --target=i686-pc-windows-gnu with lld; lld-link is required for /lib.
$pe32Programs = [ordered]@{
    'hello32.exe' = @{ Src = @('hello32.c'); Libs = @() }
    'api32.exe' = @{ Src = @('api32.c'); Libs = @('advapi32', 'user32', 'shell32', 'gdi32', 'comctl32', 'ole32', 'bcrypt', 'secur32') }
    'thread32.exe' = @{ Src = @('thread32.c'); Libs = @() }
    'gui32.exe' = @{ Src = @('gui32.c'); Libs = @('user32', 'gdi32') }
}
$pe32Common = @('--target=i686-pc-windows-gnu', '-nostdlib', '-ffreestanding', '-O2', '-Wall', '-Werror')
if ($pe32Programs.Count -gt 0) {
    if (-not $lldLink) {
        throw 'lld-link not found (C:\msys64\ucrt64\bin\lld-link.exe): the i686 toolchain is needed to build hello32.exe'
    }
    # One import library per <dll>_x86.def.
    foreach ($dll in 'kernel32', 'advapi32', 'user32', 'shell32', 'gdi32', 'comctl32', 'ole32', 'bcrypt', 'secur32') {
        $lib = Join-Path $out "${dll}_x86.lib"
        if (Stale $lib @("$src\${dll}_x86.def", (Join-Path $PSScriptRoot 'build-wintests.ps1'))) {
            Invoke-Checked "$dll x86 import library" {
                & $lldLink /lib "/def:$src\${dll}_x86.def" /machine:x86 /out:$lib
            }
        }
    }
    $kernel32x86 = Join-Path $out 'kernel32_x86.lib'
    $gui32Resource = Join-Path $out 'gui32-resource.o'
    if (Stale $gui32Resource @("$src\gui32.rc", "$src\gui32.bmp", (Join-Path $PSScriptRoot 'build-wintests.ps1'))) {
        $resourceCompiler = Find-Tool 'windres' @('C:\msys64\ucrt64\bin\windres.exe')
        if (-not $resourceCompiler) { throw 'windres required for PE32 dialog fixture' }
        Invoke-Checked 'gui32 resource' { & $resourceCompiler --target=pe-i386 -I "$src" "$src\gui32.rc" -O coff -o $gui32Resource }
    }
    foreach ($name in $pe32Programs.Keys) {
        $p = $pe32Programs[$name]
        $objects = @()
        foreach ($s in $p.Src) {
            $srcFile = Join-Path $src $s
            $obj = Join-Path $out (($s -replace '\.c$', '') + '.32.o')
            $objects += $obj
            if (Stale $obj @($srcFile, (Join-Path $PSScriptRoot 'build-wintests.ps1'))) {
                Invoke-Checked "$s (i686)" { & $clang @pe32Common -c $srcFile -o $obj }
            }
        }
        if ($name -eq 'gui32.exe') { $objects += $gui32Resource }
        $target = Join-Path $out $name
        $libs = @($kernel32x86) + @($p.Libs | Where-Object { $_ } | ForEach-Object { Join-Path $out "${_}_x86.lib" })
        $inputs = $objects + $libs + @("$src\kernel32_x86.def", (Join-Path $PSScriptRoot 'build-wintests.ps1'))
        if (Stale $target $inputs) {
            Invoke-Checked $name {
                & $clang '-fuse-ld=lld' @pe32Common '-Wl,--subsystem,console' '-Wl,-e,start' `
                    '-Wl,--no-insert-timestamp' '-Wl,--build-id=none' @objects @libs -o $target
            }
        }
    }
    $plugin32 = Join-Path $out 'plugin32.dll'
    if (Stale $plugin32 @("$src\plugin32.c", $kernel32x86, (Join-Path $PSScriptRoot 'build-wintests.ps1'))) {
        Invoke-Checked 'plugin32.dll' {
            & $clang '-fuse-ld=lld' @pe32Common '-shared' '-Wl,-e,DllMain' '-Wl,--dynamicbase' `
                '-Wl,--no-insert-timestamp' '-Wl,--build-id=none' "$src\plugin32.c" $kernel32x86 -o $plugin32
        }
    }
}
Get-ChildItem $out -File -Include *.exe, *.dll -Recurse | ForEach-Object { Write-Host ("    {0,-14} {1,7} bytes" -f $_.Name, $_.Length) }
