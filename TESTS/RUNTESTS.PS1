# RUNTESTS.PS1 - build and run the host-side tests (no BBS needed).
#
# EDTEST checks the settings editor (/TIP).  Its code is copied out of
# SRC\SNTIPCTL.C at test time, so the test always runs the real source:
#   - the CIDR helpers (parse_cidr, cidr_to_str, parse_cidr6, cidr6_to_str)
#   - the settings editor, from its section banner up to ed_applyvalue
# Exit code 0 = all passed.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = [IO.File]::ReadAllText((Join-Path $here '..\SRC\SNTIPCTL.C'), [Text.Encoding]::GetEncoding(28591))
$src  = $src -replace "`r`n", "`n"

function Get-Function([string]$name) {
    $m = [regex]::Match($src, "(?ms)^static [A-Z]+\s*\n$name\(.*?^\}\n")
    if (-not $m.Success) { throw "function $name not found in SNTIPCTL.C" }
    $m.Value
}

$a = $src.IndexOf("/*   Settings editor (/TIP")
$b = $src.IndexOf("/* Set, save and report a new value")
if ($a -lt 0 -or $b -lt $a) { throw "editor section markers not found in SNTIPCTL.C" }
$a = $src.LastIndexOf("/* ====", $a)

$inc = (Get-Function 'parse_cidr') + (Get-Function 'cidr_to_str') +
       (Get-Function 'parse_cidr6') + (Get-Function 'cidr6_to_str') +
       $src.Substring($a, $b - $a)

$out = Join-Path $here '..\BUILD\TESTS'
New-Item -ItemType Directory -Force $out | Out-Null
[IO.File]::WriteAllText((Join-Path $here 'EDCODE.INC'), $inc, [Text.Encoding]::GetEncoding(28591))

$vs  = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
$bat = Join-Path $vs 'VC\Auxiliary\Build\vcvars32.bat'
$exe = Join-Path $out 'EDTEST.EXE'
$obj = Join-Path $out 'EDTEST.OBJ'
cmd /c "`"$bat`" >nul 2>nul && cl /nologo /W3 /J /TC /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_DEPRECATE /D_WINSOCK_DEPRECATED_NO_WARNINGS /Fo`"$obj`" /Fe`"$exe`" `"$here\EDTEST.C`" /link ws2_32.lib"
if ($LASTEXITCODE -ne 0) { Remove-Item (Join-Path $here 'EDCODE.INC'); throw "EDTEST did not compile" }
Remove-Item (Join-Path $here 'EDCODE.INC')
& $exe
exit $LASTEXITCODE
