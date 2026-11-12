# Prints the path of the Inno Setup compiler (ISCC.exe), version 7 or 6. Nothing is downloaded
# or installed: GitHub's Windows images ship Inno Setup 6, and a developer installs it once
# (https://jrsoftware.org/isdl.php).
$ErrorActionPreference = 'Stop'

$candidates = @(
    "$env:ProgramFiles\Inno Setup 7\ISCC.exe"
    "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe"
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
)
$found = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $found) {
    throw "Inno Setup 6.3 or later is not installed (looked for ISCC.exe under Program Files)."
}
$found
