# Fails if a tracked text file contains characters that can hide or reorder what a reviewer
# sees: bidirectional controls, zero-width characters, Unicode line separators, or control
# characters other than tab, CR and LF. Tests that need such characters build them from code
# points instead of typing them.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

$binary = '\.(ico|png|jpg|gif|pdf|zip|exe|dll|pdb|bin)$'
$files = @(git -C $root ls-files --cached --others --exclude-standard) |
    Where-Object { $_ -and $_ -notmatch $binary }

if ($files.Count -eq 0) {
    Write-Host "::error::No files listed by git under $root; nothing was checked."
    exit 1
}

function Test-Forbidden([int] $code) {
    if ($code -lt 0x20) { return $code -notin 0x09, 0x0A, 0x0D }   # control characters
    if ($code -eq 0x7F) { return $true }                           # delete
    if ($code -ge 0x80 -and $code -le 0x9F) { return $true }       # C1 controls
    if ($code -ge 0x200B -and $code -le 0x200F) { return $true }   # zero-width, direction marks
    if ($code -ge 0x202A -and $code -le 0x202E) { return $true }   # bidirectional embedding/override
    if ($code -ge 0x2066 -and $code -le 0x2069) { return $true }   # bidirectional isolates
    if ($code -in 0x2028, 0x2029, 0x2060, 0xFEFF) { return $true } # separators, joiner, stray BOM
    return $false
}

$problems = @()
foreach ($file in $files) {
    $path = Join-Path $root $file
    if (-not (Test-Path $path -PathType Leaf)) { continue }

    $text = [System.IO.File]::ReadAllText($path)
    if ($text.Length -gt 0 -and [int] $text[0] -eq 0xFEFF) { $text = $text.Substring(1) }  # leading BOM is fine

    $line = 1
    foreach ($char in $text.ToCharArray()) {
        $code = [int] $char
        if ($code -eq 0x0A) { $line++; continue }
        if (Test-Forbidden $code) {
            $problems += ('{0}:{1}: hidden or control character U+{2:X4}' -f $file, $line, $code)
        }
    }
}

if ($problems) {
    $problems | Select-Object -First 50 | ForEach-Object { Write-Host "::error::$_" }
    exit 1
}

Write-Host "Source text: $($files.Count) files, no hidden or control characters."
exit 0
