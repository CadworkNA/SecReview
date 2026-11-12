# Checks the folder that ships (artifacts\stage) before anything is built on top of it:
#   1. its file list equals scripts\stage-files.txt, so a new or missing file is a reviewed change;
#   2. every binary that is not ours carries a valid Microsoft Authenticode signature.
#
#   scripts\check-stage.ps1 -Stage artifacts\stage            # check
#   scripts\check-stage.ps1 -Stage artifacts\stage -Update    # rewrite stage-files.txt
param(
    [Parameter(Mandatory)] [string] $Stage,
    [switch] $Update
)
$ErrorActionPreference = 'Stop'

$stagePath = (Resolve-Path $Stage).Path.TrimEnd('\')
$listFile = Join-Path $PSScriptRoot 'stage-files.txt'
$ours = 'SecReview.exe', 'SecReviewCli.exe'

$actual = @(Get-ChildItem $stagePath -Recurse -File |
    ForEach-Object { $_.FullName.Substring($stagePath.Length + 1).Replace('\', '/') } |
    Sort-Object { $_.ToLowerInvariant() })

if ($actual.Count -eq 0) {
    Write-Host "::error::$Stage is empty."
    exit 1
}

if ($Update) {
    $header = @(
        '# Every file that ships, relative to the install folder. scripts\check-stage.ps1 fails the'
        '# build when the staged output differs. Regenerate with: scripts\check-stage.ps1 -Stage'
        '# artifacts\stage -Update, and review the difference before committing.'
    )
    [System.IO.File]::WriteAllLines($listFile, [string[]] ($header + $actual))
    Write-Host "stage-files.txt updated: $($actual.Count) files."
    exit 0
}

$problems = @()

if (-not (Test-Path $listFile)) {
    Write-Host "::error::scripts\stage-files.txt is missing; create it with -Update."
    exit 1
}

$expected = @(Get-Content $listFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
$difference = Compare-Object $expected $actual -CaseSensitive:$false
foreach ($entry in $difference) {
    $problems += if ($entry.SideIndicator -eq '=>') {
        "Unexpected file in the staged output: $($entry.InputObject)"
    } else {
        "Missing from the staged output: $($entry.InputObject)"
    }
}

$binaries = Get-ChildItem $stagePath -Recurse -File -Include *.exe, *.dll, *.mui |
    Where-Object { $_.Name -notin $ours }
foreach ($binary in $binaries) {
    $signature = Get-AuthenticodeSignature -LiteralPath $binary.FullName
    $relative = $binary.FullName.Substring($stagePath.Length + 1)
    if ($signature.Status -ne 'Valid') {
        $problems += "Not validly signed ($($signature.Status)): $relative"
    } elseif ($signature.SignerCertificate.Subject -notmatch '(^|, )O=Microsoft Corporation(,|$)') {
        $problems += "Signed by someone other than Microsoft: $relative ($($signature.SignerCertificate.Subject))"
    }
}

if ($problems) {
    $problems | Select-Object -First 50 | ForEach-Object { Write-Host "::error::$_" }
    exit 1
}

Write-Host "Staged output: $($actual.Count) files as listed; $(@($binaries).Count) third-party binaries signed by Microsoft."
exit 0
