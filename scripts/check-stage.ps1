# Checks the folder that ships (artifacts\stage) before anything is built on top of it.
# scripts\stage-files.txt lists every file. For each file that is not ours:
#   - a binary (exe, dll, mui) must carry a valid Authenticode signature from Microsoft
#     Corporation that chains to one of the pinned Microsoft roots;
#   - any other file (metadata, resource index, image) must match the SHA-256 in the list.
# A new, missing or changed file is therefore a reviewed change to stage-files.txt.
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

# Built here on every run, so neither signed by Microsoft nor of a fixed hash.
$ours = 'SecReview.exe', 'SecReviewCli.exe', 'SecReview.pri'
$signedExtensions = '.exe', '.dll', '.mui'

# SHA-1 thumbprints of the root certificates the Windows App SDK binaries chain to.
$microsoftRoots = @(
    '8F43288AD272F3103B6FB1428485EA3014C0BCFE'   # Microsoft Root Certificate Authority 2011
    '3B1EFD3A66EA28B16697394703A72CA340A05BD5'   # Microsoft Root Certificate Authority 2010
)
$organizationOid = '2.5.4.10'

function Get-RelativePath([System.IO.FileInfo] $file) {
    $file.FullName.Substring($stagePath.Length + 1).Replace('\', '/')
}

# Returns nothing when the file is signed by Microsoft, otherwise the reason it is not.
function Test-MicrosoftSignature([string] $path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'Valid') { return "not validly signed ($($signature.Status))" }

    $certificate = $signature.SignerCertificate
    # Read the O= part of the subject as a parsed name, not by matching the subject string.
    $organizations = @($certificate.SubjectName.EnumerateRelativeDistinguishedNames() |
        Where-Object { -not $_.HasMultipleElements -and $_.GetSingleElementType().Value -eq $organizationOid } |
        ForEach-Object { $_.GetSingleElementValue() })
    if ($organizations.Count -ne 1 -or $organizations[0] -cne 'Microsoft Corporation') {
        return "signed by '$($organizations -join ', ')', not Microsoft Corporation"
    }

    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        # Catalog and timestamped signatures stay valid after the signing certificate expires.
        $chain.ChainPolicy.VerificationFlags = 'IgnoreNotTimeValid'
        if (-not $chain.Build($certificate)) { return 'certificate chain does not build' }
        $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        if ($root.Thumbprint -notin $microsoftRoots) {
            return "chains to an unexpected root ($($root.GetNameInfo('SimpleName', $false)), $($root.Thumbprint))"
        }
    } finally {
        $chain.Dispose()
    }
}

$files = @(Get-ChildItem $stagePath -Recurse -File)
if ($files.Count -eq 0) {
    Write-Host "::error::$Stage is empty."
    exit 1
}

# path -> the line that belongs in stage-files.txt for the file as staged
$actual = [System.Collections.Generic.SortedDictionary[string, string]]::new([System.StringComparer]::Ordinal)
foreach ($file in $files) {
    $relative = Get-RelativePath $file
    $hashed = $file.Name -notin $ours -and $file.Extension -notin $signedExtensions
    $actual[$relative] = if ($hashed) {
        "$relative sha256=$((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant())"
    } else {
        $relative
    }
}

if ($Update) {
    $header = @(
        '# Every file that ships, relative to the install folder. Files without an Authenticode'
        '# signature that are not built here carry their SHA-256. scripts\check-stage.ps1 fails the'
        '# build when the staged output differs. Regenerate with: scripts\check-stage.ps1 -Stage'
        '# artifacts\stage -Update, and review the difference before committing.'
    )
    [System.IO.File]::WriteAllLines($listFile, [string[]] ($header + $actual.Values))
    Write-Host "stage-files.txt updated: $($actual.Count) files."
    exit 0
}

if (-not (Test-Path $listFile)) {
    Write-Host "::error::scripts\stage-files.txt is missing; create it with -Update."
    exit 1
}

$problems = [System.Collections.Generic.List[string]]::new()

$expected = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
foreach ($line in Get-Content $listFile) {
    $line = $line.Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }
    $expected[($line -split ' ', 2)[0]] = $line
}

foreach ($path in $actual.Keys) {
    if (-not $expected.ContainsKey($path)) {
        $problems.Add("Unexpected file in the staged output: $path")
    } elseif ($expected[$path] -cne $actual[$path]) {
        $problems.Add("Content differs from stage-files.txt: $path")
    }
}
foreach ($path in $expected.Keys) {
    if (-not $actual.ContainsKey($path)) { $problems.Add("Missing from the staged output: $path") }
}

$signed = 0
foreach ($file in $files) {
    if ($file.Name -in $ours -or $file.Extension -notin $signedExtensions) { continue }
    $signed++
    $reason = Test-MicrosoftSignature $file.FullName
    if ($reason) { $problems.Add("$(Get-RelativePath $file): $reason") }
}

if ($problems.Count -gt 0) {
    $problems | Select-Object -First 50 | ForEach-Object { Write-Host "::error::$_" }
    exit 1
}

$hashedCount = @($actual.Values | Where-Object { $_ -match ' sha256=' }).Count
Write-Host ("Staged output: {0} files as listed; {1} binaries signed by Microsoft; {2} other files match their hash." -f
    $actual.Count, $signed, $hashedCount)
exit 0
