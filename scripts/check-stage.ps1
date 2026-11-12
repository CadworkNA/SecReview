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
    [switch] $Update,
    # A release: our own two programs must carry a valid, timestamped signature as well.
    [switch] $OursSigned
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

# The list of known-malicious packages is rebuilt every day, so it is neither in the list nor
# of a fixed hash, and a development build has none. It carries its own checksum, which the
# apps verify each time they load it (build.ps1 -MalwareIndex has the smoke test prove that).
$optional = 'known-malicious.idx'
$files = @(Get-ChildItem $stagePath -Recurse -File | Where-Object { (Get-RelativePath $_) -cne $optional })
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

if ($OursSigned) {
    # The publisher the programs are compiled to accept updates from. What this build signs
    # must be signed by that same publisher, or its own updates would be refused.
    $publisher = ([xml] (Get-Content (Join-Path $PSScriptRoot '..\signing\Publisher.props') -Raw)).Project.PropertyGroup
    foreach ($name in 'SecReview.exe', 'SecReviewCli.exe') {
        $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $stagePath $name)
        if ($signature.Status -ne 'Valid') {
            $problems.Add("${name}: not validly signed ($($signature.Status))")
            continue
        }
        if (-not $signature.TimeStamperCertificate) {
            $problems.Add("${name}: the signature has no timestamp, so it would lapse with the certificate")
        }
        $certificate = $signature.SignerCertificate
        $usages = @($certificate.Extensions |
            Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
            ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
        if ($certificate.Subject -cne $publisher.PublisherSubject) {
            $problems.Add("${name}: signed by '$($certificate.Subject)', not by the publisher in signing\Publisher.props")
        } elseif ($publisher.PublisherIdentityOid -and $publisher.PublisherIdentityOid -notin $usages) {
            $problems.Add("${name}: the signing certificate does not carry the publisher's identifier from signing\Publisher.props")
        } else {
            Write-Host "${name}: signed by $($certificate.GetNameInfo('SimpleName', $false)), the publisher in signing\Publisher.props."
        }
    }
}

# Our own programs, read as bytes. Neither may carry the folder it was built in (under a
# user's profile that is the builder's name, shipped to everyone), and the command-line helper,
# the only program that runs elevated, must hold nothing of the error-reporting library.
function Test-Contains([string] $program, [string] $text) {
    # The text as single bytes, and as the two-byte characters Windows programs keep text in.
    $wide = -join ($text.ToCharArray() | ForEach-Object { "$_`0" })
    return $program.IndexOf($text, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $program.IndexOf($wide, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

$repository = (Split-Path $PSScriptRoot -Parent).TrimEnd('\')
foreach ($name in 'SecReview.exe', 'SecReviewCli.exe') {
    $program = Join-Path $stagePath $name
    if (-not (Test-Path $program)) { continue }

    # One character per byte, so the file can be searched as text.
    $bytes = [System.Text.Encoding]::Latin1.GetString([System.IO.File]::ReadAllBytes($program))
    if (Test-Contains $bytes $repository) {
        $problems.Add("$name contains the folder it was built in ($repository).")
    }
    if ($name -eq 'SecReviewCli.exe' -and (Test-Contains $bytes 'sentry')) {
        $problems.Add('SecReviewCli.exe contains the error-reporting library; only the app may.')
    }
}

if ($problems.Count -gt 0) {
    $problems | Select-Object -First 50 | ForEach-Object { Write-Host "::error::$_" }
    exit 1
}

$hashedCount = @($actual.Values | Where-Object { $_ -match ' sha256=' }).Count
Write-Host ("Staged output: {0} files as listed; {1} binaries signed by Microsoft; {2} other files match their hash." -f
    $actual.Count, $signed, $hashedCount)
exit 0
