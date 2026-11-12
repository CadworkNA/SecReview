# Signs files with Azure Artifact Signing. Used by build.ps1 -Sign for the two programs and, as
# Inno Setup's sign tool, for the setup program and the uninstaller.
#
# Sign-in: whatever the Azure tools find; in CI that is the session of the azure/login step
# (OpenID Connect, no stored secret). Nothing is signed on a developer's PC.
# Settings (environment): SIGNING_ACCOUNT_NAME, CERTIFICATE_PROFILE_NAME and, optionally,
# SIGNING_ENDPOINT.
param([Parameter(Mandatory, ValueFromRemainingArguments)] [string[]] $Files)

$ErrorActionPreference = 'Stop'

# The module that talks to the signing service: the exact version azure/artifact-signing-action v2.0.0 uses.
$moduleVersion = '0.1.8'

foreach ($name in 'SIGNING_ACCOUNT_NAME', 'CERTIFICATE_PROFILE_NAME') {
    if (-not [Environment]::GetEnvironmentVariable($name)) { throw "$name is not set." }
}
$endpoint = if ($env:SIGNING_ENDPOINT) { $env:SIGNING_ENDPOINT } else { 'https://wus2.codesigning.azure.net/' }

if (-not (Get-Module -ListAvailable ArtifactSigning | Where-Object Version -eq $moduleVersion)) {
    Install-Module ArtifactSigning -RequiredVersion $moduleVersion -Force -Repository PSGallery -Scope CurrentUser
}
Import-Module ArtifactSigning -RequiredVersion $moduleVersion

# Inno Setup hands over temporary files with names such as "uninst.e32.tmp". The signing
# tools go by the extension, so those are signed as copies named .exe and copied back.
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('sign-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $map = [ordered]@{}
    foreach ($file in $Files) {
        $full = (Resolve-Path -LiteralPath $file).Path
        $extension = [System.IO.Path]::GetExtension($full).ToLowerInvariant()
        $target = if ($extension -in '.exe', '.dll') { $full } else {
            $copy = Join-Path $work ('{0}-{1}.exe' -f $map.Count, [System.IO.Path]::GetFileNameWithoutExtension($full))
            Copy-Item -LiteralPath $full -Destination $copy
            $copy
        }
        $map[$full] = $target
    }
    "Signing: $($map.Keys -join ', ')"

    $arguments = @{
        Endpoint               = $endpoint
        CodeSigningAccountName = $env:SIGNING_ACCOUNT_NAME
        CertificateProfileName = $env:CERTIFICATE_PROFILE_NAME
        Files                  = ($map.Values -join ',')
        FileDigest             = 'SHA256'
        TimestampRfc3161       = 'http://timestamp.acs.microsoft.com'
        TimestampDigest        = 'SHA256'
    }
    # From a folder outside the repository: the module installs its own tools with NuGet, and
    # the repository's nuget.config (one source, every package id mapped to it) is meant for
    # SecReview's packages, not for the signing tools. Files are given by their full paths.
    Push-Location -LiteralPath $work
    try {
        Invoke-ArtifactSigning @arguments
    } finally {
        Pop-Location
    }

    foreach ($entry in $map.GetEnumerator()) {
        $signature = Get-AuthenticodeSignature -LiteralPath $entry.Value
        if ($signature.Status -ne 'Valid') {
            throw "The signature on '$($entry.Key)' is $($signature.Status): $($signature.StatusMessage)"
        }
        if (-not $signature.TimeStamperCertificate) { throw "The signature on '$($entry.Key)' has no timestamp." }
        if ($entry.Value -ne $entry.Key) { Copy-Item -LiteralPath $entry.Value -Destination $entry.Key -Force }
        "Signed: $($entry.Key) ($($signature.SignerCertificate.Subject))"
    }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
