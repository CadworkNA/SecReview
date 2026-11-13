# Makes the signing tools ready for sign.ps1 and prints the path of the ArtifactSigning module
# to import. They run next to the Azure sign-in, so each package is downloaded here and used only
# if its SHA-256 is the one below:
#   - the ArtifactSigning module (the exact version azure/artifact-signing-action v2.0.0 uses);
#   - the three tools the module would otherwise fetch by itself on first use. They are unpacked
#     where the module looks for them, so it finds them and downloads nothing.
# A package that no longer matches fails the build. A new version or hash comes in by pull request.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$gallery = 'https://www.powershellgallery.com/api/v2/package'
$nuget = 'https://www.nuget.org/api/v2/package'
$module = @{ Id = 'ArtifactSigning'; Version = '0.1.8'; Source = $gallery; Sha256 = '3221344B8C627915D3870F23E80816F31A5D8C2BAE1D7C0CDD6C9652F6C4E089' }
# The versions are the ones ArtifactSigning 0.1.8 asks for (NugetInstall.psm1).
$tools = @(
    @{ Id = 'Microsoft.Windows.SDK.BuildTools'; Version = '10.0.26100.4188'; Source = $nuget; Sha256 = '180DEB372659029864C10A0C04787833234D64AACD1D2C0661D2C00295D8E022' }
    @{ Id = 'Microsoft.ArtifactSigning.Client'; Version = '1.0.128'; Source = $nuget; Sha256 = '74BD7D27E6CE1051409C38D9B46BC8DF0400ECD643D51FFBF2AC00869061E40B' }
    @{ Id = 'sign'; Version = '0.9.1-beta.26227.3'; Source = $nuget; Sha256 = '34FD0D4AEABDBC363A48883881865B4DD65E6C11BA916028082FA23F3E1B1BA1' }
)

# Unpacks a checked package into $Destination. sign.ps1 runs several times in one build, so a
# folder this script filled before (its hash file beside it) is kept; anything else there is
# replaced.
function Install-CheckedPackage([hashtable] $Package, [string] $Destination) {
    $marker = "$Destination.sha256"
    if ((Test-Path -LiteralPath $Destination) -and (Test-Path -LiteralPath $marker) -and
        (Get-Content -LiteralPath $marker -Raw).Trim() -eq $Package.Sha256) {
        return
    }
    Remove-Item -LiteralPath $Destination, $marker -Recurse -Force -ErrorAction SilentlyContinue

    $download = Join-Path ([System.IO.Path]::GetTempPath()) ('package-' + [guid]::NewGuid().ToString('N') + '.nupkg')
    try {
        Invoke-WebRequest -Uri "$($Package.Source)/$($Package.Id)/$($Package.Version)" -OutFile $download -UseBasicParsing
        $actual = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash
        if ($actual -ne $Package.Sha256) {
            throw "$($Package.Id) $($Package.Version) is not the package this script was checked with (SHA-256 $actual)."
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($download, $Destination)
        Set-Content -LiteralPath $marker -Value $Package.Sha256
    } finally {
        Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
    }
}

# Where the module looks: %LOCALAPPDATA%\ArtifactSigning\<id>\<id>.<version>.
foreach ($tool in $tools) {
    $folder = Join-Path $env:LOCALAPPDATA "ArtifactSigning\$($tool.Id)\$($tool.Id).$($tool.Version)"
    Install-CheckedPackage $tool $folder
}

$moduleFolder = Join-Path $env:LOCALAPPDATA "SecReviewSigning\$($module.Id).$($module.Version)"
Install-CheckedPackage $module $moduleFolder
Join-Path $moduleFolder "$($module.Id).psd1"
