#requires -Version 7.0
# Packs a staged folder into the setup program with Inno Setup: <Out>\SecReview-<Version>-setup.exe.
# Called by build.ps1 -Installer, and twice on one folder by the reproducible-build workflow.
#
#   scripts\pack.ps1 -Stage artifacts\stage -Version 1.2.3 -Out artifacts\installer [-Sign]
param(
    [Parameter(Mandatory)] [string] $Stage,
    [Parameter(Mandatory)] [string] $Version,
    [Parameter(Mandatory)] [string] $Out,
    [switch] $Sign
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path $PSScriptRoot -Parent
$invariant = [cultureinfo]::InvariantCulture

$iscc = & (Join-Path $PSScriptRoot 'ensure-inno.ps1')
$numbers = ($Version -split '-', 2)[0]
$publisher = ([xml] (Get-Content (Join-Path $root 'Directory.Build.props') -Raw)).Project.PropertyGroup.Company |
    Where-Object { $_ } | Select-Object -First 1
# Every packed file carries the commit's time, in UTC, not the time it was built.
$committed = git -C $root show -s --format=%cI HEAD
if ($LASTEXITCODE -or -not $committed) { throw 'The setup program needs the commit time, and git could not read it.' }
$committed = ([datetimeoffset]::Parse($committed, $invariant)).UtcDateTime

$isccArgs = @(
    '/Q'
    "/DAppVersion=$Version"
    "/DFileVersion=$numbers.0"
    "/DFileDate=$($committed.ToString('yyyy-MM-dd', $invariant))"
    "/DFileTime=$($committed.ToString('HH:mm:ss', $invariant))"
    "/DStage=$((Resolve-Path $Stage).Path)"
    "/DOutputFolder=$([IO.Path]::GetFullPath($Out))"
    "/DPublisher=$publisher"
)
if ($Sign) {
    # Inno Setup calls this for the uninstaller and for the setup program itself.
    $isccArgs += '/DSIGN'
    # ($q is Inno Setup's way of writing a quotation mark; $f is the file to sign.)
    $isccArgs += '/Sartifactsigning=pwsh -NoProfile -File $q' + (Join-Path $PSScriptRoot 'sign.ps1') + '$q $f'
}
& $iscc @isccArgs (Join-Path $root 'installer\SecReview.iss')
if ($LASTEXITCODE) { throw "Inno Setup failed ($LASTEXITCODE)." }
