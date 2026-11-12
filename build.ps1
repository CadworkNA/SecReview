#requires -Version 7.0
# Builds, tests and publishes SecReview. Output: artifacts\stage (what ships), artifacts\symbols.
# Run it from PowerShell 7 (pwsh), not Windows PowerShell.
#
#   .\build.ps1                      # restore, build, test, publish
#   .\build.ps1 -Version 1.2.3       # stamp a version (semantic version)
#   .\build.ps1 -NoTests             # skip the unit tests
#   .\build.ps1 -NoPublish           # stop after the tests (no Native AOT publish)
#   .\build.ps1 -LocalCache          # keep NuGet's caches inside the repo (.nuget\)
#   .\build.ps1 -Locked              # restore in locked mode, as CI does
param(
    [string] $Version = '0.0.0-dev',
    [switch] $NoTests,
    [switch] $NoPublish,
    [switch] $LocalCache,
    [switch] $Locked
)
$ErrorActionPreference = 'Stop'
# Exit codes of native commands are checked explicitly below, whatever the user's profile says.
$PSNativeCommandUseErrorActionPreference = $false
$root = $PSScriptRoot

if ($Version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$') {
    throw "Version must be a semantic version (X.Y.Z or X.Y.Z-pre), got '$Version'."
}

function Invoke-Step([string] $Name, [scriptblock] $Action) {
    Write-Host "== $Name" -ForegroundColor Cyan
    & $Action
    if ($LASTEXITCODE) { throw "$Name failed ($LASTEXITCODE)." }
}

# No telemetry from the SDK or the test runner.
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
$env:TESTINGPLATFORM_TELEMETRY_OPTOUT = '1'

if ($LocalCache) {
    $env:NUGET_PACKAGES = Join-Path $root '.nuget\packages'
    $env:NUGET_HTTP_CACHE_PATH = Join-Path $root '.nuget\http-cache'
}

# Native AOT finds the MSVC linker through vswhere, which Visual Studio does not put on PATH.
$vsInstaller = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
if ((Test-Path (Join-Path $vsInstaller 'vswhere.exe')) -and ($env:PATH -notlike "*$vsInstaller*")) {
    $env:PATH += ";$vsInstaller"
}

$solution = Join-Path $root 'SecReview.slnx'
# -Locked is the only switch for locked restore: without it the lock files may be updated.
$restoreArgs = @('restore', $solution, "-p:RestoreLockedMode=$($Locked.IsPresent.ToString().ToLowerInvariant())")

Invoke-Step 'Check source text' { & (Join-Path $root 'scripts\check-source-text.ps1') }
Invoke-Step 'Restore' { dotnet @restoreArgs }
Invoke-Step 'Check lock files' { & (Join-Path $root 'scripts\check-lockfiles.ps1') }
Invoke-Step 'Build' { dotnet build $solution -c Release --no-restore "-p:Version=$Version" }

if (-not $NoTests) {
    Invoke-Step 'Test' { dotnet test --solution $solution -c Release --no-build }
}

if ($NoPublish) { return }

$publish = Join-Path $root 'artifacts\publish'
$stage = Join-Path $root 'artifacts\stage'
$symbols = Join-Path $root 'artifacts\symbols'
foreach ($dir in $publish, $stage, $symbols) {
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    New-Item -ItemType Directory -Path $dir | Out-Null
}

Invoke-Step 'Publish SecReviewCli (Native AOT)' {
    dotnet publish (Join-Path $root 'src\SecReview.Cli') -c Release --no-restore `
        -o (Join-Path $publish 'cli') "-p:Version=$Version"
}

# Stage only what ships; symbols are kept apart.
Copy-Item (Join-Path $publish 'cli\SecReviewCli.exe') $stage
Copy-Item (Join-Path $publish 'cli\*.pdb') $symbols

Invoke-Step 'Smoke test' {
    $cli = Join-Path $stage 'SecReviewCli.exe'

    $shown = & $cli --version
    if ($LASTEXITCODE -ne 0 -or $shown -ne "SecReview $Version") {
        throw "--version printed '$shown' (exit $LASTEXITCODE), expected 'SecReview $Version'."
    }

    & $cli --no-such-command 2>$null | Out-Null
    if ($LASTEXITCODE -ne 2) { throw "An unknown command exited with $LASTEXITCODE, expected 2." }
    $global:LASTEXITCODE = 0
}

Get-ChildItem $stage | Select-Object Name, Length
