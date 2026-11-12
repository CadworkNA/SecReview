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
#   .\build.ps1 -UpdateStageList     # rewrite scripts\stage-files.txt from this build's output
#                                    # (after a Windows App SDK change; review the difference)
param(
    [string] $Version = '0.0.0-dev',
    [switch] $NoTests,
    [switch] $NoPublish,
    [switch] $LocalCache,
    [switch] $Locked,
    [switch] $UpdateStageList
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

Invoke-Step 'Publish SecReview (Native AOT)' {
    dotnet publish (Join-Path $root 'src\SecReview.App') -c Release --no-restore `
        -o (Join-Path $publish 'app') "-p:Version=$Version"
}

# Stage only what ships: the app with the Windows App SDK files that must sit next to it, and
# the command-line exe. Symbols are kept apart; XML doc files are dropped.
#
# Parts of the Windows App SDK that SecReview never uses are left out, so they are not there to
# be abused: the WebView2 browser control and the map page built on it, the design-time
# library, and the helper exe behind the restart API.
$notShipped = @(
    'WebView2Loader.dll'
    'Microsoft.Web.WebView2.Core.dll'
    'Microsoft.UI.Xaml\Assets\map.html'
    'Microsoft.UI.Designer.dll'
    'RestartAgent.exe'
)
$appPublish = Join-Path $publish 'app'
foreach ($file in Get-ChildItem $appPublish -Recurse -File) {
    $relative = $file.FullName.Substring($appPublish.Length + 1)
    if ($file.Extension -eq '.pdb') {
        Copy-Item -LiteralPath $file.FullName (Join-Path $symbols $file.Name)
        continue
    }
    if ($file.Extension -eq '.xml' -or $relative -in $notShipped) { continue }

    $target = Join-Path $stage $relative
    New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $file.FullName $target
}
Copy-Item (Join-Path $publish 'cli\SecReviewCli.exe') $stage
Copy-Item (Join-Path $publish 'cli\*.pdb') $symbols -Force

Invoke-Step 'Check staged output' {
    & (Join-Path $root 'scripts\check-stage.ps1') -Stage $stage -Update:$UpdateStageList
}

# Starts SecReview.exe with the given arguments. Returns its exit code, or 'timeout'.
function Invoke-App([string[]] $Arguments, [int] $TimeoutSeconds = 60) {
    $start = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $stage 'SecReview.exe'))
    $start.UseShellExecute = $false
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }

    $process = [System.Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            return 'timeout'
        }
        return $process.ExitCode
    } finally {
        $process.Dispose()
    }
}

Invoke-Step 'Smoke test' {
    $cli = Join-Path $stage 'SecReviewCli.exe'

    $shown = & $cli --version
    if ($LASTEXITCODE -ne 0 -or $shown -ne "SecReview $Version") {
        throw "--version printed '$shown' (exit $LASTEXITCODE), expected 'SecReview $Version'."
    }

    & $cli --no-such-command 2>$null | Out-Null
    if ($LASTEXITCODE -ne 2) { throw "An unknown command exited with $LASTEXITCODE, expected 2." }

    # Every probe must answer from the compiled helper on real Windows: a value, "needs
    # administrator" or "not supported" are all fine; an outright failure is not. The values
    # are this machine's settings, so only the status column is printed outside CI.
    $report = & $cli --diagnose
    $diagnoseExit = $LASTEXITCODE
    foreach ($line in $report) {
        if ($env:CI -eq 'true') { Write-Host "  $line" }
        elseif ($line.Length -gt 41) { Write-Host "  $($line.Substring(0, 41).TrimEnd())" }
        else { Write-Host "  $line" }
    }
    if ($diagnoseExit -ne 0) { throw "SecReviewCli --diagnose exited with $diagnoseExit, expected 0." }

    # The window must load and draw from the staged folder (catches a missing DLL or resource
    # file, which only shows at start-up). Exit codes: SecReview.CommandLine.ExitCode.
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $exit = Invoke-App '--smoke-test'
    if ($exit -ne 0) {
        throw "SecReview.exe --smoke-test ended with '$exit', expected 0."
    }
    Write-Host "SecReview.exe: window shown and closed in $($timer.ElapsedMilliseconds) ms."

    $exit = Invoke-App '--no-such-argument'
    if ($exit -ne 2) { throw "SecReview.exe with an unknown argument exited with '$exit', expected 2." }

    $global:LASTEXITCODE = 0
}

$files = Get-ChildItem $stage -Recurse -File
'Staged: {0} files, {1:N1} MB' -f $files.Count, (($files | Measure-Object Length -Sum).Sum / 1MB)
