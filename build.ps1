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
#   .\build.ps1 -MalwareIndex <file> # ship this list of known-malicious packages (built by the
#                                    # "Known-malicious list" workflow); without it there is none
#   .\build.ps1 -ErrorReportAddress <dsn>   # where the app reports its own errors (official
#                                    # builds only); without it the app never sends anything
param(
    [string] $Version = '0.0.0-dev',
    [switch] $NoTests,
    [switch] $NoPublish,
    [switch] $LocalCache,
    [switch] $Locked,
    [switch] $UpdateStageList,
    [string] $MalwareIndex,
    [string] $ErrorReportAddress
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
# What every compile gets. With a list of known-malicious packages, its SHA-256 is compiled
# into the programs, which then load that exact file and no other.
$compileArgs = @("-p:Version=$Version")
$listFile = $null
if ($MalwareIndex) {
    if ($NoPublish) { throw '-MalwareIndex ships a list with the published programs; it cannot be combined with -NoPublish.' }
    $listFile = (Resolve-Path -LiteralPath $MalwareIndex).Path
    $compileArgs += "-p:KnownMaliciousListSha256=$((Get-FileHash -LiteralPath $listFile -Algorithm SHA256).Hash.ToLowerInvariant())"
}

if ($ErrorReportAddress) {
    if ($ErrorReportAddress -notmatch '^https://[0-9a-f]+@[A-Za-z0-9.-]+/[0-9]+$') {
        throw '-ErrorReportAddress must look like https://<key>@<host>/<project number>.'
    }
    $compileArgs += "-p:ErrorReportAddress=$ErrorReportAddress"
}

Invoke-Step 'Build' { dotnet build $solution -c Release --no-restore @compileArgs }

if ($listFile) {
    # The list must load, come from the feed, be recent and not have lost packages.
    Invoke-Step 'Check the list of known-malicious packages' {
        dotnet (Join-Path $root 'tools\SecReview.IndexBuilder\bin\Release\net10.0\SecReviewIndexBuilder.dll') --check $listFile
    }
}

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
        -o (Join-Path $publish 'cli') @compileArgs
}

Invoke-Step 'Publish SecReview (Native AOT)' {
    dotnet publish (Join-Path $root 'src\SecReview.App') -c Release --no-restore `
        -o (Join-Path $publish 'app') @compileArgs
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

if ($listFile) {
    Copy-Item -LiteralPath $listFile (Join-Path $stage 'known-malicious.idx')
}

Invoke-Step 'Check staged output' {
    & (Join-Path $root 'scripts\check-stage.ps1') -Stage $stage -Update:$UpdateStageList
}

# The app keeps its log (and later its results and settings) in the build output while it is
# being smoke-tested, not in the profile of whoever runs the build. The variable is set for the
# app only (see Invoke-App), so the shell that ran the build is left as it was.
$appData = Join-Path $root 'artifacts\appdata'
if (Test-Path $appData) { Remove-Item $appData -Recurse -Force }

# What the app logged, for the message when a smoke test fails.
function Get-AppLog {
    $log = Join-Path $appData 'logs\SecReview.log'
    if (Test-Path $log) { "`nThe app's log:`n" + ((Get-Content $log | Select-Object -First 30) -join "`n") } else { '' }
}

# Starts SecReview.exe with the given arguments. Returns its exit code, or 'timeout'.
function Invoke-App([string[]] $Arguments, [int] $TimeoutSeconds = 90) {
    $start = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $stage 'SecReview.exe'))
    $start.UseShellExecute = $false
    $start.Environment['SECREVIEW_DATA_DIR'] = $appData
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
    # administrator" or "not supported" are all fine; an outright failure is not. A successful
    # line ends with this machine's settings, so outside CI those are left out; the reason on
    # any other line is always shown.
    $report = & $cli --diagnose
    $diagnoseExit = $LASTEXITCODE
    foreach ($line in $report) {
        $isValue = $line.Length -gt 41 -and $line.Substring(21, 20).Trim() -eq 'ok'
        if ($isValue -and $env:CI -ne 'true') { Write-Host "  $($line.Substring(0, 41).TrimEnd())" }
        else { Write-Host "  $line" }
    }
    if ($diagnoseExit -ne 0) { throw "SecReviewCli --diagnose exited with $diagnoseExit, expected 0." }

    # The checks must run from the compiled helper and produce a well-formed report. Whether
    # this machine passes them is not the build's business.
    $reportPath = Join-Path $root 'artifacts\smoke.report.json'
    & $cli --report $reportPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "SecReviewCli --report exited with $LASTEXITCODE, expected 0." }
    $report = Get-Content $reportPath -Raw | ConvertFrom-Json
    $counts = $report.counts
    $total = $counts.pass + $counts.fail + $counts.needsAdmin + $counts.notApplicable + $counts.error
    if ($report.schemaVersion -ne 1 -or $report.checks.Count -eq 0 -or $total -ne $report.checks.Count) {
        throw "The report is malformed: schema $($report.schemaVersion), $($report.checks.Count) checks, counts add up to $total."
    }
    if ($report.version -ne $Version) { throw "The report says version '$($report.version)', expected '$Version'." }
    foreach ($check in $report.checks) {
        if (-not $check.id -or -not $check.title -or -not $check.summary) {
            throw "A check in the report has no id, title or summary."
        }
        if ($env:CI -eq 'true') { Write-Host ("  {0,-20} {1,-14} {2}" -f $check.id, $check.status, $check.summary) }
    }
    Write-Host "Report: $($report.checks.Count) checks, well-formed."

    # A list that was staged must load in the compiled helper: the hash compiled in, its own
    # checksum and every entry.
    if ($listFile) {
        $list = $report.checks | Where-Object { $_.id -eq 'sc.malware.list' }
        if (-not $list -or $list.status -ne 'Pass') {
            throw "The staged list of known-malicious packages was not usable: $($list.status), $($list.summary)"
        }
        Write-Host "Known-malicious list: $($list.summary)"
    }

    # The window must load and draw from the staged folder (catches a missing DLL or resource
    # file, which only shows at start-up). Exit codes: SecReview.CommandLine.ExitCode.
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $exit = Invoke-App '--smoke-test'
    if ($exit -ne 0) {
        throw "SecReview.exe --smoke-test ended with '$exit', expected 0.$(Get-AppLog)"
    }
    Write-Host "SecReview.exe: this PC scanned, window shown and closed in $($timer.ElapsedMilliseconds) ms."

    # A picture of the window with made-up results covering every kind of outcome: proof that
    # the rows, tables and fix steps draw, and something to look at without any real PC's data.
    $shots = Join-Path $root 'artifacts\screenshots'
    if (Test-Path $shots) { Remove-Item $shots -Recurse -Force }
    New-Item -ItemType Directory -Path $shots | Out-Null
    # One picture per state of the window. Each run also checks that everything on screen has
    # a name for a screen reader and can be reached with the keyboard (exit code 10 if not).
    # The last state also opens every dialog once and checks it the same way.
    foreach ($state in 'mixed', 'all-pass', 'first-run', 'ignored', 'loading', 'failed', 'dialogs') {
        $picture = Join-Path $shots "demo-$state.png"
        $exit = Invoke-App '--demo', $state, '--screenshot', $picture
        if ($exit -ne 0 -or -not (Test-Path $picture) -or (Get-Item $picture).Length -lt 10KB) {
            throw "SecReview.exe --demo $state --screenshot ended with '$exit' and no usable picture.$(Get-AppLog)"
        }
        Write-Host "Screenshot: artifacts\screenshots\demo-$state.png ($([int]((Get-Item $picture).Length / 1KB)) KB)."
    }

    # What an error report holds. The app raises made-up errors that carry this PC's user
    # name, computer name, profile path and a made-up secret, and writes what it would have
    # sent to a file instead of sending it. The errors must be there; none of those may be,
    # nor anything else about the device, and nothing may be written to the user's profile.
    $sdkFolder = Join-Path $env:LOCALAPPDATA 'Sentry'
    $sdkFoldersBefore = @(Get-ChildItem $sdkFolder -ErrorAction SilentlyContinue).Count
    $reportFile = Join-Path $root 'artifacts\error-report-test.txt'
    if (Test-Path $reportFile) { Remove-Item $reportFile -Force }
    $exit = Invoke-App '--error-report-test', $reportFile
    if ($exit -ne 0 -or -not (Test-Path $reportFile)) {
        throw "SecReview.exe --error-report-test ended with '$exit'.$(Get-AppLog)"
    }
    $reports = Get-Content $reportFile -Raw
    foreach ($expected in 'System.InvalidOperationException', 'System.FormatException', 'selftest.check',
            "secreview@$Version", 'ended without closing down', 'Self-test feedback', 'firewall.enabled: Fail') {
        if (-not $reports.Contains($expected)) { throw "The error-report test output lacks '$expected'." }
    }
    $forbidden = [ordered]@{
        'the made-up secret'    = 'made-up-token-7c1f'
        'the computer name'     = $env:COMPUTERNAME
        'the profile path'      = $env:USERPROFILE.Replace('\', '\\')
        'the server name field' = '"server_name"'
        'a device section'      = '"device"'
        'the time zone'         = 'timezone'
        'a user id'             = '"user":{"id"'
        'the list of modules'   = '"modules"'
    }
    # A user name such as "admin" is too ordinary a word to be told from text and is left alone
    # by the scrubber; any other is looked for.
    if ($env:USERNAME.Length -ge 5 -and $env:USERNAME -notmatch '^(administrator|guest|owner|default|public|system|users)$') {
        $forbidden['the user name'] = $env:USERNAME
    }
    foreach ($what in $forbidden.Keys) {
        if ($reports.IndexOf($forbidden[$what], [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "The error-report test output holds $what."
        }
    }
    if (@(Get-ChildItem $sdkFolder -ErrorAction SilentlyContinue).Count -ne $sdkFoldersBefore) {
        throw "The error-reporting SDK wrote into $sdkFolder; it must write nothing to the user's profile."
    }
    Write-Host "Error reports: 4 made-up reports written to a file, none sent; no name, path, secret or device detail in them."

    $exit = Invoke-App '--no-such-argument'
    if ($exit -ne 2) { throw "SecReview.exe with an unknown argument exited with '$exit', expected 2." }

    $global:LASTEXITCODE = 0
}

$files = Get-ChildItem $stage -Recurse -File
'Staged: {0} files, {1:N1} MB' -f $files.Count, (($files | Measure-Object Length -Sum).Sum / 1MB)
