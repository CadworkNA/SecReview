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
#   .\build.ps1 -UpdateUrl <url>     # where the programs look for updates: the https address of
#                                    # latest.json (official builds only); without it they never look
#   .\build.ps1 -Installer           # also build the setup program (needs Inno Setup 6.3+ or 7):
#                                    # artifacts\installer\SecReview-<version>-setup.exe
#   .\build.ps1 -Installer -Sign     # sign the two programs, the setup program and the
#                                    # uninstaller (release workflow only; see scripts\sign.ps1)
param(
    [string] $Version = '0.0.0-dev',
    [switch] $NoTests,
    [switch] $NoPublish,
    [switch] $LocalCache,
    [switch] $Locked,
    [switch] $UpdateStageList,
    [string] $MalwareIndex,
    [string] $ErrorReportAddress,
    [string] $UpdateUrl,
    [switch] $Installer,
    [switch] $Sign
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

if ($UpdateUrl) {
    if ($UpdateUrl -notmatch '^https://[A-Za-z0-9.-]+/[A-Za-z0-9._~/-]+\.json$') {
        throw '-UpdateUrl must be the https address of a .json file, without a query or a port.'
    }
    $compileArgs += "-p:UpdateManifestUrl=$UpdateUrl"
}

if ($Sign) {
    # A signed build knows its publisher (signing\Publisher.props) and so may install updates.
    $compileArgs += '-p:SignedBuild=true'
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

# The licences of SecReview and of what it contains (THIRD-PARTY-NOTICES.md says which is
# which). Texts that belong to a package version are taken from the restored package, so they
# always match what was compiled in.
$licenses = New-Item -ItemType Directory -Path (Join-Path $stage 'licenses')
$packages = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path $env:USERPROFILE '.nuget\packages' }
function Get-PackageFolder([string] $Id) {
    $lock = Get-Content (Join-Path $root 'src\SecReview.App\packages.lock.json') -Raw | ConvertFrom-Json -AsHashtable
    foreach ($framework in $lock.dependencies.Values) {
        if ($framework.ContainsKey($Id)) { return Join-Path $packages "$($Id.ToLowerInvariant())\$($framework[$Id].resolved)" }
    }
    throw "Package $Id is not in the app's lock file."
}
$windowsAppSdk = Get-PackageFolder 'Microsoft.WindowsAppSDK.Runtime'
$winUi = Get-PackageFolder 'Microsoft.WindowsAppSDK.WinUI'
$compiler = Get-PackageFolder 'runtime.win-x64.Microsoft.DotNet.ILCompiler'
$licenseFiles = [ordered]@{
    'SecReview-LICENSE.txt'            = Join-Path $root 'LICENSE'
    'THIRD-PARTY-NOTICES.txt'          = Join-Path $root 'THIRD-PARTY-NOTICES.md'
    'dotnet-runtime-LICENSE.txt'       = Join-Path $root 'notices\dotnet-runtime-LICENSE.txt'
    'dotnet-THIRD-PARTY-NOTICES.txt'   = Join-Path $compiler 'THIRD-PARTY-NOTICES.TXT'
    'WindowsAppSDK-license.txt'        = Join-Path $windowsAppSdk 'license.txt'
    'WindowsAppSDK-NOTICE.txt'         = Join-Path $windowsAppSdk 'NOTICE.txt'
    'WindowsAppSDK-WinUI-NOTICE.txt'   = Join-Path $winUi 'NOTICE.txt'
    'CsWinRT-LICENSE.txt'              = Join-Path $root 'notices\CsWinRT-LICENSE.txt'
    'sentry-dotnet-LICENSE.txt'        = Join-Path $root 'notices\sentry-dotnet-LICENSE.txt'
    'Ben.Demystifier-LICENSE.txt'      = Join-Path $root 'notices\Ben.Demystifier-LICENSE.txt'
    'malicious-packages-LICENSE.txt'   = Join-Path $root 'notices\malicious-packages-LICENSE.txt'
    'InnoSetup-license.txt'            = Join-Path $root 'notices\InnoSetup-license.txt'
}
foreach ($name in $licenseFiles.Keys) {
    Copy-Item -LiteralPath $licenseFiles[$name] (Join-Path $licenses $name)
}

if ($Sign) {
    # Before anything looks at the programs: what is checked, tried and packed is what ships.
    Invoke-Step 'Sign the programs' {
        & (Join-Path $root 'scripts\sign.ps1') (Join-Path $stage 'SecReview.exe') (Join-Path $stage 'SecReviewCli.exe')
    }
}

Invoke-Step 'Check staged output' {
    & (Join-Path $root 'scripts\check-stage.ps1') -Stage $stage -Update:$UpdateStageList -OursSigned:$Sign
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
function Invoke-App([string[]] $Arguments, [int] $TimeoutSeconds = 90, [hashtable] $Environment = @{}) {
    $start = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $stage 'SecReview.exe'))
    $start.UseShellExecute = $false
    $start.Environment['SECREVIEW_DATA_DIR'] = $appData
    foreach ($name in $Environment.Keys) { $start.Environment[$name] = $Environment[$name] }
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

# What this build measures on the way, held against scripts\budgets.psd1 at the end.
$measured = [ordered]@{}

Invoke-Step 'Smoke test' {
    $cli = Join-Path $stage 'SecReviewCli.exe'

    $shown = & $cli --version
    if ($LASTEXITCODE -ne 0 -or $shown -ne "SecReview $Version") {
        throw "--version printed '$shown' (exit $LASTEXITCODE), expected 'SecReview $Version'."
    }

    # How long the helper takes to start: the best of three, so that a virus scanner looking
    # at a program it has not seen before does not count.
    $measured.HelperStartMs = (1..3 | ForEach-Object { (Measure-Command { & $cli --version | Out-Null }).TotalMilliseconds } | Measure-Object -Minimum).Minimum

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
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    & $cli --report $reportPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "SecReviewCli --report exited with $LASTEXITCODE, expected 0." }
    $measured.ScanMs = $timer.ElapsedMilliseconds
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

    # The administrator helper, over a real pipe. This script stands in for the window: it
    # makes a pipe of the name the helper accepts, starts the compiled helper and reads its
    # answer. On a build machine that runs with administrator rights the checks are really
    # answered; anywhere else they say that they need those rights. Either way the answer
    # must be the administrator checks and nothing else.
    $pipeName = 'SecReview.Elev.' + (-join (1..32 | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) }))
    $pipe = [System.IO.Pipes.NamedPipeServerStream]::new(
        $pipeName, [System.IO.Pipes.PipeDirection]::In, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $connected = $pipe.WaitForConnectionAsync()
        $helper = Start-Process -FilePath $cli -ArgumentList '--elevated-scan', '--pipe', $pipeName -PassThru -WindowStyle Hidden
        if (-not $connected.Wait(30000)) { throw 'SecReviewCli --elevated-scan did not connect to the pipe within 30 seconds.' }
        $answer = [System.IO.StreamReader]::new($pipe, [System.Text.Encoding]::UTF8).ReadToEnd()
        if (-not $helper.WaitForExit(60000)) { $helper.Kill(); throw 'SecReviewCli --elevated-scan did not exit.' }
        if ($helper.ExitCode -ne 0) { throw "SecReviewCli --elevated-scan exited with $($helper.ExitCode), expected 0." }
    } finally {
        $pipe.Dispose()
    }
    $administratorScan = $answer | ConvertFrom-Json
    $elevatedHere = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    $asking = @($administratorScan.checks | Where-Object { $_.status -eq 'NeedsAdmin' }).Count
    if ($administratorScan.schemaVersion -ne 2 -or $administratorScan.appVersion -ne $Version -or $administratorScan.checks.Count -lt 5) {
        throw "The administrator helper's answer is malformed: $($answer.Substring(0, [Math]::Min(200, $answer.Length)))"
    }
    if (@($administratorScan.checks | Where-Object { $null -ne $_.administrator }).Count -gt 0) {
        throw 'The administrator helper sent a second answer beside its own.'
    }
    if ($administratorScan.checks.Count -ge $report.checks.Count) { throw 'The administrator helper answered for more than the administrator checks.' }
    if ($administratorScan.elevated -ne $elevatedHere) { throw "The helper says elevated=$($administratorScan.elevated); this build runs elevated=$elevatedHere." }
    if ($elevatedHere -and $asking -gt 0) { throw "$asking administrator checks still ask for administrator rights although the helper had them." }
    if (-not $elevatedHere -and $asking -eq 0) { throw 'Without administrator rights some checks must say they need them.' }
    Write-Host "Administrator helper: $($administratorScan.checks.Count) checks answered over a pipe (administrator rights: $elevatedHere; still asking: $asking)."

    & $cli --elevated-scan --pipe 'not-a-pipe-of-ours' 2>$null | Out-Null
    if ($LASTEXITCODE -ne 2) { throw "SecReviewCli --elevated-scan with another pipe name exited with $LASTEXITCODE, expected 2." }

    # The window must load and draw from the staged folder (catches a missing DLL or resource
    # file, which only shows at start-up). Exit codes: SecReview.CommandLine.ExitCode.
    $timer.Restart()
    $exit = Invoke-App '--smoke-test'
    if ($exit -ne 0) {
        throw "SecReview.exe --smoke-test ended with '$exit', expected 0.$(Get-AppLog)"
    }
    Write-Host "SecReview.exe: this PC scanned, window shown and closed in $($timer.ElapsedMilliseconds) ms."

    # The notification-area icon: it must start without the UI framework, put up its icon,
    # run the checks once and save what the window shows. On build machines only: an icon in
    # the notification area is something Windows remembers, and a developer's PC is not for
    # that. A build machine may have no notification area; the icon's log says which it was.
    if ($env:CI -eq 'true') {
        $results = Join-Path $appData 'results.json'
        if (Test-Path $results) { Remove-Item $results -Force }
        $timer.Restart()
        $exit = Invoke-App '--tray', '--smoke-test' -TimeoutSeconds 120
        if ($exit -ne 0 -or -not (Test-Path $results)) {
            throw "SecReview.exe --tray --smoke-test ended with '$exit' (results saved: $(Test-Path $results)).$(Get-AppLog)"
        }
        $said = Get-Content (Join-Path $appData 'logs\SecReview.log') | Where-Object { $_ -match 'Smoke test: (.+)$' } | ForEach-Object { $Matches[1] } | Select-Object -Last 1
        if (-not $said) { throw "The notification-area icon did not say whether it was shown.$(Get-AppLog)" }
        Write-Host "SecReview.exe --tray: checks run and results saved in $($timer.ElapsedMilliseconds) ms. $said"

        # A second icon for the same user ends at once, and the window asked to show a check
        # it does not have is still a window.
        $exit = Invoke-App '--show', 'no.such.check', '--smoke-test'
        if ($exit -ne 0) { throw "SecReview.exe --show no.such.check --smoke-test ended with '$exit', expected 0.$(Get-AppLog)" }

        # What the icon uses while it waits. It has just scanned, so the next scan is hours
        # away, and it leaves its first minute alone in any case: these ten seconds are idle.
        # Not in a build that knows a server (the update address, the error-report address):
        # an automated run asks no server, and this one is the icon as users have it.
        if (-not $UpdateUrl -and -not $ErrorReportAddress) {
            $start = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $stage 'SecReview.exe'))
            $start.UseShellExecute = $false
            $start.Environment['SECREVIEW_DATA_DIR'] = $appData
            $start.ArgumentList.Add('--tray')
            $icon = [System.Diagnostics.Process]::Start($start)
            try {
                Start-Sleep -Seconds 8
                if ($icon.HasExited) { throw "SecReview.exe --tray ended by itself with $($icon.ExitCode).$(Get-AppLog)" }
                $icon.Refresh()
                $before = $icon.TotalProcessorTime
                Start-Sleep -Seconds 10
                if ($icon.HasExited) { throw "SecReview.exe --tray ended by itself with $($icon.ExitCode).$(Get-AppLog)" }
                $icon.Refresh()
                $measured.IconIdleCpuMs = ($icon.TotalProcessorTime - $before).TotalMilliseconds
                $measured.IconMemoryMB = $icon.PrivateMemorySize64 / 1MB
            } finally {
                if (-not $icon.HasExited) { $icon.Kill() }
                $icon.Dispose()
            }
            Write-Host ('SecReview.exe --tray: waiting, it used {0:N0} ms of processor time in 10 s and holds {1:N0} MB.' -f $measured.IconIdleCpuMs, $measured.IconMemoryMB)
        }
    } else {
        Write-Host 'SecReview.exe --tray: not run here (build machines only).'
    }

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
        $timer.Restart()
        $exit = Invoke-App '--demo', $state, '--screenshot', $picture
        $took = $timer.ElapsedMilliseconds
        if ($exit -ne 0 -or -not (Test-Path $picture) -or (Get-Item $picture).Length -lt 10KB) {
            throw "SecReview.exe --demo $state --screenshot ended with '$exit' and no usable picture.$(Get-AppLog)"
        }
        Write-Host "Screenshot: artifacts\screenshots\demo-$state.png ($([int]((Get-Item $picture).Length / 1KB)) KB, $took ms)."

        # From start to a drawn window, a saved picture and the end: the quickest of the
        # states, the one with the dialogs aside (it opens every dialog in turn).
        if ($state -ne 'dialogs' -and (-not $measured.Contains('WindowMs') -or $took -lt $measured.WindowMs)) { $measured.WindowMs = $took }
    }

    # What an error report holds. The app raises made-up errors that carry this PC's user
    # name, computer name, profile path and a made-up secret, and writes what it would have
    # sent to a file instead of sending it. The errors must be there; none of those may be,
    # nor anything else about the device, and nothing may be written to the user's profile.
    # The app gets empty folders of its own as its profile's local data and its temporary
    # folder: whatever the reporting library writes would land there, and both must stay empty.
    $sandbox = Join-Path $root 'artifacts\error-report-sandbox'
    if (Test-Path $sandbox) { Remove-Item $sandbox -Recurse -Force }
    $sandboxLocal = (New-Item -ItemType Directory -Path (Join-Path $sandbox 'local')).FullName
    $sandboxTemp = (New-Item -ItemType Directory -Path (Join-Path $sandbox 'temp')).FullName
    $reportFile = Join-Path $root 'artifacts\error-report-test.txt'
    if (Test-Path $reportFile) { Remove-Item $reportFile -Force }
    $exit = Invoke-App '--error-report-test', $reportFile -Environment @{ LOCALAPPDATA = $sandboxLocal; TEMP = $sandboxTemp; TMP = $sandboxTemp }
    if ($exit -ne 0 -or -not (Test-Path $reportFile)) {
        throw "SecReview.exe --error-report-test ended with '$exit'.$(Get-AppLog)"
    }
    $reports = Get-Content $reportFile -Raw
    foreach ($expected in 'System.InvalidOperationException', 'System.FormatException', 'System.AggregateException',
            'System.InvalidCastException', 'System.ArgumentException', 'System.NotSupportedException', '"check":"selftest.check"',
            "secreview@$Version", 'ended without closing down', 'Self-test feedback', 'firewall.enabled: Fail') {
        if (-not $reports.Contains($expected)) { throw "The error-report test output lacks '$expected'." }
    }

    # Each made-up bug once (four errors and the fixed message), and the feedback: the second
    # and third copy of a bug, in the same check or another, must not have been written.
    $events = [regex]::Matches($reports, '"type":"event"').Count
    $feedbacks = [regex]::Matches($reports, '"type":"feedback"').Count
    if ($events -ne 5 -or $feedbacks -ne 1) {
        throw "The error-report test wrote $events reports and $feedbacks feedback; 5 and 1 were expected."
    }

    $forbidden = [ordered]@{
        'the made-up secret'          = 'made-up-token-7c1f'
        'an error message'            = 'Self-test error:'
        'the computer name'           = $env:COMPUTERNAME
        'the profile path'            = $env:USERPROFILE.Replace('\', '\\')
        'the folder SecReview is in'  = $root.Replace('\', '\\')
        'the server name field'       = '"server_name"'
        'a device section'            = '"device"'
        'the time zone'               = 'timezone'
        'the time the app started'    = 'app_start_time'
        'a user id'                   = '"user":{"id"'
        'a user name field'           = '"username"'
        'an address of the PC'        = 'ip_address'
        'the list of modules'         = '"modules"'
        'the list of program files'   = 'debug_meta'
        'extra data'                  = '"extra"'
        'a trail of earlier events'   = '"breadcrumbs"'
        'a second check tag'          = 'selftest.other'
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
    $written = @(Get-ChildItem $sandbox -Recurse -File)
    if ($written.Count -gt 0) {
        throw "Reporting wrote to the user's folders, which it must not: $($written[0].FullName.Substring($sandbox.Length + 1))"
    }
    Write-Host "Error reports: $events made-up reports and $feedbacks feedback written to a file, none sent; no message, name, path, secret or device detail in them; nothing written to the profile."

    $exit = Invoke-App '--no-such-argument'
    if ($exit -ne 2) { throw "SecReview.exe with an unknown argument exited with '$exit', expected 2." }

    $global:LASTEXITCODE = 0
}

$files = Get-ChildItem $stage -Recurse -File
'Staged: {0} files, {1:N1} MB' -f $files.Count, (($files | Measure-Object Length -Sum).Sum / 1MB)

# The list is counted apart: it grows with the feed, not with SecReview.
$list = $files | Where-Object Name -eq 'known-malicious.idx'
$measured.StagedFolderMB = (($files | Where-Object Name -ne 'known-malicious.idx' | Measure-Object Length -Sum).Sum) / 1MB
$measured.WindowProgramMB = (Get-Item (Join-Path $stage 'SecReview.exe')).Length / 1MB
$measured.HelperProgramMB = (Get-Item (Join-Path $stage 'SecReviewCli.exe')).Length / 1MB
if ($list) { $measured.MaliciousListMB = $list.Length / 1MB }

if ($Installer) {
    # The setup program: the staged folder, packed. Compiled here, never run here.
    $installerOut = Join-Path $root 'artifacts\installer'
    if (Test-Path $installerOut) { Remove-Item $installerOut -Recurse -Force }

    # The folder was checked before the programs were tried out. Checked again here, so that
    # what is packed is exactly what was checked, whatever ran in between.
    Invoke-Step 'Check staged output again' {
        & (Join-Path $root 'scripts\check-stage.ps1') -Stage $stage -OursSigned:$Sign
    }
    Invoke-Step 'Build the setup program' {
        & (Join-Path $root 'scripts\pack.ps1') -Stage $stage -Version $Version -Out $installerOut -Sign:$Sign
    }

    $setup = Get-Item (Join-Path $installerOut "SecReview-$Version-setup.exe")
    if ($Sign) {
        $signature = Get-AuthenticodeSignature -LiteralPath $setup.FullName
        if ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate) {
            throw "The setup program is not validly signed and timestamped ($($signature.Status))."
        }
        # By the publisher installed copies accept updates from, or they would refuse this one.
        $expected = ([xml] (Get-Content (Join-Path $root 'signing\Publisher.props') -Raw)).Project.PropertyGroup.PublisherSubject
        if ($signature.SignerCertificate.Subject -cne $expected) {
            throw "The setup program is signed by '$($signature.SignerCertificate.Subject)', not by the publisher in signing\Publisher.props."
        }
    }
    'Setup: {0}, {1:N1} MB, SHA-256 {2}' -f $setup.Name, ($setup.Length / 1MB), (Get-FileHash -LiteralPath $setup.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $measured.SetupProgramMB = $setup.Length / 1MB
}

# Size, start-up and scan time, and the icon's idle use, against scripts\budgets.psd1.
Invoke-Step 'Check budgets' { & (Join-Path $root 'scripts\check-budgets.ps1') -Measured $measured }
