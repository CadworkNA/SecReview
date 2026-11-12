#requires -Version 7.0
# Installs, upgrades and uninstalls SecReview and checks what each step leaves on the PC.
#
# This changes the machine it runs on, so it runs on GitHub's own disposable build machines
# only and refuses anywhere else.
#
#   scripts\test-install.ps1 -Setup artifacts\installer\SecReview-1.2.3-setup.exe -Stage artifacts\stage -Version 1.2.3
#   add -Signed for a signed build: the installed programs and the uninstaller must then be signed
param(
    [Parameter(Mandatory)] [string] $Setup,
    [Parameter(Mandatory)] [string] $Stage,
    [Parameter(Mandatory)] [string] $Version,
    [switch] $Signed
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This script installs and removes software. It is for GitHub-hosted, disposable build machines only.'
}

$root = Split-Path $PSScriptRoot -Parent
$setupPath = (Resolve-Path -LiteralPath $Setup).Path
$stagePath = (Resolve-Path -LiteralPath $Stage).Path.TrimEnd('\')
$app = Join-Path $env:ProgramFiles 'SecReview'
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9133D268-5237-4719-B107-00C0C086FCDE}_is1'
$shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\SecReview.lnk'
# Where the installed programs keep this user's settings and results: the real place.
$data = Join-Path $env:LOCALAPPDATA 'SecReview'
$work = Join-Path $root 'artifacts\install-test'
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Path $work | Out-Null

function Assert([bool] $condition, [string] $message) {
    if (-not $condition) { throw "Install test: $message" }
}

function Get-RunValue {
    (Get-Item -LiteralPath $runKey).GetValue('SecReview')
}

function Get-Running {
    @(Get-Process -Name 'SecReview', 'SecReviewCli' -ErrorAction SilentlyContinue)
}

# Runs a setup program without any window and returns its exit code.
function Invoke-Setup([string] $path, [string] $name, [string[]] $more = @()) {
    $log = Join-Path $work "$name.log"
    $arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$log`"") + $more
    (Start-Process -FilePath $path -ArgumentList $arguments -Wait -PassThru).ExitCode
}

function Assert-Setup([string] $path, [string] $name, [string[]] $more = @()) {
    $exit = Invoke-Setup $path $name $more
    if ($exit -ne 0) {
        $log = Join-Path $work "$name.log"
        $tail = if (Test-Path $log) { (Get-Content $log -Tail 40) -join "`n" } else { '(no log)' }
        throw "Install test: $name ended with $exit.`n$tail"
    }
}

function Start-Installed([string[]] $arguments) {
    $start = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $app 'SecReview.exe'))
    $start.UseShellExecute = $false
    foreach ($argument in $arguments) { $start.ArgumentList.Add($argument) }
    [System.Diagnostics.Process]::Start($start)
}

# Who may change the installed programs: Windows itself and administrators, nobody else.
$mayChange = @(
    'S-1-5-18'                                                       # SYSTEM
    'S-1-5-32-544'                                                   # Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
    'S-1-3-0'                                                        # "whoever creates a file here", which only the above can
)
# Any right that changes a file or folder: write, append, write attributes, delete, change
# permissions or owner, and the generic forms of "write" and "everything".
$changes = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000

function Assert-OnlyAdministratorsCanChange([string] $path) {
    $acl = Get-Acl -LiteralPath $path
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    Assert ($owner -in $mayChange) "$path is owned by $owner."
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $canChange = $rule.AccessControlType -eq 'Allow' -and (([int] $rule.FileSystemRights) -band $changes) -ne 0
        Assert (-not ($canChange -and $rule.IdentityReference.Value -notin $mayChange)) "$path can be changed by $($rule.IdentityReference.Value)."
    }
}

function Assert-Installed([string] $version, [bool] $autostart) {
    # Every staged file, byte for byte, and nothing else but the uninstaller.
    $staged = Get-ChildItem $stagePath -Recurse -File
    foreach ($file in $staged) {
        $relative = $file.FullName.Substring($stagePath.Length + 1)
        $installed = Join-Path $app $relative
        Assert (Test-Path -LiteralPath $installed) "$relative is not installed."
        Assert ((Get-FileHash -LiteralPath $installed).Hash -eq (Get-FileHash -LiteralPath $file.FullName).Hash) "$relative differs from what was staged."
    }
    $extra = @(Get-ChildItem $app -Recurse -File | Where-Object {
        $relative = $_.FullName.Substring($app.Length + 1)
        -not (Test-Path -LiteralPath (Join-Path $stagePath $relative)) -and $relative -notmatch '^unins\d{3}\.(exe|dat|msg)$'
    })
    Assert ($extra.Count -eq 0) "unexpected files in the install folder: $($extra.Name -join ', ')"

    $entry = Get-ItemProperty -LiteralPath $uninstallKey -ErrorAction SilentlyContinue
    Assert ($null -ne $entry) 'no entry in "Installed apps".'
    Assert ($entry.DisplayVersion -eq $version) "installed version is '$($entry.DisplayVersion)', expected '$version'."
    Assert ($entry.DisplayName -eq 'SecReview') "the entry is named '$($entry.DisplayName)'."
    Assert (Test-Path -LiteralPath $shortcut) 'no Start menu shortcut.'

    $expected = if ($autostart) { "`"$app\SecReview.exe`" --tray" } else { $null }
    Assert ((Get-RunValue) -eq $expected) "the sign-in entry is '$(Get-RunValue)', expected '$expected'."

    # An ordinary user must not be able to change the programs: the administrator checks run
    # the helper from here with administrator rights.
    foreach ($path in $app, (Join-Path $app 'SecReviewCli.exe'), (Join-Path $app 'SecReview.exe'), (Join-Path $app 'licenses')) {
        Assert-OnlyAdministratorsCanChange $path
    }
}

# --- 0. Setup installs into Program Files and refuses any other folder.
Assert (-not (Test-Path $app)) "$app exists before the test."
$elsewhere = Join-Path $env:SystemDrive 'SecReviewElsewhere'
$exit = Invoke-Setup $setupPath 'elsewhere' @("/DIR=`"$elsewhere`"")
Assert ($exit -ne 0) 'setup accepted another folder (/DIR).'
Assert (-not (Test-Path $elsewhere) -and -not (Test-Path $app)) 'a refused setup left files behind.'
Assert (-not (Test-Path -LiteralPath $uninstallKey) -and $null -eq (Get-RunValue)) 'a refused setup left registry entries behind.'
Write-Host "Setup refuses a folder outside Program Files (exit code $exit) and changes nothing."

# --- 1. A fresh install, the way a management tool runs it.
Assert-Setup $setupPath 'install'
Assert-Installed $Version $true
Assert ((Get-Running).Count -eq 0) 'a silent install started SecReview.'
Write-Host "Installed ${Version}: files match the staged output, sign-in entry and shortcut are there, only administrators can change the folder."

if ($Signed) {
    # What landed on the PC is signed and timestamped, by one publisher: both programs, the
    # uninstaller and the setup program.
    $subjects = foreach ($path in (Join-Path $app 'SecReview.exe'), (Join-Path $app 'SecReviewCli.exe'), (Join-Path $app 'unins000.exe'), $setupPath) {
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        Assert ($signature.Status -eq 'Valid') "$path is not validly signed ($($signature.Status))."
        Assert ($null -ne $signature.TimeStamperCertificate) "the signature on $path has no timestamp."
        $signature.SignerCertificate.Subject
    }
    Assert (@($subjects | Select-Object -Unique).Count -eq 1) "the files are signed by different publishers: $($subjects -join ' | ')"
    Write-Host "Signed and timestamped, all by: $($subjects[0])"
}

# The installed programs work from where they are, with their files in the user's profile.
$report = Join-Path $work 'installed.report.json'
& (Join-Path $app 'SecReviewCli.exe') --report $report | Out-Null
Assert ($LASTEXITCODE -eq 0 -and (Test-Path $report)) "the installed SecReviewCli --report ended with $LASTEXITCODE."
$checks = (Get-Content $report -Raw | ConvertFrom-Json).checks
Assert ($checks.Count -gt 50) "the installed report has $($checks.Count) checks."
$window = Start-Installed '--smoke-test'
Assert ($window.WaitForExit(120000)) 'the installed window did not close.'
Assert ($window.ExitCode -eq 0) "the installed SecReview --smoke-test ended with $($window.ExitCode)."
Assert (Test-Path (Join-Path $data 'results.json')) "the installed window left no results in $data."
Assert ((Get-Running).Count -eq 0) 'the window''s automated run left a SecReview process behind (it must not start the notification-area icon).'
Write-Host "Installed programs: report with $($checks.Count) checks, window shown and closed, results kept in the user's profile."

# --- 2. An upgrade while the notification-area icon is running, leaving out the sign-in entry.
# The same programs packed as a later version: this tests the setup program, not the programs.
# To see that it really replaces and cleans up, one installed file is damaged and a file that
# no version ships is put next to the programs, as an earlier version might have left it.
$numbers = [version] (($Version -split '-', 2)[0])
$later = '{0}.{1}.{2}' -f $numbers.Major, $numbers.Minor, ($numbers.Build + 1)
$iscc = & (Join-Path $PSScriptRoot 'ensure-inno.ps1')
& $iscc /Q "/DAppVersion=$later" "/DFileVersion=$later.0" "/DStage=$stagePath" "/DOutputFolder=$work" (Join-Path $root 'installer\SecReview.iss')
Assert ($LASTEXITCODE -eq 0) "building the later setup program failed ($LASTEXITCODE)."
$laterSetup = Join-Path $work "SecReview-$later-setup.exe"

Set-Content -LiteralPath (Join-Path $app 'licenses\SecReview-LICENSE.txt') -Value 'damaged by the install test'
Set-Content -LiteralPath (Join-Path $app 'left-by-an-earlier-version.dll') -Value 'not a real library'
New-Item -ItemType Directory -Path (Join-Path $app 'old-folder') | Out-Null
Set-Content -LiteralPath (Join-Path $app 'old-folder\old.txt') -Value 'old'

$tray = Start-Installed '--tray'
Start-Sleep -Seconds 5
Assert (-not $tray.HasExited) "the installed notification-area icon ended by itself with $($tray.ExitCode)."
Assert-Setup $laterSetup 'upgrade' @('/MERGETASKS="!autostart"')
Assert ($tray.WaitForExit(15000)) 'the upgrade left the old notification-area icon running.'
Assert-Installed $later $false
Assert (-not (Test-Path (Join-Path $app 'old-folder'))) 'the upgrade left a folder of an earlier version.'
Write-Host "Upgraded to $later with the icon running: the icon was ended, the damaged file replaced, leftovers removed, sign-in entry removed as asked."

# --- 3. The sign-in entry comes back when asked for.
Assert-Setup $laterSetup 'repair' @('/TASKS="autostart"')
Assert-Installed $later $true

# --- 4. Uninstall, again with the icon running.
$tray = Start-Installed '--tray'
Start-Sleep -Seconds 5
Assert (-not $tray.HasExited) 'the notification-area icon did not stay up before the uninstall.'
$uninstaller = Join-Path $app 'unins000.exe'
Assert (Test-Path $uninstaller) 'there is no uninstaller.'
$process = Start-Process -FilePath $uninstaller -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
Assert ($process.ExitCode -eq 0) "the uninstaller ended with $($process.ExitCode)."
# The uninstaller finishes in a copy of itself; give that a moment.
foreach ($attempt in 1..60) {
    if (-not (Test-Path $app)) { break }
    Start-Sleep -Seconds 1
}
Assert (-not (Test-Path $app)) "the uninstall left files: $((Get-ChildItem $app -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 5).Name -join ', ')"
Assert ($null -eq (Get-RunValue)) 'the uninstall left the sign-in entry.'
Assert (-not (Test-Path -LiteralPath $uninstallKey)) 'the uninstall left the entry in "Installed apps".'
Assert (-not (Test-Path -LiteralPath $shortcut)) 'the uninstall left the Start menu shortcut.'
Assert ((Get-Running).Count -eq 0) 'the uninstall left SecReview running.'
Assert (Test-Path (Join-Path $data 'results.json')) "the uninstall removed the user's own data in $data."
Write-Host 'Uninstalled with the icon running: programs, sign-in entry, shortcut and the "Installed apps" entry are gone; the user''s settings and results are left.'
