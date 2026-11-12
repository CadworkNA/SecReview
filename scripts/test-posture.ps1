#requires -Version 7.0
# Proves that the checks fail, for the right reason, when a setting really is weak: sets a few
# settings of this machine to a good state, reads them with SecReviewCli, weakens them, and
# reads them again.
#
# This weakens the machine it runs on, creates a local user account and writes a made-up token
# into that account's profile. It runs on GitHub's own disposable build machines only and
# refuses anywhere else. Never run it, or anything like it, on a real PC.
#
#   scripts\test-posture.ps1 -Cli "$env:ProgramFiles\SecReview\SecReviewCli.exe"
param([Parameter(Mandatory)] [string] $Cli)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This script weakens security settings. It is for GitHub-hosted, disposable build machines only.'
}

$cliPath = (Resolve-Path -LiteralPath $Cli).Path
$work = Join-Path (Split-Path $PSScriptRoot -Parent) 'artifacts\posture-test'
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Path $work | Out-Null

$terminalServer = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$listener = "$terminalServer\WinStations\RDP-Tcp"
$wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$explorerPolicy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
# Made up for this test; no part of it may appear in a report.
$token = 'npm_MadeUpForTheBuild0123456789abcdefghij'

function Set-Number([string] $key, [string] $name, [int] $value) {
    if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -LiteralPath $key -Name $name -Value $value -Type DWord
}

function Set-GoodState {
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
    Set-Number $terminalServer 'fDenyTSConnections' 1
    Set-Number $listener 'UserAuthentication' 1
    Set-Number $wdigest 'UseLogonCredential' 0
    Set-Number $explorerPolicy 'NoDriveTypeAutoRun' 255
}

function ConvertTo-Scan([string] $file) {
    $text = Get-Content -LiteralPath $file -Raw
    $report = $text | ConvertFrom-Json
    $byId = @{}
    foreach ($check in $report.checks) { $byId[$check.id] = $check }
    [pscustomobject]@{ Checks = $byId; Text = $text; Elevated = $report.elevated }
}

# One scan as this build's own account, which is an administrator.
function Read-Checks([string] $name) {
    $file = Join-Path $work "$name.report.json"
    & $cliPath --report $file | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $file)) { throw "Posture test: SecReviewCli --report ended with $LASTEXITCODE." }
    ConvertTo-Scan $file
}

function Assert-Status($scan, [string] $id, [string] $status) {
    $check = $scan.Checks[$id]
    if (-not $check) { throw "Posture test: the report has no check '$id'." }
    if ($check.status -ne $status) {
        throw "Posture test: $id is $($check.status) ('$($check.summary)'), expected $status."
    }
    Write-Host ("  {0,-22} {1,-5} {2}" -f $id, $check.status, $check.summary)
    $check
}

function Assert-NothingPrivate($scan, [string[]] $names) {
    # Any stretch of the token, not only the whole of it.
    foreach ($start in 0, 4, 12, ($token.Length - 10)) {
        if ($scan.Text.Contains($token.Substring($start, 10))) { throw 'Posture test: the report contains part of the token.' }
    }
    foreach ($name in $names) {
        if ($scan.Text -match [regex]::Escape($name)) { throw 'Posture test: the report names the user or the computer.' }
    }
}

try {
    # --- Settings of the PC. A good state first, so what follows is known to come from the change.
    Set-GoodState
    Write-Host 'With the settings in order:'
    $before = Read-Checks 'before'
    foreach ($id in 'firewall.enabled', 'remote.desktop', 'harden.wdigest', 'harden.autoplay') {
        Assert-Status $before $id 'Pass' | Out-Null
    }

    Set-NetFirewallProfile -Profile Public -Enabled False
    Set-Number $terminalServer 'fDenyTSConnections' 0
    Set-Number $listener 'UserAuthentication' 0
    Set-Number $wdigest 'UseLogonCredential' 1
    Remove-ItemProperty -LiteralPath $explorerPolicy -Name 'NoDriveTypeAutoRun'

    Write-Host 'With the settings weakened:'
    $after = Read-Checks 'after'

    $firewall = Assert-Status $after 'firewall.enabled' 'Fail'
    $public = @($firewall.findings | Where-Object { $_.item -match 'Public' })
    if ($public.Count -ne 1 -or $public[0].found -notmatch 'Off') { throw "Posture test: the firewall check does not name the Public network as off: $($firewall.findings | ConvertTo-Json -Compress)" }
    $others = @($firewall.findings | Where-Object { $_.item -match 'Domain|Private' -and $_.found -match 'Off' })
    if ($others.Count -ne 0) { throw 'Posture test: the firewall check blames a network that is on.' }

    $desktop = Assert-Status $after 'remote.desktop' 'Fail'
    $nla = @($desktop.findings | Where-Object { $_.item -eq 'Network Level Authentication' })
    if ($nla.Count -ne 1 -or $nla[0].found -ne 'Not required') { throw "Posture test: the Remote Desktop check does not say that Network Level Authentication is not required: $($desktop.findings | ConvertTo-Json -Compress)" }

    Assert-Status $after 'harden.wdigest' 'Fail' | Out-Null
    $autoplay = Assert-Status $after 'harden.autoplay' 'Fail'
    if (($autoplay.findings | ConvertTo-Json -Compress) -notmatch 'Not configured') { throw 'Posture test: the AutoPlay check does not say the setting is not configured.' }

    # With administrator rights SecReview does not read a user's own files, and says so
    # instead of passing.
    $skipped = Assert-Status $after 'sc.npm.credentials' 'Error'
    if ($skipped.summary -notmatch 'administrator') { throw 'Posture test: the npm check does not say why it was not run.' }
    if (-not $after.Elevated) { throw 'Posture test: the report does not say it was made with administrator rights.' }
    Assert-NothingPrivate $after @($env:USERNAME, $env:COMPUTERNAME)

    # --- A user's own settings, read as an ordinary user. This build's account is an
    # administrator, so an ordinary account is made for it; the machine is thrown away after.
    $user = 'secreview-test'
    $password = -join ((1..20 | ForEach-Object { [char] (Get-Random -Minimum 97 -Maximum 123) }) + 'A', '7', '!')
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser -Name $user -Password $secure -AccountNeverExpires -Description 'SecReview build test' | Out-Null
    Add-LocalGroupMember -Group 'Users' -Member $user
    $credential = [pscredential]::new("$env:COMPUTERNAME\$user", $secure)

    # Where that account can write its report and this one can read it.
    $shared = Join-Path $env:PUBLIC 'secreview-posture'
    New-Item -ItemType Directory -Path $shared -Force | Out-Null
    & icacls.exe $shared /grant "${user}:(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE) { throw "Posture test: granting the test account access failed ($LASTEXITCODE)." }

    function Read-ChecksAsUser([string] $name) {
        $file = Join-Path $shared "$name.report.json"
        $process = Start-Process -FilePath $cliPath -ArgumentList '--report', "`"$file`"" -Credential $credential -LoadUserProfile `
            -WorkingDirectory $shared -Wait -PassThru
        if ($process.ExitCode -ne 0 -or -not (Test-Path $file)) { throw "Posture test: SecReviewCli --report as an ordinary user ended with $($process.ExitCode)." }
        ConvertTo-Scan $file
    }

    Write-Host 'As an ordinary user, without a token:'
    $userBefore = Read-ChecksAsUser 'user-before'
    if ($userBefore.Elevated) { throw 'Posture test: the ordinary user''s report says it had administrator rights.' }
    if ($userBefore.Checks['sc.npm.credentials'].status -in 'Fail', 'Error') {
        throw "Posture test: sc.npm.credentials is $($userBefore.Checks['sc.npm.credentials'].status) before any token was written."
    }
    $asking = @($userBefore.Checks.Values | Where-Object status -eq 'NeedsAdmin').Count
    if ($asking -eq 0) { throw 'Posture test: without administrator rights some checks must say they need them.' }
    Write-Host "  $asking checks say they need administrator rights; none of them passes instead."

    # The first run made the account's profile; the token goes where npm keeps it.
    $profileFolder = (Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like "*\$user" } | Select-Object -First 1).LocalPath
    if (-not $profileFolder -or -not (Test-Path -LiteralPath $profileFolder)) { throw 'Posture test: the test account has no profile folder.' }
    $npmrc = Join-Path $profileFolder '.npmrc'
    Set-Content -LiteralPath $npmrc -Value "registry=https://registry.npmjs.org/`n//registry.npmjs.org/:_authToken=$token`n" -NoNewline
    & icacls.exe $npmrc /grant "${user}:R" | Out-Null

    Write-Host 'As an ordinary user, with a token in .npmrc:'
    $userAfter = Read-ChecksAsUser 'user-after'
    $npm = Assert-Status $userAfter 'sc.npm.credentials' 'Fail'
    if (($npm.findings | ConvertTo-Json -Compress) -notmatch '\.npmrc') { throw 'Posture test: the npm check does not name the file the token is in.' }
    Assert-NothingPrivate $userAfter @($user, $env:COMPUTERNAME)

    Write-Host 'Five weakened settings, five checks that say so, each for its own reason. With administrator rights the user''s files are not read, and the report says so. No part of the token and no name of a user or the computer is in any report.'
} finally {
    # The machine is thrown away after the build; this is tidiness, also when a check above failed.
    Set-GoodState
}
