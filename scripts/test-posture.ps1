#requires -Version 7.0
# Proves that the checks fail, for the right reason, when a setting really is weak: sets a few
# settings of this machine to a good state, reads them with the built SecReviewCli, weakens
# them, and reads them again.
#
# This weakens the machine it runs on. It runs on disposable build machines only and refuses
# anywhere else. Never run it, or anything like it, on a real PC.
#
#   scripts\test-posture.ps1 -Stage artifacts\stage
param([Parameter(Mandatory)] [string] $Stage)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true') {
    throw 'This script weakens security settings. It is for disposable build machines only.'
}

$cli = Join-Path (Resolve-Path -LiteralPath $Stage).Path 'SecReviewCli.exe'
$work = Join-Path (Split-Path $PSScriptRoot -Parent) 'artifacts\posture-test'
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Path $work | Out-Null

$terminalServer = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$listener = "$terminalServer\WinStations\RDP-Tcp"
$wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$explorerPolicy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$npmrc = Join-Path $env:USERPROFILE '.npmrc'
# Made up for this test; it must never appear in a report.
$token = 'npm_MadeUpForTheBuild0123456789abcdefghij'

function Set-Number([string] $key, [string] $name, [int] $value) {
    if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -LiteralPath $key -Name $name -Value $value -Type DWord
}

# The checks of one scan, by identifier, and the report's text.
function Read-Checks([string] $name) {
    $file = Join-Path $work "$name.report.json"
    & $cli --report $file | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $file)) { throw "Posture test: SecReviewCli --report ended with $LASTEXITCODE." }
    $text = Get-Content $file -Raw
    $byId = @{}
    foreach ($check in ($text | ConvertFrom-Json).checks) { $byId[$check.id] = $check }
    [pscustomobject]@{ Checks = $byId; Text = $text }
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

# --- A good state first, so what follows is known to come from the change.
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
Set-Number $terminalServer 'fDenyTSConnections' 1
Set-Number $wdigest 'UseLogonCredential' 0
Set-Number $explorerPolicy 'NoDriveTypeAutoRun' 255
if (Test-Path -LiteralPath $npmrc) { Remove-Item -LiteralPath $npmrc -Force }

Write-Host 'With the settings in order:'
$before = Read-Checks 'before'
foreach ($id in 'firewall.enabled', 'remote.desktop', 'harden.wdigest', 'harden.autoplay') {
    Assert-Status $before $id 'Pass' | Out-Null
}
if ($before.Checks['sc.npm.credentials'].status -eq 'Fail') { throw 'Posture test: sc.npm.credentials fails before any token was written.' }

# --- Weakened.
Set-NetFirewallProfile -Profile Public -Enabled False
Set-Number $terminalServer 'fDenyTSConnections' 0
Set-Number $listener 'UserAuthentication' 0
Set-Number $wdigest 'UseLogonCredential' 1
Remove-ItemProperty -LiteralPath $explorerPolicy -Name 'NoDriveTypeAutoRun'
Set-Content -LiteralPath $npmrc -Value "registry=https://registry.npmjs.org/`n//registry.npmjs.org/:_authToken=$token`n" -NoNewline

Write-Host 'With the settings weakened:'
$after = Read-Checks 'after'

$firewall = Assert-Status $after 'firewall.enabled' 'Fail'
$public = @($firewall.findings | Where-Object { $_.item -match 'Public' })
if ($public.Count -ne 1 -or $public[0].found -notmatch 'Off') { throw "Posture test: the firewall check does not name the Public network as off: $($firewall.findings | ConvertTo-Json -Compress)" }
$others = @($firewall.findings | Where-Object { $_.item -match 'Domain|Private' -and $_.found -match 'Off' })
if ($others.Count -ne 0) { throw 'Posture test: the firewall check blames a network that is on.' }

$desktop = Assert-Status $after 'remote.desktop' 'Fail'
if (($desktop.findings | ConvertTo-Json -Compress) -notmatch 'Network Level Authentication') { throw 'Posture test: the Remote Desktop check does not say that Network Level Authentication is off.' }

Assert-Status $after 'harden.wdigest' 'Fail' | Out-Null
$autoplay = Assert-Status $after 'harden.autoplay' 'Fail'
if (($autoplay.findings | ConvertTo-Json -Compress) -notmatch 'Not configured') { throw 'Posture test: the AutoPlay check does not say the setting is not configured.' }

$npm = Assert-Status $after 'sc.npm.credentials' 'Fail'
if (($npm.findings | ConvertTo-Json -Compress) -notmatch '\.npmrc') { throw 'Posture test: the npm check does not name the file the token is in.' }
if ($after.Text.Contains($token) -or $after.Text.Contains($token.Substring(4, 12))) { throw 'Posture test: the report contains the token.' }
if ($after.Text -match [regex]::Escape($env:USERNAME) -or $after.Text -match [regex]::Escape($env:COMPUTERNAME)) {
    throw 'Posture test: the report names the user or the computer.'
}

# --- Back to the good state. The machine is thrown away after the build; this is tidiness.
Set-NetFirewallProfile -Profile Public -Enabled True
Set-Number $terminalServer 'fDenyTSConnections' 1
Set-Number $listener 'UserAuthentication' 1
Set-Number $wdigest 'UseLogonCredential' 0
Set-Number $explorerPolicy 'NoDriveTypeAutoRun' 255
Remove-Item -LiteralPath $npmrc -Force

Write-Host 'Five weakened settings, five checks that say so, each for its own reason; the token and the names of user and computer are not in the report.'
