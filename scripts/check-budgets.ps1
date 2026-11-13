# Holds what a build measured against scripts\budgets.psd1: sizes, start-up and scan times, and
# what the notification-area icon uses while it waits. Fails when a measurement is over its
# limit, or when one has no limit (so a new measurement cannot go unjudged).
#
#   scripts\check-budgets.ps1 -Measured @{ StagedFolderMB = 84.4; ScanMs = 3300 }
#
# A limit that was not measured in this build (the setup program without -Installer, the
# icon anywhere but on a build machine) is listed as such and does not fail the build.
# Writes artifacts\budgets.json, and a table to the job summary on GitHub.
param(
    [Parameter(Mandatory)] [System.Collections.IDictionary] $Measured
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$budgets = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'budgets.psd1')

$unknown = @($Measured.Keys | Where-Object { -not $budgets.ContainsKey($_) })
if ($unknown) { throw "Measured without a limit in scripts\budgets.psd1: $($unknown -join ', ')." }

$rows = foreach ($name in ($budgets.Keys | Sort-Object)) {
    $limit = [double] $budgets[$name]
    if ($Measured.Contains($name)) {
        $value = [Math]::Round([double] $Measured[$name], 1)
        [pscustomobject]@{ Name = $name; Measured = $value; Limit = $limit; Over = $value -gt $limit }
    } else {
        [pscustomobject]@{ Name = $name; Measured = $null; Limit = $limit; Over = $false }
    }
}

foreach ($row in $rows) {
    $shown = if ($null -eq $row.Measured) { 'not measured here' } else { '{0:N1}' -f $row.Measured }
    $mark = if ($row.Over) { '  OVER' } else { '' }
    Write-Host ('  {0,-16} {1,18}   limit {2,8:N0}{3}' -f $row.Name, $shown, $row.Limit, $mark)
}

$artifacts = Join-Path $root 'artifacts'
if (Test-Path $artifacts) {
    $rows | Select-Object Name, Measured, Limit | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $artifacts 'budgets.json') -Encoding utf8
}

if ($env:GITHUB_STEP_SUMMARY) {
    $table = @('### Budgets', '', '| What | Measured | Limit |', '|---|--:|--:|')
    $table += $rows | ForEach-Object {
        $shown = if ($null -eq $_.Measured) { 'not measured' } else { '{0:N1}' -f $_.Measured }
        '| {0} | {1}{2} | {3:N0} |' -f $_.Name, $shown, $(if ($_.Over) { ' **over**' } else { '' }), $_.Limit
    }
    $table -join "`n" | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Encoding utf8
}

$over = @($rows | Where-Object Over)
if ($over) {
    $over | ForEach-Object { Write-Host "::error::$($_.Name) is $($_.Measured), over its limit of $($_.Limit) (scripts/budgets.psd1)." }
    exit 1
}

Write-Host "Budgets: $(@($rows | Where-Object { $null -ne $_.Measured }).Count) of $($rows.Count) measured, none over its limit."
exit 0
