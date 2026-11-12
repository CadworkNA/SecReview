# Fails if a project has no packages.lock.json, or if any lock file names a package that is not
# in scripts\allowed-packages.txt. A new dependency, direct or transitive, therefore needs a
# reviewed change to that list.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

$allowed = Get-Content (Join-Path $PSScriptRoot 'allowed-packages.txt') |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') }
$allowedSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]] $allowed, [System.StringComparer]::OrdinalIgnoreCase)

$problems = @()
$projects = Get-ChildItem $root -Recurse -Filter *.csproj |
    Where-Object { $_.FullName -notmatch '\\(bin|obj|artifacts|\.nuget)\\' }

foreach ($project in $projects) {
    $lockFile = Join-Path $project.DirectoryName 'packages.lock.json'
    if (-not (Test-Path $lockFile)) {
        $problems += "$($project.Name): packages.lock.json is missing."
        continue
    }

    $lock = Get-Content $lockFile -Raw | ConvertFrom-Json
    foreach ($framework in $lock.dependencies.PSObject.Properties) {
        foreach ($package in $framework.Value.PSObject.Properties) {
            if ($package.Value.type -eq 'Project') { continue }
            if (-not $allowedSet.Contains($package.Name)) {
                $problems += "$($project.Name): '$($package.Name)' is not in scripts\allowed-packages.txt."
            }
        }
    }
}

if ($problems) {
    $problems | Sort-Object -Unique | ForEach-Object { Write-Host "::error::$_" }
    exit 1
}

Write-Host "Lock files: $($projects.Count) projects, every package is on the allow-list."
exit 0
