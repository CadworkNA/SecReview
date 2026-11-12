# Fails if a project has no packages.lock.json, or if any lock file names a package that is not
# in scripts\allowed-packages.txt. A new dependency, direct or transitive, therefore needs a
# reviewed change to that list.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

# A line is a package id, optionally followed by "only:<project>" for a package that may
# appear in that one project's lock file and nowhere else.
$allowedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$onlyIn = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($line in Get-Content (Join-Path $PSScriptRoot 'allowed-packages.txt')) {
    $line = $line.Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }
    $parts = $line -split '\s+'
    if ($parts.Count -eq 1) {
        [void] $allowedSet.Add($parts[0])
    } elseif ($parts.Count -eq 2 -and $parts[1].StartsWith('only:') -and $parts[1].Length -gt 5) {
        [void] $allowedSet.Add($parts[0])
        $onlyIn[$parts[0]] = $parts[1].Substring(5)
    } else {
        Write-Host "::error::allowed-packages.txt: cannot read the line '$line'."
        exit 1
    }
}

$problems = @()
# Match on the path inside the repo, so a checkout under a folder named "obj" or "artifacts"
# does not hide every project.
$projects = @(Get-ChildItem $root -Recurse -Filter *.csproj | Where-Object {
    $relative = $_.FullName.Substring($root.Length)
    $relative -notmatch '\\(bin|obj|artifacts|\.nuget|\.dotnet)\\'
})

if ($projects.Count -eq 0) {
    Write-Host "::error::No project files found under $root; nothing was checked."
    exit 1
}

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
            } elseif ($onlyIn.ContainsKey($package.Name) -and $project.BaseName -ne $onlyIn[$package.Name]) {
                $problems += "$($project.Name): '$($package.Name)' is allowed in $($onlyIn[$package.Name]) only."
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
