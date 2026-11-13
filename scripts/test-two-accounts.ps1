#requires -Version 7.0
# Runs the tests that need two more accounts on the machine: a standard user and an
# administrator. The administrator pipe must refuse the first and let in the second
# (tests\SecReview.Core.Tests\Elevation\TwoAccountPipeTests.cs).
#
# This adds accounts to the machine it runs on, so it runs on GitHub's own disposable build
# machines only and refuses anywhere else. The tests must have been built (build.ps1).
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This script adds accounts to the machine. It is for GitHub-hosted, disposable build machines only.'
}

$root = Split-Path $PSScriptRoot -Parent
$standardUser = 'srtest-user'
$otherAdministrator = 'srtest-admin'

# One random password for both, used only for this run: 24 characters from four kinds.
$kinds = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%+-=?@'
$characters = foreach ($i in 0..23) {
    $kind = $kinds[$i % $kinds.Count]
    $kind[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($kind.Length)]
}
$password = -join $characters
$secure = ConvertTo-SecureString $password -AsPlainText -Force

try {
    foreach ($name in $standardUser, $otherAdministrator) {
        New-LocalUser -Name $name -Password $secure -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
        Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $name
    }
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544') -Member $otherAdministrator
    "Accounts: $standardUser (standard user), $otherAdministrator (administrator)."

    $env:SECREVIEW_TEST_STANDARD_USER = $standardUser
    $env:SECREVIEW_TEST_OTHER_ADMINISTRATOR = $otherAdministrator
    $env:SECREVIEW_TEST_PASSWORD = $password
    $tests = Join-Path $root 'tests\SecReview.Core.Tests\SecReview.Core.Tests.csproj'
    dotnet test --project $tests -c Release --no-build --filter 'TestCategory=TwoAccounts' --minimum-expected-tests 1
    if ($LASTEXITCODE) { throw "The two-account tests failed ($LASTEXITCODE)." }
} finally {
    Remove-Item Env:SECREVIEW_TEST_PASSWORD -ErrorAction SilentlyContinue
    foreach ($name in $standardUser, $otherAdministrator) {
        Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
    }
}
