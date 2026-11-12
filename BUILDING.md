# Building SecReview

## Requirements

- Windows 10 22H2 or Windows 11, x64
- .NET SDK **11.0.100** exactly (`global.json` pins it; the apps target .NET 10)
- Visual Studio 2022 or 2026 with **Desktop development with C++** (Native AOT uses its linker)
- Network access to nuget.org on the first build

## Build

Run `build.ps1` from PowerShell 7 (`pwsh`). Its header lists every switch; the common ones:

```
.\build.ps1                    # restore, build, test, publish
.\build.ps1 -Version 1.2.3     # stamp a semantic version
.\build.ps1 -NoPublish         # no Native AOT publish (quick loop)
.\build.ps1 -NoTests           # skip the unit tests
.\build.ps1 -LocalCache        # keep NuGet's caches inside the repo (.nuget\)
.\build.ps1 -Locked            # restore in locked mode, as CI does
```

Output: `artifacts\stage` (what ships) and `artifacts\symbols`. The script ends with a smoke test
that opens the app window for a moment.

Run the tests again without rebuilding:

```
dotnet test --solution SecReview.slnx -c Release --no-build
```

## Layout

| Path | Contents |
|------|----------|
| `src/SecReview.Core` | Everything without UI: checks, rules, readers, command-line parsing. All logic lives here and is unit-tested |
| `src/SecReview.Cli` | `SecReviewCli.exe` (Native AOT console). The only binary that ever runs elevated |
| `src/SecReview.App` | `SecReview.exe` (WinUI 3, Native AOT, unpackaged, Windows App SDK copied next to it). `Program.Main` picks the role before XAML starts |
| `tests/SecReview.Core.Tests` | MSTest unit tests for `Core` |
| `scripts/` | Build checks: `check-lockfiles.ps1` with `allowed-packages.txt` (package allow-list), `check-source-text.ps1` (no hidden or bidirectional control characters in the repo), `check-stage.ps1` with `stage-files.txt` (what ships: every binary not ours must be signed by Microsoft and chain to a pinned root, every other file must match its recorded hash) |
| `build.ps1` | The one entry point; CI runs the same script |
| `.github/workflows/build.yml` | CI: locked restore, build, tests, publish, smoke test |

## Dependencies

The build is strict about what it downloads:

- **One source.** `nuget.config` allows nuget.org only, maps package ids to it by pattern, and
  requires nuget.org's repository signature on every package.
- **Exact versions.** `Directory.Packages.props` pins every package; `global.json` pins the SDK.
- **Lock files.** Each project commits `packages.lock.json`. CI restores with `--locked-mode`.
- **Allow-list.** `scripts/check-lockfiles.ps1` fails the build if a lock file names a package
  that is not in `scripts/allowed-packages.txt`.
- **Cooldown.** Take a new package version only once it is at least 7 days old (GitHub Actions:
  14 days). Dependabot is configured the same way.

To add or update a package: change `Directory.Packages.props`, run `.\build.ps1` (not `-Locked`)
so the lock files update, add any new id to `allowed-packages.txt`, and commit all of it together.
A package not published by Microsoft needs the maintainer's approval first.

To move to a new SDK: change `global.json`, rebuild so the lock files update, commit together.
Dependabot does not propose SDK updates for that reason.

The two Windows App SDK packages (`Microsoft.WindowsAppSDK.WinUI`, `.Runtime`) must always have
the same version. After changing them, the files that ship change too: run
`.\build.ps1 -UpdateStageList` and review the difference in `scripts\stage-files.txt`. Parts of
the SDK that SecReview does not use (WebView2, the design-time library, the restart helper) are
left out of the staged output; the list is in `build.ps1`.

If restore fails with **NU3034** after nuget.org rotates its signing certificate, run
`dotnet nuget trust sync nuget.org` and commit the updated fingerprints in `nuget.config`.

## Conventions

- Warnings are errors, including code-style and analyzer warnings.
- GitHub Actions are pinned by full commit SHA with the version as a comment.
- Pull request titles use a conventional prefix and become the release notes; the list is in
  [CONTRIBUTING.md](CONTRIBUTING.md).
