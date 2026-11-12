# Building SecReview

## Requirements

- Windows 10 22H2 or Windows 11, x64
- .NET SDK **11.0.100** exactly (`global.json` pins it; the apps target .NET 10)
- Visual Studio 2022 or 2026 with **Desktop development with C++** (Native AOT uses its linker)
- Network access to nuget.org on the first build

## Build

```
.\build.ps1                    # restore, build, test, publish
.\build.ps1 -Version 1.2.3     # stamp a semantic version
.\build.ps1 -NoPublish         # stop after the unit tests
.\build.ps1 -LocalCache        # keep NuGet's caches inside the repo (.nuget\)
.\build.ps1 -Locked            # restore in locked mode, as CI does
```

Output: `artifacts\stage` (what ships) and `artifacts\symbols`.

Run the tests again without rebuilding:

```
dotnet test --solution SecReview.slnx -c Release --no-build
```

## Layout

| Path | Contents |
|------|----------|
| `src/SecReview.Core` | Everything without UI: checks, rules, readers, command-line parsing. All logic lives here and is unit-tested |
| `src/SecReview.Cli` | `SecReviewCli.exe` (Native AOT console). The only binary that ever runs elevated |
| `tests/SecReview.Core.Tests` | MSTest unit tests for `Core` |
| `scripts/` | Build helpers: `check-lockfiles.ps1`, `allowed-packages.txt` |
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

If restore fails with **NU3034** after nuget.org rotates its signing certificate, run
`dotnet nuget trust sync nuget.org` and commit the updated fingerprints in `nuget.config`.

## Conventions

- Warnings are errors, including code-style and analyzer warnings.
- GitHub Actions are pinned by full commit SHA with the version as a comment.
- Pull request titles use a conventional prefix (`feat:`, `fix:`, `docs:`, `ci:`,
  `build(deps):`, `chore:`); they become the release notes. See [CONTRIBUTING.md](CONTRIBUTING.md).
