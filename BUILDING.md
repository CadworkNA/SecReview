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
| `src/SecReview.Core/Checks` | The check model (`ICheck`, outcomes, findings), the runner (time limit and isolation per check) and, under `BuiltIn/`, the checks written in code |
| `src/SecReview.Core/Catalogue` | The wording of every check (`checks.en.json`: titles, why, fix steps, Settings link), embedded as data. Tests enforce completeness and length limits. Also the lists some checks compare against, each with the date it was verified: `windows-servicing.json` (end of security updates per Windows release) and `password-managers.json` (app names and browser-extension identifiers) |
| `src/SecReview.Core/Rules` and `rules/` | Checks written as data: `rules/*.json` (embedded at build time) and the engine that runs them. A rule names a registry value, service, account policy value, audit subcategory, user right or Microsoft Defender setting, what is expected, what it means when the value is absent, and the Microsoft page and date it was verified against. A rule file that does not hold together fails the load, and so the tests |
| `src/SecReview.Core/Config` | Readers for the settings files of developer tools: TOML, YAML, INI, Git's settings format, XML and Java-style properties. Each covers what settings files use and stops at the first thing it does not understand, with the line number: a file is read in full or not judged at all. Seeded mutation tests keep them from crashing or hanging |
| `src/SecReview.Core/SupplyChain` | The developer supply-chain checks, a folder per tool or topic (uv, pnpm, Scoop, npm, Yarn, pip, NuGet, Cargo, Go, Git, editors, AI agents and MCP servers, Docker, winget, Chocolatey, environment variables, stored credentials): release cooldowns, unsafe package sources, switched-off protections, secrets stored as plain text. No tool is ever run: versions come from files, and where none records one the result says so. A check does not apply when its tool is absent |
| `src/SecReview.Core/Malware` | Known-malicious package matching: the index format (compact, checksummed, searched in place), version ordering per registry, the reader for OSV advisories, and the places packages are looked for (global packages, Python environments, editor extensions, download caches). Names are compared first and a version is read only for a listed name; what is installed never leaves the PC |
| `src/SecReview.Core/Scanning` | Runs the catalogue and pairs results with wording; the display order and headline; the made-up results behind `--demo` |
| `src/SecReview.Core/Reporting` | The report written by `SecReviewCli --report` |
| `src/SecReview.Core/Diagnostics` | `--diagnose`, the local error log (size-capped, names removed) and where SecReview keeps its files |
| `src/SecReview.Core/Probing` | How the machine is read. Interfaces and result types at the top; `Windows/` holds the real implementations (the only place with Windows API calls and unsafe code). `NativeMethods.txt` lists the Windows APIs that CsWin32 generates declarations for |
| `src/SecReview.Cli` | `SecReviewCli.exe` (Native AOT console). The only binary that ever runs elevated |
| `src/SecReview.App` | `SecReview.exe` (WinUI 3, Native AOT, unpackaged, Windows App SDK copied next to it). `Program.Main` picks the role before XAML starts |
| `tests/SecReview.Core.Tests` | MSTest unit tests for `Core` |
| `tools/SecReview.IndexBuilder` | Builds the list of known-malicious packages from a checkout of the OpenSSF malicious-packages feed. Compiles the same source files the apps read the list with. Not shipped |
| `scripts/` | Build checks: `check-lockfiles.ps1` with `allowed-packages.txt` (package allow-list), `check-source-text.ps1` (no hidden or bidirectional control characters in the repo), `check-stage.ps1` with `stage-files.txt` (what ships: every binary not ours must be signed by Microsoft and chain to a pinned root, every other file must match its recorded hash) |
| `build.ps1` | The one entry point; CI runs the same script |
| `.github/workflows/build.yml` | CI: locked restore, build, tests, publish, smoke test |
| `.github/workflows/malware-index.yml` | Daily, on Linux: fetches the feed, builds the list and keeps it as the `known-malicious-index` artifact. The build fails rather than produce a list from a feed that looks broken |

## The list of known-malicious packages

The list is a file beside the programs, `known-malicious.idx`. A plain build has none, and the
three checks that need it then say so ("could not check"). To build with one, take it from the
latest scheduled run on `main` (a pull request's run builds with unreviewed code and uploads
under another name):

```
$run = gh run list --workflow malware-index.yml --branch main --event schedule --status success --limit 1 --json databaseId --jq '.[0].databaseId'
gh run download $run --name known-malicious-index --dir out
.\build.ps1 -MalwareIndex out\known-malicious.idx
```

The build refuses a list that does not load, does not come from the feed, is older than 7 days
or has lost packages, and compiles the list's SHA-256 into the programs: only that exact file is
ever loaded, so a list put beside the programs by someone else is not used.

The data comes from the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages)
feed (Apache-2.0). Tests use made-up package names only: no real advisory and no real package is
in the repository.

## Looking at the window

```
SecReview.exe                                  # scan this PC and show the results
SecReview.exe --demo                           # made-up results covering every kind of outcome
SecReview.exe --demo --screenshot shot.png     # save a picture of the window, then exit
```

Use `--demo` for screenshots in documentation and pull requests: it shows no real PC's results.
The build saves one to `artifacts\screenshots\demo.png`.

Set `SECREVIEW_DATA_DIR` to keep the app's files (its log, for now) out of your profile while
developing; `build.ps1` points it at `artifacts\appdata` for its smoke tests. If the window
fails to start, the reason is in `logs\SecReview.log` there.

The app project needs `AllowUnsafeBlocks` although it has no unsafe code: the WinRT interop
generator emits nothing without it, and bound lists then fail at run time with "not a supported
vector". Collections bound to list controls are typed as `object` and named in
`ViewModels/WinRtExposedTypes.cs` for the same reason.

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
