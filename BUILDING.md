# Building SecReview

## Requirements

- Windows 11, x64
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
.\build.ps1 -Installer         # also build the setup program (needs Inno Setup 6.3+ or 7)
```

Output: `artifacts\stage` (what ships), `artifacts\symbols` and, with `-Installer`,
`artifacts\installer`. The script ends with a smoke test that opens the app window for a moment,
and holds what it measured against the [budgets](#budgets).

Run the tests again without rebuilding:

```
dotnet test --solution SecReview.slnx -c Release --no-build
```

## Layout

| Path | Contents |
|------|----------|
| `src/SecReview.Core` | Everything without UI: checks, rules, readers, command-line parsing. All logic lives here and is unit-tested |
| `src/SecReview.Core/Checks` | The check model (`ICheck`, outcomes, findings), the runner (time limit and isolation per check) and, under `BuiltIn/`, the checks written in code. `BuiltIn/Programs/` holds the checks that ask whether a standard user can change what Windows runs or trusts for everyone (start-up programs, services, scheduled tasks, the search path, program folders, registered components, programs allowed by the firewall and by ransomware protection, settings kept in the registry for the whole PC), with what they share: reading a permission list the way Windows applies it, finding the program a stored command names without keeping its arguments, and judging that program with every folder above it |
| `src/SecReview.Core/Catalogue` | The wording of every check (`checks.en.json`: titles, why, fix steps, Settings link), embedded as data. Tests enforce completeness and length limits. Also the lists some checks compare against, each with the date it was verified: `windows-servicing.json` (end of security updates per Windows release) and `password-managers.json` (app names and browser-extension identifiers) |
| `src/SecReview.Core/Rules` and `rules/` | Checks written as data: `rules/*.json` (embedded at build time) and the engine that runs them. A rule names a registry value, service, account policy value, audit subcategory, user right or Microsoft Defender setting, what is expected, what it means when the value is absent, and the Microsoft page and date it was verified against. A rule file that does not hold together fails the load, and so the tests |
| `src/SecReview.Core/Config` | Readers for the settings files of developer tools: TOML, YAML, INI, Git's settings format, XML and Java-style properties. Each covers what settings files use and stops at the first thing it does not understand, with the line number: a file is read in full or not judged at all. Seeded mutation tests keep them from crashing or hanging |
| `src/SecReview.Core/SupplyChain` | The developer supply-chain checks, a folder per tool or topic (uv, pnpm, Scoop, npm, Yarn, pip, NuGet, Cargo, Go, Git, editors, AI agents and MCP servers, Docker, winget, Chocolatey, environment variables, stored credentials): release cooldowns, unsafe package sources, switched-off protections, secrets stored as plain text. No tool is ever run: versions come from files, and where none records one the result says so. A check does not apply when its tool is absent |
| `src/SecReview.Core/Malware` | Known-malicious package matching: the index format (compact, checksummed, searched in place), version ordering per registry, the reader for OSV advisories, and the places packages are looked for (global packages, Python environments, editor extensions, download caches). Names are compared first and a version is read only for a listed name; what is installed never leaves the PC |
| `src/SecReview.Core/Elevation` | The administrator checks: the pipe's name and rules, what the helper does when started elevated, and the app's side (make the pipe, start the helper through the Windows prompt, verify who answers, read the answer) |
| `src/SecReview.Core/Tray` | The notification-area icon: when the checks run again, what the icon, its tooltip and a notification say (`TrayLogic`), the icon's picture drawn in code (`TrayIconImage`), what the process behind it does (`TraySession`), what an app notification holds and what a click on one may ask for (`AppNotification`), and under `Windows/` the icon itself and the class that takes a click from Windows |
| `src/SecReview.Core/Updates` | Looking for a newer version (`latest.json`, the allowed addresses, what was found), the check "SecReview is up to date", and installing an update: the helper's rules, the window's side, and under `Windows/` the signature check and the administrators-only folder |
| `src/SecReview.Core/Instances` | How SecReview's processes find each other: one window and one icon per user, the signal from the window to the icon, and a second start handing over to the open window |
| `src/SecReview.Core/Scanning` | Runs the catalogue and pairs results with wording, handing each result over as it arrives; filters, groups and the headline; the last scan kept in `results.json`; the made-up results behind `--demo` |
| `src/SecReview.Core/Settings` | What is remembered between runs (`settings.json`): ignored checks with their reasons. A damaged file is set aside and never stops the app |
| `src/SecReview.Core/Reporting` | The report written by `SecReviewCli --report` |
| `src/SecReview.Core/Diagnostics` | `--diagnose`, the local error log (size-capped, names removed) and where SecReview keeps its files |
| `src/SecReview.Core/Probing` | How the machine is read. Interfaces and result types at the top; `Windows/` holds the real implementations (the only place with Windows API calls and unsafe code). Permission lists are read as stored, never tested by writing; links are not followed and network paths are never opened. `NativeMethods.txt` lists the Windows APIs that CsWin32 generates declarations for |
| `src/SecReview.Cli` | `SecReviewCli.exe` (Native AOT console). The only binary that ever runs elevated |
| `src/SecReview.App` | `SecReview.exe` (WinUI 3, Native AOT, unpackaged, Windows App SDK copied next to it). `Program.Main` picks the role before XAML starts |
| `tests/SecReview.Core.Tests` | MSTest unit tests for `Core` |
| `tools/SecReview.IndexBuilder` | Builds the list of known-malicious packages from a checkout of the OpenSSF malicious-packages feed. Compiles the same source files the apps read the list with. Not shipped |
| `scripts/` | Build checks: `check-lockfiles.ps1` with `allowed-packages.txt` (package allow-list), `check-source-text.ps1` (no hidden or bidirectional control characters in the repo), `check-stage.ps1` with `stage-files.txt` (what ships: every binary not ours must be signed by Microsoft and chain to a pinned root, every other file must match its recorded hash), `check-budgets.ps1` with `budgets.psd1` (size and time limits) |
| `build.ps1` | The one entry point; CI runs the same script |
| `.github/workflows/build.yml` | CI: locked restore, build, tests, publish, smoke test |
| `.github/workflows/malware-index.yml` | Daily, on Linux: fetches the feed, builds the list and keeps it as the `known-malicious-index` artifact. The build fails rather than produce a list from a feed that looks broken |
| `.github/workflows/reproducible.yml` | Two machines build one commit, setup program included; every file must have the same SHA-256. Runs when the build's inputs change, and by hand |
| `.github/workflows/codeql.yml`, `scorecard.yml` | CodeQL's security queries over the C# code and the workflows, and the OpenSSF Scorecard. Both do nothing while the repository is private and start by themselves once it is public |

## Damaged input

Whatever SecReview reads can be damaged or written by someone else: settings files, the
registry, its own files, the answer of its helper, an update's description. Nothing read may
make it throw, hang or call something safe that it could not judge.

- **Every check test is a mutation test too.** After a test has run a check against its fake
  PC, the test helper runs the check again against damaged copies of that PC
  (`tests/.../Checks/DamagedCopies.cs`): one file, registry value or variable the check read
  is damaged per round, as text or, for JSON, by putting a value of another kind in a
  value's place. The check must answer, in time, with one short line. A new check gets this
  from its ordinary tests.
- **Each reader has its own seeded test** with what must still hold after damage: the
  settings-file readers, SSH keys, the list of known-malicious packages, saved results and
  settings, `latest.json` and `update.json`, the helper's answer, the rule files, and both
  programs' arguments.
- **A deeper run:** set `SECREVIEW_TEST_DAMAGE` to a number to multiply the rounds, for
  example `$env:SECREVIEW_TEST_DAMAGE = 100` before `dotnet test`. Seeds are fixed, so a
  failure repeats, and its message shows the damaged text.
- **Text in a result is one line.** A summary and each cell of "found versus expected" lose
  their line breaks, control characters and invisible direction marks, and are cut at 1000
  characters (`Wording.OneLine`), whatever the check put into them.

## Budgets

`scripts\budgets.psd1` limits what SecReview weighs and how long it takes: the installed
folder, the two programs, the list, the setup program; the helper's start, a whole scan, the
window from start to drawn; and what the icon uses while it waits. `build.ps1` measures them
on every build and fails when one is over. The measurements are written to
`artifacts\budgets.json` and, on GitHub, to the run's summary.

- A limit is not a target: each leaves room for a slow build machine and catches the change
  that doubles something unnoticed. Raising one is a reviewed change to that file.
- The icon is measured on build machines only, like its smoke test, and only in a build that
  knows no server.

## Administrator checks

Some checks need administrator rights. The app never has them: it starts
`SecReviewCli.exe --elevated-scan --pipe <name>` through the Windows prompt and reads the
answer from a pipe.

- **The helper takes one thing:** a pipe name of the one form the app makes (`SecReview.Elev.`
  and 32 random hexadecimal digits). No paths, lists or options. It runs the machine-scope
  checks that need administrator rights, writes their results as one document and exits. It
  reads nothing from the pipe, and connects without lending its identity to whoever made it.
- **The app trusts nothing it did not check:** the pipe is the first of its name; only
  Administrators can write to it (the helper always is one), not even its maker can change
  that, and nothing comes over the network; only a connection from the process Windows
  started is heard; the answer is capped at 1 MB, read like `results.json`, and must hold
  exactly the administrator checks of this version, read with administrator rights.
- **Only from Program Files.** The helper runs elevated, so it must be a file an ordinary
  user cannot replace. A copy of SecReview anywhere else shows why the button is not there.
  The permissions are read too: the helper, its folder and every folder above it up to
  Program Files must be changeable by administrators and Windows only, and none may be a link.
- **No Windows shell with administrator rights.** Drive encryption is read from BitLocker's
  own management class; the shell, which other software can extend, is not loaded.
- **Saying no at the prompt** changes nothing: the checks stay "needs administrator".
- **Afterwards** a check keeps both answers side by side, each with its date: the latest read
  without administrator rights and, for 30 days, the latest read with them. A new answer
  replaces only the earlier one of its own kind, so lists do not swap between scans. The
  answer that says something worse decides where the check stands; where an ordinary scan
  can only say "needs administrator rights", the administrator answer does. The window shows
  both under their own headings.
- **`--report` with administrator rights** never replaces an existing file: an elevated
  program that overwrites whatever it is pointed at could be used to destroy any file.
- The build runs the compiled helper over a real pipe (`build.ps1` stands in for the app). On
  a build machine that runs with administrator rights, as hosted runners do, the checks are
  really answered. The Windows prompt itself cannot be exercised by a build.

## The notification-area icon

`SecReview.exe --tray` is the icon: no window, and the UI framework is never started. It runs
the checks again when they are due, keeps `results.json` for the window, and says so when a
check starts failing.

- **Schedule:** one interval (1, 4, 12 or 24 hours; 4 by default) after the last scan,
  whoever ran it; not in the first minute after starting; not while paused. After a scan that
  could not run, the next try is 15 minutes later.
- **A notification** only for a check that was known not to fail and now does. The first scan
  of a PC, an ignored check and one that was already failing are not news. Clicking it opens
  the window on that check (`SecReview.exe --show <check>`).
- **App notifications** (title, reason, a "Show" button; they stay in the notification
  centre) from the installed copy, without administrator rights. Elsewhere, or when Windows
  does not know SecReview (setup's registration is missing), the icon shows its own. When
  the user or the organisation switched SecReview's notifications off in Windows, nothing is
  shown.
- **A click on an app notification** makes Windows start `SecReview.exe --notification-click`
  through setup's class, even after the icon has ended. That process takes the click from
  Windows (`NotificationClicks`), then opens the window. It accepts only what SecReview's
  notifications hold (`show` or `show:<check>`), since any program of the user can send a
  "click".
- **The icon** is green only when everything checked is in order; orange when something
  needs attention; grey when nothing is known, something could not be checked, or the checks
  are paused. A scan older than two intervals and a day no longer makes it green. Checks that
  wait for administrator rights do not count against green, as in the window; the tooltip
  then says "No problems found so far". It is drawn in code, so there are no image files.
- **Shared files:** the window and the icon both read and write `settings.json` and
  `results.json`. Each changes the settings as they are on disk, never a copy it read
  earlier. Before saving results each takes in the other's newer answers, check by check,
  and an open window shows what the icon found within seconds. The window signals the icon
  after writing. A file the other process has open for a moment is written on a later try.
- **Never as administrator through the prompt:** the icon stays all day and opens the
  window, so with those rights it would pass them on. It does not run then, and an elevated
  window does not start it. Where administrators are always elevated it runs as they do.
- **One of each:** a second icon ends at once; a second window brings the open one forward.
  The names they find each other by are local to the user's Windows session and carry the
  data folder, so a copy run with `SECREVIEW_DATA_DIR` is a set of its own.
- **Nothing is registered with Windows by the app.** Starting at sign-in and app
  notifications are the installer's entries; the switch in Settings is what the icon looks at
  when it starts, and it ends itself when the switch is off.
- **Testing:** the rules run in unit tests against a fake icon and a clock. The icon itself
  runs on build machines only (`--tray --smoke-test`: put up the icon, run the checks once,
  save, exit); `build.ps1` skips it elsewhere, because Windows remembers every icon it has
  shown. A notification click is taken through COM within one process in a unit test, and
  from another process by the installed program in `scripts\test-install.ps1`. Clicking the
  icon, its menu and showing a notification cannot be exercised by a build.

## The setup program and releases

`installer\SecReview.iss` (Inno Setup) packs the staged folder. Its header lists everything
setup changes on a PC; the uninstaller removes all of it and leaves each user's own data.

- **Program Files, for all users, and nowhere else.** The folder is not asked for and
  `/DIR` is refused: the administrator checks need programs an ordinary user cannot replace.
- **An upgrade** removes what the earlier version left in the folder before it copies, so
  the folder holds exactly the new version.
- **Start at sign-in** is one value under `HKLM\...\Run` (`SecReview.exe --tray`), a task
  that is on by default. Each user can still switch the icon off in Settings.
- **App notifications:** the Start menu shortcut carries SecReview's identity
  (`Cadwork.SecReview`) and the class Windows starts for a click; that class is one key under
  `HKLM\Software\Classes\CLSID`. The installed window takes the same identity, so it joins
  the shortcut pinned to the taskbar.
- **Silent:** `SecReview-<version>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`; add
  `/MERGETASKS="!autostart"` to leave out the icon at sign-in.
- **Running copies are ended** by setup and by the uninstaller, for every signed-in user.
- **Never run on a developer PC.** `build.ps1 -Installer` only compiles it.
  `scripts\test-install.ps1` installs, upgrades and uninstalls it and checks each step; it
  refuses to run anywhere but a build machine.
- **The icon** (`resources\SecReview.ico`) is what `SecReview.Tray.IconFile` draws. A test
  fails when the file differs and leaves the right file in the test output folder.
- **Licences:** `THIRD-PARTY-NOTICES.md` says what the programs contain. The texts are
  installed in `licenses\`; those that belong to a package version are copied from the
  restored package at build time.

The **Package and release** workflow (`full.yml`) is the only place a release is built:

1. Official build: the newest list of known-malicious packages from the daily workflow, and
   the error-report address from the repository's settings.
2. The two programs are signed (Azure Artifact Signing, signed in through OpenID Connect; no
   stored key), then the uninstaller and the setup program. A signature without a timestamp
   fails the build. A run by hand signs only when asked to; a version tag always does.
   Signing is tied to the `release` environment: Azure gives the signing identity to that
   environment only, the environment accepts only `main` and `v*` tags, and a ruleset lets
   only repository administrators create, move or delete `v*` tags. The signing module and
   the three tools it uses are each checked by SHA-256 before they run
   (`scripts/signing-tools.ps1`).
3. Install, upgrade and uninstall on the build machine, with what landed on it compared to
   the staged folder and, for a signed build, its signatures.
4. An SBOM of the install folder and the packages behind it (SPDX 2.2, Microsoft's SBOM tool,
   pinned in `.config\dotnet-tools.json`).
5. A **draft** release with the setup program and the SBOM, and, once the repository is
   public, a Sigstore bundle proving where they were built.
6. On a second machine, `scripts/test-posture.ps1` installs the setup program and weakens
   what ten checks look at. For the PC: firewall off for one network, Remote Desktop on
   without Network Level Authentication, WDigest, AutoPlay, more cached sign-ins. For an
   ordinary user made for the test: a made-up npm token, a proxy script over plain HTTP,
   revocation checks off, a FileZilla password, and a key file beside a trusted made-up
   certificate authority. Each check must fail for its own reason, the user's files must
   not be read with administrator rights, and no report may hold a made-up secret or a name.
   A release waits for this. The script refuses to run anywhere but GitHub's own machines.

**Reproducible:** one commit, built unsigned on GitHub's image with the same version and list,
gives the same programs and setup program. The linker writes a hash instead of the time
(`/Brepro`), and packed files carry the commit's time. Limits:

- A signed build always differs: each signature carries the time it was made.
- The XAML compiler writes the build folder's path into the window program, so another folder
  gives another program. GitHub always builds in the same one.
- The C++ linker and Inno Setup come from the machine image, so a later image can give
  other bytes.

Start it by hand (Actions, "Package and release") to try all of this without a release. A
release is made by the maintainer: push the tag `vX.Y.Z`, wait for the draft, publish it.

## Updates

SecReview says when there is a newer version and installs it when the user asks. There is no
silent updater.

- **One address, compiled in.** Official builds get the address of `latest.json`
  (`build.ps1 -UpdateUrl`, written in `full.yml`, so a change is part of the code's history).
  Nothing on a PC can point SecReview elsewhere. A build without it never looks and never installs.
- **Looking** (once a day, by the window or the icon; the answer is kept in `update.json`
  for both): one anonymous request that carries the product's name and version and nothing
  about the PC. HTTPS only, on the manifest's own host (for GitHub, also where it serves
  release files from); every address a server sends SecReview on to is checked the same way.
  A look that fails is shown as such, with the reason, and never reads as "up to date".
- **`latest.json`** is written by the release workflow and attached to the release:
  version, the setup program's address and SHA-256, the date, what is new. Anything not
  wholly right makes the manifest unusable. "What's new" in the window is made from the
  release's generated notes: one plain line per `feat:` ("New: ...") and `fix:` ("Fixed: ...")
  pull request; authors, addresses and other kinds of change are left out. A version is three numbers and, optionally, a
  pre-release part, and nothing else; no text from the server takes part in a file name.
- **"Update now"** starts `SecReviewCli.exe --apply-update --pipe <name>` through the Windows
  prompt. The helper takes only the pipe to report on. It reads the manifest again itself,
  downloads the setup program into a folder only administrators can touch, holds the file
  open, and starts it only when all of this holds:
  - the server's version is higher than the one running;
  - the file has the SHA-256 the manifest names;
  - Windows accepts its signature, with revocation checked, and it is timestamped;
  - it is signed by the publisher in `signing\Publisher.props`, which is compiled into
    signed builds only: the certificate's subject, the signing service's identifier for
    this publisher, and the root certificate the chain ends in. The root matters because
    the helper runs as the user who asked, and a user's own trusted roots can be added to
    without administrator rights;
  - the file's own version, which the signature covers, is exactly the announced one (so a
    signed pre-release cannot pass for the release).
  A file that fails any of this is deleted.
  Then setup runs silently, with the administrators-only folder as its temporary folder,
  closes SecReview, and opens the window again for the user who asked. With another
  account's administrator rights the user opens it again themselves.
- **The organisation decides** (`HKLM\Software\Policies\SecReview`): `NoUpdateCheck`
  switches looking off; `NoSelfUpdate` leaves the notice and takes away "Update now". A
  policy that cannot be read counts as set.
- **The publisher** in `signing\Publisher.props` is also what the release build holds its own
  signatures to. Signing with another certificate means changing that file in a reviewed
  pull request, and installed copies will only take updates signed as it said when they
  were built.
- **Testing:** the rules run in unit tests with a made-up server, including the real pipe
  and Windows' real signature check on a Microsoft-signed file. A whole update, from the
  prompt to the reopened window, needs a published release and is on the manual list.

## Error reports

The app can report its own errors (an unhandled error, a check that threw, a run that never
closed down) and send feedback the user types. It uses the Sentry SDK, in the app only: the
command-line helper, the only binary that runs elevated, has no such code, and the build fails
if it ever does (`check-lockfiles.ps1` allows the package in the app's lock file only;
`check-stage.ps1` looks inside the helper).

- Nothing is sent unless the build was given an address (`.\build.ps1 -ErrorReportAddress`),
  the organisation has not set `NoErrorReports` under `HKLM\SOFTWARE\Policies\SecReview`, the
  settings could be read, the user has closed the welcome notice (which says that errors are
  reported) and has left the switch in Settings on. A plain build has no address. Made-up
  results (`--demo`) and automated runs (`--smoke-test`, `--screenshot`) never report.
- A report holds the error's type and stack, the check it happened in, and the versions of
  SecReview, Windows and .NET. Never an error's message (it can quote anything), no results,
  no names or paths, no device details, no installation identifier, no trail of earlier
  events, nothing on disk, and no memory dumps.
- What leaves is not the report the SDK made but a new one that `ErrorReporter.Clean` fills
  with those few things. A field the SDK adds in a later version is left behind unless that
  method names it.
- Each bug is reported once a day and at most ten different ones a day; `reported.txt` in the
  data folder remembers the day and a hash per bug.
- `SecReview.exe --error-report-test <file>` raises made-up errors carrying this PC's real
  names and a made-up secret (in messages, in errors inside errors, in attached data) and
  writes what would have been sent to the file. The build reads it and fails if any of that
  is in there, if a bug was written twice, or if anything was written to the folders it gave
  the app as its profile and temporary folder.
- Only the package's library is used. Its build steps and its code generator are left out in
  the app's project file: they write every build property, the project folder among them,
  into the program, and can upload symbols and sources. `check-stage.ps1` fails the build if
  either program contains the folder it was built in.

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
SecReview.exe --demo all-pass                  # one state of the window: mixed, all-pass, first-run,
                                               # ignored, loading, failed, dialogs
SecReview.exe --demo --screenshot shot.png     # save a picture of the window, then exit
```

Use `--demo` for screenshots in documentation and pull requests: it shows no real PC's results
and writes nothing. The build saves one picture per state to `artifacts\screenshots`.

Every automated start of the window (`--smoke-test`, `--screenshot`) also walks what Windows
hands to screen readers: each button, box and tab must have a name and be reachable with the
keyboard, or the run ends with exit code 10 and the log names the control. `--demo dialogs`
opens every dialog once and checks those too. Give a new control a name
(`AutomationProperties.Name`) when its content is not plain text.

The app keeps three things in its data folder (`%LOCALAPPDATA%\SecReview`): `settings.json`
(ignored checks and their reasons), `results.json` (the last scan, shown at once on the next
start) and `logs\SecReview.log`. Set `SECREVIEW_DATA_DIR` to keep them out of your profile while
developing; `build.ps1` points it at `artifacts\appdata` for its smoke tests. If the window
fails to start, the reason is in the log there.

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

Tools used by workflows only (the SBOM tool) are pinned in `.config\dotnet-tools.json` and come
from nuget.org under the same rules.

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
