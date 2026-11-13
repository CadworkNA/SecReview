# Answers for the OpenSSF Best Practices badge

Prepared answers for the passing level at <https://www.bestpractices.dev>. The maintainer
creates the project there once the repository is public and pastes these in; the badge then
goes at the top of the README. Keep this file true: when a practice changes, change the
answer here in the same pull request.

"Met" unless it says otherwise. Paths are files in this repository.

## Basics

| Criterion | Answer |
|-----------|--------|
| description_good | `README.md`, first paragraph: what SecReview checks and that it never changes a setting. |
| interact | `README.md` (install, "Contributing and security"), `CONTRIBUTING.md`. |
| contribution | `CONTRIBUTING.md`: issues, then pull requests against `main`. |
| contribution_requirements | `CONTRIBUTING.md`, "Requirements for a pull request" and "Test policy". |
| floss_license | MIT. |
| floss_license_osi | MIT is approved by the OSI. |
| license_location | `LICENSE`; what the programs contain from others: `THIRD-PARTY-NOTICES.md`. |
| documentation_basics | `README.md` (install, use, what leaves the PC); `BUILDING.md`. |
| documentation_interface | `README.md`, "For IT": silent install, policies, `SecReviewCli --report`; `SecReviewCli --help`. |
| sites_https | Everything is on github.com, over HTTPS. |
| discussion | GitHub issues: searchable, addressable by URL, open to all. |
| english | Documentation, issues and code are in English. |
| maintained | Yes. |

## Change control

| Criterion | Answer |
|-----------|--------|
| repo_public | The GitHub repository. |
| repo_track | Git: who changed what, and when. |
| repo_interim | Every change is its own pull request on `main` between releases. |
| repo_distributed | Git. |
| version_unique | Each release has its own semantic version, compiled into the programs. |
| version_semver | Semantic Versioning; `build.ps1` refuses anything else. |
| version_tags | Tag `vX.Y.Z` per release; a ruleset lets only administrators create or move these tags. |
| release_notes | Each GitHub release lists the merged pull requests by title (`.github/release.yml`); the app shows the features and fixes under "What's new". |
| release_notes_vulns | N/A so far: no release has fixed a publicly known vulnerability. `SECURITY.md`: a fix ships with a GitHub security advisory, named in the notes. |

## Reporting

| Criterion | Answer |
|-----------|--------|
| report_process | `CONTRIBUTING.md` and the issue forms (`.github/ISSUE_TEMPLATE`). |
| report_tracker | GitHub issues. |
| report_responses | Reports are answered by the maintainer; `.github/CODEOWNERS` routes every pull request to them. |
| enhancement_responses | Check requests have their own issue form and are answered the same way. |
| report_archive | GitHub issues keep reports and answers, public and searchable. |
| vulnerability_report_process | `SECURITY.md`. |
| vulnerability_report_private | GitHub private vulnerability reporting, linked from `SECURITY.md` and the issue chooser. |
| vulnerability_report_response | `SECURITY.md`: acknowledgement within 5 business days. No report has been received so far. |

## Quality

| Criterion | Answer |
|-----------|--------|
| build | `.\build.ps1` restores, builds, tests and publishes. |
| build_common_tools | The .NET SDK and PowerShell 7. |
| build_floss_tools | **Unmet.** Native AOT on Windows links with Microsoft's C++ build tools, which are free of charge but not open source. The .NET SDK, PowerShell and Inno Setup are. |
| test | MSTest suite in `tests/`, more than 2,500 tests; MIT-licensed tooling. |
| test_invocation | `dotnet test --solution SecReview.slnx`, as `BUILDING.md` says. |
| test_most | All logic lives in `SecReview.Core` and is unit-tested against fakes of the machine; the programs themselves are run by the build's smoke test. |
| test_continuous_integration | `.github/workflows/build.yml` on every pull request and every push to `main`. |
| test_policy | `CONTRIBUTING.md`, "Test policy". |
| tests_are_added | Each milestone's pull request added the tests for what it added; see the merged pull requests. |
| tests_documented_added | `CONTRIBUTING.md`, requirement 5 and "Test policy". |
| warnings | .NET analyzers at `latest-recommended` and code-style rules run in every build (`Directory.Build.props`). |
| warnings_fixed | Warnings are errors; the build fails on one. |
| warnings_strict | Yes, as above; a suppressed rule needs a comment that says why. |

## Security

| Criterion | Answer |
|-----------|--------|
| know_secure_design | `BUILDING.md` and `CONTRIBUTING.md` state the rules the design follows: read-only, least privilege (the app never runs elevated; the helper takes one pipe name and nothing else), fail-safe results ("could not check" is never a pass), allow-lists for packages and shipped files, a pinned publisher for updates. |
| know_common_errors | Input from files, the registry, the network and the helper is treated as hostile and tested as such (`BUILDING.md`, "Damaged input"); secrets are never put into results, logs or error reports. |
| crypto_published | SHA-256, TLS and Authenticode only. |
| crypto_call | Nothing is implemented here: .NET's and Windows' implementations are called. |
| crypto_floss | The functions used (SHA-256, TLS, Authenticode verification) all have open-source implementations. |
| crypto_keylength | SHA-256 for files; TLS and signature key lengths are those of Windows and of the signing service. SecReview creates no keys. |
| crypto_working | No MD5, SHA-1, DES or RC4 in the programs. (Certificates are named by their SHA-1 thumbprint, as Windows shows them: Microsoft's roots in the build script, and trusted authorities in the check that looks for their key on the PC. Nothing is secured by that hash.) |
| crypto_weaknesses | As above. |
| crypto_pfs | N/A: SecReview implements no key agreement; its two HTTPS requests use Windows' TLS. |
| crypto_password_storage | N/A: SecReview stores no passwords. |
| crypto_random | Pipe names and working folders come from the operating system's cryptographic random source (`RandomNumberGenerator`). |
| delivery_mitm | Releases are downloaded over HTTPS, signed (Authenticode, timestamped), and attested (Sigstore). The updater also checks the SHA-256, the publisher, the certificate's root and the file's version before it installs. |
| delivery_unsigned | A hash is never trusted by itself: the updater requires the publisher's signature as well. |
| vulnerabilities_fixed_60_days | No known vulnerability is open. |
| vulnerabilities_critical_fixed | As above. |
| no_leaked_credentials | No credential is in the repository. Signing uses OpenID Connect, without a stored key; secret scanning with push protection is on. |

## Analysis

| Criterion | Answer |
|-----------|--------|
| static_analysis | .NET analyzers in every build; CodeQL on every pull request and weekly (`.github/workflows/codeql.yml`); OpenSSF Scorecard weekly. |
| static_analysis_common_vulnerabilities | CodeQL's `security-extended` queries for C# and for the workflows. |
| static_analysis_fixed | No finding of medium or higher severity is open. |
| static_analysis_often | On every pull request. |
| dynamic_analysis | Seeded mutation tests run in every build: each check and each reader is run against damaged input (`BUILDING.md`, "Damaged input"). The release workflow also weakens settings on a disposable machine and requires the installed program to report each. |
| dynamic_analysis_unsafe | N/A: C#, a memory-safe language. The `unsafe` blocks are the calls into Windows. |
| dynamic_analysis_enable_assertions | **Unmet.** Tests run the Release build, the one that ships. |
| dynamic_analysis_fixed | No such finding is open. |

## Before answering

These are settings only the maintainer can change; the answers above assume them (see the
"Owner follow-ups" issue):

- the repository is public;
- private vulnerability reporting, secret scanning with push protection and Dependabot alerts
  are on;
- `main` is protected by a ruleset: pull request with review, required checks, no force-push.
