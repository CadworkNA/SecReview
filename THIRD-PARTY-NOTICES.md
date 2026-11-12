# Third-party notices

SecReview is MIT-licensed (`LICENSE`). The installed programs also contain or come with the
following. Each licence text is installed in the `licenses` folder next to the programs.

| Component | Where it is | Licence | Text |
|-----------|-------------|---------|------|
| .NET runtime and libraries (Microsoft, .NET Foundation and contributors) | Compiled into `SecReview.exe` and `SecReviewCli.exe` | MIT | `dotnet-runtime-LICENSE.txt`; notices of what .NET itself contains: `dotnet-THIRD-PARTY-NOTICES.txt` |
| Windows App SDK and WinUI (Microsoft) | The Microsoft-signed files next to `SecReview.exe` | Microsoft Software License Terms, Microsoft Windows App SDK | `WindowsAppSDK-license.txt`; notices: `WindowsAppSDK-NOTICE.txt` |
| Sentry SDK for .NET (Sentry) | Compiled into `SecReview.exe` only; reports errors of SecReview itself, and only where that is switched on | MIT | `sentry-dotnet-LICENSE.txt` |
| OpenSSF Malicious Packages data (Open Source Security Foundation and contributors) | `known-malicious.idx`, a list of package names, versions and advisory identifiers built from that data; in official builds | Apache-2.0 | `malicious-packages-LICENSE.txt` |

Sources:

- .NET: <https://github.com/dotnet/runtime>
- Windows App SDK: <https://github.com/microsoft/WindowsAppSDK>
- Sentry SDK for .NET: <https://github.com/getsentry/sentry-dotnet>
- OpenSSF Malicious Packages: <https://github.com/ossf/malicious-packages>. The list is
  changed in form only: SecReview keeps the registry, package name, affected versions,
  identifier and date of each `MAL-` advisory, and nothing else.

Used to build or test SecReview, and not part of what is installed: C#/Win32 (CsWin32, MIT),
MSTest (MIT), the .NET SDK (MIT), Inno Setup (its own licence), the Microsoft SBOM tool (MIT).
