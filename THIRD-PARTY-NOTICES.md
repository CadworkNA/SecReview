# Third-party notices

SecReview is MIT-licensed (`LICENSE`). The installed programs also contain or come with the
following. Each licence text is installed in the `licenses` folder next to the programs.

| Component | Where it is | Licence | Text |
|-----------|-------------|---------|------|
| .NET runtime and libraries (Microsoft, .NET Foundation and contributors) | Compiled into `SecReview.exe` and `SecReviewCli.exe` | MIT | `dotnet-runtime-LICENSE.txt`; notices of what .NET itself contains: `dotnet-THIRD-PARTY-NOTICES.txt` |
| Windows App SDK and WinUI (Microsoft) | The Microsoft-signed files next to `SecReview.exe`, and the code that calls them, compiled into `SecReview.exe` | Microsoft Software License Terms, Microsoft Windows App SDK | `WindowsAppSDK-license.txt`; notices: `WindowsAppSDK-NOTICE.txt`, `WindowsAppSDK-WinUI-NOTICE.txt` |
| Windows SDK for .NET (Microsoft) | Compiled into `SecReview.exe`: the code that calls Windows' own interfaces | Microsoft Windows SDK licence terms | <https://aka.ms/WinSDKLicenseURL> |
| C#/WinRT (Microsoft) | Compiled into `SecReview.exe` | MIT | `CsWinRT-LICENSE.txt` |
| Sentry SDK for .NET (Sentry) | Compiled into `SecReview.exe` only; reports errors of SecReview itself, and only where that is switched on | MIT | `sentry-dotnet-LICENSE.txt` |
| Ben.Demystifier (Ben Adams and contributors), as included in the Sentry SDK | Compiled into `SecReview.exe` with the Sentry SDK | Apache-2.0 | `Ben.Demystifier-LICENSE.txt` |
| OpenSSF Malicious Packages data (Open Source Security Foundation and contributors) | `known-malicious.idx`, a list of package names, versions and advisory identifiers built from that data; in official builds | Apache-2.0 | `malicious-packages-LICENSE.txt` |
| Inno Setup (Jordan Russell, Martijn Laan) | The setup program and the uninstaller (`unins000.exe`) | Inno Setup License | `InnoSetup-license.txt` |

Sources:

- .NET: <https://github.com/dotnet/runtime>
- Windows App SDK: <https://github.com/microsoft/WindowsAppSDK>
- C#/WinRT: <https://github.com/microsoft/CsWinRT>
- Sentry SDK for .NET: <https://github.com/getsentry/sentry-dotnet>
- Ben.Demystifier: <https://github.com/benaadams/Ben.Demystifier>
- OpenSSF Malicious Packages: <https://github.com/ossf/malicious-packages>. The list is
  changed in form only: SecReview keeps the registry, package name, affected versions,
  identifier and date of each `MAL-` advisory, and nothing else.
- Inno Setup: <https://jrsoftware.org/isinfo.php>

Used to build or test SecReview, and not part of what is installed: C#/Win32 (CsWin32, MIT),
MSTest (MIT), the .NET SDK (MIT), the Microsoft SBOM tool (MIT).
