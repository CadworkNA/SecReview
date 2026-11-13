# SecReview

SecReview checks a Windows PC's security settings and tells you **why** a check failed and how
to fix it. It never changes a setting itself.

It covers:

- **The basics:** screen lock, sign-in, updates, firewall, disk encryption, antivirus.
- **Hardening:** a curated set of rules, each resting on a page of Microsoft's documentation.
- **Developer supply chain:** release cooldowns of package managers (uv, pnpm, npm, Yarn, Bun,
  pip, Poetry, PDM, NuGet), unsafe package sources, switched-off protections, tokens stored as
  plain text, editor extensions, AI agents and MCP servers, and packages known to be malicious.

Every check ends as "pass", "fail" or "could not check", with the reason. What SecReview could
not read is never shown as a pass.

**Status:** the first release is being prepared. Until it is published there is nothing to
download; SecReview can be [built from source](BUILDING.md).

## Install

Run `SecReview-<version>-setup.exe` from the [releases](https://github.com/CadworkNA/SecReview/releases).
It needs administrator rights once, to install for everyone who uses the PC; SecReview itself
runs without them. Windows 10 22H2 or Windows 11, 64-bit.

- SecReview opens from the Start menu. Its icon in the notification area shows how the PC is
  doing and tells you when a check starts failing.
- To remove it: Settings, Apps, Installed apps, SecReview, Uninstall. Your settings and last
  results stay in `%LOCALAPPDATA%\SecReview`; delete that folder to remove them too.

To check a download before running it:

- Its properties show a digital signature by **Cadwork Informatique Inc.**
- Its SHA-256 is on the release page: `Get-FileHash SecReview-<version>-setup.exe`.
- The release page also says how to verify, with `gh attestation verify`, that the file was
  built by this repository's workflow.

## What SecReview does on your PC

- It **reads**: settings, the registry, and the settings files of developer tools. It changes
  nothing, starts no PowerShell and never runs a tool it inspects.
- It runs as you. A few checks need administrator rights; they run only when you ask, behind
  the Windows prompt.
- Where it finds a password or token stored in the open, it names the file and the setting,
  never the secret.
- It keeps three things in `%LOCALAPPDATA%\SecReview`: your settings, the last results and a
  log. The results list this PC's weaknesses: share them, or a saved report, with care.

## What leaves your PC

Nothing about your PC, and no results. SecReview has no usage statistics. Packages are
compared with the list of known-malicious packages on the PC; what is installed is not sent
anywhere.

A released version talks to a server in two cases:

- **Looking for updates,** once a day: one anonymous request to this repository's releases on
  GitHub, carrying SecReview's name and version. "Update now" downloads the setup program
  from there, and installs it only when it is signed by the publisher of the copy you have.
- **Error reports,** when SecReview itself fails: the error's type and where in SecReview it
  happened, the check it happened in, and the versions of SecReview, Windows and .NET. Never
  an error's message, a result, a name, a path or anything that identifies you or the PC.
  **Send feedback** sends what you type and, if you tick the box, the list of results shown
  to you there.

Error reports can be switched off in Settings. A copy built from source without the
maintainer's addresses does neither.

## For IT

- **Silent install:** `SecReview-<version>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`.
  Add `/MERGETASKS="!autostart"` to leave out the icon at sign-in.
- **Policies,** as DWORD values of 1 under `HKLM\Software\Policies\SecReview`:
  `NoUpdateCheck` (never look for updates), `NoSelfUpdate` (say when there is one, but leave
  installing to you), `NoErrorReports` (never report errors or send feedback).
- **A report as a file:** `SecReviewCli.exe --report report.json`.

## Contributing and security

- Bugs, check requests and pull requests: [CONTRIBUTING.md](CONTRIBUTING.md).
- Security problems: [SECURITY.md](SECURITY.md). Please do not open an issue for them.
- Building and how the parts fit together: [BUILDING.md](BUILDING.md).

## License

[MIT](LICENSE). What the installed programs contain from others: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
