# SecReview

SecReview checks a Windows PC's security settings and tells you **why** a check failed and how to
fix it. It never changes a setting itself.

It covers the basics (firewall, disk encryption, antivirus, screen lock, updates), a curated set of
hardening rules, and developer supply-chain risks (package-manager cooldowns, stored tokens,
editor extensions, known-malicious packages).

**Status:** in development. There is no release yet.

## Install

Run `SecReview-<version>-setup.exe` from the [releases](https://github.com/CadworkNA/SecReview/releases).
It needs administrator rights once, to install for everyone who uses the PC; SecReview itself
runs without them.

- SecReview opens from the Start menu. Its icon in the notification area shows how the PC is
  doing and tells you when a check starts failing.
- To remove it: Settings, Apps, Installed apps, SecReview, Uninstall. Your settings and last
  results stay in `%LOCALAPPDATA%\SecReview`; delete that folder to remove them too.
- For IT: `SecReview-<version>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` installs
  without a window. Add `/MERGETASKS="!autostart"` to leave out the icon at sign-in.

## Building

See [BUILDING.md](BUILDING.md).

## License

[MIT](LICENSE). What the installed programs contain from others: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
