# Contributing

Bug reports, check requests and pull requests are welcome.

- **Bugs and requests:** open a [GitHub issue](https://github.com/CadworkNA/SecReview/issues).
  Include the SecReview version and Windows version. **Never attach a real report from your PC**:
  it lists that PC's weaknesses. Reduce the problem to the one check and setting involved.
- **Security problems:** do not open an issue; follow [SECURITY.md](SECURITY.md).
- **Changes:** open a pull request against `main`. For anything larger than a fix, open an issue
  first so the approach can be agreed.

## Requirements for a pull request

1. **Results stay honest.** A check that cannot determine the answer reports "could not check"
   with the reason. It never passes by default, and errors are never swallowed.
2. **Checks only read.** SecReview never changes a setting, never starts PowerShell, and never
   executes a tool it inspects. It reads files, registry and environment.
3. **Secrets never leave their file.** A credential finding names the file and key, not the value.
4. **The elevated helper accepts nothing from its caller** except a pipe name of a fixed form.
5. **It comes with tests** (see below) and `.\build.ps1 -Locked` passes with no warnings.
6. **User-facing text is short:** a title is one sentence, a reason is one line, fix steps are
   numbered actions.
7. **No new dependency** without prior agreement; see [BUILDING.md](BUILDING.md#dependencies).
8. **No secrets or real data:** no reports, paths or settings from a real PC. Fixtures and
   screenshots use made-up data.
9. **The title uses a conventional prefix:** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
   `build:` (build system; `build(deps):` for dependencies), `ci:` or `chore:`. Pull requests are
   squash-merged, so the title becomes the release-notes entry.

Every pull request is reviewed by a maintainer ([CODEOWNERS](.github/CODEOWNERS)).

## Test policy

- **A new check or rule:** unit tests for pass, fail, "could not check" and "not applicable",
  against the fake system probe. Tests never read the real machine.
- **A new rule in `rules/`:** a new kind of rule needs those tests; a rule of an existing kind
  needs none of its own, but must name the Microsoft documentation page it rests on, the day it
  was checked, and what Windows does when the value is absent. Do not copy benchmark text.
- **A bug fix:** a test that fails without the fix.
- **Code that parses a file format:** fixture files plus mutation tests showing that malformed
  input never crashes or hangs and never produces a pass.
- **A change to elevation or updating:** tests for every refusal case.
