# CLAUDE.md

Read `BUILDING.md` (build, layout, dependency rules) and `CONTRIBUTING.md` (pull request
requirements, test policy) first. The pinned **Roadmap** issue lists the milestones and which are
done; start there when resuming work.

## Build and test

- `.\build.ps1 -LocalCache` restores, builds, tests and publishes. Add `-NoPublish` for a quick
  loop. CI runs `.\build.ps1 -Locked`.
- Warnings are errors. Fix the cause; do not suppress a rule without a comment saying why.
- After changing packages or the SDK, rebuild without `-Locked` so `packages.lock.json` updates,
  and add new ids to `scripts/allowed-packages.txt`.

## Rules that are easy to break

- **Honest results.** Unknown is "could not check" with a reason, never a pass. A setting that only
  works from some tool version says so when the version cannot be read.
- **Read-only.** No setting is ever changed, PowerShell is never started, inspected tools are
  never executed. All machine access goes through the probe interface so tests use a fake.
- **Never weaken a real machine to test a check.** Use fixtures and the fake probe; failing states
  on real Windows are reproduced on disposable CI runners only.
- **No real data in the repo:** no reports, paths, host or user names from a real PC, in code,
  tests, fixtures, screenshots, commits, pull requests or issues.
- **Secrets:** report file and key, never the value; nothing secret in logs or error reports.
- **Elevated code** (`SecReviewCli --elevated-scan`, `--apply-update`) takes only a pipe name of a
  fixed form from its caller. No paths, no lists, no URLs.
- **Dependencies:** Microsoft-published packages only, exact versions, at least 7 days old. The
  one exception, approved by the maintainer, is the error-reporting SDK (`Sentry`, app only).
  Ask before adding anything else.
- **Error reports** hold an error's type and stack, the check it happened in and the versions
  of SecReview and Windows. Never a message, results, names, paths or an identifier. What
  leaves is a new report that `ErrorReporter.Clean` fills field by field: add nothing there
  without asking. The build's `--error-report-test` proves it. The elevated helper never
  reports anything.
- **Text is short.** Titles one sentence, reasons one line, fix steps as numbered actions. The
  same goes for docs, pull requests and issues.

## Commits and pull requests

- One pull request per milestone or fix, squash-merged. Title with a conventional prefix; the
  list is in `CONTRIBUTING.md`.
- Body: `- ` bullets that give the reason, then **Testing** (what ran, with numbers) and
  **Not tested**.
- Never push a version tag or publish a release; the maintainer does that.
- Track follow-ups as GitHub issues.
