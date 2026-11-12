# Security policy

## Reporting a vulnerability

Report vulnerabilities **privately** through GitHub:
[Security → Report a vulnerability](https://github.com/CadworkNA/SecReview/security/advisories/new).
Please do not open a public issue, pull request or discussion for a security problem.

Include what you can: the SecReview version, the Windows version, the steps or file that
reproduce it, and the impact you expect.

What to expect:

- acknowledgement within **5 business days**;
- an assessment, and a fix or mitigation plan, once the report is confirmed;
- the fix ships as a new release with a GitHub security advisory, crediting you unless you prefer
  otherwise.

## Supported versions

Fixes are made to the latest release. Older releases are not patched.

## Scope

In scope, for example:

- anything that lets a standard user gain rights through SecReview's elevated helper or updater;
- an update or data download that is installed or used without passing verification;
- a crafted config file, lockfile or cache entry that crashes SecReview, makes it hang, or runs
  code;
- a crafted input that makes a failing check report **pass**;
- a secret (token, password) copied into a report, log, error report or notification;
- SecReview sending anything beyond what the README documents.

Out of scope (open a regular issue instead):

- a weakness on your PC that SecReview does not check for: that is a missing check;
- a check that reports "could not check" where it could have answered.
