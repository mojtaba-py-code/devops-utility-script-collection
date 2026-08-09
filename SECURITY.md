# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Security fixes are applied to `main` and released from there.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's
[Report a vulnerability](https://github.com/mojtaba-py-code/devops-utility-script-collection/security/advisories/new)
form, or by email to **mojtaba.python@gmail.com**.

Include what you can:

- the affected version, tag or commit,
- what the issue is and what an attacker gains from it,
- steps or a minimal proof of concept that reproduces it.

## What to expect

- Acknowledgement within **72 hours**.
- An initial assessment within **7 days**.
- A fix and a published advisory once a patch is ready.
- Credit in the advisory, if you want it.

## Scope

This toolkit runs privileged operations — it deletes and restores files, opens
SSH sessions, drives Docker, manages services and deploys. Anything that lets a
caller reach further than the command they invoked is a security issue. In
particular:

- command or argument injection in any tool under `tools/`,
- path traversal in the backup, sync, archive or checksum commands,
- a credential (SSH key, password, token, webhook URL) reaching a log line, a
  report file, or the audit history database,
- a destructive command running without its confirmation or dry-run gate.

Out of scope:

- Vulnerabilities in third-party dependencies — report those upstream; if this
  project's use of a dependency is what makes it exploitable, that *is* in scope.
- Findings that require an attacker to already control the host or the process,
  or that amount to "a user with the credentials can use the credentials".

## Automated checks

CI runs on every push and pull request:

- **Bandit** (`bandit -r . -x ./tests --severity-level medium`) — static analysis,
  the build fails on medium-or-higher findings.
- **pip-audit** (`pip-audit -r requirements.txt`) — known CVEs in dependencies.

These catch common mistakes; they are not a substitute for a report.

## Notes for operators

- Credentials come from the environment or your config file, never from the
  source. Do not commit a populated `.env`.
- Reports (`--report json|csv|txt|html|pdf`) and the audit history can contain
  hostnames, paths and command output. Treat them as sensitive.
- Run destructive commands with a dry run first.
