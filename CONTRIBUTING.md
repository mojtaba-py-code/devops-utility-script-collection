# Contributing

Thanks for taking a look. This is how the project is developed locally and what
CI expects before a change lands.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env
```

`requirements.txt` holds the runtime dependencies; `requirements-dev.txt` pulls
those in and adds the test tooling plus the optional integrations (`docker`,
`paramiko`) so their imports resolve during tests. Optional extras that only
some commands need — `reportlab` for PDF reports — are listed as comments in
`requirements.txt`; install them when you touch that command.

## Before you push

These are exactly the steps CI runs, so run them locally first:

```bash
pytest -q
bandit -r . -x ./tests --severity-level medium
pip-audit -r requirements.txt
```

The test job runs on Python 3.11 and 3.12; the security job runs on 3.12.

## Conventions

- **One uniform result.** Every tool returns the same result object so it can be
  printed, emitted as JSON, written to a report and recorded to the audit
  history without special-casing. A new tool in `tools/` follows that contract.
- **Security first.** No shell string interpolation — build argument lists and
  avoid `shell=True`. Bandit runs in CI at medium severity and is not to be
  silenced with a blanket `# nosec`; if a finding is genuinely a false positive,
  narrow the ignore and say why in the PR.
- **Destructive operations ask first.** Anything that deletes, overwrites or
  restarts must support a dry run and require explicit confirmation.
- **Cross-platform.** The toolkit targets Linux, macOS and Windows. Use
  `pathlib` and guard platform-specific behaviour.
- **Secrets** come from the environment or the config, never from a literal in
  the source, and never reach a log line or a report.
- **Tests.** Add tests with the change. Docker, SSH and network calls are
  exercised through mocks — a test must never touch a real host.
- **Commits.** Short imperative subject, a body explaining the *why*.

## Reporting a security problem

Do not open a public issue — see [SECURITY.md](SECURITY.md).
