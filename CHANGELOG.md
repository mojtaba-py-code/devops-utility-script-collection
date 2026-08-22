# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - Unreleased

### Security

- `safe_run` now runs only the binary the allow-list actually vetted: a command
  must be a bare program name, it is resolved on `PATH`, re-checked against the
  allow-list, and refused when it resolves into the working directory or the
  system temp tree.
- ZIP extraction refuses symlink members, and the deployment health check is
  bounded so a hostile endpoint cannot hold the pipeline open.
- Reading a TLS certificate requires TLS 1.2 or better.
- CI fails the build when a credential-shaped value (AWS id, PEM private-key
  header, GitHub/Slack/Stripe/Google token, Slack webhook) is committed, or
  when `.env` is tracked.
- `.gitignore` covers certificates, keystores and credential files.

### Added

- Contributing guide, security policy and status badges.
- A recorded terminal session in the README.

### Changed

- `mypy` requires a full signature on every function in `core`, `tools`,
  `utils` and `main.py`; all nineteen CLI handlers are annotated.
- CI measures coverage and fails below an 85% floor; the README states the
  floor it enforces rather than a frozen percentage.
- `ruff` and `mypy` run on every push, and the security scans re-run weekly.
- GitHub Actions are pinned to commit SHAs and the workflow token is scoped to
  read.
- Dependencies tracked by Dependabot: docker, requests, pyyaml, rich, psutil,
  paramiko and the dev-tooling group.

## [1.0.0] - 2026-08-04

### Added

- DevOps Utility Script Collection: a security-first Python CLI over fifteen
  tools — system info, backups, file sync, checksums, archives, disk and log
  analysis, process control, a network toolkit, Docker, SSH, service
  management, deployment and resource monitoring.
- A uniform `OperationResult` contract with JSON/CSV/TXT/HTML/PDF reporting and
  a SQLite audit history.
- CI: the pytest suite on Python 3.11 and 3.12, a Bandit SAST job that fails on
  any medium-or-higher finding, and a pip-audit dependency scan.

### Security

- Hardened archive extraction against Zip-Slip / Tar-Slip, and documented the
  reviewed SSH exceptions.

[1.1.0]: https://github.com/mojtaba-py-code/devops-utility-script-collection/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mojtaba-py-code/devops-utility-script-collection/releases/tag/v1.0.0
