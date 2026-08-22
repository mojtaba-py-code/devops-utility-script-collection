# DevOps Utility Script Collection

[![CI](https://github.com/mojtaba-py-code/devops-utility-script-collection/actions/workflows/ci.yml/badge.svg)](https://github.com/mojtaba-py-code/devops-utility-script-collection/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org)
[![Typed](https://img.shields.io/badge/typed-mypy-2A6DB2.svg)](https://mypy-lang.org/)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A585%25%20enforced%20in%20CI-brightgreen.svg)](.github/workflows/ci.yml)
[![Ruff](https://img.shields.io/badge/style-ruff-D7FF64.svg)](https://docs.astral.sh/ruff/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Deps: pip-audit](https://img.shields.io/badge/deps-pip--audit-orange.svg)](https://github.com/pypa/pip-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-grade, security-first toolkit of DevOps automation utilities behind
a single command-line interface. It bundles the day-to-day tasks a system
administrator, DevOps or cloud engineer reaches for — backups, file sync,
archives, checksums, disk & log analysis, process control, a network toolkit,
Docker, SSH, service management, deployment and resource monitoring — into one
consistent, well-tested, cross-platform tool.

Every operation returns a uniform result that can be printed, emitted as JSON,
written to a report (JSON/CSV/TXT/HTML/PDF), and recorded to an audit history
database.

- **Python:** 3.11+ (CI runs 3.11 and 3.12)
- **Platforms:** Windows, Linux, macOS
- **Tests:** 173 passing · coverage **≥85% enforced in CI**
- **Checks:** `ruff` · `mypy` · `bandit` · `pip-audit`, all enforced in CI
- **License:** MIT

---

## Highlights

- **Secure by design.** Path-traversal / Zip-Slip protection, command
  allow-listing (no shell), symlink-write refusal, protected-path deletion
  guards, input validation for hosts/ports/PIDs, secrets sourced only from the
  environment, and automatic secret redaction in logs.
- **Uniform result model.** Every tool returns an `OperationResult`
  (`status`, `message`, `data`, `errors`, `warnings`, timing) — so output,
  reporting and history all speak one language.
- **Graceful degradation.** Optional integrations (Docker, Paramiko, reportlab)
  are imported lazily; a host without them still runs everything else.
- **Auditability.** Each run is recorded to a SQLite history table with a
  queryable summary.
- **Cross-platform.** Service management, ping and paths adapt to the OS;
  output is UTF-8 safe even on a legacy Windows code page.

---

## Installation

```bash
git clone <your-repo-url>
cd "6 DevOps Utility Script Collection"

python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/mac: source .venv/bin/activate

pip install -r requirements.txt          # runtime
pip install -r requirements-dev.txt      # + test/optional deps
```

Copy the environment template and fill in any secrets you need:

```bash
cp .env.example .env        # never commit .env
```

---

## Quick start

```bash
python main.py --help                       # list all commands
python main.py system-info                  # host CPU/RAM/disk/OS/network
python main.py backup ./src --dest ./backups --mode full
python main.py sync ./src ./mirror --mode mirror --dry-run
python main.py checksum file.iso -a sha256
python main.py disk . --largest 10
python main.py logs /var/log/app.log --keywords error timeout
python main.py ping example.com
python main.py scan 10.0.0.5 --ports 1-1024
python main.py ssl example.com
python main.py monitor
python main.py docker list
python main.py deploy /srv/app --branch main --health-url http://localhost:8000/health
```

Four of them on a real run — a verified backup, a mirror sync that reports what
it *would* do before touching anything, and two live network checks:

![Terminal session: full backup, dry-run mirror sync, TLS expiry check and an
HTTP health check](docs/images/session.png)

Every command prints a one-line status followed by a JSON result, so the same
invocation works for a human reading a terminal and for a script piping into
`jq`. `--dry-run` is available wherever an operation writes — above it listed
the three files it would copy and deleted nothing — and `disk cleanup`, the one
command that deletes by nature, is dry-run *by default* and needs `--force`.

### Global flags

| Flag | Purpose |
|------|---------|
| `--config FILE` | Alternative `settings.yaml` |
| `--servers FILE` | Alternative `servers.yaml` inventory |
| `--json` | Machine-readable JSON output |
| `--report {json,csv,txt,html,pdf}` | Also write a report file |
| `--output DIR` | Report output directory |
| `--verbose` | DEBUG logging |
| `--no-history` | Do not record the run to the history DB |
| `--dry-run` / `--force` | Plan-only vs. actually apply (destructive actions) |

---

## Commands

| Command | What it does |
|---------|--------------|
| `system-info` | CPU, RAM, disk, OS, hostname, IP/MAC, uptime, Python version |
| `backup` | Full/incremental backups, verify, restore, versioning, list |
| `sync` | One-way / mirror / two-way directory sync with SHA-256 diffing |
| `checksum` | MD5/SHA-1/SHA-256/SHA-512 generate & verify |
| `archive` | Create / extract / verify ZIP, TAR, GZIP, BZIP2 (Zip-Slip safe) |
| `disk` | Usage, largest files, empty dirs, temp-file cleanup |
| `logs` | Error/warning counts, IP extraction, threat heuristics |
| `processes` | List by CPU/memory, details, safe kill/suspend/resume |
| `ping` `scan` `dns` `http` `ssl` | Network toolkit |
| `docker` | list / start / stop / restart / remove / logs / stats / pull |
| `services` | status / start / stop / restart / enable / disable (systemctl \| sc) |
| `deploy` | git pull → install → health check, auto-rollback on failure |
| `monitor` | Sample CPU/memory/disk against thresholds with severity |
| `history` | Audit trail of past runs (with `--summary`) |
| `config` | Print the effective configuration |

Run `python main.py <command> --help` for per-command options.

---

## Architecture

```
main.py                 # argparse CLI: dispatch, emit, record, report
core/
  base.py               # OperationResult / Status + timed() context manager
  database.py           # SQLite run-history (audit trail)
  reporting.py          # JSON / CSV / TXT / HTML / PDF renderers
tools/
  system_info.py  backup.py     file_sync.py    checksum.py
  archive.py      disk_tools.py  log_analyzer.py process_tools.py
  network_tools.py docker_tools.py ssh_tools.py  service_manager.py
  deploy.py       monitoring.py  notify.py
utils/
  security.py           # path/command/input validation, secrets, redaction
  config.py             # layered YAML config with ${ENV} expansion
  logging_config.py     # rotating, per-domain, secret-redacting logs
  formatting.py         # human-readable bytes/durations/timestamps
config/                 # settings.yaml, servers.yaml, logging.yaml
tests/                  # 173 tests, coverage floor enforced in CI
```

**Design principles:** modular single-responsibility tools, a shared result
contract, dependency-light imports, and a security module that every
side-effectful path is routed through.

---

## Security

Security is enforced centrally in `utils/security.py` and applied everywhere:

- **Path safety** — writes/deletes are resolved, refused through symlinks, and
  confined to `security.allowed_roots` when set; filesystem roots and known
  system directories can never be deleted.
- **Archive extraction** — every member is validated against the destination
  before writing, defeating Zip-Slip / Tar-Slip; link members are rejected.
- **Command execution** — every sub-process the toolkit starts goes through the
  single `safe_run` helper, so only an allow-listed binary can ever run: the
  caller names one (never a path), it is resolved on `PATH`, the file that
  resolution landed on is re-checked against the allow-list, and a resolution
  into the working directory or the temp tree is refused — always with
  `shell=False` and a timeout (no shell injection, no planted binaries, no
  hangs).
- **Input validation** — hosts, ports, port ranges and PIDs are validated;
  PID 0/1 are protected from signals.
- **Secrets** — credentials come only from environment variables / `.env`
  (never config or argv) and are redacted from all logs.

Run the test-suite's security checks directly:

```bash
pytest tests/test_security.py -v
```

---

## Configuration

`config/settings.yaml` overrides the built-in defaults; secrets are referenced
by environment-variable name using `${VAR}` expansion. `config/servers.yaml`
holds the remote host inventory for SSH/deploy — again with credentials named,
not stored. See `.env.example` for the expected variables.

---

## Testing

```bash
pytest                                  # run everything
pytest --cov=core --cov=tools --cov=utils --cov=main --cov-report=term-missing
```

CI runs the second form with `--cov-fail-under=85`, so a change that drops
coverage below the floor fails the build rather than the badge quietly lying.

The suite is hermetic: Docker/SSH are exercised through injected fakes, the
network toolkit runs against localhost sockets and mocks, and no test touches a
real remote host or the production history database.

---

## License

Released under the [MIT License](LICENSE). © 2026 Mojtaba Karimi.
