#!/usr/bin/env python3
"""DevOps Utility Script Collection — unified command-line entry point.

A single, secure CLI over a collection of DevOps automation tools: system
information, backups, file sync, archives, checksums, disk & log analysis,
process control, a network toolkit, Docker, SSH, service management, deployment
and resource monitoring.

Every command returns a uniform result that can be printed, emitted as JSON, or
written to a report file, and is recorded to an audit history database.

Run ``python main.py --help`` or ``python main.py <command> --help``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _force_utf8_streams() -> None:
    """Make stdout/stderr UTF-8 so rich glyphs and non-ASCII data never crash
    the CLI on a legacy Windows code page (cp1252). Best-effort and safe under
    pytest capture, where the streams are not reconfigurable."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - non-reconfigurable stream
                pass


_force_utf8_streams()

from core.base import OperationResult  # noqa: E402
from core.database import HistoryDB  # noqa: E402
from core.reporting import SUPPORTED_FORMATS, generate_report  # noqa: E402
from tools import (  # noqa: E402
    archive,
    backup,
    checksum,
    deploy,
    disk_tools,
    docker_tools,
    file_sync,
    log_analyzer,
    monitoring,
    network_tools,
    process_tools,
    service_manager,
    system_info,
)
from utils.config import Config  # noqa: E402
from utils.exceptions import DevOpsError  # noqa: E402
from utils.logging_config import setup_logging  # noqa: E402
from utils.security import load_dotenv  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent
__version__ = "1.0.0"

# Optional at runtime, always present for the type checker: rich is imported
# normally under TYPE_CHECKING so its real signatures are used, and degrades to
# plain prints at runtime when it is not installed.
if TYPE_CHECKING:
    from rich.console import Console
    from rich.table import Table

    _console: Console | None = Console()
else:
    try:
        from rich.console import Console
        from rich.table import Table

        _console = Console()
    except ImportError:  # pragma: no cover
        _console = None
        Console = Table = None


def _out(message: str) -> None:
    (_console.print if _console else print)(message)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def _common() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", metavar="FILE", help="Path to settings.yaml.")
    common.add_argument("--servers", metavar="FILE", help="Path to servers.yaml.")
    common.add_argument("--verbose", "-v", action="store_true", help="Enable DEBUG logging.")
    common.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    common.add_argument("--report", choices=list(SUPPORTED_FORMATS), help="Also write a report file.")
    common.add_argument("--output", "-o", metavar="DIR", help="Report output directory.")
    common.add_argument("--no-history", action="store_true", help="Do not record to the history DB.")
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(prog="devops", description="DevOps Utility Script Collection")
    parser.add_argument("--version", action="version", version=f"DevOps Utility Collection {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    sub.add_parser("system-info", parents=[common], help="Show host CPU/RAM/disk/OS/network info.")

    p = sub.add_parser("backup", parents=[common], help="Create/verify/restore/list backups.")
    p.add_argument("source", nargs="?", help="Directory to back up.")
    p.add_argument("--dest", help="Backup destination directory.")
    p.add_argument("--mode", choices=["full", "incremental"], default="full")
    p.add_argument("--restore", metavar="ARCHIVE", help="Restore this backup archive.")
    p.add_argument("--target", help="Restore target directory.")
    p.add_argument("--verify", metavar="ARCHIVE", help="Verify a backup archive.")
    p.add_argument("--list", action="store_true", help="List available backups.")

    p = sub.add_parser("sync", parents=[common], help="Synchronise two directories.")
    p.add_argument("source", help="Source directory.")
    p.add_argument("dest", help="Destination directory.")
    p.add_argument("--mode", choices=["one-way", "mirror", "two-way"], default="one-way")
    p.add_argument("--dry-run", action="store_true", help="Plan only; touch nothing.")

    p = sub.add_parser("checksum", parents=[common], help="Hash or verify files.")
    p.add_argument("paths", nargs="+", help="Files to hash.")
    p.add_argument("--algorithm", "-a", default="sha256", choices=list(checksum.SUPPORTED_ALGORITHMS))
    p.add_argument("--verify", metavar="DIGEST", help="Verify the single file against this digest.")

    p = sub.add_parser("archive", parents=[common], help="Create/extract/verify archives.")
    p.add_argument("--create", nargs="+", metavar="SRC", help="Sources to compress.")
    p.add_argument("--extract", metavar="ARCHIVE", help="Archive to extract.")
    p.add_argument("--verify", metavar="ARCHIVE", help="Archive to verify.")
    p.add_argument("--dest", help="Output archive path or extraction directory.")
    p.add_argument("--format", choices=["zip", "tar", "gztar", "bztar"], default="zip")

    p = sub.add_parser("disk", parents=[common], help="Disk usage, largest files, cleanup.")
    p.add_argument("path", nargs="?", default=".", help="Path to inspect.")
    p.add_argument("--largest", type=int, metavar="N", help="Show N largest files.")
    p.add_argument("--empty", action="store_true", help="List empty directories.")
    p.add_argument("--cleanup", action="store_true", help="Remove temporary files.")
    p.add_argument("--older-than", type=float, default=0, metavar="DAYS")
    p.add_argument("--force", action="store_true", help="Actually delete (disables dry-run).")

    p = sub.add_parser("logs", parents=[common], help="Analyse a log file.")
    p.add_argument("path", help="Log file to analyse.")
    p.add_argument("--keywords", nargs="*", help="Keywords to count.")

    p = sub.add_parser("processes", parents=[common], help="List or control processes.")
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--sort", choices=["cpu", "memory"], default="cpu")
    p.add_argument("--details", type=int, metavar="PID")
    p.add_argument("--kill", type=int, metavar="PID")
    p.add_argument("--suspend", type=int, metavar="PID")
    p.add_argument("--resume", type=int, metavar="PID")
    p.add_argument("--force", action="store_true", help="Skip the confirmation prompt.")

    p = sub.add_parser("ping", parents=[common], help="Ping a host.")
    p.add_argument("host")
    p.add_argument("--count", type=int, default=3)

    p = sub.add_parser("scan", parents=[common], help="Scan TCP ports on a host.")
    p.add_argument("host")
    p.add_argument("--ports", default="1-1024")

    p = sub.add_parser("dns", parents=[common], help="DNS forward/reverse lookup.")
    p.add_argument("host")

    p = sub.add_parser("http", parents=[common], help="HTTP(S) health check.")
    p.add_argument("url")
    p.add_argument("--expect", type=int, default=200)

    p = sub.add_parser("ssl", parents=[common], help="Check TLS certificate expiry.")
    p.add_argument("host")
    p.add_argument("--port", type=int, default=443)

    p = sub.add_parser("docker", parents=[common], help="Manage Docker containers/images.")
    p.add_argument("action", choices=["list", "start", "stop", "restart", "remove", "logs", "stats", "pull"])
    p.add_argument("target", nargs="?", help="Container name/id or image reference.")

    p = sub.add_parser("services", parents=[common], help="Query/control a system service.")
    p.add_argument("name")
    p.add_argument("action", choices=["status", "start", "stop", "restart", "enable", "disable"])

    p = sub.add_parser("deploy", parents=[common], help="Run a deployment pipeline.")
    p.add_argument("repo")
    p.add_argument("--branch")
    p.add_argument("--manager", choices=["pip", "npm"], default="pip")
    p.add_argument("--health-url")

    sub.add_parser("monitor", parents=[common], help="Sample CPU/memory/disk against thresholds.")

    p = sub.add_parser("history", parents=[common], help="Show the operation history.")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--tool")
    p.add_argument("--summary", action="store_true")

    sub.add_parser("config", parents=[common], help="Print the effective configuration.")

    return parser


# ---------------------------------------------------------------------------
# Command handlers — each returns an OperationResult or a list of them.
# ---------------------------------------------------------------------------
def cmd_system_info(args, cfg, db):
    return system_info.collect_system_info()


def cmd_backup(args, cfg, db):
    roots = cfg.allowed_roots()
    if args.list:
        dest = args.dest or cfg.get("backup.destination", "backups")
        entries = backup.list_backups(dest)
        _out(json.dumps(entries, indent=2) if args.json else _format_list("Backups", entries))
        return None
    if args.verify:
        return backup.verify_backup(args.verify)
    if args.restore:
        target = args.target or "restore"
        return backup.restore_backup(args.restore, target, allowed_roots=roots)
    if not args.source:
        raise DevOpsError("backup: provide a source directory (or use --list/--verify/--restore)")
    dest = args.dest or cfg.get("backup.destination", "backups")
    return backup.create_backup(
        args.source, dest, mode=args.mode, allowed_roots=roots,
        verify=cfg.get("backup.verify", True), keep_versions=cfg.get("backup.keep_versions", 5),
    )


def cmd_sync(args, cfg, db):
    return file_sync.sync(args.source, args.dest, mode=args.mode,
                          dry_run=args.dry_run, allowed_roots=cfg.allowed_roots())


def cmd_checksum(args, cfg, db):
    if args.verify:
        if len(args.paths) != 1:
            raise DevOpsError("--verify expects exactly one file")
        return checksum.verify_paths({args.paths[0]: args.verify}, algorithm=args.algorithm)
    return checksum.hash_paths(args.paths, algorithm=args.algorithm)


def cmd_archive(args, cfg, db):
    roots = cfg.allowed_roots()
    if args.create:
        if not args.dest:
            raise DevOpsError("archive --create requires --dest")
        return archive.create_archive(args.create, args.dest, fmt=args.format, allowed_roots=roots)
    if args.extract:
        if not args.dest:
            raise DevOpsError("archive --extract requires --dest")
        return archive.extract_archive(args.extract, args.dest, allowed_roots=roots)
    if args.verify:
        return archive.verify_archive(args.verify)
    raise DevOpsError("archive: choose --create, --extract or --verify")


def cmd_disk(args, cfg, db):
    if args.largest:
        return disk_tools.largest_files(args.path, top=args.largest)
    if args.empty:
        return disk_tools.empty_dirs(args.path)
    if args.cleanup:
        return disk_tools.cleanup_temp(args.path, older_than_days=args.older_than,
                                       dry_run=not args.force, allowed_roots=cfg.allowed_roots())
    return disk_tools.disk_usage(args.path)


def cmd_logs(args, cfg, db):
    return log_analyzer.analyze_log(args.path, keywords=args.keywords)


def cmd_processes(args, cfg, db):
    for verb, pid in (("kill", args.kill), ("suspend", args.suspend), ("resume", args.resume)):
        if pid is not None:
            if not args.force and not _confirm(f"Really {verb} PID {pid}?"):
                raise DevOpsError("Aborted by user")
            return process_tools.control_process(pid, verb)
    if args.details is not None:
        return process_tools.process_details(args.details)
    return process_tools.list_processes(top=args.top, sort_by=args.sort)


def cmd_ping(args, cfg, db):
    return network_tools.ping(args.host, count=args.count, timeout=cfg.get("network.timeout", 3.0))


def cmd_scan(args, cfg, db):
    return network_tools.scan_ports(args.host, args.ports, timeout=cfg.get("network.port_scan_timeout", 0.5))


def cmd_dns(args, cfg, db):
    return network_tools.dns_lookup(args.host)


def cmd_http(args, cfg, db):
    return network_tools.http_health(args.url, expect=args.expect, timeout=cfg.get("network.timeout", 5.0))


def cmd_ssl(args, cfg, db):
    return network_tools.ssl_expiry(args.host, port=args.port)


def cmd_docker(args, cfg, db):
    if args.action == "list":
        return docker_tools.list_containers()
    if not args.target:
        raise DevOpsError(f"docker {args.action} requires a target")
    if args.action == "logs":
        return docker_tools.container_logs(args.target)
    if args.action == "stats":
        return docker_tools.container_stats(args.target)
    if args.action == "pull":
        return docker_tools.pull_image(args.target)
    return docker_tools.container_action(args.target, args.action)


def cmd_services(args, cfg, db):
    return service_manager.manage_service(args.name, args.action)


def cmd_deploy(args, cfg, db):
    return deploy.deploy(args.repo, branch=args.branch, manager=args.manager, health_url=args.health_url)


def cmd_monitor(args, cfg, db):
    return monitoring.snapshot(cfg.get("monitoring"))


def cmd_history(args, cfg, db):
    if db is None:
        raise DevOpsError("History database unavailable")
    payload = db.summary() if args.summary else db.recent(tool=args.tool, limit=args.limit)
    _print_json(payload)
    return None


def cmd_config(args, cfg, db):
    _print_json({"settings": cfg.settings, "servers": cfg.servers})
    return None


_HANDLERS: dict[str, Callable] = {
    "system-info": cmd_system_info, "backup": cmd_backup, "sync": cmd_sync,
    "checksum": cmd_checksum, "archive": cmd_archive, "disk": cmd_disk, "logs": cmd_logs,
    "processes": cmd_processes, "ping": cmd_ping, "scan": cmd_scan, "dns": cmd_dns,
    "http": cmd_http, "ssl": cmd_ssl, "docker": cmd_docker, "services": cmd_services,
    "deploy": cmd_deploy, "monitor": cmd_monitor, "history": cmd_history, "config": cmd_config,
}


# ---------------------------------------------------------------------------
# Output, history and reporting
# ---------------------------------------------------------------------------
def _confirm(question: str) -> bool:  # pragma: no cover - interactive
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def _format_list(title: str, entries: list) -> str:
    if not entries:
        return f"{title}: none"
    return f"{title}:\n" + "\n".join(f"  - {json.dumps(e, default=str)}" for e in entries)


def _print_json(obj) -> None:
    # Plain stdout, never the rich console — rich soft-wraps long lines, which
    # would insert newlines inside string values and corrupt the JSON.
    print(json.dumps(obj, indent=2, default=str))


def _emit(results: Sequence[OperationResult], args) -> None:
    if args.json:
        _print_json([r.as_dict() for r in results])
        return
    if _console is not None and Table is not None:
        for r in results:
            _render_result(_console, r)
    else:  # pragma: no cover - rich always present in practice
        for r in results:
            print(f"[{r.status.value.upper()}] {r.tool}.{r.action}: {r.message}")


def _render_result(console: Console, r: OperationResult) -> None:
    # The console is passed in rather than read from the module global so the
    # "rich is missing" branch above is the only place that has to think about
    # it being None.
    colour = {"success": "green", "dry_run": "cyan", "partial": "yellow",
              "skipped": "grey58", "failure": "red"}.get(r.status.value, "white")
    console.print(f"[{colour}]● {r.status.value.upper()}[/{colour}]  "
                  f"[bold]{r.tool}.{r.action}[/bold]  {r.message}  "
                  f"[grey58]({r.duration_ms} ms)[/grey58]")
    for warn in r.warnings:
        console.print(f"    [yellow]! {warn}[/yellow]")
    for err in r.errors:
        console.print(f"    [red]✗ {err}[/red]")
    if r.data:
        console.print_json(json.dumps(r.data, default=str))


def _record(results: Sequence[OperationResult], db: HistoryDB | None, args) -> None:
    if db is None or args.no_history:
        return
    for r in results:
        try:
            db.record(r)
        except DevOpsError:  # pragma: no cover
            pass


def _maybe_report(results: Sequence[OperationResult], cfg: Config, args) -> None:
    if not args.report:
        return
    out_dir = args.output or (PROJECT_ROOT / cfg.get("reporting.directory", "reports"))
    path = generate_report(results, fmt=args.report, output_dir=out_dir, allowed_roots=cfg.allowed_roots())
    _out(f"[green]Report written: {path}[/green]" if _console else f"Report written: {path}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def _open_db(cfg: Config):
    if _current_args and _current_args.no_history:
        return None
    try:
        db = HistoryDB(PROJECT_ROOT / cfg.get("database.path", "database/history.db"))
        db.prune(int(cfg.get("database.retention_days", 90)))
        return db
    except DevOpsError as exc:  # pragma: no cover
        _out(f"History disabled: {exc}")
        return None


_current_args: argparse.Namespace | None = None


def main(argv: list[str] | None = None) -> int:
    global _current_args
    parser = build_parser()
    args = parser.parse_args(argv)
    _current_args = args
    if not args.command:
        parser.print_help()
        return 0

    load_dotenv(PROJECT_ROOT / ".env")
    cfg = Config.load(getattr(args, "config", None), getattr(args, "servers", None))
    log_cfg = dict(cfg.settings.get("logging", {}))
    if args.verbose:
        log_cfg["level"] = "DEBUG"
    setup_logging(log_cfg, root=PROJECT_ROOT)
    db = _open_db(cfg)

    try:
        outcome = _HANDLERS[args.command](args, cfg, db)
        if outcome is None:  # handler printed its own output
            return 0
        results = outcome if isinstance(outcome, list) else [outcome]
        _emit(results, args)
        _record(results, db, args)
        _maybe_report(results, cfg, args)
        return 0 if all(r.ok for r in results) else 1
    except DevOpsError as exc:
        _out(f"[red]Error: {exc}[/red]" if _console else f"Error: {exc}")
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    except OSError as exc:
        # A handler that touches the filesystem outside a timed() block (e.g.
        # listing backups) could surface an OSError — render it cleanly rather
        # than dumping a traceback at the user.
        _out(f"[red]Unexpected error: {exc}[/red]" if _console else f"Unexpected error: {exc}")
        return 3
    finally:
        if db is not None:
            db.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
