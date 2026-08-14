"""Log analyzer: counts, keyword search, IP extraction and threat heuristics.

Log files can be large, so the analyzer streams line-by-line rather than
reading the whole file into memory. Beyond simple error/warning counts it
extracts client IPs and flags a few well-known suspicious patterns (auth
failures, traversal attempts, SQL-injection probes), producing a compact
security-oriented summary.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from core.base import OperationResult, timed
from utils.exceptions import ValidationError
from utils.logging_config import get_logger

_log = get_logger("log_analyzer")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b", re.IGNORECASE)

# (label, compiled pattern) — deliberately conservative to limit false positives.
_SUSPICIOUS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "auth_failure",
        re.compile(r"(failed password|authentication failure|invalid user|access denied)", re.I),
    ),
    ("path_traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.I)),
    ("sql_injection", re.compile(r"(union\s+select|or\s+1=1|';--|xp_cmdshell)", re.I)),
    ("xss_attempt", re.compile(r"(<script>|javascript:|onerror=)", re.I)),
    ("suspicious_agent", re.compile(r"(sqlmap|nikto|nmap|masscan|acunetix)", re.I)),
)


def _iter_lines(path: Path) -> Iterable[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        yield from handle


def analyze_log(
    path: str | Path,
    *,
    keywords: list[str] | None = None,
    top_ips: int = 10,
) -> OperationResult:
    """Analyse a single log file and return counts, IPs and threat findings."""
    with timed("log_analyzer", "analyze") as result:
        file_path = Path(path)
        if not file_path.is_file():
            raise ValidationError(f"Not a file: {file_path}")

        levels: Counter[str] = Counter()
        ip_counter: Counter[str] = Counter()
        keyword_hits: dict[str, int] = {kw: 0 for kw in (keywords or [])}
        threats: dict[str, list[dict[str, Any]]] = {label: [] for label, _ in _SUSPICIOUS}
        total = 0

        for lineno, line in enumerate(_iter_lines(file_path), start=1):
            total += 1
            match = _LEVEL_RE.search(line)
            if match:
                levels[_normalize_level(match.group(1))] += 1
            for ip in _IPV4_RE.findall(line):
                if _valid_ipv4(ip):
                    ip_counter[ip] += 1
            for kw in keyword_hits:
                if kw.lower() in line.lower():
                    keyword_hits[kw] += 1
            for label, pattern in _SUSPICIOUS:
                if pattern.search(line):
                    if len(threats[label]) < 50:  # cap evidence to keep report bounded
                        threats[label].append({"line": lineno, "text": line.strip()[:200]})

        findings = {label: hits for label, hits in threats.items() if hits}
        result.data = {
            "file": str(file_path),
            "lines": total,
            "errors": levels.get("ERROR", 0) + levels.get("CRITICAL", 0),
            "warnings": levels.get("WARNING", 0),
            "levels": dict(levels),
            "top_ips": [{"ip": ip, "count": n} for ip, n in ip_counter.most_common(top_ips)],
            "unique_ips": len(ip_counter),
            "keywords": keyword_hits,
            "suspicious": {label: len(hits) for label, hits in findings.items()},
            "suspicious_detail": findings,
        }
        threat_total = sum(len(h) for h in findings.values())
        if threat_total:
            result.add_warning(f"{threat_total} suspicious line(s) across {len(findings)} categor(y/ies)")
        result.finalize(
            f"{total} line(s): {result.data['errors']} error(s), "
            f"{result.data['warnings']} warning(s), {threat_total} suspicious"
        )
        _log.info("log_analyzer: %s -> %d lines, %d threats", file_path.name, total, threat_total)
    return result


def _normalize_level(token: str) -> str:
    token = token.upper()
    return {"WARN": "WARNING", "FATAL": "CRITICAL"}.get(token, token)


def _valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
