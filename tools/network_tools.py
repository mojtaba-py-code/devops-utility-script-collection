"""Network toolkit: ping, port scan, DNS, HTTP health and TLS expiry checks.

Every host/port is validated before use (defeating argument-injection into the
resolver or socket layer), scans are bounded by a timeout, and the port scanner
fans out across a :class:`~concurrent.futures.ThreadPoolExecutor` so a /24 sweep
finishes in seconds instead of minutes.
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from core.base import OperationResult, timed
from utils.exceptions import ToolError
from utils.logging_config import get_logger
from utils.security import (
    safe_run,
    validate_host,
    validate_http_url,
    validate_port,
    validate_port_range,
)

# Optional at runtime, always present for the type checker: the module is
# imported normally under TYPE_CHECKING so its real signatures are used,
# and falls back to None at runtime when it is not installed.
if TYPE_CHECKING:
    import requests
else:
    try:
        import requests
    except ImportError:  # pragma: no cover
        requests = None

_log = get_logger("network_tools")


def ping(host: str, *, count: int = 3, timeout: float = 3.0) -> OperationResult:
    """Ping *host* using the platform's ``ping`` binary; parse reachability."""
    with timed("network_tools", "ping") as result:
        import platform

        host = validate_host(host)
        count = max(1, min(int(count), 20))
        flag = "-n" if platform.system() == "Windows" else "-c"
        # Named, never pathed: ``safe_run`` resolves ``ping`` on PATH, re-checks
        # the file it landed on against the allow-list and refuses a copy
        # planted in the working directory or the temp tree — the same rule
        # every other sub-process in the toolkit goes through. The host is
        # already validated above, so the argv carries no injectable text.
        proc = safe_run(["ping", flag, str(count), host], timeout=timeout * count + 5)
        reachable = proc.returncode == 0
        result.data = {"host": host, "reachable": reachable, "count": count,
                       "output": proc.stdout.strip()[-500:]}
        result.status = result.status.SUCCESS if reachable else result.status.FAILURE
        result.finalize(f"{host} is {'reachable' if reachable else 'unreachable'}")
    return result


def _probe_port(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def scan_ports(
    host: str, ports: str = "1-1024", *, timeout: float = 0.5, workers: int = 100
) -> OperationResult:
    """Concurrently scan *ports* on *host*; report which are open."""
    with timed("network_tools", "scan") as result:
        host = validate_host(host)
        port_list = validate_port_range(ports)
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=min(workers, len(port_list))) as pool:
            futures = {pool.submit(_probe_port, host, p, timeout): p for p in port_list}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except OSError:  # pragma: no cover
                    continue
        open_ports.sort()
        result.data = {"host": host, "scanned": len(port_list), "open_ports": open_ports}
        result.finalize(f"{len(open_ports)} open port(s) on {host}")
        _log.info("network_tools: scanned %d ports on %s, %d open", len(port_list), host, len(open_ports))
    return result


def tcp_check(host: str, port: int, *, timeout: float = 3.0) -> OperationResult:
    """Test a single TCP connection to *host*:*port*."""
    with timed("network_tools", "tcp_check") as result:
        host, port = validate_host(host), validate_port(port)
        is_open = _probe_port(host, port, timeout)
        result.data = {"host": host, "port": port, "open": is_open}
        result.status = result.status.SUCCESS if is_open else result.status.FAILURE
        result.finalize(f"{host}:{port} is {'open' if is_open else 'closed'}")
    return result


def dns_lookup(host: str) -> OperationResult:
    """Forward and reverse DNS resolution for *host*."""
    with timed("network_tools", "dns") as result:
        host = validate_host(host)
        # getaddrinfo's sockaddr is typed as a union covering IPv4/IPv6/other
        # families; the first element is the address string in every family we
        # can reach here, so name it as such rather than indexing a union.
        addresses = sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None)})
        reverse: dict[str, str] = {}
        for addr in addresses:
            try:
                reverse[addr] = socket.gethostbyaddr(addr)[0]
            except (socket.herror, socket.gaierror):
                reverse[addr] = ""
        result.data = {"host": host, "addresses": addresses, "reverse": reverse}
        result.finalize(f"{host} resolves to {len(addresses)} address(es)")
    return result


def http_health(url: str, *, timeout: float = 5.0, expect: int = 200) -> OperationResult:
    """HTTP(S) health check: request *url* and compare the status code."""
    with timed("network_tools", "http_health") as result:
        if requests is None:  # pragma: no cover
            from utils.exceptions import DependencyError

            raise DependencyError("http health checks require 'requests'")
        url = validate_http_url(url)
        session = requests.Session()
        # An unbounded redirect chain turns a health check into a way to hang
        # the caller (or walk it somewhere unexpected); three hops is plenty
        # for the load-balancer and trailing-slash redirects that are normal here.
        session.max_redirects = 3
        response = session.get(url, timeout=timeout, allow_redirects=True)
        healthy = response.status_code == expect
        result.data = {
            "url": url,
            "status_code": response.status_code,
            "expected": expect,
            "healthy": healthy,
            "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
        }
        result.status = result.status.SUCCESS if healthy else result.status.FAILURE
        result.finalize(f"{url} -> {response.status_code} ({'ok' if healthy else 'unexpected'})")
    return result


def ssl_expiry(host: str, *, port: int = 443, timeout: float = 5.0) -> OperationResult:
    """Check the TLS certificate expiry for *host*:*port*."""
    with timed("network_tools", "ssl_expiry") as result:
        host, port = validate_host(host), validate_port(port)
        context = ssl.create_default_context()
        # create_default_context() still permits TLS 1.0/1.1 on older Python
        # builds. Both are deprecated and a host that only offers them has a
        # worse problem than a soon-to-expire certificate, so refuse the
        # handshake rather than report a reassuring expiry date over it.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        # getpeercert() is typed loosely (values may be strings or nested
        # tuples); narrow the two fields we actually read.
        not_after = str(cert.get("notAfter", "")) if cert else ""
        if not not_after:
            raise ToolError(f"{host}:{port} presented no certificate expiry")
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        days_left = (expires - datetime.now(UTC)).days
        issuer_rdns: Any = cert.get("issuer", ()) if cert else ()
        result.data = {
            "host": host, "port": port,
            "expires": expires.isoformat(),
            "days_left": days_left,
            "issuer": dict(rdn[0] for rdn in issuer_rdns if rdn),
        }
        if days_left < 0:
            result.fail(f"Certificate for {host} EXPIRED {abs(days_left)} day(s) ago")
        elif days_left < 14:
            result.add_warning(f"Certificate for {host} expires in {days_left} day(s)")
            result.finalize(f"{host} certificate expires in {days_left} day(s)")
        else:
            result.finalize(f"{host} certificate valid for {days_left} more day(s)")
    return result
