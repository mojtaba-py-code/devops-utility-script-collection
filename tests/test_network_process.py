"""Tests for the network toolkit and process manager.

Network tests avoid the public internet: the port scanner and TCP check run
against a real socket bound to localhost, and DNS resolves ``localhost``.
Outbound HTTP/TLS/ping are exercised through mocks.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from tools import network_tools, process_tools
from utils import security


@pytest.fixture
def open_port():
    """Bind a listening socket on localhost and yield its port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        yield port
    finally:
        srv.close()


def test_tcp_check_open_and_closed(open_port: int):
    ok = network_tools.tcp_check("127.0.0.1", open_port)
    assert ok.ok and ok.data["open"]
    from utils.security import free_tcp_port

    closed = network_tools.tcp_check("127.0.0.1", free_tcp_port())
    assert not closed.ok


def test_scan_ports_finds_open(open_port: int):
    result = network_tools.scan_ports("127.0.0.1", f"{open_port}", timeout=0.5)
    assert result.ok
    assert open_port in result.data["open_ports"]


def test_scan_ports_validates_host():
    result = network_tools.scan_ports("bad host!", "22")
    assert not result.ok


def test_dns_lookup_localhost():
    result = network_tools.dns_lookup("localhost")
    assert result.ok
    assert result.data["addresses"]


def test_ping_mocked(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(command, **kwargs):
        seen.append(list(command))
        return SimpleNamespace(returncode=0, stdout="1 received")

    monkeypatch.setattr(network_tools, "safe_run", fake_run)
    result = network_tools.ping("example.com", count=1)
    assert result.ok and result.data["reachable"]
    # The hardened path is the one that runs it: a bare, allow-listed name that
    # ``safe_run`` resolves and vets, never a caller-supplied path.
    argv = seen[0]
    assert argv[0] == "ping"
    assert security._is_allow_listed(argv[0])
    assert argv[1] in ("-n", "-c") and argv[2] == "1" and argv[3] == "example.com"


def test_ping_unreachable_mocked(monkeypatch):
    monkeypatch.setattr(
        network_tools, "safe_run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="timeout"),
    )
    result = network_tools.ping("10.255.255.1", count=1)
    assert not result.ok


def test_ping_refuses_a_binary_it_cannot_vet(monkeypatch):
    """``ping`` now goes through the allow-list, so a failed vet stops the run."""
    monkeypatch.setattr(security.shutil, "which", lambda name: None)
    result = network_tools.ping("example.com", count=1)
    assert not result.ok
    assert any("SecurityError" in err for err in result.errors)


def _mock_session(monkeypatch, status_code):
    """Replace requests.Session so no test ever reaches the real network.

    Returns the list of sessions the code under test constructed, so a caller
    can assert on how each one was configured.
    """
    created = []

    class _Resp:
        elapsed = SimpleNamespace(total_seconds=lambda: 0.01)

    _Resp.status_code = status_code

    class _Session:
        def __init__(self):
            self.max_redirects = 30  # requests' default
            created.append(self)

        def get(self, *a, **k):
            return _Resp()

    monkeypatch.setattr(network_tools.requests, "Session", _Session)
    return created


def test_http_health_mocked(monkeypatch):
    _mock_session(monkeypatch, 200)
    result = network_tools.http_health("https://example.com")
    assert result.ok and result.data["status_code"] == 200


def test_http_health_unexpected_status(monkeypatch):
    _mock_session(monkeypatch, 503)
    result = network_tools.http_health("https://example.com")
    assert not result.ok


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "gopher://127.0.0.1:11211/", "ftp://example.com/x", "not-a-url", ""],
)
def test_http_health_rejects_non_http_urls(url, monkeypatch):
    """A scheme other than http(s) is never what an operator meant to type."""
    created = _mock_session(monkeypatch, 200)
    result = network_tools.http_health(url)
    assert not result.ok
    assert not created  # rejected before any session was opened


def test_http_health_bounds_redirects(monkeypatch):
    created = _mock_session(monkeypatch, 200)
    network_tools.http_health("https://example.com")
    assert [s.max_redirects for s in created] == [3]


def test_ssl_expiry_mocked(monkeypatch):
    import ssl as ssl_mod

    class _TLS:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def getpeercert(self):
            return {"notAfter": "Dec 31 23:59:59 2030 GMT",
                    "issuer": ((("organizationName", "Test CA"),),)}

    class _Ctx:
        def wrap_socket(self, sock, server_hostname=None): return _TLS()

    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(ssl_mod, "create_default_context", lambda: _Ctx())
    monkeypatch.setattr(network_tools.socket, "create_connection", lambda *a, **k: _Conn())
    result = network_tools.ssl_expiry("example.com")
    assert result.ok
    assert result.data["days_left"] > 0


# --- process tools ----------------------------------------------------------
def test_list_processes():
    result = process_tools.list_processes(top=5)
    assert result.ok
    assert result.data["processes"]
    assert len(result.data["processes"]) <= 5


def test_list_processes_bad_sort():
    result = process_tools.list_processes(sort_by="disk")
    assert not result.ok


def test_process_details_self():
    import os

    result = process_tools.process_details(os.getpid())
    assert result.ok
    assert result.data["pid"] == os.getpid()


def test_control_process_validates_pid():
    result = process_tools.control_process(1, "kill")
    assert not result.ok  # protected PID rejected
    bad = process_tools.control_process(999_999, "explode")
    assert not bad.ok     # invalid action
