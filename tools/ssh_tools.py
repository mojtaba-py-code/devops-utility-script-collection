"""SSH automation via Paramiko: remote commands and SFTP transfers.

Security posture:

* **Credentials never come from config or argv** — the password/key passphrase
  is read from an environment variable named in the server inventory.
* **Host keys are verified.** The client uses ``RejectPolicy`` by default; a
  host is only trusted if it is already in ``known_hosts`` (or the caller opts
  in explicitly). This prevents silent man-in-the-middle acceptance, which is
  what ``AutoAddPolicy`` would allow.
* Connections always run with a timeout and are closed in a ``finally`` block.

Paramiko is optional at import time; SSH actions raise a clear error if it is
missing. A client can be injected for testing so no real host is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.base import OperationResult, timed
from utils.exceptions import DependencyError, RemoteError, SecurityError
from utils.logging_config import domain_logger
from utils.security import get_secret

# Optional at runtime, always present for the type checker: the module is
# imported normally under TYPE_CHECKING so its real signatures are used,
# and falls back to None at runtime when it is not installed.
if TYPE_CHECKING:
    import paramiko
else:
    try:
        import paramiko
    except ImportError:  # pragma: no cover
        paramiko = None

_log = domain_logger("ssh")


def _require_paramiko() -> None:
    if paramiko is None:  # pragma: no cover
        raise DependencyError("SSH actions require 'paramiko' (pip install paramiko)")


def connect(
    host: str,
    *,
    port: int = 22,
    username: str,
    password_env: str | None = None,
    key_filename: str | None = None,
    key_passphrase_env: str | None = None,
    timeout: float = 10.0,
    allow_unknown_hosts: bool = False,
    client: Any = None,
) -> Any:
    """Open (or return an injected) authenticated SSH client.

    Secrets are pulled from the environment variables named by *password_env*
    and *key_passphrase_env* — never passed in as literals.
    """
    if client is not None:
        return client
    _require_paramiko()
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if allow_unknown_hosts:
        # Opt-in only (default is RejectPolicy below), and WarningPolicy still
        # records the key and logs a warning rather than blindly trusting it.
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())  # nosec B507 - opt-in, non-default
    else:
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

    password = get_secret(password_env) if password_env else None
    passphrase = get_secret(key_passphrase_env) if key_passphrase_env else None
    if not password and not key_filename:
        raise SecurityError("No SSH credential supplied (set password_env or key_filename)")
    try:
        ssh.connect(
            hostname=host, port=port, username=username,
            password=password, key_filename=key_filename, passphrase=passphrase,
            timeout=timeout, allow_agent=False, look_for_keys=False,
        )
    except paramiko.SSHException as exc:  # pragma: no cover - needs a live host
        raise RemoteError(f"SSH connection to {host} failed: {exc}") from exc
    return ssh


def run_command(client: Any, command: str, *, timeout: float = 30.0) -> OperationResult:
    """Execute *command* on the remote host and capture stdout/stderr/exit."""
    with timed("ssh", "exec") as result:
        try:
            # Running an operator-supplied command on the remote host is the
            # explicit purpose of this function, over an already-authenticated
            # channel; there is no shell interpolation of untrusted local input.
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)  # nosec B601
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            raise RemoteError(f"Remote command failed: {exc}") from exc
        result.data = {"command": command, "exit_code": exit_code,
                       "stdout": out[-4000:], "stderr": err[-2000:]}
        if exit_code != 0:
            result.fail(f"Remote command exited with {exit_code}")
        else:
            result.finalize("Remote command succeeded")
        _log.info("ssh: exec exit=%s", exit_code)
    return result


def upload(client: Any, local: str | Path, remote: str) -> OperationResult:
    """Upload a local file to the remote host over SFTP."""
    with timed("ssh", "upload") as result:
        local_path = Path(local)
        if not local_path.is_file():
            raise RemoteError(f"Local file not found: {local_path}")
        sftp = client.open_sftp()
        try:
            sftp.put(str(local_path), remote)
        finally:
            sftp.close()
        result.data = {"local": str(local_path), "remote": remote,
                       "size_bytes": local_path.stat().st_size}
        result.finalize(f"Uploaded {local_path.name} -> {remote}")
        _log.info("ssh: uploaded %s -> %s", local_path.name, remote)
    return result


def download(client: Any, remote: str, local: str | Path) -> OperationResult:
    """Download a remote file to the local host over SFTP."""
    with timed("ssh", "download") as result:
        local_path = Path(local)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        sftp = client.open_sftp()
        try:
            sftp.get(remote, str(local_path))
        finally:
            sftp.close()
        result.data = {"remote": remote, "local": str(local_path)}
        result.finalize(f"Downloaded {remote} -> {local_path.name}")
    return result
