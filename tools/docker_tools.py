"""Docker utility: manage containers and images via the Docker SDK.

The Docker SDK and a running daemon are both optional at import time — the
module loads without them and raises a clear :class:`DependencyError` /
:class:`ToolError` only when a Docker action is actually invoked, so the rest of
the toolkit works on a host without Docker.
"""

from __future__ import annotations

from typing import Any

from core.base import OperationResult, timed
from utils.exceptions import DependencyError, ToolError
from utils.logging_config import domain_logger

try:
    import docker
    from docker.errors import DockerException, NotFound
except ImportError:  # pragma: no cover
    docker = None  # type: ignore[assignment]
    DockerException = NotFound = Exception  # type: ignore[assignment,misc]

_log = domain_logger("docker")


def get_client(client: Any = None) -> Any:
    """Return a Docker client, connecting to the daemon from the environment.

    Accepts an injected *client* (used by tests) so the tool never has to talk
    to a real daemon to be exercised.
    """
    if client is not None:
        return client
    if docker is None:  # pragma: no cover
        raise DependencyError("Docker actions require 'docker' (pip install docker)")
    try:
        return docker.from_env()
    except DockerException as exc:  # pragma: no cover - daemon down
        raise ToolError(f"Cannot reach the Docker daemon: {exc}") from exc


def list_containers(*, all_containers: bool = True, client: Any = None) -> OperationResult:
    """List Docker containers (running, or all when *all_containers*)."""
    with timed("docker", "list") as result:
        cli = get_client(client)
        try:
            containers = cli.containers.list(all=all_containers)
        except DockerException as exc:  # pragma: no cover
            raise ToolError(f"Failed to list containers: {exc}") from exc
        items = [
            {
                "id": c.short_id,
                "name": c.name,
                "image": _image_tag(c),
                "status": c.status,
            }
            for c in containers
        ]
        result.data = {"count": len(items), "containers": items}
        result.finalize(f"{len(items)} container(s)")
    return result


def container_action(name: str, action: str, *, client: Any = None) -> OperationResult:
    """Start / stop / restart / remove a container by name or id."""
    with timed("docker", action) as result:
        if action not in ("start", "stop", "restart", "remove"):
            raise ToolError(f"Unknown container action {action!r}")
        cli = get_client(client)
        try:
            container = cli.containers.get(name)
            getattr(container, action)()
        except NotFound as exc:
            raise ToolError(f"No such container: {name}") from exc
        except DockerException as exc:  # pragma: no cover
            raise ToolError(f"Docker {action} failed for {name}: {exc}") from exc
        result.data = {"container": name, "action": action}
        result.finalize(f"{action} succeeded for container {name}")
        _log.info("docker: %s container %s", action, name)
    return result


def container_logs(name: str, *, tail: int = 100, client: Any = None) -> OperationResult:
    """Fetch the last *tail* log lines of a container."""
    with timed("docker", "logs") as result:
        cli = get_client(client)
        try:
            container = cli.containers.get(name)
            raw = container.logs(tail=tail)
        except NotFound as exc:
            raise ToolError(f"No such container: {name}") from exc
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        result.data = {"container": name, "tail": tail, "logs": text}
        result.finalize(f"Fetched {tail} log line(s) for {name}")
    return result


def container_stats(name: str, *, client: Any = None) -> OperationResult:
    """Return a one-shot CPU/memory statistics snapshot for a container."""
    with timed("docker", "stats") as result:
        cli = get_client(client)
        try:
            container = cli.containers.get(name)
            stats = container.stats(stream=False)
        except NotFound as exc:
            raise ToolError(f"No such container: {name}") from exc
        mem = stats.get("memory_stats", {})
        result.data = {
            "container": name,
            "memory_usage": mem.get("usage"),
            "memory_limit": mem.get("limit"),
            "cpu": stats.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage"),
        }
        result.finalize(f"Stats snapshot for {name}")
    return result


def pull_image(reference: str, *, client: Any = None) -> OperationResult:
    """Pull an image by reference (e.g. ``nginx:latest``)."""
    with timed("docker", "pull") as result:
        cli = get_client(client)
        try:
            image = cli.images.pull(reference)
        except DockerException as exc:  # pragma: no cover
            raise ToolError(f"Failed to pull {reference}: {exc}") from exc
        tags = getattr(image, "tags", []) or [reference]
        result.data = {"reference": reference, "tags": tags}
        result.finalize(f"Pulled {reference}")
        _log.info("docker: pulled %s", reference)
    return result


def _image_tag(container: Any) -> str:
    try:
        tags = container.image.tags
        return tags[0] if tags else container.image.short_id
    except Exception:  # noqa: BLE001  # pragma: no cover
        return "?"
