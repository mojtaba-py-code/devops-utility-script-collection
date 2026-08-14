"""Core result model shared by every tool.

Every operation a tool performs returns an :class:`OperationResult`: a uniform,
serialisable record of *what happened*. The CLI, the reporting layer and the
SQLite history all consume this one shape, so adding a new tool never means
teaching the rest of the system a new vocabulary.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from utils.formatting import utc_now_iso


class Status(StrEnum):
    """The outcome of an operation (string-valued for clean JSON)."""

    SUCCESS = "success"
    PARTIAL = "partial"   # completed with some per-item failures
    FAILURE = "failure"
    SKIPPED = "skipped"
    DRY_RUN = "dry_run"

    @property
    def ok(self) -> bool:
        return self in (Status.SUCCESS, Status.DRY_RUN, Status.SKIPPED)


@dataclass
class OperationResult:
    """A uniform, serialisable record of a single tool operation."""

    tool: str
    action: str
    status: Status = Status.SUCCESS
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now_iso)
    duration_ms: int = 0

    # -- mutation helpers ---------------------------------------------------
    def add_error(self, message: str) -> None:
        self.errors.append(message)
        if self.status is Status.SUCCESS:
            self.status = Status.PARTIAL

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def fail(self, message: str) -> OperationResult:
        self.status = Status.FAILURE
        if message:
            self.errors.append(message)
            self.message = self.message or message
        return self

    def finalize(self, message: str | None = None) -> OperationResult:
        """Promote a clean run to SUCCESS and set a summary message."""
        if message is not None:
            self.message = message
        if self.status is Status.SUCCESS and self.errors:
            self.status = Status.PARTIAL
        return self

    # -- serialisation ------------------------------------------------------
    @property
    def ok(self) -> bool:
        return self.status.ok

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "action": self.action,
            "status": self.status.value,
            "message": self.message,
            "data": self.data,
            "errors": self.errors,
            "warnings": self.warnings,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
        }


@contextmanager
def timed(tool: str, action: str) -> Iterator[OperationResult]:
    """Context manager that builds an :class:`OperationResult` and times it.

    Any exception raised inside the block is captured onto the result as a
    failure (and re-raised is *not* — the caller inspects ``result.status``),
    so a single tool never crashes the CLI.
    """
    result = OperationResult(tool=tool, action=action)
    start = time.perf_counter()
    try:
        yield result
    except Exception as exc:  # noqa: BLE001 - isolate tool failures uniformly
        result.fail(f"{type(exc).__name__}: {exc}")
    finally:
        result.duration_ms = int((time.perf_counter() - start) * 1000)
