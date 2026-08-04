"""Typed exception hierarchy for the DevOps Utility Collection.

A single base class (:class:`DevOpsError`) makes it trivial for the CLI to
catch every application-level failure and turn it into a clean exit code,
while the specific subclasses let individual tools react to precise causes.
"""

from __future__ import annotations


class DevOpsError(Exception):
    """Base class for all application-specific errors."""


class ConfigError(DevOpsError):
    """Configuration could not be loaded or is invalid."""


class SecurityError(DevOpsError):
    """An operation would violate a security guarantee."""


class ValidationError(DevOpsError):
    """User-supplied input failed validation."""


class ToolError(DevOpsError):
    """A tool failed to complete its operation."""


class DatabaseError(DevOpsError):
    """A database operation failed."""


class NetworkError(DevOpsError):
    """A network operation failed (DNS, TCP, HTTP, TLS)."""


class RemoteError(DevOpsError):
    """A remote (SSH/SFTP) operation failed."""


class DependencyError(DevOpsError):
    """An optional third-party dependency is required but unavailable."""


class UnsupportedPlatformError(DevOpsError):
    """A feature is not available on the current operating system."""
