"""The DevOps utility tools.

Each module exposes small, composable functions that return a uniform
:class:`core.base.OperationResult`. They are deliberately import-light so a
host missing an optional dependency (docker, paramiko, requests) can still load
and use the rest of the toolkit.
"""
