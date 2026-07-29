"""Audit system -- crash-safe logging and metrics for pentest sessions.

Public API:

- :class:`AuditSession` -- main facade coordinating all audit components.
- :func:`get_workspace_path` -- resolve the workspace directory for a session.
"""

from .session import AuditSession, get_workspace_path

__all__ = ["AuditSession", "get_workspace_path"]
