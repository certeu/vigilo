"""Forges a repository can be cloned from (GitLab, GitHub).

``get_forge(repo.source_type)`` returns the :class:`~src.services.forges.base.Forge`
for a forge source, or None for an uploaded one.
"""
from __future__ import annotations

from src.services.forges.base import CredentialRejected, Forge, hosts_match
from src.services.forges.github import GitHubForge
from src.services.forges.gitlab import GitLabForge

FORGES: dict[str, Forge] = {f.name: f for f in (GitLabForge(), GitHubForge())}
FORGE_NAMES: tuple[str, ...] = tuple(FORGES)

#: run-secret kind of the token a run may push with (any forge)
FORGE_TOKEN_SECRET = "forge_token"


def get_forge(source_type: str | None) -> Forge | None:
    return FORGES.get(source_type or "")


def forge_for_kind(kind: str) -> Forge | None:
    """The forge a credential kind authenticates against, if any."""
    for forge in FORGES.values():
        if kind in forge.credential_kinds:
            return forge
    return None


__all__ = ["CredentialRejected", "FORGES", "FORGE_NAMES", "FORGE_TOKEN_SECRET", "Forge",
           "forge_for_kind", "get_forge", "hosts_match"]
