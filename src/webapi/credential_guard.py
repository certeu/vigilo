"""Ownership / kind / host checks applied before a stored credential is used.

A credential is only ever usable by its owner, for the kind of secret it holds, and
(for forge credentials with a recorded base URL) only against that forge host. The
forge-specific rules live in :mod:`src.services.forges`. These
checks run both when a credential is linked (create/update) and again when a run
starts, right before the secret is decrypted.
"""
from __future__ import annotations

import uuid
from typing import Any

from src.services.forges import CredentialRejected, get_forge, hosts_match
from src.services.forges.gitlab import GITLAB_TOKEN_KIND
from src.webapi.models import Credential

GITLAB_KIND = GITLAB_TOKEN_KIND
COOKIE_KIND = "cookie_header"

__all__ = ["COOKIE_KIND", "GITLAB_KIND", "CredentialRejected", "hosts_match",
           "repo_access_token", "validate_cookie_credential", "validate_gitlab_credential",
           "validate_repo_credential"]


def validate_repo_credential(
    cred: Credential | None, owner_id: uuid.UUID | None, source_type: str,
    remote_url: str | None,
) -> None:
    """Raise :class:`CredentialRejected` unless ``cred`` may be used to reach a
    repository of ``source_type`` at ``remote_url`` on behalf of ``owner_id``."""
    forge = get_forge(source_type)
    if forge is None:
        raise CredentialRejected("This repository source does not use a credential")
    forge.check_credential(cred, owner_id, remote_url)


def validate_gitlab_credential(
    cred: Credential | None, owner_id: uuid.UUID | None, repo_url: str | None
) -> None:
    """:func:`validate_repo_credential` for a GitLab repository."""
    validate_repo_credential(cred, owner_id, "gitlab", repo_url)


def repo_access_token(cred: Credential | None, source_type: str, remote_url: str) -> str | None:
    """Decrypt ``cred`` and turn it into the token ``git`` authenticates with (a
    GitHub App mints a fresh installation token here). None without a credential.
    Blocking: run it off the event loop. Validate the credential first."""
    if cred is None:
        return None
    forge = get_forge(source_type)
    if forge is None:
        return None
    from src.webapi.security.vault import build_vault
    from src.webapi.settings import get_settings
    secret = build_vault(get_settings()).decrypt(cred.secret_enc)
    return forge.access_token(cred.kind, secret, remote_url)


def validate_cookie_credential(cred: Credential | None, owner_id: Any) -> None:
    if cred is None:
        raise CredentialRejected("Unknown credential")
    if owner_id is None or cred.owner_id != owner_id:
        raise CredentialRejected("Credential is not owned by the job owner")
    if cred.kind != COOKIE_KIND:
        raise CredentialRejected("Credential is not a cookie credential")
