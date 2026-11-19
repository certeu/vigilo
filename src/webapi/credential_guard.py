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
LOGIN_KIND = "login_account"

__all__ = ["COOKIE_KIND", "GITLAB_KIND", "CredentialRejected", "hosts_match",
           "parse_login_secret", "repo_access_token", "validate_cookie_credential",
           "validate_gitlab_credential", "validate_login_credential", "validate_repo_credential"]


def parse_login_secret(plain: str | bytes) -> dict:
    """A ``login_account`` credential's PLAINTEXT secret as a dict:
    ``{user, password, login_url?, user_field?, password_field?, method?, body?}``.
    Raises :class:`CredentialRejected` for anything malformed."""
    import json
    try:
        data = json.loads(plain.decode() if isinstance(plain, bytes) else str(plain))
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except (ValueError, UnicodeDecodeError) as exc:
        raise CredentialRejected("login account secret is malformed") from exc
    user = str(data.get("user") or "").strip()
    password = str(data.get("password") or "")
    if not user or not password:
        raise CredentialRejected("login account needs a user and a password")
    for key, maxlen in (("user", 200), ("password", 500), ("login_url", 500),
                        ("user_field", 100), ("password_field", 100), ("body", 20)):
        if len(str(data.get(key) or "")) > maxlen:
            raise CredentialRejected(f"login account field {key} is too long")
    method = str(data.get("method") or "POST").upper()
    if method not in ("GET", "POST"):
        raise CredentialRejected("login account method must be GET or POST")
    body = str(data.get("body") or "auto").lower()
    if body not in ("auto", "form", "json", "jsonrpc"):
        raise CredentialRejected("login account body must be auto, form, json or jsonrpc")
    return {"user": user, "password": password,
            "login_url": str(data.get("login_url") or "") or None,
            "user_field": str(data.get("user_field") or "") or None,
            "password_field": str(data.get("password_field") or "") or None,
            "method": method, "body": body}


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


def validate_login_credential(cred: Credential | None, owner_id: Any) -> dict:
    """A login_account credential: owned by ``owner_id`` and carrying a usable
    user/password pair. Returns the parsed secret dict (structure checked by
    :func:`parse_login_secret` on the decrypted plaintext)."""
    from src.webapi.security.vault import build_vault
    from src.webapi.settings import get_settings
    if cred is None:
        raise CredentialRejected("Unknown credential")
    if owner_id is None or cred.owner_id != owner_id:
        raise CredentialRejected("Credential is not owned by the target owner")
    if cred.kind != LOGIN_KIND:
        raise CredentialRejected("Credential is not a login account")
    plain = build_vault(get_settings()).decrypt(cred.secret_enc)
    return parse_login_secret(plain)
