"""Ownership / kind / host checks applied before a stored credential is used.

A credential is only ever usable by its owner, for the kind of secret it holds, and
(for GitLab tokens with a recorded base URL) only against that GitLab host. These
checks run both when a credential is linked (create/update) and again when a run
starts, right before the secret is decrypted.
"""
from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlsplit

from src.webapi.models import Credential

GITLAB_KIND = "gitlab_token"
COOKIE_KIND = "cookie_header"
LOGIN_KIND = "login_account"


class CredentialRejected(ValueError):
    pass


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


def _host_port(url: str) -> tuple[str, int] | None:
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower().rstrip(".")
        scheme = (parts.scheme or "https").lower()
        port = parts.port or (80 if scheme == "http" else 443)
    except ValueError:
        return None
    return (host, port) if host else None


def hosts_match(base_url: str | None, target_url: str | None) -> bool:
    """True when ``base_url`` is unset, or names the same host:port as ``target_url``."""
    if not base_url:
        return True
    a, b = _host_port(base_url), _host_port(target_url or "")
    return a is not None and a == b


def validate_gitlab_credential(
    cred: Credential | None, owner_id: uuid.UUID | None, repo_url: str | None
) -> None:
    """Raise :class:`CredentialRejected` unless ``cred`` is a gitlab_token owned by
    ``owner_id`` and (when it records a base URL) bound to ``repo_url``'s host."""
    if cred is None:
        raise CredentialRejected("Unknown credential")
    if owner_id is None or cred.owner_id != owner_id:
        raise CredentialRejected("Credential is not owned by the repository owner")
    if cred.kind != GITLAB_KIND:
        raise CredentialRejected("Credential is not a GitLab token")
    if repo_url and not hosts_match(cred.gitlab_base_url, repo_url):
        raise CredentialRejected("Credential is bound to a different GitLab host")


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
