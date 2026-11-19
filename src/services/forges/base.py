"""What every forge (GitLab, GitHub, ...) provides to the platform.

A repository with a forge source (``Repository.source_type`` is a forge name) is
reached through its :class:`Forge`: the forge checks the repository URL, decides
which stored credentials may be used for it, and turns a credential into the token
``git`` authenticates with. Callers never branch on the forge name themselves.

Credentials are passed in duck-typed (``owner_id``, ``kind``, ``forge_base_url``)
so this package does not depend on the web API's models and can be used by the
worker as well.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlsplit


class CredentialRejected(ValueError):
    """A credential may not be used for this repository (never carries secrets)."""


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


def check_owner(cred: Any, owner_id: uuid.UUID | None) -> None:
    if cred is None:
        raise CredentialRejected("Unknown credential")
    if owner_id is None or cred.owner_id != owner_id:
        raise CredentialRejected("Credential is not owned by the repository owner")


class Forge(ABC):
    #: ``Repository.source_type`` value
    name: str
    #: human-readable name for messages
    label: str
    #: user name ``git`` sends together with the token over HTTPS
    clone_username: str
    #: credential kinds that can authenticate against this forge
    credential_kinds: tuple[str, ...]
    #: remediation can push fix branches and open change requests here
    supports_push: bool = False

    @abstractmethod
    def check_remote_url(self, url: str) -> None:
        """Raise ``ValueError`` unless ``url`` is an acceptable repository URL."""

    @abstractmethod
    def credential_base_url(self, remote_url: str) -> str:
        """The URL a token pasted for ``remote_url`` is bound to (only its host and
        port are compared later, see :func:`hosts_match`)."""

    def check_credential_secret(self, kind: str, secret: str, base_url: str | None) -> None:
        """Raise ``ValueError`` when a new credential of ``kind`` is malformed."""

    def check_credential(self, cred: Any, owner_id: uuid.UUID | None,
                         remote_url: str | None) -> None:
        """Raise :class:`CredentialRejected` unless ``cred`` belongs to ``owner_id``,
        is of a kind this forge accepts and (when it records a base URL) is bound to
        ``remote_url``'s host."""
        check_owner(cred, owner_id)
        if cred.kind not in self.credential_kinds:
            raise CredentialRejected(f"Credential is not a {self.label} credential")
        if remote_url and not hosts_match(cred.forge_base_url, remote_url):
            raise CredentialRejected(f"Credential is bound to a different {self.label} host")

    @abstractmethod
    def access_token(self, kind: str, secret: str, remote_url: str) -> str:
        """The token ``git`` (and the forge API) authenticates with, from a decrypted
        credential secret. May call the forge (blocking): run it off the event loop,
        right before the token is needed."""
