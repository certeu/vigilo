"""GitLab (gitlab.com and self-managed): personal, group or project access tokens."""
from __future__ import annotations

from urllib.parse import urlparse

from src.services.forges.base import Forge

GITLAB_TOKEN_KIND = "gitlab_token"


class GitLabForge(Forge):
    name = "gitlab"
    label = "GitLab"
    clone_username = "oauth2"
    credential_kinds = (GITLAB_TOKEN_KIND,)
    supports_push = True

    def check_remote_url(self, url: str) -> None:
        # Reject non-web schemes (file://, ext::, ssh://, …): otherwise a user could
        # point the clone at a local repo or an internal host (SSRF/LFI).
        scheme = (urlparse(url).scheme or "https").lower()
        if scheme not in ("https", "http"):
            raise ValueError(f"remote_url must be an http(s) URL (got {scheme!r})")
        from src.webapi.ingestion import reject_embedded_credentials
        reject_embedded_credentials(url)

    def credential_base_url(self, remote_url: str) -> str:
        return remote_url

    def access_token(self, kind: str, secret: str, remote_url: str) -> str:
        return secret
