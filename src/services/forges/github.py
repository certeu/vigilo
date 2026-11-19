"""GitHub (github.com and GitHub Enterprise Server).

Two credential kinds:

* ``github_token``: a personal access token (fine-grained or classic), used as is;
* ``github_app``: a GitHub App (ID, private key, optional installation ID). A
  short-lived installation token, limited to the one repository and
  ``contents: read``, is minted each time a token is needed (see
  :mod:`src.services.forges.github_app`).
"""
from __future__ import annotations

from urllib.parse import urlsplit

from src.services.forges import github_app
from src.services.forges.base import Forge

GITHUB_TOKEN_KIND = "github_token"
GITHUB_APP_KIND = github_app.GITHUB_APP_KIND


class GitHubForge(Forge):
    name = "github"
    label = "GitHub"
    clone_username = github_app.CLONE_USERNAME
    credential_kinds = (GITHUB_TOKEN_KIND, GITHUB_APP_KIND)

    def check_remote_url(self, url: str) -> None:
        github_app.parse_repo_url(url)

    def credential_base_url(self, remote_url: str) -> str:
        return github_app.parse_repo_url(remote_url).web_base

    def check_credential_secret(self, kind: str, secret: str, base_url: str | None) -> None:
        if not base_url or (urlsplit(base_url).scheme or "").lower() != "https":
            raise ValueError("a GitHub credential needs an https:// forge_base_url "
                             "(https://github.com or your GitHub Enterprise URL)")
        if kind == GITHUB_APP_KIND:
            github_app.parse_app_secret(secret)

    def access_token(self, kind: str, secret: str, remote_url: str) -> str:
        if kind == GITHUB_APP_KIND:
            return github_app.installation_token(secret, remote_url)
        return secret
