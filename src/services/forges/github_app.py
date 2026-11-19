"""GitHub (github.com and GitHub Enterprise Server) access through a GitHub App.

A GitHub repository can be accessed with a short-lived *installation access
token*. The token is minted right before it is needed (it expires after an hour)
and never stored:

1. sign a JWT (RS256, at most 10 minutes) with the App's private key,
2. find the App's installation on the repository (or use the configured one),
3. ask for an installation token scoped to that single repository with
   ``contents: read``,
4. clone over HTTPS as ``x-access-token:<token>``.

The App configuration (``app_id``, ``private_key``, optional ``installation_id``) is
stored as one encrypted ``github_app`` credential (JSON). Its ``forge_base_url``
column holds the GitHub *web* base URL (``https://github.com`` or
``https://ghe.example.com``) the credential is bound to; the REST API base is
derived from it (``https://api.github.com`` or ``https://<host>/api/v3``).

Only the standard library and ``cryptography`` (already a platform dependency) are
used.
"""
from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

GITHUB_APP_KIND = "github_app"
CLONE_USERNAME = "x-access-token"
_PUBLIC_WEB_HOST = "github.com"
_PUBLIC_API_BASE = "https://api.github.com"
_TIMEOUT = 30
_DIGITS = re.compile(r"^[0-9]{1,20}$")


class GitHubAppError(RuntimeError):
    """A GitHub App configuration or API problem (never carries secrets)."""


# ── URLs ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class GitHubRepo:
    web_base: str   # https://github.com | https://ghe.example.com[:port]
    owner: str
    name: str

    @property
    def api_base(self) -> str:
        return api_base_for(self.web_base)


def parse_repo_url(url: str) -> GitHubRepo:
    """Split ``https://<host>/<owner>/<repo>[.git]`` into its parts. https only, no
    credentials, exactly two path segments (GitHub has no nested groups)."""
    parts = urlsplit((url or "").strip())
    if (parts.scheme or "").lower() != "https":
        raise ValueError("a GitHub repository URL must use https://")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("the repository URL must not contain credentials")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("the repository URL has no host")
    if parts.query or parts.fragment:
        raise ValueError("the repository URL must not have a query or fragment")
    segs = [s for s in parts.path.split("/") if s]
    if len(segs) != 2:
        raise ValueError("a GitHub repository URL looks like https://<host>/<owner>/<repo>")
    owner, name = segs[0], segs[1]
    if name.endswith(".git"):
        name = name[:-4]
    if not owner or not name:
        raise ValueError("a GitHub repository URL looks like https://<host>/<owner>/<repo>")
    web_base = f"https://{host}" + (f":{parts.port}" if parts.port else "")
    return GitHubRepo(web_base=web_base, owner=owner, name=name)


def api_base_for(web_base: str) -> str:
    """REST API base for a GitHub web base URL: github.com uses ``api.github.com``,
    GitHub Enterprise Server serves the API under ``/api/v3`` on its own host."""
    parts = urlsplit(web_base.strip())
    host = (parts.hostname or "").lower().rstrip(".")
    if host in (_PUBLIC_WEB_HOST, "www.github.com"):
        return _PUBLIC_API_BASE
    return f"https://{host}" + (f":{parts.port}" if parts.port else "") + "/api/v3"


# ── App configuration (the decrypted credential secret) ─────────────────────


@dataclass(frozen=True)
class AppConfig:
    app_id: str
    private_key: str
    installation_id: str | None = None


def parse_app_secret(secret: str) -> AppConfig:
    """Parse and validate the JSON secret of a ``github_app`` credential."""
    try:
        data = json.loads(secret)
    except (TypeError, ValueError) as exc:
        raise ValueError("a github_app secret must be a JSON object") from exc
    if not isinstance(data, dict):
        raise ValueError("a github_app secret must be a JSON object")
    app_id = str(data.get("app_id") or "").strip()
    if not _DIGITS.match(app_id):
        raise ValueError("app_id must be the numeric GitHub App ID")
    inst = data.get("installation_id")
    inst = str(inst).strip() if inst not in (None, "") else None
    if inst is not None and not _DIGITS.match(inst):
        raise ValueError("installation_id must be numeric")
    key = str(data.get("private_key") or "").strip()
    _load_private_key(key)  # raises ValueError when it is not a usable RSA key
    return AppConfig(app_id=app_id, private_key=key, installation_id=inst)


def build_app_secret(app_id: str | int, private_key: str,
                     installation_id: str | int | None = None) -> str:
    """Validate the parts and serialise them as a ``github_app`` credential secret."""
    raw = json.dumps({
        "app_id": str(app_id).strip(),
        "private_key": (private_key or "").strip(),
        "installation_id": (str(installation_id).strip() if installation_id not in (None, "")
                            else None),
    })
    parse_app_secret(raw)
    return raw


def _load_private_key(pem: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if "PRIVATE KEY" not in pem:
        raise ValueError("private_key must be the PEM private key downloaded for the GitHub App")
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise ValueError("private_key is not a readable PEM private key") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("private_key must be an RSA key (GitHub Apps use RSA)")
    return key


# ── JWT + REST ──────────────────────────────────────────────────────────────


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(cfg: AppConfig, now: float | None = None) -> str:
    """An RS256 JWT authenticating as the App. ``iat`` is back-dated 60s for clock
    drift; GitHub accepts at most 10 minutes of lifetime."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(now if now is not None else time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(
        {"iat": now - 60, "exp": now + 540, "iss": cfg.app_id}, separators=(",", ":"),
    ).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = _load_private_key(cfg.private_key).sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(sig)}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _api_request(method: str, url: str, bearer: str, body: dict | None = None,
                 opener=None) -> dict:
    """One GitHub REST call. Redirects are refused (the bearer must not travel to
    another host); error bodies are shortened and never contain the bearer."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {bearer}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vigilo",
        **({"Content-Type": "application/json"} if data is not None else {}),
    })
    opener = opener or urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=_TIMEOUT) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise GitHubAppError(
                f"GitHub API answered with a redirect (HTTP {exc.code}); refusing to follow it"
            ) from None
        detail = ""
        try:
            detail = json.loads(exc.read() or b"{}").get("message", "")
        except Exception:
            pass
        raise GitHubAppError(
            f"GitHub API error {exc.code} on {method} {urlsplit(url).path}: {detail}"[:300]
        ) from None
    except urllib.error.URLError as exc:
        raise GitHubAppError(f"GitHub API not reachable: {exc.reason}"[:300]) from None
    try:
        return json.loads(raw or b"{}")
    except ValueError:
        raise GitHubAppError("GitHub API returned a non-JSON response") from None


def installation_token(secret: str, repo_url: str, opener=None) -> str:
    """Mint an installation access token for ``repo_url`` with ``contents: read``,
    restricted to that one repository. Valid for at most one hour; not stored."""
    cfg = parse_app_secret(secret)
    repo = parse_repo_url(repo_url)
    api = repo.api_base
    jwt = app_jwt(cfg)
    inst = cfg.installation_id
    if not inst:
        info = _api_request(
            "GET", f"{api}/repos/{quote(repo.owner, safe='')}/{quote(repo.name, safe='')}/installation",
            jwt, opener=opener,
        )
        inst = str(info.get("id") or "")
        if not _DIGITS.match(inst):
            raise GitHubAppError("the GitHub App is not installed on this repository")
    out = _api_request(
        "POST", f"{api}/app/installations/{inst}/access_tokens", jwt,
        body={"repositories": [repo.name], "permissions": {"contents": "read"}},
        opener=opener,
    )
    token = out.get("token")
    if not isinstance(token, str) or not token:
        raise GitHubAppError("GitHub did not return an installation token")
    return token
