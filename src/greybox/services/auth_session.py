"""Real HTTP session capture for managed scans.

Performs a form-based login per identity, captures the resulting cookies,
and persists them as JSON files so managed scanners can authenticate.

The login flow currently supports:
- ``method: form`` — POST the field map to the login URL, follow redirects.
- ``cookie_header`` — operator-supplied raw Cookie header (for EU Login /
  external SSO with 2FA). A synthetic session file is written directly;
  no HTTP POST is performed.

Session payload schema (``{workspace}/sessions/{identity}.json``):

    {
      "identity": "admin",
      "captured_at": "2026-04-29T12:34:56Z",
      "login_url": "https://target/login",
      "cookies": {"session": "abc...", "csrf": "def..."},
      "cookie_header": "session=abc...; csrf=def...",
      "verified": true
    }

``verified`` is True when the post-login response contained the identity's
``success_indicator`` (case-insensitive substring match in the body).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.greybox.types.config import IdentityConfig

logger = logging.getLogger(__name__)


class LoginError(Exception):
    """Raised when a login attempt fails irrecoverably."""


def _build_cookie_header(cookies: dict[str, str]) -> str:
    """Render a dict of cookies as a single ``Cookie:`` header value."""
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


async def login_identity(
    identity: IdentityConfig,
    web_url: str,
    *,
    timeout: float = 15.0,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Perform a login for one identity and return a session payload.

    Returns the payload dict described in the module docstring. Raises
    ``LoginError`` if the login URL is unreachable; returns ``verified=False``
    when the success indicator does not appear in the response body so the
    caller can decide whether to proceed with potentially-stale cookies.
    """
    if identity.login is None:
        raise LoginError(
            f"Identity {identity.name!r} has no login config — cannot capture session"
        )

    import httpx

    login_cfg = identity.login
    method = login_cfg.get("method", "form")
    if method != "form":
        raise LoginError(
            f"Login method {method!r} is not supported by auth_session "
            f"(identity={identity.name}); only 'form' is supported in v1."
        )

    raw_url = login_cfg.get("url", web_url.rstrip("/") + "/login")
    login_url = raw_url.replace("{{WEB_URL}}", web_url.rstrip("/"))
    fields: dict[str, str] = login_cfg.get("fields", {}) or {}
    success = login_cfg.get("success_indicator", "")

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=verify_tls,
        follow_redirects=True,
    ) as client:
        try:
            response = await client.post(login_url, data=fields)
        except httpx.HTTPError as exc:
            raise LoginError(
                f"Login POST to {login_url} failed for {identity.name}: {exc}"
            ) from exc

        cookies = {c.name: c.value for c in client.cookies.jar}

    body_text = response.text or ""
    verified = bool(success) and success.lower() in body_text.lower()

    if not cookies:
        logger.warning(
            "Login for %s captured no cookies (status=%d). "
            "Scanner auth will be a no-op.",
            identity.name, response.status_code,
        )

    return {
        "identity": identity.name,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "login_url": login_url,
        "status_code": response.status_code,
        "cookies": cookies,
        "cookie_header": _build_cookie_header(cookies),
        "verified": verified,
    }


async def _validate_cookie(
    cookie_header: str,
    web_url: str,
    *,
    timeout: float = 15.0,
    verify_tls: bool = True,
) -> bool:
    """Check if a pre-supplied cookie is still valid by GETting the target URL.

    Returns True if the response looks authenticated (no redirect to login,
    no 401/403). Returns False on expiry indicators. Never raises — validation
    failure is non-fatal for grey-box (the scan proceeds with partial auth).
    """
    import httpx

    _LOGIN_KEYWORDS = ("/login", "/auth", "/sso", "/cas/", "/oauth", "signin")

    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=verify_tls, follow_redirects=False,
        ) as client:
            response = await client.get(
                web_url, headers={"Cookie": cookie_header},
            )
        if response.status_code in (401, 403):
            logger.warning(
                "Cookie validation returned %d — cookie may be expired",
                response.status_code,
            )
            return False
        if response.status_code in (301, 302, 303, 307, 308):
            location = (response.headers.get("location") or "").lower()
            if any(kw in location for kw in _LOGIN_KEYWORDS):
                logger.warning(
                    "Cookie validation redirected to %s — cookie likely expired",
                    response.headers.get("location"),
                )
                return False
        return True
    except Exception as exc:
        logger.warning("Cookie validation failed (non-fatal): %s", exc)
        return True


async def capture_all_sessions(
    identities: list[IdentityConfig],
    web_url: str,
    sessions_dir: Path,
    *,
    timeout: float = 15.0,
    verify_tls: bool = True,
) -> dict[str, str]:
    """Login each identity that has a login config and persist a JSON file.

    Returns a mapping of identity name -> absolute path of the session file.
    Identities with no ``login`` (e.g. ``anonymous``) are skipped silently.
    Failures are logged but do not abort the batch — partial coverage is
    better than none, and the caller can fall back to unauthenticated scans
    for the missing identities.
    """
    sessions_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}

    for ident in identities:
        # Pre-supplied cookie: write a synthetic session file, skip HTTP login.
        if ident.cookie_header and ident.cookie_header.strip():
            verified = await _validate_cookie(
                ident.cookie_header, web_url,
                timeout=timeout, verify_tls=verify_tls,
            )
            payload = {
                "identity": ident.name,
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "login_url": "pre-authenticated",
                "status_code": 0,
                "cookies": {},
                "cookie_header": ident.cookie_header.strip(),
                "verified": verified,
            }
            out_path = sessions_dir / f"{ident.name}.json"
            out_path.write_text(json.dumps(payload, indent=2))
            paths[ident.name] = str(out_path)
            logger.info(
                "Wrote pre-authenticated session for %s (cookie reuse, verified=%s)",
                ident.name, verified,
            )
            continue

        if ident.login is None:
            continue
        try:
            payload = await login_identity(
                ident, web_url, timeout=timeout, verify_tls=verify_tls,
            )
        except LoginError as exc:
            logger.warning(
                "Session capture skipped for %s: %s", ident.name, exc,
            )
            continue

        out_path = sessions_dir / f"{ident.name}.json"
        out_path.write_text(json.dumps(payload, indent=2))
        paths[ident.name] = str(out_path)

        logger.info(
            "Captured session for %s (%d cookies, verified=%s)",
            ident.name, len(payload["cookies"]), payload["verified"],
        )

    return paths


def load_session(session_file: Path) -> dict[str, Any]:
    """Read a session file. Returns the parsed payload.

    A small wrapper that exists so callers don't have to know the JSON layout
    or the path encoding; tests can also mock it with a single override.
    """
    return json.loads(session_file.read_text())


def cookie_header_from_session(session_file: Path | str | None) -> str:
    """Return the ``Cookie:`` header string from a session file, or empty.

    Tolerates ``None`` (no auth) and missing files (logs and returns empty)
    so scanners can call this unconditionally.
    """
    if session_file is None:
        return ""
    path = Path(session_file)
    if not path.exists():
        logger.warning("Session file not found: %s — scan will be unauthenticated", path)
        return ""
    payload = load_session(path)
    header = payload.get("cookie_header", "") or ""
    return header
