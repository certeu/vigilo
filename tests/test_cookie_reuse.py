"""Tests for cookie reuse (EU Login / external SSO with 2FA)."""
from __future__ import annotations

import asyncio
import json
import sys
from unittest.mock import MagicMock

import pytest

from src.greybox.types.config import IdentityConfig
from src.types.config import Authentication


# ---------------------------------------------------------------------------
# White-box config validation
# ---------------------------------------------------------------------------


class TestWhiteBoxAuthentication:
    def test_cookie_type_requires_cookie_header(self):
        with pytest.raises(ValueError, match="cookie_header is required"):
            Authentication(login_type="cookie")

    def test_cookie_type_rejects_empty_header(self):
        with pytest.raises(ValueError, match="cookie_header is required"):
            Authentication(login_type="cookie", cookie_header="   ")

    def test_cookie_type_accepts_valid_header(self):
        auth = Authentication(
            login_type="cookie",
            cookie_header="JSESSIONID=abc123; eu_login=xyz",
        )
        assert auth.login_type == "cookie"
        assert auth.cookie_header == "JSESSIONID=abc123; eu_login=xyz"
        assert auth.credentials is None

    def test_cookie_type_ignores_credentials(self):
        auth = Authentication(
            login_type="cookie",
            cookie_header="sid=abc",
        )
        assert auth.credentials is None

    def test_form_type_requires_credentials(self):
        with pytest.raises(ValueError, match="credentials are required"):
            Authentication(login_type="form", login_url="http://x/login")

    def test_sso_type_requires_credentials(self):
        with pytest.raises(ValueError, match="credentials are required"):
            Authentication(login_type="sso", login_url="http://x/login")


# ---------------------------------------------------------------------------
# Grey-box config validation
# ---------------------------------------------------------------------------


class TestGreyBoxIdentityConfig:
    def test_cookie_header_and_login_exclusive(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            IdentityConfig(
                name="op",
                role="user",
                cookie_header="sid=1",
                login={"method": "form", "url": "http://x"},
            )

    def test_cookie_header_without_login_ok(self):
        ident = IdentityConfig(
            name="op",
            role="user",
            privilege_level=3,
            cookie_header="JSESSIONID=abc; csrf=xyz",
        )
        assert ident.cookie_header == "JSESSIONID=abc; csrf=xyz"
        assert ident.login is None

    def test_login_without_cookie_header_ok(self):
        ident = IdentityConfig(
            name="admin",
            role="admin",
            login={"method": "form", "url": "http://x/login", "fields": {}},
        )
        assert ident.cookie_header is None
        assert ident.login is not None


# ---------------------------------------------------------------------------
# Synthetic session file generation
# ---------------------------------------------------------------------------


def _patch_httpx_get(monkeypatch, *, status: int, location: str | None = None):
    """Patch httpx to script a GET response for cookie validation."""

    class _FakeResponse:
        def __init__(self):
            self.status_code = status
            self.headers = {"location": location} if location else {}

    class _FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, headers=None): return _FakeResponse()

    fake_httpx = MagicMock()
    fake_httpx.AsyncClient = _FakeClient
    fake_httpx.HTTPError = Exception
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)


class TestSyntheticSession:
    def test_capture_writes_synthetic_file(self, monkeypatch, tmp_path):
        _patch_httpx_get(monkeypatch, status=200)
        from src.greybox.services.auth_session import capture_all_sessions

        ident = IdentityConfig(
            name="operator", role="user", privilege_level=3,
            cookie_header="JSESSIONID=abc; eu_login=xyz",
        )
        paths = asyncio.run(
            capture_all_sessions([ident], "https://target.local", tmp_path / "sessions")
        )
        assert "operator" in paths
        payload = json.loads(open(paths["operator"]).read())
        assert payload["identity"] == "operator"
        assert payload["cookie_header"] == "JSESSIONID=abc; eu_login=xyz"
        assert payload["login_url"] == "pre-authenticated"
        assert payload["status_code"] == 0
        assert payload["cookies"] == {}
        assert payload["verified"] is True

    def test_capture_marks_expired_cookie_unverified(self, monkeypatch, tmp_path):
        _patch_httpx_get(monkeypatch, status=302, location="https://login.eu/sso")
        from src.greybox.services.auth_session import capture_all_sessions

        ident = IdentityConfig(
            name="op", role="user",
            cookie_header="expired=old",
        )
        paths = asyncio.run(
            capture_all_sessions([ident], "https://target.local", tmp_path / "sessions")
        )
        payload = json.loads(open(paths["op"]).read())
        assert payload["verified"] is False
        assert payload["cookie_header"] == "expired=old"

    def test_capture_skips_empty_cookie_header(self, monkeypatch, tmp_path):
        """cookie_header with only whitespace is treated as absent."""
        _patch_httpx_get(monkeypatch, status=200)
        from src.greybox.services.auth_session import capture_all_sessions

        ident = IdentityConfig(name="op", role="user", cookie_header="   ")
        paths = asyncio.run(
            capture_all_sessions([ident], "https://target.local", tmp_path / "sessions")
        )
        assert "op" not in paths


# ---------------------------------------------------------------------------
# Cookie validation helper
# ---------------------------------------------------------------------------


class TestValidateCookie:
    def test_valid_cookie_returns_true(self, monkeypatch):
        _patch_httpx_get(monkeypatch, status=200)
        from src.greybox.services.auth_session import _validate_cookie

        result = asyncio.run(_validate_cookie("sid=1", "https://target.local"))
        assert result is True

    def test_401_returns_false(self, monkeypatch):
        _patch_httpx_get(monkeypatch, status=401)
        from src.greybox.services.auth_session import _validate_cookie

        result = asyncio.run(_validate_cookie("sid=1", "https://target.local"))
        assert result is False

    def test_403_returns_false(self, monkeypatch):
        _patch_httpx_get(monkeypatch, status=403)
        from src.greybox.services.auth_session import _validate_cookie

        result = asyncio.run(_validate_cookie("sid=1", "https://target.local"))
        assert result is False

    def test_redirect_to_login_returns_false(self, monkeypatch):
        _patch_httpx_get(monkeypatch, status=302, location="https://login.eu/sso/auth")
        from src.greybox.services.auth_session import _validate_cookie

        result = asyncio.run(_validate_cookie("sid=1", "https://target.local"))
        assert result is False

    def test_redirect_to_non_login_returns_true(self, monkeypatch):
        _patch_httpx_get(monkeypatch, status=302, location="https://target.local/dashboard")
        from src.greybox.services.auth_session import _validate_cookie

        result = asyncio.run(_validate_cookie("sid=1", "https://target.local"))
        assert result is True

    def test_network_error_returns_true(self, monkeypatch):
        """Non-fatal: can't reach target, assume cookie might be fine."""

        class _BrokenClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get(self, url, headers=None):
                raise ConnectionError("network down")

        fake_httpx = MagicMock()
        fake_httpx.AsyncClient = _BrokenClient
        monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
        from src.greybox.services.auth_session import _validate_cookie

        result = asyncio.run(_validate_cookie("sid=1", "https://target.local"))
        assert result is True


# ---------------------------------------------------------------------------
# Prompt manager: login instructions for cookie type
# ---------------------------------------------------------------------------


class TestPromptManagerCookie:
    def test_auth_context_for_cookie_type(self):
        from src.services.prompt_manager import _build_auth_context

        config = {"authentication": {"login_type": "cookie", "login_url": "https://x"}}
        result = _build_auth_context(config)
        assert "PRE-AUTHENTICATED COOKIE" in result
        assert "EU Login" in result

    def test_auth_context_for_form_type(self):
        from src.services.prompt_manager import _build_auth_context

        config = {
            "authentication": {
                "login_type": "form",
                "login_url": "http://x",
                "credentials": {"username": "u", "password": "p"},
            }
        }
        result = _build_auth_context(config)
        assert "FORM" in result


# ---------------------------------------------------------------------------
# Credentials block for grey-box cookie identities
# ---------------------------------------------------------------------------


class TestCredentialsBlock:
    def test_cookie_identity_block(self):
        from src.greybox.services.credentials import build_identities_block

        idents = [
            IdentityConfig(name="op", role="user", privilege_level=3,
                           cookie_header="sid=1"),
        ]
        result = build_identities_block(idents, "https://target.local")
        assert "op" in result
        assert "Pre-authenticated via cookie" in result
        assert "Do not attempt to log in" in result

    def test_mixed_cookie_and_login_identities(self):
        from src.greybox.services.credentials import build_identities_block

        idents = [
            IdentityConfig(name="cookie_user", role="user", privilege_level=3,
                           cookie_header="sid=1"),
            IdentityConfig(name="form_admin", role="admin", privilege_level=10,
                           login={"method": "form", "url": "http://x/login",
                                  "fields": {"u": "a"}}),
        ]
        result = build_identities_block(idents, "https://target.local")
        assert "cookie_user" in result
        assert "form_admin" in result
        assert "Pre-authenticated via cookie" in result
        assert "Navigate to" in result
