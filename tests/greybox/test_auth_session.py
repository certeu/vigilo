"""Tests for the auth_session service (real HTTP login + cookie capture)."""
from __future__ import annotations

import asyncio
import json
import sys
from unittest.mock import MagicMock

import pytest

from src.greybox.types.config import IdentityConfig


def _make_identity(name: str = "admin", with_login: bool = True) -> IdentityConfig:
    return IdentityConfig(
        name=name,
        role="admin",
        privilege_level=10,
        login={
            "url": "{{WEB_URL}}/login",
            "method": "form",
            "fields": {"username": "admin@example.com", "password": "secret"},
            "success_indicator": "Dashboard",
        } if with_login else None,
    )


def _patch_httpx(monkeypatch, *, cookies: dict[str, str], status: int, body: str):
    """Replace httpx in sys.modules with a fake that scripts one POST."""

    class _FakeCookie:
        def __init__(self, name: str, value: str):
            self.name = name
            self.value = value

    class _FakeJar:
        def __init__(self, items: dict[str, str]):
            self._items = items
        def __iter__(self):
            return iter(_FakeCookie(n, v) for n, v in self._items.items())

    class _FakeResponse:
        def __init__(self):
            self.status_code = status
            self.text = body

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            self.cookies = MagicMock(jar=_FakeJar(cookies))
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, data=None): return _FakeResponse()

    fake_httpx = MagicMock()
    fake_httpx.AsyncClient = _FakeClient
    fake_httpx.HTTPError = Exception
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)


def test_login_identity_captures_cookies(monkeypatch):
    """A successful form login produces a verified payload with cookies."""
    from src.greybox.services.auth_session import login_identity

    _patch_httpx(
        monkeypatch,
        cookies={"session": "abc", "csrf": "def"},
        status=200,
        body="<html>Welcome to Dashboard</html>",
    )

    payload = asyncio.run(login_identity(_make_identity(), "https://target.local"))
    assert payload["identity"] == "admin"
    assert payload["status_code"] == 200
    assert payload["cookies"] == {"session": "abc", "csrf": "def"}
    assert "session=abc" in payload["cookie_header"]
    assert "csrf=def" in payload["cookie_header"]
    assert payload["verified"] is True
    assert payload["login_url"] == "https://target.local/login"


def test_login_identity_unverified_when_indicator_missing(monkeypatch):
    """verified=False when the success_indicator is absent from the body."""
    from src.greybox.services.auth_session import login_identity

    _patch_httpx(monkeypatch, cookies={"x": "y"}, status=401, body="Invalid")
    payload = asyncio.run(login_identity(_make_identity(), "https://target.local"))
    assert payload["verified"] is False
    assert payload["cookies"] == {"x": "y"}


def test_login_identity_rejects_non_form_method():
    """OAuth/SAML/etc are explicitly unsupported in v1."""
    from src.greybox.services.auth_session import LoginError, login_identity

    ident = _make_identity()
    ident.login["method"] = "oauth"
    with pytest.raises(LoginError, match="not supported"):
        asyncio.run(login_identity(ident, "https://target.local"))


def test_login_identity_no_login_config_raises():
    """An identity with login=None is a programming error to call directly."""
    from src.greybox.services.auth_session import LoginError, login_identity

    with pytest.raises(LoginError, match="no login config"):
        asyncio.run(login_identity(_make_identity(with_login=False), "https://target.local"))


def test_capture_all_sessions_writes_files(monkeypatch, tmp_path):
    """capture_all_sessions persists one JSON file per logged-in identity."""
    from src.greybox.services.auth_session import capture_all_sessions

    _patch_httpx(
        monkeypatch,
        cookies={"sid": "1"},
        status=200,
        body="Dashboard",
    )

    identities = [
        _make_identity("admin"),
        _make_identity("user"),
        _make_identity("anonymous", with_login=False),
    ]
    sessions_dir = tmp_path / "sessions"
    paths = asyncio.run(
        capture_all_sessions(identities, "https://target.local", sessions_dir)
    )

    assert set(paths.keys()) == {"admin", "user"}
    for name, path in paths.items():
        payload = json.loads(open(path).read())
        assert payload["identity"] == name
        assert payload["cookies"] == {"sid": "1"}
        assert payload["verified"] is True


def test_capture_all_sessions_swallows_individual_failures(monkeypatch, tmp_path):
    """One identity's failure must not abort the batch."""
    from src.greybox.services.auth_session import capture_all_sessions

    call_count = {"n": 0}

    class _FakeCookie:
        def __init__(self, n, v): self.name = n; self.value = v

    class _FakeJar:
        def __init__(self, items): self._items = items
        def __iter__(self): return iter(_FakeCookie(n, v) for n, v in self._items.items())

    class _FakeResponse:
        def __init__(self, status, body): self.status_code = status; self.text = body

    class _FakeClient:
        def __init__(self, *a, **k):
            call_count["n"] += 1
            self.cookies = MagicMock(jar=_FakeJar({"s": "1"}))
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, data=None):
            # First identity succeeds, second raises an HTTP error.
            if call_count["n"] == 1:
                return _FakeResponse(200, "Dashboard")
            raise Exception("boom")

    fake_httpx = MagicMock()
    fake_httpx.AsyncClient = _FakeClient
    fake_httpx.HTTPError = Exception
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    paths = asyncio.run(capture_all_sessions(
        [_make_identity("admin"), _make_identity("user")],
        "https://target.local",
        tmp_path / "sessions",
    ))
    assert "admin" in paths
    assert "user" not in paths


def test_cookie_header_from_session(tmp_path):
    """cookie_header_from_session reads back what login_identity wrote."""
    from src.greybox.services.auth_session import cookie_header_from_session

    payload = {"cookie_header": "a=1; b=2", "cookies": {"a": "1", "b": "2"}}
    f = tmp_path / "admin.json"
    f.write_text(json.dumps(payload))

    assert cookie_header_from_session(str(f)) == "a=1; b=2"
    assert cookie_header_from_session(None) == ""
    assert cookie_header_from_session(tmp_path / "missing.json") == ""
