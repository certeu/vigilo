"""The preflight cookie check must never write the cookie value to the worker log."""
from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace

import pytest
from temporalio.exceptions import ApplicationError

from src.temporal import activities as act

SECRET = "s3cr3t-session-value"


async def _check_against_local_server(monkeypatch, cookie: str, status: int = 200) -> None:
    """Run the preflight cookie check against a throwaway local HTTP server."""

    async def handler(reader, writer):
        await reader.read(65536)
        writer.write(f"HTTP/1.1 {status} X\r\ncontent-length: 0\r\n\r\n".encode())
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def fake_login(_config, _input, _template):
        return {"authentication": {"login_type": "cookie", "cookie_header": cookie}}

    monkeypatch.setattr(act, "_with_cookie_login", fake_login)
    inp = SimpleNamespace(web_url=f"http://127.0.0.1:{port}/", auth={"cookie": True})
    try:
        await act._preflight_cookie_check(inp)
    finally:
        server.close()


def test_invalid_header_value_is_not_logged(monkeypatch, caplog):
    # httpx rejects the value with "Illegal header value b'<the value>'"; that message
    # used to go to the worker log verbatim.
    caplog.set_level(logging.DEBUG, logger=act.logger.name)
    asyncio.run(_check_against_local_server(monkeypatch, f"sid=abc\n{SECRET}"))

    assert SECRET not in caplog.text
    assert "Cookie validation skipped" in caplog.text
    assert "LocalProtocolError" in caplog.text
    assert "not a valid HTTP header value" in caplog.text


def test_valid_cookie_is_not_logged(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=act.logger.name)
    asyncio.run(_check_against_local_server(monkeypatch, f"sid={SECRET}"))

    assert SECRET not in caplog.text
    assert "validated successfully" in caplog.text


def test_expired_cookie_still_fails_the_run(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=act.logger.name)
    with pytest.raises(ApplicationError, match="expired or is invalid"):
        asyncio.run(_check_against_local_server(monkeypatch, f"sid={SECRET}", status=401))
    assert SECRET not in caplog.text


def test_skipped_without_cookie_auth(monkeypatch):
    async def must_not_run(*_a):
        raise AssertionError("cookie must not be redeemed")

    monkeypatch.setattr(act, "_with_cookie_login", must_not_run)
    asyncio.run(act._preflight_cookie_check(SimpleNamespace(web_url="http://x", auth={})))
    asyncio.run(act._preflight_cookie_check(SimpleNamespace(web_url=None, auth={"cookie": True})))
