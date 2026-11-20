"""The preflight cookie check must not write the cookie value to the worker log.

httpx rejects an invalid header value with "Illegal header value b'<the value>'";
that message used to be logged verbatim by the white-box preflight check.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from temporalio.exceptions import ApplicationError

from src.temporal import activities as act

SECRET = "s3cr3t-session-value"


@asynccontextmanager
async def _local_server(status: int = 200):
    """A throwaway HTTP server on 127.0.0.1 answering every request with ``status``."""

    async def handler(reader, writer):
        await reader.read(65536)
        writer.write(f"HTTP/1.1 {status} X\r\ncontent-length: 0\r\n\r\n".encode())
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    try:
        yield f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/"
    finally:
        server.close()
        await server.wait_closed()


async def _preflight(monkeypatch, cookie: str, status: int = 200) -> None:
    async def fake_login(_config, _input, _template):
        return {"authentication": {"login_type": "cookie", "cookie_header": cookie}}

    monkeypatch.setattr(act, "_with_cookie_login", fake_login)
    async with _local_server(status) as url:
        await act._preflight_cookie_check(SimpleNamespace(web_url=url, auth={"cookie": True}))


# --- white-box preflight ------------------------------------------------------

async def test_invalid_header_value_is_not_logged(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=act.logger.name)
    await _preflight(monkeypatch, f"sid=abc\n{SECRET}")

    assert SECRET not in caplog.text
    assert "Cookie validation skipped" in caplog.text
    assert "LocalProtocolError" in caplog.text
    assert "not a valid HTTP header value" in caplog.text


async def test_valid_cookie_is_not_logged(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=act.logger.name)
    await _preflight(monkeypatch, f"sid={SECRET}")

    assert SECRET not in caplog.text
    assert "validated successfully" in caplog.text


async def test_expired_cookie_still_fails_the_run(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=act.logger.name)
    with pytest.raises(ApplicationError, match="expired or is invalid"):
        await _preflight(monkeypatch, f"sid={SECRET}", status=401)
    assert SECRET not in caplog.text


async def test_skipped_without_cookie_auth(monkeypatch):
    async def must_not_run(*_a):
        raise AssertionError("cookie must not be redeemed")

    monkeypatch.setattr(act, "_with_cookie_login", must_not_run)
    await act._preflight_cookie_check(SimpleNamespace(web_url="http://x", auth={}))
    await act._preflight_cookie_check(SimpleNamespace(web_url=None, auth={"cookie": True}))

