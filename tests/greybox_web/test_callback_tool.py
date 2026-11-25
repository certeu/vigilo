"""Controlled local callback observation and correlation controls."""
from __future__ import annotations

import json
import threading
from contextlib import asynccontextmanager, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

import pytest

from src.greybox_web import tools as gb_tools
from src.greybox_web.netguard import Budget, GuardedHttpClient, NetPolicy, NullRecorder
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.tools import ToolContext, callback


@contextmanager
def _callback_services():
    hits: set[str] = set()

    class Observer(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = self.path.strip("/").split("/", 1)
            token = parts[1] if len(parts) == 2 else ""
            if parts[0] == "callback":
                hits.add(token)
                body, status = b"", 204
            elif parts[0] == "observe" and token in hits:
                body, status = json.dumps({"seen": token}).encode(), 200
            else:
                body, status = b'{"seen":false}', 200
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    observer = ThreadingHTTPServer(("127.0.0.1", 0), Observer)
    observer_thread = threading.Thread(target=observer.serve_forever, daemon=True)
    observer_thread.start()
    observer_base = f"http://127.0.0.1:{observer.server_port}"

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = urlsplit(self.path)
            supplied = parse_qs(parts.query).get("url", [""])[0]
            if parts.path == "/vulnerable" and supplied:
                with urlopen(supplied, timeout=1):
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"processed")

        def log_message(self, *_args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    try:
        yield (f"http://127.0.0.1:{target.server_port}/", observer_base, hits)
    finally:
        target.shutdown()
        observer.shutdown()
        target.server_close()
        observer.server_close()
        target_thread.join(timeout=2)
        observer_thread.join(timeout=2)


@asynccontextmanager
async def _context(trigger_base: str, observer_base: str, trigger_path: str):
    scope = ScopePolicy.from_dict({
        "allowed_hosts": ["127.0.0.1"], "allowed_schemes": ["http"],
        "allowed_ports": [urlsplit(trigger_base).port, urlsplit(observer_base).port],
        "path_prefixes": ["/"], "redirect_policy": "none"})
    client = GuardedHttpClient(scope=scope, budget=Budget(50, 30),
        policy=NetPolicy(allow_private=True), rate_limit_rps=100,
        request_timeout_s=2, recorder=NullRecorder())
    params = {"trigger_url": trigger_base + trigger_path,
              "callback_url": observer_base + "/callback/{token}",
              "observation_url": observer_base + "/observe/{token}",
              "param": "url", "poll_attempts": 1}
    try:
        yield ToolContext(http=client.bind("callback.observe"), base_url=trigger_base,
                          scope=scope, limits={}, params=params), client
    finally:
        await client.aclose()


def test_callback_tool_is_first_class_and_verifiable():
    check = gb_tools.get("callback.observe")
    verify = gb_tools.get("verify.callback.observe")
    assert check is not None and check.kind == "discovery"
    assert verify is not None and verify.kind == "verify"
    assert {"trigger_url", "callback_url", "observation_url", "param"} <= set(check.param_keys)


@pytest.mark.asyncio
async def test_local_callback_requires_positive_and_negative_correlation():
    with _callback_services() as (target, observer, hits):
        async with _context(target, observer, "vulnerable") as (ctx, client):
            result = await callback.observe(ctx)
            assert result.counts == {"attempted": 1, "callbacks": 1}
            assert result.observations[0].facts["outcome"] == "confirmed_exploitable"
            assert result.observations[0].facts["negative_control"] is True
            assert len(result.findings) == 1 and result.findings[0].cwe == "CWE-918"
            assert len(hits) == 1 and next(iter(hits)).startswith("vigilo-callback-")
            assert all(urlsplit(item.url).hostname == "127.0.0.1"
                       for item in client.recorder.items)
            ctx.params = {**result.findings[0].verify, "finding_id": "ignored"}
            verified = await callback.verify(ctx)
            assert verified.confirmed and verified.outcome == "confirmed_exploitable"
        assert len(hits) == 2


@pytest.mark.asyncio
async def test_negative_target_does_not_create_a_callback_finding():
    with _callback_services() as (target, observer, hits):
        async with _context(target, observer, "safe") as (ctx, _client):
            result = await callback.observe(ctx)
    assert result.counts == {"attempted": 1, "callbacks": 0}
    assert result.findings == [] and result.observations[0].facts["outcome"] == "not_reproduced"
    assert hits == set()


@pytest.mark.asyncio
async def test_external_callback_is_blocked_before_any_request():
    class FakeHttp:
        def __init__(self):
            self.calls = []

        def sessions(self):
            return []

        def in_scope(self, _url):
            return True

        async def request(self, *_args, **_kwargs):
            self.calls.append((_args, _kwargs))
            raise AssertionError("no request may be made")

    http = FakeHttp()
    ctx = ToolContext(http=http, base_url="http://127.0.0.1/", scope=None, limits={},
        params={"trigger_url": "http://127.0.0.1/fetch", "param": "url",
                "callback_url": "https://example.test/callback/{token}",
                "observation_url": "https://example.test/observe/{token}"})
    result = await callback.observe(ctx)
    assert result.observations[0].facts["outcome"] == "blocked_by_configuration"
    assert "local endpoints" in result.observations[0].facts["note"]
    assert http.calls == []
