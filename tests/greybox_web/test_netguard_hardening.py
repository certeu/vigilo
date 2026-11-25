"""Guarded-client hardening: preflight must not leak denied addresses (E),
canonical host for blocked endpoints (G), IDNA Host header/SNI (H) and bounded
decompression (I). httpx.MockTransport + fake resolver: no real network/DNS."""
from __future__ import annotations

import gzip
import zlib

import httpx
import pytest

from src.greybox_web import netguard
from src.greybox_web.netguard import (
    READ_CAP,
    Budget,
    GuardedHttpClient,
    NetPolicy,
    NullRecorder,
    ScopeViolation,
)
from src.greybox_web.scope import ScopePolicy
from tests.greybox_web.conftest import create_target, h


def scope(*hosts: str) -> ScopePolicy:
    return ScopePolicy.from_dict({
        "allowed_hosts": list(hosts), "allowed_schemes": ["http"],
        "allowed_ports": [43123], "path_prefixes": ["/"], "excluded_paths": [],
        "redirect_policy": "in_scope", "allow_auth_testing": False})


class FakeResolver:
    def __init__(self, table=None, default=("93.184.216.34",)) -> None:
        self.table, self.default = table or {}, list(default)
        self.calls: list[str] = []

    async def resolve(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        return list(self.table.get(host, self.default))


class StreamingTransport(httpx.AsyncBaseTransport):
    """Like a real network transport: the body is NOT pre-read (MockTransport
    reads and decodes it eagerly, which would hide the decode path)."""

    def __init__(self, content: bytes, headers: dict[str, str]) -> None:
        self.content, self.headers = content, headers

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=self.headers,
                              stream=httpx.ByteStream(self.content))


def make_stream(content: bytes, headers: dict[str, str]) -> GuardedHttpClient:
    return GuardedHttpClient(
        scope=scope("a.test"), budget=Budget(100, 60), policy=NetPolicy(),
        recorder=NullRecorder(), resolver=FakeResolver(),
        transport=StreamingTransport(content, headers))


def make(policy: NetPolicy, handler, *hosts: str, resolver=None) -> GuardedHttpClient:
    return GuardedHttpClient(
        scope=scope(*hosts), budget=Budget(100, 60), policy=policy,
        recorder=NullRecorder(), resolver=resolver or FakeResolver(),
        transport=httpx.MockTransport(handler))


def ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok", headers={
        "X-Host": request.headers.get("host", ""),
        "X-Sni": str(request.extensions.get("sni_hostname"))})


# ------------------------------------------------------------------------- E


@pytest.mark.parametrize("host,ips", [
    ("db.corp.internal", ["10.1.2.3"]),                 # private for a public name
    ("meta.corp.internal", ["169.254.169.254"]),        # always denied
    ("mixed.corp.internal", ["93.184.216.34", "10.1.2.3"]),
])
async def test_preflight_does_not_leak_denied_internal_addresses(
        client, user_token, monkeypatch, host, ips):
    async def fake_resolve(self, h_, port):
        return list(ips)

    monkeypatch.setattr(netguard.SystemResolver, "resolve", fake_resolve)
    t = await create_target(client, user_token, base_url=f"http://{host}:43123/")
    r = await client.post(f"/greybox/targets/{t['id']}/preflight",
                          headers=h(user_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is False
    assert body["resolved_ips"] == []
    assert body["blocked_reason"] == "address not permitted"
    text = r.text
    assert not any(ip in text for ip in ips)
    assert "ip_denied" not in text and "private" not in text


# ------------------------------------------------------------------------- G


def test_policy_blocked_endpoint_ignores_trailing_dot_and_case():
    p = NetPolicy(allow_private=True, blocked_endpoints=(("db.corp.test", 5432),))
    for h_ in ("db.corp.test", "db.corp.test.", "DB.Corp.Test."):
        assert p.address_denial(h_, "93.184.216.34", 5432) == "blocked_endpoint"
    assert p.address_denial("db.corp.test.", "93.184.216.34", 80) is None
    assert NetPolicy(blocked_hosts=frozenset({"evil.test"})).host_blocked("EVIL.test.")


async def test_trailing_dot_host_does_not_bypass_blocked_endpoint():
    policy = NetPolicy(allow_private=False,
                       blocked_endpoints=(("blocked.test", 43123),))
    for url in ("http://blocked.test:43123/", "http://blocked.test.:43123/"):
        c = make(policy, ok, "blocked.test")
        with pytest.raises(ScopeViolation) as ei:
            await c.request("GET", url, prov={"tool": "t"})
        assert ei.value.reason == "blocked_endpoint", url
        await c.aclose()


# ------------------------------------------------------------------------- H


async def test_idn_host_uses_punycode_for_host_header_and_sni():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return ok(request)

    c = make(NetPolicy(), handler, "xn--bcher-kva.test")
    resp = await c.request("GET", "http://bücher.test:43123/x", prov={"tool": "t"})
    assert resp.status == 200
    assert resp.header("x-host") == "xn--bcher-kva.test:43123"
    assert c.budget.used == 1            # a clean request, no crash after consume
    await c.aclose()


async def test_idn_host_sni_is_ascii():
    scope_https = ScopePolicy.from_dict({
        "allowed_hosts": ["xn--bcher-kva.test"], "allowed_schemes": ["https"],
        "allowed_ports": [443], "path_prefixes": ["/"], "excluded_paths": [],
        "redirect_policy": "in_scope", "allow_auth_testing": False})
    c = GuardedHttpClient(scope=scope_https, budget=Budget(10, 60),
                          policy=NetPolicy(), recorder=NullRecorder(),
                          resolver=FakeResolver(),
                          transport=httpx.MockTransport(ok))
    resp = await c.request("GET", "https://bücher.test/", prov={"tool": "t"})
    assert resp.header("x-sni") == "xn--bcher-kva.test"
    await c.aclose()


# ------------------------------------------------------------------------- I


class _SpyDecompress:
    def __init__(self, real, sizes):
        self._real, self._sizes = real, sizes

    def decompress(self, data, max_length=0):
        out = self._real.decompress(data, max_length)
        self._sizes.append(len(out))
        return out

    def __getattr__(self, name):
        return getattr(self._real, name)


async def test_gzip_bomb_is_capped_incrementally(monkeypatch):
    bomb = gzip.compress(b"\0" * (48 * 1024 * 1024), compresslevel=9)
    assert len(bomb) < READ_CAP            # one small raw chunk
    sizes: list[int] = []
    real = zlib.decompressobj
    monkeypatch.setattr(zlib, "decompressobj",
                        lambda *a, **k: _SpyDecompress(real(*a, **k), sizes))
    c = make_stream(bomb, {"Content-Encoding": "gzip"})
    resp = await c.request("GET", "http://a.test:43123/", prov={"tool": "t"})
    assert resp.truncated is True
    assert len(resp.body) == READ_CAP
    assert sizes and max(sizes) <= READ_CAP       # never expanded past the cap
    await c.aclose()


@pytest.mark.parametrize("coding,compress", [
    ("gzip", gzip.compress),
    ("deflate", zlib.compress),
    ("deflate", lambda b: zlib.compress(b)[2:-4]),   # raw deflate stream
])
async def test_small_compressed_bodies_decode(coding, compress):
    payload = b"hello world " * 100
    c = make_stream(compress(payload), {"Content-Encoding": coding})
    resp = await c.request("GET", "http://a.test:43123/", prov={"tool": "t"})
    assert resp.body == payload and resp.truncated is False
    await c.aclose()


async def test_identity_body_cap_still_applies():
    c = make_stream(b"x" * (READ_CAP * 2), {})
    resp = await c.request("GET", "http://a.test:43123/", prov={"tool": "t"})
    assert len(resp.body) == READ_CAP and resp.truncated is True
    await c.aclose()
