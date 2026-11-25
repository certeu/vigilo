"""T4/T5/T6/T8: the guarded client — the engine's only network path.

Uses httpx.MockTransport plus a fake resolver, so no real network is touched:
scope per hop (scope first, then IP policy), IP pinning (Host header kept),
redirect policy, cookie attachment only to allowed hosts, blocked attempts
counted, body cap, rate limit and the request budget.
"""
from __future__ import annotations

import time

import httpx
import pytest

from src.greybox_web.netguard import (
    Budget,
    BudgetExhausted,
    GuardedHttpClient,
    NetPolicy,
    NullRecorder,
    RunCancelled,
    ScopeViolation,
    TransportFailure,
)
from src.greybox_web.scope import ScopePolicy

SCOPE = ScopePolicy.from_dict({
    "allowed_hosts": ["127.0.0.1", "app.demo.test", "public.test", "meta.test"],
    "allowed_schemes": ["http"],
    "allowed_ports": [43123],
    "path_prefixes": ["/"],
    "excluded_paths": ["/forbidden"],
    "redirect_policy": "in_scope",
    "allow_auth_testing": False,
})
POLICY = NetPolicy(allow_private=True)

RESOLVER_TABLE = {
    "127.0.0.1": ["127.0.0.1"],
    "app.demo.test": ["127.0.0.1"],          # scoped name -> private: rebinding
    "public.test": ["93.184.216.34"],
    "meta.test": ["169.254.169.254"],        # always-denied range
}


class FakeResolver:
    def __init__(self, table: dict[str, list[str]] | None = None) -> None:
        self.table = table or RESOLVER_TABLE
        self.calls: list[str] = []

    async def resolve(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        return self.table.get(host, ["192.0.2.1"])


def handler(fn):
    return httpx.MockTransport(fn)


def echo(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok",
                          headers={"X-Wire-Url": str(request.url),
                                   "X-Wire-Host": request.headers.get("host", "")})


def client(**kw) -> GuardedHttpClient:
    return GuardedHttpClient(
        scope=SCOPE, budget=Budget(100, 60), policy=POLICY,
        recorder=NullRecorder(), resolver=FakeResolver(), **kw)


async def test_pins_to_resolved_ip_with_host_header_preserved():
    c = client(transport=handler(echo))
    resp = await c.request("GET", "http://public.test:43123/x", prov={"tool": "t"})
    # Wire URL is the pinned IP; the Host header keeps the original name.
    assert resp.header("x-wire-url").startswith("http://93.184.216.34:43123/")
    assert resp.header("x-wire-host") == "public.test:43123"
    await c.aclose()


async def test_out_of_scope_blocked_and_recorded():
    c = client(transport=handler(echo))
    with pytest.raises(ScopeViolation) as exc:
        await c.request("GET", "http://other.test:43123/x", prov={"tool": "t"})
    assert exc.value.reason == "host_not_allowed"
    assert c.recorder.items[-1].blocked
    assert c.recorder.items[-1].block_reason == "host_not_allowed"
    assert c.budget.used == 1                  # blocked attempts count (T8)
    await c.aclose()


async def test_excluded_path_blocked():
    c = client(transport=handler(echo))
    with pytest.raises(ScopeViolation) as exc:
        await c.request("GET", "http://127.0.0.1:43123/forbidden/page", prov={"tool": "t"})
    assert exc.value.reason == "path_excluded"
    await c.aclose()


async def test_port_and_scheme_enforced():
    c = client(transport=handler(echo))
    with pytest.raises(ScopeViolation) as e1:
        await c.request("GET", "http://127.0.0.1:9999/", prov={"tool": "t"})
    assert e1.value.reason == "port_not_allowed"
    with pytest.raises(ScopeViolation) as e2:
        await c.request("GET", "https://127.0.0.1:43123/", prov={"tool": "t"})
    assert e2.value.reason == "scheme_not_allowed"
    await c.aclose()


async def test_redirect_to_metadata_blocked_at_hop():
    """T5: a redirect to a metadata endpoint is blocked at the hop (scope passes
    because the host is scoped, but the address class is never authorisable)."""

    def redirect_to_meta(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redirect":
            return httpx.Response(302, headers={"Location": "http://meta.test:43123/"})
        return httpx.Response(200, text="meta")

    c = client(transport=handler(redirect_to_meta))
    resp = await c.request("GET", "http://127.0.0.1:43123/redirect", prov={"tool": "t"})
    assert resp.status == 302
    assert resp.redirect_blocked == "ip_denied:metadata"
    blocked = [e for e in c.recorder.items if e.blocked]
    assert blocked and blocked[-1].url == "http://meta.test:43123/"
    assert blocked[-1].redirect_hop == 1
    assert blocked[-1].request_headers == []   # nothing was ever sent
    await c.aclose()


async def test_redirect_in_scope_followed_cookie_only_for_allowed_hosts():
    def redirect(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redirect":
            return httpx.Response(302, headers={
                "Location": "http://public.test:43123/landing"})
        # The landing page echoes the Cookie header it received.
        return httpx.Response(200, text=request.headers.get("cookie", "none"))

    c = client(transport=handler(redirect), cookie_header="session=secret-value-1")
    resp = await c.request("GET", "http://127.0.0.1:43123/redirect", prov={"tool": "t"})
    assert resp.url.endswith("/landing")
    assert resp.status == 200
    # An allowed host receives the cookie (attachment rule)...
    assert "session=secret-value-1" in resp.text
    # ... and the original request to 127.0.0.1 carried it too.
    first = [e for e in c.recorder.items if not e.blocked][0]
    assert ("Cookie", "session=secret-value-1") in first.request_headers
    await c.aclose()


async def test_rebinding_scoped_name_resolving_private_denied():
    """T6: a scoped *name* that resolves to a private address is denied even
    with private targets allowed; only explicitly private hosts (IP literals,
    localhost) may resolve private."""
    c = client(transport=handler(echo))
    with pytest.raises(ScopeViolation) as exc:
        await c.request("GET", "http://app.demo.test:43123/x", prov={"tool": "t"})
    assert exc.value.reason == "private_ip_for_public_name"
    blocked = [e for e in c.recorder.items if e.blocked]
    assert blocked and blocked[-1].block_reason == "private_ip_for_public_name"
    await c.aclose()


async def test_budget_exhaustion():
    c = client(transport=handler(echo))
    c.budget.max_requests = 2
    await c.request("GET", "http://127.0.0.1:43123/a", prov={"tool": "t"})
    await c.request("GET", "http://127.0.0.1:43123/b", prov={"tool": "t"})
    with pytest.raises(BudgetExhausted) as exc:
        await c.request("GET", "http://127.0.0.1:43123/c", prov={"tool": "t"})
    assert exc.value.budget == "requests"
    assert len(c.recorder.items) == 2          # exactly the allowed requests
    await c.aclose()


async def test_cancel_flag_checked_before_request():
    c = client(transport=handler(echo))
    c.budget.cancelled = True
    with pytest.raises(RunCancelled):
        await c.request("GET", "http://127.0.0.1:43123/a", prov={"tool": "t"})
    await c.aclose()


async def test_body_read_cap():
    big = "x" * (2 * 1024 * 1024)

    def huge(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=big)

    c = client(transport=handler(huge))
    resp = await c.request("GET", "http://127.0.0.1:43123/big", prov={"tool": "t"})
    assert resp.truncated
    assert len(resp.body) <= 1024 * 1024 + 64
    await c.aclose()


async def test_rate_limit_paces_requests():
    c = client(transport=handler(echo), rate_limit_rps=5)
    t0 = time.monotonic()
    for _ in range(6):
        await c.request("GET", "http://127.0.0.1:43123/r", prov={"tool": "t"})
    assert time.monotonic() - t0 >= 0.8          # 6 requests at 5/s ≈ 1 s
    await c.aclose()


async def test_dangerous_methods_rejected():
    c = client(transport=handler(echo))
    # state-changing methods are an activity-policy refusal (recorded, never sent)
    with pytest.raises(ScopeViolation) as exc:
        await c.request("DELETE", "http://127.0.0.1:43123/x", prov={"tool": "t"})
    assert exc.value.reason == "state_changing_not_allowed"
    # methods the guard never speaks are a programming error
    for m in ("TRACE", "CONNECT"):
        with pytest.raises(ValueError):
            await c.request(m, "http://127.0.0.1:43123/x", prov={"tool": "t"})
    await c.aclose()


async def test_transport_failure_recorded():
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope", request=request)

    c = client(transport=handler(fail))
    with pytest.raises(TransportFailure) as exc:
        await c.request("GET", "http://127.0.0.1:43123/x", prov={"tool": "t"})
    assert exc.value.kind == "connect_error"
    assert c.recorder.items[-1].error == "connect_error"
    await c.aclose()
