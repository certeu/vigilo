"""Regression tests for the authorised security assessment (grey-box side): report
markdown injection, SSE re-authorisation, cursor bounds, API port block."""
from __future__ import annotations

import asyncio
import uuid

import pytest

from src.greybox_web import report
from src.greybox_web.api import events as api_events
from tests.greybox_web.conftest import create_target, h, start_run


# ------------------------------------------------------------ report markdown injection


@pytest.mark.parametrize("evil", [
    "[click](http://evil.example/)", "![x](http://evil.example/p.png)",
    "<img src=x onerror=alert(1)>", "<http://evil.example>", "http://evil.example/a",
    "www.evil.example", "me@evil.example", "# heading", "- item", "1. item",
    "line1\n\n# injected\n[a](b)", "a | b |", "**bold** _em_ ~~s~~", "x # y",
])
def test_md_neutralises_untrusted_text(evil):
    out = report._md(evil)
    assert "\n" not in out and " " not in out
    assert "<" not in out and ">" not in out                       # no raw HTML / autolink
    import re
    # every markdown-active char is preceded by a backslash
    for m in re.finditer(r"[\[\]*_|~@]", out):
        assert out[m.start() - 1] == "\\", (evil, out)
    assert "](" not in out.replace("\\](", "")                     # no live link
    assert "http://" not in out and "https://" not in out         # bare URL not autolinkable
    assert not re.match(r"^(#|-|\+|>|=|\d+[.)])", out)            # cannot open a block


def test_code_span_cannot_be_escaped():
    for evil in ("a`b", "``", "`x`", "`` ` ``", "x\n`y"):
        c = report._code(evil)
        fence = c[:len(c) - len(c.lstrip("`"))]
        inner = c[len(fence):-len(fence)]
        assert c.endswith(fence) and "\n" not in c
        import re
        assert all(len(m) != len(fence) for m in re.findall(r"`+", inner))


async def test_report_with_hostile_finding(client, user_token, session_maker):
    from src.greybox_web.models import GreyboxFinding
    t = await create_target(client, user_token)
    r = await start_run(client, user_token, t["id"])
    run_id = uuid.UUID(r.json()["id"])
    evil_cookie = "[pwn](http://evil.example/)<script>alert(1)</script>"
    async with session_maker() as s:
        s.add(GreyboxFinding(
            run_id=run_id, dedup_key="k1", confidence="high", first_event_seq=1, version=1, check_id="cookies.flags", severity="low", status="verified",
            title=f"Cookie {evil_cookie} lacks HttpOnly",
            description=f"Server: ![i](http://evil.example/p.png) {evil_cookie}",
            location={"url": "http://127.0.0.1:43123/<b>x</b>", "method": "GET",
                      "parameter": "a`b"},
            evidence=[], verification={}, detection_hints=[], references=[]))
        await s.commit()
        md = await report.generate(s, run_id)
    assert "<script>" not in md and "<b>" not in md and "<img" not in md
    assert "[pwn](" not in md and "![i](" not in md
    assert "&lt;script&gt;" in md


# ------------------------------------------------------------ cursor bounds (#12)


async def test_oversized_cursors_are_422_not_500(client, user_token):
    t = await create_target(client, user_token)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    big = 2 ** 63
    for url in (f"/greybox/runs/{run_id}/events?after_seq={big}",
                f"/greybox/runs/{run_id}/events?before_seq={big}",
                f"/greybox/runs/{run_id}/events/stream?after={big}",
                f"/greybox/runs/{run_id}/graph/exploration?since_version={big}",
                f"/greybox/runs/{run_id}/graph/assets?since_version={big}"):
        r = await client.get(url, headers=h(user_token))
        assert r.status_code == 422, (url, r.status_code)
    r = await client.get(f"/greybox/runs/{run_id}/events?after_seq={2 ** 63 - 1}",
                         headers=h(user_token))
    assert r.status_code == 200
    r = await client.get(f"/greybox/runs/{run_id}/events/stream",
                         headers={**h(user_token), "Last-Event-ID": str(big)})
    assert r.status_code == 422


# ------------------------------------------------------------ SSE re-authorisation (#3)


async def test_stream_closes_after_logout(client, user_token, monkeypatch):
    monkeypatch.setattr(api_events, "REVALIDATE_S", 0.05)
    t = await create_target(client, user_token)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]   # queued: stays open

    async def read():
        async with client.stream("GET", f"/greybox/runs/{run_id}/events/stream",
                                 headers=h(user_token)) as r:
            return r.status_code, "".join([c async for c in r.aiter_text()])

    task = asyncio.create_task(read())
    await asyncio.sleep(0.5)
    assert not task.done()                        # still streaming (token valid)
    assert (await client.post("/auth/jwt/logout", headers=h(user_token))).status_code == 204
    status, body = await asyncio.wait_for(task, timeout=10)
    assert status == 200 and "event: end" not in body      # closed by revocation, not completion
    # reconnect now gets 401, which is the SPA's sign-out path
    r = await client.get(f"/greybox/runs/{run_id}/events/stream", headers=h(user_token))
    assert r.status_code == 401


async def test_stream_closes_when_token_expires(client, user_token, monkeypatch):
    """Expiry is enforced by the same re-validation (decode_jwt checks ``exp``)."""
    monkeypatch.setattr(api_events, "REVALIDATE_S", 0.05)
    from src.webapi.auth import backend
    t = await create_target(client, user_token)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    calls = {"n": 0}
    real = backend.authenticate_bearer

    async def expiring(token, session):
        calls["n"] += 1
        return None if calls["n"] > 1 else await real(token, session)
    monkeypatch.setattr(backend, "authenticate_bearer", expiring)

    async def read():
        async with client.stream("GET", f"/greybox/runs/{run_id}/events/stream",
                                 headers=h(user_token)) as r:
            return "".join([c async for c in r.aiter_text()])
    body = await asyncio.wait_for(read(), timeout=10)
    assert "event: end" not in body and calls["n"] >= 2


# ------------------------------------------------------------ platform API port (#14)


def test_blocked_endpoints_follow_api_port(set_env):
    from src.greybox_web import settings as gbs
    ports = {(e.host, e.port) for e in gbs.blocked_endpoints()}
    assert ("private", 8080) in ports and ("private", 8081) in ports   # safe default
    set_env("VIGILO_API_PORT", "9443")
    set_env("VIGILO_API_HOST", "203.0.113.10")
    ports = {(e.host, e.port) for e in gbs.blocked_endpoints()}
    assert ("private", 9443) in ports and ("private", 8080) in ports
    assert ("203.0.113.10", 9443) in ports
