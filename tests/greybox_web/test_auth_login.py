"""auth.login against three real login styles, and identity attribution of every
recorded request.

* Fjord Intranet — HTML form with a hidden CSRF token bound to a pre-session
  cookie, session id rotated on login;
* Ledgerline — JSON-only token endpoint returning a bearer token in the body;
* Lumen Boards — JSON or form login setting a session cookie.

Each established identity must then reach its own data — and only the requests
made with it may be attributed to it.
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from src.greybox_web.netguard import Budget, GuardedHttpClient, NetPolicy
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.tools import ToolContext, auth
from tests.greybox_web.conftest import FAST_LIMITS
from tests.greybox_web.fixtures import fjord_intranet, ledgerline_api, lumen_boards

FIX = Path(__file__).parent / "fixtures"


class ListRecorder:
    def __init__(self) -> None:
        self.rows: list = []

    async def record(self, ex) -> int:
        self.rows.append(ex)
        return len(self.rows)


def accounts(name: str) -> dict[str, dict]:
    spec = json.loads((FIX / name / "assessment.json").read_text())
    return {a["label"]: {"user": a["user"], "password": a["password"]}
            for a in spec["accounts"]}


@asynccontextmanager
async def ctx_for(url: str, name: str):
    port = urlsplit(url).port
    scope = ScopePolicy.from_dict({
        "allowed_hosts": ["127.0.0.1"], "allowed_schemes": ["http"],
        "allowed_ports": [port], "path_prefixes": ["/"],
        "redirect_policy": "in_scope", "allow_auth_testing": True})
    rec = ListRecorder()
    client = GuardedHttpClient(
        scope=scope, budget=Budget(300, 300), policy=NetPolicy(allow_private=True),
        rate_limit_rps=50, request_timeout_s=5, recorder=rec)
    accts = accounts(name)
    try:
        yield (lambda params: ToolContext(
            http=client.bind("auth.login"), base_url=url, scope=scope,
            limits=dict(FAST_LIMITS), params=params,
            accounts=tuple((k, v["user"], {}) for k, v in accts.items()),
            account_credentials=lambda label: accts.get(label))), client, rec
    finally:
        await client.aclose()


@pytest.fixture(scope="module")
def servers():
    started = [m.serve(0) for m in (fjord_intranet, ledgerline_api, lumen_boards)]
    yield {"fjord": started[0][1], "ledgerline": started[1][1],
           "lumen": started[2][1]}
    for s, _ in started:
        s.should_exit = True


def _established(res) -> dict:
    assert res.counts.get("established") == 1, res.summary
    return res.observations[0].facts


async def test_csrf_protected_form_login(servers):
    url = servers["fjord"]
    async with ctx_for(url, "fjord_intranet") as (mk, client, rec):
        facts = _established(await auth.login(mk({"url": url + "login",
                                                  "account": "sofia",
                                                  "user_field": "username"})))
        assert facts["body"] == "form" and "fjord_session" in facts["cookie_names"]
        # the session works: sofia's own profile, under her identity
        me = await client.bind("t").get(url + "api/me", session="sofia")
        assert me.status == 200 and "sofia" in me.text
        assert rec.rows[-1].identity == "sofia"


async def test_json_login_with_bearer_token_in_the_body(servers):
    url = servers["ledgerline"]
    async with ctx_for(url, "ledgerline_api") as (mk, client, rec):
        facts = _established(await auth.login(mk({"url": url + "v1/auth/token",
                                                  "account": "omar",
                                                  "user_field": "username"})))
        assert facts["authorization"] is True and facts["cookie_names"] == []
        me = await client.bind("t").get(url + "v1/me", session="omar")
        assert me.status == 200 and "omar" in me.text
        anon = await client.bind("t").get(url + "v1/me", session="anon")
        assert anon.status == 401
        assert [r.identity for r in rec.rows[-2:]] == ["omar", "anon"]
        # the token never reaches an observation
        assert "Bearer" not in json.dumps(facts)


async def test_explicit_json_body_and_two_identities(servers):
    url = servers["lumen"]
    async with ctx_for(url, "lumen_boards") as (mk, client, rec):
        for label in ("maya", "iris"):
            _established(await auth.login(mk({"url": url + "api/v2/session",
                                              "account": label, "user_field": "email",
                                              "body": "json"})))
        h = client.bind("t")
        maya = await h.get(url + "api/v2/me", session="maya")
        iris = await h.get(url + "api/v2/me", session="iris")
        assert "maya@" in maya.text and "iris@" in iris.text
        assert [r.identity for r in rec.rows[-2:]] == ["maya", "iris"]


async def test_account_login_url_overrides_a_wrong_planner_guess(servers):
    url = servers["lumen"]
    async with ctx_for(url, "lumen_boards") as (mk, client, _rec):
        ctx = mk({"url": url, "account": "maya"})
        secret = {**accounts("lumen_boards")["maya"], "login_url": "/api/v2/session",
                  "user_field": "email", "body": "json"}
        ctx.account_credentials = lambda _label: secret
        result = await auth.login(ctx)
        _established(result)
        assert result.observations[0].url.endswith("/api/v2/session")
        me = await client.bind("t").get(url + "api/v2/me", session="maya")
        assert me.status == 200 and "maya@" in me.text


async def test_wrong_password_is_rejected_not_established(servers):
    url = servers["ledgerline"]
    async with ctx_for(url, "ledgerline_api") as (mk, client, rec):
        ctx = mk({"url": url + "v1/auth/token", "account": "omar",
                  "user_field": "username"})
        ctx.account_credentials = lambda label: {"user": "omar", "password": "nope"}
        res = await auth.login(ctx)
        assert res.counts.get("established") == 0
        assert client.sessions() == []


async def test_unknown_session_label_is_refused(servers):
    url = servers["lumen"]
    async with ctx_for(url, "lumen_boards") as (_mk, client, _rec):
        with pytest.raises(ValueError):
            await client.bind("t").get(url + "api/v2/me", session="nobody")


def test_identity_labels():
    c = GuardedHttpClient.__new__(GuardedHttpClient)
    c._cookie = None
    assert c._identity_label(None, None) == "anon"
    assert c._identity_label("anon", None) == "anon"
    assert c._identity_label("maya", None) == "maya"
    # a browser page carrying its own jar
    assert c._identity_label("maya", "s=1") == "maya"
    assert c._identity_label("anon", "") == "anon"
    assert c._identity_label("anon", "s=1") == "browser-session"
    c._cookie = "provided=1"
    assert c._identity_label(None, None) == "provided-cookie"
    assert c._identity_label(None, "provided=1") == "provided-cookie"
