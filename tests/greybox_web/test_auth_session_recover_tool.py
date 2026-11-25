from __future__ import annotations

import json
from dataclasses import dataclass

from src.greybox_web.netguard import HttpResponse
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.tools import ToolContext, auth, get


@dataclass
class FakeHttp:
    responses: list[HttpResponse]
    labels: list[str]

    def sessions(self):
        return [{"label": label} for label in self.labels]

    async def get(self, _url, **_kwargs):
        return self.responses.pop(0)

    def establish_session(self, label, _cookie, _authorization):
        self.labels.append(label)


def response(status=200):
    return HttpResponse(url="http://target.test/me", status=status, headers=[],
                        body=b"ok", truncated=False, exchange_id=7,
                        exchange_ids=[7], elapsed_ms=1,
                        hops=["http://target.test/me"])


def context(http, allowed=True, credentials=None):
    return ToolContext(
        http=http,
        base_url="http://target.test/",
        scope=ScopePolicy.from_dict({
            "allowed_hosts": ["target.test"], "allowed_schemes": ["http"],
            "allowed_ports": [80], "allow_auth_testing": allowed}),
        limits={},
        params={"account": "member", "probe_url": "http://target.test/me"},
        accounts=(("member", "member@example.test", {}),),
        account_credentials=credentials)


def test_session_recovery_is_a_guarded_registered_tool():
    spec = get("auth.session_recover")
    assert spec is not None
    assert spec.kind == "discovery"
    assert spec.param_keys == ("account", "url", "probe_url", "login_url")


async def test_session_recovery_reports_fresh_without_credentials():
    result = await auth.session_recover(context(FakeHttp([response()], ["member"])))
    assert result.counts == {"checked": 1, "usable": 1, "recovered": 0, "blocked": 0}
    assert result.observations[0].facts["state"] == "fresh"


async def test_session_recovery_reauthenticates_without_disclosing_secrets(monkeypatch):
    http = FakeHttp([response(401), response()], ["member"])
    secret = {"user": "member@example.test", "password": "do-not-disclose"}

    async def login(ctx):
        assert ctx.account_credentials("member") == secret
        http.establish_session("member", "session=secret", None)
        return type("LoginResult", (), {"counts": {"established": 1}})()

    monkeypatch.setattr(auth, "login", login)
    result = await auth.session_recover(context(http, credentials=lambda _label: secret))
    encoded = json.dumps({"summary": result.summary,
                          "observations": [item.facts for item in result.observations]})
    assert result.counts["recovered"] == 1
    assert result.observations[0].exchange_ids == [7]
    assert secret["password"] not in encoded and "session=secret" not in encoded


async def test_session_recovery_does_not_access_credentials_when_auth_is_disabled():
    accessed = False

    def credentials(_label):
        nonlocal accessed
        accessed = True
        return {"user": "member", "password": "secret"}

    result = await auth.session_recover(context(
        FakeHttp([response(401)], ["member"]), allowed=False,
        credentials=credentials))
    assert not accessed
    assert result.counts["blocked"] == 1
    assert result.observations[0].facts["state"] == "blocked"
