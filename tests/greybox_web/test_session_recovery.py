from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from src.greybox_web.netguard import HttpResponse
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.session_recovery import probe, recover
from src.greybox_web.tools import ToolContext


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


def response(status=200, url="http://target.test/me", body="ok"):
    return HttpResponse(url=url, status=status, headers=[], body=body.encode(),
                        truncated=False, exchange_id=1, exchange_ids=[1],
                        elapsed_ms=1, hops=["http://target.test/me", url])


def context(http, account_credentials=None):
    return ToolContext(http=http, base_url="http://target.test/",
        scope=ScopePolicy(("target.test",), ("http",), (80,)), limits={}, params={},
        accounts=(("member", "member", {}),),
        account_credentials=account_credentials)


async def test_probe_distinguishes_missing_expired_and_fresh():
    missing = await probe(context(FakeHttp([], [])), "member", "http://target.test/me")
    expired = await probe(context(FakeHttp([response(401)], ["member"])),
                          "member", "http://target.test/me")
    fresh = await probe(context(FakeHttp([response()], ["member"])),
                        "member", "http://target.test/me")
    assert (missing.state, expired.state, fresh.state) == ("missing", "expired", "fresh")
    assert fresh.exchange_ids == (1,)


async def test_probe_detects_external_identity_provider():
    result = await probe(context(FakeHttp([response(200,
        "https://login.microsoftonline.com/authorize")], ["member"])),
        "member", "http://target.test/me")
    assert result.state == "identity_boundary" and not result.usable


async def test_recover_uses_supported_account_login_and_reprobes(monkeypatch):
    http = FakeHttp([response(401), response(200)], ["member"])

    async def login(ctx):
        assert ctx.params == {"url": "http://target.test/login", "account": "member"}
        return SimpleNamespace(counts={"established": 1})

    from src.greybox_web.tools import auth
    monkeypatch.setattr(auth, "login", login)
    ctx = context(http, lambda label: {"user": label, "password": "not-returned"})
    result = await recover(ctx, "member", "http://target.test/me",
                           "http://target.test/login")
    assert result.state == "fresh" and result.recovered


async def test_recovery_stays_blocked_without_configured_account():
    ctx = context(FakeHttp([response(401)], ["member"]))
    result = await recover(ctx, "member", "http://target.test/me")
    assert result.state == "expired" and "no configured account" in result.reason
