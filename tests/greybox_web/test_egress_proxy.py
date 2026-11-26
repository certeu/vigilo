"""Opt-in egress proxies: admin CRUD and authz, target validation, the
guarded network path through a forward proxy (scope per hop, local DNS defence, proxy
allow-list, auth, error mapping) and a full run through the proxy.

Only the synthetic 127.0.0.1 target and an in-process forward proxy are used.
"""
from __future__ import annotations

import base64
import json
import logging
import socket
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.models import (
    RUN_CHILD_MODELS, GreyboxEgressProxy, GreyboxHttpExchange, GreyboxRun, GreyboxTarget,
)
from src.greybox_web.netguard import (
    Budget, EgressProxy, GuardedHttpClient, NetPolicy, NullRecorder, ScopeViolation,
    TransportFailure,
)
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.supervisor import DIRECT_PROXY_HINT, _unreachable_message
from tests.greybox_web.conftest import (
    FAST_LIMITS, create_target, h, other_user_token, run_worker_once, start_run,
)
from tests.greybox_web.fixtures.forward_proxy import ForwardProxy

PX_USER = "pxuser-9f3a1c"
PX_PASS = "px-S3cr3t-Zq81wv"
BASIC = base64.b64encode(f"{PX_USER}:{PX_PASS}".encode()).decode()
NEEDLES = (PX_USER, PX_PASS, BASIC)


@pytest.fixture
def proxies_on(set_env):
    set_env("VIGILO_GREYBOX_EGRESS_PROXIES_ENABLED", "true")


@pytest.fixture
async def fwd():
    p = await ForwardProxy().start()
    yield p
    await p.stop()


@pytest.fixture
async def fwd_auth():
    p = await ForwardProxy(auth=(PX_USER, PX_PASS)).start()
    yield p
    await p.stop()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def proxy_body(url: str, **over) -> dict:
    body = {"name": "corp-squid", "url": url, "allowed_hosts": ["127.0.0.1"],
            "enabled": True}
    body.update(over)
    return body


async def make_proxy(client, admin_token, url: str, **over) -> dict:
    r = await client.post("/greybox/egress-proxies", headers=h(admin_token),
                          json=proxy_body(url, **over))
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------------------ switch, authz, CRUD


async def test_master_switch_off_is_404_and_targets_cannot_select(
        client, admin_token, user_token, target_server):
    for path in ("/greybox/egress-proxies", "/greybox/egress-proxies/available",
                 f"/greybox/egress-proxies/{uuid.uuid4()}"):
        for token in (admin_token, user_token):
            assert (await client.get(path, headers=h(token))).status_code == 404
    r = await client.post("/greybox/egress-proxies", headers=h(admin_token),
                          json=proxy_body("http://127.0.0.1:3128"))
    assert r.status_code == 404
    r = await client.post("/greybox/targets", headers=h(user_token), json={
        "name": "t", "base_url": target_server.url,
        "egress_proxy_id": str(uuid.uuid4())})
    assert r.status_code == 422
    assert "not enabled" in json.dumps(r.json())
    cfg = (await client.get("/greybox/config", headers=h(user_token))).json()
    assert cfg["egress_proxies_enabled"] is False


async def test_admin_crud_and_credentials_never_returned(
        client, admin_token, user_token, proxies_on, caplog):
    caplog.set_level(logging.INFO)
    created = await make_proxy(client, admin_token, "http://10.1.2.3:3128/",
                               username=PX_USER, password=PX_PASS,
                               allowed_hosts=["*.Corp.Test", "app.example.test"])
    assert created["url"] == "http://10.1.2.3:3128"
    assert created["has_credentials"] is True
    assert created["allowed_hosts"] == ["*.corp.test", "app.example.test"]
    assert set(created) == {"id", "name", "url", "has_credentials", "allowed_hosts",
                            "enabled", "created_at", "updated_at"}
    pid = created["id"]

    r = await client.get("/greybox/egress-proxies", headers=h(admin_token))
    assert [p["id"] for p in r.json()] == [pid]
    r = await client.get(f"/greybox/egress-proxies/{pid}", headers=h(admin_token))
    assert r.status_code == 200

    r = await client.patch(f"/greybox/egress-proxies/{pid}", headers=h(admin_token),
                           json={"enabled": False, "allowed_hosts": ["x.corp.test"]})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert r.json()["has_credentials"] is True          # untouched
    r = await client.patch(f"/greybox/egress-proxies/{pid}", headers=h(admin_token),
                           json={"username": None, "password": None})
    assert r.json()["has_credentials"] is False
    r = await client.patch(f"/greybox/egress-proxies/{pid}", headers=h(admin_token),
                           json={"username": PX_USER, "password": PX_PASS})
    assert r.json()["has_credentials"] is True

    everything = ""
    for path in ("/greybox/egress-proxies", f"/greybox/egress-proxies/{pid}"):
        everything += (await client.get(path, headers=h(admin_token))).text
    everything += caplog.text
    assert not any(n in everything for n in NEEDLES)

    r = await client.post("/greybox/egress-proxies", headers=h(admin_token),
                          json=proxy_body("http://10.9.9.9:3128"))
    assert r.status_code == 409                       # duplicate name

    assert (await client.delete(f"/greybox/egress-proxies/{pid}",
                                headers=h(admin_token))).status_code == 204
    assert (await client.get(f"/greybox/egress-proxies/{pid}",
                             headers=h(admin_token))).status_code == 404


async def test_credentials_are_encrypted_at_rest(client, admin_token, session_maker,
                                                 proxies_on):
    await make_proxy(client, admin_token, "http://10.1.2.3:3128",
                     username=PX_USER, password=PX_PASS)
    async with session_maker() as s:
        row = (await s.scalars(select(GreyboxEgressProxy))).one()
    assert row.credentials_enc and PX_PASS.encode() not in row.credentials_enc
    assert PX_USER.encode() not in row.credentials_enc


async def test_non_admin_cannot_manage_and_available_lists_enabled_only(
        client, admin_token, user_token, proxies_on):
    a = await make_proxy(client, admin_token, "http://10.1.2.3:3128", name="on")
    await make_proxy(client, admin_token, "http://10.1.2.4:3128", name="off",
                     enabled=False)
    pid = a["id"]
    hu = h(user_token)
    assert (await client.get("/greybox/egress-proxies", headers=hu)).status_code == 403
    assert (await client.post("/greybox/egress-proxies", headers=hu,
                              json=proxy_body("http://10.1.2.5:3128"))).status_code == 403
    assert (await client.get(f"/greybox/egress-proxies/{pid}", headers=hu)).status_code == 403
    assert (await client.patch(f"/greybox/egress-proxies/{pid}", headers=hu,
                               json={"enabled": False})).status_code == 403
    assert (await client.delete(f"/greybox/egress-proxies/{pid}",
                                headers=hu)).status_code == 403
    r = await client.get("/greybox/egress-proxies/available", headers=hu)
    assert r.status_code == 200
    assert r.json() == [{"id": pid, "name": "on", "allowed_hosts": ["127.0.0.1"]}]
    assert (await client.get("/greybox/egress-proxies/available")).status_code == 401
    cfg = (await client.get("/greybox/config", headers=hu)).json()
    assert cfg["egress_proxies_enabled"] is True


@pytest.mark.parametrize("url", [
    "http://user:pw@10.1.2.3:3128", "http://10.1.2.3:3128/path", "http://10.1.2.3:3128?x=1",
    "ftp://10.1.2.3:3128", "socks5://10.1.2.3:1080", "10.1.2.3:3128", "http://",
    "http://169.254.169.254:80", "http://[fe80::1]:3128", "http://0.0.0.0:3128",
    "http://224.0.0.1:3128",
])
async def test_proxy_url_validation(client, admin_token, proxies_on, url):
    r = await client.post("/greybox/egress-proxies", headers=h(admin_token),
                          json=proxy_body(url))
    assert r.status_code == 422, (url, r.text)


@pytest.mark.parametrize("hosts", [[], ["*"], ["*.com"], ["a/b"], ["host:80"]])
async def test_allowed_hosts_validation(client, admin_token, proxies_on, hosts):
    r = await client.post("/greybox/egress-proxies", headers=h(admin_token),
                          json=proxy_body("http://10.1.2.3:3128", allowed_hosts=hosts))
    assert r.status_code == 422, (hosts, r.text)


async def test_private_and_https_proxy_urls_are_allowed(client, admin_token, proxies_on):
    await make_proxy(client, admin_token, "https://proxy.corp.test:8443", name="a")
    await make_proxy(client, admin_token, "http://192.168.1.10:3128", name="b")


# ---------------------------------------------------------------- target validation


async def _target(client, token, base_url, proxy_id, **over):
    return await client.post("/greybox/targets", headers=h(token), json={
        "name": "t", "base_url": base_url, "egress_proxy_id": proxy_id, **over})


async def test_target_host_must_match_allowed_hosts(client, admin_token, user_token,
                                                    proxies_on):
    p = await make_proxy(client, admin_token, "http://10.1.2.3:3128",
                         allowed_hosts=["*.corp.test", "exact.other.test"])
    ok = await _target(client, user_token, "http://app.corp.test:8080/", p["id"],
                       scope={"allowed_hosts": ["app.corp.test", "*.corp.test",
                                                "exact.other.test"]})
    assert ok.status_code == 201, ok.text
    assert ok.json()["egress_proxy_id"] == p["id"]
    got = (await client.get(f"/greybox/targets/{ok.json()['id']}",
                            headers=h(user_token))).json()
    assert got["egress_proxy_id"] == p["id"]

    bad = await _target(client, user_token, "http://other.example.test/", p["id"])
    assert bad.status_code == 422
    assert "does not allow" in json.dumps(bad.json()) and "other.example.test" in bad.text
    # one extra in-scope host that the proxy does not allow is enough to refuse
    bad = await _target(client, user_token, "http://app.corp.test/", p["id"],
                        scope={"allowed_hosts": ["app.corp.test", "evil.test"]})
    assert bad.status_code == 422 and "evil.test" in bad.text
    # a wildcard wider than the proxy's is refused too
    bad = await _target(client, user_token, "http://app.corp.test/", p["id"],
                        scope={"allowed_hosts": ["app.corp.test", "*.test.example"]})
    assert bad.status_code == 422
    # validate endpoint reports it as a field error
    r = await client.post("/greybox/targets/validate", headers=h(user_token), json={
        "name": "t", "base_url": "http://nope.test/", "egress_proxy_id": p["id"]})
    assert r.status_code == 200 and r.json()["valid"] is False
    assert r.json()["errors"][0]["loc"] == ["body", "egress_proxy_id"]


async def test_unknown_or_disabled_proxy_is_422(client, admin_token, user_token,
                                                proxies_on):
    r = await _target(client, user_token, "http://127.0.0.1:43123/", str(uuid.uuid4()))
    assert r.status_code == 422 and "Unknown or disabled" in r.text
    p = await make_proxy(client, admin_token, "http://10.1.2.3:3128", enabled=False)
    r = await _target(client, user_token, "http://127.0.0.1:43123/", p["id"])
    assert r.status_code == 422 and "Unknown or disabled" in r.text


async def test_target_update_set_and_clear_proxy(client, admin_token, user_token,
                                                 proxies_on):
    p = await make_proxy(client, admin_token, "http://10.1.2.3:3128")
    t = await create_target(client, user_token)
    assert t["egress_proxy_id"] is None
    r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                           json={"egress_proxy_id": p["id"]})
    assert r.status_code == 200 and r.json()["egress_proxy_id"] == p["id"]
    r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                           json={"base_url": "http://elsewhere.test/"})
    assert r.status_code == 422                        # proxy no longer covers the host
    r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                           json={"egress_proxy_id": None})
    assert r.status_code == 200 and r.json()["egress_proxy_id"] is None


async def test_delete_blocked_by_active_run_then_clears_targets(
        client, admin_token, user_token, session_maker, proxies_on):
    p = await make_proxy(client, admin_token, "http://10.1.2.3:3128")
    r = await _target(client, user_token, "http://127.0.0.1:43123/", p["id"])
    tid = r.json()["id"]
    r = await start_run(client, user_token, tid, key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["egress_proxy"] == {"id": p["id"], "name": "corp-squid"}
    assert "url" not in run["egress_proxy"]
    assert (await client.delete(f"/greybox/egress-proxies/{p['id']}",
                                headers=h(admin_token))).status_code == 409
    assert (await client.post(f"/greybox/runs/{run['id']}/cancel",
                              headers=h(user_token), json={})).status_code == 202
    assert (await client.delete(f"/greybox/egress-proxies/{p['id']}",
                                headers=h(admin_token))).status_code == 204
    got = (await client.get(f"/greybox/targets/{tid}", headers=h(user_token))).json()
    assert got["egress_proxy_id"] is None
    # the finished run keeps its snapshot
    got = (await client.get(f"/greybox/runs/{run['id']}", headers=h(user_token))).json()
    assert got["egress_proxy"]["name"] == "corp-squid"


async def test_run_start_refused_when_proxy_disabled_after_target_saved(
        client, admin_token, user_token, proxies_on):
    p = await make_proxy(client, admin_token, "http://10.1.2.3:3128")
    t = (await _target(client, user_token, "http://127.0.0.1:43123/", p["id"])).json()
    await client.patch(f"/greybox/egress-proxies/{p['id']}", headers=h(admin_token),
                       json={"enabled": False})
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 422 and "egress" in r.text.lower()


# ------------------------------------------------------- the guarded client, proxied


def _scope(port: int, *hosts: str, schemes=("http",)) -> ScopePolicy:
    return ScopePolicy.from_dict({
        "allowed_hosts": list(hosts) or ["127.0.0.1"], "allowed_schemes": list(schemes),
        "allowed_ports": [port], "path_prefixes": ["/"], "excluded_paths": [],
        "redirect_policy": "in_scope", "allow_auth_testing": False})


class _Resolver:
    def __init__(self, table=None, fail=False):
        self.table, self.fail, self.calls = table or {}, fail, []

    async def resolve(self, host, port):
        self.calls.append(host)
        if self.fail:
            raise OSError("no such host")
        return self.table.get(host, ["192.0.2.7"])


def _client(scope, proxy: EgressProxy, *, resolver=None, allow_private=True):
    return GuardedHttpClient(scope=scope, budget=Budget(100, 60),
                             policy=NetPolicy(allow_private=allow_private),
                             recorder=NullRecorder(), egress_proxy=proxy,
                             resolver=resolver or _Resolver(), request_timeout_s=5)


def _proxy(fwd: ForwardProxy, *hosts: str, **kw) -> EgressProxy:
    return EgressProxy(id="p1", name="corp-squid", url=fwd.url,
                       allowed_hosts=tuple(hosts or ("127.0.0.1",)), **kw)


async def test_http_goes_absolute_form_through_the_proxy(fwd, target_server):
    port = int(target_server.url.rsplit(":", 1)[1].strip("/"))
    c = _client(_scope(port), _proxy(fwd))
    resp = await c.request("GET", target_server.url, prov={"tool": "t"})
    await c.aclose()
    assert resp.status == 200 and resp.resolved_ip is None
    assert fwd.requests and fwd.requests[0][1].startswith(f"http://127.0.0.1:{port}")
    ex = c.recorder.items[0]
    assert ex.via_proxy is True and ex.resolved_ip is None


async def test_out_of_scope_redirect_is_blocked_and_never_reaches_the_proxy(
        fwd, target_server):
    port = int(target_server.url.rsplit(":", 1)[1].strip("/"))
    c = _client(_scope(port), _proxy(fwd, "127.0.0.1", "localhost"))
    url = f"{target_server.url}redirect?to=http://localhost:{port}/secret"
    resp = await c.request("GET", url, prov={"tool": "t"})
    await c.aclose()
    assert resp.status == 302 and resp.redirect_blocked == "host_not_allowed"
    assert [u for _m, u in fwd.requests if "localhost" in u.split("?")[0]] == []
    assert len(fwd.requests) == 1
    assert target_server.counts().get("/secret", 0) == 0


async def test_proxy_allow_list_is_an_independent_second_check(fwd, target_server):
    port = int(target_server.url.rsplit(":", 1)[1].strip("/"))
    c = _client(_scope(port), _proxy(fwd, "only.corp.test"))
    with pytest.raises(ScopeViolation) as exc:
        await c.request("GET", target_server.url, prov={"tool": "t"})
    await c.aclose()
    assert exc.value.reason == "proxy_host_not_allowed"
    assert fwd.seen == 0


async def test_name_resolving_locally_to_metadata_is_refused(fwd):
    scope = _scope(80, "meta.corp.test")
    resolver = _Resolver({"meta.corp.test": ["169.254.169.254"]})
    c = _client(scope, _proxy(fwd, "*.corp.test"), resolver=resolver)
    with pytest.raises(ScopeViolation) as exc:
        await c.request("GET", "http://meta.corp.test/", prov={"tool": "t"})
    await c.aclose()
    assert exc.value.reason == "ip_denied:metadata"
    assert fwd.seen == 0
    assert c.recorder.items[0].blocked and not c.recorder.items[0].via_proxy


async def test_private_local_answer_follows_allow_private(fwd):
    scope = _scope(80, "app.corp.test")
    resolver = _Resolver({"app.corp.test": ["10.0.0.5"]})
    c = _client(scope, _proxy(fwd, "*.corp.test"), resolver=resolver, allow_private=False)
    with pytest.raises(ScopeViolation) as exc:
        await c.request("GET", "http://app.corp.test/", prov={"tool": "t"})
    await c.aclose()
    assert exc.value.reason == "ip_denied:private"
    assert fwd.seen == 0
    # allowed when the run allows private targets (the proxy gets the request; its own
    # resolution is authoritative, here it cannot resolve the name and answers 502)
    c = _client(scope, _proxy(fwd, "*.corp.test"), resolver=resolver, allow_private=True)
    with pytest.raises(TransportFailure) as exc2:
        await c.request("GET", "http://app.corp.test/", prov={"tool": "t"})
    await c.aclose()
    assert exc2.value.kind == "proxy_refused" and fwd.requests


async def test_name_the_engine_cannot_resolve_is_left_to_the_proxy(fwd):
    c = _client(_scope(80, "internal.corp.test"), _proxy(fwd, "*.corp.test"),
                resolver=_Resolver(fail=True))
    with pytest.raises(TransportFailure) as exc:
        await c.request("GET", "http://internal.corp.test/", prov={"tool": "t"})
    await c.aclose()
    assert exc.value.kind == "proxy_refused"            # the proxy was asked and refused
    assert fwd.requests == [("GET", "http://internal.corp.test/")]


async def test_ip_literal_goes_through_the_ip_policy(fwd):
    c = _client(_scope(80, "169.254.169.254"), _proxy(fwd, "169.254.169.254"))
    with pytest.raises(ScopeViolation) as exc:
        await c.request("GET", "http://169.254.169.254/latest/", prov={"tool": "t"})
    await c.aclose()
    assert exc.value.reason == "ip_denied:metadata" and fwd.seen == 0


async def test_host_blocked_still_applies(fwd):
    policy = NetPolicy(allow_private=True, blocked_hosts=frozenset({"corp.test"}))
    c = GuardedHttpClient(scope=_scope(80, "app.corp.test"), budget=Budget(10, 60),
                          policy=policy, recorder=NullRecorder(),
                          egress_proxy=_proxy(fwd, "*.corp.test"), resolver=_Resolver())
    with pytest.raises(ScopeViolation) as exc:
        await c.request("GET", "http://app.corp.test/", prov={"tool": "t"})
    await c.aclose()
    assert exc.value.reason == "blocked_host" and fwd.seen == 0


async def test_https_uses_connect_and_verifies_tls(fwd, target_server):
    port = int(target_server.url.rsplit(":", 1)[1].strip("/"))
    c = _client(_scope(port, schemes=("https",)), _proxy(fwd))
    with pytest.raises(TransportFailure) as exc:
        await c.request("GET", f"https://127.0.0.1:{port}/", prov={"tool": "t"})
    await c.aclose()
    assert fwd.connects == [f"127.0.0.1:{port}"] and fwd.requests == []
    assert exc.value.kind == "tls_error"      # plain-HTTP peer behind the tunnel


async def test_connect_refusal_is_target_refused_via_proxy():
    p = await ForwardProxy(deny_hosts=("denied.corp.test",)).start()
    try:
        c = _client(_scope(443, "denied.corp.test", schemes=("https",)),
                    _proxy(p, "*.corp.test"), resolver=_Resolver(fail=True))
        with pytest.raises(TransportFailure) as exc:
            await c.request("GET", "https://denied.corp.test/", prov={"tool": "t"})
        await c.aclose()
        assert exc.value.kind == "proxy_refused"
        assert p.connects == ["denied.corp.test:443"]
    finally:
        await p.stop()


async def test_proxy_auth_required_and_wrong_credentials(fwd_auth, target_server):
    port = int(target_server.url.rsplit(":", 1)[1].strip("/"))
    for kw in ({}, {"username": PX_USER, "password": "wrong"}):
        c = _client(_scope(port), _proxy(fwd_auth, **kw))
        with pytest.raises(TransportFailure) as exc:
            await c.request("GET", target_server.url, prov={"tool": "t"})
        await c.aclose()
        assert exc.value.kind == "proxy_auth"
    assert fwd_auth.auth_failures == 2
    c = _client(_scope(port), _proxy(fwd_auth, username=PX_USER, password=PX_PASS))
    resp = await c.request("GET", target_server.url, prov={"tool": "t"})
    await c.aclose()
    assert resp.status == 200
    # the Basic credential is never part of what the engine records
    blob = json.dumps([e.request_headers for e in c.recorder.items])
    assert not any(n in blob for n in NEEDLES)


async def test_proxy_down_is_proxy_unreachable():
    dead = EgressProxy(id="p", name="corp-squid", url=f"http://127.0.0.1:{_closed_port()}",
                       allowed_hosts=("127.0.0.1",))
    c = _client(_scope(43123), dead)
    with pytest.raises(TransportFailure) as exc:
        await c.request("GET", "http://127.0.0.1:43123/", prov={"tool": "t"})
    await c.aclose()
    assert exc.value.kind == "proxy_unreachable"


def test_env_proxy_variables_are_never_read(monkeypatch, fwd):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    c = GuardedHttpClient(scope=_scope(80), budget=Budget(1, 1), policy=NetPolicy(),
                          resolver=_Resolver())
    assert c._client._trust_env is False and not c._client._mounts


# ----------------------------------------------------------- failure text (direct path)


def test_direct_failure_text_hints_at_a_proxy_on_connection_refused():
    msg = _unreachable_message("http://x.corp.test/", "connect_error")
    assert msg.startswith("Target unreachable: could not connect to http://x.corp.test/")
    assert DIRECT_PROXY_HINT in msg and "PAC/WPAD" in msg
    assert DIRECT_PROXY_HINT not in _unreachable_message("http://x/", "dns_error")
    assert DIRECT_PROXY_HINT not in _unreachable_message("http://x/", "timeout")
    # with a proxy the text names it, distinguishes the failure and gives no direct hint
    for code, needle in (("proxy_unreachable", "proxy unreachable"),
                         ("proxy_refused", "target refused via proxy"),
                         ("proxy_auth", "credentials")):
        m = _unreachable_message("http://x/", code, "corp-squid")
        assert "corp-squid" in m and needle in m and DIRECT_PROXY_HINT not in m


# ---------------------------------------------------------------- API: preflight


async def test_preflight_through_the_proxy_and_its_errors(
        client, admin_token, user_token, proxies_on, fwd, fwd_auth, target_server):
    p = await make_proxy(client, admin_token, fwd.url, name="ok")
    t = await _target(client, user_token, target_server.url, p["id"])
    r = await client.post(f"/greybox/targets/{t.json()['id']}/preflight",
                          headers=h(user_token))
    assert r.status_code == 200 and r.json()["ok"] is True, r.text
    assert r.json()["resolved_ips"] == [] and fwd.requests

    bad = await make_proxy(client, admin_token, fwd_auth.url, name="badauth",
                           username=PX_USER, password="nope")
    t = await _target(client, user_token, target_server.url, bad["id"], name="t2")
    r = await client.post(f"/greybox/targets/{t.json()['id']}/preflight",
                          headers=h(user_token))
    assert r.json()["ok"] is False
    assert r.json()["blocked_reason"] == "proxy authentication failed"

    down = await make_proxy(client, admin_token, f"http://127.0.0.1:{_closed_port()}",
                            name="down")
    t = await _target(client, user_token, target_server.url, down["id"], name="t3")
    r = await client.post(f"/greybox/targets/{t.json()['id']}/preflight",
                          headers=h(user_token))
    assert r.json()["blocked_reason"] == "proxy unreachable"


# ------------------------------------------------------------- API: full runs


async def test_full_run_through_the_proxy(
        client, admin_token, user_token, session_maker, proxies_on, fwd_auth,
        target_server, caplog):
    from src.audit import redact
    caplog.set_level(logging.INFO)
    p = await make_proxy(client, admin_token, fwd_auth.url, name="corp-squid",
                         username=PX_USER, password=PX_PASS)
    r = await _target(client, user_token, target_server.url, p["id"],
                      limits=dict(FAST_LIMITS))
    assert r.status_code == 201, r.text
    r = await start_run(client, user_token, r.json()["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    assert r.json()["egress_proxy"] == {"id": p["id"], "name": "corp-squid"}
    try:
        assert await run_worker_once(session_maker) == run_id
        body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
        assert body["status"] == "succeeded", body
        assert body["egress_proxy"] == {"id": p["id"], "name": "corp-squid"}

        # the proxy carried the traffic (and demanded the stored credentials)
        assert len(fwd_auth.requests) >= 5 and fwd_auth.auth_failures == 0
        assert target_server.counts().get("/", 0) >= 1
        async with session_maker() as s:
            ex = (await s.scalars(select(GreyboxHttpExchange).where(
                GreyboxHttpExchange.run_id == run_id,
                GreyboxHttpExchange.blocked.is_(False)))).all()
            assert ex and all(e.via_proxy and e.resolved_ip is None for e in ex)
            assert len(ex) == len(fwd_auth.requests)
        # findings as usual
        r = await client.get(f"/greybox/runs/{run_id}/findings", headers=h(user_token))
        assert r.status_code == 200 and r.json()["items"]
        # run.started names the proxy
        r = await client.get(f"/greybox/runs/{run_id}/events", headers=h(user_token),
                             params={"kinds": "run.started"})
        started = [e for e in r.json()["items"] if e["kind"] == "run.started"]
        assert started and started[0]["data"]["egress_proxy"] == "corp-squid"
        # the report's Limitations section states the proxy
        r = await client.get(f"/greybox/runs/{run_id}/report", headers=h(user_token))
        md = r.json()["markdown"]
        limitations = md.split("## Limitations", 1)[1]
        assert "egress proxy corp-squid" in limitations and "DNS" in limitations

        # redaction: no credential form anywhere in the database, report or logs
        async with session_maker() as s:
            for model in (GreyboxTarget, GreyboxRun, GreyboxEgressProxy,
                          *RUN_CHILD_MODELS):
                for row in (await s.scalars(select(model))).all():
                    for column in model.__table__.columns:
                        v = getattr(row, column.name)
                        blob = v.decode("utf-8", "replace") if isinstance(v, bytes) \
                            else json.dumps(v, default=str) if isinstance(v, (dict, list)) \
                            else v if isinstance(v, str) else ""
                        for n in NEEDLES:
                            assert n not in blob, (model.__tablename__, column.name)
        assert not any(n in md for n in NEEDLES)
        assert not any(n in caplog.text for n in NEEDLES)
        # the stored snapshot has the URL but no credential
        async with session_maker() as s:
            snap = (await s.get(GreyboxRun, run_id)).egress_proxy
        assert snap == {"id": p["id"], "name": "corp-squid", "url": fwd_auth.url}
    finally:
        redact.clear()


async def test_run_fails_with_proxy_unreachable_message(
        client, admin_token, user_token, session_maker, proxies_on, target_server):
    p = await make_proxy(client, admin_token, f"http://127.0.0.1:{_closed_port()}")
    r = await _target(client, user_token, target_server.url, p["id"],
                      limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, r.json()["id"], key=uuid.uuid4().hex)
    run_id = r.json()["id"]
    assert str(await run_worker_once(session_maker)) == run_id
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "failed"
    assert "proxy unreachable" in body["error_summary"]
    assert "corp-squid" in body["error_summary"]
    assert target_server.counts() == {}            # nothing reached the target


async def test_run_fails_closed_when_the_proxy_is_disabled_after_start(
        client, admin_token, user_token, session_maker, proxies_on, fwd, target_server):
    p = await make_proxy(client, admin_token, fwd.url)
    r = await _target(client, user_token, target_server.url, p["id"],
                      limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, r.json()["id"], key=uuid.uuid4().hex)
    run_id = r.json()["id"]
    await client.patch(f"/greybox/egress-proxies/{p['id']}", headers=h(admin_token),
                       json={"enabled": False})
    assert str(await run_worker_once(session_maker)) == run_id
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "failed"
    assert fwd.seen == 0 and target_server.counts() == {}      # never went direct either
