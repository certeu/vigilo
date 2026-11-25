"""Network protocol identification against the Harbor Net segment: the inert
identification hellos (memcached version, SMTP EHLO), the TLS handshake, and the
negative controls that must stay clean (Redis with AUTH, PostgreSQL rejecting,
an SSH banner). Everything goes through the guarded capability (scope, pacing,
audit); the out-of-scope listener must never see a connection."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src.greybox_web.netcap import GuardedNet, ToolNet
from src.greybox_web.netguard import Budget, GuardedHttpClient, NetPolicy
from src.greybox_web.tools import ToolContext
from src.greybox_web.tools import netinv
from tests.greybox_web.fixtures import harbor_net
from tests.greybox_web.test_policy_network import Rec, _scope

SPEC = json.loads((Path(harbor_net.__file__).parent / "assessment.json").read_text())


@pytest.fixture
async def lab():
    if not harbor_net.addresses_available():
        pytest.skip(harbor_net.UNAVAILABLE_REASON)
    lab = await harbor_net.start(dynamic_ports=True)
    yield lab
    await lab.close()


def _ctx(params, lab):
    scope = _scope({"targets": SPEC["network"]["targets"],
                    "ports": sorted({port for _, port in lab.ports.values()}),
                    "protocols": SPEC["network"]["protocols"], "rate_per_s": 20})
    client = GuardedHttpClient(scope=scope, budget=Budget(200, 120),
                               policy=NetPolicy(allow_private=True), recorder=Rec())
    net = GuardedNet(client)
    return ToolContext(http=client.bind("t"), base_url="http://127.0.0.11/",
                       scope=scope, limits={}, params=params,
                       net=ToolNet(net, {"tool": "net.probe"})), client


async def _probe(lab, host, port, probe=None):
    ctx, client = _ctx({"host": host, "port": port, **({"probe": probe} if probe else {})}, lab)
    try:
        return await netinv.probe(ctx), ctx
    finally:
        await client.aclose()


def _checks(res):
    return {f.check_id for f in res.findings}


async def test_memcached_without_auth_is_one_finding_and_reverifies(lab):
    res, ctx = await _probe(lab, *lab.ports["data-01:memcached"], "memcached_version")
    titles = [f.title for f in res.findings]
    assert any("Memcached answers commands without authentication" in t for t in titles)
    assert "net.exposed_store" not in _checks(res)       # one root cause, one finding
    for _ in range(50):                    # the lab records on connection close
        if lab.received.get("data-01:memcached"):
            break
        await asyncio.sleep(0.02)
    assert lab.received["data-01:memcached"][-1] == b"version\r\n"
    f = next(f for f in res.findings if f.check_id == "net.unauthenticated")
    ctx2, client = _ctx(f.verify, lab)
    try:
        v = await netinv.verify(ctx2)
    finally:
        await client.aclose()
    assert v.confirmed, v.note


async def test_smtp_auth_without_starttls_needs_the_ehlo_answer(lab):
    res, _ = await _probe(lab, *lab.ports["app-01:smtp"])           # greeting only
    assert not any("STARTTLS" in f.title for f in res.findings)
    res, _ = await _probe(lab, *lab.ports["app-01:smtp"], "smtp_ehlo")
    assert any("without STARTTLS" in f.title for f in res.findings), \
        [f.title for f in res.findings]


async def test_expired_self_signed_certificate(lab):
    ctx, client = _ctx({"host": lab.ports["edge-gw:https"][0], "port": lab.ports["edge-gw:https"][1]}, lab)
    try:
        res = await netinv.tls(ctx)
        cert = res.observations[0].facts["certificate"]
        assert cert["expired"] and cert["self_signed"]
        assert "vpn.harbor.internal" in cert["subject"]
        assert res.observations[0].facts["trusted"] is False
        f = res.findings[0]
        assert f.check_id == "net.tls" and "expired" in f.title
        assert f.finding_class == "misconfiguration"
        v = await netinv.verify(_ctx(f.verify, lab)[0])
        assert v.confirmed, v.note
    finally:
        await client.aclose()


async def test_tls_on_a_cleartext_port_is_reported_not_crashed(lab):
    ctx, client = _ctx({"host": lab.ports["edge-gw:ssh"][0], "port": lab.ports["edge-gw:ssh"][1]}, lab)
    try:
        res = await netinv.tls(ctx)
    finally:
        await client.aclose()
    assert res.observations[0].facts["state"] in ("not_tls", "error")
    assert res.findings == []


@pytest.mark.parametrize("host,port,probe", [
    ("127.0.0.13", 6379, "redis_ping"),          # NOAUTH: correctly configured
    ("127.0.0.13", 5432, "crlf"),                # rejects
    ("127.0.0.11", 2222, None),                  # current OpenSSH
])
async def test_negative_controls_have_no_vulnerability(lab, host, port, probe):
    key = {6379: "data-01:redis", 5432: "data-01:postgres", 2222: "edge-gw:ssh"}[port]
    res, _ = await _probe(lab, *lab.ports[key], probe)
    assert not [f for f in res.findings if f.finding_class == "vulnerability"], \
        [f.title for f in res.findings]


async def test_out_of_scope_host_is_never_contacted(lab):
    host, port = lab.ports["out-of-scope:http"]
    res, _ = await _probe(lab, host, port)
    assert lab.outside_connections == 0
    ctx, client = _ctx({"host": host, "port": port}, lab)
    try:
        r = await netinv.tls(ctx)
    finally:
        await client.aclose()
    assert r.observations[0].facts["state"] == "blocked"
    assert lab.outside_connections == 0
