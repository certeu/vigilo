"""Target-neutral policy: the network scope,
the activity policy and the raw-protocol guard (acceptance 7, 12).

Real loopback sockets, a fake resolver, no external network.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from src.greybox_web import modes, netscope
from src.greybox_web.netcap import GuardedNet
from src.greybox_web.netguard import (
    Budget,
    GuardedHttpClient,
    NetPolicy,
    ScopeViolation,
)
from src.greybox_web.scope import PolicyContext, ScopePolicy, build_scope


class Rec:
    def __init__(self) -> None:
        self.rows = []

    async def record(self, ex):
        self.rows.append(ex)
        return len(self.rows)


class FakeResolver:
    def __init__(self, table):
        self.table = table

    async def resolve(self, host, port):
        return self.table.get(host, ["192.0.2.1"])


CTX = PolicyContext(allow_private=True)


def _scope(network=None, **extra) -> ScopePolicy:
    base, pol, errs = build_scope("http://127.0.0.1:18000/",
                                  {**({"network": network} if network else {}), **extra},
                                  CTX)
    assert not errs, errs
    return pol


# ------------------------------------------------------------------ scope model


def test_network_scope_parses_explicit_boundaries_only():
    s, errs = netscope.parse({"targets": ["127.0.0.0/30", "db.lab.test"],
                              "ports": [22, "8000-8002"], "protocols": ["tcp", "dns"]})
    assert not errs
    assert s.check("127.0.0.1", 22, "tcp").allowed
    assert s.check("127.0.0.4", 22, "tcp").reason == "address_not_in_scope"  # neighbour
    assert s.check("127.0.0.1", 23, "tcp").reason == "port_not_in_scope"
    assert s.check("127.0.0.1", 22, "http").reason == "protocol_not_allowed"
    assert s.check("db.lab.test", 8001, "tcp").allowed
    assert s.check("x.db.lab.test", 8001, "tcp").reason == "name_not_in_scope"
    assert s.addresses() == ["127.0.0.1", "127.0.0.2"]


@pytest.mark.parametrize("raw,needle", [
    ({"targets": ["10.0.0.0/8"], "ports": [22]}, "at most 256"),
    ({"targets": ["*.lab.test"], "ports": [22]}, "Wildcards"),
    ({"targets": ["127.0.0.1"], "ports": ["1-65535"]}, "At most 256 ports"),
    ({"targets": ["127.0.0.1"]}, "authorised ports"),
    ({"targets": ["127.0.0.1"], "ports": [22], "protocols": ["icmp"]}, "one of"),
    ({"targets": ["127.0.0.1"], "ports": [22], "rate_per_s": 1000}, "between"),
    ({"targets": ["169.254.169.254"], "ports": [80]}, ""),
])
def test_network_scope_refuses_unsafe_or_vague_boundaries(raw, needle):
    _, _, errs = build_scope("http://127.0.0.1:18000/", {"network": raw}, CTX)
    assert errs and needle in " ".join(e.msg for e in errs)


def test_scope_round_trips_and_mode_snapshot():
    pol = _scope({"targets": ["127.0.0.1"], "ports": [22]}, activity={"state_changing": True})
    d = pol.to_dict()
    d["assessment"] = {"mode": "network", "disabled_capabilities": ["dns"]}
    back = ScopePolicy.from_dict(d)
    assert back.network.ports == (22,) and back.state_changing
    assert back.mode == "network" and back.disabled_capabilities == ("dns",)
    caps = modes.CapabilityPolicy.for_run(back.mode, back.disabled_capabilities)
    assert caps.allows(modes.TCP_CONNECT) and not caps.allows(modes.BROWSER)
    assert not caps.allows("dns")
    # a web-only scope authorises no socket at all
    assert _scope().check_endpoint("127.0.0.1", 22, "tcp").reason == "no_network_scope"


def test_http_over_an_authorised_network_segment_only_with_the_http_protocol():
    tcp_only = _scope({"targets": ["127.0.0.2"], "ports": [8080]})
    assert tcp_only.check_url("http://127.0.0.2:8080/").reason == "host_not_allowed"
    with_http = _scope({"targets": ["127.0.0.2"], "ports": [8080],
                        "protocols": ["tcp", "http"]})
    assert with_http.check_url("http://127.0.0.2:8080/x").allowed
    assert not with_http.check_url("http://127.0.0.2:8081/x").allowed
    assert not with_http.check_url("http://127.0.0.3:8080/x").allowed


def test_artifact_and_network_modes_never_reach_web_only_capabilities():
    art = modes.CapabilityPolicy.for_run("artifact")
    assert not art.allows(modes.effective(None))       # legacy HTTP tool
    assert art.allows(modes.SANDBOX) and art.allows(modes.RECORDED)
    net = modes.CapabilityPolicy.for_run("network")
    assert not net.allows(modes.BROWSER) and net.allows(modes.TCP_CONNECT)
    assert not modes.CapabilityPolicy.for_run("web").allows(modes.TCP_CONNECT)


# ------------------------------------------------------------------ activity


async def test_state_changing_methods_are_refused_and_recorded_by_default():
    sent = []
    transport = httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200))
    rec = Rec()
    pol = _scope()
    client = GuardedHttpClient(scope=pol, budget=Budget(50, 60),
                               policy=NetPolicy(allow_private=True), recorder=rec,
                               resolver=FakeResolver({}), transport=transport)
    prov = {"tool": "t"}
    for m in ("PUT", "PATCH", "DELETE"):
        with pytest.raises(ScopeViolation) as exc:
            await client.request(m, "http://127.0.0.1:18000/api/x", prov=prov,
                                 body=b"{}")
        assert exc.value.reason == "state_changing_not_allowed"
    assert not sent and all(r.block_reason == "state_changing_not_allowed"
                            for r in rec.rows)
    # a JSON POST is a read-shaped request the guard carries with its own body
    r = await client.request("POST", "http://127.0.0.1:18000/api/x", prov=prov,
                             body='{"a":1}', content_type="application/json")
    assert r.status == 200 and sent[-1].content == b'{"a":1}'
    assert sent[-1].headers["content-type"] == "application/json"
    await client.aclose()
    opted = _scope(activity={"state_changing": True})
    client = GuardedHttpClient(scope=opted, budget=Budget(50, 60),
                               policy=NetPolicy(allow_private=True), recorder=rec,
                               resolver=FakeResolver({}), transport=transport)
    r = await client.request("DELETE", "http://127.0.0.1:18000/api/x", prov=prov)
    assert r.status == 200 and sent[-1].method == "DELETE"
    await client.aclose()


# ------------------------------------------------------------------ raw TCP / DNS


@pytest.fixture
async def listeners():
    """Two loopback services: one with a banner, one silent; plus a closed port."""
    async def banner(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n")
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(100), 1)
        except asyncio.TimeoutError:
            pass
        writer.close()

    received = []

    async def silent(reader, writer):
        try:
            received.append(await asyncio.wait_for(reader.read(100), 2))
        except asyncio.TimeoutError:
            pass
        writer.close()

    s1 = await asyncio.start_server(banner, "127.0.0.1", 0)
    s2 = await asyncio.start_server(silent, "127.0.0.1", 0)
    p1 = s1.sockets[0].getsockname()[1]
    p2 = s2.sockets[0].getsockname()[1]
    # a port that is certainly closed: bind then release
    s3 = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    p3 = s3.sockets[0].getsockname()[1]
    s3.close()
    await s3.wait_closed()
    yield {"banner": p1, "silent": p2, "closed": p3, "received": received}
    s1.close()
    s2.close()


def _net(scope, *, resolver=None, proxy=None, policy=None):
    rec = Rec()
    client = GuardedHttpClient(scope=scope, budget=Budget(100, 60),
                               policy=policy or NetPolicy(allow_private=True),
                               recorder=rec,
                               resolver=resolver or FakeResolver({}))
    client.proxy = proxy
    return GuardedNet(client), rec, client


async def test_tcp_probe_reads_banners_and_states_within_scope(listeners):
    ports = [listeners["banner"], listeners["silent"], listeners["closed"]]
    scope = _scope({"targets": ["127.0.0.1"], "ports": ports, "rate_per_s": 20})
    net, rec, client = _net(scope)
    prov = {"tool": "net.probe"}
    r = await net.tcp("127.0.0.1", listeners["banner"], prov=prov)
    assert r.state == "open" and r.banner.startswith(b"SSH-2.0-OpenSSH_7.2p2")
    r2 = await net.tcp("127.0.0.1", listeners["silent"], prov=prov)
    assert r2.state == "open" and r2.banner == b""
    r3 = await net.tcp("127.0.0.1", listeners["closed"], prov=prov)
    assert r3.state == "closed"
    assert [x.scheme for x in rec.rows] == ["tcp"] * 3
    assert rec.rows[0].response_body.startswith(b"SSH-2.0")
    await client.aclose()


async def test_tcp_outside_the_boundary_never_opens_a_socket(listeners):
    scope = _scope({"targets": ["127.0.0.1"], "ports": [listeners["banner"]]})
    resolver = FakeResolver({"evil.test": ["127.0.0.1"], "meta.test": ["169.254.169.254"]})
    net, rec, client = _net(scope, resolver=resolver)
    prov = {"tool": "x"}
    cases = [("127.0.0.1", listeners["silent"], "port_not_in_scope"),
             ("127.0.0.2", listeners["banner"], "address_not_in_scope"),
             ("evil.test", listeners["banner"], "name_not_in_scope")]
    for host, port, reason in cases:
        r = await net.tcp(host, port, prov=prov)
        assert r.state == "blocked" and r.reason == reason, (host, r)
    assert all(row.blocked for row in rec.rows)
    assert listeners["received"] == []                 # nothing reached the silent one
    await client.aclose()


async def test_listed_name_resolving_to_a_never_class_is_refused():
    scope = _scope({"targets": ["meta.test"], "ports": [80]})
    net, rec, client = _net(scope, resolver=FakeResolver({"meta.test": ["169.254.169.254"]}))
    r = await net.tcp("meta.test", 80, prov={"tool": "x"})
    assert r.state == "blocked" and r.reason and r.reason != "name_not_in_scope"
    await client.aclose()


async def test_payloads_are_inert_unless_state_changing_is_authorised(listeners):
    port = listeners["silent"]
    scope = _scope({"targets": ["127.0.0.1"], "ports": [port], "rate_per_s": 20})
    net, rec, client = _net(scope)
    r = await net.tcp("127.0.0.1", port, prov={"tool": "x"}, send="FLUSHALL\r\n")
    assert r.state == "blocked" and r.reason == "custom_payload_not_allowed"
    r = await net.tcp("127.0.0.1", port, prov={"tool": "x"}, send="redis_ping")
    assert r.state == "open" and r.sent == "redis_ping"
    await asyncio.sleep(0.2)
    assert listeners["received"] == [b"PING\r\n"]
    await client.aclose()


async def test_raw_tcp_is_refused_when_traffic_must_use_the_egress_proxy(listeners):
    scope = _scope({"targets": ["127.0.0.1"], "ports": [listeners["banner"]]})
    net, rec, client = _net(scope, proxy=object())
    r = await net.tcp("127.0.0.1", listeners["banner"], prov={"tool": "x"})
    assert r.state == "blocked" and r.reason == "egress_proxy_no_raw_tcp"
    await client.aclose()


async def test_dns_resolves_only_authorised_names():
    scope = _scope({"targets": ["db.lab.test"], "ports": [5432],
                    "protocols": ["tcp", "dns"]})
    net, rec, client = _net(scope, resolver=FakeResolver({"db.lab.test": ["10.1.1.5"]}))
    ok = await net.resolve("db.lab.test", prov={"tool": "x"})
    assert ok.addresses == ["10.1.1.5"] and ok.reason is None
    no = await net.resolve("other.lab.test", prov={"tool": "x"})
    assert no.reason == "name_not_in_scope" and not no.addresses
    assert [r.scheme for r in rec.rows] == ["dns", "dns"] and rec.rows[1].blocked
    await client.aclose()


def test_established_session_tokens_become_redaction_secrets():
    from src.greybox_web import redaction
    client = GuardedHttpClient(scope=_scope(), budget=Budget(1, 1),
                               policy=NetPolicy(allow_private=True))
    client.establish_session("ana", "sid=ana-session-token-777; theme=dark",
                             "Bearer eyJhbGciOi.token-xyz")
    out = redaction.text("echo ana-session-token-777 and eyJhbGciOi.token-xyz dark")
    assert "ana-session-token-777" not in out and "eyJhbGciOi.token-xyz" not in out
    assert "dark" in out                    # short values are not secrets
