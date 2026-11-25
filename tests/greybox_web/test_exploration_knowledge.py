"""Knowledge builder tests (M2): what the model sees is the graph — capped,
redacted, honest about tools — and the quiet-mode fingerprint reacts to real
state changes only."""
from __future__ import annotations

import json
import uuid

import pytest

from src.greybox_web.exploration.knowledge import (
    KnowledgeInputs,
    build,
    fingerprint,
)
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxGraphNode,
    GreyboxRun,
    GreyboxTarget,
    GreyboxWorkOrder,
)


@pytest.fixture
async def seeded(session_maker):
    """A run with a small but representative graph: endpoints (API + login form),
    a parameter, observations, an open lead, a settled lead, a finding, work
    orders in every state."""
    owner = uuid.uuid4()
    run_id = uuid.uuid4()
    target_id = uuid.uuid4()
    async with session_maker() as s:
        s.add(GreyboxTarget(id=target_id, owner_id=owner, name="t",
                            base_url="http://target.test/",
                            scope={"allowed_hosts": ["target.test"],
                                   "allowed_schemes": ["http"], "allowed_ports": [80]},
                            limits={"max_requests": 100, "max_duration_s": 600},
                            checks=None, description="Ticketing API demo"))
        await s.flush()
        s.add(GreyboxRun(id=run_id, target_id=target_id, owner_id=owner,
                         base_url="http://target.test/",
                         scope={"allowed_hosts": ["target.test"],
                                "allowed_schemes": ["http"], "allowed_ports": [80]},
                         limits={"max_requests": 100, "max_duration_s": 600},
                         checks=["headers.security", "cors.policy"],
                         status="running", idempotency_key="k"))
        host = GreyboxAsset(run_id=run_id, kind="host", key="target.test",
                            label="target.test", in_scope=True, first_seen_seq=1,
                            state="in_scope", version=1)
        svc = GreyboxAsset(run_id=run_id, kind="service", key="http://target.test/",
                           label="http", in_scope=True, first_seen_seq=1,
                           state="in_scope", version=1, parent_id=None)
        s.add(host), s.add(svc)
        await s.flush()
        ep1 = GreyboxAsset(run_id=run_id, kind="endpoint", key="http://target.test/api/tickets",
                           label="/api/tickets", in_scope=True, tested=True,
                           first_seen_seq=2, state="tested", version=2, parent_id=svc.id,
                           data={"status_codes": [200, 200],
                                 "content_type": "application/json",
                                 "title": "Tickets"})
        ep2 = GreyboxAsset(run_id=run_id, kind="endpoint", key="http://target.test/login",
                           label="/login", in_scope=True, first_seen_seq=3,
                           state="in_scope", version=3, parent_id=svc.id,
                           data={"status_codes": [200], "login_form": {
                               "method": "POST", "fields": {"user": "text",
                                                            "pass": "password"}}})
        out_scope = GreyboxAsset(run_id=run_id, kind="endpoint",
                                 key="http://elsewhere.test/x", label="/x",
                                 in_scope=False, first_seen_seq=4,
                                 state="out_of_scope", version=4, parent_id=svc.id)
        s.add_all([ep1, ep2, out_scope])
        await s.flush()
        s.add(GreyboxAsset(run_id=run_id, kind="parameter",
                           key="http://target.test/api/tickets#query:page",
                           label="page", in_scope=True, first_seen_seq=5,
                           state="in_scope", version=5, parent_id=ep1.id,
                           data={"location": "query", "name": "page"}))
        s.add(GreyboxGraphNode(run_id=run_id, kind="objective", key="objective",
                               label="Assess", status="active", version=1,
                               data={"base_url": "http://target.test/"}))
        s.add(GreyboxGraphNode(run_id=run_id, kind="observation",
                               key="signal.login_form|/login", label="Login form on /login",
                               status="recorded", version=2,
                               data={"facts": {"fields": ["user", "pass"]},
                                     "url": "http://target.test/login"}))
        s.add(GreyboxGraphNode(run_id=run_id, kind="lead", key="lead:llm:api-auth",
                               label="API authorization untested", status="open",
                               version=3, data={"hypothesis": "OLAC is missing.",
                                                "type": "explorer"}))
        s.add(GreyboxGraphNode(run_id=run_id, kind="lead", key="lead:cookie-flags",
                               label="Cookie flags", status="confirmed", version=4,
                               outcome="reported", data={"type": "rule"}))
        s.add(GreyboxWorkOrder(run_id=run_id, dedup_key="wo|1", kind="check",
                               tool="headers.security", title="Headers",
                               reason="rules", params={"url": "http://target.test/"},
                               priority=25, status="done", node_id=None,
                               created_seq=1, result_summary="2 issues"))
        s.add(GreyboxWorkOrder(run_id=run_id, dedup_key="wo|2", kind="check",
                               tool="cors.policy", title="CORS", reason="rules",
                               params={"url": "http://target.test/"},
                               priority=30, status="pending", node_id=None,
                               created_seq=2))
        await s.commit()
    return run_id


async def test_build_shape_and_selection(seeded, session_maker):
    async with session_maker() as s:
        k = await build(s, seeded, KnowledgeInputs(
            budget={"requests_used": 12, "requests_max": 100},
            frontier=["http://target.test/api/users"],
            coverage={"pages_fetched": 5, "max_pages": 50},
            agent={"calls_left": 39, "tokens_left": 380000},
            delta=[{"kind": "observation.recorded", "summary": "Login form"},
                   {"kind": "finding.verified", "summary": "x"}],
            todolist=[{"step": "Examine the API", "status": "in_progress"}]))
    assert k["run"]["base_url"] == "http://target.test/"
    assert "Ticketing API demo" in k["run"]["objective"]
    assert k["run"]["scope"]                      # a scope summary exists
    eps = {e["url"]: e for e in k["assets"]["endpoints"]}
    assert set(eps) == {"http://target.test/api/tickets",
                        "http://target.test/login"}     # out-of-scope dropped
    assert eps["http://target.test/api/tickets"]["api"] is True
    assert eps["http://target.test/api/tickets"]["tested"] is True
    assert eps["http://target.test/login"]["login_form"]["fields"] == ["pass", "user"]
    assert eps["http://target.test/login"]["api"] is False
    assert k["assets"]["parameters"][0]["name"] == "page"
    assert k["coverage"]["endpoints_discovered"] == 2
    assert k["coverage"]["endpoints_examined"] == 1
    assert k["frontier"] == ["http://target.test/api/users"]
    assert k["hypotheses"]["open"][0]["label"] == "API authorization untested"
    assert k["hypotheses"]["settled"][0]["status"] == "confirmed"
    assert k["work"]["pending"][0]["tool"] == "cors.policy"
    assert k["work"]["recent"][0]["summary"] == "2 issues"
    assert k["todolist"][0]["step"] == "Examine the API"
    assert k["delta"][0]["kind"] == "observation.recorded"
    # honest tool list: registered, selected checks, no verify.* and no active probes
    assert "discovery.crawl" in k["tools"]
    assert "headers.security" in k["tools"] and "cors.policy" in k["tools"]
    assert "cookies.flags" not in k["tools"]          # not selected for the run
    assert not any(t.startswith("verify.") for t in k["tools"])
    assert "infra.tls" not in k["tools"]


async def test_build_unknown_run_returns_empty(seeded, session_maker):
    async with session_maker() as s:
        assert await build(s, uuid.uuid4()) == {}


async def test_fingerprint_reacts_to_state_not_noise(seeded, session_maker):
    async with session_maker() as s:
        base = KnowledgeInputs(frontier=["http://target.test/api/users"],
                               coverage={"pages_fetched": 5})
        k1 = await build(s, seeded, base)
        f1 = fingerprint(k1)
        # identical inputs: identical fingerprint
        k2 = await build(s, seeded, base)
        assert fingerprint(k2) == f1
        # frontier drained (work progressed): different fingerprint
        k3 = await build(s, seeded, KnowledgeInputs(
            frontier=[], coverage={"pages_fetched": 6, "max_pages": 50}))
        assert fingerprint(k3) != f1
        # a new pending work order changes it
        async with session_maker() as w:
            w.add(GreyboxWorkOrder(run_id=seeded, dedup_key="wo|3", kind="discovery",
                                   tool="discovery.crawl", title="Crawl",
                                   reason="llm", params={}, priority=20,
                                   status="pending", created_seq=3))
            await w.commit()
        k4 = await build(s, seeded, base)
        assert fingerprint(k4) != f1


# ------------------------------------------- static assets and the byte budget

import json  # noqa: E402

from src.greybox_web.exploration.knowledge import (  # noqa: E402
    BYTE_BUDGET,
    COMPACT_BYTE_BUDGET,
    compact,
    is_static_asset,
    size,
    summarise_static,
)


async def _add_assets(session_maker, run_id, keys):
    async with session_maker() as s:
        svc = (await s.scalars(__import__("sqlalchemy").select(GreyboxAsset).where(
            GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "service"))).one()
        s.add_all([GreyboxAsset(
            run_id=run_id, kind="endpoint", key=k, label=k.rsplit("/", 1)[-1],
            in_scope=True, first_seen_seq=10 + i, state="in_scope", version=10 + i,
            parent_id=svc.id, data={"status_codes": [200]})
            for i, k in enumerate(keys)])
        await s.commit()


def test_static_asset_classification():
    for u in ("http://t/_next/static/chunks/a1b2.js", "http://t/static/app.css",
              "http://t/favicon.ico", "http://t/fonts/x.woff2", "http://t/a/b.js.map",
              "http://t/images/logo.png", "http://t/assets/x"):
        assert is_static_asset(u), u
    for u in ("http://t/", "http://t/login", "http://t/api/tickets",
              "http://t/robots.txt", "http://t/_next/data/build/x.json"):
        assert not is_static_asset(u), u


def test_summarise_static_counts_by_prefix_and_type():
    urls = [f"http://t/_next/static/chunks/{i}.js" for i in range(40)] \
        + [f"http://t/_next/static/css/{i}.css" for i in range(5)] \
        + ["http://t/favicon.ico"]
    s = summarise_static(urls)
    assert s["count"] == 46
    assert s["by_prefix"]["/_next/static"] == 45
    assert s["by_type"]["js"] == 40 and s["by_type"]["css"] == 5


async def test_static_assets_are_aggregated_not_listed(seeded, session_maker):
    keys = [f"http://target.test/_next/static/chunks/{i:016x}.js" for i in range(300)]
    keys += [f"http://target.test/static/img/{i}.png" for i in range(50)]
    keys += ["http://target.test/dashboard", "http://target.test/api/users"]
    await _add_assets(session_maker, seeded, keys)
    async with session_maker() as s:
        k = await build(s, seeded, KnowledgeInputs(
            frontier=["http://target.test/_next/static/chunks/zzz.js",
                      "http://target.test/settings"]))
    urls = {e["url"] for e in k["assets"]["endpoints"]}
    assert "http://target.test/dashboard" in urls and "http://target.test/api/users" in urls
    assert not any("/_next/static" in u or "/static/img" in u for u in urls)
    st = k["assets"]["static"]
    assert st["count"] == 350 and st["by_prefix"]["/_next/static"] == 300
    assert st["by_prefix"]["/static"] == 50
    assert k["coverage"]["endpoints_discovered"] >= 350      # the true total is kept
    # the frontier is filtered before it is capped (defect F3): the real page is
    # first, and a hashed build chunk never displaces it
    assert k["frontier"][0] == "http://target.test/settings"
    assert "_next/static/chunks/0000" not in json.dumps(k)    # nothing listed
    assert "zzz.js" not in json.dumps(k["assets"]["endpoints"])


async def test_static_assets_do_not_change_the_quiet_fingerprint(seeded, session_maker):
    async with session_maker() as s:
        before = fingerprint(await build(s, seeded))
    await _add_assets(session_maker, seeded,
                      [f"http://target.test/_next/static/chunks/n{i}.js" for i in range(20)])
    async with session_maker() as s:
        assert fingerprint(await build(s, seeded)) == before


async def test_large_synthetic_graph_stays_inside_the_byte_budget(
        seeded, session_maker, capsys):
    """A Next.js-like site: 1500 static chunks, 400 real endpoints, 800 work orders."""
    keys = [f"http://target.test/_next/static/chunks/{i:016x}.js" for i in range(1500)]
    keys += [f"http://target.test/app/page{i}?id={i}" for i in range(400)]
    await _add_assets(session_maker, seeded, keys)
    async with session_maker() as s:
        s.add_all([GreyboxWorkOrder(
            run_id=seeded, dedup_key=f"wo|big|{i}", kind="check", tool="headers.security",
            title=f"Headers {i}", reason="x" * 200,
            params={"url": f"http://target.test/app/page{i}"}, priority=25,
            status="done" if i % 3 else "pending", node_id=None, created_seq=100 + i,
            result_summary="r" * 300) for i in range(800)])
        await s.commit()
        k = await build(s, seeded, KnowledgeInputs(
            frontier=[f"http://target.test/f/{i}" for i in range(500)],
            delta=[{"kind": "x", "summary": "s" * 300}] * 40))
    n = size(k)
    assert n <= BYTE_BUDGET, n
    assert k["assets"]["static"]["count"] == 1500
    small = compact(k)
    assert size(small) <= COMPACT_BYTE_BUDGET, size(small)
    assert size(small) < n and small["run"] == k["run"] and small["tools"] == k["tools"]
    with capsys.disabled():
        print(f"\n[knowledge] synthetic 1900 endpoints/800 work orders: "
              f"snapshot {n} B (budget {BYTE_BUDGET}), compact {size(small)} B")


def test_cache_buster_query_strings_on_static_urls_are_not_parameters():
    from src.greybox_web.tools.discovery import url_query_params
    assert url_query_params("http://t/favicon.ico?favicon.0b3bf435.ico") == []
    assert url_query_params("http://t/_next/static/a.js?v=3") == []
    assert [p.name for p in url_query_params("http://t/search?q=x")] == ["q"]


# ------------------------------------------------- operator messages (run chat)


async def test_hints_are_not_in_the_untrusted_knowledge(seeded, session_maker):
    from src.greybox_web.models import GreyboxHint
    async with session_maker() as s:
        s.add(GreyboxHint(run_id=seeded, text="please look at /admin", action="note",
                          status="addressed", result="noted", work_order_ids=[],
                          created_by=uuid.uuid4(), created_by_name="op@example.test"))
        await s.commit()
    async with session_maker() as s:
        k = await build(s, seeded)
    assert "hints" not in k and "please look at /admin" not in json.dumps(k)


def test_fingerprint_is_keyed_by_message_ids_not_by_action_and_status():
    """Two notes look identical as action:target:status; by id they differ."""
    k = {"assets": {"endpoints": []}, "work": {}}
    a, b = uuid.uuid4(), uuid.uuid4()
    assert fingerprint(k) == fingerprint(k, [])
    assert fingerprint(k, [a]) != fingerprint(k)
    assert fingerprint(k, [a]) != fingerprint(k, [b])
    assert fingerprint(k, [a, b]) == fingerprint(k, [b, a])


def test_cors_gap_requires_a_check_on_an_api_endpoint():
    """Regression (live Codex run): cors.policy on the HTML root closed the service's
    CORS gap although only the API sends CORS headers."""
    from types import SimpleNamespace as NS
    from src.greybox_web.exploration.knowledge import _gaps
    svc = NS(key="http://h:1", id=1, data={})
    api = NS(key="http://h:1/api/me", id=2, data={"content_type": "application/json"},
             tested=False, parent_id=1)
    root_done = NS(status="done", tool="cors.policy", params={"url": "http://h:1/"})
    gaps, _ = _gaps({"cors.policy"}, True, True, [root_done], [api], [], [svc])
    assert gaps["services"] == [{"url": "http://h:1/", "cors_on": "http://h:1/api/me",
                                 "missing": ["cors.policy"]}]
    api_done = NS(status="done", tool="cors.policy", params={"url": "http://h:1/api/me"})
    gaps, _ = _gaps({"cors.policy"}, True, True, [root_done, api_done], [api], [], [svc])
    assert gaps["services"] == []
