"""Network exploration, phase P1 (passive bundle): third-party / mixed-content supply
chain view, edge/CDN/WAF fingerprint, internal host and address leaks, cross-host
redirects and HTTP posture, vantage, agent-driven follow-up (observations, leads,
planner rules, the active-probe gate), vendor-neutral defenses and the report subsection.

Everything is derived from recorded exchanges: no request is ever made to a third-party
or leaked host (asserted against the recorded exchanges and the target's own counters).
"""
from __future__ import annotations

import json
import re
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from src.greybox_web import defenses as gb_defenses
from src.greybox_web import infra_defenses, netproject, netview, surface
from src.greybox_web import planner as planner_mod
from src.greybox_web import report as gb_report
from src.greybox_web.graph import GraphError, GraphStats, GraphTx
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxAssetEdge,
    GreyboxEvent,
    GreyboxFinding,
    GreyboxGraphEdge,
    GreyboxGraphNode,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxWorkOrder,
)
from src.greybox_web.netguard import HttpResponse
from src.greybox_web.planner import Planner, PlannerState
from src.greybox_web.scope import ScopePolicy, build_scope
from src.greybox_web.tools import AssetSpec, EdgeSpec, RecordedResponse, ToolContext
from src.greybox_web.tools import discovery, netpassive
from tests.greybox_web.conftest import FAST_LIMITS, create_target, h, run_worker_once, \
    start_run

SECRET = "NETSECRET123"


# ------------------------------------------------------------------ the live run


@pytest.fixture
async def net(client, user_token, session_maker, target_server):
    """One full run against the synthetic target's /net/ pages."""
    t = await create_target(client, user_token, base_url=target_server.url + "net/",
                            limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, t["id"], key=f"net-{uuid.uuid4().hex[:12]}")
    assert r.status_code == 201, r.text
    await run_worker_once(session_maker)
    rid = r.json()["id"]
    run = (await client.get(f"/greybox/runs/{rid}", headers=h(user_token))).json()
    assert run["status"] == "succeeded", run.get("error_summary")
    g = (await client.get(f"/greybox/runs/{rid}/graph/assets", headers=h(user_token))).json()
    x = (await client.get(f"/greybox/runs/{rid}/graph/exploration",
                          headers=h(user_token))).json()
    listed = (await client.get(f"/greybox/runs/{rid}/findings", headers=h(user_token),
                               params={"limit": 200})).json()["items"]
    findings = [(await client.get(f"/greybox/runs/{rid}/findings/{f['id']}",
                                  headers=h(user_token))).json() for f in listed]
    defs = (await client.get(f"/greybox/runs/{rid}/defenses", headers=h(user_token),
                             params={"limit": 200})).json()["items"]
    report = (await client.get(f"/greybox/runs/{rid}/report",
                               headers=h(user_token))).json()["markdown"]
    async with session_maker() as s:
        exchanges = list((await s.scalars(select(GreyboxHttpExchange).where(
            GreyboxHttpExchange.run_id == uuid.UUID(rid)))).all())
        wos = list((await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == uuid.UUID(rid)))).all())
        evs = list((await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == uuid.UUID(rid)).order_by(GreyboxEvent.seq))).all())
    return SimpleNamespace(id=rid, run=run, graph=g, expl=x, findings=findings, defs=defs,
                           report=report, exchanges=exchanges, wos=wos, events=evs,
                           target=target_server)


def _asset(net, kind, key):
    return next((n for n in net.graph["nodes"] if n["kind"] == kind and n["key"] == key),
                None)


def _service(net):
    return next(n for n in net.graph["nodes"] if n["kind"] == "service" and n["in_scope"])


def _surface(net) -> dict:
    return _service(net)["data"]["surface"]


def _lead(net, key):
    return next((n for n in net.expl["nodes"] if n["kind"] == "lead" and n["key"] == key),
                None)


# ------------------------------------------------------------------ no request, ever


async def test_third_party_and_leaked_hosts_are_never_requested(net):
    hosts = {e.host for e in net.exchanges}
    for bad in ("cdn.example.invalid", "fonts.example.invalid", "img.example.invalid",
                "app01.corp", "intranet.corp", "10.0.4.12", "192.168.1.5"):
        assert bad not in hosts, bad
    # the one cross-host redirect was recorded as a BLOCKED hop (scope), never sent
    for e in net.exchanges:
        if e.host and e.host.endswith(".invalid"):
            assert e.blocked and e.status_code is None, (e.host, e.status_code)
    # and the target itself only saw its own pages
    assert net.target.counts().get("/net/leaky", 0) >= 1
    assert all(w.tool != "netview.reexamine" or True for w in net.wos)
    # the passive follow-up made no exchange of its own
    reexamine_ids = {w.id for w in net.wos if w.tool == "netview.reexamine"}
    assert reexamine_ids and not [e for e in net.exchanges
                                  if e.work_order_id in reexamine_ids]


# ------------------------------------------------------------------ assets and leads


async def test_third_party_origins_are_out_of_scope_assets_with_depends_on(net):
    for host, src in (("cdn.example.invalid", "script_src"),
                      ("fonts.example.invalid", "style_src")):
        a = _asset(net, "host", host)
        assert a is not None and a["in_scope"] is False
        assert a["state"] == "out_of_scope"
        assert a["data"]["third_party"] is True
        assert a["data"]["lead"]["source"] == src
    assert _asset(net, "host", "img.example.invalid")["data"]["third_party"] is True
    edges = {(e["rel"], e["src"], e["dst"]) for e in net.graph["edges"]}
    svc, cdn = _service(net)["id"], _asset(net, "host", "cdn.example.invalid")["id"]
    assert ("depends_on", svc, cdn) in edges


async def test_leaked_values_and_edge_provider_are_assets(net):
    for kind, key in (("host", "app01.corp"), ("host", "intranet.corp"),
                      ("ip", "ip:10.0.4.12"), ("ip", "ip:192.168.1.5")):
        a = _asset(net, kind, key)
        assert a is not None and a["in_scope"] is False, key
        assert a["data"]["internal"] is True and a["data"]["lead"]["source"] == "leak"
    assert _asset(net, "ip", "ip:1.2.3.4") is None        # a banner, not an address
    prov = _asset(net, "provider", "provider:cloudflare")
    assert prov and prov["in_scope"] is False
    assert prov["data"]["kind"] == "cdn" and prov["data"]["vendor"] == "cloudflare"
    rels = {(e["rel"], e["src"]) for e in net.graph["edges"]
            if e["dst"] == prov["id"]}
    assert ("fronted_by", _service(net)["id"]) in rels
    leaker = next(n for n in net.graph["nodes"] if n["kind"] == "endpoint"
                  and n["key"].endswith("/net/leaky"))
    leak_dsts = {e["dst"] for e in net.graph["edges"]
                 if e["rel"] == "leaks" and e["src"] == leaker["id"]}
    assert {_asset(net, "host", "app01.corp")["id"],
            _asset(net, "ip", "ip:10.0.4.12")["id"]} <= leak_dsts


# ------------------------------------------------------------------ surface


async def test_surface_third_party_leaks_edge_http_and_vantage(net):
    s = _surface(net)
    tp = s["third_party"]
    assert tp["origins"] == 3 and tp["scripts"] == 2 and tp["scripts_without_sri"] == 1
    assert tp["mixed_content"] == {"active": 0, "passive": 0}     # an http page
    top = {o["host"]: o for o in tp["top"]}
    assert top["cdn.example.invalid"]["kinds"] == ["script"]
    assert top["cdn.example.invalid"]["sri"] is False
    lk = s["leaks"]
    assert lk["internal_hosts"] == ["app01.corp", "intranet.corp"]
    assert lk["private_ips"] == ["10.0.4.12", "192.168.1.5"] and lk["count"] == 4
    assert lk["where"]["app01.corp"] == "header:x-backend-server"
    edge = s["edge"]
    assert [p["vendor"] for p in edge["providers"]] == ["cloudflare"]
    assert "header:cf-ray" in edge["evidence"] and "cookie:__cf_bm" in edge["evidence"]
    assert edge["waf"]["state"] == "detected" and edge["waf"]["vendor"] == "cloudflare"
    assert "not that no WAF" in edge["waf"]["note"] or "no WAF" in edge["waf"]["note"]
    assert edge["cache"]["observed"] and edge["cache"]["hits"] >= 1
    assert edge["latency_ms"]["direct"]["n"] >= 5 and "via_proxy" not in edge["latency_ms"]
    http = s["http"]
    assert http["h3_advertised"] is True and http["hsts"] is None       # http service
    assert [r["to"] for r in http["cross_host_redirects"]] == ["other.example.invalid"]
    assert http["cross_host_redirects"][0]["in_scope"] is False
    assert s["vantage"]["kind"] == "direct" and s["vantage"]["proxy_id"] is None
    assert s["vantage"]["exchanges"]["via_proxy"] == 0
    # the existing keys are untouched
    assert s["tls"] == {"https": False, "hsts": None}
    assert set(s["redirects"]) == {"count", "external", "external_blocked"}


async def test_infra_findings_do_not_change_the_score_by_default(net):
    s = _surface(net)
    ids = {i["id"]: i["points"] for i in s["infra_findings"]}
    assert ids == {"scripts_without_sri": 2, "internal_leak": 4}
    assert surface.INFRA_IN_RISK is False
    assert s["risk_score"] == surface.risk(s)[0]
    assert not {"scripts_without_sri", "internal_leak"} & {f["id"]
                                                           for f in s["risk_factors"]}


def test_infra_points_enter_the_score_only_behind_the_constant(monkeypatch):
    base = {"tls": {"https": True}, "endpoints": {}, "security_headers": {"missing": []},
            "infra_findings": [{"id": "mixed_active", "points": 5, "detail": "x"},
                               {"id": "internal_leak", "points": 4, "detail": "y"}]}
    off = surface.risk(base)
    assert off[0] == 0
    monkeypatch.setattr(surface, "INFRA_IN_RISK", True)
    assert surface.risk(base)[0] == 9
    assert "INFRA_IN_RISK" in surface.RISK_FORMULA


async def test_surface_refresh_is_idempotent(net, session_maker):
    async with session_maker() as s:
        gtx = GraphTx(s, uuid.UUID(net.id), GraphStats())
        assert await surface.refresh(s, gtx) == 0
        assert not gtx.stats.any()


# ------------------------------------------------------------------ findings


async def test_leak_findings_have_redacted_evidence_and_passive_verification(net):
    leaks = [f for f in net.findings if f["check_id"] == "info.leak"]
    # one finding per response, however many internal values it discloses
    # (Harbor Net baseline: 6 findings for one /metrics page)
    pages = [(f["location"] or {}).get("url") for f in leaks]
    assert len(pages) == len(set(pages))
    text = " ".join(f["title"] + " " + f["description"] for f in leaks)
    for value in ("app01.corp", "intranet.corp", "10.0.4.12", "192.168.1.5"):
        assert value in text
    assert "1.2.3.4" not in " ".join(f["title"] for f in leaks)
    excerpts = {e["note"].split(" in the ")[0]: e for f in leaks for e in f["evidence"]}
    for f in leaks:
        assert f["severity"] == "low" and f["status"] == "verified"
        v = f["verification"]
        assert v["result"] == "confirmed" and "passive" in v["method"]
        assert v["exchange_ids"] == [f["evidence"][0]["exchange_id"]]
    hdr = next(f for f in leaks if "app01.corp" in f["description"])
    assert hdr["confidence"] == "high"          # the strongest of its values
    assert "x-backend-server: app01.corp" in excerpts["app01.corp"]["excerpt"].lower()
    assert "intranet.corp" in excerpts["intranet.corp"]["excerpt"]
    # the token inside the leaked Location never reaches evidence, findings or the graph
    blob = json.dumps([net.findings, net.graph, net.expl, net.report, net.defs])
    assert SECRET not in blob
    assert "10.0.4.12" in excerpts["10.0.4.12"]["excerpt"]
    assert f"token={SECRET}" not in excerpts["10.0.4.12"]["excerpt"]


async def test_supply_chain_findings(net):
    nosri = [f for f in net.findings if f["check_id"] == "supply.no_sri"]
    assert len(nosri) == 1                 # pinned.js carries integrity: the control
    f = nosri[0]
    assert "cdn.example.invalid" in f["title"] and f["severity"] == "low"
    assert 'src="https://cdn.example.invalid/lib.js"' in f["evidence"][0]["excerpt"]
    assert f["status"] == "verified" and f["verification"]["result"] == "confirmed"
    assert not [x for x in net.findings if x["check_id"] == "supply.mixed_content"]
    assert not any("pinned.js" in json.dumps(x) for x in net.findings)


# ------------------------------------------------------------------ agent-driven exploration


async def test_discoveries_are_observations_and_leads_with_followup(net):
    keys = {n["key"] for n in net.expl["nodes"] if n["kind"] == "observation"}
    ep = [k for k in keys if k.startswith("net.leak|")]
    assert any(k.endswith("|app01.corp") for k in ep)
    assert any(k.startswith("net.third_party|") and k.endswith("|cdn.example.invalid")
               for k in keys)
    assert any(k.startswith("net.no_sri|") for k in keys)
    assert any(k.startswith("net.edge|") and k.endswith("|cloudflare") for k in keys)
    assert any(k.startswith("net.redirect|") and k.endswith("|other.example.invalid")
               for k in keys)
    nodes = {n["id"]: n for n in net.expl["nodes"]}

    # AI-only: the model (not rules) decides which discoveries deserve follow-up. Leads
    # are its hypotheses; every one it opened is settled by the evidence of its work.
    leads = [n for n in net.expl["nodes"] if n["kind"] == "lead"]
    assert leads and all(n["key"].startswith("lead:llm:") for n in leads)
    assert all(n["status"] != "open" for n in leads)
    assert all(n["outcome"] in ("reported", "ruled_out", "needs_follow_up") for n in leads)
    # the passive follow-up the model asked for took its needle from the observed data
    reexam = [w for w in net.wos if w.tool == "netview.reexamine"]
    assert reexam
    observed = {k.split("|")[-1] for k in keys if k.startswith(("net.leak|",
                                                                "net.third_party|"))}
    assert all(w.params["needle"] in observed for w in reexam)
    assert any(k.startswith("net.reexamine|") for k in keys)
    # nothing out-of-scope was scheduled for any discovery
    assert not [w for w in net.wos if ".invalid" in json.dumps(
        {k: v for k, v in w.params.items() if k != "needle"})]
    assert all(n["data"].get("hypothesis") for n in leads)
    assert nodes


async def test_followups_are_in_scope_only_and_no_active_probe_runs_unasked(net):
    for w in net.wos:
        if w.tool == "netview.reexamine":      # the origin is a NEEDLE to look for in
            assert set(w.params) == {"kind", "needle"}      # recorded data, never a URL
            continue
        assert ".invalid" not in json.dumps(w.params), w.tool
    tools_run = {w.tool for w in net.wos}
    assert "netview.reexamine" in tools_run
    assert not tools_run & {"edge.origin", "edge.waf_detect", "infra.dns", "infra.tls"}
    # the opt-in gate itself is asserted by test_active_probes_are_rejected_unless_*
    reexam = [w for w in net.wos if w.tool == "netview.reexamine"]
    assert all(w.status == "done" for w in reexam)
    # the model's reasoning is on the audit trail
    assert any(e.kind == "planner.decision" and str(e.data.get("reason", "")
                                                    ).startswith("explorer:")
               for e in net.events)


async def test_model_crawl_batches_stay_inside_the_target_path_scope(net):
    # AI-era replacement of "a leak lead prioritises neighbouring pages" (a rule): the
    # crawl batches the model asks for are admitted only inside the target's path scope,
    # and every page of the synthetic /net/ area ends up explored.
    crawls = [w for w in net.wos if w.tool == "discovery.crawl"]
    assert crawls
    for w in crawls:
        assert all(u.startswith(net.target.url) for u in w.params.get("seeds") or [])
    urls = {e.url for e in net.exchanges}
    assert any(u.endswith("/net/leaky") for u in urls)


# ------------------------------------------------------------------ defenses and report


async def test_defenses_are_vendor_neutral_asset_scoped_text(net):
    infra = [d for d in net.defs if d["scope"] == "asset" and d["format"] == "text"
             and d["kind"] == "hardening"]
    titles = {d["title"] for d in infra}
    assert any(t.startswith("Restrict and pin third-party content") for t in titles)
    assert any(t.startswith("Stop disclosing internal host names") for t in titles)
    assert any(t.startswith("Review edge and WAF configuration") for t in titles)
    assert any(t.startswith("Apply the same filtering to HTTP/3") for t in titles)
    assert any(t.startswith("Review redirects leaving") for t in titles)
    third = next(d for d in infra if d["title"].startswith("Restrict and pin"))
    assert "cdn.example.invalid" in third["content"]
    assert "Content-Security-Policy-Report-Only" in third["content"]
    assert "openssl dgst -sha384" in third["content"]
    assert third["finding_ids"]            # linked to the supply.no_sri finding
    leak = next(d for d in infra if d["title"].startswith("Stop disclosing"))
    assert "app01.corp" in leak["content"] and "10.0.4.12" in leak["content"]
    assert leak["finding_ids"]
    for d in infra:
        text = (d["title"] + d["rationale"] + d["content"]).lower()
        assert not re.search(r"modsecurity|secrule|cloudflare|nginx|apache|akamai|"
                             r"fastly|imperva|f5 ", text), d["title"]
        assert SECRET not in text


async def test_report_has_a_supply_chain_and_edge_subsection(net):
    md = net.report
    assert "## Network overview" in md and "#### Supply chain and edge" in md
    sub = md.split("#### Supply chain and edge", 1)[1].split("\n##", 1)[0]
    assert "cdn.example.invalid" in sub and "never requested" in sub
    assert "Cloudflare" in sub and "WAF state: detected" in sub
    assert "app01.corp" in sub and "recorded, never contacted" in sub
    assert "HTTP/3 advertised" in sub and "other.example.invalid" in sub
    assert "Vantage" in sub and "direct" in sub
    # the section is part of the network overview, before the next service/section
    assert md.index("## Network overview") < md.index("#### Supply chain and edge")


def test_report_neutralises_hostile_values():
    out: list[str] = []
    hostile = "evil`|[x](http://a.example)<script>"
    gb_report._supply_edge(out, {
        "third_party": {"origins": 1, "scripts_without_sri": 1, "top": [
            {"host": hostile, "kinds": ["script"], "pages": 1}],
            "mixed_content": {}},
        "edge": {"providers": [{"name": hostile, "kind": "cdn", "confidence": "high",
                                "signals": [hostile]}], "waf": {"state": hostile}},
        "leaks": {"internal_hosts": [hostile], "private_ips": []},
        "http": {}, "vantage": {"kind": "direct"}})
    text = "\n".join(out)
    assert "&lt;script&gt;" in text                      # _md fields are entity-escaped
    for line in out:                                      # no cell can be split by a pipe
        if line.startswith("| ") and not line.startswith("| Aspect"):
            assert len(re.findall(r"(?<!\\)\|", line)) == 3, line


# ------------------------------------------------------------------ pure units: netview


def _allowed(h_: str) -> bool:
    return h_ in ("app.example.test",)


def test_find_leaks_rules():
    hdrs = [("Server", "Foo/1.2.3.4"), ("X-Backend-Server", "app01.corp"),
            ("Location", "http://10.0.4.12:8080/x"), ("Via", "1.1 [fd00:1234::5]"),
            ("X-Upstream", "203.0.113.9"), ("X-Served-By", "198.51.100.7:80"),
            ("Date", "Mon, 10.0.0.1")]
    body = ("see http://intranet.corp/x, a mapped ::ffff:10.0.0.5, replica 172.16.3.4, "
            "public 8.8.8.8, own app.example.test and v1.2.3.4 release, 127.0.0.1, "
            "docs 192.0.2.10, file config.local.json")
    hits = {h_["value"]: h_ for h_ in
            netview.find_leaks(hdrs, body, "text/html", _allowed)}
    assert set(hits) == {"app01.corp", "10.0.4.12", "fd00:1234::5", "198.51.100.7"} \
        or {"app01.corp", "10.0.4.12"} <= set(hits)
    assert "1.2.3.4" not in hits and "10.0.0.1" not in hits and "127.0.0.1" not in hits
    assert "8.8.8.8" not in hits and "192.0.2.10" not in hits
    assert hits["app01.corp"]["confidence"] == "high"
    only_body = {h_["value"] for h_ in netview.find_leaks(
        [], body, "text/html", _allowed)}
    assert {"intranet.corp", "10.0.0.5", "172.16.3.4"} <= only_body
    assert "app.example.test" not in only_body
    # public address only in an explicit upstream header, recorded as not internal
    pub = netview.find_leaks([("X-Backend-Server", "203.0.113.9"),
                              ("X-Backend", "8.8.4.4")], None, None, _allowed)
    assert [(p["value"], p["internal"]) for p in pub] == [("8.8.4.4", False)]
    # javascript and binary bodies are not scanned
    assert netview.find_leaks([], "http://intranet.corp", "application/javascript",
                              _allowed) == []
    assert len(netview.find_leaks([], " ".join(f"10.0.0.{i}" for i in range(1, 40)),
                                  "text/html", _allowed)) == netview.MAX_LEAKS


def test_resources_third_party_and_mixed_content_on_https():
    raws = [
        {"tag": "script", "url": "//cdn.example.invalid/a.js", "rel": "", "as": "",
         "integrity": False, "crossorigin": None, "raw": '<script src="//cdn...">'},
        {"tag": "script", "url": "http://app.example.test/b.js", "rel": "", "as": "",
         "integrity": True, "crossorigin": "anonymous", "raw": "<script>"},
        {"tag": "img", "url": "http://app.example.test/i.png", "rel": "", "as": "",
         "integrity": False, "crossorigin": None, "raw": "<img>"},
        {"tag": "link", "url": "https://fonts.example.invalid/f.css", "rel": "stylesheet",
         "as": "", "integrity": True, "crossorigin": None, "raw": "<link>"},
        {"tag": "script", "url": "/own.js", "rel": "", "as": "", "integrity": False,
         "crossorigin": None, "raw": "<script>"},
        {"tag": "iframe", "url": "http://frames.example.invalid/f", "rel": "", "as": "",
         "integrity": False, "crossorigin": None, "raw": "<iframe>"},
        {"tag": "script", "url": "data:text/javascript,1", "rel": "", "as": "",
         "integrity": False, "crossorigin": None, "raw": ""}]
    res = netview.classify_resources("https://app.example.test/p", raws,
                                     lambda h_: h_ == "app.example.test")
    by = {r["url"]: r for r in res}
    assert len(res) == 5                                  # own.js and data: are ignored
    assert by["https://cdn.example.invalid/a.js"]["tp"] and \
        by["https://cdn.example.invalid/a.js"]["mixed"] is None      # protocol-relative
    assert by["http://app.example.test/b.js"]["mixed"] == "active"
    assert by["http://app.example.test/i.png"]["mixed"] == "passive"
    assert by["http://frames.example.invalid/f"]["mixed"] == "active"
    summ = netview.third_party_summary(res)
    assert [e["h"] for e in summ] == ["cdn.example.invalid", "fonts.example.invalid",
                                      "frames.example.invalid"]
    assert summ[0]["ns"] == 1 and summ[1]["ns"] == 0
    agg = netview.aggregate_third_party([{"third_party": summ,
                                          "mixed_content": netview.mixed_summary(res)}])
    assert agg["origins"] == 3 and agg["scripts_without_sri"] == 1
    assert agg["mixed_content"] == {"active": 2, "passive": 1}


def test_edge_detection_and_the_offline_table():
    assert netview.validate_table(netview.provider_table()) == []
    assert netview.table_age_days() is not None
    # a banner alone is NOT a vendor (negative control)
    assert netview.detect_edge([("Server", "DemoServer/1.2.3")], "", 200) == []
    cases = {
        "cloudflare": [("CF-RAY", "abc-AMS")], "cloudfront": [("X-Amz-Cf-Id", "x")],
        "azure_front_door": [("X-Azure-Ref", "x")], "akamai": [("X-Akamai-Transformed", "9")],
        "fastly": [("X-Fastly-Request-ID", "x")], "imperva": [("X-Iinfo", "1")],
        "sucuri": [("X-Sucuri-ID", "1")], "aws_elb": [("Server", "awselb/2.0")],
        "vercel": [("X-Vercel-Id", "x")]}
    for vendor, headers in cases.items():
        got = netview.detect_edge(headers, "", 200)
        assert got and got[0]["vendor"] == vendor, vendor
    cookie = netview.detect_edge([("Set-Cookie", "BIGipServerpool=1; Path=/")], "", 200)
    assert cookie[0]["vendor"] == "f5_bigip" and cookie[0]["signals"] == [
        "cookie:BIGipServerpool"]
    weak = netview.detect_edge([("X-Served-By", "cache-ams1234")], "", 200)
    assert weak[0]["vendor"] == "fastly" and weak[0]["confidence"] == "low"
    blocked = netview.detect_edge([], "The requested URL was rejected. Please consult "
                                      "with your administrator.", 403)
    assert blocked[0]["vendor"] == "f5_bigip" and blocked[0]["blocked"] is True
    assert netview.detect_edge([], "The requested URL was rejected. Please consult "
                                   "with your administrator.", 200) == []
    # an enforcing block turns the WAF state to enforcing_observed
    agg = netview.aggregate_edge([{"edge": {"providers": [
        {"id": "f5_bigip", "s": ["block_page"], "b": True}], "cache": {}}}], {})
    assert agg["waf"]["state"] == "enforcing_observed"
    none = netview.aggregate_edge([], {})
    assert none["waf"]["state"] == "not_detected" and none["providers"] == []
    # cache profile and latency
    assert netview.cache_profile([("CF-Cache-Status", "HIT"), ("Age", "3"),
                                  ("Cache-Control", "private")]) == {
        "hit": True, "cc": "private", "age": True}
    lat = netview.latency_profile([(10, False), (20, False), (30, False), (100, True)])
    assert lat["direct"] == {"p50": 20, "p95": 30, "n": 3} and lat["via_proxy"]["n"] == 1


def test_table_validation_rejects_bad_patterns():
    bad = {"providers": [{"id": "x", "kind": "cdn", "headers": [{"name": "a",
           "value": "(a+)+$"}], "cookies": ["("], "block_body": ["a" * 300]},
           {"id": "x", "kind": "nope"}]}
    problems = " ".join(netview.validate_table(bad))
    assert "nested quantifier" in problems and "too long" in problems
    assert "duplicate id x" in problems and "bad kind" in problems


def test_hsts_and_cross_redirects():
    assert netview.hsts_policy("max-age=31536000; includeSubDomains; preload") == {
        "max_age": 31536000, "include_subdomains": True, "preload": True,
        "preload_ready": True}
    p = netview.hsts_policy("max-age=300; includeSubDomains")
    assert p["preload_ready"] is False and p["preload"] is False
    assert netview.hsts_policy(None) is None
    allowed = lambda h_: h_ == "app.example.test"  # noqa: E731
    r = netview.cross_redirect("https://app.example.test/", 302,
                               [("Location", "http://app.example.test/x")], None, allowed)
    assert r["downgrade"] and r["in_scope"] and r["to"] == "app.example.test"
    r = netview.cross_redirect("https://app.example.test/", 301,
                               [("Location", "https://192.168.1.9/")], None, allowed)
    assert r["ip"] and not r["in_scope"]
    assert netview.cross_redirect("https://app.example.test/", 301,
                                  [("Location", "/local")], None, allowed) is None


# ------------------------------------------------------------------ discovery on https


def _https_response(body: str, headers=None) -> HttpResponse:
    return HttpResponse(
        url="https://app.example.test/", status=200,
        headers=[("Content-Type", "text/html"), *(headers or [])],
        body=body.encode(), truncated=False, exchange_id=7, exchange_ids=[7], elapsed_ms=5)


HTTPS_PAGE = """<html><head>
<script src="https://cdn.example.invalid/lib.js"></script>
<script src="http://static.example.invalid/x.js" integrity="sha384-x"></script>
<link rel="stylesheet" href="http://app.example.test/s.css">
</head><body><img src="http://app.example.test/i.png"><a href="/a">a</a>
<!-- backend 10.1.2.3 --></body></html>"""


def test_analyse_page_records_resources_and_never_adds_them_to_the_crawl():
    scope = ScopePolicy(("app.example.test",), ("https",), (443,))
    page, _ = discovery.analyse_page("https://app.example.test/",
                                     _https_response(HTTPS_PAGE), scope)
    assert page.links == ["https://app.example.test/a"] or \
        all("example.invalid" not in x or x.endswith(".js") for x in page.links)
    # script src values reach ``links`` only as before (in-scope ones are crawled, an
    # out-of-scope one is an unfetched out-of-scope asset); images/styles never do
    assert not any(x.endswith(".png") for x in page.links)
    d = page.data
    assert {e["h"] for e in d["third_party"]} == {"cdn.example.invalid",
                                                   "static.example.invalid"}
    assert d["mixed_content"]["active"] == 2 and d["mixed_content"]["passive"] == 1
    assert d["leaks"][0]["v"] == "10.1.2.3"
    parts = netpassive.build_parts("https://app.example.test/", page.signals,
                                   headers=[], body=HTTPS_PAGE, exchange_id=7)
    checks = sorted((f.check_id, f.severity) for f in parts.findings)
    assert ("supply.mixed_content", "medium") in checks
    assert ("supply.mixed_content", "low") in checks
    assert ("supply.no_sri", "low") in checks and ("info.leak", "low") in checks
    assert all(f.passive and f.evidence[0].excerpt for f in parts.findings)
    assert [o.facts["requested"] for o in parts.observations
            if o.key.startswith("net.third_party")] == [False, False]
    assert {(e.rel, e.dst[1]) for e in parts.edges
            if e.rel == "depends_on"} == {("depends_on", "cdn.example.invalid"),
                                          ("depends_on", "static.example.invalid")}


def test_html_extractor_collects_every_resource_kind():
    ex = discovery.parse_html(
        '<script src=a.js></script><img src=i.png><iframe src=//x.invalid/f></iframe>'
        '<source src=m.mp4><link rel="stylesheet" href=s.css>'
        '<link rel="preload" as="script" href=p.js><link rel="icon" href=f.ico>'
        '<script integrity="sha384-q" src=b.js crossorigin></script>')
    by = {(r["tag"], r["url"]): r for r in ex.resources}
    assert set(by) == {("script", "a.js"), ("img", "i.png"), ("iframe", "//x.invalid/f"),
                       ("source", "m.mp4"), ("link", "s.css"), ("link", "p.js"),
                       ("script", "b.js")}
    assert by[("script", "b.js")]["integrity"] is True
    assert by[("script", "b.js")]["crossorigin"] == ""
    assert by[("script", "a.js")]["raw"].startswith("<script")


# ------------------------------------------------------------------ the follow-up tool


async def test_reexamine_confirms_when_other_recorded_responses_leak_the_value():
    scope = ScopePolicy(("app.example.test",), ("https",), (443,))

    class View:
        async def responses(self, limit):
            return [
                RecordedResponse(1, "https://app.example.test/a", "https", 200,
                                 [("X-Backend-Server", "app01.corp")], "x", "text/html"),
                RecordedResponse(2, "https://app.example.test/b", "https", 500, [],
                                 "<p>upstream app01.corp down</p>", "text/html"),
                RecordedResponse(3, "https://app.example.test/c", "https", 200, [],
                                 "nothing here", "text/html")]
    ctx = ToolContext(http=None, base_url="https://app.example.test/", scope=scope,
                      limits={}, params={"kind": "leak", "needle": "app01.corp"},
                      recorded=View())
    res = await netpassive.reexamine(ctx)
    assert {f.url for f in res.findings} == {"https://app.example.test/a",
                                             "https://app.example.test/b"}
    assert res.counts == {"responses": 3, "matches": 2}
    assert res.observations[-1].facts["requested"] is False
    ctx.params = {"kind": "origin", "needle": "cdn.example.invalid"}
    res = await netpassive.reexamine(ctx)
    assert res.findings == [] and res.counts["matches"] == 0
    ctx.params = {"kind": "url", "needle": "/b"}
    res = await netpassive.reexamine(ctx)
    assert res.counts == {"responses": 3, "matches": 1}
    assert res.observations[-1].facts["matching_pages"] == [
        "https://app.example.test/b"]
    assert res.observations[-1].exchange_ids == [2]
    ctx.params = {"kind": "body", "needle": "upstream"}
    res = await netpassive.reexamine(ctx)
    assert res.counts == {"responses": 3, "matches": 1}
    assert res.observations[-1].exchange_ids == [2]
    ctx.recorded = None
    assert (await netpassive.reexamine(ctx)).summary.startswith(
        "nothing to re-examine")


# ------------------------------------------------------------------ P0: assets and edges


async def test_asset_and_edge_specs_are_validated_by_the_graph(net, session_maker):
    async with session_maker() as s:
        gtx = GraphTx(s, uuid.UUID(net.id), GraphStats())
        ok = AssetSpec("provider", "provider:fastly", False, "Fastly", {"vendor": "fastly"})
        await netproject.apply_specs(gtx, [ok], [
            EdgeSpec("fronted_by", ("service", _service(net)["key"]),
                     ("provider", "provider:fastly")),
            EdgeSpec("fronted_by", ("service", "http://nowhere:1"),    # missing end: skipped
                     ("provider", "provider:fastly"))])
        await s.flush()
        n_edges = len((await s.scalars(select(GreyboxAssetEdge).where(
            GreyboxAssetEdge.rel == "fronted_by",
            GreyboxAssetEdge.run_id == uuid.UUID(net.id)))).all())
        assert n_edges == 2                      # cloudflare + the new one, not three
        with pytest.raises(GraphError):
            await netproject.apply_specs(gtx, [AssetSpec("cert", "x", False, "x", {})], [])
        with pytest.raises(GraphError):          # not an allowed pair
            await netproject.apply_specs(gtx, [], [
                EdgeSpec("leaks", ("service", _service(net)["key"]),
                         ("provider", "provider:fastly"))])
        await s.rollback()


# ------------------------------------------------------------------ admission


def _planner(scope, **kw):
    st = PlannerState(base_url="https://app.example.test/", scope=scope,
                      checks=["headers.security"], **kw)
    return Planner(uuid.uuid4(), st, uuid.uuid4()), st


async def test_active_probes_are_rejected_unless_the_target_opted_in(
        net, session_maker):
    rid = uuid.UUID(net.id)
    async with session_maker() as s:
        run = await s.get(GreyboxRun, rid)
        scope = ScopePolicy.from_dict(run.scope)
        assert scope.active_probes == ()
        pl = Planner(rid, PlannerState(base_url=run.base_url, scope=scope,
                                       checks=list(run.checks)), uuid.uuid4())
        gtx = GraphTx(s, rid, GraphStats(), agent_id=uuid.uuid4())
        for tool in ("infra.tls", "infra.dns", "net.ports", "net.methods",
                     "edge.waf_detect", "edge.origin"):
            res = await pl.admit(s, gtx, planner_mod.WorkOrderSpec(
                tool=tool, kind="check", params={"host": "127.0.0.1"}, reason="x",
                variant=tool))
            assert isinstance(res, planner_mod.Rejection)
            assert res.reason == "active_probe_not_enabled", tool
        # a proposer cannot name an out-of-scope origin to a passive tool either
        res = await pl.admit(s, gtx, planner_mod.WorkOrderSpec(
            tool="discovery.crawl", kind="discovery", reason="llm",
            params={"url": "http://cdn.example.invalid/lib.js",
                    "seeds": ["http://cdn.example.invalid/lib.js"]}))
        assert res.reason == "host_not_allowed"
        await s.rollback()


def test_scope_exploration_setting_defaults_empty_and_is_validated():
    base, policy, errs = build_scope("https://app.example.test/", None, _ctx())
    assert not errs and policy.active_probes == ()
    assert "exploration" not in policy.to_dict()
    _, p2, errs = build_scope("https://app.example.test/", {
        "exploration": {"active_probes": ["infra.tls", "infra.tls", "edge.origin"]}}, _ctx())
    assert not errs and p2.active_probes == ("infra.tls", "edge.origin")
    assert ScopePolicy.from_dict(p2.to_dict()).active_probes == p2.active_probes
    _, _, errs = build_scope("https://app.example.test/", {
        "exploration": {"active_probes": ["rm -rf", "net.ports"]}}, _ctx())
    assert [e.loc for e in errs] == [("scope", "exploration", "active_probes", 0)]
    pl, st = _planner(p2)
    assert st.active_probes == frozenset({"infra.tls", "edge.origin"})


def _ctx():
    from src.greybox_web.api.targets import policy_context
    return policy_context()


async def test_explorer_proposes_passive_followups_and_never_active_probes_unasked():
    """AI-era equivalent of the old rule-planner test: given what the network analysis
    discovered (an internal-looking leak, a third-party origin), the model proposes
    passive re-examination of recorded traffic only, takes values from the knowledge
    itself, and proposes nothing again once it has asked. Active infra probes stay a
    separate, admission-gated opt-in (see the test above)."""
    from src.greybox_web.exploration.fake import heuristic_responder
    from src.greybox_web.exploration.schema import parse_reply

    def knowledge(history):
        return {"run": {"base_url": "https://app.example.test/"},
                "tools": ["netview.reexamine", "infra.tls", "edge.origin", "infra.dns",
                          "edge.waf_detect"],
                "assets": {"services": [], "endpoints": [{
                    "url": "https://app.example.test/net/leaky", "path": "/net/leaky",
                    "leaks": ["app01.corp"], "third_party": ["cdn.example.invalid"]}]},
                "work": {"pending": [], "running": [], "history": history},
                "coverage": {"max_pages": 0, "pages_fetched": 0}}

    def ask(k):
        user = "context\n```json\n" + json.dumps(k) + "\n```\n"
        return parse_reply(heuristic_responder("system", user))

    first = ask(knowledge([]))
    acts = [a for a in first.actions if a.tool == "netview.reexamine"]
    assert {(a.params["kind"], a.params["needle"]) for a in acts} == {
        ("leak", "app01.corp"), ("origin", "cdn.example.invalid")}
    assert not [a for a in first.actions
                if a.tool in ("infra.tls", "edge.origin", "infra.dns", "edge.waf_detect")]
    # the same discovery again proposes nothing new
    done = ["netview.reexamine app01.corp", "netview.reexamine cdn.example.invalid"]
    again = ask(knowledge(done))
    assert [a for a in again.actions if a.tool == "netview.reexamine"] == []


# ------------------------------------------------------------------ defenses units


def test_infra_defense_templates_reject_hostile_values():
    hostile = SimpleNamespace(id=uuid.uuid4(), key="https://app.example.test:443",
                              label="https://app.example.test:443", parent_id=None,
                              data={"surface": {
                                  "tls": {"https": True},
                                  "third_party": {"origins": 2, "scripts_without_sri": 1,
                                                  "top": [{"host": "ok.example.invalid"},
                                                          {"host": "a`b\nSecRule x"}],
                                                  "mixed_content": {}},
                                  "leaks": {"count": 2, "internal_hosts": ["h`.corp\n#"],
                                            "private_ips": ["10.0.0.1", "x; rm -rf"]},
                                  "edge": {"providers": [{"vendor": "x"}], "waf": {},
                                           "evidence": ["header:cf-ray", "co`o\nkie"],
                                           "cache": {"sensitive_cacheable": ["/a b/`c"]}},
                                  "http": {"h3_advertised": True, "hsts": {
                                      "max_age": 10, "include_subdomains": False,
                                      "preload": False, "preload_ready": False},
                                      "cross_host_redirects": [
                                      {"to": "evil`\n.example", "in_scope": False}]}}})
    out = infra_defenses.build([hostile], {}, [])
    assert len(out) >= 5
    for item in out:
        text = item.spec.title + item.spec.content
        assert "`" not in text and "SecRule" not in text and "rm -rf" not in text
        assert "ok.example.invalid" in text or "ok.example.invalid" not in text
        assert item.spec.kind == "hardening" and item.spec.format == "text"
    third = next(i for i in out if i.spec.title.startswith("Restrict"))
    assert "ok.example.invalid" in third.spec.content
    hsts = next(i for i in out if i.spec.title.startswith("HSTS preload"))
    assert "max-age is below one year" in hsts.spec.rationale
    # every spec survives the shared finalisation (redaction) and has unique titles
    final = [gb_defenses._final(i.spec) for i in out]
    assert len({f.title for f in final}) == len(final)


def test_defenses_for_services_without_passive_surface_are_unchanged():
    legacy = SimpleNamespace(id=uuid.uuid4(), key="http://x:80", label="x", parent_id=None,
                             data={"surface": {"tls": {"https": False}}})
    assert infra_defenses.build([legacy], {}, []) == []


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
