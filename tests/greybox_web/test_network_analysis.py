"""Live network / attack-surface analysis and network-wide
recommendations.

One full run against the live synthetic target: service and endpoint surfaces match
what the synthetic app serves, ``surface.updated`` is emitted and coalesced, the risk
score is deterministic, asset-scoped defenses exist with valid syntax and correct
asset/finding links, the asset graph carries ``defense`` nodes with ``protects`` edges,
the report has the new sections, and nothing target-derived is trusted or leaks.
"""
from __future__ import annotations

import io
import json
import re
import uuid
import zipfile
from collections import defaultdict

import pytest
import sqlalchemy as sa
import yaml
from sqlalchemy import select

from src.greybox_web import defenses as gb_defenses
from src.greybox_web import redaction
from src.greybox_web import report as gb_report
from src.greybox_web import surface as gb_surface
from src.greybox_web.graph import GraphStats, GraphTx
from src.greybox_web.models import (
    RUN_CHILD_MODELS,
    GreyboxAsset,
    GreyboxDefense,
    GreyboxEvent,
    GreyboxFinding,
)
from tests.greybox_web import defense_harness as H
from tests.greybox_web.conftest import h, run_worker_once, start_run

SEC_HEADERS = {"content-security-policy", "x-content-type-options", "x-frame-options",
               "referrer-policy"}


@pytest.fixture
async def run(client, user_token, live_target, session_maker):
    r = await start_run(client, user_token, live_target["id"],
                        key=f"net-{uuid.uuid4().hex[:12]}")
    assert r.status_code == 201, r.text
    await run_worker_once(session_maker)
    body = (await client.get(f"/greybox/runs/{r.json()['id']}",
                             headers=h(user_token))).json()
    assert body["status"] == "succeeded", body.get("error_summary")
    return body


async def _graph(client, token, rid):
    r = await client.get(f"/greybox/runs/{rid}/graph/assets", headers=h(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _defenses(client, token, rid, **params):
    r = await client.get(f"/greybox/runs/{rid}/defenses", headers=h(token),
                         params=params)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def _service(graph) -> dict:
    svcs = [n for n in graph["nodes"] if n["kind"] == "service" and n["in_scope"]]
    assert len(svcs) == 1
    assert "surface" not in next(n for n in graph["nodes"] if n["kind"] == "service"
                                 and not n["in_scope"])["data"]
    return svcs[0]


# ------------------------------------------------------------------ live surface


async def test_service_surface_matches_the_synthetic_target(client, user_token, run):
    g = await _graph(client, user_token, run["id"])
    svc = _service(g)
    s = svc["data"]["surface"]
    assert s["server"] == "DemoServer/1.2.3"
    assert s["version_disclosure"] == ["server"]
    assert "DemoServer 1.2.3" in s["technologies"]
    sh = s["security_headers"]
    assert SEC_HEADERS <= set(sh["missing"])
    assert "strict-transport-security" not in sh["missing"] + sh["present"]   # http
    assert sh["present"] == [] and sh["evaluated"] >= 3
    assert sh["counts"]["content-security-policy"]["missing"] == sh["evaluated"]
    assert s["cookie_flags"]["session"] == {"secure": False, "httponly": False,
                                            "samesite": None}
    assert s["cors"]["reflects_origin"] and s["cors"]["allows_credentials"]
    assert s["cors"]["paths"] == ["/api/data"]
    assert s["tls"] == {"https": False, "hsts": None}
    assert set(s["redirects"]) == {"count", "external", "external_blocked"}
    ep = s["endpoints"]
    assert ep["total"] >= 5 and ep["tested"] >= 1 and ep["with_findings"] >= 1
    assert ep["auth_like"] >= 1 and "/login" in s["auth_paths"]
    assert ep["sensitive"] >= 1
    assert "/.git/HEAD" in {x["path"] for x in s["sensitive_paths"]}
    assert 0 < s["risk_score"] <= 100
    assert s["risk_score"] == gb_surface.risk(s)[0]
    assert [f["points"] for f in s["risk_factors"]] == sorted(
        (f["points"] for f in s["risk_factors"]), reverse=True)

    eps = {n["label"]: n["data"]["surface"] for n in g["nodes"]
           if n["kind"] == "endpoint" and n["data"].get("surface")}
    assert eps["/login"]["password_form"] and eps["/login"]["has_form"]
    assert eps["/login"]["methods"] and "text/html" in eps["/login"]["content_types"]
    assert eps["/api/data"]["content_types"] == ["application/json"]
    assert eps["/api/data"]["status_codes"] == [200]
    assert eps["/.git/HEAD"]["sensitive"] == "git repository"
    assert eps["/search"]["params"] >= 1 and eps["/search"]["sensitive"] is None


async def test_surface_is_a_pure_function_of_the_evidence(run, session_maker):
    """Recomputing from the stored exchanges changes nothing (deterministic)."""
    async with session_maker() as s:
        gtx = GraphTx(s, uuid.UUID(run["id"]), GraphStats())
        assert await gb_surface.refresh(s, gtx) == 0
        assert not gtx.stats.any()


def test_risk_formula_is_deterministic():
    surface = {
        "security_headers": {"missing": ["content-security-policy", "x-frame-options"]},
        "version_disclosure": ["server"],
        "cookie_flags": {"session": {"secure": False, "httponly": False,
                                     "samesite": None}},
        "cors": {"reflects_origin": True, "allows_credentials": True},
        "tls": {"https": False},
        "endpoints": {"auth_like": 1, "sensitive": 1},
        "sensitive_paths": [{"path": "/.git/HEAD", "served": True}],
        "findings": {"verified": {"high": 1}, "candidate": {"medium": 2}},
    }
    # headers 6 + banner 8 + cookies 2*2 (httponly, samesite; http) + cors 20
    # + http 10+5 + sensitive 12 + login 3 + findings 10 + 2*0.5*5 = 15
    score, factors = gb_surface.risk(surface)
    assert score == 6 + 8 + 4 + 20 + 15 + 12 + 3 + 15 == 83
    assert (score, factors) == gb_surface.risk(json.loads(json.dumps(surface)))
    assert factors[0] == {"id": "cors", "points": 20,
                          "detail": "origin reflected with credentials"}
    surface["findings"] = {"verified": {"critical": 9}}
    assert gb_surface.risk(surface)[0] == 6 + 8 + 4 + 20 + 15 + 12 + 3 + 25 == 93
    assert gb_surface.risk({"tls": {"https": True}})[0] == 0
    surface["findings"] = {"verified": {"critical": 99}}
    surface["sensitive_paths"] = []
    surface["endpoints"]["sensitive"] = 9
    assert gb_surface.risk(surface)[0] == 100


async def test_surface_updated_events_are_emitted_and_coalesced(client, user_token, run,
                                                                session_maker):
    async with session_maker() as s:
        evs = list((await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == uuid.UUID(run["id"]),
            GreyboxEvent.kind == "surface.updated").order_by(GreyboxEvent.seq))).all())
    assert evs
    per_asset = defaultdict(list)
    for e in evs:
        assert (e.source, e.level, e.status) == ("agent", "debug", "ok")
        assert set(e.data) == {"asset_id", "kind", "risk_score", "changed"}
        assert e.data["kind"] in ("service", "endpoint") and e.data["changed"]
        assert e.refs["asset_ids"] == [e.data["asset_id"]]
        per_asset[e.data["asset_id"]].append(e)
    for aid, items in per_asset.items():
        for a, b in zip(items, items[1:]):
            assert (b.ts - a.ts).total_seconds() >= 0.95, aid     # at most 1 per second
    g = await _graph(client, user_token, run["id"])
    svc = _service(g)
    last = per_asset[svc["id"]][-1]
    assert last.data["risk_score"] == svc["data"]["surface"]["risk_score"]
    assert isinstance(last.data["risk_score"], int)
    assert all(e.data["risk_score"] is None for e in evs if e.data["kind"] == "endpoint")
    # sequence invariants (8.3) still hold with the new kind in the stream
    async with session_maker() as s:
        seqs = list((await s.scalars(select(GreyboxEvent.seq).where(
            GreyboxEvent.run_id == uuid.UUID(run["id"])).order_by(GreyboxEvent.seq))).all())
        kinds = list((await s.scalars(select(GreyboxEvent.kind).where(
            GreyboxEvent.run_id == uuid.UUID(run["id"])).order_by(GreyboxEvent.seq))).all())
    assert seqs == list(range(1, len(seqs) + 1))
    assert kinds[0] == "run.queued" and kinds[-1] == "run.completed"
    assert sum(k.startswith("run.") and k in ("run.completed", "run.failed",
                                              "run.cancelled") for k in kinds) == 1


async def test_announce_merges_changed_keys_within_a_second(run, session_maker):
    async with session_maker() as s:
        rid = uuid.UUID(run["id"])
        svc = (await s.scalars(select(GreyboxAsset).where(
            GreyboxAsset.run_id == rid, GreyboxAsset.kind == "service",
            GreyboxAsset.in_scope.is_(True)))).one()
        before = (await s.scalar(select(sa.func.count()).select_from(GreyboxEvent).where(
            GreyboxEvent.run_id == rid, GreyboxEvent.kind == "surface.updated"))) or 0
        gtx = GraphTx(s, rid, GraphStats())
        await gb_surface._announce(s, gtx, svc, {"server"}, 10)
        await gb_surface._announce(s, gtx, svc, {"cors"}, 20)
        await gb_surface._announce(s, gtx, svc, {"tls"}, 30)
        assert gb_surface.pending_delay(gtx.stats) > 0
        await gb_surface.flush(s, gtx)
        assert gb_surface.pending_delay(gtx.stats) == 0
        evs = list((await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == rid, GreyboxEvent.kind == "surface.updated")
            .order_by(GreyboxEvent.seq))).all())[before:]
    assert [e.data["changed"] for e in evs] == [["server"], ["cors", "tls"]]
    assert [e.data["risk_score"] for e in evs] == [10, 30]


# ------------------------------------------------------------------ defenses


def _validate(items) -> None:
    """Every defense passes the linter of its format; ids and Sigma ids are unique."""
    ids: list[int] = []
    bodies: dict[int, set[str]] = {}
    sigma_ids: list[str] = []
    for d in items:
        c = d["content"]
        if d["format"] == "modsecurity":
            assert H.lint_modsecurity(c, allow_placeholders=True) == [], d["title"]
            for i in re.findall(r"(?m)^[^#\n]*\bid:(\d+)", re.sub(r"\\\n\s*", " ", c)):
                ids.append(int(i))
                bodies.setdefault(int(i), set()).add(" ".join(c.split()))
        elif d["format"] == "sigma":
            assert H.lint_sigma(c) == [], d["title"]
            sigma_ids.append(str(uuid.UUID(yaml.safe_load(c)["id"])))
        elif d["format"] == "nginx":
            H.parse_nginx(c)
            assert not re.search(r"^\s*location\b", c, re.M), d["title"]
        elif d["format"] == "apache":
            assert H.lint_apache(c, "global", allow_placeholders=True) == [] or \
                H.lint_apache(c, "vhost", allow_placeholders=True) == [], d["title"]
    # identical rules (same stable id) may repeat across finding and asset scope: the
    # bundle lists them once; what must hold is that one id never has two bodies
    assert all(len(b) == 1 for b in bodies.values())
    assert all(gb_defenses.MODSEC_BASE <= i < gb_defenses.MODSEC_BASE + gb_defenses.MODSEC_SPAN
               for i in ids)


async def test_asset_scoped_defenses(client, user_token, run, session_maker):
    rid = run["id"]
    g = await _graph(client, user_token, rid)
    by_id = {n["id"]: n for n in g["nodes"]}
    svc = _service(g)
    allitems = await _defenses(client, user_token, rid)
    items = await _defenses(client, user_token, rid, scope="asset")
    assert items and {d["id"] for d in items} <= {d["id"] for d in allitems}
    fitems = await _defenses(client, user_token, rid, scope="finding")
    assert {d["id"] for d in items} | {d["id"] for d in fitems} == \
        {d["id"] for d in allitems}
    assert all(d["scope"] == "finding" and d["finding_id"] and
               d["finding_id"] in d["finding_ids"] and d["asset_id"] is None
               for d in fitems)
    async with session_maker() as s:
        findings = {str(f.id): f for f in (await s.scalars(select(GreyboxFinding).where(
            GreyboxFinding.run_id == uuid.UUID(rid)))).all()}
    for d in items:
        assert set(d) == {"id", "run_id", "finding_id", "asset_id", "scope",
                          "finding_ids", "node_id", "kind", "format", "title",
                          "rationale", "content", "confidence", "status", "created_at"}
        assert d["scope"] == "asset" and d["finding_id"] is None
        assert d["asset_id"] in by_id and by_id[d["asset_id"]]["kind"] in (
            "host", "service", "endpoint")
        assert d["status"] == "proposed" and d["node_id"] in by_id
        assert d["kind"] in ("waf_rule", "detection_rule", "config", "hardening")
        assert set(d["finding_ids"]) <= set(findings)
        assert d["content"].strip() and d["rationale"]
    _validate(allitems)

    def one(fmt, needle, asset_kind=None):
        hit = [d for d in items if d["format"] == fmt and needle in d["content"]]
        assert hit, (fmt, needle)
        if asset_kind:
            assert by_id[hit[0]["asset_id"]]["kind"] == asset_kind, (fmt, needle)
        return hit[0]

    hdr = one("nginx", "add_header Content-Security-Policy-Report-Only", "service")
    assert hdr["asset_id"] == svc["id"] and hdr["kind"] == "hardening"
    assert "Strict-Transport-Security" not in hdr["content"]      # http service
    assert len(re.findall(r"(?m)^add_header", hdr["content"])) == 4
    assert hdr["rationale"].startswith("Policy: ")               # vendor-neutral first
    assert re.search(r"content-security-policy \(\d+/\d+\)", hdr["rationale"].lower())
    hdr_f = {fid for fid, f in findings.items() if f.check_id == "headers.security"}
    assert hdr_f and set(hdr["finding_ids"]) == hdr_f
    one("apache", "Header always set X-Frame-Options", "service")

    ban = one("nginx", "server_tokens off;", "host")
    assert "DemoServer/1.2.3" in ban["rationale"]
    disc = {fid for fid, f in findings.items() if f.check_id == "headers.disclosure"}
    assert set(ban["finding_ids"]) == disc
    one("apache", "ServerTokens Prod", "host")

    waf = one("modsecurity", "\\.git", "service")
    assert waf["kind"] == "waf_rule" and "REQUEST_FILENAME" in waf["content"]
    git = {fid for fid, f in findings.items()
           if f.check_id == "exposure.files" and "/.git/" in f.location["url"]}
    assert git and set(waf["finding_ids"]) == git        # the findings of that path class
    one("nginx", "if ($vigilo_path_", "service")
    sig = yaml.safe_load(one("sigma", "/.git/", "service")["content"])
    assert sig["detection"]["selection_path"]["c-uri|startswith"] == "/.git/"

    login = one("nginx", "limit_req zone=", "endpoint")
    assert by_id[login["asset_id"]]["label"] == "/login"
    assert "location" not in login["content"].replace("no location", "")   # routing intact
    assert "limit_req_status 429;" in login["content"] and "POST" in login["content"]
    msc = one("modsecurity", "@gt 10", "endpoint")
    assert msc["asset_id"] == login["asset_id"] and '"@streq POST"' in msc["content"]

    cors = one("nginx", "Access-Control-Allow-Origin", "service")
    assert "@@REPLACE_ALLOWED_ORIGIN@@" in cors["content"]       # a REQUIRED EDIT
    assert "location" not in cors["content"]
    cors_f = {fid for fid, f in findings.items() if f.check_id == "cors.policy"}
    assert cors_f and set(cors["finding_ids"]) == cors_f
    ck = one("nginx", "proxy_cookie_flags session httponly samesite=lax;", "service")
    assert "session" in ck["rationale"]
    assert {fid for fid, f in findings.items()
            if f.check_id == "cookies.flags"} == set(ck["finding_ids"])
    one("apache", "Header always edit Set-Cookie", "service")

    https = one("nginx", "return 301 https://127.0.0.1$request_uri;", "service")
    assert "Strict-Transport-Security" in https["content"] and https["finding_ids"] == []
    assert "plain http" in https["rationale"]
    one("apache", "RewriteRule ^ https://", "service")

    # filters and download
    only = await _defenses(client, user_token, rid, asset_id=svc["id"])
    assert only and all(d["asset_id"] == svc["id"] for d in only)
    r = await client.get(f"/greybox/runs/{rid}/defenses/download", headers=h(user_token),
                         params={"format": "all", "scope": "asset"})
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    blob = "".join(z.read(n).decode() for n in z.namelist())
    assert "server_tokens off;" in blob and "(asset " in blob
    assert "autoindex off" not in blob          # finding-scoped ones filtered out
    r = await client.get(f"/greybox/runs/{rid}/defenses/download", headers=h(user_token),
                         params={"format": "nginx", "asset_id": svc["id"]})
    assert r.status_code == 200 and "add_header" in r.text and "server_tokens" not in r.text
    r = await client.get(f"/greybox/runs/{rid}/defenses", headers=h(user_token),
                         params={"scope": "bogus"})
    assert r.status_code == 422


async def test_asset_graph_defense_nodes_and_protects_edges(client, user_token, run):
    rid = run["id"]
    g = await _graph(client, user_token, rid)
    nodes = {n["id"]: n for n in g["nodes"]}
    items = await _defenses(client, user_token, rid, scope="asset")
    dnodes = [n for n in g["nodes"] if n["kind"] == "defense"]
    assert {n["id"] for n in dnodes} == {d["node_id"] for d in items}
    by_def = {d["node_id"]: d for d in items}
    for n in dnodes:
        d = by_def[n["id"]]
        assert n["label"] == d["title"] and n["parent_id"] is None
        assert n["data"] == {"kind": d["kind"], "format": d["format"], "scope": "asset",
                             "defense_id": d["id"], "confidence": d["confidence"]}
        assert n["in_scope"] is True
    protects = [e for e in g["edges"] if e["rel"] == "protects"]
    assert len(protects) == len(items)
    for e in protects:
        assert nodes[e["src"]]["kind"] == "defense"
        assert nodes[e["dst"]]["kind"] in ("host", "service", "endpoint")
        assert e["dst"] == by_def[e["src"]]["asset_id"]
    # coverage counts endpoints only (and leaves static assets to
    # static_endpoints); host/service/defense nodes do not distort it
    eps = [n for n in g["nodes"] if n["kind"] == "endpoint" and n["in_scope"]]
    assert g["coverage"]["in_scope_endpoints"] == \
        len(eps) - g["coverage"]["static_endpoints"]
    # finding-scoped defenses stay in the exploration graph
    ex = (await client.get(f"/greybox/runs/{rid}/graph/exploration",
                           headers=h(user_token))).json()
    fdef = await _defenses(client, user_token, rid, scope="finding")
    assert {n["id"] for n in ex["nodes"] if n["kind"] == "defense"} == \
        {d["node_id"] for d in fdef}
    ev = (await client.get(f"/greybox/runs/{rid}/events", headers=h(user_token),
                           params={"kind": "defense.proposed", "limit": 500})).json()
    proposed = [e for e in ev["items"] if e["data"].get("scope") == "asset"]
    assert len(proposed) == len(items)
    for e in proposed:
        assert e["data"]["asset_id"] in nodes and e["data"]["finding_id"] is None
        assert isinstance(e["data"]["finding_ids"], list)


# ------------------------------------------------------------------ report


async def test_report_network_sections(client, user_token, run):
    md = (await client.get(f"/greybox/runs/{run['id']}/report",
                           headers=h(user_token))).json()["markdown"]
    assert md.index("## Verified findings") < md.index("## Network overview") \
        < md.index("## Detection and WAF suggestions") < md.index("## Coverage")
    net = md[md.index("## Network overview"):md.index("## Detection and WAF suggestions")]
    assert re.search(r"### http\\://127\.0\.0\.1:\d+ — risk \d+/100", net)
    assert "`DemoServer/1.2.3`" in net and "plain http (no TLS)" in net
    assert "| Security headers |" in net and "`content-security-policy`" in net
    assert "`session`: no Secure, no HttpOnly, no SameSite" in net
    assert "origin reflected with credentials (`/api/data`)" in net
    assert "`/.git/HEAD`" in net and "Top issues:" in net
    tail = md[md.index("## Detection and WAF suggestions"):md.index("## Coverage")]
    assert "### Network recommendations — http\\://127.0.0.1:" in tail
    assert "_Addresses: " in tail and "server_tokens off;" in tail
    assert "limit_req zone=" in tail and "location = /login" not in tail


def _assert_inert(md: str) -> None:
    """Outside code spans and fences: no raw HTML, no live link or image."""
    plain = re.sub(r"(`+)(?:(?!\1).)*?\1", "", md)
    plain = re.sub(r"(?s)(`{3,}).*?\1", "", plain)
    assert "<" not in plain and not re.search(r"(?<!\\)\]\(", plain), plain
    assert not re.search(r"(?<!\\)\[", plain.replace("\\[", ""))


def test_report_neutralises_target_derived_text():
    hostile = "<img src=x onerror=1> [x](http://evil.invalid/) | `tick` # head"
    svc = GreyboxAsset(
        id=uuid.uuid4(), run_id=uuid.uuid4(), kind="service", key="http://h:80",
        label="http://h:80 <b>bold</b>", in_scope=True, tested=False, finding_count=0,
        state="in_scope", first_seen_seq=1, version=1,
        data={"surface": {
            "server": hostile, "technologies": [hostile], "risk_score": 7,
            "security_headers": {"missing": [hostile], "present": [], "evaluated": 1,
                                 "counts": {}},
            "cookie_flags": {hostile: {"secure": False, "httponly": True,
                                       "samesite": "lax"}},
            "cors": {"tested": True, "paths": [hostile]},
            "redirects": {}, "tls": {"https": False}, "endpoints": {},
            "sensitive_paths": [{"path": hostile, "reason": hostile}],
            "risk_factors": [{"id": "x", "points": 1, "detail": hostile}]}})
    out: list[str] = []
    gb_report._network_section(out, [svc])
    md = "\n".join(out)
    _assert_inert(md)
    for line in md.splitlines():        # every table row keeps its two cells
        if line.startswith("| "):
            assert len(re.findall(r"(?<!\\)\|", line)) == 3, line
    d = GreyboxDefense(
        id=uuid.uuid4(), run_id=svc.run_id, finding_id=None, asset_id=svc.id,
        scope="asset", finding_ids=[], node_id=None, kind="hardening", format="nginx",
        title=hostile, rationale=hostile, content="x;\n```\n# injected\n",
        confidence="high", status="proposed")
    out = []
    gb_report._defenses_section(out, [], [d], {svc.id: svc})
    md = "\n".join(out)
    _assert_inert(md)
    assert "````nginx" in md          # the fence outgrows backticks in the content


def test_templates_keep_hostile_text_out_of_rules():
    run_id = uuid.uuid4()
    host = GreyboxAsset(id=uuid.uuid4(), run_id=run_id, kind="host", key="h", label="h",
                        in_scope=True, tested=False, finding_count=0, state="in_scope",
                        first_seen_seq=1, version=1, data={})
    bad = '/a"b\nSecRule x "y" \'z\'}\n{'
    svc = GreyboxAsset(
        id=uuid.uuid4(), run_id=run_id, kind="service", key="http://h:80",
        label='http://h:80"\n}', parent_id=host.id, in_scope=True, tested=False,
        finding_count=0, state="in_scope", first_seen_seq=1, version=1,
        data={"surface": {
            "server": "X/1\n'; drop", "version_disclosure": ["server"],
            "security_headers": {"missing": ["content-security-policy", "bogus"],
                                 "counts": {}, "evaluated": 1},
            "cookie_flags": {}, "cors": {"reflects_origin": True, "paths": [bad]},
            "tls": {"https": False}, "endpoints": {"auth_like": 1},
            "auth_paths": [], "sensitive_paths": [{"path": bad, "reason": "x\n'"}]}})
    specs = gb_defenses.build_for_assets(
        [svc], {host.id: host}, {svc.id: []}, [], run_id,
        gb_defenses.ModSecIds(), "2026/01/01")
    assert specs
    for a in specs:
        c = a.spec.content
        assert "\nSecRule x" not in c and 'b\nSec' not in c and "}\n}" not in c
        assert '"b' not in c
        if a.spec.format == "sigma":
            yaml.safe_load(c)
        assert "\n" not in a.spec.title and '"' not in a.spec.title
        assert "bogus" not in c
    assert not [a for a in specs if a.spec.format == "sigma"
                and "\n}" in a.spec.rationale]


def test_registered_secret_never_reaches_a_network_rule():
    redaction.register_secret("hunter2-net-secret")
    try:
        run_id = uuid.uuid4()
        svc = GreyboxAsset(
            id=uuid.uuid4(), run_id=run_id, kind="service",
            key="http://h:80", label="http://h:80 hunter2-net-secret", in_scope=True,
            tested=False, finding_count=0, state="in_scope", first_seen_seq=1, version=1,
            data={"surface": {
                "server": "hunter2-net-secret/1.0", "version_disclosure": ["server"],
                "security_headers": {"missing": ["x-frame-options"], "counts": {},
                                     "evaluated": 1},
                "cookie_flags": {"hunter2-net-secret": {"secure": False, "httponly": False,
                                                        "samesite": None}},
                "cors": {}, "tls": {"https": False}, "endpoints": {},
                "sensitive_paths": [{"path": "/hunter2-net-secret/.env",
                                     "reason": "environment file"}]}})
        host = GreyboxAsset(id=uuid.uuid4(), run_id=run_id, kind="host", key="h",
                            label="h", in_scope=True, tested=False, finding_count=0,
                            state="in_scope", first_seen_seq=1, version=1, data={})
        svc.parent_id = host.id
        specs = gb_defenses.build_for_assets(
            [svc], {host.id: host}, {svc.id: []}, [], run_id,
            gb_defenses.ModSecIds(), "2026/01/01")
        assert specs
        for a in specs:
            assert "hunter2" not in f"{a.spec.title}{a.spec.rationale}{a.spec.content}"
    finally:
        redaction._registry.clear()


async def test_registered_credential_never_persisted_in_network_data(
        client, user_token, target_server, session_maker):
    from src.audit import redact
    from tests.greybox_web.conftest import create_target
    secret = "session=net-analysis-secret-77"
    r = await client.post("/credentials", headers=h(user_token), json={
        "kind": "cookie_header", "label": "net", "secret": secret})
    assert r.status_code == 201, r.text
    t = await create_target(client, user_token, base_url=target_server.url,
                            credential_id=r.json()["id"])
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    assert await run_worker_once(session_maker) == run_id
    try:
        async with session_maker() as s:
            kinds = {m: len((await s.scalars(select(m))).all())
                     for m in (GreyboxDefense, GreyboxAsset)}
            assert kinds[GreyboxDefense] and (await s.scalars(select(GreyboxAsset).where(
                GreyboxAsset.kind == "defense"))).first() is not None
            svc = (await s.scalars(select(GreyboxAsset).where(
                GreyboxAsset.kind == "service", GreyboxAsset.in_scope.is_(True)))).one()
            assert svc.data["surface"]["cookie_flags"]
            for model in RUN_CHILD_MODELS:
                for row in (await s.scalars(select(model))).all():
                    for col in model.__table__.columns:
                        v = getattr(row, col.name)
                        blob = v if isinstance(v, str) else json.dumps(v, default=str) \
                            if isinstance(v, (dict, list)) else ""
                        for needle in ("net-analysis-secret-77", "session=net-analysis"):
                            assert needle not in blob, (model.__tablename__, col.name)
        md = (await client.get(f"/greybox/runs/{run_id}/report",
                               headers=h(user_token))).json()["markdown"]
        assert "net-analysis-secret-77" not in md and "## Network overview" in md
    finally:
        redact.clear()


# ------------------------------------------------------------------ migration


def test_migration_0015_upgrades_and_downgrades(tmp_path):
    from alembic import command

    from scripts.run_migrations import build_config
    url = f"sqlite:///{tmp_path}/mig.db"
    cfg = build_config(url)
    command.upgrade(cfg, "0014_greybox_defenses")
    eng = sa.create_engine(url)
    # make sure 0014 (old shape), not 0003, created the table
    with eng.begin() as c:
        c.execute(sa.text("DROP TABLE greybox_defenses"))
    command.downgrade(cfg, "0013_greybox_hints")
    command.upgrade(cfg, "0014_greybox_defenses")
    cols = {c["name"]: c for c in sa.inspect(eng).get_columns("greybox_defenses")}
    assert "asset_id" not in cols and cols["finding_id"]["nullable"] is False
    run_id, fid, did = (uuid.uuid4().hex for _ in range(3))
    insert = ("INSERT INTO greybox_defenses (id, run_id, finding_id, kind, format, title, "
              "rationale, content, confidence, status, created_at) VALUES "
              "(:id, :run, :f, 'config', 'nginx', 't', 'r', 'c', 'high', 'proposed', "
              "'2026-01-01 00:00:00')")
    with eng.begin() as c:
        c.execute(sa.text(insert), {"id": did, "run": run_id, "f": fid})

    command.upgrade(cfg, "head")
    command.upgrade(cfg, "head")                       # idempotent
    cols = {c["name"]: c for c in sa.inspect(eng).get_columns("greybox_defenses")}
    assert {"asset_id", "scope", "finding_ids"} <= set(cols)
    assert cols["finding_id"]["nullable"] is True and cols["asset_id"]["nullable"] is True
    assert cols["scope"]["nullable"] is False and cols["finding_ids"]["nullable"] is False
    with eng.connect() as c:
        row = c.execute(sa.text(
            "SELECT scope, finding_ids, finding_id FROM greybox_defenses")).one()
        assert row.scope == "finding" and json.loads(row.finding_ids) == [
            str(uuid.UUID(fid))]
        assert c.execute(sa.text("SELECT version_num FROM alembic_version")).scalar() == \
            "0024_greybox_exchange_identity"
    # the account_ids columns (login accounts per target/run) came with 0019
    for table in ("greybox_targets", "greybox_runs"):
        cols = {c["name"]: c for c in sa.inspect(eng).get_columns(table)}
        assert "account_ids" in cols and cols["account_ids"]["nullable"] is False
    with eng.begin() as c:                              # an asset-scoped row
        c.execute(sa.text(
            "INSERT INTO greybox_defenses (id, run_id, asset_id, scope, finding_ids, "
            "kind, format, title, rationale, content, confidence, status, created_at) "
            "VALUES (:id, :run, :a, 'asset', '[]', 'hardening', 'nginx', 't2', 'r', "
            "'c', 'high', 'proposed', '2026-01-01 00:00:00')"),
            {"id": uuid.uuid4().hex, "run": run_id, "a": uuid.uuid4().hex})

    command.downgrade(cfg, "0014_greybox_defenses")
    cols = {c["name"]: c for c in sa.inspect(eng).get_columns("greybox_defenses")}
    assert not ({"asset_id", "scope", "finding_ids"} & set(cols))
    assert cols["finding_id"]["nullable"] is False
    with eng.connect() as c:
        assert c.execute(sa.text("SELECT count(*) FROM greybox_defenses")).scalar() == 1
    command.upgrade(cfg, "head")


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
