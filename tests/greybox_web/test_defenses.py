"""Defensive recommendations generated after verification.

One full run against the live synthetic target; every verified finding gets
defenses whose rules are syntactically valid, uniquely identified and secret-free,
projected into the graph, announced as events, rendered in the report and served by
the list and download endpoints.
"""
from __future__ import annotations

import io
import re
import uuid
import zipfile

import pytest
import yaml
from sqlalchemy import select

from src.greybox_web import defenses as gb_defenses
from src.greybox_web import redaction
from src.greybox_web.models import GreyboxDefense, GreyboxEvent, GreyboxFinding
from tests.greybox_web import defense_harness as H
from tests.greybox_web.conftest import h, other_user_token, run_worker_once, start_run


@pytest.fixture
async def done_run(client, user_token, live_target, session_maker):
    r = await start_run(client, user_token, live_target["id"],
                        key=f"def-{uuid.uuid4().hex[:12]}")
    assert r.status_code == 201, r.text
    await run_worker_once(session_maker)
    run = (await client.get(f"/greybox/runs/{r.json()['id']}",
                            headers=h(user_token))).json()
    assert run["status"] == "succeeded"
    return run


async def _defenses(client, token, run_id, **params):
    r = await client.get(f"/greybox/runs/{run_id}/defenses", headers=h(token),
                         params=params)
    assert r.status_code == 200, r.text
    return r.json()["items"]


async def test_every_verified_finding_has_defenses(client, user_token, done_run,
                                                   session_maker):
    rid = done_run["id"]
    items = await _defenses(client, user_token, rid)
    assert items
    async with session_maker() as s:
        rows = (await s.scalars(select(GreyboxFinding).where(
            GreyboxFinding.run_id == uuid.UUID(rid)))).all()
    verified = {str(f.id) for f in rows if f.status == "verified"}
    rejected = {str(f.id) for f in rows if f.status == "rejected"}
    assert verified
    items = [d for d in items if d["scope"] == "finding"]    # asset ones: 10.7
    covered = {d["finding_id"] for d in items} | {x for d in items for x in d["finding_ids"]}
    assert verified <= covered, "a verified finding has no defense"
    assert not (rejected & covered), "defenses for a rejected finding"
    for d in items:
        assert set(d) == {"id", "run_id", "finding_id", "asset_id", "scope",
                          "finding_ids", "node_id", "kind", "format",
                          "title", "rationale", "content", "confidence", "status",
                          "created_at"}
        assert d["finding_id"] in d["finding_ids"]
        assert d["kind"] in ("waf_rule", "detection_rule", "config")
        assert d["format"] in ("modsecurity", "sigma", "nginx", "apache", "text")
        assert d["status"] == ("proposed" if d["finding_id"] in verified
                               else "unverified")
        assert d["content"].strip() and d["rationale"] and d["node_id"]
    # filters
    one = items[0]["finding_id"]
    assert {d["finding_id"] for d in await _defenses(client, user_token, rid,
                                                    finding_id=one)} == {one}
    assert all(d["kind"] == "config" for d in
               await _defenses(client, user_token, rid, kind="config"))
    assert all(d["format"] == "sigma" for d in
               await _defenses(client, user_token, rid, format="sigma"))


async def test_rule_syntax(client, user_token, done_run):
    """Every stored defense passes the structural linter of its format; ids are
    unique and stable."""
    items = await _defenses(client, user_token, done_run["id"])
    ids: list[int] = []
    bodies: dict[int, set[str]] = {}
    sbodies: dict[str, set[str]] = {}
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
            sid = str(uuid.UUID(yaml.safe_load(c)["id"]))
            sigma_ids.append(sid)
            sbodies.setdefault(sid, set()).add(" ".join(c.split()))
        elif d["format"] == "nginx":
            H.parse_nginx(c)                    # balanced, terminated, quoted
            assert not re.search(r"^\s*location\b", c, re.M), d["title"]
        elif d["format"] == "apache":
            assert H.lint_apache(c, "global", allow_placeholders=True) == [] or \
                H.lint_apache(c, "vhost", allow_placeholders=True) == [], d["title"]
    # the same rule may be listed under a finding and under the service (identical text,
    # stable id, listed once in the bundle): one id never has two different bodies
    assert ids and all(len(b) == 1 for b in bodies.values())
    assert all(gb_defenses.MODSEC_BASE <= i < gb_defenses.MODSEC_BASE + gb_defenses.MODSEC_SPAN for i in ids)
    assert sigma_ids and all(len(b) == 1 for b in sbodies.values())


async def test_git_head_defenses(client, user_token, done_run):
    items = await _defenses(client, user_token, done_run["id"])
    git = [d for d in items if ".git" in d["content"]]
    fmts = {d["format"] for d in git}
    assert {"modsecurity", "nginx", "sigma"} <= fmts
    msc = next(d for d in git if d["format"] == "modsecurity")
    assert "\\.git" in msc["content"] and "SecRule REQUEST_FILENAME" in msc["content"]
    nginx = next(d for d in git if d["format"] == "nginx")
    assert "\\.git" in nginx["content"] and "return 404;" in nginx["content"]
    assert "location" not in nginx["content"]
    apache = next(d for d in git if d["format"] == "apache")
    assert "<LocationMatch" in apache["content"] and "DirectoryMatch" not in apache["content"]
    docs = [yaml.safe_load(d["content"]) for d in git if d["format"] == "sigma"]
    assert {d["level"] for d in docs} == {"informational", "high"}      # attempt, served
    for sig in docs:
        assert sig["logsource"]["category"] == "webserver"
        assert sig["detection"]["selection_path"]["c-uri|startswith"] == "/.git/"


async def test_defenses_per_check(client, user_token, done_run):
    titles = " | ".join(d["title"] + d["content"]
                        for d in await _defenses(client, user_token, done_run["id"]))
    for needle in ("autoindex off;", "server_tokens off;", "Content-Security-Policy",
                   "CORS", "proxy_cookie_flags session httponly;"):
        assert needle in titles, needle


async def test_graph_nodes_edges_and_events(client, user_token, done_run, session_maker):
    rid = done_run["id"]
    items = await _defenses(client, user_token, rid, scope="finding")
    g = (await client.get(f"/greybox/runs/{rid}/graph/exploration",
                          headers=h(user_token))).json()
    nodes = {n["id"]: n for n in g["nodes"]}
    node_ids = {d["node_id"] for d in items}
    for d in items:
        n = nodes[d["node_id"]]
        assert n["kind"] == "defense" and n["label"] == d["title"]
        assert n["status"] == d["status"]
        assert n["data"] == {"kind": d["kind"], "format": d["format"]}
    mit = [e for e in g["edges"] if e["rel"] == "mitigates"]
    # one edge per (defense, finding it addresses): identical defenses are one row
    assert {e["src"] for e in mit} == node_ids
    assert len(mit) == sum(len(d["finding_ids"]) for d in items)
    for e in mit:
        assert nodes[e["dst"]]["kind"] == "finding"
    async with session_maker() as s:
        evs = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == uuid.UUID(rid),
            GreyboxEvent.kind == "defense.proposed"))).all()
    evs = [e for e in evs if e.data.get("scope") == "finding"]
    assert len(evs) == len(items)
    ev = evs[0]
    assert (ev.source, ev.level, ev.status) == ("agent", "info", "ok")
    assert set(ev.data) >= {"defense_id", "finding_id", "kind", "format", "title"}
    assert {e.data["defense_id"] for e in evs} == {d["id"] for d in items}


async def test_report_section(client, user_token, done_run):
    md = (await client.get(f"/greybox/runs/{done_run['id']}/report",
                           headers=h(user_token))).json()["markdown"]
    assert "## Detection and WAF suggestions" in md
    assert md.index("## Verified findings") < md.index("## Detection and WAF suggestions") \
        < md.index("## Coverage")
    assert "SecRule REQUEST_FILENAME" in md and "```nginx" in md and "```yaml" in md
    assert "Merge request" not in md and "Patch:" not in md


async def test_downloads(client, user_token, done_run):
    rid = done_run["id"]
    short = rid[:8]
    expect = {"modsecurity": "conf", "sigma": "yml", "nginx": "conf", "apache": "conf"}
    for fmt, ext in expect.items():
        r = await client.get(f"/greybox/runs/{rid}/defenses/download",
                             headers=h(user_token), params={"format": fmt})
        assert r.status_code == 200, (fmt, r.text)
        assert r.headers["content-type"].startswith("text/plain")
        assert r.headers["content-disposition"] == \
            f'attachment; filename="greybox-defenses-{short}.{ext}"'
        if fmt == "sigma":
            docs = [d for d in yaml.safe_load_all(r.text) if d]
            assert docs and all("detection" in d for d in docs)
        if fmt == "modsecurity":
            assert r.text.count("SecRule") >= 2
    r = await client.get(f"/greybox/runs/{rid}/defenses/download", headers=h(user_token),
                         params={"format": "all"})
    assert r.headers["content-type"] == "application/zip"
    assert r.headers["content-disposition"] == \
        f'attachment; filename="greybox-defenses-{short}.zip"'
    names = set(zipfile.ZipFile(io.BytesIO(r.content)).namelist())
    assert {"modsecurity.conf", "sigma.yml", "nginx.conf", "apache.conf"} <= names
    r = await client.get(f"/greybox/runs/{rid}/defenses/download", headers=h(user_token),
                         params={"format": "bogus"})
    assert r.status_code == 422


async def test_other_user_gets_404(client, user_token, done_run, session_maker):
    other = await other_user_token(client, session_maker, "intruder@example.com")
    rid = done_run["id"]
    for path in ("/defenses", "/defenses/download"):
        r = await client.get(f"/greybox/runs/{rid}{path}", headers=h(other))
        assert r.status_code == 404
    assert (await client.get(f"/greybox/runs/{rid}/defenses")).status_code == 401


def test_registered_secret_is_masked_in_every_field():
    redaction.register_secret("hunter2-secret-path")
    try:
        f = GreyboxFinding(
            id=uuid.uuid4(), run_id=uuid.uuid4(), dedup_key="exposure.files|x|/hunter2-secret-path",
            check_id="exposure.files", title="Exposed file: /hunter2-secret-path",
            severity="high", status="verified", confidence="high", description="d",
            location={"url": "http://127.0.0.1/hunter2-secret-path"},
            detection_hints=[], evidence=[], references=[])
        specs = gb_defenses.build_for_finding(
            f, f.run_id, gb_defenses.ModSecIds(), "2026/01/01")
        assert specs
        for s in specs:
            assert "hunter2" not in f"{s.title}{s.rationale}{s.content}"
    finally:
        redaction._registry.clear()


def test_hostile_path_cannot_break_quoting():
    f = GreyboxFinding(
        id=uuid.uuid4(), run_id=uuid.uuid4(), dedup_key="exposure.files|x|/a",
        check_id="exposure.files", title="t", severity="high", status="candidate",
        confidence="high", description="d",
        location={"url": 'http://h/a"b\'c\n}\nSecRule x'},
        detection_hints=[], evidence=[], references=[])
    for s in gb_defenses.build_for_finding(
            f, f.run_id, gb_defenses.ModSecIds(), "2026/01/01"):
        assert "\nSecRule x" not in s.content and "}\n}" not in s.content
        if s.format == "sigma":
            yaml.safe_load(s.content)


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
