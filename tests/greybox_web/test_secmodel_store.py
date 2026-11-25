"""Security relationship model — persistence, evidence resolution, derived view,
agent-knowledge integration and the API (database-backed)."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from src.greybox_web import secmodel as sm
from src.greybox_web import secmodel_store as store
from src.greybox_web.exploration import knowledge
from src.greybox_web.exploration.schema import parse_reply
from src.greybox_web.graph import GraphTx
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxAssetEdge,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxTarget,
)

BASE = "http://target.test"


@pytest.fixture
async def run(session_maker):
    owner, run_id, target_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    scope = {"allowed_hosts": ["target.test"], "allowed_schemes": ["http"],
             "allowed_ports": [80]}
    async with session_maker() as s:
        s.add(GreyboxTarget(id=target_id, owner_id=owner, name="t", base_url=BASE + "/",
                            scope=scope, limits={"max_requests": 100}, checks=None))
        await s.flush()
        s.add(GreyboxRun(id=run_id, target_id=target_id, owner_id=owner,
                         base_url=BASE + "/", scope=scope, limits={"max_requests": 100},
                         checks=[], status="running", idempotency_key="k"))
        await s.flush()

        def ex(path, ident, status, body=None, ct="application/json"):
            s.add(GreyboxHttpExchange(
                run_id=run_id, tool="t", method="GET", url=BASE + path, path=path,
                status_code=status, identity=ident, response_body=body,
                content_type=ct, request_headers=[], response_headers=[]))
        # the project list tells us "atlas"/"cobalt" are identifiers
        ex("/api/projects", "erin", 200,
           '{"projects": [{"id": "atlas"}, {"id": "cobalt"}]}')
        ex("/api/projects/cobalt", "dave", 403, '{"error": "forbidden"}')
        ex("/api/projects/cobalt", "erin", 200, '{"id": "cobalt"}')
        ex("/api/projects/cobalt/activity", "dave", 200, '{"events": []}')
        ex("/api/documents/d-a71f30", "dave", 200, '{"id": "d-a71f30"}')
        ex("/api/documents/d-a71f30", None, 200, "{}")          # older, unattributed
        await s.commit()
    return run_id


async def _apply(session_maker, run_id, raw):
    async with session_maker() as s:
        gtx = GraphTx(s, run_id)
        out = await store.apply(s, gtx, sm.clean(raw))
        await s.commit()
    return out


async def test_view_derives_identities_interfaces_and_signals(session_maker, run):
    async with session_maker() as s:
        v = await store.view(s, run)
    assert {i["identity"] for i in v["identities"]} == {"dave", "erin"}
    ifaces = {i["interface"]: i["access"] for i in v["interfaces"]}
    assert ifaces["/api/projects/{id}"] == {"dave": {"deny": 1}, "erin": {"allow": 1}}
    # cobalt is refused to dave by the project API and served by its activity
    # interface: a signal with both exchanges as evidence -- not a finding
    sig = [x for x in v["signals"] if x["instance"] == "cobalt"]
    assert sig and sig[0]["kind"] == "inconsistent_boundary"
    assert sig[0]["identity"] == "dave" and len(sig[0]["evidence"]) == 2
    assert sig[0]["status"] == "unverified"
    # nothing expected yet: every resource type is unresolved, not concluded
    assert {u["resource_type"] for u in v["unresolved"]
            if u["kind"] == "no_expectation"} >= {"projects", "documents"}


async def test_declarations_persist_with_resolved_evidence(session_maker, run):
    async with session_maker() as s:
        xid = (await s.scalars(select(GreyboxHttpExchange.id).where(
            GreyboxHttpExchange.run_id == run,
            GreyboxHttpExchange.url == BASE + "/api/projects/cobalt",
            GreyboxHttpExchange.identity == "dave"))).one()
    out = await _apply(session_maker, run, {
        "entities": [{"kind": "identity", "name": "dave",
                      "attributes": {"role": "member"}}],
        "relations": [
            {"src": {"kind": "identity", "name": "dave"}, "rel": "member_of",
             "dst": {"kind": "resource", "name": "beacon"}, "basis": "observed_ui",
             "evidence": ["/api/projects"]},
            {"src": {"kind": "resource", "name": "d-a71f30"}, "rel": "belongs_to",
             "dst": {"kind": "resource", "name": "atlas"}, "basis": "documented",
             "evidence": ["exchange:999999"]}],              # not in this run
        "expectations": [
            {"subject": {"kind": "identity", "name": "dave"}, "operation": "read",
             "resource": {"kind": "resource_type", "name": "projects"},
             "expected": "deny", "basis": "observed_ui",
             "evidence": [f"exchange:{xid}"], "note": "cobalt is not his"},
            {"subject": {"kind": "role", "name": "member"}, "operation": "read",
             "resource": {"kind": "resource_type", "name": "documents"},
             "expected": "allow", "basis": "documented", "evidence": ["made-up-ref"]}]})
    assert out["relations"] == 2 and out["expectations"] == 2
    # unresolvable evidence downgrades the basis to an assumption, with a note
    assert any("kept as" in n for n in out["notes"])
    async with session_maker() as s:
        d = await store.declared(s, run)
        kinds = {a.kind for a in (await s.scalars(select(GreyboxAsset).where(
            GreyboxAsset.run_id == run))).all()}
        n_edges = len((await s.scalars(select(GreyboxAssetEdge).where(
            GreyboxAssetEdge.run_id == run))).all())
    assert {"identity", "resource", "resource_type", "role"} <= kinds
    assert n_edges == 2
    rels = {(r["src"], r["rel"], r["dst"]): r for r in d["relations"]}
    assert rels[("identity:dave", "member_of", "resource:beacon")]["basis"] == \
        "observed_ui"
    assert rels[("resource:d-a71f30", "belongs_to", "resource:atlas")]["basis"] == \
        "stated"
    exp = {e["subject"]: e for e in d["expectations"]}
    assert exp["identity:dave"]["basis"] == "observed_ui"
    assert exp["identity:dave"]["evidence"] == [f"exchange:{xid}"]
    assert exp["role:member"]["basis"] == "stated"
    assert exp["role:member"]["unresolved"] == ["made-up-ref"]
    # an established expectation now resolves the type and is checked
    async with session_maker() as s:
        v = await store.view(s, run)
    assert "projects" not in {u.get("resource_type") for u in v["unresolved"]}
    assert v["counts"]["expectations"] == 2


async def test_expectation_contradicted_by_observation(session_maker, run):
    await _apply(session_maker, run, {"expectations": [
        {"subject": {"kind": "identity", "name": "dave"}, "operation": "read",
         "resource": {"kind": "resource_type", "name": "documents"},
         "expected": "deny", "basis": "stated"}]})
    async with session_maker() as s:
        v = await store.view(s, run)
    hits = [x for x in v["signals"] if x["kind"] == "contradicts_expectation"]
    assert hits and hits[0]["identity"] == "dave"
    assert hits[0]["resource_type"] == "documents"


async def test_redeclaring_updates_instead_of_duplicating(session_maker, run):
    raw = {"expectations": [{"subject": {"kind": "identity", "name": "dave"},
                             "operation": "read",
                             "resource": {"kind": "resource", "name": "atlas"},
                             "expected": "deny", "basis": "stated"}]}
    await _apply(session_maker, run, raw)
    raw["expectations"][0]["note"] = "removed on 2026-11-16"
    await _apply(session_maker, run, raw)
    async with session_maker() as s:
        d = await store.declared(s, run)
    assert len(d["expectations"]) == 1
    assert d["expectations"][0]["note"] == "removed on 2026-11-16"


async def test_knowledge_carries_the_model(session_maker, run):
    async with session_maker() as s:
        k = await knowledge.build(s, run)
    m = k["security_model"]
    assert {i["identity"] for i in m["identities"]} == {"dave", "erin"}
    assert any(x["kind"] == "inconsistent_boundary" for x in m["signals"])
    assert m["counts"]["interfaces"] >= 3


def test_agent_reply_carries_model_updates():
    p = parse_reply('{"reasoning": "r", "assessment": "incomplete", "actions": [], '
                    '"model": {"entities": [{"kind": "role", "name": "approver"}]}}')
    assert p.model["entities"][0]["name"] == "approver"
    # a reply that ONLY updates the model is usable content
    p = parse_reply('{"model": {"entities": [{"kind": "role", "name": "lead"}]}}')
    assert p.model


async def test_model_entities_stay_out_of_the_asset_graph_api(
        session_maker, run, client, user_token):
    # the run belongs to a random owner: the API must not show it to another user
    r = await client.get(f"/greybox/runs/{run}/model",
                         headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 404


async def _add(session_maker, run_id, rows):
    async with session_maker() as s:
        for path, ident, status, body in rows:
            s.add(GreyboxHttpExchange(
                run_id=run_id, tool="t", method="GET", url=BASE + path, path=path,
                status_code=status, identity=ident, response_body=body,
                content_type="application/json", request_headers=[],
                response_headers=[]))
        await s.commit()


async def test_gate_collaboration_listed_to_the_reader_is_authorised(session_maker, run):
    await _add(session_maker, run, [
        ("/api/projects/beacon/documents", "dave", 200,
         '{"documents": [{"id": "d-b2e641", "author": "erin"}]}'),
        ("/api/projects/beacon/documents", "erin", 200,
         '{"documents": [{"id": "d-b2e641", "author": "erin"}]}'),
        ("/api/documents/d-b2e641", "dave", 200, '{"id": "d-b2e641"}')])
    async with session_maker() as s:
        d, why = await store.access_gate(s, run, BASE + "/api/documents/d-b2e641",
                                         ["dave", "erin"])
    assert d == store.AUTHORISED, why
    assert any("lists documents d-b2e641" in r for r in why)


async def test_gate_idor_not_listed_to_the_reader_stays(session_maker, run):
    await _add(session_maker, run, [
        ("/api/invoices", "alice", 200, '{"invoices": [{"id": 1041}, {"id": 1042}]}'),
        ("/api/invoices", "bob", 200, '{"invoices": [{"id": 1043}, {"id": 1044}]}'),
        # a feed that mentions the id is NOT the invoices list
        ("/api/activity", "alice", 200, '{"events": ["bob approve inv:1043"]}')])
    async with session_maker() as s:
        d, why = await store.access_gate(s, run, BASE + "/api/invoices/1043",
                                         ["alice", "bob"])
    assert d == store.UNKNOWN
    assert any(r.startswith("bob: the application lists") for r in why)
    assert any(r.startswith("alice: intended access") for r in why)


async def test_gate_established_expectations_decide(session_maker, run):
    await _apply(session_maker, run, {"expectations": [
        {"subject": {"kind": "role", "name": "approver"}, "operation": "read",
         "resource": {"kind": "resource_type", "name": "documents"},
         "expected": "allow", "basis": "stated"},
        {"subject": {"kind": "identity", "name": "dave"}, "operation": "read",
         "resource": {"kind": "resource", "name": "d-a71f30"},
         "expected": "deny", "basis": "stated", "note": "removed from atlas"}],
        "entities": [{"kind": "identity", "name": "erin",
                      "attributes": {"role": "approver"}}]})
    async with session_maker() as s:
        a, _ = await store.access_gate(s, run, BASE + "/api/documents/d-c3f812",
                                       ["erin"])
        b, why = await store.access_gate(s, run, BASE + "/api/documents/d-a71f30",
                                         ["dave"])
    assert a == store.AUTHORISED
    assert b == store.EXPECTED_DENY and "removed" not in why[0]  # basis, not the note


def test_open_signals_make_the_verdict_partial():
    from src.greybox_web import coverage
    v = coverage.assess(coverage.CoverageInput(
        endpoints=3, endpoints_tested=3,
        model_open_signals=("projects cobalt: refused to dave via /api/projects/{id} "
                            "but served via /api/projects/{id}/activity",),
        model_unresolved=("intended access to projects not established",)))
    assert v.outcome == coverage.PARTIAL
    assert any("cross-interface" in r for r in v.reasons)
    assert any(lim.startswith("Security model:") for lim in v.limitations)


async def test_a_signal_is_settled_by_an_exposure_examination(session_maker, run):
    from src.greybox_web.graph import GraphTx
    async with session_maker() as s:
        assert len(await store.open_signals(s, run)) == 1
        gtx = GraphTx(s, run)
        await gtx.node("observation", "authz.exposure|/api/projects/cobalt/activity|"
                       "/api/projects/cobalt|dave", "x", "recorded",
                       data={"facts": {"interface": "/api/projects/cobalt/activity",
                                       "control": "/api/projects/cobalt",
                                       "decision": "boundary_crossed"}})
        await s.commit()
    async with session_maker() as s:
        assert await store.open_signals(s, run) == []


async def test_report_shows_expected_and_observed_access(session_maker, run):
    from src.greybox_web import report
    await _apply(session_maker, run, {"expectations": [
        {"subject": {"kind": "identity", "name": "dave"}, "operation": "read",
         "resource": {"kind": "resource_type", "name": "projects"},
         "expected": "deny", "basis": "stated"}]})
    async with session_maker() as s:
        md = await report.generate(s, run)
    md = md if isinstance(md, str) else md.markdown
    assert "## Security model" in md
    assert "| read |" in md and "| deny | stated |" in md and "projects" in md
    assert "/api/projects/{id}" in md and "not verified" in md


async def test_gate_established_membership_authorises_reads_under_it(session_maker, run):
    """Ledgerline run: a viewer reading his own organisation's objects was reported
    as shared access. An established membership (with evidence) authorises it; an
    assumed one does not. Instance ids keep their case in URLs."""
    async with session_maker() as s:
        before, _ = await store.access_gate(
            s, run, BASE + "/v1/orgs/org_7Hq2/invoices/inv_tuncsFs0UOVSvQ", ["omar"])
    assert before == store.UNKNOWN
    await _apply(session_maker, run, {"relations": [
        {"src": {"kind": "identity", "name": "omar"}, "rel": "member_of",
         "dst": {"kind": "resource", "name": "org_7Hq2"}, "basis": "observed_ui",
         "evidence": ["/api/projects"]},
        {"src": {"kind": "identity", "name": "greta"}, "rel": "member_of",
         "dst": {"kind": "resource", "name": "org_7Hq2"}, "basis": "stated"}]})
    async with session_maker() as s:
        a, why = await store.access_gate(
            s, run, BASE + "/v1/orgs/org_7Hq2/invoices/inv_tuncsFs0UOVSvQ", ["omar"])
        b, _ = await store.access_gate(
            s, run, BASE + "/v1/orgs/org_7Hq2/invoices/inv_tuncsFs0UOVSvQ", ["greta"])
        c, _ = await store.access_gate(       # another tenant's object: not covered
            s, run, BASE + "/v1/orgs/org_K9pX/invoices/inv_x0x0x0x0x0x", ["omar"])
    assert a == store.AUTHORISED and "member of org_7hq2" in why[0]
    assert b == store.UNKNOWN                  # an assumption never authorises
    assert c == store.UNKNOWN


async def test_gate_membership_follows_belongs_to(session_maker, run):
    await _apply(session_maker, run, {"relations": [
        {"src": {"kind": "identity", "name": "finn"}, "rel": "member_of",
         "dst": {"kind": "resource", "name": "beacon"}, "basis": "observed_ui",
         "evidence": ["/api/projects"]},
        {"src": {"kind": "resource", "name": "d-b2981a"}, "rel": "belongs_to",
         "dst": {"kind": "resource", "name": "beacon"}, "basis": "observed_ui",
         "evidence": ["/api/projects"]},
        # an assumed parent link grants nothing
        {"src": {"kind": "resource", "name": "d-c3f812"}, "rel": "belongs_to",
         "dst": {"kind": "resource", "name": "beacon"}, "basis": "stated"}]})
    async with session_maker() as s:
        a, why = await store.access_gate(s, run, BASE + "/api/documents/d-b2981a",
                                         ["finn"])
        b, _ = await store.access_gate(s, run, BASE + "/api/documents/d-c3f812",
                                       ["finn"])
    assert a == store.AUTHORISED and "member of beacon" in why[0]
    assert b == store.UNKNOWN


async def test_gate_accepts_resource_specific_html_parent_list_but_not_feed(
        session_maker, run):
    """Rendered relationship pages are evidence; generic feeds containing the same
    identifier are not, otherwise a leaking feed would authorise itself."""
    async with session_maker() as s:
        for path, body in [
                ("/projects/beacon", '<h2>Documents</h2><a href="/documents/d-b2981a">x</a>'),
                ("/activity", '<h2>Activity</h2><a href="/documents/d-feed99">x</a>')]:
            s.add(GreyboxHttpExchange(
                run_id=run, tool="browser.visit", method="GET", url=BASE + path,
                path=path, status_code=200, identity="finn", response_body=body,
                content_type="text/html", request_headers=[], response_headers=[]))
        await s.commit()
    async with session_maker() as s:
        listed, why = await store.access_gate(
            s, run, BASE + "/api/documents/d-b2981a", ["finn"])
        leaked, _ = await store.access_gate(
            s, run, BASE + "/api/documents/d-feed99", ["finn"])
    assert listed == store.AUTHORISED and "/projects/beacon" in why[0]
    assert leaked == store.UNKNOWN
