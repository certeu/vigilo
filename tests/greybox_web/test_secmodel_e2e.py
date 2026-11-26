"""Security model end to end through the real worker (SCRIPTED agent, not a real
model): Harbor Docs, two accounts.

The fake agent only reads the knowledge snapshot and acts like the business-logic
playbook says: log in as both identities, request the private project and the
team feed as the non-member, declare an expectation in its reply's ``model``
field, and verify the "refused here, shown there" case with authz.exposure.

Checked: identity attribution of the recorded requests; the engine-derived
interfaces and access matrix; the agent's expectation stored with a resolved
basis; the verified cross-interface finding with an evidence chain; the
security-model section of the report; the /model API.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from src.greybox_web.exploration.client import FakeClient
from src.greybox_web.exploration.knowledge import extract_knowledge
from src.greybox_web.models import GreyboxEvent, GreyboxFinding, GreyboxHttpExchange
from tests.greybox_web.conftest import create_target, h, run_worker_once, start_run
from tests.greybox_web.fixtures import harbor_docs
from tests.greybox_web.test_web_autonomy import LIMITS, _act, _reply

SPEC = json.loads((Path(harbor_docs.__file__).parent / "assessment.json").read_text())


@pytest.fixture(scope="module")
def harbor():
    server, url = harbor_docs.serve(0)
    yield url
    server.should_exit = True


async def _accounts(client, token) -> list[str]:
    ids = []
    for a in SPEC["accounts"]:
        if a["label"] not in ("dave", "finn"):
            continue
        r = await client.post("/credentials", headers=h(token), json={
            "kind": "login_account", "label": a["label"],
            "secret": json.dumps({"user": a["user"], "password": a["password"]})})
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    return ids


def model_agent(base: str, trace: dict):
    def respond(system: str, user: str) -> str:
        k = extract_knowledge(user)
        trace.setdefault("k", []).append(k)
        done = " ".join((k.get("work") or {}).get("history") or []) + " " + " ".join(
            f"{w['tool']} {w['url']}" for w in (k.get("work") or {}).get("pending") or [])
        sessions = {s["label"] for s in k["run"].get("sessions") or []}
        acts, model = [], {}
        if not sessions:
            for label in ("dave", "finn"):
                acts.append(_act("auth.login", {"url": base + "login", "account": label,
                                                "user_field": "username"},
                                 "establish identity", f"login-{label}"))
            return _reply(acts)
        if "api/projects/cobalt" not in done:
            acts.append(_act("authz.object", {"url": base + "api/projects/cobalt"},
                             "who may open the private project", "cobalt"))
            return _reply(acts)
        # the access matrix shows dave refused: state the expectation, citing it
        iface = {i["interface"]: i for i in k["security_model"]["interfaces"]}
        cobalt = iface.get("/api/projects/{id}") or {}
        if "dave" in (cobalt.get("access") or {}) and not \
                k["security_model"]["expectations"]:
            model = {"entities": [{"kind": "resource", "name": "cobalt",
                                   "attributes": {"visibility": "private"}}],
                     "relations": [{"src": {"kind": "identity", "name": "finn"},
                                    "rel": "member_of",
                                    "dst": {"kind": "resource", "name": "cobalt"},
                                    "basis": "observed_ui",
                                    "evidence": [base + "api/projects/cobalt"]}],
                     "expectations": [{"subject": {"kind": "identity", "name": "dave"},
                                       "operation": "read",
                                       "resource": {"kind": "resource", "name": "cobalt"},
                                       "expected": "deny", "basis": "observed_ui",
                                       "evidence": [base + "api/projects/cobalt"]}]}
        if "authz.exposure" not in done:
            acts.append(_act("authz.exposure", {
                "url": base + "api/teams/meridian/activity", "viewer": "dave",
                "marker": "Cobalt", "control_url": base + "api/projects/cobalt",
                "owner": "finn"}, "feed vs project boundary", "feed-cobalt"))
        reply = json.loads(_reply(acts, assessment="incomplete" if acts else "adequate"))
        if model:
            reply["model"] = model
        return json.dumps(reply)
    return respond


async def test_cross_interface_reasoning_end_to_end(
        client, user_token, session_maker, monkeypatch, harbor):
    trace: dict = {}
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client",
                        lambda *a, **kw: FakeClient(model_agent(harbor, trace)))
    t = await create_target(client, user_token, name="harbor-model", base_url=harbor,
                            model_backend="fake", limits=dict(LIMITS),
                            account_ids=await _accounts(client, user_token))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "succeeded", body.get("error_summary")

    async with session_maker() as s:
        xs = (await s.scalars(select(GreyboxHttpExchange).where(
            GreyboxHttpExchange.run_id == run_id))).all()
        findings = (await s.scalars(select(GreyboxFinding).where(
            GreyboxFinding.run_id == run_id))).all()
        evs = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id))).all()
    # every request after login carries the identity that made it
    cobalt = {(x.identity, x.status_code) for x in xs
              if x.url.endswith("/api/projects/cobalt")}
    assert ("dave", 403) in cobalt and ("finn", 200) in cobalt

    # the agent's expectation was stored with its basis (evidence resolved)
    assert any(e.kind == "model.updated" for e in evs)
    m = (await client.get(f"/greybox/runs/{run_id}/model", headers=h(user_token))).json()
    exp = [e for e in m["expectations"] if e["resource"] == "resource:cobalt"]
    assert exp and exp[0]["basis"] == "observed_ui" and exp[0]["expected"] == "deny"
    assert any(r["rel"] == "member_of" for r in m["relations"])
    assert m["interfaces"] and {"dave", "finn"} <= {i["identity"] for i in m["identities"]}

    # the cross-interface finding: verified by re-running every step
    xf = [f for f in findings if f.check_id == "authz.exposure"]
    assert len(xf) == 1 and xf[0].status == "verified", [
        (f.check_id, f.status, f.title) for f in findings]
    assert "Expected boundary" in xf[0].description
    rep = (await client.get(f"/greybox/runs/{run_id}/report",
                            headers=h(user_token))).json()
    md = rep.get("markdown") or ""
    assert "## Security model" in md
    assert "observed\\_ui" in md or "observed_ui" in md


def members_agent(base: str):
    """Both identities read their shared project's document list, then the agent
    tests one of those documents across identities."""
    def respond(system: str, user: str) -> str:
        k = extract_knowledge(user)
        done = " ".join((k.get("work") or {}).get("history") or []) + " " + " ".join(
            f"{w['tool']} {w['url']}" for w in (k.get("work") or {}).get("pending") or [])
        if not k["run"].get("sessions"):
            return _reply([_act("auth.login", {"url": base + "login", "account": a,
                                               "user_field": "username"}, "login",
                                f"login-{a}") for a in ("dave", "finn")])
        acts = []
        if "documents-list" not in done:
            acts.append(_act("tool.compose", {"spec": {
                "id": "documents-list", "title": "beacon documents per identity",
                "purpose": "read the project document list as each identity",
                "capabilities": ["http"],
                "source": "def analyse(ctx):\n"
                          "    for s in ctx.broker.sessions():\n"
                          "        ctx.broker.get(ctx.base_url + 'api/projects/beacon/"
                          "documents', session=s['label'])\n"
                          "    return {'summary': 'ok', 'observations': [], "
                          "'findings': []}\n"}}, "lists", "define"))
        elif "tool.documents-list" not in done:
            acts.append(_act("tool.documents-list", {}, "read lists", "run"))
        elif "authz.object" not in done:
            acts.append(_act("authz.object", {"url": base + "api/documents/d-b2981a"},
                             "who reads the shared document", "doc"))
        return _reply(acts, assessment="incomplete" if acts else "adequate")
    return respond


async def test_shared_access_by_project_members_is_not_a_finding(
        client, user_token, session_maker, monkeypatch, harbor):
    """Real Codex runs: members of the same project reading a project document were
    reported as "readable by every tested account". The verification gate must
    reject that (the application lists the document to both) and the decision must
    be stored with the finding."""
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client",
                        lambda *a, **kw: FakeClient(members_agent(harbor)))
    t = await create_target(client, user_token, name="harbor-members", base_url=harbor,
                            model_backend="fake", limits=dict(LIMITS),
                            account_ids=await _accounts(client, user_token))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    async with session_maker() as s:
        findings = (await s.scalars(select(GreyboxFinding).where(
            GreyboxFinding.run_id == run_id,
            GreyboxFinding.check_id == "authz.object"))).all()
    assert findings, "authz.object reported nothing to gate"
    for f in findings:
        assert f.status == "rejected", (f.title, f.verification)
        assert f.verification["result"] == "authorised_by_model"
        assert f.verification["model"]["decision"] == "authorised"
        assert any("lists documents d-b2981a" in r
                   for r in f.verification["model"]["reasons"])


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
