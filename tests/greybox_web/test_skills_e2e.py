"""Skills, end to end through the real engine (Phase 5).

Real worker, database, guarded HTTP, Chromium, sandbox and broker against the SPA
fixture; the model is a scripted agent that FOLLOWS what the engine shows it: the
skill index in the system prompt, the playbook in the trusted ACTIVE SKILLS section,
the phase gates and criteria in ``knowledge.skills.loaded`` and the ``progress``
section. Asserted:

* progressive disclosure: the index is in the instructions, the playbook appears
  only after ``skill.read`` (an audited work order with the agent's reason);
* phase gates move as the ENGINE evaluates the evidence (A → B → C);
* anti-loop: a static re-extraction that already taught nothing is refused;
* tool workflow: an unfamiliar response format → the agent writes a parser →
  it runs through the broker → its finding is verified → the skill continues;
* claims: a satisfied claim citing real evidence counts, one citing nothing does not;
* the coverage verdict and the report carry the definition of done;
* resume: loaded skills, claims and refusals survive; the skill is not re-loaded.
"""
from __future__ import annotations

import json
import re
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.exploration.client import FakeClient
from src.greybox_web.exploration.knowledge import extract_knowledge
from src.greybox_web.models import (
    GreyboxEvent,
    GreyboxFinding,
    GreyboxRun,
    GreyboxWorkOrder,
)
from src.greybox_web.tools import browser
from tests.greybox_web.conftest import create_target, h, run_worker_once, start_run
from tests.greybox_web.fixtures import spa_app
from tests.greybox_web.test_web_autonomy import LIMITS, _accounts, _act, _reply

pytestmark = [pytest.mark.slow, pytest.mark.skipif(not browser.available(),
                                reason="Playwright is not installed")]

AUDIT_PARSER = '''
"""Parse the VGLAUDIT/1 activity feed and flag records of other users."""

def analyse(ctx):
    me = ctx.args.get("as")
    r = ctx.broker.get(ctx.base_url.rstrip("/") + "/api/audit", session=me)
    lines = (r.get("body") or "").splitlines()
    if not lines or not lines[0].startswith("VGLAUDIT/"):
        return {"summary": "not an audit feed: " + str(r.get("status"))}
    records = []
    for line in lines[1:]:
        rec = dict(kv.split("=", 1) for kv in line.split(";") if "=" in kv)
        if rec:
            records.append(rec)
    foreign = [x for x in records if x.get("user") != me]
    out = {"summary": f"{len(records)} audit record(s), {len(foreign)} of other users",
           "observations": [{"key": "audit.feed", "facts": {
               "records": len(records), "foreign": len(foreign),
               "fields": ",".join(sorted({k for x in records for k in x}))}}]}
    if foreign:
        out["findings"] = [{
            "title": "Audit feed exposes other users' activity, e-mail and IPs",
            "severity": "medium", "class": "vulnerability", "cwe": "CWE-359",
            "description": f"As {me}, /api/audit returns {len(foreign)} record(s) of "
                           "other users including e-mail and internal IP addresses.",
            "evidence": [json.dumps(foreign[0])[:200]],
            "remediation": {"summary": "Filter the feed to the caller's records.",
                            "steps": ["Scope the audit query to the session user; "
                                      "drop e-mail/IP for non-admins."],
                            "validation": ["As user A, no record of user B appears."]}}]
    return out
'''


def skill_agent(trace: dict):
    trace.setdefault("prompts", [])

    def respond(system: str, user: str) -> str:
        k = extract_knowledge(user)
        trace["prompts"].append((system, user, k))
        base = k["run"]["base_url"]
        work = k.get("work") or {}
        done = " ".join(work.get("history") or []) + " " + " ".join(
            f"{w['tool']} {w['url']}" for w in (work.get("pending") or [])
            + (work.get("running") or []))
        tools = set(k.get("tools") or [])
        sk = k.get("skills") or {}
        loaded = {s["name"]: s for s in sk.get("loaded") or []}
        sessions = {s["label"] for s in k["run"].get("sessions") or []}
        accounts = [a["label"] for a in k["run"].get("accounts") or []]
        eps = (k.get("assets") or {}).get("endpoints") or []
        paths = {e["path"] for e in eps}
        acts, hyps, claims = [], [], []

        # Layer 1 -> layer 2: load the methodology before the work it covers
        if "api-recon" not in loaded:
            assert "- api-recon:" in system                 # discoverable from the index
            if "skill.read" not in done:
                acts.append(_act("skill.read", {"name": "api-recon"},
                                 "SPA shell, API unknown: map it with api-recon", "sk-recon"))
            return _reply(acts)
        assert "### skill: api-recon" in user              # trusted playbook shown
        recon = loaded["api-recon"]
        crit = {c["id"]: c for c in recon["criteria"]}
        trace.setdefault("phases", []).append(recon["current_phase"])

        def once(tool, target, *a, **kw):
            if f"{tool} {target}" not in done:
                acts.append(_act(tool, *a, **kw))

        # Phase A
        if crit["entry-points"]["status"] != "satisfied":
            once("browser.visit", base, {"url": base}, "entry point", "entry")
        once("discovery.scripts", base, {"url": base}, "read the bundle", "static-1")
        # a looping model: the same extraction again (and again)
        n_static = sum(1 for h in work.get("history") or []
                       if h.startswith("discovery.scripts "))
        if crit["static-resources"]["status"] == "satisfied" and n_static < 3 \
                and trace.get("static_repeats", 0) < 3:
            trace["static_repeats"] = trace.get("static_repeats", 0) + 1
            acts.append(_act("discovery.scripts", {"url": base}, "maybe more this time",
                             f"static-again-{trace['static_repeats']}"))
        # Phase B (runtime) — the gate says static evidence named few API calls
        if recon["current_phase"] in ("B", "C") or \
                crit["static-candidates"]["status"] != "unsatisfied":
            once("browser.act", base + "#/login", {"url": base + "#/login", "actions": [
                {"kind": "click", "selector": "#go"}]}, "find the login call", "login-probe")
            if "/api/session" in paths:
                for acct in accounts:
                    if acct not in sessions:
                        once("auth.login", f"{base}api/session|acct:{acct}",
                             {"url": base + "api/session", "account": acct,
                              "user_field": "username", "password_field": "password"},
                             "identity for workflows", f"login-{acct}")
            if "ana" in sessions:
                for frag in ("#/dashboard", "#/settings"):
                    once("browser.visit", f"{base}{frag}|as:ana",
                         {"url": base + frag, "session": "ana"}, "walk as ana",
                         "ana-" + frag.strip("#/"))
                for ref in sorted(set(re.findall(r"href=#/notebooks/(\d+)",
                                                 json.dumps(k))))[:2]:
                    once("browser.visit", f"{base}#/notebooks/{ref}|as:ana",
                         {"url": f"{base}#/notebooks/{ref}", "session": "ana"},
                         "open a record", f"ana-nb-{ref}")
        # an unfamiliar response format -> write a parser (skill + tool creation)
        odd = [e for e in eps if e.get("content_type")
               and not re.search(r"json|html|javascript|css", e["content_type"])]
        if odd and "ana" in sessions:
            hyps.append({"id": "h-feed", "label": "custom feed",
                         "hypothesis": f"{odd[0]['path']} returns an unfamiliar format "
                                       f"({odd[0]['content_type']}): parse it"})
            once("tool.compose", "define:audit-feed", {"spec": {
                "id": "audit-feed", "title": "VGLAUDIT feed parser",
                "purpose": "no built-in tool parses the line-based VGLAUDIT format",
                "capabilities": ["http"], "source": "import json\n" + AUDIT_PARSER}},
                "unfamiliar format", "compose-feed", "h-feed")
            if "tool.audit-feed" in tools:
                once("tool.audit-feed", '|args:{"as": "ana"}', {"args": {"as": "ana"}},
                     "parse the feed as ana", "feed-ana", "h-feed")
        # Phase C
        if crit["runtime-observed"]["status"] == "satisfied":
            once("discovery.routes", "", {}, "consolidate: infer templates", "routes")
        inv = [o["key"] for o in k.get("observations") or []
               if o["key"].startswith("route.inventory|")]
        if inv:
            claims += [{"skill": "api-recon", "id": "correlated", "status": "satisfied",
                        "evidence": [inv[0]], "note": "route.inventory classifies"},
                       {"skill": "api-recon", "id": "gaps", "status": "satisfied",
                        "evidence": ["nonexistent-evidence-key-123"]},
                       {"skill": "api-recon", "id": "workflows", "status": "blocked",
                        "note": "bruno's workflows not walked in this test",
                        "category": "target"}]
        if not acts:
            return json.dumps({"reasoning": "phases done", "assessment": "adequate",
                               "todolist": [], "hypotheses": [], "actions": [],
                               "criteria": claims})
        return json.dumps({"reasoning": f"api-recon phase {recon['current_phase']}",
                           "assessment": "incomplete", "todolist": [],
                           "hypotheses": hyps, "actions": acts[:8],
                           "criteria": claims})
    return respond


async def _rows(session_maker, run_id, model):
    async with session_maker() as s:
        return list((await s.scalars(select(model).where(model.run_id == run_id)))
                    .all())


async def test_skill_guided_investigation_end_to_end(
        client, user_token, session_maker, monkeypatch, spa_server):
    base = spa_server.url
    trace: dict = {}
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client",
                        lambda *a, **kw: FakeClient(skill_agent(trace)))
    t = await create_target(client, user_token, name="spa-skills", base_url=base,
                            model_backend="fake", limits=dict(LIMITS),
                            account_ids=await _accounts(client, user_token))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "succeeded", body.get("error_summary")

    # --- progressive disclosure, audited with the agent's reason
    first_system, first_user, _ = trace["prompts"][0]
    assert "- api-recon:" in first_system and "### skill: api-recon" not in first_user
    wos = await _rows(session_maker, run_id, GreyboxWorkOrder)
    reads = [w for w in wos if w.tool == "skill.read"]
    assert len(reads) == 1 and "api-recon" in reads[0].reason
    evs = await _rows(session_maker, run_id, GreyboxEvent)
    loaded = [e for e in evs if e.kind == "skill.loaded"]
    assert loaded and loaded[0].data["skill"] == "api-recon" \
        and "SPA shell" in loaded[0].data["reason"]

    # --- the engine moved the gates as evidence arrived
    phases = [p for p in trace["phases"] if p]
    assert phases[0] == "A" and "C" in phases, phases

    # --- anti-loop: the repeated extraction stopped being admitted
    refused = [e for e in evs if e.kind == "planner.decision"
               and (e.data or {}).get("reason") == "no_new_information"]
    assert refused and "discovery.scripts" in refused[0].summary
    runs = [w for w in wos if w.tool == "discovery.scripts"]
    assert len(runs) <= 2, [w.params for w in runs]

    # --- unfamiliar format -> written parser -> broker -> verified finding
    feed = [w for w in wos if w.tool == "tool.audit-feed"]
    assert feed and feed[0].status == "done"
    findings = await _rows(session_maker, run_id, GreyboxFinding)
    leak = [f for f in findings if f.check_id == "tool.audit-feed"]
    assert leak and leak[0].status == "verified", [(f.title, f.status) for f in findings]

    # --- definition of done: engine evidence, validated claims, verdict, report
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
    v = run.coverage_verdict
    recon = v["skills"]["api-recon"]
    assert recon["satisfied"] >= 6 and recon["blocked"] == 1, recon
    assert recon["unsatisfied"] >= 1           # the claim with fabricated evidence
    rep = (await client.get(f"/greybox/runs/{run_id}/report",
                            headers=h(user_token))).json()["markdown"]
    sec = rep.split("## Methodology and definition of done", 1)[1]
    assert "**established** (engine)" in sec and "**established** (agent)" in sec
    assert "**blocked** (agent)" in sec
    assert "claimed satisfied without evidence" in sec
    assert "inferred route" in json.dumps([e.summary for e in evs]) or \
        "route template" in json.dumps([w.result_summary for w in wos])


async def test_skill_state_survives_a_resume(
        client, user_token, session_maker, monkeypatch, spa_server):
    base = spa_server.url
    trace: dict = {}
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client",
                        lambda *a, **kw: FakeClient(skill_agent(trace)))
    t = await create_target(client, user_token, name="spa-skills-resume", base_url=base,
                            model_backend="fake",
                            limits={**LIMITS, "max_requests": 12},
                            account_ids=await _accounts(client, user_token))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    async with session_maker() as s:
        assert (await s.get(GreyboxRun, run_id)).end_reason in (
            "budget_requests", "budget_exhausted")
    r = await client.post(f"/greybox/runs/{run_id}/resume", headers=h(user_token),
                          json={"max_requests": 600})
    assert r.status_code == 202, r.text
    trace["prompts"].clear()
    assert str(await run_worker_once(session_maker)) == str(run_id)

    # the first prompt after the resume already has the skill active
    _, user, k = trace["prompts"][0]
    assert [s["name"] for s in k["skills"]["loaded"]] == ["api-recon"]
    assert "### skill: api-recon" in user
    wos = await _rows(session_maker, run_id, GreyboxWorkOrder)
    assert len([w for w in wos if w.tool == "skill.read"]) == 1     # never re-loaded
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
    assert run.status == "succeeded" and "api-recon" in run.coverage_verdict["skills"]
