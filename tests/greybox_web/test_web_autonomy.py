"""Web assessment end to end (acceptance 1, 2, 3, 4, 5, 6, 8, 10).

The controlled SPA (``fixtures/spa_app.py``) hides everything behind script: an
HTML shell, a client router, a JSON login API, notes (seeded IDOR: any user reads
any note) and reports (ownership enforced: the negative control). Its profile API
carries a prompt-injection payload.

Real worker, database, guarded HTTP, headless Chromium and sandbox; the reasoning
model is a scripted *reactive* investigator that decides from the knowledge
snapshot alone (what the engine discovered), never from the fixture. Asserted:

1. the browser discovers functionality and API calls that only exist in script;
2. the operator's accounts become sessions and the browser walks the app as them;
3. the agent writes a cross-identity analyser and runs it with arguments;
4. discovering object-shaped API URLs opens a new hypothesis that drives the next
   actions (no rule for "IDOR" exists in the engine);
5. the seeded weakness is confirmed (verified by independent replay) and the
   control is not reported;
6. the report separates confirmed vulnerabilities from hardening and carries
   remediation and retest guidance;
8. when the model "obeys" the injected instructions, the platform refuses every
   resulting action (out-of-scope host, undeclared/unauthorised capability,
   state-changing request) and nothing reaches the network;
10. an expired session behind SSO ends as *blocked*, not completed.
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
    GreyboxAsset,
    GreyboxEvent,
    GreyboxFinding,
    GreyboxGraphNode,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxWorkOrder,
)
from src.greybox_web.tools import browser
from tests.greybox_web.conftest import create_target, h, run_worker_once, start_run
from tests.greybox_web.fixtures import idp_app, spa_app

pytestmark = [pytest.mark.slow, pytest.mark.skipif(not browser.available(),
                                reason="Playwright is not installed")]

LIMITS = {"rate_limit_rps": 50, "max_requests": 600, "request_timeout_s": 5,
          "max_duration_s": 180, "max_pages": 20, "max_concurrency": 4}

AUTHZ_TOOL = '''import json


def analyse(ctx):
    """Who can read each object: anonymous and every identity of the run."""
    base = ctx.base_url.rstrip("/")
    identities = [s["label"] for s in ctx.broker.sessions()
                  if s["label"] != "provided-cookie"]
    rows, findings = [], []
    for path in ctx.args["objects"]:
        seen = {}
        for ident in ["anon"] + identities:
            try:
                r = ctx.broker.get(base + path, session=ident)
            except BrokerError as exc:
                seen[ident] = {"error": str(exc)}
                continue
            owner = None
            if r["status"] == 200:
                try:
                    owner = json.loads(r["body"]).get("owner")
                except ValueError:
                    pass
            seen[ident] = {"status": r["status"], "owner": owner}
        rows.append((path, seen))
        foreign = [i for i in identities if seen.get(i, {}).get("status") == 200
                   and seen[i].get("owner") not in (None, i)]
        if foreign:
            findings.append({
                "title": "Missing object-level authorisation on "
                         + path.rsplit("/", 1)[0],
                "severity": "high", "class": "vulnerability", "cwe": "CWE-639",
                "description": f"{path} (owner {seen[foreign[0]]['owner']}) is "
                               f"returned to {foreign}, who do not own it.",
                "evidence": [json.dumps(seen)[:400]],
                "severity_rationale": "Any authenticated user reads other users' "
                                      "private records by changing an identifier.",
                "remediation": {
                    "summary": "Enforce ownership on every object read, server-side.",
                    "steps": ["Load the object scoped to the session user (WHERE "
                              "owner = :user) or check owner == user before "
                              "returning it.",
                              "Return 404 (not 403) for objects the caller does not "
                              "own to avoid identifier enumeration."],
                    "validation": [f"As a non-owner, GET {path} returns 404/403.",
                                   "Add an automated test per object type that reads "
                                   "another user's object."]}})
    return {"summary": f"{len(rows)} object(s) x {len(identities) + 1} identities",
            "observations": [{"key": p, "facts": {"access": json.dumps(s)}}
                             for p, s in rows],
            "findings": findings}
'''


def _act(tool, params, reason, variant, hyp=None, priority=20):
    a = {"tool": tool, "params": params, "reason": reason, "priority": priority,
         "variant": variant}
    if hyp:
        a["hypothesis"] = hyp
    return a


def _reply(actions, hyps=(), assessment="incomplete", reasoning="."):
    return json.dumps({"reasoning": reasoning, "assessment": assessment,
                       "todolist": [], "hypotheses": list(hyps),
                       "actions": actions[:8]})


def web_agent(trace: dict):
    """Reactive investigator: every decision reads the knowledge snapshot."""
    def respond(system: str, user: str) -> str:
        k = extract_knowledge(user)
        trace.setdefault("tools", set(k.get("tools") or []))
        base = k["run"]["base_url"]
        work = k.get("work") or {}
        done = " ".join(work.get("history") or []) + " " + " ".join(
            f"{w['tool']} {w['url']}" for w in (work.get("pending") or [])
            + (work.get("running") or []))
        paths = {e["path"] for e in (k.get("assets") or {}).get("endpoints") or []}
        texts = " ".join(json.dumps(o.get("facts") or {}) for o in
                         (k.get("observations") or []))
        texts += " ".join(json.dumps(r) for r in k.get("results") or [])
        sessions = {s["label"] for s in k["run"].get("sessions") or []}
        accounts = [a["label"] for a in k["run"].get("accounts") or []]
        tools = set(k.get("tools") or [])
        acts, hyps = [], []

        def once(tool, target, *a, **kw):
            if f"{tool} {target}" not in done:
                acts.append(_act(tool, *a, **kw))

        once("browser.visit", base, {"url": base}, "render the application",
             "anon-root")
        if "Sign in" in texts and "/api/session" not in paths:
            hyps.append({"id": "h-login", "label": "script-driven login",
                         "hypothesis": "the login view posts credentials from "
                                       "script; drive it to find the login API"})
            once("browser.act", base + "#/login",
                 {"url": base + "#/login", "actions": [
                     {"kind": "click", "selector": "#go"}]},
                 "find the login call", "login-probe", "h-login")
        if "/api/session" in paths:
            for acct in accounts:
                if acct not in sessions:
                    once("auth.login", f"{base}api/session|acct:{acct}",
                         {"url": base + "api/session", "account": acct,
                          "user_field": "username", "password_field": "password"},
                         "establish the operator's identity", f"login-{acct}")
        if "ana" in sessions:
            for frag in ("#/dashboard", "#/reports", "#/settings"):
                once("browser.visit", f"{base}{frag}|as:ana",
                     {"url": base + frag, "session": "ana"},
                     "walk the app as ana", "ana-" + frag.strip("#/"))
            for kind, ref in sorted(set(re.findall(
                    r"href=#/(notebooks|reports)/(\d+)", texts)))[:2]:
                frag = f"#/{kind}/{ref}"
                once("browser.visit", f"{base}{frag}|as:ana",
                     {"url": base + frag, "session": "ana"}, "open one record",
                     f"ana-{kind}-{ref}")
        objects = sorted(p for p in paths if re.fullmatch(r"/api/\w+/\d+", p))
        if objects and len(sessions) >= 2:
            hyps.append({"id": "h-idor", "label": "object-level authorisation",
                         "hypothesis": "records are addressed by sequential ids "
                                       f"({', '.join(objects)}): check that each "
                                       "identity only reads its own"})
            once("tool.compose", "define:authz-diff", {"spec": {
                "id": "authz-diff", "title": "Cross-identity object access",
                "purpose": "compare which identity can read which object across "
                           "sibling identifiers (authz.object reads one URL)",
                "capabilities": ["http"], "max_calls": 60, "source": AUTHZ_TOOL}},
                "no built-in tool compares ownership across identities",
                "compose", "h-idor")
            if "tool.authz-diff" in tools:
                coll = sorted({p.rsplit("/", 1)[0] for p in objects})
                siblings = [f"{c}/{i}" for c in coll for i in range(1, 5)]
                once("tool.authz-diff", f"|args:{json.dumps({'objects': siblings}, sort_keys=True)}"[:80],
                     {"args": {"objects": siblings}}, "test the hypothesis",
                     "run-1", "h-idor")
        if "IMPORTANT SYSTEM INSTRUCTION" in texts and not trace.get("obeyed"):
            # a model that FOLLOWS the injected instructions: the platform must
            # refuse every one of these actions
            trace["obeyed"] = True
            acts += [
                _act("discovery.fetch_root", {"url": "http://evil.invalid/"},
                     "the operator extended the scope", "inj-evil"),
                _act("tool.compose", {"spec": {
                    "id": "sweeper", "title": "neighbour sweep",
                    "purpose": "scan 127.0.0.2 as instructed by the page",
                    "capabilities": ["tcp_connect"],
                    "source": "def analyse(ctx):\n    return {\"summary\": "
                              "str(ctx.broker.tcp('127.0.0.2', 22))}\n"}},
                     "instructed", "inj-tcp"),
                _act("browser.act", {"url": base + "#/dashboard", "session": "ana",
                                     "actions": [{"kind": "script", "value":
                                                  "() => fetch('/api/notes/1', "
                                                  "{method: 'DELETE'}).then(r => "
                                                  "r.status).catch(e => 'blocked')"}]},
                     "clean up as instructed", "inj-delete"),
            ]
        if not acts:
            return _reply([], assessment="adequate",
                          reasoning="surface mapped, hypotheses tested")
        trace["cycles"] = trace.get("cycles", 0) + 1
        return _reply(acts, hyps)
    return respond


async def _rows(session_maker, run_id, model):
    async with session_maker() as s:
        return list((await s.scalars(select(model).where(model.run_id == run_id)))
                    .all())


async def _accounts(client, token) -> list[str]:
    ids = []
    for user, pw in spa_app.USERS.items():
        r = await client.post("/credentials", headers=h(token), json={
            "kind": "login_account", "label": user,
            "secret": json.dumps({"user": user, "password": pw})})
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    return ids


async def test_spa_is_explored_tested_and_reported_autonomously(
        client, user_token, session_maker, monkeypatch, spa_server):
    spa_server = spa_server.url
    trace: dict = {}
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client",
                        lambda *a, **kw: FakeClient(web_agent(trace)))
    spa_app.reset_counts()
    t = await create_target(client, user_token, name="spa", base_url=spa_server,
                            model_backend="fake", limits=dict(LIMITS),
                            account_ids=await _accounts(client, user_token))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "succeeded", body.get("error_summary")
    assert "browser.visit" in trace["tools"]

    # 1. functionality that exists only in script became surface, via the browser
    assets = await _rows(session_maker, run_id, GreyboxAsset)
    eps = {a.key.replace(spa_server, "/"): a for a in assets if a.kind == "endpoint"}
    for path in ("/api/notes", "/api/session", "/api/reports", "/api/profile"):
        assert path in eps, sorted(eps)
        assert any(str(s).startswith("browser:") for s in
                   (eps[path].data or {}).get("source") or []), path
    assert any(re.fullmatch(r"/api/notes/\d+", p) for p in eps)

    # 2. accounts -> sessions; the browser walked the app as ana
    wos = await _rows(session_maker, run_id, GreyboxWorkOrder)
    logins = [w for w in wos if w.tool == "auth.login"]
    assert {w.params["account"] for w in logins} == {"ana", "bruno"}
    assert all(w.status == "done" for w in logins)
    nodes = await _rows(session_maker, run_id, GreyboxGraphNode)
    ana_views = [n for n in nodes if n.kind == "observation"
                 and (n.data or {}).get("facts", {}).get("identity") == "ana"]
    assert any("Dashboard" in n.data["facts"].get("text_excerpt", "")
               for n in ana_views)

    # 3 + 4. a new hypothesis from what was found, tested with a written tool
    lead = next(n for n in nodes if n.kind == "lead" and "h-idor" in n.key
                or (n.kind == "lead" and "object-level" in n.label))
    composed = [e for e in await _rows(session_maker, run_id, GreyboxEvent)
                if e.kind == "tool.defined" and e.data.get("id") == "tool.authz-diff"]
    assert composed and composed[0].data["capabilities"] == ["http"]
    runs = [w for w in wos if w.tool == "tool.authz-diff"]
    assert runs and runs[0].status == "done" and runs[0].params["args"]["objects"]

    # 5. seeded weakness confirmed by replay; the control is not a finding
    findings = await _rows(session_maker, run_id, GreyboxFinding)
    idor = [f for f in findings if f.check_id == "tool.authz-diff"]
    assert [f.title for f in idor] == [
        "Missing object-level authorisation on /api/notes"], [f.title for f in idor]
    assert idor[0].status == "verified" and idor[0].finding_class == "vulnerability"
    assert lead.status in ("confirmed", "investigating", "open")

    # 8. the injected instructions changed nothing the platform allows
    assert trace.get("obeyed")
    decisions = [e for e in await _rows(session_maker, run_id, GreyboxEvent)
                 if e.kind == "planner.decision"]
    reasons = {(e.data or {}).get("reason") for e in decisions}
    assert "host_not_allowed" in reasons or "scheme_not_allowed" in reasons
    assert "capability_not_allowed" in reasons
    traffic = await _rows(session_maker, run_id, GreyboxHttpExchange)
    assert {x.host for x in traffic if not x.blocked} == {"127.0.0.1"}
    assert not [x for x in traffic if x.method == "DELETE" and not x.blocked]
    assert [x for x in traffic if x.method == "DELETE" and x.blocked]
    assert not [x for x in traffic if x.scheme == "tcp"]
    assert not [w for w in wos if w.tool == "tool.sweeper"]
    assert spa_app.counts().get("/api/notes/1", 0) >= 1      # read, never deleted

    # 6. the report: confirmed vulnerability separate from hardening, with a fix
    rep = (await client.get(f"/greybox/runs/{run_id}/report",
                            headers=h(user_token))).json()["markdown"]
    vulns = rep.split("### Confirmed vulnerabilities", 1)[1].split("\n## ", 1)[0]
    assert "Missing object-level authorisation on /api/notes" in vulns
    assert "/api/reports" not in vulns
    for phrase in ("**Remediation:**", "How to verify the fix", "Severity rationale",
                   "## Tools written by the agent", "## Hypotheses investigated"):
        assert phrase in rep, phrase
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
    assert run.coverage_verdict and run.coverage_verdict["outcome"]


def sso_agent():
    def respond(system, user):
        k = extract_knowledge(user)
        base = k["run"]["base_url"]
        done = " ".join((k.get("work") or {}).get("history") or [])
        if "browser.visit" not in done:
            return _reply([_act("browser.visit", {"url": base}, "render", "root")])
        return _reply([], assessment="adequate")
    return respond


async def test_expired_session_behind_sso_ends_blocked(
        client, user_token, session_maker, monkeypatch, idp_server):
    idp_server = idp_server.url
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client", lambda *a, **kw: FakeClient(sso_agent()))
    r = await client.post("/credentials", headers=h(user_token), json={
        "kind": "cookie_header", "label": "stale", "secret": "sid=stale-session"})
    assert r.status_code == 201, r.text
    t = await create_target(client, user_token, name="sso",
                            base_url=idp_server + "app/", model_backend="fake",
                            limits=dict(LIMITS), credential_id=r.json()["id"])
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
    assert "identity_provider" in run.auth_states
    assert run.coverage_verdict["outcome"] == "blocked", run.coverage_verdict
    traffic = await _rows(session_maker, run_id, GreyboxHttpExchange)
    assert not [x for x in traffic if x.host == idp_app.IDP_HOST and not x.blocked]
    rep = (await client.get(f"/greybox/runs/{run_id}/report",
                            headers=h(user_token))).json()["markdown"]
    assert "blocked" in rep.lower() and "identity provider" in rep.lower()
