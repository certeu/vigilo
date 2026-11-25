"""Identity persistence across a resume (sessionvault.py).

A run logs in as ``ana`` and walks the app in the browser as ana, then stops at its
request budget. Resumed, it must still BE ana — the session and the browser jar
come back (encrypted at rest, never in any API/event/report) — without a second
login. When the stored state is older than the configured maximum age it is not
restored, and the run says so.
"""
from __future__ import annotations

import json
import re
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web import sessionvault
from src.greybox_web.exploration.client import FakeClient
from src.greybox_web.exploration.knowledge import extract_knowledge
from src.greybox_web.models import GreyboxEvent, GreyboxRun, GreyboxWorkOrder
from src.greybox_web.tools import browser
from tests.greybox_web.conftest import create_target, h, run_worker_once, start_run
from tests.greybox_web.test_web_autonomy import LIMITS, _accounts, _act, _reply

pytestmark = [pytest.mark.slow, pytest.mark.skipif(not browser.available(),
                                reason="Playwright is not installed")]


def agent(trace: dict):
    trace.setdefault("knowledge", [])

    def respond(system, user):
        k = extract_knowledge(user)
        trace["knowledge"].append(k)
        base = k["run"]["base_url"]
        done = " ".join((k.get("work") or {}).get("history") or []) + " " + " ".join(
            f"{w['tool']} {w['url']}" for w in (k.get("work") or {}).get("pending") or [])
        sessions = {s["label"] for s in k["run"].get("sessions") or []}
        acts = []
        if "ana" not in sessions and f"auth.login {base}api/session|acct:ana" not in done:
            acts.append(_act("auth.login", {"url": base + "api/session", "account": "ana",
                                            "user_field": "username",
                                            "password_field": "password"},
                             "identity", "login-ana"))
        if "ana" in sessions:
            for frag in ("#/dashboard", "#/settings", "#/notebooks/1", "#/reports"):
                if f"browser.visit {base}{frag}|as:ana" not in done:
                    acts.append(_act("browser.visit", {"url": base + frag,
                                                       "session": "ana"},
                                     "walk as ana", "ana-" + frag.strip("#/")
                                     .replace("/", "-")))
                    break
        return _reply(acts) if acts else _reply([], assessment="adequate")
    return respond


async def _interrupted_run(client, token, session_maker, base, trace):
    t = await create_target(client, token, name="sess", base_url=base,
                            model_backend="fake", limits={**LIMITS, "max_requests": 9},
                            account_ids=await _accounts(client, token))
    r = await start_run(client, token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
    assert run.end_reason in ("budget_requests", "budget_exhausted"), run.end_reason
    assert run.session_vault and b"ana" not in run.session_vault     # encrypted
    r = await client.post(f"/greybox/runs/{run_id}/resume", headers=h(token),
                          json={"max_requests": 200})
    assert r.status_code == 202, r.text
    assert "session_vault" not in json.dumps(r.json())
    trace["knowledge"].clear()
    return run_id


async def test_identities_survive_a_resume(client, user_token, session_maker,
                                           monkeypatch, spa_server):
    trace: dict = {}
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client", lambda *a, **kw: FakeClient(agent(trace)))
    run_id = await _interrupted_run(client, user_token, session_maker, spa_server.url,
                                    trace)
    assert str(await run_worker_once(session_maker)) == str(run_id)
    # the first resumed prompt already knows ana, and nobody logged in again
    assert "ana" in {s["label"] for s in trace["knowledge"][0]["run"]["sessions"]}
    async with session_maker() as s:
        wos = (await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run_id))).all()
        evs = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id))).all()
    assert len([w for w in wos if w.tool == "auth.login"]) == 1
    assert any((e.data or {}).get("decision") == "identities_restored" for e in evs)
    # the browser walked as ana after the resume and was let in
    texts = json.dumps([k.get("results") for k in trace["knowledge"]])
    assert "Settings" in texts or "Notebook" in texts or "Reports" in texts
    # the secret never appears in events
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
    blob = json.dumps([[e.kind, e.data] for e in evs], default=str)
    leaks = [m.group(0) for m in re.finditer(r".{60}ana:[0-9a-f]{6,}.{20}", blob)]
    assert not leaks, leaks[:3]
    assert run.status == "succeeded"


async def test_stale_identities_are_not_restored(client, user_token, session_maker,
                                                 monkeypatch, spa_server):
    trace: dict = {}
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client", lambda *a, **kw: FakeClient(agent(trace)))
    run_id = await _interrupted_run(client, user_token, session_maker, spa_server.url,
                                    trace)
    monkeypatch.setenv(sessionvault.MAX_AGE_ENV, "0")
    assert str(await run_worker_once(session_maker)) == str(run_id)
    assert "ana" not in {s["label"] for s in trace["knowledge"][0]["run"]["sessions"]}
    async with session_maker() as s:
        evs = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id))).all()
    note = [e for e in evs if (e.data or {}).get("decision") == "identities_not_restored"]
    assert note and "expired" in note[0].summary
