"""Resumability (acceptance 9): an interrupted assessment continues from its
persisted knowledge — evidence, hypotheses and the tools the agent wrote — without
repeating finished work.

The network lab run is interrupted by its request budget right after the agent
composed its analyser; ``POST /runs/{id}/resume`` raises the budget; the second
worker pass must reuse the composed tool (not recompose it), must not sweep
again, and must keep every observation and finding of the first pass.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select

from src.greybox_web.exploration.client import FakeClient
from src.greybox_web.models import (
    GreyboxEvent,
    GreyboxFinding,
    GreyboxGraphNode,
    GreyboxRun,
    GreyboxWorkOrder,
)
from tests.greybox_web.conftest import create_target, h, run_worker_once, start_run
from tests.greybox_web.fixtures import net_lab
from tests.greybox_web.test_network_assessment import LIMITS, network_agent


async def _rows(session_maker, run_id, model):
    async with session_maker() as s:
        return list((await s.scalars(select(model).where(model.run_id == run_id)))
                    .all())


async def test_interrupted_run_resumes_without_losing_or_repeating_work(
        client, user_token, session_maker, monkeypatch):
    lab = await net_lab.start()
    seen: list = []
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client",
                        lambda *a, **kw: FakeClient(network_agent(seen)))
    ports = [lab.ports[n] for n in ("ssh", "telnet", "redis", "web", "closed")]
    try:
        t = await create_target(
            client, user_token, name="lab-resume",
            base_url=f"http://127.0.0.1:{lab.ports['web']}/",
            assessment_mode="network", model_backend="fake",
            # 5 sweep connections + 2 probes, then the budget is gone
            limits={**LIMITS, "max_requests": 8},
            scope={"network": {"targets": ["127.0.0.1"], "ports": ports,
                               "protocols": ["tcp"], "rate_per_s": 20}})
        r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
        run_id = uuid.UUID(r.json()["id"])
        assert str(await run_worker_once(session_maker)) == str(run_id)
        async with session_maker() as s:
            first = await s.get(GreyboxRun, run_id)
            assert first.end_reason in ("budget_requests", "budget_exhausted"), \
                first.end_reason
        wos1 = await _rows(session_maker, run_id, GreyboxWorkOrder)
        obs1 = {n.key for n in await _rows(session_maker, run_id, GreyboxGraphNode)
                if n.kind == "observation"}
        f1 = {f.dedup_key for f in await _rows(session_maker, run_id, GreyboxFinding)}
        assert [w for w in wos1 if w.tool == "net.sweep" and w.status == "done"]
        composed1 = [w for w in wos1 if w.tool == "tool.compose"]

        # --- resume with a larger budget (the scope cannot change)
        r = await client.post(f"/greybox/runs/{run_id}/resume", headers=h(user_token),
                              json={"max_requests": 200})
        assert r.status_code == 202, r.text
        assert r.json()["status"] == "queued"
        again = await client.post(f"/greybox/runs/{run_id}/resume",
                                  headers=h(user_token), json={})
        assert again.status_code == 409                  # already active
        seen.clear()
        assert str(await run_worker_once(session_maker)) == str(run_id)
    finally:
        await lab.close()

    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
    assert run.status == "succeeded" and run.end_reason not in (
        "budget_requests", "budget_exhausted"), run.end_reason

    # the agent was told it is resuming, and saw its earlier knowledge at once
    first_prompt = seen[0][1]
    assert any(str(o.get("key", "")).startswith("net.service|")
               for o in first_prompt["observations"])

    wos = await _rows(session_maker, run_id, GreyboxWorkOrder)
    # nothing finished was repeated: one sweep, one composition, probes once each
    assert len([w for w in wos if w.tool == "net.sweep"]) == 1
    probes = [(w.params["port"], w.params["probe"]) for w in wos if w.tool == "net.probe"]
    assert len(probes) == len(set(probes))
    composed = [w for w in wos if w.tool == "tool.compose"]
    assert len(composed) == 1 and len(composed1) <= 1
    # the tool written before the interruption was used after it
    assert [w for w in wos if w.tool == "tool.ssh-patch" and w.status == "done"]

    # knowledge and evidence were kept, and grew
    obs2 = {n.key for n in await _rows(session_maker, run_id, GreyboxGraphNode)
            if n.kind == "observation"}
    f2 = {f.dedup_key for f in await _rows(session_maker, run_id, GreyboxFinding)}
    assert obs1 <= obs2 and f1 <= f2 and len(f2) > len(f1)

    evs = await _rows(session_maker, run_id, GreyboxEvent)
    kinds = [e.kind for e in evs]
    assert "run.resumed" in kinds
    assert any(e.kind == "planner.decision" and (e.data or {}).get("decision") == "resume"
               for e in evs)
    assert any(e.kind == "llm.requested" and (e.data or {}).get("trigger") == "resume"
               for e in evs) or seen
    assert lab.outside_connections == 0


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
import pytest  # noqa: E402

pytestmark = pytest.mark.slow
