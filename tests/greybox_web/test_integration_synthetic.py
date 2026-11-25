"""M2 end-to-end integration against the live synthetic target.

One full default run (real worker, real HTTP over 127.0.0.1) is executed per
test through the ``full_run`` fixture and asserted against the persisted
``greybox_events`` for every event invariant plus the acceptance criteria at the
API level. A second scenario points a target at a closed local port and
observes the preflight failure path. Only 127.0.0.1 is ever requested.
"""
from __future__ import annotations

import socket
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from src.greybox_web.models import (
    GreyboxAsset, GreyboxEvent, GreyboxFinding, GreyboxHttpExchange, GreyboxRun,
    GreyboxWorkOrder,
)
from tests.greybox_web.conftest import (
    create_target, h, run_worker_once, start_run,
)

TERMINAL = ("run.completed", "run.failed", "run.cancelled")
ENVELOPE = ("seq", "run_id", "ts", "kind", "level", "source", "agent_id",
            "agent_name", "work_order_id", "tool_call_id", "summary", "status",
            "duration_ms", "refs", "data")
REF_KEYS = ("node_ids", "asset_ids", "finding_id", "exchange_ids")
STATUSES = {"ok", "error", "blocked", "pending", "skipped", "cancelled", None}
SOURCES = {"system", "planner", "agent", "api"}
LEVELS = {"debug", "info", "warning", "error"}

# kind -> (allowed sources, level or None, status or None, required data keys)
KIND_RULES = {
    "run.queued": ({"api"}, "info", "pending",
                   {"target_id", "base_url", "scope_summary", "limits", "checks",
                    "initiated_by"}),
    "run.started": ({"system"}, "info", "ok", {"worker", "attempt"}),
    "run.phase": ({"system"}, "info", "ok", {"from", "to"}),
    "run.completed": ({"system"}, "info", "ok",
                      {"end_reason", "duration_ms", "requests_made", "findings"}),
    "run.failed": ({"system"}, "error", "error", {"reason", "error"}),
    "planner.decision": ({"planner"}, "info", "ok",
                         {"decision", "reason", "work_order_ids", "considered"}),
    "llm.request": ({"agent"}, "info", "pending", {"trigger", "cycle", "attempt"}),
    "llm.response": ({"agent"}, "info", "ok",
                     {"cycle", "reasoning", "assessment", "actions", "hypotheses"}),
    "agent.started": ({"agent"}, "info", "ok", {"role", "name"}),
    "agent.finished": ({"agent"}, "info", "ok",
                       {"work_orders_done", "work_orders_failed"}),
    "work_order.created": ({"planner"}, "info", "pending",
                           {"kind", "tool", "title", "reason", "asset_id",
                            "parent_node_id", "priority"}),
    "work_order.claimed": ({"agent"}, "info", "ok", {"attempt"}),
    "work_order.completed": ({"agent"}, "info", "ok", {"result_summary"}),
    # a work order can legitimately fail (tool error, sandbox refusal); the run
    # carries on. The kind must be known, with its error and attempt.
    "work_order.failed": ({"agent"}, "error", "error", {"error", "attempt"}),
    "work_order.skipped": ({"planner"}, "info", "skipped", {"reason"}),
    "tool.started": ({"agent"}, "info", "pending", {"tool", "args"}),
    "tool.succeeded": ({"agent"}, "info", "ok", {"tool", "result"}),
    "tool.failed": ({"agent"}, "error", "error", {"tool", "error"}),
    "http.exchange": ({"agent"}, "debug", None,
                      {"exchange_id", "method", "url", "status_code",
                       "duration_ms", "redirect_hop"}),
    "observation.recorded": ({"agent"}, "info", "ok",
                             {"node_id", "observation", "facts"}),
    "asset.discovered": ({"agent"}, "info", "ok",
                         {"asset_id", "kind", "key", "in_scope"}),
    "graph.updated": ({"system"}, "debug", "ok",
                      {"version", "nodes", "edges", "assets", "asset_edges",
                       "max_created_version"}),
    "surface.updated": ({"agent"}, "debug", "ok",
                        {"asset_id", "kind", "risk_score", "changed"}),
    "finding.created": ({"agent"}, "warning", "pending",
                        {"finding_id", "title", "severity", "check_id", "status"}),
    "finding.verified": ({"agent"}, "warning", "ok",
                         {"finding_id", "method", "exchange_ids"}),
    "defense.proposed": ({"agent"}, "info", "ok",
                         {"defense_id", "finding_id", "kind", "format", "title"}),
    "report.started": ({"agent"}, "info", "pending", set()),
    "report.ready": ({"agent"}, "info", "ok", {"bytes"}),
    "auth.state": ({"agent"}, "warning", "blocked",
                   {"url", "state", "provider", "detail"}),
    # info when a declarative instrument is defined, warning when the agent authors
    # code for the sandbox (Phase 3): that one is worth an operator's attention
    "tool.defined": ({"planner"}, {"info", "warning"}, "ok",
                     {"id", "kind", "title", "param_keys"}),
    "coverage.verdict": ({"system"}, {"info", "warning"}, "ok",
                         {"outcome", "reasons", "limitations"}),
}


async def _events(session_maker, run_id) -> list[GreyboxEvent]:
    async with session_maker() as s:
        return list((await s.scalars(
            select(GreyboxEvent).where(GreyboxEvent.run_id == uuid.UUID(run_id))
            .order_by(GreyboxEvent.seq))).all())


async def _count(session_maker, model, run_id) -> int:
    async with session_maker() as s:
        return (await s.scalar(select(func.count()).select_from(model).where(
            model.run_id == uuid.UUID(run_id)))) or 0


@pytest.fixture
async def full_run(client, user_token, session_maker, live_target, target_server):
    key = uuid.uuid4().hex
    r = await start_run(client, user_token, live_target["id"], key=key)
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    assert str(await run_worker_once(session_maker)) == run_id
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    return SimpleNamespace(id=run_id, key=key, body=body, target=live_target,
                           events=await _events(session_maker, run_id))


# ------------------------------------------------------------ 8.3 invariants


async def test_invariant_seq_starts_at_1_and_is_contiguous(full_run):
    seqs = [e.seq for e in full_run.events]
    assert seqs == list(range(1, len(seqs) + 1))
    assert full_run.body["last_seq"] == seqs[-1]
    assert full_run.body["counters"]["events"] == seqs[-1]


async def test_invariant_first_event_is_run_queued(full_run):
    assert full_run.events[0].kind == "run.queued"
    assert [e.kind for e in full_run.events].count("run.queued") == 1


async def test_invariant_exactly_one_terminal_event_and_it_is_last(full_run):
    terminals = [e for e in full_run.events if e.kind in TERMINAL]
    assert len(terminals) == 1
    assert terminals[0].seq == max(e.seq for e in full_run.events)
    assert full_run.events[-1] is terminals[0]
    assert terminals[0].kind == "run.completed"


async def test_invariant_no_exchange_after_terminal_event(full_run, session_maker):
    terminal = full_run.events[-1]
    async with session_maker() as s:
        n = await s.scalar(select(func.count()).select_from(GreyboxHttpExchange)
                           .where(GreyboxHttpExchange.run_id == uuid.UUID(full_run.id),
                                  GreyboxHttpExchange.ts > terminal.ts))
    assert n == 0


async def test_invariant_every_tool_started_has_exactly_one_outcome(full_run):
    started, outcomes = {}, {}
    for e in full_run.events:
        if e.kind == "tool.started":
            assert e.tool_call_id, "tool.started without tool_call_id"
            assert e.tool_call_id not in started
            started[e.tool_call_id] = e
        elif e.kind in ("tool.succeeded", "tool.failed"):
            assert e.tool_call_id
            outcomes.setdefault(e.tool_call_id, []).append(e)
    assert started, "the run executed no tools"
    assert set(outcomes) == set(started)
    for tc, evs in outcomes.items():
        assert len(evs) == 1, f"{tc}: {[x.kind for x in evs]}"
        assert evs[0].seq > started[tc].seq
        assert evs[0].data["tool"] == started[tc].data["tool"]


async def test_invariant_persisted_envelope_and_refs_always_present(full_run):
    for e in full_run.events:
        assert e.run_id == uuid.UUID(full_run.id)
        assert e.ts is not None and e.summary
        assert e.source in SOURCES and e.level in LEVELS
        assert e.status in STATUSES
        assert isinstance(e.data, dict)
        for k in REF_KEYS:
            assert k in e.refs, f"{e.kind} refs lacks {k}"
        for k in ("node_ids", "asset_ids", "exchange_ids"):
            assert isinstance(e.refs[k], list), (e.kind, k)


async def test_invariant_envelope_via_events_api(full_run, client, user_token):
    r = await client.get(f"/greybox/runs/{full_run.id}/events", headers=h(user_token),
                         params={"limit": 1000})
    assert r.status_code == 200
    items = r.json()["items"]
    for it in items:
        for f in ENVELOPE:
            assert f in it, f"{it['kind']} lacks envelope field {f}"
        for k in REF_KEYS:
            assert k in it["refs"]
        assert (it["agent_name"] is None) == (it["agent_id"] is None)


async def test_invariant_per_kind_source_level_status_and_data_shape(full_run):
    seen = set()
    for e in full_run.events:
        assert e.kind in KIND_RULES, e.kind
        rule = KIND_RULES.get(e.kind)
        if rule is None:
            continue
        seen.add(e.kind)
        sources, level, status, keys = rule
        assert e.source in sources, (e.kind, e.source)
        if level:
            allowed_levels = {level} if isinstance(level, str) else level
            assert e.level in allowed_levels, (e.kind, e.level)
        if status:
            assert e.status == status, (e.kind, e.status)
        missing = keys - set(e.data)
        assert not missing, f"{e.kind} data lacks {missing}: {e.data}"
    for kind in ("run.queued", "run.started", "run.phase", "run.completed",
                 "planner.decision", "work_order.created", "work_order.claimed",
                 "work_order.completed", "tool.started", "tool.succeeded",
                 "http.exchange", "asset.discovered", "finding.verified",
                 "report.ready"):
        assert kind in seen, f"no {kind} event in a full run"


async def test_invariant_phases_in_order_and_exchange_events_match_rows(full_run,
                                                                        session_maker):
    phases = [e.data["to"] for e in full_run.events if e.kind == "run.phase"]
    assert phases[0] == "discovery"
    assert phases[-1] == "reporting"       # set when the final report is written
    # the current activity, not a fixed sequence: "planning" = waiting for the AI
    assert set(phases) <= {"discovery", "checks", "verification", "planning",
                           "reporting"}
    ex_events = {e.data["exchange_id"] for e in full_run.events
                 if e.kind == "http.exchange"}
    async with session_maker() as s:
        ids = set((await s.scalars(select(GreyboxHttpExchange.id).where(
            GreyboxHttpExchange.run_id == uuid.UUID(full_run.id)))).all())
    assert ex_events <= ids


async def test_invariant_no_registered_secret_in_events(full_run):
    # no credential was registered for this run; the engine must still never
    # leak platform secrets or auth material into any event text. The needles
    # match VALUES (the fixture's token format), not header names: a masked
    # "set-cookie: session=***" is exactly what SHOULD appear.
    blob = "\n".join(f"{e.summary} {e.data}" for e in full_run.events).lower()
    for needle in ("authorization: bearer", "test-secret", "session=sess-",
                   "authorization: eyj"):
        assert needle not in blob


# ------------------------------------------------------------ M2 acceptance


async def test_run_succeeds_and_counters_agree_with_db(full_run, session_maker):
    b = full_run.body
    assert b["status"] == "succeeded", b.get("error_summary")
    assert b["end_reason"] == "completed"
    assert b["report_status"] == "ready"
    assert b["finished_at"] is not None
    c = b["counters"]
    assert c["requests"] > 10
    async with session_maker() as s:
        rid = uuid.UUID(full_run.id)
        run = await s.get(GreyboxRun, rid)
        assert c["requests"] == run.requests_made
        assert c["requests_blocked"] == run.requests_blocked
        n_ex = await s.scalar(select(func.count()).select_from(GreyboxHttpExchange)
                              .where(GreyboxHttpExchange.run_id == rid))
        assert n_ex >= run.requests_made
        n_blocked = await s.scalar(select(func.count()).select_from(GreyboxHttpExchange)
                                   .where(GreyboxHttpExchange.run_id == rid,
                                          GreyboxHttpExchange.blocked.is_(True)))
        assert n_blocked == run.requests_blocked
        assert c["assets"] == await s.scalar(select(func.count()).select_from(
            GreyboxAsset).where(GreyboxAsset.run_id == rid))
        wo = dict((await s.execute(
            select(GreyboxWorkOrder.status, func.count()).where(
                GreyboxWorkOrder.run_id == rid).group_by(GreyboxWorkOrder.status))).all())
        for st in ("pending", "running", "done", "failed", "skipped", "cancelled"):
            assert c["work_orders"][st] == wo.get(st, 0), st
        verified = await s.scalar(select(func.count()).select_from(GreyboxFinding)
                                  .where(GreyboxFinding.run_id == rid,
                                         GreyboxFinding.status == "verified"))
        assert verified >= 4
        completed = full_run.events[-1].data
        assert completed["findings"]["verified"] == verified
        assert completed["requests_made"] == run.requests_made
    assert c["work_orders"]["pending"] == 0 and c["work_orders"]["running"] == 0
    assert c["agents_active"] == 0


async def test_run_findings_counts_match_db(full_run, session_maker):
    async with session_maker() as s:
        rows = (await s.execute(
            select(GreyboxFinding.status, func.count()).where(
                GreyboxFinding.run_id == uuid.UUID(full_run.id))
            .group_by(GreyboxFinding.status))).all()
    expected = dict(rows)
    f = full_run.body["findings"]
    for st in ("verified", "candidate", "rejected"):
        assert f[st] == expected.get(st, 0), st


async def test_report_ready_via_api(full_run, client, user_token):
    r = await client.get(f"/greybox/runs/{full_run.id}/report", headers=h(user_token))
    assert r.status_code == 200
    assert r.json()["status"] == "ready" and r.json()["markdown"]


async def test_same_idempotency_key_returns_same_run_no_second_row(
        full_run, client, user_token, session_maker):
    r = await start_run(client, user_token, full_run.target["id"], key=full_run.key)
    assert r.status_code == 200
    assert r.json()["id"] == full_run.id
    async with session_maker() as s:
        n = await s.scalar(select(func.count()).select_from(GreyboxRun).where(
            GreyboxRun.target_id == uuid.UUID(full_run.target["id"])))
    assert n == 1


async def test_new_key_while_active_is_409_with_run_id(client, user_token,
                                                      live_target, session_maker):
    r1 = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex)
    assert r1.status_code == 201
    r2 = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex)
    assert r2.status_code == 409
    assert r2.json()["run_id"] == r1.json()["id"]
    assert r2.json()["detail"] == "A run for this target is already active"
    async with session_maker() as s:
        n = await s.scalar(select(func.count()).select_from(GreyboxRun))
    assert n == 1


async def test_every_exchange_host_is_loopback_and_in_scope(full_run, session_maker,
                                                            target_server):
    async with session_maker() as s:
        rows = (await s.execute(select(GreyboxHttpExchange.host,
                                       GreyboxHttpExchange.blocked,
                                       GreyboxHttpExchange.url).where(
            GreyboxHttpExchange.run_id == uuid.UUID(full_run.id)))).all()
    assert rows
    assert {r.host for r in rows} == {"127.0.0.1"}, {r.url for r in rows
                                                     if r.host != "127.0.0.1"}


# ------------------------------------------------------------ failure path


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def test_unreachable_target_fails_with_preflight_reason(
        client, user_token, session_maker):
    from tests.greybox_web.conftest import FAST_LIMITS
    port = _closed_port()
    t = await create_target(client, user_token, base_url=f"http://127.0.0.1:{port}/",
                            limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    assert str(await run_worker_once(session_maker)) == run_id

    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "failed"
    assert body["end_reason"] == "error"      # 4.4 enumeration; preflight is the event reason
    assert body["error_summary"]

    evs = await _events(session_maker, run_id)
    assert [e.seq for e in evs] == list(range(1, len(evs) + 1))
    assert evs[0].kind == "run.queued"
    terminals = [e for e in evs if e.kind in TERMINAL]
    assert len(terminals) == 1 and evs[-1] is terminals[0]
    assert terminals[0].kind == "run.failed"
    assert terminals[0].level == "error" and terminals[0].status == "error"
    assert terminals[0].data["reason"] == "preflight"
    # readable for the user, not a transport code (UI e2e finding)
    assert body["error_summary"].startswith("Target unreachable: could not connect to ")
    assert "connect_error" not in body["error_summary"]
    assert terminals[0].data["error"]
    assert any(e.level == "error" for e in evs)       # an error event was recorded
    assert not any(e.kind == "run.completed" for e in evs)

    async with session_maker() as s:
        hosts = set((await s.scalars(select(GreyboxHttpExchange.host).where(
            GreyboxHttpExchange.run_id == uuid.UUID(run_id)))).all())
        codes = set((await s.scalars(select(GreyboxHttpExchange.status_code).where(
            GreyboxHttpExchange.run_id == uuid.UUID(run_id)))).all())
    assert hosts <= {"127.0.0.1"}
    assert codes <= {None}


async def test_verification_work_orders_state_their_outcome(full_run):
    done = [e for e in full_run.events
            if e.kind == "work_order.completed" and e.summary.startswith("verify.")]
    assert done, "the run verified at least one finding"
    for e in done:
        assert (e.data["result_summary"].startswith(("confirmed:", "not reproduced:"))), e.data
        assert e.refs.get("finding_id"), e.refs
    verified = [e for e in full_run.events if e.kind == "finding.verified"]
    assert verified and all(e.data.get("title") and e.data.get("severity")
                            for e in verified)
    created = [e for e in full_run.events if e.kind == "finding.created"]
    assert created and all(e.data.get("url") for e in created)


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
