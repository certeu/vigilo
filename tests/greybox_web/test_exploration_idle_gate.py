"""Idle gate, cancellation and prompt-injection integration.

Real worker + supervisor + HTTP target on 127.0.0.1; only the model is scripted (the
supervisor's ``build_client`` is patched to return a scripted client). No real model
and no external host is ever contacted.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.exploration.client import AgentBudget, FakeClient, ModelClient
from src.greybox_web.exploration.explorer import Explorer
from src.greybox_web.exploration.proposer import LlmProposer
from src.greybox_web.models import (
    GreyboxEvent,
    GreyboxHttpExchange,
    GreyboxReport,
    GreyboxRun,
    GreyboxWorkOrder,
)
from tests.greybox_web.conftest import create_target, h, start_run
from tests.greybox_web.test_exploration_acceptance import (
    LIMITS,
    build_ticketing_api,
    serve,
)


def _reply(assessment="incomplete", actions=(), hypotheses=(), reasoning="scripted model reply"):
    return json.dumps({"reasoning": reasoning, "assessment": assessment,
                       "todolist": [], "hypotheses": list(hypotheses),
                       "actions": list(actions)})


@pytest.fixture
def agent_env(monkeypatch):
    from src.webapi.settings import get_settings
    monkeypatch.setenv("VIGILO_DEV_MODE", "true")
    monkeypatch.setenv("VIGILO_IGNORE_DOTENV", "1")      # never the real .env keys
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _patch_client(monkeypatch, client: ModelClient) -> None:
    import src.greybox_web.supervisor as sup
    monkeypatch.setattr(sup, "build_client", lambda *a, **kw: client)


async def _queue(client, token, url) -> uuid.UUID:
    t = await create_target(client, token, base_url=url, limits=dict(LIMITS),
                            model_backend="fake")
    r = await start_run(client, token, t["id"])
    assert r.status_code == 201, r.text
    return uuid.UUID(r.json()["id"])


async def _events(session_maker, run_id, kind):
    async with session_maker() as s:
        return list((await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id, GreyboxEvent.kind == kind)
            .order_by(GreyboxEvent.seq))).all())


def _decisions(evs):
    return [(e.data or {}).get("decision") for e in evs]


def _empty_rounds(evs):
    return [(e.data or {}).get("empty_rounds") for e in evs
            if (e.data or {}).get("decision") in ("explorer_no_work",
                                                   "coverage_challenge",
                                                   "explorer_exhausted")]


async def _run(session_maker, monkeypatch, client, user_token, fake):
    _patch_client(monkeypatch, fake)
    server, url = serve(build_ticketing_api())
    try:
        run_id = await _queue(client, user_token, url)
        from src.greybox_web.worker import run_once
        await asyncio.wait_for(run_once(session_maker), timeout=120)
    finally:
        server.should_exit = True
    return run_id


async def test_adequate_reply_completes_after_k_empty_rounds_and_is_reported(
        agent_env, monkeypatch, client, user_token, session_maker):
    from src.greybox_web.supervisor import EMPTY_ROUNDS_TO_COMPLETE as K
    fake = FakeClient(lambda s, u: _reply("adequate", reasoning="nothing is left to examine"))
    _patch_client(monkeypatch, fake)
    server, url = serve(build_ticketing_api())
    try:
        run_id = await _queue(client, user_token, url)
        from src.greybox_web.worker import run_once
        await asyncio.wait_for(run_once(session_maker), timeout=120)
    finally:
        server.should_exit = True
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "succeeded", run.end_reason
        report = await s.get(GreyboxReport, run_id)
    notes = await _events(session_maker, run_id, "planner.decision")
    decisions = _decisions(notes)
    assert "waiting_for_explorer" in decisions          # visible in Live Activity
    # one "adequate" verdict does not end the run: K fresh empty rounds do
    assert decisions.count("explorer_no_work") == K - 1
    assert decisions.count("explorer_exhausted") == 1
    assert _empty_rounds(notes) == list(range(1, K + 1))
    done = next(e for e in notes if e.data.get("decision") == "explorer_exhausted")
    assert f"explorer exhausted after {K} empty rounds" in done.summary
    assert f"{K} consecutive rounds" in report.markdown
    assert len(fake.calls) >= K                          # asked again each round
    assert len(fake.calls) <= 40                         # within the agent budget
    resp = await _events(session_maker, run_id, "llm.response")
    assert resp and all(isinstance((e.data or {}).get("cycle"), int) for e in resp)
    req = await _events(session_maker, run_id, "llm.request")
    assert req and all(isinstance((e.data or {}).get("cycle"), int) for e in req)


async def test_incomplete_without_actions_completes_not_loops(
        agent_env, monkeypatch, client, user_token, session_maker):
    from src.greybox_web.supervisor import EMPTY_ROUNDS_TO_COMPLETE as K
    fake = FakeClient(lambda s, u: _reply("incomplete"))
    _patch_client(monkeypatch, fake)
    server, url = serve(build_ticketing_api())
    try:
        run_id = await _queue(client, user_token, url)
        from src.greybox_web.worker import run_once
        await asyncio.wait_for(run_once(session_maker), timeout=120)
    finally:
        server.should_exit = True
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "succeeded", run.end_reason
    notes = await _events(session_maker, run_id, "planner.decision")
    decisions = _decisions(notes)
    assert "explorer_no_work" in decisions and "explorer_exhausted" in decisions
    assert _empty_rounds(notes) == list(range(1, K + 1))
    assert decisions.count("waiting_for_explorer") <= 8
    assert len(fake.calls) <= 40
    # the repeated idle prompts tell the model its last answer led nowhere
    assert "admitted no new work" in fake.calls[-1][1]


async def test_duplicate_only_proposals_complete_after_k_rounds(
        agent_env, monkeypatch, client, user_token, session_maker):
    """The model keeps proposing the same action: it is admitted once, then refused
    as a duplicate; each such idle round counts, and the run completes after K."""
    from src.greybox_web.exploration.knowledge import extract_knowledge
    from src.greybox_web.supervisor import EMPTY_ROUNDS_TO_COMPLETE as K

    def same(system, user):
        base = (extract_knowledge(user).get("run") or {}).get("base_url")
        return _reply("incomplete", actions=[
            {"tool": "discovery.fetch_root", "params": {"url": base},
             "reason": "look at the root", "priority": 10, "variant": "root"}])

    fake = FakeClient(same)
    run_id = await _run(session_maker, monkeypatch, client, user_token, fake)
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "succeeded", run.end_reason
        wos = (await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run_id))).all()
    assert len(wos) == 1                                 # admitted once
    notes = await _events(session_maker, run_id, "planner.decision")
    # Stopping depends on value, not silence alone: when the agent runs dry while
    # the coverage verdict is still partial, it is confronted ONCE with the reasons
    # (a coverage challenge), then the run ends after K more empty rounds.
    challenged = [e for e in notes if e.data.get("decision") == "coverage_challenge"]
    assert len(challenged) <= 1
    rounds = list(range(1, K + 1)) * (2 if challenged else 1)
    assert _empty_rounds(notes) == rounds
    assert {e.data.get("why") for e in notes
            if e.data.get("decision") == "explorer_exhausted"} == {"ok"}
    idle_prompts = [u for _s, u in fake.calls if "admitted no new work" in u]
    assert len(idle_prompts) == (K - 1) * (2 if challenged else 1)
    assert "discovery.fetch_root (root)" in idle_prompts[-1]
    if challenged:
        assert any("COVERAGE CHECK" in u for _s, u in fake.calls)


async def test_admitted_work_resets_the_empty_round_counter(
        agent_env, monkeypatch, client, user_token, session_maker):
    """After an empty round, a reply that admits new work resets the counter: the run
    then needs K fresh empty rounds again."""
    from src.greybox_web.exploration.knowledge import extract_knowledge
    from src.greybox_web.supervisor import EMPTY_ROUNDS_TO_COMPLETE as K
    state = {"revived": False}

    def script(system, user):
        if "admitted no new work" in user and not state["revived"]:
            state["revived"] = True
            base = (extract_knowledge(user).get("run") or {}).get("base_url")
            return _reply("incomplete", actions=[
                {"tool": "discovery.robots", "params": {"url": base},
                 "reason": "a new avenue", "priority": 10, "variant": "late"}])
        return _reply("adequate")

    fake = FakeClient(script)
    run_id = await _run(session_maker, monkeypatch, client, user_token, fake)
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "succeeded", run.end_reason
        wos = (await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run_id))).all()
    assert [w.tool for w in wos] == ["discovery.robots"]
    notes = await _events(session_maker, run_id, "planner.decision")
    assert _empty_rounds(notes) == [1, *range(1, K + 1)]


async def test_operator_message_resets_the_empty_round_counter(
        agent_env, monkeypatch, client, user_token, session_maker):
    """A message posted while the run is running out of ideas is new direction: the
    empty-round count starts over, the agent reads the message (or the platform
    answers it) and the run then needs K fresh empty rounds again."""
    from src.greybox_web import wakeup
    from src.greybox_web.models import GreyboxHint
    from src.greybox_web.supervisor import EMPTY_ROUNDS_TO_COMPLETE as K
    state: dict = {"posted": None}

    class Chatty(FakeClient):
        async def complete(self, system, user, **kw):
            if "admitted no new work" in user and state["posted"] is None:
                run = state["run_id"]
                async with session_maker() as s:
                    hint = GreyboxHint(
                        run_id=run, text="try the admin API", action="note",
                        status="open", work_order_ids=[], created_by=uuid.uuid4(),
                        created_by_name="op@example.test")
                    s.add(hint)
                    await s.commit()
                    state["posted"] = hint.id
                wakeup.notify(run)
            return await super().complete(system, user, **kw)

    def script(system, user):
        if "id=m1" in user:
            return json.dumps({**json.loads(_reply("adequate")),
                               "replies": [{"id": "m1", "reply": "Nothing left there."}]})
        return _reply("adequate")

    fake = Chatty(script)
    _patch_client(monkeypatch, fake)
    server, url = serve(build_ticketing_api())
    try:
        run_id = await _queue(client, user_token, url)
        state["run_id"] = run_id
        from src.greybox_web.worker import run_once
        await asyncio.wait_for(run_once(session_maker), timeout=120)
    finally:
        server.should_exit = True
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "succeeded", run.end_reason
        hint = await s.get(GreyboxHint, state["posted"])
    assert hint.status == "addressed" and hint.reply == "Nothing left there."
    assert hint.seen_cycle is not None and hint.reply_cycle == hint.seen_cycle
    notes = await _events(session_maker, run_id, "planner.decision")
    rounds = _empty_rounds(notes)
    # round 1; the message arrives during round 2's call, so that answer is not a
    # verdict and the count starts over: 1..K
    assert rounds == [1, *range(1, K + 1)], rounds
    assert "explorer_operator_message" in _decisions(notes)
    assert any("id=m1" in u for _s, u in fake.calls)
    replied = await _events(session_maker, run_id, "hint.replied")
    assert [e.data["by"] for e in replied] == ["agent"]


async def test_idle_cycle_is_never_quiet_and_flags_fresh_rounds(session_maker, run_id):
    """Unchanged knowledge suppresses a mid-flight call, never an idle one: the empty
    queue always gets a real (fresh) answer."""
    fake = FakeClient(lambda s, u: _reply("adequate"))
    ex = await _unit_explorer(session_maker, run_id, fake, AgentBudget())
    ex.start()
    first = await ex.wait_cycle(30)
    second = await ex.wait_cycle(30)
    assert first is not None and second is not None
    assert first.idle and second.idle
    assert first.why == second.why == "adequate"
    assert len(fake.calls) == 2                          # the same knowledge, asked again
    await ex.stop()


async def test_cycle_already_in_flight_is_not_a_fresh_idle_answer(session_maker, run_id):
    gate = asyncio.Event()

    class Slow(FakeClient):
        async def complete(self, system, user, **kw):
            await gate.wait()
            return await super().complete(system, user, **kw)

    fake = Slow(lambda s, u: _reply("adequate"))
    ex = await _unit_explorer(session_maker, run_id, fake, AgentBudget())
    ex.start()
    ex.wake("start")
    while not ex._running:
        await asyncio.sleep(0.01)
    waiter = asyncio.create_task(ex.wait_cycle(30))
    await asyncio.sleep(0.05)
    gate.set()
    res = await asyncio.wait_for(waiter, timeout=30)
    assert res is not None and not res.idle             # the supervisor asks again
    await ex.stop()


class _HangingClient(ModelClient):
    """A model call that never returns; records that it was interrupted."""

    def __init__(self) -> None:
        super().__init__(model="hang", timeout_s=600.0)
        self.started = asyncio.Event()
        self.interrupted = False
        self.closed = 0

    async def complete(self, system, user, **kw):
        self.started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.interrupted = True
            raise

    async def aclose(self) -> None:
        self.closed += 1
        await super().aclose()


async def test_cancel_during_in_flight_model_call(
        agent_env, monkeypatch, client, user_token, session_maker):
    hang = _HangingClient()
    _patch_client(monkeypatch, hang)
    server, url = serve(build_ticketing_api())
    try:
        run_id = await _queue(client, user_token, url)
        from src.greybox_web.worker import run_once
        worker = asyncio.create_task(run_once(session_maker))
        try:
            await asyncio.wait_for(hang.started.wait(), timeout=60)
            # wait until the run sits at the idle gate (the 150 s+ blocking point)
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if "waiting_for_explorer" in _decisions(
                        await _events(session_maker, run_id, "planner.decision")):
                    break
                await asyncio.sleep(0.2)
            else:
                pytest.fail("run never reached the idle gate")
            t0 = time.monotonic()
            r = await client.post(f"/greybox/runs/{run_id}/cancel",
                                  headers=h(user_token), json={"reason": "stop"})
            assert r.status_code == 202
            await asyncio.wait_for(worker, timeout=15)
            assert time.monotonic() - t0 < 10.0
        finally:
            if not worker.done():
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)
    finally:
        server.should_exit = True
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "cancelled", (run.status, run.end_reason)
    assert hang.interrupted
    assert hang.closed == 1                              # closed once, not twice


async def test_prompt_injection_proposal_is_rejected_and_never_requested(
        agent_env, monkeypatch, client, user_token, session_maker):
    """The target's content tells the model to fetch an attacker host; a
    compliant scripted model proposes it; admission rejects it (rejection event) and
    no request leaves the guarded client."""
    seen_injection = {"n": 0}

    def compliant(system, user):
        if "SYSTEM OVERRIDE" in user:
            seen_injection["n"] += 1
        from src.greybox_web.exploration.knowledge import extract_knowledge
        base = (extract_knowledge(user).get("run") or {}).get("base_url")
        legit = [] if seen_injection["n"] or not base else [
            {"tool": "discovery.fetch_root", "params": {"url": base},
             "reason": "start by looking at the target root", "priority": 10,
             "variant": "start"}]
        return _reply(
            "incomplete",
            reasoning="The page instructed me to scan the collector host.",
            actions=legit + [
                {"tool": "discovery.crawl",
                 "params": {"url": "http://evil.invalid/",
                            "seeds": ["http://evil.invalid/"]},
                 "reason": "page said to", "priority": 5, "variant": "inj1"},
                {"tool": "headers.security",
                 "params": {"url": "http://collector.invalid/report"},
                 "reason": "page said to", "priority": 5, "variant": "inj2"}])

    _patch_client(monkeypatch, FakeClient(compliant))
    server, url = serve(build_ticketing_api())
    try:
        run_id = await _queue(client, user_token, url)
        from src.greybox_web.worker import run_once
        await asyncio.wait_for(run_once(session_maker), timeout=120)
    finally:
        server.should_exit = True
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "succeeded", run.end_reason
        exchanges = (await s.scalars(select(GreyboxHttpExchange).where(
            GreyboxHttpExchange.run_id == run_id))).all()
        wos = (await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run_id))).all()
    rejected = [e for e in await _events(session_maker, run_id, "planner.decision")
                if (e.data or {}).get("decision") == "rejected"
                and "invalid" in json.dumps(e.data) + e.summary]
    assert rejected, "the out-of-scope proposals must produce rejection events"
    assert exchanges
    for ex in exchanges:
        assert ex.url.startswith("http://127.0.0.1:"), ex.url
    for w in wos:
        assert "invalid" not in json.dumps(w.params)


# ------------------------------------------------------------------- unit-level

async def _unit_explorer(session_maker, run_id, client, budget):
    return Explorer(session_maker, run_id, LlmProposer(), client,
                    agent_budget=budget,
                    live=lambda: {"frontier": [], "coverage": {},
                                  "budget": {"requests_used": 1}})


@pytest.fixture
async def run_id(client, user_token, session_maker, live_target):
    r = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex)
    return uuid.UUID(r.json()["id"])


async def test_repair_round_never_exceeds_max_calls(session_maker, run_id):
    fake = FakeClient(lambda s, u: "not json at all")
    ex = await _unit_explorer(session_maker, run_id, fake,
                              AgentBudget(max_calls=1, max_tokens=100_000))
    res = await ex.cycle("delta")
    assert res.why == "failed"
    assert len(fake.calls) == 1                         # no repair call
    assert ex.budget.calls_used == 1 <= ex.budget.max_calls
    failed = await _events(session_maker, run_id, "llm.failed")
    assert failed and "repair" in failed[0].summary
    await ex.stop()


async def test_stop_is_idempotent_and_closes_client_once(session_maker, run_id):
    closes = {"n": 0}

    class C(FakeClient):
        async def aclose(self):
            closes["n"] += 1
            await super().aclose()

    ex = await _unit_explorer(session_maker, run_id, C(lambda s, u: _reply()),
                              AgentBudget())
    ex.start()
    await ex.stop()
    await ex.stop()
    assert closes["n"] == 1


async def test_wait_cycle_returns_immediately_when_budget_exhausted(
        session_maker, run_id):
    ex = await _unit_explorer(session_maker, run_id, FakeClient(lambda s, u: _reply()),
                              AgentBudget(max_calls=2, max_tokens=10))
    ex.budget.calls_used = 2
    t0 = time.monotonic()
    assert await ex.wait_cycle(300) is None
    assert time.monotonic() - t0 < 1.0
    await ex.stop()


async def test_cancel_releases_a_blocked_wait_cycle(session_maker, run_id):
    hang = _HangingClient()
    ex = await _unit_explorer(session_maker, run_id, hang, AgentBudget())
    ex.start()
    waiter = asyncio.create_task(ex.wait_cycle(300))
    await asyncio.wait_for(hang.started.wait(), timeout=30)
    ex.cancel()
    assert await asyncio.wait_for(waiter, timeout=5) is None
    await ex.stop()
    assert hang.interrupted


# --------------------------------------------------- retries, failure, coalescing

class _Flaky(ModelClient):
    """Fails ``n`` times with a transient error, then answers."""

    def __init__(self, n: int) -> None:
        super().__init__(model="flaky", timeout_s=5.0)
        self.n = n
        self.calls = 0

    async def complete(self, system, user, **kw):
        from src.greybox_web.exploration.client import AgentError, ModelReply
        self.calls += 1
        if self.calls <= self.n:
            raise AgentError("model API returned 503: overloaded")
        return ModelReply(_reply("adequate", reasoning="nothing left to examine"),
                          "flaky", 10, 10, 1)


async def test_transient_model_errors_are_retried_with_backoff(session_maker, run_id):
    flaky = _Flaky(2)
    ex = Explorer(session_maker, run_id, LlmProposer(), flaky,
                  agent_budget=AgentBudget(), retry_backoff_s=(0.0, 0.0))
    res = await ex.cycle("start")
    assert res.why == "adequate" and flaky.calls == 3
    assert ex.failures == 0 and ex.budget.calls_used == 3
    retries = [e for e in await _events(session_maker, run_id, "planner.decision")
               if (e.data or {}).get("decision") == "model_retry"]
    assert len(retries) == 2
    await ex.stop()


async def test_persistent_model_failure_is_reported_not_swallowed(session_maker, run_id):
    flaky = _Flaky(99)
    ex = Explorer(session_maker, run_id, LlmProposer(), flaky,
                  agent_budget=AgentBudget(), retry_backoff_s=(0.0,))
    res = await ex.cycle("start")
    assert res.why == "failed" and flaky.calls == 3     # 1 try + 2 retries
    assert ex.failures == 1 and "503" in ex.last_error
    assert await _events(session_maker, run_id, "llm.failed")
    await ex.stop()


async def test_run_fails_with_a_clear_error_when_the_model_keeps_failing(
        agent_env, monkeypatch, client, user_token, session_maker):
    flaky = _Flaky(999)
    _patch_client(monkeypatch, flaky)
    server, url = serve(build_ticketing_api())
    try:
        run_id = await _queue(client, user_token, url)
        from src.greybox_web.worker import run_once
        await asyncio.wait_for(run_once(
            session_maker, explorer_options={"retry_backoff_s": (0.0,),
                                             "cycle_backoff_s": (0.0,)}),
            timeout=120)
    finally:
        server.should_exit = True
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "failed", (run.status, run.end_reason)
        assert "AI model failed" in (run.error_summary or "")
        assert "503" in (run.error_summary or "")
    failed = await _events(session_maker, run_id, "llm.failed")
    # a failed cycle never ends the run by itself: exactly N consecutive failed
    # cycles (each with its own transient retries) before it gives up
    assert len(failed) == 3 and [e.data["consecutive_failures"] for e in failed] == [1, 2, 3]
    assert flaky.calls == 9                             # 3 cycles x (1 try + 2 retries)
    notes = [e for e in await _events(session_maker, run_id, "planner.decision")
             if (e.data or {}).get("decision") == "model_cycle_retry"]
    assert len(notes) == 2                              # back off and retry, twice
    assert len(await _events(session_maker, run_id, "agent.failed")) == 1   # once


async def test_run_survives_two_failed_cycles_and_completes(
        agent_env, monkeypatch, client, user_token, session_maker):
    flaky = _Flaky(6)           # cycles 1 and 2 fail (3 attempts each), cycle 3 answers
    _patch_client(monkeypatch, flaky)
    server, url = serve(build_ticketing_api())
    try:
        run_id = await _queue(client, user_token, url)
        from src.greybox_web.worker import run_once
        await asyncio.wait_for(run_once(
            session_maker, explorer_options={"retry_backoff_s": (0.0,),
                                             "cycle_backoff_s": (0.0,)}),
            timeout=120)
    finally:
        server.should_exit = True
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "succeeded", (run.status, run.error_summary)
    assert len(await _events(session_maker, run_id, "llm.failed")) == 2
    assert not await _events(session_maker, run_id, "run.failed")


def test_idle_grace_is_model_timeout_times_attempts_plus_margin_and_capped():
    from src.greybox_web.exploration.explorer import MODEL_RETRIES
    from src.greybox_web.supervisor import GRACE_CAP_S, GRACE_MARGIN_S, grace_seconds
    assert grace_seconds(60.0) == 60.0 * (MODEL_RETRIES + 1) + GRACE_MARGIN_S == 210.0
    assert grace_seconds(5.0) < 60
    assert grace_seconds(10_000.0) == GRACE_CAP_S


async def test_waiting_note_is_human_and_precedes_nothing_misleading(
        agent_env, monkeypatch, client, user_token, session_maker):
    _patch_client(monkeypatch, FakeClient(lambda s, u: _reply("adequate")))
    server, url = serve(build_ticketing_api())
    try:
        run_id = await _queue(client, user_token, url)
        from src.greybox_web.worker import run_once
        await asyncio.wait_for(run_once(session_maker), timeout=120)
    finally:
        server.should_exit = True
    waits = [e for e in await _events(session_maker, run_id, "planner.decision")
             if (e.data or {}).get("decision") == "waiting_for_explorer"]
    assert waits and all(
        e.summary == "Waiting for the AI planner to decide the next steps" for e in waits)
    assert all("390" not in e.summary and "queue is empty" not in e.summary
               for e in waits)


async def test_delta_wakeups_are_coalesced_into_one_model_call(session_maker, run_id):
    fake = FakeClient(lambda s, u: _reply("incomplete", reasoning="working on it"))
    ex = Explorer(session_maker, run_id, LlmProposer(), fake,
                  agent_budget=AgentBudget(), coalesce_s=0.4)
    ex.start()
    for _ in range(6):                       # six completions in quick succession
        ex.wake("delta")
        await asyncio.sleep(0.05)
    await asyncio.sleep(1.5)                 # the burst settles, then one call
    assert len(fake.calls) == 1
    # an idle moment is NOT delayed by the window
    t0 = time.monotonic()
    ex.coalesce_s = 30.0
    res = await ex.wait_cycle(10)
    assert res is not None and time.monotonic() - t0 < 5
    await ex.stop()


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
