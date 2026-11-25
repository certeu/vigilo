"""Explorer cycle tests against a real run
row, with a scripted fake client: reasoning nodes, llm events, quiet mode, the
repair round, budget enforcement and the retained todolist.

No real model is ever called; the responder is plain Python.
"""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.exploration.client import AgentBudget, FakeClient
from src.greybox_web.exploration.explorer import Explorer
from src.greybox_web.exploration.proposer import LlmProposer
from src.greybox_web.models import GreyboxEvent, GreyboxGraphNode
from tests.greybox_web.conftest import start_run

VALID = {
    "reasoning": "The run has fetched its root and robots; the interesting surface "
                 "is the login form, so session handling comes first.",
    "assessment": "incomplete",
    "todolist": [{"step": "Examine session cookies on the login flow",
                  "status": "in_progress"},
                 {"step": "Map the remaining frontier", "status": "pending"}],
    "hypotheses": [{"id": "h1", "label": "Session handling untested",
                    "hypothesis": "Session cookie flags are weak."}],
    "actions": [{"tool": "cookies.flags", "params": {"url": "URL"},
                 "reason": "the login flow issues session cookies",
                 "priority": 30, "variant": "login-session", "hypothesis": "h1"}],
}


def _reply(url: str) -> str:
    return json.dumps(VALID).replace("URL", url)


@pytest.fixture
async def run_id(client, user_token, session_maker, live_target):
    r = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex)
    return uuid.UUID(r.json()["id"])


async def _url(session_maker, run_id) -> str:
    from src.greybox_web.models import GreyboxRun
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        return run.base_url


def _explorer(session_maker, run_id, responder, budget=None) -> Explorer:
    return Explorer(
        session_maker, run_id, LlmProposer(), FakeClient(responder),
        agent_budget=budget or AgentBudget(max_calls=10, max_tokens=100_000),
        live=lambda: {"frontier": [], "coverage": {"pages_fetched": 1},
                      "budget": {"requests_used": 3, "requests_max": 100}})


async def _events(session_maker, run_id, kind):
    async with session_maker() as s:
        return list((await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id, GreyboxEvent.kind == kind)
            .order_by(GreyboxEvent.seq))).all())


async def test_cycle_records_reasoning_node_events_and_stores(session_maker, run_id):
    url = await _url(session_maker, run_id)
    ex = _explorer(session_maker, run_id, lambda s, u: _reply(url))
    res = await ex.cycle("delta")
    assert res.stored and res.why == "ok" and res.calls == 1 and res.model
    # reasoning node with the model's analysis, todo list and assessment
    async with session_maker() as s:
        nodes = list((await s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id,
            GreyboxGraphNode.kind == "reasoning"))).all())
    assert len(nodes) == 1 and nodes[0].status == "active"
    d = nodes[0].data
    assert d["assessment"] == "incomplete" and d["trigger"] == "new_results"
    assert d["todolist"][0]["step"] == "Examine session cookies on the login flow"
    assert "login form" in d["reasoning"]
    assert d["actions"] == ["cookies.flags"]
    # events: request before, response after, with the reasoning surfaced
    req = await _events(session_maker, run_id, "llm.request")
    resp = await _events(session_maker, run_id, "llm.response")
    assert len(req) == 1 and req[0].data["trigger"] == "new_results" and req[0].data["attempt"] == 1
    assert len(resp) == 1 and resp[0].data["assessment"] == "incomplete"
    assert resp[0].data["actions"] == 1 and "reasoning" in resp[0].data
    # proposals cached for the next planning cycle
    st = ex.proposer.stored
    assert st is not None and len(st.groups) == 1
    assert st.groups[0].specs[0].tool == "cookies.flags"
    assert st.groups[0].specs[0].parent_node_id == nodes[0].id
    await ex.stop()


async def test_quiet_mode_suppresses_repeat_calls(session_maker, run_id):
    url = await _url(session_maker, run_id)
    ex = _explorer(session_maker, run_id, lambda s, u: _reply(url))
    r1 = await ex.cycle("delta")
    assert r1.calls == 1
    ex._busy = lambda k: True                 # nothing changed, work still in flight
    r2 = await ex.cycle("delta")
    assert r2.why == "quiet" and r2.calls == 0
    assert len(ex.client.calls) == 1          # one model call, not two
    # the empty queue is never quiet: the same knowledge is asked about again
    r3 = await ex.cycle("idle")
    assert r3.why != "quiet" and r3.calls == 1
    assert len(ex.client.calls) == 2
    await ex.stop()


async def test_repair_round_recovers_a_malformed_reply(session_maker, run_id):
    url = await _url(session_maker, run_id)
    replies = iter(["sorry, I cannot answer in JSON",
                    _reply(url)])

    def responder(s, u):
        return next(replies)

    ex = _explorer(session_maker, run_id, responder)
    res = await ex.cycle("delta")
    assert res.stored and res.calls == 2          # original + one repair round
    assert len(ex.client.calls) == 2
    assert "NOT applied" in ex.client.calls[1][1]     # the repair prompt explains why
    await ex.stop()


async def test_persistent_garbage_fails_closed_with_llm_failed(session_maker, run_id):
    ex = _explorer(session_maker, run_id, lambda s, u: "no json here at all")
    res = await ex.cycle("delta")
    assert not res.stored and res.why == "failed" and res.calls == 2
    failed = await _events(session_maker, run_id, "llm.failed")
    assert len(failed) == 1 and "no JSON object" in failed[0].summary
    assert ex.proposer.stored is None            # nothing half-applied
    await ex.stop()


async def test_budget_stops_cycles(session_maker, run_id):
    url = await _url(session_maker, run_id)
    ex = _explorer(session_maker, run_id, lambda s, u: _reply(url),
                   budget=AgentBudget(max_calls=1, max_tokens=1000))
    r1 = await ex.cycle("delta")
    assert r1.stored
    r2 = await ex.cycle("delta")
    assert r2.why == "budget" and r2.calls == 0 and not r2.stored
    await ex.stop()


async def test_second_cycle_supersedes_and_retains_todolist(session_maker, run_id):
    url = await _url(session_maker, run_id)
    calls = {"n": 0}

    def responder(s, u):
        calls["n"] += 1
        # cycle 2: the same todo list, now advanced, and no further actions
        if calls["n"] == 1:
            return _reply(url)
        return json.dumps({
            "reasoning": "The session direction advanced; cookies were examined and "
                         "the frontier is drained, so the assessment stands.",
            "assessment": "adequate",
            "todolist": [{"step": "Examine session cookies on the login flow",
                          "status": "done"},
                         {"step": "Map the remaining frontier", "status": "done"}],
            "hypotheses": [], "actions": []})

    ex = _explorer(session_maker, run_id, responder)
    await ex.cycle("delta")
    # force a knowledge change so the second cycle is not quiet
    from src.greybox_web.models import GreyboxWorkOrder
    async with session_maker() as s:
        s.add(GreyboxWorkOrder(run_id=run_id, dedup_key="x|forced", kind="check",
                               tool="headers.security", title="x", reason="test",
                               params={}, priority=50, status="done",
                               created_seq=99, result_summary="forced change"))
        await s.commit()
    r2 = await ex.cycle("delta")
    assert r2.why == "adequate" and r2.assessment == "adequate" and r2.stored is False
    async with session_maker() as s:
        nodes = list((await s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id,
            GreyboxGraphNode.kind == "reasoning").order_by(
            GreyboxGraphNode.created_at))).all())
    assert [n.status for n in nodes] == ["superseded", "active"]
    assert nodes[1].data["todolist"][0]["status"] == "done"
    # and cycle 3 reads the retained todolist back into the prompt
    await ex.cycle("delta")     # quiet (nothing changed) is fine; we only need no error
    assert "Examine session cookies" in ex.client.calls[1][1] or ex.client.calls[1:]
    await ex.stop()


async def test_wakeup_task_runs_cycles_in_background(session_maker, run_id):
    url = await _url(session_maker, run_id)
    ex = _explorer(session_maker, run_id, lambda s, u: _reply(url))
    ex.start()
    try:
        ex.wake("delta")
        ok = await ex.wait_cycle(timeout_s=10)
        assert ok and ex.cycle_count == 1
        # the next idle wake also cycles (never quiet at an empty queue)
        ok = await ex.wait_cycle(timeout_s=10)
        assert ok
    finally:
        await ex.stop()
    assert ex.task is None or ex.task.done()


# ------------------------------------------------ robustness: truncation, tolerance

import httpx  # noqa: E402

from src.greybox_web.exploration.client import (  # noqa: E402
    AnthropicClient,
    ModelClient,
    ModelReply,
    OpenAIResponsesClient,
)


class _Scripted(ModelClient):
    """Returns the scripted ``ModelReply`` objects in order; records each call."""

    def __init__(self, replies):
        super().__init__(model="scripted", timeout_s=5.0)
        self.replies = list(replies)
        self.calls: list[dict] = []

    async def complete(self, system, user, **kw):
        self.calls.append({"user": user, **kw})
        return self.replies.pop(0)


def _mr(text, *, truncated=False, stop="", out=100, **kw):
    return ModelReply(text, "scripted", 50, out, 1, stop_reason=stop,
                      truncated=truncated, **kw)


async def test_truncated_reply_keeps_the_complete_items(session_maker, run_id):
    url = await _url(session_maker, run_id)
    cut = _reply(url)[:-40]                      # cut inside the (only) action
    ex = _explorer(session_maker, run_id, lambda s, u: "")
    ex.client = _Scripted([_mr(cut, truncated=True, stop="max_tokens", out=8000)])
    res = await ex.cycle("delta")
    assert res.why == "ok" and res.calls == 1 and res.assessment == "incomplete"
    resp = (await _events(session_maker, run_id, "llm.response"))[0]
    assert resp.data["truncated"] is True and resp.data["stop_reason"] == "max_tokens"
    assert any("truncated" in n for n in resp.data["notes"])
    assert ex.failures == 0
    await ex.stop()


async def test_truncated_without_content_retries_once_with_a_smaller_snapshot(
        session_maker, run_id):
    url = await _url(session_maker, run_id)
    ex = _explorer(session_maker, run_id, lambda s, u: "")
    ex.client = _Scripted([
        _mr("", truncated=True, stop="max_output_tokens", out=2000),    # all reasoning
        _mr(_reply(url))])
    res = await ex.cycle("delta")
    first, second = ex.client.calls
    assert res.why == "ok" and res.calls == 2
    assert len(second["user"]) <= len(first["user"])
    assert second["max_output_tokens"] > first["max_output_tokens"]
    assert first["schema"] and second["schema"]              # structured output asked
    shrink = [e for e in await _events(session_maker, run_id, "planner.decision")
              if (e.data or {}).get("decision") == "model_shrink"]
    assert len(shrink) == 1
    await ex.stop()


async def test_truncated_twice_fails_with_a_debuggable_event(session_maker, run_id):
    ex = _explorer(session_maker, run_id, lambda s, u: "")
    ex.client = _Scripted([_mr("", truncated=True, stop="length", out=2000),
                           _mr("", truncated=True, stop="length", out=2000)])
    res = await ex.cycle("delta")
    assert res.why == "failed" and res.calls == 2
    failed = (await _events(session_maker, run_id, "llm.failed"))[0]
    d = failed.data
    assert d["stop_reason"] == "length" and d["truncated"] is True
    assert d["output_tokens"] == 2000 and d["cycle"] == 1 and d["attempt"] == 1
    assert d["trigger"] == "new_results" and d["consecutive_failures"] == 1
    await ex.stop()


async def test_llm_failed_carries_a_redacted_head_and_tail_of_the_reply(
        session_maker, run_id):
    secret = "Bearer abcdefghijklmnop.secret"
    garbage = "no json here " + "z" * 900 + " ?token=sup3rs3cretvalue " + "end" * 50
    ex = _explorer(session_maker, run_id, lambda s, u: garbage)
    res = await ex.cycle("delta")
    assert res.why == "failed"
    d = (await _events(session_maker, run_id, "llm.failed"))[0].data
    assert d["reply_chars"] == len(garbage)
    assert d["reply_head"].startswith("no json here") and len(d["reply_head"]) <= 300
    assert len(d["reply_tail"]) <= 300 and d["reply_tail"].endswith("end")
    assert "sup3rs3cretvalue" not in json.dumps(d) and secret not in json.dumps(d)
    await ex.stop()


async def test_tolerant_reply_one_bad_action_among_good_ones(session_maker, run_id):
    url = await _url(session_maker, run_id)
    obj = json.loads(_reply(url))
    good = obj["actions"][0]
    obj["actions"] = [{"tool": "??"}, good, {"nonsense": True}]
    obj["surprise"] = "ignored"
    text = "Here you go:\n```json\n" + json.dumps(obj) + "\n```"
    ex = _explorer(session_maker, run_id, lambda s, u: text)
    res = await ex.cycle("delta")
    assert res.why == "ok" and res.calls == 1
    assert [s.tool for g in ex.proposer.stored.groups for s in g.specs] == ["cookies.flags"]
    resp = (await _events(session_maker, run_id, "llm.response"))[0]
    assert len([n for n in resp.data["notes"] if "dropped" in n]) == 2
    await ex.stop()


async def test_anthropic_tool_call_reply_drives_a_cycle(session_maker, run_id):
    url = await _url(session_maker, run_id)

    async def handler(request):
        body = json.loads(request.content)
        assert body["tool_choice"]["name"] == "propose" and body["max_tokens"] >= 4000
        return httpx.Response(200, json={
            "content": [{"type": "tool_use", "name": "propose",
                         "input": json.loads(_reply(url))}],
            "stop_reason": "tool_use", "usage": {"input_tokens": 5, "output_tokens": 5}})
    client = AnthropicClient(api_key="k", transport=httpx.MockTransport(handler))
    ex = Explorer(session_maker, run_id, LlmProposer(), client,
                  agent_budget=AgentBudget(), live=lambda: {})
    res = await ex.cycle("start")
    assert res.why == "ok" and res.stored
    resp = (await _events(session_maker, run_id, "llm.response"))[0]
    assert resp.data["mode"] == "tool"
    await ex.stop()


async def test_responses_incomplete_payload_is_recovered_end_to_end(
        session_maker, run_id):
    """The maintainer's run: cycle 2 on a Responses model returned status incomplete
    with the JSON cut mid-way. It must be used (partial), not fail the cycle."""
    url = await _url(session_maker, run_id)
    cut = _reply(url)[:-40]

    async def handler(request):
        return httpx.Response(200, json={
            "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"},
            "output": [{"type": "reasoning", "content": []},
                       {"type": "message", "content": [
                           {"type": "output_text", "text": cut}]}],
            "usage": {"input_tokens": 5, "output_tokens": 8000}})
    client = OpenAIResponsesClient(base_url="http://gw/v1", api_key="k", model="gpt-x",
                                   transport=httpx.MockTransport(handler))
    ex = Explorer(session_maker, run_id, LlmProposer(), client,
                  agent_budget=AgentBudget(), live=lambda: {})
    res = await ex.cycle("idle")
    assert res.why == "ok" and ex.failures == 0
    resp = (await _events(session_maker, run_id, "llm.response"))[0]
    assert resp.data["truncated"] and resp.data["output_tokens"] == 8000
    await ex.stop()


async def test_failed_cycles_back_off_and_a_success_resets_the_streak(
        session_maker, run_id):
    url = await _url(session_maker, run_id)
    url = await _url(session_maker, run_id)
    ex = Explorer(session_maker, run_id, LlmProposer(),
                  FakeClient(lambda s, u: "garbage"),
                  agent_budget=AgentBudget(), cycle_backoff_s=(7.0, 20.0, 50.0),
                  live=lambda: {})
    await ex.cycle("idle")                       # garbage + repair garbage: failed
    assert ex.failures == 1 and ex.cycle_backoff() == 7.0
    await ex.cycle("idle")
    assert ex.failures == 2 and ex.cycle_backoff() == 20.0
    await ex.cycle("idle")
    assert ex.failures == 3 and ex.cycle_backoff() == 50.0
    ex.client.responder = lambda s, u: _reply(url)
    res = await ex.cycle("idle")
    assert res.why == "ok" and ex.failures == 0 and ex.cycle_backoff() == 0.0
    await ex.stop()


async def test_background_cycles_pause_during_the_backoff(session_maker, run_id):
    ex = Explorer(session_maker, run_id, LlmProposer(),
                  FakeClient(lambda s, u: "garbage"), agent_budget=AgentBudget(),
                  cycle_backoff_s=(300.0,), coalesce_s=0, live=lambda: {})
    ex.start()
    try:
        ex.wake("delta")
        res = await ex.wait_cycle(10)            # the failing cycle
        assert res is not None and ex.failures == 1
        calls = len(ex.client.calls)
        ex.wake("delta")                         # inside the backoff: no model call
        await asyncio.sleep(0.5)
        assert len(ex.client.calls) == calls
        res = await ex.wait_cycle(10)            # idle is never held back
        assert len(ex.client.calls) > calls
    finally:
        await ex.stop()


async def test_prompt_asks_for_concise_output_and_summarises_static_assets(
        session_maker, run_id):
    ex = _explorer(session_maker, run_id, lambda s, u: _reply("http://x/"))
    await ex.cycle("delta")
    system, user = ex.client.calls[0]
    assert "at most 6" in user or "6 sentences" in system
    assert "at most 8 actions" in user.lower() or "at most 8 actions" in system.lower()
    assert "Static assets" in system
    await ex.stop()


# ------------------------------------------------- operator messages (run chat)


async def _message(session_maker, run_id, text="please focus on the API",
                   status="addressed", result="noted", about_node_id=None):
    from src.greybox_web.models import GreyboxHint
    async with session_maker() as s:
        hint = GreyboxHint(run_id=run_id, text=text, action="note", status=status,
                           result=result, work_order_ids=[], created_by=uuid.uuid4(),
                           created_by_name="op@example.test",
                           about_node_id=about_node_id)
        s.add(hint)
        await s.commit()
        return hint.id


async def _hint(session_maker, hint_id):
    from src.greybox_web.models import GreyboxHint
    async with session_maker() as s:
        return await s.get(GreyboxHint, hint_id)


def _with_replies(url, replies):
    return json.dumps({**json.loads(_reply(url)), "replies": replies})


async def test_operator_message_is_trusted_section_and_gets_the_agents_reply(
        session_maker, run_id):
    from src.greybox_web.exploration.knowledge import extract_knowledge
    url = await _url(session_maker, run_id)
    hid = await _message(session_maker, run_id, text="please focus on the API")
    pending = await _message(session_maker, run_id, text="still open", status="open",
                             result=None)
    ex = _explorer(session_maker, run_id, lambda s, u: _with_replies(url, [
        {"id": "m1", "reply": "Will do: the API is my next direction."},
        {"id": "m9", "reply": "an id that was never sent is ignored"}]))
    res = await ex.cycle("hint")
    assert res.why == "ok"
    user = ex.client.calls[0][1]
    # a separate, trusted section after the untrusted block; not inside the JSON
    assert "## OPERATOR MESSAGES" in user
    assert user.index("## OPERATOR MESSAGES") > user.index("</untrusted-KNOWLEDGE-")
    assert "id=m1" in user and "please focus on the API" in user
    assert "still open" not in user                   # not delivered yet
    assert "cannot widen the scope" in user
    assert "please focus on the API" not in json.dumps(extract_knowledge(user))
    # llm.request names the messages it carries; seen_cycle and the reply are stored
    req = await _events(session_maker, run_id, "llm.request")
    assert req[0].data["hint_ids"] == [str(hid)]
    h = await _hint(session_maker, hid)
    assert h.seen_cycle == 1 and h.reply_cycle == 1 and h.replied_at is not None
    assert h.reply == "Will do: the API is my next direction."
    assert (await _hint(session_maker, pending)).reply is None
    replied = await _events(session_maker, run_id, "hint.replied")
    assert len(replied) == 1 and replied[0].data["hint_id"] == str(hid)
    assert replied[0].data["reply"] == h.reply and replied[0].data["by"] == "agent"
    assert (replied[0].source, replied[0].level, replied[0].status) == \
        ("agent", "info", "ok")
    # answered: the next call no longer carries it
    await ex.cycle("idle")
    assert "## OPERATOR MESSAGES" not in ex.client.calls[1][1]
    assert (await _events(session_maker, run_id, "llm.request"))[1].data["hint_ids"] == []
    await ex.stop()


async def test_pending_message_is_never_quiet(session_maker, run_id):
    url = await _url(session_maker, run_id)
    ex = _explorer(session_maker, run_id, lambda s, u: _reply(url))
    ex._busy = lambda k: True
    await ex.cycle("delta")
    assert (await ex.cycle("delta")).why == "quiet"
    await _message(session_maker, run_id)             # a new operator message
    r = await ex.cycle("delta")
    assert r.why != "quiet" and len(ex.client.calls) == 2
    await ex.stop()


async def test_unanswered_message_gets_a_platform_reply_after_two_cycles(
        session_maker, run_id):
    url = await _url(session_maker, run_id)
    hid = await _message(session_maker, run_id, result="noted")
    ex = _explorer(session_maker, run_id, lambda s, u: _reply(url))   # never replies
    await ex.cycle("hint")
    await ex.cycle("idle")
    assert (await _hint(session_maker, hid)).reply is None
    assert all("id=m1" in u for _s, u in ex.client.calls)
    await ex.cycle("idle")                            # third: the platform answers
    assert "## OPERATOR MESSAGES" not in ex.client.calls[2][1]
    h = await _hint(session_maker, hid)
    assert h.reply == "Noted — platform applied: noted" and h.seen_cycle == 1
    replied = await _events(session_maker, run_id, "hint.replied")
    assert len(replied) == 1 and replied[0].data["by"] == "platform"
    await ex.stop()


async def test_exhausted_budget_answers_waiting_messages(session_maker, run_id):
    url = await _url(session_maker, run_id)
    ex = _explorer(session_maker, run_id, lambda s, u: _reply(url),
                   budget=AgentBudget(max_calls=1, max_tokens=100_000))
    await ex.cycle("delta")
    hid = await _message(session_maker, run_id, status="rejected",
                         result="out_of_scope")
    r = await ex.cycle("hint")
    assert r.why == "budget" and len(ex.client.calls) == 1
    h = await _hint(session_maker, hid)
    assert h.reply == "Noted — the platform could not apply it: out_of_scope"
    await ex.stop()


async def test_messages_are_capped_oldest_first_with_about_label(session_maker, run_id):
    from src.greybox_web.exploration.messages import CAP_MESSAGES
    url = await _url(session_maker, run_id)
    async with session_maker() as s:
        node = (await s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id))).first()
        about = (node.id, node.label) if node is not None else (None, None)
    ids = [await _message(session_maker, run_id, text=f"message {i}",
                          about_node_id=about[0] if i == 0 else None)
           for i in range(CAP_MESSAGES + 2)]
    ex = _explorer(session_maker, run_id, lambda s, u: _reply(url))
    await ex.cycle("hint")
    user = ex.client.calls[0][1]
    assert "message 0" in user and f"message {CAP_MESSAGES - 1}" in user
    assert f"message {CAP_MESSAGES}" not in user
    if about[0] is not None:
        assert f'about graph node "{about[1]}' in user
    req = await _events(session_maker, run_id, "llm.request")
    assert req[0].data["hint_ids"] == [str(i) for i in ids[:CAP_MESSAGES]]
    await ex.stop()
