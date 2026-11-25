"""Analyst hints: steering a running scan without widening it.

Live scenarios keep a run active on the synthetic target's /slow endpoint (the
discovery slot is blocked on it, so the planner's 0.5 s cycle is what handles
the hints) and cancel it at the end. Out-of-scope hints are asserted against
the target's request counter and the exchange table: nothing is requested.
"""
from __future__ import annotations

import asyncio
import time
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.models import (
    GreyboxEvent, GreyboxGraphEdge, GreyboxGraphNode, GreyboxHint,
    GreyboxHttpExchange, GreyboxWorkOrder,
)
from tests.greybox_web.conftest import (
    FAST_LIMITS, create_target, h, other_user_token, run_worker_once, start_run,
)


async def _wait_status(client, token, run_id, statuses, timeout=15.0):
    deadline = time.monotonic() + timeout
    body = {}
    while time.monotonic() < deadline:
        body = (await client.get(f"/greybox/runs/{run_id}", headers=h(token))).json()
        if body["status"] in statuses:
            return body
        await asyncio.sleep(0.1)
    raise AssertionError(f"run never reached {statuses}: {body.get('status')}")


async def _post(client, token, run_id, **body):
    body.setdefault("text", "analyst note")
    return await client.post(f"/greybox/runs/{run_id}/hints", headers=h(token), json=body)


async def _hints(client, token, run_id) -> list[dict]:
    r = await client.get(f"/greybox/runs/{run_id}/hints", headers=h(token))
    assert r.status_code == 200, r.text
    return r.json()["items"]


async def _settled(client, token, run_id, hint_id, timeout=6.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for x in await _hints(client, token, run_id):
            if x["id"] == hint_id and x["status"] != "open":
                return x
        await asyncio.sleep(0.1)
    raise AssertionError("hint was not processed in time")


async def _graph(client, token, run_id) -> dict:
    r = await client.get(f"/greybox/runs/{run_id}/graph/exploration", headers=h(token))
    assert r.status_code == 200, r.text
    return r.json()


def _guided(graph: dict, hint: dict) -> set[str]:
    return {str(e["dst"]) for e in graph["edges"]
            if e["rel"] == "guides" and str(e["src"]) == hint["node_id"]}


async def _events(session_maker, run_id) -> list[GreyboxEvent]:
    async with session_maker() as s:
        return list((await s.scalars(
            select(GreyboxEvent).where(GreyboxEvent.run_id == uuid.UUID(run_id))
            .order_by(GreyboxEvent.seq))).all())


def _assert_invariants(evs: list[GreyboxEvent]) -> None:
    assert [e.seq for e in evs] == list(range(1, len(evs) + 1))
    assert evs[0].kind == "run.queued"
    terminal = [e for e in evs if e.kind in ("run.completed", "run.failed",
                                             "run.cancelled")]
    assert len(terminal) == 1 and evs[-1].seq == terminal[0].seq


@pytest.fixture
async def slow_run(client, user_token, session_maker, target_server):
    """A run held active by /slow (fetch_root blocks for up to 30 s)."""
    t = await create_target(client, user_token, base_url=target_server.url + "slow",
                            limits={**FAST_LIMITS, "request_timeout_s": 30})
    r = await start_run(client, user_token, t["id"])
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    from src.greybox_web.worker import run_once
    worker = asyncio.create_task(run_once(session_maker))
    await _wait_status(client, user_token, run_id, {"running"})
    yield run_id
    await client.post(f"/greybox/runs/{run_id}/cancel", headers=h(user_token))
    await asyncio.wait_for(worker, timeout=20)


async def _wos(session_maker, run_id) -> list[GreyboxWorkOrder]:
    async with session_maker() as s:
        return list((await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == uuid.UUID(run_id)))).all())


# ----------------------------------------------------------------- live actions


async def test_note_addressed_with_node_and_events(client, user_token, session_maker,
                                                   slow_run):
    r = await _post(client, user_token, slow_run, action="note",
                    text="the admin area is out of our remit", target="ignored")
    assert r.status_code == 201, r.text
    hint = r.json()
    assert hint["status"] == "open" and hint["target"] is None
    assert hint["created_by_name"] and hint["work_order_ids"] == []
    done = await _settled(client, user_token, slow_run, hint["id"])
    assert (done["status"], done["result"]) == ("addressed", "noted")
    assert done["addressed_at"] is not None

    g = await _graph(client, user_token, slow_run)
    node = next(n for n in g["nodes"] if n["id"] == hint["node_id"])
    assert node["kind"] == "hint" and node["status"] == "open"
    assert node["data"]["result"] == "delivered to the agent; awaiting its reply"
    assert node["label"] == "the admin area is out of our remit"
    assert node["data"]["action"] == "note"
    assert node["data"]["created_by_name"] == hint["created_by_name"]

    evs = [e for e in await _events(session_maker, slow_run)
           if e.kind.startswith("hint.") and e.kind != "hint.replied"]   # run chat
    assert [e.kind for e in evs] == ["hint.added", "hint.addressed"]
    added, addressed = evs
    assert (added.source, added.level, added.status) == ("api", "info", "pending")
    assert added.data["hint_id"] == hint["id"] and added.data["action"] == "note"
    assert added.data["text"] == hint["text"]
    assert (addressed.source, addressed.level, addressed.status) == \
        ("planner", "info", "ok")
    assert addressed.data == {"hint_id": hint["id"], "result": "noted",
                              "work_order_ids": []}


async def test_label_is_first_80_chars(client, user_token, slow_run):
    r = await _post(client, user_token, slow_run, action="note", text="x" * 500)
    g = await _graph(client, user_token, slow_run)
    node = next(n for n in g["nodes"] if n["id"] == r.json()["node_id"])
    assert node["label"] == "x" * 80
    assert (await _post(client, user_token, slow_run, action="note",
                        text="y" * 2000)).status_code == 201
    assert (await _post(client, user_token, slow_run, action="note",
                        text="y" * 2001)).status_code == 422


async def test_focus_prioritises_and_seeds_with_guides(client, user_token,
                                                       session_maker, slow_run):
    g0 = await _graph(client, user_token, slow_run)
    objective = next(n for n in g0["nodes"] if n["kind"] == "objective")
    r = await _post(client, user_token, slow_run, action="focus", target="/slow",
                    about_node_id=objective["id"], text="look here first")
    assert r.status_code == 201, r.text
    hint = await _settled(client, user_token, slow_run, r.json()["id"])
    assert hint["status"] == "addressed", hint
    assert hint["result"] == "prioritised 2 work orders, added 1 seed"
    wos = {str(w.id): w for w in await _wos(session_maker, slow_run)}
    assert len(hint["work_order_ids"]) == 3
    by_tool = {wos[i].tool: wos[i] for i in hint["work_order_ids"]}
    assert by_tool["discovery.robots"].priority == 0
    assert by_tool["discovery.sitemap"].priority == 0
    seed = by_tool["discovery.crawl"]
    # the interactive discovery lane (priority <= 5) may already have claimed the seed
    assert seed.priority == 5 and seed.status in ("pending", "running", "done")
    assert seed.params["url"].endswith("/slow")

    g = await _graph(client, user_token, slow_run)
    node_of = {str(w.node_id): str(w.id) for w in wos.values()}
    guided = _guided(g, hint)
    assert objective["id"] in guided
    assert {node_of[n] for n in guided if n in node_of} == set(hint["work_order_ids"])
    assert next(n for n in g["nodes"]
                if n["id"] == hint["node_id"])["status"] == "addressed"

    evs = await _events(session_maker, slow_run)
    kinds = [e.kind for e in evs]
    i_added = kinds.index("hint.added")
    i_seed = kinds.index("work_order.created", i_added)
    i_addr = kinds.index("hint.addressed")
    assert i_added < i_seed < i_addr


async def test_add_seed_creates_crawl_once(client, user_token, session_maker, slow_run):
    a = await _post(client, user_token, slow_run, action="add_seed",
                    target="/static/")
    a = await _settled(client, user_token, slow_run, a.json()["id"])
    assert (a["status"], a["result"]) == ("addressed", "added 1 seed")
    assert len(a["work_order_ids"]) == 1
    wo = next(w for w in await _wos(session_maker, slow_run)
              if str(w.id) == a["work_order_ids"][0])
    assert wo.tool == "discovery.crawl" and wo.status in ("pending", "running", "done")
    assert wo.params["url"].endswith("/static/")

    again = await _post(client, user_token, slow_run, action="add_seed",
                        target="/static/")
    again = await _settled(client, user_token, slow_run, again.json()["id"])
    assert again["status"] == "addressed" and again["work_order_ids"] == []
    assert again["result"] == "seed already planned"      # dedup holds


async def test_deprioritize_lowest(client, user_token, session_maker, slow_run):
    # the premise is "pending work exists": wait for the agent's first proposals
    # (posting earlier races the first planning cycle by a few milliseconds)
    for _ in range(200):
        tools = {w.tool for w in await _wos(session_maker, slow_run)}
        if {"discovery.robots", "discovery.sitemap"} <= tools:
            break
        await asyncio.sleep(0.05)
    r = await _post(client, user_token, slow_run, action="deprioritize",
                    target="/slow")
    hint = await _settled(client, user_token, slow_run, r.json()["id"])
    assert hint["status"] == "addressed"
    assert hint["result"] == "deprioritised 2 work orders"
    wos = {w.tool: w for w in await _wos(session_maker, slow_run)}
    assert wos["discovery.robots"].priority == 100
    assert wos["discovery.sitemap"].priority == 100
    g = await _graph(client, user_token, slow_run)
    assert len(_guided(g, hint)) == 2


async def test_out_of_scope_rejected_no_request(client, user_token, session_maker,
                                                slow_run, target_server):
    target_server.reset()
    evil = "http://127.0.0.2:9/oos-probe"
    for action in ("add_seed", "focus"):
        r = await _post(client, user_token, slow_run, action=action, target=evil)
        assert r.status_code == 201, r.text
        hint = await _settled(client, user_token, slow_run, r.json()["id"])
        assert hint["status"] == "rejected"
        assert hint["result"] == "host_not_allowed"
        assert hint["work_order_ids"] == []
        g = await _graph(client, user_token, slow_run)
        assert next(n for n in g["nodes"]
                    if n["id"] == hint["node_id"])["status"] == "rejected"
    rej = [e for e in await _events(session_maker, slow_run)
           if e.kind == "hint.rejected"]
    assert len(rej) == 2
    for e in rej:
        assert (e.source, e.level, e.status) == ("planner", "warning", "skipped")
        assert e.data["reason"] == "host_not_allowed"
    assert target_server.counts().get("/oos-probe") is None
    async with session_maker() as s:
        hosts = {x.host for x in (await s.scalars(select(GreyboxHttpExchange).where(
            GreyboxHttpExchange.run_id == uuid.UUID(slow_run)))).all()}
    assert hosts <= {"127.0.0.1"}
    assert not [w for w in await _wos(session_maker, slow_run)
                if "oos-probe" in str(w.params)]


async def test_skip_check_unselected_rejected(client, user_token, session_maker,
                                              slow_run):
    for target in ("no.such.check", "auth.default_creds_not_real"):
        r = await _post(client, user_token, slow_run, action="skip_check",
                        target=target)
        hint = await _settled(client, user_token, slow_run, r.json()["id"])
        assert hint["status"] == "rejected" and hint["result"] == "check_not_selected"


async def test_target_required_422(client, user_token, slow_run):
    for action in ("focus", "add_seed", "skip_check", "deprioritize"):
        assert (await _post(client, user_token, slow_run, action=action)
                ).status_code == 422
    assert (await _post(client, user_token, slow_run, action="focus",
                        target="not-a-url")).status_code == 422
    assert (await _post(client, user_token, slow_run, action="shout")
            ).status_code == 422
    assert (await _post(client, user_token, slow_run, action="note", text="")
            ).status_code == 422
    assert (await _post(client, user_token, slow_run, action="note",
                        about_node_id=str(uuid.uuid4()))).status_code == 422


# ------------------------------------------------- checks: skip stops new orders


async def test_skip_check_stops_new_work_orders(client, user_token, session_maker,
                                                target_server):
    """Posted while queued, processed once the planner runs: no cors.policy work
    order is ever created, the other service checks still are."""
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=FAST_LIMITS)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    r = await _post(client, user_token, run_id, action="skip_check",
                    target="cors.policy", text="CORS is handled by the gateway")
    assert r.status_code == 201, r.text
    assert (await _hints(client, user_token, run_id))[0]["status"] == "open"
    await run_worker_once(session_maker)
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "succeeded"
    hint = (await _hints(client, user_token, run_id))[0]
    assert hint["status"] == "addressed"
    tools = {w.tool for w in await _wos(session_maker, run_id)}
    assert "cors.policy" not in tools
    assert "headers.security" in tools
    evs = await _events(session_maker, run_id)
    _assert_invariants(evs)
    assert not [e for e in evs if e.kind == "work_order.skipped"
                and e.data.get("reason") == "operator"]    # nothing was pending yet


async def test_skip_check_skips_pending_and_blocks_new(session_maker, client,
                                                       user_token, target_server):
    """Planner level: pending orders of the check are skipped with reason
    ``operator`` and the planner refuses to create more."""
    from src.greybox_web.graph import GraphStats, GraphTx
    from src.greybox_web.planner import Planner, PlannerState
    from src.greybox_web.scope import ScopePolicy
    from src.greybox_web.models import GreyboxRun

    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=FAST_LIMITS)
    run_id = uuid.UUID((await start_run(client, user_token, t["id"])).json()["id"])
    r = await _post(client, user_token, str(run_id), action="skip_check",
                    target="headers.security")
    assert r.status_code == 201

    async with session_maker() as s:
        async with s.begin():
            run = await s.get(GreyboxRun, run_id)
            pl = Planner(run_id, PlannerState(
                base_url=run.base_url, scope=ScopePolicy.from_dict(run.scope),
                checks=list(run.checks)), uuid.uuid4())
            gtx = GraphTx(s, run_id, GraphStats())
            await pl.initial(s, gtx)
            wo = await pl.create_wo(
                s, gtx, tool="headers.security", kind="check", title="t", reason="r",
                params={"url": run.base_url}, priority=50, variant="x")
            assert wo is not None
            assert len(await pl.process_hints(s, gtx)) == 1
            assert wo.status == "skipped"
            again = await pl.create_wo(
                s, gtx, tool="headers.security", kind="check", title="t", reason="r",
                params={"url": run.base_url}, priority=50, variant="y")
            assert again is None
    async with session_maker() as s:
        ev = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id, GreyboxEvent.kind == "work_order.skipped"
        ))).one()
        assert ev.data["reason"] == "operator" and ev.status == "skipped"
        node = await s.get(GreyboxGraphNode, wo.node_id)
        assert node.status == "skipped"
        hint = (await s.scalars(select(GreyboxHint))).one()
        assert hint.status == "addressed" and hint.work_order_ids == [str(wo.id)]
        guides = (await s.scalars(select(GreyboxGraphEdge).where(
            GreyboxGraphEdge.run_id == run_id, GreyboxGraphEdge.rel == "guides"))).all()
        assert {e.dst_id for e in guides} == {wo.node_id}


# ---------------------------------------------------------- lifecycle and access


async def test_hints_on_queued_run_processed_to_completion(client, user_token,
                                                           session_maker, target_server):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=FAST_LIMITS)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    await _post(client, user_token, run_id, action="note", text="first")
    await _post(client, user_token, run_id, action="focus", target="/search",
                text="second")
    await _post(client, user_token, run_id, action="add_seed", target="/static/",
                text="third")
    await run_worker_once(session_maker)
    items = await _hints(client, user_token, run_id)
    assert [x["text"] for x in items] == ["first", "second", "third"]   # oldest first
    assert all(x["status"] == "addressed" for x in items), items
    evs = await _events(session_maker, run_id)
    _assert_invariants(evs)
    kinds = [e.kind for e in evs]
    assert kinds.count("hint.added") == 3 and kinds.count("hint.addressed") == 3
    assert kinds.index("hint.added") < kinds.index("run.started")


async def test_open_hint_at_terminal_is_rejected(client, user_token, session_maker,
                                                 slow_run):
    await _post(client, user_token, slow_run, action="note", text="late")
    await client.post(f"/greybox/runs/{slow_run}/cancel", headers=h(user_token))
    await _wait_status(client, user_token, slow_run, {"cancelled"}, timeout=8)
    items = await _hints(client, user_token, slow_run)
    assert items and all(x["status"] != "open" for x in items)
    _assert_invariants(await _events(session_maker, slow_run))


async def test_409_on_terminal_run(client, user_token):
    t = await create_target(client, user_token)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    assert (await client.post(f"/greybox/runs/{run_id}/cancel",
                              headers=h(user_token))).status_code == 202
    r = await _post(client, user_token, run_id, action="note")
    assert r.status_code == 409
    assert await _hints(client, user_token, run_id) == []


async def test_404_for_other_user_admin_allowed(client, user_token, admin_token,
                                                session_maker):
    t = await create_target(client, user_token)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    other = await other_user_token(client, session_maker)
    assert (await _post(client, other, run_id, action="note")).status_code == 404
    assert (await client.get(f"/greybox/runs/{run_id}/hints",
                             headers=h(other))).status_code == 404
    assert (await client.get(f"/greybox/runs/{uuid.uuid4()}/hints",
                             headers=h(user_token))).status_code == 404
    assert (await _post(client, admin_token, run_id, action="note")).status_code == 201
    assert len(await _hints(client, user_token, run_id)) == 1


async def test_rate_limit_429(client, user_token):
    t = await create_target(client, user_token)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    for i in range(10):
        assert (await _post(client, user_token, run_id, action="note",
                            text=f"n{i}")).status_code == 201
    r = await _post(client, user_token, run_id, action="note", text="one too many")
    assert r.status_code == 429
    assert len(await _hints(client, user_token, run_id)) == 10
    # another run has its own budget
    t2 = await create_target(client, user_token, name="second",
                             base_url="http://127.0.0.1:43124/")
    run2 = (await start_run(client, user_token, t2["id"])).json()["id"]
    assert (await _post(client, user_token, run2, action="note")).status_code == 201


async def test_hint_text_is_redacted(client, user_token, session_maker):
    from src.audit import redact
    from src.greybox_web import redaction
    secret = "hunter2-very-secret-token"
    t = await create_target(client, user_token)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    redaction.register_secret(secret)
    try:
        r = await _post(client, user_token, run_id, action="note",
                        text=f"the token is {secret}, careful")
        assert r.status_code == 201
        assert secret not in r.text
        listed = await client.get(f"/greybox/runs/{run_id}/hints",
                                  headers=h(user_token))
        assert secret not in listed.text
        g = await _graph(client, user_token, run_id)
        assert secret not in str(g)
        async with session_maker() as s:
            for model in (GreyboxHint, GreyboxEvent, GreyboxGraphNode):
                rows = (await s.scalars(select(model).where(
                    model.run_id == uuid.UUID(run_id)))).all()
                for row in rows:
                    blob = " ".join(str(getattr(row, c.name, ""))
                                    for c in model.__table__.columns)
                    assert secret not in blob, model.__tablename__
    finally:
        redact.clear()


async def test_add_seed_dedup_includes_the_query_string(client, user_token,
                                                        session_maker, slow_run):
    """/slow?i=1 and /slow?i=2 are different seeds; the same URL twice is one."""
    results = []
    for target in ("/slow?i=1", "/slow?i=2", "/slow?i=1"):
        r = await _post(client, user_token, slow_run, action="add_seed", target=target)
        results.append(await _settled(client, user_token, slow_run, r.json()["id"]))
    assert [x["result"] for x in results] == [
        "added 1 seed", "added 1 seed", "seed already planned"]
    seeds = sorted(w.params["url"] for w in await _wos(session_maker, slow_run)
                   if w.tool == "discovery.crawl")
    assert seeds == [seeds[0], seeds[1]] and len(seeds) == 2
    assert [s.rsplit("/slow", 1)[1] for s in seeds] == ["?i=1", "?i=2"]


# ------------------------------------------------------------------ run chat


async def test_free_text_message_defaults_to_note_and_carries_the_about_label(
        client, user_token, session_maker):
    t = await create_target(client, user_token)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    async with session_maker() as s:
        node = GreyboxGraphNode(run_id=uuid.UUID(run_id), kind="observation",
                                key="http://t/api/users", label="GET /api/users",
                                status="recorded", data={}, version=1)
        s.add(node)
        await s.commit()
        node_id = str(node.id)
    r = await client.post(f"/greybox/runs/{run_id}/hints", headers=h(user_token),
                          json={"text": "is this one authorized?",
                                "about_node_id": node_id})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["action"] == "note" and body["about_label"] == "GET /api/users"
    assert (body["reply"], body["replied_at"], body["reply_cycle"],
            body["seen_cycle"]) == (None, None, None, None)
    plain = await client.post(f"/greybox/runs/{run_id}/hints", headers=h(user_token),
                              json={"text": "just a note"})
    assert plain.status_code == 201 and plain.json()["about_label"] is None
    items = await _hints(client, user_token, run_id)
    assert [x["about_label"] for x in items] == ["GET /api/users", None]


async def test_unanswered_messages_get_a_platform_reply_when_the_run_ends(
        client, user_token, session_maker, target_server):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=FAST_LIMITS)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    await _post(client, user_token, run_id, text="first")
    await run_worker_once(session_maker)
    items = await _hints(client, user_token, run_id)
    assert items[0]["status"] == "addressed"
    assert items[0]["reply"] and items[0]["replied_at"]          # agent or platform
    evs = await _events(session_maker, run_id)
    _assert_invariants(evs)
    replied = [e for e in evs if e.kind == "hint.replied"]
    assert len(replied) == 1 and replied[0].data["hint_id"] == items[0]["id"]
    assert replied[0].data["reply"] == items[0]["reply"]


async def test_open_message_at_cancel_is_rejected_and_answered(
        client, user_token, session_maker, slow_run):
    await _post(client, user_token, slow_run, text="late")
    await client.post(f"/greybox/runs/{slow_run}/cancel", headers=h(user_token))
    await _wait_status(client, user_token, slow_run, {"cancelled"}, timeout=8)
    items = await _hints(client, user_token, slow_run)
    assert items and all(x["reply"] for x in items), items
    _assert_invariants(await _events(session_maker, slow_run))


async def test_note_graph_node_stays_open_until_answered(client, user_token,
                                                         session_maker, target_server):
    """A delivered note is not done: its graph node stays open (in force) until the
    agent replies, and the reply is what addresses it. A queued run, so no worker
    races the two steps."""
    from src.greybox_web.exploration import messages
    from src.greybox_web.graph import GraphTx
    from src.greybox_web.planner import Planner

    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=FAST_LIMITS)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    hint = (await _post(client, user_token, run_id, action="note",
                        text="try other users' notebooks")).json()
    rid = uuid.UUID(run_id)
    planner = Planner(rid, None, None, proposer=object())

    async def node_and_row():
        async with session_maker() as s:
            return (await s.get(GreyboxGraphNode, uuid.UUID(hint["node_id"])),
                    await s.get(GreyboxHint, uuid.UUID(hint["id"])))

    # delivery: the row is addressed (the agent's inbox), the graph node is NOT
    async with session_maker() as s, s.begin():
        row = await s.get(GreyboxHint, uuid.UUID(hint["id"]))
        await planner.settle_hint(s, GraphTx(s, rid), row, "addressed", result="noted")
    node, row = await node_and_row()
    assert row.status == "addressed" and row.reply is None
    assert node.status == "open" and "awaiting" in node.data["result"]

    # the agent's reply addresses the node and carries the answer
    async with session_maker() as s, s.begin():
        row = await s.get(GreyboxHint, uuid.UUID(hint["id"]))
        assert await messages.write_reply(s, rid, row, "Testing notebook IDs now.",
                                          cycle=3, by="agent")
    node, row = await node_and_row()
    assert node.status == "addressed"
    assert node.data["reply"] == "Testing notebook IDs now."
    assert node.data["result"] == "answered by the agent"


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
