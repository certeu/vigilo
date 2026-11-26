"""Events SSE stream."""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web import events as gb_events
from src.greybox_web.api import events as api_events
from src.greybox_web.models import GreyboxEvent, GreyboxRun
from tests.greybox_web.conftest import (create_target, h, other_user_token,
                                        run_worker_once, start_run)


def parse(text: str):
    """-> (events, end, raw frames)"""
    frames = [f for f in text.split("\n\n") if f.strip()]
    evs, end = [], None
    for f in frames:
        lines = f.split("\n")
        if "event: end" in lines:
            end = json.loads(next(x for x in lines if x.startswith("data: "))[6:])
        elif "event: event" in lines:
            evs.append((int(lines[0][4:]), json.loads(lines[2][6:]), lines))
    return evs, end, frames


async def read(client, token, run_id, params=None, headers=None):
    hd = h(token)
    hd.update(headers or {})
    async with client.stream("GET", f"/greybox/runs/{run_id}/events/stream",
                             headers=hd, params=params) as r:
        body = "".join([c async for c in r.aiter_text()])
        return r, body


@pytest.fixture
async def finished(client, user_token, session_maker):
    t = await create_target(client, user_token)
    r = await start_run(client, user_token, t["id"])
    run_id = uuid.UUID(r.json()["id"])
    async with session_maker() as s:
        for i in range(5):
            await gb_events.emit(s, run_id, "log.warning", f"w{i}")
        await gb_events.emit(s, run_id, "run.cancelled", "cancelled",
                             data={"reason": "user", "open_work_orders_cancelled": 0})
        run = await s.get(GreyboxRun, run_id)
        run.status = "cancelled"
        await s.commit()
    return run_id   # seq 1..7, terminal


async def test_frames_and_headers(client, user_token, finished):
    r, body = await read(client, user_token, finished)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.headers["cache-control"] == "no-cache"
    assert r.headers["x-accel-buffering"] == "no"
    assert body.startswith("retry: 3000\n\n")
    evs, end, _ = parse(body)
    assert [i for i, _, _ in evs] == list(range(1, 8))
    for seq, payload, lines in evs:
        assert payload["seq"] == seq and len(lines) == 3   # one-line JSON
        assert set(payload["refs"]) == {"node_ids", "asset_ids", "finding_id",
                                        "exchange_ids"}
    assert end == {"status": "cancelled", "last_seq": 7}
    assert body.endswith(f'event: end\ndata: {json.dumps(end)}\n\n')


async def test_resume_after_and_header_wins(client, user_token, finished):
    _, body = await read(client, user_token, finished, params={"after": 4})
    assert [i for i, _, _ in parse(body)[0]] == [5, 6, 7]
    _, body = await read(client, user_token, finished, params={"after": 4},
                         headers={"Last-Event-ID": "6"})
    assert [i for i, _, _ in parse(body)[0]] == [7]
    _, body = await read(client, user_token, finished, headers={"Last-Event-ID": "7"})
    evs, end, _ = parse(body)
    assert evs == [] and end["last_seq"] == 7


async def test_bad_cursor_422(client, user_token, finished):
    for params, headers in [({"after": "x"}, None), ({"after": -1}, None),
                            (None, {"Last-Event-ID": "abc"}),
                            ({"after": 1}, {"Last-Event-ID": "-3"})]:
        r, _ = await read(client, user_token, finished, params, headers)
        assert r.status_code == 422, (params, headers)


async def test_non_owner_404_before_stream(client, user_token, session_maker, finished):
    other = await other_user_token(client, session_maker)
    r, body = await read(client, other, finished)
    assert r.status_code == 404 and "event-stream" not in r.headers["content-type"]
    assert "Not found" in body
    r, _ = await read(client, user_token, uuid.uuid4())
    assert r.status_code == 404


async def test_unknown_kind_passes_through(client, user_token, session_maker, finished):
    async with session_maker() as s:
        s.add(GreyboxEvent(run_id=finished, seq=8, kind="hint.added", level="info",
                           source="api", summary="hint", status="pending",
                           refs={}, data={"hint_id": "x"}))
        run = await s.get(GreyboxRun, finished)
        run.last_seq = 8
        await s.commit()
    _, body = await read(client, user_token, finished, params={"after": 6})
    evs, end, _ = parse(body)
    assert [p["kind"] for _, p, _ in evs] == ["run.cancelled", "hint.added"]
    assert evs[1][1]["refs"]["finding_id"] is None
    assert end["last_seq"] == 8


async def test_ping_and_max_lifetime(client, user_token, session_maker, monkeypatch):
    monkeypatch.setattr(api_events, "PING_S", 0.1)
    monkeypatch.setattr(api_events, "MAX_LIFETIME_S", 0.6)
    t = await create_target(client, user_token)
    run_id = (await start_run(client, user_token, t["id"])).json()["id"]
    r, body = await read(client, user_token, run_id, params={"after": 1})
    assert r.status_code == 200
    assert ": ping\n\n" in body
    evs, end, _ = parse(body)
    assert evs == [] and end is None   # clean close, no end frame: client reconnects


async def test_live_delivery_while_worker_runs(client, user_token, session_maker,
                                               live_target, target_server):
    r = await start_run(client, user_token, live_target["id"])
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    reader = asyncio.create_task(read(client, user_token, run_id))
    await asyncio.sleep(0.3)   # the stream is open before the engine starts
    assert str(await run_worker_once(session_maker)) == run_id
    resp, body = await asyncio.wait_for(reader, 30)
    assert resp.status_code == 200
    evs, end, frames = parse(body)
    seqs = [i for i, _, _ in evs]
    async with session_maker() as s:
        db = list((await s.scalars(select(GreyboxEvent.seq).where(
            GreyboxEvent.run_id == uuid.UUID(run_id)).order_by(GreyboxEvent.seq))).all())
    assert seqs == db == list(range(1, len(db) + 1))   # ordered, no gaps, no dupes
    assert evs[0][1]["kind"] == "run.queued"
    assert evs[-1][1]["kind"] in ("run.completed", "run.failed", "run.cancelled")
    assert end["last_seq"] == seqs[-1] and end["status"] in ("succeeded", "failed",
                                                             "cancelled")
    assert frames[-1].startswith("event: end")
