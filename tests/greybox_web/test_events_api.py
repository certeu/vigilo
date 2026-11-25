"""Events history API."""
from __future__ import annotations

import uuid

import pytest

from src.greybox_web import events as gb_events
from src.greybox_web.models import GreyboxAgent
from tests.greybox_web.conftest import (create_target, h, other_user_token,
                                        start_run)

REF_KEYS = ("node_ids", "asset_ids", "finding_id", "exchange_ids")


@pytest.fixture
async def seeded(client, user_token, session_maker):
    t = await create_target(client, user_token)
    r = await start_run(client, user_token, t["id"])
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    agent_id, wo = uuid.uuid4(), uuid.uuid4()
    async with session_maker() as s:
        s.add(GreyboxAgent(id=agent_id, run_id=run_id, name="checker-1", role="checker"))
        await s.flush()
        for i in range(2, 12):   # seq 1 is run.queued
            if i == 5:
                await gb_events.emit(s, run_id, "tool.failed", "Boom FAILED here",
                                     agent_id=agent_id, work_order_id=wo,
                                     refs={"exchange_ids": [3]})
            elif i == 6:
                await gb_events.emit(s, run_id, "http.exchange", "GET /x")
            else:
                await gb_events.emit(s, run_id, "log.warning", f"warn {i}")
        await s.commit()
    return run_id, agent_id, wo


def url(run_id, suffix="events"):
    return f"/greybox/runs/{run_id}/{suffix}"


async def get(client, token, run_id, **params):
    return await client.get(url(run_id), headers=h(token), params=params)


async def test_tail_default_ascending_and_envelope(client, user_token, seeded):
    run_id, agent_id, _ = seeded
    r = await get(client, user_token, run_id)
    assert r.status_code == 200
    b = r.json()
    seqs = [e["seq"] for e in b["items"]]
    assert seqs == list(range(1, 12))
    assert b["last_seq"] == 11 and b["run_status"] == "queued"
    assert b["has_more_before"] is False and b["has_more_after"] is False
    first, failed = b["items"][0], b["items"][4]
    assert first["kind"] == "run.queued" and first["agent_name"] is None
    assert first["ts"].endswith("Z")
    for e in b["items"]:
        for k in REF_KEYS:
            assert k in e["refs"]
    assert failed["agent_name"] == "checker-1" and failed["agent_id"] == str(agent_id)
    assert failed["refs"]["exchange_ids"] == [3] and failed["refs"]["finding_id"] is None


async def test_tail_limit_has_more_before(client, user_token, seeded):
    r = await get(client, user_token, seeded[0], limit=3)
    b = r.json()
    assert [e["seq"] for e in b["items"]] == [9, 10, 11]
    assert b["has_more_before"] is True and b["has_more_after"] is False


async def test_after_seq(client, user_token, seeded):
    b = (await get(client, user_token, seeded[0], after_seq=4, limit=3)).json()
    assert [e["seq"] for e in b["items"]] == [5, 6, 7]
    assert b["has_more_after"] is True and b["has_more_before"] is True
    b = (await get(client, user_token, seeded[0], after_seq=11)).json()
    assert b["items"] == [] and b["last_seq"] == 11
    b = (await get(client, user_token, seeded[0], after_seq=0)).json()
    assert len(b["items"]) == 11 and b["has_more_before"] is False


async def test_before_seq_returns_latest_ascending(client, user_token, seeded):
    b = (await get(client, user_token, seeded[0], before_seq=8, limit=3)).json()
    assert [e["seq"] for e in b["items"]] == [5, 6, 7]
    assert b["has_more_before"] is True and b["has_more_after"] is True
    b = (await get(client, user_token, seeded[0], before_seq=3)).json()
    assert [e["seq"] for e in b["items"]] == [1, 2]
    assert b["has_more_before"] is False


async def test_both_cursors_422(client, user_token, seeded):
    r = await get(client, user_token, seeded[0], after_seq=1, before_seq=5)
    assert r.status_code == 422


async def test_limit_cap_and_validation(client, user_token, seeded):
    assert (await get(client, user_token, seeded[0], limit=1000)).status_code == 200
    assert (await get(client, user_token, seeded[0], limit=1001)).status_code == 422
    assert (await get(client, user_token, seeded[0], limit=0)).status_code == 422


async def test_filters(client, user_token, seeded):
    run_id, agent_id, wo = seeded
    b = (await get(client, user_token, run_id, kinds="tool.failed,http.exchange")).json()
    assert [e["kind"] for e in b["items"]] == ["tool.failed", "http.exchange"]
    b = (await get(client, user_token, run_id, agent_id=str(agent_id))).json()
    assert [e["seq"] for e in b["items"]] == [5]
    b = (await get(client, user_token, run_id, work_order_id=str(wo))).json()
    assert [e["seq"] for e in b["items"]] == [5]
    b = (await get(client, user_token, run_id, level="error")).json()
    assert [e["kind"] for e in b["items"]] == ["tool.failed"]
    b = (await get(client, user_token, run_id, level="warning")).json()
    assert {e["kind"] for e in b["items"]} == {"tool.failed", "log.warning"}
    b = (await get(client, user_token, run_id, level="info")).json()
    assert "http.exchange" not in {e["kind"] for e in b["items"]}
    b = (await get(client, user_token, run_id, q="boom failed")).json()
    assert [e["seq"] for e in b["items"]] == [5]
    assert (await get(client, user_token, run_id, q="100%")).json()["items"] == []
    assert (await get(client, user_token, run_id, level="loud")).status_code == 422


async def test_non_owner_404_admin_200(client, user_token, admin_token, session_maker,
                                       seeded):
    other = await other_user_token(client, session_maker)
    assert (await get(client, other, seeded[0])).status_code == 404
    assert (await get(client, admin_token, seeded[0])).status_code == 200
    assert (await get(client, user_token, uuid.uuid4())).status_code == 404


async def test_requires_auth(client, seeded):
    assert (await client.get(url(seeded[0]))).status_code == 401
