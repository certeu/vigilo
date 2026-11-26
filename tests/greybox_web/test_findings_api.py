"""Findings list and detail against a full run on the synthetic target."""
from __future__ import annotations

import uuid

import pytest

from src.greybox_web.schemas import SEVERITIES
from tests.greybox_web.conftest import h, other_user_token, run_worker_once, start_run


@pytest.fixture
async def done_run(client, user_token, live_target, session_maker):
    r = await start_run(client, user_token, live_target["id"],
                        key=f"fa-{uuid.uuid4().hex[:12]}")
    assert r.status_code == 201, r.text
    await run_worker_once(session_maker)
    run = (await client.get(f"/greybox/runs/{r.json()['id']}", headers=h(user_token))).json()
    assert run["status"] == "succeeded"
    return run


async def _list(client, token, rid, **params):
    r = await client.get(f"/greybox/runs/{rid}/findings", headers=h(token), params=params)
    assert r.status_code == 200, r.text
    return r.json()["items"]


async def test_list_order_and_filters(client, user_token, done_run):
    rid = done_run["id"]
    items = await _list(client, user_token, rid)
    assert items
    ranks = [SEVERITIES.index(i["severity"]) for i in items]
    assert ranks == sorted(ranks)
    for i in items:
        assert {"id", "title", "severity", "status", "confidence", "check_id",
                "affected_asset", "agent_name", "evidence_count", "defense_count",
                "created_at", "updated_at"} <= set(i)
        assert i["evidence_count"] >= 1
    sev = items[0]["severity"]
    only = await _list(client, user_token, rid, severity=sev)
    assert only and all(i["severity"] == sev for i in only)
    ver = await _list(client, user_token, rid, status="verified")
    assert ver and all(i["status"] == "verified" for i in ver)
    assert await _list(client, user_token, rid, status="rejected") == []
    r = await client.get(f"/greybox/runs/{rid}/findings", headers=h(user_token),
                         params={"severity": "bogus"})
    assert r.status_code == 422
    assert any(i["affected_asset"] for i in items)
    assert any(i["defense_count"] for i in ver)


async def test_detail(client, user_token, done_run):
    rid = done_run["id"]
    ver = await _list(client, user_token, rid, status="verified")
    fid = ver[0]["id"]
    r = await client.get(f"/greybox/runs/{rid}/findings/{fid}", headers=h(user_token))
    assert r.status_code == 200, r.text
    f = r.json()
    assert f["id"] == fid and f["run_id"] == rid
    assert f["description"] and f["location"]["url"] and f["location"]["method"]
    assert f["evidence"] and f["evidence"][0]["excerpt"]
    assert f["evidence"][0]["role"] in ("baseline", "proof", "verification")
    assert f["verification"]["result"] == "confirmed"
    assert f["verification"]["method"]
    assert isinstance(f["detection_hints"], list) and isinstance(f["references"], list)
    assert f["provenance"]["agent_name"]
    assert isinstance(f["provenance"]["first_event_seq"], int)
    assert f["defense_ids"] and len(f["defense_ids"]) == ver[0]["defense_count"]
    nid = f["provenance"]["node_id"]
    assert nid
    g = (await client.get(f"/greybox/runs/{rid}/graph/exploration?limit=5000",
                          headers=h(user_token))).json()
    node = next(n for n in g["nodes"] if n["id"] == nid)
    assert node["kind"] == "finding" and node["finding_id"] == fid
    # detail exchange ids resolve in traffic
    xid = f["evidence"][0]["exchange_id"]
    if xid is not None:
        r = await client.get(f"/greybox/runs/{rid}/traffic/{xid}", headers=h(user_token))
        assert fid in r.json()["finding_ids"]


async def test_acl_and_unknown(client, user_token, admin_token, done_run, session_maker):
    rid = done_run["id"]
    fid = (await _list(client, user_token, rid))[0]["id"]
    other = await other_user_token(client, session_maker, "intruder@example.com")
    for path in ("/findings", f"/findings/{fid}"):
        r = await client.get(f"/greybox/runs/{rid}{path}", headers=h(other))
        assert r.status_code == 404 and r.json() == {"detail": "Not found"}
    r = await client.get(f"/greybox/runs/{rid}/findings/{uuid.uuid4()}",
                         headers=h(user_token))
    assert r.status_code == 404
    r = await client.get(f"/greybox/runs/{uuid.uuid4()}/findings", headers=h(user_token))
    assert r.status_code == 404
    # admin may read
    r = await client.get(f"/greybox/runs/{rid}/findings/{fid}", headers=h(admin_token))
    assert r.status_code == 200


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
