"""Traffic list (filters, after_id pagination) and exchange detail."""
from __future__ import annotations

import json
import uuid

import pytest

from src.audit import redact
from tests.greybox_web.conftest import (
    create_target,
    h,
    other_user_token,
    run_worker_once,
    start_run,
)
from tests.greybox_web.test_redaction import NEEDLES, SECRET


@pytest.fixture
async def done_run(client, user_token, live_target, session_maker):
    r = await start_run(client, user_token, live_target["id"],
                        key=f"ta-{uuid.uuid4().hex[:12]}")
    assert r.status_code == 201, r.text
    await run_worker_once(session_maker)
    return (await client.get(f"/greybox/runs/{r.json()['id']}",
                             headers=h(user_token))).json()


async def _traffic(client, token, rid, **params):
    r = await client.get(f"/greybox/runs/{rid}/traffic", headers=h(token), params=params)
    assert r.status_code == 200, r.text
    return r.json()


async def test_list_filters_and_pagination(client, user_token, done_run):
    rid = done_run["id"]
    body = await _traffic(client, user_token, rid, limit=200)
    items = body["items"]
    assert items and body["capture"] == "enabled"
    ids = [i["id"] for i in items]
    assert ids == sorted(ids)
    assert {"method", "scheme", "host", "port", "path", "status_code", "tool", "blocked",
            "redirect_hop", "finding_ids", "agent_name"} <= set(items[0])

    # pagination with after_id walks every exchange exactly once
    seen, after, pages = [], None, 0
    while True:
        params = {"limit": 5, **({"after_id": after} if after is not None else {})}
        page = await _traffic(client, user_token, rid, **params)
        assert len(page["items"]) <= 5
        seen += [i["id"] for i in page["items"]]
        pages += 1
        after = page["next_after_id"]
        if after is None:
            break
        assert pages < 500
    assert seen == ids if len(ids) < 200 else seen[:200] == ids
    if len(ids) > 5:
        assert pages > 1

    first = items[0]
    only = (await _traffic(client, user_token, rid, method=first["method"].lower()))["items"]
    assert only and all(i["method"] == first["method"] for i in only)
    sc = next(i["status_code"] for i in items if i["status_code"] is not None)
    only = (await _traffic(client, user_token, rid, status_code=sc))["items"]
    assert only and all(i["status_code"] == sc for i in only)
    only = (await _traffic(client, user_token, rid, host=first["host"]))["items"]
    assert only
    assert (await _traffic(client, user_token, rid, host="nope.invalid"))["items"] == []
    only = (await _traffic(client, user_token, rid, path_prefix="/static"))["items"]
    assert all(i["path"].startswith("/static") for i in only)
    assert (await _traffic(client, user_token, rid, blocked="false"))["items"]
    assert all(i["blocked"] for i in
               (await _traffic(client, user_token, rid, blocked="true"))["items"])
    ag = next((i["agent_id"] for i in items if i["agent_id"]), None)
    if ag:
        only = (await _traffic(client, user_token, rid, agent_id=ag))["items"]
        assert only and all(i["agent_id"] == ag for i in only)
    wo = next((i["work_order_id"] for i in items if i["work_order_id"]), None)
    if wo:
        only = (await _traffic(client, user_token, rid, work_order_id=wo))["items"]
        assert only and all(i["work_order_id"] == wo for i in only)

    # finding_id filter
    linked = next(i for i in items if i["finding_ids"])
    fid = linked["finding_ids"][0]
    only = (await _traffic(client, user_token, rid, finding_id=fid))["items"]
    assert linked["id"] in [i["id"] for i in only]
    assert all(fid in i["finding_ids"] for i in only)

    # bounds
    for bad in ({"limit": 201}, {"limit": 0}, {"after_id": 2**63}, {"status_code": 2**63}):
        r = await client.get(f"/greybox/runs/{rid}/traffic", headers=h(user_token),
                             params=bad)
        assert r.status_code == 422, bad


async def test_exchange_detail(client, user_token, done_run):
    rid = done_run["id"]
    items = (await _traffic(client, user_token, rid, limit=200))["items"]
    summary = next(i for i in items if i["status_code"] == 200)
    r = await client.get(f"/greybox/runs/{rid}/traffic/{summary['id']}",
                         headers=h(user_token))
    assert r.status_code == 200, r.text
    x = r.json()
    assert x["id"] == summary["id"] and x["url"].startswith("http")
    for side in ("request", "response"):
        assert set(x[side]) == {"headers", "body", "body_truncated", "body_omitted_reason"}
        assert all(len(p) == 2 for p in x[side]["headers"])
    assert x["response"]["headers"]
    assert {"resolved_ip", "parent_exchange_id"} <= set(x)


async def test_acl_and_unknown(client, user_token, admin_token, done_run, session_maker):
    rid = done_run["id"]
    xid = (await _traffic(client, user_token, rid))["items"][0]["id"]
    other = await other_user_token(client, session_maker, "intruder@example.com")
    for path in ("/traffic", f"/traffic/{xid}"):
        r = await client.get(f"/greybox/runs/{rid}{path}", headers=h(other))
        assert r.status_code == 404 and r.json() == {"detail": "Not found"}
    for path in (f"/traffic/{xid + 10**6}", "/traffic/-1", f"/traffic/{2**70}"):
        r = await client.get(f"/greybox/runs/{rid}{path}", headers=h(user_token))
        assert r.status_code in (404, 422), path
    r = await client.get(f"/greybox/runs/{uuid.uuid4()}/traffic", headers=h(user_token))
    assert r.status_code == 404
    r = await client.get(f"/greybox/runs/{rid}/traffic/{xid}", headers=h(admin_token))
    assert r.status_code == 200


async def test_exchange_from_other_run_is_404(client, user_token, done_run, live_target,
                                              session_maker):
    r = await start_run(client, user_token, live_target["id"],
                        key=f"tb-{uuid.uuid4().hex[:12]}")
    await run_worker_once(session_maker)
    other_run = r.json()["id"]
    xid = (await _traffic(client, user_token, done_run["id"]))["items"][0]["id"]
    ids2 = [i["id"] for i in (await _traffic(client, user_token, other_run,
                                             limit=200))["items"]]
    if xid not in ids2:
        r = await client.get(f"/greybox/runs/{other_run}/traffic/{xid}",
                             headers=h(user_token))
        assert r.status_code == 404


async def test_secret_never_served(client, user_token, target_server, session_maker):
    r = await client.post("/credentials", headers=h(user_token), json={
        "kind": "cookie_header", "label": "staging session", "secret": SECRET})
    cred = r.json()
    t = await create_target(client, user_token, base_url=target_server.url,
                            credential_id=cred["id"])
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    rid = r.json()["id"]
    assert str(await run_worker_once(session_maker)) == rid
    try:
        blobs = []
        page = await _traffic(client, user_token, rid, limit=200)
        for s in page["items"]:
            d = await client.get(f"/greybox/runs/{rid}/traffic/{s['id']}",
                                 headers=h(user_token))
            blobs.append(d.text)
        blobs.append(json.dumps(page))
        fl = (await client.get(f"/greybox/runs/{rid}/findings", headers=h(user_token))).json()
        for f in fl["items"]:
            blobs.append((await client.get(f"/greybox/runs/{rid}/findings/{f['id']}",
                                           headers=h(user_token))).text)
        assert blobs and len(blobs) > 3
        for blob in blobs:
            for needle in NEEDLES:
                assert needle not in blob
        assert any('"Cookie"' in b and '"***"' in b for b in blobs)
    finally:
        redact.clear()


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
