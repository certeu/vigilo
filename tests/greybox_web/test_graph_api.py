"""Exploration graph (snapshot, delta, truncation, focus), node
drawer, asset graph with coverage, asset detail, ACL and limits."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxAssetEdge,
    GreyboxGraphEdge,
    GreyboxGraphNode,
)
from tests.greybox_web.conftest import h, other_user_token, start_run


@pytest.fixture
async def done_run(client, user_token, live_target, session_maker):
    from tests.greybox_web.conftest import run_worker_once
    r = await start_run(client, user_token, live_target["id"])
    assert r.status_code == 201, r.text
    await run_worker_once(session_maker)
    run = (await client.get(f"/greybox/runs/{r.json()['id']}",
                            headers=h(user_token))).json()
    assert run["status"] == "succeeded"
    return run


async def _get(client, token, run_id, path, **params):
    return await client.get(f"/greybox/runs/{run_id}{path}", headers=h(token),
                            params=params)


async def _count(session_maker, model, run_id):
    async with session_maker() as s:
        return int(await s.scalar(select(func.count()).select_from(model).where(
            model.run_id == uuid.UUID(run_id))))


async def test_snapshot_shape_and_counts(client, user_token, done_run, session_maker):
    rid = done_run["id"]
    r = await _get(client, user_token, rid, "/graph/exploration")
    assert r.status_code == 200, r.text
    g = r.json()
    assert g["full"] is True and g["since_version"] == 0 and g["truncated"] is False
    assert g["version"] == done_run["graph_version"] > 0
    n_nodes = await _count(session_maker, GreyboxGraphNode, rid)
    n_edges = await _count(session_maker, GreyboxGraphEdge, rid)
    assert g["total_nodes"] == len(g["nodes"]) == n_nodes > 0
    assert g["total_edges"] == len(g["edges"]) == n_edges > 0
    ids = {n["id"] for n in g["nodes"]}
    for e in g["edges"]:
        assert e["src"] in ids and e["dst"] in ids
        assert e["rel"] and e["version"] <= g["version"]
    kinds = {n["kind"] for n in g["nodes"]}
    assert {"objective", "work_order", "action"} <= kinds
    for n in g["nodes"]:
        assert n["created_version"] <= n["version"] <= g["version"]
        assert len(n["exchange_ids"]) <= 20
        assert isinstance(n["data"], dict)
    assert g["agents"] and {"id", "name", "role"} == set(g["agents"][0])
    agent_names = {a["id"]: a["name"] for a in g["agents"]}
    assert any(n["agent_name"] for n in g["nodes"])
    for n in g["nodes"]:
        if n["agent_id"]:
            assert n["agent_name"] == agent_names[n["agent_id"]]
    assert any(n["exchange_ids"] for n in g["nodes"] if n["kind"] == "action")
    # work orders that ran carry an explicit outcome
    assert any(n["outcome"] for n in g["nodes"] if n["kind"] == "work_order")


async def test_delta_returns_only_newer_upserts(client, user_token, done_run):
    rid = done_run["id"]
    full = (await _get(client, user_token, rid, "/graph/exploration")).json()
    mid = full["version"] // 2
    assert mid > 0
    d = (await _get(client, user_token, rid, "/graph/exploration",
                    since_version=mid)).json()
    assert d["full"] is False and d["since_version"] == mid
    want = {n["id"] for n in full["nodes"] if n["version"] > mid}
    assert {n["id"] for n in d["nodes"]} == want and want
    assert all(n["version"] > mid for n in d["nodes"])
    assert {e["id"] for e in d["edges"]} == \
        {e["id"] for e in full["edges"] if e["version"] > mid}
    # delta edge guarantee: each endpoint is returned or was known at `mid`
    known = {n["id"] for n in full["nodes"] if n["created_version"] <= mid}
    ids = {n["id"] for n in d["nodes"]}
    for e in d["edges"]:
        assert e["src"] in ids | known and e["dst"] in ids | known
    # nothing newer than the current version
    d2 = (await _get(client, user_token, rid, "/graph/exploration",
                     since_version=full["version"])).json()
    assert d2["nodes"] == [] and d2["edges"] == [] and d2["truncated"] is False


async def test_truncation(client, user_token, done_run):
    rid = done_run["id"]
    full = (await _get(client, user_token, rid, "/graph/exploration")).json()
    r = await _get(client, user_token, rid, "/graph/exploration", limit=5)
    g = r.json()
    assert g["truncated"] is True and len(g["nodes"]) == 5
    order = sorted(full["nodes"], key=lambda n: (n["version"], n["id"]))[:5]
    assert [n["id"] for n in g["nodes"]] == [n["id"] for n in order]
    assert sum(g["truncated_by_kind"].values()) == full["total_nodes"] - 5
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["src"] in ids and e["dst"] in ids for e in g["edges"])
    assert g["total_nodes"] == full["total_nodes"]


async def test_limit_above_max_rejected(client, user_token, done_run):
    for path in ("/graph/exploration", "/graph/assets"):
        r = await _get(client, user_token, done_run["id"], path, limit=5001)
        assert r.status_code == 422
        r = await _get(client, user_token, done_run["id"], path, limit=5000)
        assert r.status_code == 200
    r = await _get(client, user_token, done_run["id"], "/graph/exploration", hops=4,
                   focus=str(uuid.uuid4()))
    assert r.status_code == 422


async def test_focus_neighbourhood(client, user_token, done_run):
    rid = done_run["id"]
    full = (await _get(client, user_token, rid, "/graph/exploration")).json()
    wo = next(n for n in full["nodes"] if n["kind"] == "work_order")
    adj: dict[str, set] = {}
    for e in full["edges"]:
        adj.setdefault(e["src"], set()).add(e["dst"])
        adj.setdefault(e["dst"], set()).add(e["src"])

    def hood(h_):
        seen, fr = {wo["id"]}, {wo["id"]}
        for _ in range(h_):
            fr = {x for f in fr for x in adj.get(f, ())} - seen
            seen |= fr
        return seen

    for hops in (1, 2, 3):
        g = (await _get(client, user_token, rid, "/graph/exploration",
                        focus=wo["id"], hops=hops)).json()
        assert {n["id"] for n in g["nodes"]} == hood(hops)
        ids = {n["id"] for n in g["nodes"]}
        assert all(e["src"] in ids and e["dst"] in ids for e in g["edges"])
        assert g["total_nodes"] == full["total_nodes"]
    g1 = (await _get(client, user_token, rid, "/graph/exploration", focus=wo["id"])).json()
    assert len(g1["nodes"]) < full["total_nodes"]
    r = await _get(client, user_token, rid, "/graph/exploration",
                   focus=str(uuid.uuid4()))
    assert r.status_code == 404


async def test_node_drawer(client, user_token, done_run):
    rid = done_run["id"]
    full = (await _get(client, user_token, rid, "/graph/exploration")).json()
    by_id = {n["id"]: n for n in full["nodes"]}
    wo = next(n for n in full["nodes"] if n["kind"] == "work_order"
              and any(e["src"] == n["id"] and by_id[e["dst"]]["kind"] == "action"
                      for e in full["edges"]))
    r = await _get(client, user_token, rid, f"/graph/exploration/nodes/{wo['id']}")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["node"]["id"] == wo["id"]
    assert {e["id"] for e in d["in_edges"]} == \
        {e["id"] for e in full["edges"] if e["dst"] == wo["id"]}
    assert {e["id"] for e in d["out_edges"]} == \
        {e["id"] for e in full["edges"] if e["src"] == wo["id"]}
    assert len(d["neighbours"]) == len(d["in_edges"]) + len(d["out_edges"])
    assert {n["id"] for n in d["neighbours"]} <= set(by_id)
    assert d["work_order"] is not None and d["work_order"]["status"] == wo["status"]
    assert d["agent_name"] == wo["agent_name"]
    assert len(d["exchanges"]) <= 50
    assert [x["id"] for x in d["exchanges"]] == wo["exchange_ids"] or \
        len(wo["exchange_ids"]) == 20
    # an action node lists the exchanges of its tool call
    act = next(n for n in full["nodes"] if n["kind"] == "action" and n["exchange_ids"])
    da = (await _get(client, user_token, rid,
                     f"/graph/exploration/nodes/{act['id']}")).json()
    assert [x["id"] for x in da["exchanges"]] == act["exchange_ids"]
    assert all(x["host"] and x["method"] for x in da["exchanges"])
    # finding nodes link their finding
    fnd = next((n for n in full["nodes"] if n["kind"] == "finding"), None)
    if fnd:
        df = (await _get(client, user_token, rid,
                         f"/graph/exploration/nodes/{fnd['id']}")).json()
        assert df["finding"]["id"] == fnd["finding_id"]


async def test_assets_graph_and_coverage(client, user_token, done_run, session_maker):
    rid = done_run["id"]
    r = await _get(client, user_token, rid, "/graph/assets")
    assert r.status_code == 200, r.text
    g = r.json()
    assert g["full"] is True and g["truncated"] is False
    assert len(g["nodes"]) == g["total_nodes"] == \
        await _count(session_maker, GreyboxAsset, rid)
    assert len(g["edges"]) == await _count(session_maker, GreyboxAssetEdge, rid)
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["src"] in ids and e["dst"] in ids for e in g["edges"])
    eps = [n for n in g["nodes"] if n["kind"] == "endpoint" and n["in_scope"]]
    cov = g["coverage"]
    # coverage excludes static assets (build output is not surface) and counts them
    # separately; every other in-scope endpoint is surface
    from src.greybox_web import assetclass
    from src.greybox_web.surface import endpoint_class
    from src.greybox_web.models import GreyboxAsset as _A
    async with session_maker() as _s:
        rows = {str(a.id): a for a in (await _s.scalars(
            select(_A).where(_A.run_id == uuid.UUID(rid)))).all()}
    non_static = [n for n in eps if not rows[n["id"]].finding_count
                  and assetclass.is_static_like(endpoint_class(rows[n["id"]]))]
    assert cov["in_scope_endpoints"] == len(eps) - len(non_static) >= 5
    assert cov["static_endpoints"] == len(non_static)
    assert cov["tested_endpoints"] == len([n for n in eps if n["tested"]])
    assert 0 < cov["tested_endpoints"] <= cov["in_scope_endpoints"]
    assert "completed" in cov["definition"]
    for n in g["nodes"]:
        if not n["in_scope"]:
            assert n["state"] == "out_of_scope"
        elif n["finding_count"]:
            assert n["state"] == "finding_linked"
        else:
            assert n["state"] == ("tested" if n["tested"] else "in_scope")
    # delta + truncation
    mid = g["version"] // 2
    d = (await _get(client, user_token, rid, "/graph/assets", since_version=mid)).json()
    assert d["full"] is False
    assert {n["id"] for n in d["nodes"]} == \
        {n["id"] for n in g["nodes"] if n["version"] > mid}
    assert d["coverage"] == cov
    t = (await _get(client, user_token, rid, "/graph/assets", limit=3)).json()
    assert t["truncated"] and len(t["nodes"]) == 3
    assert sum(t["truncated_by_kind"].values()) == g["total_nodes"] - 3
    tids = {n["id"] for n in t["nodes"]}
    assert all(e["src"] in tids and e["dst"] in tids for e in t["edges"])


async def test_asset_detail(client, user_token, done_run):
    rid = done_run["id"]
    g = (await _get(client, user_token, rid, "/graph/assets")).json()
    ep = next(n for n in g["nodes"] if n["kind"] == "endpoint" and n["tested"])
    r = await _get(client, user_token, rid, f"/assets/{ep['id']}")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["id"] == ep["id"] and d["key"] == ep["key"]
    assert d["work_orders"] and all(w["asset"]["id"] == ep["id"] for w in d["work_orders"])
    assert d["children_count"] == len([n for n in g["nodes"] if n["parent_id"] == ep["id"]])
    assert d["exchanges"] and all(x["path"] for x in d["exchanges"])
    assert len(d["exchanges"]) <= 50
    host = next(n for n in g["nodes"] if n["kind"] == "host")
    dh = (await _get(client, user_token, rid, f"/assets/{host['id']}")).json()
    assert dh["children_count"] >= 1
    linked = next((n for n in g["nodes"] if n["finding_count"]), None)
    if linked:
        dl = (await _get(client, user_token, rid, f"/assets/{linked['id']}")).json()
        assert len(dl["findings"]) == linked["finding_count"]


async def test_acl_and_not_found(client, user_token, done_run, session_maker, set_env):
    rid = done_run["id"]
    full = (await _get(client, user_token, rid, "/graph/exploration")).json()
    node_id = full["nodes"][0]["id"]
    asset_id = (await _get(client, user_token, rid, "/graph/assets")).json()["nodes"][0]["id"]
    paths = ["/graph/exploration", "/graph/assets",
             f"/graph/exploration/nodes/{node_id}", f"/assets/{asset_id}"]
    other = await other_user_token(client, session_maker)
    for p in paths:
        r = await _get(client, other, rid, p)
        assert r.status_code == 404 and r.json() == {"detail": "Not found"}
    ghost = str(uuid.uuid4())
    for p in paths:
        assert (await _get(client, user_token, ghost, p)).status_code == 404
    for p in (f"/graph/exploration/nodes/{ghost}", f"/assets/{ghost}"):
        assert (await _get(client, user_token, rid, p)).status_code == 404
    # a node id from another path kind does not resolve
    assert (await _get(client, user_token, rid, f"/assets/{node_id}")).status_code == 404
    assert (await client.get(f"/greybox/runs/{rid}/graph/exploration")).status_code == 401
    set_env("VIGILO_GREYBOX_WEB_ENABLED", "false")
    for p in paths:
        assert (await _get(client, user_token, rid, p)).status_code == 404


async def test_admin_can_read(client, admin_token, done_run):
    r = await _get(client, admin_token, done_run["id"], "/graph/exploration")
    assert r.status_code == 200 and r.json()["nodes"]


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
