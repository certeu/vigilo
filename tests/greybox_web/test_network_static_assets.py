"""Static assets (build output, media) are kept as assets but are not attack surface:
the asset-graph coverage and the service surface count them separately."""
from __future__ import annotations

import uuid

from sqlalchemy import select

from src.greybox_web import surface as gb_surface
from src.greybox_web.graph import GraphStats, GraphTx
from src.greybox_web.models import GreyboxAsset
from tests.greybox_web.conftest import h
from tests.greybox_web.test_network_analysis import _graph, _service, run  # noqa: F401

STATIC_PATHS = [f"/_next/static/chunks/{i:016x}.js" for i in range(6)] + [
    "/_next/static/chunks/a.css", "/_next/static/media/f-s.p.3a6ba036.woff2", "/favicon.ico"]


async def _seed(session_maker, rid, *, finding_on: str | None = None):
    async with session_maker() as s:
        gtx = GraphTx(s, uuid.UUID(rid), GraphStats())
        svc = (await s.scalars(select(GreyboxAsset).where(
            GreyboxAsset.run_id == uuid.UUID(rid), GreyboxAsset.kind == "service",
            GreyboxAsset.in_scope.is_(True)))).first()
        for p in STATIC_PATHS:
            e = await gtx.asset("endpoint", f"{svc.key}{p}", p, in_scope=True, parent=svc)
            if p == finding_on:
                e.finding_count = 1
        await s.commit()
    return svc.id


async def test_coverage_and_surface_leave_static_assets_out(client, user_token, run,
                                                            session_maker):
    rid = run["id"]
    before = await _graph(client, user_token, rid)
    base = before["coverage"]
    await _seed(session_maker, rid)
    after = (await _graph(client, user_token, rid))["coverage"]
    assert after["in_scope_endpoints"] == base["in_scope_endpoints"]
    assert after["tested_endpoints"] == base["tested_endpoints"]
    assert after["static_endpoints"] == base["static_endpoints"] + len(STATIC_PATHS)

    async with session_maker() as s:
        gtx = GraphTx(s, uuid.UUID(rid), GraphStats())
        await gb_surface.refresh(s, gtx)
        await s.commit()
    g = await _graph(client, user_token, rid)
    ep = _service(g)["data"]["surface"]["endpoints"]
    assert ep["static"] >= len(STATIC_PATHS)
    stat = [n for n in g["nodes"] if n["kind"] == "endpoint" and n["label"] in STATIC_PATHS]
    assert len(stat) == len(STATIC_PATHS)
    assert all(n["data"]["surface"]["class"] in ("static", "media") for n in stat)
    assert ep["total"] + ep["static"] == sum(
        1 for n in g["nodes"] if n["kind"] == "endpoint" and n["in_scope"])


async def test_a_static_asset_with_a_finding_stays_in_the_surface(client, user_token, run,
                                                                  session_maker):
    rid = run["id"]
    base = (await _graph(client, user_token, rid))["coverage"]
    await _seed(session_maker, rid, finding_on="/_next/static/chunks/a.css")
    cov = (await _graph(client, user_token, rid))["coverage"]
    assert cov["in_scope_endpoints"] == base["in_scope_endpoints"] + 1
    assert cov["static_endpoints"] == base["static_endpoints"] + len(STATIC_PATHS) - 1
