"""Planner rules and scope enforcement, asserted through the DB.

A run with selected checks only ever spawns those checks' work orders (plus
discovery, their verifications, and — batch E — any dynamic instrument the agent
itself composes and defines through the same admission: those are the agent's
own checks, not catalogue ones) — nothing leaks in. Target content cannot
expand the scope: an off-scope link becomes an out-of-scope asset, never a
request, while the /.env soft-404 control shows the exposure check did run on the
authorised host. Excluded paths are never requested yet are still recorded as
out of scope, and the run succeeds. A login form under an auth-testing scope
makes the model propose the default-credentials check; its work order
investigates the model's default-credentials lead and the login POSTs happen.
"""
from __future__ import annotations

import uuid

from sqlalchemy import func, select

from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxGraphNode,
    GreyboxHttpExchange,
    GreyboxWorkOrder,
)
from tests.greybox_web.conftest import (
    FAST_LIMITS,
    create_target,
    h,
    run_worker_once,
    start_run,
)


async def _run_to_completion(client, token, target_id, session_maker) -> dict:
    """Start the run with a unique idempotency key, run one worker pass to
    completion and return the run read body."""
    r = await start_run(client, token, target_id, key=f"plan-{uuid.uuid4().hex[:12]}")
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    assert str(await run_worker_once(session_maker)) == run_id
    r = await client.get(f"/greybox/runs/{run_id}", headers=h(token))
    body = r.json()
    assert body["status"] == "succeeded", body.get("error_summary")
    assert body["end_reason"] == "completed"
    return body


async def test_selected_checks_only(client, user_token, session_maker, target_server):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS), checks=["headers.security"])
    body = await _run_to_completion(client, user_token, t["id"], session_maker)
    assert body["checks"] == ["headers.security"]
    async with session_maker() as s:
        tools_seen = set((await s.scalars(select(GreyboxWorkOrder.tool).where(
            GreyboxWorkOrder.run_id == uuid.UUID(body["id"])))).all())
    allowed = {"discovery.fetch_root", "discovery.robots", "discovery.sitemap",
               "discovery.crawl", "headers.security", "verify.headers.security",
               # discovery of the API a page's client code names is discovery, not a
               # catalogue check
               "discovery.scripts",
               # ... and so is authoring a tool the catalogue lacks (Phase 3)
               "tool.compose", "tool.envelope-meta",
               "verify.tool.envelope-meta",
               # agent-defined instruments (batch E) are not catalogue checks: the
               # agent composes them when no fixed tool fits, whatever the run's
               # check selection — they pass the same admission (validation,
               # scope, budgets), not the catalogue-selection gate
               "tool.define", "dyn.header-reflection",
               "verify.dyn.header-reflection"}
    assert tools_seen <= allowed, sorted(tools_seen - allowed)
    assert {"discovery.fetch_root", "discovery.robots", "discovery.sitemap",
            "discovery.crawl", "headers.security"} <= tools_seen
    # the weaknesses are all there, but no other CATALOGUE check was planned
    # against them
    assert not tools_seen & {"headers.disclosure", "cors.policy", "cookies.flags",
                             "exposure.files", "exposure.dirlisting",
                             "injection.reflection", "auth.default_creds"}


async def test_content_cannot_expand_scope(client, user_token, session_maker,
                                           target_server):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS))
    body = await _run_to_completion(client, user_token, t["id"], session_maker)
    run = uuid.UUID(body["id"])
    async with session_maker() as s:
        hosts = set((await s.scalars(select(GreyboxHttpExchange.host).where(
            GreyboxHttpExchange.run_id == run))).all())
        evil = (await s.scalars(select(GreyboxAsset).where(
            GreyboxAsset.run_id == run, GreyboxAsset.kind == "endpoint",
            GreyboxAsset.key.like("http://evil.invalid%")))).all()
    # every request the run ever made stayed on the authorised host
    assert hosts and hosts <= {"127.0.0.1"}, hosts
    # the off-scope link on the root page became an asset — recorded and marked,
    # never requested
    assert len(evil) == 1
    assert evil[0].in_scope is False
    assert evil[0].state == "out_of_scope"
    # the exposure check did run on the target: /.env was probed (its soft-404
    # page is the negative control, so it yields no finding)
    assert target_server.counts().get("/.env", 0) >= 1


async def test_excluded_path_never_requested(client, user_token, session_maker,
                                             target_server):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS),
                            scope={"excluded_paths": ["/logout"]})
    body = await _run_to_completion(client, user_token, t["id"], session_maker)
    # /logout is linked from the root page but the scope guard keeps it unrequested
    assert target_server.counts().get("/logout", 0) == 0
    run = uuid.UUID(body["id"])
    async with session_maker() as s:
        logout = (await s.scalars(select(GreyboxAsset).where(
            GreyboxAsset.run_id == run, GreyboxAsset.kind == "endpoint",
            GreyboxAsset.key.like("%/logout")))).one()
    assert logout.in_scope is False
    assert logout.state == "out_of_scope"


async def test_login_lead_with_auth_testing(client, user_token, session_maker,
                                            target_server):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS),
                            scope={"allow_auth_testing": True})
    body = await _run_to_completion(client, user_token, t["id"], session_maker)
    # the check is implemented and the scope allows it: it is effective, and the
    # reactive model proposes it on the discovered login form
    assert "auth.default_creds" in body["checks"]
    run = uuid.UUID(body["id"])
    async with session_maker() as s:
        wos = (await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run,
            GreyboxWorkOrder.tool == "auth.default_creds"))).all()
        leads = (await s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run, GreyboxGraphNode.kind == "lead"))).all()
        posts = (await s.scalar(
            select(func.count()).select_from(GreyboxHttpExchange).where(
                GreyboxHttpExchange.run_id == run,
                GreyboxHttpExchange.method == "POST",
                GreyboxHttpExchange.path == "/login"))) or 0
    assert wos, "the model must propose the default-credentials check on the login form"
    assert all(w.status == "done" for w in wos)
    # the work order investigates the model's default-credentials lead
    lead = next(l for l in leads if "default credential" in l.label.lower())
    assert lead.key.startswith("lead:llm:")
    assert any(w.parent_node_id == lead.id for w in wos)
    assert "default" in str((lead.data or {}).get("hypothesis", "")).lower()
    # the login POSTs happened: an invalid baseline plus the fixed pairs (and
    # their verification) — never more than the check's own budget
    assert 2 <= posts <= 6, posts


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
import pytest  # noqa: E402

pytestmark = pytest.mark.slow
