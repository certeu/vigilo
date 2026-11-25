"""Phase 0 regression protection: failure modes found in a field assessment.

The review of a field assessment of a single-page application behind SSO found
that a modern single-page application was assessed as if it were a set of static
pages, that a third-party identity provider reached by redirect was analysed as
if it belonged to the target, and that the run declared itself complete while the
application's API had never been seen. Each defect below is pinned by a test
against a controlled fixture, so a refactor cannot reintroduce it silently.

Fixture: :mod:`tests.greybox_web.fixtures.spa_app` -- a JavaScript-driven
application whose pages, navigation and API calls only exist after script
execution, behind a login, with an object-level authorization weakness planted
for the agent to find.

The tests are ordered by the defect they pin:

1. JavaScript-driven content is invisible to the page fetcher (bundle and markup
   carry no links, so nothing is discovered and the run "completes").
2. A run that never saw the application's API must not claim a completed
   assessment.
3. Frontier truncation hides discoverable work behind a wall of build output.
4. Redirects are followed to a third party and analysed as the target.
5. A session that expired (redirect to an identity provider) is not reported.
6. Unsupported tool options fail silently.
7. Service metadata that was observed never reaches the report.
8. The same missing header on many URLs is reported many times.
"""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxEvent,
    GreyboxFinding,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxWorkOrder,
)
from tests.greybox_web.conftest import (
    FAST_LIMITS,
    create_target,
    h,
    run_worker_once,
    start_run,
)


async def _run(client, user_token, session_maker, url, *, limits=None, scope=None,
               checks=None):
    over: dict = {"base_url": url, "limits": dict(FAST_LIMITS, **(limits or {}))}
    if scope is not None:
        over["scope"] = scope
    if checks is not None:
        over["checks"] = checks
    t = await create_target(client, user_token, **over)
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    return run_id, body


async def _rows(session_maker, run_id, model, *where):
    async with session_maker() as s:
        return list((await s.scalars(
            select(model).where(model.run_id == run_id, *where))).all())


# --------------------------------------------------------------------- 1. SPA


async def test_spa_pages_api_calls_are_discovered(
        client, user_token, session_maker, spa_server):
    """(1) The application's pages exist only because JavaScript rendered them, and
    its API is only reachable through calls the bundle makes. A run that understands
    the application discovers the API endpoint and marks it as part of the surface."""
    run_id, body = await _run(client, user_token, session_maker, spa_server.url)
    assert body["status"] == "succeeded"
    assets = await _rows(session_maker, run_id, GreyboxAsset,
                         GreyboxAsset.kind == "endpoint")
    paths = {a.key.split("://", 1)[-1].split("/", 1)[-1].split("?")[0]
             for a in assets}
    assert "api/notes" in paths, sorted(paths)
    assert "dashboard" in paths and "settings" in paths, sorted(paths)


async def test_spa_api_is_not_declared_complete_untested(
        client, user_token, session_maker, spa_server):
    """(2) An unknown API endpoint is not a tested one. When the assessment ends
    without testing the API it found, it says so instead of reporting completion."""
    run_id, body = await _run(client, user_token, session_maker, spa_server.url)
    assert body["end_reason"] in ("completed", "partial", "stalled", "blocked",
                                  "needs_authorisation"), body["end_reason"]
    report = (await client.get(f"/greybox/runs/{run_id}/report",
                               headers=h(user_token))).json()
    md = report["markdown"] or ""
    if body["end_reason"] == "completed":
        # a completed run must have actually tested the API it discovered
        tested = [a for a in await _rows(session_maker, run_id, GreyboxAsset,
                                         GreyboxAsset.kind == "endpoint")
                  if a.tested and "/api/" in a.key]
        assert tested, "run completed without testing any discovered API endpoint"
    else:
        assert "not tested" in md.lower() or "untested" in md.lower()


# ----------------------------------------------------------------- 3. frontier


def test_frontier_truncation_hides_work_behind_build_output():
    """(3) The knowledge frontier is capped AFTER filtering build output, never
    before: a wall of hashed bundle URLs must not consume the whole list."""
    from src.greybox_web.exploration.knowledge import frontier_view

    noise = [f"https://app.test/_next/static/chunks/{i:x}aef{c}.js"
             for i, c in enumerate(range(40))]
    real = ["https://app.test/dashboard", "https://app.test/settings"]
    view = frontier_view([*noise, *real], cap=5)
    assert view[:2] == sorted(real), view


# --------------------------------------------------------------- 4. redirects


async def test_redirect_to_third_party_is_never_analysed_as_the_target(
        client, user_token, session_maker, idp_server, spa_server):
    """(4) A redirect out of scope is recorded, never followed, and the attribution
    of what was analysed stays on the target."""
    # the operator declares the identity provider as a deliberate redirect target:
    # the run must then never address a packet to it, and must say so.
    run_id, body = await _run(
        client, user_token, session_maker, idp_server.url + "app/",
        scope={"redirect_hosts": [idp_server.idp_host],
               "honor_declared_redirects": True})
    assert body["status"] == "succeeded"
    ex = await _rows(session_maker, run_id, GreyboxHttpExchange)
    # nothing was ever requested from the identity provider's login host: the hop
    # may be RECORDED as refused evidence, but no packet was addressed to it, so the
    # exchange carries no status code and no body.
    reached = [e for e in ex if (e.host or "").startswith("login.")
               and (e.status_code is not None or e.response_body)]
    assert not reached, sorted({(e.host, e.url, e.status_code) for e in reached})
    assert not [e for e in ex if e.blocked and e.block_reason != "declared_redirect"], \
        [(e.host, e.block_reason) for e in ex if e.blocked]
    # ... and the redirect is disclosed, not swallowed
    evs = await _rows(session_maker, run_id, GreyboxEvent, GreyboxEvent.kind == "auth.state")
    assert evs, "the redirect to the identity provider was not recorded"


# ------------------------------------------------------------ 5. session state


async def test_expired_session_is_reported_as_blocked_not_completed(
        client, user_token, session_maker, idp_server):
    """(5) A target that answers every page with a redirect to its identity provider
    has not been assessed: the run says it is blocked by authentication (and names
    the provider), it does not complete with a few header findings."""
    from src.webapi.models import Credential
    from src.webapi.security.vault import build_vault, generate_key
    import os
    # an operator-provided session that the application considers expired
    r = await client.post("/credentials", headers=h(user_token),
                          json={"kind": "cookie_header", "label": "expired session",
                                "secret": "session=stale-session-value"})
    assert r.status_code == 201, r.text
    cred_id = r.json()["id"]
    t = await create_target(client, user_token, base_url=idp_server.url + "app/",
                            limits=dict(FAST_LIMITS), credential_id=cred_id)
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "succeeded"
    assert body["end_reason"] in ("blocked", "needs_authorisation"), body["end_reason"]
    evs = await _rows(session_maker, run_id, GreyboxEvent, GreyboxEvent.kind == "auth.state")
    assert evs, "no auth.state event: the expired session was never noticed"
    assert "login" in json.dumps([e.data for e in evs]).lower()


# --------------------------------------------------------- 6. silent option


async def test_unsupported_tool_option_is_rejected_loudly(
        client, user_token, session_maker, target_server):
    """(6) ``netview.reexamine`` with an unsupported ``kind`` was accepted and
    answered "nothing to re-examine" -- indistinguishable from a clean result. The
    option is now validated at admission and refused with a reason."""
    from src.greybox_web.planner import Planner, PlannerState
    from src.greybox_web.planning import WorkOrderSpec
    from src.greybox_web.scope import ScopePolicy
    from src.greybox_web.graph import GraphStats, GraphTx

    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        scope = ScopePolicy.from_dict(run.scope)
        state = PlannerState(base_url=run.base_url, scope=scope,
                             checks=list(run.checks or []), max_pages=10)
        gtx = GraphTx(s, run_id, GraphStats())
        planner = Planner(run_id, state, uuid.uuid4())
        result = await planner.admit(
            s, gtx, WorkOrderSpec(tool="netview.reexamine",
                                  params={"kind": "endpoint", "needle": "/x"},
                                  reason="test"))
        assert type(result).__name__ == "Rejection", result
        assert result.reason == "invalid_option", result.reason
        ok = await planner.admit(
            s, gtx, WorkOrderSpec(tool="netview.reexamine",
                                  params={"kind": "leak", "needle": "10.0.0.1"},
                                  reason="test"))
        assert type(ok).__name__ != "Rejection", ok
        relative = await planner.admit(
            s, gtx, WorkOrderSpec(tool="discovery.fetch_root",
                                  params={"url": "/relative"}, reason="test"))
        assert type(relative).__name__ != "Rejection", relative
        assert relative.params["url"] == target_server.url.rstrip("/") + "/relative"


def test_reexamine_prompt_contract_matches_admission_options():
    from src.greybox_web.exploration.explorer import system_prompt
    from src.greybox_web.tools import get

    spec = get("netview.reexamine")
    assert spec is not None and spec.options is not None
    contract = f"kind: {'|'.join(spec.options['kind'])}"
    for mode in ("web", "network"):
        prompt = system_prompt(mode)
        assert f"netview.reexamine: {{{contract}, needle}}" in prompt
        assert "URL fragments (url), or response-body markers (body)" in prompt


# -------------------------------------------------------- 2/7. report quality


async def test_report_inventories_the_service_and_its_observed_metadata(
        client, user_token, session_maker, target_server):
    """(7) What the run observed about the service (server banner, technologies,
    cookies, redirect posture) reaches the report's inventory instead of leaving
    "Server: not disclosed" next to a page that disclosed it."""
    run_id, body = await _run(client, user_token, session_maker, target_server.url)
    md = ((await client.get(f"/greybox/runs/{run_id}/report",
                            headers=h(user_token))).json()["markdown"]) or ""
    assert "DemoServer" in md, md[:4000]


async def test_identical_header_findings_across_urls_are_one_finding(
        client, user_token, session_maker, target_server):
    """(8) Missing HSTS on every page of one service is one finding with several
    affected URLs, not one finding per URL."""
    run_id, body = await _run(client, user_token, session_maker, target_server.url)
    findings = await _rows(session_maker, run_id, GreyboxFinding)
    hsts = [f for f in findings if "Strict-Transport-Security" in f.title]
    assert len(hsts) <= 1, [(f.title, (f.location or {}).get("url")) for f in hsts]


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
