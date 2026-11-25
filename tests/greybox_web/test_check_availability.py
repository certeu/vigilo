"""Catalogue checks that have no implementation are
flagged unavailable, never default, normalised out of a run's checks and recorded.
Every built-in check is implemented in this build, so the skip bookkeeping is
exercised by removing a check from the registry (the out-of-build stand-in)."""
from __future__ import annotations

import uuid

from sqlalchemy import select

from src.greybox_web import checks as gb_checks
from src.greybox_web import tools as gb_tools
from src.greybox_web.models import GreyboxEvent, GreyboxRun, GreyboxTarget
from tests.greybox_web.conftest import (
    FAST_LIMITS,
    create_target,
    h,
    run_worker_once,
    start_run,
)

# every catalogue check is implemented in this build: nothing is paused
PAUSED: set[str] = set()


def _drop_from_registry(monkeypatch, *tool_ids: str) -> None:
    """Simulate a check whose implementation is absent: availability is derived from
    the registry, so removing the ToolSpec is the whole out-of-build stand-in."""
    gb_tools.get("headers.security")            # force registry initialisation
    kept = {tid: spec for tid, spec in gb_tools._TOOLS.items()
            if tid not in set(tool_ids)}
    monkeypatch.setattr(gb_tools, "_TOOLS", kept)


async def test_config_flags_derived_from_registry(client, user_token):
    r = await client.get("/greybox/config", headers=h(user_token))
    assert r.status_code == 200
    checks = {c["id"]: c for c in r.json()["checks"]}
    for cid, c in checks.items():
        implemented = gb_tools.get(cid) is not None
        assert c["available"] is implemented, cid
        assert (c["unavailable_reason"] is None) is implemented, cid
        if not implemented:
            assert c["default_enabled"] is False, cid
    assert {cid for cid, c in checks.items() if not c["available"]} == set()
    assert checks["headers.security"]["available"] is True
    assert checks["headers.security"]["default_enabled"] is True
    assert checks["injection.reflection"]["available"] is True
    assert checks["injection.reflection"]["unavailable_reason"] is None
    assert checks["injection.reflection"]["default_enabled"] is True


async def test_availability_follows_registry(monkeypatch):
    from src.greybox_web.tools import ToolSpec
    base = gb_tools.get("headers.security")
    monkeypatch.setattr(gb_tools, "_TOOLS", {
        **{t: gb_tools.get(t) for t in ("headers.security",)},
        "injection.errors": ToolSpec("injection.errors", "check", base.run)})
    assert gb_checks.is_available("injection.errors")
    assert not gb_checks.is_available("cors.policy")
    assert "injection.errors" in gb_checks.default_selection()


def test_defaults_exclude_unavailable():
    # the pentest checks are implemented: the defaults include them…
    assert {"injection.reflection", "injection.errors", "redirect.open",
            "info.errors"} <= set(gb_checks.default_selection(False))
    # …but never a check the scope does not allow (auth testing narrowed off)
    assert "auth.default_creds" not in gb_checks.default_selection(False)
    assert "authz.object" not in gb_checks.default_selection(False)
    assert "auth.default_creds" not in gb_checks.resolve_checks(None, False)
    # authentication testing is the default: all auth checks are effective
    assert {"injection.reflection", "injection.errors", "redirect.open",
            "info.errors", "auth.default_creds", "authz.object"} <= \
        set(gb_checks.default_selection(True))
    assert {"injection.reflection", "auth.default_creds"} <= \
        set(gb_checks.resolve_checks(None, True))
    assert "headers.security" in gb_checks.resolve_checks(None, False)


async def test_target_with_unavailable_check_runs_and_records_skip(
        client, user_token, target_server, session_maker, monkeypatch):
    _drop_from_registry(monkeypatch, "injection.reflection")
    wanted = ["headers.security", "injection.reflection", "redirect.open"]
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS), checks=wanted)
    async with session_maker() as s:                   # stored as selected
        assert (await s.get(GreyboxTarget, uuid.UUID(t["id"]))).checks == wanted
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["checks"] == ["headers.security", "redirect.open"]
    expect = [{"id": "injection.reflection", "reason": "Not implemented in this build"}]
    assert body["skipped_checks"] == expect
    run_id = uuid.UUID(body["id"])
    assert await run_worker_once(session_maker) == run_id

    got = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert got["status"] == "succeeded" and got["skipped_checks"] == expect
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.checks == ["headers.security", "redirect.open"]
        ev = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id, GreyboxEvent.kind == "log.warning")
            .order_by(GreyboxEvent.seq))).all()
    assert ev and ev[0].level == "warning"
    assert "injection.reflection" in ev[0].summary
    assert ev[0].data["skipped_checks"] == expect
    # no work order was ever created for a removed check
    ev_all = await client.get(f"/greybox/runs/{run_id}/events", headers=h(user_token),
                              params={"kinds": "work_order.skipped", "limit": 200})
    assert ev_all.status_code == 200
    assert not [e for e in ev_all.json()["items"]
                if e["data"].get("tool") == "injection.reflection"]


async def test_default_run_has_no_skipped_checks(client, user_token, live_target):
    r = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    assert r.json()["skipped_checks"] == []
    # the implemented pentest checks are defaults — including the authentication
    # ones ("hardcore by default": a login form the crawl finds is tried against
    # the fixed default pairs even with no accounts linked)
    assert {"injection.reflection", "injection.errors", "redirect.open",
            "info.errors", "auth.default_creds", "authz.object"} <= \
        set(r.json()["checks"])


def test_report_lists_unregistered_checks_that_were_scheduled():
    from src.greybox_web.report import _unregistered_checks
    # every built-in check is registered in this build, so the "scheduled but
    # unregistered" path is exercised with a stand-in id no tool exists for
    assert _unregistered_checks(
        ["headers.security", "future.check"],
        {"future.check": {"skipped": 1}, "headers.security": {"done": 1}}
    ) == ["future.check"]
    # a removed check has no work orders: nothing to report as "not run"
    assert _unregistered_checks(["headers.security"], {}) == []


async def test_report_lists_checks_removed_at_run_start(client, user_token, session_maker,
                                                       target_server, monkeypatch):
    """A target that explicitly selected a check with no implementation (an
    out-of-build stand-in) gets it named in the report's coverage (it is removed from
    the run at start, so no work order exists)."""
    _drop_from_registry(monkeypatch, "injection.errors")
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS),
                            checks=["headers.security", "injection.errors"])
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    await run_worker_once(session_maker)
    rep = (await client.get(f"/greybox/runs/{run_id}/report", headers=h(user_token))).json()
    assert rep["status"] == "ready"
    line = next(l for l in rep["markdown"].splitlines()
                if l.startswith("- **Checks not run in this build:**"))
    assert "injection.errors" in line and "headers.security" not in line


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
import pytest  # noqa: E402

pytestmark = pytest.mark.slow
