"""Run start/cancel/delete through the API.

Authorization confirmation, executor states, idempotency, per-target 409,
per-user 429, credential re-validation at start, queued-cancel, list/read
counters, deletion rules and preflight.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest

from tests.greybox_web.conftest import create_target, h, start_run, target_body


async def test_start_requires_confirmation(client, user_token, live_target):
    r = await client.post(f"/greybox/targets/{live_target['id']}/runs",
                          headers=h(user_token), json={})
    assert r.status_code == 422
    r = await client.post(f"/greybox/targets/{live_target['id']}/runs",
                          headers=h(user_token),
                          json={"authorization_confirmed": False})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "confirm" in str(detail).lower()


async def test_start_503_when_executor_off(client, user_token, live_target, set_env):
    set_env("VIGILO_GREYBOX_EXECUTOR", "off")
    r = await start_run(client, user_token, live_target["id"])
    assert r.status_code == 503
    assert r.json()["detail"] == "Grey-box executor is not running"


async def test_start_idempotent_same_key_same_run(client, user_token, live_target):
    key = f"retry-{uuid.uuid4().hex[:12]}"
    r1 = await start_run(client, user_token, live_target["id"], key=key)
    assert r1.status_code == 201
    r2 = await start_run(client, user_token, live_target["id"], key=key)
    assert r2.status_code == 200                     # not 201, not a second run
    assert r2.json()["id"] == r1.json()["id"]
    # a different key while a run is active -> 409 with the active run id
    r3 = await start_run(client, user_token, live_target["id"],
                         key=f"other-{uuid.uuid4().hex[:12]}")
    assert r3.status_code == 409
    assert r3.json()["run_id"] == r1.json()["id"]
    assert r3.json()["detail"] == "A run for this target is already active"


async def test_start_409_without_key_when_active(client, user_token, live_target):
    r1 = await start_run(client, user_token, live_target["id"])
    assert r1.status_code == 201
    r2 = await start_run(client, user_token, live_target["id"])
    assert r2.status_code == 409
    assert r2.json()["run_id"] == r1.json()["id"]


async def test_start_429_per_user_cap(client, user_token, target_server, set_env):
    set_env("VIGILO_GREYBOX_MAX_ACTIVE_RUNS_PER_USER", "1")
    t1 = await create_target(client, user_token, base_url=target_server.url)
    t2 = await create_target(client, user_token, base_url=target_server.url,
                             name="second")
    r1 = await start_run(client, user_token, t1["id"])
    assert r1.status_code == 201
    r2 = await start_run(client, user_token, t2["id"])
    assert r2.status_code == 429
    assert r2.json()["detail"] == "Too many active grey-box runs"


async def test_start_revalidates_credential(client, user_token, target_server):
    # A cookie credential that is deleted after the target was created must be
    # rejected at run start — SQLite does not enforce the FK.
    r = await client.post("/credentials", headers=h(user_token), json={
        "kind": "cookie_header", "label": "staging session",
        "secret": "session=abcdef123456"})
    assert r.status_code == 201, r.text
    cred = r.json()
    target = await create_target(client, user_token, base_url=target_server.url,
                                 credential_id=cred["id"])
    r = await client.delete(f"/credentials/{cred['id']}", headers=h(user_token))
    assert r.status_code == 204
    rr = await start_run(client, user_token, target["id"])
    assert rr.status_code == 422
    assert "credential" in str(rr.json()["detail"]).lower()


async def test_run_read_shape_and_counters(client, user_token, live_target,
                                           session_maker):
    from tests.greybox_web.conftest import run_worker_once
    key = f"shape-{uuid.uuid4().hex[:12]}"
    r = await start_run(client, user_token, live_target["id"], key=key)
    run = r.json()
    assert run["status"] == "queued"
    assert run["target"]["id"] == live_target["id"]
    assert run["target"]["name"] == "demo-app"
    assert run["owner_id"] == live_target["owner_id"]
    assert run["cancel_requested"] is False
    assert run["counters"]["events"] == 1
    assert run["counters"]["work_orders"]["pending"] == 0
    assert run["report_status"] == "pending"
    assert run["scope"]["allowed_hosts"] == ["127.0.0.1"]
    assert "checks" in run and isinstance(run["checks"], list)
    await run_worker_once(session_maker)
    r = await client.get(f"/greybox/runs/{run['id']}", headers=h(user_token))
    body = r.json()
    assert body["status"] == "succeeded"
    assert body["counters"]["events"] >= 20
    assert body["counters"]["requests"] >= 20
    assert body["counters"]["endpoints"] >= 5
    assert body["counters"]["assets"] > body["counters"]["endpoints"]
    assert body["counters"]["work_orders"]["done"] >= 15
    assert body["counters"]["work_orders"]["skipped"] == 0   # paused checks are never defaults
    assert body["counters"]["agents_active"] == 0
    assert body["report_status"] == "ready"
    assert body["last_event_at"] is not None
    assert body["phase"] == "reporting"


async def test_runs_list_filters_and_cursor(client, user_token, target_server):
    t = await create_target(client, user_token, base_url=target_server.url)
    r1 = await start_run(client, user_token, t["id"])
    r2 = await start_run(client, user_token, t["id"])
    assert r1.status_code == 201 and r2.status_code == 409
    r = await client.get("/greybox/runs", headers=h(user_token))
    page = r.json()
    assert page["items"], "at least the queued run"
    assert all(item["target"]["id"] == t["id"] for item in page["items"])
    r = await client.get("/greybox/runs", headers=h(user_token),
                         params={"status": "succeeded"})
    assert r.json()["items"] == []
    r = await client.get("/greybox/runs", headers=h(user_token),
                         params={"status": "queued,running,cancelling"})
    assert [i["status"] for i in r.json()["items"]] == ["queued"]
    r = await client.get("/greybox/runs", headers=h(user_token),
                         params={"target_id": str(uuid.uuid4())})
    assert r.json()["items"] == []


async def test_cancel_queued_run_completes_immediately(client, user_token,
                                                       target_server):
    t = await create_target(client, user_token, base_url=target_server.url)
    r = await start_run(client, user_token, t["id"])
    run_id = r.json()["id"]
    r = await client.post(f"/greybox/runs/{run_id}/cancel", headers=h(user_token),
                          json={"reason": "not now"})
    assert r.status_code == 202
    assert r.json()["status"] == "cancelled"
    # terminal -> further cancel 409
    r = await client.post(f"/greybox/runs/{run_id}/cancel", headers=h(user_token))
    assert r.status_code == 409
    assert r.json()["detail"] == "Run already finished"


async def test_delete_run_rules(client, user_token, target_server):
    t = await create_target(client, user_token, base_url=target_server.url)
    r = await start_run(client, user_token, t["id"])
    run_id = r.json()["id"]
    r = await client.delete(f"/greybox/runs/{run_id}", headers=h(user_token))
    assert r.status_code == 409                      # queued is not terminal
    await client.post(f"/greybox/runs/{run_id}/cancel", headers=h(user_token))
    r = await client.delete(f"/greybox/runs/{run_id}", headers=h(user_token))
    assert r.status_code == 204
    r = await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))
    assert r.status_code == 404


async def test_report_download_only_when_ready(client, user_token, live_target,
                                               session_maker):
    from tests.greybox_web.conftest import run_worker_once
    r = await start_run(client, user_token, live_target["id"],
                        key=f"rep-{uuid.uuid4().hex[:12]}")
    run_id = r.json()["id"]
    r = await client.get(f"/greybox/runs/{run_id}/report/download",
                         headers=h(user_token))
    assert r.status_code == 404
    await run_worker_once(session_maker)
    r = await client.get(f"/greybox/runs/{run_id}/report", headers=h(user_token))
    body = r.json()
    assert body["status"] == "ready"
    assert "Grey-box security assessment" in body["markdown"]
    r = await client.get(f"/greybox/runs/{run_id}/report/download",
                         headers=h(user_token))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert r.headers["content-disposition"] == \
        f'attachment; filename="greybox-report-{run_id[:8]}.md"'


async def test_preflight_one_guarded_get(client, user_token, live_target,
                                         target_server, session_maker):
    r = await client.post(f"/greybox/targets/{live_target['id']}/preflight",
                          headers=h(user_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["status_code"] == 200
    assert body["final_url"] == target_server.url
    assert body["blocked_reason"] is None
    assert "127.0.0.1" in body["resolved_ips"]
    assert 0 <= body["elapsed_ms"] < 2000
    # rate limited: 1 per 5 s per target
    r = await client.post(f"/greybox/targets/{live_target['id']}/preflight",
                          headers=h(user_token))
    assert r.status_code == 429
    # the preflight persists nothing: no run exists, so no exchanges can exist
    from sqlalchemy import func, select
    from src.greybox_web.models import GreyboxHttpExchange
    async with session_maker() as s:
        n = await s.scalar(select(func.count()).select_from(GreyboxHttpExchange))
    assert n == 0


async def test_start_refused_when_no_ai_model_configured(
        client, user_token, live_target, monkeypatch):
    from src.webapi.settings import get_settings
    monkeypatch.delenv("VIGILO_DEV_MODE")       # no fake backend, no provider keys
    get_settings.cache_clear()
    r = await start_run(client, user_token, live_target["id"])
    assert r.status_code == 409, r.text
    assert r.json()["detail"].startswith("No AI model configured for grey-box exploration")
