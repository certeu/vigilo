"""Regression (security assessment, 2026-11-20): a heartbeat without a cancel request
must not cancel the run. ``heartbeat()`` returns ``(ok, cancel_requested: bool)`` and
the supervisor used to test ``is not None``, so every run that outlived the first
heartbeat (``greybox_heartbeat_s``, 10 s by default) ended as ``cancelled (user)``."""
from __future__ import annotations

import uuid

from sqlalchemy import select

from src.greybox_web.models import GreyboxEvent, GreyboxRun
from src.webapi.settings import get_settings
from tests.greybox_web.conftest import FAST_LIMITS, create_target, run_worker_once, start_run


async def test_run_outliving_heartbeats_is_not_cancelled(client, user_token, session_maker,
                                                        target_server, monkeypatch):
    monkeypatch.setenv("VIGILO_GREYBOX_HEARTBEAT_S", "1")
    get_settings.cache_clear()
    # /slow blocks for 30 s; a 3 s request timeout keeps the run alive across
    # several 1 s heartbeats, then preflight fails it (nothing ever answered).
    t = await create_target(client, user_token, base_url=target_server.url + "slow",
                            limits={**FAST_LIMITS, "request_timeout_s": 3})
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    await run_worker_once(session_maker)

    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        kinds = (await s.scalars(select(GreyboxEvent.kind)
                                 .where(GreyboxEvent.run_id == run_id))).all()
    assert run.cancel_requested_at is None
    assert run.status != "cancelled", (run.status, run.end_reason)
    assert "run.cancelled" not in kinds
    assert run.status == "failed" and "Target unreachable" in (run.error_summary or "")


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
import pytest  # noqa: E402

pytestmark = pytest.mark.slow
