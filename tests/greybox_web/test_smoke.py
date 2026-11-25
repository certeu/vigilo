"""First end-to-end smoke (kept as the shortest integration test): start a run
against the live synthetic target through the API, run one worker pass, and
assert the lifecycle result. The full assertions live in
``test_integration_synthetic.py``."""
from __future__ import annotations

import uuid

from tests.greybox_web.conftest import h, run_worker_once, start_run


async def test_smoke_run_to_completion(client, user_token, session_maker,
                                       live_target, target_server):
    r = await start_run(client, user_token, live_target["id"],
                        key=f"smoke-{uuid.uuid4().hex[:12]}")
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["status"] == "queued"
    assert run["counters"]["events"] == 1          # run.queued

    done = await run_worker_once(session_maker)
    assert str(done) == run["id"]

    r = await client.get(f"/greybox/runs/{run['id']}", headers=h(user_token))
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "succeeded", body.get("error_summary")
    assert body["end_reason"] == "completed"
    assert body["report_status"] == "ready"
    assert body["counters"]["events"] >= 10
    assert body["counters"]["requests"] > 10


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
import pytest  # noqa: E402

pytestmark = pytest.mark.slow
