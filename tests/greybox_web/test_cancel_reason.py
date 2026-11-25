"""RunRead exposes who cancelled a run and why (UI header outcome line)."""
from __future__ import annotations

import uuid

from tests.greybox_web.conftest import FAST_LIMITS, create_target, h, start_run


async def test_run_read_reports_cancel_reason_and_actor(client, user_token, target_server):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = r.json()["id"]
    before = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert before["cancel_reason"] is None and before["cancelled_by"] is None

    c = await client.post(f"/greybox/runs/{run_id}/cancel", headers=h(user_token),
                          json={"reason": "Wrong environment"})
    assert c.status_code in (200, 202), c.text
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["cancel_reason"] == "Wrong environment"
    assert body["cancelled_by"] and "@" in body["cancelled_by"]
