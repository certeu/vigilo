"""Cross-user isolation: targets part (M1), runs part (M2).

User B gets 404 on every target and run endpoint for user A's objects; an
admin gets 200. The run routes are exercised against a queued run (no worker
and no live target needed). Event, traffic and graph endpoints join in M3+.
"""
from __future__ import annotations

import uuid

from tests.greybox_web.conftest import (create_target, h, other_user_token,
                                        start_run, target_body)

# (method, path template, json body) for every M1 target route that takes an id.
TARGET_ROUTES = [
    ("GET", "/greybox/targets/{id}", None),
    ("PATCH", "/greybox/targets/{id}", {"name": "pwned"}),
    ("PATCH", "/greybox/targets/{id}", {"archived": True}),
    ("DELETE", "/greybox/targets/{id}", None),
]


async def _setup(client, user_token, session_maker):
    cred = await client.post("/credentials", headers=h(user_token), json={
        "kind": "cookie_header", "label": "a-session", "secret": "sid=A-ONLY-SECRET"})
    assert cred.status_code == 201
    t = await create_target(client, user_token, name="a-target",
                            credential_id=cred.json()["id"])
    b = await other_user_token(client, session_maker, "b@example.com")
    return t, cred.json()["id"], b


# (method, path template, json body) for every M2 run route that takes an id.
RUN_ROUTES = [
    ("GET", "/greybox/runs/{id}", None),
    ("POST", "/greybox/runs/{id}/cancel", {"reason": "pwned"}),
    ("DELETE", "/greybox/runs/{id}", None),
    ("GET", "/greybox/runs/{id}/report", None),
    ("GET", "/greybox/runs/{id}/report/download", None),
]


async def _setup_run(client, user_token, session_maker):
    """A queued run owned by A (TARGET_URL, no live server, no worker) + user B."""
    t = await create_target(client, user_token, name="a-run-target")
    r = await start_run(client, user_token, t["id"],
                        key=f"iso-{uuid.uuid4().hex[:12]}")
    assert r.status_code == 201, r.text
    b = await other_user_token(client, session_maker, "b@example.com")
    return t, r.json(), b


class TestRunIsolation:
    async def test_user_b_gets_404_on_every_run_route(self, client, user_token,
                                                      session_maker):
        t, run, b = await _setup_run(client, user_token, session_maker)
        for method, path, body in RUN_ROUTES:
            r = await client.request(method, path.format(id=run["id"]), headers=h(b),
                                     json=body)
            assert r.status_code == 404, (method, path, r.status_code)
            assert r.json() == {"detail": "Not found"}
        # lists filter by ownership instead of 404ing on a foreign target
        r = await client.get("/greybox/runs", headers=h(b),
                             params={"target_id": t["id"]})
        assert r.status_code == 200
        assert r.json()["items"] == []
        r = await client.get("/greybox/runs", headers=h(b))
        assert r.json()["items"] == []
        # nothing changed for A: the run is still there and still queued
        got = await client.get(f"/greybox/runs/{run['id']}", headers=h(user_token))
        assert got.status_code == 200
        assert got.json()["status"] == "queued"

    async def test_admin_gets_200(self, client, user_token, admin_token,
                                  session_maker):
        _, run, _ = await _setup_run(client, user_token, session_maker)
        got = await client.get(f"/greybox/runs/{run['id']}", headers=h(admin_token))
        assert got.status_code == 200, got.text
        assert got.json()["status"] == "queued"
        assert got.json()["report_status"] == "pending"   # no worker ran
        rep = await client.get(f"/greybox/runs/{run['id']}/report",
                               headers=h(admin_token))
        assert rep.status_code == 200
        assert rep.json() == {"status": "pending", "markdown": None,
                              "generated_at": None, "error": None}

    async def test_user_b_cannot_start_a_run_on_a_target(self, client, user_token,
                                                         session_maker):
        t, _, b = await _setup_run(client, user_token, session_maker)
        r = await client.post(f"/greybox/targets/{t['id']}/runs", headers=h(b),
                              json={"authorization_confirmed": True})
        assert r.status_code == 404
        assert r.json() == {"detail": "Not found"}


class TestTargetIsolation:
    async def test_user_b_gets_404_on_every_target_route(self, client, user_token,
                                                         session_maker):
        t, _, b = await _setup(client, user_token, session_maker)
        for method, path, body in TARGET_ROUTES:
            r = await client.request(method, path.format(id=t["id"]), headers=h(b), json=body)
            assert r.status_code == 404, (method, path, r.status_code)
            assert r.json() == {"detail": "Not found"}
        # nothing changed for A
        got = await client.get(f"/greybox/targets/{t['id']}", headers=h(user_token))
        assert got.status_code == 200
        assert got.json()["name"] == "a-target" and got.json()["archived"] is False

    async def test_lists_do_not_leak(self, client, user_token, session_maker):
        t, _, b = await _setup(client, user_token, session_maker)
        for archived in ("false", "true"):
            r = await client.get("/greybox/targets", headers=h(b),
                                 params={"archived": archived, "q": "a-target"})
            assert r.json()["items"] == []
        r = await client.get("/analyses", headers=h(b), params={"mode": "greybox"})
        assert r.json()["items"] == []

    async def test_user_b_cannot_use_a_credential(self, client, user_token, session_maker):
        _, cred_id, b = await _setup(client, user_token, session_maker)
        r = await client.post("/greybox/targets", headers=h(b),
                              json=target_body(credential_id=cred_id))
        assert r.status_code == 422
        assert {tuple(e["loc"]): e["msg"] for e in r.json()["detail"]}[
            ("body", "credential_id")] == "Unknown credential"
        v = await client.post("/greybox/targets/validate", headers=h(b),
                              json=target_body(credential_id=cred_id))
        assert v.json()["valid"] is False
        own = await create_target(client, b)
        r = await client.patch(f"/greybox/targets/{own['id']}", headers=h(b),
                               json={"credential_id": cred_id})
        assert r.status_code == 422

    async def test_admin_gets_200(self, client, user_token, admin_token, session_maker):
        t, _, _ = await _setup(client, user_token, session_maker)
        for method, path, body in TARGET_ROUTES:
            r = await client.request(method, path.format(id=t["id"]), headers=h(admin_token),
                                     json=body)
            assert r.status_code in (200, 204), (method, path, r.text)

    async def test_responses_never_contain_secrets(self, client, user_token, admin_token,
                                                   session_maker):
        t, _, _ = await _setup(client, user_token, session_maker)
        for tok in (user_token, admin_token):
            for path in (f"/greybox/targets/{t['id']}", "/greybox/targets", "/analyses"):
                r = await client.get(path, headers=h(tok))
                assert "A-ONLY-SECRET" not in r.text
