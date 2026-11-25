"""Authorised access-control testing is on by default with operator identities, and
switching it off is visible — never a silent loss of coverage."""
from __future__ import annotations

import json

from src.greybox_web import coverage
from tests.greybox_web.conftest import create_target, h


async def _account(client, token, label):
    r = await client.post("/credentials", headers=h(token), json={
        "kind": "login_account", "label": label,
        "secret": json.dumps({"user": label, "password": label + "-pw"})})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_default_target_with_identities_runs_access_control_checks(
        client, user_token):
    ids = [await _account(client, user_token, n) for n in ("alice", "bob")]
    t = await create_target(client, user_token, base_url="http://127.0.0.1:18999/",
                            account_ids=ids)
    assert t["scope"]["allow_auth_testing"] is True
    assert "authz.object" in t["checks"] and "auth.default_creds" in t["checks"]
    assert len(t["accounts"]) == 2


async def test_disabling_auth_testing_with_accounts_is_warned_and_reported(
        client, user_token):
    ids = [await _account(client, user_token, "carol")]
    r = await client.post("/greybox/targets/validate", headers=h(user_token), json={
        "name": "t", "base_url": "http://127.0.0.1:18999/", "account_ids": ids,
        "scope": {"allow_auth_testing": False}})
    assert r.status_code == 200, r.text
    assert any("authentication testing" in w for w in r.json()["warnings"])
    from src.greybox_web import checks as gb_checks
    norm = r.json()["normalized"]
    resolved = gb_checks.resolve_checks(norm["checks"],
                                        norm["scope"]["allow_auth_testing"])
    assert "authz.object" not in resolved
    v = coverage.assess(coverage.CoverageInput(endpoints=1, endpoints_tested=1,
                                               accounts_unused=1))
    assert v.outcome == "needs_authorisation"
    assert "not tested" in v.reasons[0]
