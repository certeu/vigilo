"""Grey-box targets API: config, validate, CRUD, ACL, feature flag."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.models import GreyboxRun, GreyboxTarget
from tests.greybox_web.conftest import (
    TARGET_URL,
    create_target,
    h,
    other_user_token,
    start_run,
    target_body,
    user_id,
)


def _locs(resp) -> dict:
    assert resp.status_code == 422, resp.text
    return {tuple(e["loc"]): e["msg"] for e in resp.json()["detail"]}


async def _cookie_cred(client, token, kind="cookie_header", label="staging session",
                       secret="session=SUPERSECRETCOOKIE"):
    r = await client.post("/credentials", headers=h(token),
                          json={"kind": kind, "label": label, "secret": secret})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _add_run(session_maker, target_id, owner_id, status="succeeded"):
    async with session_maker() as s:
        t = await s.get(GreyboxTarget, uuid.UUID(target_id))
        run = GreyboxRun(target_id=t.id, owner_id=owner_id, status=status,
                         base_url=t.base_url, scope=t.scope, limits=t.limits, checks=[])
        s.add(run)
        await s.commit()
        return run.id


class TestConfig:
    async def test_config_shape(self, client, user_token):
        r = await client.get("/greybox/config", headers=h(user_token))
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is True
        assert body["executor"] == "worker"
        assert body["allow_private_targets"] is True
        ids = [c["id"] for c in body["checks"]]
        assert "headers.security" in ids and "auth.default_creds" in ids
        auth = next(c for c in body["checks"] if c["id"] == "auth.default_creds")
        # Authentication testing is on by default (operator decision 2026-11-21):
        # both auth checks are default-enabled and gated only by the scope flag.
        assert auth == {**auth, "default_enabled": True, "requires_auth_testing": True}
        authz = next(c for c in body["checks"] if c["id"] == "authz.object")
        assert authz == {**authz, "default_enabled": True, "requires_auth_testing": True}
        assert authz["area"] == "Authorization"
        assert "expected access" in authz["evidence"]
        assert body["limits"]["defaults"] == {
            "max_requests": 5000, "max_duration_s": 3600, "max_concurrency": 4,
            "rate_limit_rps": 10, "request_timeout_s": 10, "max_pages": 2000}
        assert body["limits"]["max"]["max_requests"] == 50000
        assert body["limits"]["max"]["max_duration_s"] == 28800
        assert body["limits"]["max"]["max_pages"] == 20000

    async def test_config_requires_auth(self, client):
        assert (await client.get("/greybox/config")).status_code == 401


class TestFeatureFlag:
    async def test_disabled_routes_404_config_reports_disabled(self, client, user_token,
                                                               set_env):
        t = await create_target(client, user_token)
        set_env("VIGILO_GREYBOX_WEB_ENABLED", "false")
        cfg = await client.get("/greybox/config", headers=h(user_token))
        assert cfg.status_code == 200 and cfg.json()["enabled"] is False
        for method, path, body in [
            ("GET", "/greybox/targets", None),
            ("POST", "/greybox/targets", target_body()),
            ("POST", "/greybox/targets/validate", target_body()),
            ("GET", f"/greybox/targets/{t['id']}", None),
            ("PATCH", f"/greybox/targets/{t['id']}", {"name": "x"}),
            ("DELETE", f"/greybox/targets/{t['id']}", None),
        ]:
            r = await client.request(method, path, headers=h(user_token), json=body)
            assert r.status_code == 404, (method, path, r.text)
            assert r.json() == {"detail": "Not found"}

    async def test_default_is_disabled(self, monkeypatch):
        monkeypatch.delenv("VIGILO_GREYBOX_WEB_ENABLED", raising=False)
        monkeypatch.delenv("VIGILO_GREYBOX_ALLOW_PRIVATE_TARGETS", raising=False)
        from src.webapi.settings import Settings
        s = Settings(_env_file=None)
        assert s.greybox_web_enabled is False
        assert s.greybox_allow_private_targets is False
        assert s.greybox_executor == "worker"


class TestCreate:
    async def test_create_without_repository(self, client, user_token, session_maker):
        r = await client.post("/greybox/targets", headers=h(user_token), json=target_body(
            description="Staging shop", scope={"excluded_paths": ["/logout"]},
            limits={"max_requests": 50}, checks=["headers.security", "cors.policy"]))
        assert r.status_code == 201, r.text
        t = r.json()
        assert t["base_url"] == TARGET_URL
        assert t["owner_id"] == str(await user_id(session_maker, "user@example.com"))
        assert t["scope"] == {
            "allowed_hosts": ["127.0.0.1"], "allowed_schemes": ["http"],
            "allowed_ports": [43123], "path_prefixes": ["/"], "excluded_paths": ["/logout"],
            "redirect_policy": "in_scope", "allow_auth_testing": True}
        assert "Paths: / (excluding /logout)" in t["scope_summary"]
        assert t["limits"]["max_requests"] == 50 and t["limits"]["max_pages"] == 2000
        assert t["checks"] == ["headers.security", "cors.policy"]
        assert t["credential"] is None and t["accounts"] == [] \
            and t["last_run"] is None and t["archived"] is False
        assert set(t) == {"id", "owner_id", "name", "description", "base_url", "scope",
                          "scope_summary", "limits", "checks", "credential", "accounts",
                          "egress_proxy_id", "model_backend", "model",
                          "assessment_mode", "capabilities",
                          "archived", "created_at", "updated_at", "last_run"}
        assert t["assessment_mode"] == "web" and t["capabilities"] == []

    async def test_legacy_crawl_depth_is_accepted_and_dropped(self, client, user_token,
                                                              session_maker):
        """Crawl depth no longer exists: old clients still sending it do not 422, and
        targets stored with it keep working (read, patch, run)."""
        r = await client.post("/greybox/targets", headers=h(user_token), json=target_body(
            limits={"max_requests": 50, "max_crawl_depth": 3}))
        assert r.status_code == 201, r.text
        t = r.json()
        assert "max_crawl_depth" not in t["limits"]
        async with session_maker() as s:       # a row written before the removal
            row = await s.get(GreyboxTarget, uuid.UUID(t["id"]))
            row.limits = {**row.limits, "max_crawl_depth": 3}
            await s.commit()
        got = await client.get(f"/greybox/targets/{t['id']}", headers=h(user_token))
        assert got.status_code == 200, got.text
        assert "max_crawl_depth" not in got.json()["limits"]
        p = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                               json={"limits": {"max_pages": 30}})
        assert p.status_code == 200, p.text
        assert p.json()["limits"]["max_pages"] == 30
        run = await start_run(client, user_token, t["id"])
        assert run.status_code == 201, run.text
        assert "max_crawl_depth" not in run.json()["limits"]

    async def test_model_choice_round_trips_and_is_validated(self, client, user_token):
        t = await create_target(client, user_token)
        assert t["model_backend"] is None and t["model"] is None     # server default
        t = await create_target(client, user_token, model_backend="fake",
                                model="fake-explorer", name="m")
        assert (t["model_backend"], t["model"]) == ("fake", "fake-explorer")
        got = await client.get(f"/greybox/targets/{t['id']}", headers=h(user_token))
        assert got.json()["model_backend"] == "fake"
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                               json={"model_backend": None, "model": None})
        assert r.status_code == 200, r.text
        assert r.json()["model_backend"] is None
        bad = await client.post("/greybox/targets", headers=h(user_token),
                                json=target_body(model_backend="chaos"))
        assert bad.status_code == 422
        bad = await client.post("/greybox/targets", headers=h(user_token),
                                json=target_body(model_backend="fake", model="gpt-x"))
        assert bad.status_code == 422
        bad = await client.post("/greybox/targets", headers=h(user_token),
                                json=target_body(model_backend="claude"))   # no key
        assert bad.status_code == 422 and "not available" in bad.text
        bad = await client.patch(f"/greybox/targets/{t['id']}",
                                 headers=h(user_token), json={"model_backend": "x"})
        assert bad.status_code == 422

    async def test_config_lists_backends_and_hides_keys(
            self, client, user_token, monkeypatch):
        from src.greybox_web import modelsel
        monkeypatch.setattr(modelsel, "load_env", lambda: {
            "ANTHROPIC_FOUNDRY_API_KEY": "sk-SECRETKEY",
            "ANTHROPIC_FOUNDRY_BASE_URL": "https://secret-host.example/anthropic",
            "CLAUDE_CODE_USE_FOUNDRY": "1", "ANTHROPIC_MEDIUM_MODEL": "m-medium"})
        cfg = await client.get("/greybox/config", headers=h(user_token))
        assert "SECRETKEY" not in cfg.text and "secret-host" not in cfg.text
        agent = cfg.json()["agent"]
        assert agent["available"] is True
        by_id = {b["id"]: b for b in agent["backends"]}
        assert by_id["claude"]["available"] and by_id["claude"]["models"][0] == "m-medium"
        assert by_id["fake"]["available"] and not by_id["codex"]["available"]
        assert agent["default"] == {"backend": "claude", "model": "m-medium"}

    async def test_validate_warns_without_any_backend(
            self, client, user_token, monkeypatch):
        monkeypatch.delenv("VIGILO_DEV_MODE")
        from src.webapi.settings import get_settings
        get_settings.cache_clear()
        v = await client.post("/greybox/targets/validate", headers=h(user_token),
                              json=target_body())
        assert v.status_code == 200, v.text
        assert any("No AI model configured" in w for w in v.json()["warnings"])
        assert (await client.get("/greybox/config", headers=h(user_token))
                ).json()["agent"]["available"] is False

    async def test_default_checks_resolved(self, client, user_token):
        # Authentication testing is on by default: both auth checks are effective
        # for a bare target. An owner can still narrow it off in the scope.
        t = await create_target(client, user_token)
        assert "auth.default_creds" in t["checks"] and "authz.object" in t["checks"] \
            and "headers.security" in t["checks"]
        t2 = await create_target(client, user_token,
                                  scope={"allow_auth_testing": False})
        assert "auth.default_creds" not in t2["checks"] \
            and "authz.object" not in t2["checks"]

    @pytest.mark.parametrize("body,loc", [
        (target_body(base_url="http://169.254.169.254/"), ("body", "base_url")),
        (target_body(scope={"allowed_hosts": ["127.0.0.1", "fd00:ec2::254"]}),
         ("body", "scope", "allowed_hosts", 1)),
        (target_body(base_url="http://api:8000/"), ("body", "base_url")),
        (target_body(base_url="http://temporal/"), ("body", "base_url")),
        (target_body(scope={"allowed_hosts": ["127.0.0.2"]}), ("body", "scope", "allowed_hosts")),
        (target_body(scope={"allowed_hosts": ["127.0.0.1", "*"]}),
         ("body", "scope", "allowed_hosts", 1)),
        (target_body(checks=["headers.security", "nmap.full"]), ("body", "checks", 1)),
        (target_body(base_url="http://u:p@127.0.0.1:43123/"), ("body", "base_url")),
        (target_body(base_url="http://127.0.0.1:8080/"), ("body", "base_url")),
    ])
    async def test_field_errors(self, client, user_token, body, loc):
        r = await client.post("/greybox/targets", headers=h(user_token), json=body)
        assert loc in _locs(r)

    async def test_internal_api_host_blocked(self, client, user_token, set_env):
        set_env("VIGILO_INTERNAL_API_URL", "http://vigilo-internal.test:8081")
        r = await client.post("/greybox/targets", headers=h(user_token),
                              json=target_body(base_url="http://vigilo-internal.test/"))
        assert "platform service" in _locs(r)[("body", "base_url")]

    async def test_configured_blocked_hosts(self, client, user_token, set_env):
        set_env("VIGILO_GREYBOX_BLOCKED_HOSTS", "grafana.corp.test, Vault")
        for host in ("grafana.corp.test", "vault"):
            r = await client.post("/greybox/targets", headers=h(user_token),
                                  json=target_body(base_url=f"http://{host}/"))
            assert ("body", "base_url") in _locs(r)

    async def test_structural_errors(self, client, user_token):
        r = await client.post("/greybox/targets", headers=h(user_token),
                              json=target_body(name="", limits={"max_requests": 999999},
                                               scope={"allowed_hostz": ["x"]}))
        locs = _locs(r)
        assert ("body", "name") in locs
        assert ("body", "limits", "max_requests") in locs
        assert ("body", "scope", "allowed_hostz") in locs

    async def test_private_target_rejected_when_flag_off(self, client, user_token, set_env):
        set_env("VIGILO_GREYBOX_ALLOW_PRIVATE_TARGETS", "false")
        r = await client.post("/greybox/targets", headers=h(user_token), json=target_body())
        assert "disabled on this platform" in _locs(r)[("body", "base_url")]
        r = await client.post("/greybox/targets", headers=h(user_token),
                              json=target_body(base_url="http://localhost:43123/"))
        assert ("body", "base_url") in _locs(r)

    async def test_own_cookie_credential_accepted_secret_never_returned(self, client,
                                                                        user_token):
        cid = await _cookie_cred(client, user_token)
        t = await create_target(client, user_token, credential_id=cid)
        assert t["credential"] == {"id": cid, "label": "staging session",
                                   "kind": "cookie_header"}
        listing = await client.get("/greybox/targets", headers=h(user_token))
        for resp in (str(t), listing.text):
            assert "SUPERSECRETCOOKIE" not in resp

    async def test_foreign_credential_rejected(self, client, user_token, session_maker):
        other = await other_user_token(client, session_maker)
        foreign = await _cookie_cred(client, other)
        r = await client.post("/greybox/targets", headers=h(user_token),
                              json=target_body(credential_id=foreign))
        # reported exactly like a non-existent credential (no existence leak)
        assert _locs(r)[("body", "credential_id")] == "Unknown credential"
        r2 = await client.post("/greybox/targets", headers=h(user_token),
                               json=target_body(credential_id=str(uuid.uuid4())))
        assert _locs(r2)[("body", "credential_id")] == "Unknown credential"

    async def test_wrong_kind_credential_rejected(self, client, user_token):
        cid = await _cookie_cred(client, user_token, kind="gitlab_token", secret="glpat-x")
        r = await client.post("/greybox/targets", headers=h(user_token),
                              json=target_body(credential_id=cid))
        assert "not a cookie" in _locs(r)[("body", "credential_id")]


class TestValidate:
    async def test_valid(self, client, user_token):
        r = await client.post("/greybox/targets/validate", headers=h(user_token),
                              json=target_body(scope={"excluded_paths": ["/logout"]}))
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is True and body["errors"] == []
        assert body["normalized"]["base_url"] == TARGET_URL
        assert body["normalized"]["scope"]["allowed_ports"] == [43123]
        assert body["scope_summary"][0] == "Hosts: 127.0.0.1"
        assert any("private" in w for w in body["warnings"])

    async def test_invalid_returns_200_with_errors(self, client, user_token):
        r = await client.post("/greybox/targets/validate", headers=h(user_token),
                              json=target_body(base_url="http://169.254.169.254/",
                                               checks=["bogus"]))
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is False and body["normalized"] is None
        locs = {tuple(e["loc"]) for e in body["errors"]}
        assert {("body", "base_url"), ("body", "checks", 0)} <= locs

    async def test_structural_error_returns_200(self, client, user_token):
        r = await client.post("/greybox/targets/validate", headers=h(user_token),
                              json={"base_url": TARGET_URL})
        assert r.status_code == 200
        assert ["body", "name"] in [e["loc"] for e in r.json()["errors"]]

    async def test_auth_check_warning(self, client, user_token):
        # Default scope (auth testing on): the warning says logins will be attempted.
        r = await client.post("/greybox/targets/validate", headers=h(user_token),
                              json=target_body(checks=["auth.default_creds"]))
        assert r.json()["valid"] is True
        assert any("will attempt logins" in w for w in r.json()["warnings"])
        # Narrowed off: the check is dropped with a warning naming it.
        r2 = await client.post("/greybox/targets/validate", headers=h(user_token),
                               json=target_body(checks=["auth.default_creds"],
                                                scope={"allow_auth_testing": False}))
        assert r2.json()["valid"] is True
        assert any("auth.default_creds" in w and "disabled" in w
                   for w in r2.json()["warnings"])

    async def test_nothing_persisted(self, client, user_token, session_maker):
        await client.post("/greybox/targets/validate", headers=h(user_token), json=target_body())
        async with session_maker() as s:
            assert (await s.scalars(select(GreyboxTarget))).all() == []


class TestReadUpdateDelete:
    async def test_get_list_pagination_and_filters(self, client, user_token):
        ids = [(await create_target(client, user_token, name=f"t{i}"))["id"] for i in range(5)]
        seen, cursor = [], None
        while True:
            params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
            page = (await client.get("/greybox/targets", headers=h(user_token),
                                     params=params)).json()
            seen += [t["id"] for t in page["items"]]
            cursor = page["next_cursor"]
            if not cursor:
                break
        assert seen == list(reversed(ids))
        q = (await client.get("/greybox/targets", headers=h(user_token),
                              params={"q": "t3"})).json()
        assert [t["name"] for t in q["items"]] == ["t3"]
        one = await client.get(f"/greybox/targets/{ids[0]}", headers=h(user_token))
        assert one.status_code == 200 and one.json()["name"] == "t0"

    async def test_bad_cursor_422(self, client, user_token):
        r = await client.get("/greybox/targets", headers=h(user_token),
                             params={"cursor": "!!!"})
        assert r.status_code == 422

    async def test_patch_and_archive(self, client, user_token):
        t = await create_target(client, user_token)
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token), json={
            "name": "renamed", "scope": {"excluded_paths": ["/logout"]},
            "limits": {"max_pages": 10}})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["name"] == "renamed"
        assert body["scope"]["excluded_paths"] == ["/logout"]
        assert body["scope"]["allowed_hosts"] == ["127.0.0.1"]
        assert body["limits"]["max_pages"] == 10 and body["limits"]["max_requests"] == 5000
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                               json={"archived": True})
        assert r.json()["archived"] is True
        active = (await client.get("/greybox/targets", headers=h(user_token))).json()
        archived = (await client.get("/greybox/targets", headers=h(user_token),
                                     params={"archived": "true"})).json()
        assert t["id"] not in [x["id"] for x in active["items"]]
        assert t["id"] in [x["id"] for x in archived["items"]]

    async def test_patch_validates(self, client, user_token):
        t = await create_target(client, user_token)
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                               json={"base_url": "http://127.0.0.9:43123/"})
        assert ("body", "scope", "allowed_hosts") in _locs(r) or \
            ("body", "base_url") in _locs(r)
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                               json={"scope": {"allowed_hosts": ["127.0.0.1", "169.254.169.254"]}})
        assert ("body", "scope", "allowed_hosts", 1) in _locs(r)

    async def test_patch_credential(self, client, user_token, session_maker):
        t = await create_target(client, user_token)
        cid = await _cookie_cred(client, user_token)
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                               json={"credential_id": cid})
        assert r.json()["credential"]["id"] == cid
        other = await other_user_token(client, session_maker)
        foreign = await _cookie_cred(client, other)
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                               json={"credential_id": foreign})
        assert ("body", "credential_id") in _locs(r)
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(user_token),
                               json={"credential_id": None})
        assert r.json()["credential"] is None

    async def test_last_run_and_delete(self, client, user_token, session_maker):
        t = await create_target(client, user_token)
        uid = await user_id(session_maker, "user@example.com")
        await _add_run(session_maker, t["id"], uid, status="succeeded")
        latest = await _add_run(session_maker, t["id"], uid, status="running")
        got = (await client.get(f"/greybox/targets/{t['id']}", headers=h(user_token))).json()
        assert got["last_run"]["id"] == str(latest) and got["last_run"]["status"] == "running"
        r = await client.delete(f"/greybox/targets/{t['id']}", headers=h(user_token))
        assert r.status_code == 409 and r.json() == {"detail": "Target has active runs"}
        async with session_maker() as s:
            run = await s.get(GreyboxRun, latest)
            run.status = "cancelled"
            await s.commit()
        r = await client.delete(f"/greybox/targets/{t['id']}", headers=h(user_token))
        assert r.status_code == 204
        async with session_maker() as s:
            assert (await s.scalars(select(GreyboxRun))).all() == []
            assert (await s.scalars(select(GreyboxTarget))).all() == []


class TestAcl:
    async def test_non_owner_gets_404_everywhere(self, client, user_token, session_maker):
        t = await create_target(client, user_token)
        other = await other_user_token(client, session_maker)
        for method, body in [("GET", None), ("PATCH", {"name": "x"}), ("DELETE", None)]:
            r = await client.request(method, f"/greybox/targets/{t['id']}", headers=h(other),
                                     json=body)
            assert r.status_code == 404 and r.json() == {"detail": "Not found"}, method
        listing = (await client.get("/greybox/targets", headers=h(other))).json()
        assert listing["items"] == []
        # still intact for the owner
        assert (await client.get(f"/greybox/targets/{t['id']}",
                                 headers=h(user_token))).json()["name"] == "demo-app"

    async def test_unknown_id_404(self, client, user_token):
        r = await client.get(f"/greybox/targets/{uuid.uuid4()}", headers=h(user_token))
        assert r.status_code == 404

    async def test_admin_sees_and_edits_everything(self, client, user_token, admin_token,
                                                   session_maker):
        t = await create_target(client, user_token)
        listing = (await client.get("/greybox/targets", headers=h(admin_token))).json()
        assert t["id"] in [x["id"] for x in listing["items"]]
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(admin_token),
                               json={"name": "admin-renamed"})
        assert r.status_code == 200 and r.json()["owner_id"] == t["owner_id"]
        # an admin can only attach a credential owned by the target owner
        admin_cred = await _cookie_cred(client, admin_token)
        r = await client.patch(f"/greybox/targets/{t['id']}", headers=h(admin_token),
                               json={"credential_id": admin_cred})
        assert ("body", "credential_id") in _locs(r)
        assert (await client.delete(f"/greybox/targets/{t['id']}",
                                    headers=h(admin_token))).status_code == 204

    async def test_unauthenticated(self, client):
        assert (await client.get("/greybox/targets")).status_code == 401
        assert (await client.post("/greybox/targets", json=target_body())).status_code == 401


class TestDeleteUserGuard:
    async def test_delete_user_with_greybox_target_409(self, client, user_token, admin_token,
                                                       session_maker):
        await create_target(client, user_token)
        uid = await user_id(session_maker, "user@example.com")
        r = await client.delete(f"/users/{uid}", headers=h(admin_token))
        assert r.status_code == 409 and "grey-box" in r.json()["detail"]

    async def test_delete_user_with_greybox_run_409(self, client, user_token, admin_token,
                                                    session_maker):
        # the admin owns the target, the user only triggered a run on it
        t = await create_target(client, admin_token)
        uid = await user_id(session_maker, "user@example.com")
        await _add_run(session_maker, t["id"], uid)
        r = await client.delete(f"/users/{uid}", headers=h(admin_token))
        assert r.status_code == 409

    async def test_delete_user_without_greybox_data_ok(self, client, user_token, admin_token,
                                                       session_maker):
        uid = await user_id(session_maker, "user@example.com")
        r = await client.delete(f"/users/{uid}", headers=h(admin_token))
        assert r.status_code == 204
