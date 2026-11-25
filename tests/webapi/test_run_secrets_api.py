"""Per-run secret records, the internal redemption endpoint, and cookie credentials on jobs."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from src.webapi import secret_store
from src.webapi.models import (
    RUN_CANCELLED,
    RUN_FAILED,
    RUN_RUNNING,
    RUN_SUCCEEDED,
    Job,
    Repository,
    Run,
    RunSecret,
    User,
)
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _reset_limits():
    secret_store.reset_rate_limits()
    yield
    secret_store.reset_rate_limits()


async def _make_run(session_maker, status=RUN_RUNNING) -> uuid.UUID:
    async with session_maker() as s:
        user = User(id=uuid.uuid4(), email=f"{uuid.uuid4().hex[:6]}@e.com", hashed_password="x",
                    role="user", is_active=True, is_superuser=False, is_verified=True)
        s.add(user)
        await s.flush()
        repo = Repository(created_by=user.id, name="r", source_type="upload")
        s.add(repo)
        await s.flush()
        job = Job(created_by=user.id, repository_id=repo.id, name="j", stage_preset="vuln")
        s.add(job)
        await s.flush()
        run = Run(job_id=job.id, status=status, session_id="s", data_dir="/tmp/x")
        s.add(run)
        await s.commit()
        return run.id


@pytest.fixture
async def internal(session_maker):
    from src.webapi.db import get_async_session
    from src.webapi.internal import create_internal_app

    async def _session():
        async with session_maker() as s:
            yield s

    app = create_internal_app()
    app.dependency_overrides[get_async_session] = _session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://internal") as c:
        yield c


def _post(client, run_id, key, want=("gitlab_token",)):
    return client.post(f"/internal/v1/runs/{run_id}/secrets", json={"key": key, "want": list(want)})


class TestStore:
    async def test_secret_is_encrypted_at_rest_and_key_is_hashed(self, session_maker):
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"gitlab_token": "glpat-PLAIN"})
        async with session_maker() as s:
            rec = await s.get(RunSecret, rid)
        assert b"glpat-PLAIN" not in rec.secret_enc and key not in rec.key_hash
        assert len(key) >= 32

    async def test_redeem_returns_only_the_requested_kinds(self, session_maker):
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"gitlab_token": "t0k", "cookie_header": "S=c"})
        async with session_maker() as s:
            assert await secret_store.redeem(s, rid, key, ["cookie_header"]) == {"cookie_header": "S=c"}
            assert await secret_store.redeem(s, rid, key, ["gitlab_token"]) == {"gitlab_token": "t0k"}

    async def test_wrong_key_unknown_run_and_other_runs_key_are_refused(self, session_maker):
        a, b = await _make_run(session_maker), await _make_run(session_maker)
        async with session_maker() as s:
            ka = await secret_store.issue(s, a, {"gitlab_token": "tok-a"})
            kb = await secret_store.issue(s, b, {"gitlab_token": "tok-b"})
        async with session_maker() as s:
            for rid, key in ((a, "wrong" * 8), (a, kb), (b, ka), (uuid.uuid4(), ka)):
                with pytest.raises(secret_store.RedemptionRefused):
                    await secret_store.redeem(s, rid, key, ["gitlab_token"])
            assert await secret_store.redeem(s, a, ka, ["gitlab_token"]) == {"gitlab_token": "tok-a"}

    async def test_kind_not_held_is_refused(self, session_maker):
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"cookie_header": "S=c"})
        async with session_maker() as s:
            with pytest.raises(secret_store.RedemptionRefused):
                await secret_store.redeem(s, rid, key, ["gitlab_token"])

    @pytest.mark.parametrize("status", [RUN_SUCCEEDED, RUN_FAILED, RUN_CANCELLED])
    async def test_refused_once_the_run_is_terminal_and_record_dropped(self, session_maker, status):
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"gitlab_token": "t0k"})
        async with session_maker() as s:
            run = await s.get(Run, rid)
            run.status = status
            await s.commit()
        async with session_maker() as s:
            with pytest.raises(secret_store.RedemptionRefused):
                await secret_store.redeem(s, rid, key, ["gitlab_token"])
        async with session_maker() as s:
            assert await s.get(RunSecret, rid) is None

    async def test_expired_record_is_refused(self, session_maker):
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"gitlab_token": "t0k"})
            rec = await s.get(RunSecret, rid)
            rec.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            await s.commit()
        async with session_maker() as s:
            with pytest.raises(secret_store.RedemptionRefused):
                await secret_store.redeem(s, rid, key, ["gitlab_token"])

    async def test_revoke_and_purge(self, session_maker):
        a, b = await _make_run(session_maker), await _make_run(session_maker, RUN_SUCCEEDED)
        async with session_maker() as s:
            await secret_store.issue(s, a, {"gitlab_token": "x"})
            await secret_store.issue(s, b, {"gitlab_token": "y"})
        async with session_maker() as s:
            assert await secret_store.purge_finished(s) == 1       # b is terminal
            assert await secret_store.revoke(s, a) is True
            assert await secret_store.revoke(s, a) is False         # idempotent
            assert (await s.scalars(select(RunSecret))).all() == []

    async def test_rate_limited_and_counted(self, session_maker, monkeypatch):
        monkeypatch.setenv("VIGILO_REDEEM_MAX_PER_MINUTE", "3")
        from src.webapi.settings import get_settings
        get_settings.cache_clear()
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"gitlab_token": "t0k"})
        async with session_maker() as s:
            for _ in range(3):
                await secret_store.redeem(s, rid, key, ["gitlab_token"])
            with pytest.raises(secret_store.RedemptionRateLimited):
                await secret_store.redeem(s, rid, key, ["gitlab_token"])
            assert (await s.get(RunSecret, rid)).redeem_count == 3
        get_settings.cache_clear()

    async def test_redemptions_are_logged_without_values(self, session_maker, caplog):
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"gitlab_token": "glpat-VALUE"})
        caplog.set_level("INFO")
        async with session_maker() as s:
            await secret_store.redeem(s, rid, key, ["gitlab_token"], client="10.0.0.5")
            with pytest.raises(secret_store.RedemptionRefused):
                await secret_store.redeem(s, rid, "bad" * 10, ["gitlab_token"], client="10.0.0.6")
        text = caplog.text
        assert "secret redeemed" in text and "refused" in text and str(rid) in text
        assert "glpat-VALUE" not in text and key not in text


class TestInternalEndpoint:
    async def test_redeem_over_http(self, internal, session_maker):
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"gitlab_token": "t0k", "cookie_header": "S=c"})
        r = await _post(internal, rid, key, ["gitlab_token"])
        assert r.status_code == 200 and r.json() == {"secrets": {"gitlab_token": "t0k"}}
        assert r.headers["cache-control"] == "no-store"

    async def test_refusals_are_403_and_uniform(self, internal, session_maker):
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"gitlab_token": "t0k"})
        bad = await _post(internal, rid, "x" * 40)
        unknown = await _post(internal, uuid.uuid4(), key)
        assert bad.status_code == unknown.status_code == 403 and bad.json() == unknown.json()

    async def test_refused_after_terminal(self, internal, session_maker):
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"gitlab_token": "t0k"})
            (await s.get(Run, rid)).status = RUN_CANCELLED
            await s.commit()
        assert (await _post(internal, rid, key)).status_code == 403

    async def test_rate_limit_is_429(self, internal, session_maker, monkeypatch):
        monkeypatch.setenv("VIGILO_REDEEM_MAX_PER_MINUTE", "2")
        from src.webapi.settings import get_settings
        get_settings.cache_clear()
        rid = await _make_run(session_maker)
        codes = [(await _post(internal, rid, "x" * 40)).status_code for _ in range(3)]
        assert codes == [403, 403, 429]
        get_settings.cache_clear()

    async def test_bad_request_shapes(self, internal):
        rid = uuid.uuid4()
        assert (await _post(internal, rid, "short")).status_code == 422
        assert (await _post(internal, rid, "x" * 40, ["bogus"])).status_code == 422

    def test_not_reachable_through_the_public_app_or_proxy(self, _env):
        from src.webapi.app import create_app

        public = create_app(run_lifespan=False)
        assert not [r for r in public.routes if "internal" in getattr(r, "path", "")]
        assert "internal" not in json.dumps(public.openapi())
        nginx = (ROOT / "web" / "nginx.conf").read_text()
        directives = "\n".join(ln for ln in nginx.splitlines() if not ln.strip().startswith("#"))
        assert "8081" not in directives and "internal" not in directives
        compose = (ROOT / "deploy" / "docker-compose.full.yml").read_text()
        assert "8081:" not in compose and '"8081' not in compose   # never published
        assert "traefik.http.routers" not in compose.split("  api:")[1].split("  ui:")[0]

    async def test_public_app_serves_no_internal_path(self, client):
        r = await client.post(f"/internal/v1/runs/{uuid.uuid4()}/secrets",
                              json={"key": "x" * 40, "want": ["gitlab_token"]})
        assert r.status_code == 404


class TestLifecycle:
    async def test_failed_launch_revokes_the_record(self, session_maker, monkeypatch):
        from src.webapi.runsvc import _launch

        monkeypatch.setattr("src.webapi.db._session_maker", lambda: session_maker)
        rid = await _make_run(session_maker, "queued")

        class Boom:
            async def start(self, run, job, repo):
                async with session_maker() as s:
                    await secret_store.issue(s, run.id, {"gitlab_token": "t0k"})
                raise RuntimeError("no docker")

        async with session_maker() as s:
            run = await s.get(Run, rid)
            job = await s.get(Job, run.job_id)
            await _launch(s, Boom(), run, job, None)
            assert run.status == RUN_FAILED
            assert await s.get(RunSecret, rid) is None

    async def test_deleting_a_run_deletes_its_record(self, session_maker):
        from src.webapi.deletion import delete_run
        from src.webapi.engine.fake import FakeEngine

        rid = await _make_run(session_maker, RUN_SUCCEEDED)
        async with session_maker() as s:
            await secret_store.issue(s, rid, {"gitlab_token": "t0k"})
            await delete_run(s, FakeEngine(), await s.get(Run, rid))
            await s.commit()
            assert await s.get(RunSecret, rid) is None


# ------------------------------------------------------------------ cookie credential on jobs


async def _login(client, session_maker, email):
    await _make_user(session_maker, email, PW, "user")
    return {"Authorization": f"Bearer {await _token(client, email, PW)}"}


async def _cred(client, h, kind="cookie_header", secret="SESSION=abc"):
    r = await client.post("/credentials", headers=h,
                          json={"kind": kind, "label": f"{kind}-1", "secret": secret})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _repo(client, h):
    return (await client.post("/repositories", headers=h, json={
        "name": "r", "source_type": "gitlab", "gitlab_url": "https://gl.example/g/p.git"})).json()["id"]


def _job_body(repo_id, **kw):
    return {"repository_id": repo_id, "name": "j", "stage_preset": "vuln",
            "target_url": "https://app.example", **kw}


class TestJobCookieCredential:
    async def test_create_with_own_cookie_credential(self, client, session_maker):
        h = await _login(client, session_maker, "a@example.com")
        repo, cred = await _repo(client, h), await _cred(client, h)
        r = await client.post("/jobs", headers=h, json=_job_body(repo, target_credential_id=cred))
        assert r.status_code == 201 and r.json()["target_credential_id"] == cred
        got = await client.get(f"/jobs/{r.json()['id']}", headers=h)
        assert got.json()["target_credential_id"] == cred
        assert "SESSION=abc" not in got.text

    async def test_default_is_none(self, client, session_maker):
        h = await _login(client, session_maker, "a@example.com")
        r = await client.post("/jobs", headers=h, json=_job_body(await _repo(client, h)))
        assert r.status_code == 201 and r.json()["target_credential_id"] is None

    async def test_someone_elses_or_wrong_kind_or_unknown_is_422(self, client, session_maker):
        ha = await _login(client, session_maker, "a@example.com")
        hb = await _login(client, session_maker, "b@example.com")
        repo = await _repo(client, ha)
        theirs = await _cred(client, hb)
        token_kind = await _cred(client, ha, kind="gitlab_token", secret="glpat-x")
        for cid in (theirs, token_kind, str(uuid.uuid4())):
            r = await client.post("/jobs", headers=ha, json=_job_body(repo, target_credential_id=cid))
            assert r.status_code == 422, (cid, r.text)
            assert "cookie_header" in r.text

    async def test_needs_a_target_url(self, client, session_maker):
        h = await _login(client, session_maker, "a@example.com")
        repo, cred = await _repo(client, h), await _cred(client, h)
        body = _job_body(repo, target_credential_id=cred, target_url=None)
        r = await client.post("/jobs", headers=h, json=body)
        assert r.status_code == 422 and "target URL" in r.text

    async def test_update_set_and_clear(self, client, session_maker):
        h = await _login(client, session_maker, "a@example.com")
        repo, cred = await _repo(client, h), await _cred(client, h)
        job = (await client.post("/jobs", headers=h, json=_job_body(repo))).json()
        r = await client.patch(f"/jobs/{job['id']}", headers=h, json={"target_credential_id": cred})
        assert r.status_code == 200 and r.json()["target_credential_id"] == cred
        r = await client.patch(f"/jobs/{job['id']}", headers=h, json={"notify_email": True})
        assert r.json()["target_credential_id"] == cred            # untouched when omitted
        r = await client.patch(f"/jobs/{job['id']}", headers=h, json={"target_credential_id": None})
        assert r.json()["target_credential_id"] is None

    async def test_update_cannot_use_a_foreign_credential(self, client, session_maker):
        ha = await _login(client, session_maker, "a@example.com")
        hb = await _login(client, session_maker, "b@example.com")
        job = (await client.post("/jobs", headers=ha, json=_job_body(await _repo(client, ha)))).json()
        r = await client.patch(f"/jobs/{job['id']}", headers=ha,
                               json={"target_credential_id": await _cred(client, hb)})
        assert r.status_code == 422

    async def test_update_without_target_url_is_422(self, client, session_maker):
        h = await _login(client, session_maker, "a@example.com")
        job = (await client.post("/jobs", headers=h, json=_job_body(
            await _repo(client, h), target_url=None))).json()
        r = await client.patch(f"/jobs/{job['id']}", headers=h,
                               json={"target_credential_id": await _cred(client, h)})
        assert r.status_code == 422

    async def test_deleting_the_credential_clears_the_job_reference(self, client, session_maker):
        h = await _login(client, session_maker, "a@example.com")
        repo, cred = await _repo(client, h), await _cred(client, h)
        job = (await client.post("/jobs", headers=h, json=_job_body(repo, target_credential_id=cred))).json()
        assert (await client.delete(f"/credentials/{cred}", headers=h)).status_code == 204
        assert (await client.get(f"/jobs/{job['id']}", headers=h)).json()["target_credential_id"] is None

    async def test_resolve_job_cookie_only_for_owner_kind_and_target(self, client, session_maker, monkeypatch):
        from types import SimpleNamespace

        from src.webapi.engine.common import resolve_job_cookie

        monkeypatch.setattr("src.webapi.db._session_maker", lambda: session_maker)
        ha = await _login(client, session_maker, "a@example.com")
        hb = await _login(client, session_maker, "b@example.com")
        cred = await _cred(client, ha, secret="SESSION=zzz")
        theirs = await _cred(client, hb)
        async with session_maker() as s:
            owner = (await s.scalars(select(User).where(User.email == "a@example.com"))).one().id
        mk = lambda **kw: SimpleNamespace(**{"target_url": "https://app.example", "created_by": owner, **kw})
        assert await resolve_job_cookie(mk(target_credential_id=uuid.UUID(cred))) == "SESSION=zzz"
        assert await resolve_job_cookie(mk(target_credential_id=uuid.UUID(cred), target_url=None)) is None
        assert await resolve_job_cookie(mk(target_credential_id=uuid.UUID(theirs))) is None
        assert await resolve_job_cookie(mk(target_credential_id=uuid.uuid4())) is None
        assert await resolve_job_cookie(mk(target_credential_id=None)) is None


class TestRepositoryUrl:
    async def test_userinfo_in_gitlab_url_is_422(self, client, session_maker):
        h = await _login(client, session_maker, "a@example.com")
        for url in ("https://user:pw@gl.example/g/p.git", "https://oauth2:glpat-x@gl.example/g/p.git",
                    "https://tokenonly@gl.example/g/p.git"):
            r = await client.post("/repositories", headers=h, json={
                "name": "r", "source_type": "gitlab", "gitlab_url": url})
            assert r.status_code == 422, url
            assert "credentials" in r.text

    def test_ingestion_helpers_reject_userinfo(self):
        from src.webapi.ingestion import build_clone_url, reject_embedded_credentials

        with pytest.raises(ValueError):
            reject_embedded_credentials("https://u:p@h/x.git")
        with pytest.raises(ValueError):
            build_clone_url("https://u:p@h/x.git", "tok")
        reject_embedded_credentials("https://h:8443/x.git")
