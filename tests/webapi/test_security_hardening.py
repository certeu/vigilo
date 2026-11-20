"""Security regressions: symlink exfiltration, credential ownership, secret store limits,
credential revocation, ingestion hardening, and the agent env scrubber."""
from __future__ import annotations

import os
import subprocess
import uuid

import pytest
from sqlalchemy import select

from src.webapi import secret_store
from src.webapi.models import RUN_RUNNING, Job, Repository, Run, RunSecret, User
from src.webapi.reports import REPORT_FILENAME, deliverables_dir
from tests.webapi.test_reports import _repo_job_run
from tests.webapi.test_run_secrets_api import _cred, _job_body, _login, _make_run


@pytest.fixture(autouse=True)
def _reset_limits():
    secret_store.reset_rate_limits()
    yield
    secret_store.reset_rate_limits()


def _workspace(run):
    from src.webapi.settings import get_settings
    data_dir = os.path.join(get_settings().jobs_data_dir, run["id"])
    return data_dir, os.path.join(data_dir, "repo", ".vigilo", run["session_id"])


@pytest.fixture
def outside(tmp_path):
    p = tmp_path / "outside-secret.txt"
    p.write_text("VIGILO_FERNET_KEY=super-secret-material\n")
    return p


# ---------------------------------------------------------------- 1. symlinks


class TestSymlinkExfiltration:
    async def test_report_symlink_is_not_served(self, client, user_token, outside):
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        data_dir, _ws = _workspace(run)
        d = deliverables_dir(data_dir, run["session_id"])
        os.makedirs(d)
        os.symlink(outside, os.path.join(d, REPORT_FILENAME))
        r = await client.get(f"/runs/{run['id']}/report", headers=h)
        assert r.json() == {"exists": False, "markdown": ""}
        assert "super-secret" not in r.text
        for kind in ("report_md",):
            assert (await client.get(f"/runs/{run['id']}/artifacts/{kind}", headers=h)).status_code == 404
        assert (await client.get(f"/runs/{run['id']}/artifacts", headers=h)).json()["artifacts"] == []

    async def test_regular_artifact_still_served(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        data_dir, _ws = _workspace(run)
        d = deliverables_dir(data_dir, run["session_id"])
        os.makedirs(d)
        with open(os.path.join(d, "findings_index.json"), "w") as fh:
            fh.write('{"a": 1}')
        r = await client.get(f"/runs/{run['id']}/artifacts/findings_index", headers=h)
        assert r.status_code == 200 and r.content == b'{"a": 1}'

    async def test_artifact_symlink_and_symlinked_directory(self, client, user_token, outside, tmp_path):
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        data_dir, ws = _workspace(run)
        d = deliverables_dir(data_dir, run["session_id"])
        os.makedirs(d)
        os.symlink(outside, os.path.join(d, "findings_index.json"))
        assert (await client.get(f"/runs/{run['id']}/artifacts/findings_index", headers=h)).status_code == 404
        # the whole deliverables directory replaced by a symlink to another tree
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / REPORT_FILENAME).write_text("stolen report")
        os.remove(os.path.join(d, "findings_index.json"))
        os.rmdir(d)
        os.symlink(elsewhere, d)
        assert (await client.get(f"/runs/{run['id']}/report", headers=h)).json()["exists"] is False

    async def test_workspace_symlink_and_fifo_are_refused(self, client, user_token, tmp_path):
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        data_dir, ws = _workspace(run)
        d = deliverables_dir(data_dir, run["session_id"])
        os.makedirs(d)
        os.mkfifo(os.path.join(d, REPORT_FILENAME))
        r = await client.get(f"/runs/{run['id']}/report", headers=h)  # must not block either
        assert r.json()["exists"] is False

    async def test_logs_and_events_symlinks_not_followed(self, client, user_token, outside):
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        _data, ws = _workspace(run)
        os.makedirs(ws)
        os.symlink(outside, os.path.join(ws, "events.jsonl"))
        os.symlink(outside, os.path.join(ws, "workflow.log"))
        r = await client.get(f"/runs/{run['id']}/logs", headers=h)
        assert r.status_code == 200
        assert "super-secret" not in r.text and r.json()["lines"] == []

    def test_logs_read_from_and_current_stage(self, tmp_path, outside):
        from src.webapi.logs import current_stage, read_from, workspace_for
        ws = workspace_for(str(tmp_path), "s1")
        os.makedirs(ws)
        os.symlink(outside, os.path.join(ws, "workflow.log"))
        os.symlink(outside, os.path.join(ws, "events.jsonl"))
        assert read_from(os.path.join(ws, "workflow.log"), 0) == ([], 0)
        assert read_from(os.path.join(ws, "workflow.log"), 0, data_dir=str(tmp_path), session_id="s1") == ([], 0)
        assert current_stage(str(tmp_path), "s1") is None

    def test_metrics_do_not_follow_symlinks(self, tmp_path, outside):
        from src.webapi.metrics import extract_run_metrics
        d = deliverables_dir(str(tmp_path), "s1")
        os.makedirs(d)
        outside.write_text('{"severity_counts": {"critical": 99}}')
        os.symlink(outside, os.path.join(d, "report_stats.json"))
        assert extract_run_metrics(str(tmp_path), "s1") is None

    async def test_completion_email_does_not_attach_symlink_target(
        self, client, session_maker, user_token, fake_mailer, outside
    ):
        from src.webapi.models import RUN_SUCCEEDED
        run = await _repo_job_run(client, user_token)
        data_dir, _ws = _workspace(run)
        d = deliverables_dir(data_dir, run["session_id"])
        os.makedirs(d)
        os.symlink(outside, os.path.join(d, REPORT_FILENAME))
        from src.webapi.routers.runs import _maybe_notify
        async with session_maker() as sess:
            row = await sess.get(Run, uuid.UUID(run["id"]))
            row.status = RUN_SUCCEEDED
            await _maybe_notify(row, sess, fake_mailer)
        assert len(fake_mailer.sent) == 1
        assert fake_mailer.sent[0]["attachment"] is None   # symlinked report is not attached

    async def test_completion_email_attaches_a_private_copy_of_a_real_report(
        self, client, session_maker, user_token, fake_mailer
    ):
        from src.webapi.models import RUN_SUCCEEDED
        run = await _repo_job_run(client, user_token)
        data_dir, _ws = _workspace(run)
        d = deliverables_dir(data_dir, run["session_id"])
        os.makedirs(d)
        with open(os.path.join(d, REPORT_FILENAME), "w") as fh:
            fh.write("# real")
        seen = {}

        class Spy:
            def send(self, to, subject, body, attachment_path):
                seen["content"] = open(attachment_path).read() if attachment_path else None
                seen["path"] = attachment_path

        from src.webapi.routers.runs import _maybe_notify
        async with session_maker() as sess:
            row = await sess.get(Run, uuid.UUID(run["id"]))
            row.status = RUN_SUCCEEDED
            await _maybe_notify(row, sess, Spy())
        assert seen["content"] == "# real" and not seen["path"].startswith(data_dir)
        assert not os.path.exists(seen["path"])  # temp copy removed


# ------------------------------------------------- 2. credential ownership


async def _gitlab_cred(client, h, base_url=None):
    body = {"kind": "gitlab_token", "label": "t", "secret": "glpat-x"}
    if base_url:
        body["gitlab_base_url"] = base_url
    r = await client.post("/credentials", headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _gl_repo(client, h, url="https://gl.example/g/p.git"):
    r = await client.post("/repositories", headers=h, json={
        "name": "r", "source_type": "gitlab", "gitlab_url": url})
    assert r.status_code == 201, r.text
    return r.json()["id"]


class TestCredentialOwnership:
    async def test_patch_rejects_foreign_credential(self, client, session_maker):
        ha = await _login(client, session_maker, "a@example.com")
        hb = await _login(client, session_maker, "b@example.com")
        theirs = await _gitlab_cred(client, hb)
        repo = await _gl_repo(client, ha)
        r = await client.patch(f"/repositories/{repo}", headers=ha, json={"default_credential_id": theirs})
        assert r.status_code == 400
        got = await client.get(f"/repositories/{repo}", headers=ha)
        assert got.json()["default_credential_id"] != theirs

    async def test_patch_rejects_wrong_kind_and_wrong_host(self, client, session_maker):
        ha = await _login(client, session_maker, "a@example.com")
        repo = await _gl_repo(client, ha)
        cookie = await _cred(client, ha)  # cookie_header kind
        assert (await client.patch(f"/repositories/{repo}", headers=ha,
                                   json={"default_credential_id": cookie})).status_code == 400
        other_host = await _gitlab_cred(client, ha, base_url="https://evil.example")
        assert (await client.patch(f"/repositories/{repo}", headers=ha,
                                   json={"default_credential_id": other_host})).status_code == 400
        same_host = await _gitlab_cred(client, ha, base_url="https://gl.example")
        r = await client.patch(f"/repositories/{repo}", headers=ha, json={"default_credential_id": same_host})
        assert r.status_code == 200 and r.json()["default_credential_id"] == same_host
        plain = await _gitlab_cred(client, ha)  # no base URL: allowed
        assert (await client.patch(f"/repositories/{repo}", headers=ha,
                                   json={"default_credential_id": plain})).status_code == 200

    async def test_run_start_rechecks_before_decrypting(self, client, session_maker, monkeypatch):
        from src.webapi.engine.temporal import TemporalEngine
        monkeypatch.setattr("src.webapi.db._session_maker", lambda: session_maker)
        ha = await _login(client, session_maker, "a@example.com")
        hb = await _login(client, session_maker, "b@example.com")
        theirs = await _gitlab_cred(client, hb)
        mine = await _gitlab_cred(client, ha, base_url="https://gl.example")
        repo_id = await _gl_repo(client, ha)
        async with session_maker() as s:
            repo = await s.get(Repository, uuid.UUID(repo_id))
            # simulate a row written around the API validation (older data, direct DB write)
            engine = TemporalEngine()
            with pytest.raises(RuntimeError):
                await engine._resolve_token(uuid.UUID(theirs), repo)
            assert await engine._resolve_token(uuid.UUID(mine), repo) == "glpat-x"
            repo.remote_url = "https://other.example/g/p.git"  # host drift: binding refuses
            with pytest.raises(RuntimeError):
                await engine._resolve_token(uuid.UUID(mine), repo)

    async def test_job_cookie_refused_when_job_has_no_owner(self, client, session_maker, monkeypatch):
        from types import SimpleNamespace

        from src.webapi.engine.common import resolve_job_cookie
        monkeypatch.setattr("src.webapi.db._session_maker", lambda: session_maker)
        ha = await _login(client, session_maker, "a@example.com")
        cred = await _cred(client, ha, secret="SESSION=zzz")
        job = SimpleNamespace(target_credential_id=uuid.UUID(cred), target_url="https://app.example",
                              created_by=None)
        assert await resolve_job_cookie(job) is None


# ------------------------------------------------ 5. smaller items


class TestSecretStoreRateLimit:
    async def test_stranger_cannot_starve_the_runs_worker(self, session_maker, monkeypatch):
        monkeypatch.setenv("VIGILO_REDEEM_MAX_PER_MINUTE", "3")
        from src.webapi.settings import get_settings
        get_settings.cache_clear()
        rid = await _make_run(session_maker)
        async with session_maker() as s:
            key = await secret_store.issue(s, rid, {"forge_token": "t0k"})
        async with session_maker() as s:
            seen = set()
            for _ in range(10):  # the stranger floods the run with bad keys
                try:
                    await secret_store.redeem(s, rid, "x" * 40, ["forge_token"], client="evil")
                except secret_store.RedemptionRefused:
                    seen.add("refused")
                except secret_store.RedemptionRateLimited:
                    seen.add("limited")
            assert seen == {"refused", "limited"}      # brute force is still throttled
            # ... and the legitimate worker, holding the key, is unaffected
            assert await secret_store.redeem(s, rid, key, ["forge_token"], client="worker") == {"forge_token": "t0k"}
        get_settings.cache_clear()

    async def test_per_source_failure_limit_spans_runs(self, session_maker, monkeypatch):
        monkeypatch.setenv("VIGILO_REDEEM_MAX_PER_MINUTE", "2")   # per-source = 10
        from src.webapi.settings import get_settings
        get_settings.cache_clear()
        outcomes = []
        async with session_maker() as s:
            for _ in range(14):
                try:
                    await secret_store.redeem(s, uuid.uuid4(), "x" * 40, ["forge_token"], client="evil")
                except secret_store.RedemptionRefused:
                    outcomes.append("refused")
                except secret_store.RedemptionRateLimited:
                    outcomes.append("limited")
        assert outcomes[:10] == ["refused"] * 10 and set(outcomes[10:]) == {"limited"}
        get_settings.cache_clear()


class TestCredentialDeletionRevokesRunSecrets:
    async def test_active_runs_using_the_credential_lose_their_secret(self, client, session_maker):
        ha = await _login(client, session_maker, "a@example.com")
        cookie = await _cred(client, ha)
        repo = await _gl_repo(client, ha)
        job = (await client.post("/jobs", headers=ha, json=_job_body(repo, target_credential_id=cookie))).json()
        other_job = (await client.post("/jobs", headers=ha, json=_job_body(repo))).json()
        async with session_maker() as s:
            runs = []
            for j in (job["id"], other_job["id"]):
                run = Run(job_id=uuid.UUID(j), status=RUN_RUNNING, session_id="s", data_dir="/tmp/x")
                s.add(run)
                runs.append(run)
            await s.commit()
            ids = [r.id for r in runs]
        async with session_maker() as s:
            for rid in ids:
                await secret_store.issue(s, rid, {"cookie_header": "S=abc"})
        assert (await client.delete(f"/credentials/{cookie}", headers=ha)).status_code == 204
        async with session_maker() as s:
            left = {r.run_id for r in (await s.scalars(select(RunSecret))).all()}
        assert left == {ids[1]}   # only the run that did not use the credential keeps its record


class TestIngestion:
    def test_scrub_failure_fails_ingestion_and_deletes_checkout(self, tmp_path, monkeypatch):
        from src.webapi import ingestion
        repo_dir = tmp_path / "repo"

        def fake_clone(url, dest, **kw):
            os.makedirs(os.path.join(dest, ".git"))
            open(os.path.join(dest, "x.py"), "w").write("1")
            return dest

        def boom(*a, **k):
            raise subprocess.CalledProcessError(1, "git")

        monkeypatch.setattr(ingestion, "clone_repo", fake_clone)
        monkeypatch.setattr(ingestion, "scrub_origin_credentials", boom)
        with pytest.raises(RuntimeError, match="scrub"):
            ingestion.prepare_repo(source_type="gitlab", repo_dir=str(repo_dir),
                                   remote_url="https://gl.example/g/p.git", token="glpat-x")
        assert os.listdir(repo_dir) == []

    def test_scrub_uses_check_true(self):
        from src.webapi import ingestion
        seen = {}

        def runner(cmd, **kw):
            seen.update(kw)
        ingestion.scrub_origin_credentials("/x", "https://a/b", runner=runner)
        assert seen["check"] is True

    def test_http_url_with_token_is_rejected(self):
        from src.webapi.ingestion import build_clone_url
        with pytest.raises(ValueError, match="https"):
            build_clone_url("http://gl.example/g/p.git", "glpat-x")
        assert build_clone_url("https://gl.example/g/p.git", "glpat-x").startswith("https://oauth2:")

    async def test_pasting_a_token_for_http_url_is_rejected(self, client, session_maker):
        ha = await _login(client, session_maker, "a@example.com")
        r = await client.post("/repositories", headers=ha, json={
            "name": "r", "source_type": "gitlab", "gitlab_url": "http://gl.example/g/p.git",
            "gitlab_token": "glpat-x"})
        assert r.status_code == 400


# --------------------------------------------------------------- 6. env scrubber


class TestEnvGuard:
    def test_platform_secrets_stripped_provider_keys_kept(self):
        from src.ai.envguard import strip_secret_env
        env = {
            "VIGILO_SMTP_PASSWORD": "a", "VIGILO_SMTP_USER": "a", "POSTGRES_USER": "a",
            "POSTGRES_PASSWORD": "a", "VIGILO_DATABASE_URL": "a", "VIGILO_FERNET_KEY": "a",
            "VIGILO_JWT_SECRET": "a", "DB_PASSWORD": "a", "MY_SECRET_THING": "a",
            "SOMETHING_TOKEN": "a", "GITHUB_TOKEN": "a",
            "ANTHROPIC_API_KEY": "k", "ANTHROPIC_AUTH_TOKEN": "k", "CLAUDE_CODE_OAUTH_TOKEN": "k",
            "AWS_BEARER_TOKEN_BEDROCK": "k", "AWS_SECRET_ACCESS_KEY": "k", "OPENAI_API_KEY": "k",
            "CODEX_API_KEY": "k", "LITELLM_API_KEY": "k", "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "64000",
            "PATH": "/bin", "HOME": "/h", "HTTPS_PROXY": "p",
        }
        out = strip_secret_env(dict(env))
        assert set(out) == {
            "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
            "AWS_BEARER_TOKEN_BEDROCK", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "CODEX_API_KEY",
            "LITELLM_API_KEY", "CLAUDE_CODE_MAX_OUTPUT_TOKENS", "PATH", "HOME", "HTTPS_PROXY",
        }
