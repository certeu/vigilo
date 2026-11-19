"""Engine wiring (temporal / docker): workflow type, workflow id, per-run secret reference."""
from __future__ import annotations

import json
import os
import sys
import types
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.webapi.models import RUN_RUNNING
from src.webapi.settings import Settings


def _settings(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


# --------------------------------------------------------------------------- helpers

def _run(tmp_path) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(), session_id="sess-abc123", workflow_id=None, task_queue=None,
        container_id=None, status="queued", current_phase=None, commit_sha=None,
        data_dir=str(tmp_path / "run"),
    )


def _job(**kw) -> SimpleNamespace:
    base = dict(target_url="http://target.test", stage_preset="full",
                target_credential_id=None, created_by=uuid.uuid4())
    base.update(kw)
    return SimpleNamespace(**base)


def _repo(**kw) -> SimpleNamespace:
    base = dict(
        id=uuid.uuid4(), source_type="upload", default_credential_id=None,
        gitlab_url=None, push_patches=False, scan_config={}, pipeline_config={},
    )
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture
def patched_settings(monkeypatch, tmp_path):
    def _apply(**kw):
        s = _settings(jobs_data_dir=str(tmp_path / "jobs"),
                      uploads_dir=str(tmp_path / "uploads"), **kw)
        monkeypatch.setattr("src.webapi.engine.temporal.get_settings", lambda: s)
        monkeypatch.setattr("src.webapi.engine.docker_temporal.get_settings", lambda: s)
        return s
    return _apply


@pytest.fixture(autouse=True)
def _db(monkeypatch, session_maker):
    """Run-secret records go to the test database."""
    monkeypatch.setattr("src.webapi.db._session_maker", lambda: session_maker)


async def stored_bundle(session_maker, run) -> dict:
    """Decrypt the run's stored secret record (what the worker may redeem)."""
    from src.webapi.models import RunSecret
    from src.webapi.security.vault import build_vault
    from src.webapi.settings import get_settings
    async with session_maker() as s:
        rec = await s.get(RunSecret, run.id)
    return json.loads(build_vault(get_settings()).decrypt(rec.secret_enc)) if rec else {}


@pytest.fixture(autouse=True)
def _no_ingestion(monkeypatch, request):
    admin = getattr(request, "param", None) or SimpleNamespace(
        default_max_concurrent_pipelines=8, executor="", model_small="",
        model_medium="", model_large="")
    monkeypatch.setattr("src.webapi.engine.common.load_admin_config",
                        AsyncMock(return_value=admin))
    monkeypatch.setattr("src.webapi.ingestion.prepare_repo", MagicMock())
    monkeypatch.setattr("src.webapi.repo_tree.capture_repo_tree", MagicMock())


# --------------------------------------------------------------------------- temporal

GITLAB_REPO = dict(source_type="gitlab", gitlab_url="https://gl.example/g/x.git",
                   default_credential_id=uuid.uuid4())


class TestTemporalEngine:
    async def _start(self, monkeypatch, tmp_path, repo=None, token=None):
        from src.webapi.engine.temporal import TemporalEngine
        engine = TemporalEngine()
        client = MagicMock()
        client.start_workflow = AsyncMock()
        monkeypatch.setattr(engine, "_client", AsyncMock(return_value=client))
        monkeypatch.setattr(engine, "_resolve_token", AsyncMock(return_value=token))
        run = _run(tmp_path)
        await engine.start(run, _job(), repo or _repo())
        return run, client

    async def test_always_starts_whitebox_engine_workflow(
        self, monkeypatch, tmp_path, patched_settings
    ):
        patched_settings()
        run, client = await self._start(monkeypatch, tmp_path)
        args, kwargs = client.start_workflow.call_args
        assert args[0] == "WhiteboxEngineWorkflow"
        assert args[1]["session_id"] == run.session_id
        assert "push" not in args[1]
        assert kwargs["id"] == run.session_id
        assert run.workflow_id == run.session_id
        assert run.status == RUN_RUNNING

    async def test_pipeline_config_and_model_overrides(
        self, monkeypatch, tmp_path, patched_settings
    ):
        patched_settings()
        admin = SimpleNamespace(default_max_concurrent_pipelines=5, executor="claude",
                                model_small="s-admin", model_medium="", model_large="l-admin")
        monkeypatch.setattr("src.webapi.engine.common.load_admin_config",
                            AsyncMock(return_value=admin))
        from src.webapi.engine.temporal import TemporalEngine
        engine = TemporalEngine()
        client = MagicMock()
        client.start_workflow = AsyncMock()
        monkeypatch.setattr(engine, "_client", AsyncMock(return_value=client))
        job = _job()
        job.pipeline_overrides = {"findings_per_prover": 2, "bogus": 1}
        repo = _repo(pipeline_config={"model_small": "s-repo"})
        await engine.start(_run(tmp_path), job, repo)
        payload = client.start_workflow.call_args.args[1]
        assert payload["pipeline_config"] == {
            "max_concurrent_pipelines": 5, "findings_per_prover": 2}
        assert payload["model_overrides"] == {
            "executor": "claude", "model_small": "s-repo", "model_large": "l-admin"}

    async def test_no_model_overrides_when_empty(self, monkeypatch, tmp_path, patched_settings):
        patched_settings()
        _, client = await self._start(monkeypatch, tmp_path)
        payload = client.start_workflow.call_args.args[1]
        assert "model_overrides" not in payload
        assert payload["pipeline_config"] == {"max_concurrent_pipelines": 8}

    async def test_refresh_and_cancel(self, monkeypatch, tmp_path, patched_settings):
        from src.webapi.engine.temporal import TemporalEngine
        patched_settings()
        engine = TemporalEngine()
        handle = MagicMock()
        handle.describe = AsyncMock(return_value=SimpleNamespace(status=SimpleNamespace(value=2)))
        handle.cancel = AsyncMock()
        handle.terminate = AsyncMock()
        client = MagicMock()
        client.get_workflow_handle = MagicMock(return_value=handle)
        monkeypatch.setattr(engine, "_client", AsyncMock(return_value=client))
        run = _run(tmp_path)
        run.workflow_id = "sess-abc123"
        await engine.refresh(run)
        assert run.status == "succeeded"
        await engine.cancel(run)
        assert run.status == "cancelled"
        client.get_workflow_handle.assert_called_with("sess-abc123")
        handle.cancel.assert_awaited_once()
        # belt-and-braces: terminate is still awaited after the cancel request
        handle.terminate.assert_awaited_once()

    async def test_push_patches_sends_flags_and_a_reference_only(
        self, monkeypatch, tmp_path, patched_settings, session_maker
    ):
        patched_settings()
        run, client = await self._start(
            monkeypatch, tmp_path, _repo(push_patches=True, **GITLAB_REPO), token="glpat-secret")
        payload = client.start_workflow.call_args.args[1]
        assert payload["push"] == {"enabled": True}
        assert payload["source"] == {"remote_url": "https://gl.example/g/x.git", "commit": None}
        assert set(payload["secrets"]) == {"ref", "key"} and payload["secrets"]["ref"] == str(run.id)
        assert "auth" not in payload
        assert "glpat-secret" not in repr(client.start_workflow.call_args)
        # nothing on disk for the run: the token lives only in the encrypted DB record
        assert not os.path.exists(os.path.join(run.data_dir, ".vigilo-secrets"))
        for base, _d, files in os.walk(run.data_dir):
            for f in files:
                assert "glpat-secret" not in open(os.path.join(base, f), errors="ignore").read()
        assert await stored_bundle(session_maker, run) == {"gitlab_token": "glpat-secret"}

    async def test_no_secret_without_opt_in(self, monkeypatch, tmp_path, patched_settings, session_maker):
        patched_settings()
        run, client = await self._start(
            monkeypatch, tmp_path, _repo(push_patches=False, **GITLAB_REPO), token="glpat-secret")
        payload = client.start_workflow.call_args.args[1]
        assert "push" not in payload and "secrets" not in payload
        assert payload["source"]["remote_url"] == "https://gl.example/g/x.git"  # non-secret, for rebuild
        assert await stored_bundle(session_maker, run) == {}

    async def test_upload_repo_pushes_nothing(self, monkeypatch, tmp_path, patched_settings, session_maker):
        patched_settings()
        run, client = await self._start(
            monkeypatch, tmp_path, _repo(source_type="upload", push_patches=True))
        payload = client.start_workflow.call_args.args[1]
        assert "push" not in payload and "secrets" not in payload and "source" not in payload

    async def test_scanned_commit_is_sent_as_source(self, monkeypatch, tmp_path, patched_settings):
        patched_settings()
        from src.webapi.engine.temporal import TemporalEngine
        engine = TemporalEngine()
        client = MagicMock()
        client.start_workflow = AsyncMock()
        monkeypatch.setattr(engine, "_client", AsyncMock(return_value=client))
        monkeypatch.setattr("src.webapi.engine.temporal.capture_source_info",
                            lambda run, repo, d: setattr(run, "commit_sha", "a" * 40))
        await engine.start(_run(tmp_path), _job(), _repo(**GITLAB_REPO))
        assert client.start_workflow.call_args.args[1]["source"]["commit"] == "a" * 40

    async def test_job_cookie_adds_flag_and_reference_not_the_cookie(
        self, monkeypatch, tmp_path, patched_settings, session_maker
    ):
        patched_settings()
        monkeypatch.setattr("src.webapi.engine.common.resolve_job_cookie",
                            AsyncMock(return_value="SESSION=cookie-secret-value"))
        run, client = await self._start(monkeypatch, tmp_path, _repo(), token=None)
        payload = client.start_workflow.call_args.args[1]
        assert payload["auth"] == {"cookie": True} and "secrets" in payload
        assert "cookie-secret-value" not in repr(client.start_workflow.call_args)
        assert await stored_bundle(session_maker, run) == {"cookie_header": "SESSION=cookie-secret-value"}

    async def test_token_and_cookie_share_one_record(
        self, monkeypatch, tmp_path, patched_settings, session_maker
    ):
        patched_settings()
        monkeypatch.setattr("src.webapi.engine.common.resolve_job_cookie",
                            AsyncMock(return_value="S=c00kie-value"))
        run, client = await self._start(
            monkeypatch, tmp_path, _repo(push_patches=True, **GITLAB_REPO), token="t0k3n-value")
        assert await stored_bundle(session_maker, run) == {
            "gitlab_token": "t0k3n-value", "cookie_header": "S=c00kie-value"}

    async def test_secret_revoked_when_run_finishes(
        self, monkeypatch, tmp_path, patched_settings, session_maker
    ):
        from src.webapi.engine.temporal import TemporalEngine
        patched_settings()
        run, client = await self._start(
            monkeypatch, tmp_path, _repo(push_patches=True, **GITLAB_REPO), token="t0k")
        assert await stored_bundle(session_maker, run)
        engine = TemporalEngine()
        handle = MagicMock()
        handle.describe = AsyncMock(return_value=SimpleNamespace(status=SimpleNamespace(value=2)))
        client2 = MagicMock()
        client2.get_workflow_handle = MagicMock(return_value=handle)
        monkeypatch.setattr(engine, "_client", AsyncMock(return_value=client2))
        run.workflow_id = run.session_id
        await engine.refresh(run)
        assert await stored_bundle(session_maker, run) == {}

    async def test_secret_revoked_when_run_is_cancelled(
        self, monkeypatch, tmp_path, patched_settings, session_maker
    ):
        from src.webapi.engine.temporal import TemporalEngine
        patched_settings()
        run, client = await self._start(
            monkeypatch, tmp_path, _repo(push_patches=True, **GITLAB_REPO), token="t0k")
        engine = TemporalEngine()
        client2 = MagicMock()
        client2.get_workflow_handle = MagicMock(return_value=MagicMock(terminate=AsyncMock()))
        monkeypatch.setattr(engine, "_client", AsyncMock(return_value=client2))
        run.workflow_id = run.session_id
        await engine.cancel(run)
        assert await stored_bundle(session_maker, run) == {}

    async def test_secret_revoked_when_start_fails(
        self, monkeypatch, tmp_path, patched_settings, session_maker
    ):
        from src.webapi.engine.temporal import TemporalEngine
        patched_settings()
        engine = TemporalEngine()
        client = MagicMock()
        client.start_workflow = AsyncMock(side_effect=RuntimeError("boom"))
        monkeypatch.setattr(engine, "_client", AsyncMock(return_value=client))
        monkeypatch.setattr(engine, "_resolve_token", AsyncMock(return_value="t0k"))
        run = _run(tmp_path)
        with pytest.raises(RuntimeError):
            await engine.start(run, _job(), _repo(push_patches=True, **GITLAB_REPO))
        assert await stored_bundle(session_maker, run) == {}


# --------------------------------------------------------------------------- docker

class TestDockerEngine:
    def _fake_docker(self, monkeypatch):
        container = SimpleNamespace(id="cont-1")
        client = MagicMock()
        client.containers.run.return_value = container
        mod = types.ModuleType("docker")
        mod.from_env = lambda: client
        monkeypatch.setitem(sys.modules, "docker", mod)
        # The API (not the container) starts the workflow through the Temporal client.
        self.tclient = MagicMock()
        self.tclient.start_workflow = AsyncMock()
        tc = types.ModuleType("temporalio.client")
        tc.Client = SimpleNamespace(connect=AsyncMock(return_value=self.tclient))
        tcommon = types.ModuleType("temporalio.common")
        tcommon.WorkflowIDConflictPolicy = SimpleNamespace(USE_EXISTING="use_existing")
        monkeypatch.setitem(sys.modules, "temporalio", types.ModuleType("temporalio"))
        monkeypatch.setitem(sys.modules, "temporalio.client", tc)
        monkeypatch.setitem(sys.modules, "temporalio.common", tcommon)
        return client

    async def _start(self, monkeypatch, tmp_path, repo=None, token=None):
        from src.webapi.engine.docker_temporal import DockerTemporalEngine
        client = self._fake_docker(monkeypatch)
        engine = DockerTemporalEngine()
        monkeypatch.setattr(engine, "_resolve_token", AsyncMock(return_value=token))
        run = _run(tmp_path)
        await engine.start(run, _job(), repo or _repo())
        return run, client.containers.run.call_args

    async def test_command_hosts_a_worker_that_exits_with_the_workflow(
        self, monkeypatch, tmp_path, patched_settings
    ):
        patched_settings()
        run, call = await self._start(monkeypatch, tmp_path)
        cmd = call.kwargs["command"]
        assert "--engine" not in cmd and "--serve" in cmd
        assert cmd[cmd.index("--exit-with-workflow") + 1] == run.session_id

    async def test_network_and_internal_api_url_env(self, monkeypatch, tmp_path, patched_settings):
        patched_settings(docker_network="my_net", internal_api_url="http://api:9999")
        _, call = await self._start(monkeypatch, tmp_path)
        assert call.kwargs["network"] == "my_net"
        env = call.kwargs["environment"]
        assert env["VIGILO_INTERNAL_API_URL"] == "http://api:9999"
        assert set(env) == {"TEMPORAL_ADDRESS", "VIGILO_INTERNAL_API_URL"}

    async def test_workflow_started_by_the_api_with_the_full_input(
        self, monkeypatch, tmp_path, patched_settings
    ):
        patched_settings()
        run, call = await self._start(monkeypatch, tmp_path)
        args, kwargs = self.tclient.start_workflow.call_args
        assert args[0] == "WhiteboxEngineWorkflow"
        assert args[1]["repo_path"] == "/repos/target" and args[1]["session_id"] == run.session_id
        assert args[1]["pipeline_config"] == {"max_concurrent_pipelines": 8}
        assert kwargs["id"] == run.session_id == run.workflow_id
        assert kwargs["task_queue"] == call.kwargs["command"][call.kwargs["command"].index("--task-queue") + 1]
        assert run.container_id == "cont-1"

    async def test_refresh_sets_phase_and_cost(self, monkeypatch, tmp_path, patched_settings):
        import json as _json

        from src.webapi.engine.docker_temporal import DockerTemporalEngine
        patched_settings()
        run = _run(tmp_path)
        run.workflow_id = run.session_id
        run.total_cost_usd = None
        run.error_summary = None
        sdir = os.path.join(run.data_dir, "repo", ".vigilo", run.session_id)
        os.makedirs(sdir)
        with open(os.path.join(sdir, "session.json"), "w") as fh:
            _json.dump({"metrics": {"total_cost_usd": 1.5}}, fh)
        handle = MagicMock()
        handle.describe = AsyncMock(return_value=SimpleNamespace(status=SimpleNamespace(value=2)))
        client = MagicMock()
        client.get_workflow_handle = MagicMock(return_value=handle)
        temporalio = types.ModuleType("temporalio")
        tc = types.ModuleType("temporalio.client")
        tc.Client = SimpleNamespace(connect=AsyncMock(return_value=client))
        monkeypatch.setitem(sys.modules, "temporalio", temporalio)
        monkeypatch.setitem(sys.modules, "temporalio.client", tc)
        await DockerTemporalEngine().refresh(run)
        assert run.status == "succeeded"
        assert run.current_phase == "report"
        assert run.total_cost_usd == 1.5

    async def test_no_secret_in_env_command_volumes_or_workflow_input(
        self, monkeypatch, tmp_path, patched_settings, session_maker
    ):
        patched_settings()
        monkeypatch.setattr("src.webapi.engine.common.resolve_job_cookie",
                            AsyncMock(return_value="S=cookie-secret-value"))
        repo = _repo(push_patches=True, **GITLAB_REPO)
        run, call = await self._start(monkeypatch, tmp_path, repo, token="glpat-secret")
        key = self.tclient.start_workflow.call_args.args[1]["secrets"]["key"]
        container_view = repr(call.kwargs)
        for secret in ("glpat-secret", "cookie-secret-value", key):
            assert secret not in container_view      # nothing for an agent to read from /proc
            assert secret not in repr(self.tclient.start_workflow.call_args) or secret == key
        assert list(call.kwargs["volumes"]) == [os.path.join(run.data_dir, "repo")]
        assert await stored_bundle(session_maker, run) == {
            "gitlab_token": "glpat-secret", "cookie_header": "S=cookie-secret-value"}

    async def test_secret_revoked_when_launch_fails(
        self, monkeypatch, tmp_path, patched_settings, session_maker
    ):
        patched_settings()
        from src.webapi.engine.docker_temporal import DockerTemporalEngine
        self._fake_docker(monkeypatch)
        self.tclient.start_workflow = AsyncMock(side_effect=RuntimeError("temporal down"))
        engine = DockerTemporalEngine()
        monkeypatch.setattr(engine, "_resolve_token", AsyncMock(return_value="glpat-secret"))
        run = _run(tmp_path)
        with pytest.raises(RuntimeError):
            await engine.start(run, _job(), _repo(push_patches=True, **GITLAB_REPO))
        assert await stored_bundle(session_maker, run) == {}

    async def test_upload_repo_pushes_nothing(self, monkeypatch, tmp_path, patched_settings):
        patched_settings()
        run, call = await self._start(
            monkeypatch, tmp_path, _repo(source_type="upload", push_patches=True))
        assert "secrets" not in self.tclient.start_workflow.call_args.args[1]
        assert len(call.kwargs["volumes"]) == 1
