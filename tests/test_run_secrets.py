"""Worker side of per-run secrets: just-in-time redemption, redaction, agent env, prompts.

The token / cookie must never be on disk, in workflow input, argv, saved prompts, logs or
events, and an agent's process environment must lack the redemption reference.
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

# Some grey-box test modules replace temporalio / aiofiles in sys.modules at import
# time; reuse the white-box suite's isolation so these tests see the real packages.
from tests.test_whitebox_engine import (  # noqa: F401
    ActivityInput,
    ApplicationError,
    _real_temporal_modules,
    acts,
    temporalio,
)

from src.ai.envguard import strip_secret_env
from src.audit import redact as redact_mod
from src.services import run_secrets

COOKIE = "SESSION=cookie-secret-AAAA1111; csrf=csrf-secret-BBBB2222"
REF = {"ref": "22222222-2222-2222-2222-222222222222", "key": "redemption-key-" + "z" * 24}


@pytest.fixture(autouse=True)
def _clean_registry():
    redact_mod.clear()
    yield
    redact_mod.clear()


# ------------------------------------------------------------------ redemption client


class _Stub:
    """A tiny HTTP server standing in for the API's internal listener."""

    def __init__(self, status=200, body=None):
        self.status, self.body, self.requests = status, body or {}, []
        stub = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length", 0))
                stub.requests.append((self.path, json.loads(self.rfile.read(n))))
                data = json.dumps(stub.body).encode()
                self.send_response(stub.status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def stub(monkeypatch):
    made = []

    def make(**kw):
        s = _Stub(**kw)
        made.append(s)
        monkeypatch.setenv("VIGILO_INTERNAL_API_URL", s.url)
        return s

    yield make
    for s in made:
        s.close()


class TestRedeemClient:
    async def test_redeems_exactly_the_requested_kinds(self, stub):
        s = stub(body={"secrets": {"forge_token": "glpat-TOKEN-1234"}})
        got = await run_secrets.redeem(REF, ["forge_token"])
        assert got == {"forge_token": "glpat-TOKEN-1234"}
        path, body = s.requests[0]
        assert path == f"/internal/v1/runs/{REF['ref']}/secrets"
        assert body == {"key": REF["key"], "want": ["forge_token"]}

    async def test_redeemed_values_are_registered_for_masking(self, stub):
        stub(body={"secrets": {"cookie_header": COOKIE}})
        await run_secrets.redeem(REF, ["cookie_header"])
        out = redact_mod.redact(f"curl -H 'Cookie: {COOKIE}' and csrf-secret-BBBB2222 alone")
        assert "cookie-secret-AAAA1111" not in out and "csrf-secret-BBBB2222" not in out

    @pytest.mark.parametrize("code", [403, 404, 410])
    async def test_refusal_is_permanent_and_leaks_nothing(self, stub, code):
        stub(status=code, body={"detail": "refused"})
        with pytest.raises(run_secrets.RedemptionRefused) as e:
            await run_secrets.redeem(REF, ["forge_token"])
        assert REF["key"] not in str(e.value)

    @pytest.mark.parametrize("code", [429, 500, 502])
    async def test_server_trouble_is_transient(self, stub, code):
        stub(status=code)
        with pytest.raises(run_secrets.RedemptionUnavailable):
            await run_secrets.redeem(REF, ["forge_token"])

    async def test_unreachable_is_transient(self, monkeypatch):
        with socket.socket() as sk:
            sk.bind(("127.0.0.1", 0))
            port = sk.getsockname()[1]
        monkeypatch.setenv("VIGILO_INTERNAL_API_URL", f"http://127.0.0.1:{port}")
        with pytest.raises(run_secrets.RedemptionUnavailable):
            await run_secrets.redeem(REF, ["forge_token"])

    async def test_no_reference_is_refused_without_a_request(self):
        for ref in (None, {}, {"ref": "x"}):
            with pytest.raises(run_secrets.RedemptionRefused):
                await run_secrets.redeem(ref, ["forge_token"])

    async def test_proxies_from_the_environment_are_not_used(self, stub, monkeypatch):
        s = stub(body={"secrets": {"forge_token": "tok-abcdef"}})
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
        assert (await run_secrets.redeem(REF, ["forge_token"]))["forge_token"] == "tok-abcdef"
        assert s.requests

    def test_default_url_points_at_the_internal_port(self, monkeypatch):
        monkeypatch.delenv("VIGILO_INTERNAL_API_URL", raising=False)
        assert run_secrets.internal_api_url() == "http://api:8081"


class TestEndToEndAgainstTheRealInternalApp:
    """Worker client -> real uvicorn listener -> real secret_store, over a file SQLite DB."""

    async def test_redeem_refuse_and_revoke(self, tmp_path, monkeypatch):
        import uvicorn
        from sqlalchemy import create_engine
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

        from src.webapi import secret_store
        from src.webapi.db import Base, get_async_session
        from src.webapi.internal import create_internal_app
        from src.webapi.models import Job, Repository, Run, User
        from src.webapi.security.vault import generate_key
        from src.webapi.settings import get_settings

        monkeypatch.setenv("VIGILO_FERNET_KEY", generate_key())
        monkeypatch.setenv("VIGILO_JWT_SECRET", "x")
        get_settings.cache_clear()
        url = f"sqlite+aiosqlite:///{tmp_path}/e2e.db"
        sync = create_engine(f"sqlite:///{tmp_path}/e2e.db")
        Base.metadata.create_all(sync)

        eng = create_async_engine(url)
        maker = async_sessionmaker(eng, expire_on_commit=False, class_=AsyncSession)
        async with maker() as s:
            import uuid
            u = User(id=uuid.uuid4(), email="e@e.com", hashed_password="x", role="user",
                     is_active=True, is_superuser=False, is_verified=True)
            s.add(u)
            await s.flush()
            r = Repository(created_by=u.id, name="r", source_type="upload")
            s.add(r)
            await s.flush()
            j = Job(created_by=u.id, repository_id=r.id, name="j", stage_preset="vuln")
            s.add(j)
            await s.flush()
            run = Run(job_id=j.id, status="running", session_id="s", data_dir="/x")
            other = Run(job_id=j.id, status="running", session_id="s2", data_dir="/y")
            s.add_all([run, other])
            await s.commit()
            key = await secret_store.issue(s, run.id, {"forge_token": "glpat-E2E-TOKEN"})
            run_id, other_id = run.id, other.id
        await eng.dispose()

        app = create_internal_app()
        holder: dict[str, Any] = {}

        async def _session():
            if "maker" not in holder:  # created inside the server's own loop
                holder["eng"] = create_async_engine(url)
                holder["maker"] = async_sessionmaker(holder["eng"], expire_on_commit=False, class_=AsyncSession)
            async with holder["maker"]() as s:
                yield s

        app.dependency_overrides[get_async_session] = _session
        with socket.socket() as sk:
            sk.bind(("127.0.0.1", 0))
            port = sk.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        t = threading.Thread(target=server.run, daemon=True)
        t.start()
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        monkeypatch.setenv("VIGILO_INTERNAL_API_URL", f"http://127.0.0.1:{port}")
        try:
            ref = {"ref": str(run_id), "key": key}
            assert await run_secrets.redeem(ref, ["forge_token"]) == {"forge_token": "glpat-E2E-TOKEN"}
            # another run's id with this run's key, and a wrong key: refused
            with pytest.raises(run_secrets.RedemptionRefused):
                await run_secrets.redeem({"ref": str(other_id), "key": key}, ["forge_token"])
            with pytest.raises(run_secrets.RedemptionRefused):
                await run_secrets.redeem({"ref": str(run_id), "key": "w" * 40}, ["forge_token"])
            # the platform marks the run finished: no more redemption
            eng2 = create_async_engine(url)
            async with async_sessionmaker(eng2, class_=AsyncSession)() as s:
                (await s.get(Run, run_id)).status = "succeeded"
                await s.commit()
            await eng2.dispose()
            with pytest.raises(run_secrets.RedemptionRefused):
                await run_secrets.redeem(ref, ["forge_token"])
        finally:
            server.should_exit = True
            t.join(5)
            get_settings.cache_clear()


# ------------------------------------------------------------------ redaction in the audit writers


class TestRedaction:
    def test_variants_and_short_values(self):
        redact_mod.register_secret('a=short; token="quoted value 12345"')
        out = redact_mod.redact('x quoted value 12345 y; short stays; a=short')
        assert "quoted value 12345" not in out and "short stays" in out
        redact_mod.register_secret("p@ss/w0rd+long")
        assert "p%40ss%2Fw0rd%2Blong" not in redact_mod.redact("p%40ss%2Fw0rd%2Blong")

    async def test_event_log_workflow_log_and_agent_logs_are_masked(self, tmp_path):
        from src.audit.agent_logger import AgentLogger
        from src.audit.events import EventLog

        redact_mod.register_secret(COOKIE)
        ev = EventLog(str(tmp_path), "run1")
        ev.agent_turn("investigator-1", 3, f"I will curl with Cookie: {COOKIE} now", "investigate")
        ev.emit("agent.failed", f"boom {COOKIE}", actor="x")
        for name in ("events.jsonl", "workflow.log"):
            text = (tmp_path / name).read_text()
            assert "cookie-secret-AAAA1111" not in text and "csrf-secret-BBBB2222" not in text, name
            assert "***" in text

        lg = AgentLogger(str(tmp_path))
        await lg.start_agent_log("investigator-1", 1, session_id="s", web_url="http://t")
        await lg.log_event("investigator-1", "llm_response", {"content": f"saw {COOKIE}"})
        await lg.save_prompt("investigator-1", f"use Cookie: {COOKIE}", session_id="s")
        for p in list((tmp_path / "agents").glob("*")) + list((tmp_path / "prompts").glob("*")):
            text = p.read_text()
            assert "cookie-secret-AAAA1111" not in text and "csrf-secret-BBBB2222" not in text, p
        assert "***" in (tmp_path / "prompts" / "investigator-1.md").read_text()

    async def test_session_metadata_is_masked(self, tmp_path):
        from src.audit.metrics_tracker import MetricsTracker

        redact_mod.register_secret(COOKIE)
        mt = MetricsTracker(str(tmp_path / "session.json"))
        await mt._write_unsafe({"metrics": {"error": f"leak {COOKIE}"}})
        assert "cookie-secret-AAAA1111" not in (tmp_path / "session.json").read_text()

    def test_error_text_sent_to_temporal_is_masked(self):
        redact_mod.register_secret(COOKIE)
        assert "cookie-secret-AAAA1111" not in acts._truncate(f"agent failed: {COOKIE}")


# ------------------------------------------------------------------ agent environment


SECRET_ENV = {
    "VIGILO_REDEEM_KEY": "k", "VIGILO_SECRET_REF": "r", "VIGILO_RUN_SECRETS": "x",
    "VIGILO_GIT_TOKEN": "glpat-leak", "GIT_ASKPASS": "/tmp/askpass.sh",
    "GITLAB_TOKEN": "glpat-leak2", "VIGILO_INTERNAL_API_URL": "http://api:8081",
    "VIGILO_FERNET_KEY": "f", "VIGILO_JWT_SECRET": "j", "VIGILO_DATABASE_URL": "postgres://u:p@h/d",
}


class TestAgentEnv:
    def test_strip(self):
        env = {**SECRET_ENV, "PATH": "/bin", "VIGILO_AGENT": "a", "VIGILO_REPO_PATH": "/r",
               "VIGILO_EXECUTOR": "claude", "ANTHROPIC_API_KEY": "sk"}
        out = strip_secret_env(env)
        assert set(out) == {"PATH", "VIGILO_AGENT", "VIGILO_REPO_PATH", "VIGILO_EXECUTOR", "ANTHROPIC_API_KEY"}

    @pytest.mark.parametrize("backend", ["claude", "codex", "opencode"])
    async def test_agent_subprocess_env_lacks_secrets(self, tmp_path, monkeypatch, backend):
        dump = tmp_path / "env.txt"
        fake = tmp_path / backend
        fake.write_text(f"#!/bin/sh\nenv > {dump}\nexit 0\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        for k, v in SECRET_ENV.items():          # present in the WORKER's environment
            monkeypatch.setenv(k, v)
        from src.ai.executor import execute

        await execute(
            prompt="hi", agent_name="surveyor", model_tier="medium", cwd=str(tmp_path),
            extra_env={"VIGILO_EXECUTOR": backend, "VIGILO_RUN_SECRET_KEY": "from-extra-env",
                       "VIGILO_REPO_PATH": str(tmp_path)},
            idle_timeout_s=30,  # generous: a loaded CI box can be slow to start the fake CLI
        )
        seen = dump.read_text()
        for name in list(SECRET_ENV) + ["VIGILO_RUN_SECRET_KEY"]:
            assert f"{name}=" not in seen, name
        assert "VIGILO_AGENT=surveyor" in seen and "VIGILO_REPO_PATH=" in seen


# ------------------------------------------------------------------ cookie in agents' prompts


def _fake_world(monkeypatch, repo: Path):
    """Real prompts + real audit writers; fake executor / validation / redemption."""
    seen: dict[str, Any] = {"redeems": []}

    async def fake_redeem(secrets, want, **kw):
        seen["redeems"].append((secrets, list(want)))
        redact_mod.register_secret(COOKIE)
        return {"cookie_header": COOKIE}

    async def fake_execute(prompt, agent_name, model_tier, cwd, on_stream=None, extra_env=None, **kw):
        from src.ai.executor import ExecutorResult
        seen.setdefault("prompts", {})[agent_name] = prompt
        seen.setdefault("env", {})[agent_name] = dict(extra_env or {})
        if on_stream:  # the agent echoes the cookie in its output
            await on_stream(agent_name, 1, f"curl -H 'Cookie: {COOKIE}' http://target")
        return ExecutorResult(success=True, duration_ms=1, cost_usd=0.0, num_turns=1, model="m",
                              input_tokens=1, output_tokens=1, result_text="ok")

    async def ok(*a, **k):
        return True

    async def noop(*a, **k):
        return None

    monkeypatch.setattr(run_secrets, "redeem", fake_redeem)
    monkeypatch.setattr("src.ai.executor.execute", fake_execute)
    monkeypatch.setattr("src.ai.executor.validate_agent_output", ok)
    monkeypatch.setattr(acts, "_validate_output", ok)
    monkeypatch.setattr(acts, "_sync_deliverables", noop)
    return seen


def _ai(repo: Path, **kw) -> ActivityInput:
    base = dict(repo_path=str(repo), workflow_id="wf", session_id="sess", web_url="http://target.local",
                auth={"cookie": True}, secrets=REF)
    base.update(kw)
    return ActivityInput(**base)


def _run(actor: str, ai: ActivityInput) -> Any:
    return asyncio.run(temporalio.testing.ActivityEnvironment().run(acts.run_agent, actor, ai))


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    return r


class TestCookieInPrompts:
    @pytest.mark.parametrize("actor", ["surveyor", "investigator-1", "prover-2"])
    def test_cookie_reaches_live_target_actors_but_is_masked_everywhere_persisted(
        self, monkeypatch, repo, actor
    ):
        seen = _fake_world(monkeypatch, repo)
        _run(actor, _ai(repo, extra_context="LEADS: L-001"))

        prompt = seen["prompts"][actor]
        assert "cookie-secret-AAAA1111" in prompt                 # the agent can log in
        assert seen["redeems"] == [(REF, ["cookie_header"])]
        # the agent's environment never carries the reference
        assert REF["key"] not in json.dumps(seen["env"][actor]) and REF["key"] not in prompt

        ws = repo / ".vigilo" / "sess"
        persisted = [p for p in ws.rglob("*") if p.is_file()]
        assert persisted
        for p in persisted:
            text = p.read_text(errors="ignore")
            assert "cookie-secret-AAAA1111" not in text, p
            assert "csrf-secret-BBBB2222" not in text, p
            assert REF["key"] not in text, p
        snap = next(p for p in persisted if p.parent.name == "prompts")
        assert "***" in snap.read_text()                         # masked, not dropped
        assert "***" in (ws / "events.jsonl").read_text()        # the echoed output is masked too

    def test_planner_gets_no_cookie_and_no_redemption(self, monkeypatch, repo):
        seen = _fake_world(monkeypatch, repo)
        _run("planner", _ai(repo))
        assert "cookie-secret-AAAA1111" not in seen["prompts"]["planner"]
        assert seen["redeems"] == []

    @pytest.mark.parametrize("kw", [{"auth": None}, {"web_url": ""}])
    def test_nothing_redeemed_without_flag_or_target(self, monkeypatch, repo, kw):
        seen = _fake_world(monkeypatch, repo)
        _run("investigator-1", _ai(repo, **kw))
        assert seen["redeems"] == []
        assert "cookie-secret-AAAA1111" not in seen["prompts"]["investigator-1"]

    def test_refused_redemption_is_permanent_and_unreachable_platform_is_retried(self, monkeypatch, repo):
        _fake_world(monkeypatch, repo)

        async def refuse(*a, **k):
            raise run_secrets.RedemptionRefused("HTTP 403")

        async def down(*a, **k):
            raise run_secrets.RedemptionUnavailable("URLError")

        monkeypatch.setattr(run_secrets, "redeem", refuse)
        with pytest.raises(ApplicationError) as e:
            _run("investigator-1", _ai(repo))
        assert e.value.non_retryable and e.value.type == "ConfigurationError"
        monkeypatch.setattr(run_secrets, "redeem", down)
        with pytest.raises(ApplicationError) as e:
            _run("investigator-1", _ai(repo))
        assert not e.value.non_retryable

    def test_the_cookie_never_becomes_part_of_the_activity_input(self):
        from temporalio.converter import DataConverter

        ai = _ai(Path("/r"))
        payloads = DataConverter.default.payload_converter.to_payloads([ai])
        assert "cookie-secret" not in repr(payloads)


# ------------------------------------------------------------------ per-run worker lifetime


class TestWorkerExitsWithWorkflow:
    async def test_shuts_down_when_the_workflow_closes(self):
        from types import SimpleNamespace

        from src.temporal.worker import _run_until_workflow_closes

        state = {"n": 0, "down": False}

        class Worker:
            async def run(self):
                while not state["down"]:
                    await asyncio.sleep(0.01)

            async def shutdown(self):
                state["down"] = True

        class Handle:
            async def describe(self):
                state["n"] += 1
                if state["n"] == 1:
                    raise RuntimeError("not found yet")
                return SimpleNamespace(status=SimpleNamespace(value=1 if state["n"] < 4 else 2))

        client = SimpleNamespace(get_workflow_handle=lambda wid: Handle())
        await asyncio.wait_for(
            _run_until_workflow_closes(Worker(), client, "wf", poll_s=0.01), 5)
        assert state["down"] and state["n"] >= 4

    async def test_gives_up_if_the_workflow_never_starts(self):
        from types import SimpleNamespace

        from src.temporal.worker import _run_until_workflow_closes

        down = {"v": False}

        class Worker:
            async def run(self):
                while not down["v"]:
                    await asyncio.sleep(0.01)

            async def shutdown(self):
                down["v"] = True

        class Handle:
            async def describe(self):
                raise RuntimeError("nope")

        await asyncio.wait_for(_run_until_workflow_closes(
            Worker(), SimpleNamespace(get_workflow_handle=lambda w: Handle()), "wf",
            poll_s=0.01, start_grace_s=0.05), 5)
        assert down["v"]
