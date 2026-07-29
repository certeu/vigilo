"""Tests for the executor abstraction layer (src/ai/executor.py).

Covers auto-detection of executor type, explicit overrides, edge cases,
and dispatch to the correct backend.
"""
from __future__ import annotations

import pytest

from src.ai.executor import (
    ExecutorResult,
    ExecutorType,
    _OPENCODE_SIGNAL_VARS,
    get_executor_type,
)


# ---------------------------------------------------------------------------
# get_executor_type() — auto-detection
# ---------------------------------------------------------------------------


class TestGetExecutorTypeAutoDetection:
    """Auto-detect opencode when LiteLLM/OpenCode env vars are present."""

    def test_default_is_claude(self, monkeypatch):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        for v in _OPENCODE_SIGNAL_VARS:
            monkeypatch.delenv(v, raising=False)
        assert get_executor_type() == "claude"

    @pytest.mark.parametrize("signal_var", _OPENCODE_SIGNAL_VARS)
    def test_auto_detects_opencode_from_single_var(self, monkeypatch, signal_var):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        for v in _OPENCODE_SIGNAL_VARS:
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setenv(signal_var, "some-value")
        assert get_executor_type() == "opencode"

    def test_auto_detects_opencode_from_multiple_vars(self, monkeypatch):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        monkeypatch.setenv("LITELLM_BASE_URL", "https://litellm.local/")
        monkeypatch.setenv("OPENCODE_LARGE_MODEL", "deepseek-v3")
        assert get_executor_type() == "opencode"

    def test_empty_signal_var_does_not_trigger(self, monkeypatch):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        for v in _OPENCODE_SIGNAL_VARS:
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setenv("LITELLM_BASE_URL", "")
        assert get_executor_type() == "claude"


# ---------------------------------------------------------------------------
# get_executor_type() — explicit override
# ---------------------------------------------------------------------------


class TestGetExecutorTypeExplicit:
    """VIGILO_EXECUTOR always takes precedence over auto-detection."""

    def test_explicit_claude(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "claude")
        monkeypatch.setenv("LITELLM_BASE_URL", "https://litellm.local/")
        assert get_executor_type() == "claude"

    def test_explicit_opencode(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "opencode")
        for v in _OPENCODE_SIGNAL_VARS:
            monkeypatch.delenv(v, raising=False)
        assert get_executor_type() == "opencode"

    def test_explicit_with_whitespace(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "  opencode  ")
        assert get_executor_type() == "opencode"

    def test_explicit_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "OPENCODE")
        assert get_executor_type() == "opencode"

    def test_unknown_explicit_value_falls_back_to_claude(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "gpt-magic")
        assert get_executor_type() == "claude"

    def test_explicit_empty_string_triggers_auto_detection(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "")
        monkeypatch.setenv("LITELLM_BASE_URL", "https://litellm.local/")
        assert get_executor_type() == "opencode"

    def test_explicit_empty_string_defaults_to_claude(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "")
        for v in _OPENCODE_SIGNAL_VARS:
            monkeypatch.delenv(v, raising=False)
        assert get_executor_type() == "claude"


# ---------------------------------------------------------------------------
# ExecutorResult
# ---------------------------------------------------------------------------


class TestExecutorResult:
    def test_fields(self):
        r = ExecutorResult(
            success=True,
            duration_ms=1234,
            cost_usd=0.05,
            num_turns=3,
            model="claude-sonnet-4-6",
            input_tokens=1000,
            output_tokens=500,
            result_text="done",
        )
        assert r.success is True
        assert r.error is None
        assert r.model == "claude-sonnet-4-6"

    def test_error_default(self):
        r = ExecutorResult(
            success=False,
            duration_ms=0,
            cost_usd=0.0,
            num_turns=0,
            model=None,
            input_tokens=0,
            output_tokens=0,
            result_text=None,
            error="boom",
        )
        assert r.error == "boom"


# ---------------------------------------------------------------------------
# execute() dispatch — verify it routes to the right backend
# ---------------------------------------------------------------------------


class TestExecuteDispatch:
    """Verify execute() calls the correct backend based on executor type."""

    @pytest.mark.asyncio
    async def test_dispatches_to_claude_by_default(self, monkeypatch, tmp_path):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        for v in _OPENCODE_SIGNAL_VARS:
            monkeypatch.delenv(v, raising=False)

        fake = tmp_path / "claude"
        fake.write_text('#!/bin/sh\necho \'{"type":"result","result":"ok","num_turns":1,"total_cost_usd":0.0}\'\n')
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        from src.ai.executor import execute
        result = await execute(
            prompt="test",
            agent_name="test-agent",
            model_tier="medium",
            cwd=str(tmp_path),
            max_turns=1,
        )
        assert result.model is not None
        assert "claude" in result.model or "sonnet" in result.model or "opus" in result.model or "haiku" in result.model

    @pytest.mark.asyncio
    async def test_dispatches_to_opencode_when_autodetected(self, monkeypatch, tmp_path):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        monkeypatch.setenv("LITELLM_BASE_URL", "https://litellm.local/")

        fake = tmp_path / "opencode"
        fake.write_text('#!/bin/sh\necho \'{"type":"step_start","part":{"type":"step-start"}}\'\necho \'{"type":"step_finish","part":{"type":"step-finish","reason":"stop","tokens":{"input":10,"output":5},"cost":0.001}}\'\n')
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

        from src.ai.executor import execute
        result = await execute(
            prompt="test",
            agent_name="test-agent",
            model_tier="medium",
            cwd=str(tmp_path),
            max_turns=1,
        )
        assert result.model is not None
        assert "litellm" in result.model

    @pytest.mark.asyncio
    async def test_dispatches_to_opencode_with_explicit_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("VIGILO_EXECUTOR", "opencode")

        fake = tmp_path / "opencode"
        fake.write_text('#!/bin/sh\necho \'{"type":"step_finish","part":{"type":"step-finish","reason":"stop","tokens":{"input":1,"output":1},"cost":0.0}}\'\n')
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

        from src.ai.executor import execute
        result = await execute(
            prompt="test",
            agent_name="test-agent",
            model_tier="small",
            cwd=str(tmp_path),
            max_turns=1,
        )
        assert "litellm" in (result.model or "")

    @pytest.mark.asyncio
    async def test_explicit_claude_ignores_opencode_vars(self, monkeypatch, tmp_path):
        monkeypatch.setenv("VIGILO_EXECUTOR", "claude")
        monkeypatch.setenv("LITELLM_BASE_URL", "https://litellm.local/")
        monkeypatch.setenv("OPENCODE_LARGE_MODEL", "deepseek-v3")

        fake = tmp_path / "claude"
        fake.write_text('#!/bin/sh\necho \'{"type":"result","result":"ok","num_turns":1,"total_cost_usd":0.0}\'\n')
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        from src.ai.executor import execute
        result = await execute(
            prompt="test",
            agent_name="test-agent",
            model_tier="large",
            cwd=str(tmp_path),
            max_turns=1,
        )
        assert "litellm" not in (result.model or "")


# ---------------------------------------------------------------------------
# Model tier resolution per executor
# ---------------------------------------------------------------------------


class TestModelResolution:
    def test_claude_default_tiers(self, monkeypatch):
        for v in ("ANTHROPIC_SMALL_MODEL", "ANTHROPIC_MEDIUM_MODEL", "ANTHROPIC_LARGE_MODEL"):
            monkeypatch.delenv(v, raising=False)
        from src.ai.claude_executor import resolve_model
        assert resolve_model("small") == "claude-haiku-4-5"
        assert resolve_model("medium") == "claude-sonnet-4-6"
        assert resolve_model("large") == "claude-opus-4-6"

    def test_claude_env_override(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_LARGE_MODEL", "claude-opus-4-7")
        from src.ai.claude_executor import resolve_model
        assert resolve_model("large") == "claude-opus-4-7"

    def test_claude_empty_env_uses_default(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_SMALL_MODEL", "")
        from src.ai.claude_executor import resolve_model
        assert resolve_model("small") == "claude-haiku-4-5"

    def test_claude_unknown_tier_passes_through_as_concrete_model(self, monkeypatch):
        from src.ai.claude_executor import resolve_model
        assert resolve_model("turbo") == "turbo"

    def test_opencode_default_tiers(self, monkeypatch):
        for v in ("OPENCODE_SMALL_MODEL", "OPENCODE_MEDIUM_MODEL", "OPENCODE_LARGE_MODEL"):
            monkeypatch.delenv(v, raising=False)
        from src.ai.opencode_executor import resolve_model
        assert resolve_model("small") == "litellm/qwen3.6"
        assert resolve_model("medium") == "litellm/qwen3.6"
        assert resolve_model("large") == "litellm/qwen3.6"

    def test_opencode_env_override(self, monkeypatch):
        monkeypatch.setenv("OPENCODE_LARGE_MODEL", "deepseek-v3")
        from src.ai.opencode_executor import resolve_model
        assert resolve_model("large") == "litellm/deepseek-v3"

    def test_opencode_already_prefixed(self, monkeypatch):
        monkeypatch.setenv("OPENCODE_MEDIUM_MODEL", "litellm/custom-model")
        from src.ai.opencode_executor import resolve_model
        assert resolve_model("medium") == "litellm/custom-model"

    def test_opencode_empty_env_uses_default(self, monkeypatch):
        monkeypatch.setenv("OPENCODE_SMALL_MODEL", "")
        from src.ai.opencode_executor import resolve_model
        assert resolve_model("small") == "litellm/qwen3.6"


# ---------------------------------------------------------------------------
# Idle timeout — both executors
# ---------------------------------------------------------------------------


class TestIdleTimeout:
    @pytest.mark.asyncio
    async def test_claude_idle_timeout(self, monkeypatch, tmp_path):
        fake = tmp_path / "claude"
        fake.write_text("#!/bin/sh\nexec sleep 60\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        from src.ai.claude_executor import execute
        result = await execute(
            prompt="hello",
            agent_name="timeout-test",
            model_tier="medium",
            cwd=str(tmp_path),
            idle_timeout_s=0.3,
        )
        assert result.success is False
        assert "idle timeout" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_opencode_idle_timeout(self, monkeypatch, tmp_path):
        fake = tmp_path / "opencode"
        fake.write_text("#!/bin/sh\nexec sleep 60\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

        from src.ai.opencode_executor import execute
        result = await execute(
            prompt="hello",
            agent_name="timeout-test",
            model_tier="medium",
            cwd=str(tmp_path),
            idle_timeout_s=0.3,
        )
        assert result.success is False
        assert "idle timeout" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# CLI not found — both executors
# ---------------------------------------------------------------------------


class TestCLINotFound:
    @pytest.mark.asyncio
    async def test_claude_cli_not_found(self, monkeypatch, tmp_path):
        monkeypatch.setenv("PATH", str(tmp_path))
        from src.ai.claude_executor import execute
        result = await execute(
            prompt="hello",
            agent_name="missing-cli",
            model_tier="medium",
            cwd=str(tmp_path),
        )
        assert result.success is False
        assert "not found" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_opencode_cli_not_found(self, monkeypatch, tmp_path):
        monkeypatch.setenv("PATH", str(tmp_path))
        from src.ai.opencode_executor import execute
        result = await execute(
            prompt="hello",
            agent_name="missing-cli",
            model_tier="medium",
            cwd=str(tmp_path),
        )
        assert result.success is False
        assert "not found" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_get_cli_name_claude(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "claude")
        from src.ai.executor import get_cli_name
        assert get_cli_name() == "claude"

    def test_get_cli_name_opencode(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "opencode")
        from src.ai.executor import get_cli_name
        assert get_cli_name() == "opencode"

    def test_get_cli_name_auto_detected(self, monkeypatch):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        for v in _OPENCODE_SIGNAL_VARS:
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setenv("LITELLM_BASE_URL", "https://litellm.local/")
        from src.ai.executor import get_cli_name
        assert get_cli_name() == "opencode"

    def test_get_preflight_cmd_claude(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "claude")
        from src.ai.executor import get_preflight_cmd
        cmd = get_preflight_cmd()
        assert cmd[0] == "claude"

    def test_get_preflight_cmd_opencode(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "opencode")
        from src.ai.executor import get_preflight_cmd
        cmd = get_preflight_cmd()
        assert cmd[0] == "opencode"

    def test_build_env_claude_has_max_output_tokens(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "claude")
        from src.ai.executor import build_env
        env = build_env()
        assert "CLAUDE_CODE_MAX_OUTPUT_TOKENS" in env

    def test_build_env_opencode_inherits_process_env(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "opencode")
        monkeypatch.setenv("LITELLM_BASE_URL", "https://litellm.local/")
        from src.ai.executor import build_env
        env = build_env()
        assert env.get("LITELLM_BASE_URL") == "https://litellm.local/"


# ---------------------------------------------------------------------------
# Greybox worker uses get_executor_type() (not raw env var)
# ---------------------------------------------------------------------------


class TestGreyboxWorkerUsesAbstraction:
    """Verify the greybox worker routes through get_executor_type()."""

    def test_worker_source_uses_get_executor_type(self):
        import inspect
        from pathlib import Path
        worker_path = Path(__file__).resolve().parent.parent / "src" / "greybox" / "temporal" / "worker.py"
        source = worker_path.read_text()
        assert "get_executor_type()" in source
        assert 'os.environ.get("VIGILO_EXECUTOR"' not in source


# ---------------------------------------------------------------------------
# Standalone report script uses abstraction
# ---------------------------------------------------------------------------


class TestStandaloneReportUsesAbstraction:
    """Verify run_report_standalone.py uses the executor abstraction."""

    def test_report_script_uses_executor_abstraction(self):
        from pathlib import Path
        script_path = Path(__file__).resolve().parent.parent / "scripts" / "run_report_standalone.py"
        source = script_path.read_text()
        assert "get_executor_type" in source
        assert "from src.ai.executor import" in source
        assert "if executor_type" in source


# ---------------------------------------------------------------------------
# Log output format parity between executors
# ---------------------------------------------------------------------------


class TestLogFormatParity:
    """Both executors must produce the same structured log output."""

    @pytest.mark.asyncio
    async def test_claude_success_log_format(self, monkeypatch, tmp_path, capsys):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        for v in _OPENCODE_SIGNAL_VARS:
            monkeypatch.delenv(v, raising=False)

        fake = tmp_path / "claude"
        fake.write_text(
            '#!/bin/sh\n'
            'echo \'{"type":"result","result":"ok","num_turns":2,'
            '"total_cost_usd":0.01,"usage":{"input_tokens":100,"output_tokens":50},'
            '"model":"claude-sonnet-4-6"}\'\n'
        )
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        from src.ai.claude_executor import execute
        await execute(
            prompt="test", agent_name="log-test",
            model_tier="medium", cwd=str(tmp_path),
        )
        captured = capsys.readouterr().out
        assert "[log-test] done -- 2 turns, $0.01" in captured

    @pytest.mark.asyncio
    async def test_opencode_success_log_format(self, monkeypatch, tmp_path, capsys):
        fake = tmp_path / "opencode"
        fake.write_text(
            '#!/bin/sh\n'
            'echo \'{"type":"step_start","part":{"type":"step-start"}}\'\n'
            'echo \'{"type":"step_start","part":{"type":"step-start"}}\'\n'
            'echo \'{"type":"step_finish","part":{"type":"step-finish","reason":"stop",'
            '"tokens":{"input":60,"output":30},"cost":0.005}}\'\n'
            'echo \'{"type":"step_finish","part":{"type":"step-finish","reason":"stop",'
            '"tokens":{"input":40,"output":20},"cost":0.005}}\'\n'
        )
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

        from src.ai.opencode_executor import execute
        await execute(
            prompt="test", agent_name="log-test",
            model_tier="medium", cwd=str(tmp_path),
        )
        captured = capsys.readouterr().out
        assert "[log-test] done -- 2 turns, $0.01" in captured

    @pytest.mark.asyncio
    async def test_both_executors_error_log_has_executor_field(self, monkeypatch, tmp_path):
        """error.log JSON entries must include 'executor' key for both backends."""
        import json

        for cli_name, executor_mod, executor_label in [
            ("claude", "src.ai.claude_executor", "claude"),
            ("opencode", "src.ai.opencode_executor", "opencode"),
        ]:
            error_log = tmp_path / cli_name / "error.log"
            error_log.parent.mkdir(exist_ok=True)

            fake = error_log.parent / cli_name
            fake.write_text("#!/bin/sh\nexit 1\n")
            fake.chmod(0o755)
            monkeypatch.setenv("PATH", f"{error_log.parent}:/usr/bin:/bin")
            monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

            mod = __import__(executor_mod, fromlist=["execute"])
            await mod.execute(
                prompt="fail", agent_name="err-test",
                model_tier="medium", cwd=str(error_log.parent),
            )

            assert error_log.exists(), f"error.log not created for {executor_label}"
            entry = json.loads(error_log.read_text().strip().split("\n")[-1])
            assert entry["executor"] == executor_label
            assert "agent" in entry
            assert "timestamp" in entry
            assert "duration_ms" in entry

    @pytest.mark.asyncio
    async def test_logger_info_includes_executor_tag(self, monkeypatch, tmp_path):
        """Both executors include executor= in their logger.info messages."""
        from pathlib import Path
        claude_src = (Path(__file__).resolve().parent.parent / "src" / "ai" / "claude_executor.py").read_text()
        opencode_src = (Path(__file__).resolve().parent.parent / "src" / "ai" / "opencode_executor.py").read_text()

        assert "executor=claude" in claude_src
        assert "executor=opencode" in opencode_src

    def test_done_line_uses_double_dash_not_emdash(self):
        """Both executors use '-- ' (double dash) not '— ' (em-dash) in done line."""
        from pathlib import Path
        for name in ("claude_executor.py", "opencode_executor.py"):
            src = (Path(__file__).resolve().parent.parent / "src" / "ai" / name).read_text()
            assert "done --" in src, f"{name} missing 'done --'"
            assert "done —" not in src, f"{name} still uses em-dash"


# ---------------------------------------------------------------------------
# Codex executor wiring
# ---------------------------------------------------------------------------


class TestCodexExecutor:
    def test_explicit_codex(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "codex")
        from src.ai.executor import get_executor_type
        assert get_executor_type() == "codex"

    def test_autodetect_codex_before_opencode(self, monkeypatch):
        from src.ai.executor import (
            _OPENCODE_SIGNAL_VARS,
            _CODEX_SIGNAL_VARS,
            get_executor_type,
        )
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        for v in (*_OPENCODE_SIGNAL_VARS, *_CODEX_SIGNAL_VARS):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setenv("LITELLM_BASE_URL", "https://litellm.local/")
        monkeypatch.setenv("CODEX_API_KEY", "sk-x")
        assert get_executor_type() == "codex"

    def test_get_cli_name_codex(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "codex")
        from src.ai.executor import get_cli_name
        assert get_cli_name() == "codex"

    def test_get_preflight_cmd_codex(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "codex")
        from src.ai.executor import get_preflight_cmd
        cmd = get_preflight_cmd()
        assert cmd[0] == "codex" and "--skip-git-repo-check" in cmd

    def test_unknown_executor_still_falls_through_to_claude(self, monkeypatch):
        monkeypatch.setenv("VIGILO_EXECUTOR", "gpt-magic")
        from src.ai.executor import get_executor_type
        assert get_executor_type() == "claude"

    @pytest.mark.asyncio
    async def test_dispatches_to_codex_with_explicit_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("VIGILO_EXECUTOR", "codex")
        called = {}

        async def fake_execute(**kwargs):
            called.update(kwargs)
            from src.ai.executor import ExecutorResult
            return ExecutorResult(
                success=True, duration_ms=1, cost_usd=0.0, num_turns=1,
                model="gpt-5-codex", input_tokens=1, output_tokens=1,
                result_text="ok",
            )

        import src.ai.codex_executor as cx
        monkeypatch.setattr(cx, "execute", fake_execute)

        from src.ai.executor import execute
        res = await execute(
            prompt="p", agent_name="a", model_tier="large", cwd=str(tmp_path),
        )
        assert res.success is True
        assert called["agent_name"] == "a"
