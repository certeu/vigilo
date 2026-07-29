"""Tests for Feature A: model override — concrete model bypasses tier resolution."""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Executor resolve_model() pass-through for concrete models
# ---------------------------------------------------------------------------


class TestClaudeResolveModelPassthrough:
    def test_known_tier_resolves_normally(self, monkeypatch):
        for v in ("ANTHROPIC_SMALL_MODEL", "ANTHROPIC_MEDIUM_MODEL", "ANTHROPIC_LARGE_MODEL"):
            monkeypatch.delenv(v, raising=False)
        from src.ai.claude_executor import resolve_model
        assert resolve_model("medium") == "claude-sonnet-4-6"

    def test_concrete_model_passes_through(self):
        from src.ai.claude_executor import resolve_model
        assert resolve_model("gpt-5-5") == "gpt-5-5"

    def test_concrete_model_with_slashes(self):
        from src.ai.claude_executor import resolve_model
        assert resolve_model("openai/gpt-5-5") == "openai/gpt-5-5"

    def test_concrete_model_with_version(self):
        from src.ai.claude_executor import resolve_model
        assert resolve_model("claude-opus-4-7") == "claude-opus-4-7"

    def test_env_override_still_works(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_LARGE_MODEL", "claude-opus-4-7")
        from src.ai.claude_executor import resolve_model
        assert resolve_model("large") == "claude-opus-4-7"


class TestOpenCodeResolveModelPassthrough:
    def test_known_tier_resolves_normally(self, monkeypatch):
        for v in ("OPENCODE_SMALL_MODEL", "OPENCODE_MEDIUM_MODEL", "OPENCODE_LARGE_MODEL"):
            monkeypatch.delenv(v, raising=False)
        from src.ai.opencode_executor import resolve_model
        assert resolve_model("medium") == "litellm/qwen3.6"

    def test_concrete_model_gets_litellm_prefix(self):
        from src.ai.opencode_executor import resolve_model
        assert resolve_model("gpt-5-5") == "litellm/gpt-5-5"

    def test_already_prefixed_model_kept_as_is(self):
        from src.ai.opencode_executor import resolve_model
        assert resolve_model("litellm/gpt-5-5") == "litellm/gpt-5-5"

    def test_env_override_still_works(self, monkeypatch):
        monkeypatch.setenv("OPENCODE_LARGE_MODEL", "deepseek-v3")
        from src.ai.opencode_executor import resolve_model
        assert resolve_model("large") == "litellm/deepseek-v3"


# ---------------------------------------------------------------------------
# GreyBoxConfig.model field
# ---------------------------------------------------------------------------


class TestGreyBoxConfigModel:
    def test_default_model_is_none(self):
        from src.greybox.types.config import GreyBoxConfig
        config = GreyBoxConfig()
        assert config.model is None

    def test_model_can_be_set(self):
        from src.greybox.types.config import GreyBoxConfig
        config = GreyBoxConfig(model="gpt-5-5")
        assert config.model == "gpt-5-5"

    def test_model_parsed_from_yaml(self, tmp_path):
        from src.greybox.types.config import GreyBoxConfig
        config_file = tmp_path / "config.yaml"
        config_file.write_text("model: gpt-5-5\nbudget:\n  max_cost_usd: 10\n")
        config = GreyBoxConfig.from_yaml(config_file)
        assert config.model == "gpt-5-5"

    def test_model_absent_in_yaml_stays_none(self, tmp_path):
        from src.greybox.types.config import GreyBoxConfig
        config_file = tmp_path / "config.yaml"
        config_file.write_text("budget:\n  max_cost_usd: 10\n")
        config = GreyBoxConfig.from_yaml(config_file)
        assert config.model is None


# ---------------------------------------------------------------------------
# ChildWorkflowInput carries model_override
# ---------------------------------------------------------------------------


class TestChildWorkflowInputModelOverride:
    def test_default_model_override_empty(self):
        from src.greybox.temporal.workflows import ChildWorkflowInput
        cwi = ChildWorkflowInput(
            agent_id="test", agent_type="injection-specialist",
            action_type="PROBE_PARAMETERS", session="agent1",
            web_url="http://target", session_id="s1",
            credentials_path="/creds.yaml", output_path="/out",
        )
        assert cwi.model_override == ""

    def test_model_override_set(self):
        from src.greybox.temporal.workflows import ChildWorkflowInput
        cwi = ChildWorkflowInput(
            agent_id="test", agent_type="injection-specialist",
            action_type="PROBE_PARAMETERS", session="agent1",
            web_url="http://target", session_id="s1",
            credentials_path="/creds.yaml", output_path="/out",
            model_override="gpt-5-5",
        )
        assert cwi.model_override == "gpt-5-5"
