"""Tests for Feature C: auth session sharing.

Verifies that pre-authenticated session directory paths flow from
Phase 1 through to child workflows and prompt templates.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# ChildWorkflowInput carries auth_session_dir
# ---------------------------------------------------------------------------


class TestChildWorkflowInputAuthSession:
    def test_default_empty(self):
        from src.greybox.temporal.workflows import ChildWorkflowInput
        cwi = ChildWorkflowInput(
            agent_id="test", agent_type="injection-specialist",
            action_type="PROBE_PARAMETERS", session="agent1",
            web_url="http://target", session_id="s1",
            credentials_path="/creds.yaml", output_path="/out",
        )
        assert cwi.auth_session_dir == ""

    def test_session_dir_set(self):
        from src.greybox.temporal.workflows import ChildWorkflowInput
        cwi = ChildWorkflowInput(
            agent_id="test", agent_type="injection-specialist",
            action_type="PROBE_PARAMETERS", session="agent1",
            web_url="http://target", session_id="s1",
            credentials_path="/creds.yaml", output_path="/out",
            auth_session_dir="/workspace/sessions",
        )
        assert cwi.auth_session_dir == "/workspace/sessions"


# ---------------------------------------------------------------------------
# ResolveContextInput carries auth_session_dir
# ---------------------------------------------------------------------------


class TestResolveContextInputAuthSession:
    def test_default_empty(self):
        from src.greybox.temporal.activities import ResolveContextInput
        rci = ResolveContextInput(
            session_id="s1",
            credentials_path="/creds.yaml",
            web_url="http://target",
        )
        assert rci.auth_session_dir == ""

    def test_session_dir_set(self):
        from src.greybox.temporal.activities import ResolveContextInput
        rci = ResolveContextInput(
            session_id="s1",
            credentials_path="/creds.yaml",
            web_url="http://target",
            auth_session_dir="/workspace/sessions",
        )
        assert rci.auth_session_dir == "/workspace/sessions"


# ---------------------------------------------------------------------------
# BuildPromptInput carries auth_session_dir
# ---------------------------------------------------------------------------


class TestBuildPromptInputAuthSession:
    def test_default_empty(self):
        from src.greybox.temporal.activities import BuildPromptInput
        bpi = BuildPromptInput(
            web_url="http://target",
            session_id="s1",
            agent_name="test-agent",
            prompt_template="greybox/specialist-injection",
        )
        assert bpi.auth_session_dir == ""

    def test_session_dir_set(self):
        from src.greybox.temporal.activities import BuildPromptInput
        bpi = BuildPromptInput(
            web_url="http://target",
            session_id="s1",
            agent_name="test-agent",
            prompt_template="greybox/specialist-injection",
            auth_session_dir="/workspace/sessions",
        )
        assert bpi.auth_session_dir == "/workspace/sessions"


# ---------------------------------------------------------------------------
# Template variable {{AUTH_SESSION_DIR}} is substituted
# ---------------------------------------------------------------------------


class TestAuthSessionDirTemplateVariable:
    def test_substitution(self):
        from src.services.prompt_manager import _interpolate_greybox_variables
        template = "Sessions at: {{AUTH_SESSION_DIR}}"
        result = _interpolate_greybox_variables(
            template,
            web_url="http://target",
            auth_session_dir="/workspace/sessions",
        )
        assert result == "Sessions at: /workspace/sessions"

    def test_empty_substitution(self):
        from src.services.prompt_manager import _interpolate_greybox_variables
        template = "Sessions at: {{AUTH_SESSION_DIR}}"
        result = _interpolate_greybox_variables(
            template,
            web_url="http://target",
        )
        assert result == "Sessions at: "

    def test_no_unresolved_placeholder(self):
        from src.services.prompt_manager import _interpolate_greybox_variables
        template = "URL: {{WEB_URL}}, auth: {{AUTH_SESSION_DIR}}, done"
        result = _interpolate_greybox_variables(
            template,
            web_url="http://target",
            auth_session_dir="/sessions",
        )
        assert "{{" not in result
        assert result == "URL: http://target, auth: /sessions, done"
