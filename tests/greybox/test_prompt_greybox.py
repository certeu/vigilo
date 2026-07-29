"""Tests for grey-box prompt extensions (Task 7)."""
from __future__ import annotations

from pathlib import Path


# Project root: four levels up from this test file
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def test_greybox_scope_partial_exists():
    """Verify the _greybox-scope.txt shared partial exists and contains key sections."""
    scope_path = _PROJECT_ROOT / "prompts" / "shared" / "_greybox-scope.txt"
    assert scope_path.is_file(), f"Missing: {scope_path}"
    content = scope_path.read_text()
    assert "GREY-BOX TESTING SCOPE" in content
    assert "EXPLOITED" in content
    assert "POTENTIAL" in content
    assert "LEAD" in content
    assert "FALSE_POSITIVE" in content
    assert "graph-tool" in content


def test_greybox_tools_partial_exists():
    """Verify the _greybox-tools.txt shared partial exists and documents all live commands."""
    tools_path = _PROJECT_ROOT / "prompts" / "shared" / "_greybox-tools.txt"
    assert tools_path.is_file(), f"Missing: {tools_path}"
    content = tools_path.read_text()
    # Live commands (Slice 2 removed `slice`, `bulk-add`, `archive`).
    commands = [
        "query", "add", "update", "test-attempt", "finding", "lead",
        "access", "claim", "release", "signal", "relate",
        "raw", "export",
    ]
    for cmd in commands:
        assert cmd in content, f"Command '{cmd}' not documented in _greybox-tools.txt"
    # Removed commands must not be advertised to agents.
    for removed in ("graph-tool slice", "graph-tool bulk-add", "graph-tool archive"):
        assert removed not in content, f"Removed command '{removed}' still documented"


def test_greybox_prompt_interpolation():
    """Test _interpolate_greybox_variables replaces all placeholders (NOT async per E28)."""
    from src.services.prompt_manager import _interpolate_greybox_variables

    template = (
        "Target: {{WEB_URL}}\n"
        "Targets: {{ASSIGNED_TARGETS}}\n"
        "Slice: {{GRAPH_SLICE}}\n"
        "Summary: {{GRAPH_SUMMARY}}\n"
        "IDs: {{IDENTITIES}}\n"
        "Signals: {{RECENT_SIGNALS}}\n"
        "Active: {{ACTIVE_AGENTS}}\n"
        "Budget: {{BUDGET_STATUS}}\n"
        "Chains: {{CHAIN_CANDIDATES}}\n"
        "Login: {{LOGIN_INSTRUCTIONS}}\n"
        "Desc: {{DESCRIPTION}}\n"
        "Avoid: {{RULES_AVOID}}\n"
        "Focus: {{RULES_FOCUS}}\n"
        "Session: {{PLAYWRIGHT_SESSION}}\n"
    )

    result = _interpolate_greybox_variables(
        template,
        web_url="http://target.local",
        assigned_targets="endpoint:GET_api_users",
        graph_slice="slice-data",
        graph_summary="summary-data",
        identities="admin, user",
        recent_signals="none",
        active_agents="injection-specialist",
        budget_status="$2.50 / $50.00",
        chain_candidates="F_001 + F_002",
        login_instructions="Login as admin",
        description="Test app",
        rules_avoid="Do not test /health",
        rules_focus="Focus on /api",
        playwright_session="agent3",
    )

    assert "{{" not in result, f"Unresolved placeholders in result: {result}"
    assert "http://target.local" in result
    assert "endpoint:GET_api_users" in result
    assert "slice-data" in result
    assert "summary-data" in result
    assert "admin, user" in result
    assert "injection-specialist" in result
    assert "$2.50 / $50.00" in result
    assert "F_001 + F_002" in result
    assert "Login as admin" in result
    assert "Test app" in result
    assert "Do not test /health" in result
    assert "Focus on /api" in result
    assert "agent3" in result


def test_greybox_prompt_interpolation_defaults():
    """Test that default empty strings are used for optional variables."""
    from src.services.prompt_manager import _interpolate_greybox_variables

    template = "URL={{WEB_URL}} TARGETS={{ASSIGNED_TARGETS}} SLICE={{GRAPH_SLICE}}"
    result = _interpolate_greybox_variables(template, web_url="http://example.com")
    assert "http://example.com" in result
    assert "{{ASSIGNED_TARGETS}}" not in result
    assert "{{GRAPH_SLICE}}" not in result
