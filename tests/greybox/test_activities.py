"""Tests for grey-box Temporal activity dataclasses (Task 8)."""
from __future__ import annotations

import pytest


def test_activity_input_dataclass():
    """GreyBoxActivityInput can be instantiated with required and default fields."""
    from src.greybox.temporal.activities import GreyBoxActivityInput

    inp = GreyBoxActivityInput(
        web_url="http://target.local",
        session_id="gb-test-001",
        credentials_path="/path/to/creds.yaml",
    )
    assert inp.web_url == "http://target.local"
    assert inp.session_id == "gb-test-001"
    assert inp.credentials_path == "/path/to/creds.yaml"
    assert inp.config_path is None
    assert inp.output_path is None
    assert inp.description == ""
    assert inp.rules_avoid == []
    assert inp.rules_focus == []


def test_init_workspace_input():
    """InitWorkspaceInput can be instantiated with required fields."""
    from src.greybox.temporal.activities import InitWorkspaceInput

    inp = InitWorkspaceInput(
        web_url="http://target.local",
        session_id="gb-test-001",
    )
    assert inp.web_url == "http://target.local"
    assert inp.session_id == "gb-test-001"
    assert inp.output_path is None


def test_prepare_session_input():
    """PrepareSessionInput captures identity and session details."""
    from src.greybox.temporal.activities import PrepareSessionInput

    inp = PrepareSessionInput(
        web_url="http://target.local",
        session_id="gb-test-001",
        credentials_path="/path/to/creds.yaml",
        identity_name="admin",
        playwright_session="agent1",
    )
    assert inp.identity_name == "admin"
    assert inp.playwright_session == "agent1"
    assert inp.credentials_path == "/path/to/creds.yaml"


def test_build_prompt_input():
    """BuildPromptInput carries agent name and template."""
    from src.greybox.temporal.activities import BuildPromptInput

    inp = BuildPromptInput(
        web_url="http://target.local",
        session_id="gb-test-001",
        agent_name="injection-specialist",
        prompt_template="greybox/specialist-injection",
    )
    assert inp.agent_name == "injection-specialist"
    assert inp.prompt_template == "greybox/specialist-injection"
    assert inp.playwright_session == "agent1"
    assert inp.assigned_targets == ""
    assert inp.graph_slice == ""
    assert inp.chain_candidates == ""


def test_check_signals_input():
    """CheckSignalsInput for E2 credential signal checking."""
    from src.greybox.temporal.activities import CheckSignalsInput

    inp = CheckSignalsInput(
        session_id="gb-test-001",
        signals_dir="/path/to/deliverables/.signals",
    )
    assert inp.session_id == "gb-test-001"
    assert inp.signals_dir == "/path/to/deliverables/.signals"


def test_agent_execution_input():
    """AgentExecutionInput carries prompt and model tier."""
    from src.greybox.temporal.activities import AgentExecutionInput

    inp = AgentExecutionInput(
        web_url="http://target.local",
        session_id="gb-test-001",
        agent_name="xss-specialist",
        prompt="Test XSS on /search",
    )
    assert inp.agent_name == "xss-specialist"
    assert inp.prompt == "Test XSS on /search"
    assert inp.model_tier == "medium"
    assert inp.cwd == "/app"


def test_managed_scan_input_and_result():
    """ManagedScanInput and ManagedScanResult dataclasses."""
    from src.greybox.temporal.activities import ManagedScanInput, ManagedScanResult

    scan_input = ManagedScanInput(
        web_url="http://target.local",
        session_id="gb-test-001",
        scan_type="nuclei",
    )
    assert scan_input.scan_type == "nuclei"
    assert scan_input.output_dir == ""

    scan_result = ManagedScanResult(
        scan_type="nuclei",
        success=True,
        output_file="/tmp/nuclei.json",
        duration_ms=5000,
        nodes_added=12,
    )
    assert scan_result.success is True
    assert scan_result.nodes_added == 12


def test_export_graph_input():
    """ExportGraphInput has format and token budget defaults."""
    from src.greybox.temporal.activities import ExportGraphInput

    inp = ExportGraphInput(
        session_id="gb-test-001",
        output_path="/output",
    )
    assert inp.format == "yaml"
    assert inp.max_tokens == 15000


def test_non_retryable_errors_list():
    """NON_RETRYABLE_ERRORS includes expected error types."""
    from src.greybox.temporal.activities import NON_RETRYABLE_ERRORS

    assert "AuthenticationError" in NON_RETRYABLE_ERRORS
    assert "ConfigurationError" in NON_RETRYABLE_ERRORS
    assert "BudgetExhaustedError" in NON_RETRYABLE_ERRORS
    assert len(NON_RETRYABLE_ERRORS) >= 7


def test_schema_version_mismatch_is_non_retryable():
    """SchemaVersionMismatchError must be non-retryable at both the activity
    and workflow layers — grey-box is a fresh-scan project, so a version
    mismatch is definitionally unrecoverable without operator intervention.
    """
    from src.greybox.temporal.activities import NON_RETRYABLE_ERRORS
    from src.greybox.temporal.workflows import _NON_RETRYABLE_TYPES

    assert "SchemaVersionMismatchError" in NON_RETRYABLE_ERRORS
    assert "SchemaVersionMismatchError" in _NON_RETRYABLE_TYPES


def test_init_graph_input():
    """InitGraphInput carries session and credentials path."""
    from src.greybox.temporal.activities import InitGraphInput

    inp = InitGraphInput(
        session_id="gb-test-001",
        credentials_path="/creds.yaml",
        web_url="http://target.local",
    )
    assert inp.session_id == "gb-test-001"
    assert inp.credentials_path == "/creds.yaml"
    assert inp.web_url == "http://target.local"


@pytest.mark.asyncio
async def test_resolve_agent_context_populates_chain_candidates(monkeypatch):
    """Chain-exploit context includes the curated candidate text for the prompt."""
    from src.greybox.temporal.activities import ResolveContextInput, resolve_agent_context

    class _FakeGraphClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def raw_query(self, query, params=None):
            if "SELECT count() AS c FROM" in query:
                return [{"c": 1}]
            if "FROM finding WHERE id IN $ids" in query:
                return [
                    {
                        "id": "finding:F1",
                        "vuln_type": "ssrf",
                        "severity": "high",
                        "title": "SSRF",
                        "grants": ["internal_http"],
                        "requires": ["authenticated"],
                    },
                    {
                        "id": "finding:F2",
                        "vuln_type": "authorization",
                        "severity": "high",
                        "title": "Auth Bypass",
                        "grants": ["authenticated"],
                        "requires": [],
                    },
                ]
            return []

    monkeypatch.setattr("src.greybox.graph.client.GraphClient", _FakeGraphClient)
    monkeypatch.setattr(
        "src.greybox.services.credentials.load_identities",
        lambda path: [],
    )
    monkeypatch.setattr(
        "src.greybox.services.credentials.build_login_block",
        lambda identity, web_url: "",
    )

    result = await resolve_agent_context(
        ResolveContextInput(
            session_id="gb-test-001",
            credentials_path="/tmp/creds.yaml",
            web_url="http://target.local",
            target='{"finding_ids":["finding:F1","finding:F2"],"candidates":[{"from_finding_id":"finding:F1","to_finding_id":"finding:F2","shared_capabilities":["authenticated"]}],"matched_patterns":[{"pattern_name":"Auth Bypass + SSRF","finding_ids":["finding:F2","finding:F1"]}],"chain_context":"Escalate to internal SSRF"}',
        )
    )

    assert "Candidates:" in result["chain_candidates"]
    assert "finding:F1 -> finding:F2" in result["chain_candidates"]
    assert "Matched patterns:" in result["chain_candidates"]
    assert "Auth Bypass + SSRF" in result["chain_candidates"]
    assert "Escalate to internal SSRF" in result["chain_candidates"]
