"""Tests for grey-box audit trail writer."""

import asyncio
import json
from pathlib import Path

import pytest

from src.greybox.services.audit_integration import (
    append_workflow_log,
    finalize_session,
    init_session_json,
    log_agent_complete,
    log_managed_scan,
    log_phase_complete,
    log_phase_start,
    log_workflow_complete,
    log_workflow_header,
    save_agent_prompt,
    save_agent_result,
    update_session_agent,
    update_session_managed_scan,
    update_session_phase,
    update_session_spawned,
)


def _run(coro):
    """Run an async coroutine in a new event loop."""
    return asyncio.run(coro)


def test_workflow_header(tmp_path: Path) -> None:
    """Verify workflow.log header is written."""
    workspace = str(tmp_path)
    _run(log_workflow_header(workspace, "sess-001", "https://target.local", ["admin", "user"]))

    log_path = tmp_path / "workflow.log"
    assert log_path.exists()
    content = log_path.read_text()
    assert "sess-001" in content
    assert "https://target.local" in content
    assert "admin, user" in content


def test_phase_logging(tmp_path: Path) -> None:
    """Verify phase start/complete log lines."""
    workspace = str(tmp_path)
    _run(log_phase_start(workspace, "preflight"))
    _run(log_phase_complete(workspace, "preflight"))

    content = (tmp_path / "workflow.log").read_text()
    assert "[PHASE] Starting: preflight" in content
    assert "[PHASE] Completed: preflight" in content


def test_agent_logging(tmp_path: Path) -> None:
    """Verify agent completion is logged."""
    workspace = str(tmp_path)
    _run(log_agent_complete(workspace, "xss-agent", 12.5, 0.0345, 2))

    content = (tmp_path / "workflow.log").read_text()
    assert "xss-agent" in content
    assert "12.5s" in content
    assert "$0.0345" in content
    assert "findings=2" in content


def test_managed_scan_logging(tmp_path: Path) -> None:
    """Verify managed scan is logged."""
    workspace = str(tmp_path)
    _run(log_managed_scan(workspace, "nuclei", 42, 15, 3000))

    content = (tmp_path / "workflow.log").read_text()
    assert "[SCAN] nuclei" in content
    assert "42 items" in content
    assert "15 nodes" in content


def test_workflow_complete_logging(tmp_path: Path) -> None:
    """Verify final workflow summary."""
    workspace = str(tmp_path)
    _run(log_workflow_complete(workspace, "completed", 1.25, 60000, 5, 10))

    content = (tmp_path / "workflow.log").read_text()
    assert "COMPLETED" in content
    assert "60s" in content
    assert "$1.2500" in content
    assert "Findings: 5" in content


def test_session_json_init(tmp_path: Path) -> None:
    """Verify initial session.json structure."""
    workspace = str(tmp_path)
    _run(init_session_json(workspace, "sess-002", "https://app.local", ["admin"]))

    data = json.loads((tmp_path / "session.json").read_text())
    assert data["session_id"] == "sess-002"
    assert data["pipeline_type"] == "greybox"
    assert data["status"] == "running"
    assert data["total_cost_usd"] == 0.0
    assert data["agents"] == {}
    assert data["phases_completed"] == []


def test_session_json_phase_update(tmp_path: Path) -> None:
    """Verify phase completion updates session.json."""
    workspace = str(tmp_path)
    _run(init_session_json(workspace, "s1", "http://t", []))
    _run(update_session_phase(workspace, "preflight"))
    _run(update_session_phase(workspace, "managed_scans"))

    data = json.loads((tmp_path / "session.json").read_text())
    assert data["phases_completed"] == ["preflight", "managed_scans"]


def test_session_json_agent_update(tmp_path: Path) -> None:
    """Verify agent results update session.json."""
    workspace = str(tmp_path)
    _run(init_session_json(workspace, "s1", "http://t", []))
    _run(update_session_agent(
        workspace, "xss-agent",
        duration_ms=5000, cost_usd=0.05,
        input_tokens=1000, output_tokens=500,
        num_turns=3, model="sonnet", findings_count=2,
    ))

    data = json.loads((tmp_path / "session.json").read_text())
    assert "xss-agent" in data["agents"]
    agent = data["agents"]["xss-agent"]
    assert agent["cost_usd"] == 0.05
    assert agent["findings_count"] == 2
    assert data["total_cost_usd"] == 0.05
    assert data["agents_completed"] == 1
    assert data["findings_count"] == 2


def test_session_json_managed_scan(tmp_path: Path) -> None:
    """Verify managed scan results update session.json."""
    workspace = str(tmp_path)
    _run(init_session_json(workspace, "s1", "http://t", []))
    _run(update_session_managed_scan(workspace, "nuclei", 10, 5, 2000))

    data = json.loads((tmp_path / "session.json").read_text())
    assert "nuclei" in data["managed_scans"]
    assert data["managed_scans"]["nuclei"]["items_found"] == 10


def test_session_json_spawned_counter(tmp_path: Path) -> None:
    """Verify agents_spawned increments."""
    workspace = str(tmp_path)
    _run(init_session_json(workspace, "s1", "http://t", []))
    _run(update_session_spawned(workspace))
    _run(update_session_spawned(workspace))

    data = json.loads((tmp_path / "session.json").read_text())
    assert data["agents_spawned"] == 2


def test_session_json_finalize(tmp_path: Path) -> None:
    """Verify session finalization."""
    workspace = str(tmp_path)
    _run(init_session_json(workspace, "s1", "http://t", []))
    _run(finalize_session(workspace, "completed", 120000))

    data = json.loads((tmp_path / "session.json").read_text())
    assert data["status"] == "completed"
    assert data["total_duration_ms"] == 120000
    assert "completed_at" in data


def test_save_agent_prompt(tmp_path: Path) -> None:
    """Verify prompt is saved to deliverables/prompts/."""
    workspace = str(tmp_path)
    _run(save_agent_prompt(workspace, "xss-agent", "Test the XSS vectors"))

    path = tmp_path / "deliverables" / "prompts" / "xss-agent.md"
    assert path.exists()
    content = path.read_text()
    assert "Test the XSS vectors" in content
    assert "# Prompt: xss-agent" in content


def test_save_agent_result(tmp_path: Path) -> None:
    """Verify agent result is saved to deliverables/agents/."""
    workspace = str(tmp_path)
    result = {"agent_name": "sqli-agent", "cost_usd": 0.1, "findings": []}
    _run(save_agent_result(workspace, "sqli-agent", result))

    path = tmp_path / "deliverables" / "agents" / "sqli-agent.json"
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["agent_name"] == "sqli-agent"
