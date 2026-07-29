"""Tests for Workstream-D code changes.

1. The chain-exploitation gate must count only CONFIRMED findings
   (exploited/potential), not any non-empty bucket — chaining off unconfirmed
   or suppressed findings was a false-positive amplifier.
2. SharedContextManager.read surfaces a missing/empty context file as a warning
   (silent skips previously hid disabled graphql/websocket pipelines).
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.temporal.activities import ActivityInput, check_chain_exploit_readiness  # noqa: E402
from src.services.shared_context import SharedContextManager  # noqa: E402


def _write_index(repo: Path, by_type: dict) -> None:
    d = repo / "deliverables"
    d.mkdir(parents=True, exist_ok=True)
    total = sum(len(v) for v in by_type.values())
    (d / "findings_index.json").write_text(
        json.dumps({"total_vulnerabilities": total, "by_type": by_type}), encoding="utf-8"
    )


def _readiness(repo: Path) -> dict:
    inp = ActivityInput(repo_path=str(repo), workflow_id="w", session_id="s")
    return asyncio.run(check_chain_exploit_readiness(inp))


def test_chain_gate_needs_two_confirmed_types(tmp_path: Path) -> None:
    # Two types, both only UNCONFIRMED -> must not chain.
    _write_index(tmp_path, {
        "injection": [{"ID": "INJ-1", "status": "unconfirmed"}],
        "xss": [{"ID": "XSS-1", "status": "unconfirmed"}],
    })
    assert _readiness(tmp_path)["should_chain"] is False


def test_chain_gate_fires_on_two_demonstrated_types(tmp_path: Path) -> None:
    # Demonstrated = live-exploited OR code-only harness-confirmed.
    _write_index(tmp_path, {
        "injection": [{"ID": "INJ-1", "status": "exploited"}],
        "auth": [{"ID": "AUTH-1", "status": "potential", "harness_confirmed": True}],
    })
    result = _readiness(tmp_path)
    assert result["should_chain"] is True
    assert result["types_with_findings"] == 2


def test_chain_gate_ignores_undemonstrated_potential(tmp_path: Path) -> None:
    # Plain `potential` (not_testable/blocked/static) is NOT a demonstration —
    # it must not arm chaining. Only 1 demonstrated type here -> no chain.
    _write_index(tmp_path, {
        "injection": [{"ID": "INJ-1", "status": "exploited"}],
        "auth": [{"ID": "AUTH-1", "status": "potential"}],   # no harness_confirmed
    })
    assert _readiness(tmp_path)["should_chain"] is False


def test_chain_gate_ignores_suppressed(tmp_path: Path) -> None:
    # One demonstrated type + one suppressed type -> only 1 counts -> no chain.
    _write_index(tmp_path, {
        "injection": [{"ID": "INJ-1", "status": "exploited"}],
        "ssrf": [{"ID": "SSRF-1", "status": "suppressed"}],
    })
    assert _readiness(tmp_path)["should_chain"] is False


def test_shared_context_missing_warns(tmp_path: Path, caplog) -> None:
    with caplog.at_level(logging.WARNING):
        data = asyncio.run(SharedContextManager().read(str(tmp_path)))
    assert data == {}
    assert any("shared_context.json not found" in r.message for r in caplog.records)


def test_shared_context_reads_valid_file(tmp_path: Path) -> None:
    d = tmp_path / "deliverables"
    d.mkdir(parents=True, exist_ok=True)
    (d / "shared_context.json").write_text(json.dumps({"tech_stack": {"graphql": True}}), encoding="utf-8")
    data = asyncio.run(SharedContextManager().read(str(tmp_path)))
    assert data["tech_stack"]["graphql"] is True
