"""Tests for the recall backstop (findings_guard).

Guarantees the guard flags the two silent-drop paths the adversarial review
identified: an index finding with no critique annotation, and a serious+reachable
finding the critic tried to keep out of the report.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.services.findings_guard import audit, audit_critique  # noqa: E402


def _ann(**kw):
    base = {"severity_adjusted": "medium", "reachability": "external", "include_in_report": True}
    base.update(kw)
    return base


def test_clean_when_all_annotated_and_no_floor_violation():
    index = {"by_type": {"injection": [{"ID": "INJ-1"}, {"ID": "INJ-2"}]}}
    critique = {"annotations": {"INJ-1": _ann(), "INJ-2": _ann(include_in_report=False, severity_adjusted="low")}}
    result = audit(index, critique)
    assert result["ok"] is True
    assert result["missing_annotations"] == []
    assert result["floor_violations"] == []


def test_missing_annotation_is_flagged():
    index = {"by_type": {"xss": [{"ID": "XSS-1"}, {"ID": "XSS-2"}]}}
    critique = {"annotations": {"XSS-1": _ann()}}  # XSS-2 un-annotated
    result = audit(index, critique)
    assert result["ok"] is False
    assert result["missing_annotations"] == ["XSS-2"]


def test_recall_floor_violation_is_flagged():
    index = {"by_type": {"auth": [{"ID": "AUTH-1"}]}}
    critique = {"annotations": {
        "AUTH-1": _ann(severity_adjusted="critical", reachability="external", include_in_report=False),
    }}
    result = audit(index, critique)
    assert result["ok"] is False
    assert result["floor_violations"][0]["id"] == "AUTH-1"


def test_low_severity_excluded_is_allowed():
    index = {"by_type": {"crypto": [{"ID": "CRYPTO-1"}]}}
    critique = {"annotations": {
        "CRYPTO-1": _ann(severity_adjusted="low", reachability="external", include_in_report=False),
    }}
    assert audit(index, critique)["ok"] is True


def test_internal_only_critical_excluded_is_allowed():
    # critical but not reachable (internal_only / mitigated) may be excluded.
    index = {"by_type": {"ssrf": [{"ID": "SSRF-1"}]}}
    critique = {"annotations": {
        "SSRF-1": _ann(severity_adjusted="critical", reachability="internal_only", include_in_report=False),
    }}
    assert audit(index, critique)["ok"] is True


def test_audit_critique_writes_sidecar(tmp_path: Path):
    d = tmp_path / "deliverables"
    d.mkdir(parents=True)
    (d / "findings_index.json").write_text(
        json.dumps({"by_type": {"injection": [{"ID": "INJ-1"}]}}), encoding="utf-8")
    (d / "findings_critique.json").write_text(
        json.dumps({"annotations": {"INJ-1": _ann()}}), encoding="utf-8")
    result = asyncio.run(audit_critique(str(tmp_path)))
    assert result["ok"] is True
    written = json.loads((d / "findings_critique_audit.json").read_text())
    assert written["counts"]["index_findings"] == 1


def test_audit_critique_missing_critique_is_loud_not_crash(tmp_path: Path):
    d = tmp_path / "deliverables"
    d.mkdir(parents=True)
    (d / "findings_index.json").write_text(
        json.dumps({"by_type": {"injection": [{"ID": "INJ-1"}]}}), encoding="utf-8")
    # no findings_critique.json
    result = asyncio.run(audit_critique(str(tmp_path)))
    assert result["ok"] is False
    assert result["missing_annotations"] == ["INJ-1"]
