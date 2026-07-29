"""Offline end-to-end test of the structured hand-off (no Docker/LLM).

Simulates the deliverables an agent run against the mock vulnerable app would
produce — specialist queues, exploit verdicts, and a critic adjudication — then
runs the REAL aggregator and recall guard over them and asserts the
false-positive-reduction behaviour holds end-to-end:

  * confirmed true positives keep their status/severity,
  * an exploit-agent false_positive is suppressed (kept + reasoned, not exploited),
  * an unscored finding is NOT inflated to critical,
  * the guard passes when the critique is complete and floor-compliant,
  * the guard flags a silently-dropped finding and a buried serious+reachable one.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.services.findings_aggregator import FindingsAggregator  # noqa: E402
from src.services.findings_guard import audit_critique  # noqa: E402
from src.services.patch_verify import verify_patches  # noqa: E402


def test_code_only_run_produces_potential_and_verifies_patches(tmp_path: Path):
    """End-to-end (offline) for the WS1/WS2 additions: a code-only run confirms
    findings via harness -> `potential` (not `unreachable`), SCA dedups, and
    verify_patches classifies the fix branches."""
    d = tmp_path / "deliverables"
    d.mkdir(parents=True)
    # Injection specialist + code-only harness verdicts
    (d / "injection_exploitation_queue.json").write_text(json.dumps({"vulnerabilities": [
        {"ID": "INJ-VULN-01", "severity": "high"},
        {"ID": "INJ-VULN-02", "severity": "high"},
        {"ID": "INJ-VULN-03", "severity": "high"},
    ]}))
    (d / "injection_exploitation_verdicts.json").write_text(json.dumps({"verdicts": [
        {"id": "INJ-VULN-01", "verdict": "confirmed", "harness_path": "harnesses/INJ-VULN-01.py"},
        {"id": "INJ-VULN-02", "verdict": "not_testable"},
        {"id": "INJ-VULN-03", "verdict": "refuted", "notes": "parameterised; no effect"},
    ]}))
    # SCA with duplicates
    (d / "sca_findings.json").write_text(json.dumps({"vulnerabilities": [
        {"package": "lodash", "cve_ids": ["CVE-1"]},
        {"package": "lodash", "cve_ids": ["CVE-1"]},   # dup
        {"package": "minimatch", "cve_ids": ["CVE-2"]},
    ]}))
    index = asyncio.run(FindingsAggregator().aggregate_and_write(str(tmp_path)))
    by = {v["ID"]: v for vs in index["by_type"].values() for v in vs if v.get("ID")}
    # code-only confirmations are `potential` (not unreachable) -> chain gate can fire
    assert by["INJ-VULN-01"]["status"] == "potential" and by["INJ-VULN-01"]["harness_confirmed"] is True
    assert by["INJ-VULN-02"]["status"] == "potential"
    assert by["INJ-VULN-03"]["status"] == "suppressed"
    # SCA deduped 3 -> 2
    assert len(index["by_type"]["supply_chain"]) == 2

    # verify_patches over a manifest (stub checker: INJ-01 fixed via harness)
    (d / "remediation_manifest.json").write_text(json.dumps({"branches": [
        {"branch": "fix/INJ-VULN-01", "finding_ids": ["INJ-VULN-01"], "pushed": False, "diff_nonempty": True},
    ]}))
    summary = asyncio.run(verify_patches(str(tmp_path),
        checker=lambda b, ids, hp: {"verified": "pass", "method": "harness"}))
    assert summary["verified"] == 1


def _seed_deliverables(repo: Path) -> Path:
    d = repo / "deliverables"
    d.mkdir(parents=True, exist_ok=True)

    # Injection specialist: SQLi + command injection + a duplicate of the SQLi.
    (d / "injection_exploitation_queue.json").write_text(json.dumps({"vulnerabilities": [
        {"ID": "INJ-VULN-01", "vulnerability_type": "SQLi", "severity": "high"},
        {"ID": "INJ-VULN-02", "vulnerability_type": "CommandInjection", "severity": "high"},
        {"ID": "INJ-VULN-03", "vulnerability_type": "SQLi"},  # dup of 01, no severity
    ]}))
    (d / "injection_exploitation_verdicts.json").write_text(json.dumps({"verdicts": [
        {"id": "INJ-VULN-01", "verdict": "exploited", "severity": "critical"},
        {"id": "INJ-VULN-02", "verdict": "exploited", "severity": "high"},
        {"id": "INJ-VULN-03", "verdict": "false_positive", "notes": "same sink as INJ-VULN-01; not a distinct bug"},
    ]}))

    # SSRF specialist: one confirmed.
    (d / "ssrf_exploitation_queue.json").write_text(json.dumps({"vulnerabilities": [
        {"ID": "SSRF-VULN-01", "vulnerability_type": "SSRF", "severity": "high"},
    ]}))
    (d / "ssrf_exploitation_verdicts.json").write_text(json.dumps({"verdicts": [
        {"id": "SSRF-VULN-01", "verdict": "exploited", "severity": "high"},
    ]}))

    # Crypto specialist: analysis-only, no verdict file (crypto has no exploit agent).
    (d / "crypto_exploitation_queue.json").write_text(json.dumps({"vulnerabilities": [
        {"ID": "CRYPTO-01", "vulnerability_type": "weak_crypto"},  # no severity
    ]}))
    return d


def _by_id(index: dict) -> dict:
    out = {}
    for vulns in index["by_type"].values():
        for v in vulns:
            out[v.get("ID") or v.get("id")] = v
    return out


def test_aggregator_handoff_reduces_false_positives(tmp_path: Path):
    repo = tmp_path
    _seed_deliverables(repo)

    index = asyncio.run(FindingsAggregator().aggregate_and_write(str(repo)))
    findings = _by_id(index)

    # Confirmed TPs keep status; severity follows precedence (specialist > verdict
    # > default) — INJ-VULN-01's explicit specialist "high" wins over the verdict's
    # "critical". The critic re-grades authoritatively downstream anyway.
    assert findings["INJ-VULN-01"]["status"] == "exploited"
    assert findings["INJ-VULN-01"]["severity"] == "high"
    assert findings["SSRF-VULN-01"]["status"] == "exploited"

    # The duplicate SQLi the exploiter dismissed is suppressed (kept, reasoned).
    assert findings["INJ-VULN-03"]["status"] == "suppressed"
    assert "distinct" in findings["INJ-VULN-03"]["suppression_reason"]

    # Unscored crypto finding is NOT inflated to critical (de-inflation).
    assert findings["CRYPTO-01"]["status"] == "unconfirmed"
    assert findings["CRYPTO-01"]["severity"] == "medium"

    # Everything is still recorded in the index — nothing silently dropped.
    assert set(findings) == {"INJ-VULN-01", "INJ-VULN-02", "INJ-VULN-03", "SSRF-VULN-01", "CRYPTO-01"}


def _clean_critique() -> dict:
    """A complete, floor-compliant critique for the seeded findings."""
    def ann(sev, reach, include, **extra):
        a = {"severity_adjusted": sev, "reachability": reach, "include_in_report": include,
             "confidence": "confirmed", "group_id": None, "possible_false_positive": False}
        a.update(extra)
        return a
    return {"annotations": {
        "INJ-VULN-01": ann("critical", "external", True, group_id="sqli-user"),
        # INJ-VULN-03 grouped with 01 (dedup) and excluded as a dup — low, so floor OK.
        "INJ-VULN-03": ann("low", "external", False, group_id="sqli-user", confidence="theoretical"),
        "INJ-VULN-02": ann("high", "external", True, group_id="cmdi-ping"),
        "SSRF-VULN-01": ann("high", "external", True, group_id="ssrf-fetch"),
        "CRYPTO-01": ann("medium", "authenticated", True, group_id="md5-pw"),
    }}


def test_guard_passes_on_complete_floor_compliant_critique(tmp_path: Path):
    d = _seed_deliverables(tmp_path)
    asyncio.run(FindingsAggregator().aggregate_and_write(str(tmp_path)))
    (d / "findings_critique.json").write_text(json.dumps(_clean_critique()))

    result = asyncio.run(audit_critique(str(tmp_path)))
    assert result["ok"] is True, result
    assert result["counts"]["annotations"] == 5


def test_guard_flags_dropped_and_buried_findings(tmp_path: Path):
    d = _seed_deliverables(tmp_path)
    asyncio.run(FindingsAggregator().aggregate_and_write(str(tmp_path)))

    critique = _clean_critique()
    del critique["annotations"]["SSRF-VULN-01"]                       # silently dropped
    critique["annotations"]["INJ-VULN-02"]["include_in_report"] = False  # buried critical/high+external
    (d / "findings_critique.json").write_text(json.dumps(critique))

    result = asyncio.run(audit_critique(str(tmp_path)))
    assert result["ok"] is False
    assert "SSRF-VULN-01" in result["missing_annotations"]
    assert any(v["id"] == "INJ-VULN-02" for v in result["floor_violations"])
