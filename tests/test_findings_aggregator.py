"""Tests for the structured (de-regexed) findings aggregator.

These lock in the Workstream-A contract: status/severity/code_fixable come from
structured JSON the agents write, never from scraping evidence prose. The
central regression guard is that a finding the exploit agent judged
``false_positive`` is NOT reported as exploited even though its ID appears in an
evidence markdown file (the old ``_scan_evidence_vuln_ids`` behaviour).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Make `src` importable when pytest is run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.services.findings_aggregator import FindingsAggregator  # noqa: E402


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def _aggregate(repo: Path) -> dict:
    return asyncio.run(FindingsAggregator().aggregate(str(repo)))


def _by_id(index: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for vulns in index["by_type"].values():
        for v in vulns:
            out[v.get("ID") or v.get("id")] = v
    return out


def test_verdict_drives_status(tmp_path: Path) -> None:
    d = tmp_path / "deliverables"
    _write(d / "injection_exploitation_queue.json", {"vulnerabilities": [
        {"ID": "INJ-VULN-01", "severity": "high"},
        {"ID": "INJ-VULN-02", "severity": "high"},
        {"ID": "INJ-VULN-03", "severity": "high"},
    ]})
    _write(d / "injection_exploitation_verdicts.json", {"verdicts": [
        {"id": "INJ-VULN-01", "verdict": "exploited", "evidence_ref": "e.md#1"},
        {"id": "INJ-VULN-02", "verdict": "blocked"},
        # INJ-VULN-03 has no verdict
    ]})

    findings = _by_id(_aggregate(tmp_path))
    assert findings["INJ-VULN-01"]["status"] == "exploited"
    assert findings["INJ-VULN-01"]["evidence_ref"] == "e.md#1"
    assert findings["INJ-VULN-02"]["status"] == "potential"   # blocked-by-control
    assert findings["INJ-VULN-03"]["status"] == "unconfirmed"  # no verdict


def test_code_only_harness_verdicts(tmp_path: Path) -> None:
    """Code-only confirmation verdicts keep findings at `potential` (not
    `unreachable`) and carry harness evidence; `refuted` is suppressed."""
    d = tmp_path / "deliverables"
    _write(d / "injection_exploitation_queue.json", {"vulnerabilities": [
        {"ID": "INJ-VULN-01", "severity": "high"},
        {"ID": "INJ-VULN-02", "severity": "high"},
        {"ID": "INJ-VULN-03", "severity": "high"},
    ]})
    _write(d / "injection_exploitation_verdicts.json", {"verdicts": [
        {"id": "INJ-VULN-01", "verdict": "confirmed", "harness_path": "harnesses/INJ-VULN-01.py"},
        {"id": "INJ-VULN-02", "verdict": "not_testable"},
        {"id": "INJ-VULN-03", "verdict": "refuted", "notes": "input is parameterised; payload had no effect"},
    ]})
    f = _by_id(_aggregate(tmp_path))
    # confirmed -> potential, with harness evidence carried through
    assert f["INJ-VULN-01"]["status"] == "potential"
    assert f["INJ-VULN-01"]["harness_confirmed"] is True
    assert f["INJ-VULN-01"]["harness_path"] == "harnesses/INJ-VULN-01.py"
    # not_testable (static trace holds) -> potential, still visible for chaining
    assert f["INJ-VULN-02"]["status"] == "potential"
    # refuted (harness ran, no effect) -> suppressed with reason
    assert f["INJ-VULN-03"]["status"] == "suppressed"
    assert "parameterised" in f["INJ-VULN-03"]["suppression_reason"]
    assert f["INJ-VULN-03"]["harness_confirmed"] is False


def test_false_positive_is_suppressed_not_exploited(tmp_path: Path) -> None:
    """Regression guard for the removed regex ID-mention scan.

    The finding's ID even appears in an evidence markdown file, which under the
    old aggregator would have flipped it to ``exploited``. With structured
    verdicts it must be ``suppressed`` with a reason.
    """
    d = tmp_path / "deliverables"
    _write(d / "ssrf_exploitation_queue.json", {"vulnerabilities": [
        {"ID": "SSRF-VULN-01", "severity": "critical"},
    ]})
    _write(d / "ssrf_exploitation_verdicts.json", {"verdicts": [
        {"id": "SSRF-VULN-01", "verdict": "false_positive",
         "notes": "URL is validated against an allowlist before the request."},
    ]})
    # An evidence file that mentions the ID (old regex would match this).
    (d).mkdir(parents=True, exist_ok=True)
    (d / "ssrf_exploitation_evidence.md").write_text(
        "## Potential Vulnerabilities (Validation Blocked)\n### SSRF-VULN-01\n...",
        encoding="utf-8",
    )

    finding = _by_id(_aggregate(tmp_path))["SSRF-VULN-01"]
    assert finding["status"] == "suppressed"
    assert "allowlist" in finding["suppression_reason"]


def test_severity_is_carried_through_not_inferred(tmp_path: Path) -> None:
    """No severity => conservative 'medium' default, never auto-'critical'."""
    d = tmp_path / "deliverables"
    _write(d / "xss_exploitation_queue.json", {"vulnerabilities": [
        {"ID": "XSS-VULN-01", "confidence": "high", "externally_exploitable": True},  # no severity
        {"ID": "XSS-VULN-02", "severity": "low"},  # explicit
    ]})

    findings = _by_id(_aggregate(tmp_path))
    # Old heuristic would have minted 'critical' from high-confidence+external.
    assert findings["XSS-VULN-01"]["severity"] == "medium"
    assert findings["XSS-VULN-02"]["severity"] == "low"


def test_verdict_severity_used_when_specialist_omits_it(tmp_path: Path) -> None:
    d = tmp_path / "deliverables"
    _write(d / "auth_exploitation_queue.json", {"vulnerabilities": [{"ID": "AUTH-VULN-01"}]})
    _write(d / "auth_exploitation_verdicts.json", {"verdicts": [
        {"id": "AUTH-VULN-01", "verdict": "exploited", "severity": "critical"},
    ]})
    finding = _by_id(_aggregate(tmp_path))["AUTH-VULN-01"]
    assert finding["severity"] == "critical"
    assert finding["status"] == "exploited"


def test_chain_findings_loaded_from_structured_file(tmp_path: Path) -> None:
    d = tmp_path / "deliverables"
    _write(d / "chain_findings.json", {"chains": [
        {"ID": "CHAIN-001", "severity": "high", "status": "exploited",
         "components": ["INJ-VULN-01", "AUTH-VULN-01"], "notes": "SQLi -> auth bypass"},
    ]})
    index = _aggregate(tmp_path)
    chain = index["by_type"]["chain"][0]
    assert chain["ID"] == "CHAIN-001"
    assert chain["status"] == "exploited"
    assert chain["code_fixable"] is False
    assert chain["chain_components"] == ["INJ-VULN-01", "AUTH-VULN-01"]


def test_code_fixable_explicit_only(tmp_path: Path) -> None:
    d = tmp_path / "deliverables"
    _write(d / "crypto_exploitation_queue.json", {"vulnerabilities": [
        {"ID": "CRYPTO-01", "severity": "medium"},                      # defaults True
        {"ID": "CRYPTO-02", "severity": "medium", "code_fixable": False},
    ]})
    findings = _by_id(_aggregate(tmp_path))
    assert findings["CRYPTO-01"]["code_fixable"] is True
    assert findings["CRYPTO-02"]["code_fixable"] is False


def test_empty_workspace_is_valid(tmp_path: Path) -> None:
    index = _aggregate(tmp_path)
    assert index["total_vulnerabilities"] == 0
    assert isinstance(index["by_type"], dict)


def test_malformed_queue_is_skipped(tmp_path: Path) -> None:
    d = tmp_path / "deliverables"
    d.mkdir(parents=True, exist_ok=True)
    (d / "injection_exploitation_queue.json").write_text("{not json", encoding="utf-8")
    index = _aggregate(tmp_path)
    assert index["by_type"]["injection"] == []


if __name__ == "__main__":  # allow running without pytest
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    import tempfile
    for fn in fns:
        with tempfile.TemporaryDirectory() as td:
            try:
                fn(Path(td))
                print(f"PASS {fn.__name__}")
            except Exception:
                failed += 1
                print(f"FAIL {fn.__name__}")
                traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
