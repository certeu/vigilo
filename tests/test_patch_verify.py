"""Tests for patch verification (WS1/A1)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.services.patch_verify import classify_patch, verify_patches  # noqa: E402


def test_classify_harness_is_authoritative():
    # harness exit 0 = payload still works = patch FAILED
    assert classify_patch(0, True, True) == ("fail", "harness")
    # harness exit !=0 = payload blocked = VERIFIED
    assert classify_patch(1, False, False) == ("pass", "harness")


def test_classify_fallbacks():
    # build-ok does NOT prove the fix -> not_tested (never "pass"/verified)
    assert classify_patch(None, True, None) == ("not_tested", "build")
    # a build failure IS a real signal the patch is broken
    assert classify_patch(None, False, None) == ("fail", "build")
    assert classify_patch(None, None, True) == ("pass", "tests")
    assert classify_patch(None, None, None) == ("not_tested", "none")
    # tests take priority over build when both present
    assert classify_patch(None, True, False) == ("fail", "tests")


def test_build_ok_is_never_verified():
    """Regression: 'code compiles' must never be badged as a verified fix."""
    verified, method = classify_patch(None, True, None)
    assert verified != "pass"


def _seed(tmp_path: Path):
    d = tmp_path / "deliverables"
    d.mkdir(parents=True)
    (d / "remediation_manifest.json").write_text(json.dumps({"branches": [
        {"branch": "fix/INJ-VULN-01", "finding_ids": ["INJ-VULN-01"], "pushed": False, "diff_nonempty": True},
        {"branch": "fix/AUTH-VULN-01", "finding_ids": ["AUTH-VULN-01"], "pushed": False, "diff_nonempty": True},
    ]}))
    (d / "findings_index.json").write_text(json.dumps({"by_type": {"injection": [
        {"ID": "INJ-VULN-01", "harness_path": "harnesses/INJ-VULN-01.py"},
    ]}}))
    return d


def test_verify_patches_writes_results_and_summary(tmp_path: Path):
    d = _seed(tmp_path)

    def stub_checker(branch, finding_ids, harness_paths):
        # INJ branch has a harness and is fixed; AUTH has none -> not_tested
        if harness_paths:
            return {"verified": "pass", "method": "harness", "detail": f"{harness_paths[0]} exit=1"}
        return {"verified": "not_tested", "method": "none", "detail": "no harness"}

    summary = asyncio.run(verify_patches(str(tmp_path), checker=stub_checker))
    assert summary == {"branches": 2, "verified": 1, "failed": 0, "not_tested": 1}

    manifest = json.loads((d / "remediation_manifest.json").read_text())
    by = {b["branch"]: b for b in manifest["branches"]}
    assert by["fix/INJ-VULN-01"]["verified"] == "pass"
    assert by["fix/INJ-VULN-01"]["verify_method"] == "harness"
    assert by["fix/AUTH-VULN-01"]["verified"] == "not_tested"


def test_verify_patches_no_manifest_is_safe(tmp_path: Path):
    (tmp_path / "deliverables").mkdir(parents=True)
    summary = asyncio.run(verify_patches(str(tmp_path)))
    assert summary["branches"] == 0


def test_verify_patches_checker_exception_is_contained(tmp_path: Path):
    _seed(tmp_path)

    def boom(branch, finding_ids, harness_paths):
        raise RuntimeError("kaboom")

    summary = asyncio.run(verify_patches(str(tmp_path), checker=boom))
    assert summary["branches"] == 2 and summary["not_tested"] == 2
