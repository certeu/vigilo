"""Tests for the SCA pre-filter (WS2/B2)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.services.sca_filter import (  # noqa: E402
    build_usage_index, dedup_and_annotate, filter_sca, _normalize_pkg,
)


def test_dedup_collapses_same_package_advisory():
    findings = [
        {"package": "lodash", "cve_ids": ["CVE-2021-23337"], "version": "4.17.15"},
        {"package": "lodash", "cve_ids": ["CVE-2021-23337"], "version": "4.17.20"},  # dup advisory
        {"package": "lodash", "cve_ids": ["CVE-2020-8203"]},                          # diff advisory
        {"package": "minimatch", "advisory": "GHSA-xxxx"},
    ]
    out = dedup_and_annotate(findings, usage_index=set())
    assert len(out) == 3  # two lodash advisories + one minimatch
    lodash_337 = next(f for f in out if f["dedup_group"] == "lodash::CVE-2021-23337")
    assert lodash_337["absorbed_count"] == 2


def test_advisory_less_findings_are_not_over_merged():
    # Two distinct vulns on the same package, neither with an advisory id, must
    # NOT collapse into one (that would drop a real finding).
    findings = [
        {"package": "acme", "title": "path traversal"},
        {"package": "acme", "title": "prototype pollution"},
    ]
    out = dedup_and_annotate(findings, usage_index=set())
    assert len(out) == 2


def test_multi_cve_uses_full_set_not_first():
    # Different-but-overlapping CVE sets must not collide on the first CVE.
    findings = [
        {"package": "acme", "cve_ids": ["CVE-1", "CVE-2"]},
        {"package": "acme", "cve_ids": ["CVE-1", "CVE-3"]},
    ]
    out = dedup_and_annotate(findings, usage_index=set())
    assert len(out) == 2
    # identical CVE sets DO merge
    same = dedup_and_annotate(
        [{"package": "acme", "cve_ids": ["CVE-1", "CVE-2"]},
         {"package": "acme", "cve_ids": ["CVE-2", "CVE-1"]}], usage_index=set())
    assert len(same) == 1 and same[0]["absorbed_count"] == 2


def test_usage_flag_is_true_or_unknown_never_false():
    findings = [
        {"package": "requests", "cve_ids": ["CVE-1"]},
        {"package": "some-unused-lib", "cve_ids": ["CVE-2"]},
    ]
    out = dedup_and_annotate(findings, usage_index={"requests", "flask"})
    used = {f["package"]: f["dependency_used"] for f in out}
    assert used["requests"] == "true"
    assert used["some-unused-lib"] == "unknown"   # NOT "false" — absence isn't proof
    assert "false" not in used.values()


def test_normalize_pkg():
    assert _normalize_pkg("Flask==3.0.3") == "flask"
    assert _normalize_pkg("requests>=2.0") == "requests"
    assert _normalize_pkg("@scope/pkg@1.2.3").startswith("@scope/pkg")


def test_build_usage_index_finds_imports(tmp_path: Path):
    (tmp_path / "app.py").write_text("import requests\nfrom flask import Flask\n")
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\nflask==3.0.3\n")
    # noise dir that must be skipped
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "evil.js").write_text("require('should-be-ignored')")
    idx = build_usage_index(str(tmp_path))
    assert "requests" in idx and "flask" in idx
    assert "should-be-ignored" not in idx


def test_filter_sca_end_to_end(tmp_path: Path):
    (tmp_path / "app.py").write_text("import lodash_used\n")  # pretend used
    findings = [
        {"package": "lodash_used", "cve_ids": ["CVE-A"]},
        {"package": "lodash_used", "cve_ids": ["CVE-A"]},  # dup
        {"package": "ghost_dep", "cve_ids": ["CVE-B"]},
    ]
    out = filter_sca(findings, str(tmp_path))
    assert len(out) == 2
    by = {f["package"]: f for f in out}
    assert by["lodash_used"]["dependency_used"] == "true"
    assert by["lodash_used"]["absorbed_count"] == 2
    assert by["ghost_dep"]["dependency_used"] == "unknown"
