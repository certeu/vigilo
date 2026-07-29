"""Regression test: metrics extraction against the pipeline's CURRENT output shape
(findings_critique.json + findings_index.by_type; no report_stats.json). Modeled on a
real run's deliverables (samples/mock_repo scan)."""
from __future__ import annotations

import json
import os

from src.webapi.metrics import extract_run_metrics
from src.webapi.reports import deliverables_dir


def _write(base, name, data):
    with open(os.path.join(base, name), "w") as fh:
        json.dump(data, fh)


class TestCritiqueExtraction:
    def test_extracts_from_critique_when_no_report_stats(self, tmp_path):
        base = deliverables_dir(str(tmp_path), "s1")
        os.makedirs(base, exist_ok=True)
        _write(base, "findings_index.json", {
            "total_vulnerabilities": 3,
            "by_type": {
                "injection": [{"ID": "INJ-1"}],
                "auth": [{"ID": "AUTH-1"}],
                "supply_chain": [{"ID": "SCA-1"}],
            },
        })
        _write(base, "findings_critique.json", {
            "version": "1.0",
            "summary": {"total_findings": 4},
            "annotations": {
                "INJ-1": {"severity_adjusted": "critical", "confidence": "confirmed",
                         "include_in_report": True},
                "AUTH-1": {"severity_adjusted": "medium", "confidence": "potential",
                          "include_in_report": True},
                "SCA-1": {"severity_adjusted": "low", "confidence": "confirmed",
                         "include_in_report": True},
                "NOISE-1": {"severity_adjusted": "critical", "confidence": "confirmed",
                           "include_in_report": False},  # excluded from report
            },
        })
        m = extract_run_metrics(str(tmp_path), "s1")
        assert m["source"] == "critique"
        assert m["total_findings"] == 3  # NOISE-1 excluded (include_in_report=False)
        assert m["severity_counts"]["critical"] == 1
        assert m["severity_counts"]["medium"] == 1
        assert m["severity_counts"]["low"] == 1
        assert m["status_counts"]["exploited"] == 2   # confirmed x2
        assert m["status_counts"]["unconfirmed"] == 1
        assert m["category_counts"] == {"injection": 1, "auth": 1, "supply_chain": 1}
        assert m["supply_chain"] == 1

    def test_group_id_dedup_matches_report_counts(self, tmp_path):
        # Findings sharing a group_id are ONE unique finding (the report groups
        # duplicate observations). Regression for the dashboard over-counting vs
        # the report (e.g. 4 High annotations in 2 groups -> 2 High unique).
        base = deliverables_dir(str(tmp_path), "sg")
        os.makedirs(base, exist_ok=True)
        _write(base, "findings_index.json", {"by_type": {
            "injection": [{"ID": "INJ-1"}, {"ID": "INJ-2"}],
            "authz": [{"ID": "AUTHZ-1"}, {"ID": "AUTHZ-2"}],
        }})
        _write(base, "findings_critique.json", {"annotations": {
            # group A: two HIGH annotations -> counts once
            "INJ-1": {"severity_adjusted": "high", "confidence": "potential",
                      "include_in_report": True, "group_id": "gA"},
            "AUTHZ-1": {"severity_adjusted": "high", "confidence": "confirmed",
                        "include_in_report": True, "group_id": "gA"},
            # group B: HIGH + MEDIUM -> counts once as HIGH (max severity)
            "INJ-2": {"severity_adjusted": "medium", "confidence": "potential",
                      "include_in_report": True, "group_id": "gB"},
            "AUTHZ-2": {"severity_adjusted": "high", "confidence": "potential",
                        "include_in_report": True, "group_id": "gB"},
        }})
        m = extract_run_metrics(str(tmp_path), "sg")
        assert m["total_findings"] == 2               # 4 annotations -> 2 groups
        assert m["severity_counts"]["high"] == 2
        assert m["severity_counts"]["medium"] == 0
        assert m["status_counts"]["exploited"] == 1   # group A had a confirmed member
        assert m["status_counts"]["unconfirmed"] == 1

    def test_critique_preferred_over_legacy_report_stats(self, tmp_path):
        """findings_critique.json is the source of truth; a legacy report_stats.json
        present alongside it (old runs / demo engine) must be ignored."""
        base = deliverables_dir(str(tmp_path), "s2")
        os.makedirs(base, exist_ok=True)
        _write(base, "report_stats.json", {
            "totals": {"unique_findings": 5},
            "severity_counts": {"critical": 5, "high": 0, "medium": 0, "low": 0},
            "status_counts": {"exploited": 5, "unconfirmed": 0},
            "category_counts": {"injection": {"total": 5}},
        })
        _write(base, "findings_critique.json", {
            "annotations": {
                "V1": {"severity_adjusted": "high", "confidence": "confirmed",
                       "include_in_report": True},
            }
        })
        m = extract_run_metrics(str(tmp_path), "s2")
        assert m["source"] == "critique"          # critique wins over legacy report_stats
        assert m["total_findings"] == 1
        assert m["severity_counts"]["high"] == 1
