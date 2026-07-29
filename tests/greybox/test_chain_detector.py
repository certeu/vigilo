"""Tests for rule-based chain pre-filter."""
from __future__ import annotations


def test_find_chain_candidates_basic():
    from src.greybox.planner.chain_detector import find_chain_candidates
    findings = [
        {"id": "finding:F001", "vuln_type": "injection", "grants": ["db_read", "credential_access"], "requires": ["authenticated"]},
        {"id": "finding:F002", "vuln_type": "authorization", "grants": ["admin_access"], "requires": ["db_read"]},
    ]
    candidates = find_chain_candidates(findings)
    assert len(candidates) == 1
    assert candidates[0]["finding_a"] == "finding:F001"
    assert candidates[0]["finding_b"] == "finding:F002"
    assert "db_read" in candidates[0]["capability_overlap"]


def test_find_chain_candidates_no_overlap():
    from src.greybox.planner.chain_detector import find_chain_candidates
    findings = [
        {"id": "finding:F001", "grants": ["db_read"], "requires": ["authenticated"]},
        {"id": "finding:F002", "grants": ["reflection"], "requires": ["authenticated"]},
    ]
    candidates = find_chain_candidates(findings)
    assert len(candidates) == 0


def test_find_chain_candidates_bidirectional():
    from src.greybox.planner.chain_detector import find_chain_candidates
    findings = [
        {"id": "finding:F001", "grants": ["credential_access"], "requires": ["admin_access"]},
        {"id": "finding:F002", "grants": ["admin_access"], "requires": ["credential_access"]},
    ]
    candidates = find_chain_candidates(findings)
    assert len(candidates) == 2


def test_find_chain_candidates_empty():
    from src.greybox.planner.chain_detector import find_chain_candidates
    assert find_chain_candidates([]) == []


def test_known_chain_patterns_count():
    from src.greybox.planner.chain_detector import KNOWN_CHAIN_PATTERNS
    assert len(KNOWN_CHAIN_PATTERNS) == 7


def test_match_ssrf_cloud_metadata_chain():
    from src.greybox.planner.chain_detector import ChainDetector
    detector = ChainDetector()
    candidates = [
        {
            "finding_a": "finding:F001",
            "finding_b": "finding:F002",
            "a_vuln_type": "ssrf",
            "b_vuln_type": "ssrf",
            "a_grants": ["internal_network"],
            "b_requires": ["internal_network"],
            "capability_overlap": ["internal_network"],
        }
    ]
    matched = detector.match_known_patterns(candidates)
    assert len(matched) >= 1
    assert any("SSRF" in m.get("pattern_name", "") or "cloud" in m.get("pattern_name", "").lower()
               for m in matched)


def test_match_xss_csrf_chain():
    from src.greybox.planner.chain_detector import ChainDetector
    detector = ChainDetector()
    candidates = [
        {
            "finding_a": "finding:F010",
            "finding_b": "finding:F011",
            "a_vuln_type": "reflection",
            "b_vuln_type": "csrf",
            "a_grants": ["session_hijack", "csrf_bypass"],
            "b_requires": ["csrf_bypass"],
            "capability_overlap": ["csrf_bypass"],
        }
    ]
    matched = detector.match_known_patterns(candidates)
    assert len(matched) >= 1


def test_no_false_chain_matches():
    from src.greybox.planner.chain_detector import ChainDetector
    detector = ChainDetector()
    candidates = [
        {
            "finding_a": "finding:FA",
            "finding_b": "finding:FB",
            "a_vuln_type": "headers",
            "b_vuln_type": "headers",
            "a_grants": ["authenticated"],
            "b_requires": ["authenticated"],
            "capability_overlap": ["authenticated"],
        }
    ]
    matched = detector.match_known_patterns(candidates)
    assert len(matched) == 0


def test_build_chain_context_for_prompt():
    from src.greybox.planner.chain_detector import ChainDetector
    detector = ChainDetector()
    matched = [
        {
            "pattern_name": "SSRF + Cloud Metadata",
            "finding_a": "finding:F001",
            "finding_b": "finding:F002",
            "combined_impact": "Data breach via cloud credential extraction",
            "steps": ["SSRF reads metadata", "Extract IAM creds", "Access storage"],
            "capability_overlap": ["internal_network"],
        }
    ]
    context = detector.build_chain_context(matched)
    assert "SSRF" in context
    assert "finding:F001" in context
    assert "finding:F002" in context
