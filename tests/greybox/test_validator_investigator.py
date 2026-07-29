"""Tests for validator and lead investigator context builders."""
from __future__ import annotations


def test_build_validator_context():
    """Validator context includes key fields and excludes evidence."""
    from src.greybox.services.validator import build_validator_context

    finding = {
        "id": "F-001",
        "vuln_type": "injection",
        "severity": "high",
        "url": "http://target.local/api/users",
        "cwe": "CWE-89",
        "poc_payload": "' OR 1=1 --",
        "title": "SQL Injection in user search",
        "evidence_file": "evidence/sqli_001.md",
        "reasoning": "The parameter was reflected in the SQL query without sanitization",
    }
    context = build_validator_context(finding)

    # Required fields present
    assert "F-001" in context
    assert "injection" in context
    assert "high" in context
    assert "http://target.local/api/users" in context
    assert "CWE-89" in context
    assert "' OR 1=1 --" in context
    assert "SQL Injection in user search" in context

    # Evidence and reasoning must be excluded (prevents confirmation bias)
    assert "evidence/sqli_001.md" not in context
    assert "reflected in the SQL query" not in context
    assert "evidence_file" not in context

    # Instructs independent reproduction
    assert "independently" in context.lower() or "from scratch" in context.lower()


def test_build_validator_context_minimal():
    """Validator context works with minimal finding data."""
    from src.greybox.services.validator import build_validator_context

    finding = {
        "id": "F-002",
        "vuln_type": "reflection",
        "severity": "medium",
    }
    context = build_validator_context(finding)
    assert "F-002" in context
    assert "reflection" in context
    assert "medium" in context
    # Optional fields should not cause errors or show 'None'
    assert "None" not in context
    # CWE and PoC lines should be absent when not provided
    assert "CWE" not in context
    assert "PoC" not in context


def test_build_investigator_context():
    """Investigator context includes hints, budget, and hypothesis."""
    from src.greybox.services.investigator import build_investigator_context

    lead = {
        "id": "L-010",
        "signal_type": "timing_anomaly",
        "strength": "high",
        "url": "http://target.local/api/search",
        "hypothesis": "Possible blind SQL injection via timing side-channel",
        "hints": [
            "Response time varies with input length",
            "Try SLEEP-based payloads",
        ],
        "attempt_count": 1,
    }
    context = build_investigator_context(lead, max_attempts=3)

    assert "L-010" in context
    assert "timing_anomaly" in context
    assert "high" in context
    assert "http://target.local/api/search" in context
    assert "blind SQL injection" in context
    assert "Response time varies" in context
    assert "SLEEP-based" in context
    # Budget should show remaining = 3 - 1 = 2
    assert "2" in context
    assert "3" in context


def test_investigator_context_shows_remaining_budget():
    """Budget calculation: max_attempts - attempt_count = remaining."""
    from src.greybox.services.investigator import build_investigator_context

    lead = {
        "id": "L-020",
        "signal_type": "response_code_anomaly",
        "url": "http://target.local/admin",
        "attempt_count": 2,
    }
    context = build_investigator_context(lead, max_attempts=3)

    # 3 - 2 = 1 remaining
    assert "1" in context
    assert "3" in context
    assert "Remaining attempts" in context


def test_investigator_context_no_hints():
    """Investigator context works without hints."""
    from src.greybox.services.investigator import build_investigator_context

    lead = {
        "id": "L-030",
        "signal_type": "error_response",
        "url": "http://target.local/debug",
        "hypothesis": "Debug endpoint may leak stack traces",
        "attempt_count": 0,
    }
    context = build_investigator_context(lead, max_attempts=3)
    assert "L-030" in context
    assert "Debug endpoint" in context
    # Without hints, no Hints section header
    assert "Hints" not in context
    # Full budget available
    assert "3 of 3" in context


def test_investigator_context_default_max_attempts():
    """Default max_attempts is 3."""
    from src.greybox.services.investigator import build_investigator_context

    lead = {"id": "L-040", "signal_type": "test", "attempt_count": 0}
    context = build_investigator_context(lead)
    assert "3 of 3" in context
