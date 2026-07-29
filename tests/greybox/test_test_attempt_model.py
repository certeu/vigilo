"""Tests for the ``TestAttemptNode`` verdict taxonomy.

Slice 1 replaces the old ``result`` field with ``verdict`` and makes
``failure_reason`` mandatory (enforced via a Pydantic validator) whenever
the verdict is ``"failed"``.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError


def _kwargs(**overrides):
    """Return a minimal valid TestAttemptNode kwargs dict with overrides."""
    base = {
        "vuln_type": "injection",
        "technique": "union_based",
        "payload": "' UNION SELECT NULL--",
        "response_code": 200,
        "duration_ms": 120,
        "agent": "injection-specialist",
    }
    base.update(overrides)
    return base


def test_verdict_is_required():
    from src.greybox.graph.schema import TestAttemptNode

    with pytest.raises(ValidationError):
        TestAttemptNode(**_kwargs())


def test_verdict_accepts_all_four_values():
    from src.greybox.graph.schema import TestAttemptNode

    for v in ("conclusive_vulnerable", "conclusive_clean", "inconclusive"):
        ta = TestAttemptNode(**_kwargs(verdict=v))
        assert ta.verdict == v

    ta = TestAttemptNode(**_kwargs(verdict="failed", failure_reason="timeout"))
    assert ta.verdict == "failed"
    assert ta.failure_reason == "timeout"


def test_verdict_rejects_unknown_value():
    from src.greybox.graph.schema import TestAttemptNode

    with pytest.raises(ValidationError):
        TestAttemptNode(**_kwargs(verdict="bogus"))


def test_verdict_rejects_legacy_result_values():
    """The old taxonomy ('success'/'fail'/'error') is gone."""
    from src.greybox.graph.schema import TestAttemptNode

    for legacy in ("success", "fail", "error"):
        with pytest.raises(ValidationError):
            TestAttemptNode(**_kwargs(verdict=legacy))


def test_failed_verdict_requires_failure_reason():
    from src.greybox.graph.schema import TestAttemptNode

    with pytest.raises(ValidationError) as exc_info:
        TestAttemptNode(**_kwargs(verdict="failed"))
    assert "failure_reason" in str(exc_info.value)


def test_failed_verdict_with_failure_reason_accepted():
    from src.greybox.graph.schema import TestAttemptNode

    ta = TestAttemptNode(**_kwargs(verdict="failed", failure_reason="agent_crash"))
    assert ta.failure_reason == "agent_crash"


def test_failure_reason_optional_for_non_failed_verdicts():
    from src.greybox.graph.schema import TestAttemptNode

    ta = TestAttemptNode(**_kwargs(verdict="inconclusive"))
    assert ta.failure_reason is None


def test_test_attempt_ddl_has_verdict_fields():
    """The SurrealDB DDL must define verdict + failure_reason, not result."""
    from src.greybox.graph.init_schema import TABLES_DDL

    assert (
        "DEFINE FIELD verdict ON test_attempt TYPE string" in TABLES_DDL
    )
    assert "'conclusive_vulnerable'" in TABLES_DDL
    assert "'conclusive_clean'" in TABLES_DDL
    assert "'inconclusive'" in TABLES_DDL
    assert "'failed'" in TABLES_DDL
    assert (
        "DEFINE FIELD failure_reason ON test_attempt TYPE option<string>"
        in TABLES_DDL
    )
    assert "DEFINE FIELD result ON test_attempt" not in TABLES_DDL
