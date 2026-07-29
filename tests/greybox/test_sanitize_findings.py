"""Tests for SurrealDB type sanitization in activity returns."""
from __future__ import annotations

import json
from datetime import datetime, timezone


def test_sanitize_for_json_converts_record_id():
    """RecordID objects become plain strings after sanitization."""
    from src.greybox.temporal.activities import _sanitize_for_json

    class FakeRecordID:
        def __init__(self, table: str, key: str):
            self.table = table
            self.key = key

        def __str__(self) -> str:
            return f"{self.table}:{self.key}"

    findings = [
        {
            "id": FakeRecordID("finding", "abc123"),
            "vuln_type": "reflection",
            "discovered_by": "reflection-specialist-001",
            "created_at": datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc),
            "severity": "high",
            "nested": {
                "ref": FakeRecordID("endpoint", "login"),
                "ts": datetime(2026, 4, 20, 13, 0, 0, tzinfo=timezone.utc),
            },
        }
    ]

    result = _sanitize_for_json(findings)

    serialized = json.dumps(result)
    assert isinstance(serialized, str)

    assert result[0]["id"] == "finding:abc123"
    assert result[0]["created_at"] == "2026-04-20 12:00:00+00:00"
    assert result[0]["nested"]["ref"] == "endpoint:login"


def test_sanitize_for_json_passthrough_primitives():
    """Primitive types pass through unchanged."""
    from src.greybox.temporal.activities import _sanitize_for_json

    data = [{"name": "test", "count": 42, "active": True, "tags": ["a", "b"]}]
    result = _sanitize_for_json(data)
    assert result == data


def test_sanitize_for_json_empty_list():
    """Empty list returns empty list."""
    from src.greybox.temporal.activities import _sanitize_for_json

    assert _sanitize_for_json([]) == []
