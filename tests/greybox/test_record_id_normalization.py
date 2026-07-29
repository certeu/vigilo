"""Tests for RecordID normalization across the graph stack.

Feature F: SurrealDB v2 returns RecordID objects from query results.
All ID-accepting functions must coerce these to ``table:id`` strings
before regex validation or string comparison.
"""
from __future__ import annotations

import pytest


class FakeRecordID:
    """Mimics the SurrealDB SDK RecordID with .table and .id attrs."""

    def __init__(self, table: str, key: str) -> None:
        self.table = table
        self.id = key

    def __str__(self) -> str:
        return f"{self.table}:{self.id}"


# ---------------------------------------------------------------------------
# client.normalize_record_id
# ---------------------------------------------------------------------------


class TestNormalizeRecordId:
    def test_string_passthrough(self):
        from src.greybox.graph.ids import normalize_record_id
        assert normalize_record_id("lead:L_abc123") == "lead:L_abc123"

    def test_record_id_object(self):
        from src.greybox.graph.ids import normalize_record_id
        rid = FakeRecordID("lead", "L_abc123")
        assert normalize_record_id(rid) == "lead:L_abc123"

    def test_arbitrary_object_fallback(self):
        from src.greybox.graph.ids import normalize_record_id
        assert normalize_record_id(42) == "42"

    def test_empty_string(self):
        from src.greybox.graph.ids import normalize_record_id
        assert normalize_record_id("") == ""


# ---------------------------------------------------------------------------
# views._stringify_id
# ---------------------------------------------------------------------------


class TestStringifyId:
    def test_string_passthrough(self):
        from src.greybox.graph.views import _stringify_id
        assert _stringify_id("parameter:p1") == "parameter:p1"

    def test_record_id_object(self):
        from src.greybox.graph.views import _stringify_id
        rid = FakeRecordID("parameter", "p1")
        assert _stringify_id(rid) == "parameter:p1"

    def test_integer_fallback(self):
        from src.greybox.graph.views import _stringify_id
        assert _stringify_id(123) == "123"


# ---------------------------------------------------------------------------
# graph_tool._str_id
# ---------------------------------------------------------------------------


class TestGraphToolStrId:
    def test_string_passthrough(self):
        from scripts.graph_tool import _str_id
        assert _str_id("test_attempt:ta_abc") == "test_attempt:ta_abc"

    def test_record_id_object(self):
        from scripts.graph_tool import _str_id
        rid = FakeRecordID("test_attempt", "ta_abc")
        assert _str_id(rid) == "test_attempt:ta_abc"

    def test_none_fallback(self):
        from scripts.graph_tool import _str_id
        assert _str_id(None) == "None"


# ---------------------------------------------------------------------------
# create_edge accepts RecordID-like objects (normalizes before validation)
# ---------------------------------------------------------------------------


class TestCreateEdgeAcceptsRecordId:
    @pytest.mark.asyncio
    async def test_create_edge_with_record_id_objects(self):
        """create_edge should normalize RecordID objects before regex validation."""
        from src.greybox.graph.ids import normalize_record_id
        from_id = normalize_record_id(FakeRecordID("test_attempt", "ta_abc123"))
        to_id = normalize_record_id(FakeRecordID("parameter", "p1"))
        assert from_id == "test_attempt:ta_abc123"
        assert to_id == "parameter:p1"

    def test_normalize_handles_finding_ids(self):
        from src.greybox.graph.ids import normalize_record_id
        rid = FakeRecordID("finding", "F_abc123def456")
        assert normalize_record_id(rid) == "finding:F_abc123def456"

    def test_normalize_handles_lead_ids(self):
        from src.greybox.graph.ids import normalize_record_id
        rid = FakeRecordID("lead", "L_dba7ddafee85")
        assert normalize_record_id(rid) == "lead:L_dba7ddafee85"
