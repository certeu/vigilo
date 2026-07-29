"""Tests for greybox graph schema initialization.

Ensures every edge registered in EDGE_TYPES has a corresponding
DEFINE TABLE statement emitted by ``ensure_schema`` on first-time init.
"""
from __future__ import annotations

from typing import Any

import pytest

from src.greybox.graph.init_schema import ensure_schema
from src.greybox.graph.schema import EDGE_TYPES


class _RecordingClient:
    """Minimal async GraphClient stand-in that records every raw_query.

    ``meta_row = None`` simulates an empty database (first-time init path),
    which is what we need to exercise the DDL emission.
    """

    def __init__(self) -> None:
        self.queries: list[tuple[str, dict[str, Any] | None]] = []

    async def raw_query(
        self, query: str, params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        self.queries.append((query, params))
        # Empty DB: the meta probe returns no rows so ensure_schema runs
        # the first-time init path and emits the full DDL.
        return []


@pytest.mark.asyncio
async def test_ensure_schema_defines_all_edge_tables():
    client = _RecordingClient()
    await ensure_schema(client)

    joined = "\n".join(q for q, _ in client.queries)

    for edge_name in EDGE_TYPES:
        assert f"DEFINE TABLE IF NOT EXISTS {edge_name}" in joined, (
            f"Edge table {edge_name!r} not defined in ensure_schema DDL"
        )
