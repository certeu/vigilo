"""Tests for the schema-version ratchet in ``init_schema.ensure_schema``.

Grey-box is a fresh-scan project — on mismatch, the operator must wipe
the SurrealDB database and re-scan. No in-place migrations.
"""
from __future__ import annotations

from typing import Any

import pytest


class _FakeClient:
    """Minimal async GraphClient stand-in.

    ``meta_row`` is the canned row that ``SELECT version FROM _schema_meta``
    will return. ``None`` = empty DB (first-time init).
    """

    def __init__(self, meta_row: dict[str, Any] | None) -> None:
        self.meta_row = meta_row
        # Recorded for assertions.
        self.queries: list[tuple[str, dict[str, Any] | None]] = []

    async def raw_query(
        self, query: str, params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        self.queries.append((query, params))
        if "SELECT version FROM _schema_meta" in query:
            return [self.meta_row] if self.meta_row else []
        # DDL and CREATE queries don't return rows we care about.
        return []


@pytest.mark.asyncio
async def test_ensure_schema_first_time_init_applies_ddl_and_inserts_meta():
    from src.greybox.graph import init_schema as init_mod

    client = _FakeClient(meta_row=None)
    await init_mod.ensure_schema(client)

    joined = "\n".join(q for q, _ in client.queries)
    # Initial probe happened
    assert any(
        "SELECT version FROM _schema_meta" in q for q, _ in client.queries
    )
    # Full DDL was applied
    assert "DEFINE TABLE IF NOT EXISTS endpoint SCHEMAFULL" in joined
    assert "DEFINE TABLE IF NOT EXISTS _schema_meta SCHEMAFULL" in joined
    # Meta row was inserted with the parameterized version
    create_calls = [
        (q, p) for q, p in client.queries
        if "CREATE _schema_meta" in q
    ]
    assert len(create_calls) == 1
    _, params = create_calls[0]
    assert params is not None
    assert params["v"] == init_mod.SCHEMA_VERSION


@pytest.mark.asyncio
async def test_ensure_schema_matching_version_is_noop():
    from src.greybox.graph import init_schema as init_mod

    client = _FakeClient(meta_row={"version": init_mod.SCHEMA_VERSION})
    await init_mod.ensure_schema(client)

    joined = "\n".join(q for q, _ in client.queries)
    # Probe ran
    assert any(
        "SELECT version FROM _schema_meta" in q for q, _ in client.queries
    )
    # DDL was NOT re-applied
    assert "DEFINE TABLE IF NOT EXISTS endpoint" not in joined
    # Meta was NOT re-inserted
    assert "CREATE _schema_meta" not in joined


@pytest.mark.asyncio
async def test_ensure_schema_mismatch_raises():
    from src.greybox.graph import init_schema as init_mod

    client = _FakeClient(meta_row={"version": init_mod.SCHEMA_VERSION - 1})
    with pytest.raises(init_mod.SchemaVersionMismatchError) as exc_info:
        await init_mod.ensure_schema(client)

    msg = str(exc_info.value)
    assert "Schema version mismatch" in msg
    assert f"code={init_mod.SCHEMA_VERSION}" in msg
    assert "fresh-scan" in msg or "delete" in msg.lower()


def test_schema_version_mismatch_error_is_runtime_error():
    from src.greybox.graph.init_schema import SchemaVersionMismatchError

    assert issubclass(SchemaVersionMismatchError, RuntimeError)
