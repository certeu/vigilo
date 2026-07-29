"""Tests for the C2 active-claims guard (Slice 8).

When rules emit no verbs but specialist agents are still running
(``active_claims`` is non-empty), the scheduler must return ``[]``
instead of ``[Done(reason="coverage_complete")]``. Emitting DONE
while work is in-flight would tell the workflow to stop before the
running agents have reported back.

Budget exhaustion is a hard stop and must NOT be guarded — an empty
budget halts dispatch regardless of in-flight claims.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL
from src.greybox.scheduler.core import schedule
from src.greybox.scheduler.rules import SchedulerConfig


class _InMemoryGraph:
    def __init__(self, db: AsyncSurreal) -> None:
        self.db = db

    async def raw_query(self, query, params=None):
        result = await self.db.query(query, params or {})
        return result or []


@pytest_asyncio.fixture
async def empty_graph():
    db = AsyncSurreal("mem://")
    async with db:
        await db.use("vigilo", "test_active_claims_guard")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)
        yield _InMemoryGraph(db)


@pytest.mark.asyncio
async def test_empty_graph_empty_claims_emits_done(empty_graph):
    result = await schedule(empty_graph, SchedulerConfig(), active_claims=[])
    assert len(result.verbs) == 1
    assert result.verbs[0].kind == "DONE"
    assert result.verbs[0].reason == "coverage_complete"


@pytest.mark.asyncio
async def test_empty_graph_with_active_claims_returns_empty(empty_graph):
    result = await schedule(
        empty_graph,
        SchedulerConfig(),
        active_claims=["parameter:inflight"],
    )
    assert result.verbs == []


@pytest.mark.asyncio
async def test_budget_exhausted_fires_even_with_active_claims(empty_graph):
    # Below the floor (default 0.03) triggers the exhausted hard halt.
    result = await schedule(
        empty_graph,
        SchedulerConfig(),
        active_claims=["parameter:inflight"],
        budget_remaining_pct=0.01,
    )
    assert len(result.verbs) == 1
    assert result.verbs[0].kind == "DONE"
    assert result.verbs[0].reason == "budget_exhausted"


@pytest.mark.asyncio
async def test_tick_log_records_waiting_for_agents_halt_hint(empty_graph, tmp_path):
    config = SchedulerConfig(tick_log_dir=tmp_path)
    result = await schedule(
        empty_graph,
        config,
        active_claims=["parameter:inflight"],
        tick_number=3,
    )
    assert result.verbs == []
    body = json.loads((tmp_path / "tick-003.json").read_text())
    assert body["emitted_verbs"] == []
    assert body["active_claims"] == ["parameter:inflight"]
    assert body["halt_hint"] == "waiting_for_agents"
