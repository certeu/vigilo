"""Tests for the C3 diminishing-returns halt (Slice 9).

Progress tracking moves from the workflow into the scheduler. A tick is
"progress" if either:

- A new ``finding`` node appeared since the previous tick, or
- A new ``test_attempt`` with ``verdict='conclusive_vulnerable'`` appeared
  since the previous tick.

``verdict='inconclusive'`` and ``verdict='failed'`` do NOT count as
progress — they are retry candidates, not completed tests.

When ``ticks_since_last_progress`` hits ``idle_ticks_before_done``, the
scheduler emits ``Done(reason="diminishing_returns")``.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL
from src.greybox.scheduler.core import ScheduleTickResult, schedule
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
        await db.use("vigilo", "test_diminishing_returns")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)
        yield _InMemoryGraph(db)


async def _create_finding(graph: _InMemoryGraph, fid: str) -> None:
    await graph.db.query(
        f"""
        CREATE {fid} SET vuln_type = 'injection', severity = 'high',
            status = 'confirmed', confidence = 'high',
            title = 't', impact = 'x',
            discovered_by = 'test', discovered_at = time::now();
        """
    )


async def _create_test_attempt(
    graph: _InMemoryGraph, ta_id: str, verdict: str,
) -> None:
    failure_clause = (
        ", failure_reason = 'synthetic'"
        if verdict == "failed"
        else ""
    )
    await graph.db.query(
        f"""
        CREATE {ta_id} SET vuln_type = 'injection', technique = 'batch',
            payload = 'x', payload_hash = 'sha256:x',
            verdict = '{verdict}'{failure_clause},
            response_code = 200, duration_ms = 1, agent = 'test',
            attempted_at = time::now();
        """
    )


@pytest.mark.asyncio
async def test_returns_schedule_tick_result(empty_graph):
    """``schedule()`` returns a ScheduleTickResult carrying counts + counter."""
    result = await schedule(empty_graph, SchedulerConfig(), active_claims=[])
    assert isinstance(result, ScheduleTickResult)
    assert isinstance(result.verbs, list)
    assert isinstance(result.graph_counts, dict)
    assert isinstance(result.verdict_counts, dict)
    assert isinstance(result.ticks_since_last_progress, int)


@pytest.mark.asyncio
async def test_counter_increments_when_no_progress(empty_graph):
    """With no new finding or conclusive attempt, counter goes prev+1."""
    result = await schedule(
        empty_graph,
        SchedulerConfig(idle_ticks_before_done=100),
        active_claims=["parameter:inflight"],
        previous_graph_counts={"finding": 0, "test_attempt": 0,
                               "endpoint": 0, "parameter": 0, "lead": 0},
        previous_verdict_counts={
            "conclusive_vulnerable": 0,
            "conclusive_clean": 0,
            "inconclusive": 0,
            "failed": 0,
        },
        ticks_since_last_progress=5,
    )
    assert result.ticks_since_last_progress == 6


@pytest.mark.asyncio
async def test_counter_resets_on_new_finding(empty_graph):
    """A new finding since last tick resets the counter to 0."""
    await _create_finding(empty_graph, "finding:f1")
    result = await schedule(
        empty_graph,
        SchedulerConfig(idle_ticks_before_done=100),
        active_claims=["parameter:inflight"],
        previous_graph_counts={"finding": 0, "test_attempt": 0,
                               "endpoint": 0, "parameter": 0, "lead": 0},
        previous_verdict_counts={
            "conclusive_vulnerable": 0,
            "conclusive_clean": 0,
            "inconclusive": 0,
            "failed": 0,
        },
        ticks_since_last_progress=10,
    )
    assert result.ticks_since_last_progress == 0
    assert result.graph_counts["finding"] == 1


@pytest.mark.asyncio
async def test_counter_resets_on_new_conclusive_vulnerable(empty_graph):
    """A new conclusive_vulnerable attempt (even without finding) resets counter."""
    await _create_test_attempt(empty_graph, "test_attempt:ta1", "conclusive_vulnerable")
    result = await schedule(
        empty_graph,
        SchedulerConfig(idle_ticks_before_done=100),
        active_claims=["parameter:inflight"],
        previous_graph_counts={"finding": 0, "test_attempt": 0,
                               "endpoint": 0, "parameter": 0, "lead": 0},
        previous_verdict_counts={
            "conclusive_vulnerable": 0,
            "conclusive_clean": 0,
            "inconclusive": 0,
            "failed": 0,
        },
        ticks_since_last_progress=7,
    )
    assert result.ticks_since_last_progress == 0
    assert result.verdict_counts["conclusive_vulnerable"] == 1


@pytest.mark.asyncio
async def test_counter_does_not_reset_on_inconclusive(empty_graph):
    """New inconclusive attempts do NOT count as progress."""
    await _create_test_attempt(empty_graph, "test_attempt:ta_inc", "inconclusive")
    result = await schedule(
        empty_graph,
        SchedulerConfig(idle_ticks_before_done=100),
        active_claims=["parameter:inflight"],
        previous_graph_counts={"finding": 0, "test_attempt": 0,
                               "endpoint": 0, "parameter": 0, "lead": 0},
        previous_verdict_counts={
            "conclusive_vulnerable": 0,
            "conclusive_clean": 0,
            "inconclusive": 0,
            "failed": 0,
        },
        ticks_since_last_progress=4,
    )
    assert result.ticks_since_last_progress == 5
    assert result.verdict_counts["inconclusive"] == 1


@pytest.mark.asyncio
async def test_counter_does_not_reset_on_failed(empty_graph):
    """New failed attempts do NOT count as progress."""
    await _create_test_attempt(empty_graph, "test_attempt:ta_fail", "failed")
    result = await schedule(
        empty_graph,
        SchedulerConfig(idle_ticks_before_done=100),
        active_claims=["parameter:inflight"],
        previous_graph_counts={"finding": 0, "test_attempt": 0,
                               "endpoint": 0, "parameter": 0, "lead": 0},
        previous_verdict_counts={
            "conclusive_vulnerable": 0,
            "conclusive_clean": 0,
            "inconclusive": 0,
            "failed": 0,
        },
        ticks_since_last_progress=4,
    )
    assert result.ticks_since_last_progress == 5
    assert result.verdict_counts["failed"] == 1


@pytest.mark.asyncio
async def test_emits_diminishing_returns_when_counter_hits_threshold(empty_graph):
    """Counter at threshold → DONE with reason=diminishing_returns.

    Graph has an in-flight claim so ``coverage_complete`` doesn't win
    the race in ``rule_done``; the diminishing-returns halt must still
    fire when nothing has progressed for ``idle_ticks_before_done``.
    """
    result = await schedule(
        empty_graph,
        SchedulerConfig(idle_ticks_before_done=20),
        active_claims=["parameter:inflight"],
        previous_graph_counts={"finding": 0, "test_attempt": 0,
                               "endpoint": 0, "parameter": 0, "lead": 0},
        previous_verdict_counts={
            "conclusive_vulnerable": 0,
            "conclusive_clean": 0,
            "inconclusive": 0,
            "failed": 0,
        },
        ticks_since_last_progress=19,
    )
    assert len(result.verbs) == 1
    assert result.verbs[0].kind == "DONE"
    assert result.verbs[0].reason == "diminishing_returns"
    assert result.ticks_since_last_progress == 20


@pytest.mark.asyncio
async def test_threshold_not_triggered_before_limit(empty_graph):
    """Counter one below threshold does not trigger diminishing_returns."""
    result = await schedule(
        empty_graph,
        SchedulerConfig(idle_ticks_before_done=20),
        active_claims=["parameter:inflight"],
        previous_graph_counts={"finding": 0, "test_attempt": 0,
                               "endpoint": 0, "parameter": 0, "lead": 0},
        previous_verdict_counts={
            "conclusive_vulnerable": 0,
            "conclusive_clean": 0,
            "inconclusive": 0,
            "failed": 0,
        },
        ticks_since_last_progress=18,
    )
    assert result.ticks_since_last_progress == 19
    assert all(v.kind != "DONE" or v.reason != "diminishing_returns"
               for v in result.verbs)
