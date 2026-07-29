"""Progress formula counts only conclusive verdicts + new findings.

A tick is "progress" iff at least one of these deltas is positive:

- new ``finding`` nodes since the previous tick
- new ``test_attempt`` rows with ``verdict = 'conclusive_vulnerable'``
- new ``test_attempt`` rows with ``verdict = 'conclusive_clean'``

``inconclusive`` and ``failed`` deltas do NOT count — those are retry
candidates, not coverage. This test drives the counter through a
multi-tick sequence using a fake graph reader so we don't depend on
SurrealDB for a formula-only check.
"""
from __future__ import annotations

from typing import Any

import pytest

from src.greybox.scheduler.core import schedule
from src.greybox.scheduler.rules import SchedulerConfig


class _FakeGraph:
    """Minimal graph reader returning scripted counts per table."""

    def __init__(self, graph_counts: dict[str, int], verdict_counts: dict[str, int]):
        self._graph_counts = graph_counts
        self._verdict_counts = verdict_counts

    async def raw_query(
        self, query: str, params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        stripped = query.strip()
        if stripped.startswith("SELECT count() FROM"):
            table = stripped.split()[3]
            count = self._graph_counts.get(table, 0)
            return [{"count": count}] if count else []
        if stripped.startswith("SELECT verdict, count()"):
            return [
                {"verdict": v, "c": c}
                for v, c in self._verdict_counts.items()
                if c > 0
            ]
        return []


def _base_verdicts() -> dict[str, int]:
    return {
        "conclusive_vulnerable": 0,
        "conclusive_clean": 0,
        "inconclusive": 0,
        "failed": 0,
    }


def _base_graph_counts() -> dict[str, int]:
    return {
        "endpoint": 0,
        "parameter": 0,
        "lead": 0,
        "finding": 0,
        "test_attempt": 0,
    }


@pytest.mark.asyncio
async def test_inconclusive_and_failed_growth_increments_counter():
    """Inconclusive + failed deltas are not progress — counter increments."""
    prev_verdicts = _base_verdicts()
    current_verdicts = _base_verdicts()
    current_verdicts["inconclusive"] = 4
    current_verdicts["failed"] = 7
    graph = _FakeGraph(
        graph_counts={"test_attempt": 11},
        verdict_counts=current_verdicts,
    )
    result = await schedule(
        graph,
        SchedulerConfig(idle_ticks_before_done=100),
        active_claims=["parameter:inflight"],
        previous_graph_counts=_base_graph_counts(),
        previous_verdict_counts=prev_verdicts,
        ticks_since_last_progress=3,
    )
    assert result.ticks_since_last_progress == 4


@pytest.mark.asyncio
async def test_conclusive_vulnerable_growth_resets_counter():
    """A new conclusive_vulnerable attempt resets the counter to 0."""
    prev_verdicts = _base_verdicts()
    current_verdicts = _base_verdicts()
    current_verdicts["conclusive_vulnerable"] = 1
    graph = _FakeGraph(
        graph_counts={"test_attempt": 1},
        verdict_counts=current_verdicts,
    )
    result = await schedule(
        graph,
        SchedulerConfig(idle_ticks_before_done=100),
        active_claims=["parameter:inflight"],
        previous_graph_counts=_base_graph_counts(),
        previous_verdict_counts=prev_verdicts,
        ticks_since_last_progress=4,
    )
    assert result.ticks_since_last_progress == 0


@pytest.mark.asyncio
async def test_conclusive_clean_growth_resets_counter():
    """A new conclusive_clean attempt resets the counter to 0."""
    prev_verdicts = _base_verdicts()
    current_verdicts = _base_verdicts()
    current_verdicts["conclusive_clean"] = 1
    graph = _FakeGraph(
        graph_counts={"test_attempt": 1},
        verdict_counts=current_verdicts,
    )
    result = await schedule(
        graph,
        SchedulerConfig(idle_ticks_before_done=100),
        active_claims=["parameter:inflight"],
        previous_graph_counts=_base_graph_counts(),
        previous_verdict_counts=prev_verdicts,
        ticks_since_last_progress=5,
    )
    assert result.ticks_since_last_progress == 0


@pytest.mark.asyncio
async def test_new_finding_resets_counter_regression_guard():
    """A new finding (no verdict delta) still resets the counter to 0."""
    prev_graph = _base_graph_counts()
    current_graph = _base_graph_counts()
    current_graph["finding"] = 1
    graph = _FakeGraph(
        graph_counts=current_graph,
        verdict_counts=_base_verdicts(),
    )
    result = await schedule(
        graph,
        SchedulerConfig(idle_ticks_before_done=100),
        active_claims=["parameter:inflight"],
        previous_graph_counts=prev_graph,
        previous_verdict_counts=_base_verdicts(),
        ticks_since_last_progress=6,
    )
    assert result.ticks_since_last_progress == 0
