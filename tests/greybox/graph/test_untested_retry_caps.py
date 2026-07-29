"""Retry caps in ``untested_parameters`` (Slice 12 / D4).

A parameter is returned from ``untested_parameters`` iff:

- no conclusive attempt (vulnerable or clean) exists for the vuln_type
- inconclusive attempts are strictly below ``max_inconclusive_retries``
- failed attempts are strictly below ``max_failed_retries``

Conclusive verdicts always foreclose — retry caps are irrelevant in
that case. Only counts attempts for the requested vuln_type.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL
from src.greybox.graph.views import untested_parameters


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
        await db.use("vigilo", "test_retry_caps")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)
        yield _InMemoryGraph(db)


async def _seed_param(graph: _InMemoryGraph, pid: str) -> None:
    await graph.db.query(
        f"""
        CREATE endpoint:ep_{pid.split(':')[1]} SET method = 'GET', path = '/x',
            full_url = 'http://t/x', discovered_by = 'test',
            discovered_at = time::now(), rate_limited = false,
            requires_auth = false, status_codes_seen = [200];
        CREATE {pid} SET name = 'p', location = 'query', data_type = 'int',
            shape = 'numeric_id', discovered_by = 'test',
            discovered_at = time::now();
        RELATE endpoint:ep_{pid.split(':')[1]}->has_param->{pid};
        """
    )


async def _seed_attempt(
    graph: _InMemoryGraph,
    ta_id: str,
    param_id: str,
    verdict: str,
    vuln_type: str = "injection",
) -> None:
    failure_clause = (
        ", failure_reason = 'synthetic'" if verdict == "failed" else ""
    )
    await graph.db.query(
        f"""
        CREATE {ta_id} SET vuln_type = '{vuln_type}', technique = 'batch',
            payload = 'x', payload_hash = 'sha256:{ta_id}',
            verdict = '{verdict}'{failure_clause},
            response_code = 200, duration_ms = 1, agent = 'test',
            attempted_at = time::now();
        RELATE {ta_id}->tested_against->{param_id};
        """
    )


@pytest.mark.asyncio
async def test_two_inconclusive_at_cap_excludes_parameter(empty_graph):
    """Inconclusive attempts == cap → parameter excluded."""
    await _seed_param(empty_graph, "parameter:p1")
    await _seed_attempt(empty_graph, "test_attempt:i1", "parameter:p1", "inconclusive")
    await _seed_attempt(empty_graph, "test_attempt:i2", "parameter:p1", "inconclusive")
    result = await untested_parameters(
        empty_graph,
        vuln_type="injection",
        shapes=["numeric_id"],
        max_inconclusive_retries=2,
        max_failed_retries=3,
    )
    assert [p.id for p in result] == []


@pytest.mark.asyncio
async def test_one_inconclusive_below_cap_includes_parameter(empty_graph):
    """Inconclusive attempts < cap → parameter still included."""
    await _seed_param(empty_graph, "parameter:p1")
    await _seed_attempt(empty_graph, "test_attempt:i1", "parameter:p1", "inconclusive")
    result = await untested_parameters(
        empty_graph,
        vuln_type="injection",
        shapes=["numeric_id"],
        max_inconclusive_retries=2,
        max_failed_retries=3,
    )
    assert [p.id for p in result] == ["parameter:p1"]


@pytest.mark.asyncio
async def test_conclusive_vulnerable_excludes_regardless_of_caps(empty_graph):
    """A single conclusive_vulnerable attempt excludes the parameter."""
    await _seed_param(empty_graph, "parameter:p1")
    await _seed_attempt(
        empty_graph, "test_attempt:cv", "parameter:p1", "conclusive_vulnerable"
    )
    result = await untested_parameters(
        empty_graph,
        vuln_type="injection",
        shapes=["numeric_id"],
        max_inconclusive_retries=2,
        max_failed_retries=3,
    )
    assert [p.id for p in result] == []


@pytest.mark.asyncio
async def test_conclusive_clean_excludes_regardless_of_caps(empty_graph):
    """A single conclusive_clean attempt excludes the parameter."""
    await _seed_param(empty_graph, "parameter:p1")
    await _seed_attempt(
        empty_graph, "test_attempt:cc", "parameter:p1", "conclusive_clean"
    )
    result = await untested_parameters(
        empty_graph,
        vuln_type="injection",
        shapes=["numeric_id"],
        max_inconclusive_retries=2,
        max_failed_retries=3,
    )
    assert [p.id for p in result] == []


@pytest.mark.asyncio
async def test_three_failed_at_cap_excludes_parameter(empty_graph):
    """Failed attempts == cap → parameter excluded."""
    await _seed_param(empty_graph, "parameter:p1")
    await _seed_attempt(empty_graph, "test_attempt:f1", "parameter:p1", "failed")
    await _seed_attempt(empty_graph, "test_attempt:f2", "parameter:p1", "failed")
    await _seed_attempt(empty_graph, "test_attempt:f3", "parameter:p1", "failed")
    result = await untested_parameters(
        empty_graph,
        vuln_type="injection",
        shapes=["numeric_id"],
        max_inconclusive_retries=2,
        max_failed_retries=3,
    )
    assert [p.id for p in result] == []


@pytest.mark.asyncio
async def test_two_failed_below_cap_includes_parameter(empty_graph):
    """Failed attempts < cap → parameter still included."""
    await _seed_param(empty_graph, "parameter:p1")
    await _seed_attempt(empty_graph, "test_attempt:f1", "parameter:p1", "failed")
    await _seed_attempt(empty_graph, "test_attempt:f2", "parameter:p1", "failed")
    result = await untested_parameters(
        empty_graph,
        vuln_type="injection",
        shapes=["numeric_id"],
        max_inconclusive_retries=2,
        max_failed_retries=3,
    )
    assert [p.id for p in result] == ["parameter:p1"]


@pytest.mark.asyncio
async def test_retry_caps_only_count_matching_vuln_type(empty_graph):
    """Attempts for another vuln_type do not count against retry caps."""
    await _seed_param(empty_graph, "parameter:p1")
    await _seed_attempt(
        empty_graph, "test_attempt:x1", "parameter:p1",
        "inconclusive", vuln_type="reflection",
    )
    await _seed_attempt(
        empty_graph, "test_attempt:x2", "parameter:p1",
        "inconclusive", vuln_type="reflection",
    )
    result = await untested_parameters(
        empty_graph,
        vuln_type="injection",
        shapes=["numeric_id"],
        max_inconclusive_retries=2,
        max_failed_retries=3,
    )
    assert [p.id for p in result] == ["parameter:p1"]
