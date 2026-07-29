"""Tests for the single read-path views over the SurrealDB graph."""
from __future__ import annotations

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL
from src.greybox.graph.views import (
    AccessMatrix,
    CoverageView,
    LeadView,
    ParameterView,
    VerdictCounts,
    access_matrix,
    attempt_counts_by_verdict,
    coverage_by_vuln_type,
    open_leads,
    untested_parameters,
)


@pytest.mark.asyncio
async def test_untested_parameters_filters_by_shape_and_vuln_type(graph_fixture):
    # graph_fixture seeds params with shapes numeric_id (5), free_text (3)
    # and one test_attempt marking 1 numeric_id param as tested for injection
    result = await untested_parameters(
        graph_fixture,
        vuln_type="injection",
        shapes=["numeric_id"],
    )
    assert len(result) == 4
    assert all(isinstance(p, ParameterView) for p in result)
    assert all(p.shape == "numeric_id" for p in result)
    assert all(p.endpoint_id.startswith("endpoint:") for p in result)


@pytest.mark.asyncio
async def test_open_leads_filters_by_strength(graph_fixture):
    result = await open_leads(graph_fixture, min_strength="medium")
    assert len(result) >= 1
    assert all(isinstance(l, LeadView) for l in result)
    assert all(l.signal_strength in {"medium", "high"} for l in result)
    assert all(l.status == "open" for l in result)


@pytest.mark.asyncio
async def test_coverage_by_vuln_type_counts_tested_params(graph_fixture):
    result = await coverage_by_vuln_type(graph_fixture)
    assert isinstance(result, dict)
    assert "injection" in result
    assert isinstance(result["injection"], CoverageView)
    assert result["injection"].tested == 1
    assert result["injection"].total == 8
    assert "reflection" in result
    assert result["reflection"].tested == 1
    assert result["reflection"].total == 8


@pytest.mark.asyncio
async def test_access_matrix_groups_allow_and_deny_by_identity(graph_fixture):
    await graph_fixture.db.query(
        """
        CREATE identity:anonymous SET role = 'anonymous', privilege_level = 0,
            auth_method = 'session_cookie', credential_ref = 'anon',
            session_active = true, discovered_by = 'test', discovered_at = time::now();
        CREATE identity:user SET role = 'user', privilege_level = 1,
            auth_method = 'session_cookie', credential_ref = 'user',
            session_active = true, discovered_by = 'test', discovered_at = time::now();
        RELATE identity:anonymous->denied_access->endpoint:e1;
        RELATE identity:user->can_access->endpoint:e1;
        RELATE identity:user->can_access->endpoint:e2;
        """
    )

    result = await access_matrix(graph_fixture, ["identity:anonymous", "identity:user"])

    assert isinstance(result, AccessMatrix)
    assert result.denied_access["identity:anonymous"] == ["endpoint:e1"]
    assert set(result.can_access["identity:user"]) == {"endpoint:e1", "endpoint:e2"}


class _InMemoryGraph:
    def __init__(self, db: AsyncSurreal) -> None:
        self.db = db

    async def raw_query(self, query, params=None):
        result = await self.db.query(query, params or {})
        return result or []


@pytest_asyncio.fixture
async def _empty_graph():
    db = AsyncSurreal("mem://")
    async with db:
        await db.use("vigilo", "test_verdict_counts")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)
        yield _InMemoryGraph(db)


@pytest.mark.asyncio
async def test_attempt_counts_by_verdict_empty_graph(_empty_graph):
    result = await attempt_counts_by_verdict(_empty_graph)
    assert isinstance(result, VerdictCounts)
    assert result.conclusive_vulnerable == 0
    assert result.conclusive_clean == 0
    assert result.inconclusive == 0
    assert result.failed == 0


@pytest.mark.asyncio
async def test_attempt_counts_by_verdict_counts_each_verdict(_empty_graph):
    await _empty_graph.db.query(
        """
        CREATE test_attempt:v1 SET vuln_type = 'injection', technique = 't',
            payload = 'p', payload_hash = 'sha256:a',
            verdict = 'conclusive_vulnerable',
            response_code = 200, duration_ms = 1, agent = 'a',
            attempted_at = time::now();
        CREATE test_attempt:v2 SET vuln_type = 'injection', technique = 't',
            payload = 'p', payload_hash = 'sha256:b',
            verdict = 'conclusive_vulnerable',
            response_code = 200, duration_ms = 1, agent = 'a',
            attempted_at = time::now();
        CREATE test_attempt:c1 SET vuln_type = 'injection', technique = 't',
            payload = 'p', payload_hash = 'sha256:c',
            verdict = 'conclusive_clean',
            response_code = 200, duration_ms = 1, agent = 'a',
            attempted_at = time::now();
        CREATE test_attempt:i1 SET vuln_type = 'injection', technique = 't',
            payload = 'p', payload_hash = 'sha256:d',
            verdict = 'inconclusive',
            response_code = 429, duration_ms = 1, agent = 'a',
            attempted_at = time::now();
        CREATE test_attempt:f1 SET vuln_type = 'injection', technique = 't',
            payload = 'p', payload_hash = 'sha256:e',
            verdict = 'failed', failure_reason = 'crash',
            response_code = 0, duration_ms = 1, agent = 'a',
            attempted_at = time::now();
        CREATE test_attempt:f2 SET vuln_type = 'injection', technique = 't',
            payload = 'p', payload_hash = 'sha256:f',
            verdict = 'failed', failure_reason = 'crash',
            response_code = 0, duration_ms = 1, agent = 'a',
            attempted_at = time::now();
        CREATE test_attempt:f3 SET vuln_type = 'injection', technique = 't',
            payload = 'p', payload_hash = 'sha256:g',
            verdict = 'failed', failure_reason = 'crash',
            response_code = 0, duration_ms = 1, agent = 'a',
            attempted_at = time::now();
        """
    )
    result = await attempt_counts_by_verdict(_empty_graph)
    assert result.conclusive_vulnerable == 2
    assert result.conclusive_clean == 1
    assert result.inconclusive == 1
    assert result.failed == 3
