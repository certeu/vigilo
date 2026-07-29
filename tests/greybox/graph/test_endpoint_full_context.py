"""``endpoint_full_context`` typed graph view (Slice 15 / G1).

For a given endpoint and a set of identities, the view returns:

- ``siblings`` — all parameters attached to that endpoint (via ``has_param``)
- ``test_attempts`` — every ``test_attempt`` against any of those siblings,
  across ALL identities in the graph (not just the caller's set)
- ``findings`` — every finding with an ``exploits`` edge to the endpoint
- ``access_observations`` — per-identity ``can_access`` / ``denied_access``,
  restricted to the provided ``identity_ids``

Scope decisions:

- Siblings include every parameter on the endpoint (we do NOT exclude the
  parameter currently being probed — the caller already knows which one it
  is, and excluding it complicates the query for no analytic gain).
- ``test_attempts`` are returned for every identity in the graph (not
  filtered to the caller's ``identity_ids``). Cross-identity visibility is
  the whole point of the view; trimming it to the caller's set would mean
  a specialist running as ``identity:user`` never learns that
  ``identity:admin`` already probed the same endpoint.
- Nothing from unrelated endpoints leaks into any list.
- Missing endpoint returns an empty ``EndpointContextView``; never raises.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL
from src.greybox.graph.views import (
    AccessObservation,
    EndpointContextView,
    FindingSummary,
    TestAttemptSummary,
    endpoint_full_context,
)


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
        await db.use("vigilo", "test_endpoint_full_ctx")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)
        yield _InMemoryGraph(db)


async def _seed_endpoint(graph: _InMemoryGraph, ep_id: str, path: str = "/x") -> None:
    await graph.db.query(
        f"""
        CREATE {ep_id} SET method = 'GET', path = '{path}',
            full_url = 'http://t{path}', discovered_by = 'test',
            discovered_at = time::now(), rate_limited = false,
            requires_auth = false, status_codes_seen = [200];
        """
    )


async def _seed_param(
    graph: _InMemoryGraph, param_id: str, endpoint_id: str,
    name: str = "p", shape: str = "free_text", location: str = "query",
) -> None:
    await graph.db.query(
        f"""
        CREATE {param_id} SET name = '{name}', location = '{location}',
            data_type = 'string', shape = '{shape}', discovered_by = 'test',
            discovered_at = time::now();
        RELATE {endpoint_id}->has_param->{param_id};
        """
    )


async def _seed_identity(graph: _InMemoryGraph, identity_id: str, role: str) -> None:
    await graph.db.query(
        f"""
        CREATE {identity_id} SET role = '{role}', privilege_level = 0,
            auth_method = 'session_cookie', credential_ref = 'cfg:{role}',
            session_active = true, discovered_by = 'test',
            discovered_at = time::now();
        """
    )


async def _seed_attempt(
    graph: _InMemoryGraph, ta_id: str, param_id: str,
    vuln_type: str = "injection", verdict: str = "conclusive_clean",
    agent: str = "specialist",
) -> None:
    await graph.db.query(
        f"""
        CREATE {ta_id} SET vuln_type = '{vuln_type}', technique = 'batch',
            payload = 'x', payload_hash = 'sha256:{ta_id}',
            verdict = '{verdict}',
            response_code = 200, duration_ms = 1, agent = '{agent}',
            attempted_at = time::now();
        RELATE {ta_id}->tested_against->{param_id};
        """
    )


async def _seed_finding(
    graph: _InMemoryGraph, finding_id: str, endpoint_id: str,
    vuln_type: str = "authorization", severity: str = "high",
    title: str = "Horizontal escalation",
) -> None:
    await graph.db.query(
        f"""
        CREATE {finding_id} SET title = '{title}',
            vuln_type = '{vuln_type}', severity = '{severity}',
            status = 'confirmed', confidence = 'high',
            impact = 'impact', discovered_by = 'specialist',
            discovered_at = time::now();
        RELATE {finding_id}->exploits->{endpoint_id};
        """
    )


@pytest.mark.asyncio
async def test_returns_siblings_on_same_endpoint(empty_graph):
    """All parameters linked via has_param to the endpoint appear as siblings."""
    await _seed_endpoint(empty_graph, "endpoint:5", path="/item")
    await _seed_endpoint(empty_graph, "endpoint:9", path="/other")
    await _seed_param(empty_graph, "parameter:a", "endpoint:5", name="id", shape="numeric_id")
    await _seed_param(empty_graph, "parameter:b", "endpoint:5", name="slug", shape="free_text")
    await _seed_param(empty_graph, "parameter:c", "endpoint:5", name="cat", shape="enum")
    # Noise: unrelated parameter on a different endpoint.
    await _seed_param(empty_graph, "parameter:z", "endpoint:9", name="noise")

    result = await endpoint_full_context(
        empty_graph, "endpoint:5", ["identity:admin", "identity:user"]
    )

    assert isinstance(result, EndpointContextView)
    assert result.endpoint_id == "endpoint:5"
    sibling_ids = sorted(s.id for s in result.siblings)
    assert sibling_ids == ["parameter:a", "parameter:b", "parameter:c"]
    # Unrelated parameter MUST NOT leak in.
    assert "parameter:z" not in sibling_ids


@pytest.mark.asyncio
async def test_returns_test_attempts_across_identities(empty_graph):
    """Every test_attempt against a sibling parameter is surfaced."""
    await _seed_endpoint(empty_graph, "endpoint:5")
    await _seed_identity(empty_graph, "identity:admin", "admin")
    await _seed_identity(empty_graph, "identity:user", "user")
    await _seed_param(empty_graph, "parameter:a", "endpoint:5")

    await _seed_attempt(
        empty_graph, "test_attempt:ta1", "parameter:a",
        vuln_type="injection", verdict="conclusive_clean", agent="specialist_admin",
    )
    await _seed_attempt(
        empty_graph, "test_attempt:ta2", "parameter:a",
        vuln_type="authorization", verdict="inconclusive", agent="specialist_user",
    )
    await _seed_attempt(
        empty_graph, "test_attempt:ta3", "parameter:a",
        vuln_type="reflection", verdict="conclusive_vulnerable", agent="specialist_admin",
    )

    result = await endpoint_full_context(
        empty_graph, "endpoint:5", ["identity:admin", "identity:user"]
    )

    assert len(result.test_attempts) == 3
    for attempt in result.test_attempts:
        assert isinstance(attempt, TestAttemptSummary)
        assert attempt.vuln_type
        assert attempt.verdict
        assert attempt.agent
    ids = sorted(a.id for a in result.test_attempts)
    assert ids == ["test_attempt:ta1", "test_attempt:ta2", "test_attempt:ta3"]


@pytest.mark.asyncio
async def test_returns_findings_exploiting_endpoint(empty_graph):
    """Findings with an ``exploits`` edge to the endpoint are listed."""
    await _seed_endpoint(empty_graph, "endpoint:5")
    await _seed_finding(
        empty_graph, "finding:f1", "endpoint:5",
        vuln_type="authorization", severity="high",
        title="Horizontal escalation",
    )
    await _seed_finding(
        empty_graph, "finding:f2", "endpoint:5",
        vuln_type="injection", severity="critical",
        title="SQL injection in id parameter",
    )

    result = await endpoint_full_context(empty_graph, "endpoint:5", [])

    assert len(result.findings) == 2
    for f in result.findings:
        assert isinstance(f, FindingSummary)
    by_id = {f.id: f for f in result.findings}
    assert by_id["finding:f1"].title == "Horizontal escalation"
    assert by_id["finding:f1"].severity == "high"
    assert by_id["finding:f2"].vuln_type == "injection"


@pytest.mark.asyncio
async def test_returns_access_observations(empty_graph):
    """can_access and denied_access edges are grouped per identity."""
    await _seed_endpoint(empty_graph, "endpoint:5")
    await _seed_identity(empty_graph, "identity:admin", "admin")
    await _seed_identity(empty_graph, "identity:user", "user")
    await empty_graph.db.query("RELATE identity:admin->can_access->endpoint:5;")
    await empty_graph.db.query("RELATE identity:user->denied_access->endpoint:5;")

    result = await endpoint_full_context(
        empty_graph, "endpoint:5", ["identity:admin", "identity:user"]
    )

    assert len(result.access_observations) == 2
    by_identity = {obs.identity_id: obs for obs in result.access_observations}
    assert isinstance(by_identity["identity:admin"], AccessObservation)
    assert by_identity["identity:admin"].kind == "allowed"
    assert by_identity["identity:user"].kind == "denied"


@pytest.mark.asyncio
async def test_empty_when_endpoint_absent(empty_graph):
    """Missing endpoint returns an empty view, not an exception."""
    result = await endpoint_full_context(
        empty_graph, "endpoint:missing", ["identity:admin"]
    )

    assert isinstance(result, EndpointContextView)
    assert result.endpoint_id == "endpoint:missing"
    assert result.siblings == []
    assert result.test_attempts == []
    assert result.findings == []
    assert result.access_observations == []


@pytest.mark.asyncio
async def test_ignores_unrelated_endpoints(empty_graph):
    """State on other endpoints must not bleed into the view."""
    await _seed_endpoint(empty_graph, "endpoint:5", path="/five")
    await _seed_endpoint(empty_graph, "endpoint:6", path="/six")
    await _seed_param(empty_graph, "parameter:p5", "endpoint:5", name="p5")
    await _seed_param(empty_graph, "parameter:p6", "endpoint:6", name="p6")
    await _seed_attempt(
        empty_graph, "test_attempt:on5", "parameter:p5",
        vuln_type="injection", verdict="conclusive_clean",
    )
    await _seed_attempt(
        empty_graph, "test_attempt:on6", "parameter:p6",
        vuln_type="injection", verdict="conclusive_vulnerable",
    )
    await _seed_finding(
        empty_graph, "finding:on5", "endpoint:5",
        vuln_type="authorization", severity="medium", title="on five",
    )
    await _seed_finding(
        empty_graph, "finding:on6", "endpoint:6",
        vuln_type="authorization", severity="high", title="on six",
    )
    await _seed_identity(empty_graph, "identity:admin", "admin")
    await empty_graph.db.query("RELATE identity:admin->can_access->endpoint:6;")

    result = await endpoint_full_context(
        empty_graph, "endpoint:5", ["identity:admin"]
    )

    assert [s.id for s in result.siblings] == ["parameter:p5"]
    assert [a.id for a in result.test_attempts] == ["test_attempt:on5"]
    assert [f.id for f in result.findings] == ["finding:on5"]
    # admin's can_access edge targets endpoint:6, so no observations for endpoint:5.
    assert result.access_observations == []
