"""Tests for the scheduler core ``schedule()`` orchestration."""
from __future__ import annotations

import json

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL
from src.greybox.scheduler.core import _apply_caps, schedule
from src.greybox.scheduler.rules import SchedulerConfig
from src.greybox.scheduler.verbs import (
    AttemptChain,
    Done,
    InvestigateLead,
    ProbeParameters,
    TestAccessMatrix,
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
        await db.use("vigilo", "test_sched_empty")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)
        yield _InMemoryGraph(db)


async def _seed_params(
    graph: _InMemoryGraph,
    count: int,
    vuln_type: str,
    shape: str = "numeric_id",
) -> None:
    # The vuln_type arg is informational — the actual routing happens via
    # shape affinity. We just need params of the right shape.
    await graph.db.query(
        """
        CREATE endpoint:seed_ep SET method = 'GET', path = '/x',
            full_url = 'http://t/x', discovered_by = 'test',
            discovered_at = time::now(), rate_limited = false,
            requires_auth = false, status_codes_seen = [200];
        """
    )
    for i in range(count):
        pid = f"parameter:sd{i}"
        await graph.db.query(
            f"""
            CREATE {pid} SET name = 'p{i}', location = 'query',
                data_type = 'int', shape = $shape,
                discovered_by = 'test', discovered_at = time::now();
            RELATE endpoint:seed_ep->has_param->{pid};
            """,
            {"shape": shape},
        )


async def _seed_high_lead(graph: _InMemoryGraph, lead_id: str = "lead:hi") -> None:
    await graph.db.query(
        f"""
        CREATE {lead_id} SET signal = 'reflection',
            hypothesis = 'blind SQLi', signal_strength = 'high',
            investigation_hints = [], status = 'open',
            investigation_attempts = 0, max_attempts = 3,
            discovered_by = 'test', discovered_at = time::now();
        """
    )


async def _seed_authz_diff(graph: _InMemoryGraph) -> None:
    await graph.db.query(
        """
        CREATE identity:anonymous SET role = 'anonymous', privilege_level = 0,
            auth_method = 'session_cookie', credential_ref = 'anon',
            session_active = true, discovered_by = 'test', discovered_at = time::now();
        CREATE identity:user SET role = 'user', privilege_level = 1,
            auth_method = 'session_cookie', credential_ref = 'user',
            session_active = true, discovered_by = 'test', discovered_at = time::now();
        CREATE endpoint:authz_a SET method = 'GET', path = '/admin',
            full_url = 'http://t/admin', discovered_by = 'test',
            discovered_at = time::now(), rate_limited = false,
            requires_auth = true, status_codes_seen = [200, 403];
        CREATE endpoint:authz_b SET method = 'GET', path = '/billing',
            full_url = 'http://t/billing', discovered_by = 'test',
            discovered_at = time::now(), rate_limited = false,
            requires_auth = true, status_codes_seen = [200, 403];
        RELATE identity:user->can_access->endpoint:authz_a;
        RELATE identity:anonymous->denied_access->endpoint:authz_a;
        RELATE identity:anonymous->can_access->endpoint:authz_b;
        RELATE identity:user->denied_access->endpoint:authz_b;
        """
    )


@pytest.mark.asyncio
async def test_schedule_emits_done_on_empty_graph(empty_graph):
    result = await schedule(empty_graph, SchedulerConfig(), active_claims=[])
    verbs = result.verbs
    assert len(verbs) == 1
    assert verbs[0].kind == "DONE"
    assert verbs[0].reason == "coverage_complete"


@pytest.mark.asyncio
async def test_schedule_emits_done_on_low_budget(graph_fixture):
    # Below the floor (default 0.03) → exhausted mode → DONE.
    result = await schedule(
        graph_fixture,
        SchedulerConfig(),
        active_claims=[],
        budget_remaining_pct=0.01,
    )
    verbs = result.verbs
    assert len(verbs) == 1
    assert verbs[0].kind == "DONE"
    assert verbs[0].reason == "budget_exhausted"


@pytest.mark.asyncio
async def test_schedule_respects_active_claims(graph_fixture):
    result = await schedule(
        graph_fixture,
        SchedulerConfig(),
        active_claims=["parameter:p1"],
    )
    probe_verbs = [v for v in result.verbs if v.kind == "PROBE_PARAMETERS"]
    for verb in probe_verbs:
        assert "parameter:p1" not in verb.param_ids


@pytest.mark.asyncio
async def test_schedule_respects_active_claims_for_leads(graph_fixture):
    result = await schedule(
        graph_fixture,
        SchedulerConfig(),
        active_claims=["lead:l1"],
    )
    assert all(
        not (verb.kind == "INVESTIGATE_LEAD" and verb.lead_id == "lead:l1")
        for verb in result.verbs
    )


@pytest.mark.asyncio
async def test_schedule_orders_high_before_medium(graph_fixture):
    # graph_fixture already has a high-strength lead (lead:l1) plus
    # medium-priority untested params.
    result = await schedule(graph_fixture, SchedulerConfig(), active_claims=[])
    verbs = result.verbs
    assert len(verbs) >= 1
    assert verbs[0].kind == "INVESTIGATE_LEAD"
    assert verbs[0].priority == "high"


@pytest.mark.asyncio
async def test_schedule_caps_per_type(empty_graph):
    # 5 batches of 15 params each = 75 injection params, producing 5 verbs
    # before the cap. With per_type_cap=2, only 2 should remain.
    await _seed_params(empty_graph, count=75, vuln_type="injection", shape="numeric_id")
    config = SchedulerConfig(batch_size=15, per_type_cap=2)
    result = await schedule(empty_graph, config, active_claims=[])
    injection_probes = [
        v for v in result.verbs
        if v.kind == "PROBE_PARAMETERS" and v.vuln_type == "injection"
    ]
    assert len(injection_probes) <= 2


@pytest.mark.asyncio
async def test_schedule_caps_specialists_per_endpoint(empty_graph):
    # An endpoint with a free_text parameter attracts 3 specialists uncapped
    # (reflection, injection, ssrf). With the default cap of 2, only the top
    # two by _SPECIALIST_PRIORITY (injection, reflection) receive a
    # PROBE_PARAMETERS verb for this endpoint's params.
    await _seed_params(empty_graph, count=1, vuln_type="any", shape="free_text")
    config = SchedulerConfig(max_specialists_per_endpoint=2)
    result = await schedule(empty_graph, config, active_claims=[])
    dispatched_vuln_types = {
        v.vuln_type for v in result.verbs if v.kind == "PROBE_PARAMETERS"
    }
    assert dispatched_vuln_types == {"injection", "reflection"}


@pytest.mark.asyncio
async def test_schedule_returns_only_done_when_rule_done_fires(empty_graph):
    await _seed_params(empty_graph, count=3, vuln_type="injection", shape="numeric_id")
    # Below the floor (default 0.03) → exhausted → DONE short-circuits
    # even when there is still untested work in the graph.
    result = await schedule(
        empty_graph,
        SchedulerConfig(),
        active_claims=[],
        budget_remaining_pct=0.01,
    )
    verbs = result.verbs
    assert len(verbs) == 1
    assert verbs[0].kind == "DONE"
    assert verbs[0].reason == "budget_exhausted"


@pytest.mark.asyncio
async def test_tick_log_persisted(tmp_path, graph_fixture):
    config = SchedulerConfig(tick_log_dir=tmp_path)
    await schedule(
        graph_fixture,
        config,
        active_claims=["parameter:p42"],
        tick_number=7,
    )
    path = tmp_path / "tick-007.json"
    assert path.exists()
    body = json.loads(path.read_text())
    assert body["tick"] == 7
    expected_keys = {
        "tick", "timestamp", "graph_counts", "verdict_counts",
        "ticks_since_last_progress", "budget_mode",
        "emitted_verbs", "active_claims", "halt_hint",
    }
    assert set(body.keys()) == expected_keys
    assert body["active_claims"] == ["parameter:p42"]
    assert body["budget_mode"] in {"normal", "cheap-only", "exhausted"}


@pytest.mark.asyncio
async def test_tick_log_halt_hint_populated_when_done(empty_graph, tmp_path):
    config = SchedulerConfig(tick_log_dir=tmp_path)
    await schedule(empty_graph, config, active_claims=[], tick_number=1)
    body = json.loads((tmp_path / "tick-001.json").read_text())
    assert body["halt_hint"] == "coverage_complete"


@pytest.mark.asyncio
async def test_tick_log_skipped_when_dir_unset(graph_fixture, tmp_path):
    await schedule(graph_fixture, SchedulerConfig(), active_claims=[], tick_number=1)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_schedule_emits_authz_only_for_differential_endpoints(empty_graph):
    await _seed_authz_diff(empty_graph)
    result = await schedule(
        empty_graph,
        SchedulerConfig(batch_size=1),
        active_claims=[],
    )
    authz_verbs = [v for v in result.verbs if v.kind == "TEST_ACCESS_MATRIX"]
    assert len(authz_verbs) == 2
    assert {tuple(v.endpoint_ids) for v in authz_verbs} == {
        ("endpoint:authz_a",),
        ("endpoint:authz_b",),
    }


@pytest.mark.asyncio
async def test_schedule_skips_claimed_authz_endpoint(empty_graph):
    await _seed_authz_diff(empty_graph)
    result = await schedule(
        empty_graph,
        SchedulerConfig(),
        active_claims=["endpoint:authz_a"],
    )
    authz_verbs = [v for v in result.verbs if v.kind == "TEST_ACCESS_MATRIX"]
    assert len(authz_verbs) == 1
    assert authz_verbs[0].endpoint_ids == ["endpoint:authz_b"]


# --- _apply_caps unit tests (Slice 6 / C5) -----------------------------------
#
# Caps are applied after rules emit and after priority sorting, so the input
# order reflects priority (high before low). The expectation is that the first
# N verbs of each kind survive — i.e., high-priority wins when truncated.


def _probe(i: int, priority: str = "medium") -> ProbeParameters:
    return ProbeParameters(
        vuln_type="injection",
        param_ids=[f"parameter:p{i}"],
        identity="identity:anonymous",
        priority=priority,
    )


def _investigate(i: int, priority: str = "high") -> InvestigateLead:
    return InvestigateLead(lead_id=f"lead:l{i}", priority=priority)


def _authz(i: int, priority: str = "medium") -> TestAccessMatrix:
    return TestAccessMatrix(
        endpoint_ids=[f"endpoint:e{i}"],
        identities=["identity:a", "identity:b"],
        priority=priority,
    )


def _chain(i: int, priority: str = "high") -> AttemptChain:
    return AttemptChain(finding_ids=[f"finding:f{i}"], priority=priority)


def test_per_type_cap_bounds_probe():
    verbs = [_probe(i) for i in range(10)]
    out = _apply_caps(verbs, SchedulerConfig(per_type_cap=3))
    kept = [v for v in out if v.kind == "PROBE_PARAMETERS"]
    assert len(kept) == 3
    # priority order preserved — first 3 of input survive
    assert [v.param_ids for v in kept] == [["parameter:p0"], ["parameter:p1"], ["parameter:p2"]]


def test_per_type_cap_bounds_investigate():
    verbs = [_investigate(i) for i in range(10)]
    out = _apply_caps(verbs, SchedulerConfig(per_type_cap=3))
    kept = [v for v in out if v.kind == "INVESTIGATE_LEAD"]
    assert len(kept) == 3
    assert [v.lead_id for v in kept] == ["lead:l0", "lead:l1", "lead:l2"]




def test_authz_cap_independent():
    # authz_per_tick_cap is independent of per_type_cap — setting per_type_cap
    # very high does not lift the authz cap.
    verbs = [_authz(i) for i in range(10)]
    out = _apply_caps(
        verbs,
        SchedulerConfig(per_type_cap=100, authz_per_tick_cap=2),
    )
    kept = [v for v in out if v.kind == "TEST_ACCESS_MATRIX"]
    assert len(kept) == 2
    assert [v.endpoint_ids for v in kept] == [["endpoint:e0"], ["endpoint:e1"]]


def test_chain_cap_independent():
    verbs = [_chain(i) for i in range(10)]
    out = _apply_caps(
        verbs,
        SchedulerConfig(per_type_cap=100, chain_per_tick_cap=1),
    )
    kept = [v for v in out if v.kind == "ATTEMPT_CHAIN"]
    assert len(kept) == 1
    assert kept[0].finding_ids == ["finding:f0"]


def test_done_not_capped():
    # [DONE] passes through untouched, even with caps that would otherwise
    # truncate. (DONE is emitted solo by schedule(), but _apply_caps must not
    # drop it if it ever sees one.)
    done = Done(reason="coverage_complete")
    out = _apply_caps(
        [done],
        SchedulerConfig(per_type_cap=0, authz_per_tick_cap=0, chain_per_tick_cap=0),
    )
    assert out == [done]


def test_mixed_verbs_respect_caps():
    # 5 PROBE + 5 AUTHZ + 3 CHAIN → caps 3 / 2 / 1 → 6 total.
    verbs: list = (
        [_probe(i) for i in range(5)]
        + [_authz(i) for i in range(5)]
        + [_chain(i) for i in range(3)]
    )
    out = _apply_caps(
        verbs,
        SchedulerConfig(per_type_cap=3, authz_per_tick_cap=2, chain_per_tick_cap=1),
    )
    assert len(out) == 6
    by_kind = {"PROBE_PARAMETERS": 0, "TEST_ACCESS_MATRIX": 0, "ATTEMPT_CHAIN": 0}
    for v in out:
        by_kind[v.kind] += 1
    assert by_kind == {"PROBE_PARAMETERS": 3, "TEST_ACCESS_MATRIX": 2, "ATTEMPT_CHAIN": 1}


def test_unknown_kind_passes_through():
    # Defensive: a hypothetical verb kind not in CAP_FOR_KIND should not crash
    # _apply_caps or be silently dropped. Simulate via a Done-like object since
    # Done is the only non-capped kind in the real schema.
    done = Done(reason="diminishing_returns")
    verbs = [done, _probe(0), done, _probe(1), done]
    out = _apply_caps(
        verbs,
        SchedulerConfig(per_type_cap=1, authz_per_tick_cap=1, chain_per_tick_cap=1),
    )
    # All three DONEs pass through; PROBE is capped to 1.
    assert sum(1 for v in out if v.kind == "DONE") == 3
    assert sum(1 for v in out if v.kind == "PROBE_PARAMETERS") == 1
