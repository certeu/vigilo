"""Tests for the C1 three-tier budget mode classifier and filter (Slice 10).

``classify_budget_mode(remaining, ceiling, floor)`` maps remaining-budget
fractions to one of three modes:

- ``remaining > ceiling``                  → ``"normal"``
- ``floor <= remaining <= ceiling``        → ``"cheap-only"``
- ``remaining < floor``                    → ``"exhausted"``

Boundary semantics match the plan's [0.50, 0.10, 0.05, 0.02] ladder →
["normal", "cheap-only", "cheap-only", "exhausted"]: exactly at the
ceiling is already cheap-only, exactly at the floor is still cheap-only,
strictly below the floor is exhausted.

``schedule()`` consumes the classified mode:
- ``normal``     → full verb set emitted.
- ``cheap-only`` → ``PROBE_PARAMETERS`` and ``ATTEMPT_CHAIN`` are filtered
  out; ``INVESTIGATE_LEAD`` and ``TEST_ACCESS_MATRIX`` pass.
- ``exhausted``  → short-circuit to ``[Done(reason="budget_exhausted")]``.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL
from src.greybox.scheduler.core import classify_budget_mode, schedule
from src.greybox.scheduler.rules import SchedulerConfig


# ---------------------------------------------------------------------------
# Pure-function classifier tests (Task 10.2)
# ---------------------------------------------------------------------------


def test_classify_normal_when_well_above_ceiling():
    assert classify_budget_mode(0.50, ceiling=0.10, floor=0.03) == "normal"


def test_classify_normal_just_above_ceiling():
    assert classify_budget_mode(0.11, ceiling=0.10, floor=0.03) == "normal"


def test_classify_cheap_only_at_ceiling_boundary():
    # [0.50, 0.10, 0.05, 0.02] → second entry must be cheap-only.
    assert classify_budget_mode(0.10, ceiling=0.10, floor=0.03) == "cheap-only"


def test_classify_cheap_only_between_floor_and_ceiling():
    assert classify_budget_mode(0.05, ceiling=0.10, floor=0.03) == "cheap-only"


def test_classify_cheap_only_at_floor_boundary():
    # Exactly at floor is still cheap-only; exhausted is strictly below.
    assert classify_budget_mode(0.03, ceiling=0.10, floor=0.03) == "cheap-only"


def test_classify_exhausted_below_floor():
    assert classify_budget_mode(0.02, ceiling=0.10, floor=0.03) == "exhausted"


def test_classify_exhausted_at_zero():
    assert classify_budget_mode(0.0, ceiling=0.10, floor=0.03) == "exhausted"


def test_classify_plan_ladder():
    """The plan's explicit [0.50, 0.10, 0.05, 0.02] → ladder of modes."""
    ladder = [0.50, 0.10, 0.05, 0.02]
    modes = [classify_budget_mode(r, ceiling=0.10, floor=0.03) for r in ladder]
    assert modes == ["normal", "cheap-only", "cheap-only", "exhausted"]


# ---------------------------------------------------------------------------
# schedule() integration tests (Task 10.3)
# ---------------------------------------------------------------------------


class _InMemoryGraph:
    def __init__(self, db: AsyncSurreal) -> None:
        self.db = db

    async def raw_query(self, query, params=None):
        result = await self.db.query(query, params or {})
        return result or []


@pytest_asyncio.fixture
async def populated_graph():
    """Graph seeded with content that exercises the expensive + cheap verbs.

    - one numeric_id parameter on an endpoint → PROBE_PARAMETERS (expensive)
    - two identities + one endpoint with allow/deny → TEST_ACCESS_MATRIX (cheap)
    - one open medium-strength lead → INVESTIGATE_LEAD (cheap)
    """
    db = AsyncSurreal("mem://")
    async with db:
        await db.use("vigilo", "test_budget_mode")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)
        await db.query(
            """
            CREATE identity:anonymous SET role = 'anonymous', privilege_level = 0,
                auth_method = 'session_cookie', credential_ref = 'anon',
                session_active = true, discovered_by = 'seed',
                discovered_at = time::now();
            CREATE identity:user SET role = 'user', privilege_level = 1,
                auth_method = 'session_cookie', credential_ref = 'user',
                session_active = true, discovered_by = 'seed',
                discovered_at = time::now();
            CREATE endpoint:e1 SET method = 'GET', path = '/api/a',
                full_url = 'http://t/api/a', discovered_by = 'seed',
                discovered_at = time::now(), rate_limited = false,
                requires_auth = true, status_codes_seen = [200, 403];
            CREATE parameter:p1 SET name = 'q', location = 'query',
                data_type = 'int', shape = 'numeric_id',
                discovered_by = 'seed', discovered_at = time::now();
            RELATE endpoint:e1->has_param->parameter:p1;
            CREATE lead:l1 SET signal = 'response_code_anomaly',
                hypothesis = 'h', signal_strength = 'medium',
                investigation_hints = [], status = 'open',
                investigation_attempts = 0, max_attempts = 3,
                discovered_by = 'seed', discovered_at = time::now();
            RELATE identity:user->can_access->endpoint:e1;
            RELATE identity:anonymous->denied_access->endpoint:e1;
            """
        )
        yield _InMemoryGraph(db)


@pytest.mark.asyncio
async def test_schedule_normal_mode_preserves_probe_parameters(populated_graph):
    """With budget > ceiling, PROBE_PARAMETERS survives (normal mode)."""
    result = await schedule(
        populated_graph,
        SchedulerConfig(),
        active_claims=[],
        budget_remaining_pct=0.50,
    )
    kinds = {v.kind for v in result.verbs}
    assert result.budget_mode == "normal"
    assert "PROBE_PARAMETERS" in kinds
    assert "DONE" not in kinds


@pytest.mark.asyncio
async def test_schedule_cheap_only_strips_probe_parameters(populated_graph):
    """In cheap-only mode, PROBE_PARAMETERS is filtered out."""
    result = await schedule(
        populated_graph,
        SchedulerConfig(),
        active_claims=[],
        budget_remaining_pct=0.05,  # between floor 0.03 and ceiling 0.10
    )
    kinds = {v.kind for v in result.verbs}
    assert result.budget_mode == "cheap-only"
    assert "PROBE_PARAMETERS" not in kinds
    assert "ATTEMPT_CHAIN" not in kinds
    # Cheap verbs still flow.
    assert kinds & {"INVESTIGATE_LEAD", "TEST_ACCESS_MATRIX"}


@pytest.mark.asyncio
async def test_schedule_exhausted_short_circuits_to_done(populated_graph):
    """In exhausted mode, emit [Done(reason='budget_exhausted')] only."""
    result = await schedule(
        populated_graph,
        SchedulerConfig(),
        active_claims=[],
        budget_remaining_pct=0.01,  # below floor 0.03
    )
    assert result.budget_mode == "exhausted"
    assert len(result.verbs) == 1
    assert result.verbs[0].kind == "DONE"
    assert result.verbs[0].reason == "budget_exhausted"


@pytest.mark.asyncio
async def test_schedule_exhausted_wins_over_active_claims(populated_graph):
    """Budget is a hard stop — active claims do not defer the DONE."""
    result = await schedule(
        populated_graph,
        SchedulerConfig(),
        active_claims=["parameter:inflight"],
        budget_remaining_pct=0.01,
    )
    assert result.budget_mode == "exhausted"
    assert len(result.verbs) == 1
    assert result.verbs[0].kind == "DONE"
    assert result.verbs[0].reason == "budget_exhausted"


@pytest.mark.asyncio
async def test_schedule_cheap_only_with_active_claims(populated_graph):
    """In cheap-only mode, the filter applies regardless of active claims."""
    result = await schedule(
        populated_graph,
        SchedulerConfig(),
        active_claims=["parameter:other"],
        budget_remaining_pct=0.05,
    )
    assert result.budget_mode == "cheap-only"
    kinds = {v.kind for v in result.verbs}
    assert "PROBE_PARAMETERS" not in kinds
    assert "ATTEMPT_CHAIN" not in kinds


@pytest.mark.asyncio
async def test_schedule_budget_mode_uses_configured_thresholds(populated_graph):
    """Thresholds come from SchedulerConfig, not hard-coded 0.10/0.03."""
    # With ceiling=0.50, a 0.40 remaining-budget lands in cheap-only.
    result = await schedule(
        populated_graph,
        SchedulerConfig(budget_cheap_ceiling_pct=0.50, budget_cheap_floor_pct=0.20),
        active_claims=[],
        budget_remaining_pct=0.40,
    )
    assert result.budget_mode == "cheap-only"


@pytest.mark.asyncio
async def test_schedule_tick_result_exposes_budget_mode(populated_graph):
    """ScheduleTickResult carries the classified mode string."""
    result = await schedule(
        populated_graph,
        SchedulerConfig(),
        active_claims=[],
        budget_remaining_pct=0.50,
    )
    assert result.budget_mode in {"normal", "cheap-only", "exhausted"}
