"""Tests for Feature B: scheduler waiting timeout.

When the scheduler emits no verbs but claims are active for
``max_consecutive_waiting_ticks`` consecutive ticks, it should
emit ``Done(reason="waiting_timeout")`` instead of looping forever.
"""
from __future__ import annotations

import pytest

from src.greybox.scheduler.core import ScheduleTickResult, schedule
from src.greybox.scheduler.rules import SchedulerConfig, SchedulerContext
from src.greybox.scheduler.verbs import Done


# ---------------------------------------------------------------------------
# SchedulerConfig defaults
# ---------------------------------------------------------------------------


class TestSchedulerConfigWaitingTimeout:
    def test_default_max_consecutive_waiting_ticks(self):
        config = SchedulerConfig()
        assert config.max_consecutive_waiting_ticks == 10

    def test_custom_max_consecutive_waiting_ticks(self):
        config = SchedulerConfig(max_consecutive_waiting_ticks=5)
        assert config.max_consecutive_waiting_ticks == 5


# ---------------------------------------------------------------------------
# ScheduleTickResult carries the counter
# ---------------------------------------------------------------------------


class TestScheduleTickResultCounter:
    def test_default_consecutive_waiting_ticks(self):
        result = ScheduleTickResult()
        assert result.consecutive_waiting_ticks == 0

    def test_set_consecutive_waiting_ticks(self):
        result = ScheduleTickResult(consecutive_waiting_ticks=3)
        assert result.consecutive_waiting_ticks == 3


# ---------------------------------------------------------------------------
# rule_done does not emit waiting_timeout (that lives in schedule())
# ---------------------------------------------------------------------------


class TestRuleDoneUnchanged:
    def test_rule_done_coverage_complete(self):
        from src.greybox.scheduler.rules import rule_done
        ctx = SchedulerContext(
            leads=[],
            untested_parameters_by_vuln={},
            identities=[],
            endpoints=[],
            access_matrix=_empty_access_matrix(),
            chain_candidates=[],
            budget_remaining_pct=1.0,
            active_claims=[],
        )
        result = rule_done(ctx)
        assert len(result) == 1
        assert result[0].reason == "coverage_complete"

    def test_rule_done_diminishing_returns(self):
        from src.greybox.scheduler.rules import rule_done
        ctx = SchedulerContext(
            leads=[],
            untested_parameters_by_vuln={"injection": [_fake_param("p1")]},
            identities=[],
            endpoints=[],
            access_matrix=_empty_access_matrix(),
            chain_candidates=[],
            budget_remaining_pct=1.0,
            active_claims=[],
            ticks_since_last_progress=20,
            config=SchedulerConfig(idle_ticks_before_done=20),
        )
        result = rule_done(ctx)
        assert len(result) == 1
        assert result[0].reason == "diminishing_returns"


# ---------------------------------------------------------------------------
# schedule() waiting timeout integration
# ---------------------------------------------------------------------------


class TestScheduleWaitingTimeout:
    @pytest.mark.asyncio
    async def test_waiting_timeout_emitted_at_threshold(self):
        """After max_consecutive_waiting_ticks empty-verb ticks with active
        claims, schedule() should emit Done(reason='waiting_timeout')."""
        graph = _StubGraph()
        config = SchedulerConfig(max_consecutive_waiting_ticks=3)
        result = await schedule(
            graph, config,
            active_claims=["parameter:p1"],
            consecutive_waiting_ticks=2,
        )
        assert len(result.verbs) == 1
        assert isinstance(result.verbs[0], Done)
        assert result.verbs[0].reason == "waiting_timeout"

    @pytest.mark.asyncio
    async def test_counter_increments_below_threshold(self):
        """Below the threshold, schedule() returns [] and increments the counter."""
        graph = _StubGraph()
        config = SchedulerConfig(max_consecutive_waiting_ticks=5)
        result = await schedule(
            graph, config,
            active_claims=["parameter:p1"],
            consecutive_waiting_ticks=2,
        )
        assert result.verbs == []
        assert result.consecutive_waiting_ticks == 3

    @pytest.mark.asyncio
    async def test_counter_resets_when_verbs_emitted(self):
        """When real verbs are emitted, the counter resets to 0."""
        graph = _StubGraphWithParams()
        config = SchedulerConfig(max_consecutive_waiting_ticks=5)
        result = await schedule(
            graph, config,
            active_claims=[],
            consecutive_waiting_ticks=4,
        )
        # Should have emitted verbs (or coverage_complete/diminishing_returns)
        assert result.consecutive_waiting_ticks == 0

    @pytest.mark.asyncio
    async def test_disabled_when_zero(self):
        """When max_consecutive_waiting_ticks=0, no waiting timeout fires."""
        graph = _StubGraph()
        config = SchedulerConfig(max_consecutive_waiting_ticks=0)
        result = await schedule(
            graph, config,
            active_claims=["parameter:p1"],
            consecutive_waiting_ticks=100,
        )
        assert result.verbs == []
        assert result.consecutive_waiting_ticks == 101

    @pytest.mark.asyncio
    async def test_budget_exhausted_resets_counter(self):
        """Budget exhausted path returns counter=0."""
        graph = _StubGraph()
        config = SchedulerConfig(
            max_consecutive_waiting_ticks=5,
            budget_cheap_floor_pct=0.03,
        )
        result = await schedule(
            graph, config,
            active_claims=["parameter:p1"],
            budget_remaining_pct=0.01,
            consecutive_waiting_ticks=4,
        )
        assert result.consecutive_waiting_ticks == 0
        assert result.verbs[0].reason == "budget_exhausted"


# ---------------------------------------------------------------------------
# GreyBoxConfig includes max_consecutive_waiting_ticks
# ---------------------------------------------------------------------------


class TestGreyBoxConfigWaitingTimeout:
    def test_default(self):
        from src.greybox.types.config import GreyBoxConfig
        config = GreyBoxConfig()
        assert config.max_consecutive_waiting_ticks == 10

    def test_from_yaml(self, tmp_path):
        from src.greybox.types.config import GreyBoxConfig
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "guardrails:\n  max_consecutive_waiting_ticks: 7\n"
        )
        config = GreyBoxConfig.from_yaml(config_file)
        assert config.max_consecutive_waiting_ticks == 7


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeAccessMatrix:
    can_access: dict = {}
    denied_access: dict = {}


def _empty_access_matrix():
    return _FakeAccessMatrix()


class _FakeParam:
    def __init__(self, id: str):
        self.id = id
        self.endpoint_id = ""
        self.shape = "string"


def _fake_param(id: str):
    return _FakeParam(id)


class _StubGraph:
    """Minimal stub that returns empty results for all graph queries."""

    async def raw_query(self, query: str, params=None):
        if "count()" in query:
            return [{"count": 0}]
        return []


class _StubGraphWithParams:
    """Stub that returns one untested parameter to trigger verb emission."""

    async def raw_query(self, query: str, params=None):
        if "count()" in query:
            if "parameter" in query:
                return [{"count": 1}]
            return [{"count": 0}]
        if "parameter" in query and "SELECT" in query:
            return [{
                "id": "parameter:p1",
                "name": "test_param",
                "shape": "string",
                "endpoint_id": "endpoint:e1",
                "verdict_counts": {},
            }]
        return []
