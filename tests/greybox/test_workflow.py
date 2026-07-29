"""Tests for GreyBoxPipelineWorkflow state management.

These tests do NOT import Temporal or require a running server.
They test workflow state management logic in isolation by directly
instantiating the workflow class and exercising its methods.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Mock all Temporal and heavy third-party dependencies before importing workflows.
#
# The workflow module uses `from temporalio import workflow` which resolves
# `workflow` as `temporalio.workflow`. We must ensure both the module dict
# entry AND the attribute on the parent mock point to the same object.
# ---------------------------------------------------------------------------

# 1. Build workflow mock with passthrough decorators
_workflow_mod = MagicMock()
_workflow_mod.defn = lambda cls=None, **kw: cls if cls else (lambda c: c)
_workflow_mod.run = lambda fn: fn
_workflow_mod.query = lambda fn: fn
_workflow_mod.signal = lambda fn: fn

@contextmanager
def _passthrough():
    yield

_workflow_mod.unsafe.imports_passed_through = _passthrough

# 2. Build the temporalio package mock so `from temporalio import workflow` works
_temporal_mock = MagicMock()
_temporal_mock.workflow = _workflow_mod  # crucial: attribute == submodule

_common_mod = MagicMock()
_common_mod.RetryPolicy = MagicMock
_temporal_mock.common = _common_mod

_exceptions_mod = MagicMock()
_temporal_mock.exceptions = _exceptions_mod

# 3. Activity mock so activities.py @activity.defn is a passthrough
_activity_mod = MagicMock()
_activity_mod.defn = lambda fn=None, **kw: fn if fn else (lambda f: f)
_activity_mod.heartbeat = MagicMock()
_temporal_mock.activity = _activity_mod

# 4. Inject into sys.modules
sys.modules["temporalio"] = _temporal_mock
sys.modules["temporalio.workflow"] = _workflow_mod
sys.modules["temporalio.common"] = _common_mod
sys.modules["temporalio.exceptions"] = _exceptions_mod
sys.modules["temporalio.activity"] = _activity_mod

# 5. Mock aiofiles so activities.py can import
sys.modules.setdefault("aiofiles", MagicMock())

# 6. Now import — the mocked modules prevent real Temporal / aiofiles loading
from src.greybox.temporal.workflows import (  # noqa: E402
    AgentExecutionWorkflow,
    ChildWorkflowInput,
    GreyBoxPipelineWorkflow,
    _KIND_TO_AGENT,
    _SESSION_POOL_SIZE,
    _SESSION_PREFIX,
    _VULN_TO_AGENT,
    AGENT_RETRY,
    DISCOVERY_RETRY,
    PREFLIGHT_RETRY,
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWorkflowClassExists:
    """Verify the workflow classes exist and have required structure."""

    def test_workflow_class_exists(self) -> None:
        assert GreyBoxPipelineWorkflow is not None
        wf = GreyBoxPipelineWorkflow()
        assert hasattr(wf, "run")
        assert hasattr(wf, "get_progress")

    def test_agent_execution_workflow_exists(self) -> None:
        assert AgentExecutionWorkflow is not None
        agent_wf = AgentExecutionWorkflow()
        assert hasattr(agent_wf, "run")


class TestWorkflowInitialState:
    """Verify workflow initializes with correct defaults."""

    def test_workflow_initial_state(self) -> None:
        wf = GreyBoxPipelineWorkflow()

        assert wf.current_phase == "phase_1"
        assert wf.done is False
        assert wf.error is None
        assert wf.tick == 0
        assert wf.total_cost == 0.0
        assert wf.findings == []
        assert wf.completed_agents == []
        assert wf.agent_metrics == {}

    def test_initial_session_pool_size(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        assert len(wf.session_pool) == 8

    def test_initial_session_pool_names(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        expected = {f"{_SESSION_PREFIX}{i}" for i in range(1, _SESSION_POOL_SIZE + 1)}
        assert wf.session_pool == expected

    def test_initial_signal_state(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        assert wf.urgent_signal is False
        assert wf.new_findings_signal is False
        assert wf.replan_requested is False

    def test_initial_tracking_dicts(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        assert wf.agent_costs == {}
        assert wf.vuln_type_counts == {}
        assert wf.agent_target_claims == {}
        assert wf.agent_vuln_buckets == {}
        assert wf.spawn_depth == {}
        assert wf.session_assignments == {}
        assert wf.active_agents == {}


class TestSessionAcquireRelease:
    """Test session pool acquire/release mechanics."""

    def test_session_acquire_release(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        initial_size = len(wf.session_pool)

        session = wf._acquire_session()
        assert session is not None
        assert session.startswith(_SESSION_PREFIX)
        assert len(wf.session_pool) == initial_size - 1

        wf._release_session(session)
        assert len(wf.session_pool) == initial_size
        assert session in wf.session_pool

    def test_session_acquire_multiple(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        sessions = []

        for _ in range(4):
            s = wf._acquire_session()
            assert s is not None
            sessions.append(s)

        assert len(wf.session_pool) == 4
        # All acquired sessions should be unique
        assert len(set(sessions)) == 4

        # Release them all
        for s in sessions:
            wf._release_session(s)
        assert len(wf.session_pool) == 8

    def test_session_pool_exhaustion(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        sessions = []

        # Acquire all 8
        for _ in range(8):
            s = wf._acquire_session()
            assert s is not None
            sessions.append(s)

        assert len(wf.session_pool) == 0

        # Next acquire should return None
        result = wf._acquire_session()
        assert result is None

        # Release one, acquire again
        wf._release_session(sessions[0])
        result = wf._acquire_session()
        assert result is not None
        assert result == sessions[0]


class TestConstants:
    """Verify module-level constants are correct."""

    def test_session_pool_size(self) -> None:
        assert _SESSION_POOL_SIZE == 8

    def test_session_prefix(self) -> None:
        assert _SESSION_PREFIX == "agent"


class TestGetProgress:
    """Test the get_progress query handler returns expected shape."""

    def test_get_progress_shape(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        progress = wf.get_progress()

        assert isinstance(progress, dict)
        assert progress["phase"] == "phase_1"
        assert progress["done"] is False
        assert progress["error"] is None
        assert progress["tick"] == 0
        assert progress["active_agents"] == []
        assert progress["completed_agents"] == []
        assert progress["session_pool_available"] == 8
        assert progress["total_cost"] == 0.0
        assert progress["findings_count"] == 0

    def test_get_progress_after_state_change(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        wf.current_phase = "phase_2"
        wf.tick = 3
        wf.total_cost = 7.5
        wf.findings = [{"id": "A"}, {"id": "B"}]
        wf.completed_agents = ["x"]

        progress = wf.get_progress()
        assert progress["phase"] == "phase_2"
        assert progress["tick"] == 3
        assert progress["total_cost"] == 7.5
        assert progress["findings_count"] == 2
        assert progress["completed_agents"] == ["x"]


class TestPhase3SchedulerLoop:
    """Tests for Phase 3 reactive loop — scheduler-driven."""

    def test_kind_to_agent_mapping(self) -> None:
        assert _KIND_TO_AGENT["INVESTIGATE_LEAD"] == "lead-investigator"
        assert _KIND_TO_AGENT["TEST_ACCESS_MATRIX"] == "authorization-specialist"
        assert _KIND_TO_AGENT["ATTEMPT_CHAIN"] == "chain-exploit"

    def test_vuln_to_agent_mapping(self) -> None:
        assert _VULN_TO_AGENT["injection"] == "injection-specialist"
        assert _VULN_TO_AGENT["reflection"] == "reflection-specialist"
        assert _VULN_TO_AGENT["ssrf"] == "ssrf-specialist"
        assert _VULN_TO_AGENT["authorization"] == "authorization-specialist"

    def test_verb_to_target_probe_parameters(self) -> None:
        target = GreyBoxPipelineWorkflow._verb_to_target({
            "kind": "PROBE_PARAMETERS",
            "vuln_type": "injection",
            "identity": "identity:anonymous",
            "param_ids": ["parameter:a", "parameter:b"],
        })
        assert target["mode"] == "batch"
        assert target["vuln_type"] == "injection"
        assert target["param_ids"] == ["parameter:a", "parameter:b"]

    def test_verb_to_target_lead(self) -> None:
        target = GreyBoxPipelineWorkflow._verb_to_target({
            "kind": "INVESTIGATE_LEAD",
            "lead_id": "lead:xyz",
            "identity": "identity:admin",
        })
        assert target["mode"] == "lead"
        assert target["lead_id"] == "lead:xyz"
        assert target["identity"] == "identity:admin"

    def test_verb_to_target_access_matrix(self) -> None:
        target = GreyBoxPipelineWorkflow._verb_to_target({
            "kind": "TEST_ACCESS_MATRIX",
            "endpoint_ids": ["endpoint:a"],
            "identities": ["identity:admin", "identity:user"],
        })
        assert target["endpoint_ids"] == ["endpoint:a"]
        assert len(target["identities"]) == 2

    def test_verb_to_target_attempt_chain(self) -> None:
        target = GreyBoxPipelineWorkflow._verb_to_target({
            "kind": "ATTEMPT_CHAIN",
            "finding_ids": ["finding:1", "finding:2"],
            "chain_candidates": [{"pattern_name": "Auth -> SSRF"}],
            "chain_context": "Candidate chain context",
        })
        assert target["finding_ids"] == ["finding:1", "finding:2"]
        assert target["chain_candidates"] == [{"pattern_name": "Auth -> SSRF"}]
        assert target["chain_context"] == "Candidate chain context"

    def test_target_claim_ids_tracks_graph_targets(self) -> None:
        assert GreyBoxPipelineWorkflow._target_claim_ids({
            "mode": "batch",
            "param_ids": ["parameter:a", "parameter:b"],
        }) == {"parameter:a", "parameter:b"}
        assert GreyBoxPipelineWorkflow._target_claim_ids({
            "lead_id": "lead:l1",
            "endpoint_ids": ["endpoint:e1"],
        }) == {"lead:l1", "endpoint:e1"}

    def test_clear_active_agent_tracking_decrements_active_vuln_count(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        wf.vuln_type_counts["reflection"] = 2
        wf.agent_vuln_buckets["agent-1"] = "reflection"
        wf.agent_target_claims["agent-1"] = {"parameter:p1"}

        wf._clear_active_agent_tracking("agent-1")

        assert wf.vuln_type_counts["reflection"] == 1
        assert "agent-1" not in wf.agent_vuln_buckets
        assert "agent-1" not in wf.agent_target_claims

    def test_active_claim_ids_flattens_agent_claims(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        wf.agent_target_claims = {
            "a": {"parameter:p2", "lead:l1"},
            "b": {"parameter:p1"},
        }
        assert wf._active_claim_ids() == ["lead:l1", "parameter:p1", "parameter:p2"]

    @pytest.mark.asyncio
    async def test_reactive_loop_exits_on_done_verb(self) -> None:
        """DONE verb from scheduler ends Phase 3 immediately."""
        import src.greybox.temporal.workflows as wf_mod
        from src.greybox.types.config import GreyBoxConfig

        wf = GreyBoxPipelineWorkflow()

        # Mock execute_activity to return a DONE verb
        async def fake_execute_activity(activity, *args, **kwargs):
            fn_name = getattr(activity, "__name__", "")
            if fn_name == "schedule_tick_activity":
                return [{"kind": "DONE", "reason": "coverage_complete"}]
            return {}

        wf_mod.workflow.execute_activity = fake_execute_activity

        # Use a freezable start_time; workflow.now() returns MagicMock so
        # we patch it to produce a deterministic, small elapsed duration.
        from datetime import datetime, timedelta as _td
        t0 = datetime(2026, 1, 1)
        call_count = {"n": 0}

        def fake_now():
            call_count["n"] += 1
            return t0 + _td(seconds=call_count["n"])

        wf_mod.workflow.now = fake_now
        wf_mod.workflow.logger = MagicMock()

        base_input = MagicMock()
        base_input.output_path = "/tmp/test"
        base_input.session_id = "s1"
        base_input.web_url = "http://test"
        base_input.description = ""
        base_input.rules_avoid = []
        base_input.rules_focus = []
        base_input.credentials_path = "/tmp/c"

        config = GreyBoxConfig()
        config.per_scan_cost_ceiling = 10.0
        config.max_duration_hours = 24.0

        # Should exit on DONE without looping
        await wf.phase_2_reactive_loop(base_input, config, t0)

        # Exactly one tick — then DONE branched out
        assert wf.tick == 1

    @pytest.mark.asyncio
    async def test_reactive_loop_dispatches_verb(self) -> None:
        """Non-DONE verbs lead to specialist dispatch."""
        import src.greybox.temporal.workflows as wf_mod
        from src.greybox.types.config import GreyBoxConfig

        wf = GreyBoxPipelineWorkflow()

        # Track dispatched agents via the helper
        dispatched: list[dict[str, Any]] = []

        async def fake_spawn(verb, base_input, config, tick):
            dispatched.append(verb)

        wf._spawn_specialist_from_verb = fake_spawn  # type: ignore[assignment]

        tick_calls = {"n": 0}

        async def fake_execute_activity(activity, *args, **kwargs):
            fn_name = getattr(activity, "__name__", "")
            if fn_name == "schedule_tick_activity":
                tick_calls["n"] += 1
                if tick_calls["n"] == 1:
                    return [
                        {"kind": "PROBE_PARAMETERS", "vuln_type": "xss",
                         "param_ids": ["p1"], "identity": "identity:anonymous"},
                    ]
                # Second tick: DONE so loop exits
                return [{"kind": "DONE", "reason": "done"}]
            return {}

        async def fake_wait_condition(*args, **kwargs):
            return None

        wf_mod.workflow.execute_activity = fake_execute_activity
        wf_mod.workflow.wait_condition = fake_wait_condition
        wf_mod.workflow.logger = MagicMock()

        from datetime import datetime, timedelta as _td
        t0 = datetime(2026, 1, 1)
        counter = {"n": 0}

        def fake_now():
            counter["n"] += 1
            return t0 + _td(seconds=counter["n"])

        wf_mod.workflow.now = fake_now

        base_input = MagicMock()
        base_input.output_path = "/tmp/test"
        base_input.session_id = "s1"
        base_input.web_url = "http://test"
        base_input.description = ""
        base_input.rules_avoid = []
        base_input.rules_focus = []
        base_input.credentials_path = "/tmp/c"

        config = GreyBoxConfig()
        config.per_scan_cost_ceiling = 10.0
        config.max_duration_hours = 24.0

        await wf.phase_2_reactive_loop(base_input, config, t0)

        assert len(dispatched) == 1
        assert dispatched[0]["kind"] == "PROBE_PARAMETERS"
        assert dispatched[0]["vuln_type"] == "xss"


class TestChildWorkflowInputBookkeeping:
    """ChildWorkflowInput carries bookkeeping fields."""

    def test_lead_max_attempts_field_exists(self) -> None:
        inp = ChildWorkflowInput(
            agent_id="test-001",
            agent_type="injection",
            action_type="INVESTIGATE_LEAD",
            session="agent1",
            web_url="http://target",
            session_id="gb-test",
            credentials_path="/creds.yaml",
            output_path="/out",
        )
        assert inp.lead_max_attempts == 3

    def test_lead_max_attempts_custom_value(self) -> None:
        inp = ChildWorkflowInput(
            agent_id="test-001",
            agent_type="injection",
            action_type="INVESTIGATE_LEAD",
            session="agent1",
            web_url="http://target",
            session_id="gb-test",
            credentials_path="/creds.yaml",
            output_path="/out",
            lead_max_attempts=5,
        )
        assert inp.lead_max_attempts == 5


class TestRetryPolicyCaps:
    """Verify retry policies have reasonable caps for LLM activities."""

    def test_agent_retry_max_attempts(self) -> None:
        assert AGENT_RETRY.maximum_attempts <= 3

    def test_agent_retry_initial_interval(self) -> None:
        from datetime import timedelta
        assert AGENT_RETRY.initial_interval <= timedelta(minutes=2)

    def test_agent_retry_maximum_interval(self) -> None:
        from datetime import timedelta
        assert AGENT_RETRY.maximum_interval <= timedelta(minutes=5)
