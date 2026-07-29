"""Trace-rail phase/agent → step mapping (src/webapi/trace_rail.py)."""
import typing

import pytest

from src.session_manager import AGENT_PHASE_MAP
from src.types.agents import PhaseName
from src.webapi import trace_rail


class TestTraceRailMapping:
    def test_every_pipeline_phase_is_mapped(self):
        # The robustness guard: adding/renaming a PhaseName without mapping it must
        # not silently mis-bucket logs. Every enum member has a step.
        for phase in typing.get_args(PhaseName):
            assert phase in trace_rail.PHASE_TO_STEP, f"unmapped phase: {phase}"
            assert trace_rail.PHASE_TO_STEP[phase] in {k for k, _ in trace_rail.STEP_ORDER}

    def test_every_agent_maps_to_a_step(self):
        for agent in AGENT_PHASE_MAP:
            assert trace_rail.step_for_marker(agent) is not None, agent

    @pytest.mark.parametrize("identifier,expected", [
        # early analysis phases collapse into Recon
        ("pre-recon", "recon"),
        ("recon", "recon"),
        ("sca", "recon"),
        ("integrity", "recon"),
        # vuln + exploit (incl. the combined workflow marker) collapse into Vuln
        ("vulnerability-analysis", "vuln"),
        ("exploitation", "vuln"),
        ("vulnerability-exploitation", "vuln"),
        ("injection-vuln", "vuln"),
        ("injection-exploit", "vuln"),
        # previously mis-bucketed by substring matching:
        ("chain-exploitation", "chain"),   # used to match "exploit" -> vuln
        ("report-critic", "critique"),     # used to match "report" -> report
        ("critique", "critique"),
        ("reporting", "report"),
        ("report", "report"),
        ("remediation", "remediation"),
        ("preflight", "preflight"),
    ])
    def test_specific_markers(self, identifier, expected):
        assert trace_rail.step_for_marker(identifier) == expected

    def test_unknown_marker_returns_none(self):
        assert trace_rail.step_for_marker("totally-made-up") is None
        assert trace_rail.step_for_marker(None) is None

    def test_preset_steps_reflect_stage_selection(self):
        assert trace_rail.PRESET_STEPS["vuln"] == ["preflight", "recon", "vuln", "critique", "report"]
        assert trace_rail.PRESET_STEPS["vuln_patch"] == ["preflight", "recon", "vuln", "critique", "remediation", "report"]
        assert trace_rail.PRESET_STEPS["full"] == ["preflight", "recon", "vuln", "chain", "critique", "remediation", "report"]


class TestTraceRailEndpoint:
    async def test_endpoint_returns_config(self, client, user_token):
        r = await client.get("/pipeline/trace-rail", headers={"Authorization": f"Bearer {user_token}"})
        assert r.status_code == 200
        cfg = r.json()
        assert {"steps", "presets", "phase_to_step", "agent_to_step"} <= cfg.keys()
        assert cfg["phase_to_step"]["chain-exploitation"] == "chain"
        assert cfg["agent_to_step"]["report-critic"] == "critique"
