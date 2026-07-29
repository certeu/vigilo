"""Trace-rail mapping — single source of truth for UI phase buckets.

The pipeline emits many fine-grained phase and agent identifiers (see
``src.types.agents.PhaseName`` and ``src.session_manager.AGENT_PHASE_MAP``). The
UI shows a coarser "trace rail" of user-facing steps. This module maps the real
pipeline identifiers onto those steps and is exposed to the frontend via
``GET /pipeline/trace-rail`` so the UI never has to guess names.

Robustness: ``PHASE_TO_STEP`` must cover *every* ``PhaseName``. If a phase is
renamed or added without updating the map, the module-level assertion fails at
import (and in tests) instead of silently mis-bucketing logs. Agent→step is
derived from ``AGENT_PHASE_MAP`` so new agents inherit their phase's step for free.
"""
from __future__ import annotations

import typing

from src.session_manager import AGENT_PHASE_MAP
from src.types.agents import PhaseName
from src.types.stages import PRESET_FULL, PRESET_VULN, PRESET_VULN_PATCH, stages_for_preset

# Ordered canonical rail steps (superset). Presets select a subset, in this order.
STEP_ORDER: list[tuple[str, str]] = [
    ("preflight", "Preflight"),
    ("recon", "Recon"),
    ("vuln", "Vuln + Exploit"),
    ("chain", "Chain"),
    ("critique", "Critique"),
    ("remediation", "Remediation"),
    ("report", "Report"),
]
_STEP_KEYS = {k for k, _ in STEP_ORDER}

# Every real pipeline phase → its rail step. Not 1:1: the early analysis phases
# (pre-recon/recon/sca/integrity) collapse into "Recon", and the pipelined
# vulnerability-analysis + exploitation phases collapse into "Vuln + Exploit".
PHASE_TO_STEP: dict[str, str] = {
    "preflight": "preflight",
    "pre-recon": "recon",
    "recon": "recon",
    "sca": "recon",
    "integrity": "recon",
    "vulnerability-analysis": "vuln",
    "exploitation": "vuln",
    "chain-exploitation": "chain",
    "critique": "critique",
    "remediation": "remediation",
    "reporting": "report",
}

# The workflow also emits a combined marker for the pipelined vuln+exploit phase
# (``[PHASE] Starting: vulnerability-exploitation``) that is not a PhaseName enum
# member. Alias it explicitly.
_PHASE_ALIASES: dict[str, str] = {
    "vulnerability-exploitation": "vuln",
}

# --- Robustness guards: fail loudly rather than silently mis-bucket ----------
_ALL_PHASES = set(typing.get_args(PhaseName))
_unmapped = _ALL_PHASES - set(PHASE_TO_STEP)
assert not _unmapped, f"trace_rail: PhaseName(s) missing from PHASE_TO_STEP: {sorted(_unmapped)}"
_bad_targets = {s for s in PHASE_TO_STEP.values() if s not in _STEP_KEYS}
assert not _bad_targets, f"trace_rail: PHASE_TO_STEP points at unknown steps: {sorted(_bad_targets)}"

# Agent → step, derived from the canonical agent→phase map.
AGENT_TO_STEP: dict[str, str] = {
    agent: PHASE_TO_STEP[phase] for agent, phase in AGENT_PHASE_MAP.items()
}

# Full phase-marker lookup exposed to the UI (real phases + aliases).
PHASE_MARKER_TO_STEP: dict[str, str] = {**PHASE_TO_STEP, **_PHASE_ALIASES}


def _steps_for_preset(preset: str) -> list[str]:
    """Ordered step keys that actually run for a preset (mirrors stages_for_preset)."""
    sel = stages_for_preset(preset)
    keys = ["preflight", "recon", "vuln"]
    if sel.run_chain:
        keys.append("chain")
    keys.append("critique")  # always on (forced)
    if sel.run_remediation:
        keys.append("remediation")
    keys.append("report")
    return keys


PRESET_STEPS: dict[str, list[str]] = {
    p: _steps_for_preset(p) for p in (PRESET_VULN, PRESET_VULN_PATCH, PRESET_FULL)
}


def step_for_marker(identifier: str | None) -> str | None:
    """Map a raw phase-or-agent identifier from a log marker onto a rail step."""
    if not identifier:
        return None
    return PHASE_MARKER_TO_STEP.get(identifier) or AGENT_TO_STEP.get(identifier)


def trace_rail_config() -> dict:
    """The full mapping payload served to the UI."""
    return {
        "steps": [{"key": k, "label": lbl} for k, lbl in STEP_ORDER],
        "presets": PRESET_STEPS,
        "phase_to_step": PHASE_MARKER_TO_STEP,
        "agent_to_step": AGENT_TO_STEP,
    }
