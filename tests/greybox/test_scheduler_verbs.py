"""Tests for grey-box scheduler Verb types."""
from __future__ import annotations

from src.greybox.scheduler.verbs import (
    ProbeParameters, TestAccessMatrix, InvestigateLead,
    AttemptChain, Done, Verb,
)


def test_probe_parameters_has_required_fields():
    v = ProbeParameters(
        vuln_type="reflection",
        param_ids=["parameter:p1", "parameter:p2"],
        identity="identity:anonymous",
        priority="high",
    )
    assert v.kind == "PROBE_PARAMETERS"
    assert v.param_ids == ["parameter:p1", "parameter:p2"]


def test_verb_is_union_of_five():
    allowed = {"PROBE_PARAMETERS", "TEST_ACCESS_MATRIX", "INVESTIGATE_LEAD",
               "ATTEMPT_CHAIN", "DONE"}
    # Verb is a tagged union — build each and verify .kind
    from src.greybox.scheduler.verbs import VERB_REGISTRY
    assert set(VERB_REGISTRY.keys()) == allowed


def test_done_carries_reason():
    v = Done(reason="budget_exhausted")
    assert v.reason == "budget_exhausted"
