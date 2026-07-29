"""Tests for the six pure-function scheduler rules."""
from __future__ import annotations

from src.greybox.graph.views import AccessMatrix, ChainCandidateView, LeadView, ParameterView
from src.greybox.scheduler.rules import (
    SchedulerConfig,
    SchedulerContext,
    rule_attempt_chain,
    rule_done,
    rule_investigate_leads,
    rule_probe_parameters,
    rule_test_access_matrix,
)


def _ctx(
    *,
    leads: list[LeadView] | None = None,
    untested: dict[str, list[ParameterView]] | None = None,
    identities: list[str] | None = None,
    endpoints: list[str] | None = None,
    access_matrix: AccessMatrix | None = None,
    chain_candidates: list[ChainCandidateView] | None = None,
    budget_remaining_pct: float = 1.0,
    active_claims: list[str] | None = None,
    config: SchedulerConfig | None = None,
) -> SchedulerContext:
    return SchedulerContext(
        leads=leads or [],
        untested_parameters_by_vuln=untested or {},
        identities=identities or ["identity:anonymous"],
        endpoints=endpoints or [],
        access_matrix=access_matrix or AccessMatrix(),
        chain_candidates=chain_candidates or [],
        budget_remaining_pct=budget_remaining_pct,
        active_claims=active_claims or [],
        config=config or SchedulerConfig(),
    )


def _lead(
    *,
    id: str = "lead:1",
    signal_strength: str = "high",
    status: str = "open",
    investigation_attempts: int = 0,
    max_attempts: int = 3,
) -> LeadView:
    return LeadView(
        id=id,
        signal="reflection",
        signal_strength=signal_strength,  # type: ignore[arg-type]
        hypothesis="possible XSS",
        status=status,
        investigation_attempts=investigation_attempts,
        max_attempts=max_attempts,
    )


def _param(id: str, shape: str = "free_text") -> ParameterView:
    return ParameterView(
        id=id,
        name="q",
        location="query",
        shape=shape,  # type: ignore[arg-type]
        endpoint_id="endpoint:e1",
    )


# ---------------------------------------------------------------------------
# rule_investigate_leads
# ---------------------------------------------------------------------------

class TestRuleInvestigateLeads:
    def test_high_signal_lead_emits_verb(self):
        lead = _lead(id="lead:hi", signal_strength="high")
        ctx = _ctx(leads=[lead])
        verbs = rule_investigate_leads(ctx)
        assert len(verbs) == 1
        assert verbs[0].kind == "INVESTIGATE_LEAD"
        assert verbs[0].lead_id == "lead:hi"
        assert verbs[0].priority == "high"

    def test_medium_signal_emits_with_medium_priority(self):
        lead = _lead(id="lead:med", signal_strength="medium")
        ctx = _ctx(leads=[lead])
        verbs = rule_investigate_leads(ctx)
        assert len(verbs) == 1
        assert verbs[0].priority == "medium"

    def test_low_signal_skipped(self):
        lead = _lead(signal_strength="low")
        ctx = _ctx(leads=[lead])
        assert rule_investigate_leads(ctx) == []

    def test_dismissed_lead_skipped(self):
        lead = _lead(status="dismissed")
        ctx = _ctx(leads=[lead])
        assert rule_investigate_leads(ctx) == []

    def test_exhausted_lead_skipped(self):
        lead = _lead(investigation_attempts=3, max_attempts=3)
        ctx = _ctx(leads=[lead])
        assert rule_investigate_leads(ctx) == []


# ---------------------------------------------------------------------------
# rule_probe_parameters
# ---------------------------------------------------------------------------

class TestRuleProbeParameters:
    def test_batches_by_batch_size(self):
        params = [_param(f"parameter:p{i}") for i in range(25)]
        ctx = _ctx(untested={"injection": params}, config=SchedulerConfig(batch_size=15))
        verbs = rule_probe_parameters(ctx)
        assert len(verbs) == 2
        assert len(verbs[0].param_ids) == 15
        assert len(verbs[1].param_ids) == 10
        assert verbs[0].vuln_type == "injection"
        assert verbs[0].priority == "medium"

    def test_empty_vuln_type_returns_no_verb(self):
        ctx = _ctx(untested={"reflection": []})
        assert rule_probe_parameters(ctx) == []

    def test_multiple_vuln_types_each_get_own_verb(self):
        ctx = _ctx(
            untested={
                "injection": [_param(f"parameter:i{i}") for i in range(3)],
                "reflection": [_param(f"parameter:x{i}") for i in range(3)],
            }
        )
        verbs = rule_probe_parameters(ctx)
        assert len(verbs) == 2
        vuln_types = {v.vuln_type for v in verbs}
        assert vuln_types == {"injection", "reflection"}

    def test_unknown_vuln_type_skipped(self):
        # Routing table returns [] for unknown vuln types; rule should skip
        # those rather than emitting a Probe for a type the router can't
        # service.
        ctx = _ctx(untested={"not_a_vuln": [_param("parameter:p1")]})
        assert rule_probe_parameters(ctx) == []


# ---------------------------------------------------------------------------
# rule_test_access_matrix
# ---------------------------------------------------------------------------

class TestRuleTestAccessMatrix:
    def test_single_identity_emits_vertical_only(self):
        # Slice 16 / G2: one identity → vertical-only mode (privilege
        # escalation per endpoint). The exhaustive identity-count gate
        # matrix lives in tests/greybox/scheduler/test_authz_identity_gate.py.
        ctx = _ctx(identities=["identity:anonymous"], endpoints=["endpoint:e1"])
        verbs = rule_test_access_matrix(ctx)
        assert len(verbs) == 1
        assert verbs[0].mode == "vertical_only"

    def test_skipped_when_no_identities(self):
        # Bypass `_ctx` default — identities=[] is falsy there.
        ctx = SchedulerContext(
            leads=[],
            untested_parameters_by_vuln={},
            identities=[],
            endpoints=["endpoint:e1"],
            access_matrix=AccessMatrix(),
            chain_candidates=[],
            budget_remaining_pct=1.0,
            active_claims=[],
        )
        assert rule_test_access_matrix(ctx) == []

    def test_emits_batched_verbs_for_differential_access(self):
        ctx = _ctx(
            identities=["identity:anonymous", "identity:user"],
            endpoints=["endpoint:e1", "endpoint:e2", "endpoint:e3"],
            access_matrix=AccessMatrix(
                can_access={
                    "identity:anonymous": ["endpoint:e1"],
                    "identity:user": ["endpoint:e2"],
                },
                denied_access={
                    "identity:anonymous": ["endpoint:e2"],
                    "identity:user": ["endpoint:e1", "endpoint:e3"],
                },
            ),
            config=SchedulerConfig(batch_size=1),
        )
        verbs = rule_test_access_matrix(ctx)
        assert len(verbs) == 2
        assert [v.endpoint_ids for v in verbs] == [["endpoint:e1"], ["endpoint:e2"]]
        assert all(v.identities == ["identity:anonymous", "identity:user"] for v in verbs)
        assert all(v.priority == "medium" for v in verbs)

    def test_skips_endpoints_without_conflicting_observations(self):
        ctx = _ctx(
            identities=["identity:anonymous", "identity:user"],
            endpoints=["endpoint:e1", "endpoint:e2"],
            access_matrix=AccessMatrix(
                can_access={"identity:user": ["endpoint:e1"]},
                denied_access={"identity:anonymous": ["endpoint:e2"]},
            ),
        )
        assert rule_test_access_matrix(ctx) == []

    def test_skips_already_claimed_endpoint(self):
        ctx = _ctx(
            identities=["identity:anonymous", "identity:user"],
            endpoints=["endpoint:e1"],
            access_matrix=AccessMatrix(
                can_access={"identity:user": ["endpoint:e1"]},
                denied_access={"identity:anonymous": ["endpoint:e1"]},
            ),
            active_claims=["endpoint:e1"],
        )
        assert rule_test_access_matrix(ctx) == []


# ---------------------------------------------------------------------------
# rule_attempt_chain
# ---------------------------------------------------------------------------

class TestRuleAttemptChain:
    def test_emits_one_verb_per_candidate(self):
        c1 = ChainCandidateView(
            grants_finding_id="finding:a",
            requires_finding_id="finding:b",
            finding_ids=["finding:a", "finding:b"],
        )
        c2 = ChainCandidateView(
            grants_finding_id="finding:c",
            requires_finding_id="finding:d",
            finding_ids=["finding:c", "finding:d"],
        )
        ctx = _ctx(chain_candidates=[c1, c2])
        verbs = rule_attempt_chain(ctx)
        assert len(verbs) == 2
        assert verbs[0].finding_ids == ["finding:a", "finding:b"]
        assert verbs[1].finding_ids == ["finding:c", "finding:d"]
        assert verbs[0].priority == "high"

    def test_empty_candidates_returns_empty(self):
        ctx = _ctx(chain_candidates=[])
        assert rule_attempt_chain(ctx) == []


# ---------------------------------------------------------------------------
# rule_done
# ---------------------------------------------------------------------------

class TestRuleDone:
    def test_rule_done_ignores_budget_remaining_pct(self):
        """C1: budget logic lives in schedule(), not rule_done.

        rule_done must never emit budget_exhausted — the three-tier
        classifier in schedule() owns the hard halt. Low budget alone,
        with rules otherwise empty, still yields coverage_complete.
        """
        ctx = _ctx(
            budget_remaining_pct=0.01,
            identities=["identity:anonymous"],
            active_claims=[],
        )
        verbs = rule_done(ctx)
        assert len(verbs) == 1
        assert verbs[0].reason == "coverage_complete"

    def test_done_when_all_rules_empty_and_no_active_claims(self):
        ctx = _ctx(
            budget_remaining_pct=0.8,
            identities=["identity:anonymous"],
            active_claims=[],
        )
        verbs = rule_done(ctx)
        assert len(verbs) == 1
        assert verbs[0].reason == "coverage_complete"

    def test_not_done_when_work_remains(self):
        ctx = _ctx(
            budget_remaining_pct=0.8,
            untested={"injection": [_param("parameter:p1")]},
        )
        assert rule_done(ctx) == []

    def test_not_done_when_active_claims_even_if_empty(self):
        ctx = _ctx(
            budget_remaining_pct=0.8,
            identities=["identity:anonymous"],
            active_claims=["claim:1"],
        )
        assert rule_done(ctx) == []
