"""Scheduler rules — one pure function per verb.

Each rule takes a :class:`SchedulerContext` and returns a list of
:class:`Verb`. Rules are independent, deterministic, and side-effect
free. The caller (``scheduler/core.py``, Task 3.4) composes them into
a single ``schedule()`` function.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from src.greybox.graph.views import AccessMatrix, ChainCandidateView, LeadView, ParameterView
from src.greybox.scheduler.routing import shapes_for_vuln
from src.greybox.scheduler.verbs import (
    AttemptChain,
    Done,
    InvestigateLead,
    ProbeParameters,
    TestAccessMatrix,
)


# Signal strength → verb priority. "low" leads don't produce verbs at
# all (filtered before mapping), so we only list medium+high here.
_SIGNAL_PRIORITY: dict[str, str] = {
    "high": "high",
    "medium": "medium",
}

# Anonymous identity is the scheduler's default target for parameter
# probes. Task 3.4 (or the dispatcher) can override per batch.
_DEFAULT_IDENTITY = "identity:anonymous"


@dataclass(frozen=True)
class SchedulerConfig:
    batch_size: int = 15
    per_type_cap: int = 3
    authz_per_tick_cap: int = 2
    chain_per_tick_cap: int = 1
    max_specialists_per_endpoint: int = 2
    tick_log_dir: Path | None = None
    idle_ticks_before_done: int = 20
    # C1: three-tier budget mode thresholds. Fractions of remaining budget
    # (0.0–1.0). `cheap-only` below ceiling; `exhausted` below floor.
    budget_cheap_ceiling_pct: float = 0.10
    budget_cheap_floor_pct: float = 0.03
    # D4: retry caps per non-conclusive verdict. A parameter with this many
    # `inconclusive` (or `failed`) attempts for a given vuln_type is excluded
    # from `untested_parameters` — conclusive attempts always exclude.
    max_inconclusive_retries: int = 2
    max_failed_retries: int = 3
    max_consecutive_waiting_ticks: int = 10


@dataclass(frozen=True)
class SchedulerContext:
    leads: list[LeadView]
    untested_parameters_by_vuln: dict[str, list[ParameterView]]
    identities: list[str]
    endpoints: list[str]
    access_matrix: AccessMatrix
    chain_candidates: list[ChainCandidateView]
    budget_remaining_pct: float
    active_claims: list[str]
    config: SchedulerConfig = field(default_factory=SchedulerConfig)
    ticks_since_last_progress: int = 0
    tick_number: int = 0

    @property
    def has_authz_candidates(self) -> bool:
        # Slice 16 / G2: identity-count gate.
        # 0 identities → no candidates (specialist refuses).
        # 1 identity  → any non-claimed endpoint is a vertical-only candidate.
        # 2+         → full-matrix requires conflicting allow/deny observations.
        if len(self.identities) == 0:
            return False
        if len(self.identities) == 1:
            return any(
                ep not in self.active_claims for ep in self.endpoints
            )
        allowed: dict[str, set[str]] = {}
        denied: dict[str, set[str]] = {}
        for identity_id, endpoint_ids in self.access_matrix.can_access.items():
            for endpoint_id in endpoint_ids:
                allowed.setdefault(endpoint_id, set()).add(identity_id)
        for identity_id, endpoint_ids in self.access_matrix.denied_access.items():
            for endpoint_id in endpoint_ids:
                denied.setdefault(endpoint_id, set()).add(identity_id)
        for endpoint_id in self.endpoints:
            if endpoint_id in self.active_claims:
                continue
            if allowed.get(endpoint_id) and denied.get(endpoint_id):
                return True
        return False

    @property
    def all_rules_empty(self) -> bool:
        return (
            not self.leads
            and all(not v for v in self.untested_parameters_by_vuln.values())
            and not self.chain_candidates
            and not self.has_authz_candidates
        )


def rule_investigate_leads(ctx: SchedulerContext) -> list[InvestigateLead]:
    verbs: list[InvestigateLead] = []
    for lead in ctx.leads:
        if lead.status != "open":
            continue
        if lead.investigation_attempts >= lead.max_attempts:
            continue
        if lead.id in ctx.active_claims:
            continue
        priority = _SIGNAL_PRIORITY.get(lead.signal_strength)
        if priority is None:
            continue
        verbs.append(InvestigateLead(lead_id=lead.id, priority=priority))  # type: ignore[arg-type]
    return verbs


def rule_probe_parameters(ctx: SchedulerContext) -> list[ProbeParameters]:
    verbs: list[ProbeParameters] = []
    batch_size = ctx.config.batch_size
    for vuln_type, params in ctx.untested_parameters_by_vuln.items():
        if not params or not shapes_for_vuln(vuln_type):
            continue
        for start in range(0, len(params), batch_size):
            batch = params[start : start + batch_size]
            verbs.append(
                ProbeParameters(
                    vuln_type=vuln_type,
                    param_ids=[p.id for p in batch],
                    identity=_DEFAULT_IDENTITY,
                    priority="medium",
                )
            )
    return verbs


def rule_test_access_matrix(ctx: SchedulerContext) -> list[TestAccessMatrix]:
    # Slice 16 / G2: identity-count gate picks the methodology.
    identity_count = len(ctx.identities)
    if identity_count == 0:
        return []

    batch_size = ctx.config.batch_size

    if identity_count == 1:
        # Vertical-only mode: every non-claimed endpoint is a candidate.
        # Access-matrix observations are irrelevant — the specialist tests
        # privilege escalation per endpoint with the single identity.
        candidates = [ep for ep in ctx.endpoints if ep not in ctx.active_claims]
        if not candidates:
            return []
        verbs: list[TestAccessMatrix] = []
        for start in range(0, len(candidates), batch_size):
            batch = candidates[start : start + batch_size]
            verbs.append(
                TestAccessMatrix(
                    endpoint_ids=batch,
                    identities=list(ctx.identities),
                    mode="vertical_only",
                    priority="medium",
                )
            )
        return verbs

    # identity_count >= 2 → full-matrix mode (existing behaviour).
    endpoint_observations: dict[str, dict[str, set[str]]] = {}
    for identity_id, endpoint_ids in ctx.access_matrix.can_access.items():
        for endpoint_id in endpoint_ids:
            endpoint_observations.setdefault(
                endpoint_id, {"allow": set(), "deny": set()}
            )["allow"].add(identity_id)
    for identity_id, endpoint_ids in ctx.access_matrix.denied_access.items():
        for endpoint_id in endpoint_ids:
            endpoint_observations.setdefault(
                endpoint_id, {"allow": set(), "deny": set()}
            )["deny"].add(identity_id)

    candidate_endpoints = [
        endpoint_id
        for endpoint_id in ctx.endpoints
        if endpoint_id not in ctx.active_claims
        and endpoint_id in endpoint_observations
        and endpoint_observations[endpoint_id]["allow"]
        and endpoint_observations[endpoint_id]["deny"]
    ]
    if not candidate_endpoints:
        return []

    verbs = []
    for start in range(0, len(candidate_endpoints), batch_size):
        batch = candidate_endpoints[start : start + batch_size]
        involved_identities: set[str] = set()
        for endpoint_id in batch:
            observations = endpoint_observations[endpoint_id]
            involved_identities.update(observations["allow"])
            involved_identities.update(observations["deny"])
        if len(involved_identities) < 2:
            continue
        verbs.append(
            TestAccessMatrix(
                endpoint_ids=batch,
                identities=sorted(involved_identities),
                mode="full_matrix",
                priority="medium",
            )
        )
    return verbs


def rule_attempt_chain(ctx: SchedulerContext) -> list[AttemptChain]:
    return [
        AttemptChain(finding_ids=list(c.finding_ids), priority="high")
        for c in ctx.chain_candidates
        if not set(c.finding_ids).intersection(ctx.active_claims)
    ]


def rule_done(ctx: SchedulerContext) -> list[Done]:
    # Note: the ``budget_exhausted`` branch lives in ``schedule()`` so the
    # three-tier budget mode (C1) stays authoritative and owns the halt.
    if ctx.all_rules_empty and not ctx.active_claims:
        return [Done(reason="coverage_complete")]
    idle_limit = ctx.config.idle_ticks_before_done
    if idle_limit > 0 and ctx.ticks_since_last_progress >= idle_limit:
        return [Done(reason="diminishing_returns")]
    return []
