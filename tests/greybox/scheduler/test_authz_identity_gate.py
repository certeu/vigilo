"""Authorization rule identity-count gate — Slice 16 / G2.

The authorization rule branches its emitted verbs on the number of
identities in the context:

- ``0``  → no verbs (can't test auth without a principal)
- ``1``  → ``mode="vertical_only"`` over all non-claimed, non-active
          endpoints (batched by ``batch_size``), no access_matrix
          observations required — vertical escalation applies everywhere.
- ``2+`` → ``mode="full_matrix"`` (existing behavior) using the
          allow/deny observations to pick candidate endpoints.
"""
from __future__ import annotations

from src.greybox.graph.views import AccessMatrix
from src.greybox.scheduler.rules import (
    SchedulerConfig,
    SchedulerContext,
    rule_test_access_matrix,
)


def _ctx(
    *,
    identities: list[str],
    endpoints: list[str],
    access_matrix: AccessMatrix | None = None,
    active_claims: list[str] | None = None,
    batch_size: int = 15,
) -> SchedulerContext:
    return SchedulerContext(
        leads=[],
        untested_parameters_by_vuln={},
        identities=identities,
        endpoints=endpoints,
        access_matrix=access_matrix or AccessMatrix(),
        chain_candidates=[],
        budget_remaining_pct=1.0,
        active_claims=active_claims or [],
        config=SchedulerConfig(batch_size=batch_size),
    )


def test_identity_count_zero_returns_empty():
    ctx = _ctx(identities=[], endpoints=["ep:1", "ep:2"])
    assert rule_test_access_matrix(ctx) == []


def test_identity_count_one_emits_vertical_only():
    ctx = _ctx(identities=["id:user"], endpoints=["ep:1", "ep:2"])
    verbs = rule_test_access_matrix(ctx)
    assert len(verbs) == 1
    v = verbs[0]
    assert v.mode == "vertical_only"
    assert v.identities == ["id:user"]
    assert v.endpoint_ids == ["ep:1", "ep:2"]


def test_identity_count_one_excludes_active_claims():
    ctx = _ctx(
        identities=["id:user"],
        endpoints=["ep:1", "ep:2"],
        active_claims=["ep:1"],
    )
    verbs = rule_test_access_matrix(ctx)
    assert len(verbs) == 1
    assert verbs[0].endpoint_ids == ["ep:2"]


def test_identity_count_one_no_endpoints_returns_empty():
    ctx = _ctx(identities=["id:user"], endpoints=[])
    assert rule_test_access_matrix(ctx) == []


def test_identity_count_two_full_matrix_mode():
    ctx = _ctx(
        identities=["id:admin", "id:user"],
        endpoints=["ep:1"],
        access_matrix=AccessMatrix(
            can_access={"id:admin": ["ep:1"]},
            denied_access={"id:user": ["ep:1"]},
        ),
    )
    verbs = rule_test_access_matrix(ctx)
    assert len(verbs) == 1
    assert verbs[0].mode == "full_matrix"


def test_identity_count_three_still_full_matrix():
    ctx = _ctx(
        identities=["id:admin", "id:user", "id:auditor"],
        endpoints=["ep:1"],
        access_matrix=AccessMatrix(
            can_access={"id:admin": ["ep:1"]},
            denied_access={"id:user": ["ep:1"]},
        ),
    )
    verbs = rule_test_access_matrix(ctx)
    assert len(verbs) == 1
    assert verbs[0].mode == "full_matrix"


def test_vertical_mode_respects_batch_size():
    endpoints = [f"ep:{i}" for i in range(30)]
    ctx = _ctx(identities=["id:user"], endpoints=endpoints, batch_size=15)
    verbs = rule_test_access_matrix(ctx)
    assert len(verbs) == 2
    assert all(v.mode == "vertical_only" for v in verbs)
    assert len(verbs[0].endpoint_ids) == 15
    assert len(verbs[1].endpoint_ids) == 15
