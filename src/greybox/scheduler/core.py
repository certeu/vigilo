"""Scheduler core — compose rules into a single ``schedule()`` entry point.

The workflow calls :func:`schedule` once per tick. It builds a
:class:`SchedulerContext` from the graph, runs the six pure rules,
sorts verbs by priority, and caps per-type concurrency before
returning.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import aiofiles
from pathlib import Path
from typing import Any, Literal

from src.greybox.graph.views import (
    access_matrix as view_access_matrix,
    ParameterView,
    VerdictCounts,
    _GraphReader,
    _stringify_id,
    attempt_counts_by_verdict,
    chain_candidates as view_chain_candidates,
    open_leads,
    untested_parameters,
)
from src.greybox.scheduler.routing import (
    shapes_for_vuln,
    specialists_for_endpoint,
)
from src.greybox.types.agents import VULN_TYPES
from src.greybox.scheduler.rules import (
    SchedulerConfig,
    SchedulerContext,
    rule_attempt_chain,
    rule_done,
    rule_investigate_leads,
    rule_probe_parameters,
    rule_test_access_matrix,
)
from src.greybox.scheduler.verbs import Done, Verb

BudgetMode = Literal["normal", "cheap-only", "exhausted"]


def classify_budget_mode(
    remaining: float, *, ceiling: float, floor: float
) -> BudgetMode:
    """Classify the remaining-budget fraction into a three-tier mode.

    - ``remaining > ceiling``          → ``"normal"`` (full verb set)
    - ``floor <= remaining <= ceiling``→ ``"cheap-only"`` (drop expensive verbs)
    - ``remaining < floor``            → ``"exhausted"`` (hard halt)

    All inputs are fractions of the total budget (0.0–1.0), matching the
    existing ``budget_remaining_pct`` convention. Exact-ceiling lands in
    cheap-only and exact-floor also lands in cheap-only — exhausted is
    strictly below the floor.
    """
    if remaining > ceiling:
        return "normal"
    if remaining < floor:
        return "exhausted"
    return "cheap-only"


@dataclass
class ScheduleTickResult:
    """Outcome of a single :func:`schedule` invocation.

    ``verbs`` is the ordered list the caller should dispatch.
    ``graph_counts`` and ``verdict_counts`` are the post-tick snapshots
    the caller should pass back as ``previous_*`` on the next tick so
    the scheduler can compare deltas. ``ticks_since_last_progress`` is
    the updated diminishing-returns counter. ``budget_mode`` records the
    three-tier classification (``"normal"`` / ``"cheap-only"`` /
    ``"exhausted"``) that drove this tick's verb filtering.
    """

    verbs: list[Any] = field(default_factory=list)
    graph_counts: dict[str, int] = field(default_factory=dict)
    verdict_counts: dict[str, int] = field(default_factory=dict)
    ticks_since_last_progress: int = 0
    consecutive_waiting_ticks: int = 0
    budget_mode: BudgetMode = "normal"


_PRIORITY_RANK: dict[Any, int] = {"high": 0, "medium": 1, "low": 2, None: 3}

# Rule order within a priority band — reflects information value.
_KIND_ORDER: dict[str, int] = {
    "INVESTIGATE_LEAD": 0,
    "ATTEMPT_CHAIN": 1,
    "PROBE_PARAMETERS": 2,
    "TEST_ACCESS_MATRIX": 3,
    "DONE": 4,
}

# Verb kinds dropped when the scheduler is in the cheap-only budget
# tier (C1). Both kinds dispatch the heaviest specialist agents.
_CHEAP_ONLY_FILTERED: frozenset[str] = frozenset({"PROBE_PARAMETERS", "ATTEMPT_CHAIN"})


async def _collect_untested_by_vuln(
    graph: _GraphReader,
    active_claims: set[str],
    max_specialists_per_endpoint: int,
    max_inconclusive_retries: int,
    max_failed_retries: int,
) -> dict[str, list[ParameterView]]:
    # Iterate the canonical vuln_type roster and keep only those that
    # actually route to a parameter shape (graphql/websocket are
    # endpoint-level and skipped here).
    vuln_types = [vt for vt in VULN_TYPES if shapes_for_vuln(vt)]
    results = await asyncio.gather(
        *(
            untested_parameters(
                graph,
                vt,
                shapes_for_vuln(vt),
                max_inconclusive_retries=max_inconclusive_retries,
                max_failed_retries=max_failed_retries,
            )
            for vt in vuln_types
        )
    )
    # Group shapes observed on each endpoint so we can compute the capped
    # specialist set per endpoint (C4: prevents specialist stacking).
    shapes_by_endpoint: dict[str, set[str]] = {}
    for params in results:
        for p in params:
            if not p.endpoint_id:
                continue
            shapes_by_endpoint.setdefault(p.endpoint_id, set()).add(p.shape)
    allowed_by_endpoint: dict[str, set[str]] = {
        endpoint_id: set(
            specialists_for_endpoint(shapes, max_specialists_per_endpoint)
        )
        for endpoint_id, shapes in shapes_by_endpoint.items()
    }
    out: dict[str, list[ParameterView]] = {}
    for vuln_type, params in zip(vuln_types, results):
        filtered = [
            p for p in params
            if p.id not in active_claims
            and (
                not p.endpoint_id
                or vuln_type in allowed_by_endpoint.get(p.endpoint_id, set())
            )
        ]
        out[vuln_type] = filtered
    return out


async def _collect_ids(graph: _GraphReader, table: str) -> list[str]:
    rows = await graph.raw_query(f"SELECT id FROM {table}")
    return [_stringify_id(row.get("id")) for row in rows if row.get("id") is not None]


_TICK_LOG_TABLES = ("endpoint", "parameter", "lead", "finding", "test_attempt")


async def _graph_counts(graph: _GraphReader) -> dict[str, int]:
    rows_per_table = await asyncio.gather(
        *(graph.raw_query(f"SELECT count() FROM {t} GROUP ALL") for t in _TICK_LOG_TABLES)
    )
    counts: dict[str, int] = {}
    for table, rows in zip(_TICK_LOG_TABLES, rows_per_table):
        counts[table] = int(rows[0]["count"]) if rows else 0
    return counts


async def write_tick_log(
    tick_log_dir: Path,
    tick_number: int,
    graph_counts: dict[str, int],
    verdict_counts: dict[str, int],
    ticks_since_last_progress: int,
    verbs: list[Verb],
    active_claims: list[str],
    budget_mode: str,
) -> None:
    tick_log_dir.mkdir(parents=True, exist_ok=True)
    if verbs and verbs[0].kind == "DONE":
        halt_hint = verbs[0].reason
    elif not verbs and active_claims:
        halt_hint = "waiting_for_agents"
    else:
        halt_hint = None
    body = {
        "tick": tick_number,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "graph_counts": graph_counts,
        "verdict_counts": verdict_counts,
        "ticks_since_last_progress": ticks_since_last_progress,
        "budget_mode": budget_mode,
        "emitted_verbs": [v.model_dump() for v in verbs],
        "active_claims": list(active_claims),
        "halt_hint": halt_hint,
    }
    path = tick_log_dir / f"tick-{tick_number:03d}.json"
    async with aiofiles.open(path, mode="w") as f:
        await f.write(json.dumps(body, indent=2, default=str))


_EMPTY_VERDICT_COUNTS: dict[str, int] = {
    "conclusive_vulnerable": 0,
    "conclusive_clean": 0,
    "inconclusive": 0,
    "failed": 0,
}


def _coerce_verdict_counts(value: Any) -> dict[str, int]:
    if isinstance(value, VerdictCounts):
        return value.as_dict()
    if isinstance(value, dict):
        return {k: int(value.get(k, 0)) for k in _EMPTY_VERDICT_COUNTS}
    return dict(_EMPTY_VERDICT_COUNTS)


async def schedule(
    graph: _GraphReader,
    config: SchedulerConfig,
    active_claims: list[str],
    *,
    budget_remaining_pct: float = 1.0,
    tick_number: int | None = None,
    previous_graph_counts: dict[str, int] | None = None,
    previous_verdict_counts: dict[str, int] | VerdictCounts | None = None,
    ticks_since_last_progress: int = 0,
    consecutive_waiting_ticks: int = 0,
) -> ScheduleTickResult:
    claims_set = set(active_claims)
    prev_graph = previous_graph_counts or {}
    prev_verdicts = _coerce_verdict_counts(previous_verdict_counts)

    budget_mode = classify_budget_mode(
        budget_remaining_pct,
        ceiling=config.budget_cheap_ceiling_pct,
        floor=config.budget_cheap_floor_pct,
    )

    # Exhausted mode is a hard stop — skip graph reads entirely, ignore
    # active claims, emit DONE. Tick-log still gets written for audit.
    if budget_mode == "exhausted":
        done_verb: Verb = Done(reason="budget_exhausted")
        if config.tick_log_dir is not None and tick_number is not None:
            await write_tick_log(
                config.tick_log_dir,
                tick_number,
                {},
                dict(_EMPTY_VERDICT_COUNTS),
                ticks_since_last_progress,
                [done_verb],
                active_claims,
                budget_mode,
            )
        return ScheduleTickResult(
            verbs=[done_verb],
            graph_counts={},
            verdict_counts=dict(_EMPTY_VERDICT_COUNTS),
            ticks_since_last_progress=ticks_since_last_progress,
            consecutive_waiting_ticks=0,
            budget_mode=budget_mode,
        )

    identities = await _collect_ids(graph, "identity")
    (
        untested_by_vuln,
        leads,
        endpoints,
        access_matrix,
        chains,
        current_graph_counts,
        current_verdicts_view,
    ) = await asyncio.gather(
        _collect_untested_by_vuln(
            graph,
            claims_set,
            config.max_specialists_per_endpoint,
            config.max_inconclusive_retries,
            config.max_failed_retries,
        ),
        open_leads(graph, min_strength="medium"),
        _collect_ids(graph, "endpoint"),
        view_access_matrix(graph, identities),
        view_chain_candidates(graph),
        _graph_counts(graph),
        attempt_counts_by_verdict(graph),
    )
    current_verdicts = current_verdicts_view.as_dict()

    new_findings = current_graph_counts.get("finding", 0) - prev_graph.get("finding", 0)
    new_conclusive_vulnerable = (
        current_verdicts["conclusive_vulnerable"]
        - prev_verdicts["conclusive_vulnerable"]
    )
    new_conclusive_clean = (
        current_verdicts["conclusive_clean"]
        - prev_verdicts["conclusive_clean"]
    )
    progress = (
        new_findings + new_conclusive_vulnerable + new_conclusive_clean
    ) > 0
    new_counter = 0 if progress else ticks_since_last_progress + 1

    ctx = SchedulerContext(
        leads=leads,
        untested_parameters_by_vuln=untested_by_vuln,
        identities=identities,
        endpoints=endpoints,
        access_matrix=access_matrix,
        chain_candidates=chains,
        budget_remaining_pct=budget_remaining_pct,
        active_claims=list(active_claims),
        config=config,
        ticks_since_last_progress=new_counter,
        tick_number=tick_number or 0,
    )

    done_verbs = rule_done(ctx)
    if done_verbs:
        verbs_out: list[Verb] = [done_verbs[0]]
    else:
        verbs: list[Verb] = []
        verbs.extend(rule_investigate_leads(ctx))
        verbs.extend(rule_attempt_chain(ctx))
        verbs.extend(rule_probe_parameters(ctx))
        verbs.extend(rule_test_access_matrix(ctx))

        if budget_mode == "cheap-only":
            # C1: below the cheap-tier ceiling, drop expensive verbs.
            # PROBE_PARAMETERS and ATTEMPT_CHAIN spawn the costliest
            # specialists; keep INVESTIGATE_LEAD / TEST_ACCESS_MATRIX
            # running to finish what's cheap.
            verbs = [v for v in verbs if v.kind not in _CHEAP_ONLY_FILTERED]

        verbs.sort(
            key=lambda v: (
                _PRIORITY_RANK.get(getattr(v, "priority", None), 3),
                _KIND_ORDER.get(v.kind, 99),
            )
        )

        verbs = _apply_caps(verbs, config)
        if verbs:
            verbs_out = verbs
            consecutive_waiting_ticks = 0
        elif active_claims:
            consecutive_waiting_ticks += 1
            max_waiting = config.max_consecutive_waiting_ticks
            if max_waiting > 0 and consecutive_waiting_ticks >= max_waiting:
                verbs_out = [Done(reason="waiting_timeout")]
            else:
                verbs_out = []
        else:
            verbs_out = [Done(reason="coverage_complete")]

    if config.tick_log_dir is not None and tick_number is not None:
        await write_tick_log(
            config.tick_log_dir,
            tick_number,
            current_graph_counts,
            current_verdicts,
            new_counter,
            verbs_out,
            active_claims,
            budget_mode,
        )

    return ScheduleTickResult(
        verbs=verbs_out,
        graph_counts=current_graph_counts,
        verdict_counts=current_verdicts,
        ticks_since_last_progress=new_counter,
        consecutive_waiting_ticks=consecutive_waiting_ticks,
        budget_mode=budget_mode,
    )


def _apply_caps(verbs: list[Verb], config: SchedulerConfig) -> list[Verb]:
    """Cap emitted verbs per kind, preserving input (priority) order.

    Three independent caps:
    - ``per_type_cap``       → PROBE_PARAMETERS, INVESTIGATE_LEAD
    - ``authz_per_tick_cap`` → TEST_ACCESS_MATRIX
    - ``chain_per_tick_cap`` → ATTEMPT_CHAIN

    DONE and any unknown verb kinds pass through uncapped.
    """
    cap_for_kind: dict[str, int] = {
        "PROBE_PARAMETERS": config.per_type_cap,
        "INVESTIGATE_LEAD": config.per_type_cap,
        "TEST_ACCESS_MATRIX": config.authz_per_tick_cap,
        "ATTEMPT_CHAIN": config.chain_per_tick_cap,
    }
    counts: dict[str, int] = {}
    kept: list[Verb] = []
    for verb in verbs:
        cap = cap_for_kind.get(verb.kind)
        if cap is None:
            kept.append(verb)
            continue
        if counts.get(verb.kind, 0) >= cap:
            continue
        counts[verb.kind] = counts.get(verb.kind, 0) + 1
        kept.append(verb)
    return kept
