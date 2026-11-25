"""Grey-box run/target service helpers.

``start_run`` (idempotent), ``cancel_run`` and ``reap_expired_leases``. All run
writes share one short transaction per state change, and events are emitted in
the same transaction (``events.emit`` allocates ``seq`` there).
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import checks as gb_checks
from src.greybox_web import events, modelsel
from src.greybox_web.models import (
    GB_ACTIVE,
    GB_CANCELLING,
    GB_CANCELLED,
    GB_QUEUED,
    GB_RUNNING,
    GB_FAILED,
    GB_PREPARING,
    GB_TERMINAL,
    RUN_CHILD_MODELS,
    GreyboxAgent,
    GreyboxGraphNode,
    GreyboxRun,
    GreyboxTarget,
    GreyboxWorkOrder,
)
from src.greybox_web.schemas import stored_limits
from src.greybox_web.scope import ScopePolicy


class RunStartError(Exception):
    """Domain error mapped to an HTTP status by the API layer."""

    def __init__(self, status_code: int, detail: str, **extra: object) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.extra = extra


async def count_active_runs(session: AsyncSession, *, target_id: uuid.UUID) -> int:
    return int(await session.scalar(
        select(func.count()).select_from(GreyboxRun).where(
            GreyboxRun.target_id == target_id, GreyboxRun.status.in_(tuple(GB_ACTIVE)))
    ) or 0)


async def purge_runs(session: AsyncSession, run_ids: Sequence[uuid.UUID]) -> None:
    """Delete runs and all their child rows explicitly (children first).

    Postgres would cascade through the FKs, but SQLite only enforces ON DELETE CASCADE
    with ``PRAGMA foreign_keys=ON``, which the platform does not set."""
    ids = list(run_ids)
    if not ids:
        return
    for model in reversed(RUN_CHILD_MODELS):
        await session.execute(delete(model).where(model.run_id.in_(ids)))
    await session.execute(delete(GreyboxRun).where(GreyboxRun.id.in_(ids)))


# --------------------------------------------------------------------- start


async def _existing_for_key(session: AsyncSession, owner: uuid.UUID, key: str,
                            target_id: uuid.UUID) -> GreyboxRun | None:
    """The run created with ``(owner, key)``. A key already bound to a run of a
    different target is a client error (409), never another target's run."""
    existing = (await session.scalars(
        select(GreyboxRun).where(GreyboxRun.owner_id == owner,
                                 GreyboxRun.idempotency_key == key))).first()
    if existing is not None and existing.target_id != target_id:
        raise RunStartError(
            409, "Idempotency key already used for a different target")
    return existing


def _run_scope(target: GreyboxTarget) -> dict:
    """The scope a run snapshots: the target's scope plus its assessment mode and
    disabled capabilities (``modes.py``), so admission enforces the mode for the
    whole run without re-reading the target (which may change meanwhile)."""
    from src.greybox_web import modes
    scope = dict(target.scope)
    mode = modes.normalise_mode(getattr(target, "assessment_mode", modes.DEFAULT_MODE))
    disabled = sorted(str(c) for c in (getattr(target, "disabled_capabilities", None)
                                       or ()))
    if mode != modes.DEFAULT_MODE or disabled:
        scope["assessment"] = {"mode": mode, "disabled_capabilities": disabled}
    return scope


async def start_run(session: AsyncSession, *, target: GreyboxTarget,
                    user_id: uuid.UUID,
                    idempotency_key: str | None) -> tuple[GreyboxRun, bool]:
    """Insert a queued run for ``target`` and emit ``run.queued`` in the same
    transaction. Returns ``(run, created)``; a repeated idempotency key returns
    the existing run (T10). Raises :class:`RunStartError` for 409/429."""
    from src.greybox_web import settings as gb_settings

    owner = target.owner_id
    target_id = target.id
    target_name = target.name
    if idempotency_key:
        existing = await _existing_for_key(session, owner, idempotency_key, target_id)
        if existing is not None:
            return existing, False
    # Serialise the per-user cap check across workers/API processes: lock the owner
    # row (Postgres SELECT ... FOR UPDATE; SQLite ignores it and is already
    # serialised by txn.sqlite_write_lock). The per-target rule is additionally
    # backed by a partial unique index (ux_greybox_runs_one_active_per_target).
    from src.webapi.models import User
    await session.execute(
        select(User.id).where(User.id == owner).with_for_update())
    active = (await session.scalars(
        select(GreyboxRun).where(
            GreyboxRun.target_id == target.id,
            GreyboxRun.status.in_(tuple(GB_ACTIVE)))
        .order_by(GreyboxRun.created_at))).first()
    if active is not None:
        raise RunStartError(409, "A run for this target is already active",
                            run_id=str(active.id))
    cap = int(gb_settings.settings().greybox_max_active_runs_per_user)
    own_active = int(await session.scalar(
        select(func.count()).select_from(GreyboxRun).where(
            GreyboxRun.owner_id == owner,
            GreyboxRun.status.in_(tuple(GB_ACTIVE)))) or 0)
    if own_active >= cap:
        raise RunStartError(429, "Too many active grey-box runs")

    policy = ScopePolicy.from_dict(target.scope)
    checks = gb_checks.resolve_checks(
        target.checks if target.checks is None else list(target.checks),
        policy.allow_auth_testing)
    skipped = gb_checks.skipped_checks(
        None if target.checks is None else list(target.checks))
    limits = stored_limits(target.limits).model_dump()
    egress_proxy: dict | None = None
    if target.egress_proxy_id is not None:
        # Re-validated at start (the proxy may have been disabled or narrowed since the
        # target was saved). The snapshot never holds credentials.
        from src.greybox_web.api.egress_proxies import proxy_problem
        problem, prow = await proxy_problem(session, target.egress_proxy_id,
                                            list(policy.allowed_hosts))
        if problem or prow is None:
            raise RunStartError(422, f"egress_proxy_id: {problem}")
        egress_proxy = {"id": str(prow.id), "name": prow.name, "url": prow.url}
    # The exploration agent is the only planner: refuse to queue a run that could not
    # call a model. The resolved choice is snapshotted (never the key).
    try:
        chosen = modelsel.resolve_model(target)
    except modelsel.ModelSelectionError as exc:
        raise RunStartError(409, str(exc)) from None
    run = GreyboxRun(
        id=uuid.uuid4(), target_id=target.id,
        model_backend=chosen.backend, model=chosen.model, owner_id=owner, status=GB_QUEUED,
        base_url=target.base_url, scope=_run_scope(target), limits=limits,
        checks=checks, credential_id=target.credential_id,
        account_ids=list(target.account_ids or []),
        egress_proxy=egress_proxy, idempotency_key=idempotency_key, initiated_by=user_id)
    session.add(run)
    try:
        await session.flush()
    except IntegrityError:
        # Either the (owner, key) unique constraint or the one-active-run-per-target
        # partial unique index fired: a concurrent start won. Roll back and answer
        # exactly as the sequential path would.
        await session.rollback()
        if idempotency_key:
            existing = await _existing_for_key(session, owner, idempotency_key,
                                               target_id)
            if existing is not None:
                return existing, False
        active = (await session.scalars(
            select(GreyboxRun).where(
                GreyboxRun.target_id == target_id,
                GreyboxRun.status.in_(tuple(GB_ACTIVE)))
            .order_by(GreyboxRun.created_at))).first()
        if active is None:
            raise
        raise RunStartError(409, "A run for this target is already active",
                            run_id=str(active.id)) from None
    await events.emit(
        session, run.id, "run.queued", f"run queued for {target_name}",
        data={"target_id": str(target_id), "base_url": run.base_url,
              "scope_summary": policy.summary(), "limits": limits,
              "checks": checks, "skipped_checks": skipped,
              "initiated_by": str(user_id)},
        refs={})
    if skipped:
        ids = ", ".join(s["id"] for s in skipped)
        await events.emit(
            session, run.id, "log.warning",
            f"requested checks not available in this build, not run: {ids}",
            data={"message": "Requested checks without an implementation were "
                             "removed from this run: " + ids,
                  "skipped_checks": skipped})
    return run, True


# -------------------------------------------------------------------- cancel


async def cancel_run(session: AsyncSession, run: GreyboxRun, *, user_id: uuid.UUID,
                     reason: str | None) -> GreyboxRun:
    """User cancellation. A queued run is cancelled immediately by
    the API; a claimed run gets the ``cancelling`` flag and the supervisor (or
    the reaper, on lease expiry) writes the terminal acknowledgement."""
    if run.status in GB_TERMINAL:
        raise RunStartError(409, "Run already finished")
    now = datetime.now(timezone.utc)
    run_id = run.id
    # Conditional UPDATEs: a run that went terminal concurrently must not be
    # resurrected as ``cancelling`` (it would have a NULL lease and never be reaped).
    res = await session.execute(
        update(GreyboxRun)
        .where(GreyboxRun.id == run_id, GreyboxRun.status == GB_QUEUED)
        .values(status=GB_CANCELLED, end_reason="cancelled", finished_at=now,
                cancel_requested_at=now, cancel_requested_by=user_id)
        .execution_options(synchronize_session=False))
    if res.rowcount == 1:
        await session.refresh(run)
        # Record who and why (shown in the run header), then the terminal event.
        await events.emit(
            session, run_id, "run.cancel_requested", "cancellation requested",
            source="api", level="warning", status="pending",
            data={"requested_by": str(user_id), "reason": reason})
        await events.emit(
            session, run_id, "run.cancelled", "run cancelled before it started",
            source="api", status="cancelled",
            data={"reason": "user", "open_work_orders_cancelled": 0})
        return run
    res = await session.execute(
        update(GreyboxRun)
        .where(GreyboxRun.id == run_id,
               GreyboxRun.status.in_((GB_PREPARING, GB_RUNNING, GB_CANCELLING)))
        .values(status=GB_CANCELLING, cancel_requested_at=now,
                cancel_requested_by=user_id)
        .execution_options(synchronize_session=False))
    await session.refresh(run)
    if res.rowcount != 1:
        raise RunStartError(409, "Run already finished"
                            if run.status in GB_TERMINAL
                            else "Run state changed; retry")
    await events.emit(
        session, run_id, "run.cancel_requested", "cancellation requested",
        source="api", level="warning", status="pending",
        data={"requested_by": str(user_id), "reason": reason})
    return run


# -------------------------------------------------------------------- reaper


def _lease_dead(now: datetime):
    """Lease expired, or (defence in depth) a ``cancelling`` run with no lease at
    all, which ``lease_expires_at < now`` would never match."""
    return or_(GreyboxRun.lease_expires_at < now,
               and_(GreyboxRun.status == GB_CANCELLING,
                    GreyboxRun.lease_expires_at.is_(None)))


async def reap_expired_leases(factory, worker_id: str | None = None) -> int:
    """Fail runs whose worker died (lease expired, no auto-retry) and finish
    runs that were already cancelling. Returns the number of reaped runs.
    Called from every worker loop and from the in-process executor."""
    from src.greybox_web.graph import GraphStats, GraphTx
    from src.greybox_web.supervisor import _settle_nodes, settle_open_graph
    from src.greybox_web.txn import read as tx_read
    from src.greybox_web.txn import write as tx_write

    async def _find(session: AsyncSession) -> list[uuid.UUID]:
        return list((await session.scalars(
            select(GreyboxRun.id).where(
                GreyboxRun.status.in_((GB_PREPARING, GB_RUNNING, GB_CANCELLING)),
                _lease_dead(datetime.now(timezone.utc)))
        )).all())

    ids = await tx_read(factory, _find)
    reaped = 0
    for run_id in ids:

        async def one(session: AsyncSession, run_id: uuid.UUID = run_id) -> bool:
            now = datetime.now(timezone.utc)
            row = (await session.execute(
                select(GreyboxRun.status).where(
                    GreyboxRun.id == run_id,
                    GreyboxRun.status.in_((GB_PREPARING, GB_RUNNING, GB_CANCELLING)),
                    _lease_dead(now)))).first()
            if row is None:
                return False                       # lease was renewed meanwhile
            was_cancelling = row[0] == GB_CANCELLING
            new_status = GB_CANCELLED if was_cancelling else GB_FAILED
            await session.execute(
                update(GreyboxRun).where(GreyboxRun.id == run_id)
                .values(status=new_status, end_reason="lease_expired",
                        error_summary=None if was_cancelling else
                        "Worker lease expired (worker crash or restart). The run "
                        "was not retried automatically; start a new run if needed.",
                        finished_at=now, lease_owner=None, lease_expires_at=None)
                .execution_options(synchronize_session=False))
            open_wos = (await session.scalars(
                select(GreyboxWorkOrder).where(
                    GreyboxWorkOrder.run_id == run_id,
                    GreyboxWorkOrder.status.in_(("pending", "running"))))).all()
            gtx = GraphTx(session, run_id, GraphStats())
            for wo in open_wos:
                wo.status = "cancelled"
                wo.finished_at = now
                # same settling as the supervisor's finalize: work-order node plus any
                # action node still running (no node is left "running" after a reap)
                await _settle_nodes(session, gtx, wo, "cancelled", "not_applicable")
            await settle_open_graph(session, gtx, run_id)
            if gtx.stats.any():                    # graph.updated precedes the terminal
                version = int(await session.scalar(
                    select(GreyboxRun.graph_version).where(GreyboxRun.id == run_id)) or 0)
                await events.emit(session, run_id, "graph.updated", "graph updated",
                                  data={"version": version, **gtx.stats.take()})
            await session.execute(
                update(GreyboxAgent).where(GreyboxAgent.run_id == run_id)
                .values(status="cancelled", current_work_order_id=None,
                        finished_at=now)
                .execution_options(synchronize_session=False))
            if was_cancelling:
                await events.emit(
                    session, run_id, "run.cancelled",
                    "run cancelled (lease expired)", status="cancelled",
                    data={"reason": "lease_expired",
                          "open_work_orders_cancelled": len(open_wos)})
            else:
                await events.emit(
                    session, run_id, "run.failed",
                    "run failed: worker lease expired",
                    level="error", status="error",
                    data={"reason": "lease_expired", "error": "lease expired"})
            return True

        if await tx_write(factory, one):
            reaped += 1
    return reaped


RESUMABLE_END_REASONS = frozenset({
    "lease_expired", "cancelled", "error", "budget_requests", "budget_time",
    "completed", "budget_exhausted", "blocked", "needs_authorisation"})


async def resume_run(session: AsyncSession, run: GreyboxRun, *, user_id: uuid.UUID,
                     limits: dict | None = None) -> GreyboxRun:
    """Continue a finished or interrupted run from its persisted state.

    Nothing is discarded: work orders, observations, hypotheses, findings, the
    graph, the traffic and the tools the agent wrote stay, and the supervisor
    rebuilds its state from them (``Planner.hydrate``) so done work is not repeated.
    ``limits`` may RAISE the request/time budget (validated like a target's
    limits); it can never widen the scope, which stays the run's snapshot.
    Raises :class:`RunStartError` (409) when the run is active, another run of the
    target is active, or the run cannot be resumed."""
    from src.greybox_web import events as gb_events
    if run.status not in GB_TERMINAL:
        raise RunStartError(409, "The run is still active")
    if run.end_reason and run.end_reason not in RESUMABLE_END_REASONS:
        raise RunStartError(409, f"A run that ended with {run.end_reason!r} cannot "
                                 f"be resumed")
    active = (await session.scalars(
        select(GreyboxRun.id).where(GreyboxRun.target_id == run.target_id,
                                    GreyboxRun.status.in_(tuple(GB_ACTIVE))))).first()
    if active is not None:
        raise RunStartError(409, "A run for this target is already active",
                            run_id=str(active))
    if limits:
        merged = {**(run.limits or {}), **{k: v for k, v in limits.items()
                                           if k in ("max_requests", "max_duration_s")}}
        try:
            run.limits = stored_limits(merged).model_dump()
        except Exception as exc:                        # noqa: BLE001 — pydantic
            raise RunStartError(422, f"limits: {exc}") from None
    previous = run.end_reason
    run.status = GB_QUEUED
    run.end_reason = None
    run.error_summary = None
    run.finished_at = None
    run.cancel_requested_at = None
    run.cancel_requested_by = None
    run.lease_owner = None
    run.lease_expires_at = None
    run.coverage_verdict = None
    await gb_events.emit(
        session, run.id, "run.resumed",
        f"run resumed (previous end: {previous or 'unknown'})",
        data={"previous_end_reason": previous, "by": str(user_id),
              "limits": {k: (run.limits or {}).get(k)
                         for k in ("max_requests", "max_duration_s")}})
    await session.flush()
    return run
