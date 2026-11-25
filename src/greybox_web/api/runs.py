"""Grey-box run lifecycle API: start, list, read, cancel, delete.

Start is idempotent (T10), requires an explicit authorization confirmation (T1),
re-validates the target's credential, and enforces the per-target and per-user
caps. Cancel acknowledges asynchronously (202) once a worker owns the run.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import service as gb_service
from src.greybox_web import settings as gb_settings
from src.greybox_web.acl import get_run_or_404, get_target_or_404
from src.greybox_web.models import (
    GB_ACTIVE,
    GB_TERMINAL,
    GreyboxAgent,
    GreyboxAsset,
    GreyboxEvent,
    GreyboxFinding,
    GreyboxReport,
    GreyboxRun,
    GreyboxTarget,
    GreyboxWorkOrder,
)
from src.greybox_web.pagination import (
    as_utc,
    clamp_limit,
    decode_cursor,
    encode_cursor,
    parse_ts,
    parse_uuid,
)
from src.greybox_web.schemas import (
    CancelRequest,
    CredentialRef,
    FindingCounts,
    ReportRead,
    RunCounters,
    RunPage,
    RunRead,
    RunStart,
    RunSummary,
    TargetRef,
    WorkOrderCounts,
    stored_limits,
)
from src.greybox_web.service import RunStartError
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.txn import sqlite_write_lock
from src.webapi.auth.deps import current_active_user
from src.webapi.credential_guard import COOKIE_KIND, CredentialRejected, \
    validate_cookie_credential
from src.webapi.db import get_async_session
from src.webapi.models import Credential, User

router = APIRouter(prefix="/greybox", tags=["greybox"])


async def _credential_ref(session: AsyncSession,
                          run: GreyboxRun) -> CredentialRef | None:
    if run.credential_id is None:
        return None
    cred = await session.get(Credential, run.credential_id)
    if cred is None or cred.kind != COOKIE_KIND:
        return None
    return CredentialRef(id=cred.id, label=cred.label, kind=COOKIE_KIND)


async def _finding_counts(session: AsyncSession,
                          run_ids: list[uuid.UUID]) -> dict[uuid.UUID, FindingCounts]:
    out = {rid: FindingCounts(candidate=0, verified=0, rejected=0, by_severity={})
           for rid in run_ids}
    if not run_ids:
        return out
    rows = (await session.execute(
        select(GreyboxFinding.run_id, GreyboxFinding.status, GreyboxFinding.severity,
               func.count())
        .where(GreyboxFinding.run_id.in_(run_ids))
        .group_by(GreyboxFinding.run_id, GreyboxFinding.status,
                  GreyboxFinding.severity))).all()
    for rid, fstatus, severity, n in rows:
        c = out[rid]
        setattr(c, fstatus, getattr(c, fstatus) + int(n))
        if fstatus in ("candidate", "verified"):
            c.by_severity[severity] = c.by_severity.get(severity, 0) + int(n)
    return out


async def _report_status(session: AsyncSession,
                         run_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not run_ids:
        return {}
    rows = (await session.execute(
        select(GreyboxReport.run_id, GreyboxReport.status)
        .where(GreyboxReport.run_id.in_(run_ids)))).all()
    return {rid: s for rid, s in rows}


async def _last_event_at(session: AsyncSession,
                         run_ids: list[uuid.UUID]) -> dict[uuid.UUID, object]:
    if not run_ids:
        return {}
    rows = (await session.execute(
        select(GreyboxEvent.run_id, func.max(GreyboxEvent.ts))
        .where(GreyboxEvent.run_id.in_(run_ids))
        .group_by(GreyboxEvent.run_id))).all()
    return {rid: as_utc(ts) for rid, ts in rows}


async def _counters(session: AsyncSession, run: GreyboxRun) -> RunCounters:
    wo_rows = (await session.execute(
        select(GreyboxWorkOrder.status, func.count())
        .where(GreyboxWorkOrder.run_id == run.id)
        .group_by(GreyboxWorkOrder.status))).all()
    wo = {s: int(n) for s, n in wo_rows}
    assets = int(await session.scalar(
        select(func.count()).select_from(GreyboxAsset).where(
            GreyboxAsset.run_id == run.id)) or 0)
    endpoints = int(await session.scalar(
        select(func.count()).select_from(GreyboxAsset).where(
            GreyboxAsset.run_id == run.id,
            GreyboxAsset.kind == "endpoint")) or 0)
    agents_active = int(await session.scalar(
        select(func.count()).select_from(GreyboxAgent).where(
            GreyboxAgent.run_id == run.id, GreyboxAgent.status == "running")) or 0)
    return RunCounters(
        events=int(run.last_seq or 0), requests=int(run.requests_made or 0),
        requests_blocked=int(run.requests_blocked or 0), assets=assets,
        endpoints=endpoints,
        work_orders=WorkOrderCounts(
            pending=wo.get("pending", 0), running=wo.get("running", 0),
            done=wo.get("done", 0), failed=wo.get("failed", 0),
            skipped=wo.get("skipped", 0), cancelled=wo.get("cancelled", 0)),
        agents_active=agents_active)


async def _summary(session: AsyncSession, run: GreyboxRun, target: GreyboxTarget,
                   findings: FindingCounts) -> RunSummary:
    return RunSummary(
        id=run.id,
        target=TargetRef(id=target.id, name=target.name, base_url=run.base_url),
        owner_id=run.owner_id, status=run.status, phase=run.phase,
        end_reason=run.end_reason,
        cancel_requested=run.cancel_requested_at is not None,
        findings=findings, created_at=as_utc(run.created_at),
        started_at=as_utc(run.started_at), finished_at=as_utc(run.finished_at))


async def _cancel_info(session: AsyncSession,
                       run: GreyboxRun) -> tuple[str | None, str | None]:
    """(cancelled_by email, reason) for a run whose cancel was requested."""
    if run.cancel_requested_at is None:
        return None, None
    who = None
    if run.cancel_requested_by is not None:
        u = await session.get(User, run.cancel_requested_by)
        who = u.email if u is not None else None
    data = await session.scalar(
        select(GreyboxEvent.data).where(GreyboxEvent.run_id == run.id,
                                        GreyboxEvent.kind == "run.cancel_requested")
        .order_by(GreyboxEvent.seq.desc()).limit(1))
    reason = (data or {}).get("reason") if isinstance(data, dict) else None
    return who, (reason or None)


async def _skipped_checks(session: AsyncSession,
                          run: GreyboxRun) -> list[dict[str, str]]:
    """Requested-but-unavailable checks, recorded in ``run.queued`` at start."""
    data = await session.scalar(
        select(GreyboxEvent.data).where(GreyboxEvent.run_id == run.id,
                                        GreyboxEvent.kind == "run.queued")
        .order_by(GreyboxEvent.seq).limit(1))
    skipped = (data or {}).get("skipped_checks") if isinstance(data, dict) else None
    return [{"id": str(s["id"]), "reason": str(s["reason"])}
            for s in skipped or [] if isinstance(s, dict) and "id" in s and "reason" in s]


def _proxy_ref(run: GreyboxRun) -> dict | None:
    snap = run.egress_proxy
    if isinstance(snap, dict) and snap.get("id") and snap.get("name"):
        return {"id": snap["id"], "name": snap["name"]}
    return None


async def _run_read(session: AsyncSession, run: GreyboxRun) -> RunRead:
    target = await session.get(GreyboxTarget, run.target_id)
    findings = (await _finding_counts(session, [run.id]))[run.id]
    base = await _summary(session, run, target, findings)
    cancelled_by, cancel_reason = await _cancel_info(session, run)
    return RunRead(
        **base.model_dump(),
        skipped_checks=await _skipped_checks(session, run),
        egress_proxy=_proxy_ref(run),
        model_backend=run.model_backend or None, model=run.model or None,
        error_summary=run.error_summary,
        scope=ScopePolicy.from_dict(run.scope).to_dict(),   # type: ignore[arg-type]
        scope_summary=ScopePolicy.from_dict(run.scope).summary(),
        limits=stored_limits(run.limits),
        checks=list(run.checks or []),
        credential=await _credential_ref(session, run),
        counters=await _counters(session, run),
        last_seq=int(run.last_seq or 0), graph_version=int(run.graph_version or 0),
        heartbeat_at=as_utc(run.heartbeat_at),
        last_event_at=(await _last_event_at(session, [run.id])).get(run.id),
        report_status=(await _report_status(session, [run.id])).get(run.id, "pending"),
        cancelled_by=cancelled_by, cancel_reason=cancel_reason,
        coverage_verdict=run.coverage_verdict if isinstance(run.coverage_verdict, dict)
        else None,
        auth_states=list(run.auth_states or []),
        resumable=run.status in GB_TERMINAL
        and (run.end_reason or "") in gb_service.RESUMABLE_END_REASONS)


# ---------------------------------------------------------------------- routes


@router.post("/targets/{target_id}/runs", response_model=None)
async def start_run(
    target_id: uuid.UUID,
    payload: RunStart,
    response: Response,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> RunRead:
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Authorization must be confirmed to start a grey-box run")
    if gb_settings.settings().greybox_executor == "off":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Grey-box executor is not running")
    target = await get_target_or_404(session, user, target_id)
    if target.credential_id is not None:          # re-validate at run start
        cred = await session.get(Credential, target.credential_id)
        try:
            validate_cookie_credential(cred, target.owner_id)
        except CredentialRejected as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"credential_id: {exc}") from None
    async with sqlite_write_lock(session):
        try:
            run, created = await gb_service.start_run(
                session, target=target, user_id=user.id,
                idempotency_key=payload.idempotency_key)
        except RunStartError as exc:
            # The contract body carries extra keys (e.g. run_id) at the top
            # level, next to `detail`.
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=exc.status_code,
                                content={"detail": exc.detail, **exc.extra})
        await session.commit()
        await session.refresh(run)
    response.status_code = status.HTTP_201_CREATED if created \
        else status.HTTP_200_OK
    return await _run_read(session, run)


@router.get("/runs", response_model=RunPage)
async def list_runs(
    target_id: uuid.UUID | None = None,
    status_filter: str | None = Query(default=None, alias="status", max_length=100),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None, max_length=200),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> RunPage:
    from src.greybox_web.acl import is_admin
    n = clamp_limit(limit)
    stmt = select(GreyboxRun)
    if not is_admin(user):
        stmt = stmt.where(GreyboxRun.owner_id == user.id)
    if target_id is not None:
        stmt = stmt.where(GreyboxRun.target_id == target_id)
    if status_filter:
        wanted = tuple(s.strip() for s in status_filter.split(",") if s.strip())
        if wanted:
            stmt = stmt.where(GreyboxRun.status.in_(wanted))
    if cursor:
        ts_s, id_s = decode_cursor(cursor, 2)
        ts, cid = parse_ts(ts_s), parse_uuid(id_s)
        stmt = stmt.where(or_(GreyboxRun.created_at < ts,
                              and_(GreyboxRun.created_at == ts,
                                   GreyboxRun.id < cid)))
    stmt = stmt.order_by(GreyboxRun.created_at.desc(),
                         GreyboxRun.id.desc()).limit(n + 1)
    runs = list((await session.scalars(stmt)).all())
    next_cursor = None
    if len(runs) > n:
        runs = runs[:n]
        next_cursor = encode_cursor(runs[-1].created_at, runs[-1].id)
    targets = {t.id: t for t in (await session.scalars(
        select(GreyboxTarget).where(
            GreyboxTarget.id.in_([r.target_id for r in runs])))).all()} \
        if runs else {}
    findings = await _finding_counts(session, [r.id for r in runs])
    items = [await _summary(session, r, targets[r.target_id], findings[r.id])
             for r in runs if r.target_id in targets]
    return RunPage(items=items, next_cursor=next_cursor)


@router.get("/runs/{run_id}", response_model=RunRead)
async def read_run(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> RunRead:
    run = await get_run_or_404(session, user, run_id)
    return await _run_read(session, run)


@router.post("/runs/{run_id}/cancel", response_model=RunRead,
             status_code=status.HTTP_202_ACCEPTED)
async def cancel_run(
    run_id: uuid.UUID,
    payload: CancelRequest | None = None,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> RunRead:
    run = await get_run_or_404(session, user, run_id)
    async with sqlite_write_lock(session):
        try:
            run = await gb_service.cancel_run(
                session, run, user_id=user.id,
                reason=(payload.reason if payload else None))
        except RunStartError as exc:
            raise HTTPException(status_code=exc.status_code,
                                detail=exc.detail) from None
        await session.commit()
        await session.refresh(run)
    return await _run_read(session, run)


class ResumeRequest(BaseModel):
    """Optional budget increase for the resumed run (never the scope)."""

    model_config = ConfigDict(extra="forbid")
    max_requests: int | None = None
    max_duration_s: int | None = None


@router.post("/runs/{run_id}/resume", response_model=RunRead,
             status_code=status.HTTP_202_ACCEPTED)
async def resume_run(
    run_id: uuid.UUID,
    payload: ResumeRequest | None = None,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> RunRead:
    """Continue an interrupted or finished run from its persisted knowledge: work
    orders, evidence, hypotheses and agent-written tools are kept, done work is not
    repeated. The scope is the run's own snapshot and cannot change."""
    if gb_settings.settings().greybox_executor == "off":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Grey-box executor is not running")
    run = await get_run_or_404(session, user, run_id)
    async with sqlite_write_lock(session):
        try:
            run = await gb_service.resume_run(
                session, run, user_id=user.id,
                limits=payload.model_dump(exclude_none=True) if payload else None)
        except RunStartError as exc:
            raise HTTPException(status_code=exc.status_code,
                                detail=exc.detail) from None
        await session.commit()
        await session.refresh(run)
    return await _run_read(session, run)


@router.delete("/runs/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_run(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    run = await get_run_or_404(session, user, run_id)
    if run.status not in GB_TERMINAL:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Run is not finished")
    await gb_service.purge_runs(session, [run.id])
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------- report


@router.get("/runs/{run_id}/report", response_model=ReportRead)
async def read_report(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> ReportRead:
    run = await get_run_or_404(session, user, run_id)
    row = await session.get(GreyboxReport, run.id)
    if row is None:
        return ReportRead(status="pending", markdown=None, generated_at=None,
                          error=None)
    return ReportRead(status=row.status, markdown=row.markdown,
                      generated_at=as_utc(row.generated_at), error=row.error)


@router.get("/runs/{run_id}/report/download")
async def download_report(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    run = await get_run_or_404(session, user, run_id)
    row = await session.get(GreyboxReport, run.id)
    if row is None or row.status != "ready" or not row.markdown:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Report is not ready")
    filename = f"greybox-report-{str(run.id)[:8]}.md"
    return Response(
        content=row.markdown, media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'})
