"""Unified cross-mode list ``GET /analyses``.

White-box rows: visibility from ``src.webapi.acl.accessible_repo_ids`` (existing ACL,
unchanged), status/phase as stored on the ``Run`` row (never ``engine.refresh``),
findings from ``RunMetrics`` (null without a metrics row).

Grey-box rows (only when the feature flag is on): owner/admin ACL, findings counted
from ``greybox_findings`` (candidate + verified).

Both sources are queried in SQL ordered by ``created_at desc`` and merged; the cursor is
``(created_at, mode, id)``.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import settings as gb_settings
from src.greybox_web.acl import is_admin
from src.greybox_web.models import GreyboxFinding, GreyboxRun, GreyboxTarget
from src.greybox_web.pagination import (
    as_utc,
    clamp_limit,
    decode_cursor,
    encode_cursor,
    parse_ts,
    parse_uuid,
)
from src.greybox_web.schemas import (
    SEVERITIES,
    AnalysesPage,
    AnalysisFindings,
    AnalysisItem,
    AnalysisSubject,
)
from src.webapi.acl import accessible_repo_ids
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import Job, Repository, Run, RunMetrics, User

router = APIRouter(tags=["analyses"])

Cursor = tuple[datetime, str, uuid.UUID]


def _after(created_col, id_col, mode: str, cur: Cursor | None):
    """SQL condition for rows of ``mode`` whose key (created_at, mode, id) sorts
    strictly below the cursor in descending order."""
    if cur is None:
        return None
    ts, c_mode, c_id = cur
    if mode < c_mode:
        return created_col <= ts
    if mode > c_mode:
        return created_col < ts
    return or_(created_col < ts, and_(created_col == ts, id_col < c_id))


def _duration(started: datetime | None, finished: datetime | None) -> int | None:
    if started is None:
        return None
    end = finished or datetime.now(timezone.utc)
    return max(0, int((end - started).total_seconds()))


async def _whitebox(session: AsyncSession, user: User, statuses: list[str] | None,
                    q: str | None, cur: Cursor | None, n: int) -> list[AnalysisItem]:
    allowed = await accessible_repo_ids(session, user)
    if allowed is not None and not allowed:
        return []
    stmt = (
        select(Run, Job, Repository, RunMetrics)
        .join(Job, Job.id == Run.job_id)
        .join(Repository, Repository.id == Job.repository_id)
        .outerjoin(RunMetrics, RunMetrics.run_id == Run.id)
    )
    if allowed is not None:
        stmt = stmt.where(Job.repository_id.in_(allowed))
    if statuses:
        stmt = stmt.where(Run.status.in_(statuses))
    if q:
        stmt = stmt.where(or_(Job.name.icontains(q, autoescape=True),
                              Repository.name.icontains(q, autoescape=True)))
    cond = _after(Run.created_at, Run.id, "whitebox", cur)
    if cond is not None:
        stmt = stmt.where(cond)
    stmt = stmt.order_by(Run.created_at.desc(), Run.id.desc()).limit(n + 1)
    out = []
    for run, job, repo, m in (await session.execute(stmt)).all():
        started, finished = as_utc(run.started_at), as_utc(run.finished_at)
        findings = None
        if m is not None:
            findings = AnalysisFindings(total=m.total_findings, by_severity={
                "critical": m.critical, "high": m.high, "medium": m.medium,
                "low": m.low, "info": m.informational})
        out.append(AnalysisItem(
            mode="whitebox", id=run.id, name=job.name,
            subject=AnalysisSubject(type="repository", id=repo.id, name=repo.name),
            status=run.status, phase=run.current_phase,
            owner_id=run.triggered_by or job.created_by,
            created_at=as_utc(run.created_at), started_at=started, finished_at=finished,
            duration_s=_duration(started, finished), findings=findings,
            href=f"/runs/{run.id}",
        ))
    return out


async def _greybox(session: AsyncSession, user: User, statuses: list[str] | None,
                   q: str | None, cur: Cursor | None, n: int) -> list[AnalysisItem]:
    stmt = select(GreyboxRun, GreyboxTarget).join(
        GreyboxTarget, GreyboxTarget.id == GreyboxRun.target_id)
    if not is_admin(user):
        stmt = stmt.where(GreyboxRun.owner_id == user.id)
    if statuses:
        stmt = stmt.where(GreyboxRun.status.in_(statuses))
    if q:
        stmt = stmt.where(or_(GreyboxTarget.name.icontains(q, autoescape=True),
                              GreyboxTarget.base_url.icontains(q, autoescape=True)))
    cond = _after(GreyboxRun.created_at, GreyboxRun.id, "greybox", cur)
    if cond is not None:
        stmt = stmt.where(cond)
    stmt = stmt.order_by(GreyboxRun.created_at.desc(), GreyboxRun.id.desc()).limit(n + 1)
    rows = (await session.execute(stmt)).all()
    counts: dict[uuid.UUID, dict[str, int]] = {}
    if rows:
        agg = await session.execute(
            select(GreyboxFinding.run_id, GreyboxFinding.severity, func.count())
            .where(GreyboxFinding.run_id.in_([r.id for r, _ in rows]),
                   GreyboxFinding.status.in_(("candidate", "verified")))
            .group_by(GreyboxFinding.run_id, GreyboxFinding.severity))
        for run_id, sev, cnt in agg.all():
            counts.setdefault(run_id, {})[sev] = int(cnt)
    out = []
    for run, target in rows:
        started, finished = as_utc(run.started_at), as_utc(run.finished_at)
        by_sev = {s: counts.get(run.id, {}).get(s, 0) for s in SEVERITIES}
        out.append(AnalysisItem(
            mode="greybox", id=run.id, name=target.name,
            subject=AnalysisSubject(type="target", id=target.id, name=target.name,
                                    base_url=target.base_url),
            status=run.status, phase=run.phase, owner_id=run.owner_id,
            created_at=as_utc(run.created_at), started_at=started, finished_at=finished,
            duration_s=_duration(started, finished),
            findings=AnalysisFindings(total=sum(by_sev.values()), by_severity=by_sev),
            href=f"/greybox/runs/{run.id}",
        ))
    return out


def _key(item: AnalysisItem) -> tuple[Any, ...]:
    return (item.created_at, item.mode, item.id)


@router.get("/analyses", response_model=AnalysesPage)
async def list_analyses(
    mode: Literal["all", "whitebox", "greybox"] = "all",
    status: str | None = Query(default=None, max_length=200,
                               description="Status, or comma-separated statuses"),
    q: str | None = Query(default=None, max_length=200),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None, max_length=300),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> AnalysesPage:
    n = clamp_limit(limit)
    cur: Cursor | None = None
    if cursor:
        ts_s, c_mode, id_s = decode_cursor(cursor, 3)
        if c_mode not in ("whitebox", "greybox"):
            raise HTTPException(status_code=422, detail="Invalid cursor")
        cur = (parse_ts(ts_s), c_mode, parse_uuid(id_s))
    statuses = [s.strip() for s in status.split(",") if s.strip()] if status else None

    items: list[AnalysisItem] = []
    if mode in ("all", "whitebox"):
        items += await _whitebox(session, user, statuses, q, cur, n)
    if mode in ("all", "greybox") and gb_settings.enabled():
        items += await _greybox(session, user, statuses, q, cur, n)
    items.sort(key=_key, reverse=True)
    next_cursor = None
    if len(items) > n:
        items = items[:n]
        last = items[-1]
        next_cursor = encode_cursor(last.created_at, last.mode, last.id)
    return AnalysesPage(items=items, next_cursor=next_cursor)
