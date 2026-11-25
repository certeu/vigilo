"""Findings of a run: list and detail. Read-only, owner/admin only.

Stored rows are redacted at write time; excerpts are re-checked against the secret
registry on the way out. Every query is scoped to the run.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import redaction
from src.greybox_web import correlation
from src.greybox_web.acl import NOT_FOUND, get_run_or_404
from src.greybox_web import findclass
from src.greybox_web.models import GreyboxAgent, GreyboxAsset, GreyboxDefense, GreyboxFinding
from src.greybox_web.pagination import as_utc
from src.greybox_web.schemas import (
    SEVERITIES,
    AffectedAsset,
    FindingHintRead,
    FindingEvidenceRead,
    FindingList,
    FindingLocation,
    FindingProvenance,
    FindingRead,
    FindingReference,
    FindingStatus,
    FindingSummaryRead,
    FindingVerificationRead,
    Severity,
)
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import User

router = APIRouter(prefix="/greybox", tags=["greybox"])

_SEVERITY_RANK = case({s: i for i, s in enumerate(SEVERITIES)},
                      value=GreyboxFinding.severity, else_=len(SEVERITIES))


def _t(value: Any) -> Any:
    return redaction.text(value) if isinstance(value, str) else value


async def _agent_names(session: AsyncSession, run_id: uuid.UUID) -> dict[uuid.UUID, str]:
    rows = await session.execute(
        select(GreyboxAgent.id, GreyboxAgent.name).where(GreyboxAgent.run_id == run_id))
    return {i: n for i, n in rows.all()}


async def _assets(session: AsyncSession, run_id: uuid.UUID,
                  ids: set[uuid.UUID]) -> dict[uuid.UUID, AffectedAsset]:
    if not ids:
        return {}
    rows = await session.execute(select(GreyboxAsset.id, GreyboxAsset.kind, GreyboxAsset.label)
                                 .where(GreyboxAsset.run_id == run_id,
                                        GreyboxAsset.id.in_(ids)))
    return {i: AffectedAsset(id=i, kind=k, label=lbl) for i, k, lbl in rows.all()}


async def _defense_ids(session: AsyncSession, run_id: uuid.UUID
                       ) -> dict[uuid.UUID, list[uuid.UUID]]:
    rows = await session.execute(
        select(GreyboxDefense.finding_id, GreyboxDefense.id)
        .where(GreyboxDefense.run_id == run_id)
        .order_by(GreyboxDefense.created_at, GreyboxDefense.id))
    out: dict[uuid.UUID, list[uuid.UUID]] = {}
    for fid, did in rows.all():
        out.setdefault(fid, []).append(did)
    return out


def _summary(f: GreyboxFinding, agents: dict, assets: dict, defenses: dict,
             issue: dict | None = None) -> dict:
    issue = issue or {}
    return dict(
        id=f.id, title=f.title, severity=f.severity, status=f.status,
        confidence=f.confidence, check_id=f.check_id,
        affected_asset=assets.get(f.affected_asset_id) if f.affected_asset_id else None,
        agent_name=agents.get(f.agent_id) if f.agent_id else None,
        evidence_count=len(f.evidence or []),
        defense_count=len(defenses.get(f.id, [])),
        created_at=as_utc(f.created_at), updated_at=as_utc(f.updated_at),
        finding_class=f.finding_class or findclass.classify(f.check_id),
        canonical_issue_id=f.canonical_issue_id,
        verification_status=issue.get("verification_status") or f.status,
        observation_count=issue.get("observation_count") or 0,
        affected_location_count=issue.get("affected_location_count") or 0)


@router.get("/runs/{run_id}/canonical-issues")
async def list_canonical_issues(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    run = await get_run_or_404(session, user, run_id)
    return {"items": await correlation.candidate_issue_summaries(session, run.id)}


@router.get("/runs/{run_id}/canonical-issues/{canonical_issue_id}")
async def get_canonical_issue(
    run_id: uuid.UUID,
    canonical_issue_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    run = await get_run_or_404(session, user, run_id)
    try:
        return await correlation.inspect_issue(
            session, run.id, canonical_issue_id=canonical_issue_id)
    except correlation.CorrelationNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND) from None


@router.post("/runs/{run_id}/finding-actions")
async def apply_finding_action(
    run_id: uuid.UUID,
    action: str = Body(embed=True),
    params: dict = Body(default_factory=dict),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """Agent action API; explorer code normally calls correlation helpers directly."""
    run = await get_run_or_404(session, user, run_id)
    try:
        result = await correlation.apply_agent_action(session, run.id, action, params)
        await session.commit()
        return result
    except correlation.CorrelationNotFound:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND) from None
    except correlation.CorrelationConflict as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from None
    except correlation.CorrelationError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=str(exc)) from None


@router.get("/runs/{run_id}/findings", response_model=FindingList)
async def list_findings(
    run_id: uuid.UUID,
    status_: FindingStatus | None = Query(None, alias="status"),
    severity: Severity | None = None,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> FindingList:
    run = await get_run_or_404(session, user, run_id)
    stmt = select(GreyboxFinding).where(GreyboxFinding.run_id == run.id)
    if status_ is not None:
        stmt = stmt.where(GreyboxFinding.status == status_)
    if severity is not None:
        stmt = stmt.where(GreyboxFinding.severity == severity)
    rows = (await session.scalars(stmt.order_by(
        _SEVERITY_RANK, GreyboxFinding.created_at, GreyboxFinding.id))).all()
    agents = await _agent_names(session, run.id)
    assets = await _assets(session, run.id,
                           {f.affected_asset_id for f in rows if f.affected_asset_id})
    defenses = await _defense_ids(session, run.id)
    issue_rows = await correlation.candidate_issue_summaries(session, run.id)
    issues = {uuid.UUID(item["canonical_issue_id"]): item for item in issue_rows}
    return FindingList(items=[FindingSummaryRead(**_summary(
                                  f, agents, assets, defenses,
                                  issues.get(f.canonical_issue_id)))
                              for f in rows])


@router.get("/runs/{run_id}/findings/{finding_id}", response_model=FindingRead)
async def get_finding(
    run_id: uuid.UUID,
    finding_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> FindingRead:
    run = await get_run_or_404(session, user, run_id)
    f = await session.get(GreyboxFinding, finding_id)
    if f is None or f.run_id != run.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
    agents = await _agent_names(session, run.id)
    assets = await _assets(session, run.id,
                           {f.affected_asset_id} if f.affected_asset_id else set())
    defenses = await _defense_ids(session, run.id)
    loc = f.location or {}
    v = f.verification
    issue = await correlation.inspect_issue(
        session, run.id, canonical_issue_id=f.canonical_issue_id) \
        if f.canonical_issue_id else {}
    history = issue.get("correlation_history") or []
    return FindingRead(
        **_summary(f, agents, assets, defenses, issue),
        run_id=f.run_id, description=_t(f.description) or "", cwe=f.cwe,
        remediation=f.remediation or findclass.default_remediation(f.check_id, f.title),
        location=FindingLocation(url=_t(loc.get("url") or ""), method=loc.get("method") or "",
                                 parameter=_t(loc.get("parameter"))),
        evidence=[FindingEvidenceRead(
            role=e.get("role", "proof"), exchange_id=e.get("exchange_id"),
            excerpt=_t(e.get("excerpt") or "") or "", note=_t(e.get("note")))
            for e in (f.evidence or [])],
        verification=None if not v else FindingVerificationRead(
            method=v.get("method", ""), attempts=v.get("attempts", 1),
            result=v.get("result", "not_reproduced"),
            exchange_ids=list(v.get("exchange_ids") or []),
            verified_at=v.get("verified_at"), agent_id=v.get("agent_id"),
            work_order_id=v.get("work_order_id")),
        detection_hints=[FindingHintRead(type=x.get("type", ""), title=_t(x.get("title") or ""),
                                         content=_t(x.get("content") or ""))
                         for x in (f.detection_hints or [])],
        references=[FindingReference(title=r.get("title", ""), url=r.get("url", ""))
                    for r in (f.references or [])],
        provenance=FindingProvenance(
            agent_id=f.agent_id, agent_name=agents.get(f.agent_id) if f.agent_id else None,
            work_order_id=f.work_order_id, node_id=f.node_id,
            first_event_seq=f.first_event_seq),
        defense_ids=defenses.get(f.id, []),
        affected_locations=issue.get("affected_locations") or [],
        findings=issue.get("findings") or [], root_cause=issue.get("root_cause"),
        correlation_rationale=history[-1]["rationale"] if history else None,
        correlation_history=history,
        retesting_guidance=issue.get("retesting_guidance"))
