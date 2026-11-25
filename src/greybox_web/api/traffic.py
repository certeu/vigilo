"""Captured HTTP exchanges of a run: filtered list and detail.

Read-only, owner/admin only. Rows are redacted at write time; headers and bodies are
passed through the secret registry once more on the way out.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import redaction
from src.greybox_web.acl import NOT_FOUND, get_run_or_404
from src.greybox_web.models import GreyboxAgent, GreyboxFinding, GreyboxHttpExchange
from src.greybox_web.pagination import as_utc
from src.greybox_web.schemas import (
    ExchangeList,
    ExchangeRead,
    ExchangeSide,
    ExchangeSummaryRead,
)
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import User

router = APIRouter(prefix="/greybox", tags=["greybox"])

MAX_INT = 2**63 - 1
DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def _t(value: str | None) -> str | None:
    return redaction.text(value) if value is not None else None


def _headers(items: Any) -> list[tuple[str, str]]:
    out = []
    for p in items or []:
        if isinstance(p, (list, tuple)) and len(p) >= 2:
            out.append((str(p[0]), _t(str(p[1])) or ""))
    return out


async def _finding_links(session: AsyncSession, run_id: uuid.UUID
                         ) -> dict[int, list[uuid.UUID]]:
    """exchange id -> finding ids, from evidence[*].exchange_id and verification ids."""
    rows = await session.execute(
        select(GreyboxFinding.id, GreyboxFinding.evidence, GreyboxFinding.verification)
        .where(GreyboxFinding.run_id == run_id)
        .order_by(GreyboxFinding.created_at, GreyboxFinding.id))
    out: dict[int, list[uuid.UUID]] = {}
    for fid, evidence, verification in rows.all():
        ids = {e.get("exchange_id") for e in (evidence or []) if isinstance(e, dict)}
        ids |= set((verification or {}).get("exchange_ids") or [])
        for xid in ids:
            if isinstance(xid, int) and fid not in out.setdefault(xid, []):
                out[xid].append(fid)
    return out


def _summary(x: GreyboxHttpExchange, agents: dict, links: dict) -> dict:
    return dict(
        id=x.id, ts=as_utc(x.ts), method=x.method, scheme=x.scheme, host=x.host,
        port=x.port, path=x.path, status_code=x.status_code, duration_ms=x.duration_ms,
        content_type=x.content_type, response_size=x.response_size, tool=x.tool,
        agent_id=x.agent_id, agent_name=agents.get(x.agent_id) if x.agent_id else None,
        work_order_id=x.work_order_id, blocked=x.blocked, block_reason=x.block_reason,
        error=_t(x.error), redirect_hop=x.redirect_hop, finding_ids=links.get(x.id, []))


async def _agents(session: AsyncSession, run_id: uuid.UUID) -> dict[uuid.UUID, str]:
    rows = await session.execute(
        select(GreyboxAgent.id, GreyboxAgent.name).where(GreyboxAgent.run_id == run_id))
    return {i: n for i, n in rows.all()}


@router.get("/runs/{run_id}/traffic", response_model=ExchangeList)
async def list_traffic(
    run_id: uuid.UUID,
    method: str | None = Query(None, max_length=10),
    status_code: int | None = Query(None, ge=0, le=MAX_INT),
    host: str | None = Query(None, max_length=255),
    path_prefix: str | None = Query(None, max_length=1000),
    agent_id: uuid.UUID | None = None,
    work_order_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
    blocked: bool | None = None,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    after_id: int | None = Query(None, ge=0, le=MAX_INT),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> ExchangeList:
    run = await get_run_or_404(session, user, run_id)
    links = await _finding_links(session, run.id)
    stmt = select(GreyboxHttpExchange).where(GreyboxHttpExchange.run_id == run.id)
    if method:
        stmt = stmt.where(GreyboxHttpExchange.method == method.upper())
    if status_code is not None:
        stmt = stmt.where(GreyboxHttpExchange.status_code == status_code)
    if host:
        stmt = stmt.where(GreyboxHttpExchange.host == host.lower())
    if path_prefix:
        stmt = stmt.where(GreyboxHttpExchange.path.startswith(path_prefix, autoescape=True))
    if agent_id is not None:
        stmt = stmt.where(GreyboxHttpExchange.agent_id == agent_id)
    if work_order_id is not None:
        stmt = stmt.where(GreyboxHttpExchange.work_order_id == work_order_id)
    if finding_id is not None:
        ids = [xid for xid, fids in links.items() if finding_id in fids]
        stmt = stmt.where(GreyboxHttpExchange.id.in_(ids))
    if blocked is not None:
        stmt = stmt.where(GreyboxHttpExchange.blocked == blocked)
    if after_id is not None:
        stmt = stmt.where(GreyboxHttpExchange.id > after_id)
    rows = list((await session.scalars(
        stmt.order_by(GreyboxHttpExchange.id).limit(limit + 1))).all())
    more = len(rows) > limit
    rows = rows[:limit]
    agents = await _agents(session, run.id)
    return ExchangeList(
        items=[ExchangeSummaryRead(**_summary(x, agents, links)) for x in rows],
        next_after_id=rows[-1].id if more and rows else None, capture="enabled")


@router.get("/runs/{run_id}/traffic/{exchange_id}", response_model=ExchangeRead)
async def get_exchange(
    run_id: uuid.UUID,
    exchange_id: int,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> ExchangeRead:
    run = await get_run_or_404(session, user, run_id)
    x = None
    if 0 <= exchange_id <= MAX_INT:
        x = await session.get(GreyboxHttpExchange, exchange_id)
    if x is None or x.run_id != run.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
    links = await _finding_links(session, run.id)
    agents = await _agents(session, run.id)
    return ExchangeRead(
        **_summary(x, agents, links), url=_t(x.url) or "", resolved_ip=x.resolved_ip,
        parent_exchange_id=x.parent_exchange_id,
        request=ExchangeSide(
            headers=_headers(x.request_headers), body=_t(x.request_body),
            body_truncated=x.request_body_truncated, body_omitted_reason=None),
        response=ExchangeSide(
            headers=_headers(x.response_headers), body=_t(x.response_body),
            body_truncated=x.response_body_truncated,
            body_omitted_reason=x.body_omitted_reason))
