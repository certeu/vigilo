"""Grey-box run events: history API and SSE stream.

The ``greybox_events`` table is the only source of truth: the stream polls it with a
fresh short-lived session per poll (no session or transaction is held between polls,
so the engine's SQLite writes are never blocked) and therefore works across
processes. Event kinds are passed through verbatim (no allowlist).
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web.acl import get_run_or_404
from src.greybox_web.events import LEVELS
from src.greybox_web.models import GB_TERMINAL, GreyboxAgent, GreyboxEvent, GreyboxRun
from src.greybox_web.pagination import as_utc
from src.greybox_web.schemas import EventPage, EventRefs, GreyboxEventOut
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import User

router = APIRouter(prefix="/greybox", tags=["greybox"])

DEFAULT_LIMIT = 200
MAX_LIMIT = 1000

# Stream tuning (module level so tests can patch them).
POLL_FAST_S = 0.25        # while the run is active and events are flowing
POLL_MAX_S = 1.0          # idle back-off ceiling
POLL_IDLE_AFTER_S = 5.0   # no events for this long -> start backing off
POLL_BACKOFF = 1.5
BATCH = 500
PING_S = 15.0
MAX_LIFETIME_S = 15 * 60
RETRY_MS = 3000
REVALIDATE_S = 5.0        # re-check the bearer token (exp, active, session_epoch)
MAX_SEQ = 2**63 - 1       # SQL BIGINT ceiling: larger cursors would 500 in the driver


def _event_out(ev: GreyboxEvent, names: dict[uuid.UUID, str]) -> GreyboxEventOut:
    r = ev.refs or {}
    return GreyboxEventOut(
        seq=ev.seq, run_id=ev.run_id, ts=as_utc(ev.ts), kind=ev.kind, level=ev.level,
        source=ev.source, agent_id=ev.agent_id,
        agent_name=names.get(ev.agent_id) if ev.agent_id else None,
        work_order_id=ev.work_order_id, tool_call_id=ev.tool_call_id,
        summary=ev.summary, status=ev.status, duration_ms=ev.duration_ms,
        refs=EventRefs(
            node_ids=[str(x) for x in (r.get("node_ids") or [])],
            asset_ids=[str(x) for x in (r.get("asset_ids") or [])],
            finding_id=str(r["finding_id"]) if r.get("finding_id") else None,
            exchange_ids=[int(x) for x in (r.get("exchange_ids") or [])]),
        data=ev.data or {})


async def _to_out(session: AsyncSession, run_id: uuid.UUID,
                  rows: list[GreyboxEvent]) -> list[GreyboxEventOut]:
    ids = {e.agent_id for e in rows if e.agent_id}
    names: dict[uuid.UUID, str] = {}
    if ids:
        res = await session.execute(select(GreyboxAgent.id, GreyboxAgent.name).where(
            GreyboxAgent.run_id == run_id, GreyboxAgent.id.in_(ids)))
        names = {i: n for i, n in res.all()}
    return [_event_out(e, names) for e in rows]


def _filters(run_id: uuid.UUID, kinds: str | None, agent_id: uuid.UUID | None,
             work_order_id: uuid.UUID | None, level: str | None, q: str | None) -> list:
    conds = [GreyboxEvent.run_id == run_id]
    if kinds:
        ks = [k.strip() for k in kinds.split(",") if k.strip()]
        if ks:
            conds.append(GreyboxEvent.kind.in_(ks))
    if agent_id is not None:
        conds.append(GreyboxEvent.agent_id == agent_id)
    if work_order_id is not None:
        conds.append(GreyboxEvent.work_order_id == work_order_id)
    if level:
        if level not in LEVELS:
            raise HTTPException(status_code=422, detail=f"level must be one of {LEVELS}")
        conds.append(GreyboxEvent.level.in_(LEVELS[LEVELS.index(level):]))
    if q:
        esc = q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conds.append(func.lower(GreyboxEvent.summary).like(f"%{esc}%", escape="\\"))
    return conds


@router.get("/runs/{run_id}/events", response_model=EventPage)
async def list_events(
    run_id: uuid.UUID,
    after_seq: int | None = Query(None, ge=0, le=MAX_SEQ),
    before_seq: int | None = Query(None, ge=0, le=MAX_SEQ),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    kinds: str | None = None,
    agent_id: uuid.UUID | None = None,
    work_order_id: uuid.UUID | None = None,
    level: str | None = None,
    q: str | None = None,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> EventPage:
    if after_seq is not None and before_seq is not None:
        raise HTTPException(status_code=422,
                            detail="after_seq and before_seq are mutually exclusive")
    run = await get_run_or_404(session, user, run_id)
    conds = _filters(run_id, kinds, agent_id, work_order_id, level, q)
    stmt = select(GreyboxEvent).where(*conds)
    if after_seq is not None:
        stmt = stmt.where(GreyboxEvent.seq > after_seq).order_by(GreyboxEvent.seq)
    else:
        if before_seq is not None:
            stmt = stmt.where(GreyboxEvent.seq < before_seq)
        stmt = stmt.order_by(GreyboxEvent.seq.desc())
    rows = list((await session.scalars(stmt.limit(limit + 1))).all())
    more = len(rows) > limit
    rows = rows[:limit]
    if after_seq is None:
        rows.reverse()

    async def any_where(*extra) -> bool:
        return bool(await session.scalar(select(exists().where(*conds, *extra))))

    if rows:
        lo, hi = rows[0].seq, rows[-1].seq
        before = more if after_seq is None else await any_where(GreyboxEvent.seq < lo)
        after = more if after_seq is not None else (
            before_seq is not None and await any_where(GreyboxEvent.seq > hi))
    else:
        before = (await any_where(GreyboxEvent.seq <= after_seq)) if after_seq else False
        if before_seq is not None:
            after = await any_where(GreyboxEvent.seq >= before_seq)
        else:
            after = False
    items = await _to_out(session, run_id, rows)
    await session.refresh(run)
    return EventPage(items=items, last_seq=run.last_seq, has_more_before=before,
                     has_more_after=after, run_status=run.status)


def _parse_cursor(value: str, what: str) -> int:
    try:
        n = int(value.strip())
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail=f"{what} must be an integer >= 0") from None
    if n < 0 or n > MAX_SEQ:
        raise HTTPException(status_code=422, detail=f"{what} must be an integer >= 0")
    return n


async def _poll(open_session, run_id: uuid.UUID, cursor: int):
    """One short-lived session: (run status, last_seq, events after cursor)."""
    async with open_session() as s:
        row = (await s.execute(select(GreyboxRun.status, GreyboxRun.last_seq)
                               .where(GreyboxRun.id == run_id))).first()
        if row is None:
            return None, cursor, []
        # Status is read BEFORE the events: a terminal status seen here implies the
        # terminal event is already committed and visible to the next read.
        rows = list((await s.scalars(
            select(GreyboxEvent).where(GreyboxEvent.run_id == run_id,
                                       GreyboxEvent.seq > cursor)
            .order_by(GreyboxEvent.seq).limit(BATCH))).all())
        out = await _to_out(s, run_id, rows)
        await s.rollback()
        return row[0], row[1], out


def _session_opener(request: Request):
    """Fresh session per call, honouring the app's session dependency (and any
    override of it), without holding it between polls."""
    dep = request.app.dependency_overrides.get(get_async_session, get_async_session)

    class _Ctx:
        def __init__(self) -> None:
            self.gen = dep()

        async def __aenter__(self) -> AsyncSession:
            return await self.gen.__anext__()

        async def __aexit__(self, *exc) -> None:
            await self.gen.aclose()

    return _Ctx


def _bearer_token(request: Request) -> str | None:
    scheme, _, value = (request.headers.get("authorization") or "").partition(" ")
    return value.strip() if scheme.lower() == "bearer" and value.strip() else None


async def _still_authorised(open_session, token: str) -> bool:
    from src.webapi.auth.backend import authenticate_bearer
    async with open_session() as s:
        try:
            return await authenticate_bearer(token, s) is not None
        finally:
            await s.rollback()


async def _stream(request: Request, run_id: uuid.UUID, cursor: int) -> AsyncIterator[str]:
    open_session = _session_opener(request)
    token = _bearer_token(request)
    next_check = time.monotonic() + REVALIDATE_S
    started = last_data = last_event = time.monotonic()
    yield f"retry: {RETRY_MS}\n\n"
    interval = POLL_FAST_S
    while True:
        if await request.is_disconnected():
            return
        if token is not None and time.monotonic() >= next_check:
            # Expired / revoked (logout, password change, deactivation) token: close
            # cleanly. The client's reconnect then gets a 401 and returns to /login.
            if not await _still_authorised(open_session, token):
                return
            next_check = time.monotonic() + REVALIDATE_S
        status, last_seq, events = await _poll(open_session, run_id, cursor)
        now = time.monotonic()
        if status is None:
            return
        for ev in events:
            cursor = ev.seq
            yield (f"id: {ev.seq}\nevent: event\n"
                   f"data: {ev.model_dump_json()}\n\n")
        if events:
            last_data = last_event = now
            interval = POLL_FAST_S
            if len(events) >= BATCH:
                continue   # full batch: more is waiting, no sleep
        elif status in GB_TERMINAL:
            yield ("event: end\ndata: "
                   + json.dumps({"status": status, "last_seq": last_seq}) + "\n\n")
            return
        else:
            if now - last_event > POLL_IDLE_AFTER_S:
                interval = min(interval * POLL_BACKOFF, POLL_MAX_S)
        if now - started >= MAX_LIFETIME_S:
            return
        if now - last_data >= PING_S:
            yield ": ping\n\n"
            last_data = now
        # Sleep, but never past the ping / lifetime deadlines.
        wait = min(interval, max(0.0, PING_S - (time.monotonic() - last_data)),
                   max(0.0, MAX_LIFETIME_S - (time.monotonic() - started)))
        await asyncio.sleep(wait)


@router.get("/runs/{run_id}/events/stream")
async def stream_events(
    run_id: uuid.UUID,
    request: Request,
    after: str | None = Query(None),
    last_event_id: str | None = Header(None, alias="Last-Event-ID"),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> StreamingResponse:
    await get_run_or_404(session, user, run_id)   # 404 before the stream opens
    # Release the request session now; the stream uses its own short sessions.
    await session.rollback()
    await session.close()
    if last_event_id is not None and last_event_id.strip() != "":
        cursor = _parse_cursor(last_event_id, "Last-Event-ID")
    elif after is not None:
        cursor = _parse_cursor(after, "after")
    else:
        cursor = 0
    return StreamingResponse(
        _stream(request, run_id, cursor), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
