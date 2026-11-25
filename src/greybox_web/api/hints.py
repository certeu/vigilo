"""Analyst steering for running scans: post and list hints.

A hint is untrusted text: it is redacted like event text, stored as plain text and
capped. It never widens what a run may do. The planner (not this module) applies it,
and only by reordering, skipping or adding *in-scope* work through the usual
dedup, budgets and guarded client.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import events, redaction, wakeup
from src.greybox_web.acl import get_run_or_404
from src.greybox_web.graph import GraphStats, GraphTx
from src.greybox_web.models import (
    GB_TERMINAL,
    GreyboxGraphNode,
    GreyboxHint,
    GreyboxRun,
)
from src.greybox_web.pagination import as_utc
from src.greybox_web.schemas import HINT_TEXT_MAX, HintCreate, HintList, HintRead
from src.greybox_web.txn import sqlite_write_lock
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import User

router = APIRouter(prefix="/greybox", tags=["greybox"])

HINTS_PER_MINUTE = 10
NODE_LABEL_CHARS = 80


def _read(h: GreyboxHint, about_label: str | None = None) -> HintRead:
    return HintRead(
        id=h.id, run_id=h.run_id, text=h.text, action=h.action, target=h.target,
        about_node_id=h.about_node_id, node_id=h.node_id, status=h.status,
        result=h.result,
        work_order_ids=[uuid.UUID(str(i)) for i in (h.work_order_ids or [])],
        created_by=h.created_by, created_by_name=h.created_by_name,
        created_at=as_utc(h.created_at), addressed_at=as_utc(h.addressed_at),
        reply=h.reply, replied_at=as_utc(h.replied_at), reply_cycle=h.reply_cycle,
        seen_cycle=h.seen_cycle, about_label=about_label)


def _conflict() -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Run already finished")


@router.post("/runs/{run_id}/hints", response_model=HintRead,
             status_code=status.HTTP_201_CREATED)
async def add_hint(
    run_id: uuid.UUID,
    payload: HintCreate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> HintRead:
    run = await get_run_or_404(session, user, run_id)
    if run.status in GB_TERMINAL:
        raise _conflict()
    about = None
    if payload.about_node_id is not None:
        about = await session.get(GreyboxGraphNode, payload.about_node_id)
        if about is None or about.run_id != run_id:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="about_node_id: unknown node for this run")
    user_id, user_name = user.id, user.email
    text = (redaction.scrub(payload.text) or "")[:HINT_TEXT_MAX]
    target = events.clip(payload.target, 2000) if payload.target else None
    now = datetime.now(timezone.utc)

    async with sqlite_write_lock(session):
        # Atomic "run is not terminal" guard that also takes the run row lock, so a
        # hint can never be recorded after the terminal event.
        res = await session.execute(
            update(GreyboxRun)
            .where(GreyboxRun.id == run_id, GreyboxRun.status.not_in(tuple(GB_TERMINAL)))
            .values(last_seq=GreyboxRun.last_seq)
            .execution_options(synchronize_session=False))
        if res.rowcount != 1:
            raise _conflict()
        recent = int(await session.scalar(
            select(func.count()).select_from(GreyboxHint).where(
                GreyboxHint.run_id == run_id,
                GreyboxHint.created_at > now - timedelta(minutes=1))) or 0)
        if recent >= HINTS_PER_MINUTE:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"At most {HINTS_PER_MINUTE} hints per minute per run",
                headers={"Retry-After": "60"})
        hint = GreyboxHint(
            id=uuid.uuid4(), run_id=run_id, text=text, action=payload.action,
            target=target, about_node_id=payload.about_node_id, status="open",
            result=None, work_order_ids=[], created_by=user_id,
            created_by_name=user_name, created_at=now)
        session.add(hint)
        stats = GraphStats()
        gtx = GraphTx(session, run_id, stats)
        node = await gtx.node(
            "hint", f"hint:{hint.id}", text[:NODE_LABEL_CHARS], "open",
            data={"action": payload.action, "target": target,
                  "created_by_name": user_name})
        hint.node_id = node.id
        if about is not None:
            await gtx.edge(node, about, "guides")
        ev = await events.emit(
            session, run_id, "hint.added", f"hint added: {payload.action}"
            + (f" {target}" if target else ""),
            data={"hint_id": str(hint.id), "action": payload.action, "target": target,
                  "text": text,
                  "about_node_id": str(payload.about_node_id)
                  if payload.about_node_id else None},
            refs={"node_ids": [node.id]})
        node.event_seq = ev.seq
        node.last_event_seq = ev.seq
        version = int(await session.scalar(
            select(GreyboxRun.graph_version).where(GreyboxRun.id == run_id)) or 0)
        await events.emit(session, run_id, "graph.updated", "graph updated",
                          data={"version": version, **stats.take()})
        await session.commit()
        await session.refresh(hint)
    wakeup.notify(run_id)         # in-process supervisor reacts now; others poll
    return _read(hint, about.label if about is not None else None)


@router.get("/runs/{run_id}/hints", response_model=HintList)
async def list_hints(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> HintList:
    await get_run_or_404(session, user, run_id)
    rows = (await session.scalars(
        select(GreyboxHint).where(GreyboxHint.run_id == run_id)
        .order_by(GreyboxHint.created_at, GreyboxHint.id))).all()
    about_ids = {h.about_node_id for h in rows if h.about_node_id is not None}
    labels: dict[uuid.UUID, str] = {}
    if about_ids:
        labels = dict((await session.execute(
            select(GreyboxGraphNode.id, GreyboxGraphNode.label).where(
                GreyboxGraphNode.run_id == run_id,
                GreyboxGraphNode.id.in_(about_ids)))).all())
    return HintList(items=[_read(h, labels.get(h.about_node_id)) for h in rows])
