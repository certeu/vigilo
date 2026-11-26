"""EventSink: the single emit point for grey-box run events.

``emit`` must be called inside the write transaction that performs the related state
change. It allocates the per-run ``seq`` with
``UPDATE greybox_runs SET last_seq = last_seq + 1 ... RETURNING last_seq`` (row lock on
Postgres, serialised writer on SQLite; see :mod:`src.greybox_web.txn`), so ``seq``
starts at 1 and is contiguous per run. Text is redacted and ``data`` is capped before
the insert.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import redaction
from src.greybox_web.models import GreyboxAgent, GreyboxEvent, GreyboxRun

LEVELS = ("debug", "info", "warning", "error")
SOURCES = ("system", "planner", "agent", "api")
STATUSES = ("ok", "error", "blocked", "pending", "skipped", "cancelled")

# kind -> (default source, level, status).
KINDS: dict[str, tuple[str, str, str | None]] = {
    "run.queued": ("api", "info", "pending"),
    # An interrupted/finished run continues from its persisted knowledge.
    "run.resumed": ("api", "info", "pending"),
    # Methodology: a skill playbook loaded / definition-of-done claims made.
    "skill.loaded": ("agent", "info", "ok"),
    "skill.criteria": ("agent", "info", None),
    "model.updated": ("agent", "info", None),
    "run.started": ("system", "info", "ok"),
    "run.phase": ("system", "info", "ok"),
    "run.cancel_requested": ("api", "warning", "pending"),
    "run.cancelled": ("system", "warning", "cancelled"),
    "run.completed": ("system", "info", "ok"),
    "run.failed": ("system", "error", "error"),
    "run.budget_exhausted": ("system", "warning", "skipped"),
    "planner.decision": ("planner", "info", "ok"),
    "llm.request": ("agent", "info", "pending"),
    "llm.response": ("agent", "info", "ok"),
    "llm.failed": ("agent", "error", "error"),
    "agent.started": ("agent", "info", "ok"),
    "agent.finished": ("agent", "info", "ok"),
    "agent.failed": ("agent", "error", "error"),
    "work_order.created": ("planner", "info", "pending"),
    "work_order.claimed": ("agent", "info", "ok"),
    "work_order.completed": ("agent", "info", "ok"),
    "work_order.failed": ("agent", "error", "error"),
    "work_order.skipped": ("planner", "info", "skipped"),
    "hint.added": ("api", "info", "pending"),
    "hint.addressed": ("planner", "info", "ok"),
    "hint.rejected": ("planner", "warning", "skipped"),
    "hint.replied": ("agent", "info", "ok"),
    "tool.started": ("agent", "info", "pending"),
    "tool.succeeded": ("agent", "info", "ok"),
    "tool.failed": ("agent", "error", "error"),
    # batch E: a run-defined dynamic instrument became available (admission emitted
    # it right after registering the instrument and its verify entry)
    "tool.defined": ("planner", "info", "ok"),
    "http.exchange": ("agent", "debug", "ok"),
    "scope.blocked": ("agent", "warning", "blocked"),
    "observation.recorded": ("agent", "info", "ok"),
    # Authentication boundary: the run met an identity provider, an
    # expired session or a login screen. Never "completed" on top of this.
    "auth.state": ("agent", "warning", "blocked"),
    # The completion verdict: what the run did and did not cover.
    "coverage.verdict": ("system", "warning", "ok"),
    "asset.discovered": ("agent", "info", "ok"),
    "graph.updated": ("system", "debug", "ok"),
    "surface.updated": ("agent", "debug", "ok"),
    "finding.created": ("agent", "warning", "pending"),
    "finding.verified": ("agent", "warning", "ok"),
    "finding.rejected": ("agent", "info", "skipped"),
    "defense.proposed": ("agent", "info", "ok"),
    "report.started": ("agent", "info", "pending"),
    "report.ready": ("agent", "info", "ok"),
    "report.failed": ("agent", "error", "error"),
    "log.warning": ("system", "warning", None),
    "log.error": ("system", "error", None),
}
TERMINAL_KINDS = frozenset({"run.completed", "run.failed", "run.cancelled"})

SUMMARY_MAX = 300
DATA_MAX_BYTES = 16 * 1024


def _refs(refs: dict[str, Any] | None) -> dict[str, Any]:
    r = refs or {}
    return {
        "node_ids": [str(x) for x in (r.get("node_ids") or [])],
        "asset_ids": [str(x) for x in (r.get("asset_ids") or [])],
        "finding_id": str(r["finding_id"]) if r.get("finding_id") else None,
        "exchange_ids": [int(x) for x in (r.get("exchange_ids") or [])],
    }


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def cap_data(data: dict[str, Any] | None, limit: int = DATA_MAX_BYTES) -> dict[str, Any]:
    """Redacted, JSON-safe ``data`` of at most ``limit`` serialised bytes."""
    clean = redaction.structured(_jsonable(data or {}))
    raw = json.dumps(clean)
    if len(raw.encode()) <= limit:
        return clean
    # Keep scalar fields, drop the large ones, and flag the truncation.
    out: dict[str, Any] = {"_truncated": True}
    budget = limit - 64
    for k, v in clean.items():
        piece = json.dumps({k: v})
        if len(piece.encode()) < budget // 4:
            out[k] = v
            budget -= len(piece.encode())
    return out


def clip(text: str | None, n: int) -> str:
    t = redaction.scrub(text or "") or ""
    return t if len(t) <= n else t[: n - 1] + "…"


async def next_seq(session: AsyncSession, run_id: uuid.UUID) -> int:
    res = await session.execute(
        update(GreyboxRun).where(GreyboxRun.id == run_id)
        .values(last_seq=GreyboxRun.last_seq + 1)
        .returning(GreyboxRun.last_seq)
        .execution_options(synchronize_session=False))
    seq = res.scalar_one_or_none()
    if seq is None:
        raise LookupError(f"run {run_id} not found")
    return int(seq)


async def emit(session: AsyncSession, run_id: uuid.UUID, kind: str, summary: str, *,
               data: dict[str, Any] | None = None, refs: dict[str, Any] | None = None,
               source: str | None = None, level: str | None = None,
               status: str | None = ..., agent_id: uuid.UUID | None = None,
               work_order_id: uuid.UUID | None = None, tool_call_id: str | None = None,
               duration_ms: int | None = None) -> GreyboxEvent:
    if kind not in KINDS:
        raise ValueError(f"unknown event kind {kind!r}")
    d_source, d_level, d_status = KINDS[kind]
    source = source or d_source
    level = level or d_level
    status = d_status if status is ... else status
    if source not in SOURCES or level not in LEVELS or (status is not None
                                                         and status not in STATUSES):
        raise ValueError(f"invalid envelope for {kind}: {source}/{level}/{status}")
    seq = await next_seq(session, run_id)
    ev = GreyboxEvent(
        run_id=run_id, seq=seq, ts=datetime.now(timezone.utc), kind=kind, level=level,
        source=source, agent_id=agent_id, work_order_id=work_order_id,
        tool_call_id=tool_call_id, summary=clip(summary, SUMMARY_MAX), status=status,
        duration_ms=duration_ms, refs=_refs(refs), data=cap_data(data),
    )
    session.add(ev)
    if agent_id is not None:
        await session.execute(
            update(GreyboxAgent).where(GreyboxAgent.id == agent_id,
                                       GreyboxAgent.run_id == run_id)
            .values(last_event_seq=seq).execution_options(synchronize_session=False))
    return ev
