"""Projection helpers for passive network signals, used by the supervisor.

* :func:`apply_specs` writes a tool's ``assets`` / ``edges`` into the asset graph
  (validated by ``graph.ASSET_KINDS`` / ``ASSET_RULES``).
* :func:`passive_verify` verifies a passive finding by re-reading the RECORDED exchange
  it cites (stored headers and body): no request is made.
* :class:`RecordedView` is the read-only seam a passive follow-up tool reads through
  (``ToolContext.recorded``).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.greybox_web import events, netview, redaction
from src.greybox_web.graph import GraphTx
from src.greybox_web.models import GreyboxAsset, GreyboxHttpExchange
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.tools import RecordedResponse
from src.greybox_web.txn import read as tx_read


async def apply_specs(gtx: GraphTx, assets: list, edges: list) -> None:
    """Upsert the assets, then the edges whose ends both exist (others are skipped).
    An unknown kind or relation raises ``GraphError`` (the work order fails)."""
    for a in assets:
        parent = await gtx.get_asset(*a.parent) \
            if getattr(a, "parent", None) else None
        row = await gtx.asset(a.kind, a.key, a.label, in_scope=a.in_scope,
                              data=a.data or None, parent=parent)
        if parent is not None and row.parent_id is None:
            row.parent_id = parent.id           # first seen without its parent
            await gtx.asset_edge(parent, row, "contains")
        if getattr(a, "tested", False) and a.in_scope:
            await gtx.mark_tested(row.id)
    for e in edges:
        src = await gtx.get_asset(*e.src)
        dst = await gtx.get_asset(*e.dst)
        if src is not None and dst is not None:
            await gtx.asset_edge(src, dst, e.rel)


async def rollup_redirect(gtx: GraphTx, src: GreyboxAsset, dst: GreyboxAsset) -> None:
    """Endpoint-to-endpoint redirect across services: roll it up to service level."""
    if src.parent_id is None or dst.parent_id is None or src.parent_id == dst.parent_id:
        return
    a = await gtx.s.get(GreyboxAsset, src.parent_id)
    b = await gtx.s.get(GreyboxAsset, dst.parent_id)
    if a is not None and b is not None and a.kind == b.kind == "service":
        await gtx.asset_edge(a, b, "redirects_to")


# ------------------------------------------------------------------ passive verification


def recheck(passive: dict[str, Any], row: GreyboxHttpExchange, scope: ScopePolicy) -> bool:
    """Does the recorded exchange still show what the finding claims? Pure."""
    from src.greybox_web.tools.discovery import parse_html
    check = passive.get("check")
    headers = row.response_headers or []
    body = row.response_body or ""
    ct = row.content_type or ""
    if check == "info.leak":
        want = str(passive.get("value") or "").lower()
        hits = netview.find_leaks(headers, body, ct, scope.host_allowed)
        return any(h["value"].lower() == want and h["internal"] for h in hits)
    if check in ("supply.no_sri", "supply.mixed_content"):
        if "html" not in ct.lower():
            return False
        raws = parse_html(body).resources
        url = str(passive.get("url") or "")
        for r in netview.classify_resources(row.url, raws, scope.host_allowed):
            if redaction.scrub(r["url"]) != redaction.scrub(url):
                continue
            if check == "supply.no_sri":
                return bool(r["tp"] and r["kind"] == "script" and not r["sri"])
            return bool(r["mixed"])
    return False


async def passive_verify(session: AsyncSession, gtx: GraphTx, finding, node, spec,
                         scope: ScopePolicy, *, agent_id, work_order_id) -> bool:
    """Verify ``finding`` by re-reading the recorded exchange (no network). True when
    the evidence reproduces; the finding is then ``verified``."""
    passive = spec.passive or {}
    ex_id = passive.get("exchange_id")
    row = await session.get(GreyboxHttpExchange, ex_id) if ex_id else None
    if row is None or row.run_id != finding.run_id or not recheck(passive, row, scope):
        return False
    finding.status = "verified"
    finding.verification = {
        "method": "passive re-check of the recorded exchange (no new request)",
        "attempts": 1, "result": "confirmed", "exchange_ids": [ex_id],
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "agent_id": str(agent_id), "work_order_id": str(work_order_id)}
    ev = await events.emit(
        session, finding.run_id, "finding.verified", f"verified: {finding.title}",
        level="warning",
        data={"finding_id": str(finding.id),
              "method": "passive re-check of the recorded exchange",
              "exchange_ids": [ex_id]},
        refs={"finding_id": finding.id, "node_ids": [node.id] if node else [],
              "exchange_ids": [ex_id]},
        agent_id=agent_id, work_order_id=work_order_id)
    if node is not None:
        node.status = "verified"
        node.last_event_seq = ev.seq
        node.version = await gtx.version()
    return True


# ------------------------------------------------------------------ recorded view


class RecordedView:
    """Read-only access to what the run already recorded. Performs no network I/O."""

    def __init__(self, factory: async_sessionmaker, run_id: uuid.UUID) -> None:
        self.factory = factory
        self.run_id = run_id

    async def responses(self, limit: int = 300) -> list[RecordedResponse]:
        async def fn(session: AsyncSession) -> list[RecordedResponse]:
            rows = (await session.scalars(
                select(GreyboxHttpExchange).where(
                    GreyboxHttpExchange.run_id == self.run_id,
                    GreyboxHttpExchange.blocked.is_(False),
                    GreyboxHttpExchange.status_code.is_not(None))
                .order_by(GreyboxHttpExchange.id).limit(max(1, min(limit, 1000))))).all()
            return [RecordedResponse(
                id=r.id, url=r.url, scheme=r.scheme, status=r.status_code,
                headers=[(str(k), str(v)) for k, v in (r.response_headers or [])],
                body=r.response_body, content_type=r.content_type) for r in rows]
        return await tx_read(self.factory, fn)

    async def query(self, *, contains: str | None = None, scheme: str | None = None,
                    method: str | None = None, limit: int = 20,
                    newest_first: bool = True) -> list[dict]:
        """Recorded exchanges of every protocol (http, tcp, dns), filtered: what a
        brokered tool may read back. Redacted at write time; read-only here."""
        async def fn(session: AsyncSession) -> list[dict]:
            q = select(GreyboxHttpExchange).where(
                GreyboxHttpExchange.run_id == self.run_id,
                GreyboxHttpExchange.blocked.is_(False))
            if contains:
                q = q.where(GreyboxHttpExchange.url.contains(contains[:200]))
            if scheme:
                q = q.where(GreyboxHttpExchange.scheme == scheme)
            if method:
                q = q.where(GreyboxHttpExchange.method == method.upper())
            q = q.order_by(GreyboxHttpExchange.id.desc() if newest_first
                           else GreyboxHttpExchange.id).limit(max(1, min(limit, 50)))
            rows = (await session.scalars(q)).all()
            return [{"exchange_id": r.id, "method": r.method, "url": r.url,
                     "scheme": r.scheme, "status": r.status_code, "tool": r.tool,
                     "request_headers": [list(h) for h in (r.request_headers or [])],
                     "request_body": (r.request_body or "")[:20_000],
                     "headers": [list(h) for h in (r.response_headers or [])],
                     "body": (r.response_body or "")[:50_000],
                     "content_type": r.content_type, "error": r.error}
                    for r in rows]
        return await tx_read(self.factory, fn)

    async def endpoints(self, limit: int = 2000) -> list[dict]:
        """Discovered in-scope endpoint assets with their provenance (read-only):
        what an analysis instrument may correlate (e.g. route-template inference)."""
        from src.greybox_web.models import GreyboxAsset

        async def fn(session: AsyncSession) -> list[dict]:
            rows = (await session.scalars(
                select(GreyboxAsset).where(GreyboxAsset.run_id == self.run_id,
                                           GreyboxAsset.kind == "endpoint",
                                           GreyboxAsset.in_scope.is_(True))
                .order_by(GreyboxAsset.key).limit(limit))).all()
            return [{"url": a.key, "source": list((a.data or {}).get("source") or []),
                     "methods": list((a.data or {}).get("methods") or []),
                     "status": ((a.data or {}).get("status_codes") or [None])[-1],
                     "tested": bool(a.tested)} for a in rows]
        return await tx_read(self.factory, fn)
