"""Grey-box graph API: exploration graph, node drawer, asset graph,
asset detail. Read-only; ownership and feature flag as the runs endpoints."""
from __future__ import annotations

import uuid
from collections import defaultdict
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import assetclass
from src.greybox_web.acl import NOT_FOUND, get_run_or_404
from src.greybox_web.models import (
    GreyboxAgent,
    GreyboxAsset,
    GreyboxAssetEdge,
    GreyboxFinding,
    GreyboxGraphEdge,
    GreyboxGraphNode,
    GreyboxHttpExchange,
    GreyboxWorkOrder,
)
from src.greybox_web.pagination import as_utc
from src.greybox_web.schemas import (
    AssetCoverage,
    AssetDetail,
    AssetGraphResponse,
    AssetNodeOut,
    ExplorationGraphResponse,
    ExplorationNodeDetail,
    ExplorationNodeOut,
    GraphAgentRef,
    GraphAssetRef,
    GraphEdgeOut,
    GraphExchangeSummary,
    GraphFindingSummary,
    GraphWorkOrder,
    NeighbourSummary,
)
from src.greybox_web.scope import normalise_path
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import User

router = APIRouter(prefix="/greybox", tags=["greybox"])

DEFAULT_LIMIT = 2000
MAX_LIMIT = 5000
NODE_EXCHANGE_CAP = 20      # exchange_ids on a graph node
DRAWER_EXCHANGE_CAP = 50    # exchange summaries on a drawer / asset detail
ASSET_WORK_ORDER_CAP = 100
COVERAGE_DEFINITION = ("Pages and API endpoints in scope on which at least one enabled "
                       "check completed (done). Static assets are not counted.")


def _404(detail: str = NOT_FOUND) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


# --------------------------------------------------------------------- mappers


def _edge_out(e) -> GraphEdgeOut:
    return GraphEdgeOut(id=e.id, src=e.src_id, dst=e.dst_id, rel=e.rel,
                        version=int(e.version))


def _asset_ref(a: GreyboxAsset | None) -> GraphAssetRef | None:
    return None if a is None else GraphAssetRef(id=a.id, kind=a.kind, label=a.label)


async def _agent_names(session: AsyncSession, run_id: uuid.UUID) -> dict[uuid.UUID, GreyboxAgent]:
    return {a.id: a for a in (await session.scalars(
        select(GreyboxAgent).where(GreyboxAgent.run_id == run_id)
        .order_by(GreyboxAgent.name))).all()}


async def _node_exchange_ids(session: AsyncSession, run_id: uuid.UUID,
                             nodes: list[GreyboxGraphNode],
                             cap: int) -> dict[uuid.UUID, list[int]]:
    """Exchanges backing each node (nodes carry no column for this): action ->
    its tool call; work order -> its exchanges; finding -> evidence and
    verification exchanges; observation -> the action that observed it."""
    out: dict[uuid.UUID, list[int]] = {n.id: [] for n in nodes}
    kinds = {n.kind for n in nodes}
    by_call: dict[str, list[int]] = defaultdict(list)
    by_wo: dict[uuid.UUID, list[int]] = defaultdict(list)
    if kinds & {"action", "work_order", "observation"}:
        for xid, wo_id, call in (await session.execute(
                select(GreyboxHttpExchange.id, GreyboxHttpExchange.work_order_id,
                       GreyboxHttpExchange.tool_call_id)
                .where(GreyboxHttpExchange.run_id == run_id)
                .order_by(GreyboxHttpExchange.id))).all():
            if call:
                by_call[call].append(int(xid))
            if wo_id is not None:
                by_wo[wo_id].append(int(xid))
    wo_by_node: dict[uuid.UUID, uuid.UUID] = {}
    if "work_order" in kinds:
        wo_by_node = {nid: wid for nid, wid in (await session.execute(
            select(GreyboxWorkOrder.node_id, GreyboxWorkOrder.id).where(
                GreyboxWorkOrder.run_id == run_id,
                GreyboxWorkOrder.node_id.is_not(None)))).all()}
    finding_ids: dict[uuid.UUID, list[int]] = {}
    if "finding" in kinds:
        for fid, evidence, verification in (await session.execute(
                select(GreyboxFinding.id, GreyboxFinding.evidence,
                       GreyboxFinding.verification)
                .where(GreyboxFinding.run_id == run_id))).all():
            finding_ids[fid] = _finding_exchange_ids(evidence, verification)
    obs_action: dict[uuid.UUID, str] = {}
    obs_nodes = [n for n in nodes if n.kind == "observation"]
    if obs_nodes:
        rows = (await session.execute(
            select(GreyboxGraphEdge.dst_id, GreyboxGraphNode.key)
            .join(GreyboxGraphNode, GreyboxGraphNode.id == GreyboxGraphEdge.src_id)
            .where(GreyboxGraphEdge.run_id == run_id,
                   GreyboxGraphEdge.rel == "observed",
                   GreyboxGraphEdge.dst_id.in_([n.id for n in obs_nodes])))).all()
        obs_action = {dst: key for dst, key in rows}
    for n in nodes:
        ids: list[int] = []
        if n.kind == "action":
            ids = by_call.get(n.key, [])
        elif n.kind == "work_order":
            wid = n.work_order_id or wo_by_node.get(n.id)
            ids = by_wo.get(wid, []) if wid else []
        elif n.kind == "finding":
            ids = finding_ids.get(n.finding_id, []) if n.finding_id else []
        elif n.kind == "observation":
            ids = by_call.get(obs_action.get(n.id, ""), [])
        out[n.id] = sorted(set(ids))[:cap]
    return out


def _finding_exchange_ids(evidence, verification) -> list[int]:
    ids: list[int] = []
    for ev in evidence or []:
        if isinstance(ev, dict) and ev.get("exchange_id") is not None:
            ids.append(int(ev["exchange_id"]))
    if isinstance(verification, dict):
        ids.extend(int(i) for i in verification.get("exchange_ids") or [])
    return ids


def _node_out(n: GreyboxGraphNode, agents: dict, exch: dict) -> ExplorationNodeOut:
    agent = agents.get(n.agent_id) if n.agent_id else None
    return ExplorationNodeOut(
        id=n.id, kind=n.kind, key=n.key, label=n.label, status=n.status,
        agent_id=n.agent_id, agent_name=agent.name if agent else None,
        work_order_id=n.work_order_id, finding_id=n.finding_id, asset_id=n.asset_id,
        parent_id=n.parent_id, event_seq=n.event_seq, last_event_seq=n.last_event_seq,
        severity=n.severity, outcome=n.outcome, exchange_ids=exch.get(n.id, []),
        data=n.data or {},
        created_version=int(n.created_version if n.created_version is not None
                            else n.version),
        version=int(n.version), created_at=as_utc(n.created_at),
        updated_at=as_utc(n.updated_at))


def _work_order_out(w: GreyboxWorkOrder, agents: dict,
                    assets: dict) -> GraphWorkOrder:
    dur = None
    if w.started_at and w.finished_at:
        dur = max(0, int((as_utc(w.finished_at) - as_utc(w.started_at))
                         .total_seconds() * 1000))
    agent = agents.get(w.agent_id) if w.agent_id else None
    return GraphWorkOrder(
        id=w.id, kind=w.kind, tool=w.tool, title=w.title, reason=w.reason,
        status=w.status, priority=w.priority,
        asset=_asset_ref(assets.get(w.asset_id)) if w.asset_id else None,
        node_id=w.node_id, parent_node_id=w.parent_node_id, agent_id=w.agent_id,
        agent_name=agent.name if agent else None, attempts=w.attempts,
        max_attempts=w.max_attempts, lease_expires_at=as_utc(w.lease_expires_at),
        result_summary=w.result_summary, error=w.error, created_seq=int(w.created_seq),
        created_at=as_utc(w.created_at), started_at=as_utc(w.started_at),
        finished_at=as_utc(w.finished_at), duration_ms=dur)


def _finding_out(f: GreyboxFinding, agents: dict, assets: dict) -> GraphFindingSummary:
    agent = agents.get(f.agent_id) if f.agent_id else None
    return GraphFindingSummary(
        id=f.id, title=f.title, severity=f.severity, status=f.status,
        confidence=f.confidence, check_id=f.check_id,
        affected_asset=(_asset_ref(assets.get(f.affected_asset_id))
                        if f.affected_asset_id else None),
        agent_name=agent.name if agent else None, evidence_count=len(f.evidence or []),
        created_at=as_utc(f.created_at), updated_at=as_utc(f.updated_at))


async def _exchange_summaries(session: AsyncSession, run_id: uuid.UUID,
                              rows: list[GreyboxHttpExchange],
                              agents: dict) -> list[GraphExchangeSummary]:
    ex_findings: dict[int, list[uuid.UUID]] = defaultdict(list)
    if rows:
        for fid, evidence, verification in (await session.execute(
                select(GreyboxFinding.id, GreyboxFinding.evidence,
                       GreyboxFinding.verification)
                .where(GreyboxFinding.run_id == run_id))).all():
            for xid in set(_finding_exchange_ids(evidence, verification)):
                ex_findings[xid].append(fid)
    out = []
    for x in rows:
        agent = agents.get(x.agent_id) if x.agent_id else None
        out.append(GraphExchangeSummary(
            id=int(x.id), ts=as_utc(x.ts), method=x.method, scheme=x.scheme or "",
            host=x.host or "", port=int(x.port or 0), path=x.path or "",
            status_code=x.status_code, duration_ms=x.duration_ms,
            content_type=x.content_type, response_size=x.response_size, tool=x.tool,
            agent_id=x.agent_id, agent_name=agent.name if agent else None,
            work_order_id=x.work_order_id, blocked=bool(x.blocked),
            block_reason=x.block_reason, error=x.error,
            redirect_hop=int(x.redirect_hop or 0),
            finding_ids=ex_findings.get(int(x.id), [])))
    return out


def _paged(model, run_id, since: int, limit: int):
    """First ``limit`` rows with version > since by (version, id), plus the
    matching count per kind."""
    q = select(model).where(model.run_id == run_id, model.version > since)
    return q.order_by(model.version, model.id).limit(limit + 1)


async def _truncation(session, model, run_id, since: int,
                      returned: list) -> tuple[bool, dict[str, int]]:
    rows = (await session.execute(
        select(model.kind, func.count()).where(
            model.run_id == run_id, model.version > since)
        .group_by(model.kind))).all()
    matched = {k: int(n) for k, n in rows}
    kept: dict[str, int] = defaultdict(int)
    for r in returned:
        kept[r.kind] += 1
    missing = {k: n - kept.get(k, 0) for k, n in matched.items() if n > kept.get(k, 0)}
    return bool(missing), missing


async def _counts(session, model, run_id) -> int:
    return int(await session.scalar(
        select(func.count()).select_from(model).where(model.run_id == run_id)) or 0)


async def _versioned_edges(session, model, run_id, since: int, ids: set[uuid.UUID],
                           truncated: bool) -> list:
    edges = (await session.scalars(
        select(model).where(model.run_id == run_id, model.version > since)
        .order_by(model.version, model.id))).all()
    if truncated:    # only edges whose two endpoints are both returned
        edges = [e for e in edges if e.src_id in ids and e.dst_id in ids]
    return list(edges)


# ------------------------------------------------------------------ exploration


async def _neighbourhood(session, run_id, focus: uuid.UUID, hops: int) -> set[uuid.UUID]:
    pairs = (await session.execute(
        select(GreyboxGraphEdge.src_id, GreyboxGraphEdge.dst_id)
        .where(GreyboxGraphEdge.run_id == run_id))).all()
    adj: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    for s, d in pairs:
        adj[s].add(d)
        adj[d].add(s)
    seen, frontier = {focus}, {focus}
    for _ in range(hops):
        frontier = {n for f in frontier for n in adj.get(f, ())} - seen
        seen |= frontier
    return seen


@router.get("/runs/{run_id}/graph/exploration", response_model=ExplorationGraphResponse)
async def exploration_graph(
    run_id: uuid.UUID,
    since_version: int = Query(default=0, ge=0, le=2**63 - 1),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    focus: uuid.UUID | None = None,
    hops: int = Query(default=1, ge=1, le=3),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> ExplorationGraphResponse:
    run = await get_run_or_404(session, user, run_id)
    agents = await _agent_names(session, run_id)
    version = int(run.graph_version or 0)
    total_nodes = await _counts(session, GreyboxGraphNode, run_id)
    total_edges = await _counts(session, GreyboxGraphEdge, run_id)
    agent_refs = [GraphAgentRef(id=a.id, name=a.name, role=a.role)
                  for a in agents.values()]

    if focus is not None:
        node = await session.get(GreyboxGraphNode, focus)
        if node is None or node.run_id != run_id:
            raise _404()
        ids = await _neighbourhood(session, run_id, focus, hops)
        nodes = list((await session.scalars(
            select(GreyboxGraphNode).where(
                GreyboxGraphNode.run_id == run_id, GreyboxGraphNode.id.in_(ids))
            .order_by(GreyboxGraphNode.version, GreyboxGraphNode.id))).all())
        truncated = len(nodes) > limit
        by_kind: dict[str, int] = {}
        if truncated:
            for n in nodes[limit:]:
                by_kind[n.kind] = by_kind.get(n.kind, 0) + 1
            nodes = nodes[:limit]
        kept = {n.id for n in nodes}
        edges = [e for e in (await session.scalars(
            select(GreyboxGraphEdge).where(GreyboxGraphEdge.run_id == run_id)
            .order_by(GreyboxGraphEdge.version, GreyboxGraphEdge.id))).all()
            if e.src_id in kept and e.dst_id in kept]
        # A neighbourhood is a complete picture, not a delta.
        since_out, full = 0, True
    else:
        rows = list((await session.scalars(
            _paged(GreyboxGraphNode, run_id, since_version, limit))).all())
        nodes = rows[:limit]
        truncated, by_kind = (False, {})
        if len(rows) > limit:
            truncated, by_kind = await _truncation(
                session, GreyboxGraphNode, run_id, since_version, nodes)
        edges = await _versioned_edges(session, GreyboxGraphEdge, run_id,
                                       since_version, {n.id for n in nodes}, truncated)
        since_out, full = since_version, since_version == 0

    exch = await _node_exchange_ids(session, run_id, nodes, NODE_EXCHANGE_CAP)
    return ExplorationGraphResponse(
        version=version, since_version=since_out, full=full, truncated=truncated,
        truncated_by_kind=by_kind, total_nodes=total_nodes, total_edges=total_edges,
        agents=agent_refs, nodes=[_node_out(n, agents, exch) for n in nodes],
        edges=[_edge_out(e) for e in edges])


@router.get("/runs/{run_id}/graph/exploration/nodes/{node_id}",
            response_model=ExplorationNodeDetail)
async def exploration_node(
    run_id: uuid.UUID,
    node_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> ExplorationNodeDetail:
    await get_run_or_404(session, user, run_id)
    node = await session.get(GreyboxGraphNode, node_id)
    if node is None or node.run_id != run_id:
        raise _404()
    agents = await _agent_names(session, run_id)
    edges = list((await session.scalars(
        select(GreyboxGraphEdge).where(
            GreyboxGraphEdge.run_id == run_id,
            (GreyboxGraphEdge.src_id == node_id) | (GreyboxGraphEdge.dst_id == node_id))
        .order_by(GreyboxGraphEdge.version, GreyboxGraphEdge.id))).all())
    in_edges = [e for e in edges if e.dst_id == node_id]
    out_edges = [e for e in edges if e.src_id == node_id]
    other_ids = {e.src_id for e in in_edges} | {e.dst_id for e in out_edges}
    others = {n.id: n for n in (await session.scalars(
        select(GreyboxGraphNode).where(GreyboxGraphNode.run_id == run_id,
                                       GreyboxGraphNode.id.in_(other_ids)))).all()} \
        if other_ids else {}
    neighbours = [
        NeighbourSummary(id=o.id, kind=o.kind, label=o.label, status=o.status,
                         severity=o.severity, outcome=o.outcome, rel=e.rel,
                         direction=direction)
        for direction, group in (("in", in_edges), ("out", out_edges))
        for e in group
        for o in [others.get(e.src_id if direction == "in" else e.dst_id)]
        if o is not None]

    wo_row = None
    if node.work_order_id is not None:
        wo_row = await session.get(GreyboxWorkOrder, node.work_order_id)
    if node.kind == "work_order" and (wo_row is None or wo_row.run_id != run_id):
        wo_row = (await session.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run_id,
            GreyboxWorkOrder.node_id == node_id))).first()
    if wo_row is not None and wo_row.run_id != run_id:
        wo_row = None
    f_row = None
    if node.finding_id is not None:
        f_row = await session.get(GreyboxFinding, node.finding_id)
        if f_row is not None and f_row.run_id != run_id:
            f_row = None
    asset_ids = {x for x in (wo_row.asset_id if wo_row else None,
                             f_row.affected_asset_id if f_row else None) if x}
    assets = {a.id: a for a in (await session.scalars(
        select(GreyboxAsset).where(GreyboxAsset.id.in_(asset_ids)))).all()} \
        if asset_ids else {}

    exch = await _node_exchange_ids(session, run_id, [node], DRAWER_EXCHANGE_CAP)
    ids = exch[node.id]
    rows = list((await session.scalars(
        select(GreyboxHttpExchange).where(
            GreyboxHttpExchange.run_id == run_id, GreyboxHttpExchange.id.in_(ids))
        .order_by(GreyboxHttpExchange.id))).all()) if ids else []
    agent = agents.get(node.agent_id) if node.agent_id else None
    return ExplorationNodeDetail(
        node=_node_out(node, agents, exch),
        in_edges=[_edge_out(e) for e in in_edges],
        out_edges=[_edge_out(e) for e in out_edges], neighbours=neighbours,
        work_order=_work_order_out(wo_row, agents, assets) if wo_row else None,
        finding=_finding_out(f_row, agents, assets) if f_row else None,
        agent_name=agent.name if agent else None,
        exchanges=await _exchange_summaries(session, run_id, rows, agents))


# ----------------------------------------------------------------------- assets


def _asset_node(a: GreyboxAsset) -> AssetNodeOut:
    return AssetNodeOut(
        id=a.id, kind=a.kind, key=a.key, label=a.label, parent_id=a.parent_id,
        state=a.state, in_scope=bool(a.in_scope), tested=bool(a.tested),
        finding_count=int(a.finding_count or 0), data=a.data or {},
        version=int(a.version))


async def _coverage(session, run_id) -> AssetCoverage:
    """In-scope endpoints and how many were tested. Static assets and media (build
    output, see ``assetclass``) are not attack surface: they are left out of both counts
    unless a finding is attached, and reported separately as ``static_endpoints``."""
    from src.greybox_web.surface import endpoint_class
    # populate_existing: these rows were written by the worker's session, so this
    # session's identity map may hold stale copies of ``tested``/``finding_count``.
    rows = (await session.scalars(
        select(GreyboxAsset).where(
            GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "endpoint",
            GreyboxAsset.in_scope.is_(True))
        .execution_options(populate_existing=True))).all()
    n_scope = n_tested = n_static = 0
    for a in rows:
        if not a.finding_count and assetclass.is_static_like(endpoint_class(a)):
            n_static += 1
            continue
        n_scope += 1
        n_tested += bool(a.tested)
    return AssetCoverage(in_scope_endpoints=n_scope, tested_endpoints=n_tested,
                         static_endpoints=n_static, definition=COVERAGE_DEFINITION)


@router.get("/runs/{run_id}/graph/assets", response_model=AssetGraphResponse)
async def asset_graph(
    run_id: uuid.UUID,
    since_version: int = Query(default=0, ge=0, le=2**63 - 1),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> AssetGraphResponse:
    run = await get_run_or_404(session, user, run_id)
    from src.greybox_web.graph import MODEL_KINDS
    # the security model's entities have their own view (/runs/{id}/model): the
    # asset graph stays the network/web surface
    rows = [a for a in (await session.scalars(
        _paged(GreyboxAsset, run_id, since_version, limit))).all()
        if a.kind not in MODEL_KINDS]
    nodes = rows[:limit]
    truncated, by_kind = (False, {})
    if len(rows) > limit:
        truncated, by_kind = await _truncation(
            session, GreyboxAsset, run_id, since_version, nodes)
    model_ids = set((await session.scalars(select(GreyboxAsset.id).where(
        GreyboxAsset.run_id == run_id, GreyboxAsset.kind.in_(MODEL_KINDS)))).all())
    edges = [e for e in await _versioned_edges(
        session, GreyboxAssetEdge, run_id, since_version, {a.id for a in nodes},
        truncated) if e.src_id not in model_ids and e.dst_id not in model_ids]
    return AssetGraphResponse(
        version=int(run.graph_version or 0), since_version=since_version,
        full=since_version == 0, truncated=truncated, truncated_by_kind=by_kind,
        total_nodes=await _counts(session, GreyboxAsset, run_id),
        total_edges=await _counts(session, GreyboxAssetEdge, run_id),
        nodes=[_asset_node(a) for a in nodes], edges=[_edge_out(e) for e in edges],
        coverage=await _coverage(session, run_id))


async def _asset_exchanges(session, run_id, asset: GreyboxAsset) -> list[GreyboxHttpExchange]:
    """Exchanges that hit the asset (a parameter inherits its endpoint)."""
    if asset.kind == "parameter" and asset.parent_id is not None:
        parent = await session.get(GreyboxAsset, asset.parent_id)
        if parent is None or parent.run_id != run_id:
            return []
        asset = parent
    key = asset.key
    q = select(GreyboxHttpExchange).where(GreyboxHttpExchange.run_id == run_id)
    if asset.kind == "host":
        host = key.strip("[]")
        q = q.where(GreyboxHttpExchange.host == host)
        match = None
    else:
        parts = urlsplit(key)
        if not parts.hostname:
            return []
        q = q.where(GreyboxHttpExchange.host == parts.hostname,
                    GreyboxHttpExchange.scheme == parts.scheme,
                    GreyboxHttpExchange.port == parts.port)
        match = normalise_path(parts.path or "/") if asset.kind == "endpoint" else None
    out: list[GreyboxHttpExchange] = []
    for x in (await session.scalars(q.order_by(GreyboxHttpExchange.id))).all():
        if match is None or normalise_path(x.path or "/") == match:
            out.append(x)
            if len(out) >= DRAWER_EXCHANGE_CAP:
                break
    return out


@router.get("/runs/{run_id}/model")
async def security_model(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """The run's security relationship model (secmodel_store.view): identities,
    per-interface observed access, declared entities/relations/expectations,
    correlation signals and what is still unresolved. Read-only, derived."""
    from src.greybox_web import redaction, secmodel_store
    await get_run_or_404(session, user, run_id)
    return redaction.structured(await secmodel_store.view(session, run_id))


@router.get("/runs/{run_id}/assets/{asset_id}", response_model=AssetDetail)
async def asset_detail(
    run_id: uuid.UUID,
    asset_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> AssetDetail:
    await get_run_or_404(session, user, run_id)
    asset = await session.get(GreyboxAsset, asset_id)
    if asset is None or asset.run_id != run_id:
        raise _404()
    agents = await _agent_names(session, run_id)
    assets = {asset.id: asset}
    wos = list((await session.scalars(
        select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run_id, GreyboxWorkOrder.asset_id == asset_id)
        .order_by(GreyboxWorkOrder.created_seq).limit(ASSET_WORK_ORDER_CAP))).all())
    findings = list((await session.scalars(
        select(GreyboxFinding).where(
            GreyboxFinding.run_id == run_id,
            GreyboxFinding.affected_asset_id == asset_id)
        .order_by(GreyboxFinding.created_at, GreyboxFinding.id))).all())
    children = int(await session.scalar(
        select(func.count()).select_from(GreyboxAsset).where(
            GreyboxAsset.run_id == run_id, GreyboxAsset.parent_id == asset_id)) or 0)
    return AssetDetail(
        **_asset_node(asset).model_dump(),
        work_orders=[_work_order_out(w, agents, assets) for w in wos],
        findings=[_finding_out(f, agents, assets) for f in findings],
        exchanges=await _exchange_summaries(
            session, run_id, await _asset_exchanges(session, run_id, asset), agents),
        children_count=children)
