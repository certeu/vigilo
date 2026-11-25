"""Graph projection: the ONLY writer of the exploration graph and the asset graph.

All node kinds, statuses, edge relations and the allowed (src kind, dst kind) pairs are
declared here, in one place, so the vocabulary can be extended (for example
``hypothesis``/``evidence`` nodes with ``supports``/``refutes`` edges) without touching
the planner, the supervisor or the tools. Every write validates against these tables.

Leads are hypotheses. A ``lead`` node carries ``data.hypothesis`` (the statement being
checked) and ``data.signals`` (why the planner formed it). Its status is explicit:
``open`` (formed, nothing run yet), ``investigating`` (a work order spawned by it is
running), ``confirmed`` (a finding produced through it was verified) or ``refuted``
(every work order it spawned finished and no finding was verified).

Each write transaction bumps ``greybox_runs.graph_version`` once and stamps every node,
edge and asset it touches with that version, which gives ``since_version`` deltas.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import events, redaction
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxAssetEdge,
    GreyboxGraphEdge,
    GreyboxGraphNode,
    GreyboxRun,
)
from src.greybox_web.scope import DEFAULT_PORTS, ScopePolicy, canonical_host, normalise_path

# ------------------------------------------------------------------ vocabulary

NODE_KINDS: dict[str, tuple[str, ...]] = {
    "objective": ("active", "done"),
    "lead": ("open", "investigating", "confirmed", "refuted", "inconclusive"),
    "work_order": ("pending", "running", "done", "failed", "skipped", "cancelled"),
    "action": ("running", "succeeded", "failed", "blocked", "cancelled"),
    "observation": ("recorded",),
    "finding": ("candidate", "verified", "rejected"),
    "hint": ("open", "addressed", "rejected"),
    # Defensive recommendation generated after verification.
    "defense": ("proposed", "unverified"),
    # One explorer reasoning cycle: the model's
    # analysis and todolist snapshot, superseded by the next cycle. Everything the
    # explorer spawns (leads, work orders) is parented to a reasoning node.
    "reasoning": ("active", "superseded"),
}
# rel -> allowed (src kind, dst kind) pairs.
EDGE_RULES: dict[str, frozenset[tuple[str, str]]] = {
    "spawned": frozenset({("objective", "work_order"), ("lead", "work_order"),
                          ("observation", "lead"), ("finding", "work_order"),
                          ("objective", "reasoning"), ("reasoning", "lead"),
                          ("reasoning", "work_order")}),
    "executed": frozenset({("work_order", "action")}),
    "observed": frozenset({("action", "observation")}),
    "investigated": frozenset({("work_order", "lead")}),
    "supports": frozenset({("observation", "finding"), ("observation", "lead")}),
    "contradicts": frozenset({("observation", "lead")}),
    "verified": frozenset({("action", "finding")}),
    "refuted": frozenset({("action", "finding")}),
    # Analyst steering: a hint guides any node.
    "guides": frozenset({("hint", kind) for kind in NODE_KINDS}),
    # A proposed defense protects against a finding.
    "mitigates": frozenset({("defense", "finding")}),
}
# Drawn but excluded from layout ranks and collapse.
FEEDBACK_RELS = frozenset({"investigated", "verified", "refuted", "contradicts",
                           "guides", "mitigates"})
LEAD_TERMINAL = frozenset({"confirmed", "refuted", "inconclusive"})

# Work-order/lead node outcomes (coverage-ledger vocabulary).
OUTCOMES = ("reported", "no_issue_found", "ruled_out", "not_applicable", "needs_follow_up")

# "defense" assets are network recommendations written in the reporting phase (10.7).
# "ip" and "provider" are never parents: leaked or
# attributed things recorded as out-of-scope assets, never contacted.
# Network/web surface kinds, then the security relationship model's entity kinds
# (secmodel.ENTITY_KINDS: identities, roles, resources, workflows, trust boundaries).
SURFACE_KINDS = ("host", "service", "endpoint", "parameter", "defense", "ip", "provider")
MODEL_KINDS = ("identity", "role", "resource_type", "resource", "workflow",
               "workflow_state", "trust_boundary")
ASSET_KINDS = SURFACE_KINDS + MODEL_KINDS
ASSET_PARENT = {"service": "host", "endpoint": "service", "parameter": "endpoint"}
ASSET_RULES: dict[str, frozenset[tuple[str, str]]] = {
    "contains": frozenset({("host", "service"), ("service", "endpoint")}),
    "has_param": frozenset({("endpoint", "parameter")}),
    "links_to": frozenset({("endpoint", "endpoint")}),
    "redirects_to": frozenset({("endpoint", "endpoint"), ("endpoint", "service"),
                               ("service", "service"), ("service", "host")}),
    # Peripheral passive relations (network exploration 7.1): a third-party origin a
    # service loads resources from, the CDN/WAF in front of a service, an internal
    # name/address an endpoint leaks.
    "depends_on": frozenset({("service", "host")}),
    "fronted_by": frozenset({("service", "provider")}),
    "leaks": frozenset({("endpoint", "host"), ("endpoint", "ip")}),
    # A network recommendation protects the asset it was derived from (10.7).
    "protects": frozenset({("defense", "host"), ("defense", "service"),
                           ("defense", "endpoint")}),
}

def _merge_model_relations() -> None:
    """The security model's relations (secmodel.RELATIONS) join the asset edge
    vocabulary, so declared relations are ordinary, validated asset edges."""
    from src.greybox_web.secmodel import RELATIONS
    for rel, pairs in RELATIONS.items():
        ASSET_RULES[rel] = ASSET_RULES.get(rel, frozenset()) | pairs


_merge_model_relations()
PARAM_LOCATIONS = ("query", "form", "cookie", "header")
# Persisted asset states; "discovered" is transient and never stored.
ASSET_STATES = ("discovered", "in_scope", "out_of_scope", "tested", "finding_linked")


def asset_state(in_scope: bool, tested: bool, finding_count: int) -> str:
    if not in_scope:
        return "out_of_scope"
    if finding_count > 0:
        return "finding_linked"
    return "tested" if tested else "in_scope"


# ------------------------------------------------------------------ canonical keys


@dataclass(frozen=True)
class UrlKeys:
    host: str            # host asset key
    service: str         # scheme://host:port
    endpoint: str        # service + normalised path
    path: str
    scheme: str
    port: int


def url_keys(url: str) -> UrlKeys | None:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    host = canonical_host(parts.hostname or "")
    if scheme not in DEFAULT_PORTS or not host:
        return None
    port = port or DEFAULT_PORTS[scheme]
    host_key = f"[{host}]" if ":" in host else host
    service = f"{scheme}://{host_key}:{port}"
    path = normalise_path(parts.path or "/")
    return UrlKeys(host_key, service, service + path, path, scheme, port)


def param_key(endpoint_key: str, location: str, name: str) -> str:
    return f"{endpoint_key}#{location}:{name}"


# ------------------------------------------------------------------ change counters


@dataclass
class GraphStats:
    """Changes since the last ``graph.updated`` event (coalesced by the supervisor)."""

    nodes: int = 0
    edges: int = 0
    assets: int = 0
    asset_edges: int = 0
    max_created_version: int = 0   # highest created_version among nodes created in the window

    def any(self) -> bool:
        return bool(self.nodes or self.edges or self.assets or self.asset_edges)

    def take(self) -> dict[str, int]:
        out = {"nodes": self.nodes, "edges": self.edges, "assets": self.assets,
               "asset_edges": self.asset_edges,
               "max_created_version": self.max_created_version}
        self.nodes = self.edges = self.assets = self.asset_edges = 0
        self.max_created_version = 0
        return out


class GraphError(ValueError):
    pass


# ------------------------------------------------------------------ projection


class GraphTx:
    """Graph writes inside one write transaction for one run."""

    def __init__(self, session: AsyncSession, run_id: uuid.UUID,
                 stats: GraphStats | None = None, *, agent_id: uuid.UUID | None = None,
                 work_order_id: uuid.UUID | None = None) -> None:
        self.s = session
        self.run_id = run_id
        self.stats = stats or GraphStats()
        self.agent_id = agent_id
        self.work_order_id = work_order_id
        self._version: int | None = None
        self.new_assets: list[GreyboxAsset] = []
        # Existing assets whose data gained a planner-relevant signal
        # (``sets_cookies`` / ``login_form``) in this transaction: the planner
        # must re-consider them even though they are not new.
        self.revised_assets: list[GreyboxAsset] = []

    async def version(self) -> int:
        if self._version is None:
            res = await self.s.execute(
                update(GreyboxRun).where(GreyboxRun.id == self.run_id)
                .values(graph_version=GreyboxRun.graph_version + 1)
                .returning(GreyboxRun.graph_version)
                .execution_options(synchronize_session=False))
            self._version = int(res.scalar_one())
        return self._version

    # -- exploration graph ----------------------------------------------------
    async def get_node(self, kind: str, key: str) -> GreyboxGraphNode | None:
        return (await self.s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == self.run_id, GreyboxGraphNode.kind == kind,
            GreyboxGraphNode.key == key[:300]))).one_or_none()

    async def node(self, kind: str, key: str, label: str, status: str, *,
                   data: dict[str, Any] | None = None, event_seq: int | None = None,
                   agent_id: uuid.UUID | None = None,
                   work_order_id: uuid.UUID | None = None,
                   finding_id: uuid.UUID | None = None,
                   asset_id: uuid.UUID | None = None,
                   parent: "GreyboxGraphNode | None" = None,
                   severity: str | None = None,
                   outcome: str | None = None) -> GreyboxGraphNode:
        if kind not in NODE_KINDS:
            raise GraphError(f"unknown node kind {kind!r}")
        if status not in NODE_KINDS[kind]:
            raise GraphError(f"invalid status {status!r} for {kind}")
        if severity is not None and kind != "finding":
            raise GraphError("severity is a finding-node field")
        if outcome is not None and kind not in ("work_order", "lead", "objective"):
            raise GraphError("outcome is a work-order/lead/objective field")
        if outcome is not None and outcome not in OUTCOMES:
            raise GraphError(f"unknown outcome {outcome!r}")
        version = await self.version()
        node = await self.get_node(kind, key)
        clean = events.cap_data(data, 4096) if data is not None else None
        if node is None:
            node = GreyboxGraphNode(
                id=uuid.uuid4(), run_id=self.run_id, kind=kind, key=key[:300],
                label=events.clip(label, 300), status=status, data=clean or {},
                event_seq=event_seq, last_event_seq=event_seq, agent_id=agent_id,
                work_order_id=work_order_id, finding_id=finding_id, asset_id=asset_id,
                parent_id=parent.id if parent is not None else None,
                severity=severity, outcome=outcome, created_version=version,
                version=version)
            self.s.add(node)
            self.stats.max_created_version = max(self.stats.max_created_version, version)
        else:
            node.label = events.clip(label, 300)
            node.status = status
            if clean is not None:
                node.data = {**(node.data or {}), **clean}
            for name, value in (("agent_id", agent_id), ("work_order_id", work_order_id),
                                ("finding_id", finding_id), ("asset_id", asset_id),
                                ("event_seq", event_seq), ("parent_id",
                                parent.id if parent is not None else None),
                                ("severity", severity), ("outcome", outcome)):
                if value is not None and getattr(node, name) is None:
                    setattr(node, name, value)
            node.version = version
        self.stats.nodes += 1
        return node

    async def set_status(self, node: GreyboxGraphNode, status: str,
                         data: dict[str, Any] | None = None,
                         *, last_event_seq: int | None = None,
                         outcome: str | None = None) -> None:
        if status not in NODE_KINDS[node.kind]:
            raise GraphError(f"invalid status {status!r} for {node.kind}")
        node.status = status
        if last_event_seq is not None:
            node.last_event_seq = last_event_seq
        if outcome is not None:
            if node.kind not in ("work_order", "lead", "objective") or outcome not in OUTCOMES:
                raise GraphError(f"outcome {outcome!r} not valid for {node.kind}")
            node.outcome = outcome
        if data:
            node.data = {**(node.data or {}), **events.cap_data(data, 4096)}
        node.version = await self.version()
        self.stats.nodes += 1

    async def set_status_by_id(self, node_id: uuid.UUID | None, status: str) -> None:
        if node_id is None:
            return
        node = await self.s.get(GreyboxGraphNode, node_id)
        if node is not None and node.run_id == self.run_id:
            await self.set_status(node, status)

    async def edge(self, src: GreyboxGraphNode, dst: GreyboxGraphNode, rel: str) -> None:
        allowed = EDGE_RULES.get(rel)
        if allowed is None:
            raise GraphError(f"unknown edge rel {rel!r}")
        if (src.kind, dst.kind) not in allowed:
            raise GraphError(f"{rel}: {src.kind} -> {dst.kind} not allowed")
        if src.id == dst.id:
            raise GraphError("self loop")
        exists = await self.s.scalar(select(GreyboxGraphEdge.id).where(
            GreyboxGraphEdge.run_id == self.run_id, GreyboxGraphEdge.src_id == src.id,
            GreyboxGraphEdge.rel == rel, GreyboxGraphEdge.dst_id == dst.id))
        if exists is not None:
            return
        self.s.add(GreyboxGraphEdge(run_id=self.run_id, src_id=src.id, dst_id=dst.id,
                                    rel=rel, version=await self.version()))
        self.stats.edges += 1

    # -- asset graph ----------------------------------------------------------
    async def get_asset(self, kind: str, key: str) -> GreyboxAsset | None:
        return (await self.s.scalars(select(GreyboxAsset).where(
            GreyboxAsset.run_id == self.run_id, GreyboxAsset.kind == kind,
            GreyboxAsset.key == key[:600]))).one_or_none()

    async def asset(self, kind: str, key: str, label: str, *, in_scope: bool,
                    parent: GreyboxAsset | None = None,
                    data: dict[str, Any] | None = None) -> GreyboxAsset:
        """Upsert an asset. ``data`` is merged (lists are unioned)."""
        if kind not in ASSET_KINDS:
            raise GraphError(f"unknown asset kind {kind!r}")
        if parent is not None and ASSET_PARENT.get(kind) != parent.kind:
            raise GraphError(f"{kind} cannot be contained by {parent.kind}")
        asset = await self.get_asset(kind, key)
        version = await self.version()
        if asset is None:
            asset = GreyboxAsset(
                id=uuid.uuid4(), run_id=self.run_id, kind=kind, key=key[:600],
                label=events.clip(label, 300), parent_id=parent.id if parent else None,
                in_scope=in_scope, tested=False, finding_count=0,
                state=asset_state(in_scope, False, 0),
                data=events.cap_data(data, 4096) if data else {}, version=version)
            ev = await events.emit(
                self.s, self.run_id, "asset.discovered",
                f"{kind} {label}" + ("" if in_scope else " (out of scope, not requested)"),
                data={"asset_id": str(asset.id), "kind": kind, "key": key,
                      "in_scope": in_scope},
                refs={"asset_ids": [asset.id]}, agent_id=self.agent_id,
                work_order_id=self.work_order_id)
            asset.first_seen_seq = ev.seq
            self.s.add(asset)
            self.new_assets.append(asset)
            self.stats.assets += 1
            if parent is not None:
                rel = "has_param" if kind == "parameter" else "contains"
                await self.asset_edge(parent, asset, rel)
            return asset
        if data:
            merged = dict(asset.data or {})
            for k, v in events.cap_data(data, 4096).items():
                old = merged.get(k)
                if isinstance(old, list) and isinstance(v, list):
                    merged[k] = old + [x for x in v if x not in old]
                else:
                    merged[k] = v
            if merged != asset.data:
                gained_signal = any(
                    merged.get(k) and not (asset.data or {}).get(k)
                    for k in ("sets_cookies", "login_form", "leaks", "third_party",
                              "mixed_content", "edge", "cross_redirect"))
                asset.data = merged
                asset.version = version
                self.stats.assets += 1
                if gained_signal:
                    self.revised_assets.append(asset)
        return asset

    async def asset_edge(self, src: GreyboxAsset, dst: GreyboxAsset, rel: str) -> None:
        allowed = ASSET_RULES.get(rel)
        if allowed is None or (src.kind, dst.kind) not in allowed:
            raise GraphError(f"asset edge {rel}: {src.kind} -> {dst.kind} not allowed")
        if src.id == dst.id:
            return
        exists = await self.s.scalar(select(GreyboxAssetEdge.id).where(
            GreyboxAssetEdge.run_id == self.run_id, GreyboxAssetEdge.src_id == src.id,
            GreyboxAssetEdge.rel == rel, GreyboxAssetEdge.dst_id == dst.id))
        if exists is not None:
            return
        self.s.add(GreyboxAssetEdge(run_id=self.run_id, src_id=src.id, dst_id=dst.id,
                                    rel=rel, version=await self.version()))
        self.stats.asset_edges += 1

    async def _restate(self, asset: GreyboxAsset) -> None:
        asset.state = asset_state(asset.in_scope, asset.tested, asset.finding_count)
        asset.version = await self.version()
        self.stats.assets += 1

    async def mark_tested(self, asset_id: uuid.UUID | None) -> None:
        asset = await self._own_asset(asset_id)
        if asset is not None and not asset.tested:
            asset.tested = True
            await self._restate(asset)

    async def finding_delta(self, asset_id: uuid.UUID | None, delta: int) -> None:
        asset = await self._own_asset(asset_id)
        if asset is not None:
            asset.finding_count = max(0, asset.finding_count + delta)
            await self._restate(asset)

    async def _own_asset(self, asset_id: uuid.UUID | None) -> GreyboxAsset | None:
        if asset_id is None:
            return None
        asset = await self.s.get(GreyboxAsset, asset_id)
        return asset if asset is not None and asset.run_id == self.run_id else None

    async def url_assets(self, url: str, scope: ScopePolicy,
                         data: dict[str, Any] | None = None) -> GreyboxAsset | None:
        """host -> service -> endpoint chain for ``url``; returns the endpoint."""
        k = url_keys(url)
        if k is None:
            return None
        host_name = k.host.strip("[]")
        host_in = scope.host_allowed(host_name)
        svc_in = host_in and k.scheme in scope.allowed_schemes and \
            k.port in scope.allowed_ports
        ep_in = scope.check_url(url).allowed
        host = await self.asset("host", k.host, k.host, in_scope=host_in)
        svc = await self.asset("service", k.service, k.service, in_scope=svc_in,
                               parent=host)
        return await self.asset("endpoint", k.endpoint, k.path, in_scope=ep_in,
                                parent=svc, data=data)

    async def param_asset(self, endpoint: GreyboxAsset, location: str, name: str,
                          data: dict[str, Any] | None = None) -> GreyboxAsset:
        if location not in PARAM_LOCATIONS:
            raise GraphError(f"unknown parameter location {location!r}")
        if data and isinstance(data.get("sample"), str) \
                and redaction.SENSITIVE_PARAM.search(name):
            data = {**data, "sample": redaction.MASK}
        return await self.asset("parameter", param_key(endpoint.key, location, name),
                                f"{name} ({location})", in_scope=endpoint.in_scope,
                                parent=endpoint, data=data)

    async def defense_asset(self, did: uuid.UUID, title: str, target: GreyboxAsset, *,
                            data: dict[str, Any], first_seen_seq: int) -> GreyboxAsset:
        """The asset-graph node of an asset-scoped defense (10.7), with a ``protects``
        edge to ``target``. No ``asset.discovered`` event: ``defense.proposed``
        announces it (``first_seen_seq`` is that event's seq)."""
        version = await self.version()
        asset = GreyboxAsset(
            id=uuid.uuid4(), run_id=self.run_id, kind="defense", key=f"defense:{did}",
            label=events.clip(title, 300), parent_id=None, in_scope=True, tested=False,
            finding_count=0, state="in_scope", data=events.cap_data(data, 4096),
            first_seen_seq=first_seen_seq, version=version)
        self.s.add(asset)
        self.stats.assets += 1
        await self.s.flush()
        await self.asset_edge(asset, target, "protects")
        return asset

    async def set_surface(self, asset: GreyboxAsset, surface: dict[str, Any]) -> bool:
        """Store ``data.surface`` (10.7); True when it changed. Redacted and capped."""
        clean = events.cap_data({"surface": surface}, 8192).get("surface")
        if clean is None or (asset.data or {}).get("surface") == clean:
            return False
        asset.data = {**(asset.data or {}), "surface": clean}
        asset.version = await self.version()
        self.stats.assets += 1
        return True
