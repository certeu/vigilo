"""Planner: the admission platform around the exploration agent.

The only proposer is the LLM explorer (``exploration/``): it proposes
:class:`~src.greybox_web.planning.WorkOrderSpec` objects from the run's knowledge.
Candidate-finding verification (:func:`verification_specs`) is the one automatic
rule: an evidence-quality gate, not exploration. :class:`Planner` is the platform
around them: the single admission step (:meth:`Planner.admit`: scope, tool kind and
selection, param allow-list, quotas, dedup), analyst hints and standing directives,
lead settlement and the ``planner.decision`` audit trail. Nothing a proposer says can
widen scope, budgets or the selected checks.

The planner's state (``PlannerState``) is derivable from the database
(:meth:`Planner.hydrate`): the persisted work orders, assets, hints and events are the
source of truth, the in-memory sets are a cache and ``admit`` also checks the unique
dedup key in the DB.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urldefrag, urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import checks as gb_checks
from src.greybox_web import events, modes, progress, tools
from src.greybox_web.graph import GraphTx, url_keys
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxEvent,
    GreyboxFinding,
    GreyboxGraphEdge,
    GreyboxGraphNode,
    GreyboxHint,
    GreyboxWorkOrder,
)
from src.greybox_web.planning import (  # noqa: F401  (re-exported interface)
    EventView,
    HintView,
    LeadSpec,
    NewAsset,
    NewFinding,
    PlanGroup,
    PlannerInput,
    PlannerOutput,
    PlannerProtocol,
    Rejection,
    Terminal,
    WorkOrderSpec,
    is_authored_tool,
    trigger,
    visited_urls,
)
from src.greybox_web.scope import ACTIVE_PROBE_TOOLS, ScopePolicy, normalise_path
from src.greybox_web.tools import dynspec, toolsmith
from src.greybox_web.tools.discovery import visit_key

# Lower runs first.
PRIORITY_DISCOVERY_ROOT = 10
PRIORITY_CRAWL = 15
PRIORITY_DISCOVERY = 20
PRIORITY_VERIFY = 10
PRIORITY_CHECK = 50
# Analyst hints: a focus is above everything else, deprioritize below.
PRIORITY_FOCUS = 0
PRIORITY_FOCUS_SEED = 5
PRIORITY_DEPRIORITIZED = 100

DISCOVERY_INITIAL = ("discovery.fetch_root", "discovery.robots", "discovery.sitemap")

# Admission quotas (per run / per planning cycle). Generous: they bound a runaway
# proposer, not the rule planner on a normal target.
MAX_PENDING_WORK_ORDERS = 2000
MAX_ADMITTED_PER_CYCLE = 500
MAX_PARAMS_BYTES = 8192
MAX_SPEC_PARAMS_BYTES = 16384      # a composed tool carries its source
@dataclass
class PlannerState:
    base_url: str
    scope: ScopePolicy
    checks: list[str]                 # resolved catalogue ids enabled for the run
    seen_dedup: set[str] = field(default_factory=set)
    planned_assets: set[uuid.UUID] = field(default_factory=set)
    initial_tools_done: set[str] = field(default_factory=set)
    crawl_created: bool = False
    objective_node_id: uuid.UUID | None = None
    lead_nodes: dict[uuid.UUID, uuid.UUID] = field(default_factory=dict)  # wo -> lead
    skipped_checks: set[str] = field(default_factory=set)   # operator skip_check hints
    # standing analyst directives, in hint order: (level, service, path prefix)
    directives: list[tuple[str, str, str]] = field(default_factory=list)
    # frontier-driven crawl
    max_pages: int = 2000
    frontier: set[str] = field(default_factory=set)             # unfetched in-scope URLs
    frontier_seen: set[str] = field(default_factory=set)        # visit keys queued/fetched
    crawl_fetched: int = 0            # pages fetched by finished crawl work orders
    crawl_reserved: int = 0           # pages promised to pending/running crawl work orders
    open_batches: int = 0             # pending/running continuation batches
    batch_seq: int = 0
    # Active infrastructure probes the analyst opted in to (scope.exploration); empty
    # by default: ``admit`` rejects every ACTIVE_PROBE_TOOLS proposal otherwise.
    active_probes: frozenset[str] = field(default_factory=frozenset)
    # Run-defined dynamic tools (batch E, "tools on demand"): ``admit`` fills this
    # registry when a ``tool.define`` spec passes validation (the instrument entry
    # plus its ``verify.<id>`` replay entry); the supervisor's claim path and the
    # exploration knowledge read it. In-memory by design — an id, a declarative
    # spec and its executions live inside one run's process, so there is nothing to
    # persist and nothing that survives the run. Deliberately NOT hydrated: a
    # resumed process re-registers nothing (the definition work orders remain in
    # the story) — dynamic tools exist while the run's process defines them.
    dynamic_tools: dict[str, tools.ToolSpec] = field(default_factory=dict)
    # The capabilities this run may use (``modes.py``): derived from the target's
    # assessment mode. None = unrestricted (legacy callers and unit tests).
    capabilities: Any = None

    def __post_init__(self) -> None:
        if not self.active_probes:
            self.active_probes = frozenset(getattr(self.scope, "active_probes", ()) or ())


def service_probe_url(service_key: str, base_url: str, scope: ScopePolicy) -> str:
    """The service root when it is in scope, else the run's base URL."""
    root = service_key.rstrip("/") + "/"
    return root if scope.check_url(root).allowed else base_url


def resolve_hint_url(base_url: str, target: str) -> str | None:
    """A hint target as an absolute URL: a path is resolved against the run's base
    origin (never against another host), a URL is used as given. ``None`` when the
    target is neither. The result is only ever *checked* by ``ScopePolicy`` before use."""
    t = urldefrag((target or "").strip())[0]
    if t.startswith("/"):
        parts = urlsplit(base_url)
        return f"{parts.scheme}://{parts.netloc}/{t.lstrip('/')}"
    if re.match(r"https?://", t, re.IGNORECASE):
        return t
    return None


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _path_prefix(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    p = prefix.rstrip("/")
    return path == p or path.startswith(p + "/")


def _title(tool: str, target: str) -> str:
    return f"{tool} on {target}"


def _under(url: str, service: str, prefix: str) -> bool:
    have = url_keys(url)
    return have is not None and have.service == service and _path_prefix(have.path, prefix)


def directive_level(st: PlannerState, urls: list[str]) -> str | None:
    """The latest standing directive ('focus' | 'depri') covering any of ``urls``."""
    level = None
    for lv, service, prefix in st.directives:
        if any(_under(u, service, prefix) for u in urls):
            level = lv
    return level


def _seed_variant(url: str) -> str:
    """Dedup variant of an analyst seed: the normalised URL *including its query*
    (``/slow?i=1`` and ``/slow?i=2`` are different seeds)."""
    keys = url_keys(url)
    if keys is None:
        return f"seed:{url}"
    query = urlsplit(url).query
    return f"seed:{keys.endpoint}" + (f"?{query}" if query else "")


# ============================================================ evidence verification


def verification_specs(findings, dynamic_tools: dict[str, Any] | None = None) \
        -> list[WorkOrderSpec]:
    """A candidate finding gets a ``verify.*`` work order (priority 10). This is the
    evidence-quality gate, not exploration: it stays automatic, and the specs go
    through :meth:`Planner.admit` like every other proposal (a verifier for a check
    the run did not select is rejected there). Dynamic tools (batch E) verify
    through their ``verify.<dyn id>`` replay entry in the run's dynamic registry —
    passed in by the supervisor because it owns that registry."""
    out = []
    dyn = dynamic_tools or {}
    for f in sorted(findings, key=lambda x: x.dedup_key):
        if not f.verify:
            continue
        tool = f"verify.{f.check_id}"
        # a run-authored tool verifies through the registry entry it got when it was
        # authored, in this same cycle -- before any dynamic-tools list is rebuilt
        if tools.get(tool) is None and tool not in dyn \
                and not is_authored_tool(tool):
            continue
        out.append(WorkOrderSpec(
            tool=tool, kind="verify", title=f"Verify {f.check_id}",
            reason=f"candidate finding {f.dedup_key} needs a reproducible check",
            params={"finding_id": str(f.id), **f.verify},
            priority=PRIORITY_VERIFY, asset_id=f.asset_id, variant=f.dedup_key))
    return out


# ================================================================== the platform


class Planner:
    """Admission, hints, leads and audit. All methods run inside a write transaction
    (``session`` + ``gtx``). ``proposer`` is any :class:`PlannerProtocol`."""

    def __init__(self, run_id: uuid.UUID, state: PlannerState,
                 planner_agent_id: uuid.UUID,
                 proposer: PlannerProtocol | None = None) -> None:
        self.run_id = run_id
        self.state = state
        self.planner_agent_id = planner_agent_id
        if proposer is None:
            from src.greybox_web.exploration.proposer import LlmProposer
            proposer = LlmProposer()
        self.proposer: PlannerProtocol = proposer
        self.cycle_no = 0
        self._admitted = 0
        self._ledger = None
        self._pending = 0

    # ---------------------------------------------------------------- hydrate
    async def hydrate(self, session: AsyncSession) -> None:
        """Rebuild the planner state from the persisted graph, work orders, assets,
        hints and events (the database is the source of truth; resume-safe)."""
        st, rid = self.state, self.run_id
        wos = (await session.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == rid))).all()
        st.seen_dedup |= {w.dedup_key for w in wos}
        # Tools the agent defined or wrote survive an interruption: they are
        # re-validated from the work order that admitted them (its params hold the
        # whole spec) and registered again, so a resumed agent can keep using them.
        for w in sorted(wos, key=lambda w: w.created_at):
            if w.status in ("failed", "skipped", "cancelled") and w.tool == "tool.define":
                continue
            spec_raw = (w.params or {}).get("spec")
            if w.tool == "tool.compose":
                composed, _ = toolsmith.check_spec(spec_raw)
                if composed is not None and composed["id"] not in st.dynamic_tools:
                    st.dynamic_tools.update(toolsmith.registry_entries(composed))
            elif w.tool == "tool.define":
                dyn, _ = dynspec.validate_spec(spec_raw)
                if dyn is not None and dyn.id not in st.dynamic_tools:
                    st.dynamic_tools.update(dynspec.registry_entries(dyn))
        st.planned_assets |= {w.asset_id for w in wos if w.asset_id is not None}
        st.initial_tools_done |= {w.tool for w in wos if w.tool in DISCOVERY_INITIAL
                                  and w.status in ("done", "failed", "skipped",
                                                   "cancelled")}
        crawls = [w for w in wos if w.tool == "discovery.crawl"]
        st.crawl_created = bool(crawls)
        st.batch_seq = max([st.batch_seq] + [
            int(w.dedup_key.rsplit("batch:", 1)[1]) for w in crawls
            if "batch:" in w.dedup_key and w.dedup_key.rsplit("batch:", 1)[1].isdigit()])
        obj = (await session.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == rid, GreyboxGraphNode.kind == "objective"))
               ).first()
        if obj is not None:
            st.objective_node_id = obj.id
        lead_nodes = (await session.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == rid, GreyboxGraphNode.kind == "lead"))).all()
        lead_ids = {n.id for n in lead_nodes}
        for w in wos:
            if w.parent_node_id in lead_ids:
                st.lead_nodes[w.id] = w.parent_node_id
        hints = (await session.scalars(select(GreyboxHint).where(
            GreyboxHint.run_id == rid, GreyboxHint.status == "addressed")
            .order_by(GreyboxHint.created_at, GreyboxHint.id))).all()
        for h in hints:
            target = (h.target or "").strip()
            if h.action == "skip_check" and target in st.checks:
                st.skipped_checks.add(target)
            elif h.action in ("focus", "deprioritize"):
                url = resolve_hint_url(st.base_url, target)
                keys = url_keys(url) if url else None
                if keys is not None:
                    self._add_directive("focus" if h.action == "focus" else "depri",
                                        keys.service, keys.path)
        # crawl: pages fetched so far (from tool.succeeded counts) and the visit set
        for ev in (await session.scalars(select(GreyboxEvent).where(
                GreyboxEvent.run_id == rid, GreyboxEvent.kind == "tool.succeeded"))).all():
            d = ev.data or {}
            if d.get("tool") == "discovery.crawl":
                st.crawl_fetched += int((d.get("result") or {}).get("fetched", 0) or 0)
        st.frontier_seen.add(visit_key(st.base_url))
        for w in crawls:
            for u in (w.params or {}).get("seeds") or []:
                st.frontier_seen.add(visit_key(u))
        eps = (await session.scalars(select(GreyboxAsset).where(
            GreyboxAsset.run_id == rid, GreyboxAsset.kind == "endpoint",
            GreyboxAsset.in_scope.is_(True)).order_by(GreyboxAsset.key))).all()
        for a in eps:            # known but never fetched: back on the frontier
            if "status_codes" in (a.data or {}):
                continue
            k = visit_key(a.key)
            if k not in st.frontier_seen:
                st.frontier_seen.add(k)
                st.frontier.add(a.key)
        await self._sync_counters(session)

    async def _sync_counters(self, session: AsyncSession) -> None:
        """Counters that must match the table exactly (pages promised, open batches,
        pending work orders) are re-read, never accumulated."""
        st = self.state
        rows = (await session.execute(
            select(GreyboxWorkOrder.tool, GreyboxWorkOrder.dedup_key,
                   GreyboxWorkOrder.params).where(
                GreyboxWorkOrder.run_id == self.run_id,
                GreyboxWorkOrder.status.in_(("pending", "running"))))).all()
        self._pending = len(rows)
        st.crawl_reserved = sum(int((p or {}).get("max_pages") or 0)
                                for t, _k, p in rows if t == "discovery.crawl")
        st.open_batches = sum(1 for t, k, _p in rows
                              if t == "discovery.crawl" and "|batch:" in k)

    async def begin_cycle(self, session: AsyncSession) -> None:
        self._admitted = 0
        self._ledger = None                  # progress ledger, loaded on demand
        await self._sync_counters(session)

    # -------------------------------------------------------------- admission
    def _add_directive(self, level: str, service: str, path: str) -> None:
        d = (level, service, path)
        if d in self.state.directives:
            self.state.directives.remove(d)       # the latest hint wins
        self.state.directives.append(d)

    async def _reject(self, session: AsyncSession, spec: WorkOrderSpec, reason: str,
                      detail: str) -> Rejection:
        rej = Rejection(reason, detail)
        await events.emit(
            session, self.run_id, "planner.decision",
            f"rejected: {spec.tool}: {reason}"[:300], level="warning",
            data={"decision": "rejected", "reason": reason, "tool": spec.tool,
                  "detail": events.clip(detail, 300), "work_order_ids": [],
                  "considered": 1, "trigger": trigger("admission")},
            agent_id=self.planner_agent_id)
        return rej

    async def admit(self, session: AsyncSession, gtx: GraphTx, spec: WorkOrderSpec,
                    *, origin: str = "planner") -> GreyboxWorkOrder | Rejection:
        """The single admission step for work orders (rule planner, hints, any future
        LLM planner). Order of checks: tool and kind (from the registry, never from the
        proposer) and the run's selected checks; operator-skipped check; every URL in
        ``params`` through ``ScopePolicy``; size; dedup (memory and database); quotas;
        priority clamp (only the platform may use analyst priorities); standing
        directives. Anything else is refused with a ``planner.decision`` rejection
        (routine duplicates are silent). The guarded client still re-checks every
        request."""
        st = self.state
        if spec.tool in ACTIVE_PROBE_TOOLS and spec.tool not in st.active_probes:
            return await self._reject(
                session, spec, "active_probe_not_enabled",
                f"{spec.tool} is an active probe; the target has not opted in "
                "(scope.exploration.active_probes)")
        registered = tools.get(spec.tool)
        if registered is None:
            # run-defined instrument (batch E): the same admission, resolved through
            # the run's dynamic registry instead of the static one
            registered = st.dynamic_tools.get(spec.tool)
        dynamic = spec.tool in st.dynamic_tools
        if registered is not None:
            kind = registered.kind
        elif spec.kind == "check" and spec.tool in st.checks:
            kind = "check"            # selected but paused: skipped honestly at claim
        else:
            return await self._reject(session, spec, "unknown_tool",
                                      f"{spec.tool} is not a registered tool")
        if spec.kind is not None and spec.kind != kind:
            return await self._reject(session, spec, "kind_mismatch",
                                      f"{spec.tool} is a {kind} tool, not {spec.kind}")
        # a dynamic instrument IS its own selection: defined by this run's agent,
        # through this same admission — the catalogue-selection gate applies to
        # static checks only
        if kind == "check" and not dynamic and spec.tool not in st.checks:
            return await self._reject(session, spec, "check_not_selected",
                                      f"{spec.tool} is not selected for this run")
        # a verifier follows a catalogue check only if the run selected that check;
        # findings of discovery tools (net.*, browser) verify unconditionally
        if kind == "verify" and not dynamic \
                and spec.tool.removeprefix("verify.") in gb_checks.CHECK_IDS \
                and spec.tool.removeprefix("verify.") not in st.checks:
            return await self._reject(session, spec, "check_not_selected",
                                      f"{spec.tool} follows a check this run did not select")
        if spec.tool in st.skipped_checks:
            return Rejection("check_skipped")       # the operator skipped it (hint)
        params = dict(spec.params)
        if spec.tool == "discovery.crawl":
            params.pop("depths", None)    # crawl depth no longer exists: ignore it
        for key in ("url", "endpoint"):
            value = params.get(key)
            if isinstance(value, str) and value.startswith("/"):
                params[key] = resolve_hint_url(st.base_url, value)
        if isinstance(params.get("seeds"), list):
            params["seeds"] = [resolve_hint_url(st.base_url, value)
                               if isinstance(value, str) and value.startswith("/")
                               else value for value in params["seeds"]]
        if registered is not None and registered.param_keys:
            not_allowed = sorted(k for k in params
                                 if k not in registered.param_keys)
            if not_allowed:
                return await self._reject(
                    session, spec, "params_not_allowed",
                    f"{spec.tool} accepts only {', '.join(registered.param_keys)}; "
                    f"unknown: {', '.join(not_allowed)}")
        # An enumerated option takes one of a fixed set: an unsupported value is a
        # refusal with a reason, never silently treated as "no result" (seen in the field: a
        # netview.reexamine with kind=endpoint answered "nothing to re-examine").
        if registered is not None and registered.options:
            for key, allowed in registered.options.items():
                if key in params and str(params[key]) not in allowed:
                    return await self._reject(
                        session, spec, "invalid_option",
                        f"{spec.tool} {key}={str(params[key])[:60]!r} is not "
                        f"supported; allowed: {', '.join(allowed)}")
        # The run's capability policy (modes.py): a tool that needs the browser
        # cannot run against a network-only or artifact-only target.
        if registered is not None and st.capabilities is not None \
                and not st.capabilities.allows(modes.effective(registered.capability)):
            return await self._reject(
                session, spec, "capability_not_allowed",
                f"{spec.tool} needs the {modes.effective(registered.capability)} "
                f"capability, which this {st.capabilities.mode} assessment does not "
                f"have")
        urls = [params.get(k) for k in ("url", "endpoint")]
        urls += list(params.get("seeds") or [])
        for u in urls:
            if isinstance(u, str) and u:
                decision = st.scope.check_url(u)
                if not decision.allowed:
                    return await self._reject(
                        session, spec, decision.reason or "out_of_scope",
                        f"{events.clip(u, 200)} is outside the run's scope")
        cap_bytes = MAX_SPEC_PARAMS_BYTES if spec.tool in ("tool.compose",
                                                           "tool.define") \
            else MAX_PARAMS_BYTES
        if len(json.dumps(params, default=str)) > cap_bytes:
            return await self._reject(session, spec, "params_too_large",
                                      f"parameters exceed {cap_bytes} bytes")
        dyn_tool = None
        if spec.tool == "tool.define":
            # batch E: validate the declarative spec BEFORE anything is registered or
            # requested. These are correctness gates — vocabulary, key sets, string
            # sanity, duplicate ids — never a quota on how many instruments a run
            # may define (there is no count cap).
            dyn_tool, spec_errors = dynspec.validate_spec(params.get("spec"))
            if dyn_tool is None:
                return await self._reject(
                    session, spec, "invalid_spec",
                    "; ".join(spec_errors)[:300] or "invalid spec")
            if tools.get(dyn_tool.id) is not None or dyn_tool.id in st.dynamic_tools:
                return await self._reject(
                    session, spec, "tool_duplicate",
                    f"{dyn_tool.id} already exists in this run; redefine it under a "
                    "new id")
        composed = None
        if spec.tool == "tool.compose":
            # Sandboxed authoring: the source is validated BEFORE it
            # is registered, and every declared input must already be in scope — the
            # generated code never fetches anything itself.
            composed, spec_errors = toolsmith.check_spec(params.get("spec"))
            if composed is None:
                return await self._reject(
                    session, spec, "invalid_spec",
                    "; ".join(spec_errors)[:400] or "invalid spec")
            for item in composed["inputs"]:
                decision = st.scope.check_url(item["url"])
                if not decision.allowed:
                    return await self._reject(
                        session, spec, decision.reason or "out_of_scope",
                        f"input {events.clip(item['url'], 160)} is outside the run's "
                        f"scope")
            if st.capabilities is not None:
                missing = [c for c in composed["capabilities"]
                           if not st.capabilities.allows(c)]
                if missing:
                    return await self._reject(
                        session, spec, "capability_not_allowed",
                        f"{composed['id']} declares {', '.join(missing)}, which this "
                        f"{st.capabilities.mode} assessment does not authorise")
            if tools.get(composed["id"]) is not None \
                    or composed["id"] in st.dynamic_tools:
                return await self._reject(
                    session, spec, "tool_duplicate",
                    f"{composed['id']} already exists in this run; compose it under a "
                    "new id")
        if spec.asset_id is None and kind == "check":
            # A model addresses targets by URL: bind the check to the endpoint asset
            # it examines (tested flag, finding attachment, coverage).
            keys = url_keys(str(params.get("endpoint") or params.get("url") or ""))
            if keys is not None:
                found = await session.scalar(select(GreyboxAsset.id).where(
                    GreyboxAsset.run_id == self.run_id,
                    GreyboxAsset.kind == "endpoint", GreyboxAsset.key == keys.endpoint))
                if found is not None:
                    spec = replace(spec, asset_id=found)
        asset_key = ""
        if spec.asset_id is not None:
            asset = await session.get(GreyboxAsset, spec.asset_id)
            asset_key = asset.key if asset is not None else ""
        dedup = f"{spec.tool}|{asset_key}|{spec.variant}"[:300]
        if dedup in st.seen_dedup:
            return Rejection("duplicate")
        if await session.scalar(select(GreyboxWorkOrder.id).where(
                GreyboxWorkOrder.run_id == self.run_id,
                GreyboxWorkOrder.dedup_key == dedup)) is not None:
            st.seen_dedup.add(dedup)
            return Rejection("duplicate")
        if self._pending >= MAX_PENDING_WORK_ORDERS:
            return await self._reject(session, spec, "quota_pending",
                                      f"{self._pending} work orders already pending")
        if self._admitted >= MAX_ADMITTED_PER_CYCLE:
            return await self._reject(session, spec, "quota_cycle",
                                      "too many work orders in one planning cycle")
        if spec.tool == "discovery.crawl":
            seeds = list(params.get("seeds") or [params.get("url")])
            remaining = st.max_pages - st.crawl_fetched - st.crawl_reserved
            if remaining <= 0:
                return await self._reject(session, spec, "quota_pages",
                                          f"max_pages ({st.max_pages}) reached")
            params["max_pages"] = max(1, min(int(params.get("max_pages") or len(seeds)),
                                             len(seeds), remaining))
        lo = PRIORITY_FOCUS if origin == "platform" else PRIORITY_FOCUS_SEED
        priority = min(max(int(spec.priority), lo), PRIORITY_DEPRIORITIZED)
        cands = ([asset_key.split("#", 1)[0]] if asset_key else []) + \
            [v for v in (params.get("url"), params.get("endpoint")) if isinstance(v, str)]
        level = directive_level(st, cands)
        if level == "focus":
            priority = min(priority, PRIORITY_FOCUS_SEED) if kind == "discovery" \
                else PRIORITY_FOCUS
        elif level == "depri":
            priority = PRIORITY_DEPRIORITIZED
        # Anti-loop (progress.py): an action identical to one that already ran
        # and taught the run nothing -- or that failed twice -- is refused with a
        # reason the agent reads; a different method or input is always admitted.
        if origin != "platform" and kind != "verify":
            if getattr(self, "_ledger", None) is None:
                self._ledger = await progress.ledger(session, self.run_id)
            refused = progress.refusal(self._ledger, spec.tool, params)
            if refused is not None:
                return await self._reject(session, spec, refused[0], refused[1])
        # a lead this work order investigates (hypothesis)
        parent_node_id = spec.parent_node_id
        lead = None
        if spec.lead is not None:
            lead = await self._open_lead(session, gtx, spec.lead)
            parent_node_id = lead.id
        if dyn_tool is not None:
            # the instrument exists from this admission on: claim, verification and
            # the exploration knowledge resolve it through the run-scoped registry
            st.dynamic_tools.update(dynspec.registry_entries(dyn_tool))
        if composed is not None:
            st.dynamic_tools.update(toolsmith.registry_entries(composed))
        wo = await self._write_wo(session, gtx, spec, kind=kind, params=params,
                                  priority=priority, dedup=dedup, asset_key=asset_key,
                                  parent_node_id=parent_node_id, lead=lead)
        self._admitted += 1
        self._pending += 1
        if dyn_tool is not None:
            await events.emit(
                session, self.run_id, "tool.defined",
                f"instrument defined: {dyn_tool.id} — {dyn_tool.title}"[:300],
                data={"id": dyn_tool.id, "kind": dyn_tool.kind,
                      "title": events.clip(dyn_tool.title, 200),
                      "param_keys": list(dyn_tool.param_keys)},
                refs={"node_ids": [wo.node_id] if wo.node_id else []},
                agent_id=self.planner_agent_id, work_order_id=wo.id)
        if composed is not None:
            # The audited composition: why, from what inputs, from which source,
            # under which limits. The source is the record of what ran.
            await events.emit(
                session, self.run_id, "tool.defined",
                f"analysis tool composed: {composed['id']} — {composed['title']}"[:300],
                data=toolsmith.audit_payload(composed),
                refs={"node_ids": [wo.node_id] if wo.node_id else []},
                agent_id=self.planner_agent_id, work_order_id=wo.id,
                level="warning")
        if spec.tool == "discovery.crawl":
            st.crawl_reserved += int(params["max_pages"])
            st.crawl_created = True
            for seed in params.get("seeds") or []:     # promised: no longer frontier
                if isinstance(seed, str):
                    st.frontier.discard(seed)
                    st.frontier_seen.add(visit_key(seed))
        return wo

    async def _open_lead(self, session: AsyncSession, gtx: GraphTx,
                         lead: LeadSpec) -> GreyboxGraphNode:
        """Open (or reuse) a lead; ``observation -spawned-> lead`` when it came from a
        recorded observation."""
        existing = await gtx.get_node("lead", lead.key)
        if existing is not None:
            existing.label = lead.label
            existing.data = {**(existing.data or {}), "hypothesis": lead.hypothesis,
                             "signals": lead.signals}
            existing.version = await gtx.version()
            return existing
        node = await gtx.node(
            "lead", lead.key, lead.label, "open",
            data={"hypothesis": lead.hypothesis, "signals": lead.signals,
                  "type": lead.type_id,
                  "evidence": {"supports": 0, "contradicts": 0},
                  "asset_id": str(lead.asset_id) if lead.asset_id else None},
            asset_id=lead.asset_id, agent_id=self.planner_agent_id)
        if lead.observation_key:
            obs = await gtx.get_node("observation", lead.observation_key)
            if obs is not None:
                await gtx.edge(obs, node, "spawned")
        if lead.parent_node_id is not None:
            parent = await session.get(GreyboxGraphNode, lead.parent_node_id)
            if parent is not None and parent.run_id == self.run_id:
                await gtx.edge(parent, node, "spawned")
        return node

    async def _write_wo(self, session: AsyncSession, gtx: GraphTx, spec: WorkOrderSpec,
                        *, kind: str, params: dict[str, Any], priority: int, dedup: str,
                        asset_key: str, parent_node_id: uuid.UUID | None,
                        lead: GreyboxGraphNode | None) -> GreyboxWorkOrder:
        st = self.state
        tool = spec.tool
        title = spec.title or _title(tool, asset_key or params.get("url", ""))
        parent_node = None
        if parent_node_id is not None:
            parent_node = lead if lead is not None and lead.id == parent_node_id \
                else await session.get(GreyboxGraphNode, parent_node_id)
        node = await gtx.node(
            "work_order", dedup, _title(tool, asset_key or params.get("url", "")),
            "pending", data={"tool": tool, "title": title, "reason": spec.reason},
            agent_id=self.planner_agent_id, work_order_id=None, asset_id=spec.asset_id,
            parent=parent_node)
        wo = GreyboxWorkOrder(
            id=uuid.uuid4(), run_id=self.run_id, dedup_key=dedup, kind=kind,
            tool=tool, title=events.clip(title, 300), reason=events.clip(spec.reason, 500),
            params=events.cap_data(params, 4096), priority=priority, status="pending",
            asset_id=spec.asset_id, node_id=node.id, parent_node_id=parent_node_id,
            created_seq=0, max_attempts=2)
        session.add(wo)
        await session.flush()
        ev = await events.emit(
            session, self.run_id, "work_order.created",
            _title(tool, asset_key or params.get("url", "")),
            data={"kind": kind, "tool": tool, "title": title, "reason": spec.reason,
                  "asset_id": str(spec.asset_id) if spec.asset_id else None,
                  "parent_node_id": str(parent_node_id) if parent_node_id else None,
                  "priority": priority},
            refs={"node_ids": [node.id],
                  "asset_ids": [spec.asset_id] if spec.asset_id else []},
            agent_id=self.planner_agent_id, work_order_id=wo.id)
        node.work_order_id = wo.id
        node.event_seq = ev.seq
        node.last_event_seq = ev.seq
        wo.created_seq = ev.seq
        st.seen_dedup.add(dedup)
        if parent_node is not None:
            await gtx.edge(parent_node, node, "spawned")
            if parent_node.kind == "lead":
                await gtx.edge(node, parent_node, "investigated")
                st.lead_nodes[wo.id] = parent_node.id
        return wo

    async def create_wo(self, session: AsyncSession, gtx: GraphTx, *, tool: str,
                        kind: str, title: str, reason: str, params: dict[str, Any],
                        priority: int, asset_id: uuid.UUID | None = None,
                        parent_node_id: uuid.UUID | None = None,
                        variant: str = "") -> GreyboxWorkOrder | None:
        """Platform-originated work order (initial plan, analyst seeds): same admission."""
        res = await self.admit(
            session, gtx, WorkOrderSpec(
                tool=tool, kind=kind, title=title, reason=reason, params=params,
                priority=priority, asset_id=asset_id, parent_node_id=parent_node_id,
                variant=variant), origin="platform")
        return res if isinstance(res, GreyboxWorkOrder) else None

    async def decision(self, session: AsyncSession, decision: str, reason: str,
                       *, work_orders: list[GreyboxWorkOrder] = (),
                       considered: int = 0,
                       trigger_: dict[str, Any] | None = None) -> None:
        await events.emit(
            session, self.run_id, "planner.decision",
            f"{decision}: {reason}"[:300],
            data={"decision": decision, "reason": reason,
                  "work_order_ids": [str(w.id) for w in work_orders],
                  "considered": considered,
                  "trigger": trigger_ or trigger("run")},
            refs={"node_ids": [w.node_id for w in work_orders if w.node_id]},
            agent_id=self.planner_agent_id)

    async def apply(self, session: AsyncSession, gtx: GraphTx,
                    out: PlannerOutput, *, origin: str = "planner") -> list[GreyboxWorkOrder]:
        """Admit every proposed spec and record one decision per group."""
        made: list[GreyboxWorkOrder] = []
        for lead in out.leads:
            if await gtx.get_node("lead", lead.key) is None:
                node = await self._open_lead(session, gtx, lead)
                await self.decision(
                    session, "open_lead", f"lead {lead.label!r} opened for the analyst",
                    trigger_=trigger("lead", node_ids=[node.id]))
        for group in out.groups:
            created = []
            for spec in group.specs:
                res = await self.admit(session, gtx, spec, origin=origin)
                if isinstance(res, GreyboxWorkOrder):
                    created.append(res)
            if created:
                await self.decision(session, group.decision, group.reason,
                                    work_orders=created, considered=group.considered,
                                    trigger_=group.trigger)
            made += created
        return made

    # ------------------------------------------------------------------ cycle
    async def initial(self, session: AsyncSession, gtx: GraphTx) -> None:
        st = self.state
        obj = await gtx.node(
            "objective", "objective", f"Assess {st.base_url} within scope", "active",
            data={"base_url": st.base_url, "checks": st.checks})
        st.objective_node_id = obj.id
        await self.begin_cycle(session)
        # No initial plan: the exploration agent proposes the first actions itself
        # (its bootstrap cycle), exactly like every later one.

    def on_terminal(self, terminal: tuple[Terminal, ...]) -> None:
        """Bookkeeping for work orders that just ended (crawl pages, initial tools)."""
        st = self.state
        for t in terminal:
            if t.tool in DISCOVERY_INITIAL:
                st.initial_tools_done.add(t.tool)
            if t.tool == "discovery.crawl":
                st.crawl_fetched += int(t.fetched)
        self._ingest_frontier(terminal)

    def _ingest_frontier(self, terminal: tuple[Terminal, ...]) -> None:
        """Discovery results feed the frontier the model sees: in-scope links not seen
        before (by visit key). Bookkeeping only: nothing is
        crawled unless the model asks for it. Sorted, so arrival order cannot matter.

        A URL a tool has just *acted on* leaves the frontier. Without this the only
        exit was ``discovery.crawl`` retiring its own seeds, so a bundle fetched by
        ``discovery.scripts`` or rendered by ``browser.visit`` stayed open forever:
        the agent was told coverage was incomplete, went back to the file it had
        already read, and looped (defect F-frontier-loop, seen live on the SPA fixture).
        """
        st = self.state
        for t in sorted(terminal, key=lambda x: str(x.wo_id)):
            if t.status != "done":
                continue
            for url in visited_urls(t):
                st.frontier.discard(url)
            for url in sorted(t.frontier):
                key = visit_key(url)
                if key in st.frontier_seen or not st.scope.check_url(url).allowed:
                    continue
                st.frontier_seen.add(key)
                st.frontier.add(url)

    async def cycle(self, session: AsyncSession, gtx: GraphTx, *,
                    assets: list[NewAsset] = (), findings: list[NewFinding] = (),
                    terminal: tuple[Terminal, ...] = (), events_: tuple[EventView, ...] = (),
                    hints: tuple[HintView, ...] = ()) -> list[GreyboxWorkOrder]:
        """One planning step: the proposer sees the delta, admission decides."""
        self.on_terminal(terminal)
        self.cycle_no += 1
        out = await self.proposer.observe(PlannerInput(
            cycle=self.cycle_no, objective_node_id=self.state.objective_node_id,
            assets=tuple(assets), findings=tuple(findings), terminal=terminal,
            hints=hints, events=events_))
        # settle the crawl counters again: a batch admitted above is already counted
        return await self.apply(session, gtx, out)

    async def on_assets(self, session: AsyncSession, gtx: GraphTx,
                        assets: list[NewAsset]) -> None:
        await self.begin_cycle(session)
        await self.cycle(session, gtx, assets=assets)

    async def on_findings(self, session: AsyncSession, gtx: GraphTx,
                          findings: list[NewFinding]) -> None:
        await self.begin_cycle(session)
        await self.cycle(session, gtx, findings=findings)

    # ------------------------------------------------------------------ leads
    async def finalize_leads(self, session: AsyncSession, gtx: GraphTx) -> None:
        """Settle hypotheses (10.1). A lead settles when every work order that
        investigates it is terminal. Evidence first: each observation a done work order
        produced becomes ``supports`` (the order produced a finding) or ``contradicts``
        the lead. Then ``confirmed`` (a finding verified through it), ``refuted``
        (checked, only contradicting evidence) or ``inconclusive`` (never actually
        checked: skipped, failed, cancelled; no evidence either way)."""
        st = self.state
        if not st.lead_nodes:
            return
        for lead_id in sorted({str(v) for v in st.lead_nodes.values()}):
            lead = await session.get(GreyboxGraphNode, uuid.UUID(lead_id))
            if lead is None or lead.status not in ("open", "investigating"):
                continue
            wos = (await session.scalars(select(GreyboxWorkOrder).where(
                GreyboxWorkOrder.run_id == self.run_id,
                GreyboxWorkOrder.parent_node_id == lead.id))).all()
            if any(w.status in ("pending", "running") for w in wos):
                if lead.status != "investigating":
                    await gtx.set_status(lead, "investigating")
                continue
            done = [w for w in wos if w.status == "done"]
            wo_ids = [w.id for w in wos]
            findings = (await session.execute(
                select(GreyboxFinding.work_order_id, GreyboxFinding.status).where(
                    GreyboxFinding.run_id == self.run_id,
                    GreyboxFinding.work_order_id.in_(wo_ids)))).all() if wo_ids else []
            produced = {w for w, s in findings if s != "rejected"}
            verified = any(s == "verified" for _w, s in findings)
            signals = (lead.data or {}).get("signals") or {}
            investigation = signals.get("investigation") if isinstance(signals, dict) else None
            # A mapping/discovery direction ("what is the surface?") is established
            # by observing; only checks can come back clean. It is never "refuted"
            # because discovery succeeded.
            mapping = bool(done) and all(
                (tools.get(w.tool) is not None and tools.get(w.tool).kind == "discovery")
                or w.tool.startswith(("discovery.", "netview."))
                for w in done)
            supports = contradicts = 0
            for w in done:
                for obs in await self._observations_of(session, w.id):
                    if w.id in produced or mapping:
                        await gtx.edge(obs, lead, "supports")
                        supports += 1
                    else:
                        await gtx.edge(obs, lead, "contradicts")
                        contradicts += 1
            # ``basis`` says WHY a lead settled, so nobody (report, UI, agent)
            # mistakes "discovery ran" or "the checks found nothing" for a verdict
            # on the hypothesis itself.
            declared_state = investigation.get("state") if isinstance(investigation, dict) else None
            if declared_state == "verified" or verified:
                status, outcome, basis = "confirmed", "reported", "verified_finding"
            elif declared_state == "rejected":
                status, outcome, basis = "refuted", "ruled_out", "agent_conclusion"
            elif declared_state in ("inconclusive", "blocked"):
                status, outcome, basis = "inconclusive", "needs_follow_up", declared_state
            elif isinstance(investigation, dict):
                await gtx.set_status(lead, "investigating",
                                     data={"evidence": {"supports": supports,
                                                        "contradicts": contradicts},
                                           "rationale": "investigation remains open pending "
                                                        "agent conclusion"})
                continue
            elif mapping:
                status, outcome, basis = "confirmed", "reported", "observed"
            elif done and supports:
                status, outcome, basis = "confirmed", "reported", "unverified_finding"
            elif done:
                status, outcome, basis = "refuted", "ruled_out", "checks_clean"
            else:
                status, outcome, basis = "inconclusive", "needs_follow_up", "not_run"
            await gtx.set_status(
                lead, status, outcome=outcome,
                data={"evidence": {"supports": supports, "contradicts": contradicts},
                      "basis": basis,
                      "rationale": f"{_n(len(done), 'test')} ran of {len(wos)}; "
                                   f"{supports} supporting, {contradicts} contradicting"})
            await self.decision(
                session, "settle_lead",
                f"lead {lead.label!r} explored: surface mapped, {supports} observation(s)"
                if mapping and status == "confirmed"
                else f"lead {lead.label!r} {status} ({outcome})",
                considered=len(wos),
                trigger_=trigger("wo_terminal", node_ids=[lead.id] + [
                    w.node_id for w in wos if w.node_id]))

    async def _observations_of(self, session: AsyncSession,
                               wo_id: uuid.UUID) -> list[GreyboxGraphNode]:
        actions = select(GreyboxGraphNode.id).where(
            GreyboxGraphNode.run_id == self.run_id, GreyboxGraphNode.kind == "action",
            GreyboxGraphNode.work_order_id == wo_id)
        return list((await session.scalars(
            select(GreyboxGraphNode).join(
                GreyboxGraphEdge, GreyboxGraphEdge.dst_id == GreyboxGraphNode.id)
            .where(GreyboxGraphEdge.run_id == self.run_id,
                   GreyboxGraphEdge.rel == "observed",
                   GreyboxGraphEdge.src_id.in_(actions))
            .order_by(GreyboxGraphNode.key))).all())

    async def complete(self, session: AsyncSession, gtx: GraphTx) -> None:
        await self.decision(session, "complete",
                            "no pending or running work orders remain")

    async def budget_stop(self, session: AsyncSession, gtx: GraphTx,
                          budget: str, limit: int, used: int,
                          skipped: int) -> None:
        await events.emit(
            session, self.run_id, "run.budget_exhausted",
            f"{budget} budget exhausted ({used}/{limit})", level="warning",
            status="skipped",
            data={"budget": budget, "limit": limit, "used": used,
                  "work_orders_skipped": skipped})

    # ------------------------------------------------------------------ hints
    async def process_hints(self, session: AsyncSession, gtx: GraphTx
                            ) -> tuple[HintView, ...]:
        """Apply every open analyst hint exactly once. A hint can only
        reorder, skip or add *in-scope* work: seeds go through ``admit`` (dedup, scope
        and budgets as usual) and every request still passes the guarded client.
        Returns the hints handled, as context for the proposer."""
        hints = (await session.scalars(
            select(GreyboxHint).where(
                GreyboxHint.run_id == self.run_id, GreyboxHint.status == "open")
            .order_by(GreyboxHint.created_at, GreyboxHint.id))).all()
        views = tuple(HintView(h.id, h.action, h.target, h.text or "") for h in hints)
        for hint in hints:
            try:
                async with session.begin_nested():
                    await self._apply_hint(session, gtx, hint)
            except Exception as exc:                 # noqa: BLE001 — never kill the run
                await self.settle_hint(session, gtx, hint, "rejected",
                                       reason=f"internal_error: {type(exc).__name__}")
        return views

    async def settle_hint(self, session: AsyncSession, gtx: GraphTx,
                          hint: GreyboxHint, status: str, *, result: str | None = None,
                          reason: str | None = None,
                          work_orders: list[GreyboxWorkOrder] = ()) -> None:
        """Mark ``hint`` addressed/rejected: row, event, graph node and guides edges."""
        node = await session.get(GreyboxGraphNode, hint.node_id) \
            if hint.node_id else None
        wo_ids = [w.id for w in work_orders]
        if status == "addressed":
            ev = await events.emit(
                session, self.run_id, "hint.addressed",
                f"hint addressed: {result}",
                data={"hint_id": str(hint.id), "result": result,
                      "work_order_ids": [str(i) for i in wo_ids]},
                refs={"node_ids": ([node.id] if node else []) +
                      [w.node_id for w in work_orders if w.node_id]},
                agent_id=self.planner_agent_id)
        else:
            result = reason
            ev = await events.emit(
                session, self.run_id, "hint.rejected", f"hint rejected: {reason}",
                data={"hint_id": str(hint.id), "reason": reason},
                refs={"node_ids": [node.id] if node else []},
                agent_id=self.planner_agent_id)
        hint.status = status
        hint.result = events.clip(result, 500)
        hint.work_order_ids = [str(i) for i in wo_ids]
        hint.addressed_at = datetime.now(timezone.utc)
        if node is not None and status == "addressed" and hint.action == "note":
            # A free-text note is only *delivered* here: the agent has not read it
            # yet. Its graph node stays open (in force) until the agent or the
            # platform fallback replies (messages.write_reply settles it), so the
            # graph never shows a message as done that nobody has answered.
            await gtx.set_status(node, "open",
                                 data={"result": "delivered to the agent; awaiting "
                                                 "its reply"},
                                 last_event_seq=ev.seq)
        elif node is not None:
            await gtx.set_status(node, status, data={"result": hint.result},
                                 last_event_seq=ev.seq)
            for w in work_orders:
                wn = await session.get(GreyboxGraphNode, w.node_id) \
                    if w.node_id else None
                if wn is not None:
                    await gtx.edge(node, wn, "guides")

    async def _matching_pending(self, session: AsyncSession, url: str,
                                ) -> list[GreyboxWorkOrder]:
        """Pending work orders whose asset key or url/endpoint param is under ``url``
        (same service, prefix match on the normalised path; covers an exact URL)."""
        want = url_keys(url)
        if want is None:
            return []
        rows = (await session.execute(
            select(GreyboxWorkOrder, GreyboxAsset.key)
            .outerjoin(GreyboxAsset, GreyboxAsset.id == GreyboxWorkOrder.asset_id)
            .where(GreyboxWorkOrder.run_id == self.run_id,
                   GreyboxWorkOrder.status == "pending")
            .order_by(GreyboxWorkOrder.created_at, GreyboxWorkOrder.id))).all()
        out = []
        for wo, asset_key in rows:
            cands = [asset_key.split("#", 1)[0]] if asset_key else []
            for k in ("url", "endpoint"):
                v = (wo.params or {}).get(k)
                if isinstance(v, str):
                    cands.append(v)
            if any(_under(c, want.service, want.path) for c in cands):
                out.append(wo)
        return out

    async def _seed(self, session: AsyncSession, gtx: GraphTx, url: str,
                    priority: int, why: str, hint: GreyboxHint | None = None,
                    ) -> GreyboxWorkOrder | None:
        wo = await self.create_wo(
            session, gtx, tool="discovery.crawl", kind="discovery",
            title=_title("discovery.crawl", url), reason=why,
            params={"url": url, "seeds": [url], "max_pages": 1},
            priority=priority, parent_node_id=self.state.objective_node_id,
            variant=_seed_variant(url))
        if wo is not None:
            await self.decision(
                session, "dispatch", f"analyst seed {url}", work_orders=[wo],
                considered=1,
                trigger_=trigger("hint", node_ids=[hint.node_id] if hint else [],
                                 hint_ids=[hint.id] if hint else []))
        return wo

    async def _apply_hint(self, session: AsyncSession, gtx: GraphTx,
                          hint: GreyboxHint) -> None:
        st = self.state
        action, target = hint.action, (hint.target or "").strip()
        if action == "note":
            return await self.settle_hint(session, gtx, hint, "addressed",
                                          result="noted")
        if action == "skip_check":
            if target not in st.checks:
                return await self.settle_hint(session, gtx, hint, "rejected",
                                              reason="check_not_selected")
            st.skipped_checks.add(target)
            pending = (await session.scalars(
                select(GreyboxWorkOrder).where(
                    GreyboxWorkOrder.run_id == self.run_id,
                    GreyboxWorkOrder.status == "pending",
                    GreyboxWorkOrder.tool == target)
                .order_by(GreyboxWorkOrder.created_at, GreyboxWorkOrder.id))).all()
            for wo in pending:
                wo.status = "skipped"
                wo.result_summary = "skipped by operator"
                wo.finished_at = datetime.now(timezone.utc)
                ev = await events.emit(
                    session, self.run_id, "work_order.skipped",
                    f"{wo.tool} skipped: operator hint",
                    data={"reason": "operator", "hint_id": str(hint.id)},
                    agent_id=self.planner_agent_id, work_order_id=wo.id,
                    refs={"node_ids": [wo.node_id] if wo.node_id else []})
                node = await session.get(GreyboxGraphNode, wo.node_id) \
                    if wo.node_id else None
                if node is not None:
                    await gtx.set_status(node, "skipped", last_event_seq=ev.seq,
                                         outcome="not_applicable")
            return await self.settle_hint(
                session, gtx, hint, "addressed", work_orders=pending,
                result=f"skipped {_n(len(pending), 'pending work order')} for "
                       f"{target}; no new ones will be created")
        # focus / add_seed / deprioritize: the target is a URL or a path
        url = resolve_hint_url(st.base_url, target)
        if url is None or url_keys(url) is None:
            return await self.settle_hint(session, gtx, hint, "rejected",
                                          reason="invalid_target")
        if action in ("focus", "add_seed"):
            decision = st.scope.check_url(url)
            if not decision.allowed:
                return await self.settle_hint(session, gtx, hint, "rejected",
                                              reason=decision.reason or "out_of_scope")
        if action == "add_seed":
            # interactive lane: an analyst seed does not wait behind a running crawl
            wo = await self._seed(session, gtx, url, PRIORITY_FOCUS_SEED,
                                  f"analyst hint: crawl from {url}", hint)
            if wo is None:
                return await self.settle_hint(session, gtx, hint, "addressed",
                                              result="seed already planned")
            return await self.settle_hint(session, gtx, hint, "addressed",
                                          work_orders=[wo], result="added 1 seed")
        keys = url_keys(url)
        # standing directive: work created later under this prefix inherits it
        self._add_directive("focus" if action == "focus" else "depri",
                            keys.service, keys.path)
        matched = await self._matching_pending(session, url)
        level = PRIORITY_FOCUS if action == "focus" else PRIORITY_DEPRIORITIZED
        touched: list[GreyboxWorkOrder] = []
        for wo in matched:
            wo.priority = level
            node = await session.get(GreyboxGraphNode, wo.node_id) \
                if wo.node_id else None
            if node is not None:
                await gtx.set_status(node, node.status, data={"priority": level})
            touched.append(wo)
        if action == "deprioritize":
            return await self.settle_hint(
                session, gtx, hint, "addressed", work_orders=touched,
                result=f"deprioritised {_n(len(touched), 'work order')}")
        seeds = 0
        known = await session.scalar(
            select(GreyboxAsset.id).where(
                GreyboxAsset.run_id == self.run_id, GreyboxAsset.kind == "endpoint",
                GreyboxAsset.key == keys.endpoint))
        if known is None:
            wo = await self._seed(session, gtx, url, PRIORITY_FOCUS_SEED,
                                  f"analyst hint: focus on undiscovered {url}", hint)
            if wo is not None:
                touched.append(wo)
                seeds = 1
        await self.settle_hint(
            session, gtx, hint, "addressed", work_orders=touched,
            result=f"prioritised {_n(len(matched), 'work order')}, "
                   f"added {_n(seeds, 'seed')}")

    async def reject_open_hints(self, session: AsyncSession, gtx: GraphTx,
                                reason: str = "run_ended") -> None:
        """Hints still open when the run ends are rejected (before the terminal event)."""
        hints = (await session.scalars(
            select(GreyboxHint).where(
                GreyboxHint.run_id == self.run_id, GreyboxHint.status == "open")
            .order_by(GreyboxHint.created_at, GreyboxHint.id))).all()
        for hint in hints:
            await self.settle_hint(session, gtx, hint, "rejected", reason=reason)
