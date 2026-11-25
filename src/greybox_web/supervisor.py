"""RunSupervisor: executes one claimed grey-box run.

One supervisor per claimed run, in the worker process (or the in-process
executor). It owns:

* a ``Budget`` and the single ``GuardedHttpClient`` every tool request goes
  through, with a :class:`DbRecorder` that redacts and persists every exchange
  (blocked attempts included) and emits ``http.exchange`` / ``scope.blocked``;
* fixed worker slots (``discovery-1``, ``checker-1..2``, ``verifier-1``) backed
  by ``greybox_agents`` rows, plus logical ``planner`` and ``reporter`` agents;
* the deterministic :class:`~src.greybox_web.planner.Planner`, woken after each
  completion batch (debounced by the loop's 0.5 s tick);
* a 1 s cancel watcher (M2 acceptance: cancelled within 5 s) and the lease
  heartbeat (``greybox_heartbeat_s``); a lost lease stops the supervisor
  **without writing anything further** — the reaper owns the run then.

All writes go through :func:`src.greybox_web.txn.write`: short transactions,
nothing held across tool execution, and the terminal ``run.*`` event is the
last event of the run.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from collections.abc import Callable
from typing import Any

from sqlalchemy import func, not_, or_, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from src.greybox_web.netcap import GuardedNet, ToolNet
from src.greybox_web import coverage, events, findclass, modes, netproject, redaction, tools, wakeup
from src.greybox_web.exploration import (
    AgentBudget,
    AgentUnavailable,
    ModelClient,
    build_client,
)
from src.greybox_web.exploration.explorer import MODEL_RETRIES, Explorer
from src.greybox_web.exploration.knowledge import (
    frontier_view,
    is_work_url,
)
from src.greybox_web.exploration import messages as opmsg
from src.greybox_web.exploration.proposer import LlmProposer
from src.greybox_web.graph import GraphStats, GraphTx, url_keys
from src.greybox_web.models import (
    GB_CANCELLING,
    GB_CANCELLED,
    GB_FAILED,
    GB_PREPARING,
    GB_RUNNING,
    GB_SUCCEEDED,
    GB_TERMINAL,
    GreyboxAgent,
    GreyboxAsset,
    GreyboxEvent,
    GreyboxFinding,
    GreyboxGraphNode,
    GreyboxHint,
    GreyboxHttpExchange,
    GreyboxReport,
    GreyboxRun,
    GreyboxTarget,
    GreyboxWorkOrder,
)
from src.greybox_web.netguard import (
    Budget,
    BudgetExhausted,
    GuardedHttpClient,
    NetPolicy,
    Resolver,
    RunCancelled,
    ScopeViolation,
    TransportFailure,
)
from src.greybox_web.planner import (
    PRIORITY_FOCUS_SEED,
    EventView,
    NewAsset,
    NewFinding,
    Planner,
    PlannerProtocol,
    PlannerState,
    Terminal,
)
from src.greybox_web.tools.discovery import url_query_params
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.txn import read as tx_read
from src.greybox_web.txn import write as tx_write

log = logging.getLogger(__name__)

BODY_STORE_CAP = 64 * 1024          # stored per body
BINARY_TYPES = ("image/", "audio/", "video/", "font/", "application/octet-stream",
                "application/zip", "application/gzip", "application/pdf",
                "application/wasm", "application/x-msdownload")
CANCEL_POLL_S = 1.0                 # dedicated watcher: 5 s acceptance
SKIP = "skip"                       # sentinel: work order skipped at claim (unregistered tool)
GRAPH_FLUSH_S = 0.5                 # coalesce graph.updated
MAX_IDLE_GATES = 500                # explorer idle gates per run (loop bound)
MAX_MODEL_FAILURES = 3              # consecutive failed model cycles (nothing in flight) that end the run
EMPTY_ROUNDS_TO_COMPLETE = 3        # consecutive fresh idle cycles admitting no work that end the run
GRACE_MARGIN_S = 30.0               # idle-gate wait = model timeout x attempts + this
GRACE_CAP_S = 600.0
from src.greybox_web.modelsel import NO_MODEL_MESSAGE  # noqa: E402
POLL_S = 0.25                       # cross-process fallback for hints (in-process: wakeup)
PLANNER_EVENT_KINDS = ("observation.recorded", "finding.created", "finding.verified",
                       "finding.rejected", "work_order.completed", "work_order.failed",
                       "work_order.skipped", "hint.added", "asset.discovered")
PLANNER_EVENTS_PER_CYCLE = 200


def grace_seconds(model_timeout_s: float) -> float:
    """How long the idle gate waits for one planner cycle: the model timeout times its
    attempts (first try + transient retries), plus a margin; capped."""
    return min(GRACE_CAP_S, model_timeout_s * (MODEL_RETRIES + 1) + GRACE_MARGIN_S)


# Hard ceiling on one tool call. A tool that never returns (a wedged browser page, a
# stuck socket) would otherwise hold its slot forever: discovery has one general slot,
# so the whole frontier, and the agent's plans that depend on it, would stall while the
# run still looks alive. On timeout the work order fails and the run moves on.
TOOL_TIMEOUT_S = 600.0               # crawls can legitimately take minutes
BROWSER_TOOL_TIMEOUT_S = 90.0        # render calls fail promptly
SCRIPT_TOOL_TIMEOUT_S = 150.0        # at most eight guarded bundle requests
PENDING_STARVATION_S = 45.0          # old queued work runs before newer model proposals


def tool_timeout_s(tool: str, limits: dict | None = None) -> float:
    """The ceiling for one call of ``tool`` (``limits['tool_timeout_s']`` overrides
    the general value; browser tools keep their tighter bound)."""
    general = float((limits or {}).get("tool_timeout_s") or TOOL_TIMEOUT_S)
    if tool.startswith("browser."):
        return min(general, BROWSER_TOOL_TIMEOUT_S)
    if tool == "discovery.scripts":
        return min(general, SCRIPT_TOOL_TIMEOUT_S)
    return general


@dataclass(frozen=True)
class Slot:
    name: str
    role: str          # discovery | checker | verifier
    kinds: frozenset   # work-order kinds this slot runs
    max_priority: int | None = None    # interactive lane: only work with priority <= this
    tool_prefixes: tuple[str, ...] = ()
    exclude_tool_prefixes: tuple[str, ...] = ()


def slot_accepts(slot: Slot, tool: str, priority: int) -> bool:
    """Whether a pending order can use ``slot``.

    Browser work has its own lane: a renderer waiting on application scripts can no
    longer block crawls, skill reads and passive discovery behind it (or vice versa).
    """
    if slot.max_priority is not None and priority > slot.max_priority:
        return False
    if slot.tool_prefixes and not tool.startswith(slot.tool_prefixes):
        return False
    return not slot.exclude_tool_prefixes or not tool.startswith(
        slot.exclude_tool_prefixes)


def slot_filters(slot: Slot) -> list[Any]:
    """Database predicates equivalent to :func:`slot_accepts`."""
    predicates: list[Any] = []
    if slot.max_priority is not None:
        predicates.append(GreyboxWorkOrder.priority <= slot.max_priority)
    if slot.tool_prefixes:
        predicates.append(or_(*(GreyboxWorkOrder.tool.like(f"{p}%")
                                for p in slot.tool_prefixes)))
    if slot.exclude_tool_prefixes:
        predicates.append(not_(or_(*(GreyboxWorkOrder.tool.like(f"{p}%")
                                     for p in slot.exclude_tool_prefixes))))
    return predicates


LOCAL_ANALYSIS_PREFIXES = ("skill.", "discovery.routes", "netview.", "tool.")
REMOTE_DISCOVERY_PREFIXES = ("browser.", *LOCAL_ANALYSIS_PREFIXES)

SLOTS = (
    Slot("browser-1", "discovery", frozenset({"discovery"}),
         tool_prefixes=("browser.",)),
    Slot("analysis-1", "discovery", frozenset({"discovery"}),
         tool_prefixes=LOCAL_ANALYSIS_PREFIXES),
    Slot("discovery-1", "discovery", frozenset({"discovery"}),
         exclude_tool_prefixes=REMOTE_DISCOVERY_PREFIXES),
    # Interactive lane: analyst seeds and focused discovery never wait
    # behind a running crawl batch.
    Slot("discovery-2", "discovery", frozenset({"discovery"}),
         max_priority=PRIORITY_FOCUS_SEED,
         exclude_tool_prefixes=REMOTE_DISCOVERY_PREFIXES),
    Slot("checker-1", "checker", frozenset({"check"})),
    Slot("checker-2", "checker", frozenset({"check"})),
    Slot("verifier-1", "verifier", frozenset({"verify"})),
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------- recorder


class DbRecorder:
    """Persists every exchange attempt, redacted, with its event, in one txn."""

    def __init__(self, factory: async_sessionmaker, run_id: uuid.UUID) -> None:
        self.factory = factory
        self.run_id = run_id

    async def record(self, ex) -> int | None:
        async def fn(session: AsyncSession) -> int | None:
            row = _exchange_row(self.run_id, ex)
            session.add(row)
            await session.flush()
            await session.execute(
                update(GreyboxRun).where(GreyboxRun.id == self.run_id)
                .values(requests_made=GreyboxRun.requests_made + 1,
                        requests_blocked=GreyboxRun.requests_blocked
                        + (1 if ex.blocked else 0))
                .execution_options(synchronize_session=False))
            if ex.blocked:
                await events.emit(
                    session, self.run_id, "scope.blocked",
                    f"blocked ({ex.block_reason}): {redaction.url(ex.url)}",
                    level="warning", status="blocked",
                    data={"exchange_id": row.id, "url": redaction.url(ex.url),
                          "reason": ex.block_reason},
                    refs={"exchange_ids": [row.id]},
                    agent_id=ex.agent_id, work_order_id=ex.work_order_id,
                    tool_call_id=ex.tool_call_id)
            else:
                await events.emit(
                    session, self.run_id, "http.exchange",
                    f"{ex.method} {redaction.url(ex.url)} -> "
                    f"{ex.status_code if ex.status_code is not None else ex.error}",
                    level="debug", status="ok" if ex.status_code is not None
                    else "error",
                    data={"exchange_id": row.id, "method": ex.method,
                          "url": redaction.url(ex.url),
                          "status_code": ex.status_code,
                          "duration_ms": ex.duration_ms,
                          "redirect_hop": ex.redirect_hop},
                    refs={"exchange_ids": [row.id]},
                    agent_id=ex.agent_id, work_order_id=ex.work_order_id,
                    tool_call_id=ex.tool_call_id)
            return int(row.id) if row.id is not None else None

        return await tx_write(self.factory, fn)


def _binary(ct: str | None) -> bool:
    ct = (ct or "").lower()
    return any(ct.startswith(p) for p in BINARY_TYPES) or "binary" in ct


def _store_body(body: bytes | None, ct: str | None) -> tuple[str | None, bool, str | None]:
    """(stored_text, truncated, omitted_reason). The text is redacted BEFORE it is
    cut to the cap, so a secret cannot survive half-cut at the boundary."""
    if body is None:
        return None, False, "not_captured"
    if _binary(ct):
        return None, False, "binary"
    raw = body.decode("utf-8", errors="replace")
    if ct and "application/x-www-form-urlencoded" in ct.lower():
        text = redaction.body(raw, ct) or ""
    else:
        text = redaction.body_text(raw) or ""
    if len(raw) > BODY_STORE_CAP:
        return text[:BODY_STORE_CAP], True, None
    return text, False, None


_TRANSPORT_ERRORS = {
    "connect_error": "connection refused or no route to host",
    "dns_error": "the host name did not resolve",
    "timeout": "the request timed out",
    "transport_error": "the connection failed",
}
DIRECT_PROXY_HINT = ("If a browser can reach this host, it may require a proxy (PAC/WPAD); "
                     "an administrator can configure an egress proxy.")
_PROXY_MESSAGES = {
    "proxy_unreachable": "could not connect to the egress proxy '{p}' (proxy unreachable: "
                         "connection refused, no route or timeout); ask an administrator "
                         "to check the proxy",
    "proxy_auth": "the egress proxy '{p}' rejected its credentials (407 proxy "
                  "authentication failed); ask an administrator to update them",
    "proxy_refused": "target refused via proxy: the egress proxy '{p}' would not connect "
                     "to the target (denied by the proxy's rules, or the target is "
                     "unreachable from the proxy)",
    "tls_error": "TLS verification of the target failed through the egress proxy '{p}'",
}


def _unreachable_message(base_url: str, code: str | None,
                         proxy_name: str | None = None) -> str:
    """Preflight failure text shown to the user (Overview tab, run.failed event)."""
    if proxy_name is not None and code in _PROXY_MESSAGES:
        return (f"Target unreachable: {base_url} could not be reached: "
                + _PROXY_MESSAGES[code].format(p=proxy_name) + ".")
    why = _TRANSPORT_ERRORS.get(code or "", code or "no response")
    msg = f"Target unreachable: could not connect to {base_url} ({why})."
    if proxy_name is None and code == "connect_error":
        msg += " " + DIRECT_PROXY_HINT
    return msg


def _exchange_row(run_id: uuid.UUID, ex) -> GreyboxHttpExchange:
    req_body = redaction.body(ex.request_body, "application/x-www-form-urlencoded") \
        if ex.request_body else None
    resp_text, resp_trunc, omitted = _store_body(ex.response_body, ex.content_type)
    return GreyboxHttpExchange(
        run_id=run_id, ts=utcnow(), agent_id=ex.agent_id,
        work_order_id=ex.work_order_id, tool=ex.tool, tool_call_id=ex.tool_call_id,
        method=ex.method, url=redaction.url(ex.url)[:2000], scheme=ex.scheme,
        host=ex.host, port=ex.port, path=redaction.text(ex.path)[:1000] if ex.path else None,
        resolved_ip=ex.resolved_ip, via_proxy=bool(getattr(ex, "via_proxy", False)),
        status_code=ex.status_code,
        duration_ms=ex.duration_ms,
        request_headers=redaction.headers(ex.request_headers or []),
        request_body=req_body, request_body_truncated=False,
        response_headers=redaction.headers(ex.response_headers or []),
        response_body=resp_text, response_body_truncated=resp_trunc,
        response_size=len(ex.response_body) if ex.response_body is not None else None,
        content_type=ex.content_type, body_omitted_reason=omitted,
        blocked=bool(ex.blocked), block_reason=ex.block_reason, error=ex.error,
        redirect_hop=ex.redirect_hop, parent_exchange_id=ex.parent_exchange_id,
        identity=getattr(ex, "identity", None))

# ------------------------------------------------------------------ slot jobs


@dataclass
class WOJob:
    wo_id: uuid.UUID
    tool: str
    params: dict[str, Any]
    tool_call_id: str
    agent_id: uuid.UUID
    attempts: int


@dataclass
class WODone:
    job: WOJob
    outcome: str                 # ok | retry | fail | budget | cancelled
    result: Any = None
    error: str | None = None
    budget: str | None = None
    duration_ms: int = 0


@dataclass
class _Snapshot:
    run_id: uuid.UUID
    target_id: uuid.UUID
    base_url: str
    scope: ScopePolicy
    limits: dict[str, Any]
    checks: list[str]
    credential_id: uuid.UUID | None
    max_requests: int
    max_duration_s: int
    egress_proxy: dict[str, Any] | None = None     # {id, name, url} snapshot at start
    model_backend: str = ""                        # the run's selected model (snapshot)
    model: str = ""


# ------------------------------------------------------------------- supervisor


class RunSupervisor:
    def __init__(self, factory: async_sessionmaker, run_id: uuid.UUID,
                 worker_id: str, *, policy: NetPolicy | None = None,
                 resolver: Resolver | None = None, transport=None,
                 planner_factory: Callable[[PlannerState], PlannerProtocol] | None = None,
                 model_client: ModelClient | None = None,
                 explorer_options: dict | None = None,
                 ) -> None:
        """``planner_factory(state)`` builds the proposer (default: the LLM proposer,
        driven by the explorer). Whatever it proposes is admitted by
        ``Planner.admit`` (scope, selected checks, param allow-list, quotas, dedup);
        it cannot widen the run. ``model_client`` (tests) replaces the client built
        from the configured backend; ``explorer_options`` tunes the explorer
        (coalescing window, retry backoff)."""
        self.planner_factory = planner_factory or (
            lambda state: LlmProposer(state.dynamic_tools))
        self._model_client = model_client
        self._explorer_options = dict(explorer_options or {})
        self._wake = asyncio.Event()
        self._event_cursor = 0
        self.factory = factory
        self.worker_id = worker_id
        # Run-scoped dynamic tool registry (batch E): admission fills it when a
        # tool.define spec validates (dyn.<id> + verify.<id> entries); the claim
        # path, verification and the knowledge resolve through it. In-memory by
        # design — the registry lives exactly as long as this run's process.
        self.run_dynamic_tools: dict[str, tools.ToolSpec] = {}
        self._injected = dict(policy=policy, resolver=resolver, transport=transport)
        self.run_id = run_id
        self.snap: _Snapshot | None = None
        self.client: GuardedHttpClient | None = None
        self.net: GuardedNet | None = None
        self._coverage_challenged = False
        self._resumed = False
        self._model_budget_spent = False
        self._identity_writes: set[asyncio.Task] = set()
        self._identity_note: str | None = None
        self.budget: Budget | None = None
        self.stats = GraphStats()
        self.planner: Planner | None = None
        self._agents: dict[str, uuid.UUID] = {}
        self._slot_tasks: dict[str, asyncio.Task] = {}
        self._task_slot: dict[int, str] = {}
        self._slot_wo: dict[str, uuid.UUID] = {}
        self._bg: list[asyncio.Task] = []
        self._cancelled = False
        self._lost = False
        self._budget_stop: str | None = None
        self._fail: tuple[str, str] | None = None      # ("preflight"|"error", text)
        self._last_graph_flush = 0.0
        self._planned_ids: set[uuid.UUID] = set()      # agent ids created
        # Exploration agent: the only proposer of
        # the run, started by _maybe_start_explorer. Without a model the run fails
        # fast; there is no rule fallback.
        self.explorer: Explorer | None = None
        self._llm: LlmProposer | None = None
        self._idle_grace_s: float = 150.0
        self._idle_gates = 0                           # explorer idle gates entered
        self._reporting = False                        # the final report is being written
        self._idle_silences = 0                        # consecutive idle gates without an answer
        self._empty_rounds = 0                         # consecutive fresh idle cycles, no work admitted
        self._explorer_note: str | None = None         # surfaced in the run report

    # ------------------------------------------------------------- lifecycle
    async def run_to_completion(self) -> None:
        wakeup.register(self.run_id, self._wake)
        try:
            await self._setup()
            if self._lost:
                return
            await self._setup_txn()
            if self._lost:
                return
            await self._maybe_start_explorer()
            if self._cancelled:
                await self._finalize(("cancelled", "user", None))
                return
            outcome = await self._execute()
            if outcome[0] == "lost":
                return
            if self.explorer is not None:
                await self.explorer.stop()     # no reasoning past the engine loop
            if outcome[0] == "completed" and not self._fail:
                await self._report(outcome[1] or "completed")
            await self._finalize(outcome)
        except RunCancelled:
            await self._drain()
            await self._finalize(("cancelled", "user", None))
        except Exception as exc:                       # noqa: BLE001 — fail the run
            log.exception("grey-box run %s failed", self.run_id)
            try:
                await self._drain()
                await self._finalize(("failed", "error", f"{type(exc).__name__}: {exc}"))
            except Exception:                          # noqa: BLE001 — reaper fallback
                log.exception("grey-box run %s: could not record the failure; "
                              "the reaper will fail it on lease expiry", self.run_id)
        finally:
            wakeup.unregister(self.run_id, self._wake)
            if self.explorer is not None:
                await self.explorer.stop()
            for t in self._bg:
                t.cancel()
            try:                                   # the run's browser, if it had one
                from src.greybox_web.tools import browser as _browser
                await asyncio.wait_for(_browser.close_run(self.run_id), timeout=20)
            except Exception:                      # noqa: BLE001 — never block teardown
                log.warning("grey-box run %s: browser close failed", self.run_id)
            if self._identity_writes:              # the last identity state lands
                await asyncio.wait(list(self._identity_writes), timeout=10)
            if self.client is not None:
                await self.client.aclose()

    async def _setup(self) -> None:
        from src.greybox_web import settings as gb_settings

        async def fn(session: AsyncSession) -> _Snapshot | tuple | None:
            run = await session.get(GreyboxRun, self.run_id)
            if run is None:
                return None
            return (run, await session.get(GreyboxTarget, run.target_id))

        got = await tx_read(self.factory, fn)
        if got is None:
            self._lost = True
            return
        run, _target = got
        s = gb_settings.settings()
        self.snap = _Snapshot(
            run_id=run.id, target_id=run.target_id, base_url=run.base_url,
            scope=ScopePolicy.from_dict(run.scope), limits=dict(run.limits or {}),
            checks=list(run.checks or []), credential_id=run.credential_id,
            max_requests=int((run.limits or {}).get("max_requests", 1000)),
            max_duration_s=int((run.limits or {}).get("max_duration_s", 900)),
            egress_proxy=run.egress_proxy if isinstance(run.egress_proxy, dict)
            else None,
            model_backend=getattr(run, "model_backend", "") or "",
            model=getattr(run, "model", "") or "")
        # A resumed run keeps the requests it already spent (its time window is new:
        # the interruption was not assessment time).
        self.budget = Budget(self.snap.max_requests, self.snap.max_duration_s,
                             used=int(run.requests_made or 0))

        cookie: str | None = None
        if run.credential_id is not None:
            async def cred_fn(session: AsyncSession) -> tuple | None:
                from src.webapi.credential_guard import validate_cookie_credential
                from src.webapi.models import Credential
                from src.webapi.security.vault import build_vault
                cred = await session.get(Credential, run.credential_id)
                validate_cookie_credential(cred, run.owner_id)
                return build_vault(gb_settings.settings()).decrypt(cred.secret_enc)
            try:
                cookie = await tx_read(self.factory, cred_fn)
            except Exception as exc:                   # noqa: BLE001
                # Never fall back to an unauthenticated run (design: the credential
                # is re-validated at run start). Fail with a clear reason.
                raise CredentialUnavailable(
                    "credential could not be loaded; run not started "
                    f"unauthenticated ({type(exc).__name__})") from None
            if cookie:
                redaction.register_secret(cookie)      # before the first write
        # Login accounts (optional): decrypted once at run start, passwords
        # registered as redaction secrets, and held only by this supervisor.
        # auth.login uses them through ctx.account_credentials; they never enter
        # work orders, events, knowledge or stored exchanges.
        self._account_secrets: dict[str, dict] = {}
        for aid in (run.account_ids or [] if self.snap.scope.allow_auth_testing else []):
            async def acct_fn(session: AsyncSession, aid=uuid.UUID(str(aid))) -> dict | None:
                from src.webapi.credential_guard import validate_login_credential
                from src.webapi.models import Credential
                cred = await session.get(Credential, aid)
                data = validate_login_credential(cred, run.owner_id)
                data["label"] = cred.label
                return data
            try:
                acct = await tx_read(self.factory, acct_fn)
            except Exception:                        # noqa: BLE001 — same policy as the cookie
                raise CredentialUnavailable(
                    "a login account could not be loaded; run not started "
                    "half-authenticated") from None
            if acct:
                label = acct["label"]
                self._account_secrets[label] = acct
                redaction.register_secret(acct.get("password"))
        proxy = await self._load_proxy()
        policy: NetPolicy = self._injected.get("policy") or NetPolicy.from_settings()
        self.client = GuardedHttpClient(
            scope=self.snap.scope, budget=self.budget, policy=policy,
            max_concurrency=int(self.snap.limits.get("max_concurrency", 4)),
            rate_limit_rps=float(self.snap.limits.get("rate_limit_rps", 10)),
            request_timeout_s=float(self.snap.limits.get("request_timeout_s", 10)),
            recorder=DbRecorder(self.factory, self.run_id),
            resolver=self._injected.get("resolver"),
            transport=self._injected.get("transport"), cookie_header=cookie,
            egress_proxy=proxy)
        # Identity persistence for resume (sessionvault.py): every change to the
        # run's sessions or browser jars is written, encrypted; a resumed run gets
        # them back while they are fresh.
        self.client.on_identity_change = self._persist_identities
        self._identity_note = await self._restore_identities(run)
        # Raw-protocol guard (TCP/DNS). Always present so a tool gets an honest
        # refusal ("no_network_scope") rather than a missing attribute: without a
        # network scope, ScopePolicy.check_endpoint refuses every socket.
        self.net = GuardedNet(self.client)
        self._bg.append(asyncio.create_task(self._watcher(), name="gb-cancel-watch"))
        self._bg.append(asyncio.create_task(
            self._heartbeat_loop(s.greybox_heartbeat_s, s.greybox_lease_ttl_s),
            name="gb-heartbeat"))

    def _persist_identities(self) -> None:
        """Called (synchronously) by the guarded client when an identity changes:
        schedule the encrypted write without blocking the tool."""
        if self.client is None:
            return
        sessions, jars = self.client.identity_state()
        task = asyncio.get_running_loop().create_task(
            self._write_identities(sessions, jars))
        self._identity_writes.add(task)
        task.add_done_callback(self._identity_writes.discard)

    async def _write_identities(self, sessions: dict, jars: dict) -> None:
        from src.greybox_web import sessionvault
        try:
            blob = sessionvault.seal(sessions, jars)

            async def fn(session: AsyncSession) -> None:
                run = await session.get(GreyboxRun, self.run_id)
                if run is not None:
                    run.session_vault = blob
            await tx_write(self.factory, fn)
        except Exception:                          # noqa: BLE001 — never fail the run
            log.warning("grey-box run %s: identity state not persisted", self.run_id)

    async def _restore_identities(self, run: GreyboxRun) -> str | None:
        """On a resumed run: reinstate fresh identities, or say why not."""
        from src.greybox_web import sessionvault
        blob = getattr(run, "session_vault", None)
        if not blob:
            return None
        doc, why = sessionvault.unseal(blob)
        if doc is None:
            return (f"identity state from before the interruption not restored "
                    f"({why}); sessions must be established again")
        sessionvault.register_secrets(doc)          # before anything is written
        labels = self.client.restore_identities(doc.get("sessions") or {},
                                                doc.get("jars") or {})
        jars = sorted((doc.get("jars") or {}).keys())
        return (f"restored {len(labels)} session(s) ({', '.join(labels) or 'none'}) "
                f"and {len(jars)} browser identity jar(s) "
                f"({', '.join(jars) or 'none'}) from before the interruption")

    async def _load_proxy(self):
        """The run's egress proxy with its decrypted credentials, or None (direct).
        Fails the run (never falls back to a direct connection) when the proxy was
        removed or disabled, the feature switched off, or the target's hosts are no
        longer allowed by it."""
        snap = self.snap.egress_proxy if self.snap else None
        if not snap:
            return None
        from src.greybox_web import settings as gb_settings
        from src.greybox_web.api.egress_proxies import to_engine_proxy
        from src.greybox_web.models import GreyboxEgressProxy

        async def fn(session: AsyncSession):
            row = await session.get(GreyboxEgressProxy, uuid.UUID(str(snap["id"])))
            if row is None or not row.enabled:
                return None
            return to_engine_proxy(row)

        name = snap.get("name")
        if not gb_settings.egress_proxies_enabled():
            raise EgressProxyUnavailable(
                f"egress proxy '{name}' is not available: egress proxies are disabled "
                "on this platform; run not started")
        try:
            proxy = await tx_read(self.factory, fn)
        except Exception as exc:                       # noqa: BLE001
            raise EgressProxyUnavailable(
                f"egress proxy '{name}' could not be loaded ({type(exc).__name__}); "
                "run not started") from None
        if proxy is None:
            raise EgressProxyUnavailable(
                f"egress proxy '{name}' was removed or disabled; run not started")
        missing = proxy.covers(list(self.snap.scope.allowed_hosts))
        if missing:
            raise EgressProxyUnavailable(
                f"egress proxy '{name}' no longer allows: {', '.join(missing)}; "
                "run not started")
        for secret in (proxy.username, proxy.password):
            if secret:
                redaction.register_secret(secret)      # before the first write
        if proxy.username:
            import base64
            redaction.register_secret(base64.b64encode(
                f"{proxy.username}:{proxy.password or ''}".encode()).decode())
        return proxy

    async def _setup_txn(self) -> None:
        st = self.snap
        assert st is not None and self.budget is not None

        async def fn(session: AsyncSession) -> None:
            run = await session.get(GreyboxRun, self.run_id)
            if run is None or run.lease_owner != self.worker_id \
                    or run.status not in (GB_PREPARING, GB_RUNNING, GB_CANCELLING):
                raise _Lost()
            await events.emit(session, self.run_id, "run.started",
                              f"worker {self.worker_id} started the run",
                              data={"worker": self.worker_id, "attempt": run.attempts,
                                    "egress_proxy": (st.egress_proxy or {}).get("name")})
            if run.cancel_requested_at is not None:
                self._cancelled = True
            run.status = GB_RUNNING
            run.started_at = run.started_at or utcnow()
            # agents: planner + slots + reporter
            roles = [("planner", "planner")] + [(s.name, s.role) for s in SLOTS] + \
                [("reporter", "reporter")]
            existing = {a.name: a for a in (await session.scalars(
                select(GreyboxAgent).where(GreyboxAgent.run_id == self.run_id))).all()}
            for name, role in roles:
                agent = existing.get(name)
                if agent is not None:           # a resumed run keeps its agents
                    agent.status = "idle"
                    agent.finished_at = None
                    agent.current_work_order_id = None
                else:
                    agent = GreyboxAgent(id=uuid.uuid4(), run_id=self.run_id,
                                         name=name, role=role, status="idle",
                                         started_at=utcnow())
                    session.add(agent)
                await session.flush()
                self._agents[name] = agent.id
                await events.emit(session, self.run_id, "agent.started",
                                  f"{role} agent {name} started",
                                  data={"role": role, "name": name},
                                  agent_id=agent.id)
            gtx = GraphTx(session, self.run_id, self.stats,
                          agent_id=self._agents["planner"])
            # Resume: a run that already has work continues from it.
            # Work interrupted mid-flight goes back to the queue; everything done
            # stays done (Planner.hydrate rebuilds the dedup sets from it).
            interrupted = (await session.scalars(select(GreyboxWorkOrder).where(
                GreyboxWorkOrder.run_id == self.run_id,
                GreyboxWorkOrder.status == "running"))).all()
            for wo in interrupted:
                wo.status = "pending"
                wo.lease_owner = None
            prior = int(await session.scalar(
                select(func.count()).select_from(GreyboxWorkOrder).where(
                    GreyboxWorkOrder.run_id == self.run_id)) or 0)
            if prior:
                self._resumed = True
                await events.emit(
                    session, self.run_id, "planner.decision",
                    f"resuming: {prior} work order(s) on record, "
                    f"{len(interrupted)} interrupted and re-queued",
                    data={"decision": "resume", "work_orders": prior,
                          "requeued": len(interrupted),
                          "requests_used": self.budget.used})
                if self._identity_note:
                    await events.emit(
                        session, self.run_id, "planner.decision",
                        self._identity_note[:300],
                        data={"decision": "identities_restored"
                              if self._identity_note.startswith("restored")
                              else "identities_not_restored",
                              "detail": self._identity_note[:300]})
            state = PlannerState(
                base_url=st.base_url, scope=st.scope, checks=st.checks,
                max_pages=int(st.limits.get("max_pages", 2000)),
                dynamic_tools=self.run_dynamic_tools,
                capabilities=modes.for_scope(st.scope))
            self.planner = Planner(self.run_id, state, self._agents["planner"],
                                   proposer=self.planner_factory(state))
            await self.planner.hydrate(session)
            if self._resumed and state.objective_node_id is not None:
                await self.planner.begin_cycle(session)
            else:
                await self.planner.initial(session, gtx)

        try:
            await tx_write(self.factory, fn)
        except _Lost:
            self._lost = True

    # ------------------------------------------------------------------ loops
    async def _watcher(self) -> None:
        while True:
            await asyncio.sleep(CANCEL_POLL_S)

            async def fn(session: AsyncSession) -> tuple[bool, bool]:
                row = (await session.execute(
                    select(GreyboxRun.cancel_requested_at, GreyboxRun.status)
                    .where(GreyboxRun.id == self.run_id))).one_or_none()
                if row is None:
                    return False, False          # gone: treat as lost
                cancel = row[0] is not None or row[1] == GB_CANCELLING
                return True, cancel or row[1] in GB_TERMINAL

            alive, stop = await tx_read(self.factory, fn)
            if not alive or stop:
                if not alive:
                    self._lost = True
                self._cancelled = True
                if self.budget:
                    self.budget.cancelled = True
                self._cancel_tasks()
                return

    async def _heartbeat_loop(self, interval_s: int, ttl_s: int) -> None:
        from src.greybox_web.worker import heartbeat
        while True:
            await asyncio.sleep(max(0.5, interval_s))
            try:
                ok, cancel_requested = await heartbeat(self.factory, self.run_id,
                                                       self.worker_id, ttl_s)
            except Exception:                    # noqa: BLE001 — DB gone: stop writing
                ok, cancel_requested = False, False
            if not ok:
                self._lost = True
                self._cancelled = True
                if self.budget:
                    self.budget.cancelled = True
                self._cancel_tasks()
                return
            if cancel_requested:
                self._cancelled = True
                if self.budget:
                    self.budget.cancelled = True
                self._cancel_tasks()
                return

    def _cancel_tasks(self) -> None:
        if self.explorer is not None:
            self.explorer.cancel()          # interrupt an in-flight model call
        for t in list(self._slot_tasks.values()):
            if not t.done():
                t.cancel()

    async def _drain(self, *, graceful_s: float = 0.0) -> None:
        tasks = list(self._slot_tasks.values())
        if graceful_s > 0 and tasks:
            # Requests budget: every request already counted must still be recorded, so
            # in-flight tools finish (their next request raises BudgetExhausted) instead
            # of being cancelled between ``consume()`` and the exchange record.
            await asyncio.wait(tasks, timeout=graceful_s)
        for t in tasks:
            if not t.done():
                t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._slot_tasks.clear()
        self._task_slot.clear()
        self._slot_wo.clear()

    async def _execute(self) -> tuple[str, Any, Any]:
        assert self.budget is not None
        try:
            async with asyncio.timeout(self.budget.max_duration_s):
                return await self._loop()
        except TimeoutError:
            # The outer timeout cancels this loop, not the slot tasks: drain them
            # before anything else writes (no exchange may follow the terminal).
            await self._drain()
            self._budget_stop = self._budget_stop or "time"
            return ("completed", "budget_time", None)

    async def _loop(self) -> tuple[str, Any, Any]:
        while True:
            if self._lost:
                await self._drain()
                return ("lost", None, None)
            if self._cancelled:
                await self._drain()
                return ("cancelled", "user", None)
            if self._fail is not None:
                await self._drain()
                return ("failed", self._fail[0], self._fail[1])
            try:
                self.budget.check()
            except BudgetExhausted as exc:
                self._budget_stop = exc.budget
            if self._budget_stop is not None:
                await self._drain(graceful_s=float(self.snap.limits.get(
                    "request_timeout_s", 10)) + 1.0
                    if self._budget_stop == "requests" else 0.0)
                await self._budget_skip_all()
                return ("completed",
                        f"budget_{self._budget_stop}", None)
            if self._llm is not None and self._llm.stored is not None:
                await self._plan([], [])          # cached explorer proposals
            if await self._open_hints():
                # analyst hints; ``_plan`` resets the empty-round
                # count and wakes the model for each operator message it handles
                await self._plan([], [])
            await self._dispatch()
            await self._maybe_flush_graph()
            if self._slot_tasks:
                self._reset_empty_rounds()       # work was admitted: the model goes on
            if not self._slot_tasks:
                if await self._open_work_orders() == 0:
                    if self._fail:
                        continue
                    if await self._explore_idle():
                        continue                  # a new direction arrived
                    if self._cancelled or self._lost or self._fail:
                        continue                  # cancelled / model failed at the gate
                    # An honest end: "completed" only when nothing crawlable is
                    # left (coverage discipline). A stalled explorer with a
                    # live frontier and page budget is reported as stalled, never
                    # as a finished assessment.
                    return ("completed",
                            "stalled" if self._frontier_left() else "completed",
                            None)
                await self._wait(set(), 0.1)     # pending exists, no free slot yet
                continue
            done = await self._wait(set(self._slot_tasks.values()), POLL_S)
            if done is None:                     # woken by a hint: loop to handle it
                continue
            await self._process_done(done)
            if self.explorer is not None:
                self.explorer.wake("delta")      # new knowledge for the model

    async def _wait(self, tasks: set[asyncio.Task], timeout: float
                    ) -> set[asyncio.Task] | None:
        """Wait for a slot task to finish, ``timeout``, or a wake-up (a hint was posted
        in this process). Returns the finished tasks (possibly none on timeout), or
        ``None`` when only the wake-up fired."""
        waker = asyncio.ensure_future(self._wake.wait())
        try:
            done, _ = await asyncio.wait({*tasks, waker}, timeout=timeout,
                                         return_when=asyncio.FIRST_COMPLETED)
        finally:
            if not waker.done():
                waker.cancel()
        woke = waker in done
        if woke:
            self._wake.clear()
        done = done - {waker}
        if woke and not done:
            return None
        return done

    # ------------------------------------------------------- explorer agent
    def _build_model_client(self) -> ModelClient:
        """The one place the run's model client is built: the backend/model the run
        selected (snapshotted at start), resolved by ``modelsel``. Raises
        :class:`AgentUnavailable` with a clear message when it is unusable."""
        if self._model_client is not None:
            return self._model_client
        from src.greybox_web.modelsel import ModelSelectionError, resolve_model
        try:
            backend, model, creds = resolve_model(self.snap)
        except ModelSelectionError as exc:
            raise AgentUnavailable(str(exc) or NO_MODEL_MESSAGE) from None
        return build_client(creds.protocol, base_url=creds.base_url,
                            api_key=creds.api_key, model=model)

    async def _maybe_start_explorer(self) -> None:
        """Start the exploration agent: the only proposer. No model -> the run fails
        fast with a clear error (never a silent rule-based run). A proposer injected
        by a test that is not the LLM proposer runs without an explorer (test seam)."""
        if self.planner is None or self._lost or self._cancelled:
            return
        agent = self.planner.proposer
        if not isinstance(agent, LlmProposer):
            return
        try:
            client = self._build_model_client()
        except AgentUnavailable as exc:
            msg = str(exc) or NO_MODEL_MESSAGE
            log.warning("grey-box run %s: no model (%s)", self.run_id, msg)
            self._fail = ("error", msg)
            return
        from src.greybox_web import settings as gb_settings
        s = gb_settings.settings()
        self._llm = agent
        # one idle gate covers a model call with its transient-error retries
        self._idle_grace_s = grace_seconds(float(s.greybox_agent_timeout_s))
        self.explorer = Explorer(
            self.factory, self.run_id, agent, client,
            agent_budget=AgentBudget(max_calls=int(s.greybox_agent_max_calls),
                                     max_tokens=int(s.greybox_agent_max_tokens)),
            live=self._live_inputs, agent_id=self._agents.get("planner"),
            on_stored=self._wake.set, **self._explorer_options)
        self._bg.append(self.explorer.start())
        # the bootstrap cycle; a resumed run continues from its knowledge
        self.explorer.wake("resume" if self._resumed else "start")
        log.info("grey-box run %s: exploration agent started (model %s)",
                 self.run_id, getattr(client, "model", "?"))

    def _live_inputs(self) -> dict:
        """Live values for the knowledge snapshot: budget, frontier, coverage."""
        st = self.planner.state if self.planner is not None else None
        budget = {"requests_used": self.budget.used if self.budget else 0,
                  "requests_max": self.budget.max_requests if self.budget else 0,
                  "duration_s": int(self.budget.max_duration_s
                                    - self.budget.remaining_s())
                  if self.budget else 0}
        # Filter before capping (defect F3): the agent must see the pages and
        # interfaces, never 20 hashed build chunks in front of them.
        frontier = frontier_view(st.frontier) if st is not None else []
        coverage = {"pages_fetched": st.crawl_fetched if st is not None else 0,
                    "max_pages": st.max_pages if st is not None else 0}
        agent = {"calls_left": self.explorer.budget.calls_left
                 if self.explorer else 0,
                 "tokens_left": self.explorer.budget.tokens_left
                 if self.explorer else 0}
        # Accounts and sessions ("hardcore by default"): labels and usernames only —
        # never a secret, never a cookie value — the model learns WHO it can be,
        # not HOW the authentication works underneath.
        accounts = [{"label": label, "user": secret.get("user"),
                     **{key: secret.get(key) for key in
                        ("login_url", "user_field", "password_field", "method", "body")
                        if secret.get(key)}}
                    for label, secret in (self._account_secrets or {}).items()] \
            if self.snap.scope.allow_auth_testing else []
        sessions = [{"label": s["label"], "cookies": s.get("cookies")}
                    for s in self.client.sessions()] \
            if (self.client is not None and self.snap.scope.allow_auth_testing) else []
        # Run-defined dynamic instruments (batch E): id, title and param keys only —
        # the knowledge shows the model WHAT exists, and every use is a proposal
        # through the same admission (the spec itself stays with the executor).
        dynamic_tools = [{"id": s.id, "title": s.title or s.id,
                          "kind": s.kind, "param_keys": list(s.param_keys)}
                         for s in self.run_dynamic_tools.values()
                         if not s.id.startswith("verify.")][:20]
        return {"budget": budget, "frontier": frontier, "coverage": coverage,
                "agent": agent, "accounts": accounts, "sessions": sessions,
                "dynamic_tools": dynamic_tools}

    def _model_failed(self, why: str) -> None:
        """The model keeps failing: end the run with a clear error."""
        ex = self.explorer
        detail = f": {ex.last_error}" if ex is not None and ex.last_error else ""
        self._fail = ("error", f"The AI model failed repeatedly ({why}){detail}")

    def _reset_empty_rounds(self) -> None:
        self._empty_rounds = 0
        if self.explorer is not None:
            self.explorer.empty_rounds = 0

    def _frontier_left(self) -> bool:
        """True when the run ends with unfetched frontier URLs and page budget to
        fetch them — the assessment is not complete, whatever the model said.
        Uses the same static-asset filter as the knowledge frontier: URLs the model
        can see and schedule, not asset files it is never asked to crawl."""
        st = self.planner.state if self.planner is not None else None
        if st is None:
            return False
        crawlable = [u for u in st.frontier if is_work_url(u)]
        return bool(crawlable
                    and st.max_pages - st.crawl_fetched - st.crawl_reserved > 0)

    async def _explore_idle(self) -> bool:
        """The queue is empty: ask the model for more work. True keeps the run going
        (new work was admitted, or the model is simply asked again); False ends it.

        The run completes only after ``EMPTY_ROUNDS_TO_COMPLETE`` consecutive *fresh*
        idle cycles (triggered by this empty queue, see ``CycleResult.idle``) admitted
        no work — whatever the model's verdict ("adequate", refused or duplicate
        proposals, nothing new). A reply from a cycle that was already in flight is
        not such a round: the model is asked again. Otherwise only the model budget,
        repeated model failures, ``MAX_IDLE_GATES`` or the run's own budgets end it."""
        ex = self.explorer
        if ex is None or self._llm is None or self._cancelled:
            return False
        if not ex.budget.allows():
            self._explorer_note = "The AI model budget was exhausted."
            # the verdict must say the run stopped at its budget, not that it was
            # complete (or blocked)
            self._model_budget_spent = True
            await self._note("model budget exhausted: completing",
                             {"decision": "idle_budget"})
            return False
        if self._idle_gates >= MAX_IDLE_GATES:
            await self._note("explorer idle gate limit reached: completing",
                             {"decision": "idle_limit"})
            return False
        self._idle_gates += 1
        await self._note("Waiting for the AI planner to decide the next steps",
                         {"decision": "waiting_for_explorer",
                          "grace_s": int(self._idle_grace_s)})
        result = await ex.wait_cycle(self._idle_grace_s)
        if self._cancelled:
            return False
        if result is None:
            # no answer within the grace: the cycle may still be running. A slow
            # model is not a verdict; only repeated silence ends the run.
            self._idle_silences += 1
            if self._idle_silences >= MAX_MODEL_FAILURES:
                self._model_failed("no answer in time")
                return False
            await self._note("The AI planner is slow to answer; still waiting",
                             {"decision": "explorer_slow",
                              "attempt": self._idle_silences})
            return True
        self._idle_silences = 0
        if result.why == "failed":
            # A failed cycle never ends the run by itself: back off and retry, until
            # N consecutive cycles failed while nothing is in flight (we are at the
            # idle gate: the queue is empty and no slot is running).
            if ex.failures >= MAX_MODEL_FAILURES:
                self._model_failed("the last request failed")
                return False
            delay = ex.cycle_backoff()
            await self._note(
                f"The AI planner failed (attempt {ex.failures} of "
                f"{MAX_MODEL_FAILURES}): {ex.last_error[:120]}. Retrying in "
                f"{int(delay)}s",
                {"decision": "model_cycle_retry", "failures": ex.failures,
                 "retry_in_s": int(delay), "error": ex.last_error[:300]})
            await self._pause(delay)
            return True
        if self._llm.stored is not None:
            if await self._plan([], []):             # consume what it stored
                # an operator message arrived meanwhile: new direction, not a verdict
                await self._note("An operator message arrived; asking the AI planner "
                                 "again", {"decision": "explorer_operator_message"})
                return True
        if await self._open_work_orders() > 0:
            self._reset_empty_rounds()
            return True
        if result.why == "budget":
            return True                              # the budget check above ends it
        if not result.idle:
            # answered by a cycle that started before the queue emptied (or a
            # suppressed one): not a verdict on the empty queue, ask again
            await self._note("The AI planner's last answer predates the empty queue; "
                             "asking again",
                             {"decision": "explorer_ask_again", "why": result.why})
            return True
        self._empty_rounds += 1
        ex.empty_rounds = self._empty_rounds         # the next idle prompt says so
        human = {"adequate": "the AI planner judged coverage exhausted",
                 "ok": "all of the AI planner's proposals were refused or duplicates",
                 "quiet": "the AI planner had nothing new to add"}.get(
            result.why, f"the AI planner proposed no new work ({result.why})")
        data = {"why": result.why, "assessment": result.assessment,
                "empty_rounds": self._empty_rounds,
                "max_empty_rounds": EMPTY_ROUNDS_TO_COMPLETE}
        if self._empty_rounds < EMPTY_ROUNDS_TO_COMPLETE:
            await self._note(
                f"No new work ({human}); asking the AI planner again "
                f"(round {self._empty_rounds} of {EMPTY_ROUNDS_TO_COMPLETE})",
                {"decision": "explorer_no_work", **data})
            return True
        # Stop on value, not on silence alone: if the coverage verdict still names
        # actionable gaps, put them in front of the agent once before ending.
        if not self._coverage_challenged:
            from src.greybox_web import coverage as cov

            async def verdict_fn(session: AsyncSession):
                run = await session.get(GreyboxRun, self.run_id)
                return await self._coverage_verdict(session, run) if run else None
            verdict = await tx_read(self.factory, verdict_fn)
            if verdict is not None and verdict.outcome == cov.PARTIAL:
                self._coverage_challenged = True
                ex.coverage_challenge = list(verdict.reasons)
                self._reset_empty_rounds()
                await self._note(
                    "The AI planner has no more ideas, but coverage is partial: "
                    "asking it to address the gaps once more",
                    {"decision": "coverage_challenge", **data,
                     "reasons": list(verdict.reasons)[:5]})
                return True
        self._explorer_note = (
            f"The exploration agent proposed no new admissible work in "
            f"{EMPTY_ROUNDS_TO_COMPLETE} consecutive rounds at an empty queue "
            f"(last: {human}).")
        left = len([u for u in (self.planner.state.frontier if self.planner is not None else ())
                    if is_work_url(u)])
        await self._note(
            f"Completing: explorer exhausted after {EMPTY_ROUNDS_TO_COMPLETE} "
            f"empty rounds ({human})"
            + (f" — {left} frontier URL(s) were never fetched (end reason: "
               "stalled, not completed)" if self._frontier_left() else ""),
            {"decision": "explorer_exhausted", **data,
             **({"frontier_left": left} if self._frontier_left() else {})})
        return False

    async def _pause(self, seconds: float) -> None:
        """Sleep ``seconds`` but wake early on cancel, lost lease, failure or a hint."""
        end = time.monotonic() + max(0.0, seconds)
        while not (self._cancelled or self._lost or self._fail):
            left = end - time.monotonic()
            if left <= 0:
                return
            if await self._wait(set(), min(1.0, left)) is None:
                return

    async def _note(self, summary: str, data: dict) -> None:
        """A visible planner note (Live Activity) in its own small transaction."""
        async def fn(session: AsyncSession) -> None:
            full = {"reason": summary, "considered": 0, "work_order_ids": [], **data}
            await events.emit(session, self.run_id, "planner.decision", summary,
                              data=full, agent_id=self._agents.get("planner"))
        try:
            await tx_write(self.factory, fn)
        except Exception:                            # noqa: BLE001 — a note only
            log.exception("could not emit planner note (run %s)", self.run_id)

    # -------------------------------------------------------------- dispatch
    async def _dispatch(self) -> None:
        skipped = False
        for slot in SLOTS:
            if slot.name in self._slot_tasks:
                continue
            while True:                       # drain consecutive skips in one pass
                wo = await self._next_pending(slot)
                if wo is None:
                    break
                job = await self._claim(slot, wo)
                if job is None:
                    continue                   # skipped (unregistered) or raced
                if job == SKIP:
                    skipped = True
                    continue
                task = asyncio.create_task(
                    self._run_tool(slot.name, job),
                    name=f"gb-{slot.name}-{job.wo_id}")
                self._slot_tasks[slot.name] = task
                self._task_slot[id(task)] = slot.name
                self._slot_wo[slot.name] = job.wo_id
                break                          # slot is busy now
        if skipped:
            # A skip is a completion for planning purposes: phases and the
            # completion check must see it.
            await self._plan([], [])

    async def _next_pending(self, slot: Slot) -> dict | None:
        async def fn(session: AsyncSession) -> dict | None:
            base = select(
                GreyboxWorkOrder.id, GreyboxWorkOrder.tool, GreyboxWorkOrder.params,
                GreyboxWorkOrder.attempts, GreyboxWorkOrder.kind,
            ).where(
                GreyboxWorkOrder.run_id == self.run_id,
                GreyboxWorkOrder.status == "pending",
                GreyboxWorkOrder.kind.in_(tuple(slot.kinds)), *slot_filters(slot),
            )
            # A separate one-row query avoids loading a growing pending queue while
            # ensuring fresh high-priority proposals cannot starve admitted work.
            cutoff = utcnow() - timedelta(seconds=PENDING_STARVATION_S)
            wo = (await session.execute(
                base.where(GreyboxWorkOrder.created_at <= cutoff)
                .order_by(GreyboxWorkOrder.created_at).limit(1))).one_or_none()
            if wo is None:
                wo = (await session.execute(
                    base.order_by(GreyboxWorkOrder.priority,
                                  GreyboxWorkOrder.created_at).limit(1))).one_or_none()
            if wo is None:
                return None
            return {"id": wo.id, "tool": wo.tool, "params": dict(wo.params or {}),
                    "attempts": wo.attempts, "kind": wo.kind}

        return await tx_read(self.factory, fn)

    async def _claim(self, slot: Slot, wo: dict) -> WOJob | None | str:
        tool_call = f"tc-{uuid.uuid4().hex}"
        agent_id = self._agents[slot.name]

        async def fn(session: AsyncSession) -> WOJob | None:
            row = await session.get(GreyboxWorkOrder, wo["id"])
            if row is None or row.run_id != self.run_id or row.status != "pending":
                return None
            spec = tools.get(row.tool)
            if spec is None:
                # run-defined dynamic tool (batch E): resolved through the run's
                # registry, never the static one
                spec = self.run_dynamic_tools.get(row.tool)
            if spec is None:
                # Paused check: skip honestly, never pretend it ran.
                row.status = "skipped"
                row.result_summary = "Not implemented in this engine build"
                row.finished_at = utcnow()
                ev = await events.emit(
                    session, self.run_id, "work_order.skipped",
                    f"{row.tool} skipped: no implementation registered",
                    data={"reason": "disabled",
                          "note": "no implementation registered for this tool",
                          "tool": row.tool}, agent_id=agent_id,
                    work_order_id=row.id, refs={"node_ids": [row.node_id]
                                                if row.node_id else []})
                gtx = GraphTx(session, self.run_id, self.stats, agent_id=agent_id,
                              work_order_id=row.id)
                await gtx.set_status_by_id(row.node_id, "skipped")
                if row.node_id:
                    node = await session.get(GreyboxGraphNode, row.node_id)
                    if node is not None:
                        node.last_event_seq = ev.seq
                        node.outcome = "not_applicable"
                return SKIP
            row.status = "running"
            row.agent_id = agent_id
            row.attempts += 1
            row.started_at = utcnow()
            row.lease_owner = f"{self.worker_id}:{slot.name}"
            await session.execute(
                update(GreyboxAgent).where(GreyboxAgent.id == agent_id)
                .values(status="running", current_work_order_id=row.id,
                        current_summary=events.clip(row.title, 300))
                .execution_options(synchronize_session=False))
            ev = await events.emit(
                session, self.run_id, "work_order.claimed",
                f"{slot.name} claimed {row.tool}",
                data={"attempt": row.attempts}, agent_id=agent_id,
                work_order_id=row.id,
                refs={"node_ids": [row.node_id] if row.node_id else []})
            gtx = GraphTx(session, self.run_id, self.stats, agent_id=agent_id,
                          work_order_id=row.id)
            wo_node = await session.get(GreyboxGraphNode, row.node_id) \
                if row.node_id else None
            if wo_node is not None:
                wo_node.status = "running"
                wo_node.last_event_seq = ev.seq
                wo_node.version = await gtx.version()
            action = await gtx.node(
                "action", tool_call, f"{row.tool} call", "running",
                data={"tool": row.tool}, agent_id=agent_id, work_order_id=row.id,
                parent=wo_node)
            if wo_node is not None:
                await gtx.edge(wo_node, action, "executed")
            ev2 = await events.emit(
                session, self.run_id, "tool.started", f"{row.tool} started",
                data={"tool": row.tool,
                      "args": events.cap_data(dict(row.params or {}), 2048)},
                agent_id=agent_id, work_order_id=row.id, tool_call_id=tool_call,
                refs={"node_ids": [action.id]})
            action.event_seq = ev2.seq
            action.last_event_seq = ev2.seq
            return WOJob(wo_id=row.id, tool=row.tool, params=dict(row.params or {}),
                         tool_call_id=tool_call, agent_id=agent_id,
                         attempts=row.attempts)

        return await tx_write(self.factory, fn)

    async def _run_tool(self, slot: str, job: WOJob) -> WODone:
        assert self.client is not None and self.snap is not None
        spec = tools.get(job.tool) or self.run_dynamic_tools.get(job.tool)
        assert spec is not None
        started = time.monotonic()
        bound = self.client.bind(job.tool, agent_id=job.agent_id,
                                 work_order_id=job.wo_id,
                                 tool_call_id=job.tool_call_id)
        params = dict(job.params)
        if job.tool == "api.operation.invoke" and isinstance(params.get("operation_ref"), str) \
                and not isinstance(params.get("operation"), dict):
            async with self.factory() as session:
                operation_rows = (await session.scalars(select(GreyboxGraphNode).where(
                    GreyboxGraphNode.run_id == self.run_id,
                    GreyboxGraphNode.kind == "observation",
                    GreyboxGraphNode.key.startswith("api.operation|")))).all()
            from src.greybox_web.investigation import operation_from_mapping
            for operation_row in operation_rows:
                candidate = dict((operation_row.data or {}).get("facts") or {})
                durable = operation_from_mapping(candidate)
                if durable is not None and durable.id == params["operation_ref"]:
                    params["operation"] = candidate
                    break
        inventory = None
        if self.snap.scope.mode == modes.ARTIFACT:
            from src.greybox_web import artifact, settings as gb_settings
            inventory = artifact.Reader(artifact.target_root(
                gb_settings.settings().uploads_dir, self.snap.target_id))
        ctx = tools.ToolContext(
            http=bound, run_id=self.run_id,
            net=ToolNet(self.net, bound._prov) if self.net is not None else None,
            base_url=self.snap.base_url, scope=self.snap.scope,
            limits=self.snap.limits, params=params,
            recorded=netproject.RecordedView(self.factory, self.run_id),
            accounts=tuple(
                (label, s["user"], {k: s.get(k) for k in
                 ("login_url", "user_field", "password_field", "method")})
                for label, s in self._account_secrets.items()),
            account_credentials=(lambda label, _s=self._account_secrets:
                                 _s.get(label)), inventory=inventory)
        limit_s = tool_timeout_s(job.tool, self.snap.limits)
        try:
            result = await asyncio.wait_for(spec.run(ctx), timeout=limit_s)
            return WODone(job, "ok", result,
                          duration_ms=int((time.monotonic() - started) * 1000))
        except TimeoutError:
            log.warning("grey-box run %s: tool %s exceeded %.0fs; abandoned",
                        self.run_id, job.tool, limit_s)
            return WODone(job, "fail",
                          error=f"timeout: {job.tool} did not finish within "
                                f"{limit_s:.0f}s and was abandoned",
                          duration_ms=int((time.monotonic() - started) * 1000))
        except BudgetExhausted as exc:
            return WODone(job, "budget", budget=exc.budget,
                          duration_ms=int((time.monotonic() - started) * 1000))
        except (RunCancelled, asyncio.CancelledError):
            return WODone(job, "cancelled")
        except TransportFailure as exc:
            if exc.kind == "declared_redirect":
                # the target answered with a redirect to a host the operator declared
                # (an identity provider): not a transport fault and not this tool's
                # business -- the discovery tools record it, checks skip it.
                await self._note(
                    f"{job.tool}: the target redirects to a declared host; the work "
                    f"order is not applicable", {"decision": "declared_redirect",
                                                 "tool": job.tool})
                return WODone(job, "fail",
                              error="declared_redirect: the target redirects to a "
                                    "host the operator declared (not assessed)")
            return WODone(job, "retry" if job.attempts < 2 else "fail",
                          error=exc.kind)
        except ScopeViolation as exc:
            return WODone(job, "fail", error=f"blocked: {exc.reason}")
        except Exception as exc:                  # noqa: BLE001 — tool bug: fail the WO
            log.exception("grey-box run %s: tool %s crashed", self.run_id, job.tool)
            return WODone(job, "fail",
                          error=f"{type(exc).__name__}: {exc}"[:300],
                          duration_ms=int((time.monotonic() - started) * 1000))

    # ------------------------------------------------------------ completions
    async def _process_done(self, done: set[asyncio.Task]) -> None:
        new_assets: list[NewAsset] = []
        new_findings: list[NewFinding] = []
        terminal: list[Terminal] = []
        for task in done:
            slot = self._task_slot.pop(id(task), None)
            if slot is not None:
                self._slot_tasks.pop(slot, None)
                self._slot_wo.pop(slot, None)
            try:
                result: WODone = task.result()
            except Exception as exc:              # noqa: BLE001 — task crashed
                result = WODone(WOJob(uuid.uuid4(), "?", {}, "?", uuid.uuid4(), 2),
                                "fail", error=f"slot task crashed: {exc}")
            if result.outcome == "budget":
                self._budget_stop = result.budget
                await self._complete_wo(result, skipped_budget=True)
                terminal.append(Terminal(result.job.wo_id, result.job.tool, "skipped",
                                         result.job.params))
            elif result.outcome == "ok":
                await self._complete_wo(result)
                res = result.result
                terminal.append(Terminal(
                    result.job.wo_id, result.job.tool, "done", result.job.params,
                    fetched=int((getattr(res, "counts", None) or {}).get("fetched", 0)),
                    frontier=tuple(getattr(res, "frontier", None) or ()),
                    urls=_acted_on(result.job.params, res)))
                if isinstance(result.result, tools.ToolResult):
                    a, f = await _project(self.factory, self.run_id, result,
                                          self.stats)
                    new_assets.extend(a)
                    new_findings.extend(f)
                elif isinstance(result.result, tools.VerifyResult):
                    await _apply_verification(self.factory, self.run_id, result,
                                              self.stats)
            elif result.outcome == "retry":
                await self._complete_wo(result)
            elif result.outcome == "fail":
                await self._complete_wo(result)
                terminal.append(Terminal(result.job.wo_id, result.job.tool, "failed",
                                         result.job.params))
            # "cancelled": the finalize txn marks open work orders cancelled
        await self._plan(new_assets, new_findings, terminal)

    async def _complete_wo(self, r: WODone, *, skipped_budget: bool = False) -> None:
        job = r.job

        async def fn(session: AsyncSession) -> None:
            wo = await session.get(GreyboxWorkOrder, job.wo_id)
            if wo is None or wo.run_id != self.run_id:
                return
            wo.finished_at = utcnow()
            await session.execute(
                update(GreyboxAgent).where(GreyboxAgent.id == job.agent_id)
                .values(status="idle", current_work_order_id=None,
                        current_summary=None,
                        work_orders_done=GreyboxAgent.work_orders_done
                        + (1 if r.outcome in ("ok", "retry", "fail") else 0),
                        work_orders_failed=GreyboxAgent.work_orders_failed
                        + (1 if r.outcome == "fail" else 0))
                .execution_options(synchronize_session=False))
            gtx = GraphTx(session, self.run_id, self.stats, agent_id=job.agent_id,
                          work_order_id=wo.id)
            node = await session.get(GreyboxGraphNode, wo.node_id) \
                if wo.node_id else None
            action = await gtx.get_node("action", job.tool_call_id)
            if skipped_budget:
                wo.status = "skipped"
                wo.result_summary = "budget exhausted"
                ev = await events.emit(
                    session, self.run_id, "work_order.skipped",
                    f"{wo.tool} skipped: budget exhausted",
                    data={"reason": "budget"}, agent_id=job.agent_id,
                    work_order_id=wo.id)
                if node is not None:
                    node.status = "skipped"
                    node.last_event_seq = ev.seq
                    node.outcome = "not_applicable"
                    node.version = await gtx.version()
                if action is not None:
                    action.status = "cancelled"
                    action.version = await gtx.version()
                return
            if r.outcome == "ok":
                wo.status = "done"
                vrefs: dict[str, Any] = {}
                if isinstance(r.result, tools.VerifyResult):
                    # a verification states its outcome, linked to its finding
                    vr = r.result
                    summary = (f"{'confirmed' if vr.confirmed else 'not reproduced'}: "
                               f"{vr.note}")
                    counts = {"confirmed": bool(vr.confirmed), "method": vr.method,
                              "exchanges": len(vr.exchange_ids)}
                    fid = (wo.params or {}).get("finding_id")
                    if fid:
                        vrefs = {"finding_id": str(fid)}
                    if vr.exchange_ids:
                        vrefs["exchange_ids"] = list(vr.exchange_ids)
                else:
                    summary = getattr(r.result, "summary", "")
                    counts = getattr(r.result, "counts", None)
                wo.result_summary = events.clip(summary, 500)
                ev = await events.emit(
                    session, self.run_id, "work_order.completed",
                    f"{wo.tool} done: {wo.result_summary}",
                    data={"result_summary": wo.result_summary, **(
                        {"result": counts} if isinstance(
                            r.result, tools.VerifyResult) else {})},
                    refs=vrefs or None,
                    agent_id=job.agent_id, work_order_id=wo.id, duration_ms=r.duration_ms)
                ev2 = await events.emit(
                    session, self.run_id, "tool.succeeded",
                    f"{wo.tool} succeeded",
                    data={"tool": wo.tool, "result": counts or {}},
                    agent_id=job.agent_id, work_order_id=wo.id,
                    tool_call_id=job.tool_call_id, duration_ms=r.duration_ms)
                if node is not None:
                    node.status = "done"
                    node.last_event_seq = ev.seq
                    produced = 0
                    if isinstance(r.result, tools.ToolResult):
                        produced = len(r.result.findings)
                    elif isinstance(r.result, tools.VerifyResult):
                        produced = 1 if r.result.confirmed else 0
                    node.outcome = "reported" if produced else "no_issue_found"
                    node.version = await gtx.version()
                if action is not None:
                    action.status = "succeeded"
                    action.last_event_seq = ev2.seq
                    action.version = await gtx.version()
                # tested: check WOs mark their asset (and its parent) tested
                if wo.kind == "check" and wo.asset_id is not None:
                    asset = await session.get(GreyboxAsset, wo.asset_id)
                    if asset is not None:
                        await gtx.mark_tested(asset.id)
                        if asset.parent_id is not None:
                            await gtx.mark_tested(asset.parent_id)
                return
            if r.outcome == "retry":
                wo.status = "pending"
                wo.agent_id = None
                wo.lease_owner = None
                await events.emit(
                    session, self.run_id, "work_order.failed",
                    f"{wo.tool} failed ({r.error}), will retry",
                    level="error", status="error",
                    data={"error": r.error, "attempt": job.attempts,
                          "will_retry": True},
                    agent_id=job.agent_id, work_order_id=wo.id)
                if node is not None:
                    node.status = "pending"
                    node.version = await gtx.version()
                if action is not None:
                    action.status = "failed"
                    action.version = await gtx.version()
                return
            # terminal failure
            wo.status = "failed"
            wo.error = events.clip(r.error, 1000)
            ev = await events.emit(
                session, self.run_id, "work_order.failed",
                f"{wo.tool} failed: {r.error}", level="error", status="error",
                data={"error": r.error, "attempt": job.attempts,
                      "will_retry": False},
                agent_id=job.agent_id, work_order_id=wo.id)
            await events.emit(
                session, self.run_id, "tool.failed", f"{wo.tool} failed: {r.error}",
                level="error", status="error",
                data={"tool": wo.tool, "error": r.error},
                agent_id=job.agent_id, work_order_id=wo.id,
                tool_call_id=job.tool_call_id, duration_ms=r.duration_ms)
            if node is not None:
                node.status = "failed"
                node.last_event_seq = ev.seq
                node.outcome = "needs_follow_up"
                node.version = await gtx.version()
            if action is not None:
                action.status = "failed"
                action.version = await gtx.version()
            if wo.tool == "discovery.fetch_root" and \
                    self.snap.scope.mode == modes.WEB:
                # Nothing ever answered: fail the run fast (preflight). Web targets
                # only: a network/artifact target's anchor URL is not its surface,
                # and its evidence (TCP answers) carries no HTTP status.
                ok = (await session.scalar(
                    select(GreyboxHttpExchange.id).where(
                        GreyboxHttpExchange.run_id == self.run_id,
                        GreyboxHttpExchange.status_code.isnot(None)).limit(1)))
                if ok is None:
                    self._fail = ("preflight", _unreachable_message(
                        self.snap.base_url, r.error,
                        (self.snap.egress_proxy or {}).get("name")))

        await tx_write(self.factory, fn)

    # ------------------------------------------------------------------ plan
    async def _plan(self, new_assets: list[NewAsset], new_findings: list[NewFinding],
                    terminal: list[Terminal] = ()) -> int:
        """One planning step in one write transaction: platform hints first (standing
        directives, skips, seeds), then the proposer sees the delta (assets, findings,
        finished work orders, recent events) and everything it proposes is admitted.
        Returns the number of operator messages (hints) handled: each is new
        direction, so the empty-round count starts over and the model is woken."""
        assert self.planner is not None
        pl = self.planner
        cursor = self._event_cursor
        handled = 0

        async def fn(session: AsyncSession) -> int:
            gtx = GraphTx(session, self.run_id, self.stats,
                          agent_id=self._agents["planner"])
            await pl.begin_cycle(session)
            nonlocal handled
            hints = await pl.process_hints(session, gtx)
            handled = len(hints)
            rows = (await session.scalars(
                select(GreyboxEvent).where(
                    GreyboxEvent.run_id == self.run_id, GreyboxEvent.seq > cursor,
                    GreyboxEvent.kind.in_(PLANNER_EVENT_KINDS))
                .order_by(GreyboxEvent.seq).limit(PLANNER_EVENTS_PER_CYCLE))).all()
            await pl.cycle(
                session, gtx, assets=new_assets, findings=new_findings,
                terminal=tuple(terminal), hints=hints,
                events_=tuple(EventView(e.seq, e.kind, e.summary, dict(e.data or {}))
                              for e in rows))
            await pl.finalize_leads(session, gtx)
            await self._phase_step(session, gtx)
            return rows[-1].seq if rows else cursor

        self._event_cursor = await tx_write(self.factory, fn)
        if handled:
            self._reset_empty_rounds()
            if self.explorer is not None:
                self.explorer.wake("hint")    # the model must read and answer them
        return handled

    async def _phase_step(self, session: AsyncSession, gtx: GraphTx) -> None:
        run = await session.get(GreyboxRun, self.run_id)
        if run is None:
            return
        kinds = (await session.scalars(
            select(GreyboxWorkOrder.kind).where(
                GreyboxWorkOrder.run_id == self.run_id,
                GreyboxWorkOrder.status.in_(("pending", "running"))))).unique().all()
        if "discovery" in kinds:
            phase = "discovery"
        elif "check" in kinds:
            phase = "checks"
        elif "verify" in kinds:
            phase = "verification"
        elif self.explorer is not None and not self._reporting:
            phase = "planning"            # nothing queued: the AI planner decides next
        else:
            phase = "reporting"
        await self._set_phase(session, gtx, run, phase)

    async def _set_phase(self, session: AsyncSession, gtx: GraphTx,
                         run: GreyboxRun, phase: str) -> None:
        """The run's current activity (no fixed sequence: the model decides)."""
        if run.phase != phase:
            old = run.phase
            run.phase = phase
            ev = await events.emit(session, self.run_id, "run.phase",
                                   f"phase {old or '—'} → {phase}",
                                   data={"from": old, "to": phase})
            obj = await gtx.get_node("objective", "objective")
            if obj is not None:
                obj.last_event_seq = ev.seq

    async def _open_hints(self) -> int:
        async def fn(session: AsyncSession) -> int:
            return int(await session.scalar(
                select(func.count()).select_from(GreyboxHint).where(
                    GreyboxHint.run_id == self.run_id,
                    GreyboxHint.status == "open")) or 0)
        return await tx_read(self.factory, fn)

    async def _open_work_orders(self) -> int:
        async def fn(session: AsyncSession) -> int:
            return int(await session.scalar(
                select(func.count()).select_from(GreyboxWorkOrder).where(
                    GreyboxWorkOrder.run_id == self.run_id,
                    GreyboxWorkOrder.status.in_(("pending", "running")))) or 0)
        return await tx_read(self.factory, fn)

    async def _budget_skip_all(self) -> None:
        assert self.budget is not None and self.planner is not None
        budget = self._budget_stop or "requests"

        async def fn(session: AsyncSession) -> None:
            gtx = GraphTx(session, self.run_id, self.stats,
                          agent_id=self._agents["planner"])
            open_ids = (await session.scalars(
                select(GreyboxWorkOrder.id).where(
                    GreyboxWorkOrder.run_id == self.run_id,
                    GreyboxWorkOrder.status.in_(("pending", "running"))))).all()
            for wid in open_ids:
                wo = await session.get(GreyboxWorkOrder, wid)
                if wo is None:
                    continue
                wo.status = "skipped"
                wo.result_summary = "budget exhausted"
                wo.finished_at = utcnow()
                await events.emit(
                    session, self.run_id, "work_order.skipped",
                    f"{wo.tool} skipped: budget exhausted",
                    data={"reason": "budget"}, agent_id=self._agents["planner"],
                    work_order_id=wo.id)
                await _settle_nodes(session, gtx, wo, "skipped", "not_applicable")
            limit = (self.budget.max_requests if budget == "requests"
                     else int(self.budget.max_duration_s))
            used = (self.budget.used if budget == "requests"
                    else int(self.budget.max_duration_s - self.budget.remaining_s()))
            await self.planner.budget_stop(session, gtx, budget, limit, used,
                                           len(open_ids))

        await tx_write(self.factory, fn)

    # ---------------------------------------------------------------- report
    async def _report(self, end_reason: str) -> None:
        from src.greybox_web import report as report_mod

        self._reporting = True

        async def started(session: AsyncSession) -> None:
            run = await session.get(GreyboxRun, self.run_id)
            if run is not None:
                await self._set_phase(
                    session, GraphTx(session, self.run_id, self.stats,
                                     agent_id=self._agents.get("reporter")),
                    run, "reporting")
            await events.emit(session, self.run_id, "report.started",
                              "report generation started",
                              agent_id=self._agents.get("reporter"))
        await tx_write(self.factory, started)
        await self._final_surface()
        await self._propose_defenses()
        try:
            # The verdict must exist BEFORE the report is written: the report's
            # outcome, summary and blind spots come from it (otherwise a blocked
            # or partial run reads as if coverage were complete).
            async def verdict(session: AsyncSession) -> None:
                run = await session.get(GreyboxRun, self.run_id)
                if run is not None:
                    run.coverage_verdict = (
                        await self._coverage_verdict(session, run)).as_dict()
            await tx_write(self.factory, verdict)

            async def build(session: AsyncSession) -> str:
                return await report_mod.generate(session, self.run_id,
                                                 finished_at=utcnow(),
                                                 end_reason=end_reason)
            markdown = await tx_read(self.factory, build)
            if self._explorer_note:
                markdown += f"\n\n> {self._explorer_note}\n"

            async def ready(session: AsyncSession) -> None:
                row = await session.get(GreyboxReport, self.run_id)
                if row is None:
                    session.add(GreyboxReport(run_id=self.run_id, status="ready",
                                              markdown=markdown,
                                              generated_at=utcnow()))
                else:
                    row.status = "ready"
                    row.markdown = markdown
                    row.generated_at = utcnow()
                    row.error = None
                await session.execute(
                    update(GreyboxAgent).where(
                        GreyboxAgent.id == self._agents["reporter"])
                    .values(status="finished", finished_at=utcnow())
                    .execution_options(synchronize_session=False))
                await events.emit(
                    session, self.run_id, "report.ready",
                    f"report ready ({len(markdown)} bytes)",
                    data={"bytes": len(markdown)},
                    agent_id=self._agents["reporter"])
            await tx_write(self.factory, ready)
        except Exception as exc:                  # noqa: BLE001 — report failure
            async def failed(session: AsyncSession) -> None:
                row = await session.get(GreyboxReport, self.run_id)
                err = events.clip(f"{type(exc).__name__}: {exc}", 500)
                if row is None:
                    session.add(GreyboxReport(run_id=self.run_id, status="failed",
                                              error=err))
                else:
                    row.status = "failed"
                    row.error = err
                await events.emit(session, self.run_id, "report.failed",
                                  f"report failed: {err}", level="error",
                                  status="error", data={"error": err},
                                  agent_id=self._agents["reporter"])
            try:
                await tx_write(self.factory, failed)
            except Exception:                      # noqa: BLE001
                pass

    async def _final_surface(self) -> None:
        """Last recomputation of every service surface (verification may have changed
        the finding counts) and the coalesced ``surface.updated`` still pending.
        Best effort."""
        from src.greybox_web import surface as surface_mod

        async def refresh(session: AsyncSession) -> None:
            reporter = self._agents.get("reporter")
            await surface_mod.refresh(
                session, GraphTx(session, self.run_id, self.stats, agent_id=reporter))

        async def flush(session: AsyncSession) -> None:
            reporter = self._agents.get("reporter")
            await surface_mod.flush(
                session, GraphTx(session, self.run_id, self.stats, agent_id=reporter))
        try:
            await tx_write(self.factory, refresh)
            await asyncio.sleep(surface_mod.pending_delay(self.stats))
            await tx_write(self.factory, flush)
        except Exception:                          # noqa: BLE001
            pass

    async def _propose_defenses(self) -> None:
        """Defensive recommendations for the findings, before the report
        so it can include them. Best effort: a failure never blocks the report."""
        from src.greybox_web import defenses as defenses_mod

        async def fn(session: AsyncSession) -> None:
            reporter = self._agents.get("reporter")
            gtx = GraphTx(session, self.run_id, self.stats, agent_id=reporter)
            await defenses_mod.generate(session, self.run_id, gtx, agent_id=reporter)
            await defenses_mod.generate_network(session, self.run_id, gtx,
                                                agent_id=reporter)
        try:
            await tx_write(self.factory, fn)
        except Exception as exc:                  # noqa: BLE001
            async def warn(session: AsyncSession) -> None:
                await events.emit(session, self.run_id, "log.warning",
                                  f"defense generation failed: {type(exc).__name__}",
                                  data={"message": events.clip(str(exc), 300)})
            try:
                await tx_write(self.factory, warn)
            except Exception:                      # noqa: BLE001
                pass

    # -------------------------------------------------------------- finalize
    async def _finalize(self, outcome: tuple) -> None:
        kind = outcome[0]
        if kind == "lost" or self._lost:
            return                                  # reaper owns the run

        async def fn(session: AsyncSession) -> None:
            run = await session.get(GreyboxRun, self.run_id)
            if run is None or run.status in GB_TERMINAL:
                return
            gtx = GraphTx(session, self.run_id, self.stats,
                          agent_id=self._agents.get("planner"))
            # hints still open are rejected before the terminal event
            if self.planner is not None:
                await self.planner.reject_open_hints(session, gtx)
            # operator messages nobody answered get the platform's reply (the agent
            # can no longer read them), before the terminal event
            await opmsg.platform_reply(session, self.run_id,
                                       agent_id=self._agents.get("planner"))
            # flush any pending graph changes first (graph.updated precedes the
            # terminal event)
            if self.stats.any():
                version = int(await session.scalar(
                    select(GreyboxRun.graph_version).where(
                        GreyboxRun.id == self.run_id)) or 0)
                await events.emit(session, self.run_id, "graph.updated",
                                  "graph updated", data={"version": version,
                                                         **self.stats.take()})
            # agents finish before the terminal event
            agent_ids = list(self._agents.values())
            for aid in agent_ids:
                await session.execute(
                    update(GreyboxAgent).where(GreyboxAgent.id == aid)
                    .values(status="finished", current_work_order_id=None,
                            finished_at=utcnow())
                    .execution_options(synchronize_session=False))
            agent_failed_emitted = False
            for name, aid in self._agents.items():
                agent = await session.get(GreyboxAgent, aid)
                if agent is None:
                    continue
                if kind == "failed":
                    await session.execute(
                        update(GreyboxAgent).where(GreyboxAgent.id == aid)
                        .values(status="failed")
                        .execution_options(synchronize_session=False))
                    if not agent_failed_emitted:      # one event, not one per agent
                        agent_failed_emitted = True
                        await events.emit(
                            session, self.run_id, "agent.failed",
                            "agents stopped: the run failed",
                            level="error", status="error",
                            data={"error": outcome[2] or "run failed",
                                  "agents": sorted(self._agents)},
                            agent_id=self._agents.get("planner") or aid)
                else:
                    await events.emit(
                        session, self.run_id, "agent.finished",
                        f"agent {name} finished "
                        f"({agent.work_orders_done} done, "
                        f"{agent.work_orders_failed} failed)",
                        data={"work_orders_done": agent.work_orders_done,
                              "work_orders_failed": agent.work_orders_failed},
                        agent_id=aid)
            # settle open work orders
            open_ids = (await session.scalars(
                select(GreyboxWorkOrder.id).where(
                    GreyboxWorkOrder.run_id == self.run_id,
                    GreyboxWorkOrder.status.in_(("pending", "running"))))).all()
            for wid in open_ids:
                wo = await session.get(GreyboxWorkOrder, wid)
                if wo is None:
                    continue
                wo.status = "cancelled"
                wo.finished_at = utcnow()
                await _settle_nodes(session, gtx, wo, "cancelled", "not_applicable")
            duration_ms = int((time.monotonic() - self.budget.started) * 1000) \
                if self.budget else None
            findings = {"verified": 0, "candidate": 0, "rejected": 0}
            for status_, n in (await session.execute(
                    select(GreyboxFinding.status, func.count())
                    .where(GreyboxFinding.run_id == self.run_id)
                    .group_by(GreyboxFinding.status))).all():
                findings[status_] = int(n)
            run.finished_at = utcnow()
            run.lease_owner = None
            run.lease_expires_at = None
            obj = await gtx.get_node("objective", "objective")
            if kind == "cancelled":
                run.status = GB_CANCELLED
                run.end_reason = "cancelled"
                await events.emit(
                    session, self.run_id, "run.cancelled",
                    f"run cancelled ({outcome[1]})",
                    status="cancelled",
                    data={"reason": outcome[1] or "user",
                          "open_work_orders_cancelled": len(open_ids)})
            elif kind == "failed":
                run.status = GB_FAILED
                run.end_reason = "error"
                run.error_summary = events.clip(outcome[2], 2000)
                await events.emit(
                    session, self.run_id, "run.failed",
                    f"run failed: {outcome[1]}",
                    level="error", status="error",
                    data={"reason": outcome[1], "error": outcome[2] or ""})
            else:
                run.status = GB_SUCCEEDED
                run.end_reason = outcome[1] or "completed"
                # The completion verdict: a run that met an
                # authentication boundary -- an identity provider, an expired
                # session, a login screen -- has not assessed the application, so
                # it never ends as "completed" (field-assessment defect F5).
                verdict = await self._coverage_verdict(session, run)
                await events.emit(
                    session, self.run_id, "coverage.verdict",
                    f"coverage: {verdict.outcome} "
                    f"({(verdict.reasons or ('',))[0]})",
                    data={"outcome": verdict.outcome,
                          "reasons": list(verdict.reasons),
                          "limitations": list(verdict.limitations)},
                    level="warning" if verdict.outcome in ("blocked",
                                                          "needs_authorisation",
                                                          "partial")
                    else "info")
                if verdict.outcome in ("blocked", "needs_authorisation",
                                       "budget_exhausted"):
                    if run.end_reason in ("completed", "stalled"):
                        run.end_reason = verdict.outcome
                run.coverage_verdict = verdict.as_dict()
                await events.emit(
                    session, self.run_id, "run.completed",
                    f"run completed ({run.end_reason})",
                    data={"end_reason": run.end_reason,
                          "duration_ms": duration_ms,
                          "requests_made": run.requests_made,
                          "findings": findings,
                          "coverage": verdict.outcome})
            if obj is not None:
                obj.status = "done"
                verified_total = findings["verified"] + findings["candidate"]
                obj.outcome = "reported" if verified_total else "no_issue_found"

        try:
            await tx_write(self.factory, fn)
        except Exception:                            # noqa: BLE001 — reaper fallback
            log.exception("grey-box run %s: could not finalize (reaper fallback)",
                          self.run_id)

    async def _coverage_verdict(self, session: AsyncSession, run: GreyboxRun
                                ) -> "coverage.CoverageVerdict":
        """The honest verdict for this run, from cheap counts:
        what was discovered, what was examined, what the authentication boundary
        allowed, and whether a budget -- not completeness -- stopped the run."""
        from src.greybox_web import coverage, authboundary
        endpoints = (await session.scalars(
            select(GreyboxAsset).where(GreyboxAsset.run_id == self.run_id,
                                       GreyboxAsset.kind == "endpoint",
                                       GreyboxAsset.in_scope.is_(True)))).all()
        from src.greybox_web.tools.routes import examined_surface
        surf = examined_surface(endpoints)
        states = [coverage.AuthState(s) for s in (run.auth_states or [])]
        st = self.planner.state if self.planner is not None else None
        pending = int(await session.scalar(
            select(func.count()).select_from(GreyboxWorkOrder).where(
                GreyboxWorkOrder.run_id == self.run_id,
                GreyboxWorkOrder.status.in_(("pending", "running")))) or 0)
        unverified = int(await session.scalar(
            select(func.count()).select_from(GreyboxFinding).where(
                GreyboxFinding.run_id == self.run_id,
                GreyboxFinding.status == "candidate")) or 0)
        from src.greybox_web import skillbook
        sk_scope = self.snap.scope if self.snap is not None else \
            ScopePolicy.from_dict(run.scope)
        sk_state = await skillbook.run_state(
            session, self.run_id, sk_scope,
            identities=1 + (len(self.client.sessions()) if self.client else 0))
        sk_items = tuple(skillbook.coverage_items(sk_state))
        sk_unloaded = len([x for x in skillbook.available(
            sk_scope.mode, modes.for_scope(sk_scope).allowed)
            if x.name not in {s["name"] for s in sk_state}])
        open_leads = int(await session.scalar(
            select(func.count()).select_from(GreyboxGraphNode).where(
                GreyboxGraphNode.run_id == self.run_id,
                GreyboxGraphNode.kind == "lead",
                GreyboxGraphNode.status.in_(("open", "investigating")))) or 0)
        scope = self.snap.scope if self.snap is not None else None
        if scope is not None and scope.mode != modes.WEB:
            # a non-web target is measured by what it consists of: hosts and
            # services (tcp://...), never URLs
            services = (await session.scalars(
                select(GreyboxAsset).where(GreyboxAsset.run_id == self.run_id,
                                           GreyboxAsset.kind == "service",
                                           GreyboxAsset.in_scope.is_(True)))).all()
            net_svc = [a for a in services if a.key.startswith("tcp://")]
            swept = int(await session.scalar(
                select(func.count()).select_from(GreyboxWorkOrder).where(
                    GreyboxWorkOrder.run_id == self.run_id,
                    GreyboxWorkOrder.tool.in_(("net.sweep", "net.probe")),
                    GreyboxWorkOrder.status == "done")) or 0)
            extra = [] if swept or scope.mode == modes.ARTIFACT else [
                "The authorised address set was never swept: no service was "
                "examined."]
            return coverage.assess(coverage.CoverageInput(
                mode=scope.mode, endpoints=len(net_svc),
                endpoints_tested=sum(1 for a in net_svc if a.tested),
                gaps=pending, unverified_findings=unverified,
                open_hypotheses=open_leads, budget_stop=self._budget_stop or ("model" if self._model_budget_spent else None),
                extra_reasons=tuple(extra), skills=sk_items,
                skills_available_not_loaded=sk_unloaded))
        accounts_unused = 0 if sk_scope.allow_auth_testing else \
            len(run.account_ids or [])
        from src.greybox_web import secmodel_store
        mview = await secmodel_store.view(session, self.run_id)
        opened = await secmodel_store.open_signals(session, self.run_id, mview)
        return coverage.assess(coverage.CoverageInput(
            model_open_signals=tuple(s["summary"][:200] for s in opened),
            model_unresolved=tuple(u["detail"] if u["kind"] != "no_expectation" else
                                   f"intended access to {u['resource_type']} not "
                                   "established" for u in mview["unresolved"]),
            accounts_unused=accounts_unused,
            skills=sk_items, skills_available_not_loaded=sk_unloaded,
            open_hypotheses=open_leads,
            endpoints=surf["endpoints"],
            endpoints_tested=surf["tested"],
            api_endpoints=surf["api"],
            api_untested=len(surf["api_untested"]),
            frontier=len([u for u in (st.frontier if st else ()) if is_work_url(u)]),
            page_budget_left=max(0, (st.max_pages - st.crawl_fetched - st.crawl_reserved)
                                 if st is not None else 0),
            gaps=pending,
            unverified_findings=unverified,
            identities=len(self.client.sessions()) if self.client else 0,
            auth=authboundary.summarise(states),
            budget_stop=self._budget_stop or ("model" if self._model_budget_spent else None),
            stopped_by=None))

    async def _maybe_flush_graph(self) -> None:
        if not self.stats.any():
            return
        if time.monotonic() - self._last_graph_flush < GRAPH_FLUSH_S:
            return

        async def fn(session: AsyncSession) -> None:
            version = int(await session.scalar(
                select(GreyboxRun.graph_version).where(
                    GreyboxRun.id == self.run_id)) or 0)
            await events.emit(session, self.run_id, "graph.updated", "graph updated",
                              data={"version": version, **self.stats.take()})
        try:
            await tx_write(self.factory, fn)
        except Exception:                             # noqa: BLE001
            pass
        self._last_graph_flush = time.monotonic()


class EgressProxyUnavailable(Exception):
    """The run's egress proxy is gone, disabled or no longer allows the scope."""


class CredentialUnavailable(Exception):
    """The run's credential is missing, foreign, wrong-kind or undecryptable."""


class _Lost(Exception):
    pass


async def _settle_nodes(session: AsyncSession, gtx: GraphTx,
                        wo: GreyboxWorkOrder, status: str, outcome: str) -> None:
    """Settle a work order's node and any action node still running for it."""
    if wo.node_id is not None:
        node = await session.get(GreyboxGraphNode, wo.node_id)
        if node is not None:
            node.status = status
            node.outcome = outcome
            node.version = await gtx.version()
    actions = (await session.scalars(
        select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == wo.run_id, GreyboxGraphNode.kind == "action",
            GreyboxGraphNode.work_order_id == wo.id,
            GreyboxGraphNode.status == "running"))).all()
    for action in actions:
        action.status = "cancelled"
        action.version = await gtx.version()


async def settle_open_graph(session: AsyncSession, gtx: GraphTx, run_id: uuid.UUID,
                            outcome: str = "needs_follow_up") -> None:
    """After a run stopped without finishing (lease reaper): no node stays live. Leads
    still open become inconclusive, running action nodes are cancelled and the objective
    is done with ``outcome``."""
    for node in (await session.scalars(
            select(GreyboxGraphNode).where(
                GreyboxGraphNode.run_id == run_id,
                ((GreyboxGraphNode.kind == "lead")
                 & GreyboxGraphNode.status.in_(("open", "investigating")))
                | ((GreyboxGraphNode.kind == "action")
                   & (GreyboxGraphNode.status == "running"))
                | ((GreyboxGraphNode.kind == "objective")
                   & (GreyboxGraphNode.status == "active"))
                | ((GreyboxGraphNode.kind == "reasoning")
                   & (GreyboxGraphNode.status == "active")))
            .order_by(GreyboxGraphNode.created_version, GreyboxGraphNode.key))).all():
        if node.kind == "lead":
            await gtx.set_status(node, "inconclusive", outcome=outcome)
        elif node.kind == "action":
            await gtx.set_status(node, "cancelled")
        elif node.kind == "reasoning":
            await gtx.set_status(node, "superseded")
        else:
            await gtx.set_status(node, "done", outcome=outcome)


# ------------------------------------------------------------- projection


async def _fold_occurrence(session: AsyncSession, finding_id: Any,
                           spec: Any, r: WODone) -> None:
    """Record that an identity-scoped finding was seen at another location.

    The finding stays one issue with one proof; the extra URLs are kept as
    ``location.also_at`` so the report can say where else it holds. Written as a fresh
    JSON object (not mutated in place) so SQLAlchemy sees the change.
    """
    f = await session.get(GreyboxFinding, finding_id)
    if f is None:
        return
    loc = dict(f.location or {})
    also = list(loc.get("also_at") or [])
    here = redaction.url(spec.occurrence or spec.url)
    if here and here != loc.get("url") and here not in also:
        also.append(here)
        loc["also_at"] = also[:50]
        f.location = loc
        f.version = (f.version or 0) + 1


async def _project(factory, run_id: uuid.UUID, r: WODone, stats: GraphStats
                   ) -> tuple[list[NewAsset], list[NewFinding]]:
    """A successful tool result becomes assets, observations and findings."""
    result: tools.ToolResult = r.result
    scope: ScopePolicy | None = None

    async def fn(session: AsyncSession) -> tuple[list, list]:
        nonlocal scope
        run = await session.get(GreyboxRun, run_id)
        if run is None:
            return [], []
        scope = ScopePolicy.from_dict(run.scope)
        wo = await session.get(GreyboxWorkOrder, r.job.wo_id)
        gtx = GraphTx(session, run_id, stats, agent_id=r.job.agent_id,
                      work_order_id=r.job.wo_id)
        action = await gtx.get_node("action", r.job.tool_call_id)
        new_assets: list[NewAsset] = []
        new_findings: list[NewFinding] = []
        for page in result.pages:
            endpoint = await gtx.url_assets(page.url, scope, data=page.data)
            if endpoint is None:
                continue
            for p in (page.params or url_query_params(page.url)):
                await gtx.param_asset(endpoint, p.location, p.name, data=p.data)
            for link in page.links:
                linked = await gtx.url_assets(link, scope)
                if linked is None or linked.id == endpoint.id:
                    continue
                for p in url_query_params(link):
                    await gtx.param_asset(linked, p.location, p.name, data=p.data)
                await gtx.asset_edge(endpoint, linked, "links_to")
            if page.redirect_to:
                target = await gtx.url_assets(page.redirect_to, scope)
                if target is not None and target.id != endpoint.id:
                    await gtx.asset_edge(endpoint, target, "redirects_to")
                    await netproject.rollup_redirect(gtx, endpoint, target)
        # Redirect provenance and authentication state (defects F2/F5). A response
        # fetched through redirects is recorded against the URL that answered, and a
        # chain that left the target for an identity provider is recorded as the
        # reason -- so the report can never claim the application was assessed when
        # what answered was a login screen.
        auth_seen: list[Any] = []
        for page in result.pages:
            final = (page.data or {}).get("final_url")
            if page.redirected_from and final and final != page.redirected_from:
                answered = await gtx.url_assets(final, scope)
                if answered is not None:
                    await gtx.asset_edge(answered, None, "redirects_to")                         if answered.id == "" else None
            state = (page.data or {}).get("auth_state")
            # A 401 on ONE endpoint, or one login page, is an ordinary fact about a
            # part of the application -- not a blocked assessment: a real application
            # has protected areas and a login screen. Only an identity provider (the
            # target handing every client to an SSO service) means the run never
            # reached the application; the coverage verdict derives the rest from
            # what was actually examined.
            if state and state.get("state") == coverage.AUTH_IDP:
                auth_seen.append({"url": page.url, **state})
        if auth_seen:
            for item in auth_seen[:5]:
                key = f"auth.state|{item.get('state')}|{item.get('url')}"[:300]
                await gtx.node(
                    "observation", key,
                    f"authentication: {item.get('state')} at {item.get('url')}",
                    "recorded",
                    data={"facts": item, "auth_state": item.get("state")},
                    agent_id=r.job.agent_id, work_order_id=r.job.wo_id)
                await events.emit(
                    session, run_id, "auth.state",
                    f"authentication state {item.get('state')} at "
                    f"{item.get('provider') or item.get('url')}",
                    data={**item, "detail": item.get("detail")},
                    agent_id=r.job.agent_id, work_order_id=r.job.wo_id)
            if result.observations is not None:
                result.observations = list(result.observations)
            auth_states = [s.get("state") for s in auth_seen]
            run_row = await session.get(GreyboxRun, run_id)
            if run_row is not None and auth_states:
                # the run remembers what it met (used by the completion verdict)
                run_row.auth_states = sorted(set(run_row.auth_states or [])
                                             | set(auth_states))
        # Passive network signals (third-party origins, edge providers, leaks): assets
        # and edges a tool asked for.
        await netproject.apply_specs(gtx, result.assets, result.edges)
        # Endpoints an unbound tool (an agent-written analyser) actually examined.
        for u in getattr(result, "examined", None) or []:
            examined = await gtx.url_assets(u, scope)
            if examined is not None:
                await gtx.mark_tested(examined.id)
        # Signals the planner reasons about become observations of their own (design
        # 10.1): a lead can then be spawned *from* the observation that justified it.
        signal_obs = []
        for page in result.pages:
            login = page.data.get("login_form")
            ep = url_keys(page.url)
            if login and ep is not None and await gtx.get_node(
                    "observation", f"signal.login_form|{ep.endpoint}"[:300]) is None:
                signal_obs.append(tools.Observation(
                    key=f"signal.login_form|{ep.endpoint}"[:300],
                    label=f"Login form on {ep.path}", url=page.url,
                    exchange_ids=list(page.exchange_ids),
                    facts={"method": login.get("method"),
                           "fields": sorted((login.get("fields") or {}))}))
        for obs in [*result.observations, *signal_obs]:
            node = await gtx.node(
                "observation", obs.key, obs.label, "recorded",
                data={"facts": obs.facts, "url": obs.url},
                agent_id=r.job.agent_id, work_order_id=r.job.wo_id)
            ev = await events.emit(
                session, run_id, "observation.recorded", obs.label,
                data={"node_id": str(node.id), "observation": obs.label,
                      "facts": obs.facts},
                refs={"node_ids": [node.id],
                      "exchange_ids": obs.exchange_ids},
                agent_id=r.job.agent_id, work_order_id=r.job.wo_id)
            node.event_seq = ev.seq
            node.last_event_seq = ev.seq
            if action is not None:
                await gtx.edge(action, node, "observed")
            if obs.key.startswith("skill.loaded|") and wo is not None:
                # which methodology the agent chose, and why (its own reason)
                await events.emit(
                    session, run_id, "skill.loaded",
                    f"skill loaded: {obs.facts.get('skill')}",
                    data={"skill": obs.facts.get("skill"),
                          "reason": events.clip(wo.reason, 400),
                          "criteria": obs.facts.get("criteria") or []},
                    refs={"node_ids": [node.id]},
                    agent_id=r.job.agent_id, work_order_id=r.job.wo_id)
        for spec in result.findings:
            asset = await gtx.get_asset(*spec.asset_ref) if spec.asset_ref \
                else await gtx.url_assets(spec.asset_url or spec.url, scope)
            if asset is None:
                continue
            # Identity, not location: a service-wide fact is reported once and grows a
            # list of locations; anything else is identified by the URL it was seen on.
            where = spec.identity or asset.key
            dedup = (redaction.scrub(f"{spec.check_id}|{where}|{spec.detail}") or "")[:300]
            existing = (await session.scalar(
                select(GreyboxFinding.id).where(GreyboxFinding.run_id == run_id,
                                               GreyboxFinding.dedup_key == dedup)))
            if existing is not None:
                if spec.identity and spec.occurrence:
                    await _fold_occurrence(session, existing, spec, r)
                continue
            finding = GreyboxFinding(
                id=uuid.uuid4(), run_id=run_id, dedup_key=dedup,
                check_id=spec.check_id, title=events.clip(spec.title, 300),
                severity=spec.severity, status="candidate",
                confidence=spec.confidence,
                description=redaction.scrub(spec.description) or "",
                location={"url": redaction.url(spec.url), "method": spec.method,
                          "parameter": redaction.scrub(spec.parameter)},
                affected_asset_id=asset.id, agent_id=r.job.agent_id,
                work_order_id=r.job.wo_id,
                evidence=redaction.structured(
                    [{**d, "excerpt": redaction.body_text(d["excerpt"])}
                     for d in (e.as_dict() for e in spec.evidence)]),
                verification=None,
                detection_hints=redaction.structured(spec.detection_hints),
                references=spec.references, cwe=spec.cwe,
                finding_class=findclass.classify(spec.check_id, spec.finding_class),
                remediation=redaction.structured(
                    findclass.clean_remediation(spec.remediation)
                    or findclass.default_remediation(spec.check_id, spec.title)),
                first_event_seq=0,
                version=await gtx.version())
            session.add(finding)
            await session.flush()
            node = await gtx.node(
                "finding", dedup, spec.title, "candidate", data={
                    "check_id": spec.check_id, "severity": spec.severity,
                    "url": redaction.url(spec.url)},
                agent_id=r.job.agent_id, work_order_id=r.job.wo_id,
                finding_id=finding.id, asset_id=asset.id,
                parent=await gtx.get_node("action", r.job.tool_call_id))
            ev = await events.emit(
                session, run_id, "finding.created",
                f"candidate finding: {spec.title} ({spec.severity})",
                level="warning", status="pending",
                data={"finding_id": str(finding.id), "title": spec.title,
                      "severity": spec.severity, "check_id": spec.check_id,
                      "finding_class": finding.finding_class,
                      "status": "candidate", "url": redaction.url(spec.url),
                      "evidence": events.clip(redaction.scrub(
                          "; ".join(str(d.get("excerpt") or d.get("description") or "")
                                    for d in (e.as_dict() for e in spec.evidence[:2])
                                    ) or spec.description) or "", 240),
                      "evidence_count": len(spec.evidence)},
                refs={"finding_id": finding.id, "node_ids": [node.id],
                      "asset_ids": [asset.id],
                      "exchange_ids": [e.exchange_id for e in spec.evidence
                                       if e.exchange_id]},
                agent_id=r.job.agent_id, work_order_id=r.job.wo_id)
            finding.first_event_seq = ev.seq
            finding.node_id = node.id
            node.event_seq = ev.seq
            node.last_event_seq = ev.seq
            node.severity = spec.severity
            await gtx.finding_delta(asset.id, +1)
            if spec.observation_key:
                obs_node = await gtx.get_node("observation", spec.observation_key)
                if obs_node is not None:
                    await gtx.edge(obs_node, node, "supports")
            if spec.passive:        # verified by re-reading the recorded exchange
                await netproject.passive_verify(
                    session, gtx, finding, node, spec, scope,
                    agent_id=r.job.agent_id, work_order_id=r.job.wo_id)
            new_findings.append(NewFinding(
                id=finding.id, check_id=spec.check_id, dedup_key=dedup,
                verify={} if spec.passive else spec.verify, asset_id=asset.id))
        # live network analysis: derived from recorded exchanges only
        from src.greybox_web import surface as surface_mod
        await surface_mod.refresh(session, gtx, work_order_id=r.job.wo_id)
        # report created AND signal-revised assets to the planner
        for a in [*gtx.new_assets, *gtx.revised_assets]:
            new_assets.append(NewAsset(id=a.id, kind=a.kind, key=a.key,
                                       in_scope=a.in_scope, data=dict(a.data or {})))
        return new_assets, new_findings

    return await tx_write(factory, fn)


async def _apply_verification(factory, run_id: uuid.UUID, r: WODone,
                              stats: GraphStats) -> None:
    async def fn(session: AsyncSession) -> None:
        result: tools.VerifyResult = r.result      # per attempt (the gate may revise it)
        wo = await session.get(GreyboxWorkOrder, r.job.wo_id)
        if wo is None:
            return
        finding_id = wo.params.get("finding_id")
        finding = await session.get(GreyboxFinding,
                                    uuid.UUID(str(finding_id))) if finding_id else None
        gtx = GraphTx(session, run_id, stats, agent_id=r.job.agent_id,
                      work_order_id=r.job.wo_id)
        action = await gtx.get_node("action", r.job.tool_call_id)
        if finding is None or finding.run_id != run_id:
            return
        outcome = result.outcome or (
            "confirmed" if result.confirmed else "not_reproduced")
        keep_candidate = outcome in {"potential_vulnerability", "unknown",
                                     "inconclusive", "blocked_by_configuration"}
        if result.confirmed and outcome not in {"confirmed", "confirmed_exploitable",
                                                "confirmed_misconfiguration"}:
            result = tools.VerifyResult(False, result.method,
                f"verification outcome cannot confirm impact: {outcome}",
                result.exchange_ids, result.excerpt, outcome)
        record = {
            "method": result.method, "attempts": 1, "result": outcome,
            "exchange_ids": result.exchange_ids, "verified_at": utcnow().isoformat(),
            "agent_id": str(r.job.agent_id), "work_order_id": str(r.job.wo_id)}
        if result.confirmed and finding.check_id == "authz.object":
            # Reproduced access is not itself evidence of unauthorised access.
            decision, reasons = await _model_gate(session, run_id, finding,
                                                  result.exchange_ids)
            record["model"] = {"decision": decision, "reasons": reasons[:6]}
            if decision == "authorised":
                result = tools.VerifyResult(
                    False, result.method,
                    "reproduced, but consistent with the application's access "
                    "model: " + "; ".join(reasons)[:400], result.exchange_ids)
                record["result"] = "authorised_by_model"
            elif decision == "unknown":
                result = tools.VerifyResult(
                    False, result.method,
                    "access reproduced, but its intended permission remains unknown: "
                    + "; ".join(reasons)[:400], result.exchange_ids)
                record["result"] = "inconclusive"
                keep_candidate = True
        # one assignment of a complete record: an in-place change to a JSON value
        # already assigned is not persisted
        finding.verification = record
        node = await session.get(GreyboxGraphNode, finding.node_id) \
            if finding.node_id else None
        if result.confirmed:
            finding.status = "verified"
            ev = await events.emit(
                session, run_id, "finding.verified",
                f"verified: {finding.title}", level="warning",
                data={"finding_id": str(finding.id), "title": finding.title,
                      "severity": finding.severity, "check_id": finding.check_id,
                      "method": result.method, "exchange_ids": result.exchange_ids},
                refs={"finding_id": finding.id, "node_ids": [node.id]
                      if node else [],
                      "exchange_ids": result.exchange_ids},
                agent_id=r.job.agent_id, work_order_id=r.job.wo_id)
            if node is not None:
                node.status = "verified"
                node.last_event_seq = ev.seq
                node.version = await gtx.version()
            if action is not None and node is not None:
                await gtx.edge(action, node, "verified")
        elif keep_candidate:
            finding.status = "candidate"
            if node is not None:
                node.status = "candidate"
                node.version = await gtx.version()
        else:
            finding.status = "rejected"
            ev = await events.emit(
                session, run_id, "finding.rejected",
                f"rejected: {finding.title} ({result.note})", status="skipped",
                data={"finding_id": str(finding.id), "reason": result.note},
                refs={"finding_id": finding.id, "node_ids": [node.id]
                      if node else []},
                agent_id=r.job.agent_id, work_order_id=r.job.wo_id)
            if node is not None:
                node.status = "rejected"
                node.last_event_seq = ev.seq
                node.version = await gtx.version()
            if action is not None and node is not None:
                await gtx.edge(action, node, "refuted")
            await gtx.finding_delta(finding.affected_asset_id, -1)

    await tx_write(factory, fn)


async def _model_gate(session: AsyncSession, run_id: uuid.UUID, finding,
                      exchange_ids: list[int]) -> tuple[str, list[str]]:
    """Readers of the re-verified object (from the verification's own attributed
    exchanges) checked against the security model."""
    from src.greybox_web import secmodel_store
    if not exchange_ids:
        return "unknown", []
    rows = (await session.execute(
        select(GreyboxHttpExchange.url, GreyboxHttpExchange.identity,
               GreyboxHttpExchange.status_code)
        .where(GreyboxHttpExchange.run_id == run_id,
               GreyboxHttpExchange.id.in_(list(exchange_ids)[:50])))).all()
    served = [(u, i) for u, i, st in rows if st is not None and 200 <= st < 300 and i]
    if not served or any(i == "anon" for _, i in served):
        return "unknown", (["anonymous access"] if served else [])
    url = served[0][0]
    readers = sorted({i for _, i in served if i not in ("browser-session",)})
    return await secmodel_store.access_gate(session, run_id, url, readers)


def _acted_on(params: dict[str, Any], res: Any) -> tuple[str, ...]:
    """URLs a successful call proved it has already fetched.

    Evidence, not intent: a URL counts as visited only when the result carries a page
    for it that was actually fetched (``fetched`` true, or a status code recorded).
    ``discovery.crawl`` still retires its own seeds separately; this covers every
    other tool that reads a URL — ``browser.visit``, ``discovery.scripts``,
    ``exposure.files`` — so none of them can leave the frontier pointing at a file
    the agent has already read.
    """
    out: list[str] = []
    for page in getattr(res, "pages", None) or ():
        url = getattr(page, "url", None)
        if not isinstance(url, str) or not url:
            continue
        if getattr(page, "fetched", False) or getattr(page, "status", None) is not None:
            out.append(url)
    return tuple(dict.fromkeys(out))
