"""Grey-box Temporal workflows — 4-phase event-driven pentest pipeline.

Orchestrates:
  Phase 1: Preflight + Discovery + Managed Scans — init graph, init workspace,
           authenticate sessions, then run discovery and managed scans
           concurrently (scanners populate graph in parallel with discovery).
  Phase 2: Reactive   — deterministic scheduler loop emitting verbs, spawning specialists
  Phase 3: Chain      — chain exploitation of linked findings
  Phase 4: Report     — final report generation + graph export

Features:
- Session pool (8 Playwright sessions) with acquire/release
- Child workflows for agent isolation (AgentExecutionWorkflow)
- Credential signal forwarding via check_credential_signals activity (E2)
- Queryable progress via get_progress
- Per-agent cost ceiling enforcement (E15)
- Max spawn depth guardrail (E8)
- Per-vuln-type agent limit (E12)
- Max duration enforcement via workflow.now() (E25)
"""

from __future__ import annotations

import asyncio  # E1.5
import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from src.greybox.planner.chain_detector import ChainDetector
    from src.greybox.temporal.activities import (
        AgentExecutionInput,
        AuditEventInput,
        BuildPromptInput,
        CheckSignalsInput,
        ExportGraphInput,
        GreyBoxActivityInput,
        InitGraphInput,
        InitWorkspaceInput,
        ManagedScanInput,
        PostAgentBookkeepingInput,
        PrepareSessionInput,
        ResolveContextInput,
        ScheduleTickInput,
        authenticate_sessions,
        build_agent_prompt,
        check_credential_signals,
        export_graph,
        init_graph,
        init_workspace,
        post_agent_bookkeeping,
        prepare_session,
        resolve_agent_context,
        run_greybox_agent,
        run_managed_scan,
        schedule_tick_activity,
        write_audit_event,
    )
    from src.greybox.types.agents import (
        AGENT_MODEL_TIERS,
        AGENT_PROMPT_TEMPLATES,
    )
    from src.greybox.types.config import GreyBoxConfig, GreyBoxInput


# ---------------------------------------------------------------------------
# Child workflow input — richer than AgentExecutionInput (activity-level)
# ---------------------------------------------------------------------------


@dataclass
class ChildWorkflowInput:
    """Input for AgentExecutionWorkflow child workflows.

    Carries everything needed to build a prompt, check credentials,
    and execute an agent in isolation.
    """

    agent_id: str
    agent_type: str
    action_type: str
    session: str
    web_url: str
    session_id: str
    credentials_path: str
    output_path: str
    target: dict[str, Any] = field(default_factory=dict)
    parent_workflow_id: str = ""
    description: str = ""
    rules_avoid: str = ""
    rules_focus: str = ""
    specialist_model: str = "medium"
    model_override: str = ""
    auth_session_dir: str = ""
    budget_remaining_pct: float = 1.0
    lead_max_attempts: int = 3

# ---------------------------------------------------------------------------
# Non-retryable error types
# ---------------------------------------------------------------------------

_NON_RETRYABLE_TYPES: list[str] = [
    "AuthenticationError",
    "BudgetExhaustedError",
    "ConfigurationError",
    "ExecutionError",
    "ExecutionLimitError",
    "InvalidRequestError",
    "InvalidTargetError",
    "PermissionError",
    "RequestTooLargeError",
    "ScannerNotFoundError",
    "SchemaVersionMismatchError",
]

# ---------------------------------------------------------------------------
# Retry policies
# ---------------------------------------------------------------------------

PREFLIGHT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=10),
    maximum_interval=timedelta(minutes=1),
    backoff_coefficient=2.0,
    maximum_attempts=3,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

# E13: Discovery gets its own retry policy — more aggressive than preflight
DISCOVERY_RETRY = RetryPolicy(
    initial_interval=timedelta(minutes=5),
    maximum_interval=timedelta(minutes=30),
    backoff_coefficient=2.0,
    maximum_attempts=10,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

AGENT_RETRY = RetryPolicy(
    initial_interval=timedelta(minutes=1),
    maximum_interval=timedelta(minutes=5),
    backoff_coefficient=2.0,
    maximum_attempts=3,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

# ---------------------------------------------------------------------------
# Timeout defaults
# ---------------------------------------------------------------------------

_AGENT_START_TO_CLOSE = timedelta(hours=2)
_AGENT_HEARTBEAT = timedelta(minutes=60)
_UTILITY_START_TO_CLOSE = timedelta(minutes=5)
_PREFLIGHT_START_TO_CLOSE = timedelta(minutes=2)

# Session pool size
_SESSION_POOL_SIZE = 8
_SESSION_PREFIX = "agent"

_SCHEDULER_TICK_TIMEOUT_S = 30

# Maps scheduler verb kind → agent type. PROBE_PARAMETERS is handled
# separately because its agent is chosen per-verb from verb.vuln_type.
_KIND_TO_AGENT: dict[str, str] = {
    "INVESTIGATE_LEAD": "lead-investigator",
    "TEST_ACCESS_MATRIX": "authorization-specialist",
    "ATTEMPT_CHAIN": "chain-exploit",
}

# Maps vuln_type (from PROBE_PARAMETERS verb) → specialist agent type.
# Roster: 4 flagship (authorization, injection, reflection, ssrf) +
# 2 conditional (graphql, websocket). See Slice 14 / Cluster E.
_VULN_TO_AGENT: dict[str, str] = {
    "authorization": "authorization-specialist",
    "injection": "injection-specialist",
    "reflection": "reflection-specialist",
    "ssrf": "ssrf-specialist",
    "graphql": "graphql-specialist",
    "websocket": "websocket-specialist",
}


# ---------------------------------------------------------------------------
# GreyBoxPipelineWorkflow — main 4-phase workflow
# ---------------------------------------------------------------------------


# Map legacy ``current_phase`` values (pre-Slice-13) to the new naming scheme so
# existing resume_state files remain compatible.
_LEGACY_PHASE_MAP: dict[str, str] = {
    "preflight": "phase_1",
    "managed_scans": "phase_1",
    "reactive": "phase_2",
    "chain": "phase_3",
    "report": "phase_4",
}


@workflow.defn
class GreyBoxPipelineWorkflow:
    """4-phase grey-box pentest pipeline orchestrated via Temporal.

    Manages session pool, dynamic agent spawning, and the scheduler-driven
    reactive loop.
    """

    def __init__(self) -> None:
        # Phase tracking
        self.current_phase: str = "phase_1"
        self.done: bool = False
        self.error: str | None = None

        # Session pool: 8 Playwright sessions
        self.session_pool: set[str] = {
            f"{_SESSION_PREFIX}{i}" for i in range(1, _SESSION_POOL_SIZE + 1)
        }
        self.session_assignments: dict[str, str] = {}  # agent_id -> session

        # Agent tracking
        self.active_agents: dict[str, asyncio.Task] = {}
        self.completed_agents: list[str] = []
        self.agent_metrics: dict[str, dict[str, Any]] = {}
        self.agent_costs: dict[str, float] = {}  # E15: per-agent cost tracking
        self.vuln_type_counts: dict[str, int] = {}  # E12: active per-vuln-type count
        self.agent_target_claims: dict[str, set[str]] = {}  # agent_id -> graph ids in flight
        self.agent_vuln_buckets: dict[str, str] = {}  # agent_id -> active vuln bucket
        self.agent_action_types: dict[str, str] = {}  # agent_id -> verb kind
        self.agent_targets: dict[str, dict[str, Any]] = {}  # agent_id -> target dict

        # Reactive-loop state
        self.tick: int = 0
        self.total_cost: float = 0.0
        self.findings: list[dict[str, Any]] = []
        self.spawn_depth: dict[str, int] = {}  # E8: agent_id -> depth

        # Scheduler progress-tracking state (owned by the scheduler —
        # the workflow only forwards these between ticks).
        self.previous_graph_counts: dict[str, int] = {}
        self.previous_verdict_counts: dict[str, int] = {}
        self.ticks_since_last_progress: int = 0
        self.consecutive_waiting_ticks: int = 0

        # Auth session state (populated in Phase 1, shared with Phase 2 agents)
        self.auth_session_dir: str = ""

        # Signal state
        self.urgent_signal: bool = False
        self.new_findings_signal: bool = False
        self.replan_requested: bool = False

    # -------------------------------------------------------------------
    # Signals
    # -------------------------------------------------------------------

    @workflow.signal
    async def signal_new_findings(self, findings: list[dict[str, Any]]) -> None:
        """Signal from agents that new findings have been discovered."""
        self.findings.extend(findings)
        self.new_findings_signal = True

    @workflow.signal
    async def signal_urgent(self, reason: str) -> None:
        """Signal for urgent replanning (e.g., critical vuln found)."""
        workflow.logger.info("Urgent signal received: %s", reason)
        self.urgent_signal = True

    @workflow.signal
    async def signal_replan(self) -> None:
        """Signal requesting a replan cycle."""
        self.replan_requested = True

    # -------------------------------------------------------------------
    # Query
    # -------------------------------------------------------------------

    @workflow.query
    def get_progress(self) -> dict[str, Any]:
        """Return current pipeline progress."""
        return {
            "phase": self.current_phase,
            "done": self.done,
            "error": self.error,
            "tick": self.tick,
            "active_agents": list(self.active_agents.keys()),
            "completed_agents": self.completed_agents,
            "session_pool_available": len(self.session_pool),
            "total_cost": self.total_cost,
            "findings_count": len(self.findings),
            "ticks_since_last_progress": self.ticks_since_last_progress,
        }

    # -------------------------------------------------------------------
    # Session pool management
    # -------------------------------------------------------------------

    def _acquire_session(self) -> str | None:
        """Acquire a Playwright session from the pool. Returns None if exhausted."""
        if not self.session_pool:
            return None
        return self.session_pool.pop()

    def _release_session(self, session: str) -> None:
        """Release a Playwright session back to the pool."""
        self.session_pool.add(session)

    # -------------------------------------------------------------------
    # Audit helper
    # -------------------------------------------------------------------

    async def _audit(self, workspace: str, **kwargs: object) -> None:
        """Fire-and-forget audit event. Failures are non-fatal."""
        try:
            await workflow.execute_activity(
                write_audit_event,
                AuditEventInput(workspace=workspace, **kwargs),
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=PREFLIGHT_RETRY,
            )
        except Exception as exc:
            workflow.logger.warning("Audit event failed: %s", exc)

    # -------------------------------------------------------------------
    # Main workflow run
    # -------------------------------------------------------------------

    @workflow.run
    async def run(self, input: GreyBoxInput) -> dict[str, Any]:
        """Execute the 4-phase grey-box pipeline."""
        config = input.config
        start_time = workflow.now()

        # Build base activity input (matches GreyBoxActivityInput dataclass)
        wf_id = input.workflow_id or workflow.info().workflow_id
        resolved_output = input.output_path or f".vigilo/{input.session_id}"
        base_input = GreyBoxActivityInput(
            web_url=input.web_url,
            session_id=input.session_id,
            credentials_path=input.credentials_path,
            config_path=input.config_path,
            output_path=resolved_output,
            description=input.description,
            rules_avoid=input.rules_avoid,
            rules_focus=input.rules_focus,
        )
        # Store workflow_id and config for child workflow construction
        self._workflow_id = wf_id
        self._input = input

        workspace = resolved_output

        # Translate legacy resume values ("preflight"/"managed_scans"/...)
        # to the new phase names so existing resume_state files still work.
        if self.current_phase in _LEGACY_PHASE_MAP:
            self.current_phase = _LEGACY_PHASE_MAP[self.current_phase]

        try:
            # =============================================================
            # Phase 1: Preflight + Discovery + Managed Scans
            # =============================================================
            if self.current_phase == "phase_1":
                await self._audit(workspace, event_type="phase_start", phase="phase_1")
                await self.phase_1_preflight_discovery_scans(base_input, config)
                await self._audit(workspace, event_type="phase_complete", phase="phase_1")
                self.current_phase = "phase_2"

            # =============================================================
            # Phase 2: Reactive Testing Loop
            # =============================================================
            if self.current_phase == "phase_2":
                await self._audit(workspace, event_type="phase_start", phase="phase_2")
                await self.phase_2_reactive_loop(base_input, config, start_time)
                await self._audit(workspace, event_type="phase_complete", phase="phase_2")
                self.current_phase = "phase_3"

            # =============================================================
            # Phase 3: Chain Exploitation
            # =============================================================
            if self.current_phase == "phase_3":
                await self._audit(workspace, event_type="phase_start", phase="phase_3")
                await self.phase_3_chain_exploitation(base_input, config)
                await self._audit(workspace, event_type="phase_complete", phase="phase_3")
                self.current_phase = "phase_4"

            # =============================================================
            # Phase 4: Report + Graph Export
            # =============================================================
            if self.current_phase == "phase_4":
                await self._audit(workspace, event_type="phase_start", phase="phase_4")
                await self.phase_4_report(base_input, config)
                await self._audit(workspace, event_type="phase_complete", phase="phase_4")

            self.done = True
            self.current_phase = "completed"

            # Finalize audit trail
            elapsed_ms = int((workflow.now() - start_time).total_seconds() * 1000)
            await self._audit(
                workspace,
                event_type="finalize",
                status="completed",
                total_duration_ms=elapsed_ms,
                total_cost=self.total_cost,
                findings_count=len(self.findings),
                agents_completed=len(self.completed_agents),
            )

            return self.get_progress()

        except Exception as e:
            self.error = str(e)[:2000]
            self.done = True
            workflow.logger.error("Pipeline failed: %s", self.error)

            # Finalize audit trail on failure
            elapsed_ms = int((workflow.now() - start_time).total_seconds() * 1000)
            await self._audit(
                workspace,
                event_type="finalize",
                status="failed",
                total_duration_ms=elapsed_ms,
                total_cost=self.total_cost,
                findings_count=len(self.findings),
                agents_completed=len(self.completed_agents),
                error=self.error,
            )
            raise

    # -------------------------------------------------------------------
    # Phase 1: Preflight + Discovery + Managed Scans
    # -------------------------------------------------------------------

    async def phase_1_preflight_discovery_scans(
        self,
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
    ) -> None:
        """Phase 1: Initialize graph + workspace + sessions (sequential),
        then run discovery and managed scans concurrently.

        Init must complete before the gather so the graph exists before any
        scanner or discovery write.
        """
        workflow.logger.info("Phase 1: Preflight + Discovery + Managed Scans")

        # Init graph — must complete before any downstream write.
        await workflow.execute_activity(
            init_graph,
            InitGraphInput(
                session_id=base_input.session_id,
                credentials_path=base_input.credentials_path,
                web_url=base_input.web_url,
            ),
            start_to_close_timeout=_PREFLIGHT_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )

        # Init workspace
        await workflow.execute_activity(
            init_workspace,
            InitWorkspaceInput(
                session_id=base_input.session_id,
                web_url=base_input.web_url,
                output_path=base_input.output_path,
            ),
            start_to_close_timeout=_PREFLIGHT_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )

        # Authenticate sessions and capture HTTP cookies for managed scans.
        auth_result = await workflow.execute_activity(
            authenticate_sessions,
            base_input,
            start_to_close_timeout=_AGENT_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )
        cookie_paths: dict[str, str] = (auth_result or {}).get("cookie_paths", {}) or {}
        if cookie_paths and base_input.output_path:
            self.auth_session_dir = f"{base_input.output_path}/sessions"

        # Pick the identity to run scans as. Order of preference:
        # 1) configured ``default_identity`` if it has captured cookies,
        # 2) any captured identity (first in the dict, deterministic),
        # 3) none — scans run unauthenticated.
        scan_identity: str | None = None
        scan_session_file: str | None = None
        if cookie_paths:
            if config.default_identity in cookie_paths:
                scan_identity = config.default_identity
            else:
                scan_identity = next(iter(cookie_paths))
            scan_session_file = cookie_paths[scan_identity]
            workflow.logger.info(
                "Managed scans will run as identity %r (session=%s)",
                scan_identity, scan_session_file,
            )
        else:
            workflow.logger.info("No captured sessions — managed scans run unauthenticated")

        # Run discovery and managed scans concurrently — scanners populate
        # endpoints/techs/findings/leads while discovery crawls. The scanner
        # gather is wrapped in ``asyncio.wait_for`` so a stuck tool can't hold
        # up the transition to Phase 2.
        async def _scans_with_deadline() -> None:
            try:
                await asyncio.wait_for(
                    self._dispatch_managed_scans(
                        base_input, config, scan_identity, scan_session_file,
                    ),
                    timeout=config.preflight_scan_deadline_s,
                )
            except asyncio.TimeoutError:
                workflow.logger.warning(
                    "Managed scans exceeded preflight deadline of %ss — "
                    "continuing to Phase 2 without waiting for stragglers",
                    config.preflight_scan_deadline_s,
                )

        await asyncio.gather(
            self._run_discovery_agent(base_input, config),
            _scans_with_deadline(),
            return_exceptions=False,
        )

    async def _run_discovery_agent(
        self,
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
    ) -> None:
        """Run the single discovery agent with DISCOVERY_RETRY (E13)."""
        discovery_session = self._acquire_session()
        if not discovery_session:
            workflow.logger.warning("No session available for discovery")
            return

        agent_id = f"discovery-{str(workflow.uuid4())[:8]}"  # E1.1
        try:
            discovery_result = await workflow.execute_child_workflow(
                AgentExecutionWorkflow.run,
                self._build_child_input(
                    agent_id=agent_id,
                    agent_type="discovery",
                    action_type="DISCOVERY",
                    session=discovery_session,
                    base_input=base_input,
                    config=config,
                ),
                id=agent_id,
                retry_policy=DISCOVERY_RETRY,
            )
            self._record_agent_result(agent_id, discovery_result, config)
        finally:
            self._release_session(discovery_session)

    async def _dispatch_managed_scans(
        self,
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
        scan_identity: str | None = None,
        scan_session_file: str | None = None,
    ) -> list[Any]:
        """Launch all enabled managed scans in parallel.

        When ``scan_identity`` is set, scanners run authenticated using the
        cookies captured at ``scan_session_file``. Without it, scans run
        unauthenticated (legacy behavior).

        Failure-isolated: each scanner's exception is logged and recorded
        against its slot; successful results feed ``agent_metrics`` and
        ``total_cost`` so the reactive loop sees them. Concurrency is
        bounded by ``config.managed_scan_concurrency`` so large rosters
        don't swamp the container.
        """
        from src.greybox.managed import ACTIVE_RECON_SCANNERS

        enabled_scans = [
            name for name, enabled in config.managed_scans.items() if enabled
        ]
        if not config.active_recon_enabled:
            dropped = [n for n in enabled_scans if n in ACTIVE_RECON_SCANNERS]
            if dropped:
                workflow.logger.info(
                    "Active recon disabled — skipping scanners: %s",
                    ", ".join(dropped),
                )
            enabled_scans = [n for n in enabled_scans if n not in ACTIVE_RECON_SCANNERS]

        if not enabled_scans:
            workflow.logger.info("No managed scans enabled")
            return []

        semaphore = asyncio.Semaphore(config.managed_scan_concurrency)

        async def _run_one(scan_name: str) -> Any:
            async with semaphore:
                return await workflow.execute_activity(
                    run_managed_scan,
                    ManagedScanInput(
                        web_url=base_input.web_url,
                        session_id=base_input.session_id,
                        scan_type=scan_name,
                        output_dir=base_input.output_path,
                        identity_name=scan_identity or "",
                        session_file=scan_session_file or "",
                    ),
                    start_to_close_timeout=_AGENT_START_TO_CLOSE,
                    heartbeat_timeout=_AGENT_HEARTBEAT,
                    retry_policy=AGENT_RETRY,
                    activity_id=f"managed-scan:{scan_name}",
                )

        results = await asyncio.gather(
            *(_run_one(name) for name in enabled_scans),
            return_exceptions=True,
        )

        for i, result in enumerate(results):
            scan_name = enabled_scans[i]
            if isinstance(result, BaseException):
                workflow.logger.warning(
                    "Managed scan %s failed: %s", scan_name, str(result)[:500]
                )
            else:
                self.completed_agents.append(f"managed:{scan_name}")
                if isinstance(result, dict):
                    self.agent_metrics[f"managed:{scan_name}"] = result
                    self.total_cost += result.get("cost_usd", 0.0)

        return list(results)

    # -------------------------------------------------------------------
    # Phase 2: Reactive Testing Loop
    # -------------------------------------------------------------------

    async def phase_2_reactive_loop(
        self,
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
        start_time: Any,
    ) -> None:
        """Phase 2: Scheduler-driven reactive testing loop.

        Each tick calls ``schedule_tick_activity`` which runs the
        deterministic scheduler and returns a list of verb dicts.
        DONE ends the loop; other verbs dispatch specialists.
        """
        workflow.logger.info("Phase 2 (reactive) started — scheduler-driven")
        max_ticks = config.max_scheduler_ticks

        while self.tick < max_ticks:
            # E25: Check max_duration_hours
            elapsed_hours = (
                workflow.now() - start_time
            ).total_seconds() / 3600.0
            if elapsed_hours >= config.max_duration_hours:
                workflow.logger.info(
                    "Max duration %.1fh reached, ending reactive loop",
                    config.max_duration_hours,
                )
                break

            if self.total_cost >= config.per_scan_cost_ceiling:
                workflow.logger.info(
                    "Cost ceiling $%.2f reached, ending reactive loop",
                    config.per_scan_cost_ceiling,
                )
                break

            self.tick += 1
            active_claims = self._active_claim_ids()

            # Compute budget remaining pct from cost ceiling
            budget_remaining = 1.0
            if config.per_scan_cost_ceiling > 0:
                budget_remaining = max(
                    0.0,
                    1.0 - self.total_cost / config.per_scan_cost_ceiling,
                )

            tick_result = await workflow.execute_activity(
                schedule_tick_activity,
                ScheduleTickInput(
                    session_id=base_input.session_id,
                    workspace=base_input.output_path or "",
                    active_claims=active_claims,
                    tick_number=self.tick,
                    budget_remaining_pct=budget_remaining,
                    previous_graph_counts=self.previous_graph_counts,
                    previous_verdict_counts=self.previous_verdict_counts,
                    ticks_since_last_progress=self.ticks_since_last_progress,
                    consecutive_waiting_ticks=self.consecutive_waiting_ticks,
                    idle_ticks_before_done=config.idle_ticks_before_done,
                    per_type_cap=config.per_type_cap,
                    authz_per_tick_cap=config.authz_per_tick_cap,
                    chain_per_tick_cap=config.chain_per_tick_cap,
                    max_specialists_per_endpoint=config.max_specialists_per_endpoint,
                    budget_cheap_ceiling_pct=config.budget_cheap_ceiling_pct,
                    budget_cheap_floor_pct=config.budget_cheap_floor_pct,
                    max_inconclusive_retries=config.max_inconclusive_retries,
                    max_failed_retries=config.max_failed_retries,
                    max_consecutive_waiting_ticks=config.max_consecutive_waiting_ticks,
                ),
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=PREFLIGHT_RETRY,
            )

            # Support both ScheduleTickOutput dataclass and plain-dict returns
            # (Temporal serializes dataclass→dict over the wire, tests stub
            # with a bare list[dict] pre-Slice-9).
            if isinstance(tick_result, dict):
                verb_dicts = tick_result.get("verbs", [])
                self.previous_graph_counts = dict(tick_result.get("graph_counts", {}))
                self.previous_verdict_counts = dict(tick_result.get("verdict_counts", {}))
                self.ticks_since_last_progress = int(
                    tick_result.get("ticks_since_last_progress", 0)
                )
                self.consecutive_waiting_ticks = int(
                    tick_result.get("consecutive_waiting_ticks", 0)
                )
            elif isinstance(tick_result, list):
                verb_dicts = tick_result
            else:
                verb_dicts = list(tick_result.verbs)
                self.previous_graph_counts = dict(tick_result.graph_counts)
                self.previous_verdict_counts = dict(tick_result.verdict_counts)
                self.ticks_since_last_progress = tick_result.ticks_since_last_progress
                self.consecutive_waiting_ticks = tick_result.consecutive_waiting_ticks

            # Check for DONE verb first — scheduler emits it solo when halting.
            if any(v.get("kind") == "DONE" for v in verb_dicts):
                done_reason = next(
                    (v.get("reason") for v in verb_dicts if v.get("kind") == "DONE"),
                    "unknown",
                )
                workflow.logger.info(
                    "Scheduler emitted DONE (%s), exiting Phase 2", done_reason,
                )
                break

            for verb in verb_dicts:
                kind = verb.get("kind")
                if kind == "DONE":
                    continue
                await self._spawn_specialist_from_verb(verb, base_input, config, self.tick)

            # Reset signal flags before waiting
            self.new_findings_signal = False
            self.urgent_signal = False
            self.replan_requested = False

            def scheduler_should_tick() -> bool:
                return (
                    self.new_findings_signal
                    or self.urgent_signal
                    or self.replan_requested
                    or len(self.active_agents) == 0
                )

            try:
                await workflow.wait_condition(
                    scheduler_should_tick,
                    timeout=timedelta(seconds=_SCHEDULER_TICK_TIMEOUT_S),
                )
            except TimeoutError:
                pass  # 30s tick elapsed — re-schedule

            await self._harvest_completed_agents(config, base_input.session_id)

        # Drain remaining agents before leaving the loop
        if self.active_agents:
            await self._harvest_all_agents(config, base_input.session_id)

    # -------------------------------------------------------------------
    # Agent spawning
    # -------------------------------------------------------------------

    async def _spawn_specialist_from_verb(
        self,
        verb: dict[str, Any],
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
        tick: int,
    ) -> None:
        """Spawn a child workflow for a scheduler verb.

        Enforces:
        - E12: max_per_vuln_type (for PROBE_PARAMETERS)
        - Session pool availability
        - Max concurrent agents
        """
        kind = verb.get("kind", "")

        # Resolve agent type + vuln bucket
        if kind == "PROBE_PARAMETERS":
            vuln_type = verb.get("vuln_type", "injection")
            agent_type = _VULN_TO_AGENT.get(vuln_type, f"{vuln_type}-specialist")
        elif kind in _KIND_TO_AGENT:
            agent_type = _KIND_TO_AGENT[kind]
            vuln_type = kind.lower()
        else:
            workflow.logger.warning("Unknown verb kind, skipping: %s", kind)
            return

        # E12: Enforce max_per_vuln_type
        current_count = self.vuln_type_counts.get(vuln_type, 0)
        if current_count >= config.max_per_vuln_type:
            workflow.logger.warning(
                "Max per-vuln-type %d reached for %s, skipping",
                config.max_per_vuln_type, vuln_type,
            )
            return

        if len(self.active_agents) >= config.max_concurrent_agents:
            workflow.logger.info(
                "Max concurrent agents %d reached, skipping %s",
                config.max_concurrent_agents, kind,
            )
            return

        session = self._acquire_session()
        if session is None:
            workflow.logger.info("No sessions available, skipping %s", kind)
            return

        agent_id = f"{agent_type}-{str(workflow.uuid4())[:8]}"
        self.spawn_depth[agent_id] = 0
        self.vuln_type_counts[vuln_type] = current_count + 1
        self.agent_vuln_buckets[agent_id] = vuln_type
        self.session_assignments[agent_id] = session

        target = self._verb_to_target(verb)
        self.agent_target_claims[agent_id] = self._target_claim_ids(target)
        self.agent_action_types[agent_id] = kind
        self.agent_targets[agent_id] = target

        task = asyncio.create_task(
            self._run_child_agent(
                agent_id=agent_id,
                action_type=kind,
                agent_type=agent_type,
                session=session,
                target=target,
                base_input=base_input,
                config=config,
            )
        )
        self.active_agents[agent_id] = task

    @staticmethod
    def _verb_to_target(verb: dict[str, Any]) -> dict[str, Any]:
        """Translate a scheduler verb dict into a target blob for the child workflow.

        BatchDispatch / LeadDispatch payloads are serialized here; the
        child workflow carries them through to ``resolve_agent_context``.
        """
        kind = verb.get("kind", "")
        if kind == "PROBE_PARAMETERS":
            return {
                "mode": "batch",
                "vuln_type": verb.get("vuln_type", ""),
                "identity": verb.get("identity", "identity:anonymous"),
                "param_ids": list(verb.get("param_ids", [])),
            }
        if kind == "INVESTIGATE_LEAD":
            return {
                "mode": "lead",
                "lead_id": verb.get("lead_id", ""),
                "identity": verb.get("identity", "identity:anonymous"),
            }
        if kind == "TEST_ACCESS_MATRIX":
            return {
                "endpoint_ids": list(verb.get("endpoint_ids", [])),
                "identities": list(verb.get("identities", [])),
            }
        if kind == "ATTEMPT_CHAIN":
            return {
                "finding_ids": list(verb.get("finding_ids", [])),
                "chain_candidates": verb.get("chain_candidates", []),
                "chain_context": verb.get("chain_context", ""),
            }
        return {}

    @staticmethod
    def _target_claim_ids(target: dict[str, Any]) -> set[str]:
        """Extract graph IDs that should be considered in-flight claims."""
        claim_ids: set[str] = set()
        for key in ("param_ids", "endpoint_ids", "finding_ids"):
            values = target.get(key, [])
            if isinstance(values, list):
                claim_ids.update(str(value) for value in values if value)
        lead_id = target.get("lead_id")
        if lead_id:
            claim_ids.add(str(lead_id))
        return claim_ids

    def _active_claim_ids(self) -> list[str]:
        """Return all graph target IDs currently assigned to active agents."""
        claim_ids: set[str] = set()
        for ids in self.agent_target_claims.values():
            claim_ids.update(ids)
        return sorted(claim_ids)

    def _clear_active_agent_tracking(self, agent_id: str) -> None:
        """Release scheduler bookkeeping for a finished child agent."""
        vuln_bucket = self.agent_vuln_buckets.pop(agent_id, None)
        if vuln_bucket is not None:
            current = self.vuln_type_counts.get(vuln_bucket, 0)
            if current <= 1:
                self.vuln_type_counts.pop(vuln_bucket, None)
            else:
                self.vuln_type_counts[vuln_bucket] = current - 1
        self.agent_target_claims.pop(agent_id, None)

    def _build_child_input(
        self,
        agent_id: str,
        agent_type: str,
        action_type: str,
        session: str,
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
        target: dict[str, Any] | None = None,
    ) -> ChildWorkflowInput:
        """Build a ChildWorkflowInput from base_input and agent details."""
        rules_avoid = "\n".join(f"- {r}" for r in base_input.rules_avoid) if base_input.rules_avoid else ""
        rules_focus = "\n".join(f"- {r}" for r in base_input.rules_focus) if base_input.rules_focus else ""
        budget_remaining = 1.0
        if config.per_scan_cost_ceiling > 0:
            budget_remaining = max(
                0.0, 1.0 - self.total_cost / config.per_scan_cost_ceiling,
            )
        return ChildWorkflowInput(
            agent_id=agent_id,
            agent_type=agent_type,
            action_type=action_type,
            session=session,
            web_url=base_input.web_url,
            session_id=base_input.session_id,
            credentials_path=base_input.credentials_path,
            output_path=base_input.output_path,
            target=target or {},
            parent_workflow_id=workflow.info().workflow_id,
            description=base_input.description,
            rules_avoid=rules_avoid,
            rules_focus=rules_focus,
            specialist_model=config.specialist_model,
            model_override=config.model or "",
            auth_session_dir=self.auth_session_dir,
            budget_remaining_pct=budget_remaining,
            lead_max_attempts=config.lead_max_attempts,
        )

    async def _run_child_agent(
        self,
        agent_id: str,
        action_type: str,
        agent_type: str,
        session: str,
        target: dict[str, Any],
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
    ) -> dict[str, Any]:
        """Execute a child workflow for a single agent and handle cleanup."""
        try:
            result = await workflow.execute_child_workflow(
                AgentExecutionWorkflow.run,
                self._build_child_input(
                    agent_id=agent_id,
                    agent_type=agent_type,
                    action_type=action_type,
                    session=session,
                    base_input=base_input,
                    config=config,
                    target=target,
                ),
                id=agent_id,
                retry_policy=AGENT_RETRY,
            )
            return result
        except Exception as exc:
            workflow.logger.warning(
                "Agent %s (%s) failed: %s",
                agent_id, action_type, str(exc)[:500],
            )
            return {"error": str(exc)[:500], "agent_id": agent_id}
        finally:
            # Always release session
            self._release_session(session)
            if agent_id in self.session_assignments:
                del self.session_assignments[agent_id]

    # -------------------------------------------------------------------
    # Agent harvesting
    # -------------------------------------------------------------------

    async def _harvest_completed_agents(
        self, config: GreyBoxConfig, session_id: str,
    ) -> None:
        """Check for completed agent tasks and collect results."""
        completed_ids = []
        for agent_id, task in self.active_agents.items():
            if task.done():
                completed_ids.append(agent_id)

        for agent_id in completed_ids:
            task = self.active_agents.pop(agent_id)
            self.agent_action_types.pop(agent_id, "")
            self.agent_targets.pop(agent_id, {})
            self._clear_active_agent_tracking(agent_id)
            try:
                result = task.result()
                self._record_agent_result(agent_id, result, config)
            except Exception as exc:
                workflow.logger.warning(
                    "Agent %s result error: %s", agent_id, str(exc)[:500]
                )
                self.completed_agents.append(agent_id)

    async def _harvest_all_agents(
        self, config: GreyBoxConfig, session_id: str,
    ) -> None:
        """Wait for all active agents to complete and collect results."""
        if not self.active_agents:
            return

        tasks = list(self.active_agents.values())
        agent_ids = list(self.active_agents.keys())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            agent_id = agent_ids[i]
            self.active_agents.pop(agent_id, None)
            self.agent_action_types.pop(agent_id, "")
            self.agent_targets.pop(agent_id, {})
            self._clear_active_agent_tracking(agent_id)
            if isinstance(result, BaseException):
                workflow.logger.warning(
                    "Agent %s failed during harvest: %s",
                    agent_id, str(result)[:500],
                )
                self.completed_agents.append(agent_id)
            else:
                self._record_agent_result(agent_id, result, config)

    def _record_agent_result(
        self,
        agent_id: str,
        result: dict[str, Any],
        config: GreyBoxConfig,
    ) -> None:
        """Record agent result, update cost tracking, collect findings."""
        self.completed_agents.append(agent_id)
        self.agent_metrics[agent_id] = result

        # E15: Track per-agent cost
        cost = result.get("cost_usd", 0.0)
        self.agent_costs[agent_id] = cost
        self.total_cost += cost

        if cost > config.per_agent_cost_ceiling:
            workflow.logger.warning(
                "Agent %s exceeded per-agent cost ceiling: $%.2f > $%.2f",
                agent_id, cost, config.per_agent_cost_ceiling,
            )

        # Collect any findings from agent result
        agent_findings = result.get("findings", [])
        if agent_findings:
            self.findings.extend(agent_findings)
            self.new_findings_signal = True

    # -------------------------------------------------------------------
    # Phase 3: Chain Exploitation
    # -------------------------------------------------------------------

    async def phase_3_chain_exploitation(
        self,
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
    ) -> None:
        """Phase 3: Chain exploitation of linked findings."""
        workflow.logger.info("Phase 3: Chain Exploitation")

        if len(self.findings) < 2:
            workflow.logger.info(
                "Fewer than 2 findings, skipping chain exploitation"
            )
            return

        # Use ChainDetector to find candidates
        detector = ChainDetector()
        candidates = detector.compute_candidates(self.findings)
        matched = detector.match_known_patterns(candidates)

        if not candidates and not matched:
            workflow.logger.info("No chain candidates found, skipping")
            return

        # Acquire session for chain exploit agent
        session = self._acquire_session()
        if session is None:
            workflow.logger.warning("No session for chain exploitation")
            return

        agent_id = f"chain-exploit-{str(workflow.uuid4())[:8]}"  # E1.1
        try:
            chain_result = await workflow.execute_child_workflow(
                AgentExecutionWorkflow.run,
                self._build_child_input(
                    agent_id=agent_id,
                    agent_type="chain-exploit",
                    action_type="CHAIN_EXPLOIT",
                    session=session,
                    base_input=base_input,
                    config=config,
                    target={
                        "finding_ids": sorted({
                            candidate.get("from_finding_id")
                            or candidate.get("grants_finding_id")
                            for candidate in candidates
                            if (
                                candidate.get("from_finding_id")
                                or candidate.get("grants_finding_id")
                            )
                        } | {
                            candidate.get("to_finding_id")
                            or candidate.get("requires_finding_id")
                            for candidate in candidates
                            if (
                                candidate.get("to_finding_id")
                                or candidate.get("requires_finding_id")
                            )
                        }),
                        "candidates": candidates,
                        "matched_patterns": matched,
                        "chain_context": detector.build_chain_context(matched),
                    },
                ),
                id=agent_id,
                retry_policy=AGENT_RETRY,
            )
            self._record_agent_result(agent_id, chain_result, config)
        finally:
            self._release_session(session)

    # -------------------------------------------------------------------
    # Phase 4: Report + Graph Export
    # -------------------------------------------------------------------

    async def phase_4_report(
        self,
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
    ) -> None:
        """Phase 4: Generate final report and export graph."""
        workflow.logger.info("Phase 4: Report + Graph Export")

        # Run report agent
        session = self._acquire_session()
        if session is None:
            workflow.logger.warning("No session for report agent")
            return

        agent_id = f"report-{str(workflow.uuid4())[:8]}"  # E1.1
        try:
            report_result = await workflow.execute_child_workflow(
                AgentExecutionWorkflow.run,
                self._build_child_input(
                    agent_id=agent_id,
                    agent_type="report",
                    action_type="REPORT",
                    session=session,
                    base_input=base_input,
                    config=config,
                    target={"findings": self.findings},
                ),
                id=agent_id,
                retry_policy=AGENT_RETRY,
            )
            self._record_agent_result(agent_id, report_result, config)
        finally:
            self._release_session(session)

        # Export graph
        try:
            await workflow.execute_activity(
                export_graph,
                ExportGraphInput(
                    session_id=base_input.session_id,
                    output_path=base_input.output_path,
                ),
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=PREFLIGHT_RETRY,
            )
        except Exception as exc:
            workflow.logger.warning("Graph export failed (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# AgentExecutionWorkflow — child workflow for agent isolation
# ---------------------------------------------------------------------------


@workflow.defn
class AgentExecutionWorkflow:
    """Child workflow for isolated agent execution.

    Handles prompt building, agent invocation, and credential signal
    forwarding via check_credential_signals activity (E2).
    """

    @workflow.run
    async def run(self, input: ChildWorkflowInput) -> dict[str, Any]:
        """Execute a single agent in isolation."""
        agent_id = input.agent_id
        agent_type = input.agent_type
        action_type = input.action_type
        session = input.session

        # E1.3: Access parent workflow id from input field (not workflow.info().parent_workflow_id)
        parent_id = input.parent_workflow_id

        workflow.logger.info(
            "AgentExecution started: %s (%s) session=%s parent=%s",
            agent_id, action_type, session, parent_id,
        )

        # Resolve model tier — concrete model_override bypasses tier lookup
        if input.model_override:
            model_tier = input.model_override
        else:
            model_tier = AGENT_MODEL_TIERS.get(action_type, input.specialist_model)

        # Resolve prompt template
        prompt_template = AGENT_PROMPT_TEMPLATES.get(agent_type, f"greybox/{agent_type}")

        # Resolve dynamic context: graph summary/slice, identities, dispatch vars
        ctx = await workflow.execute_activity(
            resolve_agent_context,
            ResolveContextInput(
                session_id=input.session_id,
                credentials_path=input.credentials_path,
                web_url=input.web_url,
                target=json.dumps(input.target) if input.target else "{}",
                budget_remaining_pct=input.budget_remaining_pct,
                auth_session_dir=input.auth_session_dir,
            ),
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )

        # Build prompt via activity
        prompt_result = await workflow.execute_activity(
            build_agent_prompt,
            BuildPromptInput(
                web_url=input.web_url,
                session_id=input.session_id,
                agent_name=agent_id,
                prompt_template=prompt_template,
                description=input.description,
                rules_avoid=input.rules_avoid,
                rules_focus=input.rules_focus,
                playwright_session=session,
                output_path=input.output_path or "",
                assigned_targets=ctx.get("assigned_targets", ""),
                graph_slice=ctx.get("graph_slice", ""),
                graph_summary=ctx.get("graph_summary", ""),
                endpoint_context=ctx.get("endpoint_context", ""),
                identities=ctx.get("identities", ""),
                identities_block=ctx.get("identities_block", ""),
                identity_count=ctx.get("identity_count", ""),
                budget_status=ctx.get("budget_status", ""),
                chain_candidates=ctx.get("chain_candidates", ""),
                login_instructions=ctx.get("login_instructions", ""),
                dispatch_mode=ctx.get("dispatch_mode", ""),
                vuln_type=ctx.get("vuln_type", ""),
                param_ids=ctx.get("param_ids", ""),
                lead_id=ctx.get("lead_id", ""),
                lead_signal=ctx.get("lead_signal", ""),
                lead_hypothesis=ctx.get("lead_hypothesis", ""),
                evidence_blob_path=ctx.get("evidence_blob_path", ""),
                identity=ctx.get("identity", ""),
                auth_session_dir=ctx.get("auth_session_dir", ""),
            ),
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )

        prompt = (
            prompt_result
            if isinstance(prompt_result, str)
            else prompt_result.get("prompt", "")
        )

        # E2: Check credential signals via activity (not filesystem I/O)
        signals_dir = f"{input.output_path}/deliverables/.signals" if input.output_path else ""
        cred_signals = await workflow.execute_activity(
            check_credential_signals,
            CheckSignalsInput(
                session_id=input.session_id,
                signals_dir=signals_dir,
            ),
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )

        # Prepare session if credential signals were found
        if isinstance(cred_signals, list) and cred_signals:
            await workflow.execute_activity(
                prepare_session,
                PrepareSessionInput(
                    web_url=input.web_url,
                    session_id=input.session_id,
                    credentials_path=input.credentials_path,
                    identity_name="admin",  # default identity for rotation
                    playwright_session=session,
                ),
                start_to_close_timeout=_AGENT_START_TO_CLOSE,
                retry_policy=PREFLIGHT_RETRY,
            )

        # Execute the agent — cwd is the session workspace so relative paths
        # (deliverables/*, .vigilo/*) resolve inside the mounted volume.
        workspace_cwd = (
            input.output_path
            if input.output_path and input.output_path.startswith("/")
            else f"/app/{input.output_path}"
            if input.output_path
            else "/app"
        )
        result = await workflow.execute_activity(
            run_greybox_agent,
            AgentExecutionInput(
                web_url=input.web_url,
                session_id=input.session_id,
                agent_name=agent_id,
                prompt=prompt,
                model_tier=model_tier if isinstance(model_tier, str) else "medium",
                cwd=workspace_cwd,
                output_path=input.output_path or "",
            ),
            start_to_close_timeout=_AGENT_START_TO_CLOSE,
            heartbeat_timeout=_AGENT_HEARTBEAT,
            retry_policy=AGENT_RETRY,
            activity_id=f"agent:{agent_id}",
        )

        workflow.logger.info(
            "AgentExecution completed: %s cost=$%.2f",
            agent_id,
            result.get("cost_usd", 0.0) if isinstance(result, dict) else 0.0,
        )

        # Run bookkeeping before return — ensures graph updates happen
        # even if the return value later fails Temporal serialization.
        if action_type in ("INVESTIGATE_LEAD", "PROBE_PARAMETERS"):
            had_findings = bool(
                isinstance(result, dict) and result.get("findings")
            )
            try:
                await workflow.execute_activity(
                    post_agent_bookkeeping,
                    PostAgentBookkeepingInput(
                        session_id=input.session_id,
                        action_type=action_type,
                        target=input.target,
                        had_findings=had_findings,
                        lead_max_attempts=input.lead_max_attempts,
                    ),
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=PREFLIGHT_RETRY,
                )
            except Exception as exc:
                workflow.logger.warning(
                    "Child bookkeeping failed for %s: %s",
                    action_type, str(exc)[:200],
                )

        # Signal parent with findings if any
        if isinstance(result, dict) and result.get("findings") and parent_id:
            try:
                parent_handle = workflow.get_external_workflow_handle(parent_id)
                await parent_handle.signal(
                    GreyBoxPipelineWorkflow.signal_new_findings,
                    result["findings"],
                )
            except Exception as exc:
                workflow.logger.warning(
                    "Failed to signal parent with findings: %s", exc
                )

        return result if isinstance(result, dict) else {"result": str(result)}
