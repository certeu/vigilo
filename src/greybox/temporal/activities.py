"""Temporal activities for the grey-box penetration testing pipeline.

Each activity wraps service calls with Temporal-specific concerns:
- Heartbeat loop (2s interval) to signal worker liveness
- Error classification into ApplicationError (retryable vs non-retryable)
- Environment isolation (E9: no os.environ mutation)

Business logic is delegated to services in src/greybox/services/ and src/services/.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiofiles
from temporalio import activity
from temporalio.exceptions import ApplicationError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEARTBEAT_INTERVAL_S = 2

MAX_ERROR_MESSAGE_LENGTH = 2000

NON_RETRYABLE_ERRORS = [
    "AuthenticationError",
    "BudgetExhaustedError",
    "ConfigurationError",
    "ExecutionLimitError",
    "InvalidRequestError",
    "InvalidTargetError",
    "PermissionError",
    "PromptSubstitutionError",
    "RequestTooLargeError",
    "ScannerNotFoundError",
    "SchemaVersionMismatchError",
]


def _surreal_env() -> tuple[str, str, str]:
    return (
        os.environ.get("SURREALDB_URL", "ws://surrealdb:8000"),
        os.environ.get("SURREALDB_USER", "root"),
        os.environ.get("SURREALDB_PASS", "changeme"),
    )


# ---------------------------------------------------------------------------
# Activity input dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GreyBoxActivityInput:
    """Base input shared by all grey-box activities."""

    web_url: str
    session_id: str
    credentials_path: str
    config_path: str | None = None
    output_path: str | None = None
    description: str = ""
    rules_avoid: list[str] = field(default_factory=list)
    rules_focus: list[str] = field(default_factory=list)


@dataclass
class InitWorkspaceInput:
    """Input for init_workspace activity."""

    web_url: str
    session_id: str
    output_path: str | None = None


@dataclass
class InitGraphInput:
    """Input for init_graph activity."""

    session_id: str
    credentials_path: str
    web_url: str


@dataclass
class PrepareSessionInput:
    """Input for prepare_session (Playwright auth) activity."""

    web_url: str
    session_id: str
    credentials_path: str
    identity_name: str
    playwright_session: str


@dataclass
class ScheduleTickInput:
    """Input for schedule_tick_activity."""

    session_id: str
    workspace: str
    active_claims: list[str]
    tick_number: int
    budget_remaining_pct: float = 1.0
    previous_graph_counts: dict[str, int] | None = None
    previous_verdict_counts: dict[str, int] | None = None
    ticks_since_last_progress: int = 0
    consecutive_waiting_ticks: int = 0
    idle_ticks_before_done: int = 20
    per_type_cap: int = 3
    authz_per_tick_cap: int = 2
    chain_per_tick_cap: int = 1
    max_specialists_per_endpoint: int = 2
    budget_cheap_ceiling_pct: float = 0.10
    budget_cheap_floor_pct: float = 0.03
    max_inconclusive_retries: int = 2
    max_failed_retries: int = 3
    max_consecutive_waiting_ticks: int = 10


@dataclass
class ScheduleTickOutput:
    """Result returned by schedule_tick_activity."""

    verbs: list[dict[str, Any]] = field(default_factory=list)
    graph_counts: dict[str, int] = field(default_factory=dict)
    verdict_counts: dict[str, int] = field(default_factory=dict)
    ticks_since_last_progress: int = 0
    consecutive_waiting_ticks: int = 0
    budget_mode: str = "normal"


@dataclass
class PostAgentBookkeepingInput:
    """Input for post_agent_bookkeeping activity."""

    session_id: str
    action_type: str
    target: dict[str, Any] = field(default_factory=dict)
    had_findings: bool = False
    lead_max_attempts: int = 3


@dataclass
class BuildPromptInput:
    """Input for build_agent_prompt activity."""

    web_url: str
    session_id: str
    agent_name: str
    prompt_template: str
    assigned_targets: str = ""
    graph_slice: str = ""
    graph_summary: str = ""
    endpoint_context: str = ""
    identities: str = ""
    identities_block: str = ""
    identity_count: str = ""
    recent_signals: str = ""
    active_agents: str = ""
    budget_status: str = ""
    chain_candidates: str = ""
    login_instructions: str = ""
    description: str = ""
    rules_avoid: str = ""
    rules_focus: str = ""
    playwright_session: str = "agent1"
    output_path: str = ""
    dispatch_mode: str = ""
    vuln_type: str = ""
    param_ids: str = ""
    lead_id: str = ""
    lead_signal: str = ""
    lead_hypothesis: str = ""
    evidence_blob_path: str = ""
    identity: str = ""
    auth_session_dir: str = ""


@dataclass
class AgentExecutionInput:
    """Input for run_greybox_agent activity."""

    web_url: str
    session_id: str
    agent_name: str
    prompt: str
    model_tier: str = "medium"
    cwd: str = "/app"
    output_path: str = ""


@dataclass
class ManagedScanInput:
    """Input for managed scan activities."""

    web_url: str
    session_id: str
    scan_type: str
    output_dir: str = ""
    # Auth context. When set, the scanner runs against the target with the
    # captured cookies. Empty string = unauthenticated scan (the legacy path).
    identity_name: str = ""
    session_file: str = ""


@dataclass
class ManagedScanResult:
    """Result from a managed scan activity."""

    scan_type: str
    success: bool
    output_file: str = ""
    error: str = ""
    duration_ms: int = 0
    nodes_added: int = 0


@dataclass
class ExportGraphInput:
    """Input for export_graph activity."""

    session_id: str
    output_path: str
    format: str = "yaml"
    max_tokens: int = 15000


@dataclass
class CheckSignalsInput:
    """Input for check_credential_signals activity (E2)."""

    session_id: str
    signals_dir: str


@dataclass
class ResolveContextInput:
    """Input for resolve_agent_context activity."""

    session_id: str
    credentials_path: str
    web_url: str
    target: str = "{}"
    budget_remaining_pct: float = 1.0
    auth_session_dir: str = ""


@dataclass
class AuditEventInput:
    """Input for write_audit_event activity."""

    workspace: str
    event_type: str
    phase: str = ""
    agent_name: str = ""
    status: str = ""
    total_duration_ms: int = 0
    error: str = ""
    total_cost: float = 0.0
    findings_count: int = 0
    agents_completed: int = 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _heartbeat_loop(agent_name: str, start_time: float) -> None:
    """Send heartbeat to Temporal every 2 seconds."""
    while True:
        elapsed = int(time.time() - start_time)
        activity.heartbeat({"agent": agent_name, "elapsed_seconds": elapsed})
        await asyncio.sleep(HEARTBEAT_INTERVAL_S)


def _truncate(message: str, max_length: int = MAX_ERROR_MESSAGE_LENGTH) -> str:
    """Truncate a string to prevent Temporal serialization overflow."""
    if len(message) <= max_length:
        return message
    return f"{message[:max_length - 20]}\n[truncated]"


def _classify_and_raise(
    error: Exception,
    agent_name: str,
    start_time: float,
) -> None:
    """Classify an exception and re-raise as a Temporal ApplicationError."""
    if isinstance(error, ApplicationError):
        raise error

    error_type = type(error).__name__
    is_non_retryable = error_type in NON_RETRYABLE_ERRORS
    elapsed = int((time.time() - start_time) * 1000)
    message = _truncate(str(error))

    raise ApplicationError(
        message,
        {"agent": agent_name, "elapsed_ms": elapsed},
        type=error_type,
        non_retryable=is_non_retryable,
    )


def _render_endpoint_context(view: Any) -> str:
    """Render an :class:`EndpointContextView` as a human-readable block.

    Produces four lines per endpoint: siblings, prior test attempts,
    findings, and access observations. Each sub-list falls back to a
    brief ``none observed`` marker when empty so the prompt never
    contains a dangling placeholder.
    """
    lines: list[str] = [f"Endpoint: {view.endpoint_id}"]

    if view.siblings:
        sibling_parts = [
            f"{s.name or s.id} (shape={s.shape})" for s in view.siblings
        ]
        lines.append(
            f"  Siblings ({len(view.siblings)}): " + ", ".join(sibling_parts)
        )
    else:
        lines.append("  Siblings (0): none observed")

    if view.test_attempts:
        attempt_parts = [
            f"[{a.agent or 'unknown'}] {a.vuln_type}->{a.verdict}"
            for a in view.test_attempts
        ]
        lines.append(
            f"  Prior test attempts ({len(view.test_attempts)}): "
            + ", ".join(attempt_parts)
        )
    else:
        lines.append("  Prior test attempts (0): none observed")

    if view.findings:
        finding_parts = [
            f"{f.id} ({f.vuln_type}, {f.severity}): \"{f.title}\""
            for f in view.findings
        ]
        lines.append(
            f"  Findings on this endpoint ({len(view.findings)}): "
            + ", ".join(finding_parts)
        )
    else:
        lines.append("  Findings on this endpoint (0): none observed")

    if view.access_observations:
        obs_parts = [
            f"{obs.identity_id}={obs.kind}" for obs in view.access_observations
        ]
        lines.append("  Access observations: " + ", ".join(obs_parts))
    else:
        lines.append("  Access observations: none recorded")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------


@activity.defn
async def init_workspace(input: InitWorkspaceInput) -> dict[str, Any]:
    """Initialize workspace directories for a grey-box scan session.

    Creates the output directory structure:
      .vigilo/{session_id}/deliverables/
      .vigilo/{session_id}/deliverables/screenshots/
      .vigilo/{session_id}/deliverables/.signals/
    """
    start_time = time.time()

    try:
        base = Path(input.output_path) if input.output_path else Path(f".vigilo/{input.session_id}")
        deliverables = base / "deliverables"
        deliverables.mkdir(parents=True, exist_ok=True)
        (deliverables / "screenshots").mkdir(exist_ok=True)
        (deliverables / ".signals").mkdir(exist_ok=True)
        (deliverables / "agents").mkdir(exist_ok=True)
        (deliverables / "prompts").mkdir(exist_ok=True)

        # Initialize audit trail
        from src.greybox.services.audit_integration import (
            init_session_json,
            log_workflow_header,
        )

        workspace = str(base)
        await log_workflow_header(workspace, input.session_id, input.web_url, [])
        await init_session_json(workspace, input.session_id, input.web_url, [])

        logger.info("Workspace initialized at %s", base)
        return {
            "workspace_path": workspace,
            "deliverables_path": str(deliverables),
            "session_id": input.session_id,
        }
    except Exception as e:
        _classify_and_raise(e, "init_workspace", start_time)
        raise  # pragma: no cover


@activity.defn
async def init_graph(input: InitGraphInput) -> dict[str, Any]:
    """Initialize the SurrealDB knowledge graph with schema and seed data.

    Creates tables, indexes, and seeds identity nodes from the credentials file.
    """
    start_time = time.time()
    heartbeat_task = asyncio.create_task(_heartbeat_loop("init_graph", start_time))

    try:
        from src.greybox.graph.client import GraphClient
        from src.greybox.graph.init_schema import ensure_schema
        from src.greybox.graph.schema import IdentityNode
        from src.greybox.services.credentials import load_identities

        url, user, password = _surreal_env()

        async with GraphClient(url, input.session_id, user, password) as client:
            await ensure_schema(client)

            identities = load_identities(Path(input.credentials_path))
            for ident in identities:
                node = IdentityNode(
                    role=ident.role,
                    privilege_level=ident.privilege_level,
                    auth_method="session_cookie",
                    credential_ref=f"config:{ident.name}",
                    discovered_by="preflight",
                )
                await client.create_node("identity", ident.name, node)

            logger.info(
                "Graph initialized with %d identities", len(identities)
            )
            return {
                "identities_seeded": len(identities),
                "session_id": input.session_id,
            }
    except Exception as e:
        _classify_and_raise(e, "init_graph", start_time)
        raise  # pragma: no cover
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


@activity.defn
async def authenticate_sessions(input: GreyBoxActivityInput) -> dict[str, Any]:
    """Authenticate all identities and capture HTTP sessions.

    Two things happen here:

    1. Build human-readable login instructions for each identity (still used
       by Playwright-driven LLM agents via ``{{LOGIN_INSTRUCTIONS}}``).
    2. Perform a real HTTP form login per identity and persist the cookies
       to ``{output_path}/sessions/{identity}.json`` so the managed scanners
       can run authenticated. Identities without a ``login`` block (e.g.
       ``anonymous``) are skipped; identities whose login fails are logged
       and excluded from ``cookie_paths`` — scans then fall back to
       unauthenticated mode for that identity.

    Returns a dict with:
        session_map: identity -> playwright session name (legacy)
        login_blocks: identity -> human-readable login instructions
        cookie_paths: identity -> absolute path to a captured-session JSON
        identity_count: int
    """
    start_time = time.time()
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop("authenticate_sessions", start_time)
    )

    try:
        from src.greybox.services.auth_session import capture_all_sessions
        from src.greybox.services.credentials import (
            build_login_block,
            load_identities,
        )

        identities = load_identities(Path(input.credentials_path))
        session_map: dict[str, str] = {}
        login_blocks: dict[str, str] = {}

        for i, ident in enumerate(identities, start=1):
            session_name = f"agent{i}"
            session_map[ident.name] = session_name
            login_blocks[ident.name] = build_login_block(ident, input.web_url)

        cookie_paths: dict[str, str] = {}
        if input.output_path:
            sessions_dir = Path(input.output_path) / "sessions"
            cookie_paths = await capture_all_sessions(
                identities, input.web_url, sessions_dir,
            )
        else:
            logger.warning(
                "authenticate_sessions: no output_path; skipping cookie capture. "
                "Managed scans will run unauthenticated.",
            )

        logger.info(
            "Prepared %d identity sessions (%d with captured cookies)",
            len(session_map), len(cookie_paths),
        )
        return {
            "session_map": session_map,
            "login_blocks": login_blocks,
            "cookie_paths": cookie_paths,
            "identity_count": len(identities),
        }
    except Exception as e:
        _classify_and_raise(e, "authenticate_sessions", start_time)
        raise  # pragma: no cover
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


@activity.defn
async def prepare_session(input: PrepareSessionInput) -> dict[str, Any]:
    """Prepare a Playwright browser session for a specific identity.

    Builds login instructions and returns session metadata.
    """
    start_time = time.time()

    try:
        from src.greybox.services.credentials import (
            build_login_block,
            load_identities,
        )

        identities = load_identities(Path(input.credentials_path))
        target_identity = None
        for ident in identities:
            if ident.name == input.identity_name:
                target_identity = ident
                break

        if target_identity is None:
            raise ApplicationError(
                f"Identity not found: {input.identity_name}",
                type="ConfigurationError",
                non_retryable=True,
            )

        login_block = build_login_block(target_identity, input.web_url)

        return {
            "identity": input.identity_name,
            "playwright_session": input.playwright_session,
            "login_instructions": login_block,
            "role": target_identity.role,
            "privilege_level": target_identity.privilege_level,
        }
    except ApplicationError:
        raise
    except Exception as e:
        _classify_and_raise(e, "prepare_session", start_time)
        raise  # pragma: no cover


@activity.defn
async def build_agent_prompt(input: BuildPromptInput) -> str:
    """Build a fully interpolated prompt for a grey-box agent.

    Loads the prompt template, processes @include() directives,
    and substitutes all grey-box variables.
    """
    start_time = time.time()

    try:
        from src.services.prompt_manager import (
            PROMPTS_DIR,
            _interpolate_greybox_variables,
            _process_includes,
            _read_file,
        )

        prompt_path = PROMPTS_DIR / f"{input.prompt_template}.txt"
        if not prompt_path.is_file():
            raise ApplicationError(
                f"Prompt template not found: {prompt_path}",
                type="ConfigurationError",
                non_retryable=True,
            )

        template = await _read_file(prompt_path)
        template = await _process_includes(template, PROMPTS_DIR)

        result = _interpolate_greybox_variables(
            template,
            web_url=input.web_url,
            assigned_targets=input.assigned_targets,
            graph_slice=input.graph_slice,
            graph_summary=input.graph_summary,
            endpoint_context=input.endpoint_context,
            identities=input.identities,
            identities_block=input.identities_block,
            identity_count=input.identity_count,
            recent_signals=input.recent_signals,
            active_agents=input.active_agents,
            budget_status=input.budget_status,
            chain_candidates=input.chain_candidates,
            login_instructions=input.login_instructions,
            description=input.description,
            rules_avoid=input.rules_avoid,
            rules_focus=input.rules_focus,
            playwright_session=input.playwright_session,
            dispatch_mode=input.dispatch_mode,
            vuln_type=input.vuln_type,
            param_ids=input.param_ids,
            lead_id=input.lead_id,
            lead_signal=input.lead_signal,
            lead_hypothesis=input.lead_hypothesis,
            evidence_blob_path=input.evidence_blob_path,
            identity=input.identity,
            auth_session_dir=input.auth_session_dir,
        )

        logger.info(
            "Built prompt for %s (%d chars)", input.agent_name, len(result)
        )

        # Save rendered prompt to deliverables
        if input.output_path:
            try:
                from src.greybox.services.audit_integration import (
                    save_agent_prompt,
                )

                await save_agent_prompt(input.output_path, input.agent_name, result)
            except Exception as exc:
                logger.warning("Failed to save prompt for %s: %s", input.agent_name, exc)

        return result

    except ApplicationError:
        raise
    except Exception as e:
        _classify_and_raise(e, f"build_prompt:{input.agent_name}", start_time)
        raise  # pragma: no cover


@activity.defn
async def schedule_tick_activity(input: ScheduleTickInput) -> ScheduleTickOutput:
    """Run one scheduler tick and return verbs + progress counters."""
    from src.greybox.graph.client import GraphClient
    from src.greybox.scheduler.core import schedule
    from src.greybox.scheduler.rules import SchedulerConfig

    url, user, password = _surreal_env()

    workspace_path = Path(input.workspace) if input.workspace else None
    tick_log_dir = (workspace_path / "deliverables" / "scheduler") if workspace_path else None
    config = SchedulerConfig(
        tick_log_dir=tick_log_dir,
        idle_ticks_before_done=input.idle_ticks_before_done,
        per_type_cap=input.per_type_cap,
        authz_per_tick_cap=input.authz_per_tick_cap,
        chain_per_tick_cap=input.chain_per_tick_cap,
        max_specialists_per_endpoint=input.max_specialists_per_endpoint,
        budget_cheap_ceiling_pct=input.budget_cheap_ceiling_pct,
        budget_cheap_floor_pct=input.budget_cheap_floor_pct,
        max_inconclusive_retries=input.max_inconclusive_retries,
        max_failed_retries=input.max_failed_retries,
        max_consecutive_waiting_ticks=input.max_consecutive_waiting_ticks,
    )

    async with GraphClient(url, input.session_id, user, password) as client:
        result = await schedule(
            client,
            config,
            input.active_claims,
            budget_remaining_pct=input.budget_remaining_pct,
            tick_number=input.tick_number,
            previous_graph_counts=input.previous_graph_counts,
            previous_verdict_counts=input.previous_verdict_counts,
            ticks_since_last_progress=input.ticks_since_last_progress,
            consecutive_waiting_ticks=input.consecutive_waiting_ticks,
        )
    return ScheduleTickOutput(
        verbs=[v.model_dump() for v in result.verbs],
        graph_counts=result.graph_counts,
        verdict_counts=result.verdict_counts,
        ticks_since_last_progress=result.ticks_since_last_progress,
        consecutive_waiting_ticks=result.consecutive_waiting_ticks,
        budget_mode=result.budget_mode,
    )


@activity.defn
async def post_agent_bookkeeping(input: PostAgentBookkeepingInput) -> None:
    """Update the graph after an agent completes.

    For INVESTIGATE_LEAD: increment investigation_attempts, promote or dismiss.
    For PROBE_PARAMETERS: bulk-create test_attempt records for all params in batch.
    """
    from src.greybox.graph.client import GraphClient

    url, user, password = _surreal_env()

    async with GraphClient(url, input.session_id, user, password) as client:
        if input.action_type == "INVESTIGATE_LEAD":
            lead_id = input.target.get("lead_id", "")
            if not lead_id:
                return
            lead = await client.get_node(lead_id)
            if lead is None:
                return
            attempts = int(lead.get("investigation_attempts", 0)) + 1
            updates: dict[str, Any] = {"investigation_attempts": attempts}
            if input.had_findings:
                updates["status"] = "promoted"
            elif attempts >= input.lead_max_attempts:
                updates["status"] = "dismissed"
            await client.update_node(lead_id, updates)
            logger.info(
                "Bookkeeping %s: attempts=%d status=%s",
                lead_id, attempts, updates.get("status", "open"),
            )

        elif input.action_type == "PROBE_PARAMETERS":
            from surrealdb import RecordID
            vuln_type = input.target.get("vuln_type", "")
            param_ids = input.target.get("param_ids", [])
            if not vuln_type or not param_ids:
                return
            param_record_ids = [
                RecordID(*pid.split(":", 1)) if isinstance(pid, str) and ":" in pid else pid
                for pid in param_ids
            ]
            existing = await client.raw_query(
                "SELECT <-tested_against<-test_attempt[WHERE vuln_type = $vuln].id AS ta_ids, id "
                "FROM parameter WHERE id IN $ids",
                {"vuln": vuln_type, "ids": param_record_ids},
            )
            already_tested = set()
            for row in existing:
                if row.get("ta_ids"):
                    already_tested.add(str(row.get("id", "")))
            missing = [pid for pid in param_ids if pid not in already_tested]
            if not missing:
                return
            import uuid as _uuid
            for pid in missing:
                suffix = f"ta_{_uuid.uuid4().hex[:12]}"
                ta_id = f"test_attempt:{suffix}"
                await client.raw_query(
                    "CREATE $ta_id SET vuln_type = $vuln, technique = 'batch_sweep', "
                    "payload = 'workflow_bookkeeping', "
                    "payload_hash = 'sha256:workflow_bookkeeping', "
                    "verdict = 'failed', "
                    "failure_reason = 'agent_produced_no_test_attempt', "
                    "response_code = 0, duration_ms = 0, "
                    "agent = 'workflow_bookkeeping', "
                    "attempted_at = time::now()",
                    {"ta_id": RecordID("test_attempt", suffix), "vuln": vuln_type},
                )
                await client.create_edge("tested_against", ta_id, pid)
            logger.info(
                "Bookkeeping PROBE_PARAMETERS: marked %d/%d params tested for %s",
                len(missing), len(param_ids), vuln_type,
            )


def _sanitize_for_json(data: list[dict[str, Any]] | dict[str, Any]) -> list[dict[str, Any]] | dict[str, Any]:
    """Convert non-JSON-serializable SurrealDB types (RecordID, datetime) to primitives."""
    return json.loads(json.dumps(data, default=str))


@activity.defn
async def run_greybox_agent(input: AgentExecutionInput) -> dict[str, Any]:
    """Execute a grey-box specialist agent.

    Runs Claude with the fully built prompt. Uses env_copy (E9)
    to pass agent-specific env vars without mutating os.environ.
    """
    start_time = time.time()
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(input.agent_name, start_time)
    )

    try:
        from src.ai.executor import execute
        from src.audit.agent_logger import AgentLogger

        extra_env = {
            "VIGILO_AGENT_NAME": input.agent_name,
            "SURREALDB_SESSION": input.session_id,
        }

        try:
            attempt = activity.info().attempt
        except Exception:
            attempt = 1

        # White-box-compatible per-agent log: {workspace}/agents/{ts}_{agent}_attempt-{N}.log
        workspace = input.output_path or input.cwd
        agent_logger = AgentLogger(workspace)
        await agent_logger.start_agent_log(
            input.agent_name,
            attempt=attempt,
            session_id=input.session_id,
            web_url=input.web_url,
        )
        await agent_logger.save_prompt(
            input.agent_name,
            input.prompt,
            session_id=input.session_id,
            web_url=input.web_url,
        )

        async def _on_stream(name: str, turn: int, content: str) -> None:
            try:
                await agent_logger.log_event(
                    name, "llm_response", {"turn": turn, "content": content}
                )
            except Exception:
                pass  # non-fatal

        result = await execute(
            prompt=input.prompt,
            agent_name=input.agent_name,
            model_tier=input.model_tier,
            cwd=input.cwd,
            extra_env=extra_env,
            on_stream=_on_stream,
        )

        if not result.success:
            raise ApplicationError(
                f"Agent {input.agent_name} failed: {result.error}",
                type="ExecutionError",
                non_retryable=True,
            )

        duration_ms = int((time.time() - start_time) * 1000)
        agent_result: dict[str, Any] = {
            "agent_name": input.agent_name,
            "duration_ms": duration_ms,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "cost_usd": result.cost_usd,
            "num_turns": result.num_turns,
            "model": result.model,
            "success": True,
        }

        # Query graph for findings created by this agent
        try:
            from src.greybox.graph.client import GraphClient

            url, user, password = _surreal_env()

            async with GraphClient(url, input.session_id, user, password) as client:
                findings = await client.query_nodes(
                    "finding",
                    filters={"discovered_by": input.agent_name},
                )
                if findings:
                    agent_result["findings"] = _sanitize_for_json(findings)
                    logger.info(
                        "Agent %s produced %d findings", input.agent_name, len(findings),
                    )
        except Exception as graph_exc:
            logger.warning(
                "Failed to query findings for %s: %s",
                input.agent_name, str(graph_exc)[:300],
            )

        # Write audit trail
        if input.output_path:
            try:
                from src.greybox.services.audit_integration import (
                    log_agent_complete,
                    save_agent_result,
                    update_session_agent,
                )

                findings_count = len(agent_result.get("findings", []))
                await log_agent_complete(
                    input.output_path,
                    input.agent_name,
                    duration_ms / 1000,
                    result.cost_usd,
                    findings_count,
                )
                await update_session_agent(
                    input.output_path,
                    input.agent_name,
                    duration_ms=duration_ms,
                    cost_usd=result.cost_usd,
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                    num_turns=result.num_turns,
                    model=result.model,
                    findings_count=findings_count,
                )
                await save_agent_result(input.output_path, input.agent_name, agent_result)
            except Exception as audit_exc:
                logger.warning("Audit write failed for %s: %s", input.agent_name, audit_exc)

        return agent_result

    except ApplicationError:
        raise
    except Exception as e:
        _classify_and_raise(e, input.agent_name, start_time)
        raise  # pragma: no cover
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


@activity.defn
async def run_managed_scan(input: ManagedScanInput) -> dict[str, Any]:
    """Run a deterministic managed security scan (no LLM).

    Imports the correct scanner wrapper, executes it, and writes
    discovered nodes/findings to the knowledge graph.
    """
    start_time = time.time()
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(f"managed:{input.scan_type}", start_time)
    )

    try:
        from src.greybox.managed import get_scanner
        from src.greybox.services.auth_session import cookie_header_from_session

        # Resolve auth context. Scanners that don't benefit from auth
        # (e.g. ssl_analysis) can be passed an identity but will silently
        # ignore the cookie header — see BaseScanner.is_authenticated.
        cookie_header = cookie_header_from_session(input.session_file or None)
        scanner_kwargs: dict[str, Any] = {}
        if cookie_header:
            scanner_kwargs["cookie_header"] = cookie_header
        if input.identity_name:
            scanner_kwargs["identity_name"] = input.identity_name

        scanner = get_scanner(input.scan_type, input.web_url, **scanner_kwargs)
        try:
            result = await scanner.run()
        except RuntimeError as exc:
            # Scanner binary not found — non-retryable
            raise ApplicationError(
                str(exc),
                type="ScannerNotFoundError",
                non_retryable=True,
            ) from exc

        duration_ms = int((time.time() - start_time) * 1000)

        nodes_added = 0
        # Write discovered data to the graph if SurrealDB is available
        try:
            from src.greybox.graph.client import GraphClient
            from src.greybox.graph.schema import (
                EndpointNode,
                FindingNode,
                LeadNode,
                TechnologyNode,
            )

            url, user, password = _surreal_env()

            # Tag every node with the identity used for the scan so the
            # graph distinguishes anonymous vs. admin-authenticated findings.
            discovered_by = f"managed:{input.scan_type}"
            if input.identity_name:
                discovered_by = f"{discovered_by}:{input.identity_name}"

            async with GraphClient(url, input.session_id, user, password) as client:
                for ep in result.new_endpoints:
                    node = EndpointNode(
                        method=ep.get("method", "GET"),
                        path=ep.get("path", "/"),
                        full_url=ep.get("url", f"{input.web_url}{ep.get('path', '/')}"),
                        status_codes_seen=[ep["status_code"]] if ep.get("status_code") else [],
                        discovered_by=discovered_by,
                    )
                    await client.create_node(
                        "endpoint", f"{node.method}_{node.path}", node,
                    )
                    nodes_added += 1

                for tech in result.technologies:
                    node = TechnologyNode(
                        name=tech.get("name", "unknown"),
                        version=tech.get("version"),
                        category=tech.get("category", "framework"),
                        confidence="confirmed" if tech.get("confidence", 0) > 0.8 else "detected",
                        discovered_by=discovered_by,
                    )
                    await client.create_node("technology", node.name, node)
                    nodes_added += 1

                for finding in result.findings:
                    raw_evidence = finding.get("evidence")
                    if isinstance(raw_evidence, (dict, list)):
                        evidence_ref = json.dumps(raw_evidence, default=str)
                    elif raw_evidence is None:
                        evidence_ref = None
                    else:
                        evidence_ref = str(raw_evidence)
                    node = FindingNode(
                        vuln_type=finding.get("vuln_type", input.scan_type),
                        severity=finding.get("severity", "info"),
                        status="potential",
                        title=finding.get("title", f"{input.scan_type} finding"),
                        impact=finding.get("description", finding.get("impact", "")),
                        evidence_ref=evidence_ref,
                        discovered_by=discovered_by,
                    )
                    await client.create_node(
                        "finding",
                        f"{input.scan_type}_{finding.get('id', nodes_added)}",
                        node,
                    )
                    nodes_added += 1

                for lead in result.leads:
                    node = LeadNode(
                        signal=lead.get("signal_type", lead.get("signal", "error_leak")),
                        hypothesis=lead.get("hypothesis", lead.get("description", "")),
                        signal_strength=lead.get("signal_strength", "medium"),
                        discovered_by=discovered_by,
                    )
                    await client.create_node(
                        "lead",
                        f"{input.scan_type}_{lead.get('id', nodes_added)}",
                        node,
                    )
                    nodes_added += 1

        except Exception as graph_exc:
            logger.warning(
                "Failed to write managed scan results to graph: %s",
                str(graph_exc)[:500],
            )

        logger.info(
            "Managed scan %s completed: %d items found, %d nodes added in %dms",
            input.scan_type, result.items_found, nodes_added, duration_ms,
        )

        # Write audit trail
        if input.output_dir:
            try:
                from src.greybox.services.audit_integration import (
                    log_managed_scan,
                    update_session_managed_scan,
                )

                await log_managed_scan(
                    input.output_dir, input.scan_type,
                    result.items_found, nodes_added, duration_ms,
                )
                await update_session_managed_scan(
                    input.output_dir, input.scan_type,
                    result.items_found, nodes_added, duration_ms,
                )
            except Exception as audit_exc:
                logger.warning("Audit write failed for scan %s: %s", input.scan_type, audit_exc)

        return {
            "scan_type": input.scan_type,
            "success": True,
            "items_found": result.items_found,
            "nodes_added": nodes_added,
            "duration_ms": duration_ms,
            "endpoints": len(result.new_endpoints),
            "findings": len(result.findings),
            "leads": len(result.leads),
            "technologies": len(result.technologies),
        }

    except Exception as e:
        _classify_and_raise(e, f"managed:{input.scan_type}", start_time)
        raise  # pragma: no cover
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


@activity.defn
async def resolve_agent_context(input: ResolveContextInput) -> dict[str, str]:
    """Resolve dynamic template variables for an agent prompt.

    Fetches graph summary, graph slice for assigned targets, identity list,
    login instructions, lead details (for lead-mode dispatch), and formats
    budget status. Returns a flat dict of string template variables.
    """
    start_time = time.time()

    try:
        from src.greybox.graph.client import GraphClient
        from src.greybox.graph.views import endpoint_full_context
        from src.greybox.services.credentials import (
            build_identities_block,
            build_login_block,
            load_identities,
        )

        target: dict[str, Any] = json.loads(input.target) if input.target else {}
        url, user, password = _surreal_env()

        # -- Graph summary (node counts) --
        graph_summary = ""
        graph_slice = ""
        endpoint_context = ""
        chain_candidates = ""
        async with GraphClient(url, input.session_id, user, password) as client:
            node_tables = [
                "page", "endpoint", "parameter", "technology",
                "finding", "lead", "test_attempt",
            ]
            counts = await asyncio.gather(
                *(client.raw_query(f"SELECT count() AS c FROM {t} GROUP ALL") for t in node_tables)
            )
            summary_parts = []
            for table, result in zip(node_tables, counts):
                c = int(result[0]["c"]) if result else 0
                if c > 0:
                    summary_parts.append(f"{table}: {c}")
            if summary_parts:
                graph_summary = "Node counts: " + ", ".join(summary_parts)

            # -- Graph slice: fetch data relevant to the assigned targets --
            mode = target.get("mode", "")
            param_ids = target.get("param_ids", [])
            lead_id = target.get("lead_id", "")

            if mode == "batch" and param_ids:
                rows = await client.raw_query(
                    """
                    SELECT
                        id, name, location, shape, data_type,
                        <-has_param<-endpoint.{id, method, path, full_url} AS endpoints
                    FROM parameter
                    WHERE id IN $ids
                    """,
                    {"ids": param_ids},
                )
                endpoint_ids_seen: list[str] = []
                if rows:
                    lines = []
                    for row in rows:
                        ep_list = row.get("endpoints") or []
                        ep_info = ep_list[0] if ep_list else {}
                        ep_id = str(ep_info.get("id") or "")
                        if ep_id and ep_id not in endpoint_ids_seen:
                            endpoint_ids_seen.append(ep_id)
                        lines.append(
                            f"- {row.get('id')}: name={row.get('name')}, "
                            f"shape={row.get('shape')}, location={row.get('location')}, "
                            f"endpoint={ep_info.get('method', '?')} {ep_info.get('path', '?')}"
                        )
                    graph_slice = "Assigned parameters:\n" + "\n".join(lines)

                # -- {{ENDPOINT_CONTEXT}}: cross-identity view per endpoint --
                # Pull the identity IDs from the graph so access observations
                # are resolved against the actual population of identities,
                # not whatever the caller happened to pass in the verb.
                identity_rows = await client.raw_query(
                    "SELECT id FROM identity"
                )
                graph_identity_ids = [
                    str(r.get("id")) for r in identity_rows if r.get("id")
                ]
                blocks: list[str] = []
                for ep_id in endpoint_ids_seen:
                    view = await endpoint_full_context(
                        client, ep_id, graph_identity_ids
                    )
                    blocks.append(_render_endpoint_context(view))
                if blocks:
                    endpoint_context = "\n\n".join(blocks)

            # Lead row is reused for both graph_slice and dispatch vars
            lead_signal = ""
            lead_hypothesis = ""
            evidence_blob_path = ""

            if mode == "lead" and lead_id:
                rows = await client.raw_query(
                    "SELECT * FROM type::thing($id)",
                    {"id": lead_id},
                )
                if rows:
                    row = rows[0]
                    lead_signal = str(row.get("signal") or "")
                    lead_hypothesis = str(row.get("hypothesis") or "")
                    evidence_blob_path = str(row.get("evidence_blob_path") or "")
                    graph_slice = (
                        f"Lead {lead_id}:\n"
                        f"  signal: {lead_signal}\n"
                        f"  hypothesis: {lead_hypothesis}\n"
                        f"  signal_strength: {row.get('signal_strength', '')}\n"
                        f"  evidence_blob: {evidence_blob_path}"
                    )

            elif target.get("finding_ids"):
                finding_ids = target["finding_ids"]
                rows = await client.raw_query(
                    "SELECT id, vuln_type, severity, title, grants, requires FROM finding WHERE id IN $ids",
                    {"ids": finding_ids},
                )
                if rows:
                    lines = [
                        f"- {r.get('id')}: {r.get('title')} "
                        f"(severity={r.get('severity')}, grants={r.get('grants')}, requires={r.get('requires')})"
                        for r in rows
                    ]
                    graph_slice = "Chain finding details:\n" + "\n".join(lines)
                parts: list[str] = []
                candidates = target.get("candidates", [])
                matched_patterns = target.get("matched_patterns", [])
                chain_context = str(target.get("chain_context") or "").strip()
                if candidates:
                    parts.append("Candidates:")
                    for candidate in candidates:
                        from_id = candidate.get("from_finding_id") or candidate.get("grants_finding_id") or "?"
                        to_id = candidate.get("to_finding_id") or candidate.get("requires_finding_id") or "?"
                        capabilities = candidate.get("shared_capabilities") or []
                        parts.append(
                            f"- {from_id} -> {to_id}"
                            + (f" via {capabilities}" if capabilities else "")
                        )
                if matched_patterns:
                    parts.append("Matched patterns:")
                    for match in matched_patterns:
                        name = match.get("pattern_name") or match.get("pattern") or "unknown"
                        parts.append(f"- {name}: {match.get('finding_ids') or []}")
                if chain_context:
                    parts.append(chain_context)
                chain_candidates = "\n".join(parts).strip()

            elif target.get("endpoint_ids"):
                endpoint_ids = target["endpoint_ids"]
                rows = await client.raw_query(
                    "SELECT id, method, path, full_url FROM endpoint WHERE id IN $ids",
                    {"ids": endpoint_ids},
                )
                if rows:
                    lines = [f"- {r.get('id')}: {r.get('method')} {r.get('path')}" for r in rows]
                    graph_slice = "Assigned endpoints:\n" + "\n".join(lines)

        # -- Identities + login instructions --
        identities_text = ""
        identities_block = "No authenticated identities configured."
        identity_count = "0"
        login_instructions = ""
        identity_name = target.get("identity", "")
        try:
            identities = load_identities(Path(input.credentials_path))
            id_lines = [
                f"- {i.name} (role: {i.role}, privilege: {i.privilege_level})"
                for i in identities
            ]
            identities_text = "\n".join(id_lines)
            identities_block = build_identities_block(identities, input.web_url)
            identity_count = str(len(identities))

            if identity_name:
                clean_name = identity_name.replace("identity:", "")
                for i in identities:
                    if i.name == clean_name:
                        login_instructions = build_login_block(i, input.web_url)
                        break
            if not login_instructions and identities:
                login_instructions = build_login_block(identities[0], input.web_url)
        except Exception as exc:
            logger.warning("Failed to load identities: %s", exc)

        # -- Budget status --
        pct = input.budget_remaining_pct
        if pct >= 0.75:
            budget_status = f"Budget: {pct:.0%} remaining — proceed normally."
        elif pct >= 0.25:
            budget_status = f"Budget: {pct:.0%} remaining — prioritize high-value targets."
        else:
            budget_status = f"Budget: {pct:.0%} remaining — CRITICAL: focus only on highest-severity work."

        # -- Assigned targets (human-readable) --
        assigned_targets = ""
        if mode == "batch":
            assigned_targets = (
                f"Mode: batch\n"
                f"Vuln type: {target.get('vuln_type', '')}\n"
                f"Parameters to test:\n"
                + "\n".join(f"- {pid}" for pid in param_ids)
            )
        elif mode == "lead":
            assigned_targets = (
                f"Mode: lead investigation\n"
                f"Lead: {lead_id}\n"
                f"Signal: {lead_signal}\n"
                f"Hypothesis: {lead_hypothesis}"
            )
        elif target.get("finding_ids"):
            assigned_targets = (
                "Chain exploitation\n"
                "Findings to chain:\n"
                + "\n".join(f"- {fid}" for fid in target["finding_ids"])
            )
        elif target.get("endpoint_ids"):
            assigned_targets = (
                "Access matrix testing\n"
                "Endpoints:\n"
                + "\n".join(f"- {eid}" for eid in target["endpoint_ids"])
                + "\nIdentities:\n"
                + "\n".join(f"- {i}" for i in target.get("identities", []))
            )
        elif target.get("target"):
            assigned_targets = f"Deep crawl target: {target['target']}"

        # -- Dispatch vars --
        # Batch/lead are mutually exclusive; whichever is inactive emits
        # an empty string so the prompt substitution renders a clean
        # blank instead of a literal placeholder.
        param_ids_text = "\n".join(f"- {pid}" for pid in param_ids)
        if mode == "batch":
            batch_params = param_ids_text
            lead_evidence = ""
        elif mode == "lead":
            batch_params = ""
            lead_evidence = (
                f"Lead: {lead_id}\n"
                f"Signal: {lead_signal}\n"
                f"Hypothesis: {lead_hypothesis}\n"
                f"Evidence blob: {evidence_blob_path}"
            )
        else:
            batch_params = ""
            lead_evidence = ""

        # Lead-mode scope: vuln_type / param_ids should be blank so
        # prompts see a clean lead context with no leftover batch data.
        if mode == "lead":
            batch_vuln_type = ""
            param_ids_rendered = ""
        else:
            batch_vuln_type = target.get("vuln_type", "")
            param_ids_rendered = param_ids_text

        result: dict[str, str] = {
            "graph_summary": graph_summary,
            "graph_slice": graph_slice,
            "endpoint_context": endpoint_context,
            "identities": identities_text,
            "identities_block": identities_block,
            "identity_count": identity_count,
            "login_instructions": login_instructions,
            "budget_status": budget_status,
            "chain_candidates": chain_candidates,
            "assigned_targets": assigned_targets,
            "dispatch_mode": mode,
            "vuln_type": batch_vuln_type,
            "param_ids": param_ids_rendered,
            "batch_params": batch_params,
            "lead_id": lead_id,
            "lead_signal": lead_signal,
            "lead_hypothesis": lead_hypothesis,
            "evidence_blob_path": evidence_blob_path,
            "lead_evidence": lead_evidence,
            "identity": identity_name,
            "auth_session_dir": input.auth_session_dir,
        }

        logger.info("Resolved agent context: %d vars", len(result))
        return result

    except Exception as e:
        _classify_and_raise(e, "resolve_agent_context", start_time)
        raise  # pragma: no cover


@activity.defn
async def export_graph(input: ExportGraphInput) -> dict[str, Any]:
    """Export the knowledge graph to a file for reporting.

    Dumps all graph tables to YAML or JSON format.
    """
    start_time = time.time()

    try:
        from src.greybox.graph.client import GraphClient

        url, user, password = _surreal_env()

        async with GraphClient(url, input.session_id, user, password) as client:
            node_tables = [
                "page", "endpoint", "parameter", "technology",
                "identity", "workflow", "component",
                "test_attempt", "finding", "lead",
            ]
            edge_tables = [
                "has_param", "has_endpoint", "belongs_to", "detected_on",
                "links_to", "has_step", "depends_on", "param_depends_on",
                "tested_against", "exploits", "observed_at", "promoted_to",
                "derived_from", "supersedes", "can_access", "denied_access",
                "chains_with", "reflects_in", "produced_from", "data_flows_to",
                "input_of",
            ]
            all_tables = node_tables + edge_tables
            results = await asyncio.gather(
                *(client.raw_query(f"SELECT * FROM {t}") for t in all_tables)
            )
            all_data: dict[str, list] = dict(zip(node_tables, results[:len(node_tables)]))
            edges = {
                t: rows for t, rows in zip(edge_tables, results[len(node_tables):])
                if rows
            }
            if edges:
                all_data["_edges"] = edges

        if input.format == "yaml":
            import yaml

            output = yaml.dump(all_data, default_flow_style=False)
        else:
            output = json.dumps(all_data, indent=2, default=str)

        if len(output) > input.max_tokens * 4:
            output = output[: input.max_tokens * 4]

        output_file = Path(input.output_path) / "deliverables" / f"graph_export.{input.format}"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        async with aiofiles.open(output_file, mode="w", encoding="utf-8") as f:
            await f.write(output)

        logger.info("Graph exported to %s (%d chars)", output_file, len(output))
        return {
            "output_file": str(output_file),
            "format": input.format,
            "size_chars": len(output),
            "tables": list(all_data.keys()),
        }

    except Exception as e:
        _classify_and_raise(e, "export_graph", start_time)
        raise  # pragma: no cover


@activity.defn
async def check_credential_signals(input: CheckSignalsInput) -> list[dict[str, Any]]:
    """Check for credential signals written by agents (E2).

    Scans deliverables/.signals/ for credentials_found signal files.
    This filesystem I/O MUST be in an activity, not the workflow.

    Returns a list of signal dicts, each containing:
        {"type": "credentials_found", "data": {...}}
    """
    start_time = time.time()

    try:
        signals_dir = Path(input.signals_dir)
        if not signals_dir.is_dir():
            return []

        signals: list[dict[str, Any]] = []
        for signal_file in sorted(signals_dir.glob("*.json")):
            try:
                async with aiofiles.open(
                    signal_file, mode="r", encoding="utf-8"
                ) as f:
                    content = await f.read()
                signal_data = json.loads(content)
                if signal_data.get("type") == "credentials_found":
                    signals.append(signal_data)
                    # Remove consumed signal
                    signal_file.unlink()
                    logger.info("Consumed credential signal: %s", signal_file.name)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning(
                    "Failed to read signal file %s: %s", signal_file, exc
                )

        if signals:
            logger.info("Found %d credential signals", len(signals))
        return signals

    except Exception as e:
        _classify_and_raise(e, "check_credential_signals", start_time)
        raise  # pragma: no cover


@activity.defn
async def write_audit_event(input: AuditEventInput) -> None:
    """Write an audit event to the workspace (workflow.log + session.json).

    This activity handles all audit I/O that the workflow cannot do directly
    (Temporal workflows must not do file I/O). Called at phase boundaries,
    agent spawn events, and pipeline completion.
    """
    from src.greybox.services.audit_integration import (
        finalize_session,
        log_agent_error,
        log_agent_start,
        log_phase_complete,
        log_phase_start,
        log_workflow_complete,
        update_session_phase,
        update_session_spawned,
    )

    try:
        if input.event_type == "phase_start":
            await log_phase_start(input.workspace, input.phase)

        elif input.event_type == "phase_complete":
            await log_phase_complete(input.workspace, input.phase)
            await update_session_phase(input.workspace, input.phase)

        elif input.event_type == "agent_start":
            await log_agent_start(input.workspace, input.agent_name)

        elif input.event_type == "agent_spawned":
            await update_session_spawned(input.workspace)

        elif input.event_type == "agent_error":
            await log_agent_error(input.workspace, input.agent_name, input.error)

        elif input.event_type == "finalize":
            await log_workflow_complete(
                input.workspace,
                status=input.status,
                total_cost=input.total_cost,
                total_duration_ms=input.total_duration_ms,
                findings_count=input.findings_count,
                agents_completed=input.agents_completed,
                error=input.error or None,
            )
            await finalize_session(
                input.workspace,
                status=input.status,
                total_duration_ms=input.total_duration_ms,
                error=input.error or None,
            )

    except Exception as exc:
        logger.warning("Audit event %s failed: %s", input.event_type, exc)
