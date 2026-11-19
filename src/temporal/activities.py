"""Temporal activities for pipeline.

Each activity wraps service calls with Temporal-specific concerns:
- Heartbeat loop (2s interval) to signal worker liveness
- Error classification into ApplicationError (retryable vs non-retryable)
- Audit session lifecycle management

Business logic is delegated to services in src/services/.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from temporalio import activity
from temporalio.exceptions import ApplicationError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEARTBEAT_INTERVAL_S = 2

# Max length to prevent Temporal protobuf buffer overflow
MAX_ERROR_MESSAGE_LENGTH = 2000

# Max retries for output validation errors (agent didn't save deliverables)
MAX_OUTPUT_VALIDATION_RETRIES = 3

# Error types that should never be retried
NON_RETRYABLE_ERROR_TYPES = [
    "AuthenticationError",
    "PermissionError",
    "InvalidRequestError",
    "RequestTooLargeError",
    "ConfigurationError",
    "InvalidTargetError",
    "ExecutionLimitError",
    "ModelRefusalError",
]


# ---------------------------------------------------------------------------
# Activity input — shared by all activities
# ---------------------------------------------------------------------------

@dataclass
class ActivityInput:
    """Input for all agent activities.

    Shared activity input. Passed from the workflow
    to every activity invocation.
    """

    repo_path: str
    workflow_id: str
    session_id: str
    web_url: str = ""
    output_path: str | None = None
    extra_context: str | None = None
    # Per-repository scan settings from the platform (description / focus / avoid);
    # merged into the prompt config by run_agent. See scan_config_from_input().
    scan_config: dict[str, Any] | None = None
    # Non-secret patch-delivery settings from the platform: {"enabled": True}.
    # The GitLab token is NOT part of this (see ``secrets``).
    push: dict[str, Any] | None = None
    # Non-secret facts about the checkout's upstream, from the repository record:
    # {"remote_url": <clean https URL>, "commit": <scanned commit sha or None>}. The
    # trusted push / MR target: never read from files in the checkout.
    source: dict[str, Any] | None = None
    # Non-secret flag for authenticated testing: {"cookie": True} means a cookie header
    # can be redeemed for the agents that test the live target (not the planner).
    auth: dict[str, Any] | None = None
    # Redemption reference for this run's secrets: {"ref": <run id>, "key": <random>}.
    # Not the secrets themselves: activities redeem them just in time from the API's
    # internal listener (src.services.run_secrets), hold them in memory for one call,
    # and never persist or log them. The key is never shown to an agent.
    secrets: dict[str, Any] | None = None
    # Per-run executor / model-tier overrides from the platform:
    # {"executor": ..., "model_small": ..., "model_medium": ..., "model_large": ...}
    # (src.types.config.MODEL_OVERRIDE_ENV). run_agent turns them into environment
    # variables for that agent's executor process only. Never holds secrets.
    model_overrides: dict[str, str] | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _heartbeat_loop(agent_name: str, start_time: float) -> None:
    """Send heartbeat to Temporal every 2 seconds."""
    while True:
        elapsed = int(time.time() - start_time)
        activity.heartbeat({"agent": agent_name, "elapsed_seconds": elapsed})
        await asyncio.sleep(HEARTBEAT_INTERVAL_S)


@contextlib.asynccontextmanager
async def _heartbeating(name: str):
    """Heartbeat every HEARTBEAT_INTERVAL_S while the body runs.

    For long utility activities. The body must not block the event loop (use
    asyncio subprocesses / ``asyncio.to_thread``), otherwise the heartbeats stop
    too. Heartbeating is also how a timed-out or cancelled attempt is told to stop.
    """
    task = asyncio.create_task(_heartbeat_loop(name, time.time()))
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def _truncate(message: str, max_length: int = MAX_ERROR_MESSAGE_LENGTH) -> str:
    """Truncate a string to prevent Temporal serialization overflow (and mask any
    secret an agent or tool echoed into an error message)."""
    from src.audit.redact import redact

    message = redact(message)
    if len(message) <= max_length:
        return message
    return f"{message[:max_length - 20]}\n[truncated]"


def _get_workspace_deliverables_path(input: ActivityInput) -> Path | None:
    """Return the workspace deliverables path, or None if not determinable."""
    effective = input.output_path or str(Path(input.repo_path) / ".vigilo" / input.session_id)
    path = Path(effective) / "deliverables"
    return path if path.is_dir() else None


async def _sync_deliverables(repo_path: str, output_path: str | None, session_id: str) -> None:
    await asyncio.to_thread(_sync_deliverables_blocking, repo_path, output_path, session_id)


def _sync_deliverables_blocking(repo_path: str, output_path: str | None, session_id: str) -> None:
    """Copy deliverables from repo to workspace output directory.

    Called after each agent completes so deliverables survive early termination.
    If deliverables/ is a symlink to the output directory (set up during preflight),
    writes already land in the right place — skip the copy.
    """
    import shutil

    src = Path(repo_path) / "deliverables"
    if not src.is_dir():
        return

    effective = output_path if output_path else str(Path(repo_path) / ".vigilo" / session_id)
    dst = Path(effective) / "deliverables"

    # Symlink means deliverables/ already points to the output directory.
    if src.is_symlink() and src.resolve() == dst.resolve():
        return

    dst.mkdir(parents=True, exist_ok=True)

    for item in src.iterdir():
        try:
            dest_item = dst / item.name
            if item.is_file():
                shutil.copy2(item, dest_item)
            elif item.is_dir():
                if dest_item.exists():
                    shutil.rmtree(dest_item)
                shutil.copytree(item, dest_item)
        except Exception as exc:
            logger.warning("Failed to sync deliverable %s: %s", item.name, exc)


def _classify_and_raise(
    error: Exception,
    agent_name: str,
    start_time: float,
) -> None:
    """Classify an exception and re-raise as a Temporal ApplicationError.

    Non-retryable error types cause Temporal to stop retrying immediately.
    All other errors are retryable by default.
    """
    # If already an ApplicationError, re-raise directly
    if isinstance(error, ApplicationError):
        raise error

    error_type = type(error).__name__
    is_non_retryable = error_type in NON_RETRYABLE_ERROR_TYPES
    elapsed = int((time.time() - start_time) * 1000)
    message = _truncate(str(error))

    raise ApplicationError(
        message,
        {"agent": agent_name, "elapsed_ms": elapsed},
        type=error_type,
        non_retryable=is_non_retryable,
    )


def _failure_parts(
    agent_name: str, executor: str, model: str | None,
    error: str | None, status: int | None = None,
) -> tuple[str, str, bool]:
    """``(message, error type, non_retryable)`` for a failed executor run.
    Permanent causes (bad credentials, unknown model, safety refusal) are
    non-retryable with a typed, actionable message; anything else stays a
    retryable ``ExecutionError``."""
    from src.ai.errors import classify_agent_error, format_agent_error, provider_message

    found = classify_agent_error(error, status)
    if found is None:
        reason = provider_message(error or "unknown error", 600)
        return format_agent_error(agent_name, executor, model, reason), "ExecutionError", False
    msg = format_agent_error(agent_name, executor, model, found.reason, found.hint)
    return _truncate(msg), found.error_type, found.non_retryable


def _execution_failure(
    agent_name: str, executor: str, model: str | None,
    error: str | None, status: int | None = None,
) -> ApplicationError:
    """The ApplicationError for a failed executor run (see :func:`_failure_parts`)."""
    message, error_type, non_retryable = _failure_parts(agent_name, executor, model, error, status)
    return ApplicationError(
        message, {"agent": agent_name, "executor": executor, "model": model},
        type=error_type, non_retryable=non_retryable,
    )


def _retry_schedule(attempt: int) -> tuple[float | None, int | None]:
    """``(seconds until the next attempt, max attempts)`` from the activity's
    retry policy; ``(None, ...)`` when this was the last attempt."""
    policy = activity.info().retry_policy
    if policy is None:
        return None, None
    max_attempts = policy.maximum_attempts or None
    if max_attempts and attempt >= max_attempts:
        return None, max_attempts
    delay = policy.initial_interval.total_seconds() * (policy.backoff_coefficient ** (attempt - 1))
    if policy.maximum_interval:
        delay = min(delay, policy.maximum_interval.total_seconds())
    return delay, max_attempts


async def _record_retry(audit: Any, agent_name: str, error: Exception) -> None:
    """Emit ``agent.retrying`` when this failed attempt will be retried."""
    from datetime import datetime, timedelta, timezone

    from src.ai.errors import provider_message

    if isinstance(error, ApplicationError):
        if error.non_retryable or error.type in NON_RETRYABLE_ERROR_TYPES:
            return
        error_type = error.type or "ApplicationError"
    else:
        error_type = type(error).__name__
        if error_type in NON_RETRYABLE_ERROR_TYPES:
            return
    attempt = activity.info().attempt
    delay, max_attempts = _retry_schedule(attempt)
    if delay is None and max_attempts is not None:
        return  # last attempt: the run fails with the final error
    when = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat() if delay else None
    await audit.retry_agent(
        agent_name, attempt=attempt, error_type=error_type,
        reason=provider_message(str(error), 400), next_attempt_at=when,
        retry_in_s=delay, max_attempts=max_attempts,
    )


def _build_session_metadata(input: ActivityInput) -> dict[str, Any]:
    """Build a SessionMetadata-compatible dict from ActivityInput."""
    meta: dict[str, Any] = {
        "id": input.session_id,
        "web_url": input.web_url,
        "repo_path": input.repo_path,
    }
    if input.output_path:
        meta["output_path"] = input.output_path
    return meta


_SCAN_KEYS = ("description", "focus", "avoid")


def scan_config_from_input(input: dict[str, Any]) -> dict[str, Any] | None:
    """Per-repository scan settings from a workflow input dict, or None.

    The platform sends ``scan: {description, focus, avoid}`` (older API builds
    sent only a top-level ``description``). Deterministic, so workflows may call it.
    """
    scan = dict(input.get("scan") or {})
    if input.get("description") and not scan.get("description"):
        scan["description"] = input["description"]
    scan = {k: v for k, v in scan.items() if k in _SCAN_KEYS and v}
    return scan or None


def merge_scan_config(
    config: dict[str, Any] | None, scan: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Overlay platform scan settings onto a loaded config file.

    The config file wins where it already sets a value; the platform fills the
    gaps. Focus/avoid are free text (one rule per line), which load_prompt
    accepts as flat ``focus`` / ``avoid`` entries.
    """
    if not scan:
        return config
    merged = dict(config or {})
    rules = merged.get("rules") if isinstance(merged.get("rules"), dict) else {}
    for key in _SCAN_KEYS:
        if scan.get(key) and not merged.get(key) and not rules.get(key):
            merged[key] = scan[key]
    return merged


def _resolve_agent(agent_name: str, agents: Any) -> tuple[Any, int | None]:
    """Map an actor name to ``(definition, instance)``.

    ``investigator-3`` → (``AGENTS["investigator"]``, 3); ``surveyor`` →
    (``AGENTS["surveyor"]``, None). An exact registry match always wins, so
    names that merely end in digits are never misread. Unknown names are a
    permanent configuration error.
    """
    from src.pipeline.stages import base_actor

    if agent_name in agents:
        return agents[agent_name], None
    base = base_actor(agent_name)
    if base != agent_name and base in agents:
        return agents[base], int(agent_name.rsplit("-", 1)[1])
    raise ApplicationError(
        f"Unknown agent {agent_name!r}",
        type="ConfigurationError",
        non_retryable=True,
    )


def _ledger_assignment_done(base_name: str, input: ActivityInput) -> bool | None:
    """Check a batched agent against its assignment in the findings ledger.

    Investigators must close at least one of their ``LEADS`` (a ``lead-done``
    record); provers must give at least one of their ``FINDINGS`` a verdict.
    Returns ``None`` when the agent has no batch assignment (then the normal
    deliverable check applies). Leads/findings an agent leaves open are picked
    up by later passes, so "at least one" is the bar for "the agent did work".
    """
    from src.pipeline.ledger import Ledger
    from src.temporal.batching import FINDINGS_PREFIX, LEADS_PREFIX, parse_assignment

    if base_name == "investigator":
        ids = parse_assignment(input.extra_context, LEADS_PREFIX)
        if not ids:
            return None
        done = Ledger.for_repo(input.repo_path).lead_status()
    elif base_name == "prover":
        ids = parse_assignment(input.extra_context, FINDINGS_PREFIX)
        if not ids:
            return None
        done = Ledger.for_repo(input.repo_path).verdicts()
    else:
        return None
    covered = [i for i in ids if i in done]
    logger.info(
        "%s assignment: %d/%d recorded (%s)",
        base_name, len(covered), len(ids), ",".join(covered) or "none",
    )
    return bool(covered)


async def _validate_output(base_name: str, input: ActivityInput, validate_fn: Any) -> bool:
    """Ledger check for batched agents, deliverable-file check for the rest.

    The planner is the exception: a clean repository legitimately yields zero
    leads, so a missing or empty ``ledger/leads.jsonl`` is a valid outcome (the
    file is created empty so later stages read an existing, empty ledger). The
    workflow then skips investigate and prove.
    """
    if base_name == "planner":
        leads = Path(input.repo_path) / "deliverables" / "ledger" / "leads.jsonl"
        await asyncio.to_thread(leads.parent.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(leads.touch)
        return True
    ledger_ok = _ledger_assignment_done(base_name, input)
    if ledger_ok is not None:
        return ledger_ok
    return await validate_fn(base_name, input.repo_path)


# ---------------------------------------------------------------------------
# Core activity: run a single agent
# ---------------------------------------------------------------------------

# Actors that change git state (branches/commits) and so need their base ref
# restored. Every other actor is read-only; see run_agent.
GIT_WRITING_ACTORS = frozenset({"remediator"})


async def _git_base_ref(repo_path: str) -> str | None:
    """The branch (or, detached, the commit) HEAD is on, never a ``fix/*`` branch
    (a failed earlier attempt may have left HEAD on one: use the default branch).
    None when the path is not a git repository."""
    from src.services.git_manager import execute_git_command, is_git_repository

    if not await is_git_repository(repo_path):
        return None

    async def git(*args: str) -> str:
        out, _ = await execute_git_command(["git", *args], cwd=repo_path, description=" ".join(args))
        return out.strip()

    try:
        ref = await git("rev-parse", "--abbrev-ref", "HEAD")
        if ref == "HEAD":  # detached
            return await git("rev-parse", "HEAD")
        if ref and not ref.startswith("fix/"):
            return ref
        # Same order as patch_export._base_branch: the upstream default branch
        # (origin/HEAD), then main/master.
        try:
            origin = await git("symbolic-ref", "--short", "refs/remotes/origin/HEAD")
        except Exception:
            origin = ""
        if origin:
            name = origin.removeprefix("origin/")
            for cand in (name, origin):
                if cand.startswith("fix/") or cand == "HEAD":
                    continue
                try:
                    await git("rev-parse", "--verify", "--quiet", cand)
                    return cand
                except Exception:
                    continue
        for name in ("main", "master"):
            try:
                await git("rev-parse", "--verify", "--quiet", name)
                return name
            except Exception:
                continue
    except Exception as exc:
        logger.warning("Could not determine the base git ref: %s", exc)
    return None


async def _return_to_base_ref(repo_path: str, ref: str, *, force: bool) -> None:
    """Check ``ref`` out again. ``force`` discards modifications of tracked files
    (a failed remediator attempt's half-done edits); untracked files are untouched."""
    from src.services.git_manager import execute_git_command

    args = ["git", "checkout", "--quiet"] + (["--force"] if force else []) + [ref]
    try:
        await execute_git_command(args, cwd=repo_path, description=f"return to {ref}")
    except Exception as exc:
        logger.warning("Could not return to %s: %s", ref, exc)

async def _with_cookie_login(
    config: dict[str, Any] | None, input: ActivityInput, prompt_template: str,
) -> dict[str, Any] | None:
    """Overlay the run's cookie credential as the prompt's ``authentication`` block
    for actors that test the live target. A no-op without ``auth.cookie`` / target URL
    or for actors without a login block. A refusal (run finished) is permanent; an
    unreachable platform is retried."""
    from src.services import run_secrets
    from src.services.prompt_manager import takes_login_block

    if not ((input.auth or {}).get("cookie") and input.web_url and takes_login_block(prompt_template)):
        return config
    try:
        got = await run_secrets.redeem(input.secrets, ["cookie_header"])
    except run_secrets.RedemptionRefused as exc:
        raise ApplicationError(
            f"Cookie credential refused by the platform ({exc}); the run may have finished",
            type="ConfigurationError", non_retryable=True,
        )
    except run_secrets.RedemptionUnavailable as exc:
        raise ApplicationError(
            f"Could not reach the platform to redeem the cookie credential ({exc})",
            type="SecretServiceUnavailable", non_retryable=False,
        )
    cookie = got.get("cookie_header")
    if not cookie:
        return config
    merged = dict(config or {})
    merged["authentication"] = {
        "login_type": "cookie", "cookie_header": cookie, "login_url": input.web_url,
    }
    return merged


@activity.defn
async def run_agent(agent_name: str, input: ActivityInput) -> dict[str, Any]:
    """Core activity: run a single agent with heartbeat, prompt loading,
    executor run, output validation and audit logging.

    Git policy. All parallel agents share ONE checkout, so this activity never
    checkpoints, commits, resets or cleans it:

    * Every actor except the remediator is read-only with respect to the
      repository. It writes only to ``deliverables/`` (a git-ignored symlink to
      the run workspace) through ``vigilo-record`` / ``save-deliverable``. There
      is nothing to roll back, and a ``git reset --hard`` + ``git clean -fd`` on
      failure would delete files that agents running at the same moment wrote. A
      retry simply re-runs; ledger records are append-only and idempotent.
    * The remediator works on ``fix/*`` branches it creates and commits itself.
      The rollback that matters there is "get back to the branch we started on":
      its base ref is remembered, and on retry, failure and success HEAD is
      returned to it. Nothing is committed on its behalf (a ``git add -A`` would
      put untracked junk such as ``.vigilo-remote-url`` or scratch PoCs on the
      base branch, and from there into every fix branch and merge request), and
      partial fix branches of a failed attempt are kept, not deleted.

    Returns agent metrics as a dict (serializable for Temporal).
    """
    start_time = time.time()
    heartbeat_task = asyncio.create_task(_heartbeat_loop(agent_name, start_time))
    audit = None
    base_ref: str | None = None

    try:
        # Late imports to avoid importing non-deterministic code at module level
        from src.ai.executor import execute, validate_agent_output
        from src.audit.session import AuditSession
        from src.services.git_manager import get_commit_hash
        from src.services.prompt_manager import load_prompt
        from src.session_manager import AGENTS
        from src.types.audit import SessionMetadata
        from src.types.config import model_override_env
        from src.types.metrics import AgentMetrics

        # Numbered parallel instances ("investigator-3") share the base
        # actor's definition and prompt; the instance number gives each copy
        # its own browser session. Events, logs and VIGILO_AGENT keep the full
        # numbered name.
        agent_def, instance = _resolve_agent(agent_name, AGENTS)
        attempt_number = activity.info().attempt

        # 1. Load config (file) and overlay the platform's scan settings
        config = merge_scan_config(
            None, input.scan_config
        )
        # 1.5. Authenticated testing: redeem the job's cookie header just in time and
        # put it in THIS agent's prompt config (never the planner's, never persisted
        # unmasked: it is registered for redaction in every audit writer).
        config = await _with_cookie_login(config, input, agent_def.prompt_template)

        # 2. Load and interpolate prompt
        prompt = await load_prompt(
            agent_def.prompt_template,
            web_url=input.web_url,
            repo_path=input.repo_path,
            config=config,
            extra_context=input.extra_context or "",
            instance=instance,
        )

        # 3. Initialize audit session
        metadata = SessionMetadata(
            id=input.session_id,
            web_url=input.web_url,
            repo_path=input.repo_path,
            output_path=input.output_path,
        )
        audit = AuditSession(metadata)
        await audit.initialize(input.workflow_id)
        await audit.start_agent(agent_name, attempt_number)

        # 3.5. Save prompt snapshot
        if audit._agent_logger:
            await audit._agent_logger.save_prompt(
                agent_name,
                prompt,
                session_id=input.session_id,
                web_url=input.web_url,
            )

        # 3.6. Git base ref (remediator only; see "Git policy" in run_agent's
        # docstring). Nothing is committed, reset or cleaned for any actor.
        if agent_def.name in GIT_WRITING_ACTORS:
            base_ref = await _git_base_ref(input.repo_path)
            if base_ref and attempt_number > 1:
                # A failed earlier attempt may have left HEAD on a fix branch.
                await _return_to_base_ref(input.repo_path, base_ref, force=True)

        # 4. Execute Claude (with stream callback for audit logging)
        async def _on_stream(name: str, turn: int, content: str) -> None:
            """Record each model turn (excerpt in events, full text in the agent log)."""
            try:
                await audit.log_agent_turn(name, turn, content)
            except Exception:
                pass  # non-fatal

        # Report agent generates a massive document in a single API call;
        # extended thinking + large Write can exceed the default 900s idle timeout.
        idle_timeout = 2700.0 if agent_def.name == "reporter" else None

        # Per-run model/executor overrides apply to this agent's process only
        # (the worker is shared, so os.environ must not change). VIGILO_REPO_PATH
        # lets the ledger CLI find this run's checkout from any working directory.
        import os

        from src.ai.executor import get_executor_type

        override_executor = (input.model_overrides or {}).get("executor")
        effective_executor = get_executor_type(
            {**os.environ, "VIGILO_EXECUTOR": override_executor}
            if override_executor else None
        )
        extra_env = {
            **model_override_env(input.model_overrides, effective_executor),
            "VIGILO_REPO_PATH": input.repo_path,
        }

        result = await execute(
            prompt=prompt,
            agent_name=agent_name,
            model_tier=agent_def.model_tier,
            cwd=input.repo_path,
            on_stream=_on_stream,
            extra_env=extra_env,
            idle_timeout_s=idle_timeout,
        )

        # 5. Check execution success, then validate deliverable
        if not result.success:
            raise _execution_failure(
                agent_name, effective_executor, result.model, result.error,
                result.error_status,
            )

        if not await _validate_output(agent_def.name, input, validate_agent_output):
            # Check if we've hit the validation retry limit
            if attempt_number >= MAX_OUTPUT_VALIDATION_RETRIES:
                raise ApplicationError(
                    f"Agent {agent_name} failed output validation after {attempt_number} attempts",
                    type="OutputValidationError",
                    non_retryable=True,
                )
            raise ApplicationError(
                f"Agent {agent_name} failed to produce deliverable",
                type="OutputValidationError",
                non_retryable=False,
            )

        # 6. Leave the checkout on the ref it was on (remediator only), then
        # note HEAD for the audit record. Nothing is committed here.
        if base_ref:
            await _return_to_base_ref(input.repo_path, base_ref, force=False)
        checkpoint = await get_commit_hash(input.repo_path)

        # 6.5. Sync deliverables to workspace (survives early termination)
        await _sync_deliverables(input.repo_path, input.output_path, input.session_id)

        # 7. Record metrics and log to audit
        duration_ms = int((time.time() - start_time) * 1000)
        metrics = AgentMetrics(
            duration_ms=duration_ms,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_usd=result.cost_usd,
            num_turns=result.num_turns,
            model=result.model,
        )
        await audit.end_agent(agent_name, metrics, checkpoint)

        return metrics.model_dump()

    except Exception as e:
        # Only the remediator touches git state; put the checkout back on its
        # base ref. No `git reset --hard` / `git clean`: other agents share this
        # checkout and may be writing files right now.
        if base_ref:
            try:
                await _return_to_base_ref(input.repo_path, base_ref, force=True)
            except Exception:
                pass  # best-effort

        # Record the failure if the audit session got far enough to exist.
        try:
            if audit is not None and audit._initialized:
                await audit.fail_agent(agent_name, str(e))
                await _record_retry(audit, agent_name, e)
        except Exception:
            pass
        _classify_and_raise(e, agent_name, start_time)
        # unreachable, but satisfies type checker
        raise  # pragma: no cover
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


# ---------------------------------------------------------------------------
# Preflight validation
# ---------------------------------------------------------------------------

@activity.defn
async def preflight_validation(input: ActivityInput) -> None:
    """Preflight checks before any agent execution.

    Validates:
    1. Repository path exists and contains a .git directory
    2. Config file is valid (if provided)
    3. Target URL is reachable

    Raises ApplicationError (non-retryable) for permanent failures,
    or retryable ApplicationError for transient network issues.
    """
    start_time = time.time()
    attempt_number = activity.info().attempt

    heartbeat_task = asyncio.create_task(
        _heartbeat_loop("preflight", start_time)
    )

    try:
        from src.services.git_manager import is_git_repository

        repo_path = Path(input.repo_path)

        # 1. Check repository path
        if not repo_path.is_dir():
            raise ApplicationError(
                f"Repository path does not exist: {input.repo_path}",
                type="ConfigurationError",
                non_retryable=True,
            )

        if not await is_git_repository(input.repo_path):
            # Initialize git repo if not present (target repo may lack .git)
            logger.info("Initializing git repository at %s", input.repo_path)
            proc = await asyncio.create_subprocess_exec(
                "git", "init",
                cwd=input.repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            from src.services.git_manager import ensure_vigilo_excludes as _excl
            _excl(input.repo_path)  # before `add -A`: never commit Vigilo-owned files
            # Initial commit so checkpoints work
            proc = await asyncio.create_subprocess_exec(
                "git", "add", "-A",
                cwd=input.repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            proc = await asyncio.create_subprocess_exec(
                "git", "commit", "-m", "initial: baseline for security scan",
                "--allow-empty", "--no-verify",
                cwd=input.repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

        # 1.5. Ensure .vigilo/ and deliverables are in the target repo's .gitignore.
        # deliverables/ is a symlink to .vigilo/{session}/deliverables/. Both must
        # be gitignored so they stay untracked and survive branch checkouts (the
        # remediation agent creates fix branches from main — tracked files not in
        # main would be deleted on checkout, breaking deliverable access).
        gitignore_path = repo_path / ".gitignore"
        ignore_patterns = [".vigilo/", "deliverables"]
        try:
            existing = gitignore_path.read_text() if gitignore_path.is_file() else ""
            existing_lines = existing.splitlines()
            missing = [p for p in ignore_patterns if p not in existing_lines]
            if missing:
                with open(gitignore_path, "a") as gi:
                    if existing and not existing.endswith("\n"):
                        gi.write("\n")
                    for pattern in missing:
                        gi.write(f"{pattern}\n")
                logger.info("Added %s to target repo .gitignore", ", ".join(missing))
        except OSError as exc:
            logger.warning("Could not update .gitignore: %s", exc)

        # 1.55. Vigilo-owned files (.vigilo-remote-url, .vigilo/, deliverables) must
        # never be committed onto a fix branch: exclude them locally (untracked file).
        from src.services.git_manager import ensure_vigilo_excludes
        ensure_vigilo_excludes(str(repo_path))

        # 1.6. Clean and recreate deliverables directory
        # Target repos may contain stale deliverables from previous scans.
        # Clean slate for every fresh run.
        # Symlink deliverables/ → .vigilo/{session}/deliverables/ so writes
        # land directly in the mounted volume and survive container kills.
        deliverables_dir = repo_path / "deliverables"
        if deliverables_dir.is_symlink() or deliverables_dir.is_dir():
            import shutil
            if deliverables_dir.is_symlink():
                deliverables_dir.unlink()
            else:
                shutil.rmtree(deliverables_dir)

        effective_output = Path(
            input.output_path
            if input.output_path
            else str(repo_path / ".vigilo" / input.session_id)
        )
        output_deliverables = effective_output / "deliverables"
        output_deliverables.mkdir(parents=True, exist_ok=True)
        # Screenshots subdirectory
        (output_deliverables / "screenshots").mkdir(exist_ok=True)
        deliverables_dir.symlink_to(output_deliverables)
        logger.info("Deliverables symlinked to %s", output_deliverables)

        # 2.5. Validate API credentials by making a minimal CLI call
        try:
            from src.ai.executor import build_env, get_cli_name, get_preflight_cmd
            from src.ai.envguard import strip_secret_env
            preflight_cmd = get_preflight_cmd()
            cli_name = get_cli_name()
            proc = await asyncio.create_subprocess_exec(
                *preflight_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=strip_secret_env(build_env()),
            )
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
            if proc.returncode != 0:
                stderr_text = stderr.decode("utf-8", errors="replace").strip()
                auth_keywords = ["authentication", "api key", "unauthorized", "forbidden", "invalid"]
                if any(kw in stderr_text.lower() for kw in auth_keywords):
                    raise ApplicationError(
                        f"API credential validation failed: {stderr_text[:500]}",
                        type="AuthenticationError",
                        non_retryable=True,
                    )
        except asyncio.TimeoutError:
            logger.warning("Credential validation timed out, continuing")
        except ApplicationError:
            raise
        except FileNotFoundError:
            raise ApplicationError(
                f"'{cli_name}' CLI not found. Is it installed?",
                type="ConfigurationError",
                non_retryable=True,
            )
        except Exception as exc:
            logger.warning("Credential validation skipped: %s", exc)

        # 2.7. Validate the job's session-cookie credential against the target, so an
        # expired cookie fails the run now instead of every agent testing logged out.
        if input.web_url and (input.auth or {}).get("cookie"):
            cookie_cfg = await _with_cookie_login(None, input, "whitebox/surveyor")
            auth_cfg = (cookie_cfg or {}).get("authentication", {})
            if auth_cfg.get("login_type") == "cookie" and auth_cfg.get("cookie_header"):
                cookie_val = auth_cfg["cookie_header"]
                try:
                    import httpx
                    _LOGIN_KW = ("/login", "/auth", "/sso", "/cas/", "/oauth", "signin")
                    # Skip TLS verification for self-signed certificates
                    # (matches existing preflight reachability check below)
                    async with httpx.AsyncClient(
                        timeout=30, verify=False, follow_redirects=False,
                    ) as client:
                        resp = await client.get(
                            input.web_url, headers={"Cookie": cookie_val},
                        )
                    expired = False
                    status = resp.status_code
                    if status in (401, 403):
                        expired = True
                    elif status in (301, 302, 303, 307, 308):
                        loc = (resp.headers.get("location") or "").lower()
                        if any(kw in loc for kw in _LOGIN_KW):
                            expired = True
                    if expired:
                        raise ApplicationError(
                            "The job's session cookie has expired or is invalid. "
                            "Log in again in the browser and update the cookie "
                            "credential selected on the job.",
                            type="ConfigurationError",
                            non_retryable=True,
                        )
                    # 404 = auth filter accepted the cookie, route just doesn't
                    # exist. Typical when web_url is the bare host of an API
                    # with no `/` handler (e.g. Spring returns 404 JSON only
                    # AFTER the security filter passes — a bad cookie would
                    # have produced 401 before routing).
                    if status == 404:
                        logger.info(
                            "Pre-supplied cookie validated (404 at %s: auth passed, no `/` handler)",
                            input.web_url,
                        )
                    elif 500 <= status < 600:
                        logger.warning(
                            "Pre-supplied cookie check inconclusive: target returned %d. "
                            "Cookie state cannot be confirmed; continuing.",
                            status,
                        )
                    else:
                        logger.info(
                            "Pre-supplied cookie validated successfully (status %d)",
                            status,
                        )
                except ApplicationError:
                    raise
                except Exception as exc:
                    logger.warning(
                        "Cookie validation skipped (non-fatal): %s", exc,
                    )

        # 3. Check target URL reachability (skip when no URL provided)
        if input.web_url:
            try:
                import ssl
                import urllib.request

                # Skip TLS verification for self-signed certificates
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(
                    input.web_url,
                    method="HEAD",
                    headers={"User-Agent": "Vigilo-Preflight/1.0"},
                )
                # Use a short timeout; we just need to confirm the host responds
                # urlopen blocks: run it off the worker's event loop.
                await asyncio.to_thread(
                    urllib.request.urlopen, req, timeout=30, context=ssl_ctx,
                )
            except urllib.error.HTTPError:
                # HTTP error means the server is reachable (e.g. 403, 405)
                pass
            except Exception as exc:
                raise ApplicationError(
                    f"Target URL unreachable: {input.web_url} ({exc})",
                    type="InvalidTargetError",
                    non_retryable=True,
                )
        else:
            logger.info("No target URL provided — skipping reachability check (code-only mode)")

        logger.info(
            "Preflight validation passed (attempt %d)", attempt_number
        )

    except ApplicationError:
        raise
    except Exception as e:
        _classify_and_raise(e, "preflight", start_time)
        raise  # pragma: no cover
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


# ---------------------------------------------------------------------------
# Findings aggregation
# ---------------------------------------------------------------------------

@activity.defn
async def aggregate_findings(input: ActivityInput) -> None:
    """Aggregate the findings ledger, SCA and integrity outputs into a unified
    findings_index.json for the review, remediation and report stages."""
    from src.services.findings_aggregator import FindingsAggregator

    aggregator = FindingsAggregator()
    await aggregator.aggregate_and_write(input.repo_path)


# ---------------------------------------------------------------------------
# White-box engine: findings ledger
# ---------------------------------------------------------------------------

@activity.defn
async def read_ledger_work(input: ActivityInput) -> dict[str, Any]:
    """Return the ledger's outstanding work for the investigate/prove stages.

    Shape (kept small — it travels through workflow history)::

        {"open_leads": [{"id": "L-001", "priority": 1}, ...],        # priority order
         "unproven_findings": [{"id": "VG-002", "severity": "high"}, ...],
         "coverage": coverage_summary(ledger)}
    """
    from src.pipeline.ledger import Ledger, coverage_summary

    ledger = Ledger.for_repo(input.repo_path)
    verdicts = ledger.verdicts()
    open_leads = [
        {"id": lead["id"], "priority": lead.get("priority", 3)}
        for lead in ledger.open_leads()
    ]
    unproven = [
        {"id": fid, "severity": str(f.get("severity") or "medium").lower()}
        for fid, f in sorted(ledger.findings().items())
        if fid not in verdicts
    ]
    coverage = coverage_summary(ledger)
    logger.info(
        "Ledger: %d open leads of %d, %d unproven findings of %d",
        len(open_leads), coverage["leads_total"], len(unproven), coverage["findings_total"],
    )
    return {"open_leads": open_leads, "unproven_findings": unproven, "coverage": coverage}


@activity.defn
async def materialize_ledger_evidence(input: ActivityInput) -> dict[str, Any]:
    """Write ``{category}_exploitation_evidence.md`` files from the ledger.

    The review, remediation and report agents read per-category evidence
    files; this renders ledger findings, verdicts, evidence write-ups and
    chains into that form. A no-op when the ledger is empty, and never
    overwrites an agent-written evidence file (see src/services/report_ledger).
    """
    from src.services.report_ledger import write_ledger_evidence

    return await asyncio.to_thread(
        write_ledger_evidence, Path(input.repo_path) / "deliverables"
    )


@activity.defn
async def attach_workspace(input: ActivityInput) -> dict[str, Any]:
    """Point ``<repo>/deliverables`` at an existing run's workspace.

    Used by a standalone ``PatchWorkflow`` (re-generating patches for a
    finished run without re-scanning): unlike preflight it never clears
    deliverables. Fails permanently when the workspace has no
    ``findings_index.json`` — there is nothing to patch.
    """
    repo_path = Path(input.repo_path)
    if not repo_path.is_dir():
        raise ApplicationError(
            f"Repository path does not exist: {input.repo_path}",
            type="ConfigurationError",
            non_retryable=True,
        )
    workspace = Path(
        input.output_path or str(repo_path / ".vigilo" / input.session_id)
    ) / "deliverables"
    link = repo_path / "deliverables"
    if not (workspace / "findings_index.json").is_file():
        # The deliverables may already be in the repo (no separate workspace).
        if (link / "findings_index.json").is_file():
            return {"deliverables": str(link), "attached": False}
        raise ApplicationError(
            f"No findings_index.json in {workspace}: run a scan before generating patches",
            type="ConfigurationError",
            non_retryable=True,
        )
    if link.is_symlink() and link.resolve() == workspace.resolve():
        return {"deliverables": str(workspace), "attached": False}
    if link.is_symlink():
        link.unlink()
    elif link.exists():
        raise ApplicationError(
            f"{link} exists and is not a link to the run workspace {workspace}; "
            "refusing to replace it",
            type="ConfigurationError",
            non_retryable=True,
        )
    link.symlink_to(workspace)
    from src.services.git_manager import ensure_vigilo_excludes
    ensure_vigilo_excludes(str(repo_path))
    logger.info("Attached deliverables to workspace %s", workspace)
    return {"deliverables": str(workspace), "attached": True}


# ---------------------------------------------------------------------------
# Remediation gate
# ---------------------------------------------------------------------------

# Critic confidence values the remediator reports but does not patch
# (prompts/remediation.txt: "reported in the appendix only").
_NOT_PATCHED_CONFIDENCE = frozenset({"defense-in-depth", "theoretical"})
# Dependency upgrades and code-integrity review are never patched by the remediator.
_NOT_PATCHED_ID_PREFIXES = ("SCA-VULN-", "INTEGRITY-")


def count_remediable(index: dict[str, Any], critique: dict[str, Any] | None) -> dict[str, int]:
    """How many findings of ``findings_index.json`` remediation would act on.

    A finding counts unless it is a chain (fixed through its components), is
    ``code_fixable: false``, is an ``SCA-VULN-*`` / ``INTEGRITY-*`` entry, has the
    ``suppressed`` status (prover judged it a false positive / unreachable /
    refuted) and the critic did not re-promote it (``include_in_report: true``),
    or the critic annotated it
    ``include_in_report: false`` or as defense-in-depth / theoretical.
    """
    annotations = (critique or {}).get("annotations")
    annotations = annotations if isinstance(annotations, dict) else {}
    total = 0
    remediable = 0
    for entries in (index.get("by_type") or {}).values():
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            total += 1
            fid = str(entry.get("ID") or entry.get("id") or "")
            ann = annotations.get(fid)
            ann = ann if isinstance(ann, dict) else {}
            if (
                entry.get("vulnerability_type") == "chain"
                or entry.get("code_fixable") is False
                or fid.upper().startswith(_NOT_PATCHED_ID_PREFIXES)
                or (entry.get("status") == "suppressed" and ann.get("include_in_report") is not True)
                or ann.get("include_in_report") is False
                or str(ann.get("confidence", "")).lower() in _NOT_PATCHED_CONFIDENCE
            ):
                continue
            remediable += 1
    return {"total": total, "remediable": remediable}


@activity.defn
async def count_remediable_findings(input: ActivityInput) -> dict[str, int]:
    """``{"total": n, "remediable": m}`` from findings_index.json and, when the
    reviewer wrote it, findings_critique.json. The workflow skips remediation
    when ``remediable`` is 0. A missing index counts as zero findings."""
    deliverables = Path(input.repo_path) / "deliverables"

    def load(name: str) -> dict[str, Any] | None:
        try:
            data = json.loads((deliverables / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    index = await asyncio.to_thread(load, "findings_index.json")
    critique = await asyncio.to_thread(load, "findings_critique.json")
    result = count_remediable(index or {}, critique)
    logger.info("Remediation gate: %d of %d findings are remediable", result["remediable"], result["total"])
    return result


# ---------------------------------------------------------------------------
# Critique recall guard (deterministic backstop against silently-dropped TPs)
# ---------------------------------------------------------------------------

@activity.defn
async def audit_critique(input: ActivityInput) -> dict[str, Any]:
    """Reconcile findings_index.json against findings_critique.json.

    Flags (loudly, traceably) any index finding with no critique annotation and
    any serious+reachable finding the critic marked include_in_report=false.
    Writes deliverables/findings_critique_audit.json. Non-fatal: surfaces
    problems for the report step and the operator; never drops findings.
    """
    from src.services.findings_guard import audit_critique as _audit

    return await _audit(input.repo_path)


# ---------------------------------------------------------------------------
# Patch verification (re-run the confirmation harness against each fix branch)
# ---------------------------------------------------------------------------

@activity.defn
async def verify_patches(input: ActivityInput) -> dict[str, Any]:
    """Verify each fix/* branch by re-running the finding's source-level harness.

    Reads remediation_manifest.json, checks out each branch, re-runs the harness
    the prover built (``VIGILO_RESULT: VULNERABLE`` + exit 0 = still vulnerable,
    ``VIGILO_RESULT: NOT_VULNERABLE`` + exit 1 = fixed, anything else = not
    tested) and writes verified=pass|fail|not_tested + verify_method back into the
    manifest. Falls back to a build check when no harness exists. Non-fatal.

    Long-running, so it heartbeats and never blocks the event loop (asyncio
    subprocesses). If a retry overlaps a previous attempt that is still alive,
    patch_verify's file lock makes it wait; the checkout is always restored.
    """
    from src.services.patch_verify import verify_patches as _verify

    async with _heartbeating("verify_patches"):
        return await _verify(input.repo_path, heartbeat=lambda: activity.heartbeat("verify_patches"))


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

@activity.defn
async def assemble_report(input: ActivityInput) -> None:
    """Restore deliverables before the reporter runs.

    The reporter agent authors the full report from the findings index, the
    critique and the per-category evidence files. This step only makes sure
    those files exist: it restores deliverables displaced from the checkout and
    renders the ledger's evidence files.
    """
    await asyncio.to_thread(_restore_and_render_deliverables, input)


def _restore_and_render_deliverables(input: ActivityInput) -> None:
    import shutil

    # Restore deliverables from workspace before the report runs.
    # Agent git operations (branch checkout, merge) during earlier phases can
    # displace untracked deliverable files from the repo working directory.
    # The workspace copy (synced after each agent) is the source of truth.
    workspace_deliverables = _get_workspace_deliverables_path(input)
    repo_deliverables = Path(input.repo_path) / "deliverables"
    if workspace_deliverables and workspace_deliverables.is_dir():
        repo_deliverables.mkdir(parents=True, exist_ok=True)
        restored = 0
        for item in workspace_deliverables.iterdir():
            dest = repo_deliverables / item.name
            try:
                if item.is_file() and not dest.exists():
                    shutil.copy2(item, dest)
                    restored += 1
                elif item.is_dir() and not dest.exists():
                    shutil.copytree(item, dest)
                    restored += 1
            except Exception as exc:
                logger.warning("Failed to restore %s: %s", item.name, exc)
        if restored:
            logger.info("Restored %d missing deliverables before the report", restored)

    # Render the findings ledger (findings, verdicts, evidence write-ups,
    # chains) into the per-category evidence files the reporter reads. No-op
    # when the ledger is empty; never overwrites agent-written evidence files.
    try:
        from src.services.report_ledger import write_ledger_evidence

        write_ledger_evidence(repo_deliverables)
    except Exception as exc:
        logger.warning("Ledger evidence rendering failed (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# Inject model metadata into report
# ---------------------------------------------------------------------------

@activity.defn
async def inject_report_metadata(input: ActivityInput) -> None:
    """Inject model information from session.json into the final report.

    Reads session.json from the workspace output directory to extract
    unique model names from all agents, then inserts a Model line
    into the Executive Summary section.
    """
    from src.services.reporting import inject_model_into_report

    effective_output_path = (
        input.output_path
        if input.output_path
        else str(Path(input.repo_path) / ".vigilo" / input.session_id)
    )

    try:
        await inject_model_into_report(input.repo_path, effective_output_path)
    except Exception as exc:
        logger.warning("Error injecting model metadata into report: %s", exc)


# ---------------------------------------------------------------------------
# Final redaction of deliverables
# ---------------------------------------------------------------------------

@activity.defn
async def redact_deliverables(input: ActivityInput) -> dict[str, Any]:
    """Mask the run's secrets (the job's cookie) in every text deliverable.

    Evidence write-ups and the report can quote the cookie an agent used; the audit
    logs are redacted as they are written, but deliverables are not. When the run had a
    cookie, it is redeemed here (memory only, registered for masking) and every text
    file under ``deliverables/`` is rewritten in place, never following symlinks.
    A transient platform outage is retried so an unredacted report is not shipped;
    a refused redemption means the run has no cookie (or is over): nothing to mask
    beyond what this process already knows.
    """
    from src.services import run_secrets
    from src.services.deliverable_redact import redact_tree

    if (input.auth or {}).get("cookie") and run_secrets.has_reference(input.secrets):
        try:
            await run_secrets.redeem(input.secrets, ["cookie_header"])
        except run_secrets.RedemptionRefused:
            logger.warning("redact_deliverables: cookie no longer available; masking known secrets only")
        except run_secrets.RedemptionUnavailable as exc:
            raise ApplicationError(
                f"Could not reach the platform to redeem the cookie for redaction: {exc}",
                type="SecretServiceUnavailable", non_retryable=False,
            ) from exc

    if input.output_path:
        base, parts = input.output_path, ("deliverables",)
    else:
        base, parts = input.repo_path, (".vigilo", input.session_id, "deliverables")
    stats = await asyncio.to_thread(redact_tree, base, *parts)
    if stats["redacted"]:
        logger.info("Redacted secrets in %d deliverable file(s)", stats["redacted"])
    return {k: stats[k] for k in ("scanned", "redacted", "skipped", "errors")}


# ---------------------------------------------------------------------------
# Rebuild git from upstream (before remediation)
# ---------------------------------------------------------------------------

@activity.defn
async def rebuild_git(input: ActivityInput) -> dict[str, Any]:
    """Rebuild git from the upstream remote before remediation.

    Replaces the checkout's ``.git`` with a shallow clone of the repository's remote
    (``input.source``, from the platform), based on the commit that was scanned when it
    exists upstream, else on the upstream HEAD. The swap is atomic. Non-fatal: on
    failure the existing ``.git`` stays and remediation still runs, but branches cannot
    be pushed.

    Returns ``{"ok", "base", "commit", "requested_commit", "reason"}``. A private
    repository needs the run's GitLab token to be cloned; it is redeemed just in time
    (only when push is enabled), given to git through ``GIT_ASKPASS`` and dropped.
    """
    from src.services import run_secrets
    from src.services.git_push import rebuild_git_from_remote

    src = input.source or {}
    token = None
    try:
        async with _heartbeating("rebuild_git"):
            if (input.push or {}).get("enabled") and run_secrets.has_reference(input.secrets):
                try:
                    token = (await run_secrets.redeem(input.secrets, ["forge_token"])).get("forge_token")
                except (run_secrets.RedemptionRefused, run_secrets.RedemptionUnavailable) as exc:
                    logger.warning("Git rebuild: GitLab credential not available (%s)", exc)
            return await rebuild_git_from_remote(
                input.repo_path, remote_url=src.get("remote_url"),
                commit=src.get("commit"), token=token,
            )
    except Exception as exc:
        if isinstance(exc, asyncio.CancelledError):
            raise
        logger.warning("Git rebuild failed (non-fatal): %s", exc)
        return {"ok": False, "base": None, "commit": None,
                "requested_commit": src.get("commit"), "reason": str(exc)[:300]}
    finally:
        token = None


# ---------------------------------------------------------------------------
# Export fix branches as .patch files
# ---------------------------------------------------------------------------

@activity.defn
async def export_patches(input: ActivityInput) -> dict[str, Any]:
    """Export all fix/* branches as .patch files into deliverables/patches/.

    Runs after remediation — patches persist to the host via the deliverables
    symlink regardless of push configuration. Git runs as asyncio subprocesses
    and the activity heartbeats, so a long export never blocks the worker.
    """
    try:
        from src.services.patch_export import export_patches as do_export

        async with _heartbeating("export_patches"):
            result = await do_export(input.repo_path)
        if result.get("exported"):
            logger.info(
                "Exported %d patches to deliverables/patches/",
                len(result["exported"]),
            )
        return result
    except Exception as exc:
        logger.warning("Failed to export patches: %s", exc)
        return {"exported": [], "failed": [], "error": str(exc)[:500]}


# ---------------------------------------------------------------------------
# Deliver patches: push fix branches + open merge requests
# ---------------------------------------------------------------------------

@activity.defn
async def deliver_patches(input: ActivityInput) -> dict[str, Any]:
    """Push fix/* branches to the upstream remote and open one GitLab MR per branch.

    Runs after verify_patches. Acts only when the input has ``push.enabled``, the
    repository's remote (``source``) and a secrets reference; the GitLab token is
    redeemed just in time inside the delivery and never touches disk. Idempotent and
    serialized: a retry that overlaps a still-running earlier attempt waits for it,
    skips branches already pushed at the same commit and never downgrades a recorded
    success. Heartbeats while pushing, so a dead attempt is detected and a cancelled
    one stops its git subprocess. The per-branch outcome goes into
    remediation_manifest.json. Non-fatal: git/GitLab failures are recorded, not raised;
    only cancellation and a transient platform outage (retryable) propagate.
    """
    try:
        from src.services.git_push import deliver_patches as do_deliver

        async with _heartbeating("deliver_patches"):
            result = await do_deliver(
                input.repo_path, input.session_id, input.push,
                source=input.source, secrets=input.secrets,
            )
        if result.get("retryable"):
            # The platform's internal API was unreachable: retrying is safe because
            # delivery is idempotent (already-pushed branches are skipped).
            raise ApplicationError(
                "Could not reach the platform to redeem the GitLab credential",
                type="SecretServiceUnavailable", non_retryable=False,
            )
        return result
    except (asyncio.CancelledError, ApplicationError):
        raise
    except Exception as exc:
        logger.warning("Patch delivery failed (non-fatal): %s", exc)
        return {"status": "failed", "reason": str(exc)[:300], "pushed": [],
                "already_delivered": [], "failed": [], "merge_requests": []}


# ---------------------------------------------------------------------------
# Phase transition logging
# ---------------------------------------------------------------------------

@activity.defn
async def log_phase_transition(
    input: ActivityInput, phase: str, event: str, reason: str | None = None
) -> None:
    """Log a stage transition (start/complete/skip/warn/fail) to the run's audit log."""
    from src.audit.session import AuditSession
    from src.types.audit import SessionMetadata

    metadata = SessionMetadata(
        id=input.session_id,
        web_url=input.web_url,
        repo_path=input.repo_path,
        output_path=input.output_path,
    )
    audit = AuditSession(metadata)
    await audit.initialize(input.workflow_id)

    if event == "start":
        await audit.log_phase_start(phase)
    elif event in ("skip", "warn", "fail"):
        if reason:
            await audit.log_stage(phase, event, reason=reason)
        else:
            await audit.log_stage(phase, event)
    else:
        await audit.log_phase_complete(phase)


# ---------------------------------------------------------------------------
# Workflow completion logging
# ---------------------------------------------------------------------------

@activity.defn
async def log_workflow_complete(
    input: ActivityInput, summary: dict[str, Any]
) -> None:
    """Log workflow completion with full summary and copy deliverables.

    Called on both success and failure to record final pipeline state.
    """
    from src.audit.session import AuditSession
    from src.types.audit import SessionMetadata

    metadata = SessionMetadata(
        id=input.session_id,
        web_url=input.web_url,
        repo_path=input.repo_path,
        output_path=input.output_path,
    )
    audit = AuditSession(metadata)
    await audit.initialize(input.workflow_id)

    # Update session status
    status = summary.get("status", "unknown")
    await audit.update_session_status(status)

    # Write completion entry to workflow.log
    await audit.log_workflow_complete(summary)

    # Final deliverables sync (catches anything missed by incremental copies)
    await _sync_deliverables(input.repo_path, input.output_path, input.session_id)
