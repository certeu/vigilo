"""Temporal activities for pipeline.

Each activity wraps service calls with Temporal-specific concerns:
- Heartbeat loop (2s interval) to signal worker liveness
- Error classification into ApplicationError (retryable vs non-retryable)
- Audit session lifecycle management

Business logic is delegated to services in src/services/.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
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
]


# ---------------------------------------------------------------------------
# Activity input — shared by all activities
# ---------------------------------------------------------------------------

@dataclass
class ActivityInput:
    """Input for all agent activities.

    Matches Shannon's ActivityInput interface. Passed from the workflow
    to every activity invocation.
    """

    repo_path: str
    workflow_id: str
    session_id: str
    web_url: str = ""
    config_path: str | None = None
    output_path: str | None = None
    extra_context: str | None = None


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


def _get_workspace_deliverables_path(input: ActivityInput) -> Path | None:
    """Return the workspace deliverables path, or None if not determinable."""
    effective = input.output_path or str(Path(input.repo_path) / ".vigilo" / input.session_id)
    path = Path(effective) / "deliverables"
    return path if path.is_dir() else None


async def _sync_deliverables(repo_path: str, output_path: str | None, session_id: str) -> None:
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


async def _load_config(config_path: str | None) -> dict[str, Any] | None:
    """Load a YAML config file, returning None if not provided or missing."""
    if not config_path:
        return None

    path = Path(config_path)
    if not path.is_file():
        logger.warning("Config file not found: %s", config_path)
        return None

    try:
        import yaml

        async with aiofiles.open(path, mode="r", encoding="utf-8") as f:
            content = await f.read()
        return yaml.safe_load(content)
    except Exception as exc:
        logger.warning("Failed to load config from %s: %s", config_path, exc)
        return None


# ---------------------------------------------------------------------------
# Core activity: run a single agent
# ---------------------------------------------------------------------------

@activity.defn
async def run_agent(agent_name: str, input: ActivityInput) -> dict[str, Any]:
    """Core activity: run a single agent with heartbeat, prompt loading,
    Claude execution, output validation, git checkpoint, and audit logging.

    Returns agent metrics as a dict (serializable for Temporal).
    """
    start_time = time.time()
    heartbeat_task = asyncio.create_task(_heartbeat_loop(agent_name, start_time))

    try:
        # Late imports to avoid importing non-deterministic code at module level
        from src.ai.executor import execute, validate_agent_output
        from src.audit.session import AuditSession
        from src.services.git_manager import commit_success, get_commit_hash
        from src.services.prompt_manager import load_prompt
        from src.session_manager import AGENTS
        from src.types.audit import SessionMetadata
        from src.types.metrics import AgentMetrics

        agent_def = AGENTS[agent_name]
        attempt_number = activity.info().attempt

        # 1. Load config
        config = await _load_config(input.config_path)

        # 2. Load and interpolate prompt
        prompt = await load_prompt(
            agent_def.prompt_template,
            web_url=input.web_url,
            repo_path=input.repo_path,
            config=config,
            extra_context=input.extra_context or "",
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

        # 3.6. Git checkpoint before execution (rollback point for retries)
        from src.services.git_manager import create_checkpoint
        await create_checkpoint(input.repo_path, agent_name, attempt_number)

        # 4. Execute Claude (with stream callback for audit logging)
        async def _on_stream(name: str, turn: int, content: str) -> None:
            """Write each LLM turn to workflow.log and agent log."""
            try:
                if audit._workflow_logger:
                    await audit._workflow_logger.log_llm_response(name, turn, content)
                if audit._agent_logger:
                    await audit._agent_logger.log_event(
                        name, "llm_response", {"turn": turn, "content": content}
                    )
            except Exception:
                pass  # non-fatal

        # Report agent generates a massive document in a single API call;
        # extended thinking + large Write can exceed the default 900s idle timeout.
        idle_timeout = 2700.0 if agent_name == "report" else None

        result = await execute(
            prompt=prompt,
            agent_name=agent_name,
            model_tier=agent_def.model_tier,
            cwd=input.repo_path,
            on_stream=_on_stream,
            idle_timeout_s=idle_timeout,
        )

        # 5. Check execution success, then validate deliverable
        if not result.success:
            raise ApplicationError(
                f"Agent {agent_name} execution failed: {result.error}",
                type="ExecutionError",
                non_retryable=False,
            )

        if not await validate_agent_output(agent_name, input.repo_path):
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

        # 6. Git checkpoint
        await commit_success(input.repo_path, agent_name)
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
        # Rollback workspace to prevent stale deliverables contaminating retries
        try:
            from src.services.git_manager import rollback_workspace
            await rollback_workspace(input.repo_path, f"{agent_name} failure cleanup")
        except Exception:
            pass  # best-effort rollback

        # Log failure to audit if session was initialized
        try:
            if 'audit' in dir() and audit._initialized:
                await audit._agent_logger.log_event(
                    agent_name, "agent_error", {"error": str(e)[:500]}
                )
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

        # 1.6. Clean and recreate deliverables directory
        # Target repos may contain stale deliverables from previous scans
        # (baked into Docker image). Clean slate for every fresh run.
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

        # 2. Validate config if provided
        if input.config_path:
            config = await _load_config(input.config_path)
            if config is None:
                raise ApplicationError(
                    f"Config file not found or invalid: {input.config_path}",
                    type="ConfigurationError",
                    non_retryable=True,
                )

        # 2.5. Validate API credentials by making a minimal CLI call
        try:
            from src.ai.executor import build_env, get_cli_name, get_preflight_cmd
            preflight_cmd = get_preflight_cmd()
            cli_name = get_cli_name()
            proc = await asyncio.create_subprocess_exec(
                *preflight_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=build_env(),
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

        # 2.7. Validate pre-supplied cookie (login_type: cookie)
        if input.web_url and input.config_path:
            config_for_cookie = await _load_config(input.config_path)
            auth_cfg = (config_for_cookie or {}).get("authentication", {})
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
                            "Pre-supplied cookie has expired or is invalid. "
                            "Re-login via the browser and update cookie_header "
                            "in your config YAML.",
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

                # Skip TLS verification for self-signed certificates (matches Shannon)
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(
                    input.web_url,
                    method="HEAD",
                    headers={"User-Agent": "Vigilo-Preflight/1.0"},
                )
                # Use a short timeout; we just need to confirm the host responds
                urllib.request.urlopen(req, timeout=30, context=ssl_ctx)
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
# Exploitation queue check
# ---------------------------------------------------------------------------

@activity.defn
async def check_exploitation_queue(
    input: ActivityInput, vuln_type: str
) -> dict[str, Any]:
    """Read the exploitation queue JSON for a vuln type and decide whether
    to run the exploit agent.

    Returns:
        {"should_exploit": bool, "vulnerability_count": int, "vuln_type": str}
    """
    from src.session_manager import VULN_TYPE_CONFIG

    config = VULN_TYPE_CONFIG.get(vuln_type)
    if not config:
        logger.warning("Unknown vuln type: %s", vuln_type)
        return {
            "should_exploit": False,
            "vulnerability_count": 0,
            "vuln_type": vuln_type,
        }

    deliverables_dir = Path(input.repo_path) / "deliverables"
    queue_path = deliverables_dir / config.queue_filename
    deliverable_path = deliverables_dir / config.analysis_deliverable

    queue_exists = queue_path.is_file()
    deliverable_exists = deliverable_path.is_file()

    # Symmetric validation: both files must exist together.
    # If only one exists, the agent produced partial output — retryable.
    if deliverable_exists and not queue_exists:
        logger.info(
            "No exploitation queue for %s (file not found: %s)",
            vuln_type,
            queue_path,
        )
        return {
            "should_exploit": False,
            "vulnerability_count": 0,
            "vuln_type": vuln_type,
        }

    if queue_exists and not deliverable_exists:
        raise ApplicationError(
            f"Queue exists without deliverable for {vuln_type} — partial output, retrying",
            type="OutputValidationError",
            non_retryable=False,
        )

    if not queue_exists and not deliverable_exists:
        logger.info("No output for %s (neither queue nor deliverable found)", vuln_type)
        return {
            "should_exploit": False,
            "vulnerability_count": 0,
            "vuln_type": vuln_type,
        }

    try:
        async with aiofiles.open(queue_path, mode="r", encoding="utf-8") as f:
            content = await f.read()
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        # Malformed JSON is retryable — agent can fix on retry
        raise ApplicationError(
            f"Malformed exploitation queue JSON for {vuln_type}: {exc}",
            type="OutputValidationError",
            non_retryable=False,
        )
    except OSError as exc:
        logger.warning(
            "Failed to read exploitation queue for %s: %s", vuln_type, exc
        )
        return {
            "should_exploit": False,
            "vulnerability_count": 0,
            "vuln_type": vuln_type,
        }

    vulns = data.get("vulnerabilities", [])

    if not isinstance(vulns, list):
        # Invalid structure is retryable
        raise ApplicationError(
            f"Queue file for {vuln_type} has non-list 'vulnerabilities' field",
            type="OutputValidationError",
            non_retryable=False,
        )

    vuln_count = len(vulns)
    should_exploit = vuln_count > 0

    logger.info(
        "Exploitation queue for %s: %d vulnerabilities, should_exploit=%s",
        vuln_type,
        vuln_count,
        should_exploit,
    )

    return {
        "should_exploit": should_exploit,
        "vulnerability_count": vuln_count,
        "vuln_type": vuln_type,
    }


# ---------------------------------------------------------------------------
# Feedback loop: needs_more_info check
# ---------------------------------------------------------------------------

@activity.defn
async def check_needs_more_info(
    input: ActivityInput, vuln_type: str
) -> dict[str, Any] | None:
    """Check if an exploit agent wrote a needs_more_info request.

    Returns the parsed NeedsMoreInfo dict if the file exists, or None.
    """
    needs_info_path = (
        Path(input.repo_path)
        / "deliverables"
        / f"{vuln_type}_needs_more_info.json"
    )

    if not needs_info_path.is_file():
        return None

    try:
        async with aiofiles.open(
            needs_info_path, mode="r", encoding="utf-8"
        ) as f:
            content = await f.read()
        data = json.loads(content)
        logger.info(
            "Found needs_more_info for %s with %d questions",
            vuln_type,
            len(data.get("questions", [])),
        )
        return data

    except (json.JSONDecodeError, OSError) as exc:
        logger.warning(
            "Failed to read needs_more_info for %s: %s", vuln_type, exc
        )
        return None


# ---------------------------------------------------------------------------
# Feedback loop: cleanup needs_more_info after consumption
# ---------------------------------------------------------------------------

@activity.defn
async def cleanup_needs_more_info(
    input: ActivityInput, vuln_type: str
) -> None:
    """Remove needs_more_info file after it has been consumed by the feedback loop.

    Prevents the same feedback request from re-triggering on resume.
    """
    needs_info_path = (
        Path(input.repo_path)
        / "deliverables"
        / f"{vuln_type}_needs_more_info.json"
    )

    if needs_info_path.is_file():
        needs_info_path.unlink()
        logger.info("Cleaned up needs_more_info for %s", vuln_type)


# ---------------------------------------------------------------------------
# Feedback loop: queue backup/merge to prevent data loss on vuln re-run
# ---------------------------------------------------------------------------

@activity.defn
async def backup_exploitation_queue(
    input: ActivityInput, vuln_type: str
) -> None:
    """Back up the exploitation queue before a vuln agent feedback re-run.

    Copies {type}_exploitation_queue.json → {type}_exploitation_queue.backup.json
    so findings from the original run are preserved if the re-run produces a
    smaller queue (focused on the feedback questions).
    """
    from src.session_manager import VULN_TYPE_CONFIG

    config = VULN_TYPE_CONFIG.get(vuln_type)
    if not config:
        return

    deliverables_dir = Path(input.repo_path) / "deliverables"
    queue_path = deliverables_dir / config.queue_filename
    backup_path = queue_path.with_suffix(".backup.json")

    if queue_path.is_file():
        import shutil
        shutil.copy2(queue_path, backup_path)
        logger.info("Backed up %s queue before feedback re-run", vuln_type)


@activity.defn
async def merge_exploitation_queue_backup(
    input: ActivityInput, vuln_type: str
) -> None:
    """Merge the backup queue with the new queue after a vuln agent feedback re-run.

    Reads both the new queue (written by the re-run) and the backup (from before
    the re-run), merges by vuln ID (union), and writes the merged result back.
    This prevents data loss when a focused re-run produces fewer findings than
    the original.
    """
    from src.session_manager import VULN_TYPE_CONFIG

    config = VULN_TYPE_CONFIG.get(vuln_type)
    if not config:
        return

    deliverables_dir = Path(input.repo_path) / "deliverables"
    queue_path = deliverables_dir / config.queue_filename
    backup_path = queue_path.with_suffix(".backup.json")

    if not backup_path.is_file():
        logger.debug("No backup queue for %s — nothing to merge", vuln_type)
        return

    try:
        # Read both queues
        new_vulns: list[dict] = []
        if queue_path.is_file():
            async with aiofiles.open(queue_path, mode="r", encoding="utf-8") as f:
                new_data = json.loads(await f.read())
            new_vulns = new_data.get("vulnerabilities", [])

        async with aiofiles.open(backup_path, mode="r", encoding="utf-8") as f:
            backup_data = json.loads(await f.read())
        backup_vulns = backup_data.get("vulnerabilities", [])

        # Merge by vuln ID: new findings take precedence over backup
        seen_ids: set[str] = set()
        merged: list[dict] = []
        for vuln in new_vulns:
            vid = vuln.get("ID", vuln.get("id", ""))
            if vid:
                seen_ids.add(vid)
            merged.append(vuln)

        # Add backup findings not present in the new queue
        restored = 0
        for vuln in backup_vulns:
            vid = vuln.get("ID", vuln.get("id", ""))
            if vid and vid not in seen_ids:
                merged.append(vuln)
                seen_ids.add(vid)
                restored += 1

        # Write merged queue
        merged_data = {"vulnerabilities": merged}
        async with aiofiles.open(queue_path, mode="w", encoding="utf-8") as f:
            await f.write(json.dumps(merged_data, indent=2, ensure_ascii=False))

        # Clean up backup
        backup_path.unlink()

        if restored:
            logger.info(
                "Merged %s queue: %d new + %d restored from backup = %d total",
                vuln_type, len(new_vulns), restored, len(merged),
            )
        else:
            logger.info("Queue merge for %s: no additional findings in backup", vuln_type)

    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to merge %s queue backup: %s", vuln_type, exc)
        # Clean up backup on failure to prevent stale state
        if backup_path.is_file():
            backup_path.unlink()


# ---------------------------------------------------------------------------
# Chain exploitation readiness check
# ---------------------------------------------------------------------------

@activity.defn
async def check_chain_exploit_readiness(
    input: ActivityInput,
) -> dict[str, Any]:
    """Check if chain exploitation is worth attempting.

    Returns {"should_chain": True, "types_with_findings": N} if at least
    2 vulnerability types have confirmed findings in findings_index.json.
    """
    findings_path = Path(input.repo_path) / "deliverables" / "findings_index.json"

    if not findings_path.is_file():
        return {"should_chain": False, "types_with_findings": 0}

    try:
        async with aiofiles.open(findings_path, mode="r", encoding="utf-8") as f:
            content = await f.read()
        index = json.loads(content)

        by_type = index.get("by_type", {})
        # Gate on DEMONSTRATED findings only: live-exploited, OR code-only
        # harness-confirmed. Plain `potential` (blocked / not_testable / static
        # trace) is NOT a demonstration and must not pull a whole type into the
        # chain search — chaining off unproven findings was a false-positive
        # amplifier. (Suppressed/unconfirmed never count.)
        def _demonstrated(v: dict[str, Any]) -> bool:
            return (
                str(v.get("status", "")).lower() == "exploited"
                or v.get("harness_confirmed") is True
            )

        def _has_demonstrated(vulns: Any) -> bool:
            return isinstance(vulns, list) and any(
                isinstance(v, dict) and _demonstrated(v) for v in vulns
            )

        types_with_findings = sum(1 for vulns in by_type.values() if _has_demonstrated(vulns))

        should_chain = types_with_findings >= 2
        logger.info(
            "Chain exploit readiness: %d types with CONFIRMED findings (need >= 2)",
            types_with_findings,
        )
        return {
            "should_chain": should_chain,
            "types_with_findings": types_with_findings,
        }

    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read findings_index for chain check: %s", exc)
        return {"should_chain": False, "types_with_findings": 0}


# ---------------------------------------------------------------------------
# Read detected technologies from pre-recon deliverable
# ---------------------------------------------------------------------------

@activity.defn
async def read_detected_technologies(
    input: ActivityInput,
) -> dict[str, Any]:
    """Parse the pre-recon deliverable for detected_technologies.

    Reads shared_context.json (populated by pre-recon agent) and extracts
    technology detection flags used for conditional agent enablement
    (GraphQL, WebSocket).

    Returns a dict with boolean flags, e.g.:
        {"graphql": True, "websocket": False}
    """
    from src.services.shared_context import SharedContextManager

    ctx_manager = SharedContextManager()
    context = await ctx_manager.read(input.repo_path)
    tech_stack = context.get("tech_stack", {})

    # Build detection flags from tech stack
    detected: dict[str, Any] = {
        "graphql": bool(tech_stack.get("graphql")),
        "websocket": bool(tech_stack.get("websocket") or tech_stack.get("websockets")),
    }

    # Also check for explicit detected_technologies key
    detected_tech = context.get("detected_technologies", {})
    if detected_tech:
        detected["graphql"] = detected["graphql"] or bool(
            detected_tech.get("graphql")
        )
        detected["websocket"] = detected["websocket"] or bool(
            detected_tech.get("websocket") or detected_tech.get("websockets")
        )

    logger.info("Detected technologies: %s", detected)
    return detected


# ---------------------------------------------------------------------------
# Findings aggregation
# ---------------------------------------------------------------------------

@activity.defn
async def aggregate_findings(input: ActivityInput) -> None:
    """Aggregate all exploitation queue files into a unified findings_index.json.

    Called between vulnerability analysis and exploitation phases so exploit
    agents have cross-type awareness. Also called as final aggregation before
    remediation to ensure all queue data is captured.
    """
    import shutil
    from src.services.findings_aggregator import FindingsAggregator

    # Restore queue files from workspace if missing in repo (resume scenario).
    workspace_deliverables = _get_workspace_deliverables_path(input)
    repo_deliverables = Path(input.repo_path) / "deliverables"
    if workspace_deliverables and workspace_deliverables.is_dir():
        repo_deliverables.mkdir(parents=True, exist_ok=True)
        for item in workspace_deliverables.iterdir():
            if item.is_file() and item.name.endswith("_exploitation_queue.json"):
                dest = repo_deliverables / item.name
                if not dest.exists():
                    shutil.copy2(item, dest)
                    logger.info("Restored queue file %s from workspace", item.name)

    aggregator = FindingsAggregator()
    await aggregator.aggregate_and_write(input.repo_path)


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
    the exploit agent built (exit 0 = still vulnerable, non-zero = fixed), and
    writes verified=pass|fail|not_tested + verify_method back into the manifest.
    Falls back to a build check when no harness exists. Non-fatal.
    """
    from src.services.patch_verify import verify_patches as _verify

    return await _verify(input.repo_path)


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

@activity.defn
async def assemble_report(input: ActivityInput) -> None:
    """Restore deliverables before the report agent runs.

    The report agent (LLM) now authors the full report from raw evidence
    files. The Python assembler is disabled but kept in reporting.py for
    reference or fallback.
    """
    import shutil

    # Restore deliverables from workspace before assembly.
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
            logger.info("Restored %d missing deliverables before report assembly", restored)

    # Python assembler disabled — the report agent (LLM) now writes the
    # full report from raw evidence files. To re-enable:
    #
    #   from src.services.reporting import assemble_structured_report
    #   config = await _load_config(input.config_path)
    #   description = config.get("description") if config else None
    #   await assemble_structured_report(
    #       repo_path=input.repo_path,
    #       web_url=input.web_url,
    #       description=description,
    #   )


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
# Rebuild git from upstream (before remediation)
# ---------------------------------------------------------------------------

@activity.defn
async def rebuild_git(input: ActivityInput) -> bool:
    """Rebuild git from the upstream remote before remediation.

    Replaces the preflight-created .git with a clone of the real upstream,
    giving fix branches correct ancestry for direct push. Non-fatal: if
    rebuild fails, remediation still runs but branches cannot be pushed.
    """
    from src.services.git_push import rebuild_git_from_remote

    try:
        return await rebuild_git_from_remote(input.repo_path)
    except Exception as exc:
        logger.warning("Git rebuild failed (non-fatal): %s", exc)
        return False


# ---------------------------------------------------------------------------
# Export fix branches as .patch files
# ---------------------------------------------------------------------------

@activity.defn
async def export_patches(input: ActivityInput) -> dict[str, Any]:
    """Export all fix/* branches as .patch files into deliverables/patches/.

    Always runs after remediation — patches persist to the host via the
    deliverables symlink regardless of push configuration.
    """
    try:
        from src.services.patch_export import export_patches as do_export

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
# Push fix branches to upstream
# ---------------------------------------------------------------------------

@activity.defn
async def push_fix_branches(input: ActivityInput) -> dict[str, Any]:
    """Push fix/* branches to the upstream git remote.

    Opt-in via VIGILO_PUSH_BRANCHES=true (set by make scan PUSH=1).
    Non-fatal: returns empty result if not configured or push fails.
    """
    try:
        from src.services.git_push import push_fix_branches as do_push

        result = await do_push(input.repo_path)
        if result.get("pushed"):
            logger.info(
                "Pushed %d fix branches to upstream",
                len(result["pushed"]),
            )
        return result
    except Exception as exc:
        logger.warning("Failed to push fix branches: %s", exc)
        return {"pushed": [], "failed": [], "skipped": False, "error": str(exc)[:500]}


# ---------------------------------------------------------------------------
# GitLab Merge Request creation
# ---------------------------------------------------------------------------

@activity.defn
async def create_merge_request(
    input: ActivityInput,
    pushed_branches: list[str] | None = None,
) -> dict[str, Any]:
    """Create GitLab MRs for remediation patches — one MR per fix branch.

    Each MR includes a rich description with vulnerability metadata,
    evidence excerpts, and screenshot references.

    Parameters
    ----------
    pushed_branches:
        Branch names successfully pushed by push_fix_branches (e.g.
        ["fix/AUTH-VULN-01"]).

    Returns dict with created/failed MR lists. Non-fatal: returns empty
    result if GITLAB_TOKEN is not configured or no branches provided.
    """
    import os

    if not os.environ.get("GITLAB_TOKEN"):
        logger.info("GITLAB_TOKEN not set — skipping MR creation")
        return {"created": [], "failed": [], "total": 0}

    if not pushed_branches:
        logger.info("No pushed branches — skipping MR creation")
        return {"created": [], "failed": [], "total": 0}

    try:
        from src.services.gitlab_mr import create_remediation_mrs

        result = await create_remediation_mrs(
            input.repo_path, input.session_id, pushed_branches
        )
        created = result.get("created", [])
        if created:
            logger.info(
                "Created %d GitLab MR(s): %s",
                len(created),
                [mr["mr_url"] for mr in created],
            )
        return result
    except Exception as exc:
        logger.warning("Failed to create GitLab MRs: %s", exc)
        return {"created": [], "failed": [], "total": 0, "error": str(exc)[:500]}


# ---------------------------------------------------------------------------
# Phase transition logging
# ---------------------------------------------------------------------------

@activity.defn
async def log_phase_transition(
    input: ActivityInput, phase: str, event: str
) -> None:
    """Log a phase transition (start/complete) to the workflow audit log."""
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


# ---------------------------------------------------------------------------
# Resume state activities
# ---------------------------------------------------------------------------


@activity.defn
async def load_resume_state(
    input: ActivityInput, workspace_name: str
) -> dict[str, Any] | None:
    """Load resume state from an existing workspace.

    Validates workspace exists, cross-checks agent status with deliverables
    on disk, and returns the set of truly completed agents.
    """
    from src.session_manager import AGENTS

    session_path = Path(input.repo_path) / ".vigilo" / workspace_name / "session.json"

    if not session_path.is_file():
        raise ApplicationError(
            f"Workspace not found: {workspace_name}",
            type="ConfigurationError",
            non_retryable=True,
        )

    try:
        async with aiofiles.open(session_path, mode="r", encoding="utf-8") as f:
            content = await f.read()
        session = json.loads(content)
    except Exception as exc:
        raise ApplicationError(
            f"Corrupted session.json in workspace {workspace_name}: {exc}",
            type="ConfigurationError",
            non_retryable=True,
        )

    # Validate URL match
    session_url = (
        session.get("session", {}).get("webUrl")
        or session.get("session", {}).get("web_url")
    )
    if session_url and session_url != input.web_url:
        raise ApplicationError(
            f"URL mismatch: workspace={session_url}, provided={input.web_url}",
            type="ConfigurationError",
            non_retryable=True,
        )

    # Restore deliverables from workspace into repo working directory.
    # On a fresh container /repos/target/deliverables/ is empty because the
    # build excludes it. The persisted copies live in .vigilo/<workspace>/deliverables/.
    # Set up the same symlink as preflight so new writes land directly on the mount.
    workspace_deliverables = Path(input.repo_path) / ".vigilo" / workspace_name / "deliverables"
    repo_deliverables = Path(input.repo_path) / "deliverables"
    if workspace_deliverables.is_dir():
        import shutil

        # Replace repo deliverables dir with a symlink to the workspace copy,
        # matching the preflight setup so future writes persist immediately.
        if repo_deliverables.is_symlink():
            repo_deliverables.unlink()
        elif repo_deliverables.is_dir():
            shutil.rmtree(repo_deliverables)
        workspace_deliverables.mkdir(parents=True, exist_ok=True)
        (workspace_deliverables / "screenshots").mkdir(exist_ok=True)
        repo_deliverables.symlink_to(workspace_deliverables)
        logger.info(
            "Restored %d deliverables from workspace (symlinked)",
            sum(1 for _ in workspace_deliverables.iterdir()),
        )

    # Cross-check agent status with deliverables on disk.
    # An agent is considered complete if its deliverable exists, regardless of
    # session.json status (which may be stale if the process was interrupted
    # between deliverable write and status update).
    completed_agents: list[str] = []
    agents_data = session.get("metrics", {}).get("agents", {})

    for agent_name in agents_data:
        agent_def = AGENTS.get(agent_name)
        if agent_def is None:
            continue

        deliverable_path = (
            Path(input.repo_path) / "deliverables" / agent_def.deliverable_filename
        )
        if deliverable_path.is_file():
            completed_agents.append(agent_name)
        else:
            status = agents_data[agent_name].get("status", "unknown")
            if status == "success":
                logger.warning(
                    "Agent %s shows success but deliverable missing, will re-run",
                    agent_name,
                )
            else:
                logger.info(
                    "Agent %s (status=%s) has no deliverable, will re-run",
                    agent_name, status,
                )

    # Find latest checkpoint hash
    checkpoints = [
        agents_data[name].get("checkpoint")
        for name in completed_agents
        if agents_data.get(name, {}).get("checkpoint")
    ]
    checkpoint_hash = checkpoints[-1] if checkpoints else None

    original_workflow_id = (
        session.get("session", {}).get("originalWorkflowId")
        or session.get("session", {}).get("id", "")
    )

    logger.info(
        "Resume state loaded: %d completed agents, checkpoint=%s",
        len(completed_agents),
        checkpoint_hash,
    )

    return {
        "workspace_name": workspace_name,
        "completed_agents": completed_agents,
        "checkpoint_hash": checkpoint_hash,
        "original_workflow_id": original_workflow_id,
    }


@activity.defn
async def restore_git_checkpoint(
    input: ActivityInput, checkpoint_hash: str, incomplete_agents: list[str]
) -> None:
    """Restore git workspace to a checkpoint and clean up partial deliverables."""
    from src.services.git_manager import execute_git_command
    from src.session_manager import AGENTS

    logger.info("Restoring git workspace to %s", checkpoint_hash)

    await execute_git_command(
        ["git", "reset", "--hard", checkpoint_hash],
        input.repo_path,
        "reset to checkpoint for resume",
    )
    await execute_git_command(
        ["git", "clean", "-fd"],
        input.repo_path,
        "clean untracked files for resume",
    )

    # Clean up partial deliverables from incomplete agents
    for agent_name in incomplete_agents:
        agent_def = AGENTS.get(agent_name)
        if agent_def is None:
            continue
        deliverable_path = (
            Path(input.repo_path) / "deliverables" / agent_def.deliverable_filename
        )
        if deliverable_path.exists():
            logger.warning("Cleaning partial deliverable: %s", agent_name)
            deliverable_path.unlink()

    logger.info("Workspace restored to clean state")


@activity.defn
async def record_resume_attempt(
    input: ActivityInput,
    terminated_workflows: list[str],
    checkpoint_hash: str,
    previous_workflow_id: str,
    completed_agents: list[str],
) -> None:
    """Record a resume attempt in session.json and workflow.log."""
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

    await audit.add_resume_attempt(
        input.workflow_id, terminated_workflows, checkpoint_hash
    )
    await audit.log_resume_header({
        "previous_workflow_id": previous_workflow_id,
        "new_workflow_id": input.workflow_id,
        "checkpoint_hash": checkpoint_hash,
        "completed_agents": completed_agents,
    })
