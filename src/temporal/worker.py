"""Combined Temporal worker + client for Vigilo pentest pipeline.

Starts a worker on a per-invocation task queue, submits a workflow,
waits for the result, and exits. Designed to run as a single ephemeral
container per scan.

Usage:
    python -m src.temporal.worker <repo_path> [options]

Options:
    --url <target_url>     Target URL to test (optional; also reads TARGET_URL env var)
    --task-queue <name>    Task queue name (required, unique per scan)
    --config <path>        Configuration file path
    --output <path>        Override output directory (default: repo/.vigilo/)
    --workspace <name>     Resume from existing workspace
    --help                 Show this help message

Environment:
    TEMPORAL_ADDRESS - Temporal server address (default: localhost:7233)
    TARGET_URL       - Target URL to test (alternative to --url flag)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from temporalio.client import Client
from temporalio.worker import Worker

from src.temporal import activities
from src.temporal.workflows import PentestPipelineWorkflow

logger = logging.getLogger(__name__)

# Progress query interval in seconds
PROGRESS_POLL_INTERVAL_S = 30


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Vigilo Pipeline Worker — combined Temporal worker + client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m src.temporal.worker /path/to/repo "
            "--url http://target --task-queue scan-001\n"
            "  python -m src.temporal.worker /path/to/repo "
            "--task-queue scan-002 --config config.yaml\n"
            "  python -m src.temporal.worker /path/to/repo "
            "--task-queue scan-003  # code-only, no target URL\n"
        ),
    )
    parser.add_argument(
        "repo_path", nargs="?", default=None,
        help="Path to the repository under test (omit in --serve mode)",
    )
    parser.add_argument(
        "--url",
        dest="web_url",
        default=os.environ.get("TARGET_URL", ""),
        help="Target URL to test (optional; also reads TARGET_URL env var)",
    )
    parser.add_argument(
        "--task-queue",
        required=True,
        help="Temporal task queue name (must be unique per scan)",
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--output",
        dest="output_path",
        help="Override output directory (default: repo/.vigilo/)",
    )
    parser.add_argument(
        "--workspace",
        dest="resume_workspace",
        help="Resume from an existing workspace name",
    )
    parser.add_argument(
        "--stages",
        dest="stages",
        default=None,
        help=(
            "Stage selection: a preset name (vuln|vuln_patch|full) or a JSON "
            "flag-dict. Omit for the full pipeline (legacy behavior)."
        ),
    )
    parser.add_argument(
        "--session-id",
        dest="session_id",
        default=None,
        help=(
            "Force the session/workflow id (platform use). When set, overrides the "
            "auto-generated hostname-timestamp id so outputs land at a known path."
        ),
    )
    parser.add_argument(
        "--serve",
        dest="serve",
        action="store_true",
        default=False,
        help=(
            "Persistent-worker mode (platform use): host the pipeline workflow + "
            "activities on --task-queue and run forever WITHOUT starting a workflow. "
            "The API starts workflows on this queue via the Temporal client."
        ),
    )
    return parser


# ---------------------------------------------------------------------------
# Hostname sanitization
# ---------------------------------------------------------------------------


def sanitize_hostname(url: str) -> str:
    """Extract and sanitize hostname from a URL for use in identifiers."""
    parsed = urlparse(url)
    hostname = parsed.hostname or "unknown"
    # Replace dots and colons with hyphens for Temporal workflow ID compatibility
    return hostname.replace(".", "-").replace(":", "-")


# ---------------------------------------------------------------------------
# Workspace resolution
# ---------------------------------------------------------------------------


def _is_valid_workspace_name(name: str) -> bool:
    """Validate workspace name: alphanumeric, hyphens, underscores, 1-128 chars."""
    import re

    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$", name))


async def _terminate_existing_workflows(
    client: Client, session_data: dict[str, Any]
) -> list[str]:
    """Terminate any still-running workflows from a previous session.

    Reads workflow IDs from session.json (original + resume attempts) and
    terminates any that are still RUNNING. Returns list of terminated IDs.
    """
    terminated: list[str] = []

    # Collect all workflow IDs from previous session
    workflow_ids: list[str] = []
    original_id = session_data.get("session", {}).get("originalWorkflowId") or session_data.get("session", {}).get("id", "")
    if original_id:
        workflow_ids.append(original_id)
    for attempt in session_data.get("session", {}).get("resumeAttempts", []):
        wf_id = attempt.get("workflowId") or attempt.get("workflow_id")
        if wf_id:
            workflow_ids.append(wf_id)

    for wf_id in workflow_ids:
        try:
            handle = client.get_workflow_handle(wf_id)
            desc = await handle.describe()
            if desc.status and desc.status.name == "RUNNING":
                await handle.terminate(reason="Superseded by resume")
                terminated.append(wf_id)
                logger.info("Terminated previous workflow: %s", wf_id)
        except Exception as exc:
            logger.debug("Could not check/terminate workflow %s: %s", wf_id, exc)

    return terminated


async def _resolve_workspace(
    args: argparse.Namespace,
    client: Client | None = None,
) -> tuple[str, str, bool, list[str]]:
    """Resolve workspace name, workflow ID, and session ID.

    Returns:
        (workflow_id, session_id, is_resume, terminated_workflows)
    """
    terminated_workflows: list[str] = []

    if not args.resume_workspace:
        # New run: generate workflow ID from hostname + timestamp
        hostname = sanitize_hostname(args.web_url) if args.web_url else "code-only"
        ts = int(time.time() * 1000)
        workflow_id = f"{hostname}_vigilo-{ts}"
        return workflow_id, workflow_id, False, terminated_workflows

    workspace = args.resume_workspace
    session_path = Path(args.repo_path) / ".vigilo" / workspace / "session.json"

    if session_path.is_file():
        # Resume mode: workspace exists
        print("=== RESUME MODE ===")
        print(f"Workspace: {workspace}\n")

        # Load session to validate URL match
        with open(session_path, "r", encoding="utf-8") as f:
            session_data = json.load(f)

        session_url = session_data.get("session", {}).get("webUrl") or session_data.get("session", {}).get("web_url")
        if session_url and session_url != args.web_url:
            print("ERROR: URL mismatch with workspace", file=sys.stderr)
            print(f"  Workspace URL: {session_url}", file=sys.stderr)
            print(f"  Provided URL:  {args.web_url}", file=sys.stderr)
            sys.exit(1)

        # Terminate any still-running workflows from the previous session
        if client:
            terminated_workflows = await _terminate_existing_workflows(client, session_data)
            if terminated_workflows:
                print(f"Terminated {len(terminated_workflows)} previous workflow(s)")

        ts = int(time.time() * 1000)
        workflow_id = f"{workspace}_resume_{ts}"
        return workflow_id, workspace, True, terminated_workflows

    # New named workspace
    if not _is_valid_workspace_name(workspace):
        print(
            f'ERROR: Invalid workspace name: "{workspace}"',
            file=sys.stderr,
        )
        print(
            "  Must be 1-128 characters, alphanumeric/hyphens/underscores, "
            "starting with alphanumeric",
            file=sys.stderr,
        )
        sys.exit(1)

    print("=== NEW NAMED WORKSPACE ===")
    print(f"Workspace: {workspace}\n")

    # Avoid double _vigilo- suffix
    import re

    if re.search(r"_vigilo-\d+$", workspace):
        workflow_id = workspace
    else:
        ts = int(time.time() * 1000)
        workflow_id = f"{workspace}_vigilo-{ts}"

    return workflow_id, workspace, False, terminated_workflows


# ---------------------------------------------------------------------------
# Pipeline config loading
# ---------------------------------------------------------------------------


async def _load_pipeline_config(
    config_path: str | None,
) -> dict[str, Any]:
    """Load pipeline-specific configuration from the YAML config file."""
    if not config_path:
        return {}

    try:
        import yaml
        import aiofiles

        async with aiofiles.open(config_path, mode="r", encoding="utf-8") as f:
            content = await f.read()
        config = yaml.safe_load(content)

        pipeline = config.get("pipeline") if config else None
        if not pipeline:
            return {}

        result: dict[str, Any] = {}
        if "retry_preset" in pipeline:
            result["retry_preset"] = pipeline["retry_preset"]
        if "max_concurrent_pipelines" in pipeline:
            result["max_concurrent_pipelines"] = int(
                pipeline["max_concurrent_pipelines"]
            )
        return result
    except Exception as exc:
        logger.warning("Failed to load pipeline config from %s: %s", config_path, exc)
        return {}


# ---------------------------------------------------------------------------
# Pipeline input construction
# ---------------------------------------------------------------------------


def _build_pipeline_input(
    args: argparse.Namespace,
    workflow_id: str,
    session_id: str,
    is_resume: bool,
    terminated_workflows: list[str],
    pipeline_config: dict[str, Any],
) -> dict[str, Any]:
    """Build the PipelineInput dict for the workflow."""
    input_data: dict[str, Any] = {
        "web_url": args.web_url,
        "repo_path": args.repo_path,
        "workflow_id": workflow_id,
        "session_id": session_id,
    }

    if args.config_path:
        input_data["config_path"] = args.config_path
    if args.output_path:
        input_data["output_path"] = args.output_path
    if is_resume and args.resume_workspace:
        input_data["resume_from_workspace"] = args.resume_workspace
    if terminated_workflows:
        input_data["terminated_workflows"] = terminated_workflows
    if pipeline_config:
        input_data["pipeline_config"] = pipeline_config
    stages = getattr(args, "stages", None)
    if stages:
        # Accept a JSON flag-dict or a bare preset name; the workflow's
        # resolve_stages() handles both. Only attach when provided so the
        # default remains the full pipeline.
        try:
            input_data["stages"] = json.loads(stages)
        except (ValueError, TypeError):
            input_data["stages"] = stages

    return input_data


# ---------------------------------------------------------------------------
# Progress polling
# ---------------------------------------------------------------------------


async def _poll_progress(handle: Any, interval: int = PROGRESS_POLL_INTERVAL_S) -> None:
    """Periodically query workflow progress and print status updates.

    Elapsed time is wall-clock (measured here), NOT the workflow's ``elapsed_ms``:
    that value is Temporal workflow-time, which freezes while the workflow is
    parked ``await``-ing long-running activities — so a perfectly healthy run
    would otherwise appear stuck at the same second. ``current_phase`` /
    ``current_agent`` still reflect the last state set before such an ``await``
    (e.g. one of several agents running concurrently), which is why they can lag.
    """
    start = time.monotonic()
    consecutive_errors = 0
    while True:
        await asyncio.sleep(interval)
        elapsed = int(time.monotonic() - start)
        try:
            progress = await handle.query(
                PentestPipelineWorkflow.get_progress
            )
            consecutive_errors = 0
            phase = progress.get("current_phase") or "unknown"
            agent = progress.get("current_agent") or "none"
            completed = len(progress.get("completed_agents", []) or [])
            failed = progress.get("failed_agent")
            suffix = f" | Failed: {failed}" if failed else ""
            print(
                f"[{elapsed}s] Phase: {phase} | Agent: {agent} | "
                f"Completed: {completed}{suffix}"
            )
        except Exception as e:
            # Workflow may have completed, or a query timed out mid-activity.
            # Don't swallow silently forever — surface it periodically.
            consecutive_errors += 1
            if consecutive_errors in (1, 10, 50):
                logger.debug(
                    "progress query failed (%dx): %s", consecutive_errors, e
                )


# ---------------------------------------------------------------------------
# Deliverables copy
# ---------------------------------------------------------------------------


def _copy_deliverables(repo_path: str, output_path: str) -> None:
    """Copy deliverables from the repo to the output directory."""
    deliverables_dir = Path(repo_path) / "deliverables"
    if not deliverables_dir.is_dir():
        print("No deliverables directory found, skipping copy")
        return

    files = list(deliverables_dir.iterdir())
    if not files:
        print("No deliverables to copy")
        return

    output = Path(output_path)
    output.mkdir(parents=True, exist_ok=True)

    for item in files:
        dest = output / item.name
        if item.is_dir():
            shutil.copytree(item, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest)

    print(f"Copied {len(files)} deliverable(s) to {output_path}")


# ---------------------------------------------------------------------------
# All activity functions (collected for worker registration)
# ---------------------------------------------------------------------------

ALL_ACTIVITIES = [
    activities.run_agent,
    activities.preflight_validation,
    activities.check_exploitation_queue,
    activities.check_needs_more_info,
    activities.cleanup_needs_more_info,
    activities.backup_exploitation_queue,
    activities.merge_exploitation_queue_backup,
    activities.check_chain_exploit_readiness,
    activities.read_detected_technologies,
    activities.aggregate_findings,
    activities.audit_critique,
    activities.verify_patches,
    activities.assemble_report,
    activities.inject_report_metadata,
    activities.log_phase_transition,
    activities.log_workflow_complete,
    activities.load_resume_state,
    activities.restore_git_checkpoint,
    activities.record_resume_attempt,
    activities.rebuild_git,
    activities.export_patches,
    activities.create_merge_request,
    activities.push_fix_branches,
]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    """Parse CLI args, start Temporal worker, submit workflow, wait for result."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Parse CLI arguments
    parser = _build_parser()
    args = parser.parse_args()

    # Connect to Temporal server
    address = os.environ.get("TEMPORAL_ADDRESS", "localhost:7233")
    print(f"Connecting to Temporal at {address}...")

    client = await Client.connect(address)

    # Persistent-worker mode (platform): host the workflow + activities on the shared
    # task queue and run forever. The API starts workflows via the Temporal client.
    if getattr(args, "serve", False):
        print(f"Serving pipeline worker on task queue: {args.task_queue}")
        worker = Worker(
            client,
            task_queue=args.task_queue,
            workflows=[PentestPipelineWorkflow],
            activities=ALL_ACTIVITIES,
        )
        await worker.run()
        return

    # Resolve workspace (pass client for workflow termination on resume)
    workflow_id, session_id, is_resume, terminated_workflows = (
        await _resolve_workspace(args, client=client)
    )

    # Platform override: force a known session/workflow id so outputs land at a
    # predictable path (.vigilo/<session_id>/) the API can tail for logs/report.
    if getattr(args, "session_id", None):
        workflow_id = args.session_id
        session_id = args.session_id

    # Load pipeline config
    pipeline_config = await _load_pipeline_config(args.config_path)

    # Build pipeline input
    input_data = _build_pipeline_input(
        args,
        workflow_id,
        session_id,
        is_resume,
        terminated_workflows,
        pipeline_config,
    )

    # Create and start worker
    print(f"Starting worker on task queue: {args.task_queue}")

    worker = Worker(
        client,
        task_queue=args.task_queue,
        workflows=[PentestPipelineWorkflow],
        activities=ALL_ACTIVITIES,
    )

    # Start worker in background
    worker_task = asyncio.create_task(worker.run())

    try:
        # Submit workflow
        handle = await client.start_workflow(
            PentestPipelineWorkflow.run,
            input_data,
            id=workflow_id,
            task_queue=args.task_queue,
        )

        print(f"Workflow started: {workflow_id}")
        if is_resume:
            print(f"Resuming from workspace: {args.resume_workspace}")

        # Start progress polling in background
        progress_task = asyncio.create_task(_poll_progress(handle))

        try:
            # Wait for workflow result
            result = await handle.result()
            progress_task.cancel()

            print("\nPipeline completed successfully!")

            summary = result.get("summary") if isinstance(result, dict) else None
            if summary:
                duration_s = summary.get("total_duration_ms", 0) // 1000
                agent_count = summary.get("agent_count", 0)
                total_turns = summary.get("total_turns", 0)
                cost = summary.get("total_cost_usd", 0.0)

                print(f"Duration: {duration_s}s")
                print(f"Agents completed: {agent_count}")
                print(f"Total turns: {total_turns}")
                print(f"Run cost: ${cost:.4f}")

                # For resume runs, show cumulative cost from session.json
                if is_resume:
                    try:
                        session_path = (
                            Path(args.repo_path) / ".vigilo" / session_id / "session.json"
                        )
                        if session_path.is_file():
                            with open(session_path, "r", encoding="utf-8") as f:
                                session_data = json.load(f)
                            cumulative_cost = (
                                session_data.get("metrics", {}).get(
                                    "total_cost_usd", 0.0
                                )
                            )
                            print(f"Cumulative cost: ${cumulative_cost:.4f}")
                    except Exception:
                        pass  # Non-fatal

            # Copy deliverables to output directory if specified
            if args.output_path:
                _copy_deliverables(args.repo_path, args.output_path)

        except Exception as e:
            progress_task.cancel()
            print(f"\nPipeline failed: {e}", file=sys.stderr)
            sys.exit(1)

    finally:
        # Graceful shutdown
        await worker.shutdown()
        try:
            await worker_task
        except Exception:
            pass  # Worker may already have stopped


if __name__ == "__main__":
    asyncio.run(main())
