"""Grey-box Temporal worker + client entry point.

Starts a worker on the vigilo-greybox task queue, submits a
GreyBoxPipelineWorkflow, waits for the result, and exits.

Usage:
    python -m src.greybox.temporal.worker --url http://target --creds creds.yaml

Options:
    --url <target_url>     Target URL to test (required)
    --creds <path>         Path to YAML credentials file (required)
    --config <path>        Path to grey-box YAML config file
    --output <path>        Override output directory
    --workspace <name>     Resume from existing workspace
    --task-queue <name>    Temporal task queue (default: vigilo-greybox)
    --help                 Show this help message

Environment:
    TEMPORAL_ADDRESS       Temporal server address (default: localhost:7233)
    SURREALDB_URL          SurrealDB connection URL
    GREYBOX_MODE           Set automatically to 'true' (E30)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Worker

from src.greybox.temporal.workflows import (
    AgentExecutionWorkflow,
    GreyBoxPipelineWorkflow,
)
from src.greybox.temporal.activities import (
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
from src.greybox.types.config import GreyBoxConfig, GreyBoxInput
from src.greybox.services.credentials import load_identities

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# All activity functions (collected for worker registration)
# ---------------------------------------------------------------------------

ALL_ACTIVITIES = [
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
]


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Exposed as a standalone function for testability.
    """
    parser = argparse.ArgumentParser(
        description="Vigilo Grey-Box Pipeline Worker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m src.greybox.temporal.worker "
            "--url http://target --creds configs/creds.yaml\n"
            "  python -m src.greybox.temporal.worker "
            "--url http://target --creds creds.yaml --config gb-config.yaml\n"
            "  python -m src.greybox.temporal.worker "
            "--url http://target --creds creds.yaml --workspace gb-myhost-1713200000\n"
        ),
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL to test",
    )
    parser.add_argument(
        "--creds",
        required=True,
        help="Path to YAML credentials file",
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        default=None,
        help="Path to grey-box YAML configuration file",
    )
    parser.add_argument(
        "--output",
        dest="output_path",
        default=None,
        help="Override output directory",
    )
    parser.add_argument(
        "--workspace",
        dest="resume_workspace",
        default=None,
        help="Resume from an existing workspace name",
    )
    parser.add_argument(
        "--task-queue",
        default="vigilo-greybox",
        help="Temporal task queue name (default: vigilo-greybox)",
    )
    return parser


# ---------------------------------------------------------------------------
# Session ID generation
# ---------------------------------------------------------------------------


def _generate_session_id() -> str:
    """Generate a grey-box session ID: gb-{hostname[:12]}-{timestamp}."""
    hostname = socket.gethostname()[:12]
    ts = int(time.time())
    return f"gb-{hostname}-{ts}"


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

    # E30: mark grey-box mode
    os.environ["GREYBOX_MODE"] = "true"

    # Parse CLI arguments
    parser = build_parser()
    args = parser.parse_args()

    # Load config from YAML if provided
    config = GreyBoxConfig()
    config_raw: dict[str, Any] = {}
    if args.config_path:
        config_path = Path(args.config_path)
        if not config_path.exists():
            print(f"ERROR: Config file not found: {args.config_path}", file=sys.stderr)
            sys.exit(1)
        config = GreyBoxConfig.from_yaml(config_path)
        config_raw = yaml.safe_load(config_path.read_text()) or {}

    # Load identities from credentials YAML
    creds_path = Path(args.creds)
    if not creds_path.exists():
        print(f"ERROR: Credentials file not found: {args.creds}", file=sys.stderr)
        sys.exit(1)
    identities = load_identities(creds_path)

    # Generate session ID
    session_id = _generate_session_id()
    if args.resume_workspace:
        session_id = args.resume_workspace

    # Build workflow input
    gb_input = GreyBoxInput(
        web_url=args.url,
        session_id=session_id,
        credentials_path=args.creds,
        config_path=args.config_path,
        output_path=args.output_path,
        description=config_raw.get("target", {}).get("description", ""),
        rules_avoid=config_raw.get("scope", {}).get("rules_avoid", []),
        rules_focus=config_raw.get("scope", {}).get("rules_focus", []),
        config=config,
        identities=identities,
        resume_phase=None if not args.resume_workspace else "resume",
    )

    from src.ai.executor import get_executor_type
    executor_type = get_executor_type()
    pipeline_workflow = GreyBoxPipelineWorkflow

    # Connect to Temporal server
    address = os.environ.get("TEMPORAL_ADDRESS", "localhost:7233")
    print(f"Connecting to Temporal at {address}...")
    client = await Client.connect(address, data_converter=pydantic_data_converter)

    # Build workflow ID
    workflow_id = f"greybox-{session_id}"

    # Create and start worker
    print(f"Starting worker on task queue: {args.task_queue}")
    print(f"Session: {session_id}")
    print(f"Target: {args.url}")
    print(f"Identities: {[i.name for i in identities]}")
    print(f"Pipeline: full (multi-agent) (executor={executor_type})")

    worker = Worker(
        client,
        task_queue=args.task_queue,
        workflows=[GreyBoxPipelineWorkflow, AgentExecutionWorkflow],
        activities=ALL_ACTIVITIES,
    )

    # Start worker in background
    worker_task = asyncio.create_task(worker.run())

    try:
        # Submit workflow
        handle = await client.start_workflow(
            pipeline_workflow.run,
            gb_input,
            id=workflow_id,
            task_queue=args.task_queue,
        )

        print(f"Workflow started: {workflow_id}")
        if args.resume_workspace:
            print(f"Resuming from workspace: {args.resume_workspace}")

        try:
            # Wait for workflow result
            result = await handle.result()

            print("\nGrey-box pipeline completed!")
            if isinstance(result, dict):
                findings = result.get("findings_count", 0)
                cost = result.get("total_cost_usd", 0.0)
                duration = result.get("total_duration_ms", 0) // 1000
                print(f"Findings: {findings}")
                print(f"Duration: {duration}s")
                print(f"Cost: ${cost:.4f}")

        except Exception as exc:
            print(f"\nPipeline failed: {exc}", file=sys.stderr)
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
