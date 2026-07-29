#!/usr/bin/env python3
"""Run the grey-box report agent standalone against a live SurrealDB.

Builds the report prompt, creates CLI shims for graph-tool and save-deliverable,
then invokes Claude directly (no Temporal). Use this to generate a report from
an existing scan session without re-running the full pipeline.

Usage:
    .venv/bin/python scripts/run_report_standalone.py \
        --session gb-92210e89a1eb-1776701240 \
        --url http://host.docker.internal:8502/ \
        [--surrealdb-url ws://localhost:8010] \
        [--model large]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import stat
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
PROMPTS_DIR = PROJECT_ROOT / "prompts"

SURREALDB_DEFAULTS = {
    "url": "ws://localhost:8010",
    "user": "root",
    "password": "changeme",
}


async def build_graph_summary(session_id: str, db_url: str) -> str:
    """Query node counts from the live graph."""
    from surrealdb import AsyncSurreal

    tables = [
        "page", "endpoint", "parameter", "technology",
        "finding", "lead", "test_attempt",
    ]
    surreal = AsyncSurreal(db_url)
    async with surreal as db:
        await db.signin({
            "username": SURREALDB_DEFAULTS["user"],
            "password": SURREALDB_DEFAULTS["password"],
        })
        await db.use("vigilo", session_id)

        counts = []
        for table in tables:
            raw = await db.query(f"SELECT count() AS c FROM {table} GROUP ALL")
            result = raw[0]["result"] if raw and isinstance(raw[0], dict) and "result" in raw[0] else raw
            c = result[0]["c"] if result and isinstance(result, list) and result else 0
            counts.append(f"{table}: {c}")

    return "Node counts: " + ", ".join(counts)


async def build_prompt(
    web_url: str, session_id: str, db_url: str,
    description: str = "", rules_avoid: str = "", rules_focus: str = "",
) -> str:
    """Load, include-expand, and interpolate the report prompt template."""
    from src.services.prompt_manager import (
        _interpolate_greybox_variables,
        _process_includes,
        _read_file,
    )

    template = await _read_file(PROMPTS_DIR / "greybox" / "report.txt")
    template = await _process_includes(template, PROMPTS_DIR)

    graph_summary = await build_graph_summary(session_id, db_url)

    return _interpolate_greybox_variables(
        template,
        web_url=web_url,
        graph_summary=graph_summary,
        description=description,
        rules_avoid=rules_avoid,
        rules_focus=rules_focus,
        playwright_session="agent1",
    )


def create_cli_shims(bin_dir: Path, project_root: Path, python: str) -> None:
    """Create graph-tool and save-deliverable wrapper scripts."""
    for name, script in [
        ("graph-tool", "graph_tool.py"),
        ("save-deliverable", "save_deliverable.py"),
    ]:
        shim = bin_dir / name
        shim.write_text(
            f'#!/bin/sh\n'
            f'exec "{python}" "{project_root}/scripts/{script}" "$@"\n'
        )
        shim.chmod(shim.stat().st_mode | stat.S_IEXEC)


async def run_report(
    prompt: str,
    cwd: str,
    session_id: str,
    db_url: str,
    model_tier: str = "large",
) -> int:
    """Invoke the configured executor CLI with the report prompt."""
    from src.ai.executor import get_cli_name, get_executor_type, resolve_model

    executor_type = get_executor_type()
    model = resolve_model(model_tier)
    cli_name = get_cli_name()
    python = sys.executable

    bin_dir = Path(cwd) / ".vigilo-bin"
    bin_dir.mkdir(exist_ok=True)
    create_cli_shims(bin_dir, PROJECT_ROOT, python)

    env = os.environ.copy()
    env["SURREALDB_URL"] = db_url
    env["SURREALDB_USER"] = SURREALDB_DEFAULTS["user"]
    env["SURREALDB_PASS"] = SURREALDB_DEFAULTS["password"]
    env["SURREALDB_SESSION"] = session_id
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    if executor_type != "opencode":
        env.setdefault("CLAUDE_CODE_MAX_OUTPUT_TOKENS", "64000")

    if executor_type == "opencode":
        cmd = [
            "opencode", "run",
            "--model", model,
            "--format", "json",
            "--dangerously-skip-permissions",
            "--dir", cwd,
        ]
    else:
        cmd = [
            "claude",
            "--print",
            "--model", model,
            "--dangerously-skip-permissions",
            "--max-turns", "200",
        ]

    print(f"Executor: {cli_name}")
    print(f"Model: {model}")
    print(f"Working directory: {cwd}")
    print(f"SurrealDB: {db_url} / vigilo / {session_id}")
    print(f"graph-tool shim: {bin_dir / 'graph-tool'}")
    print("=" * 60)
    print(f"Starting {cli_name} report agent...\n")

    if executor_type == "opencode":
        cmd.append(prompt)
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd, env=env,
            stdin=asyncio.subprocess.DEVNULL,
        )
    else:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd, env=env,
            stdin=asyncio.subprocess.PIPE,
        )
        proc.stdin.write(prompt.encode())
        proc.stdin.close()

    await proc.wait()

    report_path = Path(cwd) / "deliverables" / "greybox_assessment_report.md"
    if report_path.exists():
        size = report_path.stat().st_size
        print(f"\nReport written: {report_path} ({size} bytes)")
    else:
        print(f"\nWARN: Report file not found at {report_path}")

    return proc.returncode or 0


async def main() -> int:
    parser = argparse.ArgumentParser(description="Run grey-box report agent standalone")
    parser.add_argument("--session", required=True, help="Session ID")
    parser.add_argument("--url", required=True, help="Target URL tested")
    parser.add_argument("--surrealdb-url", default=SURREALDB_DEFAULTS["url"])
    parser.add_argument("--model", default="large", help="Model tier: large/medium/small")
    parser.add_argument("--workspace", default=None, help="Override workspace directory")
    args = parser.parse_args()

    workspace = args.workspace or str(Path.cwd() / ".vigilo" / args.session)

    if not Path(workspace).exists():
        print(f"ERROR: Workspace not found: {workspace}", file=sys.stderr)
        return 1

    print(f"Building report prompt for session {args.session}...")
    prompt = await build_prompt(
        web_url=args.url,
        session_id=args.session,
        db_url=args.surrealdb_url,
    )
    print(f"Prompt built: {len(prompt)} chars")

    prompt_path = Path(workspace) / "deliverables" / "prompts" / "report-standalone-prompt.txt"
    prompt_path.parent.mkdir(parents=True, exist_ok=True)
    prompt_path.write_text(prompt)
    print(f"Prompt saved: {prompt_path}")

    return await run_report(
        prompt=prompt,
        cwd=workspace,
        session_id=args.session,
        db_url=args.surrealdb_url,
        model_tier=args.model,
    )


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
