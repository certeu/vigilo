"""Execution engine interface + shared run preparation helpers.

An engine is responsible for taking a queued Run and (a) launching the Vigilo
pipeline for it, (b) reporting status, and (c) cancelling it. The API layer talks
only to this Protocol, so the Docker+Temporal engine and the in-memory fake used by
tests are fully interchangeable.
"""
from __future__ import annotations

import uuid
from typing import Protocol, runtime_checkable

from src.types.stages import stages_for_preset
from src.webapi.models import Job, Repository, Run


@runtime_checkable
class ExecutionEngine(Protocol):
    """Launch/observe/cancel a pipeline run. Implementations MUTATE the passed
    Run (setting workflow_id/task_queue/container_id/status/current_phase); the
    caller is responsible for committing the change."""

    async def start(self, run: Run, job: Job, repo: Repository) -> None: ...

    async def cancel(self, run: Run) -> None: ...

    async def refresh(self, run: Run) -> None: ...


def new_run_identity() -> tuple[uuid.UUID, str, str]:
    """Return (run_id, session_id, task_queue) for a fresh run."""
    run_id = uuid.uuid4()
    short = run_id.hex[:12]
    return run_id, f"web-{short}", f"vigilo-{short}"


def build_stages_payload(job: Job) -> dict:
    """Materialize the job's preset into the flag-dict passed as PipelineInput.stages.

    Goes through stages_for_preset so the invariants (exploit welded to vuln,
    critique always on) are applied here too — the API never sends a raw preset the
    workflow would have to trust blindly.
    """
    sel = stages_for_preset(job.stage_preset)
    return {
        "run_vuln": sel.run_vuln,
        "run_sca": sel.run_sca,
        "run_integrity": sel.run_integrity,
        "run_chain": sel.run_chain,
        "run_critique": sel.run_critique,
        "run_remediation": sel.run_remediation,
    }
