"""Temporal-client execution engine (persistent-worker model).

The API ingests the repo onto a shared volume, then starts the real
``PentestPipelineWorkflow`` on the shared task queue via the Temporal client. A
persistent worker (compose service running `python -m src.temporal.worker --serve
--task-queue vigilo-pipeline`) executes it and writes outputs to
``{data_dir}/repo/.vigilo/{session}/`` on the same shared volume, which the API tails
for logs/report. This replaces the old `make scan` CLI path.

Temporal workflows are durable, so this engine is ``durable`` (reconciliation
re-attaches rather than fails on restart).
"""
from __future__ import annotations

import json
import logging
import os
import re

from src.webapi.engine.base import build_stages_payload
from src.webapi.models import (
    RUN_CANCELLED,
    RUN_FAILED,
    RUN_PREPARING,
    RUN_RUNNING,
    RUN_SUCCEEDED,
    Job,
    Repository,
    Run,
)
from src.webapi.settings import get_settings

logger = logging.getLogger(__name__)

# Temporal WorkflowExecutionStatus enum → Run.status
_WF_STATUS = {
    1: RUN_RUNNING, 2: RUN_SUCCEEDED, 3: RUN_FAILED,
    4: RUN_CANCELLED, 5: RUN_FAILED, 6: RUN_RUNNING, 7: RUN_FAILED,
}

_GENERIC = {"Activity task failed", "Workflow execution failed", ""}


def _unwrap_failure(exc: BaseException) -> str:
    """Walk the Temporal exception cause chain to the real reason. Temporal wraps the
    actual ApplicationError (with .type + .message, e.g. 'Target URL unreachable') inside
    ActivityError/WorkflowFailureError whose str() is just 'Activity task failed'."""
    try:
        from temporalio.exceptions import ApplicationError
    except Exception:  # pragma: no cover
        ApplicationError = ()  # type: ignore
    best, cur, depth = None, exc, 0
    while cur is not None and depth < 12:
        msg = getattr(cur, "message", None)
        if ApplicationError and isinstance(cur, ApplicationError) and msg:
            t = getattr(cur, "type", None)
            return (f"{t}: {msg}" if t else msg)[:800]
        candidate = msg or str(cur)
        if candidate and candidate not in _GENERIC and best is None:
            best = candidate
        cur = getattr(cur, "cause", None)
        depth += 1
    return (best or "Run failed (no failure detail available).")[:800]


class TemporalEngine:
    durable = True

    async def _client(self):
        from temporalio.client import Client
        return await Client.connect(get_settings().temporal_address)

    async def _resolve_token(self, credential_id) -> str | None:
        from src.webapi.db import _session_maker
        from src.webapi.models import Credential
        from src.webapi.security.vault import build_vault
        async with _session_maker()() as session:
            cred = await session.get(Credential, credential_id)
            if cred is None:
                return None
            return build_vault(get_settings()).decrypt(cred.secret_enc)

    async def start(self, run: Run, job: Job, repo: Repository) -> None:
        from src.webapi.ingestion import (
            prepare_repo,
            upload_archive_path,
            upload_tree_dir,
        )
        settings = get_settings()
        repo_dir = os.path.join(run.data_dir, "repo")
        os.makedirs(repo_dir, exist_ok=True)

        # Materialize the source (clone GitLab / extract-or-copy upload) into the
        # shared volume the worker also mounts.
        token = None
        upload_path = None
        if repo.source_type == "gitlab" and repo.default_credential_id:
            token = await self._resolve_token(repo.default_credential_id)
        if repo.source_type == "upload":
            archive = upload_archive_path(settings.uploads_dir, str(repo.id))
            tree = upload_tree_dir(settings.uploads_dir, str(repo.id))
            upload_path = archive if os.path.isfile(archive) else tree
        run.status = RUN_PREPARING
        prepare_repo(
            source_type=repo.source_type, repo_dir=repo_dir,
            upload_path=upload_path, gitlab_url=repo.gitlab_url, token=token,
        )
        # Capture (best-effort) the commit SHA the run scans + a persistent, browse-only
        # file tree — this checkout is the only place a GitLab tree exists (it's deleted
        # after the run), so grab both now.
        if repo.source_type == "gitlab":
            try:
                import subprocess
                out = subprocess.run(
                    ["git", "-C", repo_dir, "rev-parse", "HEAD"],
                    capture_output=True, text=True, timeout=15,
                )
                if out.returncode == 0 and out.stdout.strip():
                    run.commit_sha = out.stdout.strip()[:40]
            except Exception as exc:  # pragma: no cover - best-effort
                logger.warning("commit SHA capture failed for run %s: %s", run.id, exc)
        try:
            from src.webapi.repo_tree import capture_repo_tree
            capture_repo_tree(str(repo.id), repo_dir)
        except Exception as exc:  # pragma: no cover - best-effort
            logger.warning("repo tree capture failed for %s: %s", repo.id, exc)
        # The API writes the checkout as root; the worker runs as a different uid on
        # the shared volume. Make the run dir writable so the worker can create
        # .vigilo/ outputs inside it.
        for base, dirs, fnames in os.walk(run.data_dir):
            try:
                os.chmod(base, 0o777)
                for f in fnames:
                    os.chmod(os.path.join(base, f), 0o666)
            except OSError:
                pass

        scan = repo.scan_config or {}
        input_data = {
            "web_url": job.target_url or "",
            "repo_path": repo_dir,
            "session_id": run.session_id,
            "workflow_id": run.session_id,
            "stages": build_stages_payload(job),
            "description": scan.get("description", ""),
        }
        from temporalio.common import WorkflowIDConflictPolicy

        client = await self._client()
        # USE_EXISTING: if a workflow with this id is already running (e.g. start() is
        # re-fired after a transient error / retry), adopt it instead of raising
        # "Workflow execution already started" — which would mark this run failed while
        # the real execution keeps running as an untracked zombie.
        await client.start_workflow(
            "PentestPipelineWorkflow",
            input_data,
            id=run.session_id,
            task_queue=settings.temporal_task_queue,
            id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
        )
        run.workflow_id = run.session_id
        run.status = RUN_RUNNING
        run.current_phase = "preflight"
        logger.info("Started workflow %s on %s", run.session_id, settings.temporal_task_queue)

    async def refresh(self, run: Run) -> None:
        if not run.workflow_id:
            return
        try:
            client = await self._client()
            desc = await client.get_workflow_handle(run.workflow_id).describe()
            mapped = _WF_STATUS.get(getattr(desc.status, "value", None))
            if mapped:
                run.status = mapped
                # Surface the REAL failure reason (activity/application error message +
                # type) rather than the generic "Activity task failed". describe() only
                # returns the status enum — the detail is in the workflow result/cause.
                if mapped == RUN_FAILED and not run.error_summary:
                    run.error_summary = await self._failure_detail(run.workflow_id)
        except Exception as exc:  # pragma: no cover - best-effort
            logger.warning("temporal refresh failed for %s: %s", run.id, exc)
        # Best-effort current phase from the workflow.log's phase markers. The log
        # is human-readable text ("[ts] [PHASE] Starting: recon"), NOT JSON — parse
        # the marker the pipeline actually writes and keep the latest phase started.
        try:
            from src.webapi.logs import log_path_for, read_from
            lines, _ = read_from(log_path_for(run.data_dir, run.session_id), 0)
            for ln in reversed(lines):
                m = re.search(r"\[PHASE\]\s+Starting:\s*(\S.*?)\s*$", ln)
                if m:
                    run.current_phase = m.group(1)
                    break
        except Exception:
            pass
        # On completion, capture the real cost + final phase from session.json.
        from src.webapi.models import RUN_SUCCEEDED
        if run.status == RUN_SUCCEEDED:
            run.current_phase = "report"
            try:
                sp = os.path.join(run.data_dir, "repo", ".vigilo", run.session_id, "session.json")
                if os.path.isfile(sp):
                    with open(sp, encoding="utf-8") as fh:
                        sess = json.load(fh)
                    cost = (sess.get("metrics") or {}).get("total_cost_usd")
                    if cost is not None:
                        run.total_cost_usd = float(cost)
            except Exception:
                pass

    async def _failure_detail(self, workflow_id: str) -> str | None:
        """Fetch a failed workflow's real error reason (unwrapped cause chain)."""
        try:
            client = await self._client()
            await client.get_workflow_handle(workflow_id).result()
            return None  # completed without error (unexpected for a FAILED run)
        except Exception as exc:
            return _unwrap_failure(exc)

    async def cancel(self, run: Run) -> None:
        if not run.workflow_id:
            run.status = RUN_CANCELLED
            return
        try:
            client = await self._client()
            await client.get_workflow_handle(run.workflow_id).terminate(
                reason="cancelled via platform"
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("terminate failed for %s: %s", run.id, exc)
        run.status = RUN_CANCELLED
