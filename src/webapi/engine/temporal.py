"""Temporal-client execution engine (persistent-worker model).

The API ingests the repo onto a shared volume, then starts the white-box workflow
(``WhiteboxEngineWorkflow``) on the shared task queue via the Temporal client. A
persistent worker (compose service running
``python -m src.temporal.worker --serve --task-queue vigilo-pipeline``) executes it
and writes outputs to ``{data_dir}/repo/.vigilo/{session}/`` on the same shared
volume, which the API tails for logs/report.

Temporal workflows are durable, so this engine is ``durable`` (reconciliation
re-attaches rather than fails on restart).
"""
from __future__ import annotations

import logging
import os

from src.webapi.engine.common import (
    build_workflow_input,
    capture_source_info,
    resolve_repo_token,
    drop_run_secrets,
    refresh_run,
)
from src.webapi.engine.common import (
    unwrap_failure as _unwrap_failure,  # noqa: F401  (re-export)
)
from src.webapi.models import (
    RUN_CANCELLED,
    RUN_PREPARING,
    RUN_RUNNING,
    Job,
    Repository,
    Run,
)
from src.webapi.settings import get_settings

logger = logging.getLogger(__name__)


class TemporalEngine:
    durable = True

    async def _client(self):
        from temporalio.client import Client
        return await Client.connect(get_settings().temporal_address)

    async def _resolve_token(self, credential_id, repo) -> str | None:
        """The owner's forge token (checked, decrypted, or minted for a GitHub App)."""
        return await resolve_repo_token(credential_id, repo)

    async def start(self, run: Run, job: Job, repo: Repository) -> None:
        from src.webapi.ingestion import (
            prepare_repo,
            upload_archive_path,
            upload_tree_dir,
        )
        settings = get_settings()
        repo_dir = os.path.join(run.data_dir, "repo")
        os.makedirs(repo_dir, exist_ok=True)

        # Materialize the source (clone from the forge / extract-or-copy upload) into the
        # shared volume the worker also mounts.
        token = None
        upload_path = None
        if repo.source_type != "upload" and repo.default_credential_id:
            token = await self._resolve_token(repo.default_credential_id, repo)
        if repo.source_type == "upload":
            archive = upload_archive_path(settings.uploads_dir, str(repo.id))
            tree = upload_tree_dir(settings.uploads_dir, str(repo.id))
            upload_path = archive if os.path.isfile(archive) else tree
        run.status = RUN_PREPARING
        prepare_repo(
            source_type=repo.source_type, repo_dir=repo_dir,
            upload_path=upload_path, remote_url=repo.remote_url, token=token,
        )
        # Commit SHA + persistent browse-only file tree (best-effort).
        capture_source_info(run, repo, repo_dir)
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

        # Everything per-run that is not a secret goes into the workflow input; the
        # forge token (push) and the job's cookie header are stored as an encrypted
        # per-run record and only a redemption reference travels in the input.
        input_data = await build_workflow_input(run, job, repo, repo_dir, token)
        from temporalio.common import WorkflowIDConflictPolicy

        # USE_EXISTING: if a workflow with this id is already running (e.g. start() is
        # re-fired after a transient error / retry), adopt it instead of raising
        # "Workflow execution already started" — which would mark this run failed while
        # the real execution keeps running as an untracked zombie.
        workflow_type = "WhiteboxEngineWorkflow"
        try:
            client = await self._client()
            await client.start_workflow(
                workflow_type,
                input_data,
                id=run.session_id,
                task_queue=settings.temporal_task_queue,
                id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
            )
        except Exception:
            await drop_run_secrets(run)
            raise
        run.workflow_id = run.session_id
        run.status = RUN_RUNNING
        run.current_phase = "preflight"
        logger.info(
            "Started %s %s on %s", workflow_type, run.session_id, settings.temporal_task_queue
        )

    async def refresh(self, run: Run) -> None:
        await refresh_run(run, self._client)

    async def cancel(self, run: Run) -> None:
        if not run.workflow_id:
            await drop_run_secrets(run)
            run.status = RUN_CANCELLED
            return
        try:
            client = await self._client()
            await client.get_workflow_handle(run.workflow_id).terminate(
                reason="cancelled via platform"
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("terminate failed for %s: %s", run.id, exc)
        await drop_run_secrets(run)
        run.status = RUN_CANCELLED
