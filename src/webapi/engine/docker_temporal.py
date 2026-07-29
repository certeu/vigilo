"""Real execution engine: one ephemeral worker container per run.

Launches the generic Vigilo worker image with the run's repo mounted at runtime
(no per-job image build) on a dedicated Temporal task queue. The worker starts the
pipeline workflow; this engine reports status and cancels via the Temporal client.

Docker and Temporal client libraries are imported lazily inside methods so this
module is importable without them (the API only touches this engine at run time).

NOTE: exercised via integration/manual runs (needs Docker + Temporal); it is not
covered by the unit suite, which uses FakeEngine.
"""
from __future__ import annotations

import json
import logging
import os

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

# Temporal workflow execution status → Run.status
_WF_STATUS = {
    1: RUN_RUNNING,     # RUNNING
    2: RUN_SUCCEEDED,   # COMPLETED
    3: RUN_FAILED,      # FAILED
    4: RUN_CANCELLED,   # CANCELED
    5: RUN_FAILED,      # TERMINATED
    6: RUN_RUNNING,     # CONTINUED_AS_NEW
    7: RUN_FAILED,      # TIMED_OUT
}


class DockerTemporalEngine:
    """Container-per-job launcher + Temporal-backed status/cancel."""

    # Temporal workflows are durable: they survive an API restart and resume from
    # the last completed activity, so reconciliation re-attaches rather than fails.
    durable = True

    async def _resolve_token(self, credential_id) -> str | None:
        """Decrypt the owner's credential secret (integration path only)."""
        from src.webapi.db import _session_maker
        from src.webapi.models import Credential
        from src.webapi.security.vault import build_vault

        async with _session_maker()() as session:
            cred = await session.get(Credential, credential_id)
            if cred is None:
                return None
            return build_vault(get_settings()).decrypt(cred.secret_enc)

    async def start(self, run: Run, job: Job, repo: Repository) -> None:
        import docker  # lazy

        from src.webapi.ingestion import prepare_repo

        settings = get_settings()
        repo_dir = os.path.join(run.data_dir, "repo")
        os.makedirs(repo_dir, exist_ok=True)

        # Materialize the source into repo_dir (extract upload / clone GitLab).
        token = None
        upload_path = None
        if repo.source_type == "gitlab" and repo.default_credential_id:
            token = await self._resolve_token(repo.default_credential_id)
            # Patch push-back: the pipeline gates fix-branch push + MR creation on
            # GITLAB_TOKEN being present. Only inject it when the owner opted in.
            if repo.push_patches and token:
                env["GITLAB_TOKEN"] = token
        if repo.source_type == "upload":
            from src.webapi.ingestion import upload_archive_path, upload_tree_dir
            archive = upload_archive_path(settings.uploads_dir, str(repo.id))
            tree = upload_tree_dir(settings.uploads_dir, str(repo.id))
            upload_path = archive if os.path.isfile(archive) else tree
        run.status = RUN_PREPARING
        prepare_repo(
            source_type=repo.source_type, repo_dir=repo_dir,
            upload_path=upload_path, gitlab_url=repo.gitlab_url, token=token,
        )

        env = {
            "TARGET_URL": job.target_url or "",
            "TEMPORAL_ADDRESS": settings.temporal_address,
        }
        # Per-repository overrides of the global model/executor config (spec: global
        # default in admin, overridable per repository). Unset keys fall back to the
        # container's own env (compose/.env).
        cfg = repo.pipeline_config or {}
        _env_map = {
            "executor": "VIGILO_EXECUTOR",
            "model_small": "ANTHROPIC_SMALL_MODEL",
            "model_medium": "ANTHROPIC_MEDIUM_MODEL",
            "model_large": "ANTHROPIC_LARGE_MODEL",
        }
        for key, env_name in _env_map.items():
            if cfg.get(key):
                env[env_name] = cfg[key]
        # Custom scan instructions (description / focus / avoid) → worker env.
        scan = repo.scan_config or {}
        _scan_map = {
            "description": "VIGILO_SCAN_DESCRIPTION",
            "focus": "VIGILO_SCAN_FOCUS",
            "avoid": "VIGILO_SCAN_AVOID",
        }
        for key, env_name in _scan_map.items():
            if scan.get(key):
                env[env_name] = scan[key]
        command = [
            "python", "-m", "src.temporal.worker", "/repos/target",
            "--task-queue", run.task_queue or f"vigilo-{run.id.hex[:12]}",
            "--url", job.target_url or "",
            "--session-id", run.session_id,
            "--stages", json.dumps(build_stages_payload(job)),
        ]

        client = docker.from_env()
        container = client.containers.run(
            settings.worker_image,
            command=command,
            environment=env,
            volumes={repo_dir: {"bind": "/repos/target", "mode": "rw"}},
            network="lab-net",
            detach=True,
            labels={"vigilo.run_id": str(run.id)},
        )
        run.container_id = container.id
        run.workflow_id = run.workflow_id or f"vigilo-{run.session_id}"
        run.status = RUN_PREPARING
        logger.info("Launched worker container %s for run %s", container.id, run.id)

    async def refresh(self, run: Run) -> None:
        if not run.workflow_id:
            return
        try:
            from temporalio.client import Client  # lazy

            client = await Client.connect(get_settings().temporal_address)
            desc = await client.get_workflow_handle(run.workflow_id).describe()
            status_code = getattr(desc.status, "value", None)
            mapped = _WF_STATUS.get(status_code)
            if mapped:
                run.status = mapped
        except Exception as exc:  # pragma: no cover - best-effort observability
            logger.warning("refresh failed for run %s: %s", run.id, exc)

    async def cancel(self, run: Run) -> None:
        # Terminate the workflow, then stop the container. Both best-effort.
        try:
            from temporalio.client import Client  # lazy

            if run.workflow_id:
                client = await Client.connect(get_settings().temporal_address)
                await client.get_workflow_handle(run.workflow_id).terminate(
                    reason="cancelled via platform"
                )
        except Exception as exc:  # pragma: no cover
            logger.warning("workflow terminate failed for run %s: %s", run.id, exc)
        try:
            import docker  # lazy

            if run.container_id:
                docker.from_env().containers.get(run.container_id).stop(timeout=10)
        except Exception as exc:  # pragma: no cover
            logger.warning("container stop failed for run %s: %s", run.id, exc)
        run.status = RUN_CANCELLED
