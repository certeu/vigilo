"""Real execution engine: one ephemeral worker container per run.

Launches the generic Vigilo worker image with the run's repo mounted at runtime
(no per-job image build) on a dedicated Temporal task queue. The container only
hosts the worker (``--serve --exit-with-workflow``); THIS engine starts the white-box
workflow through the Temporal client, so the per-run redemption reference for secrets
never has to be placed in the container's environment (where an agent could read it
from /proc). The container exits when the workflow closes. The engine reports status
and cancels via the Temporal client.

Docker and Temporal client libraries are imported lazily inside methods so this
module is importable without them (the API only touches this engine at run time).

NOTE: exercised via integration/manual runs (needs Docker + Temporal); it is not
covered by the unit suite, which uses FakeEngine.
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
from src.webapi.models import (
    RUN_CANCELLED,
    RUN_PREPARING,
    Job,
    Repository,
    Run,
)
from src.webapi.settings import get_settings

logger = logging.getLogger(__name__)


class DockerTemporalEngine:
    """Container-per-job launcher + Temporal-backed status/cancel."""

    # Temporal workflows are durable: they survive an API restart and resume from
    # the last completed activity, so reconciliation re-attaches rather than fails.
    durable = True

    async def _resolve_token(self, credential_id, repo) -> str | None:
        """The owner's forge token (checked, decrypted, or minted for a GitHub App)."""
        return await resolve_repo_token(credential_id, repo)

    async def start(self, run: Run, job: Job, repo: Repository) -> None:
        import docker  # lazy

        from src.webapi.ingestion import prepare_repo

        settings = get_settings()
        repo_dir = os.path.join(run.data_dir, "repo")
        os.makedirs(repo_dir, exist_ok=True)

        env = {
            "TEMPORAL_ADDRESS": settings.temporal_address,
        }

        # Materialize the source into repo_dir (extract upload / clone from the forge).
        token = None
        upload_path = None
        if repo.source_type != "upload" and repo.default_credential_id:
            token = await self._resolve_token(repo.default_credential_id, repo)
        if repo.source_type == "upload":
            from src.webapi.ingestion import upload_archive_path, upload_tree_dir
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

        # Only the repo is mounted. No secret is mounted or put in the environment:
        # the forge token / cookie header are redeemed by the worker just in time via
        # the reference carried in the workflow input (see build_run_extras).
        volumes = {repo_dir: {"bind": "/repos/target", "mode": "rw"}}
        env["VIGILO_INTERNAL_API_URL"] = settings.internal_api_url
        task_queue = run.task_queue or f"vigilo-{run.id.hex[:12]}"
        command = [
            "python", "-m", "src.temporal.worker", "--serve",
            "--task-queue", task_queue,
            "--exit-with-workflow", run.session_id,
        ]

        try:
            client = docker.from_env()
            container = client.containers.run(
                settings.worker_image,
                command=command,
                environment=env,
                volumes=volumes,
                network=settings.docker_network,
                detach=True,
                labels={"vigilo.run_id": str(run.id)},
            )
            run.container_id = container.id
            # Per-run model/executor overrides, scan settings, tuning and the secret
            # reference are workflow input (model_overrides / scan / pipeline_config).
            input_data = await build_workflow_input(run, job, repo, "/repos/target", token)
            from temporalio.client import Client  # lazy
            from temporalio.common import WorkflowIDConflictPolicy

            tclient = await Client.connect(settings.temporal_address)
            await tclient.start_workflow(
                "WhiteboxEngineWorkflow",
                input_data,
                id=run.session_id,
                task_queue=task_queue,
                id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
            )
        except Exception:
            await drop_run_secrets(run)
            if run.container_id:
                try:
                    docker.from_env().containers.get(run.container_id).stop(timeout=10)
                except Exception:  # pragma: no cover - best-effort
                    pass
            raise
        run.workflow_id = run.session_id
        run.status = RUN_PREPARING
        logger.info("Launched worker container %s for run %s", container.id, run.id)

    async def refresh(self, run: Run) -> None:
        async def _client():
            from temporalio.client import Client  # lazy
            return await Client.connect(get_settings().temporal_address)

        await refresh_run(run, _client)

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
        await drop_run_secrets(run)
        run.status = RUN_CANCELLED
