"""Logic shared by the Temporal-backed engines (persistent-worker and container-per-run).

Covers the workflow-input tuning (``pipeline_config`` / ``model_overrides``), the
post-ingestion capture (commit SHA, browse-only file tree) and the status refresh
(Temporal status -> Run fields, current stage, cost, failure detail).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from src.webapi.logs import current_stage
from src.webapi.models import (
    RUN_CANCELLED,
    RUN_FAILED,
    RUN_RUNNING,
    RUN_SUCCEEDED,
    Repository,
    Run,
)

logger = logging.getLogger(__name__)

# Temporal WorkflowExecutionStatus enum -> Run.status
WF_STATUS = {
    1: RUN_RUNNING,     # RUNNING
    2: RUN_SUCCEEDED,   # COMPLETED
    3: RUN_FAILED,      # FAILED
    4: RUN_CANCELLED,   # CANCELED
    5: RUN_FAILED,      # TERMINATED
    6: RUN_RUNNING,     # CONTINUED_AS_NEW
    7: RUN_FAILED,      # TIMED_OUT
}
TERMINAL = (RUN_SUCCEEDED, RUN_FAILED, RUN_CANCELLED)

_GENERIC = {"Activity task failed", "Workflow execution failed", ""}

# repository pipeline_config / AdminConfig keys -> workflow ``model_overrides`` keys
MODEL_KEYS = ("executor", "model_small", "model_medium", "model_large")


def unwrap_failure(exc: BaseException) -> str:
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


async def drop_run_secrets(run: Run) -> None:
    """Delete the run's secret record (idempotent, never raises). Called when the run
    reaches a terminal state, is cancelled, or fails to start."""
    from src.webapi.secret_store import revoke_for_run
    await revoke_for_run(run.id)


async def resolve_job_cookie(job: Any) -> str | None:
    """The job's cookie header (decrypted), or None.

    Only a ``cookie_header`` credential owned by the job's owner is honoured, and only
    for a job with a target URL (a cookie is useless without a live target); anything
    else is ignored with a log line, never an error: the run proceeds unauthenticated.
    """
    cred_id = getattr(job, "target_credential_id", None)
    if not cred_id:
        return None
    if not getattr(job, "target_url", None):
        logger.warning("job has a cookie credential but no target URL; ignoring it")
        return None
    from src.webapi.db import _session_maker
    from src.webapi.models import Credential
    from src.webapi.security.vault import build_vault
    from src.webapi.settings import get_settings

    async with _session_maker()() as session:
        cred = await session.get(Credential, cred_id)
    owner = getattr(job, "created_by", None)
    # A job with no owner can never prove it may use someone's cookie: refuse.
    if cred is None or cred.kind != "cookie_header" or owner is None or cred.owner_id != owner:
        logger.warning("job cookie credential %s is missing or not usable; ignoring it", cred_id)
        return None
    return build_vault(get_settings()).decrypt(cred.secret_enc)


async def build_run_extras(run: Run, job: Any, repo: Repository, token: str | None) -> dict:
    """Non-secret workflow-input fields about the source, patch push and authenticated
    testing, plus the ``secrets`` reference when the run holds any secret.

    The GitLab token (only when the repo opted into ``push_patches``) and the job's
    cookie header are stored as ONE encrypted per-run record; the input carries just
    ``{"ref": <run id>, "key": <redemption key>}``. The worker redeems them
    just in time over the internal API. Raises if the record cannot be stored (the
    caller must treat that as a failed start)."""
    extras: dict = {}
    if repo.source_type == "gitlab" and repo.gitlab_url:
        extras["source"] = {"remote_url": repo.gitlab_url, "commit": run.commit_sha or None}
    bundle: dict[str, str] = {}
    if repo.push_patches:
        if repo.source_type == "gitlab" and token:
            bundle["gitlab_token"] = token
            extras["push"] = {"enabled": True}
        else:
            logger.info(
                "Run %s: push_patches is on but there is nothing to push to (%s); "
                "patches stay local.", run.id,
                "uploaded source has no remote" if repo.source_type == "upload"
                else "no credential attached",
            )
    cookie = await resolve_job_cookie(job)
    if cookie:
        bundle["cookie_header"] = cookie
        extras["auth"] = {"cookie": True}
    if bundle:
        from src.webapi import secret_store
        from src.webapi.db import _session_maker

        async with _session_maker()() as session:
            key = await secret_store.issue(session, run.id, bundle)
        extras["secrets"] = {"ref": str(run.id), "key": key}
    return extras


async def build_workflow_input(
    run: Run, job: Any, repo: Repository, repo_path: str, token: str | None,
) -> dict:
    """The complete ``WhiteboxEngineWorkflow`` input (both Temporal engines)."""
    from src.webapi.engine.base import build_stages_payload

    scan = repo.scan_config or {}
    data = {
        "web_url": job.target_url or "",
        "repo_path": repo_path,
        "session_id": run.session_id,
        "workflow_id": run.session_id,
        "stages": build_stages_payload(job),
        "description": scan.get("description", ""),
        # description / focus / avoid -> merged into every agent's prompt config
        "scan": {k: scan[k] for k in ("description", "focus", "avoid") if scan.get(k)},
    }
    admin = await load_admin_config()
    data["pipeline_config"] = build_pipeline_config(admin, job)
    overrides = build_model_overrides(admin, repo)
    if overrides:
        data["model_overrides"] = overrides
    data.update(await build_run_extras(run, job, repo, token))
    return data


async def load_admin_config():
    """The singleton AdminConfig row, or None (missing / DB unavailable)."""
    try:
        from src.webapi.db import _session_maker
        from src.webapi.models import AdminConfig

        async with _session_maker()() as session:
            return await session.get(AdminConfig, 1)
    except Exception as exc:  # pragma: no cover - best-effort
        logger.warning("could not load admin config: %s", exc)
        return None


def build_pipeline_config(admin: Any, job: Any) -> dict:
    """``pipeline_config`` workflow input: the admin default for
    ``max_concurrent_pipelines`` merged with the job's overrides (allowed keys only)."""
    from src.webapi.schemas import PIPELINE_OVERRIDE_KEYS

    cfg: dict = {}
    default = getattr(admin, "default_max_concurrent_pipelines", None)
    if default is None:
        from src.webapi.settings import get_settings
        default = get_settings().default_max_concurrent_pipelines
    if default:
        cfg["max_concurrent_pipelines"] = int(default)
    overrides = getattr(job, "pipeline_overrides", None) or {}
    for key, val in overrides.items():
        if key in PIPELINE_OVERRIDE_KEYS and val is not None:
            cfg[key] = val
    return cfg


def build_model_overrides(admin: Any, repo: Repository) -> dict:
    """``model_overrides`` workflow input: AdminConfig globals, overridden by the
    repository's own settings. Empty values mean "unset" (the worker's own
    defaults apply). Model names belong to an executor, so when the effective
    executor is not the admin's, the admin's model names are not inherited: only
    the repository's own names are sent."""
    def clean(v: Any) -> str:
        return v.strip() if isinstance(v, str) else ""

    repo_cfg = getattr(repo, "pipeline_config", None) or {}
    admin_executor = clean(getattr(admin, "executor", None))
    executor = clean(repo_cfg.get("executor")) or admin_executor
    inherit = not admin_executor or executor == admin_executor
    out: dict = {}
    if executor:
        out["executor"] = executor
    for key in MODEL_KEYS:
        if key == "executor":
            continue
        val = clean(repo_cfg.get(key)) or (clean(getattr(admin, key, None)) if inherit else "")
        if val:
            out[key] = val
    return out


def capture_source_info(run: Run, repo: Repository, repo_dir: str) -> None:
    """Best-effort: commit SHA of a GitLab checkout + a persistent browse-only file
    tree (the checkout is deleted after the run, so grab both now)."""
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


async def failure_detail(client, workflow_id: str) -> str | None:
    """A failed workflow's real error reason (unwrapped cause chain)."""
    try:
        await client.get_workflow_handle(workflow_id).result()
        return None  # completed without error (unexpected for a FAILED run)
    except Exception as exc:
        return unwrap_failure(exc)


async def refresh_run(run: Run, client_factory) -> None:
    """Sync a run from Temporal + its workspace: status, error summary, current stage,
    and (on success) final phase + cost. ``client_factory`` is an async callable
    returning a connected Temporal client."""
    if not run.workflow_id:
        return
    closed_at = None
    try:
        client = await client_factory()
        desc = await client.get_workflow_handle(run.workflow_id).describe()
        closed_at = getattr(desc, "close_time", None)
        mapped = WF_STATUS.get(getattr(desc.status, "value", None))
        if mapped:
            run.status = mapped
            # describe() only returns the status enum; the real reason is in the
            # workflow result/cause, not the generic "Activity task failed".
            if mapped == RUN_FAILED and not run.error_summary:
                run.error_summary = await failure_detail(client, run.workflow_id)
    except Exception as exc:  # pragma: no cover - best-effort
        logger.warning("temporal refresh failed for %s: %s", run.id, exc)
    if run.status in TERMINAL:
        # Record the end once: the workflow's own close time when Temporal reports it,
        # else now (the first time this run is seen terminal). Never overwritten.
        if run.finished_at is None:
            if isinstance(closed_at, datetime):
                run.finished_at = closed_at if closed_at.tzinfo else \
                    closed_at.replace(tzinfo=timezone.utc)
            else:
                run.finished_at = datetime.now(timezone.utc)
        await drop_run_secrets(run)  # secrets only live while the run does
    # Best-effort current stage: the latest stage.started event.
    try:
        run.current_phase = current_stage(run.data_dir, run.session_id) or run.current_phase
    except Exception:
        pass
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
