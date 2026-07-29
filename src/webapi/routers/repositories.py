"""Repositories: attachable sources (upload or GitLab), with per-repo privacy.

Non-private repos are team-visible; private repos are visible only to the owner,
explicitly-granted users, and admins (see acl.py). The credential used to fetch a
repo stays private to its owner.
"""
from __future__ import annotations

import logging
import os
import secrets
import uuid

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.ingestion import (
    is_archive_name,
    upload_archive_path,
    upload_tree_dir,
    validate_upload,
)
from src.webapi.settings import get_settings

from src.webapi.acl import (
    accessible_repo_ids,
    is_owner_or_admin,
    require_repo_access,
)
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.engine.base import ExecutionEngine
from src.webapi.engine.provider import get_engine
from src.webapi.models import (
    ROLE_ADMIN,
    Credential,
    Repository,
    RepositoryAccess,
    User,
)
from src.webapi.schemas import (
    AccessGrantCreate,
    AccessGrantRead,
    BulkDeleteRequest,
    BulkDeleteResult,
    RepositoryCreate,
    RepositoryRead,
    RepositoryUpdate,
)

router = APIRouter(tags=["repositories"])
logger = logging.getLogger(__name__)


def _to_read(r: Repository) -> RepositoryRead:
    return RepositoryRead(
        id=r.id, created_by=r.created_by, name=r.name, source_type=r.source_type,
        gitlab_url=r.gitlab_url, gitlab_project_id=r.gitlab_project_id,
        default_credential_id=r.default_credential_id,
        has_webhook=bool(r.webhook_secret), is_private=r.is_private,
        upload_ready=r.upload_ready, push_patches=r.push_patches,
        archived=r.archived,
        ingestion_status=r.ingestion_status, ingestion_error=r.ingestion_error,
        pipeline_config=r.pipeline_config or {}, scan_config=r.scan_config or {},
        created_at=r.created_at,
    )


def _safe_rel(name: str) -> str:
    """Sanitize an uploaded filename/relative path (defense vs traversal)."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return os.path.join(*parts) if parts else ""


_CHUNK = 1024 * 1024  # 1 MiB — stream so multi-GB uploads never load into memory


async def _stream_to_disk(upload: UploadFile, dest: str, max_bytes: int) -> None:
    """Stream an UploadFile to ``dest`` in bounded chunks (safe for very large files).
    Aborts + cleans up if the size cap is exceeded (413)."""
    await upload.seek(0)
    total = 0
    with open(dest, "wb") as fh:
        while True:
            chunk = await upload.read(_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                fh.close()
                os.remove(dest)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Upload exceeds the {max_bytes // (1024 * 1024)} MiB limit",
                )
            fh.write(chunk)


async def _require_owner_or_admin(session, user, repo_id) -> Repository:
    repo = await session.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    if not is_owner_or_admin(user, repo):
        raise HTTPException(status_code=403, detail="Only the owner or an admin may do this")
    return repo


async def _make_gitlab_credential(session, user, label, token, base_url):
    """Encrypt a pasted GitLab token as a per-user credential; return its id."""
    from src.webapi.security.vault import build_vault
    cred = Credential(
        owner_id=user.id, kind="gitlab_token", label=label[:200],
        secret_enc=build_vault(get_settings()).encrypt(token),
        gitlab_base_url=base_url,
    )
    session.add(cred)
    await session.flush()
    return cred.id


async def _validate_gitlab_bg(repo_id: uuid.UUID) -> None:
    """Background: verify the repo's access token can reach the GitLab repo
    (`git ls-remote`), capture its browse-only file tree, and ALWAYS resolve
    ingestion_status to ready/failed. Previously an exception outside the inner
    try (e.g. a decrypt/DB error) left the status stuck at 'importing' forever —
    the "checking token" hang. This now records a terminal status no matter what."""
    import asyncio as _asyncio

    from src.webapi.db import _session_maker
    from src.webapi.ingestion import validate_gitlab_access
    from src.webapi.repo_tree import capture_gitlab_tree
    from src.webapi.security.vault import build_vault

    status_val, err, url, token = "failed", "validation did not run", None, None
    try:
        async with _session_maker()() as session:
            repo = await session.get(Repository, repo_id)
            if repo is None:
                return
            url = repo.gitlab_url
            if repo.default_credential_id:
                cred = await session.get(Credential, repo.default_credential_id)
                token = build_vault(get_settings()).decrypt(cred.secret_enc) if cred else None
        try:
            await _asyncio.to_thread(validate_gitlab_access, url, token)  # read/access check
            status_val, err = "ready", None
        except Exception as exc:  # bad token, insufficient scope, host unreachable, …
            status_val, err = "failed", str(exc)[:500]
        if status_val == "ready":  # capture the browse-only tree while access is valid
            try:
                await _asyncio.to_thread(capture_gitlab_tree, str(repo_id), url, token)
            except Exception as exc:
                logger.warning("gitlab tree capture for repo %s failed: %s", repo_id, exc)
    except Exception as exc:  # decrypt/DB/etc. — record failed, never leave 'importing'
        status_val = "failed"
        err = f"validation error: {type(exc).__name__}: {str(exc)[:200]}"
        logger.warning("gitlab validation for repo %s errored: %s", repo_id, exc)
    # ALWAYS persist a terminal status (the fix for the stuck-'importing' hang).
    try:
        async with _session_maker()() as session:
            repo = await session.get(Repository, repo_id)
            if repo is not None:
                repo.ingestion_status = status_val
                repo.ingestion_error = err
                await session.commit()
    except Exception as exc:  # pragma: no cover - last-ditch
        logger.warning("could not persist gitlab status for %s: %s", repo_id, exc)


@router.post("/repositories", response_model=RepositoryRead,
             status_code=status.HTTP_201_CREATED)
async def create_repository(
    payload: RepositoryCreate,
    background: BackgroundTasks,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> RepositoryRead:
    if payload.default_credential_id is not None:
        cred = await session.get(Credential, payload.default_credential_id)
        if cred is None or cred.owner_id != user.id:
            raise HTTPException(status_code=400, detail="Unknown or non-owned credential")
    if payload.push_patches and payload.source_type != "gitlab":
        raise HTTPException(status_code=400,
                            detail="push_patches requires a GitLab source")
    cred_id = payload.default_credential_id
    # A pasted token is encrypted as a credential and linked to this repo.
    if payload.source_type == "gitlab" and payload.gitlab_token:
        cred_id = await _make_gitlab_credential(
            session, user, f"{payload.name} GitLab token",
            payload.gitlab_token, payload.gitlab_url,
        )
    is_gitlab = payload.source_type == "gitlab"
    repo = Repository(
        created_by=user.id, name=payload.name, source_type=payload.source_type,
        gitlab_url=payload.gitlab_url, gitlab_project_id=payload.gitlab_project_id,
        default_credential_id=cred_id,
        is_private=payload.is_private, scan_config=payload.scan_config or {},
        push_patches=payload.push_patches,
        # GitLab: validate access in the background (importing → ready/failed).
        # Upload: stays idle until source is attached.
        ingestion_status="importing" if is_gitlab else "idle",
    )
    session.add(repo)
    await session.commit()
    await session.refresh(repo)
    if is_gitlab:
        background.add_task(_validate_gitlab_bg, repo.id)
    return _to_read(repo)


@router.get("/repositories", response_model=list[RepositoryRead])
async def list_repositories(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[RepositoryRead]:
    allowed = await accessible_repo_ids(session, user)
    rows = (await session.scalars(select(Repository))).all()
    return [_to_read(r) for r in rows if allowed is None or r.id in allowed]


@router.get("/repositories/{repo_id}", response_model=RepositoryRead)
async def get_repository(
    repo_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> RepositoryRead:
    repo = await require_repo_access(session, user, repo_id)
    return _to_read(repo)


@router.get("/repositories/{repo_id}/tree")
async def repository_tree(
    repo_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """Browse-only file/directory structure of the repo (file paths, names ONLY —
    never contents). Access-controlled like everything else (require_repo_access →
    404 if the caller can't see this repo). There is intentionally NO endpoint to
    fetch a file's contents; this is structural exploration only."""
    repo = await require_repo_access(session, user, repo_id)
    from src.webapi.repo_tree import capture_gitlab_tree, capture_repo_tree, read_repo_tree
    tree = read_repo_tree(str(repo_id))
    if tree is None:
        # Self-heal from the PERSISTENT source (never the ephemeral scan checkout, which
        # is deleted post-run). Covers repos created before tree capture existed and
        # GitLab repos browsed before their first scan.
        try:
            if repo.source_type == "upload":
                uploads = get_settings().uploads_dir
                archive = upload_archive_path(uploads, str(repo_id))
                src = archive if os.path.isfile(archive) else upload_tree_dir(uploads, str(repo_id))
                if os.path.exists(src):
                    capture_repo_tree(str(repo_id), src)
            elif repo.source_type == "gitlab" and repo.gitlab_url:
                token = None
                if repo.default_credential_id:
                    from src.webapi.security.vault import build_vault
                    cred = await session.get(Credential, repo.default_credential_id)
                    token = build_vault(get_settings()).decrypt(cred.secret_enc) if cred else None
                capture_gitlab_tree(str(repo_id), repo.gitlab_url, token)
        except Exception as exc:
            logger.warning("tree backfill failed for repo %s: %s", repo_id, exc)
        tree = read_repo_tree(str(repo_id))
    if tree is None:
        msg = ("Couldn't read the repository source — check the GitLab URL/token is valid "
               "and the host is reachable." if repo.source_type == "gitlab"
               else "No source uploaded yet.")
        return {"available": False, "paths": [], "truncated": False, "count": 0, "message": msg}
    return {"available": True, **tree}


@router.patch("/repositories/{repo_id}", response_model=RepositoryRead)
async def update_repository(
    repo_id: uuid.UUID,
    payload: RepositoryUpdate,
    background: BackgroundTasks,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> RepositoryRead:
    repo = await _require_owner_or_admin(session, user, repo_id)
    data = payload.model_dump(exclude_unset=True)
    revalidate = False
    if data.get("name") is not None:
        repo.name = data["name"]
    if "default_credential_id" in data:
        repo.default_credential_id = data["default_credential_id"]
    # A pasted token replaces the linked credential and triggers re-validation.
    if data.get("gitlab_token"):
        if repo.source_type != "gitlab":
            raise HTTPException(status_code=400, detail="Token only applies to GitLab repos")
        repo.default_credential_id = await _make_gitlab_credential(
            session, user, f"{repo.name} GitLab token", data["gitlab_token"], repo.gitlab_url,
        )
        repo.ingestion_status = "importing"
        repo.ingestion_error = None
        revalidate = True
    if data.get("is_private") is not None:
        repo.is_private = data["is_private"]
    if data.get("push_patches") is not None:
        if data["push_patches"] and repo.source_type != "gitlab":
            raise HTTPException(
                status_code=400,
                detail="push_patches requires a GitLab source with a write-scoped token",
            )
        repo.push_patches = data["push_patches"]
    if data.get("pipeline_config") is not None:
        repo.pipeline_config = data["pipeline_config"]
    if data.get("scan_config") is not None:
        repo.scan_config = data["scan_config"]
    await session.commit()
    await session.refresh(repo)
    if revalidate:
        background.add_task(_validate_gitlab_bg, repo.id)
    return _to_read(repo)


@router.delete("/repositories/{repo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_repository(
    repo_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
    engine: ExecutionEngine = Depends(get_engine),
) -> None:
    repo = await session.get(Repository, repo_id)
    if repo is None:
        # Private repos the caller can't see must 404 (no existence leak); otherwise
        # a no-op 204 is fine (already gone).
        raise HTTPException(status_code=404, detail="Repository not found")
    if not is_owner_or_admin(user, repo):
        # 404 not 403 for a private repo the caller can't see; 403 for a visible one.
        if repo.is_private and user.role != ROLE_ADMIN:
            raise HTTPException(status_code=404, detail="Repository not found")
        raise HTTPException(status_code=403, detail="Not your repository")
    from src.webapi.deletion import delete_repository as _delete_repo
    await _delete_repo(session, engine, repo_id)
    await session.commit()


@router.post("/repositories/bulk-delete", response_model=BulkDeleteResult)
async def bulk_delete_repositories(
    payload: BulkDeleteRequest,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
    engine: ExecutionEngine = Depends(get_engine),
) -> BulkDeleteResult:
    """Delete several repositories in one action. ACL is enforced per repo — repos the
    caller doesn't own (and isn't admin for) are reported under ``denied`` and left
    untouched, never silently deleted."""
    from src.webapi.deletion import delete_repository as _delete_repo
    result = BulkDeleteResult()
    for repo_id in payload.ids:
        repo = await session.get(Repository, repo_id)
        if repo is None or not is_owner_or_admin(user, repo):
            result.denied.append(repo_id)
            continue
        await _delete_repo(session, engine, repo_id)
        result.deleted.append(repo_id)
    await session.commit()
    return result


async def _ingest_repo_bg(repo_id: uuid.UUID) -> None:
    """Background: validate the uploaded source and flip the repo to ready/failed.

    Runs after the upload response is returned so a large/slow archive never blocks
    the request (or other users). Uses its own DB session."""
    from src.webapi.db import _session_maker
    uploads = get_settings().uploads_dir
    archive = upload_archive_path(uploads, str(repo_id))
    tree = upload_tree_dir(uploads, str(repo_id))
    path = archive if os.path.isfile(archive) else tree
    status_val, err = "ready", None
    try:
        validate_upload(path)
        # Persist a browse-only file tree for the repo explorer (best-effort).
        try:
            from src.webapi.repo_tree import capture_repo_tree
            capture_repo_tree(str(repo_id), path)
        except Exception as exc:  # pragma: no cover - best-effort
            logger.warning("repo %s tree capture failed: %s", repo_id, exc)
    except Exception as exc:  # invalid/empty/unsafe upload
        status_val, err = "failed", str(exc)[:500]
    # A background task must never raise unhandled (a DB hiccup shouldn't crash the
    # worker or lose the result silently); wrap the write too.
    try:
        async with _session_maker()() as session:
            repo = await session.get(Repository, repo_id)
            if repo is not None:
                repo.ingestion_status = status_val
                repo.ingestion_error = err
                repo.upload_ready = status_val == "ready"
                await session.commit()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("repo %s ingestion status update failed: %s", repo_id, exc)


@router.post("/repositories/{repo_id}/upload", response_model=RepositoryRead)
async def upload_source(
    repo_id: uuid.UUID,
    background: BackgroundTasks,
    files: list[UploadFile] = File(...),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> RepositoryRead:
    """Attach source for an upload repo: a single archive (.zip/.tar.gz) OR a set of
    uncompressed files (a folder upload). Owner/admin only."""
    repo = await _require_owner_or_admin(session, user, repo_id)
    if repo.source_type != "upload":
        raise HTTPException(status_code=400, detail="Repository is not an upload source")
    uploads = get_settings().uploads_dir
    os.makedirs(uploads, exist_ok=True)
    archive_dest = upload_archive_path(uploads, str(repo_id))
    tree_dest = upload_tree_dir(uploads, str(repo_id))
    # Clear any previous upload.
    for p in (archive_dest, tree_dest):
        if os.path.isfile(p):
            os.remove(p)
        elif os.path.isdir(p):
            import shutil
            shutil.rmtree(p)

    max_bytes = get_settings().max_upload_mb * 1024 * 1024
    if len(files) == 1 and is_archive_name(files[0].filename or ""):
        await _stream_to_disk(files[0], archive_dest, max_bytes)
    else:
        # Uncompressed: write each file preserving its relative path (shared budget).
        os.makedirs(tree_dest, exist_ok=True)
        wrote = 0
        for uf in files:
            rel = _safe_rel(uf.filename or "")
            if not rel:
                continue
            target = os.path.join(tree_dest, rel)
            os.makedirs(os.path.dirname(target) or tree_dest, exist_ok=True)
            await _stream_to_disk(uf, target, max_bytes)
            max_bytes -= os.path.getsize(target)
            wrote += 1
        if wrote == 0:
            raise HTTPException(status_code=400, detail="No usable files uploaded")

    # Files are on disk; validate/ingest in the background so the request returns
    # immediately (doesn't block this or other users). The repo shows "importing"
    # until the background task flips it to ready/failed.
    repo.upload_ready = False
    repo.ingestion_status = "importing"
    repo.ingestion_error = None
    await session.commit()
    await session.refresh(repo)
    background.add_task(_ingest_repo_bg, repo_id)
    return _to_read(repo)


@router.post("/repositories/{repo_id}/webhook")
async def issue_webhook(
    repo_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict[str, str]:
    repo = await _require_owner_or_admin(session, user, repo_id)
    repo.webhook_secret = secrets.token_urlsafe(32)
    await session.commit()
    return {
        "webhook_url": "/api/v1/webhooks/gitlab",
        "secret": repo.webhook_secret,
        "note": "Add this as a Merge Request events webhook with the secret token.",
    }


# --- Access grants (owner/admin manage who can see a private repo) ---

@router.get("/repositories/{repo_id}/access", response_model=list[AccessGrantRead])
async def list_access(
    repo_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[AccessGrantRead]:
    await _require_owner_or_admin(session, user, repo_id)
    grants = (await session.scalars(
        select(RepositoryAccess).where(RepositoryAccess.repository_id == repo_id))).all()
    out: list[AccessGrantRead] = []
    for g in grants:
        u = await session.get(User, g.user_id)
        out.append(AccessGrantRead(
            user_id=g.user_id, email=u.email if u else "?", created_at=g.created_at))
    return out


@router.post("/repositories/{repo_id}/access", response_model=AccessGrantRead,
             status_code=status.HTTP_201_CREATED)
async def grant_access(
    repo_id: uuid.UUID,
    payload: AccessGrantCreate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> AccessGrantRead:
    await _require_owner_or_admin(session, user, repo_id)
    if payload.user_id is not None:
        target = await session.get(User, payload.user_id)
    else:
        target = await session.scalar(
            select(User).where(User.email == (payload.email or "").lower())
        )
    if target is None:
        raise HTTPException(status_code=400, detail="Unknown user")
    exists = await session.scalar(select(RepositoryAccess).where(
        RepositoryAccess.repository_id == repo_id,
        RepositoryAccess.user_id == payload.user_id))
    if exists is None:
        grant = RepositoryAccess(repository_id=repo_id, user_id=payload.user_id)
        session.add(grant)
        await session.commit()
        await session.refresh(grant)
        created = grant.created_at
    else:
        created = exists.created_at
    return AccessGrantRead(user_id=payload.user_id, email=target.email, created_at=created)


@router.delete("/repositories/{repo_id}/access/{user_id}",
               status_code=status.HTTP_204_NO_CONTENT)
async def revoke_access(
    repo_id: uuid.UUID,
    user_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> None:
    await _require_owner_or_admin(session, user, repo_id)
    grant = await session.scalar(select(RepositoryAccess).where(
        RepositoryAccess.repository_id == repo_id,
        RepositoryAccess.user_id == user_id))
    if grant is not None:
        await session.delete(grant)
        await session.commit()
