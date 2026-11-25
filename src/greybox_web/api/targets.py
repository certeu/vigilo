"""Grey-box targets: validate + CRUD. Owner/admin ACL, 404 otherwise.

``POST /greybox/targets/{id}/preflight`` and the run routes are M2.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Body, Depends, File, HTTPException, Query, Response, UploadFile, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import checks as gb_checks
from src.greybox_web import modelsel
from src.greybox_web import modes
from src.greybox_web import settings as gb_settings
from src.greybox_web.acl import get_target_or_404, is_admin
from src.greybox_web.models import GreyboxRun, GreyboxTarget
from src.greybox_web.netguard import is_loopback_name, is_private, classify_ip, parse_ip
from src.greybox_web.pagination import (
    as_utc,
    clamp_limit,
    decode_cursor,
    encode_cursor,
    parse_ts,
    parse_uuid,
)
from src.greybox_web.schemas import (
    AccountRef,
    CredentialRef,
    LastRun,
    PreflightResult,
    ScopePolicyOut,
    TargetCreate,
    TargetNormalized,
    TargetPage,
    TargetRead,
    TargetUpdate,
    ValidateResponse,
    ValidationIssue,
    stored_limits,
)
from src.greybox_web.scope import FieldError, PolicyContext, ScopePolicy, build_scope
from src.greybox_web.service import count_active_runs, purge_runs
from src.webapi.auth.deps import current_active_user
from src.webapi.credential_guard import (
    COOKIE_KIND,
    CredentialRejected,
    validate_cookie_credential,
    validate_login_credential,
)
from src.webapi.db import get_async_session
from src.webapi.models import Credential, User

router = APIRouter(prefix="/greybox", tags=["greybox"])

# In-process preflight rate limit: one call per target per 5 s.
_PREFLIGHT_AT: dict[uuid.UUID, float] = {}
PREFLIGHT_INTERVAL_S = 5.0


# ------------------------------------------------------------------- evaluation


def policy_context() -> PolicyContext:
    s = gb_settings.settings()
    return PolicyContext(
        allow_private=bool(s.greybox_allow_private_targets),
        blocked_hosts=gb_settings.blocked_hosts(s),
        blocked_endpoints=tuple((e.host, e.port) for e in gb_settings.blocked_endpoints(s)),
    )


@dataclass
class Evaluation:
    errors: list[FieldError]
    warnings: list[str]
    normalized: TargetNormalized | None = None
    policy: ScopePolicy | None = None


def _host_is_private(host: str) -> bool:
    ip = parse_ip(host)
    return is_private(classify_ip(ip)) if ip is not None else is_loopback_name(host)


async def evaluate(session: AsyncSession, owner_id: uuid.UUID, *, name: str,
                   description: str | None, base_url: str, scope: dict[str, Any] | None,
                   limits: dict[str, Any] | None, checks: list[str] | None,
                   credential_id: uuid.UUID | None,
                   account_ids: list[uuid.UUID] | None = None,
                   egress_proxy_id: uuid.UUID | None = None,
                   model_backend: str | None = "", model: str | None = "",
                   assessment_mode: str = "web",
                   capabilities: list[str] | None = None) -> Evaluation:
    """Semantic validation shared by validate / create / update."""
    base, policy, errors = build_scope(base_url, scope, policy_context())
    warnings: list[str] = []
    mode = modes.normalise_mode(assessment_mode)
    if assessment_mode and mode != assessment_mode:
        errors.append(FieldError(("assessment_mode",),
                                 f"Unknown assessment mode: {assessment_mode}"))
    disabled = sorted({str(c) for c in (capabilities or ())})
    for i, cap in enumerate(disabled):
        if cap not in modes.CAPABILITIES:
            errors.append(FieldError(("capabilities", i),
                                     f"Unknown capability: {cap}"))
        elif cap not in modes.MODE_CAPABILITIES[mode]:
            warnings.append(f"{cap} is not part of a {mode} assessment; ignoring it.")
    disabled = [c for c in disabled if c in modes.MODE_CAPABILITIES[mode]]
    if mode == modes.NETWORK and policy is not None and policy.network is None:
        errors.append(FieldError(("scope", "network"),
                                 "A network assessment needs scope.network: the "
                                 "authorised targets (addresses/CIDR/names) and ports"))
    if mode != modes.WEB:
        warnings.append(f"{mode} assessment: the web checks and the browser are not "
                        "used; discovery and inventory tools apply instead.")

    if checks is not None:
        seen: list[str] = []
        for i, cid in enumerate(checks):
            if cid not in gb_checks.CHECK_IDS:
                errors.append(FieldError(("checks", i), f"Unknown check: {cid}"))
            elif cid not in seen:
                seen.append(cid)
        checks = seen
        if not checks:
            warnings.append("No checks selected: only discovery will run.")

    if credential_id is not None:
        cred = await session.get(Credential, credential_id)
        try:
            validate_cookie_credential(cred, owner_id)
        except CredentialRejected as exc:
            # A foreign credential is reported exactly like a missing one (no existence leak).
            msg = ("Unknown credential" if cred is None or cred.owner_id != owner_id
                   else str(exc))
            errors.append(FieldError(("credential_id",), msg))

    # Login accounts: each must be an existing login_account credential of the owner
    # (a foreign or deleted one is reported exactly like a missing one). Stored as
    # plain strings — the JSON column must never receive a UUID object.
    accounts: list[str] = []
    for i, aid in enumerate(account_ids or []):
        cred = await session.get(Credential, aid)
        try:
            validate_login_credential(cred, owner_id)
        except CredentialRejected as exc:
            msg = ("Unknown credential" if cred is None or cred.owner_id != owner_id
                   else str(exc))
            errors.append(FieldError(("account_ids", i), msg))
        else:
            accounts.append(str(aid))

    try:
        model_backend, model = modelsel.validate_choice(model_backend or "", model or "")
    except modelsel.ModelSelectionError as exc:
        errors.append(FieldError(
            ("model" if "is not offered" in str(exc) else "model_backend",), str(exc)))
    else:
        if not model_backend and modelsel.default_choice() is None:
            warnings.append(modelsel.NO_MODEL_MESSAGE)

    merged_limits = stored_limits(
        {k: v for k, v in (limits or {}).items() if v is not None})

    if errors or policy is None or base is None:
        return Evaluation(errors=errors, warnings=warnings)

    if egress_proxy_id is not None:
        from src.greybox_web.api.egress_proxies import proxy_problem
        problem, _row = await proxy_problem(session, egress_proxy_id,
                                            list(policy.allowed_hosts))
        if problem:
            errors.append(FieldError(("egress_proxy_id",), problem))
            return Evaluation(errors=errors, warnings=warnings)
        warnings.append("Traffic to this target will go through the egress proxy: the "
                        "proxy resolves host names, so DNS pinning does not apply.")

    if checks is not None and not policy.allow_auth_testing:
        gated = [c for c in checks if (spec := gb_checks.get(c)) and spec.requires_auth_testing]
        if gated:
            warnings.append(f"{', '.join(gated)} will not run: authentication testing "
                            "is disabled in the scope.")
    if policy.allow_auth_testing:
        warnings.append("Authentication testing is enabled: the default-credential check "
                        "will attempt logins on detected login forms.")
    if accounts and not policy.allow_auth_testing:
        warnings.append("Login accounts are linked but authentication testing is "
                        "disabled in the scope: they will not be used.")
    if any(_host_is_private(h) for h in policy.allowed_hosts):
        warnings.append("The scope includes loopback or private addresses (allowed on this "
                        "platform for development and testing only).")
    if credential_id is not None and "http" in policy.allowed_schemes:
        warnings.append("The session cookie will be sent over plain http to in-scope hosts.")

    normalized = TargetNormalized(
        name=name, description=description, base_url=base,
        scope=ScopePolicyOut(**policy.to_dict()), limits=merged_limits, checks=checks,
        credential_id=credential_id, account_ids=accounts,
        egress_proxy_id=egress_proxy_id,
        assessment_mode=mode, capabilities=disabled,
        model_backend=model_backend or None, model=model or None,
    )
    return Evaluation(errors=[], warnings=warnings, normalized=normalized, policy=policy)


def _raise_422(errors: list[FieldError]) -> None:
    raise RequestValidationError(
        [{"loc": ("body", *e.loc), "msg": e.msg, "type": e.type} for e in errors]
    )


# --------------------------------------------------------------------- read model


async def to_reads(session: AsyncSession, targets: list[GreyboxTarget]) -> list[TargetRead]:
    if not targets:
        return []
    ids = [t.id for t in targets]
    cred_ids = {t.credential_id for t in targets if t.credential_id is not None}
    # stored account ids are plain strings; the credential table keys are UUIDs
    cred_ids |= {uuid.UUID(a) for t in targets for a in (t.account_ids or [])}
    creds = {}
    if cred_ids:
        creds = {c.id: c for c in (await session.scalars(
            select(Credential).where(Credential.id.in_(cred_ids)))).all()}
    latest = (
        select(GreyboxRun.target_id, func.max(GreyboxRun.created_at).label("mx"))
        .where(GreyboxRun.target_id.in_(ids)).group_by(GreyboxRun.target_id).subquery()
    )
    last: dict[uuid.UUID, GreyboxRun] = {}
    for r in (await session.scalars(select(GreyboxRun).join(
            latest, and_(GreyboxRun.target_id == latest.c.target_id,
                         GreyboxRun.created_at == latest.c.mx)))).all():
        if r.target_id not in last or r.id > last[r.target_id].id:
            last[r.target_id] = r

    out = []
    for t in targets:
        policy = ScopePolicy.from_dict(t.scope)
        cred = creds.get(t.credential_id) if t.credential_id else None
        cref = None
        if cred is not None and cred.kind == COOKIE_KIND and cred.owner_id == t.owner_id:
            cref = CredentialRef(id=cred.id, label=cred.label, kind=COOKIE_KIND)
        arefs = [AccountRef(id=c.id, label=c.label)
                 for aid in (t.account_ids or [])
                 if (c := creds.get(uuid.UUID(str(aid)))) is not None
                 and c.owner_id == t.owner_id and c.kind == "login_account"]
        lr = last.get(t.id)
        out.append(TargetRead(
            id=t.id, owner_id=t.owner_id, name=t.name, description=t.description,
            base_url=t.base_url, scope=ScopePolicyOut(**policy.to_dict()),
            scope_summary=policy.summary(),
            limits=stored_limits(t.limits),
            checks=gb_checks.resolve_checks(t.checks, policy.allow_auth_testing),
            credential=cref, accounts=arefs, egress_proxy_id=t.egress_proxy_id,
            assessment_mode=modes.normalise_mode(
                getattr(t, "assessment_mode", modes.DEFAULT_MODE)),
            capabilities=list(getattr(t, "disabled_capabilities", None) or []),
            archived=t.archived,
            model_backend=t.model_backend or None, model=t.model or None,
            created_at=as_utc(t.created_at), updated_at=as_utc(t.updated_at),
            last_run=LastRun(id=lr.id, status=lr.status, created_at=as_utc(lr.created_at))
            if lr else None,
        ))
    return out


# ------------------------------------------------------------------------- routes


def _clean_msg(msg: str) -> str:
    return msg.removeprefix("Value error, ")


@router.post("/targets/validate", response_model=ValidateResponse)
async def validate_target(
    payload: dict[str, Any] = Body(...),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> ValidateResponse:
    """Dry-run of create: always 200, with field errors in the body."""
    try:
        data = TargetCreate.model_validate(payload)
    except ValidationError as exc:
        issues = [ValidationIssue(loc=["body", *e["loc"]], msg=_clean_msg(e["msg"]),
                                  type=e["type"]) for e in exc.errors()]
        return ValidateResponse(valid=False, normalized=None, scope_summary=[],
                                errors=issues, warnings=[])
    ev = await evaluate(
        session, user.id, name=data.name, description=data.description,
        base_url=data.base_url,
        scope=data.scope.model_dump(exclude_none=True) if data.scope else None,
        limits=data.limits.model_dump(exclude_none=True) if data.limits else None,
        checks=data.checks, credential_id=data.credential_id,
        account_ids=data.account_ids,
        egress_proxy_id=data.egress_proxy_id, model_backend=data.model_backend,
        model=data.model, assessment_mode=data.assessment_mode,
        capabilities=data.capabilities,
    )
    return ValidateResponse(
        valid=not ev.errors, normalized=ev.normalized,
        scope_summary=ev.policy.summary() if ev.policy else [],
        errors=[ValidationIssue(loc=["body", *e.loc], msg=e.msg, type=e.type)
                for e in ev.errors],
        warnings=ev.warnings,
    )


@router.post("/targets", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> TargetRead:
    ev = await evaluate(
        session, user.id, name=payload.name, description=payload.description,
        base_url=payload.base_url,
        scope=payload.scope.model_dump(exclude_none=True) if payload.scope else None,
        limits=payload.limits.model_dump(exclude_none=True) if payload.limits else None,
        checks=payload.checks, credential_id=payload.credential_id,
        account_ids=payload.account_ids,
        egress_proxy_id=payload.egress_proxy_id, model_backend=payload.model_backend,
        model=payload.model, assessment_mode=payload.assessment_mode,
        capabilities=payload.capabilities,
    )
    if ev.errors or ev.normalized is None:
        _raise_422(ev.errors)
    n = ev.normalized
    target = GreyboxTarget(
        owner_id=user.id, name=n.name, description=n.description, base_url=n.base_url,
        scope=n.scope.model_dump(), limits=n.limits.model_dump(), checks=n.checks,
        credential_id=n.credential_id, account_ids=n.account_ids,
        egress_proxy_id=n.egress_proxy_id,
        assessment_mode=n.assessment_mode or modes.DEFAULT_MODE,
        disabled_capabilities=list(n.capabilities or []),
        model_backend=n.model_backend or "", model=n.model or "",
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return (await to_reads(session, [target]))[0]


@router.get("/targets", response_model=TargetPage)
async def list_targets(
    q: str | None = Query(default=None, max_length=200),
    archived: bool = False,
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None, max_length=200),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> TargetPage:
    n = clamp_limit(limit)
    stmt = select(GreyboxTarget).where(GreyboxTarget.archived == archived)
    if not is_admin(user):
        stmt = stmt.where(GreyboxTarget.owner_id == user.id)
    if q:
        stmt = stmt.where(or_(GreyboxTarget.name.icontains(q, autoescape=True),
                              GreyboxTarget.base_url.icontains(q, autoescape=True)))
    if cursor:
        ts_s, id_s = decode_cursor(cursor, 2)
        ts, cid = parse_ts(ts_s), parse_uuid(id_s)
        stmt = stmt.where(or_(GreyboxTarget.created_at < ts,
                              and_(GreyboxTarget.created_at == ts, GreyboxTarget.id < cid)))
    stmt = stmt.order_by(GreyboxTarget.created_at.desc(), GreyboxTarget.id.desc()).limit(n + 1)
    rows = list((await session.scalars(stmt)).all())
    next_cursor = None
    if len(rows) > n:
        rows = rows[:n]
        next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id)
    return TargetPage(items=await to_reads(session, rows), next_cursor=next_cursor)


@router.get("/targets/{target_id}", response_model=TargetRead)
async def get_target(
    target_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> TargetRead:
    target = await get_target_or_404(session, user, target_id)
    return (await to_reads(session, [target]))[0]


@router.post("/targets/{target_id}/artifact", status_code=status.HTTP_201_CREATED)
async def upload_target_artifact(
    target_id: uuid.UUID,
    file: UploadFile = File(...),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict[str, Any]:
    """Replace an artifact target's offline inventory with a bounded safe archive."""
    import shutil
    import tempfile
    from pathlib import Path
    from src.greybox_web import artifact
    from src.greybox_web.models import GB_ACTIVE
    from src.webapi.ingestion import extract_archive, is_archive_name, validate_upload

    target = await get_target_or_404(session, user, target_id)
    if modes.normalise_mode(target.assessment_mode) != modes.ARTIFACT:
        raise HTTPException(status.HTTP_409_CONFLICT, "target is not artifact mode")
    active = await session.scalar(select(func.count()).select_from(GreyboxRun).where(
        GreyboxRun.target_id == target.id, GreyboxRun.status.in_(GB_ACTIVE)))
    if active:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot replace artifact during an active run")
    filename = file.filename or "artifact"
    if not is_archive_name(filename):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "artifact must be zip, tar, tar.gz, or tgz")
    suffix = ".tar.gz" if filename.lower().endswith((".tar.gz", ".tgz")) else Path(filename).suffix
    max_bytes = int(gb_settings.settings().max_upload_mb) * 1024 * 1024
    with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
        written = 0
        while chunk := await file.read(1024 * 1024):
            written += len(chunk)
            if written > max_bytes:
                raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "artifact exceeds upload limit")
            tmp.write(chunk)
        tmp.flush()
        try:
            count = validate_upload(tmp.name)
            root = artifact.target_root(gb_settings.settings().uploads_dir, target.id)
            shutil.rmtree(root, ignore_errors=True)
            extract_archive(tmp.name, str(root))
        except (ValueError, OSError) as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)[:500]) from exc
    return {"target_id": str(target.id), "files": count}


@router.patch("/targets/{target_id}", response_model=TargetRead)
async def update_target(
    target_id: uuid.UUID,
    payload: TargetUpdate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> TargetRead:
    """Partial update. Running runs keep their own scope/limits snapshot."""
    target = await get_target_or_404(session, user, target_id)
    sent = payload.model_fields_set
    if sent <= {"archived"}:
        # Archiving never re-validates: it must work even if platform policy changed.
        if payload.archived is not None:
            target.archived = payload.archived
            await session.commit()
            await session.refresh(target)
        return (await to_reads(session, [target]))[0]

    def pick(field: str, current: Any) -> Any:
        value = getattr(payload, field)
        return value if field in sent and value is not None else current

    scope = dict(target.scope)
    if payload.scope is not None:
        scope.update(payload.scope.model_dump(exclude_none=True))
    limits = dict(target.limits)
    if payload.limits is not None:
        limits.update(payload.limits.model_dump(exclude_none=True))
    description = payload.description if "description" in sent else target.description
    checks = payload.checks if "checks" in sent else target.checks
    # The credential is re-validated when it changes (and again at run start, M2).
    cred_changed = "credential_id" in sent and payload.credential_id != target.credential_id
    acct_changed = "account_ids" in sent and [str(a) for a in payload.account_ids or []] \
        != (target.account_ids or [])
    proxy_id = payload.egress_proxy_id if "egress_proxy_id" in sent \
        else target.egress_proxy_id
    # An unchanged proxy is re-checked only when the host set could have changed.
    proxy_check = ("egress_proxy_id" in sent and proxy_id != target.egress_proxy_id
                   ) or bool(sent & {"base_url", "scope"})
    ev = await evaluate(
        session, target.owner_id, name=pick("name", target.name), description=description,
        base_url=pick("base_url", target.base_url), scope=scope, limits=limits,
        checks=checks,
        credential_id=payload.credential_id if cred_changed else None,
        account_ids=payload.account_ids if acct_changed else None,
        egress_proxy_id=proxy_id if proxy_check else None,
        # Re-validated only when sent: a stored choice whose backend was later
        # unconfigured must not block unrelated edits (it is re-checked at run start).
        model_backend=(payload.model_backend or "") if "model_backend" in sent else "",
        model=(payload.model or "") if sent & {"model", "model_backend"} else "",
        assessment_mode=(payload.assessment_mode
                         if payload.assessment_mode is not None
                         else getattr(target, "assessment_mode", "web")),
        capabilities=(payload.capabilities if "capabilities" in sent
                      else list(getattr(target, "disabled_capabilities", None) or [])),
    )
    if ev.errors or ev.normalized is None:
        _raise_422(ev.errors)
    n = ev.normalized
    target.name = n.name
    target.description = n.description
    target.base_url = n.base_url
    target.scope = n.scope.model_dump()
    target.limits = n.limits.model_dump()
    target.checks = n.checks
    if sent & {"model", "model_backend"}:
        # Changing only the backend resets the model to that backend's default.
        target.model_backend = n.model_backend or ""
        target.model = n.model or ""
    if "credential_id" in sent:
        target.credential_id = payload.credential_id
    if "account_ids" in sent:
        target.account_ids = [str(a) for a in payload.account_ids or []]
    if "egress_proxy_id" in sent:
        target.egress_proxy_id = payload.egress_proxy_id
    target.assessment_mode = n.assessment_mode or "web"
    if "capabilities" in sent or "assessment_mode" in sent:
        target.disabled_capabilities = list(n.capabilities or [])
    if payload.archived is not None:
        target.archived = payload.archived
    await session.commit()
    await session.refresh(target)
    return (await to_reads(session, [target]))[0]


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    target = await get_target_or_404(session, user, target_id)
    if await count_active_runs(session, target_id=target.id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Target has active runs")
    run_ids = list((await session.scalars(
        select(GreyboxRun.id).where(GreyboxRun.target_id == target.id))).all())
    await purge_runs(session, run_ids)
    await session.delete(target)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/targets/{target_id}/preflight", response_model=PreflightResult)
async def preflight_target(
    target_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> PreflightResult:
    """One guarded GET of the target base URL. Nothing is persisted:
    connectivity, scope and IP policy only. Rate limited to 1 per 5 s per target."""
    import time as _time

    target = await get_target_or_404(session, user, target_id)
    now = _time.monotonic()
    last = _PREFLIGHT_AT.get(target.id, 0.0)
    if now - last < PREFLIGHT_INTERVAL_S:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Preflight was called moments ago; wait a few seconds")
    _PREFLIGHT_AT[target.id] = now

    from src.greybox_web.netguard import (
        Budget,
        GuardedHttpClient,
        NetPolicy,
        NullRecorder,
        ScopeViolation,
        TransportFailure,
    )

    scope = ScopePolicy.from_dict(target.scope)
    limits = stored_limits(target.limits).model_dump()
    budget = Budget(max_requests=8, max_duration_s=20)
    started = _time.monotonic()
    result = PreflightResult(ok=False, status_code=None, final_url=None,
                             blocked_reason=None, resolved_ips=[], elapsed_ms=0)
    try:
        from urllib.parse import urlsplit
        host = urlsplit(target.base_url).hostname or ""
        port = urlsplit(target.base_url).port or (443 if target.base_url
                                                  .startswith("https") else 80)
        policy = NetPolicy.from_settings()
        proxy = None
        if target.egress_proxy_id is not None:
            from src.greybox_web.api.egress_proxies import proxy_problem, to_engine_proxy
            problem, prow = await proxy_problem(session, target.egress_proxy_id,
                                                list(scope.allowed_hosts))
            if problem or prow is None:
                return result.model_copy(update={
                    "blocked_reason": "egress proxy unavailable: " + (problem or "")})
            proxy = to_engine_proxy(prow)
        client = GuardedHttpClient(
            scope=scope, budget=budget, policy=policy,
            max_concurrency=2, rate_limit_rps=10,
            request_timeout_s=float(limits.get("request_timeout_s", 10)),
            recorder=NullRecorder(), egress_proxy=proxy)
        try:
            if proxy is None and not policy.host_blocked(host):
                ips = await client.resolver.resolve(host, port)
                # Never reveal addresses the IP policy forbids (internal-DNS
                # oracle): report none if any one is denied.
                if all(policy.address_denial(host, ip, port) is None for ip in ips):
                    result = result.model_copy(update={"resolved_ips": ips[:5]})
        except Exception:                          # noqa: BLE001 — reporting only
            pass
        try:
            resp = await client.request("GET", target.base_url,
                                        prov={"tool": "preflight"})
            result = result.model_copy(update={
                "ok": resp.status is not None and resp.status < 500,
                "status_code": resp.status, "final_url": resp.url})
        except ScopeViolation as exc:
            reason = exc.reason
            if reason == "blocked_host" or reason == "blocked_endpoint" \
                    or reason == "private_ip_for_public_name" \
                    or reason.startswith("ip_denied"):
                reason = "address not permitted"       # generic: no network detail
            result = result.model_copy(update={"blocked_reason": reason})
        except TransportFailure as exc:
            from src.greybox_web.netguard import PROXY_ERRORS
            result = result.model_copy(update={
                "blocked_reason": PROXY_ERRORS.get(exc.kind, exc.kind)})
        finally:
            await client.aclose()
    finally:
        result = result.model_copy(
            update={"elapsed_ms": int((_time.monotonic() - started) * 1000)})
    return result
