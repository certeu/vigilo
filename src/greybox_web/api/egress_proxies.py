"""Opt-in egress proxies. Admin CRUD plus the user-visible ``available`` list.

The routes are mounted behind the grey-box flag AND ``VIGILO_GREYBOX_EGRESS_PROXIES_ENABLED``
(404 when off). Proxy credentials are Fernet-encrypted in one blob and are never returned,
never logged and never part of any run snapshot; the ``has_credentials`` flag is all the
API reveals.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import settings as gb_settings
from src.greybox_web.acl import NOT_FOUND
from src.greybox_web.models import GB_ACTIVE, GreyboxEgressProxy, GreyboxRun, GreyboxTarget
from src.greybox_web.netguard import ALWAYS_DENIED, EgressProxy, classify_ip, parse_ip
from src.greybox_web.pagination import as_utc
from src.greybox_web.scope import normalise_host_pattern
from src.webapi.auth.deps import current_active_user, require_admin
from src.webapi.db import get_async_session
from src.webapi.models import User

logger = logging.getLogger(__name__)


def require_egress_proxies_enabled() -> None:
    if not gb_settings.egress_proxies_enabled():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)


router = APIRouter(prefix="/greybox", tags=["greybox"],
                   dependencies=[Depends(require_egress_proxies_enabled)])


# ----------------------------------------------------------------------- validation


def normalise_proxy_url(raw: str) -> str:
    """``scheme://host[:port]`` or raise ValueError. http/https only; no userinfo, path,
    query or fragment; the host must not be a metadata/link-local/unspecified/multicast/
    reserved address. A private or loopback proxy address is expected and allowed."""
    raw = (raw or "").strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise ValueError("Invalid proxy URL") from None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("The proxy URL must start with http:// or https://")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ValueError("Do not put credentials in the proxy URL; use username and password")
    if not host:
        raise ValueError("The proxy URL needs a host")
    if parts.path not in ("", "/") or parts.query or parts.fragment or "?" in raw \
            or "#" in raw:
        raise ValueError("The proxy URL must be http(s)://host:port, without path or query")
    host = host.lower().rstrip(".")
    ip = parse_ip(host)
    if ip is not None:
        cat = classify_ip(ip)
        if cat in ALWAYS_DENIED:
            raise ValueError(f"The proxy address is not allowed ({cat})")
        host = str(ip)
    h = f"[{host}]" if ":" in host else host
    return f"{scheme}://{h}" + (f":{port}" if port else "")


def normalise_allowed_hosts(items: list[str]) -> list[str]:
    if not items:
        raise ValueError("At least one allowed host is required")
    out: list[str] = []
    for raw in items:
        pattern, err = normalise_host_pattern(raw)
        if err or pattern is None:
            raise ValueError(f"allowed_hosts: {err} ({raw!r})")
        if pattern not in out:
            out.append(pattern)
    return out


class EgressProxyRead(BaseModel):
    id: uuid.UUID
    name: str
    url: str
    has_credentials: bool
    allowed_hosts: list[str]
    enabled: bool
    created_at: datetime
    updated_at: datetime


class EgressProxyAvailable(BaseModel):
    id: uuid.UUID
    name: str
    allowed_hosts: list[str]


class EgressProxyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=500)
    username: str | None = Field(default=None, max_length=200)
    password: str | None = Field(default=None, max_length=500)
    allowed_hosts: list[str] = Field(max_length=200)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name must not be empty")
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return normalise_proxy_url(v)

    @field_validator("allowed_hosts")
    @classmethod
    def _hosts(cls, v: list[str]) -> list[str]:
        return normalise_allowed_hosts(v)


class EgressProxyUpdate(BaseModel):
    """PATCH: only the fields present change. Sending ``username``/``password`` replaces
    the stored credentials (a missing half keeps the stored value); sending both as null
    (or ``username: null``) removes them."""

    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    url: str | None = Field(default=None, min_length=1, max_length=500)
    username: str | None = Field(default=None, max_length=200)
    password: str | None = Field(default=None, max_length=500)
    allowed_hosts: list[str] | None = Field(default=None, max_length=200)
    enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("Name must not be empty")
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        return None if v is None else normalise_proxy_url(v)

    @field_validator("allowed_hosts")
    @classmethod
    def _hosts(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else normalise_allowed_hosts(v)


# --------------------------------------------------------------------- credentials


def _encrypt(username: str | None, password: str | None) -> bytes | None:
    if not username:
        return None
    from src.webapi.security.vault import build_vault
    blob = json.dumps({"u": username, "p": password or ""})
    return build_vault(gb_settings.settings()).encrypt(blob)


def _decrypt(token: bytes | None) -> tuple[str | None, str | None]:
    if not token:
        return None, None
    from src.webapi.security.vault import build_vault
    data = json.loads(build_vault(gb_settings.settings()).decrypt(token))
    return data.get("u") or None, data.get("p") or ""


def to_engine_proxy(row: GreyboxEgressProxy) -> EgressProxy:
    """The runtime view (credentials decrypted). Used by the supervisor and preflight."""
    user, password = _decrypt(row.credentials_enc)
    return EgressProxy(id=str(row.id), name=row.name, url=row.url,
                       allowed_hosts=tuple(row.allowed_hosts or ()),
                       username=user, password=password)


def _read(row: GreyboxEgressProxy) -> EgressProxyRead:
    return EgressProxyRead(
        id=row.id, name=row.name, url=row.url,
        has_credentials=row.credentials_enc is not None,
        allowed_hosts=list(row.allowed_hosts or ()), enabled=row.enabled,
        created_at=as_utc(row.created_at), updated_at=as_utc(row.updated_at))


# ----------------------------------------------------------- shared with targets / runs


async def proxy_problem(session: AsyncSession, proxy_id: uuid.UUID,
                        scope_hosts: list[str]) -> tuple[str | None, GreyboxEgressProxy | None]:
    """Why a target (with these in-scope host patterns) cannot use ``proxy_id`` now, or
    ``(None, row)`` when it can."""
    if not gb_settings.egress_proxies_enabled():
        return "Egress proxies are not enabled on this platform", None
    row = await session.get(GreyboxEgressProxy, proxy_id)
    if row is None or not row.enabled:
        return "Unknown or disabled egress proxy", None
    missing = EgressProxy(id=str(row.id), name=row.name, url=row.url,
                          allowed_hosts=tuple(row.allowed_hosts or ())).covers(scope_hosts)
    if missing:
        return (f"Egress proxy '{row.name}' does not allow these in-scope hosts: "
                f"{', '.join(missing)}. Its allowed hosts are: "
                f"{', '.join(row.allowed_hosts or ())}"), None
    return None, row


# ------------------------------------------------------------------------- routes


@router.get("/egress-proxies/available", response_model=list[EgressProxyAvailable])
async def available_proxies(
    _: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[EgressProxyAvailable]:
    rows = (await session.scalars(
        select(GreyboxEgressProxy).where(GreyboxEgressProxy.enabled.is_(True))
        .order_by(GreyboxEgressProxy.name))).all()
    return [EgressProxyAvailable(id=r.id, name=r.name,
                                 allowed_hosts=list(r.allowed_hosts or ())) for r in rows]


@router.get("/egress-proxies", response_model=list[EgressProxyRead])
async def list_proxies(
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> list[EgressProxyRead]:
    rows = (await session.scalars(
        select(GreyboxEgressProxy).order_by(GreyboxEgressProxy.name))).all()
    return [_read(r) for r in rows]


@router.post("/egress-proxies", response_model=EgressProxyRead,
             status_code=status.HTTP_201_CREATED)
async def create_proxy(
    payload: EgressProxyCreate,
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> EgressProxyRead:
    if payload.password and not payload.username:
        raise HTTPException(status_code=422, detail=[{
            "loc": ["body", "username"], "msg": "A password needs a username",
            "type": "value_error"}])
    row = GreyboxEgressProxy(
        name=payload.name, url=payload.url, allowed_hosts=payload.allowed_hosts,
        credentials_enc=_encrypt(payload.username, payload.password),
        enabled=payload.enabled, created_by=admin.id)
    session.add(row)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status_code=409, detail="An egress proxy with this name exists") \
            from None
    await session.refresh(row)
    logger.info("egress proxy %s created by %s", row.id, admin.id)
    return _read(row)


async def _get(session: AsyncSession, proxy_id: uuid.UUID) -> GreyboxEgressProxy:
    row = await session.get(GreyboxEgressProxy, proxy_id)
    if row is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return row


@router.get("/egress-proxies/{proxy_id}", response_model=EgressProxyRead)
async def get_proxy(
    proxy_id: uuid.UUID,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> EgressProxyRead:
    return _read(await _get(session, proxy_id))


@router.patch("/egress-proxies/{proxy_id}", response_model=EgressProxyRead)
async def update_proxy(
    proxy_id: uuid.UUID,
    payload: EgressProxyUpdate,
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> EgressProxyRead:
    row = await _get(session, proxy_id)
    sent = payload.model_fields_set
    for field in ("name", "url", "allowed_hosts", "enabled"):
        value = getattr(payload, field)
        if field in sent and value is not None:
            setattr(row, field, value)
    if sent & {"username", "password"}:
        old_user, old_pass = _decrypt(row.credentials_enc)
        user = payload.username if "username" in sent else old_user
        password = payload.password if "password" in sent else old_pass
        if password and not user:
            raise HTTPException(status_code=422, detail=[{
                "loc": ["body", "username"], "msg": "A password needs a username",
                "type": "value_error"}])
        row.credentials_enc = _encrypt(user, password)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status_code=409, detail="An egress proxy with this name exists") \
            from None
    await session.refresh(row)
    logger.info("egress proxy %s updated by %s", row.id, admin.id)
    return _read(row)


@router.delete("/egress-proxies/{proxy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_proxy(
    proxy_id: uuid.UUID,
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    row = await _get(session, proxy_id)
    snaps = (await session.scalars(
        select(GreyboxRun.egress_proxy).where(
            GreyboxRun.status.in_(tuple(GB_ACTIVE)),
            GreyboxRun.egress_proxy.isnot(None)))).all()
    if any(isinstance(s, dict) and s.get("id") == str(proxy_id) for s in snaps):
        raise HTTPException(status_code=409, detail="Active runs are using this egress proxy")
    # Targets keep working on the direct path (fully guarded) once the reference is gone.
    await session.execute(
        update(GreyboxTarget).where(GreyboxTarget.egress_proxy_id == proxy_id)
        .values(egress_proxy_id=None).execution_options(synchronize_session=False))
    await session.delete(row)
    await session.commit()
    logger.info("egress proxy %s deleted by %s", proxy_id, admin.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
