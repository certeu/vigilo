"""Admin invitations: invite by email, redeem via token to set a password."""
from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi_users.password import PasswordHelper
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.auth.deps import require_admin
from src.webapi.db import get_async_session
from src.webapi.mailer_provider import get_mailer
from src.webapi.models import Invitation, User
from src.webapi.notifications import Mailer
from src.webapi.notifications import FakeMailer
from src.webapi.schemas import (
    AcceptInvite,
    InvitationCreate,
    InvitationCreated,
    InvitationRead,
)
from src.webapi.settings import get_settings

router = APIRouter(tags=["invitations"])
logger = logging.getLogger(__name__)


def _to_read(inv: Invitation) -> InvitationRead:
    return InvitationRead(
        id=inv.id, email=inv.email, role=inv.role,
        accepted=inv.accepted_at is not None, created_at=inv.created_at,
    )


@router.post("/invitations", response_model=InvitationCreated,
             status_code=status.HTTP_201_CREATED)
async def create_invitation(
    payload: InvitationCreate,
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
    mailer: Mailer = Depends(get_mailer),
) -> InvitationCreated:
    email = payload.email.lower()
    existing_user = await session.scalar(select(User).where(User.email == email))
    if existing_user is not None:
        raise HTTPException(status_code=409, detail="A user with that email exists")
    inv = Invitation(
        email=email, token=secrets.token_urlsafe(32), role=payload.role,
        invited_by=admin.id,
    )
    session.add(inv)
    await session.commit()
    await session.refresh(inv)

    base = get_settings().ui_base_url or ""
    link = f"{base}/accept-invite?token={inv.token}"
    body = (
        f"You've been invited to Vigilo as '{inv.role}'.\n\n"
        f"Set your password here: {link}\n"
    )
    # Distinguish three states so the admin sees the truth (and we surface the link
    # to share manually whenever the email didn't actually go out):
    #   - no SMTP configured (FakeMailer)        -> email_error="SMTP not configured"
    #   - SMTP configured but send raised         -> email_error=<reason> (logged)
    #   - sent                                    -> email_sent=True, no error
    email_sent = False
    email_error: str | None = None
    try:
        mailer.send(email, "[Vigilo] You're invited", body, None)
        if isinstance(mailer, FakeMailer):
            email_error = "SMTP not configured"  # no-op mailer: nothing actually sent
        else:
            email_sent = True
    except Exception as exc:  # relay unreachable, auth failure, etc.
        email_error = f"Email send failed: {type(exc).__name__}: {str(exc)[:200]}"
        logger.warning("Invitation email to %s failed: %s", email, exc)
    base_read = _to_read(inv)
    return InvitationCreated(
        **base_read.model_dump(), accept_url=link,
        email_sent=email_sent, email_error=email_error,
    )


@router.get("/invitations", response_model=list[InvitationRead])
async def list_invitations(
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> list[InvitationRead]:
    rows = (await session.scalars(select(Invitation))).all()
    return [_to_read(i) for i in rows]


@router.delete("/invitations/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_invitation(
    invitation_id: uuid.UUID,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> None:
    inv = await session.get(Invitation, invitation_id)
    if inv is not None and inv.accepted_at is None:
        await session.delete(inv)
        await session.commit()


@router.post("/auth/accept-invite", response_model=dict)
async def accept_invite(
    payload: AcceptInvite,
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    inv = await session.scalar(
        select(Invitation).where(Invitation.token == payload.token)
    )
    if inv is None or inv.accepted_at is not None:
        raise HTTPException(status_code=400, detail="Invalid or already-used invitation")
    if len(payload.password) < 8:
        raise HTTPException(status_code=422, detail="Password too short (min 8)")
    # Guard against a race where the email got registered meanwhile.
    if await session.scalar(select(User).where(User.email == inv.email)):
        raise HTTPException(status_code=409, detail="User already exists")
    session.add(User(
        email=inv.email, hashed_password=PasswordHelper().hash(payload.password),
        role=inv.role, is_active=True, is_superuser=False, is_verified=True,
    ))
    inv.accepted_at = datetime.now(timezone.utc)
    await session.commit()
    return {"status": "ok", "email": inv.email}
