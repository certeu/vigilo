"""Per-run secret records: issue, redeem just in time, revoke.

A run that needs a secret (the owner's forge token to push patches, a cookie header
for authenticated testing) gets ONE record here, encrypted with the platform's Fernet
key and keyed by a random *redemption key*. Only a reference (run id + key) goes into
the workflow input; the worker redeems it over the internal listener
(``src/webapi/internal.py``) for the single call that needs the value.

Rules enforced by :func:`redeem`: the key must match this run's record
(constant-time), the run must not be terminal, the record must not be expired, the
caller may only ask for kinds the record holds, and redemptions are rate limited and
logged (never the values). Records are deleted when the run ends, is cancelled, or
fails to start (:func:`revoke`).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.models import RUN_TERMINAL, Run, RunSecret
from src.webapi.security.vault import build_vault
from src.webapi.settings import get_settings

logger = logging.getLogger(__name__)

SECRET_KINDS = ("forge_token", "cookie_header")
# Earlier name of a kind -> its current name. Records issued before the rename (and
# callers that still ask for the old name) keep working.
LEGACY_KINDS = {"gitlab_token": "forge_token"}


class RedemptionRefused(Exception):
    """Wrong key / unknown or finished run / nothing to give (HTTP 403)."""


class RedemptionRateLimited(Exception):
    """Too many attempts for this run (HTTP 429)."""


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def issue(session: AsyncSession, run_id: uuid.UUID, bundle: dict[str, str]) -> str:
    """Store ``bundle`` (kind -> value) for the run; return the redemption key.
    Replaces any earlier record of the run."""
    bundle = {LEGACY_KINDS.get(k, k): v for k, v in bundle.items()}
    bundle = {k: v for k, v in bundle.items() if k in SECRET_KINDS and v}
    if not bundle:
        raise ValueError("nothing to store")
    settings = get_settings()
    key = secrets.token_urlsafe(32)
    await session.execute(delete(RunSecret).where(RunSecret.run_id == run_id))
    session.add(RunSecret(
        run_id=run_id,
        key_hash=_hash(key),
        secret_enc=build_vault(settings).encrypt(json.dumps(bundle)),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.secret_max_age_hours),
    ))
    await session.commit()
    return key


async def revoke(session: AsyncSession, run_id: uuid.UUID) -> bool:
    """Delete the run's record (idempotent). True when one existed."""
    res = await session.execute(delete(RunSecret).where(RunSecret.run_id == run_id))
    await session.commit()
    return bool(res.rowcount)


async def revoke_for_run(run_id: uuid.UUID) -> None:
    """Best-effort revoke from engine code (own session; never raises)."""
    try:
        from src.webapi.db import _session_maker

        async with _session_maker()() as session:
            await revoke(session, run_id)
    except Exception as exc:  # pragma: no cover - best-effort
        logger.warning("could not revoke secrets of run %s: %s", run_id, exc)


async def purge_finished(session: AsyncSession) -> int:
    """Safety net: drop records of terminal runs and expired records."""
    terminal = select(Run.id).where(Run.status.in_(tuple(RUN_TERMINAL)))
    res = await session.execute(delete(RunSecret).where(RunSecret.run_id.in_(terminal)))
    res2 = await session.execute(
        delete(RunSecret).where(RunSecret.expires_at < datetime.now(timezone.utc))
    )
    await session.commit()
    return (res.rowcount or 0) + (res2.rowcount or 0)


# -- rate limiting (in-process; the API is a single process) ---------------------------
#
# The key is checked FIRST. A valid key is only subject to a (generous) per-run success
# limit; limits on *failed* attempts (per run, per source address, global) only ever
# slow down callers that do not hold the key, so a stranger who spams a run id cannot
# starve the run's own worker (the key is 256 bits: guessing is infeasible, the limits
# just stop log/CPU flooding).

_ok_attempts: dict[str, deque] = defaultdict(deque)
_failed: dict[str, deque] = defaultdict(deque)
_failed_global: deque = deque()


def _hit(q: deque, limit: int, now: float) -> bool:
    """Record one event; True when the window (60 s) now exceeds ``limit``."""
    while q and now - q[0] > 60:
        q.popleft()
    q.append(now)
    return len(q) > limit


def _prune(d: dict[str, deque], now: float) -> None:
    if len(d) > 10_000:  # bound memory: forget idle keys
        for k in [k for k, q in d.items() if not q or now - q[-1] > 60]:
            d.pop(k, None)


def _rate_limit_success(run_id: str) -> None:
    limit = get_settings().redeem_max_per_minute
    if limit <= 0:
        return
    now = time.monotonic()
    if _hit(_ok_attempts[run_id], limit, now):
        raise RedemptionRateLimited(run_id)
    _prune(_ok_attempts, now)


def _rate_limit_failure(run_id: str, client: str) -> None:
    """Count a failed attempt; raise when this run, this source or the whole API
    sees too many of them."""
    limit = get_settings().redeem_max_per_minute
    if limit <= 0:
        return
    now = time.monotonic()
    over = _hit(_failed[f"run:{run_id}"], limit, now)
    over = _hit(_failed[f"src:{client}"], limit * 5, now) or over
    over = _hit(_failed_global, limit * 20, now) or over
    _prune(_failed, now)
    if over:
        raise RedemptionRateLimited(run_id)


def reset_rate_limits() -> None:
    _ok_attempts.clear()
    _failed.clear()
    _failed_global.clear()


async def redeem(
    session: AsyncSession, run_id: uuid.UUID, key: str, want: list[str], client: str = "?",
) -> dict[str, str]:
    """Return the requested secrets of ``run_id`` or raise.

    Only the kinds in ``want`` are returned, so a caller that needs the cookie never
    receives the token and vice versa."""
    rec = await session.get(RunSecret, run_id)
    if rec is None or not key or not hmac.compare_digest(rec.key_hash, _hash(key)):
        logger.warning("secret redemption refused: run=%s client=%s (bad key or no record)",
                       run_id, client)
        _rate_limit_failure(str(run_id), client)
        raise RedemptionRefused("refused")
    _rate_limit_success(str(run_id))
    run = await session.get(Run, run_id)
    if run is None or run.status in RUN_TERMINAL or _utc(rec.expires_at) < datetime.now(timezone.utc):
        await session.execute(delete(RunSecret).where(RunSecret.run_id == run_id))
        await session.commit()
        logger.warning("secret redemption refused: run=%s client=%s (run finished/expired)",
                       run_id, client)
        raise RedemptionRefused("refused")
    bundle = json.loads(build_vault(get_settings()).decrypt(rec.secret_enc))
    bundle = {LEGACY_KINDS.get(k, k): v for k, v in bundle.items()}
    out = {k: bundle[LEGACY_KINDS.get(k, k)] for k in want if LEGACY_KINDS.get(k, k) in bundle}
    if not out:
        raise RedemptionRefused("refused")
    rec.redeem_count += 1
    rec.last_redeemed_at = datetime.now(timezone.utc)
    await session.commit()
    logger.info("secret redeemed: run=%s kinds=%s count=%d client=%s",
                run_id, sorted(out), rec.redeem_count, client)
    return out
