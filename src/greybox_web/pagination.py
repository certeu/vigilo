"""Opaque cursors for grey-box lists: base64url of ``created_at|...|id``."""
from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException

DEFAULT_LIMIT = 50
MAX_LIMIT = 100


def clamp_limit(limit: int | None, default: int = DEFAULT_LIMIT, cap: int = MAX_LIMIT) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), cap))


def as_utc(dt: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes (stored as UTC); make them aware."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def encode_cursor(*parts: object) -> str:
    out = []
    for p in parts:
        if isinstance(p, datetime):
            p = as_utc(p).isoformat()
        out.append(str(p))
    return base64.urlsafe_b64encode("|".join(out).encode()).decode().rstrip("=")


def decode_cursor(cursor: str, n_parts: int) -> list[str]:
    try:
        pad = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(cursor + pad).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=422, detail="Invalid cursor") from None
    parts = raw.split("|")
    if len(parts) != n_parts:
        raise HTTPException(status_code=422, detail="Invalid cursor")
    return parts


def parse_ts(value: str) -> datetime:
    try:
        return as_utc(datetime.fromisoformat(value))
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid cursor") from None


def parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid cursor") from None


def decode_embedded_cursor(cursor: str) -> dict[str, object] | None:
    """Decode an opaque cursor only when it is base64url-encoded JSON.

    This is evidence for parameters an application transports in its cursor, not
    permission evidence and not permission to invent or mutate cursor contents.
    """
    if not cursor or len(cursor) > 4096:
        return None
    try:
        import json
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def response_page(document: object) -> tuple[int, str | None, bool | None]:
    """Return item count, server-provided next cursor, and has-more flag."""
    if not isinstance(document, dict):
        return 0, None, None
    items = next((value for key in ("data", "items", "results", "records")
                  if isinstance((value := document.get(key)), list)), [])
    cursor = next((document.get(key) for key in ("next_cursor", "nextCursor", "cursor", "continuationToken")
                   if isinstance(document.get(key), str) and document.get(key)), None)
    has_more = next((document.get(key) for key in ("has_more", "hasMore")
                     if isinstance(document.get(key), bool)), None)
    return len(items), cursor, has_more
