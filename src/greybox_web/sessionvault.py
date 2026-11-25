"""Encrypted, bounded persistence of a run's identities across a resume.

What is kept: the sessions ``auth.login`` established (label → Cookie /
Authorization) and each browser identity's cookie jar. Where: one column,
``greybox_runs.session_vault``, encrypted with the platform's Fernet vault (the key
that protects stored credentials). When: rewritten whenever an identity changes, so
a crash does not lose it. For how long: restored only within
``VIGILO_GREYBOX_SESSION_MAX_AGE_S`` (default 12 h) of the last write — an older
state is discarded and the agent is told to authenticate again; it is deleted with
the run. Never returned by the API, never part of events, knowledge or reports.
Restored values are registered as redaction secrets before anything else runs.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

MAX_AGE_ENV = "VIGILO_GREYBOX_SESSION_MAX_AGE_S"
DEFAULT_MAX_AGE_S = 12 * 3600
MAX_JAR_COOKIES = 60
VERSION = 1


def max_age_s() -> int:
    try:
        return max(0, int(os.environ.get(MAX_AGE_ENV) or DEFAULT_MAX_AGE_S))
    except ValueError:
        return DEFAULT_MAX_AGE_S


def _vault():
    from src.greybox_web import settings as gb_settings
    from src.webapi.security.vault import build_vault
    return build_vault(gb_settings.settings())


def seal(sessions: dict[str, dict], jars: dict[str, list[dict]],
         now: float | None = None) -> bytes:
    doc = {"v": VERSION, "saved_at": now if now is not None else time.time(),
           "sessions": {k: {"cookie": v.get("cookie"),
                            "authorization": v.get("authorization")}
                        for k, v in sessions.items()},
           "jars": {k: [{f: c.get(f) for f in ("name", "value", "domain", "path",
                                                "secure", "httpOnly", "sameSite",
                                                "expires") if f in c}
                        for c in v[:MAX_JAR_COOKIES]]
                    for k, v in jars.items()}}
    return _vault().encrypt(json.dumps(doc))


def unseal(blob: bytes | None, now: float | None = None) -> tuple[dict | None, str]:
    """(state, why). ``state`` is None when there is nothing usable; ``why`` says
    why (absent / expired / unreadable) for the run's audit trail."""
    if not blob:
        return None, "absent"
    try:
        doc = json.loads(_vault().decrypt(blob))
    except Exception:                                   # noqa: BLE001 — key rotated
        return None, "unreadable"
    age = (now if now is not None else time.time()) - float(doc.get("saved_at") or 0)
    if age > max_age_s():
        return None, f"expired ({int(age)} s old; max {max_age_s()} s)"
    return doc, "ok"


def register_secrets(doc: dict[str, Any]) -> None:
    from src.greybox_web import redaction
    from src.greybox_web.netguard import register_session_secrets
    for s in (doc.get("sessions") or {}).values():
        register_session_secrets(redaction, s.get("cookie"), s.get("authorization"))
    for jar in (doc.get("jars") or {}).values():
        for c in jar:
            if len(str(c.get("value") or "")) >= 8:
                redaction.register_secret(str(c["value"]))
