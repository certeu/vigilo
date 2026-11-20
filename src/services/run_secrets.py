"""Worker-side redemption of per-run secrets.

The platform never writes a secret to disk and never puts one in the workflow input.
The input carries only a reference, ``secrets = {"ref": <run id>, "key": <random
redemption key>}``, plus non-secret flags (``push.enabled``, ``auth.cookie``). An
activity that needs a secret calls :func:`redeem` for exactly the kinds it needs,
holds the value in memory for that call only, and drops it. The API refuses the
redemption for any other run, a wrong key, a finished run, or an expired record (see
``src/webapi/secret_store.py``).

The key is in Temporal history (internal-only); it is never written to the worker's
environment, agent prompts, logs or events, and the agent subprocess environment is
stripped of anything secret-looking (``src/ai/envguard.py``).

Dependency-free beyond the standard library so the worker image needs nothing extra.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any

from src.audit.redact import register_secret

logger = logging.getLogger(__name__)

DEFAULT_INTERNAL_API_URL = "http://api:8081"


class RedemptionRefused(Exception):
    """The platform will not hand the secret out (wrong key, run finished, ...).
    Permanent: retrying cannot help."""


class RedemptionUnavailable(Exception):
    """The internal API could not be reached or answered with an error. Transient."""


def internal_api_url() -> str:
    return (os.environ.get("VIGILO_INTERNAL_API_URL") or DEFAULT_INTERNAL_API_URL).rstrip("/")


def has_reference(secrets: dict[str, Any] | None) -> bool:
    return bool(secrets and secrets.get("ref") and secrets.get("key"))


def _post(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    # Internal network only: never through an HTTP(S) proxy from the environment.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 403, 404, 410, 422):
            raise RedemptionRefused(f"HTTP {exc.code}") from None
        raise RedemptionUnavailable(f"HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RedemptionUnavailable(type(exc).__name__) from None


async def redeem(
    secrets: dict[str, Any] | None, want: Iterable[str], *, timeout: float = 15.0,
) -> dict[str, str]:
    """Redeem the requested secret kinds (``forge_token`` / ``cookie_header``).

    Every returned value is registered for masking in persisted output. Raises
    :class:`RedemptionRefused` / :class:`RedemptionUnavailable`; never includes the key
    or a value in an error message."""
    if not has_reference(secrets):
        raise RedemptionRefused("no secret reference in the workflow input")
    url = f"{internal_api_url()}/internal/v1/runs/{secrets['ref']}/secrets"
    body = await asyncio.to_thread(
        _post, url, {"key": secrets["key"], "want": list(want)}, timeout,
    )
    out = {k: v for k, v in (body.get("secrets") or {}).items() if isinstance(v, str) and v}
    for value in out.values():
        register_secret(value)
    return out
