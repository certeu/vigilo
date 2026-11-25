"""Accessors over the ``greybox_*`` fields of ``src.webapi.settings.Settings``.

Always read through :func:`src.webapi.settings.get_settings` at call time (never cached
here) so tests can flip the environment and clear the settings cache.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from src.webapi.settings import Settings, get_settings

# Platform service names that can never be a grey-box target.
BUILTIN_BLOCKED_HOSTS = (
    "api", "web", "db", "postgres", "temporal", "surrealdb", "localhost.localdomain",
)
API_LISTEN_PORT = 8080      # historical default; also always blocked (see blocked_endpoints)
PRIVATE_SCOPE = "private"   # blocked-endpoint host meaning "any loopback/private address"


def settings() -> Settings:
    return get_settings()


def enabled(s: Settings | None = None) -> bool:
    return bool((s or get_settings()).greybox_web_enabled)


def egress_proxies_enabled(s: Settings | None = None) -> bool:
    return bool((s or get_settings()).greybox_egress_proxies_enabled)


def _csv(value: str) -> list[str]:
    return [p.strip().lower().rstrip(".") for p in (value or "").split(",") if p.strip()]


def blocked_hosts(s: Settings | None = None) -> frozenset[str]:
    s = s or get_settings()
    hosts = set(BUILTIN_BLOCKED_HOSTS) | set(_csv(s.greybox_blocked_hosts))
    try:
        internal = (urlsplit(s.internal_api_url).hostname or "").lower().rstrip(".")
    except ValueError:
        internal = ""
    if internal:
        hosts.add(internal)
    return frozenset(hosts)


def _db_port(database_url: str) -> int | None:
    try:
        from sqlalchemy.engine import make_url
        url = make_url(database_url)
    except Exception:
        return None
    if url.get_backend_name() == "sqlite":
        return None
    if url.port:
        return int(url.port)
    return {"postgresql": 5432, "mysql": 3306}.get(url.get_backend_name())


@dataclass(frozen=True)
class BlockedEndpoint:
    host: str          # PRIVATE_SCOPE, an IP literal or a hostname (lowercase)
    port: int


def blocked_endpoints(s: Settings | None = None) -> tuple[BlockedEndpoint, ...]:
    s = s or get_settings()
    # The ACTUAL public API port (VIGILO_API_PORT) plus the default 8080 (a harmless
    # superset if the port was changed), the internal listener and the database.
    out: list[BlockedEndpoint] = [
        BlockedEndpoint(PRIVATE_SCOPE, int(s.api_port)),
        BlockedEndpoint(PRIVATE_SCOPE, API_LISTEN_PORT),
        BlockedEndpoint(PRIVATE_SCOPE, int(s.internal_port)),
    ]
    # A specific (non-wildcard) bind address is blocked on that port too, even if public.
    bind = (s.api_host or "").strip().strip("[]").lower()
    if bind and bind not in ("0.0.0.0", "::", "*"):
        out.append(BlockedEndpoint(bind, int(s.api_port)))
        out.append(BlockedEndpoint(bind, int(s.internal_port)))
    dbp = _db_port(s.database_url)
    if dbp:
        out.append(BlockedEndpoint(PRIVATE_SCOPE, dbp))
    for item in _csv(s.greybox_blocked_endpoints):
        host, sep, port = item.rpartition(":")
        if not sep or not port.isdigit():
            continue
        host = host.strip("[]") or PRIVATE_SCOPE
        out.append(BlockedEndpoint(host, int(port)))
    seen: set[BlockedEndpoint] = set()
    return tuple(e for e in out if not (e in seen or seen.add(e)))
