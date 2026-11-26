"""Login brute-force throttle.

fastapi-users' auth router has no rate limiting, so repeated password guesses
against ``POST /auth/jwt/login`` are otherwise unbounded. This middleware keeps two
sliding windows of *failed* login attempts in memory, and answers ``429`` (with
``Retry-After``) once EITHER is full:

* per client IP, so one host cannot guess against many accounts;
* per account (normalised email), so many hosts (or a spoofed address) cannot guess
  against one account. Trade-off: someone who knows an email can lock that account
  for up to the window by failing on purpose; the window is short and self-draining.

Both use ``VIGILO_LOGIN_MAX_FAILURES`` / ``VIGILO_LOGIN_FAILURE_WINDOW_S``. A
successful login clears the counters of that IP and that account, so legitimate users
are never locked out by their own earlier typos.

The client IP is the TCP peer unless the peer is a trusted proxy
(``VIGILO_TRUSTED_PROXIES``, default none); only then is ``X-Forwarded-For`` read, and
the right-most address that is NOT a trusted proxy is used, so entries a client
prepended are never believed. Set ``VIGILO_LOGIN_MAX_FAILURES=0`` to disable.

In-memory state is per-process, which is correct for the single-instance deployment.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import parse_qs

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


MAX_TRACKED_KEYS = 50_000      # memory bound; expired entries are purged first
MAX_BODY = 16 * 1024           # login forms are tiny; never buffer more than this


def parse_trusted_proxies(value: str) -> list:
    """``"10.0.0.0/8, 172.18.0.5"`` -> list of ip_network (invalid entries raise)."""
    return [ipaddress.ip_network(p.strip(), strict=False)
            for p in (value or "").split(",") if p.strip()]


def _in(nets, addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in n for n in nets)


def client_ip(peer: str | None, xff: str | None, trusted: list) -> str:
    """Real client address: the peer, unless the peer is a trusted proxy; then walk
    X-Forwarded-For right to left past trusted hops and take the first untrusted one."""
    peer = peer or "unknown"
    if not trusted or not xff or not _in(trusted, peer):
        return peer
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    for hop in reversed(hops):
        if not _in(trusted, hop):
            try:
                return str(ipaddress.ip_address(hop))
            except ValueError:
                return peer      # garbage from the trusted hop: fall back to the peer
    return hops[0] if hops else peer


class LoginRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, max_failures: int = 10, window_s: int = 300,
                 path: str = "/auth/jwt/login", trusted_proxies: str | list = "") -> None:
        super().__init__(app)
        self.max_failures = max_failures
        self.window_s = window_s
        self.path = path
        self.trusted = (parse_trusted_proxies(trusted_proxies)
                        if isinstance(trusted_proxies, str) else list(trusted_proxies))
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _client_key(self, request: Request) -> str:
        peer = request.client.host if request.client else None
        return "ip:" + client_ip(peer, request.headers.get("x-forwarded-for"), self.trusted)

    async def _account_key(self, request: Request) -> str | None:
        """``acct:<normalised email>`` from the login form (None if absent)."""
        body = await request.body()      # cached: the downstream handler still sees it
        if len(body) > MAX_BODY:
            return None
        username = (parse_qs(body.decode("utf-8", "replace")).get("username") or [""])[0]
        username = username.strip().lower()
        return f"acct:{username[:320]}" if username else None

    def _prune(self, key: str, now: float) -> deque:
        dq = self._failures[key]
        while dq and now - dq[0] > self.window_s:
            dq.popleft()
        return dq

    def _purge(self, now: float) -> None:
        if len(self._failures) < MAX_TRACKED_KEYS:
            return
        for k in list(self._failures):
            if not self._prune(k, now):
                del self._failures[k]

    async def dispatch(self, request: Request, call_next):
        if (self.max_failures <= 0
                or request.method != "POST"
                or request.url.path != self.path):
            return await call_next(request)

        keys = [self._client_key(request)]
        acct = await self._account_key(request)
        if acct:
            keys.append(acct)
        now = time.monotonic()
        self._purge(now)
        queues = [self._prune(k, now) for k in keys]

        full = [dq for dq in queues if len(dq) >= self.max_failures]
        if full:
            retry = max(int(self.window_s - (now - dq[0])) + 1 for dq in full)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many failed login attempts. Try again later."},
                headers={"Retry-After": str(max(1, retry))},
            )

        response = await call_next(request)
        if response.status_code == 200:
            for k in keys:           # legitimate login: forget past failures
                self._failures.pop(k, None)
        else:
            for dq in queues:
                dq.append(now)
        return response
