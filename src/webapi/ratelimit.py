"""Login brute-force throttle.

fastapi-users' auth router has no rate limiting, so repeated password guesses
against ``POST /auth/jwt/login`` are otherwise unbounded. This middleware keeps a
per-client sliding window of *failed* login attempts in memory; once a client
exceeds the threshold it gets ``429`` until the window drains. A successful login
clears that client's counter, so legitimate users are never locked out by their
own earlier typos.

In-memory state is per-process, which is correct for the single-instance
docker-compose deployment. Behind Traefik the real client is taken from the
first ``X-Forwarded-For`` hop; direct (:8080) hits fall back to the peer address.
Set ``VIGILO_LOGIN_MAX_FAILURES=0`` to disable (e.g. in tests).
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class LoginRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, max_failures: int = 10, window_s: int = 300,
                 path: str = "/auth/jwt/login") -> None:
        super().__init__(app)
        self.max_failures = max_failures
        self.window_s = window_s
        self.path = path
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _client_key(self, request: Request) -> str:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        if (self.max_failures <= 0
                or request.method != "POST"
                or request.url.path != self.path):
            return await call_next(request)

        key = self._client_key(request)
        now = time.monotonic()
        dq = self._failures[key]
        while dq and now - dq[0] > self.window_s:
            dq.popleft()

        if len(dq) >= self.max_failures:
            retry = int(self.window_s - (now - dq[0])) + 1
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many failed login attempts. Try again later."},
                headers={"Retry-After": str(max(1, retry))},
            )

        response = await call_next(request)
        if response.status_code == 200:
            dq.clear()  # legitimate login → forget past failures
        else:
            dq.append(now)
        return response
