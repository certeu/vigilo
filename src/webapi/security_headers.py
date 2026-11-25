"""Security headers for API responses (pure ASGI, safe for streaming/SSE bodies).

The API only serves JSON/text/file downloads, never HTML, so the CSP is maximally
restrictive. HSTS is opt-in (``VIGILO_HSTS_ENABLED``): sending it over plain http is
harmless but pointless, and a mistaken HSTS on a non-https host is hard to undo.
The interactive docs (when enabled) need scripts/styles from a CDN, so they are
exempt from the CSP.
"""
from __future__ import annotations

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
DOC_PATHS = ("/docs", "/redoc")


class SecurityHeadersMiddleware:
    def __init__(self, app, *, hsts: bool = False) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        is_doc = path in DOC_PATHS or path.startswith("/docs/")

        async def send_wrapper(message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {k.lower() for k, _ in headers}

                def add(name: bytes, value: str) -> None:
                    if name not in present:
                        headers.append((name, value.encode("latin-1")))

                add(b"x-content-type-options", "nosniff")
                add(b"x-frame-options", "DENY")
                add(b"referrer-policy", "no-referrer")
                if not is_doc:
                    add(b"content-security-policy", API_CSP)
                if self.hsts:
                    add(b"strict-transport-security", "max-age=63072000; includeSubDomains")
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)
