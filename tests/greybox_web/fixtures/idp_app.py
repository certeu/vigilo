"""An application behind a single-sign-on proxy: a common enterprise authentication shape.

``/app/`` and everything below it is protected. A request without a valid session
gets ``302`` to an **out-of-scope identity provider** (``login.idp.invalid`` — the
``.invalid`` TLD never resolves, so a test that follows it fails visibly). With a
valid session the application answers normally and sets the metadata a real
application leaks: a server banner, a framework header, cookies, and the signed-in
user's address.

Two operator credentials model the two states that matter:

* ``alice-session``  — valid: ``sid=alice-session`` is accepted;
* anything else      — expired: the application redirects to the identity provider,
  which is exactly what "the saved cookie went stale" looks like on the wire.

The identity provider page it would redirect to is *also* served here (under
``/idp/login``) so a test can assert that the platform never fetches it — scope
(forbids) has to win, not reachability.
"""
from __future__ import annotations

import threading
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

IDP_HOST = "login.idp.invalid"
VALID_SESSIONS = {"alice-session"}

IDP_PAGE = """<!doctype html><html><head><title>Sign in to your account</title>
</head><body><div id="lightbox">Sign in</div>
<span id="user">alice@example.test</span></body></html>"""

_counts: dict[str, int] = {}
_lock = threading.Lock()


def counts() -> dict[str, int]:
    with _lock:
        return dict(_counts)


def reset_counts() -> None:
    with _lock:
        _counts.clear()


def _hit(path: str) -> None:
    with _lock:
        _counts[path] = _counts.get(path, 0) + 1


def _authed(request: Request) -> bool:
    sid = request.cookies.get("sid") or ""
    return sid in VALID_SESSIONS


def _to_idp(request: Request) -> RedirectResponse:
    return RedirectResponse(
        f"https://{IDP_HOST}/oauth2/authorize?client_id=vigilo&"
        f"redirect_uri={request.url.scheme}://{request.url.netloc}/app/callback",
        status_code=302)


async def app_index(request: Request) -> Response:
    _hit(request.url.path)
    if not _authed(request):
        return _to_idp(request)
    return HTMLResponse("""<!doctype html><html><head><title>Workspace</title></head>
<body><h1>Workspace</h1><ul><li><a href="/app/folder">folder</a></li></ul>
</body></html>""", headers={
        "Server": "nginx/1.25.3",
        "X-Powered-By": "Next.js",
        "Set-Cookie": "app_pref=dark; Path=/; HttpOnly",
    })


async def folder(request: Request) -> Response:
    _hit(request.url.path)
    if not _authed(request):
        return _to_idp(request)
    return HTMLResponse("<h1>Folder</h1><p>alice@example.test</p>")


async def api_whoami(request: Request) -> Response:
    _hit(request.url.path)
    if not _authed(request):
        return _to_idp(request)
    return JSONResponse({"user": "alice@example.test", "role": "member"})


async def callback(request: Request) -> Response:
    _hit(request.url.path)
    return Response("callback", status_code=500)


async def idp_login(request: Request) -> Response:
    """What an over-eager crawler would fetch if it followed the redirect."""
    _hit(request.url.path)
    return HTMLResponse(IDP_PAGE)


async def not_found(request: Request, exc: Exception) -> Response:
    _hit(request.url.path)
    if not _authed(request):
        return _to_idp(request)
    return HTMLResponse("<h1>Not found</h1>", status_code=404)


def build_app() -> Starlette:
    return Starlette(routes=[
        Route("/app", app_index),
        Route("/app/", app_index),
        Route("/app/folder", folder),
        Route("/app/callback", callback),
        Route("/app/api/whoami", api_whoami),
        Route("/idp/login", idp_login),
    ], exception_handlers={404: not_found})


def serve(blocking: bool = False, port: int = 0):
    import uvicorn

    config = uvicorn.Config(build_app(), host="127.0.0.1", port=port,
                            log_level="warning", lifespan="off", access_log=False,
                            server_header=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="gb-idp")
    thread.start()
    while not server.started:
        time.sleep(0.01)
    actual = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{actual}/"
    if blocking:
        thread.join()
    return server, url


def main(argv: list[str] | None = None) -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0)
    _, url = serve(blocking=True, port=parser.parse_args(argv).port)
    print(url)


if __name__ == "__main__":
    main()
