"""Synthetic local grey-box target — the ONLY target tests scan.

A small Starlette app with deliberate weaknesses, each with a matching negative
control, and a per-path request counter so tests can assert that excluded or
blocked URLs were never requested. Served by uvicorn on 127.0.0.1:0 (ephemeral
port, never a platform port) from a background thread; never exposed publicly.

Manual / Playwright use::

    python -m tests.greybox_web.fixtures.target_app --port 0
    # prints the base URL and keeps running
"""
from __future__ import annotations

import argparse
import random
import re
import threading
import time
from urllib.parse import parse_qsl

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Route

SLOW_SECONDS = 30.0
SERVER_BANNER = "DemoServer/1.2.3"

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


def _html(body: str, status: int = 200, headers: dict[str, str] | None = None) \
        -> HTMLResponse:
    h = {"Server": SERVER_BANNER, **(headers or {})}
    return HTMLResponse(body, status_code=status, headers=h)


SOFT_404 = ("<!doctype html><html><head><title>Demo app</title></head><body>"
            "<h1>Page not found</h1><p>Nothing is served here.</p></body></html>")

# A Werkzeug-style debugger page (info.errors): matches discovery's
# ERROR_SIGNATURES ("Traceback (most recent call last)", "Werkzeug Debugger") and
# must NOT match the SQL-error text of /item — it is a distinct weakness. Ordinary
# 404/soft-404 pages (SOFT_404) are the negative control: they match nothing.
DEBUG_PAGE = ("<!doctype html><html><head><title>Werkzeug Debugger</title></head><body>"
              "<h1>Werkzeug Debugger</h1>"
              "<p><b>Console Locked</b>: a console is already open (click to unlock).</p>"
              "<pre>Traceback (most recent call last):\n"
              '  File "/app/handler.py", line 42, in dispatch\n'
              "    handler(request)\n"
              '  File "/app/views.py", line 17, in render\n'
              "    return render(template)\n"
              "ValueError: unsupported format character\n</pre>"
              "<p>The Werkzeug Debugger discloses the traceback to the client "
              "(unencoded debug page — the weakness).</p>"
              "</body></html>")


async def root(request: Request) -> HTMLResponse:
    _hit("/")
    return _html(f"""<!doctype html><html><head><title>Demo app</title></head><body>
<h1>Demo app</h1>
<p>A deliberately vulnerable synthetic target for Vigilo grey-box tests.</p>
<ul>
<li><a href="/search?q=hello">search</a></li>
<li><a href="/safe-search?q=hello">safe search</a></li>
<li><a href="/login">login</a></li>
<li><a href="/static/">static files</a></li>
<li><a href="/api/data">api</a></li>
<li><a href="/api/notes">notes</a></li>
<li><a href="/redirect?to=/">redirect</a></li>
<li><a href="/echo">echo note</a></li>
<li><a href="/safe-echo">safe echo</a></li>
<li><a href="/logout">logout</a></li>
<li><a href="/debug">debug page</a></li>
<li><a href="http://evil.invalid/">external</a></li>
</ul>
<form action="/search" method="get"><input name="q" value="hello"><input
type="submit" value="go"></form>
</body></html>""")


async def robots(request: Request) -> PlainTextResponse:
    _hit("/robots.txt")
    return PlainTextResponse(
        "User-agent: *\nDisallow: /admin/\nDisallow: /static/\n"
        "Sitemap: /sitemap.xml\n", headers={"Server": SERVER_BANNER})


async def sitemap(request: Request) -> Response:
    _hit("/sitemap.xml")
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">"
        "<url><loc>/search</loc></url>"
        "<url><loc>/safe-search</loc></url>"
        "<url><loc>/item?id=1</loc></url>"
        "<url><loc>/api/data</loc></url>"
        "<url><loc>/debug</loc></url>"
        "</urlset>", media_type="application/xml",
        headers={"Server": SERVER_BANNER})


async def search(request: Request) -> HTMLResponse:
    _hit("/search")
    q = request.query_params.get("q", "")
    return _html(f"""<!doctype html><html><head><title>Results</title></head><body>
<h1>Results for {q}</h1><p>(unencoded reflection — the weakness)</p>
<form action="/search" method="get"><input name="q" value="{q}"><input
type="submit" value="search"></form></body></html>""")


async def safe_search(request: Request) -> HTMLResponse:
    _hit("/safe-search")
    q = request.query_params.get("q", "")
    from html import escape
    return _html(f"""<!doctype html><html><head><title>Results</title></head><body>
<h1>Results for {escape(q)}</h1><p>(escaped reflection — the negative control)</p>
</body></html>""")


async def login_get(request: Request) -> HTMLResponse:
    _hit("/login")
    # Pre-session cookie without HttpOnly/Secure/SameSite (the weakness).
    token = f"guest-{random.randbytes(8).hex()}"
    return _html("""<!doctype html><html><head><title>Login</title></head><body>
<h1>Sign in</h1>
<form action="/login" method="post">
<input name="user" value=""><input type="password" name="password" value="">
<input type="submit" value="Sign in"></form></body></html>""",
                 headers={"Set-Cookie": f"session={token}; Path=/"})


async def login_post(request: Request) -> Response:
    _hit("/login")
    form = dict(parse_qsl((await request.body()).decode(errors="replace")))
    users = {"admin": "admin", "alice": "alicepass", "bob": "bobpass"}
    if form.get("user") in users and form.get("password") == users[form["user"]]:
        # The session token identifies its user (sess-<user>-<rand>): object-level
        # access in /api/notes is enforced (or, for alice's notes, NOT enforced)
        # per user.
        token = f"sess-{form['user']}-{random.randbytes(12).hex()}"
        return RedirectResponse("/", status_code=302, headers={
            "Server": SERVER_BANNER,
            "Set-Cookie": f"session={token}; Path=/"})
    return _html("<h1>Invalid credentials</h1>", status=200)


def _session_user(request: Request) -> str | None:
    """The user a request's session cookie belongs to (sess-<user>-<rand>)."""
    m = re.match(r"^sess-([a-z]+)-[0-9a-f]+$",
                 request.cookies.get("session") or "")
    return m.group(1) if m else None


# Alice's notes: readable by ANYONE — no authentication, no ownership check (the
# planted object-level weakness). Bob's notes: readable by bob only (the negative
# control: alice and anonymous are refused).
NOTES = {1: "alice", 2: "alice", 3: "bob", 4: "bob"}


async def notes_index(request: Request) -> HTMLResponse:
    _hit("/api/notes")
    return _html("""<!doctype html><html><head><title>Notes</title></head><body>
<h1>Notes</h1><ul>
<li><a href="/api/notes/1">note 1</a></li>
<li><a href="/api/notes/2">note 2</a></li>
<li><a href="/api/notes/3">note 3</a></li>
<li><a href="/api/notes/4">note 4</a></li>
</ul></body></html>""")


async def note(request: Request) -> Response:
    try:
        nid = int(request.path_params["id"])
    except (KeyError, ValueError):
        return _html("<h1>Not found</h1>", status=404)
    _hit(f"/api/notes/{nid}")
    owner = NOTES.get(nid)
    if owner is None:
        return _html("<h1>Not found</h1>", status=404)
    user = _session_user(request)
    if owner == "alice" or user == "bob":
        return _html(f"<!doctype html><html><head><title>Note {nid}</title></head>"
                     f"<body><h1>Note {nid}</h1>"
                     f"<p>Private note owned by {owner}.</p></body></html>")
    return _html("<h1>Forbidden</h1>", status=403)


async def api_data(request: Request) -> JSONResponse:
    _hit("/api/data")
    origin = request.headers.get("origin")
    headers = {"Server": SERVER_BANNER}
    if origin:                      # reflects ANY origin with credentials (weakness)
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"
    # The envelope names the stack (seeded weakness for the Phase 3 sandbox tests:
    # no built-in check reads response DATA shape, only an analysis tool can).
    return JSONResponse({"items": [1, 2, 3], "ok": True,
                         "meta": {"engine": "PostgreSQL 14.2", "owner": "app_rw",
                                  "built": "2024-11-06T09:14:00Z"}},
                        headers=headers)


async def git_head(request: Request) -> PlainTextResponse:
    _hit("/.git/HEAD")
    return PlainTextResponse("ref: refs/heads/main\n",
                             headers={"Server": SERVER_BANNER})


async def soft_404_env(request: Request) -> HTMLResponse:
    _hit("/.env")
    return _html(SOFT_404)          # 200 with a generic page: the negative control


async def static_index(request: Request) -> HTMLResponse:
    _hit("/static/")
    return _html("""<!doctype html><html><head><title>Index of /static/</title></head>
<body><h1>Index of /static/</h1><ul>
<li><a href="/static/app.js">app.js</a></li></ul></body></html>""")


async def static_app_js(request: Request) -> Response:
    _hit("/static/app.js")
    return Response("console.log('demo');", media_type="application/javascript",
                    headers={"Server": SERVER_BANNER})


async def item(request: Request) -> HTMLResponse:
    _hit("/item")
    iid = request.query_params.get("id", "")
    if "'" in iid:                   # error-based indicator (injection.errors, M5)
        return _html(
            "<h1>Database error</h1><pre>You have an error in your SQL syntax near "
            f"''{iid}'' SELECT * FROM items WHERE id='{iid}'</pre>")
    return _html(f"<h1>Item {iid}</h1>")


async def redirect(request: Request) -> Response:
    _hit("/redirect")
    to = request.query_params.get("to", "/")
    return RedirectResponse(to, status_code=302,
                            headers={"Server": SERVER_BANNER})


async def debug_page(request: Request) -> HTMLResponse:
    """A disclosed framework debugger page (info.errors): a full traceback and a
    debug banner served to any client, linked from the root and the sitemap."""
    _hit("/debug")
    return _html(DEBUG_PAGE)


async def echo(request: Request) -> HTMLResponse:
    """Request-header reflection (batch E): the value of the X-Note-Name request
    header is rendered into the HTML UNENCODED. No built-in tool sends request
    headers, so only a run-defined dynamic instrument can test this — discovery's
    marker header makes the echo visible as a header_reflect_hint on the endpoint
    (an HTML-escaped echo does not match the marker)."""
    _hit("/echo")
    note = request.headers.get("x-note-name", "")
    return _html(f"""<!doctype html><html><head><title>Your note</title></head><body>
<h1>Your note</h1>
<p id="note">{note}</p>
</body></html>""")


async def safe_echo(request: Request) -> HTMLResponse:
    """Negative control for /echo: the same X-Note-Name header rendered
    HTML-escaped — a dynamic reflection instrument must not fire here."""
    _hit("/safe-echo")
    from html import escape
    note = escape(request.headers.get("x-note-name", ""))
    return _html(f"""<!doctype html><html><head><title>Your note</title></head><body>
<h1>Your note (encoded)</h1>
<p id="note">{note}</p>
</body></html>""")


async def slow(request: Request) -> Response:
    _hit("/slow")
    import asyncio
    await asyncio.sleep(SLOW_SECONDS)      # async: the server stays responsive
    return PlainTextResponse("finally", headers={"Server": SERVER_BANNER})


async def logout(request: Request) -> Response:
    _hit("/logout")
    return PlainTextResponse("Logged out.",
                             headers={"Server": SERVER_BANNER,
                                      "Set-Cookie": "session=; Path=/; Max-Age=0"})


async def admin(request: Request) -> Response:
    _hit("/admin/")
    return _html("<h1>Admin (401)</h1>", status=401)


async def leaky(request: Request) -> HTMLResponse:
    """Redaction probe: echoes the request Cookie, sets a Location header carrying a
    token, links to /x?token=ABC and has a form with hidden csrf / api_key fields."""
    _hit("/leaky")
    cookie = request.headers.get("cookie", "")
    return _html(f"""<!doctype html><html><head><title>Leaky</title></head><body>
<h1>Leaky</h1><pre>cookie: {cookie}</pre>
<a href="/x?token=ABC">x</a>
<form action="/leaky-post" method="post"><input name="note" value="hi">
<input type="hidden" name="csrf_token" value="CSRFVALUE123">
<input type="hidden" name="api_key" value="APIKEYVALUE456">
<input type="submit" value="go"></form></body></html>""",
                 headers={"Location": "/x?token=LOCSECRET789"})


async def leaky_body(request: Request) -> HTMLResponse:
    """Body-masking probe: target-issued secrets in an HTML body."""
    _hit("/leaky-body")
    return _html("""<!doctype html><html><head><title>Leaky body</title>
<meta name="csrf-token" content="METACSRF-AAA111"></head><body>
<h1>Leaky body</h1><p>Plain visible text ORDINARY-CONTENT.</p>
<a href="/leaky-json">json</a> <a href="/x?token=LINKTOKEN-BBB222&amp;page=2">x</a>
<form action="/leaky-post" method="post"><input name="note" value="NOTE-VISIBLE">
<input type="hidden" name="csrf_token" value="HIDDENCSRF-CCC333">
<input type="hidden" id="api_key" value="APIKEYINPUT-DDD444">
<input type="submit" value="go"></form></body></html>""")


async def leaky_json(request: Request) -> JSONResponse:
    _hit("/leaky-json")
    return JSONResponse({"user": "VISIBLE-USER", "access_token": "JSONTOKEN-EEE555",
                         "profile": {"password": "JSONPASS-FFF666", "city": "Rome"}},
                        headers={"Server": SERVER_BANNER})


# ---- network exploration (P1) probes: out-of-scope hosts are *.invalid and are never
# contacted; the engine must only record them.


async def net_index(request: Request) -> HTMLResponse:
    """Supply-chain page: third-party scripts (one with SRI, one without), a third-party
    stylesheet and an http:// image, plus one in-scope script and links to the other
    /net/ routes."""
    _hit("/net/")
    return _html("""<!doctype html><html><head><title>Network probes</title>
<script src="https://cdn.example.invalid/lib.js"></script>
<script src="https://cdn.example.invalid/pinned.js"
 integrity="sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
 crossorigin="anonymous"></script>
<link rel="stylesheet" href="https://fonts.example.invalid/font.css">
<script src="/static/app.js"></script></head><body>
<h1>Network probes</h1>
<img src="http://img.example.invalid/x.png" alt="">
<ul><li><a href="/net/leaky">leaky</a></li><li><a href="/net/edge">edge</a></li>
<li><a href="/net/cross">cross</a></li><li><a href="/net/other">other</a></li></ul>
</body></html>""")


async def net_leaky(request: Request) -> HTMLResponse:
    """Internal host names and addresses in a header, a Location and the body; the
    ``Server`` value is a banner with a four-part version that must NOT be a leak."""
    _hit("/net/leaky")
    return _html("""<!doctype html><html><head><title>Leaky net</title></head><body>
<h1>Status</h1>
<!-- upstream: http://intranet.corp/status ; replica 192.168.1.5 -->
<a href="/net/other">other</a></body></html>""", headers={
        "Server": "Foo/1.2.3.4",
        "X-Backend-Server": "app01.corp",
        "Location": "http://10.0.4.12:8080/x?token=NETSECRET123"})


async def net_edge(request: Request) -> HTMLResponse:
    """Edge-provider signals: headers, a cookie, cache and Alt-Svc."""
    _hit("/net/edge")
    return _html("<!doctype html><html><head><title>Edge</title></head><body>"
                 "<h1>Edge</h1><a href=\"/net/other\">other</a></body></html>", headers={
        "Server": "cloudflare",
        "CF-RAY": "8a1b2c3d4e5f6a7b-AMS",
        "CF-Cache-Status": "HIT",
        "Age": "12",
        "Cache-Control": "public, max-age=300",
        "Alt-Svc": 'h3=":443"; ma=86400',
        "Set-Cookie": "__cf_bm=cfvalue; Path=/; HttpOnly"})


async def net_cross(request: Request) -> Response:
    """A redirect to another (out-of-scope) host: recorded, never followed."""
    _hit("/net/cross")
    return RedirectResponse("http://other.example.invalid/landing", status_code=302,
                            headers={"Server": SERVER_BANNER})


async def net_other(request: Request) -> HTMLResponse:
    _hit("/net/other")
    return _html("<!doctype html><html><head><title>Other</title></head><body>"
                 "<h1>Other</h1></body></html>")


async def not_found(request: Request, exc: Exception) -> HTMLResponse:
    _hit(request.url.path)
    return _html(SOFT_404, status=404)


def build_app() -> Starlette:
    return Starlette(routes=[
        Route("/", root),
        Route("/robots.txt", robots),
        Route("/sitemap.xml", sitemap),
        Route("/search", search),
        Route("/safe-search", safe_search),
        Route("/login", login_get, methods=["GET"]),
        Route("/login", login_post, methods=["POST"]),
        Route("/api/data", api_data),
        Route("/api/notes", notes_index),
        Route("/api/notes/{id}", note),
        Route("/.git/HEAD", git_head),
        Route("/.env", soft_404_env),
        Route("/static/", static_index),
        Route("/static/app.js", static_app_js),
        Route("/item", item),
        Route("/redirect", redirect),
        Route("/debug", debug_page),
        Route("/echo", echo),
        Route("/safe-echo", safe_echo),
        Route("/slow", slow),
        Route("/logout", logout),
        Route("/admin/", admin),
        Route("/leaky", leaky),
        Route("/leaky-body", leaky_body),
        Route("/leaky-json", leaky_json),
        Route("/net/", net_index),
        Route("/net/leaky", net_leaky),
        Route("/net/edge", net_edge),
        Route("/net/cross", net_cross),
        Route("/net/other", net_other),
    ], exception_handlers={404: not_found})


def serve(blocking: bool = False, port: int = 0):
    """Start uvicorn on 127.0.0.1:<port> (0 = ephemeral). Returns (server, url)."""
    import uvicorn

    app = build_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning",
                            lifespan="off", access_log=False, server_header=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="gb-target")
    thread.start()
    while not server.started:
        time.sleep(0.01)
    actual = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{actual}/"
    if blocking:
        thread.join()
    return server, url


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    _, url = serve(blocking=True, port=args.port)
    print(url)


if __name__ == "__main__":
    main()
