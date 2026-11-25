"""Acme Workspace — a realistic, entirely synthetic enterprise web service used as a
permanent end-to-end evaluation target for Vigilo (see README.md and
ground_truth.json in this directory).

A small single-page application (hash router, one hashed bundle that builds API URLs
at runtime) over a cookie-session REST API: projects, invoices, documents, an
activity feed in a custom line format, a profile, an admin API and a public health
endpoint. Two synthetic accounts with different roles:

    alice / Alice-Pw-2024!   role "member"
    bob   / Bob-Pw-2024!     role "manager"

Seeded, non-destructive weaknesses (ground_truth.json):

GT1  /api/invoices/{id}   no ownership check (sibling numeric ids)        vulnerability
GT2  /api/health          public internal metadata (host names, commit)   disclosure
GT3  /api/*               CORS reflects any Origin with credentials       misconfiguration
GT4  all HTML responses   no CSP / X-Content-Type-Options / Referrer-Policy hardening
GT5  /api/activity + /api/documents/{uuid}: the feed (text/x-acme-feed) lists other
     users' document UUIDs; documents have no ownership check. Needs the workflow
     (sign in, open the dashboard), a parser for the feed, and correlation.

Negative controls: /api/admin/users enforces the manager role; /api/me and
/api/documents list only the caller's own data. Nothing here writes or deletes.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from urllib.parse import parse_qsl

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

USERS = {"alice": {"password": "Alice-Pw-2024!", "role": "member",
                   "name": "Alice Martin", "email": "alice@acme.example"},
         "bob": {"password": "Bob-Pw-2024!", "role": "manager",
                 "name": "Bob Keller", "email": "bob@acme.example"}}
PROJECTS = {"p-orion": {"name": "Orion migration", "members": ["alice", "bob"]},
            "p-vega": {"name": "Vega analytics", "members": ["bob"]}}
INVOICES = {1041: ("alice", "p-orion", "Northwind Ltd", 12400),
            1042: ("alice", "p-orion", "Contoso SA", 3180),
            1043: ("bob", "p-vega", "Fabrikam GmbH", 98000),
            1044: ("bob", "p-vega", "Tailspin BV", 45150)}
DOCUMENTS = {"7c1e2a90-4f6b-4d1a-9b8e-2f0c3d4e5a61": ("alice", "Orion cut-over plan"),
             "a3b9f2d4-1c8e-4e7a-b6d5-0e9f8a7b6c52": ("alice", "Vendor shortlist"),
             "e5d4c3b2-a190-4f8e-8d7c-6b5a4f3e2d13": ("bob", "Board salary review 2025"),
             "0f9e8d7c-6b5a-4c3d-9e2f-1a0b9c8d7e64": ("bob", "Vega acquisition memo")}
FEED = [
    ("2024-11-18T08:02:11Z", "alice", "login", "-"),
    ("2024-11-18T08:05:40Z", "alice", "view", "doc:7c1e2a90-4f6b-4d1a-9b8e-2f0c3d4e5a61"),
    ("2024-11-18T09:13:02Z", "bob", "upload", "doc:e5d4c3b2-a190-4f8e-8d7c-6b5a4f3e2d13"),
    ("2024-11-18T09:20:55Z", "bob", "approve", "inv:1043"),
    ("2024-11-18T10:44:31Z", "alice", "upload", "doc:a3b9f2d4-1c8e-4e7a-b6d5-0e9f8a7b6c52"),
    ("2024-11-18T11:30:09Z", "bob", "upload", "doc:0f9e8d7c-6b5a-4c3d-9e2f-1a0b9c8d7e64"),
]
HEALTH = {"status": "ok", "service": "acme-workspace-api", "version": "3.8.2",
          "build": "2024.11.3-rc1", "commit": "5d1e9c0a",
          "node": "app-int-07.acme.internal",
          "database": "postgres://db-int-02.acme.internal:5432/workspace",
          "cache": "redis://cache-int-01.acme.internal:6379/0"}
BUNDLE_NAME = "app.4f9c21.js"

SHELL = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Acme Workspace</title><link rel="stylesheet" href="/assets/app.css">
<script defer src="/assets/{BUNDLE_NAME}"></script></head>
<body><div id="app">Loading…</div></body></html>"""

CSS = "body{font-family:sans-serif;margin:2rem}nav a{margin-right:1rem}"

# The application: routes and API calls exist only in this code.
BUNDLE = r"""
(function () {
  var app = document.getElementById('app');
  var me = null;
  function h(s) { return String(s).replace(/[&<>"]/g, function (c) {
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]; }); }
  function api(path) {
    return fetch('/api' + path, {credentials: 'same-origin',
                                 headers: {'Accept': 'application/json'}})
      .then(function (r) {
        if (r.status === 401) { location.hash = '#/login'; throw new Error('auth'); }
        return r.json();
      });
  }
  function nav() {
    return '<nav><a href="#/dashboard">Dashboard</a><a href="#/invoices">Invoices</a>' +
      '<a href="#/documents">Documents</a><a href="#/settings">Settings</a>' +
      (me && me.role === 'manager' ? '<a href="#/team">Team</a>' : '') + '</nav>';
  }
  function page(html) { app.innerHTML = nav() + html; }
  // The activity feed is not JSON: one record per line, "|"-separated.
  function parseFeed(text) {
    return text.split('\n').filter(function (l) { return l && l[0] !== '#'; })
      .map(function (l) { var p = l.split('|');
        return {ts: p[0], actor: p[1], action: p[2], ref: p[3]}; });
  }
  var routes = {
    login: function () {
      app.innerHTML = '<h1>Sign in</h1><form id="f"><input name="username" id="u">' +
        '<input name="password" id="p" type="password"><button id="go">Sign in</button>' +
        '</form><p id="err"></p>';
      document.getElementById('f').onsubmit = function (e) {
        e.preventDefault();
        fetch('/api/auth/login', {method: 'POST', credentials: 'same-origin',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({username: document.getElementById('u').value,
                                password: document.getElementById('p').value})})
          .then(function (r) {
            if (r.ok) { location.hash = '#/dashboard'; }
            else { document.getElementById('err').textContent = 'Invalid login'; }
          });
      };
    },
    dashboard: function () {
      api('/me').then(function (u) {
        me = u;
        return fetch('/api/activity', {credentials: 'same-origin'})
          .then(function (r) { return r.text(); });
      }).then(function (t) {
        var mine = parseFeed(t).filter(function (x) { return x.actor === me.username; });
        page('<h1>Welcome ' + h(me.name) + '</h1><h2>Your recent activity</h2><ul>' +
          mine.map(function (x) { return '<li>' + h(x.ts) + ' ' + h(x.action) + ' ' +
            h(x.ref) + '</li>'; }).join('') + '</ul>');
      });
    },
    invoices: function (id) {
      if (id) {
        return api('/invoices/' + id).then(function (inv) {
          page('<h1>Invoice ' + h(inv.id) + '</h1><p>' + h(inv.customer) + ' — ' +
               h(inv.amount) + ' EUR</p><p>Project ' + h(inv.project) + '</p>');
        });
      }
      api('/invoices').then(function (d) {
        page('<h1>Invoices</h1><ul>' + d.invoices.map(function (i) {
          return '<li><a href="#/invoices/' + i.id + '">' + h(i.id) + ' ' +
            h(i.customer) + '</a></li>'; }).join('') + '</ul>');
      });
    },
    documents: function (id) {
      if (id) {
        return api('/documents/' + id).then(function (d) {
          page('<h1>' + h(d.title) + '</h1><p>Owner: ' + h(d.owner) + '</p>');
        });
      }
      api('/documents').then(function (d) {
        page('<h1>Documents</h1><ul>' + d.documents.map(function (x) {
          return '<li><a href="#/documents/' + x.id + '">' + h(x.title) + '</a></li>';
        }).join('') + '</ul>');
      });
    },
    team: function () {
      api('/admin/users').then(function (d) {
        page('<h1>Team</h1><ul>' + d.users.map(function (u) {
          return '<li>' + h(u.username) + ' (' + h(u.role) + ')</li>'; }).join('') +
          '</ul>');
      });
    },
    settings: function () {
      api('/me').then(function (u) { me = u;
        page('<h1>Settings</h1><p>' + h(u.email) + ' — ' + h(u.role) + '</p>'); });
    }
  };
  function render() {
    var parts = (location.hash || '#/dashboard').slice(2).split('/');
    var r = routes[parts[0]] || routes.dashboard;
    try { r(parts[1]); } catch (e) {}
  }
  window.addEventListener('hashchange', render);
  render();
})();
"""

_sessions: dict[str, str] = {}
_hits: dict[str, int] = {}
_lock = threading.Lock()


def counts() -> dict[str, int]:
    with _lock:
        return dict(_hits)


def _hit(request: Request) -> None:
    with _lock:
        _hits[request.url.path] = _hits.get(request.url.path, 0) + 1


def _user(request: Request) -> str | None:
    return _sessions.get(request.cookies.get("acme_sid") or "")


def _cors(request: Request, resp: Response) -> Response:
    origin = request.headers.get("origin")
    if origin:   # GT3: any origin is reflected, with credentials
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
    return resp


def _json(request: Request, body, status: int = 200) -> Response:
    resp = JSONResponse(body, status_code=status)
    resp.headers["X-Powered-By"] = "Express"           # framework banner (GT4 extra)
    return _cors(request, resp)


def _need(request: Request) -> str | None:
    return _user(request)


async def shell(request: Request) -> Response:
    _hit(request)
    return HTMLResponse(SHELL)


async def asset(request: Request) -> Response:
    _hit(request)
    name = request.path_params["name"]
    if name == BUNDLE_NAME:
        return Response(BUNDLE, media_type="application/javascript")
    if name == "app.css":
        return Response(CSS, media_type="text/css")
    return PlainTextResponse("not found", status_code=404)


async def login(request: Request) -> Response:
    _hit(request)
    raw = (await request.body()).decode("utf-8", "replace")
    if "json" in request.headers.get("content-type", ""):
        try:
            body = json.loads(raw or "{}")
        except ValueError:
            body = {}
    else:
        body = dict(parse_qsl(raw))
    user = str(body.get("username") or "")
    if user in USERS and body.get("password") == USERS[user]["password"]:
        sid = secrets.token_hex(16)
        _sessions[sid] = user
        resp = _json(request, {"ok": True, "user": user})
        resp.set_cookie("acme_sid", sid, httponly=True, samesite="lax", path="/")
        return resp
    return _json(request, {"error": "invalid credentials"}, 401)


async def logout(request: Request) -> Response:
    _hit(request)
    _sessions.pop(request.cookies.get("acme_sid") or "", None)
    return _json(request, {"ok": True})


async def me(request: Request) -> Response:
    _hit(request)
    u = _need(request)
    if u is None:
        return _json(request, {"error": "authentication required"}, 401)
    d = USERS[u]
    return _json(request, {"username": u, "name": d["name"], "email": d["email"],
                           "role": d["role"]})


async def invoices(request: Request) -> Response:
    _hit(request)
    u = _need(request)
    if u is None:
        return _json(request, {"error": "authentication required"}, 401)
    return _json(request, {"invoices": [
        {"id": i, "customer": c, "project": p} for i, (o, p, c, _a) in INVOICES.items()
        if o == u]})


async def invoice(request: Request) -> Response:
    _hit(request)
    u = _need(request)
    if u is None:
        return _json(request, {"error": "authentication required"}, 401)
    try:
        owner, proj, cust, amount = INVOICES[int(request.path_params["id"])]
    except (KeyError, ValueError):
        return _json(request, {"error": "not found"}, 404)
    # GT1: NO ownership check
    return _json(request, {"id": int(request.path_params["id"]), "owner": owner,
                           "project": proj, "customer": cust, "amount": amount,
                           "requested_by": u})


async def documents(request: Request) -> Response:
    _hit(request)
    u = _need(request)
    if u is None:
        return _json(request, {"error": "authentication required"}, 401)
    return _json(request, {"documents": [{"id": k, "title": t}
                                         for k, (o, t) in DOCUMENTS.items() if o == u]})


async def document(request: Request) -> Response:
    _hit(request)
    u = _need(request)
    if u is None:
        return _json(request, {"error": "authentication required"}, 401)
    d = DOCUMENTS.get(request.path_params["id"])
    if d is None:
        return _json(request, {"error": "not found"}, 404)
    # GT5: NO ownership check (ids are UUIDs: only guessable via the feed)
    return _json(request, {"id": request.path_params["id"], "owner": d[0],
                           "title": d[1], "classification": "internal"})


async def activity(request: Request) -> Response:
    _hit(request)
    if _need(request) is None:
        return _json(request, {"error": "authentication required"}, 401)
    # GT5: every user's activity, in a custom line format
    body = "#ACMEFEED/2 ts|actor|action|ref\n" + "\n".join("|".join(r) for r in FEED)
    return _cors(request, Response(body + "\n", media_type="text/x-acme-feed"))


async def admin_users(request: Request) -> Response:
    _hit(request)
    u = _need(request)
    if u is None:
        return _json(request, {"error": "authentication required"}, 401)
    if USERS[u]["role"] != "manager":                  # negative control
        return _json(request, {"error": "forbidden"}, 403)
    return _json(request, {"users": [{"username": k, "role": v["role"]}
                                     for k, v in USERS.items()]})


async def health(request: Request) -> Response:
    _hit(request)
    return _json(request, HEALTH)                      # GT2: public internal metadata


async def api_404(request: Request) -> Response:
    _hit(request)
    return _json(request, {"error": "not found"}, 404)


def build_app() -> Starlette:
    return Starlette(routes=[
        Route("/", shell),
        Route("/assets/{name}", asset),
        Route("/api/auth/login", login, methods=["POST"]),
        Route("/api/auth/logout", logout, methods=["POST"]),
        Route("/api/me", me),
        Route("/api/invoices", invoices),
        Route("/api/invoices/{id}", invoice),
        Route("/api/documents", documents),
        Route("/api/documents/{id}", document),
        Route("/api/activity", activity),
        Route("/api/admin/users", admin_users),
        Route("/api/health", health),
        Route("/api/{rest:path}", api_404),
        Route("/{rest:path}", shell),
    ])


def serve(port: int = 0, host: str = "127.0.0.1", blocking: bool = False):
    import uvicorn
    config = uvicorn.Config(build_app(), host=host, port=port, log_level="warning",
                            lifespan="off", access_log=False, server_header=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="acme-portal")
    thread.start()
    while not server.started:
        time.sleep(0.01)
    url = f"http://{host}:{server.servers[0].sockets[0].getsockname()[1]}/"
    if blocking:
        thread.join()
    return server, url
