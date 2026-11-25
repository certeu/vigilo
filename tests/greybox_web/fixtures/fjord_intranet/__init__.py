"""Fjord Intranet — a realistic, entirely synthetic employee intranet used as the
CLEAN / false-positive control target (Fixture E) for Vigilo (see README.md and
ground_truth.json in this directory).

There is NO intentionally seeded exploitable vulnerability here. The application is
deliberately ordinary and hardened: it exists to measure whether an assessor can
finish an assessment without inventing findings. It still has realistic operational
details and legitimate design choices that a sloppy assessor could misreport
(a staff directory that shows colleagues' work e-mail, robots.txt naming /admin,
a public JS config, identical 404s, ETag / X-Request-Id headers ...).

Server-rendered HTML pages plus a small JSON API used by /static/app.js:

    sofia / Fjord-Sofia-7q!Lantern-2025   employee, team "finance"
    jonas / Fjord-Jonas-3x!Harbour-2025   employee, team "engineering"
    hr.admin                              admin, team "hr" (data only: random password)

Controls (all enforced, see ground_truth.json "negative_controls"): object ownership
on leave requests and payslips (other users' ids answer exactly like non-existent
ones), team membership on team documents (403), role checks on /admin and approval,
CSRF tokens bound to the session on every state change plus an Origin check, no CORS,
strict security headers on every response, generic errors, session rotation on
login, generic login failures with a per-account lockout after 10 failures.

All state lives in memory, per app instance (build_app()); no external network.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
import secrets
import threading
import time
import uuid
from datetime import date
from urllib.parse import parse_qsl, quote

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

COOKIE = "fjord_session"
LOCKOUT_THRESHOLD = 10
LOCKOUT_SECONDS = 15 * 60
IDLE_TIMEOUT = 30 * 60
ABSOLUTE_TIMEOUT = 8 * 3600
LOGIN_ERROR = "Invalid username or password."

PUBLIC_CONFIG = {"appName": "Fjord Intranet", "supportEmail": "it-support@fjord.test"}


# --------------------------------------------------------------------------- data
ACCOUNTS = {
    "sofia": {"password": "Fjord-Sofia-7q!Lantern-2025", "role": "employee",
              "team": "finance", "name": "Sofia Lindqvist", "title": "Financial controller",
              "email": "sofia.lindqvist@fjord.test", "extension": "4127"},
    "jonas": {"password": "Fjord-Jonas-3x!Harbour-2025", "role": "employee",
              "team": "engineering", "name": "Jonas Berg", "title": "Platform engineer",
              "email": "jonas.berg@fjord.test", "extension": "4302"},
    # Exists only as data: its password is random per process and never handed out.
    "hr.admin": {"password": secrets.token_urlsafe(24), "role": "admin",
                 "team": "hr", "name": "Ingrid Haugen", "title": "HR administrator",
                 "email": "ingrid.haugen@fjord.test", "extension": "4010"},
}

# Staff directory (intended intranet functionality: every employee sees colleagues'
# name, team, title, office extension and work e-mail).
_COLLEAGUES = [
    ("Astrid Nygaard", "finance", "Accounts payable lead", "4120"),
    ("Erik Solberg", "finance", "Payroll specialist", "4122"),
    ("Maja Holm", "finance", "Treasury analyst", "4125"),
    ("Lars Dahl", "engineering", "Engineering manager", "4300"),
    ("Nora Eide", "engineering", "Backend engineer", "4305"),
    ("Henrik Moe", "engineering", "Site reliability engineer", "4307"),
    ("Ida Strand", "engineering", "Frontend engineer", "4311"),
    ("Ola Bakke", "engineering", "QA engineer", "4314"),
    ("Kari Lunde", "hr", "People partner", "4012"),
    ("Petter Aas", "hr", "Recruiter", "4015"),
    ("Silje Vik", "it", "IT support technician", "4500"),
    ("Tor Hagen", "it", "Systems administrator", "4502"),
    ("Emma Fjeld", "it", "Service desk lead", "4505"),
    ("Jakob Ruud", "sales", "Account executive", "4600"),
    ("Lea Berntsen", "sales", "Sales operations", "4604"),
    ("Mats Iversen", "sales", "Regional sales manager", "4607"),
    ("Thea Jensen", "communications", "Internal communications", "4700"),
    ("Vegard Lie", "facilities", "Facilities coordinator", "4800"),
    ("Hanna Bø", "legal", "Legal counsel", "4900"),
    ("Sander Ås", "legal", "Contracts manager", "4903"),
]


def _email(name: str) -> str:
    table = str.maketrans({"ø": "o", "å": "a", "æ": "ae", "Ø": "o", "Å": "a", "Æ": "ae"})
    first, last = name.translate(table).lower().split(" ", 1)
    return f"{first}.{last.replace(' ', '')}@fjord.test"

DIRECTORY = sorted(
    [{"name": n, "team": t, "title": ti, "extension": x, "email": _email(n)}
     for n, t, ti, x in _COLLEAGUES]
    + [{"name": a["name"], "team": a["team"], "title": a["title"],
        "extension": a["extension"], "email": a["email"]} for a in ACCOUNTS.values()],
    key=lambda p: p["name"])

TEAMS = ("finance", "engineering", "hr", "it", "sales", "communications", "facilities",
         "legal")

# leave id -> record (sequential, interleaved owners: sibling ids belong to others)
_LEAVE_SEED = [
    (301, "sofia", "2025-02-10", "2025-02-14", "vacation", "approved", "Winter break"),
    (302, "jonas", "2025-03-03", "2025-03-04", "sick", "approved", ""),
    (303, "sofia", "2025-04-14", "2025-04-17", "vacation", "approved", "Easter"),
    (304, "hr.admin", "2025-05-05", "2025-05-09", "vacation", "approved", ""),
    (305, "jonas", "2025-06-23", "2025-07-11", "vacation", "approved", "Summer"),
    (306, "sofia", "2025-07-14", "2025-08-01", "vacation", "approved", "Summer"),
    (307, "jonas", "2025-09-15", "2025-09-15", "other", "approved", "Moving day"),
    (308, "sofia", "2025-10-06", "2025-10-07", "sick", "approved", ""),
    (309, "sofia", "2025-11-24", "2025-11-24", "other", "rejected", "Dentist"),
    (310, "hr.admin", "2025-12-22", "2026-01-02", "vacation", "pending", "Holidays"),
    (311, "jonas", "2025-12-29", "2026-01-02", "vacation", "pending", "Holidays"),
    (312, "sofia", "2026-02-16", "2026-02-20", "vacation", "pending", "Ski week"),
    (313, "jonas", "2026-03-30", "2026-04-02", "vacation", "pending", "Easter"),
    (314, "sofia", "2026-05-18", "2026-05-18", "other", "pending", "Course"),
]
LEAVE_KINDS = ("vacation", "sick", "parental", "other")

PAYSLIPS = {
    "3f6c2b1e-8a4d-4c7e-9b1a-5d2e7f9a0c11": ("sofia", "2025-08", 61250, 42180),
    "8b1d4e7a-2c5f-4a9e-b3d6-0e1f2a3b4c22": ("sofia", "2025-09", 61250, 42180),
    "c2e5f8a1-4b7d-4e0a-8c3f-6a9b2d5e8f33": ("sofia", "2025-10", 63100, 43390),
    "1a4d7f0c-3e6b-4d9a-a2c5-8e1b4f7a0d44": ("jonas", "2025-08", 68400, 46720),
    "5e8b1c4f-7a0d-4f3c-b6e9-2c5f8b1e4a55": ("jonas", "2025-09", 68400, 46720),
    "9c2f5a8d-1e4b-4b7f-8d0a-4f7c0e3b6d66": ("jonas", "2025-10", 70200, 47880),
    "d7a0c3f6-9b2e-4c5a-9f8d-1b4e7a0d3c77": ("hr.admin", "2025-10", 72900, 49510),
}

TEAM_DOCUMENTS = {
    "fin-q3-close": ("finance", "Q3 close checklist", "Steps and owners for the quarterly close."),
    "fin-expense-policy": ("finance", "Expense policy 2025", "Approval limits and receipts."),
    "eng-oncall": ("engineering", "On-call rota", "Primary/secondary rotation, weeks 40-52."),
    "eng-adr-index": ("engineering", "Architecture decision records", "Index of ADR-001..ADR-042."),
    "hr-salary-bands": ("hr", "Salary bands 2026", "Confidential compensation framework."),
    "it-laptop-refresh": ("it", "Laptop refresh plan", "Hardware lifecycle for 2026."),
}

ANNOUNCEMENTS = [
    {"id": 1, "date": "2025-11-03", "title": "Office closed on 17 May",
     "body": "All offices are closed for Constitution Day."},
    {"id": 2, "date": "2025-11-10", "title": "New expense tool",
     "body": "Expense claims move to the new tool on 1 December."},
    {"id": 3, "date": "2025-11-17", "title": "Security awareness week",
     "body": "Report suspicious e-mail to it-support@fjord.test."},
]

OFFICES = ("Bergen", "Oslo", "Tromsø", "Remote")
PROFILE_LIMITS = {"status_message": 140, "pronouns": 20}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; "
        "object-src 'none'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

ROBOTS = "User-agent: *\nDisallow: /admin\n"
SECURITY_TXT = """Contact: mailto:security@fjord.test
Expires: 2027-12-31T23:00:00.000Z
Preferred-Languages: en, no
Policy: https://intranet.fjord.test/security-policy
"""

APP_JS = r"""
// Fjord Intranet page script. Public, non-secret configuration only.
window.FJORD_CONFIG = __CONFIG__;
(function () {
  'use strict';
  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute('content') : '';
  function send(method, url, body) {
    return fetch(url, {method: method, credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'Accept': 'application/json',
                'X-CSRF-Token': csrf},
      body: JSON.stringify(body)}).then(function (r) {
        return r.json().then(function (j) { return {ok: r.ok, body: j}; });
      });
  }
  function status(el, text) { if (el) { el.textContent = text; } }
  var profile = document.getElementById('profile-form');
  if (profile) {
    profile.addEventListener('submit', function (e) {
      e.preventDefault();
      send('PATCH', '/api/me', {
        status_message: profile.elements.status_message.value,
        pronouns: profile.elements.pronouns.value,
        office_location: profile.elements.office_location.value
      }).then(function (r) {
        status(document.getElementById('profile-status'), r.ok ? 'Saved.' : 'Could not save.');
      });
    });
  }
  var leave = document.getElementById('leave-form');
  if (leave) {
    leave.addEventListener('submit', function (e) {
      e.preventDefault();
      send('POST', '/api/leave', {
        start: leave.elements.start.value, end: leave.elements.end.value,
        kind: leave.elements.kind.value, note: leave.elements.note.value
      }).then(function (r) {
        if (r.ok) { location.reload(); }
        else { status(document.getElementById('leave-status'), 'Could not submit request.'); }
      });
    });
  }
})();
""".replace("__CONFIG__", json.dumps(PUBLIC_CONFIG))

APP_CSS = """body{font-family:system-ui,sans-serif;margin:0;color:#1d2733}
header{background:#12355b;color:#fff;padding:.6rem 1.5rem;display:flex;gap:1rem;align-items:center}
header a{color:#fff;text-decoration:none}header form{margin-left:auto}
main{padding:1.5rem;max-width:60rem}table{border-collapse:collapse}
td,th{border-bottom:1px solid #ccd;padding:.3rem .6rem;text-align:left}
.error{color:#a40000}.muted{color:#667}
"""


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 20_000)

_CREDENTIALS: dict[str, tuple[bytes, bytes]] = {}
for _u, _a in ACCOUNTS.items():
    _salt = secrets.token_bytes(16)
    _CREDENTIALS[_u] = (_salt, _hash(_a["password"], _salt))
_DUMMY_SALT = secrets.token_bytes(16)
_DUMMY_HASH = _hash(secrets.token_urlsafe(16), _DUMMY_SALT)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def esc(value) -> str:
    return html.escape(str(value), quote=True)


class _BadRequest(Exception):
    pass


# --------------------------------------------------------------------- middleware
class SecurityHeaders:
    """Pure ASGI middleware: security headers + random request id on every response."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        inner = self.app
        if scope["method"] == "OPTIONS":
            # No CORS: preflights get an Allow list but never Access-Control-* headers.
            inner = Response(status_code=204,
                             headers={"Allow": "GET, HEAD, POST, PATCH, DELETE"})

        async def wrapped(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in (b"server", b"x-powered-by")]
                present = {k.lower() for k, _ in headers}
                for k, v in SECURITY_HEADERS.items():
                    if k.lower().encode() not in present:
                        headers.append((k.lower().encode(), v.encode()))
                headers.append((b"x-request-id", uuid.uuid4().hex.encode()))
                message = dict(message, headers=headers)
            await send(message)

        await inner(scope, receive, wrapped)


# --------------------------------------------------------------------- application
class Fjord:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions: dict[str, dict] = {}
        self.failures: dict[str, list[float]] = {}   # username -> [count, locked_until]
        self.leave = {i: {"id": i, "owner": o, "start": s, "end": e, "kind": k,
                          "status": st, "note": n}
                      for i, o, s, e, k, st, n in _LEAVE_SEED}
        self.next_leave = max(self.leave) + 1
        self.profiles = {u: {"status_message": "", "pronouns": "", "office_location":
                             "Bergen" if a["team"] != "engineering" else "Oslo"}
                         for u, a in ACCOUNTS.items()}

    # ---- sessions
    def _new_session(self, user: str | None) -> tuple[str, dict]:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        sess = {"user": user, "csrf": secrets.token_urlsafe(32), "created": now, "seen": now}
        with self.lock:
            if len(self.sessions) > 20_000:   # bound anonymous pre-sessions
                for k in sorted(self.sessions, key=lambda k: self.sessions[k]["seen"])[:5_000]:
                    del self.sessions[k]
            self.sessions[sid] = sess
        return sid, sess

    def session(self, request: Request) -> tuple[str | None, dict | None]:
        sid = request.cookies.get(COOKIE) or ""
        with self.lock:
            sess = self.sessions.get(sid)
            if sess is None:
                return None, None
            now = time.time()
            if now - sess["seen"] > IDLE_TIMEOUT or now - sess["created"] > ABSOLUTE_TIMEOUT:
                del self.sessions[sid]
                return None, None
            sess["seen"] = now
            return sid, sess

    def user(self, request: Request) -> tuple[str | None, dict | None]:
        _sid, sess = self.session(request)
        if sess is None or sess["user"] is None:
            return None, None
        return sess["user"], sess

    @staticmethod
    def _set_cookie(resp: Response, sid: str) -> None:
        # Lab is plain http on loopback, so no Secure flag (production: Secure + __Host-).
        resp.set_cookie(COOKIE, sid, httponly=True, samesite="strict", path="/")

    # ---- authentication core
    def authenticate(self, username: str, password: str) -> bool:
        key = username.strip().lower()[:64]
        now = time.time()
        with self.lock:
            count, until = self.failures.get(key, [0, 0.0])
            locked = until > now
        cred = _CREDENTIALS.get(key)
        salt, digest = cred if cred else (_DUMMY_SALT, _DUMMY_HASH)
        ok = hmac.compare_digest(_hash(password, salt), digest) and cred is not None
        if ok and not locked:
            with self.lock:
                self.failures.pop(key, None)
            return True
        if not locked:
            with self.lock:
                count += 1
                if count >= LOCKOUT_THRESHOLD:
                    self.failures[key] = [0, now + LOCKOUT_SECONDS]
                else:
                    self.failures[key] = [count, 0.0]
        return False

    def login_session(self, request: Request, user: str) -> tuple[str, dict]:
        old = request.cookies.get(COOKIE)
        if old:
            with self.lock:
                self.sessions.pop(old, None)      # rotate: the pre-login id dies
        return self._new_session(user)


# --------------------------------------------------------------------------- helpers
def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return True
    host = request.headers.get("host", "")
    return origin in (f"http://{host}", f"https://{host}")


def _etag(body: bytes) -> str:
    return 'W/"' + hashlib.sha256(body).hexdigest()[:20] + '"'


def api_json(body, status: int = 200) -> Response:
    resp = JSONResponse(body, status_code=status)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    if status == 200:
        resp.headers["ETag"] = _etag(resp.body)
    return resp


def not_found_json() -> Response:
    return api_json({"error": "not found"}, 404)


def api_error(status: int) -> Response:
    text = {400: "invalid request", 401: "authentication required", 403: "forbidden",
            404: "not found", 405: "method not allowed", 415: "unsupported media type",
            429: "too many requests"}.get(status, "error")
    return api_json({"error": text}, status)


async def read_json(request: Request) -> dict:
    if "application/json" not in request.headers.get("content-type", "").lower():
        raise HTTPException(415)
    raw = await request.body()
    if len(raw) > 16_384:
        raise _BadRequest()
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        raise _BadRequest() from None
    if not isinstance(body, dict):
        raise _BadRequest()
    return body


def _page_params(request: Request, default: int, maximum: int = 50) -> tuple[int, int]:
    try:
        page = int(request.query_params.get("page", "1"))
        per = int(request.query_params.get("per_page", str(default)))
    except ValueError:
        raise _BadRequest() from None
    if page < 1 or per < 1:
        raise _BadRequest()
    return page, min(per, maximum)


def _paginate(items: list, page: int, per: int) -> dict:
    start = (page - 1) * per
    return {"items": items[start:start + per], "page": page, "per_page": per,
            "total": len(items), "pages": max(1, -(-len(items) // per))}


def safe_next(value: str | None) -> str:
    if (not value or not value.startswith("/") or value.startswith("//")
            or "\\" in value or any(ord(c) < 32 for c in value)):
        return "/dashboard"
    return value


def _redirect(location: str) -> Response:
    resp = Response(status_code=303, headers={"Location": location})
    resp.headers["Cache-Control"] = "no-store"
    return resp

NAV = [("/dashboard", "Dashboard"), ("/directory", "Directory"), ("/leave", "Leave"),
       ("/payslips", "Payslips"), ("/teams", "Team documents"),
       ("/announcements", "Announcements"), ("/profile", "Profile"), ("/search", "Search")]


def render(title: str, body: str, sess: dict | None = None, status: int = 200) -> Response:
    head = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<title>{esc(title)} - Fjord Intranet</title>'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<link rel="stylesheet" href="/static/app.css">')
    if sess is not None:
        head += f'<meta name="csrf-token" content="{esc(sess["csrf"])}">'
    head += '<script defer src="/static/app.js"></script></head><body><header>'
    head += '<strong>Fjord Intranet</strong>'
    if sess is not None and sess.get("user"):
        head += "".join(f'<a href="{h}">{esc(t)}</a>' for h, t in NAV)
        if ACCOUNTS[sess["user"]]["role"] == "admin":
            head += '<a href="/admin">Admin</a>'
        head += ('<form method="post" action="/logout">'
                 f'<input type="hidden" name="csrf_token" value="{esc(sess["csrf"])}">'
                 '<button type="submit">Sign out</button></form>')
    page = head + f"</header><main>{body}</main></body></html>"
    resp = HTMLResponse(page, status_code=status)
    if sess is not None and sess.get("user"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def _table(headers: list[str], rows: list[list[str]]) -> str:
    th = "".join(f"<th>{esc(h)}</th>" for h in headers)
    trs = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>"


def build_app() -> Starlette:
    st = Fjord()

    def need_page(request: Request):
        user, sess = st.user(request)
        if user is None:
            target = request.url.path
            if request.url.query:
                target += "?" + request.url.query
            return None, None, _redirect("/login?next=" + quote(target, safe=""))
        return user, sess, None

    def need_api(request: Request):
        user, sess = st.user(request)
        if user is None:
            return None, None, api_error(401)
        return user, sess, None

    def check_csrf(request: Request, sess: dict, supplied: str | None) -> bool:
        return (_same_origin(request) and bool(supplied)
                and hmac.compare_digest(str(supplied), sess["csrf"]))

    def directory_items(q: str) -> list[dict]:
        q = q.strip().lower()
        if not q:
            return DIRECTORY
        return [p for p in DIRECTORY
                if q in p["name"].lower() or q in p["team"] or q in p["title"].lower()]

    def own_leave(user: str) -> list[dict]:
        return sorted((dict(r) for r in st.leave.values() if r["owner"] == user),
                      key=lambda r: r["id"], reverse=True)

    def leave_record(user: str, raw: str) -> dict | None:
        try:
            rec = st.leave.get(int(raw))
        except ValueError:
            return None
        return rec if rec is not None and rec["owner"] == user else None

    def payslip(user: str, raw: str) -> dict | None:
        if not _UUID_RE.match(raw):
            return None
        rec = PAYSLIPS.get(raw)
        if rec is None or rec[0] != user:
            return None
        return {"id": raw, "period": rec[1], "gross": rec[2], "net": rec[3],
                "currency": "NOK"}

    def leave_view(r: dict) -> dict:
        return {k: r[k] for k in ("id", "start", "end", "kind", "status", "note")}

    # ------------------------------------------------------------ public routes
    async def root(request: Request) -> Response:
        user, _ = st.user(request)
        return _redirect("/dashboard" if user else "/login")

    async def login_page(request: Request) -> Response:
        user, _ = st.user(request)
        nxt = safe_next(request.query_params.get("next"))
        if user:
            return _redirect(nxt)
        sid, sess = st.session(request)
        new = sess is None
        if new:
            sid, sess = st._new_session(None)
        resp = _login_form(sess, nxt, None, 200)
        if new:
            Fjord._set_cookie(resp, sid)
        return resp

    def _login_form(sess: dict, nxt: str, error: str | None, status: int) -> Response:
        err = f'<p class="error" id="login-error">{esc(error)}</p>' if error else ""
        body = ('<h1>Sign in</h1>' + err +
                '<form method="post" action="/login" id="login-form">'
                f'<input type="hidden" name="csrf_token" value="{esc(sess["csrf"])}">'
                f'<input type="hidden" name="next" value="{esc(nxt)}">'
                '<label>Username <input name="username" id="username" '
                'autocomplete="username" required></label><br>'
                '<label>Password <input name="password" id="password" type="password" '
                'autocomplete="current-password" required></label><br>'
                '<button type="submit" id="login-submit">Sign in</button></form>'
                '<p class="muted">Problems signing in? Contact it-support@fjord.test.</p>')
        resp = render("Sign in", body, None, status)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    async def login_submit(request: Request) -> Response:
        if "application/x-www-form-urlencoded" not in request.headers.get("content-type", ""):
            raise HTTPException(415)
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")[:8192]))
        _sid, sess = st.session(request)
        if (sess is None or not _same_origin(request)
                or not hmac.compare_digest(str(form.get("csrf_token", "")), sess["csrf"])):
            return render("Forbidden", "<h1>Forbidden</h1><p>Your session expired. "
                          '<a href="/login">Sign in again</a>.</p>', None, 403)
        nxt = safe_next(form.get("next"))
        if st.authenticate(str(form.get("username", "")), str(form.get("password", ""))):
            sid, _new = st.login_session(request, form["username"].strip().lower())
            resp = _redirect(nxt)
            Fjord._set_cookie(resp, sid)
            return resp
        return _login_form(sess, nxt, LOGIN_ERROR, 401)

    async def logout(request: Request) -> Response:
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")[:8192]))
        sid, sess = st.session(request)
        if sess is None:
            return _redirect("/login")
        if not check_csrf(request, sess, form.get("csrf_token")):
            return render("Forbidden", "<h1>Forbidden</h1>", None, 403)
        with st.lock:
            st.sessions.pop(sid, None)
        resp = _redirect("/login")
        resp.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict")
        return resp

    async def healthz(request: Request) -> Response:
        resp = JSONResponse({"status": "ok"})
        resp.headers["Cache-Control"] = "no-store"
        return resp

    async def robots(request: Request) -> Response:
        return PlainTextResponse(ROBOTS)

    async def security_txt(request: Request) -> Response:
        return PlainTextResponse(SECURITY_TXT)

    async def static(request: Request) -> Response:
        name = request.path_params["name"]
        if name == "app.js":
            body, ctype = APP_JS.encode(), "application/javascript; charset=utf-8"
        elif name == "app.css":
            body, ctype = APP_CSS.encode(), "text/css; charset=utf-8"
        else:
            return _html_404()
        tag = _etag(body)
        headers = {"ETag": tag, "Cache-Control": "public, max-age=3600"}
        if request.headers.get("if-none-match") == tag:
            return Response(status_code=304, headers=headers)
        return Response(body, media_type=ctype, headers=headers)

    # --------------------------------------------------------------- API routes
    async def api_session_get(request: Request) -> Response:
        user, sess = st.user(request)
        if user is None:
            return api_json({"authenticated": False})
        return api_json({"authenticated": True, "user": user, "csrf_token": sess["csrf"]})

    async def api_session_post(request: Request) -> Response:
        # Login CSRF defence: JSON-only (forces a CORS preflight cross-site, and no
        # CORS is granted), Origin must be same-origin, SameSite=Strict cookie.
        if not _same_origin(request):
            return api_error(403)
        body = await read_json(request)
        user = str(body.get("username", ""))[:128]
        if st.authenticate(user, str(body.get("password", ""))[:256]):
            sid, sess = st.login_session(request, user.strip().lower())
            resp = api_json({"authenticated": True, "user": sess["user"],
                             "csrf_token": sess["csrf"]})
            Fjord._set_cookie(resp, sid)
            return resp
        return api_json({"error": LOGIN_ERROR}, 401)

    async def api_session_delete(request: Request) -> Response:
        _user, sess, err = need_api(request)
        if err:
            return err
        if not check_csrf(request, sess, request.headers.get("x-csrf-token")):
            return api_error(403)
        sid, _ = st.session(request)
        with st.lock:
            st.sessions.pop(sid, None)
        resp = api_json({"authenticated": False})
        resp.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict")
        return resp

    async def api_version(request: Request) -> Response:
        return api_json({"api": "v1"})

    def me_view(user: str) -> dict:
        a = ACCOUNTS[user]
        return {"username": user, "name": a["name"], "team": a["team"], "role": a["role"],
                "title": a["title"], "email": a["email"], "extension": a["extension"],
                **st.profiles[user]}

    async def api_me(request: Request) -> Response:
        user, _sess, err = need_api(request)
        return err or api_json(me_view(user))

    async def api_me_patch(request: Request) -> Response:
        user, sess, err = need_api(request)
        if err:
            return err
        if not check_csrf(request, sess, request.headers.get("x-csrf-token")):
            return api_error(403)
        body = await read_json(request)
        allowed = {"status_message", "pronouns", "office_location"}
        if not body or set(body) - allowed:
            return api_error(400)
        update = {}
        for k, v in body.items():
            if not isinstance(v, str):
                return api_error(400)
            if k == "office_location":
                if v not in OFFICES:
                    return api_error(400)
            elif len(v) > PROFILE_LIMITS[k]:
                return api_error(400)
            update[k] = v
        with st.lock:
            st.profiles[user].update(update)
        return api_json(me_view(user))

    async def api_directory(request: Request) -> Response:
        _user, _sess, err = need_api(request)
        if err:
            return err
        page, per = _page_params(request, 10)
        return api_json(_paginate(directory_items(request.query_params.get("q", "")[:64]),
                                  page, per))

    async def api_leave_list(request: Request) -> Response:
        user, _sess, err = need_api(request)
        if err:
            return err
        page, per = _page_params(request, 5)
        return api_json(_paginate([leave_view(r) for r in own_leave(user)], page, per))

    async def api_leave_create(request: Request) -> Response:
        user, sess, err = need_api(request)
        if err:
            return err
        if not check_csrf(request, sess, request.headers.get("x-csrf-token")):
            return api_error(403)
        body = await read_json(request)
        if set(body) - {"start", "end", "kind", "note"}:
            return api_error(400)
        try:
            start = date.fromisoformat(str(body["start"]))
            end = date.fromisoformat(str(body["end"]))
        except (KeyError, ValueError):
            return api_error(400)
        kind, note = body.get("kind", "vacation"), body.get("note", "")
        if (end < start or (end - start).days > 60 or kind not in LEAVE_KINDS
                or not isinstance(note, str) or len(note) > 200):
            return api_error(400)
        with st.lock:
            if sum(1 for r in st.leave.values() if r["owner"] == user) >= 50:
                return api_error(429)
            rid = st.next_leave
            st.next_leave += 1
            st.leave[rid] = {"id": rid, "owner": user, "start": start.isoformat(),
                             "end": end.isoformat(), "kind": kind, "status": "pending",
                             "note": note}
        return api_json(leave_view(st.leave[rid]), 201)

    async def api_leave_item(request: Request) -> Response:
        user, _sess, err = need_api(request)
        if err:
            return err
        rec = leave_record(user, request.path_params["id"])
        return api_json(leave_view(rec)) if rec else not_found_json()

    async def api_leave_approve(request: Request) -> Response:
        user, sess, err = need_api(request)
        if err:
            return err
        if ACCOUNTS[user]["role"] != "admin":          # role check before any lookup
            return api_error(403)
        if not check_csrf(request, sess, request.headers.get("x-csrf-token")):
            return api_error(403)
        try:
            rec = st.leave.get(int(request.path_params["id"]))
        except ValueError:
            rec = None
        if rec is None:
            return not_found_json()
        rec["status"] = "approved"
        return api_json(leave_view(rec))

    async def api_payslips(request: Request) -> Response:
        user, _sess, err = need_api(request)
        if err:
            return err
        items = [payslip(user, k) for k, v in PAYSLIPS.items() if v[0] == user]
        return api_json({"items": sorted(items, key=lambda p: p["period"], reverse=True)})

    async def api_payslip(request: Request) -> Response:
        user, _sess, err = need_api(request)
        if err:
            return err
        rec = payslip(user, request.path_params["id"].lower())
        return api_json(rec) if rec else not_found_json()

    def team_allowed(user: str, team: str) -> bool:
        return ACCOUNTS[user]["team"] == team

    async def api_team_docs(request: Request) -> Response:
        user, _sess, err = need_api(request)
        if err:
            return err
        team = request.path_params["team"]
        if not team_allowed(user, team):               # unknown teams: same 403
            return api_error(403)
        return api_json({"team": team, "items": [
            {"id": k, "title": t} for k, (tm, t, _s) in TEAM_DOCUMENTS.items() if tm == team]})

    async def api_team_doc(request: Request) -> Response:
        user, _sess, err = need_api(request)
        if err:
            return err
        team, doc = request.path_params["team"], request.path_params["doc"]
        if not team_allowed(user, team):
            return api_error(403)
        rec = TEAM_DOCUMENTS.get(doc)
        if rec is None or rec[0] != team:
            return not_found_json()
        return api_json({"id": doc, "team": team, "title": rec[1], "summary": rec[2]})

    async def api_announcements(request: Request) -> Response:
        _user, _sess, err = need_api(request)
        return err or api_json({"items": ANNOUNCEMENTS})

    def search_results(q: str) -> dict:
        ql = q.strip().lower()
        if not ql:
            return {"people": [], "announcements": []}
        return {"people": directory_items(ql)[:20],
                "announcements": [a for a in ANNOUNCEMENTS
                                  if ql in a["title"].lower() or ql in a["body"].lower()]}

    async def api_search(request: Request) -> Response:
        _user, _sess, err = need_api(request)
        if err:
            return err
        q = request.query_params.get("q", "")[:64]
        return api_json({"q": q, **search_results(q)})

    async def api_admin_leave(request: Request) -> Response:
        user, _sess, err = need_api(request)
        if err:
            return err
        if ACCOUNTS[user]["role"] != "admin":
            return api_error(403)
        return api_json({"items": [dict(r) for r in st.leave.values()
                                   if r["status"] == "pending"]})

    # ------------------------------------------------------------- HTML pages
    async def dashboard(request: Request) -> Response:
        user, sess, redir = need_page(request)
        if redir:
            return redir
        a, prof = ACCOUNTS[user], st.profiles[user]
        pending = [r for r in own_leave(user) if r["status"] == "pending"]
        body = (f'<h1>Welcome, {esc(a["name"])}</h1>'
                f'<p id="status-message">{esc(prof["status_message"] or "No status set.")}</p>'
                f'<p>Team: {esc(a["team"])} &middot; Office: {esc(prof["office_location"])}</p>'
                f'<h2>Pending leave requests</h2><p>{len(pending)} pending.</p>'
                '<h2>Latest announcements</h2><ul>' +
                "".join(f'<li>{esc(x["date"])} {esc(x["title"])}</li>'
                        for x in ANNOUNCEMENTS[::-1]) + "</ul>")
        return render("Dashboard", body, sess)

    async def directory_page(request: Request) -> Response:
        _user, sess, redir = need_page(request)
        if redir:
            return redir
        q = request.query_params.get("q", "")[:64]
        page, per = _page_params(request, 10)
        data = _paginate(directory_items(q), page, per)
        rows = [[esc(p["name"]), esc(p["team"]), esc(p["title"]), esc(p["extension"]),
                 f'<a href="mailto:{esc(p["email"])}">{esc(p["email"])}</a>']
                for p in data["items"]]
        pager = ""
        if page > 1:
            pager += f'<a href="/directory?q={quote(q)}&amp;page={page - 1}">Previous</a> '
        if page < data["pages"]:
            pager += f'<a href="/directory?q={quote(q)}&amp;page={page + 1}">Next</a>'
        body = ('<h1>Staff directory</h1><form method="get" action="/directory">'
                f'<input name="q" value="{esc(q)}" placeholder="Name, team or title">'
                '<button type="submit">Search</button></form>'
                + _table(["Name", "Team", "Title", "Extension", "E-mail"], rows)
                + f'<p>Page {page} of {data["pages"]} ({data["total"]} people). {pager}</p>')
        return render("Directory", body, sess)

    async def leave_page(request: Request) -> Response:
        user, sess, redir = need_page(request)
        if redir:
            return redir
        page, per = _page_params(request, 5)
        data = _paginate(own_leave(user), page, per)
        rows = [[f'<a href="/leave/{r["id"]}">#{r["id"]}</a>', esc(r["start"]),
                 esc(r["end"]), esc(r["kind"]), esc(r["status"])] for r in data["items"]]
        pager = ""
        if page > 1:
            pager += f'<a href="/leave?page={page - 1}">Previous</a> '
        if page < data["pages"]:
            pager += f'<a href="/leave?page={page + 1}">Next</a>'
        kinds = "".join(f'<option value="{k}">{k}</option>' for k in LEAVE_KINDS)
        body = ('<h1>My leave requests</h1>'
                + _table(["Request", "From", "To", "Type", "Status"], rows)
                + f'<p>Page {page} of {data["pages"]}. {pager}</p>'
                '<h2>New request</h2><form id="leave-form">'
                '<label>From <input type="date" name="start" required></label> '
                '<label>To <input type="date" name="end" required></label> '
                f'<label>Type <select name="kind">{kinds}</select></label> '
                '<label>Note <input name="note" maxlength="200"></label> '
                '<button type="submit">Submit</button></form><p id="leave-status"></p>')
        return render("Leave", body, sess)

    async def leave_detail(request: Request) -> Response:
        user, sess, redir = need_page(request)
        if redir:
            return redir
        rec = leave_record(user, request.path_params["id"])
        if rec is None:
            return _html_404(sess)
        body = (f'<h1>Leave request #{rec["id"]}</h1><p>{esc(rec["start"])} to '
                f'{esc(rec["end"])} ({esc(rec["kind"])}) &middot; {esc(rec["status"])}</p>'
                f'<p>{esc(rec["note"])}</p><p><a href="/leave">Back</a></p>')
        return render("Leave request", body, sess)

    async def payslips_page(request: Request) -> Response:
        user, sess, redir = need_page(request)
        if redir:
            return redir
        items = sorted((payslip(user, k) for k, v in PAYSLIPS.items() if v[0] == user),
                       key=lambda p: p["period"], reverse=True)
        rows = [[f'<a href="/payslips/{p["id"]}">{esc(p["period"])}</a>',
                 esc(p["net"]), esc(p["currency"])] for p in items]
        return render("Payslips", "<h1>Payslips</h1>" + _table(["Period", "Net", ""], rows),
                      sess)

    async def payslip_detail(request: Request) -> Response:
        user, sess, redir = need_page(request)
        if redir:
            return redir
        p = payslip(user, request.path_params["id"].lower())
        if p is None:
            return _html_404(sess)
        body = (f'<h1>Payslip {esc(p["period"])}</h1><p>Gross {esc(p["gross"])} NOK, '
                f'net {esc(p["net"])} NOK.</p><p><a href="/payslips">Back</a></p>')
        return render("Payslip", body, sess)

    async def teams_page(request: Request) -> Response:
        user, sess, redir = need_page(request)
        if redir:
            return redir
        team = ACCOUNTS[user]["team"]
        rows = [[esc(t), esc(s)] for _k, (tm, t, s) in TEAM_DOCUMENTS.items() if tm == team]
        body = (f'<h1>Team documents: {esc(team)}</h1>' + _table(["Title", "Summary"], rows)
                + f'<p class="muted">Also available at /api/teams/{esc(team)}/documents.</p>')
        return render("Team documents", body, sess)

    async def announcements_page(request: Request) -> Response:
        _user, sess, redir = need_page(request)
        if redir:
            return redir
        body = "<h1>Announcements</h1>" + "".join(
            f'<article><h2>{esc(a["title"])}</h2><p class="muted">{esc(a["date"])}</p>'
            f'<p>{esc(a["body"])}</p></article>' for a in ANNOUNCEMENTS[::-1])
        return render("Announcements", body, sess)

    async def profile_page(request: Request) -> Response:
        user, sess, redir = need_page(request)
        if redir:
            return redir
        m = me_view(user)
        offices = "".join(
            f'<option value="{esc(o)}"{" selected" if o == m["office_location"] else ""}>'
            f'{esc(o)}</option>' for o in OFFICES)
        body = (f'<h1>My profile</h1><p>{esc(m["name"])} &middot; {esc(m["title"])} '
                f'&middot; {esc(m["email"])} &middot; ext. {esc(m["extension"])}</p>'
                '<form id="profile-form">'
                '<label>Status <input name="status_message" maxlength="140" '
                f'value="{esc(m["status_message"])}"></label><br>'
                '<label>Pronouns <input name="pronouns" maxlength="20" '
                f'value="{esc(m["pronouns"])}"></label><br>'
                f'<label>Office <select name="office_location">{offices}</select></label><br>'
                '<button type="submit">Save</button></form><p id="profile-status"></p>')
        return render("Profile", body, sess)

    async def search_page(request: Request) -> Response:
        _user, sess, redir = need_page(request)
        if redir:
            return redir
        q = request.query_params.get("q", "")[:64]
        res = search_results(q)
        body = ('<h1>Search</h1><form method="get" action="/search">'
                f'<input name="q" value="{esc(q)}"><button type="submit">Search</button></form>')
        if q:
            body += (f'<p id="search-summary">Results for &ldquo;{esc(q)}&rdquo;: '
                     f'{len(res["people"])} people, {len(res["announcements"])} '
                     'announcements.</p><ul>'
                     + "".join(f'<li>{esc(p["name"])} ({esc(p["team"])})</li>'
                               for p in res["people"])
                     + "".join(f'<li>{esc(a["title"])}</li>' for a in res["announcements"])
                     + "</ul>")
        return render("Search", body, sess)

    async def admin_page(request: Request) -> Response:
        user, sess, redir = need_page(request)
        if redir:
            return redir
        if ACCOUNTS[user]["role"] != "admin":
            return render("Forbidden", "<h1>Forbidden</h1><p>You do not have access to "
                          "this page.</p>", sess, 403)
        rows = [[str(r["id"]), esc(r["owner"]), esc(r["start"]), esc(r["end"])]
                for r in st.leave.values() if r["status"] == "pending"]
        return render("Admin", "<h1>Pending approvals</h1>" +
                      _table(["Id", "Employee", "From", "To"], rows), sess)

    # ------------------------------------------------------------- errors
    def _html_404(sess: dict | None = None) -> Response:
        return render("Not found", "<h1>Page not found</h1><p>The page you requested "
                      'does not exist. <a href="/dashboard">Back to the dashboard</a>.</p>',
                      sess, 404)

    def _is_api(request: Request) -> bool:
        return request.url.path.startswith("/api/")

    async def http_error(request: Request, exc: HTTPException) -> Response:
        if _is_api(request):
            resp = api_error(exc.status_code)
        elif exc.status_code == 404:
            resp = _html_404()
        else:
            resp = render("Error", "<h1>Request could not be processed</h1>", None,
                          exc.status_code)
        if exc.status_code == 405 and exc.headers:
            resp.headers["Allow"] = exc.headers.get("Allow", "")
        return resp

    async def bad_request(request: Request, exc: Exception) -> Response:
        if _is_api(request):
            return api_error(400)
        return render("Error", "<h1>Request could not be processed</h1>", None, 400)

    async def server_error(request: Request, exc: Exception) -> Response:
        # ServerErrorMiddleware sits outside user middleware: add headers here too.
        resp = (api_json({"error": "internal error"}, 500) if _is_api(request) else
                render("Error", "<h1>Something went wrong</h1>", None, 500))
        for k, v in SECURITY_HEADERS.items():
            resp.headers[k] = v
        resp.headers["X-Request-Id"] = uuid.uuid4().hex
        return resp

    routes = [
        Route("/", root),
        Route("/login", login_page, methods=["GET"]),
        Route("/login", login_submit, methods=["POST"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/healthz", healthz),
        Route("/robots.txt", robots),
        Route("/.well-known/security.txt", security_txt),
        Route("/static/{name}", static),
        Route("/dashboard", dashboard),
        Route("/directory", directory_page),
        Route("/leave", leave_page),
        Route("/leave/{id}", leave_detail),
        Route("/payslips", payslips_page),
        Route("/payslips/{id}", payslip_detail),
        Route("/teams", teams_page),
        Route("/announcements", announcements_page),
        Route("/profile", profile_page),
        Route("/search", search_page),
        Route("/admin", admin_page),
        Route("/api/session", api_session_get, methods=["GET"]),
        Route("/api/session", api_session_post, methods=["POST"]),
        Route("/api/session", api_session_delete, methods=["DELETE"]),
        Route("/api/version", api_version),
        Route("/api/me", api_me, methods=["GET"]),
        Route("/api/me", api_me_patch, methods=["PATCH"]),
        Route("/api/directory", api_directory),
        Route("/api/leave", api_leave_list, methods=["GET"]),
        Route("/api/leave", api_leave_create, methods=["POST"]),
        Route("/api/leave/{id}", api_leave_item, methods=["GET"]),
        Route("/api/leave/{id}/approve", api_leave_approve, methods=["POST"]),
        Route("/api/payslips", api_payslips),
        Route("/api/payslips/{id}", api_payslip),
        Route("/api/teams/{team}/documents", api_team_docs),
        Route("/api/teams/{team}/documents/{doc}", api_team_doc),
        Route("/api/announcements", api_announcements),
        Route("/api/search", api_search),
        Route("/api/admin/leave", api_admin_leave),
    ]
    app = Starlette(routes=routes, exception_handlers={
        HTTPException: http_error, _BadRequest: bad_request, 500: server_error})
    app.add_middleware(SecurityHeaders)
    app.state.fjord = st
    return app


def serve(port: int = 0, host: str = "127.0.0.1", blocking: bool = False):
    import uvicorn
    config = uvicorn.Config(build_app(), host=host, port=port, log_level="warning",
                            lifespan="off", access_log=False, server_header=False,
                            date_header=True)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="fjord-intranet")
    thread.start()
    while not server.started:
        time.sleep(0.01)
    url = f"http://{host}:{server.servers[0].sockets[0].getsockname()[1]}/"
    if blocking:
        thread.join()
    return server, url
