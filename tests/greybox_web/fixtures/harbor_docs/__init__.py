"""Harbor Docs — a realistic, entirely synthetic team document-sharing and approval
application used as a permanent end-to-end evaluation target for Vigilo (see
README.md and ground_truth.json in this directory).

Server-rendered HTML pages (dashboard, projects, project, document, versions,
approvals, activity, profile) with real links and forms, over a cookie-session JSON
API under /api/ that some pages fetch. Team "Meridian" with three projects:

    atlas   private        erin (lead); dave was a member until 2026-11-16 (removed)
    beacon  team-visible   erin, dave, finn
    cobalt  private        finn; erin reads in-review work as team approver

Documents follow a workflow (draft -> in_review -> approved -> archived) and have
versions, shares (share links /s/{token} with expiry) and approval requests.
Synthetic accounts:

    erin / Harbor-Erin-7q!Lw2c   team lead, approver
    dave / Harbor-Dave-4m!Tz8k   member
    finn / Harbor-Finn-9k!Rv3p   member

Seeded, non-destructive weaknesses (ground_truth.json) — none needs a
state-changing request to observe:

C1  /api/teams/{team}/activity   returns every team event, including private
    projects the caller cannot open (cobalt project name, document titles, actors);
    the HTML Activity page filters to the viewer's projects client-side.
C2  /api/documents/{id}/versions[/{n}]   checks project membership only, not the
    draft rule: a draft is 404 on /api/documents/{id} for non-authors but its
    content is readable through the versions interface by any project member.
C3  /api/documents/{id}   checks "has ever been a member" instead of current
    membership: dave, removed from atlas, still reads atlas documents (ids in his
    /api/me/recent history), while /api/projects/atlas[/documents] deny him.

Negative controls: project endpoints enforce current membership; cobalt documents
are denied to dave; drafts are 404 to non-authors on /api/documents/{id}; the
expired share link returns 410; approval decisions are approver-only; ownership
transfer is author/lead-only; CSRF token on state-changing requests; CSP, nosniff,
Referrer-Policy, X-Frame-Options; HttpOnly + SameSite=Lax session cookie; no CORS.
"""
from __future__ import annotations

import copy
import html
import json
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                                 RedirectResponse, Response)
from starlette.routing import Route

COOKIE = "harbor_session"
TEAM = "meridian"

USERS = {
    "erin": {"password": "Harbor-Erin-7q!Lw2c", "name": "Erin Okafor",
             "email": "erin@meridian.example", "team_role": "lead",
             "permissions": ["approver"]},
    "dave": {"password": "Harbor-Dave-4m!Tz8k", "name": "Dave Lindqvist",
             "email": "dave@meridian.example", "team_role": "member", "permissions": []},
    "finn": {"password": "Harbor-Finn-9k!Rv3p", "name": "Finn Moreau",
             "email": "finn@meridian.example", "team_role": "member", "permissions": []},
}

PROJECTS = {
    "atlas": {"name": "Atlas", "visibility": "private",
              "description": "Vendor and partner negotiations."},
    "beacon": {"name": "Beacon", "visibility": "team",
               "description": "Product planning and release coordination."},
    "cobalt": {"name": "Cobalt", "visibility": "private",
               "description": "Organisation planning (restricted)."},
}

# membership history: removed_at None means current
MEMBERSHIPS = [
    {"project": "atlas", "user": "erin", "role": "lead",
     "joined_at": "2026-03-02T09:00:00Z", "removed_at": None},
    {"project": "atlas", "user": "dave", "role": "member",
     "joined_at": "2026-03-10T09:00:00Z", "removed_at": "2026-11-16T15:42:00Z"},
    {"project": "beacon", "user": "erin", "role": "lead",
     "joined_at": "2026-01-12T09:00:00Z", "removed_at": None},
    {"project": "beacon", "user": "dave", "role": "member",
     "joined_at": "2026-01-12T09:05:00Z", "removed_at": None},
    {"project": "beacon", "user": "finn", "role": "member",
     "joined_at": "2026-02-01T10:00:00Z", "removed_at": None},
    {"project": "cobalt", "user": "finn", "role": "lead",
     "joined_at": "2026-06-20T08:30:00Z", "removed_at": None},
]


def _v(n, at, author, summary, content):
    return {"n": n, "created_at": at, "author": author, "summary": summary,
            "content": content}


DOCUMENTS = {
    "d-a71f30": {
        "project": "atlas", "author": "erin", "state": "approved",
        "title": "Atlas — vendor contract renewal terms",
        "created_at": "2026-09-03T10:00:00Z",
        "versions": [
            _v(1, "2026-09-03T10:00:00Z", "erin", "Initial terms",
               "Renewal with Northwind Logistics: 3-year term, 4% annual uplift cap."),
            _v(2, "2026-09-18T14:20:00Z", "erin", "Negotiated floor",
               "Renewal with Northwind Logistics: 3-year term, 2.5% uplift cap; "
               "walk-away floor EUR 1.42M/yr; termination for convenience at 90 days."),
        ]},
    "d-a79e15": {
        "project": "atlas", "author": "erin", "state": "in_review",
        "title": "Atlas — partner acquisition shortlist",
        "created_at": "2026-11-19T09:10:00Z",
        "versions": [
            _v(1, "2026-11-19T09:10:00Z", "erin", "Shortlist",
               "Shortlist: Tailspin BV (preferred, est. EUR 18M), Fabrikam GmbH."),
        ]},
    "d-b2e641": {
        "project": "beacon", "author": "finn", "state": "approved",
        "title": "Beacon — onboarding guide",
        "created_at": "2026-02-10T11:00:00Z",
        "versions": [
            _v(1, "2026-02-10T11:00:00Z", "finn", "First cut",
               "Welcome to Beacon. Accounts, tooling, rota."),
            _v(2, "2026-04-02T09:30:00Z", "finn", "Tooling update",
               "Welcome to Beacon. Accounts, tooling (new CI), rota, escalation."),
            _v(3, "2026-07-21T16:00:00Z", "dave", "Escalation contacts",
               "Welcome to Beacon. Accounts, tooling, rota, escalation contacts."),
        ]},
    "d-b25d07": {
        "project": "beacon", "author": "erin", "state": "draft",
        "title": "Beacon — 2027 roadmap",
        "created_at": "2026-11-17T08:15:00Z",
        "versions": [
            _v(1, "2026-11-17T08:15:00Z", "erin", "Outline",
               "DRAFT — not for circulation. Themes: consolidate tiers, reduce scope."),
            _v(2, "2026-11-20T17:05:00Z", "erin", "Staffing",
               "DRAFT — not for circulation. Sunset the Harbor Classic tier in Q2 2027; "
               "move two Beacon engineers to Cobalt; freeze hiring until Q3."),
        ]},
    "d-b2981a": {
        "project": "beacon", "author": "dave", "state": "in_review",
        "title": "Beacon — release checklist 4.2",
        "created_at": "2026-11-05T13:00:00Z",
        "versions": [
            _v(1, "2026-11-05T13:00:00Z", "dave", "Checklist",
               "Freeze, smoke tests, staged rollout 10/50/100, rollback plan."),
        ]},
    "d-b2c3f9": {
        "project": "beacon", "author": "finn", "state": "archived",
        "title": "Beacon — 2025 retrospective",
        "created_at": "2025-12-15T10:00:00Z",
        "versions": [
            _v(1, "2025-12-15T10:00:00Z", "finn", "Retro",
               "What went well, what did not, actions for 2026."),
        ]},
    "d-c3f812": {
        "project": "cobalt", "author": "finn", "state": "in_review",
        "title": "Cobalt — layoffs scenario Q3",
        "created_at": "2026-11-10T07:50:00Z",
        "versions": [
            _v(1, "2026-11-10T07:50:00Z", "finn", "Scenario A",
               "Scenario A: reduce support headcount by 14 roles across two sites."),
            _v(2, "2026-11-14T12:30:00Z", "finn", "Scenario B",
               "Scenario B: reduce support headcount by 9 roles; close Lyon office."),
        ]},
    "d-c30a77": {
        "project": "cobalt", "author": "finn", "state": "draft",
        "title": "Cobalt — restructuring cost model",
        "created_at": "2026-11-18T10:00:00Z",
        "versions": [
            _v(1, "2026-11-18T10:00:00Z", "finn", "Model",
               "Severance assumptions and one-off restructuring costs (draft)."),
        ]},
}

APPROVALS = {
    "apr-5c21": {"document": "d-b2981a", "requested_by": "dave", "status": "pending",
                 "requested_at": "2026-11-05T13:05:00Z", "decided_by": None,
                 "decided_at": None, "comment": None},
    "apr-9e47": {"document": "d-c3f812", "requested_by": "finn", "status": "pending",
                 "requested_at": "2026-11-14T12:35:00Z", "decided_by": None,
                 "decided_at": None, "comment": None},
    "apr-1b08": {"document": "d-a71f30", "requested_by": "erin", "status": "approved",
                 "requested_at": "2026-09-18T14:30:00Z", "decided_by": "erin",
                 "decided_at": "2026-09-19T08:00:00Z", "comment": "Self-approved as lead."},
}

# "recently viewed" history per user (dave's atlas entries predate his removal)
RECENT = {
    "dave": [
        {"document": "d-b2981a", "viewed_at": "2026-11-21T10:02:00Z"},
        {"document": "d-b2e641", "viewed_at": "2026-11-18T09:40:00Z"},
        {"document": "d-a71f30", "viewed_at": "2026-11-13T16:11:00Z"},
    ],
    "erin": [
        {"document": "d-b25d07", "viewed_at": "2026-11-20T17:06:00Z"},
        {"document": "d-a79e15", "viewed_at": "2026-11-19T09:12:00Z"},
        {"document": "d-c3f812", "viewed_at": "2026-11-15T08:00:00Z"},
    ],
    "finn": [
        {"document": "d-c3f812", "viewed_at": "2026-11-14T12:31:00Z"},
        {"document": "d-b2e641", "viewed_at": "2026-11-12T11:00:00Z"},
    ],
}


def _ev(eid, at, actor, action, doc, summary):
    d = DOCUMENTS[doc]
    return {"id": eid, "at": at, "actor": actor, "action": action,
            "project": d["project"], "project_name": PROJECTS[d["project"]]["name"],
            "document_id": doc, "document_title": d["title"], "summary": summary}


ACTIVITY = [
    _ev("ev-1052", "2026-11-20T17:05:00Z", "erin", "document.version_added", "d-b25d07",
        "erin saved version 2 of a draft"),
    _ev("ev-1049", "2026-11-19T09:10:00Z", "erin", "document.submitted", "d-a79e15",
        "erin submitted a document for review"),
    _ev("ev-1047", "2026-11-18T10:00:00Z", "finn", "document.created", "d-c30a77",
        "finn created a draft"),
    _ev("ev-1044", "2026-11-17T08:15:00Z", "erin", "document.created", "d-b25d07",
        "erin created a draft"),
    _ev("ev-1041", "2026-11-15T08:00:00Z", "erin", "approval.viewed", "d-c3f812",
        "erin opened an approval request"),
    _ev("ev-1039", "2026-11-14T12:35:00Z", "finn", "document.submitted", "d-c3f812",
        "finn submitted a document for review"),
    _ev("ev-1033", "2026-11-10T07:50:00Z", "finn", "document.created", "d-c3f812",
        "finn created a document"),
    _ev("ev-1030", "2026-11-05T13:05:00Z", "dave", "document.submitted", "d-b2981a",
        "dave submitted a document for review"),
    _ev("ev-1021", "2026-09-19T08:00:00Z", "erin", "approval.approved", "d-a71f30",
        "erin approved a document"),
    _ev("ev-1012", "2026-07-21T16:00:00Z", "dave", "document.version_added", "d-b2e641",
        "dave saved version 3"),
]
# the membership removal itself is in the feed too (no document)
ACTIVITY.insert(3, {"id": "ev-1045", "at": "2026-11-16T15:42:00Z", "actor": "erin",
                    "action": "project.member_removed", "project": "atlas",
                    "project_name": "Atlas", "document_id": None,
                    "document_title": None, "summary": "erin removed dave from Atlas"})

_NOW = datetime.now(timezone.utc)
SHARES = {
    "d-b2e641": [
        {"id": "sh-31", "kind": "link",
         "token": "x7Qe2LwV0b-old-onboarding",
         "created_by": "finn", "created_at": "2026-08-01T09:00:00Z",
         "expires_at": (_NOW - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")},
        {"id": "sh-32", "kind": "user", "with": "dave", "created_by": "finn",
         "created_at": "2026-02-10T11:05:00Z", "expires_at": None},
    ],
    "d-a71f30": [
        {"id": "sh-40", "kind": "link",
         "token": "Rk9vPq3ZsT1mYc8NwA5eHd2L",
         "created_by": "erin", "created_at": "2026-09-19T08:05:00Z",
         "expires_at": (_NOW + timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")},
    ],
}

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; "
                                "style-src 'self'; img-src 'self'; object-src 'none'; "
                                "base-uri 'self'; form-action 'self'; "
                                "frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}

CSS = ("body{font-family:system-ui,sans-serif;margin:0;color:#1d2433}"
       "header{background:#14325c;color:#fff;padding:.6rem 1.5rem}"
       "header a{color:#fff;margin-right:1rem;text-decoration:none}"
       "main{padding:1.5rem}table{border-collapse:collapse}"
       "td,th{border:1px solid #ccd;padding:.3rem .6rem;text-align:left}"
       ".state{font-size:.8rem;padding:.1rem .4rem;background:#eef}"
       "pre{background:#f5f6f8;padding:.8rem;white-space:pre-wrap}")

# The Activity page: renders only events of the viewer's own projects.
ACTIVITY_JS = r"""
(function () {
  var box = document.getElementById('feed');
  var team = box.getAttribute('data-team');
  function h(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]; }); }
  function get(p) { return fetch(p, {credentials: 'same-origin',
    headers: {'Accept': 'application/json'}}).then(function (r) { return r.json(); }); }
  Promise.all([get('/api/projects'), get('/api/teams/' + team + '/activity')])
    .then(function (res) {
      var mine = {};
      res[0].projects.forEach(function (p) { mine[p.id] = true; });
      var items = res[1].events.filter(function (e) { return mine[e.project]; });
      box.innerHTML = items.length ? '<ul>' + items.map(function (e) {
        var doc = e.document_id ? ' <a href="/documents/' + h(e.document_id) + '">' +
          h(e.document_title) + '</a>' : '';
        return '<li>' + h(e.at) + ' — ' + h(e.summary) + ' [' + h(e.project_name) +
          ']' + doc + '</li>'; }).join('') + '</ul>' : '<p>No recent activity.</p>';
    });
})();
"""

# The document page: loads the document, then its versions, from the JSON API.
DOCUMENT_JS = r"""
(function () {
  var box = document.getElementById('doc');
  var id = box.getAttribute('data-id');
  function h(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]; }); }
  function get(p) { return fetch(p, {credentials: 'same-origin',
    headers: {'Accept': 'application/json'}}).then(function (r) {
      return r.json().then(function (b) { b._status = r.status; return b; }); }); }
  var mode = box.getAttribute('data-mode');
  if (mode === 'versions') {
    get('/api/documents/' + id + '/versions').then(function (d) {
      if (d._status !== 200) { box.innerHTML = '<p>' + h(d.error) + '</p>'; return; }
      box.innerHTML = '<h1>Versions</h1><ul>' + d.versions.map(function (v) {
        return '<li><a href="#" data-n="' + v.n + '">v' + v.n + '</a> ' +
          h(v.created_at) + ' ' + h(v.author) + ' — ' + h(v.summary) + '</li>';
      }).join('') + '</ul><pre id="v"></pre>';
      box.querySelectorAll('a[data-n]').forEach(function (a) {
        a.onclick = function (ev) { ev.preventDefault();
          get('/api/documents/' + id + '/versions/' + a.getAttribute('data-n'))
            .then(function (v) { document.getElementById('v').textContent = v.content; });
        };
      });
    });
    return;
  }
  get('/api/documents/' + id).then(function (d) {
    if (d._status !== 200) { box.innerHTML = '<p>' + h(d.error) + '</p>'; return; }
    box.innerHTML = '<h1>' + h(d.title) + '</h1><p>Project ' + h(d.project) +
      ' · author ' + h(d.author) + ' · <span class="state">' + h(d.state) +
      '</span> · version ' + h(d.current_version) + '</p><pre>' + h(d.content) +
      '</pre><p><a href="/documents/' + h(id) + '/versions">Version history</a></p>';
  });
})();
"""


class State:
    def __init__(self) -> None:
        self.memberships = copy.deepcopy(MEMBERSHIPS)
        self.documents = copy.deepcopy(DOCUMENTS)
        self.approvals = copy.deepcopy(APPROVALS)
        self.activity = copy.deepcopy(ACTIVITY)
        self.shares = copy.deepcopy(SHARES)
        self.sessions: dict[str, dict] = {}
        self.lock = threading.Lock()

    # --- membership ---------------------------------------------------------
    def current_role(self, user: str, project: str) -> str | None:
        for m in self.memberships:
            if m["user"] == user and m["project"] == project and m["removed_at"] is None:
                return m["role"]
        return None

    def ever_member(self, user: str, project: str) -> bool:
        return any(m["user"] == user and m["project"] == project
                   for m in self.memberships)

    @staticmethod
    def approver(user: str) -> bool:
        return "approver" in USERS[user]["permissions"]

    def can_view_project(self, user: str, project: str) -> bool:
        return self.current_role(user, project) is not None or self.approver(user)

    # --- documents ----------------------------------------------------------
    def can_read_document(self, user: str, doc: dict) -> tuple[bool, int]:
        """Rule for /api/documents/{id}. Drafts: author only (404 otherwise)."""
        if doc["state"] == "draft" and doc["author"] != user:
            return False, 404
        if doc["author"] == user:
            return True, 200
        # membership check uses the full history (removed members included)
        if self.ever_member(user, doc["project"]):
            return True, 200
        if self.approver(user):
            return True, 200
        return False, 403

    def can_read_versions(self, user: str, doc: dict) -> tuple[bool, int]:
        """Rule for the versions interface: current project membership."""
        if doc["author"] == user or self.current_role(user, doc["project"]):
            return True, 200
        if self.approver(user) and doc["state"] != "draft":
            return True, 200
        if doc["state"] == "draft":
            return False, 404
        return False, 403

    def can_read_shares(self, user: str, doc: dict) -> tuple[bool, int]:
        if doc["state"] == "draft" and doc["author"] != user:
            return False, 404
        if doc["author"] == user or self.current_role(user, doc["project"]):
            return True, 200
        if self.approver(user):
            return True, 200
        return False, 403


# --------------------------------------------------------------------------- utils
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _secure(resp: Response) -> Response:
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    return resp


def _json(body, status: int = 200) -> Response:
    return _secure(JSONResponse(body, status_code=status))


def _err(status: int, msg: str) -> Response:
    return _json({"error": msg}, status)


def _session(st: State, request: Request) -> dict | None:
    return st.sessions.get(request.cookies.get(COOKIE) or "")


async def _body(request: Request) -> dict:
    raw = (await request.body()).decode("utf-8", "replace")
    if "json" in request.headers.get("content-type", ""):
        try:
            b = json.loads(raw or "{}")
            return b if isinstance(b, dict) else {}
        except ValueError:
            return {}
    return dict(parse_qsl(raw))


def _is_form(request: Request) -> bool:
    return "application/x-www-form-urlencoded" in request.headers.get("content-type", "")


def _e(s) -> str:
    return html.escape("" if s is None else str(s))


def _page(title: str, body: str, sess: dict | None = None, status: int = 200,
          scripts: tuple[str, ...] = ()) -> Response:
    nav = ""
    if sess:
        nav = ('<header><a href="/dashboard">Harbor Docs</a><a href="/projects">Projects'
               '</a><a href="/approvals">Approvals</a><a href="/activity">Activity</a>'
               '<a href="/profile">Profile</a>'
               '<form method="post" action="/logout" style="display:inline">'
               f'<input type="hidden" name="csrf_token" value="{_e(sess["csrf"])}">'
               f'<button>Sign out ({_e(sess["user"])})</button></form></header>')
    csrf_meta = (f'<meta name="csrf-token" content="{_e(sess["csrf"])}">' if sess else "")
    js = "".join(f'<script src="/static/{s}"></script>' for s in scripts)
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">{csrf_meta}'
           f'<title>{_e(title)} · Harbor Docs</title>'
           '<link rel="stylesheet" href="/static/app.css"></head>'
           f'<body>{nav}<main>{body}</main>{js}</body></html>')
    return _secure(HTMLResponse(doc, status_code=status))


def _doc_summary(doc_id: str, d: dict) -> dict:
    return {"id": doc_id, "title": d["title"], "state": d["state"],
            "author": d["author"], "project": d["project"],
            "updated_at": d["versions"][-1]["created_at"]}


# --------------------------------------------------------------------------- app
def build_app() -> Starlette:  # noqa: C901 - one closure per route, kept together
    st = State()

    def need_api(request: Request):
        s = _session(st, request)
        return s, (None if s else _err(401, "authentication required"))

    def need_page(request: Request):
        s = _session(st, request)
        return s, (None if s else _secure(RedirectResponse("/login", status_code=303)))

    def csrf_ok(request: Request, sess: dict, body: dict) -> bool:
        tok = request.headers.get("x-csrf-token") or body.get("csrf_token") or ""
        return secrets.compare_digest(str(tok), sess["csrf"])

    def start_session(user: str) -> tuple[str, dict]:
        sid = secrets.token_urlsafe(24)
        sess = {"user": user, "csrf": secrets.token_urlsafe(18)}
        with st.lock:
            st.sessions[sid] = sess
        return sid, sess

    def set_cookie(resp: Response, sid: str) -> Response:
        resp.set_cookie(COOKIE, sid, httponly=True, samesite="lax", path="/")
        return resp

    def check_password(body: dict) -> str | None:
        user = str(body.get("username") or "")
        if user in USERS and secrets.compare_digest(
                str(body.get("password") or ""), USERS[user]["password"]):
            return user
        return None

    def projects_for(user: str) -> list[dict]:
        out = []
        for pid, p in PROJECTS.items():
            role = st.current_role(user, pid)
            if role is None and not st.approver(user):
                continue
            out.append({"id": pid, "name": p["name"], "visibility": p["visibility"],
                        "access": role or "approver"})
        return out

    def project_documents(user: str, pid: str) -> list[dict]:
        member = st.current_role(user, pid) is not None
        out = []
        for did, d in st.documents.items():
            if d["project"] != pid:
                continue
            if not member and d["state"] == "draft":
                continue   # approvers do not see others' drafts in the list
            out.append(_doc_summary(did, d))
        return out

    def approvals_for(user: str) -> list[dict]:
        if not st.approver(user):
            return []
        return [approval_view(aid, a) for aid, a in st.approvals.items()
                if a["status"] == "pending"]

    def approval_view(aid: str, a: dict) -> dict:
        d = st.documents[a["document"]]
        return {"id": aid, "document": a["document"], "document_title": d["title"],
                "project": d["project"], **{k: a[k] for k in (
                    "requested_by", "requested_at", "status", "decided_by",
                    "decided_at", "comment")}}

    # ---------------------------------------------------------------- auth
    async def login_page(request: Request) -> Response:
        if request.method == "GET":
            if _session(st, request):
                return _secure(RedirectResponse("/dashboard", status_code=303))
            return _page("Sign in", LOGIN_FORM)
        user = check_password(await _body(request))
        if user is None:
            return _page("Sign in", '<p role="alert">Invalid username or password.</p>'
                         + LOGIN_FORM, status=401)
        sid, _ = start_session(user)
        return set_cookie(_secure(RedirectResponse("/dashboard", status_code=303)), sid)

    async def api_login(request: Request) -> Response:
        user = check_password(await _body(request))
        if user is None:
            return _err(401, "invalid credentials")
        sid, sess = start_session(user)
        return set_cookie(_json({"ok": True, "user": user, "csrf_token": sess["csrf"]}),
                          sid)

    async def logout(request: Request) -> Response:
        sess = _session(st, request)
        body = await _body(request)
        if sess and csrf_ok(request, sess, body):
            st.sessions.pop(request.cookies.get(COOKIE) or "", None)
        if request.url.path.startswith("/api/"):
            return _json({"ok": True})
        resp = _secure(RedirectResponse("/login", status_code=303))
        resp.delete_cookie(COOKIE, path="/")
        return resp

    # ---------------------------------------------------------------- JSON API
    async def api_me(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        u = sess["user"]
        info = USERS[u]
        return _json({
            "username": u, "name": info["name"], "email": info["email"],
            "team": {"id": TEAM, "name": "Meridian", "role": info["team_role"],
                     "permissions": info["permissions"]},
            "memberships": [
                {"project": m["project"], "project_name": PROJECTS[m["project"]]["name"],
                 "role": m["role"], "joined_at": m["joined_at"],
                 "removed_at": m["removed_at"],
                 "status": "removed" if m["removed_at"] else "active"}
                for m in st.memberships if m["user"] == u],
            "csrf_token": sess["csrf"]})

    async def api_me_recent(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        items = []
        for r in RECENT.get(sess["user"], []):
            d = st.documents[r["document"]]
            items.append({"document": r["document"], "title": d["title"],
                          "project": d["project"], "viewed_at": r["viewed_at"]})
        return _json({"recent": items})

    async def api_projects(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        return _json({"projects": projects_for(sess["user"])})

    def project_gate(request: Request):
        sess, err = need_api(request)
        if err:
            return None, None, err
        pid = request.path_params["pid"]
        if pid not in PROJECTS:
            return sess, pid, _err(404, "project not found")
        if not st.can_view_project(sess["user"], pid):
            return sess, pid, _err(403, "you are not a member of this project")
        return sess, pid, None

    async def api_project(request: Request) -> Response:
        sess, pid, err = project_gate(request)
        if err:
            return err
        p = PROJECTS[pid]
        return _json({"id": pid, "name": p["name"], "team": TEAM,
                      "visibility": p["visibility"], "description": p["description"],
                      "your_role": st.current_role(sess["user"], pid) or "approver",
                      "document_count": len(project_documents(sess["user"], pid))})

    async def api_project_documents(request: Request) -> Response:
        sess, pid, err = project_gate(request)
        if err:
            return err
        return _json({"project": pid, "documents": project_documents(sess["user"], pid)})

    async def api_project_members(request: Request) -> Response:
        sess, pid, err = project_gate(request)
        if err:
            return err
        return _json({"project": pid, "members": [
            {"user": m["user"], "name": USERS[m["user"]]["name"], "role": m["role"],
             "joined_at": m["joined_at"]}
            for m in st.memberships if m["project"] == pid and m["removed_at"] is None]})

    def doc_or_404(request: Request):
        did = request.path_params["did"]
        return did, st.documents.get(did)

    async def api_document(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        did, d = doc_or_404(request)
        if d is None:
            return _err(404, "document not found")
        ok, status = st.can_read_document(sess["user"], d)
        if not ok:
            return _err(status, "document not found" if status == 404
                        else "you do not have access to this document")
        cur = d["versions"][-1]
        return _json({"id": did, "title": d["title"], "project": d["project"],
                      "author": d["author"], "state": d["state"],
                      "created_at": d["created_at"], "current_version": cur["n"],
                      "updated_at": cur["created_at"], "content": cur["content"],
                      "links": {"versions": f"/api/documents/{did}/versions",
                                "shares": f"/api/documents/{did}/shares"}})

    async def api_versions(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        did, d = doc_or_404(request)
        if d is None:
            return _err(404, "document not found")
        ok, status = st.can_read_versions(sess["user"], d)
        if not ok:
            return _err(status, "document not found" if status == 404
                        else "you do not have access to this document")
        return _json({"document": did, "versions": [
            {"n": v["n"], "created_at": v["created_at"], "author": v["author"],
             "summary": v["summary"], "excerpt": v["content"][:60],
             "href": f"/api/documents/{did}/versions/{v['n']}"}
            for v in d["versions"]]})

    async def api_version(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        did, d = doc_or_404(request)
        if d is None:
            return _err(404, "document not found")
        ok, status = st.can_read_versions(sess["user"], d)
        if not ok:
            return _err(status, "document not found" if status == 404
                        else "you do not have access to this document")
        try:
            n = int(request.path_params["n"])
            v = next(x for x in d["versions"] if x["n"] == n)
        except (ValueError, StopIteration):
            return _err(404, "version not found")
        return _json({"document": did, "title": d["title"], **v})

    async def api_shares(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        did, d = doc_or_404(request)
        if d is None:
            return _err(404, "document not found")
        ok, status = st.can_read_shares(sess["user"], d)
        if not ok:
            return _err(status, "document not found" if status == 404
                        else "you do not have access to this document")
        now = _now()
        out = []
        for s in st.shares.get(did, []):
            item = {k: v for k, v in s.items() if k != "token"}
            if s["kind"] == "link":
                expired = s["expires_at"] < now
                item["status"] = "expired" if expired else "active"
                # active link tokens are shown to their creator only
                if expired or s["created_by"] == sess["user"]:
                    item["url"] = f"/s/{s['token']}"
                else:
                    item["token_hint"] = s["token"][:4] + "…"
            out.append(item)
        return _json({"document": did, "shares": out})

    async def api_transfer(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        body = await _body(request)
        if not csrf_ok(request, sess, body):
            return _err(403, "missing or invalid CSRF token")
        did, d = doc_or_404(request)
        if d is None:
            return _err(404, "document not found")
        u = sess["user"]
        if not (d["author"] == u or st.current_role(u, d["project"]) == "lead"):
            return _err(403, "only the author or the project lead can transfer ownership")
        to = str(body.get("to") or "")
        if to not in USERS or st.current_role(to, d["project"]) is None:
            return _err(400, "the new owner must be a current project member")
        with st.lock:
            d["author"] = to
        return _json({"ok": True, "document": did, "author": to})

    async def api_approvals(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        u = sess["user"]
        return _json({"approvals": approvals_for(u), "submitted": [
            approval_view(aid, a) for aid, a in st.approvals.items()
            if a["requested_by"] == u]})

    async def api_approval(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        a = st.approvals.get(request.path_params["aid"])
        if a is None:
            return _err(404, "approval request not found")
        u = sess["user"]
        if not (st.approver(u) or a["requested_by"] == u):
            return _err(403, "you cannot view this approval request")
        return _json(approval_view(request.path_params["aid"], a))

    async def api_decision(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        body = await _body(request)
        if not csrf_ok(request, sess, body):
            return _err(403, "missing or invalid CSRF token")
        aid = request.path_params["aid"]
        a = st.approvals.get(aid)
        if a is None:
            return _err(404, "approval request not found")
        u = sess["user"]
        if not st.approver(u):
            return _err(403, "approver permission required")
        decision = str(body.get("decision") or "")
        if decision not in ("approve", "reject"):
            return _err(400, "decision must be 'approve' or 'reject'")
        if a["status"] != "pending":
            return _err(409, "request already decided")
        with st.lock:
            a.update(status="approved" if decision == "approve" else "rejected",
                     decided_by=u, decided_at=_now(),
                     comment=str(body.get("comment") or "")[:500] or None)
            d = st.documents[a["document"]]
            d["state"] = "approved" if decision == "approve" else "draft"
        if _is_form(request):
            return _secure(RedirectResponse("/approvals", status_code=303))
        return _json(approval_view(aid, a))

    async def api_activity(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        if request.path_params["team"] != TEAM:
            return _err(404, "team not found")
        # every event of the team, whatever the project
        return _json({"team": TEAM, "events": st.activity})

    async def api_team(request: Request) -> Response:
        sess, err = need_api(request)
        if err:
            return err
        if request.path_params["team"] != TEAM:
            return _err(404, "team not found")
        return _json({"id": TEAM, "name": "Meridian", "members": [
            {"user": k, "name": v["name"], "role": v["team_role"],
             "permissions": v["permissions"]} for k, v in USERS.items()],
            "links": {"activity": f"/api/teams/{TEAM}/activity"}})

    async def api_404(request: Request) -> Response:
        return _err(404, "not found")

    # ---------------------------------------------------------------- share links
    async def share_link(request: Request) -> Response:
        tok = request.path_params["token"]
        for did, items in st.shares.items():
            for s in items:
                if s["kind"] == "link" and secrets.compare_digest(s.get("token", ""), tok):
                    if s["expires_at"] < _now():
                        return _page("Link expired",
                                     "<h1>This link has expired</h1><p>Ask the "
                                     "document owner for a new link.</p>", status=410)
                    d = st.documents[did]
                    return _page(d["title"], f"<h1>{_e(d['title'])}</h1>"
                                 f"<p>Shared read-only copy.</p>"
                                 f"<pre>{_e(d['versions'][-1]['content'])}</pre>")
        return _page("Not found", "<h1>Link not found</h1>", status=404)

    # ---------------------------------------------------------------- HTML pages
    async def root(request: Request) -> Response:
        return _secure(RedirectResponse(
            "/dashboard" if _session(st, request) else "/login", status_code=303))

    async def dashboard(request: Request) -> Response:
        sess, redir = need_page(request)
        if redir:
            return redir
        u = sess["user"]
        projects = "".join(f'<li><a href="/projects/{p["id"]}">{_e(p["name"])}</a> '
                           f'({_e(p["access"])})</li>' for p in projects_for(u))
        recent = "".join(
            f'<li><a href="/documents/{r["document"]}">'
            f'{_e(st.documents[r["document"]]["title"])}</a> — viewed {_e(r["viewed_at"])}'
            f'</li>' for r in RECENT.get(u, []))
        pending = len(approvals_for(u))
        body = (f"<h1>Welcome, {_e(USERS[u]['name'])}</h1>"
                f"<h2>Your projects</h2><ul>{projects}</ul>"
                f"<h2>Recently viewed</h2><ul>{recent or '<li>Nothing yet.</li>'}</ul>"
                + (f'<p><a href="/approvals">{pending} approval request(s) waiting</a></p>'
                   if pending else "")
                + '<p><a href="/activity">Team activity</a></p>')
        return _page("Dashboard", body, sess)

    async def projects_page(request: Request) -> Response:
        sess, redir = need_page(request)
        if redir:
            return redir
        rows = "".join(f'<tr><td><a href="/projects/{p["id"]}">{_e(p["name"])}</a></td>'
                       f'<td>{_e(p["visibility"])}</td><td>{_e(p["access"])}</td></tr>'
                       for p in projects_for(sess["user"]))
        return _page("Projects", "<h1>Projects</h1><table><tr><th>Project</th>"
                     f"<th>Visibility</th><th>Your access</th></tr>{rows}</table>", sess)

    async def project_page(request: Request) -> Response:
        sess, redir = need_page(request)
        if redir:
            return redir
        pid = request.path_params["pid"]
        u = sess["user"]
        if pid not in PROJECTS:
            return _page("Not found", "<h1>Project not found</h1>", sess, 404)
        if not st.can_view_project(u, pid):
            return _page("Forbidden", "<h1>You are not a member of this project</h1>",
                         sess, 403)
        docs = "".join(
            f'<tr><td>' + (f'<a href="/documents/{d["id"]}">{_e(d["title"])}</a>'
                           if d["state"] != "draft" or d["author"] == u
                           else _e(d["title"]))
            + f'</td><td><span class="state">{_e(d["state"])}</span></td>'
            f'<td>{_e(d["author"])}</td><td>{_e(d["updated_at"])}</td></tr>'
            for d in project_documents(u, pid))
        members = "".join(f'<li>{_e(m["user"])} ({_e(m["role"])})</li>'
                          for m in st.memberships
                          if m["project"] == pid and m["removed_at"] is None)
        p = PROJECTS[pid]
        return _page(p["name"], f"<h1>{_e(p['name'])}</h1><p>{_e(p['description'])}</p>"
                     "<h2>Documents</h2><table><tr><th>Title</th><th>State</th>"
                     f"<th>Author</th><th>Updated</th></tr>{docs}</table>"
                     f"<h2>Members</h2><ul>{members}</ul>", sess)

    async def document_page(request: Request) -> Response:
        sess, redir = need_page(request)
        if redir:
            return redir
        did = request.path_params["did"]
        return _page("Document", f'<div id="doc" data-id="{_e(did)}" data-mode="doc">'
                     'Loading…</div>', sess, scripts=("document.js",))

    async def versions_page(request: Request) -> Response:
        sess, redir = need_page(request)
        if redir:
            return redir
        did = request.path_params["did"]
        return _page("Versions", f'<div id="doc" data-id="{_e(did)}" '
                     'data-mode="versions">Loading…</div>'
                     f'<p><a href="/documents/{_e(did)}">Back to document</a></p>',
                     sess, scripts=("document.js",))

    async def approvals_page(request: Request) -> Response:
        sess, redir = need_page(request)
        if redir:
            return redir
        u = sess["user"]
        rows = ""
        for a in approvals_for(u):
            rows += (f'<tr><td><a href="/documents/{a["document"]}">'
                     f'{_e(a["document_title"])}</a></td><td>{_e(a["requested_by"])}</td>'
                     f'<td>{_e(a["requested_at"])}</td><td>'
                     f'<form method="post" action="/api/approvals/{a["id"]}/decision">'
                     f'<input type="hidden" name="csrf_token" value="{_e(sess["csrf"])}">'
                     '<input name="comment" placeholder="Comment">'
                     '<button name="decision" value="approve">Approve</button>'
                     '<button name="decision" value="reject">Reject</button>'
                     '</form></td></tr>')
        mine = "".join(
            f'<li>{_e(st.documents[a["document"]]["title"])} — {_e(a["status"])}</li>'
            for a in st.approvals.values() if a["requested_by"] == u)
        body = ("<h1>Approvals</h1>" + (
            "<h2>Waiting for your decision</h2><table><tr><th>Document</th>"
            f"<th>Requested by</th><th>Requested</th><th>Decision</th></tr>{rows}</table>"
            if st.approver(u) else "<p>You do not have approver permission.</p>")
            + f"<h2>Your requests</h2><ul>{mine or '<li>None.</li>'}</ul>")
        return _page("Approvals", body, sess)

    async def activity_page(request: Request) -> Response:
        sess, redir = need_page(request)
        if redir:
            return redir
        return _page("Activity", f'<h1>Team activity</h1><div id="feed" '
                     f'data-team="{TEAM}">Loading…</div>', sess, scripts=("activity.js",))

    async def profile_page(request: Request) -> Response:
        sess, redir = need_page(request)
        if redir:
            return redir
        u = sess["user"]
        info = USERS[u]
        rows = "".join(
            f'<tr><td>{_e(PROJECTS[m["project"]]["name"])}</td><td>{_e(m["role"])}</td>'
            f'<td>{_e(m["joined_at"])}</td><td>{_e(m["removed_at"] or "—")}</td></tr>'
            for m in st.memberships if m["user"] == u)
        perms = ", ".join(info["permissions"]) or "none"
        return _page("Profile", f"<h1>{_e(info['name'])}</h1><p>{_e(info['email'])}</p>"
                     f"<p>Team Meridian — {_e(info['team_role'])}; permissions: "
                     f"{_e(perms)}</p><h2>Project memberships</h2><table><tr>"
                     "<th>Project</th><th>Role</th><th>Joined</th><th>Removed</th></tr>"
                     f"{rows}</table>", sess)

    async def static(request: Request) -> Response:
        name = request.path_params["name"]
        files = {"app.css": (CSS, "text/css"),
                 "activity.js": (ACTIVITY_JS, "application/javascript"),
                 "document.js": (DOCUMENT_JS, "application/javascript")}
        if name not in files:
            return _secure(PlainTextResponse("not found", status_code=404))
        content, media = files[name]
        return _secure(Response(content, media_type=media))

    async def not_found(request: Request) -> Response:
        return _page("Not found", "<h1>Page not found</h1>", _session(st, request), 404)

    return Starlette(routes=[
        Route("/", root),
        Route("/login", login_page, methods=["GET", "POST"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/dashboard", dashboard),
        Route("/projects", projects_page),
        Route("/projects/{pid}", project_page),
        Route("/documents/{did}", document_page),
        Route("/documents/{did}/versions", versions_page),
        Route("/approvals", approvals_page),
        Route("/activity", activity_page),
        Route("/profile", profile_page),
        Route("/s/{token}", share_link),
        Route("/static/{name}", static),
        Route("/api/login", api_login, methods=["POST"]),
        Route("/api/logout", logout, methods=["POST"]),
        Route("/api/me", api_me),
        Route("/api/me/recent", api_me_recent),
        Route("/api/projects", api_projects),
        Route("/api/projects/{pid}", api_project),
        Route("/api/projects/{pid}/documents", api_project_documents),
        Route("/api/projects/{pid}/members", api_project_members),
        Route("/api/documents/{did}", api_document),
        Route("/api/documents/{did}/versions", api_versions),
        Route("/api/documents/{did}/versions/{n}", api_version),
        Route("/api/documents/{did}/shares", api_shares),
        Route("/api/documents/{did}/transfer", api_transfer, methods=["POST"]),
        Route("/api/approvals", api_approvals),
        Route("/api/approvals/{aid}", api_approval),
        Route("/api/approvals/{aid}/decision", api_decision, methods=["POST"]),
        Route("/api/teams/{team}", api_team),
        Route("/api/teams/{team}/activity", api_activity),
        Route("/api/{rest:path}", api_404),
        Route("/{rest:path}", not_found),
    ])


LOGIN_FORM = ('<h1>Sign in to Harbor Docs</h1><form method="post" action="/login">'
              '<label>Username <input name="username" autocomplete="username"></label> '
              '<label>Password <input name="password" type="password" '
              'autocomplete="current-password"></label> <button>Sign in</button></form>')


def serve(port: int = 0, host: str = "127.0.0.1", blocking: bool = False):
    import uvicorn
    config = uvicorn.Config(build_app(), host=host, port=port, log_level="warning",
                            lifespan="off", access_log=False, server_header=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="harbor-docs")
    thread.start()
    while not server.started:
        time.sleep(0.01)
    url = f"http://{host}:{server.servers[0].sockets[0].getsockname()[1]}/"
    if blocking:
        thread.join()
    return server, url
