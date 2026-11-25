"""Lumen Boards — a realistic, entirely synthetic project-board web application used
as an end-to-end evaluation target for Vigilo (see README.md and ground_truth.json
in this directory; assessment.json is the only part an agent is given).

A JavaScript-heavy single-page application: an HTML shell, a History-API router
(``/w/{workspace}/boards/{board}``), a content-hashed main bundle that learns its API
base from ``/static/config.json`` at boot and assembles every API URL from segments,
and a lazily loaded chunk (``chunk-board-share.<hash>.js``) that is only fetched when
the user opens a board's "⋯" (export / share) menu. The API is a cookie-session +
CSRF-token JSON REST API (``/api/v2``): workspaces (tenants) → boards → cards
(paginated) → comments, board and workspace members, notifications, invitations,
profile, and board export.

Three synthetic accounts in two workspaces:

    maya@lumen.test  Maya-Lumen-7Qx!2026  owner  of "northstar"
    leo@lumen.test   Leo-Lumen-4Vt!2026   member of "northstar"
    iris@lumen.test  Iris-Lumen-9Kp!2026  owner  of "quasar"

Seeded conditions (ground_truth.json):

A1  main.<hash>.js.map is served; its sourcesContent holds original source with an
    internal admin-API host and the unreleased feature-flag config     misconfiguration
A2  /static/config.json (fetched at boot) also carries a server-side search admin
    key next to the intended public values                             sensitive data
A3  /api/v2/boards/{b}/export (lazy chunk only) checks the session but not workspace
    membership: another tenant can export a board with cards+comments  vulnerability

Negative controls: every workspace-scoped endpoint enforces membership (404 for
non-members); /api/v2/me is the caller only; CSP/nosniff/Referrer-Policy/framing
headers are on every response; no CORS headers; HttpOnly+SameSite session cookie;
state-changing requests need X-CSRF-Token. All data is in memory; nothing touches
disk or the network.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import secrets
import threading
import time
from urllib.parse import parse_qsl

from starlette.applications import Starlette
from starlette.datastructures import MutableHeaders
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

# --------------------------------------------------------------------------- data
USERS = {
    "maya": {"id": "u-101", "email": "maya@lumen.test", "password": "Maya-Lumen-7Qx!2026",
             "name": "Maya Okafor", "title": "Head of Product"},
    "leo": {"id": "u-102", "email": "leo@lumen.test", "password": "Leo-Lumen-4Vt!2026",
            "name": "Leo Brandt", "title": "Product Marketing"},
    "iris": {"id": "u-201", "email": "iris@lumen.test", "password": "Iris-Lumen-9Kp!2026",
             "name": "Iris Navarro", "title": "Engineering Manager"},
}
WORKSPACES = {
    "northstar": {"name": "Northstar Labs", "members": {"maya": "owner", "leo": "member"}},
    "quasar": {"name": "Quasar Studio", "members": {"iris": "owner"}},
}
COLUMNS = ["Backlog", "In progress", "Done"]
BOARDS = {
    "b7k2xq": {"workspace": "northstar", "name": "Q3 launch plan",
               "description": "Everything that has to ship for the October launch."},
    "m4p9wd": {"workspace": "northstar", "name": "Hiring pipeline",
               "description": "Open roles, interview loops and offers."},
    "r8t3nz": {"workspace": "quasar", "name": "Platform roadmap",
               "description": "Quarterly platform themes and commitments."},
}
# card id -> (board, column, title, assignee, description)
CARDS = {
    "4101": ("b7k2xq", "Backlog", "Pricing page copy", "leo", "Rewrite tiers around seats."),
    "4102": ("b7k2xq", "Backlog", "Partner announcement embargo", "maya",
             "Coordinate the embargo with Halcyon PR."),
    "4103": ("b7k2xq", "In progress", "Onboarding email sequence", "leo", "Five emails, day 0-14."),
    "4104": ("b7k2xq", "In progress", "Usage-based billing dry run", "maya",
             "Shadow-bill ten design partners for one cycle."),
    "4105": ("b7k2xq", "Done", "Beta feedback synthesis", "leo", "Top themes from 42 interviews."),
    "4106": ("b7k2xq", "Backlog", "Status page copy", "leo", "Incident templates."),
    "4107": ("b7k2xq", "Backlog", "Localisation: DE / FR", "maya", "Vendor quote pending."),
    "4108": ("b7k2xq", "In progress", "Press kit assets", "leo", "Logos, screenshots, bios."),
    "4109": ("b7k2xq", "Backlog", "Webinar run-of-show", "leo", "45 minutes, two speakers."),
    "4110": ("b7k2xq", "In progress", "Sales enablement deck", "maya", "Objection handling."),
    "4111": ("b7k2xq", "Done", "Support macros", "leo", "Billing and SSO macros."),
    "4112": ("b7k2xq", "Backlog", "Release notes draft", "maya", "Owner: product."),
    "4113": ("b7k2xq", "Done", "Changelog widget", "leo", "Embedded in the app header."),
    "4114": ("b7k2xq", "Backlog", "Customer advisory board invites", "maya", "Twelve accounts."),
    "4201": ("m4p9wd", "In progress", "Senior backend engineer - offer", "maya",
             "Final approval from finance."),
    "4202": ("m4p9wd", "In progress", "Design lead - final round", "maya", "Panel on Thursday."),
    "4203": ("m4p9wd", "Backlog", "Referral bonus policy", "leo", "Benchmark against peers."),
    "4204": ("m4p9wd", "Done", "Interview rubric refresh", "maya", "Rolled out to all loops."),
    "4301": ("r8t3nz", "Backlog", "Multi-region failover", "iris", "Active/passive first."),
    "4302": ("r8t3nz", "In progress", "Postgres 17 upgrade", "iris", "Blue/green with logical rep."),
    "4303": ("r8t3nz", "In progress", "SSO for enterprise tier", "iris", "SAML + SCIM."),
    "4304": ("r8t3nz", "Done", "Rate limiter v2", "iris", "Token bucket per tenant."),
    "4305": ("r8t3nz", "Backlog", "Audit log export", "iris", "Customer-facing, CSV + JSON."),
}
# card id -> [(comment id, author, body, created_at)]
COMMENTS = {
    "4101": [("cm-9001", "maya", "Keep the free tier above the fold.", "2026-10-02T09:14:00Z")],
    "4102": [("cm-9002", "maya", "Launch date is 14 Oct - do not share outside Northstar until "
                                 "Halcyon confirms.", "2026-10-03T08:01:00Z"),
             ("cm-9003", "leo", "Halcyon wants the quote from their CEO by Friday.",
              "2026-10-03T10:40:00Z")],
    "4104": [("cm-9004", "leo", "Finance needs the dry-run numbers before pricing sign-off.",
              "2026-10-05T15:22:00Z")],
    "4201": [("cm-9101", "maya", "Offer approved at 142k + 0.08% equity; candidate answers "
                                 "Friday.", "2026-10-07T17:05:00Z")],
    "4202": [("cm-9102", "maya", "Strong portfolio; references pending.", "2026-10-08T11:30:00Z")],
    "4302": [("cm-9201", "iris", "Cut-over window booked for 2 Nov, 02:00 UTC.",
              "2026-10-09T13:00:00Z")],
    "4303": [("cm-9202", "iris", "Okta and Entra test tenants are ready.", "2026-10-10T09:45:00Z")],
}
NOTIFICATIONS = {
    "maya": [("Leo commented on “Partner announcement embargo”",
              "/w/northstar/boards/b7k2xq", False),
             ("Weekly digest for Northstar Labs is ready", "/w/northstar", True)],
    "leo": [("Maya assigned you “Press kit assets”", "/w/northstar/boards/b7k2xq", False)],
    "iris": [("Postgres 17 upgrade moved to In progress", "/w/quasar/boards/r8t3nz", True)],
}

# Served at /static/config.json and read by the bundle at boot. All of it is meant to
# be public except searchServiceAdminKey (A2), which belongs on the server only.
RUNTIME_CONFIG = {
    "apiBase": "/api/v2",
    "release": "2026.11.2",
    "environment": "production",
    "sentryDsn": "https://3f9a1c2e7b8d4e6f@errors.lumen.example/42",
    "search": {"url": "https://search.lumen.example", "publicKey": "lmn_pub_pk_5c2e0a9f7d41"},
    "searchServiceAdminKey": "lmn_live_sk_9Qe4TzV7m2Lx8RfK1bNw6YhC3pDs",
    "features": {"boardExport": True, "cardTemplates": False},
}

# ------------------------------------------------------------------ front end
CSS = """[hidden]{display:none!important}
body{font-family:system-ui,sans-serif;margin:0;color:#1d2330;background:#f5f6f8}
header.top{display:flex;gap:1rem;align-items:center;padding:.6rem 1.2rem;background:#1d2330}
header.top a,header.top button{color:#fff;background:none;border:0;cursor:pointer}
.brand{font-weight:700}.ws{flex:1;display:flex;gap:.8rem}
main{padding:1.2rem}footer{padding:1rem;color:#888;font-size:.8rem}
.panel{background:#fff;border:1px solid #ccd;padding:.8rem;position:absolute;z-index:5}
.boards li{margin:.3rem 0}.boards span{color:#888;margin-left:.6rem}
.board-head{display:flex;gap:1rem;align-items:center}.menu-wrap{position:relative}
.columns{display:flex;gap:1rem}.col{flex:1;background:#e9ecf1;padding:.6rem}
.card{display:block;width:100%;text-align:left;margin:.3rem 0;padding:.5rem;
background:#fff;border:1px solid #d6d9e0;cursor:pointer}
.drawer{position:fixed;right:0;top:0;bottom:0;width:26rem;background:#fff;padding:1rem;
box-shadow:-4px 0 12px rgba(0,0,0,.15);overflow:auto}
.error{color:#b00020}.sub{color:#666}.preview{max-height:16rem;overflow:auto}
"""

# The chunk is only requested by loadChunk() when a board's "⋯" menu is opened.
CHUNK_JS = r"""/*! lumen-web | chunk board-share */
(self.lumenChunks = self.lumenChunks || []).push(['board-share', function (rt) {
  'use strict';
  var api = rt.api, h = rt.h;

  // Exports are produced by the board service, addressed by board id.
  function exportBoard(boardId, format) {
    return api.get(['boards', boardId, 'export'], {format: format});
  }

  function downloadLink(name, text, type) {
    var href = URL.createObjectURL(new Blob([text], {type: type}));
    return '<a class="download" href="' + href + '" download="' + h(name) + '">Download ' +
      h(name) + '</a>';
  }

  function mount(panel, ctx) {
    var board = ctx.board;
    panel.innerHTML = '<h3>Export</h3>' +
      '<button type="button" data-format="json">Export as JSON</button> ' +
      '<button type="button" data-format="csv">Export as CSV</button>' +
      '<div class="export-result"></div><h3>Share</h3>' +
      '<div class="share-members">Loading members…</div>';
    var out = panel.querySelector('.export-result');
    Array.prototype.forEach.call(panel.querySelectorAll('[data-format]'), function (btn) {
      btn.addEventListener('click', function () {
        var format = btn.getAttribute('data-format');
        out.textContent = 'Preparing export…';
        exportBoard(board.id, format).then(function (data) {
          var text = format === 'json' ? JSON.stringify(data, null, 2) : String(data);
          var summary = format === 'json' ? data.cards.length + ' cards exported' :
            (text.trim().split('\n').length - 1) + ' cards exported';
          out.innerHTML = '<p>' + h(summary) + '</p>' +
            downloadLink('board-' + board.id + '.' + format, text,
                         format === 'json' ? 'application/json' : 'text/csv') +
            '<pre class="preview">' + h(text.slice(0, 1500)) + '</pre>';
        }).catch(function (e) { out.innerHTML = '<p class="error">' + h(e.message) + '</p>'; });
      });
    });
    api.get(['workspaces', ctx.workspace, 'boards', board.id, 'members']).then(function (d) {
      panel.querySelector('.share-members').innerHTML = '<ul>' + d.members.map(function (m) {
        return '<li>' + h(m.name) + ' — ' + h(m.role) + '</li>'; }).join('') + '</ul>' +
        '<p class="sub">Everyone in this workspace can open the board.</p>';
    });
  }

  return {mount: mount};
}]);
"""

MAIN_JS = r"""/*! lumen-web 2026.11.2 | (c) Lumen Software */
(function () {
  'use strict';
  var CHUNKS = {'board-share': '__BOARD_SHARE_CHUNK__'};
  var root = document.getElementById('root');
  var state = {cfg: null, user: null, csrf: null, workspaces: [], unread: null};

  function h(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
    });
  }
  function $(sel, el) { return (el || document).querySelector(sel); }

  // Error reporting: the DSN is public; events are buffered in this build.
  var reporter = {dsn: null, queue: [], capture: function (e) {
    this.queue.push(String((e && e.message) || e)); this.queue = this.queue.slice(-20); }};
  window.addEventListener('error', function (e) { reporter.capture(e.error || e.message); });

  // ---- API client: the base path is read from the runtime config at boot ----
  function apiUrl(segments, query) {
    var url = state.cfg.apiBase + '/' + segments.map(encodeURIComponent).join('/');
    var q = Object.keys(query || {}).filter(function (k) { return query[k] != null; })
      .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(query[k]); });
    return q.length ? url + '?' + q.join('&') : url;
  }
  function call(method, url, opts) {
    opts = opts || {};
    var headers = {'Accept': 'application/json'};
    var init = {method: method, credentials: 'same-origin', headers: headers};
    if (method !== 'GET' && state.csrf) { headers['X-CSRF-Token'] = state.csrf; }
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.body);
    }
    return fetch(url, init).then(function (res) {
      var type = res.headers.get('content-type') || '';
      return (type.indexOf('json') >= 0 ? res.json() : res.text()).then(function (body) {
        if (res.status === 401 && !opts.quiet) { state.user = null; navigate('/login', true); }
        if (!res.ok) {
          var err = new Error((body && body.error) || res.statusText);
          err.status = res.status;
          throw err;
        }
        return body;
      });
    });
  }
  var api = {
    url: apiUrl,
    get: function (segs, query, opts) { return call('GET', apiUrl(segs, query), opts); },
    follow: function (url) { return call('GET', url); },
    post: function (segs, body, opts) {
      return call('POST', apiUrl(segs), Object.assign({body: body}, opts)); },
    del: function (segs) { return call('DELETE', apiUrl(segs)); }
  };

  // ---- lazily loaded chunks (registered through self.lumenChunks) ----
  var modules = {}, loading = {};
  var registry = self.lumenChunks = self.lumenChunks || [];
  function define(entry) { modules[entry[0]] = entry[1]({api: api, h: h, state: state}); }
  registry.forEach(define);
  registry.push = function (entry) { define(entry); return Array.prototype.push.call(this, entry); };
  function loadChunk(name) {
    if (modules[name]) { return Promise.resolve(modules[name]); }
    if (!loading[name]) {
      loading[name] = new Promise(function (resolve, reject) {
        var s = document.createElement('script');
        s.src = '/static/js/' + CHUNKS[name];
        s.async = true;
        s.onload = function () {
          if (modules[name]) { resolve(modules[name]); }
          else { reject(new Error('chunk ' + name + ' did not register')); }
        };
        s.onerror = function () { delete loading[name]; reject(new Error('could not load ' + name)); };
        document.head.appendChild(s);
      });
    }
    return loading[name];
  }

  // ---- History API router ----
  var routes = [
    [/^\/login\/?$/, viewLogin, true],
    [/^\/$/, viewHome],
    [/^\/w\/([^/]+)\/?$/, viewWorkspace],
    [/^\/w\/([^/]+)\/boards\/([^/]+)\/?$/, viewBoard],
    [/^\/w\/([^/]+)\/members\/?$/, viewMembers],
    [/^\/settings\/?$/, viewSettings]
  ];
  function navigate(path, replace) {
    history[replace ? 'replaceState' : 'pushState'](null, '', path);
    render();
  }
  function render() {
    var path = location.pathname;
    for (var i = 0; i < routes.length; i++) {
      var m = routes[i][0].exec(path);
      if (!m) { continue; }
      if (!routes[i][2] && !state.user) { return navigate('/login', true); }
      return Promise.resolve()
        .then(function () { return routes[i][1].apply(null, m.slice(1).map(decodeURIComponent)); })
        .catch(showError);
    }
    if (!state.user) { return navigate('/login', true); }
    layout('<h1>Page not found</h1><p class="sub">' + h(path) + '</p>');
  }
  document.addEventListener('click', function (e) {
    var a = e.target.closest('a[data-link]');
    if (!a || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey) { return; }
    e.preventDefault();
    navigate(a.getAttribute('href'));
  });
  window.addEventListener('popstate', render);

  function showError(err) {
    if (err && err.status === 401) { return; }
    var msg = err && err.status === 404 ?
      'This page does not exist or you do not have access to it.' : (err && err.message);
    if (state.user) { layout('<h1>Something went wrong</h1><p class="error">' + h(msg) + '</p>'); }
    else { root.innerHTML = '<p class="error">' + h(msg) + '</p>'; }
  }

  function layout(main) {
    var ws = state.workspaces.map(function (w) {
      return '<a data-link href="/w/' + h(w.slug) + '">' + h(w.name) + '</a>'; }).join('');
    root.innerHTML = '<header class="top"><a data-link class="brand" href="/">Lumen</a>' +
      '<nav class="ws">' + ws + '</nav>' +
      '<button id="bell" type="button" aria-label="Notifications">Inbox <span id="unread">' +
      (state.unread ? state.unread : '') + '</span></button>' +
      '<a data-link href="/settings">' + h(state.user.name) + '</a>' +
      '<button id="signout" type="button">Sign out</button></header>' +
      '<div id="notifications" class="panel" hidden></div>' +
      '<main>' + main + '</main><footer>Lumen Boards ' + h(state.cfg.release) + '</footer>';
    $('#signout').addEventListener('click', signOut);
    $('#bell').addEventListener('click', toggleNotifications);
    if (state.unread === null) {
      api.get(['notifications']).then(function (d) {
        state.unread = d.unread;
        var el = $('#unread'); if (el) { el.textContent = d.unread || ''; }
      });
    }
  }

  function toggleNotifications() {
    var panel = $('#notifications');
    if (!panel.hidden) { panel.hidden = true; return; }
    panel.hidden = false;
    panel.textContent = 'Loading…';
    api.get(['notifications']).then(function (d) {
      panel.innerHTML = '<ul>' + d.items.map(function (n) {
        return '<li><a data-link href="' + h(n.link) + '">' + h(n.text) + '</a></li>';
      }).join('') + '</ul>';
    });
  }

  function startSession(d) {
    state.user = d.user;
    state.csrf = d.csrfToken;
    return api.get(['workspaces']).then(function (r) { state.workspaces = r.workspaces; });
  }

  function signOut() {
    api.del(['session']).catch(function () {}).then(function () {
      state.user = null; state.csrf = null; state.workspaces = []; state.unread = null;
      navigate('/login', true);
    });
  }

  // ---- views ----
  function viewLogin() {
    root.innerHTML = '<main class="login"><h1>Sign in to Lumen</h1><form id="login-form">' +
      '<p><label>Email <input id="email" name="email" type="email" autocomplete="username" ' +
      'required></label></p><p><label>Password <input id="password" name="password" ' +
      'type="password" autocomplete="current-password" required></label></p>' +
      '<button type="submit">Sign in</button><p id="login-error" class="error" role="alert">' +
      '</p></form></main>';
    $('#login-form').addEventListener('submit', function (e) {
      e.preventDefault();
      api.post(['session'], {email: $('#email').value, password: $('#password').value},
               {quiet: true})
        .then(startSession)
        .then(function () { navigate('/', true); })
        .catch(function () { $('#login-error').textContent = 'Email or password is incorrect.'; });
    });
  }

  function viewHome() {
    if (state.workspaces.length) { return navigate('/w/' + state.workspaces[0].slug, true); }
    layout('<h1>No workspaces yet</h1>');
  }

  function viewWorkspace(slug) {
    return Promise.all([api.get(['workspaces', slug]), api.get(['workspaces', slug, 'boards'])])
      .then(function (r) {
        var ws = r[0];
        layout('<h1>' + h(ws.name) + '</h1><p class="sub">You are ' + h(ws.role) +
          ' · <a data-link href="/w/' + h(slug) + '/members">Members</a></p>' +
          '<h2>Boards</h2><ul class="boards">' + r[1].boards.map(function (b) {
            return '<li><a data-link href="/w/' + h(slug) + '/boards/' + h(b.id) + '">' +
              h(b.name) + '</a><span>' + h(b.card_count) + ' cards</span></li>';
          }).join('') + '</ul>');
      });
  }

  function viewBoard(slug, boardId) {
    var path = ['workspaces', slug, 'boards', boardId];
    return Promise.all([api.get(path), api.get(path.concat('cards'), {page: 1, per_page: 10})])
      .then(function (r) {
        var board = r[0], next = null;
        layout('<p class="sub"><a data-link href="/w/' + h(slug) + '">All boards</a></p>' +
          '<div class="board-head"><h1>' + h(board.name) + '</h1>' +
          '<div class="menu-wrap"><button id="board-menu" type="button" aria-haspopup="true" ' +
          'aria-label="Board actions">⋯</button>' +
          '<div id="board-menu-panel" class="panel" hidden></div></div></div>' +
          '<p class="sub">' + h(board.description) + '</p><div id="columns" class="columns">' +
          board.columns.map(function (c) {
            return '<section class="col" data-column="' + h(c) + '"><h2>' + h(c) + '</h2></section>';
          }).join('') + '</div><button id="more" type="button" hidden>Load more cards</button>' +
          '<aside id="drawer" class="drawer" hidden></aside>');
        function addCards(page) {
          page.cards.forEach(function (c) {
            var col = $('[data-column="' + c.column + '"]') || $('.col');
            col.insertAdjacentHTML('beforeend', '<button type="button" class="card" data-card="' +
              h(c.id) + '">' + h(c.title) + '<br><small>' + h(c.assignee) + '</small></button>');
          });
          next = page.next;
          $('#more').hidden = !next;
        }
        addCards(r[1]);
        $('#more').addEventListener('click', function () { api.follow(next).then(addCards); });
        $('#columns').addEventListener('click', function (e) {
          var btn = e.target.closest('[data-card]');
          if (btn) { openCard(slug, boardId, btn.getAttribute('data-card')); }
        });
        $('#board-menu').addEventListener('click', function () { toggleBoardMenu(slug, board); });
      });
  }

  function openCard(slug, boardId, cardId) {
    var path = ['workspaces', slug, 'boards', boardId, 'cards', cardId];
    var drawer = $('#drawer');
    drawer.hidden = false;
    drawer.textContent = 'Loading…';
    Promise.all([api.get(path), api.get(path.concat('comments'))]).then(function (r) {
      var c = r[0], comments = r[1].comments;
      drawer.innerHTML = '<button id="drawer-close" type="button">Close</button>' +
        '<h2>' + h(c.title) + '</h2><p class="sub">' + h(c.column) + ' · ' +
        h(c.assignee) + ' · due ' + h(c.due) + '</p><p>' + h(c.description) + '</p>' +
        '<h3>Comments (' + comments.length + ')</h3><ul>' + comments.map(function (m) {
          return '<li><strong>' + h(m.author) + '</strong> ' + h(m.body) +
            ' <small>' + h(m.created_at) + '</small></li>';
        }).join('') + '</ul>';
      $('#drawer-close').addEventListener('click', function () { drawer.hidden = true; });
    }).catch(function (e) { drawer.innerHTML = '<p class="error">' + h(e.message) + '</p>'; });
  }

  function toggleBoardMenu(slug, board) {
    var panel = $('#board-menu-panel');
    if (!panel.hidden) { panel.hidden = true; return; }
    panel.hidden = false;
    panel.textContent = 'Loading…';
    loadChunk('board-share').then(function (mod) {
      mod.mount(panel, {workspace: slug, board: board});
    }).catch(function (e) { panel.innerHTML = '<p class="error">' + h(e.message) + '</p>'; });
  }

  function viewMembers(slug) {
    return Promise.all([api.get(['workspaces', slug]), api.get(['workspaces', slug, 'members'])])
      .then(function (r) {
        var ws = r[0], owner = ws.role === 'owner';
        layout('<h1>' + h(ws.name) + ' — members</h1><table><tr><th>Name</th>' +
          '<th>Email</th><th>Role</th></tr>' + r[1].members.map(function (m) {
            return '<tr><td>' + h(m.name) + '</td><td>' + h(m.email) + '</td><td>' +
              h(m.role) + '</td></tr>'; }).join('') + '</table>' +
          (owner ? '<h2>Invite someone</h2><form id="invite-form"><input id="invite-email" ' +
            'type="email" placeholder="name@company.com" required> <select id="invite-role">' +
            '<option value="member">Member</option></select> <button type="submit">Send ' +
            'invite</button><p id="invite-status" role="status"></p></form>' :
            '<p class="sub">Only workspace owners can invite people.</p>'));
        if (!owner) { return; }
        $('#invite-form').addEventListener('submit', function (e) {
          e.preventDefault();
          api.post(['workspaces', slug, 'invitations'],
                   {email: $('#invite-email').value, role: $('#invite-role').value})
            .then(function (inv) { $('#invite-status').textContent = 'Invitation sent to ' + inv.email; })
            .catch(function (err) { $('#invite-status').textContent = err.message; });
        });
      });
  }

  function viewSettings() {
    return api.get(['me']).then(function (me) {
      layout('<h1>Your profile</h1><dl><dt>Name</dt><dd>' + h(me.name) + '</dd><dt>Email</dt>' +
        '<dd>' + h(me.email) + '</dd><dt>Title</dt><dd>' + h(me.title) + '</dd></dl>' +
        '<h2>Workspaces</h2><ul>' + me.workspaces.map(function (w) {
          return '<li>' + h(w.name) + ' (' + h(w.role) + ')</li>'; }).join('') + '</ul>');
    });
  }

  // ---- boot ----
  fetch('/static/config.json', {credentials: 'same-origin'})
    .then(function (r) { return r.json(); })
    .then(function (cfg) {
      state.cfg = cfg;
      reporter.dsn = cfg.sentryDsn;
      return api.get(['session'], null, {quiet: true});
    })
    .then(function (s) { if (s.authenticated) { return startSession(s); } })
    .then(render)
    .catch(function (e) { root.textContent = 'Lumen could not start: ' + e.message; });
})();
"""

# Original modules that only survive in the source map (A1): the build tree-shakes
# them out of the shipped bundle, but sourcesContent keeps them verbatim.
ORIGINAL_ENDPOINTS = """// src/config/endpoints.js
// NOTE(platform): support tooling talks to the admin API directly from inside the
// VPN; it trusts the X-Lumen-Staff header and is not exposed through the gateway.
// Never call it from the browser build.
export const INTERNAL_ADMIN_API = "https://admin-api.lumen.internal:8443";
export const INTERNAL_METRICS = "http://metrics.lumen.internal:9090";
export const PUBLIC_API_BASE = "/api/v2";
"""
ORIGINAL_FLAGS = """// src/config/flags.js -- rollout config, do not publish before GA
export const FLAGS = {
  cardTemplates: { enabled: false, allowlist: ["northstar"] },
  billingUsageMeter: { enabled: false, rollout: 0.05, owners: ["growth"] },
  staffImpersonation: { enabled: true, staffOnly: true, header: "X-Lumen-Staff" },
  legacyExportV1: { enabled: true, sunset: "2027-01-31" },
};
"""


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:8]


LAZY_CHUNK = f"chunk-board-share.{_hash(CHUNK_JS)}.js"
_MAIN_BODY = MAIN_JS.replace("__BOARD_SHARE_CHUNK__", LAZY_CHUNK)
MAIN_BUNDLE = f"main.{_hash(_MAIN_BODY)}.js"
SOURCE_MAP = MAIN_BUNDLE + ".map"
CSS_FILE = f"app.{_hash(CSS)}.css"
MAIN_JS_SERVED = _MAIN_BODY + f"//# sourceMappingURL={SOURCE_MAP}\n"
SOURCE_MAP_JSON = json.dumps({
    "version": 3, "file": MAIN_BUNDLE, "sourceRoot": "",
    "sources": ["webpack://lumen-web/./src/app.js",
                "webpack://lumen-web/./src/config/endpoints.js",
                "webpack://lumen-web/./src/config/flags.js"],
    "sourcesContent": [_MAIN_BODY, ORIGINAL_ENDPOINTS, ORIGINAL_FLAGS],
    "names": [], "mappings": "AAAA;AACA",
})
STATIC_JS = {MAIN_BUNDLE: MAIN_JS_SERVED, LAZY_CHUNK: CHUNK_JS, SOURCE_MAP: SOURCE_MAP_JSON}

SHELL = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lumen Boards</title>
<link rel="stylesheet" href="/static/css/{CSS_FILE}">
<script defer src="/static/js/{MAIN_BUNDLE}"></script>
</head><body><div id="root">Loading Lumen…</div>
<noscript>Lumen Boards needs JavaScript.</noscript></body></html>"""

# ------------------------------------------------------------------ server side
SESSION_COOKIE = "lumen_session"
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; "
                               "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                               "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


class SecurityHeaders:
    """Pure ASGI middleware: defensive headers on every response (negative control)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for k, v in SECURITY_HEADERS.items():
                    headers.setdefault(k, v)
                if scope["path"].startswith("/api/"):
                    headers.setdefault("Cache-Control", "no-store")
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _json(body, status: int = 200, headers: dict | None = None) -> Response:
    return JSONResponse(body, status_code=status, headers=headers)


def _error(status: int, code: str) -> Response:
    return _json({"error": code}, status)


def _session(request: Request) -> dict | None:
    return request.app.state.sessions.get(request.cookies.get(SESSION_COOKIE) or "")


def _caller(request: Request) -> str | None:
    s = _session(request)
    return s["user"] if s else None


def _csrf_ok(request: Request) -> bool:
    s = _session(request)
    return bool(s) and secrets.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"])


async def _body(request: Request) -> dict:
    raw = (await request.body()).decode("utf-8", "replace")
    if "json" in request.headers.get("content-type", ""):
        try:
            data = json.loads(raw or "{}")
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}
    return dict(parse_qsl(raw))


def _user_public(label: str) -> dict:
    u = USERS[label]
    return {"id": u["id"], "email": u["email"], "name": u["name"]}


def _resolve(request: Request):
    """Authenticate and resolve the workspace / board / card named in the path,
    enforcing workspace membership. Returns (user, scope) or an error response.
    Non-members get the same 404 as a missing resource."""
    user = _caller(request)
    if user is None:
        return _error(401, "authentication_required")
    p = request.path_params
    ws = WORKSPACES.get(p["workspace"])
    if ws is None or user not in ws["members"]:
        return _error(404, "not_found")
    scope = {"slug": p["workspace"], "ws": ws, "role": ws["members"][user]}
    if "board" in p:
        board = BOARDS.get(p["board"])
        if board is None or board["workspace"] != p["workspace"]:
            return _error(404, "not_found")
        scope["board_id"], scope["board"] = p["board"], board
    if "card" in p:
        card = CARDS.get(p["card"])
        if card is None or card[0] != p["board"]:
            return _error(404, "not_found")
        scope["card_id"], scope["card"] = p["card"], card
    return user, scope


def _board_json(board_id: str) -> dict:
    b = BOARDS[board_id]
    return {"id": board_id, "workspace": b["workspace"], "name": b["name"],
            "description": b["description"], "columns": COLUMNS,
            "card_count": sum(1 for c in CARDS.values() if c[0] == board_id)}


def _card_json(card_id: str, full: bool = False) -> dict:
    board, column, title, assignee, description = CARDS[card_id]
    out = {"id": card_id, "board": board, "column": column, "title": title,
           "assignee": USERS[assignee]["name"]}
    if full:
        out.update(description=description, due=f"2026-10-{10 + int(card_id) % 18:02d}",
                   comment_count=len(COMMENTS.get(card_id, [])))
    return out


def _comments_json(card_id: str) -> list[dict]:
    return [{"id": i, "author": USERS[a]["name"], "body": b, "created_at": t}
            for i, a, b, t in COMMENTS.get(card_id, [])]


# --- pages and static assets
async def shell(request: Request) -> Response:
    return HTMLResponse(SHELL)


async def static_js(request: Request) -> Response:
    name = request.path_params["name"]
    if name not in STATIC_JS:
        return PlainTextResponse("Not Found", status_code=404)
    media = ("application/json" if name.endswith(".map")
             else "application/javascript; charset=utf-8")
    return Response(STATIC_JS[name], media_type=media,
                    headers={"Cache-Control": "public, max-age=31536000, immutable"})


async def static_css(request: Request) -> Response:
    if request.path_params["name"] != CSS_FILE:
        return PlainTextResponse("Not Found", status_code=404)
    return Response(CSS, media_type="text/css")


async def runtime_config(request: Request) -> Response:
    return _json(RUNTIME_CONFIG, headers={"Cache-Control": "no-cache"})


async def static_404(request: Request) -> Response:
    return PlainTextResponse("Not Found", status_code=404)


# --- session
async def session(request: Request) -> Response:
    sessions = request.app.state.sessions
    if request.method == "GET":
        s = _session(request)
        if not s:
            return _json({"authenticated": False, "csrfToken": None})
        return _json({"authenticated": True, "user": _user_public(s["user"]),
                      "csrfToken": s["csrf"]})
    if request.method == "DELETE":
        if _session(request) is None:
            return _error(401, "authentication_required")
        if not _csrf_ok(request):
            return _error(403, "csrf_token_invalid")
        sessions.pop(request.cookies.get(SESSION_COOKIE), None)
        resp = Response(status_code=204)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp
    body = await _body(request)
    email = str(body.get("email") or "").strip().lower()
    label = next((k for k, u in USERS.items() if u["email"] == email), None)
    if label is None or not secrets.compare_digest(str(body.get("password") or ""),
                                                   USERS[label]["password"]):
        return _error(401, "invalid_credentials")
    sid, csrf = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    sessions[sid] = {"user": label, "csrf": csrf}
    resp = _json({"user": _user_public(label), "csrfToken": csrf})
    resp.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="lax", path="/")
    return resp


# --- profile and notifications
async def me(request: Request) -> Response:
    user = _caller(request)
    if user is None:
        return _error(401, "authentication_required")
    u = USERS[user]
    return _json({**_user_public(user), "title": u["title"], "workspaces": [
        {"slug": s, "name": w["name"], "role": w["members"][user]}
        for s, w in WORKSPACES.items() if user in w["members"]]})


async def notifications(request: Request) -> Response:
    user = _caller(request)
    if user is None:
        return _error(401, "authentication_required")
    items = [{"id": f"n-{i + 1}", "text": t, "link": link, "read": read}
             for i, (t, link, read) in enumerate(NOTIFICATIONS.get(user, []))]
    return _json({"unread": sum(not n["read"] for n in items), "items": items})


# --- workspaces
async def workspaces(request: Request) -> Response:
    user = _caller(request)
    if user is None:
        return _error(401, "authentication_required")
    return _json({"workspaces": [{"slug": s, "name": w["name"], "role": w["members"][user]}
                                 for s, w in WORKSPACES.items() if user in w["members"]]})


async def workspace(request: Request) -> Response:
    r = _resolve(request)
    if isinstance(r, Response):
        return r
    _, sc = r
    return _json({"slug": sc["slug"], "name": sc["ws"]["name"], "role": sc["role"],
                  "member_count": len(sc["ws"]["members"])})


async def workspace_members(request: Request) -> Response:
    r = _resolve(request)
    if isinstance(r, Response):
        return r
    _, sc = r
    body = {"members": [{**_user_public(u), "role": role}
                        for u, role in sc["ws"]["members"].items()]}
    if sc["role"] == "owner":
        body["invitations"] = [i for i in request.app.state.invitations
                               if i["workspace"] == sc["slug"]]
    return _json(body)


async def invitations(request: Request) -> Response:
    r = _resolve(request)
    if isinstance(r, Response):
        return r
    user, sc = r
    if not _csrf_ok(request):
        return _error(403, "csrf_token_invalid")
    if sc["role"] != "owner":
        return _error(403, "forbidden")
    body = await _body(request)
    email, role = str(body.get("email") or "").strip().lower(), body.get("role", "member")
    if not EMAIL_RE.match(email) or role != "member":
        return _error(422, "invalid_invitation")
    inv = {"id": "inv-" + secrets.token_hex(4), "workspace": sc["slug"], "email": email,
           "role": role, "invited_by": USERS[user]["email"], "status": "pending"}
    request.app.state.invitations.append(inv)
    return _json(inv, 201)


# --- boards, cards, comments
async def boards(request: Request) -> Response:
    r = _resolve(request)
    if isinstance(r, Response):
        return r
    _, sc = r
    return _json({"boards": [_board_json(b) for b, v in BOARDS.items()
                             if v["workspace"] == sc["slug"]]})


async def board(request: Request) -> Response:
    r = _resolve(request)
    if isinstance(r, Response):
        return r
    return _json(_board_json(r[1]["board_id"]))


async def board_members(request: Request) -> Response:
    r = _resolve(request)
    if isinstance(r, Response):
        return r
    _, sc = r
    return _json({"board": sc["board_id"], "members": [
        {**_user_public(u), "role": role} for u, role in sc["ws"]["members"].items()]})


async def cards(request: Request) -> Response:
    r = _resolve(request)
    if isinstance(r, Response):
        return r
    _, sc = r
    try:
        page = max(1, int(request.query_params.get("page", 1)))
        per_page = min(50, max(1, int(request.query_params.get("per_page", 10))))
    except ValueError:
        return _error(400, "invalid_pagination")
    ids = [c for c, v in CARDS.items() if v[0] == sc["board_id"]]
    chunk = ids[(page - 1) * per_page: page * per_page]
    nxt = None
    headers = {}
    if page * per_page < len(ids):
        nxt = (f"/api/v2/workspaces/{sc['slug']}/boards/{sc['board_id']}/cards"
               f"?page={page + 1}&per_page={per_page}")
        headers["Link"] = f'<{nxt}>; rel="next"'
    return _json({"cards": [_card_json(c) for c in chunk], "page": page,
                  "per_page": per_page, "total": len(ids), "next": nxt}, headers=headers)


async def card(request: Request) -> Response:
    r = _resolve(request)
    if isinstance(r, Response):
        return r
    return _json(_card_json(r[1]["card_id"], full=True))


async def comments(request: Request) -> Response:
    r = _resolve(request)
    if isinstance(r, Response):
        return r
    return _json({"card": r[1]["card_id"], "comments": _comments_json(r[1]["card_id"])})


async def board_export(request: Request) -> Response:
    """Board export, called only by the lazy board-share chunk. A3 (ground_truth.json):
    it requires a session but never checks membership of the board's workspace."""
    user = _caller(request)
    if user is None:
        return _error(401, "authentication_required")
    board_id = request.path_params["board"]
    if board_id not in BOARDS:
        return _error(404, "not_found")
    fmt = request.query_params.get("format", "json")
    ids = [c for c, v in CARDS.items() if v[0] == board_id]
    disposition = {"Content-Disposition": f'attachment; filename="board-{board_id}.{fmt}"'}
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["id", "title", "column", "assignee", "description", "comments"])
        for c in ids:
            cj = _card_json(c, full=True)
            w.writerow([c, cj["title"], cj["column"], cj["assignee"], cj["description"],
                        " | ".join(f"{m['author']}: {m['body']}" for m in _comments_json(c))])
        return Response(buf.getvalue(), media_type="text/csv", headers=disposition)
    if fmt != "json":
        return _error(400, "unsupported_format")
    return _json({"format": "lumen-board-export/1",
                  "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "exported_by": USERS[user]["email"], "board": _board_json(board_id),
                  "cards": [{**_card_json(c, full=True), "comments": _comments_json(c)}
                            for c in ids]}, headers=disposition)


async def api_404(request: Request) -> Response:
    return _error(404, "not_found")


def build_app() -> Starlette:
    ws, bd = "/api/v2/workspaces/{workspace}", "/api/v2/workspaces/{workspace}/boards/{board}"
    app = Starlette(routes=[
        Route("/static/config.json", runtime_config),
        Route("/static/js/{name}", static_js),
        Route("/static/css/{name}", static_css),
        Route("/static/{rest:path}", static_404),
        Route("/api/v2/session", session, methods=["GET", "POST", "DELETE"]),
        Route("/api/v2/me", me),
        Route("/api/v2/notifications", notifications),
        Route("/api/v2/workspaces", workspaces),
        Route(ws, workspace),
        Route(ws + "/members", workspace_members),
        Route(ws + "/invitations", invitations, methods=["POST"]),
        Route(ws + "/boards", boards),
        Route(bd, board),
        Route(bd + "/members", board_members),
        Route(bd + "/cards", cards),
        Route(bd + "/cards/{card}", card),
        Route(bd + "/cards/{card}/comments", comments),
        Route("/api/v2/boards/{board}/export", board_export),
        Route("/api/{rest:path}", api_404, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
        Route("/{rest:path}", shell),
    ], middleware=[Middleware(SecurityHeaders)])
    app.state.sessions = {}
    app.state.invitations = []
    return app


def serve(port: int = 0, host: str = "127.0.0.1", blocking: bool = False):
    import uvicorn
    config = uvicorn.Config(build_app(), host=host, port=port, log_level="warning",
                            lifespan="off", access_log=False, server_header=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="lumen-boards")
    thread.start()
    while not server.started:
        time.sleep(0.01)
    url = f"http://{host}:{server.servers[0].sockets[0].getsockname()[1]}/"
    if blocking:
        thread.join()
    return server, url
