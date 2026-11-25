"""Browser capability: the agent's own browser.

An HTTP-only crawler cannot see a JavaScript application: pages are rendered,
navigation is client-side, and the API calls are made by script. The agent needs a
browser it can *drive*:

* ``browser.visit``      navigate, let the application settle, and report what the
                         page became: final URL, title, visible text, DOM outline,
                         console, links, forms, and **every request the page made**
                         (XHR/fetch with method, status, content type and request
                         body shape). Same-origin calls become endpoints.
* ``browser.act``        click / fill / select / press / submit / evaluate / back /
                         wait, then report what changed and what was requested:
                         how the agent walks *functionality*, not just URLs.
* ``browser.cookies``    the browser's cookies (names and flags, never values).
* ``browser.screenshot`` a JPEG of the rendered page, stored in the run's audited
                         traffic as an artifact row.

Every call takes an optional ``session``: ``anon``, ``provided-cookie`` (the
operator's cookie credential, the default when one exists) or the label of an
account ``auth.login`` established. Each identity gets its own browser context
(cookie jar), kept for the whole run.

Safety — enforced here, never trusted to the page
-------------------------------------------------
* **The browser has no network of its own.** Every request it makes (documents,
  scripts, XHR, fetch, frames, redirects) is intercepted and *answered by the
  engine's guarded HTTP client* (``ctx.http.request``): per-hop scope, the platform
  IP policy (no DNS rebinding into private or metadata ranges), the egress proxy,
  the activity policy (no PUT/PATCH/DELETE unless authorised), budgets, rate limits
  and the recorded traffic all apply to the browser exactly as to any tool.
  Redirects are returned to the browser un-followed, so each hop is a new,
  scope-checked request.
* **Fail closed.** Chromium additionally runs with every host name mapped to
  NOTFOUND and a dead proxy, so anything that escaped interception (DNS prefetch,
  preconnect) has nowhere to go; WebRTC is limited to proxied UDP (none);
  WebSockets are not proxied by the guard and are therefore refused and reported
  (a coverage limitation, never a silent bypass); service workers, downloads,
  popups and dialogs are blocked.
* **Identity providers are never assessed.** A navigation to an out-of-scope host
  is aborted and reported; if that host is an identity provider (or a declared
  redirect host), the result carries ``auth_state: identity_provider`` so the
  coverage verdict says *blocked by authentication* instead of analysing the login
  page as the application.
* **Bounded.** Per-call wall clock, request cap, action cap, text/DOM caps;
  images, media and fonts are not fetched at all (they say nothing about
  behaviour and would spend the request budget).

Playwright is an optional dependency (``pip install vigilo[browser]`` and
``playwright install chromium``); without it the capability is reported
unavailable and is not offered to the agent.
"""
from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import html
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from src.greybox_web import modes
from src.greybox_web.tools import Observation, PageInfo, ParamInfo, ToolContext, ToolResult

log = logging.getLogger("greybox.browser")

MAX_ACTIONS = 8
PAGE_CLOSE_TIMEOUT_S = 5.0          # a wedged page must not hold its caller
MAX_REQUESTS_PER_CALL = 150
MAX_TEXT = 6000
MAX_REQUESTS_RETURNED = 60
SCREENSHOT_MAX_B64 = 60_000
VIEWPORT = {"width": 1280, "height": 900}
SKIPPED_RESOURCES = ("image", "media", "font")
# Hop-by-hop / identity headers never forwarded from the page to the guard: the
# guard owns Host, Cookie (the identity's jar, passed explicitly), Authorization
# (the session), Content-Length and the User-Agent.
_DROP_REQ = {"host", "cookie", "authorization", "content-length", "connection",
             "user-agent", "accept-encoding", "proxy-authorization", "te",
             "upgrade", "keep-alive", "transfer-encoding"}
_DROP_RESP = {"content-length", "transfer-encoding", "connection", "keep-alive"}
ACTION_KINDS = ("click", "fill", "select", "press", "check", "submit", "script",
                "back", "wait", "goto")
IDENTITY_DEFAULT = "default"
LIB_DIR_ENV = "VIGILO_GREYBOX_BROWSER_LIB_DIR"


# A redirect answered to the browser: in scope it becomes a new navigation (which
# is routed and scope-checked again); out of scope it stops here, visibly.
_REDIRECT_SHIM = ("<!doctype html><meta name=vigilo-redirect>"
                  "<script>location.replace({target})</script>")
_BLOCKED_PAGE = ("<!doctype html><title>Blocked by assessment scope</title>"
                 "<p id=vigilo-blocked>The target answered {status} and redirected to "
                 "{host}, which is outside the authorised scope. The assessment did "
                 "not follow it.</p>")


class BrowserUnavailable(RuntimeError):
    """Playwright (or a usable browser) is not installed on this worker."""


@functools.lru_cache(maxsize=1)
def _headless_available() -> bool:
    """Is Playwright importable? A spec lookup, not an import: the knowledge builder
    asks on every cycle and importing Playwright costs ~0.5 s."""
    import importlib.util
    try:
        return importlib.util.find_spec("playwright.async_api") is not None
    except (ImportError, ValueError):
        return False


def available() -> bool:
    """Cheap capability probe (import only; never launches a browser)."""
    return _headless_available()


def _clean_url(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))[:500]


def _same_origin(url: str, base: str) -> bool:
    a, b = urlsplit(url), urlsplit(base)
    return (a.scheme, a.hostname, a.port or (443 if a.scheme == "https" else 80)) == \
           (b.scheme, b.hostname, b.port or (443 if b.scheme == "https" else 80))


def _is_idp_url(url: str, scope) -> bool:
    """An identity provider (well-known SSO host or a host the operator declared
    the target redirects to) rather than the application."""
    from src.greybox_web.authboundary import looks_like_identity_provider
    return looks_like_identity_provider(url) or scope.declared_redirect(url)


# --------------------------------------------------------------------- call state


@dataclass
class _Call:
    """What one browser call observed (filled by the route handler)."""

    requests: list[dict[str, Any]] = field(default_factory=list)
    blocked: list[dict[str, Any]] = field(default_factory=list)
    skipped: int = 0
    websockets: list[str] = field(default_factory=list)
    console: list[str] = field(default_factory=list)
    exchange_ids: list[int] = field(default_factory=list)
    navigations: list[dict[str, Any]] = field(default_factory=list)
    idp: str | None = None
    budget_error: BaseException | None = None


# --------------------------------------------------------------------- the driver


class BrowserSession:
    """One headless Chromium per run; one context (cookie jar) per identity."""

    def __init__(self) -> None:
        self._pw = None
        self._browser = None
        self._contexts: dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def _ensure_browser(self):
        if self._browser is not None:
            return self._browser
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()
        env = None
        libdir = os.environ.get(LIB_DIR_ENV)
        if libdir:
            # extra shared libraries for hosts without the system packages
            env = {**os.environ, "LD_LIBRARY_PATH": ":".join(
                p for p in (libdir, os.environ.get("LD_LIBRARY_PATH")) if p)}
        self._browser = await self._pw.chromium.launch(
            headless=True, env=env,
            # Fail-closed network: everything is answered by the route handler; a
            # request that escaped it resolves nowhere and reaches a dead proxy.
            proxy={"server": "http://127.0.0.1:9"},
            args=["--host-resolver-rules=MAP * ~NOTFOUND",
                  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                  "--disable-background-networking", "--disable-component-update",
                  "--disable-default-apps", "--disable-sync", "--no-first-run",
                  "--disable-domain-reliability", "--dns-prefetch-disable",
                  "--disable-features=Translate,MediaRouter,NetworkPrediction"])
        return self._browser

    async def context(self, identity: str, cookie_header: str | None, base_url: str,
                      jar: list[dict] | None = None):
        """The context for ``identity``, created on first use with its cookies (a
        persisted jar from before a resume wins over the plain cookie header)."""
        async with self._lock:
            ctx = self._contexts.get(identity)
            if ctx is not None:
                return ctx
            browser = await self._ensure_browser()
            ctx = await browser.new_context(
                viewport=VIEWPORT, java_script_enabled=True, accept_downloads=False,
                ignore_https_errors=False, service_workers="block")
            ctx.set_default_timeout(10_000)
            ctx.set_default_navigation_timeout(20_000)
            if jar:
                try:
                    await ctx.add_cookies([{k: v for k, v in c.items()
                                            if v is not None} for c in jar])
                    cookie_header = None
                except Exception:                       # noqa: BLE001 — malformed jar
                    pass
            if cookie_header:
                host = urlsplit(base_url).hostname or ""
                cookies = []
                for part in cookie_header.split(";"):
                    name, _, value = part.strip().partition("=")
                    if name:
                        cookies.append({"name": name, "value": value, "path": "/",
                                        "domain": host})
                if cookies:
                    await ctx.add_cookies(cookies)
            self._contexts[identity] = ctx
            return ctx

    async def discard(self, identity: str) -> None:
        """Forget ``identity``'s context after one of its pages would not close (a
        wedged renderer). The next call recreates it from the persisted jar; closing
        the old one is bounded so it can never hang the caller."""
        async with self._lock:
            ctx = self._contexts.pop(identity, None)
        if ctx is not None:
            try:
                await asyncio.wait_for(ctx.close(), timeout=PAGE_CLOSE_TIMEOUT_S)
            except BaseException:                       # noqa: BLE001 — best effort
                pass

    async def close(self) -> None:
        for ctx in list(self._contexts.values()):
            try:
                await ctx.close()
            except Exception:                           # noqa: BLE001
                pass
        self._contexts.clear()
        try:
            if self._browser is not None:
                await self._browser.close()
            if self._pw is not None:
                await self._pw.stop()
        except Exception:                               # noqa: BLE001
            pass
        self._browser = self._pw = None


_SESSIONS: dict[Any, BrowserSession] = {}           # run id -> session


def session_for(ctx: ToolContext) -> BrowserSession:
    key = ctx.run_id or id(ctx.scope)
    sess = _SESSIONS.get(key)
    if sess is None:
        sess = _SESSIONS[key] = BrowserSession()
    return sess


async def close_run(run_id: Any) -> None:
    """End of a run: close its browser (called by the supervisor)."""
    sess = _SESSIONS.pop(run_id, None)
    if sess is not None:
        await sess.close()


# --------------------------------------------------------------------- routing


def _identity(ctx: ToolContext) -> tuple[str, str | None, str | None]:
    """(context key, initial cookie header, guard session label) for the call."""
    want = str(ctx.params.get("session") or "").strip()
    labels = {s.get("label") for s in ctx.http.sessions()}
    if want in ("", IDENTITY_DEFAULT, "provided-cookie"):
        if "provided-cookie" in labels:
            return "provided-cookie", ctx.http.session_cookie(None), None
        return "anon", None, "anon"
    if want == "anon":
        return "anon", None, "anon"
    if want not in labels:
        raise ValueError(f"unknown session {want!r}; known: "
                         f"{', '.join(sorted(l for l in labels if l)) or 'none'}")
    return want, ctx.http.session_cookie(want), want


def _handler(ctx: ToolContext, call: _Call, guard_session: str | None):
    """The route handler: every request the page makes, answered by the guard."""
    from src.greybox_web.netguard import (
        BudgetExhausted,
        RunCancelled,
        ScopeViolation,
        TransportFailure,
    )
    scope = ctx.scope

    async def handle(route) -> None:
        req = route.request
        url = req.url
        if url.startswith(("data:", "blob:", "about:")):
            await route.continue_()             # no network involved
            return
        if req.resource_type in SKIPPED_RESOURCES:
            call.skipped += 1
            await route.abort("blockedbyclient")
            return
        if not url.startswith(("http://", "https://")):
            call.blocked.append({"url": url[:300], "reason": "scheme_not_allowed",
                                 "resource": req.resource_type})
            await route.abort("blockedbyclient")
            return
        is_nav = req.is_navigation_request()
        decision = scope.check_url(url)
        if not decision.allowed:
            call.blocked.append({"url": _clean_url(url), "reason": decision.reason,
                                 "resource": req.resource_type,
                                 "navigation": is_nav})
            if is_nav and _is_idp_url(url, scope):
                call.idp = _clean_url(url)
            await route.abort("blockedbyclient")
            return
        if len(call.requests) >= MAX_REQUESTS_PER_CALL:
            call.blocked.append({"url": _clean_url(url), "reason": "request_cap",
                                 "resource": req.resource_type})
            await route.abort("blockedbyclient")
            return
        headers = [(k, v) for k, v in (await req.all_headers()).items()
                   if k.lower() not in _DROP_REQ and not k.startswith(":")]
        cookie = (await req.header_value("cookie")) or ""
        body = req.post_data_buffer
        try:
            # Navigations: the browser must see each redirect (it changes the
            # document's URL), so the guard does not follow them; sub-resources and
            # XHR: the guard follows in-scope hops itself (each one scope-checked
            # and recorded), because Chromium does not route a fulfilled redirect.
            resp = await ctx.http.request(
                req.method, url, headers=headers, body=body,
                content_type=await req.header_value("content-type"),
                follow=not is_nav, session=guard_session, cookie=cookie)
        except ScopeViolation as exc:
            call.blocked.append({"url": _clean_url(url), "reason": exc.reason,
                                 "resource": req.resource_type, "method": req.method})
            if exc.exchange_id is not None:
                call.exchange_ids.append(exc.exchange_id)
            await route.abort("blockedbyclient")
            return
        except TransportFailure as exc:
            call.requests.append({"method": req.method, "url": _clean_url(url),
                                  "resource": req.resource_type, "status": None,
                                  "error": exc.kind})
            await route.abort("failed")
            return
        except (BudgetExhausted, RunCancelled) as exc:
            call.budget_error = exc
            await route.abort("failed")
            return
        except ValueError as exc:               # a method the guard never sends
            call.blocked.append({"url": _clean_url(url), "reason": str(exc)[:80],
                                 "resource": req.resource_type})
            await route.abort("blockedbyclient")
            return
        call.exchange_ids.extend(i for i in (resp.exchange_ids or []) if i is not None)
        location = resp.header("location") if 300 <= resp.status < 400 else None
        if location:
            target = urljoin(url, location.strip())
            allowed = scope.check_url(target).allowed and not resp.redirect_blocked
            call.requests.append({"method": req.method, "url": _clean_url(url),
                                  "resource": req.resource_type,
                                  "status": resp.status, "navigation": is_nav,
                                  "location": _clean_url(target)[:300],
                                  "exchange_id": resp.exchange_id})
            if is_nav:
                call.navigations.append({"url": _clean_url(url), "status": resp.status,
                                         "location": _clean_url(target)})
            if not allowed:
                reason = resp.redirect_blocked or scope.check_url(target).reason \
                    or "redirect_out_of_scope"
                call.blocked.append({"url": _clean_url(target), "reason": reason,
                                     "resource": req.resource_type,
                                     "navigation": is_nav, "redirect_from":
                                     _clean_url(url)})
                if is_nav and _is_idp_url(target, scope):
                    call.idp = _clean_url(target)
                if not is_nav:
                    await route.abort("blockedbyclient")
                    return
                await route.fulfill(status=200, content_type="text/html",
                                    body=_BLOCKED_PAGE.format(
                                        status=resp.status,
                                        host=html.escape(urlsplit(target).hostname
                                                         or "?")))
                return
            # in scope: a fresh (routed, scope-checked) navigation to the target
            await route.fulfill(status=200, content_type="text/html",
                                body=_REDIRECT_SHIM.format(
                                    target=json.dumps(target).replace("</", "<\\/")))
            return
        rh = []
        decoded = True      # the guard decodes gzip/deflate; other codings stay raw
        for k, v in resp.headers:
            lk = k.lower()
            if lk == "content-encoding":
                if v.strip().lower() in ("gzip", "x-gzip", "deflate"):
                    continue
                decoded = False
            if lk in _DROP_RESP:
                continue
            rh.append((k, v))
        ct = resp.header("content-type") or ""
        entry = {"method": req.method, "url": _clean_url(url),
                 "resource": req.resource_type, "status": resp.status,
                 "content_type": ct[:100], "exchange_id": resp.exchange_id,
                 "navigation": is_nav, "truncated": bool(resp.truncated)}
        if body:
            entry["post_data"] = body[:600].decode("utf-8", "replace")
            entry["request_content_type"] = (await req.header_value("content-type")
                                             or "")[:100]
        call.requests.append(entry)
        if is_nav:
            call.navigations.append({"url": _clean_url(url), "status": resp.status,
                                     "location": entry.get("location")})
        # Playwright wants a dict; repeated headers (Set-Cookie) are newline-joined
        merged: dict[str, str] = {}
        for k, v in rh:
            merged[k] = f"{merged[k]}\n{v}" if k in merged else v
        _ = decoded
        await route.fulfill(status=resp.status, headers=merged, body=resp.body or b"")

    return handle


async def _ws_refuse(ws_route, call: _Call) -> None:
    """WebSockets are not proxied by the guarded client: never connected, always
    reported (a coverage limitation, not a silent bypass)."""
    call.websockets.append(_clean_url(ws_route.url.replace("ws", "http", 1)))
    try:
        await ws_route.close(code=1008, reason="not permitted by the assessment policy")
    except Exception:                                   # noqa: BLE001
        pass


async def _page(ctx: ToolContext, call: _Call):
    identity, cookie, guard_session = _identity(ctx)
    sess = session_for(ctx)
    bctx = await sess.context(identity, cookie, ctx.base_url,
                              ctx.http.jar(identity) if hasattr(ctx.http, "jar")
                              else None)
    page = await bctx.new_page()
    await page.route("**/*", _handler(ctx, call, guard_session))
    try:
        await page.route_web_socket("**/*", lambda ws: _ws_refuse(ws, call))
    except AttributeError:                             # Playwright < 1.48
        pass
    page.on("console", lambda m: call.console.append(f"{m.type}: {(m.text or '')[:300]}")
            if len(call.console) < 40 else None)
    page.on("pageerror", lambda e: call.console.append(f"pageerror: {str(e)[:300]}")
            if len(call.console) < 40 else None)
    page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
    page.on("popup", lambda p: asyncio.ensure_future(p.close()))
    return page, identity


async def _close_page(page, ctx: ToolContext, identity: str) -> None:
    """Close a call's page within :data:`PAGE_CLOSE_TIMEOUT_S`. Runs in ``finally``
    blocks, including when the supervisor's per-tool timeout cancels the call: an
    unbounded close there would make that timeout hang too. A page that will not
    close takes its identity's context with it."""
    try:
        await asyncio.wait_for(page.close(), timeout=PAGE_CLOSE_TIMEOUT_S)
    except Exception:                                   # noqa: BLE001 — incl. timeout
        log.warning("browser page did not close in %ss; discarding the %s context",
                    PAGE_CLOSE_TIMEOUT_S, identity)
        await session_for(ctx).discard(identity)


async def _protect_jar(page, ctx: ToolContext | None = None,
                       identity: str | None = None) -> None:
    """Every cookie the identity's jar holds is a secret: register the values for
    redaction before anything this call observed (text, script results, console) is
    stored or shown to the model; then hand the jar to the run so it survives a
    resume (encrypted, sessionvault.py)."""
    from src.greybox_web import redaction
    try:
        cookies = await page.context.cookies()
    except Exception:                                   # noqa: BLE001
        return
    for c in cookies:
        value = str(c.get("value") or "")
        if len(value) >= 8:
            redaction.register_secret(value)
    if ctx is not None and identity and hasattr(ctx.http, "remember_jar"):
        ctx.http.remember_jar(identity, cookies)


async def _settle(page, wait_ms: int) -> None:
    await page.wait_for_timeout(max(0, min(wait_ms, 5000)))
    try:
        await page.wait_for_load_state("networkidle", timeout=3000)
    except Exception:                                   # noqa: BLE001 — still busy
        pass


async def _snapshot(page) -> dict[str, Any]:
    out: dict[str, Any] = {"final_url": _clean_url(page.url)}
    try:
        out["title"] = (await page.title() or "")[:200]
    except Exception:                                   # noqa: BLE001
        out["title"] = ""
    try:
        out["text"] = (await page.inner_text("body"))[:MAX_TEXT] \
            if await page.locator("body").count() else ""
    except Exception:                                   # noqa: BLE001
        out["text"] = ""
    out["dom"] = await _dom_outline(page)
    out["links"] = await _links(page)
    out["forms"] = await _forms(page)
    out["storage"] = await _storage_keys(page)
    return out


async def _dom_outline(page) -> str:
    try:
        return (await page.evaluate("""() => {
            const lines = [];
            const walk = (el, depth) => {
              if (!el || lines.length > 120 || depth > 5) return;
              const tag = el.tagName.toLowerCase();
              if (['script','style','svg','path','noscript'].includes(tag)) return;
              const id = el.id ? '#' + el.id : '';
              const cls = (el.className && typeof el.className === 'string')
                ? '.' + el.className.trim().split(/\\s+/).slice(0,3).join('.') : '';
              const attrs = ['name','type','href','role','data-testid','aria-label']
                .map(a => el.getAttribute(a) ? ` ${a}=${el.getAttribute(a).slice(0,60)}` : '')
                .join('');
              const own = Array.from(el.childNodes).filter(n => n.nodeType === 3)
                .map(n => n.textContent.trim()).join(' ').slice(0, 80);
              lines.push('  '.repeat(depth) + tag + id + cls + attrs + (own ? ' :: ' + own : ''));
              for (const c of el.children) walk(c, depth + 1);
            };
            walk(document.body, 0);
            return lines.join('\\n');
        }"""))[:5000]
    except Exception:                                   # noqa: BLE001
        return ""


async def _links(page) -> list[str]:
    try:
        return [h for h in await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href).slice(0, 200)") if isinstance(h, str)]
    except Exception:                                   # noqa: BLE001
        return []


async def _forms(page) -> list[dict[str, Any]]:
    try:
        return await page.evaluate("""() => Array.from(document.forms).slice(0, 10).map(f => ({
            action: f.action || '', method: (f.getAttribute('method') || 'GET').toUpperCase(),
            fields: Array.from(f.elements).filter(e => e.name).slice(0, 25).map(e => ({
              name: e.name, type: (e.type || 'text').toLowerCase()}))}))""")
    except Exception:                                   # noqa: BLE001
        return []


async def _storage_keys(page) -> dict[str, list[str]]:
    """localStorage/sessionStorage KEY names (never values): where client state lives."""
    try:
        return await page.evaluate("""() => ({
            local: Object.keys(window.localStorage || {}).slice(0, 30),
            session: Object.keys(window.sessionStorage || {}).slice(0, 30)})""")
    except Exception:                                   # noqa: BLE001
        return {"local": [], "session": []}


# --------------------------------------------------------------------- results


def _json_keys(body: str) -> list[str]:
    try:
        doc = json.loads(body)
    except ValueError:
        return []
    return [str(k)[:60] for k in doc][:20] if isinstance(doc, dict) else []


def _requests_to_pages(base_url: str, scope, requests: list[dict[str, Any]]
                       ) -> tuple[list[PageInfo], list[str]]:
    """Same-origin XHR/fetch/document requests become endpoints (with the method,
    status and the parameter names their query/JSON/form bodies carry)."""
    pages: dict[tuple[str, str], PageInfo] = {}
    frontier: list[str] = []
    for r in requests:
        url = str(r.get("url") or "")
        if not url or not scope.check_url(url).allowed or not _same_origin(url, base_url):
            continue
        resource = str(r.get("resource") or "")
        if resource not in ("xhr", "fetch", "document", "script", "other"):
            continue
        method = str(r.get("method") or "GET").upper()
        p = pages.get((url, method))
        if p is None:
            p = pages[(url, method)] = PageInfo(
                url=url, status=r.get("status"), content_type=r.get("content_type"),
                fetched=False,
                exchange_ids=[r["exchange_id"]] if r.get("exchange_id") else [])
        src = f"browser:{resource}"
        p.data.setdefault("source", [])
        if src not in p.data["source"]:
            p.data["source"].append(src)
        if method not in (p.data.get("methods") or []):
            p.data["methods"] = [*(p.data.get("methods") or []), method]
        if resource in ("xhr", "fetch"):
            p.data["api"] = True
        if r.get("content_type"):
            p.data["content_type"] = str(r["content_type"])[:100]
        if r.get("status") and r["status"] not in (p.data.get("status_codes") or []):
            p.data["status_codes"] = [*(p.data.get("status_codes") or []), r["status"]]
        body = r.get("post_data") or ""
        rct = str(r.get("request_content_type") or "")
        if body:
            names = _json_keys(body) if "json" in rct or body.lstrip().startswith("{") \
                else [k for k, _ in parse_qsl(body)][:20]
            loc = "form"
            for n in names:
                if all(x.name != n for x in p.params):
                    p.params.append(ParamInfo(loc, n, {"method": method, "url": url,
                                                       "body": "json" if "json" in rct
                                                       else "form",
                                                       "source": "browser"}))
            p.data.setdefault("observed_bodies", [])
            if len(p.data["observed_bodies"]) < 3:
                p.data["observed_bodies"].append(body[:400])
        if resource == "document" and method == "GET" and r.get("status") == 200 \
                and url not in frontier:
            frontier.append(url)
    return list(pages.values()), frontier


def _result(ctx: ToolContext, tool: str, start: str, call: _Call, snap: dict,
            identity: str, extra: dict | None = None,
            started: float = 0.0) -> ToolResult:
    """Pages, frontier, observation and the authentication state of one call."""
    from src.greybox_web.tools.discovery import _http_link, strip_fragment
    scope = ctx.scope
    final = snap.get("final_url") or start
    pages, frontier = _requests_to_pages(ctx.base_url, scope, call.requests)
    page = PageInfo(url=_clean_url(start), status=(call.navigations[0]["status"]
                                                   if call.navigations else None),
                    content_type="text/html", fetched=True,
                    exchange_ids=call.exchange_ids[:20])
    page.data.update({"final_url": final, "title": snap.get("title"),
                      "rendered": True})
    if final != _clean_url(start):
        page.redirect_to = final
        page.redirected_from = _clean_url(start)
    for href in snap.get("links") or []:
        link = _http_link(final, href)
        if link and scope.check_url(link).allowed and link not in page.links:
            page.links.append(link)
            if link not in frontier:
                frontier.append(link)
    for form in snap.get("forms") or []:
        action = _http_link(final, form.get("action") or final) or final
        fields = [f for f in form.get("fields") or [] if f.get("name")]
        if not fields or not scope.check_url(action).allowed:
            continue
        method = "POST" if form.get("method") == "POST" else "GET"
        target = PageInfo(url=strip_fragment(action), fetched=False)
        target.data["methods"] = [method]
        target.data["forms"] = [{"method": method,
                                 "fields": sorted(f["name"] for f in fields)}]
        if any(f.get("type") == "password" for f in fields):
            target.data["login_form"] = {
                "method": method,
                "user_field": next((f["name"] for f in fields
                                    if f.get("type") in ("text", "email")), None),
                "password_field": next(f["name"] for f in fields
                                       if f.get("type") == "password"),
                "fields": {f["name"]: "" for f in fields}}
        for f in fields:
            if f.get("type") != "password":
                target.params.append(ParamInfo(
                    "form" if method == "POST" else "query", f["name"],
                    {"method": method, "url": target.url, "type": f.get("type")}))
        pages.append(target)
    # authentication state: the run met an identity provider, or a login screen
    # stood where the application should be
    auth: dict[str, Any] | None = None
    if call.idp:
        auth = {"state": "identity_provider",
                "provider": urlsplit(call.idp).hostname, "url": _clean_url(start),
                "detail": f"navigation to {call.idp} (identity {identity}) was "
                          f"stopped at the scope boundary"}
    elif any(t.get("login_form") for t in (p.data for p in pages)) \
            and identity != "anon" and _same_origin(final, ctx.base_url) \
            and final != _clean_url(start):
        auth = {"state": "login_required", "url": _clean_url(start),
                "detail": f"identity {identity} was sent to a login form at {final}"}
    if auth and auth["state"] == "identity_provider":
        page.data["auth_state"] = auth
    api = sorted({p.url for p in pages if p.data.get("api")})
    facts = {"identity": identity, "final_url": final, "title": snap.get("title"),
             "requests": len(call.requests), "api_calls": api[:20],
             "blocked": call.blocked[:10], "skipped_static": call.skipped,
             "websockets_refused": call.websockets[:5],
             "console": call.console[:8], "storage_keys": snap.get("storage"),
             "text_excerpt": (snap.get("text") or "")[:800],
             "dom_outline": (snap.get("dom") or "")[:1500],
             "ms": int((time.monotonic() - started) * 1000) if started else None,
             **({"auth": auth} if auth else {}), **(extra or {})}
    obs = Observation(key=f"{tool}|{identity}|{_clean_url(start)}|"
                          f"{len(call.requests)}"[:300],
                      label=(f"{tool} ({identity}): {_clean_url(start)} → {final}"
                             + (f" — {snap.get('title')}" if snap.get("title") else "")),
                      facts=facts, url=_clean_url(start),
                      exchange_ids=call.exchange_ids[:50])
    summary = (f"{tool} as {identity}: {_clean_url(start)}"
               + (f" → {final}" if final != _clean_url(start) else "")
               + f"; {len(call.requests)} requests, {len(api)} API call(s), "
               f"{len(frontier)} URL(s)"
               + (f", {len(call.blocked)} blocked" if call.blocked else "")
               + (f", {len(call.websockets)} websocket(s) refused"
                  if call.websockets else "")
               + (f"; AUTH: {auth['state']}" if auth else ""))
    if call.budget_error is not None:
        raise call.budget_error
    return ToolResult(summary=summary[:400],
                      counts={"requests": len(call.requests), "api": len(api),
                              "blocked": len(call.blocked), "new_urls": len(frontier)},
                      pages=[page, *pages], observations=[obs],
                      frontier=sorted(set(frontier))[:60])


def _unavailable(tool: str, url: str) -> ToolResult:
    return ToolResult(summary=f"{tool}: the browser capability is not installed on "
                              f"this worker",
                      observations=[Observation(
                          key=f"browser.unavailable|{_clean_url(url)}"[:300],
                          label="browser unavailable (Playwright not installed)",
                          facts={"available": False}, url=url)])


# --------------------------------------------------------------------- tools


async def visit(ctx: ToolContext) -> ToolResult:
    """``browser.visit {url, wait_ms?, timeout_s?, session?}``."""
    url = str(ctx.params.get("url") or ctx.base_url)
    if not ctx.scope.check_url(url).allowed:
        return ToolResult(summary=f"refused {url}: outside the run's scope")
    if not available():
        return _unavailable("browser.visit", url)
    call = _Call()
    started = time.monotonic()
    page, identity = await _page(ctx, call)
    try:
        error = None
        try:
            await asyncio.wait_for(page.goto(url, wait_until="domcontentloaded"),
                                   timeout=float(ctx.params.get("timeout_s") or 30))
        except Exception as exc:                        # noqa: BLE001
            error = f"{type(exc).__name__}: {str(exc)[:160]}"
        if error is None:
            await _settle(page, int(ctx.params.get("wait_ms") or 1200))
        await _protect_jar(page, ctx, identity)
        snap = await _snapshot(page)
    finally:
        await _close_page(page, ctx, identity)
    return _result(ctx, "browser.visit", url, call, snap, identity,
                   {"error": error} if error else None, started)


async def act(ctx: ToolContext) -> ToolResult:
    """``browser.act {url?, actions[{kind, selector?, value?}], session?}``."""
    url = str(ctx.params.get("url") or ctx.base_url)
    actions = ctx.params.get("actions") or []
    if isinstance(actions, dict):
        actions = [actions]
    if not actions and ctx.params.get("selector"):
        actions = [{"kind": "click", "selector": ctx.params["selector"],
                    "value": ctx.params.get("value")}]
    if not isinstance(actions, list) or not actions:
        return ToolResult(summary="browser.act needs at least one action")
    bad = [str(a.get("kind")) for a in actions
           if not isinstance(a, dict) or a.get("kind", "click") not in ACTION_KINDS]
    if bad:
        # an unsupported option is a loud refusal, never "nothing happened" (F4)
        return ToolResult(summary=f"browser.act: unsupported action kind(s) "
                                  f"{', '.join(bad)}; allowed: {', '.join(ACTION_KINDS)}")
    if not ctx.scope.check_url(url).allowed:
        return ToolResult(summary=f"refused {url}: outside the run's scope")
    if not available():
        return _unavailable("browser.act", url)
    call = _Call()
    started = time.monotonic()
    page, identity = await _page(ctx, call)
    done: list[str] = []
    try:
        try:
            await page.goto(url, wait_until="domcontentloaded")
            await _settle(page, 600)
        except Exception as exc:                        # noqa: BLE001
            done.append(f"navigation failed: {type(exc).__name__}")
        before = len(call.requests)
        for a in actions[:MAX_ACTIONS]:
            kind = str(a.get("kind") or "click")
            sel = str(a.get("selector") or "")
            val = a.get("value")
            n0 = len(call.requests)
            try:
                if kind == "click":
                    await page.click(sel, timeout=5000)
                elif kind == "fill":
                    await page.fill(sel, str(val or ""), timeout=5000)
                elif kind == "select":
                    await page.select_option(sel, str(val or ""), timeout=5000)
                elif kind == "press":
                    await page.press(sel or "body", str(val or "Enter"), timeout=5000)
                elif kind == "check":
                    await page.check(sel, timeout=5000)
                elif kind == "submit":
                    await page.eval_on_selector(
                        sel or "form", "f => f.requestSubmit ? f.requestSubmit() "
                                       ": f.submit()")
                elif kind == "script":
                    res = await page.evaluate(str(val or "")[:2000])
                    done.append(f"script -> {json.dumps(res, default=str)[:400]}")
                elif kind == "back":
                    await page.go_back()
                elif kind == "wait":
                    await page.wait_for_timeout(min(int(val or 500), 5000))
                elif kind == "goto":
                    target = str(val or sel)
                    if not ctx.scope.check_url(target).allowed:
                        done.append(f"goto {target} refused: outside the scope")
                        continue
                    await page.goto(target, wait_until="domcontentloaded")
                await _settle(page, 400)
                if kind != "script":
                    new = [r["method"] + " " + urlsplit(r["url"]).path
                           for r in call.requests[n0:]
                           if r.get("resource") in ("xhr", "fetch", "document")]
                    done.append(f"{kind} {sel or val or ''}".strip()
                                + (f" -> {', '.join(new[:4])}" if new else
                                   " -> no request"))
            except Exception as exc:                    # noqa: BLE001 — one may fail
                done.append(f"{kind} {sel} failed: {type(exc).__name__}: "
                            f"{str(exc).splitlines()[0][:140]}")
        await _protect_jar(page, ctx, identity)
        snap = await _snapshot(page)
    finally:
        await _close_page(page, ctx, identity)
    return _result(ctx, "browser.act", url, call, snap, identity,
                   {"actions": done, "requests_from_actions":
                    len(call.requests) - before}, started)


async def cookies(ctx: ToolContext) -> ToolResult:
    """``browser.cookies {session?}``: names and flags only, never values."""
    if not available():
        return _unavailable("browser.cookies", ctx.base_url)
    identity, cookie, _ = _identity(ctx)
    bctx = await session_for(ctx).context(identity, cookie, ctx.base_url)
    rows = [{"name": c.get("name"), "domain": c.get("domain"), "path": c.get("path"),
             "httpOnly": c.get("httpOnly"), "secure": c.get("secure"),
             "sameSite": c.get("sameSite"),
             "session_cookie": (c.get("expires") or -1) < 0}
            for c in await bctx.cookies()][:60]
    weak = [c["name"] for c in rows if not c.get("secure") or not c.get("httpOnly")]
    obs = Observation(key=f"browser.cookies|{identity}|{len(rows)}"[:300],
                      label=f"browser ({identity}) holds {len(rows)} cookie(s)",
                      facts={"identity": identity, "cookies": rows, "weak": weak})
    return ToolResult(summary=f"browser cookies ({identity}): {len(rows)} "
                              f"({len(weak)} without Secure/HttpOnly)",
                      counts={"cookies": len(rows)}, observations=[obs])


async def screenshot(ctx: ToolContext) -> ToolResult:
    """``browser.screenshot {url?, session?}``: a JPEG of the rendered page, stored
    as an artifact row in the run's audited traffic (scheme ``browser``)."""
    url = str(ctx.params.get("url") or ctx.base_url)
    if not ctx.scope.check_url(url).allowed:
        return ToolResult(summary=f"refused {url}: outside the run's scope")
    if not available():
        return _unavailable("browser.screenshot", url)
    call = _Call()
    page, identity = await _page(ctx, call)
    try:
        await page.goto(url, wait_until="domcontentloaded")
        await _settle(page, 800)
        data = b""
        for quality in (45, 25, 12):
            data = await page.screenshot(type="jpeg", quality=quality, full_page=False)
            if len(base64.b64encode(data)) <= SCREENSHOT_MAX_B64:
                break
        snap = await _snapshot(page)
    finally:
        await _close_page(page, ctx, identity)
    b64 = base64.b64encode(data).decode()
    stored = len(b64) <= SCREENSHOT_MAX_B64
    xid = await ctx.http.artifact(
        "SCREENSHOT", snap.get("final_url") or url,
        b64 if stored else None, "text/x-vigilo-jpeg-base64")
    res = _result(ctx, "browser.screenshot", url, call, snap, identity,
                  {"screenshot": {"sha256": hashlib.sha256(data).hexdigest(),
                                  "bytes": len(data), "stored": stored,
                                  "artifact_exchange_id": xid}})
    return res


TOOLS = ("browser.visit", "browser.act", "browser.cookies", "browser.screenshot")


def capability_ok(spec_id: str) -> str | None:
    return modes.BROWSER if spec_id in TOOLS else None
