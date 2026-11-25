"""Discovery tools: fetch_root, robots, sitemap and a bounded BFS crawl.

Links are parsed with the stdlib ``html.parser``. Out-of-scope or excluded URLs found
in content are returned as unfetched pages (recorded as out-of-scope assets) and are
never requested: target content cannot expand the scope (T12).
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from src.greybox_web.assetclass import classify_path, is_static_like
from src.greybox_web import authboundary, coverage, netview, redaction
from src.greybox_web.graph import url_keys
from src.greybox_web.netguard import HttpResponse, ScopeViolation, TransportFailure
from src.greybox_web.tools import Observation, PageInfo, ParamInfo, ToolContext, ToolResult
from src.greybox_web.tools import netpassive

ERROR_SIGNATURES = (
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"Exception in thread|java\.lang\.\w+Exception"),
    re.compile(r"(?i)Werkzeug Debugger|Django Version:|Whoops! There was an error"),
    re.compile(r"(?i)<b>(?:Fatal error|Warning)</b>:.* on line <b>\d+</b>"),
)
LOGIN_HINT = re.compile(r"(?i)log ?in|sign ?in|auth")

# Request-header echo probe (batch E): every discovery page fetch carries this
# marker header. A page that echoes the marker value back into its HTML records
# the header name on the endpoint (``header_reflect_hint``) — a reflection the
# built-in tools cannot test (injection.* address query/form parameters only);
# the knowledge surfaces it so the agent can compose a dynamic instrument for it.
# The value is inert, identifies Vigilo's own traffic, and carries raw angle
# brackets so an HTML-ESCAPED echo does not match it — only an unencoded
# reflection records the hint (same principle as the injection canary).
ECHO_PROBE_HEADER = "X-Note-Name"


# JSON envelope probe (Phase 3): a JSON body whose top level carries a nested
# object under one of these keys (and a version/driver-looking value inside it) is
# a developer-facing envelope. No built-in check decides that: headers.*, cookies.*
# and exposure.* look at the wire and at well-known paths, not at data shape. The
# knowledge surfaces the hint and the agent writes the analyser for it.
_ENVELOPE_KEYS = ("meta", "_meta", "debug", "_debug", "system", "diagnostics")
_DEVELOPER_VALUE = re.compile(
    r"(?i)(postgres|mysql|mariadb|sqlite|mssql|oracle|mongodb|redis|"
    r"django|rails|spring|express|fastapi|node|php|\d+\.\d+\.\d+)")


def json_envelope_hints(resp: HttpResponse) -> dict[str, Any]:
    """Developer-facing JSON envelope signals for one response ({} when none).

    Only the SHAPE is recorded (keys, a boolean per signal) — never the values,
    which may be sensitive and belong in the report, not in the model's context."""
    ct = (resp.header("content-type") or "").lower()
    if "json" not in ct or not resp.body:
        return {}
    try:
        doc = json.loads(resp.text)
    except ValueError:
        return {}
    if not isinstance(doc, dict):
        return {}
    out: dict[str, Any] = {"keys": sorted(str(k) for k in doc)[:12]}
    for key in _ENVELOPE_KEYS:
        meta = doc.get(key)
        if isinstance(meta, dict) and meta:
            out["developer_meta"] = key
            out["meta_keys"] = sorted(str(k) for k in meta)[:10]
            if any(isinstance(v, str) and _DEVELOPER_VALUE.search(v)
                   for v in meta.values()):
                out["meta_versions"] = True
            break
    # A response that lists internal paths or hosts is an inventory leak no
    # built-in check reads either (it is data, not a header or a path).
    for key in ("routes", "endpoints", "internal_hosts", "debug"):
        if isinstance(doc.get(key), (list, dict)) and doc.get(key):
            out.setdefault("inventory_key", key)
            break
    if set(out) <= {"keys"}:
        out.pop("keys", None)
    return out


def echo_marker() -> str:
    """A fresh marker value for one fetch."""
    return f"vigilo{ToolContext.token()}<e>"


def record_echo_hint(page: PageInfo, resp: HttpResponse, marker: str) -> None:
    """Record the header-echo hint when the marker value came back in the HTML."""
    if resp.is_html and marker in resp.text:
        page.data["header_reflect_hint"] = ECHO_PROBE_HEADER


def error_signature(text: str) -> str | None:
    for rx in ERROR_SIGNATURES:
        m = rx.search(text or "")
        if m:
            return m.group(0)[:120]
    return None


def service_root(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "/", "", ""))


def strip_fragment(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        # Sub-resources for the supply-chain view (script, stylesheet, img, iframe,
        # source, preload): RECORDED only, never requested or crawled by this path.
        self.resources: list[dict] = []
        self._form: dict | None = None

    def _resource(self, tag: str, a: dict) -> None:
        url = a.get("src") or (a.get("href") if tag == "link" else "")
        if not url and tag == "source":
            url = (a.get("srcset") or "").split(",")[0].split()[0] if a.get("srcset") else ""
        if not url or len(self.resources) >= 200:
            return
        rel = (a.get("rel") or "").lower()
        if tag == "link" and not any(x in rel for x in ("stylesheet", "preload",
                                                        "modulepreload")):
            return
        self.resources.append({
            "tag": tag, "url": url[:500], "rel": rel[:60], "as": (a.get("as") or "")[:20],
            "integrity": bool((a.get("integrity") or "").strip()),
            "crossorigin": a.get("crossorigin") if "crossorigin" in a else None,
            "raw": (self.get_starttag_text() or "")[:240]})

    def handle_starttag(self, tag: str, attrs) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "link", "img", "iframe", "frame", "source", "video",
                   "audio", "track"):
            self._resource(tag, a)
        if tag in ("a", "link", "area") and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "iframe", "frame") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "GET").upper(), "fields": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select", "button") and self._form is not None:
            if a.get("name"):
                self._form["fields"].append({
                    "name": a["name"][:100],
                    "type": (a.get("type") or ("text" if tag != "button" else "submit"))
                    .lower()[:20],
                    "value": a.get("value", "")[:200]})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def parse_html(text: str) -> _Extractor:
    ex = _Extractor()
    try:
        ex.feed(text[:1024 * 1024])
        ex.close()
    except Exception:   # malformed markup: keep what was parsed
        pass
    return ex


def _http_link(base: str, href: str) -> str | None:
    href = href.strip()
    if not href or href.startswith(("#", "javascript:", "mailto:", "data:", "tel:")):
        return None
    url = strip_fragment(urljoin(base, href))
    return url if urlsplit(url).scheme in ("http", "https") else None


def _page_from_response(url: str, resp: HttpResponse) -> PageInfo:
    page = PageInfo(url=url, status=resp.status, content_type=resp.header("content-type"),
                    fetched=True, exchange_ids=list(resp.exchange_ids),
                    redirected_from=url if resp.url != url else None)
    page.data["status_codes"] = [resp.status]
    page.data["methods"] = ["GET"]
    # The response we actually got, when the request was redirected (defect F2): the
    # body belongs to ``resp.url``, never to the URL that was asked for.
    if resp.url != url:
        page.data["final_url"] = resp.url
        page.data["redirect_chain"] = list(getattr(resp, "hops", ()) or [])[:6]
    if getattr(resp, "redirect_blocked", None):
        page.data["redirect_blocked"] = resp.redirect_blocked
    # A redirect the operator declared as intentional (an SSO provider): recorded as
    # what it is -- the target hands the client to another party -- never as an
    # application page and never as a finding about this application.

    if resp.header("content-type"):
        page.data["content_type"] = resp.header("content-type")[:100]
    if resp.header("server"):
        page.data["server"] = resp.header("server")[:100]
    if resp.header_all("set-cookie"):
        page.data["sets_cookies"] = True
        page.data["cookie_names"] = sorted({c.split("=", 1)[0].strip()[:64]
                                            for c in resp.header_all("set-cookie")})
    if resp.url != url:
        page.redirect_to = resp.url
    hints = json_envelope_hints(resp)
    if hints:
        page.data.update(hints)
    return page


def url_query_params(url: str) -> list[ParamInfo]:
    """Query parameters declared in a URL's query string, regardless of whether
    the URL was fetched (used for sitemap entries and links). Static assets and media
    (``/favicon.ico?favicon.0b3bf435.ico``) carry cache-busters, not parameters."""
    out: list[ParamInfo] = []
    if is_static_like(classify_path(url)):
        return out
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if not name or len(name) > 100 or any(p.name == name for p in out):
            continue
        out.append(ParamInfo("query", name, {"sample": value[:200], "method": "GET",
                                             "url": url}))
    return out


def _query_params(url: str, body: str) -> list[ParamInfo]:
    out: list[ParamInfo] = []
    if is_static_like(classify_path(url)):
        return out                         # a cache-buster is not a parameter
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if not name or len(name) > 100 or any(p.name == name for p in out):
            continue
        reflected = len(value) >= 3 and value in body
        out.append(ParamInfo("query", name, {"sample": value[:200], "method": "GET",
                                             "url": url, "echoed": reflected}))
    return out


def record_declared_redirect(page: PageInfo, url: str, final: str, scope) -> None:
    """Note a redirect to a host the operator declared (an identity provider).

    Called both when the hop was recorded-and-refused (the default) and when the
    client returned it as the response's final URL."""
    if scope is None or final == url:
        return
    try:
        declared = scope.declared_redirect(final)
    except Exception:                                  # noqa: BLE001 — old scopes
        declared = False
    if declared:
        page.data["declared_redirect"] = final
        page.data["auth_state"] = {
            "state": coverage.AUTH_IDP,
            "provider": urlsplit(final).hostname,
            "detail": ("the target redirects to a host the operator declared as an "
                       "identity provider; it was not followed"),
            "declared": True}


def analyse_page(url: str, resp: HttpResponse, scope=None
                 ) -> tuple[PageInfo, list[PageInfo]]:
    """The fetched page plus the form-action pages it declares. With ``scope``, the
    passive network signals of the response (third-party resources, mixed content,
    internal leaks, edge attribution) are computed and kept on ``page.signals``; their
    compact form is stored in ``page.data``."""
    page = _page_from_response(url, resp)
    text = resp.text if resp.body else ""
    page.params = _query_params(url, text)
    sig = error_signature(text)
    if sig:
        page.data["error_signature"] = sig
    extra: list[PageInfo] = []
    raws: list[dict] = []
    if resp.is_html:
        ex = parse_html(text)
        raws = ex.resources
        base = resp.url
        for href in ex.links:
            link = _http_link(base, href)
            if link and link not in page.links:
                page.links.append(link)
        for form in ex.forms:
            action = _http_link(base, form["action"] or base) or base
            fields = [f for f in form["fields"] if f["type"] not in ("submit", "button",
                                                                      "reset", "image")]
            if not fields:
                continue
            method = form["method"] if form["method"] in ("GET", "POST") else "GET"
            # Hidden csrf tokens and other sensitive defaults are masked by name
            # before they can reach any persisted asset or param data.
            defaults = redaction.mask_fields({f["name"]: f["value"] for f in fields})
            target = PageInfo(url=strip_fragment(action.split("?")[0]
                                                 if method == "POST" else action))
            target.data["methods"] = [method]
            target.data["forms"] = [{"method": method, "fields": sorted(defaults)}]
            if any(f["type"] == "password" for f in fields):
                user = next((f["name"] for f in fields if f["type"] in ("text", "email")),
                            None)
                pwd = next(f["name"] for f in fields if f["type"] == "password")
                target.data["login_form"] = {"user_field": user, "password_field": pwd,
                                             "fields": defaults, "method": method}
            for f in fields:
                if f["type"] == "hidden" and re.search(r"(?i)csrf|token", f["name"]):
                    continue
                target.params.append(ParamInfo("form" if method == "POST" else "query",
                                               f["name"], {
                    "sample": f["value"] or "test", "method": method,
                    "url": target.url, "fields": defaults, "type": f["type"]}))
            page.links.append(target.url)
            extra.append(target)
    # Sub-resources the page declares (scripts, stylesheets, images, frames): they are
    # discovery material, not noise. Same-origin scripts become part of the frontier
    # (the JS/JSON extractor reads them); third-party ones are recorded as supply
    # chain signals by the passive analyser below.
    resources: list[str] = []
    for raw in raws[:60]:
        link = _http_link(resp.url, raw.get("url") or "")
        if link and link not in resources:
            resources.append(link)
    page.resources = resources
    # Was this actually the application, or an identity provider / login screen?
    state = auth_state_of(resp, url, scope)
    if state.state != coverage.AUTH_UNKNOWN:
        page.data["auth_state"] = state.as_dict()
    final = resp.url
    if getattr(resp, "redirect_blocked", None) == "declared_redirect":
        # the client stopped at the boundary: the Location header names the provider
        final = resp.header("location") or resp.url
    record_declared_redirect(page, url, final, scope)
    if scope is not None:
        psig = netview.analyse(
            resp.url, resp.status, resp.headers, text, resp.content_type, raws,
            scope.host_allowed, followed_to=resp.url if resp.url != url else None)
        page.signals = psig
        page.data.update(psig.page_data())
    if page.data.get("auth_state") and not page.data.get("final_url"):
        # a refused hop is not the response's URL: keep the provenance explicit
        page.data["final_url"] = resp.url
    return page, extra


def auth_state_of(resp: HttpResponse, url: str, scope=None) -> coverage.AuthState:
    """The authentication verdict for one response (defect F5).

    The redirect chain is the strongest signal (it is where an expired session
    announces itself); a refused hop to a declared or out-of-scope host counts too,
    because a target that redirects every page somewhere else has not answered.
    """
    chain = [str(h) for h in (getattr(resp, "hops", ()) or ())]
    final = resp.url
    if getattr(resp, "redirect_blocked", None):
        location = resp.header("location")
        if location:
            chain.append(urljoin(final, location))
    return authboundary.detect(
        requested_url=url, final_url=final, chain=chain,
        body=resp.text[:200_000] if resp.body else None, status=resp.status,
        base_host=urlsplit(url).hostname)


def script_urls(page: PageInfo, scope, base_url: str) -> list[str]:
    """The same-origin scripts of a fetched page, in scope: material for the JS
    extractor (``tools/jsintel``). Nothing is requested here."""
    from src.greybox_web.jsintel import looks_like_javascript
    base = urlsplit(base_url)
    out: list[str] = []
    for res in page.resources or []:
        if not looks_like_javascript(res):
            continue
        if not scope.check_url(res).allowed:
            continue
        out.append(res)
    # same-origin only: a bundle served by a CDN is supply chain, not the app's code
    base_host = (base.hostname or "").lower()
    return [u for u in out if (urlsplit(u).hostname or "").lower() == base_host][:12]


def _add_passive(into: ToolResult, page: PageInfo, resp: HttpResponse) -> None:
    """Observations, assets, edges and passive findings from the page's network signals
    (third-party origins, mixed content, internal leaks, edge provider, redirects)."""
    if page.signals is None:
        return
    part = netpassive.build_parts(
        page.url, page.signals, headers=resp.headers,
        body=resp.text if resp.body else None, exchange_id=resp.exchange_id)
    netpassive.merge_parts(into, part)


async def _get(ctx: ToolContext, url: str) -> HttpResponse | None:
    try:
        return await ctx.http.get(url)
    except TransportFailure as exc:
        # A redirect the operator declared (an SSO provider): the target answered, it
        # just handed the client to somebody else. That answer is evidence (status,
        # Location), not a transport error.
        return exc.response
    except ScopeViolation:
        return None


async def fetch_root(ctx: ToolContext) -> ToolResult:
    url = ctx.params.get("url") or ctx.base_url
    marker = echo_marker()
    try:
        resp = await ctx.http.get(url, headers=[(ECHO_PROBE_HEADER, marker)])
    except TransportFailure as exc:
        if exc.response is None:
            raise
        resp = exc.response    # declared redirect: the answer is the redirect
    # failures propagate: the target is unreachable
    page, extra = analyse_page(url, resp, ctx.scope)
    record_echo_hint(page, resp, marker)
    obs = Observation(
        key=f"discovery.fetch_root|{url}", label=f"Root {urlsplit(url).path or '/'} "
        f"answered {resp.status}", url=url, exchange_ids=resp.exchange_ids,
        facts={"status": resp.status, "content_type": resp.header("content-type"),
               "server": resp.header("server"), "links": len(page.links)})
    post_only = {e.url for e in extra if e.data.get("methods") == ["POST"]}
    frontier = [link for link in page.links
                if link not in post_only and ctx.http.in_scope(link)]
    result = ToolResult(summary=f"GET {url} -> {resp.status}, {len(page.links)} links",
                        counts={"status": resp.status, "links": len(page.links)},
                        pages=[page, *extra], observations=[obs], frontier=frontier)
    _add_passive(result, page, resp)
    return result


def _in_scope_page(ctx: ToolContext, url: str, source: str) -> PageInfo:
    page = PageInfo(url=url)
    page.data["source"] = [source]
    return page


async def robots(ctx: ToolContext) -> ToolResult:
    root = service_root(ctx.params.get("url") or ctx.base_url)
    url = urljoin(root, "/robots.txt")
    resp = await _get(ctx, url)
    pages: list[PageInfo] = []
    if resp is not None and resp.status == 200 and not resp.is_html:
        for line in resp.text.splitlines()[:500]:
            key, _, value = line.partition(":")
            value = value.split("#", 1)[0].strip()
            if key.strip().lower() in ("disallow", "allow") and value.startswith("/"):
                path = value.replace("*", "").split("$", 1)[0] or "/"
                pages.append(_in_scope_page(ctx, urljoin(root, path), "robots.txt"))
            elif key.strip().lower() == "sitemap" and value:
                link = _http_link(root, value)
                if link:
                    pages.append(_in_scope_page(ctx, link, "robots.txt"))
    status = resp.status if resp is not None else None
    obs = Observation(key=f"discovery.robots|{url}",
                      label=f"robots.txt: {len(pages)} paths", url=url,
                      exchange_ids=resp.exchange_ids if resp else [],
                      facts={"status": status, "paths": [p.url for p in pages][:50]})
    return ToolResult(summary=f"robots.txt -> {status}, {len(pages)} paths",
                      counts={"paths": len(pages)}, pages=pages, observations=[obs],
                      frontier=[p.url for p in pages if ctx.http.in_scope(p.url)])


_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


async def sitemap(ctx: ToolContext) -> ToolResult:
    root = service_root(ctx.params.get("url") or ctx.base_url)
    url = urljoin(root, "/sitemap.xml")
    resp = await _get(ctx, url)
    pages: list[PageInfo] = []
    if resp is not None and resp.status == 200:
        for loc in _LOC.findall(resp.text)[:500]:
            link = _http_link(root, loc)
            if link:
                pages.append(_in_scope_page(ctx, link, "sitemap.xml"))
    status = resp.status if resp is not None else None
    obs = Observation(key=f"discovery.sitemap|{url}",
                      label=f"sitemap.xml: {len(pages)} URLs", url=url,
                      exchange_ids=resp.exchange_ids if resp else [],
                      facts={"status": status, "urls": [p.url for p in pages][:50]})
    return ToolResult(summary=f"sitemap.xml -> {status}, {len(pages)} URLs",
                      counts={"urls": len(pages)}, pages=pages, observations=[obs],
                      frontier=[p.url for p in pages if ctx.http.in_scope(p.url)])


def visit_key(url: str) -> str:
    k = url_keys(url)
    names = sorted({n for n, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})
    return f"{k.endpoint if k else url}?{'&'.join(names)}"


async def crawl(ctx: ToolContext) -> ToolResult:
    """One crawl *batch*: fetch the given frontier URLs (``params.seeds``),
    at most ``params.max_pages`` (and never more than the run's
    ``max_pages``), and return the pages plus the new in-scope links as
    ``ToolResult.frontier`` for the planner to schedule. Links are not followed inside
    the batch, so every batch's discoveries are projected, checked and orderable as soon
    as it ends. The page limit is enforced here and again at admission."""
    run_cap = int(ctx.limits.get("max_pages", 2000))
    seeds = list(ctx.params.get("seeds") or []) or [ctx.base_url]
    cap = max(0, min(int(ctx.params.get("max_pages") or len(seeds)), run_cap))
    pages: dict[str, PageInfo] = {}
    observations: list[Observation] = []
    passive = ToolResult(summary="")
    frontier: set[str] = set()
    fetched = skipped = failed = 0

    def merge(into: PageInfo, other: PageInfo) -> None:
        into.params += [x for x in other.params
                        if all(x.name != y.name or x.location != y.location
                               for y in into.params)]
        for k, v in other.data.items():
            cur = into.data.get(k)
            if isinstance(cur, list) and isinstance(v, list):
                into.data[k] = cur + [x for x in v if x not in cur]
            else:
                into.data.setdefault(k, v)

    def keep(p: PageInfo) -> None:
        old = pages.get(p.url)
        if old is None:
            pages[p.url] = p
        elif p.fetched and not old.fetched:
            merge(p, old)
            pages[p.url] = p
        else:
            merge(old, p)

    for url in seeds:
        if fetched >= cap:
            frontier.add(url)                  # not fetched: give back
            continue
        if not ctx.http.in_scope(url):
            skipped += 1
            keep(PageInfo(url=url))
            continue
        marker = echo_marker()
        try:
            resp = await ctx.http.get(url, headers=[(ECHO_PROBE_HEADER, marker)])
        except ScopeViolation:
            skipped += 1
            continue
        except TransportFailure as exc:
            if exc.response is None:
                failed += 1
                continue
            resp = exc.response          # declared redirect: still an answer
        fetched += 1
        page, extra = analyse_page(url, resp, ctx.scope)
        record_echo_hint(page, resp, marker)
        _add_passive(passive, page, resp)
        keep(page)
        for e in extra:
            keep(e)
        observations.append(Observation(
            key=f"discovery.crawl|{url}", label=f"GET {urlsplit(url).path or '/'} -> "
            f"{resp.status}" + (f", {len(page.params)} params" if page.params else ""),
            url=url, exchange_ids=resp.exchange_ids,
            facts={"status": resp.status, "links": len(page.links),
                   "params": [p.name for p in page.params],
                   "forms": len(extra), "redirect_to": page.redirect_to}))
        post_only = {e.url for e in extra if e.data.get("methods") == ["POST"]}
        for link in page.links:
            if link in post_only or not ctx.http.in_scope(link):
                continue   # POST-only form action: never crawled with GET
            frontier.add(link)
    out = list(pages.values())
    return ToolResult(
        summary=f"crawled {fetched} pages, {len(out)} endpoints, "
                f"{sum(len(p.params) for p in out)} parameters, "
                f"{len(frontier)} URLs on the frontier"
                + (f", {skipped} out of scope (not requested)" if skipped else ""),
        counts={"fetched": fetched, "endpoints": len(out), "out_of_scope": skipped,
                "failed": failed, "params": sum(len(p.params) for p in out),
                "frontier": len(frontier)},
        pages=out, observations=[*observations, *passive.observations],
        findings=passive.findings, assets=passive.assets, edges=passive.edges,
        frontier=sorted(frontier))
