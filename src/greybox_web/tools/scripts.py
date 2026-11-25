"""``discovery.scripts``: read the application's JavaScript and JSON manifests and
turn what they name into surface (defects F1/F9).

A modern application's HTML is a shell. Its routes, its API endpoints, the parameters
those endpoints take and the identifiers they use are *string literals inside the
bundles the shell loads*. This tool fetches those bundles through the guarded client
(so: same scope, same budget, same redaction as every other request) and hands them to
:mod:`src.greybox_web.jsintel`, which extracts candidates. Every candidate that stays
under the run's base URL becomes an endpoint asset with ``source: ["script:<bundle>"]``
— ordinary surface that every check can then test.

It is a *discovery* tool: it makes no findings. It exists because reading code is not a
vulnerability check, it is how a tester finds out what to check.

Bounded: at most ``max_scripts`` bundles (default 8), each capped in size, and only
scripts that are same-origin with the base URL.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from src.greybox_web import jsintel
from src.greybox_web.graph import url_keys
from src.greybox_web.netguard import ScopeViolation, TransportFailure
from src.greybox_web.tools import Observation, PageInfo, ParamInfo, ToolContext, ToolResult
from src.greybox_web.tools.discovery import _http_link, parse_html, script_urls

MAX_SCRIPTS = 8
MAX_BYTES = 2 * 1024 * 1024


def _candidate_url(base_url: str, path: str) -> str | None:
    """A path from a bundle as an absolute URL under the base origin.

    Only same-origin candidates are returned: a bundle cannot point the assessment at
    another host, and a relative path is resolved against the application's root."""
    if path.startswith("//"):
        return None
    from urllib.parse import urlunsplit
    b = urlsplit(base_url)
    url = urlunsplit((b.scheme, b.netloc, path.split("?")[0] or "/",
                      path.split("?", 1)[1] if "?" in path else "", ""))
    return url


def _targets(ctx: ToolContext) -> tuple[list[str], list[str]]:
    """What to fetch: ``(pages, bundles)``.

    A caller naming ``scripts`` is naming *bundles* — code to read — not pages to
    parse. Treating them as pages made the tool fetch the .js, parse it as HTML and
    report "read 0 script(s)": the agent then looped on the very file that held the
    routes it was looking for (defect F-scripts). Named bundles are read directly;
    when the element looks like a page instead, it goes in as a page.
    """
    from src.greybox_web.jsintel import looks_like_javascript
    named = [str(u) for u in (ctx.params.get("scripts") or []) if u]
    bundles = [u for u in named if looks_like_javascript(u)][:MAX_SCRIPTS]
    pages = [u for u in named if not looks_like_javascript(u)][:2]
    if pages or bundles:
        return pages, bundles
    page = str(ctx.params.get("url") or ctx.base_url)
    urls = [page]
    if page.rstrip("/") != ctx.base_url.rstrip("/"):
        urls.append(ctx.base_url)
    return urls[:2], []


async def scripts(ctx: ToolContext) -> ToolResult:
    """Fetch the page, find its scripts, read them, and return the routes and API
    calls they name as endpoints."""
    seeds, named_bundles = _targets(ctx)
    limit = max(1, min(int(ctx.params.get("max_scripts") or MAX_SCRIPTS), MAX_SCRIPTS))
    pages: dict[str, PageInfo] = {}
    frontier: list[str] = []
    observations: list[Observation] = []
    intel = jsintel.Intel()
    read: list[str] = []
    failed = 0
    sources: dict[str, str] = {}          # path -> bundle it was found in
    security_candidates: list[dict[str, str]] = []

    candidates: list[str] = []
    for seed in seeds:
        try:
            resp = await ctx.http.get(seed)
        except (ScopeViolation, TransportFailure):
            failed += 1
            continue
        text = resp.text if resp.body else ""
        ex = parse_html(text) if resp.is_html else None
        page = PageInfo(url=seed, status=resp.status, fetched=True,
                        content_type=resp.header("content-type"),
                        exchange_ids=list(resp.exchange_ids),
                        redirected_from=seed if resp.url != seed else None)
        page.resources = [u for u in (_http_link(resp.url, r.get("url") or "")
                                      for r in (ex.resources if ex else [])) if u]
        if resp.url != seed:
            page.data["final_url"] = resp.url
        pages[seed] = page
        candidates.extend(script_urls(page, ctx.scope, ctx.base_url))
        # inline bundles: Next.js flight payloads and pushed RSC state live in the HTML
        if ex is not None and text:
            inline = jsintel.extract(text)
            if inline.candidates:
                jsintel.merge(intel, inline)
                for c in inline.candidates:
                    sources.setdefault(c.path, seed)

    queue = list(dict.fromkeys([*named_bundles, *candidates]))
    index = 0
    while index < len(queue) and len(read) < limit:
        url = queue[index]
        index += 1
        try:
            resp = await ctx.http.get(url, follow=False)
        except (ScopeViolation, TransportFailure):
            failed += 1
            continue
        if not resp.body or (resp.content_type and "image" in resp.content_type):
            continue
        body = resp.text[:MAX_BYTES]
        pages[url] = PageInfo(url=url, status=resp.status, fetched=True,
                              content_type=resp.header("content-type"),
                              exchange_ids=list(resp.exchange_ids))
        from src.greybox_web.tools.clientassets import classify
        security_kind, security_marker = classify(url, body)
        if security_kind:
            security_candidates.append({"url": url, "kind": security_kind,
                                        "marker": str(security_marker)})
        found = jsintel.extract(body, name=urlsplit(url).path.rsplit("/", 1)[-1])
        if found.truncated:
            failed += 0                   # still useful, just partial
        jsintel.merge(intel, found)
        for c in found.candidates:
            sources.setdefault(c.path, url)
        read.append(url)
        if found.source_map:
            sm = urljoin(url, found.source_map)
            if ctx.scope.check_url(sm).allowed and sm not in queue:
                queue.append(sm)

    # Candidates become endpoints under the base URL, with the method the call used.
    found_paths: list[tuple[str, str, str]] = []      # (url, method, kind)
    for path in intel.paths():
        url = _candidate_url(ctx.base_url, path)
        if url is None or not ctx.scope.check_url(url).allowed:
            continue
        cand = next(c for c in intel.candidates if c.path == path)
        found_paths.append((url, cand.method, cand.kind))
        key = url_keys(url)
        if key is None:
            continue
        page = pages.get(url) or PageInfo(url=url, status=None, fetched=False)
        pages[url] = page
        page.data.setdefault("source", [])
        src = f"script:{sources.get(path, '?')}"
        if src not in page.data["source"]:
            page.data["source"].append(src)
        methods = page.data.get("methods") or []
        if cand.method not in methods:
            page.data["methods"] = [*methods, cand.method]
        # query parameters the bundle declared on this path
        if "?" in path:
            from urllib.parse import parse_qsl
            for name, value in parse_qsl(path.split("?", 1)[1], keep_blank_values=True):
                if name and all(p.name != name for p in page.params):
                    page.params.append(ParamInfo("query", name,
                                                 {"sample": value[:100],
                                                  "source": "script"}))
        # body fields the bundle sends to this path: JSON literals near the call site
        for field in jsintel.body_fields("\n".join(
                c.evidence for c in intel.candidates if c.path == path)):
            if all(p.name != field for p in page.params):
                # a JSON request body is a POST form as far as the checks are
                # concerned (``injection.*`` send it as a form field)
                page.params.append(ParamInfo(
                    "form", field,
                    {"source": "script", "method": cand.method or "POST",
                     "url": page.url}))
        if cand.method == "GET" and (cand.kind in ("route",) or
                                     path.endswith((".json", ".map"))) and url not in frontier:
            frontier.append(url)

    api = [u for u, _m, k in found_paths
           if k in ("api", "graphql", "operation") or jsintel.looks_like_api_path(u)]
    obs = Observation(
        key=f"discovery.scripts|{urlsplit(ctx.base_url).netloc}"[:300],
        label=(f"read {len(read)} script(s): {len(found_paths)} paths "
               f"({len(api)} API) named in code"),
        facts={"scripts_read": [urlsplit(u).path for u in read][:10],
               "paths": [u for u, _m, _k in found_paths][:40],
               "api": api[:20], "operations": intel.operations[:10],
               "source_map": intel.source_map, "security_candidates": security_candidates[:12],
               "failed": failed},
        url=ctx.base_url)
    observations.append(obs)
    return ToolResult(
        summary=(f"read {len(read)} script(s): {len(found_paths)} paths named in code "
                 f"({len(api)} API)" if read else
                 "no same-origin script found to read"),
        counts={"scripts": len(read), "paths": len(found_paths), "api": len(api),
                "failed": failed},
        pages=list(pages.values()),
        observations=observations,
        frontier=sorted(frontier)[:40])
