"""``discovery.routes``: route-template inference and static/runtime correlation.

An analysis instrument over what the run already discovered (no request): the
endpoint assets with their provenance (``script:<bundle>`` = static evidence,
``browser:<type>`` = observed at runtime, anything else = links/crawl).

* **Templates are inferences, recorded as such.** ``/api/notes/123``,
  ``/api/notes/456`` → ``/api/notes/{id}`` with the samples, the number of samples
  and a confidence (high ≥ 3 samples, medium 2, low 1 id-shaped sample). The
  observation is ``route.template|<template>`` with ``inferred: true``; the direct
  observations (the endpoint assets) are untouched.
* **Correlation.** Each template is classified by where its evidence came from:
  static only (named by code, never seen at runtime — maybe dead, maybe reachable
  only in another role), runtime only (observed but not found in the code examined),
  or both. ``route.inventory|`` summarises it for the definition of done.
"""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlsplit

from src.greybox_web.tools import Observation, ToolContext, ToolResult

_ID_PATTERNS = (
    ("{uuid}", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                          r"[0-9a-f]{12}$", re.I)),
    ("{id}", re.compile(r"^\d{1,19}$")),
    ("{hex}", re.compile(r"^[0-9a-f]{12,64}$", re.I)),
    ("{token}", re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{16,}$")),
)
MAX_TEMPLATES = 60


def _kind(segment: str) -> str | None:
    for name, rx in _ID_PATTERNS:
        if rx.match(segment):
            return name
    return None


def _origin(sources: list[str]) -> set[str]:
    out = set()
    for s in sources:
        out.add("static" if s.startswith("script:") else
                "runtime" if s.startswith("browser:") else "link")
    return out or {"link"}


def infer(endpoints: list[dict]) -> list[dict]:
    """Templates from endpoint URLs (pure; tested directly)."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in endpoints:
        p = urlsplit(e["url"])
        segs = [s for s in p.path.split("/") if s]
        if not segs:
            continue
        shape = tuple(_kind(s) or s for s in segs)
        if not any(_kind(s) for s in segs):
            continue                       # nothing parameter-shaped: not a template
        groups[(p.scheme, p.netloc, shape)].append(e)
    out = []
    for (scheme, netloc, shape), members in groups.items():
        template = "/" + "/".join(shape)
        origins: set[str] = set()
        for m in members:
            origins |= _origin(m.get("source") or [])
        n = len(members)
        correlation = ("both" if {"static", "runtime"} <= origins else
                       "runtime_only" if "runtime" in origins else
                       "static_only" if "static" in origins else "links_only")
        out.append({"template": template, "origin": f"{scheme}://{netloc}",
                    "samples": sorted(m["url"] for m in members)[:5], "count": n,
                    "confidence": "high" if n >= 3 else "medium" if n == 2 else "low",
                    "methods": sorted({x for m in members for x in m.get("methods") or []}),
                    "tested": sum(1 for m in members if m.get("tested")),
                    "evidence_origin": sorted(origins), "correlation": correlation,
                    "inferred": True})
    out.sort(key=lambda t: (-t["count"], t["template"]))
    return out[:MAX_TEMPLATES]


async def routes(ctx: ToolContext) -> ToolResult:
    if ctx.recorded is None or not hasattr(ctx.recorded, "endpoints"):
        return ToolResult(summary="discovery.routes: no discovered surface to analyse")
    eps = await ctx.recorded.endpoints()
    templates = infer(eps)
    api = [e for e in eps if urlsplit(e["url"]).path.startswith("/api")]
    origin = defaultdict(int)
    for e in api or eps:
        for o in _origin(e.get("source") or []):
            origin[o] += 1
    obs = [Observation(key=f"route.template|{t['origin']}{t['template']}"[:300],
                       label=f"inferred route {t['template']} ({t['count']} sample(s), "
                             f"{t['confidence']}; {t['correlation']})",
                       facts=t, url=t["samples"][0]) for t in templates]
    corr = defaultdict(int)
    for t in templates:
        corr[t["correlation"]] += 1
    obs.append(Observation(
        key=f"route.inventory|{len(eps)}|{len(templates)}"[:300],
        label=f"route inventory: {len(eps)} endpoint(s), {len(templates)} template(s)",
        facts={"endpoints": len(eps), "api_endpoints": len(api),
               "templates": len(templates), "endpoint_origins": dict(origin),
               "template_correlation": dict(corr),
               "untested_api": [e["url"] for e in api if not e.get("tested")][:15]}))
    return ToolResult(
        summary=(f"{len(templates)} route template(s) inferred from {len(eps)} "
                 f"endpoint(s); correlation: "
                 + (", ".join(f"{k} {v}" for k, v in sorted(corr.items())) or "none")),
        counts={"templates": len(templates), "endpoints": len(eps)},
        observations=obs)


# ------------------------------------------------------- template endpoints
# Code names routes like `/api/notes/${id}`; discovery records them as endpoints
# with a placeholder (`{id}`, percent-encoded in asset keys). No request can ever
# "test" a placeholder URL: a template is examined when a concrete instance is.
_PLACEHOLDER = re.compile(r"(\{[^/{}]*\}|%7B[^/]*?%7D|/:[A-Za-z_]\w*)", re.I)


def is_template(url: str) -> bool:
    return bool(_PLACEHOLDER.search(urlsplit(url).path))


def _instance_rx(url: str) -> re.Pattern:
    p = urlsplit(url)
    parts = _PLACEHOLDER.split(p.path)
    body = "".join("/[^/]+" if part.startswith("/:") else "[^/]+"
                   if _PLACEHOLDER.fullmatch(part) else re.escape(part)
                   for part in parts if part)
    return re.compile("^" + re.escape(f"{p.scheme}://{p.netloc}") + body + "$")


def template_coverage(endpoints: list[tuple[str, bool]]) -> dict[str, dict]:
    """For every template endpoint: concrete instances seen and tested."""
    concrete = [(k, t) for k, t in endpoints if not is_template(k)]
    out: dict[str, dict] = {}
    for key, _ in endpoints:
        if not is_template(key):
            continue
        rx = _instance_rx(key)
        inst = [(k, t) for k, t in concrete if rx.match(k.split("?", 1)[0])]
        out[key] = {"instances": len(inst), "tested": sum(1 for _, t in inst if t)}
    return out


def effectively_tested(key: str, tested: bool, coverage: dict[str, dict]) -> bool:
    """A concrete endpoint: its own flag; a template: any tested instance."""
    if key in coverage:
        return coverage[key]["tested"] > 0
    return tested


def examined_surface(endpoints: list) -> dict:
    """THE definition of examined API surface, shared by the coverage verdict and
    the agent's knowledge (they must never disagree). ``endpoints``: asset-like
    objects with ``key``, ``tested`` and ``data``. Excludes static/non-work URLs and
    endpoints that only ever answered 404/410 (guesses that missed); a template is
    examined through any tested instance."""
    from src.greybox_web.exploration.knowledge import is_work_url
    from src.greybox_web.jsintel import looks_like_api_path

    def only_missing(a) -> bool:
        codes = [str(c)[:3] for c in ((a.data or {}).get("status_codes") or [])]
        return bool(codes) and all(c in ("404", "410") for c in codes)
    live = [a for a in endpoints if is_work_url(a.key) and not only_missing(a)]
    tcov = template_coverage([(a.key, bool(a.tested)) for a in live])
    tested = [a for a in live if effectively_tested(a.key, a.tested, tcov)]
    api = [a for a in live if looks_like_api_path(a.key)]
    untested_api = [a.key for a in api if not effectively_tested(a.key, a.tested, tcov)]
    return {"endpoints": len(live), "tested": len(tested), "api": len(api),
            "api_untested": untested_api, "template_coverage": tcov}
