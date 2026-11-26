"""Verification-backed analysis of publicly served client configuration and source maps."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from src.greybox_web.tools import Evidence, FindingSpec, Observation, ToolContext, ToolResult, VerifyResult, excerpt

_SOURCE_MARKERS = re.compile(r"(?i)(?:\.internal\b|trusts?\s+(?:the\s+)?x-[a-z-]+|unreleased|staff.?impersonat|feature.?flag)")
_SECRET_KEY = re.compile(r"(?i)(?:password|secret|private.?key|admin.?key|access.?token|service.?token)")
_PUBLIC_KEY = re.compile(r"(?i)(?:public|publishable|client)")
_PLACEHOLDER = re.compile(r"(?i)^(?:|null|none|changeme|example|placeholder|<[^>]+>)$")


def _json(text: str):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _walk(value, path: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield child_path, child
            yield from _walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def classify(url: str, text: str) -> tuple[str | None, str | None]:
    doc = _json(text)
    if isinstance(doc, dict) and isinstance(doc.get("sourcesContent"), list):
        joined = "\n".join(str(v) for v in doc["sourcesContent"] if isinstance(v, str))
        marker = _SOURCE_MARKERS.search(joined)
        if marker:
            return "source_map", marker.group(0)
    if isinstance(doc, (dict, list)):
        for path, value in _walk(doc):
            leaf = path.rsplit(".", 1)[-1]
            if not _SECRET_KEY.search(leaf) or _PUBLIC_KEY.search(leaf):
                continue
            shown = str(value).strip()
            if isinstance(value, (str, int)) and not _PLACEHOLDER.match(shown) and len(shown) >= 8:
                return "secret_config", path
    return None, None


async def analyse(ctx: ToolContext) -> ToolResult:
    urls = ctx.params.get("urls") or [ctx.params.get("url")]
    if isinstance(urls, str):
        urls = [urls]
    findings = []
    observations = []
    for url in list(dict.fromkeys(str(u) for u in urls if u))[:12]:
        resp = await ctx.http.request("GET", url, session="anon", follow=False)
        kind, marker = classify(url, resp.text)
        observations.append(Observation(
            key=f"client.assets|{url}", label=f"client asset {urlsplit(url).path}: {kind or 'no sensitive exposure'}",
            facts={"kind": kind, "marker": marker, "status": resp.status},
            url=url, exchange_ids=resp.exchange_ids))
        if not kind:
            continue
        title = ("Production source map exposes non-public source details" if kind == "source_map"
                 else f"Runtime configuration exposes server-side credential field {marker}")
        description = (f"Anonymous GET {url} returned an enabled source map whose original source contains "
                       f"non-public implementation details ({marker})." if kind == "source_map" else
                       f"Anonymous GET {url} returned runtime configuration containing secret-like field "
                       f"{marker}; public or publishable keys and placeholders were excluded.")
        findings.append(FindingSpec(
            check_id="client.assets", detail=kind, title=title,
            severity="low" if kind == "source_map" else "high", confidence="high",
            description=description, url=url, asset_url=url,
            evidence=[Evidence("proof", resp.exchange_id, excerpt(resp.text, marker),
                               "anonymous response matched semantic client-asset analysis")],
            verify={"url": url, "kind": kind, "marker": marker},
            cwe="CWE-200", finding_class="misconfiguration" if kind == "source_map" else "vulnerability",
            remediation={"summary": "Remove private material from public client artifacts.",
                         "steps": ["Disable production source maps or serve them only to authorised diagnostics.",
                                   "Keep server credentials outside browser runtime configuration."],
                         "validation": ["Anonymous requests no longer return the sensitive material."],
                         "reproduction": [f"GET {url} without credentials and inspect the response."],
                         "severity_rationale": "The proof exposes non-public source or a server credential to unauthenticated clients."}))
    return ToolResult(summary=f"analysed {len(observations)} client asset(s), {len(findings)} exposure(s)",
                      counts={"analysed": len(observations), "exposed": len(findings)},
                      observations=observations, findings=findings,
                      examined=[o.url for o in observations if o.url])


async def verify(ctx: ToolContext) -> VerifyResult:
    url = str(ctx.params["url"])
    resp = await ctx.http.request("GET", url, session="anon", follow=False)
    kind, marker = classify(url, resp.text)
    wanted_kind, wanted_marker = ctx.params.get("kind"), str(ctx.params.get("marker") or "")
    confirmed = resp.status == 200 and kind == wanted_kind and marker == wanted_marker
    return VerifyResult(confirmed, "anonymous client-asset refetch",
                        f"{kind or 'no exposure'} reproduced at HTTP {resp.status}",
                        list(resp.exchange_ids or []))
