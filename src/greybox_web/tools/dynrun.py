"""The generic executor for dynamic tools (batch E, "tools on demand").

A dynamic tool is a validated declarative spec (:class:`~src.greybox_web.tools.dynspec.DynTool`):
a request pattern plus verdict predicates. This module turns ONE work order into
requests through the guarded client — reusing :mod:`src.greybox_web.tools.injection`'s
payload builders so the payload floor is identical to the fixed tools (inert
canary, single appended quote, ``.invalid`` probe host never followed,
non-destructive GET/POST/HEAD/OPTIONS) — evaluates the predicates, and reports
like every tool: a FindingSpec on a positive verdict, an Observation with the
predicate outcomes always (a negative result is recorded work, not silence).

Verification (:func:`replay`) is a second, independent execution of the SAME
declarative spec: fresh probe values, fresh baseline — the verdict must reproduce.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from src.greybox_web.netguard import REDIRECT_CODES, HttpResponse
from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    VerifyResult,
    excerpt,
)
from src.greybox_web.tools.dynspec import DynInject, DynPredicate, DynTool
from src.greybox_web.tools.injection import (
    baseline_value,
    canary,
    error_indicator,
    probe_host,
    reflected_unencoded,
    with_query_param,
)

_MISSING = object()          # a json_path walk that never reached a node


def _sanitize(value: Any) -> str:
    """Header-safe text: no control characters (a CR/LF in a header name or value
    would smuggle headers)."""
    return "".join(ch for ch in str(value or "") if ch >= " " and ch != "\x7f")[:200]


@dataclass(frozen=True)
class _Point:
    """One injection point at execution time: the spec's inject with the work
    order's single-point overrides applied (``param``/``header``/``location``)."""

    into: str          # url | param | header
    key: str
    location: str      # query | form | header
    transform: str


def _points(tool: DynTool, params: dict[str, Any]) -> list[_Point]:
    """Apply the work order's param overrides. Only meaningful for a spec that
    defines exactly one injection point — several points are fixed by the spec."""
    injects: tuple[DynInject, ...] = tool.request.inject
    single = len(injects) == 1
    out: list[_Point] = []
    for inj in injects:
        key, location = inj.key, inj.location
        if single:
            if inj.into == "header" and _sanitize(params.get("header")):
                key = _sanitize(params.get("header"))
            elif inj.into == "param":
                if _sanitize(params.get("param")):
                    key = _sanitize(params.get("param"))
                if str(params.get("location") or "") in ("query", "form"):
                    location = str(params["location"])
        out.append(_Point(inj.into, key, location, inj.transform))
    return out


def _probe_value(point: _Point, token: str, url: str,
                 params: dict[str, Any]) -> str:
    """The inert payload a transform fills the point with (injection.py's floor)."""
    if point.transform == "canary":
        return canary(token)
    if point.transform == "probe_host":
        return f"https://{probe_host(token)}/"    # .invalid: never followed
    if point.transform == "append_quote":
        # the parameter's natural value with one single quote appended
        return baseline_value(url, point.key,
                              "form" if point.location == "form" else "query") + "'"
    if point.transform == "set":
        return _sanitize(params.get("value")) or "test"
    # from_param: the value the target URL already carries for that name (its
    # natural value), whatever it is — a plain GET
    return baseline_value(url, point.key, "query")


async def _send(ctx: ToolContext, tool: DynTool, url: str, points: list[_Point],
                values: list[str], *, baseline: bool = False) -> HttpResponse:
    """One request of the instrument: the work order's URL (scope-checked at
    admission, per hop by the guarded client) carrying every injection point — or,
    for a baseline fetch, the same request with each point's natural value."""
    qurl, form, headers = url, {}, []
    for point, value in zip(points, values, strict=True):
        if point.into == "header":
            if not baseline:
                headers.append((point.key, _sanitize(value)))
        elif point.location == "form":
            form[point.key] = baseline_value(url, point.key, "form") \
                if baseline else value
        else:
            qurl = with_query_param(
                qurl, point.key,
                baseline_value(url, point.key, "query") if baseline else value)
    method, follow = tool.request.method, tool.request.follow
    if method == "POST":
        return await ctx.http.post(qurl, form, headers=headers, follow=follow)
    if method == "HEAD":
        return await ctx.http.head(qurl, headers=headers, follow=follow)
    if method == "OPTIONS":
        return await ctx.http.options(qurl, headers=headers, follow=follow)
    return await ctx.http.get(qurl, headers=headers, follow=follow)


def _json_walk(text: str, path: str) -> Any:
    """Walk ``a.b.0.c`` through a parsed JSON document; ``_MISSING`` when the path
    does not resolve (or the body is not JSON)."""
    try:
        node = json.loads(text)
    except ValueError:
        return _MISSING
    for seg in path.split("."):
        if isinstance(node, dict):
            if seg not in node:
                return _MISSING
            node = node[seg]
        elif isinstance(node, list):
            if not seg.isdigit() or int(seg) >= len(node):
                return _MISSING
            node = node[int(seg)]
        else:
            return _MISSING
    return node


def _json_equals(node: Any, value: str) -> bool:
    if node is None:
        return value in ("", "null")
    if isinstance(node, bool):
        return value.lower() == ("true" if node else "false")
    return str(node) == value


def _evaluate(pred: DynPredicate, probe: HttpResponse, base: HttpResponse | None,
              tokens: dict[str, str]) -> tuple[bool, str]:
    """One predicate: ``(outcome, anchor)`` — the anchor is an excerpt anchor
    (what matched) or a short note for the evidence."""
    d, t = pred.data, pred.type
    if t == "reflection_of":
        mark = tokens.get("canary") or ""
        return reflected_unencoded(probe, mark), mark
    if t == "signature":
        matched, is_sql = error_indicator(
            probe.text, base.text if base is not None else "")
        which = d.get("which", "any")
        return (matched is not None and (which == "any" or (which == "sql") == is_sql),
                matched or "")
    if t == "body_contains":
        return d["value"] in probe.text, d["value"]
    if t == "body_regex":
        m = re.search(d["value"], probe.text)
        return m is not None, (m.group(0) if m else "")
    if t == "status_class":
        return str(probe.status)[0] == d["value"], f"HTTP {probe.status}"
    if t == "status_differs":
        base_status = f"HTTP {base.status}" if base is not None else "no baseline"
        return base is not None and probe.status != base.status, \
            f"HTTP {probe.status} vs {base_status}"
    if t == "body_differs":
        return base is not None and probe.text != base.text, ""
    if t == "header_contains":
        v = probe.header(d["name"]) or ""
        return bool(v) and d["value"] in v, f"{d['name']}: {v}"[:120]
    if t == "location_host_is":
        host = tokens.get("probe_host") or ""
        header = probe.header("location")
        target = (urlsplit(urljoin(probe.url, header)).hostname or "") if header else ""
        return probe.status in REDIRECT_CODES and target == host, \
            f"Location: {header}"[:120] if header else "no Location header"
    if t == "json_path":
        node = _json_walk(probe.text, d["path"])
        if node is _MISSING:
            return False, f"no {d['path']} in the response"
        shown = json.dumps(node, default=str)[:120]
        if d.get("op", "exists") == "exists":
            return True, shown
        return _json_equals(node, d.get("value", "")), shown
    return False, ""


async def execute(tool: DynTool, ctx: ToolContext) -> ToolResult:
    """Run the instrument once for one work order: optional baseline fetch, probe
    fetch, predicate evaluation, verdict, then the standard tool report."""
    url = str(ctx.params.get("url") or ctx.base_url).strip()
    points = _points(tool, ctx.params)
    token = ctx.token()
    values = [_probe_value(p, token, url, ctx.params) for p in points]
    tokens: dict[str, str] = {}
    for p, v in zip(points, values, strict=True):
        if p.transform == "canary":
            tokens["canary"] = v
        elif p.transform == "probe_host":
            tokens["probe_host"] = urlsplit(v).hostname or ""
    base = await _send(ctx, tool, url, points, values, baseline=True) \
        if tool.request.baseline else None
    probe = await _send(ctx, tool, url, points, values)
    outcomes = [_evaluate(pred, probe, base, tokens)
                for pred in tool.verdict.predicates]
    matched = [ok for ok, _ in outcomes]
    verdict = all(matched) if tool.verdict.mode == "all" else any(matched)

    path = urlsplit(url).path or "/"
    detail = ", ".join(f"{p.key}@{p.location}" for p in points)[:80]
    obs_key = f"{tool.id}|{url}|{detail}"[:300]
    findings: list[FindingSpec] = []
    if verdict:
        anchor = next((a for ok, a in outcomes if ok and a), "")
        proof = excerpt(probe.text, anchor) if anchor and anchor in probe.text \
            else (excerpt(probe.text) or f"HTTP {probe.status}")
        evidence = [Evidence(role="proof", exchange_id=probe.exchange_id,
                             excerpt=proof,
                             note=f"{sum(matched)}/{len(matched)} predicate(s) "
                                  f"matched ({tool.verdict.mode})")]
        if base is not None:
            evidence.append(Evidence(role="baseline", exchange_id=base.exchange_id,
                                     excerpt=f"HTTP {base.status}, "
                                             f"{len(base.text)} chars",
                                     note="the same request without the transform"))
        f = tool.finding
        findings.append(FindingSpec(
            check_id=tool.id, detail=detail, title=f.title, severity=f.severity,
            confidence=f.confidence, description=f.description,
            url=url, method=tool.request.method,
            parameter=points[0].key, param_location=points[0].location,
            asset_url=url, evidence=evidence,
            # the verify work order replays this exact spec on this exact target:
            # the work order's own params, spread into verify.<dyn id>
            verify={k: v for k, v in ctx.params.items()},
            cwe=f.cwe,
            detection_hints=([{"type": "remediation", "title": "Remediation",
                               "content": f.hint}] if f.hint else []),
            observation_key=obs_key))
    obs = Observation(
        key=obs_key,
        label=f"{tool.title[:80]}: {'matched' if verdict else 'no match'} on {path}",
        url=url,
        exchange_ids=(base.exchange_ids if base is not None else [])
        + probe.exchange_ids,
        facts={"predicates": [{"type": p.type, "ok": ok} for p, (ok, _)
                               in zip(tool.verdict.predicates, outcomes, strict=True)],
               "mode": tool.verdict.mode, "verdict": verdict,
               "injections": [f"{p.key}@{p.location}:{p.transform}" for p in points],
               "method": tool.request.method, "status": probe.status,
               "baseline_status": base.status if base is not None else None})
    return ToolResult(
        summary=f"{tool.id} on {path}: {sum(matched)}/{len(matched)} "
                f"predicate(s) matched",
        counts={"probed": 1, "baseline": 1 if base is not None else 0,
                "matched": sum(matched), "verdict": int(verdict)},
        observations=[obs], findings=findings)


async def replay(tool: DynTool, ctx: ToolContext) -> VerifyResult:
    """Verify a dynamic-tool finding: the SAME declarative spec executed again,
    with fresh probe values and a fresh baseline — the verdict must reproduce."""
    result = await execute(tool, ctx)
    ids = [i for o in result.observations for i in o.exchange_ids]
    ok = bool(result.findings)
    matched = int(result.counts.get("matched") or 0)
    note = (f"the instrument's verdict reproduced with fresh probe values "
            f"({matched}/{len(tool.verdict.predicates)} predicates matched)"
            if ok else
            f"the instrument's verdict did not reproduce this time "
            f"({matched}/{len(tool.verdict.predicates)} predicates matched)")
    exc = result.findings[0].evidence[0].excerpt if result.findings else ""
    return VerifyResult(confirmed=ok, method="replayed declarative spec",
                        note=note, exchange_ids=ids, excerpt=exc[:1000])
