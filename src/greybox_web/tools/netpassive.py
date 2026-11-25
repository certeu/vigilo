"""Passive network/infrastructure signals as tool results.

Two entry points, neither of which performs a request:

* :func:`build_parts` turns the :class:`~src.greybox_web.netview.PageSignals` of a page
  the discovery tools just fetched into observations (exploration graph), assets and
  edges (third-party origins, edge providers, leaked hosts and addresses) and passive
  findings.
* :func:`reexamine` is the passive follow-up tool the planner schedules from a lead
  ("which other recorded responses leak this host / load this origin?"). It reads the
  run's own recorded exchanges through ``ctx.recorded``.

Third-party and internal values are only RECORDED: they become out-of-scope assets, never
a request (T12). Every string is target-derived and is redacted when stored.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from src.greybox_web import netview
from src.greybox_web.graph import url_keys
from src.greybox_web.tools import (
    AssetSpec,
    EdgeSpec,
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    excerpt,
)

MAX_FINDINGS_PER_PAGE = 10
MAX_REEXAMINE = 300          # recorded responses inspected by one follow-up
# What a passive follow-up can look for. Admission validates the option against this
# tuple, so an unsupported ``kind`` is refused with a reason instead of being answered
# with "nothing to re-examine" (which reads exactly like a clean result).
REEXAMINE_KINDS: tuple[str, ...] = ("leak", "origin", "url", "body")


def _ip_key(value: str) -> str:
    return f"ip:[{value}]" if ":" in value else f"ip:{value}"


def _leak_evidence(headers, body, leak) -> tuple[str, str]:
    if leak["where"].startswith("header:"):
        name = leak["where"].split(":", 1)[1]
        for k, v in headers or []:
            if str(k).lower() == name and leak["value"] in str(v).lower():
                return f"{k}: {str(v)[:300]}", "header"
        return f"{name}: …{leak['value']}…", "header"
    return excerpt(body or "", leak["value"], 160), "body"


def _asset_for_leak(leak, endpoint: str) -> tuple[AssetSpec, EdgeSpec]:
    where = leak["where"][:48]
    data = {"internal": bool(leak["internal"]),
            "lead": {"source": "leak", "from": endpoint, "where": where}}
    if leak["kind"] == "hostname":
        spec = AssetSpec("host", leak["value"], False, leak["value"], data)
        return spec, EdgeSpec("leaks", ("endpoint", endpoint), ("host", spec.key))
    spec = AssetSpec("ip", _ip_key(leak["value"]), False, leak["value"], data)
    return spec, EdgeSpec("leaks", ("endpoint", endpoint), ("ip", spec.key))


def build_parts(url: str, sig: netview.PageSignals, *, headers: list, body: str | None,
                exchange_id: int | None, only_leak: str | None = None,
                only_origin: str | None = None) -> ToolResult:
    """Observations, assets, edges and findings for one analysed response. ``only_*``
    restrict the output to one leaked value / one origin (follow-up tool)."""
    keys = url_keys(url)
    res = ToolResult(summary="")
    if keys is None:
        return res
    ek, sk = keys.endpoint, keys.service
    ex_ids = [exchange_id] if exchange_id else []
    path = keys.path

    # --- supply chain: third-party origins, SRI, mixed content
    by_host: dict[str, list[dict]] = {}
    for r in ([] if only_leak else sig.resources):
        if only_origin and r["host"] != only_origin:
            continue
        by_host.setdefault(r["host"], []).append(r)
    n_find = 0
    for host in sorted(by_host):
        rs = by_host[host]
        tp = [r for r in rs if r["tp"]]
        if tp:
            kinds = sorted({r["kind"] for r in tp})
            scripts = [r for r in tp if r["kind"] == "script"]
            nosri = [r for r in scripts if not r["sri"]]
            res.observations.append(Observation(
                key=netview.obs_key("third_party", ek, host),
                label=f"Third-party origin {host} loaded by {path}", url=url,
                exchange_ids=ex_ids,
                facts={"origin": host, "kinds": kinds, "references": len(tp),
                       "scripts": len(scripts), "scripts_without_sri": len(nosri),
                       "requested": False}))
            src = {"script": "script_src", "style": "style_src", "frame": "frame_src"}
            res.assets.append(AssetSpec(
                "host", host, False, host,
                {"third_party": True, "lead": {"source": src.get(kinds[0], "resource_src"),
                                                "from": sk}}))
            res.edges.append(EdgeSpec("depends_on", ("service", sk), ("host", host)))
            if nosri:
                res.observations.append(Observation(
                    key=netview.obs_key("no_sri", ek, host),
                    label=f"{len(nosri)} script(s) from {host} without SRI on {path}",
                    url=url, exchange_ids=ex_ids,
                    facts={"origin": host, "scripts_without_sri": len(nosri)}))
            for r in nosri:
                if n_find >= MAX_FINDINGS_PER_PAGE:
                    break
                n_find += 1
                res.findings.append(FindingSpec(
                    check_id="supply.no_sri", detail=r["url"][:200],
                    title=f"Third-party script without Subresource Integrity ({host})",
                    severity="low", confidence="high",
                    description=(
                        f"The page loads a script from {host}, which is outside the "
                        "tested scope, without an integrity attribute. If that origin "
                        "is compromised the script can change without the page owner "
                        "noticing. The URL was only recorded, never requested."),
                    url=url, asset_url=url, cwe="CWE-829",
                    observation_key=netview.obs_key("no_sri", ek, host),
                    evidence=[Evidence("proof", exchange_id, r["raw"] or r["url"],
                                       "script tag as served")],
                    passive={"check": "supply.no_sri", "exchange_id": exchange_id,
                             "url": r["url"]}))
        for r in rs:
            if not r["mixed"] or n_find >= MAX_FINDINGS_PER_PAGE:
                continue
            n_find += 1
            res.observations.append(Observation(
                key=netview.obs_key("mixed", ek, r["url"][:120]),
                label=f"Mixed content ({r['mixed']}): http {r['kind']} on {path}",
                url=url, exchange_ids=ex_ids,
                facts={"resource": r["url"][:200], "class": r["mixed"], "kind": r["kind"]}))
            res.findings.append(FindingSpec(
                check_id="supply.mixed_content", detail=r["url"][:200],
                title=f"Mixed content: http:// {r['kind']} loaded by an https page",
                severity="medium" if r["mixed"] == "active" else "low",
                confidence="high",
                description=(
                    f"An https page references a {r['kind']} over plain http "
                    f"({r['mixed']} mixed content). A network attacker can read or, "
                    "for active content, modify it. The URL was only recorded, never "
                    "requested."),
                url=url, asset_url=url, cwe="CWE-319",
                observation_key=netview.obs_key("mixed", ek, r["url"][:120]),
                evidence=[Evidence("proof", exchange_id, r["raw"] or r["url"],
                                   "reference as served")],
                passive={"check": "supply.mixed_content", "exchange_id": exchange_id,
                         "url": r["url"]}))

    # --- internal hostnames and addresses
    if only_origin is None:
        for leak in sig.leaks:
            if only_leak and leak["value"] != only_leak:
                continue
            spec, edge = _asset_for_leak(leak, ek)
            res.assets.append(spec)
            res.edges.append(edge)
            res.observations.append(Observation(
                key=netview.obs_key("leak", ek, leak["value"]),
                label=f"{'Internal' if leak['internal'] else 'Upstream'} {leak['kind']} "
                      f"{leak['value']} leaked in {leak['where']} of {path}",
                url=url, exchange_ids=ex_ids,
                facts={"value": leak["value"], "kind": leak["kind"],
                       "where": leak["where"], "internal": leak["internal"],
                       "requested": False}))
        internal = [lk for lk in sig.leaks if lk["internal"]
                    and (not only_leak or lk["value"] == only_leak)]
        if internal and n_find < MAX_FINDINGS_PER_PAGE:
            # one finding per response: the disclosure is ONE issue of this page,
            # however many internal names it lists (each is in the description and
            # the observations above)
            n_find += 1
            rank = {"high": 2, "medium": 1, "low": 0}
            internal.sort(key=lambda lk: -rank.get(lk["confidence"], 0))
            first = internal[0]
            evidence = []
            for lk in internal[:8]:
                ev, where = _leak_evidence(headers, body, lk)
                evidence.append(Evidence("proof", exchange_id, ev,
                                         f"{lk['value']} in the {lk['where']} of the "
                                         "recorded response"))
            names = ", ".join(sorted({lk["value"] for lk in internal}))
            kinds = sorted({lk["kind"] for lk in internal})
            res.findings.append(FindingSpec(
                check_id="info.leak", detail=f"page|{path}",
                title=(f"Internal {first['kind']} disclosed: {first['value']}"
                       if len(internal) == 1 else
                       f"{len(internal)} internal {'/'.join(kinds)} values disclosed "
                       f"by {path}"),
                severity="low", confidence=first["confidence"],
                description=(
                    f"The response discloses internal {'/'.join(kinds)} values "
                    f"({names[:600]}) in its "
                    f"{', '.join(sorted({lk['where'] for lk in internal}))}. Internal "
                    "names and addresses help an attacker map the network behind the "
                    "service. The values were only recorded, never contacted."),
                url=url, asset_url=url, cwe="CWE-200",
                observation_key=netview.obs_key("leak", ek, first["value"]),
                evidence=evidence,
                passive={"check": "info.leak", "exchange_id": exchange_id,
                         "value": first["value"]}))

    # --- edge / CDN / WAF
    if only_origin is None and only_leak is None:
        for e in sig.edge:
            info = netview.provider_info(e["vendor"]) or {}
            key = f"provider:{e['vendor']}"
            res.assets.append(AssetSpec(
                "provider", key, False, info.get("name", e["vendor"]),
                {"vendor": e["vendor"], "kind": e["kind"], "confidence": e["confidence"]}))
            res.edges.append(EdgeSpec("fronted_by", ("service", sk), ("provider", key)))
            res.observations.append(Observation(
                key=netview.obs_key("edge", ek, e["vendor"]),
                label=f"{info.get('name', e['vendor'])} ({e['kind']}) in front of {sk}",
                url=url, exchange_ids=ex_ids,
                facts={"vendor": e["vendor"], "kind": e["kind"],
                       "confidence": e["confidence"], "signals": e["signals"],
                       "block_page": e["blocked"]}))
        # --- redirects to another host
        r = sig.redirect
        if r:
            res.observations.append(Observation(
                key=netview.obs_key("redirect", ek, r["to"]),
                label=f"{path} redirects to {r['to']}"
                      + (" (https to http)" if r["downgrade"] else ""),
                url=url, exchange_ids=ex_ids,
                facts={"to": r["to"], "in_scope": r["in_scope"],
                       "downgrade": r["downgrade"], "ip_literal": r["ip"],
                       "status": r["status"]}))
            if not r["in_scope"]:
                res.assets.append(AssetSpec(
                    "host", r["to"], False, r["to"],
                    {"lead": {"source": "redirect", "from": sk}}))
                res.edges.append(EdgeSpec("redirects_to", ("service", sk),
                                          ("host", r["to"])))
    return res


def merge_parts(into: ToolResult, part: ToolResult) -> None:
    seen = {o.key for o in into.observations}
    into.observations += [o for o in part.observations if o.key not in seen]
    have = {(a.kind, a.key) for a in into.assets}
    into.assets += [a for a in part.assets if (a.kind, a.key) not in have]
    have_e = {(e.rel, e.src, e.dst) for e in into.edges}
    into.edges += [e for e in part.edges if (e.rel, e.src, e.dst) not in have_e]
    have_f = {(f.check_id, f.asset_url, f.detail) for f in into.findings}
    into.findings += [f for f in part.findings
                      if (f.check_id, f.asset_url, f.detail) not in have_f]


# ------------------------------------------------------------------ follow-up tool


async def reexamine(ctx: ToolContext) -> ToolResult:
    """Passive follow-up of a lead: look through every response the run recorded (also
    those fetched by the check tools, which the crawl does not analyse) for one leaked
    value (``kind=leak``), third-party origin (``kind=origin``), URL fragment
    (``kind=url``), or response-body marker (``kind=body``). Leak/origin findings are
    created only for responses not already reported; URL/body searches only return
    bounded, attributed matches for further investigation."""
    from src.greybox_web.tools.discovery import parse_html
    kind = str(ctx.params.get("kind") or "")
    needle = str(ctx.params.get("needle") or "")[:200].lower()
    out = ToolResult(summary="")
    recorded = ctx.recorded
    if kind not in REEXAMINE_KINDS:
        # admission validates this too; reaching it means a caller bypassed it
        raise ValueError(f"unsupported kind {kind!r}; supported: "
                         f"{', '.join(REEXAMINE_KINDS)}")
    if recorded is None or not needle:
        out.summary = ("nothing to re-examine: no needle given" if not needle
                       else "nothing to re-examine: no recorded traffic")
        return out
    rows = await recorded.responses(MAX_REEXAMINE)
    matched: list[str] = []
    matching_excerpts: list[dict[str, object]] = []
    for row in rows:
        if row.status is None:
            continue
        if kind == "url":
            if needle in row.url.lower():
                matched.append(row.url)
                matching_excerpts.append({"exchange_id": row.id, "url": row.url})
            continue
        if not row.body and not row.headers:
            continue
        ct = row.content_type or ""
        raws = parse_html(row.body or "").resources if "html" in ct.lower() and row.body \
            else []
        if kind in ("url", "body"):
            value = row.url if kind == "url" else row.body or ""
            if needle in value.lower():
                matched.append(row.url)
                matching_excerpts.append({"exchange_id": row.id, "url": row.url,
                                          "excerpt": excerpt(value, needle)})
            continue
        sig = netview.analyse(row.url, row.status, row.headers, row.body, ct, raws,
                              ctx.scope.host_allowed)
        part = build_parts(row.url, sig, headers=row.headers, body=row.body,
                           exchange_id=row.id,
                           only_leak=needle if kind == "leak" else None,
                           only_origin=needle if kind == "origin" else None)
        if part.findings or part.assets:
            keys = url_keys(row.url)
            matched.append(keys.path if keys else urlsplit(row.url).path)
            merge_parts(out, part)
    pages = sorted(set(matched))
    out.observations.append(Observation(
        key=f"net.reexamine|{kind}|{needle}"[:300],
        label=f"Re-examined {len(rows)} recorded responses for {needle}: "
              f"{len(pages)} mention it",
        facts={"kind": kind, "needle": needle, "responses": len(rows),
               "matching_pages": pages[:20], "matches": matching_excerpts[:20],
               "requested": False},
        exchange_ids=[row.id for row in rows
                      if (kind == "url" and needle in row.url.lower())
                      or (kind == "body" and needle in (row.body or "").lower())][:20]))
    out.summary = (f"re-examined {len(rows)} recorded responses for {needle}: "
                   f"{len(pages)} mention it, {len(out.findings)} finding(s)")
    out.counts = {"responses": len(rows), "matches": len(pages)}
    return out
