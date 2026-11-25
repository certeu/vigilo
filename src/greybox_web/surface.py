"""Live network / attack-surface analysis of the asset graph.

Derived ONLY from what the run already observed: the stored (redacted) exchanges, the
endpoint assets and the findings. It never makes a request. After every projected tool
result the services (and their endpoints) touched by that work order are recomputed
from scratch and ``data.surface`` is rewritten when it changed, so the result is a pure
function of the recorded evidence (deterministic, idempotent, order-independent).

``surface.updated`` events are coalesced: at most one per asset per second; keys that
changed in between are merged into the next event (and flushed at the end of the run).

Everything stored is redacted (``GraphTx.set_surface`` -> ``events.cap_data``), and the
target-derived strings (banners, cookie names, paths) are length-bounded here.
"""
from __future__ import annotations

import re
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import assetclass, events, netview
from src.greybox_web.graph import GraphTx, url_keys
from src.greybox_web.models import GreyboxAsset, GreyboxFinding, GreyboxHttpExchange, GreyboxRun
from src.greybox_web.scope import normalise_path

EMIT_INTERVAL_S = 1.0
MAX_LIST = 10                      # bounded lists inside data.surface

# Headers evaluated on each service. HSTS: https services only.
SECURITY_HEADERS = ("content-security-policy", "x-content-type-options",
                    "x-frame-options", "referrer-policy", "strict-transport-security")

# (regex on the normalised, lower-cased path, reason)
SENSITIVE_PATHS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(rx), why) for rx, why in (
        (r"^/\.git(/|$)", "git repository"),
        (r"^/\.svn(/|$)", "svn repository"),
        (r"^/\.hg(/|$)", "mercurial repository"),
        (r"(^|/)\.env(\.[a-z0-9_-]+)?$", "environment file"),
        (r"(^|/)\.ht(access|passwd)$", "web server access file"),
        (r"(^|/)\.ds_store$", "directory metadata file"),
        (r"\.(bak|old|orig|save|swp|sql|dump|tar|tgz|zip|gz|7z|rar)$",
         "backup or archive file"),
        (r"~$", "editor backup file"),
        (r"^/(admin|administrator|wp-admin|manager|phpmyadmin|adminer|console)(/|$)",
         "administrative interface"),
        (r"^/(phpinfo|info)\.php$", "diagnostic page"),
        (r"^/(server-status|server-info|actuator|debug|_profiler|trace)(/|$)",
         "diagnostic endpoint"),
        (r"^/(config|configuration|settings)\.(php|json|ya?ml|xml|ini)$",
         "configuration file"),
        (r"^/(backup|backups|dump|dumps)(/|$)", "backup location"),
    ))
AUTH_PATH = re.compile(r"(?i)^/(login|logon|signin|sign-in|auth|sso|wp-login\.php|"
                       r"user/login|account/login)(/|$)")

_BANNER = re.compile(r"^([A-Za-z][A-Za-z0-9 _.\-]{0,38}?)\s*/\s*v?([0-9][0-9A-Za-z.\-+_]*)")
_COOKIE_TECH = (("phpsessid", "PHP"), ("jsessionid", "Java"),
                ("asp.net_sessionid", "ASP.NET"), ("laravel_session", "Laravel"),
                ("connect.sid", "Node.js"), ("csrftoken", "Django"),
                ("_rails", "Ruby on Rails"), ("ci_session", "CodeIgniter"))
_PATH_TECH = ((re.compile(r"\.php$"), "PHP"), (re.compile(r"\.aspx?$"), "ASP.NET"),
              (re.compile(r"\.jsp$"), "Java"), (re.compile(r"^/wp-(admin|content|login)"),
                                                "WordPress"))

# ------------------------------------------------------------------ risk score
RISK_FORMULA = (
    "risk_score = min(100, sum of: missing security headers 3 each (max 15); version "
    "banner 8; cookie flag gaps 2 each (max 12); CORS reflection with credentials 20 "
    "(reflection alone 8, wildcard with credentials 10); plain http 10 (+5 when a login "
    "endpoint exists); sensitive endpoints 12 each when served with 2xx else 4 "
    "(max 30); login endpoints 3 each (max 6); findings on the service's endpoints: "
    "verified critical 15, high 10, medium 5, low 2 each and half of that for "
    "candidates (max 25))")
# Infrastructure signals (third-party scripts without SRI, mixed active content, internal
# leaks) are listed in ``surface.infra_findings`` with the points the design proposes
# (netview.INFRA_POINTS). The maintainer has not decided whether they enter the score:
# flip this constant to add them to ``risk_score`` (and to RISK_FORMULA's effect). Off by
# default, so scores and their tests are unchanged.
INFRA_IN_RISK = False
RISK_FORMULA += ("; infrastructure signals (mixed active content 5, third-party scripts "
                 "without SRI 2 each max 6, internal host/IP leak 4) are listed as "
                 "infra_findings and count only when surface.INFRA_IN_RISK is enabled "
                 "(off by default)")
_FINDING_POINTS = {"critical": 15.0, "high": 10.0, "medium": 5.0, "low": 2.0, "info": 0.0}


# ------------------------------------------------------------------ helpers


def _hdr(headers: list, name: str) -> list[str]:
    return [str(v) for k, v in (headers or []) if str(k).lower() == name]


def _first(headers: list, name: str) -> str | None:
    v = _hdr(headers, name)
    return v[0] if v else None


def _ctype(ct: str | None) -> str | None:
    base = (ct or "").split(";", 1)[0].strip().lower()
    return base[:60] or None


def _tech(value: str) -> str | None:
    value = " ".join((value or "").split())[:80]
    if not value:
        return None
    m = _BANNER.match(value)
    if m:
        return f"{m.group(1).strip()} {m.group(2)}"
    return value.split()[0][:40] if re.match(r"[A-Za-z]", value) else None


def _has_version(value: str) -> bool:
    return bool(_BANNER.match((value or "").strip()))


def sensitive_reason(path: str) -> str | None:
    p = normalise_path(path or "/").lower()
    for rx, why in SENSITIVE_PATHS:
        if rx.search(p):
            return why
    return None


def _parse_cookie(line: str) -> tuple[str, dict[str, Any]] | None:
    parts = [p.strip() for p in str(line).split(";")]
    if "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()[:64]
    if not name:
        return None
    attrs = [p.lower() for p in parts[1:]]
    if any(a == "max-age=0" or a.startswith("max-age=-") for a in attrs):
        return None                         # a deletion, not a cookie the app relies on
    samesite = next((a.split("=", 1)[1].strip() for a in attrs
                     if a.startswith("samesite=")), None)
    return name, {"secure": "secure" in attrs, "httponly": "httponly" in attrs,
                  "samesite": samesite if samesite in ("lax", "strict", "none") else None}


def _service_key(scheme: str | None, host: str | None, port: int | None) -> str | None:
    if not scheme or not host or not port:
        return None
    h = f"[{host}]" if ":" in host else host
    k = url_keys(f"{scheme}://{h}:{port}/")
    return k.service if k else None


@dataclass
class _Evidence:
    """Per service, what the exchanges showed."""
    server: Counter = field(default_factory=Counter)
    version_headers: set = field(default_factory=set)
    tech: set = field(default_factory=set)
    hdr_present: Counter = field(default_factory=Counter)
    hdr_missing: Counter = field(default_factory=Counter)
    evaluated: int = 0
    hsts: bool = False
    cookies: dict = field(default_factory=dict)
    cors_tested: bool = False
    cors_reflect: bool = False
    cors_creds: bool = False
    cors_star: bool = False
    cors_paths: set = field(default_factory=set)
    redirects: int = 0
    external: int = 0
    exchange_ids: set = field(default_factory=set)
    by_endpoint: dict = field(default_factory=lambda: defaultdict(list))


def _fold(rows: list, https: bool, host: str) -> _Evidence:
    ev = _Evidence()
    latest: dict[str, Any] = {}            # endpoint key -> latest GET 2xx html/json row
    for r in rows:
        k = url_keys(r.url)
        if k is None:
            continue
        ev.exchange_ids.add(r.id)
        ev.by_endpoint[k.endpoint].append(r)
        rh = r.response_headers or []
        srv = _first(rh, "server")
        if srv:
            ev.server[srv.strip()[:120]] += 1
            if _has_version(srv):
                ev.version_headers.add("server")
            t = _tech(srv)
            if t:
                ev.tech.add(t)
        xp = _first(rh, "x-powered-by")
        if xp:
            if _has_version(xp):
                ev.version_headers.add("x-powered-by")
            t = _tech(xp)
            if t:
                ev.tech.add(t)
        for hname, label in (("x-aspnet-version", "ASP.NET"), ("x-generator", None)):
            v = _first(rh, hname)
            if v:
                ev.tech.add(f"{label} {v.strip()[:20]}" if label else _tech(v) or "")
        for line in _hdr(rh, "set-cookie"):
            parsed = _parse_cookie(line)
            if parsed is None:
                continue
            name, flags = parsed
            cur = ev.cookies.get(name)
            if cur is None:
                ev.cookies[name] = flags
            else:                           # weakest observed value wins
                cur["secure"] &= flags["secure"]
                cur["httponly"] &= flags["httponly"]
                if cur["samesite"] != flags["samesite"]:
                    cur["samesite"] = None
            low = name.lower()
            for needle, tech in _COOKIE_TECH:
                if low.startswith(needle):
                    ev.tech.add(tech)
        for rx, tech in _PATH_TECH:
            if rx.search((k.path or "").lower()) and r.status_code and r.status_code < 400:
                ev.tech.add(tech)
        origin = _first(r.request_headers or [], "origin")
        if origin:
            ev.cors_tested = True
            acao = (_first(rh, "access-control-allow-origin") or "").strip()
            acac = (_first(rh, "access-control-allow-credentials") or "").strip().lower() \
                == "true"
            if acao and acao == origin:
                ev.cors_reflect = True
                ev.cors_paths.add(k.path)
                ev.cors_creds |= acac
            elif acao == "*":
                ev.cors_star = True
                ev.cors_paths.add(k.path)
                ev.cors_creds |= acac
        sc = r.status_code or 0
        if 300 <= sc < 400:
            ev.redirects += 1
            loc = _first(rh, "location") or ""
            lk = url_keys(loc) if re.match(r"(?i)https?://", loc) else None
            if lk is not None and lk.host != host:
                ev.external += 1
        ct = _ctype(r.content_type)
        if (r.method == "GET" and 200 <= sc < 300 and not r.redirect_hop
                and (ct is None or ct in ("application/json", "application/xhtml+xml")
                     or ct.startswith("text/html"))):
            latest[k.endpoint] = r
    for r in latest.values():
        rh = r.response_headers or []
        ev.evaluated += 1
        csp = (_first(rh, "content-security-policy") or "").lower()
        for name in SECURITY_HEADERS:
            if name == "strict-transport-security":
                if not https:
                    continue
                sts = _first(rh, name)
                ok = bool(sts) and "max-age=0" not in sts.lower()
                ev.hsts |= ok
            elif name == "x-frame-options":
                ok = bool(_first(rh, name)) or "frame-ancestors" in csp
            else:
                ok = bool(_first(rh, name))
            (ev.hdr_present if ok else ev.hdr_missing)[name] += 1
    return ev


def _lst(values, n: int = MAX_LIST) -> list:
    return sorted(values)[:n]


def endpoint_class(asset: GreyboxAsset, ctypes=()) -> str:
    """page / api / static / media / other for an endpoint asset (``assetclass``)."""
    from urllib.parse import urlsplit
    ct = sorted(ctypes)[0] if ctypes else next(
        (c for c in ((asset.data or {}).get("surface") or {}).get("content_types", [])
         if isinstance(c, str)), None)
    return assetclass.classify_path(urlsplit(asset.key).path or "/", ct)


def _endpoint_surface(asset: GreyboxAsset, rows: list, params: int,
                      findings: int) -> dict[str, Any]:
    data = asset.data or {}
    codes = {r.status_code for r in rows if r.status_code}
    methods = {r.method for r in rows} | {m for m in data.get("methods", [])
                                          if isinstance(m, str)}
    ctypes = {c for c in (_ctype(r.content_type) for r in rows) if c}
    codes |= {c for c in data.get("status_codes", []) if isinstance(c, int)}
    login = bool(data.get("login_form"))
    return {
        "class": endpoint_class(asset, ctypes),
        "size": max((r.response_size for r in rows if r.response_size), default=None),
        "status_codes": _lst(codes), "content_types": _lst(ctypes),
        "methods": _lst(methods),
        "has_form": bool(data.get("forms") or login),
        "password_form": login, "params": params,
        "sensitive": _sensitive(asset, codes, findings),
    }


def _sensitive(asset: GreyboxAsset, codes: set, findings: int) -> str | None:
    """The reason this endpoint is sensitive, or None. An endpoint that only ever
    answered 404/5xx is not reachable content; one we merely know of (never fetched)
    counts as referenced."""
    from urllib.parse import urlsplit
    reason = sensitive_reason(urlsplit(asset.key).path)
    if reason is None:
        return None
    if codes and not findings and not any(c < 400 or c in (401, 403) for c in codes):
        return None
    return reason if codes or findings else f"{reason} (referenced, not fetched)"


def risk(surface: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    """The documented formula (``RISK_FORMULA``) over a service surface; returns the
    score and the contributing factors, largest first."""
    f: list[tuple[str, float, str]] = []
    sh = surface.get("security_headers", {})
    n = len(sh.get("missing", []))
    if n:
        f.append(("missing_headers", min(15, 3 * n),
                  f"{n} security header(s) missing: {', '.join(sh['missing'])}"))
    if surface.get("version_disclosure"):
        f.append(("version_banner", 8, "version banner in "
                  + ", ".join(surface["version_disclosure"])))
    https = surface.get("tls", {}).get("https", False)
    gaps = 0
    for flags in surface.get("cookie_flags", {}).values():
        gaps += (not flags["httponly"]) + (flags["samesite"] is None) \
            + ((not flags["secure"]) if https else 0)
    if gaps:
        f.append(("cookie_flags", min(12, 2 * gaps), f"{gaps} cookie flag gap(s)"))
    cors = surface.get("cors", {})
    if cors.get("reflects_origin") and cors.get("allows_credentials"):
        f.append(("cors", 20, "origin reflected with credentials"))
    elif cors.get("reflects_origin"):
        f.append(("cors", 8, "origin reflected"))
    elif cors.get("wildcard") and cors.get("allows_credentials"):
        f.append(("cors", 10, "wildcard origin with credentials"))
    ep = surface.get("endpoints", {})
    if not https:
        f.append(("plain_http", 10 + (5 if ep.get("auth_like") else 0),
                  "service is plain http" + (" and has login endpoints"
                                             if ep.get("auth_like") else "")))
    sens = surface.get("sensitive_paths", [])
    if ep.get("sensitive"):
        pts = sum(12 if s.get("served") else 4 for s in sens) \
            + 4 * max(0, ep["sensitive"] - len(sens))
        f.append(("sensitive_paths", min(30, pts),
                  f"{ep['sensitive']} sensitive endpoint(s)"))
    if ep.get("auth_like"):
        f.append(("login_endpoints", min(6, 3 * ep["auth_like"]),
                  f"{ep['auth_like']} login endpoint(s)"))
    fnd = surface.get("findings", {})
    fp = sum(_FINDING_POINTS.get(sev, 0) * (1 if st == "verified" else 0.5) * cnt
             for st, by in fnd.items() for sev, cnt in by.items())
    if fp:
        f.append(("findings", min(25, round(fp)), "findings on this service's endpoints"))
    if INFRA_IN_RISK:
        f += [(i["id"], float(i["points"]), i["detail"])
              for i in surface.get("infra_findings", [])]
    total = min(100, int(round(sum(p for _, p, _ in f))))
    ranked = sorted(f, key=lambda x: (-x[1], x[0]))
    return total, [{"id": i, "points": int(round(p)), "detail": d[:160]}
                   for i, p, d in ranked]


# ------------------------------------------------------------------ passive network view


def _infra(rows: list, pages: list[dict[str, Any]], https: bool, run: GreyboxRun | None
           ) -> dict[str, Any]:
    """The P1 keys of a service surface: ``third_party``, ``edge``, ``leaks``, ``http``,
    ``vantage`` and ``infra_findings``. Third-party, leaks and edge providers are a
    projection of what the graph already holds (the endpoint assets' stored signals);
    latency, cache of sensitive paths, HSTS and ``Alt-Svc`` come from the recorded
    exchanges. No request is made."""
    third = netview.aggregate_third_party(pages)
    leaks = netview.aggregate_leaks(pages)
    cacheable: set[str] = set()
    h3 = False
    hsts = None
    to_https = False
    plain_ok = False
    for r in rows:
        rh = r.response_headers or []
        k = url_keys(r.url)
        path = k.path if k else ""
        if any("h3" in v.lower() for v in _hdr(rh, "alt-svc")):
            h3 = True
        sts = _first(rh, "strict-transport-security")
        if https and sts:
            hsts = netview.hsts_policy(sts)
        sc = r.status_code or 0
        if not https and r.method == "GET":
            if 300 <= sc < 400 and re.match(r"(?i)https://", _first(rh, "location") or ""):
                to_https = True
            elif 200 <= sc < 300 and path == "/":
                plain_ok = True
        prof = netview.cache_profile(rh)
        if (prof["hit"] or prof["cc"] == "public") and 200 <= sc < 300 and (
                sensitive_reason(path) or AUTH_PATH.search(path)):
            cacheable.add(path[:120])
    redirects: dict[tuple, dict[str, Any]] = {}
    for d in pages:
        cr = d.get("cross_redirect")
        if cr:
            e = redirects.setdefault((cr["to"], bool(cr.get("downgrade"))), {
                "to": cr["to"], "in_scope": bool(cr.get("in_scope")),
                "downgrade": bool(cr.get("downgrade")), "ip": bool(cr.get("ip")), "pages": 0})
            e["pages"] += 1
    direct = sum(1 for r in rows if not r.via_proxy)
    proxied = len(rows) - direct
    vantage = {"kind": "proxy" if proxied and not direct else "mixed" if proxied else "direct",
               "exchanges": {"direct": direct, "via_proxy": proxied},
               "proxy_id": str(run.egress_proxy_id) if run is not None and proxied
               and getattr(run, "egress_proxy_id", None) else None}
    edge = netview.aggregate_edge(pages, {
        "latency": netview.latency_profile([(r.duration_ms, bool(r.via_proxy)) for r in rows]),
        "sensitive_cacheable": sorted(cacheable)})
    infra: list[dict[str, Any]] = []
    P = netview.INFRA_POINTS
    if third["mixed_content"]["active"]:
        infra.append({"id": "mixed_active", "points": P["mixed_active"],
                      "detail": f"{third['mixed_content']['active']} http:// active "
                                "resource(s) on https pages"})
    if third["scripts_without_sri"]:
        infra.append({"id": "scripts_without_sri",
                      "points": min(P["no_sri_max"], P["no_sri_each"] * third["scripts_without_sri"]),
                      "detail": f"{third['scripts_without_sri']} third-party script "
                                "reference(s) without SRI"})
    if leaks["count"]:
        infra.append({"id": "internal_leak", "points": P["leak"],
                      "detail": f"{leaks['count']} internal host(s)/address(es) disclosed"})
    return {
        "third_party": third, "edge": edge, "leaks": leaks,
        "http": {"h3_advertised": h3,
                 "http_to_https": None if https else (True if to_https else
                                                      (False if plain_ok else None)),
                 "hsts": hsts if https else None,
                 "cross_host_redirects": sorted(redirects.values(),
                                                key=lambda e: (e["to"], e["downgrade"]))
                 [:MAX_LIST]},
        "vantage": vantage, "infra_findings": infra}


# ------------------------------------------------------------------ tracker


class _Tracker:
    def __init__(self) -> None:
        self.last: dict[uuid.UUID, float] = {}
        self.pending: dict[uuid.UUID, dict[str, Any]] = {}


def _tracker(stats) -> _Tracker:
    t = getattr(stats, "_surface_tracker", None)
    if t is None:
        t = _Tracker()
        stats._surface_tracker = t
    return t


async def _announce(session: AsyncSession, gtx: GraphTx, asset: GreyboxAsset,
                    changed: set[str], score: int | None, *, force: bool = False) -> None:
    t = _tracker(gtx.stats)
    p = t.pending.setdefault(asset.id, {"keys": set(), "kind": asset.kind})
    p["keys"] |= changed
    p["risk"] = score
    now = time.monotonic()
    if not force and now - t.last.get(asset.id, -1e9) < EMIT_INTERVAL_S:
        return
    keys = sorted(t.pending.pop(asset.id)["keys"])
    t.last[asset.id] = now
    await events.emit(
        session, gtx.run_id, "surface.updated",
        f"surface updated: {asset.kind} {asset.label}",
        data={"asset_id": str(asset.id), "kind": asset.kind, "risk_score": score,
              "changed": keys},
        refs={"asset_ids": [asset.id]}, agent_id=gtx.agent_id,
        work_order_id=gtx.work_order_id)


def pending_delay(stats) -> float:
    """Seconds until every pending ``surface.updated`` may be emitted."""
    t = getattr(stats, "_surface_tracker", None)
    if t is None or not t.pending:
        return 0.0
    now = time.monotonic()
    return max(0.0, max(EMIT_INTERVAL_S - (now - t.last.get(a, -1e9))
                        for a in t.pending))


async def flush(session: AsyncSession, gtx: GraphTx) -> None:
    """Emit every still-pending (coalesced) ``surface.updated``."""
    t = _tracker(gtx.stats)
    for aid in list(t.pending):
        asset = await session.get(GreyboxAsset, aid)
        if asset is not None and asset.run_id == gtx.run_id:
            await _announce(session, gtx, asset, set(),
                            t.pending[aid].get("risk"), force=True)
        else:
            t.pending.pop(aid, None)


# ------------------------------------------------------------------ refresh


async def refresh(session: AsyncSession, gtx: GraphTx, *,
                  work_order_id: uuid.UUID | None = None) -> int:
    """Recompute the surface of every service touched by ``work_order_id``'s exchanges
    (all services when None) and of their endpoints. Returns the assets changed."""
    q = select(GreyboxHttpExchange.scheme, GreyboxHttpExchange.host,
               GreyboxHttpExchange.port).where(
        GreyboxHttpExchange.run_id == gtx.run_id,
        GreyboxHttpExchange.blocked.is_(False),
        GreyboxHttpExchange.status_code.is_not(None)).distinct()
    if work_order_id is not None:
        q = q.where(GreyboxHttpExchange.work_order_id == work_order_id)
    triples = sorted({tuple(r) for r in (await session.execute(q)).all()},
                     key=lambda t: tuple(str(x) for x in t))
    changed_assets = 0
    for scheme, host, port in triples:
        key = _service_key(scheme, host, port)
        svc = await gtx.get_asset("service", key) if key else None
        if svc is None or not svc.in_scope:
            continue
        changed_assets += await _refresh_service(session, gtx, svc, scheme, host, port)
    return changed_assets


async def _refresh_service(session: AsyncSession, gtx: GraphTx, svc: GreyboxAsset,
                           scheme: str, host: str, port: int) -> int:
    rows = list((await session.scalars(
        select(GreyboxHttpExchange).where(
            GreyboxHttpExchange.run_id == gtx.run_id,
            GreyboxHttpExchange.scheme == scheme, GreyboxHttpExchange.host == host,
            GreyboxHttpExchange.port == port,
            GreyboxHttpExchange.blocked.is_(False),
            GreyboxHttpExchange.status_code.is_not(None))
        .order_by(GreyboxHttpExchange.id))).all())
    https = scheme == "https"
    ev = _fold(rows, https, svc.key.split("://", 1)[1].rsplit(":", 1)[0])
    endpoints = list((await session.scalars(
        select(GreyboxAsset).where(
            GreyboxAsset.run_id == gtx.run_id, GreyboxAsset.kind == "endpoint",
            GreyboxAsset.parent_id == svc.id, GreyboxAsset.in_scope.is_(True))
        .order_by(GreyboxAsset.key))).all())
    param_counts: Counter = Counter()
    if endpoints:
        for (pid,) in (await session.execute(
                select(GreyboxAsset.parent_id).where(
                    GreyboxAsset.run_id == gtx.run_id,
                    GreyboxAsset.kind == "parameter",
                    GreyboxAsset.parent_id.in_([e.id for e in endpoints])))).all():
            param_counts[pid] += 1
    blocked_hops = 0
    if ev.exchange_ids:
        blocked_hops = len((await session.execute(
            select(GreyboxHttpExchange.id).where(
                GreyboxHttpExchange.run_id == gtx.run_id,
                GreyboxHttpExchange.blocked.is_(True),
                GreyboxHttpExchange.redirect_hop > 0,
                GreyboxHttpExchange.parent_exchange_id.in_(ev.exchange_ids)))).all())
    frows = (await session.execute(
        select(GreyboxFinding.severity, GreyboxFinding.status,
               GreyboxFinding.affected_asset_id).where(
            GreyboxFinding.run_id == gtx.run_id,
            GreyboxFinding.status.in_(("verified", "candidate"))))).all()
    ep_ids = {e.id for e in endpoints}
    findings: dict[str, Counter] = {"verified": Counter(), "candidate": Counter()}
    for sev, st, aid in frows:
        if aid in ep_ids:
            findings[st][sev] += 1
    findings = {st: dict(sorted(c.items())) for st, c in findings.items() if c}

    changed = 0
    auth_paths: list[str] = []
    sens: list[dict[str, Any]] = []
    n_tested = n_find = n_auth = n_sens = n_static = 0
    ep_updates: list[tuple[GreyboxAsset, dict[str, Any]]] = []
    for e in endpoints:
        e_rows = ev.by_endpoint.get(e.key, [])
        es = _endpoint_surface(e, e_rows, param_counts[e.id], e.finding_count)
        ep_updates.append((e, es))
        if assetclass.is_static_like(es["class"]) and not e.finding_count:
            # Build output and media: kept as assets, but not counted as attack surface
            # (they would drown the coverage and the per-service endpoint figures).
            # One carrying a finding (a leaked secret in a bundle) stays a normal endpoint.
            n_static += 1
            continue
        path = url_keys(e.key).path if url_keys(e.key) else e.label
        n_tested += bool(e.tested)
        n_find += e.finding_count > 0
        ok_codes = set(es["status_codes"])
        if es["password_form"] or (AUTH_PATH.search(path) and (
                not ok_codes or any(c < 400 for c in ok_codes))):
            n_auth += 1
            auth_paths.append(path[:120])
        if es["sensitive"]:
            n_sens += 1
            sens.append({"path": path[:120], "reason": es["sensitive"][:80],
                         "served": any(200 <= c < 300 for c in ok_codes),
                         "status": sorted(ok_codes)[:3]})
    sens.sort(key=lambda s: s["path"])
    server = ev.server.most_common(1)[0][0] if ev.server else None
    surface: dict[str, Any] = {
        "server": server,
        "version_disclosure": sorted(ev.version_headers),
        "technologies": _lst({t for t in ev.tech if t}, 12),
        "security_headers": {
            "present": [h for h in SECURITY_HEADERS
                        if ev.hdr_present[h] and not ev.hdr_missing[h]],
            "missing": [h for h in SECURITY_HEADERS if ev.hdr_missing[h]],
            "counts": {h: {"present": ev.hdr_present[h], "missing": ev.hdr_missing[h]}
                       for h in SECURITY_HEADERS
                       if ev.hdr_present[h] or ev.hdr_missing[h]},
            "evaluated": ev.evaluated,
        },
        "cookie_flags": {n: ev.cookies[n] for n in sorted(ev.cookies)[:MAX_LIST]},
        "cors": {"tested": ev.cors_tested, "reflects_origin": ev.cors_reflect,
                 "allows_credentials": ev.cors_creds, "wildcard": ev.cors_star,
                 "paths": _lst(ev.cors_paths, 5)},
        "redirects": {"count": ev.redirects, "external": ev.external,
                      "external_blocked": blocked_hops},
        "tls": {"https": https, "hsts": ev.hsts if https else None},
        "endpoints": {"total": len(endpoints) - n_static, "static": n_static,
                      "tested": n_tested,
                      "with_findings": n_find, "auth_like": n_auth,
                      "sensitive": n_sens},
        "auth_paths": sorted(auth_paths)[:MAX_LIST],
        "sensitive_paths": sens[:MAX_LIST],
        "findings": findings,
        **_infra(rows, [e.data or {} for e in endpoints], https,
                 await session.get(GreyboxRun, gtx.run_id)),
    }
    score, factors = risk(surface)
    surface["risk_score"] = score
    surface["risk_factors"] = factors[:8]

    prev = (svc.data or {}).get("surface") or {}
    if await gtx.set_surface(svc, surface):
        changed += 1
        keys = {k for k in surface if prev.get(k) != (svc.data or {})["surface"].get(k)}
        await _announce(session, gtx, svc, keys, score)
    for e, es in ep_updates:
        prev = (e.data or {}).get("surface") or {}
        if await gtx.set_surface(e, es):
            changed += 1
            keys = {k for k in es if prev.get(k) != (e.data or {})["surface"].get(k)}
            await _announce(session, gtx, e, keys, None)
    return changed
