"""Passive network and infrastructure view.

Pure functions over data the run ALREADY recorded: response headers, cookie names, stored
(redacted, capped) bodies, exchange timings. Nothing here performs I/O or imports a
network library; third-party URLs found in content are *described*, never requested.
Everything that comes from the target is untrusted: it is length-bounded here, redacted
again when it is stored (``GraphTx``/``events.cap_data``) and escaped when reported.

Signals produced for one response (:func:`analyse`), stored compactly on the endpoint
asset's ``data`` (the graph state that the surface and the report project from):

* ``third_party``   per external origin: kinds, references, scripts and scripts without SRI,
                    mixed-content class
* ``mixed_content`` http:// subresources of an https page (active: script, style, frame;
                    passive: images, media)
* ``leaks``         internal hostnames and private addresses in headers and bodies
* ``edge``          CDN / WAF / load-balancer attribution (offline table) and cache hints
* ``cross_redirect`` a redirect to another host (downgrade, IP literal, out of scope)
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from src.greybox_web.scope import DEFAULT_PORTS, canonical_host

DATA_FILE = Path(__file__).parent / "data" / "edge_providers.json"
STALE_AFTER_DAYS = 120

MAX_ORIGINS = 10          # third-party origins kept per page / listed per service
MAX_MIXED = 5
MAX_LEAKS = 6
MAX_SIGNALS = 4
BODY_SCAN = 64 * 1024     # bytes of a stored body inspected for leaks
PATTERN_MAX = 200         # signature patterns are short and anchored (bounded matching)

_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


# ------------------------------------------------------------------ provider table


@lru_cache(maxsize=1)
def provider_table() -> dict[str, Any]:
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def validate_table(table: dict[str, Any]) -> list[str]:
    """Problems in a provider table (empty when fine): every pattern compiles, is short
    and has no unbounded nested quantifier; ids are unique."""
    problems: list[str] = []
    seen: set[str] = set()
    nested = re.compile(r"\((?:[^()]*[+*])\)[+*]")
    for p in table.get("providers", []):
        pid = p.get("id", "?")
        if pid in seen:
            problems.append(f"duplicate id {pid}")
        seen.add(pid)
        if p.get("kind") not in ("cdn", "waf", "lb", "cloud"):
            problems.append(f"{pid}: bad kind")
        patterns = [h["value"] for h in p.get("headers", []) if "value" in h]
        patterns += p.get("cookies", []) + p.get("block_body", [])
        for rx in patterns:
            if len(rx) > PATTERN_MAX:
                problems.append(f"{pid}: pattern too long")
            if nested.search(rx):
                problems.append(f"{pid}: nested quantifier in {rx!r}")
            try:
                re.compile(rx, re.I)
            except re.error as exc:
                problems.append(f"{pid}: {rx!r}: {exc}")
    return problems


def table_age_days(today=None) -> int | None:
    from datetime import date
    try:
        gen = date.fromisoformat(provider_table().get("generated_at", ""))
    except ValueError:
        return None
    return ((today or date.today()) - gen).days


@lru_cache(maxsize=1)
def _compiled() -> tuple[dict[str, Any], ...]:
    out = []
    for p in provider_table()["providers"]:
        out.append({
            **p,
            "_headers": [(h["name"].lower(), re.compile(h["value"], re.I) if "value" in h
                          else None, bool(h.get("weak"))) for h in p.get("headers", [])],
            "_cookies": [re.compile(c, re.I) for c in p.get("cookies", [])],
            "_block": [re.compile(b, re.I) for b in p.get("block_body", [])],
        })
    return tuple(out)


def provider_info(vendor: str) -> dict[str, Any] | None:
    for p in provider_table()["providers"]:
        if p["id"] == vendor:
            return p
    return None


# ------------------------------------------------------------------ helpers


def _hv(headers: list, name: str) -> list[str]:
    return [str(v) for k, v in (headers or []) if str(k).lower() == name]


def _clip(v: Any, n: int) -> str:
    return " ".join(str(v).split())[:n]


def cookie_names(headers: list) -> list[str]:
    out = []
    for line in _hv(headers, "set-cookie"):
        name = line.split("=", 1)[0].strip()
        if name and "=" in line:
            out.append(name[:64])
    return out


# ------------------------------------------------------------------ edge / CDN / WAF


def detect_edge(headers: list, body: str | None = None, status: int | None = None
                ) -> list[dict[str, Any]]:
    """Providers attributed from one response, best first. Each:
    ``{"vendor", "kind", "confidence", "signals": ["header:cf-ray", ...], "blocked"}``.
    A single weak signal downgrades the confidence to ``low``; ``blocked`` is true when
    a 4xx/5xx body carries the vendor's block-page text."""
    out: list[dict[str, Any]] = []
    names = cookie_names(headers)
    snippet = (body or "")[:4096] if status and status >= 400 else ""
    for p in _compiled():
        signals: list[str] = []
        strong = 0
        for hname, rx, weak in p["_headers"]:
            for v in _hv(headers, hname):
                if rx is None or rx.search(v[:300]):
                    signals.append(f"header:{hname}")
                    strong += 0 if weak else 1
                    break
        for rx in p["_cookies"]:
            hit = next((n for n in names if rx.search(n)), None)
            if hit:
                signals.append(f"cookie:{hit[:40]}")
                strong += 1
        blocked = bool(snippet) and any(rx.search(snippet) for rx in p["_block"])
        if blocked:
            signals.append("block_page")
            strong += 1
        if not signals:
            continue
        conf = p.get("confidence", "medium") if strong else "low"
        out.append({"vendor": p["id"], "kind": p["kind"], "confidence": conf,
                    "signals": sorted(set(signals))[:MAX_SIGNALS], "blocked": blocked})
    out.sort(key=lambda m: (_CONF_RANK.get(m["confidence"], 3), m["vendor"]))
    return out


def cache_profile(headers: list) -> dict[str, Any]:
    """Cache behaviour visible in one response (no request): hit/miss from the usual
    edge headers, ``Age`` presence and the Cache-Control class."""
    hit: bool | None = None
    for name in ("cf-cache-status", "x-cache", "x-cache-status", "x-proxy-cache"):
        for v in _hv(headers, name):
            low = v.lower()
            if "hit" in low:
                hit = True
            elif "miss" in low or "dynamic" in low or "bypass" in low:
                hit = False if hit is None else hit
    cc = " ".join(_hv(headers, "cache-control")).lower()
    klass = None
    if "no-store" in cc:
        klass = "no-store"
    elif "private" in cc:
        klass = "private"
    elif "public" in cc or re.search(r"max-age=[1-9]", cc) or "s-maxage" in cc:
        klass = "public"
    return {"hit": hit, "cc": klass, "age": bool(_hv(headers, "age"))}


def _percentile(sorted_vals: list[int], q: float) -> int:
    idx = max(0, min(len(sorted_vals) - 1, int(round(q * len(sorted_vals) + 0.5)) - 1))
    return sorted_vals[idx]


def latency_profile(rows: list[tuple[int | None, bool]]) -> dict[str, Any] | None:
    """p50 / p95 over ``(duration_ms, via_proxy)`` pairs, direct and proxied kept apart
    (a proxy hop adds latency that is not the target's)."""
    out: dict[str, Any] = {}
    for label, flag in (("direct", False), ("via_proxy", True)):
        vals = sorted(d for d, p in rows if d is not None and p is flag)
        if vals:
            out[label] = {"p50": _percentile(vals, 0.5), "p95": _percentile(vals, 0.95),
                          "n": len(vals)}
    return out or None


# ------------------------------------------------------------------ internal leaks

INTERNAL_SUFFIXES = ("local", "lan", "internal", "intranet", "corp", "home", "localdomain",
                     "home.arpa", "localhost")
_HOST = re.compile(
    r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,40}[a-z0-9])?\.){1,6}(?:"
    + "|".join(re.escape(s) for s in sorted(INTERNAL_SUFFIXES, key=len, reverse=True))
    + r"))(?![\w-])", re.I)
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w])")
_IPV6 = re.compile(r"(?<![\w:])((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4})(?![\w:])", re.I)
_VERSION_CTX = re.compile(r"[A-Za-z][\w.-]*/v?$")     # "Foo/1.2.3.4": a banner, not a host

# Headers whose value is a reasonable place for an upstream address or name.
BACKEND_HEADERS = ("location", "content-location", "refresh", "x-backend-server",
                   "x-served-by", "x-server", "x-upstream", "x-upstream-addr", "x-real-server",
                   "x-forwarded-host", "x-forwarded-server", "x-host", "x-node", "x-origin",
                   "via", "server-timing", "access-control-allow-origin", "link")
SKIP_HEADERS = frozenset({"date", "content-type", "content-length", "etag", "expires",
                          "last-modified", "set-cookie", "cache-control", "vary"})
_TEXTUAL = ("text/", "application/json", "application/xml", "application/xhtml",
            "application/problem+json", "application/ld+json")


def internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return False
    if ip in ipaddress.ip_network("192.0.2.0/24") or ip in ipaddress.ip_network(
            "198.51.100.0/24") or ip in ipaddress.ip_network("203.0.113.0/24"):
        return False                       # documentation ranges
    return (ip.is_private or ip.is_link_local
            or (ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10")))


def _scan(text: str, where: str, host_allowed: Callable[[str], bool],
          public_ok: bool, out: dict[str, dict[str, Any]]) -> None:
    for m in _IPV4.finditer(text):
        val = m.group(1)
        if _VERSION_CTX.search(text[max(0, m.start() - 40):m.start()]):
            continue
        try:
            ip = ipaddress.ip_address(val)
        except ValueError:
            continue
        internal = internal_ip(val)
        if not internal and not (public_ok and ip.is_global):
            continue
        out.setdefault(val, {"value": val, "kind": "ipv4", "where": where,
                             "internal": internal})
    for m in _IPV6.finditer(text):
        val = m.group(1).rstrip(":")
        if not internal_ip(val):
            continue
        out.setdefault(val.lower(), {"value": val.lower()[:60], "kind": "ipv6",
                                     "where": where, "internal": True})
    for m in _HOST.finditer(text):
        val = m.group(1).lower()
        if host_allowed(val):
            continue                          # the target's own (in-scope) name
        out.setdefault(val, {"value": val[:120], "kind": "hostname", "where": where,
                             "internal": True})


def find_leaks(headers: list, body: str | None, content_type: str | None,
               host_allowed: Callable[[str], bool]) -> list[dict[str, Any]]:
    """Internal hostnames and addresses in a response: headers first (high confidence),
    then the first 64 KiB of a textual body (medium). A public address is kept only
    when it sits in an explicit upstream header or in ``Location``. At most
    ``MAX_LEAKS`` hits, in order of appearance."""
    found: dict[str, dict[str, Any]] = {}
    for name, value in headers or []:
        low = str(name).lower()
        if low in SKIP_HEADERS:
            continue
        backend = low in BACKEND_HEADERS or bool(re.search(
            r"backend|upstream|origin|forward|real-?(ip|server)|node|host", low))
        if not backend:
            continue
        _scan(str(value)[:500], f"header:{low[:40]}", host_allowed, True, found)
    if body and (not content_type or any(content_type.lower().startswith(t)
                                         or t in content_type.lower() for t in _TEXTUAL)):
        _scan(body[:BODY_SCAN], "body", host_allowed, False, found)
    hits = list(found.values())[:MAX_LEAKS]
    for h in hits:
        h["confidence"] = "high" if h["where"].startswith("header:") else "medium"
    return hits


# ------------------------------------------------------------------ resources


_ACTIVE = {"script", "style", "frame"}


def resource_kind(tag: str, rel: str, as_: str) -> str | None:
    rel = (rel or "").lower().split()
    if tag == "script":
        return "script"
    if tag in ("iframe", "frame"):
        return "frame"
    if tag in ("img", "source", "video", "audio", "track", "picture"):
        return "image" if tag in ("img", "picture") else "media"
    if tag == "link":
        if "stylesheet" in rel:
            return "style"
        if "modulepreload" in rel:
            return "script"
        if "preload" in rel:
            return {"script": "script", "style": "style"}.get((as_ or "").lower(), "image"
                                                              if (as_ or "").lower() == "image"
                                                              else "media")
    return None


def classify_resources(base_url: str, raws: list[dict[str, Any]],
                       host_allowed: Callable[[str], bool]) -> list[dict[str, Any]]:
    """Resources that matter for the supply-chain view: those served by a host outside
    the run's scope (third party) and any http:// subresource of an https page (mixed
    content). Each: tag, kind, url, host, sri, crossorigin, tp, mixed, raw (the start
    tag, for evidence). Nothing is requested."""
    page_https = urlsplit(base_url).scheme == "https"
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for r in raws:
        ref = (r.get("url") or "").strip()
        kind = resource_kind(r.get("tag", ""), r.get("rel", ""), r.get("as", ""))
        if not ref or kind is None or ref.startswith(("#", "data:", "javascript:", "about:",
                                                      "blob:", "mailto:")):
            continue
        try:
            absolute = urljoin(base_url, ref)
            p = urlsplit(absolute)
            host = canonical_host(p.hostname or "")
        except ValueError:
            continue
        if p.scheme not in ("http", "https") or not host:
            continue
        tp = not host_allowed(host)
        mixed = None
        if page_https and p.scheme == "http":
            mixed = "active" if kind in _ACTIVE else "passive"
        if not tp and mixed is None:
            continue
        if (r["tag"], absolute) in seen:
            continue
        seen.add((r["tag"], absolute))
        out.append({"tag": r["tag"], "kind": kind, "url": absolute[:300], "host": host,
                    "sri": bool(r.get("integrity")), "crossorigin": r.get("crossorigin"),
                    "tp": tp, "mixed": mixed, "raw": r.get("raw", "")[:240]})
        if len(out) >= 100:
            break
    return out


def third_party_summary(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per external origin, for one page (compact, stored on the endpoint asset)."""
    by: dict[str, dict[str, Any]] = {}
    for r in resources:
        if not r["tp"]:
            continue
        e = by.setdefault(r["host"], {"h": r["host"][:120], "k": set(), "n": 0, "s": 0,
                                      "ns": 0, "m": None})
        e["k"].add(r["kind"])
        e["n"] += 1
        if r["kind"] == "script":
            e["s"] += 1
            e["ns"] += 0 if r["sri"] else 1
        if r["mixed"] == "active" or (r["mixed"] and e["m"] is None):
            e["m"] = r["mixed"]
    out = [{**e, "k": sorted(e["k"])} for _, e in sorted(by.items())]
    return out[:MAX_ORIGINS]


def mixed_summary(resources: list[dict[str, Any]]) -> dict[str, Any] | None:
    mixed = [r for r in resources if r["mixed"]]
    if not mixed:
        return None
    return {"active": sum(r["mixed"] == "active" for r in mixed),
            "passive": sum(r["mixed"] == "passive" for r in mixed),
            "samples": [{"u": r["url"][:160], "t": r["tag"], "m": r["mixed"]}
                        for r in mixed[:MAX_MIXED]]}


# ------------------------------------------------------------------ redirects / HSTS


def cross_redirect(url: str, status: int | None, headers: list, followed_to: str | None,
                   host_allowed: Callable[[str], bool]) -> dict[str, Any] | None:
    """A redirect to another host, to an IP literal, or from https to http. From the
    ``Location`` of a 3xx answer or the URL the client ended on."""
    target = followed_to
    if target is None and status and 300 <= status < 400:
        loc = (_hv(headers, "location") or [""])[0].strip()
        target = urljoin(url, loc) if loc else None
    if not target:
        return None
    try:
        a, b = urlsplit(url), urlsplit(target)
        src, dst = canonical_host(a.hostname or ""), canonical_host(b.hostname or "")
    except ValueError:
        return None
    if b.scheme not in ("http", "https") or not dst:
        return None
    downgrade = a.scheme == "https" and b.scheme == "http"
    if dst == src and not downgrade:
        return None
    try:
        ipaddress.ip_address(dst)
        is_ip = True
    except ValueError:
        is_ip = False
    return {"to": dst[:120], "in_scope": host_allowed(dst), "downgrade": downgrade,
            "ip": is_ip, "status": status}


def hsts_policy(value: str | None) -> dict[str, Any] | None:
    """Parse ``Strict-Transport-Security``; preload readiness is computed offline
    (max-age >= 1 year, includeSubDomains and preload; the preload list is not
    consulted)."""
    if not value:
        return None
    max_age = 0
    m = re.search(r"max-age\s*=\s*\"?(\d{1,12})", value, re.I)
    if m:
        max_age = int(m.group(1))
    sub = bool(re.search(r"(?i)(^|;)\s*includesubdomains\s*(;|$)", value))
    pre = bool(re.search(r"(?i)(^|;)\s*preload\s*(;|$)", value))
    return {"max_age": max_age, "include_subdomains": sub, "preload": pre,
            "preload_ready": max_age >= 31536000 and sub and pre}


# ------------------------------------------------------------------ one response


@dataclass
class PageSignals:
    resources: list[dict[str, Any]] = field(default_factory=list)
    leaks: list[dict[str, Any]] = field(default_factory=list)
    edge: list[dict[str, Any]] = field(default_factory=list)
    cache: dict[str, Any] = field(default_factory=dict)
    redirect: dict[str, Any] | None = None

    def page_data(self) -> dict[str, Any]:
        """Compact form stored on the endpoint asset (``data``; bounded)."""
        d: dict[str, Any] = {}
        tp = third_party_summary(self.resources)
        if tp:
            d["third_party"] = tp
        mixed = mixed_summary(self.resources)
        if mixed:
            d["mixed_content"] = mixed
        if self.leaks:
            d["leaks"] = [{"v": h["value"], "k": h["kind"], "w": h["where"][:48],
                           "i": h["internal"]} for h in self.leaks]
        if self.edge or self.cache.get("hit") is not None or self.cache.get("cc"):
            d["edge"] = {"providers": [{"id": e["vendor"], "s": e["signals"],
                                        "b": e["blocked"]} for e in self.edge[:3]],
                         "cache": self.cache}
        if self.redirect:
            d["cross_redirect"] = self.redirect
        return d


def analyse(url: str, status: int | None, headers: list, body: str | None,
            content_type: str | None, raw_resources: list[dict[str, Any]],
            host_allowed: Callable[[str], bool], followed_to: str | None = None
            ) -> PageSignals:
    """All passive signals of one recorded response. Deterministic."""
    return PageSignals(
        resources=classify_resources(url, raw_resources, host_allowed),
        leaks=find_leaks(headers, body, content_type, host_allowed),
        edge=detect_edge(headers, body, status),
        cache=cache_profile(headers),
        redirect=cross_redirect(url, status, headers, followed_to, host_allowed))


def obs_key(kind: str, endpoint: str, ident: str) -> str:
    """The exploration-graph key of a passive observation (shared by the tool that
    records it and the planner rule that opens a lead from it)."""
    return f"net.{kind}|{endpoint}|{ident}"[:300]


# ------------------------------------------------------------------ service projection

# Risk points for infrastructure signals. They are listed as separate
# ``infra_findings`` and ENTER ``risk_score`` only when ``surface.INFRA_IN_RISK`` is true.
INFRA_POINTS = {"mixed_active": 5, "no_sri_each": 2, "no_sri_max": 6, "leak": 4}


def aggregate_third_party(pages: list[dict[str, Any]]) -> dict[str, Any]:
    """Service-level ``data.surface.third_party`` from the endpoints' stored page data."""
    per: dict[str, dict[str, Any]] = {}
    mixed = Counter()
    scripts = no_sri = 0
    for d in pages:
        for e in d.get("third_party") or []:
            o = per.setdefault(e["h"], {"host": e["h"], "kinds": set(), "pages": 0,
                                        "scripts": 0, "no_sri": 0, "mixed": None})
            o["kinds"].update(e.get("k", []))
            o["pages"] += 1
            o["scripts"] += e.get("s", 0)
            o["no_sri"] += e.get("ns", 0)
            if e.get("m") == "active" or (e.get("m") and o["mixed"] is None):
                o["mixed"] = e["m"]
            scripts += e.get("s", 0)
            no_sri += e.get("ns", 0)
        mc = d.get("mixed_content")
        if mc:
            mixed["active"] += mc.get("active", 0)
            mixed["passive"] += mc.get("passive", 0)
    top = sorted(per.values(), key=lambda o: (-o["pages"], o["host"]))[:MAX_ORIGINS]
    return {
        "origins": len(per), "scripts": scripts, "scripts_without_sri": no_sri,
        "mixed_content": {"active": mixed["active"], "passive": mixed["passive"]},
        "top": [{"host": o["host"], "kinds": sorted(o["kinds"]), "pages": o["pages"],
                 "sri": o["scripts"] > 0 and o["no_sri"] == 0,
                 **({"mixed": o["mixed"]} if o["mixed"] else {})} for o in top],
    }


def aggregate_leaks(pages: list[dict[str, Any]]) -> dict[str, Any]:
    hosts: Counter = Counter()
    ips: Counter = Counter()
    where: dict[str, str] = {}
    for d in pages:
        for h in d.get("leaks") or []:
            if not h.get("i"):
                continue
            (hosts if h["k"] == "hostname" else ips)[h["v"]] += 1
            where.setdefault(h["v"], h.get("w", ""))
    return {"count": len(hosts) + len(ips),
            "internal_hosts": sorted(hosts)[:MAX_ORIGINS],
            "private_ips": sorted(ips)[:MAX_ORIGINS],
            "where": {k: where[k] for k in sorted(where)[:2 * MAX_ORIGINS]}}


def aggregate_edge(pages: list[dict[str, Any]], rows_meta: dict[str, Any]) -> dict[str, Any]:
    """Service-level ``data.surface.edge``. ``rows_meta`` carries what only the raw
    exchanges hold (latency profile, sensitive cacheable paths)."""
    found: dict[str, dict[str, Any]] = {}
    blocked = 0
    hits = observed = 0
    for d in pages:
        e = d.get("edge")
        if not e:
            continue
        for p in e.get("providers", []):
            f = found.setdefault(p["id"], {"signals": set(), "blocked": 0})
            f["signals"].update(p.get("s", []))
            if p.get("b"):
                f["blocked"] += 1
                blocked += 1
        c = e.get("cache") or {}
        if c.get("hit") is not None or c.get("cc"):
            observed += 1
        hits += 1 if c.get("hit") else 0
    providers = []
    for vendor in sorted(found):
        info = provider_info(vendor) or {}
        providers.append({"vendor": vendor, "name": info.get("name", vendor),
                          "kind": info.get("kind", "cdn"),
                          "confidence": info.get("confidence", "medium"),
                          "signals": sorted(found[vendor]["signals"])[:MAX_SIGNALS]})
    providers.sort(key=lambda p: (_CONF_RANK.get(p["confidence"], 3), p["vendor"]))
    waf_vendor = next((p["vendor"] for p in providers
                       if (provider_info(p["vendor"]) or {}).get("waf_capable")), None)
    if blocked:
        state = "enforcing_observed"
    elif waf_vendor:
        state = "detected"
    else:
        state = "not_detected"
    return {
        "providers": providers,
        "evidence": sorted({s for p in providers for s in p["signals"]})[:2 * MAX_SIGNALS],
        "waf": {"state": state, "vendor": waf_vendor,
                "blocked_responses": blocked,
                "note": "Derived from recorded responses only. 'not_detected' means no "
                        "signal was observed, not that no WAF is present."},
        "cache": {"observed": observed > 0, "hits": hits,
                  "sensitive_cacheable": rows_meta.get("sensitive_cacheable", [])[:5]},
        "latency_ms": rows_meta.get("latency"),
    }
