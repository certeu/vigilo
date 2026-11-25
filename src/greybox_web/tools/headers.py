"""Security-header and version-disclosure checks.

Logic ported from the retired legacy CLI pipeline into the guarded tool
interface: one GET of the target URL, then pure response analysis. Payloads are
inert (no payload at all); every request goes through ``ctx.http``.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from src.greybox_web.netguard import ScopeViolation, TransportFailure
from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    excerpt,
    header_excerpt,
)

# (name, title, severity, cwe, reference) — checked for presence/value.
HEADER_CHECKS: tuple[tuple[str, str, str, str, str], ...] = (
    ("content-security-policy", "Content-Security-Policy", "medium", "CWE-693",
     "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options: nosniff", "low", "CWE-430",
     "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy", "low", "CWE-200",
     "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"),
)

XFO_REF = "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"
HSTS_REF = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"
MDN_SERVER = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Server"

# name with a version suffix, e.g. "DemoServer/1.2.3", "Apache/2.4.52 (Debian)"
VERSION_BANNER = re.compile(r"(?i)^[a-z][a-z0-9 _.-]*/\s*v?[0-9][0-9a-z.\-+_]*")
DISCLOSURE_HEADERS = ("server", "x-powered-by")


def _frame_ancestors(csp: str | None) -> bool:
    return bool(csp) and "frame-ancestors" in csp.lower()


async def security(ctx: ToolContext) -> ToolResult:
    """One finding per missing security header (severity per header)."""
    url = ctx.params["url"]
    resp = await ctx.http.get(url)   # primary URL: transport failures propagate
    headers_line = header_excerpt(resp.headers)
    findings: list[FindingSpec] = []
    missing: list[str] = []
    hints = [{
        "type": "waf_rule",
        "title": "Add the missing security headers at the reverse proxy",
        "content": "Set Content-Security-Policy, X-Content-Type-Options: nosniff, "
                   "X-Frame-Options (or CSP frame-ancestors) and Referrer-Policy on "
                   "every response; add Strict-Transport-Security on https.",
    }]

    def miss(name: str, title: str, severity: str, cwe: str, ref: str,
             note: str) -> None:
        missing.append(name)
        findings.append(FindingSpec(
            check_id="headers.security", detail=f"missing:{name}",
            title=f"Missing {title} header", severity=severity, confidence="high",
            description=f"The response from {url} does not send the {title} header. "
                        f"{note}",
            url=url, method="GET",
            evidence=[Evidence(role="proof", exchange_id=resp.exchange_id,
                               excerpt=excerpt(headers_line) or "(no headers)",
                               note="response headers")],
            verify={"url": url, "header": name, "expect": "absent"},
            # A header is set (or not) by the service, not by the path: "missing CSP"
            # on five pages is one finding naming five locations, not five findings
            # (defect F4). The first sighting keeps the proof.
            identity=f"service:{urlsplit(url).netloc}", occurrence=url,
            cwe=cwe, references=[{"title": f"{title} (MDN)", "url": ref}],
            detection_hints=hints,
            observation_key=f"headers.security|{url}|{name}"))

    for name, title, severity, cwe, ref in HEADER_CHECKS:
        if resp.header(name) is None:
            note = {"content-security-policy":
                    "Without a policy the page can load arbitrary scripts.",
                    "x-content-type-options":
                    "Without nosniff browsers may sniff the content type.",
                    "referrer-policy":
                    "Without a policy full URLs may leak to third parties."}[name]
            miss(name, title, severity, cwe, ref, note)

    if (resp.header("x-frame-options") is None
            and not _frame_ancestors(resp.header("content-security-policy"))):
        miss("x-frame-options", "X-Frame-Options or CSP frame-ancestors", "low",
             "CWE-1021", XFO_REF,
             "The page can be framed, enabling clickjacking.")

    if url.startswith("https://"):
        hsts = resp.header("strict-transport-security")
        if hsts is None or "max-age=0" in hsts.lower():
            miss("strict-transport-security", "Strict-Transport-Security", "medium",
                 "CWE-319", HSTS_REF,
                 "Clients may downgrade the connection to plain http.")

    obs = Observation(
        key=f"headers.security|{url}",
        label=f"{len(missing)} security headers missing on {url}"
        if missing else f"security headers present on {url}",
        url=url, exchange_ids=resp.exchange_ids,
        facts={"status": resp.status, "missing": missing,
               "present": [h for h, _, _, _, _ in HEADER_CHECKS
                           if resp.header(h) is not None]})
    summary = (f"{len(missing)} missing security headers on {url}"
               if missing else f"security headers present on {url}")
    return ToolResult(summary=summary, counts={"status": resp.status,
                                               "missing": len(missing)},
                      observations=[obs], findings=findings)


async def disclosure(ctx: ToolContext) -> ToolResult:
    """`Server` / `X-Powered-By` banners that reveal a software version."""
    url = ctx.params["url"]
    resp = await ctx.http.get(url)
    findings: list[FindingSpec] = []
    seen: list[str] = []
    for name in DISCLOSURE_HEADERS:
        value = resp.header(name)
        if not value or not VERSION_BANNER.match(value.strip()):
            continue
        seen.append(f"{name}: {value.strip()}")
        findings.append(FindingSpec(
            check_id="headers.disclosure", detail=f"version:{name}",
            title=f"{name} header reveals a software version",
            severity="low" if name == "server" else "info", confidence="high",
            description=f"The response from {url} advertises `{name}: {value.strip()}`, "
                        "which identifies the software and its version and helps an "
                        "attacker match known vulnerabilities.",
            url=url, method="GET",
            evidence=[Evidence(role="proof", exchange_id=resp.exchange_id,
                               excerpt=excerpt(header_excerpt(resp.headers, (name,))),
                               note="banner header")],
            verify={"url": url, "header": name, "value": value.strip()},
            cwe="CWE-200",
            references=[{"title": "Server header (MDN)", "url": MDN_SERVER}],
            detection_hints=[{
                "type": "waf_rule",
                "title": "Strip version banners at the edge",
                "content": f"Remove or generalise the {name} header on every response.",
            }],
            observation_key=f"headers.disclosure|{url}|{name}"))
    obs = Observation(key=f"headers.disclosure|{url}",
                      label=f"version banners: {'; '.join(seen)}" if seen
                      else f"no version banners on {url}",
                      url=url, exchange_ids=resp.exchange_ids,
                      facts={"status": resp.status, "banners": seen})
    return ToolResult(
        summary=f"{len(seen)} version banner(s) on {url}" if seen
        else f"no version banners on {url}",
        counts={"status": resp.status, "banners": len(seen)},
        observations=[obs], findings=findings)
