"""CORS policy check, logic ported from the retired legacy CLI pipeline.

Sends an inert ``Origin`` under the reserved ``.invalid`` TLD (never resolves,
RFC 2606) and inspects the reflection. Nothing is followed blindly: the response
is analysed, not acted on.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from src.greybox_web.netguard import TransportFailure  # noqa: F401  (re-exported for tests)
from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    excerpt,
    header_excerpt,
)

CORS_REF = "https://developer.mozilla.org/docs/Web/HTTP/CORS"


def probe_origin(token: str) -> str:
    return f"https://vigilo-probe-{token}.invalid"


def _hints(mode: str) -> list[dict[str, str]]:
    return [
        {
            "type": "log_signature",
            "title": "Probe origin in access logs",
            "content": "Vigilo sends Origin headers whose host ends in "
                        ".invalid (e.g. https://vigilo-probe-<hex>.invalid); "
                        "such lines in the access log are this check, not an attack.",
        },
        {
            "type": "siem_query",
            "title": "CORS reflection attempts",
            "content": 'web.accesslog where to_lower(origin) like "%.invalid%" '
                       "and status in (200, 204) | count by host, path",
        },
        {
            "type": "waf_rule",
            "title": "Do not echo arbitrary origins",
            "content": "Reject responses whose Access-Control-Allow-Origin equals the "
                       "request Origin unless the origin is on an explicit allow-list; "
                       f"never combine reflection with "
                       f"Access-Control-Allow-Credentials: true ({mode}).",
        },
    ]


async def policy(ctx: ToolContext) -> ToolResult:
    url = ctx.params["url"]
    origin = probe_origin(ctx.token())
    resp = await ctx.http.get(url, headers=[("Origin", origin)])
    acao = resp.header("access-control-allow-origin")
    acac = (resp.header("access-control-allow-credentials") or "").strip().lower() == "true"
    findings: list[FindingSpec] = []
    mode: str | None = None
    if acao == origin and acac:
        mode = "reflect"
        findings.append(FindingSpec(
            check_id="cors.policy", detail="reflected-with-credentials",
            title="CORS reflects arbitrary origins with credentials",
            severity="high", confidence="high",
            description=f"{url} echoes any request Origin into "
                        f"Access-Control-Allow-Origin together with "
                        f"Access-Control-Allow-Credentials: true. Any origin can read "
                        f"authenticated responses from this endpoint cross-site.",
            url=url, method="GET",
            evidence=[Evidence(role="proof", exchange_id=resp.exchange_id,
                               excerpt=excerpt(header_excerpt(resp.headers, (
                                   "access-control-allow-origin",
                                   "access-control-allow-credentials", "origin"))),
                               note="probe response headers")],
            verify={"url": url, "mode": mode},
            cwe="CWE-942",
            references=[{"title": "CORS (MDN)", "url": CORS_REF}],
            detection_hints=_hints("reflection"),
            observation_key=f"cors.policy|{url}",
            # one CORS policy per service: further URLs are locations of it
            identity=f"service:{urlsplit(url).netloc}", occurrence=url))
    elif acao == "*" and acac:
        mode = "star"
        findings.append(FindingSpec(
            check_id="cors.policy", detail="star-with-credentials",
            title="CORS allows all origins with credentials",
            severity="medium", confidence="medium",
            description=f"{url} sends Access-Control-Allow-Origin: * together with "
                        f"Access-Control-Allow-Credentials: true. Browsers reject this "
                        f"combination, but it signals a misconfigured CORS policy that "
                        f"changes to a dangerous one with a small edit.",
            url=url, method="GET",
            evidence=[Evidence(role="proof", exchange_id=resp.exchange_id,
                               excerpt=excerpt(header_excerpt(resp.headers, (
                                   "access-control-allow-origin",
                                   "access-control-allow-credentials"))),
                               note="probe response headers")],
            verify={"url": url, "mode": mode},
            cwe="CWE-942",
            references=[{"title": "CORS (MDN)", "url": CORS_REF}],
            detection_hints=_hints("wildcard"),
            observation_key=f"cors.policy|{url}",
            # one CORS policy per service: further URLs are locations of it
            identity=f"service:{urlsplit(url).netloc}", occurrence=url))
    obs = Observation(
        key=f"cors.policy|{url}",
        label=f"ACAO reflects probe origin{'+credentials' if acac else ''}"
        if acao == origin else f"no origin reflection on {url}",
        url=url, exchange_ids=resp.exchange_ids,
        facts={"status": resp.status, "acao": acao, "acac": acac,
               "probe_origin": origin})
    return ToolResult(summary=f"cors on {url}: acao={acao!r}, credentials={acac}",
                      counts={"status": resp.status, "reflected": acao == origin,
                              "credentials": acac},
                      observations=[obs], findings=findings)
