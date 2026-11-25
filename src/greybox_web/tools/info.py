"""Debug-page and stack-trace disclosure check.

``info.errors`` refetches one endpoint and looks for the signatures of an error or
debug page: bare stack traces and framework debug banners (Django DEBUG, the
Werkzeug debugger, ASP.NET yellow screens, Spring Boot, Rails, JSP containers).
The traceback signatures are shared with the crawl's ``error_signature`` so both
views agree on what a disclosed error is. No payload is sent.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    excerpt,
)
from src.greybox_web.tools.discovery import ERROR_SIGNATURES

WSTG_ERRORS = ("https://wstg.owasp.org/latest/12-Error_Handling/"
               "01-Improper_Error_Handling")

# Framework debug/error banners: a debugging or configuration page is served.
DEBUG_SIGNATURES = (
    re.compile(r"(?i)Server Error in '/[^']*' Application"),      # ASP.NET
    re.compile(r"(?i)Runtime Error[\s\S]{0,400}?Stack Trace"),    # ASP.NET
    re.compile(r"(?i)javax\.servlet"),                            # JSP containers
    re.compile(r"(?i)Whitelabel Error Page"),                     # Spring Boot
    re.compile(r"(?i)ActionView::TemplateError|Rails::Info"),     # Rails
    re.compile(r"(?i)You're seeing this (?:error|exception) because"   # Django DEBUG
               r"[\s\S]{0,120}DEBUG\s*=\s*True"),
)
# Framework banners that live in the shared traceback table (Werkzeug debugger,
# Django version line, Laravel Whoops): a served debug page, not a bare trace.
_BANNER_WORDS = ("werkzeug", "django", "whoops")


def page_signature(text: str) -> tuple[str | None, bool]:
    """The first error/debug signature in ``text``: ``(matched text, debug
    banner?)``; ``(None, False)`` for a clean page. Debug banners rank above bare
    tracebacks — they are the more specific disclosure."""
    for rx in DEBUG_SIGNATURES:
        m = rx.search(text or "")
        if m:
            return m.group(0)[:120], True
    for rx in ERROR_SIGNATURES:
        m = rx.search(text or "")
        if m:
            return m.group(0)[:120], any(w in m.group(0).lower()
                                         for w in _BANNER_WORDS)
    return None, False


async def errors(ctx: ToolContext) -> ToolResult:
    """A refetched page that discloses a stack trace or a framework debug banner."""
    url = ctx.params["url"]
    resp = await ctx.http.get(url)
    signature, debug = page_signature(resp.text)
    path = urlsplit(url).path or "/"
    findings: list[FindingSpec] = []
    if signature:
        findings.append(FindingSpec(
            check_id="info.errors", detail="page",
            title=f"Error/debug page disclosed at {path}",
            severity="medium" if debug else "low", confidence="high",
            description=f"{url} answers with an error or debug page (matched: "
                        f"{signature!r}). Stack traces and framework debug banners "
                        f"disclose versions, file paths, queries and sometimes "
                        f"secrets, and debug consoles can be exploitable.",
            url=url, method="GET", asset_url=url,
            evidence=[Evidence(role="proof", exchange_id=resp.exchange_id,
                               excerpt=excerpt(resp.text, signature),
                               note="error/debug page signature")],
            verify={"url": url},
            cwe="CWE-489" if debug else "CWE-209",
            references=[{"title": "OWASP WSTG — improper error handling",
                         "url": WSTG_ERRORS}],
            detection_hints=[{
                "type": "waf_rule",
                "title": "Serve a generic error page",
                "content": "Answer failures with a generic error page — no stack "
                           "traces, framework banners or debug consoles — and "
                           "disable debug modes in production.",
            }],
            observation_key=f"info.errors|{url}"))
    obs = Observation(
        key=f"info.errors|{url}",
        label=f"error/debug page disclosed at {path}" if signature
        else f"no error/debug page at {path}",
        url=url, exchange_ids=resp.exchange_ids,
        facts={"signature": signature, "status": resp.status})
    return ToolResult(
        summary=f"GET {url} -> {resp.status}, "
                + ("error/debug page disclosed" if signature else "no error page"),
        counts={"probed": 1, "disclosed": 1 if signature else 0},
        observations=[obs], findings=findings)
