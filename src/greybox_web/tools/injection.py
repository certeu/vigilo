"""Injection and redirect checks: reflected canary, error-based
indicators, open redirect.

Payloads are inert (design "safety properties of payloads"): a fixed canary
(``vgl<8hex>"'<>b``) that only an *unencoded* reflection carries verbatim, a single
quote appended to a parameter's normal value, and an
``https://vigilo-probe-<rand>.invalid/`` URL (RFC 2606: ``.invalid`` never
resolves) whose only use is to be read back from a Location header — it is never
followed. Nothing here builds SQL, executes anything or calls out of band; all
I/O goes through ``ctx.http``.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from src.greybox_web.netguard import REDIRECT_CODES, HttpResponse
from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    excerpt,
)
from src.greybox_web.tools.discovery import ERROR_SIGNATURES

WSTG_XSS = "https://wstg.owasp.org/latest/11-Injection/01-Reflected_Cross_Site_Scripting"
WSTG_SQL = "https://wstg.owasp.org/latest/11-Injection/04-SQL_Injection"
WSTG_ERRORS = ("https://wstg.owasp.org/latest/12-Error_Handling/"
               "01-Improper_Error_Handling")
WSTG_REDIRECT = "https://wstg.owasp.org/latest/11-Injection/23-Server-side_URL_Redirect"


# ------------------------------------------------------------- inert payloads

def canary(token: str) -> str:
    """The reflection canary: a random marker plus the characters an unencoded
    reflection would carry (``vgl<8hex>"'<>``); the trailing ``b`` makes
    the HTML context visible."""
    return f"vgl{token}\"'<>b"


def probe_host(token: str) -> str:
    """A random host under ``.invalid`` (RFC 2606: guaranteed not to resolve)."""
    return f"vigilo-probe-{token}.invalid"


def with_query_param(url: str, name: str, value: str) -> str:
    """``url`` with query parameter ``name`` SET to ``value``; other parameters and
    their order are preserved."""
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != name]
    pairs.append((name, value))
    return urlunsplit(parts._replace(query=urlencode(pairs)))


def baseline_value(url: str, param: str, location: str) -> str:
    """The parameter's current value (query location), or ``test``: what a normal
    request carries, and the base the single quote is appended to."""
    if location != "form":
        for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if k == param and v:
                return v
    return "test"


async def send_value(ctx: ToolContext, url: str, param: str, location: str,
                     value: str, *, follow: bool = True) -> HttpResponse:
    """One request carrying ``value`` in ``param``: GET (query) or the form-encoded
    POST a discovered form declared. Scope and transport failures propagate (the
    supervisor records them and retries or fails the work order)."""
    if location == "form":
        return await ctx.http.post(url, {param: value})
    return await ctx.http.get(with_query_param(url, param, value), follow=follow)


# ------------------------------------------------------------- detection

def reflected_unencoded(resp: HttpResponse, mark: str) -> bool:
    """The exact canary — including its raw ``< > " '`` characters — appears in an
    HTML response (status < 500: a 5xx body echo is noise, not a reflection)."""
    return resp.is_html and resp.status < 500 and mark in resp.text


# Conservative database-error text. Never bare "select from" prose.
SQL_SIGNATURES = (
    re.compile(r"(?i)you have an error in your sql syntax"),
    re.compile(r"(?i)sql syntax"),
    re.compile(r"(?i)sqlstate\["),
    re.compile(r"(?i)ora-\d{5}"),
    re.compile(r"(?i)psycopg2\."),
    re.compile(r"(?i)sqlite3?\."),
    re.compile(r"(?i)mysql_fetch"),
    re.compile(r"(?i)warning: mysql_"),
    re.compile(r"(?i)postgres.*error"),
    re.compile(r"(?i)unterminated quoted string"),
    re.compile(r"(?i)odbc driver"),
    re.compile(r"(?i)microsoft ole db"),
    re.compile(r"(?i)sql server error"),
    re.compile(r"(?i)jdbc \w*exception"),
    re.compile(r"(?i)doctrine\\dbal"),
)


def error_indicator(probe: str, baseline: str) -> tuple[str | None, bool]:
    """The first signature the single-quote probe *newly* triggers: present in the
    probe response and absent from the baseline (the comparison is the indicator).
    Returns ``(matched text, is_sql)``, or ``(None, False)`` when clean."""
    for rx in SQL_SIGNATURES:
        m = rx.search(probe or "")
        if m and not rx.search(baseline or ""):
            return m.group(0)[:120], True
    for rx in ERROR_SIGNATURES:
        m = rx.search(probe or "")
        if m and not rx.search(baseline or ""):
            return m.group(0)[:120], False
    return None, False


# ------------------------------------------------------------- checks

SIEM_QUERY = ('web.accesslog where to_lower(url) like "%vgl%" '
              'or to_lower(url) like "%vigilo-probe%" | count by host, path')


def _hints(check: str, log_signature: str, hardening: str) -> list[dict[str, str]]:
    return [
        {"type": "log_signature", "title": f"Probe values of {check}",
         "content": log_signature},
        {"type": "siem_query", "title": "Vigilo probe traffic",
         "content": SIEM_QUERY},
        {"type": "waf_rule", "title": "Blunt the probe at the edge",
         "content": hardening},
    ]


REFLECTION_LOG = ("GET/POST lines whose query or form parameter carries a value "
                  "like vgl<hex>\"'<>b are this Vigilo canary (injection."
                  "reflection), not an attack.")
REFLECTION_WAF = ("Encode untrusted values by output context (element body, "
                  "attribute, JavaScript, URL); a reflection that still carries "
                  "raw <, >, \" or ' characters is exploitable.")
ERRORS_LOG = ("Requests whose parameter value is a normal value with a single "
              "quote appended (e.g. id=1%27) are this Vigilo check (injection."
              "errors), not an attack.")
ERRORS_WAF = ("Use parameterised queries everywhere and answer failures with a "
              "generic error page — no SQL text, stack traces or framework "
              "banners.")
REDIRECT_LOG = ("Requests whose redirect parameter carries an https://vigilo-"
                "probe-<hex>.invalid/ value are this Vigilo check (redirect.open); "
                "the host never resolves and is never contacted.")
REDIRECT_WAF = ("Resolve redirect targets server-side against an allow-list of "
                "paths and hosts; never pass a user-controlled value straight into "
                "a Location header.")


async def reflection(ctx: ToolContext) -> ToolResult:
    """An inert canary reflected unencoded into an HTML response (potential XSS)."""
    url = ctx.params["url"]
    param = ctx.params["param"]
    location = ctx.params.get("location") or "query"
    mark = canary(ctx.token())                 # one canary per run of the tool
    resp = await send_value(ctx, url, param, location, mark)
    method = "POST" if location == "form" else "GET"
    reflected = reflected_unencoded(resp, mark)
    path = urlsplit(url).path or "/"
    findings: list[FindingSpec] = []
    if reflected:
        findings.append(FindingSpec(
            check_id="injection.reflection", detail=f"{param}@{location}",
            title=f"Unencoded reflection of parameter {param} (potential XSS)",
            severity="medium", confidence="high",
            description=f"The value of {param} (sent in the {location}) is echoed "
                        f"into the HTML of {url} without encoding: the inert canary "
                        f"Vigilo sent, including its raw <, >, \" and ' characters, "
                        f"appears verbatim in the response. Whoever controls "
                        f"{param} controls markup and script in the page.",
            url=url, method=method, parameter=param, param_location=location,
            asset_url=url,
            evidence=[Evidence(role="proof", exchange_id=resp.exchange_id,
                               excerpt=excerpt(resp.text, mark),
                               note="unencoded canary reflection")],
            verify={"url": url, "param": param, "location": location},
            cwe="CWE-79",
            references=[{"title": "OWASP WSTG — reflected cross-site scripting",
                         "url": WSTG_XSS}],
            detection_hints=_hints("injection.reflection", REFLECTION_LOG,
                                   REFLECTION_WAF),
            observation_key=f"injection.reflection|{url}|{location}:{param}"))
    obs = Observation(
        key=f"injection.reflection|{url}|{location}:{param}",
        label=f"{param} on {path} reflects input unencoded" if reflected
        else f"no unencoded reflection of {param} on {path}",
        url=url, exchange_ids=resp.exchange_ids,
        facts={"param": param, "location": location, "reflected": reflected,
               "status": resp.status, "method": method})
    return ToolResult(
        summary=f"canary in {param}: "
                f"{'reflected unencoded' if reflected else 'not reflected'}",
        counts={"probed": 1, "reflected": 1 if reflected else 0},
        observations=[obs], findings=findings)


async def errors(ctx: ToolContext) -> ToolResult:
    """A single quote that triggers an SQL or stack-trace error the baseline does
    not carry (error-based injection indicator)."""
    url = ctx.params["url"]
    param = ctx.params["param"]
    location = ctx.params.get("location") or "query"
    base_value = baseline_value(url, param, location)
    probe_value = base_value + "'"
    base = await send_value(ctx, url, param, location, base_value)
    probe = await send_value(ctx, url, param, location, probe_value)
    method = "POST" if location == "form" else "GET"
    signature, sql = error_indicator(probe.text, base.text)
    findings: list[FindingSpec] = []
    if signature:
        findings.append(FindingSpec(
            check_id="injection.errors", detail=f"{param}@{location}",
            title=f"Error-based injection indicator on {param}",
            severity="high" if sql else "medium", confidence="high",
            description=f"Appending a single quote to the {location} parameter "
                        f"{param} makes {url} answer with a database error the "
                        f"normal request does not carry (matched: {signature!r}). "
                        f"The value likely reaches a SQL interpreter or an "
                        f"unhandled exception path.",
            url=url, method=method, parameter=param, param_location=location,
            asset_url=url,
            evidence=[Evidence(role="proof", exchange_id=probe.exchange_id,
                               excerpt=excerpt(probe.text, signature),
                               note="error signature present on the probe only")],
            verify={"url": url, "param": param, "location": location,
                    "value": probe_value},
            cwe="CWE-209",
            references=[{"title": "OWASP WSTG — SQL injection", "url": WSTG_SQL},
                        {"title": "OWASP WSTG — improper error handling",
                         "url": WSTG_ERRORS}],
            detection_hints=_hints("injection.errors", ERRORS_LOG, ERRORS_WAF),
            observation_key=f"injection.errors|{url}|{location}:{param}"))
    obs = Observation(
        key=f"injection.errors|{url}|{location}:{param}",
        label=f"{param} triggers an error the baseline does not carry" if signature
        else f"no error-based indicator on {param}",
        url=url, exchange_ids=base.exchange_ids + probe.exchange_ids,
        facts={"param": param, "location": location, "signature": signature,
               "baseline_status": base.status, "probe_status": probe.status,
               "indicator": signature is not None})
    return ToolResult(
        summary=f"single quote in {param}: "
                + (f"error signature {signature!r}" if signature
                   else "no indicator"),
        counts={"probed": 2, "indicator": 1 if signature else 0},
        observations=[obs], findings=findings)


async def open_redirect(ctx: ToolContext) -> ToolResult:
    """A redirect parameter that sends the user to an arbitrary host (the probe
    host is read back from Location, never followed)."""
    url = ctx.params["url"]
    param = ctx.params["param"]
    location = ctx.params.get("location") or "query"
    host = probe_host(ctx.token())
    resp = await send_value(ctx, url, param, location, f"https://{host}/",
                            follow=False)      # the target host is never requested
    method = "POST" if location == "form" else "GET"
    header = resp.header("location")
    target = (urlsplit(urljoin(resp.url, header)).hostname or "") if header else ""
    open_ = resp.status in REDIRECT_CODES and target == host
    findings: list[FindingSpec] = []
    if open_:
        findings.append(FindingSpec(
            check_id="redirect.open", detail=f"{param}@{location}",
            title=f"Open redirect through {param}",
            severity="medium", confidence="high",
            description=f"The {location} parameter {param} of {url} is used as the "
                        f"redirect target: the endpoint answered {resp.status} with "
                        f"a Location pointing at the host Vigilo chose ({host}, "
                        f"reserved .invalid, never contacted). An attacker can send "
                        f"users to any host through this endpoint, e.g. in phishing "
                        f"links that keep the trusted domain.",
            url=url, method=method, parameter=param, param_location=location,
            asset_url=url,
            evidence=[Evidence(role="proof", exchange_id=resp.exchange_id,
                               excerpt=excerpt(f"Location: {header}", header),
                               note="redirect target is the probe host")],
            verify={"url": url, "param": param, "location": location},
            cwe="CWE-601",
            references=[{"title": "OWASP WSTG — server-side URL redirect",
                         "url": WSTG_REDIRECT}],
            detection_hints=_hints("redirect.open", REDIRECT_LOG, REDIRECT_WAF),
            observation_key=f"redirect.open|{url}|{location}:{param}"))
    obs = Observation(
        key=f"redirect.open|{url}|{location}:{param}",
        label=f"{param} redirects to an arbitrary host" if open_
        else f"{param} does not redirect to an arbitrary host",
        url=url, exchange_ids=resp.exchange_ids,
        facts={"param": param, "location": location, "status": resp.status,
               "location_header": target or None, "open": open_})
    return ToolResult(
        summary=f"redirect target in {param}: "
                + (f"arbitrary host accepted ({resp.status})" if open_
                   else "not arbitrary"),
        counts={"probed": 1, "open": 1 if open_ else 0},
        observations=[obs], findings=findings)
