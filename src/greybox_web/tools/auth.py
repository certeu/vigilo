"""Default-credential check: only when the scope allows it.

A login form is a standing weakness when it still accepts well-known default
pairs. At most five FIXED pairs are tried; each response is compared with a
baseline built from a certainly-invalid random pair, and the first working pair
stops the check. Redirects are never followed, so nothing beyond the login
answer itself is ever requested. ``scope.allow_auth_testing`` is the hard guard:
without it the tool makes no request at all (the platform also drops the check
from the run's selected checks — defence in depth).
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from src.greybox_web.netguard import REDIRECT_CODES, HttpResponse
from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    cookies,
    excerpt,
)

# The fixed, well-known pairs (at most five, never generated).
PAIRS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("test", "test"),
)

WSTG_CREDS = "https://wstg.owasp.org/latest/08-Authentication/01-Default_Credentials"
WSTG_AUTHZ = ("https://wstg.owasp.org/latest/05-Authorization/"
              "02-Testing-for-IDOR")


def cookie_from_response(resp: HttpResponse) -> str | None:
    """A Cookie header value from a login response's Set-Cookie headers
    (``name=value`` pairs; flags and attributes dropped). None when none set."""
    pairs = [h.split(";", 1)[0].strip() for h in resp.header_all("set-cookie")]
    pairs = [p for p in pairs if "=" in p]
    return "; ".join(pairs) or None

HINTS = [
    {
        "type": "log_signature",
        "title": "Default-credential attempts are this check",
        "content": "Login requests carrying admin/admin, admin/password, "
                   "admin/admin123, root/root or test/test are this Vigilo check "
                   "(auth.default_creds), not an attack; it runs only when the "
                   "target's scope allows authentication testing.",
    },
    {
        "type": "waf_rule",
        "title": "Remove default accounts",
        "content": "Delete vendor default accounts, force a password change on "
                   "first login and enforce a strong password policy.",
    },
]


def login_url(url: str, user_field: str, password_field: str, user: str,
              password: str) -> str:
    """``url`` with the two login fields set in the query string (GET-method form)."""
    parts = urlsplit(url)
    keep = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k not in (user_field, password_field)]
    keep += [(user_field, user), (password_field, password)]
    return urlunsplit(parts._replace(query=urlencode(keep)))


async def send_pair(ctx: ToolContext, url: str, user_field: str,
                    password_field: str, user: str, password: str,
                    method: str = "POST") -> HttpResponse:
    """One login request. Redirects are never followed: the answer itself (status,
    Set-Cookie, Location) is the whole observation."""
    if method == "GET":
        return await ctx.http.get(
            login_url(url, user_field, password_field, user, password),
            follow=False)
    return await ctx.http.post(url, {user_field: user, password_field: password})


def success_indicator(base: HttpResponse, attempt: HttpResponse) -> str | None:
    """How a pair's response differs from the certainly-invalid baseline: a
    different status, a newly set cookie, or a different redirect target. ``None``
    when the pair behaves exactly like the baseline."""
    if attempt.status != base.status:
        return "status"
    if attempt.header_all("set-cookie") and not base.header_all("set-cookie"):
        return "set_cookie"
    if (attempt.status in REDIRECT_CODES and base.status in REDIRECT_CODES
            and attempt.header("location") != base.header("location")):
        return "location"
    return None


def _excerpt(resp: HttpResponse) -> str:
    lines = [f"HTTP {resp.status}"]
    # cookie VALUES are live credentials: masked (name and flags stay, so the
    # analyst still sees what was issued)
    lines += [f"Set-Cookie: {cookies.masked(c)}"
              for c in resp.header_all("set-cookie")]
    if resp.header("location"):
        lines.append(f"Location: {resp.header('location')}")
    return excerpt("\n".join(lines))


async def default_creds(ctx: ToolContext) -> ToolResult:
    """The fixed default pairs against a detected login form, first hit wins."""
    url = ctx.params["url"]
    if not ctx.scope.allow_auth_testing:       # the hard guard: no request at all
        return ToolResult(
            summary="authentication testing not allowed by the scope",
            counts={"skipped": 1},
            observations=[Observation(
                key=f"auth.default_creds|{url}",
                label="default-credentials check skipped: auth testing disabled",
                url=url, facts={"reason": "allow_auth_testing"})])
    user_field = ctx.params.get("user_field") or "user"
    password_field = ctx.params.get("password_field") or "password"
    method = (ctx.params.get("method") or "POST").upper()
    token = ctx.token()
    base = await send_pair(ctx, url, user_field, password_field,
                           f"vgl{token}", f"vgl{token}", method)
    findings: list[FindingSpec] = []
    worked: str | None = None
    worked_password = ""
    indicator: str | None = None
    tried = 0
    for user, password in PAIRS:               # the first working pair wins
        tried += 1
        resp = await send_pair(ctx, url, user_field, password_field,
                               user, password, method)
        fired = success_indicator(base, resp)
        if fired is None:
            continue
        worked, worked_password, indicator = user, password, fired
        findings.append(FindingSpec(
            check_id="auth.default_creds", detail=f"{user}:{password}",
            title=f"Working default credentials: {user}/{password}",
            severity="high", confidence="high",
            description=f"The login form at {url} accepts the well-known default "
                        f"pair {user}/{password} (fields {user_field} / "
                        f"{password_field}): the response differs from an invalid "
                        f"baseline by its {fired} indicator. Anyone can sign in "
                        f"with credentials published in the product's "
                        f"documentation.",
            url=url, method=method, asset_url=url,
            evidence=[Evidence(role="proof", exchange_id=resp.exchange_id,
                               excerpt=_excerpt(resp),
                               note=f"success indicator: {fired}")],
            verify={"url": url, "user_field": user_field,
                    "password_field": password_field, "method": method,
                    "user": user, "password": password, "expect": "success"},
            cwe="CWE-798",
            references=[{"title": "OWASP WSTG — default credentials",
                         "url": WSTG_CREDS}],
            detection_hints=HINTS,
            observation_key=f"auth.default_creds|{url}"))
        break
    path = urlsplit(url).path or "/"
    obs = Observation(
        key=f"auth.default_creds|{url}",
        label=f"default credentials {worked}/{worked_password} work on {path}"
        if worked else f"no default credentials worked ({tried} pairs)",
        url=url, exchange_ids=base.exchange_ids,
        facts={"user_field": user_field, "password_field": password_field,
               "pairs_tried": tried, "worked": worked, "indicator": indicator})
    return ToolResult(
        summary=f"default-credential pairs on {path}: "
                + (f"{worked}/{worked_password} works ({indicator})" if worked
                   else "none accepted"),
        counts={"pairs_tried": tried, "baseline": 1, "worked": 1 if worked else 0},
        observations=[obs], findings=findings)


# ------------------------------------------------------------------ login helpers
# Field names under which login APIs commonly return a bearer token (top level or
# one level down: {"data": {"token": ...}}). The token becomes the identity's
# Authorization header; it is never shown to the agent or stored in events.
TOKEN_KEYS = ("access_token", "accessToken", "token", "id_token", "jwt",
              "session_token", "sessionToken", "auth_token", "authToken")
TOKEN_NESTS = ("data", "result", "session", "auth", "tokens")
_HIDDEN_RE = re.compile(r"<input\b[^>]*>", re.I)
_ATTR_RE = re.compile(r"""(\w[\w-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""")
LOGIN_BODIES = ("auto", "form", "json", "jsonrpc")


def token_from_body(resp: HttpResponse) -> tuple[str | None, str]:
    """(bearer token, scheme) from a JSON login answer, or (None, "")."""
    if "json" not in (resp.content_type or "") and not resp.text.lstrip().startswith("{"):
        return None, ""
    try:
        doc = json.loads(resp.text)
    except ValueError:
        return None, ""
    if not isinstance(doc, dict):
        return None, ""
    scopes = [doc] + [doc[k] for k in TOKEN_NESTS if isinstance(doc.get(k), dict)]
    for d in scopes:
        for k in TOKEN_KEYS:
            v = d.get(k)
            if isinstance(v, str) and len(v) >= 16 and " " not in v:
                scheme = str(d.get("token_type") or doc.get("token_type") or "Bearer")
                return v, ("Bearer" if scheme.lower() == "bearer" else scheme[:20])
    return None, ""


def hidden_fields(html: str, skip: set[str]) -> dict[str, str]:
    """Hidden inputs of the page's forms (CSRF tokens and the like), by name."""
    out: dict[str, str] = {}
    for tag in _HIDDEN_RE.findall(html or "")[:60]:
        attrs = {k.lower(): v.strip("\"'") for k, v in _ATTR_RE.findall(tag)}
        if attrs.get("type", "").lower() == "hidden" and attrs.get("name") \
                and attrs["name"] not in skip:
            out[attrs["name"]] = attrs.get("value", "")
    return out


async def _preflight(ctx: ToolContext, url: str, skip: set[str]
                     ) -> tuple[dict[str, str], str | None, list[int]]:
    """Fetch the login page once, anonymously: hidden form fields (CSRF tokens)
    and the pre-session cookie a CSRF-protected form needs to be accepted."""
    try:
        page = await ctx.http.get(url, session="anon")
    except Exception:                                   # noqa: BLE001
        return {}, None, []
    if page.status >= 400 or "html" not in (page.content_type or ""):
        return {}, cookie_from_response(page), list(page.exchange_ids)
    return (hidden_fields(page.text, skip), cookie_from_response(page),
            list(page.exchange_ids))


async def send_login(ctx: ToolContext, url: str, user_field: str,
                     password_field: str, user: str, password: str,
                     method: str = "POST", body: str = "form"
                     ) -> tuple[HttpResponse, str | None, list[int]]:
    """One login attempt the way a client of this endpoint would send it:
    a form (with the page's hidden CSRF fields and pre-session cookie when the
    login page has them) or a JSON document. Returns (response, the pre-session
    cookie that was sent, preflight exchange ids). Redirects are not followed."""
    if method == "GET":
        return await send_pair(ctx, url, user_field, password_field, user, password,
                               method), None, []
    if body in ("json", "jsonrpc"):
        payload = {user_field: user, password_field: password}
        if body == "jsonrpc":
            payload = {"jsonrpc": "2.0", "method": "auth.login",
                       "params": payload, "id": 1}
        resp = await ctx.http.request(
            "POST", url, body=json.dumps(payload),
            content_type="application/json", follow=False, session="anon",
            headers=[("Accept", "application/json")])
        return resp, None, []
    hidden, pre_cookie, pre_ids = await _preflight(ctx, url, {user_field, password_field})
    if not hidden and not pre_cookie:
        return await send_pair(ctx, url, user_field, password_field, user, password,
                               method), None, pre_ids
    form = {**hidden, user_field: user, password_field: password}
    resp = await ctx.http.request(
        "POST", url, body=urlencode(form),
        content_type="application/x-www-form-urlencoded", follow=False,
        session="anon", cookie=pre_cookie or "")
    return resp, pre_cookie, pre_ids


def merge_cookies(pre: str | None, resp: HttpResponse) -> str | None:
    """The identity's Cookie header: the pre-session cookie updated by the login
    answer's Set-Cookie (a rotated session id replaces the pre-session one)."""
    jar: dict[str, str] = {}
    for part in (pre or "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            jar[k] = v
    for part in (cookie_from_response(resp) or "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            jar[k] = v
    return "; ".join(f"{k}={v}" for k, v in jar.items()) or None



async def login(ctx: ToolContext) -> ToolResult:
    """Establish a session for one of the target's login accounts: send the login
    form, and on success register the session's cookies for every later tool of
    this run. Not a finding — an instrument (the account came from the operator)."""
    url = ctx.params["url"]
    label = str(ctx.params.get("account") or "")
    if not ctx.scope.allow_auth_testing:            # the narrowing still applies
        return ToolResult(
            summary="authentication testing not allowed by the scope",
            counts={"skipped": 1},
            observations=[Observation(
                key=f"auth.login|{url}",
                label="login skipped: auth testing disabled", url=url,
                facts={"reason": "allow_auth_testing", "account": label})])
    secret = (ctx.account_credentials(label) if ctx.account_credentials else None) \
        if label else None
    if secret is None:
        return ToolResult(
            summary=f"unknown account {label!r} on {url}",
            counts={"skipped": 1},
            observations=[Observation(
                key=f"auth.login|{url}",
                label=f"login failed before any request: unknown account {label!r}",
                url=url, facts={"account": label, "known": [
                    a[0] for a in (ctx.accounts or [])]})])
    configured_url = str(secret.get("login_url") or "").strip()
    if configured_url:
        url = urljoin(ctx.base_url, configured_url)
    user_field = str(ctx.params.get("user_field")
                     or secret.get("user_field") or "user")
    password_field = str(ctx.params.get("password_field")
                         or secret.get("password_field") or "password")
    method = str(ctx.params.get("method") or secret.get("method") or "POST").upper()
    want = str(ctx.params.get("body") or secret.get("body") or "auto").lower()
    if want not in LOGIN_BODIES:
        want = "auto"
    path = urlsplit(url).path or "/"
    token = ctx.token()
    tried: list[str] = []
    resp = base = None
    pre_cookie: str | None = None
    indicator: str | None = None
    ids: list[int] = []
    # "auto": a form first (what an HTML login expects), then a JSON document when
    # the form was not understood (an API login): both are what a legitimate
    # client of this endpoint sends, with the operator's own account.
    for body in (["form", "json", "jsonrpc"] if want == "auto" else [want]):
        tried.append(body)
        base, _, pre_ids = await send_login(ctx, url, user_field, password_field,
                                            f"vgl{token}", f"vgl{token}", method, body)
        resp, pre_cookie, pre_ids2 = await send_login(
            ctx, url, user_field, password_field, str(secret["user"]),
            str(secret["password"]), method, body)
        ids += pre_ids + pre_ids2 + base.exchange_ids + resp.exchange_ids
        indicator = success_indicator(base, resp)
        bearer, _ = token_from_body(resp)
        if indicator is None and bearer and not token_from_body(base)[0]:
            indicator = "token"
        if indicator is not None and resp.status < 400:
            break
        if method == "GET":
            break
    if indicator is None or resp.status >= 400:
        return ToolResult(
            summary=f"login as {label} on {path}: rejected (like the invalid "
                    f"baseline; tried {'/'.join(tried)})",
            counts={"requests": len(ids), "established": 0},
            observations=[Observation(
                key=f"auth.login|{url}|{label}",
                label=f"account {label} could not log in on {path} (no difference "
                      "from an invalid pair)",
                url=url, exchange_ids=ids[:20],
                facts={"account": label, "user": secret["user"], "bodies": tried,
                       "indicator": indicator, "status": resp.status})])
    cookie = merge_cookies(pre_cookie, resp) if cookie_from_response(resp) else None
    bearer, scheme = token_from_body(resp)
    authorization = resp.header("authorization") or (
        f"{scheme} {bearer}" if bearer else None)
    if cookie is None and authorization is None:
        return ToolResult(
            summary=f"login as {label} on {path}: accepted ({indicator}) but no "
                    "session token was set",
            counts={"requests": len(ids), "established": 0},
            observations=[Observation(
                key=f"auth.login|{url}|{label}",
                label=f"account {label} logged in on {path} but the response set "
                      "no cookie or token: nothing to reuse",
                url=url, exchange_ids=resp.exchange_ids,
                facts={"account": label, "user": secret["user"],
                       "indicator": indicator, "status": resp.status})])
    ctx.http.establish_session(label, cookie, authorization)
    names = [p.split("=", 1)[0] for p in (cookie or "").split("; ") if "=" in p]
    return ToolResult(
        summary=f"session established for account {label} on {path} "
                f"({indicator}; {tried[-1]} body"
                + ("; bearer token" if authorization else "") + ")",
        counts={"requests": len(ids), "established": 1},
        observations=[Observation(
            key=f"auth.login|{url}|{label}",
            label=f"session for account {label} (user {secret['user']}) "
                  f"established on {path}",
            url=url, exchange_ids=resp.exchange_ids,
            facts={"account": label, "user": secret["user"],
                   "indicator": indicator, "cookie_names": names,
                   "body": tried[-1],
                   "authorization": bool(authorization), "status": resp.status})])


async def session_recover(ctx: ToolContext) -> ToolResult:
    """Check one configured identity and recover it through supported login only."""
    from src.greybox_web import session_recovery

    identity = str(ctx.params.get("account") or "")
    probe_url = str(ctx.params.get("probe_url") or ctx.params.get("url")
                    or ctx.base_url)
    login_url = str(ctx.params.get("login_url") or "").strip() or None
    if ctx.scope.allow_auth_testing:
        result = await session_recovery.recover(ctx, identity, probe_url, login_url)
    else:
        result = await session_recovery.probe(ctx, identity, probe_url)
    blocked = not result.usable and not ctx.scope.allow_auth_testing
    state = "blocked" if blocked else result.state
    reason = (result.reason + "; recovery requires allow_auth_testing") \
        if blocked else result.reason
    recovered = False if blocked else result.recovered
    counts = {
        "checked": 1,
        "usable": int(result.usable),
        "recovered": int(recovered),
        "blocked": int(blocked),
    }
    return ToolResult(
        summary=f"session {identity!r}: {state}" + (
            " (recovered)" if recovered else ""),
        counts=counts,
        observations=[Observation(
            key=f"auth.session_recover|{identity}|{probe_url}",
            label=f"session {identity!r} is {state}",
            url=probe_url,
            exchange_ids=list(result.exchange_ids),
            facts={
                "account": identity,
                "state": state,
                "reason": reason,
                "usable": result.usable,
                "recovered": recovered,
            })])

