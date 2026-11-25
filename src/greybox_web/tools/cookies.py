"""Cookie-flag check: HttpOnly, Secure (https) and SameSite.

The evidence excerpt is pre-masked here (cookie value replaced) so the finding
never carries the value even before persistence redaction; the exchange row is
masked structurally by ``redaction.headers`` the same way.
"""
from __future__ import annotations

from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    excerpt,
)

COOKIE_REF = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie"
# Cookie names that typically carry a session -> missing flags are worse.
SESSION_COOKIE = ("session", "sid", "sess", "auth", "token", "login", "jwt", "phpsessid")


def parse_set_cookie(line: str) -> tuple[str, list[str]]:
    """``name=value; Flag; Attr=v`` -> (name lowercased, attribute list lowercased)."""
    parts = [p.strip() for p in line.split(";")]
    name = parts[0].split("=", 1)[0].strip().lower() if "=" in parts[0] else ""
    return name, [p.lower() for p in parts[1:]]


def masked(line: str) -> str:
    first, sep, rest = line.partition(";")
    name, eq, _ = first.partition("=")
    if not eq:
        return first
    return f"{name.strip()}=***{sep}{rest}"


def _hints() -> list[dict[str, str]]:
    return [{
        "type": "waf_rule",
        "title": "Harden Set-Cookie at the edge",
        "content": "Rewrite Set-Cookie to add HttpOnly, SameSite=Lax (or Strict) and, "
                   "on https, Secure; strip the flags from no session cookie.",
    }]


async def flags(ctx: ToolContext) -> ToolResult:
    url = ctx.params["url"]
    resp = await ctx.http.get(url)
    https = url.startswith("https://")
    findings: list[FindingSpec] = []
    problems: list[str] = []
    for line in resp.header_all("set-cookie"):
        name, attrs = parse_set_cookie(line)
        if not name:
            continue
        session_like = any(s in name for s in SESSION_COOKIE)
        checks = [
            ("httponly", "HttpOnly", "medium" if session_like else "low"),
            ("samesite", "SameSite", "medium" if session_like else "low"),
        ]
        if https:
            checks.append(("secure", "Secure", "medium" if session_like else "low"))
        for flag, title, severity in checks:
            if any(a == flag or a.startswith(flag + "=") for a in attrs):
                continue
            problems.append(f"{name}:{flag}")
            findings.append(FindingSpec(
                check_id="cookies.flags", detail=f"{name}:missing-{flag}",
                title=f"Cookie '{name}' is set without {title}",
                severity=severity, confidence="high",
                description=f"{url} sets the cookie `{name}` without the {title} "
                            f"attribute"
                            + (" over https, so it is sent on plain http requests"
                               if flag == "secure" else
                               " (it can be stolen through XSS or cross-site "
                               "requests)" if flag == "samesite" else
                               " (scripts can read it through XSS)"),
                url=url, method="GET",
                evidence=[Evidence(role="proof", exchange_id=resp.exchange_id,
                                   excerpt=excerpt(masked(line)),
                                   note="Set-Cookie (value masked)")],
                verify={"url": url, "cookie": name, "flag": flag},
                cwe="CWE-1004" if flag == "httponly" else "CWE-1275",
                references=[{"title": "Set-Cookie (MDN)", "url": COOKIE_REF}],
                detection_hints=_hints(),
                observation_key=f"cookies.flags|{url}|{name}"))
    obs = Observation(key=f"cookies.flags|{url}",
                      label=f"cookie flags: {', '.join(problems)}" if problems
                      else f"all cookies fully flagged on {url}",
                      url=url, exchange_ids=resp.exchange_ids,
                      facts={"status": resp.status,
                             "cookies": [masked(l) for l in resp.header_all("set-cookie")],
                             "problems": problems})
    return ToolResult(
        summary=f"{len(problems)} cookie flag problem(s) on {url}" if problems
        else f"cookies fully flagged on {url}",
        counts={"status": resp.status, "cookies": len(resp.header_all("set-cookie")),
                "problems": len(problems)},
        observations=[obs], findings=findings)
