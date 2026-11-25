"""Verification strategies per check id.

A candidate finding is only reported as **verified** when its check reproduces
under a second, independent tool call: a refetch with the same observation, a
second random probe value, or (exposure) a refetch whose signature also fails to
appear on a random baseline path — the soft-404 guard. Verifiers receive the
``verify`` params the check stored on the work order; they never get secrets.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from src.greybox_web.netguard import REDIRECT_CODES, ScopeViolation, TransportFailure
from src.greybox_web.tools import VerifyResult, excerpt
from src.greybox_web.tools.auth import send_pair, success_indicator
from src.greybox_web.tools.cookies import parse_set_cookie
from src.greybox_web.tools.cors import probe_origin
from src.greybox_web.tools.exposure import DIR_PATTERN, FILES, baseline_path
from src.greybox_web.tools.headers import VERSION_BANNER, _frame_ancestors
from src.greybox_web.tools.info import page_signature
from src.greybox_web.tools.injection import (
    baseline_value,
    canary,
    error_indicator,
    probe_host,
    reflected_unencoded,
    send_value,
)


async def _get(ctx, url: str):
    try:
        return await ctx.http.get(url)
    except (ScopeViolation, TransportFailure):
        return None


async def _authz_object(ctx) -> VerifyResult:
    """Re-run the identity matrix independently (fresh requests, redirects not
    followed) with the SAME decision as the check (``authz.measure``): the object is
    still shared across identities, or a non-owner still receives it."""
    from src.greybox_web.tools.authz import measure
    url = ctx.params["url"]
    if len(ctx.http.sessions()) < 1:
        return VerifyResult(False, "identity matrix",
                            "no identities left to re-test the object")
    matrix, shared, foreign = await measure(ctx, url)
    ids = [x for m in matrix.values() for x in m["exchange_ids"]]
    ok = len(shared) >= 2 or bool(foreign)
    note = (f"{shared and len(shared)} identities again receive the same object"
            if len(shared) >= 2 else
            f"{foreign[0][0]} again receives {foreign[0][1]}'s object" if foreign
            else "the object is no longer shared across identities")
    statuses = ", ".join(f"{i}:{m['status']}" for i, m in matrix.items())
    return VerifyResult(ok, "identity matrix", note, ids, statuses[:300])


async def _headers_security(ctx) -> VerifyResult:
    p = ctx.params
    resp = await _get(ctx, p["url"])
    if resp is None:
        return VerifyResult(False, "refetch", "target unreachable during verification")
    if p.get("header") == "x-frame-options":
        ok = resp.header("x-frame-options") is None and \
            not _frame_ancestors(resp.header("content-security-policy"))
    else:
        ok = resp.header(p["header"]) is None
    return VerifyResult(ok, "refetch: header still absent",
                        f"{p['header']} is {'still absent' if ok else 'now present'}",
                        resp.exchange_ids, excerpt_status(resp))


def excerpt_status(resp) -> str:
    return f"HTTP {resp.status}"


async def _headers_disclosure(ctx) -> VerifyResult:
    p = ctx.params
    resp = await _get(ctx, p["url"])
    if resp is None:
        return VerifyResult(False, "refetch", "target unreachable during verification")
    value = (resp.header(p["header"]) or "").strip()
    ok = value == p.get("value") and bool(VERSION_BANNER.match(value))
    return VerifyResult(ok, "refetch: same version banner",
                        f"{p['header']} now: {value or '(absent)'}",
                        resp.exchange_ids, excerpt_status(resp))


async def _cors_policy(ctx) -> VerifyResult:
    p = ctx.params
    origin = probe_origin(ctx.token())       # a *second* random origin
    try:
        resp = await ctx.http.get(p["url"], headers=[("Origin", origin)])
    except (ScopeViolation, TransportFailure):
        return VerifyResult(False, "second origin", "target unreachable")
    acao = resp.header("access-control-allow-origin")
    acac = (resp.header("access-control-allow-credentials") or "").lower() == "true"
    ok = (acao == origin and acac) if p.get("mode") == "reflect" \
        else (acao == "*" and acac)
    return VerifyResult(ok, "second random origin also reflected",
                        f"ACAO={acao!r}, credentials={acac}",
                        resp.exchange_ids, excerpt_status(resp))


async def _cookies_flags(ctx) -> VerifyResult:
    p = ctx.params
    resp = await _get(ctx, p["url"])
    if resp is None:
        return VerifyResult(False, "refetch", "target unreachable during verification")
    flag = p["flag"]
    ok = False
    note = f"cookie {p['cookie']!r} no longer set"
    for line in resp.header_all("set-cookie"):
        name, attrs = parse_set_cookie(line)
        if name != p["cookie"]:
            continue
        ok = not any(a == flag or a.startswith(flag + "=") for a in attrs)
        note = f"{p['cookie']} attributes: {', '.join(attrs) or '(none)'}"
        break
    return VerifyResult(ok, "refetch: same attributes", note,
                        resp.exchange_ids, excerpt_status(resp))


async def _exposure_files(ctx) -> VerifyResult:
    p = ctx.params
    sig = FILES[p["path"]]
    url = urljoin(p["url"], p["path"])
    resp = await _get(ctx, url)
    if resp is None:
        return VerifyResult(False, "refetch", "target unreachable during verification")
    if resp.status != 200 or not sig.matches(resp.body, resp.text):
        return VerifyResult(False, "refetch + signature",
                            f"{p['path']} no longer carries the signature "
                            f"(HTTP {resp.status})", resp.exchange_ids,
                            excerpt_status(resp))
    # Soft-404 guard: a random path must NOT produce the same signature.
    base = await _get(ctx, urljoin(p["url"], baseline_path(ctx.token())))
    base_sig = base is not None and base.status == 200 and \
        sig.matches(base.body, base.text)
    ok = not base_sig
    note = ("baseline path returns the same signature (soft 404): not a real "
            "exposure" if base_sig else
            f"signature reproduced on {p['path']}, absent on the baseline")
    return VerifyResult(ok, "refetch + signature + soft-404 baseline", note,
                        resp.exchange_ids + (base.exchange_ids if base else []),
                        excerpt_status(resp))


async def _exposure_dirlisting(ctx) -> VerifyResult:
    p = ctx.params
    resp = await _get(ctx, p["url"])
    if resp is None:
        return VerifyResult(False, "refetch", "target unreachable during verification")
    if resp.status != 200 or not DIR_PATTERN.search(resp.text):
        return VerifyResult(False, "refetch + signature",
                            f"directory index no longer served (HTTP {resp.status})",
                            resp.exchange_ids, excerpt_status(resp))
    base = await _get(ctx, urljoin(p["url"], baseline_path(ctx.token())))
    base_sig = base is not None and base.status == 200 and \
        DIR_PATTERN.search(base.text)
    ok = not base_sig
    note = ("baseline path is also an index page: cannot confirm" if base_sig
            else "index reproduced, baseline path is not an index")
    return VerifyResult(ok, "refetch + signature + soft-404 baseline", note,
                        resp.exchange_ids + (base.exchange_ids if base else []),
                        excerpt_status(resp))


async def _send(ctx, url: str, param: str, location: str, value: str,
                *, follow: bool = True):
    """One injection probe value (the tools' own request builder), or None when the
    target is unreachable."""
    try:
        return await send_value(ctx, url, param, location, value, follow=follow)
    except (ScopeViolation, TransportFailure):
        return None


async def _injection_reflection(ctx) -> VerifyResult:
    p = ctx.params
    mark = canary(ctx.token())            # a second, distinct canary
    resp = await _send(ctx, p["url"], p["param"], p.get("location") or "query", mark)
    if resp is None:
        return VerifyResult(False, "second canary also reflected",
                            "target unreachable during verification")
    ok = reflected_unencoded(resp, mark)
    return VerifyResult(
        ok, "second canary also reflected",
        f"second canary {'reflected unencoded' if ok else 'not reflected unencoded'}",
        resp.exchange_ids,
        excerpt(resp.text, mark) if ok else excerpt_status(resp))


async def _injection_errors(ctx) -> VerifyResult:
    p = ctx.params
    location = p.get("location") or "query"
    base_value = baseline_value(p["url"], p["param"], location)
    base = await _send(ctx, p["url"], p["param"], location, base_value)
    probe = await _send(ctx, p["url"], p["param"], location,
                        str(p.get("value") or base_value + "'"))
    if base is None or probe is None:
        return VerifyResult(False, "repeat + baseline",
                            "target unreachable during verification")
    signature, _sql = error_indicator(probe.text, base.text)
    ok = signature is not None
    note = (f"signature {signature!r} reproduced on the probe, absent from the "
            f"baseline" if ok else
            "no error signature reproduced (or the baseline carries it too)")
    return VerifyResult(ok, "repeat + baseline", note, probe.exchange_ids,
                        excerpt(probe.text, signature) if signature
                        else excerpt_status(probe))


async def _redirect_open(ctx) -> VerifyResult:
    p = ctx.params
    host = probe_host(ctx.token())         # a second, distinct .invalid host
    resp = await _send(ctx, p["url"], p["param"], p.get("location") or "query",
                       f"https://{host}/", follow=False)
    if resp is None:
        return VerifyResult(False, "second host also accepted",
                            "target unreachable during verification")
    header = resp.header("location")
    target = (urlsplit(urljoin(resp.url, header)).hostname or "") if header else ""
    ok = resp.status in REDIRECT_CODES and target == host
    note = (f"Location again points at the probe host {host}" if ok else
            f"no redirect to {host} (HTTP {resp.status}, Location={header!r})")
    return VerifyResult(ok, "second host also accepted", note, resp.exchange_ids,
                        excerpt_status(resp))


async def _info_errors(ctx) -> VerifyResult:
    resp = await _get(ctx, ctx.params["url"])
    if resp is None:
        return VerifyResult(False, "refetch", "target unreachable during verification")
    signature, _debug = page_signature(resp.text)
    ok = signature is not None
    return VerifyResult(
        ok, "refetch",
        f"error/debug signature {signature!r} still present" if ok
        else "no error/debug signature on the refetch",
        resp.exchange_ids,
        excerpt(resp.text, signature) if signature else excerpt_status(resp))


async def _auth_default_creds(ctx) -> VerifyResult:
    """Repeat ONLY the successful pair once, against a fresh invalid baseline."""
    p = ctx.params
    url = p["url"]
    user_field = p.get("user_field") or "user"
    password_field = p.get("password_field") or "password"
    method = (p.get("method") or "POST").upper()

    async def _pair(user: str, password: str):
        try:
            return await send_pair(ctx, url, user_field, password_field,
                                   user, password, method)
        except (ScopeViolation, TransportFailure):
            return None

    token = ctx.token()
    base = await _pair(f"vgl{token}", f"vgl{token}")
    resp = await _pair(str(p.get("user") or ""), str(p.get("password") or ""))
    if base is None or resp is None:
        return VerifyResult(False, "successful login repeated",
                            "target unreachable during verification")
    fired = success_indicator(base, resp)
    ok = fired is not None
    note = (f"the pair is accepted again (indicator: {fired})" if ok
            else "the pair no longer differs from an invalid baseline")
    return VerifyResult(ok, "successful login repeated", note, resp.exchange_ids,
                        excerpt_status(resp))


VERIFIERS = {
    "headers.security": _headers_security,
    "headers.disclosure": _headers_disclosure,
    "cors.policy": _cors_policy,
    "cookies.flags": _cookies_flags,
    "exposure.files": _exposure_files,
    "exposure.dirlisting": _exposure_dirlisting,
    "injection.reflection": _injection_reflection,
    "injection.errors": _injection_errors,
    "redirect.open": _redirect_open,
    "info.errors": _info_errors,
    "auth.default_creds": _auth_default_creds,
    "authz.object": _authz_object,
    "authz.exposure": None,          # set below (tools/xref.verify)
}


def _install_xref() -> None:
    from src.greybox_web.tools import xref
    VERIFIERS["authz.exposure"] = xref.verify


_install_xref()
