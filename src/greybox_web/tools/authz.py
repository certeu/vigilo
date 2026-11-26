"""Object-level access testing.

The attacker behaviour this models: log in, then ask for an object that belongs to
somebody else — or ask for it with no login at all — and see whether the
application hands it over. The tool fetches ONE discovered object URL under every
identity the run has (anonymous, the provided cookie session, and every session the
auth.login tool established), without following redirects (a redirect is a login
wall, not the object), and compares status class and body.

No finding when only one identity (or only anonymous) can read it. A finding when
two or more identities receive the same object — shared object access, i.e. missing
object-level authorization — with the whole access matrix recorded as evidence for
the analyst. Nothing here guesses ownership; it measures who can read what.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.greybox_web.netguard import HttpResponse
from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    excerpt,
)

REMEDIATION = {
    "summary": "Enforce object ownership on the server for every read of this "
               "object type.",
    "steps": ["Load the object scoped to the authenticated user (e.g. WHERE "
              "owner_id = :session_user) or check ownership/permission before "
              "returning it; never trust the client-supplied identifier alone.",
              "Answer 404 for objects the caller may not access (avoid confirming "
              "that the identifier exists).",
              "Log and alert on repeated cross-user access denials."],
    "validation": ["As a user who does not own the object, request it: the response "
                   "is 404/403 and contains no object data.",
                   "Add an automated test per object type reading another user's "
                   "object with a valid session."],
    "severity_rationale": "Any authenticated (or anonymous) caller reads other "
                          "users' records by changing an identifier.",
}

WSTG_AUTHZ = ("https://wstg.owasp.org/latest/05-Authorization/"
              "02-Testing-for-IDOR")

HINTS = [
    {
        "type": "waf_rule",
        "title": "Enforce ownership server-side",
        "content": "Check, on every request for an object, that the authenticated "
                   "user owns or may access it (server-side, from the session — "
                   "never from a client-sent id alone), and answer 403/404 "
                   "otherwise. Log cross-user access denials.",
    },
]

_OBJECT_LAST = re.compile(
    r"^[0-9]+$|^[0-9a-f]{8,}$|^[0-9a-f]{8}-[0-9a-f]{4}"
    r"-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def route_template(url: str) -> str:
    """``/api/notes/7`` -> ``host/api/notes/{id}`` (the identity of an ownership
    finding: the missing check is per route, not per object)."""
    p = urlsplit(url)
    segs = [("{id}" if _OBJECT_LAST.match(x.lower()) else x)
            for x in (p.path or "/").split("/")]
    return f"{p.netloc}{'/'.join(segs)}"


def _tpl_path(url: str) -> str:
    """The route template's path (``/api/invoices/{id}``)."""
    t = route_template(url)
    return t[t.index("/"):] if "/" in t else "/"


def looks_like_object(path: str) -> bool:
    """A URL path that names ONE object of a collection (``/api/notes/7``,
    ``/users/9f3c1b2e``) rather than a page, a form or a collection index. The last
    segment looks like an id (numeric or hex/uuid); guessed ownership is never
    required — only who can read it is measured."""
    parts = [p for p in (path or "/").split("/") if p]
    return (len(parts) >= 2 and bool(_OBJECT_LAST.match(parts[-1].lower()))
            and parts[-1] not in ("login", "logout", "search", "debug"))


OWNER_KEYS = ("owner", "owner_id", "user", "username", "user_id", "author",
              "created_by", "account", "email")


def _normalise(value, own: frozenset[str]):
    """A JSON value without the parts that merely echo the REQUESTING identity
    (``"viewer": "ana"``): two identities receiving the same object must compare
    equal even when the API mirrors who asked."""
    if isinstance(value, dict):
        return {k: _normalise(v, own) for k, v in value.items()
                if not (isinstance(v, str) and v in own)}
    if isinstance(value, list):
        return [_normalise(v, own) for v in value]
    return value


def _body_key(resp: HttpResponse, own: frozenset[str] = frozenset()) -> str:
    text = resp.text or ""
    try:
        doc = json.loads(text)
        text = json.dumps(_normalise(doc, own), sort_keys=True)
    except ValueError:
        for name in sorted(own, key=len, reverse=True):
            if len(name) >= 3:
                text = text.replace(name, "<self>")
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _owner_of(resp: HttpResponse) -> str | None:
    """The object's declared owner (a top-level owner-like field), if any."""
    try:
        doc = json.loads(resp.text or "")
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    for k in OWNER_KEYS:
        v = doc.get(k)
        if isinstance(v, (str, int)) and str(v):
            return str(v)
    return None


_IMPOSSIBLE_IDS = ("987654321987", "ffffffff-0000-4000-8000-00000000dead")
_CAPABILITY_QUERY = {"access_token", "code", "key", "secret", "share", "signature", "sig", "token"}
_CAPABILITY_PATH = re.compile(r"/(?:s|share|shared)/[A-Za-z0-9_-]{8,}(?:/|$)", re.I)
_OBJECT_QUERY_KEYS = {"id", "key", "object", "record", "resource"}


def _query_object(url: str) -> tuple[list[tuple[str, str]], int] | None:
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    for index, (key, value) in enumerate(pairs):
        if (key.lower() in _OBJECT_QUERY_KEYS or key.lower().endswith("_id")) \
                and _OBJECT_LAST.match(value.lower()):
            return pairs, index
    return None


def capability_url(url: str) -> bool:
    """Whether a URL carries an explicit sharing capability, not just an object id."""
    from urllib.parse import parse_qsl
    parsed = urlsplit(url)
    if _CAPABILITY_PATH.search(parsed.path):
        return True
    return any(k.lower() in _CAPABILITY_QUERY and bool(v)
               for k, v in parse_qsl(parsed.query, keep_blank_values=True))


async def _generic_route(ctx: ToolContext, url: str, ident: str, body_key: str,
                         names: dict) -> bool:
    """Does the route return the same body for an identifier that cannot exist?"""
    from src.greybox_web.netguard import ScopeViolation, TransportFailure
    p = urlsplit(url)
    segs = p.path.rstrip("/").split("/")
    if segs and _OBJECT_LAST.match(segs[-1].lower()):
        fake = _IMPOSSIBLE_IDS[1] if "-" in segs[-1] else _IMPOSSIBLE_IDS[0]
        sibling = p._replace(path="/".join(segs[:-1] + [fake])).geturl()
    else:
        query_object = _query_object(url)
        if query_object is None:
            return False
        pairs, index = query_object
        key, value = pairs[index]
        pairs[index] = (key, _IMPOSSIBLE_IDS[1] if "-" in value else _IMPOSSIBLE_IDS[0])
        sibling = urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), p.fragment))
    try:
        resp = await ctx.http.get(sibling, follow=False, session=ident)
    except (ScopeViolation, TransportFailure):
        return False
    return 200 <= resp.status < 300 and \
        _body_key(resp, names.get(ident, frozenset({ident}))) == body_key


def identity_names(ctx: ToolContext) -> dict[str, frozenset[str]]:
    """label -> the names that identity goes by (its label and account user)."""
    out: dict[str, set[str]] = {}
    for acct in ctx.accounts or ():
        label, user = acct[0], acct[1]
        out.setdefault(label, set()).update({str(label), str(user)})
    for s in ctx.http.sessions():
        out.setdefault(s["label"], set()).add(s["label"])
    return {k: frozenset(v) for k, v in out.items()}


async def measure(ctx: ToolContext, url: str) -> tuple[dict, list[str], list[tuple]]:
    """The identity matrix for one object: (matrix, identities sharing the same
    object, foreign reads). A foreign read is an identity receiving an object whose
    owner field names ANOTHER identity of this run — direct evidence even when only
    one non-owner was tested."""
    from src.greybox_web.netguard import ScopeViolation, TransportFailure
    names = identity_names(ctx)
    identities = _identities(ctx)
    matrix: dict[str, dict] = {}
    for ident in identities:
        try:
            resp = await ctx.http.get(url, follow=False, session=ident)
        except (ScopeViolation, TransportFailure):
            continue
        saw = 200 <= resp.status < 300        # a redirect is a login wall
        own = names.get(ident, frozenset({ident}))
        matrix[ident] = {"status": resp.status, "saw": saw,
                         "body": _body_key(resp, own) if saw else None,
                         "owner": _owner_of(resp) if saw else None,
                         "exchange_id": resp.exchange_id,
                         "exchange_ids": list(resp.exchange_ids or [])}
    seers = [i for i, m in matrix.items() if m["saw"]]
    shared: dict[str, list[str]] = {}
    for i in seers:
        shared.setdefault(matrix[i]["body"], []).append(i)
    ref = max(shared.values(), key=len) if shared else []
    if len(ref) >= 2 and await _generic_route(ctx, url, ref[0],
                                              matrix[ref[0]]["body"], names):
        # Soft-404 baseline: the route answers the SAME for an identifier that
        # cannot exist (an SPA shell, a generic page) -- it does not serve an
        # object, so identical answers across identities prove nothing.
        for i in ref:
            matrix[i]["generic"] = True
        ref = []
    foreign: list[tuple] = []
    for i in seers:
        owner = matrix[i]["owner"]
        if owner is None or i == "anon" or owner in names.get(i, frozenset({i})):
            continue
        owner_ident = next((lbl for lbl, ns in names.items()
                            if owner in ns and lbl != i), None)
        if owner_ident is not None:
            foreign.append((i, owner_ident, owner))
    return matrix, ref, foreign



def _identities(ctx: ToolContext) -> list[str]:
    """Every identity of this run: anonymous plus each established session (the
    provided cookie counts as one). Anonymous is always first."""
    return ["anon"] + [s["label"] for s in ctx.http.sessions()]


async def object_access(ctx: ToolContext) -> ToolResult:
    """One object URL under every identity; shared access becomes a finding."""
    url = ctx.params["url"]
    if "{" in url or "}" in url or (not looks_like_object(urlsplit(url).path)
                                     and _query_object(url) is None):
        return ToolResult(
            summary=f"object access on {urlsplit(url).path}: skipped non-object route",
            counts={"requests": 0, "identities": 0},
            observations=[Observation(
                key=f"authz.object|{url}",
                label="object-level access untested: concrete identifier required",
                url=url, facts={"reason": "route_template"})])
    identities = _identities(ctx)
    if len(identities) < 2:
        return ToolResult(
            summary=f"object access on {urlsplit(url).path or '/'}: untestable "
                    "(no session: no accounts provided, no cookie)",
            counts={"requests": 0, "identities": len(identities)},
            observations=[Observation(
                key=f"authz.object|{url}",
                label="object-level access untested: no identity to compare",
                url=url, facts={"identities": identities})])

    matrix, ref_seers, foreign = await measure(ctx, url)
    path = urlsplit(url).path or "/"
    findings: list[FindingSpec] = []
    if len(ref_seers) >= 2 and ("anon" not in ref_seers or not capability_url(url)):
        anon_in = "anon" in ref_seers
        # the most damning proof: the object handed to a request with NO login at
        # all; otherwise the first identity that is not the reference's own
        non_owner = "anon" if anon_in else next(
            i for i in ref_seers if i != ref_seers[0])
        proof = matrix[non_owner]
        others = ", ".join(i for i in identities if i not in ref_seers) or "nobody else"
        findings.append(FindingSpec(
            check_id="authz.object", detail="shared",
            title=f"Objects at {_tpl_path(url)} readable by "
                  + ("anyone (no authentication)" if anon_in
                     else f"every tested account ({', '.join(ref_seers)})"),
            severity="high" if anon_in else "medium", confidence="medium",
            description=f"The object at {url} was requested under every identity "
                        f"of this run: {', '.join(ref_seers)} all received the "
                        f"same response (HTTP {proof['status']}), while "
                        f"{others} did not. Shared access to an object "
                        "across accounts — or without any login — usually means "
                        "the server does not tie the object to its owner. The "
                        "full matrix is in the observation; ownership was not "
                        "guessed, only measured.",
            url=url, method="GET", asset_url=url,
            evidence=[Evidence(role="proof", exchange_id=proof["exchange_id"],
                               excerpt=excerpt(f"GET {url} as {non_owner} -> "
                                               f"{proof['status']}", url),
                               note=f"{non_owner} receives the object")],
            verify={"url": url},
            cwe="CWE-639" if anon_in else "CWE-284",
            references=[{"title": "OWASP WSTG — testing for IDOR",
                         "url": WSTG_AUTHZ}],
            detection_hints=HINTS,
            remediation=REMEDIATION,
            observation_key=f"authz.object|{url}",
            # one missing check per route: sibling objects are further locations
            identity=f"route:{route_template(url)}", occurrence=url))
    elif foreign:
        reader, owner_ident, owner = foreign[0]
        proof = matrix[reader]
        findings.append(FindingSpec(
            check_id="authz.object", detail="foreign_read",
            title=f"Objects at {_tpl_path(url)} are readable by users who do not "
                  f"own them ({reader} read {owner_ident}'s)",
            severity="high", confidence="high",
            description=f"{url} declares its owner as {owner!r} (identity "
                        f"{owner_ident}), yet {reader} received it with HTTP "
                        f"{proof['status']}. The server returns another user's "
                        "object to a caller that does not own it.",
            url=url, method="GET", asset_url=url,
            evidence=[Evidence(role="proof", exchange_id=proof["exchange_id"],
                               excerpt=excerpt(f"GET {url} as {reader} -> "
                                               f"{proof['status']} (owner {owner})",
                                               url),
                               note=f"{reader} receives {owner_ident}'s object")],
            verify={"url": url}, cwe="CWE-639",
            references=[{"title": "OWASP WSTG — testing for IDOR",
                         "url": WSTG_AUTHZ}],
            detection_hints=HINTS, remediation=REMEDIATION,
            observation_key=f"authz.object|{url}",
            # one missing check per route: sibling objects are further locations
            identity=f"route:{route_template(url)}", occurrence=url))
    obs = Observation(
        key=f"authz.object|{url}",
        label=f"object at {path}: "
              + (f"readable by {', '.join(ref_seers)}" if ref_seers
                 else "readable by no tested identity"),
        url=url,
        exchange_ids=[m["exchange_id"] for m in matrix.values() if m["exchange_id"]],
        facts={"matrix": {i: {"status": m["status"], "saw": m["saw"],
                              **({"owner": m["owner"]} if m["owner"] else {})}
                          for i, m in matrix.items()},
               "identities": identities, "shared": len(ref_seers),
               **({"generic_route": True} if any(m.get("generic")
                                                for m in matrix.values()) else {}),
               **({"foreign_reads": [f"{r} read {o}'s object" for r, o, _ in foreign]}
                  if foreign else {})})
    return ToolResult(
        summary=f"object access on {path}: "
                + (f"shared by {', '.join(ref_seers)}" if len(ref_seers) >= 2
                   else f"{foreign[0][0]} reads {foreign[0][1]}'s object" if foreign
                   else "single-identity (enforced)" if len(ref_seers) == 1
                   else "not readable"),
        counts={"requests": len(identities), "identities": len(identities),
                "shared": len(ref_seers)},
        observations=[obs], findings=findings)
