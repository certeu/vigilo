"""Extract the application's own routes and API calls from its JavaScript.

A modern application ships an empty shell and one bundle. Everything a tester needs
to know — the client routes, the API endpoints, the parameters each call takes, the
object identifiers — is *in that bundle*, as string literals. A page fetcher that
reads only HTML therefore sees a one-page application with no API, which is exactly
what happened in a field assessment: 25 bundle URLs, two pages, zero parameters, and an entire
API surface that never appeared.

This module turns bundle text into candidates. It is deliberately conservative:

* only **path-shaped** literals are considered (they start with ``/`` and look like a
  route, not like a CSS selector or a regex);
* nothing is resolved against a host here — the caller keeps a candidate only when it
  is under the run's base URL, so a bundle cannot name an off-scope target;
* ``{id}`` / ``:id`` / ``${id}`` segments are normalised to one placeholder so
  ``/api/notes/${id}`` and ``/api/notes/:id`` are the same endpoint;
* queries are kept (``?include=owner`` names a parameter), fragments are dropped.

Pure: no I/O, no network, no framework knowledge. Tested on the SPA fixture bundle,
on Next.js ``self.__next_f`` payloads and on deliberately hostile input.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

# A quoted string that looks like a path: "..." or '...' or `...`, starting with /.
_QUOTED = re.compile(r"""(?P<q>["'`])(?P<v>/[^"'`\\\s<>]{0,200})(?P=q)""")
# Template literal with an interpolation: `/api/notes/${id}`
_INTERP = re.compile(r"\$\{[^}]{1,60}\}")
# A call site worth attributing a path to: fetch(...), axios.get(...), $.ajax(...),
# XMLHttpRequest.open('GET', ...), useSWR('/api/...'), instance.get('/api/...').
_CALL = re.compile(
    r"(?i)(?:fetch|axios(?:\.\w+)?|\$\.(?:ajax|get|post)|\w+\.(?:get|post|put|patch|"
    r"delete)|useSWR|useQuery|xhr\.open|\.open|request)\s*\(\s*$")
_METHOD_HINT = re.compile(
    r"(?i)\bmethod\s*[:=]\s*[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']")
_AXIOS_METHOD = re.compile(r"(?i)axios\s*\.\s*(get|post|put|patch|delete|head)\s*\(\s*$")
_OPEN_METHOD = re.compile(r"(?i)\.open\(\s*[\"'](GET|POST|PUT|PATCH|DELETE)[\"']\s*,\s*$")
# Next.js flight/RSC payload pushes: self.__next_f.push([1,"..."])
_NEXTF = re.compile(r"self\.__next_f\.push\(\[\s*\d+\s*,\s*\"((?:[^\"\\]|\\.)*)\"\s*\]\)")
_GRAPHQL_OP = re.compile(r"(?i)\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{2,60})")
_ROUTE_DEF = re.compile(
    r"(?i)\b(?:path|route|url|to|href)\s*:\s*[\"'](/[^\"']{1,200})[\"']")
_NEXT_PAGES_MANIFEST = re.compile(r'"(/[^"]{0,200})"\s*:\s*"(?:pages|app)/')
# JavaScript escapes a bundler may apply to a path literal: \/ and \u002f (slash),
# \u002e (dot). Undoing them BEFORE scanning is what makes an escaped bundle readable.
_ESCAPED_SLASH = re.compile(r"\\/|\\u002[fF]")
_ESCAPED_DOT = re.compile(r"\\u002[eE]")
# Neighbours of a literal, to tell a call site from a concatenation.
_AFTER_LITERAL = re.compile(r"^\s*\+\s*[A-Za-z_$({]")
# After the concatenated variable: a literal tail that is part of the same path,
# e.g. `"/api/notes/" + id + "/body"` -> /body
_TRAILING_SUFFIX = re.compile(r"""^[^;\n]{0,40}?\+\s*['"](/[A-Za-z0-9_\-/{}.]{0,80})['"]""")
_BEFORE_JOIN = re.compile(r"[A-Za-z0-9_$\]\)\}][^;{}()]{0,12}\+\s*$")

MAX_JS_BYTES = 3 * 1024 * 1024       # one bundle, capped
MAX_CANDIDATES = 150                 # per bundle; more is not useful in a prompt
# A path that is really a build artefact, an image or a selector, not a route.
_NOT_A_ROUTE = re.compile(
    r"(?i)\.(?:js|mjs|css|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|eot|mp4|webm)"
    r"\b|^/[*#.\[]|^//|^/\d+$|^/\.well-known/")
_ASSET_SEGMENT = re.compile(r"(?i)(?:^|/)(?:static|assets|chunks|media|dist|build|"
                            r"fonts|images|img|icons?)/")
API_HINTS = ("/api", "/graphql", "/gql", "/rest", "/v1", "/v2", "/v3", "/trpc", "/rpc",
             "/_next/data", "/odata", "/jsonrpc", "/ajax", "/wp-json", "/oauth2")
_HEADER_NAMES = frozenset((
    "content-type", "accept", "authorization", "x-requested-with", "accept-language",
    "x-csrf-token", "x-xsrf-token", "cache-control", "if-none-match", "accept-encoding",
))
# Words that are framework plumbing, not parameters a tester would vary.
_NOT_A_FIELD = frozenset((
    "id", "key", "index", "length", "items", "children", "props", "state",
    "class", "className", "style", "onClick", "onChange", "onSubmit", "config",
    "constructor", "prototype", "then", "valueOf", "toString", "undefined", "null",
    "method", "headers", "body", "mode", "cache", "credentials", "redirect",
    "referrer", "signal", "keepalive", "integrity", "priority",
))


@dataclass
class Candidate:
    """One path a bundle mentions, with how it was found."""

    path: str
    method: str = "GET"
    kind: str = "route"              # route | api | graphql | operation
    evidence: str = ""               # the snippet it came from (capped)
    fields: list[str] = field(default_factory=list)   # body fields seen at the call

    @property
    def is_api(self) -> bool:
        low = self.path.lower()
        return self.kind in ("api", "graphql", "operation") or any(
            low == h or low.startswith(h + "/") or low.startswith(h + "?")
            for h in API_HINTS)


@dataclass
class Intel:
    """What one bundle revealed."""

    candidates: list[Candidate] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)   # GraphQL op names
    next_data_routes: list[str] = field(default_factory=list)
    source_map: str | None = None
    truncated: bool = False

    def paths(self, api_only: bool = False) -> list[str]:
        seen: dict[str, Candidate] = {}
        for c in self.candidates:
            if api_only and not c.is_api:
                continue
            if not is_route_shaped(c.path):
                continue
            cur = seen.get(c.path)
            if cur is None or (cur.method == "GET" and c.method != "GET"):
                seen[c.path] = c
        return sorted(seen)


def _template(literal: str, before: str, after: str) -> str:
    """A path literal that is one piece of a concatenated URL, as a templated path.

    ``api('/api/notes/' + id)``     -> ``/api/notes/{id}``
    ``api('/api/notes/' + id + '/x')`` -> ``/api/notes/{id}/x``
    ``base + '/api/notes'``        -> ``/api/notes`` (a suffix is already whole)

    Only what the source actually shows is templated: an unknown middle segment is a
    single ``{id}``, never a guess at how many segments there are."""
    p = literal.strip()
    # something is concatenated onto the END of this literal -> it continues
    if _AFTER_LITERAL.search(after or ""):
        tail = after
        # a literal suffix after the variable (`... + id + '/body'`) belongs to the path
        rest = _TRAILING_SUFFIX.search(tail)
        p = p.rstrip("/") + "/{id}" + (rest.group(1) if rest else "")
    return _normalise(p)


def _normalise(raw: str) -> str:
    """One path literal as a comparable, safe route."""
    p = raw.strip()
    p = _INTERP.sub("{id}", p)
    if not p.startswith("/"):
        p = "/" + p
    p = re.sub(r"/{2,}", "/", p)
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/") or "/"
    return p[:200]


def is_route_shaped(path: str) -> bool:
    """Would a browser treat this as a same-origin route worth discovering?"""
    if not path or not path.startswith("/") or len(path) > 200:
        return False
    if _NOT_A_ROUTE.search(path):
        return False
    if _ASSET_SEGMENT.search(path.split("?")[0]):
        return False
    if path in ("/", "/index.html"):
        return True
    if path.strip("/") in ("", "{id}"):
        return False
    return True


def _method_near(text: str, pos: int, window: int = 400) -> str:
    """The HTTP method a call site uses, if the snippet says so."""
    before = text[max(0, pos - 120):pos]
    m = _OPEN_METHOD.search(before) or _AXIOS_METHOD.search(before)
    if m:
        return m.group(1).upper()
    snippet = text[pos:pos + window] + " " + before
    m = _METHOD_HINT.search(snippet)
    return m.group(1).upper() if m else "GET"


def _kind(path: str) -> str:
    return "api" if looks_like_api_path(path) else "route"


def looks_like_api_path(url: str) -> bool:
    """Does the *path* of this URL name an API namespace?"""
    path = (urlsplit(url).path or "").lower()
    return any(path == h or path.startswith(h + "/") or path.startswith(h + "?")
               for h in API_HINTS)


def _header_names(near: str) -> set[str]:
    return {n.lower() for n in _HEADER_NAMES if n.lower() in near.lower()}


_BODY_ASSIGN = re.compile(r"(?i)\bbody\s*:\s*JSON\.stringify\s*\(\s*\{")
# A payload object passed to a call: `payload = {...}` / `data: {...}` near the call.
_PAYLOAD_ASSIGN = re.compile(
    r"(?i)(?:\bpayload|\bdata|\bparams|\binput|\bform)\b\s*(?:=|:)\s*\{")
_JSON_KEYS = re.compile(
    r"""(?:(?<!\w)(?:"([A-Za-z_][A-Za-z0-9_]{1,40})"|'([A-Za-z_][A-Za-z0-9_]{1,40})')"""
    r"""|(?<=[{,])\s*([A-Za-z_][A-Za-z0-9_]{1,40}))\s*:""")


def body_fields(near_call: str) -> list[str]:
    """Field names a bundle puts in a request body.

    Only keys *inside* a ``body: {...}`` / ``body: JSON.stringify({...})`` object
    count: JSON keys elsewhere are application data, not request parameters."""
    text = near_call or ""
    m = _BODY_ASSIGN.search(text) or _PAYLOAD_ASSIGN.search(text)
    if m is None:
        return []
    start = text.index("{", m.start())
    window = text[start:start + 1200]
    window = "{" + window[1:]
    depth, end = 0, len(window)
    for i, ch in enumerate(window):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    out: list[str] = []
    for k in _JSON_KEYS.finditer(window[:end]):
        name = k.group(1) or k.group(2) or k.group(3)
        if name in _NOT_A_FIELD or name in out or name.startswith("_"):
            continue
        out.append(name)
        if len(out) >= 12:
            break
    return out


def extract(text: str, *, name: str = "") -> Intel:
    """Everything :class:`Intel` worth having from one bundle / JSON document."""
    out = Intel()
    if not text:
        return out
    text = _ESCAPED_SLASH.sub("/", text)
    text = _ESCAPED_DOT.sub(".", text)
    if len(text) > MAX_JS_BYTES:
        text = text[:MAX_JS_BYTES]
        out.truncated = True

    # Next.js flight payloads carry the route manifest as escaped JSON inside a
    # string literal: decode each push and scan the decoded text as well.
    decoded: list[str] = []
    for raw in _NEXTF.findall(text)[:50]:
        try:
            decoded.append(json.loads(f'"{raw}"'))
        except ValueError:
            continue
    if not decoded and text.lstrip().startswith(("{", "[")):
        decoded.append(text)          # a JSON manifest served without a .json name
    haystacks = [text, *decoded]

    seen: set[str] = set()
    for hay in haystacks:
        for m in _QUOTED.finditer(hay):
            path = _normalise(m.group("v"))
            before = hay[max(0, m.start() - 120):m.start()]
            after = hay[m.end():m.end() + 900]
            # Object URLs are built by concatenation far more often than by template
            # literals: ``api('/api/notes/' + id)``, ``fetch('/api/x/' + key + '/y')``.
            # Such a literal is a *prefix of a real path* — the REST collection whose
            # item URL is where broken object-level authorisation lives — so complete
            # it into a templated path instead of discarding it (defect F-path-concat).
            if _BEFORE_JOIN.search(before) or _AFTER_LITERAL.search(after):
                path = _template(m.group("v"), before, after)
            if not is_route_shaped(path) or path in seen:
                continue
            seen.add(path)
            call = bool(_CALL.search(before))
            near = before + hay[m.start():m.end()] + after
            payload = after if call else (before if _CALL.search(before) else "")
            cand = Candidate(
                path=path,
                method=_method_near(hay, m.start()) if call else "GET",
                kind=_kind(path),
                evidence=(before[-60:] + hay[m.start():m.end()] + after[:200])[:400],
                fields=body_fields(payload) if payload else [])
            # A URL whose call passes an Authorization/X-CSRF header must be requested
            # WITH that header: treated as an anonymous GET it answers 401 and the
            # endpoint looks protected when it is a missing credential on our side.
            if call and _header_names(near) & {"authorization", "x-csrf-token",
                                               "x-xsrf-token", "x-requested-with"}:
                cand.kind = "api"
                cand.evidence += " [sends-auth-header]"
            out.candidates.append(cand)
            if len(out.candidates) >= MAX_CANDIDATES:
                break
    for m in _NEXT_PAGES_MANIFEST.finditer(text):
        path = _normalise(m.group(1))
        if is_route_shaped(path) and path not in seen:
            seen.add(path)
            out.candidates.append(Candidate(path=path, kind=_kind(path),
                                            evidence="pages manifest"))
    out.operations = sorted({m.group(2) for m in _GRAPHQL_OP.finditer(text)})[:20]
    for op in out.operations:
        out.candidates.append(Candidate(path=f"/graphql#op:{op}", kind="operation",
                                        evidence=op, method="POST"))
    m = re.search(r"sourceMappingURL=([^\s*'\"]{1,200})", text)
    if m:
        out.source_map = m.group(1)
    return out


def merge(into: Intel, other: Intel) -> Intel:
    """Combine the intel of several bundles (one page usually loads many)."""
    have = {(c.path, c.method) for c in into.candidates}
    for c in other.candidates:
        if (c.path, c.method) not in have:
            into.candidates.append(c)
            have.add((c.path, c.method))
    into.operations = sorted(set(into.operations) | set(other.operations))[:20]
    into.next_data_routes = sorted(set(into.next_data_routes) |
                                   set(other.next_data_routes))[:50]
    into.source_map = into.source_map or other.source_map
    into.truncated = into.truncated or other.truncated
    return into


def looks_like_javascript(url: str, content_type: str | None = None) -> bool:
    """Is this response a script (or a manifest) worth extracting from?"""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct in ("application/javascript", "text/javascript", "application/x-javascript",
              "application/ecmascript", "text/ecmascript",
              "application/json", "application/manifest+json"):
        # JSON counts: Next.js route manifests and OpenAPI-ish documents are how a
        # client learns its endpoints. The caller caps the size.
        return True
    path = (urlsplit(url).path or "").lower()
    return path.endswith((".js", ".mjs", ".cjs", ".json"))


def manifest_urls(text: str) -> list[str]:
    """Sub-resources a manifest names (chunk lists, page routes) — still only paths."""
    out: list[str] = []
    for m in _QUOTED.finditer(text or ""):
        p = _normalise(m.group("v"))
        if is_route_shaped(p) and p not in out:
            out.append(p)
    return out[:200]


def query_params(path: str) -> list[tuple[str, str]]:
    """The ``name=value`` pairs a path declared."""
    if "?" not in path:
        return []
    return parse_qsl(path.split("?", 1)[1], keep_blank_values=True)[:20]
