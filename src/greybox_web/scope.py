"""Scope policy. Pure: no I/O, no settings access.

* :func:`build_scope` turns a base URL plus a partial scope into a validated, normalised
  :class:`ScopePolicy`, or a list of :class:`FieldError` (create/update time, HTTP 422).
* :meth:`ScopePolicy.check_url` is the per-request gate used by the M2 guarded client.
* :meth:`ScopePolicy.summary` renders human-readable lines for the UI and the report.

Matching rules:

* Hosts: exact match on the normalised host (lowercase, no trailing dot, IDNA, canonical
  IP literal). ``*.example.test`` matches one or more labels below the suffix, never the
  suffix itself. IP literals never match a wildcard.
* Paths are normalised before matching (unreserved percent-escapes decoded, other
  escapes upper-cased, dot segments resolved, repeated slashes collapsed).
  ``path_prefixes`` match on segment boundaries (``/app`` matches ``/app`` and
  ``/app/x``, not ``/application``). ``excluded_paths`` match as plain,
  case-insensitive string prefixes, so they exclude more rather than less.
  Exclusion always wins over inclusion.
"""
from __future__ import annotations

import re
import string
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from src.greybox_web.netscope import NetworkScope
from src.greybox_web.netguard import (
    classify_ip,
    is_always_denied,
    is_loopback_name,
    is_private,
    parse_ip,
)

SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_POLICIES = ("in_scope", "none")
MAX_REDIRECT_HOPS = 5

LIMITS = {
    "allowed_hosts": (1, 20),
    "allowed_schemes": (1, 2),
    "allowed_ports": (1, 20),
    "path_prefixes": (1, 50),
    "excluded_paths": (0, 100),
    "redirect_hosts": (0, 10),
}
MAX_PATH_LEN = 500

REASONS = (
    "scheme_not_allowed", "host_not_allowed", "port_not_allowed",
    "path_not_in_scope", "path_excluded", "userinfo_present", "invalid_url",
)

_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_LABEL = re.compile(r"^(?:[0-9]+|0x[0-9a-f]*)$")
_BAD_URL_CHARS = re.compile(r"[\x00-\x20\x7f\\]")
_CATEGORY_TEXT = {
    "metadata": "cloud metadata",
    "link_local": "link-local",
    "unspecified": "unspecified",
    "multicast": "multicast",
    "reserved": "reserved",
    "loopback": "loopback",
    "private": "private network",
    "cgnat": "carrier-grade NAT",
    "ula": "unique-local (private)",
}


# --------------------------------------------------------------------------- errors


@dataclass(frozen=True)
class FieldError:
    loc: tuple[str | int, ...]   # relative to the request body, e.g. ("scope", "allowed_hosts", 0)
    msg: str
    type: str = "value_error"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None


@dataclass(frozen=True)
class PolicyContext:
    """Platform settings that constrain what a scope may authorise."""

    allow_private: bool = False
    blocked_hosts: frozenset[str] = frozenset()
    # (host, port) pairs; host "private" = any loopback/private address.
    blocked_endpoints: tuple[tuple[str, int], ...] = ()


# --------------------------------------------------------------------- normalisation


def normalise_path(path: str) -> str:
    """Canonical form used for scope matching (never sent on the wire)."""

    def _esc(m: re.Match) -> str:
        ch = chr(int(m.group(1), 16))
        return ch if ch in _UNRESERVED else "%" + m.group(1).upper()

    p = re.sub(r"%([0-9A-Fa-f]{2})", _esc, path or "/")
    if not p.startswith("/"):
        p = "/" + p
    p = re.sub(r"/{2,}", "/", p)
    # Path parameters (``;x=y``) are stripped from every segment BEFORE dot-segment
    # resolution: servers such as Tomcat do the same, so ``/app;/../admin`` and
    # ``/app/a/..;/admin`` must resolve to ``/admin`` / ``/app/admin`` here too,
    # otherwise ``excluded_paths`` / ``path_prefixes`` can be bypassed.
    segments = [seg.split(";", 1)[0] for seg in p.split("/")[1:]]
    segments = [seg for i, seg in enumerate(segments)
                if seg or i == len(segments) - 1]
    stack: list[str] = []
    for seg in segments:
        if seg == "..":
            if stack:
                stack.pop()
        elif seg != ".":
            stack.append(seg)
    trailing = bool(segments) and segments[-1] in (".", "..") and bool(stack)
    out = "/" + "/".join(stack)
    if trailing and not out.endswith("/"):
        out += "/"
    return out


def _idna(host: str) -> str | None:
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def _valid_hostname(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    if not all(_LABEL.match(lbl) for lbl in labels):
        return False
    # A numeric/hex final label is an alternative IPv4 spelling (2852039166, 0x7f.1,
    # 0177.0.0.1), resolved by getaddrinfo to an address: never a valid target name.
    return not _NUMERIC_LABEL.match(labels[-1])


def canonical_host(raw: str) -> str | None:
    """Normalise a URL hostname for matching; None when unusable."""
    h = (raw or "").strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    ip = parse_ip(h)
    if ip is not None:
        return str(ip)
    return _idna(h)


def normalise_host_pattern(raw: Any) -> tuple[str | None, str | None]:
    """(normalised pattern, error message) for an ``allowed_hosts`` entry."""
    if not isinstance(raw, str):
        return None, "Must be a string"
    h = raw.strip().lower()
    if not h:
        return None, "Host must not be empty"
    if any(c in h for c in "/\\@?#") or _BAD_URL_CHARS.search(h):
        return None, ("Enter a hostname or IP address only, without scheme, credentials, "
                      "path or spaces")
    h = h.rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        ip = parse_ip(h)
        if ip is None:
            return None, "Invalid IPv6 address"
        return str(ip), None
    ip = parse_ip(h)
    if ip is not None:
        return str(ip), None
    if ":" in h:
        return None, "Do not include a port here; list ports in allowed_ports"
    if "*" in h:
        if h == "*":
            return None, "A bare * is not allowed; list the hosts you are authorised to test"
        if not h.startswith("*.") or "*" in h[2:]:
            return None, "Wildcards are only allowed as a leading label, e.g. *.example.test"
        suffix = _idna(h[2:])
        if suffix is None or not _valid_hostname(suffix):
            return None, "Invalid wildcard suffix"
        if "." not in suffix:
            return None, "A wildcard must cover a domain, not a top-level domain (e.g. *.com)"
        return "*." + suffix, None
    name = _idna(h)
    if name is None or not _valid_hostname(name):
        return None, "Invalid hostname"
    return name, None


def host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]   # ".example.test"
        return parse_ip(host) is None and host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


@dataclass(frozen=True)
class ParsedURL:
    scheme: str
    host: str
    port: int
    path: str          # normalised


def parse_url(url: str) -> tuple[ParsedURL | None, str | None]:
    """Parse an absolute http(s) URL for scope matching: (parsed, reason code)."""
    if not isinstance(url, str) or not url or _BAD_URL_CHARS.search(url):
        return None, "invalid_url"
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None, "invalid_url"
    if not parts.scheme or not parts.netloc:
        return None, "invalid_url"
    if "@" in parts.netloc:
        return None, "userinfo_present"
    scheme = parts.scheme.lower()
    host = canonical_host(parts.hostname or "")
    if not host:
        return None, "invalid_url"
    if port is None:
        port = DEFAULT_PORTS.get(scheme)
        if port is None:
            return ParsedURL(scheme, host, 0, normalise_path(parts.path)), None
    return ParsedURL(scheme, host, port, normalise_path(parts.path)), None


# --------------------------------------------------------------------------- policy


def _prefix_match(prefix: str, path: str) -> bool:
    if prefix == "/" or path == prefix:
        return True
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path.startswith(prefix + "/")


# Active infrastructure probes an analyst may opt in to. Defaults to none: the planner may PROPOSE these as work
# orders, but ``Planner.admit`` rejects them (``active_probe_not_enabled``) unless the
# target's ``scope.exploration.active_probes`` lists the tool. The tools themselves ship
# in a later phase.
ACTIVE_PROBE_TOOLS = ("infra.tls", "infra.dns", "net.methods", "net.ports",
                      "edge.waf_detect", "edge.origin")
RESOURCE_LIFECYCLES = ("unknown", "disposable_resettable")


@dataclass(frozen=True)
class ScopePolicy:
    allowed_hosts: tuple[str, ...]
    allowed_schemes: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    path_prefixes: tuple[str, ...] = ("/",)
    excluded_paths: tuple[str, ...] = ()
    redirect_policy: str = "in_scope"
    # Authentication testing is ON by default (operator decision 2026-11-21): the
    # engine behaves like a real attacker and tests login forms, default
    # credentials and authenticated surfaces without anyone enabling anything.
    # An owner can still narrow it to False — the scope is the authorization
    # boundary, not a capability checklist.
    allow_auth_testing: bool = True
    active_probes: tuple[str, ...] = ()
    # Hosts the OPERATOR believes the target redirects to on purpose (an identity
    # provider, a partner site). Disclosed, never tested: a run announces "the
    # target hands the browser to login.example.com" instead of silently following
    # it or silently ignoring it, and the Analyst decides whether that host belongs
    # in the scope. A redirect whose host is here is recordable evidence, not scope.
    redirect_hosts: tuple[str, ...] = ()
    # When true, a redirect to a ``redirect_hosts`` entry is not even *recorded* as
    # a request: the run announces "the target hands the client to login.x" and
    # moves on. Off by default (the blocked hop is useful evidence: an analyst can
    # see that the session was refused); the acceptance suite for SSO targets turns
    # it on so no packet is ever addressed to the identity provider.
    honor_declared_redirects: bool = False
    # Target-neutral boundary (``netscope.py``): authorised addresses, ports and
    # protocols for non-URL capabilities (TCP connect, banner read, DNS). ``None``
    # for a web-only target: every non-HTTP action is then refused.
    network: NetworkScope | None = None
    # Activity policy: may the assessment send state-changing requests (PUT, PATCH,
    # DELETE, arbitrary-body POSTs from generated tools)? Off by default; the
    # operator opts in per target. Read-only + inert probes is the default posture.
    state_changing: bool = False
    # Target-wide operator guarantee. This conveys only that synthetic resources
    # in the environment may be mutated and reset; it carries no operation name,
    # object ID, or vulnerability knowledge. Unknown is the safe default.
    resource_lifecycle: str = "unknown"
    # Snapshot of the target's assessment mode and disabled capabilities, written at
    # run start (``service.start_run``) so the run never re-reads the target.
    mode: str = "web"
    disabled_capabilities: tuple[str, ...] = ()

    # -- serialisation ------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_schemes": list(self.allowed_schemes),
            "allowed_ports": list(self.allowed_ports),
            "path_prefixes": list(self.path_prefixes),
            "excluded_paths": list(self.excluded_paths),
            "redirect_policy": self.redirect_policy,
            "allow_auth_testing": self.allow_auth_testing,
            **({"exploration": {"active_probes": list(self.active_probes)}}
               if self.active_probes else {}),
            **({"redirect_hosts": list(self.redirect_hosts)}
               if self.redirect_hosts else {}),
            **({"honor_declared_redirects": True}
               if self.honor_declared_redirects else {}),
            **({"network": self.network.to_dict()} if self.network else {}),
            **({"activity": {
                **({"state_changing": True} if self.state_changing else {}),
                **({"resource_lifecycle": self.resource_lifecycle}
                   if self.resource_lifecycle != "unknown" else {}),
            }} if self.state_changing or self.resource_lifecycle != "unknown" else {}),
            **({"assessment": {"mode": self.mode,
                               "disabled_capabilities": list(self.disabled_capabilities)}}
               if self.mode != "web" or self.disabled_capabilities else {}),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> ScopePolicy:
        """Load a stored (already validated) scope."""
        return cls(
            allowed_hosts=tuple(d["allowed_hosts"]),
            allowed_schemes=tuple(d["allowed_schemes"]),
            allowed_ports=tuple(int(p) for p in d["allowed_ports"]),
            path_prefixes=tuple(d.get("path_prefixes") or ("/",)),
            excluded_paths=tuple(d.get("excluded_paths") or ()),
            redirect_policy=d.get("redirect_policy", "in_scope"),
            allow_auth_testing=bool(d.get("allow_auth_testing", True)),
            active_probes=tuple(p for p in ((d.get("exploration") or {})
                                            .get("active_probes") or ())
                                if p in ACTIVE_PROBE_TOOLS),
            redirect_hosts=tuple(str(h) for h in (d.get("redirect_hosts") or ())),
            honor_declared_redirects=bool(d.get("honor_declared_redirects", False)),
            network=NetworkScope.from_dict(d.get("network")),
            state_changing=bool((d.get("activity") or {}).get("state_changing", False)),
            resource_lifecycle=str((d.get("activity") or {}).get(
                "resource_lifecycle") or "unknown")
            if str((d.get("activity") or {}).get("resource_lifecycle") or "unknown")
            in RESOURCE_LIFECYCLES else "unknown",
            mode=str((d.get("assessment") or {}).get("mode") or "web"),
            disabled_capabilities=tuple(
                str(c) for c in (d.get("assessment") or {}).get(
                    "disabled_capabilities") or ()),
        )

    def redirect_is_declared(self, url: str) -> bool:
        """Should a redirect to ``url`` be refused BEFORE any packet is sent?"""
        return self.honor_declared_redirects and self.declared_redirect(url)

    # -- matching -----------------------------------------------------------------
    def host_allowed(self, host: str) -> bool:
        h = canonical_host(host)
        return h is not None and any(host_matches(p, h) for p in self.allowed_hosts)

    def declared_redirect(self, url: str) -> bool:
        """Is this URL on a host the operator pre-declared as a redirect target?

        Declared is not in scope: it is never requested, then or later; it is what
        the run says out loud ("the target redirects to login.example.com") instead
        of a blind redirect that looks like an application page."""
        try:
            host = canonical_host(urlsplit(url).hostname or "")
        except ValueError:
            return False
        return host is not None and any(host_matches(p, host)
                                        for p in self.redirect_hosts)

    def path_excluded(self, normalised_path: str) -> bool:
        low = normalised_path.lower()
        return any(low.startswith(e.lower()) for e in self.excluded_paths)

    def check_endpoint(self, host: str, port: int | None, protocol: str) -> Decision:
        """The predicate for every non-URL action (TCP connect, banner read, DNS).
        Only the network scope authorises them: a web-only scope refuses all."""
        if self.network is None:
            return Decision(False, "no_network_scope")
        d = self.network.check(host, port, protocol)
        return Decision(d.allowed, d.reason)

    def _network_http(self, parsed: ParsedURL) -> bool:
        """An http(s) URL on an address:port the network scope authorises for http."""
        return (self.network is not None
                and self.network.check(parsed.host, parsed.port, "http").allowed)

    def check_url(self, url: str) -> Decision:
        parsed, reason = parse_url(url)
        if parsed is None:
            return Decision(False, reason)
        if self._network_http(parsed):
            pass          # authorised network segment: the path rules still apply
        elif parsed.scheme not in self.allowed_schemes:
            return Decision(False, "scheme_not_allowed")
        elif not any(host_matches(p, parsed.host) for p in self.allowed_hosts):
            return Decision(False, "host_not_allowed")
        elif parsed.port not in self.allowed_ports:
            return Decision(False, "port_not_allowed")
        if self.path_excluded(parsed.path):
            return Decision(False, "path_excluded")
        if not any(_prefix_match(p, parsed.path) for p in self.path_prefixes):
            return Decision(False, "path_not_in_scope")
        return Decision(True, None)

    # -- presentation -------------------------------------------------------------
    def summary(self) -> list[str]:
        paths = ", ".join(self.path_prefixes)
        if self.excluded_paths:
            paths += f" (excluding {', '.join(self.excluded_paths)})"
        return [
            f"Hosts: {', '.join(self.allowed_hosts)}",
            f"Schemes: {', '.join(self.allowed_schemes)}",
            f"Ports: {', '.join(str(p) for p in self.allowed_ports)}",
            f"Paths: {paths}",
            "Redirects: followed only within scope" if self.redirect_policy == "in_scope"
            else "Redirects: never followed",
            *([f"Target redirects to (declared, not tested): "
               f"{', '.join(self.redirect_hosts)}"] if self.redirect_hosts else []),
            "Authentication testing: enabled (logins, default credentials, "
            "object-level access)"
            if self.allow_auth_testing else "Authentication testing: disabled",
            *(["Active infrastructure probes (opt-in): " + ", ".join(self.active_probes)]
              if self.active_probes else []),
            *([self.network.summary()] if self.network else []),
            "State-changing requests: allowed (operator opt-in)" if self.state_changing
            else "State-changing requests: refused (read-only + inert probes)",
        ]


# ----------------------------------------------------------------------- validation


@dataclass
class _Collector:
    errors: list[FieldError] = field(default_factory=list)

    def add(self, loc: tuple, msg: str) -> None:
        self.errors.append(FieldError(loc, msg))


def normalise_base_url(raw: Any, errs: _Collector) -> ParsedURL | None:
    """Validate ``base_url`` (http/https, no userinfo/fragment) and return its parts."""
    loc = ("base_url",)
    if not isinstance(raw, str) or not raw.strip():
        errs.add(loc, "Enter the target base URL")
        return None
    url = raw.strip()
    if _BAD_URL_CHARS.search(url):
        errs.add(loc, "The URL must not contain spaces, control characters or backslashes")
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        errs.add(loc, "Invalid URL or port")
        return None
    scheme = parts.scheme.lower()
    if scheme not in SCHEMES or not parts.netloc:
        errs.add(loc, "Use an absolute http:// or https:// URL")
        return None
    if "@" in parts.netloc:
        errs.add(loc, "The URL must not contain credentials (user:password@)")
        return None
    if "#" in url:
        errs.add(loc, "The URL must not contain a fragment (#...)")
        return None
    host, herr = normalise_host_pattern(parts.hostname or "")
    if herr or host is None:
        errs.add(loc, f"Invalid host: {herr}")
        return None
    if host.startswith("*."):
        errs.add(loc, "The base URL must name a concrete host, not a wildcard")
        return None
    if port == 0:
        errs.add(loc, "Invalid port")
        return None
    return ParsedURL(scheme, host, port or DEFAULT_PORTS[scheme], normalise_path(parts.path))


def format_base_url(p: ParsedURL, query: str = "") -> str:
    host = f"[{p.host}]" if ":" in p.host else p.host
    port = "" if DEFAULT_PORTS[p.scheme] == p.port else f":{p.port}"
    return f"{p.scheme}://{host}{port}{p.path}" + (f"?{query}" if query else "")


def _list(value: Any, key: str, errs: _Collector) -> list | None:
    lo, hi = LIMITS[key]
    if not isinstance(value, list):
        errs.add(("scope", key), "Must be a list")
        return None
    if not lo <= len(value) <= hi:
        errs.add(("scope", key), f"Must contain between {lo} and {hi} entries")
        return None
    return value


def _dedupe(items: Iterable) -> list:
    seen: set = set()
    return [x for x in items if not (x in seen or seen.add(x))]


def _host_policy_error(host: str, ctx: PolicyContext) -> str | None:
    """Platform-level refusal for a scoped host (6.1 create-time rules)."""
    ip = parse_ip(host)
    if ip is not None:
        cat = classify_ip(ip)
        text = _CATEGORY_TEXT.get(cat, cat)
        if is_always_denied(cat):
            return f"{host} is a {text} address and can never be scanned"
        if is_private(cat) and not ctx.allow_private:
            return (f"{host} is a {text} address; private and loopback targets are "
                    "disabled on this platform")
        return None
    bare = host[2:] if host.startswith("*.") else host
    if is_loopback_name(bare):
        if not ctx.allow_private:
            return (f"{host} is a loopback name; private and loopback targets are "
                    "disabled on this platform")
    if any(host_matches(host, b) or host == b for b in ctx.blocked_hosts):
        return f"{host} is a platform service and can never be a target"
    return None


def _is_private_host(host: str) -> bool:
    ip = parse_ip(host)
    if ip is not None:
        return is_private(classify_ip(ip))
    return is_loopback_name(host[2:] if host.startswith("*.") else host)


def _endpoint_blocked(host: str, port: int, ctx: PolicyContext) -> bool:
    for b_host, b_port in ctx.blocked_endpoints:
        if b_port != port:
            continue
        if b_host == "private" and _is_private_host(host):
            return True
        if b_host == host or (host.startswith("*.") and host_matches(host, b_host)):
            return True
    return False


def build_scope(base_url: Any, scope: Mapping[str, Any] | None,
                ctx: PolicyContext) -> tuple[str | None, ScopePolicy | None, list[FieldError]]:
    """Validate and normalise. Returns (normalised base_url, policy, errors).

    Missing scope fields default from the base URL. ``scope`` must have
    passed structural (type) validation already; this applies the semantic rules."""
    errs = _Collector()
    query = ""
    if isinstance(base_url, str):
        try:
            query = urlsplit(base_url.strip()).query
        except ValueError:
            query = ""
    base = normalise_base_url(base_url, errs)
    scope = dict(scope or {})

    # hosts --------------------------------------------------------------------
    hosts: list[str] = []
    hosts_ok = False   # an explicit list that parsed cleanly
    raw_hosts = scope.get("allowed_hosts")
    if raw_hosts is None:
        hosts = [base.host] if base else []
    elif (lst := _list(raw_hosts, "allowed_hosts", errs)) is not None:
        hosts_ok = True
        for i, h in enumerate(lst):
            norm, msg = normalise_host_pattern(h)
            if msg:
                errs.add(("scope", "allowed_hosts", i), msg)
                hosts_ok = False
            else:
                hosts.append(norm)
        hosts = _dedupe(hosts)
    if base:
        if hosts_ok and base.host not in hosts:
            errs.add(("scope", "allowed_hosts"),
                     f"Must include the base URL host ({base.host})")
        msg = _host_policy_error(base.host, ctx)
        if msg:
            errs.add(("base_url",), msg)
    if raw_hosts is not None and isinstance(raw_hosts, list):
        for i, h in enumerate(raw_hosts):
            norm, _ = normalise_host_pattern(h)
            if norm is None or (base and norm == base.host):
                continue   # syntax error already reported / base host reported on base_url
            msg = _host_policy_error(norm, ctx)
            if msg:
                errs.add(("scope", "allowed_hosts", i), msg)

    # schemes ------------------------------------------------------------------
    schemes: list[str] = []
    raw_schemes = scope.get("allowed_schemes")
    if raw_schemes is None:
        schemes = [base.scheme] if base else []
    elif (lst := _list(raw_schemes, "allowed_schemes", errs)) is not None:
        schemes_ok = True
        for i, s in enumerate(lst):
            s2 = s.strip().lower() if isinstance(s, str) else None
            if s2 not in SCHEMES:
                errs.add(("scope", "allowed_schemes", i), "Must be http or https")
                schemes_ok = False
            else:
                schemes.append(s2)
        schemes = [s for s in SCHEMES if s in schemes]
        if base and schemes_ok and base.scheme not in schemes:
            errs.add(("scope", "allowed_schemes"),
                     f"Must include the base URL scheme ({base.scheme})")

    # ports --------------------------------------------------------------------
    ports: list[int] = []
    raw_ports = scope.get("allowed_ports")
    if raw_ports is None:
        ports = [base.port] if base else []
    elif (lst := _list(raw_ports, "allowed_ports", errs)) is not None:
        bad = False
        for i, p in enumerate(lst):
            if isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535:
                errs.add(("scope", "allowed_ports", i), "Must be a port between 1 and 65535")
                bad = True
            else:
                ports.append(p)
        ports = _dedupe(ports)
        if base and not bad and base.port not in ports:
            errs.add(("scope", "allowed_ports"),
                     f"Must include the base URL port ({base.port})")
    for i, p in enumerate(ports):
        blocked_on = [h for h in hosts if _endpoint_blocked(h, p, ctx)]
        if blocked_on:
            loc = ("base_url",) if (raw_ports is None) else ("scope", "allowed_ports", i)
            errs.add(loc, f"Port {p} on {blocked_on[0]} is a platform service and can "
                          "never be a target")

    # paths --------------------------------------------------------------------
    def _paths(key: str, default: list[str]) -> list[str]:
        raw = scope.get(key)
        if raw is None:
            return list(default)
        lst = _list(raw, key, errs)
        if lst is None:
            return []
        out = []
        for i, p in enumerate(lst):
            if not isinstance(p, str) or not p.startswith("/"):
                errs.add(("scope", key, i), "Must start with /")
            elif len(p) > MAX_PATH_LEN or _BAD_URL_CHARS.search(p) or "?" in p or "#" in p:
                errs.add(("scope", key, i),
                         f"Must be a path of at most {MAX_PATH_LEN} characters, "
                         "without spaces, query or fragment")
            else:
                out.append(normalise_path(p))
        return _dedupe(out)

    prefixes = _paths("path_prefixes", ["/"])
    excluded = _paths("excluded_paths", [])

    redirect = scope.get("redirect_policy", "in_scope")
    if redirect not in REDIRECT_POLICIES:
        errs.add(("scope", "redirect_policy"), "Must be in_scope or none")
    # Hosts the target is known to redirect to (an SSO provider, a partner): never
    # requested, only announced. A host that is already in scope needs no entry.
    declared_redirects: list[str] = []
    honor_declared = scope.get("honor_declared_redirects", False)
    if not isinstance(honor_declared, bool):
        errs.add(("scope", "honor_declared_redirects"), "Must be true or false")
        honor_declared = False
    raw_redir_hosts = scope.get("redirect_hosts")
    if raw_redir_hosts is not None:
        lst = _list(raw_redir_hosts, "redirect_hosts", errs) or []
        if len(lst) > 10:
            errs.add(("scope", "redirect_hosts"), "Must list at most 10 hosts")
            lst = lst[:10]
        for i, h in enumerate(lst):
            norm, msg = normalise_host_pattern(h)
            if msg:
                errs.add(("scope", "redirect_hosts", i), msg)
            elif norm not in hosts and norm not in declared_redirects:
                declared_redirects.append(norm)
    auth = scope.get("allow_auth_testing", True)
    if not isinstance(auth, bool):
        errs.add(("scope", "allow_auth_testing"), "Must be true or false")

    probes: list[str] = []
    raw_expl = scope.get("exploration")
    if raw_expl is not None:
        if not isinstance(raw_expl, Mapping):
            errs.add(("scope", "exploration"), "Must be an object")
        else:
            lst = raw_expl.get("active_probes", [])
            if not isinstance(lst, list) or len(lst) > 10:
                errs.add(("scope", "exploration", "active_probes"),
                         "Must be a list of at most 10 entries")
                lst = []
            for i, name in enumerate(lst):
                if name not in ACTIVE_PROBE_TOOLS:
                    errs.add(("scope", "exploration", "active_probes", i),
                             "Must be one of: " + ", ".join(ACTIVE_PROBE_TOOLS))
                elif name not in probes:
                    probes.append(name)

    # target-neutral network boundary (netscope.py) ------------------------------
    from src.greybox_web import netscope
    network, net_errs = netscope.parse(
        scope.get("network"), host_error=lambda h: _host_policy_error(h, ctx))
    for loc, msg in net_errs:
        errs.add(loc, msg)
    state_changing = False
    resource_lifecycle = "unknown"
    raw_activity = scope.get("activity")
    if raw_activity is not None:
        if not isinstance(raw_activity, Mapping) or set(raw_activity) - {
                "state_changing", "resource_lifecycle"}:
            errs.add(("scope", "activity"),
                     "Must contain only state_changing and resource_lifecycle")
        else:
            state_changing = raw_activity.get("state_changing", False)
            if not isinstance(state_changing, bool):
                errs.add(("scope", "activity", "state_changing"), "Must be true or false")
                state_changing = False
            resource_lifecycle = raw_activity.get("resource_lifecycle", "unknown")
            if resource_lifecycle not in RESOURCE_LIFECYCLES:
                errs.add(("scope", "activity", "resource_lifecycle"),
                         "Must be one of: " + ", ".join(RESOURCE_LIFECYCLES))
                resource_lifecycle = "unknown"

    if errs.errors or base is None:
        return None, None, errs.errors
    policy = ScopePolicy(
        allowed_hosts=tuple(hosts), allowed_schemes=tuple(schemes),
        allowed_ports=tuple(ports), path_prefixes=tuple(prefixes),
        excluded_paths=tuple(excluded), redirect_policy=redirect,
        allow_auth_testing=auth, active_probes=tuple(probes),
        redirect_hosts=tuple(declared_redirects),
        honor_declared_redirects=honor_declared,
        network=network, state_changing=state_changing,
        resource_lifecycle=resource_lifecycle,
    )
    normalised = format_base_url(base, query)
    # The base URL itself must be in scope, or nothing could ever be requested.
    decision = policy.check_url(normalised)
    if not decision.allowed:
        loc = ("scope", "excluded_paths") if decision.reason == "path_excluded" else \
            ("scope", "path_prefixes")
        return None, None, [FieldError(loc, f"The base URL path {base.path} is outside "
                                            f"the scope ({decision.reason})")]
    return normalised, policy, []
