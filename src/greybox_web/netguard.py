"""IP policy and the guarded HTTP client for grey-box runs.

The top half is pure IP classification, shared with create-time scope validation. The
bottom half (M2) is the only network path of the engine: :class:`GuardedHttpClient`
with an injectable resolver, IP pinning, per-hop scope re-checks, budgets, rate and
concurrency limits, body caps and an exchange recorder hook. Tools never import httpx.

Categories returned by :func:`classify_ip`:

* always denied: ``metadata``, ``link_local``, ``unspecified``, ``multicast``, ``reserved``
* denied unless authorised: ``loopback``, ``private``, ``cgnat``, ``ula``
* ``public``

IPv4-mapped (``::ffff:a.b.c.d``), IPv4-compatible (``::a.b.c.d``), NAT64
(``64:ff9b::/96``, ``64:ff9b:1::/48``) and 6to4 (``2002::/16``) addresses are classified
by the IPv4 address they embed, so ``::ffff:169.254.169.254`` is ``metadata``.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any, Protocol
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

import httpx

IPAddress = IPv4Address | IPv6Address

ALWAYS_DENIED = frozenset({"metadata", "link_local", "unspecified", "multicast", "reserved"})
PRIVATE_CATEGORIES = frozenset({"loopback", "private", "cgnat", "ula"})

_METADATA = frozenset({
    IPv4Address("169.254.169.254"),
    IPv6Address("fd00:ec2::254"),
})

_V4_RULES: tuple[tuple[IPv4Network, str], ...] = (
    (IPv4Network("0.0.0.0/8"), "unspecified"),
    (IPv4Network("169.254.0.0/16"), "link_local"),
    (IPv4Network("224.0.0.0/4"), "multicast"),
    (IPv4Network("240.0.0.0/4"), "reserved"),       # includes 255.255.255.255
    (IPv4Network("127.0.0.0/8"), "loopback"),
    (IPv4Network("10.0.0.0/8"), "private"),
    (IPv4Network("172.16.0.0/12"), "private"),
    (IPv4Network("192.168.0.0/16"), "private"),
    (IPv4Network("100.64.0.0/10"), "cgnat"),
)

_V6_RULES: tuple[tuple[IPv6Network, str], ...] = (
    (IPv6Network("::/128"), "unspecified"),
    (IPv6Network("::1/128"), "loopback"),
    (IPv6Network("fe80::/10"), "link_local"),
    (IPv6Network("ff00::/8"), "multicast"),
    (IPv6Network("fc00::/7"), "ula"),
    (IPv6Network("fec0::/10"), "private"),          # deprecated site-local
)

_NAT64 = (IPv6Network("64:ff9b::/96"), IPv6Network("64:ff9b:1::/48"))
_IPV4_COMPAT = IPv6Network("::/96")
_6TO4 = IPv6Network("2002::/16")


def parse_ip(host: str) -> IPAddress | None:
    """Return the address if ``host`` is a canonical IPv4/IPv6 literal (``[...]`` allowed)."""
    h = (host or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if "%" in h:  # zone ids (fe80::1%eth0) are never valid targets
        return None
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        return None


def _embedded_v4(ip: IPv6Address) -> IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if any(ip in net for net in _NAT64):
        return IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _6TO4:
        return ip.sixtofour
    if ip in _IPV4_COMPAT and int(ip) > 1:   # ::a.b.c.d (deprecated), not :: or ::1
        return IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def classify_ip(ip: IPAddress | str) -> str:
    if isinstance(ip, str):
        parsed = parse_ip(ip)
        if parsed is None:
            raise ValueError(f"not an IP address: {ip!r}")
        ip = parsed
    if ip in _METADATA:
        return "metadata"
    if isinstance(ip, IPv6Address):
        v4 = _embedded_v4(ip)
        if v4 is not None:
            return classify_ip(v4)
        rules = _V6_RULES
    else:
        rules = _V4_RULES
    for net, cat in rules:
        if ip in net:
            return cat
    return "public"


def is_always_denied(category: str) -> bool:
    return category in ALWAYS_DENIED


def is_private(category: str) -> bool:
    return category in PRIVATE_CATEGORIES


def ip_denial(ip: IPAddress | str, *, allow_private: bool, host_authorised: bool = True) -> str | None:
    """Reason code (``ip_denied:<category>`` / ``private_ip_for_public_name``) or None.

    ``host_authorised`` is False when the request host is a public name that is not
    itself a scoped private host (DNS-rebinding defence, used by M2's client)."""
    cat = classify_ip(ip)
    if is_always_denied(cat):
        return f"ip_denied:{cat}"
    if is_private(cat):
        if not allow_private:
            return f"ip_denied:{cat}"
        if not host_authorised:
            return "private_ip_for_public_name"
    return None


def is_loopback_name(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    return h == "localhost" or h.endswith(".localhost")


# =====================================================================================
# M2: resolver, budget and GuardedHttpClient
# =====================================================================================


READ_CAP = 1024 * 1024          # bytes read from a response body at most (4.5)
MAX_REDIRECT_HOPS = 5
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "Vigilo-Greybox/1 (authorised security test)"


READ_METHODS = ("GET", "HEAD", "OPTIONS", "POST")
# Sent only when the operator authorised state-changing activity for the target.
STATE_CHANGING_METHODS = ("PUT", "PATCH", "DELETE")
MAX_REQUEST_BODY = 64 * 1024


class RunCancelled(Exception):
    """The run was cancelled (or lost its lease): stop immediately."""


class BudgetExhausted(Exception):
    def __init__(self, budget: str) -> None:   # "requests" | "time"
        super().__init__(f"{budget} budget exhausted")
        self.budget = budget


class ScopeViolation(Exception):
    def __init__(self, url: str, reason: str, exchange_id: int | None = None) -> None:
        super().__init__(f"blocked ({reason})")
        self.url = url
        self.reason = reason
        self.exchange_id = exchange_id


class TransportFailure(Exception):
    """Network-level failure (timeout, connect error, DNS). Retryable once."""

    def __init__(self, kind: str, exchange_id: int | None = None,
                 response: "HttpResponse | None" = None) -> None:
        super().__init__(kind)
        self.kind = kind
        self.exchange_id = exchange_id
        # Set only for ``declared_redirect``: the target DID answer (the response
        # before the refused hop). The tool can analyse that answer instead of
        # treating the whole work order as a network failure.
        self.response = response


class Budget:
    """Request count, deadline and cancellation for one run.

    ``check()`` runs before every request and every redirect hop; blocked attempts
    count. The supervisor sets ``cancelled`` when it observes the DB cancel flag."""

    def __init__(self, max_requests: int, max_duration_s: float, *, used: int = 0,
                 clock=time.monotonic) -> None:
        self.max_requests = max_requests
        self.max_duration_s = max_duration_s
        self.used = used
        self._clock = clock
        self.started = clock()
        self.deadline = self.started + max_duration_s
        self.cancelled = False
        self.exhausted: str | None = None

    def remaining_s(self) -> float:
        return max(0.0, self.deadline - self._clock())

    def check(self) -> None:
        if self.cancelled:
            raise RunCancelled()
        if self._clock() >= self.deadline:
            self.exhausted = self.exhausted or "time"
            raise BudgetExhausted("time")
        if self.used >= self.max_requests:
            self.exhausted = self.exhausted or "requests"
            raise BudgetExhausted("requests")

    def check_cancel(self) -> None:
        """Cancellation only — safe after ``consume()`` has already counted this
        request (a request waiting on the semaphore/rate limit must still abort
        promptly on cancel, but must not be double-counted)."""
        if self.cancelled:
            raise RunCancelled()

    def consume(self) -> None:
        self.check()
        self.used += 1


class Resolver(Protocol):
    async def resolve(self, host: str, port: int) -> list[str]: ...


class SystemResolver:
    async def resolve(self, host: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        out: list[str] = []
        for info in infos:
            addr = str(info[4][0])
            if addr not in out:
                out.append(addr)
        return out


def _canon_host(host: str) -> str:
    """Same canonical form as scope matching (lower-case, no trailing dot, IDNA)."""
    from src.greybox_web.scope import canonical_host   # lazy: scope imports netguard
    return canonical_host(host) or (host or "").lower().rstrip(".")


@dataclass(frozen=True)
class NetPolicy:
    """Platform-level network policy (settings), applied after DNS resolution."""

    allow_private: bool = False
    blocked_hosts: frozenset[str] = frozenset()
    blocked_endpoints: tuple[tuple[str, int], ...] = ()   # ("private"|host|ip, port)

    @classmethod
    def from_settings(cls) -> NetPolicy:
        from src.greybox_web import settings as gb_settings
        s = gb_settings.settings()
        return cls(
            allow_private=bool(s.greybox_allow_private_targets),
            blocked_hosts=gb_settings.blocked_hosts(s),
            blocked_endpoints=tuple((e.host, e.port)
                                    for e in gb_settings.blocked_endpoints(s)),
        )

    def host_blocked(self, host: str) -> bool:
        h = _canon_host(host)
        return any(h == b or h.endswith("." + b) for b in self.blocked_hosts)

    def address_denial(self, host: str, addr: str, port: int, *,
                       via_proxy: bool = False) -> str | None:
        """Reason the resolved ``addr`` must not be contacted, or None.

        ``via_proxy``: ``addr`` is the engine's own (advisory) DNS answer for a name the
        proxy will resolve. The rebinding rule "private answer for a public name" does
        not apply (an internal name resolving to a private address is the normal case
        behind a corporate proxy), but the never-classes and ``allow_private`` do."""
        literal = parse_ip(host) is not None
        authorised = literal or is_loopback_name(host) or via_proxy
        reason = ip_denial(addr, allow_private=self.allow_private,
                           host_authorised=authorised)
        if reason:
            return reason
        cat = classify_ip(addr)
        canon = str(parse_ip(addr))
        for b_host, b_port in self.blocked_endpoints:
            if b_port != port:
                continue
            if b_host == "private" and is_private(cat):
                return "blocked_endpoint"
            if b_host in (canon, _canon_host(host)) or _canon_host(b_host) == canon \
                    or _canon_host(b_host) == _canon_host(host):
                return "blocked_endpoint"
        return None


def _pattern_covers_host(patterns: Sequence[str], host: str) -> bool:
    from src.greybox_web.scope import host_matches
    return any(host_matches(q, host) for q in patterns)


def _pattern_covers_pattern(patterns: Sequence[str], p: str) -> bool:
    """True when every host matched by scope pattern ``p`` (exact host or ``*.suffix``)
    is matched by one of ``patterns``."""
    if not p.startswith("*."):
        return _pattern_covers_host(patterns, p)
    t = p[2:]
    for q in patterns:
        if q == p:
            return True
        if q.startswith("*.") and (t == q[2:] or t.endswith("." + q[2:])):
            return True
    return False


@dataclass(frozen=True)
class EgressProxy:
    """The explicit, admin-selected forward proxy of one run.

    ``password`` never appears in ``repr`` (so it cannot reach a log through it)."""

    id: str
    name: str
    url: str                                   # scheme://host:port, no userinfo
    allowed_hosts: tuple[str, ...]
    username: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)

    def host_allowed(self, host: str) -> bool:
        return _pattern_covers_host(self.allowed_hosts, _canon_host(host))

    def covers(self, scope_hosts: Sequence[str]) -> list[str]:
        """The scope host patterns this proxy does NOT allow (empty = all covered)."""
        return [h for h in scope_hosts
                if not _pattern_covers_pattern(self.allowed_hosts, h)]

    def transport(self, *, max_connections: int) -> httpx.AsyncBaseTransport:
        auth = (self.username, self.password or "") if self.username else None
        return httpx.AsyncHTTPTransport(
            verify=True, trust_env=False,
            limits=httpx.Limits(max_connections=max(1, max_connections)),
            proxy=httpx.Proxy(self.url, auth=auth))


# Transport failure kinds specific to the proxy path (ExchangeData.error / TransportFailure.kind).
PROXY_ERRORS = {
    "proxy_unreachable": "proxy unreachable",
    "proxy_auth": "proxy authentication failed",
    "proxy_refused": "target refused via proxy",
    "tls_error": "TLS verification failed",
}


@dataclass
class ExchangeData:
    """One request attempt, unredacted. The recorder redacts before persisting."""

    method: str
    url: str
    tool: str
    agent_id: Any = None
    work_order_id: Any = None
    tool_call_id: str | None = None
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    resolved_ip: str | None = None
    via_proxy: bool = False
    status_code: int | None = None
    duration_ms: int | None = None
    request_headers: list[tuple[str, str]] = field(default_factory=list)
    request_body: str | None = None
    response_headers: list[tuple[str, str]] = field(default_factory=list)
    response_body: bytes | None = None
    response_truncated: bool = False
    content_type: str | None = None
    blocked: bool = False
    block_reason: str | None = None
    error: str | None = None
    redirect_hop: int = 0
    parent_exchange_id: int | None = None
    identity: str | None = None


class Recorder(Protocol):
    async def record(self, ex: ExchangeData) -> int | None: ...


class NullRecorder:
    """Keeps exchanges in memory (preflight, unit tests)."""

    def __init__(self) -> None:
        self.items: list[ExchangeData] = []

    async def record(self, ex: ExchangeData) -> int | None:
        self.items.append(ex)
        return len(self.items)


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool
    exchange_id: int | None
    exchange_ids: list[int]
    elapsed_ms: int
    resolved_ip: str | None = None
    redirect_blocked: str | None = None
    # Every URL this request visited, in order, before the response returned
    # (``[requested, hop1, ..., final]``). A redirect chain that leaves the target is
    # how an expired session announces itself; tools and the auth-boundary detector
    # read it, and discovery never attributes a followed body to the URL requested.
    hops: list[str] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").lower()

    @property
    def text(self) -> str:
        charset = "utf-8"
        ct = self.content_type
        if "charset=" in ct:
            charset = ct.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type


class _RateLimiter:
    def __init__(self, rps: float) -> None:
        self.interval = 1.0 / max(rps, 0.001)
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next = max(now, self._next) + self.interval


async def _read_bounded(resp: httpx.Response) -> tuple[bytes, bool]:
    """Read the body with a hard cap on DECODED bytes (gzip-bomb defence).

    Reads raw (still encoded) chunks and decodes gzip/deflate incrementally with
    ``zlib.decompressobj(...).decompress(data, max_length)``, so no single chunk can
    expand beyond what is left of READ_CAP. Other or stacked content-codings are
    returned undecoded (raw bytes, same cap) rather than decoded unboundedly."""
    if resp.is_stream_consumed:
        # Already buffered (and decoded) by an in-memory transport such as
        # httpx.MockTransport; real network responses are never pre-read.
        data = resp.content
        return data[:READ_CAP], len(data) >= READ_CAP
    coding = (resp.headers.get("content-encoding") or "").strip().lower()
    wbits = {"gzip": 16 + zlib.MAX_WBITS, "x-gzip": 16 + zlib.MAX_WBITS,
             "deflate": zlib.MAX_WBITS}.get(coding)
    out: list[bytes] = []
    size = 0
    raw_size = 0
    dec = zlib.decompressobj(wbits) if wbits is not None else None
    first = True
    async for chunk in resp.aiter_raw():
        raw_size += len(chunk)
        if dec is None:
            out.append(chunk)
            size += len(chunk)
            if size >= READ_CAP:
                return b"".join(out)[:READ_CAP], True
            continue
        pending = chunk
        while pending:
            try:
                part = dec.decompress(pending, READ_CAP - size)
            except zlib.error:
                if first and coding == "deflate":
                    dec = zlib.decompressobj(-zlib.MAX_WBITS)   # raw deflate
                    first = False
                    continue
                return b"".join(out)[:READ_CAP], size >= READ_CAP   # corrupt: keep prefix
            first = False
            out.append(part)
            size += len(part)
            if size >= READ_CAP:
                return b"".join(out)[:READ_CAP], True
            pending = dec.unconsumed_tail
            if dec.eof:
                break
        if raw_size >= READ_CAP and not dec.eof:
            return b"".join(out)[:READ_CAP], True
    return b"".join(out)[:READ_CAP], False


def _is_tls_failure(exc: BaseException) -> bool:
    """A TLS handshake/verification failure (in the exception chain), as opposed to a
    failure to connect to the proxy."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, ssl.SSLError):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False


def _netloc(host: str, port: int, scheme: str) -> str:
    h = f"[{host}]" if ":" in host else host
    default = {"http": 80, "https": 443}.get(scheme)
    return h if port == default else f"{h}:{port}"


class GuardedHttpClient:
    """The only HTTP client of the engine.

    For each request and each redirect hop: budget check (cancel, deadline, count) ->
    scope check -> resolve + classify every address -> pin to the first validated
    address (Host header and TLS SNI keep the original name) -> rate limit +
    concurrency -> capped streaming read -> record -> maybe follow (in scope only)."""

    def __init__(self, *, scope, budget: Budget, policy: NetPolicy,
                 max_concurrency: int = 4, rate_limit_rps: float = 10,
                 request_timeout_s: float = 10, recorder: Recorder | None = None,
                 resolver: Resolver | None = None, cookie_header: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None,
                 egress_proxy: EgressProxy | None = None) -> None:
        self.scope = scope
        self.proxy = egress_proxy
        self.budget = budget
        self.policy = policy
        self.recorder = recorder or NullRecorder()
        self.resolver = resolver or SystemResolver()
        self._cookie = cookie_header
        # Established sessions (label -> {"cookie", "authorization"}): created by
        # the auth.login tool at run time and readable by every later tool. The
        # provided cookie credential stays the DEFAULT identity (requests that do
        # not ask for a session); "anon" explicitly sends no identity.
        self._sessions: dict[str, dict[str, str | None]] = {}
        # browser identity -> cookie jar, and who to tell when identities change
        # (the supervisor persists them, encrypted, for resume: sessionvault.py)
        self._jars: dict[str, list[dict]] = {}
        self.on_identity_change: Any = None
        self._timeout = float(min(request_timeout_s, 30))
        self._sem = asyncio.Semaphore(max(1, max_concurrency))
        self._rate = _RateLimiter(rate_limit_rps)
        if egress_proxy is not None and transport is None:
            # A dedicated transport per run; never the environment (trust_env=False).
            transport = egress_proxy.transport(max_connections=max_concurrency)
        self._client = httpx.AsyncClient(
            follow_redirects=False, trust_env=False, verify=True,
            timeout=httpx.Timeout(self._timeout),
            limits=httpx.Limits(max_connections=max(1, max_concurrency)),
            transport=transport)
        self.blocked: list[tuple[str, str]] = []   # (url, reason), for callers/tests

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> GuardedHttpClient:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    def bind(self, tool: str, *, agent_id=None, work_order_id=None,
             tool_call_id: str | None = None) -> ToolHttp:
        return ToolHttp(self, dict(tool=tool, agent_id=agent_id,
                                   work_order_id=work_order_id,
                                   tool_call_id=tool_call_id))

    # ------------------------------------------------------------- sessions
    def establish_session(self, label: str, cookie: str | None,
                          authorization: str | None = None) -> None:
        """Register (or replace) a session the auth.login tool established. The
        values are only ever sent as request headers to in-scope hosts."""
        if not label or label == "anon" or len(label) > 100:
            raise ValueError("invalid session label")
        # Session tokens are secrets from now on: whatever later echoes them (a
        # page script, a response body, an agent-written tool's output) is
        # redacted before it is stored, streamed or shown to the model.
        from src.greybox_web import redaction
        register_session_secrets(redaction, cookie, authorization)
        self._sessions[label] = {"cookie": cookie, "authorization": authorization}
        self._identity_changed()

    # ------------------------------------------------- identity persistence
    def _identity_changed(self) -> None:
        cb = self.on_identity_change
        if cb is not None:
            try:
                cb()
            except Exception:                           # noqa: BLE001 — never a tool's problem
                pass

    def remember_jar(self, identity: str, cookies: list[dict]) -> None:
        """The browser's cookie jar of one identity (persisted for resume)."""
        if self._jars.get(identity) != cookies:
            self._jars[identity] = list(cookies)
            self._identity_changed()

    def jar(self, identity: str) -> list[dict] | None:
        return self._jars.get(identity)

    def identity_state(self) -> tuple[dict, dict]:
        return dict(self._sessions), dict(self._jars)

    def restore_identities(self, sessions: dict, jars: dict) -> list[str]:
        """Reinstate persisted identities (resume). Returns the labels restored."""
        for label, s in (sessions or {}).items():
            if label and label != "anon" and len(label) <= 100:
                self._sessions[label] = {"cookie": s.get("cookie"),
                                         "authorization": s.get("authorization")}
        self._jars = {k: list(v) for k, v in (jars or {}).items()}
        return sorted(self._sessions)

    def sessions(self) -> list[dict[str, Any]]:
        """Session labels and what they hold — names only, never values."""
        out = [{"label": label, "cookie_names": _cookie_names(
                    (s.get("cookie") or "")),
                "authorization": bool(s.get("authorization"))}
               for label, s in self._sessions.items()]
        if self._cookie:
            out.append({"label": "provided-cookie", "cookie_names":
                        _cookie_names(self._cookie), "authorization": False})
        return out

    def _identity_label(self, session: str | None, cookie: str | None) -> str:
        """Which identity a request is attributed to in the audit trail (a label,
        never a value): the named session, the provided cookie, or anonymous.

        A browser request (``cookie`` given: the page's own jar) is attributed to
        the identity whose jar it is. An anonymous browser context that acquired
        cookies by itself (e.g. a login driven through the UI) is NOT anonymous any
        more and is labelled ``browser-session``, so cross-identity analyses never
        mistake what it was shown for what an anonymous visitor sees."""
        if cookie is not None:
            if session == "anon" or (session is None and not self._cookie):
                return "anon" if not cookie else "browser-session"
            return str(session)[:64] if session else "provided-cookie"
        if session == "anon":
            return "anon"
        if session:
            return str(session)[:64]
        return "provided-cookie" if self._cookie else "anon"

    def _resolve_session(self, session: str | None) -> dict[str, str | None] | None:
        """The identity a request carries: a named session, the provided cookie
        (default), or none (``"anon"``)."""
        if session is None or session == "":
            return {"cookie": self._cookie, "authorization": None} \
                if self._cookie else None
        if session == "anon":
            return None
        sess = self._sessions.get(session)
        if sess is None and session == "provided-cookie" and self._cookie:
            # the label sessions() advertises for the operator-provided cookie:
            # callers that iterate the advertised identities must be able to use it
            return {"cookie": self._cookie, "authorization": None}
        if sess is None:
            raise ValueError(f"unknown session {session!r}")
        return sess

    # ---------------------------------------------------------------- internals
    async def _block(self, base: ExchangeData, reason: str) -> int | None:
        base.blocked = True
        base.block_reason = reason
        self.blocked.append((base.url, reason))
        return await self.recorder.record(base)

    async def _resolve(self, host: str, port: int) -> list[str]:
        ip = parse_ip(host)
        if ip is not None:
            return [str(ip)]
        return await asyncio.wait_for(self.resolver.resolve(host, port),
                                      timeout=self._timeout)

    async def request(self, method: str, url: str, *, prov: Mapping[str, Any],
                      headers: Sequence[tuple[str, str]] | None = None,
                      form: Mapping[str, str] | None = None,
                      follow: bool = True,
                      session: str | None = None,
                      body: bytes | str | None = None,
                      content_type: str | None = None,
                      cookie: str | None = None,
                      state_changing: bool = False) -> HttpResponse:
        """``cookie``: an explicit Cookie header (the browser's own jar) used INSTEAD
        of the run's session identity, and only ever sent to an in-scope host."""
        method = method.upper()
        if method not in READ_METHODS + STATE_CHANGING_METHODS:
            raise ValueError(f"method {method} not allowed")
        if (method in STATE_CHANGING_METHODS or state_changing) \
                and not getattr(self.scope, "state_changing", False):
            # Activity policy (scope.activity.state_changing, off by default): the
            # refusal is recorded like any scope refusal, never sent.
            ex = ExchangeData(method=method, url=url, **prov)
            xid = await self._block(ex, "state_changing_not_allowed")
            raise ScopeViolation(url, "state_changing_not_allowed", xid)
        hop = 0
        parent: int | None = None
        ids: list[int] = []
        prev: HttpResponse | None = None
        raw_body: bytes | None = None
        if body is not None and method in ("POST", "PUT", "PATCH", "DELETE"):
            raw_body = body.encode() if isinstance(body, str) else bytes(body)
            if len(raw_body) > MAX_REQUEST_BODY:
                raise ValueError("request body too large")
        body = urlencode(dict(form)) if form is not None and method == "POST" else None
        if raw_body is not None and body is None:
            body = raw_body.decode("utf-8", "replace")
        while True:
            self.budget.consume()   # raises RunCancelled / BudgetExhausted
            ex = ExchangeData(method=method, url=url, redirect_hop=hop,
                              parent_exchange_id=parent, **prov)
            ex.identity = self._identity_label(session, cookie)
            decision = self.scope.check_url(url)
            parts = urlsplit(url)
            ex.scheme = (parts.scheme or "").lower() or None
            ex.path = parts.path or "/"
            try:
                ex.host = (parts.hostname or "").lower() or None
                ex.port = parts.port or {"http": 80, "https": 443}.get(ex.scheme or "")
            except ValueError:
                ex.port = None
            # A redirect to a host the operator DECLARED as intentional (an SSO
            # provider) is refused before any packet is addressed to it: the hop is
            # recorded as evidence and the previous response is returned. Scope is
            # unchanged (declared is not in scope) -- only the wire is spared.
            if hop > 0 and prev is not None and (
                    self.scope.redirect_is_declared(url)
                    if hasattr(self.scope, "redirect_is_declared") else False):
                ex.blocked = True
                ex.block_reason = "declared_redirect"
                ex.error = "declared_redirect_not_followed"
                xid = await self.recorder.record(ex)
                if xid is not None:
                    ids.append(xid)
                prev.redirect_blocked = "declared_redirect"
                prev.exchange_ids = list(ids)
                if hop > 1:
                    return prev            # a later hop: the first response stands
                # the FIRST response redirected off-scope: the tool has no
                # HttpResponse to return, but the answer exists -- hand it over
                raise TransportFailure("declared_redirect", xid, response=prev)
            if not decision.allowed:
                xid = await self._block(ex, decision.reason or "invalid_url")
                return self._blocked_result(prev, url, decision.reason, xid, ids, hop)
            host, port, scheme = ex.host or "", int(ex.port or 0), ex.scheme or "http"
            # Canonical ASCII (punycode, no trailing dot) form for policy, DNS, the
            # Host header and SNI: a trailing dot must not dodge blocked_endpoints and
            # a Unicode name must not crash header encoding after the budget is spent.
            from src.greybox_web.scope import canonical_host
            host_ascii = canonical_host(host)
            if host_ascii is None or not host_ascii.isascii():
                xid = await self._block(ex, "invalid_url")
                return self._blocked_result(prev, url, "invalid_url", xid, ids, hop)
            host = host_ascii
            reason = "blocked_host" if self.policy.host_blocked(host) else None
            addrs: list[str] = []
            if reason is None and self.proxy is not None:
                reason = await self._proxy_denial(host, port)
            elif reason is None:
                try:
                    addrs = await self._resolve(host, port)
                except (OSError, asyncio.TimeoutError, UnicodeError):
                    ex.error = "dns_error"
                    xid = await self.recorder.record(ex)
                    raise TransportFailure("dns_error", xid) from None
                if not addrs:
                    reason = "dns_no_address"
                for addr in addrs:
                    reason = reason or self.policy.address_denial(host, addr, port)
            if reason:
                xid = await self._block(ex, reason)
                return self._blocked_result(prev, url, reason, xid, ids, hop)

            if self.proxy is not None:
                # The proxy resolves the name: nothing to pin, the wire URL keeps the
                # hostname (CONNECT host:port / absolute-form; TLS verifies the name).
                pinned = None
                ex.via_proxy = True
                wire = urlunsplit((scheme, _netloc(host, port, scheme),
                                   parts.path or "/", parts.query, ""))
            else:
                pinned = str(parse_ip(addrs[0]))
                ex.resolved_ip = pinned
                wire = urlunsplit((scheme, _netloc(pinned, port, scheme),
                                   parts.path or "/", parts.query, ""))
            req_headers: list[tuple[str, str]] = [
                ("Host", _netloc(host, port, scheme)), ("User-Agent", USER_AGENT),
            ]
            if not any(k.lower() == "accept" for k, _ in headers or ()):
                req_headers.append(("Accept", "*/*"))
            for k, v in headers or ():
                if k.lower() not in ("host", "cookie", "authorization",
                                     "content-length"):
                    req_headers.append((k, v))
            sess = dict(self._resolve_session(session) or {})
            if cookie is not None:          # an explicit jar replaces only the cookie
                sess["cookie"] = cookie or None
            if sess and (self.scope.host_allowed(host)
                         or self.scope.check_url(url).allowed):
                if sess.get("cookie"):
                    req_headers.append(("Cookie", sess["cookie"]))
                if sess.get("authorization"):
                    req_headers.append(("Authorization", sess["authorization"]))
            if body is not None and not any(k.lower() == "content-type"
                                            for k, _ in req_headers):
                req_headers.append(("Content-Type", content_type or (
                    "application/x-www-form-urlencoded" if raw_body is None
                    else "application/octet-stream")))
            ex.request_headers = list(req_headers)
            ex.request_body = body
            extensions = {"sni_hostname": host} \
                if scheme == "https" and self.proxy is None else {}
            wire_body = raw_body if raw_body is not None else (
                body.encode() if body is not None else None)
            request = httpx.Request(method, wire, headers=req_headers,
                                    content=wire_body, extensions=extensions)
            started = time.monotonic()
            try:
                async with self._sem:
                    await self._rate.acquire()
                    self.budget.check_cancel()
                    started = time.monotonic()
                    async with asyncio.timeout(self._timeout * 2 + 1):
                        resp = await self._client.send(request, stream=True)
                        try:
                            data, truncated = await _read_bounded(resp)
                        finally:
                            await resp.aclose()
            except (httpx.TimeoutException, asyncio.TimeoutError) as exc:
                ex.error = "proxy_unreachable" \
                    if self.proxy is not None and isinstance(exc, httpx.ConnectTimeout) \
                    else "timeout"
            except httpx.ProxyError as exc:
                # CONNECT answered with a non-2xx status: "407 Proxy Authentication
                # Required", "403 Forbidden", "502 Bad Gateway" ...
                ex.error = "proxy_auth" if str(exc).startswith("407") else "proxy_refused"
            except httpx.TransportError as exc:
                if self.proxy is None:
                    ex.error = "connect_error" if isinstance(exc, httpx.ConnectError) \
                        else "transport_error"
                elif _is_tls_failure(exc):
                    ex.error = "tls_error"
                elif isinstance(exc, httpx.ConnectError):
                    ex.error = "proxy_unreachable"
                else:
                    ex.error = "transport_error"
            else:
                if self.proxy is not None:
                    # absolute-form HTTP: the proxy's own refusals arrive as responses
                    if resp.status_code == 407:
                        ex.error = "proxy_auth"
                    elif resp.status_code >= 400 and resp.headers.get("x-squid-error"):
                        ex.error = "proxy_refused"
            if ex.error:
                ex.duration_ms = int((time.monotonic() - started) * 1000)
                xid = await self.recorder.record(ex)
                raise TransportFailure(ex.error, xid)
            self._client.cookies.clear()   # never keep target cookies between requests
            ex.status_code = resp.status_code
            ex.duration_ms = int((time.monotonic() - started) * 1000)
            ex.response_headers = [(k.decode("latin-1") if isinstance(k, bytes) else str(k),
                                    v.decode("latin-1") if isinstance(v, bytes) else str(v))
                                   for k, v in resp.headers.raw]
            ex.response_body = data
            ex.response_truncated = truncated
            ex.content_type = resp.headers.get("content-type")
            xid = await self.recorder.record(ex)
            if xid is not None:
                ids.append(xid)
            prev = HttpResponse(url=url, status=resp.status_code,
                                headers=ex.response_headers, body=data,
                                truncated=truncated, exchange_id=xid,
                                exchange_ids=list(ids), elapsed_ms=ex.duration_ms or 0,
                                resolved_ip=pinned,
                                hops=[*(prev.hops if prev is not None else (url,)),
                                      str(resp.url)])
            location = prev.header("location")
            if (not follow or self.scope.redirect_policy != "in_scope"
                    or resp.status_code not in REDIRECT_CODES or not location
                    or hop >= MAX_REDIRECT_HOPS):
                return prev
            url = urljoin(url, location.strip())
            if resp.status_code in (301, 302, 303) and method != "HEAD" \
                    and method != "GET":
                method, body, raw_body = "GET", None, None
            hop += 1
            parent = xid

    async def _proxy_denial(self, host: str, port: int) -> str | None:
        """Checks for a request that goes through the egress proxy.

        The proxy's host allow-list (independent of scope), then the IP policy: an IP
        literal is classified as on the direct path; a name is resolved LOCALLY as
        defence in depth and refused if any local answer is in a never-class (or
        private without ``allow_private``). The proxy's own resolution is
        authoritative and may differ; a name the engine cannot resolve is left to the
        proxy (internal names are often visible only to it)."""
        assert self.proxy is not None
        if not self.proxy.host_allowed(host):
            return "proxy_host_not_allowed"
        literal = parse_ip(host)
        if literal is not None:
            return self.policy.address_denial(host, str(literal), port, via_proxy=True)
        try:
            addrs = await asyncio.wait_for(self.resolver.resolve(host, port),
                                           timeout=self._timeout)
        except (OSError, asyncio.TimeoutError, UnicodeError):
            return None
        for addr in addrs:
            denial = self.policy.address_denial(host, addr, port, via_proxy=True)
            if denial:
                return denial
        return None

    def _blocked_result(self, prev: HttpResponse | None, url: str, reason: str | None,
                        xid: int | None, ids: list[int], hop: int) -> HttpResponse:
        if hop == 0 or prev is None:
            raise ScopeViolation(url, reason or "blocked", xid)
        prev.redirect_blocked = reason
        if xid is not None:
            prev.exchange_ids = [*ids, xid]
        return prev


def register_session_secrets(redaction, cookie: str | None,
                             authorization: str | None = None) -> None:
    """Register every cookie VALUE of a Cookie header (and an Authorization value)
    as a redaction secret. Short values are skipped (redacting "1" everywhere would
    destroy evidence and protects nothing)."""
    for part in (cookie or "").split(";"):
        value = part.partition("=")[2].strip()
        if len(value) >= 8:
            redaction.register_secret(value)
    if authorization:
        token = authorization.split(" ", 1)[-1].strip()
        if len(token) >= 8:
            redaction.register_secret(token)


def _cookie_names(header: str) -> list[str]:
    """The cookie NAMES of a Cookie header (``a=1; b=2`` -> ``[a, b]``): enough to
    know which session exists, never the values."""
    return [p.split("=", 1)[0].strip() for p in header.split(";") if "=" in p][:12]


class ToolHttp:
    """What a tool gets: the guarded client bound to its provenance."""

    def __init__(self, client: GuardedHttpClient, prov: dict[str, Any]) -> None:
        self._client = client
        self._prov = prov

    @property
    def scope(self):
        return self._client.scope

    def in_scope(self, url: str) -> bool:
        return self._client.scope.check_url(url).allowed

    def establish_session(self, label: str, cookie: str | None,
                          authorization: str | None = None) -> None:
        """Register a session the auth.login tool just established (visible to
        every later tool of the run; values only ever sent to in-scope hosts)."""
        self._client.establish_session(label, cookie, authorization)

    def sessions(self) -> list[dict[str, Any]]:
        """All identities of this run (labels + cookie names only)."""
        return self._client.sessions()

    def remember_jar(self, identity: str, cookies: list[dict]) -> None:
        self._client.remember_jar(identity, cookies)

    def jar(self, identity: str) -> list[dict] | None:
        return self._client.jar(identity)

    def session_cookie(self, label: str | None) -> str | None:
        """The Cookie header of one identity (``None`` = the provided cookie), for
        the browser capability ONLY: it seeds that identity's cookie jar, and every
        request the jar's cookies ride on still goes through this guard."""
        if label is None:
            return self._client._cookie
        return (self._client._sessions.get(label) or {}).get("cookie")

    async def artifact(self, kind: str, url: str, body: str | None,
                       content_type: str) -> int | None:
        """Record a non-network artifact (a browser screenshot) in the run's audited
        traffic: no request is made, nothing is sent."""
        ex = ExchangeData(method=kind[:10], url=url, scheme="browser",
                          **self._prov)
        ex.response_body = body.encode() if body is not None else None
        ex.content_type = content_type
        return await self._client.recorder.record(ex)

    async def get(self, url: str, *, headers: Sequence[tuple[str, str]] | None = None,
                  follow: bool = True, session: str | None = None) -> HttpResponse:
        return await self._client.request("GET", url, prov=self._prov, headers=headers,
                                          follow=follow, session=session)

    async def post(self, url: str, form: Mapping[str, str], *,
                   headers: Sequence[tuple[str, str]] | None = None,
                   follow: bool = False, session: str | None = None) -> HttpResponse:
        return await self._client.request("POST", url, prov=self._prov, form=form,
                                          headers=headers, follow=follow,
                                          session=session)

    async def request(self, method: str, url: str, *,
                      headers: Sequence[tuple[str, str]] | None = None,
                      body: bytes | str | None = None,
                      content_type: str | None = None,
                      follow: bool = True, session: str | None = None,
                      cookie: str | None = None,
                      state_changing: bool = False) -> HttpResponse:
        """Any method the activity policy allows (state-changing methods only with
        ``scope.activity.state_changing``), any body: the browser's XHRs and the
        brokered calls of agent-written tools. Same per-hop scope and budgets."""
        return await self._client.request(method, url, prov=self._prov,
                                          headers=headers, follow=follow,
                                          session=session, body=body,
                                          content_type=content_type, cookie=cookie,
                                          state_changing=state_changing)

    # HEAD/OPTIONS for dynamic tool specs (batch E): the guarded client already
    # allows exactly these four non-destructive methods; these are the same
    # bound wrappers as get/post, with the same per-hop scope and budgets.
    async def head(self, url: str, *, headers: Sequence[tuple[str, str]] | None = None,
                   follow: bool = True, session: str | None = None) -> HttpResponse:
        return await self._client.request("HEAD", url, prov=self._prov, headers=headers,
                                          follow=follow, session=session)

    async def options(self, url: str, *, headers: Sequence[tuple[str, str]] | None = None,
                      follow: bool = True, session: str | None = None) -> HttpResponse:
        return await self._client.request("OPTIONS", url, prov=self._prov,
                                          headers=headers, follow=follow,
                                          session=session)
