"""Target-neutral scope: authorised addresses, ports and protocols.

:class:`~src.greybox_web.scope.ScopePolicy` answers "may this *URL* be requested?".
That is the right question for a web application and the wrong one for a network
segment, a mail server or a database port: those have an address, a port and a
protocol, never a path. This module is the second predicate, used by every
non-HTTP capability (raw TCP connect, banner read, DNS) and by HTTP itself when
the operator authorised a network segment rather than one application.

Rules, all enforced here — outside the model — and re-checked at the socket by
:class:`~src.greybox_web.netguard.GuardedNet`:

* **Explicit boundaries only.** ``targets`` are IP addresses, CIDR blocks or exact
  host names. A CIDR never implies its neighbours; a name never implies its
  sub-domains. The expanded address count is capped (:data:`MAX_ADDRESSES`), so a
  typo cannot authorise a /8.
* **Explicit ports.** ``ports`` are numbers or ``a-b`` ranges, capped at
  :data:`MAX_PORTS` after expansion. There is no "all ports".
* **Explicit protocols.** ``tcp`` (connect + passive banner read), ``dns``
  (resolution of in-scope names) and ``http`` (HTTP to any in-scope address:port).
  An unlisted protocol is refused even for an in-scope address.
* **Conservative rates.** ``rate_per_s`` and ``connect_timeout_s`` are clamped to
  non-disruptive ranges.

Pure module: no I/O, no settings, no DNS — resolution happens in the guard, which
then re-checks each resolved address against the address set and the platform IP
policy (``netguard.ip_denial``).
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

PROTOCOLS = ("tcp", "dns", "http")
DEFAULT_PROTOCOLS = ("tcp",)
MAX_TARGET_ENTRIES = 32
MAX_ADDRESSES = 256          # after CIDR expansion
MAX_PORT_ENTRIES = 64
MAX_PORTS = 256              # after range expansion
RATE_RANGE = (0.2, 20.0)     # connection attempts per second
DEFAULT_RATE = 5.0
TIMEOUT_RANGE = (0.5, 10.0)
DEFAULT_TIMEOUT = 3.0
BANNER_MAX = 1024

REASONS = ("address_not_in_scope", "port_not_in_scope", "protocol_not_allowed",
           "name_not_in_scope", "no_network_scope", "invalid_target")


@dataclass(frozen=True)
class NetDecision:
    allowed: bool
    reason: str | None = None


def _norm_name(raw: str) -> str | None:
    from src.greybox_web.scope import canonical_host
    return canonical_host(raw)


@dataclass(frozen=True)
class NetworkScope:
    """The authorised network boundary of one assessment."""

    targets: tuple[str, ...] = ()          # canonical IP / CIDR / host name strings
    ports: tuple[int, ...] = ()
    protocols: tuple[str, ...] = DEFAULT_PROTOCOLS
    rate_per_s: float = DEFAULT_RATE
    connect_timeout_s: float = DEFAULT_TIMEOUT

    # -- derived ------------------------------------------------------------------
    @property
    def networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        out = []
        for t in self.targets:
            try:
                out.append(ipaddress.ip_network(t, strict=False))
            except ValueError:
                continue
        return tuple(out)

    @property
    def names(self) -> tuple[str, ...]:
        out = []
        for t in self.targets:
            try:
                ipaddress.ip_network(t, strict=False)
            except ValueError:
                out.append(t)
        return tuple(out)

    def addresses(self) -> list[str]:
        """Every in-scope literal address (CIDRs expanded, capped)."""
        out: list[str] = []
        for net in self.networks:
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            for ip in hosts:
                out.append(str(ip))
                if len(out) >= MAX_ADDRESSES:
                    return out
        return out

    # -- predicates ---------------------------------------------------------------
    def address_in_scope(self, addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in net for net in self.networks)

    def host_in_scope(self, host: str) -> bool:
        """An IP literal inside a listed network, or an exactly listed name."""
        if self.address_in_scope(host.strip("[]")):
            return True
        name = _norm_name(host)
        return name is not None and name in self.names

    def check(self, host: str, port: int | None, protocol: str) -> NetDecision:
        """The single predicate for a non-URL action (``protocol`` in PROTOCOLS)."""
        if not self.targets:
            return NetDecision(False, "no_network_scope")
        if protocol not in self.protocols:
            return NetDecision(False, "protocol_not_allowed")
        if not host:
            return NetDecision(False, "invalid_target")
        if not self.host_in_scope(host):
            try:
                ipaddress.ip_address(host.strip("[]"))
                return NetDecision(False, "address_not_in_scope")
            except ValueError:
                return NetDecision(False, "name_not_in_scope")
        if port is not None and port not in self.ports:
            return NetDecision(False, "port_not_in_scope")
        return NetDecision(True, None)

    def resolved_ok(self, name: str, addr: str) -> bool:
        """A name was resolved: is the answer still inside the boundary? An address
        that is itself listed always is; for a listed *name*, the answer may be any
        address the platform IP policy allows (checked by the guard), because the
        operator authorised the name. Literal-IP scopes never follow DNS."""
        return self.address_in_scope(addr) or (_norm_name(name) in self.names)

    # -- serialisation ------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {"targets": list(self.targets), "ports": list(self.ports),
                "protocols": list(self.protocols), "rate_per_s": self.rate_per_s,
                "connect_timeout_s": self.connect_timeout_s}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any] | None) -> "NetworkScope | None":
        if not d:
            return None
        return cls(targets=tuple(str(t) for t in d.get("targets") or ()),
                   ports=tuple(int(p) for p in d.get("ports") or ()),
                   protocols=tuple(str(p) for p in d.get("protocols")
                                   or DEFAULT_PROTOCOLS),
                   rate_per_s=float(d.get("rate_per_s") or DEFAULT_RATE),
                   connect_timeout_s=float(d.get("connect_timeout_s")
                                           or DEFAULT_TIMEOUT))

    def summary(self) -> str:
        t = ", ".join(self.targets[:6]) + (" …" if len(self.targets) > 6 else "")
        p = _compress_ports(self.ports)
        return (f"network: {t} · ports {p} · protocols {'/'.join(self.protocols)} · "
                f"≤{self.rate_per_s:g} conn/s")


def _compress_ports(ports: Iterable[int]) -> str:
    ps = sorted(set(ports))
    out: list[str] = []
    i = 0
    while i < len(ps):
        j = i
        while j + 1 < len(ps) and ps[j + 1] == ps[j] + 1:
            j += 1
        out.append(str(ps[i]) if i == j else f"{ps[i]}-{ps[j]}")
        i = j + 1
    return ",".join(out[:12]) + (" …" if len(out) > 12 else "")


def parse(raw: Any, *, host_error=None) -> tuple[NetworkScope | None, list[tuple[tuple, str]]]:
    """Validate an operator-supplied ``scope.network`` object.

    ``host_error(host) -> str | None`` is the platform's own host policy (private
    addresses, platform services), applied to every listed literal and name.
    Returns ``(scope, errors)``; errors are ``(location, message)`` pairs.
    """
    errs: list[tuple[tuple, str]] = []
    if raw is None:
        return None, []
    if not isinstance(raw, Mapping):
        return None, [(("scope", "network"), "Must be an object")]
    unknown = set(raw) - {"targets", "ports", "protocols", "rate_per_s",
                          "connect_timeout_s"}
    if unknown:
        errs.append((("scope", "network"), f"Unknown keys: {', '.join(sorted(unknown))}"))
    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, list) or not targets_raw:
        errs.append((("scope", "network", "targets"),
                     "Must list at least one address, CIDR block or host name"))
        targets_raw = []
    if len(targets_raw) > MAX_TARGET_ENTRIES:
        errs.append((("scope", "network", "targets"),
                     f"At most {MAX_TARGET_ENTRIES} entries"))
        targets_raw = targets_raw[:MAX_TARGET_ENTRIES]
    targets: list[str] = []
    total = 0
    for i, t in enumerate(targets_raw):
        loc = ("scope", "network", "targets", i)
        if not isinstance(t, str) or not t.strip():
            errs.append((loc, "Must be an address, CIDR block or host name"))
            continue
        t = t.strip()
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            net = None
        if net is not None:
            total += net.num_addresses
            if total > MAX_ADDRESSES:
                errs.append((loc, f"The scope may cover at most {MAX_ADDRESSES} "
                                  "addresses (use a smaller block)"))
                continue
            first = str(net.network_address)
            msg = host_error(first) if host_error else None
            if msg:
                errs.append((loc, msg))
                continue
            canon = str(net) if net.num_addresses > 1 else str(net.network_address)
        else:
            if "*" in t or "/" in t:
                errs.append((loc, "Wildcards are not allowed in a network scope; list "
                                  "names exactly"))
                continue
            canon = _norm_name(t)
            if canon is None:
                errs.append((loc, "Not a valid address, CIDR block or host name"))
                continue
            msg = host_error(canon) if host_error else None
            if msg:
                errs.append((loc, msg))
                continue
        if canon not in targets:
            targets.append(canon)

    ports_raw = raw.get("ports")
    ports: list[int] = []
    if not isinstance(ports_raw, list) or not ports_raw:
        errs.append((("scope", "network", "ports"),
                     "Must list the authorised ports (numbers or 'a-b' ranges)"))
        ports_raw = []
    if len(ports_raw) > MAX_PORT_ENTRIES:
        errs.append((("scope", "network", "ports"), f"At most {MAX_PORT_ENTRIES} entries"))
        ports_raw = ports_raw[:MAX_PORT_ENTRIES]
    for i, p in enumerate(ports_raw):
        loc = ("scope", "network", "ports", i)
        lo = hi = None
        if isinstance(p, int) and not isinstance(p, bool):
            lo = hi = p
        elif isinstance(p, str) and "-" in p:
            a, _, b = p.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                lo, hi = int(a), int(b)
        elif isinstance(p, str) and p.strip().isdigit():
            lo = hi = int(p)
        if lo is None or hi is None or not 1 <= lo <= hi <= 65535:
            errs.append((loc, "Must be a port 1-65535 or a range 'a-b'"))
            continue
        for port in range(lo, hi + 1):
            if port not in ports:
                ports.append(port)
        if len(ports) > MAX_PORTS:
            errs.append((loc, f"At most {MAX_PORTS} ports after expanding ranges"))
            ports = ports[:MAX_PORTS]
            break

    protos_raw = raw.get("protocols", list(DEFAULT_PROTOCOLS))
    protocols: list[str] = []
    if not isinstance(protos_raw, list):
        errs.append((("scope", "network", "protocols"), "Must be a list"))
        protos_raw = []
    for i, pr in enumerate(protos_raw):
        if pr not in PROTOCOLS:
            errs.append((("scope", "network", "protocols", i),
                         f"Must be one of: {', '.join(PROTOCOLS)}"))
        elif pr not in protocols:
            protocols.append(pr)

    def _num(key: str, default: float, rng: tuple[float, float]) -> float:
        v = raw.get(key, default)
        if isinstance(v, bool) or not isinstance(v, (int, float)) \
                or not rng[0] <= float(v) <= rng[1]:
            errs.append((("scope", "network", key),
                         f"Must be a number between {rng[0]:g} and {rng[1]:g}"))
            return default
        return float(v)

    rate = _num("rate_per_s", DEFAULT_RATE, RATE_RANGE)
    timeout = _num("connect_timeout_s", DEFAULT_TIMEOUT, TIMEOUT_RANGE)
    if errs:
        return None, errs
    return NetworkScope(targets=tuple(targets), ports=tuple(sorted(ports)),
                        protocols=tuple(protocols or DEFAULT_PROTOCOLS),
                        rate_per_s=rate, connect_timeout_s=timeout), []
