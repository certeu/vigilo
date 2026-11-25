"""Guarded non-HTTP network capabilities: TCP connect / banner read and DNS.

The HTTP guard (:class:`~src.greybox_web.netguard.GuardedHttpClient`) protects URLs.
It says nothing about a raw socket, so "the HTTP client is guarded" must never be
read as "the network is guarded". This module is the equivalent boundary for the
other protocols the engine speaks, and the ONLY code that opens a raw socket:

* **Scope.** Every attempt is checked against
  :meth:`ScopePolicy.check_endpoint` (address/CIDR/name, port, protocol). A name is
  resolved here, and every answer is re-checked: against the network scope and the
  platform IP policy (never-classes such as metadata and link-local are always
  refused; private ranges only when the platform allows them).
* **Activity.** Connect + passive banner read is the default. Sending bytes is
  limited to :data:`SAFE_PROBES` (inert identification hellos) unless the operator
  authorised state-changing activity for the target.
* **Pacing.** A per-run rate limiter at ``network.rate_per_s`` and a connect timeout
  of ``network.connect_timeout_s``; each attempt consumes the run's request budget.
* **Audit.** Every attempt — allowed, refused or failed — becomes a row in the run's
  traffic (``scheme`` ``tcp``/``dns``) exactly like an HTTP exchange.
* **No proxy bypass.** When the run's traffic must go through an egress proxy, raw
  TCP is refused: it cannot be carried by the proxy, and going around it would
  defeat the administrator's egress control.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from src.greybox_web.netguard import (
    ExchangeData,
    GuardedHttpClient,
    ScopeViolation,
    _RateLimiter,
    parse_ip,
)

BANNER_MAX = 1024
SEND_MAX = 512
# Identification hellos that change no state on any common service.
SAFE_PROBES: dict[str, bytes] = {
    "crlf": b"\r\n",
    "http_head": b"HEAD / HTTP/1.0\r\n\r\n",
    "redis_ping": b"PING\r\n",
    "smtp_quit": b"QUIT\r\n",
    # Identification hellos that read service metadata and change nothing:
    # memcached's version string, SMTP's capability list (EHLO then QUIT), FTP's
    # feature list (FEAT then QUIT). None authenticates, reads data or writes.
    "memcached_version": b"version\r\n",
    "smtp_ehlo": b"EHLO vigilo.invalid\r\nQUIT\r\n",
    "ftp_feat": b"FEAT\r\nQUIT\r\n",
}


@dataclass
class TcpResult:
    host: str
    port: int
    state: str                       # open | closed | filtered | blocked | error
    banner: bytes = b""
    resolved_ip: str | None = None
    exchange_id: int | None = None
    duration_ms: int = 0
    reason: str | None = None        # block / error reason
    sent: str | None = None          # probe name or "custom"

    def as_dict(self) -> dict[str, Any]:
        return {"host": self.host, "port": self.port, "state": self.state,
                "banner": self.banner.decode("latin-1")[:BANNER_MAX],
                "resolved_ip": self.resolved_ip, "exchange_id": self.exchange_id,
                "duration_ms": self.duration_ms, "reason": self.reason,
                "sent": self.sent}


@dataclass
class DnsResult:
    name: str
    addresses: list[str] = field(default_factory=list)
    exchange_id: int | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "addresses": self.addresses,
                "exchange_id": self.exchange_id, "reason": self.reason}


class GuardedNet:
    """Raw-protocol counterpart of the guarded HTTP client; shares its budget,
    recorder, resolver, IP policy and cancellation."""

    def __init__(self, client: GuardedHttpClient) -> None:
        self.client = client
        net = getattr(client.scope, "network", None)
        self._rate = _RateLimiter(net.rate_per_s if net else 1.0)
        self._timeout = float(net.connect_timeout_s) if net else 3.0
        self._sem = asyncio.Semaphore(4)

    @property
    def scope(self):
        return self.client.scope

    async def _record(self, ex: ExchangeData) -> int | None:
        return await self.client.recorder.record(ex)

    async def _refuse(self, ex: ExchangeData, reason: str) -> int | None:
        ex.blocked = True
        ex.block_reason = reason
        return await self._record(ex)

    # ------------------------------------------------------------------- DNS
    async def resolve(self, name: str, *, prov: Mapping[str, Any]) -> DnsResult:
        """Resolve a name the scope authorises for ``dns`` (a listed network name)
        or that is one of the web scope's own hosts. Answers are reported, never
        contacted by this call."""
        self.client.budget.consume()
        ex = ExchangeData(method="RESOLVE", url=f"dns://{name}", scheme="dns",
                          host=name, **prov)
        allowed = self.scope.check_endpoint(name, None, "dns").allowed \
            or self.scope.host_allowed(name)
        if not allowed or parse_ip(name) is not None:
            xid = await self._refuse(ex, "name_not_in_scope")
            return DnsResult(name, exchange_id=xid, reason="name_not_in_scope")
        started = time.monotonic()
        try:
            async with self._sem:
                await self._rate.acquire()
                addrs = await self.client._resolve(name, 0)
        except (OSError, asyncio.TimeoutError, UnicodeError):
            ex.error = "dns_error"
            ex.duration_ms = int((time.monotonic() - started) * 1000)
            xid = await self._record(ex)
            return DnsResult(name, exchange_id=xid, reason="dns_error")
        ex.duration_ms = int((time.monotonic() - started) * 1000)
        ex.response_body = "\n".join(addrs).encode()
        ex.content_type = "text/plain"
        xid = await self._record(ex)
        return DnsResult(name, addresses=list(dict.fromkeys(addrs)), exchange_id=xid)

    # ------------------------------------------------------------------- TCP
    def _payload(self, send: str | bytes | None) -> tuple[bytes | None, str | None,
                                                          str | None]:
        """(bytes, label, refusal reason)."""
        if send is None or send == "":
            return None, None, None
        if isinstance(send, str) and send in SAFE_PROBES:
            return SAFE_PROBES[send], send, None
        if not getattr(self.scope, "state_changing", False):
            return None, None, "custom_payload_not_allowed"
        raw = send.encode() if isinstance(send, str) else bytes(send)
        if len(raw) > SEND_MAX:
            return None, None, "payload_too_large"
        return raw, "custom", None

    async def tls(self, host: str, port: int, *, prov: Mapping[str, Any],
                       server_name: str | None = None) -> TlsResult:
        """Handshake with ``host:port`` and describe the certificate. Same admission
        as :meth:`GuardedNet.tcp` (scope, proxy, address policy, budget, pacing);
        nothing is sent after the handshake. A second handshake validates the chain
        against the system trust store so "trusted" is measured, not assumed."""
        import ssl
        self.client.budget.consume()
        port = int(port)
        ex = ExchangeData(method="TLS", url=f"tls://{host}:{port}", scheme="tcp",
                          host=host, port=port, **prov)
        res = TlsResult(host=host, port=port, state="blocked")
        addr, _ = await self._admit(host, port, ex, res)
        if addr is None:
            return res
        sni = server_name or (None if parse_ip(host) is not None else host)
        started = time.monotonic()

        async def handshake(verify: bool):
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            async with self._sem:
                await self._rate.acquire()
                self.client.budget.check_cancel()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(addr, port, ssl=ctx, server_hostname=sni
                                            or (host if verify else None)),
                    timeout=self._timeout)
            try:
                obj = writer.get_extra_info("ssl_object")
                return obj.version(), (obj.cipher() or (None,))[0], \
                    obj.getpeercert(binary_form=True)
            finally:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except (asyncio.TimeoutError, OSError, ssl.SSLError):
                    pass
        try:
            res.protocol, res.cipher, der = await handshake(False)
            res.state = "ok"
            if der:
                res.certificate = describe_certificate(der)
        except ConnectionRefusedError:
            res.state = "closed"
        except (asyncio.TimeoutError, TimeoutError):
            res.state = "filtered"
        except ssl.SSLError as exc:
            res.state, res.reason = "not_tls", str(exc)[:160]
        except OSError as exc:
            res.state, res.reason = "error", type(exc).__name__
        if res.state == "ok":
            self.client.budget.consume()
            try:
                await handshake(True)
                res.trusted = True
            except ssl.SSLCertVerificationError as exc:
                res.trusted, res.trust_error = False, (exc.verify_message or str(exc))[:160]
            except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
                res.trusted, res.trust_error = False, str(exc)[:160]
        res.duration_ms = ex.duration_ms = int((time.monotonic() - started) * 1000)
        ex.error = None if res.state == "ok" else res.state
        import json as _json
        ex.response_body = _json.dumps(res.as_dict(), default=str).encode()
        ex.content_type = "application/json; x-vigilo=tls"
        res.exchange_id = await self._record(ex)
        return res

    async def _admit(self, host: str, port: int, ex: ExchangeData, res,
                     preason: str | None = None) -> tuple[str | None, str | None]:
        """Scope, proxy, host and address policy for one TCP endpoint — the single
        admission path of raw connections (plain TCP and TLS alike). On refusal the
        attempt is recorded and ``res`` carries the reason; returns (address, None)
        when the connection may be made."""
        decision = self.scope.check_endpoint(host, port, "tcp")
        reason = None if decision.allowed else decision.reason
        if reason is None and self.client.proxy is not None:
            reason = "egress_proxy_no_raw_tcp"
        reason = reason or preason
        if reason is None and self.client.policy.host_blocked(host):
            reason = "blocked_host"
        addrs: list[str] = []
        if reason is None:
            try:
                addrs = await self.client._resolve(host, port)
            except (OSError, asyncio.TimeoutError, UnicodeError):
                ex.error = "dns_error"
                res.state, res.reason = "error", "dns_error"
                res.exchange_id = await self._record(ex)
                return None, "dns_error"
            if not addrs:
                reason = "dns_no_address"
            for a in addrs:
                if reason:
                    break
                if not self.scope.network.resolved_ok(host, a):
                    reason = "resolved_address_not_in_scope"
                else:
                    reason = self.client.policy.address_denial(host, a, port)
        if reason:
            res.reason = reason
            res.exchange_id = await self._refuse(ex, reason)
            return None, reason
        addr = str(parse_ip(addrs[0]))
        ex.resolved_ip = res.resolved_ip = addr
        return addr, None

    async def tcp(self, host: str, port: int, *, prov: Mapping[str, Any],
                  send: str | bytes | None = None,
                  read_banner: bool = True) -> TcpResult:
        """Connect to ``host:port`` (scope-checked), optionally send an inert probe,
        read up to :data:`BANNER_MAX` bytes, close. Never raises for a refusal: the
        result's ``state`` is ``blocked`` with the reason (and the attempt is
        recorded); a cancelled run or an exhausted budget raises as usual."""
        self.client.budget.consume()
        port = int(port)
        ex = ExchangeData(method="CONNECT", url=f"tcp://{host}:{port}", scheme="tcp",
                          host=host, port=port, **prov)
        res = TcpResult(host=host, port=port, state="blocked")
        payload, label, preason = self._payload(send)
        addr, reason = await self._admit(host, port, ex, res, preason)
        if addr is None:
            return res
        if payload is not None:
            ex.request_body = payload.decode("latin-1")
            res.sent = label
        started = time.monotonic()
        writer = None
        try:
            async with self._sem:
                await self._rate.acquire()
                self.client.budget.check_cancel()
                started = time.monotonic()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(addr, port), timeout=self._timeout)
                res.state = "open"
                if payload is not None:
                    writer.write(payload)
                    await writer.drain()
                if read_banner:
                    res.banner = await _read_until_quiet(
                        reader, total_s=min(self._timeout, 2.0))
        except ConnectionRefusedError:
            res.state = "closed"
        except (asyncio.TimeoutError, TimeoutError):
            res.state = "filtered"
        except OSError as exc:
            res.state, res.reason = "error", type(exc).__name__
            ex.error = "connect_error"
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except (asyncio.TimeoutError, OSError):
                    pass
        res.duration_ms = ex.duration_ms = int((time.monotonic() - started) * 1000)
        ex.error = ex.error or (None if res.state == "open" else res.state)
        ex.response_body = res.banner or None
        ex.content_type = "text/plain; x-vigilo=banner" if res.banner else None
        res.exchange_id = await self._record(ex)
        return res


@dataclass
class TlsResult:
    """One TLS handshake: what the service presented. No application data sent."""

    host: str
    port: int
    state: str                       # ok | blocked | closed | filtered | error | not_tls
    reason: str | None = None
    resolved_ip: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    certificate: dict[str, Any] | None = None
    trusted: bool | None = None      # chain + name valid against the system CAs
    trust_error: str | None = None
    exchange_id: int | None = None
    duration_ms: int | None = None

    def as_dict(self) -> dict[str, Any]:
        from dataclasses import asdict
        return {k: v for k, v in asdict(self).items() if v is not None}


def describe_certificate(der: bytes) -> dict[str, Any]:
    """Subject, issuer, validity, names and key of a DER certificate (pure)."""
    from datetime import datetime, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    key = cert.public_key()
    key_desc = (f"RSA {key.key_size}" if isinstance(key, rsa.RSAPublicKey) else
                f"EC {key.curve.name}" if isinstance(key, ec.EllipticCurvePublicKey)
                else type(key).__name__)
    return {"subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "self_signed": cert.issuer == cert.subject,
            "not_before": nb.isoformat(), "not_after": na.isoformat(),
            "expired": na < now, "not_yet_valid": nb > now,
            "days_left": (na - now).days, "dns_names": list(san)[:20],
            "key": key_desc, "signature_hash": getattr(
                cert.signature_hash_algorithm, "name", None),
            "serial": format(cert.serial_number, "x")[:40]}


async def _read_until_quiet(reader, *, total_s: float, idle_s: float = 0.4) -> bytes:
    """Read what the service sends until it goes quiet (``idle_s`` without data),
    closes, or ``total_s``/BANNER_MAX is reached. A greeting followed by the answer
    to a hello (SMTP 220 then 250-…) arrives in several segments: one read would
    keep only the first. A silent service yields b''."""
    buf = b""
    deadline = time.monotonic() + total_s
    first = True
    while len(buf) < BANNER_MAX:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(BANNER_MAX - len(buf)),
                                           timeout=left if first else min(idle_s, left))
        except (asyncio.TimeoutError, TimeoutError):
            break
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        first = False
    return buf




class ToolNet:
    """The provenance-bound view tools receive as ``ctx.net``."""

    def __init__(self, net: GuardedNet, prov: dict[str, Any]) -> None:
        self._net = net
        self._prov = prov

    @property
    def scope(self):
        return self._net.scope

    async def tcp(self, host: str, port: int, *, send: str | bytes | None = None,
                  read_banner: bool = True) -> TcpResult:
        return await self._net.tcp(host, port, prov=self._prov, send=send,
                                   read_banner=read_banner)

    async def resolve(self, name: str) -> DnsResult:
        return await self._net.resolve(name, prov=self._prov)

    async def tls(self, host: str, port: int, *,
                  server_name: str | None = None) -> TlsResult:
        return await self._net.tls(host, port, prov=self._prov, server_name=server_name)


__all__ = ["GuardedNet", "ToolNet", "TcpResult", "TlsResult", "DnsResult",
           "SAFE_PROBES", "describe_certificate",
           "ScopeViolation"]
