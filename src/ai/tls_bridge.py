"""Loopback TLS bridge for the Codex CLI (opt-in: ``CODEX_TLS_BRIDGE=true``).

Some model endpoints drop TLS 1.3 handshakes that offer the post-quantum / X25519 key
shares the Codex CLI's Rust TLS stack sends, instead of asking for another group (seen
with an Azure AI Foundry endpoint; curl, Node and Python's OpenSSL negotiate fine).
The CLI has no setting for its key exchange, so the worker can run this bridge:

* it listens on 127.0.0.1 ONLY and speaks plain HTTP/1.1 to the CLI, so the
  unencrypted leg never leaves the container;
* it forwards every request to ONE configured upstream (``--upstream``), never to a
  host named by the client: absolute-URI requests are refused, so it is not an open
  proxy;
* it talks to the upstream with OpenSSL, certificate verification on, and if the
  handshake itself is rejected it retries once with the key exchange pinned to P-256
  (mandatory-to-implement in TLS 1.3), then keeps that setting;
* responses are streamed back chunk by chunk (Server-Sent Events from ``/responses``).

Run: ``python3 -m src.ai.tls_bridge --upstream https://host[/path] --listen 127.0.0.1:18443``.
The entrypoint starts it and points ``CODEX_BASE_URL`` at it.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import ssl
from urllib.parse import urlsplit

import httpx

log = logging.getLogger("vigilo.tls_bridge")

FALLBACK_ECDH_CURVE = "prime256v1"
MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 32 * 1024 * 1024
# Hop-by-hop headers (RFC 9110 §7.6.1) plus the ones this bridge recomputes.
_HOP = frozenset({"connection", "keep-alive", "proxy-connection", "proxy-authorization",
                  "transfer-encoding", "te", "trailer", "upgrade", "host",
                  "content-length"})


def ssl_context(ca_file: str | None = None, curve: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)
    if curve:
        ctx.set_ecdh_curve(curve)
    return ctx


def _handshake_rejected(exc: BaseException) -> bool:
    """The TLS handshake was cut off or refused (not a certificate problem)."""
    cur: BaseException | None = exc
    for _ in range(6):
        if cur is None:
            return False
        if isinstance(cur, ssl.SSLCertVerificationError):
            return False
        if isinstance(cur, ssl.SSLEOFError) or (isinstance(cur, ssl.SSLError) and any(
                a in str(cur) for a in ("ALERT_PROTOCOL_VERSION", "ALERT_HANDSHAKE_FAILURE"))):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


class BadRequest(Exception):
    pass


class Bridge:
    def __init__(self, upstream: str, *, ca_file: str | None = None,
                 timeout_s: float = 900.0) -> None:
        parts = urlsplit(upstream)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("--upstream must be an https:// URL")
        # only the origin is used; the client's request path is appended to it
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self.ca_file = ca_file
        self.timeout = httpx.Timeout(timeout_s, connect=20.0)
        self.fallback = False
        self._client = self._make_client()

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=ssl_context(self.ca_file, FALLBACK_ECDH_CURVE if self.fallback else None),
            timeout=self.timeout, trust_env=True, follow_redirects=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _send(self, method: str, path: str, headers: list[tuple[str, str]],
                    body: bytes) -> httpx.Response:
        try:
            req = self._client.build_request(method, self.origin + path, headers=headers,
                                             content=body)
            return await self._client.send(req, stream=True)
        except httpx.ConnectError as exc:
            if self.fallback or not _handshake_rejected(exc):
                raise
            log.warning("TLS handshake with %s rejected; retrying with the key exchange "
                        "pinned to %s", self.origin, FALLBACK_ECDH_CURVE)
            self.fallback = True
            old, self._client = self._client, self._make_client()
            await old.aclose()
            req = self._client.build_request(method, self.origin + path, headers=headers,
                                             content=body)
            return await self._client.send(req, stream=True)

    # ---------------------------------------------------------------- HTTP/1.1 server
    async def _read_request(self, reader: asyncio.StreamReader
                            ) -> tuple[str, str, list[tuple[str, str]], bytes, bool] | None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError:
            return None                                    # client closed
        except asyncio.LimitOverrunError as exc:
            raise BadRequest("request header too large") from exc
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError as exc:
            raise BadRequest("malformed request line") from exc
        if not target.startswith("/"):
            raise BadRequest("only origin-form targets are accepted (not a proxy)")
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line:
                continue
            name, sep, value = line.partition(":")
            if not sep:
                raise BadRequest("malformed header")
            headers.append((name.strip(), value.strip()))
        lower = {k.lower(): v for k, v in headers}
        body = b""
        if "chunked" in lower.get("transfer-encoding", "").lower():
            parts = []
            total = 0
            while True:
                size_line = await reader.readuntil(b"\r\n")
                size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    await reader.readuntil(b"\r\n")          # end of trailers
                    break
                total += size
                if total > MAX_BODY_BYTES:
                    raise BadRequest("request body too large")
                parts.append(await reader.readexactly(size))
                await reader.readexactly(2)
            body = b"".join(parts)
        elif lower.get("content-length"):
            length = int(lower["content-length"])
            if length > MAX_BODY_BYTES:
                raise BadRequest("request body too large")
            body = await reader.readexactly(length)
        keep_alive = version.upper() == "HTTP/1.1" and \
            lower.get("connection", "").lower() != "close"
        fwd = [(k, v) for k, v in headers if k.lower() not in _HOP]
        return method, target, fwd, body, keep_alive

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                try:
                    req = await self._read_request(reader)
                except BadRequest as exc:
                    msg = str(exc).encode()
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
                                 b"Connection: close\r\nContent-Length: "
                                 + str(len(msg)).encode() + b"\r\n\r\n" + msg)
                    await writer.drain()
                    return
                if req is None:
                    return
                method, target, headers, body, keep_alive = req
                try:
                    resp = await self._send(method, target, headers, body)
                except httpx.HTTPError as exc:
                    log.warning("upstream error for %s %s: %s", method, target,
                                type(exc).__name__)
                    msg = f"bridge: upstream unreachable ({type(exc).__name__})".encode()
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n"
                                 b"Connection: close\r\nContent-Length: "
                                 + str(len(msg)).encode() + b"\r\n\r\n" + msg)
                    await writer.drain()
                    return
                try:
                    writer.write(f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\r\n"
                                 .encode("latin-1"))
                    for k, v in resp.headers.multi_items():
                        # httpx decodes content-encoding: the body sent on is decoded
                        if k.lower() not in _HOP | {"content-encoding"}:
                            writer.write(f"{k}: {v}\r\n".encode("latin-1"))
                    writer.write(b"Transfer-Encoding: chunked\r\n")
                    writer.write(b"Connection: keep-alive\r\n\r\n" if keep_alive
                                 else b"Connection: close\r\n\r\n")
                    async for chunk in resp.aiter_bytes():
                        if chunk:
                            writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                            await writer.drain()
                    writer.write(b"0\r\n\r\n")
                    await writer.drain()
                finally:
                    await resp.aclose()
                if not keep_alive:
                    return
        except (ConnectionError, asyncio.IncompleteReadError):
            return                                          # client went away
        except Exception:                                   # noqa: BLE001 — keep serving others
            log.exception("bridge connection failed")
        finally:
            writer.close()


def _loopback_only(host: str) -> str:
    try:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError
    except ValueError as exc:
        raise SystemExit(f"--listen must be a loopback address, not {host!r}") from exc
    return host


async def serve(upstream: str, host: str, port: int, *, ca_file: str | None = None,
                ready: asyncio.Event | None = None) -> None:
    bridge = Bridge(upstream, ca_file=ca_file)
    server = await asyncio.start_server(bridge.handle, _loopback_only(host), port,
                                        limit=MAX_HEADER_BYTES)
    log.info("TLS bridge listening on %s:%s -> %s", host, port, bridge.origin)
    if ready is not None:
        ready.set()
    try:
        async with server:
            await server.serve_forever()
    finally:
        await bridge.aclose()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--upstream", required=True, help="https://host[:port][/path]")
    ap.add_argument("--listen", default="127.0.0.1:18443", help="loopback host:port")
    ap.add_argument("--ca-file", default=None, help="extra CA bundle for the upstream")
    args = ap.parse_args(argv)
    host, _, port = args.listen.rpartition(":")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    asyncio.run(serve(args.upstream, host or "127.0.0.1", int(port), ca_file=args.ca_file))


if __name__ == "__main__":
    main()
