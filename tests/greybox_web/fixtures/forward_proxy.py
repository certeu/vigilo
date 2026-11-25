"""A minimal asyncio forward proxy for the egress-proxy tests.

Handles ``CONNECT host:port`` (blind TCP tunnel) and absolute-form HTTP requests
(``GET http://host:port/path``), counts what it saw, and optionally demands HTTP
Basic ``Proxy-Authorization``. Bound to 127.0.0.1 on an ephemeral port; it forwards
only to whatever the test asks for (the synthetic local target).
"""
from __future__ import annotations

import asyncio
import base64
from urllib.parse import urlsplit


class ForwardProxy:
    def __init__(self, *, auth: tuple[str, str] | None = None,
                 deny_hosts: tuple[str, ...] = ()) -> None:
        self.auth = auth
        self.deny_hosts = deny_hosts
        self.requests: list[tuple[str, str]] = []     # (method, absolute URL) of HTTP forwards
        self.connects: list[str] = []                 # "host:port" of CONNECT requests
        self.auth_failures = 0
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def seen(self) -> int:
        return len(self.requests) + len(self.connects)

    async def start(self) -> ForwardProxy:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    # ------------------------------------------------------------------ internals
    def _authorised(self, headers: dict[str, str]) -> bool:
        if self.auth is None:
            return True
        want = base64.b64encode(f"{self.auth[0]}:{self.auth[1]}".encode()).decode()
        return headers.get("proxy-authorization") == f"Basic {want}"

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: str, extra: str = "") -> None:
        writer.write(f"HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\n"
                     f"Connection: close\r\n\r\n".encode())
        await writer.drain()

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _version = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if not self._authorised(headers):
                self.auth_failures += 1
                await self._reply(writer, "407 Proxy Authentication Required",
                                  'Proxy-Authenticate: Basic realm="test"\r\n')
                return
            if method == "CONNECT":
                host, _, port = target.rpartition(":")
                self.connects.append(target)
                if host in self.deny_hosts:
                    await self._reply(writer, "403 Forbidden")
                    return
                await self._tunnel(reader, writer, host, int(port))
            else:
                parts = urlsplit(target)
                if parts.hostname is None:
                    await self._reply(writer, "400 Bad Request")
                    return
                self.requests.append((method, target))
                if parts.hostname in self.deny_hosts:
                    await self._reply(writer, "403 Forbidden", "X-Squid-Error: ERR_ACCESS_DENIED\r\n")
                    return
                await self._forward(reader, writer, method, parts, headers, lines)
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            writer.close()

    async def _tunnel(self, reader, writer, host: str, port: int) -> None:
        try:
            up_r, up_w = await asyncio.open_connection(host, port)
        except OSError:
            await self._reply(writer, "502 Bad Gateway")
            return
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(self._pipe(reader, up_w), self._pipe(up_r, writer),
                             return_exceptions=True)

    async def _forward(self, reader, writer, method, parts, headers, lines) -> None:
        port = parts.port or 80
        try:
            up_r, up_w = await asyncio.open_connection(parts.hostname, port)
        except OSError:
            await self._reply(writer, "502 Bad Gateway", "X-Squid-Error: ERR_CONNECT_FAIL\r\n")
            return
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        out = [f"{method} {path} HTTP/1.1"]
        for line in lines[1:]:
            low = line.lower()
            if not line or low.startswith(("proxy-authorization:", "proxy-connection:",
                                           "connection:")):
                continue
            out.append(line)
        out.append("Connection: close")
        up_w.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        length = int(headers.get("content-length", "0") or 0)
        if length:
            up_w.write(await reader.readexactly(length))
        await up_w.drain()
        await self._pipe(up_r, writer)
        up_w.close()

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while data := await src.read(65536):
                dst.write(data)
                await dst.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                dst.close()
            except Exception:                       # noqa: BLE001
                pass
