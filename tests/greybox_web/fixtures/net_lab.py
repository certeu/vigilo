"""A small, controlled network segment for the non-web vertical slice (acceptance 11).

Real TCP services on loopback, each with a known, inert behaviour:

* ``ssh``    — greets with an outdated OpenSSH banner (version disclosure; the
               version is old enough that an assessor should flag the patch level);
* ``telnet`` — a cleartext remote-login service (IAC negotiation + ``login:``);
* ``redis``  — SILENT until spoken to; answers ``PING`` with ``+PONG`` and no
               authentication (the seeded vulnerability), everything else with an
               error. It records every byte it receives, so a test can prove only
               the inert hello was ever sent;
* ``web``    — silent HTTP service, identified only by an HTTP hello.

``outside`` listens on 127.0.0.2 — NOT in the authorised scope. It counts
connections: any connection to it is a scope violation.

Random ports, so identification cannot rely on well-known port numbers: the
assessor has to read banners and, for silent services, ask.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

SSH_BANNER = b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n"
TELNET_GREETING = b"\xff\xfb\x01\xff\xfb\x03\r\nlab-router login: "


@dataclass
class Lab:
    ports: dict[str, int] = field(default_factory=dict)
    received: dict[str, list[bytes]] = field(default_factory=dict)
    outside_connections: int = 0
    outside_listening: bool = True     # False when 127.0.0.2 is not bindable (macOS)
    servers: list = field(default_factory=list)

    async def close(self) -> None:
        for s in self.servers:
            s.close()
        for s in self.servers:
            try:
                await asyncio.wait_for(s.wait_closed(), 2)
            except (asyncio.TimeoutError, Exception):       # noqa: BLE001
                pass


async def _read(reader, timeout=1.5) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(256), timeout)
    except asyncio.TimeoutError:
        return b""


async def start() -> Lab:
    lab = Lab()

    async def ssh(reader, writer):
        writer.write(SSH_BANNER)
        await writer.drain()
        lab.received.setdefault("ssh", []).append(await _read(reader))
        writer.close()

    async def telnet(reader, writer):
        writer.write(TELNET_GREETING)
        await writer.drain()
        lab.received.setdefault("telnet", []).append(await _read(reader))
        writer.close()

    async def redis(reader, writer):
        data = await _read(reader, 2.5)
        lab.received.setdefault("redis", []).append(data)
        if data.strip().upper() == b"PING":
            writer.write(b"+PONG\r\n")
        elif data:
            writer.write(b"-ERR unknown command\r\n")
        await writer.drain()
        writer.close()

    async def web(reader, writer):
        data = await _read(reader, 2.5)
        lab.received.setdefault("web", []).append(data)
        if data.startswith((b"GET", b"HEAD")):
            writer.write(b"HTTP/1.0 200 OK\r\nServer: lab-httpd/2.4.1\r\n"
                         b"Content-Length: 0\r\n\r\n")
            await writer.drain()
        writer.close()

    async def outside(reader, writer):
        lab.outside_connections += 1
        writer.close()

    for name, fn in (("ssh", ssh), ("telnet", telnet), ("redis", redis),
                     ("web", web)):
        srv = await asyncio.start_server(fn, "127.0.0.1", 0)
        lab.servers.append(srv)
        lab.ports[name] = srv.sockets[0].getsockname()[1]
    # a closed port inside the authorised list: bind, remember, release
    tmp = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    lab.ports["closed"] = tmp.sockets[0].getsockname()[1]
    tmp.close()
    await tmp.wait_closed()
    # The tripwire needs 127.0.0.2. Linux answers the whole 127/8 on loopback; macOS
    # only configures 127.0.0.1 unless aliased (`ifconfig lo0 alias 127.0.0.2`). If
    # it cannot bind, nothing can connect there either: the tests still prove the
    # guard refused the attempt from the recorded traffic.
    try:
        out = await asyncio.start_server(outside, "127.0.0.2", lab.ports["redis"])
    except OSError:
        lab.outside_listening = False
    else:
        lab.servers.append(out)
    return lab
