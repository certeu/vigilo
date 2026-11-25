"""python -m tests.greybox_web.fixtures.harbor_net [--check]

Runs the Harbor Net segment until interrupted and prints its inventory. With
``--check`` it starts, verifies every listener answers as designed (and that the
authorised-but-closed ports really are closed), prints the result and exits.
"""
from __future__ import annotations

import argparse
import asyncio
import ssl
import sys

from tests.greybox_web.fixtures import harbor_net as hn


async def _talk(host, port, send: bytes | None, *, tls=False, wait=1.0) -> bytes:
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), 5)
    try:
        if send is not None:
            w.write(send)
            await w.drain()
        out = b""
        while True:
            try:
                chunk = await asyncio.wait_for(r.read(4096), wait)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            out += chunk
        return out
    finally:
        w.close()


CHECKS = {
    "edge-gw:ssh": (None, False, b"SSH-2.0-OpenSSH_9.6p1"),
    "edge-gw:https": (b"GET / HTTP/1.0\r\n\r\n", True, b"Harbor VPN portal"),
    "app-01:admin": (b"GET / HTTP/1.0\r\n\r\n", False, b'realm="harbor-admin"'),
    "app-01:metrics": (b"GET /metrics HTTP/1.0\r\n\r\n", False, b"harbor_build_info"),
    "app-01:smtp": (b"EHLO check\r\nQUIT\r\n", False, b"250-AUTH PLAIN LOGIN"),
    "data-01:redis": (b"PING\r\n", False, b"-NOAUTH"),
    "data-01:memcached": (b"version\r\nquit\r\n", False, b"VERSION 1.6.21"),
    "data-01:postgres": (b"\x00\x00\x00\x08\x04\xd2\x16\x2f", False, b"N"),
    "legacy-01:ftp": (b"QUIT\r\n", False, b"220 (vsFTPd 2.3.4)"),
}


async def _check() -> int:
    lab = await hn.start()
    failed = 0
    try:
        for name, (send, tls, expect) in CHECKS.items():
            host, port = lab.ports[name]
            try:
                got = await _talk(host, port, send, tls=tls)
                ok = expect in got
            except Exception as exc:                      # noqa: BLE001
                ok, got = False, repr(exc).encode()
            failed += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {name:22} {host}:{port}"
                  + ("" if ok else f"  got {got[:120]!r}"))
        for addr in (a for k, a in hn.HOSTS.items() if k != "out-of-scope"):
            for port in hn.CLOSED_PORTS:
                try:
                    _r, w = await asyncio.wait_for(asyncio.open_connection(addr, port), 2)
                    w.close()
                    failed += 1
                    print(f"FAIL {addr}:{port} should be closed but accepted a "
                          f"connection (another local service listens on 0.0.0.0)")
                except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
                    pass
        print(f"closed ports {list(hn.CLOSED_PORTS)} verified on every in-scope host"
              if not failed else "")
        if lab.outside_connections:
            failed += 1
            print("FAIL the out-of-scope listener was contacted")
    finally:
        await lab.close()
    print("Harbor Net check: " + ("PASS" if not failed else f"{failed} FAILED"))
    return 1 if failed else 0


async def _run() -> None:
    lab = await hn.start()
    print("Harbor Net is up (Ctrl-C to stop)")
    for item in lab.inventory():
        print(f"  {item['address']:>11}:{item['port']:<5} {item['service']:22} "
              f"{item['description']}")
    print(f"  passive FTP data port {hn.HOSTS['legacy-01']}:{hn.FTP_PASV_PORT}")
    print(f"  authorised but closed: {list(hn.CLOSED_PORTS)}")
    sys.stdout.flush()
    try:
        while True:
            await asyncio.sleep(10)
            if lab.outside_connections:
                print(f"  !! out-of-scope connections: {lab.outside_connections}",
                      flush=True)
    finally:
        await lab.close()


def main() -> None:
    p = argparse.ArgumentParser(description="Harbor Net (synthetic Vigilo network target)")
    p.add_argument("--check", action="store_true",
                   help="start, verify every listener answers, exit")
    a = p.parse_args()
    if a.check:
        sys.exit(asyncio.run(_check()))
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


main()
