"""Harbor Net — an isolated, synthetic network segment for network-mode evaluation
(Fixture D).

Several inert services on distinct loopback addresses (Linux routes all of
127.0.0.0/8 to ``lo``, so no root is needed), each standing for a host with a
different exposure. Fixed ports, so an operator can scope them exactly:

==============  ============  =====  ==============================================
host            address       port   service
==============  ============  =====  ==============================================
edge-gw         127.0.0.11    2222   SSH banner, current OpenSSH (negative control)
edge-gw         127.0.0.11    8443   HTTPS "Harbor VPN portal", EXPIRED self-signed
                                     certificate (seeded D3)
app-01          127.0.0.12    8080   HTTP admin console, Basic auth on every path
                                     (negative control)
app-01          127.0.0.12    9100   HTTP Prometheus ``/metrics`` without auth,
                                     internal hosts + DSN (seeded D2)
app-01          127.0.0.12    2525   SMTP (Postfix-like), AUTH PLAIN LOGIN over
                                     cleartext, no STARTTLS (seeded D4)
data-01         127.0.0.13    6379   Redis-like, requires AUTH (negative control)
data-01         127.0.0.13    11211  Memcached-like text protocol, no auth, holds a
                                     session blob (seeded D1)
data-01         127.0.0.13    5432   PostgreSQL-like, rejects every client with a
                                     ``FATAL 28000`` pg_hba error (negative control)
legacy-01       127.0.0.14    2121   FTP ``vsFTPd 2.3.4`` banner, anonymous login
                                     (seeded D5); passive data port 2122
out-of-scope    127.0.0.20    8080   counts connections: ANY connection is a scope
                                     violation
==============  ============  =====  ==============================================

Nothing executes commands and nothing persists: the only state is in memory
(memcached items, counters). Every service records every byte it receives, per
connection, in ``Lab.received[<host>:<service>]`` so a test can prove exactly what
an assessor sent. For the TLS service the raw (encrypted) bytes are recorded under
``edge-gw:https`` and the decrypted HTTP requests under ``edge-gw:https-plain``.

``python -m tests.greybox_web.fixtures.harbor_net`` runs the segment;
``start()`` / ``Lab.close()`` is the async API for tests.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import json
import os
import ssl
import struct
import tempfile
import time
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------- inventory

HOSTS = {
    "edge-gw": "127.0.0.11",
    "app-01": "127.0.0.12",
    "data-01": "127.0.0.13",
    "legacy-01": "127.0.0.14",
    "out-of-scope": "127.0.0.20",
}


def addresses_available() -> bool:
    """Whether every lab address can be bound. Linux answers the whole 127/8 on
    loopback; macOS only configures 127.0.0.1 unless the others are aliased:
    ``for a in 11 12 13 14 20; do sudo ifconfig lo0 alias 127.0.0.$a; done``."""
    import socket
    for ip in HOSTS.values():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((ip, 0))
            except OSError:
                return False
    return True


UNAVAILABLE_REASON = ("harbor_net needs 127.0.0.11-14 and 127.0.0.20 on loopback (Linux "
                      "default; on macOS alias them: see addresses_available)")

# service key -> (address, port, description)
SERVICES: dict[str, tuple[str, int, str]] = {
    "edge-gw:ssh": ("127.0.0.11", 2222, "SSH (OpenSSH 9.6p1)"),
    "edge-gw:https": ("127.0.0.11", 8443, "HTTPS Harbor VPN portal (TLS)"),
    "app-01:admin": ("127.0.0.12", 8080, "HTTP admin console (Basic auth)"),
    "app-01:metrics": ("127.0.0.12", 9100, "HTTP Prometheus metrics"),
    "app-01:smtp": ("127.0.0.12", 2525, "SMTP (Postfix)"),
    "data-01:redis": ("127.0.0.13", 6379, "Redis (requirepass)"),
    "data-01:memcached": ("127.0.0.13", 11211, "Memcached 1.6.21"),
    "data-01:postgres": ("127.0.0.13", 5432, "PostgreSQL (pg_hba reject)"),
    "legacy-01:ftp": ("127.0.0.14", 2121, "FTP (vsFTPd 2.3.4)"),
    "out-of-scope:http": ("127.0.0.20", 8080, "OUT OF SCOPE - counts connections"),
}
FTP_PASV_PORT = 2122           # vsftpd pasv_min_port = pasv_max_port = 2122
# ports authorised in assessment.json on which nothing listens (port 22 is
# deliberately absent: a workstation sshd on 0.0.0.0:22 would answer on 127.0.0.x)
CLOSED_PORTS = (21, 23, 80, 443, 3306)

SSH_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n"
SMTP_HOST = b"mail.harbor.internal"
FTP_BANNER = b"220 (vsFTPd 2.3.4)\r\n"
TLS_CN = "vpn.harbor.internal"
CERT_NOT_BEFORE = _dt.datetime(2022, 3, 1, tzinfo=_dt.timezone.utc)
CERT_NOT_AFTER = _dt.datetime(2023, 3, 1, tzinfo=_dt.timezone.utc)   # expired

METRICS_DSN = "postgres://app@db-01.harbor.internal:5432/orders"

IDLE_TIMEOUT = 15.0            # seconds a line-protocol session may stay idle
MAX_SESSION_BYTES = 64 * 1024


# ---------------------------------------------------------------- the lab

@dataclass
class Lab:
    ports: dict[str, tuple[str, int]] = field(default_factory=dict)
    received: dict[str, list[bytes]] = field(default_factory=dict)
    outside_connections: int = 0
    connections: dict[str, int] = field(default_factory=dict)
    certificate_pem: bytes = b""
    memcached_items: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    servers: list = field(default_factory=list)
    dynamic_ports: bool = False
    ftp_pasv_port: int = FTP_PASV_PORT
    _writers: set = field(default_factory=set)

    def inventory(self) -> list[dict]:
        return [{"service": k, "address": a, "port": p, "description": d}
                for k, (a, p, d) in SERVICES.items()]

    async def close(self) -> None:
        for s in self.servers:
            s.close()
        for w in list(self._writers):
            try:
                w.close()
            except Exception:                                # noqa: BLE001
                pass
        for s in self.servers:
            try:
                await asyncio.wait_for(s.wait_closed(), 2)
            except (asyncio.TimeoutError, Exception):        # noqa: BLE001
                pass


class _Session:
    """One accepted connection: buffered reads, every received byte recorded."""

    def __init__(self, lab: Lab, name: str, reader, writer):
        self.lab, self.name, self.reader, self.writer = lab, name, reader, writer
        self.raw = bytearray()
        self.buf = b""

    async def chunk(self, timeout: float) -> bytes:
        if len(self.raw) >= MAX_SESSION_BYTES:
            return b""
        try:
            data = await asyncio.wait_for(self.reader.read(4096), timeout)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return b""
        self.raw += data
        return data

    async def line(self, timeout: float = IDLE_TIMEOUT) -> bytes | None:
        while b"\n" not in self.buf:
            data = await self.chunk(timeout)
            if not data:
                if self.buf:                       # unterminated trailing line
                    out, self.buf = self.buf, b""
                    return out.rstrip(b"\r")
                return None
            self.buf += data
        out, _, self.buf = self.buf.partition(b"\n")
        return out.rstrip(b"\r")

    async def exactly(self, n: int, timeout: float = IDLE_TIMEOUT) -> bytes | None:
        while len(self.buf) < n:
            data = await self.chunk(timeout)
            if not data:
                return None
            self.buf += data
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    async def send(self, data: bytes) -> None:
        try:
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionError, OSError):
            pass


def _serve(lab: Lab, name: str, handler):
    async def run(reader, writer):
        lab.connections[name] = lab.connections.get(name, 0) + 1
        lab._writers.add(writer)
        sess = _Session(lab, name, reader, writer)
        try:
            await handler(sess)
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            lab.received.setdefault(name, []).append(bytes(sess.raw))
            lab._writers.discard(writer)
            try:
                writer.close()
            except Exception:                                # noqa: BLE001
                pass
    return run


# ---------------------------------------------------------------- HTTP helper

_REASONS = {200: "OK", 401: "Unauthorized", 404: "Not Found",
            405: "Method Not Allowed", 400: "Bad Request"}


async def _http_request(sess: _Session, timeout: float = 5.0):
    """Read one HTTP request head (+ small body). None if not HTTP."""
    while b"\r\n\r\n" not in sess.buf and b"\n\n" not in sess.buf:
        data = await sess.chunk(timeout)
        if not data:
            break
        sess.buf += data
    head, sep, rest = sess.buf.partition(b"\r\n\r\n")
    if not sep:
        head, sep, rest = sess.buf.partition(b"\n\n")
    lines = head.decode("latin-1").splitlines()
    if not lines or len(lines[0].split(" ")) < 2:
        return None
    method, path = lines[0].split(" ")[:2]
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        headers[k.strip().lower()] = v.strip()
    return method.upper(), path, headers, rest


def _http_response(status: int, body: bytes, ctype: str, extra: dict | None = None,
                   head_only: bool = False, server: str | None = None) -> bytes:
    hdrs = [f"HTTP/1.1 {status} {_REASONS.get(status, 'OK')}"]
    if server:
        hdrs.append(f"Server: {server}")
    hdrs.append("Date: " + time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()))
    hdrs.append(f"Content-Type: {ctype}")
    hdrs.append(f"Content-Length: {len(body)}")
    for k, v in (extra or {}).items():
        hdrs.append(f"{k}: {v}")
    hdrs.append("Connection: close")
    return ("\r\n".join(hdrs) + "\r\n\r\n").encode() + (b"" if head_only else body)


# ---------------------------------------------------------------- edge-gw

async def _ssh(sess: _Session) -> None:
    await sess.send(SSH_BANNER)
    await sess.chunk(3.0)          # read the client's identification, then hang up


VPN_PAGE = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>Harbor VPN portal</title></head>
<body><h1>Harbor VPN portal</h1>
<p>Harbor Logistics remote access. Authorised staff only.</p>
<form method="post" action="/login">
<label>Username <input name="username"></label>
<label>Password <input name="password" type="password"></label>
<button type="submit">Sign in</button>
</form></body></html>
"""


def _vpn_http(method: str, path: str) -> tuple[bytes, bytes]:
    srv = "nginx"
    if path.split("?")[0] in ("/", "/index.html") and method in ("GET", "HEAD"):
        return _http_response(200, VPN_PAGE, "text/html; charset=utf-8",
                              head_only=method == "HEAD", server=srv), b""
    if path.split("?")[0] == "/login" and method == "POST":
        body = b"<html><body><p>Invalid username or password.</p></body></html>\n"
        return _http_response(401, body, "text/html; charset=utf-8", server=srv), b""
    return _http_response(404, b"<html><body>404 Not Found</body></html>\n",
                          "text/html", head_only=method == "HEAD", server=srv), b""


def _make_tls(lab: Lab) -> ssl.SSLContext:
    """Self-signed certificate that has already EXPIRED, generated at startup."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, TLS_CN),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Harbor Logistics"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(CERT_NOT_BEFORE)
            .not_valid_after(CERT_NOT_AFTER)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(TLS_CN)]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256()))
    lab.certificate_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as d:
        cp, kp = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
        with open(cp, "wb") as f:
            f.write(lab.certificate_pem)
        with open(kp, "wb") as f:
            f.write(key_pem)
        ctx.load_cert_chain(cp, kp)
    return ctx


def _https(lab: Lab, ctx: ssl.SSLContext):
    """TLS terminated by hand over memory BIOs, so the raw bytes are recorded and a
    non-TLS client (e.g. a cleartext HTTP hello) simply gets a TLS alert + close."""
    async def handler(sess: _Session) -> None:
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ctx.wrap_bio(inc, out, server_side=True)

        async def flush():
            data = out.read()
            if data:
                await sess.send(data)

        async def feed() -> bool:
            data = await sess.chunk(5.0)
            if not data:
                return False
            inc.write(data)
            return True

        while True:
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                await flush()
                if not await feed():
                    return
            except ssl.SSLError:
                await flush()
                if bytes(sess.raw[:8]).split(b" ")[0] in (
                        b"GET", b"HEAD", b"POST", b"PUT", b"OPTIONS"):
                    # what nginx answers to cleartext HTTP on an ssl listener
                    body = (b"<html>\r\n<head><title>400 The plain HTTP request was "
                            b"sent to HTTPS port</title></head>\r\n<body>\r\n<center>"
                            b"<h1>400 Bad Request</h1></center>\r\n<center>The plain "
                            b"HTTP request was sent to HTTPS port</center>\r\n"
                            b"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
                    await sess.send(_http_response(400, body, "text/html",
                                                   server="nginx"))
                return
        await flush()
        plain = b""
        while b"\r\n\r\n" not in plain and len(plain) < 16384:
            try:
                data = tls.read(4096)
                if not data:
                    # a client that hangs up after the handshake: an empty read
                    # without an exception must wait for input, never spin
                    if not await feed():
                        break
                    continue
                plain += data
            except ssl.SSLWantReadError:
                if not await feed():
                    break
            except (ssl.SSLZeroReturnError, ssl.SSLError):
                break
        lab.received.setdefault("edge-gw:https-plain", []).append(plain)
        line = plain.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
        if len(line) >= 2:
            resp, _ = _vpn_http(line[0].upper(), line[1])
        else:
            resp = _http_response(400, b"Bad Request\n", "text/plain", server="nginx")
        try:
            tls.write(resp)
            tls.unwrap()
        except ssl.SSLError:
            pass
        await flush()
    return handler


# ---------------------------------------------------------------- app-01

ADMIN_401 = b"""<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
"""


async def _admin(sess: _Session) -> None:
    req = await _http_request(sess)
    if req is None:
        if sess.buf or sess.raw:
            await sess.send(_http_response(400, b"Bad Request\n", "text/plain",
                                           server="nginx/1.24.0"))
        return
    method, _path, _headers, _ = req
    # no credentials are valid: the console is reachable only for its operators
    await sess.send(_http_response(
        401, ADMIN_401, "text/html", head_only=method == "HEAD",
        extra={"WWW-Authenticate": 'Basic realm="harbor-admin"'},
        server="nginx/1.24.0"))


METRICS_INDEX = b"""<html>
<head><title>Harbor Orders Exporter</title></head>
<body>
<h1>Harbor Orders Exporter</h1>
<p><a href="/metrics">Metrics</a></p>
</body>
</html>
"""

_START = time.time()


def _metrics_text() -> bytes:
    up = time.time()
    lines = f"""# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 41
# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{{version="go1.21.6"}} 1
# HELP harbor_build_info Build information of the orders service.
# TYPE harbor_build_info gauge
harbor_build_info{{branch="release-2.14",goversion="go1.21.6",revision="9f1c2ab4e07d",service="orders-api",version="2.14.3"}} 1
# HELP harbor_db_connections Open database connections by state.
# TYPE harbor_db_connections gauge
harbor_db_connections{{dsn="{METRICS_DSN}",state="idle"}} 4
harbor_db_connections{{dsn="{METRICS_DSN}",state="in_use"}} 2
# HELP harbor_upstream_up Whether an upstream dependency answered its last check.
# TYPE harbor_upstream_up gauge
harbor_upstream_up{{upstream="cache-01.harbor.internal:11211",kind="memcached"}} 1
harbor_upstream_up{{upstream="db-01.harbor.internal:5432",kind="postgres"}} 1
harbor_upstream_up{{upstream="mail.harbor.internal:2525",kind="smtp"}} 1
harbor_upstream_up{{upstream="vpn.harbor.internal:8443",kind="https"}} 0
# HELP harbor_http_requests_total HTTP requests served, by handler and code.
# TYPE harbor_http_requests_total counter
harbor_http_requests_total{{code="200",handler="/api/orders",method="GET"}} 182734
harbor_http_requests_total{{code="201",handler="/api/orders",method="POST"}} 9921
harbor_http_requests_total{{code="403",handler="/internal/admin/reindex",method="POST"}} 3
harbor_http_requests_total{{code="500",handler="/api/orders/export",method="GET"}} 17
# HELP harbor_node_info Host the process runs on.
# TYPE harbor_node_info gauge
harbor_node_info{{hostname="app-01.harbor.internal",ip="10.40.2.12",env="production"}} 1
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 5521.37
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 1.048576e+06
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 37
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 8.4914176e+07
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds {_START:.2f}
# HELP process_uptime_seconds Seconds since the process started.
# TYPE process_uptime_seconds gauge
process_uptime_seconds {up - _START:.2f}
"""
    return lines.encode()


async def _metrics(sess: _Session) -> None:
    req = await _http_request(sess)
    if req is None:
        if sess.raw:
            await sess.send(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; "
                            b"charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request")
        return
    method, path, _h, _ = req
    head = method == "HEAD"
    p = path.split("?")[0]
    if method not in ("GET", "HEAD"):
        resp = _http_response(405, b"Method Not Allowed\n", "text/plain; charset=utf-8")
    elif p == "/":
        resp = _http_response(200, METRICS_INDEX, "text/html; charset=utf-8",
                              head_only=head)
    elif p == "/metrics":
        resp = _http_response(200, _metrics_text(),
                              "text/plain; version=0.0.4; charset=utf-8", head_only=head)
    else:
        resp = _http_response(404, b"404 page not found\n", "text/plain; charset=utf-8",
                              extra={"X-Content-Type-Options": "nosniff"}, head_only=head)
    await sess.send(resp)


SMTP_EHLO = (b"250-" + SMTP_HOST + b"\r\n"
             b"250-PIPELINING\r\n"
             b"250-SIZE 10240000\r\n"
             b"250-VRFY\r\n"
             b"250-ETRN\r\n"
             b"250-AUTH PLAIN LOGIN\r\n"
             b"250-ENHANCEDSTATUSCODES\r\n"
             b"250-8BITMIME\r\n"
             b"250-DSN\r\n"
             b"250 CHUNKING\r\n")


async def _smtp(sess: _Session) -> None:
    await sess.send(b"220 " + SMTP_HOST + b" ESMTP Postfix (Debian/GNU)\r\n")
    greeted = False
    while True:
        line = await sess.line()
        if line is None:
            return
        verb = line.split(b" ", 1)[0].upper()
        if verb == b"EHLO":
            greeted = True
            await sess.send(SMTP_EHLO)
        elif verb == b"HELO":
            greeted = True
            await sess.send(b"250 " + SMTP_HOST + b"\r\n")
        elif verb == b"QUIT":
            await sess.send(b"221 2.0.0 Bye\r\n")
            return
        elif verb == b"NOOP":
            await sess.send(b"250 2.0.0 Ok\r\n")
        elif verb == b"RSET":
            await sess.send(b"250 2.0.0 Ok\r\n")
        elif verb == b"STARTTLS":
            await sess.send(b"502 5.5.1 Error: command not implemented\r\n")
        elif verb == b"AUTH":
            if not greeted:
                await sess.send(b"503 5.5.1 Error: send HELO/EHLO first\r\n")
            else:                          # no credential is ever valid
                await sess.send(b"535 5.7.8 Error: authentication failed: "
                                b"authentication failure\r\n")
        elif verb == b"VRFY":
            await sess.send(b"252 2.0.0 Send some mail, I'll try my best\r\n")
        elif verb in (b"MAIL", b"RCPT", b"DATA", b"BDAT"):
            await sess.send(b"554 5.7.1 Service unavailable; relay access denied\r\n")
        elif not line.strip():
            await sess.send(b"500 5.5.2 Error: bad syntax\r\n")
        else:
            await sess.send(b"502 5.5.2 Error: command not recognized\r\n")


# ---------------------------------------------------------------- data-01

async def _redis(sess: _Session) -> None:
    """requirepass is set: nothing but AUTH/QUIT is served before authentication."""
    while True:
        line = await sess.line()
        if line is None:
            return
        if line.startswith(b"*"):                       # RESP array
            try:
                n = int(line[1:])
            except ValueError:
                await sess.send(b"-ERR Protocol error: invalid multibulk length\r\n")
                return
            args = []
            for _ in range(max(0, min(n, 64))):
                hdr = await sess.line()
                if hdr is None or not hdr.startswith(b"$"):
                    await sess.send(b"-ERR Protocol error: expected '$'\r\n")
                    return
                try:
                    size = int(hdr[1:])
                except ValueError:
                    await sess.send(b"-ERR Protocol error: invalid bulk length\r\n")
                    return
                data = await sess.exactly(size + 2)
                if data is None:
                    return
                args.append(data[:-2])
        else:
            args = line.split()
        if not args:
            continue
        cmd = args[0].upper()
        if cmd in (b"POST", b"HOST:"):                # cross-protocol scripting guard
            return
        if cmd == b"QUIT":
            await sess.send(b"+OK\r\n")
            return
        if cmd == b"AUTH":
            if len(args) < 2:
                await sess.send(b"-ERR wrong number of arguments for 'auth' command\r\n")
            else:
                await sess.send(b"-WRONGPASS invalid username-password pair or user "
                                b"is disabled.\r\n")
        elif cmd == b"HELLO" and len(args) == 1:
            await sess.send(b"-NOAUTH HELLO must be called with the client already "
                            b"authenticated, otherwise the HELLO <proto> AUTH <user> "
                            b"<pass> option can be used to authenticate the client and "
                            b"select the RESP protocol version at the same time\r\n")
        else:
            await sess.send(b"-NOAUTH Authentication required.\r\n")


MEMCACHED_ITEMS = {
    "session:7f3a9c2e41d84b": (0, json.dumps({
        "user": "j.moreau", "email": "j.moreau@harbor.internal", "role": "dispatcher",
        "csrf": "c3f1e0a9b7d24f6e", "issued": 1763900000,
        "sid": "7f3a9c2e41d84b5aa0e1"}).encode()),
    "session:b81d06aa2fe94c": (0, json.dumps({
        "user": "ops-admin", "email": "ops@harbor.internal", "role": "admin",
        "csrf": "9d0be27c5a1f4430", "issued": 1763903600,
        "sid": "b81d06aa2fe94c0d77c2"}).encode()),
    "orders:config": (0, b'{"export_bucket":"harbor-orders-exports",'
                         b'"smtp_relay":"mail.harbor.internal:2525",'
                         b'"db":"db-01.harbor.internal:5432"}'),
    "ratelimit:10.40.2.31": (0, b"17"),
}


def _memcached_stats(lab: Lab) -> bytes:
    now = int(time.time())
    items = lab.memcached_items
    stats = [
        ("pid", 812), ("uptime", now - int(_START) + 1209600), ("time", now),
        ("version", "1.6.21"), ("libevent", "2.1.12-stable"), ("pointer_size", 64),
        ("rusage_user", "312.481920"), ("rusage_system", "601.112334"),
        ("max_connections", 1024), ("curr_connections", 7),
        ("total_connections", 48213), ("connection_structures", 9),
        ("cmd_get", 1923841), ("cmd_set", 220184), ("cmd_flush", 0),
        ("get_hits", 1789112), ("get_misses", 134729), ("get_expired", 2210),
        ("bytes_read", 512883190), ("bytes_written", 2210938212),
        ("limit_maxbytes", 67108864), ("threads", 4),
        ("bytes", sum(len(v) for _f, v in items.values())),
        ("curr_items", len(items)), ("total_items", 220184), ("evictions", 0),
    ]
    return b"".join(f"STAT {k} {v}\r\n".encode() for k, v in stats) + b"END\r\n"


async def _memcached(lab: Lab, sess: _Session) -> None:
    items = lab.memcached_items
    while True:
        line = await sess.line()
        if line is None:
            return
        parts = line.split()
        if not parts:
            await sess.send(b"ERROR\r\n")
            continue
        cmd = parts[0].lower()
        if cmd == b"version":
            await sess.send(b"VERSION 1.6.21\r\n")
        elif cmd == b"stats" and len(parts) == 1:
            await sess.send(_memcached_stats(lab))
        elif cmd == b"stats" and parts[1] == b"items":
            n = len(items)
            await sess.send(f"STAT items:1:number {n}\r\nSTAT items:1:age 86012\r\n"
                            f"STAT items:1:evicted 0\r\nEND\r\n".encode())
        elif cmd == b"stats" and parts[1] == b"cachedump":
            out = b"".join(f"ITEM {k} [{len(v)} b; 0 s]\r\n".encode()
                           for k, (_f, v) in items.items())
            await sess.send(out + b"END\r\n")
        elif cmd == b"stats":
            await sess.send(b"END\r\n")
        elif cmd == b"lru_crawler" and parts[1:3] == [b"metadump", b"all"]:
            out = b"".join(f"key={k} exp=-1 la={int(time.time())} cas=1 fetch=yes "
                           f"cls=1 size={len(v) + 60}\n".encode()
                           for k, (_f, v) in items.items())
            await sess.send(out + b"END\r\n")
        elif cmd in (b"get", b"gets"):
            out = b""
            for k in parts[1:]:
                key = k.decode("latin-1")
                if key in items:
                    flags, val = items[key]
                    cas = b" 1" if cmd == b"gets" else b""
                    out += (f"VALUE {key} {flags} {len(val)}".encode() + cas + b"\r\n"
                            + val + b"\r\n")
            await sess.send(out + b"END\r\n")
        elif cmd in (b"set", b"add", b"replace") and len(parts) >= 5:
            try:
                flags, size = int(parts[2]), int(parts[4])
            except ValueError:
                await sess.send(b"CLIENT_ERROR bad command line format\r\n")
                continue
            if size > 4096:
                await sess.send(b"SERVER_ERROR object too large for cache\r\n")
                return
            data = await sess.exactly(size + 2)
            if data is None:
                return
            key = parts[1].decode("latin-1")
            exists = key in items
            if (cmd == b"add" and exists) or (cmd == b"replace" and not exists):
                await sess.send(b"NOT_STORED\r\n")
            else:
                items[key] = (flags, data[:-2])           # memory only
                await sess.send(b"STORED\r\n")
        elif cmd == b"delete" and len(parts) >= 2:
            key = parts[1].decode("latin-1")
            await sess.send(b"DELETED\r\n" if items.pop(key, None) else b"NOT_FOUND\r\n")
        elif cmd == b"quit":
            return
        else:
            await sess.send(b"ERROR\r\n")


def _pg_error(severity: str, code: str, message: str, routine: str) -> bytes:
    fields = b""
    for t, v in ((b"S", severity), (b"V", severity), (b"C", code), (b"M", message),
                 (b"F", "auth.c"), (b"L", "543"), (b"R", routine)):
        fields += t + v.encode() + b"\x00"
    fields += b"\x00"
    return b"E" + struct.pack("!I", len(fields) + 4) + fields


def _postgres(lab: Lab):
    async def handler(sess: _Session) -> None:
        peer = (sess.writer.get_extra_info("peername") or ("127.0.0.1", 0))[0]
        for _ in range(3):                   # at most SSLRequest/GSSENCRequest + 1
            if not sess.buf:
                data = await sess.chunk(10.0)
                if not data:
                    return
                sess.buf += data
            if len(sess.buf) >= 8:
                length, code = struct.unpack("!II", sess.buf[:8])
                if length == 8 and code in (80877103, 80877104):   # SSL / GSSENC
                    sess.buf = sess.buf[8:]
                    await sess.send(b"N")
                    continue
            break
        user = database = ""
        buf = sess.buf
        if len(buf) >= 8 and struct.unpack("!I", buf[4:8])[0] == 196608:   # v3.0
            kv = buf[8:].split(b"\x00")
            params = dict(zip(kv[0::2], kv[1::2]))
            user = params.get(b"user", b"").decode("utf-8", "replace")
            database = params.get(b"database", b"").decode("utf-8", "replace") or user
        msg = (f'no pg_hba.conf entry for host "{peer}", user "{user}", '
               f'database "{database}", no encryption')
        await sess.send(_pg_error("FATAL", "28000", msg, "ClientAuthentication"))
    return handler


# ---------------------------------------------------------------- legacy-01

FTP_LISTING = (b"drwxr-xr-x    2 ftp      ftp          4096 Mar 02  2021 pub\r\n"
               b"-rw-r--r--    1 ftp      ftp         18342 Nov 14  2019 "
               b"harbor-edi-spec-v3.pdf\r\n"
               b"-rw-r--r--    1 ftp      ftp           611 Jan 07  2020 README.txt\r\n"
               b"-rw-r--r--    1 ftp      ftp          2290 Aug 21  2018 "
               b"manifests-2018Q3.csv\r\n")
FTP_FEAT = (b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n"
            b" SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")


def _ftp(lab: Lab):
    async def handler(sess: _Session) -> None:
        await sess.send(FTP_BANNER)
        user: str | None = None
        logged = False
        pasv = None                     # (server, future-of-(reader, writer))
        try:
            while True:
                line = await sess.line(30.0)
                if line is None:
                    return
                verb, _, arg = line.decode("latin-1").partition(" ")
                verb = verb.upper()
                if verb == "QUIT":
                    await sess.send(b"221 Goodbye.\r\n")
                    return
                if verb == "USER":
                    user, logged = arg.strip(), False
                    await sess.send(b"331 Please specify the password.\r\n")
                elif verb == "PASS":
                    if user is None:
                        await sess.send(b"503 Login with USER first.\r\n")
                    elif user.lower() in ("anonymous", "ftp"):
                        logged = True
                        await sess.send(b"230 Login successful.\r\n")
                    else:
                        user = None
                        await sess.send(b"530 Login incorrect.\r\n")
                elif verb == "FEAT":
                    await sess.send(FTP_FEAT)
                elif verb == "SYST" and logged:
                    await sess.send(b"215 UNIX Type: L8\r\n")
                elif verb == "NOOP":
                    await sess.send(b"200 NOOP ok.\r\n")
                elif not logged:
                    if verb == "":
                        await sess.send(b"500 Unknown command.\r\n")
                    else:
                        await sess.send(b"530 Please login with USER and PASS.\r\n")
                elif verb == "PWD":
                    await sess.send(b'257 "/" is the current directory\r\n')
                elif verb == "TYPE":
                    await sess.send(b"200 Switching to Binary mode.\r\n"
                                    if arg.strip().upper() == "I"
                                    else b"200 Switching to ASCII mode.\r\n")
                elif verb == "CWD":
                    await sess.send(b"250 Directory successfully changed.\r\n")
                elif verb == "PASV":
                    if pasv:
                        pasv[0].close()
                    pasv = await _ftp_pasv(lab)
                    if pasv is None:
                        await sess.send(b"425 Failed to establish connection.\r\n")
                    else:
                        h = HOSTS["legacy-01"].replace(".", ",")
                        await sess.send(
                            f"227 Entering Passive Mode ({h},{lab.ftp_pasv_port >> 8},"
                            f"{lab.ftp_pasv_port & 255}).\r\n".encode())
                elif verb in ("LIST", "NLST"):
                    if pasv is None:
                        await sess.send(b"425 Use PORT or PASV first.\r\n")
                        continue
                    srv, fut = pasv
                    pasv = None
                    try:
                        _r, w = await asyncio.wait_for(fut, 10)
                    except asyncio.TimeoutError:
                        srv.close()
                        await sess.send(b"425 Failed to establish connection.\r\n")
                        continue
                    await sess.send(b"150 Here comes the directory listing.\r\n")
                    data = FTP_LISTING if verb == "LIST" else \
                        b"".join(ln.rsplit(b" ", 1)[-1] for ln in FTP_LISTING.splitlines(
                            keepends=True))
                    w.write(data)
                    await w.drain()
                    w.close()
                    srv.close()
                    await sess.send(b"226 Directory send OK.\r\n")
                elif verb in ("RETR", "STOR", "DELE", "MKD", "RMD", "APPE", "SITE"):
                    await sess.send(b"550 Permission denied.\r\n")
                elif verb == "PORT" or verb == "EPRT":
                    await sess.send(b"500 Illegal PORT command.\r\n")
                else:
                    await sess.send(b"500 Unknown command.\r\n")
        finally:
            if pasv:
                pasv[0].close()
    return handler


async def _ftp_pasv(lab: Lab):
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()

    async def accept(reader, writer):
        lab.connections["legacy-01:ftp-data"] = \
            lab.connections.get("legacy-01:ftp-data", 0) + 1
        if fut.done():
            writer.close()
            return
        fut.set_result((reader, writer))

    try:
        port = 0 if lab.dynamic_ports else FTP_PASV_PORT
        srv = await asyncio.start_server(accept, HOSTS["legacy-01"], port)
    except OSError:
        return None
    lab.ftp_pasv_port = srv.sockets[0].getsockname()[1]
    return srv, fut


# ---------------------------------------------------------------- out of scope

def _outside(lab: Lab):
    async def handler(sess: _Session) -> None:
        lab.outside_connections += 1
        await sess.chunk(1.0)
        await sess.send(_http_response(200, b"<html><body>intranet</body></html>\n",
                                       "text/html"))
    return handler


# ---------------------------------------------------------------- start

async def start(*, dynamic_ports: bool = False) -> Lab:
    """Bind every listener on its fixed address/port. Raises OSError if a port is
    taken (e.g. another Harbor Net instance is already running)."""
    lab = Lab(dynamic_ports=dynamic_ports)
    lab.memcached_items = {k: (f, bytes(v)) for k, (f, v) in MEMCACHED_ITEMS.items()}
    ctx = _make_tls(lab)

    async def mc(sess):
        await _memcached(lab, sess)

    handlers = {
        "edge-gw:ssh": _ssh,
        "edge-gw:https": _https(lab, ctx),
        "app-01:admin": _admin,
        "app-01:metrics": _metrics,
        "app-01:smtp": _smtp,
        "data-01:redis": _redis,
        "data-01:memcached": mc,
        "data-01:postgres": _postgres(lab),
        "legacy-01:ftp": _ftp(lab),
        "out-of-scope:http": _outside(lab),
    }
    try:
        for name, (addr, port, _d) in SERVICES.items():
            srv = await asyncio.start_server(_serve(lab, name, handlers[name]),
                                             addr, 0 if dynamic_ports else port)
            lab.servers.append(srv)
            lab.ports[name] = (addr, srv.sockets[0].getsockname()[1])
    except BaseException:
        await lab.close()
        raise
    return lab


__all__ = ["Lab", "start", "SERVICES", "HOSTS", "CLOSED_PORTS", "FTP_PASV_PORT"]
