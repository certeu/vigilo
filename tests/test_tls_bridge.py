"""The loopback TLS bridge for the Codex CLI (src/ai/tls_bridge.py), against a real
local HTTPS upstream with a test certificate."""
from __future__ import annotations

import asyncio
import datetime as dt
import ssl

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.ai import tls_bridge


def _cert(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    cert_pem, key_pem = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return str(cert_pem), str(key_pem)


class Upstream:
    """A tiny HTTPS server: /echo returns method, path and body; /stream sends SSE
    events one by one."""

    def __init__(self):
        self.requests: list[tuple[str, str, bytes, dict]] = []

    async def handle(self, reader, writer):
        try:
            while True:
                try:
                    head = await reader.readuntil(b"\r\n\r\n")
                except asyncio.IncompleteReadError:
                    return
                lines = head.decode().split("\r\n")
                method, path, _ = lines[0].split(" ", 2)
                hdrs = {k.strip().lower(): v.strip() for k, _, v in
                        (ln.partition(":") for ln in lines[1:] if ln)}
                body = await reader.readexactly(int(hdrs.get("content-length", 0) or 0))
                self.requests.append((method, path, body, hdrs))
                if path.endswith("/stream"):
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                                 b"Transfer-Encoding: chunked\r\n\r\n")
                    for i in range(3):
                        ev = f"data: event-{i}\n\n".encode()
                        writer.write(f"{len(ev):x}\r\n".encode() + ev + b"\r\n")
                        await writer.drain()
                        await asyncio.sleep(0.05)
                    writer.write(b"0\r\n\r\n")
                else:
                    out = f"{method} {path} {body.decode()}".encode()
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                                 b"Content-Length: " + str(len(out)).encode() + b"\r\n\r\n" + out)
                await writer.drain()
        finally:
            writer.close()


@pytest.fixture
async def bridge(tmp_path):
    cert, key = _cert(tmp_path)
    sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sctx.load_cert_chain(cert, key)
    up = Upstream()
    server = await asyncio.start_server(up.handle, "127.0.0.1", 0, ssl=sctx)
    up_port = server.sockets[0].getsockname()[1]
    # bind an ephemeral port for the bridge, then release it for serve()
    probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = probe.sockets[0].getsockname()[1]
    probe.close()
    await probe.wait_closed()
    ready = asyncio.Event()
    task = asyncio.create_task(tls_bridge.serve(f"https://localhost:{up_port}/openai/v1",
                                                "127.0.0.1", port, ca_file=cert, ready=ready))
    await asyncio.wait_for(ready.wait(), 5)
    yield f"http://127.0.0.1:{port}", up
    task.cancel()
    server.close()


async def test_post_body_and_path_reach_the_upstream_over_tls(bridge):
    base, up = bridge
    async with httpx.AsyncClient() as c:
        r = await c.post(base + "/openai/v1/responses", content=b'{"input":"hi"}',
                         headers={"Authorization": "Bearer k", "Content-Type": "application/json"})
    assert r.status_code == 200
    assert r.text == 'POST /openai/v1/responses {"input":"hi"}'
    method, path, body, hdrs = up.requests[0]
    assert hdrs["authorization"] == "Bearer k" and hdrs["host"].startswith("localhost")


async def test_server_sent_events_are_streamed(bridge):
    base, _ = bridge
    seen = []
    async with httpx.AsyncClient() as c:
        async with c.stream("POST", base + "/openai/v1/stream", content=b"{}") as r:
            async for line in r.aiter_lines():
                if line.startswith("data:"):
                    seen.append(line)
    assert seen == ["data: event-0", "data: event-1", "data: event-2"]


async def test_keep_alive_serves_several_requests_on_one_connection(bridge):
    base, up = bridge
    async with httpx.AsyncClient() as c:
        for i in range(3):
            r = await c.post(base + f"/openai/v1/echo{i}", content=str(i).encode())
            assert r.text.endswith(str(i))
    assert len(up.requests) == 3


async def test_not_an_open_proxy(bridge):
    base, up = bridge
    host, port = base.removeprefix("http://").split(":")
    reader, writer = await asyncio.open_connection(host, int(port))
    writer.write(b"GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n")
    await writer.drain()
    head = await asyncio.wait_for(reader.read(200), 5)
    writer.close()
    assert head.startswith(b"HTTP/1.1 400") and up.requests == []


def test_listen_address_must_be_loopback():
    with pytest.raises(SystemExit):
        tls_bridge._loopback_only("0.0.0.0")
    assert tls_bridge._loopback_only("127.0.0.1") == "127.0.0.1"


def test_upstream_must_be_https():
    with pytest.raises(ValueError):
        tls_bridge.Bridge("http://example.org")


def test_only_handshake_rejections_trigger_the_p256_retry():
    eof = ssl.SSLEOFError(8, "EOF occurred in violation of protocol")
    alert = ssl.SSLError(1, "[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version")
    cert = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED]")
    for exc, expected in ((eof, True), (alert, True), (cert, False)):
        wrapped = httpx.ConnectError("")
        wrapped.__cause__ = exc
        assert tls_bridge._handshake_rejected(wrapped) is expected
