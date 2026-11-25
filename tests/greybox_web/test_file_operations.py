"""Controlled file workflow instruments remain guarded and evidence-backed."""
from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from src.greybox_web import tools as gb_tools
from src.greybox_web.netguard import Budget, GuardedHttpClient, NetPolicy, NullRecorder, ScopeViolation
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.tools import ToolContext, fileops


@pytest.fixture(scope="module")
def file_service():
    state = {"upload": b""}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("content-length", "0"))
            state["upload"] = self.rfile.read(size)
            self.send_response(201)
            self.send_header("Location", "/files/new")
            self.end_headers()

        def do_GET(self):
            if self.path == "/files/owner.txt" and self.headers.get("Authorization") != "Bearer owner":
                self.send_response(403)
                self.end_headers()
                return
            body = b"vigilo-file-marker" if self.path in {
                "/files/owner.txt", "/raw/proof.txt", "/raw/safe/%2e%2e/proof.txt"} else b"not found"
            self.send_response(200 if body.startswith(b"vigilo") else 404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Disposition", 'attachment; filename="proof.txt"')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/", state
    server.shutdown()
    thread.join(timeout=2)


@asynccontextmanager
async def _context(base_url, params, *, state_changing=True):
    scope = ScopePolicy.from_dict({"allowed_hosts": ["127.0.0.1"], "allowed_schemes": ["http"],
        "allowed_ports": [urlsplit(base_url).port], "path_prefixes": ["/"],
        "activity": {"state_changing": state_changing}})
    client = GuardedHttpClient(scope=scope, budget=Budget(20, 30),
        policy=NetPolicy(allow_private=True), rate_limit_rps=50, request_timeout_s=2,
        recorder=NullRecorder())
    client.bind("setup").establish_session("owner", None, "Bearer owner")
    client.bind("setup").establish_session("other", None, "Bearer other")
    try:
        yield ToolContext(http=client.bind("test"), base_url=base_url, scope=scope,
                          limits={}, params=params), client
    finally:
        await client.aclose()


async def test_multipart_upload_is_state_change_guarded(file_service):
    base_url, state = file_service
    params = {"url": "/upload", "identity": "owner", "filename": "nested/../proof.txt",
              "field": "document", "content": "vigilo-file-marker",
              "resource_ref": "file:pending", "expected_owner": "owner"}
    async with _context(base_url, params) as (ctx, _):
        result = await fileops.upload(ctx)
    assert result.counts == {"attempted": 1, "succeeded": 1}
    facts = result.observations[0].facts
    assert facts["normalised_filename"] == "proof.txt"
    assert facts["ownership"]["resource_ref"] == "file:pending"
    assert b'name="document"; filename="nested/../proof.txt"' in state["upload"]

    async with _context(base_url, params, state_changing=False) as (ctx, _):
        with pytest.raises(ScopeViolation, match="state_changing_not_allowed"):
            await fileops.upload(ctx)


async def test_download_records_cross_identity_ownership_evidence(file_service):
    base_url, _ = file_service
    async with _context(base_url, {"url": "/files/owner.txt", "identities": ["owner", "other"],
            "marker": "vigilo-file-marker", "expected_owner": "owner",
            "resource_ref": "file:owned"}) as (ctx, _):
        result = await fileops.download(ctx)
    matrix = result.observations[0].facts["matrix"]
    assert [(row["identity"], row["status"], row["marker_present"]) for row in matrix] == [
        ("owner", 200, True), ("other", 403, False)]
    assert all(row["ownership"]["expected_owner"] == "owner" for row in matrix)


async def test_path_compare_is_bound_to_synthetic_marker(file_service):
    base_url, _ = file_service
    params = {"url_template": "/raw/{path}", "control_path": "proof.txt",
              "candidate_path": "safe/%2e%2e/proof.txt", "identity": "owner",
              "marker": "vigilo-file-marker", "resource_ref": "file:path-proof"}
    async with _context(base_url, params) as (ctx, _):
        result = await fileops.path_compare(ctx)
    assert result.counts == {"attempted": 2, "marker_responses": 2}
    assert [row["marker_present"] for row in result.observations[0].facts["paths"]] == [True, True]
    assert all(gb_tools.get(name) for name in ("file.upload", "file.download", "file.path_compare"))
