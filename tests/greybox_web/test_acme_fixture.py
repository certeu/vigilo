"""The Acme Workspace evaluation fixture behaves exactly as its ground truth says.

If this fails, ground_truth.json no longer describes the target and every
evaluation scored against it is meaningless — fix the fixture or the manifest
together.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from tests.greybox_web.fixtures import acme_portal

GT = json.loads((Path(acme_portal.__file__).parent / "ground_truth.json").read_text())


@pytest.fixture(scope="module")
def acme():
    server, url = acme_portal.serve(0)
    yield url
    server.should_exit = True


def _login(url, user):
    acct = next(a for a in GT["accounts"] if a["user"] == user)
    c = httpx.Client(base_url=url, trust_env=False)
    assert c.post("/api/auth/login", json={"username": user,
                                           "password": acct["password"]}).status_code == 200
    return c


def test_seeded_issues_and_controls_hold(acme):
    anon = httpx.Client(base_url=acme, trust_env=False)
    alice, bob = _login(acme, "alice"), _login(acme, "bob")
    # the API is invisible in the HTML shell: only the bundle names it
    shell = anon.get("/").text
    assert "/api/" not in shell and acme_portal.BUNDLE_NAME in shell
    bundle = anon.get(f"/assets/{acme_portal.BUNDLE_NAME}").text
    # routes are assembled at runtime ('/api' + '/invoices/' + id): no full literal,
    # so static extraction alone cannot recover them -- runtime observation can
    assert "'/invoices/' + id" in bundle and "/api/invoices/" not in bundle
    # GT1: alice reads bob's invoice
    own = [i["id"] for i in alice.get("/api/invoices").json()["invoices"]]
    assert 1043 not in own and alice.get("/api/invoices/1043").json()["owner"] == "bob"
    # GT2: public internal metadata
    h = anon.get("/api/health").json()
    assert h["node"].endswith(".acme.internal") and "db-int" in h["database"]
    # GT3: arbitrary origin reflected with credentials
    r = alice.get("/api/me", headers={"Origin": "https://evil.example"})
    assert r.headers["access-control-allow-origin"] == "https://evil.example"
    assert r.headers["access-control-allow-credentials"] == "true"
    # GT4: no defensive headers
    r = anon.get("/")
    assert not {"content-security-policy", "x-content-type-options",
                "referrer-policy"} & {k.lower() for k in r.headers}
    # GT5: the custom feed leaks bob's unguessable document id, readable by alice
    feed = alice.get("/api/activity")
    assert feed.headers["content-type"].startswith("text/x-acme-feed")
    bob_doc = next(l.split("|")[3][4:] for l in feed.text.splitlines()
                   if "|bob|upload|doc:" in l)
    assert bob_doc not in json.dumps(alice.get("/api/documents").json())
    assert alice.get(f"/api/documents/{bob_doc}").json()["owner"] == "bob"
    # negative controls
    assert alice.get("/api/admin/users").status_code == 403
    assert bob.get("/api/admin/users").status_code == 200
    assert anon.get("/api/invoices").status_code == 401
    assert alice.get("/api/me").json()["username"] == "alice"
    # nothing in the fixture changes state
    assert anon.delete("/api/invoices/1041").status_code in (404, 405)
