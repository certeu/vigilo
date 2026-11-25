"""The Lumen Boards evaluation fixture behaves exactly as its ground truth says.

If this fails, ground_truth.json no longer describes the target and every
evaluation scored against it is meaningless — fix the fixture or the manifest
together.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest

from tests.greybox_web.fixtures import lumen_boards as lb

HERE = Path(lb.__file__).parent
GT = json.loads((HERE / "ground_truth.json").read_text())
ASSESSMENT = json.loads((HERE / "assessment.json").read_text())
SEEDED = {s["id"]: s for s in GT["seeded"]}
NCS = {n["id"]: n for n in GT["negative_controls"]}
NORTHSTAR_BOARDS = [r["id"] for r in GT["resources"]
                    if r["type"] == "board" and r["workspace"] == "northstar"]


@pytest.fixture(scope="module")
def url():
    server, base = lb.serve(0)
    yield base
    server.should_exit = True


def _client(url):
    return httpx.Client(base_url=url, trust_env=False)


def _login(url, label, form=False):
    acct = next(a for a in GT["accounts"] if a["label"] == label)
    c = _client(url)
    creds = {"email": acct["user"], "password": acct["password"]}
    r = c.post("/api/v2/session", data=creds) if form else c.post("/api/v2/session", json=creds)
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = c.get("/api/v2/session").json()["csrfToken"]
    return c


@pytest.fixture(scope="module")
def users(url):
    return {"maya": _login(url, "maya"), "leo": _login(url, "leo", form=True),
            "iris": _login(url, "iris")}


def test_spa_shell_bundles_and_lazy_chunk(url):
    anon = _client(url)
    shell = anon.get("/w/northstar/boards/b7k2xq")          # deep link -> shell
    assert shell.status_code == 200 and 'id="root"' in shell.text
    assert "/api/v2" not in shell.text and "/api/" not in shell.text
    assert lb.MAIN_BUNDLE in shell.text and lb.LAZY_CHUNK not in shell.text
    assert re.fullmatch(r"main\.[0-9a-f]{8}\.js", lb.MAIN_BUNDLE)
    assert re.fullmatch(r"chunk-board-share\.[0-9a-f]{8}\.js", lb.LAZY_CHUNK)
    main = anon.get(f"/static/js/{lb.MAIN_BUNDLE}").text
    chunk = anon.get(f"/static/js/{lb.LAZY_CHUNK}").text
    # History API routing, not hash routes; base comes from config.json at runtime
    assert "pushState" in main and "popstate" in main and "hashchange" not in main
    assert "/api/v2" not in main and "fetch('/static/config.json'" in main
    assert "'workspaces', slug, 'boards', boardId" in main
    # the export call lives only in the lazy chunk, loaded on the ⋯ menu interaction
    assert "'export'" in chunk and "export" not in main.lower()
    assert f"'board-share': '{lb.LAZY_CHUNK}'" in main and "loadChunk('board-share')" in main
    assert "'boards', boardId, 'export'" in chunk
    # unknown static and API paths do not fall through to the shell
    assert anon.get("/static/js/nope.js").status_code == 404
    assert anon.get("/api/v2/nope").json() == {"error": "not_found"}


def test_auth_session_and_csrf(url, users):
    anon = _client(url)
    assert anon.get("/api/v2/session").json() == {"authenticated": False, "csrfToken": None}
    assert anon.get("/api/v2/me").status_code == 401
    assert anon.post("/api/v2/session", json={"email": "maya@lumen.test",
                                              "password": "wrong"}).status_code == 401
    c = _client(url)
    r = c.post("/api/v2/session", json={"email": "maya@lumen.test",
                                        "password": "Maya-Lumen-7Qx!2026"})
    cookie = r.headers["set-cookie"].lower()
    assert "lumen_session=" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    # state-changing requests need the session-bound CSRF token (NC6)
    inv = "/api/v2/workspaces/northstar/invitations"
    assert c.post(inv, json={"email": "new@lumen.test"}).status_code == 403
    assert c.post(inv, json={"email": "new@lumen.test"},
                  headers={"X-CSRF-Token": "forged"}).status_code == 403
    assert c.delete("/api/v2/session").status_code == 403
    token = r.json()["csrfToken"]
    assert c.post(inv, json={"email": "new@lumen.test"},
                  headers={"X-CSRF-Token": token}).status_code == 201
    assert users["leo"].post(inv, json={"email": "x@lumen.test"}).status_code == 403  # member
    assert users["iris"].post(inv, json={"email": "x@lumen.test"}).status_code == 404
    assert c.delete("/api/v2/session", headers={"X-CSRF-Token": token}).status_code == 204
    assert c.get("/api/v2/me").status_code == 401


def test_browse_paginate_and_drawer(url, users):
    maya = users["maya"]
    assert [w["slug"] for w in maya.get("/api/v2/workspaces").json()["workspaces"]] == ["northstar"]
    base = "/api/v2/workspaces/northstar/boards/b7k2xq"
    page1 = maya.get(base + "/cards", params={"page": 1, "per_page": 10})
    body = page1.json()
    assert len(body["cards"]) == 10 and body["total"] == 14 and body["next"]
    assert 'rel="next"' in page1.headers["link"]
    page2 = maya.get(body["next"]).json()
    assert len(page2["cards"]) == 4 and page2["next"] is None
    assert maya.get(base + "/cards/4102").json()["comment_count"] == 2
    assert len(maya.get(base + "/cards/4102/comments").json()["comments"]) == 2
    assert maya.get(base + "/cards/4301").status_code == 404   # card from another board


def test_a1_source_map_exposes_internal_source(url):
    anon = _client(url)
    main = anon.get(f"/static/js/{lb.MAIN_BUNDLE}").text
    assert main.rstrip().endswith(f"//# sourceMappingURL={lb.MAIN_BUNDLE}.map")
    r = anon.get(f"/static/js/{lb.MAIN_BUNDLE}.map")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    sm = r.json()
    assert sm["version"] == 3 and sm["file"] == lb.MAIN_BUNDLE
    src = "\n".join(sm["sourcesContent"])
    assert 'INTERNAL_ADMIN_API = "https://admin-api.lumen.internal:8443"' in src
    assert "staffImpersonation" in src and "do not publish before GA" in src
    assert "lumen.internal" not in main and "staffImpersonation" not in main
    assert re.search(SEEDED["A1"]["match"]["location_regex"], f"{url}static/js/{lb.SOURCE_MAP}")


def test_a2_config_exposes_server_side_key(url):
    cfg = _client(url).get("/static/config.json").json()     # no session needed
    assert cfg["searchServiceAdminKey"].startswith("lmn_live_sk_")
    # public values (NC5) are present and intended
    assert cfg["apiBase"] == "/api/v2" and cfg["search"]["publicKey"].startswith("lmn_pub_pk_")
    assert re.fullmatch(r"https://[0-9a-f]+@errors\.lumen\.example/\d+", cfg["sentryDsn"])
    main = _client(url).get(f"/static/js/{lb.MAIN_BUNDLE}").text
    assert "searchServiceAdminKey" not in main


def test_a3_export_ignores_workspace_membership(url, users):
    maya, leo, iris = users["maya"], users["leo"], users["iris"]
    assert [w["slug"] for w in iris.get("/api/v2/workspaces").json()["workspaces"]] == ["quasar"]
    # northstar board ids are only learned as maya / leo
    seen = {b["id"] for b in leo.get("/api/v2/workspaces/northstar/boards").json()["boards"]}
    assert seen == set(NORTHSTAR_BOARDS)
    for board in NORTHSTAR_BOARDS:
        assert iris.get(f"/api/v2/workspaces/northstar/boards/{board}").status_code == 404
        mine = maya.get(f"/api/v2/boards/{board}/export", params={"format": "json"}).json()
        theirs = iris.get(f"/api/v2/boards/{board}/export", params={"format": "json"})
        assert theirs.status_code == 200
        assert theirs.json()["exported_by"] == "iris@lumen.test"
        assert theirs.json()["cards"] == mine["cards"]
    exported = iris.get("/api/v2/boards/m4p9wd/export", params={"format": "json"}).text
    assert "Offer approved at 142k" in exported
    csv_ = iris.get("/api/v2/boards/b7k2xq/export", params={"format": "csv"})
    assert csv_.headers["content-type"].startswith("text/csv") and "14 Oct" in csv_.text
    # authentication is still required, and unknown ids are 404
    assert _client(url).get("/api/v2/boards/m4p9wd/export").status_code == 401
    assert iris.get("/api/v2/boards/zzzzzz/export").status_code == 404


def test_nc1_nc2_workspace_endpoints_enforce_membership(url, users):
    maya, leo, iris = users["maya"], users["leo"], users["iris"]
    nested = ["/api/v2/workspaces/northstar", "/api/v2/workspaces/northstar/members",
              "/api/v2/workspaces/northstar/boards",
              "/api/v2/workspaces/northstar/boards/m4p9wd",
              "/api/v2/workspaces/northstar/boards/m4p9wd/members",
              "/api/v2/workspaces/northstar/boards/m4p9wd/cards",
              "/api/v2/workspaces/northstar/boards/m4p9wd/cards/4201",
              "/api/v2/workspaces/northstar/boards/m4p9wd/cards/4201/comments"]
    for path in nested:
        assert maya.get(path).status_code == 200 and leo.get(path).status_code == 200, path
        denied = iris.get(path)
        assert denied.status_code == 404 and denied.json() == {"error": "not_found"}, path
        assert re.search(NCS["NC1"]["false_positive_if"]["location_regex"], url + path[1:])
    # same 404 as an unknown workspace; a board cannot be read through the wrong tenant
    assert iris.get("/api/v2/workspaces/nope").json() == {"error": "not_found"}
    assert iris.get("/api/v2/workspaces/quasar/boards/b7k2xq").status_code == 404
    for label, c in users.items():
        me = c.get("/api/v2/me").json()
        assert me["email"] == f"{label}@lumen.test"
        assert c.get("/api/v2/notifications").status_code == 200


def test_nc3_nc4_headers_present_and_no_cors(url, users):
    anon = _client(url)
    for path in ["/", "/w/northstar", "/static/config.json", f"/static/js/{lb.MAIN_BUNDLE}",
                 "/api/v2/session", "/api/v2/nope"]:
        h = anon.get(path, headers={"Origin": "https://evil.example"}).headers
        assert "frame-ancestors 'none'" in h["content-security-policy"], path
        assert h["x-content-type-options"] == "nosniff" and h["referrer-policy"], path
        assert h["x-frame-options"] == "DENY" and "permissions-policy" in h, path
        assert "access-control-allow-origin" not in h, path
    r = users["maya"].get("/api/v2/me", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers
    assert "access-control-allow-credentials" not in r.headers
    pre = anon.options("/api/v2/me", headers={"Origin": "https://evil.example",
                                              "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in pre.headers


def _hits(rule, location, text):
    return bool(re.search(rule["location_regex"], location) and
                re.search(rule["text_regex"], text))


def test_manifest_regexes_separate_seeded_from_controls(url):
    m = f"{url}static/js/{lb.MAIN_BUNDLE}.map"
    cfg = f"{url}static/config.json"
    exp = f"{url}api/v2/boards/m4p9wd/export?format=json"
    findings = {
        "A1": (m, "Source map exposes original source and internal admin-api host"),
        "A2": (cfg, "Runtime config exposes searchServiceAdminKey (lmn_live_sk_...) to anonymous users"),
        "A3": (exp, "Board export readable by a user of another tenant (BOLA)"),
    }
    for sid, (loc, text) in findings.items():
        assert _hits(SEEDED[sid]["match"], loc, text), sid
        for nc in NCS.values():
            assert not _hits(nc["false_positive_if"], loc, text), (sid, nc["id"])
    false_positives = {
        "NC1": (f"{url}api/v2/workspaces/northstar/boards/m4p9wd/cards/4201",
                "Cross-tenant IDOR on cards"),
        "NC2": (f"{url}api/v2/me", "IDOR: profile readable by other user"),
        "NC3": (f"{url}", "Missing Content-Security-Policy header"),
        "NC4": (f"{url}api/v2/me", "Permissive CORS policy"),
        "NC5": (cfg, "Sentry DSN and public key exposed in config"),
        "NC6": (f"{url}api/v2/workspaces/northstar/invitations", "CSRF on invitations"),
    }
    for nid, (loc, text) in false_positives.items():
        assert _hits(NCS[nid]["false_positive_if"], loc, text), nid
        for s in SEEDED.values():
            assert not _hits(s["match"], loc, text), (nid, s["id"])


def test_assessment_is_generic_and_consistent():
    assert set(ASSESSMENT) >= {"name", "mode", "port", "objective", "accounts", "health_path"}
    assert ASSESSMENT["port"] == 18641 and ASSESSMENT["mode"] == GT["mode"] == "web"
    assert [(a["label"], a["user"], a["password"]) for a in ASSESSMENT["accounts"]] == \
        [(a["label"], a["user"], a["password"]) for a in GT["accounts"]]
    leaked = re.compile(r"(?i)export|source ?map|config|secret|key|tenant|chunk|admin|vuln")
    assert not leaked.search(ASSESSMENT["objective"])
