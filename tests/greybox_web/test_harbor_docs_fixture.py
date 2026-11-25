"""The Harbor Docs evaluation fixture behaves exactly as its ground truth says.

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

from tests.greybox_web.fixtures import harbor_docs

HERE = Path(harbor_docs.__file__).parent
GT = json.loads((HERE / "ground_truth.json").read_text())
ASSESSMENT = json.loads((HERE / "assessment.json").read_text())


@pytest.fixture(scope="module")
def harbor():
    server, url = harbor_docs.serve(0)
    yield url
    server.should_exit = True


def _client(url):
    return httpx.Client(base_url=url, trust_env=False)


def _login(url, user, form=False):
    pw = next(a for a in GT["accounts"] if a["user"] == user)["password"]
    c = _client(url)
    if form:
        r = c.post("/login", data={"username": user, "password": pw})
        assert r.status_code == 303 and r.headers["location"] == "/dashboard"
    else:
        r = c.post("/api/login", json={"username": user, "password": pw})
        assert r.status_code == 200
    c.headers["X-CSRF-Token"] = c.get("/api/me").json()["csrf_token"]
    return c


def test_manifests_are_consistent():
    assert {a["user"] for a in ASSESSMENT["accounts"]} == {a["user"] for a in GT["accounts"]}
    for a in ASSESSMENT["accounts"]:
        assert a["password"] == next(g for g in GT["accounts"]
                                     if g["user"] == a["user"])["password"]
    # the agent-facing objective never hints at the seeded conditions
    obj = ASSESSMENT["objective"].lower()
    for word in ("cobalt", "atlas", "draft", "removed", "former", "feed", "layoff", "stale"):
        assert word not in obj
    # seeded matchers are distinct from each other and compile
    locs = {s["id"]: re.compile(s["match"]["location_regex"]) for s in GT["seeded"]}
    texts = {s["id"]: re.compile(s["match"]["text_regex"]) for s in GT["seeded"]}
    for nc in GT["negative_controls"]:
        re.compile(nc["false_positive_if"]["location_regex"])
        re.compile(nc["false_positive_if"]["text_regex"])
    samples = {"C1": "/api/teams/meridian/activity",
               "C2": "/api/documents/d-b25d07/versions/2",
               "C3": "/api/documents/d-a71f30"}
    for cid, url in samples.items():
        assert [k for k, rx in locs.items() if rx.search(url)] == [cid]
    assert texts["C3"].search("Former member still reads documents after removal")
    nc3 = next(n for n in GT["negative_controls"] if n["id"] == "NC3")
    t = re.compile(nc3["false_positive_if"]["text_regex"])
    assert t.search("Draft readable by non-author")
    assert not t.search("Removed member reads draft-era documents")


def test_pages_are_navigable(harbor):
    anon = _client(harbor)
    assert anon.get("/").headers["location"] == "/login"
    assert anon.get("/dashboard").status_code == 303
    assert anon.get("/api/me").status_code == 401
    assert 'name="username"' in anon.get("/login").text
    dave = _login(harbor, "dave", form=True)
    dash = dave.get("/dashboard").text
    assert 'href="/projects/beacon"' in dash and 'href="/documents/d-a71f30"' in dash
    beacon = dave.get("/projects/beacon").text
    assert "Beacon — 2027 roadmap" in beacon and 'href="/documents/d-b25d07"' not in beacon
    assert dave.get("/projects/cobalt").status_code == 403
    doc = dave.get("/documents/d-b2e641").text
    assert "/static/document.js" in doc
    assert "/api/documents/" in dave.get("/static/document.js").text
    assert "removed" in dave.get("/profile").text.lower() or "2026-11-16" in dave.get("/profile").text
    act = dave.get("/static/activity.js").text
    assert "/api/teams/" in act and "filter" in act
    assert 'name="csrf-token"' in dave.get("/approvals").text
    erin = _login(harbor, "erin")
    page = erin.get("/approvals").text
    assert "/api/approvals/apr-5c21/decision" in page and 'name="csrf_token"' in page


def test_seeded_c1_activity_feed_leaks_private_project(harbor):
    dave = _login(harbor, "dave")
    assert "cobalt" not in {p["id"] for p in dave.get("/api/projects").json()["projects"]}
    assert dave.get("/api/projects/cobalt").status_code == 403
    events = dave.get("/api/teams/meridian/activity").json()["events"]
    cobalt = [e for e in events if e["project"] == "cobalt"]
    titles = {e["document_title"] for e in cobalt}
    assert "Cobalt — layoffs scenario Q3" in titles
    assert {e["actor"] for e in cobalt} >= {"finn"}
    # the leaked ids are real, but the document itself is (correctly) denied
    assert dave.get("/api/documents/d-c3f812").status_code == 403
    assert dave.get("/api/teams/other/activity").status_code == 404


def test_seeded_c2_draft_through_versions(harbor):
    dave, erin = _login(harbor, "dave"), _login(harbor, "erin")
    listed = {d["id"]: d for d in dave.get("/api/projects/beacon/documents").json()["documents"]}
    assert listed["d-b25d07"]["state"] == "draft" and "content" not in listed["d-b25d07"]
    assert dave.get("/api/documents/d-b25d07").status_code == 404      # protected
    assert erin.get("/api/documents/d-b25d07").status_code == 200      # author
    vs = dave.get("/api/documents/d-b25d07/versions")
    assert vs.status_code == 200 and len(vs.json()["versions"]) == 2
    v2 = dave.get("/api/documents/d-b25d07/versions/2")
    assert v2.status_code == 200 and "Harbor Classic" in v2.json()["content"]
    finn = _login(harbor, "finn")
    assert finn.get("/api/documents/d-b25d07/versions/1").status_code == 200
    # a draft of a project the caller is not in stays hidden on every interface
    assert erin.get("/api/documents/d-c30a77/versions").status_code == 404
    assert dave.get("/api/documents/d-c30a77/versions").status_code == 404


def test_seeded_c3_removed_member_keeps_document_access(harbor):
    dave, finn = _login(harbor, "dave"), _login(harbor, "finn")
    atlas = next(m for m in dave.get("/api/me").json()["memberships"]
                 if m["project"] == "atlas")
    assert atlas["removed_at"] and atlas["status"] == "removed"
    recent = dave.get("/api/me/recent").json()["recent"]
    assert any(r["document"] == "d-a71f30" and r["viewed_at"] < atlas["removed_at"]
               for r in recent)
    assert dave.get("/api/projects/atlas").status_code == 403
    assert dave.get("/api/projects/atlas/documents").status_code == 403
    assert "atlas" not in {p["id"] for p in dave.get("/api/projects").json()["projects"]}
    r = dave.get("/api/documents/d-a71f30")
    assert r.status_code == 200 and "1.42M" in r.json()["content"]
    assert dave.get("/api/documents/d-a79e15").status_code == 200   # created after removal
    # controls: never-member finn is denied; the versions interface checks current membership
    assert finn.get("/api/documents/d-a71f30").status_code == 403
    assert dave.get("/api/documents/d-a71f30/versions").status_code == 403
    assert dave.get("/api/documents/d-a71f30/shares").status_code == 403


def test_negative_controls(harbor):
    anon = _client(harbor)
    dave, erin, finn = (_login(harbor, u) for u in ("dave", "erin", "finn"))
    # NC1 project endpoints
    for path in ("/api/projects/cobalt", "/api/projects/cobalt/documents",
                 "/api/projects/cobalt/members", "/api/projects/atlas/members"):
        assert dave.get(path).status_code == 403
    assert finn.get("/api/projects/atlas").status_code == 403
    assert erin.get("/api/projects/cobalt").status_code == 200       # approver
    members = {m["user"] for m in erin.get("/api/projects/atlas/members").json()["members"]}
    assert members == {"erin"}
    # NC2 cobalt documents
    assert dave.get("/api/documents/d-c3f812").status_code == 403
    assert dave.get("/api/documents/d-c3f812/versions/1").status_code == 403
    # NC3 drafts on the protected interface
    assert finn.get("/api/documents/d-b25d07").status_code == 404
    assert erin.get("/api/documents/d-c30a77").status_code == 404
    # NC4 share links
    shares = finn.get("/api/documents/d-b2e641/shares").json()["shares"]
    expired = next(s for s in shares if s.get("status") == "expired")
    assert anon.get(expired["url"]).status_code == 410
    assert anon.get("/s/does-not-exist").status_code == 404
    erin_shares = erin.get("/api/documents/d-a71f30/shares").json()["shares"]
    valid = next(s for s in erin_shares if s.get("status") == "active")
    assert anon.get(valid["url"]).status_code == 200
    # NC5/NC6 approvals
    assert dave.get("/api/approvals").json()["approvals"] == []
    assert {a["id"] for a in erin.get("/api/approvals").json()["approvals"]} == {
        "apr-5c21", "apr-9e47"}
    assert dave.get("/api/approvals/apr-9e47").status_code == 403
    assert dave.get("/api/approvals/apr-5c21").status_code == 200   # his own request
    r = dave.post("/api/approvals/apr-5c21/decision", json={"decision": "approve"})
    assert r.status_code == 403 and "approver" in r.json()["error"]
    no_csrf = _client(harbor)
    no_csrf.cookies = erin.cookies
    assert no_csrf.post("/api/approvals/apr-5c21/decision",
                        json={"decision": "approve"}).status_code == 403
    assert erin.post("/api/approvals/apr-5c21/decision",
                     json={"decision": "maybe"}).status_code == 400
    assert anon.post("/api/approvals/apr-5c21/decision").status_code == 401
    # NC7 ownership transfer
    r = finn.post("/api/documents/d-b2981a/transfer", json={"to": "finn"})
    assert r.status_code == 403
    assert dave.post("/api/documents/d-b2981a/transfer",
                     json={"to": "nobody"}).status_code == 400
    # NC9-NC11 headers, cookie, CORS
    for resp in (anon.get("/login"), dave.get("/api/me", headers={"Origin": "https://evil.example"}),
                 anon.get("/api/me")):
        assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["referrer-policy"] == "same-origin"
        assert "access-control-allow-origin" not in resp.headers
    pre = anon.options("/api/me", headers={"Origin": "https://evil.example",
                                           "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in pre.headers
    pw = next(a for a in GT["accounts"] if a["user"] == "finn")["password"]
    cookie = anon.post("/api/login", json={"username": "finn", "password": pw}
                       ).headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert anon.post("/api/login", json={"username": "finn", "password": "x"}).status_code == 401
    # seeded state was not changed by the controls above
    assert erin.get("/api/approvals/apr-5c21").json()["status"] == "pending"
    assert erin.get("/api/documents/d-b2981a").json()["author"] == "dave"


def test_state_changes_work_for_the_right_role():
    """On a private instance: an approver decision and a lead transfer succeed."""
    server, url = harbor_docs.serve(0)
    try:
        erin = _login(url, "erin")
        r = erin.post("/api/approvals/apr-5c21/decision",
                      json={"decision": "approve", "comment": "ok"})
        assert r.status_code == 200 and r.json()["status"] == "approved"
        assert erin.post("/api/approvals/apr-5c21/decision",
                         json={"decision": "approve"}).status_code == 409
        r = erin.post("/api/documents/d-b2981a/transfer", json={"to": "finn"})
        assert r.status_code == 200 and r.json()["author"] == "finn"
    finally:
        server.should_exit = True
