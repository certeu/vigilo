"""Security relationship model — pure layer (no database)."""
from __future__ import annotations

import pytest

from src.greybox_web import secmodel as sm


def test_interfaces_from_path_shapes():
    i = sm.interface_of("/api/documents/7c1e2a90-4f6b-4d1a-9b8e-2f0c3d4e5a61")
    assert (i.template, i.resource_type, i.kind) == ("/api/documents/{id}",
                                                     "documents", "detail")
    i = sm.interface_of("/api/documents")
    assert (i.resource_type, i.kind) == ("documents", "list")
    i = sm.interface_of("/v1/orgs/org_7Hq2/invoices/inv_8KQ2x9")
    assert (i.template, i.resource_type, i.parents) == (
        "/v1/orgs/{id}/invoices/{id}", "invoices", ("orgs",))
    i = sm.interface_of("/api/documents/d-b25d07/versions/2")
    assert (i.resource_type, i.kind, i.parents) == ("versions", "detail",
                                                    ("documents",))
    # a nested instance is identified with its parents' ids
    assert sm.instance_of("/api/documents/d-b25d07/versions/2", i) == "d-b25d07/2"
    assert sm.interface_of("/") is None


def test_slug_ids_need_evidence_that_the_app_returned_them():
    # "atlas" is not id-shaped: a literal segment until the application itself
    # returned it as an identifier
    assert sm.interface_of("/api/projects/atlas").template == "/api/projects/atlas"
    known = sm.ids_in_body('{"projects": [{"id": "atlas", "name": "Atlas"}]}')
    assert known == {"atlas"}
    i = sm.interface_of("/api/projects/atlas", known)
    assert (i.template, i.kind) == ("/api/projects/{id}", "detail")
    sub = sm.interface_of("/api/v2/boards/b7k2xq/export", {"b7k2xq"})
    assert (sub.resource_type, sub.kind, sub.sub) == ("boards", "sub", "export")
    assert sm.instance_of("/api/v2/boards/b7k2xq/export", sub) == "b7k2xq"


def test_outcomes():
    assert sm.outcome_of(200) == "allow"
    assert sm.outcome_of(403) == "deny" and sm.outcome_of(401) == "deny"
    assert sm.outcome_of(404) == "missing"
    assert sm.outcome_of(500) == "error" and sm.outcome_of(None) == "error"


def _row(i, url, ident, status, method="GET"):
    return {"id": i, "url": "http://t" + url, "method": method,
            "status_code": status, "identity": ident, "tool": "t"}


def test_observations_keep_provenance_and_skip_unattributed():
    rows = [_row(1, "/api/documents/d-a71f30", "dave", 200),
            _row(2, "/api/documents/d-a71f30", None, 200),          # unattributed
            _row(3, "/api/documents/d-a71f30", "browser-session", 200),
            {**_row(4, "/api/documents/d-a71f30", "dave", None), "blocked": True}]
    obs = sm.observe(rows, {"dave", "anon"})
    assert len(obs) == 1
    o = obs[0]
    assert (o.identity, o.instance, o.outcome, o.operation, o.ref()) == (
        "dave", "d-a71f30", "allow", "read", "exchange:1")


def test_inconsistent_boundary_needs_the_same_instance():
    known = {"b7k2xq", "m4p9wd"}
    rows = [_row(1, "/api/v2/workspaces/northstar/boards/m4p9wd", "iris", 404),
            _row(2, "/api/v2/boards/m4p9wd/export", "iris", 200),
            # a different board served elsewhere does not pair with m4p9wd
            _row(3, "/api/v2/boards/b7k2xq/export", "maya", 200),
            _row(4, "/api/v2/workspaces/northstar/boards/b7k2xq", "iris", 404)]
    sig = sm.correlate(sm.observe(rows, {"iris", "maya"}, known | {"northstar"}))
    assert [s.instance for s in sig] == ["m4p9wd"]
    s = sig[0]
    assert s.kind == "inconsistent_boundary" and s.identity == "iris"
    assert set(s.evidence) == {"exchange:1", "exchange:2"}
    assert s.status == "unverified"


def test_a_refusal_then_a_grant_on_the_same_interface_is_not_a_signal():
    rows = [_row(1, "/api/documents/d-1x", "dave", 403),
            _row(2, "/api/documents/d-1x", "dave", 200)]
    assert sm.correlate(sm.observe(rows, {"dave"})) == []


def test_expectations_unknown_produce_nothing_established_ones_are_checked():
    rows = [_row(1, "/v1/orgs/org_7Hq2/audit-events", "omar", 200)]
    obs = sm.observe(rows, {"omar"})
    assert sm.correlate(obs) == []                         # no expectation: no signal
    exp = sm.Expectation(sm.EntityRef("role", "viewer"), "list",
                         sm.EntityRef("resource_type", "audit-events"), "deny",
                         "documented", ("openapi x-required-role",))
    sig = sm.correlate(obs, [exp], roles={"omar": "viewer"})
    assert sig and sig[0].kind == "contradicts_expectation"
    assert sig[0].evidence == ("exchange:1",)


def test_declarations_are_validated_not_trusted():
    d = sm.clean({
        "entities": [{"kind": "identity", "name": "Dave", "attributes": {"role": "member"}},
                     {"kind": "spaceship", "name": "x"}],
        "relations": [{"src": {"kind": "identity", "name": "dave"}, "rel": "member_of",
                       "dst": {"kind": "resource", "name": "atlas"}, "basis": "observed_ui",
                       "evidence": ["/api/me"]},
                      {"src": {"kind": "role", "name": "x"}, "rel": "owns",
                       "dst": {"kind": "resource", "name": "y"}}],
        "expectations": [{"subject": {"kind": "identity", "name": "dave"},
                          "operation": "read", "resource": {"kind": "resource",
                                                            "name": "cobalt"},
                          "expected": "deny", "basis": "observed_ui"},
                         {"subject": {"kind": "identity", "name": "dave"},
                          "operation": "read", "resource": {"kind": "resource",
                                                            "name": "c"},
                          "expected": "maybe", "basis": "stated"}]})
    assert [e[0].key for e in d.entities] == ["identity:dave"]
    assert len(d.relations) == 1 and d.relations[0].rel == "member_of"
    assert len(d.expectations) == 1 and d.expectations[0].expected == "deny"
    assert len(d.notes) == 3
    assert sm.clean("nonsense").empty()


def test_relation_vocabulary_is_enforced():
    with pytest.raises(sm.ModelError):
        sm.Relation(sm.EntityRef("identity", "a"), "owns",
                    sm.EntityRef("role", "b"))


def test_rendered_pages_are_not_access_observations():
    rows = [{**_row(1, "/documents/d-1x", "dave", 200), "content_type": "text/html"},
            {**_row(2, "/api/documents/d-1x", "dave", 404),
             "content_type": "application/json"},
            # a refusal page still says "refused"
            {**_row(3, "/documents/d-2x", "dave", 403), "content_type": "text/html"}]
    obs = sm.observe(rows, {"dave"})
    assert [(o.exchange_id, o.outcome) for o in obs] == [(2, "missing"), (3, "deny")]
    assert sm.correlate(obs) == []


def test_nested_numeric_ids_do_not_collide_across_parents():
    rows = [_row(1, "/api/documents/d-a71f30/versions/2", "erin", 404),
            _row(2, "/api/documents/d-c30a77/versions/2", "erin", 200)]
    assert sm.correlate(sm.observe(rows, {"erin"})) == []
