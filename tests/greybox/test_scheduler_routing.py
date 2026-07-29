from __future__ import annotations

from src.greybox.scheduler.routing import shapes_for_vuln


def test_injection_shapes():
    # After the inversion, injection appears in the priority list for
    # numeric_id, email, free_text, and json.
    assert set(shapes_for_vuln("injection")) == {
        "numeric_id", "free_text", "json", "email",
    }


def test_reflection_shapes():
    # reflection attracts free_text, url, json (HTML/attribute/JS/URL
    # reflection contexts).
    assert set(shapes_for_vuln("reflection")) == {"free_text", "url", "json"}


def test_ssrf_shapes():
    assert set(shapes_for_vuln("ssrf")) == {"url", "free_text"}


def test_authorization_shapes():
    # authorization attracts identifier-shaped params (numeric_id, uuid).
    assert set(shapes_for_vuln("authorization")) == {"uuid", "numeric_id"}


def test_endpoint_level_vuln_types_map_to_empty():
    # graphql and websocket are endpoint-level and dispatched without
    # per-shape routing.
    for vuln in ("graphql", "websocket"):
        assert shapes_for_vuln(vuln) == []


def test_unknown_vuln_returns_empty():
    assert shapes_for_vuln("not_a_vuln_type") == []
