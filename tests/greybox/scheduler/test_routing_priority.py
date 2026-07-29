"""Tests for inverted VULN_SHAPE_AFFINITY — priority list per shape.

Task 14.1: ``VULN_SHAPE_AFFINITY`` flips from ``{vuln_type: [shapes]}`` to
``{shape: [vuln_types]}`` so each shape carries an explicit priority list
of candidate specialists.
"""
from __future__ import annotations

from src.greybox.scheduler import routing
from src.greybox.types.agents import VULN_TYPES


def test_vuln_types_tuple_contents():
    assert VULN_TYPES == (
        "authorization",
        "injection",
        "reflection",
        "ssrf",
        "graphql",
        "websocket",
    )


def test_numeric_id_affinity():
    assert routing.VULN_SHAPE_AFFINITY["numeric_id"] == ["authorization", "injection"]


def test_uuid_affinity():
    assert routing.VULN_SHAPE_AFFINITY["uuid"] == ["authorization"]


def test_email_affinity():
    assert routing.VULN_SHAPE_AFFINITY["email"] == ["injection"]


def test_url_affinity():
    assert routing.VULN_SHAPE_AFFINITY["url"] == ["ssrf", "reflection"]


def test_free_text_affinity():
    assert routing.VULN_SHAPE_AFFINITY["free_text"] == ["reflection", "injection", "ssrf"]


def test_json_affinity():
    assert routing.VULN_SHAPE_AFFINITY["json"] == ["injection", "reflection"]


def test_enum_affinity_empty():
    assert routing.VULN_SHAPE_AFFINITY["enum"] == []


def test_boolean_affinity_empty():
    assert routing.VULN_SHAPE_AFFINITY["boolean"] == []


def test_priority_order_preserved_cap_one():
    assert routing.specialists_for_shape("numeric_id", cap=1) == ["authorization"]


def test_priority_order_url_cap_one():
    assert routing.specialists_for_shape("url", cap=1) == ["ssrf"]


def test_specialists_for_shape_cap_truncation():
    assert routing.specialists_for_shape("free_text", cap=2) == ["reflection", "injection"]


def test_specialists_for_shape_zero_cap():
    assert routing.specialists_for_shape("free_text", cap=0) == []


def test_specialists_for_shape_unknown_shape():
    assert routing.specialists_for_shape("not_a_shape", cap=5) == []  # type: ignore[arg-type]


def test_every_vuln_in_affinity_is_known():
    """Guardrail: every vuln_type appearing in any priority list must be a
    member of the new ``VULN_TYPES`` tuple.
    """
    known = set(VULN_TYPES)
    for shape, vuln_list in routing.VULN_SHAPE_AFFINITY.items():
        for vuln_type in vuln_list:
            assert vuln_type in known, (
                f"shape={shape!r} references unknown vuln_type={vuln_type!r}"
            )
