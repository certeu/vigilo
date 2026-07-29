"""Tests for the per-endpoint specialist cap (C4 / Slice 7).

Pure-function tests on ``specialists_for_endpoint``. End-to-end scheduler
wiring is covered in ``tests/greybox/test_scheduler_core.py``.
"""
from __future__ import annotations

import pytest

from src.greybox.scheduler.routing import (
    _SPECIALIST_PRIORITY,
    specialists_for_endpoint,
)


def test_free_text_attracts_three_specialists_before_cap():
    # Sanity: free_text's priority list is [reflection, injection, ssrf],
    # so uncapped routing returns all three.
    result = specialists_for_endpoint(["free_text"], cap=10)
    assert set(result) == {"reflection", "injection", "ssrf"}


def test_free_text_truncated_to_default_cap_of_two():
    result = specialists_for_endpoint(["free_text"], cap=2)
    assert len(result) == 2


def test_cap_honours_priority_order():
    # Among {reflection, injection, ssrf}, global priority is
    # (authorization, injection, reflection, ssrf, graphql, websocket) —
    # so within that set ordering is [injection, reflection, ssrf]. Cap=2
    # keeps injection and reflection.
    result = specialists_for_endpoint(["free_text"], cap=2)
    assert result == ["injection", "reflection"]


def test_cap_of_one_returns_top_priority_specialist():
    result = specialists_for_endpoint(["free_text"], cap=1)
    assert result == ["injection"]


def test_diverse_shapes_union_then_truncate():
    # numeric_id → {authorization, injection}; free_text adds
    # {reflection, injection, ssrf}. Union is
    # {authorization, injection, reflection, ssrf}; priority order keeps
    # authorization, injection within a cap of 2.
    result = specialists_for_endpoint(["numeric_id", "free_text"], cap=2)
    assert result == ["authorization", "injection"]


def test_cap_zero_returns_empty():
    result = specialists_for_endpoint(["free_text"], cap=0)
    assert result == []


def test_shape_with_no_matching_specialist():
    result = specialists_for_endpoint(["boolean"], cap=2)
    assert result == []


def test_specialist_priority_covers_all_vuln_types():
    # Guardrail: every vuln_type in VULN_SHAPE_AFFINITY must have a
    # priority slot so ordering is always deterministic.
    from src.greybox.scheduler.routing import VULN_SHAPE_AFFINITY
    for vuln_list in VULN_SHAPE_AFFINITY.values():
        for vuln_type in vuln_list:
            assert vuln_type in _SPECIALIST_PRIORITY


@pytest.mark.parametrize("cap", [-1, -5])
def test_negative_cap_returns_empty(cap):
    result = specialists_for_endpoint(["free_text"], cap=cap)
    assert result == []
