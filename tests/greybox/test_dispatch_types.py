"""Tests for specialist dispatch payload types."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.greybox.types.dispatch import BatchDispatch, DispatchPayload, LeadDispatch


def test_batch_dispatch_roundtrips():
    p = BatchDispatch(
        mode="batch",
        vuln_type="xss",
        identity="identity:anonymous",
        param_ids=["parameter:p1"],
    )
    serialized = p.model_dump()
    reloaded = BatchDispatch.model_validate(serialized)
    assert reloaded == p


def test_lead_dispatch_roundtrips():
    p = LeadDispatch(
        mode="lead",
        lead_id="lead:l1",
        identity="identity:anonymous",
    )
    serialized = p.model_dump()
    reloaded = LeadDispatch.model_validate(serialized)
    assert reloaded == p
    assert serialized["mode"] == "lead"


def test_dispatch_union_discriminated_by_mode_batch():
    obj = DispatchPayload.model_validate({
        "mode": "batch",
        "vuln_type": "xss",
        "identity": "identity:anonymous",
        "param_ids": ["parameter:p1"],
    })
    assert isinstance(obj.root, BatchDispatch)
    assert obj.root.vuln_type == "xss"


def test_dispatch_union_discriminated_by_mode_lead():
    obj = DispatchPayload.model_validate({
        "mode": "lead",
        "lead_id": "lead:l1",
        "identity": "identity:anonymous",
    })
    assert isinstance(obj.root, LeadDispatch)
    assert obj.root.lead_id == "lead:l1"


def test_dispatch_rejects_unknown_mode():
    with pytest.raises(ValidationError):
        DispatchPayload.model_validate({"mode": "mystery", "identity": "identity:anonymous"})


def test_batch_dispatch_requires_vuln_type():
    with pytest.raises(ValidationError):
        BatchDispatch.model_validate({
            "mode": "batch",
            "identity": "identity:anonymous",
            "param_ids": [],
        })


def test_lead_dispatch_requires_lead_id():
    with pytest.raises(ValidationError):
        LeadDispatch.model_validate({"mode": "lead", "identity": "identity:anonymous"})
