"""Tests for graph node/edge Pydantic models."""
from __future__ import annotations

from datetime import datetime, timezone


def test_endpoint_node_defaults():
    from src.greybox.graph.schema import EndpointNode
    ep = EndpointNode(
        method="GET", path="/api/users", full_url="http://t.local/api/users",
        discovered_by="discovery",
    )
    assert ep.rate_limited is False
    assert ep.requires_auth is True
    assert ep.status_codes_seen == []
    assert ep.response_headers is None


def test_parameter_node_injectable_states():
    from src.greybox.graph.schema import ParameterNode
    p = ParameterNode(
        name="q", location="query", data_type="string",
        discovered_by="discovery",
    )
    assert p.injectable == "untested"
    assert p.sanitized == "unknown"


def test_parameter_location_validation():
    import pytest
    from pydantic import ValidationError
    from src.greybox.graph.schema import ParameterNode
    with pytest.raises(ValidationError):
        ParameterNode(
            name="q", location="invalid_place", data_type="string",
            discovered_by="discovery",
        )


def test_finding_node_grants_requires():
    from src.greybox.graph.schema import FindingNode
    f = FindingNode(
        title="SQLi in search",
        vuln_type="sqli",
        severity="high",
        status="confirmed",
        confidence="high",
        impact="DB read access",
        discovered_by="injection-specialist",
        grants=["db_read", "credential_access"],
        requires=["authenticated"],
    )
    assert f.grants == ["db_read", "credential_access"]
    assert f.confirmed_by is None


def test_lead_node_defaults():
    from src.greybox.graph.schema import LeadNode
    lead = LeadNode(
        signal="timing_anomaly",
        hypothesis="Possible blind SQLi",
        signal_strength="medium",
        discovered_by="injection-specialist",
    )
    assert lead.status == "open"
    assert lead.investigation_attempts == 0
    assert lead.max_attempts == 3


def test_test_attempt_node():
    from src.greybox.graph.schema import TestAttemptNode
    ta = TestAttemptNode(
        vuln_type="sqli",
        technique="union_based",
        payload="' UNION SELECT NULL--",
        verdict="conclusive_vulnerable",
        response_code=200,
        duration_ms=234,
        agent="injection-specialist",
    )
    assert ta.payload_hash
    assert ta.error_class is None
    assert ta.failure_reason is None


def test_all_node_types_registered():
    from src.greybox.graph.schema import ALL_NODE_TYPES
    assert len(ALL_NODE_TYPES) == 10
    names = {n.__name__ for n in ALL_NODE_TYPES}
    assert "EndpointNode" in names
    assert "FindingNode" in names
    assert "LeadNode" in names


def test_edge_types():
    from src.greybox.graph.schema import EDGE_TYPES
    assert "links_to" in EDGE_TYPES
    assert "has_param" in EDGE_TYPES
    assert "tested_against" in EDGE_TYPES
    assert "chains_with" in EDGE_TYPES
    assert "param_depends_on" in EDGE_TYPES
    assert len(EDGE_TYPES) == 21  # 16 base + 4 discovery enrichments + input_of
