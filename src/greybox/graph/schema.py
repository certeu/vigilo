"""Pydantic models for all knowledge graph node and edge types.

Maps directly to the ontology in design doc Sections 3.2-3.3.
SurrealDB table names are lowercase versions of the node type
(e.g., EndpointNode -> endpoint table).
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_payload(payload: str) -> str:
    return f"sha256:{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


# ---------------------------------------------------------------------------
# Schema version ratchet
# ---------------------------------------------------------------------------
# Bumped whenever any table/field definition changes in a way that is not
# backward-compatible with existing data. ``init_schema.ensure_schema`` reads
# the ``_schema_meta`` row and raises ``SchemaVersionMismatchError`` when the
# database version differs — grey-box has no migrations, the operator must
# wipe the database and re-scan.
SCHEMA_VERSION: int = 3

SCHEMA_META_DDL: str = """
DEFINE TABLE IF NOT EXISTS _schema_meta SCHEMAFULL;
DEFINE FIELD version ON _schema_meta TYPE int;
DEFINE FIELD created_at ON _schema_meta TYPE datetime;
"""


# ---------------------------------------------------------------------------
# Shared literals
# ---------------------------------------------------------------------------


Shape = Literal[
    "numeric_id", "uuid", "email", "url",
    "free_text", "json", "enum", "boolean",
]


# ---------------------------------------------------------------------------
# Node types (10 total)
# ---------------------------------------------------------------------------


class PageNode(BaseModel):
    url: str
    title: str | None = None
    status_code: int = 200
    content_type: str = "text/html"
    crawl_depth: int = 0
    content_signature: str | None = None
    discovered_by: str
    discovered_at: datetime = Field(default_factory=_now)
    auth_required: bool = False


class EndpointNode(BaseModel):
    method: str
    path: str
    full_url: str
    content_type: str | None = None
    response_headers: dict[str, str | None] | None = None
    status_codes_seen: list[int] = Field(default_factory=list)
    discovered_by: str
    discovered_at: datetime = Field(default_factory=_now)
    rate_limited: bool = False
    requires_auth: bool = True


class ParameterNode(BaseModel):
    name: str
    location: Literal["query", "body", "header", "cookie", "path"]
    data_type: str = "string"
    shape: Shape = "free_text"
    example_value: str | None = None
    constraints: str | None = None
    injectable: Literal["untested", "yes", "no"] = "untested"
    sanitized: Literal["unknown", "yes", "partial", "no"] = "unknown"
    discovered_by: str
    discovered_at: datetime = Field(default_factory=_now)


class TechnologyNode(BaseModel):
    name: str
    version: str | None = None
    category: Literal["framework", "library", "server", "database", "cms", "language"]
    confidence: Literal["detected", "confirmed"] = "detected"
    source: str = "header"
    discovered_by: str
    discovered_at: datetime = Field(default_factory=_now)


class IdentityNode(BaseModel):
    role: str
    privilege_level: int = 0
    auth_method: str = "session_cookie"
    credential_ref: str  # pointer to config, NOT actual credentials
    session_active: bool = True
    discovered_by: str = "preflight"
    discovered_at: datetime = Field(default_factory=_now)


class WorkflowNode(BaseModel):
    name: str
    description: str = ""
    step_count: int = 0
    discovered_by: str
    discovered_at: datetime = Field(default_factory=_now)


class ComponentNode(BaseModel):
    name: str
    description: str = ""
    path_pattern: str = ""
    requires_role: str | None = None
    discovered_by: str
    discovered_at: datetime = Field(default_factory=_now)


class TestAttemptNode(BaseModel):
    vuln_type: str
    technique: str
    payload: str
    payload_hash: str = ""
    verdict: Literal[
        "conclusive_vulnerable",
        "conclusive_clean",
        "inconclusive",
        "failed",
    ]
    failure_reason: str | None = None
    error_class: str | None = None
    response_code: int = 0
    response_excerpt: str | None = None
    duration_ms: int = 0
    agent: str
    attempted_at: datetime = Field(default_factory=_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.payload_hash:
            self.payload_hash = _hash_payload(self.payload)

    @model_validator(mode="after")
    def _failure_reason_required_when_failed(self) -> "TestAttemptNode":
        if self.verdict == "failed" and self.failure_reason is None:
            raise ValueError(
                "failure_reason is required when verdict is 'failed'"
            )
        return self


class FindingNode(BaseModel):
    title: str
    vuln_type: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    status: Literal["confirmed", "potential", "lead_promoted", "invalidated"] = "confirmed"
    cwe_id: str | None = None
    cvss_estimate: float | None = None
    confidence: Literal["high", "medium", "low"] = "high"
    evidence_ref: str | None = None
    poc_payload: str | None = None
    impact: str
    discovered_by: str
    confirmed_by: str | None = None
    grants: list[str] = Field(default_factory=list)
    requires: list[str] = Field(default_factory=list)
    # Detection engineering hints. Specialists populate one or more of:
    #   waf_rule          — ModSecurity / Coraza rule snippet
    #   log_signature     — regex/grep pattern matching the attack in app/web logs
    #   siem_query        — KQL/SPL/Lucene query for SIEM dashboards
    #   network_indicator — host/path/User-Agent string an IDS/proxy can match
    # Used by the report generator to build the Detection Engineering Appendix.
    detection_hints: dict[str, str] | None = None
    discovered_at: datetime = Field(default_factory=_now)


class LeadNode(BaseModel):
    signal: str
    hypothesis: str
    signal_strength: Literal["low", "medium", "high"] = "medium"
    investigation_hints: list[str] = Field(default_factory=list)
    status: Literal["open", "investigating", "dismissed", "promoted"] = "open"
    investigation_attempts: int = 0
    max_attempts: int = 3
    assigned_to: str | None = None
    evidence_blob_path: str | None = None
    discovered_by: str
    discovered_at: datetime = Field(default_factory=_now)


# Registry
ALL_NODE_TYPES: list[type[BaseModel]] = [
    PageNode, EndpointNode, ParameterNode, TechnologyNode,
    IdentityNode, WorkflowNode, ComponentNode,
    TestAttemptNode, FindingNode, LeadNode,
]

NODE_TYPE_MAP: dict[str, type[BaseModel]] = {
    "page": PageNode,
    "endpoint": EndpointNode,
    "parameter": ParameterNode,
    "technology": TechnologyNode,
    "identity": IdentityNode,
    "workflow": WorkflowNode,
    "component": ComponentNode,
    "test_attempt": TestAttemptNode,
    "finding": FindingNode,
    "lead": LeadNode,
}


# ---------------------------------------------------------------------------
# Edge types (21 total) — E22: corrected count
# ---------------------------------------------------------------------------

# E20: broadened targets where design allows multiple types
EDGE_TYPES: dict[str, dict[str, str | list[str]]] = {
    # Structural
    "links_to": {"from": "page", "to": "page"},
    "has_endpoint": {"from": "page", "to": "endpoint"},
    "has_param": {"from": "endpoint", "to": "parameter"},
    "input_of": {"from": "parameter", "to": "endpoint"},  # inverse of has_param for planner traversal
    "belongs_to": {"from": ["endpoint", "page"], "to": "component"},
    "detected_on": {"from": "technology", "to": ["endpoint", "page"]},
    "has_step": {"from": "workflow", "to": "endpoint"},
    "depends_on": {"from": "endpoint", "to": "endpoint"},
    "param_depends_on": {"from": "parameter", "to": "parameter"},
    # Access control
    "can_access": {"from": "identity", "to": "endpoint"},
    "denied_access": {"from": "identity", "to": "endpoint"},
    # Testing
    "tested_against": {"from": "test_attempt", "to": ["endpoint", "parameter"]},
    "exploits": {"from": "finding", "to": ["endpoint", "parameter"]},
    "observed_at": {"from": "lead", "to": ["endpoint", "parameter"]},
    # Finding lifecycle
    "promoted_to": {"from": "lead", "to": "finding"},
    "supersedes": {"from": "finding", "to": "finding"},
    "chains_with": {"from": "finding", "to": "finding"},
    # Discovery/enrichment edges
    "reflects_in": {"from": "parameter", "to": "endpoint"},
    "produced_from": {"from": "lead", "to": "test_attempt"},
    "data_flows_to": {"from": "parameter", "to": "technology"},
    "derived_from": {"from": "finding", "to": "test_attempt"},
}
