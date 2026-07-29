"""Agent type definitions for the Shannon Python pipeline.

Defines the 19-agent inventory, vulnerability types, model tiers, phases,
and agent definitions. Extended from Shannon's 13-agent TypeScript pipeline
with GraphQL, WebSocket, Crypto, and Remediation agents.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Agent names — single source of truth. All 19 agents in execution order.
# ---------------------------------------------------------------------------

AgentName = Literal[
    "pre-recon",
    "recon",
    "sca",
    "integrity",
    "injection-vuln",
    "xss-vuln",
    "auth-vuln",
    "ssrf-vuln",
    "authz-vuln",
    "graphql-vuln",
    "websocket-vuln",
    "crypto-vuln",
    "injection-exploit",
    "xss-exploit",
    "auth-exploit",
    "ssrf-exploit",
    "authz-exploit",
    "graphql-exploit",
    "websocket-exploit",
    "chain-exploit",
    "report-critic",
    "report",
    "remediation",
]

ALL_AGENTS: list[AgentName] = [
    "pre-recon",
    "recon",
    "sca",
    "integrity",
    "injection-vuln",
    "xss-vuln",
    "auth-vuln",
    "ssrf-vuln",
    "authz-vuln",
    "graphql-vuln",
    "websocket-vuln",
    "crypto-vuln",
    "injection-exploit",
    "xss-exploit",
    "auth-exploit",
    "ssrf-exploit",
    "authz-exploit",
    "graphql-exploit",
    "websocket-exploit",
    "chain-exploit",
    "report-critic",
    "report",
    "remediation",
]


# ---------------------------------------------------------------------------
# Vulnerability types — 8 total (Shannon had 5, plus graphql/websocket/crypto)
# ---------------------------------------------------------------------------

VulnType = Literal[
    "injection",
    "xss",
    "auth",
    "ssrf",
    "authz",
    "graphql",
    "websocket",
    "crypto",
]

VULN_TYPES: list[VulnType] = [
    "injection",
    "xss",
    "auth",
    "ssrf",
    "authz",
    "graphql",
    "websocket",
    "crypto",
]


# ---------------------------------------------------------------------------
# Playwright sessions — one per parallel browser slot (8 agents max)
# ---------------------------------------------------------------------------

PlaywrightSession = Literal[
    "agent1",
    "agent2",
    "agent3",
    "agent4",
    "agent5",
    "agent6",
    "agent7",
    "agent8",
]


# ---------------------------------------------------------------------------
# Model tiers — resolved to concrete model names by claude_executor
# ---------------------------------------------------------------------------

ModelTier = Literal["small", "medium", "large"]


# ---------------------------------------------------------------------------
# Agent execution status
# ---------------------------------------------------------------------------

AgentStatus = Literal[
    "pending",
    "in_progress",
    "completed",
    "failed",
    "rolled_back",
]


# ---------------------------------------------------------------------------
# Pipeline phase names (7 phases)
# ---------------------------------------------------------------------------

PhaseName = Literal[
    "preflight",
    "pre-recon",
    "recon",
    "sca",
    "integrity",
    "vulnerability-analysis",
    "exploitation",
    "chain-exploitation",
    "critique",
    "reporting",
    "remediation",
]


# ---------------------------------------------------------------------------
# Agent definition — describes an agent's configuration in the registry
# ---------------------------------------------------------------------------


class AgentDefinition(BaseModel):
    """Static definition of an agent in the pipeline registry."""

    name: AgentName
    display_name: str
    prerequisites: list[AgentName] = Field(default_factory=list)
    prompt_template: str
    deliverable_filename: str
    model_tier: ModelTier = "medium"
    conditional: bool = False


# ---------------------------------------------------------------------------
# Exploitation decision — returned by queue validation
# ---------------------------------------------------------------------------


class ExploitationDecision(BaseModel):
    """Decision returned by check_exploitation_queue activity."""

    should_exploit: bool
    should_retry: bool = False
    vulnerability_count: int
    vuln_type: VulnType
