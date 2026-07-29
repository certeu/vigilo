"""Session manager: agent registry, Playwright session mapping, and vuln type config.

20 agents (+GraphQL, +WebSocket, +Crypto, +Chain exploit, +Remediation) and 8 Playwright sessions.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from pydantic import BaseModel

from src.types.agents import (
    AgentDefinition,
    AgentName,
    PhaseName,
    PlaywrightSession,
    VulnType,
)


class VulnTypeConfig(BaseModel):
    """File naming conventions for a vulnerability type."""

    deliverable_filename: str
    queue_filename: str
    analysis_deliverable: str


# ---------------------------------------------------------------------------
# AGENTS registry (20 agents)
# ---------------------------------------------------------------------------
# Immutable mapping of every agent in the pipeline. Each entry defines the
# agent's identity, prerequisites, prompt template, deliverable filename,
# model tier, and whether it's conditional on tech detection.
# ---------------------------------------------------------------------------

AGENTS: Mapping[AgentName, AgentDefinition] = MappingProxyType({
    "pre-recon": AgentDefinition(
        name="pre-recon",
        display_name="Pre-recon agent",
        prerequisites=[],
        prompt_template="pre-recon-code",
        deliverable_filename="code_analysis_deliverable.md",
        model_tier="large",
        conditional=False,
    ),
    "recon": AgentDefinition(
        name="recon",
        display_name="Recon agent",
        prerequisites=["pre-recon"],
        prompt_template="recon",
        deliverable_filename="recon_deliverable.md",
        model_tier="medium",
        conditional=False,
    ),
    # --- SCA (supply chain analysis) ---
    "sca": AgentDefinition(
        name="sca",
        display_name="SCA agent",
        prerequisites=["pre-recon"],
        prompt_template="sca",
        deliverable_filename="sca_findings.json",
        model_tier="medium",
        conditional=False,
    ),
    # --- Integrity analysis (malicious code detection) ---
    "integrity": AgentDefinition(
        name="integrity",
        display_name="Integrity analysis agent",
        prerequisites=["pre-recon"],
        prompt_template="integrity",
        deliverable_filename="integrity_analysis.json",
        model_tier="large",
        conditional=False,
    ),
    # --- Vulnerability analysis agents (8) ---
    "injection-vuln": AgentDefinition(
        name="injection-vuln",
        display_name="Injection vuln agent",
        prerequisites=["recon"],
        prompt_template="vuln-injection",
        deliverable_filename="injection_analysis_deliverable.md",
        model_tier="large",
        conditional=False,
    ),
    "xss-vuln": AgentDefinition(
        name="xss-vuln",
        display_name="XSS vuln agent",
        prerequisites=["recon"],
        prompt_template="vuln-xss",
        deliverable_filename="xss_analysis_deliverable.md",
        model_tier="large",
        conditional=False,
    ),
    "auth-vuln": AgentDefinition(
        name="auth-vuln",
        display_name="Auth vuln agent",
        prerequisites=["recon"],
        prompt_template="vuln-auth",
        deliverable_filename="auth_analysis_deliverable.md",
        model_tier="large",
        conditional=False,
    ),
    "ssrf-vuln": AgentDefinition(
        name="ssrf-vuln",
        display_name="SSRF vuln agent",
        prerequisites=["recon"],
        prompt_template="vuln-ssrf",
        deliverable_filename="ssrf_analysis_deliverable.md",
        model_tier="large",
        conditional=False,
    ),
    "authz-vuln": AgentDefinition(
        name="authz-vuln",
        display_name="Authz vuln agent",
        prerequisites=["recon"],
        prompt_template="vuln-authz",
        deliverable_filename="authz_analysis_deliverable.md",
        model_tier="large",
        conditional=False,
    ),
    "graphql-vuln": AgentDefinition(
        name="graphql-vuln",
        display_name="GraphQL vuln agent",
        prerequisites=["recon"],
        prompt_template="vuln-graphql",
        deliverable_filename="graphql_analysis_deliverable.md",
        model_tier="large",
        conditional=True,
    ),
    "websocket-vuln": AgentDefinition(
        name="websocket-vuln",
        display_name="WebSocket vuln agent",
        prerequisites=["recon"],
        prompt_template="vuln-websocket",
        deliverable_filename="websocket_analysis_deliverable.md",
        model_tier="large",
        conditional=True,
    ),
    "crypto-vuln": AgentDefinition(
        name="crypto-vuln",
        display_name="Crypto vuln agent",
        prerequisites=["recon"],
        prompt_template="vuln-crypto",
        deliverable_filename="crypto_analysis_deliverable.md",
        model_tier="large",
        conditional=False,
    ),
    # --- Exploitation agents (7) ---
    "injection-exploit": AgentDefinition(
        name="injection-exploit",
        display_name="Injection exploit agent",
        prerequisites=["injection-vuln"],
        prompt_template="exploit-injection",
        deliverable_filename="injection_exploitation_evidence.md",
        model_tier="large",
        conditional=False,
    ),
    "xss-exploit": AgentDefinition(
        name="xss-exploit",
        display_name="XSS exploit agent",
        prerequisites=["xss-vuln"],
        prompt_template="exploit-xss",
        deliverable_filename="xss_exploitation_evidence.md",
        model_tier="large",
        conditional=False,
    ),
    "auth-exploit": AgentDefinition(
        name="auth-exploit",
        display_name="Auth exploit agent",
        prerequisites=["auth-vuln"],
        prompt_template="exploit-auth",
        deliverable_filename="auth_exploitation_evidence.md",
        model_tier="large",
        conditional=False,
    ),
    "ssrf-exploit": AgentDefinition(
        name="ssrf-exploit",
        display_name="SSRF exploit agent",
        prerequisites=["ssrf-vuln"],
        prompt_template="exploit-ssrf",
        deliverable_filename="ssrf_exploitation_evidence.md",
        model_tier="large",
        conditional=False,
    ),
    "authz-exploit": AgentDefinition(
        name="authz-exploit",
        display_name="Authz exploit agent",
        prerequisites=["authz-vuln"],
        prompt_template="exploit-authz",
        deliverable_filename="authz_exploitation_evidence.md",
        model_tier="large",
        conditional=False,
    ),
    "graphql-exploit": AgentDefinition(
        name="graphql-exploit",
        display_name="GraphQL exploit agent",
        prerequisites=["graphql-vuln"],
        prompt_template="exploit-graphql",
        deliverable_filename="graphql_exploitation_evidence.md",
        model_tier="large",
        conditional=True,
    ),
    "websocket-exploit": AgentDefinition(
        name="websocket-exploit",
        display_name="WebSocket exploit agent",
        prerequisites=["websocket-vuln"],
        prompt_template="exploit-websocket",
        deliverable_filename="websocket_exploitation_evidence.md",
        model_tier="large",
        conditional=True,
    ),
    # --- Chain exploitation ---
    "chain-exploit": AgentDefinition(
        name="chain-exploit",
        display_name="Chain exploitation agent",
        prerequisites=[],
        prompt_template="exploit-chain",
        deliverable_filename="chain_exploitation_evidence.md",
        model_tier="large",
        conditional=False,
    ),
    # --- Critique (post-aggregation, pre-remediation) ---
    "report-critic": AgentDefinition(
        name="report-critic",
        display_name="Report critic agent",
        prerequisites=[],
        prompt_template="critic",
        deliverable_filename="findings_critique.json",
        model_tier="large",
        conditional=False,
    ),
    # --- Remediation ---
    "remediation": AgentDefinition(
        name="remediation",
        display_name="Remediation agent",
        prerequisites=[],
        prompt_template="remediation",
        deliverable_filename="remediation_report.md",
        model_tier="medium",
        conditional=False,
    ),
    # --- Reporting ---
    "report": AgentDefinition(
        name="report",
        display_name="Report agent",
        prerequisites=["remediation"],
        prompt_template="report-executive",
        deliverable_filename="comprehensive_security_assessment_report.md",
        model_tier="medium",
        conditional=False,
    ),
})

# ---------------------------------------------------------------------------
# AGENT_PHASE_MAP — maps each agent to its pipeline phase
# ---------------------------------------------------------------------------

AGENT_PHASE_MAP: Mapping[AgentName, PhaseName] = MappingProxyType({
    "pre-recon": "pre-recon",
    "recon": "recon",
    "sca": "sca",
    "integrity": "integrity",
    "injection-vuln": "vulnerability-analysis",
    "xss-vuln": "vulnerability-analysis",
    "auth-vuln": "vulnerability-analysis",
    "ssrf-vuln": "vulnerability-analysis",
    "authz-vuln": "vulnerability-analysis",
    "graphql-vuln": "vulnerability-analysis",
    "websocket-vuln": "vulnerability-analysis",
    "crypto-vuln": "vulnerability-analysis",
    "injection-exploit": "exploitation",
    "xss-exploit": "exploitation",
    "auth-exploit": "exploitation",
    "ssrf-exploit": "exploitation",
    "authz-exploit": "exploitation",
    "graphql-exploit": "exploitation",
    "websocket-exploit": "exploitation",
    "chain-exploit": "chain-exploitation",
    "report-critic": "critique",
    "report": "reporting",
    "remediation": "remediation",
})

# ---------------------------------------------------------------------------
# PLAYWRIGHT_SESSION_MAPPING — assigns prompt templates to browser sessions
# ---------------------------------------------------------------------------
# Each vuln/exploit pair shares a session (they run sequentially, not in
# parallel). New agents get agent6-agent8. This prevents parallel browser
# interference while maximizing session reuse.
# ---------------------------------------------------------------------------

PLAYWRIGHT_SESSION_MAPPING: Mapping[str, PlaywrightSession] = MappingProxyType({
    # Phase 2: Pre-reconnaissance
    "pre-recon-code": "agent1",
    # Phase 2.5: SCA + Integrity (no browser needed, share slot)
    "sca": "agent8",
    "integrity": "agent8",
    # Phase 3: Reconnaissance
    "recon": "agent2",
    # Phase 4: Vulnerability analysis (8 parallel agents)
    "vuln-injection": "agent1",
    "vuln-xss": "agent2",
    "vuln-auth": "agent3",
    "vuln-ssrf": "agent4",
    "vuln-authz": "agent5",
    "vuln-graphql": "agent6",
    "vuln-websocket": "agent7",
    "vuln-crypto": "agent8",
    # Phase 5: Exploitation (7 parallel agents — same sessions as vuln counterparts)
    "exploit-injection": "agent1",
    "exploit-xss": "agent2",
    "exploit-auth": "agent3",
    "exploit-ssrf": "agent4",
    "exploit-authz": "agent5",
    "exploit-graphql": "agent6",
    "exploit-websocket": "agent7",
    # Phase 5b: Chain exploitation
    "exploit-chain": "agent1",
    # Phase 5c: Critique (read-only — uses agent2 to avoid the agent1 lane)
    "critic": "agent2",
    # Phase 6: Remediation
    "remediation": "agent1",
    # Phase 7: Reporting
    "report-executive": "agent3",
})

# ---------------------------------------------------------------------------
# VULN_TYPE_CONFIG — file naming conventions per vulnerability type
# ---------------------------------------------------------------------------
# Maps each VulnType to its deliverable filename, exploitation queue filename,
# and analysis deliverable filename. Used by queue validation, findings
# aggregation, and the feedback loop system.
# ---------------------------------------------------------------------------

VULN_TYPE_CONFIG: Mapping[VulnType, VulnTypeConfig] = MappingProxyType({
    "injection": VulnTypeConfig(
        deliverable_filename="injection_exploitation_evidence.md",
        queue_filename="injection_exploitation_queue.json",
        analysis_deliverable="injection_analysis_deliverable.md",
    ),
    "xss": VulnTypeConfig(
        deliverable_filename="xss_exploitation_evidence.md",
        queue_filename="xss_exploitation_queue.json",
        analysis_deliverable="xss_analysis_deliverable.md",
    ),
    "auth": VulnTypeConfig(
        deliverable_filename="auth_exploitation_evidence.md",
        queue_filename="auth_exploitation_queue.json",
        analysis_deliverable="auth_analysis_deliverable.md",
    ),
    "ssrf": VulnTypeConfig(
        deliverable_filename="ssrf_exploitation_evidence.md",
        queue_filename="ssrf_exploitation_queue.json",
        analysis_deliverable="ssrf_analysis_deliverable.md",
    ),
    "authz": VulnTypeConfig(
        deliverable_filename="authz_exploitation_evidence.md",
        queue_filename="authz_exploitation_queue.json",
        analysis_deliverable="authz_analysis_deliverable.md",
    ),
    "graphql": VulnTypeConfig(
        deliverable_filename="graphql_exploitation_evidence.md",
        queue_filename="graphql_exploitation_queue.json",
        analysis_deliverable="graphql_analysis_deliverable.md",
    ),
    "websocket": VulnTypeConfig(
        deliverable_filename="websocket_exploitation_evidence.md",
        queue_filename="websocket_exploitation_queue.json",
        analysis_deliverable="websocket_analysis_deliverable.md",
    ),
    "crypto": VulnTypeConfig(
        deliverable_filename="crypto_exploitation_evidence.md",
        queue_filename="crypto_exploitation_queue.json",
        analysis_deliverable="crypto_analysis_deliverable.md",
    ),
})
