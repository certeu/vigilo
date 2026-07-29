"""Grey-box agent type definitions."""
from __future__ import annotations

from typing import Literal

ModelTier = Literal["small", "medium", "large"]

# Canonical vuln_type roster: 4 flagship + 2 conditional specialists.
# See Slice 14 (Cluster E). These are the only vuln_types the scheduler
# emits and the only specialists that have prompt templates.
VULN_TYPES: tuple[str, ...] = (
    "authorization",
    "injection",
    "reflection",
    "ssrf",
    "graphql",
    "websocket",
)

# Documentation-only alias — kept ``str`` on graph nodes to avoid coupling
# data-plane types to the enum (legacy attempts may still carry older
# vuln_type strings until the operator wipes the DB).
VulnType = Literal[
    "authorization",
    "injection",
    "reflection",
    "ssrf",
    "graphql",
    "websocket",
]

AGENT_MODEL_TIERS: dict[str, ModelTier] = {
    # Scheduler verb kinds (canonical since Slice 5).
    "PROBE_PARAMETERS": "medium",
    "INVESTIGATE_LEAD": "medium",
    "TEST_ACCESS_MATRIX": "medium",
    "ATTEMPT_CHAIN": "large",
    # Non-verb agent phases.
    "CHAIN_EXPLOIT": "large",
    "VALIDATE": "medium",
    "REPORT": "large",
    # Simplified pipeline (single-agent mode).
    "PENTEST": "medium",
}

AGENT_PROMPT_TEMPLATES: dict[str, str] = {
    # 4 flagship specialists
    "authorization-specialist": "greybox/specialist-authorization",
    "injection-specialist": "greybox/specialist-injection",
    "reflection-specialist": "greybox/specialist-reflection",
    "ssrf-specialist": "greybox/specialist-ssrf",
    # 2 conditional specialists
    "graphql-specialist": "greybox/specialist-graphql",
    "websocket-specialist": "greybox/specialist-websocket",
    # Non-specialist agents
    "lead-investigator": "greybox/investigator",
    "discovery": "greybox/discovery",
    "chain-exploit": "greybox/chain-exploit",
    "validator": "greybox/validator",
    "report": "greybox/report",  # E11: add report mapping
    # Simplified pipeline (single-agent mode).
    "pentest": "greybox/pentest",
}

CAPABILITY_VOCABULARY: set[str] = {
    "authenticated",
    "admin_access",
    "db_read",
    "db_write",
    "file_read",
    "file_write",
    "credential_access",
    "session_hijack",
    "internal_network",
    "arbitrary_redirect",
    "code_execution",
    "user_impersonation",
    "csrf_bypass",
    "info_disclosure",
    "cloud_metadata",
}

# E17: Lead signal vocabulary
LEAD_SIGNAL_VOCABULARY: set[str] = {
    "response_code_anomaly", "timing_anomaly", "partial_reflection",
    "error_leak", "silent_parameter_acceptance", "differential_response",
    "encoding_bypass_hint", "auth_boundary_bleed", "redirect_anomaly",
    "verbose_error", "content_size_anomaly",
}
