"""Type definitions for the Shannon Python pipeline.

Re-exports key types so consumers can write:
    from src.types import AgentName, PipelineInput, AgentMetrics
"""

from src.types.agents import (
    ALL_AGENTS,
    VULN_TYPES,
    AgentDefinition,
    AgentName,
    AgentStatus,
    ExploitationDecision,
    ModelTier,
    PhaseName,
    PlaywrightSession,
    VulnType,
)
from src.types.audit import (
    AgentAttempt,
    AgentRecord,
    LogEvent,
    SessionData,
    SessionMetadata,
)
from src.types.config import (
    Authentication,
    Credentials,
    PipelineConfig,
    PipelineInput,
    Rule,
    SuccessCondition,
)
from src.types.deliverables import (
    DELIVERABLE_FILENAMES,
    QUEUE_TYPES,
    DeliverableType,
    is_queue_type,
)
from src.types.feedback import NeedsMoreInfo
from src.types.metrics import (
    AgentMetrics,
    PipelineProgress,
    PipelineState,
    PipelineSummary,
)

__all__ = [
    # agents
    "AgentName",
    "ALL_AGENTS",
    "VulnType",
    "VULN_TYPES",
    "PlaywrightSession",
    "ModelTier",
    "AgentStatus",
    "PhaseName",
    "AgentDefinition",
    "ExploitationDecision",
    # metrics
    "AgentMetrics",
    "PipelineSummary",
    "PipelineState",
    "PipelineProgress",
    # config
    "Rule",
    "SuccessCondition",
    "Credentials",
    "Authentication",
    "PipelineConfig",
    "PipelineInput",
    # audit
    "SessionMetadata",
    "LogEvent",
    "AgentAttempt",
    "AgentRecord",
    "SessionData",
    # feedback
    "NeedsMoreInfo",
    # deliverables
    "DeliverableType",
    "DELIVERABLE_FILENAMES",
    "QUEUE_TYPES",
    "is_queue_type",
]
