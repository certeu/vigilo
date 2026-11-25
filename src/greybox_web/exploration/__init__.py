"""Exploration agent.

The LLM-driven planner of the grey-box engine: it reads what the run knows (the
graph), reasons about the application, and proposes hypotheses and targeted work
orders through the same admission path as the deterministic rules. Safety model
unchanged: no shell, no raw network for the model; every proposal passes
``Planner.admit``; every request still goes through the guarded client.
"""
from src.greybox_web.exploration.client import (
    AgentBudget,
    AgentError,
    AgentUnavailable,
    ModelClient,
    ModelReply,
    build_client,
)

__all__ = [
    "AgentBudget",
    "AgentError",
    "AgentUnavailable",
    "ModelClient",
    "ModelReply",
    "build_client",
]
