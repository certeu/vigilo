"""Signal type definitions for grey-box pipeline."""
from __future__ import annotations

from enum import StrEnum


class SignalType(StrEnum):
    """Signal types. Only CREDENTIALS_FOUND triggers immediate planner re-run."""
    CREDENTIALS_FOUND = "credentials_found"
    NEW_ENDPOINT = "new_endpoint"
    FINDING_CONFIRMED = "finding_confirmed"
    LEAD_DETECTED = "lead_detected"
