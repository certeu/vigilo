"""Feedback loop type definitions.

When an exploit agent cannot confirm a vulnerability it writes a
NeedsMoreInfo payload. The workflow reads this, appends the questions
to the vuln agent prompt, and re-runs the vuln -> exploit sequence
(max 1 feedback loop per pipeline type).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class NeedsMoreInfo(BaseModel):
    """Payload written by exploit agents to request additional analysis.

    Written to ``deliverables/{vuln_type}_needs_more_info.json``.
    """

    vuln_type: str
    questions: list[str]
    failed_vulns: list[str] = Field(default_factory=list)
    context_needed: str = ""
