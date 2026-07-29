"""Scheduler verb types — deterministic instructions emitted by the grey-box scheduler."""
from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field

Priority = Literal["high", "medium", "low"] | None


class ProbeParameters(BaseModel):
    kind: Literal["PROBE_PARAMETERS"] = "PROBE_PARAMETERS"
    vuln_type: str
    param_ids: list[str]
    identity: str
    priority: Priority = None


class TestAccessMatrix(BaseModel):
    # __test__ = False: suppress pytest's "Test"-prefix auto-collection.
    __test__ = False

    kind: Literal["TEST_ACCESS_MATRIX"] = "TEST_ACCESS_MATRIX"
    endpoint_ids: list[str]
    identities: list[str]
    # Slice 16 / G2: identity-count gate picks the specialist methodology.
    # `vertical_only` — one identity, test privilege escalation per endpoint.
    # `full_matrix`   — two or more identities, cross-identity access matrix.
    mode: Literal["vertical_only", "full_matrix"] = "full_matrix"
    priority: Priority = None


class InvestigateLead(BaseModel):
    kind: Literal["INVESTIGATE_LEAD"] = "INVESTIGATE_LEAD"
    lead_id: str
    priority: Priority = None


class AttemptChain(BaseModel):
    kind: Literal["ATTEMPT_CHAIN"] = "ATTEMPT_CHAIN"
    finding_ids: list[str]
    priority: Priority = None


DoneReason = Literal[
    "budget_exhausted", "coverage_complete", "diminishing_returns",
    "waiting_timeout",
]


class Done(BaseModel):
    kind: Literal["DONE"] = "DONE"
    reason: DoneReason


Verb = Annotated[
    Union[
        ProbeParameters,
        TestAccessMatrix,
        InvestigateLead,
        AttemptChain,
        Done,
    ],
    Field(discriminator="kind"),
]


VERB_REGISTRY: dict[str, type[BaseModel]] = {
    "PROBE_PARAMETERS": ProbeParameters,
    "TEST_ACCESS_MATRIX": TestAccessMatrix,
    "INVESTIGATE_LEAD": InvestigateLead,
    "ATTEMPT_CHAIN": AttemptChain,
    "DONE": Done,
}
