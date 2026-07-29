"""Specialist dispatch payloads — discriminated by ``mode``.

Two shapes: ``batch`` (N parameters, one vuln type) and ``lead``
(one lead record to investigate). The scheduler emits verbs that
map 1:1 onto these payloads; the workflow renders each payload
into a specialist prompt via ``resolve_agent_context``.
"""
from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, RootModel


class BatchDispatch(BaseModel):
    mode: Literal["batch"]
    vuln_type: str
    identity: str
    param_ids: list[str]


class LeadDispatch(BaseModel):
    mode: Literal["lead"]
    lead_id: str
    identity: str


_Dispatch = Annotated[Union[BatchDispatch, LeadDispatch], Field(discriminator="mode")]


class DispatchPayload(RootModel[_Dispatch]):
    pass
