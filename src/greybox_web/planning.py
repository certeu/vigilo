"""Planner interface: the seam for a future LLM planner.

A planner *proposes* :class:`WorkOrderSpec` objects from a :class:`PlannerInput`
(the graph delta of the last cycle, recent events and the hints just handled). It never
touches tools, the network or the database: every spec goes through
``Planner.admit`` (scope via ``ScopePolicy``, tool kind from the registry and the run's
selected checks, per-run quotas, dedup), the single admission step, exactly like the
rule planner's own proposals. The platform (``Planner``) also applies analyst hints,
standing directives and lead settlement; a proposer cannot bypass or widen those.

This module holds only types and the protocol so that it has no import cycle with
``planner.py``, which re-exports everything here.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class NewAsset:
    """Plain asset info handed from a projection to the planner."""

    id: uuid.UUID
    kind: str
    key: str
    in_scope: bool
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def parent_endpoint_key(self) -> str | None:
        if self.kind != "parameter":
            return None
        return self.key.split("#", 1)[0]

    @property
    def param_name(self) -> str | None:
        if self.kind != "parameter":
            return None
        return self.key.split("#", 1)[1].split(":", 1)[1]

    @property
    def param_location(self) -> str | None:
        if self.kind != "parameter":
            return None
        return self.key.split("#", 1)[1].split(":", 1)[0]


@dataclass
class NewFinding:
    id: uuid.UUID
    check_id: str
    dedup_key: str
    verify: dict[str, Any]
    asset_id: uuid.UUID | None = None


# The tool prefixes that REUSE a tool the run authored for itself (batch E's
# declarative instruments, Phase 3's sandboxed analysers). The catalogue-selection
# gate does not apply to them: they exist because this run needed them, and
# admission applies every other check (validation, scope, budgets).
AUTHORED_TOOL_PREFIXES: tuple[str, ...] = ("dyn.", "tool.")


def is_authored_tool(tool: str) -> bool:
    """True for a run-authored tool or its verifier (a catalogue check is not one)."""
    return tool.startswith(AUTHORED_TOOL_PREFIXES) \
        or tool.removeprefix("verify.").startswith(AUTHORED_TOOL_PREFIXES)


@dataclass(frozen=True)
class Terminal:
    """A work order that just reached a terminal state (done / failed / skipped)."""

    wo_id: uuid.UUID
    tool: str
    status: str
    params: dict[str, Any] = field(default_factory=dict)
    fetched: int = 0                                  # pages fetched (crawl batches)
    frontier: tuple[str, ...] = ()                    # in-scope URLs found by discovery
    urls: tuple[str, ...] = ()                         # URLs the call actually acted on


def visited_urls(t: Terminal) -> tuple[str, ...]:
    """URLs this terminal call proved it has already fetched.

    A tool that succeeded *on* a URL has visited it — a second visit would repeat the
    same request. Kept declarative (``Terminal.urls``) so a tool that wants to keep a
    URL open simply does not report it."""
    if t.status != "done":
        return ()
    return tuple(u for u in t.urls if u)


@dataclass(frozen=True)
class HintView:
    """An analyst hint, as context for the planner (text is already redacted)."""

    id: uuid.UUID
    action: str
    target: str | None
    text: str
    status: str = "open"


@dataclass(frozen=True)
class EventView:
    seq: int
    kind: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LeadSpec:
    """A hypothesis the work order investigates: the admission step opens
    the lead node, links ``observation -spawned-> lead`` when ``observation_key`` names
    a recorded observation, and links ``work_order -investigated-> lead``."""

    type_id: str
    key: str
    label: str
    hypothesis: str
    signals: dict[str, Any] = field(default_factory=dict)
    observation_key: str | None = None
    asset_id: uuid.UUID | None = None
    # The reasoning node an explorer hypothesis was spawned by (graph lineage).
    parent_node_id: uuid.UUID | None = None

    @property
    def investigation(self) -> dict[str, Any]:
        value = self.signals.get("investigation")
        return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class WorkOrderSpec:
    """A proposed work order. ``kind`` is advisory: admission reads the real kind from
    the tool registry and never trusts the proposer's value."""

    tool: str
    params: dict[str, Any]
    reason: str
    priority: int = 50
    kind: str | None = None
    title: str = ""
    asset_id: uuid.UUID | None = None
    parent_node_id: uuid.UUID | None = None
    variant: str = ""
    lead: LeadSpec | None = None

    def __post_init__(self) -> None:
        if self.lead is None or not self.lead.investigation:
            return
        from src.greybox_web.investigation import priority_for_investigation
        object.__setattr__(self, "priority",
                           priority_for_investigation(self.priority,
                                                      self.lead.investigation))


@dataclass(frozen=True)
class PlanGroup:
    """Specs proposed for one reason; becomes one ``planner.decision`` event."""

    reason: str
    specs: tuple[WorkOrderSpec, ...]
    trigger: dict[str, Any] = field(default_factory=dict)
    considered: int = 0
    decision: str = "dispatch"


@dataclass(frozen=True)
class PlannerInput:
    cycle: int
    objective_node_id: uuid.UUID | None = None
    assets: tuple[NewAsset, ...] = ()
    findings: tuple[NewFinding, ...] = ()
    terminal: tuple[Terminal, ...] = ()
    hints: tuple[HintView, ...] = ()
    events: tuple[EventView, ...] = ()


@dataclass
class PlannerOutput:
    groups: list[PlanGroup] = field(default_factory=list)
    rationale: str = ""
    # Hypotheses opened WITHOUT a work order (nothing in scope can be done about them
    # automatically, or the follow-up needs an analyst opt-in): they stay ``open`` for the
    # analyst. Opened by the platform, like a lead attached to a work order.
    leads: list[LeadSpec] = field(default_factory=list)

    @property
    def specs(self) -> list[WorkOrderSpec]:
        return [s for g in self.groups for s in g.specs]

    @classmethod
    def of(cls, specs, reason: str, trigger: dict[str, Any] | None = None,
           considered: int = 0, rationale: str = "") -> "PlannerOutput":
        specs = tuple(specs)
        if not specs:
            return cls(rationale=rationale)
        return cls([PlanGroup(reason, specs, trigger or {}, considered)], rationale)


@dataclass(frozen=True)
class Rejection:
    """Why admission refused a spec. ``duplicate`` and ``check_skipped`` are routine
    (silent); every other reason is recorded as a ``planner.decision`` rejection."""

    reason: str
    detail: str = ""

    @property
    def routine(self) -> bool:
        return self.reason in ("duplicate", "check_skipped")


class PlannerProtocol(Protocol):
    """What a planner implements. Both calls are pure with respect to tools, network
    and database: they return proposals only (``Planner.admit`` does the rest)."""

    async def start(self, inp: PlannerInput) -> PlannerOutput:
        """Initial plan, before anything ran."""

    async def observe(self, inp: PlannerInput) -> PlannerOutput:
        """React to the delta of one cycle."""


def trigger(kind: str, **ids: Any) -> dict[str, Any]:
    """``planner.decision`` trigger: what caused the decision, by id (sorted, capped)."""
    out: dict[str, Any] = {"kind": kind}
    for name, values in ids.items():
        if isinstance(values, (str, int, float, bool)) or values is None:
            out[name] = values                  # a scalar attribute, not a set of ids
            continue
        out[name] = sorted({str(v) for v in values if v is not None})[:20]
    return out
