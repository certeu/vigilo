"""The LLM proposer: the cache seam between the explorer task and the planner.

Why a cache: model calls must never run inside the supervisor's write transaction,
and the planner (``start``/``observe``) is called exactly there. So the planner role
is split:

* the **explorer** (explorer.py) — a background task the supervisor wakes when the
  run is idle or new knowledge landed — builds knowledge, calls the model, validates
  the reply against ``schema.py``, and *stores* the mapped proposals here;
* ``LlmProposer.observe`` — called in the planning cycle — pops whatever is stored
  and returns it as ordinary ``PlannerOutput`` groups. Admission applies the same
  safety it applies to the rules: scope, dedup, param allow-list, budgets.

The model is the only source of exploration; the one automatic rule is the
verification of candidate findings (an evidence-quality gate).
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

from src.greybox_web.exploration.schema import Hypothesis, Proposal
from src.greybox_web.planner import verification_specs
from src.greybox_web.planning import (
    LeadSpec,
    PlanGroup,
    PlannerInput,
    PlannerOutput,
    WorkOrderSpec,
    trigger,
)


def brief(text: str, limit: int = 200) -> str:
    """A short, complete rationale: the first sentence, cut at a word boundary."""
    t = " ".join((text or "").split())
    m = re.match(r"(.+?[.!?])(\s|$)", t)
    out = m.group(1) if m else t
    if len(out) > limit:
        out = out[:limit].rsplit(" ", 1)[0].rstrip(",;:-") + "…"
    return out


def _slug(label: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in label.lower()).strip("-")[:60]


@dataclass(frozen=True)
class StoredProposals:
    """Validated, mapped proposals waiting for the next planning cycle."""

    groups: tuple[PlanGroup, ...]
    leads: tuple[LeadSpec, ...]
    reasoning: str
    assessment: str
    model: str
    tokens: int


class LlmProposer:
    """A :class:`~src.greybox_web.planning.PlannerProtocol` that emits cached LLM
    proposals. One instance per run, shared between the supervisor (consumer) and
    the explorer (producer). Proposals accumulate: a background cycle's output is
    never lost to a later cycle before the planner consumed it.

    ``dynamic_tools`` is the run's dynamic tool registry (batch E): the supervisor
    owns it (the same object the planner state carries) so candidate findings from
    dynamic checks get their ``verify.<dyn id>`` replay work orders. When absent
    (unit tests, static-only runs) dynamic verifiers simply do not resolve."""

    def __init__(self, dynamic_tools: dict[str, Any] | None = None) -> None:
        self._pending: list[StoredProposals] = []
        self.consumed_cycles: int = 0
        # the run's registry object BY REFERENCE (it is still empty at setup and
        # admission fills it later), or a private one when none was given
        self.dynamic_tools: dict[str, Any] = \
            dynamic_tools if dynamic_tools is not None else {}

    # -- producer side (explorer, outside any write transaction) -----------------
    def store(self, proposal: Proposal, *, model: str, tokens: int,
              node_id: uuid.UUID | None = None) -> None:
        """Map a validated model reply onto planner specs/leads and cache them.
        ``node_id`` is the reasoning node this reply was recorded as: everything it
        spawns is parented there, so the graph shows why each item exists."""
        hyps: dict[str, Hypothesis] = {}
        for h in proposal.hypotheses:
            hyps.setdefault(h.id, h)

        def lead_for(hid: str | None) -> LeadSpec | None:
            h = hyps.get(hid or "")
            if h is None:
                return None
            signals = dict(h.signals or {})
            declaration = dict(h.investigation or {})
            if (h.operation or h.expected_property or h.prerequisites
                    or h.required_observations or h.planned_verification or h.progress):
                declaration.update({"operation": h.operation,
                    "expected_property": h.expected_property,
                    "prerequisites": h.prerequisites,
                    "required_observations": h.required_observations,
                    "planned_verification": h.planned_verification,
                    "progress": h.progress})
            if declaration:
                signals["investigation"] = declaration
            investigation_id = str(declaration.get("id") or "").strip()
            operation = declaration.get("operation")
            if not investigation_id and isinstance(operation, dict):
                investigation_id = str(operation.get("id") or "").strip()
            stable_key = (investigation_id if investigation_id.startswith("lead:llm:")
                          else f"lead:llm:{_slug(investigation_id) or _slug(h.label) or h.id}")
            return LeadSpec(
                type_id="explorer", key=stable_key[:300],
                label=h.label[:300],
                hypothesis=h.hypothesis[:500],
                signals=signals,
                parent_node_id=node_id)

        specs: list[WorkOrderSpec] = []
        acted: set[str] = set()
        for a in proposal.actions:
            lead = lead_for(a.hypothesis)
            if lead is not None:
                acted.add(a.hypothesis or "")
            params = {k: v for k, v in (a.params or {}).items() if v is not None}
            specs.append(WorkOrderSpec(
                tool=a.tool, params=params, reason=a.reason[:500],
                priority=a.priority, title=a.title[:120],
                variant=a.variant, lead=lead,
                parent_node_id=node_id))

        group = PlanGroup(
            reason=f"explorer: {proposal.summary or brief(proposal.reasoning)}"
            if (proposal.summary or proposal.reasoning) else "explorer proposal",
            specs=tuple(specs),
            trigger=trigger("agent", assessment=proposal.assessment,
                            model=model))
        # Hypotheses with no action: analyst-facing leads (opened by the platform).
        leads = tuple(lead_for(h.id) for h in proposal.hypotheses
                      if h.id not in acted or h.investigation)
        self._pending.append(StoredProposals(
            groups=(group,) if specs else (),
            leads=tuple(l for l in leads if l is not None),
            reasoning=proposal.reasoning,
            assessment=proposal.assessment,
            model=model, tokens=tokens))

    @property
    def stored(self) -> StoredProposals | None:
        """The merged unconsumed proposals (or None): what the next cycle will emit."""
        if not self._pending:
            return None
        if len(self._pending) == 1:
            return self._pending[0]
        groups = [g for p in self._pending for g in p.groups]
        leads: dict[str, LeadSpec] = {}
        for p in self._pending:
            for l in p.leads:
                leads.setdefault(l.key, l)          # first cycle wins
        return StoredProposals(
            groups=tuple(groups), leads=tuple(leads.values()),
            reasoning=" | ".join(p.reasoning for p in self._pending),
            assessment=self._pending[-1].assessment,
            model=self._pending[-1].model,
            tokens=sum(p.tokens for p in self._pending))

    def pop(self) -> StoredProposals | None:
        """Take and clear the cache (called by ``observe`` inside the cycle)."""
        out = self.stored
        self._pending.clear()
        if out is not None:
            self.consumed_cycles += 1
        return out

    # -- consumer side (planner, inside the write transaction) -------------------
    async def start(self, inp: PlannerInput) -> PlannerOutput:
        return PlannerOutput()                      # the explorer's bootstrap cycle opens the run

    async def observe(self, inp: PlannerInput) -> PlannerOutput:
        """Cached model proposals plus the automatic evidence gate: a candidate
        finding gets its ``verify.*`` work order (admitted like everything else)."""
        groups: list[PlanGroup] = []
        # The run's authored tools are registered in this registry object (by
        # reference), so a candidate an authored tool produced is verified by its
        # own authored verifier -- in the same cycle, not a later rebuild.
        vspecs = verification_specs(inp.findings, self.dynamic_tools)
        if vspecs:
            groups.append(PlanGroup(
                f"{len(vspecs)} verification work order(s) for candidate findings",
                tuple(vspecs), trigger("finding",
                                       finding_ids=[f.id for f in inp.findings]),
                considered=len(inp.findings)))
        stored = self.pop()
        if stored is None:
            return PlannerOutput(groups=groups)
        return PlannerOutput(groups=groups + list(stored.groups),
                             leads=list(stored.leads),
                             rationale=stored.reasoning)
