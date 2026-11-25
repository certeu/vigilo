"""Progress tracking: did an action teach the run anything? (anti-loop).

A model left to itself repeats what feels productive — re-fetching the same bundle,
re-running the same failing script — without noticing that nothing new comes back.
This module measures the **yield** of every finished work order from the database:

* observation nodes it *created* (a repeated identical observation updates the
  existing node, which keeps its first work order — so a repeat yields 0);
* assets it discovered (``asset.discovered`` events);
* findings it raised (``finding.created`` events).

From that ledger:

* the knowledge shows the agent its ``progress``: the current streak of actions that
  yielded nothing, the unproductive actions, the failing ones (with their error);
* admission refuses an action IDENTICAL (tool + parameters) to one that already ran
  and yielded nothing (``no_new_information``), or that failed twice
  (``repeated_failure``) — a change of method or of input is always admitted;
* everything is derived from persisted rows, so it survives a resume.

General by design: no technology or tool is special-cased; the skills carry the
domain-specific alternatives ("if static analysis finds no API, observe runtime").
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

# Not subject to the repetition rule: verification is meant to repeat, and these
# change state the ledger cannot see (definitions, sessions).
EXEMPT_PREFIXES = ("verify.", "tool.compose", "tool.define", "auth.login")
STREAK_WARN = 3
CAP_LIST = 6


@dataclass(frozen=True)
class Step:
    id: uuid.UUID
    tool: str
    signature: str
    status: str
    yield_: int
    target: str
    error: str


def signature(tool: str, params: Any) -> str:
    """Identity of an action: the tool and its exact parameters."""
    try:
        p = json.dumps(params or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        p = str(params)
    return f"{tool}|{p}"[:2000]


async def ledger(session: AsyncSession, run_id: uuid.UUID) -> list[Step]:
    from src.greybox_web.exploration.knowledge import _target
    from src.greybox_web.models import GreyboxEvent, GreyboxGraphNode, GreyboxWorkOrder
    wos = (await session.scalars(
        select(GreyboxWorkOrder).where(GreyboxWorkOrder.run_id == run_id,
                                       GreyboxWorkOrder.status.in_(("done", "failed")))
        .order_by(GreyboxWorkOrder.finished_at, GreyboxWorkOrder.created_at))).all()
    if not wos:
        return []
    obs = dict((await session.execute(
        select(GreyboxGraphNode.work_order_id, func.count()).where(
            GreyboxGraphNode.run_id == run_id,
            GreyboxGraphNode.kind == "observation",
            GreyboxGraphNode.work_order_id.is_not(None))
        .group_by(GreyboxGraphNode.work_order_id))).all())
    evs = dict((await session.execute(
        select(GreyboxEvent.work_order_id, func.count()).where(
            GreyboxEvent.run_id == run_id,
            GreyboxEvent.kind.in_(("asset.discovered", "finding.created")),
            GreyboxEvent.work_order_id.is_not(None))
        .group_by(GreyboxEvent.work_order_id))).all())
    return [Step(id=w.id, tool=w.tool, signature=signature(w.tool, w.params),
                 status=w.status, yield_=int(obs.get(w.id, 0)) + int(evs.get(w.id, 0)),
                 target=f"{w.tool} {_target(w)}".strip(),
                 error=(w.error or "")[:300])
            for w in wos]


def _exempt(tool: str) -> bool:
    return tool.startswith(EXEMPT_PREFIXES)


def summary(steps: list[Step]) -> dict[str, Any]:
    """The ``progress`` section of the knowledge."""
    streak = 0
    for s in reversed([s for s in steps if not _exempt(s.tool)]):
        if s.yield_ > 0:
            break
        streak += 1
    unproductive: dict[str, dict] = {}
    failing: dict[str, dict] = {}
    for s in steps:
        if _exempt(s.tool):
            continue
        if s.status == "done" and s.yield_ == 0:
            u = unproductive.setdefault(s.target, {"action": s.target, "runs": 0})
            u["runs"] += 1
        if s.status == "failed":
            f = failing.setdefault(s.target, {"action": s.target, "runs": 0})
            f["runs"] += 1
            f["last_error"] = s.error[:200]
    out: dict[str, Any] = {
        "actions_finished": len(steps),
        "actions_with_new_information": sum(1 for s in steps if s.yield_ > 0),
        "no_new_information_streak": streak,
    }
    if unproductive:
        out["unproductive"] = sorted(unproductive.values(),
                                     key=lambda x: -x["runs"])[:CAP_LIST]
    if failing:
        out["failing"] = sorted(failing.values(), key=lambda x: -x["runs"])[:CAP_LIST]
    return out


def refusal(steps: list[Step], tool: str, params: Any) -> tuple[str, str] | None:
    """(reason, detail) when ``tool(params)`` repeats an action that already proved
    useless; None otherwise."""
    if _exempt(tool):
        return None
    sig = signature(tool, params)
    same = [s for s in steps if s.signature == sig]
    if not same:
        return None
    if any(s.status == "done" and s.yield_ == 0 for s in same):
        return ("no_new_information",
                f"{tool} with these exact parameters already ran and produced no new "
                "information; change the method or the input (see the loaded skill's "
                "alternatives)")
    failures = [s for s in same if s.status == "failed"]
    if len(failures) >= 2:
        return ("repeated_failure",
                f"{tool} with these exact parameters failed {len(failures)} times "
                f"(last: {failures[-1].error[:120]}); fix the cause or try another "
                "approach")
    return None


def warning(progress: dict[str, Any]) -> str:
    """A PROGRESS CHECK note for the prompt when the agent is going in circles."""
    streak = int(progress.get("no_new_information_streak") or 0)
    if streak < STREAK_WARN:
        return ""
    names = ", ".join(u["action"] for u in (progress.get("unproductive") or [])[:4])
    return (f"PROGRESS CHECK: your last {streak} actions produced no new information"
            + (f" (e.g. {names})" if names else "") + ". Repeating them is refused. "
            "Change METHOD, not just inputs: switch between static and runtime "
            "evidence, another identity, another tool, or write an analyser; or record "
            "the direction as exhausted (hypothesis outcome / criterion blocked) and "
            "move on.\n\n")
