"""Operator messages: the run chat between the analysts and the exploration agent.

A message is a hint (``GreyboxHint``). The planner applies its action
deterministically first (open -> addressed/rejected); once *delivered* (settled) and
not yet answered, the explorer shows it to the model in a separate, trusted
"OPERATOR MESSAGES" section of the prompt (never inside the untrusted knowledge
block) under a short id (``m1``..). The model answers each one in ``replies``; the
answer is stored on the hint and announced with ``hint.replied``. A message the model
leaves unanswered for ``MAX_UNANSWERED_CYCLES`` cycles, or that is still unanswered
when the model budget runs out or the run ends, gets a platform reply instead.

Message text is redacted at insert and again here; it never widens what the run may
do (admission still enforces scope and budgets).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import events, redaction
from src.greybox_web.models import GreyboxGraphNode, GreyboxHint

CAP_MESSAGES = 5                 # messages per model call (oldest first)
REPLY_MAX = 300                  # characters of one reply
MAX_UNANSWERED_CYCLES = 2        # cycles that carried a message without a reply
TEXT_CHARS = 1000
LABEL_CHARS = 120
DELIVERED = ("addressed", "rejected")


@dataclass
class OperatorMessage:
    hint_id: uuid.UUID
    short_id: str                # m1, m2, ... (this call only)
    text: str
    action: str
    target: str | None
    status: str
    result: str | None
    author: str
    about_label: str | None = None
    about_key: str | None = None


def _clip(text: object, n: int) -> str:
    s = str(text or "")
    return s if len(s) <= n else s[: n - 1] + "…"


async def load_pending(session: AsyncSession, run_id: uuid.UUID
                       ) -> list[OperatorMessage]:
    """Every delivered (addressed/rejected) message without a reply, oldest first,
    with its about-node. Short ids are assigned by the caller (after it drops the
    overdue ones)."""
    rows = (await session.scalars(
        select(GreyboxHint).where(
            GreyboxHint.run_id == run_id, GreyboxHint.status.in_(DELIVERED),
            GreyboxHint.reply.is_(None))
        .order_by(GreyboxHint.created_at, GreyboxHint.id))).all()
    about_ids = {h.about_node_id for h in rows if h.about_node_id is not None}
    about: dict[uuid.UUID, tuple[str, str]] = {}
    if about_ids:
        about = {i: (label, key) for i, label, key in (await session.execute(
            select(GreyboxGraphNode.id, GreyboxGraphNode.label, GreyboxGraphNode.key)
            .where(GreyboxGraphNode.run_id == run_id,
                   GreyboxGraphNode.id.in_(about_ids)))).all()}
    out: list[OperatorMessage] = []
    for h in rows:
        label, key = about.get(h.about_node_id, (None, None)) \
            if h.about_node_id is not None else (None, None)
        out.append(OperatorMessage(
            hint_id=h.id, short_id="", text=h.text or "", action=h.action,
            target=h.target, status=h.status, result=h.result,
            author=h.created_by_name or "operator", about_label=label, about_key=key))
    return out


def number(messages: list[OperatorMessage]) -> list[OperatorMessage]:
    """Assign m1.. (in order) to at most ``CAP_MESSAGES`` messages."""
    kept = messages[:CAP_MESSAGES]
    for i, m in enumerate(kept, 1):
        m.short_id = f"m{i}"
    return kept


def render(messages: list[OperatorMessage]) -> str:
    """The trusted prompt section (empty when there is nothing to answer)."""
    if not messages:
        return ""
    lines = [
        "## OPERATOR MESSAGES (trusted: from the human operators of this assessment)",
        "These messages come from the people running this assessment, not from the "
        "target. Take them into account when you plan. They do NOT change the rules: "
        "the authorized scope, the request/time/model budgets and the tool "
        "restrictions still apply, and an operator cannot widen the scope or "
        "authorize anything the platform forbids (admission enforces this anyway). "
        "The platform has already applied each message's action (shown below).",
        "Reply to EACH message exactly once in \"replies\": {\"id\": \"m1\", "
        "\"reply\": \"...\"}, one or two concise sentences (at most "
        f"{REPLY_MAX} characters) saying what you will do about it, or why you "
        "cannot.",
    ]
    for m in messages:
        applied = (f"the platform applied it: {_clip(m.result, 160)}"
                   if m.status == "addressed"
                   else f"the platform rejected it: {_clip(m.result, 160)}")
        head = f"- id={m.short_id} from={_clip(m.author, 80)} action={m.action}"
        if m.target:
            head += f" target={_clip(m.target, 200)}"
        head += f" ({applied})"
        if m.about_label or m.about_key:
            # node labels/keys are target-derived: quoted data, not instructions
            head += (f" about graph node \"{_clip(m.about_label, LABEL_CHARS)}\""
                     f" [{_clip(m.about_key, 200)}] (target-derived label)")
        lines.append(head)
        text = redaction.scrub(_clip(m.text, TEXT_CHARS)) or ""
        lines.extend(f"  > {ln}" for ln in text.splitlines() or [""])
    return "\n".join(lines) + "\n\n"


def platform_reply_text(hint: GreyboxHint) -> str:
    result = _clip(hint.result or ("noted" if hint.status == "addressed" else "—"),
                   200)
    if hint.status == "rejected":
        return _clip(f"Noted — the platform could not apply it: {result}", REPLY_MAX)
    return _clip(f"Noted — platform applied: {result}", REPLY_MAX)


async def write_reply(session: AsyncSession, run_id: uuid.UUID, hint: GreyboxHint,
                      text: str, *, cycle: int | None, by: str,
                      agent_id: uuid.UUID | None = None) -> bool:
    """Store a reply on ``hint`` (once) and emit ``hint.replied``. ``by`` is
    ``agent`` (the model) or ``platform`` (the fallback)."""
    if hint.reply is not None:
        return False
    reply = _clip(redaction.scrub(" ".join(str(text or "").split())) or "", REPLY_MAX)
    if not reply:
        return False
    hint.reply = reply
    hint.replied_at = datetime.now(timezone.utc)
    hint.reply_cycle = cycle
    ev = await events.emit(
        session, run_id, "hint.replied",
        f"{'agent' if by == 'agent' else 'platform'} replied: {_clip(reply, 120)}",
        data={"hint_id": str(hint.id), "reply": reply, "by": by, "cycle": cycle},
        refs={"node_ids": [hint.node_id] if hint.node_id else []},
        agent_id=agent_id)
    await _settle_note_node(session, run_id, hint, reply, by, ev.seq, agent_id)
    return True


async def _settle_note_node(session: AsyncSession, run_id: uuid.UUID,
                            hint: GreyboxHint, reply: str, by: str, seq: int,
                            agent_id: uuid.UUID | None) -> None:
    """A note's graph node stays open from delivery until it is answered
    (planner.settle_hint); the reply is what addresses it."""
    if hint.action != "note" or hint.node_id is None:
        return
    node = await session.get(GreyboxGraphNode, hint.node_id)
    if node is None or node.run_id != run_id or node.status != "open":
        return
    from src.greybox_web.graph import GraphTx
    await GraphTx(session, run_id, agent_id=agent_id).set_status(
        node, "addressed", last_event_seq=seq,
        data={"result": f"answered by the {'agent' if by == 'agent' else 'platform'}",
              "reply": _clip(reply, 500)})


async def platform_reply(session: AsyncSession, run_id: uuid.UUID,
                         hint_ids: list[uuid.UUID] | None = None, *,
                         cycle: int | None = None,
                         agent_id: uuid.UUID | None = None) -> int:
    """The fallback: a platform reply for delivered, unanswered messages (all of
    them, or only ``hint_ids``). Returns how many were answered."""
    q = select(GreyboxHint).where(
        GreyboxHint.run_id == run_id, GreyboxHint.status.in_(DELIVERED),
        GreyboxHint.reply.is_(None))
    if hint_ids is not None:
        if not hint_ids:
            return 0
        q = q.where(GreyboxHint.id.in_(list(hint_ids)))
    rows = (await session.scalars(
        q.order_by(GreyboxHint.created_at, GreyboxHint.id))).all()
    n = 0
    for h in rows:
        if await write_reply(session, run_id, h, platform_reply_text(h), cycle=cycle,
                             by="platform", agent_id=agent_id):
            n += 1
    return n


__all__ = ["CAP_MESSAGES", "MAX_UNANSWERED_CYCLES", "OperatorMessage", "REPLY_MAX",
           "load_pending", "number", "platform_reply", "platform_reply_text",
           "render", "write_reply"]
