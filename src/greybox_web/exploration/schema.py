"""The exploration model's reply contract.

Hypotheses are *directions* ("this API probably has broken object-level
authorization"); actions are *tool-bound steps* toward them.

Robustness first: forcing a schema breaks easily (a reply cut by the output-token
limit, prose around the JSON, a trailing comma, a priority given as "high"), so the
contract is enforced in two layers:

* the model is *asked* for the shape with the provider's native structured output
  (``PROPOSAL_SCHEMA`` is the JSON schema handed to tool use / ``json_schema``);
* whatever comes back is parsed **tolerantly** (``parse_reply``): fences and prose
  are stripped, a truncated tail is repaired (open strings/arrays/objects closed,
  the complete items kept), unknown fields are ignored, types are coerced and
  lengths clamped. Every action / hypothesis / todo step is validated on its own: a
  bad one is dropped with a note and the rest is used.

Only a reply with **zero usable content** is a failure. Safety does not depend on
this layer: every action still goes through ``Planner.admit`` (scope, allow-listed
params, budgets).
"""
from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

_TodoStatus = Literal["pending", "in_progress", "done"]

MAX_TODOS = 12
MAX_HYPOTHESES = 12
MAX_ACTIONS = 8
MAX_REPLIES = 8
REPLY_MAX = 300                  # characters of one reply to an operator message


class ProposalError(Exception):
    """The reply has no usable content; ``repair_message`` tells the model why."""


class TodoStep(BaseModel):
    model_config = ConfigDict(extra="ignore")

    step: str = Field(min_length=1, max_length=200)
    status: _TodoStatus = "pending"


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=16)
    label: str = Field(min_length=1, max_length=120)
    hypothesis: str = Field(min_length=1, max_length=600)
    signals: dict[str, Any] = Field(default_factory=dict)
    operation: dict[str, Any] = Field(default_factory=dict)
    expected_property: str = Field(default="", max_length=400)
    prerequisites: list[dict[str, Any]] = Field(default_factory=list)
    required_observations: list[str] = Field(default_factory=list)
    planned_verification: dict[str, Any] = Field(default_factory=dict)
    progress: dict[str, Any] = Field(default_factory=dict)
    investigation: dict[str, Any] = Field(default_factory=dict)


class Action(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tool: str = Field(min_length=3, max_length=48)
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=400)
    priority: int = Field(default=25, ge=5, le=90)
    variant: str = Field(default="", max_length=60)
    hypothesis: str | None = Field(default=None, max_length=16)
    title: str = Field(default="", max_length=120)


class CorrelationAction(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: Literal["finding.correlate", "finding.merge", "finding.split",
                    "finding.add_location"]
    params: dict[str, Any]


class Reply(BaseModel):
    """The agent's answer to one operator message (``id`` = the prompt's m1..)."""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=16)
    reply: str = Field(min_length=1, max_length=REPLY_MAX)


class Proposal(BaseModel):
    model_config = ConfigDict(extra="ignore")

    reasoning: str = Field(default="", max_length=2000)
    summary: str = Field(default="", max_length=200)     # one-sentence rationale
    assessment: Literal["incomplete", "adequate"] = "incomplete"
    todolist: list[TodoStep] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    correlations: list[CorrelationAction] = Field(default_factory=list, max_length=8)
    replies: list[Reply] = Field(default_factory=list)
    # Definition-of-done claims for loaded skills (skillbook.clean_claims): the
    # engine re-validates every cited piece of evidence before a claim counts.
    criteria: list[dict[str, Any]] = Field(default_factory=list)
    # Security relationship model declarations (secmodel.clean validates them when
    # they are stored): entities, relations and access expectations.
    model: dict[str, Any] = Field(default_factory=dict)
    # Parser diagnostics (never sent by the model): what was repaired or dropped.
    notes: list[str] = Field(default_factory=list)
    repaired: bool = False


# JSON schema for the provider's native structured output. Deliberately loose
# (no ``additionalProperties: false``, free-form ``params``/``signals``): the schema
# steers the model, the tolerant parser below is the actual gate.
PROPOSAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string",
                      "description": "At most 6 sentences of honest analysis."},
        "summary": {"type": "string",
                    "description": "One short sentence: why these next steps."},
        "assessment": {"type": "string", "enum": ["incomplete", "adequate"]},
        "todolist": {"type": "array", "maxItems": 8, "items": {
            "type": "object",
            "properties": {"step": {"type": "string"},
                           "status": {"type": "string",
                                      "enum": ["pending", "in_progress", "done"]}},
            "required": ["step"]}},
        "hypotheses": {"type": "array", "maxItems": 8, "items": {
            "type": "object",
            "properties": {"id": {"type": "string"}, "label": {"type": "string"},
                           "hypothesis": {"type": "string"},
                           "operation": {"type": "object"},
                           "expected_property": {"type": "string"},
                           "prerequisites": {"type": "array", "items": {"type": "object"}},
                           "required_observations": {"type": "array", "items": {"type": "string"}},
                           "planned_verification": {"type": "object"},
                           "progress": {"type": "object"},
                           "investigation": {"type": "object"},
                           "signals": {"type": "object"}},
            "required": ["id", "label", "hypothesis"]}},
        "actions": {"type": "array", "maxItems": 8, "items": {
            "type": "object",
            "properties": {"tool": {"type": "string"},
                           "params": {"type": "object"},
                           "reason": {"type": "string"},
                           "priority": {"type": "integer", "minimum": 5,
                                        "maximum": 90},
                           "variant": {"type": "string"},
                           "hypothesis": {"type": "string"},
                           "title": {"type": "string"}},
            "required": ["tool", "params", "reason"]}},
        "correlations": {"type": "array", "maxItems": 8,
                         "description": "Explicit evidence-backed semantic finding grouping decisions; never group by title, CWE, URL or severity alone.",
                         "items": {"type": "object", "properties": {
                             "action": {"type": "string", "enum": ["finding.correlate", "finding.merge", "finding.split", "finding.add_location"]},
                             "params": {"type": "object"}},
                             "required": ["action", "params"]}},
        "criteria": {"type": "array", "maxItems": 12,
                     "description": "Definition-of-done claims for LOADED skills: "
                                    "satisfied (cite evidence that exists in the "
                                    "knowledge), blocked or not_applicable (with a "
                                    "note).",
                     "items": {"type": "object",
                               "properties": {
                                   "skill": {"type": "string"},
                                   "id": {"type": "string"},
                                   "status": {"type": "string",
                                              "enum": ["satisfied", "blocked",
                                                       "not_applicable"]},
                                   "evidence": {"type": "array",
                                                "items": {"type": "string"}},
                                   "note": {"type": "string"}},
                               "required": ["skill", "id", "status"]}},
        "model": {"type": "object",
                  "description": "Security model updates: {entities: [{kind, name, "
                                 "attributes?}], relations: [{src: {kind, name}, rel, "
                                 "dst: {kind, name}, basis?, evidence?}], "
                                 "expectations: [{subject: {kind, name}, operation, "
                                 "resource: {kind, name}, expected: allow|deny, "
                                 "basis, evidence?, note?}]}"},
        "replies": {"type": "array", "maxItems": 8,
                    "description": "One concise reply per operator message (by its "
                                   "id), only when OPERATOR MESSAGES are present.",
                    "items": {
                        "type": "object",
                        "properties": {"id": {"type": "string"},
                                       "reply": {"type": "string",
                                                 "maxLength": REPLY_MAX}},
                        "required": ["id", "reply"]}},
    },
    "required": ["reasoning", "assessment", "actions"],
}
PROPOSAL_TOOL_NAME = "propose"
PROPOSAL_TOOL_DESCRIPTION = (
    "Submit your analysis, plan and the next actions for the assessment. Call this "
    "exactly once; be concise.")


# ---------------------------------------------------------------- extraction
_FENCE = re.compile(r"```(?:json|JSON)?[ \t]*\r?\n?(.*?)(?:```|\Z)", re.DOTALL)


def _strip_trailing_commas(s: str) -> str:
    """Remove ``,`` that directly precede ``}``/``]`` (outside strings)."""
    out: list[str] = []
    in_str = esc = False
    for i, c in enumerate(s):
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == ",":
            j = i + 1
            while j < len(s) and s[j] in " \t\r\n":
                j += 1
            if j < len(s) and s[j] in "}]":
                continue
        out.append(c)
    return "".join(out)


def _loads(s: str) -> Any:
    return json.loads(_strip_trailing_commas(s), strict=False)


def _candidate_text(text: str) -> str:
    """The most JSON-looking part of a reply: the first fenced block that contains a
    ``{``, else the whole text."""
    s = text.strip()
    for m in _FENCE.finditer(s):
        if "{" in m.group(1):
            return m.group(1)
    return s


def _scan(s: str, start: int) -> tuple[int | None, list[tuple[int, str]], bool, str]:
    """Walk the object starting at ``start``. Returns ``(end, checkpoints, in_str,
    closers)``: ``end`` is the index of the closing brace when balanced (else None);
    ``checkpoints`` are ``(index, closers)`` after each completed value (``closers``
    = the still-open containers as the characters that close them); ``in_str`` and
    ``closers`` describe the state at the end of the text."""
    stack: list[str] = []
    checkpoints: list[tuple[int, str]] = []
    weak: list[tuple[int, str]] = []             # after a string: last resort
    in_str = esc = False
    for i in range(start, len(s)):
        c = s[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
                weak.append((i, "".join(reversed(stack))))
            continue
        if c == '"':
            in_str = True
        elif c in "{[":
            stack.append("}" if c == "{" else "]")
        elif c in "}]":
            if stack:
                stack.pop()
            if not stack:
                return i, checkpoints, False, ""
            if len(stack) <= 2:                  # a whole top-level item closed
                checkpoints.append((i, "".join(reversed(stack))))
    return None, checkpoints + weak[-20:], in_str, "".join(reversed(stack))


def extract_object(text: str) -> tuple[Any, bool]:
    """The first JSON object in ``text`` as ``(value, repaired)``. A truncated or
    slightly broken object is repaired (the longest valid prefix, containers closed);
    raises :class:`ProposalError` only when no object can be recovered."""
    s = _candidate_text(text)
    start = s.find("{")
    if start < 0:
        raise ProposalError("no JSON object found in the reply")
    end, checkpoints, in_str, closers = _scan(s, start)
    if end is not None:
        try:
            return _loads(s[start:end + 1]), False
        except ValueError:
            pass                                  # fall through to the repair path
    attempts: list[str] = []
    # Prefer whole items: cut back to the latest completed top-level item (an action,
    # a hypothesis, a todo step, a whole array) and close what is still open, so a
    # half-written action is dropped rather than half-applied.
    strong = [c for c in checkpoints if s[c[0]] in "}]"]
    for idx, cl in reversed(strong[-60:]):
        attempts.append(s[start:idx + 1] + cl)
    if end is None:
        # nothing whole to cut back to (e.g. the reasoning itself was cut): close the
        # open string and containers
        tail = s[start:].rstrip()
        if in_str:
            tail += '"'
        attempts.append(tail + closers)
        attempts.append(re.sub(r'(,|:)\s*$', "", tail).rstrip() + closers)
    for idx, cl in reversed([c for c in checkpoints if s[c[0]] == '"']):
        attempts.append(s[start:idx + 1] + cl)
    for cand in attempts:
        try:
            val = _loads(cand)
        except ValueError:
            continue
        if isinstance(val, dict) and val:
            return val, True
    raise ProposalError("no complete JSON content could be recovered from the reply")


def extract_json(text: str) -> str:
    """Back-compat helper: the repaired first JSON object as a string."""
    val, _ = extract_object(text)
    return json.dumps(val)


# ------------------------------------------------------------------ coercion
def _s(v: Any, n: int) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        v = json.dumps(v, default=str)
    return " ".join(str(v).split())[:n]


def slug_id(v: Any, fallback: str = "") -> str:
    s = re.sub(r"[^a-z0-9_-]+", "-", str(v or "").lower()).strip("-")[:16].strip("-")
    return s or fallback


_PRIORITY_WORDS = {"critical": 5, "urgent": 5, "high": 15, "medium": 30, "normal": 30,
                   "low": 60, "info": 80}


def _priority(v: Any) -> int:
    if isinstance(v, bool):
        return 25
    if isinstance(v, str):
        w = v.strip().lower()
        if w in _PRIORITY_WORDS:
            v = _PRIORITY_WORDS[w]
        else:
            m = re.search(r"-?\d+", w)
            v = int(m.group(0)) if m else 25
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        n = 25
    return max(5, min(90, n))


_TODO_STATUS = {"pending": "pending", "todo": "pending", "open": "pending",
                "not_started": "pending", "in_progress": "in_progress",
                "in-progress": "in_progress", "doing": "in_progress",
                "active": "in_progress", "running": "in_progress", "done": "done",
                "completed": "done", "complete": "done", "finished": "done"}


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        return [v]
    return [v]


def _as_dict(v: Any) -> dict[str, Any]:
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip().startswith("{"):
        try:
            d = _loads(v)
            return d if isinstance(d, dict) else {}
        except ValueError:
            return {}
    return {}


def coerce(obj: Any, *, repaired: bool = False) -> Proposal:
    """Build a :class:`Proposal` from whatever object the model produced, dropping
    what is unusable. Raises :class:`ProposalError` when nothing usable is left."""
    notes: list[str] = []
    if isinstance(obj, list):                       # a bare list of actions
        obj = {"actions": obj}
    if not isinstance(obj, dict):
        raise ProposalError("the reply is not a JSON object")
    # wrappers such as {"propose": {...}} / {"input": {...}} / {"proposal": {...}}
    keys = ("reasoning", "actions", "hypotheses", "todolist", "replies")
    if not any(k in obj for k in keys):
        for v in obj.values():
            if isinstance(v, dict) and any(k in v for k in keys):
                obj = v
                break

    reasoning = _s(obj.get("reasoning"), 2000)
    summary = _s(obj.get("summary"), 200)
    assessment = str(obj.get("assessment") or "").strip().lower()
    assessment = "adequate" if assessment == "adequate" else "incomplete"

    todos: list[TodoStep] = []
    for i, t in enumerate(_as_list(obj.get("todolist"))):
        if isinstance(t, str):
            t = {"step": t}
        if not isinstance(t, dict):
            notes.append(f"todo #{i + 1} dropped: not an object")
            continue
        step = _s(t.get("step") or t.get("title") or t.get("text"), 200)
        if not step:
            notes.append(f"todo #{i + 1} dropped: no step text")
            continue
        status = _TODO_STATUS.get(str(t.get("status") or "pending").strip().lower(),
                                  "pending")
        todos.append(TodoStep(step=step, status=status))
    if len(todos) > MAX_TODOS:
        notes.append(f"{len(todos) - MAX_TODOS} todo step(s) beyond {MAX_TODOS} dropped")
        todos = todos[:MAX_TODOS]

    hyps: list[Hypothesis] = []
    seen: set[str] = set()
    for i, h in enumerate(_as_list(obj.get("hypotheses"))):
        if isinstance(h, str):
            h = {"hypothesis": h}
        if not isinstance(h, dict):
            notes.append(f"hypothesis #{i + 1} dropped: not an object")
            continue
        text = _s(h.get("hypothesis") or h.get("description"), 600)
        label = _s(h.get("label") or h.get("title") or h.get("name"), 120)
        if not (text or label):
            notes.append(f"hypothesis #{i + 1} dropped: no label or text")
            continue
        hid = slug_id(h.get("id"), "") or slug_id(label, "") or f"h{i + 1}"
        base, n = hid, 2
        while hid in seen:                          # keep ids distinct
            hid = f"{base[:13]}-{n}"
            n += 1
        seen.add(hid)
        try:
            signals = _as_dict(h.get("signals"))
            declaration = _as_dict(h.get("investigation"))
            declaration.update({k: h[k] for k in (
                "operation", "expected_property", "prerequisites",
                "required_observations", "planned_verification", "progress", "evidence",
                "available_tools", "next_action", "state", "blocking_condition",
                "final_outcome")
                if h.get(k) not in (None, "", [], {})})
            if declaration:
                signals["investigation"] = declaration
            hyps.append(Hypothesis(id=hid, label=label or text[:120],
                                   hypothesis=text or label, signals=signals,
                                   operation=_as_dict(h.get("operation")),
                                   expected_property=_s(h.get("expected_property"), 400),
                                   prerequisites=[x for x in _as_list(h.get("prerequisites"))
                                                  if isinstance(x, dict)][:20],
                                   required_observations=[_s(x, 160) for x in
                                                          _as_list(h.get("required_observations"))
                                                          if _s(x, 160)][:20],
                                   planned_verification=_as_dict(h.get("planned_verification")),
                                   progress=_as_dict(h.get("progress")),
                                   investigation=declaration))
        except ValidationError as exc:
            notes.append(f"hypothesis #{i + 1} dropped: {str(exc)[:80]}")
    if len(hyps) > MAX_HYPOTHESES:
        notes.append(f"{len(hyps) - MAX_HYPOTHESES} hypothesis(es) beyond "
                     f"{MAX_HYPOTHESES} dropped")
        hyps = hyps[:MAX_HYPOTHESES]
    known = {h.id for h in hyps}

    actions: list[Action] = []
    for i, a in enumerate(_as_list(obj.get("actions"))):
        if not isinstance(a, dict):
            notes.append(f"action #{i + 1} dropped: not an object")
            continue
        tool = str(a.get("tool") or a.get("tool_id") or a.get("name") or "").strip()
        if not (3 <= len(tool) <= 48) or re.search(r"\s", tool):
            notes.append(f"action #{i + 1} dropped: bad tool {tool[:30]!r}")
            continue
        variant = _s(a.get("variant"), 60).lower().replace(" ", "-")
        if not re.fullmatch(r"[a-z0-9_-]{0,60}", variant):
            variant = ""
        title = _s(a.get("title"), 120)
        hid = slug_id(a.get("hypothesis")) or None
        if hid is not None and hid not in known:
            hid = None                                # dangling reference: no lead
        try:
            actions.append(Action(
                tool=tool, params=_as_dict(a.get("params")),
                reason=_s(a.get("reason") or a.get("rationale"), 400)
                or title or "proposed by the exploration agent",
                priority=_priority(a.get("priority")), variant=variant,
                hypothesis=hid, title=title))
        except ValidationError as exc:
            notes.append(f"action #{i + 1} dropped: {str(exc)[:80]}")
    if len(actions) > MAX_ACTIONS:
        notes.append(f"{len(actions) - MAX_ACTIONS} action(s) beyond {MAX_ACTIONS} "
                     "dropped")
        actions = actions[:MAX_ACTIONS]

    correlations: list[CorrelationAction] = []
    for i, item in enumerate(_as_list(obj.get("correlations"))[:8]):
        if not isinstance(item, dict):
            notes.append(f"correlation #{i + 1} dropped: not an object")
            continue
        try:
            correlations.append(CorrelationAction(
                action=str(item.get("action") or ""),
                params=_as_dict(item.get("params"))))
        except ValidationError as exc:
            notes.append(f"correlation #{i + 1} dropped: {str(exc)[:80]}")

    replies = _replies(obj.get("replies"), notes)
    from src.greybox_web import skillbook
    criteria = skillbook.clean_claims(obj.get("criteria"))
    model = obj.get("model") if isinstance(obj.get("model"), dict) else {}

    if not (reasoning or todos or hyps or actions or correlations or replies or criteria or model):
        raise ProposalError("the reply has no usable content (no reasoning, todo "
                            "steps, hypotheses, actions or replies)")
    if repaired:
        # A cut-off reply never ends the assessment: "adequate" needs a whole reply.
        assessment = "incomplete"
        notes.append("reply was truncated or malformed and was repaired")
    return Proposal(reasoning=reasoning, summary=summary, assessment=assessment, todolist=todos,
                    hypotheses=hyps, actions=actions, correlations=correlations, replies=replies, notes=notes,
                    repaired=repaired, criteria=criteria, model=model)


def _replies(raw: Any, notes: list[str]) -> list[Reply]:
    """Replies to operator messages: ``[{id, reply}]`` (also ``{"m1": "..."}`` or
    ``text``/``message`` for ``reply``). Ids are normalised (``M1`` -> ``m1``); the
    first reply per id wins; text is clamped to ``REPLY_MAX``."""
    if isinstance(raw, dict) and raw and all(isinstance(v, str) for v in raw.values()) \
            and not ({"id", "reply"} & set(raw)):
        raw = [{"id": k, "reply": v} for k, v in raw.items()]
    out: list[Reply] = []
    seen: set[str] = set()
    for i, r in enumerate(_as_list(raw)):
        if not isinstance(r, dict):
            notes.append(f"reply #{i + 1} dropped: not an object")
            continue
        rid = slug_id(r.get("id") or r.get("message_id"))
        text = _s(r.get("reply") or r.get("text") or r.get("answer"), REPLY_MAX)
        if not rid or not text:
            notes.append(f"reply #{i + 1} dropped: no id or no text")
            continue
        if rid in seen:
            continue
        seen.add(rid)
        out.append(Reply(id=rid, reply=text))
    if len(out) > MAX_REPLIES:
        notes.append(f"{len(out) - MAX_REPLIES} reply(ies) beyond {MAX_REPLIES} dropped")
        out = out[:MAX_REPLIES]
    return out


def parse_reply(text: str, *, truncated: bool = False) -> Proposal:
    """A tolerant parse of the model's text. ``truncated`` marks a reply the provider
    cut at the output limit (so ``assessment`` can never be ``adequate``). Raises
    :class:`ProposalError` only when there is nothing usable."""
    obj, repaired = extract_object(text)
    return coerce(obj, repaired=repaired or truncated)


def parse_structured(obj: Any, *, truncated: bool = False) -> Proposal:
    """The same, for an already-decoded tool-call input / structured output."""
    return coerce(obj, repaired=truncated)


def repair_message(error: ProposalError) -> str:
    return (f"Your previous reply was not usable and NOT applied: {error}. "
            "Reply again with the single JSON object only (reasoning, assessment, "
            "todolist, hypotheses, actions, and replies when operator messages are "
            "present), concise: reasoning at most 6 sentences, "
            "at most 8 todo steps and 8 actions.")
