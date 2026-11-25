"""``skill.read``: load an investigation skill (progressive disclosure, layer 2).

No I/O against the target: the tool reads a playbook shipped with the platform and
records the load as an observation (``skill.loaded|<name>``), which is what makes the
skill *active* for the rest of the run — including after a resume — and what puts
its definition of done into the knowledge and the coverage verdict. Reading a
reference or a script template records ``skill.part|<name>|<part>``; the text is
shown to the agent in the trusted prompt section of the next cycle.
"""
from __future__ import annotations

from datetime import datetime, timezone

from src.greybox_web import modes, skillbook
from src.greybox_web.tools import Observation, ToolContext, ToolResult

PARTS_HINT = "playbook (default), reference, or script:<file>"


async def read(ctx: ToolContext) -> ToolResult:
    name = str(ctx.params.get("name") or "").strip()
    part = str(ctx.params.get("part") or "playbook").strip() or "playbook"
    if not skillbook.enabled():
        return ToolResult(summary="skills are disabled on this platform")
    skill = skillbook.catalogue().get(name)
    usable = {s.name for s in skillbook.available(
        ctx.scope.mode, modes.for_scope(ctx.scope).allowed)}
    if skill is None or name not in usable:
        return ToolResult(summary=f"skill.read: no usable skill {name!r} in this "
                                  f"assessment; available: "
                                  f"{', '.join(sorted(usable)) or 'none'}")
    try:
        text = skillbook.read(name, None if part == "playbook" else part)
    except KeyError as exc:
        return ToolResult(summary=f"skill.read {name}: {exc.args[0]} ({PARTS_HINT})")
    now = datetime.now(timezone.utc).isoformat()
    if part == "playbook":
        obs = Observation(
            key=f"{skillbook.LOADED_PREFIX}{name}",
            label=f"skill loaded: {name} — {skill.description}"[:300],
            facts={"skill": name, "at": now,
                   "phases": [p.id for p in skill.phases],
                   "criteria": [c.id for c in skill.criteria],
                   "references": list(skill.references),
                   "scripts": list(skill.scripts),
                   "chars": len(text)})
        summary = (f"skill {name} loaded: {len(skill.phases)} phase(s), "
                   f"{len(skill.criteria)} completion criteria; its playbook is shown "
                   f"in ACTIVE SKILLS from now on")
    else:
        obs = Observation(
            key=f"skill.part|{name}|{part}"[:300],
            label=f"skill {name}: {part} read",
            facts={"skill": name, "part": part, "at": now, "chars": len(text)})
        summary = f"skill {name}: {part} read ({len(text)} chars; shown next cycle)"
    return ToolResult(summary=summary, counts={"chars": len(text)}, observations=[obs])
