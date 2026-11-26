"""Investigation skills: progressive-disclosure methodology for the reasoning agent.

Tools give the agent *capabilities* (browser, HTTP, TCP, sandboxed code). Skills give
it *expertise*: how to investigate a kind of problem, what counts as evidence, which
alternative to try when a method stalls, and when the investigation is done. They are
Markdown playbooks under ``src/greybox_web/skills/<name>/``::

    SKILL.md        frontmatter (name, description, when, requires, modes, phases,
                    criteria) + the playbook body
    reference.md    optional deeper reference, loaded only on request
    scripts/*.py    optional analyser templates for ``tool.compose``

Progressive disclosure:

* **Layer 1 — index.** A bounded list (name, one-line description, when to use) of
  the skills this run can use (mode and capabilities) is part of the system prompt,
  so discovery never depends on the model inspecting tool metadata.
* **Layer 2 — on demand.** ``skill.read {name, part?}`` is an ordinary registered
  tool: proposed with a reason, admitted, executed as an audited work order. A
  loaded skill's playbook is then shown to the agent in a TRUSTED prompt section
  (platform content, never mixed with untrusted target data) for the rest of the run.

Definition of done. Each skill declares criteria. A criterion may carry an
``evidence`` predicate the ENGINE evaluates against the run's persisted state (work
orders, assets, observations, findings, authentication states), plus ``na_when`` and
``blocked_when`` conditions. The agent may also *claim* a status in its reply
(``criteria`` field); a claimed ``satisfied`` only counts when it cites evidence that
exists in the run. Statuses: satisfied · unsatisfied · blocked · not_applicable. The
coverage verdict reads them (``coverage.assess``), so an investigation blocked by
missing access is distinguished from one that is simply unfinished.

Everything here is derived from the database (skill loads and claims are graph
observations), so skill state survives a resumed run without extra storage.
"""
from __future__ import annotations

import functools
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SKILLS_DIR = Path(__file__).parent / "skills"
ENABLE_ENV = "VIGILO_GREYBOX_SKILLS"            # "off" disables (baseline evaluation)
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,39}$")
BODY_CAP = 9_000
REFERENCE_CAP = 12_000
SCRIPT_CAP = 8_000
INDEX_CAP = 12

SATISFIED = "satisfied"
UNSATISFIED = "unsatisfied"
BLOCKED = "blocked"
NOT_APPLICABLE = "not_applicable"
STATUSES = (SATISFIED, UNSATISFIED, BLOCKED, NOT_APPLICABLE)
CLAIMABLE = (SATISFIED, BLOCKED, NOT_APPLICABLE)
# why a criterion is blocked: drives the coverage outcome
BLOCK_CATEGORIES = ("authentication", "authorisation", "capability", "target")

LOADED_PREFIX = "skill.loaded|"
CLAIM_PREFIX = "skill.claim|"

_PREDICATES = {"tool_done", "asset", "observation", "finding", "all_tested", "any",
               "all", "identities"}
_CONDITIONS = {"capability_missing", "mode_not", "auth_state", "no_asset",
               "identities_lt", "any"}


class SkillError(ValueError):
    """A malformed skill file (raised at load time: a bad skill never ships)."""


@dataclass(frozen=True)
class Criterion:
    id: str
    text: str
    phase: str | None = None
    evidence: dict | None = None        # engine-evaluated predicate (None: claim only)
    na_when: dict | None = None
    blocked_when: dict | None = None
    blocked_category: str = "target"


@dataclass(frozen=True)
class Phase:
    id: str
    title: str


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    when: str
    requires: tuple[str, ...]
    modes: tuple[str, ...]
    phases: tuple[Phase, ...]
    criteria: tuple[Criterion, ...]
    body: str
    path: Path
    references: tuple[str, ...] = ()
    scripts: tuple[str, ...] = ()


def enabled() -> bool:
    return (os.environ.get(ENABLE_ENV) or "on").strip().lower() not in ("off", "0",
                                                                       "false", "no")


# ------------------------------------------------------------------ loading


def _parse(path: Path) -> Skill:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise SkillError(f"{path}: missing frontmatter")
    _, front, body = text.split("---\n", 2)
    meta = yaml.safe_load(front) or {}
    name = str(meta.get("name") or "")
    if not NAME_RE.match(name) or name != path.parent.name:
        raise SkillError(f"{path}: name must be a slug equal to the directory name")
    desc = str(meta.get("description") or "").strip()
    if not 10 <= len(desc) <= 200:
        raise SkillError(f"{name}: description must be 10-200 characters")
    phases = tuple(Phase(str(p["id"]), str(p.get("title") or p["id"]))
                   for p in meta.get("phases") or ())
    phase_ids = {p.id for p in phases}
    crits: list[Criterion] = []
    for c in meta.get("criteria") or ():
        cid = str(c.get("id") or "")
        if not NAME_RE.match(cid):
            raise SkillError(f"{name}: criterion id {cid!r} is not a slug")
        if any(x.id == cid for x in crits):
            raise SkillError(f"{name}: duplicate criterion {cid}")
        phase = c.get("phase")
        if phase is not None and str(phase) not in phase_ids:
            raise SkillError(f"{name}/{cid}: unknown phase {phase}")
        for key, vocab in (("evidence", _PREDICATES), ("na_when", _CONDITIONS),
                           ("blocked_when", _CONDITIONS)):
            _check_vocab(c.get(key), vocab, f"{name}/{cid}.{key}")
        cat = str(c.get("blocked_category") or "target")
        if cat not in BLOCK_CATEGORIES:
            raise SkillError(f"{name}/{cid}: blocked_category {cat!r} unknown")
        crits.append(Criterion(cid, str(c.get("text") or "").strip(),
                               str(phase) if phase is not None else None,
                               c.get("evidence"), c.get("na_when"),
                               c.get("blocked_when"), cat))
    body = body.strip()
    if len(body) > BODY_CAP:
        raise SkillError(f"{name}: playbook body exceeds {BODY_CAP} characters")
    refs = tuple(sorted(p.name for p in path.parent.glob("*.md") if p.name != "SKILL.md"))
    scripts = tuple(sorted(p.name for p in (path.parent / "scripts").glob("*.py"))) \
        if (path.parent / "scripts").is_dir() else ()
    return Skill(name=name, description=desc,
                 when=str(meta.get("when") or "").strip()[:200],
                 requires=tuple(str(x) for x in meta.get("requires") or ()),
                 modes=tuple(str(x) for x in meta.get("modes") or ("web",)),
                 phases=phases, criteria=tuple(crits), body=body, path=path,
                 references=refs, scripts=scripts)


def _check_vocab(pred: Any, vocab: set[str], where: str) -> None:
    if pred is None:
        return
    if not isinstance(pred, dict) or not pred:
        raise SkillError(f"{where}: must be a mapping")
    for k, v in pred.items():
        if k not in vocab:
            raise SkillError(f"{where}: unknown key {k!r}")
        if k in ("any", "all"):
            if not isinstance(v, list):
                raise SkillError(f"{where}.{k}: must be a list")
            for sub in v:
                _check_vocab(sub, vocab, f"{where}.{k}")


@functools.lru_cache(maxsize=1)
def catalogue() -> dict[str, Skill]:
    """Every skill shipped with this build (validated; cached)."""
    out: dict[str, Skill] = {}
    for p in sorted(SKILLS_DIR.glob("*/SKILL.md")):
        s = _parse(p)
        out[s.name] = s
    return out


def available(mode: str, capabilities: set[str] | frozenset[str]) -> list[Skill]:
    """Skills this run can use: its mode, and every required capability present."""
    if not enabled():
        return []
    return [s for s in catalogue().values()
            if mode in s.modes and set(s.requires) <= set(capabilities)][:INDEX_CAP]


def index_text(mode: str, capabilities) -> str:
    """Layer 1: the compact index for the system prompt ('' when none apply)."""
    skills = available(mode, capabilities)
    if not skills:
        return ""
    lines = [f"- {s.name}: {s.description}" + (f" Use when: {s.when}" if s.when else "")
             for s in skills]
    return ("SKILLS (methodology playbooks; load one with skill.read {\"name\": ...} "
            "BEFORE starting the kind of work it covers — its playbook, phases and "
            "definition of done are then shown to you every cycle). Available:\n"
            + "\n".join(lines) + "\nLoaded skills list criteria under knowledge "
            "skills.loaded: satisfy them with evidence, or claim them in your reply's "
            "\"criteria\" field: [{\"skill\", \"id\", \"status\": "
            "satisfied|blocked|not_applicable, \"evidence\": [observation keys, "
            "endpoint URLs or finding titles], \"note\"}]. \"blocked\" means an "
            "external obstacle more work cannot remove (no access, no capability); "
            "work you have simply not done yet stays unclaimed.")


def read(name: str, part: str | None = None) -> str:
    """Layer 2: a skill's playbook, a reference document or a script template."""
    s = catalogue().get(name)
    if s is None:
        raise KeyError(f"unknown skill {name!r}; available: "
                       f"{', '.join(sorted(catalogue()))}")
    if not part or part == "playbook":
        return s.body
    if part.startswith("script:"):
        fname = part.split(":", 1)[1]
        if fname not in s.scripts:
            raise KeyError(f"{name} has no script {fname!r}; scripts: "
                           f"{', '.join(s.scripts) or 'none'}")
        return (s.path.parent / "scripts" / fname).read_text("utf-8")[:SCRIPT_CAP]
    fname = part if part.endswith(".md") else f"{part}.md"
    if fname not in s.references:
        raise KeyError(f"{name} has no reference {part!r}; references: "
                       f"{', '.join(s.references) or 'none'}")
    return (s.path.parent / fname).read_text("utf-8")[:REFERENCE_CAP]


# ------------------------------------------------------------------ run facts


@dataclass
class RunFacts:
    """What a definition-of-done predicate may look at (read once per evaluation)."""

    mode: str = "web"
    capabilities: frozenset[str] = frozenset()
    work: list[dict] = field(default_factory=list)          # {id, tool, status, target}
    assets: list[dict] = field(default_factory=list)        # {kind, key, data, tested}
    observations: list[dict] = field(default_factory=list)  # {key, facts}
    findings: list[dict] = field(default_factory=list)      # {check, title, status}
    auth_states: tuple[str, ...] = ()
    identities: int = 1                                     # anon + sessions known
    loaded: dict[str, dict] = field(default_factory=dict)   # skill -> load facts
    claims: dict[tuple[str, str], dict] = field(default_factory=dict)
    parts: list[dict] = field(default_factory=list)         # {skill, part, at}


async def run_facts(session, run_id, scope, *, identities: int | None = None) -> RunFacts:
    from sqlalchemy import select

    from src.greybox_web import modes
    from src.greybox_web.exploration.knowledge import _target
    from src.greybox_web.models import (
        GreyboxAsset,
        GreyboxFinding,
        GreyboxGraphNode,
        GreyboxRun,
        GreyboxWorkOrder,
    )
    run = await session.get(GreyboxRun, run_id)
    wos = (await session.scalars(select(GreyboxWorkOrder).where(
        GreyboxWorkOrder.run_id == run_id))).all()
    assets = (await session.scalars(select(GreyboxAsset).where(
        GreyboxAsset.run_id == run_id, GreyboxAsset.in_scope.is_(True)))).all()
    obs = (await session.scalars(select(GreyboxGraphNode).where(
        GreyboxGraphNode.run_id == run_id,
        GreyboxGraphNode.kind == "observation"))).all()
    finds = (await session.scalars(select(GreyboxFinding).where(
        GreyboxFinding.run_id == run_id))).all()
    f = RunFacts(mode=scope.mode,
                 capabilities=modes.for_scope(scope).allowed,
                 auth_states=tuple((run.auth_states or []) if run else ()))
    f.work = [{"id": str(w.id), "tool": w.tool, "status": w.status,
               "target": f"{w.tool} {_target(w)}"} for w in wos]
    f.assets = [{"kind": a.kind, "key": a.key, "data": a.data or {},
                 "tested": bool(a.tested)} for a in assets]
    for n in obs:
        facts = (n.data or {}).get("facts") or {}
        if n.key.startswith(LOADED_PREFIX):
            f.loaded[n.key[len(LOADED_PREFIX):]] = facts
        elif n.key.startswith(CLAIM_PREFIX):
            _, skill, cid = n.key.split("|", 2)
            f.claims[(skill, cid)] = facts
        elif n.key.startswith("skill.part|"):
            f.parts.append({"skill": facts.get("skill"), "part": facts.get("part"),
                            "at": str(facts.get("at") or "")})
        else:
            f.observations.append({"key": n.key, "facts": facts})
    f.findings = [{"check": x.check_id, "title": x.title, "status": x.status}
                  for x in finds]
    labels = set()
    for o in f.observations:
        ident = (o["facts"] or {}).get("identity") if isinstance(o["facts"], dict) else None
        if ident:
            labels.add(ident)
        acct = (o["facts"] or {}).get("account") if isinstance(o["facts"], dict) else None
        if acct and o["key"].startswith("auth.login|") and \
                (o["facts"] or {}).get("cookie_names") is not None:
            labels.add(acct)
    f.identities = identities if identities is not None else max(1, len(labels | {"anon"}))
    return f


# ------------------------------------------------------------------ predicates


def _api(a: dict) -> bool:
    from urllib.parse import urlsplit
    path = urlsplit(a["key"]).path
    ct = str(a["data"].get("content_type") or "")
    return path.startswith("/api/") or path == "/api" or "json" in ct \
        or bool(a["data"].get("api"))


def _asset_match(a: dict, spec: dict) -> bool:
    if spec.get("kind") and a["kind"] != spec["kind"]:
        return False
    if "api" in spec and _api(a) != bool(spec["api"]):
        return False
    if spec.get("source_prefix"):
        srcs = [str(s) for s in a["data"].get("source") or []]
        if not any(s.startswith(spec["source_prefix"]) for s in srcs):
            return False
    if spec.get("key_regex") and not re.search(spec["key_regex"], a["key"]):
        return False
    if "tested" in spec and a["tested"] != bool(spec["tested"]):
        return False
    return True


def _evidence(pred: dict, f: RunFacts) -> tuple[bool, list[str]]:
    """(satisfied, evidence refs). All keys of one mapping must hold."""
    refs: list[str] = []
    for key, spec in pred.items():
        if key == "tool_done":
            tools = spec if isinstance(spec, list) else [spec]
            # "tool.*" means an agent-written tool RAN: defining one is not it
            hit = [w["target"] for w in f.work if w["status"] == "done"
                   and w["tool"] not in ("tool.compose", "tool.define") and any(
                       w["tool"] == t or (t.endswith("*")
                                          and w["tool"].startswith(t[:-1]))
                       for t in tools)]
            if not hit:
                return False, []
            refs += hit[:3]
        elif key == "asset":
            hit = [a["key"] for a in f.assets if _asset_match(a, spec)]
            if len(hit) < int(spec.get("min", 1)):
                return False, []
            refs += hit[:3]
        elif key == "all_tested":
            pool = [a for a in f.assets
                    if _asset_match(a, {k: v for k, v in spec.items() if k != "tested"})]
            if not pool or not all(a["tested"] for a in pool):
                return False, []
            refs += [a["key"] for a in pool[:3]]
        elif key == "observation":
            hit = [o["key"] for o in f.observations
                   if o["key"].startswith(spec.get("key_prefix", ""))
                   and (not spec.get("fact") or (isinstance(o["facts"], dict)
                                                 and o["facts"].get(spec["fact"])))]
            if len(hit) < int(spec.get("min", 1)):
                return False, []
            refs += hit[:3]
        elif key == "finding":
            statuses = spec.get("status") or ["verified", "candidate", "rejected"]
            hit = [x["title"] for x in f.findings
                   if x["check"].startswith(spec.get("check_prefix", ""))
                   and x["status"] in statuses]
            if len(hit) < int(spec.get("min", 1)):
                return False, []
            refs += hit[:3]
        elif key == "identities":
            if f.identities < int(spec.get("min", 2)):
                return False, []
            refs.append(f"{f.identities} identities")
        elif key == "any":
            for sub in spec:
                ok, r = _evidence(sub, f)
                if ok:
                    refs += r
                    break
            else:
                return False, []
        elif key == "all":
            for sub in spec:
                ok, r = _evidence(sub, f)
                if not ok:
                    return False, []
                refs += r
    return True, refs


def _condition(cond: dict | None, f: RunFacts) -> str | None:
    """A human reason when ``cond`` holds, else None."""
    if not cond:
        return None
    for key, spec in cond.items():
        if key == "capability_missing" and spec not in f.capabilities:
            return f"the {spec} capability is not available in this assessment"
        if key == "mode_not" and f.mode not in (spec if isinstance(spec, list) else [spec]):
            return f"not applicable to a {f.mode} assessment"
        if key == "auth_state":
            hit = [s for s in f.auth_states if s in (spec if isinstance(spec, list)
                                                    else [spec])]
            if hit:
                return f"authentication boundary: {', '.join(hit)}"
        if key == "no_asset" and not any(_asset_match(a, spec) for a in f.assets):
            return "no such surface was discovered"
        if key == "identities_lt" and f.identities < int(spec):
            return (f"only {f.identities} identity(ies) available; {spec} needed "
                    f"(provide test accounts)")
        if key == "any":
            for sub in spec:
                r = _condition(sub, f)
                if r:
                    return r
    return None


def _claim_ok(refs: list, f: RunFacts) -> list[str]:
    """The cited references that exist in the run (exact or long-prefix matches)."""
    corpus = ([o["key"] for o in f.observations] + [a["key"] for a in f.assets]
              + [x["title"] for x in f.findings] + [w["target"] for w in f.work])
    ok: list[str] = []
    for r in refs or []:
        r = str(r).strip()
        if len(r) < 4:
            continue
        if any(c == r or (len(r) >= 8 and (c.startswith(r) or r in c)) for c in corpus):
            ok.append(r[:200])
    return ok


@dataclass(frozen=True)
class CriterionState:
    skill: str
    id: str
    text: str
    phase: str | None
    status: str
    by: str                     # engine | agent | none
    refs: tuple[str, ...] = ()
    note: str = ""
    category: str | None = None  # for blocked

    def as_dict(self) -> dict[str, Any]:
        d = {"id": self.id, "text": self.text, "status": self.status, "by": self.by}
        if self.phase:
            d["phase"] = self.phase
        if self.refs:
            d["evidence"] = list(self.refs)[:3]
        if self.note:
            d["note"] = self.note[:200]
        if self.category:
            d["blocked_by"] = self.category
        return d


def evaluate(skill: Skill, f: RunFacts) -> list[CriterionState]:
    """The definition-of-done state of one skill for this run."""
    out: list[CriterionState] = []
    for c in skill.criteria:
        claim = f.claims.get((skill.name, c.id)) or {}
        # Evidence that exists wins: a criterion the run demonstrably met is
        # satisfied even when a not-applicable condition also holds (e.g. an
        # API-only target whose browser walk still observed API calls).
        if c.evidence:
            ok, refs = _evidence(c.evidence, f)
            if ok:
                out.append(CriterionState(skill.name, c.id, c.text, c.phase, SATISFIED,
                                          "engine", tuple(refs)))
                continue
        na = _condition(c.na_when, f)
        if na:
            out.append(CriterionState(skill.name, c.id, c.text, c.phase,
                                      NOT_APPLICABLE, "engine", note=na))
            continue
        blocked = _condition(c.blocked_when, f)
        if blocked:
            out.append(CriterionState(skill.name, c.id, c.text, c.phase, BLOCKED,
                                      "engine", note=blocked,
                                      category=c.blocked_category))
            continue
        st = claim.get("status")
        if st == SATISFIED:
            refs = _claim_ok(claim.get("evidence") or [], f)
            if refs:
                out.append(CriterionState(skill.name, c.id, c.text, c.phase,
                                          SATISFIED, "agent", tuple(refs),
                                          str(claim.get("note") or "")))
            else:
                out.append(CriterionState(
                    skill.name, c.id, c.text, c.phase, UNSATISFIED, "agent",
                    note="claimed satisfied without evidence that exists in the run"))
            continue
        if st in (BLOCKED, NOT_APPLICABLE) and str(claim.get("note") or "").strip():
            cat = claim.get("category") if claim.get("category") in BLOCK_CATEGORIES \
                else c.blocked_category
            out.append(CriterionState(skill.name, c.id, c.text, c.phase, st, "agent",
                                      note=str(claim.get("note"))[:300],
                                      category=cat if st == BLOCKED else None))
            continue
        out.append(CriterionState(skill.name, c.id, c.text, c.phase, UNSATISFIED,
                                  "none"))
    return out


def phase_states(skill: Skill, states: list[CriterionState]) -> list[dict]:
    """Gate status per phase: done (all criteria satisfied / n.a.), blocked (the
    rest done, some blocked), open."""
    out = []
    for p in skill.phases:
        crit = [s for s in states if s.phase == p.id]
        if not crit:
            status = "open"
        elif all(s.status in (SATISFIED, NOT_APPLICABLE) for s in crit):
            status = "done"
        elif all(s.status in (SATISFIED, NOT_APPLICABLE, BLOCKED) for s in crit):
            status = "blocked"
        else:
            status = "open"
        out.append({"id": p.id, "title": p.title, "gate": status})
    return out


async def run_state(session, run_id, scope, *, identities: int | None = None
                    ) -> list[dict]:
    """Every LOADED skill's phases and criteria for this run (knowledge, coverage
    and report read this)."""
    if not enabled():
        return []
    return state_from(await run_facts(session, run_id, scope, identities=identities))


def state_from(f: RunFacts) -> list[dict]:
    out = []
    for name in sorted(f.loaded, key=lambda n: str(f.loaded[n].get("at") or "")):
        skill = catalogue().get(name)
        if skill is None:
            continue
        states = evaluate(skill, f)
        phases = phase_states(skill, states)
        current = next((p["id"] for p in phases if p["gate"] == "open"), None)
        out.append({"name": name, "phase": current, "phases": phases,
                    "criteria": [s.as_dict() for s in states]})
    return out


def coverage_items(state: list[dict]) -> list[tuple[str, str, str, str | None, str]]:
    """(skill, criterion text, status, blocked category, note) for the verdict.

    Only an ENGINE-grounded block (a recorded identity-provider / expired session,
    too few identities, a missing capability) carries its category into the verdict
    and may make the outcome ``blocked`` / ``needs_authorisation``. An agent's own
    "blocked" claim is reported as a limitation of a partial assessment: models use
    "blocked" for "not done yet", and the outcome must rest on evidence."""
    return [(s["name"], c["text"], c["status"],
             c.get("blocked_by") if c.get("by") == "engine" else None,
             c.get("note", ""))
            for s in state for c in s["criteria"]]


def clean_claims(raw: Any) -> list[dict]:
    """Criterion claims from a model reply: validated shape, bounded."""
    out: list[dict] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        skill = str(item.get("skill") or "")
        cid = str(item.get("id") or item.get("criterion") or "")
        st = str(item.get("status") or "")
        if skill not in catalogue() or st not in CLAIMABLE or \
                cid not in {c.id for c in catalogue()[skill].criteria}:
            continue
        ev = item.get("evidence") or []
        out.append({"skill": skill, "id": cid, "status": st,
                    "evidence": [str(e)[:200] for e in
                                 (ev if isinstance(ev, list) else [ev])][:6],
                    "note": str(item.get("note") or "")[:300],
                    **({"category": item["category"]}
                       if item.get("category") in BLOCK_CATEGORIES else {})})
        if len(out) >= 12:
            break
    return out


def recent_parts(f: RunFacts, n: int = 1) -> list[dict]:
    return sorted(f.parts, key=lambda p: p["at"])[-n:]


def playbook_section(names: list[str], parts: list[dict] | None = None, *,
                     full: int = 2) -> str:
    """The TRUSTED prompt section: the full playbook of the most recently loaded
    skills (``full``), titles of the others, and the reference/script the agent read
    last. Read from the shipped files, never from run data. Criteria status lives
    in the knowledge."""
    names = [n for n in names if n in catalogue()]
    if not names:
        return ""
    extra = parts
    parts = ["## ACTIVE SKILLS (trusted platform methodology — follow it; the "
             "knowledge's skills.loaded shows each skill's phase gates and criteria)"]
    for name in names[-full:]:
        s = catalogue()[name]
        parts.append(f"### skill: {name}\n{s.body}")
    older = names[:-full]
    if older:
        parts.append("Also loaded (playbook shown when first loaded; re-read with "
                     "skill.read if needed): " + ", ".join(older))
    for p in extra or []:
        try:
            text = read(str(p.get("skill")), str(p.get("part")))
        except KeyError:
            continue
        parts.append(f"### skill {p.get('skill')}: {p.get('part')} (requested)\n{text}")
    return "\n\n".join(parts) + "\n\n"


def json_size(state: list[dict]) -> int:
    return len(json.dumps(state, default=str))
