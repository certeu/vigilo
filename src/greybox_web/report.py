"""Grey-box report generation.

Deterministic markdown from the persisted run: summary, verified findings with
evidence and detection hints, candidates (explicitly labelled), coverage with
skipped checks, and limitations. No patch or MR sections. Evidence excerpts are
rendered inside fenced code blocks, so untrusted target content stays text.
"""
from __future__ import annotations

from datetime import datetime

import re
import uuid
from collections import defaultdict

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import checks as gb_checks
from src.greybox_web import correlation
from src.greybox_web.exploration.knowledge import is_work_url
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxDefense,
    GreyboxEvent,
    GreyboxFinding,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxTarget,
    GreyboxWorkOrder,
)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
END_REASONS = {
    "completed": "completed normally",
    "budget_requests": "stopped: request budget exhausted",
    "budget_time": "stopped: time budget exhausted",
    "cancelled": "cancelled",
    "error": "failed with an error",
    "lease_expired": "stopped: worker lease expired",
}


_MD_ACTIVE = re.compile(r"([\\`*_\[\]|~@])")
_MD_BLOCK_START = re.compile(r"^(?=[-+#=>])")
_MD_ORDERED = re.compile(r"^(\d{1,9})([.)])")


def _md(text: str | None) -> str:
    """One line of UNTRUSTED text rendered as inert markdown (target content
    never becomes a link, image, heading, list item or HTML).

    Whitespace (incl. newlines and unicode line separators) is folded; ``& < >`` become
    entities (no raw HTML, no ``<autolink>``); ``\\ ` * _ [ ] | ~ @`` are backslash-escaped
    (no emphasis, links, images, tables, e-mail autolinks); ``://`` and ``www.`` lose
    the characters that make GFM auto-link bare URLs; block markers at the start of
    the text (``# - + > =``, ``1.``) are escaped so the value cannot open a block."""
    t = re.sub(r"\s+", " ", (text or "")).replace("\x00", "").strip()
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = _MD_ACTIVE.sub(r"\\\1", t)
    t = t.replace("://", "\\://").replace("www.", "www\\.").replace("WWW.", "WWW\\.")
    t = _MD_BLOCK_START.sub(r"\\", t, count=1)
    return _MD_ORDERED.sub(r"\1\\\2", t, count=1)


def _code(text: str | None) -> str:
    """UNTRUSTED text as one inline code span. Inside a code span nothing is
    interpreted (no links, HTML or escapes), so the only way out is a backtick run:
    the fence is longer than any run in the text (``_fence_for`` logic)."""
    t = re.sub(r"\s+", " ", (text or "")).replace("\x00", "").strip() or " "
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    fence = "`" * (max((len(m) for m in re.findall(r"`+", t)), default=0) + 1)
    pad = " " if t.startswith("`") or t.endswith("`") else ""
    return f"{fence}{pad}{t}{pad}{fence}"


def _excerpt(text: str | None) -> str:
    return (text or "").strip()[:400] or "(empty)"


def _fence_for(content: str) -> str:
    """A code fence longer than any backtick run in ``content`` (CommonMark), so the
    content can never close it."""
    longest = max((len(m) for m in re.findall(r"`+", content)), default=0)
    return "`" * max(3, longest + 1)


async def generate(session: AsyncSession, run_id: uuid.UUID, *,
                   finished_at: datetime | None = None,
                   end_reason: str | None = None) -> str:
    """``finished_at``/``end_reason`` describe the outcome being finalised: the
    report is generated before the terminal event, when the run row has neither."""
    run = await session.get(GreyboxRun, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")
    target = await session.get(GreyboxTarget, run.target_id)
    raw_findings = (await session.scalars(
        select(GreyboxFinding).where(GreyboxFinding.run_id == run_id)
        .order_by(GreyboxFinding.created_at))).all()
    # Correlation is an explicit agent decision. Legacy findings remain independent;
    # only rows carrying the same canonical identity are presented together.
    issue_details = {}
    for issue_id in {finding.canonical_issue_id for finding in raw_findings
                     if finding.canonical_issue_id}:
        issue_details[str(issue_id)] = await correlation.inspect_issue(
            session, run_id, canonical_issue_id=issue_id)
    findings = _canonical_findings(raw_findings, issue_details)
    wo_rows = (await session.execute(
        select(GreyboxWorkOrder.tool, GreyboxWorkOrder.status, func.count())
        .where(GreyboxWorkOrder.run_id == run_id)
        .group_by(GreyboxWorkOrder.tool, GreyboxWorkOrder.status))).all()
    in_scope_eps = int(await session.scalar(
        select(func.count()).select_from(GreyboxAsset).where(
            GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "endpoint",
            GreyboxAsset.in_scope.is_(True))) or 0)
    tested_eps = int(await session.scalar(
        select(func.count()).select_from(GreyboxAsset).where(
            GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "endpoint",
            GreyboxAsset.in_scope.is_(True), GreyboxAsset.tested.is_(True))) or 0)
    blocked = int(await session.scalar(
        select(func.count()).select_from(GreyboxHttpExchange).where(
            GreyboxHttpExchange.run_id == run_id,
            GreyboxHttpExchange.blocked.is_(True))) or 0)

    by_status: dict[str, list[GreyboxFinding]] = defaultdict(list)
    for f in findings:
        by_status[getattr(f, "_report_status", f.status)].append(f)
    verified = sorted(by_status.get("verified", []),
                      key=lambda f: (SEVERITY_ORDER.index(f.severity), f.created_at))
    candidates = sorted(by_status.get("candidate", []),
                        key=lambda f: (SEVERITY_ORDER.index(f.severity), f.created_at))
    rejected = by_status.get("rejected", [])

    out: list[str] = []
    out.append(f"# Grey-box security assessment — {_md(target.name if target else run.base_url)}")
    out.append("")
    out.append(f"- **Target:** {_md(run.base_url)}")
    if target is not None and target.description:
        out.append(f"- **Objective:** {_md(target.description)}")
    from src.greybox_web.scope import ScopePolicy
    out.append(f"- **Scope:** {' · '.join(ScopePolicy.from_dict(run.scope).summary())}")
    fin = run.finished_at or finished_at
    reason = run.end_reason or end_reason
    out.append(f"- **Run:** started {run.started_at.isoformat() if run.started_at else '—'}"
               f", finished {fin.isoformat() if fin else '—'}"
               f" ({_md(END_REASONS.get(reason, reason or '—'))})")
    out.append(f"- **Requests:** {run.requests_made}"
               f" ({run.requests_blocked} blocked by scope)")
    out.append(f"- **Findings:** {len(verified)} verified · "
               f"{len(candidates)} candidate (unverified) · {len(rejected)} rejected")
    out.append("")

    from src.greybox_web import findclass
    classes = {f.id: (f.finding_class or findclass.classify(f.check_id)) for f in findings}
    _summary_section(out, verified, candidates, classes, run)

    out.append("## Verified findings")
    out.append("")
    if not verified:
        out.append("_No finding was reproduced by an independent verification "
                   "request. This is not a claim that the application is free of "
                   "vulnerabilities._")
        out.append("")
    for key, title in (("vulnerability", "Confirmed vulnerabilities"),
                       ("misconfiguration", "Security misconfigurations"),
                       ("hardening", "Hardening recommendations"),
                       ("informational", "Informational observations")):
        group = [f for f in verified if classes[f.id] == key]
        if not group:
            continue
        out.append(f"### {title}")
        out.append("")
        if key == "hardening":
            out.append("_Defence-in-depth improvements. They were observed and "
                       "reproduced, but none of them is, on its own, an exploitable "
                       "vulnerability._")
            out.append("")
        for f in group:
            _finding_block(out, f, finding_class=key)
    defenses = (await session.scalars(
        select(GreyboxDefense).where(GreyboxDefense.run_id == run_id)
        .order_by(GreyboxDefense.created_at, GreyboxDefense.id))).all()
    assets = {a.id: a for a in (await session.scalars(
        select(GreyboxAsset).where(
            GreyboxAsset.run_id == run_id,
            GreyboxAsset.kind.in_(("host", "service", "endpoint"))))).all()}
    _network_section(out, [a for a in assets.values() if a.kind == "service"
                           and a.in_scope and (a.data or {}).get("surface")])
    _defenses_section(out, [finding for finding in raw_findings if finding.status in ("verified", "candidate")], defenses, assets)
    if candidates:
        out.append("## Candidate findings (not verified)")
        out.append("")
        out.append("_Each item below was observed once; the verification request "
                   "did not reproduce it, or has not run. Treat as leads, not "
                   "confirmed vulnerabilities._")
        out.append("")
        likely = [f for f in candidates if classes[f.id] == "vulnerability"]
        other = [f for f in candidates if classes[f.id] != "vulnerability"]
        if likely:
            out.append("### Likely vulnerabilities (require verification)")
            out.append("")
            for f in likely:
                _finding_block(out, f, candidate=True, finding_class="vulnerability")
        if other:
            out.append("### Unverified misconfigurations and hardening observations")
            out.append("")
            for f in other:
                _finding_block(out, f, candidate=True, finding_class=classes[f.id])
    if rejected:
        out.append("## Rejected findings")
        out.append("")
        out.append("_Observed once, then contradicted by the independent "
                   "verification: not issues._")
        out.append("")
        for f in rejected:
            loc = (f.location or {}).get("url") or ""
            out.append(f"- {_md(f.title)} — {_code(loc)}")
        out.append("")
    await _inventory_section(out, session, run_id)
    await _hypotheses_section(out, session, run_id)
    await _security_model_section(out, session, run_id)
    await _skills_section(out, session, run)
    await _authored_tools_section(out, session, run_id)
    out.append("## Coverage")
    out.append("")
    wo_by_tool: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for tool, status_, n in wo_rows:
        wo_by_tool[tool][status_] = int(n)
    out.append("| Check | Work orders | Done | Failed | Skipped |")
    out.append("|---|---|---|---|---|")
    for spec in gb_checks.CHECKS:
        if spec.id not in wo_by_tool:
            continue
        c = wo_by_tool[spec.id]
        total = sum(c.values())
        out.append(f"| {spec.title} (`{spec.id}`) | {total} | {c.get('done', 0)} | "
                   f"{c.get('failed', 0)} | {c.get('skipped', 0)} |")
    # Run-defined dynamic instruments (batch E): real coverage rows of their own.
    # Titles come from the tool.defined events (the run-scoped registry itself is
    # in-memory and does not outlive the run's process).
    dyn_titles = {str((ev or {}).get("id")): str((ev or {}).get("title") or "")
                  for ev in (await session.scalars(
                      select(GreyboxEvent.data).where(
                          GreyboxEvent.run_id == run_id,
                          GreyboxEvent.kind == "tool.defined"))).all()
                  if (ev or {}).get("id")}
    if dyn_titles:
        for tool in sorted(t for t in wo_by_tool
                           if t.startswith("dyn.") or t == "tool.define"):
            c = wo_by_tool[tool]
            total = sum(c.values())
            if tool == "tool.define":
                name = "Dynamic instrument definitions (`tool.define`) — " \
                       "declarative, no requests"
            else:
                name = (f"Agent-defined: "
                        f"{_md(dyn_titles.get(tool) or 'dynamic check')} "
                        f"(`{tool}`)")
            out.append(f"| {name} | {total} | {c.get('done', 0)} | "
                       f"{c.get('failed', 0)} | {c.get('skipped', 0)} |")
    for tool in sorted(t for t in wo_by_tool if t.startswith("verify.")):
        c = wo_by_tool[tool]
        out.append(f"| Verification (`{tool}`) | {sum(c.values())} | "
                   f"{c.get('done', 0)} | {c.get('failed', 0)} | {c.get('skipped', 0)} |")
    out.append("")
    if dyn_titles:
        out.append("- **Agent-defined instruments:** the exploration agent composed "
                   "the check(s) above itself from a declarative vocabulary "
                   "(request pattern + verdict predicates) when no built-in tool "
                   "could express them. Execution went through the same guarded "
                   "client, scope, budgets and inert payloads as every built-in "
                   "tool; the agent never received code execution.")
    out.append(f"- **Endpoints checked:** {tested_eps} of {in_scope_eps} in-scope "
               f"endpoints had at least one enabled check complete.")
    untested = (await session.scalars(
        select(GreyboxAsset.key).where(
            GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "endpoint",
            GreyboxAsset.in_scope.is_(True), GreyboxAsset.tested.is_(False))
        .order_by(GreyboxAsset.key))).all()
    from src.greybox_web.tools.routes import template_coverage
    all_eps = (await session.execute(
        select(GreyboxAsset.key, GreyboxAsset.tested).where(
            GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "endpoint",
            GreyboxAsset.in_scope.is_(True)))).all()
    tcov = template_coverage([(k, bool(t)) for k, t in all_eps])
    visible = [u for u in untested if is_work_url(u)
               and not (u in tcov and tcov[u]["tested"])]
    if visible:
        shown = ", ".join(_code(u) for u in visible[:15])
        more = f" (+{len(visible) - 15} more)" if len(visible) > 15 else ""
        out.append(f"- **Not tested:** {len(visible)} discovered endpoint(s) never had "
                   f"a check complete: {shown}{more}.")
    out.append(f"- **Blocked requests:** {blocked} request attempts were refused by "
               f"the scope guard (out-of-scope host, path or address class) and are "
               f"recorded in the run's traffic.")
    unregistered = _unregistered_checks(run.checks or [], wo_by_tool)
    # Checks the target selected but that were removed at run start because this
    # build has no implementation (recorded on run.queued as skipped_checks).
    queued = await session.scalar(
        select(GreyboxEvent.data).where(GreyboxEvent.run_id == run.id,
                                        GreyboxEvent.kind == "run.queued").limit(1))
    for item in (queued or {}).get("skipped_checks") or []:
        cid = item.get("id") if isinstance(item, dict) else item
        if cid and cid not in unregistered:
            unregistered.append(cid)
    if unregistered:
        titles = ", ".join(_code(c) for c in unregistered)
        out.append(f"- **Checks not run in this build:** {titles}. These checks are "
                   f"selected in the target's configuration but have no "
                   f"implementation registered in this engine build, so they were "
                   f"not run.")
    out.append("")
    # The completion verdict: what this run did NOT cover.
    verdict = run.coverage_verdict if isinstance(run.coverage_verdict, dict) else None
    if verdict:
        out.append("## Assessment outcome")
        out.append("")
        out.append(f"**{_md(str(verdict.get('outcome') or 'unknown').replace('_', ' '))}"
                   f"**")
        out.append("")
        for reason in verdict.get("reasons") or []:
            out.append(f"- {_md(reason)}")
        blind = [str(x) for x in (verdict.get("limitations") or []) if x]
        if blind:
            out.append("")
            out.append("**Not covered by this assessment:**")
            out.append("")
            for item in blind:
                out.append(f"- {_md(item)}")
        out.append("")
    if run.auth_states:
        out.append("## Authentication state")
        out.append("")
        out.append("- The run met an authentication boundary: "
                   + ", ".join(_code(s) for s in run.auth_states)
                   + ". What lies behind it was not assessed; the findings below "
                     "concern only what the target answered without a valid session.")
        out.append("")
    out.append("## Limitations")
    out.append("")
    out.append("- The assessment was **AI-driven**: an exploration agent (an LLM) "
               "decided each step from what the run had observed so far. It could "
               "only act through Vigilo's scope-bounded tools — the built-in ones, "
               "declarative instruments, and short analysers it wrote itself that ran "
               "in an isolated sandbox (no network, no filesystem; every request they "
               "needed was made by the engine under the same scope, activity policy "
               "and audit). No shell, no exploitation, no state-changing request "
               "unless the operator authorised it. What the agent chose not to "
               "examine is not covered.")
    scope_obj = ScopePolicy.from_dict(run.scope)
    if scope_obj.mode == "web":
        out.append("- WebSocket traffic is not proxied by the engine's guarded "
                   "client: browser WebSocket connections were refused and are not "
                   "assessed.")
    out.append("- Exposure findings require a content signature plus a soft-404 "
               "baseline, so a generic 200 page is never reported as an exposed file.")
    out.append("- Requests were bounded by the run's limits ("
               + f"{(run.limits or {}).get('max_requests')} requests, "
               f"{(run.limits or {}).get('max_duration_s')} s).")
    proxy = run.egress_proxy if isinstance(run.egress_proxy, dict) else None
    if proxy and proxy.get("name"):
        out.append(f"- **All traffic to the target went through the egress proxy "
                   f"{_md(proxy['name'])}** (selected by an administrator). The engine "
                   f"could not pin DNS: the proxy resolved the target's host name, so "
                   f"the address actually contacted is the one the proxy chose and is "
                   f"not recorded (the engine only refused names whose own DNS answers "
                   f"fall in never-allowed ranges, and every host was checked against "
                   f"the proxy's allowed hosts). TLS was verified end to end against "
                   f"the host name. Scope, redirects, budgets and IP-literal checks "
                   f"applied as usual, but the proxy's own policy (filtering, caching, "
                   f"authentication, TLS interception) may have affected what was "
                   f"observed, and headers such as Via or X-Forwarded-For may come "
                   f"from it.")
    if run.end_reason and run.end_reason.startswith("budget_"):
        out.append(f"- The run stopped early ({_md(END_REASONS.get(run.end_reason))}); "
                   f"coverage above is partial by construction.")
    if unregistered:
        out.append("- Some configured checks are not implemented in this engine "
                   "build (see Coverage); the report never counts them as run.")
    out.append("")
    return "\n".join(out)


def _unregistered_checks(checks: list[str],
                         wo_by_tool: dict[str, dict[str, int]]) -> list[str]:
    from src.greybox_web import tools as gb_tools
    return [c for c in checks
            if gb_tools.get(c) is None
            and any(s > 0 for s in wo_by_tool.get(c, {}).values())]


def _canonical_findings(findings: list[GreyboxFinding],
                        issue_details: dict[str, dict] | None = None) -> list[GreyboxFinding]:
    grouped: dict[str, list[GreyboxFinding]] = {}
    for finding in findings:
        canonical_id = str(getattr(finding, "canonical_issue_id", "") or finding.id)
        grouped.setdefault(canonical_id, []).append(finding)
    result: list[GreyboxFinding] = []
    for canonical_id, members in grouped.items():
        representative = members[0]
        detail = (issue_details or {}).get(canonical_id, {})
        setattr(representative, "_report_canonical_id", canonical_id)
        setattr(representative, "_report_members", members)
        if detail:
            verification_status = detail["verification_status"]
            setattr(representative, "_report_verification_status", verification_status)
            setattr(representative, "_report_status",
                    "verified" if verification_status in {"verified", "verified_impact",
                    "confirmed_configuration", "confirmed_observation"} else
                    "rejected" if verification_status == "rejected" else "candidate")
            setattr(representative, "_report_affected_locations",
                    detail["affected_locations"] or None)
            setattr(representative, "_report_observation_count",
                    detail["observation_count"])
            setattr(representative, "_report_root_cause", detail.get("root_cause"))
            setattr(representative, "_report_remediation", detail.get("remediation"))
            setattr(representative, "_report_retest", detail.get("retesting_guidance"))
            history = detail.get("correlation_history") or []
            setattr(representative, "_report_correlation_rationale",
                    history[-1]["rationale"] if history else None)
        result.append(representative)
    return result


def _member_locations(f: GreyboxFinding) -> list[dict]:
    locations = getattr(f, "affected_locations", None)
    if isinstance(locations, list) and locations:
        return [location for location in locations if isinstance(location, dict)]
    location = f.location or {}
    primary = dict(location)
    primary.setdefault("evidence", f.evidence or [])
    primary.setdefault("verification", f.verification)
    primary.setdefault("status", getattr(f, "verification_status", None) or f.status)
    primary.setdefault("identities", getattr(f, "identities", None) or [])
    primary.setdefault("observation_count", getattr(f, "observation_count", None)
                       or len(f.evidence or []) or 1)
    out = [primary]
    for also_at in location.get("also_at") or []:
        if also_at:
            out.append({"url": also_at, "method": location.get("method", "GET"),
                        "status": primary["status"], "observation_count": 1})
    return out


def _canonical_locations(f: GreyboxFinding) -> list[dict]:
    locations = getattr(f, "_report_affected_locations", None)
    if locations:
        return locations
    return [location for member in getattr(f, "_report_members", [f])
            for location in _member_locations(member)]


_CLASS_LABEL = {"vulnerability": "Vulnerability", "misconfiguration":
                "Security misconfiguration", "hardening": "Hardening recommendation",
                "informational": "Informational"}


def _finding_block(out: list[str], f: GreyboxFinding, *,
                   candidate: bool = False, finding_class: str | None = None) -> None:
    sev = f.severity.upper()
    out.append(f"#### [{sev}] {_md(f.title)}" + (" — candidate" if candidate else ""))
    out.append("")
    cls = finding_class or getattr(f, "finding_class", "") or ""
    raw_status = getattr(f, "_report_verification_status", None) or f.status
    if raw_status == "verified":
        status = "verified security impact" if cls == "vulnerability" else "confirmed observation"
    else:
        status = {"verified_impact": "verified security impact",
                  "confirmed_configuration": "confirmed configuration weakness",
                  "confirmed_observation": "confirmed observation",
                  "candidate": "unverified impact",
                  "inconclusive": "inconclusive", "rejected": "rejected"}.get(raw_status, raw_status)
    members = getattr(f, "_report_members", [f])
    locations = _canonical_locations(f)
    observations = int(getattr(f, "_report_observation_count", 0) or sum(
        int(location.get("observation_count") or len(location.get("evidence") or []) or 1)
        for location in locations))
    out.append(f"- **Issue ID:** {_code(getattr(f, '_report_canonical_id', str(f.id)))} · "
               f"**Classification:** {_md(_CLASS_LABEL.get(cls, cls or '—'))} · "
               f"**Status:** {_md(status)} · **Confidence:** {_md(f.confidence)}")
    out.append(f"- **Affected locations:** {len(locations)} · "
               f"**Supporting observations:** {observations} · "
               f"**Original findings:** {len(members)}")
    if f.cwe:
        out.append(f"- **CWE:** {_md(f.cwe)}")
    out.append(f"- **Description:** {_md(f.description)}")
    root_cause = getattr(f, "_report_root_cause", None)
    rationale = getattr(f, "_report_correlation_rationale", None)
    if root_cause:
        out.append(f"- **Root cause:** {_md(root_cause)}")
    if rationale:
        out.append(f"- **Correlation rationale:** {_md(rationale)}")
    for index, location in enumerate(locations, 1):
        where = location.get("location") or location.get("url") or "Unknown location"
        out.append(f"- **Location {index}:** {_code(str(where))} · "
                   f"status {_md(str(location.get('status') or raw_status))} · "
                   f"{int(location.get('observation_count') or len(location.get('evidence') or []) or 1)} observation(s)")
        identities = location.get("identities") or []
        if identities:
            out.append("  - **Identities:** " + ", ".join(_md(str(identity)) for identity in identities))
        verification = location.get("verification")
        if verification:
            result = verification.get("result", "") if isinstance(verification, dict) else str(verification)
            out.append(f"  - **Verification:** {_md(str(result))}")
        for evidence in location.get("evidence") or []:
            if not isinstance(evidence, dict):
                evidence = {"excerpt": str(evidence)}
            note = f" — {_md(evidence.get('note'))}" if evidence.get("note") else ""
            exchange = f" · exchange {evidence.get('exchange_id')}" if evidence.get("exchange_id") else ""
            out.append(f"  - **Evidence ({_md(evidence.get('role', 'evidence'))}{exchange}){note}:**")
            excerpt = _excerpt(evidence.get("excerpt", ""))
            fence = _fence_for(excerpt)
            out.extend((fence, excerpt, fence))
    for hint in (f.detection_hints or []):
        out.append(f"- **Detection hint ({_md(hint.get('type'))}) — {_md(hint.get('title'))}:** {_md(hint.get('content'))}")
    if f.references:
        out.append("- **References:** " + ", ".join(
            f"[{_md(reference.get('title'))}]({_md(reference.get('url'))})" for reference in f.references))
    remediation = getattr(f, "_report_remediation", None) or f.remediation or {}
    if remediation.get("severity_rationale"):
        out.append(f"- **Severity rationale:** {_md(remediation['severity_rationale'])}")
    for item in remediation.get("reproduction") or []:
        out.append(f"- **Reproduce:** {_md(item)}")
    if remediation.get("summary"):
        out.append(f"- **Remediation:** {_md(remediation['summary'])}")
    for step in remediation.get("steps") or []:
        out.append(f"  - {_md(step)}")
    validation = getattr(f, "_report_retest", None) or remediation.get("validation")
    if validation:
        out.append("- **How to verify the fix:**")
        for item in ([validation] if isinstance(validation, str) else validation):
            out.append(f"  - {_md(item)}")
    out.append("")


def _summary_section(out: list[str], verified, candidates, classes, run) -> None:
    """Executive summary: what to fix first, with vulnerabilities and hardening
    counted separately (a missing header never inflates the vulnerability count)."""
    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    vulns = [f for f in verified if classes[f.id] == "vulnerability"]
    likely = [f for f in candidates if classes[f.id] == "vulnerability"]
    misc = [f for f in verified if classes[f.id] == "misconfiguration"]
    hard = [f for f in verified if classes[f.id] == "hardening"]
    out.append("## Summary")
    out.append("")
    out.append(f"- **Confirmed vulnerabilities:** {len(vulns)} · **likely "
               f"(unverified):** {len(likely)} · **misconfigurations:** {len(misc)} · "
               f"**hardening recommendations:** {len(hard)}")
    verdict = run.coverage_verdict if isinstance(run.coverage_verdict, dict) else None
    if verdict:
        out.append(f"- **Assessment outcome:** "
                   f"{_md(str(verdict.get('outcome') or '').replace('_', ' '))}"
                   + (f" — {_md((verdict.get('reasons') or [''])[0])}"
                      if verdict.get("reasons") else ""))
    top = sorted(vulns + misc, key=lambda f: (sev_rank.get(f.severity, 9),
                                              classes[f.id] != "vulnerability"))[:5]
    if top:
        out.append("- **Fix first:**")
        for f in top:
            rem = (getattr(f, "remediation", None) or {}).get("summary")
            out.append(f"  - [{f.severity.upper()}] {_md(f.title)}"
                       + (f" — {_md(rem)}" if rem else ""))
    out.append("")


async def _inventory_section(out: list[str], session, run_id) -> None:
    """Assets and services the run examined, whatever the target type: web services
    with their observed metadata, network hosts and their tcp services."""
    rows = (await session.scalars(
        select(GreyboxAsset).where(GreyboxAsset.run_id == run_id,
                                   GreyboxAsset.kind.in_(("host", "service")),
                                   GreyboxAsset.in_scope.is_(True))
        .order_by(GreyboxAsset.kind, GreyboxAsset.key))).all()
    tcp = [a for a in rows if a.kind == "service" and a.key.startswith("tcp://")]
    if not tcp:
        return
    out.append("## Asset and service inventory")
    out.append("")
    out.append("| Service | Protocol | Product / version | State | Examined |")
    out.append("|---|---|---|---|---|")
    for a in tcp[:200]:
        d = a.data or {}
        prod = " ".join(x for x in (str(d.get("product") or ""),
                                    str(d.get("version") or "")) if x) or "—"
        out.append(f"| {_tcode(a.key)} | {_md(str(d.get('protocol') or '?'))} "
                   f"({_md(str(d.get('identified_by') or '—'))}) | {_md(prod)} | "
                   f"{_md(str(d.get('state') or '—'))} | "
                   f"{'yes' if a.tested else 'no'} |")
    out.append("")


async def _hypotheses_section(out: list[str], session, run_id) -> None:
    """What the agent set out to test and how each line of inquiry ended —
    including the inconclusive and untested ones (never silently dropped)."""
    from src.greybox_web.models import GreyboxGraphNode
    leads = (await session.scalars(
        select(GreyboxGraphNode).where(GreyboxGraphNode.run_id == run_id,
                                       GreyboxGraphNode.kind == "lead")
        .order_by(GreyboxGraphNode.created_at))).all()
    if not leads:
        return
    out.append("## Hypotheses investigated")
    out.append("")
    label = {"confirmed": "confirmed", "refuted": "no finding from the checks run",
             "inconclusive": "inconclusive", "open": "not tested (left open)",
             "investigating": "not concluded (left open)"}
    by_basis = {"verified_finding": "confirmed by a verified finding",
                "unverified_finding": "supported by an unverified finding",
                "observed": "explored (observations recorded; no finding)",
                "checks_clean": "no finding from the checks run (not proven absent)",
                "not_run": "not tested (left open)"}
    for n in leads[:40]:
        hyp = (n.data or {}).get("hypothesis") or ""
        basis = (n.data or {}).get("basis")
        text = by_basis.get(basis) or label.get(n.status, n.status)
        out.append(f"- **{_md(text)}** — {_md(n.label)}"
                   + (f": {_md(str(hyp)[:300])}" if hyp else ""))
    out.append("")


async def _security_model_section(out: list[str], session, run_id) -> None:
    """The application's security model as the assessment understood it: who the
    identities were, what access was EXPECTED (and on which basis), what was
    OBSERVED per interface, and which correlations remain unverified."""
    from src.greybox_web import secmodel_store
    v = await secmodel_store.view(session, run_id)
    if not (v["interfaces"] or v["expectations"] or v["entities"]):
        return
    out.append("## Security model")
    out.append("")
    out.append("Expected access is what the application's documentation, "
               "configuration or behaviour establishes; observed access is what "
               "each identity actually received. An observation alone is not a "
               "conclusion.")
    out.append("")
    if v["identities"]:
        out.append("**Identities:** " + ", ".join(
            f"{_md(i['identity'])}" + (f" ({_md(i['role'])})" if i.get("role") else "")
            + f" — {i['requests']} request(s)" for i in v["identities"]))
        out.append("")
    if v["relations"]:
        out.append("**Relationships recorded:**")
        for r in v["relations"][:20]:
            out.append(f"- {_md(r['src'])} *{_md(r['rel'])}* {_md(r['dst'])} "
                       f"({_md(r['basis'])})")
        out.append("")
    if v["expectations"]:
        out.append("**Expected access:**")
        out.append("")
        out.append("| Subject | Operation | Resource | Expected | Basis | Evidence |")
        out.append("|---|---|---|---|---|---|")
        for e in v["expectations"][:25]:
            out.append(f"| {_md(e.get('subject'))} | {_md(e.get('operation'))} | "
                       f"{_md(e.get('resource'))} | {_md(e.get('expected'))} | "
                       f"{_md(e.get('basis'))} | "
                       f"{_md(', '.join(e.get('evidence') or []) or '—')} |")
        out.append("")
    if v["interfaces"]:
        out.append("**Observed access per interface** (reads: allowed / denied / "
                   "not found):")
        out.append("")
        out.append("| Interface | " + " | ".join(
            _md(i["identity"]) for i in v["identities"]) + " |")
        out.append("|---|" + "---|" * len(v["identities"]))
        for it in v["interfaces"][:25]:
            cells = []
            for i in v["identities"]:
                c = it["access"].get(i["identity"]) or {}
                cells.append(f"{c.get('allow', 0)}/{c.get('deny', 0)}/"
                             f"{c.get('missing', 0)}" if c else "—")
            out.append(f"| {_code(it['interface'])} | " + " | ".join(cells) + " |")
        out.append("")
    opened = {s["summary"] for s in await secmodel_store.open_signals(session, run_id, v)}
    if v["signals"]:
        out.append("**Correlation signals** (same resource instance, different "
                   "interfaces):")
        for s_ in v["signals"]:
            state = "not verified" if s_["summary"] in opened else \
                "examined (see findings / observations)"
            out.append(f"- {_md(s_['summary'])} — *{state}*; evidence "
                       f"{_md(', '.join(s_['evidence']))}")
        out.append("")


async def _skills_section(out: list[str], session, run) -> None:
    """Which methodology the agent applied, and each skill's definition of done:
    what is established (with evidence), blocked (why), not applicable or open."""
    from src.greybox_web import skillbook
    from src.greybox_web.scope import ScopePolicy
    state = await skillbook.run_state(session, run.id, ScopePolicy.from_dict(run.scope))
    if not state:
        return
    mark = {"satisfied": "established", "unsatisfied": "NOT established",
            "blocked": "blocked", "not_applicable": "not applicable"}
    out.append("## Methodology and definition of done")
    out.append("")
    out.append("_Skills the agent loaded and, for each, whether its completion criteria "
               "are met. \"engine\" = checked against the run's recorded evidence; "
               "\"agent\" = claimed by the agent with evidence the engine found in the "
               "run._")
    out.append("")
    for sk in state:
        gates = ", ".join(f"{p['id']} {p['gate']}" for p in sk["phases"])
        out.append(f"### {_md(sk['name'])}" + (f" — phases: {_md(gates)}" if gates else ""))
        out.append("")
        for c in sk["criteria"]:
            ev = "; ".join(c.get("evidence") or [])
            note = c.get("note") or ""
            out.append(f"- **{mark.get(c['status'], c['status'])}** ({c['by']}) — "
                       f"{_md(c['text'])}" + (f" · evidence: {_md(ev[:300])}" if ev else "")
                       + (f" · {_md(note[:200])}" if note else ""))
        out.append("")


async def _authored_tools_section(out: list[str], session, run_id) -> None:
    """Tools the agent wrote for this run: why, what they could do, how they ran."""
    composed = [e for e in (await session.scalars(
        select(GreyboxEvent.data).where(GreyboxEvent.run_id == run_id,
                                        GreyboxEvent.kind == "tool.defined")
        .order_by(GreyboxEvent.seq))).all()
        if (e or {}).get("kind_detail") == "composed"]
    if not composed:
        return
    runs = dict((await session.execute(
        select(GreyboxWorkOrder.tool, func.count()).where(
            GreyboxWorkOrder.run_id == run_id,
            GreyboxWorkOrder.tool.in_([str(e.get("id")) for e in composed]))
        .group_by(GreyboxWorkOrder.tool))).all())
    out.append("## Tools written by the agent")
    out.append("")
    out.append("_Analysers the agent authored during this run because no built-in "
               "tool could answer its question. Each ran in an isolated sandbox with "
               "no network and no filesystem; every request it needed was made by the "
               "engine through the same scope, policy and audit as any tool._")
    out.append("")
    for e in composed:
        out.append(f"- `{_md(str(e.get('id')))}` — {_md(str(e.get('title') or ''))}: "
                   f"{_md(str(e.get('purpose') or ''))} (capabilities: "
                   f"{_md(', '.join(e.get('capabilities') or []) or 'none')}; "
                   f"executions: {runs.get(str(e.get('id')), 0)}; source: "
                   f"{len(str(e.get('source') or '').splitlines())} lines, kept in the "
                   f"run's audit trail)")
    out.append("")


_FENCE_LANG = {"modsecurity": "apache", "sigma": "yaml", "nginx": "nginx",
               "apache": "apache", "text": ""}


def _tcode(text: str | None) -> str:
    """``_code`` for a table cell: GFM splits cells on every unescaped pipe, even
    inside a code span."""
    return _code(text).replace("|", "\\|")


def _surface_issue(f: dict) -> str:
    return f"{_md(str(f.get('detail', '')))} (+{int(f.get('points', 0))})"


def _supply_edge(out: list[str], s: dict) -> None:
    """The "Supply chain and edge" subsection of one service: a projection of ``data.surface`` (third parties, edge, leaks, HTTP posture), all
    derived from recorded responses. Every value is untrusted: ``_tcode`` / ``_md``."""
    tp, edge, lk, http = (s.get("third_party"), s.get("edge"), s.get("leaks"),
                          s.get("http"))
    if not (tp or edge or lk or http):
        return
    tp, edge, lk, http = tp or {}, edge or {}, lk or {}, http or {}
    rows: list[tuple[str, str]] = []
    top = tp.get("top") or []
    mc = tp.get("mixed_content") or {}
    rows.append(("Third-party origins", (
        f"{int(tp.get('origins', 0))}: " + ", ".join(
            f"{_tcode(o.get('host'))} ({_md(', '.join(o.get('kinds', [])))}, "
            f"{int(o.get('pages', 0))} page(s))" for o in top[:5])
        + f"; {int(tp.get('scripts_without_sri', 0))} script reference(s) without SRI"
        if tp.get("origins") else "none observed")
        + " (recorded from markup, never requested)"))
    rows.append(("Mixed content", f"{int(mc.get('active', 0))} active, "
                                   f"{int(mc.get('passive', 0))} passive"))
    prov = edge.get("providers") or []
    waf = edge.get("waf") or {}
    rows.append(("Edge / CDN / WAF", (
        ", ".join(f"{_md(p.get('name'))} ({_md(p.get('kind'))}, "
                  f"{_md(p.get('confidence'))} confidence; "
                  f"{', '.join(_tcode(x) for x in p.get('signals', []))})"
                  for p in prov) + f"; WAF state: {_md(waf.get('state'))}"
        if prov else "no edge signal observed (this does not mean there is none)")))
    cache = edge.get("cache") or {}
    lat = edge.get("latency_ms") or {}
    lat_txt = "; ".join(f"{_md(k)}: p50 {int(v.get('p50', 0))} ms, p95 "
                        f"{int(v.get('p95', 0))} ms (n={int(v.get('n', 0))})"
                        for k, v in sorted(lat.items()) if isinstance(v, dict))
    rows.append(("Cache and latency", (
        f"cache headers observed, {int(cache.get('hits', 0))} hit(s)"
        if cache.get("observed") else "no cache headers observed")
        + (f"; cacheable sensitive paths: "
           f"{', '.join(_tcode(p) for p in cache['sensitive_cacheable'])}"
           if cache.get("sensitive_cacheable") else "")
        + (f"; latency {lat_txt}" if lat_txt else "")))
    hosts, ips = lk.get("internal_hosts") or [], lk.get("private_ips") or []
    rows.append(("Internal disclosure", (
        ", ".join(_tcode(v) for v in [*hosts, *ips][:6]) + " (recorded, never contacted)"
        if hosts or ips else "none observed")))
    hs = http.get("hsts")
    rows.append(("HTTP posture", "; ".join(x for x in (
        ("HSTS " + (f"max-age {int(hs.get('max_age', 0))}"
                    + (", includeSubDomains" if hs.get("include_subdomains") else "")
                    + (", preload" if hs.get("preload") else "")
                    + (" (preload-ready)" if hs.get("preload_ready")
                       else " (not preload-ready)"))) if hs else None,
        "HTTP/3 advertised (Alt-Svc)" if http.get("h3_advertised") else None,
        {True: "http redirects to https", False: "http is served without a redirect"}.get(
            http.get("http_to_https")),
        (f"{len(http['cross_host_redirects'])} cross-host redirect(s): "
         + ", ".join(_tcode(r.get("to")) for r in http["cross_host_redirects"][:3]))
        if http.get("cross_host_redirects") else None) if x) or "nothing notable"))
    v = s.get("vantage") or {}
    rows.append(("Vantage", f"{_md(v.get('kind'))} ({int((v.get('exchanges') or {}).get('direct', 0))} "
                            f"direct, {int((v.get('exchanges') or {}).get('via_proxy', 0))} via proxy)"))
    inf = s.get("infra_findings") or []
    if inf:
        rows.append(("Infrastructure signals", "; ".join(_surface_issue(i) for i in inf)
                     + " (not part of the risk score unless enabled)"))
    out.append("#### Supply chain and edge")
    out.append("")
    out.append("| Aspect | Observed |")
    out.append("|---|---|")
    for k, val in rows:
        out.append(f"| {k} | {val} |")
    out.append("")


def _network_section(out: list[str], services: list[GreyboxAsset]) -> None:
    """Per-service surface summary from the live network analysis. Every
    value comes from the target, so it is rendered through ``_md`` / ``_code``."""
    if not services:
        return
    out.append("## Network overview")
    out.append("")
    out.append("_Derived from the requests this run already made (no extra traffic). "
               "The risk score is a deterministic 0-100 sum of weighted observations; "
               "it ranks services, it is not a vulnerability count._")
    out.append("")
    for svc in sorted(services, key=lambda a: (
            -int(((a.data or {}).get("surface") or {}).get("risk_score", 0)), a.key)):
        s = (svc.data or {})["surface"]
        out.append(f"### {_md(svc.label)} — risk {int(s.get('risk_score', 0))}/100")
        out.append("")
        sh = s.get("security_headers", {})
        ep = s.get("endpoints", {})
        cors = s.get("cors", {})
        tls = s.get("tls", {})
        rd = s.get("redirects", {})
        rows: list[tuple[str, str]] = [
            ("Server", _tcode(s["server"]) if s.get("server") else "not disclosed"),
            ("Technologies", ", ".join(_tcode(t) for t in s.get("technologies", []))
             or "none identified"),
            ("Transport", "https" + (", HSTS sent" if tls.get("hsts") else
                                     ", no HSTS") if tls.get("https")
             else "plain http (no TLS)"),
            ("Security headers",
             (f"missing: {', '.join(_tcode(h) for h in sh.get('missing', []))}"
              if sh.get("missing") else "none missing")
             + (f"; present: {', '.join(_tcode(h) for h in sh.get('present', []))}"
                if sh.get("present") else "")
             + f" ({int(sh.get('evaluated', 0))} pages evaluated)"),
            ("Cookies", "; ".join(
                f"{_tcode(n)}: " + ", ".join(
                    x for x in (
                        "Secure" if f.get("secure") else "no Secure",
                        "HttpOnly" if f.get("httponly") else "no HttpOnly",
                        f"SameSite={_md(f.get('samesite'))}" if f.get("samesite")
                        else "no SameSite") if x)
                for n, f in s.get("cookie_flags", {}).items()) or "none observed"),
            ("CORS", ("origin reflected" if cors.get("reflects_origin")
                      else "wildcard origin" if cors.get("wildcard")
                      else "no reflection" if cors.get("tested") else "not probed")
             + (" with credentials" if cors.get("allows_credentials") else "")
             + (f" ({', '.join(_tcode(p) for p in cors.get('paths', []))})"
                if cors.get("paths") else "")),
            ("Redirects", f"{int(rd.get('count', 0))} observed, "
             f"{int(rd.get('external', 0))} to other hosts, "
             f"{int(rd.get('external_blocked', 0))} blocked by scope"),
            ("Endpoints", f"{int(ep.get('total', 0))} in scope, "
             f"{int(ep.get('tested', 0))} tested, {int(ep.get('with_findings', 0))} "
             f"with findings, {int(ep.get('auth_like', 0))} login, "
             f"{int(ep.get('sensitive', 0))} sensitive"),
        ]
        if s.get("sensitive_paths"):
            rows.append(("Sensitive paths", ", ".join(
                f"{_tcode(x.get('path'))} ({_md(x.get('reason'))})"
                for x in s["sensitive_paths"])))
        out.append("| Aspect | Observed |")
        out.append("|---|---|")
        for k, v in rows:
            out.append(f"| {k} | {v} |")
        out.append("")
        _supply_edge(out, s)
        top = s.get("risk_factors", [])[:3]
        if top:
            out.append("Top issues: " + "; ".join(_surface_issue(f) for f in top))
            out.append("")


def _defense_block(out: list[str], d: GreyboxDefense) -> None:
    out.append(f"**{_md(d.title)}** — {_code(d.format)} · {_md(d.kind)} · "
               f"confidence {_md(d.confidence)}")
    out.append("")
    out.append(_md(d.rationale))
    out.append("")
    fence = _fence_for(d.content)
    out.append(fence + _FENCE_LANG.get(d.format, ""))
    out.append(d.content.rstrip("\n"))
    out.append(fence)
    out.append("")


def _defenses_section(out: list[str], findings: list[GreyboxFinding],
                      defenses: list[GreyboxDefense],
                      assets: dict[uuid.UUID, GreyboxAsset] | None = None) -> None:
    """Defensive suggestions: per finding, then network-wide ones grouped per service.
    Generated from templates, so they must be reviewed and
    tested before deployment."""
    assets = assets or {}
    by_finding: dict[uuid.UUID, list[GreyboxDefense]] = defaultdict(list)
    by_service: dict[uuid.UUID, list[GreyboxDefense]] = defaultdict(list)
    for d in defenses:
        if d.scope == "asset" and d.asset_id is not None:
            a = assets.get(d.asset_id)
            while a is not None and a.kind == "endpoint" and a.parent_id is not None:
                a = assets.get(a.parent_id)
            by_service[a.id if a is not None else d.asset_id].append(d)
        elif d.finding_id is not None:
            by_finding[d.finding_id].append(d)
    # Several findings can share one defense row (finding_ids): it is listed under the
    # first and referenced under the others. Config snippets already covered by a
    # network-wide recommendation are not repeated, and a rule identical to one listed
    # under a finding is not listed again in the network block.
    from src.greybox_web import defenses as gb_defenses
    f_by_id = {f.id: f for f in findings}
    also: dict[uuid.UUID, list[GreyboxDefense]] = defaultdict(list)
    for d in defenses:
        if d.scope == "finding":
            for x in d.finding_ids or []:
                u = uuid.UUID(str(x))
                if u != d.finding_id and u in f_by_id:
                    also[u].append(d)
    net_content: dict[str, list[str]] = defaultdict(list)
    for items in by_service.values():
        for d in items:
            net_content[d.format].append(d.content)
    if not by_finding and not by_service:
        return
    out.append("## Detection and WAF suggestions")
    out.append("")
    out.append("_Each suggestion starts with a vendor-neutral policy (what to block, "
               "allow or limit, and why); the rule or configuration after it is an "
               "illustrative example for one product, generated from templates for the "
               "findings above and for the network analysis, referencing the affected "
               "paths. Review and test each one before deploying; suggestions for "
               "candidate findings are marked unverified._")
    out.append("")
    shown: set[tuple[str, str]] = set()
    for f in findings:
        items = by_finding.get(f.id) or []
        refs = also.get(f.id) or []
        if not items and not refs:
            continue
        flag = "" if f.status == "verified" else " — unverified (candidate)"
        out.append(f"### [{f.severity.upper()}] {_md(f.title)}{flag}")
        out.append("")
        for d in items:
            if d.format in ("nginx", "apache") and gb_defenses.covered(
                    d.format, d.content, net_content[d.format]):
                out.append(f"**{_md(d.title)}** — covered by the network-wide "
                           "recommendation for this service below.")
                out.append("")
                continue
            shown.add((d.format, " ".join(d.content.split())))
            _defense_block(out, d)
            others = [f_by_id[uuid.UUID(str(i))] for i in (d.finding_ids or [])
                      if uuid.UUID(str(i)) in f_by_id and uuid.UUID(str(i)) != f.id]
            if others:
                out.append("_Also addresses: " + "; ".join(
                    f"[{o.severity.upper()}] {_md(o.title)}" for o in others[:5]) + "_")
                out.append("")
        for d in refs:
            parent = f_by_id.get(d.finding_id) if d.finding_id else None
            out.append(f"**{_md(d.title)}** — listed under "
                       f"{_md(parent.title) if parent else 'another finding'}.")
            out.append("")
    for sid, items in sorted(by_service.items(), key=lambda kv: (
            assets[kv[0]].key if kv[0] in assets else str(kv[0]))):
        items = [d for d in items if (d.format, " ".join(d.content.split())) not in shown]
        if not items:
            continue
        a = assets.get(sid)
        out.append(f"### Network recommendations — {_md(a.label if a else 'asset')}")
        out.append("")
        for d in items:
            _defense_block(out, d)
            linked = [f_by_id[uuid.UUID(str(i))] for i in (d.finding_ids or [])
                      if uuid.UUID(str(i)) in f_by_id]
            if linked:
                out.append("_Addresses: " + "; ".join(
                    f"[{f.severity.upper()}] {_md(f.title)}" for f in linked[:5]) + "_")
                out.append("")
