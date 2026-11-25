"""``tool.compose``: the agent authors an analysis tool and the run executes it.

Why this exists next to ``tool.define``
---------------------------------------
``tool.define`` (batch E) lets the agent express *one request plus verdict
predicates*. It cannot express computation: walk an unusual API envelope, diff two
responses field by field, correlate a route table from a bundle with the endpoints
actually observed, decide which of two sessions is privileged. Those are analysis
needs, and the agent must be able
to write the analyser itself instead of waiting for a developer.

So this is the same lifecycle — propose, validate, register, execute, reuse, audit —
with the *spec* replaced by *short Python*:

====================  ====================================================
proposal              ``tool.compose`` work order, params ``spec``
validation            :func:`sandbox.validate_source` (structural) +
                      :func:`check_spec` (identity, purpose, inputs, advisory
                      verdict)  — both BEFORE registration
registration          the validated source is kept in the run-scoped registry
                      and gets two tools: ``tool.<id>`` (analysis) and
                      ``verify.tool.<id>`` (independent re-execution)
execution             :func:`src.greybox_web.sandbox.run`: the engine resolves
                      and fetches ``spec.inputs`` through the ordinary guarded
                      client (scope, IP policy, budgets, sessions), hands the
                      responses to the generated ``analyse(ctx)``, and validates
                      the returned JSON
result                observations + *candidate* findings (never verified: only
                      the engine's own verification raises that)
reuse                 the tool stays in the registry for the rest of the run
audit                 ``tool.defined`` carries the source, the purpose, the
                      input URLs and the limits; each execution records its
                      duration, output and errors
====================  ====================================================

Prompt injection cannot buy a capability here. The source is written by the model
*in its own turn*, and the only thing target content can do is influence what the
model writes — which then runs with no network, no filesystem and no process
access, with scope already enforced by the engine (see :mod:`src.greybox_web.sandbox`).
The URL list is scope-checked at admission, so a "tool" that tries to reach a third
party is refused before it exists.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from src.greybox_web import broker, events, modes, sandbox

BROKER_CAPS = frozenset(broker.OPS.values())
from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    VerifyResult,
    excerpt,
)

_TOOL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")     # no dots: the namespace is ours
MAX_INPUTS = 8
MAX_PURPOSE = 400
MAX_ARGS_BYTES = 8_000
MAX_BODY_CHARS = 200_000            # per input, as handed to the tool
SEVERITIES = ("low", "medium", "high", "critical")
METHODS = ("GET", "POST")            # analysis reads; it does not modify


class SpecError(ValueError):
    """A composition request the engine refuses (reported, never guessed around)."""


def check_spec(raw: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate a ``tool.compose`` spec; return ``(clean_spec, errors)``.

    The spec is a *request to build an instrument*, so it is validated strictly:
    a missing purpose ("why can no existing tool do this?"), a non-analysis
    identifier, an off-scope input or a source that does not define ``analyse``
    is a refusal with a reason the agent can read and correct.
    """
    errs: list[str] = []
    if not isinstance(raw, dict):
        return None, ["spec must be an object with id, purpose, source"]
    ident = str(raw.get("id") or "").strip()
    if ident.startswith("tool."):
        ident = ident.removeprefix("tool.")
    if not _TOOL_ID_RE.match(ident):
        errs.append("id must match [a-z0-9][a-z0-9-]{0,39} (no dots: the engine "
                    "owns the 'tool.' namespace)")
    purpose = str(raw.get("purpose") or "").strip()
    if len(purpose) < 12:
        errs.append("purpose must say what no existing tool can do (>= 12 chars)")
    elif len(purpose) > MAX_PURPOSE:
        errs.append(f"purpose is longer than {MAX_PURPOSE} chars")
    title = str(raw.get("title") or ident).strip()[:120]
    try:
        source = sandbox.validate_source(raw.get("source"))
    except sandbox.SandboxError as exc:
        errs.append(str(exc))
        source = ""
    inputs = raw.get("inputs") or []
    if not isinstance(inputs, list) or len(inputs) > MAX_INPUTS:
        errs.append(f"inputs must be a list of at most {MAX_INPUTS} urls/methods")
        inputs = []
    clean_inputs: list[dict[str, str]] = []
    for item in inputs:
        if isinstance(item, str):
            item = {"url": item}
        if not isinstance(item, dict) or not str(item.get("url") or "").startswith(
                ("http://", "https://")):
            errs.append(f"each input needs an http(s) url: {item!r}"[:160])
            continue
        method = str(item.get("method") or "GET").upper()
        if method not in METHODS:
            errs.append(f"input method {method!r} is not allowed (analysis only "
                        f"reads: {'/'.join(METHODS)})")
            continue
        clean_inputs.append({"url": str(item["url"])[:2000], "method": method})
    # What the tool may do through ctx.broker (broker.OPS capabilities). Declared
    # up front so admission can refuse a tool the run could never serve, and the
    # broker refuses anything undeclared at execution time.
    caps_raw = raw.get("capabilities")
    capabilities: list[str] = []
    if caps_raw is None:
        capabilities = [modes.RECORDED] + ([modes.HTTP] if clean_inputs else [])
    elif not isinstance(caps_raw, list) or len(caps_raw) > len(BROKER_CAPS):
        errs.append(f"capabilities must be a list drawn from {sorted(BROKER_CAPS)}")
    else:
        for c in caps_raw:
            if c not in BROKER_CAPS:
                errs.append(f"unknown capability {c!r}; allowed: "
                            f"{', '.join(sorted(BROKER_CAPS))}")
            elif c not in capabilities:
                capabilities.append(c)
    if clean_inputs and modes.HTTP not in capabilities:
        capabilities.append(modes.HTTP)       # declared inputs are fetched over HTTP
    max_calls = raw.get("max_calls", broker.DEFAULT_MAX_CALLS)
    if isinstance(max_calls, bool) or not isinstance(max_calls, int) \
            or not 1 <= max_calls <= broker.MAX_CALLS_CAP:
        errs.append(f"max_calls must be an integer 1..{broker.MAX_CALLS_CAP}")
        max_calls = broker.DEFAULT_MAX_CALLS
    advisory = raw.get("advisory") or {}
    if advisory and not isinstance(advisory, dict):
        errs.append("advisory must be an object")
        advisory = {}
    if advisory:
        if not str(advisory.get("title") or "").strip():
            errs.append("advisory needs a title")
        if str(advisory.get("severity") or "low").lower() not in SEVERITIES:
            errs.append(f"advisory severity must be one of {SEVERITIES}")
    if errs:
        return None, errs
    return {
        "id": f"tool.{ident}",
        "short_id": ident,
        "title": title or f"Analysis tool {ident}",
        "purpose": purpose,
        "source": source,
        "inputs": clean_inputs,
        "capabilities": capabilities,
        "max_calls": max_calls,
        "advisory": {k: str(v)[:600] for k, v in advisory.items()} if advisory else {},
    }, []


def registry_entries(spec: dict[str, Any]) -> dict[str, Any]:
    """The run-scoped registry entries for one composed tool.

    Two tools, as for declarative instruments: the analysis itself and its
    verifier — a second, independent execution of the same source over freshly
    fetched inputs. Verification is the engine's judgement, so a composed tool can
    corroborate a hypothesis but can never declare one "verified" by itself."""
    from src.greybox_web.tools import ToolSpec

    async def _run(ctx: ToolContext) -> ToolResult:
        return await execute(spec, ctx)

    async def _verify(ctx: ToolContext) -> VerifyResult:
        return await replay(spec, ctx)

    return {
        spec["id"]: ToolSpec(spec["id"], "check", _run,
                             param_keys=("url", "urls", "args"),
                             title=spec["title"], capability=modes.SANDBOX),
        f"verify.{spec['id']}": ToolSpec(
            f"verify.{spec['id']}", "verify", _verify,
            # the finding's own text travels with the verification (it is what the
            # replay must reproduce); declare it or admission refuses the work order
            param_keys=("finding_id", "url", "urls", "title", "args",
                        "requires_effect", "effect_probe"),
            title=spec["title"], capability=modes.SANDBOX),
    }


# ------------------------------------------------------------------ execution

async def _fetch(ctx: ToolContext, spec: dict[str, Any]) -> tuple[list[dict], list[int]]:
    """Fetch the tool's declared inputs through the guarded client and describe
    them for the sandbox. Scope, IP policy, budgets, rate limits and the run's
    session cookies all apply exactly as they do for a built-in tool.

    ``ctx.params['urls']`` may narrow the set (the same tool reused on another
    page); it can never widen it beyond the declared, admitted inputs."""
    extra = ctx.params.get("urls") or []
    if isinstance(extra, str):
        extra = [extra]
    wanted = [u for u in extra if isinstance(u, str) and u.startswith(("http://",
                                                                      "https://"))]
    declared = [i["url"] for i in spec["inputs"]]
    urls = [u for u in wanted if u in declared] or declared
    if not urls and isinstance(ctx.params.get("url"), str):
        urls = [ctx.params["url"]]
    responses: list[dict] = []
    exchange_ids: list[int] = []
    for url in urls:
        try:
            resp = await ctx.http.get(url)
        except Exception as exc:                      # noqa: BLE001 - reported as data
            responses.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
            continue
        exchange_ids.extend([e for e in (resp.exchange_ids or []) if e is not None])
        headers = {k.lower(): v for k, v in resp.headers}
        cookie_names = sorted({h.split("=", 1)[0].strip()
                               for h in headers.get("set-cookie", "").split(",")[0:1]
                               if "=" in h})
        responses.append({
            "url": resp.url,
            "requested_url": url,
            "status": resp.status,
            "content_type": headers.get("content-type", ""),
            "headers": {k: headers[k] for k in sorted(headers)},
            "body": resp.text[:MAX_BODY_CHARS],
            "truncated": bool(resp.truncated) or len(resp.text) > MAX_BODY_CHARS,
            "set_cookie_names": cookie_names,
            "redirects": list(resp.hops or ()),
        })
    return responses, exchange_ids


async def execute(spec: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """One execution: fetch the inputs, run the generated analysis, report.

    A sandbox failure is a FAILED tool result with the error text (so the agent can
    fix its code and try again) — never an empty "nothing found", which would be a
    false negative dressed as an answer."""
    fetch = bool(spec["inputs"]) or (isinstance(ctx.params.get("url"), str)
                                     and modes.HTTP in (spec.get("capabilities") or ()))
    responses, exchange_ids = await _fetch(ctx, spec) if fetch else ([], [])
    args = ctx.params.get("args") or {}
    if not isinstance(args, dict) or len(json.dumps(args, default=str)) > MAX_ARGS_BYTES:
        raise sandbox.SandboxError(f"{spec['id']}: args must be an object of at most "
                                   f"{MAX_ARGS_BYTES} bytes")
    arguments = {
        "responses": responses,
        "url": ctx.params.get("url") or ctx.base_url,
        "base_url": ctx.base_url,
        "args": args,
        "params": {k: v for k, v in (ctx.params or {}).items()
                   if k not in ("spec", "args")},
    }
    if len(json.dumps(arguments, default=str)) > MAX_ARGS_BYTES * 25:
        arguments["responses"] = [
            {k: v for k, v in r.items() if k != "body"} | {"body": (r.get("body") or "")[:20_000]}
            for r in responses]
    allowed = modes.for_scope(ctx.scope).allowed
    brk = broker.Broker(ctx, declared=set(spec.get("capabilities") or ()),
                        allowed=set(allowed), max_calls=spec.get("max_calls")
                        or broker.DEFAULT_MAX_CALLS,
                        inventory=getattr(ctx, "inventory", None))
    result = await sandbox.run(spec["source"], arguments, broker=brk)
    exchange_ids = exchange_ids + [i for i in brk.exchange_ids if i not in exchange_ids]
    obs_key = f"{spec['id']}|{ctx.params.get('url') or ctx.base_url}"[:300]
    if not result.ok:
        # The error, the tool's own log and its broker calls are what the agent
        # needs to fix the code: they travel in the failure text it will read.
        calls = "; ".join(f"{c['op']} {c.get('target') or ''} -> "
                          f"{c.get('error') or c.get('status') or c['outcome']}"
                          for c in brk.calls[-5:])
        raise sandbox.SandboxError(
            f"{spec['id']} failed: {result.error}"
            + (f" || last broker calls: {calls}" if calls else "")
            + (f" || log: {result.log[-300:]}" if result.log else ""))
    doc = result.result
    summary = doc.get("summary") or spec["title"]
    observations = [Observation(
        key=f"{spec['id']}|{o['key']}"[:300], label=o["key"][:200],
        facts=o["facts"], url=ctx.base_url) for o in doc["observations"]]
    findings: list[FindingSpec] = []
    requested = [str(c.get("target") or "").split(" ", 1)[1] for c in brk.calls
                 if c.get("op") == "http" and " " in str(c.get("target") or "")]
    state_changes = [c for c in brk.calls if c.get("op") == "http"
                     and c.get("state_changing")]
    effect_outcomes: list[str] = []
    title_counts = Counter(f["title"] for f in doc["findings"])
    for f in doc["findings"]:
        effect_evidence, effect_outcome = _validated_effect(f, brk.calls)
        after_id = (f.get("effect") or {}).get("after_exchange_id") \
            if isinstance(f.get("effect"), dict) else None
        effect_probe = brk.replays.get(after_id) if after_id is not None else None
        effect_outcomes.append(effect_outcome)
        # the finding is about what it names, not about where the tool was pointed
        # (an analyser run on /openapi.json reporting the audit API).
        url = located(f, requested, ctx.scope) or ctx.params.get("url") or ctx.base_url
        findings.append(FindingSpec(
            check_id=spec["id"],
            detail=(f"{spec['id']}|{f['title']}" if title_counts[f["title"]] > 1
                    else f"{spec['id']}|{url}|{f['title']}")[:300],
            title=f["title"][:200], severity=f["severity"],
            # Agent-authored analyses observe; only verify.tool.<id> confirms. The
            # confidence says so, and the finding is re-examined like any other.
            confidence="low",
            description=(f["description"] + (("\n\nWhy this tool exists: "
                                              + spec["purpose"])
                                             if spec["purpose"] else ""))[:2000],
            url=url,
            identity=(f"generated:{spec['id']}:{f['title']}"[:300]
                      if title_counts[f["title"]] > 1 else None),
            occurrence=url if title_counts[f["title"]] > 1 else None,
            cwe=f.get("cwe") or None,
            evidence=(effect_evidence or [Evidence(
                role="proof", exchange_id=exchange_ids[0] if exchange_ids else None,
                excerpt=(f.get("evidence") or [summary])[0][:500],
                note=f"produced by the agent-authored analyser {spec['id']} "
                     f"({result.duration_ms} ms); effect: {effect_outcome}")])
            + [Evidence(role="baseline", exchange_id=eid, excerpt="",
                        note="input read by the analysis tool")
               for eid in exchange_ids if eid not in {e.exchange_id
                                                       for e in effect_evidence}],
            verify={"url": url, "title": f["title"],
                    **({"args": args} if args else {}),
                    **({"requires_effect": True} if state_changes else {}),
                    **({"effect_probe": effect_probe}
                       if effect_outcome == "confirmed_exploitable" and effect_probe
                       else {})},
            observation_key=obs_key,
            finding_class=f.get("class"),
            remediation=_remediation(f),
            exploitability_outcome=effect_outcome,
            **({"asset_ref": _asset_ref(f["affected"])} if f.get("affected")
               and _asset_ref(f["affected"]) else {}),
            # an affected in-scope URL: the finding belongs to that endpoint
            **({"asset_url": f["affected"]}
               if str(f.get("affected") or "").startswith(("http://", "https://"))
               and ctx.scope.check_url(f["affected"]).allowed else {}),
        ))
    return ToolResult(
        summary=f"{spec['id']}: {summary}"[:300],
        counts={"inputs": len(responses), "findings": len(findings),
                "duration_ms": result.duration_ms,
                "broker_calls": len(brk.calls),
                "state_changes": len(state_changes),
                "observable_effects": sum(o == "confirmed_exploitable"
                                          for o in effect_outcomes)},
        examined=sorted({str(c.get("target") or "").split(" ", 1)[1]
                         for c in brk.calls
                         if c.get("op") == "http" and c.get("outcome") == "ok"
                         and str(c.get("target") or "").startswith(("GET ", "HEAD "))
                         and isinstance(c.get("status"), int)}
                        | {r.get("requested_url") or r.get("url")
                           for r in responses if r.get("status")})[:200],
        observations=observations + [Observation(
            key=obs_key, label=f"analysis tool {spec['id']}",
            facts={"inputs": [r.get("url") for r in responses],
                   "requests": len(responses), "duration_ms": result.duration_ms,
                   "limits": result.limits, "isolation": result.isolation,
                   "capabilities": list(spec.get("capabilities") or ()),
                   "broker": brk.audit(),
                   "args": args,
                   "observations": len(observations),
                   "findings": len(findings),
                   **({"log": result.log[-500:]} if result.log else {})},
            url=ctx.base_url, exchange_ids=exchange_ids[:50])],
        findings=findings)


def located(f: dict[str, Any], requested: list[str], scope) -> str | None:
    """The in-scope URL a finding names: among the URLs the tool requested, the
    one whose path (or its route template) appears in the finding's title,
    description or evidence — the most specific match. None when nothing fits."""
    from src.greybox_web.tools.authz import route_template
    affected = str(f.get("affected") or "")
    if affected.startswith(("http://", "https://")) and scope.check_url(affected).allowed:
        return affected
    text = " ".join([str(f.get("title") or ""), str(f.get("description") or "")]
                    + [str(e) for e in f.get("evidence") or []])
    best: tuple[int, str] | None = None
    for u in dict.fromkeys(requested):
        path = urlsplit(u).path or "/"
        if path in ("", "/") or not scope.check_url(u).allowed:
            continue
        tpl = "/" + route_template(u).split("/", 1)[1] if "/" in route_template(u) \
            else ""
        for cand in (path, tpl):
            if cand and cand in text and (best is None or len(cand) > best[0]):
                best = (len(cand), u.split("?", 1)[0] if cand != path else u)
    return best[1] if best else None


def _validated_effect(finding: dict[str, Any], calls: list[dict[str, Any]]) \
        -> tuple[list[Evidence], str]:
    """Validate a generated tool's effect references against engine-owned calls."""
    attempted = [c for c in calls if c.get("op") == "http"
                 and c.get("state_changing")]
    if not attempted:
        return [], "confirmed"
    if all(c.get("outcome") == "blocked" for c in attempted):
        return [], "blocked_by_configuration"
    effect = finding.get("effect")
    if not isinstance(effect, dict):
        return [], "inconclusive"
    indexed = {c.get("exchange_id"): (index, c) for index, c in enumerate(calls)
               if c.get("op") == "http" and c.get("outcome") == "ok"
               and c.get("exchange_id") is not None}
    refs = [effect.get(key) for key in ("before_exchange_id",
                                        "action_exchange_id",
                                        "after_exchange_id")]
    if any(ref not in indexed for ref in refs):
        refs = []
        for action_index, action in enumerate(calls):
            if not action.get("state_changing") or action.get("outcome") != "ok" \
                    or action.get("application_error"):
                continue
            action_url = str(action.get("target") or "").split(" ", 1)[-1]
            action_resources = (set(action.get("resource_markers") or ()) |
                                set(action.get("response_resource_markers") or ()))
            reads = [(index, item) for index, item in enumerate(calls)
                     if item.get("op") == "http" and item.get("outcome") == "ok"
                     and not item.get("state_changing")
                     and str(item.get("target") or "").split(" ", 1)[-1] == action_url]
            for before_index, before in reversed([item for item in reads if item[0] < action_index]):
                before_resources = (set(before.get("resource_markers") or ()) |
                                    set(before.get("response_resource_markers") or ()))
                for after_index, after in [item for item in reads if item[0] > action_index]:
                    after_resources = (set(after.get("resource_markers") or ()) |
                                       set(after.get("response_resource_markers") or ()))
                    if (before.get("identity") == after.get("identity")
                            and before.get("request_fingerprint") == after.get("request_fingerprint")
                            and action_resources & before_resources & after_resources):
                        refs = [before.get("exchange_id"), action.get("exchange_id"),
                                after.get("exchange_id")]
                        break
                if refs:
                    break
            if refs:
                break
        if not refs:
            return [], "inconclusive"
    (before_index, before), (action_index, action), (after_index, after) = [indexed[ref] for ref in refs]
    before_url = str(before.get("target") or "").split(" ", 1)[-1]
    after_url = str(after.get("target") or "").split(" ", 1)[-1]
    before_markers = (set(before.get("resource_markers") or ()) |
                      set(before.get("response_resource_markers") or ()))
    action_markers = (set(action.get("resource_markers") or ()) |
                      set(action.get("response_resource_markers") or ()))
    after_markers = (set(after.get("resource_markers") or ()) |
                     set(after.get("response_resource_markers") or ()))
    same_resource = bool(before_markers & action_markers & after_markers)
    valid = (before_index < action_index < after_index
             and same_resource
             and not before.get("state_changing")
             and not after.get("state_changing")
             and action.get("state_changing") and 200 <= action.get("status", 0) < 300
             and not action.get("application_error")
             and before_url == after_url
             and before.get("identity") == after.get("identity")
             and before.get("request_fingerprint")
             and before.get("request_fingerprint") == after.get("request_fingerprint"))
    if not valid:
        return [], "inconclusive"
    if before.get("response_fingerprint") == after.get("response_fingerprint"):
        return [], "no_impact"
    impact = str(effect.get("impact") or "")[:500]
    return [
        Evidence("baseline", refs[0], "state before the controlled action"),
        Evidence("proof", refs[1], impact, "operator-authorised state-changing action"),
        Evidence("proof", refs[2], "state changed after the controlled action",
                 "before/after response differs for the same resource and identity"),
    ], "confirmed_exploitable"


def _remediation(f: dict[str, Any]) -> dict[str, Any] | None:
    rem = f.get("remediation")
    doc: dict[str, Any] = dict(rem) if isinstance(rem, dict) else (
        {"summary": rem} if rem else {})
    if f.get("verification") and "validation" not in doc:
        doc["validation"] = [f["verification"]]
    if f.get("severity_rationale") and "severity_rationale" not in doc:
        doc["severity_rationale"] = f["severity_rationale"]
    return doc or None


def _asset_ref(affected: str) -> tuple[str, str] | None:
    """A finding about a non-URL asset (``tcp://host:port`` service, a host)."""
    a = affected.strip()
    if a.startswith("tcp://"):
        return ("service", a)
    if a.startswith("host:"):
        return ("host", a[5:])
    return None


async def replay(spec: dict[str, Any], ctx: ToolContext) -> VerifyResult:
    """Independently verify a generated observation.

    Read-only findings rerun the analyser. State effects are verified with a fresh
    engine-controlled read of the originally demonstrated post-condition so an
    irreversible authorised action is never repeated merely for verification."""
    finding = ctx.params.get("finding") or {}
    if not isinstance(finding, dict):
        finding = {}
    wanted_title = str(ctx.params.get("title") or finding.get("title") or "").strip()
    if not wanted_title:
        return VerifyResult(False, f"replay {spec['id']}",
                            "inconclusive: verification did not identify a finding",
                            outcome="inconclusive")
    effect_probe = ctx.params.get("effect_probe")
    if ctx.params.get("requires_effect") and isinstance(effect_probe, dict):
        try:
            resp = await ctx.http.request(
                str(effect_probe.get("method") or "GET"), str(effect_probe["url"]),
                body=effect_probe.get("body"),
                content_type=effect_probe.get("content_type"),
                follow=bool(effect_probe.get("follow", True)),
                session=effect_probe.get("session"))
        except Exception as exc:  # noqa: BLE001
            return VerifyResult(False, f"persisted effect of {spec['id']}",
                                f"independent post-condition read failed: {exc}",
                                outcome="not_reproduced")
        observed = hashlib.sha256(
            f"{resp.status}\n{resp.text}".encode("utf-8", "replace")).hexdigest()
        confirmed = observed == effect_probe.get("expected_fingerprint")
        return VerifyResult(
            confirmed, f"persisted effect of {spec['id']}",
            "independent read observed the same persisted post-condition"
            if confirmed else "the demonstrated post-condition no longer persists",
            list(resp.exchange_ids), excerpt(resp.text),
            "confirmed_exploitable" if confirmed else "not_reproduced")
    try:
        again = await execute(spec, ctx)
    except sandbox.SandboxError as exc:
        return VerifyResult(confirmed=False, method=f"replay {spec['id']}",
                            note=f"not reproducible: {exc}")
    matching = [f for f in again.findings if f.title.strip() == wanted_title]
    requires_effect = bool(ctx.params.get("requires_effect"))
    outcome = (matching[0].exploitability_outcome if matching else
               "not_reproduced")
    confirmed = bool(matching) and (not requires_effect or
                                    outcome == "confirmed_exploitable")
    ids = [e.exchange_id for f in matching for e in f.evidence
           if e.exchange_id is not None]
    note = ("the analysis reproduced the finding with an independently observed "
            "before/after state effect" if confirmed and requires_effect else
            "the analysis reproduced the finding on a fresh execution" if confirmed else
            f"the analysis did not demonstrate impact ({outcome})")
    return VerifyResult(
        confirmed=confirmed, method=f"replay {spec['id']}", note=note,
        exchange_ids=ids[:20], excerpt=excerpt(again.summary), outcome=outcome)


async def define(ctx: ToolContext) -> ToolResult:
    """Execution of a ``tool.compose`` work order: no requests, no subprocess.

    The source is already registered (admission validated it); this records the
    composition as an observation so the run's story shows the tool being built
    and why."""
    spec, errs = check_spec(ctx.params.get("spec"))
    raw = ctx.params.get("spec") if isinstance(ctx.params.get("spec"), dict) else {}
    ident = spec["id"] if spec else str(raw.get("id") or "tool.?")
    obs = Observation(
        key=f"tool.compose|{ident}"[:300],
        label=f"analysis tool composed: {ident} — "
              f"{spec['title'] if spec else raw.get('title') or ''}"[:300],
        facts={"id": ident, "purpose": (spec or raw).get("purpose", ""),
               "inputs": [i["url"] for i in spec["inputs"]] if spec else [],
               "source_lines": len((spec or raw).get("source", "").splitlines()),
               "requests_made": 0,
               "errors": errs[:3]},
        url=None)
    return ToolResult(summary=f"analysis tool composed: {ident} "
                              f"({obs.facts['source_lines']} lines)",
                      counts={"composed": 1}, observations=[obs])


def audit_payload(spec: dict[str, Any]) -> dict[str, Any]:
    """What ``tool.defined`` shows for a composed tool: the source is part of the
    permanent record (clipped), together with the declared inputs and limits."""
    return {
        "id": spec["id"], "kind": "check", "title": spec["title"][:200],
        "param_keys": ["url", "urls", "args"], "kind_detail": "composed",
        "purpose": spec["purpose"][:400],
        "inputs": [i["url"] for i in spec["inputs"]],
        "capabilities": list(spec.get("capabilities") or ()),
        "max_calls": spec.get("max_calls"),
        "limits": sandbox.DEFAULT_LIMITS.as_dict(),
        # the WHOLE source (<= TOOL_SOURCE_CAP): the record of what ran
        "source": spec["source"],
    }


def host_of(url: str) -> str:
    return urlsplit(url).hostname or ""
