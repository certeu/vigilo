"""Controlled server-side callback observation through the guarded HTTP client."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from src.greybox_web.netguard import (
    ScopeViolation,
    TransportFailure,
    classify_ip,
    is_loopback_name,
    is_private,
    parse_ip,
)
from src.greybox_web.tools import Evidence, FindingSpec, Observation, ToolContext, ToolResult, VerifyResult


@dataclass
class CallbackRun:
    outcome: str
    note: str
    trigger_status: int | None = None
    positive_status: int | None = None
    exchange_ids: list[int] | None = None
    excerpt: str = ""
    proof_exchange_id: int | None = None


def _token_url(template: str, token: str) -> str:
    if "{token}" not in template:
        raise ValueError("callback_url and observation_url must contain {token}")
    return template.replace("{token}", quote(token, safe=""))


def _local(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if is_loopback_name(host):
        return True
    address = parse_ip(host)
    return address is not None and is_private(classify_ip(address))


def _seen(response, marker: str) -> bool:
    return 200 <= response.status < 300 and marker in response.text


def _trigger_url(url: str, parameter: str, callback_url: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[parameter] = callback_url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _settings(ctx: ToolContext) -> tuple[str, str, str, str, str, int]:
    raw_trigger = str(ctx.params.get("trigger_url") or "")
    raw_callback = str(ctx.params.get("callback_url") or "")
    raw_observation = str(ctx.params.get("observation_url") or "")
    if not raw_trigger or not raw_callback or not raw_observation:
        raise ValueError("trigger_url, callback_url and observation_url are required")
    trigger = urljoin(ctx.base_url, raw_trigger)
    callback = urljoin(ctx.base_url, raw_callback)
    observation = urljoin(ctx.base_url, raw_observation)
    parameter = str(ctx.params.get("param") or "url").strip()
    identity = str(ctx.params.get("identity") or "anon")
    attempts = int(ctx.params.get("poll_attempts") or 3)
    if not parameter:
        raise ValueError("param is required")
    if not (1 <= attempts <= 5):
        raise ValueError("poll_attempts must be between 1 and 5")
    if identity not in ({str(item.get("label")) for item in ctx.http.sessions()} | {"anon"}):
        raise ValueError(f"unknown identity {identity!r}")
    for name, url in (("trigger_url", trigger), ("callback_url", callback),
                      ("observation_url", observation)):
        sample = url.replace("{token}", "vigilo-callback-scope-check")
        if not ctx.http.in_scope(sample):
            raise ValueError(f"{name} is outside the configured assessment scope")
    if not _local(callback) or not _local(observation):
        raise ValueError("callback observation is limited to in-scope local endpoints")
    _token_url(callback, "vigilo-callback-shape-check")
    _token_url(observation, "vigilo-callback-shape-check")
    marker = str(ctx.params.get("success_marker") or "{token}")
    if "{token}" not in marker:
        raise ValueError("success_marker must contain {token} for correlation")
    return trigger, callback, observation, parameter, identity, attempts


async def _execute(ctx: ToolContext) -> CallbackRun:
    trigger, callback_template, observation_template, parameter, identity, attempts = _settings(ctx)
    token = f"vigilo-callback-{ctx.token()}"
    control = f"vigilo-control-{ctx.token()}"
    callback_url = _token_url(callback_template, token)
    positive_observation_url = _token_url(observation_template, token)
    negative_observation_url = _token_url(observation_template, control)
    marker_template = str(ctx.params.get("success_marker") or "{token}")
    marker = marker_template.replace("{token}", token)
    control_marker = marker_template.replace("{token}", control)
    ids: list[int] = []

    before_positive = await ctx.http.request(
        "GET", positive_observation_url, follow=False, session="anon")
    before_control = await ctx.http.request(
        "GET", negative_observation_url, follow=False, session="anon")
    ids.extend(before_positive.exchange_ids)
    ids.extend(before_control.exchange_ids)
    if _seen(before_positive, marker) or _seen(before_control, control_marker):
        return CallbackRun("inconclusive", "callback observer was not clean before the test",
                           positive_status=before_positive.status, exchange_ids=ids)

    invoked = await ctx.http.request(
        "GET", _trigger_url(trigger, parameter, callback_url), follow=False, session=identity)
    ids.extend(invoked.exchange_ids)
    observed = None
    for attempt in range(attempts):
        observed = await ctx.http.request(
            "GET", positive_observation_url, follow=False, session="anon")
        ids.extend(observed.exchange_ids)
        if _seen(observed, marker):
            break
        if attempt + 1 < attempts:
            await asyncio.sleep(0.1)
    after_control = await ctx.http.request(
        "GET", negative_observation_url, follow=False, session="anon")
    ids.extend(after_control.exchange_ids)
    if _seen(after_control, control_marker):
        return CallbackRun("inconclusive", "negative control was reported after the trigger",
                           invoked.status, getattr(observed, "status", None), ids)
    if observed is not None and _seen(observed, marker):
        return CallbackRun(
            "confirmed_exploitable",
            "target-triggered request independently appeared at the controlled callback observer",
            invoked.status, observed.status, ids, marker, observed.exchange_id)
    return CallbackRun("not_reproduced", "no correlated callback was observed after the bounded trigger",
                       invoked.status, getattr(observed, "status", None), ids)


async def _run(ctx: ToolContext) -> CallbackRun:
    try:
        return await _execute(ctx)
    except (TypeError, ValueError) as exc:
        return CallbackRun("blocked_by_configuration", str(exc), exchange_ids=[])
    except ScopeViolation as exc:
        return CallbackRun("blocked_by_configuration", f"guard refused callback step: {exc.reason}",
                           exchange_ids=[exc.exchange_id] if exc.exchange_id else [])
    except TransportFailure as exc:
        return CallbackRun("inconclusive", f"callback endpoint unavailable: {exc.kind}",
                           exchange_ids=[exc.exchange_id] if exc.exchange_id else [])


async def observe(ctx: ToolContext) -> ToolResult:
    run = await _run(ctx)
    trigger = str(ctx.params.get("trigger_url") or ctx.base_url)
    parameter = str(ctx.params.get("param") or "url")
    facts = {"outcome": run.outcome, "note": run.note,
             "trigger_status": run.trigger_status, "observation_status": run.positive_status,
             "positive_control": run.outcome == "confirmed_exploitable",
             "negative_control": run.trigger_status is not None and run.outcome != "inconclusive"}
    observation = Observation(
        key=f"callback.observe|{trigger}|{parameter}", label=run.note, facts=facts,
        url=trigger, exchange_ids=list(run.exchange_ids or []))
    findings = []
    if run.outcome == "confirmed_exploitable":
        findings.append(FindingSpec(
            check_id="callback.observe", detail=parameter,
            title=f"Server-side callback controlled through parameter {parameter}",
            severity="medium", confidence="high",
            description=("A benign unique callback URL supplied to the application caused a "
                         "server-side request to an operator-owned local observer. A second "
                         "unique marker remained absent, excluding a promiscuous observer."),
            url=trigger, parameter=parameter, param_location="query",
            evidence=[Evidence("proof", run.proof_exchange_id, run.excerpt, run.note)],
            verify={key: value for key, value in ctx.params.items() if key in {
                "trigger_url", "callback_url", "observation_url", "param", "identity",
                "success_marker", "poll_attempts"}},
            cwe="CWE-918", observation_key=observation.key, finding_class="vulnerability",
            exploitability_outcome="confirmed_exploitable",
            remediation={
                "summary": "Restrict server-side URL fetching to explicitly approved destinations.",
                "steps": ["Validate the resolved destination and every redirect against an allowlist.",
                          "Block private, loopback, link-local and metadata address ranges."],
                "validation": ["The same benign callback and a negative control both remain absent."],
                "reproduction": ["Supply a unique in-scope local callback URL and poll its separate observer."],
                "severity_rationale": "Server-side request execution was demonstrated without probing external systems."}))
    return ToolResult(
        summary=f"controlled callback: {run.outcome} ({run.note})",
        counts={"attempted": int(run.trigger_status is not None),
                "callbacks": int(run.outcome == "confirmed_exploitable")},
        observations=[observation], findings=findings,
        examined=[trigger] if run.trigger_status is not None else [])


async def verify(ctx: ToolContext) -> VerifyResult:
    run = await _run(ctx)
    return VerifyResult(run.outcome == "confirmed_exploitable", "fresh controlled callback correlation",
                        run.note, list(run.exchange_ids or []), run.excerpt, run.outcome)
