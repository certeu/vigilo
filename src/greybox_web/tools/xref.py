"""``authz.exposure``: is information about a resource available through one interface
to an identity that the resource's own interface refuses?

Some access-control weaknesses are not visible on any single endpoint: the project
API refuses a non-member, but the team activity feed describes that project to
them; the document API hides a draft, but its versions API serves it. Verifying
such a case needs several related observations, and needs to rule out the
ordinary explanations. This check takes the agent's claim apart into requests the
engine makes itself:

``url``          the interface where the information appears (feed, export, list…)
``viewer``       the identity that should not see it
``marker``       a string from the resource (an id, a title) that shows up in it
``control_url``  the resource's own interface, where the boundary is enforced
``owner``        optional: an identity that legitimately has the resource

Requests: (1) ``url`` as the viewer — does it contain the marker? (2) ``url``
anonymously — is it simply public? (3) ``control_url`` as the viewer — is the
viewer refused? (4) ``control_url`` as the owner — does the resource exist and is
it served to someone? (5) ``control_url`` anonymously, when the url was public.

Decision (:func:`decide`, pure):

* ``not_present``      the marker is not in what the viewer receives;
* ``public``           both interfaces serve it anonymously: intentionally public;
* ``authorised``       the control interface serves the viewer too: no boundary;
* ``unknown``          the boundary cannot be established (the viewer gets 404 and
                       no owner shows the resource exists; or a 5xx);
* ``boundary_crossed`` the viewer is refused by the control interface (403/401,
                       or 404 while the owner is served) and still receives the
                       marker through ``url`` — a finding, with every step's
                       exchange as evidence.

Only ``boundary_crossed`` is a finding; the others are recorded observations. The
verifier re-runs all requests and requires the same decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from src.greybox_web.netguard import ScopeViolation, TransportFailure
from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    VerifyResult,
    excerpt,
)

MIN_MARKER = 4
NOT_PRESENT, PUBLIC, AUTHORISED, UNKNOWN, CROSSED = (
    "not_present", "public", "authorised", "unknown", "boundary_crossed")

REMEDIATION = {
    "summary": "Apply the resource's access rule in every interface that returns "
               "data about it, not only in the resource's own endpoint.",
    "steps": ["Filter the secondary interface (feed, export, search, list, history) "
              "with the same authorisation check as the resource's own read "
              "endpoint: drop records about resources the caller may not read.",
              "Centralise the rule (one policy function or query scope used by every "
              "handler) so new interfaces cannot bypass it.",
              "Add a regression test per interface reading as a user without access."],
    "validation": ["As the refused identity, the secondary interface no longer "
                   "returns the resource's identifier or metadata.",
                   "The resource's own interface still refuses that identity, and "
                   "still serves authorised users."],
    "severity_rationale": "An identity refused by the resource's own interface "
                          "obtains information about it through a related interface.",
}


@dataclass
class Step:
    name: str
    url: str
    identity: str
    status: int | None = None
    contains: bool | None = None
    exchange_ids: list[int] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"step": self.name, "identity": self.identity, "url": self.url,
                "status": self.status, "marker_present": self.contains,
                **({"error": self.error} if self.error else {})}


def _ok(s: Step | None) -> bool:
    return s is not None and s.status is not None and 200 <= s.status < 300


def _refused(s: Step | None) -> bool:
    return s is not None and s.status in (401, 403)


def _bound(owner: Step | None) -> bool:
    return owner is not None and _ok(owner) and bool(owner.contains)


def _marker_present(text: str, marker: str) -> bool:
    import re
    return bool(re.search(r"(?<![A-Za-z0-9_-])" + re.escape(marker)
                          + r"(?![A-Za-z0-9_-])", text or "", re.I))


def decide(view: Step, anon: Step | None, control: Step, owner: Step | None,
           control_anon: Step | None) -> tuple[str, str]:
    """(decision, reason) from the observed steps (pure)."""
    if not (_ok(view) and view.contains):
        return NOT_PRESENT, "the viewer does not receive the marker through the interface"
    from src.greybox_web.tools.authz import capability_url
    if _ok(anon) and anon.contains and capability_url(view.url):
        return AUTHORISED, "the related interface is an anonymous capability/share link"
    if _ok(anon) and anon.contains and _ok(control_anon):
        return PUBLIC, "both interfaces serve it without authentication"
    if _ok(control):
        return AUTHORISED, "the resource's own interface also serves the viewer"
    if _ok(owner) and not owner.contains:
        return UNKNOWN, ("the marker is not part of the resource as served to its "
                         "owner: it may identify something else (a person, a shared "
                         "label) rather than this resource")
    if control.status is None or control.status >= 500:
        return UNKNOWN, "the control interface did not answer conclusively"
    if _refused(control) and not _bound(owner):
        return UNKNOWN, ("the control refuses the viewer, but no authorised read binds "
                         "the marker to that protected resource")
    if _refused(control):
        return CROSSED, (f"refused by the control interface (HTTP {control.status}) "
                         "but present in the related interface")
    if control.status in (404, 410):
        if _ok(owner):
            return CROSSED, ("hidden from the viewer by the control interface "
                             f"(HTTP {control.status}) while it exists for the owner, "
                             "yet present in the related interface")
        return UNKNOWN, ("the control interface answers 404 and no owner shows the "
                         "resource exists: the boundary cannot be established")
    return UNKNOWN, f"unexpected control answer HTTP {control.status}"


def _validate(p: dict[str, Any], ctx: ToolContext) -> str | None:
    marker = str(p.get("marker") or "")
    if len(marker) < MIN_MARKER:
        return f"marker must be at least {MIN_MARKER} characters"
    url, control = str(p.get("url") or ""), str(p.get("control_url") or "")
    if not url or not control:
        return "url and control_url are required"
    if url.split("?", 1)[0] == control.split("?", 1)[0]:
        return "url and control_url must be different interfaces"
    if marker.lower() in url.lower():
        return "the marker appears in the url itself (an echo proves nothing)"
    if not p.get("viewer"):
        return "viewer (an identity label) is required"
    labels = {s.get("label") for s in ctx.http.sessions()} | {"anon"}
    for k in ("viewer", "owner"):
        if p.get(k) and p[k] not in labels:
            return f"unknown identity {p[k]!r}; known: {', '.join(sorted(labels))}"
    if p.get("owner") and p["owner"] == p["viewer"]:
        return "owner and viewer must be different identities"
    return None


async def _step(ctx: ToolContext, name: str, url: str, identity: str,
                marker: str) -> Step:
    s = Step(name, url, identity)
    try:
        r = await ctx.http.get(url, follow=False, session=identity)
    except (ScopeViolation, TransportFailure, ValueError) as exc:
        s.error = str(exc)[:200]
        return s
    s.status, s.exchange_ids = r.status, list(r.exchange_ids)
    s.contains = _marker_present(r.text or "", marker)
    return s


async def measure(ctx: ToolContext) -> tuple[str, str, list[Step]]:
    p = ctx.params
    marker, viewer, owner = str(p["marker"]), str(p["viewer"]), p.get("owner")
    view = await _step(ctx, "related interface as viewer", p["url"], viewer, marker)
    anon = None if viewer == "anon" else \
        await _step(ctx, "related interface anonymously", p["url"], "anon", marker)
    control = await _step(ctx, "control interface as viewer", p["control_url"],
                          viewer, marker)
    own = await _step(ctx, "control interface as owner", p["control_url"],
                      str(owner), marker) if owner else None
    control_anon = await _step(ctx, "control interface anonymously",
                               p["control_url"], "anon", marker) \
        if anon is not None and _ok(anon) and anon.contains else None
    decision, reason = decide(view, anon, control, own, control_anon)
    steps = [s for s in (view, anon, control, own, control_anon) if s is not None]
    return decision, reason, steps


def _tpl(url: str) -> str:
    from src.greybox_web.tools.authz import route_template
    return route_template(url)


async def exposure(ctx: ToolContext) -> ToolResult:
    p = ctx.params
    problem = _validate(p, ctx)
    if problem:
        raise ValueError(f"authz.exposure: {problem}")
    decision, reason, steps = await measure(ctx)
    ids = [i for s in steps for i in s.exchange_ids]
    path = urlsplit(p["url"]).path or "/"
    cpath = urlsplit(p["control_url"]).path or "/"
    facts = {"decision": decision, "reason": reason, "viewer": p["viewer"],
             "owner": p.get("owner"), "marker": str(p["marker"])[:80],
             "interface": path, "control": cpath,
             "steps": [s.as_dict() for s in steps]}
    obs = Observation(key=f"authz.exposure|{path}|{cpath}|{p['viewer']}"[:300],
                      label=f"{p['viewer']} via {path} vs {cpath}: {decision}",
                      url=p["url"], exchange_ids=ids[:20], facts=facts)
    findings = []
    if decision == CROSSED:
        public_too = any(s.identity == "anon" and _ok(s) and s.contains
                         for s in steps if s.url == p["url"])
        claim = [f"Identity: {p['viewer']}"
                 + (" (also anonymous visitors)" if public_too else ""),
                 f"Resource: identified by '{str(p['marker'])[:60]}'",
                 f"Expected boundary: {cpath} refuses {p['viewer']} "
                 + (f"and serves {p['owner']}" if p.get("owner") else ""),
                 f"Observed: {path} returns the resource's data to {p['viewer']}",
                 "Alternatives ruled out: not an echo of the request; not public "
                 "(anonymous control access refused or not served); the resource "
                 "exists (control refused with 401/403, or served to the owner)"]
        findings.append(FindingSpec(
            check_id="authz.exposure",
            detail=f"authz.exposure|{_tpl(p['url'])}|{_tpl(p['control_url'])}",
            title=f"{path} exposes data that {cpath} refuses to the same identity",
            severity="high" if public_too else "medium",
            confidence="high",
            description=(f"{reason}.\n\n" + "\n".join(f"- {c}" for c in claim))[:2000],
            url=p["url"], asset_url=p["control_url"], cwe="CWE-863",
            evidence=[Evidence(role="proof" if i == 0 else "baseline",
                               exchange_id=s.exchange_ids[0] if s.exchange_ids
                               else None,
                               excerpt=excerpt(f"{s.name}: HTTP {s.status}, marker "
                                               f"{'present' if s.contains else 'absent'}"),
                               note=s.name)
                      for i, s in enumerate(steps)],
            verify={k: p[k] for k in ("url", "viewer", "marker", "control_url",
                                      "owner") if p.get(k)},
            observation_key=obs.key, identity=str(p["viewer"]),
            finding_class="vulnerability", remediation=REMEDIATION))
    return ToolResult(summary=f"authz.exposure {path} vs {cpath} as {p['viewer']}: "
                              f"{decision} ({reason})"[:300],
                      counts={"requests": len(steps),
                              "findings": len(findings)},
                      observations=[obs], findings=findings,
                      examined=[p["url"], p["control_url"]])


async def verify(ctx: ToolContext) -> VerifyResult:
    """Independent re-run of every step; confirmed only on the same decision."""
    problem = _validate(ctx.params, ctx)
    if problem:
        return VerifyResult(False, "exposure re-check", f"cannot re-check: {problem}")
    decision, reason, steps = await measure(ctx)
    ids = [i for s in steps for i in s.exchange_ids]
    return VerifyResult(decision == CROSSED, "exposure re-check (all steps)",
                        f"{decision}: {reason}", ids[:20],
                        "; ".join(f"{s.identity}:{s.status}" for s in steps)[:300])
