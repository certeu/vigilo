"""Assessment coverage: is the work done, and if not, why?

Completion used to be "the explorer proposed nothing three times in a row", which is
not the same thing as "the assessment is done" — a field assessment ended *completed* with
an entire API untested and a live frontier. This module computes the honest answer
from the run's own state, and both the engine (stop decision) and the report read
it, so the two can never disagree.

The five outcomes (``OUTCOMES``):

``completed``           the surface that mattered was examined and nothing
                        actionable is left.
``partial``             useful work remains that this run did not get to (frontier,
                        untested endpoints, unfilled gaps, unmet authorisation).
``blocked``             the target could not be assessed because the assessment has
                        no working identity (expired session, IdP in front of it,
                        login required and none provided).
``needs_authorisation`` the next useful step is outside what the operator
                        authorised (network scope, active probes, auth testing).
``budget_exhausted``    requests, time or model budget ran out first.

Everything here is a pure function of counts and small value objects, so it is
tested without a database and used identically by the worker, the API and the
report.
"""
from __future__ import annotations

from dataclasses import dataclass, field

COMPLETED = "completed"
PARTIAL = "partial"
BLOCKED = "blocked"
NEEDS_AUTHORISATION = "needs_authorisation"
BUDGET_EXHAUSTED = "budget_exhausted"
OUTCOMES = (COMPLETED, PARTIAL, BLOCKED, NEEDS_AUTHORISATION, BUDGET_EXHAUSTED)

# Rank used by the API/report when several reasons apply: the most fundamental
# obstacle wins (a blocked run is not also "partial").
_RANK = {BLOCKED: 0, NEEDS_AUTHORISATION: 1, BUDGET_EXHAUSTED: 2, PARTIAL: 3,
         COMPLETED: 4}

AUTH_OK = "ok"
AUTH_MISSING = "missing"          # no credential/account supplied, target needs one
AUTH_EXPIRED = "expired"          # supplied identity is not accepted any more
AUTH_IDP = "identity_provider"    # every page redirects to an SSO provider
AUTH_UNKNOWN = "unknown"


@dataclass(frozen=True)
class AuthState:
    """The run's conclusion about its own identity (see ``tools/authstate``)."""

    state: str = AUTH_UNKNOWN
    provider: str | None = None       # e.g. "login.microsoftonline.com"
    detail: str = ""

    @property
    def blocked(self) -> bool:
        return self.state in (AUTH_MISSING, AUTH_EXPIRED, AUTH_IDP)

    def as_dict(self) -> dict:
        return {"state": self.state, "provider": self.provider, "detail": self.detail}


@dataclass(frozen=True)
class CoverageInput:
    """The facts a coverage verdict is derived from (all cheap counts)."""

    mode: str = "web"
    # endpoints (or addresses, for a network target) discovered and examined
    endpoints: int = 0
    endpoints_tested: int = 0
    # API-shaped endpoints discovered and never examined
    api_endpoints: int = 0
    api_untested: int = 0
    # crawl frontier still unfetched, and page budget left to fetch it
    frontier: int = 0
    page_budget_left: int = 0
    # surface × check-class gaps the ledger lists (never run, failed or skipped)
    gaps: int = 0
    # open hypotheses with no outcome, and findings left unverified
    open_hypotheses: int = 0
    unverified_findings: int = 0
    # identities and permission boundaries actually exercised
    identities: int = 0
    auth: AuthState = field(default_factory=AuthState)
    # why the run stopped, when the engine stopped it rather than the explorer
    budget_stop: str | None = None            # requests | time | model
    stopped_by: str | None = None             # cancelled | lost | error | ...
    # reasons raised elsewhere (blocked target, scope refusals that mattered)
    extra_reasons: tuple[str, ...] = ()
    # Definition of done of the loaded skills (skillbook.coverage_items):
    # (skill, criterion text, status, blocked category, note)
    skills: tuple[tuple[str, str, str, str | None, str], ...] = ()
    # skills the run could load but did not (methodology not applied)
    skills_available_not_loaded: int = 0
    # login accounts linked to the target that the run could not use because the
    # operator disabled authentication testing
    accounts_unused: int = 0
    # Security relationship model (secmodel_store): correlation signals nothing
    # settled, and what the model still does not know
    model_open_signals: tuple[str, ...] = ()
    model_unresolved: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageVerdict:
    outcome: str
    reasons: tuple[str, ...]          # human lines, most important first
    limitations: tuple[str, ...]      # what was NOT examined (report "Blind spots")
    # per-skill definition of done: {skill: {status: count}} (report, API)
    skills: dict = field(default_factory=dict)

    @property
    def completed(self) -> bool:
        return self.outcome == COMPLETED

    def as_dict(self) -> dict:
        d = {"outcome": self.outcome, "reasons": list(self.reasons),
             "limitations": list(self.limitations)}
        if self.skills:
            d["skills"] = self.skills
        return d


def assess(inp: CoverageInput) -> CoverageVerdict:
    """The honest verdict for one run, with the reasons that produced it."""
    limitations: list[str] = []
    candidates: list[tuple[str, str]] = []      # (outcome, reason)

    if inp.auth.blocked:
        where = f" (identity provider {inp.auth.provider})" if inp.auth.provider else ""
        what = {
            AUTH_EXPIRED: "the provided session is no longer accepted",
            AUTH_MISSING: "the target requires authentication and none was provided",
            AUTH_IDP: "every page redirects to an identity provider",
        }.get(inp.auth.state, "authentication could not be established")
        candidates.append((BLOCKED, f"Authentication blocks the assessment: {what}"
                                    f"{where}."))
        limitations.append(
            "Everything behind the login is unassessed: the run could only observe "
            "what the application answered before authenticating.")
    if inp.api_untested:
        candidates.append((PARTIAL,
                           f"{inp.api_untested} API endpoint(s) were discovered but "
                           "never examined."))
        limitations.append(f"{inp.api_untested} discovered API endpoint(s) were not "
                           "tested.")
    if inp.frontier and inp.page_budget_left > 0:
        candidates.append((PARTIAL, f"{inp.frontier} discovered URL(s) were never "
                                    "fetched."))
        limitations.append(f"{inp.frontier} URL(s) the crawler found were never "
                           f"fetched (page budget left: {inp.page_budget_left}).")
    if inp.gaps:
        candidates.append((PARTIAL, f"{inp.gaps} surface/check combination(s) have no "
                                    "outcome."))
        limitations.append(f"{inp.gaps} discovered surface(s) never got the check "
                           "class that applies to them.")
    if inp.unverified_findings:
        candidates.append((PARTIAL, f"{inp.unverified_findings} finding(s) await "
                                    "verification."))
        limitations.append(f"{inp.unverified_findings} candidate finding(s) were not "
                           "reproduced.")
    if inp.open_hypotheses:
        limitations.append(f"{inp.open_hypotheses} hypothesis(es) were left for the "
                           "analyst (not testable with the run's capabilities).")
    if inp.budget_stop:
        candidates.append((BUDGET_EXHAUSTED,
                           f"The {inp.budget_stop} budget was exhausted first."))
    if inp.stopped_by in ("cancelled", "lost", "error"):
        candidates.append((PARTIAL, f"The run was stopped ({inp.stopped_by}) before "
                                    "the assessment finished."))
    for reason in inp.extra_reasons:
        candidates.append((PARTIAL, reason))

    if inp.accounts_unused:
        candidates.append((NEEDS_AUTHORISATION,
                           f"{inp.accounts_unused} login account(s) are linked but "
                           "authentication testing is disabled in the scope, so "
                           "access control between users was not tested."))
        limitations.append("Access control between users was not tested "
                           "(authentication testing disabled).")
    # Skill definitions of done: what the methodology itself says is missing.
    by_skill: dict[str, dict] = {}
    for skill, text, status, category, note in inp.skills:
        b = by_skill.setdefault(skill, {"satisfied": 0, "unsatisfied": 0, "blocked": 0,
                                        "not_applicable": 0, "unmet": [],
                                        "blocked_items": []})
        b[status] = b.get(status, 0) + 1
        if status == "unsatisfied":
            b["unmet"].append(text)
        elif status == "blocked":
            b["blocked_items"].append((text, category, note))
    for skill, b in by_skill.items():
        if b["unmet"]:
            shown = "; ".join(b["unmet"][:3]) + (" …" if len(b["unmet"]) > 3 else "")
            candidates.append((PARTIAL, f"{skill}: {len(b['unmet'])} completion "
                                        f"criterion(s) not met — {shown}."))
            for text in b["unmet"]:
                limitations.append(f"{skill}: not established — {text}")
        for text, category, note in b["blocked_items"]:
            outcome = {"authentication": BLOCKED,
                       "authorisation": NEEDS_AUTHORISATION}.get(category or "", PARTIAL)
            candidates.append((outcome, f"{skill}: '{text}' is blocked"
                                        + (f" ({note})" if note else "") + "."))
            limitations.append(f"{skill}: blocked — {text}"
                               + (f" ({note})" if note else ""))
    if inp.skills_available_not_loaded and not inp.skills:
        limitations.append("No methodology skill was loaded: completeness was judged "
                           "without a skill's definition of done.")

    if inp.model_open_signals:
        candidates.append((PARTIAL, f"{len(inp.model_open_signals)} cross-interface "
                                    "signal(s) of the security model were never "
                                    "verified or explained."))
        for sig in inp.model_open_signals[:8]:
            limitations.append(f"Unverified signal: {sig}")
    for item in inp.model_unresolved[:8]:
        limitations.append(f"Security model: {item}")

    if inp.endpoints and not inp.endpoints_tested:
        candidates.append((PARTIAL, "No discovered endpoint was examined at all."))
        limitations.append("Nothing on the target was examined.")

    outcome = min((c[0] for c in candidates), key=lambda o: _RANK[o],
                  default=COMPLETED)
    reasons = tuple(r for o, r in candidates if _RANK[o] <= _RANK[outcome]) \
        or ("The surface that was discovered was examined and no actionable gap "
            "remains.",)
    if outcome == COMPLETED and not limitations and inp.identities == 0:
        limitations.append("Only the anonymous identity was exercised.")
    return CoverageVerdict(outcome=outcome, reasons=reasons,
                          limitations=tuple(dict.fromkeys(limitations)),
                          skills={k: {s: v[s] for s in ("satisfied", "unsatisfied",
                                                        "blocked", "not_applicable")}
                                  for k, v in by_skill.items()})


def headline(verdict: CoverageVerdict) -> str:
    """One sentence for the UI and the report summary."""
    return {
        COMPLETED: "Assessment completed",
        PARTIAL: "Assessment partially completed",
        BLOCKED: "Assessment blocked",
        NEEDS_AUTHORISATION: "Assessment needs additional authorisation",
        BUDGET_EXHAUSTED: "Assessment stopped at its budget",
    }.get(verdict.outcome, "Assessment finished") + (
        f": {verdict.reasons[0]}" if verdict.reasons else "")
