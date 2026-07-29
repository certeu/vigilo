"""Single read path over the SurrealDB graph.

All scheduler, context-builder, and report-layer reads go through this
module. No parallel projection layer is allowed — if a consumer needs a
shape this module doesn't expose, ADD A VIEW HERE, don't query raw.

All queries are parameterized SurrealQL (``$param``); never interpolate
user-supplied values into the query string.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from src.greybox.graph.ids import normalize_record_id
from src.greybox.graph.schema import Shape


SignalStrength = Literal["low", "medium", "high"]


class _GraphReader(Protocol):
    """Minimum surface a ``graph`` argument must expose.

    Implemented by :class:`src.greybox.graph.client.GraphClient` and by
    the test fixture. Keeping this as a Protocol avoids importing the
    concrete client (and its network dependencies) into purely
    read-side code.
    """

    async def raw_query(
        self, query: str, params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        ...


@dataclass(frozen=True)
class ParameterView:
    id: str
    name: str
    location: str
    shape: Shape
    endpoint_id: str


@dataclass(frozen=True)
class LeadView:
    id: str
    signal: str
    signal_strength: SignalStrength
    hypothesis: str
    status: str
    investigation_attempts: int
    max_attempts: int


@dataclass(frozen=True)
class CoverageView:
    tested: int
    total: int


@dataclass(frozen=True)
class ChainCandidateView:
    grants_finding_id: str
    requires_finding_id: str
    shared_capabilities: tuple[str, ...] = ()
    # Ordered list of finding IDs participating in the chain. Scheduler's
    # rule_attempt_chain consumes this directly; until chain_candidates()
    # is implemented for real (Task 3.x), callers construct it themselves.
    finding_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AccessMatrix:
    can_access: dict[str, list[str]] = field(default_factory=dict)
    denied_access: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class EndpointObservations:
    status_codes_seen: list[int] = field(default_factory=list)
    response_headers: dict[str, Any] = field(default_factory=dict)
    content_type: str | None = None


@dataclass(frozen=True)
class TestAttemptSummary:
    """Minimal projection of a ``test_attempt`` for cross-identity context."""

    # Tell pytest not to collect this as a test class — the ``Test`` prefix
    # is a pytest collection heuristic, not a type convention we want to
    # change here.
    __test__ = False

    id: str
    vuln_type: str
    verdict: str
    agent: str
    identity_id: str = ""


@dataclass(frozen=True)
class FindingSummary:
    """Minimal projection of a ``finding`` exploiting an endpoint."""

    id: str
    vuln_type: str
    severity: str
    title: str


@dataclass(frozen=True)
class AccessObservation:
    """``can_access`` / ``denied_access`` observation for one identity."""

    identity_id: str
    kind: Literal["allowed", "denied"]


@dataclass(frozen=True)
class EndpointContextView:
    """Typed bundle returned by :func:`endpoint_full_context`.

    ``siblings`` — parameters attached to the endpoint via ``has_param``.
    ``test_attempts`` — every ``test_attempt`` that targeted any sibling,
    across all identities (the point of the view is cross-identity
    visibility — a specialist running as ``identity:user`` must learn
    that ``identity:admin`` already probed the same endpoint).
    ``findings`` — findings with an ``exploits`` edge to the endpoint.
    ``access_observations`` — ``can_access`` / ``denied_access`` edges
    restricted to the provided ``identity_ids``.
    """

    endpoint_id: str
    siblings: list[ParameterView] = field(default_factory=list)
    test_attempts: list[TestAttemptSummary] = field(default_factory=list)
    findings: list[FindingSummary] = field(default_factory=list)
    access_observations: list[AccessObservation] = field(default_factory=list)


@dataclass(frozen=True)
class VerdictCounts:
    conclusive_vulnerable: int = 0
    conclusive_clean: int = 0
    inconclusive: int = 0
    failed: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "conclusive_vulnerable": self.conclusive_vulnerable,
            "conclusive_clean": self.conclusive_clean,
            "inconclusive": self.inconclusive,
            "failed": self.failed,
        }


def _stringify_id(value: Any) -> str:
    """Coerce SurrealDB RecordID objects (or plain strings) into ``table:id`` strings."""
    return normalize_record_id(value)


async def untested_parameters(
    graph: _GraphReader,
    vuln_type: str,
    shapes: list[Shape],
    max_inconclusive_retries: int = 2,
    max_failed_retries: int = 3,
) -> list[ParameterView]:
    """Parameters with a matching shape and no prior conclusive attempt.

    A parameter is returned iff all three conditions hold for ``vuln_type``:

    - no ``test_attempt`` with ``verdict`` in
      ``{conclusive_vulnerable, conclusive_clean}`` exists, and
    - fewer than ``max_inconclusive_retries`` inconclusive attempts exist,
      and
    - fewer than ``max_failed_retries`` failed attempts exist.

    Parameters without a parent endpoint are still returned (with an
    empty ``endpoint_id``) so callers never silently drop them.
    """
    query = """
        SELECT
            id, name, location, shape,
            <-has_param<-endpoint AS endpoint_ids
        FROM parameter
        WHERE shape IN $shapes
          AND array::len(
              <-tested_against<-test_attempt[
                  WHERE vuln_type = $vuln
                    AND verdict IN ['conclusive_vulnerable', 'conclusive_clean']
              ]
          ) = 0
          AND array::len(
              <-tested_against<-test_attempt[
                  WHERE vuln_type = $vuln AND verdict = 'inconclusive'
              ]
          ) < $max_inc
          AND array::len(
              <-tested_against<-test_attempt[
                  WHERE vuln_type = $vuln AND verdict = 'failed'
              ]
          ) < $max_fail
    """
    rows = await graph.raw_query(
        query,
        {
            "shapes": shapes,
            "vuln": vuln_type,
            "max_inc": max_inconclusive_retries,
            "max_fail": max_failed_retries,
        },
    )
    views: list[ParameterView] = []
    for row in rows:
        endpoint_ids = row.get("endpoint_ids") or []
        endpoint_id = _stringify_id(endpoint_ids[0]) if endpoint_ids else ""
        views.append(
            ParameterView(
                id=_stringify_id(row.get("id")),
                name=row.get("name", ""),
                location=row.get("location", ""),
                shape=row.get("shape", "free_text"),
                endpoint_id=endpoint_id,
            )
        )
    return views


async def open_leads(
    graph: _GraphReader,
    min_strength: SignalStrength = "medium",
) -> list[LeadView]:
    """Open leads at or above the given signal strength, strongest first."""
    allowed = {
        "low": ["low", "medium", "high"],
        "medium": ["medium", "high"],
        "high": ["high"],
    }[min_strength]
    query = """
        SELECT
            id, signal, signal_strength, hypothesis, status,
            investigation_attempts, max_attempts
        FROM lead
        WHERE status = 'open'
          AND signal_strength IN $allowed
    """
    rows = await graph.raw_query(query, {"allowed": allowed})
    strength_rank = {"high": 2, "medium": 1, "low": 0}
    rows.sort(
        key=lambda r: strength_rank.get(r.get("signal_strength", "low"), 0),
        reverse=True,
    )
    return [
        LeadView(
            id=_stringify_id(row.get("id")),
            signal=row.get("signal", ""),
            signal_strength=row.get("signal_strength", "medium"),
            hypothesis=row.get("hypothesis", ""),
            status=row.get("status", "open"),
            investigation_attempts=int(row.get("investigation_attempts", 0)),
            max_attempts=int(row.get("max_attempts", 3)),
        )
        for row in rows
    ]


async def coverage_by_vuln_type(
    graph: _GraphReader,
) -> dict[str, CoverageView]:
    """For each observed ``vuln_type``, (tested_params, total_params).

    ``tested`` counts distinct parameters linked via ``tested_against``
    from test_attempts of that vuln_type. ``total`` is the total number
    of parameters in the graph — until the vuln-type↔shape affinity
    table lands (Task 3.2), every parameter is a candidate denominator.
    """
    total_rows = await graph.raw_query(
        "SELECT count() AS c FROM parameter GROUP ALL"
    )
    total = int(total_rows[0]["c"]) if total_rows else 0

    # GROUP BY vuln_type + count(DISTINCT ...) is awkward in SurrealDB;
    # fetching attempts and aggregating in Python keeps the read layer
    # portable across SurrealDB versions.
    attempts = await graph.raw_query(
        """
        SELECT vuln_type, ->tested_against->parameter AS params
        FROM test_attempt
        """
    )
    tested_by_vuln: dict[str, set[str]] = {}
    for row in attempts:
        vt = row.get("vuln_type")
        if not vt:
            continue
        params = row.get("params") or []
        tested_by_vuln.setdefault(vt, set()).update(_stringify_id(p) for p in params)

    return {
        vt: CoverageView(tested=len(param_ids), total=total)
        for vt, param_ids in tested_by_vuln.items()
    }


async def chain_candidates(
    graph: _GraphReader,
) -> list[ChainCandidateView]:
    """Findings whose ``grants[]`` overlap another finding's ``requires[]``.

    Stub — the rule-based chain detector (``planner/chain_detector.py``)
    still owns this logic for now. Task 3.x will migrate it here; until
    then callers get an empty list.
    """
    return []


async def access_matrix(
    graph: _GraphReader,
    identity_ids: list[str],
) -> AccessMatrix:
    """Endpoints × identities with can_access / denied_access observations.

    Returns per-identity allow/deny observations for the provided identities.
    """
    if not identity_ids:
        return AccessMatrix()
    identity_set = set(identity_ids)
    can_access_map: dict[str, list[str]] = {}
    denied_access_map: dict[str, list[str]] = {}
    allow_rows, deny_rows = await graph.raw_query(
        "SELECT in, out FROM can_access"
    ), await graph.raw_query("SELECT in, out FROM denied_access")
    for row in allow_rows:
        identity_id = _stringify_id(row.get("in"))
        if identity_id not in identity_set:
            continue
        can_access_map.setdefault(identity_id, []).append(_stringify_id(row.get("out")))
    for row in deny_rows:
        identity_id = _stringify_id(row.get("in"))
        if identity_id not in identity_set:
            continue
        denied_access_map.setdefault(identity_id, []).append(_stringify_id(row.get("out")))
    return AccessMatrix(
        can_access=can_access_map,
        denied_access=denied_access_map,
    )


async def attempt_counts_by_verdict(
    graph: _GraphReader,
) -> VerdictCounts:
    """Per-verdict counts across all ``test_attempt`` rows.

    Used by the scheduler to distinguish conclusive attempts (which count
    as progress for the diminishing-returns halt) from inconclusive/failed
    attempts (which do not).
    """
    rows = await graph.raw_query(
        "SELECT verdict, count() AS c FROM test_attempt GROUP BY verdict"
    )
    by_verdict: dict[str, int] = {}
    for row in rows:
        verdict = row.get("verdict")
        if not verdict:
            continue
        by_verdict[str(verdict)] = int(row.get("c", 0))
    return VerdictCounts(
        conclusive_vulnerable=by_verdict.get("conclusive_vulnerable", 0),
        conclusive_clean=by_verdict.get("conclusive_clean", 0),
        inconclusive=by_verdict.get("inconclusive", 0),
        failed=by_verdict.get("failed", 0),
    )


async def endpoint_full_context(
    graph: _GraphReader,
    endpoint_id: str,
    identity_ids: list[str],
) -> EndpointContextView:
    """Cross-identity context bundle for one endpoint.

    Returns siblings (all parameters on the endpoint), test_attempts
    against any sibling across all identities, findings exploiting the
    endpoint, and per-identity access observations for ``identity_ids``.

    The view is the single read path for specialists — see design §3.7
    G1. If ``endpoint_id`` does not resolve, an empty
    :class:`EndpointContextView` is returned (never raises).
    """
    if not endpoint_id:
        return EndpointContextView(endpoint_id=endpoint_id)

    # -- Sibling parameters (has_param from the endpoint) --
    sibling_rows = await graph.raw_query(
        """
        SELECT id, name, location, shape
        FROM parameter
        WHERE <-has_param<-endpoint CONTAINS type::thing($id)
        """,
        {"id": endpoint_id},
    )
    siblings: list[ParameterView] = [
        ParameterView(
            id=_stringify_id(row.get("id")),
            name=row.get("name", ""),
            location=row.get("location", ""),
            shape=row.get("shape", "free_text"),
            endpoint_id=endpoint_id,
        )
        for row in sibling_rows
    ]

    # -- test_attempts against any sibling (all identities) --
    attempts: list[TestAttemptSummary] = []
    if siblings:
        attempt_rows = await graph.raw_query(
            """
            SELECT id, vuln_type, verdict, agent
            FROM test_attempt
            WHERE ->tested_against->parameter
                  <-has_param<-endpoint CONTAINS type::thing($id)
            """,
            {"id": endpoint_id},
        )
        attempts = [
            TestAttemptSummary(
                id=_stringify_id(row.get("id")),
                vuln_type=row.get("vuln_type", ""),
                verdict=row.get("verdict", ""),
                agent=row.get("agent", ""),
            )
            for row in attempt_rows
        ]

    # -- findings with exploits edge to the endpoint --
    # ``->exploits`` returns the edge record IDs, not the target nodes;
    # we have to traverse one more hop (``->exploits->endpoint``) to land
    # on the endpoint itself and then CONTAINS on the canonical record.
    finding_rows = await graph.raw_query(
        """
        SELECT id, vuln_type, severity, title
        FROM finding
        WHERE ->exploits->endpoint CONTAINS type::thing($id)
        """,
        {"id": endpoint_id},
    )
    findings = [
        FindingSummary(
            id=_stringify_id(row.get("id")),
            vuln_type=row.get("vuln_type", ""),
            severity=row.get("severity", ""),
            title=row.get("title", ""),
        )
        for row in finding_rows
    ]

    # -- Access observations for the requested identities --
    # The ``in`` field on ``can_access`` / ``denied_access`` stores a
    # ``RecordID`` object. Filtering ``in IN $identities`` against a
    # list of stringified IDs doesn't match, so we fetch all edges
    # targeting the endpoint and filter Python-side against the
    # provided identity set. This keeps the query parameterized and
    # the identity scope easy to reason about.
    access_observations: list[AccessObservation] = []
    if identity_ids:
        identity_set = set(identity_ids)
        allow_rows = await graph.raw_query(
            "SELECT in AS identity_id FROM can_access WHERE out = type::thing($id)",
            {"id": endpoint_id},
        )
        deny_rows = await graph.raw_query(
            "SELECT in AS identity_id FROM denied_access WHERE out = type::thing($id)",
            {"id": endpoint_id},
        )
        for row in allow_rows:
            ident = _stringify_id(row.get("identity_id"))
            if ident in identity_set:
                access_observations.append(
                    AccessObservation(identity_id=ident, kind="allowed")
                )
        for row in deny_rows:
            ident = _stringify_id(row.get("identity_id"))
            if ident in identity_set:
                access_observations.append(
                    AccessObservation(identity_id=ident, kind="denied")
                )

    return EndpointContextView(
        endpoint_id=endpoint_id,
        siblings=siblings,
        test_attempts=attempts,
        findings=findings,
        access_observations=access_observations,
    )


async def endpoint_response_observations(
    graph: _GraphReader,
    endpoint_id: str,
) -> EndpointObservations:
    """Per-endpoint response metadata used by the report layer.

    Stub — thin read of the ``endpoint`` row. Implemented as a real
    query so downstream callers can rely on the shape today; returns a
    default ``EndpointObservations`` if the endpoint does not exist.
    """
    if not endpoint_id:
        return EndpointObservations()
    rows = await graph.raw_query(
        """
        SELECT status_codes_seen, response_headers, content_type
        FROM type::thing($id)
        """,
        {"id": endpoint_id},
    )
    if not rows:
        return EndpointObservations()
    row = rows[0]
    return EndpointObservations(
        status_codes_seen=list(row.get("status_codes_seen") or []),
        response_headers=dict(row.get("response_headers") or {}),
        content_type=row.get("content_type"),
    )
