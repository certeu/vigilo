"""Security relationship model: typed entities, expected vs observed access, provenance.

This is a defensive application-security *modelling* component. It records what the
assessment has learned about the application's security model and keeps three
things strictly apart:

* **expected access** — an access relationship established by documentation, the
  operator's configuration or other reliable evidence (``Expectation``);
* **observed access** — what the run actually recorded, one row per recorded
  request, each pointing at its exchange (``Observation``);
* **unknown** — no expectation established: an observation alone is never a
  conclusion. A 200 is not a vulnerability; a difference is not broken access
  control.

Correlation (:func:`correlate`) only produces *signals* — "the same resource
instance was refused to identity X through one interface and served to X through
another", "an expectation is contradicted by an observation" — with their
evidence references. Signals feed hypotheses and verification; they never become
findings by themselves.

This module is pure (no I/O). Persistence lives in :mod:`secmodel_store`.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

# ------------------------------------------------------------------ vocabulary

ENTITY_KINDS = ("identity", "role", "resource_type", "resource", "workflow",
                "workflow_state", "trust_boundary")
# relation -> allowed (source kind, destination kind)
RELATIONS: dict[str, frozenset[tuple[str, str]]] = {
    "has_role": frozenset({("identity", "role")}),
    "member_of": frozenset({("identity", "resource")}),
    "owns": frozenset({("identity", "resource")}),
    "instance_of": frozenset({("resource", "resource_type")}),
    "belongs_to": frozenset({("resource", "resource"),
                             ("resource_type", "resource_type")}),
    "references": frozenset({("resource", "resource"),
                             ("resource_type", "resource_type")}),
    "has_state": frozenset({("workflow", "workflow_state"),
                            ("resource", "workflow_state")}),
    "transitions_to": frozenset({("workflow_state", "workflow_state")}),
    "acts_on": frozenset({("workflow", "resource_type")}),
    "protects": frozenset({("trust_boundary", "resource_type"),
                           ("trust_boundary", "resource")}),
}
OPERATIONS = ("read", "list", "create", "update", "delete", "act")
EXPECTED = ("allow", "deny")
BASES = ("documented", "configured", "observed_ui", "stated")   # where it came from
OUTCOMES = ("allow", "deny", "missing", "error")
METHOD_OPERATION = {"GET": "read", "HEAD": "read", "OPTIONS": "read",
                    "POST": "create", "PUT": "update", "PATCH": "update",
                    "DELETE": "delete"}
MAX_DECLARED = 16                 # per list, per agent reply

_ID_SHAPES = (
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    re.compile(r"^\d{1,19}$"),
    re.compile(r"^[0-9a-f]{12,64}$", re.I),
    re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{16,}$"),
    re.compile(r"^[A-Za-z]{1,6}[_-](?=[A-Za-z0-9]*\d)[A-Za-z0-9]{3,40}$"),
)
_COUNTER = re.compile(r"^\d{1,6}$")
_SKIP_SEGMENTS = {"api", "rest", "graphql", "public", "internal"}
_VERSION = re.compile(r"^v\d+(\.\d+)?$", re.I)


class ModelError(ValueError):
    """A declaration that cannot be represented (unknown kind, relation, value)."""


def norm(value: Any, n: int = 80) -> str:
    """Canonical name: lower-case, single spaces, bounded. '' when empty."""
    return re.sub(r"\s+", " ", str(value if value is not None else "")).strip().lower()[:n]


def id_shaped(segment: str) -> bool:
    return any(rx.match(segment) for rx in _ID_SHAPES)


# ------------------------------------------------------------------ typed records


@dataclass(frozen=True)
class EntityRef:
    kind: str
    name: str

    def __post_init__(self) -> None:
        if self.kind not in ENTITY_KINDS:
            raise ModelError(f"unknown entity kind {self.kind!r}")
        if not self.name:
            raise ModelError(f"{self.kind}: empty name")

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass(frozen=True)
class Relation:
    src: EntityRef
    rel: str
    dst: EntityRef
    basis: str = "stated"
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        allowed = RELATIONS.get(self.rel)
        if allowed is None:
            raise ModelError(f"unknown relation {self.rel!r}")
        if (self.src.kind, self.dst.kind) not in allowed:
            raise ModelError(f"{self.rel}: {self.src.kind} -> {self.dst.kind} "
                             "is not a valid relation")
        if self.basis not in BASES:
            raise ModelError(f"unknown basis {self.basis!r}")


@dataclass(frozen=True)
class Expectation:
    """Who SHOULD be able to do what to which resource, and why we believe it."""

    subject: EntityRef               # an identity or a role
    operation: str
    resource: EntityRef              # a resource type or an instance
    expected: str                    # allow | deny
    basis: str                       # documented | configured | observed_ui | stated
    evidence: tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        if self.subject.kind not in ("identity", "role"):
            raise ModelError("an expectation's subject is an identity or a role")
        if self.resource.kind not in ("resource", "resource_type"):
            raise ModelError("an expectation's object is a resource or resource type")
        if self.operation not in OPERATIONS:
            raise ModelError(f"unknown operation {self.operation!r}")
        if self.expected not in EXPECTED:
            raise ModelError(f"expected must be one of {EXPECTED}")
        if self.basis not in BASES:
            raise ModelError(f"unknown basis {self.basis!r}")


@dataclass(frozen=True)
class Interface:
    """An API route template and the resource it addresses."""

    template: str                    # /api/documents/{id}/versions
    resource_type: str               # documents
    kind: str                        # detail | list | sub
    sub: str = ""                    # the sub-resource/action name for kind=sub
    parents: tuple[str, ...] = ()    # enclosing resource types, outermost first
    param_index: int | None = None   # path segment holding the instance id


@dataclass(frozen=True)
class Observation:
    """One recorded access, with full provenance (the exchange is the evidence)."""

    identity: str
    interface: str                   # template
    resource_type: str
    instance: str | None             # the id in the path, when the interface has one
    operation: str
    outcome: str                     # allow | deny | missing | error
    status: int | None
    exchange_id: int
    seq: int                         # exchange order (monotonic id)
    source: str                      # the tool that made the request
    sub: str = ""                    # sub-resource/action of a sub-interface

    def addresses(self, rtype: str) -> bool:
        """Does this access concern resources of type ``rtype``?"""
        return rtype in (self.resource_type, self.sub)

    def ref(self) -> str:
        return f"exchange:{self.exchange_id}"


@dataclass(frozen=True)
class Signal:
    """A correlation worth investigating. Never a finding by itself."""

    kind: str                        # inconsistent_boundary | contradicts_expectation
    identity: str
    resource_type: str
    instance: str | None
    summary: str
    evidence: tuple[str, ...]
    interfaces: tuple[str, ...] = ()
    status: str = "unverified"

    def as_dict(self) -> dict[str, Any]:
        return {k: (list(v) if isinstance(v, tuple) else v)
                for k, v in asdict(self).items()}


# ------------------------------------------------------------------ interfaces


def outcome_of(status: int | None, *, error: bool = False) -> str:
    if error or status is None:
        return "error"
    if 200 <= status < 300 or status == 304:
        return "allow"
    if status in (401, 403):
        return "deny"
    if status in (404, 410):
        return "missing"
    return "error"


_ID_KEY = re.compile(r'"(?:id|uuid|slug|key|[A-Za-z]+_id|[A-Za-z]+Id)"\s*:\s*"([^"\\]{2,64})"')


def ids_in_body(text: str | None, cap: int = 400) -> set[str]:
    """Identifier values an application RETURNED (JSON ``id``/``*_id``/``slug``
    fields): evidence that a path segment with that value names an instance."""
    out: set[str] = set()
    for m in _ID_KEY.finditer(text or ""):
        v = m.group(1)
        if "/" not in v and " " not in v:
            out.add(v)
            if len(out) >= cap:
                break
    return out


def _param(segment: str, known: set[str] | frozenset[str]) -> bool:
    return segment.startswith("{") or id_shaped(segment) or segment in known


def interface_of(path: str, known_ids: set[str] | frozenset[str] = frozenset()
                 ) -> Interface | None:
    """The interface a concrete or template path addresses, by its shape alone.

    ``/api/v2/workspaces/ws1/boards/b7k2/cards`` → list of ``cards`` inside
    ``workspaces``/``boards``; ``/api/documents/d-1/versions/2`` → detail of
    ``versions`` inside ``documents``; ``/api/boards/b7k2/export`` → sub-interface
    ``export`` of ``boards``. Paths with no collection segment give None."""
    segs = [s for s in (urlsplit(path).path or path).split("/") if s]
    shape: list[str] = []
    collections: list[tuple[int, str]] = []    # (index, name) of collection segments
    last_param: int | None = None
    for i, s in enumerate(segs):
        if _param(s, known_ids) and i > 0:
            shape.append("{id}")
            last_param = i
        else:
            shape.append(s)
            if s.lower() not in _SKIP_SEGMENTS and not _VERSION.match(s):
                collections.append((i, s.lower()))
    if not collections:
        return None
    template = "/" + "/".join(shape)
    # resources = collections immediately followed by an id
    owned = [name for i, name in collections if i + 1 < len(segs)
             and shape[i + 1] == "{id}"]
    if last_param is not None and last_param == len(segs) - 1:
        rtype = segs[last_param - 1].lower() if last_param > 0 else "resource"
        return Interface(template, rtype, "detail",
                         parents=tuple(owned[:-1]), param_index=last_param)
    tail = collections[-1][1]
    if last_param is None:
        return Interface(template, tail, "list", parents=())
    # trailing segment(s) after the last id: a sub-collection or an action
    rtype = segs[last_param - 1].lower()
    return Interface(template, rtype, "sub", sub=tail,
                     parents=tuple(owned[:-1]), param_index=last_param)


def instance_of(path: str, iface: Interface) -> str | None:
    """The instance an interface addresses. A small counter-like id (``2``) is only
    unique within its parent, so for a nested resource the parents' ids become
    part of its identity (version 2 of document A is not version 2 of B:
    ``d-a71f30/2``). Globally unique ids (UUIDs, prefixed ids, slugs) stand alone,
    so the same board reached as ``/workspaces/w/boards/b`` and ``/boards/b/export``
    is one instance."""
    if iface.param_index is None:
        return None
    segs = [s for s in (urlsplit(path).path or path).split("/") if s]
    if iface.param_index >= len(segs):
        return None
    tpl = [s for s in iface.template.split("/") if s]
    ids = [segs[i] for i, t in enumerate(tpl[:iface.param_index + 1])
           if t == "{id}" and i < len(segs)]
    if iface.kind == "detail" and iface.parents and len(ids) > 1 \
            and _COUNTER.match(segs[iface.param_index]):
        return "/".join(ids[-(len(iface.parents) + 1):])
    return segs[iface.param_index]



def _api_operation(body: str) -> tuple[str, str] | None:
    """Return a GraphQL/JSON-RPC operation name and security operation."""
    import json
    import re
    if not body or len(body) > 100_000:
        return None
    try:
        doc = json.loads(body)
    except (TypeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    if isinstance(doc.get("method"), str):
        name = doc["method"][:80]
        return name, ("read" if re.match(r"(?i)^(get|list|read|search|find)", name) else "act")
    query = doc.get("query")
    if not isinstance(query, str):
        return None
    name = doc.get("operationName")
    mutation = bool(re.search(r"(?i)\bmutation\b", query))
    if not isinstance(name, str) or not name:
        match = re.search(r"(?is)\b(?:query|mutation)\s+([A-Za-z_]\w*)|\{\s*([A-Za-z_]\w*)", query)
        name = (match.group(1) or match.group(2)) if match else None
    return (name[:80], "act" if mutation else "read") if name else None

def observe(rows: Iterable[dict[str, Any]], identities: set[str],
            known_ids: set[str] | frozenset[str] = frozenset()) -> list[Observation]:
    """Observations from recorded exchanges (``id, url, method, status_code, error,
    identity, tool``). Only attributed requests from comparable identities count;
    blocked/refused requests are not access observations. ``known_ids``: values
    the application returned as identifiers (:func:`ids_in_body`)."""
    out: list[Observation] = []
    for r in rows:
        ident = r.get("identity")
        if ident not in identities or r.get("blocked"):
            continue
        status = r.get("status_code")
        if status is not None and 200 <= status < 300 and \
                "html" in str(r.get("content_type") or "").lower():
            # a rendered page is a shell, not the resource: pages answer 200 to
            # anyone and load the data through the API (the API answer counts)
            continue
        url = str(r.get("url") or "")
        operation_name = _api_operation(str(r.get("request_body") or ""))
        iface = interface_of(url, known_ids)
        if iface is None and operation_name:
            from urllib.parse import urlsplit
            iface = Interface(urlsplit(url).path or "/", "operations", "sub",
                              sub=operation_name[0])
        if iface is None:
            continue
        method = str(r.get("method") or "GET").upper()
        interface = iface.template + (f"#{operation_name[0]}" if operation_name else "")
        operation = operation_name[1] if operation_name else METHOD_OPERATION.get(method, "act")
        out.append(Observation(
            identity=ident, interface=interface, resource_type=iface.resource_type,
            instance=instance_of(str(r["url"]), iface),
            operation=operation,
            outcome=outcome_of(r.get("status_code"), error=bool(r.get("error"))),
            status=r.get("status_code"), exchange_id=int(r["id"]),
            seq=int(r["id"]), source=str(r.get("tool") or ""), sub=iface.sub))
    return out


# ------------------------------------------------------------------ correlation


def access_matrix(obs: list[Observation]) -> dict[str, dict[str, dict[str, int]]]:
    """interface -> identity -> outcome -> count (reads only)."""
    m: dict[str, dict[str, dict[str, int]]] = {}
    for o in obs:
        if o.operation not in ("read", "list"):
            continue
        cell = m.setdefault(o.interface, {}).setdefault(o.identity, {})
        cell[o.outcome] = cell.get(o.outcome, 0) + 1
    return m


def correlate(obs: list[Observation], expectations: list[Expectation] = (),
              roles: dict[str, str] | None = None) -> list[Signal]:
    """Signals from observations (and expectations, when established).

    * ``inconsistent_boundary``: the SAME resource instance (by id) was refused to
      an identity (deny or missing) through one interface and served (allow)
      through another. The instance id must appear in both paths, so a list page
      vs a detail page of different objects never qualifies.
    * ``contradicts_expectation``: an established expectation (deny) for an
      identity/role on a resource type is contradicted by an observed allow.
      Unknown expectations produce nothing."""
    signals: list[Signal] = []
    by_instance: dict[tuple[str, str, str], dict[str, list[Observation]]] = {}
    for o in obs:
        if o.instance is None or o.operation not in ("read", "list"):
            continue
        key = (o.identity, o.resource_type, o.instance)
        by_instance.setdefault(key, {}).setdefault(o.interface, []).append(o)
    for (ident, rtype, inst), per_iface in sorted(by_instance.items()):
        refused = {i: os_ for i, os_ in per_iface.items()
                   if any(o.outcome in ("deny", "missing") for o in os_)
                   and not any(o.outcome == "allow" for o in os_)}
        served = {i: os_ for i, os_ in per_iface.items()
                  if any(o.outcome == "allow" for o in os_)}
        if refused and served:
            ev = [o.ref() for os_ in list(refused.values()) + list(served.values())
                  for o in os_[:1]]
            signals.append(Signal(
                "inconsistent_boundary", ident, rtype, inst,
                f"{rtype} {inst}: refused to {ident} via {', '.join(sorted(refused))} "
                f"but served via {', '.join(sorted(served))}",
                tuple(ev[:6]), tuple(sorted(refused) + sorted(served))))
    roles = roles or {}
    for e in expectations:
        if e.expected != "deny" or e.operation not in ("read", "list"):
            continue
        subjects = {e.subject.name} if e.subject.kind == "identity" else \
            {i for i, r in roles.items() if r == e.subject.name}
        rtype = e.resource.name if e.resource.kind == "resource_type" else None
        hits = [o for o in obs if o.identity in subjects and o.outcome == "allow"
                and o.operation in ("read", "list")
                and (o.addresses(rtype) if rtype else o.instance == e.resource.name)]
        if hits:
            signals.append(Signal(
                "contradicts_expectation", hits[0].identity, hits[0].resource_type,
                hits[0].instance,
                f"expected deny ({e.basis}) for {e.subject.key} on {e.resource.key}, "
                f"observed allow via {hits[0].interface}",
                tuple(o.ref() for o in hits[:4]), (hits[0].interface,)))
    return signals


# ------------------------------------------------------------------ agent declarations


@dataclass
class Declarations:
    """What the agent declared in one reply, validated. Invalid items are dropped
    with a note (the reply is never rejected for them)."""

    entities: list[tuple[EntityRef, dict[str, Any]]] = field(default_factory=list)
    relations: list[Relation] = field(default_factory=list)
    expectations: list[Expectation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def empty(self) -> bool:
        return not (self.entities or self.relations or self.expectations)


def _refs(v: Any) -> tuple[str, ...]:
    if isinstance(v, str):
        v = [v]
    return tuple(str(x)[:200] for x in (v or []) if isinstance(x, (str, int)))[:6]


def _ref(v: Any) -> EntityRef:
    if not isinstance(v, dict):
        raise ModelError("entity reference must be {kind, name}")
    return EntityRef(str(v.get("kind") or ""), norm(v.get("name")))


def clean(raw: Any) -> Declarations:
    """Validate the ``model`` field of an agent reply.

    Shape: ``{"entities": [{kind, name, attributes?}], "relations": [{src, rel,
    dst, basis?, evidence?}], "expectations": [{subject, operation, resource,
    expected, basis, evidence?, note?}]}`` where src/dst/subject/resource are
    ``{kind, name}``."""
    d = Declarations()
    if not isinstance(raw, dict):
        return d
    for i, x in enumerate((raw.get("entities") or [])[:MAX_DECLARED]):
        try:
            ref = _ref(x)
            attrs = x.get("attributes") if isinstance(x.get("attributes"), dict) else {}
            d.entities.append((ref, {str(k)[:40]: v for k, v in list(attrs.items())[:12]
                                     if isinstance(v, (str, int, float, bool, list))}))
        except ModelError as exc:
            d.notes.append(f"entity #{i + 1} dropped: {exc}")
    for i, x in enumerate((raw.get("relations") or [])[:MAX_DECLARED]):
        try:
            d.relations.append(Relation(
                _ref(x.get("src")), str(x.get("rel") or ""), _ref(x.get("dst")),
                str(x.get("basis") or "stated"), _refs(x.get("evidence"))))
        except (ModelError, AttributeError) as exc:
            d.notes.append(f"relation #{i + 1} dropped: {exc}")
    for i, x in enumerate((raw.get("expectations") or [])[:MAX_DECLARED]):
        try:
            d.expectations.append(Expectation(
                _ref(x.get("subject")), str(x.get("operation") or "read"),
                _ref(x.get("resource")), str(x.get("expected") or ""),
                str(x.get("basis") or "stated"), _refs(x.get("evidence")),
                str(x.get("note") or "")[:300]))
        except (ModelError, AttributeError) as exc:
            d.notes.append(f"expectation #{i + 1} dropped: {exc}")
    return d
