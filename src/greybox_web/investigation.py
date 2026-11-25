"""Operation-aware investigation records built on Vigilo's existing graph model.

Operations are a durable projection of endpoint/interface assets. Investigations use
``lead`` graph nodes as their persistence envelope; this module owns the structured
payload and lifecycle interpretation without creating a second database.
"""
from __future__ import annotations

import hashlib
import re
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal
from urllib.parse import urlsplit

InvestigationStatus = Literal[
    "discovered", "hypothesis_established", "ready", "in_progress",
    "awaiting_evidence", "verification_pending", "confirmed", "rejected",
    "inconclusive", "blocked", "not_attempted", "verified", "budget_exhausted",
]
_PROTOCOLS = frozenset({"rest", "graphql", "jsonrpc", "browser", "file", "workflow"})
_TERMINAL = frozenset({"inconclusive", "verified", "confirmed", "rejected", "blocked",
                       "budget_exhausted"})
_SATISFIED = frozenset({"satisfied", "done", "available", "met"})


def _text(value: Any, maximum: int = 300) -> str:
    return str(value or "").strip()[:maximum]


def _refs(value: Any) -> tuple[str, ...]:
    values = value if isinstance(value, (list, tuple)) else ([value] if value else [])
    return tuple(dict.fromkeys(_text(item, 160) for item in values if _text(item, 160)))[:20]


def stable_operation_id(protocol: str, identity: str) -> str:
    """A stable technical id; it does not assert semantic equivalence."""
    raw = f"{protocol.lower()}|{identity.strip()}".encode()
    return "op_" + hashlib.sha256(raw).hexdigest()[:20]


@dataclass(frozen=True)
class Operation:
    id: str
    protocol: str
    identity: str
    endpoint: str = ""
    method: str = ""
    protocol_document: dict[str, Any] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    input_structure: dict[str, Any] = field(default_factory=dict)
    output_structure: dict[str, Any] = field(default_factory=dict)
    identities: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    permissions: tuple[dict[str, Any], ...] = ()
    state_effects: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "protocol": self.protocol, "identity": self.identity,
                "operation_id": self.identity.rsplit("#", 1)[-1],
                "endpoint": self.endpoint, "method": self.method,
                "protocol_document": self.protocol_document,
                "parameters": self.parameters, "input": self.input_structure,
                "output": self.output_structure, "identities": list(self.identities),
                "resources": list(self.resources), "permissions": list(self.permissions),
                "state_effects": list(self.state_effects),
                "provenance": list(self.provenance), "evidence": list(self.evidence)}


def operation_from_mapping(raw: dict[str, Any], *, fallback_protocol: str = "rest") -> Operation | None:
    protocol = _text(raw.get("protocol") or fallback_protocol, 16).lower()
    if protocol in ("openapi", "http"):
        protocol = "rest"
    elif protocol in ("openrpc", "json-rpc"):
        protocol = "jsonrpc"
    if protocol not in _PROTOCOLS:
        protocol = fallback_protocol
    operation_name = raw.get("operation_id") or raw.get("operation") or raw.get("identity")
    endpoint = raw.get("endpoint") or raw.get("url")
    identity = _text((f"{raw.get('method')} {endpoint}#{operation_name}"
                      if raw.get("method") and endpoint and operation_name else operation_name)
                     or raw.get("interface") or endpoint, 300)
    if not identity:
        return None
    declared = raw.get("permissions") or raw.get("security") or []
    permissions = declared if isinstance(declared, list) else [declared]
    documented_roles = raw.get("documented_roles") or []
    documented_security = raw.get("documented_security") or []
    permissions.extend({"role": role, "basis": "documented"} for role in documented_roles)
    permissions.extend({"scheme": scheme, "basis": "documented"}
                       for scheme in documented_security)
    raw_input = raw.get("input") or raw.get("input_structure")
    if not isinstance(raw_input, dict):
        raw_input = {"fields": raw.get("input_fields") or []}
    raw_output = raw.get("output") or raw.get("output_structure")
    if not isinstance(raw_output, dict):
        raw_output = {"fields": raw.get("output_fields") or []}
    return Operation(
        id=_text(raw.get("id"), 48) or stable_operation_id(protocol, identity),
        protocol=protocol, identity=identity, endpoint=_text(endpoint, 600),
        method=_text(raw.get("method"), 16),
        protocol_document=(raw.get("protocol_document")
                           if isinstance(raw.get("protocol_document"), dict) else {}),
        parameters=(raw.get("parameters") if isinstance(raw.get("parameters"), dict)
                    else {"items": raw.get("parameters")} if isinstance(raw.get("parameters"), list) else {}),
        input_structure=raw_input, output_structure=raw_output,
        identities=_refs(raw.get("identities") or raw.get("configured_identities")
                         or raw.get("sessions") or raw.get("actors")),
        resources=_refs(raw.get("resources")),
        permissions=tuple(p for p in permissions if isinstance(p, dict))[:20],
        state_effects=_refs(raw.get("state_effects") or raw.get("effects")
                            or raw.get("possible_state_effects")),
        provenance=_refs((raw.get("provenance") or {}).get("source")
                         if isinstance(raw.get("provenance"), dict)
                         else raw.get("provenance") or raw.get("source")),
        evidence=_refs(raw.get("evidence")))


def _richer(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    if not left:
        return right
    return right if len(json.dumps(right, sort_keys=True, default=str)) > len(
        json.dumps(left, sort_keys=True, default=str)) else left


def _merge_operation(left: Operation, right: Operation) -> Operation:
    permissions: dict[str, dict[str, Any]] = {}
    for item in (*left.permissions, *right.permissions):
        permissions.setdefault(json.dumps(item, sort_keys=True, default=str), item)
    return Operation(
        id=left.id, protocol=left.protocol, identity=left.identity,
        endpoint=right.endpoint or left.endpoint, method=right.method or left.method,
        protocol_document=_richer(left.protocol_document, right.protocol_document),
        parameters=_richer(left.parameters, right.parameters),
        input_structure=_richer(left.input_structure, right.input_structure),
        output_structure=_richer(left.output_structure, right.output_structure),
        identities=_refs([*left.identities, *right.identities]),
        resources=_refs([*left.resources, *right.resources]),
        permissions=tuple(permissions.values())[:20],
        state_effects=_refs([*left.state_effects, *right.state_effects]),
        provenance=_refs([*left.provenance, *right.provenance]),
        evidence=_refs([*left.evidence, *right.evidence]))

def discover_operations(endpoints: Iterable[dict[str, Any]],
                        interfaces: Iterable[dict[str, Any]] = ()) -> list[Operation]:
    """Extract reusable operation records without inventing permissions or effects."""
    found: dict[str, Operation] = {}
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        explicit = endpoint.get("operations")
        if isinstance(explicit, list):
            candidates = [x for x in explicit if isinstance(x, dict)]
        else:
            methods = endpoint.get("methods") or ([endpoint.get("method")] if endpoint.get("method") else [])
            candidates = [{**endpoint, "identity": f"{str(method).upper()} {endpoint.get('url', '')}",
                           "protocol": endpoint.get("protocol") or "rest"}
                          for method in methods if method]
        for candidate in candidates:
            operation = operation_from_mapping(candidate)
            if operation is not None:
                found[operation.id] = (_merge_operation(found[operation.id], operation)
                                       if operation.id in found else operation)
    for interface in interfaces:
        if isinstance(interface, dict):
            operation = operation_from_mapping(interface)
            if operation is not None:
                found[operation.id] = (_merge_operation(found[operation.id], operation)
                                       if operation.id in found else operation)
    return list(found.values())


@dataclass(frozen=True)
class Investigation:
    key: str
    hypothesis: str
    expected_property: str
    operation_id: str | None = None
    operation: dict[str, Any] = field(default_factory=dict)
    configured_identities: tuple[str, ...] = ()
    relevant_resources: tuple[str, ...] = ()
    known_parameters: dict[str, Any] = field(default_factory=dict)
    execution_capabilities: tuple[str, ...] = ()
    prerequisites: tuple[dict[str, Any], ...] = ()
    required_observations: tuple[str, ...] = ()
    available_tools: tuple[str, ...] = ()
    planned_verification: dict[str, Any] = field(default_factory=dict)
    progress: dict[str, Any] = field(default_factory=dict)
    status: InvestigationStatus = "discovered"
    final_outcome: str | None = None
    evidence: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        if self.status in _TERMINAL:
            return False
        return bool(self.planned_verification) and all(
            not item.get("required", True) or item.get("status") in _SATISFIED
            for item in self.prerequisites)

    @property
    def remaining_steps(self) -> int:
        steps = self.planned_verification.get("steps") or []
        completed = set(self.progress.get("completed_steps") or [])
        return max(0, len(steps) - len(completed)) if isinstance(steps, list) else 1

    @property
    def progress_state(self) -> str:
        if self.status == "verified":
            return "confirmed"
        if self.status in _TERMINAL:
            return self.status
        declared = _text(self.progress.get("state"), 32)
        if declared in {"hypothesis_established", "awaiting_evidence",
                        "verification_pending", "not_attempted"}:
            return declared
        work = self.progress.get("work_orders") or {}
        if work.get("running") or work.get("pending"):
            return "in_progress"
        if self.remaining_steps == 1 and (work.get("done") or self.evidence):
            return "verification_pending"
        if work.get("done") and self.remaining_steps:
            return "awaiting_evidence"
        if self.ready:
            return "ready"
        if self.expected_property:
            return "hypothesis_established"
        return "not_attempted"

    def next_actions(self) -> list[dict[str, Any]]:
        explicit = self.planned_verification.get("next_actions")
        if isinstance(explicit, list):
            return [item for item in explicit if isinstance(item, dict)][:6]
        actions: list[dict[str, Any]] = []
        for item in self.prerequisites:
            if item.get("required", True) and item.get("status") not in _SATISFIED:
                actions.append({"kind": "resolve_prerequisite", "prerequisite": item.get("name"),
                                "available": item.get("available")})
        if self.ready and self.operation_id:
            actions.append({
                "kind": "invoke_operation", "operation_ref": self.operation_id,
                "operation": self.operation,
                "tool": ("api.operation.invoke" if "api.operation.invoke" in self.execution_capabilities
                         else None),
                "identity_options": list(self.configured_identities),
                "resource_options": list(self.relevant_resources),
                "known_parameters": self.known_parameters,
                "required_evidence": list(self.required_observations),
            })
        if self.progress_state in ("awaiting_evidence", "verification_pending"):
            actions.append({"kind": "independent_verification",
                            "required_evidence": list(self.required_observations)})
        return actions[:6]

    def as_dict(self) -> dict[str, Any]:
        missing = [item for item in self.prerequisites
                   if item.get("required", True) and item.get("status") not in _SATISFIED]
        satisfied = [item for item in self.prerequisites if item not in missing]
        status = "ready" if self.ready and self.status == "discovered" else self.status
        return {"id": self.key, "key": self.key, "hypothesis": self.hypothesis,
                "expected_property": self.expected_property,
                "operation_id": self.operation_id, "operation": self.operation,
                "configured_identities": list(self.configured_identities),
                "relevant_resources": list(self.relevant_resources),
                "known_parameters": self.known_parameters,
                "execution_capabilities": list(self.execution_capabilities),
                "prerequisites": list(self.prerequisites),
                "satisfied_prerequisites": satisfied, "missing_prerequisites": missing,
                "required_observations": list(self.required_observations),
                "required_verification_evidence": list(self.required_observations),
                "available_tools": list(self.available_tools),
                "planned_verification": self.planned_verification,
                "progress": self.progress, "current_progress": self.progress,
                "status": status, "progress_state": self.progress_state,
                "remaining_steps": self.remaining_steps,
                "remaining_uncertainty": self.remaining_uncertainty(),
                "possible_next_actions": self.next_actions(),
                "final_outcome": self.final_outcome, "evidence": list(self.evidence)}

    def remaining_uncertainty(self) -> list[str]:
        explicit = self.progress.get("remaining_uncertainty")
        if isinstance(explicit, list):
            return [_text(item) for item in explicit if _text(item)][:10]
        if self.status in _TERMINAL:
            return []
        return ([f"Whether observed behavior satisfies: {self.expected_property}"]
                if self.expected_property else ["Security expectation is not yet established"])


def investigations_from_operations(
        operations: Iterable[Operation], *, available_identities: Iterable[str] = (),
        execution_capabilities: Iterable[str] = (),
        budget_exhausted: bool = False) -> list[Investigation]:
    """Project documented access expectations into actionable hypotheses."""
    identities = _refs(available_identities)
    capabilities = (_refs(execution_capabilities)
                    or ("api.compare_access", "tool.create", "tool.run"))
    result: list[Investigation] = []
    for operation in operations:
        documented = [permission for permission in operation.permissions
                      if permission.get("basis") == "documented"]
        if not documented:
            continue
        roles = _refs(permission.get("role") for permission in documented)
        schemes = _refs(permission.get("scheme") for permission in documented)
        expectation = ", ".join(filter(None, (
            f"role {' or '.join(roles)} required" if roles else "",
            f"authentication via {' or '.join(schemes)} required" if schemes else "")))
        key = "lead:llm:" + re.sub(r"[^a-z0-9]+", "-", operation.id.lower()).strip("-")
        state_changing = bool(operation.state_effects)
        verification_kind = ("controlled before/action/after with a fresh effect observation"
                             if state_changing else "cross-identity access comparison")
        result.append(Investigation(
            key=key,
            hypothesis=f"Documented access expectation may not be enforced for {operation.identity}",
            expected_property=expectation, operation_id=operation.id, operation=operation.as_dict(),
            configured_identities=identities, relevant_resources=operation.resources,
            known_parameters={"parameters": operation.parameters,
                              "input": operation.input_structure},
            prerequisites=(
                {"name": "operation_metadata", "required": True, "status": "satisfied"},
                {"name": "identity_contexts", "required": True,
                 "status": "satisfied" if identities else "needed",
                 "available": list(identities)}),
            required_observations=("per-identity response", "independent effect observation")
            if state_changing else ("per-identity response",),
            available_tools=tuple(tool for tool in (
                ("api.operation.invoke", "tool.create", "tool.run") if state_changing
                else ("api.operation.invoke", "api.compare_access")) if tool in capabilities),
            execution_capabilities=capabilities,
            planned_verification={"kind": verification_kind,
                                  "operation": operation.as_dict(),
                                  "steps": ["execute permitted test",
                                            "collect operation evidence",
                                            "independently verify outcome"]
                                  if state_changing else ["compare permitted identities",
                                                           "conclude expected property"]},
            progress={"source": "persisted operation observation"},
            status="budget_exhausted" if budget_exhausted else "discovered",
            evidence=operation.evidence))
    return result


def investigation_from_lead(key: str, status: str, outcome: str | None,
                            data: dict[str, Any], *, available_tools: Iterable[str] = (),
                            configured_identities: Iterable[str] = (),
                            operation_record: Operation | None = None,
                            execution_capabilities: Iterable[str] = (),
                            work_orders: Iterable[dict[str, Any]] = (),
                            budget_exhausted: bool = False) -> Investigation:
    signals = data.get("signals") if isinstance(data.get("signals"), dict) else {}
    declaration = signals.get("investigation") if isinstance(signals.get("investigation"), dict) else signals
    prereqs = declaration.get("prerequisites") or []
    prereqs = tuple(x for x in prereqs if isinstance(x, dict))[:20]
    operation = declaration.get("operation") if isinstance(declaration.get("operation"), dict) else {}
    if operation_record is not None:
        operation = {**operation_record.as_dict(), **operation}
    mapped: InvestigationStatus
    basis = _text(data.get("basis"), 48)
    declared_state = _text(declaration.get("state"), 32)
    if declared_state in _TERMINAL or declared_state in {
            "blocked", "hypothesis_established", "ready", "in_progress",
            "awaiting_evidence", "verification_pending", "not_attempted"}:
        mapped = declared_state
    elif status == "investigating":
        mapped = "in_progress"
    elif status == "confirmed":
        mapped = "verified" if basis == "verified_finding" else "inconclusive"
    elif status == "refuted":
        mapped = "rejected"
    elif status == "inconclusive":
        mapped = "inconclusive"
    elif declaration.get("blocked"):
        mapped = "blocked"
    elif budget_exhausted:
        mapped = "budget_exhausted"
    else:
        mapped = "discovered"
    progress = (declaration.get("progress")
                if isinstance(declaration.get("progress"), dict) else {}).copy()
    work = [item for item in work_orders if isinstance(item, dict)]
    if work:
        progress["work_orders"] = {state: sum(1 for item in work if item.get("status") == state)
                                   for state in ("pending", "running", "done", "failed",
                                                 "skipped", "cancelled")}
    return Investigation(
        key=key, hypothesis=_text(data.get("hypothesis"), 600),
        expected_property=_text(declaration.get("expected_property"), 400),
        operation_id=_text(declaration.get("operation_id") or operation.get("id"), 48) or None,
        operation=operation,
        configured_identities=_refs([*_refs(configured_identities),
                                     *_refs(declaration.get("configured_identities")),
                                     *_refs(operation.get("identities"))]),
        relevant_resources=_refs(declaration.get("relevant_resources")
                                 or declaration.get("resources") or operation.get("resources")),
        known_parameters=(declaration.get("known_parameters")
                          if isinstance(declaration.get("known_parameters"), dict)
                          else {"parameters": operation.get("parameters") or {},
                                "input": operation.get("input") or {}}),
        prerequisites=prereqs,
        required_observations=_refs(declaration.get("required_observations")),
        available_tools=_refs([*list(available_tools),
                               *list(declaration.get("available_tools") or [])]),
        execution_capabilities=_refs([*list(execution_capabilities),
                                      *list(declaration.get("execution_capabilities") or [])]),
        planned_verification=declaration.get("planned_verification")
        if isinstance(declaration.get("planned_verification"), dict) else {},
        progress=progress,
        status=mapped, final_outcome=outcome, evidence=_refs(declaration.get("evidence")))


def priority_for_investigation(base: int, declaration: dict[str, Any]) -> int:
    """Promote ready follow-through, especially one-step verification, over discovery."""
    inv = investigation_from_lead("", "open", None,
                                  {"hypothesis": "planned", "signals": declaration})
    if not inv.ready:
        return base
    return min(base, 7 if inv.remaining_steps <= 1 else 12)
