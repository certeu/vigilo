"""Evidence-backed lifecycle state for assessment resources.

Resources remain ordinary security-model assets.  This module only owns the
``lifecycle`` envelope in their data, making suitability and reuse explicit
without creating a second resource graph.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import secmodel as sm
from src.greybox_web.models import GreyboxAsset
from src.greybox_web.secmodel_store import resolve_evidence
from src.greybox_web.scope import ScopePolicy

MUTABILITY = {"read_only", "mutable", "unknown"}
DISPOSAL = {"disposable", "non_disposable", "unknown"}
RESET = {"supported", "unsupported", "unknown"}
STATES = {"available", "reserved", "modified", "consumed", "unsuitable", "unknown"}
TRUSTED_BASES = {"configured", "documented", "observed_ui"}


@dataclass(frozen=True)
class LifecycleDeclaration:
    resource: sm.EntityRef
    mutability: str = "unknown"
    disposal: str = "unknown"
    reset: str = "unknown"
    state: str = "available"
    basis: str = "stated"
    evidence: tuple[str, ...] = ()
    reset_operation_ref: str | None = None
    operator_configured: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        if self.resource.kind != "resource":
            raise ValueError("lifecycle declarations require a resource instance")
        if self.mutability not in MUTABILITY or self.disposal not in DISPOSAL:
            raise ValueError("invalid lifecycle classification")
        if self.reset not in RESET or self.state not in STATES:
            raise ValueError("invalid lifecycle state")
        if self.basis not in sm.BASES:
            raise ValueError("invalid lifecycle basis")


@dataclass(frozen=True)
class Suitability:
    resource_ref: str
    suitable: bool
    reason: str
    lifecycle: dict[str, Any] = field(default_factory=dict)


def from_operator_policy(scope: ScopePolicy, resource: sm.EntityRef,
                         note: str = "") -> LifecycleDeclaration:
    """Apply the target-wide guarantee to any independently discovered resource."""
    if scope.resource_lifecycle != "disposable_resettable":
        return LifecycleDeclaration(resource=resource, note=note)
    return LifecycleDeclaration(
        resource=resource, mutability="mutable", disposal="disposable",
        reset="supported", state="available", basis="configured",
        operator_configured=True,
        note=note or "target is operator-configured as disposable and resettable")


def _now() -> str:
    return datetime.now(UTC).isoformat()


async def declare(session: AsyncSession, gtx, item: LifecycleDeclaration) -> dict[str, Any]:
    """Persist a lifecycle classification and downgrade unsupported claims."""
    resolved, unresolved = await resolve_evidence(session, gtx.run_id, item.evidence)
    trusted = item.operator_configured or (item.basis in TRUSTED_BASES and bool(resolved))
    lifecycle = asdict(item)
    lifecycle["resource_ref"] = item.resource.key
    lifecycle["evidence"] = resolved[:8]
    lifecycle["unresolved"] = unresolved[:8]
    lifecycle["trusted"] = trusted
    lifecycle["updated_at"] = _now()
    if not trusted and (item.disposal == "disposable" or item.reset == "supported"):
        lifecycle["disposal"] = "unknown"
        lifecycle["reset"] = "unknown"
        lifecycle["note"] = ((item.note + "; ") if item.note else "") + \
            "disposable/resettable claim lacks supporting evidence or operator configuration"
    asset = await gtx.asset("resource", item.resource.key,
                            f"resource {item.resource.name}", in_scope=True,
                            data={"model": True, "name": item.resource.name,
                                  "lifecycle": lifecycle})
    return {"resource_ref": asset.key, **lifecycle}


async def inspect(session: AsyncSession, run_id, resource_ref: str) -> Suitability:
    asset = await session.scalar(select(GreyboxAsset).where(
        GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "resource",
        GreyboxAsset.key == resource_ref[:600]))
    if asset is None:
        return Suitability(resource_ref, False, "unknown_resource")
    lifecycle = dict((asset.data or {}).get("lifecycle") or {})
    if not lifecycle:
        return Suitability(resource_ref, False, "unknown_lifecycle")
    if lifecycle.get("state") in {"consumed", "unsuitable"}:
        return Suitability(resource_ref, False, str(lifecycle["state"]), lifecycle)
    if lifecycle.get("mutability") != "mutable":
        return Suitability(resource_ref, False, "not_known_mutable", lifecycle)
    if lifecycle.get("disposal") != "disposable" or not lifecycle.get("trusted"):
        return Suitability(resource_ref, False, "not_evidence_backed_disposable", lifecycle)
    if lifecycle.get("state") == "modified" and lifecycle.get("reset") != "supported":
        return Suitability(resource_ref, False, "modified_without_reset", lifecycle)
    return Suitability(resource_ref, True, "controlled_resource", lifecycle)


async def reserve(session: AsyncSession, run_id, resource_ref: str,
                  investigation_ref: str) -> Suitability:
    """Atomically reserve a suitable disposable resource in the caller transaction."""
    asset = await session.scalar(select(GreyboxAsset).where(
        GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "resource",
        GreyboxAsset.key == resource_ref[:600]).with_for_update())
    suitability = await inspect(session, run_id, resource_ref)
    if asset is None or not suitability.suitable:
        return suitability
    lifecycle = dict(suitability.lifecycle)
    if lifecycle.get("state") == "reserved" and \
            lifecycle.get("reserved_by") != investigation_ref:
        return Suitability(resource_ref, False, "reserved_by_other_investigation", lifecycle)
    lifecycle.update(state="reserved", reserved_by=investigation_ref, updated_at=_now())
    asset.data = {**(asset.data or {}), "lifecycle": lifecycle}
    return Suitability(resource_ref, True, "reserved", lifecycle)


async def transition(session: AsyncSession, run_id, resource_ref: str, *, state: str,
                     investigation_ref: str, operation_ref: str | None = None,
                     evidence: tuple[str, ...] = (), note: str = "") -> Suitability:
    """Record mutation, reset, consumption, or unsuitability with provenance."""
    if state not in {"available", "modified", "consumed", "unsuitable"}:
        raise ValueError("invalid resource transition")
    asset = await session.scalar(select(GreyboxAsset).where(
        GreyboxAsset.run_id == run_id, GreyboxAsset.kind == "resource",
        GreyboxAsset.key == resource_ref[:600]).with_for_update())
    if asset is None:
        return Suitability(resource_ref, False, "unknown_resource")
    lifecycle = dict((asset.data or {}).get("lifecycle") or {})
    if lifecycle.get("reserved_by") not in (None, investigation_ref):
        return Suitability(resource_ref, False, "reserved_by_other_investigation", lifecycle)
    resolved, unresolved = await resolve_evidence(session, run_id, evidence)
    history = list(lifecycle.get("history") or [])[-15:]
    history.append({"state": state, "investigation_ref": investigation_ref,
                    "operation_ref": operation_ref, "evidence": resolved[:8],
                    "unresolved": unresolved[:8], "note": note, "at": _now()})
    lifecycle.update(state=state, history=history, updated_at=_now())
    lifecycle.pop("reserved_by", None)
    asset.data = {**(asset.data or {}), "lifecycle": lifecycle}
    return Suitability(resource_ref, True, state, lifecycle)

