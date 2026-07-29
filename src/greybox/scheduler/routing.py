"""Parameter-shape ↔ specialist routing table for the scheduler.

Since Slice 14 (Cluster E) ``VULN_SHAPE_AFFINITY`` is inverted: each
parameter shape maps to an explicit priority list of specialist
vuln_types. The earlier a vuln_type appears in a shape's list, the
higher its priority on endpoints carrying that shape.

Endpoint-level vuln_types (``graphql``, ``websocket``) do not target
individual parameter shapes — they are dispatched by endpoint signature
rather than routed through this table.
"""
from __future__ import annotations

from typing import Iterable

from src.greybox.graph.schema import Shape


VULN_SHAPE_AFFINITY: dict[Shape, list[str]] = {
    "numeric_id": ["authorization", "injection"],
    "uuid":       ["authorization"],
    "email":      ["injection"],
    "url":        ["ssrf", "reflection"],
    "free_text":  ["reflection", "injection", "ssrf"],
    "json":       ["injection", "reflection"],
    "enum":       [],
    "boolean":    [],
}


# Deterministic priority order for the per-endpoint specialist cap. When an
# endpoint's parameter shapes attract more than ``max_specialists_per_endpoint``
# vuln types, the earlier entries in this tuple win. Ordering reflects
# information-richness per finding: authorization exposes broken access
# control across identities; injection yields direct RCE/SQLi; reflection
# covers XSS/HTML injection and crypto/token reflection; ssrf pivots
# internally; graphql/websocket are endpoint-level specialists and rarely
# attach to parameter shapes.
_SPECIALIST_PRIORITY: tuple[str, ...] = (
    "authorization",
    "injection",
    "reflection",
    "ssrf",
    "graphql",
    "websocket",
)


def shapes_for_vuln(vuln_type: str) -> list[Shape]:
    """Inverse lookup over the new shape→vuln dict.

    Returns every shape that lists ``vuln_type`` in its priority list,
    preserving the historic iteration order (shapes scanned in dict
    order). Used by the scheduler to filter ``untested_parameters`` by
    vuln_type before dispatching ``PROBE_PARAMETERS`` verbs.
    """
    return [
        shape
        for shape, vuln_types in VULN_SHAPE_AFFINITY.items()
        if vuln_type in vuln_types
    ]


def specialists_for_shape(shape: Shape, cap: int) -> list[str]:
    """Return the vuln_type priority list for ``shape``, truncated to ``cap``.

    ``cap <= 0`` returns an empty list. Unknown shapes return an empty
    list.
    """
    if cap <= 0:
        return []
    return list(VULN_SHAPE_AFFINITY.get(shape, []))[:cap]


def specialists_for_endpoint(
    param_shapes: Iterable[Shape],
    cap: int,
) -> list[str]:
    """Return vuln_types that match any of ``param_shapes``, ordered by
    ``_SPECIALIST_PRIORITY`` and truncated to ``cap``. Used to prevent
    specialist stacking on a single endpoint (C4).
    """
    if cap <= 0:
        return []
    # Union of vuln_types across the endpoint's parameter shapes.
    union: set[str] = set()
    for shape in param_shapes:
        union.update(VULN_SHAPE_AFFINITY.get(shape, []))
    # Return in priority order so callers can slice deterministically.
    matched = [vt for vt in _SPECIALIST_PRIORITY if vt in union]
    return matched[:cap]
