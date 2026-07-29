"""Record ID canonicalization for SurrealDB.

SurrealDB record IDs use the format `type:identifier`. URL paths contain
characters invalid in identifiers (slashes, dots, brackets, query strings).
All ID generation goes through canonicalize_id().

``normalize_record_id`` coerces SurrealDB SDK ``RecordID`` objects (returned
by query results) into plain ``table:id`` strings so downstream code can
safely apply regex validation or use them in string comparisons.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any


def normalize_record_id(value: Any) -> str:
    """Coerce a SurrealDB RecordID (or string) into the canonical ``table:id`` form."""
    if isinstance(value, str):
        return value
    try:
        return f"{value.table}:{value.id}"
    except AttributeError:
        return str(value)


def canonicalize_id(node_type: str, raw_id: str) -> str:
    """Convert an arbitrary string into a safe SurrealDB record ID."""
    # Strip scheme + host for full URLs
    cleaned = re.sub(r"^https?://[^/]+", "", raw_id)
    # Replace non-alphanumeric with underscore
    sanitized = re.sub(r"[^a-zA-Z0-9]", "_", cleaned)
    # Collapse runs of underscores, strip leading/trailing
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    # Fallback for empty result (e.g., bare "https://host/")
    if not sanitized:
        sanitized = hashlib.sha256(raw_id.encode()).hexdigest()[:16]
    # Truncate long IDs with hash suffix for uniqueness
    if len(sanitized) > 64:
        hash_suffix = hashlib.sha256(raw_id.encode()).hexdigest()[:8]
        sanitized = f"{sanitized[:55]}_{hash_suffix}"
    return f"{node_type}:{sanitized}"
