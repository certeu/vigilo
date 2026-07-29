from __future__ import annotations

import re
from src.greybox.graph.schema import Shape

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL = re.compile(r"^https?://")
_NUM = re.compile(r"^-?\d+$")

_NAME_HINTS: dict[Shape, tuple[str, ...]] = {
    "email": ("email", "mail"),
    "url": ("url", "uri", "href", "link", "callback", "redirect"),
    "numeric_id": ("_id", "id", "count", "num", "qty", "size"),
    "uuid": ("uuid", "guid"),
    "boolean": ("enabled", "active", "flag"),
}

_OPENAPI_TO_SHAPE: dict[str, Shape] = {
    "integer": "numeric_id",
    "number": "numeric_id",
    "boolean": "boolean",
}


def infer_shape(name: str, sample: str | None, openapi_type: str | None) -> Shape:
    """Infer parameter shape. OpenAPI type takes precedence when present."""
    if openapi_type and openapi_type.lower() in _OPENAPI_TO_SHAPE:
        return _OPENAPI_TO_SHAPE[openapi_type.lower()]

    if sample:
        if _UUID.match(sample):
            return "uuid"
        if _EMAIL.match(sample):
            return "email"
        if _URL.match(sample):
            return "url"
        if _NUM.match(sample):
            return "numeric_id"
        if sample.startswith(("{", "[")):
            return "json"
        if sample.lower() in {"true", "false"}:
            return "boolean"

    lower = name.lower()
    for shape, hints in _NAME_HINTS.items():
        if any(h in lower for h in hints):
            return shape

    return "free_text"
