"""Redaction applied before anything grey-box is persisted.

On top of the process-global registry in :mod:`src.audit.redact` (whole secret values
and their encoded variants), this masks by *structure*:

* sensitive header values (``Authorization``, ``Cookie``, ``X-Api-Key``...); for
  ``Set-Cookie`` only the cookie value is masked, so the name and attributes stay
  visible as ``cookies.flags`` evidence;
* query and form parameters whose name looks sensitive (``pass``, ``token``,
  ``session``...);
* stored response bodies, by name only (:func:`body_text`): ``value`` of HTML
  ``<input>`` elements and ``content`` of ``<meta>`` tags whose name/id looks
  sensitive, ``?name=value`` pairs inside any URL or text, and the values of JSON
  keys that look sensitive. Everything else stays byte-identical so evidence still
  reproduces. Secrets under non-sensitive names are NOT masked.

Every summary, ``data`` string, URL and stored body goes through :func:`text` (the
registry) as well. Over-redaction is safe; under-redaction is a bug.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.audit import redact as _registry

MASK = _registry.MASK
SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "x-api-key", "x-auth-token",
})
SENSITIVE_PARAM = re.compile(r"(?i)pass|pwd|token|secret|session|auth|key|csrf")


def register_secret(value: str | None) -> None:
    """Start masking ``value`` (and derived forms) everywhere. Call before the first
    event or exchange that could contain it is written."""
    _registry.register_secret(value)


def text(value: str | None) -> str | None:
    if value is None:
        return None
    return _registry.redact(value)


def _mask_set_cookie(value: str) -> str:
    first, sep, rest = value.partition(";")
    name, eq, _ = first.partition("=")
    if not eq:
        return value
    return f"{name.strip()}={MASK}{sep}{rest}"


URL_HEADERS = frozenset({"location", "content-location", "refresh", "link", "referer"})
# Dict keys whose value is a name -> value mapping of form/query fields.
FIELD_MAP_KEYS = frozenset({"fields", "values", "params", "form", "defaults"})
_QS_PAIR = re.compile(r"([?&;])([^=&;\s\"'<>#]+)=([^&;\s\"'<>#]*)")


def scrub(value: str | None) -> str | None:
    """Registry redaction plus name-based masking of every ``?name=value`` pair in
    free text (absolute or relative URLs, descriptions, header values)."""
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)          # httpx.URL and friends: never crash on a header

    def sub(m: re.Match[str]) -> str:
        if SENSITIVE_PARAM.search(m.group(2)):
            return f"{m.group(1)}{m.group(2)}={MASK}"
        return m.group(0)
    return text(_QS_PAIR.sub(sub, value))


def mask_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """Mask the values of a name -> value mapping by field name."""
    return {k: (MASK if SENSITIVE_PARAM.search(str(k)) and v not in (None, "") else v)
            for k, v in fields.items()}


def structured(value: Any, key: str | None = None) -> Any:
    """Recursive redaction of JSON-like data: registry + URL query masking on every
    string, and name-based masking inside field/param value mappings."""
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        if key in FIELD_MAP_KEYS:
            value = mask_fields(value)
        return {k: structured(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [structured(v, key) for v in value]
    return value


def headers(items: Iterable[tuple[str, str]]) -> list[list[str]]:
    out: list[list[str]] = []
    for name, value in items:
        low = name.lower()
        if low in SENSITIVE_HEADERS:
            value = MASK
        elif low == "set-cookie":
            value = _mask_set_cookie(value)
        elif low in URL_HEADERS:
            value = scrub(value) or ""
        out.append([name, text(value) or ""])
    return out


def _mask_pairs(qs: str) -> str:
    if not qs:
        return qs
    pairs = parse_qsl(qs, keep_blank_values=True)
    if not any(SENSITIVE_PARAM.search(k) for k, _ in pairs):
        return qs
    return urlencode([(k, MASK if SENSITIVE_PARAM.search(k) else v) for k, v in pairs],
                     safe="*")


def url(value: str) -> str:
    try:
        parts = urlsplit(value)
        value = urlunsplit(parts._replace(query=_mask_pairs(parts.query)))
    except ValueError:
        pass
    return text(value) or ""


_TAG_INPUT = re.compile(r"<input\b[^>]*>?", re.I)
_TAG_META = re.compile(r"<meta\b[^>]*>?", re.I)
_ATTR_NAME = re.compile(r"""(?i)(?<![\w-])(?:name|id)\s*=\s*("([^"]*)"?|'([^']*)'?|([^\s>"']+))""")
_ATTR_META_NAME = re.compile(r"""(?i)(?<![\w-])name\s*=\s*("([^"]*)"?|'([^']*)'?|([^\s>"']+))""")
_ATTR_VALUE = re.compile(
    r"""(?i)((?<![\w-])(?:value|content)\s*=\s*)("[^"]*(?:"|$)|'[^']*(?:'|$)|[^\s>"']+)""")
_JSON_KEY = re.compile(r'"((?:[^"\\]|\\.)*)"(\s*:\s*)')


def _attr_names(tag: str, pattern: re.Pattern[str]) -> list[str]:
    return [next((g for g in m.groups()[1:] if g is not None), "")
            for m in pattern.finditer(tag)]


def _mask_attr_value(tag: str) -> str:
    def sub(m: re.Match[str]) -> str:
        raw = m.group(2)
        quote = raw[0] if raw[0] in "\"'" else ""
        inner = raw[1:].rstrip(quote) if quote else raw
        if not inner:
            return m.group(0)
        return f"{m.group(1)}{quote}{MASK}{quote}"
    return _ATTR_VALUE.sub(sub, tag, count=0)


def _mask_html(value: str) -> str:
    def inp(m: re.Match[str]) -> str:
        tag = m.group(0)
        if any(SENSITIVE_PARAM.search(n) for n in _attr_names(tag, _ATTR_NAME)):
            return _mask_attr_value(tag)
        return tag

    def meta(m: re.Match[str]) -> str:
        tag = m.group(0)
        if any(SENSITIVE_PARAM.search(n) for n in _attr_names(tag, _ATTR_META_NAME)):
            return _mask_attr_value(tag)
        return tag
    if "<" not in value:
        return value
    return _TAG_META.sub(meta, _TAG_INPUT.sub(inp, value))


def _json_value_end(value: str, i: int) -> int:
    """End index of the JSON value starting at ``i`` (string-aware bracket match;
    scalars end at the next delimiter). Tolerates truncated input."""
    n = len(value)
    if i >= n:
        return n
    c = value[i]
    if c == '"':
        j = i + 1
        while j < n:
            if value[j] == "\\":
                j += 2
                continue
            if value[j] == '"':
                return j + 1
            j += 1
        return n
    if c in "{[":
        depth, j = 0, i
        while j < n:
            ch = value[j]
            if ch == '"':
                j = _json_value_end(value, j)
                continue
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return n
    j = i
    while j < n and value[j] not in ",}]\r\n":
        j += 1
    return len(value[:j].rstrip())


def _mask_json_keys(value: str) -> str:
    """Replace the value of every ``"<sensitive key>": value`` (any nesting, valid
    JSON or not) with the mask, keeping all other bytes. Not a parse: the text is
    scanned, so malformed or truncated JSON is handled the same way."""
    if '"' not in value or ":" not in value:
        return value
    out: list[str] = []
    pos = 0
    while True:
        m = _JSON_KEY.search(value, pos)
        if m is None:
            out.append(value[pos:])
            break
        start = m.end()
        if SENSITIVE_PARAM.search(m.group(1)):
            end = _json_value_end(value, start)
            raw = value[start:end].strip()
            out.append(value[pos:start])
            if raw in ("", "null", '""', "true", "false"):
                out.append(value[start:end])
            else:
                out.append(f'"{MASK}"')
            pos = end
        else:
            out.append(value[pos:start])
            pos = start
    return "".join(out)


def body_text(value: str | None) -> str | None:
    """Name-based masking of a stored body or evidence excerpt, then the registry.
    Applied before truncation. See the module docstring for what it covers."""
    if value is None:
        return None
    return scrub(_mask_json_keys(_mask_html(value)))


def body(value: str | None, content_type: str | None = None) -> str | None:
    if value is None:
        return None
    if content_type and "application/x-www-form-urlencoded" in content_type.lower():
        return text(_mask_pairs(value))
    return body_text(value)


def obj(value: Any) -> Any:
    """Recursively redact every string in a JSON-like value."""
    if isinstance(value, str):
        return text(value)
    if isinstance(value, dict):
        return {k: obj(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [obj(v) for v in value]
    return value
