"""Declarative dynamic tool specs (batch E, "tools on demand"): the fixed
vocabulary the exploration agent composes instruments from when no built-in tool
can express a check (a reflection in a custom header, a JSON field that flips, a
status difference only visible with a specific value).

The model NEVER gets code execution: :func:`validate_spec` accepts a spec only
when every field is one of the vocabulary values below (ids, enums, key sets,
short strings — sanity bounds on the SPEC TEXT, never quotas on tool COUNT).
Execution is the guarded generic executor (:mod:`src.greybox_web.tools.dynrun`)
through ``ctx.http`` with per-hop scope, budgets and redaction, exactly like a
built-in tool; the payloads are the same inert ones (fixed canary, single
appended quote, ``.invalid`` probe host never followed) and the methods are
non-destructive (GET/POST/HEAD/OPTIONS).

There is deliberately NO count cap on dynamic tools: the gates are this
validation and the run's own dedup/scope/budgets. Redefining an id that already
exists (static or dynamic) is rejected as a duplicate — correctness, not a quota.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from src.greybox_web.tools import Observation, ToolContext, ToolResult

# --------------------------------------------------------------------- vocabulary

# The param keys a dynamic instrument may accept (the admission vocabulary: a
# work order for the tool may carry only these). "url" is MANDATORY — dynamic
# tools are URL-addressed like every check, so admission scope-checks the target
# exactly as for a built-in tool.
ALLOWED_PARAM_KEYS = ("url", "param", "location", "header", "value", "method",
                      "path", "needle", "expect")
METHODS = ("GET", "POST", "HEAD", "OPTIONS")
INTO = ("url", "param", "header")
LOCATIONS = ("query", "form", "header")
TRANSFORMS = ("set", "canary", "append_quote", "probe_host", "from_param")
SEVERITIES = ("low", "medium", "high", "critical")
KINDS = ("check",)                     # discovery kinds arrive with a later batch

_ID_RE = re.compile(r"^dyn\.[a-z0-9][a-z0-9-]{0,39}$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")          # no CR/LF smuggling
_CWE_RE = re.compile(r"^CWE-\d{1,4}$")
_JSON_SEG_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")

# The exact key set every predicate type carries (a strict vocabulary: unknown
# fields or types are refused, not guessed). "value" is required only for a
# json_path "equals" comparison (checked separately).
PREDICATE_TYPES: dict[str, tuple[str, ...]] = {
    "reflection_of": ("of",),
    "signature": ("which",),
    "body_contains": ("value",),
    "body_regex": ("value",),
    "status_class": ("value",),
    "status_differs": ("from",),
    "body_differs": ("from",),
    "header_contains": ("name", "value"),
    "location_host_is": ("of",),
    "json_path": ("path", "op", "value"),
}
SIG_WHICH = ("sql", "debug", "any")
STATUS_CLASSES = ("2", "3", "4", "5")
JSON_OPS = ("exists", "equals")

# The regex subset a body_regex predicate may use: literal text, character
# classes and the listed quantifier/group syntax. No backslash (escapes,
# backreferences, \d-style classes), no ^/$ anchors — anything outside this set
# is refused before the pattern is ever compiled or run.
SAFE_REGEX_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    " .,:;!/'\"_%@#~=<>-"        # literal text (ASCII only)
    "+*?{}|()[]")                # the listed regex syntax

# Sanity bounds on the spec's strings (bounds on TEXT, not on tool count).
MAX_TEXT = 200                   # titles, header names, short fields
MAX_DESCRIPTION = 600            # report prose
MAX_LITERAL = 120                # predicate literals, regexes
MAX_HINT = 300                   # one remediation sentence


# ------------------------------------------------------------------ the spec types

@dataclass(frozen=True)
class DynInject:
    """One injection point: where a value goes and which inert payload fills it."""

    into: str            # url | param | header
    key: str             # the query/form parameter or request-header name
    location: str        # query | form | header
    transform: str       # set | canary | append_quote | probe_host | from_param


@dataclass(frozen=True)
class DynRequest:
    method: str
    inject: tuple[DynInject, ...]
    follow: bool
    baseline: bool


@dataclass(frozen=True)
class DynPredicate:
    type: str
    data: dict[str, str]


@dataclass(frozen=True)
class DynVerdict:
    mode: str            # any | all
    predicates: tuple[DynPredicate, ...]


@dataclass(frozen=True)
class DynFinding:
    title: str
    description: str
    severity: str
    confidence: str
    cwe: str | None
    hint: str | None


@dataclass(frozen=True)
class DynTool:
    """One validated declarative instrument (the run's registry entry is built
    from it by :func:`registry_entries`)."""

    id: str
    kind: str
    title: str
    description: str
    param_keys: tuple[str, ...]
    request: DynRequest
    verdict: DynVerdict
    finding: DynFinding


# -------------------------------------------------------------------- validation

def _text(value: Any, field: str, limit: int, errors: list[str], *,
          required: bool = True) -> str:
    if not isinstance(value, str):
        if required:
            errors.append(f"{field}: missing")
        return ""
    v = value.strip()
    if not v:
        if required:
            errors.append(f"{field}: empty")
        return ""
    if len(v) > limit:
        errors.append(f"{field}: longer than {limit} characters")
        return ""
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in v):
        errors.append(f"{field}: control characters are not allowed")
        return ""
    return v


def _key_name(value: Any, field: str, errors: list[str]) -> str:
    """A parameter or header name: short, no whitespace, no control characters
    (a CR/LF in a header name or value would smuggle headers)."""
    v = _text(value, field, MAX_TEXT, errors)
    if v and (any(ch.isspace() for ch in v)):
        errors.append(f"{field}: whitespace is not allowed in a name")
        return ""
    return v


def _regex_is_safe(pattern: str) -> str | None:
    """``None`` when the pattern is inside the subset and safe to run; a reason
    otherwise. Three gates: the character set, plain compilation, and a
    structural walk (via ``re``'s parser when available) that refuses the
    exponential-backtracking shapes — a quantified group whose body still
    contains a group, an alternation or another quantifier, e.g. ``(a|a)+`` or
    ``(a+)+``. A hostile page cannot make the executor hang on a regex."""
    bad = sorted(set(pattern) - SAFE_REGEX_CHARS)
    if bad:
        return f"regex uses characters outside the allowed subset: {''.join(bad)!r}"
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"regex does not compile: {exc}"
    try:
        from re import _constants as _c
        from re import _parser as _p
    except ImportError:                       # a future Python: gates 1 and 2 only
        return None
    quant = {_c.MAX_REPEAT, _c.MIN_REPEAT}
    group = {_c.SUBPATTERN}
    for name in ("ATOMIC_GROUP", "POSSESSIVE_REPEAT"):
        if hasattr(_c, name):
            quant.add(getattr(_c, name))
            group.add(getattr(_c, name))
    branch = _c.BRANCH

    def body(node: Any) -> list[Any]:
        return list(node) if node is not None else []

    def unwrap(av: Any) -> Any:
        # the operand of a quantifier, looking through ONE wrapping group
        items = body(av[2] if isinstance(av, tuple) and len(av) > 2 else av)
        if len(items) == 1 and items[0][0] in group:
            inner = items[0][1]
            return body(inner[3] if items[0][0] == _c.SUBPATTERN
                        and isinstance(inner, tuple) and len(inner) > 3 else inner)
        return items

    def dangerous(node: Any) -> bool:
        for op, av in body(node):
            if op in quant:
                if any(so in quant or so in group or so == branch
                       for so, _sv in unwrap(av)):
                    return True
            elif op in group:
                inner = av[3] if (op == _c.SUBPATTERN and isinstance(av, tuple)
                                  and len(av) > 3) else av
                if dangerous(body(inner) if not isinstance(inner, list) else inner):
                    return True
            elif op == branch:
                branches = av[1] if isinstance(av, tuple) and len(av) > 1 else []
                if any(dangerous(b) for b in branches):
                    return True
        return False

    try:
        if dangerous(_p.parse(pattern)):
            return "regex nests quantified groups (catastrophic backtracking)"
    except Exception:                          # noqa: BLE001 — unparseable: refuse
        return "regex could not be analysed"
    return None


def _validate_request(raw: Any, param_keys: tuple[str, ...], baseline: bool,
                      errors: list[str]) -> DynRequest | None:
    if not isinstance(raw, dict):
        errors.append("request: missing (method, inject, follow are required)")
        return None
    unknown = sorted(set(raw) - {"method", "inject", "follow"})
    if unknown:
        errors.append(f"request: unknown field(s) {', '.join(unknown)}")
    method = str(raw.get("method") or "").upper()
    if method not in METHODS:
        errors.append(f"request.method: {method!r} is not one of {', '.join(METHODS)}")
        return None
    injects_raw = raw.get("inject")
    if not isinstance(injects_raw, list) or not (1 <= len(injects_raw) <= 3):
        errors.append("request.inject: 1 to 3 injection points are required")
        return None
    injects: list[DynInject] = []
    transforms: set[str] = set()
    for i, item in enumerate(injects_raw):
        where = f"request.inject[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{where}: not an object")
            continue
        unknown = sorted(set(item) - {"into", "key", "location", "transform"})
        if unknown:
            errors.append(f"{where}: unknown field(s) {', '.join(unknown)}")
        into = str(item.get("into") or "")
        location = str(item.get("location") or "")
        transform = str(item.get("transform") or "")
        if into not in INTO:
            errors.append(f"{where}.into: {into!r} is not one of {', '.join(INTO)}")
            continue
        if transform not in TRANSFORMS:
            errors.append(f"{where}.transform: {transform!r} is not one of "
                          f"{', '.join(TRANSFORMS)}")
            continue
        # into/location consistency: a header injection lives in a header; a url
        # or parameter injection lives in the query string or a form body.
        if into == "header" and location != "header":
            errors.append(f"{where}: into=header requires location=header")
            continue
        if into != "header" and location not in ("query", "form"):
            errors.append(f"{where}: into={into} requires location query or form")
            continue
        key = _key_name(item.get("key"), f"{where}.key", errors)
        if into == "header" and key and not _HEADER_NAME_RE.match(key):
            errors.append(f"{where}.key: {key!r} is not a valid header name")
            continue
        if location == "form" and method != "POST":
            errors.append(f"{where}: a form injection requires method POST")
            continue
        if transform == "set" and "value" not in param_keys:
            errors.append(f"{where}: transform set needs 'value' in param_keys")
            continue
        if not key:
            continue
        injects.append(DynInject(into=into, key=key, location=location,
                                 transform=transform))
        transforms.add(transform)
    if len(injects) != len(injects_raw) or not injects:
        return None
    follow = raw.get("follow")
    if not isinstance(follow, bool):
        errors.append("request.follow: true or false is required")
        return None
    if "probe_host" in transforms and follow:
        # the probe host is reserved .invalid and is only ever read back from a
        # Location header: it must never be followed
        errors.append("request.follow: must be false when a transform is probe_host")
        return None
    return DynRequest(method=method, inject=tuple(injects), follow=follow,
                      baseline=baseline)


def _validate_verdict(raw: Any, request: DynRequest | None,
                      errors: list[str]) -> DynVerdict | None:
    if not isinstance(raw, dict):
        errors.append("verdict: missing (mode and predicates are required)")
        return None
    unknown = sorted(set(raw) - {"mode", "predicates"})
    if unknown:
        errors.append(f"verdict: unknown field(s) {', '.join(unknown)}")
    mode = str(raw.get("mode") or "")
    if mode not in ("any", "all"):
        errors.append(f"verdict.mode: {mode!r} is not any or all")
        return None
    preds_raw = raw.get("predicates")
    if not isinstance(preds_raw, list) or not (1 <= len(preds_raw) <= 6):
        errors.append("verdict.predicates: 1 to 6 predicates are required")
        return None
    preds: list[DynPredicate] = []
    seen_types: set[str] = set()
    for i, item in enumerate(preds_raw):
        where = f"verdict.predicates[{i}]"
        if not isinstance(item, dict) or "type" not in item:
            errors.append(f"{where}: no type")
            continue
        ptype = str(item["type"])
        if ptype not in PREDICATE_TYPES:
            errors.append(f"{where}.type: {ptype!r} is not in the predicate vocabulary")
            continue
        if ptype in seen_types:
            errors.append(f"{where}: {ptype} appears twice (one of each type)")
            continue
        seen_types.add(ptype)
        allowed = set(PREDICATE_TYPES[ptype])
        unknown = sorted(set(item) - allowed - {"type"})
        if unknown:
            errors.append(f"{where}: unknown field(s) {', '.join(unknown)}")
            continue
        missing = sorted(f for f in allowed - {"value"} if f not in item)
        if missing:
            errors.append(f"{where}: missing field(s) {', '.join(missing)}")
            continue
        data: dict[str, str] = {}
        ok = True
        if ptype == "reflection_of":
            if item.get("of") != "canary":
                errors.append(f"{where}.of: must be 'canary'")
                ok = False
            elif request is None or not any(
                    inj.transform == "canary" for inj in request.inject):
                errors.append(f"{where}: reflection_of needs a canary injection")
                ok = False
            else:
                data["of"] = "canary"
        elif ptype == "signature":
            which = str(item.get("which") or "")
            if which not in SIG_WHICH:
                errors.append(f"{where}.which: {which!r} is not one of "
                              f"{', '.join(SIG_WHICH)}")
                ok = False
            else:
                data["which"] = which
        elif ptype in ("body_contains", "body_regex"):
            value = _text(item.get("value"), f"{where}.value", MAX_LITERAL, errors)
            if not value:
                ok = False
            elif ptype == "body_regex":
                why = _regex_is_safe(value)
                if why:
                    errors.append(f"{where}.value: {why}")
                    ok = False
            if ok:
                data["value"] = value
        elif ptype == "status_class":
            value = str(item.get("value") or "")
            if value not in STATUS_CLASSES:
                errors.append(f"{where}.value: {value!r} is not one of "
                              f"{', '.join(STATUS_CLASSES)}")
                ok = False
            else:
                data["value"] = value
        elif ptype in ("status_differs", "body_differs"):
            if item.get("from") != "baseline":
                errors.append(f"{where}.from: must be 'baseline'")
                ok = False
            elif request is None or not request.baseline:
                errors.append(f"{where}: needs baseline: true in the request")
                ok = False
            else:
                data["from"] = "baseline"
        elif ptype == "header_contains":
            name = _text(item.get("name"), f"{where}.name", MAX_TEXT, errors)
            value = _text(item.get("value"), f"{where}.value", MAX_LITERAL, errors)
            if name and not _HEADER_NAME_RE.match(name):
                errors.append(f"{where}.name: {name!r} is not a valid header name")
                ok = False
            if ok and name and value:
                data["name"], data["value"] = name, value
            elif not (name and value):
                ok = False
        elif ptype == "location_host_is":
            if item.get("of") != "probe_host":
                errors.append(f"{where}.of: must be 'probe_host'")
                ok = False
            elif request is None or not any(
                    inj.transform == "probe_host" for inj in request.inject):
                errors.append(f"{where}: location_host_is needs a probe_host injection")
                ok = False
            else:
                data["of"] = "probe_host"
        elif ptype == "json_path":
            path = str(item.get("path") or "")
            segments = path.split(".") if path else []
            if not (1 <= len(segments) <= 6) or not all(
                    _JSON_SEG_RE.match(s) for s in segments):
                errors.append(f"{where}.path: {path!r} is not a dotted path of "
                              "1 to 6 short segments")
                ok = False
            op = str(item.get("op") or "")
            if op not in JSON_OPS:
                errors.append(f"{where}.op: {op!r} is not exists or equals")
                ok = False
            value = _text(item.get("value"), f"{where}.value", MAX_LITERAL, errors,
                          required=(op == "equals"))
            if not (op == "exists" or value):
                ok = False
            if ok:
                data["path"], data["op"] = path, op
                if value:
                    data["value"] = value
        if ok:
            preds.append(DynPredicate(type=ptype, data=data))
    if len(preds) != len(preds_raw) or not preds:
        return None
    return DynVerdict(mode=mode, predicates=tuple(preds))


def _validate_finding(raw: Any, errors: list[str]) -> DynFinding | None:
    if not isinstance(raw, dict):
        errors.append("finding: missing (title, description, severity, confidence)")
        return None
    unknown = sorted(set(raw) - {"title", "description", "severity", "confidence",
                                 "cwe", "hint"})
    if unknown:
        errors.append(f"finding: unknown field(s) {', '.join(unknown)}")
    title = _text(raw.get("title"), "finding.title", MAX_TEXT, errors)
    description = _text(raw.get("description"), "finding.description",
                        MAX_DESCRIPTION, errors)
    severity = str(raw.get("severity") or "")
    if severity not in SEVERITIES:
        errors.append(f"finding.severity: {severity!r} is not one of "
                      f"{', '.join(SEVERITIES)}")
    confidence = _text(raw.get("confidence"), "finding.confidence", 40, errors)
    cwe = raw.get("cwe")
    if cwe is not None and (not isinstance(cwe, str)
                            or not _CWE_RE.match(cwe.strip())):
        errors.append("finding.cwe: must look like CWE-<number>")
        cwe = None
    hint = raw.get("hint")
    if hint is not None:
        hint = _text(hint, "finding.hint", MAX_HINT, errors, required=False) or None
    if errors or not (title and description and severity and confidence):
        return None
    return DynFinding(title=title, description=description, severity=severity,
                      confidence=confidence,
                      cwe=cwe.strip() if isinstance(cwe, str) else None, hint=hint)


def validate_spec(spec: Any) -> tuple[DynTool | None, list[str]]:
    """Strict validation of one declarative spec against the vocabulary.
    Returns ``(DynTool, [])`` or ``(None, errors)``. Every bound here is a bound
    on the spec's own text (ids, enums, key sets, string sanity); nothing limits
    how many instruments a run may define."""
    errors: list[str] = []
    if not isinstance(spec, dict):
        return None, ["spec: must be a JSON object"]
    unknown = sorted(set(spec) - {"id", "kind", "title", "description", "param_keys",
                                  "request", "verdict", "finding", "baseline"})
    if unknown:
        errors.append(f"spec: unknown field(s) {', '.join(unknown)}")
    ident = str(spec.get("id") or "")
    if not _ID_RE.match(ident):
        errors.append(f"spec.id: {ident!r} must be dyn.<lowercase-slug>")
    kind = str(spec.get("kind") or "")
    if kind not in KINDS:
        errors.append(f"spec.kind: {kind!r} must be 'check'")
    title = _text(spec.get("title"), "spec.title", MAX_TEXT, errors)
    description = _text(spec.get("description"), "spec.description",
                        MAX_DESCRIPTION, errors)
    keys_raw = spec.get("param_keys")
    if not isinstance(keys_raw, list) or not keys_raw:
        errors.append("spec.param_keys: a non-empty list is required")
        return None, errors
    param_keys: list[str] = []
    for k in keys_raw:
        if not isinstance(k, str) or k not in ALLOWED_PARAM_KEYS:
            errors.append(f"spec.param_keys: {k!r} is not in the allowed vocabulary "
                          f"({', '.join(ALLOWED_PARAM_KEYS)})")
            continue
        if k not in param_keys:
            param_keys.append(k)
    if "url" not in param_keys:
        errors.append("spec.param_keys: 'url' is mandatory (dynamic tools are "
                      "URL-addressed and scope-checked like every check)")
    if errors:
        return None, errors
    baseline = spec.get("baseline", False)
    if not isinstance(baseline, bool):
        errors.append("spec.baseline: true or false is required")
        return None, errors
    request = _validate_request(spec.get("request"), tuple(param_keys), baseline,
                                errors)
    verdict = _validate_verdict(spec.get("verdict"), request, errors)
    finding = _validate_finding(spec.get("finding"), errors)
    if request is None or verdict is None or finding is None or errors:
        return None, errors
    return DynTool(id=ident, kind=kind, title=title, description=description,
                   param_keys=tuple(param_keys), request=request, verdict=verdict,
                   finding=finding), []


# ------------------------------------------------------------- run registration

def registry_entries(tool: DynTool) -> dict[str, Any]:
    """The run-scoped registry entries for one validated instrument: the check
    itself (``dyn.<id>``) and its verifier (``verify.<id>``, which replays the
    same declarative spec with fresh probe values). The closures carry the
    validated spec; admission registers them in the run's dynamic registry and
    every resolution path (claim, verification, knowledge) reads that registry —
    static registry first, dynamic second."""
    from src.greybox_web.tools import ToolSpec, VerifyResult, dynrun

    async def _check(ctx: ToolContext) -> ToolResult:
        return await dynrun.execute(tool, ctx)

    async def _verify(ctx: ToolContext) -> VerifyResult:
        return await dynrun.replay(tool, ctx)

    return {
        tool.id: ToolSpec(tool.id, tool.kind, _check, param_keys=tool.param_keys,
                          title=tool.title),
        f"verify.{tool.id}": ToolSpec(
            f"verify.{tool.id}", "verify", _verify,
            param_keys=("finding_id", *tool.param_keys), title=tool.title),
    }


async def define(ctx: ToolContext) -> ToolResult:
    """Execution of a ``tool.define`` work order: NO requests — the definition is
    free. Admission already validated the spec and registered the instrument
    (that is when it starts existing); this records the definition as an
    observation so the run's story shows the instrument appearing. A spec that
    no longer validates here (storage capped it) still records its identity."""
    tool, _errs = validate_spec(ctx.params.get("spec"))
    raw = ctx.params.get("spec") if isinstance(ctx.params.get("spec"), dict) else {}
    ident = tool.id if tool else str(raw.get("id") or "dyn.?")
    title = tool.title if tool else str(raw.get("title") or "")
    obs = Observation(
        key=f"tool.define|{ident}"[:300],
        label=f"instrument defined: {ident} — {title}"[:300],
        facts={"id": ident, "title": title,
               "param_keys": list(tool.param_keys) if tool else [],
               "requests_made": 0},
        url=None)
    return ToolResult(summary=f"instrument defined: {ident}", counts={"defined": 1},
                      observations=[obs])
