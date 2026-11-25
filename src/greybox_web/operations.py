"""Pure API operation extraction for OpenAPI, OpenRPC and GraphQL schemas."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ApiOperation:
    protocol: str
    operation_id: str
    endpoint: str
    method: str
    parameters: tuple[dict[str, Any], ...] = ()
    input_fields: tuple[str, ...] = ()
    output_fields: tuple[str, ...] = ()
    documented_roles: tuple[str, ...] = ()
    documented_security: tuple[str, ...] = ()
    possible_state_effects: tuple[str, ...] = ()
    protocol_document: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def state_changing(self) -> bool:
        return bool(self.possible_state_effects)

    def as_facts(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol, "operation_id": self.operation_id,
            "endpoint": self.endpoint, "method": self.method,
            "parameters": list(self.parameters), "input_fields": list(self.input_fields),
            "output_fields": list(self.output_fields), "documented_roles": list(self.documented_roles),
            "documented_security": list(self.documented_security),
            "possible_state_effects": list(self.possible_state_effects), "provenance": self.provenance,
            "state_changing": self.state_changing,
            "protocol_document": self.protocol_document,
        }


_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
_STATE_METHODS = {"post", "put", "patch", "delete"}
_REF = "#/components/schemas/"


def _schema_fields(schema: Any, schemas: dict[str, Any], seen: frozenset[str] = frozenset()) -> tuple[str, ...]:
    if not isinstance(schema, dict):
        return ()
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith(_REF) and ref not in seen:
        return _schema_fields(schemas.get(ref[len(_REF):]), schemas, seen | {ref})
    fields = set(str(key)[:100] for key in (schema.get("properties") or {}) if isinstance(key, str))
    fields.update(_schema_fields(schema.get("items"), schemas, seen))
    for key in ("allOf", "anyOf", "oneOf"):
        for nested in schema.get(key) or []:
            fields.update(_schema_fields(nested, schemas, seen))
    return tuple(sorted(fields))[:100]


def _security_names(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(sorted({str(key)[:100] for requirement in value if isinstance(requirement, dict)
                         for key in requirement}))


def _documented_roles(operation: dict[str, Any]) -> tuple[str, ...]:
    roles: set[str] = set()
    for key, value in operation.items():
        if key.lower() in ("x-required-role", "x-required-roles", "x-roles", "x-role"):
            if isinstance(value, str):
                roles.add(value[:100])
            elif isinstance(value, list):
                roles.update(str(item)[:100] for item in value)
    return tuple(sorted(roles))


def _state_effects(operation: dict[str, Any], *, default: str | None) -> tuple[str, ...]:
    """Apply explicit schema semantics, otherwise classify conservatively."""
    if operation.get("x-vigilo-read-only") is True or operation.get("x-read-only") is True:
        return ()
    declared = operation.get("x-state-changing")
    if declared is False:
        return ()
    if isinstance(declared, str) and declared.strip():
        return (declared.strip()[:160],)
    if declared is True:
        return (default or "declared state change",)
    effects = operation.get("x-state-effects") or operation.get("x-effects")
    if isinstance(effects, str) and effects.strip():
        return (effects.strip()[:160],)
    if isinstance(effects, list):
        values = tuple(dict.fromkeys(str(item).strip()[:160] for item in effects if str(item).strip()))
        if values:
            return values[:20]
    return (default,) if default else ()


def extract_openapi(document: dict[str, Any], source: str) -> list[ApiOperation]:
    schemas = document.get("components", {}).get("schemas", {})
    root_security = _security_names(document.get("security"))
    result = []
    for path, path_item in (document.get("paths") or {}).items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        common = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
        for method in _METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            raw_params = [*common, *(operation.get("parameters") or [])]
            params = tuple({"name": str(item.get("name", ""))[:100], "location": str(item.get("in", ""))[:30],
                            "required": bool(item.get("required")), "schema": item.get("schema", {})}
                           for item in raw_params if isinstance(item, dict) and item.get("name"))
            inputs = set(param["name"] for param in params)
            request_body = operation.get("requestBody") or {}
            content = request_body.get("content", {})
            for media in content.values() if isinstance(content, dict) else ():
                if isinstance(media, dict):
                    inputs.update(_schema_fields(media.get("schema"), schemas))
            if isinstance(content, dict) and content:
                params += ({"name": "body", "location": "body",
                            "required": bool(request_body.get("required")),
                            "schema": next((media.get("schema", {}) for media in content.values()
                                            if isinstance(media, dict)), {})},)
            outputs: set[str] = set()
            for response in (operation.get("responses") or {}).values():
                response_content = response.get("content", {}) if isinstance(response, dict) else {}
                for media in response_content.values() if isinstance(response_content, dict) else ():
                    if isinstance(media, dict):
                        outputs.update(_schema_fields(media.get("schema"), schemas))
            result.append(ApiOperation(
                protocol="openapi", operation_id=str(operation.get("operationId") or f"{method.upper()} {path}")[:160],
                endpoint=path, method=method.upper(), parameters=params,
                input_fields=tuple(sorted(inputs))[:100], output_fields=tuple(sorted(outputs))[:100],
                documented_roles=_documented_roles(operation),
                documented_security=_security_names(operation.get("security")) if "security" in operation else root_security,
                possible_state_effects=_state_effects(
                    operation, default="unspecified write" if method in _STATE_METHODS else None),
                protocol_document={"method": method.upper(), "path": path,
                                   "parameter_locations": {item["name"]: item["location"] for item in params}},
                provenance={"source": source, "documented": True,
                            "content_types": list(content)[:20] if isinstance(content, dict) else []}))
    return result


def extract_openrpc(document: dict[str, Any], source: str) -> list[ApiOperation]:
    result = []
    for method in document.get("methods") or []:
        if not isinstance(method, dict) or not isinstance(method.get("name"), str):
            continue
        params = tuple({"name": str(item.get("name", ""))[:100], "location": "params",
                        "required": bool(item.get("required", False)), "schema": item.get("schema", {})}
                       for item in method.get("params") or [] if isinstance(item, dict))
        name = method["name"][:160]
        is_read = bool(re.match(r"(?i)^(get|list|read|search|find|query)(?:[._-]|$)", name))
        result.append(ApiOperation(
            protocol="json-rpc", operation_id=name, endpoint="", method="CALL", parameters=params,
            input_fields=tuple(param["name"] for param in params if param["name"]),
            documented_roles=_documented_roles(method), documented_security=_security_names(method.get("security")),
            possible_state_effects=_state_effects(method, default=None if is_read else "unspecified RPC effect"),
            protocol_document={"jsonrpc": "2.0", "method": name,
                               "endpoint": next((item.get("url") for item in document.get("servers") or []
                                                 if isinstance(item, dict) and item.get("url")), "")},
            provenance={"source": source, "documented": True}))
    return result


_GQL_TYPE = re.compile(r"(?s)\btype\s+(Query|Mutation)\b[^\{]*\{(.*?)\}")
_GQL_FIELD = re.compile(r"(?s)([A-Za-z_]\w*)\s*(?:\((.*?)\))?\s*:\s*([!\[\]A-Za-z_][!\[\]A-Za-z_0-9]*)(.*?)(?=(?:,\s*|\s+)[A-Za-z_]\w*\s*(?:\([^)]*\))?\s*:|$)")
_GQL_ARG = re.compile(r"([A-Za-z_]\w*)\s*:\s*([^,)=]+)(?:=[^,)]+)?")
_GQL_OBJECT = re.compile(r"(?s)\btype\s+([A-Za-z_]\w*)\b[^\{]*\{(.*?)\}")
_GQL_OBJECT_FIELD = re.compile(r"(?:^|\s)([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:")


def _graphql_endpoint(source: str) -> str:
    path = urlsplit(source).path if source else ""
    if path.endswith(".graphql") or "schema" in path.lower() or not path.rstrip("/").endswith("graphql"):
        return "/graphql"
    return path


_GQL_ROLE = re.compile(r"@(?:requiresRole|auth|authorize)\s*\([^)]*?(?:role|roles)\s*:\s*(?:\[)?\s*\"?([A-Za-z0-9_.:-]+)", re.I)


def extract_graphql_sdl(text: str, source: str) -> list[ApiOperation]:
    result = []
    clean = re.sub(r'""".*?"""', "", text, flags=re.S)
    object_fields = {name: tuple(dict.fromkeys(_GQL_OBJECT_FIELD.findall(body)))[:50]
                     for name, body in _GQL_OBJECT.findall(clean)}
    for root, body in _GQL_TYPE.findall(clean):
        for field_name, raw_args, output, directives in _GQL_FIELD.findall(body):
            params = tuple({"name": name, "location": "argument", "required": "!" in kind,
                            "schema": {"type": kind.strip()}} for name, kind in _GQL_ARG.findall(raw_args or ""))
            result.append(ApiOperation(
                protocol="graphql", operation_id=field_name, endpoint=_graphql_endpoint(source), method=root.upper(), parameters=params,
                input_fields=tuple(param["name"] for param in params), output_fields=(output,),
                documented_roles=tuple(sorted(set(_GQL_ROLE.findall(directives)))),
                possible_state_effects=("unspecified mutation effect",) if root == "Mutation" else (),
                protocol_document={"kind": root.lower(), "field": field_name,
                                   "variable_types": {item["name"]: item["schema"]["type"] for item in params},
                                   "selection_fields": list(object_fields.get(
                                       output.replace("!", "").replace("[", "").replace("]", ""), ()))},
                provenance={"source": source, "documented": True}))
    return result


def extract_operations(body: str, source: str = "") -> list[ApiOperation]:
    try:
        document = json.loads(body)
    except (TypeError, ValueError):
        document = None
    if isinstance(document, dict) and (document.get("openapi") or document.get("swagger")):
        return extract_openapi(document, source)
    if isinstance(document, dict) and document.get("openrpc"):
        return extract_openrpc(document, source)
    return extract_graphql_sdl(body, source)
