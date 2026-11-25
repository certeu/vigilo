"""Guarded API schema inventory and response-driven pagination tools."""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from src.greybox_web.operations import extract_operations
from src.greybox_web.investigation import operation_from_mapping
from src.greybox_web.pagination import decode_embedded_cursor, response_page
from src.greybox_web.tools import Observation, ToolContext, ToolResult


def _identity(ctx: ToolContext) -> str:
    identity = str(ctx.params.get("identity") or "anon")
    labels = {item.get("label") for item in ctx.http.sessions()} | {"anon"}
    if identity not in labels:
        raise ValueError(f"unknown identity {identity!r}; known: {', '.join(sorted(labels))}")
    return identity


def _invocation_error(ctx: ToolContext, code: str, detail: str, operation_ref: Any) -> ToolResult:
    facts = {"ok": False, "error": {"code": code, "detail": detail[:500]},
             "operation_ref": str(operation_ref or "")[:160]}
    return ToolResult(summary=f"Operation not invoked: {code}", observations=[Observation(
        key=f"api.invocation.error|{facts['operation_ref']}|{code}"[:300],
        label=f"Operation invocation failed: {code}"[:300], url=ctx.base_url, facts=facts)],
        counts={"attempted": 0, "succeeded": 0})


def _resolve_operation(ctx: ToolContext) -> tuple[dict[str, Any] | None, Any]:
    """Resolve an operation carried from a persisted knowledge record.

    The supervisor may supply the full record as ``operation_ref`` or pair a stable
    reference with ``operation``. A bare unresolved id must never be guessed.
    """
    reference = ctx.params.get("operation_ref")
    candidate = reference if isinstance(reference, dict) else ctx.params.get("operation")
    if not isinstance(candidate, dict):
        return None, reference
    expected = str(reference or "").strip() if not isinstance(reference, dict) else ""
    identifiers = {str(candidate.get(key) or "").strip()
                   for key in ("id", "operation_id", "identity")}
    if expected and expected not in identifiers:
        return None, reference
    durable = operation_from_mapping(candidate)
    if durable is None:
        return None, reference
    operation = dict(candidate)
    operation["id"] = durable.id
    operation["protocol"] = durable.protocol
    operation["state_changing"] = bool(durable.state_effects)
    operation.setdefault("possible_state_effects", list(durable.state_effects))
    return operation, reference or durable.id


def _schema_error(arguments: dict[str, Any], operation: dict[str, Any]) -> str | None:
    parameters = operation.get("parameters") or []
    if isinstance(parameters, dict):
        parameters = parameters.get("items") or []
    if not isinstance(parameters, list):
        parameters = []
    locations = {str(item.get("location") or ""): item for item in parameters
                 if isinstance(item, dict)}
    missing = []
    for parameter in parameters:
        if not isinstance(parameter, dict) or not parameter.get("required"):
            continue
        name = str(parameter.get("name") or "")
        if name in arguments:
            continue
        if parameter.get("location") == "body" and any(
                key not in {"selection", "document"} and key not in locations for key in arguments):
            continue
        missing.append(name)
    if missing:
        return "missing required arguments: " + ", ".join(sorted(filter(None, missing)))
    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name") or "")
        if name not in arguments:
            continue
        schema = parameter.get("schema") or {}
        expected = schema.get("type") if isinstance(schema, dict) else None
        value = arguments[name]
        valid = (expected not in ("integer", "number") or isinstance(value, (int, float))
                 and not isinstance(value, bool)) and (expected != "boolean" or isinstance(value, bool)) \
            and (expected != "string" or isinstance(value, str)) \
            and (expected != "array" or isinstance(value, list)) \
            and (expected != "object" or isinstance(value, dict))
        if not valid:
            return f"argument {name!r} does not match schema type {expected}"
        if isinstance(schema, dict) and schema.get("enum") and value not in schema["enum"]:
            return f"argument {name!r} is outside its documented enum"
    return None


def _operation_endpoint(ctx: ToolContext, operation: dict[str, Any]) -> str | None:
    explicit = ctx.params.get("endpoint") or operation.get("endpoint")
    if explicit:
        return urljoin(ctx.base_url, str(explicit))
    source = operation.get("provenance") or {}
    source = source.get("source") if isinstance(source, dict) else ""
    protocol = operation.get("protocol")
    if protocol == "graphql" and source:
        parts = urlsplit(urljoin(ctx.base_url, str(source)))
        if parts.path.endswith(".graphql") or "schema" in parts.path.lower():
            return urlunsplit((parts.scheme, parts.netloc, "/graphql", "", ""))
    return None


def _graphql_document(operation: dict[str, Any], arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    supplied = arguments.pop("document", None)
    variables = arguments.pop("variables", None)
    selection = arguments.pop("selection", None)
    if supplied:
        return str(supplied), variables if isinstance(variables, dict) else arguments
    protocol_document = operation.get("protocol_document") or {}
    method = str(protocol_document.get("kind") or operation.get("method") or "QUERY").lower()
    kind = "mutation" if method == "mutation" else "query"
    name = str(operation.get("operation_id") or operation.get("identity") or "").strip()
    parameters = operation.get("parameters") or []
    if isinstance(parameters, dict):
        parameters = parameters.get("items") or []
    typed = {str(item.get("name")): str((item.get("schema") or {}).get("type") or "String")
             for item in parameters if isinstance(item, dict) and item.get("name")}
    typed.update({str(key): str(value) for key, value in
                  (protocol_document.get("variable_types") or {}).items()})
    variable_defs = [f"${key}: {typed.get(key, 'String')}" for key in arguments]
    call_args = [f"{key}: ${key}" for key in arguments]
    output = "".join(operation.get("output_fields") or [])
    base_type = output.replace("!", "").replace("[", "").replace("]", "")
    selection = selection or operation.get("selection")
    if selection is None:
        selection = " ".join(protocol_document.get("selection_fields") or [])
    if not selection:
        selection = "" if base_type in {"String", "Int", "Float", "Boolean", "ID"} else "__typename"
    selection_set = f" {{ {selection} }}" if str(selection).strip() else ""
    document = (f"{kind} VigiloInvoke" + (f"({', '.join(variable_defs)})" if variable_defs else "")
                + f" {{ {name}" + (f"({', '.join(call_args)})" if call_args else "")
                + selection_set + " }")
    return document, arguments


async def invoke(ctx: ToolContext) -> ToolResult:
    """Invoke one persisted REST, GraphQL or JSON-RPC operation through netguard."""
    operation, operation_ref = _resolve_operation(ctx)
    if operation is None:
        return _invocation_error(ctx, "operation_not_resolved",
                                 "supply a persisted operation record whose id matches operation_ref",
                                 operation_ref)
    arguments = ctx.params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return _invocation_error(ctx, "invalid_arguments", "arguments must be an object", operation_ref)
    arguments = dict(arguments)
    validation = _schema_error(arguments, operation)
    if validation:
        return _invocation_error(ctx, "schema_validation_failed", validation, operation_ref)
    identity = _identity(ctx)
    endpoint = _operation_endpoint(ctx, operation)
    if not endpoint:
        return _invocation_error(ctx, "endpoint_not_resolved",
                                 "operation has no executable endpoint; supply its observed endpoint",
                                 operation_ref)
    protocol = str(operation.get("protocol") or "").lower()
    state_changing = bool(operation.get("state_changing")
                          or operation.get("possible_state_effects"))
    method, url, request_body, content_type = "POST", endpoint, None, "application/json"
    if protocol == "rest":
        method = str(operation.get("method") or "GET").upper()
        parameters = operation.get("parameters") or []
        if isinstance(parameters, dict):
            parameters = parameters.get("items") or []
        query, headers, body_keys = {}, [], set()
        for parameter in parameters if isinstance(parameters, list) else []:
            if not isinstance(parameter, dict):
                continue
            name, location = str(parameter.get("name") or ""), str(parameter.get("location") or "")
            if name not in arguments:
                continue
            if location == "path":
                url = url.replace("{" + name + "}", quote(str(arguments[name]), safe=""))
            elif location == "query":
                query[name] = str(arguments[name])
            elif location == "header":
                headers.append((name, str(arguments[name])))
            elif location == "body":
                body_keys.add(name)
        if "{" in url or "}" in url:
            return _invocation_error(ctx, "schema_validation_failed",
                                     "not all documented path arguments were supplied", operation_ref)
        if query:
            parsed = urlsplit(url)
            merged = dict(parse_qsl(parsed.query, keep_blank_values=True)) | query
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(merged), parsed.fragment))
        request_body = arguments.get("body")
        if request_body is None and method in {"POST", "PUT", "PATCH", "DELETE"}:
            consumed = {str(item.get("name")) for item in parameters if isinstance(item, dict)
                        and item.get("location") != "body"}
            request_body = {key: value for key, value in arguments.items() if key not in consumed}
        if request_body is not None:
            request_body = json.dumps(request_body, separators=(",", ":"))
        response = await ctx.http.request(method, url, headers=headers, body=request_body,
                                          content_type=content_type, follow=False, session=identity,
                                          state_changing=state_changing)
    elif protocol == "graphql":
        document, variables = _graphql_document(operation, arguments)
        request_body = json.dumps({"query": document, "variables": variables}, separators=(",", ":"))
        response = await ctx.http.request("POST", url, body=request_body, content_type=content_type,
                                          follow=False, session=identity,
                                          state_changing=state_changing)
    elif protocol == "jsonrpc":
        method_name = str(operation.get("operation_id") or operation.get("identity") or "")
        request_body = json.dumps({"jsonrpc": "2.0", "id": f"vigilo-{ctx.token()}",
                                   "method": method_name, "params": arguments}, separators=(",", ":"))
        response = await ctx.http.request("POST", url, body=request_body, content_type=content_type,
                                          follow=False, session=identity,
                                          state_changing=state_changing)
    else:
        return _invocation_error(ctx, "unsupported_protocol", protocol, operation_ref)
    try:
        document = json.loads(response.text)
    except ValueError:
        document = None
    protocol_error = (document.get("errors") if protocol == "graphql" and isinstance(document, dict)
                      else document.get("error") if protocol == "jsonrpc" and isinstance(document, dict) else None)
    facts = {"ok": 200 <= response.status < 300 and not protocol_error,
             "operation_ref": str(operation.get("id") or operation_ref)[:160],
             "operation_id": str(operation.get("operation_id") or "")[:160],
             "investigation_ref": str(ctx.params.get("investigation_ref") or "")[:160],
             "protocol": protocol, "identity": identity, "state_changing": state_changing,
             "expected_effect": str(ctx.params.get("expected_effect") or "")[:300],
             "status": response.status, "protocol_error": protocol_error,
             "result_fields": sorted(document)[:50] if isinstance(document, dict) else []}
    return ToolResult(summary=(f"Invoked {protocol} operation {facts['operation_id']} as {identity}; "
                               f"HTTP {response.status}"), observations=[Observation(
        key=f"api.invocation|{facts['operation_ref']}|{identity}|{ctx.token()}"[:300],
        label=f"{protocol} operation {facts['operation_id']} as {identity}"[:300], url=url,
        exchange_ids=response.exchange_ids, facts=facts)],
        counts={"attempted": 1, "succeeded": 1 if facts["ok"] else 0})


async def inventory(ctx: ToolContext) -> ToolResult:
    url = str(ctx.params.get("url") or ctx.base_url)
    identity = _identity(ctx)
    response = await ctx.http.get(url, follow=False, session=identity)
    if response.status < 200 or response.status >= 300:
        return ToolResult(summary=f"API schema returned {response.status}", observations=[Observation(
            key=f"api.schema|{url}", label=f"API schema returned {response.status}", url=url,
            exchange_ids=response.exchange_ids, facts={"status": response.status, "operations": 0})],
            counts={"schemas": 0, "operations": 0})
    source_url = url
    exchange_ids = list(response.exchange_ids)
    operations = extract_operations(response.text[:1024 * 1024], source_url)
    if not operations:
        linked = re.findall(r"href=['\"]([^'\"]+)['\"]", response.text, flags=re.I)
        try:
            document = json.loads(response.text)
        except ValueError:
            document = {}
        if isinstance(document, dict) and isinstance(document.get("_links"), dict):
            linked.extend(value for value in document["_links"].values()
                          if isinstance(value, str))
        for link in dict.fromkeys(linked[:8]):
            candidate = urljoin(url, link)
            linked_response = await ctx.http.get(candidate, follow=False, session=identity)
            exchange_ids.extend(linked_response.exchange_ids)
            if 200 <= linked_response.status < 300:
                operations = extract_operations(linked_response.text[:1024 * 1024], candidate)
                if operations:
                    source_url = candidate
                    break
    observations = []
    for operation in operations[:500]:
        facts = operation.as_facts()
        facts["observed_as"] = identity
        facts["identities"] = sorted(
            {str(item.get("label")) for item in ctx.http.sessions() if item.get("label")}
            | {"anon"})
        facts["resources"] = [operation.endpoint] if operation.endpoint else []
        facts["evidence"] = [f"exchange:{exchange_id}" for exchange_id in exchange_ids]
        durable = operation_from_mapping(facts)
        if durable is not None:
            facts["id"] = durable.id
            facts["identity"] = operation.operation_id
        observations.append(Observation(
            key=f"api.operation|{url}|{operation.protocol}|{operation.method}|{operation.operation_id}"[:300],
            label=f"{operation.protocol} {operation.method} {operation.operation_id}"[:300],
            url=urljoin(source_url, operation.endpoint) if operation.endpoint else source_url,
            exchange_ids=exchange_ids, facts=facts))
    if not observations:
        observations.append(Observation(key=f"api.schema|{url}", label="No supported API operations found",
                                        url=url, exchange_ids=response.exchange_ids,
                                        facts={"status": response.status, "operations": 0}))
    return ToolResult(summary=f"Inventoried {len(operations)} API operations", observations=observations,
                      counts={"schemas": 1 if operations else 0, "operations": len(operations)})


def _with_cursor(url: str, key: str, cursor: str) -> str:
    parsed = urlsplit(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[key] = cursor
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


async def paginate(ctx: ToolContext) -> ToolResult:
    url = str(ctx.params.get("url") or ctx.base_url)
    identity = _identity(ctx)
    cursor_key = str(ctx.params.get("cursor_param") or "cursor")[:100]
    max_pages = max(1, min(int(ctx.params.get("max_pages") or 5), 20))
    pages, total, exchanges, decoded = 0, 0, [], []
    next_url = url
    seen = {next_url}
    stop = "page limit"
    while pages < max_pages:
        response = await ctx.http.get(next_url, follow=False, session=identity)
        exchanges.extend(response.exchange_ids)
        pages += 1
        try:
            document = json.loads(response.text)
        except ValueError:
            stop = "non-JSON response"
            break
        count, cursor, has_more = response_page(document)
        total += count
        if cursor:
            embedded = decode_embedded_cursor(cursor)
            if embedded is not None:
                decoded.append({"page": pages, "fields": sorted(embedded)[:30], "values": embedded})
        if not cursor or has_more is False:
            stop = "server indicated completion"
            break
        candidate = _with_cursor(url, cursor_key, cursor)
        if candidate in seen:
            stop = "repeated cursor"
            break
        seen.add(candidate)
        next_url = candidate
    return ToolResult(summary=f"Read {pages} pages and {total} items", observations=[Observation(
        key=f"api.pagination|{identity}|{url}"[:300], label=f"Read {pages} pages as {identity}",
        url=url, exchange_ids=exchanges[:100], facts={"identity": identity, "pages": pages,
            "items": total, "cursor_parameter": cursor_key, "decoded_cursors": decoded[:20],
            "stop_reason": stop})], counts={"pages": pages, "items": total})


async def compare_access(ctx: ToolContext) -> ToolResult:
    """Measure a documented read operation under multiple identity contexts."""
    url = str(ctx.params.get("url") or ctx.base_url)
    requested = ctx.params.get("identities")
    known = {item.get("label") for item in ctx.http.sessions()} | {"anon"}
    identities = requested if isinstance(requested, list) else sorted(known)
    identities = [str(identity) for identity in identities[:20]]
    unknown = sorted(set(identities) - known)
    if unknown:
        raise ValueError(f"unknown identities: {', '.join(unknown)}; known: {', '.join(sorted(known))}")
    matrix, exchanges = [], []
    for identity in identities:
        response = await ctx.http.get(url, follow=False, session=identity)
        exchanges.extend(response.exchange_ids)
        try:
            document = json.loads(response.text)
        except ValueError:
            document = None
        item_count, _, _ = response_page(document)
        matrix.append({"identity": identity, "status": response.status,
                       "content_type": response.content_type[:100], "items": item_count,
                       "top_level_fields": sorted(document)[:30] if isinstance(document, dict) else []})
    expected_role = str(ctx.params.get("expected_role") or "")[:100]
    facts = {"operation_id": str(ctx.params.get("operation_id") or "")[:160],
             "resource_scope": str(ctx.params.get("resource_scope") or "")[:200],
             "expected_access": ({"role": expected_role, "basis": "documented"}
                                 if expected_role else None), "matrix": matrix}
    return ToolResult(summary=f"Compared read access for {len(matrix)} identities",
                      observations=[Observation(
                          key=f"api.access|{facts['operation_id']}|{facts['resource_scope']}|{url}"[:300],
                          label=f"Access matrix for {facts['operation_id'] or url}"[:300], url=url,
                          exchange_ids=exchanges[:100], facts=facts)],
                      counts={"identities": len(matrix), "served": sum(
                          1 for item in matrix if 200 <= item["status"] < 300)})
