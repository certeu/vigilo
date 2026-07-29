#!/usr/bin/env python3
"""
graph-tool — Agent-callable CLI for knowledge graph interaction.

Usage:
    graph-tool query --type endpoint --filter "injectable=untested"
    graph-tool test-attempt --target "parameter:q" --vuln-type sqli ...
    graph-tool finding --target "parameter:q" --vuln-type sqli --severity high ...
    graph-tool signal --type credentials_found --data '{...}'

Output: JSON to stdout
    {"status": "success", "data": [...], "count": 5}
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="graph-tool",
        description="Knowledge graph CLI for grey-box agents",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # query
    q = sub.add_parser("query")
    q.add_argument("--type", required=True)
    q.add_argument("--filter", default=None)
    q.add_argument("--limit", type=int, default=None)

    # add
    a = sub.add_parser("add")
    a.add_argument("--type", required=True)
    a.add_argument("--id", required=True)
    a.add_argument("--data", required=True)
    a.add_argument("--parent", default=None,
                   help='Parent node ID — auto-creates structural edge '
                        '(has_param for parameter, has_endpoint for endpoint, '
                        'detected_on for technology, belongs_to for component assignment)')

    # update
    u = sub.add_parser("update")
    u.add_argument("--id", required=True)
    u.add_argument("--set", required=True, dest="set_expr")

    # test-attempt
    ta = sub.add_parser("test-attempt")
    ta.add_argument("--target", required=True)
    ta.add_argument("--vuln-type", required=True)
    ta.add_argument("--technique", required=True)
    ta.add_argument("--payload", required=True)
    ta.add_argument("--verdict", required=True,
                    choices=["conclusive_vulnerable", "conclusive_clean",
                             "inconclusive", "failed"])
    ta.add_argument("--failure-reason", default=None,
                    dest="failure_reason",
                    help="Required when --verdict=failed.")
    ta.add_argument("--response-code", type=int, default=0)
    ta.add_argument("--response-excerpt", default=None)
    ta.add_argument("--error-class", default=None)

    # finding
    f = sub.add_parser("finding")
    f.add_argument("--target", required=True)
    f.add_argument("--vuln-type", required=True)
    f.add_argument("--severity", required=True,
                   choices=["critical", "high", "medium", "low", "info"])
    f.add_argument("--cwe", default=None)
    f.add_argument("--title", required=True)
    f.add_argument("--poc-payload", default=None)
    f.add_argument("--impact", required=True)
    f.add_argument("--grants", default="[]")
    f.add_argument("--requires", default="[]")
    f.add_argument("--evidence-file", default=None)
    f.add_argument("--derived-from", default=None, dest="derived_from",
                   help='test_attempt ID that produced this finding')
    f.add_argument("--detection-hints", default=None, dest="detection_hints",
                   help='JSON object with detection-engineering hints. '
                        'Recognised keys: waf_rule, log_signature, siem_query, '
                        'network_indicator. Example: '
                        '\'{"waf_rule":"SecRule ARGS \\"@rx select.+from\\" ...",'
                        '"siem_query":"index=app sourcetype=access /api/search.*UNION"}\'')

    # lead
    le = sub.add_parser("lead")
    le.add_argument("--target", required=True)
    le.add_argument("--signal", required=True)
    le.add_argument("--hypothesis", required=True)
    le.add_argument("--signal-strength", default="medium",
                    choices=["low", "medium", "high"])
    le.add_argument("--hints", default="[]")
    le.add_argument("--evidence-blob", default=None, dest="evidence_blob",
                    help="Path to JSON evidence blob (HTTP exchange, response excerpt).")
    le.add_argument("--produced-from", default=None, dest="produced_from",
                    help='test_attempt ID that produced the signal, e.g. "test_attempt:ta1"')

    # access
    ac = sub.add_parser("access")
    ac.add_argument("--identity", required=True)
    ac.add_argument("--endpoint", required=True)
    ac.add_argument("--result", required=True, choices=["allow", "deny"])
    ac.add_argument("--status-code", type=int, required=True)

    # claim
    cl = sub.add_parser("claim")
    cl.add_argument("--id", required=True)
    cl.add_argument("--agent", required=True)
    cl.add_argument("--ttl", type=int, default=300)

    # release
    rl = sub.add_parser("release")
    rl.add_argument("--id", required=True)
    rl.add_argument("--agent", required=True)

    # signal
    sg = sub.add_parser("signal")
    sg.add_argument("--type", required=True)
    sg.add_argument("--data", required=True)

    # relate
    re_ = sub.add_parser("relate")
    re_.add_argument("--from", required=True, dest="from_id")
    re_.add_argument("--to", required=True, dest="to_id")
    re_.add_argument("--type", required=True, dest="edge_type")
    re_.add_argument("--data", default=None)

    # reflects-in (parameter → endpoint reflection observed during crawl)
    ri = sub.add_parser("reflects-in")
    ri.add_argument("--from", required=True, dest="from_id",
                    help='Parameter ID, e.g. "parameter:p1"')
    ri.add_argument("--to", required=True, dest="to_id",
                    help='Endpoint ID, e.g. "endpoint:e1"')
    ri.add_argument("--context", required=True,
                    choices=["html_body", "attribute", "js_string", "json_value",
                             "header", "url"])

    # raw
    rw = sub.add_parser("raw")
    rw.add_argument("--query", required=True)

    # export
    ex = sub.add_parser("export")
    ex.add_argument("--format", default="yaml", choices=["yaml", "json"])
    ex.add_argument("--max-tokens", type=int, default=15000)

    return parser


_PARENT_EDGE_MAP: dict[str, tuple[str, list[str]]] = {
    "parameter": ("has_param", ["endpoint"]),
    "endpoint": ("has_endpoint", ["page"]),
    "technology": ("detected_on", ["endpoint", "page"]),
    "component": ("belongs_to", ["endpoint", "page"]),
}


def _create_parent_edge(
    client, node_type: str, node_id: str, parent: str,
) -> tuple[str, str, str] | None:
    """Return (edge_type, from_id, to_id) for a parent edge, or None on error."""
    spec = _PARENT_EDGE_MAP.get(node_type)
    if not spec:
        return None
    edge_type, valid_parents = spec
    parent_type = parent.split(":")[0] if ":" in parent else ""
    if parent_type not in valid_parents:
        return None
    if edge_type == "detected_on":
        return (edge_type, node_id, parent)
    return (edge_type, parent, node_id)


async def _verify_target_exists(client, node_id: str, subcommand: str) -> None:
    """Verify the target node exists in the graph, or exit with an error.

    Used by subcommands that write edges referencing an existing node
    (currently `finding` and `test-attempt`) to prevent silent orphan
    rows from hallucinated or typo'd node IDs.

    Runs `SELECT 1 FROM type::thing($tgt)` via the SurrealDB client with
    parameterized input (never string interpolation). If the result is
    empty, prints a helpful error to stderr and calls sys.exit(1).
    """
    rows = await client.raw_query(
        "SELECT 1 FROM type::thing($tgt)",
        {"tgt": node_id},
    )
    if not rows:
        sys.stderr.write(
            f"graph-tool {subcommand}: target node {node_id!r} "
            f"does not exist in graph\n"
        )
        sys.exit(1)


def _coerce_value(v: str) -> str | int | float | bool:
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def parse_filter_string(filter_str: str) -> dict[str, str | int | float | bool]:
    """Parse 'key=value,key2=value2' into a dict with type coercion."""
    result: dict[str, str | int | float | bool] = {}
    for pair in filter_str.split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = _coerce_value(v.strip())
    return result


def _output(status: str, **kwargs) -> None:
    print(json.dumps({"status": status, **kwargs}, default=str))


def _str_id(value: object) -> str:
    """Normalize a SurrealDB RecordID (or plain string) to ``table:id`` form."""
    if isinstance(value, str):
        return value
    try:
        return f"{value.table}:{value.id}"
    except AttributeError:
        return str(value)


async def _run(args: argparse.Namespace) -> None:
    """Execute the graph-tool command against SurrealDB."""
    from src.greybox.graph.client import GraphClient
    from src.greybox.graph.schema import NODE_TYPE_MAP

    url = os.environ.get("SURREALDB_URL", "ws://surrealdb:8000")
    user = os.environ.get("SURREALDB_USER", "root")
    password = os.environ.get("SURREALDB_PASS", "changeme")
    session = os.environ.get("SURREALDB_SESSION", "default")

    async with GraphClient(url, session, user, password) as client:
        if args.command == "query":
            filters = parse_filter_string(args.filter) if args.filter else None
            results = await client.query_nodes(
                args.type, filters=filters, limit=args.limit,
            )
            _output("success", data=results, count=len(results))

        elif args.command == "raw":
            results = await client.raw_query(args.query)
            _output("success", data=results, count=len(results))

        elif args.command == "add":
            data = json.loads(args.data)
            model_cls = NODE_TYPE_MAP.get(args.type)
            if not model_cls:
                _output("error", message=f"Unknown node type: {args.type}")
                return
            node = model_cls(**data)
            result = await client.create_node(args.type, args.id, node)
            node_id = _str_id(result.get("id", ""))
            if args.parent and node_id:
                edge = _create_parent_edge(client, args.type, node_id, args.parent)
                if edge is None and args.type in _PARENT_EDGE_MAP:
                    parent_type = args.parent.split(":")[0] if ":" in args.parent else ""
                    valid = _PARENT_EDGE_MAP[args.type][1]
                    _output("error", message=f"Invalid parent type '{parent_type}' for {args.type} (expected {valid})")
                    return
                if edge:
                    await client.create_edge(*edge)
            _output("success", message="Node created", id=node_id)

        elif args.command == "test-attempt":
            from src.greybox.graph.schema import TestAttemptNode
            await _verify_target_exists(client, args.target, "test-attempt")
            agent = os.environ.get("VIGILO_AGENT_NAME", "unknown")
            node = TestAttemptNode(
                vuln_type=args.vuln_type,
                technique=args.technique,
                payload=args.payload,
                verdict=args.verdict,
                failure_reason=args.failure_reason,
                response_code=args.response_code,
                response_excerpt=args.response_excerpt,
                error_class=args.error_class,
                agent=agent,
            )
            result = await client.create_node("test_attempt", f"ta_{uuid.uuid4().hex[:12]}", node)
            ta_id = _str_id(result.get("id", ""))
            await client.create_edge("tested_against", ta_id, args.target)
            _output("success", message="Test attempt recorded", id=ta_id)

        elif args.command == "finding":
            from src.greybox.graph.schema import FindingNode
            await _verify_target_exists(client, args.target, "finding")
            agent = os.environ.get("VIGILO_AGENT_NAME", "unknown")

            existing = await client.raw_query(
                "SELECT id, severity, title FROM finding "
                "WHERE vuln_type = $vuln AND ->exploits.id CONTAINS $target",
                {"vuln": args.vuln_type, "target": args.target},
            )
            if existing:
                dup_id = _str_id(existing[0].get("id", ""))
                _output(
                    "success",
                    message="Duplicate finding — returning existing",
                    id=dup_id,
                    deduplicated=True,
                )
                return

            detection_hints = None
            if args.detection_hints:
                try:
                    parsed_hints = json.loads(args.detection_hints)
                except json.JSONDecodeError as exc:
                    _output("error", message=f"--detection-hints is not valid JSON: {exc}")
                    return
                if not isinstance(parsed_hints, dict):
                    _output("error", message="--detection-hints must be a JSON object")
                    return
                # Coerce all values to strings so the SurrealDB option<object>
                # field stays homogeneous.
                detection_hints = {str(k): str(v) for k, v in parsed_hints.items() if v}
            node = FindingNode(
                title=args.title,
                vuln_type=args.vuln_type,
                severity=args.severity,
                cwe_id=args.cwe,
                poc_payload=args.poc_payload,
                impact=args.impact,
                grants=json.loads(args.grants),
                requires=json.loads(args.requires),
                evidence_ref=args.evidence_file,
                detection_hints=detection_hints,
                discovered_by=agent,
            )
            if args.derived_from:
                await _verify_target_exists(client, args.derived_from, "finding")
            result = await client.create_node("finding", f"F_{uuid.uuid4().hex[:12]}", node)
            f_id = _str_id(result.get("id", ""))
            await client.create_edge("exploits", f_id, args.target)
            if args.derived_from:
                await client.create_edge("derived_from", f_id, args.derived_from)
            _output("success", message="Finding recorded", id=f_id)

        elif args.command == "lead":
            from src.greybox.graph.schema import LeadNode
            await _verify_target_exists(client, args.target, "lead")
            if args.produced_from:
                await _verify_target_exists(client, args.produced_from, "lead")
            agent = os.environ.get("VIGILO_AGENT_NAME", "unknown")
            node = LeadNode(
                signal=args.signal,
                hypothesis=args.hypothesis,
                signal_strength=args.signal_strength,
                investigation_hints=json.loads(args.hints),
                evidence_blob_path=args.evidence_blob,
                discovered_by=agent,
            )
            result = await client.create_node("lead", f"L_{uuid.uuid4().hex[:12]}", node)
            l_id = _str_id(result.get("id", ""))
            await client.create_edge("observed_at", l_id, args.target)
            if args.produced_from:
                await client.create_edge("produced_from", l_id, args.produced_from)
            _output("success", message="Lead recorded", id=l_id)

        elif args.command == "access":
            from src.greybox.graph.ids import canonicalize_id
            edge_type = "can_access" if args.result == "allow" else "denied_access"
            identity_id = f"identity:{args.identity}"
            endpoint_id = canonicalize_id("endpoint", args.endpoint)
            await _verify_target_exists(client, identity_id, "access")
            await _verify_target_exists(client, endpoint_id, "access")
            await client.create_edge(
                edge_type, identity_id, endpoint_id,
                properties={"status_code": args.status_code},
            )
            _output("success", message=f"Access recorded: {edge_type}")

        elif args.command == "claim":
            await _verify_target_exists(client, args.id, "claim")
            acquired = await client.claim_node(args.id, args.agent, args.ttl)
            if acquired:
                _output("success", message="Claim acquired")
            else:
                _output("error", message="Claim held by another agent",
                        retryable=True)

        elif args.command == "release":
            await _verify_target_exists(client, args.id, "release")
            await client.release_claim(args.id, args.agent)
            _output("success", message="Claim released")

        elif args.command == "relate":
            await _verify_target_exists(client, args.from_id, "relate")
            await _verify_target_exists(client, args.to_id, "relate")
            props = json.loads(args.data) if args.data else None
            await client.create_edge(
                args.edge_type, args.from_id, args.to_id, properties=props,
            )
            _output("success", message="Relation created")

        elif args.command == "reflects-in":
            await _verify_target_exists(client, args.from_id, "reflects-in")
            await _verify_target_exists(client, args.to_id, "reflects-in")
            await client.create_edge(
                "reflects_in", args.from_id, args.to_id,
                properties={"context": args.context},
            )
            _output("success", message="Reflection recorded")

        elif args.command == "signal":
            data = json.loads(args.data)
            if args.type == "credentials_found":
                signal_dir = os.path.join(os.getcwd(), "deliverables", ".signals")
                os.makedirs(signal_dir, exist_ok=True)
                signal_path = os.path.join(signal_dir, f"{uuid.uuid4()}.json")
                with open(signal_path, "w") as fp:
                    json.dump({"type": args.type, "data": data}, fp)
                _output("success", message="Urgent signal written")
            else:
                _output("success", message=f"Signal {args.type} noted (no-op)")

        elif args.command == "export":
            all_data: dict[str, list] = {}
            node_tables = [
                "page", "endpoint", "parameter", "technology",
                "identity", "workflow", "component",
                "test_attempt", "finding", "lead",
            ]
            edge_tables = [
                "has_param", "has_endpoint", "belongs_to", "detected_on",
                "links_to", "has_step", "depends_on", "param_depends_on",
                "tested_against", "exploits", "observed_at", "promoted_to",
                "derived_from", "supersedes", "can_access", "denied_access",
                "chains_with", "reflects_in", "produced_from", "data_flows_to",
                "input_of",
            ]
            for table in node_tables:
                all_data[table] = await client.raw_query(
                    f"SELECT * FROM {table}"
                )
            edges: dict[str, list] = {}
            for table in edge_tables:
                rows = await client.raw_query(f"SELECT * FROM {table}")
                if rows:
                    edges[table] = rows
            if edges:
                all_data["_edges"] = edges
            if args.format == "yaml":
                import yaml as yaml_mod
                output = yaml_mod.dump(all_data, default_flow_style=False)
            else:
                output = json.dumps(all_data, indent=2, default=str)
            if len(output) > args.max_tokens * 4:
                output = output[: args.max_tokens * 4]
            print(output)
            return

        elif args.command == "update":
            await _verify_target_exists(client, args.id, "update")
            pairs = parse_filter_string(args.set_expr)
            await client.update_node(args.id, pairs)
            _output("success", message="Node updated")

        else:
            _output("error", message=f"Unknown command: {args.command}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(_run(args))
    except Exception as e:
        _output("error", message=str(e), retryable=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
