"""The capability broker for agent-written tools.

A generated tool runs in a sandbox with **no network, no filesystem and no
processes** (``sandbox.py``: OS isolation first, interpreter narrowing second). It
still needs to *act*: request a related API object under two identities, follow a
pagination cursor, read a banner on the next port, look at what the run recorded.
It does that by asking the broker, over its stdin/stdout, and the broker performs
the call **in the engine**, with the engine's controls:

======== ============================== =======================================
op       capability                     enforced by
======== ============================== =======================================
http     ``http``                       guarded client: scope per hop, IP policy,
                                        activity policy, budgets, sessions, audit
tcp      ``tcp_connect``                ``netcap.GuardedNet``: network scope,
                                        inert payloads, rate, audit
dns      ``dns``                        ``netcap.GuardedNet``
recorded ``recorded``                   read-only view of the run's own traffic
sessions ``http``                       identity labels + cookie NAMES only
inventory ``inventory``                 operator-supplied documents (read-only)
======== ============================== =======================================

Three gates apply to every call, in order: the op's capability must be **declared
by the tool** (its spec), **allowed by the run** (mode + operator), and the call
must pass the protocol guard above. Per-execution quotas bound the number of calls
and the size of what flows back. Every call is appended to :attr:`Broker.calls` —
the audit trail stored with the tool's result.

The broker never returns a credential: session cookies are attached by the guard
on the way out and are never part of a response handed to the tool (the guard's
recorded request headers are not returned; response ``Set-Cookie`` values are
reduced to names).
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from src.greybox_web import modes

OPS: dict[str, str] = {
    "http": modes.HTTP,
    "tcp": modes.TCP_CONNECT,
    "dns": modes.DNS,
    "recorded": modes.RECORDED,
    "sessions": modes.HTTP,
    "inventory": modes.INVENTORY,
}
DEFAULT_MAX_CALLS = 40
MAX_CALLS_CAP = 120
BODY_TO_TOOL = 100_000
MAX_HEADERS = 30


class BrokerRefusal(Exception):
    """A call the broker refuses: reported to the tool as an error it can read."""


def _clean_headers(raw: Any) -> list[tuple[str, str]]:
    items: list = []
    if isinstance(raw, Mapping):
        items = list(raw.items())
    elif isinstance(raw, list):
        items = [tuple(h) for h in raw if isinstance(h, (list, tuple)) and len(h) == 2]
    out = []
    for k, v in items[:MAX_HEADERS]:
        k, v = str(k)[:100], str(v)[:2000]
        if "\n" in k or "\r" in k or "\n" in v or "\r" in v:
            raise BrokerRefusal("header names/values must not contain newlines")
        out.append((k, v))
    return out


def _response_for_tool(resp) -> dict[str, Any]:
    headers = []
    for k, v in resp.headers:
        if k.lower() == "set-cookie":
            v = v.split("=", 1)[0].strip() + "=<redacted>"
        headers.append([k, v])
    text = resp.text
    return {"status": resp.status, "url": resp.url, "headers": headers,
            "body": text[:BODY_TO_TOOL],
            "truncated": bool(resp.truncated) or len(text) > BODY_TO_TOOL,
            "exchange_id": resp.exchange_id, "redirects": list(resp.hops or ()),
            "blocked": getattr(resp, "redirect_blocked", None)}


_WRITE_METHOD = re.compile(r"(?i)(?:create|update|delete|remove|set|put|patch|approve|cancel|share|unshare|grant|revoke|transfer|upload|send|reset|rotate|publish|archive)")


def _operation_markers(body: Any) -> list[str]:
    if not isinstance(body, str):
        return []
    try:
        doc = json.loads(body)
    except ValueError:
        doc = {}
    out: set[str] = set()
    for holder in ((doc.get("variables") or {}) if isinstance(doc, dict) else {},
                   (doc.get("params") or {}) if isinstance(doc, dict) else {}):
        if isinstance(holder, dict):
            for key, value in holder.items():
                if isinstance(value, (str, int)) and (key.lower() == "id" or
                        key.lower().endswith("id")):
                    out.add(str(value)[:200])
    query = doc.get("query") if isinstance(doc, dict) else None
    if isinstance(query, str):
        out.update(re.findall(r'''(?i)\b(?:[a-z]+Id|id)\s*:\s*["']([^"']{1,200})''', query))
    return sorted(out)[:20]


def _structured_write(method: str, body: Any) -> bool:
    if method != "POST" or not isinstance(body, str):
        return False
    try:
        doc = json.loads(body)
    except ValueError:
        return False
    if not isinstance(doc, dict):
        return False
    query = doc.get("query")
    if isinstance(query, str) and re.match(r"(?is)^\s*(?:#[^\n]*\n\s*)*mutation\b", query):
        return True
    rpc_method = doc.get("method")
    return isinstance(rpc_method, str) and bool(_WRITE_METHOD.search(rpc_method))


class Broker:
    """Serves one execution of one generated tool."""

    def __init__(self, ctx, *, declared: set[str], allowed: set[str],
                 max_calls: int = DEFAULT_MAX_CALLS, inventory: Any = None) -> None:
        self.ctx = ctx
        self.declared = set(declared)
        self.allowed = set(allowed)
        self.max_calls = max(1, min(int(max_calls), MAX_CALLS_CAP))
        self.inventory = inventory          # callable(name|None) -> list/doc, or None
        self.calls: list[dict[str, Any]] = []
        self.exchange_ids: list[int] = []
        self.replays: dict[int, dict[str, Any]] = {}

    def _gate(self, op: str) -> None:
        cap = OPS.get(op)
        if cap is None:
            raise BrokerRefusal(f"unknown broker operation {op!r}; available: "
                                f"{', '.join(sorted(OPS))}")
        if cap not in self.declared:
            raise BrokerRefusal(f"{op} needs the {cap!r} capability, which this tool "
                                f"did not declare (spec.capabilities)")
        if cap not in self.allowed:
            raise BrokerRefusal(f"{op} needs the {cap!r} capability, which this "
                                f"assessment does not authorise")
        if len(self.calls) >= self.max_calls:
            raise BrokerRefusal(f"broker call quota reached ({self.max_calls})")

    async def handle(self, request: Any) -> dict[str, Any]:
        """One request from the tool -> one reply. Never raises for a refusal or a
        target-side failure (the tool reads the error); a cancelled run or an
        exhausted budget propagates and ends the execution."""
        from src.greybox_web.netguard import (
            BudgetExhausted,
            RunCancelled,
            ScopeViolation,
            TransportFailure,
        )
        op = str((request or {}).get("op") or "") if isinstance(request, dict) else ""
        args = request.get("args") if isinstance(request, dict) else None
        args = args if isinstance(args, dict) else {}
        entry: dict[str, Any] = {"op": op, "target": None, "outcome": "ok"}
        if op == "http":
            method = str(args.get("method") or "GET").upper()
            entry.update(target=f"{method} {str(args.get('url') or '')}"[:300],
                         method=method,
                         state_changing=(method in ("PUT", "PATCH", "DELETE")
                                         or bool(args.get("state_changing"))
                                         or _structured_write(method,
                                             args.get("body") or (json.dumps(args["json"])
                                             if args.get("json") is not None else None))))
        try:
            self._gate(op)
            result = await getattr(self, f"_op_{op}")(args, entry)
            self.calls.append(entry)
            return {"ok": True, "result": result}
        except (BudgetExhausted, RunCancelled):
            raise
        except BrokerRefusal as exc:
            entry.update(outcome="refused", error=str(exc)[:300])
        except ScopeViolation as exc:
            entry.update(outcome="blocked", error=f"blocked: {exc.reason}")
            if exc.exchange_id is not None:
                self.exchange_ids.append(exc.exchange_id)
        except TransportFailure as exc:
            entry.update(outcome="failed", error=f"transport: {exc.kind}")
        except (ValueError, TypeError) as exc:
            entry.update(outcome="refused", error=f"{type(exc).__name__}: {exc}"[:300])
        self.calls.append(entry)
        return {"ok": False, "error": entry["error"]}

    # ------------------------------------------------------------------ ops
    async def _op_http(self, a: dict, entry: dict) -> dict:
        url = str(a.get("url") or "")
        method = str(a.get("method") or "GET").upper()
        entry["target"] = f"{method} {url}"[:300]
        entry["method"] = method
        body = a.get("body")
        content_type = a.get("content_type")
        if a.get("json") is not None:
            body = json.dumps(a["json"])
            content_type = content_type or "application/json"
        entry["resource_markers"] = _operation_markers(body)
        entry["state_changing"] = (method in ("PUT", "PATCH", "DELETE")
                                   or bool(a.get("state_changing"))
                                   or _structured_write(method, body))
        if body is not None and not isinstance(body, str):
            raise BrokerRefusal("body must be a string (or use json=...)")
        session = a.get("session")
        if isinstance(session, dict) and isinstance(session.get("label"), str):
            # a record from ctx.broker.sessions(): the identity is its label
            session = session["label"]
        if session is not None and not isinstance(session, str):
            raise BrokerRefusal("session must be a label string, 'anon', or a "
                                "record from ctx.broker.sessions()")
        entry["identity"] = session or "provided-cookie"
        entry["request_fingerprint"] = hashlib.sha256(
            f"{method}\n{url}\n{body or ''}\n{entry['identity']}".encode(
                "utf-8", "replace")).hexdigest()
        resp = await self.ctx.http.request(
            method, url, headers=_clean_headers(a.get("headers")), body=body,
            content_type=str(content_type)[:100] if content_type else None,
            follow=bool(a.get("follow", True)), session=session,
            state_changing=bool(entry["state_changing"]))
        self.exchange_ids.extend(i for i in (resp.exchange_ids or []) if i is not None)
        entry["status"] = resp.status
        entry["exchange_id"] = resp.exchange_id
        entry["response_resource_markers"] = _operation_markers(resp.text)
        entry["response_fingerprint"] = hashlib.sha256(
            f"{resp.status}\n{resp.text}".encode("utf-8", "replace")).hexdigest()
        try:
            response_doc = json.loads(resp.text)
        except ValueError:
            response_doc = {}
        entry["application_error"] = bool(
            isinstance(response_doc, dict) and
            (response_doc.get("errors") or response_doc.get("error")))
        if resp.exchange_id is not None:
            self.replays[resp.exchange_id] = {
                "url": url, "method": method, "body": body,
                "content_type": content_type, "follow": bool(a.get("follow", True)),
                "session": session,
                "expected_fingerprint": entry["response_fingerprint"],
            }
        return _response_for_tool(resp)

    async def _op_tcp(self, a: dict, entry: dict) -> dict:
        if self.ctx.net is None:
            raise BrokerRefusal("this run has no network capability")
        host, port = str(a.get("host") or ""), int(a.get("port") or 0)
        entry["target"] = f"tcp://{host}:{port}"
        r = await self.ctx.net.tcp(host, port, send=a.get("send"))
        if r.exchange_id is not None:
            self.exchange_ids.append(r.exchange_id)
        entry.update(state=r.state, exchange_id=r.exchange_id)
        if r.state == "blocked":
            entry["outcome"] = "blocked"
        return r.as_dict()

    async def _op_dns(self, a: dict, entry: dict) -> dict:
        if self.ctx.net is None:
            raise BrokerRefusal("this run has no DNS capability")
        name = str(a.get("name") or "")
        entry["target"] = f"dns://{name}"
        r = await self.ctx.net.resolve(name)
        if r.exchange_id is not None:
            self.exchange_ids.append(r.exchange_id)
        if r.reason:
            entry["outcome"] = "blocked" if "scope" in r.reason else "failed"
        return r.as_dict()

    async def _op_recorded(self, a: dict, entry: dict) -> list:
        if self.ctx.recorded is None or not hasattr(self.ctx.recorded, "query"):
            raise BrokerRefusal("recorded traffic is not available to this tool")
        entry["target"] = f"recorded:{a.get('contains') or '*'}"[:300]
        rows = await self.ctx.recorded.query(
            contains=a.get("contains"), scheme=a.get("scheme"),
            method=a.get("method"), limit=int(a.get("limit") or 20))
        for r in rows:          # same rule as live responses: no cookie values
            r.pop("request_headers", None)
            r["headers"] = [[k, (v.split("=", 1)[0] + "=<redacted>")
                             if str(k).lower() == "set-cookie" else v]
                            for k, v in r["headers"]]
        return rows

    async def _op_sessions(self, a: dict, entry: dict) -> list:
        entry["target"] = "sessions"
        return list(self.ctx.http.sessions())

    async def _op_inventory(self, a: dict, entry: dict) -> Any:
        if self.inventory is None:
            raise BrokerRefusal("no operator-supplied inventory for this run")
        name = a.get("name")
        entry["target"] = f"inventory:{name or '*'}"
        return await self.inventory(name)

    def audit(self) -> dict[str, Any]:
        by: dict[str, int] = {}
        for c in self.calls:
            by[c["outcome"]] = by.get(c["outcome"], 0) + 1
        return {"calls": len(self.calls), "by_outcome": by,
                "log": [{k: v for k, v in c.items()} for c in self.calls[:60]]}
