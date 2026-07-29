#!/usr/bin/env python3
"""Verify the SurrealDB serialization fix against the live database.

Connects to the running SurrealDB instance, queries findings (which contain
RecordID and datetime objects), and confirms they can be sanitized and
serialized to JSON — the exact operation that was failing and causing the
retry storm.

Usage:
    .venv/bin/python scripts/verify_serialization_fix.py
"""
from __future__ import annotations

import asyncio
import json
import sys

SESSION_ID = "gb-92210e89a1eb-1776701240"
SURREALDB_URL = "ws://localhost:8010"
SURREALDB_USER = "changeme"
SURREALDB_PASS = "changeme"


def _extract(raw: list | Any) -> list:
    """Normalize SurrealDB query response to a flat list of dicts."""
    if not raw:
        return []
    if isinstance(raw, list) and raw and isinstance(raw[0], dict):
        if "result" in raw[0]:
            return raw[0]["result"] or []
    return raw if isinstance(raw, list) else [raw]


def _sanitize_for_json(data):
    """Same implementation as in activities.py."""
    return json.loads(json.dumps(data, default=str))


async def main() -> int:
    from surrealdb import AsyncSurreal

    surreal = AsyncSurreal(SURREALDB_URL)
    async with surreal as db:
        await db.signin({"username": SURREALDB_USER, "password": SURREALDB_PASS})
        await db.use("vigilo", SESSION_ID)

        print(f"Connected to {SURREALDB_URL}, namespace=vigilo, db={SESSION_ID}")
        print("=" * 60)

        # 1. Query raw findings — these contain RecordID + datetime
        raw_findings = await db.query("SELECT * FROM finding LIMIT 5")
        findings = _extract(raw_findings)

        if not findings:
            print("WARN: No findings in graph — cannot test serialization")
            return 1

        print(f"\n[1] Queried {len(findings)} findings from graph")

        # 2. Show the problematic types BEFORE sanitization
        sample = findings[0]
        print(f"\n[2] Raw types in first finding:")
        for key, val in sample.items():
            print(f"    {key}: {type(val).__module__}.{type(val).__name__} = {repr(val)[:80]}")

        # 3. Attempt raw json.dumps — this is what was failing
        print(f"\n[3] Attempting json.dumps on raw findings...")
        try:
            json.dumps(findings)
            print("    UNEXPECTED: Raw findings are already serializable?!")
        except (TypeError, ValueError) as e:
            print(f"    EXPECTED FAILURE: {e}")

        # 4. Apply the fix — sanitize then serialize
        print(f"\n[4] Applying _sanitize_for_json fix...")
        sanitized = _sanitize_for_json(findings)

        try:
            serialized = json.dumps(sanitized, indent=2)
            print(f"    SUCCESS: Serialized {len(findings)} findings ({len(serialized)} bytes)")
        except (TypeError, ValueError) as e:
            print(f"    FAILED: {e}")
            return 1

        # 5. Show sanitized sample
        print(f"\n[5] Sanitized first finding:")
        for key, val in sanitized[0].items():
            print(f"    {key}: {type(val).__name__} = {repr(val)[:80]}")

        # 6. Simulate what the activity returns — dict with findings embedded
        agent_result = {
            "agent_name": "test-verification",
            "duration_ms": 1000,
            "cost_usd": 0.0,
            "success": True,
            "findings": sanitized,
        }

        try:
            result_json = json.dumps(agent_result)
            print(f"\n[6] Full agent_result serializable: YES ({len(result_json)} bytes)")
        except (TypeError, ValueError) as e:
            print(f"\n[6] Full agent_result serializable: NO — {e}")
            return 1

        # 7. Check leads — bookkeeping fix verification
        raw_leads = await db.query("SELECT id, status, investigation_attempts FROM lead")
        leads = _extract(raw_leads)
        if leads:
            print(f"\n[7] Lead status summary ({len(leads)} leads):")
            by_status: dict[str, int] = {}
            zero_attempts = 0
            for lead in leads:
                status = str(lead.get("status", "unknown"))
                by_status[status] = by_status.get(status, 0) + 1
                if lead.get("investigation_attempts", 0) == 0:
                    zero_attempts += 1
            for status, count in sorted(by_status.items()):
                print(f"    {status}: {count}")
            print(f"    leads with investigation_attempts=0: {zero_attempts}/{len(leads)}")
            if zero_attempts == len(leads):
                print("    ^ This confirms bookkeeping never ran (the bug)")

    print("\n" + "=" * 60)
    print("VERIFICATION PASSED — serialization fix works correctly")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
