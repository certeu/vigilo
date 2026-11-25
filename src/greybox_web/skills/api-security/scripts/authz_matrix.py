"""Template for tool.compose: object ownership across identities.

Capabilities: ["http"]. args: {"objects": ["/api/notes/1", ...],
"owner_field": "owner"}. Each object is fetched as anonymous and as every session
of the run (ctx.broker.sessions()); a non-owner receiving the record is reported.
"""
import json


def analyse(ctx):
    base = ctx.base_url.rstrip("/")
    owner_field = ctx.args.get("owner_field", "owner")
    idents = [s["label"] for s in ctx.broker.sessions() if s["label"] != "provided-cookie"]
    findings, observations = [], []
    for path in ctx.args.get("objects", []):
        seen = {}
        for ident in ["anon"] + idents:
            try:
                r = ctx.broker.get(base + path, session=ident)
            except BrokerError as exc:
                seen[ident] = {"error": str(exc)}
                continue
            owner = None
            if r["status"] == 200:
                try:
                    owner = json.loads(r["body"]).get(owner_field)
                except ValueError:
                    pass
            seen[ident] = {"status": r["status"], "owner": owner}
        observations.append({"key": path, "facts": {"access": json.dumps(seen)}})
        foreign = [i for i in idents if seen.get(i, {}).get("status") == 200
                   and seen[i].get("owner") not in (None, i)]
        if foreign:
            findings.append({
                "title": "Missing object-level authorisation on " + path.rsplit("/", 1)[0],
                "severity": "high", "class": "vulnerability", "cwe": "CWE-639",
                "description": f"{path} is returned to non-owner(s) {foreign}.",
                "evidence": [json.dumps(seen)[:400]],
                "remediation": {"summary": "Enforce ownership server-side on reads.",
                                "steps": ["Scope the lookup to the session user."],
                                "validation": [f"As a non-owner, GET {path} -> 404/403."]}})
    return {"summary": f"{len(observations)} object(s) x {len(idents) + 1} identities",
            "observations": observations, "findings": findings}
