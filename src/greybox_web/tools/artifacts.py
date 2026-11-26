"""Offline artifact inventory and bounded file reader."""
from __future__ import annotations

import re

from src.greybox_web.tools import AssetSpec, Evidence, FindingSpec, Observation, ToolContext, ToolResult, VerifyResult, excerpt

_SECRET = re.compile(r"(?im)^\s*[\"']?((?=[A-Za-z0-9_.-]*(?:password|secret|private.?key|admin.?key|access.?token))[A-Za-z][A-Za-z0-9_.-]*)[\"']?\s*[:=]\s*[\"']?([^\s\"',;#}]{8,})")
_SKIP = re.compile(r"(?i)^(?:example|placeholder|changeme|<.+>|env\(|process\.env|os\.environ)")


async def inventory(ctx: ToolContext) -> ToolResult:
    if ctx.inventory is None:
        return ToolResult(summary="no artifact uploaded", counts={"files": 0})
    rows = await ctx.inventory(None)
    assets = [AssetSpec("resource_type", "repository", True, "Uploaded repository", tested=True)]
    observations = [Observation("artifact.inventory", f"uploaded repository: {len(rows)} files",
                                facts={"files": len(rows), "paths": [r["path"] for r in rows][:200],
                                       "manifests": [r["path"] for r in rows if r["manifest"]][:30]})]
    return ToolResult(summary=f"inventoried {len(rows)} uploaded files", counts={"files": len(rows)}, observations=observations, assets=assets)


async def inspect(ctx: ToolContext) -> ToolResult:
    names = ctx.params.get("paths") or [ctx.params.get("path")]
    if isinstance(names, str):
        names = [names]
    observations = []
    findings = []
    for name in list(dict.fromkeys(str(n) for n in names if n))[:20]:
        row = await ctx.inventory(name) if ctx.inventory else {"path": name, "error": "no artifact"}
        content = str(row.get("content") or "")
        observations.append(Observation(f"artifact.file|{name}", f"read artifact {name}", facts={"size": row.get("size"), "truncated": row.get("truncated")}))
        for match in list(_SECRET.finditer(content))[:3]:
            key, value = match.groups()
            if _SKIP.search(value):
                continue
            findings.append(FindingSpec(
                check_id="artifact.inspect", detail=key.lower(), title=f"Repository contains credential-like value in {name}",
                severity="high", confidence="high", description=f"The uploaded repository contains a concrete non-placeholder value for {key} in {name}.",
                url=f"artifact:{name}", asset_ref=("resource_type", "repository"),
                evidence=[Evidence("proof", None, excerpt(content, key), "offline uploaded file")],
                verify={"path": name, "key": key}, cwe="CWE-798", finding_class="vulnerability",
                remediation={"summary": "Remove and rotate committed credentials.", "steps": ["Move secrets to a managed secret store and rotate the exposed value."], "validation": ["The value and its history are absent from the repository."], "reproduction": [f"Inspect {name} for field {key}."], "severity_rationale": "A concrete credential is available to every repository reader."}))
    return ToolResult(summary=f"inspected {len(observations)} artifact file(s), {len(findings)} credential exposure(s)", counts={"files": len(observations), "findings": len(findings)}, observations=observations, findings=findings, assets=[AssetSpec("resource_type", "repository", True, "Uploaded repository", tested=True)])


async def verify(ctx: ToolContext) -> VerifyResult:
    name, key = str(ctx.params["path"]), str(ctx.params["key"])
    row = await ctx.inventory(name) if ctx.inventory else {}
    confirmed = any(m.group(1) == key and not _SKIP.search(m.group(2)) for m in _SECRET.finditer(str(row.get("content") or "")))
    return VerifyResult(confirmed, "independent offline artifact reread", "credential-like value remains" if confirmed else "value absent", [])
