"""Guarded synthetic file upload, download, and path-normalisation instruments."""
from __future__ import annotations

import base64
import hashlib
import posixpath
import re
from typing import Any
from urllib.parse import quote, urljoin

from src.greybox_web.tools import Observation, ToolContext, ToolResult


MAX_SYNTHETIC_FILE = 64 * 1024
_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


def _identities(ctx: ToolContext) -> list[str]:
    known = {str(item.get("label")) for item in ctx.http.sessions() if item.get("label")} | {"anon"}
    requested = ctx.params.get("identities")
    values = requested if isinstance(requested, list) else [ctx.params.get("identity") or "anon"]
    values = list(dict.fromkeys(str(value) for value in values))[:20]
    unknown = sorted(set(values) - known)
    if unknown:
        raise ValueError(f"unknown identities: {', '.join(unknown)}; known: {', '.join(sorted(known))}")
    return values


def _path(value: Any, name: str) -> str:
    value = str(value or "")
    if not value or len(value) > 240 or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty synthetic path under 240 characters")
    if value.startswith(("/", "\\")) or "://" in value or re.match(r"^[A-Za-z]:", value):
        raise ValueError(f"{name} must be relative")
    return value


def _fingerprint(response) -> dict[str, Any]:
    return {"status": response.status, "content_type": response.content_type[:160],
            "bytes": len(response.body), "sha256": hashlib.sha256(response.body).hexdigest(),
            "content_disposition": (response.header("content-disposition") or "")[:300],
            "location": (response.header("location") or "")[:300],
            "truncated": response.truncated}


def _ownership(ctx: ToolContext, identity: str) -> dict[str, str] | None:
    expected_owner = str(ctx.params.get("expected_owner") or "")[:160]
    resource_ref = str(ctx.params.get("resource_ref") or "")[:160]
    if not expected_owner and not resource_ref:
        return None
    return {"expected_owner": expected_owner, "resource_ref": resource_ref,
            "observed_identity": identity, "basis": "assessment relationship"}


async def download(ctx: ToolContext) -> ToolResult:
    """Read a discovered synthetic file under one or more configured identities."""
    url = urljoin(ctx.base_url, str(ctx.params.get("url") or ctx.base_url))
    marker = str(ctx.params.get("marker") or "")[:300]
    matrix, exchange_ids = [], []
    for identity in _identities(ctx):
        response = await ctx.http.get(url, follow=False, session=identity)
        exchange_ids.extend(response.exchange_ids)
        row = {"identity": identity, **_fingerprint(response),
               "marker_present": bool(marker and marker.encode() in response.body)}
        ownership = _ownership(ctx, identity)
        if ownership:
            row["ownership"] = ownership
        matrix.append(row)
    facts = {"matrix": matrix, "investigation_ref": str(
        ctx.params.get("investigation_ref") or "")[:160]}
    return ToolResult(summary=f"Downloaded synthetic file as {len(matrix)} identities",
                      observations=[Observation(key=f"file.download|{url}"[:300],
                          label="File access and ownership evidence", url=url,
                          exchange_ids=exchange_ids[:100], facts=facts)],
                      counts={"attempted": len(matrix), "served": sum(
                          200 <= row["status"] < 300 for row in matrix)})


async def upload(ctx: ToolContext) -> ToolResult:
    """Upload one bounded inert file using the guarded state-change path."""
    url = urljoin(ctx.base_url, str(ctx.params.get("url") or ctx.base_url))
    identity = _identities(ctx)[0]
    filename = _path(ctx.params.get("filename") or f"vigilo-{ctx.token()}.txt", "filename")
    field = str(ctx.params.get("field") or "file")
    if not _FIELD.fullmatch(field):
        raise ValueError("field is not a valid multipart field name")
    if ctx.params.get("content_b64") is not None:
        try:
            content = base64.b64decode(str(ctx.params["content_b64"]), validate=True)
        except ValueError as exc:
            raise ValueError("content_b64 is not valid base64") from exc
    else:
        content = str(ctx.params.get("content") or f"vigilo-file-{ctx.token()}").encode()
    if len(content) > MAX_SYNTHETIC_FILE:
        raise ValueError(f"synthetic file exceeds {MAX_SYNTHETIC_FILE} bytes")
    content_type = str(ctx.params.get("content_type") or "text/plain")[:120]
    boundary = f"vigilo-{ctx.token()}"
    disposition = f'form-data; name="{field}"; filename="{filename}"'
    body = (f"--{boundary}\r\nContent-Disposition: {disposition}\r\n"
            f"Content-Type: {content_type}\r\n\r\n").encode() + content + \
        f"\r\n--{boundary}--\r\n".encode()
    response = await ctx.http.request("POST", url, body=body,
        content_type=f"multipart/form-data; boundary={boundary}", follow=False,
        session=identity, state_changing=True)
    ownership = _ownership(ctx, identity)
    facts = {"identity": identity, "filename": filename,
             "normalised_filename": posixpath.normpath(filename.replace("\\", "/")),
             "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
             "response": _fingerprint(response), "state_changing": True,
             "investigation_ref": str(ctx.params.get("investigation_ref") or "")[:160]}
    if ownership:
        facts["ownership"] = ownership
    return ToolResult(summary=f"Uploaded bounded synthetic file ({response.status})",
                      observations=[Observation(key=f"file.upload|{identity}|{url}|{filename}"[:300],
                          label="Controlled multipart upload", url=url,
                          exchange_ids=response.exchange_ids, facts=facts)],
                      counts={"attempted": 1, "succeeded": int(
                          200 <= response.status < 300)})


async def path_compare(ctx: ToolContext) -> ToolResult:
    """Compare control and non-canonical paths for one known synthetic marker."""
    template = str(ctx.params.get("url_template") or "")
    if template.count("{path}") != 1:
        raise ValueError("url_template must contain exactly one {path} placeholder")
    marker = str(ctx.params.get("marker") or "")[:300]
    if not marker:
        raise ValueError("marker is required to bind the check to a synthetic file")
    control = _path(ctx.params.get("control_path"), "control_path")
    candidate = _path(ctx.params.get("candidate_path"), "candidate_path")
    identity = _identities(ctx)[0]
    rows, exchange_ids = [], []
    for kind, path in (("control", control), ("candidate", candidate)):
        rendered = template.replace("{path}", quote(path, safe="/%\\."))
        url = urljoin(ctx.base_url, rendered)
        response = await ctx.http.get(url, follow=False, session=identity)
        exchange_ids.extend(response.exchange_ids)
        rows.append({"kind": kind, "path": path, "url": url,
                     "marker_present": marker.encode() in response.body,
                     **_fingerprint(response)})
    facts = {"identity": identity, "paths": rows,
             "ownership": _ownership(ctx, identity),
             "investigation_ref": str(ctx.params.get("investigation_ref") or "")[:160]}
    return ToolResult(summary="Compared canonical and alternate synthetic file paths",
                      observations=[Observation(key=f"file.path|{identity}|{template}|{control}|{candidate}"[:300],
                          label="Path-normalisation evidence", url=rows[1]["url"],
                          exchange_ids=exchange_ids[:100], facts=facts)],
                      counts={"attempted": 2, "marker_responses": sum(
                          row["marker_present"] for row in rows)})
