"""Defensive recommendations of a run: list and download.

Read-only. Ownership is checked with ``get_run_or_404`` (404 for anyone but the owner
and admins); every query is scoped to the run.
"""
from __future__ import annotations

import io
import re
import uuid
import zipfile

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web.acl import get_run_or_404
from src.greybox_web.defenses import (
    REQUIRED_EDITS,
    Stmt,
    config_statements,
    merge_pcf,
    placeholders,
)
from src.greybox_web.models import GreyboxDefense
from src.greybox_web.pagination import as_utc
from src.greybox_web.schemas import (
    DefenseDownloadFormat,
    DefenseFormat,
    DefenseKind,
    DefenseList,
    DefenseRead,
    DefenseScope,
)
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import User

router = APIRouter(prefix="/greybox", tags=["greybox"])

# download format -> (extension, file inside the zip)
_EXT = {"modsecurity": "conf", "nginx": "conf", "apache": "conf", "sigma": "yml",
        "text": "txt"}
_ZIP_NAMES = {"modsecurity": "modsecurity.conf", "sigma": "sigma.yml",
              "nginx": "nginx.conf", "apache": "apache.conf", "text": "notes.txt"}
# format -> (file stem, shared-context name, per-service-context name, how to include)
_LAYOUT = {
    "nginx": ("nginx", "http", "server",
              "inside the http { } block",
              "inside the server { } block that serves the site"),
    "apache": ("apache", "global", "vhost",
               "in the global server configuration (outside any <VirtualHost>)",
               "inside the <VirtualHost> that serves the site"),
}


def _read(d: GreyboxDefense) -> DefenseRead:
    return DefenseRead(
        id=d.id, run_id=d.run_id, finding_id=d.finding_id, asset_id=d.asset_id,
        scope=d.scope, finding_ids=[uuid.UUID(str(x)) for x in (d.finding_ids or [])],
        node_id=d.node_id,
        kind=d.kind, format=d.format, title=d.title, rationale=d.rationale,
        content=d.content, confidence=d.confidence, status=d.status,
        created_at=as_utc(d.created_at))


def _comment(d: GreyboxDefense) -> str:
    title = " ".join(d.title.split())
    flag = " [UNVERIFIED finding]" if d.status == "unverified" else ""
    ref = (f"finding {str(d.finding_id)[:8]}" if d.finding_id is not None
           else f"asset {str(d.asset_id)[:8]}")
    return f"# {title} ({ref}, confidence {d.confidence}){flag}"


def _head(fmt: str, run_short: str, note: str = "", text: str = "") -> str:
    head = (f"# Vigilo grey-box defenses for run {run_short} ({fmt})\n"
            "# Generated from findings; review and test before deploying.\n")
    if note:
        head += "".join(f"# {line}\n" for line in note.splitlines())
    required = placeholders(text)
    if required:
        head += "# REQUIRED EDITS (replace each token before use):\n"
        head += "".join(f"#   {t}: {REQUIRED_EDITS.get(t, 'a value only you know')}\n"
                        for t in required)
    return head


def _modsecurity(rows: list[GreyboxDefense], run_short: str) -> str:
    seen: set[int] = set()
    parts: list[str] = []
    for d in rows:
        flat = re.sub(r"\\\n\s*", " ", d.content)
        ids = [int(i) for line in flat.splitlines() if not line.lstrip().startswith("#")
               for i in re.findall(r"\bid:(\d+)", line)]
        if ids and set(ids) <= seen:        # the same rule (stable id) once
            continue
        seen |= set(ids)
        parts.append(f"{_comment(d)}\n{d.content.rstrip()}\n")
    body = "\n".join(parts)
    note = ("Rule ids are stable per target, check and path, in the block "
            "8100000-8199999.\n"
            "Load these rules BEFORE other rule sets (for example the OWASP CRS) so "
            "that they win.\n"
            "With SecRuleEngine DetectionOnly every deny below only logs.")
    if seen:
        note += "\nRollback: SecRuleRemoveById " + " ".join(str(i) for i in sorted(seen))
    return _head("modsecurity", run_short, note, body) + "\n" + body


def _sigma(rows: list[GreyboxDefense], run_short: str) -> str:
    seen: set[str] = set()
    docs: list[str] = []
    for d in rows:       # one YAML document stream; a rule id appears once
        m = re.search(r"^id:\s*(\S+)", d.content, re.M)
        if m and m.group(1) in seen:
            continue
        if m:
            seen.add(m.group(1))
        docs.append(f"{_comment(d)}\n{d.content.rstrip()}\n")
    note = ("Rules use the portable web-server log fields (c-uri, sc-status, ...): map "
            "them to your log schema with a Sigma pipeline.")
    return _head("sigma", run_short, note) + "---\n".join(docs)


def _config_files(fmt: str, rows: list[GreyboxDefense], run_short: str) -> dict[str, str]:
    """nginx / Apache snippets assembled per context: shared (http, global) and one
    file per service (server, vhost). Statements are de-duplicated by meaning, not text."""
    stem, shared, per, where_shared, where_per = _LAYOUT[fmt]
    order: list[tuple[str, str, str]] = []
    items: dict[tuple[str, str, str], Stmt] = {}
    for d in rows:
        comment = _comment(d)
        first = True
        for st in config_statements(fmt, d.content):
            k = (st.context, "" if st.context == shared else st.origin, st.key)
            if k in items:
                if st.key.startswith("pcf:"):
                    items[k] = merge_pcf(items[k], st)
                continue
            if first:
                st = Stmt(st.context, st.key, f"{comment}\n{st.text}", st.body, st.origin)
                first = False
            items[k] = st
            order.append(k)
    shared_txt = "\n".join(items[k].text for k in order if k[0] == shared)
    origins = sorted({k[1] for k in order if k[0] == per})
    files: dict[str, str] = {}
    other = f"{stem}-{'server' if fmt == 'nginx' else 'vhost'}"
    files[f"{stem}.conf"] = _head(
        fmt, run_short,
        f"{shared} context: include this file {where_shared}.\n"
        f"The {per} context part is in {other}*.conf.", shared_txt) + "\n" + shared_txt \
        + ("\n" if shared_txt else "")
    for o in origins:
        txt = "\n".join(items[k].text for k in order if k[0] == per and k[1] == o)
        slug = re.sub(r"[^a-z0-9]+", "-", o.lower()).strip("-")
        name = f"{other}.conf" if len(origins) == 1 or not slug else f"{other}-{slug}.conf"
        files[name] = _head(
            fmt, run_short,
            f"{per} context for {o or 'the site'}: include this file {where_per}.",
            txt) + "\n" + txt + "\n"
    return files


def build_files(rows: list[GreyboxDefense], run_short: str) -> dict[str, str]:
    """Every file of the download: one per format, config formats split by context."""
    by_fmt: dict[str, list[GreyboxDefense]] = {}
    for d in rows:
        by_fmt.setdefault(d.format, []).append(d)
    files: dict[str, str] = {}
    for fmt, items in by_fmt.items():
        if fmt == "modsecurity":
            files[_ZIP_NAMES[fmt]] = _modsecurity(items, run_short)
        elif fmt == "sigma":
            files[_ZIP_NAMES[fmt]] = _sigma(items, run_short)
        elif fmt in _LAYOUT:
            files.update(_config_files(fmt, items, run_short))
        else:
            files[_ZIP_NAMES[fmt]] = _head(fmt, run_short) + "\n" + "\n".join(
                f"{_comment(d)}\n{d.content.rstrip()}\n" for d in items)
    return files


def _readme(files: dict[str, str], run_short: str, unverified: bool) -> str:
    lines = [f"Vigilo grey-box defenses for run {run_short}", "",
             "Every recommendation is a vendor-neutral policy first (see the report); "
             "these files are illustrative examples in concrete syntaxes. Review and "
             "test before deploying.", "", "Files:"]
    for name in sorted(files):
        first = next((ln[2:] for ln in files[name].splitlines()[2:]
                      if ln.startswith("# ") and "context" in ln), "")
        lines.append(f"  {name}" + (f" - {first}" if first else ""))
    required = placeholders("\n".join(files.values()))
    if required:
        lines += ["", "REQUIRED EDITS (nothing works as intended before these are replaced):"]
        lines += [f"  {t}: {REQUIRED_EDITS.get(t, 'a value only you know')}"
                  for t in required]
    lines += ["", "Validate before deploying: nginx -t, apachectl -t (or httpd -t), a "
              "Sigma conversion for your SIEM, and a replay of your normal traffic.",
              "Suggestions for unverified (candidate) findings are "
              + ("INCLUDED (marked [UNVERIFIED]) and Sigma rules carry "
                 "vigilo_verified: false." if unverified else
                 "excluded; add include_unverified=true to the download to get them.")]
    return "\n".join(lines) + "\n"


def _bundle(fmt: str, rows: list[GreyboxDefense], run_short: str) -> str:
    """One format as one text file: the parts of a config format are concatenated with
    a banner each (use the zip for files that load as they are)."""
    files = build_files(rows, run_short)
    names = [n for n in files if n.startswith(fmt) or (fmt == "text" and n == "notes.txt")
             or (fmt == "modsecurity" and n == "modsecurity.conf")
             or (fmt == "sigma" and n == "sigma.yml")]
    if len(names) == 1:
        return files[names[0]]
    return "\n".join(f"# ===== {n} =====\n{files[n]}" for n in sorted(names))


@router.get("/runs/{run_id}/defenses", response_model=DefenseList)
async def list_defenses(
    run_id: uuid.UUID,
    finding_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    scope: DefenseScope | None = None,
    kind: DefenseKind | None = None,
    format: DefenseFormat | None = None,  # noqa: A002 (query parameter name)
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> DefenseList:
    run = await get_run_or_404(session, user, run_id)
    stmt = select(GreyboxDefense).where(GreyboxDefense.run_id == run.id)
    if finding_id is not None:
        stmt = stmt.where(GreyboxDefense.finding_id == finding_id)
    if asset_id is not None:
        stmt = stmt.where(GreyboxDefense.asset_id == asset_id)
    if scope is not None:
        stmt = stmt.where(GreyboxDefense.scope == scope)
    if kind is not None:
        stmt = stmt.where(GreyboxDefense.kind == kind)
    if format is not None:
        stmt = stmt.where(GreyboxDefense.format == format)
    rows = (await session.scalars(
        stmt.order_by(GreyboxDefense.created_at, GreyboxDefense.id))).all()
    return DefenseList(items=[_read(d) for d in rows])


@router.get("/runs/{run_id}/defenses/download")
async def download_defenses(
    run_id: uuid.UUID,
    format: DefenseDownloadFormat = "all",  # noqa: A002 (query parameter name)
    asset_id: uuid.UUID | None = None,
    scope: DefenseScope | None = None,
    include_unverified: bool = False,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> Response:
    run = await get_run_or_404(session, user, run_id)
    stmt = select(GreyboxDefense).where(GreyboxDefense.run_id == run.id)
    if not include_unverified:       # rules of unverified candidates stay out by default
        stmt = stmt.where(GreyboxDefense.status != "unverified")
    if asset_id is not None:
        stmt = stmt.where(GreyboxDefense.asset_id == asset_id)
    if scope is not None:
        stmt = stmt.where(GreyboxDefense.scope == scope)
    if format != "all":
        stmt = stmt.where(GreyboxDefense.format == format)
    rows = list((await session.scalars(
        stmt.order_by(GreyboxDefense.created_at, GreyboxDefense.id))).all())
    rows.sort(key=lambda d: d.status == "unverified")      # verified first (stable)
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No defenses for this run")
    short = str(run.id)[:8]
    if format == "all":
        files = build_files(rows, short)
        files["README.txt"] = _readme(files, short, include_unverified)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, text in files.items():
                zf.writestr(name, text)
        return Response(
            content=buf.getvalue(), media_type="application/zip",
            headers={"Content-Disposition":
                     f'attachment; filename="greybox-defenses-{short}.zip"'})
    return Response(
        content=_bundle(format, rows, short), media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="greybox-defenses-{short}.{_EXT[format]}"'})
