"""Exposed sensitive files and directory listings.

A fixed list of at most 12 paths per service, each confirmed by a **content
signature**, never by status code alone — a soft-404 application answers 200 to
everything. The same signature table is reused by ``verify.exposure.*`` (refetch
plus a random-path baseline that must not match, the soft-404 guard).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin

from src.greybox_web.netguard import HttpResponse, ScopeViolation, TransportFailure
from src.greybox_web.tools import (
    Evidence,
    FindingSpec,
    Observation,
    ToolContext,
    ToolResult,
    excerpt,
)


@dataclass(frozen=True)
class FileSig:
    """A content signature: the response must be 200 and match ``match``.

    Binary magic is matched against the raw body; regexes against the decoded
    text. ``None`` means the signature is text-only (binary bodies never match)."""

    magic: bytes | None = None
    pattern: str | None = None
    predicate: Callable[[str], bool] | None = None
    severity: str = "medium"
    description: str = ""

    def matches(self, body: bytes, text: str) -> bool:
        if self.magic is not None:
            return body.startswith(self.magic)
        if self.predicate is not None:
            return bool(self.predicate(text))
        assert self.pattern is not None
        return bool(re.search(self.pattern, text))


def _env_table(text: str) -> bool:
    return len(re.findall(r"(?m)^[A-Z_][A-Z0-9_]{2,}=", text)) >= 2


def _htaccess(text: str) -> bool:
    return bool(re.search(r"(?m)^\s*(RewriteRule|AuthType|Deny\s+from)", text))


# The fixed 12 paths.
FILES: dict[str, FileSig] = {
    "/.git/HEAD": FileSig(pattern=r"(?s)^ref:\s*refs/", severity="high",
                          description="A .git directory is served: the repository, "
                          "including history and possibly secrets, can be "
                          "downloaded."),
    "/.git/config": FileSig(pattern=r"\[core\]", severity="high",
                            description="A .git configuration file is served "
                            "(repository exposure)."),
    "/.env": FileSig(predicate=_env_table, severity="high",
                     description="An environment/configuration file with KEY=VALUE "
                     "entries is served, typically holding credentials."),
    "/.svn/entries": FileSig(pattern=r"(?s)^\s*(dir|format|svn)", severity="medium",
                             description="Subversion metadata is served (repository "
                             "exposure)."),
    "/.DS_Store": FileSig(magic=b"\x00\x00\x01Bud1", severity="medium",
                          description="A macOS finder file is served and leaks file "
                          "names."),
    "/backup.zip": FileSig(magic=b"PK\x03\x04", severity="medium",
                           description="A zip archive is served at a guessable backup "
                           "name."),
    "/db.sql": FileSig(pattern=r"(?i)(CREATE\s+TABLE|INSERT\s+INTO)",
                       severity="medium",
                       description="A SQL dump is served at a guessable name."),
    "/config.bak": FileSig(pattern=r"(?i)(define\s*\(|<configuration)",
                           severity="medium",
                           description="A backup configuration file is served."),
    "/server-status": FileSig(pattern=r"(?i)Apache\s+Server\s+Status|"
                              r"Server\s+uptime", severity="medium",
                              description="The Apache status page is exposed."),
    "/phpinfo.php": FileSig(pattern=r"(?i)phpinfo\(\)|PHP\s+Version", severity="medium",
                            description="A phpinfo page is exposed and discloses the "
                            "stack."),
    "/.htaccess": FileSig(predicate=_htaccess, severity="medium",
                          description="An Apache access-control file is served."),
    "/web.config": FileSig(pattern=r"(?i)<configuration", severity="medium",
                           description="An IIS configuration file is served."),
}

DIRS: tuple[str, ...] = ("/static/", "/uploads/", "/assets/", "/backup/",
                         "/admin/", "/files/")
DIR_PATTERN = re.compile(r"(?i)(Index\s+of\s+/|<title>Index\s+of)")

OWASP_EXPOSED = "https://owasp.org/www-project-web-security-testing-guide/latest/" \
                "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_" \
                "Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files"


def _hints(detail: str) -> list[dict[str, str]]:
    return [
        {
            "type": "log_signature",
            "title": f"Probes for {detail}",
            "content": "Access-log GET lines for /.git/HEAD, /.git/config, /.env, "
                       "/.svn/entries, /.DS_Store, /backup.zip, /db.sql, "
                       "/config.bak, /server-status, /phpinfo.php, /.htaccess and "
                       "/web.config are this Vigilo check, not an attack.",
        },
        {
            "type": "siem_query",
            "title": "Sensitive-path access",
            "content": 'web.accesslog where method = "GET" and status = 200 and '
                       "path in (/.git/HEAD, /.git/config, /.env, /.svn/entries, "
                       "/.DS_Store, /backup.zip, /db.sql, /config.bak, "
                       "/server-status, /phpinfo.php, /.htaccess, /web.config)",
        },
        {
            "type": "waf_rule",
            "title": "Block sensitive paths at the edge",
            "content": "Deny requests to /.git*, /.env, /.svn*, /.DS_Store, "
                       "/backup.zip, /db.sql, /config.bak, /server-status and "
                       "/phpinfo.php; disable autoindex on /static/.",
        },
    ]


def baseline_path(token: str) -> str:
    """The random soft-404 baseline path used by the verifier (never a real file)."""
    return f"/vgl-{token}"


async def _probe(ctx: ToolContext, url: str) -> HttpResponse | None:
    """GET ``url``; None on a scope block or transport error (both recorded by the
    guard)."""
    try:
        return await ctx.http.get(url)
    except (ScopeViolation, TransportFailure):
        return None


def _finding(check_id: str, detail: str, title: str, severity: str, description: str,
             url: str, exchange_id: int | None, text: str,
             verify: dict) -> FindingSpec:
    return FindingSpec(
        check_id=check_id, detail=detail, title=title, severity=severity,
        confidence="high", description=description, url=url, method="GET",
        evidence=[Evidence(role="proof", exchange_id=exchange_id,
                           excerpt=excerpt(text), note="content signature match")],
        verify=verify, cwe="CWE-538",
        references=[{"title": "OWASP WSTG — old backup and unreferenced files",
                     "url": OWASP_EXPOSED}],
        detection_hints=_hints(detail), observation_key=f"{check_id}|{url}")


async def files(ctx: ToolContext) -> ToolResult:
    root = ctx.params["url"]
    findings: list[FindingSpec] = []
    found: list[str] = []
    blocked = failed = 0
    for path, sig in FILES.items():
        url = urljoin(root, path)
        resp = await _probe(ctx, url)
        if resp is None:
            blocked += 1
            continue
        if resp.status >= 500:
            failed += 1
            continue
        if resp.status == 200 and sig.matches(resp.body, resp.text):
            found.append(path)
            findings.append(_finding(
                "exposure.files", path, f"Exposed file: {path}", sig.severity,
                f"{sig.description} Confirmed by content signature on {url}.",
                url, resp.exchange_id, resp.text,
                {"url": root, "path": path}))
    obs = Observation(
        key=f"exposure.files|{root}",
        label=f"exposed files: {', '.join(found)}" if found
        else f"no exposed files under {root}",
        url=root, facts={"probed": len(FILES), "found": found, "blocked": blocked,
                         "failed": failed})
    return ToolResult(
        summary=f"probed {len(FILES)} paths, {len(found)} exposed" if found
        else f"probed {len(FILES)} paths, none exposed",
        counts={"probed": len(FILES), "found": len(found), "blocked": blocked,
                "failed": failed},
        observations=[obs], findings=findings)


async def dirlisting(ctx: ToolContext) -> ToolResult:
    root = ctx.params["url"]
    findings: list[FindingSpec] = []
    found: list[str] = []
    blocked = 0
    for path in DIRS:
        url = urljoin(root, path)
        resp = await _probe(ctx, url)
        if resp is None:
            blocked += 1
            continue
        if resp.status == 200 and DIR_PATTERN.search(resp.text):
            found.append(path)
            findings.append(_finding(
                "exposure.dirlisting", path, f"Directory listing: {path}", "medium",
                f"{url} serves a directory index. File names, versions and sometimes "
                f"backups become enumerable.", url, resp.exchange_id, resp.text,
                {"url": url, "path": path}))
    obs = Observation(
        key=f"exposure.dirlisting|{root}",
        label=f"directory listings: {', '.join(found)}" if found
        else f"no directory listings under {root}",
        url=root, facts={"probed": len(DIRS), "found": found, "blocked": blocked})
    return ToolResult(
        summary=f"probed {len(DIRS)} dirs, {len(found)} listing(s)" if found
        else f"probed {len(DIRS)} dirs, no listings",
        counts={"probed": len(DIRS), "found": len(found), "blocked": blocked},
        observations=[obs], findings=findings)
