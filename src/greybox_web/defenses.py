"""Defensive recommendations generated from findings.

Deterministic and template-based (no LLM, no network): after verification, every
verified finding (and every still-unverified candidate, marked ``unverified``) gets a
list of *defenses*. Each one is first a vendor-neutral **policy** (what to block, allow
or limit, and why, with the affected paths) and then an illustrative rule or
configuration snippet in a concrete syntax (nginx, Apache, ModSecurity, Sigma). They are
persisted (``greybox_defenses``), projected into the exploration graph as ``defense``
nodes with a ``mitigates`` edge to their finding, announced with ``defense.proposed``
events and rendered in the report.

Rules reference only what the finding already carries (check, detail, the URL path).
Every input is redacted first and every output field is redacted again, so a
registered secret can never reach a rule. Values placed in a rule are either tokens or
paths rendered as a regular expression over the *decoded* path with every byte outside
``[A-Za-z0-9/_~]`` written as ``\\xHH`` (or escaped), so a hostile path cannot break out
of a quoted ModSecurity, nginx, Apache or YAML string.

Config snippets are written so that the download can assemble them per context (see
``api/defenses.py``): nginx ``map``/``geo``/``limit_req_zone`` statements go to the
``http`` context and everything else to the ``server`` context; Apache ``ServerTokens``
and ``<VirtualHost>`` to the global context and everything else to a virtual host. A
leading ``# vigilo-service: <origin>`` comment says which service a snippet belongs to.
Values the defender MUST provide are written as ``@@REPLACE_...@@`` sentinels
(``REQUIRED_EDITS``); every default is safe until they are replaced.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote, unquote, unquote_to_bytes, urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web import events, redaction
from src.greybox_web.graph import GraphTx
from src.greybox_web.models import (
    GreyboxAsset,
    GreyboxDefense,
    GreyboxFinding,
    GreyboxGraphNode,
    GreyboxRun,
)
from src.greybox_web.surface import SENSITIVE_PATHS

KINDS = ("waf_rule", "detection_rule", "config", "hardening")
SCOPES = ("finding", "asset")
FORMATS = ("modsecurity", "sigma", "nginx", "apache", "text")
CONFIDENCES = ("high", "medium", "low")

# ModSecurity rule ids: 8_100_000 .. 8_199_999, derived from target + rule + path (see
# ``ModSecIds``). The block is outside the CRS (900,000-999,999) and CRS plugin
# (9,000,000-9,999,999) ranges; a registered block is deferred.
MODSEC_BASE = 8_100_000
MODSEC_SPAN = 100_000

# Placeholders the defender must replace before a snippet can work as intended.
REQUIRED_EDITS = {
    "@@REPLACE_ALLOWED_ORIGIN@@":
        "the front-end origin that may read credentialed responses, for example "
        "https://app.example.com",
    "@@REPLACE_ALLOWED_ORIGIN_REGEX@@":
        r"the same origin as an escaped regular expression, for example "
        r"https://app\.example\.com",
    "@@REPLACE_ADMIN_NETWORK@@":
        "the network (CIDR, for example 192.0.2.0/24) allowed to reach administrative paths",
    "@@REPLACE_DOCROOT@@": "the document root of the site",
    "@@REPLACE_HOST@@": "the public host name of the site",
}
_SENTINEL = re.compile(r"@@REPLACE_[A-Z_]+@@")

# Fields Sigma rules use: the portable web-server log taxonomy that pySigma pipelines map.
SIGMA_FIELDS = frozenset({"c-uri", "cs-uri-query", "sc-status", "cs-method",
                          "c-useragent", "src_ip", "cs-host"})

_TOKEN = re.compile(r"[A-Za-z0-9_.\-]{1,64}")
_PATH_SAFE = "/._-~%"
# cookies that scripts must read (anti-CSRF tokens): never made HttpOnly automatically
_JS_READ_COOKIE = re.compile(r"(?i)xsrf|csrf")


class RuleIdExhausted(RuntimeError):
    """Every ModSecurity id of the Vigilo block is taken: never silently dropped."""


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:12]


@dataclass(frozen=True)
class DefenseSpec:
    kind: str
    format: str
    title: str
    rationale: str
    content: str
    confidence: str = "medium"
    policy: str = ""        # the vendor-neutral statement, prefixed to the rationale


class ModSecIds:
    """Stable, collision-free ModSecurity rule ids.

    The id of a rule is ``MODSEC_BASE + sha256(rule_key) % MODSEC_SPAN`` where the rule
    key is ``<origin>|<kind>|<name>`` (target + check + path), so the same rule gets the
    same id in every run. If two different keys land on the same id, the later one takes
    the next free slot (deterministic for a given order); the key hash is written into
    the rule (``tag:'vigilo-key:<hash>'``) so existing defenses seed the allocator
    (``seed``) and a rule keeps its id when defenses are generated again. When the
    block is full ``RuleIdExhausted`` is raised."""

    def __init__(self) -> None:
        self.by_key: dict[str, int] = {}
        self.used: set[int] = set()

    def seed(self, content: str) -> None:
        flat = re.sub(r"\\\n\s*", " ", content or "")
        for line in flat.splitlines():
            if line.lstrip().startswith("#"):
                continue
            for m in re.finditer(r"\bid:(\d+)", line):
                self.used.add(int(m.group(1)))
            m = re.search(r"\bid:(\d+)[^\"]*?tag:'vigilo-key:([0-9a-f]+)'", line)
            if m:
                self.by_key[m.group(2)] = int(m.group(1))

    def id_for(self, key: str) -> tuple[int, str]:
        kh = key_hash(key)
        if kh in self.by_key:
            return self.by_key[kh], kh
        start = int(kh, 16) % MODSEC_SPAN
        for i in range(MODSEC_SPAN):
            cand = MODSEC_BASE + (start + i) % MODSEC_SPAN
            if cand not in self.used:
                self.used.add(cand)
                self.by_key[kh] = cand
                return cand, kh
        raise RuleIdExhausted(
            f"all {MODSEC_SPAN} ModSecurity rule ids of the Vigilo block are in use")


@dataclass
class Ctx:
    """What a template may use: the finding facts, the service origin and the ids."""
    run_id: uuid.UUID
    finding_id: uuid.UUID
    check_id: str
    detail: str
    title: str
    severity: str
    path: str
    date: str
    hints: list[dict] = field(default_factory=list)
    modsec: "ModSecIds | None" = None
    origin: str = ""                 # scheme://host:port of the service the rule is for
    verified: bool = True

    def rule_id(self, *parts: str) -> tuple[int, str] | None:
        if self.modsec is None:
            return None
        return self.modsec.id_for("|".join((self.origin, *parts)))

    def sigma_id(self, rule_key: str) -> str:
        """Stable per target and rule, never per run or finding."""
        return str(uuid.uuid5(uuid.NAMESPACE_URL,
                              f"vigilo-greybox:{self.origin}:{rule_key}"))

    def mark(self) -> str:
        return f"# vigilo-service: {self.origin}\n" if self.origin else ""

    @property
    def host(self) -> str:
        return urlsplit(self.origin).netloc or "the target"


# ------------------------------------------------------------------ small helpers


def _origin(url: str | None) -> str:
    """``scheme://host:port`` (explicit port, lower case), or "" if not expressible."""
    try:
        u = urlsplit(url or "")
        scheme = (u.scheme or "http").lower()
        host = (u.hostname or "").lower()
        port = u.port or (443 if scheme == "https" else 80)
    except ValueError:
        return ""
    if scheme not in ("http", "https") or not re.fullmatch(r"[a-z0-9.\-]{1,253}", host):
        return ""
    return f"{scheme}://{host}:{port}"


def _safe_path(url: str | None) -> str:
    """The URL path, redacted and percent-encoded to ``[A-Za-z0-9/._~%-]``."""
    try:
        path = urlsplit(redaction.url(url or "")).path or "/"
    except ValueError:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    return quote(path, safe=_PATH_SAFE)[:200] or "/"


def _label(text: str) -> str:
    """Text safe inside single-quoted msg/title strings of every format."""
    return re.sub(r"[^A-Za-z0-9 _./:()\-]", "", text)[:120]


def _yq(value: str) -> str:
    """A YAML single-quoted scalar (one line)."""
    return "'" + " ".join(value.split()).replace("'", "''") + "'"


def _token(value: str) -> str | None:
    return value if _TOKEN.fullmatch(value) else None


def _rx_literal(path: str) -> str:
    """``path`` (percent-encoded) as a regex over the DECODED path: letters, digits,
    ``/ _ ~`` literal, ``. -`` escaped, every other byte as ``\\xHH``. Engines match the
    decoded path, so a path with a space or non-ASCII character still matches."""
    out: list[str] = []
    for b in unquote_to_bytes(path):
        c = chr(b)
        if c.isascii() and (c.isalnum() or c in "/_~"):
            out.append(c)
        elif c in ".-":
            out.append("\\" + c)
        else:
            out.append(f"\\x{b:02X}")
    return "".join(out)


def _ap_unset(name: str) -> str:
    """Apache keeps response headers of proxied backends in a different table than
    error responses: ``Header unset`` reaches the first, ``Header always unset`` the
    second, so both lines are emitted."""
    return f"Header unset {name}\nHeader always unset {name}\n"


def _ap_cookie_edit(regex: str, repl: str) -> str:
    """``Header edit`` (proxied and 2xx responses) plus ``Header always edit`` (error
    responses); the negative look-ahead makes the pair idempotent."""
    return (f'Header edit Set-Cookie "{regex}" "{repl}"\n'
            f'Header always edit Set-Cookie "{regex}" "{repl}"\n')


def _norm(content: str) -> str:
    return " ".join((content or "").split())


def _secrule(ctx: Ctx, rid: tuple[int, str], target: str, operator: str, msg: str,
             actions: str, *, level: str, chain: bool = False, phase: int = 1) -> str:
    n, kh = rid
    tail = ",chain" if chain else ""
    return (f'SecRule {target} "{operator}" \\\n'
            f'    "id:{n},phase:{phase},t:none,{actions},log,msg:\'{_label(msg)}\','
            f"severity:'{_MODSEC_SEV[level]}',tag:'vigilo-greybox',"
            f"tag:'vigilo-key:{kh}'{tail}\"")


def _sigma(ctx: Ctx, rule_key: str, title: str, description: str, detection: list[str],
           condition: str, *, level: str, falsepositives: list[str],
           tags: tuple[str, ...]) -> str:
    lines = [
        f"title: {_yq(title)}",
        f"id: {ctx.sigma_id(rule_key)}",
        f"status: {'experimental' if ctx.verified else 'unsupported'}",
        f"description: {_yq(description)}",
        "author: Vigilo grey-box",
        f"date: {ctx.date}",
        "tags:",
        *[f"    - {t}" for t in tags],
        "logsource:",
        "    category: webserver",
        "detection:",
        *[f"    {l}" for l in detection],
        f"    condition: {condition}",
        "falsepositives:",
        *[f"    - {_yq(f)}" for f in falsepositives],
        f"level: {level}",
        f"vigilo_run: {ctx.run_id}",
        f"vigilo_verified: {'true' if ctx.verified else 'false'}",
    ]
    return "\n".join(lines) + "\n"


_LEVEL = {"critical": "high", "high": "high", "medium": "medium", "low": "low",
          "info": "informational"}
_MODSEC_SEV = {"critical": "CRITICAL", "high": "ERROR", "medium": "WARNING",
               "low": "NOTICE", "info": "INFO", "informational": "INFO"}
_VIGILO_FP = ("Authorised Vigilo grey-box test runs from the declared test source "
              "(requests for these paths are the Vigilo check, not an attack).")

# ------------------------------------------------------------------ path classes


@dataclass(frozen=True)
class PathClass:
    key: str            # stable class key (rule key component)
    label: str          # what the class is called in titles
    rx: str             # PCRE over the decoded, normalised path; case-insensitive
    sigma: str          # the Sigma selector line for c-uri
    action: str         # "deny" or "restrict" (allow only from admin networks)
    level: str          # alert / severity level of the class


def _harden(p: str) -> str:
    """Tolerate ``;param`` path parameters (JVM backends) and a trailing slash."""
    if p.endswith("(/|$)"):
        return p[:-5] + "([/;]|$)"
    if p.endswith("$"):
        return p[:-1] + "(;[^/]*)?/?$"
    return p


def _sigma_rx(p: str) -> str:
    if p.endswith("(/|$)"):
        return p[:-5] + "([/;?]|$)"
    if p.endswith("$"):
        return p[:-1] + r"(;[^/?]*)?/?(\?.*)?$"
    return p


_PATTERN = {why: rx.pattern for rx, why in SENSITIVE_PATHS}
_ARCHIVE = re.compile(r"\.(tar|tgz|zip|gz|7z|rar)$")
_BACKUP_EXT = r"\.(bak|old|orig|save|swp|sql|dump)$"

# reason -> (class key, label, action, level). Archives are NOT a class (legitimate
# downloads exist): only the observed path is blocked. Administrative and diagnostic
# paths are restricted by source, not denied.
_CLASSES = {
    "git repository": ("repo-git", "/.git/", "deny", "high"),
    "svn repository": ("repo-svn", "/.svn/", "deny", "high"),
    "mercurial repository": ("repo-hg", "/.hg/", "deny", "high"),
    "environment file": ("env", "environment files (.env)", "deny", "high"),
    "web server access file": ("htaccess", ".htaccess and .htpasswd files", "deny", "high"),
    "directory metadata file": ("dsstore", ".DS_Store files", "deny", "medium"),
    "editor backup file": ("editor-backup", "editor backup files", "deny", "medium"),
    "backup location": ("backup-dir", "backup directories", "deny", "medium"),
    "configuration file": ("config-file", "configuration files", "deny", "high"),
    "administrative interface": ("admin", "administrative interfaces", "restrict", "medium"),
    "diagnostic page": ("diag-page", "diagnostic pages", "restrict", "medium"),
    "diagnostic endpoint": ("diag-endpoint", "diagnostic endpoints", "restrict", "medium"),
}


def _exact_class(path: str, level: str = "high") -> PathClass:
    lit = _rx_literal(path.rstrip("/") or "/")
    shown = _label(unquote(path)) or "the path"
    sig_rx = f"^{lit}" + r"(;[^/?]*)?/?(\?.*)?$"
    return PathClass(f"exact:{key_hash(path)[:8]}", shown, f"^{lit}(;[^/]*)?/?$",
                     f"c-uri|re|i: {_yq(sig_rx)}", "deny", level)


def classify(path: str) -> PathClass:
    """The class of an observed (percent-encoded) path, from the same table that
    detected it (``surface.SENSITIVE_PATHS``)."""
    p = unquote(path).lower()
    reason = next((why for rx, why in SENSITIVE_PATHS if rx.search(p)), None)
    if reason == "backup or archive file":
        if _ARCHIVE.search(p):
            return _exact_class(path)
        pat = _BACKUP_EXT
        key, label, action, level = "backup-ext", "backup and dump files", "deny", "medium"
    elif reason in _CLASSES:
        key, label, action, level = _CLASSES[reason]
        pat = _PATTERN[reason]
    else:
        return _exact_class(path)
    if key.startswith("repo-"):
        sig = f"c-uri|startswith: {_yq(label)}"
    else:
        sig = f"c-uri|re|i: {_yq(_sigma_rx(pat))}"
    return PathClass(key, label, _harden(pat), sig, action, level)


# ------------------------------------------------------------------ path policy


def _path_specs(ctx: Ctx, cls: PathClass, seen: str) -> list[DefenseSpec]:
    """The defenses of one path class: the same text whether it comes from a finding or
    from the network analysis, so the two de-duplicate. ``seen`` is for the rationale."""
    h = key_hash(cls.key)[:8]
    lvl = cls.level
    out: list[DefenseSpec] = []
    if cls.action == "deny":
        policy = (f"Do not serve {cls.label} to anyone: refuse every request for it "
                  "(404) at the edge, matching the decoded, normalised, "
                  "case-insensitive path (so %2e, //, /./ and upper case do not "
                  "bypass it), and remove the content from the web root.")
        why = (f"Observed: {seen}. Refusing the path hides it; deleting the content "
               "removes the exposure.")
        rid = ctx.rule_id("path", cls.key)
        if rid is not None:
            out.append(DefenseSpec(
                "waf_rule", "modsecurity", f"Block requests for {cls.label}",
                f"{why} ModSecurity v2/v3 and Coraza.",
                _secrule(ctx, rid, "REQUEST_FILENAME", f"@rx (?i){cls.rx}",
                         f"Vigilo: sensitive path {cls.label}",
                         "t:urlDecodeUni,t:removeNulls,t:normalizePath,deny,status:404",
                         level=lvl) + "\n", "high", policy))
        out.append(DefenseSpec(
            "config", "nginx", f"nginx: refuse {cls.label}",
            f"{why} Example for nginx: the check runs at server level before any "
            "location is chosen, so no location order or ^~ prefix can bypass it.",
            ctx.mark()
            + "# Refuse " + cls.label + " (decoded, normalised, case-insensitive URI).\n"
            f"map $uri $vigilo_path_{h} {{\n    default 0;\n    \"~*{cls.rx}\" 1;\n}}\n"
            f"if ($vigilo_path_{h}) {{ return 404; }}\n", "high", policy))
        out.append(DefenseSpec(
            "config", "apache", f"Apache: refuse {cls.label}",
            f"{why} Example for Apache (403); LocationMatch works on the URL, so it "
            "also covers content proxied to a backend.",
            ctx.mark() + f'<LocationMatch "(?i){cls.rx}">\n'
            "    Require all denied\n</LocationMatch>\n", "high", policy))
        for served in (False, True):
            out.append(_sigma_path(ctx, cls, served, seen))
    else:
        policy = (f"Restrict {cls.label} to trusted administrator networks: allow the "
                  "listed source addresses and refuse everyone else. Do not expose them "
                  "to the internet; if they must be reachable, put them behind "
                  "authentication and a VPN.")
        why = (f"Observed: {seen}. This is a suggestion to restrict by source, not a "
               "blanket block: the interface may be a legitimate back office. List "
               "the networks that may reach it first.")
        out.append(DefenseSpec(
            "config", "nginx", f"nginx: restrict {cls.label} to trusted networks",
            f"{why} Example for nginx. Until @@REPLACE_ADMIN_NETWORK@@ is replaced "
            "nginx refuses to load the file (fail loudly, never silently open).",
            ctx.mark()
            + "# REQUIRED EDIT: list the networks allowed to reach " + cls.label
            + " (CIDR), one per line, each followed by 1.\n"
            "geo $vigilo_admin_ok {\n    default 0;\n    @@REPLACE_ADMIN_NETWORK@@ 1;\n}\n"
            f"map $uri $vigilo_adminpath_{h} {{\n    default 0;\n    \"~*{cls.rx}\" 1;\n}}\n"
            f"map \"$vigilo_adminpath_{h}$vigilo_admin_ok\" $vigilo_admindeny_{h} {{\n"
            "    default 0;\n    \"10\" 1;\n}\n"
            f"if ($vigilo_admindeny_{h}) {{ return 403; }}\n", "medium", policy))
        out.append(DefenseSpec(
            "config", "apache", f"Apache: restrict {cls.label} to trusted networks",
            f"{why} Example for Apache.",
            ctx.mark() + f'<LocationMatch "(?i){cls.rx}">\n'
            "    # REQUIRED EDIT: the networks allowed to reach it (CIDR)\n"
            "    Require ip @@REPLACE_ADMIN_NETWORK@@\n</LocationMatch>\n",
            "medium", policy))
    return out


def _sigma_path(ctx: Ctx, cls: PathClass, served: bool, seen: str) -> DefenseSpec:
    """Attempt (informational: hunting, feeds correlation) and served (the content was
    returned: 200/206) rules; the level reflects alert fidelity, not finding severity."""
    host = ctx.host
    if served:
        title = f"Exposed {cls.label} served by {host}"
        det = ["selection_path:", f"    {cls.sigma}", "selection_ok:",
               "    sc-status:", "        - 200", "        - 206"]
        cond, level = "selection_path and selection_ok", cls.level
        desc = (f"A request for {cls.label} on {host} was answered with content "
                "(200/206), so the exposed repository, configuration or backup data "
                "was served.")
        tags = ("attack.collection", "attack.t1213")
    else:
        title = f"Attempted access to {cls.label} on {host}"
        det = ["selection_path:", f"    {cls.sigma}"]
        cond, level = "selection_path", "informational"
        desc = (f"A request for {cls.label} on {host}, whatever the answer. Hunting "
                "rule: scanners probe these paths in bulk, so use it for correlation "
                "(several distinct paths from one source), not as a single alert.")
        tags = ("attack.reconnaissance", "attack.t1595.003")
    key = f"path-{'served' if served else 'attempt'}|{cls.key}"
    return DefenseSpec(
        "detection_rule", "sigma", title,
        "Needs a web-server access log mapped to the Sigma webserver fields "
        "(c-uri, sc-status). " + (f"Observed: {seen}." if seen else ""),
        _sigma(ctx, key, title, desc, det, cond, level=level,
               falsepositives=[_VIGILO_FP, "Administrators and monitoring that "
                               "legitimately request the path."], tags=tags),
        "high" if served else "medium",
        f"Alert when {cls.label} is requested, and with high priority when it is "
        "answered with content.")


# ------------------------------------------------------------------ templates

def _exposure_files(ctx: Ctx) -> list[DefenseSpec]:
    return _path_specs(ctx, classify(ctx.path), ctx.path)


def _dirlisting(ctx: Ctx) -> list[DefenseSpec]:
    path = ctx.path if ctx.path.endswith("/") else ctx.path + "/"
    policy = ("Disable automatic directory index pages: a directory URL without an "
              "index file must answer 403/404, not list its files.")
    return [
        DefenseSpec(
            "config", "nginx", f"nginx: disable directory listing for {_label(path)}",
            f"{path} served a directory index. Remove any `autoindex on;` from the "
            "location that serves it. The directive below is the server-wide default: "
            "it applies to every location that does not set autoindex itself "
            "(a bare location for this path would stop it reaching your backend, so "
            "none is emitted). There is no log-based detection for this: re-run the "
            "check to verify.",
            ctx.mark() + "autoindex off;\n", "high", policy),
        DefenseSpec(
            "config", "apache", f"Apache: disable directory listing for {_label(path)}",
            "Removes the Indexes option so Apache returns 403 instead of an index "
            "page. REQUIRED EDIT: replace the document root.",
            ctx.mark() + f'<Directory "@@REPLACE_DOCROOT@@{path.rstrip("/")}">\n'
            "    Options -Indexes\n</Directory>\n", "high", policy),
    ]


_HEADER_VALUES = {
    "content-security-policy": (
        "Content-Security-Policy-Report-Only",
        "default-src 'self'; frame-ancestors 'self'", "medium",
        "Start in report-only mode: browsers report what the policy would block "
        "without blocking it (violations appear in the browser console; add a "
        "report-uri or report-to endpoint to collect them). Once the reports show "
        "no legitimate violations, enforce it by sending the same value as "
        "Content-Security-Policy instead of Content-Security-Policy-Report-Only. "
        "Loosen the policy only for the sources the application needs.",
        "Send a Content-Security-Policy that restricts content to the site's own "
        "origin, in report-only mode first and enforced after review."),
    "x-content-type-options": (
        "X-Content-Type-Options", "nosniff", "high",
        "Stops browsers from sniffing a response into an executable type.",
        "Send X-Content-Type-Options: nosniff on every response."),
    "x-frame-options": (
        "X-Frame-Options", "SAMEORIGIN", "high",
        "Prevents the pages from being framed by other sites (clickjacking).",
        "Forbid framing of the site by other origins (X-Frame-Options: SAMEORIGIN)."),
    "referrer-policy": (
        "Referrer-Policy", "strict-origin-when-cross-origin", "high",
        "Stops full URLs from leaking to third parties.",
        "Send a Referrer-Policy that does not leak full URLs cross-origin."),
    "strict-transport-security": (
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains", "high",
        "Tells browsers to use https only. Add this on https responses and only once "
        "every subdomain serves https.",
        "Tell browsers to use https only (Strict-Transport-Security)."),
}


def _header_lines(names: list[str], fmt: str) -> str:
    out = []
    for n in names:
        header, value, _, why, _ = _HEADER_VALUES[n]
        out.append(f"# {_label(header)}: {why}\n")
        out.append(f'add_header {header} "{value}" always;\n' if fmt == "nginx"
                   else f'Header always set {header} "{value}"\n')
    return "".join(out)


def _missing_header(ctx: Ctx) -> list[DefenseSpec]:
    name = ctx.detail.removeprefix("missing:")
    spec = _HEADER_VALUES.get(name)
    if spec is None:
        return []
    header, _, conf, why, policy = spec
    return [
        DefenseSpec("config", "nginx", f"nginx: send {header}",
                    f"Example for nginx; put it in the server block (every location "
                    "that sets its own add_header must repeat it).",
                    ctx.mark() + _header_lines([name], "nginx"), conf, policy),
        DefenseSpec("config", "apache", f"Apache: send {header}",
                    "Example for Apache; requires mod_headers.",
                    ctx.mark() + _header_lines([name], "apache"), conf, policy),
    ]


def _disclosure(ctx: Ctx) -> list[DefenseSpec]:
    name = _token(ctx.detail.removeprefix("version:")) or "Server"
    policy = ("Do not advertise the software name or version in response headers or "
              "error pages: it helps an attacker match known vulnerabilities.")
    if name.lower() == "server":
        return [
            DefenseSpec("config", "nginx", "nginx: hide the server version",
                        "Example for nginx: removes the version from the Server "
                        "header and error pages (headers-more `more_clear_headers "
                        "Server;` drops the header entirely).",
                        ctx.mark() + "server_tokens off;\n", "high", policy),
            DefenseSpec("config", "apache", "Apache: hide the server version",
                        "Example for Apache: reduces the Server header to `Apache` and "
                        "removes the signature from error pages.",
                        ctx.mark() + "ServerTokens Prod\nServerSignature Off\n"
                        "# A reverse-proxied response keeps the backend's own Server "
                        "header: remove it.\n" + _ap_unset("Server"),
                        "high", policy),
        ]
    return [
        DefenseSpec("config", "nginx", f"nginx: strip the {name} header",
                    "Example for nginx: removes the banner from proxied and FastCGI "
                    "responses.",
                    ctx.mark() + f"proxy_hide_header {name};\nfastcgi_hide_header {name};\n",
                    "high", policy),
        DefenseSpec("config", "apache", f"Apache: strip the {name} header",
                    "Example for Apache: removes the banner on every response. "
                    "Requires mod_headers.",
                    ctx.mark() + _ap_unset(name), "high", policy),
    ]


_COOKIE_ATTR = {"httponly": ("HttpOnly", "httponly"),
                "secure": ("Secure", "secure"),
                "samesite": ("SameSite=Lax", "samesite=lax")}


def _cookie(ctx: Ctx) -> list[DefenseSpec]:
    name, _, rest = ctx.detail.rpartition(":missing-")
    flag = rest.lower()
    if flag not in _COOKIE_ATTR:
        return []
    attr, nginx_flag = _COOKIE_ATTR[flag]
    cookie = _token(name)
    shown = cookie or "the cookie"
    policy = (f"Mark the cookie {_label(shown)} {attr} (set it where the cookie is "
              "created; a proxy rewrite is only a stop-gap).")
    out = [DefenseSpec(
        "config", "text", f"Set {attr.split('=')[0]} on {_label(shown)} in the application",
        f"The robust fix is where the cookie is created: set the {attr} attribute "
        "in the framework's session/cookie configuration. The proxy rules below are a "
        "stop-gap for cookies you cannot change in code.",
        f"Set-Cookie: {shown}=<value>; Path=/; {attr}\n", "high", policy)]
    if cookie is None:
        return out
    if flag == "httponly" and _JS_READ_COOKIE.search(cookie):
        out[0] = DefenseSpec(
            out[0].kind, out[0].format, out[0].title,
            f"{cookie} looks like an anti-CSRF token. Scripts must read such cookies, "
            "so HttpOnly would break the application: no proxy rule is offered. "
            "Confirm in the application whether any script reads it.",
            out[0].content, "low", policy)
        return out
    flag_rx = {"httponly": "httponly", "secure": "secure", "samesite": "samesite="}[flag]
    out.append(DefenseSpec(
        "config", "nginx", f"nginx: add {attr.split('=')[0]} to cookie {cookie}",
        "Example for nginx 1.19.3 or later: adds the attribute to the Set-Cookie "
        "header of proxied responses.",
        ctx.mark() + f"proxy_cookie_flags {cookie} {nginx_flag};\n", "medium", policy))
    out.append(DefenseSpec(
        "config", "apache", f"Apache: add {attr.split('=')[0]} to cookie {cookie}",
        "Example for Apache: appends the attribute when the cookie lacks it. "
        "Requires mod_headers.",
        ctx.mark() + _ap_cookie_edit(
            f"^(?!.*(?i:;[[:space:]]*{flag_rx}))({re.escape(cookie)}=.*)$",
            f"$1; {attr}"), "medium", policy))
    return out


def _cors_modsec(ctx: Ctx, path: str) -> DefenseSpec | None:
    rid = ctx.rule_id("cors", path)
    if rid is None:
        return None
    n, kh = rid
    lit = _rx_literal(path)
    body = (
        "# DISABLED by default (detect-only): it cannot work before the allowed origin\n"
        "# is filled in. REQUIRED EDIT: replace @@REPLACE_ALLOWED_ORIGIN_REGEX@@ with the\n"
        r"# allowed origin as a regex (for example https://app\.example\.com), then remove"
        "\n# the leading '# ' from the three rule lines.\n"
        f'# SecRule REQUEST_FILENAME "@rx ^{lit}([/;]|$)" \\\n'
        f"#     \"id:{n},phase:1,t:none,t:urlDecodeUni,pass,log,msg:'Vigilo: unexpected "
        f"Origin on {_label(path)}',severity:'WARNING',tag:'vigilo-greybox',"
        f"tag:'vigilo-key:{kh}',chain\"\n"
        '#     SecRule REQUEST_HEADERS:Origin "@rx ^https?://" "t:none,chain"\n'
        '#         SecRule REQUEST_HEADERS:Origin '
        '"!@rx ^@@REPLACE_ALLOWED_ORIGIN_REGEX@@$" "t:none"\n')
    return DefenseSpec(
        "waf_rule", "modsecurity", "Log cross-origin requests from unknown origins",
        "Disabled until the allowed origin is filled in (a rule with a placeholder "
        "origin would log every legitimate request). Detection only (pass,log).",
        body, "medium",
        "Log requests to the endpoint whose Origin is outside the allow-list.")


def _cors(ctx: Ctx) -> list[DefenseSpec]:
    out: list[DefenseSpec] = []
    m = _cors_modsec(ctx, ctx.path)
    if m is not None:
        out.append(m)
    out.append(DefenseSpec(
        "detection_rule", "text", "CORS: log the request Origin and alert on unknown origins",
        "Sigma cannot express this from a default access log, which has neither the "
        "request Origin nor the Access-Control-Allow-* response headers, so no Sigma "
        "rule is generated. Add the Origin request header to the access log format "
        "(nginx $http_origin, Apache %{Origin}i), then alert on requests to "
        f"{ctx.path} whose Origin is not on the allow-list. The configuration fix is "
        "the network-wide CORS allow-list recommendation.",
        f"Log format: add the request Origin header to the access log.\n"
        f"Alert: requests to {ctx.path} whose Origin is not in the allow-list.\n",
        "medium",
        "Know which origins read credentialed responses, and alert on any other."))
    return out


_BUILDERS = {
    "exposure.files": _exposure_files,
    "exposure.dirlisting": _dirlisting,
    "headers.security": _missing_header,
    "headers.disclosure": _disclosure,
    "cors.policy": _cors,
    "cookies.flags": _cookie,
}


def _fallback(ctx: Ctx) -> list[DefenseSpec]:
    """No template for this check: carry the finding's own detection hints (already
    redacted), or one generic remediation note."""
    out = [DefenseSpec(
        "waf_rule" if h.get("type") == "waf_rule" else "detection_rule", "text",
        str(h.get("title") or "Detection hint")[:200],
        f"Guidance carried by the finding ({ctx.check_id}); no rule template exists "
        "for this check.", str(h.get("content") or ""), "low")
        for h in ctx.hints if h.get("content")]
    return out or [DefenseSpec(
        "config", "text", f"Review and remediate: {_label(ctx.title)}",
        f"No rule template exists for {ctx.check_id}.",
        f"Remediate the issue reported for {ctx.path} ({ctx.check_id}) and re-run "
        "the check.\n", "low")]


def _attribution(ctx: Ctx) -> list[DefenseSpec]:
    """The finding's own "this is the authorised Vigilo test" hint, kept next to the
    rules so a SOC can classify the alerts they raise (pseudo-query hints are dropped)."""
    return [DefenseSpec(
        "detection_rule", "text", str(h.get("title") or "Vigilo test traffic")[:200],
        "Attribution: how to recognise the authorised Vigilo grey-box requests that "
        "will trigger the rules above.", str(h.get("content") or ""), "medium")
        for h in ctx.hints if h.get("type") == "log_signature" and h.get("content")]


def build_for_finding(f: GreyboxFinding, run_id: uuid.UUID, modsec: ModSecIds,
                      date: str) -> list[DefenseSpec]:
    """The redacted defenses for one finding (pure apart from the id allocator)."""
    parts = (f.dedup_key or "").split("|", 2)
    detail = redaction.scrub(parts[2] if len(parts) == 3 else "") or ""
    url = (f.location or {}).get("url")
    ctx = Ctx(run_id=run_id, finding_id=f.id, check_id=f.check_id, detail=detail,
              title=redaction.scrub(f.title) or "", severity=f.severity,
              path=_safe_path(url), date=date,
              hints=[h for h in (f.detection_hints or []) if isinstance(h, dict)],
              modsec=modsec, origin=_origin(redaction.url(url or "")),
              verified=f.status == "verified")
    builder = _BUILDERS.get(f.check_id)
    specs = builder(ctx) if builder is not None else []
    if specs:
        specs += _attribution(ctx)
    else:
        specs = _fallback(ctx)
    return [_final(s) for s in specs]


def _final(s: DefenseSpec) -> DefenseSpec:
    rationale = redaction.scrub(s.rationale) or ""
    if s.policy:
        rationale = f"Policy: {redaction.scrub(s.policy)} {rationale}"
    return DefenseSpec(s.kind, s.format, (redaction.scrub(s.title) or "")[:300],
                       rationale, redaction.text(s.content) or "", s.confidence)


# ------------------------------------------------------------------ config statements
#
# nginx and Apache snippets are split into statements so that the download can place
# each in its context, merge duplicates by meaning (not by text) and so that a finding's
# snippet can be recognised as already covered by a network-wide one.

_NG_HTTP = {"map", "geo", "limit_req_zone", "server", "upstream", "log_format"}
_AP_GLOBAL = {"ServerTokens", "ServerSignature"}


@dataclass(frozen=True)
class Stmt:
    context: str       # nginx: http|server; apache: global|vhost
    key: str           # semantic identity (see _ng_key, _ap_key)
    text: str          # the statement, with its leading comments
    body: str          # normalised text without comments (for comparison)
    origin: str        # service it belongs to ("" if unknown)


def placeholders(text: str) -> list[str]:
    return sorted(set(_SENTINEL.findall(text)))


def _ng_key(body: str) -> str:
    first = body.split(None, 1)[0] if body.split() else ""
    toks = body.rstrip(";").split()
    if first == "add_header" and len(toks) > 1:
        return f"add_header:{toks[1].lower()}"
    if first in ("map", "geo"):
        m = re.match(r"(?:map|geo)\s+[^{]*?(\$\w+)\s*\{", body)
        return f"{first}:{m.group(1)}" if m else body
    if first == "limit_req_zone":
        m = re.search(r"zone=(\w+)", body)
        return f"limit_req_zone:{m.group(1)}" if m else body
    if first == "limit_req":
        m = re.search(r"zone=(\w+)", body)
        return f"limit_req:{m.group(1)}" if m else body
    if first in ("server_tokens", "limit_req_status", "autoindex"):
        return first
    if first in ("proxy_hide_header", "fastcgi_hide_header") and len(toks) > 1:
        return f"{first}:{toks[1].lower()}"
    if first == "proxy_cookie_flags" and len(toks) > 1:
        return f"pcf:{toks[1]}"
    return body


def nginx_statements(content: str) -> list[Stmt]:
    out: list[Stmt] = []
    comments: list[str] = []
    origin = ""
    buf: list[str] = []
    depth = 0
    quote_ch = ""
    i, n = 0, len(content)

    def finish() -> None:
        nonlocal buf, comments
        text = "".join(buf).strip()
        buf = []
        if not text:
            return
        body = _norm(text)
        first = body.split(None, 1)[0]
        out.append(Stmt("http" if first in _NG_HTTP else "server", _ng_key(body),
                        ("\n".join(comments) + "\n" if comments else "") + text,
                        body, origin))
        comments = []

    while i < n:
        c = content[i]
        if quote_ch:
            buf.append(c)
            if c == "\\" and i + 1 < n:
                buf.append(content[i + 1])
                i += 1
            elif c == quote_ch:
                quote_ch = ""
        elif c == "#":
            eol = content.find("\n", i)
            eol = n if eol < 0 else eol
            line = content[i:eol]
            if depth == 0 and not "".join(buf).strip():
                m = re.match(r"#\s*vigilo-service:\s*(\S*)", line)
                if m:
                    origin = m.group(1)
                else:
                    comments.append(line)
            else:
                buf.append(line)
            i = eol
            continue
        elif c in "\"'":
            quote_ch = c
            buf.append(c)
        elif c == "{":
            depth += 1
            buf.append(c)
        elif c == "}":
            depth -= 1
            buf.append(c)
            if depth == 0:
                finish()
        elif c == ";" and depth == 0:
            buf.append(c)
            finish()
        else:
            buf.append(c)
        i += 1
    finish()
    return out


def _ap_key(body: str) -> str:
    m = re.match(r"Header\s+(always\s+)?(set|unset)\s+(\S+)", body)
    if m:
        return f"hdr:{'always' if m.group(1) else 'ok'}:{m.group(2)}:{m.group(3).lower()}"
    first = body.split(None, 1)[0]
    if first in _AP_GLOBAL:
        return first
    return body


def apache_statements(content: str) -> list[Stmt]:
    out: list[Stmt] = []
    comments: list[str] = []
    origin = ""
    block: list[str] = []
    depth = 0
    for line in content.splitlines():
        s = line.strip()
        if depth == 0:
            if not s:
                continue
            if s.startswith("#"):
                m = re.match(r"#\s*vigilo-service:\s*(\S*)", s)
                if m:
                    origin = m.group(1)
                else:
                    comments.append(line.rstrip())
                continue
        if re.match(r"<\w+[\s>]", s):
            depth += 1
        block.append(line.rstrip())
        if re.match(r"</\w+>", s):
            depth -= 1
        if depth == 0:
            text = "\n".join(block).strip("\n")
            body = _norm("\n".join(b for b in block if not b.strip().startswith("#")))
            first = body.split(None, 1)[0]
            ctx = "global" if first in _AP_GLOBAL or first.startswith("<VirtualHost") \
                else "vhost"
            out.append(Stmt(ctx, _ap_key(body), ("\n".join(comments) + "\n" if comments
                                                 else "") + text, body, origin))
            comments, block = [], []
    return out


def config_statements(fmt: str, content: str) -> list[Stmt]:
    return nginx_statements(content) if fmt == "nginx" else apache_statements(content)


def merge_pcf(a: Stmt, b: Stmt) -> Stmt:
    """Two ``proxy_cookie_flags <name> ...`` statements for the same cookie become one
    with the union of the flags (nginx would otherwise see two directives)."""
    ta, tb = a.body.rstrip(";").split(), b.body.rstrip(";").split()
    flags = list(ta[2:]) + [f for f in tb[2:] if f not in ta[2:]]
    body = f"proxy_cookie_flags {ta[1]} {' '.join(flags)};"
    return Stmt(a.context, a.key, a.text.rsplit("\n", 1)[0] + "\n" + body
                if "\n" in a.text else body, body, a.origin)


def covered(fmt: str, content: str, others: list[str]) -> bool:
    """True if every statement of ``content`` is already in ``others`` (same meaning),
    for nginx and Apache snippets; exact normalised equality for other formats."""
    if fmt not in ("nginx", "apache"):
        return any(_norm(content) == _norm(o) for o in others)
    have: dict[str, Stmt] = {}
    for o in others:
        for s in config_statements(fmt, o):
            have[s.key] = merge_pcf(have[s.key], s) if s.key in have \
                and s.key.startswith("pcf:") else s
    mine = config_statements(fmt, content)
    if not mine:
        return False
    for s in mine:
        h = have.get(s.key)
        if h is None:
            return False
        if s.key.startswith("pcf:"):
            if not set(s.body.rstrip(";").split()[2:]) <= set(h.body.rstrip(";").split()[2:]):
                return False
        elif s.body != h.body:
            return False
    return True


# ------------------------------------------------------------------ persistence


def run_date(run: GreyboxRun | None) -> str:
    """The date rules carry: the run's own time, so output is deterministic."""
    at = None
    if run is not None:
        at = run.finished_at or run.started_at or run.created_at
    return (at or datetime(1970, 1, 1, tzinfo=timezone.utc)).strftime("%Y/%m/%d")


async def generate(session: AsyncSession, run_id: uuid.UUID, gtx: GraphTx, *,
                   agent_id: uuid.UUID | None = None) -> int:
    """Create defenses (rows, graph nodes, mitigates edges, events) for every verified
    or candidate finding that has none yet. Defenses with identical content for several
    findings are one row addressing all of them (``finding_ids``, one ``mitigates`` edge
    each). Returns the number of rows created."""
    findings = (await session.scalars(
        select(GreyboxFinding).where(
            GreyboxFinding.run_id == run_id,
            GreyboxFinding.status.in_(("verified", "candidate")))
        .order_by(GreyboxFinding.created_at, GreyboxFinding.id))).all()
    existing = (await session.scalars(
        select(GreyboxDefense).where(GreyboxDefense.run_id == run_id)
        .order_by(GreyboxDefense.created_at, GreyboxDefense.id))).all()
    modsec = ModSecIds()
    have: set[str] = set()
    seen: dict[tuple[str, str], GreyboxDefense] = {}
    for d in existing:
        if d.format == "modsecurity":
            modsec.seed(d.content)
        if d.scope == "finding":
            have |= {str(x) for x in (d.finding_ids or [])}
            if d.finding_id is not None:
                have.add(str(d.finding_id))
            seen[(d.format, _norm(d.content))] = d
    run = await session.get(GreyboxRun, run_id)
    date = run_date(run)
    created = 0
    for f in findings:
        if str(f.id) in have:
            continue
        status = "proposed" if f.status == "verified" else "unverified"
        fnode = await session.get(GreyboxGraphNode, f.node_id) if f.node_id else None
        for spec in build_for_finding(f, run_id, modsec, date):
            prior = seen.get((spec.format, _norm(spec.content)))
            if prior is not None:
                if str(f.id) not in (prior.finding_ids or []):
                    prior.finding_ids = [*(prior.finding_ids or []), str(f.id)]
                pnode = await session.get(GreyboxGraphNode, prior.node_id) \
                    if prior.node_id else None
                if status == "proposed" and prior.status == "unverified":
                    prior.status = "proposed"
                    if pnode is not None:
                        pnode.status = "proposed"
                if pnode is not None and fnode is not None and fnode.run_id == run_id:
                    await gtx.edge(pnode, fnode, "mitigates")
                continue
            did = uuid.uuid4()
            node = await gtx.node(
                "defense", f"defense:{did}", spec.title, status,
                data={"kind": spec.kind, "format": spec.format},
                agent_id=agent_id, finding_id=f.id)
            row = GreyboxDefense(
                id=did, run_id=run_id, finding_id=f.id, node_id=node.id,
                scope="finding", finding_ids=[str(f.id)],
                kind=spec.kind, format=spec.format, title=spec.title,
                rationale=spec.rationale, content=spec.content,
                confidence=spec.confidence, status=status)
            session.add(row)
            seen[(spec.format, _norm(spec.content))] = row
            if fnode is not None and fnode.run_id == run_id:
                await gtx.edge(node, fnode, "mitigates")
            ev = await events.emit(
                session, run_id, "defense.proposed",
                f"defense proposed: {spec.title}",
                data={"defense_id": str(did), "finding_id": str(f.id),
                      "kind": spec.kind, "format": spec.format, "title": spec.title,
                      "scope": "finding", "asset_id": None,
                      "finding_ids": [str(f.id)]},
                refs={"finding_id": f.id, "node_ids": [node.id]},
                agent_id=agent_id)
            node.event_seq = ev.seq
            node.last_event_seq = ev.seq
            created += 1
    return created


# ================================================================== network (10.7)
#
# Asset-scoped recommendations derived from the live surface analysis
# (``data.surface``, see surface.py): one template per class of observation, each with
# a rationale that cites the observed evidence. Same guarantees as above: deterministic,
# no network, every field redacted; target-derived text in titles and rationales goes
# through ``_label`` and values placed in rules are percent-encoded paths or tokens.

_FLAG_ATTR = {"httponly": "HttpOnly", "secure": "Secure", "samesite": "SameSite=Lax"}


@dataclass
class AssetSpec:
    asset: GreyboxAsset            # the protected host / service / endpoint
    spec: DefenseSpec
    finding_ids: list[uuid.UUID]


def _np(path: object) -> str:
    """A target-derived path, redacted first (before any regex escaping can disguise a
    registered secret) and then percent-encoded to the conservative rule charset."""
    return quote(redaction.scrub(str(path)) or "", safe=_PATH_SAFE)[:200]


def _counts_text(counts: dict, names: list[str], total: int) -> str:
    return ", ".join(f"{_label(n)} ({counts.get(n, {}).get('missing', 0)}/{total})"
                     for n in names)


def _fids(findings: list[GreyboxFinding], asset_ids: set[uuid.UUID],
          prefixes: tuple[str, ...]) -> list[uuid.UUID]:
    return [f.id for f in findings
            if f.affected_asset_id in asset_ids and f.check_id.startswith(prefixes)]


def _finding_class(f: GreyboxFinding) -> str:
    return classify(_safe_path((f.location or {}).get("url"))).key


def _host_of(origin: str) -> str:
    host = urlsplit(origin).hostname or ""
    return host if re.fullmatch(r"[a-z0-9.\-]{1,253}", host) else "@@REPLACE_HOST@@"


def build_for_assets(services: list[GreyboxAsset], hosts: dict[uuid.UUID, GreyboxAsset],
                     endpoints: dict[uuid.UUID, list[GreyboxAsset]],
                     findings: list[GreyboxFinding], run_id: uuid.UUID,
                     modsec: ModSecIds, date: str) -> list[AssetSpec]:
    """The redacted asset-scoped recommendations (pure apart from the id allocator)."""
    out: list[AssetSpec] = []
    banners: dict[uuid.UUID, dict] = {}
    for svc in services:
        s = (svc.data or {}).get("surface")
        if not isinstance(s, dict):
            continue
        eps = endpoints.get(svc.id, [])
        ep_ids = {e.id for e in eps} | {svc.id}
        https = bool(s.get("tls", {}).get("https"))
        origin = _origin(svc.key)
        ctx = Ctx(run_id=run_id, finding_id=svc.id, check_id="network", detail="",
                  title="", severity="medium", path="/", date=date, modsec=modsec,
                  origin=origin)
        mark = ctx.mark()
        where = _label(svc.label)

        # 1. service-wide security headers
        sh = s.get("security_headers", {})
        names = [n for n in sh.get("missing", []) if n in _HEADER_VALUES]
        if names:
            total = int(sh.get("evaluated", 0))
            why = (f"{len(names)} security header(s) were absent from responses of "
                   f"{where}: {_counts_text(sh.get('counts', {}), names, total)} "
                   "(missing/evaluated pages). ")
            policy = ("Send these security headers on every response: "
                      + "; ".join(_HEADER_VALUES[n][4] for n in names))
            f_ids = _fids(findings, ep_ids, ("headers.security",))
            out += [
                AssetSpec(svc, DefenseSpec(
                    "hardening", "nginx", f"nginx: add the missing security headers to {where}",
                    why + "Example for nginx: put the block in the server context; a "
                    "location that sets its own add_header must repeat it (nginx does "
                    "not inherit add_header into such a location).",
                    mark + _header_lines(names, "nginx"), "high", policy), f_ids),
                AssetSpec(svc, DefenseSpec(
                    "hardening", "apache", f"Apache: add the missing security headers to {where}",
                    why + "Example for Apache; requires mod_headers.",
                    mark + _header_lines(names, "apache"), "high", policy), f_ids)]

        # 2. version banners, per host (collected below)
        vd = s.get("version_disclosure") or []
        if vd and svc.parent_id in hosts:
            b = banners.setdefault(svc.parent_id,
                                   {"vd": set(), "svc": [], "ids": set(), "origin": origin})
            b["vd"] |= set(vd)
            b["svc"].append((where, _label(str(s.get("server") or ""))))
            b["ids"] |= ep_ids

        # 3. sensitive paths, one policy per class
        sens = [x for x in s.get("sensitive_paths", []) if isinstance(x, dict)]
        classes: dict[str, tuple[PathClass, list[str]]] = {}
        for x in sens:
            if not str(x.get("path", "")).startswith("/"):
                continue
            p = _np(x["path"])
            cls = classify(p)
            classes.setdefault(cls.key, (cls, []))[1].append(
                f"{_label(str(x['path']))} ({_label(str(x.get('reason', '')))})")
        for key in sorted(classes):
            cls, seen = classes[key]
            f_ids = [f.id for f in findings if f.affected_asset_id in ep_ids
                     and f.check_id.startswith("exposure.files")
                     and _finding_class(f) == key]
            for spec in _path_specs(ctx, cls, f"{', '.join(seen[:4])} on {where}"):
                out.append(AssetSpec(svc, spec, f_ids))

        # 4. login endpoints: rate limiting + ModSecurity counter
        by_key = {e.key: e for e in eps}
        for path in list(s.get("auth_paths", []))[:3]:
            ep = by_key.get(svc.key + str(path))
            if ep is None:
                continue
            p = _np(path)
            lit = _rx_literal(p.rstrip("/") or "/")
            h = key_hash(f"{origin}|login|{p}")[:6]
            f_ids = [f.id for f in findings if f.affected_asset_id == ep.id]
            shown = _label(str(path))
            policy = (f"Limit credential submissions: at most about 5 POSTs per minute "
                      f"per client address to {shown} (a small burst is tolerated), "
                      "answering 429 beyond that. Count only submissions, not page "
                      "views, and match /login and /login/ in any case.")
            out.append(AssetSpec(ep, DefenseSpec(
                "hardening", "nginx", f"nginx: rate-limit logins on {shown}",
                f"{shown} on {where} is a login endpoint (a password form or "
                "authentication path). Limiting the request rate slows credential "
                "stuffing and brute force. Example for nginx: a map keyed on method "
                "and URI gives an empty key (not counted) to every other request, so "
                "no location is needed and routing is untouched. Tune the rate to "
                "real traffic.",
                mark
                + f"# Login throttle for {shown}: POST only, any case, with or without a "
                "trailing slash.\n"
                "# Behind a CDN or reverse proxy $binary_remote_addr is the proxy's "
                "address, so all users would share one counter: enable the realip module\n"
                "# (set_real_ip_from <trusted proxy range>; real_ip_header "
                "X-Forwarded-For;) so the key is the real client.\n"
                f'map "$request_method:$uri" $vigilo_login_key_{h} {{\n'
                f'    default "";\n    "~*^POST:{lit}/?$" $binary_remote_addr;\n}}\n'
                f"limit_req_zone $vigilo_login_key_{h} zone=vigilo_login_{h}:10m "
                "rate=5r/m;\n"
                f"limit_req zone=vigilo_login_{h} burst=5 nodelay;\n"
                "limit_req_status 429;\n", "medium", policy), f_ids))
            ids = [ctx.rule_id("login", p, str(i)) for i in range(1, 7)]
            if all(i is not None for i in ids):
                (a, ka), (b_, kb), (c, kc), (d, kd), (e_, ke), (g, kg) = ids  # type: ignore[misc]
                tag = lambda kh: f"tag:'vigilo-greybox',tag:'vigilo-key:{kh}'"  # noqa: E731
                var, ipvar = f"vigilo_login_{h}", f"vigilo_ip_{h}"
                out.append(AssetSpec(ep, DefenseSpec(
                    "waf_rule", "modsecurity", f"ModSecurity: throttle logins on {shown}",
                    f"Counts POSTs to {shown} per client address in a fixed 60 second "
                    "window (the expiry is set only when the counter is created, so "
                    "retrying does not extend the lock-out) and refuses more than 10 "
                    "with 429. Persistent IP collections need SecDataDir; "
                    "libmodsecurity v3 and Coraza keep them in memory only.",
                    "# CONFIGURE: the client address used as the key (first rule). "
                    "REMOTE_ADDR is the peer: behind a CDN or reverse proxy that is the\n"
                    "# proxy, so all users would share one counter. Set it from the "
                    "proxy's header (for example %{REQUEST_HEADERS.X-Forwarded-For})\n"
                    "# ONLY if a proxy you trust sets that header and clients cannot "
                    "forge it.\n"
                    f'SecAction "id:{a},phase:1,t:none,pass,nolog,'
                    f"setvar:'tx.{ipvar}=%{{REMOTE_ADDR}}',{tag(ka)}\"\n"
                    f'SecRule REQUEST_METHOD "@streq POST" "id:{b_},phase:1,t:none,pass,'
                    f'nolog,{tag(kb)},chain"\n'
                    f'    SecRule REQUEST_FILENAME "@rx (?i)^{lit}/?$" "t:none,'
                    f"t:urlDecodeUni,t:removeNulls,t:normalizePath,setvar:tx.{var}=1\"\n"
                    f'SecRule TX:{var.upper()} "@eq 1" "id:{c},phase:1,t:none,pass,nolog,'
                    f"initcol:ip=%{{tx.{ipvar}}},{tag(kc)}\"\n"
                    f'SecRule TX:{var.upper()} "@eq 1" "id:{d},phase:1,t:none,pass,nolog,'
                    f'{tag(kd)},chain"\n'
                    f'    SecRule &IP:{var.upper()} "@eq 0" "t:none,'
                    f"setvar:ip.{var}=0,expirevar:ip.{var}=60\"\n"
                    f'SecRule TX:{var.upper()} "@eq 1" "id:{e_},phase:1,t:none,pass,nolog,'
                    f"setvar:ip.{var}=+1,{tag(ke)}\"\n"
                    f'SecRule IP:{var.upper()} "@gt 10" "id:{g},phase:1,t:none,deny,'
                    f"status:429,log,msg:'Vigilo: too many logins to {shown}',"
                    f"severity:'WARNING',{tag(kg)}\"\n", "medium", policy), f_ids))

        # 5. strict CORS allow-list
        cors = s.get("cors", {})
        if cors.get("reflects_origin") or cors.get("wildcard"):
            cpaths = [_np(x) for x in cors.get("paths", [])
                      if str(x).startswith("/")][:5]
            mode = ("reflects the request Origin" if cors.get("reflects_origin")
                    else "answers Access-Control-Allow-Origin: *")
            creds = " with Access-Control-Allow-Credentials: true" \
                if cors.get("allows_credentials") else ""
            why = (f"{where} {mode}{creds} on {len(cpaths)} endpoint(s): "
                   f"{', '.join(_label(x) for x in cpaths) or 'n/a'}. Any origin could "
                   "read credentialed responses. REQUIRED EDIT: replace the placeholder "
                   "origin with the real front-end origin(s). ")
            policy = ("Allow cross-origin reads only for an explicit list of "
                      "front-end origins: return Access-Control-Allow-Origin (and "
                      "-Allow-Credentials) only for those, never reflect the request "
                      "Origin and never combine * with credentials.")
            h = key_hash(origin)[:6]
            f_ids = _fids(findings, ep_ids, ("cors.",))
            out.append(AssetSpec(svc, DefenseSpec(
                "hardening", "nginx", f"nginx: strict CORS allow-list for {where}",
                why + "Example for nginx: the response headers are set at server "
                "level (so no location override drops the other add_header "
                "directives), the backend's own CORS headers are hidden first (they "
                "would otherwise still reflect any origin) and an empty value makes "
                "nginx omit the header. The allow-list applies to every response of "
                "this server.",
                mark
                + "# REQUIRED EDIT: replace @@REPLACE_ALLOWED_ORIGIN@@ with the allowed "
                "origin, for example https://app.example.com; add one line per origin.\n"
                f'map $http_origin $vigilo_cors_origin_{h} {{\n    default "";\n'
                f'    "@@REPLACE_ALLOWED_ORIGIN@@" $http_origin;\n}}\n'
                f"map $vigilo_cors_origin_{h} $vigilo_cors_creds_{h} {{\n"
                '    default "";\n    "~." "true";\n}\n'
                "proxy_hide_header Access-Control-Allow-Origin;\n"
                "proxy_hide_header Access-Control-Allow-Credentials;\n"
                f"add_header Access-Control-Allow-Origin $vigilo_cors_origin_{h} always;\n"
                f"add_header Access-Control-Allow-Credentials $vigilo_cors_creds_{h} "
                "always;\n"
                "add_header Vary Origin always;\n", "high", policy), f_ids))
            out.append(AssetSpec(svc, DefenseSpec(
                "hardening", "apache", f"Apache: strict CORS allow-list for {where}",
                why + "Example for Apache; requires mod_headers and mod_setenvif. The "
                "backend's own CORS headers are removed first.",
                mark
                + "# REQUIRED EDIT: replace @@REPLACE_ALLOWED_ORIGIN_REGEX@@ with the "
                r"allowed origin as a regex, for example https://app\.example\.com" "\n"
                'SetEnvIf Origin "^@@REPLACE_ALLOWED_ORIGIN_REGEX@@$" VIGILO_ORIGIN_OK=$0\n'
                + _ap_unset("Access-Control-Allow-Origin")
                + _ap_unset("Access-Control-Allow-Credentials")
                +
                'Header always set Access-Control-Allow-Origin "%{VIGILO_ORIGIN_OK}e" '
                "env=VIGILO_ORIGIN_OK\n"
                'Header always set Access-Control-Allow-Credentials "true" '
                "env=VIGILO_ORIGIN_OK\n"
                "Header always merge Vary Origin\n", "high", policy), f_ids))

        # 6. cookie defaults, per cookie (never a catch-all)
        ck = s.get("cookie_flags", {})
        ng_lines, ap_lines, named = [], [], []
        for name in sorted(ck):
            tok = _token(redaction.scrub(str(name)) or "")    # before any escaping
            f = ck[name]
            if tok is None:
                continue
            need = []
            if not f.get("httponly") and not _JS_READ_COOKIE.search(tok):
                need.append("httponly")
            if f.get("samesite") is None:
                need.append("samesite")
            if https and not f.get("secure"):
                need.append("secure")
            if not need:
                continue
            named.append(f"{tok} ({', '.join(_FLAG_ATTR[k].split('=')[0] for k in need)})")
            ng_lines.append(f"proxy_cookie_flags {tok} "
                            f"{' '.join(_COOKIE_ATTR[k][1] for k in need)};\n")
            for k in need:
                rx = "samesite=" if k == "samesite" else k
                ap_lines.append(_ap_cookie_edit(
                    f"^(?!.*(?i:;[[:space:]]*{rx}))({re.escape(tok)}=.*)$",
                    f"$1; {_FLAG_ATTR[k]}"))
        if named:
            skipped = [n for n in ck if _JS_READ_COOKIE.search(str(n))]
            why = (f"{len(ck)} cookie(s) observed on {where}; flags missing on "
                   f"{', '.join(named)}. The robust fix is in the application's cookie "
                   "settings; these per-cookie rules cover cookies you cannot change in "
                   "code. Only the named cookies are touched (a cookie that scripts "
                   "must read, such as an XSRF token, must not become HttpOnly: "
                   + (f"{', '.join(_label(str(n)) for n in skipped)} left without "
                      "HttpOnly" if skipped else "names matching csrf/xsrf are excluded")
                   + "; check that no other listed cookie is read by a script). ")
            policy = ("Mark each session cookie HttpOnly, Secure (on https) and "
                      "SameSite=Lax, except cookies that scripts must read.")
            f_ids = _fids(findings, ep_ids, ("cookies.",))
            out += [AssetSpec(svc, DefenseSpec(
                "hardening", "nginx", f"nginx: default cookie flags for {where}",
                why + "Example for nginx 1.19.3 or later (matches the cookie by name; "
                "it never rewrites cookies that already set SameSite).",
                mark + "".join(ng_lines), "medium", policy), f_ids),
                AssetSpec(svc, DefenseSpec(
                    "hardening", "apache", f"Apache: default cookie flags for {where}",
                    why + "Example for Apache; requires mod_headers.",
                    mark + "".join(ap_lines), "medium", policy), f_ids)]

        # 7. https redirect + HSTS
        if not https:
            host = _host_of(origin)
            ep_n = s.get("endpoints", {}).get("auth_like", 0)
            why = (f"{where} is served over plain http"
                   + (f" and has {ep_n} login endpoint(s)" if ep_n else "")
                   + (f"; {len(ck)} cookie(s) are set over it" if ck else "")
                   + ", so credentials and sessions cross the network unencrypted. ")
            policy = ("Serve the site over https only: redirect every http request to "
                      "https, then send HSTS so browsers stop trying http.")
            out += [AssetSpec(svc, DefenseSpec(
                "hardening", "nginx", f"nginx: redirect {where} to https and enable HSTS",
                why + "Example for nginx (the host name comes from the observed "
                "service; it replaces or merges with your existing port 80 server).",
                mark + "# Redirect plain http to https.\n"
                f"server {{\n    listen 80;\n    server_name {host};\n"
                f"    return 301 https://{host}$request_uri;\n}}\n"
                "# In the https server block, once https works (HSTS is ignored over "
                "http):\n"
                '# add_header Strict-Transport-Security "max-age=31536000; '
                'includeSubDomains" always;\n', "medium", policy), []),
                AssetSpec(svc, DefenseSpec(
                    "hardening", "apache", f"Apache: redirect {where} to https and enable HSTS",
                    why + "Example for Apache; requires mod_rewrite.",
                    mark + "# Redirect plain http to https.\n"
                    f"<VirtualHost *:80>\n    ServerName {host}\n"
                    "    RewriteEngine On\n"
                    f"    RewriteRule ^ https://{host}%{{REQUEST_URI}} [R=301,L]\n"
                    "</VirtualHost>\n"
                    "# In the https VirtualHost, once https works (HSTS is ignored over "
                    "http):\n"
                    '# Header always set Strict-Transport-Security "max-age=31536000; '
                    'includeSubDomains"\n', "medium", policy), [])]

    # 2 (cont.). banners, one recommendation per host
    for hid, b in sorted(banners.items(), key=lambda kv: hosts[kv[0]].key):
        host = hosts[hid]
        shown = "; ".join(f"{w}: {s or 'n/a'}" for w, s in b["svc"][:4])
        why = (f"The server on {_label(host.label)} advertises its software version "
               f"({', '.join(sorted(b['vd']))}): {shown}. Version banners help an "
               "attacker match known vulnerabilities. ")
        policy = ("Do not advertise the software name or version in the Server and "
                  "X-Powered-By headers or in error pages.")
        mark = f"# vigilo-service: {b['origin']}\n" if b["origin"] else ""
        ng, ap = [], []
        if "server" in b["vd"]:
            ng.append("server_tokens off;\n")
            ap.append("ServerTokens Prod\nServerSignature Off\n"
                      "# A reverse-proxied response keeps the backend's own Server "
                      "header: remove it.\n" + _ap_unset("Server"))
        if "x-powered-by" in b["vd"]:
            ng.append("proxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;\n")
            ap.append(_ap_unset("X-Powered-By"))
        f_ids = _fids(findings, b["ids"], ("headers.disclosure",))
        out += [AssetSpec(host, DefenseSpec(
            "hardening", "nginx", f"nginx: hide version banners on {_label(host.label)}",
            why + "Example for nginx.", mark + "".join(ng), "high", policy), f_ids),
            AssetSpec(host, DefenseSpec(
                "hardening", "apache", f"Apache: hide version banners on {_label(host.label)}",
                why + "Example for Apache.", mark + "".join(ap), "high", policy), f_ids)]
    # passive network signals (third parties, leaks, edge, HTTP posture): infra_defenses.py
    from src.greybox_web import infra_defenses
    out += infra_defenses.build(services, endpoints, findings, run_id)
    return [AssetSpec(a.asset, _final(a.spec), a.finding_ids) for a in out]


async def generate_network(session: AsyncSession, run_id: uuid.UUID, gtx: GraphTx, *,
                           agent_id: uuid.UUID | None = None) -> int:
    """Asset-scoped defenses (rows, asset-graph ``defense`` nodes with ``protects``
    edges, events) from the final service surfaces. Idempotent per (asset, title).
    Returns the number created."""
    assets = (await session.scalars(
        select(GreyboxAsset).where(
            GreyboxAsset.run_id == run_id,
            GreyboxAsset.kind.in_(("host", "service", "endpoint")),
            GreyboxAsset.in_scope.is_(True)).order_by(GreyboxAsset.key))).all()
    hosts = {a.id: a for a in assets if a.kind == "host"}
    services = [a for a in assets if a.kind == "service"]
    endpoints: dict[uuid.UUID, list[GreyboxAsset]] = {}
    for a in assets:
        if a.kind == "endpoint" and a.parent_id is not None:
            endpoints.setdefault(a.parent_id, []).append(a)
    findings = list((await session.scalars(
        select(GreyboxFinding).where(
            GreyboxFinding.run_id == run_id,
            GreyboxFinding.status.in_(("verified", "candidate")))
        .order_by(GreyboxFinding.created_at, GreyboxFinding.id))).all())
    existing = (await session.execute(
        select(GreyboxDefense.asset_id, GreyboxDefense.title, GreyboxDefense.content,
               GreyboxDefense.format).where(GreyboxDefense.run_id == run_id))).all()
    have = {(a, t) for a, t, _, _ in existing if a is not None}
    modsec = ModSecIds()
    for _, _, c, fmt in existing:
        if fmt == "modsecurity":
            modsec.seed(c)
    run = await session.get(GreyboxRun, run_id)
    date = run_date(run)
    created = 0
    for item in build_for_assets(services, hosts, endpoints, findings, run_id, modsec,
                                 date):
        spec, target = item.spec, item.asset
        if (target.id, spec.title) in have or not spec.content.strip():
            continue
        have.add((target.id, spec.title))
        did = uuid.uuid4()
        fids = [str(x) for x in item.finding_ids]
        dnode = await gtx.defense_asset(
            did, spec.title, target, first_seen_seq=0,
            data={"kind": spec.kind, "format": spec.format, "scope": "asset",
                  "defense_id": str(did), "confidence": spec.confidence})
        session.add(GreyboxDefense(
            id=did, run_id=run_id, finding_id=None, asset_id=target.id,
            scope="asset", finding_ids=fids, node_id=dnode.id, kind=spec.kind,
            format=spec.format, title=spec.title, rationale=spec.rationale,
            content=spec.content, confidence=spec.confidence, status="proposed"))
        ev = await events.emit(
            session, run_id, "defense.proposed", f"defense proposed: {spec.title}",
            data={"defense_id": str(did), "finding_id": None, "kind": spec.kind,
                  "format": spec.format, "title": spec.title, "scope": "asset",
                  "asset_id": str(target.id), "finding_ids": fids},
            refs={"asset_ids": [target.id, dnode.id]}, agent_id=agent_id)
        dnode.first_seen_seq = ev.seq
        created += 1
    return created
