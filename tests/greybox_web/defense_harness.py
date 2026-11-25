"""Validation harness for the generated defenses.

Tier 1, always: structural linters in pure Python for every format.
  * ModSecurity: the SecRule/SecAction grammar subset Vigilo emits (quoting, phases,
    actions, transformations, operators, chains, unique ids in the Vigilo block).
  * nginx: tokeniser and block parser, directive context, duplicate directives,
    undefined variables and zones.
  * Apache: section balance, directive context, ``Header`` syntax, regexes.
  * Sigma: schema, portable field vocabulary, stable ids, unique titles; and pySigma
    (rule validators and a backend conversion) when it is installed.
Tier 2, when the binaries exist (skipped otherwise): ``nginx -t`` and ``httpd -t`` on the
assembled bundle in a temporary prefix, and a LIVE replay: nginx / Apache on a free
loopback port in front of the synthetic target, the run's recorded exchanges replayed
through them (the vulnerable requests are now blocked or fixed, the baseline crawl still
works) plus evasions (case, encoding, dot segments, ``;`` parameters, trailing slash)
against a lenient backend that serves any path.

ModSecurity / Coraza engines are not exercised here (maintainer decision: vendor-neutral
focus); the ModSecurity output is linted only.
"""
from __future__ import annotations

import http.client
import io
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from src.greybox_web import defenses as gd

# ====================================================================== shared


def fill_placeholders(text: str, *, admin_network: str = "192.0.2.0/24",
                      docroot: str = "/tmp") -> str:
    """What a defender does before deploying: replace every ``@@REPLACE_...@@``."""
    values = {
        "@@REPLACE_ALLOWED_ORIGIN@@": "https://allowed.test",
        "@@REPLACE_ALLOWED_ORIGIN_REGEX@@": r"https://allowed\.test",
        "@@REPLACE_ADMIN_NETWORK@@": admin_network,
        "@@REPLACE_DOCROOT@@": docroot,
        "@@REPLACE_HOST@@": "localhost",
    }
    for k, v in values.items():
        text = text.replace(k, v)
    return text


def _split_quoted(line: str) -> list[str]:
    """Whitespace-separated words, honouring double quotes with backslash escapes."""
    out, buf, in_q, i = [], [], False, 0
    started = False
    while i < len(line):
        c = line[i]
        if in_q:
            if c == "\\" and i + 1 < len(line) and line[i + 1] in '"\\':
                buf.append(line[i + 1])
                i += 2
                continue
            if c == '"':
                in_q = False
            else:
                buf.append(c)
        elif c == '"':
            in_q = True
            started = True
        elif c.isspace():
            if buf or started:
                out.append("".join(buf))
                buf, started = [], False
        else:
            buf.append(c)
        i += 1
    if in_q:
        raise ValueError("unbalanced double quote")
    if buf or started:
        out.append("".join(buf))
    return out


def _py_regex(rx: str) -> "re.Pattern[str]":
    """Compile a PCRE as Python re (the subset Vigilo emits: POSIX classes translated)."""
    return re.compile(rx.replace("[[:space:]]", r"\s"))


# ====================================================================== ModSecurity

_MS_ACTIONS = {"id", "phase", "t", "pass", "nolog", "log", "deny", "status", "msg",
               "severity", "tag", "chain", "setvar", "initcol", "expirevar",
               "deprecatevar", "block", "capture", "ctl", "logdata", "rev", "ver"}
_MS_TRANSFORMS = {"none", "urlDecodeUni", "urlDecode", "removeNulls", "normalizePath",
                  "normalisePath", "lowercase", "compressWhitespace", "htmlEntityDecode"}
_MS_OPERATORS = {"rx", "streq", "eq", "gt", "lt", "ge", "le", "contains", "beginsWith",
                 "endsWith", "within", "ipMatch", "pm"}
_MS_SEVERITY = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO",
                "DEBUG"}
_MS_VAR = re.compile(r"[&!]?[A-Z][A-Z_]*(:[A-Za-z0-9_.\-/*]+)?")
_MS_DIRECTIVES = {"SecRule", "SecAction", "SecRuleRemoveById", "SecMarker",
                  "SecRuleEngine", "SecDataDir"}


def _split_actions(actions: str) -> list[str]:
    out, buf, in_q = [], [], False
    for c in actions:
        if c == "'":
            in_q = not in_q
        if c == "," and not in_q:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
    if in_q:
        raise ValueError("unbalanced single quote in actions")
    out.append("".join(buf))
    return [a.strip() for a in out if a.strip()]


def lint_modsecurity(text: str, *, id_range: tuple[int, int] | None = None,
                     allow_placeholders: bool = False) -> list[str]:
    """Errors for a ModSecurity rule file; ``[]`` means it passed. Comment lines (and so a
    rule that ships disabled) are not parsed."""
    lo, hi = id_range or (gd.MODSEC_BASE, gd.MODSEC_BASE + gd.MODSEC_SPAN - 1)
    errs: list[str] = []
    ids: dict[int, str] = {}
    chain_open = False
    flat = re.sub(r"\\\n\s*", " ", text)
    for n, line in enumerate(flat.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            words = _split_quoted(s)
        except ValueError as e:
            errs.append(f"line {n}: {e}: {s[:80]}")
            continue
        d = words[0]
        if d not in _MS_DIRECTIVES:
            errs.append(f"line {n}: unknown directive {d}")
            continue
        if d == "SecRuleRemoveById":
            if not all(w.isdigit() for w in words[1:]):
                errs.append(f"line {n}: SecRuleRemoveById needs ids")
            continue
        if d not in ("SecRule", "SecAction"):
            continue
        child = chain_open
        chain_open = False
        if d == "SecRule":
            if len(words) != 4:
                errs.append(f"line {n}: SecRule needs 3 arguments, got {len(words) - 1}: "
                            f"{s[:100]}")
                continue
            _, var, op, actions = words
            for v in var.split("|"):
                if not _MS_VAR.fullmatch(v):
                    errs.append(f"line {n}: bad variable {v!r}")
            m = re.fullmatch(r"(!?)@(\w+)(?:\s+(.*))?", op, re.S)
            if not m or m.group(2) not in _MS_OPERATORS:
                errs.append(f"line {n}: bad operator {op[:60]!r}")
            elif m.group(2) == "rx":
                try:
                    _py_regex(m.group(3) or "")
                except re.error as e:
                    errs.append(f"line {n}: regex does not compile: {e}")
        else:
            if len(words) != 2:
                errs.append(f"line {n}: SecAction needs 1 argument")
                continue
            actions = words[1]
            if child:
                errs.append(f"line {n}: SecAction cannot be a chain child")
        try:
            acts = _split_actions(actions)
        except ValueError as e:
            errs.append(f"line {n}: {e}")
            continue
        names = []
        for a in acts:
            name, _, val = a.partition(":")
            names.append(name)
            if name not in _MS_ACTIONS:
                errs.append(f"line {n}: unknown action {name!r}")
            if name == "t" and val not in _MS_TRANSFORMS:
                errs.append(f"line {n}: unknown transformation {val!r}")
            if name == "severity" and val.strip("'") not in _MS_SEVERITY:
                errs.append(f"line {n}: bad severity {val}")
            if name == "status" and not (val.isdigit() and 100 <= int(val) <= 599):
                errs.append(f"line {n}: bad status {val}")
            if name == "phase" and val not in ("1", "2", "3", "4", "5"):
                errs.append(f"line {n}: bad phase {val}")
            if name in ("msg", "tag") and not re.fullmatch(r"'[^']*'", val):
                errs.append(f"line {n}: {name} value must be single-quoted: {val[:40]}")
            if name == "id":
                if not val.isdigit():
                    errs.append(f"line {n}: bad id {val}")
                else:
                    i = int(val)
                    if i in ids:
                        errs.append(f"line {n}: duplicate rule id {i}")
                    ids[i] = s[:40]
                    if not lo <= i <= hi:
                        errs.append(f"line {n}: id {i} outside the Vigilo block {lo}-{hi}")
        if child:
            if "id" in names or "phase" in names:
                errs.append(f"line {n}: a chained rule must not carry id or phase")
        else:
            if "id" not in names:
                errs.append(f"line {n}: rule without id")
            if "phase" not in names:
                errs.append(f"line {n}: rule without phase")
            if "deny" in names and "status" not in names:
                errs.append(f"line {n}: deny without status")
        chain_open = "chain" in names
    if chain_open:
        errs.append("a chain is left open at the end of the file")
    if not allow_placeholders and gd.placeholders(re.sub(r"(?m)^\s*#.*$", "", text)):
        errs.append("unresolved @@REPLACE_...@@ placeholder in an active rule")
    return errs


# ====================================================================== nginx


@dataclass
class NgNode:
    name: str
    args: list[str]
    children: list["NgNode"] | None
    line: int


def _ng_tokens(text: str) -> list[tuple[str, str, int]]:
    toks: list[tuple[str, str, int]] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in ";{}":
            toks.append((c, c, line))
            i += 1
        elif c in "\"'":
            q, buf, start = c, [], line
            i += 1
            while i < n and text[i] != q:
                if text[i] == "\\" and i + 1 < n:
                    buf.append(text[i:i + 2])
                    i += 2
                    continue
                if text[i] == "\n":
                    line += 1
                buf.append(text[i])
                i += 1
            if i >= n:
                raise ValueError(f"line {start}: unterminated quoted string")
            i += 1
            toks.append(("word", "".join(buf), start))
        else:
            start = i
            while i < n and not text[i].isspace() and text[i] not in ";{}":
                i += 1
            toks.append(("word", text[start:i], line))
    return toks


def parse_nginx(text: str) -> list[NgNode]:
    toks = _ng_tokens(text)
    stack: list[list[NgNode]] = [[]]
    heads: list[NgNode] = []
    words: list[tuple[str, int]] = []
    for kind, val, ln in toks:
        if kind == "word":
            words.append((val, ln))
        elif kind == ";":
            if not words:
                raise ValueError(f"line {ln}: empty statement")
            stack[-1].append(NgNode(words[0][0], [w for w, _ in words[1:]], None,
                                    words[0][1]))
            words = []
        elif kind == "{":
            if not words:
                raise ValueError(f"line {ln}: block without a name")
            node = NgNode(words[0][0], [w for w, _ in words[1:]], [], words[0][1])
            stack[-1].append(node)
            stack.append(node.children)  # type: ignore[arg-type]
            heads.append(node)
            words = []
        else:
            if words:
                raise ValueError(f"line {ln}: missing ';' before '}}'")
            if len(stack) == 1:
                raise ValueError(f"line {ln}: unexpected '}}'")
            stack.pop()
            heads.pop()
    if words:
        raise ValueError(f"line {words[0][1]}: missing ';' at end of file")
    if len(stack) != 1:
        raise ValueError(f"unclosed '{{' for {heads[-1].name} (line {heads[-1].line})")
    return stack[0]


_NG_ANY = {"server_tokens", "add_header", "proxy_hide_header", "fastcgi_hide_header",
           "limit_req", "limit_req_status", "proxy_cookie_flags", "autoindex", "include"}
_NG_CONTEXT = {
    "main": {"http", "events", "daemon", "pid", "error_log"},
    "http": _NG_ANY | {"map", "geo", "limit_req_zone", "server", "access_log"},
    "server": _NG_ANY | {"listen", "server_name", "return", "if", "location", "root"},
    "location": _NG_ANY | {"return", "if", "proxy_pass", "root"},
    "if": {"return", "set"},
}
_NG_SINGLETON = {"server_tokens", "limit_req_status", "autoindex"}
_NG_BUILTIN_VARS = {"uri", "request_uri", "request_method", "http_origin",
                    "binary_remote_addr", "remote_addr", "host", "scheme"}


def _walk_nginx(nodes: list[NgNode], ctx: str, errs: list[str], defs: dict,
                uses: dict) -> None:
    seen_single: set[str] = set()
    seen_hdr: set[str] = set()
    seen_other: set[str] = set()
    for nd in nodes:
        where = f"line {nd.line}: {nd.name}"
        if nd.name not in _NG_CONTEXT.get(ctx, set()):
            errs.append(f"{where} is not allowed in {ctx} context")
            continue
        if nd.name in _NG_SINGLETON:
            if nd.name in seen_single:
                errs.append(f"{where} is duplicate")
            seen_single.add(nd.name)
        if nd.name in ("add_header", "proxy_hide_header", "fastcgi_hide_header",
                       "proxy_cookie_flags") and nd.args:
            key = f"{nd.name}:{nd.args[0].lower()}"
            if key in seen_hdr:
                errs.append(f"{where} {nd.args[0]} is repeated in one block")
            seen_hdr.add(key)
            if nd.name == "add_header":
                uses.setdefault("var", []).extend(re.findall(r"\$(\w+)", " ".join(nd.args[1:])))
        if nd.name == "limit_req_zone":
            m = re.search(r"zone=(\w+):", " ".join(nd.args))
            if not m:
                errs.append(f"{where} needs zone=name:size")
            else:
                if m.group(1) in defs["zones"]:
                    errs.append(f"{where} zone {m.group(1)} is defined twice")
                defs["zones"].add(m.group(1))
            uses.setdefault("var", []).extend(re.findall(r"\$(\w+)", nd.args[0] if nd.args else ""))
        if nd.name == "limit_req":
            m = re.search(r"zone=(\w+)", " ".join(nd.args))
            if not m:
                errs.append(f"{where} needs zone=")
            else:
                uses.setdefault("zone", []).append(m.group(1))
        if nd.name in ("map", "geo"):
            if nd.children is None:
                errs.append(f"{where} needs a block")
                continue
            var = next((a for a in reversed(nd.args) if a.startswith("$")), None)
            if var is None:
                errs.append(f"{where} has no target variable")
                continue
            if var[1:] in defs["vars"]:
                errs.append(f"{where} variable {var} is defined twice")
            defs["vars"].add(var[1:])
            if nd.name == "map":
                src = nd.args[0] if nd.args else ""
                uses.setdefault("var", []).extend(re.findall(r"\$(\w+)", src))
            for e in nd.children:
                if nd.name == "map":
                    key = e.name
                    if key.startswith("~"):
                        try:
                            _py_regex(key[2:] if key.startswith("~*") else key[1:])
                        except re.error as ex:
                            errs.append(f"line {e.line}: map regex does not compile: {ex}")
                    if e.children is not None or len(e.args) != 1:
                        errs.append(f"line {e.line}: map entry needs one value")
                    uses.setdefault("var", []).extend(
                        re.findall(r"\$(\w+)", " ".join(e.args)))
                else:
                    if e.name != "default":
                        if not re.fullmatch(r"[0-9a-fA-F:.]+(/\d+)?|@@REPLACE_\w+@@", e.name):
                            errs.append(f"line {e.line}: geo network {e.name!r} is invalid")
                    if len(e.args) != 1:
                        errs.append(f"line {e.line}: geo entry needs one value")
            continue
        if nd.name == "if":
            uses.setdefault("var", []).extend(re.findall(r"\$(\w+)", " ".join(nd.args)))
        if nd.name == "server" and nd.children is not None:
            seen_other.add("server")
        if nd.children is not None:
            _walk_nginx(nd.children, nd.name if nd.name in _NG_CONTEXT else "location",
                        errs, defs, uses)
            if nd.name == "location" and not any(
                    c.name in ("proxy_pass", "return", "root") for c in nd.children):
                errs.append(f"{where} {' '.join(nd.args)}: a location without proxy_pass, "
                            "return or root stops reaching the backend")


def lint_nginx(text: str, context: str = "http", *, extra: tuple[str, ...] = (),
               allow_placeholders: bool = False) -> list[str]:
    """Errors for an nginx snippet that is meant to be included in ``context``
    (``http`` or ``server``). ``extra`` are further snippets (the http part when linting
    the server part) used to resolve variables and zones."""
    errs: list[str] = []
    defs: dict = {"zones": set(), "vars": set()}
    uses: dict = {}
    try:
        for part in (*extra, text):
            tree = parse_nginx(part)
            _walk_nginx(tree, context if part is text else "http", errs, defs, uses)
    except ValueError as e:
        return [str(e)]
    undefined = {v for v in uses.get("var", []) if v not in defs["vars"]
                 and v not in _NG_BUILTIN_VARS and not v.startswith("http_")}
    for v in sorted(undefined):
        errs.append(f"variable ${v} is used but not defined by a map or geo")
    for z in uses.get("zone", []):
        if z not in defs["zones"]:
            errs.append(f"limit_req zone {z} is not defined by a limit_req_zone")
    if not allow_placeholders and gd.placeholders(re.sub(r"(?m)#.*$", "", text)):
        errs.append("unresolved @@REPLACE_...@@ placeholder")
    return errs


# ====================================================================== Apache

_AP_SECTIONS = {"VirtualHost", "Location", "LocationMatch", "Directory", "Files",
                "IfModule"}
_AP_CONTEXT = {
    "global": {"ServerTokens", "ServerSignature", "Header", "SetEnvIf", "Include",
               "RewriteEngine", "RewriteRule", "Listen", "ServerName", "LoadModule"},
    "vhost": {"ServerSignature", "Header", "SetEnvIf", "Include", "RewriteEngine",
              "RewriteRule", "ServerName", "ProxyPass", "ProxyPassReverse"},
    "location": {"Require", "Header", "SetEnvIf", "Options", "RewriteEngine",
                 "RewriteRule"},
}


def lint_apache(text: str, context: str = "vhost", *,
                allow_placeholders: bool = False) -> list[str]:
    """Errors for an Apache snippet included in ``context`` (``global`` server config or
    a ``vhost``)."""
    errs: list[str] = []
    stack: list[str] = []
    seen_single: set[str] = set()
    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            words = _split_quoted(s)
        except ValueError as e:
            errs.append(f"line {n}: {e}")
            continue
        m = re.fullmatch(r"<(/?)(\w+)\s*(.*?)>", s)
        if m:
            close, name = m.group(1) == "/", m.group(2)
            if name not in _AP_SECTIONS:
                errs.append(f"line {n}: unknown section {name}")
            if close:
                if not stack or stack[-1] != name:
                    errs.append(f"line {n}: </{name}> does not match "
                                f"{stack[-1] if stack else 'nothing'}")
                else:
                    stack.pop()
            else:
                if name == "VirtualHost" and context != "global":
                    errs.append(f"line {n}: <VirtualHost> only in the global context")
                if name in ("LocationMatch", "Location") and m.group(3):
                    try:
                        args = _split_quoted(m.group(3))
                        if name == "LocationMatch":
                            _py_regex(re.sub(r"^\(\?i\)", "", args[0]))
                    except (ValueError, re.error, IndexError) as e:
                        errs.append(f"line {n}: bad {name} argument: {e}")
                stack.append(name)
            continue
        d = words[0]
        ctx = "location" if any(x in ("Location", "LocationMatch", "Directory", "Files")
                                for x in stack) else ("vhost" if "VirtualHost" in stack
                                                      else context)
        if d not in _AP_CONTEXT.get(ctx, set()):
            errs.append(f"line {n}: {d} is not allowed in {ctx} context")
        if d in ("ServerTokens", "ServerSignature"):
            if d in seen_single:
                errs.append(f"line {n}: {d} is duplicate")
            seen_single.add(d)
        if d == "Header":
            args = [w for w in words[1:] if w != "always"]
            if not args or args[0] not in ("set", "unset", "append", "merge", "edit",
                                           "add"):
                errs.append(f"line {n}: bad Header action")
            elif args[0] == "edit":
                if len(args) < 4:
                    errs.append(f"line {n}: Header edit needs header, regex, replacement")
                else:
                    try:
                        _py_regex(args[2])
                    except re.error as e:
                        errs.append(f"line {n}: Header edit regex does not compile: {e}")
            elif args[0] in ("set", "append", "merge", "add") and len(args) < 3:
                errs.append(f"line {n}: Header {args[0]} needs a value")
        if d == "SetEnvIf":
            try:
                _py_regex(words[2])
            except (re.error, IndexError) as e:
                errs.append(f"line {n}: SetEnvIf regex: {e}")
        if d == "Require" and not re.fullmatch(r"Require\s+(all\s+(denied|granted)|ip\s+\S+)", s):
            errs.append(f"line {n}: unsupported Require form")
        if d == "Options" and not all(re.fullmatch(r"[+-]?\w+", w) for w in words[1:]):
            errs.append(f"line {n}: bad Options")
    if stack:
        errs.append(f"unclosed section <{stack[-1]}>")
    if not allow_placeholders and gd.placeholders(re.sub(r"(?m)^\s*#.*$", "", text)):
        errs.append("unresolved @@REPLACE_...@@ placeholder")
    return errs


# ====================================================================== Sigma

_SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
_SIGMA_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}


def _sigma_fields(detection: dict) -> set[str]:
    out: set[str] = set()
    for k, v in detection.items():
        if k == "condition":
            continue
        items = v if isinstance(v, list) else [v]
        for it in items:
            if isinstance(it, dict):
                out |= {f.split("|")[0] for f in it}
    return out


def lint_sigma(text: str) -> list[str]:
    """Schema checks on a YAML stream of Sigma rules, plus the portable field vocabulary,
    unique ids and titles. pySigma checks are in ``pysigma_check``."""
    errs: list[str] = []
    try:
        docs = [d for d in yaml.safe_load_all(text) if d]
    except yaml.YAMLError as e:
        return [f"YAML: {e}"]
    ids, titles = set(), set()
    for d in docs:
        t = d.get("title", "?")
        for key in ("title", "id", "status", "description", "logsource", "detection",
                    "level", "falsepositives", "tags", "date"):
            if key not in d:
                errs.append(f"{t}: missing {key}")
        if errs and "detection" not in d:
            continue
        try:
            uuid.UUID(str(d["id"]))
        except (ValueError, KeyError):
            errs.append(f"{t}: id is not a UUID")
        if d.get("id") in ids:
            errs.append(f"{t}: duplicate id {d.get('id')}")
        ids.add(d.get("id"))
        if t in titles:
            errs.append(f"duplicate title {t}")
        titles.add(t)
        if d.get("level") not in _SIGMA_LEVELS:
            errs.append(f"{t}: bad level {d.get('level')}")
        if d.get("status") not in _SIGMA_STATUS:
            errs.append(f"{t}: bad status {d.get('status')}")
        det = d["detection"]
        cond = str(det.get("condition", ""))
        if not cond:
            errs.append(f"{t}: no condition")
        for name in re.findall(r"\b(selection\w*|filter\w*)\b", cond):
            if name not in det:
                errs.append(f"{t}: condition references missing {name}")
        bad = _sigma_fields(det) - gd.SIGMA_FIELDS
        if bad:
            errs.append(f"{t}: fields outside the portable vocabulary: {sorted(bad)}")
        if gd.placeholders(text):
            errs.append(f"{t}: placeholder in a deployable rule")
        if "authorised" not in " ".join(map(str, d.get("falsepositives", []))).lower():
            errs.append(f"{t}: no authorised-test false positive note")
    return errs


def pysigma_check(text: str) -> list[str]:
    """pySigma: parse, every core validator, convert with the test backend. Returns
    ``None``-like ``["skip"]`` if pySigma is not importable."""
    try:
        from sigma.backends.test import TextQueryTestBackend
        from sigma.collection import SigmaCollection
        from sigma.validation import SigmaValidator
        from sigma.validators.core import validators
    except ImportError:
        return ["skip"]
    docs = [d for d in yaml.safe_load_all(text) if d]
    errs: list[str] = []
    collection = SigmaCollection.from_dicts(docs)
    for rule in collection.rules:
        for e in getattr(rule, "errors", []):
            errs.append(f"{rule.title}: {e}")
    issues = SigmaValidator(set(validators.values())).validate_rules(collection.rules)
    errs += [f"{type(i).__name__}: {i}" for i in issues]
    try:
        out = TextQueryTestBackend().convert(collection)
        if len(out) != len(docs):
            errs.append("conversion lost rules")
    except Exception as e:  # noqa: BLE001
        errs.append(f"conversion failed: {e}")
    return errs


def pysigma_splunk(text: str) -> list[str]:
    try:
        from sigma.backends.splunk import SplunkBackend
        from sigma.collection import SigmaCollection
    except ImportError:
        return ["skip"]
    docs = [d for d in yaml.safe_load_all(text) if d]
    try:
        out = SplunkBackend().convert(SigmaCollection.from_dicts(docs))
    except Exception as e:  # noqa: BLE001
        return [f"splunk conversion failed: {e}"]
    return [] if len(out) == len(docs) else ["splunk conversion lost rules"]


# ====================================================================== bundles


def read_zip(content: bytes) -> dict[str, str]:
    z = zipfile.ZipFile(io.BytesIO(content))
    return {n: z.read(n).decode() for n in z.namelist()}


def lint_bundle(files: dict[str, str]) -> list[str]:
    """Tier 1 over a whole download (placeholders allowed: they are REQUIRED EDITS)."""
    errs: list[str] = []
    http = files.get("nginx.conf", "")
    for name, text in files.items():
        if name == "modsecurity.conf":
            errs += [f"{name}: {e}" for e in lint_modsecurity(text, allow_placeholders=True)]
        elif name == "nginx.conf":
            errs += [f"{name}: {e}" for e in lint_nginx(text, "http", allow_placeholders=True)]
        elif name.startswith("nginx-server"):
            errs += [f"{name}: {e}" for e in lint_nginx(text, "server", extra=(http,),
                                                         allow_placeholders=True)]
        elif name == "apache.conf":
            errs += [f"{name}: {e}" for e in lint_apache(text, "global", allow_placeholders=True)]
        elif name.startswith("apache-vhost"):
            errs += [f"{name}: {e}" for e in lint_apache(text, "vhost", allow_placeholders=True)]
        elif name == "sigma.yml":
            errs += [f"{name}: {e}" for e in lint_sigma(text)]
    return errs


# ====================================================================== tier 2

NGINX = shutil.which("nginx")
HTTPD = shutil.which("httpd") or shutil.which("apache2") or (
    "/usr/sbin/httpd" if Path("/usr/sbin/httpd").exists() else None)
_APACHE_MODULE_DIRS = ("/usr/libexec/apache2", "/usr/lib/apache2/modules",
                       "/usr/local/opt/httpd/lib/httpd/modules",
                       "/opt/homebrew/opt/httpd/lib/httpd/modules")


def apache_modules() -> Path | None:
    for d in _APACHE_MODULE_DIRS:
        if Path(d, "mod_headers.so").exists():
            return Path(d)
    return None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(port: int, timeout: float = 10.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nothing listening on {port}")


def serve_lenient() -> tuple[object, int]:
    """A backend that serves ANY path with 200 (and counts nothing): evasion tests need a
    target the evasion would actually reach if the rule failed."""
    import uvicorn
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    async def echo(request):
        return PlainTextResponse("served " + request.url.path,
                                 headers={"Server": "DemoServer/1.2.3"})

    app = Starlette(routes=[Route("/{path:path}", echo, methods=["GET", "POST"])])
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                           log_level="error", lifespan="off",
                                           access_log=False, server_header=False))
    threading.Thread(target=server.run, daemon=True, name="gb-lenient").start()
    _wait(port)
    return server, port


def raw_request(port: int, path: str, *, method: str = "GET",
                headers: dict[str, str] | None = None, body: bytes | None = None
                ) -> tuple[int, dict[str, list[str]], str]:
    """Send ``path`` exactly as given (no client-side normalisation)."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        h = {"Host": "127.0.0.1", "Connection": "close", **(headers or {})}
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in h.items():
            c.putheader(k, v)
        if body is not None:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        r = c.getresponse()
        hdrs: dict[str, list[str]] = {}
        for k, v in r.getheaders():
            hdrs.setdefault(k.lower(), []).append(v)
        return r.status, hdrs, r.read().decode("utf-8", "replace")
    finally:
        c.close()


class Stack:
    """A throw-away nginx or Apache on a free loopback port in front of one backend, with
    the (placeholder-filled) bundle included. ``check()`` runs the syntax test only."""

    def __init__(self, kind: str, files: dict[str, str], backend_port: int, *,
                 admin_network: str = "192.0.2.0/24", with_bundle: bool = True) -> None:
        self.kind, self.backend = kind, backend_port
        self.tmp = Path(tempfile.mkdtemp(prefix=f"vigilo-{kind}-"))
        self.port = free_port()
        self.redirect_port = free_port()
        self.proc: subprocess.Popen | None = None
        self.files = {n: fill_placeholders(t, admin_network=admin_network,
                                           docroot=str(self.tmp / "www"))
                      for n, t in files.items()} if with_bundle else {}
        (self.tmp / "www").mkdir()
        (self.tmp / "vigilo").mkdir()
        (self.tmp / "run").mkdir()
        for n, t in self.files.items():
            (self.tmp / "vigilo" / n).write_text(t)
        self.conf = self.tmp / f"{kind}.conf"
        self.conf.write_text(self._conf())

    def _include(self, pattern: str) -> str:
        names = sorted(n for n in self.files if re.fullmatch(pattern, n))
        if self.kind == "apache":
            return "".join(f"Include {self.tmp}/vigilo/{n}\n" for n in names)
        return "".join(f"include {self.tmp}/vigilo/{n};\n" for n in names)

    def _conf(self) -> str:
        t = self.tmp
        if self.kind == "nginx":
            http = self.files.get("nginx.conf", "").replace(
                "listen 80;", f"listen 127.0.0.1:{self.redirect_port};")
            if http:
                (t / "vigilo" / "nginx.conf").write_text(http)
            return (
                f"daemon off;\npid {t}/nginx.pid;\nerror_log {t}/error.log info;\n"
                "events { worker_connections 64; }\n"
                f"http {{\n    access_log off;\n    {self._include(r'nginx.conf')}"
                f"    server {{\n        listen 127.0.0.1:{self.port};\n"
                "        server_name _;\n"
                f"        {self._include(r'nginx-server.*conf').replace(chr(10), chr(10) + '        ')}"
                "        location / {\n"
                f"            proxy_pass http://127.0.0.1:{self.backend};\n"
                "        }\n    }\n}\n")
        mods = apache_modules()
        load = "".join(f"LoadModule {m}_module {mods}/mod_{m}.so\n" for m in (
            "mpm_event", "authz_core", "authz_host", "unixd", "headers", "setenvif",
            "rewrite", "proxy", "proxy_http", "log_config"))
        apache_global = self.files.get("apache.conf", "").replace(
            "<VirtualHost *:80>", f"<VirtualHost 127.0.0.1:{self.redirect_port}>")
        if apache_global:
            (t / "vigilo" / "apache.conf").write_text(apache_global)
        return (
            f'ServerRoot "{t}"\nDefaultRuntimeDir "{t}/run"\nPidFile "{t}/httpd.pid"\nListen 127.0.0.1:{self.port}\n'
            f'{load}ErrorLog "{t}/error.log"\nLogLevel warn\nServerName 127.0.0.1\n'
            f'DocumentRoot "{t}/www"\n<Directory "{t}/www">\n    Require all granted\n'
            "</Directory>\n"
            f"{self._include(r'apache.conf')}"
            f"<VirtualHost 127.0.0.1:{self.port}>\n    ServerName 127.0.0.1\n"
            f"{self._include(r'apache-vhost.*conf')}"
            f"    ProxyPass / http://127.0.0.1:{self.backend}/\n"
            f"    ProxyPassReverse / http://127.0.0.1:{self.backend}/\n"
            "</VirtualHost>\n")

    def _cmd(self, *extra: str) -> list[str]:
        if self.kind == "nginx":
            return [NGINX, "-p", str(self.tmp), "-e", str(self.tmp / "error.log"),
                    "-c", str(self.conf), *extra]
        return [HTTPD, "-f", str(self.conf), *extra]

    def check(self) -> tuple[bool, str]:
        r = subprocess.run(self._cmd("-t"), capture_output=True, text=True, timeout=60)
        return r.returncode == 0, (r.stdout + r.stderr).strip()

    def __enter__(self) -> "Stack":
        ok, out = self.check()
        if not ok:
            raise RuntimeError(f"{self.kind} config test failed:\n{out}")
        self.proc = subprocess.Popen(
            self._cmd(*(["-DFOREGROUND"] if self.kind == "apache" else [])),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            _wait(self.port)
        except RuntimeError:
            self.proc.terminate()
            err = self.proc.stderr.read().decode() if self.proc.stderr else ""
            raise RuntimeError(f"{self.kind} did not start: {err}") from None
        return self

    def __exit__(self, *exc) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def get(self, path: str, **kw):
        return raw_request(self.port, path, **kw)


# ---------------------------------------------------------------- recorded exchanges

# evasions of a blocked path: (label, request path). All reach the lenient backend if
# the rule fails to match.
REPO_EVASIONS = [
    ("plain", "/.git/HEAD"), ("directory", "/.git/"), ("bare", "/.git"),
    ("upper case", "/.GIT/HEAD"), ("mixed case", "/.GiT/head"),
    ("encoded dot", "/%2egit/HEAD"), ("encoded letters", "/.%67it/HEAD"),
    ("fully encoded", "/%2E%47IT/HEAD"), ("double slash", "//.git/HEAD"),
    ("dot segment", "/./.git/HEAD"), ("path parameter", "/.git;x=1/HEAD"),
    ("trailing slash", "/.git/HEAD/"), ("query", "/.git/HEAD?a=b"),
]
ENV_EVASIONS = [
    ("plain", "/.env"), ("upper case", "/.ENV"), ("encoded", "/%2eenv"),
    ("suffix", "/.env.production"), ("backup suffix", "/.env.bak"),
    ("nested", "/app/.env"), ("double slash", "//app//.env"),
    ("trailing slash", "/.env/"), ("path parameter", "/.env;x=1"),
]
# must NOT be blocked (collateral of an unanchored rule)
COLLATERAL = ["/.github/workflow.yml", "/.gitignore", "/.gitlab-ci.yml", "/index.html",
              "/static/app.js", "/environment", "/app/.environment/x", "/etc/gitea"]


async def recorded_requests(client, headers, run_id: str) -> list[dict]:
    """The run's recorded exchanges as replayable requests: method, request target (path
    and query), request headers that are safe to resend, recorded status, tool, findings."""
    items: list[dict] = []
    after = None
    while True:
        r = await client.get(f"/greybox/runs/{run_id}/traffic", headers=headers,
                             params={"limit": 200, **({"after_id": after} if after else {})})
        r.raise_for_status()
        j = r.json()
        items += j["items"]
        after = j["next_after_id"]
        if not after:
            break
    out = []
    for it in items:
        d = (await client.get(f"/greybox/runs/{run_id}/traffic/{it['id']}",
                              headers=headers)).json()
        from urllib.parse import urlsplit
        u = urlsplit(d["url"])
        target = (u.path or "/") + (f"?{u.query}" if u.query else "")
        hdr = {k: v for k, v in d["request"]["headers"]
               if k.lower() in ("origin", "accept", "accept-language", "user-agent")}
        out.append({"method": d["method"], "target": target, "headers": hdr,
                    "status": d["status_code"], "tool": d["tool"],
                    "findings": d["finding_ids"], "id": d["id"]})
    return out
