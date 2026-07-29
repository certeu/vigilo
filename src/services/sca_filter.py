"""SCA pre-filter — dedup supply-chain findings and hint dependency usage.

SCA is the noisiest bucket (a single run produced 189 findings). Two cheap,
deterministic reductions applied *before* the critic sees them:

1. **Dedup** by ``(package, advisory)`` — the same CVE on the same package,
   reported multiple times (transitive paths, repeated manifests), collapses to
   one finding that records how many raw entries it absorbed.
2. **Usage hint** — a conservative ``dependency_used`` flag. It is set ``True``
   only when the package name is positively found in the source's imports /
   manifests; otherwise it is ``"unknown"`` — **never ``False``**. Distribution
   names differ from import names (``PyYAML`` -> ``yaml``) and transitive deps
   aren't imported directly, so absence is NOT proof of non-use. This keeps the
   filter from ever hiding a real finding; it only lets the critic/report
   *prioritise* the confirmed-used ones. Nothing is dropped.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SOURCE_GLOBS = ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.go", "*.rb", "*.java")
_MANIFESTS = (
    "requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg",
    "package.json", "go.mod", "Gemfile", "pom.xml", "build.gradle",
)
_SKIP_DIRS = {".git", ".vigilo", "node_modules", "venv", ".venv", "vendor",
             "site-packages", "dist", "build", "__pycache__", "deliverables"}


def _normalize_pkg(name: str) -> str:
    """Lowercase, drop scope/extras/version so package names compare cleanly."""
    n = str(name or "").strip().lower()
    n = n.split("@")[0] if not n.startswith("@") else n  # drop version, keep npm scope
    n = re.split(r"[<>=!~ \[]", n, maxsplit=1)[0]         # drop version specifiers/extras
    return n.strip().strip("/")


def build_usage_index(repo_path: str) -> set[str]:
    """Collect a set of tokens that appear in source imports / manifests.

    Deliberately broad (substring-friendly): the goal is to POSITIVELY confirm a
    package is referenced, not to prove it isn't. Tokens are lowercased words of
    length >= 2 seen in import statements and dependency manifests.
    """
    tokens: set[str] = set()
    root = Path(repo_path)
    import_re = re.compile(r"\b(?:import|from|require|use)\b[^\n;]{0,200}", re.IGNORECASE)
    word_re = re.compile(r"[A-Za-z0-9_.\-@/]{2,}")

    def _scan(text: str) -> None:
        for line in import_re.findall(text):
            for w in word_re.findall(line):
                tokens.add(w.lower())

    try:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if path.name in _MANIFESTS:
                try:
                    for w in word_re.findall(path.read_text(errors="ignore")):
                        tokens.add(w.lower())
                except OSError:
                    pass
            elif path.suffix and f"*{path.suffix}" in _SOURCE_GLOBS:
                try:
                    _scan(path.read_text(errors="ignore"))
                except OSError:
                    pass
    except OSError as exc:
        logger.warning("sca_filter: usage scan failed: %s", exc)
    return tokens


def _advisory_of(f: dict[str, Any]) -> str:
    """Canonical advisory key = the FULL set of advisory/CVE ids, sorted+joined.

    Using the complete set (not just the first CVE) prevents two findings with
    different-but-overlapping CVE lists from colliding on the same key. Returns
    "" when the finding carries no recognizable advisory id.
    """
    ids: list[str] = []
    for k in ("advisory", "advisory_id", "cve", "ghsa"):
        if f.get(k):
            ids.append(str(f[k]))
    lst = f.get("cve_ids") or f.get("advisories")
    if isinstance(lst, list):
        ids.extend(str(x) for x in lst)
    return "|".join(sorted(set(ids)))


def _usage(pkg_norm: str, usage_index: set[str]) -> str:
    """True only on a positive hit; 'unknown' otherwise (never False)."""
    if not pkg_norm:
        return "unknown"
    if pkg_norm in usage_index:
        return "true"
    # scoped/segmented names: check the last path segment too
    tail = pkg_norm.rsplit("/", 1)[-1]
    if tail and tail in usage_index:
        return "true"
    return "unknown"


def dedup_and_annotate(
    findings: list[dict[str, Any]],
    usage_index: set[str],
) -> list[dict[str, Any]]:
    """Collapse (package, advisory) duplicates and annotate dependency_used.

    Pure: takes the raw SCA findings + a usage token set, returns the reduced list.
    """
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        pkg = _normalize_pkg(f.get("package") or f.get("name") or "")
        adv = _advisory_of(f)
        # Only merge when there is a real advisory id to merge ON. Advisory-less
        # findings get a unique key so distinct ones are never collapsed (that
        # would drop a real finding).
        key = (pkg, adv) if adv else (pkg, f"__noadv_{i}")
        if key not in groups:
            merged = dict(f)
            merged["dedup_group"] = f"{pkg}::{adv}" if adv else pkg
            merged["dependency_used"] = _usage(pkg, usage_index)
            merged["absorbed_count"] = 1
            groups[key] = merged
            order.append(key)
        else:
            groups[key]["absorbed_count"] += 1
    deduped = [groups[k] for k in order]
    logger.info(
        "sca_filter: %d raw -> %d deduped SCA findings (%d confirmed-used)",
        len(findings), len(deduped),
        sum(1 for f in deduped if f.get("dependency_used") == "true"),
    )
    return deduped


def filter_sca(findings: list[dict[str, Any]], repo_path: str) -> list[dict[str, Any]]:
    """Convenience: build the usage index from the repo and dedup+annotate."""
    if not findings:
        return findings
    return dedup_and_annotate(findings, build_usage_index(repo_path))
