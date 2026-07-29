"""Findings aggregator — unified findings_index.json from structured agent outputs.

For each vulnerability type this reads two structured files the agents write
explicitly:

- ``{type}_exploitation_queue.json`` — the specialist's findings (the source of
  truth for *what* was found).
- ``{type}_exploitation_verdicts.json`` — the exploit agent's structured verdict
  per finding (the source of truth for *whether it was confirmed*).

Chain findings come from ``chain_findings.json`` (structured, written by the
chain agent); supply-chain and integrity findings from their existing JSON
deliverables.

**No prose is scraped.** Every field originates from a structured JSON file an
agent wrote on purpose. Status comes from the exploit verdict (not a regex scan
of evidence markdown); severity is carried through verbatim from the specialist
or critic (never fabricated from a confidence heuristic). Findings the exploit
agent judged ``false_positive`` or ``unreachable`` are kept in the index with a
``suppressed`` status and an explicit reason, so nothing is silently dropped —
downstream consumers exclude them from primary counts but can still audit them.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiofiles

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VulnTypeConfig:
    """Maps a vulnerability type to its queue and verdict filenames."""
    vuln_type: str
    queue_filename: str
    verdict_filename: str


# All 8 vulnerability types and their structured file names.
VULN_TYPE_CONFIGS: tuple[VulnTypeConfig, ...] = (
    VulnTypeConfig("injection", "injection_exploitation_queue.json", "injection_exploitation_verdicts.json"),
    VulnTypeConfig("xss", "xss_exploitation_queue.json", "xss_exploitation_verdicts.json"),
    VulnTypeConfig("auth", "auth_exploitation_queue.json", "auth_exploitation_verdicts.json"),
    VulnTypeConfig("ssrf", "ssrf_exploitation_queue.json", "ssrf_exploitation_verdicts.json"),
    VulnTypeConfig("authz", "authz_exploitation_queue.json", "authz_exploitation_verdicts.json"),
    VulnTypeConfig("graphql", "graphql_exploitation_queue.json", "graphql_exploitation_verdicts.json"),
    VulnTypeConfig("websocket", "websocket_exploitation_queue.json", "websocket_exploitation_verdicts.json"),
    VulnTypeConfig("crypto", "crypto_exploitation_queue.json", "crypto_exploitation_verdicts.json"),
)

# Default severity when neither the specialist nor a verdict states one. The
# critic re-grades severity authoritatively downstream, so this is a
# conservative placeholder — NOT an inference. (The old heuristic minted
# `critical`/`high` from confidence, which was the main severity-inflation
# source; that is gone by design.)
_DEFAULT_SEVERITY = "medium"

# Maps a structured exploit verdict to the finding's status bucket.
#   exploited      -> exploited   (demonstrated end-to-end against a live target)
#   confirmed      -> potential   (code-only: a source-level harness demonstrated the
#                                  vuln at the sink — real, but not a live end-to-end run)
#   blocked        -> potential   (real vuln, blocked by a control; not demonstrated)
#   not_testable   -> potential   (code-only: static source->sink trace holds but no
#                                  harness was feasible — still a real candidate)
#   unreachable    -> suppressed  (not reachable by the in-scope attacker)
#   refuted        -> suppressed  (a harness ran and the payload had no effect / the
#                                  defense holds — evidenced non-vulnerability)
#   false_positive -> suppressed  (exploit agent judged it not a vulnerability)
# A finding with no verdict stays `unconfirmed`.
#
# Note: `confirmed`/`not_testable` keep code-only findings at `potential` (not
# `unreachable`), which restores honest status semantics and re-arms the
# confirmed-only chain gate. A harness proves the SINK is vulnerable; it does NOT
# prove reachability — the critic's reachability verdict still gates severity.
_VERDICT_TO_STATUS: dict[str, str] = {
    "exploited": "exploited",
    "confirmed": "potential",
    "blocked": "potential",
    "blocked_by_security": "potential",
    "not_testable": "potential",
    "unreachable": "suppressed",
    "refuted": "suppressed",
    "false_positive": "suppressed",
}

_SUPPRESSED_VERDICTS = {"unreachable", "refuted", "false_positive"}

# Verdicts where a source-level harness actually exercised the code path.
_HARNESS_VERDICTS = {"confirmed", "refuted"}


async def _load_json(path: Path) -> Any | None:
    """Read and parse a JSON file, returning None on missing/malformed input."""
    if not path.is_file():
        return None
    try:
        async with aiofiles.open(path, mode="r", encoding="utf-8") as f:
            content = await f.read()
        return json.loads(content)
    except json.JSONDecodeError as exc:
        logger.warning("Malformed JSON in %s: %s", path, exc)
        return None
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return None


async def _load_verdicts(deliverables_dir: Path, cfg: VulnTypeConfig) -> dict[str, dict[str, Any]]:
    """Load the exploit agent's structured verdicts, keyed by finding ID.

    Expected shape::

        {"verdicts": [{"id": "INJ-VULN-01", "verdict": "exploited",
                       "severity": "high", "evidence_ref": "...", "notes": "..."}]}

    Returns an empty dict when the file is absent (findings then stay
    ``unconfirmed``).
    """
    data = await _load_json(deliverables_dir / cfg.verdict_filename)
    if not isinstance(data, dict):
        return {}
    verdicts = data.get("verdicts", [])
    if not isinstance(verdicts, list):
        logger.warning("%s has non-list 'verdicts', ignoring", cfg.verdict_filename)
        return {}
    by_id: dict[str, dict[str, Any]] = {}
    for entry in verdicts:
        if not isinstance(entry, dict):
            continue
        vid = str(entry.get("id") or entry.get("ID") or "").strip()
        if vid:
            by_id[vid] = entry
    return by_id


def _apply_verdict(vuln: dict[str, Any], verdict: dict[str, Any] | None) -> None:
    """Set status/severity/code_fixable on a finding from structured inputs only."""
    # --- status: from the structured verdict, else unconfirmed ---
    if verdict is not None:
        raw_verdict = str(verdict.get("verdict", "")).strip().lower()
        vuln["status"] = _VERDICT_TO_STATUS.get(raw_verdict, "unconfirmed")
        if raw_verdict in _SUPPRESSED_VERDICTS:
            vuln["suppression_reason"] = str(
                verdict.get("notes") or verdict.get("reason") or raw_verdict
            )
        if verdict.get("evidence_ref"):
            vuln["evidence_ref"] = verdict["evidence_ref"]
        # Source-level harness evidence (code-only confirmation). Carried through
        # so the critic can raise confidence and verify_patches can re-run it.
        if raw_verdict in _HARNESS_VERDICTS:
            vuln["harness_confirmed"] = raw_verdict == "confirmed"
        if verdict.get("harness_path"):
            vuln["harness_path"] = verdict["harness_path"]
    else:
        vuln.setdefault("status", "unconfirmed")

    # --- severity: specialist value > verdict value > conservative default ---
    severity = vuln.get("severity")
    if not severity and verdict is not None:
        severity = verdict.get("severity")
    vuln["severity"] = str(severity or _DEFAULT_SEVERITY).lower()

    # --- code_fixable: explicit field only; default True (no keyword scan) ---
    vuln["code_fixable"] = bool(vuln.get("code_fixable", True))


async def _load_chain_findings(deliverables_dir: Path) -> list[dict[str, Any]]:
    """Load structured chain findings written by the chain-exploit agent.

    Expected ``chain_findings.json`` shape::

        {"chains": [{"ID": "CHAIN-001", "severity": "high",
                     "status": "exploited", "components": ["INJ-VULN-01", ...],
                     "notes": "..."}]}
    """
    data = await _load_json(deliverables_dir / "chain_findings.json")
    if not isinstance(data, dict):
        return []
    chains = data.get("chains", [])
    if not isinstance(chains, list):
        logger.warning("chain_findings.json has non-list 'chains', ignoring")
        return []

    findings: list[dict[str, Any]] = []
    for chain in chains:
        if not isinstance(chain, dict):
            continue
        cid = str(chain.get("ID") or chain.get("id") or "").strip()
        if not cid:
            continue
        components = chain.get("components") or chain.get("chain_components") or []
        findings.append({
            "ID": cid,
            "vulnerability_type": "Chain_Exploit",
            "severity": str(chain.get("severity", "high")).lower(),
            "status": str(chain.get("status", "unconfirmed")).lower(),
            "code_fixable": False,  # chains are fixed by patching their components
            "chain_components": components,
            "notes": str(chain.get("notes", "")),
        })
    if findings:
        logger.info("Loaded %d chain findings from chain_findings.json", len(findings))
    return findings


class FindingsAggregator:
    """Reads structured agent outputs and produces a unified findings index."""

    async def aggregate(self, repo_path: str) -> dict[str, Any]:
        """Merge all queue + verdict files into the index structure.

        Returns a dict shaped as::

            {"total_vulnerabilities": 15, "by_type": {"injection": [...], ...}}

        Missing or malformed files are skipped (logged as warnings).
        """
        deliverables_dir = Path(repo_path) / "deliverables"
        by_type: dict[str, list[dict[str, Any]]] = {}
        total = 0

        for cfg in VULN_TYPE_CONFIGS:
            queue_data = await _load_json(deliverables_dir / cfg.queue_filename)
            if not isinstance(queue_data, dict):
                by_type[cfg.vuln_type] = []
                continue

            vulns = queue_data.get("vulnerabilities", [])
            if not isinstance(vulns, list):
                logger.warning("Queue %s has non-list 'vulnerabilities', skipping", cfg.queue_filename)
                by_type[cfg.vuln_type] = []
                continue

            verdicts = await _load_verdicts(deliverables_dir, cfg)
            clean: list[dict[str, Any]] = []
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vid = str(vuln.get("ID") or vuln.get("id") or "").strip()
                _apply_verdict(vuln, verdicts.get(vid))
                clean.append(vuln)

            by_type[cfg.vuln_type] = clean
            total += len(clean)
            logger.info(
                "Aggregated %d %s findings (%d with verdicts)",
                len(clean), cfg.vuln_type, len(verdicts),
            )

        # --- Chain findings (structured) ---
        chain_findings = await _load_chain_findings(deliverables_dir)
        if chain_findings:
            by_type["chain"] = chain_findings
            total += len(chain_findings)

        # --- Supply chain (SCA) findings (already structured JSON) ---
        # Pre-filter: dedup by (package, advisory) and annotate dependency_used
        # BEFORE the critic sees them, so the noisiest bucket is reduced up front.
        # Conservative: usage is only ever confirmed True or left unknown — never
        # asserted False — so a real finding is never hidden here (see sca_filter).
        sca_data = await _load_json(deliverables_dir / "sca_findings.json")
        if isinstance(sca_data, dict):
            sca_vulns = sca_data.get("vulnerabilities", [])
            if isinstance(sca_vulns, list) and sca_vulns:
                from src.services.sca_filter import filter_sca
                filtered = filter_sca(sca_vulns, repo_path)
                by_type["supply_chain"] = filtered
                total += len(filtered)
                logger.info("Added %d supply chain findings (%d raw)", len(filtered), len(sca_vulns))

        # --- Integrity findings (already structured JSON) ---
        integrity_data = await _load_json(deliverables_dir / "integrity_analysis.json")
        if isinstance(integrity_data, dict):
            integrity_findings = integrity_data.get("findings", [])
            if isinstance(integrity_findings, list) and integrity_findings:
                by_type["integrity"] = integrity_findings
                total += len(integrity_findings)
                logger.info("Added %d integrity findings", len(integrity_findings))

        index: dict[str, Any] = {
            "total_vulnerabilities": total,
            "by_type": by_type,
        }
        logger.info(
            "Findings aggregation complete: %d total across %d non-empty types",
            total,
            sum(1 for v in by_type.values() if v),
        )
        return index

    async def write_index(self, repo_path: str, index: dict[str, Any]) -> None:
        """Write the aggregated findings index to ``deliverables/findings_index.json``.

        Uses an atomic write (temp file + rename) for crash safety.
        """
        deliverables_dir = Path(repo_path) / "deliverables"
        deliverables_dir.mkdir(parents=True, exist_ok=True)

        index_path = deliverables_dir / "findings_index.json"
        tmp_path = deliverables_dir / f"findings_index.{os.getpid()}.{id(index)}.tmp"

        content = json.dumps(index, indent=2, ensure_ascii=False)
        async with aiofiles.open(tmp_path, mode="w", encoding="utf-8") as f:
            await f.write(content)
        tmp_path.replace(index_path)
        logger.info(
            "Wrote findings_index.json with %d total vulnerabilities",
            index.get("total_vulnerabilities", 0),
        )

    async def aggregate_and_write(self, repo_path: str) -> dict[str, Any]:
        """Aggregate all queues + verdicts and write the index in one step."""
        index = await self.aggregate(repo_path)
        await self.write_index(repo_path, index)
        return index
