"""Consistency tests for the deliverable registry and the aggregator contract.

Two copies of the filename map exist (the importable one in
``src/types/deliverables.py`` and an inlined copy in ``scripts/save_deliverable.py``
so the CLI works on PATH without imports). These drift silently — this test
fails loudly if they diverge. It also verifies the exploit-verdict filenames
match the ones ``findings_aggregator`` actually reads.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.types.deliverables import DELIVERABLE_FILENAMES  # noqa: E402
from src.services.findings_aggregator import VULN_TYPE_CONFIGS  # noqa: E402


def _load_save_deliverable():
    spec = importlib.util.spec_from_file_location(
        "save_deliverable", ROOT / "scripts" / "save_deliverable.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cli_filename_map_matches_types_module():
    cli = _load_save_deliverable()
    assert cli.DELIVERABLE_FILENAMES == DELIVERABLE_FILENAMES, (
        "scripts/save_deliverable.py inlined map has drifted from "
        "src/types/deliverables.py"
    )


def test_verdict_types_registered_and_match_aggregator():
    # The 7 exploit types (crypto has no exploit agent) each need a *_VERDICTS
    # deliverable whose filename equals the aggregator's verdict_filename.
    exploit_types = [c for c in VULN_TYPE_CONFIGS if c.vuln_type != "crypto"]
    for cfg in exploit_types:
        dtype = f"{cfg.vuln_type.upper()}_VERDICTS"
        assert dtype in DELIVERABLE_FILENAMES, f"missing deliverable type {dtype}"
        assert DELIVERABLE_FILENAMES[dtype] == cfg.verdict_filename


def test_chain_findings_registered():
    assert DELIVERABLE_FILENAMES["CHAIN_FINDINGS"] == "chain_findings.json"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
