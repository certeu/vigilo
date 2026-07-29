"""Pipeline stage selection.

Maps a user-facing preset (``vuln`` / ``vuln_patch`` / ``full``) to a concrete set
of phase flags read by ``PentestPipelineWorkflow``. Two product invariants are
enforced *structurally* here so they cannot be toggled off:

1. **Vulnerability analysis always includes exploitation.** There is no separate
   "exploit" flag — exploitation is welded into the vuln pipeline. Enabling vuln
   (``run_vuln``) always runs vuln+exploit; there is no way to run vuln without it.
2. **Findings critique always runs.** ``run_critique`` is forced ``True`` regardless
   of preset — it is the false-positive gate, never optional.

Implemented with a stdlib frozen dataclass (deterministic, no third-party import) so
it is safe to import inside the Temporal workflow sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

# Canonical preset names exposed to API consumers.
PRESET_VULN = "vuln"
PRESET_VULN_PATCH = "vuln_patch"
PRESET_FULL = "full"

VALID_PRESETS = (PRESET_VULN, PRESET_VULN_PATCH, PRESET_FULL)


@dataclass(frozen=True)
class StageSelection:
    """Which optional phases run. Mandatory phases (preflight, pre-recon, recon,
    report) are not represented — they always run."""

    run_vuln: bool = True         # vuln + exploit (welded; no separate exploit flag)
    run_sca: bool = True          # software composition analysis
    run_integrity: bool = True    # integrity analysis
    run_chain: bool = True        # cross-type chain exploitation
    run_critique: bool = True     # findings critique — FORCED on (see module docstring)
    run_remediation: bool = True  # fix branches / patches / MRs

    def normalized(self) -> "StageSelection":
        """Apply invariants: critique always on; remediation implies vuln."""
        run_vuln = self.run_vuln or self.run_remediation  # can't patch nothing
        return replace(self, run_vuln=run_vuln, run_critique=True)


def stages_for_preset(preset: str) -> StageSelection:
    """Return the StageSelection for a named preset (already normalized)."""
    if preset == PRESET_VULN:
        sel = StageSelection(
            run_vuln=True, run_sca=False, run_integrity=False,
            run_chain=False, run_remediation=False,
        )
    elif preset == PRESET_VULN_PATCH:
        sel = StageSelection(
            run_vuln=True, run_sca=False, run_integrity=False,
            run_chain=False, run_remediation=True,
        )
    elif preset == PRESET_FULL:
        sel = StageSelection()  # all True
    else:
        raise ValueError(
            f"Unknown stage preset {preset!r}; expected one of {VALID_PRESETS}"
        )
    return sel.normalized()


def resolve_stages(raw: object) -> StageSelection:
    """Resolve a workflow-input ``stages`` value into a StageSelection.

    Accepts ``None`` (→ full pipeline, preserving legacy behavior), a preset name
    string, or a dict of flag overrides. Always returns a normalized selection.
    """
    if raw is None:
        return StageSelection().normalized()
    if isinstance(raw, str):
        return stages_for_preset(raw)
    if isinstance(raw, StageSelection):
        return raw.normalized()
    if isinstance(raw, dict):
        if "preset" in raw:
            base = stages_for_preset(raw["preset"])
        else:
            base = StageSelection()
        fields = {
            k: bool(v) for k, v in raw.items()
            if k in StageSelection.__dataclass_fields__
        }
        return replace(base, **fields).normalized()
    raise TypeError(f"Cannot resolve stages from {type(raw).__name__}")
