"""Tests for pipeline stage selection + invariants (src/types/stages.py)."""
from __future__ import annotations

import pytest

from src.types.stages import (
    PRESET_FULL,
    PRESET_VULN,
    PRESET_VULN_PATCH,
    StageSelection,
    resolve_stages,
    stages_for_preset,
)


class TestPresets:
    def test_vuln_preset_runs_vuln_and_critique_only(self):
        s = stages_for_preset(PRESET_VULN)
        assert s.run_vuln is True
        assert s.run_critique is True          # always
        assert s.run_remediation is False
        assert s.run_chain is False
        assert s.run_sca is False
        assert s.run_integrity is False

    def test_vuln_patch_adds_remediation(self):
        s = stages_for_preset(PRESET_VULN_PATCH)
        assert s.run_vuln is True
        assert s.run_remediation is True
        assert s.run_chain is False
        assert s.run_critique is True

    def test_full_runs_everything(self):
        s = stages_for_preset(PRESET_FULL)
        assert all([s.run_vuln, s.run_sca, s.run_integrity, s.run_chain,
                    s.run_critique, s.run_remediation])

    def test_unknown_preset_raises(self):
        with pytest.raises(ValueError):
            stages_for_preset("nonsense")


class TestInvariants:
    def test_critique_cannot_be_disabled(self):
        s = StageSelection(run_critique=False).normalized()
        assert s.run_critique is True

    def test_remediation_implies_vuln(self):
        # Even if a caller tries vuln off + remediation on, vuln is forced on:
        s = StageSelection(run_vuln=False, run_remediation=True).normalized()
        assert s.run_vuln is True

    def test_no_separate_exploit_flag_exists(self):
        # Exploitation is welded into vuln; there is no independent exploit toggle.
        assert "run_exploit" not in StageSelection.__dataclass_fields__


class TestResolveStages:
    def test_none_is_full_pipeline(self):
        s = resolve_stages(None)
        assert s.run_remediation is True and s.run_chain is True

    def test_string_preset(self):
        assert resolve_stages("vuln").run_remediation is False

    def test_dict_with_preset(self):
        s = resolve_stages({"preset": "vuln"})
        assert s.run_remediation is False

    def test_dict_overrides_are_applied_then_normalized(self):
        s = resolve_stages({"preset": "vuln", "run_chain": True})
        assert s.run_chain is True
        assert s.run_critique is True  # still forced

    def test_dict_cannot_disable_critique(self):
        s = resolve_stages({"preset": "full", "run_critique": False})
        assert s.run_critique is True

    def test_bad_type_raises(self):
        with pytest.raises(TypeError):
            resolve_stages(123)
