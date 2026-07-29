"""Phase-structure invariants for the grey-box workflow.

After Slice 13 B, managed scans run inside Phase 1 alongside discovery.
The workflow class therefore exposes exactly four phase methods and no
standalone ``_run_managed_scans`` step.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from unittest.mock import MagicMock

# Prefer the real temporalio package when available so we don't disturb
# sibling tests that rely on it (``tests/greybox/test_worker.py``,
# ``tests/greybox/test_workflow.py``). Fall back to lightweight mocks so this
# module can still be imported in isolation.
try:
    import temporalio  # noqa: F401
except Exception:  # pragma: no cover — only hit in standalone runs
    _workflow_mod = MagicMock()
    _workflow_mod.defn = lambda cls=None, **kw: cls if cls else (lambda c: c)
    _workflow_mod.run = lambda fn: fn
    _workflow_mod.query = lambda fn: fn
    _workflow_mod.signal = lambda fn: fn

    @contextmanager
    def _passthrough():
        yield

    _workflow_mod.unsafe.imports_passed_through = _passthrough

    _temporal_mock = MagicMock()
    _temporal_mock.workflow = _workflow_mod

    _common_mod = MagicMock()
    _common_mod.RetryPolicy = MagicMock
    _temporal_mock.common = _common_mod

    _exceptions_mod = MagicMock()
    _temporal_mock.exceptions = _exceptions_mod

    _activity_mod = MagicMock()
    _activity_mod.defn = lambda fn=None, **kw: fn if fn else (lambda f: f)
    _activity_mod.heartbeat = MagicMock()
    _temporal_mock.activity = _activity_mod

    sys.modules["temporalio"] = _temporal_mock
    sys.modules["temporalio.workflow"] = _workflow_mod
    sys.modules["temporalio.common"] = _common_mod
    sys.modules["temporalio.exceptions"] = _exceptions_mod
    sys.modules["temporalio.activity"] = _activity_mod

sys.modules.setdefault("aiofiles", MagicMock())

from src.greybox.temporal.workflows import GreyBoxPipelineWorkflow  # noqa: E402


EXPECTED_PHASE_METHODS = [
    "phase_1_preflight_discovery_scans",
    "phase_2_reactive_loop",
    "phase_3_chain_exploitation",
    "phase_4_report",
]


class TestPhaseMethodNames:
    """The workflow class must expose exactly the four phase methods above."""

    def test_all_phase_methods_present(self) -> None:
        for name in EXPECTED_PHASE_METHODS:
            assert hasattr(GreyBoxPipelineWorkflow, name), (
                f"Expected phase method {name} on GreyBoxPipelineWorkflow"
            )

    def test_managed_scans_method_removed(self) -> None:
        assert not hasattr(GreyBoxPipelineWorkflow, "_run_managed_scans"), (
            "_run_managed_scans should have been folded into phase_1_preflight_discovery_scans"
        )

    def test_legacy_phase_methods_removed(self) -> None:
        for legacy in (
            "_run_preflight",
            "_run_reactive_loop",
            "_run_chain_exploitation",
            "_run_report",
        ):
            assert not hasattr(GreyBoxPipelineWorkflow, legacy), (
                f"Legacy phase method {legacy} should have been renamed"
            )


class TestInitialPhaseValue:
    """The initial ``current_phase`` uses the new naming scheme."""

    def test_initial_phase_is_phase_1(self) -> None:
        wf = GreyBoxPipelineWorkflow()
        assert wf.current_phase == "phase_1"
