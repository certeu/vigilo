"""Unwrapping Temporal's wrapped failures to the real reason (temporal.py _unwrap_failure)."""
from __future__ import annotations

from src.webapi.engine.temporal import _unwrap_failure


class _Wrapper(Exception):
    """Stand-in for temporalio's ActivityError/WorkflowFailureError (has .cause)."""
    def __init__(self, message, cause=None):
        super().__init__(message)
        self.message = message
        self.cause = cause


def test_extracts_application_error_type_and_message():
    from temporalio.exceptions import ApplicationError
    app = ApplicationError("Target URL unreachable: http://x (timeout)", type="InvalidTargetError")
    # Temporal wraps it: WorkflowFailureError("Workflow execution failed") ->
    # ActivityError("Activity task failed") -> ApplicationError(real reason)
    wrapped = _Wrapper("Workflow execution failed", cause=_Wrapper("Activity task failed", cause=app))
    out = _unwrap_failure(wrapped)
    assert "InvalidTargetError" in out
    assert "Target URL unreachable: http://x" in out
    assert out != "Activity task failed"


def test_falls_back_to_nongeneric_message_when_no_application_error():
    wrapped = _Wrapper("Activity task failed", cause=_Wrapper("boom: something broke", cause=None))
    out = _unwrap_failure(wrapped)
    assert out == "boom: something broke"


def test_never_returns_empty():
    assert _unwrap_failure(_Wrapper("Activity task failed")).strip()
