"""Tests for ExecutionError non-retryable classification."""
from __future__ import annotations


def test_execution_error_in_non_retryable_list():
    """ExecutionError must be in the non-retryable error types list."""
    from src.greybox.temporal.workflows import _NON_RETRYABLE_TYPES

    assert "ExecutionError" in _NON_RETRYABLE_TYPES


def test_execution_error_raised_as_non_retryable():
    """The ExecutionError raised in run_greybox_agent must have non_retryable=True."""
    import ast
    from pathlib import Path

    source = Path("src/greybox/temporal/activities.py").read_text()
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "ApplicationError":
                for kw in node.keywords:
                    if kw.arg == "type" and isinstance(kw.value, ast.Constant):
                        if kw.value.value == "ExecutionError":
                            for kw2 in node.keywords:
                                if kw2.arg == "non_retryable":
                                    assert isinstance(kw2.value, ast.Constant)
                                    assert kw2.value.value is True, (
                                        "ExecutionError must have non_retryable=True"
                                    )
                                    return
    raise AssertionError("Could not find ApplicationError with type='ExecutionError'")
