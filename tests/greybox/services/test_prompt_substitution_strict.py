"""Slice 17 / G3: strict template substitution for grey-box prompts.

``_interpolate_greybox_variables`` used to warn on unresolved ``{{PLACEHOLDER}}``
tokens and ship them to Claude. That masked template/resolver bugs and surfaced
only on expensive downstream failures. Post-G3, the function raises
:class:`PromptSubstitutionError` — a non-retryable Temporal error.
"""
from __future__ import annotations

import pytest

from src.services.prompt_manager import (
    PromptSubstitutionError,
    _interpolate_greybox_variables,
)


def test_unresolved_placeholder_raises():
    template = "Hello {{WEB_URL}} and {{DOES_NOT_EXIST}}"
    with pytest.raises(PromptSubstitutionError) as ei:
        _interpolate_greybox_variables(template, web_url="http://target")
    assert "DOES_NOT_EXIST" in str(ei.value)


def test_multiple_unresolved_all_reported():
    template = "{{UNKNOWN_ONE}} and {{UNKNOWN_TWO}}"
    with pytest.raises(PromptSubstitutionError) as ei:
        _interpolate_greybox_variables(template, web_url="http://x")
    msg = str(ei.value)
    assert "UNKNOWN_ONE" in msg
    assert "UNKNOWN_TWO" in msg


def test_all_resolved_succeeds():
    template = "URL={{WEB_URL}} Graph={{GRAPH_SLICE}}"
    result = _interpolate_greybox_variables(
        template, web_url="http://target", graph_slice="slice-data"
    )
    assert result == "URL=http://target Graph=slice-data"


def test_empty_optional_placeholder_substitutes_to_empty_string_not_error():
    # Known placeholders with default-empty resolver args must NOT raise even
    # when their value is the empty string — strict mode only catches
    # placeholders the resolver doesn't know about.
    template = "Desc={{DESCRIPTION}} Avoid={{RULES_AVOID}}"
    result = _interpolate_greybox_variables(template, web_url="http://x")
    assert result == "Desc= Avoid="


def test_unresolved_placeholders_exposed_on_exception():
    template = "{{FOO}} {{BAR}}"
    with pytest.raises(PromptSubstitutionError) as ei:
        _interpolate_greybox_variables(template, web_url="http://x")
    assert set(ei.value.unresolved) == {"{{FOO}}", "{{BAR}}"}


def test_non_retryable_error_name_matches_activity_list():
    # Guardrail: the class name must appear in activities.py NON_RETRYABLE_ERRORS
    # so Temporal's error classifier routes it correctly.
    from src.greybox.temporal.activities import NON_RETRYABLE_ERRORS

    assert "PromptSubstitutionError" in NON_RETRYABLE_ERRORS
