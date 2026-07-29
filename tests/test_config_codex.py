"""config_codex.sh renders a valid config.toml from env vars."""
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "config_codex.sh"
TEMPLATE = Path(__file__).resolve().parents[1] / "configs" / "codex.template.toml"


@pytest.mark.skipif(not SCRIPT.exists(), reason="script not created yet")
def test_render(tmp_path):
    out = tmp_path / "config.toml"
    env = {
        "PATH": "/usr/bin:/bin",
        "CODEX_HOME": str(tmp_path),
        "CODEX_BASE_URL": "https://example.openai.azure.com/openai/v1",
        "CODEX_WIRE_API": "responses",
        "CODEX_REASONING_EFFORT": "high",
        "CODEX_MEDIUM_MODEL": "gpt-5-codex",
    }
    subprocess.run(["bash", str(SCRIPT), str(TEMPLATE), str(out)],
                   check=True, env=env)
    text = out.read_text()
    assert 'base_url = "https://example.openai.azure.com/openai/v1"' in text
    assert 'wire_api = "responses"' in text
    assert 'env_key = "CODEX_API_KEY"' in text
    assert 'model_reasoning_effort = "high"' in text
    assert "${" not in text  # every placeholder substituted


@pytest.mark.skipif(not SCRIPT.exists(), reason="script not created yet")
def test_render_uses_defaults(tmp_path):
    out = tmp_path / "config.toml"
    env = {"PATH": "/usr/bin:/bin", "CODEX_HOME": str(tmp_path)}
    subprocess.run(["bash", str(SCRIPT), str(TEMPLATE), str(out)],
                   check=True, env=env)
    text = out.read_text()
    assert 'base_url = "https://api.openai.com/v1"' in text
    assert "${" not in text


def _render_base_url(tmp_path, base_url):
    out = tmp_path / "config.toml"
    env = {
        "PATH": "/usr/bin:/bin",
        "CODEX_HOME": str(tmp_path),
        "CODEX_BASE_URL": base_url,
    }
    subprocess.run(["bash", str(SCRIPT), str(TEMPLATE), str(out)],
                   check=True, env=env)
    return out.read_text()


@pytest.mark.skipif(not SCRIPT.exists(), reason="script not created yet")
def test_appends_missing_version_path(tmp_path):
    # No /v1 in the operator's value -> config-codex must add it.
    text = _render_base_url(tmp_path, "https://example.openai.azure.com/openai")
    assert 'base_url = "https://example.openai.azure.com/openai/v1"' in text


@pytest.mark.skipif(not SCRIPT.exists(), reason="script not created yet")
def test_trailing_whitespace_does_not_double_version_path(tmp_path):
    # Regression: a stray trailing space defeated the "*/v1" glob and produced
    # ".../openai/v1 /v1/responses" (404). Whitespace must be trimmed, and the
    # single existing /v1 preserved — never doubled, never left with a space.
    text = _render_base_url(tmp_path, "https://example.openai.azure.com/openai/v1  ")
    assert 'base_url = "https://example.openai.azure.com/openai/v1"' in text
    assert "/v1/v1" not in text
    assert "/v1 " not in text


@pytest.mark.skipif(not SCRIPT.exists(), reason="script not created yet")
def test_crlf_carriage_return_is_trimmed(tmp_path):
    # A CR from a CRLF-terminated .env line is whitespace too.
    text = _render_base_url(tmp_path, "https://example.openai.azure.com/openai/v1\r")
    assert 'base_url = "https://example.openai.azure.com/openai/v1"' in text
    assert "\\r" not in text and "\r" not in text
