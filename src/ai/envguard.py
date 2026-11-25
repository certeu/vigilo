"""Environment hygiene for agent subprocesses.

Agents run as the worker's own OS user with full tool access, and their environment is
built from the worker's ``os.environ`` plus per-call overrides. Whatever lives there is
readable by anything the scanned code manages to prompt-inject. Per-run secrets are
never put in the worker environment in the first place; this strips anything that
looks like one (redemption reference, git credentials, platform secrets) as defence in
depth, after the overrides are applied.
"""
from __future__ import annotations

import re
from collections.abc import MutableMapping

_PREFIXES = (
    "VIGILO_SECRET",
    "VIGILO_REDEEM",
    "VIGILO_RUN_SECRET",
    "VIGILO_GIT_TOKEN",
    "VIGILO_INTERNAL_API",
    "VIGILO_FERNET",
    "VIGILO_JWT",
    "VIGILO_DATABASE",
    "VIGILO_FIRST_ADMIN",
    "VIGILO_SMTP",
    "POSTGRES_",
    "PGPASSWORD",
)
_NAMES = frozenset({
    "GIT_ASKPASS", "SSH_ASKPASS", "GITLAB_TOKEN", "GITLAB_PRIVATE_TOKEN",
    "GITLAB_ACCESS_TOKEN", "CI_JOB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
    "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "POSTGRES_PASSWORD", "DATABASE_URL",
    "SMTP_PASSWORD",
})
# Anything that looks like a credential by name: ``*_PASSWORD``, ``*_SECRET*``,
# ``*_TOKEN``, ``*_PRIVATE_KEY`` ...
_SECRET_LOOKING = re.compile(
    r"(^|_)(PASSWORD|PASSWD|PASSPHRASE|SECRET|SECRETS|TOKEN|PRIVATE_KEY)(_|$)|SECRET", re.IGNORECASE,
)
# Variables the agent CLIs legitimately need to reach their model provider. These win
# over the name heuristic above (``ANTHROPIC_AUTH_TOKEN``, ``AWS_SECRET_ACCESS_KEY``,
# ``AWS_BEARER_TOKEN_BEDROCK``, ``CLAUDE_CODE_OAUTH_TOKEN``, ``OPENAI_API_KEY`` ...).
_PROVIDER_PREFIXES = (
    "ANTHROPIC_", "CLAUDE_CODE_", "CLAUDE_", "AWS_", "OPENAI_", "CODEX_", "OPENCODE_",
    "LITELLM_", "GOOGLE_", "GEMINI_", "AZURE_", "VERTEX_", "CLOUD_ML_", "OPENROUTER_",
)


def _is_secret(name: str) -> bool:
    if name in _NAMES or name.startswith(_PREFIXES):
        return True
    if name.startswith(_PROVIDER_PREFIXES):
        return False
    return bool(_SECRET_LOOKING.search(name))


def strip_secret_env(env: MutableMapping[str, str]) -> MutableMapping[str, str]:
    """Remove secret-bearing variables from ``env`` in place; returns it."""
    for name in [n for n in env if _is_secret(n)]:
        del env[name]
    return env
