"""Prompt manager — loads, processes includes, and interpolates prompt templates.

Handles:
- Template loading from prompts/ directory
- @include() directive resolution (shared partials)
- Variable substitution ({{WEB_URL}}, {{REPO_PATH}}, etc.)
- Playwright session assignment per agent
- Login-block assembly from config (white-box actors)
- Per-instance assignment context injection
"""

from __future__ import annotations

import logging
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiofiles

# Playwright session mapping (prompt template -> browser session). The single
# source of truth lives in src/session_manager.py next to the agent registry;
# re-exported here for callers that import it from this module.
from src.session_manager import PLAYWRIGHT_SESSION_MAPPING

logger = logging.getLogger(__name__)

# Project root is three levels up from this file: src/services/prompt_manager.py
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PROMPTS_DIR = _PROJECT_ROOT / "prompts"

_INCLUDE_RE = re.compile(r"@include\(([^)]+)\)")
_PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}")


class PromptSubstitutionError(Exception):
    """Raised when a grey-box prompt still contains ``{{PLACEHOLDER}}`` tokens
    after interpolation. Unresolved placeholders indicate a template bug or a
    missing resolver key — ship-time, not transient — so Temporal treats this
    as non-retryable.
    """

    def __init__(self, unresolved: list[str]) -> None:
        self.unresolved = unresolved
        super().__init__(
            "Unresolved placeholders in grey-box prompt: "
            + ", ".join(sorted(set(unresolved)))
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _read_file(path: Path) -> str:
    """Read a file as UTF-8 text via aiofiles."""
    async with aiofiles.open(path, mode="r", encoding="utf-8") as f:
        return await f.read()


async def _process_includes(content: str, base_dir: Path) -> str:
    """Resolve all @include() directives, replacing them with file contents.

    Validates that included paths do not escape the base directory (path traversal check).
    """
    resolved_base = base_dir.resolve()

    matches = list(_INCLUDE_RE.finditer(content))
    if not matches:
        return content

    replacements: list[tuple[str, str]] = []
    for match in matches:
        raw_path = match.group(1).strip()
        include_path = (base_dir / raw_path).resolve()

        # Path traversal guard
        try:
            include_path.relative_to(resolved_base)
        except ValueError:
            raise ValueError(
                f"Path traversal detected in @include(): {raw_path} "
                f"(resolved to {include_path}, base is {resolved_base})"
            )

        if not include_path.is_file():
            raise FileNotFoundError(
                f"Included file not found: {include_path} (from @include({raw_path}))"
            )

        partial_content = await _read_file(include_path)
        replacements.append((match.group(0), partial_content))

    for placeholder, replacement_content in replacements:
        content = content.replace(placeholder, replacement_content)

    return content


def _build_auth_context(config: dict[str, Any] | None) -> str:
    """Build a human-readable auth context summary from config."""
    if not config or not config.get("authentication"):
        return "No authentication configured - unauthenticated testing only"

    auth = config["authentication"]
    login_type = auth.get("login_type", "unknown")

    if login_type == "cookie":
        lines = [
            "- Login type: PRE-AUTHENTICATED COOKIE",
            f"- Login URL: {auth.get('login_url', 'N/A')}",
            "- Session cookies provided by operator (EU Login / external SSO)",
        ]
        return "\n".join(lines)

    lines = [
        f"- Login type: {login_type.upper()}",
        f"- Username: {(auth.get('credentials') or {}).get('username', 'N/A')}",
        f"- Login URL: {auth.get('login_url', 'N/A')}",
    ]

    if (auth.get("credentials") or {}).get("totp_secret"):
        lines.append("- MFA: TOTP enabled")

    return "\n".join(lines)


def _rule_text(rule: Any) -> str:
    """One operator rule as a line of text.

    Rules are plain strings (top-level / platform shape) or ``Rule`` dicts
    (``{"description": ..., "type": "path", "url_path": "/admin"}``, the YAML
    shape); a dict's ``url_path`` is appended when the description does not
    already mention it.
    """
    if not isinstance(rule, dict):
        return str(rule).strip()
    text = str(rule.get("description", rule)).strip()
    url_path = str(rule.get("url_path") or "").strip()
    if url_path and url_path not in text:
        text = f"{text} (path: {url_path})"
    return text


def _rule_list(value: Any) -> list[str]:
    """Normalise one ``avoid``/``focus`` value to a list of rule lines.

    Accepts a list of strings or ``Rule`` dicts, a single dict, or free text
    (the platform's per-repository scan settings are a textarea): one rule per
    non-empty line, with any leading bullet stripped.
    """
    if not value:
        return []
    if isinstance(value, str):
        lines = (re.sub(r"^\s*(?:[-*\u2022]|\d+[.)])\s+", "", ln).strip() for ln in value.splitlines())
        return [ln for ln in lines if ln]
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return [str(value)]
    return [t for t in (_rule_text(r) for r in value) if t]


def _rules_from_config(config: dict[str, Any]) -> tuple[list[str], list[str]]:
    """``(avoid, focus)`` rule lines from any supported config shape.

    - Nested shape (``src/types/config.py``):
      ``rules: {avoid: [Rule...], focus: [Rule...]}``.
    - Flat dict (platform scan settings, older callers): top-level ``avoid`` /
      ``focus`` as lists or free text.
    Both are merged when present, without repeating a rule.
    """
    nested = config.get("rules")
    nested = nested if isinstance(nested, dict) else {}
    out: list[list[str]] = []
    for key in ("avoid", "focus"):
        merged = _rule_list(config.get(key)) + _rule_list(nested.get(key))
        out.append(list(dict.fromkeys(merged)))
    return out[0], out[1]


def _interpolate_variables(
    template: str,
    web_url: str,
    repo_path: str,
    playwright_session: str,
    config: dict[str, Any] | None,
) -> str:
    """Perform variable substitution on the template string.

    Handles: {{WEB_URL}}, {{REPO_PATH}}, {{PLAYWRIGHT_SESSION}},
    {{DESCRIPTION}}, {{AUTH_CONTEXT}}, {{RULES_AVOID}}, {{RULES_FOCUS}}.
    Login instructions and rules sections require further async processing,
    so they are partially handled here.
    """
    result = (
        template
        .replace("{{WEB_URL}}", web_url or "[no target URL — code-only analysis]")
        .replace("{{REPO_PATH}}", repo_path)
        .replace("{{PLAYWRIGHT_SESSION}}", playwright_session)
        .replace("{{AUTH_CONTEXT}}", _build_auth_context(config))
        .replace(
            "{{DESCRIPTION}}",
            f"Description: {config['description']}" if config and config.get("description") else "",
        )
    )

    if config:
        avoid_rules, focus_rules = _rules_from_config(config)
        has_avoid = len(avoid_rules) > 0
        has_focus = len(focus_rules) > 0

        if not has_avoid and not has_focus:
            # Replace entire <rules> block with clean message
            clean_rules = "<rules>\nNo specific rules or focus areas provided for this test.\n</rules>"
            result = re.sub(r"<rules>[\s\S]*?</rules>", clean_rules, result)
            # Also replace bare placeholders from @include(shared/_rules.txt)
            result = result.replace("{{RULES_AVOID}}", "None").replace("{{RULES_FOCUS}}", "None")
        else:
            avoid_str = "\n".join(f"- {r}" for r in avoid_rules) if has_avoid else "None"
            focus_str = "\n".join(f"- {r}" for r in focus_rules) if has_focus else "None"
            result = result.replace("{{RULES_AVOID}}", avoid_str).replace("{{RULES_FOCUS}}", focus_str)
    else:
        clean_rules = "<rules>\nNo specific rules or focus areas provided for this test.\n</rules>"
        result = re.sub(r"<rules>[\s\S]*?</rules>", clean_rules, result)
        # Also replace bare placeholders from @include(shared/_rules.txt)
        result = result.replace("{{RULES_AVOID}}", "None").replace("{{RULES_FOCUS}}", "None")

    return result


_WHITEBOX_PREFIX = "whitebox/"
# White-box actors that never touch the live target get no login block (and
# so no credentials) at all.
_WHITEBOX_NO_LIVE_TARGET = frozenset({"whitebox/planner"})


def takes_login_block(prompt_name: str) -> bool:
    """True for white-box actors whose prompt carries a login block, i.e. those that
    test the live target (every ``whitebox/*`` prompt except the planner)."""
    return prompt_name.startswith(_WHITEBOX_PREFIX) and prompt_name not in _WHITEBOX_NO_LIVE_TARGET


_FILL_RE = re.compile(r"\{\{([A-Z_]+)\}\}")
_SUCCESS_CONDITIONS = {
    "url_contains": "the browser URL contains `{value}`.",
    "url_equals_exactly": "the browser URL is exactly `{value}`.",
    "element_present": "the page shows an element matching `{value}`.",
}


def _fill(template: str, values: dict[str, str]) -> str:
    """Substitute ``{{KEY}}`` in one pass, so values are never re-substituted."""
    return _FILL_RE.sub(lambda m: values.get(m.group(1), m.group(0)), template)


def _success_condition_text(auth: dict[str, Any]) -> str:
    cond = auth.get("success_condition") or {}
    ctype = str(cond.get("type") or "").strip() if isinstance(cond, dict) else ""
    value = str(cond.get("value") or "").strip() if isinstance(cond, dict) else ""
    if ctype and value:
        template = _SUCCESS_CONDITIONS.get(ctype, f"`{ctype}` is satisfied for `{{value}}`.")
        return template.format(value=value)
    return (
        "no success condition is configured; you are logged in when you are off the "
        "login page, no authentication error is shown, and content only a logged-in "
        "user sees is visible."
    )


def _whitebox_login_steps(auth: dict[str, Any], credentials: dict[str, Any]) -> str:
    """The numbered login steps: the operator's ``login_flow``, or a generic flow."""
    totp_hint = (
        f"the code printed by `generate-totp --secret {credentials['totp_secret']}`"
        if credentials.get("totp_secret") else "$totp"
    )
    subs = {
        "username": str(credentials.get("username") or "$username"),
        "password": str(credentials.get("password") or "$password"),
        "totp": totp_hint,
    }
    flow = [str(step) for step in (auth.get("login_flow") or []) if str(step).strip()]
    if flow:
        steps = [re.sub(r"\$(username|password|totp)", lambda m: subs[m.group(1)], step) for step in flow]
        steps.append(
            "Wait for the page to settle after any step that navigates, and click "
            'through consent or "Continue as" prompts.'
        )
    elif (auth.get("login_type") or "").lower() == "sso":
        steps = [
            "Open the login URL with `playwright-cli` and choose the single sign-on option.",
            "Sign in on the identity provider's page with the username and password above"
            + (" and the TOTP code" if credentials.get("totp_secret") else "") + ".",
            'Accept consent screens and "Continue as" prompts, and let the redirects back '
            "to the application finish.",
        ]
    else:
        steps = [
            "Open the login URL with `playwright-cli` and find the login form.",
            "Fill in the username and password above"
            + (", and the TOTP code when asked" if credentials.get("totp_secret") else "")
            + ", then submit.",
            "Wait for the page to settle and click through any consent prompt.",
        ]
    return "\n".join(f"{n}. {step}" for n, step in enumerate(steps, 1))


def _parse_cookie_header(header: str) -> list[tuple[str, str]]:
    cookies = []
    for part in header.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name.strip():
            cookies.append((name.strip(), value.strip()))
    return cookies


async def _build_whitebox_login(
    prompt_name: str,
    auth: dict[str, Any],
    web_url: str,
    playwright_session: str,
) -> str:
    """Login block for white-box actors (``prompts/whitebox/shared/_login.txt``).

    A failed login never halts the agent: source
    analysis is the primary work, so the agent records the failure and carries
    on code-only. Code-only runs (no ``web_url``) get no login at all, and
    actors that never touch the live target (the planner) get no credentials.
    """
    path = PROMPTS_DIR / "whitebox" / "shared" / "_login.txt"
    full = await _read_file(path)

    def section(name: str) -> str:
        m = re.search(rf"<!-- BEGIN:{name} -->(.*?)<!-- END:{name} -->", full, re.DOTALL)
        return m.group(1).strip() if m else ""

    if not web_url:
        return section("CODE_ONLY")
    if prompt_name in _WHITEBOX_NO_LIVE_TARGET or not auth:
        return ""

    login_type = str(auth.get("login_type") or "").lower()
    host = urlparse(web_url).hostname or web_url
    values = {
        "WEB_URL": web_url,
        "PLAYWRIGHT_SESSION": playwright_session,
        "TARGET_HOST": host,
        "SUCCESS_CONDITION": _success_condition_text(auth),
    }

    if login_type == "cookie":
        cookie_header = str(auth.get("cookie_header") or "").strip()
        cookies = _parse_cookie_header(cookie_header)
        if not cookies:
            return ""
        values["COOKIE_SET_COMMANDS"] = "\n".join(
            f"playwright-cli -s={playwright_session} cookie-set {shlex.quote(name)} "
            f"{shlex.quote(value)} --domain={shlex.quote(host)}"
            for name, value in cookies
        )
        values["CURL_COOKIE_HEADER"] = shlex.quote(f"Cookie: {cookie_header}")
        values["CURL_URL"] = shlex.quote(web_url)
        body = section("COOKIE")
    else:
        credentials = auth.get("credentials") or {}
        if not (credentials.get("username") or credentials.get("password") or auth.get("login_flow")):
            return ""
        totp = credentials.get("totp_secret")
        values.update({
            "LOGIN_TYPE": (login_type or "form").upper(),
            "LOGIN_URL": str(auth.get("login_url") or web_url),
            "USERNAME": str(credentials.get("username") or "(not provided)"),
            "PASSWORD": str(credentials.get("password") or "(not provided)"),
            "TOTP_LINE": (
                f"- TOTP: run `generate-totp --secret {totp}` for a fresh code each time one is asked for\n"
                if totp else ""
            ),
            "LOGIN_STEPS": _whitebox_login_steps(auth, credentials),
        })
        body = section("CREDENTIALS")
    return _fill(body + "\n\n" + section("ON_FAILURE"), values)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def session_for_prompt(prompt_name: str, instance: int | None = None) -> str:
    """Return the Playwright session name for a prompt, optionally per instance.

    Agents that run as several parallel instances of one prompt (``investigator-1``,
    ``investigator-2``…) must not share a browser session, or their logins and
    navigation interfere. Passing ``instance`` suffixes the base session so each
    instance gets its own: ``whitebox/investigator`` + 3 → ``agent2-3``.
    Unknown prompts fall back to ``agent1``.

    Instances are numbered from 1. ``None`` means "not an instanced agent" and
    returns the base session. An out-of-range number (0, negative) is a caller
    bug, but failing the prompt load would only make the activity retry the
    same bug forever, so it is logged and also mapped to the base session,
    which no correctly numbered instance (``agent2-1``…) ever uses.
    """
    base = PLAYWRIGHT_SESSION_MAPPING.get(prompt_name, "agent1")
    if instance is None:
        return base
    if isinstance(instance, bool) or not isinstance(instance, int) or instance < 1:
        logger.warning(
            "Invalid instance %r for %s (instances are numbered from 1); using base session %s",
            instance, prompt_name, base,
        )
        return base
    return f"{base}-{instance}"


async def load_prompt(
    prompt_name: str,
    web_url: str,
    repo_path: str,
    config: dict[str, Any] | None = None,
    extra_context: str = "",
    instance: int | None = None,
) -> str:
    """Load a prompt template by name, process includes, and substitute variables.

    Parameters
    ----------
    prompt_name:
        Base name of the prompt file (without .txt extension).
    web_url:
        Target web application URL (substituted into {{WEB_URL}}).
    repo_path:
        Path to the repository under test (substituted into {{REPO_PATH}}).
    config:
        Optional config dict with authentication, rules, description: the YAML
        shape (``{"rules": {"avoid": [...], "focus": [...]}, ...}``) or a flat
        one (``{"avoid": ..., "focus": ..., ...}``); see :func:`_rules_from_config`.
    extra_context:
        Additional text appended to the end of the prompt: for ``whitebox/*``
        prompts the instance's assignment line (``LEADS: L-001,L-004``) under
        ``--- Your Assignment ---``; for reused prompts a note under
        ``--- Additional Context ---``.
    instance:
        1-based instance number for agents that run as several parallel copies
        of one prompt; gives each copy its own Playwright session. See
        :func:`session_for_prompt`.

    Returns
    -------
    str
        The fully resolved and interpolated prompt text.
    """
    # 1. Resolve prompt file path
    prompts_dir = PROMPTS_DIR
    prompt_path = prompts_dir / f"{prompt_name}.txt"

    if not prompt_path.is_file():
        raise FileNotFoundError(f"Prompt file not found: {prompt_path}")

    # 2. Assign Playwright session
    playwright_session = session_for_prompt(prompt_name, instance)
    if prompt_name in PLAYWRIGHT_SESSION_MAPPING:
        logger.info("Assigned %s -> %s", prompt_name, playwright_session)
    else:
        logger.warning("Unknown agent %s, using fallback -> %s", prompt_name, playwright_session)

    # 3. Read template file
    template = await _read_file(prompt_path)

    # 4. Process @include directives
    template = await _process_includes(template, prompts_dir)

    # 5. Interpolate simple variables
    result = _interpolate_variables(template, web_url, repo_path, playwright_session, config)

    # 6. Handle login instructions (async — needs file read)
    auth = (config.get("authentication") or {}) if config else {}
    if prompt_name.startswith(_WHITEBOX_PREFIX):
        whitebox_login = await _build_whitebox_login(prompt_name, auth, web_url, playwright_session)
        result = result.replace("{{LOGIN_INSTRUCTIONS}}", whitebox_login)
    else:
        result = result.replace("{{LOGIN_INSTRUCTIONS}}", "")

    # 7. Warn about unresolved placeholders
    remaining = _PLACEHOLDER_RE.findall(result)
    if remaining:
        logger.warning("Found unresolved placeholders in prompt: %s", ", ".join(remaining))

    # 8. Append extra context: the white-box engine's per-instance assignment
    # (``LEADS: L-001,L-004`` / ``FINDINGS: VG-002``), or the engine's note to
    # a reused prompt (the reporter's evidence-file naming).
    if extra_context:
        header = (
            "--- Your Assignment ---"
            if prompt_name.startswith(_WHITEBOX_PREFIX)
            else "--- Additional Context ---"
        )
        result = f"{result}\n\n{header}\n{extra_context}"

    return result

