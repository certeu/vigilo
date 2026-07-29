"""Prompt manager — loads, processes includes, and interpolates prompt templates.

Handles:
- Template loading from prompts/ directory
- @include() directive resolution (shared partials)
- Variable substitution ({{WEB_URL}}, {{REPO_PATH}}, etc.)
- Playwright session assignment per agent
- Login instruction assembly from config
- Feedback loop context injection
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import aiofiles

logger = logging.getLogger(__name__)

# Project root is three levels up from this file: src/services/prompt_manager.py
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PROMPTS_DIR = _PROJECT_ROOT / "prompts"

# Playwright session mapping — assigns each agent prompt to a browser session.
# Keys are prompt template names (matching AGENTS[x].prompt_template).
PLAYWRIGHT_SESSION_MAPPING: dict[str, str] = {
    # Phase 1: Pre-reconnaissance
    "pre-recon-code": "agent1",
    # Phase 2: Reconnaissance
    "recon": "agent2",
    # Phase 3: Vulnerability Analysis (8 parallel agents)
    "vuln-injection": "agent1",
    "vuln-xss": "agent2",
    "vuln-auth": "agent3",
    "vuln-ssrf": "agent4",
    "vuln-authz": "agent5",
    "vuln-graphql": "agent6",
    "vuln-websocket": "agent7",
    "vuln-crypto": "agent8",
    # Phase 4: Exploitation (7 parallel agents)
    "exploit-injection": "agent1",
    "exploit-xss": "agent2",
    "exploit-auth": "agent3",
    "exploit-ssrf": "agent4",
    "exploit-authz": "agent5",
    "exploit-graphql": "agent6",
    "exploit-websocket": "agent7",
    # Phase 5c: Critique (read-only review of findings_index)
    "critic": "agent2",
    # Phase 6: Reporting
    "report-executive": "agent3",
    # Phase 7: Remediation
    "remediation": "agent1",
}

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


async def _build_login_instructions(authentication: dict[str, Any]) -> str:
    """Build complete login instructions from the authentication config.

    Reads the login-instructions.txt template, extracts sections based on
    login type (FORM/SSO), interpolates credentials, and returns the
    assembled instructions block.
    """
    login_instructions_path = PROMPTS_DIR / "shared" / "login-instructions.txt"

    if not login_instructions_path.is_file():
        logger.warning("Login instructions template not found at %s", login_instructions_path)
        return ""

    full_template = await _read_file(login_instructions_path)

    def _get_section(content: str, section_name: str) -> str:
        pattern = re.compile(
            rf"<!-- BEGIN:{section_name} -->(.*?)<!-- END:{section_name} -->",
            re.DOTALL,
        )
        match = pattern.search(content)
        return match.group(1).strip() if match else ""

    login_type = (authentication.get("login_type") or "").upper()

    common_section = _get_section(full_template, "COMMON")
    auth_section = _get_section(full_template, login_type) if login_type else ""
    verification_section = _get_section(full_template, "VERIFICATION")

    # Assemble instructions from sections (fallback to full template if markers missing)
    if not common_section and not auth_section and not verification_section:
        logger.warning("Section markers not found, using full login instructions template")
        login_instructions = full_template
    else:
        login_instructions = "\n\n".join(
            section for section in [common_section, auth_section, verification_section] if section
        )

    # Interpolate login flow and credential placeholders
    user_instructions = "\n".join(authentication.get("login_flow") or [])

    credentials = authentication.get("credentials") or {}
    if credentials.get("username"):
        user_instructions = user_instructions.replace("$username", credentials["username"])
    if credentials.get("password"):
        user_instructions = user_instructions.replace("$password", credentials["password"])
    if credentials.get("totp_secret"):
        user_instructions = user_instructions.replace(
            "$totp",
            f'generated TOTP code using secret "{credentials["totp_secret"]}"',
        )

    login_instructions = login_instructions.replace("{{user_instructions}}", user_instructions)

    # Replace TOTP secret placeholder if present in template, or strip the TOTP lines
    if credentials.get("totp_secret"):
        login_instructions = login_instructions.replace("{{totp_secret}}", credentials["totp_secret"])
    else:
        login_instructions = "\n".join(
            line for line in login_instructions.splitlines()
            if "{{totp_secret}}" not in line
        )

    return login_instructions


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
        avoid_rules = config.get("avoid") or []
        focus_rules = config.get("focus") or []
        has_avoid = len(avoid_rules) > 0
        has_focus = len(focus_rules) > 0

        if not has_avoid and not has_focus:
            # Replace entire <rules> block with clean message
            clean_rules = "<rules>\nNo specific rules or focus areas provided for this test.\n</rules>"
            result = re.sub(r"<rules>[\s\S]*?</rules>", clean_rules, result)
            # Also replace bare placeholders from @include(shared/_rules.txt)
            result = result.replace("{{RULES_AVOID}}", "None").replace("{{RULES_FOCUS}}", "None")
        else:
            avoid_str = (
                "\n".join(f"- {r.get('description', r) if isinstance(r, dict) else r}" for r in avoid_rules)
                if has_avoid
                else "None"
            )
            focus_str = (
                "\n".join(f"- {r.get('description', r) if isinstance(r, dict) else r}" for r in focus_rules)
                if has_focus
                else "None"
            )
            result = result.replace("{{RULES_AVOID}}", avoid_str).replace("{{RULES_FOCUS}}", focus_str)
    else:
        clean_rules = "<rules>\nNo specific rules or focus areas provided for this test.\n</rules>"
        result = re.sub(r"<rules>[\s\S]*?</rules>", clean_rules, result)
        # Also replace bare placeholders from @include(shared/_rules.txt)
        result = result.replace("{{RULES_AVOID}}", "None").replace("{{RULES_FOCUS}}", "None")

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def load_prompt(
    prompt_name: str,
    web_url: str,
    repo_path: str,
    config: dict[str, Any] | None = None,
    extra_context: str = "",
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
        Optional distributed config dict with authentication, rules, description.
        ``{"avoid": [...], "focus": [...], "authentication": {...}, "description": "..."}``.
    extra_context:
        Additional text appended to the end of the prompt (used for feedback loops).

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
    playwright_session = PLAYWRIGHT_SESSION_MAPPING.get(prompt_name, "agent1")
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
    auth = config.get("authentication", {}) if config else {}
    if auth.get("login_type") == "cookie" and auth.get("cookie_header"):
        cookie_instructions = (
            "## Pre-Authenticated Session\n\n"
            "Session cookies have been provided by the operator (EU Login / external SSO). "
            "**Do NOT attempt to log in or navigate to any login page.**\n\n"
            "Before interacting with the application, inject these cookies into your "
            "Playwright browser context:\n\n"
            "```javascript\n"
            f'await page.setExtraHTTPHeaders({{ "Cookie": "{auth["cookie_header"]}" }});\n'
            "```\n\n"
            "Alternatively, parse and add individual cookies via "
            "`context.addCookies([...])`. The session is already authenticated — "
            "proceed directly to testing."
        )
        result = result.replace("{{LOGIN_INSTRUCTIONS}}", cookie_instructions)
    elif auth.get("login_flow"):
        login_instructions = await _build_login_instructions(auth)
        result = result.replace("{{LOGIN_INSTRUCTIONS}}", login_instructions)
    else:
        result = result.replace("{{LOGIN_INSTRUCTIONS}}", "")

    # 7. Warn about unresolved placeholders
    remaining = _PLACEHOLDER_RE.findall(result)
    if remaining:
        logger.warning("Found unresolved placeholders in prompt: %s", ", ".join(remaining))

    # 8. Append extra context for feedback loops
    if extra_context:
        result = f"{result}\n\n--- Additional Context (Feedback Loop) ---\n{extra_context}"

    return result


# ---------------------------------------------------------------------------
# Grey-box prompt interpolation
# ---------------------------------------------------------------------------


def _interpolate_greybox_variables(
    template: str,
    *,
    web_url: str,
    assigned_targets: str = "",
    graph_slice: str = "",
    graph_summary: str = "",
    endpoint_context: str = "",
    identities: str = "",
    identities_block: str = "",
    identity_count: str = "",
    recent_signals: str = "",
    active_agents: str = "",
    budget_status: str = "",
    chain_candidates: str = "",
    login_instructions: str = "",
    description: str = "",
    rules_avoid: str = "",
    rules_focus: str = "",
    playwright_session: str = "",
    dispatch_mode: str = "",
    vuln_type: str = "",
    param_ids: str = "",
    lead_id: str = "",
    lead_signal: str = "",
    lead_hypothesis: str = "",
    evidence_blob_path: str = "",
    identity: str = "",
    auth_session_dir: str = "",
) -> str:
    """Interpolate grey-box specific variables into a prompt template.

    ``{{IDENTITIES}}`` prefers ``identities_block`` (per-identity login
    blocks joined by ``---``) when non-empty; falls back to ``identities``
    (comma-listed names) for backward compatibility.
    """
    replacements = {
        "{{WEB_URL}}": web_url,
        "{{ASSIGNED_TARGETS}}": assigned_targets,
        "{{GRAPH_SLICE}}": graph_slice,
        "{{GRAPH_SUMMARY}}": graph_summary,
        "{{ENDPOINT_CONTEXT}}": endpoint_context,
        "{{IDENTITIES}}": identities_block or identities,
        "{{IDENTITY_COUNT}}": identity_count,
        "{{RECENT_SIGNALS}}": recent_signals,
        "{{ACTIVE_AGENTS}}": active_agents,
        "{{BUDGET_STATUS}}": budget_status,
        "{{CHAIN_CANDIDATES}}": chain_candidates,
        "{{LOGIN_INSTRUCTIONS}}": login_instructions,
        "{{DESCRIPTION}}": description,
        "{{RULES_AVOID}}": rules_avoid,
        "{{RULES_FOCUS}}": rules_focus,
        "{{PLAYWRIGHT_SESSION}}": playwright_session,
        "{{DISPATCH_MODE}}": dispatch_mode,
        "{{VULN_TYPE}}": vuln_type,
        "{{PARAM_IDS}}": param_ids,
        "{{LEAD_ID}}": lead_id,
        "{{LEAD_SIGNAL}}": lead_signal,
        "{{LEAD_HYPOTHESIS}}": lead_hypothesis,
        "{{EVIDENCE_BLOB_PATH}}": evidence_blob_path,
        "{{IDENTITY}}": identity,
        "{{AUTH_SESSION_DIR}}": auth_session_dir,
    }
    result = template
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)
    unresolved = _PLACEHOLDER_RE.findall(result)
    if unresolved:
        raise PromptSubstitutionError(unresolved)
    return result
