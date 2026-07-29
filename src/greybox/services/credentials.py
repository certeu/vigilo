"""Credential loading and login instruction assembly for grey-box pipeline."""
from __future__ import annotations

import logging
from pathlib import Path

import yaml

from src.greybox.types.config import IdentityConfig

logger = logging.getLogger(__name__)


def load_identities(creds_path: Path) -> list[IdentityConfig]:
    """Load identity configurations from a YAML credentials file."""
    if not creds_path.exists():
        raise FileNotFoundError(f"Credentials file not found: {creds_path}")
    raw = yaml.safe_load(creds_path.read_text())
    identities = []
    for entry in raw.get("identities", []):
        identities.append(IdentityConfig(**entry))
    return identities


def build_login_block(identity: IdentityConfig, web_url: str) -> str:
    """Build login instructions for a single identity."""
    if identity.login is None:
        return ""
    login = identity.login
    url = login.get("url", web_url + "/login")
    fields = login.get("fields", {})
    success = login.get("success_indicator", "")

    lines = [
        f"**Identity: {identity.name}** (role: {identity.role}, "
        f"privilege: {identity.privilege_level})",
        "",
        f"1. Navigate to {url}",
    ]
    step = 2
    for field_name, field_value in fields.items():
        lines.append(f"{step}. Enter `{field_value}` into the {field_name} field")
        step += 1
    lines.append(f"{step}. Click the login/submit button")
    step += 1
    if success:
        lines.append(f"{step}. Verify you see '{success}' indicating successful login")

    if identity.totp_secret:
        lines.append("")
        lines.append(f"**2FA**: Use `generate-totp {identity.totp_secret}` "
                     f"to get a TOTP code")
    return "\n".join(lines)


def build_identities_block(
    identities: list[IdentityConfig], web_url: str
) -> str:
    """Concatenate per-identity login blocks for the ``{{IDENTITIES}}`` var.

    Identities without a ``login`` config (anonymous/private) are skipped —
    they have no actionable login steps for the specialist. An empty input
    list yields a deterministic placeholder string so downstream prompt
    substitution never surfaces a raw ``{{IDENTITIES}}`` placeholder.

    Multiple identities are separated by a line containing only ``---`` so
    the specialist can visually parse each block.
    """
    blocks: list[str] = []
    for i in identities:
        if i.cookie_header and i.cookie_header.strip():
            blocks.append(
                f"**Identity: {i.name}** (role: {i.role}, "
                f"privilege: {i.privilege_level})\n\n"
                f"Pre-authenticated via cookie. Session cookies are already "
                f"injected. Do not attempt to log in."
            )
        elif i.login is not None:
            block = build_login_block(i, web_url)
            if block:
                blocks.append(block)
    if not blocks:
        return "No authenticated identities configured."
    return "\n---\n".join(blocks)
