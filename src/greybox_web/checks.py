"""Catalogue of user-selectable grey-box checks.

Discovery tools always run and are not selectable. The M2 tool registry
(``tools/__init__.py``) binds implementations to these ids.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    description: str
    default_enabled: bool = True
    requires_auth_testing: bool = False


@dataclass(frozen=True)
class CheckArea:
    name: str
    evidence: str
    checks: frozenset[str]


CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec("headers.security", "Security headers",
              "Missing CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, "
              "Referrer-Policy, and HSTS on https."),
    CheckSpec("headers.disclosure", "Version disclosure",
              "Server or X-Powered-By headers that reveal a software version."),
    CheckSpec("cors.policy", "CORS policy",
              "Arbitrary origins reflected together with credentials."),
    CheckSpec("cookies.flags", "Cookie flags",
              "Cookies missing HttpOnly, Secure (https) or SameSite."),
    CheckSpec("exposure.files", "Exposed files",
              "A fixed list of at most 12 sensitive paths (.git, .env, backups), "
              "confirmed by content signature."),
    CheckSpec("exposure.dirlisting", "Directory listing",
              "Directory index pages such as \"Index of /\"."),
    CheckSpec("injection.reflection", "Reflected input",
              "An inert canary reflected unencoded in HTML (potential XSS)."),
    CheckSpec("injection.errors", "Error-based injection indicators",
              "A single quote that triggers SQL or stack-trace errors absent from the baseline."),
    CheckSpec("redirect.open", "Open redirect",
              "Redirect parameters that send users to an arbitrary .invalid host "
              "(never followed)."),
    CheckSpec("info.errors", "Debug and error pages",
              "Stack traces and framework debug pages seen while crawling."),
    CheckSpec("client.assets", "Client asset exposure",
              "Public source maps and browser runtime configuration containing non-public source or server credentials."),
    CheckSpec("artifact.inspect", "Artifact inspection",
              "Offline repository configuration and manifests containing concrete non-placeholder credentials."),
    CheckSpec("auth.default_creds", "Default credentials",
              "At most 5 well-known username/password pairs on a detected login form. "
              "Runs only when authentication testing is allowed in the scope.",
              requires_auth_testing=True),
    CheckSpec("authz.object", "Object-level access",
              "The same discovered object URL requested as every identity (anonymous "
              "and each logged-in account): readable by the wrong identity is a "
              "finding, with the full access matrix recorded. Requires a session "
              "(provided cookie or a login account).",
              requires_auth_testing=True),
    CheckSpec("authz.exposure", "Cross-interface exposure",
              "Information about a resource returned by a related interface (feed, "
              "export, history, list) to an identity that the resource's own "
              "interface refuses; every step re-requested and verified. Requires "
              "a session.",
              requires_auth_testing=True),
)

CHECK_AREAS: tuple[CheckArea, ...] = (
    CheckArea("Browser protections",
              "Response and cookie metadata from the affected page; hardening unless impact is shown.",
              frozenset({"headers.security", "cookies.flags"})),
    CheckArea("Disclosure",
              "Concrete content, source, configuration or credential exposure; not a path-shaped 404.",
              frozenset({"headers.disclosure", "exposure.files", "exposure.dirlisting",
                         "info.errors", "client.assets"})),
    CheckArea("Cross-origin behavior",
              "Credential support together with an arbitrary reflected origin on the affected interface.",
              frozenset({"cors.policy"})),
    CheckArea("Input handling",
              "A baseline/probe difference; impact must be verified before calling it a vulnerability.",
              frozenset({"injection.reflection", "injection.errors", "redirect.open"})),
    CheckArea("Authentication",
              "A confirmed login under the operator's authentication-testing permission.",
              frozenset({"auth.default_creds"})),
    CheckArea("Authorization",
              "Identity/interface comparison, expected access and an independently observed violation.",
              frozenset({"authz.object", "authz.exposure"})),
    CheckArea("Offline artifact",
              "A concrete, non-placeholder credential or configuration issue in the uploaded snapshot.",
              frozenset({"artifact.inspect"})),
)


def area(check_id: str) -> CheckArea:
    return next((candidate for candidate in CHECK_AREAS if check_id in candidate.checks),
                CheckArea("Other", "A reproducible observation from the affected interface.",
                          frozenset()))

CHECK_IDS = frozenset(c.id for c in CHECKS)
_BY_ID = {c.id: c for c in CHECKS}


def get(check_id: str) -> CheckSpec | None:
    return _BY_ID.get(check_id)


UNAVAILABLE_REASON = "Not implemented in this build"


def is_available(check_id: str) -> bool:
    """A check is available only when the tool registry has an implementation for it
    (derived, never a hard-coded list)."""
    from src.greybox_web import tools as gb_tools
    return gb_tools.get(check_id) is not None


def unavailable_reason(check_id: str) -> str | None:
    return None if is_available(check_id) else UNAVAILABLE_REASON


def default_selection(allow_auth_testing: bool = False) -> list[str]:
    """Checks selected by default: ``default_enabled`` ones, never an unavailable
    check, and never a check the scope does not allow (authentication-testing checks
    need ``allow_auth_testing``, which is the default since 2026-11-21)."""
    return [c.id for c in CHECKS
            if is_available(c.id)
            and (allow_auth_testing or not c.requires_auth_testing)
            and (c.default_enabled or (c.requires_auth_testing and allow_auth_testing))]


def skipped_checks(selected: list[str] | None) -> list[dict[str, str]]:
    """Requested checks that cannot run in this build, in catalogue order, as
    ``[{"id", "reason"}]``. ``None`` (defaults) never contains unavailable checks."""
    if not selected:
        return []
    wanted = set(selected)
    return [{"id": c.id, "reason": UNAVAILABLE_REASON}
            for c in CHECKS if c.id in wanted and not is_available(c.id)]


def resolve_checks(selected: list[str] | None, allow_auth_testing: bool) -> list[str]:
    """Effective check ids in catalogue order.

    ``None`` means the defaults: every ``default_enabled`` check, plus the
    auth-testing checks when the scope allows authentication testing. Checks that
    require auth testing are dropped when the scope does not allow it, and checks
    without a registered implementation are normalised away (see
    :func:`skipped_checks`; stored targets may still select them)."""
    if selected is None:
        wanted = set(default_selection(allow_auth_testing))
    else:
        wanted = set(selected)
    return [c.id for c in CHECKS
            if c.id in wanted and is_available(c.id)
            and (allow_auth_testing or not c.requires_auth_testing)]
