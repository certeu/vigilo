"""What kind of issue a finding is.

A missing ``Content-Security-Policy`` header and a cross-tenant object read are both
"findings", but presenting them side by side as vulnerabilities inflates the report
and buries what matters. Every finding therefore carries a **class**:

``vulnerability``     an exploitable weakness: the evidence shows a security
                      property being violated (unauthorised read, injection,
                      unauthenticated data store).
``misconfiguration``  an insecure setting that weakens a control without, on its
                      own, demonstrating exploitation (permissive CORS, cookie
                      without ``Secure``, cleartext admin protocol exposed).
``hardening``         a defence-in-depth improvement (CSP, HSTS, banner/version
                      disclosure): worth doing, not a breach.
``informational``     a fact the owner should know (technology inventory).

The report groups by class *and* by verification status, so "confirmed
vulnerability", "likely vulnerability requiring verification", "misconfiguration",
"hardening recommendation" and "informational" are distinct sections, and
inconclusive hypotheses are listed separately.

A tool may set the class explicitly; otherwise :func:`classify` derives it from
the check id. Pure module.
"""
from __future__ import annotations

from typing import Any

VULNERABILITY = "vulnerability"
MISCONFIGURATION = "misconfiguration"
HARDENING = "hardening"
INFORMATIONAL = "informational"
CLASSES = (VULNERABILITY, MISCONFIGURATION, HARDENING, INFORMATIONAL)

# check id (or prefix ending in ".") -> class
_DEFAULTS: tuple[tuple[str, str], ...] = (
    ("headers.security", HARDENING),
    ("headers.disclosure", HARDENING),
    ("info.leak", HARDENING),
    ("supply.no_sri", HARDENING),
    ("supply.mixed_content", MISCONFIGURATION),
    ("cookies.flags", MISCONFIGURATION),
    ("cors.policy", MISCONFIGURATION),
    ("exposure.dirlisting", MISCONFIGURATION),
    ("exposure.files", VULNERABILITY),
    ("info.errors", MISCONFIGURATION),
    ("injection.", VULNERABILITY),
    ("redirect.open", VULNERABILITY),
    ("auth.default_creds", VULNERABILITY),
    ("authz.", VULNERABILITY),
    ("net.cleartext", MISCONFIGURATION),
    ("net.exposed_store", MISCONFIGURATION),
    ("net.unauthenticated", VULNERABILITY),
    ("net.banner", HARDENING),
    ("net.tls", MISCONFIGURATION),
    ("net.", MISCONFIGURATION),
)

REMEDIATION_KEYS = ("summary", "steps", "validation", "reproduction",
                    "severity_rationale")


def classify(check_id: str, explicit: str | None = None) -> str:
    """The class of a finding: the tool's explicit choice when valid, else the
    default for its check, else ``vulnerability`` for agent-authored analyses that
    did not say (they are candidates until verified anyway)."""
    if explicit in CLASSES:
        return explicit
    cid = check_id or ""
    for key, cls in _DEFAULTS:
        if cid == key or (key.endswith(".") and cid.startswith(key)):
            return cls
    return VULNERABILITY


def clean_remediation(raw: Any) -> dict[str, Any] | None:
    """A remediation document with only the known keys, strings capped and lists
    of short strings. ``None`` when nothing usable was given."""
    if isinstance(raw, str):
        raw = {"summary": raw}
    if not isinstance(raw, dict):
        return None
    out: dict[str, Any] = {}
    for key in REMEDIATION_KEYS:
        v = raw.get(key)
        if isinstance(v, str) and v.strip():
            out[key] = v.strip()[:1500] if key in ("summary", "severity_rationale") \
                else [v.strip()[:500]]
        elif isinstance(v, list):
            items = [str(x).strip()[:500] for x in v if str(x).strip()][:10]
            if items:
                out[key] = items
    return out or None


# Report section titles, in order.
SECTIONS = (
    ("confirmed_vulnerability", "Confirmed vulnerabilities"),
    ("likely_vulnerability", "Likely vulnerabilities (require verification)"),
    ("misconfiguration", "Security misconfigurations"),
    ("hardening", "Hardening recommendations"),
    ("informational", "Informational observations"),
)


def section_of(finding_class: str, status: str) -> str | None:
    """Which report section a finding belongs to (``None``: rejected)."""
    if status == "rejected":
        return None
    if finding_class == VULNERABILITY:
        return "confirmed_vulnerability" if status == "verified" \
            else "likely_vulnerability"
    return finding_class if finding_class in CLASSES else "likely_vulnerability"


# Concrete default remediation for the built-in checks (used when a tool supplies
# none): what to change, where, and how the owner verifies the fix.
_HEADER_FIX = {
    "content-security-policy": ("Content-Security-Policy",
                                "default-src 'self'; object-src 'none'; "
                                "frame-ancestors 'none'; base-uri 'self'"),
    "x-content-type-options": ("X-Content-Type-Options", "nosniff"),
    "referrer-policy": ("Referrer-Policy", "strict-origin-when-cross-origin"),
    "strict-transport-security": ("Strict-Transport-Security",
                                  "max-age=31536000; includeSubDomains"),
    "x-frame-options": ("Content-Security-Policy",
                        "frame-ancestors 'none' (or X-Frame-Options: DENY)"),
    "permissions-policy": ("Permissions-Policy", "camera=(), microphone=(), "
                                                 "geolocation=()"),
}

_DEFAULTS_REM: dict[str, dict] = {
    "headers.disclosure": {
        "summary": "Stop disclosing server software and versions in responses.",
        "steps": ["Remove or genericise Server / X-Powered-By / version headers in the "
                  "web server or framework configuration (e.g. nginx "
                  "`server_tokens off;`, Express `app.disable('x-powered-by')`)."],
        "validation": ["Responses carry no product/version header."]},
    "cookies.flags": {
        "summary": "Set Secure, HttpOnly and SameSite on session cookies.",
        "steps": ["In the session middleware, issue the cookie with `Secure; "
                  "HttpOnly; SameSite=Lax` (or Strict) and a bounded lifetime."],
        "validation": ["The Set-Cookie header of the login response carries Secure, "
                       "HttpOnly and SameSite."]},
    "cors.policy": {
        "summary": "Restrict CORS to an explicit list of trusted origins.",
        "steps": ["Never reflect the request Origin; allow-list the application's own "
                  "origins, and only send Access-Control-Allow-Credentials for them."],
        "validation": ["A request with `Origin: https://evil.example` receives no "
                       "Access-Control-Allow-Origin for that origin."]},
    "exposure.files": {
        "summary": "Remove the exposed file from the web root and block the path.",
        "steps": ["Delete it from the deployed artefact; deny dot-files and backup "
                  "extensions in the web server; rotate any secret it contained."],
        "validation": ["The URL answers 404 and the content is no longer served."]},
    "exposure.dirlisting": {
        "summary": "Disable directory listing.",
        "steps": ["Turn autoindex/Indexes off for the location."],
        "validation": ["The directory URL answers 403/404 without an index."]},
    "injection.reflection": {
        "summary": "Encode output for its context and add a restrictive CSP.",
        "steps": ["HTML-encode the parameter where it is rendered (use the template "
                  "engine's auto-escaping); validate it against an allow-list."],
        "validation": ["Submitting `<x>` returns `&lt;x&gt;` in the page."]},
    "injection.errors": {
        "summary": "Use parameterised queries and stop returning raw errors.",
        "steps": ["Bind the parameter in the query; catch errors and return a "
                  "generic message; log details server-side."],
        "validation": ["A quote in the parameter no longer produces a database error "
                       "signature."]},
    "redirect.open": {
        "summary": "Only redirect to relative paths or allow-listed hosts.",
        "steps": ["Validate the redirect target server-side against an allow-list."],
        "validation": ["A redirect parameter pointing to an external host is "
                       "refused or replaced by a default page."]},
    "info.errors": {
        "summary": "Disable debug output and stack traces in production.",
        "steps": ["Turn off framework debug mode; return generic error pages."],
        "validation": ["The failing request returns a generic error without stack "
                       "traces or internal paths."]},
    "auth.default_creds": {
        "summary": "Change the default credentials and enforce a password policy.",
        "steps": ["Rotate the account's password; disable or remove default "
                  "accounts; add login throttling."],
        "validation": ["The default pair is rejected at login."]},
    "authz.object": {
        "summary": "Enforce object ownership server-side on every read.",
        "steps": ["Scope the lookup to the session user or check permission before "
                  "returning the object; answer 404 otherwise."],
        "validation": ["As a non-owner, requesting the object returns 404/403."]},
}


def default_remediation(check_id: str, title: str = "") -> dict | None:
    """Concrete remediation for a built-in check's finding (None if unknown)."""
    if check_id == "headers.security":
        low = title.lower()
        for key, (name, value) in _HEADER_FIX.items():
            if key in low or name.lower() in low:
                return {"summary": f"Send `{name}: {value}` on HTML responses.",
                        "steps": [f"Add the header in the reverse proxy or the "
                                  f"application's response middleware: `{name}: "
                                  f"{value}` (tune the value to the application)."],
                        "validation": [f"Every HTML response carries `{name}`; check "
                                       f"with `curl -sI <url> | grep -i {name}`."]}
        return {"summary": "Add the missing security header.",
                "validation": ["The header is present on every HTML response."]}
    return _DEFAULTS_REM.get(check_id)
