"""Authentication boundary: is the run actually talking to the application?
(defects F2/F7).

An assessment with a stale session, or one in front of a single-sign-on proxy, sees
a different system than the one it was asked to assess: every page is a redirect to
``login.microsoftonline.com`` or the application answers with an SSO interstitial.
A field assessment then analysed *the identity provider's* login page as if it belonged to the target
and reported security-header findings about it — and nothing in the run said the
session had expired.

This module is the single place that recognises those situations. It is pure (no
I/O): the tools feed it the redirect chain, the final URL and a little of the body,
and it says what the run is looking at.

* :func:`looks_like_identity_provider` — host/URL based: ``login.microsoftonline.com``,
  ``accounts.google.com``, ``*.auth0.com``, ``*.okta.com``, Keycloak realms, Azure
  B2C, ADFS, Siteminder, CAS, ``/oauth2/authorize``, ``/saml2/`` …
* :func:`detect` — the full verdict for one response, from the chain, the final URL
  and a body excerpt (an SSO interstitial served with 200 is caught by its markers).
* :func:`summarise` — folds many verdicts into the run's :class:`AuthState`.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from src.greybox_web import coverage

# Host suffixes that are identity providers (suffix match on the host name).
IDP_HOSTS: tuple[str, ...] = (
    "login.microsoftonline.com", "login.microsoft.com", "login.live.com",
    "login.windows.net", "sts.windows.net", "adfs.", "accounts.google.com",
    "auth0.com", "okta.com", "oktapreview.com", "onelogin.com", "pingidentity.com",
    "pingone.com", "auth0.openai.com", "keycloak.", "shibboleth.", "criipto.com",
    "authing.com", "clerk.accounts.dev", "supabase.co", "firebaseapp.com",
    "cognito-idp.",
)
# Path fragments that only an identity provider (or an SSO callback) serves.
IDP_PATHS: tuple[str, ...] = (
    "/oauth2/authorize", "/oauth2/auth", "/oauth2/callback", "/oauth2/token",
    "/oauth2/start", "/.well-known/openid-configuration", "/saml2/",
    "/saml/", "/adfs/ls", "/realms/", "/protocol/openid-connect/",
    "/login.microsoftonline.com", "/signin-oidc", "/cas/login",
)
# Body markers of the big SSO interstitials / login screens.
IDP_MARKERS: tuple[re.Pattern, ...] = (
    re.compile(r"(?i)login\.microsoftonline\.com"),
    re.compile(r"(?i)aadcdn\.msftauth\.net"),
    re.compile(r"(?i)\$Config\s*=\s*\{"),
    re.compile(r"(?i)sErrorCode|arrValErrs"),
    re.compile(r"(?i)<title>\s*Sign in to your account"),
    re.compile(r"(?i)accounts\.google\.com"),
    re.compile(r"(?i)okta-sign-in|okta-signin-container"),
    re.compile(r"(?i)auth0-lock"),
    re.compile(r"(?i)/realms/[a-z0-9-]+/protocol/openid-connect"),
)
# The application redirecting to *its own* login page (not an SSO provider).
LOGIN_PATH = re.compile(r"(?i)^/(?:login|signin|sign-in|auth|sso|session/new"
                        r"|account/login|users/sign_in)(?:/|$|\?)")


def host_is_idp(host: str) -> bool:
    h = (host or "").lower().strip(".")
    if not h:
        return False
    return any(h == s or h.endswith("." + s) or (s.endswith(".") and s in h)
               or h.startswith(s) for s in IDP_HOSTS)


def looks_like_identity_provider(url: str) -> bool:
    """Is this URL an identity provider (or its SSO endpoint)?"""
    try:
        parts = urlsplit(str(url) if url is not None else "")
    except ValueError:
        return False
    if host_is_idp(parts.hostname or ""):
        return True
    path = (parts.path or "").lower()
    return any(frag in path for frag in IDP_PATHS)


def body_is_idp_page(body: str | None) -> str | None:
    """Which marker says this body is an identity-provider page (None if none)."""
    for rx in IDP_MARKERS:
        m = rx.search(body or "")
        if m:
            return m.group(0)[:60]
    return None


def detect(*, requested_url: str, final_url: str | None,
           chain: list[str] | tuple[str, ...] = (), body: str | None = None,
           status: int | None = None,
           base_host: str | None = None) -> coverage.AuthState:
    """What the run is looking at for this response.

    ``chain`` is the redirect chain (``HttpResponse.hops`` / page navigations), which
    is the strongest signal: a chain that leaves the target's host for an identity
    provider means the session was not accepted.
    """
    final = str(final_url or requested_url or "")
    for hop in (*chain, final):
        if looks_like_identity_provider(hop):
            return coverage.AuthState(coverage.AUTH_IDP, _host(hop),
                                      "the target redirects to an identity provider")
    if body:
        marker = body_is_idp_page(body)
        if marker:
            return coverage.AuthState(coverage.AUTH_IDP, _host(final) or None,
                                      f"the page is an identity-provider screen "
                                      f"({marker})")
    try:
        p = urlsplit(final)
    except ValueError:
        return coverage.AuthState()
    host = (p.hostname or "").lower()
    if base_host and host and host != base_host.lower():
        return coverage.AuthState(
            coverage.AUTH_IDP, host,
            "the target redirects to another host before answering")
    if status in (401, 407) or (status == 403 and LOGIN_PATH.search(p.path or "")):
        return coverage.AuthState(coverage.AUTH_EXPIRED, None,
                                  f"the target answered {status}: the session is "
                                  "not accepted")
    if LOGIN_PATH.search(p.path or "") and status in (200, None):
        return coverage.AuthState(coverage.AUTH_MISSING, None,
                                  "the target answers with a login page")
    return coverage.AuthState()


def summarise(states: list[coverage.AuthState]) -> coverage.AuthState:
    """The run's auth verdict from every response it saw.

    An identity provider seen anywhere wins (it is the strongest statement that the
    run was not looking at the application); otherwise the most common non-ok state.
    """
    blocked = [s for s in states if s.blocked]
    if not blocked:
        return coverage.AuthState()
    for rank in (coverage.AUTH_IDP, coverage.AUTH_EXPIRED, coverage.AUTH_MISSING):
        for s in blocked:
            if s.state == rank:
                return s
    return blocked[0]


def _host(url: str) -> str | None:
    try:
        return (urlsplit(url).hostname or None)
    except ValueError:
        return None
