"""Default credentials probe.

Unlike the other managed scanners this one is not a thin wrapper around an
external CLI — there is no stable cross-platform binary that handles "POST
this list of credentials to a form and check whether each succeeded" without
brittle assumptions. So this scanner uses ``httpx`` directly and overrides
``run()`` to skip the subprocess path.

A login is considered successful when, after submitting the form, *any* of:

- The HTTP status is 2xx and the response body contains the configured
  ``success_indicator``, OR
- The response set a session-looking cookie that was not present before.

A working pair becomes a ``critical`` ``finding`` (default credentials are
exploitable on first contact). Suspicious-but-unconfirmed pairs (2xx without
the indicator, but a cookie was set) become ``leads`` for the auth
specialist to investigate.

When the login URL redirects to a third-party identity provider (Microsoft,
Google, Okta, Auth0, etc.), the scanner short-circuits — local credential
probing against an SSO endpoint produces only false positives because the
OAuth dance always renders 200s and sets state/nonce cookies regardless of
the credentials submitted.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

# Third-party identity provider hostnames. If the login URL resolves to one
# of these after following redirects, the target uses federated SSO and
# default-creds probing is meaningless.
SSO_PROVIDER_HOSTS: tuple[str, ...] = (
    "login.microsoftonline.com",
    "login.live.com",
    "accounts.google.com",
    "auth0.com",
    "okta.com",
    "onelogin.com",
    "pingidentity.com",
    "adfs",
)

# Common default credential pairs to test. Conservative list — short enough
# that we don't lock out accounts on real targets, and the auth specialist
# can extend it via a lead.
DEFAULT_CRED_PAIRS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", ""),
    ("administrator", "administrator"),
]


@dataclass
class _ProbeOutcome:
    username: str
    password: str
    status: int
    indicator_seen: bool
    cookie_set: bool
    body_len: int


class DefaultCredsScanner(BaseScanner):
    """Probe a login form with a small dictionary of default credentials."""

    def build_command(self) -> list[str]:
        # Required by ABC but unused — run() is overridden below.
        return ["true"]

    def parse_output(self, raw_output: str) -> ScanResult:
        # Required by ABC but unused — findings are produced inline in run().
        return ScanResult(scan_type="default_creds")

    async def run(self) -> ScanResult:
        """Probe each credential pair and return findings/leads."""
        login_url = str(self.options.get("login_url", self.target_url + "/login"))
        username_field = str(self.options.get("username_field", "username"))
        password_field = str(self.options.get("password_field", "password"))
        success_indicator = str(self.options.get("success_indicator", "")).lower()

        try:
            import httpx
        except ImportError:
            logger.warning("httpx not installed; default_creds scanner is a no-op.")
            return ScanResult(scan_type="default_creds")

        findings: list[dict] = []
        leads: list[dict] = []

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=bool(self.options.get("verify_tls", True)),
        ) as client:
            # Establish a baseline cookie set by GETting the login page first.
            try:
                response = await client.get(login_url)
            except httpx.HTTPError as exc:
                logger.warning(
                    "default_creds: cannot reach login URL %s: %s", login_url, exc,
                )
                return ScanResult(scan_type="default_creds")

            # Short-circuit on SSO: if the login URL ends up on a third-party
            # IdP, credential probing is meaningless (every OAuth dance returns
            # 200 with state cookies set, generating only false positives).
            final_host = (urlparse(str(response.url)).hostname or "").lower()
            if any(provider in final_host for provider in SSO_PROVIDER_HOSTS):
                logger.info(
                    "default_creds: login URL %s redirects to SSO provider %s; "
                    "skipping credential probe.",
                    login_url, final_host,
                )
                return ScanResult(
                    scan_type="default_creds",
                    leads=[{
                        "tool": "default_creds",
                        "signal_type": "sso_detected",
                        "url": login_url,
                        "signal_strength": "low",
                        "hypothesis": (
                            f"Login at {login_url} federates to SSO provider "
                            f"{final_host}. Default-creds probing is not "
                            f"applicable; auth specialist should consider IdP-side "
                            f"weaknesses (OAuth misconfig, open redirect on "
                            f"redirect_uri, etc.)."
                        ),
                    }],
                    items_found=1,
                )

            baseline_cookies = {c.name for c in client.cookies.jar}

            for username, password in DEFAULT_CRED_PAIRS:
                # Fresh client for each attempt so that a successful login
                # doesn't taint the baseline cookies for the next probe.
                async with httpx.AsyncClient(
                    timeout=10.0,
                    follow_redirects=True,
                    verify=bool(self.options.get("verify_tls", True)),
                ) as probe:
                    try:
                        await probe.get(login_url)
                        baseline = {c.name for c in probe.cookies.jar} or baseline_cookies
                        response = await probe.post(
                            login_url,
                            data={username_field: username, password_field: password},
                        )
                    except httpx.HTTPError as exc:
                        logger.debug(
                            "default_creds: probe %s:%s failed: %s",
                            username, password, exc,
                        )
                        continue

                    new_cookies = {c.name for c in probe.cookies.jar} - baseline
                    body = (response.text or "").lower()
                    indicator_seen = bool(success_indicator) and success_indicator in body
                    outcome = _ProbeOutcome(
                        username=username,
                        password=password,
                        status=response.status_code,
                        indicator_seen=indicator_seen,
                        cookie_set=bool(new_cookies),
                        body_len=len(body),
                    )

                # Confirmed default credential = critical finding.
                # Heuristic confirmation requires either the success indicator
                # or a freshly set cookie on a 2xx response.
                if outcome.status < 400 and (
                    outcome.indicator_seen or outcome.cookie_set
                ):
                    findings.append({
                        "tool": "default_creds",
                        "vuln_type": "auth",
                        "severity": "critical",
                        "cwe": "CWE-521",
                        "title": f"Default credentials accept {username}:{password}",
                        "description": (
                            f"Login at {login_url} accepted default credentials "
                            f"{username}:{password!r} (status={outcome.status}, "
                            f"indicator_seen={outcome.indicator_seen}, "
                            f"cookie_set={outcome.cookie_set})."
                        ),
                        "url": login_url,
                        "username": username,
                        "password": password,
                        "evidence": {
                            "status_code": outcome.status,
                            "indicator_seen": outcome.indicator_seen,
                            "new_cookies_set": outcome.cookie_set,
                        },
                    })
                elif outcome.status < 400 and outcome.body_len > 0 and not success_indicator:
                    # Without a success indicator we can't confirm, but a 2xx
                    # response is a candidate the auth specialist should look at.
                    leads.append({
                        "tool": "default_creds",
                        "signal_type": "default_credential_candidate",
                        "url": login_url,
                        "username": username,
                        "password": password,
                        "hypothesis": (
                            f"Login at {login_url} returned {outcome.status} for "
                            f"{username}:{password!r} — manual confirmation needed "
                            f"(no success_indicator configured)."
                        ),
                    })

        return ScanResult(
            scan_type="default_creds",
            findings=findings,
            leads=leads,
            items_found=len(findings) + len(leads),
        )
