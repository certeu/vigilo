"""Guarded freshness checks and supported re-authentication primitives."""
from __future__ import annotations

from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from src.greybox_web import authboundary
from src.greybox_web.tools import ToolContext


@dataclass(frozen=True)
class SessionFreshness:
    identity: str
    state: str
    reason: str
    exchange_ids: tuple[int, ...] = ()
    recovered: bool = False

    @property
    def usable(self) -> bool:
        return self.state == "fresh"


async def probe(ctx: ToolContext, identity: str, url: str) -> SessionFreshness:
    """Read one harmless protected URL through the guarded HTTP capability."""
    known = {str(s.get("label")) for s in ctx.http.sessions()}
    if identity not in known:
        return SessionFreshness(identity, "missing", "no reusable session is established")
    response = await ctx.http.get(url, session=identity, follow=True)
    auth = authboundary.detect(
        requested_url=url, final_url=response.url, chain=response.hops,
        body=response.text[:50_000], status=response.status,
        base_host=urlsplit(ctx.base_url).hostname)
    ids = tuple(response.exchange_ids)
    if auth.blocked:
        state = "expired" if auth.state == "expired" else "identity_boundary"
        return SessionFreshness(identity, state, auth.detail, ids)
    if response.status in (401, 407):
        return SessionFreshness(identity, "expired", f"probe returned {response.status}", ids)
    if response.status >= 500:
        return SessionFreshness(identity, "unknown",
                                f"probe returned transient status {response.status}", ids)
    return SessionFreshness(identity, "fresh", f"probe returned {response.status}", ids)


async def recover(ctx: ToolContext, identity: str, probe_url: str,
                  login_url: str | None = None) -> SessionFreshness:
    """Re-authenticate an expired/missing configured identity, then verify it."""
    initial = await probe(ctx, identity, probe_url)
    if initial.usable or initial.state == "unknown":
        return initial
    if ctx.account_credentials is None or ctx.account_credentials(identity) is None:
        return replace(initial, reason=initial.reason + "; no configured account recovery")
    from src.greybox_web.tools import auth
    params = {"url": login_url or ctx.base_url, "account": identity}
    result = await auth.login(replace(ctx, params=params))
    if result.counts.get("established") != 1:
        return replace(initial, reason=initial.reason + "; re-authentication failed")
    verified = await probe(ctx, identity, probe_url)
    return replace(verified, recovered=verified.usable)
