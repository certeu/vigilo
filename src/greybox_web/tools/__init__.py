"""Built-in grey-box tools: registry and the data they return.

Tools are pure async functions ``run(ctx) -> ToolResult``. Their only I/O is
``ctx.http`` (a :class:`~src.greybox_web.netguard.ToolHttp`, i.e. the guarded client
bound to the tool's provenance). They never import httpx, socket, subprocess or the
database (enforced by ``tests/greybox_web/test_tools_imports.py``); the supervisor
projects their results into assets, graph nodes, findings and events.

Payloads are inert: random canaries, a single quote, ``.invalid`` hostnames.
POST is used only by ``auth.default_creds`` and form-parameter injection probes;
every other tool is GET, and POST never goes to an excluded path (the guarded
client re-checks every request against the scope).
"""
from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from src.greybox_web import modes
from src.greybox_web.netguard import ToolHttp
from src.greybox_web.scope import ScopePolicy


@dataclass
class ParamInfo:
    location: str                 # query | form
    name: str
    data: dict[str, Any] = field(default_factory=dict)   # sample, method, action, fields


@dataclass
class PageInfo:
    """An endpoint seen by discovery (fetched, linked or a form action)."""

    url: str
    status: int | None = None
    content_type: str | None = None
    fetched: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    params: list[ParamInfo] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    redirect_to: str | None = None
    exchange_ids: list[int] = field(default_factory=list)
    # Passive network signals of the response (netview.PageSignals), not persisted.
    signals: Any = None
    # URLs this page declares as sub-resources (scripts, stylesheets, frames): the
    # JS/JSON extractor's input and the supply-chain view's evidence (never noise).
    resources: list[str] = field(default_factory=list)
    # Set when the body came from a redirect: the URL the body actually belongs to.
    # Discovery attributes content to ``redirected_from``, never to the request URL
    # (defect F2: the identity provider's SSO page was analysed as if it were the
    # protected page the request asked for).
    redirected_from: str | None = None


@dataclass
class Observation:
    key: str                      # unique per run (exploration node key)
    label: str
    facts: dict[str, Any] = field(default_factory=dict)
    url: str | None = None
    exchange_ids: list[int] = field(default_factory=list)


@dataclass
class Evidence:
    role: str                     # baseline | proof | verification
    exchange_id: int | None
    excerpt: str
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"role": self.role, "exchange_id": self.exchange_id,
                "excerpt": self.excerpt[:1000], "note": self.note}


@dataclass
class FindingSpec:
    check_id: str
    detail: str                   # dedup detail (<check>|<asset key>|<detail>)
    title: str
    severity: str
    confidence: str
    description: str
    url: str
    method: str = "GET"
    parameter: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    verify: dict[str, Any] = field(default_factory=dict)   # params for verify.<check>
    cwe: str | None = None
    references: list[dict[str, str]] = field(default_factory=list)
    detection_hints: list[dict[str, str]] = field(default_factory=list)
    observation_key: str | None = None
    asset_url: str | None = None  # endpoint the finding is attached to (default: url)
    param_location: str | None = None
    # Attach to a non-endpoint asset, (kind, key), instead of ``asset_url``.
    asset_ref: tuple[str, str] | None = None
    # Findings that describe a *service-wide* fact ("this header is not sent") are one
    # issue, not one per URL. ``identity`` names that fact; the dedup key then uses it
    # instead of the asset key, and repeated reports are folded into the first, which
    # lists every location. ``None`` = per-URL identity (the default).
    identity: str | None = None
    # Locations already folded into this finding (identity-scoped findings only).
    occurrence: str | None = None
    # Passive findings are verified WITHOUT a new request: the projection
    # re-checks the recorded exchange (``recheck`` = {"check", "exchange_id", ...}).
    passive: dict[str, Any] | None = None
    # vulnerability | misconfiguration | hardening | informational (findclass.py);
    # None = derived from the check id.
    finding_class: str | None = None
    # {"summary", "steps", "validation", "reproduction", "severity_rationale"}
    remediation: dict[str, Any] | None = None
    exploitability_outcome: str | None = None


@dataclass
class AssetSpec:
    """A non-endpoint asset a tool wants in the asset graph (third-party origin, edge
    provider, leaked host or address). Written through ``GraphTx.asset`` and validated
    against ``graph.ASSET_KINDS``; an out-of-scope asset is only ever *recorded*."""

    kind: str
    key: str
    in_scope: bool
    label: str
    data: dict[str, Any] = field(default_factory=dict)
    # (kind, key) of the containing asset (a service's host), validated against
    # graph.ASSET_PARENT; None = no parent.
    parent: tuple[str, str] | None = None
    # The tool examined this asset (coverage: discovered vs. examined).
    tested: bool = False


@dataclass
class EdgeSpec:
    """An asset-graph edge between two assets named by ``(kind, key)``; validated
    against ``graph.ASSET_RULES``. An edge whose end is missing is skipped."""

    rel: str
    src: tuple[str, str]
    dst: tuple[str, str]


@dataclass
class ToolResult:
    summary: str
    counts: dict[str, Any] = field(default_factory=dict)
    pages: list[PageInfo] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    findings: list[FindingSpec] = field(default_factory=list)
    # In-scope links discovery found but did not fetch. The planner decides what
    # to crawl next (frontier-driven crawl).
    frontier: list[str] = field(default_factory=list)
    assets: list[AssetSpec] = field(default_factory=list)
    # In-scope URLs this execution actually EXAMINED (requested and answered), for
    # tools that are not bound to one endpoint (agent-written analysers): their
    # endpoint assets count as tested, so coverage reflects real work.
    examined: list[str] = field(default_factory=list)
    edges: list[EdgeSpec] = field(default_factory=list)


@dataclass(frozen=True)
class RecordedResponse:
    """One response the run already recorded (stored, redacted, capped); what a passive
    analysis tool may read through ``ctx.recorded``."""

    id: int
    url: str
    scheme: str | None
    status: int | None
    headers: list
    body: str | None
    content_type: str | None


@dataclass
class VerifyResult:
    confirmed: bool
    method: str
    note: str
    exchange_ids: list[int] = field(default_factory=list)
    excerpt: str = ""
    outcome: str | None = None


@dataclass
class ToolContext:
    http: ToolHttp
    base_url: str
    scope: ScopePolicy
    limits: dict[str, Any]
    params: dict[str, Any]
    # Read-only view of what the run already recorded (passive analysis tools only;
    # None elsewhere). It performs no network I/O.
    recorded: Any = None
    # The run's login accounts, secret-free: (label, user, login hints) tuples the
    # knowledge and the admission layer may read. The passwords stay with the
    # supervisor (``account_credentials``) and reach only the auth.login tool.
    accounts: tuple = ()
    # label -> {user, password, login hints} for the login tool, or None. The
    # returned dicts never enter work orders, events or the knowledge.
    account_credentials: Any = None
    # Raw-protocol capabilities (``netcap.ToolNet``): TCP connect/banner and DNS,
    # scope-checked against ``scope.network``. None when the run has no network
    # scope -- a tool must then not pretend it probed anything.
    net: Any = None
    # The run's sandbox broker factory (generated tools; ``broker.py``).
    broker: Any = None
    # The run this call belongs to (per-run state such as the browser session).
    run_id: Any = None
    # Operator-supplied inventory reader (artifact capability), or None.
    inventory: Any = None

    @staticmethod
    def token() -> str:
        return secrets.token_hex(4)


ToolFn = Callable[[ToolContext], Awaitable[ToolResult]]
VerifyFn = Callable[[ToolContext], Awaitable[VerifyResult]]


@dataclass(frozen=True)
class ToolSpec:
    id: str
    kind: str                     # discovery | check | verify
    run: Callable[[ToolContext], Awaitable[Any]]
    # Parameter allow-list (admission): a work order — rules,
    # hints or LLM proposals alike — may only carry these keys. Verified with
    # every admission, so an LLM cannot smuggle extra instructions into params.
    param_keys: tuple[str, ...] = ()
    # Human title (dynamic tool specs, batch E: what the instrument tests). Static
    # registry entries have none — their titles live in the checks catalogue.
    title: str = ""
    # The protocol(s) this tool needs (``modes.py``). Admission refuses a tool
    # whose capability the run does not have, so a network-only or artifact-only
    # target can never reach the browser, and a new capability is never implicit.
    # ``None`` = the run's default (HTTP tools through the guarded client).
    capability: str | None = None
    # Values an enumerated parameter may take (admission rejects anything else:
    # an unsupported option must fail loudly, never be answered as "nothing found").
    options: Mapping[str, tuple[str, ...]] | None = None


# Parameter allow-list for every ``verify.*`` tool: the ``verify`` dict a check
# stores on its finding (plus ``finding_id``) is the whole parameter space a
# verifier may receive.
VERIFY_PARAM_KEYS = ("finding_id", "url", "path", "header", "expect", "value",
                     "cookie", "flag", "mode", "needle", "param", "location",
                     "login", "method", "status", "user", "password",
                     "user_field", "password_field", "viewer", "marker",
                     "control_url", "owner")


def _registry() -> dict[str, ToolSpec]:
    """Registered tools: the single source of truth for check availability
    (``checks.is_available`` derives from it). A catalogue check without an entry
    here is honestly reported unavailable, normalised out of a run's checks, and
    any work order that still names it is skipped with reason ``disabled``."""
    from src.greybox_web import verify
    from src.greybox_web.tools import (
        apiops,
        auth,
        authz,
        cookies,
        cors,
        discovery,
        dynspec,
        exposure,
        headers,
        info,
        injection,
        netpassive,
        scripts,
        toolsmith,
        xref,
    )
    specs = [
        ToolSpec("discovery.fetch_root", "discovery", discovery.fetch_root,
                 param_keys=("url",)),
        ToolSpec("discovery.robots", "discovery", discovery.robots,
                 param_keys=("url",)),
        ToolSpec("discovery.sitemap", "discovery", discovery.sitemap,
                 param_keys=("url",)),
        ToolSpec("discovery.crawl", "discovery", discovery.crawl,
                 param_keys=("url", "seeds", "max_pages")),
        # Read the application's own JavaScript/JSON and turn the routes and API
        # calls it names into surface (field-assessment defect F1: a bundle
        # was never read, so a one-page shell hid the whole API).
        ToolSpec("discovery.scripts", "discovery", scripts.scripts,
                 param_keys=("url", "scripts", "max_scripts")),
        ToolSpec("api.operations", "discovery", apiops.inventory,
                 param_keys=("url", "identity")),
        ToolSpec("api.paginate", "discovery", apiops.paginate,
                 param_keys=("url", "identity", "cursor_param", "max_pages")),
        ToolSpec("api.compare_access", "discovery", apiops.compare_access,
                 param_keys=("url", "identities", "operation_id", "expected_role", "resource_scope")),
        ToolSpec("api.operation.invoke", "discovery", apiops.invoke,
                 param_keys=("operation_ref", "operation", "identity", "arguments",
                             "resource_ref", "expected_effect", "investigation_ref")),
        ToolSpec("headers.security", "check", headers.security,
                 param_keys=("url", "endpoint", "service", "login")),
        ToolSpec("headers.disclosure", "check", headers.disclosure,
                 param_keys=("url", "endpoint", "service", "login")),
        ToolSpec("cors.policy", "check", cors.policy,
                 param_keys=("url", "endpoint", "service", "login")),
        ToolSpec("cookies.flags", "check", cookies.flags,
                 param_keys=("url", "endpoint", "service", "login")),
        ToolSpec("exposure.files", "check", exposure.files,
                 param_keys=("url", "endpoint", "service", "login")),
        ToolSpec("exposure.dirlisting", "check", exposure.dirlisting,
                 param_keys=("url", "endpoint", "service", "login")),
        ToolSpec("injection.reflection", "check", injection.reflection,
                 param_keys=("url", "param", "location")),
        ToolSpec("injection.errors", "check", injection.errors,
                 param_keys=("url", "param", "location")),
        ToolSpec("redirect.open", "check", injection.open_redirect,
                 param_keys=("url", "param", "location")),
        ToolSpec("info.errors", "check", info.errors, param_keys=("url",)),
        ToolSpec("auth.default_creds", "check", auth.default_creds,
                 param_keys=("url", "user_field", "password_field", "method")),
        # Sessions and object-level access ("hardcore by default", 2026-11-21):
        # login is an instrument (discovery kind: always available, no finding);
        # authz.object is a check, selected by default when the scope allows auth.
        ToolSpec("auth.login", "discovery", auth.login,
                 param_keys=("url", "account", "user_field", "password_field",
                             "method", "body")),
        ToolSpec("auth.session_recover", "discovery", auth.session_recover,
                 param_keys=("account", "url", "probe_url", "login_url")),
        ToolSpec("authz.object", "check", authz.object_access,
                 param_keys=("url",)),
        # Cross-interface exposure: the same resource refused by its own interface
        # and described by a related one (tools/xref.py), verified step by step.
        ToolSpec("authz.exposure", "check", xref.exposure,
                 param_keys=("url", "viewer", "marker", "control_url", "owner")),
        # Passive follow-up: re-examines recorded exchanges, no request.
        ToolSpec("netview.reexamine", "discovery", netpassive.reexamine,
                 param_keys=("kind", "needle"),
                 options={"kind": netpassive.REEXAMINE_KINDS},
                 capability=modes.RECORDED),
        # Dynamic tools (batch E, "tools on demand"): the agent composes a
        # DECLARATIVE instrument when no fixed tool can express a check. The spec
        # is validated against a fixed vocabulary before anything is registered;
        # the definition itself makes NO requests; execution is the generic
        # executor through this same guarded pipeline. No count cap — dedup and
        # vocabulary are the gates.
        ToolSpec("tool.define", "discovery", dynspec.define,
                 param_keys=("spec",)),
        # Sandboxed authoring: when the need is an ANALYSIS rather
        # than a single-request verdict, the agent writes a small Python function
        # that runs with no network, no filesystem and no processes over inputs the
        # engine fetched in scope (sandbox.py). Same lifecycle: validated before
        # registration, reusable for the rest of the run, fully audited.
        ToolSpec("tool.compose", "discovery", toolsmith.define,
                 param_keys=("spec",), capability=modes.SANDBOX),
    ]
    # Browser capability: the agent drives a real browser as a
    # tool. Admission refuses these unless the run has the ``browser`` capability.
    from src.greybox_web.tools import browser
    specs += [
        ToolSpec("browser.visit", "discovery", browser.visit,
                 param_keys=("url", "wait_ms", "timeout_s", "session"),
                 capability=modes.BROWSER),
        ToolSpec("browser.act", "discovery", browser.act,
                 param_keys=("url", "actions", "selector", "value", "timeout_s",
                             "session"),
                 capability=modes.BROWSER),
        ToolSpec("browser.cookies", "discovery", browser.cookies,
                 param_keys=("session",), capability=modes.BROWSER),
        ToolSpec("browser.screenshot", "discovery", browser.screenshot,
                 param_keys=("url", "session"), capability=modes.BROWSER),
    ]
    # Investigation skills (progressive disclosure, layer 2): load a methodology
    # playbook. No target I/O; recorded like any action so the run's history shows
    # which methodology the agent used and why.
    from src.greybox_web.tools import routes as route_tools
    specs += [ToolSpec("discovery.routes", "discovery", route_tools.routes,
                       param_keys=(), capability=modes.RECORDED)]
    from src.greybox_web.tools import skills as skill_tools
    specs += [ToolSpec("skill.read", "discovery", skill_tools.read,
                       param_keys=("name", "part"), capability=modes.SKILLS)]
    # Network capability: service inventory over the authorised
    # address set. Admission refuses these unless the run has ``tcp_connect``/``dns``
    # (network mode); the guard (netcap.GuardedNet) re-checks every socket.
    from src.greybox_web.tools import netinv
    from src.greybox_web import netcap
    specs += [
        ToolSpec("net.sweep", "discovery", netinv.sweep,
                 param_keys=("targets", "ports", "max_attempts"),
                 capability=modes.TCP_CONNECT),
        ToolSpec("net.probe", "discovery", netinv.probe,
                 param_keys=("host", "port", "probe"),
                 options={"probe": tuple(netcap.SAFE_PROBES)},
                 capability=modes.TCP_CONNECT),
        ToolSpec("net.resolve", "discovery", netinv.resolve,
                 param_keys=("name",), capability=modes.DNS),
        ToolSpec("net.tls", "discovery", netinv.tls,
                 param_keys=("host", "port", "server_name"),
                 capability=modes.TCP_CONNECT),
    ]
    specs += [ToolSpec(f"verify.{cid}", "verify", netinv.verify,
                       param_keys=("finding_id", "url", "host", "port", "expect"),
                       capability=modes.TCP_CONNECT)
              for cid in ("net.cleartext", "net.exposed_store", "net.unauthenticated",
                          "net.banner", "net.tls")]
    from src.greybox_web.tools import artifacts, clientassets
    specs += [
        ToolSpec("artifact.inventory", "discovery", artifacts.inventory,
                 param_keys=(), capability=modes.INVENTORY),
        ToolSpec("artifact.inspect", "check", artifacts.inspect,
                 param_keys=("path", "paths"), capability=modes.INVENTORY),
        ToolSpec("verify.artifact.inspect", "verify", artifacts.verify,
                 param_keys=("finding_id", "path", "key"), capability=modes.INVENTORY),
        ToolSpec("client.assets", "check", clientassets.analyse,
                 param_keys=("url", "urls"), capability=modes.HTTP),
        ToolSpec("verify.client.assets", "verify", clientassets.verify,
                 param_keys=("finding_id", "url", "kind", "marker"),
                 capability=modes.HTTP),
    ]
    specs += [ToolSpec(f"verify.{cid}", "verify", fn,
                       param_keys=VERIFY_PARAM_KEYS)
              for cid, fn in verify.VERIFIERS.items()]
    from src.greybox_web.tools import fileops
    specs += [
        ToolSpec("file.download", "discovery", fileops.download,
                 param_keys=("url", "identity", "identities", "marker", "resource_ref",
                             "expected_owner", "investigation_ref"), capability=modes.HTTP),
        ToolSpec("file.upload", "discovery", fileops.upload,
                 param_keys=("url", "identity", "filename", "field", "content", "content_b64",
                             "content_type", "resource_ref", "expected_owner",
                             "investigation_ref"), capability=modes.HTTP),
        ToolSpec("file.path_compare", "discovery", fileops.path_compare,
                 param_keys=("url_template", "control_path", "candidate_path", "identity",
                             "marker", "resource_ref", "expected_owner",
                             "investigation_ref"), capability=modes.HTTP),
    ]
    from src.greybox_web.tools import callback
    callback_keys = ("trigger_url", "callback_url", "observation_url", "param",
                     "identity", "success_marker", "poll_attempts")
    specs += [
        ToolSpec("callback.observe", "discovery", callback.observe, param_keys=callback_keys),
        ToolSpec("verify.callback.observe", "verify", callback.verify,
                 param_keys=("finding_id",) + callback_keys),
    ]
    return {s.id: s for s in specs}


_TOOLS: dict[str, ToolSpec] | None = None


def get(tool_id: str) -> ToolSpec | None:
    global _TOOLS
    if _TOOLS is None:
        _TOOLS = _registry()
    return _TOOLS.get(tool_id)


def excerpt(text: str, needle: str | None = None, width: int = 160) -> str:
    """A short window of ``text`` around ``needle`` (or its start)."""
    if not text:
        return ""
    if needle and needle in text:
        i = text.index(needle)
        start = max(0, i - width // 2)
        return text[start:start + width + len(needle)]
    return text[:width]


def header_excerpt(headers: list[tuple[str, str]], names: tuple[str, ...] = ()) -> str:
    wanted = {n.lower() for n in names}
    lines = [f"{k}: {v}" for k, v in headers if not wanted or k.lower() in wanted]
    return "\n".join(lines)[:1000]
