"""Assessment modes and capability gating (the target-agnostic core).

One engine assesses different kinds of target. What differs between them is *which
capability* may be used, and that is decided here — outside the model — from the
run's mode and its scope:

``web``       an http(s) application: HTTP tools and the browser.
``network``   an authorised address set (hosts / CIDR + ports): inventory over
              raw TCP connect only; no browser, no URL-shaped discovery.
``artifact``  an offline inventory supplied by the operator: no network at all.

A tool declares the capabilities it needs (:attr:`ToolSpec.capabilities`); admission
refuses a proposal whose capability the run does not have, so "no browser for a
network-only target" is a policy fact rather than a convention, and a new capability
can never be reached by accident.

Pure module: no I/O, no settings access, importable from anywhere.
"""
from __future__ import annotations

from dataclasses import dataclass

WEB = "web"
NETWORK = "network"
ARTIFACT = "artifact"
MODES: tuple[str, ...] = (WEB, NETWORK, ARTIFACT)
DEFAULT_MODE = WEB

# Capabilities a tool may declare. "http" is the default for legacy tools (every
# pre-existing tool speaks HTTP through the guarded client).
HTTP = "http"
BROWSER = "browser"
DNS = "dns"
TCP_CONNECT = "tcp_connect"
INVENTORY = "inventory"       # operator-supplied evidence (artifact mode)
SANDBOX = "sandbox"           # executes the agent's own analyser code
RECORDED = "recorded"         # re-reads what the run already recorded (no I/O)
SKILLS = "skills"             # reads the platform's methodology playbooks (no I/O)
CAPABILITIES: tuple[str, ...] = (HTTP, BROWSER, DNS, TCP_CONNECT, INVENTORY,
                                 SANDBOX, RECORDED, SKILLS)

# What each mode authorises. The network mode deliberately *includes* http: target
# services are routinely http, and a network assessment may still read a banner.
MODE_CAPABILITIES: dict[str, frozenset[str]] = {
    WEB: frozenset({HTTP, BROWSER, DNS, INVENTORY, SANDBOX, RECORDED, SKILLS}),
    NETWORK: frozenset({HTTP, DNS, TCP_CONNECT, INVENTORY, SANDBOX, RECORDED,
                        SKILLS}),
    ARTIFACT: frozenset({INVENTORY, SANDBOX, RECORDED, SKILLS}),
}


def effective(capability: str | None) -> str:
    """A tool's capability for admission: undeclared means HTTP (every legacy tool
    speaks HTTP through the guarded client). Never "no capability"."""
    return capability or HTTP


def normalise_mode(value: object) -> str:
    """A stored/requested mode as one of :data:`MODES` (unknown → the default)."""
    m = str(value or "").strip().lower()
    return m if m in MODES else DEFAULT_MODE


@dataclass(frozen=True)
class CapabilityPolicy:
    """The capabilities one run may use."""

    mode: str = DEFAULT_MODE
    # Capabilities the operator disabled for this target (target.capabilities
    # minus). Never widens: an unknown mode narrows to the default mode's set.
    disabled: frozenset[str] = frozenset()

    @classmethod
    def for_run(cls, mode: object, disabled: object = ()) -> "CapabilityPolicy":
        return cls(mode=normalise_mode(mode),
                   disabled=frozenset(str(d) for d in (disabled or ())))

    @property
    def allowed(self) -> frozenset[str]:
        return MODE_CAPABILITIES[self.mode] - self.disabled

    def allows(self, capability: str | None) -> bool:
        return capability is None or capability in self.allowed

    def as_list(self) -> list[str]:
        return sorted(self.allowed)


def describe(mode: str) -> str:
    """One human line for the UI, the knowledge and the report."""
    return {
        WEB: "web application (HTTP + browser)",
        NETWORK: "network segment (address inventory over TCP)",
        ARTIFACT: "supplied inventory (offline analysis, no network)",
    }.get(normalise_mode(mode), "web application (HTTP + browser)")


def for_scope(scope) -> CapabilityPolicy:
    """The capabilities of a run, from its (snapshotted) scope: the mode, the
    operator's disabled list, and — for a network assessment — the protocols the
    network scope lists. A network target authorises HTTP or DNS only when the
    operator listed ``http``/``dns``: the anchor URL of a network target is not an
    authorisation to run web checks against it."""
    mode = normalise_mode(getattr(scope, "mode", DEFAULT_MODE))
    disabled = set(getattr(scope, "disabled_capabilities", ()) or ())
    net = getattr(scope, "network", None)
    if mode == NETWORK:
        protos = set(net.protocols) if net is not None else set()
        if "http" not in protos:
            disabled.add(HTTP)
        if "dns" not in protos:
            disabled.add(DNS)
    return CapabilityPolicy.for_run(mode, disabled)
