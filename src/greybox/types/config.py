"""Grey-box pipeline configuration types."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator


class IdentityConfig(BaseModel):
    """A single authenticated identity for grey-box testing."""
    name: str
    role: str
    privilege_level: int = 0
    login: dict[str, Any] | None = None
    totp_secret: str | None = None
    cookie_header: str | None = None

    @model_validator(mode="after")
    def _cookie_login_exclusive(self) -> IdentityConfig:
        if self.cookie_header and self.login is not None:
            raise ValueError(
                f"Identity '{self.name}': cookie_header and login are mutually "
                f"exclusive — use one or the other"
            )
        return self


class GreyBoxConfig(BaseModel):
    """Runtime configuration for the grey-box pipeline."""
    max_concurrent_agents: int = 12
    max_per_vuln_type: int = 3
    per_scan_cost_ceiling: float = 50.0
    per_agent_cost_ceiling: float = 5.0
    max_duration_hours: float = 4.0
    lead_max_attempts: int = 3
    claim_ttl_seconds: int = 300
    max_spawn_depth: int = 3  # E8: guardrail
    specialist_model: str = "medium"
    model: str | None = None
    default_identity: str = "admin"
    max_scheduler_ticks: int = 100
    idle_ticks_before_done: int = 20
    per_type_cap: int = 3
    authz_per_tick_cap: int = 2
    chain_per_tick_cap: int = 1
    max_specialists_per_endpoint: int = 2
    max_consecutive_waiting_ticks: int = 10
    # C1: three-tier budget mode thresholds. Fractions of remaining budget
    # (0.0–1.0), not percentages. `cheap-only` kicks in below the ceiling;
    # `exhausted` kicks in below the floor.
    budget_cheap_ceiling_pct: float = Field(default=0.10, ge=0.0, le=1.0)
    budget_cheap_floor_pct: float = Field(default=0.03, ge=0.0, le=1.0)
    # D4: per-parameter retry caps by verdict. Conclusive attempts always
    # foreclose retries; inconclusive and failed attempts retry up to these
    # caps before the parameter is considered done for the vuln_type.
    max_inconclusive_retries: int = Field(default=2, ge=0)
    max_failed_retries: int = Field(default=3, ge=0)
    managed_scans: dict[str, bool] = Field(default_factory=lambda: {
        "feroxbuster": True, "nuclei": True, "ssl_analysis": True,
        "header_analysis": True, "cors_check": True, "default_creds": True,
        "tech_fingerprint": True, "robots_sitemap": True,
        # Active recon scanners — opt-in via active_recon_enabled below.
        "nmap": False, "httpx_probe": False,
    })
    # Slice 13 B: concurrency bound + wall-clock deadline for managed scans
    # running inside Phase 1.
    managed_scan_concurrency: int = Field(default=4, ge=1)
    preflight_scan_deadline_s: int = Field(default=600, ge=1)
    # Active recon master switch. When False, nmap and httpx_probe are skipped
    # even if their managed_scans entries are True. Network-touchy probes
    # (port scans, ALPN/H2/H3 fingerprinting) require explicit operator opt-in.
    active_recon_enabled: bool = False

    @model_validator(mode="after")
    def _floor_below_ceiling(self) -> GreyBoxConfig:
        if self.budget_cheap_floor_pct >= self.budget_cheap_ceiling_pct:
            raise ValueError(
                "budget_cheap_floor_pct must be strictly less than "
                "budget_cheap_ceiling_pct"
            )
        return self

    @classmethod
    def from_yaml(cls, path: Path) -> GreyBoxConfig:
        """Load config from a YAML file, mapping nested keys to flat fields."""
        raw = yaml.safe_load(path.read_text()) or {}
        budget = raw.get("budget", {})
        guardrails = raw.get("guardrails", {})
        flat: dict[str, Any] = {}
        if "max_cost_usd" in budget:
            flat["per_scan_cost_ceiling"] = budget["max_cost_usd"]
        if "max_duration_hours" in budget:
            flat["max_duration_hours"] = budget["max_duration_hours"]
        for k in ("max_concurrent_agents", "max_per_vuln_type",
                   "lead_max_attempts", "claim_ttl_seconds",
                   "max_scheduler_ticks", "idle_ticks_before_done",
                   "per_type_cap",
                   "authz_per_tick_cap", "chain_per_tick_cap",
                   "max_specialists_per_endpoint",
                   "max_consecutive_waiting_ticks",
                   "budget_cheap_ceiling_pct", "budget_cheap_floor_pct",
                   "max_inconclusive_retries", "max_failed_retries",
                   "managed_scan_concurrency", "preflight_scan_deadline_s",
                   "active_recon_enabled"):
            if k in guardrails:
                flat[k] = guardrails[k]
        if "active_recon_enabled" in raw:
            flat["active_recon_enabled"] = raw["active_recon_enabled"]
        if "managed_scans" in raw:
            flat["managed_scans"] = raw["managed_scans"]
        if "model" in raw:
            flat["model"] = raw["model"]
        return cls(**flat)


class GreyBoxInput(BaseModel):
    """Top-level input to the GreyBoxPipelineWorkflow."""
    web_url: str
    session_id: str
    credentials_path: str
    config_path: str | None = None
    output_path: str | None = None
    description: str = ""
    rules_avoid: list[str] = Field(default_factory=list)
    rules_focus: list[str] = Field(default_factory=list)
    config: GreyBoxConfig = Field(default_factory=GreyBoxConfig)
    identities: list[IdentityConfig] = Field(default_factory=list)
    resume_phase: str | None = None
    resume_state: dict[str, Any] | None = None
    workflow_id: str | None = None
