"""Tests for grey-box type definitions."""
from __future__ import annotations


def test_greybox_config_defaults():
    from src.greybox.types.config import GreyBoxConfig
    cfg = GreyBoxConfig()
    assert cfg.max_concurrent_agents == 12
    assert cfg.per_scan_cost_ceiling == 50.0
    assert cfg.lead_max_attempts == 3
    assert cfg.claim_ttl_seconds == 300
    assert cfg.max_spawn_depth == 3  # E8
    # C5: per-tick verb caps
    assert cfg.per_type_cap == 3
    assert cfg.authz_per_tick_cap == 2
    assert cfg.chain_per_tick_cap == 1
    # C4: per-endpoint specialist cap
    assert cfg.max_specialists_per_endpoint == 2


def test_greybox_config_from_yaml(tmp_path):
    import yaml
    from src.greybox.types.config import GreyBoxConfig
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml.dump({
        "budget": {"max_cost_usd": 100.0},
        "guardrails": {"max_concurrent_agents": 8},
    }))
    cfg = GreyBoxConfig.from_yaml(cfg_file)
    assert cfg.per_scan_cost_ceiling == 100.0
    assert cfg.max_concurrent_agents == 8


def test_greybox_config_from_yaml_per_tick_caps(tmp_path):
    """C5: per_type_cap, authz_per_tick_cap, chain_per_tick_cap read from guardrails."""
    import yaml
    from src.greybox.types.config import GreyBoxConfig
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml.dump({
        "guardrails": {
            "per_type_cap": 5,
            "authz_per_tick_cap": 4,
            "chain_per_tick_cap": 2,
        },
    }))
    cfg = GreyBoxConfig.from_yaml(cfg_file)
    assert cfg.per_type_cap == 5
    assert cfg.authz_per_tick_cap == 4
    assert cfg.chain_per_tick_cap == 2


def test_greybox_config_from_yaml_max_specialists_per_endpoint(tmp_path):
    """C4: max_specialists_per_endpoint read from guardrails."""
    import yaml
    from src.greybox.types.config import GreyBoxConfig
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml.dump({
        "guardrails": {"max_specialists_per_endpoint": 3},
    }))
    cfg = GreyBoxConfig.from_yaml(cfg_file)
    assert cfg.max_specialists_per_endpoint == 3


def test_greybox_config_budget_cheap_thresholds_defaults():
    """C1: budget_cheap_ceiling_pct / budget_cheap_floor_pct defaults (fractions)."""
    from src.greybox.types.config import GreyBoxConfig
    cfg = GreyBoxConfig()
    assert cfg.budget_cheap_ceiling_pct == 0.10
    assert cfg.budget_cheap_floor_pct == 0.03


def test_greybox_config_budget_thresholds_rejects_floor_above_ceiling():
    """Floor must be strictly below ceiling."""
    import pytest
    from pydantic import ValidationError
    from src.greybox.types.config import GreyBoxConfig
    with pytest.raises(ValidationError):
        GreyBoxConfig(
            budget_cheap_ceiling_pct=0.05,
            budget_cheap_floor_pct=0.10,
        )


def test_greybox_config_budget_thresholds_rejects_equal():
    """Floor == ceiling is rejected (must be strictly less)."""
    import pytest
    from pydantic import ValidationError
    from src.greybox.types.config import GreyBoxConfig
    with pytest.raises(ValidationError):
        GreyBoxConfig(
            budget_cheap_ceiling_pct=0.05,
            budget_cheap_floor_pct=0.05,
        )


def test_greybox_config_budget_thresholds_rejects_out_of_range():
    """Fractions must be in [0.0, 1.0]."""
    import pytest
    from pydantic import ValidationError
    from src.greybox.types.config import GreyBoxConfig
    with pytest.raises(ValidationError):
        GreyBoxConfig(budget_cheap_ceiling_pct=1.5)
    with pytest.raises(ValidationError):
        GreyBoxConfig(budget_cheap_floor_pct=-0.1)


def test_greybox_config_from_yaml_budget_thresholds(tmp_path):
    """C1: budget_cheap_ceiling_pct / budget_cheap_floor_pct read from guardrails."""
    import yaml
    from src.greybox.types.config import GreyBoxConfig
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml.dump({
        "guardrails": {
            "budget_cheap_ceiling_pct": 0.20,
            "budget_cheap_floor_pct": 0.05,
        },
    }))
    cfg = GreyBoxConfig.from_yaml(cfg_file)
    assert cfg.budget_cheap_ceiling_pct == 0.20
    assert cfg.budget_cheap_floor_pct == 0.05


def test_scheduler_config_budget_cheap_thresholds_defaults():
    """SchedulerConfig mirrors GreyBoxConfig defaults for the budget thresholds."""
    from src.greybox.scheduler.rules import SchedulerConfig
    cfg = SchedulerConfig()
    assert cfg.budget_cheap_ceiling_pct == 0.10
    assert cfg.budget_cheap_floor_pct == 0.03


def test_greybox_input_required_fields():
    from src.greybox.types.config import GreyBoxInput
    inp = GreyBoxInput(
        web_url="http://target.local",
        session_id="sess-001",
        credentials_path="/path/to/creds.yaml",
    )
    assert inp.web_url == "http://target.local"
    assert inp.resume_phase is None
    assert inp.resume_state is None


def test_greybox_input_resume():
    from src.greybox.types.config import GreyBoxInput
    inp = GreyBoxInput(
        web_url="http://target.local",
        session_id="sess-001",
        credentials_path="/path/to/creds.yaml",
        resume_phase="reactive-testing",
        resume_state={"planner_invocations": 3},
    )
    assert inp.resume_phase == "reactive-testing"


def test_identity_config():
    from src.greybox.types.config import IdentityConfig
    ident = IdentityConfig(
        name="admin",
        role="admin",
        privilege_level=10,
        login={"url": "http://target/login", "method": "form",
               "fields": {"username": "admin", "password": "pass123"},
               "success_indicator": "Dashboard"},
    )
    assert ident.name == "admin"
    assert ident.privilege_level == 10
    assert ident.totp_secret is None


def test_agent_model_tiers():
    from src.greybox.types.agents import AGENT_MODEL_TIERS
    assert "CHAIN_EXPLOIT" in AGENT_MODEL_TIERS


def test_signal_type_enum():
    from src.greybox.types.signals import SignalType
    assert SignalType.CREDENTIALS_FOUND == "credentials_found"


def test_capability_vocabulary():
    from src.greybox.types.agents import CAPABILITY_VOCABULARY
    assert "db_read" in CAPABILITY_VOCABULARY
    assert "credential_access" in CAPABILITY_VOCABULARY
    assert "admin_access" in CAPABILITY_VOCABULARY
    assert len(CAPABILITY_VOCABULARY) >= 15


def test_managed_scans_default_roster():
    from src.greybox.types.config import GreyBoxConfig
    cfg = GreyBoxConfig()
    # 8 always-on scanners + 2 active-recon scanners (gated by
    # active_recon_enabled, default off).
    assert len(cfg.managed_scans) == 10
    assert "tech_fingerprint" in cfg.managed_scans
    assert "robots_sitemap" in cfg.managed_scans
    assert cfg.managed_scans["nmap"] is False
    assert cfg.managed_scans["httpx_probe"] is False
    assert cfg.active_recon_enabled is False


def test_report_in_prompt_templates():
    from src.greybox.types.agents import AGENT_PROMPT_TEMPLATES
    assert "report" in AGENT_PROMPT_TEMPLATES  # E11


def test_lead_signal_vocabulary():
    from src.greybox.types.agents import LEAD_SIGNAL_VOCABULARY
    assert "response_code_anomaly" in LEAD_SIGNAL_VOCABULARY
    assert "timing_anomaly" in LEAD_SIGNAL_VOCABULARY
    assert len(LEAD_SIGNAL_VOCABULARY) >= 11  # E17
