"""``GET /greybox/config``. Always mounted, even with the flag off."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from src.greybox_web import checks as gb_checks
from src.greybox_web import modelsel
from src.greybox_web import settings as gb_settings
from src.greybox_web.schemas import (
    LIMITS_DEFAULTS,
    LIMITS_MAX,
    AgentDefault,
    AgentInfo,
    CheckInfo,
    ConfigRead,
    LimitsConfig,
    ModelBackendInfo,
)
from src.webapi.auth.deps import current_active_user
from src.webapi.models import User

router = APIRouter(prefix="/greybox", tags=["greybox"])


@router.get("/config", response_model=ConfigRead)
async def get_config(_: User = Depends(current_active_user)) -> ConfigRead:
    s = gb_settings.settings()
    return ConfigRead(
        enabled=bool(s.greybox_web_enabled),
        executor=s.greybox_executor,
        allow_private_targets=bool(s.greybox_allow_private_targets),
        egress_proxies_enabled=bool(s.greybox_egress_proxies_enabled),
        checks=[CheckInfo(id=c.id, title=c.title, description=c.description,
                          area=gb_checks.area(c.id).name,
                          evidence=gb_checks.area(c.id).evidence,
                          default_enabled=(c.default_enabled
                                           and gb_checks.is_available(c.id)),
                          requires_auth_testing=c.requires_auth_testing,
                          available=gb_checks.is_available(c.id),
                          unavailable_reason=gb_checks.unavailable_reason(c.id))
                for c in gb_checks.CHECKS],
        limits=LimitsConfig(defaults=LIMITS_DEFAULTS, max=LIMITS_MAX),
        agent=_agent_info(s),
    )


def _agent_info(s) -> AgentInfo:
    bs = modelsel.backends()
    d = modelsel.default_choice()
    return AgentInfo(
        available=any(b.available for b in bs),
        backends=[ModelBackendInfo(id=b.id, label=b.label, available=b.available,
                                   reason=b.reason, models=list(b.models)) for b in bs],
        default=AgentDefault(backend=d[0], model=d[1]) if d else None,
        max_calls=int(s.greybox_agent_max_calls),
        max_tokens=int(s.greybox_agent_max_tokens),
        timeout_s=float(s.greybox_agent_timeout_s))
