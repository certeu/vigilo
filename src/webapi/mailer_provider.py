"""Mailer dependency provider (real SMTP when configured, else a no-op fake)."""
from __future__ import annotations

from functools import lru_cache

from src.webapi.notifications import FakeMailer, Mailer, SmtpMailer
from src.webapi.settings import get_settings


@lru_cache
def _build_mailer() -> Mailer:
    s = get_settings()
    if s.smtp_host:
        return SmtpMailer(
            host=s.smtp_host, sender=s.smtp_from, port=s.smtp_port,
            user=s.smtp_user, password=s.smtp_password, starttls=s.smtp_starttls,
        )
    return FakeMailer()


def get_mailer() -> Mailer:
    return _build_mailer()
