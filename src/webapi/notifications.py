"""Completion email notifications.

A ``Mailer`` sends a simple message dict. ``SmtpMailer`` uses stdlib smtplib (run
off the event loop by the caller); ``FakeMailer`` records messages for tests and
local evaluation. ``build_completion_message`` renders the subject/body for a run.
"""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Protocol, runtime_checkable

from src.webapi.models import RUN_SUCCEEDED, Run


@runtime_checkable
class Mailer(Protocol):
    def send(self, to: str, subject: str, body: str, attachment_path: str | None) -> None: ...


class FakeMailer:
    """Captures sent messages instead of sending them."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send(self, to: str, subject: str, body: str, attachment_path: str | None) -> None:
        self.sent.append(
            {"to": to, "subject": subject, "body": body, "attachment": attachment_path}
        )


class SmtpMailer:
    def __init__(
        self, host: str, sender: str, port: int = 25,
        user: str | None = None, password: str | None = None, starttls: bool = False,
    ) -> None:
        self.host = host
        self.sender = sender
        self.port = port
        self.user = user
        self.password = password
        self.starttls = starttls

    def send(self, to: str, subject: str, body: str, attachment_path: str | None) -> None:
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        if attachment_path:
            with open(attachment_path, "rb") as fh:
                msg.add_attachment(
                    fh.read(), maintype="text", subtype="markdown",
                    filename=attachment_path.rsplit("/", 1)[-1],
                )
        with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
            if self.starttls:
                smtp.starttls()
            if self.user and self.password:
                smtp.login(self.user, self.password)
            smtp.send_message(msg)


def build_completion_message(
    run: Run,
    recipient: str,
    report_exists: bool,
    ui_base_url: str | None,
) -> dict:
    """Return {to, subject, body} for a finished run."""
    verdict = "succeeded" if run.status == RUN_SUCCEEDED else run.status
    subject = f"[Vigilo] Run {str(run.id)[:8]} {verdict}"
    lines = [
        f"Your Vigilo run {run.id} has {verdict}.",
        f"Session: {run.session_id}",
    ]
    if run.total_cost_usd is not None:
        lines.append(f"Cost: ${run.total_cost_usd:.2f}")
    if run.error_summary:
        lines.append(f"Error: {run.error_summary}")
    if ui_base_url:
        lines.append(f"\nView the run: {ui_base_url}/runs/{run.id}")
    if report_exists:
        lines.append("\nThe full report is attached.")
    else:
        lines.append("\nNo report was produced (see logs).")
    return {"to": recipient, "subject": subject, "body": "\n".join(lines)}
