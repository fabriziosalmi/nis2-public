# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Tiny email-sender wrapper.

Why stdlib `smtplib` and not `aiosmtplib` / `python-emails` / `fastmail`:
the only thing we need is `MTA.connect → STARTTLS → AUTH → sendmail`.
A blocking call inside `asyncio.to_thread(...)` is fine here — emails
are slow paths (forgot-password, future invite). Adding a runtime dep
just for that is a worse trade than 30 lines of stdlib.

When `settings.smtp_host` is empty (typical for `make dev` and the
e2e suite), we don't call out to an MTA. Instead we:
  1. Log the rendered email at INFO so a developer can copy-paste the
     reset link from `make dev-logs`.
  2. Append the message to a process-local `_DEV_OUTBOX` so the e2e
     suite can read the link via the dev-only debug endpoint
     `GET /api/v1/auth/debug/last-email` (mounted only when
     environment != "production").

This is intentionally not a queue or a worker job — the calling
endpoint awaits the send; if SMTP is down, the user sees a 5xx and
the email isn't lost (no delivery promise we couldn't keep).
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)

# Process-local in-memory outbox. Only used when smtp_host is unset
# AND environment != "production". The /auth/debug/last-email endpoint
# reads from here to support the e2e tests; cleared on each test via
# `clear_dev_outbox()`.
_DEV_OUTBOX: list[dict] = []
_DEV_OUTBOX_MAX = 100


def _is_dev_outbox_active() -> bool:
    return not settings.smtp_host and settings.environment != "production"


def clear_dev_outbox() -> None:
    """Drop every captured message. Used by tests between runs."""
    _DEV_OUTBOX.clear()


def get_dev_outbox() -> list[dict]:
    """Snapshot copy of captured messages (newest last)."""
    return list(_DEV_OUTBOX)


def _send_smtp_blocking(msg: EmailMessage) -> None:
    """The actual blocking SMTP dance. Runs inside a thread executor."""
    if settings.smtp_ssl:
        client_cls = smtplib.SMTP_SSL
    else:
        client_cls = smtplib.SMTP
    with client_cls(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        if settings.smtp_starttls and not settings.smtp_ssl:
            smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(msg)


async def send_email(
    *,
    to: str,
    subject: str,
    text: str,
    html: Optional[str] = None,
) -> None:
    """Send a transactional email or, in dev, log + capture it.

    Never raises into the caller in dev mode — failure to log is not
    interesting. Production raises whatever smtplib raises (the route
    catches and turns it into a 5xx).
    """
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")

    if _is_dev_outbox_active():
        # Dev path: log + capture, no MTA dial-out.
        logger.info(
            "[email-dev] to=%s subject=%r — body follows on next line:\n%s",
            to,
            subject,
            text,
        )
        _DEV_OUTBOX.append({"to": to, "subject": subject, "text": text, "html": html})
        # Keep memory bounded — drop oldest if we somehow accrue more
        # than _DEV_OUTBOX_MAX without a test calling clear_dev_outbox.
        while len(_DEV_OUTBOX) > _DEV_OUTBOX_MAX:
            _DEV_OUTBOX.pop(0)
        return

    if not settings.smtp_host:
        # Production with no SMTP: hard fail rather than silently drop.
        # The forgot-password route will turn this into a 503.
        raise RuntimeError(
            "SMTP is not configured. Set SMTP_HOST/SMTP_PORT/SMTP_FROM (and "
            "credentials if your relay requires them) in the environment."
        )

    # Real send — offload to a thread so we don't block the event loop.
    await asyncio.to_thread(_send_smtp_blocking, msg)
