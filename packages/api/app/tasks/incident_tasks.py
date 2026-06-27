# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
NIS2 Art. 23 incident deadline monitor.

Runs every 15 minutes via Celery beat. For each open incident, checks
whether the Art. 23 reporting deadlines are approaching or overdue and
dispatches notifications via the org's active notification channels.

Art. 23 deadlines (from incident.detected_at):
  - Early warning:   + 24 h
  - Notification:    + 72 h
  - Final report:    + 1 month

Alert windows:
  - APPROACHING: deadline is within WARN_HOURS_BEFORE hours, not yet sent
  - OVERDUE:     deadline has passed, not yet sent

Dedup is handled with Redis keys so a 15-minute beat cadence does not
spam the same alert on every tick.  Keys expire automatically — the task
never cleans them up explicitly.

Notification dispatch supports the three channel types already defined
in NotificationChannel: email, webhook (HMAC-SHA256 signed), slack.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import redis as redis_sync

from app.config import settings
from app.tasks.celery_app import celery_app
from app.utils.target_validator import validate_url_against_ssrf

logger = logging.getLogger(__name__)

# How many hours before the deadline to send the first "approaching" alert.
WARN_HOURS_BEFORE: int = 2

# Redis TTLs for dedup keys.
# APPROACHING key lives long enough to cover the warning window + one full
# beat interval so we never re-alert on the same approaching event.
_TTL_APPROACHING: int = int((WARN_HOURS_BEFORE + 1) * 3600)
# OVERDUE key re-alerts once per day if the deadline is still missed.
_TTL_OVERDUE: int = 86400  # 24 h

# Incident statuses considered "closed" — no alerts needed.
_CLOSED_STATUSES = frozenset({"closed", "recovered", "eradicated"})

# Each entry describes one Art. 23 deadline to monitor.
# (deadline_field, sent_field, label, article_ref)
_DEADLINES = [
    (
        "early_warning_deadline",
        "early_warning_sent_at",
        "Early Warning",
        "Art. 23.1 — 24h from detection",
    ),
    (
        "notification_deadline",
        "notification_sent_at",
        "Incident Notification",
        "Art. 23.1 — 72h from detection",
    ),
    (
        "final_report_deadline",
        "final_report_sent_at",
        "Final Report",
        "Art. 23.1 — 1 month from detection",
    ),
]


# ---------------------------------------------------------------------------
# Celery entry point
# ---------------------------------------------------------------------------


@celery_app.task
def check_incident_deadlines() -> dict:
    """Beat task: check NIS2 Art. 23 deadlines and dispatch alerts."""
    return asyncio.run(_check_deadlines())


# ---------------------------------------------------------------------------
# Core async logic
# ---------------------------------------------------------------------------


async def _check_deadlines() -> dict:
    from app.models.incident import Incident
    from app.models.notification_channel import NotificationChannel
    from app.models.membership import Membership
    from app.models.organization import Organization
    from app.models.user import User
    from app.database import async_session_factory, set_rls_org_context
    from sqlalchemy import select

    now = datetime.now(timezone.utc)
    total_alerts = 0

    _redis = _get_redis_client()

    async with async_session_factory() as db:
        # H5: this cross-tenant sweep has no request context, so a single
        # cross-tenant SELECT returns nothing under a NOBYPASSRLS role. Walk the
        # orgs, scope the session per-org, and gather each org's open incidents.
        # The explicit organization_id filter keeps it correct under the current
        # superuser role too. organizations has no tenant policy → enumerable.
        org_ids = (await db.execute(select(Organization.id))).scalars().all()
        incidents = []
        for _org_id in org_ids:
            await set_rls_org_context(db, str(_org_id))
            _res = await db.execute(
                select(Incident).where(
                    Incident.status.notin_(_CLOSED_STATUSES),
                    Incident.organization_id == _org_id,
                )
            )
            incidents.extend(_res.scalars().all())

        for incident in incidents:
            # Re-scope to this incident's org before its org-scoped reads/writes.
            await set_rls_org_context(db, str(incident.organization_id))
            # Load org's active notification channels once per incident
            chan_result = await db.execute(
                select(NotificationChannel).where(
                    NotificationChannel.organization_id == incident.organization_id,
                    NotificationChannel.is_active.is_(True),
                )
            )
            channels = chan_result.scalars().all()

            # If no channels configured, fall back to emailing org admins
            if not channels:
                admin_result = await db.execute(
                    select(User)
                    .join(Membership, Membership.user_id == User.id)
                    .where(
                        Membership.organization_id == incident.organization_id,
                        Membership.role.in_(("admin", "owner")),
                        User.is_active.is_(True),
                    )
                )
                admins = admin_result.scalars().all()
                channels = [_synthetic_email_channel(admin.email) for admin in admins]

            for deadline_field, sent_field, label, article_ref in _DEADLINES:
                deadline: Optional[datetime] = getattr(incident, deadline_field, None)
                sent_at: Optional[datetime] = getattr(incident, sent_field, None)

                if deadline is None:
                    continue
                # Deadline already actioned by the user → no alert needed
                if sent_at is not None:
                    continue

                alert_type = _classify_alert(now, deadline)
                if alert_type is None:
                    continue

                dedup_key = (
                    f"nis2:inc_alert:{incident.id}:{deadline_field}:{alert_type}"
                )
                if _redis and _redis.get(dedup_key):
                    # Already alerted for this window; skip.
                    continue

                # Build the alert payload
                payload = _build_alert_payload(
                    incident=incident,
                    now=now,
                    deadline=deadline,
                    label=label,
                    article_ref=article_ref,
                    alert_type=alert_type,
                )

                sent = await _dispatch_to_channels(channels, payload)
                if sent:
                    ttl = _TTL_OVERDUE if alert_type == "overdue" else _TTL_APPROACHING
                    if _redis:
                        _redis.setex(dedup_key, ttl, "1")
                    total_alerts += 1
                    logger.info(
                        "incident_deadline_alert: incident=%s deadline=%s type=%s channels=%d",
                        incident.id,
                        deadline_field,
                        alert_type,
                        sent,
                    )

    return {"alerts_dispatched": total_alerts}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_redis_client() -> Optional[redis_sync.Redis]:
    """Return a synchronous Redis client for dedup key operations.

    Uses the same URL as the Celery broker (redis://host:port/N).
    Falls back to None if Redis is unreachable — alerts will fire on
    every beat tick in that case (acceptable degraded mode: double-alert
    is less bad than silent deadline miss).
    """
    try:
        client = redis_sync.from_url(settings.redis_url, socket_connect_timeout=2)
        client.ping()
        return client
    except Exception as exc:  # noqa: BLE001
        logger.warning("incident_tasks: Redis unavailable, dedup disabled: %s", exc)
        return None


def _classify_alert(now: datetime, deadline: datetime) -> Optional[str]:
    """Return 'approaching', 'overdue', or None."""
    warn_threshold = deadline - timedelta(hours=WARN_HOURS_BEFORE)
    if now >= deadline:
        return "overdue"
    if now >= warn_threshold:
        return "approaching"
    return None


def _build_alert_payload(
    *,
    incident,
    now: datetime,
    deadline: datetime,
    label: str,
    article_ref: str,
    alert_type: str,
) -> dict:
    time_delta = deadline - now
    minutes_left = int(time_delta.total_seconds() / 60)
    if alert_type == "overdue":
        overdue_minutes = int((now - deadline).total_seconds() / 60)
        urgency = f"OVERDUE by {overdue_minutes} minutes"
        subject = f"[NIS2 OVERDUE] {label} deadline missed — {incident.title}"
    else:
        urgency = f"due in {minutes_left} minutes"
        subject = f"[NIS2 ALERT] {label} deadline approaching — {incident.title}"

    body = (
        f"NIS2 Art. 23 Deadline Alert\n"
        f"{'=' * 40}\n"
        f"Incident : {incident.title}\n"
        f"Type     : {incident.incident_type}\n"
        f"Severity : {incident.severity.upper()}\n"
        f"Detected : {incident.detected_at.strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"\n"
        f"Deadline : {label} ({article_ref})\n"
        f"Due at   : {deadline.strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"Status   : {urgency}\n"
        f"\n"
        f"Action required: report this incident to CSIRT Italia (csirt.gov.it).\n"
        f"Failure to notify within the NIS2 deadline may result in sanctions.\n"
    )

    return {
        "subject": subject,
        "body": body,
        "incident_id": str(incident.id),
        "incident_title": incident.title,
        "incident_severity": incident.severity,
        "deadline_label": label,
        "deadline_at": deadline.isoformat(),
        "alert_type": alert_type,
        "article_ref": article_ref,
    }


async def _dispatch_to_channels(channels: list, payload: dict) -> int:
    """Send alert to each active channel. Returns count of successful sends."""
    sent = 0
    async with httpx.AsyncClient(timeout=10.0) as client:
        for ch in channels:
            try:
                if ch.channel_type == "email":
                    await _dispatch_email(ch, payload)
                    sent += 1
                elif ch.channel_type == "webhook":
                    ok = await _dispatch_webhook(client, ch, payload)
                    if ok:
                        sent += 1
                elif ch.channel_type == "slack":
                    ok = await _dispatch_slack(client, ch, payload)
                    if ok:
                        sent += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "incident_tasks: dispatch failed channel=%s type=%s: %s",
                    getattr(ch, "name", "?"),
                    getattr(ch, "channel_type", "?"),
                    exc,
                )
    return sent


async def _dispatch_email(channel, payload: dict) -> None:
    from app.utils.email import send_email

    cfg = channel.config or {}
    email_to = cfg.get("email") or cfg.get("to")
    if not email_to:
        logger.warning(
            "incident_tasks: email channel %r has no 'email' in config", channel.name
        )
        return
    await send_email(
        to=email_to,
        subject=payload["subject"],
        text=payload["body"],
    )


async def _dispatch_webhook(client: httpx.AsyncClient, channel, payload: dict) -> bool:
    cfg = channel.config or {}
    url = cfg.get("url")
    if not url:
        logger.warning(
            "incident_tasks: webhook channel %r has no 'url' in config", channel.name
        )
        return False

    # Validate against SSRF
    try:
        await validate_url_against_ssrf(url)
    except Exception as exc:
        logger.warning(
            "incident_tasks: webhook %r blocked by SSRF: %s", channel.name, exc
        )
        return False

    body_bytes = json.dumps(payload).encode()

    headers = {"Content-Type": "application/json", "X-NIS2-Event": "incident.deadline"}
    secret = cfg.get("secret")
    if secret:
        # HMAC-SHA256 signature — receiver can verify: hmac.new(secret, body, sha256)
        sig = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
        headers["X-NIS2-Signature"] = f"sha256={sig}"

    resp = await client.post(url, content=body_bytes, headers=headers)
    if not resp.is_success:
        logger.warning(
            "incident_tasks: webhook %r returned %d", channel.name, resp.status_code
        )
        return False
    return True


async def _dispatch_slack(client: httpx.AsyncClient, channel, payload: dict) -> bool:
    cfg = channel.config or {}
    webhook_url = cfg.get("webhook_url")
    if not webhook_url:
        logger.warning(
            "incident_tasks: slack channel %r has no 'webhook_url' in config",
            channel.name,
        )
        return False

    # Validate against SSRF
    try:
        await validate_url_against_ssrf(webhook_url)
    except Exception as exc:
        logger.warning(
            "incident_tasks: slack channel %r blocked by SSRF: %s", channel.name, exc
        )
        return False

    alert_type = payload["alert_type"]
    emoji = ":rotating_light:" if alert_type == "overdue" else ":warning:"
    color = "#FF0000" if alert_type == "overdue" else "#FF8C00"

    slack_payload = {
        "attachments": [
            {
                "color": color,
                "title": f"{emoji} {payload['subject']}",
                "text": payload["body"],
                "footer": f"NIS2 Platform | {payload['article_ref']}",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ]
    }
    resp = await client.post(webhook_url, json=slack_payload)
    if not resp.is_success:
        logger.warning(
            "incident_tasks: slack %r returned %d", channel.name, resp.status_code
        )
        return False
    return True


def _synthetic_email_channel(email: str):
    """Create a minimal channel-like object for fallback admin email alerts."""

    class _FakeChannel:
        channel_type = "email"
        name = f"admin:{email}"
        config = {"email": email}

    return _FakeChannel()
