# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Notification channels — the delivery targets for Art. 23 deadline alerts.

The `NotificationChannel` model, the encrypted config column and the whole
dispatcher (`app/tasks/incident_tasks.py`: email, HMAC-signed webhook, Slack)
have existed for releases. There was no way to create a row: no endpoint, no
seed, and a settings screen that kept channels in React state and threw them
away on navigation while showing a success toast.

So the Art. 23 deadline monitor — which runs every 15 minutes and is the
platform's strongest NIS2 claim — always found zero channels and fell back to
emailing organisation admins, which needs SMTP configured. On a deployment with
neither, the alert for a legally binding 24-hour notification deadline was
written to the application log.

Config shape per channel type, matching what the dispatcher reads:

    email    {"email": "soc@example.com"}
    webhook  {"url": "https://...", "secret": "..."}   secret optional, HMAC-SHA256
    slack    {"webhook_url": "https://hooks.slack.com/..."}

Both URL-bearing types are validated against the SSRF blocklist on write, not
only at dispatch time: a channel pointing at 169.254.169.254 should be refused
when it is created, not fail quietly every 15 minutes inside a Celery task.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user_org, require_role
from app.models.notification_channel import NotificationChannel
from app.utils.target_validator import TargetValidationError, validate_url_against_ssrf

router = APIRouter(prefix="/notification-channels", tags=["notifications"])

CHANNEL_TYPES = ("email", "webhook", "slack")

# Where each type keeps its destination. These names are read verbatim by
# app/tasks/incident_tasks.py; if they drift, a channel saves cleanly and then
# never delivers — the silent-degradation shape this module exists to remove.
TARGET_KEY_BY_TYPE = {
    "email": "email",
    "webhook": "url",
    "slack": "webhook_url",
}

# Event names the UI offers. Kept here rather than in the frontend so the two
# cannot drift; the dispatcher currently fires on incident deadlines regardless
# of this list, which is stored for forthcoming per-event routing.
EVENT_VALUES = (
    "scan_completed",
    "scan_failed",
    "critical_finding",
    "score_dropped",
    "domain_expiring",
    "incident_deadline",
)


class ChannelCreate(BaseModel):
    channel_type: Literal["email", "webhook", "slack"]
    name: str = Field(..., min_length=1, max_length=256)
    config: dict[str, Any]
    events: list[str] = Field(default_factory=list)
    is_active: bool = True


class ChannelUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    config: Optional[dict[str, Any]] = None
    events: Optional[list[str]] = None
    is_active: Optional[bool] = None


class ChannelResponse(BaseModel):
    id: uuid.UUID
    channel_type: str
    name: str
    config: dict[str, Any]
    events: list[str]
    is_active: bool

    model_config = {"from_attributes": True}


def _redact(channel: NotificationChannel) -> dict[str, Any]:
    """Return the channel with credential material masked.

    `config` is encrypted at rest (L14) precisely because it holds Slack webhook
    URLs and webhook signing secrets. Handing them back in cleartext on every
    list request would undo that: a read-only `viewer` could harvest them, and
    they would sit in browser memory and any HTTP cache along the way. The UI
    only needs to show which target is configured, so URLs are truncated to
    their origin and secrets are replaced with a presence flag.
    """
    cfg = dict(channel.config or {})
    for key in ("secret", "token"):
        if cfg.get(key):
            cfg[key] = "••••••••"
    for key in ("url", "webhook_url"):
        raw = cfg.get(key)
        if isinstance(raw, str) and "://" in raw:
            scheme, _, rest = raw.partition("://")
            host = rest.split("/", 1)[0]
            cfg[key] = f"{scheme}://{host}/…"
    return {
        "id": channel.id,
        "channel_type": channel.channel_type,
        "name": channel.name,
        "config": cfg,
        "events": list(channel.events or []),
        "is_active": channel.is_active,
    }


async def _validate_config(channel_type: str, config: dict[str, Any]) -> None:
    """Reject a channel that could never deliver, at write time.

    Without this the dispatcher discovers the problem every 15 minutes and logs
    a warning nobody reads — the failure mode this whole module exists to end.
    """
    if channel_type == "email":
        if not (config.get("email") or config.get("to")):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="An email channel needs config.email",
            )
        return

    url_key = TARGET_KEY_BY_TYPE[channel_type]
    url = config.get(url_key)
    if not url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"A {channel_type} channel needs config.{url_key}",
        )
    try:
        await validate_url_against_ssrf(url)
    except TargetValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Blocked destination: {exc}",
        )


@router.get("", response_model=list[ChannelResponse])
async def list_channels(
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
) -> list[dict[str, Any]]:
    _, org_id = auth
    result = await db.execute(
        select(NotificationChannel)
        .where(NotificationChannel.organization_id == org_id)
        .order_by(NotificationChannel.created_at.desc())
    )
    return [_redact(c) for c in result.scalars().all()]


@router.post(
    "",
    response_model=ChannelResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin"))],
)
async def create_channel(
    payload: ChannelCreate,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
) -> dict[str, Any]:
    # admin only: a channel is an egress destination for incident data, and a
    # webhook target is somewhere the platform will POST organisation details
    # unattended every 15 minutes.
    _, org_id = auth
    await _validate_config(payload.channel_type, payload.config)
    channel = NotificationChannel(
        organization_id=org_id,
        channel_type=payload.channel_type,
        name=payload.name,
        config=payload.config,
        events=payload.events,
        is_active=payload.is_active,
    )
    db.add(channel)
    await db.flush()
    return _redact(channel)


@router.patch(
    "/{channel_id}",
    response_model=ChannelResponse,
    dependencies=[Depends(require_role("admin"))],
)
async def update_channel(
    channel_id: uuid.UUID,
    payload: ChannelUpdate,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
) -> dict[str, Any]:
    _, org_id = auth
    channel = await db.get(NotificationChannel, channel_id)
    if not channel or channel.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Channel not found")

    if payload.config is not None:
        await _validate_config(channel.channel_type, payload.config)
        channel.config = payload.config
    if payload.name is not None:
        channel.name = payload.name
    if payload.events is not None:
        channel.events = payload.events
    if payload.is_active is not None:
        channel.is_active = payload.is_active
    await db.flush()
    return _redact(channel)


@router.delete(
    "/{channel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role("admin"))],
)
async def delete_channel(
    channel_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
) -> None:
    _, org_id = auth
    channel = await db.get(NotificationChannel, channel_id)
    if not channel or channel.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Channel not found")
    await db.delete(channel)


@router.post(
    "/{channel_id}/test",
    dependencies=[Depends(require_role("admin"))],
)
async def test_channel(
    channel_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
) -> dict[str, Any]:
    """Send a sample alert through this channel.

    Worth its own endpoint: the real dispatch path only runs inside a Celery
    beat task on a 15-minute cadence, so without this an operator configuring
    Art. 23 alerting could not tell a working channel from a silent one until an
    actual incident deadline — which is the worst possible moment to find out.
    """
    _, org_id = auth
    channel = await db.get(NotificationChannel, channel_id)
    if not channel or channel.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Channel not found")

    from app.tasks.incident_tasks import _dispatch_to_channels

    payload = {
        "event": "test",
        "title": "NIS2 platform — test notification",
        "message": (
            "This is a test alert. If you are reading it, this channel is wired "
            "correctly and will receive Art. 23 deadline notifications."
        ),
        "incident_id": None,
        "deadline": None,
    }
    sent = await _dispatch_to_channels([channel], payload)
    if sent == 0:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The channel did not accept the test message. Check the API logs.",
        )
    return {"sent": sent}
