# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Art. 23 incident-deadline MONITOR (read API).

The `Incident` model (`app.models.incident`, table `incidents`) carries the
legally binding Art. 23 timeline — detection → early warning (24h) →
notification (72h) → final report (1 month) — and is written/enforced by the
Celery deadline task (`app.tasks.incident_tasks`). Until now it had NO REST
surface: the countdown that drives the whole CSIRT obligation was invisible in
the product. This router exposes it read-only so the dashboard can render the
live deadline clocks.

Distinct from `app.routers.incidents` (the `IncidentReport` CSIRT submission
form, table `incident_reports`) — different model, different purpose.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_org
from app.models.incident import Incident
from app.models.membership import Membership
from app.models.user import User

router = APIRouter(prefix="/incident-monitor", tags=["incident-monitor"])

# Statuses that stop the Art. 23 clock (no more deadlines to chase).
_CLOSED_STATUSES = ("closed", "recovered")


class DeadlineState(BaseModel):
    """One Art. 23 deadline with its live countdown, computed server-side."""

    label: str  # early_warning | notification | final_report
    deadline: Optional[datetime]
    sent_at: Optional[datetime]
    seconds_remaining: Optional[int]  # negative = overdue; None if no deadline
    breached: bool  # deadline passed AND nothing sent


class IncidentMonitorResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    incident_type: str
    severity: str
    status: str
    detected_at: datetime
    early_warning_deadline: datetime
    early_warning_sent_at: Optional[datetime] = None
    notification_deadline: datetime
    notification_sent_at: Optional[datetime] = None
    final_report_deadline: Optional[datetime] = None
    final_report_sent_at: Optional[datetime] = None
    description: str
    affected_systems: Optional[str] = None
    impact_category: str
    estimated_impact_level: int
    cross_border: bool
    supply_chain_impact: bool
    users_affected_count: Optional[int] = None
    csirt_reference_id: Optional[str] = None
    # Derived
    is_open: bool
    deadlines: list[DeadlineState]
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class IncidentMonitorListResponse(BaseModel):
    items: list[IncidentMonitorResponse]
    total: int
    open_count: int
    breached_count: int


def _deadline_state(
    label: str, deadline: Optional[datetime], sent_at: Optional[datetime], now: datetime
) -> DeadlineState:
    seconds_remaining = None
    breached = False
    if deadline is not None:
        seconds_remaining = int((deadline - now).total_seconds())
        breached = sent_at is None and deadline < now
    return DeadlineState(
        label=label,
        deadline=deadline,
        sent_at=sent_at,
        seconds_remaining=seconds_remaining,
        breached=breached,
    )


def _to_response(inc: Incident, now: datetime) -> IncidentMonitorResponse:
    is_open = inc.status not in _CLOSED_STATUSES
    # A closed incident's clock has stopped — surface the deadlines but never
    # flag them as breached (the obligation is discharged).
    deadlines = [
        _deadline_state("early_warning", inc.early_warning_deadline, inc.early_warning_sent_at, now),
        _deadline_state("notification", inc.notification_deadline, inc.notification_sent_at, now),
        _deadline_state("final_report", inc.final_report_deadline, inc.final_report_sent_at, now),
    ]
    if not is_open:
        for d in deadlines:
            d.breached = False
    return IncidentMonitorResponse(
        id=inc.id,
        organization_id=inc.organization_id,
        title=inc.title,
        incident_type=inc.incident_type,
        severity=inc.severity,
        status=inc.status,
        detected_at=inc.detected_at,
        early_warning_deadline=inc.early_warning_deadline,
        early_warning_sent_at=inc.early_warning_sent_at,
        notification_deadline=inc.notification_deadline,
        notification_sent_at=inc.notification_sent_at,
        final_report_deadline=inc.final_report_deadline,
        final_report_sent_at=inc.final_report_sent_at,
        description=inc.description,
        affected_systems=inc.affected_systems,
        impact_category=inc.impact_category,
        estimated_impact_level=inc.estimated_impact_level,
        cross_border=inc.cross_border,
        supply_chain_impact=inc.supply_chain_impact,
        users_affected_count=inc.users_affected_count,
        csirt_reference_id=inc.csirt_reference_id,
        is_open=is_open,
        deadlines=deadlines,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


@router.get("", response_model=IncidentMonitorListResponse)
async def list_incident_monitor(
    only_open: bool = Query(False, description="Return only incidents with a live Art. 23 clock"),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> IncidentMonitorListResponse:
    """List Art. 23 incidents for the active org, most recently detected first,
    with live countdowns to each deadline computed server-side."""
    _user, membership = current_org
    org_id = membership.organization_id
    now = datetime.now(timezone.utc)

    query = select(Incident).where(Incident.organization_id == org_id)
    if only_open:
        query = query.where(Incident.status.notin_(_CLOSED_STATUSES))
    query = query.order_by(Incident.detected_at.desc())

    incidents = (await db.execute(query)).scalars().all()
    items = [_to_response(i, now) for i in incidents]
    open_count = sum(1 for i in items if i.is_open)
    breached_count = sum(1 for i in items if any(d.breached for d in i.deadlines))
    return IncidentMonitorListResponse(
        items=items,
        total=len(items),
        open_count=open_count,
        breached_count=breached_count,
    )


@router.get("/{incident_id}", response_model=IncidentMonitorResponse)
async def get_incident_monitor(
    incident_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> IncidentMonitorResponse:
    _user, membership = current_org
    now = datetime.now(timezone.utc)
    inc = (
        await db.execute(select(Incident).where(Incident.id == incident_id))
    ).scalar_one_or_none()
    if inc is None or inc.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _to_response(inc, now)
