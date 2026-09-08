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

That split had a hole in it. `Incident` (table `incidents`) is what carries the
Art. 23 deadlines, and it is what this router, the Celery alerting task
(`tasks/incident_tasks.py`) and the report dossier all read. Nothing in the
application ever CREATED one: the only `Incident(...)` in the codebase was in a
demo seed script wired to no target. So three well-built components read from a
store with no producer, and the countdown, the 24 h / 72 h / 1-month alerting
and the dossier section could only ever show demo data.

Meanwhile `POST /api/v1/incidents` — the creation endpoint the README documents
— writes `IncidentReport`, a different table the clock does not look at. An
incident declared through the documented API was invisible to the deadline
monitor. Nobody noticed because the dashboard was read-only: an empty monitor
looked normal.

The write endpoints below close that: declaring an incident now produces the
record the Art. 23 clock actually watches.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_org, require_role
from app.models.incident import (
    CLOSED_STATUSES,
    INCIDENT_SEVERITY_PATTERN,
    INCIDENT_STATUS_PATTERN,
    INCIDENT_TYPE_PATTERN,
    Incident,
)
from app.models.membership import Membership
from app.models.user import User

router = APIRouter(prefix="/incident-monitor", tags=["incident-monitor"])

# Statuses that stop the Art. 23 clock. Imported rather than restated: this
# module and tasks/incident_tasks.py each had their own copy and they disagreed
# on `eradicated`, so an incident in that state was closed for the alerting and
# open for the API at the same time.
_CLOSED_STATUSES = CLOSED_STATUSES


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


# ---------------------------------------------------------------------------
# Write path
# ---------------------------------------------------------------------------

# Art. 23 windows. Stored on the row rather than derived on read so that a later
# correction to `detected_at` cannot silently move a deadline an operator has
# already acted on.
#
# The first two run from detection. The third does NOT, and getting that wrong
# is not a rounding error: Art. 23(4)(d) requires the final report "not later
# than one month after the submission of the incident notification referred to
# in point (b)" — the 72-hour notification, not the detection. This code
# computed `detected_at + 30 days` and the alert text said "1 month from
# detection", so every incident was reported as due three days early and the
# breach alert fired while the operator was still inside the legal window.
# `app/routers/acn.py` had already been corrected; the path that actually
# writes the row had not, which is the one the monitor, the dossier and the
# dashboard countdown all read.
_EARLY_WARNING_WINDOW = timedelta(hours=24)
_NOTIFICATION_WINDOW = timedelta(hours=72)
_FINAL_REPORT_WINDOW = timedelta(days=30)


def final_report_deadline_for(detected_at: datetime, notification_sent_at: Optional[datetime] = None) -> datetime:
    """When the Art. 23(4)(d) final report is due.

    Anchored on the actual submission of the 72-hour notification once that is
    recorded, and on the notification deadline until then — which is the latest
    the anchor can legally be, so the answer is never optimistic.
    """
    anchor = notification_sent_at or (detected_at + _NOTIFICATION_WINDOW)
    return anchor + _FINAL_REPORT_WINDOW


class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    # Constrained on the wire, like every other enumeration in this codebase.
    # Unconstrained, a typo in `status` made the incident permanently open: the
    # deadlines were reported as breached for ever and could not be cleared
    # through the API, because `is_open` is membership in a set the value would
    # never join.
    incident_type: str = Field(..., pattern=INCIDENT_TYPE_PATTERN)
    severity: str = Field(..., pattern=INCIDENT_SEVERITY_PATTERN)
    description: str = Field(..., min_length=1)
    # Optional so the UI can default it, but it is the value every deadline is
    # computed from: an incident is usually entered some hours after it was
    # noticed, and starting the 24-hour clock at data-entry time would report a
    # deadline later than the law allows.
    detected_at: Optional[datetime] = None
    status: str = Field(default="detected", pattern=INCIDENT_STATUS_PATTERN)
    impact_category: str = "availability"
    estimated_impact_level: int = Field(3, ge=1, le=5)
    affected_systems: Optional[str] = None
    users_affected_count: Optional[int] = Field(None, ge=0)
    cross_border: bool = False
    supply_chain_impact: bool = False


class IncidentPatchRequest(BaseModel):
    title: Optional[str] = None
    incident_type: Optional[str] = Field(None, pattern=INCIDENT_TYPE_PATTERN)
    severity: Optional[str] = Field(None, pattern=INCIDENT_SEVERITY_PATTERN)
    description: Optional[str] = None
    status: Optional[str] = Field(None, pattern=INCIDENT_STATUS_PATTERN)
    impact_category: Optional[str] = None
    estimated_impact_level: Optional[int] = Field(None, ge=1, le=5)
    affected_systems: Optional[str] = None
    users_affected_count: Optional[int] = Field(None, ge=0)
    cross_border: Optional[bool] = None
    supply_chain_impact: Optional[bool] = None
    containment_actions: Optional[str] = None
    lessons_learned: Optional[str] = None
    csirt_reference_id: Optional[str] = None


@router.post(
    "",
    response_model=IncidentMonitorResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin", "auditor"))],
)
async def declare_incident(
    payload: IncidentCreateRequest,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> IncidentMonitorResponse:
    """Open an incident and start its Art. 23 clocks."""
    user, membership = current_org
    now = datetime.now(timezone.utc)
    detected_at = payload.detected_at or now
    if detected_at.tzinfo is None:
        detected_at = detected_at.replace(tzinfo=timezone.utc)

    incident = Incident(
        organization_id=membership.organization_id,
        reported_by=user.id,
        title=payload.title,
        incident_type=payload.incident_type,
        severity=payload.severity,
        status=payload.status,
        detected_at=detected_at,
        early_warning_deadline=detected_at + _EARLY_WARNING_WINDOW,
        notification_deadline=detected_at + _NOTIFICATION_WINDOW,
        final_report_deadline=final_report_deadline_for(detected_at),
        description=payload.description,
        impact_category=payload.impact_category,
        estimated_impact_level=payload.estimated_impact_level,
        affected_systems=payload.affected_systems,
        users_affected_count=payload.users_affected_count,
        cross_border=payload.cross_border,
        supply_chain_impact=payload.supply_chain_impact,
    )
    db.add(incident)
    await db.flush()
    await db.refresh(incident)
    return _to_response(incident, now)


@router.patch(
    "/{incident_id}",
    response_model=IncidentMonitorResponse,
    dependencies=[Depends(require_role("admin", "auditor"))],
)
async def update_incident_lifecycle(
    incident_id: uuid.UUID,
    payload: IncidentPatchRequest,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> IncidentMonitorResponse:
    """Revise an incident. Deadlines are not recomputed.

    `detected_at` is deliberately absent from the patch schema: the three
    deadlines are stored at declaration time, and letting a later edit move them
    would change an obligation an operator may already have acted on. A genuinely
    wrong detection time is a delete-and-redeclare, which leaves an audit trail.
    """
    user, membership = current_org
    incident = await db.get(Incident, incident_id)
    if not incident or incident.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Incident not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)
    await db.flush()
    # updated_at carries onupdate=func.now(); without the refresh, pydantic
    # reads the expired attribute and raises MissingGreenlet.
    await db.refresh(incident)
    return _to_response(incident, datetime.now(timezone.utc))


@router.delete(
    "/{incident_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role("admin"))],
)
async def delete_incident(
    incident_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    user, membership = current_org
    incident = await db.get(Incident, incident_id)
    if not incident or incident.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    await db.delete(incident)


# ---------------------------------------------------------------------------
# Recording that an obligation was discharged
# ---------------------------------------------------------------------------

# `early_warning_sent_at`, `notification_sent_at` and `final_report_sent_at`
# were read everywhere and written nowhere. The Celery task reads them to decide
# whether an obligation is still outstanding, `_to_response` reads them, and the
# dashboard renders a "submitted" state from them — but no code path in the
# application ever set one. So the alerting could not be switched off by doing
# the thing it was alerting about: an operator who submitted the Early Warning
# to CSIRT Italia on time kept receiving breach alerts for it, daily, forever,
# and the only escape was closing the incident or deleting the row.
#
# Submission to CSIRT Italia is a manual step outside this platform — there is
# no API to submit to — so the platform cannot observe it happening. What it
# can do is let the operator record it, attributed and audited, which is also
# the artefact an auditor asks for: who declared the obligation discharged, and
# when.

_OBLIGATIONS = {
    "early_warning": ("early_warning_sent_at", "early_warning_deadline"),
    "notification": ("notification_sent_at", "notification_deadline"),
    "final_report": ("final_report_sent_at", "final_report_deadline"),
}


class RecordSubmissionRequest(BaseModel):
    obligation: str = Field(..., description="early_warning | notification | final_report")
    # Defaults to now, but the submission usually happened before someone got
    # round to recording it, and the recorded time is what an auditor reads.
    submitted_at: Optional[datetime] = None
    # CSIRT Italia returns a reference on submission; it is the only evidence
    # tying this row to the actual filing.
    csirt_reference_id: Optional[str] = Field(None, max_length=255)


@router.post(
    "/{incident_id}/submissions",
    response_model=IncidentMonitorResponse,
    # Admin only, following the precedent already set by assets.attest_authority
    # ("asserting authority over an address range is not an auditor action").
    # Recording that an Art. 23 notification was filed with CSIRT Italia on a
    # given date is an attestation about a legal act performed outside this
    # platform, not compliance work — and it is precisely the record an auditor
    # would later be examining. Everything else in the Art. 23 module stays open
    # to the auditor role.
    dependencies=[Depends(require_role("admin"))],
)
async def record_submission(
    incident_id: uuid.UUID,
    payload: RecordSubmissionRequest,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> IncidentMonitorResponse:
    """Record that an Art. 23 obligation was submitted to the CSIRT."""
    user, membership = current_org
    now = datetime.now(timezone.utc)

    incident = await db.get(Incident, incident_id)
    if not incident or incident.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Incident not found")

    if payload.obligation not in _OBLIGATIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown obligation. Expected one of: {', '.join(_OBLIGATIONS)}",
        )

    sent_field, _ = _OBLIGATIONS[payload.obligation]
    submitted_at = payload.submitted_at or now
    if submitted_at.tzinfo is None:
        submitted_at = submitted_at.replace(tzinfo=timezone.utc)
    # A submission recorded in the future is a typo, and it would silently
    # suppress the alerting until that date arrives.
    if submitted_at > now:
        raise HTTPException(
            status_code=422, detail="submitted_at cannot be in the future"
        )
    if submitted_at < incident.detected_at:
        raise HTTPException(
            status_code=422,
            detail="submitted_at cannot precede the recorded detection time",
        )

    setattr(incident, sent_field, submitted_at)
    if payload.csirt_reference_id:
        incident.csirt_reference_id = payload.csirt_reference_id

    # Art. 23(4)(d) anchors the final report on the actual submission of the
    # notification, so recording that submission fixes the anchor. Only while
    # the final report is itself still outstanding: moving a deadline that has
    # already been discharged would rewrite history.
    if payload.obligation == "notification" and incident.final_report_sent_at is None:
        incident.final_report_deadline = final_report_deadline_for(
            incident.detected_at, submitted_at
        )

    await db.flush()
    await db.refresh(incident)
    return _to_response(incident, now)
