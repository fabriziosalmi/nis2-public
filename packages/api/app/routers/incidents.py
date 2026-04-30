# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
NIS2 Art. 23 Incident Reporting API.
Replaces the legacy CLI-based IncidentReporter with a REST API.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, String, Text, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, get_db
from app.dependencies import get_current_org
from app.models.base import TimestampMixin
from app.models.membership import Membership
from app.models.user import User

# --- Model ---

class IncidentReport(TimestampMixin, Base):
    __tablename__ = "incident_reports"
    organization_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    created_by: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    entity_name: Mapped[str] = mapped_column(String(256), nullable=False)
    entity_sector: Mapped[str] = mapped_column(String(128), nullable=False)
    contact_email: Mapped[str] = mapped_column(String(256), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    incident_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(100), nullable=False)
    incident_status: Mapped[str] = mapped_column(String(50), nullable=False, default="ongoing")
    detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    affected_users: Mapped[Optional[int]] = mapped_column(nullable=True)
    cross_border: Mapped[bool] = mapped_column(default=False, nullable=False)
    submission_status: Mapped[str] = mapped_column(String(50), nullable=False, default="draft")
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    report_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

# --- Schemas ---

INCIDENT_TYPES = ["DoS/DDoS", "Malware/Ransomware", "Phishing/Social Engineering",
    "Data Leak/Breach", "System Compromise", "Unavailability (Hardware/Software Failure)", "Other"]
SEVERITY_LEVELS = ["Low", "Significant", "Critical"]

class IncidentCreate(BaseModel):
    entity_name: str = Field(..., min_length=1, max_length=256)
    entity_sector: str = Field(..., min_length=1, max_length=128)
    contact_email: str = Field(..., min_length=3, max_length=256)
    title: str = Field(..., min_length=1, max_length=512)
    incident_type: str
    severity: str
    incident_status: str = "ongoing"
    detected_at: Optional[datetime] = None
    description: str = Field(..., min_length=1)
    affected_users: Optional[int] = Field(None, ge=0)
    cross_border: bool = False

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    incident_type: Optional[str] = None
    severity: Optional[str] = None
    incident_status: Optional[str] = None
    description: Optional[str] = None
    affected_users: Optional[int] = None
    cross_border: Optional[bool] = None
    submission_status: Optional[str] = None

class IncidentResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    created_by: uuid.UUID
    entity_name: str
    entity_sector: str
    contact_email: str
    title: str
    incident_type: str
    severity: str
    incident_status: str
    detected_at: Optional[datetime] = None
    description: str
    affected_users: Optional[int] = None
    cross_border: bool
    submission_status: str
    submitted_at: Optional[datetime] = None
    report_data: Optional[dict] = None
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class IncidentListResponse(BaseModel):
    items: list[IncidentResponse]
    total: int
    page: int
    page_size: int

# --- Router ---

router = APIRouter(prefix="/incidents", tags=["incidents"])

@router.get("/taxonomy")
async def get_taxonomy():
    """Return NIS2 incident taxonomy for form dropdowns."""
    return {
        "incident_types": INCIDENT_TYPES,
        "severity_levels": SEVERITY_LEVELS,
        "incident_statuses": ["ongoing", "contained", "recovered"],
        "references": {
            "nis2_article": "Art. 23 — Reporting obligations",
            "early_warning": "24h from detection",
            "incident_notification": "72h from detection",
            "final_report": "1 month from notification",
        },
    }

@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    submission_status: Optional[str] = Query(None),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> IncidentListResponse:
    user, membership = current_org
    org_id = membership.organization_id
    query = select(IncidentReport).where(IncidentReport.organization_id == org_id)
    count_q = select(func.count(IncidentReport.id)).where(IncidentReport.organization_id == org_id)
    if submission_status:
        query = query.where(IncidentReport.submission_status == submission_status)
        count_q = count_q.where(IncidentReport.submission_status == submission_status)
    query = query.order_by(IncidentReport.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    total = (await db.execute(count_q)).scalar() or 0
    incidents = (await db.execute(query)).scalars().all()
    return IncidentListResponse(
        items=[IncidentResponse.model_validate(i) for i in incidents],
        total=total, page=page, page_size=page_size,
    )

@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: IncidentCreate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    user, membership = current_org
    incident = IncidentReport(
        organization_id=membership.organization_id,
        created_by=user.id,
        entity_name=payload.entity_name,
        entity_sector=payload.entity_sector,
        contact_email=payload.contact_email,
        title=payload.title,
        incident_type=payload.incident_type,
        severity=payload.severity,
        incident_status=payload.incident_status,
        detected_at=payload.detected_at or datetime.now(timezone.utc),
        description=payload.description,
        affected_users=payload.affected_users,
        cross_border=payload.cross_border,
        submission_status="draft",
        report_data=_build_payload(payload),
    )
    db.add(incident)
    await db.flush()
    return IncidentResponse.model_validate(incident)

@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    user, membership = current_org
    incident = await db.get(IncidentReport, incident_id)
    if not incident or incident.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Incident report not found")
    return IncidentResponse.model_validate(incident)

@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    user, membership = current_org
    incident = await db.get(IncidentReport, incident_id)
    if not incident or incident.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Incident report not found")
    if incident.submission_status == "submitted":
        raise HTTPException(status_code=400, detail="Cannot modify a submitted report")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)
    if payload.submission_status == "submitted":
        incident.submitted_at = datetime.now(timezone.utc)
    incident.report_data = _build_payload_from_model(incident)
    await db.flush()
    return IncidentResponse.model_validate(incident)

@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(
    incident_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    user, membership = current_org
    if membership.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete incident reports")
    incident = await db.get(IncidentReport, incident_id)
    if not incident or incident.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Incident report not found")
    if incident.submission_status == "submitted":
        raise HTTPException(status_code=400, detail="Cannot delete a submitted report")
    await db.delete(incident)
    await db.flush()

@router.post("/{incident_id}/export")
async def export_incident(
    incident_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Export incident report as structured JSON for CSIRT submission."""
    user, membership = current_org
    incident = await db.get(IncidentReport, incident_id)
    if not incident or incident.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Incident report not found")
    return {"format": "CSIRT_NIS2_Art23", "version": "2.2", "payload": incident.report_data or _build_payload_from_model(incident)}

# --- Helpers ---

def _build_payload(p: IncidentCreate) -> dict:
    return {
        "meta": {"generated_at": datetime.now(timezone.utc).isoformat(), "generator": "NIS2 Compliance Platform", "version": "2.2"},
        "entity": {"name": p.entity_name, "sector": p.entity_sector, "contact": p.contact_email},
        "incident": {"title": p.title, "type": p.incident_type, "severity": p.severity, "status": p.incident_status,
                      "detected_at": (p.detected_at or datetime.now(timezone.utc)).isoformat(), "description": p.description},
        "impact": {"affected_users": p.affected_users, "cross_border": p.cross_border},
        "timeline": {"early_warning_deadline": "24h from detection (Art. 23.4.a)",
                      "notification_deadline": "72h from detection (Art. 23.4.b)",
                      "final_report_deadline": "1 month from notification (Art. 23.4.d)"},
    }

def _build_payload_from_model(i: IncidentReport) -> dict:
    return {
        "meta": {"generated_at": datetime.now(timezone.utc).isoformat(), "generator": "NIS2 Compliance Platform",
                 "version": "2.2", "report_id": str(i.id)},
        "entity": {"name": i.entity_name, "sector": i.entity_sector, "contact": i.contact_email},
        "incident": {"title": i.title, "type": i.incident_type, "severity": i.severity, "status": i.incident_status,
                      "detected_at": i.detected_at.isoformat() if i.detected_at else None, "description": i.description},
        "impact": {"affected_users": i.affected_users, "cross_border": i.cross_border},
        "timeline": {"early_warning_deadline": "24h from detection (Art. 23.4.a)",
                      "notification_deadline": "72h from detection (Art. 23.4.b)",
                      "final_report_deadline": "1 month from notification (Art. 23.4.d)"},
        "submission": {"status": i.submission_status, "submitted_at": i.submitted_at.isoformat() if i.submitted_at else None},
    }
