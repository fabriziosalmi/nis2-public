# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
NIS2 Governance Checklist API.
Ports the legacy GovernanceEngine (nis2_checker/governance_engine.py) to a
first-class SaaS feature with DB persistence and per-org tracking.
"""
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, String, Text, Integer
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, get_db
from app.dependencies import get_current_org
from app.models.base import TimestampMixin
from app.models.membership import Membership
from app.models.user import User

# --- Model ---

class GovernanceItem(TimestampMixin, Base):
    __tablename__ = "governance_items"
    organization_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    item_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g. G-01
    priority: Mapped[str] = mapped_column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    nis2_reference: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="not_started")
    assigned_to_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    evidence_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

# --- Schemas ---

class GovernanceItemResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    item_id: str
    priority: str
    title: str
    description: str
    nis2_reference: str
    status: str
    assigned_to_name: Optional[str] = None
    evidence_notes: Optional[str] = None
    sort_order: int
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class GovernanceItemUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(not_started|in_progress|done|not_applicable)$")
    assigned_to_name: Optional[str] = None
    evidence_notes: Optional[str] = None

class GovernanceListResponse(BaseModel):
    items: list[GovernanceItemResponse]
    total: int
    stats: dict

class GovernanceSeedResponse(BaseModel):
    created: int
    message: str

# --- Checklist Template ---

CHECKLIST_TEMPLATE = [
    # CRITICAL
    ("G-01", "CRITICAL", "Scoping Analysis", "Confirm if entity is Essential or Important under D.Lgs 138/2024.", "Art. 3, D.Lgs 138/2024"),
    ("G-02", "CRITICAL", "ACN Portal Registration", "Register on the National Cybersecurity Agency portal.", "Art. 7, D.Lgs 138/2024"),
    ("G-03", "CRITICAL", "Board Responsibility", "Board/Directors formally assume cybersecurity responsibility.", "Art. 21.2, NIS2"),
    ("G-04", "CRITICAL", "Management Training", "Governing bodies attend mandatory cybersecurity training.", "Art. 20.2, NIS2"),
    ("G-05", "CRITICAL", "MFA on Remote Access", "MFA active on all VPN, Cloud, and privileged accounts.", "Art. 21.2.j, NIS2"),
    ("G-06", "CRITICAL", "Immutable/Offline Backups", "Critical data copy disconnected or immutable (anti-ransomware).", "Art. 21.2.c, NIS2"),
    ("G-07", "CRITICAL", "Incident Notification Procedure", "Written procedure: who notifies CSIRT within 24h.", "Art. 23, NIS2"),
    ("G-08", "CRITICAL", "Asset Inventory", "Updated list of all hardware, software, and data assets.", "Art. 21.2.i, NIS2"),
    ("G-09", "CRITICAL", "Vulnerability Management", "Critical patches installed within 48-72h from release.", "Art. 21.2.e, NIS2"),
    ("G-10", "CRITICAL", "Cybersecurity Budget", "Specific and adequate budget allocated for NIS2 compliance.", "Art. 20, NIS2"),
    # HIGH
    ("G-11", "HIGH", "Risk Assessment", "Formal cyber risk analysis on all critical assets.", "Art. 21.2.a, NIS2"),
    ("G-12", "HIGH", "Information Security Policy", "Approved master document dictating corporate security rules.", "Art. 21.2.a, NIS2"),
    ("G-13", "HIGH", "Supplier Mapping", "List of critical suppliers (MSP, Software, Cloud).", "Art. 21.2.d, NIS2"),
    ("G-14", "HIGH", "Supply Chain Security", "Security requirements and notification clauses in supplier contracts.", "Art. 21.2.d, NIS2"),
    ("G-15", "HIGH", "Incident Response Plan", "Technical plan to contain and eradicate attacks.", "Art. 21.2.b, NIS2"),
    ("G-16", "HIGH", "Business Continuity Plan", "Procedures to continue operations if IT is down.", "Art. 21.2.c, NIS2"),
    ("G-17", "HIGH", "Disaster Recovery Plan", "IT system restoration after disaster, defined and tested.", "Art. 21.2.c, NIS2"),
    ("G-18", "HIGH", "Employee Awareness Training", "Continuous anti-phishing training for all staff.", "Art. 21.2.f, NIS2"),
    ("G-19", "HIGH", "Backup Testing", "Data restoration test performed at least every 6 months.", "Art. 21.2.c, NIS2"),
    ("G-20", "HIGH", "Access Control (Least Privilege)", "Employees have only permissions strictly necessary.", "Art. 21.2.i, NIS2"),
    # MEDIUM
    ("G-21", "MEDIUM", "Network Segmentation", "Production/OT network separated from office/guest.", "Art. 21.2.e, NIS2"),
    ("G-22", "MEDIUM", "Onboarding/Offboarding", "Automatic access revocation when employees leave.", "Art. 21.2.i, NIS2"),
    ("G-23", "MEDIUM", "Encryption at Rest", "Sensitive data encrypted when stored.", "Art. 21.2.g, NIS2"),
    ("G-24", "MEDIUM", "Cryptographic Key Management", "Keys managed securely and separated from data.", "Art. 21.2.g, NIS2"),
    ("G-25", "MEDIUM", "Logging and Monitoring", "System logs collected centrally and analyzed.", "Art. 21.2.e, NIS2"),
    ("G-26", "MEDIUM", "Security in Acquisition", "Security requirements evaluated before buying/developing software.", "Art. 21.2.e, NIS2"),
    ("G-27", "MEDIUM", "Secure Emergency Communications", "Secure systems for emergency comms if email is down.", "Art. 21.2.j, NIS2"),
    ("G-28", "MEDIUM", "Internal Audits", "Periodic checks planned to verify procedure compliance.", "Art. 21, NIS2"),
    ("G-29", "MEDIUM", "VA/Pen Test", "Technical vulnerability scan performed at least annually.", "Art. 21.2.e, NIS2"),
    ("G-30", "MEDIUM", "End-to-End Encryption", "Advanced measures for protecting confidential communications.", "Art. 21.2.g, NIS2"),
]

# --- Router ---

router = APIRouter(prefix="/governance", tags=["governance"])

@router.get("", response_model=GovernanceListResponse)
async def list_governance_items(
    priority: Optional[str] = Query(None, pattern="^(CRITICAL|HIGH|MEDIUM)$"),
    status_filter: Optional[str] = Query(None, alias="status"),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> GovernanceListResponse:
    """List all governance checklist items for the organization."""
    user, membership = current_org
    org_id = membership.organization_id
    query = select(GovernanceItem).where(GovernanceItem.organization_id == org_id)
    if priority:
        query = query.where(GovernanceItem.priority == priority)
    if status_filter:
        query = query.where(GovernanceItem.status == status_filter)
    query = query.order_by(GovernanceItem.sort_order)
    result = await db.execute(query)
    items = result.scalars().all()

    # Compute stats
    total = len(items)
    done = sum(1 for i in items if i.status == "done")
    in_progress = sum(1 for i in items if i.status == "in_progress")
    not_started = sum(1 for i in items if i.status == "not_started")
    stats = {
        "total": total,
        "done": done,
        "in_progress": in_progress,
        "not_started": not_started,
        "completion_pct": round((done / total) * 100, 1) if total > 0 else 0,
    }
    return GovernanceListResponse(
        items=[GovernanceItemResponse.model_validate(i) for i in items],
        total=total, stats=stats,
    )

@router.post("/seed", response_model=GovernanceSeedResponse)
async def seed_governance(
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> GovernanceSeedResponse:
    """Initialize the 30-item governance checklist for this organization."""
    user, membership = current_org
    if membership.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can seed governance checklist")
    org_id = membership.organization_id

    # Check if already seeded
    existing = await db.execute(
        select(func.count(GovernanceItem.id)).where(GovernanceItem.organization_id == org_id)
    )
    if (existing.scalar() or 0) > 0:
        raise HTTPException(status_code=400, detail="Governance checklist already initialized. Use PATCH to update items.")

    for idx, (item_id, priority, title, description, ref) in enumerate(CHECKLIST_TEMPLATE):
        item = GovernanceItem(
            organization_id=org_id,
            item_id=item_id,
            priority=priority,
            title=title,
            description=description,
            nis2_reference=ref,
            status="not_started",
            sort_order=idx,
        )
        db.add(item)
    await db.flush()
    return GovernanceSeedResponse(created=len(CHECKLIST_TEMPLATE), message="30 governance items created")

@router.patch("/{item_id}", response_model=GovernanceItemResponse)
async def update_governance_item(
    item_id: uuid.UUID,
    payload: GovernanceItemUpdate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> GovernanceItemResponse:
    """Update a governance item's status, assignee, or evidence."""
    user, membership = current_org
    item = await db.get(GovernanceItem, item_id)
    if not item or item.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Governance item not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(item, field, value)
    await db.flush()
    return GovernanceItemResponse.model_validate(item)

@router.post("/bulk-update")
async def bulk_update_governance(
    updates: list[dict],
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Bulk update multiple governance items at once."""
    user, membership = current_org
    org_id = membership.organization_id
    updated = 0
    for upd in updates:
        gid = upd.get("id")
        if not gid:
            continue
        item = await db.get(GovernanceItem, uuid.UUID(gid))
        if not item or item.organization_id != org_id:
            continue
        for field in ("status", "assigned_to_name", "evidence_notes"):
            if field in upd:
                setattr(item, field, upd[field])
        updated += 1
    await db.flush()
    return {"updated": updated}

@router.get("/score")
async def governance_score(
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Calculate governance compliance score (0-100) with weighted priorities."""
    user, membership = current_org
    org_id = membership.organization_id
    result = await db.execute(
        select(GovernanceItem).where(GovernanceItem.organization_id == org_id)
    )
    items = result.scalars().all()
    if not items:
        return {"score": 0, "message": "No governance items. Call POST /governance/seed first."}

    weights = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0}
    total_weight = sum(weights.get(i.priority, 1.0) for i in items)
    earned = sum(weights.get(i.priority, 1.0) for i in items if i.status == "done")
    partial = sum(weights.get(i.priority, 1.0) * 0.5 for i in items if i.status == "in_progress")
    score = round(((earned + partial) / total_weight) * 100, 1) if total_weight > 0 else 0

    by_priority = {}
    for p in ("CRITICAL", "HIGH", "MEDIUM"):
        p_items = [i for i in items if i.priority == p]
        done = sum(1 for i in p_items if i.status == "done")
        by_priority[p] = {"total": len(p_items), "done": done, "pct": round((done / len(p_items)) * 100, 1) if p_items else 0}

    return {"score": score, "by_priority": by_priority, "total_items": len(items)}
