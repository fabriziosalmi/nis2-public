# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
NIS2 Governance Checklist API — DB-persisted, per-organization tracking
of the 30-item checklist cross-referenced to NIS2 Art. 21 sub-paragraphs.

The `subparagraph` field is a machine-readable enum carrying the
sub-paragraph each item maps to. Items that do not derive from
Art. 21.2 (e.g. Art. 7 ACN registration, Art. 23 incident reporting,
Art. 20 board/training) are tagged accordingly.
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

# Art. 21.2 sub-paragraphs (a)-(j) and the few sibling articles the
# checklist also touches. Used as a constrained vocabulary on
# GovernanceItem.subparagraph and surfaced via /governance/by-subparagraph.
SUBPARAGRAPHS: dict[str, str] = {
    "21.2.a": "Risk analysis and information system security policies",
    "21.2.b": "Incident handling",
    "21.2.c": "Business continuity, backup, disaster recovery, crisis management",
    "21.2.d": "Supply chain security",
    "21.2.e": "Security in network and information systems acquisition, development and maintenance",
    "21.2.f": "Policies and procedures to assess effectiveness of risk management measures",
    "21.2.g": "Basic cyber hygiene practices and cybersecurity training",
    "21.2.h": "Cryptography and, where appropriate, encryption",
    "21.2.i": "Human resources security, access control policies and asset management",
    "21.2.j": "MFA, secured voice/video/text communications and secured emergency communications",
    "20":     "Governance — board responsibility and management training (Art. 20)",
    "23":     "Incident reporting to the CSIRT (Art. 23)",
    "7":      "ACN portal registration (Art. 7, D.Lgs 138/2024)",
    "3":      "Scope determination — Essential vs Important (Art. 3, D.Lgs 138/2024)",
}


# --- Model ---

class GovernanceItem(TimestampMixin, Base):
    __tablename__ = "governance_items"
    organization_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    item_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g. G-01
    priority: Mapped[str] = mapped_column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    nis2_reference: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    # Machine-readable Art. 21.2 sub-paragraph (or sibling article) tag.
    # Indexed for cheap GROUP BY queries in /by-subparagraph.
    subparagraph: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, index=True)
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
    subparagraph: Optional[str] = None
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

# Each row is (item_id, priority, title, description, nis2_reference, subparagraph).
# `subparagraph` keys are validated against SUBPARAGRAPHS at module load time.
# The earlier table double-tagged a few items inconsistently (e.g. encryption
# items were tagged 21.2.g instead of the cryptography sub-paragraph 21.2.h);
# this version is the corrected machine-readable mapping.
CHECKLIST_TEMPLATE = [
    # CRITICAL
    ("G-01", "CRITICAL", "Scoping Analysis", "Confirm if entity is Essential or Important under D.Lgs 138/2024.", "Art. 3, D.Lgs 138/2024", "3"),
    ("G-02", "CRITICAL", "ACN Portal Registration", "Register on the National Cybersecurity Agency portal.", "Art. 7, D.Lgs 138/2024", "7"),
    ("G-03", "CRITICAL", "Board Responsibility", "Board/Directors formally assume cybersecurity responsibility.", "Art. 20, NIS2", "20"),
    ("G-04", "CRITICAL", "Management Training", "Governing bodies attend mandatory cybersecurity training.", "Art. 20.2, NIS2", "20"),
    ("G-05", "CRITICAL", "MFA on Remote Access", "MFA active on all VPN, Cloud, and privileged accounts.", "Art. 21.2.j, NIS2", "21.2.j"),
    ("G-06", "CRITICAL", "Immutable/Offline Backups", "Critical data copy disconnected or immutable (anti-ransomware).", "Art. 21.2.c, NIS2", "21.2.c"),
    ("G-07", "CRITICAL", "Incident Notification Procedure", "Written procedure: who notifies CSIRT within 24h.", "Art. 23, NIS2", "23"),
    ("G-08", "CRITICAL", "Asset Inventory", "Updated list of all hardware, software, and data assets.", "Art. 21.2.i, NIS2", "21.2.i"),
    ("G-09", "CRITICAL", "Vulnerability Management", "Critical patches installed within 48-72h from release.", "Art. 21.2.e, NIS2", "21.2.e"),
    ("G-10", "CRITICAL", "Cybersecurity Budget", "Specific and adequate budget allocated for NIS2 compliance.", "Art. 20, NIS2", "20"),
    # HIGH
    ("G-11", "HIGH", "Risk Assessment", "Formal cyber risk analysis on all critical assets.", "Art. 21.2.a, NIS2", "21.2.a"),
    ("G-12", "HIGH", "Information Security Policy", "Approved master document dictating corporate security rules.", "Art. 21.2.a, NIS2", "21.2.a"),
    ("G-13", "HIGH", "Supplier Mapping", "List of critical suppliers (MSP, Software, Cloud).", "Art. 21.2.d, NIS2", "21.2.d"),
    ("G-14", "HIGH", "Supply Chain Security", "Security requirements and notification clauses in supplier contracts.", "Art. 21.2.d, NIS2", "21.2.d"),
    ("G-15", "HIGH", "Incident Response Plan", "Technical plan to contain and eradicate attacks.", "Art. 21.2.b, NIS2", "21.2.b"),
    ("G-16", "HIGH", "Business Continuity Plan", "Procedures to continue operations if IT is down.", "Art. 21.2.c, NIS2", "21.2.c"),
    ("G-17", "HIGH", "Disaster Recovery Plan", "IT system restoration after disaster, defined and tested.", "Art. 21.2.c, NIS2", "21.2.c"),
    ("G-18", "HIGH", "Employee Awareness Training", "Continuous anti-phishing training for all staff.", "Art. 21.2.g, NIS2", "21.2.g"),
    ("G-19", "HIGH", "Backup Testing", "Data restoration test performed at least every 6 months.", "Art. 21.2.c, NIS2", "21.2.c"),
    ("G-20", "HIGH", "Access Control (Least Privilege)", "Employees have only permissions strictly necessary.", "Art. 21.2.i, NIS2", "21.2.i"),
    # MEDIUM
    ("G-21", "MEDIUM", "Network Segmentation", "Production/OT network separated from office/guest.", "Art. 21.2.e, NIS2", "21.2.e"),
    ("G-22", "MEDIUM", "Onboarding/Offboarding", "Automatic access revocation when employees leave.", "Art. 21.2.i, NIS2", "21.2.i"),
    ("G-23", "MEDIUM", "Encryption at Rest", "Sensitive data encrypted when stored.", "Art. 21.2.h, NIS2", "21.2.h"),
    ("G-24", "MEDIUM", "Cryptographic Key Management", "Keys managed securely and separated from data.", "Art. 21.2.h, NIS2", "21.2.h"),
    ("G-25", "MEDIUM", "Logging and Monitoring", "System logs collected centrally and analyzed.", "Art. 21.2.f, NIS2", "21.2.f"),
    ("G-26", "MEDIUM", "Security in Acquisition", "Security requirements evaluated before buying/developing software.", "Art. 21.2.e, NIS2", "21.2.e"),
    ("G-27", "MEDIUM", "Secure Emergency Communications", "Secure systems for emergency comms if email is down.", "Art. 21.2.j, NIS2", "21.2.j"),
    ("G-28", "MEDIUM", "Internal Audits", "Periodic checks planned to verify procedure compliance.", "Art. 21.2.f, NIS2", "21.2.f"),
    ("G-29", "MEDIUM", "VA/Pen Test", "Technical vulnerability scan performed at least annually.", "Art. 21.2.f, NIS2", "21.2.f"),
    ("G-30", "MEDIUM", "End-to-End Encryption", "Advanced measures for protecting confidential communications.", "Art. 21.2.h, NIS2", "21.2.h"),
]

# Fail at import time if anyone adds an item with an unknown subparagraph code.
for _row in CHECKLIST_TEMPLATE:
    _sp = _row[5]
    if _sp not in SUBPARAGRAPHS:
        raise RuntimeError(
            f"governance: unknown subparagraph '{_sp}' on item {_row[0]}; "
            f"add it to SUBPARAGRAPHS or correct the tag."
        )

# --- Router ---

router = APIRouter(prefix="/governance", tags=["governance"])

@router.get("", response_model=GovernanceListResponse)
async def list_governance_items(
    priority: Optional[str] = Query(None, pattern="^(CRITICAL|HIGH|MEDIUM)$"),
    status_filter: Optional[str] = Query(None, alias="status"),
    subparagraph: Optional[str] = Query(None, description="e.g. 21.2.a"),
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
    if subparagraph:
        if subparagraph not in SUBPARAGRAPHS:
            raise HTTPException(status_code=400, detail=f"Unknown subparagraph: {subparagraph}")
        query = query.where(GovernanceItem.subparagraph == subparagraph)
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

    for idx, (item_id, priority, title, description, ref, subpara) in enumerate(CHECKLIST_TEMPLATE):
        item = GovernanceItem(
            organization_id=org_id,
            item_id=item_id,
            priority=priority,
            title=title,
            description=description,
            nis2_reference=ref,
            subparagraph=subpara,
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


@router.get("/by-subparagraph")
async def governance_by_subparagraph(
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Group governance items by NIS2 sub-paragraph.

    Returns one entry per (a)-(j) plus the sibling articles (Art. 3, 7, 20, 23).
    Each entry reports total/done/pct so a CISO can see which Art. 21
    sub-paragraphs are still uncovered without parsing free-text refs.
    """
    user, membership = current_org
    org_id = membership.organization_id

    result = await db.execute(
        select(GovernanceItem).where(GovernanceItem.organization_id == org_id)
    )
    items = result.scalars().all()

    by_sp: dict[str, dict] = {}
    for sp_code, sp_label in SUBPARAGRAPHS.items():
        sp_items = [i for i in items if i.subparagraph == sp_code]
        done = sum(1 for i in sp_items if i.status == "done")
        in_progress = sum(1 for i in sp_items if i.status == "in_progress")
        by_sp[sp_code] = {
            "label": sp_label,
            "total": len(sp_items),
            "done": done,
            "in_progress": in_progress,
            "not_started": len(sp_items) - done - in_progress,
            "pct": round((done / len(sp_items)) * 100, 1) if sp_items else 0,
            "item_ids": sorted(i.item_id for i in sp_items),
        }

    untagged = [i for i in items if not i.subparagraph]
    return {
        "by_subparagraph": by_sp,
        "untagged": [{"item_id": i.item_id, "title": i.title} for i in untagged],
        "total_items": len(items),
    }


@router.get("/subparagraphs")
async def list_subparagraphs():
    """Public catalogue of recognised NIS2 sub-paragraphs and sibling articles.

    Useful for the frontend to render the (a)-(j) navigator and to validate
    user-supplied filters before calling the list endpoint.
    """
    return {"subparagraphs": SUBPARAGRAPHS}
