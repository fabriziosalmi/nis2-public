# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, String, Text, Integer
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, get_db
from app.dependencies import get_current_org, require_role
from app.models.base import TimestampMixin
from app.models.finding import Finding
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
    "20": "Governance — board responsibility and management training (Art. 20)",
    "23": "Incident reporting to the CSIRT (Art. 23)",
    "7": "ACN portal registration (Art. 7, D.Lgs 138/2024)",
    "3": "Scope determination — Essential vs Important (Art. 3, D.Lgs 138/2024)",
}


# --- Model ---


class GovernanceItem(TimestampMixin, Base):
    __tablename__ = "governance_items"
    organization_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), nullable=False, index=True
    )
    item_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g. G-01
    priority: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # CRITICAL, HIGH, MEDIUM
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    nis2_reference: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    # Machine-readable Art. 21.2 sub-paragraph (or sibling article) tag.
    # Indexed for cheap GROUP BY queries in /by-subparagraph.
    subparagraph: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="not_started"
    )
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
    status: Optional[str] = Field(
        None, pattern="^(not_started|in_progress|done|not_applicable)$"
    )
    assigned_to_name: Optional[str] = None
    evidence_notes: Optional[str] = None


class GovernanceBulkUpdateItem(BaseModel):
    """v2.5.6 security fix: typed schema replacing raw list[dict].
    Validates UUID, constrains status to valid values, limits field lengths."""

    id: uuid.UUID
    status: Optional[str] = Field(
        None, pattern="^(not_started|in_progress|done|not_applicable)$"
    )
    assigned_to_name: Optional[str] = Field(None, max_length=256)
    evidence_notes: Optional[str] = Field(None, max_length=10000)


class GovernanceBulkUpdateRequest(BaseModel):
    """Wrapper with max batch size to prevent abuse."""

    items: list[GovernanceBulkUpdateItem] = Field(..., max_length=100)


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
    (
        "G-01",
        "CRITICAL",
        "Scoping Analysis",
        "Confirm if entity is Essential or Important under D.Lgs 138/2024.",
        "Art. 3, D.Lgs 138/2024",
        "3",
    ),
    (
        "G-02",
        "CRITICAL",
        "ACN Portal Registration",
        "Register on the National Cybersecurity Agency portal.",
        "Art. 7, D.Lgs 138/2024",
        "7",
    ),
    (
        "G-03",
        "CRITICAL",
        "Board Responsibility",
        "Board/Directors formally assume cybersecurity responsibility.",
        "Art. 20, NIS2",
        "20",
    ),
    (
        "G-04",
        "CRITICAL",
        "Management Training",
        "Governing bodies attend mandatory cybersecurity training.",
        "Art. 20.2, NIS2",
        "20",
    ),
    (
        "G-05",
        "CRITICAL",
        "MFA on Remote Access",
        "MFA active on all VPN, Cloud, and privileged accounts.",
        "Art. 21.2.j, NIS2",
        "21.2.j",
    ),
    (
        "G-06",
        "CRITICAL",
        "Immutable/Offline Backups",
        "Critical data copy disconnected or immutable (anti-ransomware).",
        "Art. 21.2.c, NIS2",
        "21.2.c",
    ),
    (
        "G-07",
        "CRITICAL",
        "Incident Notification Procedure",
        "Written procedure: who notifies CSIRT within 24h.",
        "Art. 23, NIS2",
        "23",
    ),
    (
        "G-08",
        "CRITICAL",
        "Asset Inventory",
        "Updated list of all hardware, software, and data assets.",
        "Art. 21.2.i, NIS2",
        "21.2.i",
    ),
    (
        "G-09",
        "CRITICAL",
        "Vulnerability Management",
        "Critical patches installed within 48-72h from release.",
        "Art. 21.2.e, NIS2",
        "21.2.e",
    ),
    (
        "G-10",
        "CRITICAL",
        "Cybersecurity Budget",
        "Specific and adequate budget allocated for NIS2 compliance.",
        "Art. 20, NIS2",
        "20",
    ),
    # HIGH
    (
        "G-11",
        "HIGH",
        "Risk Assessment",
        "Formal cyber risk analysis on all critical assets.",
        "Art. 21.2.a, NIS2",
        "21.2.a",
    ),
    (
        "G-12",
        "HIGH",
        "Information Security Policy",
        "Approved master document dictating corporate security rules.",
        "Art. 21.2.a, NIS2",
        "21.2.a",
    ),
    (
        "G-13",
        "HIGH",
        "Supplier Mapping",
        "List of critical suppliers (MSP, Software, Cloud).",
        "Art. 21.2.d, NIS2",
        "21.2.d",
    ),
    (
        "G-14",
        "HIGH",
        "Supply Chain Security",
        "Security requirements and notification clauses in supplier contracts.",
        "Art. 21.2.d, NIS2",
        "21.2.d",
    ),
    (
        "G-15",
        "HIGH",
        "Incident Response Plan",
        "Technical plan to contain and eradicate attacks.",
        "Art. 21.2.b, NIS2",
        "21.2.b",
    ),
    (
        "G-16",
        "HIGH",
        "Business Continuity Plan",
        "Procedures to continue operations if IT is down.",
        "Art. 21.2.c, NIS2",
        "21.2.c",
    ),
    (
        "G-17",
        "HIGH",
        "Disaster Recovery Plan",
        "IT system restoration after disaster, defined and tested.",
        "Art. 21.2.c, NIS2",
        "21.2.c",
    ),
    (
        "G-18",
        "HIGH",
        "Employee Awareness Training",
        "Continuous anti-phishing training for all staff.",
        "Art. 21.2.g, NIS2",
        "21.2.g",
    ),
    (
        "G-19",
        "HIGH",
        "Backup Testing",
        "Data restoration test performed at least every 6 months.",
        "Art. 21.2.c, NIS2",
        "21.2.c",
    ),
    (
        "G-20",
        "HIGH",
        "Access Control (Least Privilege)",
        "Employees have only permissions strictly necessary.",
        "Art. 21.2.i, NIS2",
        "21.2.i",
    ),
    # MEDIUM
    (
        "G-21",
        "MEDIUM",
        "Network Segmentation",
        "Production/OT network separated from office/guest.",
        "Art. 21.2.e, NIS2",
        "21.2.e",
    ),
    (
        "G-22",
        "MEDIUM",
        "Onboarding/Offboarding",
        "Automatic access revocation when employees leave.",
        "Art. 21.2.i, NIS2",
        "21.2.i",
    ),
    (
        "G-23",
        "MEDIUM",
        "Encryption at Rest",
        "Sensitive data encrypted when stored.",
        "Art. 21.2.h, NIS2",
        "21.2.h",
    ),
    (
        "G-24",
        "MEDIUM",
        "Cryptographic Key Management",
        "Keys managed securely and separated from data.",
        "Art. 21.2.h, NIS2",
        "21.2.h",
    ),
    (
        "G-25",
        "MEDIUM",
        "Logging and Monitoring",
        "System logs collected centrally and analyzed.",
        "Art. 21.2.f, NIS2",
        "21.2.f",
    ),
    (
        "G-26",
        "MEDIUM",
        "Security in Acquisition",
        "Security requirements evaluated before buying/developing software.",
        "Art. 21.2.e, NIS2",
        "21.2.e",
    ),
    (
        "G-27",
        "MEDIUM",
        "Secure Emergency Communications",
        "Secure systems for emergency comms if email is down.",
        "Art. 21.2.j, NIS2",
        "21.2.j",
    ),
    (
        "G-28",
        "MEDIUM",
        "Internal Audits",
        "Periodic checks planned to verify procedure compliance.",
        "Art. 21.2.f, NIS2",
        "21.2.f",
    ),
    (
        "G-29",
        "MEDIUM",
        "VA/Pen Test",
        "Technical vulnerability scan performed at least annually.",
        "Art. 21.2.f, NIS2",
        "21.2.f",
    ),
    (
        "G-30",
        "MEDIUM",
        "End-to-End Encryption",
        "Advanced measures for protecting confidential communications.",
        "Art. 21.2.h, NIS2",
        "21.2.h",
    ),
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
            raise HTTPException(
                status_code=400, detail=f"Unknown subparagraph: {subparagraph}"
            )
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
        total=total,
        stats=stats,
    )


@router.post(
    "/seed",
    response_model=GovernanceSeedResponse,
    dependencies=[Depends(require_role("admin"))],
)
async def seed_governance(
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> GovernanceSeedResponse:
    """Initialize the 30-item governance checklist for this organization."""
    user, membership = current_org
    org_id = membership.organization_id

    # Check if already seeded
    existing = await db.execute(
        select(func.count(GovernanceItem.id)).where(
            GovernanceItem.organization_id == org_id
        )
    )
    if (existing.scalar() or 0) > 0:
        raise HTTPException(
            status_code=400,
            detail="Governance checklist already initialized. Use PATCH to update items.",
        )

    for idx, (item_id, priority, title, description, ref, subpara) in enumerate(
        CHECKLIST_TEMPLATE
    ):
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
    return GovernanceSeedResponse(
        created=len(CHECKLIST_TEMPLATE), message="30 governance items created"
    )


@router.patch(
    "/{item_id}",
    response_model=GovernanceItemResponse,
    dependencies=[Depends(require_role("admin", "auditor"))],
)
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


@router.post("/bulk-update", dependencies=[Depends(require_role("admin", "auditor"))])
async def bulk_update_governance(
    payload: GovernanceBulkUpdateRequest,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Bulk update multiple governance items at once.

    v2.5.6: accepts a typed GovernanceBulkUpdateRequest instead of raw
    list[dict].  Each item's id is validated as UUID, status is
    constrained to the 4 valid values, and string fields have length
    limits.  Max 100 items per request.
    """
    user, membership = current_org
    org_id = membership.organization_id
    updated = 0
    for upd in payload.items:
        item = await db.get(GovernanceItem, upd.id)
        if not item or item.organization_id != org_id:
            continue
        update_data = upd.model_dump(exclude={"id"}, exclude_unset=True)
        for field, value in update_data.items():
            setattr(item, field, value)
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
        return {
            "score": 0,
            "message": "No governance items. Call POST /governance/seed first.",
        }

    weights = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0}
    total_weight = sum(weights.get(i.priority, 1.0) for i in items)
    earned = sum(weights.get(i.priority, 1.0) for i in items if i.status == "done")
    partial = sum(
        weights.get(i.priority, 1.0) * 0.5 for i in items if i.status == "in_progress"
    )
    score = (
        round(((earned + partial) / total_weight) * 100, 1) if total_weight > 0 else 0
    )

    by_priority = {}
    for p in ("CRITICAL", "HIGH", "MEDIUM"):
        p_items = [i for i in items if i.priority == p]
        done = sum(1 for i in p_items if i.status == "done")
        by_priority[p] = {
            "total": len(p_items),
            "done": done,
            "pct": round((done / len(p_items)) * 100, 1) if p_items else 0,
        }

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


# ---------------------------------------------------------------------------
# Risk signal integration — Art. 21(a) scanner → governance bridge
# ---------------------------------------------------------------------------

# Maps scanner finding category prefixes (lowercase) to the NIS2 Art. 21.2
# sub-paragraph most directly affected. Used by /risk-summary and /sync-risk
# to route technical findings into the right governance items automatically.
#
# Matching is prefix-based (category.lower().startswith(prefix)) so that
# scanner categories like "tls_weak_cipher", "ssl_expired_cert", and
# "tls_no_hsts" all map to 21.2.h without needing an exhaustive list.
#
# The catch-all key "" maps every finding to 21.2.a (risk analysis) —
# all technical evidence is relevant to the overall risk register.
CATEGORY_SUBPARAGRAPH_MAP: list[tuple[str, str]] = [
    # Cryptography / TLS / certificates
    ("tls", "21.2.h"),
    ("ssl", "21.2.h"),
    ("certificate", "21.2.h"),
    ("crypto", "21.2.h"),
    ("encryption", "21.2.h"),
    # Access control / credentials
    ("secret", "21.2.i"),
    ("credential", "21.2.i"),
    ("password", "21.2.i"),
    ("access", "21.2.i"),
    # Authentication / MFA
    ("auth", "21.2.j"),
    ("mfa", "21.2.j"),
    # Network / acquisition / maintenance
    ("port", "21.2.e"),
    ("network", "21.2.e"),
    ("firewall", "21.2.e"),
    ("http", "21.2.e"),
    ("web", "21.2.e"),
    ("dns", "21.2.e"),
    ("patch", "21.2.e"),
    # Effectiveness / monitoring
    ("vulnerab", "21.2.f"),
    ("logging", "21.2.f"),
    ("monitor", "21.2.f"),
    # Supply chain
    ("supply", "21.2.d"),
    ("vendor", "21.2.d"),
    # Business continuity / backup
    ("backup", "21.2.c"),
    ("continuity", "21.2.c"),
    ("recovery", "21.2.c"),
    # Incident handling
    ("incident", "21.2.b"),
    # Catch-all: every finding feeds Art. 21.2.a (risk analysis)
    ("", "21.2.a"),
]

# Findings with these statuses are considered "resolved" and do not
# contribute to the active risk signal.
_RESOLVED_STATUSES = frozenset({"resolved", "accepted_risk"})
# Severity levels considered high-risk for the purpose of status escalation.
_HIGH_RISK_SEVERITIES = frozenset({"CRITICAL", "HIGH"})


def _category_to_subparagraphs(category: str) -> list[str]:
    """Return all subparagraph codes that match a finding category.

    A finding always lands in 21.2.a (catch-all) plus any more-specific
    paragraph whose prefix matches the category. Deduplicates results.
    """
    cat = (category or "").lower()
    matched: list[str] = []
    for prefix, sp in CATEGORY_SUBPARAGRAPH_MAP:
        if cat.startswith(prefix):  # "" always matches (startswith("") is True)
            if sp not in matched:
                matched.append(sp)
    return matched


@router.get("/risk-summary")
async def risk_summary(
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Computed risk picture derived from scanner findings.

    Aggregates open CRITICAL/HIGH/MEDIUM/LOW findings for the org,
    maps each category to the relevant NIS2 Art. 21 sub-paragraph(s),
    and returns which governance items are signalled — giving the CISO
    an evidence-based starting point for the risk register (Art. 21.2.a)
    without requiring manual data entry.

    This endpoint is read-only: it never mutates governance state.
    Call POST /governance/sync-risk to apply the signals automatically.
    """
    user, membership = current_org
    org_id = membership.organization_id

    result = await db.execute(
        select(Finding).where(
            Finding.organization_id == org_id,
            Finding.status.notin_(_RESOLVED_STATUSES),
        )
    )
    findings = result.scalars().all()

    # Severity counts
    counts: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    for f in findings:
        sev = f.severity.upper()
        counts[sev] = counts.get(sev, 0) + 1

    # Overall risk level
    if counts["CRITICAL"] > 0:
        risk_level = "CRITICAL"
    elif counts["HIGH"] > 0:
        risk_level = "HIGH"
    elif counts["MEDIUM"] > 0:
        risk_level = "MEDIUM"
    elif counts["LOW"] > 0:
        risk_level = "LOW"
    else:
        risk_level = "NONE"

    # Group by category → subparagraph
    sp_signals: dict[str, dict] = {}
    for f in findings:
        for sp in _category_to_subparagraphs(f.category):
            if sp not in sp_signals:
                sp_signals[sp] = {
                    "subparagraph": sp,
                    "label": SUBPARAGRAPHS.get(sp, sp),
                    "finding_count": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "top_findings": [],
                }
            entry = sp_signals[sp]
            entry["finding_count"] += 1
            sev = f.severity.upper()
            if sev == "CRITICAL":
                entry["critical"] += 1
            elif sev == "HIGH":
                entry["high"] += 1
            elif sev == "MEDIUM":
                entry["medium"] += 1
            # Collect up to 3 representative messages per subparagraph
            if len(entry["top_findings"]) < 3:
                entry["top_findings"].append(
                    {
                        "severity": f.severity,
                        "category": f.category,
                        "message": f.message[:120],
                        "target": f.target,
                    }
                )

    # Attach governance item IDs for each signalled subparagraph
    gov_result = await db.execute(
        select(GovernanceItem).where(GovernanceItem.organization_id == org_id)
    )
    gov_items = gov_result.scalars().all()
    sp_to_item_ids: dict[str, list[str]] = {}
    for gi in gov_items:
        if gi.subparagraph and gi.subparagraph in sp_signals:
            sp_to_item_ids.setdefault(gi.subparagraph, []).append(gi.item_id)
    for sp, entry in sp_signals.items():
        entry["governance_item_ids"] = sp_to_item_ids.get(sp, [])

    return {
        "risk_level": risk_level,
        "open_finding_counts": counts,
        "total_open_findings": len(findings),
        "subparagraph_signals": sorted(
            sp_signals.values(),
            key=lambda x: (-(x["critical"]), -(x["high"]), -(x["medium"])),
        ),
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/sync-risk", dependencies=[Depends(require_role("admin", "auditor"))])
async def sync_risk(
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Apply scanner findings as evidence to the governance checklist.

    For each NIS2 sub-paragraph that has open findings, the corresponding
    governance items receive an updated `evidence_notes` block with a
    timestamped summary of current HIGH/CRITICAL findings.

    Status escalation rules (conservative — human decisions are never
    overridden):
      - `not_started` + any HIGH/CRITICAL finding → escalated to `in_progress`
      - `in_progress`, `done`, `not_applicable` → status left unchanged
      - Items with zero matching findings → not touched

    Returns a summary of every item that was updated.
    """
    user, membership = current_org

    org_id = membership.organization_id

    # Load all open findings
    finding_result = await db.execute(
        select(Finding).where(
            Finding.organization_id == org_id,
            Finding.status.notin_(_RESOLVED_STATUSES),
        )
    )
    findings = finding_result.scalars().all()

    if not findings:
        return {
            "updated": 0,
            "message": "No open findings — governance items unchanged.",
            "changes": [],
        }

    # Build per-subparagraph evidence maps
    sp_evidence: dict[str, dict] = {}
    for f in findings:
        for sp in _category_to_subparagraphs(f.category):
            if sp not in sp_evidence:
                sp_evidence[sp] = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "samples": [],
                }
            ev = sp_evidence[sp]
            sev = f.severity.upper()
            if sev == "CRITICAL":
                ev["critical"] += 1
            elif sev == "HIGH":
                ev["high"] += 1
            elif sev == "MEDIUM":
                ev["medium"] += 1
            else:
                ev["low"] += 1
            if len(ev["samples"]) < 3:
                ev["samples"].append(f"[{f.severity}] {f.category}: {f.message[:100]}")

    # Load governance items for this org that have a subparagraph signal
    gov_result = await db.execute(
        select(GovernanceItem).where(
            GovernanceItem.organization_id == org_id,
            GovernanceItem.subparagraph.in_(list(sp_evidence.keys())),
        )
    )
    gov_items = gov_result.scalars().all()

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    changes: list[dict] = []

    for item in gov_items:
        sp = item.subparagraph
        ev = sp_evidence.get(sp)
        if not ev:
            continue

        # Build evidence note block
        high_risk_count = ev["critical"] + ev["high"]
        note_lines = [
            f"[Auto-sync {now_str}] Scanner findings for {SUBPARAGRAPHS.get(sp, sp)}:",
            f"  CRITICAL: {ev['critical']}  HIGH: {ev['high']}  MEDIUM: {ev['medium']}  LOW: {ev['low']}",
        ]
        for sample in ev["samples"]:
            note_lines.append(f"  • {sample}")

        new_note = "\n".join(note_lines)

        # Prepend to existing notes (most recent first), cap at 4000 chars
        existing = item.evidence_notes or ""
        combined = (new_note + "\n\n" + existing).strip()
        item.evidence_notes = combined[:4000]

        # Status escalation: only promote not_started → in_progress
        old_status = item.status
        if item.status == "not_started" and high_risk_count > 0:
            item.status = "in_progress"

        changes.append(
            {
                "item_id": item.item_id,
                "title": item.title,
                "subparagraph": sp,
                "status_before": old_status,
                "status_after": item.status,
                "evidence_added": f"CRITICAL:{ev['critical']} HIGH:{ev['high']} MEDIUM:{ev['medium']}",
            }
        )

    await db.flush()

    return {
        "updated": len(changes),
        "message": f"Risk signals applied to {len(changes)} governance items.",
        "changes": changes,
    }
