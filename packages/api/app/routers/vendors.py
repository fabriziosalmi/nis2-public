# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Vendor Risk Management API — Art. 18 D.Lgs 138/2024.
CRUD for supply chain vendor tracking and security assessment.

Scoring formula (v1.0)
----------------------
security_score is computed from five observable vendor attributes. Each
factor carries a documented maximum weight; the total is always 0-100.
The formula is intentionally deterministic and reproducible so an Art. 18
auditor can verify any score by reading the vendor record and applying
the weights below.

  Factor                  Max  Rationale
  ─────────────────────── ─── ──────────────────────────────────────────
  Security certification   25  Recognised third-party audit (ISO27001 > SOC2 > CSA_STAR)
  Data access level        25  Higher access = higher inherent risk (inverse)
  Audit recency            20  Last vendor security audit age
  Geographic location      15  Jurisdiction risk (EU/EEA trusted, third country not)
  Security clauses         15  Contract provisions: SLA, audit rights, incident
                               notification, data breach clause, sub-processor clause
  ─────────────────────── ─── ──────────────────────────────────────────
  Total                   100

Call GET /vendors/score-formula for the machine-readable breakdown.
Call GET /vendors/{id}/score for a per-vendor computed score + rationale.
Call POST /vendors/{id}/score/apply to persist the computed score.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user_org
from app.models.vendor import Vendor

router = APIRouter(prefix="/vendors", tags=["vendors"])


# ---------------------------------------------------------------------------
# Scoring formula — v1.0
# ---------------------------------------------------------------------------

# The formula is defined as a list of (factor_id, label, max_weight, description)
# tuples so it can be serialised verbatim by GET /score-formula for auditors.
SCORE_FORMULA_VERSION = "1.0"

SCORE_FACTORS = [
    {
        "factor_id": "certification",
        "label": "Security Certification",
        "max_weight": 25,
        "description": (
            "Recognised third-party security audit reduces residual risk. "
            "ISO27001=25, SOC2_Type2=22, CSA_STAR=18, SOC2_Type1=15, other recognised=10, none=0."
        ),
        "source_field": "has_security_certification",
    },
    {
        "factor_id": "data_access",
        "label": "Data Access Level",
        "max_weight": 25,
        "description": (
            "Higher data access increases inherent risk (score is inverse of access). "
            "none=25, metadata=20, operational=12, confidential=5, critical=0."
        ),
        "source_field": "data_access_level",
    },
    {
        "factor_id": "audit_recency",
        "label": "Audit Recency",
        "max_weight": 20,
        "description": (
            "Age of the last vendor security audit. "
            "<6 months=20, <12 months=15, <24 months=8, <36 months=3, never/unknown=0."
        ),
        "source_field": "last_audit_date",
    },
    {
        "factor_id": "geography",
        "label": "Geographic Location",
        "max_weight": 15,
        "description": (
            "Jurisdictional risk of vendor's data processing location. "
            "EU=15, EEA=14, adequacy_decision=10, third_country=0, unknown=5."
        ),
        "source_field": "geographic_location",
    },
    {
        "factor_id": "clauses",
        "label": "Security Contract Clauses",
        "max_weight": 15,
        "description": (
            "Contract protections from security_clauses JSONB field. "
            "3 pts each for: sla, audit_rights, incident_notification, "
            "data_breach_clause, sub_processor_clause. Max 15."
        ),
        "source_field": "security_clauses",
    },
]


def compute_vendor_score(vendor: Vendor) -> dict:
    """Compute a transparent, reproducible vendor risk score (0-100).

    Returns a dict with the total score and a per-factor breakdown so
    callers (and auditors) can inspect every component and rationale.
    """
    breakdown: list[dict] = []
    total = 0

    # ── Factor 1: Security certification (max 25) ──────────────────────────
    cert = (vendor.has_security_certification or "").upper()
    if "ISO27001" in cert or "ISO 27001" in cert:
        cert_score, cert_rationale = 25, "ISO 27001 certified (+25)"
    elif "SOC2" in cert and "TYPE2" in cert.replace(" ", ""):
        cert_score, cert_rationale = 22, "SOC 2 Type II certified (+22)"
    elif "CSA_STAR" in cert or "CSA STAR" in cert:
        cert_score, cert_rationale = 18, "CSA STAR certified (+18)"
    elif "SOC2" in cert or "SOC 2" in cert:
        cert_score, cert_rationale = 15, "SOC 2 Type I certified (+15)"
    elif cert and cert not in ("NONE", "N/A", "-"):
        cert_score, cert_rationale = 10, f"Other certification: {vendor.has_security_certification} (+10)"
    else:
        cert_score, cert_rationale = 0, "No recognised security certification (+0)"
    breakdown.append({
        "factor_id": "certification",
        "label": "Security Certification",
        "max_weight": 25,
        "earned": cert_score,
        "rationale": cert_rationale,
    })
    total += cert_score

    # ── Factor 2: Data access level (max 25, inverse of risk) ──────────────
    data_access_scores = {
        "none": (25, "No data access (+25)"),
        "metadata": (20, "Metadata access only (+20)"),
        "operational": (12, "Operational data access (+12)"),
        "confidential": (5, "Confidential data access (+5)"),
        "critical": (0, "Critical/sensitive data access (+0)"),
    }
    da_score, da_rationale = data_access_scores.get(
        (vendor.data_access_level or "none").lower(),
        (5, f"Unknown access level '{vendor.data_access_level}' (+5)"),
    )
    breakdown.append({
        "factor_id": "data_access",
        "label": "Data Access Level",
        "max_weight": 25,
        "earned": da_score,
        "rationale": da_rationale,
    })
    total += da_score

    # ── Factor 3: Audit recency (max 20) ───────────────────────────────────
    if vendor.last_audit_date:
        now = datetime.now(timezone.utc)
        last_audit = vendor.last_audit_date
        if last_audit.tzinfo is None:
            last_audit = last_audit.replace(tzinfo=timezone.utc)
        months_ago = (now - last_audit).days / 30.44
        if months_ago < 6:
            audit_score, audit_rationale = 20, f"Audit {months_ago:.0f} months ago — current (+20)"
        elif months_ago < 12:
            audit_score, audit_rationale = 15, f"Audit {months_ago:.0f} months ago (+15)"
        elif months_ago < 24:
            audit_score, audit_rationale = 8, f"Audit {months_ago:.0f} months ago — aging (+8)"
        elif months_ago < 36:
            audit_score, audit_rationale = 3, f"Audit {months_ago:.0f} months ago — stale (+3)"
        else:
            audit_score, audit_rationale = 0, f"Audit {months_ago:.0f} months ago — outdated (+0)"
    else:
        audit_score, audit_rationale = 0, "No audit on record (+0)"
    breakdown.append({
        "factor_id": "audit_recency",
        "label": "Audit Recency",
        "max_weight": 20,
        "earned": audit_score,
        "rationale": audit_rationale,
    })
    total += audit_score

    # ── Factor 4: Geographic location (max 15) ─────────────────────────────
    geo_scores = {
        "eu": (15, "EU jurisdiction — GDPR/NIS2 directly applicable (+15)"),
        "eea": (14, "EEA jurisdiction — adequately regulated (+14)"),
        "adequacy_decision": (10, "Adequacy decision country (+10)"),
        "third_country": (0, "Third country — elevated jurisdictional risk (+0)"),
    }
    geo = (vendor.geographic_location or "").lower().replace(" ", "_").replace("-", "_")
    geo_score, geo_rationale = geo_scores.get(
        geo,
        (5, f"Unknown/unspecified location '{vendor.geographic_location}' (+5)") if geo else (5, "Location not specified (+5)"),
    )
    breakdown.append({
        "factor_id": "geography",
        "label": "Geographic Location",
        "max_weight": 15,
        "earned": geo_score,
        "rationale": geo_rationale,
    })
    total += geo_score

    # ── Factor 5: Security contract clauses (max 15, 3 pts each) ───────────
    clauses = vendor.security_clauses or {}
    clause_keys = ["sla", "audit_rights", "incident_notification", "data_breach_clause", "sub_processor_clause"]
    present = [k for k in clause_keys if clauses.get(k)]
    clause_score = min(len(present) * 3, 15)
    if present:
        clause_rationale = f"{len(present)}/5 clauses present ({', '.join(present)}) (+{clause_score})"
    else:
        clause_rationale = "No security clauses documented (+0)"
    breakdown.append({
        "factor_id": "clauses",
        "label": "Security Contract Clauses",
        "max_weight": 15,
        "earned": clause_score,
        "rationale": clause_rationale,
    })
    total += clause_score

    return {
        "computed_score": min(total, 100),
        "formula_version": SCORE_FORMULA_VERSION,
        "breakdown": breakdown,
        "max_possible": 100,
    }


# --- Schemas ---

class VendorCreate(BaseModel):
    name: str
    vendor_type: str = "ict_service"
    criticality: int = Field(ge=1, le=4, default=2)
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    contract_ref: Optional[str] = None
    contract_expiry: Optional[datetime] = None
    services_provided: Optional[str] = None
    data_access_level: str = "none"
    geographic_location: Optional[str] = None
    has_security_certification: Optional[str] = None
    last_audit_date: Optional[datetime] = None
    next_audit_date: Optional[datetime] = None
    security_score: Optional[int] = Field(None, ge=0, le=100)
    risk_notes: Optional[str] = None
    acn_codice_servizio: Optional[str] = None
    acn_rilevanza_art18: bool = False


class VendorUpdate(BaseModel):
    name: Optional[str] = None
    vendor_type: Optional[str] = None
    criticality: Optional[int] = Field(None, ge=1, le=4)
    status: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    contract_ref: Optional[str] = None
    contract_expiry: Optional[datetime] = None
    services_provided: Optional[str] = None
    data_access_level: Optional[str] = None
    geographic_location: Optional[str] = None
    has_security_certification: Optional[str] = None
    last_audit_date: Optional[datetime] = None
    next_audit_date: Optional[datetime] = None
    security_score: Optional[int] = Field(None, ge=0, le=100)
    risk_notes: Optional[str] = None
    security_clauses: Optional[dict] = None
    acn_codice_servizio: Optional[str] = None
    acn_rilevanza_art18: Optional[bool] = None


class VendorOut(BaseModel):
    id: uuid.UUID
    name: str
    vendor_type: str
    criticality: int
    status: str
    contact_name: Optional[str]
    contact_email: Optional[str]
    services_provided: Optional[str]
    data_access_level: str
    geographic_location: Optional[str]
    has_security_certification: Optional[str]
    security_score: Optional[int]
    acn_rilevanza_art18: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# --- Schemas ---

class ScoreBreakdownItem(BaseModel):
    factor_id: str
    label: str
    max_weight: int
    earned: int
    rationale: str


class VendorScoreResponse(BaseModel):
    vendor_id: uuid.UUID
    vendor_name: str
    computed_score: int
    formula_version: str
    breakdown: list[ScoreBreakdownItem]
    max_possible: int
    computed_at: datetime


# --- Endpoints ---

@router.get("/score-formula")
async def get_score_formula():
    """Return the vendor risk scoring formula used by this platform.

    This endpoint is intentionally unauthenticated-friendly (still requires
    a valid session) so an Art. 18 auditor can retrieve and document the
    methodology without needing admin access.

    The formula version is included in every computed score response so
    historical scores remain traceable even after formula updates.
    """
    return {
        "formula_version": SCORE_FORMULA_VERSION,
        "total_max": 100,
        "factors": SCORE_FACTORS,
        "notes": (
            "Scores are computed deterministically from vendor fields. "
            "An operator may override security_score manually via PATCH; "
            "call POST /vendors/{id}/score/apply to replace a manual value "
            "with the formula-computed one. "
            "All factor weights and thresholds are versioned — formula_version "
            "in each score response identifies which ruleset was applied."
        ),
    }


@router.get("/{vendor_id}/score", response_model=VendorScoreResponse)
async def get_vendor_score(
    vendor_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Compute and return the vendor risk score with a full factor breakdown.

    Does NOT modify the stored security_score — use POST .../score/apply
    to persist the result. This allows a reviewer to inspect the computed
    score before deciding whether to accept it.
    """
    user, org_id = auth
    result = await db.execute(
        select(Vendor).where(Vendor.id == vendor_id, Vendor.organization_id == org_id)
    )
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    score_data = compute_vendor_score(vendor)
    return VendorScoreResponse(
        vendor_id=vendor.id,
        vendor_name=vendor.name,
        computed_at=datetime.now(timezone.utc),
        **score_data,
    )


@router.post("/{vendor_id}/score/apply")
async def apply_vendor_score(
    vendor_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Compute the vendor risk score and persist it to security_score.

    Records the previous value in risk_notes so the change is auditable.
    Returns the full breakdown so the caller can see what changed and why.
    """
    user, org_id = auth
    result = await db.execute(
        select(Vendor).where(Vendor.id == vendor_id, Vendor.organization_id == org_id)
    )
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    score_data = compute_vendor_score(vendor)
    new_score = score_data["computed_score"]
    old_score = vendor.security_score

    # Append an audit trail entry to risk_notes
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    audit_line = (
        f"[{now_str}] Score auto-computed (formula v{SCORE_FORMULA_VERSION}): "
        f"{old_score} → {new_score}"
    )
    existing_notes = vendor.risk_notes or ""
    vendor.risk_notes = (audit_line + "\n" + existing_notes).strip()[:4000]
    vendor.security_score = new_score
    await db.flush()

    return {
        "vendor_id": str(vendor.id),
        "vendor_name": vendor.name,
        "previous_score": old_score,
        "new_score": new_score,
        "formula_version": score_data["formula_version"],
        "breakdown": score_data["breakdown"],
        "computed_at": now_str,
    }


@router.get("")
async def list_vendors(
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """List all vendors for the organization."""
    user, org_id = auth
    result = await db.execute(
        select(Vendor)
        .where(Vendor.organization_id == org_id)
        .order_by(Vendor.criticality, Vendor.name)
    )
    vendors = result.scalars().all()
    return {
        "items": [VendorOut.model_validate(v) for v in vendors],
        "total": len(vendors),
    }


@router.post("", status_code=201)
async def create_vendor(
    data: VendorCreate,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Register a new vendor/supplier.

    If security_score is omitted, the formula-computed score is applied
    automatically and noted in risk_notes for traceability.
    """
    user, org_id = auth
    vendor = Vendor(organization_id=org_id, **data.model_dump())
    db.add(vendor)
    await db.flush()
    await db.refresh(vendor)

    # Auto-compute score when caller did not supply one explicitly.
    if data.security_score is None:
        score_data = compute_vendor_score(vendor)
        vendor.security_score = score_data["computed_score"]
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        audit_line = (
            f"[{now_str}] Score auto-computed at creation "
            f"(formula v{score_data['formula_version']}): {vendor.security_score}"
        )
        vendor.risk_notes = (audit_line + "\n" + (vendor.risk_notes or "")).strip()[:4000]
        await db.flush()
        await db.refresh(vendor)

    return VendorOut.model_validate(vendor)


@router.get("/stats")
async def vendor_stats(
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Supply chain risk overview: distribution by criticality, type, location."""
    user, org_id = auth
    result = await db.execute(
        select(Vendor).where(Vendor.organization_id == org_id)
    )
    vendors = result.scalars().all()

    stats = {
        "total": len(vendors),
        "by_criticality": {1: 0, 2: 0, 3: 0, 4: 0},
        "by_status": {},
        "by_type": {},
        "art18_relevant": 0,
        "without_audit": 0,
        "avg_security_score": None,
    }

    scores = []
    for v in vendors:
        stats["by_criticality"][v.criticality] = stats["by_criticality"].get(v.criticality, 0) + 1
        stats["by_status"][v.status] = stats["by_status"].get(v.status, 0) + 1
        stats["by_type"][v.vendor_type] = stats["by_type"].get(v.vendor_type, 0) + 1
        if v.acn_rilevanza_art18:
            stats["art18_relevant"] += 1
        if not v.last_audit_date:
            stats["without_audit"] += 1
        if v.security_score is not None:
            scores.append(v.security_score)

    if scores:
        stats["avg_security_score"] = round(sum(scores) / len(scores), 1)

    return stats


@router.get("/{vendor_id}")
async def get_vendor(
    vendor_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Get vendor details."""
    user, org_id = auth
    result = await db.execute(
        select(Vendor)
        .where(Vendor.id == vendor_id, Vendor.organization_id == org_id)
    )
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return VendorOut.model_validate(vendor)


@router.patch("/{vendor_id}")
async def update_vendor(
    vendor_id: uuid.UUID,
    data: VendorUpdate,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Update vendor details."""
    user, org_id = auth
    result = await db.execute(
        select(Vendor)
        .where(Vendor.id == vendor_id, Vendor.organization_id == org_id)
    )
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(vendor, field, value)

    await db.flush()
    await db.refresh(vendor)
    return VendorOut.model_validate(vendor)


@router.delete("/{vendor_id}", status_code=204)
async def delete_vendor(
    vendor_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Remove a vendor."""
    user, org_id = auth
    result = await db.execute(
        select(Vendor)
        .where(Vendor.id == vendor_id, Vendor.organization_id == org_id)
    )
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    await db.delete(vendor)
