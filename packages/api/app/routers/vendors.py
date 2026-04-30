# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Vendor Risk Management API — Art. 18 D.Lgs 138/2024.
CRUD for supply chain vendor tracking and security assessment.
"""
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user_org
from app.models.vendor import Vendor

router = APIRouter(prefix="/vendors", tags=["vendors"])


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


# --- Endpoints ---

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
    """Register a new vendor/supplier."""
    user, org_id = auth
    vendor = Vendor(organization_id=org_id, **data.model_dump())
    db.add(vendor)
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
