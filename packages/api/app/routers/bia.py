# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
BIA (Business Impact Analysis) API.
Maps business processes to IT assets and criticality for ACN BIA template.
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
from app.models.bia import BusinessProcess

router = APIRouter(prefix="/bia", tags=["bia"])


# --- Schemas ---

class ProcessCreate(BaseModel):
    name: str
    description: Optional[str] = None
    process_owner: Optional[str] = None
    department: Optional[str] = None
    criticality_level: int = Field(ge=1, le=4, default=3)
    rto_hours: Optional[int] = None
    rpo_hours: Optional[int] = None
    mtpd_hours: Optional[int] = None
    impact_financial: int = Field(ge=1, le=4, default=1)
    impact_operational: int = Field(ge=1, le=4, default=1)
    impact_reputational: int = Field(ge=1, le=4, default=1)
    impact_regulatory: int = Field(ge=1, le=4, default=1)
    impact_safety: int = Field(ge=1, le=4, default=1)
    dependent_asset_ids: Optional[list] = None
    dependent_vendor_ids: Optional[list] = None
    acn_servizio_essenziale: bool = False
    acn_codice_servizio: Optional[str] = None
    acn_settore: Optional[str] = None
    has_bcp: bool = False
    has_drp: bool = False
    notes: Optional[str] = None


class ProcessOut(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    process_owner: Optional[str]
    department: Optional[str]
    criticality_level: int
    rto_hours: Optional[int]
    rpo_hours: Optional[int]
    mtpd_hours: Optional[int]
    impact_financial: int
    impact_operational: int
    impact_reputational: int
    impact_regulatory: int
    impact_safety: int
    dependent_asset_ids: Optional[list]
    dependent_vendor_ids: Optional[list]
    acn_servizio_essenziale: bool
    acn_codice_servizio: Optional[str]
    acn_settore: Optional[str]
    has_bcp: bool
    has_drp: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# --- Endpoints ---

@router.get("")
async def list_processes(
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """List all business processes for the organization."""
    user, org_id = auth
    result = await db.execute(
        select(BusinessProcess)
        .where(BusinessProcess.organization_id == org_id)
        .order_by(BusinessProcess.criticality_level, BusinessProcess.name)
    )
    processes = result.scalars().all()
    return {
        "items": [ProcessOut.model_validate(p) for p in processes],
        "total": len(processes),
    }


@router.post("", status_code=201)
async def create_process(
    data: ProcessCreate,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Register a business process for BIA."""
    user, org_id = auth
    process = BusinessProcess(organization_id=org_id, **data.model_dump())
    db.add(process)
    await db.flush()
    await db.refresh(process)
    return ProcessOut.model_validate(process)


@router.get("/matrix")
async def bia_matrix(
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """BIA impact matrix: overview of all processes with their impact scores."""
    user, org_id = auth
    result = await db.execute(
        select(BusinessProcess)
        .where(BusinessProcess.organization_id == org_id)
        .order_by(BusinessProcess.criticality_level)
    )
    processes = result.scalars().all()

    matrix = []
    for p in processes:
        max_impact = max(
            p.impact_financial, p.impact_operational,
            p.impact_reputational, p.impact_regulatory, p.impact_safety
        )
        matrix.append({
            "id": str(p.id),
            "name": p.name,
            "criticality_level": p.criticality_level,
            "rto_hours": p.rto_hours,
            "rpo_hours": p.rpo_hours,
            "max_impact_score": max_impact,
            "has_bcp": p.has_bcp,
            "has_drp": p.has_drp,
            "acn_servizio_essenziale": p.acn_servizio_essenziale,
            "gaps": [],
        })

        # Identify gaps
        if not p.has_bcp:
            matrix[-1]["gaps"].append("Missing Business Continuity Plan")
        if not p.has_drp:
            matrix[-1]["gaps"].append("Missing Disaster Recovery Plan")
        if not p.rto_hours:
            matrix[-1]["gaps"].append("RTO not defined")
        if not p.rpo_hours:
            matrix[-1]["gaps"].append("RPO not defined")
        if p.criticality_level <= 2 and not p.last_test_date:
            matrix[-1]["gaps"].append("Critical process never tested")

    stats = {
        "total_processes": len(processes),
        "mission_critical": sum(1 for p in processes if p.criticality_level == 1),
        "without_bcp": sum(1 for p in processes if not p.has_bcp),
        "without_drp": sum(1 for p in processes if not p.has_drp),
        "essential_services": sum(1 for p in processes if p.acn_servizio_essenziale),
    }

    return {"matrix": matrix, "stats": stats}


@router.get("/{process_id}")
async def get_process(
    process_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Get business process details."""
    user, org_id = auth
    result = await db.execute(
        select(BusinessProcess)
        .where(BusinessProcess.id == process_id, BusinessProcess.organization_id == org_id)
    )
    process = result.scalar_one_or_none()
    if not process:
        raise HTTPException(status_code=404, detail="Business process not found")
    return ProcessOut.model_validate(process)


@router.delete("/{process_id}", status_code=204)
async def delete_process(
    process_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: tuple = Depends(get_current_user_org),
):
    """Remove a business process."""
    user, org_id = auth
    result = await db.execute(
        select(BusinessProcess)
        .where(BusinessProcess.id == process_id, BusinessProcess.organization_id == org_id)
    )
    process = result.scalar_one_or_none()
    if not process:
        raise HTTPException(status_code=404, detail="Business process not found")
    await db.delete(process)
