# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_org, get_org_id_dual_auth
from app.models.finding import Finding
from app.models.membership import Membership
from app.models.user import User
from app.schemas.finding import (
    BulkFindingUpdate,
    FindingListResponse,
    FindingStats,
    FindingUpdate,
)
from app.middleware.audit import log_action

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=FindingListResponse)
async def list_findings(
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    category: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    org_id: uuid.UUID = Depends(get_org_id_dual_auth),
    db: AsyncSession = Depends(get_db),
) -> FindingListResponse:
    # Dual-auth read — JWT cookie/Bearer OR `nis2_*` API key. Mutation
    # endpoints below stay on get_current_org because they want a user
    # identity to write into the audit log.

    query = select(Finding).where(Finding.organization_id == org_id)
    count_query = select(func.count(Finding.id)).where(Finding.organization_id == org_id)

    if severity:
        query = query.where(Finding.severity == severity)
        count_query = count_query.where(Finding.severity == severity)
    if status_filter:
        query = query.where(Finding.status == status_filter)
        count_query = count_query.where(Finding.status == status_filter)
    if category:
        query = query.where(Finding.category == category)
        count_query = count_query.where(Finding.category == category)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = query.order_by(Finding.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    findings = result.scalars().all()

    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=FindingStats)
async def findings_stats(
    org_id: uuid.UUID = Depends(get_org_id_dual_auth),
    db: AsyncSession = Depends(get_db),
) -> FindingStats:
    # Dual-auth read — see list_findings for the wiring note.
    select(Finding).where(Finding.organization_id == org_id)

    # Total count
    total_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.organization_id == org_id)
    )
    total = total_result.scalar() or 0

    # Severity counts
    severity_query = (
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.organization_id == org_id)
        .group_by(Finding.severity)
    )
    severity_result = await db.execute(severity_query)
    severity_counts = {row[0].upper(): row[1] for row in severity_result.all()}

    # Status counts
    status_query = (
        select(Finding.status, func.count(Finding.id))
        .where(Finding.organization_id == org_id)
        .group_by(Finding.status)
    )
    status_result = await db.execute(status_query)
    status_counts = {row[0]: row[1] for row in status_result.all()}

    return FindingStats(
        total=total,
        critical=severity_counts.get("CRITICAL", 0),
        high=severity_counts.get("HIGH", 0),
        medium=severity_counts.get("MEDIUM", 0),
        low=severity_counts.get("LOW", 0),
        info=severity_counts.get("INFO", 0),
        open=status_counts.get("open", 0),
        acknowledged=status_counts.get("acknowledged", 0),
        in_progress=status_counts.get("in_progress", 0),
        resolved=status_counts.get("resolved", 0),
        accepted_risk=status_counts.get("accepted_risk", 0),
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id_dual_auth),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    # Dual-auth read — see list_findings for the wiring note.
    finding = await db.get(Finding, finding_id)
    if not finding or finding.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    return FindingResponse.model_validate(finding)


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    user, membership = current_org

    finding = await db.get(Finding, finding_id)
    if not finding or finding.organization_id != membership.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(finding, field, value)

    if payload.status == "resolved" and not finding.resolved_at:
        finding.resolved_at = datetime.now(timezone.utc)

    await db.flush()

    await log_action(
        db,
        org_id=membership.organization_id,
        user_id=user.id,
        action="finding.updated",
        resource_type="finding",
        resource_id=str(finding.id),
        details={"status": payload.status, "updated_fields": list(update_data.keys())},
    )

    return FindingResponse.model_validate(finding)


@router.post("/bulk-update", response_model=dict)
async def bulk_update_findings(
    payload: BulkFindingUpdate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user, membership = current_org
    org_id = membership.organization_id

    result = await db.execute(
        select(Finding).where(
            Finding.id.in_(payload.finding_ids),
            Finding.organization_id == org_id,
        )
    )
    findings = result.scalars().all()

    updated_count = 0
    now = datetime.now(timezone.utc)
    for finding in findings:
        finding.status = payload.status
        if payload.resolution_note:
            finding.resolution_note = payload.resolution_note
        if payload.status == "resolved" and not finding.resolved_at:
            finding.resolved_at = now
        updated_count += 1

    await db.flush()

    await log_action(
        db,
        org_id=org_id,
        user_id=user.id,
        action="finding.bulk_updated",
        resource_type="finding",
        details={"status": payload.status, "updated_count": updated_count, "requested_count": len(payload.finding_ids)},
    )

    return {"updated": updated_count, "total_requested": len(payload.finding_ids)}
