import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_org, get_current_user
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.membership import Membership
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.models.user import User
from app.schemas.finding import FindingListResponse, FindingResponse
from app.schemas.scan import (
    ScanCreate,
    ScanListResponse,
    ScanResponse,
    ScanResultListResponse,
    ScanResultResponse,
)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=ScanListResponse)
async def list_scans(
    status_filter: Optional[str] = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> ScanListResponse:
    user, membership = current_org
    org_id = membership.organization_id

    query = select(Scan).where(Scan.organization_id == org_id)
    count_query = select(func.count(Scan.id)).where(Scan.organization_id == org_id)

    if status_filter:
        query = query.where(Scan.status == status_filter)
        count_query = count_query.where(Scan.status == status_filter)

    query = query.order_by(Scan.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListResponse(
        items=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    user, membership = current_org
    org_id = membership.organization_id

    # Resolve assets
    assets_result = await db.execute(
        select(Asset).where(
            Asset.id.in_(payload.asset_ids),
            Asset.organization_id == org_id,
            Asset.is_active.is_(True),
        )
    )
    assets = assets_result.scalars().all()

    if not assets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid active assets found for the provided IDs",
        )

    # Build config snapshot from assets
    domains: list[str] = []
    ip_ranges: list[str] = []
    for asset in assets:
        if asset.target_type == "domain":
            domains.append(asset.target_value)
        elif asset.target_type in ("ip", "cidr"):
            ip_ranges.append(asset.target_value)

    config_snapshot = {
        "name": payload.name,
        "domains": domains,
        "ip_ranges": ip_ranges,
        "scan_type": payload.scan_type,
        "features": payload.features or {
            "dns_checks": True,
            "web_checks": True,
            "port_scan": True,
            "whois_checks": True,
        },
        "concurrency": payload.concurrency or 20,
        "scan_timeout": payload.scan_timeout or 10,
        "max_hosts": payload.max_hosts or 0,  # 0 = unlimited
    }

    scan = Scan(
        organization_id=org_id,
        created_by=user.id,
        name=payload.name,
        scan_type=payload.scan_type,
        config_snapshot=config_snapshot,
        status="pending",
    )
    db.add(scan)
    await db.flush()

    # Enqueue Celery task
    try:
        from app.tasks.scan_tasks import run_scan_task

        task = run_scan_task.delay(str(scan.id))
        scan.celery_task_id = task.id
        await db.flush()
    except Exception:
        # If Celery is not available, scan stays in pending
        pass

    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    user, membership = current_org
    scan = await db.get(Scan, scan_id)

    if not scan or scan.organization_id != membership.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/results", response_model=ScanResultListResponse)
async def get_scan_results(
    scan_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> ScanResultListResponse:
    user, membership = current_org

    # Verify scan belongs to org
    scan = await db.get(Scan, scan_id)
    if not scan or scan.organization_id != membership.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    count_query = select(func.count(ScanResult.id)).where(ScanResult.scan_id == scan_id)
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = (
        select(ScanResult)
        .where(ScanResult.scan_id == scan_id)
        .order_by(ScanResult.created_at)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    results = result.scalars().all()

    return ScanResultListResponse(
        items=[ScanResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
async def get_scan_findings(
    scan_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> FindingListResponse:
    user, membership = current_org

    scan = await db.get(Scan, scan_id)
    if not scan or scan.organization_id != membership.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    count_query = select(func.count(Finding.id)).where(Finding.scan_id == scan_id)
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = (
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.severity, Finding.created_at)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    findings = result.scalars().all()

    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    user, membership = current_org

    scan = await db.get(Scan, scan_id)
    if not scan or scan.organization_id != membership.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if scan.status not in ("pending", "running"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan in '{scan.status}' status",
        )

    # Attempt to revoke Celery task
    if scan.celery_task_id:
        try:
            from app.tasks.celery_app import celery_app

            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        except Exception:
            pass

    scan.status = "cancelled"
    await db.flush()

    return ScanResponse.model_validate(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    user, membership = current_org

    if membership.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can delete scans",
        )

    scan = await db.get(Scan, scan_id)
    if not scan or scan.organization_id != membership.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    await db.delete(scan)
    await db.flush()


@router.get("/{scan_id}/compare/{other_id}")
async def compare_scans(
    scan_id: uuid.UUID,
    other_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Compare two scans: score delta, new/resolved/persistent findings."""
    user, membership = current_org
    org_id = membership.organization_id

    scan_a = await db.get(Scan, scan_id)
    scan_b = await db.get(Scan, other_id)

    if not scan_a or scan_a.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan_b or scan_b.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Comparison scan not found")

    # Load findings for both scans
    findings_a_q = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings_b_q = await db.execute(
        select(Finding).where(Finding.scan_id == other_id)
    )
    findings_a = findings_a_q.scalars().all()
    findings_b = findings_b_q.scalars().all()

    fps_a = {f.fingerprint for f in findings_a}
    fps_b = {f.fingerprint for f in findings_b}

    new_fps = fps_a - fps_b  # in A but not B
    resolved_fps = fps_b - fps_a  # in B but not A
    persistent_fps = fps_a & fps_b  # in both

    def serialize_findings(findings, fps_set):
        return [
            {"severity": f.severity, "category": f.category, "message": f.message, "target": f.target}
            for f in findings if f.fingerprint in fps_set
        ]

    return {
        "scan_a": {"id": str(scan_a.id), "name": scan_a.name, "score": scan_a.total_score, "date": scan_a.created_at.isoformat() if scan_a.created_at else None},
        "scan_b": {"id": str(scan_b.id), "name": scan_b.name, "score": scan_b.total_score, "date": scan_b.created_at.isoformat() if scan_b.created_at else None},
        "score_delta": (scan_a.total_score or 0) - (scan_b.total_score or 0),
        "new_findings": serialize_findings(findings_a, new_fps),
        "resolved_findings": serialize_findings(findings_b, resolved_fps),
        "persistent_findings": len(persistent_fps),
        "summary": {
            "new": len(new_fps),
            "resolved": len(resolved_fps),
            "persistent": len(persistent_fps),
        },
    }
