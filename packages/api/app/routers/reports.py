# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_org
from app.models.membership import Membership
from app.models.scan import Scan
from app.models.user import User

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate")
async def generate_report(
    scan_id: uuid.UUID,
    format: str = Query("pdf", pattern="^(pdf|json|csv|markdown|md|junit|xml|html)$"),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Queue a report generation task. Returns task_id to poll status."""
    user, membership = current_org

    scan = await db.get(Scan, scan_id)
    if not scan or scan.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan must be completed to generate reports")

    from app.tasks.report_tasks import generate_report_task
    task = generate_report_task.delay(str(scan_id), str(membership.organization_id), format)

    return {"task_id": task.id, "status": "queued", "format": format, "scan_id": str(scan_id)}


@router.get("/status/{task_id}")
async def report_status(
    task_id: str,
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """Check report generation status."""
    from app.tasks.celery_app import celery_app
    result = celery_app.AsyncResult(task_id)

    response = {"task_id": task_id, "status": result.status.lower()}

    if result.status == "SUCCESS" and result.result:
        response.update(result.result)
    elif result.status == "FAILURE":
        response["error"] = str(result.result) if result.result else "Generation failed"

    return response


@router.get("/download/{task_id}")
async def download_report(
    task_id: str,
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """Download a generated report file."""
    from app.tasks.celery_app import celery_app
    result = celery_app.AsyncResult(task_id)

    if result.status != "SUCCESS" or not result.result:
        raise HTTPException(status_code=404, detail="Report not ready or not found")

    file_path = result.result.get("file_path")
    filename = result.result.get("filename")
    content_type = result.result.get("content_type", "application/octet-stream")

    if not file_path:
        raise HTTPException(status_code=404, detail="Report file not found")

    import os
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report file no longer available")

    return FileResponse(
        path=file_path,
        filename=filename,
        media_type=content_type,
    )
