# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Reports API.

v2.4.19 audit hardening:

  - **Cross-tenant authorization (audit reports-001)**. The
    `/status/{task_id}` and `/download/{task_id}` endpoints
    previously trusted any authenticated user to fetch any
    task — a user from org A could enumerate task UUIDs and
    download org B's reports. Now `generate_report_task` stamps
    `org_id` into its result dict, and both endpoints verify
    that `result.org_id == caller's membership.organization_id`
    before returning anything (404 — same response as a
    not-found task — to keep the existence-of-the-task private
    across orgs).
  - **Rate limit on /generate (audit reports-018)**. 5 requests
    per minute per IP. Report generation is expensive (a 50k-
    finding scan can take 30s of CPU on a worker); without a
    limit a single client could pin every Celery worker. Same
    bucket as the /auth/login limiter so we don't have to
    register two slowapi instances.
  - **Sanitised error messages (audit reports-004)**. The
    previous version returned `str(result.result)` on FAILURE,
    leaking internal exception text (e.g. `Permission denied:
    /tmp/nis2-reports`) to the client. We now log the detail
    server-side and return a generic "Report generation failed"
    string to the client — operators read the worker logs to
    diagnose, end users get something actionable.
"""
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_org
from app.models.membership import Membership
from app.models.scan import Scan
from app.models.user import User
from app.routers.auth import limiter  # share the single Limiter instance

router = APIRouter(prefix="/reports", tags=["reports"])
logger = logging.getLogger(__name__)


def _check_task_belongs_to_org(result_payload: dict | None, org_id: uuid.UUID) -> None:
    """Raise 404 if the task result is missing, hasn't completed,
    or belongs to a different organization than the caller's.

    Surfacing 404 (rather than 403) on cross-tenant attempts keeps
    task-id existence private — an attacker enumerating UUIDs
    can't tell whether a UUID maps to a real task in another org
    versus a UUID that doesn't exist. Same discipline we use for
    `Scan not found` on the scan-detail endpoint."""
    if not isinstance(result_payload, dict):
        raise HTTPException(status_code=404, detail="Report not ready or not found")
    task_org = result_payload.get("org_id")
    if not task_org or task_org != str(org_id):
        # Don't leak that the task exists; pretend it doesn't.
        raise HTTPException(status_code=404, detail="Report not ready or not found")


@router.post("/generate")
@limiter.limit("5/minute")
async def generate_report(
    request: Request,
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
    """Check report generation status.

    On success (when the worker has finished), the response
    includes file metadata IF the calling org matches the
    org the report was generated for. Cross-org access returns
    404 — same shape as "task not found" — so an attacker
    cannot enumerate task UUIDs across tenants.
    """
    user, membership = current_org

    from app.tasks.celery_app import celery_app
    result = celery_app.AsyncResult(task_id)

    response = {"task_id": task_id, "status": result.status.lower()}

    if result.status == "SUCCESS" and result.result:
        # Cross-tenant guard: only return file metadata to the
        # org that generated the report. Other orgs see "not ready".
        _check_task_belongs_to_org(result.result, membership.organization_id)
        # Strip the internal `org_id` field from the public payload —
        # it's an implementation detail, not something the client
        # needs (and exposing it makes the cross-tenant check feel
        # circumventable even though it isn't).
        public = {k: v for k, v in result.result.items() if k != "org_id"}
        response.update(public)
    elif result.status == "FAILURE":
        # Don't leak internal exception text to the client.
        # Operators read the worker logs to diagnose; the client
        # sees a generic message they can act on (retry, contact
        # support).
        if result.result:
            logger.warning("Report task %s failed: %s", task_id, result.result)
        response["error"] = "Report generation failed"

    return response


@router.get("/download/{task_id}")
async def download_report(
    task_id: str,
    current_org: tuple[User, Membership] = Depends(get_current_org),
):
    """Download a generated report file.

    Cross-tenant access returns 404 (see `/status` for the
    rationale).
    """
    user, membership = current_org

    from app.tasks.celery_app import celery_app
    result = celery_app.AsyncResult(task_id)

    if result.status != "SUCCESS" or not result.result:
        raise HTTPException(status_code=404, detail="Report not ready or not found")

    # Cross-tenant guard. Done BEFORE we touch the filesystem so a
    # cross-org probe can't even infer file existence via timing.
    _check_task_belongs_to_org(result.result, membership.organization_id)

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
