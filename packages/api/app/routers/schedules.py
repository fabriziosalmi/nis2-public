# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_org
from app.models.membership import Membership
from app.models.scan_schedule import ScanSchedule
from app.models.user import User
from app.utils.cron import CronValidationError, validate_cron


class ScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    cron_expression: str = Field(..., min_length=5, max_length=100, examples=["0 9 * * 1-5"])
    asset_ids: list[uuid.UUID]
    scan_type: str = Field("full", pattern="^(full|quick|custom)$")
    features: Optional[dict] = None
    is_active: bool = True


class ScheduleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    cron_expression: Optional[str] = Field(None, min_length=5)
    is_active: Optional[bool] = None
    features: Optional[dict] = None


class ScheduleResponse(BaseModel):
    id: uuid.UUID
    name: str
    cron_expression: str
    config: dict
    is_active: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


router = APIRouter(prefix="/schedules", tags=["schedules"])


@router.get("", response_model=list[ScheduleResponse])
async def list_schedules(
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> list[ScheduleResponse]:
    user, membership = current_org
    result = await db.execute(
        select(ScanSchedule)
        .where(ScanSchedule.organization_id == membership.organization_id)
        .order_by(ScanSchedule.created_at.desc())
    )
    schedules = result.scalars().all()
    return [ScheduleResponse.model_validate(s) for s in schedules]


@router.post("", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScheduleCreate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> ScheduleResponse:
    user, membership = current_org

    if membership.role not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # v2.4.26 audit: validate the full cron expression (not just the
    # field count). Pre-2.4.26 the API accepted "99 99 99 99 99" and
    # the schedule silently never fired because the parser in
    # scan_tasks._should_run swallows exceptions. Now bad input is
    # rejected at create time with a message pointing at the
    # offending field.
    try:
        validate_cron(payload.cron_expression)
    except CronValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid cron expression: {exc}",
        )

    config = {
        "asset_ids": [str(a) for a in payload.asset_ids],
        "scan_type": payload.scan_type,
        "features": payload.features or {
            "dns_checks": True, "web_checks": True,
            "port_scan": True, "whois_checks": True,
        },
    }

    schedule = ScanSchedule(
        organization_id=membership.organization_id,
        created_by=user.id,
        name=payload.name,
        cron_expression=payload.cron_expression,
        config=config,
        is_active=payload.is_active,
    )
    db.add(schedule)
    await db.flush()

    return ScheduleResponse.model_validate(schedule)


@router.patch("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: uuid.UUID,
    payload: ScheduleUpdate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> ScheduleResponse:
    user, membership = current_org

    schedule = await db.get(ScanSchedule, schedule_id)
    if not schedule or schedule.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Schedule not found")

    update_data = payload.model_dump(exclude_unset=True)

    # v2.4.26 audit: same cron validation as create_schedule. Pre-2.4.26
    # a PATCH could clobber a valid schedule with a parse-fail string,
    # silently bricking a previously-working scheduled scan. The check
    # runs before any mutation so a 400 leaves the existing row intact.
    new_cron = update_data.get("cron_expression")
    if new_cron is not None:
        try:
            validate_cron(new_cron)
        except CronValidationError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid cron expression: {exc}",
            )

    for field, value in update_data.items():
        if field == "features" and value is not None:
            config = schedule.config or {}
            config["features"] = value
            schedule.config = config
        else:
            setattr(schedule, field, value)

    await db.flush()
    return ScheduleResponse.model_validate(schedule)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    user, membership = current_org

    schedule = await db.get(ScanSchedule, schedule_id)
    if not schedule or schedule.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Schedule not found")

    await db.delete(schedule)
    await db.flush()


@router.post("/{schedule_id}/run", status_code=status.HTTP_202_ACCEPTED)
async def trigger_schedule(
    schedule_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
):
    """Trigger an immediate run of a scheduled scan."""
    user, membership = current_org

    schedule = await db.get(ScanSchedule, schedule_id)
    if not schedule or schedule.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="Schedule not found")

    from app.tasks.scan_tasks import run_scheduled_scan_task
    task = run_scheduled_scan_task.delay(str(schedule.id))

    return {"task_id": task.id, "status": "queued", "schedule_id": str(schedule_id)}
