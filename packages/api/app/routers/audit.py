# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Audit log read API.

The audit_logs table is populated by app.middleware.audit on every
2xx state-changing request, plus by explicit `log_action(...)` calls
from sensitive routes. This router exposes a paginated, org-scoped
read view so the UI in settings/audit-log can render real data.

Audit B03: previous version of the UI was 100% mocked because no API
endpoint existed; the screen lied to auditors.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.dependencies import get_current_org, require_role
from app.models.audit_log import AuditLog
from app.models.membership import Membership
from app.models.user import User

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])


class AuditActor(BaseModel):
    id: Optional[uuid.UUID] = None
    email: Optional[str] = None
    full_name: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Optional[dict] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime
    actor: AuditActor

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int


@router.get(
    "",
    response_model=AuditLogListResponse,
    # Audit B12 sibling rule: audit-log read is an admin/auditor concern
    # by definition. A viewer doesn't need (and shouldn't see) the
    # IP-trail and user-agent column.
    dependencies=[Depends(require_role("admin", "auditor"))],
)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None, description="Exact match on action, e.g. 'member.role_changed'"),
    resource_type: Optional[str] = Query(None),
    user_id: Optional[uuid.UUID] = Query(None, description="Filter by actor user id"),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> AuditLogListResponse:
    user, membership = current_org
    org_id = membership.organization_id

    # Base scope: only this org's logs. RLS would enforce this anyway,
    # but an explicit WHERE makes the SQL plan obvious in EXPLAIN.
    base = select(AuditLog).where(AuditLog.organization_id == org_id)
    count_q = select(func.count(AuditLog.id)).where(AuditLog.organization_id == org_id)

    if action:
        base = base.where(AuditLog.action == action)
        count_q = count_q.where(AuditLog.action == action)
    if resource_type:
        base = base.where(AuditLog.resource_type == resource_type)
        count_q = count_q.where(AuditLog.resource_type == resource_type)
    if user_id:
        base = base.where(AuditLog.user_id == user_id)
        count_q = count_q.where(AuditLog.user_id == user_id)

    base = (
        base.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )

    total_result = await db.execute(count_q)
    total = total_result.scalar() or 0

    rows_result = await db.execute(base)
    rows = rows_result.scalars().all()

    # Hydrate actor info in one batch round-trip rather than a per-row
    # selectinload (audit_logs.user_id is nullable — system-emitted
    # entries have no actor — and the default selectinload would issue
    # a separate SELECT per page even for `None` ids).
    actor_ids = {r.user_id for r in rows if r.user_id is not None}
    actors_by_id: dict[uuid.UUID, User] = {}
    if actor_ids:
        actors_result = await db.execute(
            select(User).where(User.id.in_(actor_ids))
        )
        actors_by_id = {u.id: u for u in actors_result.scalars().all()}

    def to_response(row: AuditLog) -> AuditLogResponse:
        actor = actors_by_id.get(row.user_id) if row.user_id else None
        return AuditLogResponse(
            id=row.id,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            details=row.details or {},
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            created_at=row.created_at,
            actor=AuditActor(
                id=actor.id if actor else None,
                email=actor.email if actor else None,
                full_name=actor.full_name if actor else None,
            ),
        )

    return AuditLogListResponse(
        items=[to_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )
