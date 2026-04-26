# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.membership import Membership


async def validate_org_access(
    db: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID
) -> Membership | None:
    """Validate that a user has membership in the specified organization.

    Returns the Membership record if valid, None otherwise.
    """
    result = await db.execute(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.organization_id == org_id,
        )
    )
    return result.scalar_one_or_none()


async def validate_org_role(
    db: AsyncSession,
    user_id: uuid.UUID,
    org_id: uuid.UUID,
    required_roles: list[str],
) -> Membership | None:
    """Validate that a user has one of the required roles in an organization.

    Returns the Membership record if authorized, None otherwise.
    """
    membership = await validate_org_access(db, user_id, org_id)
    if membership and membership.role in required_roles:
        return membership
    return None
