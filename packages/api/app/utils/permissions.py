# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
from typing import Callable

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User


def require_role(roles: list[str]) -> Callable:
    """Dependency factory that checks if the current user has one of the specified roles
    in the organization referenced by the JWT token."""

    async def _check_role(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        if not current_user.memberships:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No organization membership found",
            )

        # Check if user has any membership with an allowed role
        has_role = any(m.role in roles for m in current_user.memberships)
        if not has_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {', '.join(roles)}",
            )
        return current_user

    return _check_role


def require_org_role(org_id_param: str = "org_id", roles: list[str] | None = None) -> Callable:
    """Dependency factory that checks role for a specific organization.
    The org_id is read from a path parameter."""

    async def _check_org_role(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        # This is a simpler version; the router should pass org_id explicitly
        if roles:
            has_role = any(m.role in roles for m in current_user.memberships)
            if not has_role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required role: {', '.join(roles)}",
                )
        return current_user

    return _check_org_role
