# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import hashlib
import uuid

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.api_key import ApiKey
from app.models.membership import Membership
from app.models.user import User
from app.utils.jwt import decode_token

# auto_error=False so we can fall back to the access_token cookie when
# the Authorization header is absent.
bearer_scheme = HTTPBearer(auto_error=False)


def _extract_access_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
) -> str | None:
    """Prefer the httpOnly cookie (web), fall back to Bearer (SDK / CLI)."""
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token
    if credentials and credentials.credentials:
        return credentials.credentials
    return None


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate the current user from cookie or Bearer token."""
    token = _extract_access_token(request, credentials)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    try:
        parsed_id = uuid.UUID(user_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    stmt = (
        select(User)
        .options(selectinload(User.memberships))
        .where(User.id == parsed_id)
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return user


async def get_current_org(
    current_user: User = Depends(get_current_user),
) -> tuple[User, Membership]:
    """Get the current user and their active organization membership.

    For multi-org users, defaults to the first membership.
    Clients can specify org via X-Organization-Id header in the future.
    """
    if not current_user.memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not a member of any organization",
        )

    membership = current_user.memberships[0]
    return current_user, membership


async def get_current_user_org(
    current_user: User = Depends(get_current_user),
) -> tuple[User, uuid.UUID]:
    """Sugar dependency: return (user, organization_id) directly."""
    if not current_user.memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not a member of any organization",
        )
    return current_user, current_user.memberships[0].organization_id


async def get_api_key_org(
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> tuple[ApiKey, uuid.UUID]:
    """Authenticate via API key (Bearer token starting with 'nis2_').
    Returns (api_key, organization_id) for CI/CD integrations."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    raw_key = credentials.credentials
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    result = await db.execute(
        select(ApiKey).where(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active,
        )
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
        )

    from datetime import datetime, timezone
    api_key.last_used_at = datetime.now(timezone.utc)
    await db.flush()

    return api_key, api_key.organization_id
