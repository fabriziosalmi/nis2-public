# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
API Key management and authentication for CI/CD integrations.
Uses the existing ApiKey model to provide key lifecycle management
and a dependency for API key-based auth (alternative to JWT).
"""
import hashlib
import secrets
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_org, require_role
from app.middleware.audit import log_action
from app.models.api_key import ApiKey
from app.models.membership import Membership
from app.models.user import User

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


# --- Schemas ---

class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    scopes: Optional[list[str]] = Field(default=["scan:read", "scan:write", "report:read"])

class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: Optional[list[str]] = None
    is_active: bool
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime
    model_config = {"from_attributes": True}

class ApiKeyCreated(ApiKeyResponse):
    """Only returned on creation — includes the full key (shown once)."""
    raw_key: str

class ApiKeyListResponse(BaseModel):
    items: list[ApiKeyResponse]
    total: int


# --- Router ---

@router.get(
    "",
    response_model=ApiKeyListResponse,
    # Audit B12: viewers should not see the org's CI/CD integration
    # inventory. The key prefix + last_used_at + name are still
    # useful info-leak material for an attacker scoping the org.
    dependencies=[Depends(require_role("admin", "auditor"))],
)
async def list_api_keys(
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> ApiKeyListResponse:
    user, membership = current_org
    org_id = membership.organization_id
    result = await db.execute(
        select(ApiKey).where(ApiKey.organization_id == org_id).order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()
    return ApiKeyListResponse(
        items=[ApiKeyResponse.model_validate(k) for k in keys],
        total=len(keys),
    )


@router.post(
    "",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin"))],
)
async def create_api_key(
    payload: ApiKeyCreate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> ApiKeyCreated:
    user, membership = current_org

    # Generate key: nis2_<40 random chars>
    raw_key = f"nis2_{secrets.token_urlsafe(30)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:12]

    api_key = ApiKey(
        organization_id=membership.organization_id,
        created_by=user.id,
        name=payload.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        scopes=payload.scopes,
        is_active=True,
    )
    db.add(api_key)
    await db.flush()
    # Refresh so DB-side defaults (created_at) are present before
    # Pydantic serialises — same lazy-load greenlet bug as scans.create.
    await db.refresh(api_key)

    await log_action(
        db,
        org_id=membership.organization_id,
        user_id=user.id,
        action="api_key.created",
        resource_type="api_key",
        resource_id=str(api_key.id),
        details={"name": payload.name, "prefix": key_prefix, "scopes": payload.scopes},
    )

    # Pydantic v2 doesn't accept `update=` on `model_validate`. Build the
    # response by validating into the base shape, then constructing the
    # extended one with the raw_key. This is the only place the plaintext
    # is allowed to leave the server.
    base = ApiKeyResponse.model_validate(api_key)
    return ApiKeyCreated(**base.model_dump(), raw_key=raw_key)


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role("admin"))],
)
async def revoke_api_key(
    key_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    user, membership = current_org

    api_key = await db.get(ApiKey, key_id)
    if not api_key or api_key.organization_id != membership.organization_id:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_active = False
    await db.flush()

    await log_action(
        db,
        org_id=membership.organization_id,
        user_id=user.id,
        action="api_key.revoked",
        resource_type="api_key",
        resource_id=str(api_key.id),
        details={"name": api_key.name, "prefix": api_key.key_prefix},
    )
