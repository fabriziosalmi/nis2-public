# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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


# v2.4.26 audit: canonical scope vocabulary.
#
# Pre-2.4.26 the API accepted any list of strings as `scopes` —
# `["yolo", "", "scan:read"]` was a valid request. The UI then showed
# the bogus scope to the user, who reasonably assumed the platform
# enforced it. The first half of the gap (validation at create time)
# is closed in this patch; route-level enforcement of these scopes is
# a separate, larger behavioral change tracked for a follow-up.
#
# The vocabulary mirrors the implicit shape the project already uses
# in `ApiKeyCreate.default` and the audit_log details — `<resource>:<verb>`
# where verb is `read` or `write`. Adding a scope here is a one-line
# change and ALWAYS additive (removing one would break existing keys).
VALID_API_KEY_SCOPES: frozenset[str] = frozenset(
    {
        "scan:read",
        "scan:write",
        "asset:read",
        "asset:write",
        "finding:read",
        "finding:write",
        "report:read",
        "report:write",
    }
)


def _validate_scopes(scopes: Optional[list[str]]) -> list[str]:
    """Raise HTTPException(400) on any unknown / empty / duplicate scope.

    Returns the canonical list (deduplicated, order-preserved) on success.
    None is treated as 'no override' — the schema default is applied
    elsewhere; callers that pass None get None back.
    """
    if scopes is None:
        return None  # type: ignore[return-value]
    if not isinstance(scopes, list):
        raise HTTPException(status_code=400, detail="scopes must be a list of strings")
    if not scopes:
        raise HTTPException(
            status_code=400,
            detail="scopes must not be empty (omit the field to use the default set)",
        )
    seen: set[str] = set()
    cleaned: list[str] = []
    for s in scopes:
        if not isinstance(s, str) or not s.strip():
            raise HTTPException(
                status_code=400,
                detail="scopes contains an empty or non-string value",
            )
        s = s.strip()
        if s not in VALID_API_KEY_SCOPES:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"unknown scope '{s}'. Allowed: "
                    f"{', '.join(sorted(VALID_API_KEY_SCOPES))}"
                ),
            )
        if s in seen:
            # A duplicate is almost certainly user error (UI bug or
            # copy/paste); reject rather than silently dedupe so the
            # caller knows.
            raise HTTPException(
                status_code=400,
                detail=f"duplicate scope '{s}'",
            )
        seen.add(s)
        cleaned.append(s)
    return cleaned


# --- Schemas ---


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    scopes: Optional[list[str]] = Field(
        default=["scan:read", "scan:write", "report:read"]
    )


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
        select(ApiKey)
        .where(ApiKey.organization_id == org_id)
        .order_by(ApiKey.created_at.desc())
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

    # v2.4.26 audit: validate scopes against the canonical vocabulary.
    # On 400 the route returns before any DB write, so a bad request
    # leaves no orphan key row.
    cleaned_scopes = _validate_scopes(payload.scopes)

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
        scopes=cleaned_scopes,
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
        details={"name": payload.name, "prefix": key_prefix, "scopes": cleaned_scopes},
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
