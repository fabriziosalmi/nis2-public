# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field

from app.schemas.auth import UserResponse


class OrgResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    plan: str
    settings: dict[str, Any] = {}
    max_scans_per_month: int = 50
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class OrgUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    settings: Optional[dict[str, Any]] = None


class MemberResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    role: str
    accepted_at: Optional[datetime] = None
    user: Optional[UserResponse] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role: str = Field(default="viewer", pattern="^(admin|auditor|viewer)$")


# v2.4.12: role-change moved from Query("?role=admin") to a JSON body
# so the frontend's `body: JSON.stringify({role})` actually works.
# Audit B08.
class RoleUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|auditor|viewer)$")
