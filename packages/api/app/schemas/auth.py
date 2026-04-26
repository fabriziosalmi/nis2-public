# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=1, max_length=256)
    org_name: str = Field(..., min_length=1, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    locale: str
    avatar_url: Optional[str] = None
    email_verified: bool = False
    is_active: bool = True
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=256)
    locale: Optional[str] = Field(None, max_length=10)
    avatar_url: Optional[str] = Field(None, max_length=1024)


class TokenResponse(BaseModel):
    """
    Response shape for /login, /register, /refresh.

    The web client receives `access_token` and `refresh_token` as
    httpOnly cookies (set by the route via Set-Cookie). They are also
    returned in the body so SDK and CLI clients can use Bearer auth.
    `csrf_token` is the value of the readable csrf_token cookie; the
    frontend echoes it as the `X-CSRF-Token` header on state-changing
    requests (double-submit cookie pattern).
    """
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    csrf_token: str
    user: UserResponse
    org_id: Optional[str] = None


class RefreshRequest(BaseModel):
    """
    Body is optional now: if cookies are present, /refresh reads
    refresh_token from the httpOnly cookie. SDKs can still POST it.
    """
    refresh_token: Optional[str] = None
