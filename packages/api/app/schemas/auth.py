# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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


class AcceptInviteRequest(BaseModel):
    """P0-02 audit fix (v2.5.5): lets an invited user set their password
    and activate their account. The email must match a pre-existing
    is_active=False user created by the invite_member flow."""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=1, max_length=256)


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


class ChangePasswordRequest(BaseModel):
    """
    Audit B04: previously the FE sent `current_password` + `new_password`
    to PATCH /auth/me, where `UserUpdate` silently dropped both unknown
    fields and the password was never changed. The toast still said
    "passwordUpdated". This dedicated schema makes the contract explicit
    and lets the route validate before any DB mutation.
    """
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


class ForgotPasswordRequest(BaseModel):
    """Audit B05: kicks off the reset-by-email flow. The route ALWAYS
    returns 204 regardless of whether the email exists, so this is the
    only data we accept on the wire — no extra metadata that could be
    used to enumerate registered emails."""
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Audit B05: completes the reset flow with the raw token from the
    emailed link plus the user's chosen new password. Floor of 8 chars
    matches RegisterRequest and ChangePasswordRequest so all three
    password-setting surfaces enforce the same minimum."""
    token: str = Field(..., min_length=20, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


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


class SwitchOrgRequest(BaseModel):
    """Audit B-DRA-02 (v2.4.16): switch the active organization.

    The platform is multi-tenant — a single user can hold memberships
    in any number of orgs (typically a NIS2 consultant managing several
    clients). The active org is baked into the JWT's `org_id` claim
    and read by every RLS-scoped request, so changing it requires
    minting a new token rather than mutating client state. The web UI
    posts here from the org-switcher dropdown; SDK / CLI consumers can
    call it the same way.
    """
    organization_id: uuid.UUID
