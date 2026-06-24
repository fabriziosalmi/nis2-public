# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import asyncio
import hashlib
import logging
import random
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from jwt import InvalidTokenError as JWTError
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import IS_POSTGRES, get_db
from app.dependencies import get_current_user
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.password_reset_token import PasswordResetToken
from app.models.revoked_token import RevokedToken
from app.models.user import User
from app.utils.email import get_dev_outbox, send_email
import pyotp

from app.schemas.auth import (
    AcceptInviteRequest,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MFARequiredResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    SwitchOrgRequest,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    TOTPVerifyResponse,
    TokenResponse,
    UserResponse,
    UserUpdate,
)
from app.utils.jwt import create_access_token, create_refresh_token, decode_token

router = APIRouter(prefix="/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)


def _hash_reset_token(raw: str) -> str:
    """sha256 hex digest. The DB never sees the raw token; an attacker
    with read access to password_reset_tokens still cannot reset accounts."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------
# httpOnly access/refresh cookies neutralise the XSS-token-exfil class of bug
# that Zustand-in-localStorage exposed. The csrf_token cookie is intentionally
# JS-readable: the SPA echoes it as the X-CSRF-Token header on state-changing
# requests so CSRFMiddleware can validate the double-submit.

ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"
CSRF_COOKIE = "csrf_token"
REFRESH_COOKIE_PATH = "/api/v1/auth"


def _cookie_secure() -> bool:
    return settings.environment == "production"


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: str,
) -> None:
    secure = _cookie_secure()
    samesite = "strict"
    access_max_age = settings.access_token_expire_minutes * 60
    refresh_max_age = settings.refresh_token_expire_days * 86400

    response.set_cookie(
        ACCESS_COOKIE,
        access_token,
        httponly=True,
        secure=secure,
        samesite=samesite,
        max_age=access_max_age,
        path="/",
    )
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        httponly=True,
        secure=secure,
        samesite=samesite,
        max_age=refresh_max_age,
        path=REFRESH_COOKIE_PATH,
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        httponly=False,  # readable by JS; that's the whole point
        secure=secure,
        samesite=samesite,
        max_age=access_max_age,
        path="/",
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_COOKIE_PATH)
    response.delete_cookie(CSRF_COOKIE, path="/")


async def _is_jti_revoked(db: AsyncSession, jti: str) -> bool:
    result = await db.execute(select(RevokedToken).where(RevokedToken.jti == jti))
    return result.scalar_one_or_none() is not None


async def _revoke_jti(
    db: AsyncSession,
    jti: str,
    expires_at: datetime,
    user_id: Optional[uuid.UUID] = None,
    reason: str = "logout",
) -> None:
    """Add a refresh-token jti to the revocation list. No-op on duplicate."""
    existing = await db.execute(select(RevokedToken).where(RevokedToken.jti == jti))
    if existing.scalar_one_or_none():
        return
    db.add(RevokedToken(jti=jti, expires_at=expires_at, user_id=user_id, reason=reason))
    await db.flush()


async def _set_session_user_id(db: AsyncSession | None, user_id: uuid.UUID) -> None:
    if IS_POSTGRES and db is not None:
        await db.execute(
            text("SELECT set_config('app.current_user_id', :v, true)"),
            {"v": str(user_id)},
        )


async def _set_session_org_id(db: AsyncSession | None, org_id: uuid.UUID) -> None:
    if IS_POSTGRES and db is not None:
        await db.execute(
            text("SELECT set_config('app.current_org_id', :v, true)"),
            {"v": str(org_id)},
        )


# v2.4.18: `_slugify` moved to `app/utils/slug.py` (now `slugify`)
# so `routers/organizations.py` can use the same logic for the new
# create-org endpoint without duplicating code.
from app.utils.slug import slugify as _slugify  # noqa: E402,F401


def _build_token_response(
    response: Response,
    user: User,
    organization_id: uuid.UUID | None,
    role: str | None,
    iat_override: datetime | None = None,
    slim: bool = False,
) -> TokenResponse:
    """Issue tokens, set cookies, build the JSON body.

    `iat_override` is used by /change-password to ensure the freshly
    minted tokens carry an `iat` >= the just-stamped
    `user.password_changed_at`, even when both happen in the same
    wall-clock second. Without it, a strictly-less-than check on the
    same-second case would fail half the time depending on microsecond
    rounding.
    """
    token_data: dict[str, str] = {"sub": str(user.id)}
    if organization_id is not None:
        token_data["org_id"] = str(organization_id)
    if role is not None:
        token_data["role"] = role

    access_token = create_access_token(token_data, iat_override=iat_override)
    refresh_token = create_refresh_token(token_data, iat_override=iat_override)
    # v2.5.4 (Tier 2-A): the CSRF token is intentionally re-minted on
    # every call — including from /refresh — so it rotates in lockstep
    # with the refresh-token rotation. A captured CSRF cookie (the
    # cookie is JS-readable by design, so XSS in a same-site context
    # could leak it) therefore has the same short lifetime as the
    # access token rather than surviving for the full refresh-token
    # window. Regression-locked by TestCSRF.test_csrf_token_rotates_on_refresh.
    csrf_token = secrets.token_urlsafe(32)

    _set_auth_cookies(response, access_token, refresh_token, csrf_token)

    return TokenResponse(
        access_token=None if slim else access_token,
        refresh_token=None if slim else refresh_token,
        csrf_token=csrf_token,
        user=UserResponse.model_validate(user),
        org_id=str(organization_id) if organization_id else None,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED
)
@limiter.limit("10/minute")
async def register(
    request: Request,
    response: Response,
    payload: RegisterRequest,
    slim: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        email=payload.email,
        password_hash=pwd_context.hash(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    await db.flush()

    base_slug = _slugify(payload.org_name)
    slug = base_slug
    suffix = 0
    while True:
        existing_org = await db.execute(
            select(Organization).where(Organization.slug == slug)
        )
        if not existing_org.scalar_one_or_none():
            break
        suffix += 1
        slug = f"{base_slug}-{suffix}"

    org = Organization(name=payload.org_name, slug=slug)
    db.add(org)
    await db.flush()

    # Set the session org_id so that inserting into the RLS-protected memberships table is allowed
    await _set_session_org_id(db, org.id)

    membership = Membership(
        user_id=user.id,
        organization_id=org.id,
        role="admin",
        accepted_at=datetime.now(timezone.utc),
    )
    db.add(membership)
    await db.flush()

    # P0-03 audit fix: self-registration implies email ownership in the
    # current architecture (no email verification service). Mark as
    # verified so the field is not decorative.
    user.email_verified = True
    await db.flush()

    return _build_token_response(response, user, org.id, "admin", slim=slim)


# ---------------------------------------------------------------------------
# Accept Invite — P0-02 audit fix (v2.5.5)
# ---------------------------------------------------------------------------


@router.post(
    "/accept-invite", response_model=TokenResponse, status_code=status.HTTP_200_OK
)
@limiter.limit("10/minute")
async def accept_invite(
    request: Request,
    response: Response,
    payload: AcceptInviteRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Activate an invited user's account by setting their password.

    P0-02 audit fix: the invite_member flow now creates users with
    is_active=False and no password_hash. This endpoint is the only way
    for those users to activate their account.

    v2.5.6 security hardening: a cryptographically random invite token
    is now REQUIRED.  The raw token is supplied by the invitee (from
    the invitation link / email).  We hash it with SHA-256 and compare
    (timing-safe) against the stored hash.  This prevents:
      - Account takeover by an attacker who merely knows the email
      - Email enumeration (same error for all failure modes)

    The token is single-use and time-boxed (48 h by default).
    """
    import hashlib
    import hmac

    _generic_error = "Invalid invitation or account already active"

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_generic_error,
        )

    if user.is_active and user.password_hash:
        # Already activated — don't allow re-activation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_generic_error,
        )

    # ── Token verification ──────────────────────────────────────────
    # Hash the raw token the caller supplied and compare against the
    # stored hash.  Use hmac.compare_digest for timing-safety.
    if not user.invite_token_hash:
        # No invite token on record — the user was not invited through
        # the proper flow, or the token was already consumed.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_generic_error,
        )

    supplied_hash = hashlib.sha256(payload.token.encode()).hexdigest()
    if not hmac.compare_digest(supplied_hash, user.invite_token_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_generic_error,
        )

    # Check expiry.
    if user.invite_token_expires_at and user.invite_token_expires_at < datetime.now(
        timezone.utc
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invitation has expired. Please ask an admin to re-invite you.",
        )

    # Set session user_id so we can select user's memberships under RLS
    await _set_session_user_id(db, user.id)

    # ── Membership check ────────────────────────────────────────────
    memberships_result = await db.execute(
        select(Membership).where(Membership.user_id == user.id)
    )
    membership = memberships_result.scalars().first()
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_generic_error,
        )

    # Set session org_id so we can update membership and any audit logging
    await _set_session_org_id(db, membership.organization_id)

    # ── Activate the account ────────────────────────────────────────
    user.password_hash = pwd_context.hash(payload.password)
    user.full_name = payload.full_name
    user.is_active = True
    user.email_verified = True
    user.last_login_at = datetime.now(timezone.utc)
    # Consume the token — single use.
    user.invite_token_hash = None
    user.invite_token_expires_at = None
    membership.accepted_at = datetime.now(timezone.utc)
    await db.flush()

    return _build_token_response(
        response,
        user,
        membership.organization_id,
        membership.role,
    )


@router.post("/login", response_model=TokenResponse | MFARequiredResponse)
@limiter.limit("10/minute")
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    slim: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse | MFARequiredResponse:
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not pwd_context.verify(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    # TOTP / MFA check
    if user.totp_enabled:
        if not payload.totp_code:
            # Signal the client to collect the TOTP code — no cookies set yet.
            return MFARequiredResponse(mfa_required=True, partial=True)  # type: ignore[return-value]
        if not pyotp.TOTP(user.totp_secret).verify(payload.totp_code, valid_window=1):
            recovery_valid = False
            if user.totp_recovery_codes:
                codes_list = user.totp_recovery_codes.split(",")
                input_hash = hashlib.sha256(payload.totp_code.encode()).hexdigest()
                if input_hash in codes_list:
                    recovery_valid = True
                    codes_list.remove(input_hash)
                    user.totp_recovery_codes = (
                        ",".join(codes_list) if codes_list else None
                    )
            if not recovery_valid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code",
                )

    user.last_login_at = datetime.now(timezone.utc)
    await db.flush()

    # Set session user_id so we can select user's memberships under RLS
    await _set_session_user_id(db, user.id)

    memberships_result = await db.execute(
        select(Membership).where(Membership.user_id == user.id)
    )
    membership = memberships_result.scalars().first()

    org_id = membership.organization_id if membership else None
    role = membership.role if membership else None

    if org_id:
        # Set session org_id for audit logging / token response
        await _set_session_org_id(db, org_id)

    return _build_token_response(response, user, org_id, role, slim=slim)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("20/minute")
async def refresh(
    request: Request,
    response: Response,
    payload: RefreshRequest | None = None,
    slim: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    # Prefer the httpOnly cookie (web flow); fall back to body (SDK flow).
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    if not refresh_token and payload is not None:
        refresh_token = payload.refresh_token
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token",
        )

    try:
        token_payload = decode_token(refresh_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if token_payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    jti = token_payload.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload (missing jti)",
        )
    if await _is_jti_revoked(db, jti):
        # Reuse of an already-rotated or logged-out refresh token. The token
        # is cryptographically valid but has been retired; reject and force
        # the client back through /login.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    user_id = token_payload.get("sub")
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

    result = await db.execute(select(User).where(User.id == parsed_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Password-change watermark check: a refresh token issued before
    # the user changed their password must not produce a new access
    # token. Same intent as the equivalent check in get_current_user;
    # without it, a stolen old-password refresh-token cookie could
    # outlive the password rotation by up to refresh_token_expire_days.
    # Compare in epoch seconds — see dependencies.py for the rationale.
    iat_raw = token_payload.get("iat")
    if iat_raw is not None and user.password_changed_at is not None:
        iat_seconds = (
            int(iat_raw)
            if isinstance(iat_raw, (int, float))
            else int(iat_raw.timestamp())
        )
        pwc_seconds = int(user.password_changed_at.timestamp())
        if iat_seconds < pwc_seconds:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token invalidated by password change",
            )

    # Set session user_id so we can select user's memberships under RLS
    await _set_session_user_id(db, user.id)

    memberships_result = await db.execute(
        select(Membership).where(Membership.user_id == user.id)
    )
    membership = memberships_result.scalars().first()
    org_id = membership.organization_id if membership else None
    role = membership.role if membership else None

    if org_id:
        # Set session org_id for audit logging / token response
        await _set_session_org_id(db, org_id)

    # Refresh-token rotation: revoke the token we just consumed before
    # minting the new pair. This guarantees that if the same refresh token
    # is replayed (e.g. by an attacker who stole it), the second use is
    # rejected and the legitimate session — which now holds the rotated
    # token — keeps working.
    exp_unix = token_payload.get("exp")
    if exp_unix:
        await _revoke_jti(
            db,
            jti,
            datetime.fromtimestamp(exp_unix, tz=timezone.utc),
            user_id=parsed_id,
            reason="rotated",
        )

    return _build_token_response(response, user, org_id, role, slim=slim)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Clear all auth cookies and revoke the current refresh token, if any.

    Idempotent — safe to call when not logged in (returns 204 either way).
    """
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    if refresh_token:
        try:
            payload = decode_token(refresh_token)
            jti = payload.get("jti")
            exp_unix = payload.get("exp")
            sub = payload.get("sub")
            user_id: Optional[uuid.UUID] = None
            if sub:
                try:
                    user_id = uuid.UUID(sub)
                except (ValueError, AttributeError):
                    user_id = None
            if jti and exp_unix:
                await _revoke_jti(
                    db,
                    jti,
                    datetime.fromtimestamp(exp_unix, tz=timezone.utc),
                    user_id=user_id,
                    reason="logout",
                )
        except JWTError:
            pass  # already-invalid token; nothing to revoke, just clear cookies

    _clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.patch("/me", response_model=UserResponse)
async def update_me(
    payload: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    update_data = payload.model_dump(exclude_unset=True)
    allowed_fields = {"full_name", "locale", "avatar_url"}
    for field, value in update_data.items():
        if field in allowed_fields:
            setattr(current_user, field, value)
    await db.flush()
    return UserResponse.model_validate(current_user)


# ---------------------------------------------------------------------------
# GDPR data-subject rights — Art. 17 (erasure) + Art. 20 (portability)
# ---------------------------------------------------------------------------
# v2.5.1: pre-2.5.1 the platform's privacy notice (docs/privacy.md)
# advertised these rights but provided no technical mechanism to exercise
# them. A self-hosted deployer who received an Art. 17 erasure request
# could only run raw SQL — that's the gap this section closes.
#
# Erasure model:
#   - Hard-delete the User row + memberships + api_keys + reset tokens.
#   - Pseudonymise (NOT delete) audit_log entries authored by the user:
#     audit logs are a Postgres FORCE-RLS-protected security artefact
#     and the integrity of the trail matters more than the user's
#     identifier on each row. We null user_id and replace ip_address
#     with the loopback marker, which is the same approach Art. 89(1)
#     blesses for "purposes in the public interest, scientific or
#     historical research" (audit security qualifies as legitimate
#     interest under Art. 6(1)(f) for the controller).
#   - Single-admin special case: if the user is the only admin of an
#     organisation that has other members, deletion is refused with
#     409 — the controller would lose admin reachability on a tenant
#     they still operate. Caller must promote another admin first or
#     remove other members. The user can still leave the membership
#     and self-delete with the org intact.
#   - Lone-tenant case (only admin, no other members): the org is
#     deleted along with the user (cascade through memberships /
#     scans / findings / assets / incidents / vendors / bia / api_keys).
#
# Portability model: GET /auth/me/export returns ONLY the data subject's
# personal data and the membership relationships. Tenant data (scans,
# findings, assets) is org-scoped and belongs to the controller of that
# org, not to the user — those are NOT included to avoid leaking other
# members' contributions and to avoid the right-to-portability becoming
# a covert tenant-data-exfil channel. The notice in docs/privacy.md is
# explicit about this scope.


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_me(
    request: Request,
    response: Response,
    payload: ChangePasswordRequest,  # reuse: it's {current_password, new_password}
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """GDPR Art. 17 — right to erasure.

    Hard-deletes the user account, their memberships, their API keys,
    and any password-reset tokens. Pseudonymises (does not delete) any
    audit log entries authored by the user — audit-trail integrity is
    a controller's legitimate interest under Art. 6(1)(f).

    Requires re-confirmation via the current password (the request
    payload reuses ChangePasswordRequest — the `new_password` field is
    ignored here; we only validate `current_password`).

    Returns 409 if the user is the only admin of an organisation with
    other members — caller must promote another admin first.
    """
    # All tenant-data deletions below use raw `text("DELETE FROM ...")`
    # statements rather than ORM cascades — the tables are listed
    # explicitly in `orgs_to_delete` loop and we don't need the model
    # classes for type-driven query building. No imports needed.

    # 1. Re-authenticate. We don't trust the JWT alone for a destructive
    #    irreversible operation — an attacker with a stolen access token
    #    could otherwise delete the user with one POST.
    if not pwd_context.verify(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="currentPasswordIncorrect")

    # Set session user_id so RLS allows selecting and updating user's own data
    await _set_session_user_id(db, current_user.id)

    user_id = current_user.id

    # 3. Resolve memberships and decide single-admin policy.
    res = await db.execute(select(Membership).where(Membership.user_id == user_id))
    memberships = res.scalars().all()

    orgs_to_delete: list[uuid.UUID] = []
    for m in memberships:
        # Fetch all admins of this org other than the current user.
        other_admins = await db.execute(
            select(Membership).where(
                Membership.organization_id == m.organization_id,
                Membership.role == "admin",
                Membership.user_id != user_id,
            )
        )
        other_admin_count = len(other_admins.scalars().all())

        # All members of this org other than the current user.
        other_members = await db.execute(
            select(Membership).where(
                Membership.organization_id == m.organization_id,
                Membership.user_id != user_id,
            )
        )
        other_member_count = len(other_members.scalars().all())

        if m.role == "admin" and other_admin_count == 0 and other_member_count > 0:
            raise HTTPException(
                status_code=409,
                detail=(
                    "You are the only admin of an organisation with other members. "
                    "Promote another admin or remove other members before deleting your account."
                ),
            )

        if other_member_count == 0:
            # Lone tenant — schedule the whole org for deletion.
            orgs_to_delete.append(m.organization_id)

    # 4. Pseudonymise audit log: null user_id, scrub ip_address, clear
    #    details JSONB. The `action` and `resource_type` columns stay so
    #    the audit chain still records "someone did X on this date" without
    #    linking to the erased subject. The `details` column may contain
    #    org UUIDs or role transitions that are indirectly linkable to the
    #    user — nulling it removes that linkage while preserving the event
    #    type for the controller's forensic purposes (Art. 89(1)).
    #
    # GDPR Art. 17 vs NIS2 Art. 21 — explicit resolution:
    #   The controller has a legitimate interest (Art. 6(1)(f)) in retaining
    #   pseudonymised audit events for the duration of AUDIT_LOG_RETENTION_DAYS
    #   (default 90 days). This satisfies GDPR because the event is no longer
    #   attributable to an identified or identifiable person after erasure.
    #   The NIS2 audit-trail obligation is satisfied because the event type and
    #   timestamp survive. Operators managing security incidents MUST raise
    #   AUDIT_LOG_RETENTION_DAYS ≥ 365 to fulfil the NIS2 incident evidence
    #   requirement — see docs/privacy.md §7.2 and config.py.
    await db.execute(
        text(
            "UPDATE audit_logs SET user_id = NULL, ip_address = '127.0.0.1', "
            "user_agent = '[erased]', details = NULL WHERE user_id = :uid"
        ),
        {"uid": str(user_id)},
    )

    # 5. Delete API keys, password reset tokens, memberships.
    await db.execute(
        text("DELETE FROM api_keys WHERE created_by = :uid"),
        {"uid": str(user_id)},
    )
    await db.execute(
        text("DELETE FROM password_reset_tokens WHERE user_id = :uid"),
        {"uid": str(user_id)},
    )
    await db.execute(
        text("DELETE FROM memberships WHERE user_id = :uid"),
        {"uid": str(user_id)},
    )

    # 6. Delete lone-tenant orgs and all their tenant-scoped data.
    for org_id in orgs_to_delete:
        for table in (
            "findings",
            "scan_results",
            "scans",
            "scan_schedules",
            "assets",
            "incidents",
            "vendors",
            "business_processes",
            "api_keys",
            "memberships",
            "audit_logs",
        ):
            await db.execute(
                text(f"DELETE FROM {table} WHERE organization_id = :oid"),
                {"oid": str(org_id)},
            )
        await db.execute(
            text("DELETE FROM organizations WHERE id = :oid"),
            {"oid": str(org_id)},
        )

    # 7. Revoke any active refresh token (current session) so the
    #    deleted user can't re-authenticate with a still-valid cookie.
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    if refresh_token:
        try:
            ptoken = decode_token(refresh_token)
            jti = ptoken.get("jti")
            exp_unix = ptoken.get("exp")
            if jti and exp_unix:
                await _revoke_jti(
                    db,
                    jti,
                    datetime.fromtimestamp(exp_unix, tz=timezone.utc),
                    user_id=None,  # user is being deleted — don't FK to a row about to vanish
                    reason="erasure",
                )
        except JWTError:
            pass

    # 8. Finally, delete the user row itself.
    await db.execute(
        text("DELETE FROM users WHERE id = :uid"),
        {"uid": str(user_id)},
    )

    await db.commit()

    # 9. Clear the client cookies so the next request gets a fresh
    #    unauthenticated state.
    _clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return None


@router.get("/me/export")
async def export_me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """GDPR Art. 20 — right to data portability.

    Returns a JSON document containing the personal data the platform
    holds on the requesting user, in a structured machine-readable
    format. Scope is the user's PERSONAL data only:

      - profile (email, full_name, locale, avatar_url, created_at,
        oauth provider, password_changed_at, ...)
      - memberships (org_id, org_name, role, accepted_at)
      - api keys metadata (NOT the raw secrets — those were shown
        once at creation)
      - audit log entries authored by the user (timestamped trail of
        their own actions)

    Tenant data — scans, findings, assets, incidents, vendors, BIA
    processes — is the controller's, not the user's, so it is NOT
    included. This is consistent with the "you are not the controller
    of self-hosted instances" stance in docs/privacy.md.
    """
    from app.models.api_key import ApiKey
    from app.models.audit_log import AuditLog

    # Set session user_id so RLS allows selecting user's own data
    await _set_session_user_id(db, current_user.id)
    user_id = current_user.id

    # Memberships join organization for human-readable labels.
    mres = await db.execute(
        select(Membership, Organization)
        .join(Organization, Membership.organization_id == Organization.id)
        .where(Membership.user_id == user_id)
    )
    memberships = [
        {
            "organization_id": str(m.organization_id),
            "organization_name": o.name,
            "organization_slug": o.slug,
            "role": m.role,
            "accepted_at": m.accepted_at.isoformat() if m.accepted_at else None,
            "created_at": m.created_at.isoformat() if m.created_at else None,
        }
        for m, o in mres.all()
    ]

    # API keys — metadata only.
    kres = await db.execute(select(ApiKey).where(ApiKey.user_id == user_id))
    api_keys = [
        {
            "id": str(k.id),
            "name": k.name,
            "scopes": list(k.scopes or []),
            "is_active": k.is_active,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            # `key_hash` and `key_prefix` are never returned — the raw
            # secret is only revealed once at creation by design.
        }
        for k in kres.scalars().all()
    ]

    # Audit log entries authored by the user.
    ares = await db.execute(
        select(AuditLog)
        .where(AuditLog.user_id == user_id)
        .order_by(AuditLog.created_at.desc())
    )
    audit_logs = [
        {
            "id": str(a.id),
            "organization_id": str(a.organization_id) if a.organization_id else None,
            "action": a.action,
            "resource_type": a.resource_type,
            "resource_id": str(a.resource_id) if a.resource_id else None,
            "ip_address": a.ip_address,
            "user_agent": a.user_agent,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in ares.scalars().all()
    ]

    return {
        "_meta": {
            "schema_version": "1.0",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exported_for_user_id": str(user_id),
            "scope": (
                "User personal data only. Tenant data (scans, findings, assets, "
                "incidents, vendors, BIA processes) belongs to the controller of "
                "each organisation and is excluded from this export."
            ),
        },
        "profile": {
            "id": str(current_user.id),
            "email": current_user.email,
            "full_name": current_user.full_name,
            "locale": current_user.locale,
            "avatar_url": current_user.avatar_url,
            "is_active": current_user.is_active,
            "email_verified": current_user.email_verified,
            "oauth_provider": getattr(current_user, "oauth_provider", None),
            "oauth_provider_id": getattr(current_user, "oauth_provider_id", None),
            "created_at": current_user.created_at.isoformat()
            if current_user.created_at
            else None,
            "password_changed_at": (
                current_user.password_changed_at.isoformat()
                if getattr(current_user, "password_changed_at", None)
                else None
            ),
        },
        "memberships": memberships,
        "api_keys": api_keys,
        "audit_logs": audit_logs,
    }


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("5/minute")  # protect against credential brute-force
async def change_password(
    request: Request,
    response: Response,
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Audit B04: a real password change.

    Previous behaviour: the FE sent {current_password, new_password} to
    PATCH /auth/me, which routed through `UserUpdate` — a schema that
    only declared {full_name, locale, avatar_url}. Pydantic dropped
    the password fields, the route returned 200, and the toast lied
    that the password was updated. The hash never changed.

    Now: a dedicated endpoint that
      1. verifies the current password with passlib (401 on mismatch),
      2. rejects when the new password equals the old one (no rotation
         is also a footgun — users assume something happened),
      3. hashes and persists the new password,
      4. stamps `password_changed_at = now()`. The JWT decode path then
         rejects every still-active access/refresh token with `iat`
         older than this stamp — every other session for this user is
         immediately invalidated, no per-jti tracking needed.
      5. emits an audit log entry (`user.password_changed`) so the
         compliance team can answer "when did Alice last rotate her
         password" without grepping postgres logs,
      6. rotates the *current* session's cookies so the user keeps
         using the app from the tab where they made the change. Other
         tabs / devices get bounced to /login on their next request.
    """
    # 1. Verify current password. is_active was already checked by
    #    get_current_user; an inactive account can't reach this route.
    if not current_user.password_hash or not pwd_context.verify(
        payload.current_password, current_user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    # 2. Refuse no-op rotations. Someone confused about the form should
    #    get a clear "you typed the same password twice" instead of a
    #    silent success that locks all other sessions for nothing.
    if pwd_context.verify(payload.new_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must differ from the current password",
        )

    # 3 + 4. Persist new hash and bump the watermark.
    #
    # The watermark and the iat of the just-minted tokens must agree
    # to the second so that:
    #   * tokens issued BEFORE this change (any iat <= now) are
    #     strictly less than the watermark and get 401'd,
    #   * tokens issued in this very response are >= the watermark
    #     and pass.
    # We pick `next_second = floor(now) + 1` as both the watermark and
    # the override iat for the new tokens. Without this dance, a token
    # minted in the same wall-clock second as another token in flight
    # could be invalidated by accident — exactly the rounding bug we
    # hit during e2e bring-up.
    now_floor = datetime.now(timezone.utc).replace(microsecond=0)
    next_second = now_floor + timedelta(seconds=1)
    current_user.password_hash = pwd_context.hash(payload.new_password)
    current_user.password_changed_at = next_second
    await db.flush()

    # 5. Audit. Imported lazily here to dodge a circular import — auth
    #    is imported by app.main early; the audit middleware imports
    #    auth bits transitively for token decode.
    from app.middleware.audit import log_action

    membership = current_user.memberships[0] if current_user.memberships else None
    if membership:
        await log_action(
            db,
            org_id=membership.organization_id,
            user_id=current_user.id,
            action="user.password_changed",
            resource_type="user",
            resource_id=str(current_user.id),
            details={"self_initiated": True},
            request=request,
        )

    # 6. Re-issue this session's tokens on the *injected* response so
    #    the active tab keeps working. Without this, the very next
    #    request from this tab would 401 on the iat-watermark check
    #    and bounce the user to /login — surprising and inconsistent
    #    with the "you just confirmed your password" mental model.
    #
    #    Returning None lets FastAPI use the route's status_code=204
    #    while preserving the Set-Cookie headers we just attached.
    #    Constructing a fresh Response(...) with `headers=response.headers`
    #    drops them on the floor in some Starlette versions — never do
    #    that here.
    org_id = membership.organization_id if membership else None
    role = membership.role if membership else None
    _build_token_response(
        response, current_user, org_id, role, iat_override=next_second
    )
    return None


# ---------------------------------------------------------------------------
# Switch active organization (audit B-DRA-02, v2.4.16)
# ---------------------------------------------------------------------------


@router.post("/switch-org", response_model=TokenResponse)
@limiter.limit("10/minute")
async def switch_org(
    request: Request,
    response: Response,
    payload: SwitchOrgRequest,
    slim: bool = Query(False),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Switch the active organization for this session.

    Multi-tenant context: a NIS2 consultant managing 3 clients holds 3
    memberships, but every RLS-scoped query is keyed on the JWT's
    `org_id` claim. Mutating client state is therefore not enough —
    we have to mint a fresh token with the new claim and rotate the
    cookies.

    Contract:
      * 200 + new TokenResponse on success. Cookies are rotated via
        `_build_token_response` (same helper as /login, /register,
        /refresh, /change-password) — the FE picks up the new
        access_token / refresh_token / csrf_token transparently.
      * 403 if the caller has no membership in the target org. We
        surface this as "you are not a member" rather than 404 because
        the org may exist; the membership doesn't.
      * 422 if the org_id isn't a valid UUID (Pydantic enforces this
        before we touch the DB).
      * Rate-limited 10/minute/IP — UI action, not credential surface;
        the limit exists to make brute-force enumeration of org IDs
        uninteresting (combined with the RLS guard, which already
        flatly refuses cross-org reads).

    Audit log entry `user.org_switched` records `from_org_id` and
    `to_org_id` so the compliance team can answer "when did this
    consultant last access the Acme Corp tenant".
    """
    # Resolve the membership for the target org. We pull from the
    # already-eager-loaded `current_user.memberships` rather than a
    # second SQL hit — `get_current_user` does selectinload(memberships)
    # for exactly this kind of follow-up check.
    target_membership: Membership | None = next(
        (
            m
            for m in current_user.memberships
            if m.organization_id == payload.organization_id
        ),
        None,
    )
    if target_membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of the target organization",
        )

    # Capture the previous org_id from the JWT (resolved by
    # get_current_user) so the audit log can record the transition.
    # Falls back to None for legacy tokens minted before v2.4.12
    # started writing org_id into the claims.
    from app.dependencies import _resolve_active_org_id

    previous_org_id = _resolve_active_org_id(request)

    # Audit log entry. We log under the *target* org so it shows up in
    # the org the user is moving to — that's where the security team
    # will look for "who accessed our tenant today". The `from_org_id`
    # in details lets a curious admin trace the path.
    from app.middleware.audit import log_action

    await log_action(
        db,
        org_id=target_membership.organization_id,
        user_id=current_user.id,
        action="user.org_switched",
        resource_type="organization",
        resource_id=str(target_membership.organization_id),
        details={
            "from_org_id": str(previous_org_id) if previous_org_id else None,
            "to_org_id": str(target_membership.organization_id),
            "to_role": target_membership.role,
        },
        request=request,
    )

    # Mint new tokens with the target org_id + the user's role IN that
    # org. The FE's onSuccess handler clears the TanStack Query cache
    # so every screen re-fetches with the new RLS scope; the previous
    # access_token cookie is replaced by Set-Cookie in the response
    # below.
    return _build_token_response(
        response,
        current_user,
        target_membership.organization_id,
        target_membership.role,
        slim=slim,
    )


# ---------------------------------------------------------------------------
# Forgot / reset password (audit B05)
# ---------------------------------------------------------------------------


def _reset_email_text(reset_url: str, ttl_minutes: int) -> tuple[str, str]:
    """Plain-text and HTML bodies for the reset email. Kept inline here
    rather than in a Jinja template — there's exactly one transactional
    template in the system right now and the indirection cost outweighs
    the templating value. When invites land (B06+B07) we'll factor both
    into a `templates/email/` directory."""
    text = (
        "Hello,\n\n"
        "You (or someone using your email) requested a password reset for "
        "the NIS2 Compliance Platform.\n\n"
        f"Use the link below within {ttl_minutes} minutes to choose a new "
        "password:\n\n"
        f"  {reset_url}\n\n"
        "If you did not request this reset, you can safely ignore this "
        "email — your password remains unchanged.\n"
    )
    html = (
        "<p>Hello,</p>"
        "<p>You (or someone using your email) requested a password reset for "
        "the <strong>NIS2 Compliance Platform</strong>.</p>"
        f"<p>Use the link below within <strong>{ttl_minutes} minutes</strong> "
        "to choose a new password:</p>"
        f'<p><a href="{reset_url}">{reset_url}</a></p>'
        "<p>If you did not request this reset, you can safely ignore this "
        "email — your password remains unchanged.</p>"
    )
    return text, html


@router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("5/minute")
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Audit B05 (entry-point).

    Always returns 204 regardless of whether the email exists or the
    email was actually delivered. This eliminates the single most useful
    primitive an attacker has for enumerating registered users
    (response-time / response-body diffs between known and unknown
    addresses).

    Side-effects, in order:
      1. lookup user by email (case-insensitive); if missing, return 204
      2. if found, mint a 32-byte URL-safe token, store its sha256 hash
         with `expires_at = now + reset_token_ttl_minutes`
      3. send the email (or queue it in the dev outbox); a send failure
         is logged but does not change the response — we'd rather have a
         retry than tell the user "we know you exist, but our MTA is down"
      4. neither the audit log nor the response body distinguishes
         "sent" from "would-have-sent-if-this-email-was-known". The
         only signal a legit user gets is the email itself; that's the
         intended UX.

    Bypass RLS for the bookkeeping: same rationale as register/login
    (the user has no session yet, the password_reset_tokens table is
    not tenant-scoped anyway).

    v2.5.4 (Tier 2-B) hardening:
      * The unknown-email path used to early-return after the SELECT,
        so its wall-clock time was 5–20× shorter than the known-email
        path (which generates a token, hashes it, INSERTs, and awaits
        SMTP). Pre-2.5.4 a chatty attacker could still enumerate
        registered emails via response timing alone — defeating the
        whole point of the always-204 contract. Two defenses now run
        on every request:
          (a) the unknown path performs the SAME token + hash work
              as the known path and discards the result, so the CPU
              and DB time profiles are within a few microseconds;
          (b) BOTH paths sleep a randomised duration ≥ typical SMTP
              latency before returning, so the variable cost of the
              real send_email() is masked under the same jitter.
      * The MTA-failure log used to print `user.email`, which (a)
        promotes a transient operational error into a long-lived
        PII record in the application logs and (b) creates a
        secondary enumeration channel. Now logged by user.id only.
    """
    email = payload.email.strip().lower()

    # 1. Lookup. Pydantic EmailStr lowercases the domain part for us
    #    but not the local part; we lowercase the whole thing here to
    #    match the casing convention in /register and /login.
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        # Constant-time defense: do the same CPU and DB-ish work as
        # the known-email branch, then discard. Generating a token
        # and hashing it costs the same regardless of whether we
        # later persist it; the cost is what we're matching.
        _ = _hash_reset_token(secrets.token_urlsafe(32))
        # Latency-jitter defense: typical SMTP send (Mailpit local /
        # transactional provider) sits in the 50–250ms range. We
        # sleep a uniform window over that band so neither tail of
        # the distribution is a reliable enumeration signal.
        await asyncio.sleep(random.uniform(0.05, 0.25))
        return None

    # 2. Mint and persist.
    raw_token = secrets.token_urlsafe(32)  # ~43 chars, well above the 20 schema floor
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.reset_token_ttl_minutes
    )
    token_row = PasswordResetToken(
        user_id=user.id,
        token_hash=_hash_reset_token(raw_token),
        expires_at=expires_at,
    )
    db.add(token_row)
    await db.flush()

    # 3. Send. The link points at the FE route; the FE then POSTs
    #    {token, new_password} back to /reset-password.
    reset_url = f"{settings.public_url.rstrip('/')}/reset-password?token={raw_token}"
    text, html = _reset_email_text(reset_url, settings.reset_token_ttl_minutes)
    try:
        await send_email(
            to=user.email,
            subject="Reset your NIS2 Platform password",
            text=text,
            html=html,
        )
    except Exception:
        # Don't leak the failure to the client — but log it so an
        # operator notices a misconfigured MTA before users do. Log
        # by user.id (not email) so the logs aren't a back-door
        # email-enumeration channel for anyone with log access.
        logger.exception(
            "forgot-password: failed to send reset email (user_id=%s)", user.id
        )

    # Latency-jitter on the known path too — see the timing-constant
    # rationale in the docstring. Without this, the known-path response
    # time would be dominated by send_email() variance and still differ
    # measurably from the unknown path on any given request.
    await asyncio.sleep(random.uniform(0.05, 0.25))
    return None


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("10/minute")
async def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Audit B05 (completion).

    Verifies the emailed token, sets the new password, marks the token
    used, and stamps `password_changed_at` so every other still-active
    session for this user is invalidated. Does NOT auto-login: that
    surface would require us to also issue cookies on a route that
    just took an email-link. Cleaner UX is "go to /login and use your
    new password" — the FE redirects there.

    Token semantics:
      * single-use (used_at non-null = spent)
      * 30-minute TTL by default (settings.reset_token_ttl_minutes)
      * not tenant-scoped (forgot flow runs without org context)
      * removed on success only via used_at; expired rows are pruned
      * out-of-band by a future Celery sweep (table is small, cheap)
    """
    token_hash = _hash_reset_token(payload.token)
    token_result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    )
    token_row = token_result.scalar_one_or_none()

    now = datetime.now(timezone.utc)
    # Single 400 for any of {unknown, used, expired}: don't tell the
    # attacker which of the three is true — same enumeration discipline
    # as forgot-password.
    if (
        token_row is None
        or token_row.used_at is not None
        or token_row.expires_at <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is invalid or has expired",
        )

    user_result = await db.execute(select(User).where(User.id == token_row.user_id))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is invalid or has expired",
        )

    # Persist new password and bump the watermark — same dance as
    # change-password (see that route for the floor(now)+1 rationale).
    next_second = now.replace(microsecond=0) + timedelta(seconds=1)
    user.password_hash = pwd_context.hash(payload.new_password)
    user.password_changed_at = next_second
    token_row.used_at = now
    await db.flush()

    # Audit log so an admin can see "password reset by token at T from IP".
    from app.middleware.audit import log_action

    membership = user.memberships[0] if user.memberships else None
    if membership:
        # Set session org_id so RLS allows inserting into audit_logs
        await _set_session_org_id(db, membership.organization_id)
        await log_action(
            db,
            org_id=membership.organization_id,
            user_id=user.id,
            action="user.password_reset",
            resource_type="user",
            resource_id=str(user.id),
            details={"via": "email_token"},
            request=request,
        )

    return None


# ---------------------------------------------------------------------------
# TOTP / MFA endpoints — NIS2 Art. 21(j)
# ---------------------------------------------------------------------------


@router.post("/totp/setup", response_model=TOTPSetupResponse)
async def totp_setup(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TOTPSetupResponse:
    """Generate a TOTP secret and provisioning URI (step 1 of MFA setup).

    The secret is stored on the user but `totp_enabled` is NOT set yet —
    the caller must confirm possession by calling /totp/verify first.
    """
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA already enabled",
        )
    secret = pyotp.random_base32()
    current_user.totp_secret = secret
    await db.flush()
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        current_user.email, issuer_name="NIS2 Platform"
    )
    return TOTPSetupResponse(secret=secret, provisioning_uri=provisioning_uri)


@router.post("/totp/verify", response_model=TOTPVerifyResponse)
async def totp_verify(
    payload: TOTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TOTPVerifyResponse:
    """Verify a TOTP code and enable MFA on the account (step 2 of MFA setup)."""
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA already enabled",
        )
    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Call /totp/setup first",
        )
    if not pyotp.TOTP(current_user.totp_secret).verify(payload.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code",
        )

    raw_codes = []
    hashed_codes = []
    for _ in range(8):
        code = f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}"
        raw_codes.append(code)
        hashed_code = hashlib.sha256(code.encode()).hexdigest()
        hashed_codes.append(hashed_code)

    current_user.totp_recovery_codes = ",".join(hashed_codes)
    current_user.totp_enabled = True
    await db.flush()
    return TOTPVerifyResponse(mfa_enabled=True, recovery_codes=raw_codes)


@router.post("/totp/disable", response_model=TOTPVerifyResponse)
async def totp_disable(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TOTPVerifyResponse:
    """Disable MFA. Requires re-authentication via current password."""
    if not current_user.password_hash or not pwd_context.verify(
        payload.current_password, current_user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )
    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.totp_recovery_codes = None
    await db.flush()
    return TOTPVerifyResponse(mfa_enabled=False)


# ---------------------------------------------------------------------------
# Development-only debug helper
# ---------------------------------------------------------------------------

if settings.environment != "production":

    @router.get(
        "/debug/last-email",
        # tags lower so the prod OpenAPI doc isn't polluted
        include_in_schema=False,
    )
    async def debug_last_email() -> dict:
        """Returns the most recently captured outgoing email when the
        in-memory dev outbox is active (i.e. SMTP_HOST is unset).

        Exists for the e2e tests: they trigger /forgot-password, then
        read the reset link out of here. Strictly mounted only when
        environment != "production"; the build refuses to start in
        production with SMTP_HOST empty (utils/email.py raises), so
        this surface can never coexist with a real MTA.
        """
        outbox = get_dev_outbox()
        if not outbox:
            raise HTTPException(status_code=404, detail="No emails captured")
        return outbox[-1]
