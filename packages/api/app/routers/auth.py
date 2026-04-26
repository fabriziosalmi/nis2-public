# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import JWTError
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
from app.models.revoked_token import RevokedToken
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    UserUpdate,
)
from app.utils.jwt import create_access_token, create_refresh_token, decode_token

router = APIRouter(prefix="/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
limiter = Limiter(key_func=get_remote_address)


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
    samesite = "lax"
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


async def _bypass_rls_for_bootstrap(db: AsyncSession | None) -> None:
    """Auth bootstrap routes (register/login/refresh) run before the user has
    a session, so IdentityMiddleware has not set `app.current_org_id`. The
    tenant_isolation policy's `WITH CHECK` would then block writes to
    `memberships` (and any other tenant-scoped table touched here) and the
    `USING` clause would silently filter SELECTs to zero rows. We bypass
    RLS for these specific routes — the application-layer logic is fully
    in control of which user/org is being touched.

    No-ops on SQLite (RLS is Postgres-only) and on unit-test sessions
    where `db` is overridden to None.
    """
    if not IS_POSTGRES or db is None:
        return
    await db.execute(text("SET LOCAL app.bypass_rls = 'on'"))


def _slugify(name: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", name.lower().strip())
    slug = re.sub(r"[\s_]+", "-", slug)
    return slug[:128]


def _build_token_response(
    response: Response,
    user: User,
    organization_id: uuid.UUID | None,
    role: str | None,
) -> TokenResponse:
    """Issue tokens, set cookies, build the JSON body."""
    token_data: dict[str, str] = {"sub": str(user.id)}
    if organization_id is not None:
        token_data["org_id"] = str(organization_id)
    if role is not None:
        token_data["role"] = role

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    csrf_token = secrets.token_urlsafe(32)

    _set_auth_cookies(response, access_token, refresh_token, csrf_token)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        csrf_token=csrf_token,
        user=UserResponse.model_validate(user),
        org_id=str(organization_id) if organization_id else None,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(
    request: Request,
    response: Response,
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    await _bypass_rls_for_bootstrap(db)
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

    membership = Membership(
        user_id=user.id,
        organization_id=org.id,
        role="admin",
        accepted_at=datetime.now(timezone.utc),
    )
    db.add(membership)
    await db.flush()

    return _build_token_response(response, user, org.id, "admin")


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    await _bypass_rls_for_bootstrap(db)
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

    user.last_login_at = datetime.now(timezone.utc)
    await db.flush()

    memberships_result = await db.execute(
        select(Membership).where(Membership.user_id == user.id)
    )
    membership = memberships_result.scalars().first()

    org_id = membership.organization_id if membership else None
    role = membership.role if membership else None
    return _build_token_response(response, user, org_id, role)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("20/minute")
async def refresh(
    request: Request,
    response: Response,
    payload: RefreshRequest | None = None,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    await _bypass_rls_for_bootstrap(db)
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

    memberships_result = await db.execute(
        select(Membership).where(Membership.user_id == user.id)
    )
    membership = memberships_result.scalars().first()
    org_id = membership.organization_id if membership else None
    role = membership.role if membership else None

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

    return _build_token_response(response, user, org_id, role)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Clear all auth cookies and revoke the current refresh token, if any.

    Idempotent — safe to call when not logged in (returns 204 either way).
    """
    # revoked_tokens has no organization_id column so RLS doesn't apply,
    # but bypassing keeps behaviour identical regardless of session state.
    await _bypass_rls_for_bootstrap(db)
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
    for field, value in update_data.items():
        setattr(current_user, field, value)
    await db.flush()
    return UserResponse.model_validate(current_user)
