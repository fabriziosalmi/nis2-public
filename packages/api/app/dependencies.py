# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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


async def _decode_access_token(token: str) -> dict:
    """Validate the access cookie/Bearer and return its payload.

    Centralised so `get_current_user` and `get_current_org` resolve the
    same payload from the same token — the previous version decoded in
    `get_current_user` only and threw the org_id claim away by the time
    `get_current_org` ran, which is precisely the multi-org desync that
    audit B10 flagged.
    """
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
    if not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    return payload


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

    payload = await _decode_access_token(token)

    try:
        parsed_id = uuid.UUID(payload["sub"])
    except (ValueError, AttributeError, KeyError):
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

    # Password-change watermark check (B04 follow-up). Token's `iat` is
    # the moment it was issued; if the user changed their password later,
    # this token belongs to a previous session and must be rejected even
    # though its `exp` hasn't lapsed. Tokens minted before v2.4.13 don't
    # carry `iat`; we treat that as an old-format token and accept it
    # (the access-token TTL is 30min so they age out fast anyway).
    #
    # Comparison is done in epoch *seconds* on both sides to avoid the
    # sub-second drift between `int(time())` (what jose stores in iat)
    # and `datetime.now()` with microseconds (what we'd get if we built
    # a datetime from `password_changed_at`). With `password_changed_at`
    # set to `floor(now) + 1` in /change-password, this guarantees:
    #   * tokens minted before the change (iat <= floor(now)) → 401
    #   * tokens minted at or after the change (iat >= floor(now)+1) → pass
    iat_raw = payload.get("iat")
    if iat_raw is not None and user.password_changed_at is not None:
        iat_seconds = int(iat_raw) if isinstance(iat_raw, (int, float)) else int(iat_raw.timestamp())
        pwc_seconds = int(user.password_changed_at.timestamp())
        if iat_seconds < pwc_seconds:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalidated by password change; please re-login",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Stash the JWT payload on the request state so dependencies that
    # run later in the chain (get_current_org, get_current_user_org)
    # can read the org_id claim without re-decoding the token.
    request.state.jwt_payload = payload

    return user


def _resolve_active_org_id(request: Request) -> uuid.UUID | None:
    """Return the org_id the JWT was issued against, or None if absent.

    Reads from the payload stashed by `get_current_user`. Centralised so
    every consumer of the active-org concept goes through one place.
    """
    payload = getattr(request.state, "jwt_payload", None)
    if not payload:
        return None
    raw = payload.get("org_id")
    if not raw:
        return None
    try:
        return uuid.UUID(raw)
    except (ValueError, TypeError):
        return None


async def get_current_org(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> tuple[User, Membership]:
    """Return (user, membership) for the org the JWT was issued against.

    Previous implementation returned `current_user.memberships[0]` —
    a list whose order is not guaranteed by SQLAlchemy. For a user with
    memberships in two orgs A and B, login picked one (also unordered)
    and baked it into the JWT; subsequent requests then RLS-scoped to
    JWT's org X but returned the membership for org Y, so every query
    looked empty. Audit B10.

    Now: pull the org_id from the JWT, find the matching membership,
    fall back to the only membership if the JWT is silent (legacy
    tokens issued before login started persisting org_id), refuse with
    403 if the user no longer has membership in the JWT's org (they
    were removed since the token was issued).
    """
    if not current_user.memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not a member of any organization",
        )

    jwt_org_id = _resolve_active_org_id(request)

    # No org claim → legacy token. Use the only membership the user has
    # and rely on the next login to mint a token with the claim. If the
    # user has more than one membership, refuse rather than guess.
    if jwt_org_id is None:
        if len(current_user.memberships) > 1:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Active organization not specified in token; please re-login",
            )
        return current_user, current_user.memberships[0]

    for m in current_user.memberships:
        if m.organization_id == jwt_org_id:
            return current_user, m

    # JWT says org X but the user no longer has membership X.
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="No membership for the active organization; please re-login",
    )


async def get_current_user_org(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> tuple[User, uuid.UUID]:
    """Sugar dependency: return (user, organization_id) directly."""
    _, membership = await get_current_org(request, current_user)
    return current_user, membership.organization_id


# Canonical role enum. Keep in sync with the Pydantic Literal in
# app/schemas/membership.py and the FE Select in settings/team/page.tsx.
ROLES_ADMIN = ("admin",)
ROLES_AUDITOR_OR_ADMIN = ("admin", "auditor")
ROLES_ANY = ("admin", "auditor", "viewer")


def require_role(*allowed: str):
    """Dependency factory: gate an endpoint to a set of membership roles.

    Usage:
        @router.post(..., dependencies=[Depends(require_role("admin"))])

    Or, when the route also needs the (user, membership) tuple:

        async def my_route(
            current_org: tuple[User, Membership] = Depends(get_current_org),
            _: None = Depends(require_role("admin", "auditor")),
        ): ...

    Returning None instead of raising lets FastAPI's dependency tree
    fail with 403 cleanly without the route function being entered.
    """
    async def _dep(
        request: Request,
        current_user: User = Depends(get_current_user),
    ) -> None:
        _, membership = await get_current_org(request, current_user)
        if membership.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of: {', '.join(allowed)}",
            )
    return _dep


async def get_api_key_org(
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> tuple[ApiKey, uuid.UUID]:
    """Authenticate via API key (Bearer token starting with 'nis2_').
    Returns (api_key, organization_id) for CI/CD integrations.

    Audit B11: previous version honored is_active but ignored
    expires_at, so a key that was supposed to be time-limited stayed
    valid forever; also dead code (no router was wired). Both fixed
    here and consumers can now Depends(get_api_key_org)."""
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
    now = datetime.now(timezone.utc)

    # Honor expires_at. Without this, a customer who issued a key with
    # `expires_at = now + 30d` to a contractor never had the key
    # actually expire. Defence-in-depth: also flip is_active=False so
    # `list_api_keys` shows the right status without a separate cron.
    if api_key.expires_at is not None and api_key.expires_at <= now:
        api_key.is_active = False
        await db.flush()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired",
        )

    api_key.last_used_at = now
    await db.flush()

    return api_key, api_key.organization_id


async def _resolve_dual_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    db: AsyncSession,
    required_scope: str | None,
) -> uuid.UUID:
    """Core logic shared by get_org_id_dual_auth and dual_auth_with_scope."""
    raw = credentials.credentials if credentials else None
    has_cookie = request.cookies.get("access_token") is not None

    if raw and raw.startswith("nis2_") and not has_cookie:
        api_key, org_id = await get_api_key_org(db=db, credentials=credentials)
        if (
            required_scope is not None
            and api_key.scopes is not None
            and required_scope not in api_key.scopes
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key missing required scope: {required_scope}",
            )
        return org_id

    user = await get_current_user(request=request, credentials=credentials, db=db)
    _, membership = await get_current_org(request=request, current_user=user)
    return membership.organization_id


def dual_auth_with_scope(required_scope: str):
    """Dependency factory: authenticate via JWT session OR API key, enforcing a scope.

    When the caller presents an API key (Bearer `nis2_*` with no cookie),
    the key's scope list must contain `required_scope` — otherwise 403.
    Keys with `scopes=None` (legacy, pre-2.4.26) pass through unrestricted.

    JWT sessions are not scope-constrained (role-based access handles that).

    Usage:
        org_id: uuid.UUID = Depends(dual_auth_with_scope("scan:read"))
    """
    async def _dep(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
        db: AsyncSession = Depends(get_db),
    ) -> uuid.UUID:
        return await _resolve_dual_auth(request, credentials, db, required_scope)

    return _dep


async def get_org_id_dual_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> uuid.UUID:
    """Resolve the active organization_id via either a JWT session OR
    an API key — whichever the caller presented.

    Applied to read-only endpoints in scans / findings / assets so that
    CI/CD pipelines and SDK consumers can authenticate with a long-lived
    `nis2_*` Bearer token while the web UI keeps using cookie sessions.
    Mutation endpoints stay on `get_current_org` because they want a
    user identity to attribute the change to (audit log, created_by).

    Resolution order:
      1. Bearer token starting with "nis2_" AND no access_token cookie
         → API key path (calls get_api_key_org for expiry / revocation).
         The "no cookie" guard exists so a cookie session that happens
         to also send a stale `nis2_*` API key doesn't accidentally
         downgrade authentication to the API-key code path.
      2. Otherwise → JWT path (cookie or `Bearer <jwt>`), going through
         get_current_user → get_current_org. This means the same
         per-route 401/403 behavior as JWT-only endpoints.

    Returns the organization_id only — read endpoints just need it for
    RLS scoping; they don't need the user's identity.

    Prefer dual_auth_with_scope(required_scope) for new endpoints so
    scope enforcement is explicit at the call site.
    """
    return await _resolve_dual_auth(request, credentials, db, required_scope=None)
