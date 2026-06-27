# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.dependencies import get_current_user
from app.middleware.audit import log_action
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.routers.auth import limiter  # share the single Limiter instance
from app.schemas.organization import (
    CreateOrgRequest,
    InviteMemberRequest,
    MemberResponse,
    OrgResponse,
    OrgUpdate,
    RoleUpdateRequest,
)
from app.utils.slug import slugify

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.post(
    "",
    response_model=OrgResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("5/minute")
async def create_organization(
    request: Request,
    payload: CreateOrgRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OrgResponse:
    """v2.4.18 audit follow-up: self-serve organization creation.

    Before this release the only path to a 2nd organization for a
    user was to be invited into an existing one. This route lets a
    consultant who already has org A spin up org B for a new client
    without an admin reaching across to invite them — same pattern as
    most multi-tenant SaaS (Vercel, Linear, etc.) where "create new
    workspace" lives in the workspace switcher.

    Behaviour:
      - Mints a fresh `Organization` row with `name` from the payload,
        slug derived via `slugify(name)` with `-1`, `-2`, ... suffixes
        appended on collision (slug is a UNIQUE column).
      - Creates a `Membership` for the calling user with `role="admin"`
        and `accepted_at` stamped immediately — no invite/accept loop
        for self-created orgs.
      - Audit-logs `organization.created` under the new org_id so the
        compliance team can answer "when was this tenant born".
      - Rate-limited 5/minute/IP. Genuine org creation is rare; the
        limit makes a runaway script obvious in the access logs.
      - Returns the new `Organization` shape (matches `GET /{org_id}`).
        Caller's UI is expected to follow up with `POST /auth/switch-org`
        to move the active session into the new tenant; this route
        intentionally does NOT remint the JWT itself so the user keeps
        the option of staying in the current org context.
    """
    # 1. Derive a unique slug. Same loop pattern as auth.py:register.
    base_slug = slugify(payload.name)
    if not base_slug:
        # Edge case: an org name composed entirely of unicode/emoji
        # that slugify strips to "" would otherwise hit the UNIQUE
        # index with empty strings. Fall back to a uuid-suffixed slug.
        base_slug = f"org-{uuid.uuid4().hex[:8]}"
    slug = base_slug
    suffix = 0
    while True:
        existing = await db.execute(
            select(Organization).where(Organization.slug == slug)
        )
        if not existing.scalar_one_or_none():
            break
        suffix += 1
        slug = f"{base_slug}-{suffix}"

    # 2. Create org + admin membership for the founder. Both rows
    #    flush in a single transaction so a partial failure (DB
    #    constraint, network blip) leaves no orphan org without an
    #    admin to manage it.
    org = Organization(name=payload.name, slug=slug)
    db.add(org)
    try:
        await db.flush()
    except IntegrityError:
        # Lost the check-then-insert race on the slug — another request created
        # the same slug between our uniqueness check and this flush. get_db rolls
        # the request transaction back; surface a clean 409 instead of a 500.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An organization with a conflicting name was just created; please retry.",
        )

    # The admin membership INSERT passes the memberships RLS WITH CHECK via its
    # user_id clause (the founder is current_user); the audit row below is scoped
    # to the new org by log_action itself. So no explicit context switch is needed
    # here — organizations is not RLS-scoped either.
    membership = Membership(
        user_id=current_user.id,
        organization_id=org.id,
        role="admin",
        accepted_at=datetime.now(timezone.utc),
    )
    db.add(membership)
    await db.flush()

    # 3. Audit. Logged under the *new* org so it shows up in that
    #    tenant's audit trail (which is where a curious admin will
    #    look first when wondering "when was this org created").
    await log_action(
        db,
        org_id=org.id,
        user_id=current_user.id,
        action="organization.created",
        resource_type="organization",
        resource_id=str(org.id),
        details={"name": payload.name, "slug": slug, "self_created": True},
        request=request,
    )

    return OrgResponse.model_validate(org)


@router.get("", response_model=list[OrgResponse])
async def list_organizations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[OrgResponse]:
    result = await db.execute(
        select(Organization)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == current_user.id)
        .order_by(Organization.name)
    )
    orgs = result.scalars().all()
    return [OrgResponse.model_validate(o) for o in orgs]


@router.get("/{org_id}", response_model=OrgResponse)
async def get_organization(
    org_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OrgResponse:
    # Verify membership
    membership = await _get_membership(db, current_user.id, org_id)
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    return OrgResponse.model_validate(org)


@router.patch("/{org_id}", response_model=OrgResponse)
async def update_organization(
    org_id: uuid.UUID,
    payload: OrgUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OrgResponse:
    membership = await _get_membership(db, current_user.id, org_id)
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    if membership.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can update organization settings",
        )

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    update_data = payload.model_dump(exclude_unset=True)
    allowed_fields = {"name", "settings"}
    for field, value in update_data.items():
        if field in allowed_fields:
            setattr(org, field, value)
    await db.flush()

    return OrgResponse.model_validate(org)


@router.get("/{org_id}/members", response_model=list[MemberResponse])
async def list_members(
    org_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[MemberResponse]:
    membership = await _get_membership(db, current_user.id, org_id)
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    result = await db.execute(
        select(Membership)
        .options(selectinload(Membership.user))
        .where(Membership.organization_id == org_id)
        .order_by(Membership.created_at)
    )
    members = result.scalars().all()

    return [MemberResponse.model_validate(m) for m in members]


@router.post(
    "/{org_id}/members",
    response_model=MemberResponse,
    status_code=status.HTTP_201_CREATED,
)
async def invite_member(
    org_id: uuid.UUID,
    payload: InviteMemberRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MemberResponse:
    membership = await _get_membership(db, current_user.id, org_id)
    if not membership or membership.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can invite members",
        )

    # Find or create user by email
    result = await db.execute(select(User).where(User.email == payload.email))
    target_user = result.scalar_one_or_none()

    # ── Generate invite token ───────────────────────────────────────
    # 32 bytes → 64-char hex string.  Cryptographically random.
    # Only the SHA-256 hash is stored in the DB; the raw token goes
    # to the admin for sharing with the invitee.
    import hashlib
    import secrets
    from datetime import timedelta

    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    token_expires = datetime.now(timezone.utc) + timedelta(hours=48)

    if not target_user:
        # P0-02 audit fix: create with is_active=False. The invited user
        # must complete registration (set a password) before they can
        # log in. Pre-fix, the placeholder had is_active=True + no
        # password_hash — the account appeared "active" in the member
        # list but could never actually authenticate (login rejects
        # users without password_hash). Setting is_active=False makes
        # the state explicit and prevents any future code path from
        # accidentally granting access to a passwordless account.
        target_user = User(
            email=payload.email,
            full_name=payload.email.split("@")[0],  # placeholder name
            is_active=False,
            invite_token_hash=token_hash,
            invite_token_expires_at=token_expires,
        )
        db.add(target_user)
        await db.flush()
    else:
        # Existing user being re-invited (e.g. to a different org) or
        # an expired invite being refreshed — update the token.
        target_user.invite_token_hash = token_hash
        target_user.invite_token_expires_at = token_expires
        await db.flush()

    # Check if already a member
    existing = await _get_membership(db, target_user.id, org_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already a member of this organization",
        )

    new_membership = Membership(
        user_id=target_user.id,
        organization_id=org_id,
        role=payload.role,
        invited_by=current_user.id,
    )
    db.add(new_membership)
    await db.flush()

    await log_action(
        db,
        org_id=org_id,
        user_id=current_user.id,
        action="member.invited",
        resource_type="membership",
        resource_id=str(new_membership.id),
        details={
            "target_user_id": str(target_user.id),
            "target_email": payload.email,
            "role": payload.role,
        },
    )

    # Reload with user relation
    result = await db.execute(
        select(Membership)
        .options(selectinload(Membership.user))
        .where(Membership.id == new_membership.id)
    )
    new_membership = result.scalar_one()

    resp = MemberResponse.model_validate(new_membership)
    # Attach the raw invite token so the admin can share it with the
    # invitee.  This is the ONLY time the raw token is ever exposed;
    # subsequent GET /members calls will not include it.
    resp.invite_token = raw_token
    return resp


@router.patch("/{org_id}/members/{member_id}", response_model=MemberResponse)
async def update_member_role(
    org_id: uuid.UUID,
    member_id: uuid.UUID,
    payload: RoleUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MemberResponse:
    """Change a member's role.

    Audit B08: previous version took `role` from a Query param while the
    frontend sent it in the JSON body, so every call 422'd. Moved to a
    Pydantic body model.

    Audit B09: previous version had no last-admin guard symmetric to
    `remove_member`. The sole admin could PATCH themselves to viewer
    and orphan the org with zero recovery path. Added the same admin-
    count check + an explicit self-demotion refusal (the actor cannot
    demote themselves; ask another admin or use a leave endpoint).
    """
    my_membership = await _get_membership(db, current_user.id, org_id)
    if not my_membership or my_membership.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can change roles",
        )

    target_membership = await db.get(Membership, member_id)
    if not target_membership or target_membership.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Member not found"
        )

    new_role = payload.role
    old_role = target_membership.role

    # No-op: the FE may resubmit on edit click; just return the row.
    if new_role == old_role:
        return MemberResponse.model_validate(target_membership)

    # Self-demotion is special. We refuse it explicitly: a single admin
    # acting on themselves bypasses the "last admin" intuition (their
    # own future self is the demoted one). Force them to either ask
    # another admin or leave the org via the dedicated endpoint.
    if (
        target_membership.user_id == current_user.id
        and old_role == "admin"
        and new_role != "admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot demote yourself. Ask another admin or use the leave endpoint.",
        )

    # Demoting (or removing) an admin? Make sure at least one other
    # remains. Symmetric with remove_member's guard.
    if old_role == "admin" and new_role != "admin":
        admin_count_result = await db.execute(
            select(Membership).where(
                Membership.organization_id == org_id,
                Membership.role == "admin",
            )
        )
        admins = admin_count_result.scalars().all()
        if len(admins) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the last admin of an organization",
            )

    target_membership.role = new_role
    await db.flush()
    await db.refresh(target_membership)

    # Audit S02: record before/after so the audit-log view can answer
    # "who demoted Bob from admin yesterday".
    await log_action(
        db,
        org_id=org_id,
        user_id=current_user.id,
        action="member.role_changed",
        resource_type="membership",
        resource_id=str(member_id),
        details={
            "before": old_role,
            "after": new_role,
            "target_user_id": str(target_membership.user_id),
        },
    )

    return MemberResponse.model_validate(target_membership)


@router.delete("/{org_id}/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    org_id: uuid.UUID,
    member_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    my_membership = await _get_membership(db, current_user.id, org_id)
    if not my_membership or my_membership.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can remove members",
        )

    target_membership = await db.get(Membership, member_id)
    if not target_membership or target_membership.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Member not found"
        )

    # Prevent removing the last admin
    if target_membership.role == "admin":
        admin_count_result = await db.execute(
            select(Membership).where(
                Membership.organization_id == org_id,
                Membership.role == "admin",
            )
        )
        admins = admin_count_result.scalars().all()
        if len(admins) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last admin of an organization",
            )

    target_user_id = target_membership.user_id
    target_role = target_membership.role
    await db.delete(target_membership)
    await db.flush()

    await log_action(
        db,
        org_id=org_id,
        user_id=current_user.id,
        action="member.removed",
        resource_type="membership",
        resource_id=str(member_id),
        details={
            "target_user_id": str(target_user_id),
            "removed_role": target_role,
        },
    )


async def _get_membership(
    db: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID
) -> Membership | None:
    result = await db.execute(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.organization_id == org_id,
        )
    )
    return result.scalar_one_or_none()
