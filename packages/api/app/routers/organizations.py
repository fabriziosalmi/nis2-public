# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.dependencies import get_current_user
from app.middleware.audit import log_action
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.schemas.organization import (
    InviteMemberRequest,
    MemberResponse,
    OrgResponse,
    OrgUpdate,
    RoleUpdateRequest,
)

router = APIRouter(prefix="/organizations", tags=["organizations"])


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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    if membership.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can update organization settings",
        )

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    result = await db.execute(
        select(Membership)
        .options(selectinload(Membership.user))
        .where(Membership.organization_id == org_id)
        .order_by(Membership.created_at)
    )
    members = result.scalars().all()

    return [MemberResponse.model_validate(m) for m in members]


@router.post("/{org_id}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
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

    if not target_user:
        # Create a placeholder user
        target_user = User(email=payload.email, full_name="", is_active=True)
        db.add(target_user)
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

    return MemberResponse.model_validate(new_membership)


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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

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
