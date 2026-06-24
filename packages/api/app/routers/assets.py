# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import csv
import io
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import dual_auth_with_scope, get_current_org, require_role
from app.routers.auth import limiter  # share the single Limiter instance
from app.models.asset import Asset
from app.models.membership import Membership
from app.models.user import User
from app.schemas.asset import AssetCreate, AssetListResponse, AssetResponse, AssetUpdate
from app.utils.target_validator import TargetValidationError, validate_target_pinned
from app.middleware.audit import log_action

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=AssetListResponse)
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    org_id: uuid.UUID = Depends(dual_auth_with_scope("asset:read")),
    db: AsyncSession = Depends(get_db),
) -> AssetListResponse:
    # Dual-auth read — JWT cookie/Bearer OR `nis2_*` API key. Mutation
    # endpoints below stay on get_current_org because they want a user
    # identity for the audit log + created_by attribution.

    count_query = select(func.count(Asset.id)).where(Asset.organization_id == org_id)
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = (
        select(Asset)
        .where(Asset.organization_id == org_id)
        .order_by(Asset.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    assets = result.scalars().all()

    return AssetListResponse(
        items=[AssetResponse.model_validate(a) for a in assets],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_role("admin", "auditor"))])
@limiter.limit("20/minute")
async def create_asset(
    request: Request,
    payload: AssetCreate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    user, membership = current_org
    org_id = membership.organization_id

    # Check for duplicate
    existing = await db.execute(
        select(Asset).where(
            Asset.organization_id == org_id,
            Asset.target_type == payload.target_type,
            Asset.target_value == payload.target_value,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Asset with this target already exists in your organization",
        )

    # SSRF validation + pin the IP for the scanner to use later.
    try:
        validation = await validate_target_pinned(payload.target_type, payload.target_value)
    except TargetValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    asset = Asset(
        organization_id=org_id,
        name=payload.name,
        target_type=payload.target_type,
        target_value=validation.target_value,
        pinned_ip=validation.pinned_ip,
        tags=payload.tags or [],
    )
    db.add(asset)
    await db.flush()

    await log_action(
        db,
        org_id=org_id,
        user_id=user.id,
        action="asset.created",
        resource_type="asset",
        resource_id=str(asset.id),
        details={"name": asset.name, "target": asset.target_value, "type": asset.target_type},
    )

    return AssetResponse.model_validate(asset)


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: uuid.UUID,
    org_id: uuid.UUID = Depends(dual_auth_with_scope("asset:read")),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    # Dual-auth read — see list_assets for the wiring note.
    asset = await db.get(Asset, asset_id)
    if not asset or asset.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return AssetResponse.model_validate(asset)


@router.patch("/{asset_id}", response_model=AssetResponse, dependencies=[Depends(require_role("admin", "auditor"))])
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    user, membership = current_org

    asset = await db.get(Asset, asset_id)
    if not asset or asset.organization_id != membership.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    update_data = payload.model_dump(exclude_unset=True)

    if "target_type" in update_data or "target_value" in update_data:
        new_type = update_data.get("target_type") or asset.target_type
        new_val = update_data.get("target_value") or asset.target_value

        if new_type != asset.target_type or new_val != asset.target_value:
            existing = await db.execute(
                select(Asset).where(
                    Asset.organization_id == membership.organization_id,
                    Asset.target_type == new_type,
                    Asset.target_value == new_val,
                    Asset.id != asset.id,
                )
            )
            if existing.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Asset with this target already exists in your organization",
                )

        try:
            validation = await validate_target_pinned(new_type, new_val)
            asset.target_type = new_type
            asset.target_value = validation.target_value
            asset.pinned_ip = validation.pinned_ip
        except TargetValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(e),
            )

        update_data.pop("target_type", None)
        update_data.pop("target_value", None)

    allowed_fields = {"name", "target_type", "target_value", "tags", "is_active"}
    for field, value in update_data.items():
        if field in allowed_fields:
            setattr(asset, field, value)
    await db.flush()

    await log_action(
        db,
        org_id=membership.organization_id,
        user_id=user.id,
        action="asset.updated",
        resource_type="asset",
        resource_id=str(asset.id),
        details={"name": asset.name, "target": asset.target_value, "updated_fields": list(update_data.keys())},
    )

    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_role("admin"))])
async def delete_asset(
    asset_id: uuid.UUID,
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    user, membership = current_org

    asset = await db.get(Asset, asset_id)
    if not asset or asset.organization_id != membership.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    await log_action(
        db,
        org_id=membership.organization_id,
        user_id=user.id,
        action="asset.deleted",
        resource_type="asset",
        resource_id=str(asset.id),
        details={"name": asset.name, "target": asset.target_value, "type": asset.target_type},
    )

    await db.delete(asset)
    await db.flush()


@router.post("/import", response_model=dict, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_role("admin"))])
@limiter.limit("5/minute")
async def import_assets_csv(
    request: Request,
    file: UploadFile = File(...),
    current_org: tuple[User, Membership] = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Import assets from a CSV file.
    Expected columns: name, target_type, target_value, tags (optional, semicolon-separated)
    """
    user, membership = current_org
    org_id = membership.organization_id

    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a CSV",
        )

    # P1-05 audit fix: cap file size to prevent OOM. Without this,
    # an authenticated user could upload a multi-GB CSV and crash
    # the API process. 5 MB is generous for an asset list (100k+
    # rows of domain/IP entries).
    MAX_CSV_BYTES = 5 * 1024 * 1024  # 5 MB
    content = await file.read(MAX_CSV_BYTES + 1)
    if len(content) > MAX_CSV_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"CSV file too large. Maximum size: {MAX_CSV_BYTES // (1024*1024)} MB",
        )

    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be UTF-8 encoded",
        )

    reader = csv.DictReader(io.StringIO(decoded))
    created = 0
    skipped = 0
    errors_list: list[str] = []

    # Load all existing assets into memory to avoid N+1 queries during import
    existing_assets_result = await db.execute(
        select(Asset.target_type, Asset.target_value).where(Asset.organization_id == org_id)
    )
    existing_assets = {(row[0], row[1]) for row in existing_assets_result.all()}

    # P1-05 audit fix: cap the number of rows processed. Each row
    # triggers a DNS resolution (SSRF validation), so a large CSV
    # will still be heavy, but it will no longer block the DB.
    MAX_ROWS = 10_000

    for row_num, row in enumerate(reader, start=2):
        if row_num - 1 > MAX_ROWS:
            errors_list.append(f"Row limit exceeded: maximum {MAX_ROWS} rows allowed")
            break
        name = row.get("name", "").strip()
        target_type = row.get("target_type", "").strip()
        target_value = row.get("target_value", "").strip()
        tags_str = row.get("tags", "").strip()

        if not name or not target_type or not target_value:
            errors_list.append(f"Row {row_num}: missing required fields")
            skipped += 1
            continue

        if target_type not in ("domain", "ip", "cidr"):
            errors_list.append(f"Row {row_num}: invalid target_type '{target_type}'")
            skipped += 1
            continue

        tags = [t.strip() for t in tags_str.split(";") if t.strip()] if tags_str else []

        # Check for duplicate in the memory set instead of DB
        asset_key = (target_type, target_value)
        if asset_key in existing_assets:
            skipped += 1
            continue

        # SSRF validation + pin IP
        try:
            validation = await validate_target_pinned(target_type, target_value)
        except TargetValidationError as e:
            errors_list.append(f"Row {row_num}: {e}")
            skipped += 1
            continue

        asset = Asset(
            organization_id=org_id,
            name=name,
            target_type=target_type,
            target_value=validation.target_value,
            pinned_ip=validation.pinned_ip,
            tags=tags,
        )
        db.add(asset)
        existing_assets.add(asset_key)
        created += 1

    await db.flush()

    await log_action(
        db,
        org_id=org_id,
        user_id=user.id,
        action="asset.imported",
        resource_type="asset_import",
        details={"created": created, "skipped": skipped, "errors_count": len(errors_list)},
    )

    return {"created": created, "skipped": skipped, "errors": errors_list}
