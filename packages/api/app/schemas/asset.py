import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    target_type: str = Field(..., pattern="^(domain|ip|cidr)$")
    target_value: str = Field(..., min_length=1, max_length=512)
    tags: Optional[list[str]] = None


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    tags: Optional[list[str]] = None
    is_active: Optional[bool] = None


class AssetResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    target_type: str
    target_value: str
    tags: Optional[list[str]] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AssetListResponse(BaseModel):
    items: list[AssetResponse]
    total: int
    page: int
    page_size: int
