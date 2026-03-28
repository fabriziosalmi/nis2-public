import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    asset_ids: list[uuid.UUID] = Field(..., min_length=1)
    scan_type: str = Field(default="full", max_length=50)
    features: Optional[dict[str, Any]] = None
    concurrency: Optional[int] = Field(None, ge=1, le=200)
    scan_timeout: Optional[int] = Field(None, ge=1, le=120)
    max_hosts: Optional[int] = Field(None, ge=0, le=100000)


class ScanResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    created_by: Optional[uuid.UUID] = None
    name: str
    status: str
    scan_type: str
    config_snapshot: Optional[dict[str, Any]] = None
    total_score: Optional[int] = None
    hosts_scanned: int = 0
    hosts_alive: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    compliance_matrix: Optional[dict[str, Any]] = None
    executive_summary: Optional[str] = None
    celery_task_id: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    total: int
    page: int
    page_size: int


class ScanResultResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    target: str
    ip: str
    is_alive: bool
    open_ports: Optional[list[int]] = None
    http_info: Optional[dict[str, Any]] = None
    tls_info: Optional[dict[str, Any]] = None
    dns_info: Optional[dict[str, Any]] = None
    legal_info: Optional[dict[str, Any]] = None
    resilience_info: Optional[dict[str, Any]] = None
    whois_info: Optional[dict[str, Any]] = None
    secrets_found: Optional[Any] = None
    errors: Optional[list[str]] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanResultListResponse(BaseModel):
    items: list[ScanResultResponse]
    total: int
    page: int
    page_size: int
