# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class FindingResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    scan_result_id: Optional[uuid.UUID] = None
    organization_id: uuid.UUID
    severity: str
    category: str
    message: str
    rationale: Optional[str] = None
    target: str
    reference: Optional[str] = None
    cvss_base_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    technical_detail: Optional[str] = None
    remediation: Optional[str] = None
    remediation_cost: Optional[str] = None
    remediation_effort: Optional[str] = None
    compliance_article: Optional[str] = None
    status: str
    assigned_to: Optional[uuid.UUID] = None
    resolved_at: Optional[datetime] = None
    resolution_note: Optional[str] = None
    fingerprint: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrences: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(open|acknowledged|in_progress|resolved|accepted_risk)$")
    assigned_to: Optional[uuid.UUID] = None
    resolution_note: Optional[str] = None


class BulkFindingUpdate(BaseModel):
    finding_ids: list[uuid.UUID] = Field(..., min_length=1)
    status: str = Field(..., pattern="^(open|acknowledged|in_progress|resolved|accepted_risk)$")
    resolution_note: Optional[str] = None


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    page_size: int


class FindingStats(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    open: int = 0
    acknowledged: int = 0
    in_progress: int = 0
    resolved: int = 0
    accepted_risk: int = 0
