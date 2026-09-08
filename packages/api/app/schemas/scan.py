# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


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


class ScanConfigSnapshot(BaseModel):
    """The frozen scan configuration, validated on the way in AND on the way out.

    `scans.config_snapshot` is a JSONB column, and the worker used to rebuild the
    scanner's configuration from it with `.get()` and a default for every key.
    That made a damaged or empty snapshot indistinguishable from a valid one: no
    key raised, the target lists came back empty, the scan probed nothing, and
    the compliance engine scored the result 100 — so losing a scan's own
    configuration was recorded as perfect compliance.

    The engine no longer scores an unassessed scan, which stops the wrong answer
    reaching the dossier. This stops the wrong *input* being accepted at all: a
    snapshot that does not describe at least one target is refused, loudly, with
    the scan marked failed and the reason recorded, rather than silently becoming
    a scan of nothing.

    Unknown keys are tolerated deliberately. Snapshots written by earlier
    releases must stay re-runnable, and a key this version does not read is not
    evidence of damage — the invariant worth enforcing is that the targets and
    the bounds are present and sane.
    """

    name: str = Field(..., min_length=1, max_length=256)
    domains: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    pinned_ips: dict[str, str] = Field(default_factory=dict)
    scan_type: str = Field(default="full", max_length=50)
    features: dict[str, bool] = Field(
        default_factory=lambda: {
            "dns_checks": True,
            "web_checks": True,
            "port_scan": True,
            "whois_checks": True,
        }
    )
    # Bounds mirror ScanCreate: a snapshot that survived a hand-edit or a partial
    # write must not be able to ask for concurrency the API would have rejected.
    concurrency: int = Field(default=20, ge=1, le=200)
    scan_timeout: int = Field(default=10, ge=1, le=120)
    max_hosts: int = Field(default=0, ge=0, le=100000)

    model_config = {"extra": "ignore"}

    @model_validator(mode="after")
    def _must_describe_at_least_one_target(self) -> "ScanConfigSnapshot":
        if not self.domains and not self.ip_ranges:
            raise ValueError(
                "the scan configuration names no domains and no IP ranges, so "
                "there is nothing to scan"
            )
        return self
