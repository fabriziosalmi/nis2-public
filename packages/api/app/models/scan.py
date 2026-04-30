# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_org_created", "organization_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False, default="Untitled Scan")
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending"
    )  # pending, running, completed, failed, cancelled
    scan_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="full"
    )
    config_snapshot: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Results summary
    total_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    hosts_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    hosts_alive: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_critical: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_high: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_medium: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_low: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Report data
    compliance_matrix: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Task tracking
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="scans")
    results: Mapped[list] = relationship(
        "ScanResult", back_populates="scan", lazy="select", cascade="all, delete-orphan"
    )
    findings: Mapped[list] = relationship(
        "Finding",
        back_populates="scan",
        lazy="select",
        cascade="all, delete-orphan",
        foreign_keys="Finding.scan_id",
    )

    def __repr__(self) -> str:
        return f"<Scan {self.id} status={self.status}>"
