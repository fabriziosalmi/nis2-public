# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin

if TYPE_CHECKING:
    from app.models.scan import Scan


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_org_id", "organization_id"),
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_org_severity", "organization_id", "severity"),
        Index("ix_findings_org_fingerprint", "organization_id", "fingerprint"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_result_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_results.id", ondelete="SET NULL"),
        nullable=True,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Finding details
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    reference: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # CVSS scoring
    cvss_base_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Technical details
    technical_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_cost: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    remediation_effort: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    compliance_article: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True
    )

    # Workflow
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="open"
    )  # open, acknowledged, in_progress, resolved, accepted_risk
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolution_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Deduplication
    fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # SHA-256
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    occurrences: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Relationships
    scan: Mapped[Scan] = relationship(
        "Scan", back_populates="findings", foreign_keys=[scan_id]
    )

    def __repr__(self) -> str:
        return f"<Finding {self.severity} {self.category}: {self.message[:50]}>"
