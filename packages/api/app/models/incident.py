# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Incident model for CSIRT Art. 23 D.Lgs 138/2024.
Tracks the full incident lifecycle: detection -> early warning (24h) ->
notification (72h) -> final report (1 month).
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin


class Incident(TimestampMixin, Base):
    __tablename__ = "incidents"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    reported_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )

    # Incident identification
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    incident_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # CSIRT IT taxonomy: ransomware, ddos, data_breach, supply_chain, phishing, apt, insider, other
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="high"
    )  # critical, high, medium, low
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="detected"
    )  # detected, early_warning_sent, notification_sent, contained, eradicated, recovered, closed

    # Art. 23 timeline (the legally binding timestamps)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    early_warning_deadline: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )  # detected_at + 24h
    early_warning_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notification_deadline: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )  # detected_at + 72h
    notification_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    final_report_deadline: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # detected_at + 1 month
    final_report_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Impact assessment
    description: Mapped[str] = mapped_column(Text, nullable=False)
    affected_systems: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_asset_ids: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True
    )  # List of Asset UUIDs
    impact_category: Mapped[str] = mapped_column(
        String(100), nullable=False, default="operational"
    )  # operational, financial, reputational, regulatory, safety
    estimated_impact_level: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3
    )  # 1=catastrophic, 2=severe, 3=significant, 4=minor
    cross_border: Mapped[bool] = mapped_column(default=False)
    supply_chain_impact: Mapped[bool] = mapped_column(default=False)
    users_affected_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Evidence and IOCs
    indicators_of_compromise: Mapped[Optional[dict]] = mapped_column(
        JSONB, nullable=True
    )  # IPs, domains, hashes, file paths
    evidence_files: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True
    )  # List of attached evidence references
    timeline_events: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True
    )  # Chronological event log

    # Containment and remediation
    containment_actions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    eradication_actions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recovery_actions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ACN CSIRT notification fields
    csirt_reference_id: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # Reference ID from CSIRT Italia
    csirt_taxonomy_code: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # Official CSIRT taxonomy code
