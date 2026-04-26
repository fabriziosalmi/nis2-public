# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Business Impact Analysis model.
Prepares for ACN standardized BIA template integration.
Maps business processes to assets and criticality levels.
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin


class BusinessProcess(TimestampMixin, Base):
    """A business process that depends on IT assets and services."""
    __tablename__ = "business_processes"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    process_owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # BIA classification
    criticality_level: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3
    )  # 1=mission_critical, 2=business_critical, 3=important, 4=non_critical

    # Impact assessment per time window
    rto_hours: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # Recovery Time Objective (hours)
    rpo_hours: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # Recovery Point Objective (hours)
    mtpd_hours: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # Maximum Tolerable Period of Disruption (hours)

    # Impact dimensions (1-4 scale for each)
    impact_financial: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    impact_operational: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    impact_reputational: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    impact_regulatory: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    impact_safety: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Dependencies
    dependent_asset_ids: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True
    )  # Asset UUIDs this process depends on
    dependent_vendor_ids: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True
    )  # Vendor UUIDs this process depends on
    upstream_process_ids: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True
    )  # Other processes this depends on

    # NIS2 Art. 20 service classification
    acn_servizio_essenziale: Mapped[bool] = mapped_column(default=False)
    acn_codice_servizio: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    acn_settore: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # energia, trasporti, sanita, digitale, etc.

    # Continuity
    has_bcp: Mapped[bool] = mapped_column(default=False)  # Business Continuity Plan
    has_drp: Mapped[bool] = mapped_column(default=False)  # Disaster Recovery Plan
    last_test_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
