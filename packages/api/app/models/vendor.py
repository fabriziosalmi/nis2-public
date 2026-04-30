# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Vendor Risk Management model (Art. 18 D.Lgs 138/2024).
Tracks critical suppliers and their security posture for supply chain risk.
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin


class Vendor(TimestampMixin, Base):
    __tablename__ = "vendors"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="ict_service"
    )  # ict_service, cloud, managed_security, hw_supplier, sw_supplier, other
    criticality: Mapped[int] = mapped_column(
        Integer, nullable=False, default=2
    )  # 1=critical, 2=important, 3=standard, 4=low
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="active"
    )  # active, under_review, suspended, terminated

    # Contact and contract
    contact_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contract_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contract_expiry: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Art. 18 specific fields
    services_provided: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    data_access_level: Mapped[str] = mapped_column(
        String(30), nullable=False, default="none"
    )  # none, metadata, operational, confidential, critical
    geographic_location: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # EU, EEA, adequacy_decision, third_country
    has_security_certification: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )  # ISO27001, SOC2, CSA_STAR, etc.
    last_audit_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_audit_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Security assessment
    security_score: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # 0-100
    risk_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    security_clauses: Mapped[Optional[dict]] = mapped_column(
        JSONB, nullable=True
    )  # SLA, audit_rights, incident_notification, data_breach_clause

    # ACN Determina 127437 fields
    acn_codice_servizio: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # ACN service code mapping
    acn_rilevanza_art18: Mapped[bool] = mapped_column(
        default=False
    )  # Flagged as relevant per Art. 18
