# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ARRAY, Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin

if TYPE_CHECKING:
    from app.models.organization import Organization


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "target_type",
            "target_value",
            name="uq_org_target",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    target_type: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # domain, ip, cidr
    target_value: Mapped[str] = mapped_column(String(512), nullable=False)
    # Pinned IP captured at validation time. The scanner uses this for the
    # actual TCP connection (with target_value sent as Host header) so a
    # DNS rebinding between validation and scan cannot redirect us to an
    # internal address. Null for CIDR ranges and for assets created before
    # the pinning feature was introduced — the scanner falls back to live
    # resolution in that case, with the validator catching private answers.
    pinned_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    tags: Mapped[Optional[list[str]]] = mapped_column(
        ARRAY(Text), default=list, nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Proof that this organisation may scan this target.
    #
    # There was none: any authenticated user could add any domain or a /16 and
    # have the platform port-scan it, attempt zone transfers against its
    # nameservers and request /.env from it. See app/utils/asset_verification.py
    # for why DNS proof is used for domains and an attributed attestation for
    # addresses.
    #
    # `legacy` exists so assets created before verification keep working; they
    # are shown as unverified rather than silently blocked.
    verification_status: Mapped[str] = mapped_column(
        String(16), default="unverified", nullable=False
    )
    verification_token: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Who asserted authority, for the attestation path. The audit log carries
    # the event; this keeps the answer on the row itself, where anyone reviewing
    # the asset will see it.
    verified_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization", back_populates="assets"
    )

    def __repr__(self) -> str:
        return f"<Asset {self.target_type}:{self.target_value}>"
