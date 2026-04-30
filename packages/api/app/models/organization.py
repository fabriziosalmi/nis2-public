# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.membership import Membership
    from app.models.scan import Scan


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(256), nullable=False)
    slug: Mapped[str] = mapped_column(
        String(128), unique=True, index=True, nullable=False
    )
    plan: Mapped[str] = mapped_column(String(50), default="free", nullable=False)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    max_scans_per_month: Mapped[int] = mapped_column(
        Integer, default=50, nullable=False
    )

    # Relationships
    memberships: Mapped[list[Membership]] = relationship(
        "Membership", back_populates="organization", lazy="selectin"
    )
    assets: Mapped[list[Asset]] = relationship(
        "Asset", back_populates="organization", lazy="select"
    )
    scans: Mapped[list[Scan]] = relationship(
        "Scan", back_populates="organization", lazy="select"
    )

    def __repr__(self) -> str:
        return f"<Organization {self.slug}>"
