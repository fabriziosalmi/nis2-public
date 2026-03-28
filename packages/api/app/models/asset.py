from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ARRAY, Boolean, ForeignKey, String, Text, UniqueConstraint
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
    tags: Mapped[Optional[list[str]]] = mapped_column(
        ARRAY(Text), default=list, nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization", back_populates="assets"
    )

    def __repr__(self) -> str:
        return f"<Asset {self.target_type}:{self.target_value}>"
